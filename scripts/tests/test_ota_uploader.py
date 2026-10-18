"""Public synthetic keys only. All artifacts remain under repository .tmp."""
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ota_common import Assembly, Error, Frame, Kind, Phase, Status, domain
from ota_compression import Package
from ota_job import JobStore

ROOT = Path(__file__).resolve().parents[2]
ADMIN_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
RECEIVER_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32)
ADMIN = ADMIN_PRIVATE.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
TARGET = RECEIVER_PRIVATE.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
POLICY = {"duty": 1.0, "route": {"flood": True, "path": "", "width": 1, "max_path_bytes": 1},
          "transport": "native", "local": False}


def canonical(image, counter=5):
    return (b"XN40\0" + struct.pack(">II", 0x27000, len(image)) + hashlib.sha256(image).digest()
            + struct.pack(">IIHHH", counter, 1, 1, 1, 1))


def package(image=None, compress=True):
    image = image if image is not None else (struct.pack("<II", 0x20010000, 0x27009)
                                           + hashlib.shake_256(b"v4 raw test image").digest(9000))
    return Package.build(image, canonical(image), ADMIN, ADMIN_PRIVATE.sign, compress)


def status_body(pkg, nonce, phase=Phase.RECEIVING, generation=1, transaction=b"T" * 16,
                challenge=b"C" * 16, next_chunk=0, missing=0, floor=0, evidence=1, running=bytes(32)):
    prefix = (TARGET + nonce + challenge + pkg.digest + transaction
              + struct.pack(">IIIBBHQ", generation, pkg.counter, floor, phase, 0, next_chunk, missing)
              + running + bytes([evidence]))
    assert len(prefix) == 169
    return prefix + RECEIVER_PRIVATE.sign(domain("status") + prefix)


class Scratch(unittest.TestCase):
    def setUp(self):
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.directory = ROOT / ".tmp" / ("v4-host-" + uuid.uuid4().hex)
        self.directory.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.directory)


class WireTests(Scratch):
    def test_actual_cpp_frame_encoder_matches_python_and_crc_rejects_damage(self):
        source = self.directory / "golden.cpp"
        source.write_text(r'''
#include <cstdio>
#include <helpers/ota/OtaV4Protocol.h>
int main() {
  unsigned char tag[8]={1,2,3,4,5,6,7,8}, data[128], out[151];
  for(unsigned i=0;i<128;++i)data[i]=i;
  auto n=mesh::ota::v4::encodeFrame(mesh::ota::v4::Kind::Data,0x10203040,tag,7,8192,63,data,128,out,151);
  for(unsigned i=0;i<n;++i)std::printf("%02x",out[i]);
}''')
        binary = self.directory / "golden"
        subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "src"),
                        str(source), "-o", str(binary)], check=True, capture_output=True,
                       env=dict(os.environ, TMPDIR=str(self.directory)))
        frame = Frame(Kind.DATA, 0x10203040, bytes(range(1, 9)), 7, 8192, 63, bytes(range(128)))
        self.assertEqual(subprocess.check_output([str(binary)]).decode(), frame.encode().hex())
        self.assertEqual(Frame.decode(frame.encode()), frame)
        broken = bytearray(frame.encode())
        broken[60] ^= 1
        with self.assertRaisesRegex(Error, "CRC"):
            Frame.decode(broken)

    def test_response_reassembly_accepts_new_attempts_but_refuses_conflicting_slices(self):
        data = bytes(range(233))
        assembly = Assembly(Kind.STATUS, b"T" * 8, 9)
        second = Frame(Kind.STATUS, 2, b"T" * 8, 9, len(data), 1, data[128:])
        first = Frame(Kind.STATUS, 3, b"T" * 8, 9, len(data), 0, data[:128])
        self.assertIsNone(assembly.feed(second))
        self.assertEqual(assembly.feed(first), data)
        with self.assertRaisesRegex(Error, "conflicting"):
            assembly.feed(Frame(Kind.STATUS, 4, b"T" * 8, 9, len(data), 0, bytes(128)))

    def test_status_is_challenge_bound_signed_and_requires_running_evidence(self):
        pkg, nonce = package(), b"N" * 16
        good = status_body(pkg, nonce, phase=Phase.CONFIRMED, next_chunk=len(pkg.chunks),
                           floor=pkg.counter, evidence=7, running=pkg.raw_hash)
        self.assertTrue(Status.decode(good, TARGET, nonce).installed(pkg))
        with self.assertRaisesRegex(Error, "nonce"):
            Status.decode(good, TARGET, b"S" * 16)
        bad = bytearray(good)
        bad[120] ^= 1
        with self.assertRaisesRegex(Error, "signature"):
            Status.decode(bad, TARGET, nonce)
        unknown = status_body(pkg, nonce, phase=Phase.CONFIRMED, floor=pkg.counter, evidence=1)
        self.assertFalse(Status.decode(unknown, TARGET, nonce).installed(pkg))


class JobTests(Scratch):
    def test_exclusive_restart_retains_uncertain_intent_and_exact_signed_package(self):
        pkg = package()
        path = self.directory / "job"
        job = JobStore.create(path, pkg, ADMIN, [TARGET], POLICY)
        operation = job.intent(TARGET, Kind.ACTIVATE, b"signed command")
        attempt = job.attempt()
        with self.assertRaises(BlockingIOError):
            JobStore.open(path)
        job.close()
        with JobStore.open(path) as reopened:
            self.assertEqual(reopened.package.encode(), pkg.encode())
            self.assertEqual(reopened.uncertain(TARGET, Kind.ACTIVATE), [(operation,)])
            self.assertGreater(reopened.attempt(), attempt)
        capsule = path / "package.bin"
        changed = bytearray(capsule.read_bytes())
        changed[-1] ^= 1
        capsule.write_bytes(changed)
        with self.assertRaises(Error):
            JobStore.open(path)

    def test_jobs_reject_duplicate_targets_and_symlink_database(self):
        with self.assertRaises(ValueError):
            JobStore.create(self.directory / "duplicate", package(), ADMIN, [TARGET, TARGET], POLICY)
        path = self.directory / "job"
        with JobStore.create(path, package(), ADMIN, [TARGET], POLICY):
            pass
        database = path / "job.sqlite"
        database.rename(path / "real.sqlite")
        database.symlink_to("real.sqlite")
        with self.assertRaisesRegex(Error, "nonsymlink"):
            JobStore.open(path)


if __name__ == "__main__":
    unittest.main()
