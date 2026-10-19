"""Python v4 frames -> real Receiver/nRF platform -> real C installer -> floor.

Run only through test/test_lora_ota_v4_boot/Makefile. The C executable accepts
``init|boot|inspect DIRECTORY``; the receiver accepts DIRECTORY ADMIN SEED BOARD
ROLE and the existing hex-frame / dot-delimited response stream. ``health`` runs
the production health window, not a simulated confirmation. qspi.bin/internal.bin
are full raw media, never reconstructed command or candidate fixtures.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import unittest
import zlib

from ota_common import Kind, Phase
from ota_compression import Package, descriptor
from ota_job import JobStore
from ota_uploader import Scheduler
from test_ota_deploy import Driver, DriverTransport
from test_ota_stock_companion import Clock
from test_ota_uploader import ADMIN, ADMIN_PRIVATE, POLICY, Scratch, TARGET

BUILD = os.environ.get("OTA_V4_NRF_BOOT_DIR")
PROFILES = (("xiao", "xiao_nrf52840", 0x584E3430),
            ("solar", "sensecap_solar_p1", 0x53435031))
COMMAND, CONFIRM, FLOOR = 0x18C000, 0x190000, 0x192000
APP = 0x27000


class NrfDriver(Driver):
    def __init__(self, directory, board, role, *, metadata_io_fault=False):
        self.directory = directory
        self.arguments = [str(Path(BUILD) / "receiver"), str(directory), ADMIN.hex(),
                          (bytes([2]) * 32).hex(), hex(board), str(role)]
        if metadata_io_fault:
            self.arguments.append("metadata-io")
        self.log = (directory / "receiver.log").open("a")
        self.process = subprocess.Popen(self.arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.log, text=True, bufsize=1)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=10)
        self.process.stdout.close()
        self.log.close()
        if self.process.returncode:
            raise AssertionError((self.directory / "receiver.log").read_text())


@unittest.skipUnless(BUILD, "scoped Make target supplies real C/C++ executables")
class NrfBootEndToEndTests(Scratch):
    def fixture(self, name="solar", role=1, *, compress=True, wrong_board=False, wrong_role=False):
        _, package_board, board = next(p for p in PROFILES if p[0] == name)
        directory = self.directory / f"{name}-{role}-{len(list(self.directory.iterdir()))}"
        directory.mkdir()
        helper = Path(BUILD) / f"{name}-role{role}"
        self.boot(helper, directory, "init")
        # Nonaligned old extent, different word-aligned candidate; valid Cortex vectors.
        image = (struct.pack("<II", 0x20040000, APP + 0x101)
                 + (b"\x11\x22\x33\x44" * 4998) + b"\x71\x82\x93\xa4")
        if not compress:
            image = image[:8] + hashlib.shake_256(b"nRF v4 raw").digest(len(image) - 8)
        canonical = descriptor(image, "xiao_nrf52840" if wrong_board and name == "solar"
                               else "sensecap_solar_p1" if wrong_board else package_board,
                               1 - role if wrong_role else role, 7)
        package = Package.build(image, canonical, ADMIN, ADMIN_PRIVATE.sign, compress=compress)
        job = JobStore.create(directory / "job", package, ADMIN, [TARGET], POLICY)
        self.addCleanup(job.close)
        driver = NrfDriver(directory, board, role)
        self.addCleanup(driver.close)
        clock = Clock()
        transport = DriverTransport([driver], clock)
        transport.auto_confirm = False
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        return directory, helper, board, role, package, job, driver, transport, scheduler, clock

    def boot(self, helper, directory, operation="boot"):
        result = subprocess.run([str(helper), operation, str(directory)], check=True,
                                capture_output=True, text=True, timeout=20)
        return json.loads(result.stdout)

    def media(self, directory):
        return ((directory / "qspi.bin").read_bytes(), (directory / "internal.bin").read_bytes())

    def persona_unchanged(self, baseline, current):
        qspi, internal = baseline
        q, i = current
        for begin, end in ((0xAD000, 0xC6000), (0x173000, 0x18C000), (0x194000, 0x200000)):
            self.assertEqual(q[begin:end], qspi[begin:end])
        # SoftDevice, installer, internal filesystem, marker/config and SDK tail.
        for begin, end in ((0, APP), (0xC4000, 0xFF000), (0xFF01C, 0x100000)):
            self.assertEqual(i[begin:end], internal[begin:end])
        self.assertEqual(i[0xFF004:0xFF008], internal[0xFF004:0xFF008])
        self.assertEqual(i[0xFF00C:0xFF01C], internal[0xFF00C:0xFF01C])

    def activate(self, fixture):
        directory, _, board, role, package, _, driver, transport, scheduler, clock = fixture
        ready = scheduler.stage(clock() + 1000)[0]
        self.assertEqual(ready.phase, Phase.READY)
        # A real process restart recovers the production journal/staging.
        driver.close()
        driver = NrfDriver(directory, board, role)
        self.addCleanup(driver.close)
        transport.drivers[:] = [driver]
        transport.queue.clear()
        ready = scheduler.stage(clock() + 1000)[0]
        self.assertEqual(ready.phase, Phase.READY)
        _, after = scheduler._command(Kind.ACTIVATE, TARGET, ready, clock() + 1000)
        self.assertEqual(after.phase, Phase.ACTIVATION_PENDING)
        self.assertFalse(after.installed(package))
        driver.close()
        qspi, _ = self.media(directory)
        command = qspi[COMMAND:COMMAND + 220]
        self.assertEqual(struct.unpack_from("<HH", command, 4), (3, 220))
        self.assertEqual(command[20:79], package.canonical)
        self.assertEqual(command[79:111], ADMIN)
        self.assertEqual(command[111:175], package.manifest[99:163])
        nonce = int.from_bytes(hashlib.sha256(
            b"MeshCore OTA boot transaction v4\0" + ready.transaction
            + struct.pack(">I", ready.generation) + package.canonical + ADMIN).digest()[:8], "big")
        self.assertEqual(struct.unpack_from("<Q", command, 12)[0], nonce)
        self.assertNotEqual(nonce, 0)
        self.assertEqual(qspi[:len(package.raw)], package.raw)
        return ready, nonce

    def fresh_scheduler(self, fixture):
        directory, _, board, role, _, _, _, transport, _, clock = fixture
        driver = NrfDriver(directory, board, role)
        self.addCleanup(driver.close)
        transport.drivers[:] = [driver]
        transport.queue.clear()
        scheduler = Scheduler(fixture[5], transport, clock=clock, sleep=clock.sleep)
        return driver, scheduler

    def test_real_trial_health_boot_confirmation_and_signed_floor_all_profiles(self):
        for name, _, _ in PROFILES:
            for role in (0, 1):
                for compress in (False, True):
                    with self.subTest(board=name, role=role, compressed=compress):
                        fixture = self.fixture(name, role, compress=compress)
                        directory, helper, _, _, package, _, _, _, _, clock = fixture
                        baseline = self.media(directory)
                        ready, nonce = self.activate(fixture)
                        activated = self.media(directory)
                        if compress:
                            self.assertTrue(any(chunk.codec != 0 for chunk in package.chunks))
                        trial = self.boot(helper, directory)
                        self.assertEqual((trial["phase"], trial["nonce"], trial["counter"]), (5, nonce, 7))
                        self.assertEqual((trial["floor"], trial["watchdogs"], trial["recovery"]), (0, 1, 0))
                        self.assertEqual(trial["installed_hash"], package.raw_hash.hex())
                        qspi, internal = self.media(directory)
                        self.assertEqual(qspi[:len(package.raw)], package.raw)
                        self.assertEqual(qspi[0xAB000:0xAD000], activated[0][0xAB000:0xAD000])
                        self.assertEqual(qspi[COMMAND:COMMAND + 8192], activated[0][COMMAND:COMMAND + 8192])
                        self.assertEqual(internal[APP:APP + len(package.raw)], package.raw)
                        self.assertEqual(qspi[0xC6000:0xC6000 + 8196], baseline[1][APP:APP + 8196])
                        driver, scheduler = self.fresh_scheduler(fixture)
                        status = scheduler.reconcile(clock() + 1000)[0]
                        self.assertEqual(status.phase, Phase.TRIAL)
                        self.assertEqual((status.transaction, status.generation),
                                         (ready.transaction, ready.generation))
                        self.assertFalse(status.installed(package))
                        driver.exchange("health")
                        status = scheduler.query(TARGET, clock() + 1000)
                        self.assertEqual(status.phase, Phase.TRIAL)
                        self.assertFalse(status.installed(package))
                        driver.close()
                        self.assertEqual(self.media(directory)[0][FLOOR:FLOOR + 8192],
                                         baseline[0][FLOOR:FLOOR + 8192])
                        confirmed = self.boot(helper, directory)
                        self.assertEqual((confirmed["phase"], confirmed["nonce"], confirmed["floor"]),
                                         (6, nonce, package.counter))
                        self.assertEqual(confirmed["hash"], package.raw_hash.hex())
                        self.assertEqual(confirmed["extent"], len(package.raw))
                        driver, scheduler = self.fresh_scheduler(fixture)
                        installed = scheduler.apply(clock() + 1000)[0]
                        self.assertTrue(installed.installed(package))
                        self.assertEqual((installed.transaction, installed.generation),
                                         (ready.transaction, ready.generation))
                        driver.close()
                        self.persona_unchanged(baseline, self.media(directory))
                        # Genuine cold boot remains confirmed, does not install/reconfirm.
                        before = self.media(directory)
                        self.assertEqual(self.boot(helper, directory)["phase"], 6)
                        self.assertEqual(self.media(directory), before)

    def test_corrupt_candidate_or_signature_is_rejected_by_real_boot_before_app_erase(self):
        for fault in ("candidate", "signature"):
            with self.subTest(fault=fault):
                fixture = self.fixture()
                directory, helper = fixture[:2]
                baseline = self.media(directory)
                self.activate(fixture)
                qspi, internal = self.media(directory)
                qspi = bytearray(qspi)
                if fault == "candidate":
                    qspi[129] ^= 0x01
                else:
                    qspi[COMMAND + 111] ^= 0x01
                    # Preserve record integrity, so actual Ed25519 must reject.
                    struct.pack_into("<I", qspi, COMMAND + 212,
                                     zlib.crc32(qspi[COMMAND:COMMAND + 212]))
                (directory / "qspi.bin").write_bytes(qspi)
                rejected = self.boot(helper, directory)
                self.assertNotEqual(rejected["phase"], 5)
                self.assertEqual(rejected["floor"], 0)
                self.assertEqual((rejected["app_erases"], rejected["settings_erases"]), (0, 0))
                self.assertEqual(self.media(directory)[1], internal)
                self.assertEqual(self.media(directory)[0][FLOOR:FLOOR + 8192],
                                 baseline[0][FLOOR:FLOOR + 8192])
                self.persona_unchanged(baseline, self.media(directory))

    def test_legacy_staging_metadata_does_not_block_boot_owned_trial_confirmation(self):
        fixture = self.fixture()
        directory, helper, _, _, package = fixture[:5]
        self.activate(fixture)
        qspi, _ = self.media(directory)
        qspi = bytearray(qspi)
        qspi[0xAB000:0xAD000] = b"\x33" * 8192
        (directory / "qspi.bin").write_bytes(qspi)
        self.assertEqual(self.boot(helper, directory)["phase"], 5)
        driver, scheduler = self.fresh_scheduler(fixture)
        clock = fixture[-1]
        self.assertEqual(scheduler.query(TARGET, clock() + 1000).phase, Phase.METADATA_FAULT)
        driver.exchange("health")
        driver.close()
        self.assertEqual(self.media(directory)[0][0xAB000:0xAD000], qspi[0xAB000:0xAD000])
        confirmed = self.boot(helper, directory)
        self.assertEqual((confirmed["phase"], confirmed["floor"]), (6, package.counter))
        self.assertEqual(confirmed["hash"], package.raw_hash.hex())

    def test_metadata_read_io_failure_blocks_trial_confirmation_even_after_reads_recover(self):
        fixture = self.fixture()
        directory, helper, board, role = fixture[:4]
        baseline = self.media(directory)
        self.activate(fixture)
        self.assertEqual(self.boot(helper, directory)["phase"], 5)
        driver = NrfDriver(directory, board, role, metadata_io_fault=True)
        self.addCleanup(driver.close)
        driver.exchange("health")
        driver.close()
        self.assertEqual(self.media(directory)[0][FLOOR:FLOOR + 8192],
                         baseline[0][FLOOR:FLOOR + 8192])
        self.assertNotEqual(self.boot(helper, directory)["phase"], 6)

    def test_wrong_confirmation_nonce_never_advances_floor_and_real_boot_rolls_back(self):
        fixture = self.fixture()
        directory, helper = fixture[:2]
        baseline = self.media(directory)
        _, nonce = self.activate(fixture)
        self.assertEqual(self.boot(helper, directory)["phase"], 5)
        driver, _ = self.fresh_scheduler(fixture)
        driver.exchange("health")
        driver.close()
        qspi, _ = self.media(directory)
        qspi = bytearray(qspi)
        # Damage the genuine health-produced token, retaining its valid CRC.
        slot = next(offset for offset in (CONFIRM, CONFIRM + 4096)
                    if qspi[offset:offset + 4] == struct.pack("<I", 0x58434E46))
        struct.pack_into("<Q", qspi, slot + 12, nonce ^ 1)
        struct.pack_into("<I", qspi, slot + 56, zlib.crc32(qspi[slot:slot + 56]))
        (directory / "qspi.bin").write_bytes(qspi)
        for _ in range(4):
            status = self.boot(helper, directory)
            self.assertEqual(status["floor"], 0)
            self.assertNotEqual(status["phase"], 6)
        self.assertEqual(status["phase"], 8)
        qspi, internal = self.media(directory)
        self.assertEqual(internal[APP:APP + 8196], baseline[1][APP:APP + 8196])
        self.assertEqual(internal[0xFF000:0x100000], baseline[1][0xFF000:0x100000])
        self.assertEqual(qspi[FLOOR:FLOOR + 8192], baseline[0][FLOOR:FLOOR + 8192])
        self.persona_unchanged(baseline, (qspi, internal))

    def test_board_and_role_bindings_reject_at_receiver_and_at_c_boot(self):
        for name, _, _ in PROFILES:
            for role in (0, 1):
                for mismatch in ("board", "role"):
                    with self.subTest(board=name, role=role, mismatch=mismatch):
                        fixture = self.fixture(name, role, wrong_board=mismatch == "board",
                                               wrong_role=mismatch == "role")
                        directory, _, _, _, package, _, driver, _, scheduler, clock = fixture
                        baseline = self.media(directory)
                        scheduler._send(Kind.MANIFEST, package.manifest, clock() + 1000)
                        self.assertEqual(scheduler.query(TARGET, clock() + 1000).phase, Phase.IDLE)
                        driver.close()
                        self.assertEqual(self.media(directory), baseline)
                        fixture = self.fixture(name, role)
                        directory, _ = fixture[:2]
                        baseline = self.media(directory)
                        self.activate(fixture)
                        other_name = ("solar" if name == "xiao" else "xiao") if mismatch == "board" else name
                        other_role = 1 - role if mismatch == "role" else role
                        rejected = self.boot(Path(BUILD) / f"{other_name}-role{other_role}", directory)
                        self.assertEqual(rejected["floor"], 0)
                        self.assertNotEqual(rejected["phase"], 5)
                        self.assertEqual((rejected["app_erases"], rejected["settings_erases"]), (0, 0))
                        self.assertEqual(self.media(directory)[1], baseline[1])
                        self.persona_unchanged(baseline, self.media(directory))


if __name__ == "__main__":
    unittest.main()
