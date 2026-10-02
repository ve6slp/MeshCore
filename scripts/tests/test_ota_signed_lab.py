import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ota_signed_lab as signed


ota, lab = signed.ota, signed.lab
TARGET_KEY = bytes(reversed(range(32)))


class Clock:
    def __init__(self):
        self.now = 100.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def image_manifest(counter=7, role=1, image=None):
    image = image or struct.pack("<II", 0x20040000, 0x27009) + b"\x55" * 245
    canonical = (struct.pack(">HHBII", 0x584E, 0x3430, role, 0x27000, len(image))
                 + hashlib.sha256(image).digest() + struct.pack(">IIHHH", counter, 1, 1, 1, 1))
    return image, canonical


def reply(candidate, phase, target=TARGET_KEY, result=ota.Result.OK, age=0,
          received=None, total=None):
    total = candidate.blocks if total is None else total
    received = total if received is None else received
    wire = (bytes([31, 1, ota.Op.STATUS, result, phase,
                   ota.SNAPSHOT_VALID | (ota.REMOTE if target != ota.LOCAL_TARGET else 0)])
            + target + candidate.manifest_hash
            + struct.pack(">HHIII", received, total, candidate.counter, age, 0))
    return ota.decode_reply(wire)


class Companion:
    """Existing ordinary companion query/sign protocol, not hardware evidence."""

    name = "client"

    def __init__(self):
        self.signer = Ed25519PrivateKey.generate()
        self.public_key = self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.commands = []
        self.pending = []
        self.radio = lab.NORMAL_RADIO
        self.boot = b"boot=unknown phase=unknown floor=unknown counter=0 verified=0 image=unknown"
        self.signed_data = None

    def command(self, payload, **kwargs):
        self.commands.append(payload)
        if payload[0] == lab.CMD_APP_START:
            frame = bytearray(58)
            frame[0], frame[1] = lab.RESP_SELF_INFO, lab.ADV_TYPE_CHAT
            frame[4:36] = self.public_key
            struct.pack_into("<II", frame, 48, *self.radio[:2])
            frame[56:58] = bytes(self.radio[2:])
            return bytes(frame) + b"captured-client"
        if payload[0] == lab.CMD_DEVICE_QUERY:
            frame = bytearray(82)
            frame[0], frame[1], frame[81] = lab.RESP_DEVICE_INFO, 13, lab.PATH_HASH_MODE
            return bytes(frame)
        if payload == bytes([66, 0]):
            return b"\x1d" + self.boot
        if payload == bytes([lab.CMD_SIGN_START]):
            return bytes([lab.RESP_SIGN_START, 0]) + struct.pack("<I", 176)
        if payload[0] == lab.CMD_SIGN_DATA:
            self.signed_data = payload[1:]
            return bytes([lab.RESP_OK])
        if payload == bytes([lab.CMD_SIGN_FINISH]):
            return bytes([lab.RESP_SIGNATURE]) + self.signer.sign(self.signed_data)
        raise AssertionError(f"unexpected companion command: {payload!r}")

    def poll(self, timeout=0):
        return None

    def take_pending(self, codes):
        taken = [entry for entry in self.pending if entry[1][0] in codes]
        self.pending = [entry for entry in self.pending if entry[1][0] not in codes]
        return taken

    def close(self):
        pass


class Target:
    name = "target"

    def __init__(self, companion):
        self.acl = {companion.public_key.hex(): 3, (b"\xaa" * 32).hex(): 1}
        self.phase = "unknown"
        self.counter = 0
        self.floor = 0
        self.lifecycle = None
        self.commands = []
        self.peer = companion
        self.key = TARGET_KEY
        self.radio = lab.NORMAL_RADIO

    def command(self, command, **kwargs):
        self.commands.append(command)
        values = {"get role": "repeater", "get public.key": self.key.hex(),
                  "get name": "captured-target",
                  "get radio": f"{self.radio[0] / 1000:g},{self.radio[1] / 1000:g},{self.radio[2]},{self.radio[3]}",
                  "get path.hash.mode": "2"}
        if command in values:
            return "> " + values[command]
        if command == "ota status":
            if self.lifecycle is not None:
                return self.lifecycle.pop(0)
            return (f"boot=unknown phase={self.phase} floor={self.floor} "
                    f"counter={self.counter} verified=0 image=unknown")
        if command == "advert.zerohop":
            self.peer.pending.append((signed.time.monotonic(), b"\x80" + self.key))
            return "OK - zerohop advert sent"
        raise AssertionError(f"unexpected repeater command: {command!r}")

    def get_acl(self):
        return dict(self.acl)

    def close(self):
        pass


class CampaignFixture:
    """Deterministic production-API replies for host orchestration tests only."""

    def __init__(self, pair, candidate):
        self.pair, self.candidate = pair, candidate
        self.local_valid = False
        self.ops = []
        self.reupload = None
        self.ready_reply = reply(candidate, ota.Phase.READY)
        self.error = None
        self.phase_requests = []
        self.remote_lifecycle = None

    def remaining(self, deadline):
        return min(10, deadline - signed.time.monotonic())

    def status(self, target=ota.LOCAL_TARGET, **kwargs):
        self.ops.append(ota.Op.STATUS)
        if self.local_valid:
            phase = ota.Phase.CACHE_SEALED if target == ota.LOCAL_TARGET else ota.Phase[self.pair.target.phase.upper()]
            if target != ota.LOCAL_TARGET and self.remote_lifecycle:
                phase = self.remote_lifecycle[0]
                if len(self.remote_lifecycle) > 1:
                    self.remote_lifecycle.pop(0)
                self.phase_requests.append(phase)
            return reply(self.candidate, phase, target=target)
        return ota.decode_reply(bytes([31, 1, ota.Op.STATUS, 0, 0, 0]) + bytes(64)
                                + struct.pack(">HHIII", 0, 0, 0, ota.AGE_UNKNOWN, 0))

    def cache(self, canonical, image, owner, deadline, reupload=False):
        self.ops.append(ota.Op.CACHE_BEGIN)
        self.reupload = reupload
        if self.error:
            raise self.error
        assert canonical == self.candidate.canonical and image == self.candidate.image
        assert owner == self.pair.client.public_key
        self.local_valid = True
        return reply(self.candidate, ota.Phase.CACHE_SEALED, target=ota.LOCAL_TARGET)

    def start(self, targets, body, mode, deadline):
        self.ops.extend([ota.Op.ADD_TARGET, ota.Op.START])
        assert targets == [self.pair.target.key]
        self.body, self.mode = body, mode
        self.pair.target.phase, self.pair.target.counter = "ready", self.candidate.counter

    def wait_phase(self, target, phase, manifest_hash, counter, since, deadline):
        self.phase_requests.append(phase)
        assert target == self.pair.target.key
        assert manifest_hash == self.candidate.manifest_hash and counter == self.candidate.counter
        if phase == ota.Phase.READY:
            return self.ready_reply
        return reply(self.candidate, phase, target=target)

    def commit(self, target, canonical, deadline):
        self.ops.append(ota.Op.COMMIT)
        self.pair.target.lifecycle = [
            f"boot=trial phase=trial floor=0 counter={self.candidate.counter} verified=0 image=unknown",
            f"boot=confirmed phase=installed floor={self.candidate.counter} "
            f"counter={self.candidate.counter} verified=1 image={self.candidate.metadata['image_sha256']}"]
        self.remote_lifecycle = [ota.Phase.TRIAL, ota.Phase.INSTALLED]
        return self.ready_reply


class ProductTarget(Target):
    def __init__(self, companion):
        super().__init__(companion)
        self.installed = None

    def command(self, command, **kwargs):
        if command == "ota status" and self.installed is not None:
            self.commands.append(command)
            return (f"boot=confirmed phase={self.phase} floor={self.floor} counter={self.counter} "
                    f"verified=1 image={hashlib.sha256(self.installed.image).hexdigest()}")
        return super().command(command, **kwargs)


class ProductCompanion(Companion):
    """In-memory wire/storage peer for the real Uploader, with real signing."""

    def __init__(self):
        super().__init__()
        self.target = ProductTarget(self)
        self.local = self.target_candidate = None
        self.local_phase = ota.Phase.UNKNOWN
        self.owner = self.public_key
        self.purpose = "cache"
        self.blocks = {}
        self.packets = []
        self.baseline_path = None
        self.status_mutator = None

    def empty_reply(self, op, result, target):
        remote = target != ota.LOCAL_TARGET and op != ota.Op.ADD_TARGET
        return (bytes([31, 1, op, result, 0, ota.REMOTE if remote else 0])
                + target + bytes(32) + struct.pack(">HHIII", 0, 0, 0, ota.AGE_UNKNOWN, 0))

    def snapshot_reply(self, op, result, target, candidate, phase):
        if candidate is None:
            return self.empty_reply(op, result, target)
        total = candidate.blocks
        received = len(self.blocks) if target == ota.LOCAL_TARGET else total
        digest = hashlib.sha256(candidate.image).digest() if op == ota.Op.ABORT else candidate.manifest_hash
        remote = target != ota.LOCAL_TARGET and op != ota.Op.ADD_TARGET
        return (bytes([31, 1, op, result, phase, 1 | (ota.REMOTE if remote else 0)])
                + target + digest + struct.pack(">HHIII", received, total, candidate.counter, 0, 0))

    def write_frame(self, packet):
        self.packets.append(packet)
        assert packet[0] == 66
        op, body = ota.Op(packet[1]), packet[2:]
        target, result = ota.LOCAL_TARGET, ota.Result.OK
        if op == ota.Op.STATUS:
            target = body
        elif op == ota.Op.CACHE_BEGIN:
            assert len(packet) == 158
            if self.baseline_path is not None:
                assert self.baseline_path.exists(), "candidate mutation preceded baseline capture"
            flags, owner, canonical, signature = packet[2], packet[3:35], packet[35:94], packet[94:]
            assert owner == self.public_key
            self.signer.public_key().verify(signature, canonical)
            if self.local is not None and self.local_phase != ota.Phase.ABORTED:
                same = self.local.canonical == canonical and self.owner == owner and self.purpose == "cache"
                if flags or not same:
                    result = ota.Result.BUSY
            elif self.local_phase == ota.Phase.ABORTED and flags != 1:
                result = ota.Result.DENIED
            if result == ota.Result.OK:
                if self.local is None or self.local.canonical != canonical or flags:
                    self.local = signed.Candidate(canonical, bytes(struct.unpack_from(">I", canonical, 9)[0]),
                                                  {"counter": struct.unpack_from(">I", canonical, 45)[0]})
                    self.blocks = {}
                    self.local_phase = ota.Phase.RECEIVING
                self.owner, self.purpose = owner, "cache"
        elif op == ota.Op.CACHE_PUT:
            index, length = struct.unpack_from(">HB", body)
            assert len(body[3:]) == length
            self.blocks[index] = body[3:]
        elif op == ota.Op.CACHE_SEAL:
            image = b"".join(self.blocks[i] for i in range(len(self.blocks)))
            ota.validate_image(self.local.canonical, image)
            self.local = signed.Candidate(self.local.canonical, image, self.local.metadata)
            self.local_phase = ota.Phase.CACHE_SEALED
            self.boot = (f"boot=unknown phase=cache-sealed floor=unknown counter={self.local.counter} "
                         "verified=0 image=unknown").encode()
        elif op == ota.Op.ABORT:
            assert len(packet) == 66 and body[:32] == ota.LOCAL_TARGET
            assert body[32:] == hashlib.sha256(self.local.image).digest()
            self.local_phase = ota.Phase.ABORTED
            self.boot = (f"boot=unknown phase=aborted floor=unknown counter={self.local.counter} "
                         "verified=0 image=unknown").encode()
        elif op == ota.Op.ADD_TARGET:
            target = body
            assert body == self.target.key
        elif op == ota.Op.START:
            assert self.baseline_path.exists()
            self.target_candidate = self.local
            self.target.phase, self.target.counter = "ready", self.local.counter
        elif op == ota.Op.COMMIT:
            target = body[:32]
            assert target == self.target.key
            assert body[32:64] == self.target_candidate.manifest_hash
            assert struct.unpack_from(">I", body, 64)[0] == self.target_candidate.counter
            self.target.installed = self.target_candidate
            self.target.phase = "installed"
            self.target.counter = self.target.floor = self.target_candidate.counter
        else:
            raise AssertionError(f"unexpected wire opcode {op}")
        if op == ota.Op.COMMIT or result != ota.Result.OK:
            response = self.empty_reply(op, result, target)
        elif op == ota.Op.STATUS and target != ota.LOCAL_TARGET:
            phase = ota.Phase[self.target.phase.upper()]
            response = self.snapshot_reply(op, result, target, self.target_candidate, phase)
        else:
            response = self.snapshot_reply(op, result, target, self.local, self.local_phase)
        if self.status_mutator and op == ota.Op.STATUS and target == ota.LOCAL_TARGET:
            response = self.status_mutator(response)
        self.pending.append((signed.time.monotonic(), response))


class SignedLabTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).resolve().parents[2] / ".tmp" / ("signed-host-" + uuid.uuid4().hex)
        self.directory.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.directory)
        image, canonical = image_manifest()
        self.image_path, self.manifest_path = self.directory / "image.bin", self.directory / "canonical.bin"
        self.image_path.write_bytes(image)
        self.manifest_path.write_bytes(canonical)
        self.arguments = [
            "--manifest", str(self.manifest_path), "--image", str(self.image_path),
            "--image-sha256", hashlib.sha256(image).hexdigest(), "--counter", "7",
            "--provenance", "immutable-test-build", "--commissioning-evidence", "test-commissioning"]
        self.args = signed.parser().parse_args(
            ["--artifact-dir", str(self.directory / "stage"), "stage"] + self.arguments)
        self.candidate = signed.load_candidate(self.args)
        self.clock = Clock()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(signed.time, "monotonic", self.clock.monotonic).start()
        mock.patch.object(signed.time, "sleep", self.clock.sleep).start()
        self.output = io.StringIO()
        mock.patch("sys.stdout", self.output).start()
        self.evidence = lab.Evidence(self.args.artifact_dir)
        self.addCleanup(self.evidence.events.close)
        self.client = Companion()
        self.target = Target(self.client)
        self.pair = SimpleNamespace(client=self.client, target=self.target,
                                    reenumerate=mock.Mock(), close=mock.Mock())
        self.uploader = CampaignFixture(self.pair, self.candidate)
        self.deadline = self.clock.now + 300

    def run_stage(self):
        return signed.stage(self.pair, self.uploader, self.candidate,
                            self.args, self.evidence, self.deadline)

    def prepare_commit(self):
        self.run_stage()
        args = signed.parser().parse_args(
            ["--artifact-dir", str(self.directory / "commit"), "commit", "--qualified-commit",
             "--ready-record", str(self.evidence.directory / "ready.json")] + self.arguments)
        evidence = lab.Evidence(args.artifact_dir)
        self.addCleanup(evidence.events.close)
        return args, evidence

    def product_pair(self, counter=6):
        node = ProductCompanion()
        pair = SimpleNamespace(client=node, target=node.target, reenumerate=mock.Mock(), close=mock.Mock())
        uploader = ota.Uploader(node, self.evidence)
        image, canonical = image_manifest(counter=counter)
        uploader.cache(canonical, image, node.public_key, self.clock.now + 300)
        return node, pair, uploader

    def candidate_inputs(self, counter, image=None):
        image, canonical = image_manifest(counter=counter, image=image)
        self.image_path.write_bytes(image)
        self.manifest_path.write_bytes(canonical)
        self.args.counter, self.args.image_sha256 = counter, hashlib.sha256(image).hexdigest()
        return signed.load_candidate(self.args)

    def product_stage(self, node, pair, uploader, candidate, label):
        evidence = lab.Evidence(self.directory / label)
        self.addCleanup(evidence.events.close)
        uploader.evidence = evidence
        node.baseline_path = evidence.directory / "baseline.json"
        return signed.stage(pair, uploader, candidate, self.args, evidence, self.clock.now + 300)

    def test_real_uploader_replaces_only_explicitly_zero_aborted_cache(self):
        for different_content in (False, True):
            with self.subTest(different_content=different_content):
                node, pair, uploader = self.product_pair()
                old = node.local
                uploader.abort(ota.LOCAL_TARGET, hashlib.sha256(old.image).digest())
                abort = node.packets[-1]
                self.assertEqual(abort[:34], bytes([66, ota.Op.ABORT]) + bytes(32))
                image = old.image[:-1] + b"\x66" if different_content else old.image
                candidate = self.candidate_inputs(7, image)
                before = len(node.packets)
                record = self.product_stage(node, pair, uploader, candidate, f"aborted-{different_content}")
                campaign = node.packets[before:]
                begin = next(packet for packet in campaign if packet[1] == ota.Op.CACHE_BEGIN)
                self.assertEqual(len(begin), 158)
                self.assertEqual(begin[2], 1)
                self.assertEqual(begin[3:35], node.public_key)
                self.assertEqual(begin[35:94], candidate.canonical)
                node.signer.public_key().verify(begin[94:], candidate.canonical)
                self.assertEqual(record["local_cache_before"]["phase"], "ABORTED")
                self.assertEqual(record["local_cache_before"]["hash"], old.manifest_hash.hex())
                self.assertEqual(record["ready"]["counter"], 7)
                self.assertFalse(record["auto_commit"])
                self.assertNotIn(ota.Op.ABORT, [packet[1] for packet in campaign])
                self.assertNotIn(ota.Op.COMMIT, [packet[1] for packet in campaign])

    def test_real_uploader_sequential_modes_and_rising_counters_use_operator_abort_only(self):
        node, pair, uploader = self.product_pair()
        for mode, counter in (("direct", 7), ("directed", 8), ("background", 9)):
            with self.subTest(mode=mode):
                uploader.abort(ota.LOCAL_TARGET, hashlib.sha256(node.local.image).digest())
                candidate = self.candidate_inputs(counter)
                self.args.mode, self.args.channel = mode, 2 if mode == "background" else 255
                before = len(node.packets)
                record = self.product_stage(node, pair, uploader, candidate, mode)
                campaign = node.packets[before:]
                begin = next(packet for packet in campaign if packet[1] == ota.Op.CACHE_BEGIN)
                self.assertEqual(begin[2], 1)
                self.assertEqual(record["ready"]["counter"], counter)
                self.assertEqual(record["floor"], counter - 1 if counter > 7 else 0)
                self.assertNotIn(ota.Op.ABORT, [packet[1] for packet in campaign])
                self.assertNotIn(ota.Op.COMMIT, [packet[1] for packet in campaign])
                # Explicit operator COMMIT in the model, never sent by stage().
                uploader.commit(pair.target.key, candidate.canonical, self.clock.now + 300)
                self.assertEqual(node.target.floor, counter)

    def test_local_abort_proof_missing_stale_wrong_scope_or_counter_is_refused(self):
        for defect in ("missing", "stale", "scope", "counter", "hash", "total", "phase", "cli-failed"):
            with self.subTest(defect=defect):
                node, pair, uploader = self.product_pair()
                uploader.abort(ota.LOCAL_TARGET, hashlib.sha256(node.local.image).digest())
                if defect == "cli-failed":
                    node.boot = node.boot.replace(b"phase=aborted", b"phase=failed")
                else:
                    def corrupt(frame, defect=defect):
                        if defect == "missing":
                            return node.empty_reply(ota.Op.STATUS, ota.Result.OK, ota.LOCAL_TARGET)
                        data = bytearray(frame)
                        if defect == "stale":
                            struct.pack_into(">I", data, 78, 1000)
                        elif defect == "scope":
                            data[5] |= ota.REMOTE
                        elif defect == "counter":
                            struct.pack_into(">I", data, 74, 5)
                        elif defect == "hash":
                            data[38:70] = bytes(32)
                        elif defect == "total":
                            data[70:74] = bytes(4)
                        elif defect == "phase":
                            data[4] = ota.Phase.CACHE_SEALED
                        return bytes(data)
                    node.status_mutator = corrupt
                before = len(node.packets)
                with self.assertRaises(signed.QualificationError):
                    self.product_stage(node, pair, uploader, self.candidate, "refused-" + defect)
                self.assertNotIn(ota.Op.CACHE_BEGIN, [packet[1] for packet in node.packets[before:]])
                self.assertNotIn(ota.Op.ABORT, [packet[1] for packet in node.packets[before:]])

    def test_local_abort_must_remain_consistent_after_fresh_baseline(self):
        node, pair, uploader = self.product_pair()
        uploader.abort(ota.LOCAL_TARGET, hashlib.sha256(node.local.image).digest())
        calls = 0

        def changed(frame):
            nonlocal calls
            calls += 1
            if calls > 1:
                frame = frame[:38] + b"\xbb" * 32 + frame[70:]
            return frame

        node.status_mutator = changed
        before = len(node.packets)
        with self.assertRaisesRegex(signed.QualificationError, "ABORT changed after baseline"):
            self.product_stage(node, pair, uploader, self.candidate, "abort-changed")
        self.assertTrue(node.baseline_path.exists())
        self.assertNotIn(ota.Op.CACHE_BEGIN, [packet[1] for packet in node.packets[before:]])

    def test_local_abort_proof_disappearing_after_baseline_stays_refused(self):
        node, pair, uploader = self.product_pair()
        uploader.abort(ota.LOCAL_TARGET, hashlib.sha256(node.local.image).digest())
        calls = 0

        def missing(frame):
            nonlocal calls
            calls += 1
            return frame if calls == 1 else node.empty_reply(ota.Op.STATUS, ota.Result.OK, ota.LOCAL_TARGET)

        node.status_mutator = missing
        before = len(node.packets)
        with self.assertRaisesRegex(signed.QualificationError, "ABORT is missing"):
            self.product_stage(node, pair, uploader, self.candidate, "abort-disappeared")
        self.assertTrue(node.baseline_path.exists())
        self.assertNotIn(ota.Op.CACHE_BEGIN, [packet[1] for packet in node.packets[before:]])

    def test_nonaborted_owner_content_counter_and_purpose_remain_locked(self):
        for conflict in ("counter", "content", "owner", "purpose"):
            with self.subTest(conflict=conflict):
                node, pair, uploader = self.product_pair(counter=7)
                candidate = self.candidate
                if conflict == "counter":
                    candidate = self.candidate_inputs(8)
                elif conflict == "content":
                    candidate = self.candidate_inputs(7, node.local.image[:-1] + b"x")
                elif conflict == "owner":
                    node.owner = b"\xaa" * 32
                else:
                    node.purpose = "remote-install"
                before = len(node.packets)
                with self.assertRaises(ota.UploaderError):
                    self.product_stage(node, pair, uploader, candidate, "locked-" + conflict)
                campaign = node.packets[before:]
                for packet in campaign:
                    if packet[1] == ota.Op.CACHE_BEGIN:
                        self.assertEqual(packet[2], 0)
                self.assertNotIn(ota.Op.CACHE_PUT, [packet[1] for packet in campaign])
                self.assertNotIn(ota.Op.START, [packet[1] for packet in campaign])
                self.assertNotIn(ota.Op.ABORT, [packet[1] for packet in campaign])

    def test_all_three_modes_use_actual_identity_full_image_and_never_commit(self):
        for mode, channel in (("directed", 255), ("direct", 255), ("background", 2)):
            with self.subTest(mode=mode):
                self.args.mode, self.args.channel = mode, channel
                self.target.phase, self.target.counter = "unknown", 0
                self.uploader.local_valid = False
                evidence = lab.Evidence(self.directory / mode)
                self.addCleanup(evidence.events.close)
                started = self.clock.now
                record = signed.stage(self.pair, self.uploader, self.candidate, self.args,
                                      evidence, self.clock.now + 300)
                self.assertTrue((evidence.directory / "baseline.json").exists())
                self.assertTrue((evidence.directory / "ready.json").exists())
                self.assertFalse(record["auto_commit"])
                self.assertEqual(record["target"]["pubkey"], TARGET_KEY.hex())
                self.assertEqual(record["client"]["pubkey"], self.client.public_key.hex())
                self.assertEqual(record["ready"]["received"], self.candidate.blocks)
                self.assertEqual(record["profile"]["duty_milli_percent"], 2000)
                self.assertNotIn(ota.Op.COMMIT, self.uploader.ops)
                self.assertNotIn(ota.Op.ABORT, self.uploader.ops)
                self.assertFalse(self.uploader.reupload)
                expected = ota.start_body(mode, channel, 908525 if mode == "direct" else 0,
                                          60000 if mode == "direct" else 0, 2000)
                self.assertEqual(self.uploader.body, expected)
                self.assertEqual(self.clock.now - started, 62 if mode == "direct" else 0)
                self.assertFalse(any(command.startswith("set") or command == "reboot"
                                     for command in self.target.commands))

    def test_smoke_is_explicit_and_never_recorded_as_two_percent_acceptance(self):
        self.args.duty_milli_percent = 100000
        with self.assertRaisesRegex(signed.QualificationError, "requires"):
            signed.profile(self.args)
        self.args.supervised_full_image_smoke = True
        record = self.run_stage()
        self.assertEqual(record["profile"]["budget_class"],
                         "100_percent_supervised_smoke_not_2_percent_acceptance")
        self.assertIn('"measured_duty_evidence_available": false', self.output.getvalue())

    def test_95000_requires_supervision_and_real_uploader_records_250khz_pair(self):
        self.args.duty_milli_percent = 95000
        with self.assertRaisesRegex(signed.QualificationError, "requires --supervised"):
            signed.profile(self.args)
        self.args.supervised_full_image_smoke = True
        for mode in ("direct", "directed", "background"):
            with self.subTest(mode=mode):
                node = ProductCompanion()
                node.radio = node.target.radio = (907525, 250000, 7, 5)
                pair = SimpleNamespace(client=node, target=node.target)
                uploader = ota.Uploader(node, self.evidence)
                self.args.mode, self.args.channel = mode, 2 if mode == "background" else 255
                record = self.product_stage(node, pair, uploader, self.candidate, "95-percent-" + mode)
                start = next(packet for packet in node.packets if packet[1] == ota.Op.START)
                self.assertEqual(struct.unpack_from(">I", start, 10)[0], 95000)
                self.assertEqual(record["profile"]["budget_class"],
                                 "95_percent_supervised_smoke_not_2_percent_acceptance")
                self.assertEqual(record["client"]["bw_hz"], 250000)
                self.assertEqual(record["target"]["bw_hz"], 250000)
                self.assertEqual(record["ready"]["counter"], self.candidate.counter)
                self.assertEqual(record["candidate"]["image_sha256"], self.args.image_sha256)
                self.assertNotIn(ota.Op.COMMIT, [packet[1] for packet in node.packets])
                self.assertNotIn(ota.Op.ABORT, [packet[1] for packet in node.packets])
                self.assertNotIn(lab.CMD_SET_RADIO_PARAMS, [packet[0] for packet in node.commands])
                self.assertFalse(any(command.startswith("set") or command == "reboot"
                                     for command in node.target.commands))

    def test_invalid_duties_fail_before_hardware_even_with_supervision(self):
        for value in (-1, 0, 100001):
            for supervised in (False, True):
                flags = ["--supervised-full-image-smoke"] if supervised else []
                with self.subTest(value=value, supervised=supervised), mock.patch.object(signed, "Pair") as opened:
                    with self.assertRaises(signed.QualificationError):
                        signed.main(["--artifact-dir", str(self.directory / "unused"), "stage"]
                                    + self.arguments + ["--duty-milli-percent", str(value)] + flags)
                    opened.assert_not_called()
        with mock.patch("sys.stderr", io.StringIO()), mock.patch.object(signed, "Pair") as opened:
            with self.assertRaises(SystemExit):
                signed.main(["--artifact-dir", str(self.directory / "unused"), "stage"]
                            + self.arguments + ["--duty-milli-percent", "95000.5",
                                                "--supervised-full-image-smoke"])
            opened.assert_not_called()

    def test_radio_bandwidth_mismatch_or_unapproved_profile_is_not_admitted(self):
        for client_radio, target_radio in (
                ((907525, 250000, 7, 5), (907525, 62500, 7, 5)),
                ((907525, 500000, 7, 5), (907525, 500000, 7, 5)),
                ((908525, 250000, 7, 5), (908525, 250000, 7, 5)),
                ((907525, 250000, 5, 5), (907525, 250000, 5, 5))):
            with self.subTest(client=client_radio, target=target_radio):
                self.client.radio, self.target.radio = client_radio, target_radio
                with self.assertRaises(signed.QualificationError):
                    self.run_stage()
                self.assertEqual(self.uploader.ops, [])

    def test_observed_250khz_configuration_must_remain_preserved_after_ready(self):
        self.client.radio = self.target.radio = (907525, 250000, 7, 5)
        original = self.uploader.start

        def changed(*values):
            original(*values)
            self.client.radio = self.target.radio = (907525, 62500, 7, 5)

        self.uploader.start = changed
        with self.assertRaisesRegex(signed.QualificationError, "differs from saved baseline"):
            self.run_stage()
        baseline = json.loads((self.evidence.directory / "baseline.json").read_text())
        self.assertEqual(baseline["client"]["bw_hz"], 250000)
        self.assertEqual(baseline["target"]["bw_hz"], 250000)
        self.assertFalse((self.evidence.directory / "ready.json").exists())
        self.assertNotIn(ota.Op.COMMIT, self.uploader.ops)

    def test_95000_250khz_explicit_commit_keeps_existing_install_proof_contract(self):
        self.args.duty_milli_percent = 95000
        self.args.supervised_full_image_smoke = True
        self.client.radio = self.target.radio = (907525, 250000, 7, 5)
        args, evidence = self.prepare_commit()
        outcome = signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
        self.assertEqual(outcome["profile"]["duty_milli_percent"], 95000)
        self.assertEqual(outcome["profile"]["budget_class"],
                         "95_percent_supervised_smoke_not_2_percent_acceptance")
        self.assertTrue(outcome["identity_config_acl_preserved"])
        self.assertEqual(outcome["lifecycle"]["floor"], self.candidate.counter)
        self.assertEqual(outcome["lifecycle"]["image"], self.args.image_sha256)
        self.assertEqual(self.uploader.ops.count(ota.Op.COMMIT), 1)
        self.assertFalse(outcome["usb_reset_sent"])
        self.assertFalse(outcome["measured_duty_evidence_available"])

    def test_candidate_role_counter_hash_vectors_and_provenance_admission(self):
        for field, value in (("counter", 8), ("image_sha256", "00" * 32),
                             ("provenance", " "), ("commissioning_evidence", "")):
            old = getattr(self.args, field)
            with self.subTest(field=field), self.assertRaises(signed.QualificationError):
                setattr(self.args, field, value)
                signed.load_candidate(self.args)
            setattr(self.args, field, old)
        image, canonical = image_manifest(role=0)
        self.manifest_path.write_bytes(canonical)
        with self.assertRaisesRegex(signed.QualificationError, "role-1"):
            signed.load_candidate(self.args)
        image, canonical = image_manifest(image=bytes(200))
        self.image_path.write_bytes(image)
        self.manifest_path.write_bytes(canonical)
        self.args.image_sha256 = hashlib.sha256(image).hexdigest()
        with self.assertRaisesRegex(signed.QualificationError, "vectors"):
            signed.load_candidate(self.args)

    def test_lifecycle_parser_rejects_unknown_formats_and_unproven_image_shape(self):
        for text in ("OTA unsupported", "boot=trial", "boot=foo phase=idle floor=0 counter=0 verified=0 image=unknown",
                     "boot=confirmed phase=installed floor=7 counter=7 verified=1 image=unknown",
                     "boot=unknown phase=idle floor=4294967296 counter=0 verified=0 image=unknown"):
            with self.subTest(text=text), self.assertRaises(signed.QualificationError):
                signed.boot_status(text)

    def test_missing_admin_and_unproven_floor_never_mutate_permissions_or_stage(self):
        self.target.acl[self.client.public_key.hex()] = 2
        with self.assertRaisesRegex(signed.QualificationError, "ADMIN ACL"):
            self.run_stage()
        self.assertEqual(self.uploader.ops, [])
        self.target.acl[self.client.public_key.hex()] = 3
        self.target.floor = "unknown"
        with self.assertRaisesRegex(signed.QualificationError, "floor is unproven"):
            self.run_stage()
        self.assertEqual(self.uploader.ops, [])
        self.assertFalse((self.evidence.directory / "baseline.json").exists())

    def test_target_conflict_and_current_companion_trial_fail_without_abort(self):
        self.target.phase, self.target.counter = "ready", 8
        with self.assertRaisesRegex(signed.QualificationError, "conflicting candidate"):
            self.run_stage()
        self.target.phase, self.target.counter = "unknown", 0
        self.client.boot = b"boot=trial phase=trial floor=0 counter=7 verified=0 image=unknown"
        with self.assertRaisesRegex(signed.QualificationError, "companion current trial"):
            self.run_stage()
        self.assertEqual(self.uploader.ops, [])

    def test_different_cache_and_incomplete_ready_preserve_baseline_without_reupload(self):
        self.uploader.local_valid = True
        self.uploader.status = mock.Mock(return_value=reply(
            signed.Candidate(self.candidate.canonical + b"x", self.candidate.image, self.candidate.metadata),
            ota.Phase.CACHE_SEALED, target=ota.LOCAL_TARGET))
        with self.assertRaisesRegex(signed.QualificationError, "explicit separate local ABORT"):
            self.run_stage()
        self.assertTrue((self.evidence.directory / "baseline.json").exists())
        self.assertNotIn(ota.Op.CACHE_BEGIN, self.uploader.ops)
        (self.evidence.directory / "baseline.json").unlink()
        self.uploader.status = mock.Mock(return_value=reply(
            self.candidate, ota.Phase.CACHE_SEALED, target=ota.LOCAL_TARGET))
        self.uploader.ready_reply = reply(self.candidate, ota.Phase.READY, received=1)
        with self.assertRaisesRegex(signed.QualificationError, "incomplete"):
            self.run_stage()
        self.assertFalse((self.evidence.directory / "ready.json").exists())
        self.assertNotIn(ota.Op.ABORT, self.uploader.ops)

    def test_upload_failure_and_same_cache_resume_preserve_progress(self):
        self.uploader.error = TimeoutError("transfer progress preserved")
        with self.assertRaises(TimeoutError):
            self.run_stage()
        baseline = self.evidence.directory / "baseline.json"
        self.assertTrue(baseline.exists())
        self.assertFalse((self.evidence.directory / "ready.json").exists())
        self.args.baseline_record = baseline
        self.uploader.error, self.uploader.local_valid = None, True
        self.target.phase, self.target.counter = "receiving", 7
        second = lab.Evidence(self.directory / "resume")
        self.addCleanup(second.events.close)
        record = signed.stage(self.pair, self.uploader, self.candidate,
                              self.args, second, self.deadline)
        self.assertFalse(record["auto_commit"])
        self.assertNotIn(ota.Op.ABORT, self.uploader.ops)

    def test_fresh_resume_accepts_progress_to_ready_without_waiting_for_old_phase(self):
        uploader = ota.Uploader(self.client, self.evidence)
        uploader.status = mock.Mock(return_value=reply(self.candidate, ota.Phase.READY))
        observed = signed.fresh_candidate(uploader, self.candidate, TARGET_KEY, self.deadline)
        self.assertEqual(observed.phase, ota.Phase.READY)
        uploader.status.assert_called_once()

    def test_explicit_commit_requires_trial_running_hash_floor_provenance_and_restored_acl(self):
        args, evidence = self.prepare_commit()
        outcome = signed.commit(self.pair, self.uploader, self.candidate,
                                args, evidence, self.deadline)
        self.assertEqual(self.uploader.ops.count(ota.Op.COMMIT), 1)
        self.assertEqual(self.pair.reenumerate.call_count, 1)
        self.assertEqual(outcome["lifecycle"]["image"], self.candidate.metadata["image_sha256"])
        self.assertEqual(outcome["lifecycle"]["floor"], 7)
        self.assertTrue(outcome["trial_observed"])
        self.assertIn(ota.Phase.TRIAL, self.uploader.phase_requests)
        self.assertEqual(outcome["remote_trial"]["phase"], "TRIAL")
        self.assertEqual(outcome["remote_trial"]["hash"], self.candidate.manifest_hash.hex())
        self.assertTrue(outcome["remote_install_qualified"])
        self.assertFalse(outcome["usb_reset_sent"])
        self.assertTrue(outcome["identity_config_acl_preserved"])
        self.assertFalse(outcome["measured_duty_evidence_available"])
        self.assertFalse(outcome["multihop_fleet_powercut_qualified"])
        self.assertTrue((evidence.directory / "installed.json").exists())
        self.assertNotIn("reboot", self.target.commands)

    def test_missing_remote_commit_reboot_is_explicitly_blocked_without_usb_reset(self):
        args, evidence = self.prepare_commit()
        self.pair.reenumerate.side_effect = TimeoutError("target stayed in application")
        with self.assertRaisesRegex(signed.QualificationError, "manual USB reboot would be assisted"):
            signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
        self.pair.reenumerate.assert_called_once_with(self.clock.now + args.reboot_timeout)
        self.assertEqual(evidence.summary["measurements"]["outcome"],
                         "blocked_remote_commit_did_not_reboot")
        self.assertNotIn("reboot", self.target.commands)
        self.assertFalse((evidence.directory / "installed.json").exists())
        self.assertTrue(args.ready_record.exists())
        self.assertIn('"usb_reset_sent": false', self.output.getvalue())

    def test_physical_text_trial_without_fresh_remote_trial_cannot_qualify_install(self):
        args, evidence = self.prepare_commit()
        original = self.uploader.commit

        def missed(*values):
            ack = original(*values)
            self.uploader.status = mock.Mock(return_value=reply(self.candidate, ota.Phase.READY))
            return ack

        self.uploader.commit = missed
        with self.assertRaisesRegex(signed.QualificationError, "completed evidence preserved"):
            signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
        outcome = json.loads((evidence.directory / "installed.json").read_text())
        self.assertEqual(outcome["outcome"], "remote_trial_not_observed")
        self.assertFalse(outcome["remote_install_qualified"])
        self.assertTrue(outcome["identity_config_acl_preserved"])
        self.assertTrue(outcome["ordinary_peer_received"])

    def test_stale_remote_trial_is_not_a_lifecycle_proof(self):
        args, evidence = self.prepare_commit()
        original = self.uploader.commit

        def stale(*values):
            ack = original(*values)
            self.uploader.status = mock.Mock(return_value=reply(self.candidate, ota.Phase.TRIAL, age=60000))
            return ack

        self.uploader.commit = stale
        with self.assertRaisesRegex(signed.QualificationError, "remote_install_qualified=false"):
            signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
        self.assertNotIn("trial", evidence.summary["measurements"])
        self.assertFalse(evidence.summary["measurements"]["installed"]["trial_observed"])

    def test_remote_already_installed_at_two_percent_collects_all_proofs_before_gap(self):
        args, evidence = self.prepare_commit()
        original = self.uploader.commit

        def instant(*values):
            ack = original(*values)
            self.uploader.remote_lifecycle = [ota.Phase.INSTALLED]
            return ack

        self.uploader.commit = instant
        with self.assertRaisesRegex(signed.QualificationError, "completed evidence preserved"):
            signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
        outcome = json.loads((evidence.directory / "installed.json").read_text())
        self.assertEqual(outcome["profile"]["duty_milli_percent"], 2000)
        self.assertEqual(outcome["outcome"], "remote_trial_not_observed")
        self.assertTrue(outcome["trial_observation_incomplete"])
        self.assertFalse(outcome["remote_install_qualified"])
        self.assertIsNone(outcome["remote_trial"])
        self.assertEqual(outcome["remote_installed"]["phase"], "INSTALLED")
        self.assertEqual(outcome["lifecycle"]["floor"], self.candidate.counter)
        self.assertTrue(outcome["identity_config_acl_preserved"])
        self.assertTrue(outcome["ordinary_peer_received"])
        self.assertEqual(evidence.summary["measurements"]["trial_observation_incomplete"]["reason"],
                         "remote_already_installed")
        self.assertEqual(self.uploader.ops.count(ota.Op.COMMIT), 1)

    def test_local_unobserved_trial_also_collects_all_installed_and_preservation_proofs(self):
        args, evidence = self.prepare_commit()
        original = self.uploader.commit

        def instant(*values):
            ack = original(*values)
            self.target.lifecycle.pop(0)
            return ack

        self.uploader.commit = instant
        with self.assertRaisesRegex(signed.QualificationError, "remote_install_qualified=false"):
            signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
        outcome = json.loads((evidence.directory / "installed.json").read_text())
        self.assertFalse(outcome["trial_observed"])
        self.assertTrue(outcome["ordinary_peer_received"])
        self.assertTrue(outcome["identity_config_acl_preserved"])

    def test_trial_observation_io_denied_and_failed_are_not_missed_timing(self):
        self.uploader.status = mock.Mock()
        for error in (TimeoutError("no matching OTA reply for STATUS"),
                      OSError(5, "storage I/O"), ota.UploaderError("STATUS: DENIED")):
            with self.subTest(error=error):
                self.uploader.status.side_effect = error
                with self.assertRaises(type(error)):
                    signed.remote_trial(self.uploader, self.candidate, TARGET_KEY,
                                        self.clock.now, self.deadline)
        self.uploader.status.side_effect = None
        self.uploader.status.return_value = reply(self.candidate, ota.Phase.FAILED)
        with self.assertRaisesRegex(signed.QualificationError, "failed/ABORTed"):
            signed.remote_trial(self.uploader, self.candidate, TARGET_KEY, self.clock.now, self.deadline)
        self.assertNotIn("trial_observation_incomplete", self.evidence.summary["measurements"])

    def test_incomplete_trial_still_refuses_wrong_installed_counter_hash_or_floor(self):
        for defect in ("counter", "hash", "floor"):
            with self.subTest(defect=defect):
                status = (f"boot=confirmed phase=installed floor=7 counter=7 verified=1 "
                          f"image={self.candidate.metadata['image_sha256']}")
                if defect == "counter":
                    status = status.replace("counter=7", "counter=8")
                elif defect == "floor":
                    status = status.replace("floor=7", "floor=0")
                else:
                    status = status.replace(self.candidate.metadata["image_sha256"], "aa" * 32)
                self.target.lifecycle = [status]
                with self.assertRaisesRegex(signed.QualificationError, "actual immutable running image"):
                    signed.observe_install(self.pair, self.uploader, self.candidate,
                                           TARGET_KEY, self.evidence, self.deadline)
        self.assertNotIn("installed", self.evidence.summary["measurements"])

    def test_incomplete_trial_does_not_mask_acl_or_peer_failure(self):
        for failure in ("acl", "peer", "identity", "config"):
            with self.subTest(failure=failure):
                self.target.phase, self.target.counter = "ready", 7
                self.target.lifecycle = None
                args = signed.parser().parse_args(
                    ["--artifact-dir", str(self.directory / ("bad-" + failure)), "commit", "--qualified-commit",
                     "--ready-record", str(self.evidence.directory / "ready.json")] + self.arguments)
                if not args.ready_record.exists():
                    self.target.phase, self.target.counter = "unknown", 0
                    self.run_stage()
                evidence = lab.Evidence(args.artifact_dir)
                self.addCleanup(evidence.events.close)
                original = CampaignFixture.commit.__get__(self.uploader)

                def instant(*values):
                    ack = original(*values)
                    self.uploader.remote_lifecycle = [ota.Phase.INSTALLED]
                    return ack

                self.uploader.commit = instant
                if failure == "acl":
                    with mock.patch.object(self.target, "get_acl", side_effect=[dict(self.target.acl), {}]):
                        with self.assertRaisesRegex(signed.QualificationError, "ACL did not survive"):
                            signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
                elif failure == "peer":
                    with mock.patch.object(signed, "ordinary_peer", side_effect=TimeoutError("missing peer")):
                        with self.assertRaisesRegex(TimeoutError, "missing peer"):
                            signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
                else:
                    before_info = lab.repeater_info(self.target)
                    after_info = dict(before_info)
                    after_info["pubkey" if failure == "identity" else "name"] = (
                        (b"\xbb" * 32).hex() if failure == "identity" else "changed-after-install")
                    with mock.patch.object(lab, "repeater_info", side_effect=[before_info, after_info]):
                        with self.assertRaisesRegex(signed.QualificationError, "readbacks changed across"):
                            signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
                self.assertFalse((evidence.directory / "installed.json").exists())

    def test_production_denied_or_uncertain_commit_never_observes_or_requests_a_reboot(self):
        args, evidence = self.prepare_commit()
        for result in (ota.Result.DENIED, ota.Result.IO_ERROR):
            with self.subTest(result=result):
                uploader = ota.Uploader(self.client, evidence)
                uploader.status = mock.Mock(side_effect=lambda target=ota.LOCAL_TARGET, **kwargs:
                    reply(self.candidate, ota.Phase.CACHE_SEALED if target == ota.LOCAL_TARGET
                          else ota.Phase.READY, target=target))
                denial = ota.decode_reply(
                    bytes([31, 1, ota.Op.COMMIT, result, 0, ota.REMOTE]) + TARGET_KEY + bytes(32)
                    + struct.pack(">HHIII", 0, 0, 0, ota.AGE_UNKNOWN, 0))
                uploader.exchange = mock.Mock(return_value=denial)
                with self.assertRaisesRegex(ota.UploaderError, result.name):
                    signed.commit(self.pair, uploader, self.candidate, args, evidence, self.deadline)
                uploader.exchange.assert_called_once()
        self.pair.reenumerate.assert_not_called()
        self.assertNotIn("reboot", self.target.commands)
        self.assertFalse((evidence.directory / "installed.json").exists())

    def test_nonfinite_commit_observation_timeouts_fail_before_any_hardware_open(self):
        args, evidence = self.prepare_commit()
        for option, value in (("--reboot-timeout", "nan"), ("--trial-timeout", "-1"),
                              ("--install-timeout", "inf")):
            with self.subTest(option=option), mock.patch.object(signed, "Pair") as opened, \
                    mock.patch("sys.stderr", io.StringIO()):
                with self.assertRaises(SystemExit):
                    signed.main(["--artifact-dir", str(self.directory / "unused"), "commit",
                                 "--qualified-commit", "--ready-record", str(args.ready_record)]
                                + self.arguments + [option, value])
                opened.assert_not_called()

    def test_changed_acl_or_counter_prevents_commit(self):
        args, evidence = self.prepare_commit()
        self.target.acl[(b"\xbb" * 32).hex()] = 1
        with self.assertRaisesRegex(signed.QualificationError, "acl differs"):
            signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
        self.assertNotIn(ota.Op.COMMIT, self.uploader.ops)

    def test_commit_ack_never_suffices_wrong_running_hash_fails(self):
        self.pair.reenumerate = mock.Mock()
        self.target.lifecycle = [
            "boot=trial phase=trial floor=0 counter=7 verified=0 image=unknown",
            "boot=confirmed phase=installed floor=7 counter=7 verified=1 image=" + "aa" * 32]
        with self.assertRaisesRegex(signed.QualificationError, "actual immutable running image"):
            signed.observe_install(self.pair, self.uploader, self.candidate,
                                   TARGET_KEY, self.evidence, self.deadline)
        self.assertFalse((self.evidence.directory / "installed.json").exists())

    def test_missing_trial_records_actual_installed_but_does_not_qualify_lifecycle(self):
        self.target.lifecycle = [
            "boot=confirmed phase=installed floor=7 counter=7 verified=1 image="
            + self.candidate.metadata["image_sha256"]]
        signed.observe_install(self.pair, self.uploader, self.candidate,
                               TARGET_KEY, self.evidence, self.deadline)
        self.assertFalse(self.evidence.summary["measurements"]["installed"]["trial_observed"])

    def test_role_resolution_refuses_pine_before_opening_either_port(self):
        with mock.patch.object(signed.lab_device, "resolve", side_effect=[
                SimpleNamespace(serial=signed.APPROVED["client"], by_id="/dev/serial/by-id/client"),
                SimpleNamespace(serial="49C5BAF21EEF44A1", by_id="/dev/serial/by-id/pine")]), \
                mock.patch.object(lab, "FramedSerial") as opened:
            with self.assertRaisesRegex(signed.QualificationError, "unapproved target"):
                signed.Pair(self.evidence, self.deadline)
        opened.assert_not_called()

    def test_reenumeration_requires_real_absence_and_resolves_new_stable_path(self):
        pair = object.__new__(signed.Pair)
        pair.evidence, pair.target, pair.deadline = self.evidence, mock.Mock(), self.deadline
        device = SimpleNamespace(serial=signed.APPROVED["target"], mode="app",
                                 by_id="/dev/serial/by-id/target-reenumerated")
        with mock.patch.object(signed.lab_device, "discover", side_effect=[[device], [], [device]]), \
                mock.patch.object(signed.lab_device, "resolve", return_value=device), \
                mock.patch.object(lab, "RepeaterSerial") as opened:
            pair.reenumerate(self.clock.now + 2)
        opened.assert_called_once_with("target", str(device.by_id), self.evidence)
        pair.target = mock.Mock()
        with mock.patch.object(signed.lab_device, "discover", return_value=[device]):
            with self.assertRaisesRegex(TimeoutError, "observably disconnect"):
                pair.reenumerate(self.clock.now + 0.2)

    def test_production_signing_uses_actual_companion_key_and_denial_stops_cache(self):
        sent = []

        def deny(payload):
            sent.append(payload)
            # Real new-operation no-snapshot DENIED reply, not an ACK shortcut.
            self.client.pending.append((self.clock.now,
                bytes([31, 1, payload[1], ota.Result.DENIED, 0, 0]) + bytes(64)
                + struct.pack(">HHIII", 0, 0, 0, ota.AGE_UNKNOWN, 0)))

        self.client.write_frame = deny
        uploader = ota.Uploader(self.client, self.evidence)
        with self.assertRaisesRegex(ota.UploaderError, "DENIED"):
            uploader.cache(self.candidate.canonical, self.candidate.image,
                           self.client.public_key, self.deadline)
        self.assertEqual(self.client.signed_data, self.candidate.canonical)
        self.assertEqual([packet[1] for packet in sent], [ota.Op.CACHE_BEGIN])
        self.assertNotIn(ota.Op.ABORT, [packet[1] for packet in sent])

    def test_production_stale_ready_cannot_authorize_commit(self):
        uploader = ota.Uploader(self.client, self.evidence)
        uploader.status = mock.Mock(return_value=reply(self.candidate, ota.Phase.READY, age=60000))
        uploader.exchange = mock.Mock()
        with self.assertRaisesRegex(TimeoutError, "fresh READY"):
            uploader.commit(TARGET_KEY, self.candidate.canonical, self.clock.now + 0.5)
        uploader.exchange.assert_not_called()

    def test_unknown_product_result_preserves_baseline_and_never_starts_or_commits(self):
        sent = []

        def answer(payload):
            sent.append(payload)
            result = 255 if payload[1] == ota.Op.CACHE_BEGIN else ota.Result.OK
            self.client.pending.append((self.clock.now,
                bytes([31, 1, payload[1], result, 0, 0]) + bytes(64)
                + struct.pack(">HHIII", 0, 0, 0, ota.AGE_UNKNOWN, 0)))

        self.client.write_frame = answer
        with self.assertRaisesRegex(ota.UploaderError, "unknown OTA reply"):
            signed.stage(self.pair, ota.Uploader(self.client, self.evidence), self.candidate,
                         self.args, self.evidence, self.deadline)
        self.assertEqual([packet[1] for packet in sent], [ota.Op.STATUS, ota.Op.STATUS, ota.Op.CACHE_BEGIN])
        self.assertTrue((self.evidence.directory / "baseline.json").exists())
        self.assertFalse((self.evidence.directory / "ready.json").exists())

    def test_helper_queries_and_acl_are_bounded_before_any_expired_write(self):
        node = mock.Mock()
        bounded = signed.DeadlineSerial(node, self.clock.now + 0.25)
        bounded.command(b"\x01")
        node.command.assert_called_once_with(b"\x01", timeout=0.25)
        bounded.get_acl()
        node.get_acl.assert_called_once_with(timeout=0.25)
        self.clock.sleep(0.25)
        with self.assertRaisesRegex(TimeoutError, "progress preserved"):
            bounded.command(b"\x42")
        self.assertEqual(node.command.call_count, 1)

    def test_no_expected_peer_is_a_failure_not_a_radio_settings_success(self):
        self.target.command = mock.Mock(return_value="OK - zerohop advert sent")
        self.client.poll = mock.Mock(side_effect=lambda timeout=0: self.clock.sleep(max(0.01, timeout)))
        with self.assertRaisesRegex(TimeoutError, "fresh ordinary advert"):
            signed.ordinary_peer(self.pair, TARGET_KEY, self.evidence, self.clock.now + 0.5)

    def test_post_reboot_acl_loss_does_not_write_an_installed_qualification(self):
        args, evidence = self.prepare_commit()
        self.target.get_acl = mock.Mock(side_effect=[dict(self.target.acl), {}])
        with self.assertRaisesRegex(signed.QualificationError, "ACL did not survive"):
            signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
        self.assertEqual(self.uploader.ops.count(ota.Op.COMMIT), 1)
        self.assertIn("installed", evidence.summary["measurements"])
        self.assertFalse((evidence.directory / "installed.json").exists())

    def test_postcommit_permission_errors_are_not_treated_as_disconnects(self):
        self.target.command = mock.Mock(side_effect=PermissionError(13, "permission denied"))
        with self.assertRaises(PermissionError):
            signed.observe_install(self.pair, self.uploader, self.candidate,
                                   TARGET_KEY, self.evidence, self.deadline)
        self.assertEqual(self.pair.reenumerate.call_count, 1)

    def test_invalid_profile_and_existing_artifacts_fail_before_hardware_open(self):
        with mock.patch.object(signed, "Pair") as opened:
            with self.assertRaisesRegex(signed.QualificationError, "new artifact directory"):
                signed.main(["--artifact-dir", str(self.evidence.directory), "stage"] + self.arguments)
            with self.assertRaises(ValueError):
                signed.main(["--artifact-dir", str(self.directory / "unused"), "stage"]
                            + self.arguments + ["--mode", "background"])
        opened.assert_not_called()

    def test_fatal_saves_error_and_closes_ports_without_abort(self):
        artifact = self.directory / "fatal"
        self.uploader.error = ota.UploaderError("BAD_REQUEST")
        with mock.patch.object(signed, "Pair", return_value=self.pair), \
                mock.patch.object(ota, "Uploader", return_value=self.uploader):
            with self.assertRaisesRegex(ota.UploaderError, "BAD_REQUEST"):
                signed.main(["--artifact-dir", str(artifact), "stage"] + self.arguments)
        self.pair.close.assert_called_once()
        summary = json.loads((artifact / "summary.json").read_text())
        self.assertIn("BAD_REQUEST", summary["error"])
        self.assertTrue((artifact / "baseline.json").exists())
        self.assertNotIn(ota.Op.ABORT, self.uploader.ops)

    def test_explicit_commit_parser_has_no_automatic_or_force_path(self):
        with mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                signed.parser().parse_args(["--artifact-dir", "unused", "commit",
                    "--ready-record", "ready.json"] + self.arguments)
        with self.assertRaisesRegex(FileExistsError, ""):
            signed.write_record(self.image_path, {})


if __name__ == "__main__":
    unittest.main()
