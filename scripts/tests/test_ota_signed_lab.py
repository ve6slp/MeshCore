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
BENCH_ADVERT_KEY = bytes.fromhex("f76c046e6f463a02c71df1e5ed4d78fa0bd118e05810c3012a672ad0d10b6bb6")
BENCH_LOG_RX_ADVERT = bytes.fromhex(
    "8837fb1200f76c046e6f463a02c71df1e5ed4d78fa0bd118e05810c3012a672ad0d10b6bb64"
    "a9944668b4b509a4209a91ae83864fbda27066be45a54fe803f24298aa5682757f67ec91b18ddd"
    "e735ec1b2ff1b3f1025e82df84628478b27c2e4222f8fb8affe58c80a920000000000000000"
    "4f54412d4c41422d544152474554")


def new_advert_push(key):
    return (b"\x8a" + key + bytes([2, 0, 255]) + bytes(64)
            + b"OTA-LAB-TARGET".ljust(32, b"\x00") + struct.pack("<IIII", 1, 0, 0, 1))


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
          received=None, total=None, generation=1):
    total = candidate.blocks if total is None else total
    received = total if received is None else received
    wire = (bytes([31, 2, ota.Op.STATUS, result, phase,
                   ota.SNAPSHOT_VALID | (ota.REMOTE if target != ota.LOCAL_TARGET else 0)])
            + target + candidate.manifest_hash
            + struct.pack(">HHIII", received, total, candidate.counter, age, 0)
            + struct.pack(">I", generation))
    return ota.decode_reply(wire)


def radio_diagnostic(radio, **overrides):
    values = {"f": radio[0], "b": radio[1], "s": radio[2], "c": radio[3], "v": 1, "a": 0,
              "e": 0, "d": 0, "r": 0, "td": 0, "tr": 0, "h": 1, "x": 0, "af": 0,
              "n": int(signed.time.monotonic() * 1000) & 0xFFFFFFFF}
    values.update(overrides)
    decimal = {"f", "b", "s", "c", "v", "a", "h"}
    return "src=driver-applied " + " ".join(
        f"{key}={value}" if key in decimal else f"{key}={value:08X}" for key, value in values.items())


def budget_diagnostic(**overrides):
    values = {"n": int(signed.time.monotonic() * 1000) & 0xFFFFFFFF, "w": 3600000, "b": 72000,
              "u": 0, "tx": 0, "to": 0, "af": 0}
    values.update(overrides)
    return " ".join(f"{key}={value:08X}" for key, value in values.items())


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
        self.app_name = "captured-client"
        self.packet_stats = dict.fromkeys(signed.PACKET_STATS_FIELDS, 0)
        self.radio_stats = {"noise_floor": -110, "last_rssi": -100, "last_snr": 3.0,
                            "tx_air_secs": 0, "rx_air_secs": 0}
        self.boot = b"boot=unknown phase=unknown floor=unknown counter=0 verified=0 image=unknown"
        self.signed_data = None
        self.measurement_overrides = {}
        self.budget_share = 2000

    def command(self, payload, **kwargs):
        self.commands.append(payload)
        if payload[0] == lab.CMD_APP_START:
            if len(payload) < 8:
                raise AssertionError("APP_START requires seven reserved bytes before the application name")
            frame = bytearray(58)
            frame[0], frame[1] = lab.RESP_SELF_INFO, lab.ADV_TYPE_CHAT
            frame[4:36] = self.public_key
            struct.pack_into("<II", frame, 48, *self.radio[:2])
            frame[56:58] = bytes(self.radio[2:])
            return bytes(frame) + self.app_name.encode("utf-8")
        if payload[0] == lab.CMD_DEVICE_QUERY:
            frame = bytearray(82)
            frame[0], frame[1], frame[81] = lab.RESP_DEVICE_INFO, 13, lab.PATH_HASH_MODE
            return bytes(frame)
        if payload == bytes([56, 2]):
            return bytes([24, 2]) + struct.pack("<7I", *(self.packet_stats[field]
                                                       for field in signed.PACKET_STATS_FIELDS))
        if payload == bytes([56, 1]):
            values = self.radio_stats
            return bytes([24, 1]) + struct.pack("<hbbII", values["noise_floor"], values["last_rssi"],
                int(values["last_snr"] * 4), values["tx_air_secs"], values["rx_air_secs"])
        if payload == bytes([66, 0]):
            return b"\x1d" + self.boot
        if payload == bytes([66, 0, 3]):
            text = self.measurement_overrides.get("radio", radio_diagnostic(self.radio))
            return b"\x1d" + text.encode("ascii")
        if payload == bytes([66, 0, 4]):
            text = self.measurement_overrides.get(
                "budget", budget_diagnostic(b=3600000 * self.budget_share // 100000))
            return b"\x1d" + text.encode("ascii")
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
        self.app_name = "captured-target"
        self.packet_stats = dict.fromkeys(signed.PACKET_STATS_FIELDS, 0)
        self.radio_stats = {"noise_floor": -110, "last_rssi": -100, "last_snr": 3.0,
                            "tx_air_secs": 0, "rx_air_secs": 0}
        self.measurement_overrides = {}

    def command(self, command, **kwargs):
        self.commands.append(command)
        values = {"get role": "repeater", "get public.key": self.key.hex(),
                  "get name": self.app_name,
                  "get radio": f"{self.radio[0] / 1000:g},{self.radio[1] / 1000:g},{self.radio[2]},{self.radio[3]}",
                  "get path.hash.mode": "2"}
        if command in values:
            return "> " + values[command]
        if command == "stats-packets":
            return json.dumps(self.packet_stats)
        if command == "stats-radio":
            return json.dumps(self.radio_stats)
        if command == "ota status":
            if self.lifecycle is not None:
                return self.lifecycle.pop(0)
            return (f"boot=unknown phase={self.phase} floor={self.floor} "
                    f"counter={self.counter} verified=0 image=unknown")
        if command == "ota radio":
            return self.measurement_overrides.get("radio", radio_diagnostic(self.radio))
        if command == "ota budget":
            return self.measurement_overrides.get("budget", budget_diagnostic())
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
            if target != ota.LOCAL_TARGET and self.pair.target.phase == "ready" and not self.remote_lifecycle:
                return self.ready_reply
            phase = ota.Phase.CACHE_SEALED if target == ota.LOCAL_TARGET else ota.Phase[self.pair.target.phase.upper()]
            if target != ota.LOCAL_TARGET and self.remote_lifecycle:
                phase = self.remote_lifecycle[0]
                if len(self.remote_lifecycle) > 1:
                    self.remote_lifecycle.pop(0)
                self.phase_requests.append(phase)
            return reply(self.candidate, phase, target=target)
        return ota.decode_reply(bytes([31, 2, ota.Op.STATUS, 0, 0, 0]) + bytes(64)
                                + struct.pack(">HHIII", 0, 0, 0, ota.AGE_UNKNOWN, 0) + bytes(4))

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
        self.pair.client.budget_share = struct.unpack_from(">I", body, 8)[0]
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
        self.generation = 0

    def empty_reply(self, op, result, target):
        remote = target != ota.LOCAL_TARGET and op != ota.Op.ADD_TARGET
        return (bytes([31, 2, op, result, 0, ota.REMOTE if remote else 0])
                + target + bytes(32) + struct.pack(">HHIII", 0, 0, 0, ota.AGE_UNKNOWN, 0) + bytes(4))

    def snapshot_reply(self, op, result, target, candidate, phase):
        if candidate is None:
            return self.empty_reply(op, result, target)
        total = candidate.blocks
        received = len(self.blocks) if target == ota.LOCAL_TARGET else total
        digest = candidate.manifest_hash
        remote = target != ota.LOCAL_TARGET and op != ota.Op.ADD_TARGET
        return (bytes([31, 2, op, result, phase, 1 | (ota.REMOTE if remote else 0)])
                + target + digest + struct.pack(">HHIII", received, total, candidate.counter, 0, 0)
                + struct.pack(">I", self.generation))

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
                    self.generation = (self.generation + 1) & 0xFFFFFFFF
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
            assert len(packet) == 70 and body[:32] == ota.LOCAL_TARGET
            assert body[32:64] == hashlib.sha256(self.local.image).digest()
            generation = struct.unpack_from(">I", body, 64)[0]
            allowed = {self.generation}
            if self.local_phase == ota.Phase.ABORTED:
                allowed.add((self.generation - 1) & 0xFFFFFFFF)
            if generation not in allowed:
                result = ota.Result.MISMATCH
            else:
                if self.local_phase != ota.Phase.ABORTED:
                    self.generation = (self.generation + 1) & 0xFFFFFFFF
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
            self.budget_share = struct.unpack_from(">I", body, 8)[0]
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

    def observer(self, mode="directed", duty=2000, interval=5):
        self.args.mode, self.args.channel = mode, 2 if mode == "background" else 255
        self.args.duty_milli_percent = duty
        self.args.supervised_full_image_smoke = duty != 2000
        _, requested = signed.profile(self.args)
        baseline = signed.capture(self.pair, self.candidate, self.evidence, self.deadline)
        observer = signed.TransferMeasurements(self.pair, self.candidate, requested, baseline,
                                               self.evidence, self.clock.now + 10000, interval)
        observer.observe("baseline")
        return observer

    def diagnostic_state(self, direct=False, **fields):
        profile = (908525, 250000, 5, 5) if direct else lab.NORMAL_RADIO
        text = radio_diagnostic(profile, a=int(direct), **fields)
        self.client.measurement_overrides["radio"] = text
        self.target.measurement_overrides["radio"] = text

    def test_baseline_periodic_end_diagnostics_are_recorded_without_claiming_instant_ready_duty(self):
        record = self.run_stage()
        observations = self.evidence.summary["measurements"]["transfer_measurements"]
        self.assertEqual([sample["phase"] for sample in observations["samples"]], ["baseline", "ready", "end"])
        self.assertTrue(observations["samples"][1]["fresh_remote_progress"])
        self.assertEqual(observations["samples"][1]["remote"]["hash"], self.candidate.manifest_hash.hex())
        self.assertEqual(record["transfer_measurements"]["measurement_outcome"], "incomplete")
        self.assertFalse(record["transfer_measurements"]["sampled_two_percent_budget_qualified"])
        self.assertFalse(record["transfer_measurements"]["duty_guarantee_verified"])
        self.assertNotIn(ota.Op.COMMIT, self.uploader.ops)
        self.assertNotIn(ota.Op.ABORT, self.uploader.ops)

    def test_qualification_rejects_all_driver_timeout_and_lost_accounting_counters_before_caching(self):
        for role, kind, field in (
            ("client", "radio", "x"), ("target", "radio", "af"),
            ("client", "budget", "to"), ("target", "budget", "af"),
        ):
            with self.subTest(role=role, kind=kind, field=field):
                node = self.client if role == "client" else self.target
                node.measurement_overrides[kind] = (
                    radio_diagnostic(lab.NORMAL_RADIO, **{field: 1}) if kind == "radio"
                    else budget_diagnostic(**{field: 1}))
                with self.assertRaises(signed.QualificationError):
                    self.run_stage()
                self.assertNotIn(ota.Op.CACHE_BEGIN, self.uploader.ops)
                self.assertNotIn(ota.Op.ABORT, self.uploader.ops)
                node.measurement_overrides.clear()
                (self.evidence.directory / "baseline.json").unlink()

    def test_timeout_lost_accounting_and_radio_fault_after_start_remain_fatal_with_progress_preserved(self):
        original = self.uploader.start
        def start(*args):
            result = original(*args)
            self.target.measurement_overrides["budget"] = budget_diagnostic(af=1)
            return result
        self.uploader.start = start
        with self.assertRaisesRegex(signed.QualificationError, "lost-accounting"):
            self.run_stage()
        self.assertTrue((self.evidence.directory / "baseline.json").exists())
        self.assertFalse((self.evidence.directory / "ready.json").exists())
        self.assertNotIn(ota.Op.ABORT, self.uploader.ops)
        self.assertNotIn(ota.Op.COMMIT, self.uploader.ops)

    def test_measurement_parser_and_real_io_failures_are_not_success_shaped_fallbacks(self):
        self.client.measurement_overrides["radio"] = "src=preferences f=907525"
        with self.assertRaises(ValueError):
            self.run_stage()
        self.assertNotIn(ota.Op.CACHE_BEGIN, self.uploader.ops)
        self.client.measurement_overrides.clear()
        (self.evidence.directory / "baseline.json").unlink()
        original = self.client.command
        def command(payload, **kwargs):
            if payload == bytes.fromhex("420004"):
                raise ConnectionError("client serial disconnected")
            return original(payload, **kwargs)
        self.client.command = command
        with self.assertRaisesRegex(ConnectionError, "disconnected"):
            self.run_stage()
        self.assertNotIn(ota.Op.CACHE_BEGIN, self.uploader.ops)

    def test_two_direct_applied_intervals_restore_and_fresh_bitmap_continuation_are_exposed(self):
        observer = self.observer("direct")
        self.diagnostic_state(True, d=1, td=100000, e=160000)
        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 99)
        self.clock.sleep(60)
        self.diagnostic_state(False, d=1, r=1, td=100000, tr=160000)
        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 99)
        self.clock.sleep(15)
        self.diagnostic_state(True, d=2, r=1, td=175000, tr=160000, e=235000)
        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=2), 99)
        result = observer.report()
        self.assertTrue(result["two_applied_intervals_restoration_bitmap_continuation_observed"])
        self.assertFalse(result["measurement_qualified"])
        self.assertIn("fresh_direct_handshake_token_ack_not_exposed_by_existing_status_api",
                      result["incomplete_reasons"])
        self.assertFalse(observer.record["fresh_handshake_wire_observed"])
        self.assertFalse(result["hardware_phy_readback"])

    def test_literal_production_direct_250khz_restores_captured_normal_62500(self):
        observer = self.observer("direct")
        self.assertEqual(observer.baseline["client"]["bw_hz"], 62500)
        self.assertEqual(observer.baseline["target"]["bw_hz"], 62500)
        direct = ("src=driver-applied f=908525 b=250000 s=5 c=5 v=1 a=1 e=00027100 "
                  "d=00000001 r=00000000 td=000186A0 tr=00000000 h=1 x=00000000 af=00000000 n=000186A0")
        for node in (self.client, self.target):
            node.measurement_overrides["radio"] = direct
        sample = observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 99)
        for role in ("client", "target"):
            radio = sample["nodes"][role]["radio"]
            self.assertEqual(tuple(radio[key] for key in ("f", "b", "s", "c")), (908525, 250000, 5, 5))
        self.clock.sleep(60)
        restored = ("src=driver-applied f=907525 b=62500 s=7 c=5 v=1 a=0 e=00000000 "
                    "d=00000001 r=00000001 td=000186A0 tr=00027100 h=1 x=00000000 af=00000000 n=00027100")
        for node in (self.client, self.target):
            node.measurement_overrides["radio"] = restored
        sample = observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 99)
        for role in ("client", "target"):
            self.assertEqual(sample["nodes"][role]["radio"]["b"], 62500)
        self.target.measurement_overrides["radio"] = restored.replace("b=62500", "b=250000")
        with self.assertRaisesRegex(signed.QualificationError, "differs from saved baseline"):
            observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=2), 99)

    def test_direct_frequency_follows_requested_campaign_not_fixed_default(self):
        observer = self.observer("direct")
        observer.requested["frequency_khz"] = 915525
        self.diagnostic_state(True, f=915525, d=1, td=100000, e=160000)
        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 99)
        self.diagnostic_state(True, f=908525, d=1, td=100000, e=160000)
        with self.assertRaisesRegex(signed.QualificationError, "differs from saved baseline"):
            observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=2), 99)

    def test_direct_old_bitmap_before_restore_cannot_prove_continuation(self):
        observer = self.observer("direct")
        self.diagnostic_state(True, d=1, td=100000, e=160000)
        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 90)
        self.clock.sleep(60)
        self.diagnostic_state(False, d=1, r=1, td=100000, tr=160000)
        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 90)
        self.clock.sleep(15)
        self.diagnostic_state(True, d=2, r=1, td=175000, tr=160000, e=235000)
        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=2, age=20000), 90)
        self.assertFalse(observer.report()["two_applied_intervals_restoration_bitmap_continuation_observed"])

    def test_indefinite_direct_renewal_without_observed_normal_restoration_is_incomplete(self):
        observer = self.observer("direct")
        self.diagnostic_state(True, d=1, td=100000, e=160000)
        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 99)
        self.clock.sleep(10)
        self.diagnostic_state(True, d=2, td=110000, e=170000)
        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=2), 99)
        self.assertFalse(observer.report()["two_applied_intervals_restoration_bitmap_continuation_observed"])

    def test_direct_expired_or_overlong_lease_wrong_sf_and_on_mesh_direct_active_are_fatal(self):
        for mode, expiry, spreading in (("direct", 100000, 5), ("direct", 160001, 5),
                                       ("direct", 160000, 7), ("directed", 160000, 5)):
            with self.subTest(mode=mode, expiry=expiry, sf=spreading):
                observer = self.observer(mode)
                self.diagnostic_state(True, d=1, td=100000, e=expiry, s=spreading)
                with self.assertRaises(signed.QualificationError):
                    observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 99)
                self.client.measurement_overrides.clear()
                self.target.measurement_overrides.clear()

    def test_device_clock_and_applied_counter_regression_are_refused_but_uint32_wrap_is_valid(self):
        observer = self.observer()
        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 99)
        self.diagnostic_state(False, n=1)
        with self.assertRaisesRegex(signed.QualificationError, "clock"):
            observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=2), 99)
        self.assertEqual(signed.ms_delta(4, 0xFFFFFFFC), 8)

    def test_budget_window_used_and_share_consistency_are_required_not_only_totals(self):
        for values in ({"w": 0}, {"w": 100, "b": 101}, {"u": 72001}, {"b": 3600000}):
            with self.subTest(values=values):
                observer = self.observer()
                self.client.measurement_overrides["budget"] = budget_diagnostic(**values)
                if values == {"b": 3600000}:
                    observer.observe("transfer", reply(self.candidate, ota.Phase.READY), 99)
                    with self.assertRaisesRegex(signed.QualificationError, "requested share"):
                        observer.report()
                else:
                    with self.assertRaisesRegex(signed.QualificationError, "window/budget/used"):
                        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 99)
                self.client.measurement_overrides.clear()

    def test_95_percent_samples_are_smoke_only_even_with_real_progress_and_independent_peer(self):
        observer = self.observer(duty=95000)
        for received in (1, 2, self.candidate.blocks):
            self.client.measurement_overrides["budget"] = budget_diagnostic(b=3420000, u=100)
            observer.observe("ready" if received == self.candidate.blocks else "transfer",
                             reply(self.candidate, ota.Phase.RECEIVING, received=received), 99)
            self.clock.sleep(5)
        observer.peer = {"witness": {"source": "companion_advert_push", "target": TARGET_KEY.hex()}}
        observer.observe("end")
        result = observer.report()
        self.assertTrue(result["measurement_qualified"])
        self.assertFalse(result["sampled_two_percent_budget_qualified"])
        self.assertFalse(result["duty_guarantee_verified"])
        self.assertEqual(result["requested_duty_milli_percent"], 95000)

    def test_two_percent_before_after_only_and_sampling_gaps_do_not_qualify(self):
        observer = self.observer()
        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 99)
        self.clock.sleep(3600)
        self.client.measurement_overrides["budget"] = budget_diagnostic(u=100)
        observer.observe("ready", reply(self.candidate, ota.Phase.READY), 99)
        observer.peer = {"witness": {"source": "companion_advert_push"}}
        observer.observe("end")
        result = observer.report()
        self.assertFalse(result["sampled_two_percent_budget_qualified"])
        self.assertFalse(result["full_window_periodic_coverage_observed"])

    def test_full_window_periodic_two_percent_software_coverage_is_scoped_not_phy_guarantee(self):
        observer = self.observer()
        for index in range(721):
            self.client.measurement_overrides["budget"] = budget_diagnostic(u=100)
            received = 1 if index < 720 else 2
            observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=received), 99)
            if index < 720:
                self.clock.sleep(5)
        observer.peer = {"witness": {"source": "companion_advert_push"}}
        observer.observe("end")
        result = observer.report()
        self.assertTrue(result["sampled_two_percent_budget_qualified"])
        self.assertTrue(result["full_window_periodic_coverage_observed"])
        self.assertFalse(result["duty_guarantee_verified"])

    def test_real_existing_peer_witness_is_freshly_bracketed_during_on_mesh_receiving(self):
        observer = self.observer(duty=95000)
        observer.interval = 0.1
        self.client.budget_share = 95000
        self.uploader.local_valid = True
        self.target.phase, self.target.counter = "receiving", self.candidate.counter
        replies = iter([reply(self.candidate, ota.Phase.RECEIVING, received=1),
                        reply(self.candidate, ota.Phase.RECEIVING, received=2),
                        reply(self.candidate, ota.Phase.READY)])
        self.uploader.status = mock.Mock(side_effect=lambda *args, **kwargs: next(replies))
        result = signed.wait_observed_ready(self.pair, self.uploader, self.candidate, TARGET_KEY,
                                           99, self.deadline, observer)
        self.assertEqual(result.phase, ota.Phase.READY)
        self.assertEqual(observer.peer["witness"]["source"], "companion_advert_push")
        self.assertEqual(observer.peer["before"]["received"], 1)
        self.assertEqual(observer.peer["after"]["received"], 2)
        self.assertTrue(observer.peer["tx_totals_are_not_peer_proof"])
        self.assertNotIn(ota.Op.START, self.uploader.ops)
        self.assertNotIn(ota.Op.COMMIT, self.uploader.ops)
        self.assertNotIn(ota.Op.ABORT, self.uploader.ops)

    def test_peer_ack_or_already_ready_after_probe_cannot_prove_peer_during_transfer(self):
        observer = self.observer(duty=95000)
        self.client.budget_share = 95000
        replies = iter([reply(self.candidate, ota.Phase.RECEIVING, received=1),
                        reply(self.candidate, ota.Phase.READY), reply(self.candidate, ota.Phase.READY)])
        self.uploader.status = mock.Mock(side_effect=lambda *args, **kwargs: next(replies))
        signed.wait_observed_ready(self.pair, self.uploader, self.candidate, TARGET_KEY,
                                   99, self.deadline, observer)
        self.assertIsNone(observer.peer)
        self.assertIn("ordinary_peer_not_freshly_bracketed_during_transfer", observer.report()["incomplete_reasons"])

    def test_wrong_peer_timeout_remains_fatal_and_is_not_excused_by_tx_counters(self):
        observer = self.observer()
        self.uploader.local_valid = True
        self.target.phase = "receiving"
        self.uploader.status = mock.Mock(return_value=reply(self.candidate, ota.Phase.RECEIVING, received=1))
        self.target.key = bytes([9]) * 32
        self.client.poll = lambda timeout=0: self.clock.sleep(timeout)
        with self.assertRaisesRegex(TimeoutError, "ordinary advert"):
            signed.wait_observed_ready(self.pair, self.uploader, self.candidate, TARGET_KEY,
                                       99, self.deadline, observer)
        self.assertIsNone(observer.peer)
        self.assertNotIn(ota.Op.ABORT, self.uploader.ops)

    def test_stale_remote_snapshot_cannot_gain_freshness_during_slow_measurement_reads(self):
        observer = self.observer()
        remote = reply(self.candidate, ota.Phase.RECEIVING, received=1, age=1000)
        original = self.target.command
        def command(text, **kwargs):
            if text == "ota radio":
                self.clock.sleep(2)
            return original(text, **kwargs)
        self.target.command = command
        sample = observer.observe("transfer", remote, 99.5, remote_at=100)
        self.assertFalse(sample["fresh_remote_progress"])
        self.assertEqual(sample["remote_snapshot_monotonic"], 99)

    def test_measurement_interval_refusal_is_before_any_hardware_open(self):
        for value in ("nan", "inf", "-1", "0", "0.01", "5.01"):
            with self.subTest(value=value), mock.patch.object(signed, "Pair") as pair:
                with self.assertRaisesRegex(signed.QualificationError, "measurement-interval"):
                    signed.main(["--artifact-dir", str(self.directory / "unused"), "stage"]
                                + self.arguments + ["--measurement-interval", value])
                pair.assert_not_called()

    def test_fresh_durable_bitmap_regression_is_fatal_without_abort_or_restart(self):
        observer = self.observer()
        observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=2), 99)
        self.clock.sleep(5)
        with self.assertRaisesRegex(signed.QualificationError, "bitmap count regressed"):
            observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=1), 99)
        self.assertNotIn(ota.Op.START, self.uploader.ops)
        self.assertNotIn(ota.Op.ABORT, self.uploader.ops)

    def test_aggregate_tx_and_old_budget_usage_do_not_qualify_new_transfer_or_peer(self):
        self.client.measurement_overrides["budget"] = budget_diagnostic(b=3420000, u=100, tx=900000)
        observer = self.observer(duty=95000)
        for received in (1, 2, self.candidate.blocks):
            observer.observe("transfer", reply(self.candidate, ota.Phase.RECEIVING, received=received), 99)
            self.clock.sleep(5)
        observer.observe("end")
        result = observer.report()
        self.assertFalse(result["measurement_qualified"])
        self.assertIn("new_completed_on_mesh_ota_charges_not_observed", result["incomplete_reasons"])
        self.assertIn("ordinary_peer_not_freshly_bracketed_during_transfer", result["incomplete_reasons"])

    def test_diagnostics_cannot_authorize_commit_while_driver_is_still_direct_or_unhealthy(self):
        args, evidence = self.prepare_commit()
        self.diagnostic_state(True, d=1, td=100000, e=160000)
        with self.assertRaisesRegex(signed.QualificationError, "restored normal service"):
            signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
        self.assertNotIn(ota.Op.COMMIT, self.uploader.ops)
        self.diagnostic_state(False, x=1)
        with self.assertRaisesRegex(signed.QualificationError, "driver/apply"):
            signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
        self.assertNotIn(ota.Op.COMMIT, self.uploader.ops)

    def test_real_uploader_denied_status_is_fatal_not_measurement_incomplete(self):
        node, pair, uploader = self.product_pair(counter=7)
        observer = signed.TransferMeasurements(pair, self.candidate, signed.profile(self.args)[1],
            {"client": lab.serializable_app_info(lab.companion_info(node)),
             "target": lab.repeater_info(pair.target)}, self.evidence, self.deadline, 5)
        original = node.write_frame
        def write(packet):
            original(packet)
            if packet[:2] == bytes([66, ota.Op.STATUS]) and packet[2:] == TARGET_KEY:
                _, response = node.pending[-1]
                rejected = bytearray(response)
                rejected[3] = ota.Result.DENIED
                node.pending[-1] = (self.clock.now, bytes(rejected))
        node.write_frame = write
        with self.assertRaisesRegex(ota.UploaderError, "DENIED"):
            signed.wait_observed_ready(pair, uploader, self.candidate, TARGET_KEY,
                                       99, self.deadline, observer)
        self.assertEqual(observer.samples, [])
        self.assertNotIn(ota.Op.ABORT, [packet[1] for packet in node.packets])

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
                abort = next(packet for packet in reversed(node.packets) if packet[1] == ota.Op.ABORT)
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
        self.uploader.status = mock.Mock(side_effect=lambda target=ota.LOCAL_TARGET, **kwargs:
            reply(self.candidate, ota.Phase.CACHE_SEALED, target=target)
            if target == ota.LOCAL_TARGET else self.uploader.ready_reply)
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

    def test_stage_and_post_install_peer_checks_accept_verified_raw_not_ack_only(self):
        self.target.key = BENCH_ADVERT_KEY
        self.client.radio = self.target.radio = (907525, 250000, 7, 5)
        self.client.app_name, self.target.app_name = "OTA-LAB-CLIENT", "OTA-LAB-TARGET"
        self.uploader.ready_reply = reply(self.candidate, ota.Phase.READY, target=BENCH_ADVERT_KEY)
        self.client.poll = mock.Mock(side_effect=lambda timeout=0: self.clock.sleep(max(0.01, timeout)))
        original = self.target.command

        def command(value, **kwargs):
            if value != "advert.zerohop":
                return original(value, **kwargs)
            self.target.commands.append(value)
            self.client.pending.append((self.clock.now, BENCH_LOG_RX_ADVERT))
            return "OK - zerohop advert sent"

        self.target.command = command
        args, evidence = self.prepare_commit()
        self.assertNotIn(ota.Op.COMMIT, self.uploader.ops)
        outcome = signed.commit(self.pair, self.uploader, self.candidate, args, evidence, self.deadline)
        self.assertEqual(self.uploader.ops.count(ota.Op.COMMIT), 1)
        self.assertTrue(outcome["remote_install_qualified"])
        self.assertTrue(outcome["ordinary_peer_received"])
        self.assertEqual(outcome["lifecycle"]["image"], self.candidate.metadata["image_sha256"])
        self.assertEqual(outcome["lifecycle"]["floor"], self.candidate.counter)
        self.assertEqual(self.target.commands.count("advert.zerohop"), 2)
        self.assertNotIn("reboot", self.target.commands)
        evidence.events.flush()
        events = [json.loads(line) for line in evidence.events_path.read_text().splitlines()]
        received = [event for event in events if event["event"] == "ordinary_peer_advert_received"]
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["source"], "host_verified_signed_advert")
        self.assertTrue(received[0]["signature_verified"])
        self.assertFalse(received[0]["companion_pki_acceptance_observed"])

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
                    bytes([31, 2, ota.Op.COMMIT, result, 0, ota.REMOTE]) + TARGET_KEY + bytes(32)
                    + struct.pack(">HHIII", 0, 0, 0, ota.AGE_UNKNOWN, 0) + bytes(4))
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
                bytes([31, 2, payload[1], ota.Result.DENIED, 0, 0]) + bytes(64)
                + struct.pack(">HHIII", 0, 0, 0, ota.AGE_UNKNOWN, 0) + bytes(4)))

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
                bytes([31, 2, payload[1], result, 0, 0]) + bytes(64)
                + struct.pack(">HHIII", 0, 0, 0, ota.AGE_UNKNOWN, 0) + bytes(4)))

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


class NormalPeerProbeTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).resolve().parents[2] / ".tmp" / ("normal-peer-" + uuid.uuid4().hex)
        self.directory.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.directory)
        self.clock = Clock()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(signed.time, "monotonic", self.clock.monotonic).start()
        mock.patch.object(signed.time, "sleep", self.clock.sleep).start()
        mock.patch("sys.stdout", io.StringIO()).start()
        self.new_pair()

    def new_pair(self):
        self.client = Companion()
        self.client.boot = b"stock firmware: no OTA lifecycle service"
        self.client.poll = mock.Mock(side_effect=lambda timeout=0: self.clock.sleep(max(0.01, timeout)))
        self.target = Target(self.client)
        self.target.floor = "unknown"
        self.client.radio = self.target.radio = (907525, 62500, 7, 5)
        self.pair = SimpleNamespace(client=self.client, target=self.target,
                                    reenumerate=mock.Mock(), close=mock.Mock())

    def run_probe(self, name="probe", timeout=None, outer_timeout=None):
        artifact = self.directory / name
        arguments = ["--artifact-dir", str(artifact)]
        if outer_timeout is not None:
            arguments += ["--timeout", str(outer_timeout)]
        arguments += ["probe-peer"]
        if timeout is not None:
            arguments += ["--probe-timeout", str(timeout)]
        with mock.patch.object(signed, "Pair", return_value=self.pair) as opened, \
                mock.patch.object(signed, "load_candidate", side_effect=AssertionError("image operation")) as image, \
                mock.patch.object(ota, "Uploader", side_effect=AssertionError("OTA operation")) as uploader:
            try:
                signed.main(arguments)
            finally:
                image.assert_not_called()
                uploader.assert_not_called()
                self.pair.reenumerate.assert_not_called()
                self.pair.close.assert_called_once()
                opened.assert_called_once()
                self.opened_deadline = opened.call_args.args[1]
                self.assertTrue(all(command[0] in (lab.CMD_APP_START, lab.CMD_DEVICE_QUERY, signed.CMD_GET_STATS)
                                    for command in self.client.commands))
                self.assertTrue(all(command.startswith("get ") or command in (
                                    "advert.zerohop", "stats-packets", "stats-radio")
                                    for command in self.target.commands))
                self.assertNotIn("ota status", self.target.commands)
                self.assertIsNone(self.client.signed_data)
        return json.loads((artifact / "normal-peer.json").read_text())

    def advert_reply(self, frame=None, stale=False, mutate=None):
        original = self.target.command

        def command(value, **kwargs):
            if value != "advert.zerohop":
                return original(value, **kwargs)
            self.target.commands.append(value)
            if frame is not None:
                timestamp = self.clock.now - 1 if stale else self.clock.now
                self.client.pending.append((timestamp, frame))
            if mutate:
                mutate()
            return "OK - zerohop advert sent"

        self.target.command = command

    def framed_client(self, chunks):
        client = object.__new__(lab.FramedSerial)
        client.name, client.buffer, client.pending = "client", bytearray(), []
        client.commands = self.client.commands
        client.signed_data = None
        client.command = self.client.command

        def read(timeout):
            self.clock.sleep(max(0.01, timeout))
            return chunks.pop(0) if chunks else b""

        client._read_bytes = read
        self.pair.client = client
        return client

    def test_stock_probe_uses_real_normal_queries_and_unknown_floor_is_not_an_ota_gate(self):
        for bandwidth in (62500, 250000):
            with self.subTest(bandwidth=bandwidth):
                self.new_pair()
                self.client.radio = self.target.radio = (907525, bandwidth, 7, 5)
                result = self.run_probe(str(bandwidth))
                self.assertEqual(result["configuration_before"], result["configuration_after"])
                self.assertEqual(result["configuration_before"]["client"]["pubkey"], self.client.public_key.hex())
                self.assertEqual(result["configuration_before"]["target"]["pubkey"], TARGET_KEY.hex())
                self.assertEqual(result["configuration_before"]["target"]["bw_hz"], bandwidth)
                self.assertEqual(result["configuration_before"]["acl"], self.target.acl)
                self.assertTrue(result["probe_complete"])
                self.assertTrue(result["identity_config_acl_preserved"])
                self.assertTrue(result["ordinary_peer_received"])
                self.assertFalse(result["read_only"])
                self.assertFalse(result["signed_ota_qualified"])
                self.assertEqual(result["scope"], "target_to_client_ordinary_zerohop_advert")
                witness = result["peer_receive"]
                self.assertEqual(witness["frame_hex"], (b"\x80" + TARGET_KEY).hex())
                self.assertGreaterEqual(witness["received_monotonic"], witness["request_monotonic"])
                self.assertTrue(witness["fresh_after_request"])
                self.assertEqual(self.target.commands.count("advert.zerohop"), 1)
                summary = json.loads((self.directory / str(bandwidth) / "summary.json").read_text())
                self.assertIsNone(summary["error"])

    def test_real_bench_log_rx_advert_has_existing_meshcore_signature(self):
        decoded = signed.verified_raw_advert(BENCH_LOG_RX_ADVERT, BENCH_ADVERT_KEY)
        self.assertEqual(len(BENCH_LOG_RX_ADVERT), 128)
        self.assertEqual(decoded["target"], BENCH_ADVERT_KEY.hex())
        self.assertEqual(decoded["advert_name"], "OTA-LAB-TARGET")
        self.assertEqual(decoded["path_hash_count"], 0)
        self.assertEqual(decoded["route_type"], 2)
        self.assertTrue(decoded["signature_verified"])
        self.assertEqual(decoded["reported_snr_db"], 13.75)
        self.assertEqual(decoded["reported_rssi_dbm"], -5)

    def test_real_bench_raw_frame_qualifies_only_after_signature_verification_and_normal_handshake(self):
        self.client.radio = self.target.radio = (907525, 250000, 7, 5)
        self.client.app_name, self.target.app_name = "OTA-LAB-CLIENT", "OTA-LAB-TARGET"
        self.target.key = BENCH_ADVERT_KEY
        chunks = []
        client = self.framed_client(chunks)
        original = self.target.command

        def command(value, **kwargs):
            if value != "advert.zerohop":
                return original(value, **kwargs)
            app_starts = [payload for payload in self.client.commands if payload[0] == lab.CMD_APP_START]
            self.assertEqual(len(app_starts), 2)
            self.assertTrue(all(payload == b"\x01" + bytes(7) + b"ota-rf-lab" for payload in app_starts))
            self.target.commands.append(value)
            wire = b">" + struct.pack("<H", len(BENCH_LOG_RX_ADVERT)) + BENCH_LOG_RX_ADVERT
            chunks.extend([wire[:20], wire[20:]])
            return "OK - zerohop advert sent"

        self.target.command = command
        original_evidence = lab.Evidence

        def evidence(directory):
            observed = original_evidence(directory)
            client.evidence = observed
            return observed

        with mock.patch.object(lab, "Evidence", side_effect=evidence):
            result = self.run_probe()
        witness = result["peer_receive"]
        self.assertEqual(witness["frame_hex"], BENCH_LOG_RX_ADVERT.hex())
        self.assertEqual(witness["source"], "host_verified_signed_advert")
        self.assertEqual(witness["target"], BENCH_ADVERT_KEY.hex())
        self.assertEqual(witness["advert_name"], "OTA-LAB-TARGET")
        self.assertTrue(witness["signature_verified"])
        self.assertFalse(witness["companion_pki_acceptance_observed"])
        self.assertFalse(witness["emission_freshness_verified"])
        self.assertFalse(result["signed_ota_qualified"])
        self.assertEqual(result["configuration_before"], result["configuration_after"])
        self.assertEqual(result["configuration_before"]["client"]["path_hash_mode"], 2)
        self.assertEqual(result["configuration_before"]["acl"][self.client.public_key.hex()], 3)
        events = (self.directory / "probe" / "serial-events.jsonl").read_text()
        self.assertIn("ordinary_peer_session_started", events)
        self.assertIn("ordinary_peer_raw_advert_signature_verified", events)
        self.assertIn(BENCH_LOG_RX_ADVERT.hex(), events)

    def test_raw_authentication_does_not_accept_wrong_peer_unsigned_body_or_stale_event(self):
        corrupted = bytearray(BENCH_LOG_RX_ADVERT)
        corrupted[41] ^= 1
        unsigned = bytearray(BENCH_LOG_RX_ADVERT)
        unsigned[41:105] = bytes(64)
        altered_name = bytearray(BENCH_LOG_RX_ADVERT)
        altered_name[-1] ^= 1
        for kind, payload, stale, key in (
                ("bad_signature", bytes(corrupted), False, BENCH_ADVERT_KEY),
                ("unsigned", bytes(unsigned), False, BENCH_ADVERT_KEY),
                ("signed_body_changed", bytes(altered_name), False, BENCH_ADVERT_KEY),
                ("stale_raw", BENCH_LOG_RX_ADVERT, True, BENCH_ADVERT_KEY),
                ("wrong_raw_peer", BENCH_LOG_RX_ADVERT, False, TARGET_KEY)):
            with self.subTest(kind=kind):
                self.new_pair()
                self.target.key = key
                self.advert_reply(payload, stale)
                with self.assertRaisesRegex(TimeoutError, "fresh ordinary advert"):
                    self.run_probe(kind, timeout=0.5)
                self.assertFalse((self.directory / kind / "normal-peer.json").exists())
                events = (self.directory / kind / "serial-events.jsonl").read_text()
                self.assertIn("ordinary_peer_raw_advert_ignored", events)
                self.assertNotIn("ordinary_peer_advert_received", events)

    def test_exact_packet_header_transport_path_and_advert_data_bounds_are_checked(self):
        for name, payload in (
                ("short_log", b"\x88\x00"),
                ("version", BENCH_LOG_RX_ADVERT[:3] + b"\x52" + BENCH_LOG_RX_ADVERT[4:]),
                ("other_type", BENCH_LOG_RX_ADVERT[:3] + b"\x0e" + BENCH_LOG_RX_ADVERT[4:]),
                ("truncated_transport", b"\x88\x00\x00\x10\x00"),
                ("reserved_path_size", BENCH_LOG_RX_ADVERT[:4] + b"\xc0" + BENCH_LOG_RX_ADVERT[5:]),
                ("path_too_long", BENCH_LOG_RX_ADVERT[:4] + b"\xbf" + BENCH_LOG_RX_ADVERT[5:]),
                ("truncated_path", BENCH_LOG_RX_ADVERT[:4] + b"\x95"),
                ("short_body", BENCH_LOG_RX_ADVERT[:80]),
                ("oversized_app", BENCH_LOG_RX_ADVERT + bytes(10)),
                ("unnamed", BENCH_LOG_RX_ADVERT[:105] + b"\x12" + BENCH_LOG_RX_ADVERT[106:]),
                ("truncated_location", BENCH_LOG_RX_ADVERT[:105] + b"\x92\x01"),
                ("wrong_role", BENCH_LOG_RX_ADVERT[:105] + b"\x91" + BENCH_LOG_RX_ADVERT[106:])):
            with self.subTest(name=name), self.assertRaises(ValueError):
                signed.verified_raw_advert(payload, BENCH_ADVERT_KEY)
        for route in (0, 3):
            transported = (BENCH_LOG_RX_ADVERT[:3] + bytes([0x10 | route])
                           + b"\x01\x02\x03\x04" + BENCH_LOG_RX_ADVERT[4:])
            parsed = signed.verified_raw_advert(transported, BENCH_ADVERT_KEY)
            self.assertEqual(parsed["route_type"], route)
            self.assertTrue(parsed["signature_verified"])
        for path, encoded in ((b"\x01", 1), (b"\x01\x02", 0x41), (b"\x01\x02\x03", 0x81)):
            routed = BENCH_LOG_RX_ADVERT[:4] + bytes([encoded]) + path + BENCH_LOG_RX_ADVERT[5:]
            parsed = signed.verified_raw_advert(routed, BENCH_ADVERT_KEY)
            self.assertEqual(parsed["path_hash_size"], len(path))
            self.assertEqual(parsed["path_hash_count"], 1)

    def test_signed_but_nonzerohop_raw_packet_does_not_qualify_the_requested_probe(self):
        for name, payload in (
                ("relayed", BENCH_LOG_RX_ADVERT[:4] + b"\x81" + bytes(3) + BENCH_LOG_RX_ADVERT[5:]),
                ("flood", BENCH_LOG_RX_ADVERT[:3] + b"\x11" + BENCH_LOG_RX_ADVERT[4:])):
            with self.subTest(name=name):
                self.new_pair()
                self.target.key = BENCH_ADVERT_KEY
                self.advert_reply(payload)
                with self.assertRaises(TimeoutError):
                    self.run_probe(name, timeout=0.5)

    def test_native_advert_acceptance_is_preferred_over_a_verified_raw_receipt(self):
        self.target.key = BENCH_ADVERT_KEY
        self.advert_reply(BENCH_LOG_RX_ADVERT)
        original_poll = self.client.poll
        polls_after_request = 0

        def poll(timeout=0):
            nonlocal polls_after_request
            original_poll(timeout)
            if "advert.zerohop" in self.target.commands:
                polls_after_request += 1
                if polls_after_request == 2:
                    self.client.pending.append((self.clock.now, new_advert_push(BENCH_ADVERT_KEY)))

        self.client.poll = poll
        result = self.run_probe()
        witness = result["peer_receive"]
        self.assertEqual(witness["code"], 0x8A)
        self.assertEqual(len(bytes.fromhex(witness["frame_hex"])), 148)
        self.assertEqual(witness["source"], "companion_advert_push")
        self.assertTrue(witness["companion_pki_acceptance_observed"])
        self.assertTrue(witness["signed_raw_advert"]["signature_verified"])

    def test_io_failure_after_verified_raw_is_not_hidden_by_the_native_push_grace_period(self):
        self.target.key = BENCH_ADVERT_KEY
        self.advert_reply(BENCH_LOG_RX_ADVERT)
        original_poll = self.client.poll
        polls_after_request = 0

        def poll(timeout=0):
            nonlocal polls_after_request
            original_poll(timeout)
            if "advert.zerohop" in self.target.commands:
                polls_after_request += 1
                if polls_after_request > 1:
                    raise OSError("serial disconnected after raw receive")

        self.client.poll = poll
        with self.assertRaisesRegex(OSError, "after raw receive"):
            self.run_probe()
        self.assertFalse((self.directory / "probe" / "normal-peer.json").exists())
        events = (self.directory / "probe" / "serial-events.jsonl").read_text()
        self.assertIn("ordinary_peer_raw_advert_signature_verified", events)
        self.assertNotIn("ordinary_peer_advert_received", events)

    def test_pre_request_signed_raw_is_discarded_and_cannot_authorize_later_ack_only(self):
        self.target.key = BENCH_ADVERT_KEY
        self.client.pending.append((self.clock.now, BENCH_LOG_RX_ADVERT))
        self.advert_reply()
        with self.assertRaises(TimeoutError):
            self.run_probe(timeout=0.5)
        events = (self.directory / "probe" / "serial-events.jsonl").read_text()
        self.assertIn("normal_peer_pre_request_discard", events)
        self.assertNotIn("ordinary_peer_raw_advert_signature_verified", events)

    def test_second_native_or_third_signed_raw_advert_recovers_packet_loss_with_bounded_spacing(self):
        for successful_attempt, raw in ((2, False), (3, True)):
            with self.subTest(attempt=successful_attempt, raw=raw):
                self.new_pair()
                self.client.radio = self.target.radio = (907525, 250000, 7, 5)
                if raw:
                    self.target.key = BENCH_ADVERT_KEY
                original = self.target.command
                requests = []

                def command(value, **kwargs):
                    if value != "advert.zerohop":
                        return original(value, **kwargs)
                    self.target.commands.append(value)
                    requests.append(self.clock.now)
                    self.target.packet_stats["sent"] += 1
                    if len(requests) == successful_attempt:
                        self.client.packet_stats["recv"] += 1
                        frame = BENCH_LOG_RX_ADVERT if raw else b"\x80" + self.target.key
                        self.client.pending.append((self.clock.now, frame))
                    return "OK - zerohop advert sent"

                self.target.command = command
                started = self.clock.now
                result = self.run_probe(str(successful_attempt))
                self.assertEqual(len(requests), successful_attempt)
                self.assertTrue(all(later - earlier >= 2 for earlier, later in zip(requests, requests[1:])))
                self.assertLess(self.clock.now - started, 30)
                witness = result["peer_receive"]
                self.assertEqual(witness["attempts_requested"], successful_attempt)
                self.assertEqual(witness["companion_pki_acceptance_observed"], not raw)
                self.assertFalse(witness["emission_freshness_verified"])
                if raw:
                    self.assertTrue(witness["signature_verified"])
                stats = result["statistics"]
                self.assertEqual(stats["before"]["target"]["packets"]["values"]["sent"], 0)
                self.assertEqual(stats["after"]["target"]["packets"]["values"]["sent"], successful_attempt)
                self.assertEqual(stats["after"]["client"]["packets"]["values"]["recv"], 1)
                self.assertTrue(stats["after"]["client"]["radio"]["available"])
                self.assertTrue(stats["after"]["target"]["radio"]["available"])

    def test_three_acks_and_increased_tx_rx_counters_without_receive_event_remain_failure(self):
        original = self.target.command
        requests = []

        def command(value, **kwargs):
            if value != "advert.zerohop":
                return original(value, **kwargs)
            self.target.commands.append(value)
            requests.append(self.clock.now)
            self.target.packet_stats["sent"] += 1
            self.client.packet_stats["recv"] += 1
            return "OK - zerohop advert sent"

        self.target.command = command
        started = self.clock.now
        with self.assertRaisesRegex(TimeoutError, "fresh ordinary advert"):
            self.run_probe()
        self.assertEqual(len(requests), 3)
        self.assertTrue(all(later - earlier >= 2 for earlier, later in zip(requests, requests[1:])))
        self.assertLessEqual(self.clock.now - started, 30)
        summary = json.loads((self.directory / "probe" / "summary.json").read_text())
        probe = summary["measurements"]["normal_peer_probe"]
        self.assertFalse(probe["probe_complete"])
        self.assertFalse(probe["signed_ota_qualified"])
        self.assertEqual(probe["statistics"]["after"]["target"]["packets"]["values"]["sent"], 3)
        self.assertEqual(probe["statistics"]["after"]["client"]["packets"]["values"]["recv"], 3)
        self.assertFalse((self.directory / "probe" / "normal-peer.json").exists())
        self.assertEqual(len(summary["measurements"]["ordinary_peer_requests"]), 3)

    def test_retry_does_not_waive_bad_signature_or_wrong_bound_peer(self):
        corrupted = bytearray(BENCH_LOG_RX_ADVERT)
        corrupted[41] ^= 1
        for name, frame, key in (
                ("signature", bytes(corrupted), BENCH_ADVERT_KEY),
                ("peer", BENCH_LOG_RX_ADVERT, TARGET_KEY)):
            with self.subTest(name=name):
                self.new_pair()
                self.target.key = key
                self.advert_reply(frame)
                with self.assertRaises(TimeoutError):
                    self.run_probe(name, timeout=8)
                self.assertEqual(self.target.commands.count("advert.zerohop"), 3)
                events = (self.directory / name / "serial-events.jsonl").read_text()
                self.assertNotIn("ordinary_peer_advert_received", events)
                self.assertEqual(events.count('"event": "ordinary_peer_raw_advert_ignored"'), 3)

    def test_stats_are_read_only_exact_normal_protocol_and_unavailable_is_explicit(self):
        self.client.packet_stats.update(recv=12, sent=34, recv_errors=2)
        self.target.packet_stats.update(recv=56, sent=78, recv_errors=3)
        result = self.run_probe()
        stats = result["statistics"]
        for phase in ("before", "after"):
            self.assertEqual(stats[phase]["client"]["packets"]["request_hex"], "3802")
            self.assertEqual(stats[phase]["client"]["radio"]["request_hex"], "3801")
            self.assertEqual(stats[phase]["target"]["packets"]["command"], "stats-packets")
            self.assertEqual(stats[phase]["target"]["radio"]["command"], "stats-radio")
            self.assertEqual(stats[phase]["client"]["packets"]["values"]["sent"], 34)
            self.assertEqual(stats[phase]["target"]["packets"]["values"]["sent"], 78)
            self.assertEqual(stats[phase]["client"]["radio"]["values"]["last_snr"], 3)
            self.assertTrue(stats[phase]["target"]["radio"]["aggregate_only_not_peer_proof"])
        self.new_pair()
        client_command, target_command = self.client.command, self.target.command

        def refused_client(payload, **kwargs):
            if payload[0] == 56:
                self.client.commands.append(payload)
                return bytes([1, 2])
            return client_command(payload, **kwargs)

        def unknown_target(value, **kwargs):
            if value.startswith("stats-"):
                self.target.commands.append(value)
                return "Unknown command"
            return target_command(value, **kwargs)

        self.client.command, self.target.command = refused_client, unknown_target
        result = self.run_probe("unavailable")
        self.assertTrue(result["ordinary_peer_received"])
        for phase in ("before", "after"):
            for role in ("client", "target"):
                for kind in ("packets", "radio"):
                    row = result["statistics"][phase][role][kind]
                    self.assertFalse(row["available"])
                    self.assertIn("error", row)
                    self.assertNotIn("values", row)

    def test_readability_timeouts_reserve_after_stats_and_do_not_extend_probe_deadline(self):
        original_client, original_target = self.client.command, self.target.command
        stats_timeouts = []

        def slow_client(payload, **kwargs):
            if payload[0] == 56:
                self.client.commands.append(payload)
                stats_timeouts.append(kwargs["timeout"])
                self.clock.sleep(kwargs["timeout"])
                raise TimeoutError("stats unsupported")
            return original_client(payload, **kwargs)

        def slow_target(value, **kwargs):
            if value.startswith("stats-"):
                self.target.commands.append(value)
                stats_timeouts.append(kwargs["timeout"])
                self.clock.sleep(kwargs["timeout"])
                raise TimeoutError("stats unsupported")
            if value == "advert.zerohop":
                self.target.commands.append(value)
                return "OK - zerohop advert sent"
            return original_target(value, **kwargs)

        self.client.command, self.target.command = slow_client, slow_target
        started = self.clock.now
        with self.assertRaises(TimeoutError):
            self.run_probe()
        self.assertLessEqual(self.clock.now - started, 30)
        self.assertEqual(len(stats_timeouts), 8)
        self.assertTrue(all(0 < value <= 0.5 for value in stats_timeouts))
        summary = json.loads((self.directory / "probe" / "summary.json").read_text())
        self.assertIn("after", summary["measurements"]["normal_peer_probe"]["statistics"])

    def test_late_ack_spaces_retries_from_ack_and_short_deadline_does_not_force_three_attempts(self):
        original = self.target.command
        requested, acknowledged = [], []

        def command(value, **kwargs):
            if value != "advert.zerohop":
                return original(value, **kwargs)
            self.target.commands.append(value)
            requested.append(self.clock.now)
            self.clock.sleep(0.4)
            acknowledged.append(self.clock.now)
            return "OK - zerohop advert sent"

        self.target.command = command
        with self.assertRaises(TimeoutError):
            self.run_probe(timeout=8)
        self.assertEqual(len(requested), 3)
        self.assertTrue(all(requested[index + 1] - acknowledged[index] >= 2 for index in range(2)))
        self.new_pair()
        self.advert_reply()
        with self.assertRaises(TimeoutError):
            self.run_probe("short", timeout=1)
        self.assertEqual(self.target.commands.count("advert.zerohop"), 1)

    def test_real_target_inspection_shape_without_path_mode_supports_fresh_probe(self):
        self.client.radio = self.target.radio = (907525, 250000, 7, 5)
        observed_target = {"bw_hz": 250000, "cr": 5, "freq_khz": 907525,
                           "name": "OTA-LAB-TARGET", "pubkey": self.target.key.hex(),
                           "role": "repeater", "settings_readback_scope": "preferences", "sf": 7}
        with mock.patch.object(lab, "repeater_info", return_value=observed_target) as target_info:
            result = self.run_probe()
        self.assertEqual(target_info.call_count, 2)
        self.assertEqual(result["configuration_before"]["target"], observed_target)
        self.assertEqual(result["configuration_after"]["target"], observed_target)
        self.assertNotIn("path_hash_mode", result["configuration_before"]["target"])
        self.assertEqual(result["configuration_before"]["client"]["path_hash_mode"], 2)
        self.assertEqual(result["configuration_before"]["acl"][self.client.public_key.hex()], 3)
        self.assertEqual(result["peer_receive"]["frame_hex"], (b"\x80" + TARGET_KEY).hex())
        self.assertTrue(result["probe_complete"])
        self.assertNotIn("get path.hash.mode", self.target.commands)
        events = [json.loads(line) for line in
                  (self.directory / "probe" / "serial-events.jsonl").read_text().splitlines()]
        observability = [event for event in events if event["event"] == "normal_peer_path_observability"]
        self.assertEqual(len(observability), 2)
        self.assertTrue(all(event["client_path_hash_mode"] == 2
                            and not event["target_path_hash_mode_observed"] for event in observability))

    def test_wrong_stale_malformed_contact_table_and_ack_only_do_not_prove_peer_reception(self):
        for kind, frame, stale in (
                ("wrong", b"\x80" + b"\xbb" * 32, False),
                ("stale", b"\x80" + TARGET_KEY, True),
                ("malformed", b"\x80" + TARGET_KEY[:-1], False),
                ("short_new_advert", b"\x8a" + TARGET_KEY + bytes(3), False),
                ("contact_table", b"\x03" + TARGET_KEY, False),
                ("ack_only", None, False)):
            with self.subTest(kind=kind):
                self.new_pair()
                self.advert_reply(frame, stale)
                with self.assertRaisesRegex(TimeoutError, "fresh ordinary advert"):
                    self.run_probe(kind, timeout=0.5)
                artifact = self.directory / kind
                self.assertFalse((artifact / "normal-peer.json").exists())
                summary = json.loads((artifact / "summary.json").read_text())
                probe = summary["measurements"]["normal_peer_probe"]
                self.assertIn("TimeoutError", summary["error"])
                self.assertFalse(probe["probe_complete"])
                self.assertFalse(probe["signed_ota_qualified"])
                self.assertTrue(probe["rf_request_attempted"])
                events = (artifact / "serial-events.jsonl").read_text()
                self.assertIn("ordinary_peer_advert_requested", events)
                self.assertNotIn("ordinary_peer_advert_received", events)
                if kind in ("wrong", "stale", "malformed", "short_new_advert"):
                    self.assertIn("ordinary_peer_advert_ignored", events)
                    self.assertIn(frame.hex(), events)

    def test_pre_request_correct_peer_event_is_discarded_not_reused(self):
        self.client.pending.append((self.clock.now, b"\x80" + TARGET_KEY))
        self.advert_reply()
        with self.assertRaises(TimeoutError):
            self.run_probe(timeout=0.5)
        events = (self.directory / "probe" / "serial-events.jsonl").read_text()
        self.assertIn("normal_peer_pre_request_discard", events)
        self.assertNotIn("ordinary_peer_advert_received", events)

    def test_real_framed_backlog_is_drained_and_fresh_push_is_recorded_raw(self):
        for code in (0x80, 0x8A):
            with self.subTest(code=code):
                self.new_pair()
                payload = new_advert_push(TARGET_KEY) if code == 0x8A else b"\x80" + TARGET_KEY
                wire = b">" + struct.pack("<H", len(payload)) + payload
                chunks = [wire[:8], wire[8:], wire]
                client = self.framed_client(chunks)
                original = self.target.command

                def command(value, **kwargs):
                    if value == "advert.zerohop":
                        self.target.commands.append(value)
                        chunks.extend([wire[:9], wire[9:]])
                        return "OK - zerohop advert sent"
                    return original(value, **kwargs)

                self.target.command = command
                artifact = self.directory / str(code)
                original_evidence = lab.Evidence

                def evidence(directory):
                    observed = original_evidence(directory)
                    client.evidence = observed
                    return observed

                with mock.patch.object(lab, "Evidence", side_effect=evidence):
                    result = self.run_probe(str(code))
                events = [json.loads(line) for line in (artifact / "serial-events.jsonl").read_text().splitlines()]
                discarded = [event for event in events if event["event"] == "normal_peer_pre_request_discard"]
                self.assertEqual(len(discarded), 2)
                self.assertTrue(all(not event["peer_proof"] for event in discarded))
                self.assertTrue(all(event["received_monotonic"] < result["peer_receive"]["request_monotonic"]
                                    for event in discarded))
                self.assertEqual(result["peer_receive"]["frame_hex"], payload.hex())
                self.assertEqual(result["peer_receive"]["code"], code)
                self.assertTrue(any(event["event"] == "serial_rx" and event["hex"] == payload.hex()
                                    for event in events))

    def test_incomplete_old_serial_frame_refuses_rf_request(self):
        client = self.framed_client([])
        client.buffer.extend(b">\x21\x00\x80" + TARGET_KEY[:5])
        with self.assertRaisesRegex(signed.QualificationError, "incomplete pre-request"):
            self.run_probe()
        self.assertNotIn("advert.zerohop", self.target.commands)
        summary = json.loads((self.directory / "probe" / "summary.json").read_text())
        self.assertFalse(summary["measurements"]["normal_peer_probe"]["rf_request_attempted"])

    def test_missing_existing_admin_acl_or_invalid_radio_refuses_rf_without_mutation(self):
        for kind in ("acl", "mismatch", "unapproved"):
            with self.subTest(kind=kind):
                self.new_pair()
                if kind == "acl":
                    self.target.acl.pop(self.client.public_key.hex())
                elif kind == "mismatch":
                    self.target.radio = (907525, 250000, 7, 5)
                    self.client.radio = (907525, 62500, 7, 5)
                else:
                    self.client.radio = self.target.radio = (907525, 500000, 7, 5)
                with self.assertRaises(signed.QualificationError):
                    self.run_probe(kind)
                self.assertNotIn("advert.zerohop", self.target.commands)

    def test_identity_role_and_path_are_validated_before_rf(self):
        for kind in ("same_key", "zero_key", "role", "path"):
            with self.subTest(kind=kind):
                self.new_pair()
                original = self.target.command
                if kind == "same_key":
                    self.target.key = self.client.public_key
                elif kind == "zero_key":
                    self.target.key = bytes(32)
                else:
                    def command(value, **kwargs):
                        if kind == "role" and value == "get role":
                            self.target.commands.append(value)
                            return "> companion"
                        return original(value, **kwargs)
                    self.target.command = command
                    if kind == "path":
                        original_client = self.client.command

                        def client_command(payload, **kwargs):
                            response = original_client(payload, **kwargs)
                            if payload[0] == lab.CMD_DEVICE_QUERY:
                                response = bytearray(response)
                                response[81] = 0
                                return bytes(response)
                            return response

                        self.client.command = client_command
                with self.assertRaises((signed.QualificationError, RuntimeError, AssertionError)):
                    self.run_probe(kind)
                self.assertNotIn("advert.zerohop", self.target.commands)

    def test_fresh_peer_does_not_waive_postprobe_identity_configuration_or_acl_changes(self):
        for kind in ("identity", "radio", "acl"):
            with self.subTest(kind=kind):
                self.new_pair()

                def change():
                    if kind == "identity":
                        self.target.key = b"\xcc" * 32
                    elif kind == "radio":
                        self.client.radio = self.target.radio = (907525, 250000, 7, 5)
                    else:
                        self.target.acl[(b"\xaa" * 32).hex()] = 2

                self.advert_reply(b"\x80" + TARGET_KEY, mutate=change)
                with self.assertRaisesRegex(signed.QualificationError, "changed during"):
                    self.run_probe(kind)
                artifact = self.directory / kind
                self.assertFalse((artifact / "normal-peer.json").exists())
                probe = json.loads((artifact / "summary.json").read_text())["measurements"]["normal_peer_probe"]
                self.assertIn("peer_receive", probe)
                self.assertFalse(probe["probe_complete"])

    def test_io_failure_or_rejected_advert_is_fatal_and_never_rebooted_or_retried_as_success(self):
        for kind in ("io", "denied"):
            with self.subTest(kind=kind):
                self.new_pair()
                original = self.target.command

                def command(value, **kwargs):
                    if value != "advert.zerohop":
                        return original(value, **kwargs)
                    self.target.commands.append(value)
                    if kind == "io":
                        raise OSError("serial disconnected")
                    return "ERR - denied"

                self.target.command = command
                with self.assertRaises(OSError if kind == "io" else RuntimeError):
                    self.run_probe(kind)
                self.assertEqual(self.target.commands.count("advert.zerohop"), 1)
                self.assertFalse((self.directory / kind / "normal-peer.json").exists())

    def test_probe_timeout_is_bounded_and_invalid_or_image_flags_fail_before_open(self):
        started = self.clock.now
        self.run_probe()
        self.assertEqual(self.opened_deadline, started + 30)
        self.new_pair()
        started = self.clock.now
        self.run_probe("outer", outer_timeout=0.5)
        self.assertEqual(self.opened_deadline, started + 0.5)
        args = signed.parser().parse_args(["--artifact-dir", "unused", "probe-peer"])
        self.assertEqual(args.probe_timeout, 30)
        for option in ("--timeout", "--probe-timeout"):
            for value in ("0", "-1", "nan", "inf"):
                flags = ["--artifact-dir", str(self.directory / "unused")]
                flags = flags + [option, value, "probe-peer"] if option == "--timeout" else \
                    flags + ["probe-peer", option, value]
                with self.subTest(option=option, value=value), mock.patch("sys.stderr", io.StringIO()), \
                        mock.patch.object(signed, "Pair") as opened:
                    with self.assertRaises(SystemExit):
                        signed.main(flags)
                    opened.assert_not_called()
        for flags in (["--image", "unused.bin"], ["--qualified-commit"], ["--mode", "direct"],
                      ["--duty-milli-percent", "95000"], ["--supervised-full-image-smoke"]):
            with self.subTest(flags=flags), mock.patch("sys.stderr", io.StringIO()), \
                    mock.patch.object(signed, "Pair") as opened:
                with self.assertRaises(SystemExit):
                    signed.main(["--artifact-dir", str(self.directory / "unused"), "probe-peer"] + flags)
                opened.assert_not_called()

    def test_probe_rejects_existing_evidence_directory_before_open(self):
        with mock.patch.object(signed, "Pair") as opened:
            with self.assertRaisesRegex(signed.QualificationError, "new artifact directory"):
                signed.main(["--artifact-dir", str(self.directory), "probe-peer"])
            opened.assert_not_called()

    def test_no_quiet_pre_request_window_refuses_rf(self):
        def noisy(timeout=0):
            self.clock.sleep(max(0.01, timeout))
            self.client.pending.append((self.clock.now, b"\x80" + TARGET_KEY))

        self.client.poll = noisy
        with self.assertRaisesRegex(TimeoutError, "did not become quiet"):
            self.run_probe(timeout=0.5)
        self.assertNotIn("advert.zerohop", self.target.commands)

    def test_probe_pins_both_roles_before_any_port_is_opened(self):
        with mock.patch.object(signed.lab_device, "resolve", side_effect=[
                SimpleNamespace(serial=signed.APPROVED["client"], by_id="/dev/serial/by-id/client"),
                SimpleNamespace(serial="49C5BAF21EEF44A1", by_id="/dev/serial/by-id/pine")]), \
                mock.patch.object(lab, "FramedSerial") as client_opened, \
                mock.patch.object(lab, "RepeaterSerial") as target_opened:
            with self.assertRaisesRegex(signed.QualificationError, "unapproved target"):
                signed.main(["--artifact-dir", str(self.directory / "protected"), "probe-peer"])
            client_opened.assert_not_called()
            target_opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
