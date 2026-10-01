import argparse
import hashlib
import io
import pathlib
import struct
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from unittest import mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import ota_uploader as ota


TARGET = bytes(range(32))
OTHER_TARGET = bytes(reversed(TARGET))
HASH = b"\xa5" * 32


def frame(op=ota.Op.STATUS, result=ota.Result.OK, phase=ota.Phase.READY,
          flags=3, target=TARGET, manifest_hash=HASH, received=2, total=2,
          counter=7, age=0, retry=0):
    return (bytes([31, 1, op, result, phase, flags]) + target + manifest_hash
            + struct.pack(">HHIII", received, total, counter, age, retry))


def manifest(image):
    return (struct.pack(">HHBII", 0x584E, 0x3430, 1, 0x27000, len(image))
            + hashlib.sha256(image).digest() + struct.pack(">IIHHH", 7, 1, 1, 1, 1))


class ReplyTests(unittest.TestCase):
    def test_exact_big_endian_layout_and_full_identities(self):
        decoded = ota.decode_reply(frame(received=0x1234, total=0x5678,
                                         counter=0x12345678, age=0x23456789, retry=0x3456789A))
        self.assertEqual(decoded.op, ota.Op.STATUS)
        self.assertEqual(decoded.target, TARGET)
        self.assertEqual(decoded.manifest_hash, HASH)
        self.assertEqual((decoded.received, decoded.total, decoded.counter, decoded.age_ms, decoded.retry_after_ms),
                         (0x1234, 0x5678, 0x12345678, 0x23456789, 0x3456789A))

    def test_invalid_layout_enums_counts_and_flags_are_rejected(self):
        original = frame()
        malformed = [original[:-1], original + b"\x00", frame(received=3, total=2),
                     frame(flags=4), frame(age=ota.AGE_UNKNOWN)]
        for offset in (0, 1, 2, 3, 4):
            changed = bytearray(original)
            changed[offset] = 255
            malformed.append(bytes(changed))
        for data in malformed:
            with self.subTest(data=data[:6]):
                with self.assertRaises(ota.UploaderError):
                    ota.decode_reply(data)

    def test_no_snapshot_shape_cannot_claim_progress(self):
        empty = frame(phase=ota.Phase.UNKNOWN, flags=2, manifest_hash=bytes(32),
                      received=0, total=0, counter=0, age=ota.AGE_UNKNOWN)
        decoded = ota.decode_reply(empty)
        self.assertFalse(decoded.valid)
        self.assertFalse(decoded.fresh_since(0, 100))
        for offset in (4, 38, 70, 72, 74, 78):
            with self.subTest(offset=offset):
                changed = bytearray(empty)
                changed[offset] ^= 1
                with self.assertRaises(ota.UploaderError):
                    ota.decode_reply(changed)

    def test_freshness_uses_observation_age_not_reply_arrival(self):
        decoded = ota.decode_reply(frame(age=5000))
        self.assertFalse(decoded.fresh_since(99, 100))
        self.assertTrue(decoded.fresh_since(99, 105))

    def test_commit_ack_without_snapshot_cannot_echo_unverified_progress(self):
        acknowledgement = frame(
            op=ota.Op.COMMIT, result=ota.Result.PENDING, phase=ota.Phase.UNKNOWN,
            flags=ota.REMOTE, manifest_hash=bytes(32), received=0, total=0,
            counter=0, age=ota.AGE_UNKNOWN)
        decoded = ota.decode_reply(acknowledgement)
        self.assertEqual(decoded.target, TARGET)
        self.assertFalse(decoded.valid)
        self.assertFalse(decoded.fresh_since(0, 100))
        for offset in (4, 38, 70, 72, 74, 78):
            with self.subTest(offset=offset):
                changed = bytearray(acknowledgement)
                changed[offset] ^= 1
                with self.assertRaises(ota.UploaderError):
                    ota.decode_reply(changed)


class RequestTests(unittest.TestCase):
    def test_manifest_exact_size_and_image_digest_are_checked(self):
        image = b"image" * 20
        canonical = manifest(image)
        ota.validate_image(canonical, image)
        for bad_manifest, bad_image in ((canonical[:-1], image), (canonical + b"\x00", image),
                                        (canonical, image[:-1]), (canonical, image[:-1] + b"x"),
                                        (canonical, b"")):
            with self.subTest(size=len(bad_image)):
                with self.assertRaises(ValueError):
                    ota.validate_image(bad_manifest, bad_image)

    def test_all_modes_and_configurable_lower_airtime_share(self):
        self.assertEqual(ota.start_body("directed", 255, 0, 0, 125),
                         bytes.fromhex("01ff0000000000000000007d"))
        self.assertEqual(ota.start_body("background", 2, 0, 0, 2000),
                         bytes.fromhex("0202000000000000000007d0"))
        self.assertEqual(ota.start_body("direct", 255, 908525, 60000, 100000),
                         struct.pack(">BBIHI", 0, 255, 908525, 60000, 100000))
        for duty in (1, 2000, 5000, 100000):
            self.assertEqual(struct.unpack_from(">I", ota.start_body("directed", 255, 0, 0, duty), 8)[0],
                             duty)

    def test_invalid_profiles_fail_before_transmission(self):
        for args in (("bad", 255, 0, 0, 2000), ("directed", 254, 0, 0, 2000),
                     ("background", 255, 0, 0, 2000), ("direct", 255, 0, 250, 2000),
                     ("direct", 255, 908525, 249, 2000), ("direct", 255, 908525, 60001, 2000),
                     ("directed", 255, 908525, 0, 2000), ("directed", 255, 0, 1, 2000),
                     ("directed", 255, 0, 0, 0), ("directed", 255, 0, 0, 100001)):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    ota.start_body(*args)

    def test_full_public_key_required_and_normalized(self):
        self.assertEqual(ota.full_key(TARGET.hex().upper()), TARGET)
        for text in ("", TARGET.hex()[:-1], "00" * 32, "g" * 64, " " * 64):
            with self.subTest(text=text):
                with self.assertRaises(argparse.ArgumentTypeError):
                    ota.full_key(text)


class ExchangeTests(unittest.TestCase):
    def setUp(self):
        self.node = mock.Mock()
        self.evidence = mock.Mock()
        self.uploader = ota.Uploader(self.node, self.evidence)
        self.clock = mock.Mock()
        self.clock.now = 100.0
        self.clock.monotonic.side_effect = lambda: self.clock.now

        def advance(duration=0):
            self.clock.now += max(0.01, duration)

        self.node.poll.side_effect = advance

    def test_stale_opcode_and_wrong_full_target_cannot_complete_request(self):
        self.node.take_pending.side_effect = [
            [(99, frame())],
            [(100.1, frame(op=ota.Op.COMMIT)), (100.1, frame(target=OTHER_TARGET)),
             (99, frame())],
            [(100.2, frame())],
        ]
        with mock.patch.object(ota, "time", self.clock):
            reply = self.uploader.exchange(ota.Op.STATUS, TARGET, TARGET)
        self.assertEqual(reply.target, TARGET)
        self.node.write_frame.assert_called_once_with(bytes([66, 0x17]) + TARGET)
        self.assertEqual(self.evidence.log.call_count, 3)

    def test_wrong_target_only_times_out(self):
        self.node.take_pending.side_effect = lambda codes: [(100.1, frame(target=OTHER_TARGET))]
        with mock.patch.object(ota, "time", self.clock):
            with self.assertRaisesRegex(TimeoutError, "matching OTA reply"):
                self.uploader.exchange(ota.Op.STATUS, TARGET, TARGET, timeout=0.5)

    def test_companion_errors_or_malformed_reply_fail_explicitly(self):
        for bad in (b"\x01\x03", frame()[:-1]):
            with self.subTest(bad=bad[:6]):
                self.clock.now = 100.0
                self.node.take_pending.side_effect = [[], [(100.1, bad)]]
                with mock.patch.object(ota, "time", self.clock):
                    with self.assertRaises(ota.UploaderError):
                        self.uploader.exchange(ota.Op.STATUS, TARGET, TARGET)

    def test_unavailable_is_not_a_success_or_an_empty_status(self):
        reply = ota.decode_reply(frame(result=ota.Result.UNAVAILABLE, phase=ota.Phase.UNKNOWN,
                                       flags=2, manifest_hash=bytes(32), received=0, total=0,
                                       counter=0, age=ota.AGE_UNKNOWN))
        with self.assertRaisesRegex(ota.UploaderError, "UNAVAILABLE"):
            self.uploader.require_accepted(reply)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.node = mock.Mock()
        self.uploader = ota.Uploader(self.node, mock.Mock())
        self.image = b"image" * 20
        self.canonical = manifest(self.image)
        self.manifest_hash = hashlib.sha256(self.canonical).digest()
        self.good = ota.decode_reply(frame())
        self.uploader.exchange = mock.Mock(return_value=self.good)

    def test_cache_signs_canonical_manifest_uses_84_byte_blocks_and_never_commits(self):
        self.uploader.wait_phase = mock.Mock(return_value=self.good)
        deadline = time.monotonic() + 10
        with mock.patch.object(ota.lab, "sign_manifest", return_value=b"\x5a" * 64) as sign:
            self.assertEqual(self.uploader.cache(self.canonical, self.image, TARGET, deadline,
                                                reupload=True), self.good)
        sign.assert_called_once_with(self.node, self.canonical, TARGET, deadline=deadline)
        calls = self.uploader.exchange.call_args_list
        self.assertEqual(calls[0].args[:2],
                         (ota.Op.CACHE_BEGIN, b"\x01" + TARGET + self.canonical + b"\x5a" * 64))
        self.assertEqual(2 + len(calls[0].args[1]), 158)
        self.assertEqual(calls[1].args[:2], (ota.Op.CACHE_PUT, b"\x00\x00\x54" + self.image[:84]))
        self.assertEqual(calls[2].args[:2], (ota.Op.CACHE_PUT, b"\x00\x01\x10" + self.image[84:]))
        self.assertEqual(calls[3].args, (ota.Op.CACHE_SEAL,))
        self.assertNotIn(ota.Op.COMMIT, [call.args[0] for call in calls])
        self.assertEqual(self.uploader.wait_phase.call_args.args[:4],
                         (ota.LOCAL_TARGET, ota.Phase.CACHE_SEALED, self.manifest_hash, 7))

    def test_cache_data_failure_prevents_seal_start_and_commit(self):
        rejected = ota.decode_reply(frame(result=ota.Result.IO_ERROR))
        self.uploader.exchange.side_effect = [self.good, rejected]
        with mock.patch.object(ota.lab, "sign_manifest", return_value=bytes(64)):
            with self.assertRaisesRegex(ota.UploaderError, "IO_ERROR"):
                self.uploader.cache(self.canonical, self.image, TARGET, time.monotonic() + 10)
        self.assertEqual([call.args[0] for call in self.uploader.exchange.call_args_list],
                         [ota.Op.CACHE_BEGIN, ota.Op.CACHE_PUT])

    def test_pending_cache_block_retries_identical_bytes_before_advancing(self):
        pending = ota.decode_reply(frame(result=ota.Result.PENDING))
        self.uploader.exchange.side_effect = [self.good, pending, self.good, self.good, self.good]
        self.uploader.wait_phase = mock.Mock(return_value=self.good)
        with mock.patch.object(ota.lab, "sign_manifest", return_value=bytes(64)), \
                mock.patch.object(ota.time, "sleep"):
            self.uploader.cache(self.canonical, self.image, TARGET, time.monotonic() + 10)
        puts = [call.args for call in self.uploader.exchange.call_args_list
                if call.args[0] == ota.Op.CACHE_PUT]
        self.assertEqual(puts[0], puts[1])
        self.assertEqual(puts[2][1][:2], b"\x00\x01")

    def test_target_selection_precedes_start_and_does_not_commit(self):
        body = ota.start_body("background", 0, 0, 0, 2000)
        self.uploader.start([TARGET, OTHER_TARGET], body, "background", time.monotonic() + 10)
        self.assertEqual([call.args[:3] for call in self.uploader.exchange.call_args_list],
                         [(ota.Op.ADD_TARGET, TARGET, TARGET), (ota.Op.ADD_TARGET, OTHER_TARGET, OTHER_TARGET),
                          (ota.Op.START, body)])

    def test_invalid_selection_fails_before_any_add_target(self):
        for targets, mode in (([], "background"), ([TARGET, TARGET], "background"),
                              ([TARGET, OTHER_TARGET], "directed"), ([bytes(32)], "direct")):
            with self.subTest(targets=targets, mode=mode):
                with self.assertRaises(ValueError):
                    self.uploader.start(targets, b"", mode, time.monotonic() + 10)
        self.uploader.exchange.assert_not_called()

    def test_start_mode_mismatch_cannot_select_targets(self):
        with self.assertRaisesRegex(ValueError, "START body"):
            self.uploader.start([TARGET], ota.start_body("background", 0, 0, 0, 2000),
                                "directed", time.monotonic() + 10)
        self.uploader.exchange.assert_not_called()

    def test_commit_waits_for_fresh_ready_and_binds_full_target_manifest_counter(self):
        self.uploader.wait_phase = mock.Mock(return_value=self.good)
        self.uploader.commit(TARGET, self.canonical, time.monotonic() + 10)
        self.assertEqual(self.uploader.wait_phase.call_args.args[:4],
                         (TARGET, ota.Phase.READY, self.manifest_hash, 7))
        self.assertEqual(self.uploader.exchange.call_args.args[:3],
                         (ota.Op.COMMIT, TARGET + self.manifest_hash + b"\x00\x00\x00\x07", TARGET))

    def test_no_ready_prevents_commit(self):
        self.uploader.wait_phase = mock.Mock(side_effect=TimeoutError("not READY"))
        with self.assertRaises(TimeoutError):
            self.uploader.commit(TARGET, self.canonical, time.monotonic() + 10)
        self.uploader.exchange.assert_not_called()

    def test_commit_acceptance_without_snapshot_is_not_installation(self):
        acknowledgement = ota.decode_reply(frame(
            op=ota.Op.COMMIT, result=ota.Result.PENDING, phase=ota.Phase.UNKNOWN,
            flags=ota.REMOTE, manifest_hash=bytes(32), received=0, total=0,
            counter=0, age=ota.AGE_UNKNOWN))
        self.uploader.wait_phase = mock.Mock(return_value=self.good)
        self.uploader.exchange.return_value = acknowledgement
        self.assertEqual(self.uploader.commit(TARGET, self.canonical, time.monotonic() + 10),
                         acknowledgement)
        self.uploader.wait_phase.assert_called_once()
        self.assertFalse(acknowledgement.valid)
        self.assertEqual(acknowledgement.phase, ota.Phase.UNKNOWN)

    def test_abort_uses_image_hash_not_manifest_hash(self):
        image_hash = hashlib.sha256(self.image).digest()
        self.assertNotEqual(image_hash, self.manifest_hash)
        self.uploader.abort(TARGET, image_hash)
        self.uploader.exchange.assert_called_once_with(ota.Op.ABORT, TARGET + image_hash, TARGET)

    def test_old_ready_is_not_accepted_as_fresh_completion(self):
        clock = mock.Mock()
        clock.now = 100
        clock.monotonic.side_effect = lambda: clock.now
        clock.sleep.side_effect = lambda duration: setattr(clock, "now", clock.now + duration)
        self.uploader.status = mock.Mock(side_effect=[
            ota.decode_reply(frame(manifest_hash=self.manifest_hash, age=10000)),
            ota.decode_reply(frame(manifest_hash=self.manifest_hash, age=0)),
        ])
        with mock.patch.object(ota, "time", clock):
            reply = self.uploader.wait_phase(TARGET, ota.Phase.READY, self.manifest_hash, 7, 99, 105)
        self.assertEqual(reply.age_ms, 0)
        self.assertEqual(self.uploader.status.call_count, 2)

    def test_stale_other_image_is_not_confused_with_a_current_conflicting_candidate(self):
        clock = mock.Mock()
        clock.now = 100
        clock.monotonic.side_effect = lambda: clock.now
        clock.sleep.side_effect = lambda duration: setattr(clock, "now", clock.now + duration)
        self.uploader.status = mock.Mock(side_effect=[
            ota.decode_reply(frame(manifest_hash=HASH, counter=6, age=10000)),
            ota.decode_reply(frame(manifest_hash=self.manifest_hash, age=0)),
        ])
        with mock.patch.object(ota, "time", clock):
            self.uploader.wait_phase(TARGET, ota.Phase.READY, self.manifest_hash, 7, 99, 105)
        self.assertEqual(self.uploader.status.call_count, 2)

    def test_stale_failed_snapshot_does_not_prevent_current_ready(self):
        clock = mock.Mock()
        clock.now = 100
        clock.monotonic.side_effect = lambda: clock.now
        clock.sleep.side_effect = lambda duration: setattr(clock, "now", clock.now + duration)
        self.uploader.exchange.side_effect = [
            ota.decode_reply(frame(phase=ota.Phase.FAILED, manifest_hash=HASH, counter=6, age=10000)),
            ota.decode_reply(frame(manifest_hash=self.manifest_hash)),
        ]
        with mock.patch.object(ota, "time", clock):
            self.uploader.wait_phase(TARGET, ota.Phase.READY, self.manifest_hash, 7, 99, 105)
        self.assertEqual(self.uploader.exchange.call_count, 2)

    def test_current_failure_or_abort_stops_waiting(self):
        for phase in (ota.Phase.FAILED, ota.Phase.ABORTED):
            with self.subTest(phase=phase):
                self.uploader.exchange.return_value = ota.decode_reply(
                    frame(phase=phase, manifest_hash=self.manifest_hash))
                with self.assertRaisesRegex(ota.UploaderError, phase.name):
                    self.uploader.wait_phase(TARGET, ota.Phase.READY, self.manifest_hash, 7,
                                             time.monotonic() - 1, time.monotonic() + 10)

    def test_status_reports_failed_candidate_without_claiming_successful_completion(self):
        failed = ota.decode_reply(frame(phase=ota.Phase.FAILED))
        self.uploader.exchange.return_value = failed
        self.assertEqual(self.uploader.status(TARGET), failed)

    def test_expired_cache_deadline_does_not_start_signing(self):
        with mock.patch.object(ota.lab, "sign_manifest") as sign:
            with self.assertRaises(TimeoutError):
                self.uploader.cache(self.canonical, self.image, TARGET, time.monotonic() - 1)
        sign.assert_not_called()
        self.uploader.exchange.assert_not_called()

    def test_wrong_hash_counter_scope_or_incomplete_ready_is_rejected(self):
        for reply in (frame(), frame(manifest_hash=self.manifest_hash, counter=8),
                      frame(manifest_hash=self.manifest_hash, flags=1),
                      frame(manifest_hash=self.manifest_hash, received=1)):
            with self.subTest(reply=reply[:6]):
                self.uploader.status = mock.Mock(return_value=ota.decode_reply(reply))
                with self.assertRaises(ota.UploaderError):
                    self.uploader.wait_phase(TARGET, ota.Phase.READY, self.manifest_hash, 7,
                                             time.monotonic() - 1, time.monotonic() + 10)


class CommandSafetyTests(unittest.TestCase):
    def test_invalid_deadline_cannot_open_a_device(self):
        for timeout in ("nan", "inf", "-1", "0"):
            arguments = ["ota_uploader.py", "--artifact-dir", "unused",
                         f"--timeout={timeout}", "status"]
            with self.subTest(timeout=timeout), mock.patch.object(sys, "argv", arguments), \
                    mock.patch.object(ota.lab_device, "resolve") as resolve, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    ota.main()
                resolve.assert_not_called()


class CliLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).resolve().parents[2] / ".tmp")
        self.addCleanup(self.scratch.cleanup)
        self.directory = pathlib.Path(self.scratch.name)
        self.image = b"image" * 20
        self.canonical = manifest(self.image)
        self.manifest_hash = hashlib.sha256(self.canonical).digest()
        self.image_path = self.directory / "image.bin"
        self.manifest_path = self.directory / "manifest.bin"
        self.image_path.write_bytes(self.image)
        self.manifest_path.write_bytes(self.canonical)
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.evidence = mock.Mock()
        self.node = mock.Mock()
        self.node.name = "approved-client"
        self.clock = mock.Mock()
        self.clock.now = 100.0
        self.clock.monotonic.side_effect = lambda: self.clock.now
        self.clock.sleep.side_effect = self.advance
        self.node.poll.side_effect = self.advance
        self.node.command.side_effect = self.command
        self.node.write_frame.side_effect = self.write_frame
        self.node.take_pending.side_effect = self.take_pending
        self.pending = []
        self.received = 0
        self.results = {}
        self.remote_phase = ota.Phase.READY
        self.signature_override = None

    def advance(self, duration=0):
        self.clock.now += max(0.01, duration)

    def command(self, payload, **options):
        self.advance()
        code = payload[0]
        if code == ota.lab.CMD_APP_START:
            return (bytes([ota.lab.RESP_SELF_INFO, 1, 0, 0]) + self.public_key
                    + bytes(12) + struct.pack("<II", 907525, 62500) + bytes([7, 5]))
        if code == ota.lab.CMD_SIGN_START:
            return bytes([ota.lab.RESP_SIGN_START, 0]) + struct.pack("<I", 4096)
        if code == ota.lab.CMD_SIGN_DATA:
            self.assertEqual(payload[1:], self.canonical)
            return bytes([ota.lab.RESP_OK])
        if code == ota.lab.CMD_SIGN_FINISH:
            signature = (self.private_key.sign(self.canonical) if self.signature_override is None
                         else self.signature_override)
            return bytes([ota.lab.RESP_SIGNATURE]) + signature
        raise AssertionError(f"unexpected companion command: {code}")

    def write_frame(self, payload):
        self.assertEqual(payload[0], ota.lab.CMD_OTA_CONTROL)
        op = ota.Op(payload[1])
        remote = op in (ota.Op.ADD_TARGET, ota.Op.COMMIT, ota.Op.ABORT, ota.Op.SET_ADMIN)
        target = payload[2:34] if remote or op == ota.Op.STATUS else ota.LOCAL_TARGET
        flags = ota.SNAPSHOT_VALID | (ota.REMOTE if target != ota.LOCAL_TARGET else 0)
        phase = self.remote_phase if target != ota.LOCAL_TARGET else ota.Phase.CACHE_SEALED
        received = 2
        if op == ota.Op.CACHE_BEGIN:
            phase, received = ota.Phase.RECEIVING, 0
        elif op == ota.Op.CACHE_PUT:
            self.received += 1
            phase, received = ota.Phase.RECEIVING, self.received
        elif op == ota.Op.COMMIT:
            phase = ota.Phase.COMMIT_PENDING
        elif op == ota.Op.ABORT:
            phase = ota.Phase.ABORTED
        response = frame(op=op, result=self.results.get(op, ota.Result.OK), phase=phase,
                         target=target, flags=flags, manifest_hash=self.manifest_hash,
                         received=received)
        self.pending.append((self.clock.now, response))

    def take_pending(self, codes):
        selected = [entry for entry in self.pending if entry[1][0] in codes]
        self.pending[:] = [entry for entry in self.pending if entry[1][0] not in codes]
        return selected

    def run_cli(self, arguments):
        device = mock.Mock(serial="approved-client", by_id=pathlib.Path("/dev/serial/by-id/approved-client"))
        argv = ["ota_uploader.py", "--artifact-dir", str(self.directory), "--timeout", "10", *arguments]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(ota, "time", self.clock), \
                mock.patch.object(ota.lab, "time", self.clock), \
                mock.patch.object(ota.lab, "Evidence", return_value=self.evidence), \
                mock.patch.object(ota.lab_device, "resolve", return_value=device), \
                mock.patch.object(ota.lab, "FramedSerial", return_value=self.node):
            ota.main()

    def sent_payloads(self):
        return [call.args[0] for call in self.node.write_frame.call_args_list]

    def upload_arguments(self):
        return ["upload", "--manifest", str(self.manifest_path), "--image", str(self.image_path),
                "--target", TARGET.hex()]

    def test_complete_upload_signs_and_waits_in_all_three_modes_without_committing(self):
        for mode in ota.MODES:
            with self.subTest(mode=mode):
                self.node.reset_mock()
                self.evidence.reset_mock()
                self.received = 0
                arguments = [*self.upload_arguments(), "--mode", mode, "--wait-ready"]
                if mode == "direct":
                    arguments += ["--frequency-khz", "908525", "--lease-ms", "60000"]
                elif mode == "background":
                    arguments += ["--channel", "2", "--target", OTHER_TARGET.hex()]
                self.run_cli(arguments)
                payloads = self.sent_payloads()
                self.assertEqual(payloads[0], bytes([66, ota.Op.CACHE_BEGIN, 0])
                                 + self.public_key + self.canonical
                                 + self.private_key.sign(self.canonical))
                self.assertEqual(len(payloads[0]), 158)
                self.assertEqual(payloads[1:3],
                                 [bytes([66, ota.Op.CACHE_PUT]) + b"\x00\x00\x54" + self.image[:84],
                                  bytes([66, ota.Op.CACHE_PUT]) + b"\x00\x01\x10" + self.image[84:]])
                starts = [payload for payload in payloads if payload[1] == ota.Op.START]
                self.assertEqual(len(starts), 1)
                self.assertEqual(starts[0][2], ota.MODES[mode])
                self.assertNotIn(ota.Op.COMMIT, [payload[1] for payload in payloads])
                self.assertEqual([call.args[0][0] for call in self.node.command.call_args_list],
                                 [ota.lab.CMD_APP_START, 33, 34, 35])
                self.node.close.assert_called_once()
                self.evidence.finish.assert_called_once_with(None)

    def test_upload_without_ready_wait_reports_start_only_and_never_commits(self):
        self.run_cli(self.upload_arguments())
        statuses = [payload[2:] for payload in self.sent_payloads() if payload[1] == ota.Op.STATUS]
        self.assertEqual(statuses, [ota.LOCAL_TARGET])
        self.assertEqual(self.evidence.log.call_args.kwargs["op"], ota.Op.START.name)

    def test_explicit_commit_queries_fresh_ready_then_binds_target_manifest_and_counter(self):
        self.run_cli(["commit", "--target", TARGET.hex(), "--manifest", str(self.manifest_path)])
        self.assertEqual(self.sent_payloads(),
                         [bytes([66, ota.Op.STATUS]) + TARGET,
                          bytes([66, ota.Op.COMMIT]) + TARGET + self.manifest_hash
                          + struct.pack(">I", 7)])
        self.node.command.assert_not_called()
        self.assertEqual(self.evidence.log.call_args.kwargs["phase"], ota.Phase.COMMIT_PENDING.name)

    def test_abort_passes_image_content_hash_not_descriptor_hash(self):
        self.run_cli(["abort", "--target", TARGET.hex(), "--image", str(self.image_path)])
        self.assertEqual(self.sent_payloads(),
                         [bytes([66, ota.Op.ABORT]) + TARGET + hashlib.sha256(self.image).digest()])
        self.node.close.assert_called_once()
        self.evidence.finish.assert_called_once_with(None)

    def test_admin_permission_requires_a_durable_ok_not_pending(self):
        self.run_cli(["admin", "--target", TARGET.hex(), "--enabled", "1"])
        self.assertEqual(self.sent_payloads(), [bytes([66, ota.Op.SET_ADMIN]) + TARGET + b"\x01"])
        self.node.reset_mock()
        self.evidence.reset_mock()
        self.results[ota.Op.SET_ADMIN] = ota.Result.PENDING
        with self.assertRaisesRegex(ota.UploaderError, "durably saved"):
            self.run_cli(["admin", "--target", TARGET.hex(), "--enabled", "0"])
        self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
        self.node.close.assert_called_once()

    def test_status_can_report_a_failed_candidate_without_hiding_it(self):
        self.remote_phase = ota.Phase.FAILED
        self.run_cli(["status", "--target", TARGET.hex()])
        self.assertEqual(self.evidence.log.call_args.kwargs["phase"], ota.Phase.FAILED.name)
        self.evidence.finish.assert_called_once_with(None)

    def test_failed_candidate_prevents_commit_and_records_error(self):
        self.remote_phase = ota.Phase.FAILED
        with self.assertRaisesRegex(ota.UploaderError, "FAILED"):
            self.run_cli(["commit", "--target", TARGET.hex(), "--manifest", str(self.manifest_path)])
        self.assertEqual([payload[1] for payload in self.sent_payloads()], [ota.Op.STATUS])
        self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
        self.node.close.assert_called_once()

    def test_invalid_companion_signature_prevents_cache_writes(self):
        self.signature_override = bytes(64)
        with self.assertRaises(InvalidSignature):
            self.run_cli(self.upload_arguments())
        self.node.write_frame.assert_not_called()
        self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
        self.node.close.assert_called_once()

    def test_unavailable_cache_fails_without_seal_start_or_commit(self):
        self.results[ota.Op.CACHE_BEGIN] = ota.Result.UNAVAILABLE
        with self.assertRaisesRegex(ota.UploaderError, "UNAVAILABLE"):
            self.run_cli(self.upload_arguments())
        self.assertEqual([payload[1] for payload in self.sent_payloads()], [ota.Op.CACHE_BEGIN])
        self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
        self.node.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
