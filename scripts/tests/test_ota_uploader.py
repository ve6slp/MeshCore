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
          counter=7, age=0, retry=0, generation=0):
    return (bytes([31, 2, op, result, phase, flags]) + target + manifest_hash
            + struct.pack(">HHIII", received, total, counter, age, retry)
            + struct.pack(">I", generation))


def manifest(image):
    return (struct.pack(">HHBII", 0x584E, 0x3430, 1, 0x27000, len(image))
            + hashlib.sha256(image).digest() + struct.pack(">IIHHH", 7, 1, 1, 1, 1))


class ReplyTests(unittest.TestCase):
    def test_exact_big_endian_layout_and_full_identities(self):
        decoded = ota.decode_reply(frame(received=0x1234, total=0x5678,
                                         counter=0x12345678, age=0x23456789, retry=0x3456789A,
                                         generation=0xFEDCBA98))
        self.assertEqual(decoded.op, ota.Op.STATUS)
        self.assertEqual(decoded.target, TARGET)
        self.assertEqual(decoded.manifest_hash, HASH)
        self.assertEqual((decoded.received, decoded.total, decoded.counter, decoded.age_ms, decoded.retry_after_ms),
                         (0x1234, 0x5678, 0x12345678, 0x23456789, 0x3456789A))
        self.assertEqual(decoded.generation, 0xFEDCBA98)
        self.assertEqual(decoded.summary()["generation"], 0xFEDCBA98)
        self.assertEqual(len(frame()), 90)
        self.assertEqual(frame(generation=0xFEDCBA98)[86:90], bytes.fromhex("fedcba98"))

    def test_valid_wrapped_zero_generation_and_legacy_abi_refusal(self):
        self.assertTrue(ota.decode_reply(frame(generation=0)).valid)
        self.assertEqual(ota.decode_reply(frame(generation=0)).summary()["generation"], 0)
        legacy = bytearray(frame()[:86])
        legacy[1] = 1
        for data in (bytes(legacy), frame()[:86], frame()[:1] + b"\x01" + frame()[2:]):
            with self.subTest(length=len(data)):
                with self.assertRaisesRegex(ota.UploaderError, "ABI version"):
                    ota.decode_reply(data)

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
        for offset in (4, 38, 70, 72, 74, 78, 86):
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
        for offset in (4, 38, 70, 72, 74, 78, 86):
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

    def test_pending_begin_still_waits_for_receiving_before_put_and_seal(self):
        begin = ota.decode_reply(frame(
            op=ota.Op.CACHE_BEGIN, result=ota.Result.PENDING, phase=ota.Phase.RECEIVING,
            target=ota.LOCAL_TARGET, flags=1, manifest_hash=self.manifest_hash, received=1))
        sealed = ota.decode_reply(frame(
            phase=ota.Phase.CACHE_SEALED, target=ota.LOCAL_TARGET,
            flags=1, manifest_hash=self.manifest_hash))
        self.uploader.exchange.side_effect = [begin, self.good, self.good, self.good]
        self.uploader.wait_phase = mock.Mock(side_effect=[begin, sealed])
        with mock.patch.object(ota.lab, "sign_manifest", return_value=bytes(64)):
            reply = self.uploader.cache(self.canonical, self.image, TARGET, time.monotonic() + 10)
        self.assertEqual(reply, sealed)
        self.assertEqual([call.args[0] for call in self.uploader.exchange.call_args_list],
                         [ota.Op.CACHE_BEGIN, ota.Op.CACHE_PUT, ota.Op.CACHE_PUT, ota.Op.CACHE_SEAL])
        self.assertEqual([call.args[:4] for call in self.uploader.wait_phase.call_args_list], [
            (ota.LOCAL_TARGET, ota.Phase.RECEIVING, self.manifest_hash, 7),
            (ota.LOCAL_TARGET, ota.Phase.CACHE_SEALED, self.manifest_hash, 7),
        ])

    def test_restart_during_verification_waits_for_seal_without_writing_blocks(self):
        begin = ota.decode_reply(frame(
            op=ota.Op.CACHE_BEGIN, phase=ota.Phase.VERIFYING, target=ota.LOCAL_TARGET,
            flags=1, manifest_hash=self.manifest_hash))
        statuses = iter([
            ota.decode_reply(frame(
                phase=ota.Phase.VERIFYING, target=ota.LOCAL_TARGET,
                flags=1, manifest_hash=self.manifest_hash)),
            ota.decode_reply(frame(
                phase=ota.Phase.CACHE_SEALED, target=ota.LOCAL_TARGET,
                flags=1, manifest_hash=self.manifest_hash)),
        ])

        def exchange(op, *args, **kwargs):
            if op == ota.Op.CACHE_BEGIN:
                return begin
            if op == ota.Op.STATUS:
                return next(statuses)
            return ota.decode_reply(frame(
                op=op, result=ota.Result.BAD_REQUEST, phase=ota.Phase.UNKNOWN,
                target=ota.LOCAL_TARGET, flags=0, manifest_hash=bytes(32),
                received=0, total=0, counter=0, age=ota.AGE_UNKNOWN))

        self.uploader.exchange.side_effect = exchange
        with mock.patch.object(ota.lab, "sign_manifest", return_value=bytes(64)) as sign, \
                mock.patch.object(ota.time, "sleep"):
            reply = self.uploader.cache(self.canonical, self.image, TARGET, time.monotonic() + 10)
        self.assertEqual(reply.phase, ota.Phase.CACHE_SEALED)
        self.assertEqual(reply.manifest_hash, self.manifest_hash)
        self.assertEqual((reply.received, reply.total), (2, 2))
        sign.assert_called_once()
        self.assertEqual([call.args[0] for call in self.uploader.exchange.call_args_list],
                         [ota.Op.CACHE_BEGIN, ota.Op.STATUS, ota.Op.STATUS])

    def test_verifying_restart_rejects_failed_aborted_or_mismatched_completion(self):
        begin = ota.decode_reply(frame(
            op=ota.Op.CACHE_BEGIN, phase=ota.Phase.VERIFYING, target=ota.LOCAL_TARGET,
            flags=1, manifest_hash=self.manifest_hash))
        for fields in ({"phase": ota.Phase.FAILED}, {"phase": ota.Phase.ABORTED},
                       {"manifest_hash": HASH}, {"counter": 8}, {"flags": 3},
                       {"received": 1}):
            with self.subTest(fields=fields):
                status = dict(phase=ota.Phase.CACHE_SEALED, target=ota.LOCAL_TARGET,
                              flags=1, manifest_hash=self.manifest_hash)
                status.update(fields)

                def exchange(op, *args, **kwargs):
                    if op == ota.Op.CACHE_BEGIN:
                        return begin
                    self.assertEqual(op, ota.Op.STATUS)
                    return ota.decode_reply(frame(**status))

                self.uploader.exchange.reset_mock()
                self.uploader.exchange.side_effect = exchange
                with mock.patch.object(ota.lab, "sign_manifest", return_value=bytes(64)), \
                        self.assertRaises(ota.UploaderError):
                    self.uploader.cache(self.canonical, self.image, TARGET, time.monotonic() + 10)
                self.assertEqual([call.args[0] for call in self.uploader.exchange.call_args_list],
                                 [ota.Op.CACHE_BEGIN, ota.Op.STATUS])

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
        before = ota.decode_reply(frame(manifest_hash=self.manifest_hash, generation=0x12345678))
        after = ota.decode_reply(frame(phase=ota.Phase.ABORTED, manifest_hash=self.manifest_hash,
                                      generation=0x12345679))
        self.uploader.exchange.side_effect = [before, self.good, after]
        self.assertEqual(self.uploader.abort(TARGET, image_hash), after)
        self.assertEqual([call.args[:3] for call in self.uploader.exchange.call_args_list], [
            (ota.Op.STATUS, TARGET, TARGET),
            (ota.Op.ABORT, TARGET + image_hash + bytes.fromhex("12345678"), TARGET),
            (ota.Op.STATUS, TARGET, TARGET),
        ])

    def test_local_cache_abort_uses_zero_target_and_content_hash(self):
        image_hash = hashlib.sha256(self.image).digest()
        before = ota.decode_reply(frame(target=ota.LOCAL_TARGET, flags=1,
                                       manifest_hash=self.manifest_hash, generation=0xFFFFFFFF))
        after = ota.decode_reply(frame(target=ota.LOCAL_TARGET, flags=1, phase=ota.Phase.ABORTED,
                                      manifest_hash=self.manifest_hash, generation=0))
        self.uploader.exchange.side_effect = [before, self.good, after]
        self.assertEqual(self.uploader.abort(ota.LOCAL_TARGET, image_hash), after)
        self.assertEqual(self.uploader.exchange.call_args_list[1].args[:3],
                         (ota.Op.ABORT, ota.LOCAL_TARGET + image_hash + bytes.fromhex("ffffffff"),
                          ota.LOCAL_TARGET))
        self.assertNotEqual(image_hash, self.manifest_hash)

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
        for phase, wanted in ((ota.Phase.FAILED, ota.Phase.READY),
                              (ota.Phase.ABORTED, ota.Phase.READY),
                              (ota.Phase.FAILED, ota.Phase.FAILED)):
            with self.subTest(phase=phase, wanted=wanted):
                self.uploader.exchange.return_value = ota.decode_reply(
                    frame(phase=phase, manifest_hash=self.manifest_hash))
                with self.assertRaisesRegex(ota.UploaderError, phase.name):
                    self.uploader.wait_phase(TARGET, wanted, self.manifest_hash, 7,
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

    def test_invalid_or_expired_abort_deadline_cannot_query_or_mutate(self):
        for deadline in (time.monotonic() - 1, float("nan"), float("inf")):
            with self.subTest(deadline=deadline):
                with self.assertRaises(TimeoutError):
                    self.uploader.abort(TARGET, HASH, deadline=deadline)
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
        self.local_status = {}
        self.cache_already_sealed = False
        self.local_phase = ota.Phase.CACHE_SEALED
        self.generation = 0x12345678
        self.reply_mutator = None
        self.drop_abort_reply = False

        def check(name, passed, **details):
            if not passed:
                raise AssertionError(name)

        self.evidence.check.side_effect = check

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
        phase = self.remote_phase if target != ota.LOCAL_TARGET else self.local_phase
        blocks = (len(self.image) + 83) // 84
        received = blocks
        result = self.results.get(op, ota.Result.OK)
        if op == ota.Op.CACHE_BEGIN and not self.cache_already_sealed:
            if self.local_phase == ota.Phase.ABORTED and payload[2] == 1:
                self.generation = (self.generation + 1) & 0xFFFFFFFF
            phase, received = ota.Phase.RECEIVING, 0
        elif op == ota.Op.CACHE_PUT:
            if self.cache_already_sealed:
                result = ota.Result.BAD_REQUEST
            else:
                self.received += 1
                phase, received = ota.Phase.RECEIVING, self.received
        elif op == ota.Op.CACHE_SEAL:
            self.local_phase = phase = ota.Phase.CACHE_SEALED
        elif op == ota.Op.COMMIT:
            phase = ota.Phase.COMMIT_PENDING
        elif op == ota.Op.ABORT:
            self.assertEqual(len(payload), 70)
            requested_generation = struct.unpack_from(">I", payload, 66)[0]
            allowed = {self.generation}
            if phase == ota.Phase.ABORTED:
                allowed.add((self.generation - 1) & 0xFFFFFFFF)
            if requested_generation not in allowed:
                result = ota.Result.MISMATCH
            if payload[34:66] != hashlib.sha256(self.image).digest():
                result = ota.Result.MISMATCH
            if result == ota.Result.OK:
                if phase != ota.Phase.ABORTED:
                    self.generation = (self.generation + 1) & 0xFFFFFFFF
                phase = ota.Phase.ABORTED
                if target == ota.LOCAL_TARGET:
                    self.local_phase = phase
                else:
                    self.remote_phase = phase
        fields = dict(op=op, result=result, phase=phase, target=target, flags=flags,
                      manifest_hash=self.manifest_hash, received=received, total=blocks,
                      counter=struct.unpack_from(">I", self.canonical, 45)[0], generation=self.generation)
        if op == ota.Op.STATUS and target == ota.LOCAL_TARGET:
            fields.update(self.local_status)
        response = frame(**fields)
        if self.reply_mutator is not None:
            response = self.reply_mutator(op, response)
        if op == ota.Op.ABORT and self.drop_abort_reply:
            return
        self.pending.append((self.clock.now, response))

    def take_pending(self, codes):
        selected = [entry for entry in self.pending if entry[1][0] in codes]
        self.pending[:] = [entry for entry in self.pending if entry[1][0] not in codes]
        return selected

    def run_cli(self, arguments, serial=None):
        device = mock.Mock(serial=serial or ota.lab.APPROVED_ADMIN_PAIR["client"],
                           by_id=pathlib.Path("/dev/serial/by-id/approved-client"))
        argv = ["ota_uploader.py", "--artifact-dir", str(self.directory), "--timeout", "10", *arguments]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(ota, "time", self.clock), \
                mock.patch.object(ota.lab, "time", self.clock), \
                mock.patch.object(ota.lab, "Evidence", return_value=self.evidence) as evidence_open, \
                mock.patch.object(ota.lab_device, "resolve", return_value=device) as resolve, \
                mock.patch.object(ota.lab, "FramedSerial", return_value=self.node) as client_open:
            self.evidence_open, self.resolve, self.client_open = evidence_open, resolve, client_open
            ota.main()

    def sent_payloads(self):
        return [call.args[0] for call in self.node.write_frame.call_args_list]

    def upload_arguments(self):
        return ["upload", "--manifest", str(self.manifest_path), "--image", str(self.image_path),
                "--target", TARGET.hex()]

    def cache_arguments(self):
        return ["cache", "--manifest", str(self.manifest_path), "--image", str(self.image_path)]

    def test_cache_only_signs_real_owner_and_requires_fresh_full_local_seal_without_remote_ops(self):
        self.run_cli(self.cache_arguments())
        self.resolve.assert_called_once_with("client", mode=ota.lab_device.MODE_APP)
        self.client_open.assert_called_once()
        self.evidence_open.assert_called_once_with(str(self.directory), exclusive=True)
        payloads = self.sent_payloads()
        self.assertEqual([payload[1] for payload in payloads],
                         [0x10, 0x11, 0x11, 0x12, 0x17])
        self.assertEqual(payloads[0], bytes.fromhex("421000") + self.public_key + self.canonical
                         + self.private_key.sign(self.canonical))
        self.assertEqual(payloads[1:3],
                         [bytes.fromhex("4211000054") + self.image[:84],
                          bytes.fromhex("4211000110") + self.image[84:]])
        self.assertEqual(payloads[-2:], [bytes.fromhex("4212"), bytes.fromhex("4217") + bytes(32)])
        self.assertEqual([call.args[0][0] for call in self.node.command.call_args_list], [1, 33, 34, 35])
        result = self.evidence.log.call_args.kwargs
        self.assertEqual(result["phase"], "CACHE_SEALED")
        self.assertFalse(result["remote"])
        self.assertTrue(result["snapshot_valid"])
        self.assertEqual(result["target"], "0" * 64)
        self.assertEqual(result["hash"], self.manifest_hash.hex())
        self.assertEqual((result["counter"], result["received"], result["total"]), (7, 2, 2))
        self.node.close.assert_called_once()
        self.evidence.finish.assert_called_once_with(None)

    def test_interrupted_partial_cache_is_recorded_as_failure_without_abort_or_seal(self):
        def interrupted_write(payload):
            if payload[1] == ota.Op.CACHE_PUT and payload[2:4] == b"\x00\x01":
                raise KeyboardInterrupt()
            self.write_frame(payload)

        self.node.write_frame.side_effect = interrupted_write
        with self.assertRaises(KeyboardInterrupt):
            self.run_cli(self.cache_arguments())
        self.assertEqual([payload[1] for payload in self.sent_payloads()],
                         [ota.Op.CACHE_BEGIN, ota.Op.CACHE_PUT, ota.Op.CACHE_PUT])
        self.assertEqual(self.received, 1)
        self.evidence.log.assert_any_call("fatal", error="KeyboardInterrupt: ")
        self.evidence.finish.assert_called_once_with("KeyboardInterrupt: ")
        self.node.close.assert_called_once()

    def test_duplicate_sealed_full_image_signs_and_begins_then_proves_local_status_without_writes(self):
        self.image = b"\xa5" * 537816
        canonical = bytearray(manifest(self.image))
        struct.pack_into(">I", canonical, 45, 1)
        self.canonical = bytes(canonical)
        self.manifest_hash = hashlib.sha256(self.canonical).digest()
        self.image_path.write_bytes(self.image)
        self.manifest_path.write_bytes(self.canonical)
        self.cache_already_sealed = True
        self.run_cli(self.cache_arguments())
        self.assertEqual(self.sent_payloads(), [
            bytes.fromhex("421000") + self.public_key + self.canonical
            + self.private_key.sign(self.canonical),
            bytes.fromhex("4217") + bytes(32),
        ])
        self.assertEqual([call.args[0][0] for call in self.node.command.call_args_list], [1, 33, 34, 35])
        result = self.evidence.log.call_args.kwargs
        self.assertEqual((result["op"], result["phase"]), ("STATUS", "CACHE_SEALED"))
        self.assertFalse(result["remote"])
        self.assertTrue(result["snapshot_valid"])
        self.assertEqual(result["target"], "0" * 64)
        self.assertEqual(result["hash"], self.manifest_hash.hex())
        self.assertEqual((result["counter"], result["received"], result["total"]), (1, 6403, 6403))
        self.node.close.assert_called_once()
        self.evidence.finish.assert_called_once_with(None)

    def test_explicit_upload_can_start_after_fresh_sealed_reuse_but_never_commits(self):
        self.cache_already_sealed = True
        self.run_cli([*self.upload_arguments(), "--wait-ready"])
        payloads = self.sent_payloads()
        self.assertEqual([payload[1] for payload in payloads], [0x10, 0x17, 0x13, 0x14, 0x17])
        self.assertEqual(payloads[0][2], 0)
        self.assertEqual(payloads[1], bytes.fromhex("4217") + bytes(32))
        self.assertEqual(payloads[-1], bytes.fromhex("4217") + TARGET)
        self.assertEqual([call.args[0][0] for call in self.node.command.call_args_list], [1, 33, 34, 35])
        self.evidence.finish.assert_called_once_with(None)

    def test_sealed_begin_is_not_proof_when_fresh_status_binding_scope_or_blocks_fail(self):
        cases = (
            ({"manifest_hash": HASH}, ota.UploaderError),
            ({"counter": 8}, ota.UploaderError),
            ({"flags": 3}, ota.UploaderError),
            ({"received": 1}, ota.UploaderError),
            ({"received": 0, "total": 0}, ota.UploaderError),
            ({"received": 1, "total": 1}, ota.UploaderError),
            ({"phase": ota.Phase.RECEIVING}, TimeoutError),
            ({"phase": ota.Phase.FAILED}, ota.UploaderError),
            ({"phase": ota.Phase.ABORTED}, ota.UploaderError),
            ({"age": 20000}, TimeoutError),
            ({"target": OTHER_TARGET}, TimeoutError),
            ({"result": ota.Result.BUSY}, ota.UploaderError),
            ({"flags": 0, "phase": ota.Phase.UNKNOWN, "manifest_hash": bytes(32),
              "received": 0, "total": 0, "counter": 0, "age": ota.AGE_UNKNOWN,
              "generation": 0}, TimeoutError),
        )
        for fields, error in cases:
            with self.subTest(fields=fields):
                self.setUp()
                self.cache_already_sealed = True
                self.local_status = fields
                with self.assertRaises(error):
                    self.run_cli(self.cache_arguments())
                payloads = self.sent_payloads()
                self.assertEqual(payloads[0][1:3], bytes.fromhex("1000"))
                self.assertGreaterEqual(len(payloads), 2)
                self.assertTrue(all(payload == bytes.fromhex("4217") + bytes(32)
                                    for payload in payloads[1:]))
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
                self.assertIsNotNone(self.evidence.finish.call_args.args[0])
                self.node.close.assert_called_once()

    def test_sealed_begin_busy_or_conflict_still_requires_signing_and_fails_without_status_or_takeover(self):
        for result in (ota.Result.BUSY, ota.Result.MISMATCH, ota.Result.DENIED, ota.Result.UNAVAILABLE):
            with self.subTest(result=result):
                self.setUp()
                self.cache_already_sealed = True
                self.results[ota.Op.CACHE_BEGIN] = result
                with self.assertRaisesRegex(ota.UploaderError, result.name):
                    self.run_cli(self.cache_arguments())
                self.assertEqual(self.sent_payloads(), [
                    bytes.fromhex("421000") + self.public_key + self.canonical
                    + self.private_key.sign(self.canonical),
                ])
                self.assertEqual([call.args[0][0] for call in self.node.command.call_args_list], [1, 33, 34, 35])
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
                self.node.close.assert_called_once()

    def test_cache_reupload_is_explicit_and_never_sends_abort_or_replaces_refused_cache(self):
        self.run_cli([*self.cache_arguments(), "--reupload"])
        self.assertEqual(self.sent_payloads()[0][2], 1)
        self.node.reset_mock()
        self.received = 0
        self.results[ota.Op.CACHE_BEGIN] = ota.Result.MISMATCH
        with self.assertRaisesRegex(ota.UploaderError, "MISMATCH"):
            self.run_cli([*self.cache_arguments(), "--reupload"])
        self.assertEqual([payload[1] for payload in self.sent_payloads()], [0x10])
        self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
        self.assertIsNotNone(self.evidence.finish.call_args.args[0])

    def test_cache_invalid_manifest_or_image_refuses_before_evidence_resolution_or_open(self):
        for canonical, image, error in ((self.canonical[:-1], self.image, SystemExit),
                                        (self.canonical + b"\x00", self.image, SystemExit),
                                        (self.canonical, self.image[:-1], ValueError),
                                        (self.canonical, self.image[:-1] + b"x", ValueError),
                                        (self.canonical, b"", ValueError)):
            with self.subTest(size=len(image)), redirect_stderr(io.StringIO()):
                self.manifest_path.write_bytes(canonical)
                self.image_path.write_bytes(image)
                with self.assertRaises(error):
                    self.run_cli(self.cache_arguments())
                self.evidence_open.assert_not_called()
                self.resolve.assert_not_called()
                self.client_open.assert_not_called()
                self.node.command.assert_not_called()

    def test_cache_refuses_unapproved_target_or_pine_source_before_open(self):
        for serial in ("3BE94917B92DC5E9", "49C5BAF21EEF44A1", "unapproved"):
            with self.subTest(serial=serial):
                with self.assertRaisesRegex(AssertionError, "approved-cache-client"):
                    self.run_cli(self.cache_arguments(), serial=serial)
                self.client_open.assert_not_called()
                self.node.command.assert_not_called()
                self.node.write_frame.assert_not_called()

    def test_cache_cannot_select_remote_options_or_redirect_role(self):
        for arguments in ([*self.cache_arguments(), "--target", TARGET.hex()],
                          [*self.cache_arguments(), "--wait-ready"],
                          [*self.cache_arguments(), "--mode", "direct"],
                          [*self.cache_arguments(), "--frequency-khz", "908525"],
                          ["--client-role", "target", *self.cache_arguments()],
                          ["--client-role", "pine", *self.cache_arguments()]):
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.run_cli(arguments)
                self.resolve.assert_not_called()
                self.client_open.assert_not_called()

    def test_cache_seal_ack_alone_wrong_binding_scope_or_progress_cannot_succeed(self):
        cases = (
            ({"manifest_hash": HASH}, ota.UploaderError),
            ({"counter": 8}, ota.UploaderError),
            ({"flags": 3}, ota.UploaderError),
            ({"received": 1}, ota.UploaderError),
            ({"received": 1, "total": 1}, ota.UploaderError),
            ({"phase": ota.Phase.RECEIVING}, TimeoutError),
            ({"age": 20000}, TimeoutError),
            ({"target": OTHER_TARGET}, TimeoutError),
        )
        for fields, error in cases:
            with self.subTest(fields=fields):
                self.setUp()
                self.local_status = fields
                with self.assertRaises(error):
                    self.run_cli(self.cache_arguments())
                self.assertEqual([payload[1] for payload in self.sent_payloads()[:4]], [0x10, 0x11, 0x11, 0x12])
                self.assertTrue(all(payload[1] in (0x10, 0x11, 0x12, 0x17)
                                    for payload in self.sent_payloads()))
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
                self.assertIsNotNone(self.evidence.finish.call_args.args[0])
                self.node.close.assert_called_once()

    def test_cache_bad_signature_denied_unavailable_or_io_failure_never_starts_or_aborts(self):
        for op, result, invalid_signature, error in (
            (ota.Op.CACHE_BEGIN, ota.Result.OK, True, InvalidSignature),
            (ota.Op.CACHE_BEGIN, ota.Result.DENIED, False, ota.UploaderError),
            (ota.Op.CACHE_BEGIN, ota.Result.UNAVAILABLE, False, ota.UploaderError),
            (ota.Op.CACHE_PUT, ota.Result.IO_ERROR, False, ota.UploaderError),
            (ota.Op.CACHE_SEAL, ota.Result.DENIED, False, ota.UploaderError),
        ):
            with self.subTest(op=op, result=result, invalid_signature=invalid_signature):
                self.setUp()
                self.results[op] = result
                if invalid_signature:
                    self.signature_override = bytes(64)
                with self.assertRaises(error):
                    self.run_cli(self.cache_arguments())
                self.assertTrue(all(payload[1] in (0x10, 0x11, 0x12)
                                    for payload in self.sent_payloads()))
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
                self.node.close.assert_called_once()

    def test_cache_existing_evidence_is_refused_before_device_resolution(self):
        argv = ["ota_uploader.py", "--artifact-dir", str(self.directory), *self.cache_arguments()]
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(ota.lab_device, "resolve") as resolve, \
                mock.patch.object(ota.lab, "FramedSerial") as client_open:
            with self.assertRaises(FileExistsError):
                ota.main()
            resolve.assert_not_called()
            client_open.assert_not_called()
        self.assertEqual(set(self.directory.iterdir()), {self.image_path, self.manifest_path})

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
                         [bytes([66, ota.Op.STATUS]) + TARGET,
                          bytes([66, ota.Op.ABORT]) + TARGET + hashlib.sha256(self.image).digest()
                          + bytes.fromhex("12345678"),
                          bytes([66, ota.Op.STATUS]) + TARGET])
        self.assertEqual(self.evidence.log.call_args.kwargs["generation"], 0x12345679)
        self.node.close.assert_called_once()
        self.evidence.finish.assert_called_once_with(None)

    def test_explicit_cache_abort_does_not_address_a_remote_target(self):
        self.run_cli(["abort-cache", "--image", str(self.image_path)])
        self.assertEqual(self.sent_payloads(),
                         [bytes([66, ota.Op.STATUS]) + ota.LOCAL_TARGET,
                          bytes([66, ota.Op.ABORT]) + ota.LOCAL_TARGET
                          + hashlib.sha256(self.image).digest() + bytes.fromhex("12345678"),
                          bytes([66, ota.Op.STATUS]) + ota.LOCAL_TARGET])
        self.node.command.assert_not_called()
        self.node.close.assert_called_once()
        self.assertFalse(self.evidence.log.call_args.kwargs["remote"])
        self.assertEqual(self.evidence.log.call_args.kwargs["phase"], ota.Phase.ABORTED.name)

    def test_abort_transmits_observed_nonzero_or_wrapped_zero_generation_in_exact_70_byte_request(self):
        for generation in (0, 0x12345678, 0xFFFFFFFF):
            with self.subTest(generation=generation):
                self.setUp()
                self.generation = generation
                self.run_cli(["abort-cache", "--image", str(self.image_path)])
                payloads = self.sent_payloads()
                self.assertEqual([payload[1] for payload in payloads], [0x17, 0x16, 0x17])
                self.assertEqual(len(payloads[1]), 70)
                self.assertEqual(payloads[1][2:34], bytes(32))
                self.assertEqual(payloads[1][34:66], hashlib.sha256(self.image).digest())
                self.assertEqual(payloads[1][66:70], struct.pack(">I", generation))
                result = self.evidence.log.call_args.kwargs
                self.assertEqual(result["op"], "STATUS")
                self.assertEqual(result["generation"], (generation + 1) & 0xFFFFFFFF)
                self.assertEqual(result["hash"], self.manifest_hash.hex())
                self.assertNotEqual(result["hash"], hashlib.sha256(self.image).hexdigest())
                self.node.command.assert_not_called()
                aborted_generation = self.generation
                self.node.reset_mock()
                self.run_cli(["abort-cache", "--image", str(self.image_path)])
                self.assertEqual(self.sent_payloads()[1][66:70], struct.pack(">I", aborted_generation))
                self.assertEqual(self.generation, aborted_generation)
                self.assertEqual(self.evidence.log.call_args.kwargs["generation"], aborted_generation)

    def test_missing_stale_wrong_target_scope_or_blocked_status_cannot_write_abort(self):
        cases = (
            ({"age": 20000}, TimeoutError),
            ({"target": OTHER_TARGET}, TimeoutError),
            ({"flags": 3}, ota.UploaderError),
            ({"result": ota.Result.BUSY}, ota.UploaderError),
            ({"result": ota.Result.DENIED}, ota.UploaderError),
            ({"result": ota.Result.UNAVAILABLE}, ota.UploaderError),
            ({"phase": ota.Phase.UNKNOWN}, ota.UploaderError),
            ({"phase": ota.Phase.IDLE}, ota.UploaderError),
            ({"flags": 0, "phase": ota.Phase.UNKNOWN, "manifest_hash": bytes(32),
              "received": 0, "total": 0, "counter": 0, "age": ota.AGE_UNKNOWN,
              "generation": 0}, TimeoutError),
        )
        for fields, error in cases:
            with self.subTest(fields=fields):
                self.setUp()
                self.local_status = fields
                with self.assertRaises(error):
                    self.run_cli(["abort-cache", "--image", str(self.image_path)])
                self.assertTrue(self.sent_payloads())
                self.assertTrue(all(payload == bytes.fromhex("4217") + bytes(32)
                                    for payload in self.sent_payloads()))
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
                self.assertIsNotNone(self.evidence.finish.call_args.args[0])
        self.setUp()
        self.node.take_pending.side_effect = lambda codes: []
        with self.assertRaises(TimeoutError):
            self.run_cli(["abort-cache", "--image", str(self.image_path)])
        self.assertEqual([payload[1] for payload in self.sent_payloads()], [0x17])

    def test_legacy_missing_generation_or_malformed_reply_cannot_emit_abort(self):
        for defect in ("legacy", "short-v2", "bad-enum", "no-snapshot-generation"):
            with self.subTest(defect=defect):
                self.setUp()

                def malformed(op, response):
                    data = bytearray(response)
                    if defect == "legacy":
                        data[1] = 1
                        return bytes(data[:86])
                    if defect == "short-v2":
                        return bytes(data[:86])
                    if defect == "bad-enum":
                        data[4] = 255
                    else:
                        return frame(target=ota.LOCAL_TARGET, flags=0, phase=ota.Phase.UNKNOWN,
                                     manifest_hash=bytes(32), received=0, total=0, counter=0,
                                     age=ota.AGE_UNKNOWN, generation=1)
                    return bytes(data)

                self.reply_mutator = malformed
                with self.assertRaises(ota.UploaderError):
                    self.run_cli(["abort-cache", "--image", str(self.image_path)])
                self.assertEqual([payload[1] for payload in self.sent_payloads()], [0x17])
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))

    def test_abort_ack_cannot_claim_success_without_fresh_durable_generation_bound_readback(self):
        cases = (
            ({"age": 20000}, TimeoutError),
            ({"generation": 0x12345678}, ota.UploaderError),
            ({"manifest_hash": HASH}, ota.UploaderError),
            ({"counter": 8}, ota.UploaderError),
            ({"flags": 3}, ota.UploaderError),
            ({"phase": ota.Phase.CACHE_SEALED}, TimeoutError),
            ({"result": ota.Result.BUSY}, ota.UploaderError),
            ({"result": ota.Result.PENDING}, TimeoutError),
            ({"target": OTHER_TARGET}, TimeoutError),
            ({"flags": 0, "phase": ota.Phase.UNKNOWN, "manifest_hash": bytes(32),
              "received": 0, "total": 0, "counter": 0, "age": ota.AGE_UNKNOWN,
              "generation": 0}, TimeoutError),
        )
        for fields, error in cases:
            with self.subTest(fields=fields):
                self.setUp()

                def uncertain(op, response):
                    if op == ota.Op.ABORT:
                        return frame(op=op, result=ota.Result.PENDING, target=ota.LOCAL_TARGET,
                                     flags=0, phase=ota.Phase.UNKNOWN, manifest_hash=bytes(32),
                                     received=0, total=0, counter=0, age=ota.AGE_UNKNOWN, generation=0)
                    if op == ota.Op.STATUS and self.local_phase == ota.Phase.ABORTED:
                        values = dict(target=ota.LOCAL_TARGET, flags=1, phase=ota.Phase.ABORTED,
                                      manifest_hash=self.manifest_hash, generation=self.generation)
                        values.update(fields)
                        return frame(**values)
                    return response

                self.reply_mutator = uncertain
                with self.assertRaises(error):
                    self.run_cli(["abort-cache", "--image", str(self.image_path)])
                ops = [payload[1] for payload in self.sent_payloads()]
                self.assertEqual(ops[:2], [0x17, 0x16])
                self.assertEqual(ops.count(0x16), 1)
                self.assertTrue(all(op == 0x17 for op in ops[2:]))
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
                self.assertIsNotNone(self.evidence.finish.call_args.args[0])

    def test_receiver_content_mismatch_is_not_confused_with_canonical_status_hash_or_forced(self):
        self.image_path.write_bytes(b"other" * 20)
        with self.assertRaisesRegex(ota.UploaderError, "MISMATCH"):
            self.run_cli(["abort-cache", "--image", str(self.image_path)])
        payloads = self.sent_payloads()
        self.assertEqual([payload[1] for payload in payloads], [0x17, 0x16])
        self.assertEqual(payloads[1][34:66], hashlib.sha256(b"other" * 20).digest())
        self.assertEqual(self.local_phase, ota.Phase.CACHE_SEALED)
        self.assertEqual(self.generation, 0x12345678)
        self.assertEqual(self.evidence.log.call_args.args, ("fatal",))

    def test_remote_abort_waits_through_fresh_prior_generation_until_durable_aborted_including_wrap(self):
        for generation in (0x12345678, 0xFFFFFFFF, 0):
            with self.subTest(generation=generation):
                self.setUp()
                self.generation = generation
                phases = [ota.Phase.RECEIVING, ota.Phase.VERIFYING,
                          ota.Phase.READY, ota.Phase.COMMIT_PENDING]

                def in_transit(op, response):
                    if op == ota.Op.ABORT:
                        return frame(op=op, target=TARGET, flags=ota.REMOTE, phase=ota.Phase.UNKNOWN,
                                     manifest_hash=bytes(32), received=0, total=0, counter=0,
                                     age=ota.AGE_UNKNOWN, generation=0)
                    if op == ota.Op.STATUS and self.remote_phase == ota.Phase.ABORTED and phases:
                        data = bytearray(response)
                        data[4] = phases.pop(0)
                        struct.pack_into(">I", data, 86, generation)
                        return bytes(data)
                    return response

                self.reply_mutator = in_transit
                self.run_cli(["abort", "--target", TARGET.hex(), "--image", str(self.image_path)])
                self.assertEqual([payload[1] for payload in self.sent_payloads()],
                                 [0x17, 0x16, 0x17, 0x17, 0x17, 0x17, 0x17])
                self.assertEqual(self.sent_payloads()[1][66:70], struct.pack(">I", generation))
                result = self.evidence.log.call_args.kwargs
                self.assertEqual((result["op"], result["phase"]), ("STATUS", "ABORTED"))
                self.assertEqual(result["generation"], (generation + 1) & 0xFFFFFFFF)
                self.assertFalse(phases)
                self.evidence.finish.assert_called_once_with(None)

    def test_remote_abort_stuck_at_fresh_prior_generation_times_out_without_resending_or_claiming_cancel(self):
        generation = self.generation

        def in_transit(op, response):
            if op == ota.Op.STATUS and self.remote_phase == ota.Phase.ABORTED:
                data = bytearray(response)
                data[4] = ota.Phase.RECEIVING
                struct.pack_into(">I", data, 86, generation)
                return bytes(data)
            return response

        self.reply_mutator = in_transit
        with self.assertRaisesRegex(TimeoutError, "fresh ABORTED"):
            self.run_cli(["abort", "--target", TARGET.hex(), "--image", str(self.image_path)])
        ops = [payload[1] for payload in self.sent_payloads()]
        self.assertEqual(ops[:2], [0x17, 0x16])
        self.assertEqual(ops.count(0x16), 1)
        self.assertTrue(all(op == 0x17 for op in ops[2:]))
        self.assertLessEqual(self.clock.now, 112.1)
        self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
        self.assertIsNotNone(self.evidence.finish.call_args.args[0])

    def test_remote_abort_rejects_new_attempt_or_wrong_generation_aborted_instead_of_waiting(self):
        for phase, delta in ((ota.Phase.RECEIVING, 2), (ota.Phase.READY, -1),
                             (ota.Phase.ABORTED, 0), (ota.Phase.ABORTED, 2)):
            with self.subTest(phase=phase, delta=delta):
                self.setUp()
                generation = self.generation

                def unrelated(op, response):
                    if op == ota.Op.STATUS and self.remote_phase == ota.Phase.ABORTED:
                        data = bytearray(response)
                        data[4] = phase
                        struct.pack_into(">I", data, 86, (generation + delta) & 0xFFFFFFFF)
                        return bytes(data)
                    return response

                self.reply_mutator = unrelated
                with self.assertRaisesRegex(ota.UploaderError, "different generation"):
                    self.run_cli(["abort", "--target", TARGET.hex(), "--image", str(self.image_path)])
                self.assertEqual([payload[1] for payload in self.sent_payloads()], [0x17, 0x16, 0x17])
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))

    def test_already_aborted_remote_cleanup_never_allows_previous_generation_intermediate(self):
        for generation in (0, 0x12345678):
            with self.subTest(generation=generation):
                self.setUp()
                self.generation = generation
                self.remote_phase = ota.Phase.ABORTED
                requested = False

                def previous(op, response):
                    nonlocal requested
                    if op == ota.Op.ABORT:
                        requested = True
                    elif op == ota.Op.STATUS and requested:
                        data = bytearray(response)
                        data[4] = ota.Phase.RECEIVING
                        struct.pack_into(">I", data, 86, (generation - 1) & 0xFFFFFFFF)
                        return bytes(data)
                    return response

                self.reply_mutator = previous
                with self.assertRaisesRegex(ota.UploaderError, "different generation"):
                    self.run_cli(["abort", "--target", TARGET.hex(), "--image", str(self.image_path)])
                self.assertEqual(self.sent_payloads()[1][66:70], struct.pack(">I", generation))
                self.assertEqual([payload[1] for payload in self.sent_payloads()], [0x17, 0x16, 0x17])

    def test_prior_generation_intermediate_still_requires_fresh_bound_content_counter_and_scope(self):
        for defect, error, message in (
            ("hash", ota.UploaderError, "different manifest or counter"),
            ("counter", ota.UploaderError, "different manifest or counter"),
            ("scope", ota.UploaderError, "wrong local/remote scope"),
            ("stale", TimeoutError, "fresh ABORTED"),
        ):
            with self.subTest(defect=defect):
                self.setUp()
                generation = self.generation

                def corrupt(op, response):
                    if op == ota.Op.STATUS and self.remote_phase == ota.Phase.ABORTED:
                        data = bytearray(response)
                        data[4] = ota.Phase.READY
                        struct.pack_into(">I", data, 86, generation)
                        if defect == "hash":
                            data[38:70] = HASH
                        elif defect == "counter":
                            struct.pack_into(">I", data, 74, 8)
                        elif defect == "scope":
                            data[5] &= ~ota.REMOTE
                        else:
                            struct.pack_into(">I", data, 78, 20000)
                        return bytes(data)
                    return response

                self.reply_mutator = corrupt
                with self.assertRaisesRegex(error, message):
                    self.run_cli(["abort", "--target", TARGET.hex(), "--image", str(self.image_path)])
                self.assertEqual([payload[1] for payload in self.sent_payloads()].count(0x16), 1)
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))

    def test_lost_abort_ack_retry_uses_current_aborted_generation_without_reupload_or_takeover(self):
        self.drop_abort_reply = True
        with self.assertRaises(TimeoutError):
            self.run_cli(["abort-cache", "--image", str(self.image_path)])
        self.assertEqual(self.local_phase, ota.Phase.ABORTED)
        old_abort = self.sent_payloads()[1]
        self.drop_abort_reply = False
        generation = self.generation
        self.node.reset_mock()
        self.evidence.reset_mock()
        self.run_cli(["abort-cache", "--image", str(self.image_path)])
        payloads = self.sent_payloads()
        self.assertEqual([payload[1] for payload in payloads], [0x17, 0x16, 0x17])
        self.assertEqual(payloads[1][66:70], struct.pack(">I", generation))
        self.assertEqual(self.generation, generation)
        self.node.write_frame(old_abort)
        self.assertEqual(ota.decode_reply(self.pending[-1][1]).result, ota.Result.OK)
        self.assertEqual(self.generation, generation)

    def test_old_abort_generation_cannot_cancel_explicit_same_image_reupload(self):
        self.run_cli(["abort-cache", "--image", str(self.image_path)])
        old_abort = self.sent_payloads()[1]
        self.node.reset_mock()
        self.received = 0
        self.run_cli([*self.cache_arguments(), "--reupload"])
        generation = self.generation
        self.assertEqual(self.local_phase, ota.Phase.CACHE_SEALED)
        self.node.write_frame(old_abort)
        delayed = ota.decode_reply(self.pending[-1][1])
        self.assertEqual(delayed.result, ota.Result.MISMATCH)
        self.assertEqual(self.generation, generation)
        self.assertEqual(self.local_phase, ota.Phase.CACHE_SEALED)

    def test_denied_local_cache_abort_is_not_success(self):
        self.results[ota.Op.ABORT] = ota.Result.DENIED
        with self.assertRaisesRegex(ota.UploaderError, "DENIED"):
            self.run_cli(["abort-cache", "--image", str(self.image_path)])
        self.assertEqual([payload[1] for payload in self.sent_payloads()], [ota.Op.STATUS, ota.Op.ABORT])
        self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
        self.node.close.assert_called_once()

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
