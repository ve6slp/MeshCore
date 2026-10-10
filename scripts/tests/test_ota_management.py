"""Synthetic remote-management and bounded partial-pair tests; no hardware."""
from contextlib import contextmanager, redirect_stdout
from dataclasses import replace
import io
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ota_management as management
import ota_stock_companion as ota
from test_ota_stock_companion import (Clock, FakeSerial, FleetSerial, NORMAL, OWNER, TARGET, TARGET2,
                                      Scratch, binding, candidate, census, fleet_setup, stock_async_noise)

from types import SimpleNamespace
lifecycle = SimpleNamespace(partial=ota.partial_background_operation, check_restart=ota.validate_partial_restart)
NOW = 1800000000
NAME = "synthetic-target"


def contact(key=TARGET, name=NAME):
    frame = bytearray(148)
    frame[0] = 3
    frame[1:33] = key
    frame[33] = 2
    frame[35] = 0xFF
    frame[100:100 + len(name)] = name.encode()
    return bytes(frame)


def message(text, key=TARGET, timestamp=NOW + 1, kind=1):
    return b"\x10\x00\x00\x00" + key[:6] + b"\xff" + bytes([kind]) + struct.pack("<I", timestamp) + text.encode()


class ManagementSerial(FakeSerial):
    def __init__(self, clock):
        super().__init__(clock, candidate())
        self.contacts = [contact(), contact(TARGET2)]
        self.mail = [message("PRIVATE-UNRELATED-MESSAGE", TARGET2)]
        self.login_response = b"\x85\x01" + TARGET[:6] + struct.pack("<I", NOW) + b"\x03\x02"
        self.remote_time = NOW
        self.phase = "receiving"
        self.generation = 10
        self.counter = 5
        self.image_hash = self.candidate.digest.hex()
        self.duty = 2.0
        self.durable_abort = False
        self.before_abort = None
        self.abort_mutations = 0
        self.cli_mutator = None
        self.login_mutator = None
        self.refuse_cmd = None
        self.cancel_cmd = None
        self.drop_cli = False
        self.cli = []

    def text(self, command):
        if command.startswith("ota abort"):
            if not management.valid_abort_command(command.encode("ascii")):
                return "Err - usage: ota abort <generation> <counter> <image>"
            _, _, generation, counter, image = command.split(" ")
            if self.phase == "idle":
                return "Err - OTA abort not found"
            if (int(generation) != self.generation or int(counter) != self.counter or image != self.image_hash):
                return "Err - OTA abort mismatch"
            if self.durable_abort:
                if self.phase not in ("aborted", "idle"):
                    self.generation = (self.generation + 1) & 0xFFFFFFFF
                    self.phase = "aborted"
                    self.abort_mutations += 1
            return "OK - OTA aborted"
        if command == "ota candidate":
            if self.phase == "idle":
                return "candidate=none phase=idle"
            return f"candidate=receiver phase={self.phase} counter={self.counter} generation={self.generation} image={self.image_hash}"
        if command == "ota progress":
            if self.phase == "idle":
                return "candidate=none phase=idle"
            return f"candidate=receiver phase={self.phase} received=0 total=2 missing=2 bytes=168 block=84"
        if command == "ota settings":
            return f"mode=fleet duty={self.duty:.1f}%"
        return f"boot=unknown phase={self.phase} floor=4 counter={self.counter} verified=0 image={self.image_hash}"

    def write(self, wire):
        payload = wire[3:]
        if payload[0] not in (2, 4, 10, 26):
            return super().write(wire)
        self.commands.append(payload)
        cmd = payload[0]
        if cmd == self.cancel_cmd:
            raise ota.Cancelled("synthetic host cancellation")
        if cmd == self.refuse_cmd:
            self.reply(b"\x01\x06")
            return len(wire)
        if cmd == 4:
            self.reply(b"\x02" + struct.pack("<I", len(self.contacts)))
            for record in self.contacts:
                self.reply(record)
            self.reply(b"\x04" + bytes(4))
        elif cmd == 10:
            self.reply(self.mail.pop(0) if self.mail else b"\x0a")
        elif cmd == 26:
            assert payload == b"\x1a" + TARGET
            self.reply(b"\x06\x01" + TARGET[:4] + struct.pack("<I", 1000))
            if self.login_response is not None:
                result = self.login_response
                if self.login_mutator:
                    result = self.login_mutator(result)
                self.schedule(0.1, lambda: self.reply(result))
        else:
            assert payload[:13] == b"\x02\x01\x00" + bytes(4) + TARGET[:6]
            command = payload[13:].decode()
            self.cli.append(command)
            self.reply(b"\x06\x01" + bytes(4) + struct.pack("<I", 1000))
            self.remote_time += 1
            if command.startswith("ota abort ") and self.before_abort:
                self.before_abort(self)
            result = message(self.text(command), timestamp=self.remote_time)
            if self.cli_mutator:
                result = self.cli_mutator(result)
            if not self.drop_cli:
                self.schedule(0.1, lambda: self.mail.append(result))
        return len(wire)


def setup():
    clock = Clock()
    stream = ManagementSerial(clock)
    stock = ota.Stock(ota.Frames(stream, clock, keep_login_pushes=True), OWNER, clock, clock.sleep)
    manager = management.RemoteManagement(stock, binding(), NAME, timeout=3,
                                          wall_clock=lambda: NOW, max_skew=120)
    return clock, stream, manager


class RestartFleetSerial(FleetSerial):
    def __init__(self, clock, c):
        super().__init__(clock, c)
        self.reuploads = []
        self.same_nonce = False
        for node in self.nodes.values():
            node["aborted"] = False

    def remote(self, wire):
        attempt, frame = ota.retry_payload(wire)
        if frame[0] == 1:
            blocked = [node for node in self.nodes.values() if node["aborted"] and node["permission"]]
            for node in blocked:
                node["permission"] = False
            try:
                return super().remote(wire)
            finally:
                for node in blocked:
                    node["permission"] = True
        if frame[0] == 10 and self.nodes[frame[1:33]]["aborted"]:
            node = self.nodes[frame[1:33]]
            first = struct.unpack_from(">H", frame, 65)[0]
            report = census(self.candidate, first, set(), node["generation"], lifecycle=9,
                            floor=node["floor"], nonce=node["nonce"], target=frame[1:33], challenge=0)
            report = report[:87] + b"\x05" + report[88:]
            self.schedule(0.1, lambda: self.reply(b"\x88\x08\x40\x31\x00" + ota.retry_frame(report, attempt)))
            return
        if frame[0] == 14:
            key = frame[33:65]
            node = self.nodes[key]
            self.reuploads.append(key)
            ota.verify(OWNER, ota.REUPLOAD_DOMAIN + frame[:101], frame[101:])
            assert frame[1:33] == OWNER and frame[65:97] == self.candidate.digest
            assert struct.unpack_from(">I", frame, 97)[0] == node["generation"]
            if node["aborted"] and node["permission"]:
                node["aborted"] = False
                node["generation"] += 1
                if not self.same_nonce:
                    node["nonce"] = bytes([node["generation"]]) * 16
            return
        return super().remote(wire)


def restart_setup():
    clock, _, _, original = fleet_setup(candidate(84 * 40), duty=0.8)
    stream = RestartFleetSerial(clock, original.transport.candidate)
    stock = ota.Stock(ota.Frames(stream, clock), OWNER, clock, clock.sleep)
    campaign = ota.BackgroundCampaign(stock, [t.binding for t in original.targets], original.transport.candidate,
                                      NORMAL, clock() + 10000, 0.8, clock, clock.sleep)
    return clock, stream, stock, campaign


class ManagementTests(unittest.TestCase):
    def test_real_stock_login_cli_sync_frames_no_raw_census_or_local_cli(self):
        clock, stream, manager = setup()
        manager.login()
        for operation in ("status", "candidate", "progress", "settings"):
            result = manager.query(operation)
            self.assertEqual(result["transport"], "stock-encrypted-pairwise-remote-cli")
            self.assertFalse(result["host_mac_verified"])
            self.assertFalse(result["cryptographic_request_correlation"])
            self.assertFalse(result["status_authenticated"])
        self.assertEqual(stream.cli, ["ota status", "ota candidate", "ota progress", "ota settings"])
        self.assertEqual([cmd for cmd in stream.commands if cmd[0] == 26], [b"\x1a" + TARGET])
        self.assertTrue(all(cmd[0] in (1, 22, 4, 10, 26, 2) for cmd in stream.commands))
        self.assertTrue(all(len(cmd) <= 176 for cmd in stream.commands))
        self.assertGreater(manager.discarded_messages, 0)
        self.assertNotIn("PRIVATE-UNRELATED-MESSAGE", json.dumps(result))

    def test_login_push_opt_in_preserves_bounded_default_ota_demux(self):
        _, stream, manager = setup()
        frame = stream.login_response
        wire = b">" + struct.pack("<H", len(frame)) + frame
        normal = ota.Frames(stream)
        normal.feed(wire)
        self.assertFalse(normal.pending)
        manager.stock.frames.feed(wire)
        self.assertEqual(manager.stock.frames.pending[0][1], frame)
        for _ in range(ota.PENDING_LIMIT - 1):
            manager.stock.frames.feed(wire)
        with self.assertRaisesRegex(ota.Error, "backlog"):
            manager.stock.frames.feed(wire)

    def test_missing_contact_name_or_prefix_ambiguity_refuses_before_login(self):
        for records in ([contact(TARGET2)], [contact(name="wrong")],
                        [contact(), contact(TARGET[:4] + b"\x77" * 28)], [contact(), contact()]):
            with self.subTest(records=len(records)):
                _, stream, manager = setup()
                stream.contacts = records
                with self.assertRaises(ota.Error):
                    manager.login()
                self.assertFalse(any(cmd[0] == 26 for cmd in stream.commands))

    def test_sender_identity_profile_or_label_refuses_before_management(self):
        for mutate in (lambda s: setattr(s, "wrong_identity", True),
                       lambda s: setattr(s, "profile", (919000, *NORMAL[1:]))):
            _, stream, manager = setup()
            mutate(stream)
            with self.assertRaises(ota.Error):
                manager.login()
            self.assertFalse(any(cmd[0] in (2, 26) for cmd in stream.commands))

    def test_login_denial_legacy_guest_clock_and_malformed_fail_closed(self):
        samples = [b"\x86\x00" + TARGET[:6], b"\x85\x00" + TARGET[:6],
                   b"\x85\x01" + TARGET[:6] + struct.pack("<I", NOW) + b"\x02\x02",
                   b"\x85\x01" + TARGET[:6] + struct.pack("<I", NOW - 121) + b"\x03\x02",
                   b"\x85" + bytes(8)]
        for response in samples:
            _, stream, manager = setup()
            stream.login_response = response
            with self.assertRaises(ota.Error):
                manager.login()
            self.assertFalse(manager.session)
            self.assertFalse(stream.cli)

    def test_wrong_target_login_and_no_login_timeout(self):
        for response in (None, b"\x85\x01" + TARGET2[:6] + struct.pack("<I", NOW) + b"\x03\x02"):
            _, stream, manager = setup()
            stream.login_response = response
            with self.assertRaises(ota.NoUsbResponse):
                manager.login()
            self.assertFalse(stream.cli)

    def test_admin_session_and_fixed_operation_allowlist_no_password_or_arbitrary_cli(self):
        _, stream, manager = setup()
        with self.assertRaises(ota.Error):
            manager.query("status")
        manager.login()
        for operation in ("reboot", "password secret", "ota abort", "abort", "get radio", "rollback"):
            with self.assertRaises(ota.Error):
                manager.query(operation)
        with self.assertRaises(ota.Error):
            manager._command(b"\x1a" + TARGET + b"secret", (6,), manager.stock.clock() + 3)
        with self.assertRaises(ota.Error):
            manager._command(b"\x02\x01\x00" + bytes(4) + TARGET[:6] + b"reboot",
                             (6,), manager.stock.clock() + 3)
        with self.assertRaises(ota.Error):
            manager._command(b"\x02\x01\x00" + bytes(4) + TARGET[:6] + b"ota abort",
                             (6,), manager.stock.clock() + 3)
        self.assertFalse(stream.cli)

    def test_stale_target_message_wrong_type_auth_errors_and_payload_privacy(self):
        mutations = [
            lambda f: message("PRIVATE-TARGET-MESSAGE", timestamp=NOW),
            lambda f: message("Err - candidate storage unavailable", timestamp=NOW + 1),
            lambda f: message("PRIVATE-TARGET-MESSAGE", timestamp=NOW + 1),
            lambda f: message("candidate=receiver phase=ready counter=5 generation=10 image=invalid"),
            lambda f: f[:2] + b"\x01" + f[3:],
        ]
        for mutate in mutations:
            _, stream, manager = setup()
            manager.login()
            stream.cli_mutator = mutate
            with self.assertRaises(ota.Error) as error:
                manager.query("candidate")
            self.assertNotIn("PRIVATE", str(error.exception))
            self.assertFalse(manager.session)

    def test_unrelated_messages_and_ordinary_echoes_never_become_replies(self):
        _, stream, manager = setup()
        stock_async_noise(stream)
        manager.login()
        def mixed(frame):
            stream.mail.extend([message("PRIVATE", TARGET2), message("PRIVATE", kind=0)])
            return frame
        stream.cli_mutator = mixed
        result = manager.query("settings")
        self.assertEqual(result["reply"], {"mode": "fleet", "duty": "2.0%"})
        self.assertGreaterEqual(manager.discarded_messages, 3)

    def test_remote_timeout_usb_refusal_cancel_and_session_expiry_never_auto_abort(self):
        for setting in ("drop_cli", "refuse_cmd", "cancel_cmd"):
            _, stream, manager = setup()
            manager.login()
            setattr(stream, setting, True if setting == "drop_cli" else 2)
            with self.assertRaises(ota.Error):
                manager.query("progress")
            self.assertFalse(manager.session)
            self.assertFalse(manager.abort_dispatched)
            self.assertNotIn("ota abort", stream.cli)
        clock, stream, manager = setup()
        manager.login()
        clock.sleep(301)
        with self.assertRaises(ota.Error):
            manager.query("settings")
        self.assertFalse(stream.cli)

    def test_160_byte_reply_and_176_frame_limit_invalid_geometry(self):
        valid = "candidate=receiver phase=receiving counter=4294967295 generation=4294967295 image=" + "f" * 64
        self.assertLessEqual(len(valid), 160)
        management.fields("candidate", valid)
        with self.assertRaises(ota.Error):
            management.fields("progress", "candidate=receiver phase=receiving received=3 total=2 missing=0 bytes=168 block=84")
        _, stream, manager = setup()
        with self.assertRaises(ota.Error):
            manager.stock.frames.feed(b">" + struct.pack("<H", 177) + bytes(177))

    def test_explicit_abort_guard_legacy_ack_is_not_durable_and_repeated_abort_truth(self):
        _, stream, manager = setup()
        manager.login()
        image = stream.candidate.digest.hex()
        with self.assertRaises(ota.Error):
            manager.abort(11, 5, image)
        self.assertNotIn("ota abort", stream.cli)
        result = manager.abort(10, 5, image)
        self.assertEqual(result["outcome"], "transport-stop-only-or-unproven")
        self.assertTrue(result["reply"]["abort_acknowledged"])
        self.assertFalse(result["reply"]["durable_abort_confirmed"])
        self.assertEqual(stream.phase, "receiving")
        stream.durable_abort = True
        for generation in (10, 11):
            result = manager.abort(generation, 5, image)
            self.assertTrue(result["reply"]["durable_abort_confirmed"])
            self.assertEqual(result["candidate_after"]["reply"]["phase"], "aborted")
            self.assertEqual(result["candidate_after"]["reply"]["generation"], "11")

    def test_abort_failure_or_cancel_does_not_claim_revocation(self):
        for mutation in (lambda f: message("Error: OTA unsupported"),
                         lambda f: message("OK - OTA aborted", timestamp=NOW)):
            _, stream, manager = setup()
            manager.login()
            stream.cli_mutator = lambda f: mutation(f) if stream.cli[-1].startswith("ota abort ") else f
            with self.assertRaises(ota.Error):
                manager.abort(10, 5, stream.candidate.digest.hex())
            self.assertTrue(manager.abort_dispatched)
            self.assertFalse(manager.session)

    def test_idle_guarded_abort_is_not_found_and_floor_drift_is_not_confirmed(self):
        _, stream, manager = setup()
        stream.phase = "idle"
        manager.login()
        self.assertEqual(manager.query("candidate")["reply"], {"candidate": "none", "phase": "idle"})
        with self.assertRaisesRegex(ota.Refused, "not found"):
            manager.abort(10, 5, stream.image_hash)
        self.assertEqual(stream.abort_mutations, 0)
        _, stream, manager = setup()
        manager.login()
        stream.durable_abort = True
        def drift(frame):
            if stream.cli[-1] == "ota status" and stream.phase == "aborted":
                return frame.replace(b"floor=4", b"floor=5")
            return frame
        stream.cli_mutator = drift
        self.assertFalse(manager.abort(10, 5, stream.candidate.digest.hex())["reply"]["durable_abort_confirmed"])

    def test_usb_bad_send_admission_cannot_be_cli_success(self):
        _, stream, manager = setup()
        manager.login()
        original = stream.reply
        def malformed(frame):
            original(frame[:6] if frame[:2] == b"\x06\x01" else frame)
        stream.reply = malformed
        with self.assertRaises(ota.Error):
            manager.query("settings")
        self.assertFalse(manager.session)

    def test_durable_abort_requires_generation_advance_and_repeat_is_unchanged(self):
        _, stream, manager = setup()
        manager.login()
        stream.durable_abort = True
        def unchanged(frame):
            if stream.cli[-1] == "ota candidate" and stream.phase == "aborted":
                return frame.replace(b"generation=11", b"generation=10")
            return frame
        stream.cli_mutator = unchanged
        result = manager.abort(10, 5, stream.candidate.digest.hex())
        self.assertFalse(result["reply"]["durable_abort_confirmed"])
        self.assertEqual(result["expected_aborted_generation"], 11)
        stream.cli_mutator = None
        result = manager.abort(11, 5, stream.candidate.digest.hex())
        self.assertTrue(result["reply"]["durable_abort_confirmed"])
        self.assertEqual(stream.generation, 11)

    def test_abort_wire_contains_exact_guards_and_replacement_race_is_refused_without_mutation(self):
        changes = (lambda stream: setattr(stream, "generation", 12),
                   lambda stream: setattr(stream, "counter", 6),
                   lambda stream: setattr(stream, "image_hash", "f" * 64))
        for change in changes:
            with self.subTest(change=change):
                _, stream, manager = setup()
                manager.login()
                stream.durable_abort = True
                stream.before_abort = change
                selected_hash = stream.image_hash
                with self.assertRaisesRegex(ota.Refused, "guarded OTA abort refused: mismatch"):
                    manager.abort(10, 5, selected_hash)
                self.assertEqual(stream.cli[-1], f"ota abort 10 5 {selected_hash}")
                self.assertTrue(manager.abort_dispatched)
                self.assertFalse(manager.session)
                self.assertEqual(stream.phase, "receiving")
                self.assertEqual(stream.abort_mutations, 0)
                if stream.generation == 12:
                    self.assertNotEqual(stream.generation, 13)
                self.assertEqual(sum(command.startswith("ota abort ") for command in stream.cli), 1)
                self.assertNotIn("ota abort", stream.cli)

    def test_guarded_abort_exact_bounded_syntax_and_no_plain_fallback(self):
        maximum = management.abort_command(0xFFFFFFFF, 0xFFFFFFFF, "F" * 64)
        self.assertEqual(maximum, b"ota abort 4294967295 4294967295 " + b"f" * 64)
        self.assertEqual(len(maximum), 96)
        self.assertEqual(len(maximum) + 13, 109)
        self.assertLess(len(maximum), 160)
        self.assertTrue(management.valid_abort_command(maximum))
        self.assertTrue(management.valid_abort_command(management.abort_command(1, 0, "f" * 64)))
        for generation, counter in ((0, 5), (-1, 5), (True, 5), (1, True), (1, -1),
                                    (0x100000000, 5), (1, 0x100000000)):
            with self.assertRaises(ota.Error):
                management.abort_command(generation, counter, "f" * 64)
        _, stream, manager = setup()
        manager.login()
        prefix = b"\x02\x01\x00" + bytes(4) + TARGET[:6]
        malformed = (b"ota abort", b"ota abort 1 5", b"ota abort 01 5 " + b"f" * 64,
                     b"ota abort 1 05 " + b"f" * 64, b"ota abort +1 5 " + b"f" * 64,
                     b"ota abort 1 -5 " + b"f" * 64, b"ota abort 0 5 " + b"f" * 64,
                     b"ota abort 4294967296 5 " + b"f" * 64, maximum + b" ",
                     maximum + b"\n", b"ota abort 1 5 " + b"F" * 64,
                     b"ota abort 1 5 " + b"f" * 63, b"ota abort 1 5 " + b"0" * 64,
                     b"ota abort  1 5 " + b"f" * 64)
        before = len(stream.commands)
        for text in malformed:
            self.assertFalse(management.valid_abort_command(text))
            with self.assertRaises(ota.Error):
                manager._command(prefix + text, (6,), manager.stock.clock() + 3)
        with self.assertRaises(ota.Error):
            manager.query("abort")
        self.assertEqual(len(stream.commands), before)
        self.assertFalse(manager.abort_dispatched)

    def test_settings_zero_tiny_rounded_zero_and_endpoints_match_receiver_format(self):
        for duty, rendered in ((0, "0.0%"), (0.001, "0.0%"), (0.049, "0.0%"),
                               (0.1, "0.1%"), (100, "100.0%")):
            with self.subTest(duty=duty):
                _, stream, manager = setup()
                stream.duty = duty
                manager.login()
                reply = manager.query("settings")["reply"]
                self.assertEqual(reply, {"mode": "fleet", "duty": rendered})
                self.assertTrue(manager.session)
        for value in ("-0.1%", "100.1%", "nan%", "inf%"):
            with self.assertRaises(ota.Error):
                management.fields("settings", f"mode=fleet duty={value}")


class ManagementCliTests(Scratch):
    def invoke(self, operation, *, cancel=False, durable=False):
        clock, stream, real_manager = setup()
        stream.durable_abort = durable
        if cancel:
            stream.cancel_cmd = 2
        artifacts = self.directory / operation
        args = [operation, "--serial", "synthetic", "--by-id", "/dev/serial/by-id/synthetic",
                "--sender-key", OWNER.hex(), "--target", TARGET.hex(), "--target-name", NAME,
                "--binding", str(self.directory / "binding.json"), "--artifacts", str(artifacts)]
        if operation == "abort":
            args.extend(["--expect-generation", "10", "--expect-counter", "5",
                         "--expect-image", stream.candidate.digest.hex()])
        closures = []
        @contextmanager
        def uart(bound, path, **options):
            self.assertEqual(bound.sender, OWNER)
            self.assertEqual(path, "/dev/serial/by-id/synthetic")
            try:
                yield stream
            finally:
                closures.append("closed")
        original_stock, original_frames = ota.Stock, ota.Frames
        stock_factory = lambda frames, key, **kw: original_stock(frames, key, clock, clock.sleep, **kw)
        frames_factory = lambda port, **kw: original_frames(port, clock, **kw)
        manager_factory = lambda *unused, **kw: real_manager
        output = io.StringIO()
        with patch.object(ota.Binding, "load", return_value=binding()), \
                patch.object(ota, "validated_stock_uart", uart), \
                patch.object(ota, "Stock", stock_factory), patch.object(ota, "Frames", frames_factory), \
                patch.object(management, "RemoteManagement", manager_factory), redirect_stdout(output):
            error = None
            try:
                management.main(args)
            except ota.Error as exc:
                error = exc
        self.assertEqual(closures, ["closed"])
        self.assertNotIn("PRIVATE", output.getvalue())
        self.assertTrue((artifacts / "radio-unchanged.json").exists())
        return ota.private_read(artifacts / "result.json"), error

    def test_cli_queries_and_explicit_abort_result_persist_uart_closes(self):
        result, error = self.invoke("progress")
        self.assertIsNone(error)
        self.assertEqual(result["reply"]["phase"], "receiving")
        result, error = self.invoke("abort", durable=True)
        self.assertIsNone(error)
        self.assertTrue(result["reply"]["durable_abort_confirmed"])

    def test_cli_legacy_abort_exits_error_and_cancel_is_not_receiver_abort(self):
        result, error = self.invoke("abort")
        self.assertIsInstance(error, ota.Error)
        self.assertFalse(result["reply"]["durable_abort_confirmed"])
        result, error = self.invoke("progress", cancel=True)
        self.assertIsInstance(error, ota.Cancelled)
        self.assertEqual(result["outcome"], "host-cancelled")
        self.assertFalse(result["abort_dispatched"])
        self.assertFalse(result["receiver_abort_confirmed"])


class PartialTests(Scratch):
    def test_partial_pair_only_common_prefix_persists_both_contexts_and_checkpoints(self):
        clock, stream, stock, campaign = fleet_setup(candidate(84 * 40), duty=0.8)
        stock_async_noise(stream)
        result = lifecycle.partial(stock, [t.binding for t in campaign.targets], campaign.transport.candidate,
                                   self.directory, blocks=16, duty=0.8, clock=clock)
        self.assertTrue(result["operation_complete"])
        self.assertFalse(result["commit_sent"])
        self.assertFalse(result["receiver_abort_sent"])
        self.assertFalse(result["transfer_complete"])
        self.assertEqual(result["initial_block_transmissions"], 16)
        self.assertEqual(result["repair_block_transmissions"], 0)
        self.assertEqual([index for _, index, _ in stream.deliveries], list(range(16)))
        for key, node in stream.nodes.items():
            self.assertEqual(node["received"], set(range(16)))
            self.assertEqual(node["commits"], 0)
            attempt = ota.private_read(self.directory / ("attempt-" + key.hex() + ".json"))
            checkpoint = ota.private_read(self.directory / ("checkpoint-" + key.hex() + ".json"))
            self.assertEqual(attempt["schema"], 3)
            self.assertEqual(checkpoint["received_blocks"], 16)
        self.assertTrue((self.directory / "radio-unchanged.json").exists())
        self.assertEqual(ota.private_read(self.directory / "result.json")["outcome"], "shared-partial-observed-unsigned")

    def test_invalid_bound_or_pair_refuses_no_usb_signing_or_rf(self):
        for blocks in (0, 33, True, 40):
            _, stream, _, campaign = fleet_setup(candidate(84 * 40))
            with self.assertRaises(ota.Error):
                campaign.upload_partial(blocks)
            self.assertFalse(stream.commands)
        _, stream, _, campaign = fleet_setup()
        with self.assertRaises(ota.Error):
            ota.BackgroundCampaign.validate_bindings([campaign.targets[0].binding], candidate())
        self.assertFalse(stream.commands)

    def test_partial_cancel_stops_pair_no_automatic_receiver_abort_or_commit(self):
        clock, stream, stock, campaign = fleet_setup(candidate(84 * 40), duty=0.8)
        original = ota.BackgroundCampaign.send_block
        def interrupted(self, index, **options):
            if index == 4:
                raise ota.Cancelled("synthetic prefix cancelled")
            return original(self, index, **options)
        with patch.object(ota.BackgroundCampaign, "send_block", interrupted), self.assertRaises(ota.Cancelled):
            lifecycle.partial(stock, [t.binding for t in campaign.targets], campaign.transport.candidate,
                              self.directory, 16, duty=0.8, clock=clock)
        result = ota.private_read(self.directory / "result.json")
        self.assertEqual(result["outcome"], "shared-partial-cancelled")
        self.assertFalse(result["operation_complete"])
        self.assertFalse(result["receiver_abort_sent"])
        self.assertEqual(len(stream.deliveries), 4)
        self.assertTrue(all(node["commits"] == 0 for node in stream.nodes.values()))

    def test_restart_receipts_require_same_image_pair_new_generation_and_nonce(self):
        clock, stream, stock, campaign = restart_setup()
        lifecycle.partial(stock, [t.binding for t in campaign.targets], campaign.transport.candidate,
                          self.directory, blocks=4, duty=0.8, clock=clock)
        receipts = [ota.private_read(self.directory / ("attempt-" + t.binding.target.hex() + ".json"))
                    for t in campaign.targets]
        bindings = [replace(t.binding, min_generation=old["generation"] + 2, allow_reupload=True)
                    for t, old in zip(campaign.targets, receipts)]
        lifecycle.check_restart(bindings, campaign.transport.candidate, receipts)
        for changed in (receipts[:1], list(reversed(receipts)),
                        [dict(receipts[0], counter=6), receipts[1]]):
            with self.assertRaises(ota.Error):
                lifecycle.check_restart(bindings, campaign.transport.candidate, changed)
        for t, old in zip(campaign.targets, receipts):
            node = stream.nodes[t.binding.target]
            node["received"].clear()
            node["generation"] = old["generation"] + 1
            node["aborted"] = True
        next_dir = self.directory / "restart"
        next_dir.mkdir(mode=0o700)
        result = lifecycle.partial(stock, bindings, campaign.transport.candidate, next_dir,
                                   4, duty=0.8, restart_receipts=receipts, clock=clock)
        self.assertTrue(result["restart_selected"])
        self.assertEqual(stream.reuploads, [TARGET, TARGET2])
        new_receipts = [ota.private_read(next_dir / ("attempt-" + b.target.hex() + ".json")) for b in bindings]
        for old, new in zip(receipts, new_receipts):
            self.assertEqual(new["generation"], old["generation"] + 2)
            self.assertNotEqual(new["begin_nonce"], old["begin_nonce"])
        with self.assertRaises(ota.Error):
            ota.BackgroundCampaign.validate_resume_receipts(bindings, campaign.transport.candidate, receipts, 0.8)

    def test_permission_denial_persists_incomplete_no_data_no_fallback(self):
        clock, stream, stock, campaign = fleet_setup(candidate(84 * 40), duty=0.8)
        stream.nodes[TARGET2]["permission"] = False
        result = lifecycle.partial(stock, [t.binding for t in campaign.targets], campaign.transport.candidate,
                                   self.directory, blocks=16, duty=0.8, clock=clock)
        self.assertFalse(result["operation_complete"])
        self.assertEqual(result["initial_block_transmissions"], 0)
        self.assertFalse(stream.deliveries)
        self.assertFalse(result["receiver_abort_sent"])
        self.assertEqual(ota.private_read(self.directory / "result.json")["outcome"], "shared-campaign-incomplete")

    def test_restart_unchanged_nonce_fails_before_any_common_data(self):
        clock, stream, stock, campaign = restart_setup()
        lifecycle.partial(stock, [t.binding for t in campaign.targets], campaign.transport.candidate,
                          self.directory, blocks=4, duty=0.8, clock=clock)
        receipts = [ota.private_read(self.directory / ("attempt-" + t.binding.target.hex() + ".json"))
                    for t in campaign.targets]
        bindings = [replace(t.binding, min_generation=old["generation"] + 2, allow_reupload=True)
                    for t, old in zip(campaign.targets, receipts)]
        for key, node in stream.nodes.items():
            node["received"].clear()
            node["generation"] += 1
            node["aborted"] = True
        stream.same_nonce = True
        next_dir = self.directory / "restart"
        next_dir.mkdir(mode=0o700)
        before = len(stream.deliveries)
        result = lifecycle.partial(stock, bindings, campaign.transport.candidate, next_dir,
                                   4, duty=0.8, restart_receipts=receipts, clock=clock)
        self.assertFalse(result["operation_complete"])
        self.assertEqual(len(stream.deliveries), before)

    def test_old_ready_commit_receipt_rejected_after_new_attempt_before_signing(self):
        clock, stream, stock, original = fleet_setup(candidate(84 * 40), duty=0.8)
        ready = original.upload()
        self.assertTrue(ready["operation_complete"])
        bindings = [replace(t.binding, min_generation=t.generation + 1) for t in original.targets]
        fresh = ota.BackgroundCampaign(stock, bindings, original.transport.candidate, NORMAL,
                                       clock() + 10000, 0.8, clock, clock.sleep)
        before = len(stream.commands)
        with self.assertRaises(ota.Error):
            fresh.commit(ready)
        self.assertEqual(len(stream.commands), before)
        self.assertTrue(all(node["commits"] == 0 for node in stream.nodes.values()))

    def test_restart_explicit_binding_and_both_aborted_preflight_before_any_reupload(self):
        clock, stream, stock, campaign = restart_setup()
        lifecycle.partial(stock, [t.binding for t in campaign.targets], campaign.transport.candidate,
                          self.directory, blocks=4, duty=0.8, clock=clock)
        receipts = [ota.private_read(self.directory / ("attempt-" + t.binding.target.hex() + ".json"))
                    for t in campaign.targets]
        bindings = [replace(t.binding, min_generation=old["generation"] + 2, allow_reupload=True)
                    for t, old in zip(campaign.targets, receipts)]
        for incorrect in (replace(bindings[0], allow_reupload=False),
                          replace(bindings[0], min_generation=receipts[0]["generation"] + 1),
                          replace(bindings[0], reupload_generation=receipts[0]["generation"])):
            with self.assertRaises(ota.Error):
                lifecycle.check_restart([incorrect, bindings[1]], campaign.transport.candidate, receipts)
        for key, node in stream.nodes.items():
            node["aborted"] = True
            node["generation"] += 1
        stream.nodes[TARGET2]["generation"] += 1
        next_dir = self.directory / "restart"
        next_dir.mkdir(mode=0o700)
        before = len(stream.deliveries)
        result = lifecycle.partial(stock, bindings, campaign.transport.candidate, next_dir,
                                   4, duty=0.8, restart_receipts=receipts, clock=clock)
        self.assertFalse(result["operation_complete"])
        self.assertFalse(stream.reuploads)
        self.assertEqual(len(stream.deliveries), before)
        self.assertTrue(all(node["aborted"] for node in stream.nodes.values()))

    def test_plain_old_begin_and_old_blocks_cannot_reopen_aborted_but_content_is_not_attempt_bound(self):
        clock, stream, stock, campaign = restart_setup()
        campaign.upload_partial(4)
        old_begin = next(raw[2:] for raw in stream.raw_packets if ota.retry_payload(raw[2:])[1][0] == 8)
        for node in stream.nodes.values():
            node["aborted"] = True
            node["received"].clear()
            node["generation"] += 1
        old_attempt, old_inner = ota.retry_payload(old_begin)
        stream.remote(ota.retry_frame(old_inner, old_attempt + 100000))
        self.assertTrue(all(node["aborted"] for node in stream.nodes.values()))
        block = next(raw[2:] for raw in stream.raw_packets if ota.retry_payload(raw[2:])[1][0] == 1)
        attempt, inner = ota.retry_payload(block)
        stream.remote(ota.retry_frame(inner, attempt + 100000))
        self.assertTrue(all(not node["received"] for node in stream.nodes.values()))
        self.assertFalse(stream.reuploads)


if __name__ == "__main__":
    unittest.main()
