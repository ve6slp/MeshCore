import contextlib
import io
import pathlib
import struct
import sys
import unittest
from unittest import mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import ota_rf_lab


CLIENT_KEY = bytes(range(32))
TARGET_KEY = bytes(reversed(range(32)))


def self_info(name="OTA-LAB-CLIENT", public_key=CLIENT_KEY, advert_type=1,
              radio=(907525, 62500, 7, 5)):
    frame = bytearray(58)
    frame[0] = 5
    frame[1] = advert_type
    frame[4:36] = public_key
    struct.pack_into("<II", frame, 48, *radio[:2])
    frame[56:58] = bytes(radio[2:])
    return bytes(frame) + name.encode("utf-8")


def device_info(mode=2, version=13):
    frame = bytearray(82)
    frame[0:2] = bytes([13, version])
    frame[81] = mode
    return bytes(frame)


def evidence_fixture():
    evidence = ota_rf_lab.Evidence.__new__(ota_rf_lab.Evidence)
    evidence.summary = {"measurements": {}, "checks": {}}
    evidence.log = mock.Mock()
    return evidence


def repeater_fixture(overrides=None):
    replies = {
        "get role": ["> repeater", "> repeater"],
        "get public.key": ["> " + TARGET_KEY.hex().upper(), "> " + TARGET_KEY.hex()],
        "get name": ["> existing-target", "> OTA-LAB-TARGET"],
        "get radio": ["> 869.525,250,11,5", "> 907.525,62.5,7,5"],
        "get path.hash.mode": ["> 0", "> 2"],
        "set name OTA-LAB-TARGET": ["OK"],
        "set radio 907.525,62.5,7,5": ["OK - reboot to apply"],
        "set path.hash.mode 2": ["OK"],
    }
    replies.update(overrides or {})
    node = mock.Mock()
    node.name = "target"

    def command(text):
        if text not in replies or not replies[text]:
            raise AssertionError(f"unexpected repeater command: {text}")
        return replies[text].pop(0)

    node.command.side_effect = command
    acl = {CLIENT_KEY.hex(): 1, "ab" * 32: 0x83, "cd" * 32: 2}
    node.get_acl.side_effect = [acl.copy(), acl.copy()]
    return node


class RepeaterSerialTests(unittest.TestCase):
    def setUp(self):
        self.node = ota_rf_lab.RepeaterSerial.__new__(ota_rf_lab.RepeaterSerial)
        self.node.name = "target"
        self.node.buffer = bytearray()
        self.node.pending = []
        self.node.evidence = mock.Mock()

    def test_split_echo_and_reply_preserve_complete_lines(self):
        self.node.buffer.extend(b"get public.")
        self.assertEqual(self.node._extract_lines(), [])
        self.node.buffer.extend(b"key\r\n  -> > 0123\r")
        self.assertEqual(self.node._extract_lines(), ["get public.key"])
        self.node.buffer.extend(b"\n")
        self.assertEqual(self.node._extract_lines(), ["  -> > 0123"])
        self.assertEqual(self.node.buffer, b"")

    def test_packet_logs_and_blank_lines_are_not_binary_frames(self):
        self.node.buffer.extend(b"\r\n12:00:00 RAW: 010203\r\n  -> > repeater\r\n")
        self.assertEqual(self.node._extract_lines(),
                         ["", "12:00:00 RAW: 010203", "  -> > repeater"])

    def test_unterminated_or_complete_oversized_lines_are_rejected(self):
        for suffix in (b"", b"\n"):
            with self.subTest(suffix=suffix):
                self.node.buffer = bytearray(b"x" * (self.node.MAX_LINE_BYTES + 1) + suffix)
                with self.assertRaisesRegex(ValueError, "oversized"):
                    self.node._extract_lines()

    def test_exact_line_limit_is_accepted(self):
        self.node.buffer.extend(b"x" * self.node.MAX_LINE_BYTES)
        self.assertEqual(self.node._extract_lines(), [])
        self.node.buffer.extend(b"\n")
        self.assertEqual(self.node._extract_lines(), ["x" * self.node.MAX_LINE_BYTES])

    def test_malformed_utf8_is_not_accepted_as_a_reply(self):
        self.node.buffer.extend(b"  -> \xff\r\n")
        with self.assertRaises(UnicodeDecodeError):
            self.node._extract_lines()

    def test_reply_requires_the_current_command_echo(self):
        batches = iter([
            ["get role", "  -> > stale"],
            ["  -> > unrelated", "radio log"],
            ["get role", "radio log", "  -> > repeater"],
        ])

        def poll(timeout=0):
            self.node.pending.extend(next(batches, []))

        self.node.poll = mock.Mock(side_effect=poll)
        self.node._write_bytes = mock.Mock()
        self.assertEqual(self.node.command("get role"), "> repeater")
        self.node._write_bytes.assert_called_once_with(b"get role\r")

    def test_missing_echo_times_out_instead_of_accepting_a_stale_reply(self):
        self.node.poll = mock.Mock(side_effect=lambda timeout=0: self.node.pending.append("  -> OK"))
        self.node._write_bytes = mock.Mock()
        with mock.patch.object(ota_rf_lab.time, "monotonic", side_effect=[0, 0, 0, 1]):
            with self.assertRaisesRegex(TimeoutError, "no repeater CLI reply"):
                self.node.command("get role", timeout=0.5)

    def test_error_reply_is_preserved_for_the_caller(self):
        batches = iter([[], ["setperm key 3", "  -> Err - bad pubkey"]])
        self.node.poll = mock.Mock(
            side_effect=lambda timeout=0: self.node.pending.extend(next(batches, [])))
        self.node._write_bytes = mock.Mock()
        self.assertEqual(self.node.command("setperm key 3"), "Err - bad pubkey")

    def test_invalid_commands_are_rejected_before_serial_io(self):
        self.node.poll = mock.Mock()
        self.node._write_bytes = mock.Mock()
        for command in ("", "get role\nreboot", "get role\rreboot", "\x00",
                        "x" * (self.node.MAX_COMMAND_BYTES + 1), "\x7f", "get r\u00f4le"):
            with self.subTest(command=repr(command)):
                with self.assertRaises(ValueError):
                    self.node.command(command)
        self.node.poll.assert_not_called()
        self.node._write_bytes.assert_not_called()

    def acl_fixture(self, batches, timeout=5.0):
        clock = mock.Mock()
        clock.now = 0.0
        clock.monotonic.side_effect = lambda: clock.now
        batches = iter(batches)

        def poll(duration=0):
            clock.now += max(duration, 0.01)
            self.node.pending.extend(next(batches, []))

        self.node.poll = mock.Mock(side_effect=poll)
        self.node._write_bytes = mock.Mock()
        with mock.patch.object(ota_rf_lab, "time", clock):
            return self.node.get_acl(timeout=timeout)

    def test_acl_is_delimited_by_a_fresh_following_command_not_idle_time(self):
        first = "01" * 32
        second = "AB" * 32
        entries = self.acl_fixture([
            ["get acl", "ACL:", f"03 {'ff' * 32}"],
            ["ACL:", f"03 {'ee' * 32}"],
            ["get acl", "ACL:", f"03 {first}"],
            [],
            ["12:00:00 RAW: 010203", f"82 {second}"],
            ["get role"],
            ["  -> > repeater"],
        ])
        self.assertEqual(entries, {first: 3, second.lower(): 0x82})
        self.assertEqual(self.node._write_bytes.call_args_list,
                         [mock.call(b"get acl\r"), mock.call(b"get role\r")])

    def test_empty_acl_requires_the_barrier_reply(self):
        self.assertEqual(self.acl_fixture([
            [], ["get acl", "ACL:"], ["get role", "  -> > repeater"],
        ]), {})

    def test_incomplete_acl_is_not_accepted_as_a_partial_list(self):
        for last in ([], ["get role"]):
            with self.subTest(last=last):
                self.node.pending.clear()
                with self.assertRaisesRegex(TimeoutError, "incomplete"):
                    self.acl_fixture([[], ["get acl", "ACL:", f"03 {'01' * 32}"], last],
                                     timeout=0.5)

    def test_acl_without_current_echo_is_not_accepted(self):
        with self.assertRaisesRegex(TimeoutError, "incomplete"):
            self.acl_fixture([[], ["ACL:", "get role", "  -> > repeater"]], timeout=0.5)
        self.node._write_bytes.assert_called_once_with(b"get acl\r")

    def test_invalid_or_duplicate_acl_rows_fail_explicitly(self):
        for rows in ([f"03 {'a' * 63}"], [f"03 {'g' * 64}"], ["03"],
                     [f"03 {'ab' * 32}", f"01 {'AB' * 32}"], ["ACL:"],
                     [f"3 {'ab' * 32}"], [f"ZZ {'ab' * 32}"], [f"03 {'00' * 32}"],
                     ["garbage"], [f"03  {'ab' * 32}"]):
            with self.subTest(rows=rows):
                self.node.pending.clear()
                with self.assertRaises(ValueError):
                    self.acl_fixture([[], ["get acl", "ACL:", *rows]])

    def test_acl_or_barrier_errors_are_not_success_shaped(self):
        for batches in ([[], ["get acl", "  -> Err - unsupported"]],
                        [[], ["get acl", "ACL:"], ["  -> > repeater"]],
                        [[], ["get acl", "ACL:"], ["get role", "  -> Err - unavailable"]],
                        [[], ["get acl", "ACL:"], ["get role", "  -> > companion"]]):
            with self.subTest(batches=batches):
                self.node.pending.clear()
                with self.assertRaisesRegex(RuntimeError, "unexpected ACL reply"):
                    self.acl_fixture(batches)

    def test_acl_collects_all_entries_without_a_neighbors_style_eight_row_limit(self):
        keys = [f"{index:064x}" for index in range(1, 41)]
        rows = [f"03 {key}" for key in keys]
        entries = self.acl_fixture([
            [], ["get acl", "ACL:", *rows[:10]], [], rows[10:25], [],
            rows[25:], ["get role", "  -> > repeater"],
        ])
        self.assertEqual(entries, dict.fromkeys(keys, 3))

    def test_acl_rows_after_the_barrier_echo_are_not_silently_dropped(self):
        with self.assertRaisesRegex(ValueError, "malformed ACL row"):
            self.acl_fixture([
                [], ["get acl", "ACL:"], ["get role", f"03 {'ab' * 32}",
                                         "  -> > repeater"],
            ])

    def test_acl_timeout_is_shared_with_the_barrier_not_restarted(self):
        with self.assertRaisesRegex(TimeoutError, "incomplete"):
            self.acl_fixture([
                [], [], [], ["get acl", "ACL:"], [], [], ["get role", "  -> > repeater"],
            ], timeout=0.4)
        self.assertEqual(self.node._write_bytes.call_args_list,
                         [mock.call(b"get acl\r"), mock.call(b"get role\r")])


class SerialTransportTests(unittest.TestCase):
    def setUp(self):
        self.node = ota_rf_lab.FramedSerial.__new__(ota_rf_lab.FramedSerial)
        self.node.name = "client"
        self.node.fd = 10
        self.node.evidence = mock.Mock()
        self.node.buffer = bytearray()
        self.node.pending = []

    def test_partial_writes_preserve_the_complete_companion_frame(self):
        with mock.patch.object(ota_rf_lab.select, "select", return_value=([], [10], [])), \
                mock.patch.object(ota_rf_lab.os, "write", side_effect=[2, 3]) as write:
            self.node.write_frame(b"\x16\x0d")
        self.assertEqual(write.call_args_list,
                         [mock.call(10, b"<\x02\x00\x16\x0d"), mock.call(10, b"\x00\x16\x0d")])

    def test_zero_length_write_fails_without_an_infinite_retry(self):
        with mock.patch.object(ota_rf_lab.select, "select", return_value=([], [10], [])), \
                mock.patch.object(ota_rf_lab.os, "write", return_value=0) as write:
            with self.assertRaisesRegex(ConnectionError, "no progress"):
                self.node.write_frame(b"\x16\x0d")
        write.assert_called_once()

    def test_serial_frame_limit_is_enforced_before_writing(self):
        with mock.patch.object(self.node, "_write_bytes") as write:
            self.node.write_frame(bytes(ota_rf_lab.MAX_SERIAL_FRAME_SIZE))
            self.assertEqual(len(write.call_args.args[0]), ota_rf_lab.MAX_SERIAL_FRAME_SIZE + 3)
            write.reset_mock()
            with self.assertRaisesRegex(ValueError, "too large"):
                self.node.write_frame(bytes(ota_rf_lab.MAX_SERIAL_FRAME_SIZE + 1))
            write.assert_not_called()

    def test_disconnected_port_fails_instead_of_appearing_idle(self):
        with mock.patch.object(ota_rf_lab.select, "select", return_value=([10], [], [])), \
                mock.patch.object(ota_rf_lab.os, "read", return_value=b""):
            with self.assertRaisesRegex(ConnectionError, "disconnected"):
                self.node.poll()

    def test_idle_port_does_not_attempt_a_read(self):
        with mock.patch.object(ota_rf_lab.select, "select", return_value=([], [], [])), \
                mock.patch.object(ota_rf_lab.os, "read") as read:
            self.node.poll()
        read.assert_not_called()
        self.assertEqual(self.node.pending, [])

    def test_split_frames_and_interleaved_frames_preserve_binary_payloads(self):
        self.node.buffer.extend(b"startup text>\x03")
        self.assertEqual(self.node._extract(), [])
        self.node.buffer.extend(b"\x00\x05\x00\xff>\x01\x00\x00")
        self.assertEqual(self.node._extract(), [b"\x05\x00\xff", b"\x00"])
        self.assertEqual(self.node.buffer, b"")

    def test_wait_frame_preserves_unrelated_notifications(self):
        self.node.pending = [(0.0, b"\x80advert"), (0.0, b"\x00")]
        self.node.poll = mock.Mock()
        self.assertEqual(self.node.wait_frame({0}), b"\x00")
        self.assertEqual(self.node.pending, [(0.0, b"\x80advert")])

    def test_write_timeout_is_explicit(self):
        with mock.patch.object(ota_rf_lab.select, "select", return_value=([], [], [])), \
                mock.patch.object(ota_rf_lab.os, "write") as write:
            with self.assertRaisesRegex(TimeoutError, "serial write timeout"):
                self.node.write_frame(b"\x01")
        write.assert_not_called()

    def test_unstable_port_paths_are_refused_before_open(self):
        with mock.patch.object(ota_rf_lab.os, "open") as open_port:
            with self.assertRaisesRegex(RuntimeError, "unstable device path"):
                ota_rf_lab.LabSerial("client", "/dev/ttyACM0", mock.Mock())
        open_port.assert_not_called()


class LabRoleTransportTests(unittest.TestCase):
    def test_qualification_or_obsolete_scopes_fail_before_any_physical_access(self):
        for options, message in (
            ([], "qualification is not supported"),
            (["--client-only"], "qualification is not supported"),
            (["--monitor-seconds=0"], "qualification is not supported"),
            (["--staging-only"], "unrecognized arguments"),
            (["--airtime-only"], "unrecognized arguments"),
            (["--duty-timeout=1"], "unrecognized arguments"),
            (["--configure-only", "--airtime-only"], "unrecognized arguments"),
            (["--configure-only", "--monitor-seconds=1"], "not allowed"),
            (["--grant-client-admin", "--configure-only"], "not allowed"),
            (["--grant-client-admin", "--monitor-seconds=1"], "not allowed"),
            (["--grant-client-admin", "--monitor-seconds=0"], "not allowed"),
            (["--grant-client-admin", "--client-only"], "requires both approved roles"),
            (["--grant-client"], "unrecognized arguments"),
            (["--configure"], "unrecognized arguments"),
        ):
            with self.subTest(options=options):
                arguments = ["ota_rf_lab.py", "--artifact-dir", "unused", *options]
                with mock.patch.object(sys, "argv", arguments), \
                        mock.patch.object(ota_rf_lab, "Evidence") as evidence, \
                        mock.patch.object(ota_rf_lab, "resolve_roles") as resolve, \
                        mock.patch.object(ota_rf_lab, "FramedSerial") as client, \
                        mock.patch.object(ota_rf_lab, "RepeaterSerial") as target, \
                        mock.patch.object(ota_rf_lab.os, "open") as open_port, \
                        contextlib.redirect_stderr(io.StringIO()) as errors:
                    with self.assertRaises(SystemExit) as raised:
                        ota_rf_lab.main()
                    self.assertEqual(raised.exception.code, 2)
                    self.assertIn(message, errors.getvalue())
                    evidence.assert_not_called()
                    resolve.assert_not_called()
                    client.assert_not_called()
                    target.assert_not_called()
                    open_port.assert_not_called()

    def test_invalid_monitor_duration_cannot_bypass_paired_operation_guard(self):
        for duration in ("nan", "inf", "-inf", "-1"):
            with self.subTest(duration=duration):
                arguments = ["ota_rf_lab.py", "--artifact-dir", "unused",
                             f"--monitor-seconds={duration}"]
                with mock.patch.object(sys, "argv", arguments), \
                        mock.patch.object(ota_rf_lab, "resolve_roles") as resolve, \
                        contextlib.redirect_stderr(io.StringIO()) as errors:
                    with self.assertRaises(SystemExit) as raised:
                        ota_rf_lab.main()
                    self.assertEqual(raised.exception.code, 2)
                    self.assertIn("finite and non-negative", errors.getvalue())
                    resolve.assert_not_called()

    def run_main_fixture(self, options, client_frame=None, target_role="> repeater"):
        self.devices = {
            ota_rf_lab.CLIENT_ROLE: mock.Mock(serial="client-serial",
                                              by_id="/dev/serial/by-id/client"),
            ota_rf_lab.TARGET_ROLE: mock.Mock(serial="target-serial",
                                              by_id="/dev/serial/by-id/target"),
        }
        arguments = ["ota_rf_lab.py", "--artifact-dir", "unused", *options]
        with mock.patch.object(sys, "argv", arguments), \
                mock.patch.object(ota_rf_lab, "Evidence") as evidence, \
                mock.patch.object(ota_rf_lab, "resolve_roles", return_value=self.devices) as resolve, \
                mock.patch.object(ota_rf_lab, "FramedSerial") as client, \
                mock.patch.object(ota_rf_lab, "RepeaterSerial") as target, \
                mock.patch.object(ota_rf_lab, "run_configure") as configure, \
                mock.patch.object(ota_rf_lab, "run_configure_client") as configure_client, \
                mock.patch.object(ota_rf_lab.time, "sleep"), \
                mock.patch.object(ota_rf_lab.time, "monotonic", side_effect=[0, 0, 1]):
            self.evidence = evidence
            self.resolve = resolve
            self.client = client
            self.target = target
            self.configure = configure
            self.configure_client = configure_client
            client.return_value.command.return_value = self_info() if client_frame is None else client_frame
            target.return_value.command.side_effect = [target_role, "> " + TARGET_KEY.hex()]
            ota_rf_lab.main()
        return client, target

    def test_monitor_uses_binary_client_and_text_repeater_and_reads_actual_roles(self):
        client, target = self.run_main_fixture(["--monitor-seconds=0.2"])
        client.assert_called_once_with(f"{ota_rf_lab.CLIENT_ROLE}-client-serial",
                                       "/dev/serial/by-id/client", self.evidence.return_value)
        target.assert_called_once_with(f"{ota_rf_lab.TARGET_ROLE}-target-serial",
                                       "/dev/serial/by-id/target", self.evidence.return_value)
        self.assertEqual(client.return_value.command.call_args_list, [
            mock.call(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
        ])
        self.assertEqual(target.return_value.command.call_args_list,
                         [mock.call("get role"), mock.call("get public.key")])
        for node in (client, target):
            node.return_value.poll.assert_called_once_with(0.05)
            node.return_value.pending.clear.assert_called_once()
            node.return_value.close.assert_called_once()
        self.configure.assert_not_called()
        self.configure_client.assert_not_called()

    def test_client_monitor_never_opens_the_repeater(self):
        client, target = self.run_main_fixture(["--client-only", "--monitor-seconds=0.2"])
        self.resolve.assert_called_once_with(self.evidence.return_value, client_only=True)
        target.assert_not_called()
        client.return_value.command.assert_called_once()
        client.return_value.close.assert_called_once()

    def test_wrong_role_in_either_monitor_fails_and_closes_both_ports(self):
        for frame, role in ((self_info(advert_type=2), "> repeater"),
                            (self_info(), "> room")):
            with self.subTest(frame=frame[:2], role=role):
                with self.assertRaisesRegex(RuntimeError, "role"):
                    self.run_main_fixture(["--monitor-seconds=0.2"], frame, role)
                self.client.return_value.close.assert_called_once()
                self.target.return_value.close.assert_called_once()
                self.evidence.return_value.finish.assert_called_once()
                self.evidence.return_value.log.assert_called_once()
                self.client.return_value.poll.assert_not_called()
                self.target.return_value.poll.assert_not_called()

    def test_paired_configuration_dispatches_to_role_correct_helper(self):
        client, target = self.run_main_fixture(["--configure-only"])
        self.configure.assert_called_once_with(client.return_value, target.return_value,
                                                self.evidence.return_value)
        self.configure_client.assert_not_called()
        target.assert_called_once()
        self.evidence.return_value.finish.assert_called_once_with(None)

    def test_monitor_rejects_zero_or_malformed_identity_and_closes_the_ports(self):
        for frame in (b"", self_info()[:57], self_info(public_key=bytes(32))):
            with self.subTest(frame=frame[:4]):
                with self.assertRaises(RuntimeError):
                    self.run_main_fixture(["--monitor-seconds=0.2"], frame)
                self.client.return_value.close.assert_called_once()
                self.target.return_value.close.assert_called_once()
                self.client.return_value.poll.assert_not_called()
                self.target.return_value.poll.assert_not_called()

    def test_client_configuration_never_opens_the_repeater(self):
        client, target = self.run_main_fixture(["--client-only", "--configure-only"])
        target.assert_not_called()
        self.configure.assert_not_called()
        self.configure_client.assert_called_once_with(client.return_value, self.evidence.return_value)


class CompanionConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.node = mock.Mock()
        self.node.name = "client"
        self.replies = [self_info("existing-client"), device_info(0), b"\x00",
                        b"\x00", b"\x00", self_info(), device_info()]
        self.node.command.side_effect = self.replies
        self.evidence = evidence_fixture()

    def test_configuration_uses_exact_ordinary_wire_commands_and_readbacks(self):
        info = ota_rf_lab.run_configure_client(self.node, self.evidence)
        self.assertEqual(info["pubkey_bytes"], CLIENT_KEY)
        self.assertEqual(info["path_hash_mode"], 2)
        self.assertEqual(info["settings_readback_scope"], "companion_self_info_and_device_info")
        self.assertEqual(self.node.command.call_args_list, [
            mock.call(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
            mock.call(b"\x16\x0d", expected=(13,)),
            mock.call(b"\x08OTA-LAB-CLIENT"),
            mock.call(b"\x0b" +
                      struct.pack("<II", 907525, 62500) + bytes([7, 5, 0])),
            mock.call(b"\x3d\x00\x02"),
            mock.call(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
            mock.call(b"\x16\x0d", expected=(13,)),
        ])
        self.assertTrue(self.evidence.summary["checks"]["default-radio-client"]["passed"])
        self.assertTrue(self.evidence.summary["checks"]["path-hash-mode-client"]["passed"])
        self.assertFalse(self.evidence.summary["checks"]["default-radio-client"]["active_rf_verified"])
        self.assertFalse(self.evidence.log.call_args.kwargs["reboot_persistence_verified"])
        self.assertNotIn("pubkey_bytes", self.evidence.summary["measurements"]["configured"]["client"])

    def test_failed_configuration_command_stops_before_further_changes(self):
        for index in (2, 3, 4):
            for reply in (b"", b"\x01\x04", b"\x00\x00"):
                with self.subTest(index=index, reply=reply):
                    self.node.command.reset_mock()
                    replies = self.replies.copy()
                    replies[index] = reply
                    self.node.command.side_effect = replies
                    with self.assertRaisesRegex(RuntimeError, "command failed"):
                        ota_rf_lab.run_configure_client(self.node, self.evidence)
                    self.assertEqual(self.node.command.call_count, index + 1)
                    self.assertNotIn("configured", self.evidence.summary["measurements"])

    def test_every_setting_is_checked_not_just_an_ok_response(self):
        for info, mode, check in (
            (self_info(radio=(908525, 62500, 7, 5)), 2, "default-radio-client"),
            (self_info(radio=(907525, 125000, 7, 5)), 2, "default-radio-client"),
            (self_info(radio=(907525, 62500, 8, 5)), 2, "default-radio-client"),
            (self_info(radio=(907525, 62500, 7, 6)), 2, "default-radio-client"),
            (self_info("truncated"), 2, "configured-name-client"),
            (self_info(), 0, "path-hash-mode-client"),
        ):
            with self.subTest(check=check, mode=mode):
                self.evidence = evidence_fixture()
                self.node.command.side_effect = [*self.replies[:5], info, device_info(mode)]
                with self.assertRaisesRegex(AssertionError, check):
                    ota_rf_lab.run_configure_client(self.node, self.evidence)
                self.assertFalse(self.evidence.summary["checks"][check]["passed"])
                self.assertNotIn("configured", self.evidence.summary["measurements"])

    def test_short_self_info_readback_is_rejected(self):
        self.node.command.side_effect = [*self.replies[:5], self_info()[:57]]
        with self.assertRaisesRegex(RuntimeError, "short self-info"):
            ota_rf_lab.run_configure_client(self.node, self.evidence)
        self.assertNotIn("configured", self.evidence.summary["measurements"])

    def test_identity_change_is_rejected_without_any_identity_write_command(self):
        self.node.command.side_effect = [
            *self.replies[:5], self_info(public_key=TARGET_KEY), device_info(),
        ]
        with self.assertRaisesRegex(RuntimeError, "identity changed"):
            ota_rf_lab.run_configure_client(self.node, self.evidence)
        self.assertNotIn("configured", self.evidence.summary["measurements"])
        self.assertEqual([call.args[0][0] for call in self.node.command.call_args_list],
                         [1, 22, 8, 11, 61, 1, 22])

    def test_malformed_device_info_is_rejected_before_configuration(self):
        for frame in (b"", b"\x0d", device_info()[:81], device_info(version=9),
                      b"\x01" + device_info()[1:], device_info(3)):
            with self.subTest(frame=frame[:2]):
                self.node.command.reset_mock()
                self.node.command.side_effect = [self_info(), frame]
                with self.assertRaisesRegex(RuntimeError, "readback|path hash"):
                    ota_rf_lab.run_configure_client(self.node, self.evidence)
                self.assertEqual(self.node.command.call_count, 2)

    def test_malformed_device_info_readback_does_not_claim_configuration(self):
        self.node.command.side_effect = [*self.replies[:-1], device_info()[:81]]
        with self.assertRaisesRegex(RuntimeError, "readback"):
            ota_rf_lab.run_configure_client(self.node, self.evidence)
        self.assertNotIn("configured", self.evidence.summary["measurements"])

    def test_invalid_names_fail_before_any_serial_io(self):
        for name in ("", "x" * 32, "bad\rname", "bad\nname", "bad\x00name", "caf\u00e9"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    ota_rf_lab.configure_node(self.node, name)
        self.node.command.assert_not_called()


class CompanionIdentityTests(unittest.TestCase):
    def setUp(self):
        self.node = mock.Mock()
        self.node.name = "client"

    def test_app_info_reads_full_existing_identity_and_serializes_without_bytes(self):
        self.node.command.return_value = self_info("existing-client")
        info = ota_rf_lab.app_info(self.node)
        self.assertEqual(info["role"], "companion")
        self.assertEqual(info["advert_type"], 1)
        self.assertEqual(info["pubkey_bytes"], CLIENT_KEY)
        self.assertEqual(info["pubkey"], CLIENT_KEY.hex())
        self.assertEqual(info["name"], "existing-client")
        self.assertNotIn("pubkey_bytes", ota_rf_lab.serializable_app_info(info))
        self.assertEqual(len(ota_rf_lab.serializable_app_info(info)), len(info) - 1)

    def test_app_info_enforces_role_for_existing_uploader_callers(self):
        self.assertEqual(ota_rf_lab.ADV_TYPE_CHAT, 1)
        for advert_type in (0, 2, 3, 4, 255):
            with self.subTest(advert_type=advert_type):
                self.node.command.return_value = self_info(advert_type=advert_type)
                with self.assertRaisesRegex(RuntimeError, "role"):
                    ota_rf_lab.app_info(self.node)

    def test_shared_command_number_is_the_frozen_uploader_usb_abi(self):
        self.assertEqual(ota_rf_lab.CMD_OTA_CONTROL, 66)

    def test_wrong_role_or_zero_identity_fails_before_configuration(self):
        for frame in (self_info(advert_type=0), self_info(advert_type=2),
                      self_info(advert_type=3), self_info(advert_type=4),
                      self_info(public_key=bytes(32))):
            with self.subTest(frame=frame[:2]):
                self.node.command.reset_mock()
                self.node.command.return_value = frame
                with self.assertRaisesRegex(RuntimeError, "role|public key"):
                    ota_rf_lab.run_configure_client(self.node, evidence_fixture())
                self.node.command.assert_called_once()

    def test_short_wrong_code_and_malformed_names_are_rejected(self):
        for frame, error in ((b"", RuntimeError), (self_info()[:57], RuntimeError),
                             (b"\x01" + self_info()[1:], RuntimeError),
                             (self_info()[:58] + b"\xff", UnicodeDecodeError),
                             (self_info("bad\x00name"), ValueError)):
            with self.subTest(frame=frame[:2]):
                self.node.command.return_value = frame
                with self.assertRaises(error):
                    ota_rf_lab.app_info(self.node)


class RepeaterIdentityTests(unittest.TestCase):
    def test_role_and_full_key_use_only_documented_read_only_commands(self):
        node = repeater_fixture()
        self.assertEqual(ota_rf_lab.repeater_identity(node),
                         {"role": "repeater", "pubkey": TARGET_KEY.hex()})
        self.assertEqual(node.command.call_args_list,
                         [mock.call("get role"), mock.call("get public.key")])

    def test_wrong_or_malformed_roles_fail_before_reading_or_setting_anything_else(self):
        for reply in ("> companion", "> room", "> sensor", "> repeater extra",
                      "> REPEATER", "repeater", "OK", "", "Err - unsupported"):
            with self.subTest(reply=reply):
                node = repeater_fixture({"get role": [reply]})
                with self.assertRaisesRegex(RuntimeError, "role|reply"):
                    ota_rf_lab.configure_repeater(node)
                node.command.assert_called_once_with("get role")
                node.get_acl.assert_not_called()

    def test_keys_are_full_hex_nonzero_identities_not_prefixes_or_whitespace(self):
        for key in (TARGET_KEY.hex()[:16], "aa" * 31, "aa" * 33, "gg" * 32,
                    "00" * 32, " " + TARGET_KEY.hex(), TARGET_KEY.hex() + " "):
            with self.subTest(key=key):
                node = repeater_fixture({"get public.key": ["> " + key]})
                with self.assertRaisesRegex(RuntimeError, "public key"):
                    ota_rf_lab.configure_repeater(node)
                self.assertEqual(node.command.call_count, 2)

    def test_key_error_cannot_appear_as_an_identity(self):
        node = repeater_fixture({"get public.key": ["Err - unsupported"]})
        with self.assertRaisesRegex(RuntimeError, "invalid repeater reply"):
            ota_rf_lab.repeater_identity(node)

    def test_radio_units_are_parsed_exactly_and_path_mode_is_not_hash_byte_count(self):
        node = repeater_fixture({
            "get radio": ["> 907.525000,62.500000,7,5"],
            "get path.hash.mode": ["> 2"],
        })
        info = ota_rf_lab.repeater_info(node)
        self.assertEqual((info["freq_khz"], info["bw_hz"], info["sf"], info["cr"]),
                         (907525, 62500, 7, 5))
        self.assertEqual(info["path_hash_mode"], 2)
        self.assertEqual(info["settings_readback_scope"], "preferences")

    def test_real_float32_mhz_readback_normalizes_to_the_normal_khz_profile(self):
        node = repeater_fixture({"get radio": ["> 907.5250244,62.5,7,5"]})
        info = ota_rf_lab.repeater_info(node)
        self.assertEqual((info["freq_khz"], info["bw_hz"], info["sf"], info["cr"]),
                         ota_rf_lab.NORMAL_RADIO)
        self.assertTrue(all(call.args[0].startswith("get ")
                            for call in node.command.call_args_list))

    def test_float32_truncation_in_either_direction_and_frequency_boundaries(self):
        for mhz, khz in (("150.0", 150000), ("150.001007", 150001),
                         ("900.0009765", 900001), ("907.5260009", 907526),
                         ("2499.9990234", 2499999), ("2500.0", 2500000)):
            with self.subTest(mhz=mhz):
                node = repeater_fixture({"get radio": [f"> {mhz},62.5,7,5"]})
                self.assertEqual(ota_rf_lab.repeater_info(node)["freq_khz"], khz)

    def test_nearby_noncanonical_frequencies_are_not_hidden_by_rounding_or_tolerance(self):
        for mhz in ("149.9999847", "2500.0000001", "2500.0002441",
                    "907.5250001", "907.5250243", "907.5250245",
                    "907.5249633", "907.5251", "907.5255", "900.0009766"):
            with self.subTest(mhz=mhz):
                node = repeater_fixture({"get radio": [f"> {mhz},62.5,7,5"]})
                with self.assertRaisesRegex(ValueError, "frequency readback"):
                    ota_rf_lab.configure_repeater(node)
                self.assertTrue(all(call.args[0].startswith("get ")
                                    for call in node.command.call_args_list))

    def test_float32_frequency_normalization_preserves_bandwidth_sf_and_cr_boundaries(self):
        for bw, bw_hz, sf, cr in (("7.8", 7800, 5, 5), ("500", 500000, 12, 8)):
            with self.subTest(bw=bw, sf=sf, cr=cr):
                node = repeater_fixture({"get radio": [f"> 907.5250244,{bw},{sf},{cr}"]})
                info = ota_rf_lab.repeater_info(node)
                self.assertEqual((info["freq_khz"], info["bw_hz"], info["sf"], info["cr"]),
                                 (907525, bw_hz, sf, cr))
        for bw, sf, cr in (("7.799", 7, 5), ("500.001", 7, 5),
                           ("62.5000001", 7, 5), ("62.5", 4, 5), ("62.5", 13, 5),
                           ("62.5", 7, 4), ("62.5", 7, 9)):
            with self.subTest(bw=bw, sf=sf, cr=cr):
                node = repeater_fixture({"get radio": [f"> 907.5250244,{bw},{sf},{cr}"]})
                with self.assertRaises(ValueError):
                    ota_rf_lab.configure_repeater(node)
                self.assertTrue(all(call.args[0].startswith("get ")
                                    for call in node.command.call_args_list))

    def test_invalid_radio_and_path_readbacks_are_rejected_without_configuration(self):
        for command, reply in (
            ("get radio", "> 907.525,62.5,7"),
            ("get radio", "> 907.525,62.5,7,5,0"),
            ("get radio", "> nan,62.5,7,5"),
            ("get radio", "> NaN,62.5,7,5"),
            ("get radio", "> inf,62.5,7,5"),
            ("get radio", "> Infinity,62.5,7,5"),
            ("get radio", "> 907.5250244,nan,7,5"),
            ("get radio", "> 907.5250244,inf,7,5"),
            ("get radio", "> 9.07525e2,62.5,7,5"),
            ("get radio", "> \u0669\u0660\u0667.525,62.5,7,5"),
            ("get radio", "> 907.525,inf,7,5"),
            ("get radio", "> 907.5250001,62.5,7,5"),
            ("get radio", "> 907.525,62.5000001,7,5"),
            ("get radio", "> -907.525,62.5,7,5"),
            ("get radio", "> 0,62.5,7,5"),
            ("get radio", "> 907.525,0,7,5"),
            ("get radio", "> 907.525,62.5,13,5"),
            ("get radio", "> 907.525,62.5,7,4"),
            ("get path.hash.mode", "> 3"),
            ("get path.hash.mode", "> 02"),
            ("get path.hash.mode", "> 2 bytes"),
            ("get name", "> bad\x00name"),
        ):
            with self.subTest(command=command, reply=reply):
                node = repeater_fixture({command: [reply]})
                with self.assertRaises(ValueError):
                    ota_rf_lab.configure_repeater(node)
                self.assertTrue(all(call.args[0].startswith("get ") for call in node.command.call_args_list))


class PairedConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.client = mock.Mock()
        self.client.name = "client"
        self.client.command.side_effect = [
            self_info("existing-client"), device_info(0), b"\x00", b"\x00", b"\x00",
            self_info(), device_info(),
        ]
        self.target = repeater_fixture()
        self.evidence = evidence_fixture()

    def test_paired_configuration_preserves_identities_and_every_existing_acl_entry(self):
        client_info, target_info = ota_rf_lab.run_configure(self.client, self.target, self.evidence)
        self.assertEqual(client_info["pubkey_bytes"], CLIENT_KEY)
        self.assertEqual(target_info["pubkey"], TARGET_KEY.hex())
        self.assertEqual(self.target.command.call_args_list, [
            mock.call("get role"), mock.call("get public.key"), mock.call("get name"),
            mock.call("get radio"), mock.call("get path.hash.mode"),
            mock.call("set name OTA-LAB-TARGET"), mock.call("set radio 907.525,62.5,7,5"),
            mock.call("set path.hash.mode 2"),
            mock.call("get role"), mock.call("get public.key"), mock.call("get name"),
            mock.call("get radio"), mock.call("get path.hash.mode"),
        ])
        self.assertEqual(self.target.get_acl.call_count, 2)
        measurements = self.evidence.summary["measurements"]
        self.assertEqual(measurements["acl_before"], measurements["acl_after"])
        self.assertEqual(measurements["acl_after"][CLIENT_KEY.hex()], 1)
        self.assertEqual(len(measurements["acl_after"]), 3)
        self.assertTrue(self.evidence.summary["checks"]["repeater-acl-preserved"]["passed"])
        self.assertFalse(self.evidence.summary["checks"]["repeater-acl-preserved"]["admin_provisioned"])
        self.assertFalse(self.evidence.summary["checks"]["repeater-acl-preserved"]["reboot_persistence_verified"])
        self.assertEqual(set(measurements["configured"]), {"client", "target"})
        self.assertEqual(measurements["configured"]["target"]["settings_readback_scope"], "preferences")
        self.evidence.log.assert_called_with(
            "repeater_radio_application_pending", reboot_required=True,
            reboot_requested=False, active_rf_verified=False)

    def test_real_production_frequency_before_and_after_configuration_passes_full_readback(self):
        self.target = repeater_fixture({
            "get radio": ["> 907.5250244,62.5,7,5", "> 907.5250244,62.5,7,5"],
        })
        _, target_info = ota_rf_lab.run_configure(self.client, self.target, self.evidence)
        self.assertEqual(target_info["freq_khz"], 907525)
        measurements = self.evidence.summary["measurements"]
        self.assertEqual(measurements["configuration_before"]["target"]["freq_khz"], 907525)
        self.assertEqual(measurements["configured"]["target"]["freq_khz"], 907525)
        self.assertTrue(self.evidence.summary["checks"]["default-radio-target"]["passed"])
        self.assertEqual(measurements["acl_before"], measurements["acl_after"])
        self.assertIn(mock.call("set radio 907.525,62.5,7,5"), self.target.command.call_args_list)
        self.assertFalse(self.evidence.summary["checks"]["default-radio-target"]["active_rf_verified"])

    def test_both_roles_and_complete_acl_are_checked_before_any_setting_changes(self):
        timeline = mock.Mock()
        timeline.attach_mock(self.client.command, "client")
        timeline.attach_mock(self.target.command, "target")
        timeline.attach_mock(self.target.get_acl, "acl")
        ota_rf_lab.run_configure(self.client, self.target, self.evidence)
        calls = timeline.mock_calls
        first_change = next(index for index, call in enumerate(calls)
                            if (call[0] == "client" and call.args[0][0] in (8, 11, 61))
                            or (call[0] == "target" and call.args[0].startswith("set ")))
        self.assertEqual(calls[:first_change], [
            mock.call.client(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
            mock.call.client(b"\x16\x0d", expected=(13,)),
            mock.call.target("get role"), mock.call.target("get public.key"),
            mock.call.target("get name"), mock.call.target("get radio"),
            mock.call.target("get path.hash.mode"), mock.call.acl(),
        ])

    def test_wrong_target_role_does_not_change_either_device(self):
        self.target = repeater_fixture({"get role": ["> companion"]})
        with self.assertRaisesRegex(RuntimeError, "role"):
            ota_rf_lab.run_configure(self.client, self.target, self.evidence)
        self.assertEqual(self.client.command.call_count, 2)
        self.target.command.assert_called_once_with("get role")
        self.target.get_acl.assert_not_called()

    def test_wrong_client_role_does_not_query_or_change_the_target(self):
        self.client.command.side_effect = [self_info(advert_type=2)]
        with self.assertRaisesRegex(RuntimeError, "role"):
            ota_rf_lab.run_configure(self.client, self.target, self.evidence)
        self.client.command.assert_called_once()
        self.target.command.assert_not_called()
        self.target.get_acl.assert_not_called()

    def test_duplicate_identity_does_not_change_either_node(self):
        self.target = repeater_fixture({"get public.key": ["> " + CLIENT_KEY.hex()]})
        with self.assertRaisesRegex(AssertionError, "identities-are-distinct"):
            ota_rf_lab.run_configure(self.client, self.target, self.evidence)
        self.assertEqual(self.client.command.call_count, 2)
        self.target.get_acl.assert_not_called()

    def test_incomplete_initial_acl_stops_before_configuration(self):
        self.target.get_acl.side_effect = TimeoutError("incomplete ACL")
        with self.assertRaisesRegex(TimeoutError, "incomplete ACL"):
            ota_rf_lab.run_configure(self.client, self.target, self.evidence)
        self.assertEqual(self.client.command.call_count, 2)
        self.assertTrue(all(call.args[0].startswith("get ") for call in self.target.command.call_args_list))
        self.assertNotIn("configured", self.evidence.summary["measurements"])

    def test_failed_repeater_setters_stop_and_do_not_claim_target_success(self):
        for index, command in enumerate(("set name OTA-LAB-TARGET",
                                         "set radio 907.525,62.5,7,5", "set path.hash.mode 2")):
            invalid = ("Err - bad param", "", "OK extra", "> 2")
            invalid += ("OK",) if index == 1 else ("OK - reboot to apply",)
            for reply in invalid:
                with self.subTest(command=command, reply=reply):
                    self.setUp()
                    self.target = repeater_fixture({command: [reply]})
                    with self.assertRaisesRegex(RuntimeError, "repeater command failed"):
                        ota_rf_lab.run_configure(self.client, self.target, self.evidence)
                    self.assertEqual(self.target.command.call_count, 6 + index)
                    self.assertEqual(self.target.get_acl.call_count, 1)
                    self.assertNotIn("target", self.evidence.summary["measurements"].get("configured", {}))

    def test_target_setting_readback_mismatch_is_not_reported_as_success(self):
        for command, reply, check in (
            ("get name", "> old name", "configured-name-target"),
            ("get radio", "> 907.525,250,7,5", "default-radio-target"),
            ("get radio", "> 907.5260009,62.5,7,5", "default-radio-target"),
            ("get path.hash.mode", "> 1", "path-hash-mode-target"),
        ):
            with self.subTest(command=command, reply=reply):
                self.setUp()
                first = {"get name": "> existing-target", "get radio": "> 869.525,250,11,5",
                         "get path.hash.mode": "> 0"}[command]
                self.target = repeater_fixture({command: [first, reply]})
                with self.assertRaisesRegex(AssertionError, check):
                    ota_rf_lab.run_configure(self.client, self.target, self.evidence)
                self.assertNotIn("target", self.evidence.summary["measurements"]["configured"])

    def test_target_identity_change_is_an_error_not_a_new_identity_to_provision(self):
        self.target = repeater_fixture({
            "get public.key": ["> " + TARGET_KEY.hex(), "> " + "ab" * 32],
        })
        with self.assertRaisesRegex(RuntimeError, "identity changed"):
            ota_rf_lab.run_configure(self.client, self.target, self.evidence)
        self.assertEqual(self.target.get_acl.call_count, 1)
        self.assertNotIn("target", self.evidence.summary["measurements"]["configured"])

    def test_lost_or_changed_acl_is_rejected_and_never_replaced(self):
        for after in ({}, {CLIENT_KEY.hex(): 3}, {"ab" * 32: 0x82}):
            with self.subTest(after=after):
                self.setUp()
                self.target.get_acl.side_effect = [{CLIENT_KEY.hex(): 1}, after]
                with self.assertRaisesRegex(AssertionError, "repeater-acl-preserved"):
                    ota_rf_lab.run_configure(self.client, self.target, self.evidence)
                self.assertFalse(self.evidence.summary["checks"]["repeater-acl-preserved"]["passed"])
                self.assertFalse(any(call.args[0].startswith("setperm")
                                     for call in self.target.command.call_args_list))

    def test_missing_acl_readback_is_not_accepted_as_persisted_configuration(self):
        self.target.get_acl.side_effect = [{}, TimeoutError("incomplete ACL")]
        with self.assertRaisesRegex(TimeoutError, "incomplete ACL"):
            ota_rf_lab.run_configure(self.client, self.target, self.evidence)
        self.assertNotIn("target", self.evidence.summary["measurements"]["configured"])


class GrantClientAdminTests(unittest.TestCase):
    def setUp(self):
        self.client = mock.Mock()
        self.client.name = "client"
        self.client.command.side_effect = [
            self_info("existing-client"), device_info(0),
            self_info("existing-client"), device_info(0),
        ]
        self.command = f"setperm {CLIENT_KEY.hex()} 3"
        self.target = repeater_fixture({
            "get name": ["> existing-target", "> existing-target"],
            "get radio": ["> 869.525,250,11,5", "> 869.525,250,11,5"],
            "get path.hash.mode": ["> 0", "> 0"],
            self.command: ["OK"],
        })
        self.before = {CLIENT_KEY.hex(): 1, "ab" * 32: 0x83, "cd" * 32: 2}
        self.after = {**self.before, CLIENT_KEY.hex(): 3}
        self.target.get_acl.side_effect = [self.before.copy(), self.after.copy()]
        self.evidence = evidence_fixture()
        patcher = mock.patch.object(ota_rf_lab.time, "sleep")
        self.sleep = patcher.start()
        self.addCleanup(patcher.stop)

    def grant(self):
        return ota_rf_lab.run_grant_client_admin(self.client, self.target, self.evidence)

    def mutations(self):
        return [call.args[0] for call in self.target.command.call_args_list
                if not call.args[0].startswith("get ")]

    def wire_acl_reader(self, batches):
        def read():
            node = ota_rf_lab.RepeaterSerial.__new__(ota_rf_lab.RepeaterSerial)
            node.name = "target"
            node.pending = []
            node.evidence = mock.Mock()
            node._start_command = mock.Mock()
            node._write_bytes = mock.Mock()
            remaining = iter(batches)
            now = 0.0

            def poll(duration=0):
                nonlocal now
                now += max(duration, 0.01)
                node.pending.extend(next(remaining, []))

            node.poll = poll
            with mock.patch.object(ota_rf_lab.time, "monotonic", side_effect=lambda: now):
                return node.get_acl(timeout=0.5)
        return read

    def test_exact_normal_permission_command_and_full_live_readback_without_other_writes(self):
        record = self.grant()
        self.assertEqual(self.mutations(), [self.command])
        self.assertEqual(self.target.command.call_args_list, [
            mock.call("get role"), mock.call("get public.key"), mock.call("get name"),
            mock.call("get radio"), mock.call("get path.hash.mode"), mock.call(self.command),
            mock.call("get role"), mock.call("get public.key"), mock.call("get name"),
            mock.call("get radio"), mock.call("get path.hash.mode"),
        ])
        self.assertEqual(self.client.command.call_args_list, [
            mock.call(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
            mock.call(b"\x16\x0d", expected=(13,)),
            mock.call(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
            mock.call(b"\x16\x0d", expected=(13,)),
        ])
        self.assertEqual(record["acl_before"], self.before)
        self.assertEqual(record["acl_after"], self.after)
        self.assertEqual(record["normal_identities_before"]["client"]["pubkey"], CLIENT_KEY.hex())
        self.assertEqual(record["normal_identities_before"]["target"]["pubkey"], TARGET_KEY.hex())
        self.assertNotIn("pubkey_bytes", record["normal_identities_before"]["client"])
        self.assertEqual(record["normal_identities_before"], record["normal_identities_after"])
        self.assertTrue(record["mutation_acknowledged"])
        self.assertTrue(record["live_acl_verified"])
        self.assertFalse(record["reboot_requested"])
        self.assertFalse(record["reboot_persistence_verified"])
        self.assertEqual(record["lazy_save_wait_seconds"], 6.0)
        self.sleep.assert_called_once_with(6.0)

    def test_both_actual_identities_and_complete_acl_are_captured_before_mutation(self):
        timeline = mock.Mock()
        timeline.attach_mock(self.client.command, "client")
        timeline.attach_mock(self.target.command, "target")
        timeline.attach_mock(self.target.get_acl, "acl")
        timeline.attach_mock(self.evidence.log, "log")
        timeline.attach_mock(self.sleep, "sleep")
        self.grant()
        calls = timeline.mock_calls
        write_index = calls.index(mock.call.target(self.command))
        baseline = next(index for index, call in enumerate(calls)
                        if call[0] == "log" and call.args[0] == "normal_admin_grant_baseline")
        self.assertLess(baseline, write_index)
        record = calls[baseline].kwargs
        self.assertEqual(record["acl_before"], self.before)
        self.assertEqual(record["normal_identities_before"]["client"]["pubkey"], CLIENT_KEY.hex())
        self.assertEqual(record["normal_identities_before"]["target"]["pubkey"], TARGET_KEY.hex())
        self.assertEqual([call for call in calls[:write_index] if call[0] in ("client", "target", "acl")], [
            mock.call.client(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
            mock.call.client(b"\x16\x0d", expected=(13,)),
            mock.call.target("get role"), mock.call.target("get public.key"),
            mock.call.target("get name"), mock.call.target("get radio"),
            mock.call.target("get path.hash.mode"), mock.call.acl(),
        ])
        wait_index = calls.index(mock.call.sleep(6.0))
        acl_indices = [index for index, call in enumerate(calls) if call == mock.call.acl()]
        self.assertLess(write_index, wait_index)
        self.assertLess(wait_index, acl_indices[1])

    def test_existing_exact_admin_is_idempotent_but_still_verifies_the_complete_acl(self):
        self.target.get_acl.side_effect = [self.after.copy(), self.after.copy()]
        record = self.grant()
        self.assertEqual(self.mutations(), [])
        self.sleep.assert_not_called()
        self.assertEqual(self.target.get_acl.call_count, 2)
        self.assertFalse(record["command_attempted"])
        self.assertFalse(record["mutation_acknowledged"])
        self.assertEqual(record["lazy_save_wait_seconds"], 0)
        self.assertTrue(record["live_acl_verified"])
        self.assertFalse(record["reboot_persistence_verified"])

    def test_absent_guest_readwrite_and_flagged_permissions_are_not_exact_admin(self):
        for permission in (None, 0, 1, 2, 0x83):
            with self.subTest(permission=permission):
                self.setUp()
                before = {**self.before, CLIENT_KEY.hex(): permission}
                if permission is None:
                    del before[CLIENT_KEY.hex()]
                self.target.get_acl.side_effect = [before, self.after]
                self.grant()
                self.assertEqual(self.mutations(), [self.command])

    def test_only_exact_ok_acknowledges_a_grant(self):
        for reply in ("Err - bad pubkey", "Err - table full", "", "OK extra", "> OK",
                      "OK - reboot to apply", "OK ", "ok"):
            with self.subTest(reply=reply):
                self.setUp()
                original = self.target.command.side_effect
                self.target.command.side_effect = (
                    lambda command: reply if command == self.command else original(command))
                with self.assertRaisesRegex(RuntimeError, "repeater command failed"):
                    self.grant()
                record = self.evidence.summary["measurements"]["admin_grant"]
                self.assertTrue(record["command_attempted"])
                self.assertFalse(record["mutation_acknowledged"])
                self.assertFalse(record["live_acl_verified"])
                self.assertEqual(self.target.get_acl.call_count, 1)
                self.sleep.assert_not_called()

    def test_transport_refusal_is_propagated_without_success_or_followup_mutation(self):
        original = self.target.command.side_effect

        def command(text):
            if text == self.command:
                raise TimeoutError("no repeater CLI reply")
            return original(text)

        self.target.command.side_effect = command
        with self.assertRaisesRegex(TimeoutError, "no repeater CLI reply"):
            self.grant()
        self.assertEqual(self.mutations(), [self.command])
        self.assertFalse(self.evidence.summary["measurements"]["admin_grant"]["live_acl_verified"])
        self.sleep.assert_not_called()

    def test_malformed_duplicate_zero_or_incomplete_initial_acl_prevents_any_grant(self):
        for batches, error in (
            ([["get acl", "ACL:", "03 bad-key"]], ValueError),
            ([["get acl", "ACL:", f"03 {'00' * 32}"]], ValueError),
            ([["get acl", "ACL:", f"03 {'ab' * 32}", f"01 {'AB' * 32}"]], ValueError),
            ([["get acl", "ACL:", f"03 {CLIENT_KEY.hex()}"]], TimeoutError),
            ([["get acl", "ACL:", "get role", "  -> > companion"]], RuntimeError),
        ):
            with self.subTest(batches=batches):
                self.setUp()
                self.target.get_acl.side_effect = self.wire_acl_reader(batches)
                with self.assertRaises(error):
                    self.grant()
                self.assertEqual(self.mutations(), [])
                self.sleep.assert_not_called()
                self.assertFalse(self.evidence.summary["measurements"]["admin_grant"]["command_attempted"])

    def test_malformed_or_incomplete_post_grant_acl_remains_a_failure_after_save_opportunity(self):
        for batches, error in (
            ([["get acl", "ACL:", "garbage"]], ValueError),
            ([["get acl", "ACL:", f"03 {CLIENT_KEY.hex()}", "get role"]], TimeoutError),
        ):
            with self.subTest(batches=batches):
                self.setUp()
                read = self.wire_acl_reader(batches)
                self.target.get_acl.side_effect = (
                    lambda: self.before.copy() if self.target.get_acl.call_count == 1 else read())
                with self.assertRaises(error):
                    self.grant()
                self.sleep.assert_called_once_with(6.0)
                record = self.evidence.summary["measurements"]["admin_grant"]
                self.assertTrue(record["mutation_acknowledged"])
                self.assertFalse(record["live_acl_verified"])
                self.assertFalse(record["reboot_persistence_verified"])

    def test_ok_does_not_replace_exact_permission03_readback(self):
        for permission in (None, 0, 1, 2, 0x83):
            with self.subTest(permission=permission):
                self.setUp()
                after = {**self.after, CLIENT_KEY.hex(): permission}
                if permission is None:
                    del after[CLIENT_KEY.hex()]
                self.target.get_acl.side_effect = [self.before, after]
                with self.assertRaisesRegex(AssertionError, "normal-client-admin-live"):
                    self.grant()
                self.assertFalse(self.evidence.summary["measurements"]["admin_grant"]["live_acl_verified"])

    def test_unrelated_acl_changes_additions_or_removals_are_fatal_without_repair(self):
        for after in ({CLIENT_KEY.hex(): 3}, {**self.after, "ab" * 32: 0x82},
                      {**self.after, "ef" * 32: 1}):
            with self.subTest(after=after):
                self.setUp()
                self.target.get_acl.side_effect = [self.before, after]
                with self.assertRaisesRegex(AssertionError, "unrelated-repeater-acl-preserved"):
                    self.grant()
                self.assertEqual(self.mutations(), [self.command])
                self.assertFalse(self.evidence.summary["measurements"]["admin_grant"]["live_acl_verified"])

    def test_idempotent_readback_does_not_hide_changed_unrelated_entries(self):
        self.target.get_acl.side_effect = [self.after.copy(), {**self.after, "ab" * 32: 1}]
        with self.assertRaisesRegex(AssertionError, "unrelated-repeater-acl-preserved"):
            self.grant()
        self.assertEqual(self.mutations(), [])
        self.sleep.assert_not_called()

    def test_wrong_companion_role_zero_or_short_identity_prevents_target_queries(self):
        for frame in (self_info(advert_type=2), self_info(public_key=bytes(32)), self_info()[:57]):
            with self.subTest(frame=frame[:2]):
                self.setUp()
                self.client.command.side_effect = [frame]
                with self.assertRaises(RuntimeError):
                    self.grant()
                self.target.command.assert_not_called()
                self.target.get_acl.assert_not_called()
                self.sleep.assert_not_called()

    def test_wrong_repeater_role_malformed_or_duplicate_identity_prevents_grant(self):
        for command, reply, error in (
            ("get role", "> companion", RuntimeError),
            ("get role", "> room", RuntimeError),
            ("get public.key", "> " + "00" * 32, RuntimeError),
            ("get public.key", "> " + TARGET_KEY.hex()[:16], RuntimeError),
            ("get public.key", "> " + "gg" * 32, RuntimeError),
            ("get public.key", "> " + CLIENT_KEY.hex().upper(), AssertionError),
        ):
            with self.subTest(command=command, reply=reply):
                self.setUp()
                original = self.target.command.side_effect
                self.target.command.side_effect = (
                    lambda text: reply if text == command else original(text))
                with self.assertRaises(error):
                    self.grant()
                self.target.get_acl.assert_not_called()
                self.assertEqual(self.mutations(), [])
                self.sleep.assert_not_called()

    def test_post_grant_identity_or_setting_change_is_not_success_or_repaired(self):
        for role in ("client", "target"):
            with self.subTest(role=role):
                self.setUp()
                if role == "client":
                    self.client.command.side_effect = [
                        self_info("existing-client"), device_info(0),
                        self_info("changed-client"), device_info(0),
                    ]
                else:
                    original = self.target.command.side_effect

                    def command(text):
                        if text == "get public.key":
                            return "> " + (TARGET_KEY if not self.mutations() else CLIENT_KEY).hex()
                        return original(text)

                    self.target.command.side_effect = command
                with self.assertRaisesRegex(AssertionError, f"normal-admin-grant-{role}-unchanged"):
                    self.grant()
                self.assertEqual(self.mutations(), [self.command])
                self.assertFalse(self.evidence.summary["measurements"]["admin_grant"]["live_acl_verified"])


class AdminGrantModeTests(unittest.TestCase):
    def setUp(self):
        self.evidence = evidence_fixture()
        self.evidence.finish = mock.Mock()
        self.devices = {
            role: mock.Mock(serial=serial, by_id=f"/dev/serial/by-id/{role}")
            for role, serial in ota_rf_lab.APPROVED_ADMIN_PAIR.items()
        }

    def run_main(self):
        arguments = ["ota_rf_lab.py", "--artifact-dir", "unused", "--grant-client-admin"]
        with mock.patch.object(sys, "argv", arguments), \
                mock.patch.object(ota_rf_lab, "Evidence", return_value=self.evidence), \
                mock.patch.object(ota_rf_lab.lab_device, "resolve") as resolve, \
                mock.patch.object(ota_rf_lab, "FramedSerial") as client, \
                mock.patch.object(ota_rf_lab, "RepeaterSerial") as target, \
                mock.patch.object(ota_rf_lab, "run_grant_client_admin") as grant, \
                mock.patch.object(ota_rf_lab, "run_configure") as configure, \
                mock.patch.object(ota_rf_lab, "run_configure_client") as configure_client, \
                mock.patch.object(ota_rf_lab.time, "sleep"):
            self.resolve, self.client, self.target = resolve, client, target
            self.grant, self.configure, self.configure_client = grant, configure, configure_client
            resolve.side_effect = lambda role, mode: self.devices[role]
            if hasattr(self, "failure"):
                grant.side_effect = self.failure
            ota_rf_lab.main()

    def test_explicit_grant_resolves_only_approved_app_roles_and_dispatches_separately(self):
        self.run_main()
        self.assertEqual(self.resolve.call_args_list, [
            mock.call("client", mode=ota_rf_lab.lab_device.MODE_APP),
            mock.call("target", mode=ota_rf_lab.lab_device.MODE_APP),
        ])
        self.client.assert_called_once_with("client-4186AE911D94CDB1",
                                           "/dev/serial/by-id/client", self.evidence)
        self.target.assert_called_once_with("target-3BE94917B92DC5E9",
                                           "/dev/serial/by-id/target", self.evidence)
        self.grant.assert_called_once_with(self.client.return_value, self.target.return_value,
                                          self.evidence)
        self.configure.assert_not_called()
        self.configure_client.assert_not_called()
        self.client.return_value.close.assert_called_once()
        self.target.return_value.close.assert_called_once()
        self.evidence.finish.assert_called_once_with(None)

    def test_unapproved_swapped_duplicate_or_pine_serials_fail_before_either_port_opens(self):
        for role, serial in (("client", "unapproved"), ("target", "unapproved"),
                             ("client", "3BE94917B92DC5E9"), ("target", "4186AE911D94CDB1"),
                             ("client", "49C5BAF21EEF44A1"), ("target", "49C5BAF21EEF44A1")):
            with self.subTest(role=role, serial=serial):
                self.setUp()
                self.devices[role].serial = serial
                with self.assertRaises(AssertionError):
                    self.run_main()
                self.client.assert_not_called()
                self.target.assert_not_called()
                self.grant.assert_not_called()
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
                self.assertIn("AssertionError", self.evidence.finish.call_args.args[0])

    def test_role_name_overrides_cannot_redirect_grant_to_other_roles(self):
        for client_role, target_role in (("other", "target"), ("client", "pine"), ("target", "client")):
            with self.subTest(client_role=client_role, target_role=target_role):
                self.setUp()
                with mock.patch.object(ota_rf_lab, "CLIENT_ROLE", client_role), \
                        mock.patch.object(ota_rf_lab, "TARGET_ROLE", target_role):
                    with self.assertRaisesRegex(AssertionError, "approved-admin-grant-roles"):
                        self.run_main()
                self.resolve.assert_not_called()
                self.client.assert_not_called()
                self.target.assert_not_called()

    def test_existing_role_guard_system_exit_is_logged_as_fatal_not_success(self):
        arguments = ["ota_rf_lab.py", "--artifact-dir", "unused", "--grant-client-admin"]
        with mock.patch.object(sys, "argv", arguments), \
                mock.patch.object(ota_rf_lab, "Evidence", return_value=self.evidence), \
                mock.patch.object(ota_rf_lab.lab_device, "load_roles",
                                  side_effect=SystemExit("refusing protected lab device assignment")), \
                mock.patch.object(ota_rf_lab.lab_device, "discover") as discover, \
                mock.patch.object(ota_rf_lab, "FramedSerial") as client, \
                mock.patch.object(ota_rf_lab, "RepeaterSerial") as target:
            with self.assertRaisesRegex(SystemExit, "refusing protected"):
                ota_rf_lab.main()
        discover.assert_not_called()
        client.assert_not_called()
        target.assert_not_called()
        self.evidence.log.assert_called_with(
            "fatal", error="SystemExit: refusing protected lab device assignment")
        self.evidence.finish.assert_called_once_with(
            "SystemExit: refusing protected lab device assignment")

    def test_grant_failures_are_fatal_logged_rethrown_and_close_both_ports(self):
        for error in (RuntimeError("repeater command failed"), ValueError("malformed ACL row"),
                      TimeoutError("incomplete ACL"), AssertionError("unrelated ACL changed")):
            with self.subTest(error=error):
                self.setUp()
                self.failure = error
                with self.assertRaises(type(error)):
                    self.run_main()
                self.client.return_value.close.assert_called_once()
                self.target.return_value.close.assert_called_once()
                message = f"{type(error).__name__}: {error}"
                self.evidence.log.assert_called_with("fatal", error=message)
                self.evidence.finish.assert_called_once_with(message)


class CompanionSigningTests(unittest.TestCase):
    def setUp(self):
        self.node = mock.Mock(name="client")
        self.node.name = "client"
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.canonical = bytes(range(59))
        self.signature = self.private_key.sign(self.canonical)
        self.start = bytes([ota_rf_lab.RESP_SIGN_START, 0]) + struct.pack("<I", 4096)
        self.node.command.side_effect = [
            self.start, b"\x00", bytes([ota_rf_lab.RESP_SIGNATURE]) + self.signature,
        ]

    def test_manifest_is_signed_by_existing_companion_identity_without_key_export(self):
        self.assertEqual(ota_rf_lab.sign_manifest(self.node, self.canonical, self.public_key),
                         self.signature)
        self.assertEqual(self.node.command.call_args_list, [
            mock.call(bytes([ota_rf_lab.CMD_SIGN_START]),
                      expected=(ota_rf_lab.RESP_SIGN_START, ota_rf_lab.RESP_ERR)),
            mock.call(bytes([ota_rf_lab.CMD_SIGN_DATA]) + self.canonical),
            mock.call(bytes([ota_rf_lab.CMD_SIGN_FINISH]),
                      expected=(ota_rf_lab.RESP_SIGNATURE, ota_rf_lab.RESP_ERR)),
        ])

    def test_invalid_manifest_or_public_key_fails_before_device_io(self):
        for canonical, public_key in ((b"", self.public_key), (self.canonical + b"\x00", self.public_key),
                                      (self.canonical, self.public_key[:-1])):
            with self.subTest(lengths=(len(canonical), len(public_key))):
                with self.assertRaises(ValueError):
                    ota_rf_lab.sign_manifest(self.node, canonical, public_key)
        self.node.command.assert_not_called()

    def test_invalid_start_or_insufficient_buffer_does_not_send_manifest(self):
        for start in (b"", b"\x01\x03", self.start[:-1], self.start + b"\x00",
                      bytes([ota_rf_lab.RESP_SIGN_START, 1]) + struct.pack("<I", 4096),
                      bytes([ota_rf_lab.RESP_SIGN_START, 0]) + struct.pack("<I", 58)):
            with self.subTest(start=start):
                self.node.command.reset_mock()
                self.node.command.side_effect = [start]
                with self.assertRaises(RuntimeError):
                    ota_rf_lab.sign_manifest(self.node, self.canonical, self.public_key)
                self.node.command.assert_called_once()

    def test_data_error_does_not_finish_or_accept_a_signature(self):
        for reply in (b"", b"\x01\x03", b"\x00\x00"):
            with self.subTest(reply=reply):
                self.node.command.reset_mock()
                self.node.command.side_effect = [self.start, reply]
                with self.assertRaisesRegex(RuntimeError, "command failed"):
                    ota_rf_lab.sign_manifest(self.node, self.canonical, self.public_key)
                self.assertEqual(self.node.command.call_count, 2)

    def test_invalid_signature_reply_fails_explicitly(self):
        for reply in (b"", b"\x01\x04", bytes([ota_rf_lab.RESP_SIGNATURE]) + self.signature[:-1],
                      bytes([ota_rf_lab.RESP_SIGNATURE]) + self.signature + b"\x00"):
            with self.subTest(reply=reply):
                self.node.command.side_effect = [self.start, b"\x00", reply]
                with self.assertRaisesRegex(RuntimeError, "invalid signature reply"):
                    ota_rf_lab.sign_manifest(self.node, self.canonical, self.public_key)

    def test_wrong_signer_or_other_manifest_is_not_accepted(self):
        for signature in (Ed25519PrivateKey.generate().sign(self.canonical),
                          self.private_key.sign(bytes(reversed(self.canonical)))):
            with self.subTest(signature=signature):
                self.node.command.side_effect = [
                    self.start, b"\x00", bytes([ota_rf_lab.RESP_SIGNATURE]) + signature,
                ]
                with self.assertRaises(InvalidSignature):
                    ota_rf_lab.sign_manifest(self.node, self.canonical, self.public_key)

    def test_signing_commands_share_the_remaining_operation_deadline(self):
        with mock.patch.object(ota_rf_lab.time, "monotonic", side_effect=[100, 100.25, 100.5]):
            ota_rf_lab.sign_manifest(self.node, self.canonical, self.public_key, deadline=101)
        self.assertEqual([call.kwargs["timeout"] for call in self.node.command.call_args_list],
                         [1, 0.75, 0.5])

    def test_expiry_after_start_prevents_data_and_finish(self):
        with mock.patch.object(ota_rf_lab.time, "monotonic", side_effect=[100, 101]):
            with self.assertRaisesRegex(TimeoutError, "signing deadline"):
                ota_rf_lab.sign_manifest(self.node, self.canonical, self.public_key, deadline=101)
        self.node.command.assert_called_once()

    def test_expired_or_nonfinite_deadline_never_starts_device_signing(self):
        for deadline in (99, 100, float("nan"), float("inf"), -float("inf")):
            with self.subTest(deadline=deadline), \
                    mock.patch.object(ota_rf_lab.time, "monotonic", return_value=100):
                with self.assertRaisesRegex(TimeoutError, "signing deadline"):
                    ota_rf_lab.sign_manifest(self.node, self.canonical, self.public_key, deadline=deadline)
        self.node.command.assert_not_called()

    def test_expiry_after_data_prevents_finish(self):
        with mock.patch.object(ota_rf_lab.time, "monotonic", side_effect=[100, 100.5, 101]):
            with self.assertRaisesRegex(TimeoutError, "signing deadline"):
                ota_rf_lab.sign_manifest(self.node, self.canonical, self.public_key, deadline=101)
        self.assertEqual(self.node.command.call_count, 2)

    def test_each_signing_command_is_capped_by_the_existing_command_timeout(self):
        with mock.patch.object(ota_rf_lab.time, "monotonic", return_value=100):
            ota_rf_lab.sign_manifest(self.node, self.canonical, self.public_key, deadline=200)
        self.assertEqual([call.kwargs["timeout"] for call in self.node.command.call_args_list],
                         [5, 5, 5])


if __name__ == "__main__":
    unittest.main()
