import contextlib
import io
import json
import pathlib
import struct
import sys
import tempfile
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


def device_info(mode=2, version=13, capacity=40):
    frame = bytearray(82)
    frame[0:2] = bytes([13, version])
    frame[3] = capacity
    frame[81] = mode
    return bytes(frame)


CHANNEL_SECRET_CANARY = b"SECRET-PSK-12345"
TEST_SCRATCH = pathlib.Path(__file__).resolve().parents[2] / ".tmp"


def channel_info(index=0, name=""):
    return bytes([18, index]) + name.encode("utf-8").ljust(32, b"\x00") + CHANNEL_SECRET_CANARY


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
            (["--inspect-ota-preflight", "--configure-only"], "not allowed"),
            (["--inspect-ota-preflight", "--grant-client-admin"], "not allowed"),
            (["--inspect-ota-preflight", "--monitor-seconds=0"], "not allowed"),
            (["--inspect-ota-preflight", "--monitor-seconds=1"], "not allowed"),
            (["--inspect-ota-preflight", "--bandwidth-hz=62500"], "requires --configure-only"),
            (["--inspect-ota-preflight", "--bandwidth-hz=250000"], "requires --configure-only"),
            (["--inspect-configuration", "--configure-only"], "not allowed"),
            (["--inspect-configuration", "--grant-client-admin"], "not allowed"),
            (["--inspect-configuration", "--inspect-ota-preflight"], "not allowed"),
            (["--inspect-configuration", "--monitor-seconds=0"], "not allowed"),
            (["--inspect-configuration", "--monitor-seconds=1"], "not allowed"),
            (["--inspect-configuration", "--bandwidth-hz=62500"], "requires --configure-only"),
            (["--inspect-configuration", "--bandwidth-hz=250000"], "requires --configure-only"),
            (["--inspect-channels", "--configure-only"], "not allowed"),
            (["--inspect-channels", "--grant-client-admin"], "not allowed"),
            (["--inspect-channels", "--inspect-configuration"], "not allowed"),
            (["--inspect-channels", "--inspect-ota-preflight"], "not allowed"),
            (["--inspect-channels", "--monitor-seconds=0"], "not allowed"),
            (["--inspect-channels", "--monitor-seconds=1"], "not allowed"),
            (["--inspect-channels", "--bandwidth-hz=62500"], "requires --configure-only"),
            (["--inspect-channels", "--bandwidth-hz=250000"], "requires --configure-only"),
            (["--inspect-channels", "--require-target-genesis-floor"], "requires --inspect-ota-preflight"),
            (["--inspect-channels", "--require-target-boot-addresses"], "requires --inspect-ota-preflight"),
            (["--inspect-measurements", "--configure-only"], "not allowed"),
            (["--inspect-measurements", "--grant-client-admin"], "not allowed"),
            (["--inspect-measurements", "--inspect-configuration"], "not allowed"),
            (["--inspect-measurements", "--inspect-ota-preflight"], "not allowed"),
            (["--inspect-measurements", "--inspect-channels"], "not allowed"),
            (["--inspect-measurements", "--monitor-seconds=0"], "not allowed"),
            (["--inspect-measurements", "--bandwidth-hz=250000"], "requires --configure-only"),
            (["--inspect-measurements", "--require-target-genesis-floor"], "requires --inspect-ota-preflight"),
            (["--inspect-measurements", "--require-target-boot-addresses"], "requires --inspect-ota-preflight"),
            (["--require-target-genesis-floor"], "requires --inspect-ota-preflight"),
            (["--require-target-genesis-floor", "--configure-only"], "requires --inspect-ota-preflight"),
            (["--require-target-genesis-floor", "--grant-client-admin"], "requires --inspect-ota-preflight"),
            (["--require-target-genesis-floor", "--inspect-configuration"], "requires --inspect-ota-preflight"),
            (["--require-target-genesis-floor", "--monitor-seconds=1"], "requires --inspect-ota-preflight"),
            (["--require-target-genesis-floor", "--inspect-ota-preflight", "--client-only"],
             "requires --inspect-ota-preflight"),
            (["--require-target-genesis-floor", "--inspect-ota-preflight", "--bandwidth-hz=250000"],
             "requires --configure-only"),
            (["--require-target-boot-addresses"], "requires --inspect-ota-preflight"),
            (["--require-target-boot-addresses", "--configure-only"], "requires --inspect-ota-preflight"),
            (["--require-target-boot-addresses", "--grant-client-admin"], "requires --inspect-ota-preflight"),
            (["--require-target-boot-addresses", "--monitor-seconds=0"], "requires --inspect-ota-preflight"),
            (["--require-target-boot-addresses", "--monitor-seconds=1"], "requires --inspect-ota-preflight"),
            (["--require-target-boot-addresses", "--inspect-configuration"],
             "requires --inspect-ota-preflight"),
            (["--require-target-boot-addresses", "--inspect-ota-preflight", "--client-only"],
             "requires --inspect-ota-preflight"),
            (["--require-target-boot-addresses", "--inspect-ota-preflight", "--bandwidth-hz=250000"],
             "requires --configure-only"),
            (["--monitor-seconds=1", "--bandwidth-hz=250000"], "requires --configure-only"),
            (["--grant-client-admin", "--bandwidth-hz=250000"], "requires --configure-only"),
            (["--bandwidth-hz=250000"], "requires --configure-only"),
            (["--client-only", "--bandwidth-hz=62500"], "requires --configure-only"),
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

    def test_invalid_or_unsupported_bandwidth_is_refused_before_any_physical_access(self):
        for bandwidth in ("nan", "inf", "-inf", "250000.0", "250000.5", "2.5e5",
                          "0x3d090", "-250000", "0", "7799", "7812", "15625", "100000",
                          "249999", "250001", "500001", ""):
            with self.subTest(bandwidth=bandwidth):
                arguments = ["ota_rf_lab.py", "--artifact-dir", "unused", "--configure-only",
                             f"--bandwidth-hz={bandwidth}"]
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
                    self.assertIn("--bandwidth-hz", errors.getvalue())
                    evidence.assert_not_called()
                    resolve.assert_not_called()
                    client.assert_not_called()
                    target.assert_not_called()
                    open_port.assert_not_called()

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
                                                self.evidence.return_value,
                                                radio=ota_rf_lab.NORMAL_RADIO)
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
        self.configure_client.assert_called_once_with(client.return_value, self.evidence.return_value,
                                                     radio=ota_rf_lab.NORMAL_RADIO)

    def test_supported_bandwidths_dispatch_only_the_selected_radio_profile(self):
        self.assertEqual(ota_rf_lab.SUPPORTED_LORA_BANDWIDTHS_HZ,
                         (7800, 10400, 15600, 20800, 31250, 41700,
                          62500, 125000, 250000, 500000))
        for bandwidth in ota_rf_lab.SUPPORTED_LORA_BANDWIDTHS_HZ:
            with self.subTest(bandwidth=bandwidth):
                client, target = self.run_main_fixture(
                    ["--configure-only", f"--bandwidth-hz={bandwidth}"])
                self.configure.assert_called_once_with(
                    client.return_value, target.return_value, self.evidence.return_value,
                    radio=(907525, bandwidth, 7, 5))
                self.configure_client.assert_not_called()
                self.assertEqual(ota_rf_lab.NORMAL_RADIO, (907525, 62500, 7, 5))

    def test_client_only_bandwidth_override_does_not_open_target(self):
        client, target = self.run_main_fixture(
            ["--configure-only", "--client-only", "--bandwidth-hz=250000"])
        target.assert_not_called()
        self.configure.assert_not_called()
        self.configure_client.assert_called_once_with(
            client.return_value, self.evidence.return_value, radio=(907525, 250000, 7, 5))


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

    def bandwidth_fixture(self, bandwidth, client_readback=None, target_readback=None):
        client_radio = (907525, bandwidth if client_readback is None else client_readback, 7, 5)
        target_bandwidth = bandwidth if target_readback is None else target_readback
        self.client.command.side_effect = [
            self_info("existing-client"), device_info(0), b"\x00", b"\x00", b"\x00",
            self_info(radio=client_radio), device_info(),
        ]
        self.target = repeater_fixture({
            "get radio": ["> 907.5250244,62.5,7,5",
                          f"> 907.5250244,{target_bandwidth / 1000:g},7,5"],
            f"set radio 907.525,{bandwidth / 1000:g},7,5": ["OK - reboot to apply"],
        })

    def test_default_and_250khz_override_use_actual_readbacks_exact_setters_and_selected_evidence(self):
        for override in (None, 62500, 250000):
            with self.subTest(override=override):
                self.setUp()
                bandwidth = 62500 if override is None else override
                self.bandwidth_fixture(bandwidth)
                self.evidence.finish = mock.Mock()
                arguments = ["ota_rf_lab.py", "--artifact-dir", "unused", "--configure-only"]
                if override is not None:
                    arguments.append(f"--bandwidth-hz={override}")
                devices = {
                    role: mock.Mock(serial=serial, by_id=f"/dev/serial/by-id/{role}")
                    for role, serial in ota_rf_lab.APPROVED_ADMIN_PAIR.items()
                }
                with mock.patch.object(sys, "argv", arguments), \
                        mock.patch.object(ota_rf_lab, "Evidence", return_value=self.evidence), \
                        mock.patch.object(ota_rf_lab, "resolve_roles", return_value=devices), \
                        mock.patch.object(ota_rf_lab, "FramedSerial", return_value=self.client), \
                        mock.patch.object(ota_rf_lab, "RepeaterSerial", return_value=self.target), \
                        mock.patch.object(ota_rf_lab.time, "sleep"):
                    ota_rf_lab.main()
                radio = [907525, bandwidth, 7, 5]
                self.assertEqual(self.client.command.call_args_list, [
                    mock.call(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
                    mock.call(b"\x16\x0d", expected=(13,)),
                    mock.call(b"\x08OTA-LAB-CLIENT"),
                    mock.call(b"\x0b" + struct.pack("<II", 907525, bandwidth) + bytes([7, 5, 0])),
                    mock.call(b"\x3d\x00\x02"),
                    mock.call(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
                    mock.call(b"\x16\x0d", expected=(13,)),
                ])
                self.assertEqual(self.target.command.call_args_list, [
                    mock.call("get role"), mock.call("get public.key"), mock.call("get name"),
                    mock.call("get radio"), mock.call("get path.hash.mode"),
                    mock.call("set name OTA-LAB-TARGET"),
                    mock.call(f"set radio 907.525,{bandwidth / 1000:g},7,5"),
                    mock.call("set path.hash.mode 2"),
                    mock.call("get role"), mock.call("get public.key"), mock.call("get name"),
                    mock.call("get radio"), mock.call("get path.hash.mode"),
                ])
                measurements = self.evidence.summary["measurements"]
                self.assertEqual(measurements["configuration_expected_radio"], radio)
                self.assertEqual(measurements["acl_before"], measurements["acl_after"])
                self.assertEqual(self.target.get_acl.call_count, 2)
                for role, key in (("client", CLIENT_KEY.hex()), ("target", TARGET_KEY.hex())):
                    self.assertEqual(measurements["configured"][role]["bw_hz"], bandwidth)
                    self.assertEqual(measurements["configured"][role]["pubkey"], key)
                    self.assertEqual(measurements["configured"][role]["path_hash_mode"], 2)
                    check = self.evidence.summary["checks"][f"default-radio-{role}"]
                    self.assertTrue(check["passed"])
                    self.assertEqual(check["expected_radio"], radio)
                    self.assertFalse(check["active_rf_verified"])
                readbacks = [call.kwargs for call in self.evidence.log.call_args_list
                             if call.args == ("configuration_readback",)]
                self.assertEqual(len(readbacks), 2)
                self.assertTrue(all(row["expected_radio"] == radio for row in readbacks))
                self.assertTrue(all(not row["reboot_persistence_verified"] for row in readbacks))
                self.assertEqual(ota_rf_lab.NORMAL_RADIO, (907525, 62500, 7, 5))
                self.evidence.finish.assert_called_once_with(None)

    def test_selected_bandwidth_requires_both_role_readbacks_without_falling_back_to_default(self):
        for role in ("client", "target"):
            with self.subTest(role=role):
                self.setUp()
                readbacks = {f"{role}_readback": 62500}
                self.bandwidth_fixture(250000, **readbacks)
                with self.assertRaisesRegex(AssertionError, f"default-radio-{role}"):
                    ota_rf_lab.run_configure(self.client, self.target, self.evidence,
                                            radio=(907525, 250000, 7, 5))
                check = self.evidence.summary["checks"][f"default-radio-{role}"]
                self.assertFalse(check["passed"])
                self.assertEqual(check["expected_radio"], [907525, 250000, 7, 5])
                self.assertEqual(self.evidence.summary["measurements"]["configuration_expected_radio"],
                                 [907525, 250000, 7, 5])
                self.assertNotIn(role, self.evidence.summary["measurements"].get("configured", {}))
                self.assertIn(
                    mock.call(b"\x0b" + struct.pack("<II", 907525, 250000) + bytes([7, 5, 0])),
                    self.client.command.call_args_list)
                self.assertFalse(any(call.args[0] == "set radio 907.525,62.5,7,5"
                                     for call in self.target.command.call_args_list))

    def test_override_radio_setter_still_requires_exact_reboot_pending_ok(self):
        for reply in ("OK", "OK - reboot to apply extra", "Err - bad param"):
            with self.subTest(reply=reply):
                self.setUp()
                self.bandwidth_fixture(250000)
                original = self.target.command.side_effect
                setter = "set radio 907.525,250,7,5"
                self.target.command.side_effect = (
                    lambda command: reply if command == setter else original(command))
                with self.assertRaisesRegex(RuntimeError, "repeater command failed"):
                    ota_rf_lab.run_configure(self.client, self.target, self.evidence,
                                            radio=(907525, 250000, 7, 5))
                self.assertEqual(self.target.command.call_args_list[-1], mock.call(setter))
                self.assertEqual(self.target.get_acl.call_count, 1)
                self.assertNotIn("target", self.evidence.summary["measurements"]["configured"])

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
        self.target.assert_called_once_with("target-77CD44653A967172",
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
                             ("client", "77CD44653A967172"), ("target", "4186AE911D94CDB1"),
                             ("target", "3BE94917B92DC5E9"),
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


class OtaPreflightInspectionTests(unittest.TestCase):
    EARLY = "writes=blocked marker=blank proof=sdk-read sdk=unread"
    CAPABILITY = "writes=blocked CACHE_UNAVAILABLE: SDK bank0 read failed"
    GENESIS_REASON = ("floor=present seq=00000001 ctr=00000000 ext=00000000 sha="
                      + "0" * 64 + " io=ok")
    GENESIS_CAPABILITY = "writes=allowed INSTALL_CAPABLE: " + GENESIS_REASON
    BOOT_ADDRESSES = ("mbr8=FFFFFFFF mbrc=FFFFFFFF uicrb=000F4000 uicrp=000FE000 "
                      "boot=000F4000 params=000FE000")

    def setUp(self):
        self.evidence = evidence_fixture()
        self.evidence.finish = mock.Mock()
        self.client = mock.Mock()
        self.client.name = "client"
        self.client.command.side_effect = [
            self_info(), b"\x1d" + self.EARLY.encode("ascii"),
            b"\x1d" + self.CAPABILITY.encode("ascii"),
        ]
        self.target = mock.Mock()
        self.target.name = "target"
        self.target.command.side_effect = [
            "> repeater", "> " + TARGET_KEY.hex(), self.EARLY, self.CAPABILITY,
        ]
        self.devices = {
            role: mock.Mock(serial=serial, by_id=f"/dev/serial/by-id/{role}")
            for role, serial in ota_rf_lab.APPROVED_ADMIN_PAIR.items()
        }

    def run_main(self, options=()):
        arguments = ["ota_rf_lab.py", "--artifact-dir", "unused",
                     "--inspect-ota-preflight", *options]
        with mock.patch.object(sys, "argv", arguments), \
                mock.patch.object(ota_rf_lab, "Evidence", return_value=self.evidence), \
                mock.patch.object(ota_rf_lab.lab_device, "resolve") as resolve, \
                mock.patch.object(ota_rf_lab, "FramedSerial", return_value=self.client) as client_open, \
                mock.patch.object(ota_rf_lab, "RepeaterSerial", return_value=self.target) as target_open, \
                mock.patch.object(ota_rf_lab.time, "sleep"):
            self.resolve, self.client_open, self.target_open = resolve, client_open, target_open
            resolve.side_effect = lambda role, mode: self.devices[role]
            ota_rf_lab.main()

    def genesis_fixture(self, capability=None, early_blocked=False):
        self.client.command.side_effect = [
            self_info(), b"\x1d" + self.EARLY.replace("blocked", "allowed").encode("ascii"),
            b"\x1dwrites=allowed CACHE_ONLY: verified stock boot",
        ]
        writes = "blocked" if early_blocked else "allowed"
        self.target.command.side_effect = [
            "> repeater", "> " + TARGET_KEY.hex(),
            f"writes={writes} marker=qualified proof=qualified-state state=0 phase=0 decision=0",
            self.GENESIS_CAPABILITY if capability is None else capability,
        ]

    def assert_probe_commands(self):
        self.assertEqual(self.client.command.call_args_list, [
            mock.call(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
            mock.call(bytes.fromhex("420001"), expected=(29, 1)),
            mock.call(bytes.fromhex("420002"), expected=(29, 1)),
        ])
        self.assertEqual(self.target.command.call_args_list, [
            mock.call("get role"), mock.call("get public.key"),
            mock.call("ota preflight"), mock.call("ota capability"),
        ])
        self.client.get_acl.assert_not_called()
        self.target.get_acl.assert_not_called()

    def boot_addresses_fixture(self, text=None, early_blocked=False, capability_blocked=False):
        self.genesis_fixture(early_blocked=early_blocked)
        capability = self.GENESIS_CAPABILITY.replace("allowed", "blocked") if capability_blocked \
            else self.GENESIS_CAPABILITY
        writes = "blocked" if early_blocked else "allowed"
        self.target.command.side_effect = [
            "> repeater", "> " + TARGET_KEY.hex(),
            f"writes={writes} marker=qualified proof=qualified-state state=0 phase=0 decision=0",
            capability, self.BOOT_ADDRESSES if text is None else text,
        ]

    def test_boot_addresses_inspection_captures_actual_words_without_reset_or_install(self):
        self.boot_addresses_fixture()
        self.run_main(["--require-target-boot-addresses"])
        record = self.evidence.summary["measurements"]["ota_preflight"]
        self.assertTrue(record["read_only"])
        self.assertTrue(record["target_boot_addresses_required"])
        self.assertTrue(record["target_boot_addresses_verified"])
        self.assertFalse(record["target_genesis_floor_verified"])
        self.assertEqual(record["nodes"]["target"]["bootloader"], {
            "command": "ota bootloader", "text": self.BOOT_ADDRESSES,
            "hex": {"mbr8": "FFFFFFFF", "mbrc": "FFFFFFFF",
                    "uicrb": "000F4000", "uicrp": "000FE000",
                    "boot": "000F4000", "params": "000FE000"},
            "mbr8": 0xFFFFFFFF, "mbrc": 0xFFFFFFFF,
            "uicrb": 0xF4000, "uicrp": 0xFE000, "boot": 0xF4000, "params": 0xFE000,
        })
        self.assertEqual(self.target.command.call_args_list, [
            mock.call("get role"), mock.call("get public.key"),
            mock.call("ota preflight"), mock.call("ota capability"), mock.call("ota bootloader"),
        ])
        self.assertEqual(self.client.command.call_count, 3)
        self.target.get_acl.assert_not_called()
        check = self.evidence.summary["checks"]["target-boot-addresses"]
        self.assertFalse(check["board_id_verified"])
        self.assertFalse(check["cf2_verified"])
        self.assertFalse(check["loader_installed_verified"])
        self.evidence.finish.assert_called_once_with(None)

    def test_current_mbr_words_override_uicr_without_assuming_erased_words_are_zero(self):
        text = ("mbr8=000F4000 mbrc=000FE000 uicrb=000F0000 uicrp=FFFFFFFF "
                "boot=000F4000 params=000FE000")
        self.boot_addresses_fixture(text)
        self.run_main(["--require-target-boot-addresses"])
        self.assertTrue(self.evidence.summary["measurements"]["ota_preflight"]
                        ["target_boot_addresses_verified"])

    def test_independent_word_selection_uses_only_ffffffff_as_the_uicr_sentinel(self):
        for text in (
            "mbr8=000F4000 mbrc=FFFFFFFF uicrb=00000000 uicrp=000FE000 "
            "boot=000F4000 params=000FE000",
            "mbr8=FFFFFFFF mbrc=000FE000 uicrb=000F4000 uicrp=00000000 "
            "boot=000F4000 params=000FE000",
        ):
            with self.subTest(text=text):
                self.setUp()
                self.boot_addresses_fixture(text)
                self.run_main(["--require-target-boot-addresses"])
                self.assertTrue(self.evidence.summary["measurements"]["ota_preflight"]
                                ["target_boot_addresses_verified"])
        for mbr_boot in ("00000000", "FFFFFFFE"):
            with self.subTest(mbr_boot=mbr_boot):
                self.setUp()
                text = (f"mbr8={mbr_boot} mbrc=FFFFFFFF uicrb=000F4000 "
                        f"uicrp=000FE000 boot={mbr_boot} params=000FE000")
                self.boot_addresses_fixture(text)
                with self.assertRaisesRegex(AssertionError, "target-boot-addresses"):
                    self.run_main(["--require-target-boot-addresses"])
                observed = self.evidence.summary["measurements"]["ota_preflight"]
                self.assertEqual(observed["nodes"]["target"]["bootloader"]["boot"], int(mbr_boot, 16))
                self.assertFalse(observed["target_boot_addresses_verified"])

    def test_boot_address_serial_transport_strips_the_existing_wrapper_not_a_payload_prefix(self):
        node = ota_rf_lab.RepeaterSerial.__new__(ota_rf_lab.RepeaterSerial)
        node.name = "target"
        node.pending = []
        node.buffer = bytearray()
        node.evidence = mock.Mock()
        node._write_bytes = mock.Mock()
        batches = iter([[], ["ota bootloader", "  -> " + self.BOOT_ADDRESSES]])
        node.poll = mock.Mock(side_effect=lambda timeout=0: node.pending.extend(next(batches, [])))
        text = node.command("ota bootloader")
        self.assertEqual(text, self.BOOT_ADDRESSES)
        self.assertEqual(len(text), 87)
        self.assertEqual(ota_rf_lab.parse_ota_boot_addresses(text)["hex"]["uicrb"], "000F4000")
        node._write_bytes.assert_called_once_with(b"ota bootloader\r")

    def test_backend_boot_address_refusals_keep_actual_raw_errors_and_fail_explicitly(self):
        for text in ("Err - USB only", "Err - bootloader metadata changed",
                     "Err - bootloader reply overflow"):
            with self.subTest(text=text):
                self.setUp()
                self.boot_addresses_fixture(text)
                with self.assertRaisesRegex(RuntimeError, text):
                    self.run_main(["--require-target-boot-addresses"])
                record = self.evidence.summary["measurements"]["ota_preflight"]
                self.assertFalse(record["inspection_complete"])
                self.assertFalse(record["target_boot_addresses_verified"])
                self.assertEqual(record["nodes"]["target"]["bootloader"]["text"], text)
                self.assertIn(text, record["nodes"]["target"]["bootloader"]["error"])
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
                self.client.close.assert_called_once()
                self.target.close.assert_called_once()

    def test_boot_address_requirement_cannot_bypass_approved_pair_or_role_name_guards(self):
        for role, serial in (("client", "unapproved"), ("target", "unapproved"),
                             ("target", "3BE94917B92DC5E9"),
                             ("client", "49C5BAF21EEF44A1"), ("target", "49C5BAF21EEF44A1")):
            with self.subTest(role=role, serial=serial):
                self.setUp()
                self.boot_addresses_fixture()
                self.devices[role].serial = serial
                with self.assertRaises(AssertionError):
                    self.run_main(["--require-target-boot-addresses"])
                self.client_open.assert_not_called()
                self.target_open.assert_not_called()
                self.client.command.assert_not_called()
                self.target.command.assert_not_called()
        self.setUp()
        with mock.patch.object(ota_rf_lab, "TARGET_ROLE", "pine"):
            with self.assertRaisesRegex(AssertionError, "approved-ota-preflight-roles"):
                self.run_main(["--require-target-boot-addresses"])
        self.resolve.assert_not_called()
        self.client_open.assert_not_called()
        self.target_open.assert_not_called()

    def test_boot_address_requirement_checks_actual_roles_and_distinct_normal_keys_before_queries(self):
        for frame, role, key in ((self_info(advert_type=2), "> repeater", TARGET_KEY),
                                 (self_info(), "> room", TARGET_KEY),
                                 (self_info(), "> repeater", CLIENT_KEY)):
            with self.subTest(role=role, key=key):
                self.setUp()
                self.client.command.side_effect = [frame]
                self.target.command.side_effect = [role, "> " + key.hex()]
                with self.assertRaises((RuntimeError, AssertionError)):
                    self.run_main(["--require-target-boot-addresses"])
                self.assertEqual(self.client.command.call_count, 1)
                self.assertFalse(any(call.args[0].startswith("ota ")
                                     for call in self.target.command.call_args_list))

    def test_boot_addresses_and_actual_genesis_floor_are_independent_required_proofs(self):
        self.boot_addresses_fixture()
        self.run_main(["--require-target-boot-addresses", "--require-target-genesis-floor"])
        record = self.evidence.summary["measurements"]["ota_preflight"]
        self.assertTrue(record["target_boot_addresses_verified"])
        self.assertTrue(record["target_genesis_floor_verified"])
        self.assertTrue(self.evidence.summary["checks"]["target-boot-addresses"]["passed"])
        self.assertTrue(self.evidence.summary["checks"]["target-genesis-floor"]["passed"])

    def test_boot_address_requirement_refuses_wrong_erased_zero_or_blocked_values(self):
        cases = [
            (self.BOOT_ADDRESSES.replace("000F4000", "000F0000"), False, False),
            (self.BOOT_ADDRESSES.replace("000FE000", "000FF000"), False, False),
            (self.BOOT_ADDRESSES.replace("000F4000", "FFFFFFFF").replace("000FE000", "FFFFFFFF"),
             False, False),
            (self.BOOT_ADDRESSES.replace("FFFFFFFF", "00000000")
             .replace("000F4000", "00000000").replace("000FE000", "00000000"), False, False),
            (self.BOOT_ADDRESSES, True, False),
            (self.BOOT_ADDRESSES, False, True),
        ]
        for text, early_blocked, capability_blocked in cases:
            with self.subTest(text=text, early_blocked=early_blocked,
                              capability_blocked=capability_blocked):
                self.setUp()
                self.boot_addresses_fixture(text, early_blocked, capability_blocked)
                with self.assertRaisesRegex(AssertionError, "target-boot-addresses"):
                    self.run_main(["--require-target-boot-addresses"])
                record = self.evidence.summary["measurements"]["ota_preflight"]
                self.assertTrue(record["inspection_complete"])
                self.assertFalse(record["target_boot_addresses_verified"])
                self.assertEqual(record["nodes"]["target"]["bootloader"]["text"], text)
                self.assertIn("target-boot-addresses", self.evidence.finish.call_args.args[0])

    def test_malformed_or_inconsistent_boot_words_retain_evidence_and_fail_explicitly(self):
        for text in (
            self.BOOT_ADDRESSES[:-1],
            self.BOOT_ADDRESSES + " boot=000F4000",
            self.BOOT_ADDRESSES.replace("mbr8=FFFFFFFF ", ""),
            self.BOOT_ADDRESSES.replace(" boot=000F4000", " boot=000F0000"),
            self.BOOT_ADDRESSES.replace(" params=000FE000", " params=000FF000"),
            self.BOOT_ADDRESSES.replace("mbr8=FFFFFFFF", "mbr8=000F0000"),
            self.BOOT_ADDRESSES.replace("mbrc=FFFFFFFF", "mbrc=?"),
            self.BOOT_ADDRESSES.replace("uicrb=000F4000", "uicrb=000f4000"),
            self.BOOT_ADDRESSES.replace("mbrc=FFFFFFFF", "mbrc=FFFFFFF"),
            self.BOOT_ADDRESSES.replace(" ", "  ", 1),
            self.BOOT_ADDRESSES.replace("mbr8=", "mbr_boot="),
            "bootloader " + self.BOOT_ADDRESSES,
            "> " + self.BOOT_ADDRESSES,
            self.BOOT_ADDRESSES + "\r\n",
            self.BOOT_ADDRESSES + "\x00",
            "ERR: boot metadata unavailable",
        ):
            with self.subTest(text=text):
                self.setUp()
                self.boot_addresses_fixture(text)
                with self.assertRaises(ValueError):
                    self.run_main(["--require-target-boot-addresses"])
                record = self.evidence.summary["measurements"]["ota_preflight"]
                self.assertFalse(record["inspection_complete"])
                self.assertFalse(record["target_boot_addresses_verified"])
                self.assertEqual(record["nodes"]["target"]["bootloader"]["text"], text)
                self.assertIn("error", record["nodes"]["target"]["bootloader"])
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))

    def test_ordinary_preflight_does_not_query_or_assume_boot_addresses(self):
        self.run_main()
        self.assert_probe_commands()
        record = self.evidence.summary["measurements"]["ota_preflight"]
        self.assertFalse(record["target_boot_addresses_required"])
        self.assertFalse(record["target_boot_addresses_verified"])
        self.assertNotIn("bootloader", record["nodes"]["target"])

    def test_floor_suffix_parses_full_hex_values_without_losing_the_opaque_reason(self):
        reason = ("floor=present seq=A0000001 ctr=00000002 ext=00010000 sha="
                  + "AB" * 32 + " io=ok")
        parsed = ota_rf_lab.parse_ota_preflight_diagnostic(
            "writes=blocked INSTALL_CAPABLE: " + reason, "capability")
        self.assertEqual(parsed["reason"], reason)
        self.assertFalse(parsed["writes_allowed"])
        self.assertEqual(parsed["floor"], {
            "state": "present", "seq": 0xA0000001, "ctr": 2, "ext": 0x10000,
            "sha": "AB" * 32, "io": "ok",
        })

    def test_old_opaque_reasons_explicitly_report_missing_floor_fields_not_zero(self):
        for capability, reason in (("CACHE_ONLY", "verified stock boot"),
                                   ("INSTALL_CAPABLE", "qualified custom bootloader detected (command v3)"),
                                   ("STAGING_ONLY", "floor not initialized")):
            with self.subTest(capability=capability):
                parsed = ota_rf_lab.parse_ota_preflight_diagnostic(
                    f"writes=allowed {capability}: {reason}", "capability")
                self.assertEqual(parsed["capability"], capability)
                self.assertEqual(parsed["reason"], reason)
                self.assertEqual(parsed["floor"], {
                    "state": "missing", "seq": None, "ctr": None, "ext": None, "sha": None, "io": None,
                })

    def test_nonpresent_floor_states_keep_unknown_values_and_actual_io_reason(self):
        for state, io in (("blank", "ok"), ("corrupt", "ok"),
                          ("read-error", "read-error"), ("unavailable", "geometry")):
            with self.subTest(state=state):
                prefix = "floor not initialized " if state == "blank" else ""
                reason = f"{prefix}floor={state} seq=? ctr=? ext=? sha=? io={io}"
                parsed = ota_rf_lab.parse_ota_preflight_diagnostic(
                    "writes=blocked STAGING_ONLY: " + reason, "capability")
                self.assertEqual(parsed["reason"], reason)
                self.assertEqual(parsed["floor"], {
                    "state": state, "seq": None, "ctr": None, "ext": None, "sha": None, "io": io,
                })
        parsed = ota_rf_lab.parse_ota_preflight_diagnostic(
            "writes=blocked STAGING_ONLY: floor=unavailable io=buffer", "capability")
        self.assertEqual(parsed["floor"], {
            "state": "unavailable", "seq": None, "ctr": None, "ext": None, "sha": None, "io": "buffer",
        })

    def test_malformed_truncated_duplicate_or_ambiguous_floor_tuples_are_not_opaque_fallback(self):
        for reason in (
            self.GENESIS_REASON.replace("seq=00000001 ", ""),
            self.GENESIS_REASON.replace("floor=present ", ""),
            self.GENESIS_REASON.replace("seq=00000001", "seq=0000001"),
            self.GENESIS_REASON.replace("ctr=00000000", "ctr=0000000G"),
            self.GENESIS_REASON.replace("ext=00000000", "ext=0000000a"),
            self.GENESIS_REASON.replace("sha=" + "0" * 64, "sha=" + "0" * 63),
            self.GENESIS_REASON.replace("sha=" + "0" * 64, "sha=" + "G" * 64),
            self.GENESIS_REASON.removesuffix(" io=ok"),
            self.GENESIS_REASON.replace("seq=00000001", "seq=?"),
            self.GENESIS_REASON.replace("io=ok", "io=read-error"),
            self.GENESIS_REASON + " ctr=00000000",
            "seq=00000001 " + self.GENESIS_REASON,
            "floor=blank seq=00000000 ctr=00000000 ext=00000000 sha=? io=ok",
            "floor=corrupt seq=? ctr=? ext=? sha=? io=geometry",
            "floor=read-error seq=? ctr=? ext=? sha=? io=ok",
            "floor=unavailable seq=? ctr=? ext=? sha=? io=ok",
            "floor=unknown seq=? ctr=? ext=? sha=? io=ok",
            "floor=unavailable io=geometry",
            "floor=present floor=present",
        ):
            with self.subTest(reason=reason):
                with self.assertRaises(ValueError):
                    ota_rf_lab.parse_ota_preflight_diagnostic(
                        "writes=allowed INSTALL_CAPABLE: " + reason, "capability")

    def test_exact_target_genesis_assertion_succeeds_with_stock_cache_only_client_without_floor(self):
        self.genesis_fixture()
        self.run_main(["--require-target-genesis-floor"])
        self.assert_probe_commands()
        self.assertEqual(self.resolve.call_args_list, [
            mock.call("client", mode=ota_rf_lab.lab_device.MODE_APP),
            mock.call("target", mode=ota_rf_lab.lab_device.MODE_APP),
        ])
        record = self.evidence.summary["measurements"]["ota_preflight"]
        self.assertTrue(record["inspection_complete"])
        self.assertTrue(record["target_genesis_floor_required"])
        self.assertTrue(record["target_genesis_floor_verified"])
        client = record["nodes"]["client"]["capability"]
        target = record["nodes"]["target"]["capability"]
        self.assertEqual(client["capability"], "CACHE_ONLY")
        self.assertEqual(client["floor"]["state"], "missing")
        self.assertIsNone(client["floor"]["ctr"])
        self.assertEqual(target["text"], self.GENESIS_CAPABILITY)
        self.assertEqual(target["floor"], {
            "state": "present", "seq": 1, "ctr": 0, "ext": 0, "sha": "0" * 64, "io": "ok",
        })
        self.assertTrue(self.evidence.summary["checks"]["target-genesis-floor"]["passed"])
        self.evidence.finish.assert_called_once_with(None)

    def test_genesis_requirement_refuses_stock_missing_nonpresent_nonzero_or_blocked_target(self):
        reasons = [
            "CACHE_ONLY: verified stock boot",
            "INSTALL_CAPABLE: qualified custom bootloader detected (command v3)",
            "INSTALL_CAPABLE: floor not initialized",
            "STAGING_ONLY: floor not initialized floor=blank seq=? ctr=? ext=? sha=? io=ok",
            "STAGING_ONLY: floor=corrupt seq=? ctr=? ext=? sha=? io=ok",
            "STAGING_ONLY: floor=read-error seq=? ctr=? ext=? sha=? io=read-error",
            "STAGING_ONLY: floor=unavailable seq=? ctr=? ext=? sha=? io=geometry",
            "STAGING_ONLY: floor=unavailable io=buffer",
            "CACHE_ONLY: " + self.GENESIS_REASON,
            "STAGING_ONLY: " + self.GENESIS_REASON,
            "INSTALL_CAPABLE: floor=blank seq=? ctr=? ext=? sha=? io=ok",
            "INSTALL_CAPABLE: " + self.GENESIS_REASON.replace("seq=00000001", "seq=00000000"),
            "INSTALL_CAPABLE: " + self.GENESIS_REASON.replace("seq=00000001", "seq=00000002"),
            "INSTALL_CAPABLE: " + self.GENESIS_REASON.replace("ctr=00000000", "ctr=00000001"),
            "INSTALL_CAPABLE: " + self.GENESIS_REASON.replace("ext=00000000", "ext=00000001"),
            "INSTALL_CAPABLE: " + self.GENESIS_REASON.replace("sha=" + "0" * 64, "sha=" + "0" * 63 + "1"),
        ]
        cases = [("writes=allowed " + reason, False) for reason in reasons]
        cases.extend([(self.GENESIS_CAPABILITY.replace("allowed", "blocked"), True),
                      (self.GENESIS_CAPABILITY, True)])
        for text, early_blocked in cases:
            with self.subTest(text=text, early_blocked=early_blocked):
                self.setUp()
                self.genesis_fixture(text, early_blocked=early_blocked)
                with self.assertRaisesRegex(AssertionError, "target-genesis-floor"):
                    self.run_main(["--require-target-genesis-floor"])
                self.assert_probe_commands()
                record = self.evidence.summary["measurements"]["ota_preflight"]
                self.assertTrue(record["inspection_complete"])
                self.assertTrue(record["target_genesis_floor_required"])
                self.assertFalse(record["target_genesis_floor_verified"])
                self.assertEqual(record["nodes"]["target"]["capability"]["text"], text)
                check = self.evidence.summary["checks"]["target-genesis-floor"]
                self.assertFalse(check["passed"])
                self.assertEqual(check["writes_allowed"], not text.startswith("writes=blocked"))
                self.assertEqual(check["early_writes_allowed"], not early_blocked)
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
                self.assertIn("target-genesis-floor", self.evidence.finish.call_args.args[0])
                self.client.close.assert_called_once()
                self.target.close.assert_called_once()

    def test_genesis_floor_observation_without_requirement_does_not_assert_commissioning_ready(self):
        self.genesis_fixture(self.GENESIS_CAPABILITY.replace("allowed", "blocked"), early_blocked=True)
        self.run_main()
        self.assert_probe_commands()
        record = self.evidence.summary["measurements"]["ota_preflight"]
        self.assertTrue(record["inspection_complete"])
        self.assertFalse(record["target_genesis_floor_required"])
        self.assertFalse(record["target_genesis_floor_verified"])
        target = record["nodes"]["target"]["capability"]
        self.assertFalse(target["writes_allowed"])
        self.assertEqual(target["floor"]["state"], "present")
        self.assertEqual(target["floor"]["ctr"], 0)
        self.assertNotIn("target-genesis-floor", self.evidence.summary["checks"])

    def test_malformed_floor_probe_retains_raw_evidence_and_cannot_satisfy_genesis_requirement(self):
        text = self.GENESIS_CAPABILITY.replace("seq=00000001 ", "")
        self.genesis_fixture(text)
        with self.assertRaisesRegex(ValueError, "floor tuple"):
            self.run_main(["--require-target-genesis-floor"])
        self.assert_probe_commands()
        record = self.evidence.summary["measurements"]["ota_preflight"]
        self.assertFalse(record["inspection_complete"])
        self.assertFalse(record["target_genesis_floor_verified"])
        target = record["nodes"]["target"]["capability"]
        self.assertEqual(target["text"], text)
        self.assertIn("error", target)
        self.assertEqual(self.evidence.log.call_args.args, ("fatal",))

    def test_genesis_requirement_cannot_bypass_existing_approved_roles_and_actual_identity_checks(self):
        for serial, key in (("49C5BAF21EEF44A1", TARGET_KEY), ("unapproved", TARGET_KEY),
                            ("3BE94917B92DC5E9", TARGET_KEY), ("77CD44653A967172", CLIENT_KEY)):
            with self.subTest(serial=serial, key=key):
                self.setUp()
                self.genesis_fixture()
                self.devices["target"].serial = serial
                if key == CLIENT_KEY:
                    self.target.command.side_effect = ["> repeater", "> " + key.hex()]
                with self.assertRaises(AssertionError):
                    self.run_main(["--require-target-genesis-floor"])
                if serial != "77CD44653A967172":
                    self.client_open.assert_not_called()
                    self.target_open.assert_not_called()
                self.assertFalse(any(call.args[0].startswith("ota ")
                                     for call in self.target.command.call_args_list))

    def test_parser_consumes_frozen_early_formatter_shapes_without_interpreting_proof(self):
        for detail in (
            "proof=not-run", "proof=backend-unavailable", "proof=qspi-layout", "proof=qspi-read",
            "proof=jedec observed=856015", "marker=blank proof=sdk-read sdk=unread",
            "marker=blank proof=crc off=000FE000 bank0=1 bank1=0 size=1024 crc=ABCD/1234 tail=1",
            "marker=corrupt proof=marker off=? bank0=FF bank1=FF size=0 crc=FFFF/? tail=0",
            "marker=qualified proof=qualified-state",
            "marker=qualified proof=qualified-state state=2 phase=3 decision=4",
        ):
            with self.subTest(detail=detail):
                text = f"writes=blocked {detail}"
                parsed = ota_rf_lab.parse_ota_preflight_diagnostic(text, "preflight")
                self.assertEqual(parsed["text"], text)
                self.assertFalse(parsed["writes_allowed"])
                self.assertIn("proof", parsed["early_proof"])
                self.assertNotIn("install_authority", parsed)

    def test_capability_and_actual_latch_are_independent_live_readbacks(self):
        for writes in ("allowed", "blocked"):
            for capability in ("CACHE_ONLY", "CACHE_UNAVAILABLE", "STAGING_ONLY", "INSTALL_CAPABLE"):
                with self.subTest(writes=writes, capability=capability):
                    parsed = ota_rf_lab.parse_ota_preflight_diagnostic(
                        f"writes={writes} {capability}: verified stock boot", "capability")
                    self.assertEqual(parsed["writes_allowed"], writes == "allowed")
                    self.assertEqual(parsed["capability"], capability)
                    self.assertEqual(parsed["reason"], "verified stock boot")

    def test_unknown_lifecycle_missing_reason_and_incomplete_formats_are_refused(self):
        for kind, text in (
            ("preflight", "mode=direct state=0 phase=0 floor=0"),
            ("preflight", "writes=allowed"),
            ("preflight", "writes=maybe proof=qspi-read"),
            ("preflight", "writes=blocked unknown"),
            ("preflight", "writes=blocked proof=unknown"),
            ("preflight", "writes=blocked marker=blank proof=crc off=?"),
            ("preflight", "writes=blocked marker=blank sdk=unread"),
            ("preflight", self.EARLY + "\x00"),
            ("preflight", self.EARLY + "\n"),
            ("preflight", self.EARLY.replace("sdk-read", "sdk-r\u00e9ad")),
            ("capability", "writes=blocked CACHE_UNAVAILABLE: "),
            ("capability", "writes=allowed CACHE_ONLY"),
            ("capability", "writes=allowed UNKNOWN: reason"),
            ("capability", "writes=blocked CACHE_ONLY: " + "x" * 176),
            ("capability", self.EARLY),
            ("unknown", self.CAPABILITY),
        ):
            with self.subTest(kind=kind, text=text):
                with self.assertRaises(ValueError):
                    ota_rf_lab.parse_ota_preflight_diagnostic(text, kind)

    def test_opt_in_pair_probe_is_exact_read_only_and_persists_backend_refusal_without_failing(self):
        self.run_main()
        self.assertEqual(self.resolve.call_args_list, [
            mock.call("client", mode=ota_rf_lab.lab_device.MODE_APP),
            mock.call("target", mode=ota_rf_lab.lab_device.MODE_APP),
        ])
        self.assertEqual(self.client.command.call_args_list, [
            mock.call(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
            mock.call(bytes.fromhex("420001"), expected=(29, 1)),
            mock.call(bytes.fromhex("420002"), expected=(29, 1)),
        ])
        self.assertEqual(self.target.command.call_args_list, [
            mock.call("get role"), mock.call("get public.key"),
            mock.call("ota preflight"), mock.call("ota capability"),
        ])
        record = self.evidence.summary["measurements"]["ota_preflight"]
        self.assertTrue(record["read_only"])
        self.assertTrue(record["inspection_complete"])
        self.assertEqual(record["identities"]["client"]["pubkey"], CLIENT_KEY.hex())
        self.assertEqual(record["identities"]["target"]["pubkey"], TARGET_KEY.hex())
        for role in ("client", "target"):
            early, later = record["nodes"][role]["preflight"], record["nodes"][role]["capability"]
            self.assertEqual(early["text"], self.EARLY)
            self.assertEqual(early["early_proof"], {"marker": "blank", "proof": "sdk-read", "sdk": "unread"})
            self.assertFalse(early["writes_allowed"])
            self.assertEqual(later["capability"], "CACHE_UNAVAILABLE")
            self.assertEqual(later["reason"], "SDK bank0 read failed")
            self.assertFalse(later["writes_allowed"])
        self.assertEqual(record["nodes"]["client"]["preflight"]["request_hex"], "420001")
        self.assertEqual(record["nodes"]["client"]["capability"]["request_hex"], "420002")
        self.assertEqual(record["nodes"]["client"]["preflight"]["response_hex"],
                         (b"\x1d" + self.EARLY.encode("ascii")).hex())
        self.client.get_acl.assert_not_called()
        self.target.get_acl.assert_not_called()
        self.client.close.assert_called_once()
        self.target.close.assert_called_once()
        self.evidence.finish.assert_called_once_with(None)
        self.assertEqual(self.evidence.log.call_args.kwargs["qualification_verified"], False)

    def test_client_only_probe_never_resolves_or_opens_target(self):
        self.run_main(["--client-only"])
        self.resolve.assert_called_once_with("client", mode=ota_rf_lab.lab_device.MODE_APP)
        self.target_open.assert_not_called()
        self.target.command.assert_not_called()
        record = self.evidence.summary["measurements"]["ota_preflight"]
        self.assertEqual(set(record["nodes"]), {"client"})
        self.assertTrue(record["inspection_complete"])
        self.assertEqual(record["scope"], "client_only")
        self.assertFalse(record["target_inspected"])
        self.assertFalse(record["qualification_verified"])
        self.assertFalse(record["target_genesis_floor_verified"])
        self.assertFalse(record["target_boot_addresses_verified"])
        self.assertEqual(self.client.command.call_args_list, [
            mock.call(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
            mock.call(bytes.fromhex("420001"), expected=(29, 1)),
            mock.call(bytes.fromhex("420002"), expected=(29, 1)),
        ])
        self.target.get_acl.assert_not_called()
        self.target.close.assert_not_called()

    def test_legacy_selector_fallback_is_fatal_with_all_raw_readbacks_retained(self):
        legacy = b"\x1dmode=direct state=0 phase=0 floor=0"
        self.client.command.side_effect = [self_info(), legacy, legacy]
        with self.assertRaisesRegex(ValueError, "legacy lifecycle"):
            self.run_main()
        record = self.evidence.summary["measurements"]["ota_preflight"]
        self.assertFalse(record["inspection_complete"])
        self.assertEqual(record["nodes"]["client"]["preflight"]["response_hex"], legacy.hex())
        self.assertEqual(record["nodes"]["client"]["capability"]["response_hex"], legacy.hex())
        self.assertEqual(record["nodes"]["target"]["capability"]["text"], self.CAPABILITY)
        self.assertIn("error", record["nodes"]["client"]["preflight"])
        self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
        self.assertIn("legacy lifecycle", self.evidence.finish.call_args.args[0])
        self.client.close.assert_called_once()
        self.target.close.assert_called_once()

    def test_usb_error_wrong_response_nonascii_or_truncated_diagnostic_is_not_success(self):
        for frame, error in ((b"\x01\x03", RuntimeError), (b"\x56" + self.EARLY.encode(), RuntimeError),
                             (b"", RuntimeError), (b"\x1d", ValueError),
                             (b"\x1d\xff", UnicodeDecodeError),
                             (b"\x1dwrites=blocked marker=blank proof=crc off=?", ValueError)):
            with self.subTest(frame=frame):
                self.setUp()
                self.client.command.side_effect = [self_info(), frame, b"\x1d" + self.CAPABILITY.encode()]
                with self.assertRaises(error):
                    self.run_main()
                record = self.evidence.summary["measurements"]["ota_preflight"]
                self.assertFalse(record["inspection_complete"])
                self.assertEqual(record["nodes"]["client"]["preflight"]["response_hex"], frame.hex())
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
                self.assertIsNotNone(self.evidence.finish.call_args.args[0])

    def test_unapproved_or_pine_serial_refuses_before_either_port_opens(self):
        for role in ("client", "target"):
            for serial in ("unapproved", "49C5BAF21EEF44A1", "3BE94917B92DC5E9"):
                with self.subTest(role=role, serial=serial):
                    self.setUp()
                    self.devices[role].serial = serial
                    with self.assertRaisesRegex(AssertionError, f"approved-active-lab-{role}"):
                        self.run_main()
                    self.client_open.assert_not_called()
                    self.target_open.assert_not_called()
                    self.client.command.assert_not_called()
                    self.target.command.assert_not_called()

    def test_actual_wrong_role_or_duplicate_identity_refuses_before_diagnostic_reads(self):
        for client_frame, target_role, target_key in (
            (self_info(advert_type=2), "> repeater", TARGET_KEY),
            (self_info(), "> room", TARGET_KEY),
            (self_info(), "> repeater", CLIENT_KEY),
        ):
            with self.subTest(target_role=target_role, target_key=target_key):
                self.setUp()
                self.client.command.side_effect = [client_frame]
                self.target.command.side_effect = [target_role, "> " + target_key.hex()]
                with self.assertRaises((RuntimeError, AssertionError)):
                    self.run_main()
                self.assertEqual(self.client.command.call_count, 1)
                self.assertFalse(any(call.args[0].startswith("ota ")
                                     for call in self.target.command.call_args_list))


class ConfigurationInspectionTests(unittest.TestCase):
    def setUp(self):
        self.evidence = evidence_fixture()
        self.evidence.finish = mock.Mock()
        self.client = mock.Mock()
        self.client.name = "client"
        self.client.command.side_effect = [
            self_info("observed-client", radio=(869525, 125000, 8, 6)), device_info(1),
        ]
        self.target = ota_rf_lab.RepeaterSerial.__new__(ota_rf_lab.RepeaterSerial)
        self.target.name = "target"
        self.target.evidence = self.evidence
        self.target.buffer = bytearray()
        self.target.pending = []
        self.target.command = mock.Mock(side_effect=[
            "> repeater", "> " + TARGET_KEY.hex(), "> observed-target",
            "> 907.5250244,250,7,5", "> 2",
        ])
        self.target._write_bytes = mock.Mock()
        self.target.close = mock.Mock()
        self.target.get_acl = mock.Mock(wraps=self.target.get_acl)
        self.acl = {CLIENT_KEY.hex(): 3, "ab" * 32: 0x83, "cd" * 32: 2}
        self.now = 0.0
        self.acl_batches(self.acl)

        def poll(duration=0):
            self.now += max(duration, 0.01)
            self.target.pending.extend(next(self.batches, []))

        self.target.poll = mock.Mock(side_effect=poll)
        self.devices = {
            role: mock.Mock(serial=serial, by_id=f"/dev/serial/by-id/{role}")
            for role, serial in ota_rf_lab.APPROVED_ADMIN_PAIR.items()
        }

    def acl_batches(self, acl):
        self.batches = iter([
            [], ["get acl", "ACL:", *(f"{permission:02X} {key}" for key, permission in acl.items())],
            ["get role", "  -> > repeater"],
        ])

    def run_main(self, options=()):
        arguments = ["ota_rf_lab.py", "--artifact-dir", "unused", "--inspect-configuration", *options]
        with mock.patch.object(sys, "argv", arguments), \
                mock.patch.object(ota_rf_lab, "Evidence", return_value=self.evidence), \
                mock.patch.object(ota_rf_lab.lab_device, "resolve") as resolve, \
                mock.patch.object(ota_rf_lab, "FramedSerial", return_value=self.client) as client_open, \
                mock.patch.object(ota_rf_lab, "RepeaterSerial", return_value=self.target) as target_open, \
                mock.patch.object(ota_rf_lab, "run_configure") as configure, \
                mock.patch.object(ota_rf_lab, "run_grant_client_admin") as grant, \
                mock.patch.object(ota_rf_lab.time, "sleep") as sleep, \
                mock.patch.object(ota_rf_lab.time, "monotonic", side_effect=lambda: self.now):
            self.resolve, self.client_open, self.target_open = resolve, client_open, target_open
            self.configure, self.grant, self.sleep = configure, grant, sleep
            resolve.side_effect = lambda role, mode: self.devices[role]
            ota_rf_lab.main()

    def assert_read_only_commands(self):
        self.assertEqual(self.client.command.call_args_list, [
            mock.call(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
            mock.call(b"\x16\x0d", expected=(13,)),
        ])
        self.assertEqual(self.target.command.call_args_list, [
            mock.call("get role"), mock.call("get public.key"), mock.call("get name"),
            mock.call("get radio"), mock.call("get path.hash.mode"),
        ])
        self.target.get_acl.assert_called_once_with()
        self.assertEqual(self.target._write_bytes.call_args_list,
                         [mock.call(b"get acl\r"), mock.call(b"get role\r")])
        self.configure.assert_not_called()
        self.grant.assert_not_called()
        self.sleep.assert_called_once_with(2.0)

    def test_inspection_records_arbitrary_valid_settings_full_acl_and_only_normal_reads(self):
        self.run_main()
        self.assert_read_only_commands()
        self.assertEqual(self.resolve.call_args_list, [
            mock.call("client", mode=ota_rf_lab.lab_device.MODE_APP),
            mock.call("target", mode=ota_rf_lab.lab_device.MODE_APP),
        ])
        record = self.evidence.summary["measurements"]["configuration_inspection"]
        self.assertTrue(record["read_only"])
        self.assertTrue(record["inspection_complete"])
        self.assertTrue(record["acl_complete"])
        self.assertFalse(record["reboot_requested"])
        self.assertFalse(record["reboot_persistence_verified"])
        self.assertEqual(record["raw_serial_events"], "serial-events.jsonl")
        self.assertEqual(record["acl"], self.acl)
        self.assertEqual(record["client_permission"], 3)
        client, target = record["nodes"]["client"], record["nodes"]["target"]
        self.assertEqual(client["role"], "companion")
        self.assertEqual(target["role"], "repeater")
        self.assertEqual(client["pubkey"], CLIENT_KEY.hex())
        self.assertEqual(target["pubkey"], TARGET_KEY.hex())
        self.assertNotIn("pubkey_bytes", client)
        self.assertEqual(client["name"], "observed-client")
        self.assertEqual(target["name"], "observed-target")
        self.assertEqual(tuple(client[key] for key in ("freq_khz", "bw_hz", "sf", "cr")),
                         (869525, 125000, 8, 6))
        self.assertEqual(tuple(target[key] for key in ("freq_khz", "bw_hz", "sf", "cr")),
                         (907525, 250000, 7, 5))
        self.assertEqual(client["path_hash_mode"], 1)
        self.assertEqual(target["path_hash_mode"], 2)
        self.assertEqual(target["settings_readback_scope"], "preferences")
        self.assertNotIn("configuration_expected_radio", self.evidence.summary["measurements"])
        self.assertNotIn("default-radio-client", self.evidence.summary["checks"])
        self.client.close.assert_called_once()
        self.target.close.assert_called_once()
        self.evidence.finish.assert_called_once_with(None)
        self.evidence.log.assert_called_with("configuration_inspection_complete", **record)

    def test_missing_or_nonadmin_permission_is_observed_without_auto_grant_or_repair(self):
        for acl, permission in (({}, None), ({"ab" * 32: 0x83}, None), ({CLIENT_KEY.hex(): 1}, 1)):
            with self.subTest(acl=acl):
                self.setUp()
                self.acl_batches(acl)
                self.run_main()
                self.assert_read_only_commands()
                record = self.evidence.summary["measurements"]["configuration_inspection"]
                self.assertEqual(record["acl"], acl)
                self.assertEqual(record["client_permission"], permission)
                self.assertTrue(record["acl_complete"])
                self.assertTrue(record["inspection_complete"])
                self.assertFalse(record["reboot_persistence_verified"])

    def test_incomplete_or_malformed_acl_is_fatal_with_nodes_retained_and_no_success_flag(self):
        for batches, error in (
            ([[], ["get acl", "ACL:", f"03 {CLIENT_KEY.hex()}"]], TimeoutError),
            ([[], ["get acl", "ACL:", "03 bad-key"]], ValueError),
            ([[], ["get acl", "ACL:", f"03 {CLIENT_KEY.hex()}", f"01 {CLIENT_KEY.hex()}"]], ValueError),
        ):
            with self.subTest(batches=batches):
                self.setUp()
                self.batches = iter(batches)
                with self.assertRaises(error):
                    self.run_main()
                record = self.evidence.summary["measurements"]["configuration_inspection"]
                self.assertEqual(set(record["nodes"]), {"client", "target"})
                self.assertFalse(record["acl_complete"])
                self.assertFalse(record["inspection_complete"])
                self.assertNotIn("acl", record)
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))
                self.assertIsNotNone(self.evidence.finish.call_args.args[0])
                self.client.close.assert_called_once()
                self.target.close.assert_called_once()
                self.grant.assert_not_called()
                self.configure.assert_not_called()

    def test_malformed_settings_stop_inspection_without_acl_reads_or_configuration_fallback(self):
        for role in ("client", "target"):
            with self.subTest(role=role):
                self.setUp()
                if role == "client":
                    self.client.command.side_effect = [self_info(), device_info()[:81]]
                else:
                    self.target.command.side_effect = [
                        "> repeater", "> " + TARGET_KEY.hex(), "> observed-target",
                        "> 907.5250243,250,7,5",
                    ]
                with self.assertRaises((RuntimeError, ValueError)):
                    self.run_main()
                record = self.evidence.summary["measurements"]["configuration_inspection"]
                self.assertFalse(record["inspection_complete"])
                self.assertFalse(record["acl_complete"])
                self.assertEqual(set(record["nodes"]), set() if role == "client" else {"client"})
                self.target.get_acl.assert_not_called()
                self.target._write_bytes.assert_not_called()
                self.grant.assert_not_called()
                self.configure.assert_not_called()
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))

    def test_wrong_actual_roles_invalid_or_duplicate_identity_refuse_before_acl(self):
        for client_frame, target_role, key in (
            (self_info(advert_type=2), "> repeater", TARGET_KEY.hex()),
            (self_info(public_key=bytes(32)), "> repeater", TARGET_KEY.hex()),
            (self_info(), "> room", TARGET_KEY.hex()),
            (self_info(), "> repeater", "00" * 32),
            (self_info(), "> repeater", CLIENT_KEY.hex()),
        ):
            with self.subTest(target_role=target_role, key=key):
                self.setUp()
                self.client.command.side_effect = [client_frame, device_info()]
                self.target.command.side_effect = [
                    target_role, "> " + key, "> observed-target", "> 907.5250244,250,7,5", "> 2",
                ]
                with self.assertRaises((RuntimeError, AssertionError)):
                    self.run_main()
                self.target.get_acl.assert_not_called()
                self.target._write_bytes.assert_not_called()
                self.assertFalse(self.evidence.summary["measurements"]["configuration_inspection"]["inspection_complete"])
                self.grant.assert_not_called()
                self.configure.assert_not_called()

    def test_unapproved_swapped_or_pine_usb_serial_refuses_before_either_port_opens(self):
        for role, serial in (("client", "unapproved"), ("target", "unapproved"),
                             ("client", "77CD44653A967172"), ("target", "4186AE911D94CDB1"),
                             ("target", "3BE94917B92DC5E9"),
                             ("client", "49C5BAF21EEF44A1"), ("target", "49C5BAF21EEF44A1")):
            with self.subTest(role=role, serial=serial):
                self.setUp()
                self.devices[role].serial = serial
                with self.assertRaises(AssertionError):
                    self.run_main()
                self.client_open.assert_not_called()
                self.target_open.assert_not_called()
                self.client.command.assert_not_called()
                self.target.command.assert_not_called()
                self.assertEqual(self.evidence.log.call_args.args, ("fatal",))

    def test_role_override_cannot_redirect_configuration_inspection(self):
        with mock.patch.object(ota_rf_lab, "TARGET_ROLE", "pine"):
            with self.assertRaisesRegex(AssertionError, "approved-configuration-inspection-roles"):
                self.run_main()
        self.resolve.assert_not_called()
        self.client_open.assert_not_called()
        self.target_open.assert_not_called()

    def test_client_only_configuration_uses_real_companion_reads_without_target_or_acl_claims(self):
        del self.devices["target"]
        self.run_main(["--client-only"])
        self.resolve.assert_called_once_with("client", mode=ota_rf_lab.lab_device.MODE_APP)
        self.client_open.assert_called_once()
        self.target_open.assert_not_called()
        self.target.command.assert_not_called()
        self.target.get_acl.assert_not_called()
        self.target._write_bytes.assert_not_called()
        self.target.close.assert_not_called()
        self.assertEqual(self.client.command.call_args_list, [
            mock.call(b"\x01" + bytes(7) + b"ota-rf-lab", expected=(5,)),
            mock.call(b"\x16\x0d", expected=(13,)),
        ])
        record = self.evidence.summary["measurements"]["configuration_inspection"]
        self.assertEqual(record["scope"], "client_only")
        self.assertEqual(set(record["nodes"]), {"client"})
        self.assertTrue(record["read_only"])
        self.assertTrue(record["inspection_complete"])
        for field in ("target_inspected", "target_acl_inspected", "acl_complete",
                      "qualification_verified", "reboot_requested", "reboot_persistence_verified"):
            self.assertFalse(record[field])
        self.assertNotIn("acl", record)
        self.assertNotIn("client_permission", record)
        observed = record["nodes"]["client"]
        self.assertEqual(observed["pubkey"], CLIENT_KEY.hex())
        self.assertNotIn("pubkey_bytes", observed)
        self.assertEqual(observed["name"], "observed-client")
        self.assertEqual(observed["path_hash_mode"], 1)
        self.assertEqual(tuple(observed[key] for key in ("freq_khz", "bw_hz", "sf", "cr")),
                         (869525, 125000, 8, 6))
        self.configure.assert_not_called()
        self.grant.assert_not_called()
        self.client.close.assert_called_once()
        self.evidence.finish.assert_called_once_with(None)

    def test_client_only_configuration_refuses_other_usb_sources_and_role_overrides_before_open(self):
        for serial in ("49C5BAF21EEF44A1", "77CD44653A967172", "3BE94917B92DC5E9", "unapproved"):
            with self.subTest(serial=serial):
                self.setUp()
                self.devices["client"].serial = serial
                with self.assertRaises(AssertionError):
                    self.run_main(["--client-only"])
                self.client_open.assert_not_called()
                self.target_open.assert_not_called()
                self.client.command.assert_not_called()
        with mock.patch.object(ota_rf_lab, "CLIENT_ROLE", "target"):
            with self.assertRaises(AssertionError):
                self.run_main(["--client-only"])
            self.resolve.assert_not_called()
            self.client_open.assert_not_called()
            self.target_open.assert_not_called()

    def test_client_only_bad_role_key_or_settings_are_fatal_without_success_claim(self):
        for frames in ([self_info(advert_type=2)], [self_info(public_key=bytes(32))],
                       [self_info(), device_info()[:81]]):
            with self.subTest(frames=frames):
                self.setUp()
                self.client.command.side_effect = frames
                with self.assertRaises((RuntimeError, ValueError)):
                    self.run_main(["--client-only"])
                record = self.evidence.summary["measurements"]["configuration_inspection"]
                self.assertFalse(record["inspection_complete"])
                self.assertFalse(record["acl_complete"])
                self.assertFalse(record["target_inspected"])
                self.target_open.assert_not_called()
                self.grant.assert_not_called()
                self.configure.assert_not_called()
                self.client.close.assert_called_once()
                self.assertIsNotNone(self.evidence.finish.call_args.args[0])

    def test_client_only_inspections_refuse_existing_evidence_before_resolution_or_open(self):
        for scope in ("--inspect-configuration", "--inspect-ota-preflight"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
                marker = pathlib.Path(parent) / "preserve.txt"
                marker.write_text("untouched")
                arguments = ["ota_rf_lab.py", "--artifact-dir", parent, "--client-only", scope]
                with mock.patch.object(sys, "argv", arguments), \
                        mock.patch.object(ota_rf_lab.lab_device, "resolve") as resolve, \
                        mock.patch.object(ota_rf_lab, "FramedSerial") as client_open, \
                        mock.patch.object(ota_rf_lab, "RepeaterSerial") as target_open:
                    with self.assertRaises(FileExistsError):
                        ota_rf_lab.main()
                    resolve.assert_not_called()
                    client_open.assert_not_called()
                    target_open.assert_not_called()
                self.assertEqual(marker.read_text(), "untouched")
                self.assertEqual(list(pathlib.Path(parent).iterdir()), [marker])


class ActivePairResolverTests(unittest.TestCase):
    def test_all_operational_pair_resolvers_use_literal_replacement_contract(self):
        expected = {"client": "4186AE911D94CDB1", "target": "77CD44653A967172"}
        self.assertEqual(ota_rf_lab.APPROVED_ADMIN_PAIR, expected)
        devices = {role: mock.Mock(serial=serial, by_id=f"/dev/serial/by-id/{serial}")
                   for role, serial in expected.items()}
        for resolver in (ota_rf_lab.resolve_roles, ota_rf_lab.resolve_admin_grant_roles,
                         ota_rf_lab.resolve_preflight_roles, ota_rf_lab.resolve_configuration_inspection_roles):
            with self.subTest(resolver=resolver.__name__), \
                    mock.patch.object(ota_rf_lab.lab_device, "resolve",
                                      side_effect=lambda role, mode: devices[role]) as resolve:
                self.assertEqual(resolver(evidence_fixture()), devices)
                self.assertEqual(resolve.call_args_list, [
                    mock.call("client", mode=ota_rf_lab.lab_device.MODE_APP),
                    mock.call("target", mode=ota_rf_lab.lab_device.MODE_APP),
                ])

    def test_failed_target_and_pine_are_refused_by_every_operational_resolver(self):
        for serial in ("3BE94917B92DC5E9", "49C5BAF21EEF44A1"):
            for resolver in (ota_rf_lab.resolve_roles, ota_rf_lab.resolve_admin_grant_roles,
                             ota_rf_lab.resolve_preflight_roles, ota_rf_lab.resolve_configuration_inspection_roles):
                with self.subTest(serial=serial, resolver=resolver.__name__):
                    devices = {
                        "client": mock.Mock(serial="4186AE911D94CDB1", by_id="/dev/serial/by-id/client"),
                        "target": mock.Mock(serial=serial, by_id="/dev/serial/by-id/denied"),
                    }
                    with mock.patch.object(ota_rf_lab.lab_device, "resolve",
                                           side_effect=lambda role, mode: devices[role]), \
                            mock.patch.object(ota_rf_lab, "FramedSerial") as client, \
                            mock.patch.object(ota_rf_lab, "RepeaterSerial") as target:
                        with self.assertRaises(AssertionError):
                            resolver(evidence_fixture())
                        client.assert_not_called()
                        target.assert_not_called()

    def test_client_only_resolution_never_resolves_replacement_recovery_or_pine_roles(self):
        device = mock.Mock(serial="4186AE911D94CDB1", by_id="/dev/serial/by-id/client")
        for resolver in (ota_rf_lab.resolve_roles, ota_rf_lab.resolve_preflight_roles):
            for target_role in ("target", "recovery", "pine"):
                with self.subTest(resolver=resolver.__name__, target_role=target_role), \
                        mock.patch.object(ota_rf_lab, "TARGET_ROLE", target_role), \
                        mock.patch.object(ota_rf_lab.lab_device, "resolve", return_value=device) as resolve:
                    self.assertEqual(resolver(evidence_fixture(), client_only=True), {"client": device})
                    resolve.assert_called_once_with("client", mode=ota_rf_lab.lab_device.MODE_APP)


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


class ChannelResponseRedactionTests(unittest.TestCase):
    def setUp(self):
        self.node = ota_rf_lab.FramedSerial.__new__(ota_rf_lab.FramedSerial)
        self.node.name = "client"
        self.node.buffer = bytearray()
        self.node.pending = []
        self.node.evidence = evidence_fixture()

    def receive(self, payload, split=None):
        wire = b">" + struct.pack("<H", len(payload)) + payload
        chunks = [wire] if split is None else [wire[:split], wire[split:]]
        self.node._read_bytes = mock.Mock(side_effect=chunks)
        for _ in chunks:
            self.node.poll()
        return self.node.pending[-1][1]

    def assert_no_secret(self, value):
        text = str(value)
        self.assertNotIn(CHANNEL_SECRET_CANARY.decode(), text)
        self.assertNotIn(CHANNEL_SECRET_CANARY.hex(), text)

    def test_every_fragment_boundary_redacts_before_logging_and_keeps_protocol_frame_usable(self):
        payload = channel_info(7, "#ota-lab")
        for split in range(1, len(payload) + 3):
            with self.subTest(split=split):
                self.setUp()
                self.assertEqual(self.receive(payload, split), payload)
                self.node.evidence.log.assert_called_once_with(
                    "serial_rx", node="client", length=50, code=18, redacted=True,
                    index=7, name="#ota-lab", configured=True)
                self.assert_no_secret(self.node.evidence.log.call_args_list)
                self.node._read_bytes = mock.Mock(return_value=b"")
                self.assertEqual(self.node.wait_frame({18}), payload)
                self.assertEqual(ota_rf_lab.public_channel_info(payload),
                                 {"index": 7, "name": "#ota-lab", "configured": True})

    def test_malformed_channel_lengths_never_log_hex_name_index_or_secret(self):
        for length in (1, 2, 17, 33, 34, 49, 51, 176, 200):
            with self.subTest(length=length):
                self.setUp()
                payload = (b"\x12" + CHANNEL_SECRET_CANARY * 13)[:length]
                self.assertEqual(self.receive(payload, split=4), payload)
                self.node.evidence.log.assert_called_once_with(
                    "serial_rx", node="client", length=length, code=18,
                    redacted=True, malformed=True)
                self.assert_no_secret(self.node.evidence.log.call_args_list)
                with self.assertRaisesRegex(ValueError, "malformed channel response") as error:
                    ota_rf_lab.public_channel_info(payload)
                self.assert_no_secret(repr(error.exception))

    def test_invalid_channel_names_and_reserved_index_are_redacted_and_fail_plainly(self):
        for payload in (
            bytes([18, 1]) + b"x" * 32 + CHANNEL_SECRET_CANARY,
            bytes([18, 1]) + b"\xff\x00".ljust(32, b"\x00") + CHANNEL_SECRET_CANARY,
            channel_info(1, "bad\nname"), channel_info(255, "#invalid"),
        ):
            with self.subTest(length=len(payload)):
                self.setUp()
                self.receive(payload)
                self.assertEqual(self.node.evidence.log.call_args.kwargs,
                                 {"node": "client", "length": 50, "code": 18,
                                  "redacted": True, "malformed": True})
                with self.assertRaises(ValueError) as error:
                    ota_rf_lab.public_channel_info(payload)
                self.assert_no_secret(repr(error.exception))
                self.assert_no_secret(self.node.evidence.log.call_args_list)

    def test_stale_bytes_after_name_nul_are_not_logged_or_mistaken_for_padding(self):
        payload = bytes([18, 9]) + (b"#ok\x00" + CHANNEL_SECRET_CANARY).ljust(32, b"\xff")
        payload += CHANNEL_SECRET_CANARY
        self.receive(payload)
        self.assertEqual(ota_rf_lab.public_channel_info(payload),
                         {"index": 9, "name": "#ok", "configured": True})
        self.assert_no_secret(self.node.evidence.log.call_args_list)

    def test_ordinary_frames_remain_byte_for_byte_in_logs_and_pending(self):
        for payload in (b"\x80" + CLIENT_KEY, b"\x01\x07", b"", self_info(), device_info()):
            with self.subTest(code=payload[:1]):
                self.setUp()
                self.assertEqual(self.receive(payload), payload)
                self.node.evidence.log.assert_called_once_with(
                    "serial_rx", node="client", length=len(payload),
                    code=payload[0] if payload else None, hex=payload.hex())


class ChannelInventoryTests(unittest.TestCase):
    def setUp(self):
        self.node = ota_rf_lab.FramedSerial.__new__(ota_rf_lab.FramedSerial)
        self.node.name = "client"
        self.node.fd = None
        self.node.buffer = bytearray()
        self.node.pending = []
        self.requests = []
        self.chunks = []
        self.reply_info = self_info()
        self.reply_device = device_info()
        self.channel_overrides = {}
        self.devices = {
            "client": mock.Mock(serial="4186AE911D94CDB1", by_id="/dev/serial/by-id/client"),
        }

        def write(wire):
            request = wire[3:]
            self.assertEqual(wire[:3], b"<" + struct.pack("<H", len(request)))
            self.requests.append(request)
            if request == b"\x01" + bytes(7) + b"ota-rf-lab":
                response = self.reply_info
            elif request == b"\x16\x0d":
                response = self.reply_device
            elif len(request) == 2 and request[0] == 31:
                index = request[1]
                self.assertLess(index, self.reply_device[3])
                response = self.channel_overrides.get(
                    index, channel_info(index, "#ota-lab" if index == 7 else ""))
                if isinstance(response, Exception):
                    raise response
            else:
                raise AssertionError(f"unexpected write command {request[:1].hex()}")
            framed = b">" + struct.pack("<H", len(response)) + response
            self.chunks.extend(framed[offset:offset + 7] for offset in range(0, len(framed), 7))

        self.node._write_bytes = write
        self.node._read_bytes = lambda timeout: self.chunks.pop(0) if self.chunks else b""

    def run_main(self, directory, extra=(), resolver=None):
        args = ["ota_rf_lab.py", "--artifact-dir", str(directory), "--inspect-channels", *extra]
        self.output = io.StringIO()
        with mock.patch.object(sys, "argv", args), \
                mock.patch.object(ota_rf_lab.lab_device, "resolve") as resolve, \
                mock.patch.object(ota_rf_lab, "FramedSerial", return_value=self.node) as client, \
                mock.patch.object(ota_rf_lab, "RepeaterSerial") as target, \
                mock.patch.object(ota_rf_lab.time, "sleep"), \
                contextlib.redirect_stdout(self.output):
            self.resolve, self.client_open, self.target_open = resolve, client, target
            resolve.side_effect = (resolver if resolver is not None
                                   else lambda role, mode: self.devices[role])
            def open_client(name, path, evidence):
                self.node.name = name
                self.node.evidence = evidence
                return self.node
            client.side_effect = open_client
            ota_rf_lab.main()

    def assert_secret_absent(self, directory, exception=None):
        text = self.output.getvalue() + repr(exception)
        text += "".join(path.read_text() for path in directory.iterdir())
        self.assertNotIn(CHANNEL_SECRET_CANARY.decode(), text)
        self.assertNotIn(CHANNEL_SECRET_CANARY.hex(), text)

    def record(self, directory):
        return json.loads((directory / "summary.json").read_text())["measurements"]["channel_inventory"]

    def test_actual_wire_inventory_reads_all_40_slots_only_and_discards_secrets(self):
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
            directory = pathlib.Path(parent) / "inventory"
            self.channel_overrides[39] = channel_info(39, "#last")
            self.run_main(directory)
            self.resolve.assert_called_once_with("client", mode=ota_rf_lab.lab_device.MODE_APP)
            self.client_open.assert_called_once_with("client-4186AE911D94CDB1",
                                                    "/dev/serial/by-id/client", self.node.evidence)
            self.target_open.assert_not_called()
            record = self.record(directory)
            self.assertEqual(record["capacity"], 40)
            self.assertEqual(record["configured_indices"], [7, 39])
            self.assertEqual(len(record["channels"]), 40)
            self.assertEqual(record["channels"][0], {"index": 0, "name": "", "configured": False})
            self.assertEqual(record["channels"][7],
                             {"index": 7, "name": "#ota-lab", "configured": True})
            self.assertTrue(record["inspection_complete"])
            self.assertTrue(record["read_only"])
            self.assertFalse(record["receiver_membership_verified"])
            self.assertEqual(record["client"]["pubkey"], CLIENT_KEY.hex())
            self.assertNotIn("pubkey_bytes", record["client"])
            self.assertEqual(self.requests, [b"\x01" + bytes(7) + b"ota-rf-lab", b"\x16\x0d"]
                             + [bytes([31, index]) for index in range(40)])
            self.assertEqual(self.node.pending, [])
            self.assert_secret_absent(directory)

    def test_advertised_capacity_is_used_instead_of_fixed_40_or_255(self):
        for capacity in (1, 3, 255):
            with self.subTest(capacity=capacity), tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
                self.setUp()
                self.reply_device = device_info(capacity=capacity)
                directory = pathlib.Path(parent) / "inventory"
                self.run_main(directory, ["--client-only"])
                self.assertEqual(self.requests[2:], [bytes([31, i]) for i in range(capacity)])
                self.assertEqual(len(self.record(directory)["channels"]), capacity)
                self.target_open.assert_not_called()
                self.assert_secret_absent(directory)

    def test_complete_empty_table_has_no_configured_indices_or_receiver_claim(self):
        self.reply_device = device_info(capacity=2)
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
            directory = pathlib.Path(parent) / "inventory"
            self.run_main(directory)
            record = self.record(directory)
            self.assertTrue(record["inspection_complete"])
            self.assertEqual(record["configured_indices"], [])
            self.assertFalse(any(row["configured"] for row in record["channels"]))
            self.assertFalse(record["receiver_membership_verified"])

    def test_existing_artifact_directory_is_refused_before_resolution_or_open(self):
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
            directory = pathlib.Path(parent)
            marker = directory / "preserve.txt"
            marker.write_text("untouched")
            with self.assertRaises(FileExistsError):
                self.run_main(directory)
            self.resolve.assert_not_called()
            self.client_open.assert_not_called()
            self.target_open.assert_not_called()
            self.assertEqual(marker.read_text(), "untouched")
            self.assertEqual(list(directory.iterdir()), [marker])

    def test_unapproved_pine_or_target_source_serial_never_opens_any_port(self):
        for serial in ("49C5BAF21EEF44A1", "77CD44653A967172", "3BE94917B92DC5E9", "unapproved"):
            with self.subTest(serial=serial), tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
                self.setUp()
                self.devices["client"].serial = serial
                directory = pathlib.Path(parent) / "inventory"
                with self.assertRaises(AssertionError):
                    self.run_main(directory)
                self.client_open.assert_not_called()
                self.target_open.assert_not_called()
                self.assertEqual(self.requests, [])

    def test_client_role_remapping_is_refused_before_resolution_and_queries(self):
        for role in ("target", "pine", "alternate"):
            with self.subTest(role=role), tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
                with mock.patch.object(ota_rf_lab, "CLIENT_ROLE", role):
                    with self.assertRaises(AssertionError):
                        self.run_main(pathlib.Path(parent) / "inventory")
                self.resolve.assert_not_called()
                self.client_open.assert_not_called()
                self.target_open.assert_not_called()
                self.assertEqual(self.requests, [])

    def test_protected_source_resolver_refusal_is_fatal_before_open(self):
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
            directory = pathlib.Path(parent) / "inventory"
            with mock.patch.object(ota_rf_lab, "resolve_roles",
                                   side_effect=SystemExit("refusing protected lab device assignment")):
                with self.assertRaisesRegex(SystemExit, "protected"):
                    self.run_main(directory)
            self.client_open.assert_not_called()
            self.target_open.assert_not_called()
            self.assertEqual(self.requests, [])
            self.assertIn("protected", (directory / "summary.json").read_text())

    def test_real_protected_inventory_guard_blocks_override_before_discovery_or_open(self):
        actual_resolve = ota_rf_lab.lab_device.resolve
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
            directory = pathlib.Path(parent) / "inventory"
            config = pathlib.Path(parent) / "devices.ini"
            config.write_text("[roles]\nclient = 4186AE911D94CDB1\n"
                              "[protected]\npine = 49C5BAF21EEF44A1\n")
            with mock.patch.object(ota_rf_lab.lab_device, "CONFIG_PATH", config), \
                    mock.patch.dict(ota_rf_lab.os.environ,
                                    {"MESHCORE_LAB_CLIENT_SERIAL": "49C5BAF21EEF44A1"}), \
                    mock.patch.object(ota_rf_lab.lab_device, "discover") as discover:
                with self.assertRaisesRegex(SystemExit, "refusing protected lab device assignment"):
                    self.run_main(directory, resolver=actual_resolve)
                discover.assert_not_called()
            self.client_open.assert_not_called()
            self.target_open.assert_not_called()
            self.assertEqual(self.requests, [])

    def test_companion_role_and_identity_are_checked_before_capacity_or_channel_queries(self):
        for response in (self_info(advert_type=2), self_info(public_key=bytes(32)), self_info()[:57]):
            with self.subTest(response_length=len(response)), \
                    tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
                self.setUp()
                self.reply_info = response
                with self.assertRaises(RuntimeError):
                    self.run_main(pathlib.Path(parent) / "inventory")
                self.assertEqual(len(self.requests), 1)
                self.target_open.assert_not_called()

    def test_capacity_backend_refusals_and_malformed_partial_or_zero_responses_stop_before_reads(self):
        for response, error in (
            (b"\x01\x07", RuntimeError), (device_info(capacity=0), RuntimeError),
            (device_info(version=2), ValueError), (device_info()[:4], ValueError),
            (device_info()[:79], ValueError), (device_info()[:80], ValueError),
            (device_info()[:81], ValueError),
        ):
            with self.subTest(response_length=len(response)), \
                    tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
                self.setUp()
                self.reply_device = response
                directory = pathlib.Path(parent) / "inventory"
                with self.assertRaises(error):
                    self.run_main(directory)
                self.assertEqual(len(self.requests), 2)
                self.assertFalse(self.record(directory)["inspection_complete"])

    def test_partial_failed_inventory_retains_only_public_progress_and_plain_error(self):
        for response, error in (
            (b"\x01\x07", RuntimeError), (b"\x12" + CHANNEL_SECRET_CANARY, ValueError),
            (channel_info(8, "#wrong"), ValueError), (channel_info(1, "bad\nname"), ValueError),
            (ConnectionError("client: serial disconnected"), ConnectionError),
        ):
            with self.subTest(error=error), tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
                self.setUp()
                self.channel_overrides[1] = response
                directory = pathlib.Path(parent) / "inventory"
                with self.assertRaises(error) as raised:
                    self.run_main(directory)
                record = self.record(directory)
                self.assertFalse(record["inspection_complete"])
                self.assertEqual(record["channels"], [{"index": 0, "name": "", "configured": False}])
                self.assertEqual(self.requests[-1], b"\x1f\x01")
                self.assertEqual(len(self.requests), 4)
                self.assert_secret_absent(directory, raised.exception)
                self.target_open.assert_not_called()


class OtaMeasurementDiagnosticsTests(unittest.TestCase):
    RADIO = ("src=driver-applied f=907525 b=250000 s=7 c=5 v=1 a=0 e=00000000 "
             "d=00000002 r=00000002 td=00010000 tr=00018000 h=1 x=00000000 af=00000000 n=00020000")
    BUDGET = "n=00020000 w=0036EE80 b=00011940 u=0000002A tx=00000100 to=00000000 af=00000000"

    def test_literal_radio_contract_parses_exact_fields_units_and_initial_normal_application(self):
        result = ota_rf_lab.parse_ota_radio_measurement(self.RADIO)
        self.assertEqual(result, {"src": "driver-applied", "f": 907525, "b": 250000, "s": 7, "c": 5,
            "v": 1, "a": 0, "e": 0, "d": 2, "r": 2, "td": 65536, "tr": 98304,
            "h": 1, "x": 0, "af": 0, "n": 131072})
        initial = self.RADIO.replace("d=00000002 r=00000002", "d=00000000 r=00000000")
        self.assertEqual(ota_rf_lab.parse_ota_radio_measurement(initial)["r"], 0)

    def test_literal_budget_contract_has_actual_completed_ms_and_uint32_counters(self):
        self.assertEqual(ota_rf_lab.parse_ota_budget_measurement(self.BUDGET),
                         {"n": 131072, "w": 3600000, "b": 72000, "u": 42, "tx": 256, "to": 0, "af": 0})
        highest = " ".join(f"{field}=FFFFFFFF" for field in ota_rf_lab.BUDGET_MEASUREMENT_FIELDS)
        self.assertTrue(all(value == 0xFFFFFFFF
                            for value in ota_rf_lab.parse_ota_budget_measurement(highest).values()))

    def test_radio_parser_rejects_every_truncation_duplicate_extra_and_out_of_order_key(self):
        for text in (
            *(self.RADIO[:i] for i in range(len(self.RADIO))),
            self.RADIO + " n=00020000", self.RADIO + " extra=1", self.RADIO + "\x00",
            self.RADIO + "\n", " " + self.RADIO, self.RADIO.replace("src=driver-applied", "src=preferences"),
            self.RADIO.replace("f=907525 b=250000", "b=250000 f=907525"),
            self.RADIO.replace("x=00000000", "x=0000000a"),
            self.RADIO.replace("v=1", "v=2"), self.RADIO.replace("a=0", "a=-1"),
            self.RADIO.replace("f=907525", "f=907525.0"), self.RADIO.replace("s=7", "s=07"),
            self.RADIO.replace("n=00020000", "n=100020000"),
        ):
            with self.subTest(length=len(text)), self.assertRaises(ValueError):
                ota_rf_lab.parse_ota_radio_measurement(text)

    def test_radio_range_guards_do_not_accept_unknown_phy_values(self):
        for field, bad in (("f", "149999"), ("f", "2500001"), ("b", "249999"),
                           ("s", "4"), ("s", "13"), ("c", "4"), ("c", "9")):
            old = next(token for token in self.RADIO.split() if token.startswith(field + "="))
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                ota_rf_lab.parse_ota_radio_measurement(self.RADIO.replace(old, f"{field}={bad}"))

    def test_budget_parser_rejects_missing_duplicate_reordered_noncanonical_and_extra_fields(self):
        for text in (
            *(self.BUDGET[:i] for i in range(len(self.BUDGET))),
            self.BUDGET + " af=00000000", self.BUDGET + " f=907525", self.BUDGET + "\x00",
            self.BUDGET.replace("u=0000002A", "u=0000002a"),
            self.BUDGET.replace("w=0036EE80 b=00011940", "b=00011940 w=0036EE80"),
            self.BUDGET.replace("tx=00000100", "tx=256"), self.BUDGET + "\n",
        ):
            with self.subTest(length=len(text)), self.assertRaises(ValueError):
                ota_rf_lab.parse_ota_budget_measurement(text)

    def test_read_only_parsers_faithfully_report_unhealthy_and_uninitialized_measurements(self):
        unhealthy = self.RADIO.replace("v=1", "v=0").replace("h=1", "h=0")
        unhealthy = unhealthy.replace("af=00000000", "af=00000003").replace("x=00000000", "x=00000002")
        self.assertEqual(ota_rf_lab.parse_ota_radio_measurement(unhealthy)["af"], 3)
        uninitialized = unhealthy.replace("f=907525 b=250000 s=7 c=5", "f=0 b=0 s=0 c=0")
        self.assertEqual(ota_rf_lab.parse_ota_radio_measurement(uninitialized)["v"], 0)
        counters = self.BUDGET.replace("to=00000000 af=00000000", "to=00000001 af=00000002")
        self.assertEqual(ota_rf_lab.parse_ota_budget_measurement(counters)["to"], 1)

    def test_exact_existing_companion_requests_and_repeater_commands(self):
        client, target = mock.Mock(), mock.Mock()
        client.command.side_effect = [b"\x1d" + self.RADIO.encode(), b"\x1d" + self.BUDGET.encode()]
        target.command.side_effect = [self.RADIO, self.BUDGET]
        record = ota_rf_lab.read_ota_measurements(client, target, evidence_fixture(), "test")
        self.assertEqual(client.command.call_args_list, [
            mock.call(bytes.fromhex("420003"), expected=(29, 1), timeout=5),
            mock.call(bytes.fromhex("420004"), expected=(29, 1), timeout=5)])
        self.assertEqual(target.command.call_args_list,
                         [mock.call("ota radio", timeout=5), mock.call("ota budget", timeout=5)])
        self.assertTrue(record["driver_applied_not_phy_readback"])
        self.assertFalse(record["duty_guarantee_verified"])

    def test_bad_backend_frames_and_text_fail_without_payload_or_secret_repr(self):
        for role, kind, response in (
            ("client", "radio", b"\x01\x07"), ("client", "radio", b"\x1d\xff"),
            ("client", "budget", b"\x1d" + self.BUDGET.encode() + b"\x00"),
            ("client", "radio", channel_info(1, "#channel")),
            ("target", "radio", "Err - unavailable"), ("target", "budget", "> " + self.BUDGET),
        ):
            with self.subTest(role=role, kind=kind):
                node = mock.Mock()
                node.command.return_value = response
                with self.assertRaises((ValueError, RuntimeError)) as error:
                    ota_rf_lab.read_ota_measurement(node, role, kind)
                self.assertNotIn(CHANNEL_SECRET_CANARY.decode(), repr(error.exception))
                self.assertNotIn(CHANNEL_SECRET_CANARY.hex(), repr(error.exception))

    def test_diagnostic_reader_uses_real_framing_with_interleaved_secret_channel_response(self):
        node = ota_rf_lab.FramedSerial.__new__(ota_rf_lab.FramedSerial)
        node.name, node.buffer, node.pending = "client", bytearray(), []
        node.evidence = evidence_fixture()
        node._write_bytes = mock.Mock()
        secret = channel_info(2, "#mesh")
        diagnostic = b"\x1d" + self.RADIO.encode()
        wire = b">" + struct.pack("<H", len(secret)) + secret
        wire += b">" + struct.pack("<H", len(diagnostic)) + diagnostic
        chunks = iter(wire[i:i + 5] for i in range(0, len(wire), 5))
        node._read_bytes = lambda timeout: next(chunks, b"")
        self.assertEqual(ota_rf_lab.read_ota_measurement(node, "client", "radio")["f"], 907525)
        self.assertEqual(node.pending[-1][1], secret)
        logs = repr(node.evidence.log.call_args_list)
        self.assertNotIn(CHANNEL_SECRET_CANARY.decode(), logs)
        self.assertNotIn(CHANNEL_SECRET_CANARY.hex(), logs)

    def test_standalone_inspection_is_exclusive_approved_and_read_only_even_if_unhealthy(self):
        for client_only in (False, True):
            with self.subTest(client_only=client_only), tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
                directory = pathlib.Path(parent) / "measurement"
                client, target = mock.Mock(), mock.Mock()
                client.command.side_effect = [self_info(), b"\x1d" + self.RADIO.encode(),
                    b"\x1d" + self.BUDGET.replace("to=00000000", "to=00000001").encode()]
                target.command.side_effect = ["> repeater", "> " + TARGET_KEY.hex(), self.RADIO, self.BUDGET]
                devices = {role: mock.Mock(serial=serial, by_id=f"/dev/serial/by-id/{role}")
                           for role, serial in ota_rf_lab.APPROVED_ADMIN_PAIR.items()}
                args = ["ota_rf_lab.py", "--artifact-dir", str(directory), "--inspect-measurements"]
                if client_only:
                    args.append("--client-only")
                with mock.patch.object(sys, "argv", args), \
                        mock.patch.object(ota_rf_lab.lab_device, "resolve",
                                          side_effect=lambda role, mode: devices[role]) as resolve, \
                        mock.patch.object(ota_rf_lab, "FramedSerial", return_value=client) as open_client, \
                        mock.patch.object(ota_rf_lab, "RepeaterSerial", return_value=target) as open_target, \
                        mock.patch.object(ota_rf_lab.time, "sleep"), \
                        contextlib.redirect_stdout(io.StringIO()):
                    ota_rf_lab.main()
                    count = 1 if client_only else 2
                    self.assertEqual(resolve.call_count, count)
                    if client_only:
                        open_target.assert_not_called()
                    record = json.loads((directory / "summary.json").read_text())
                    record = record["measurements"]["ota_measurement_inspection"]
                    self.assertTrue(record["inspection_complete"])
                    self.assertFalse(record["qualification_verified"])
                    self.assertEqual(record["samples"][0]["nodes"]["client"]["budget"]["to"], 1)
                    client.get_acl.assert_not_called()
                    target.get_acl.assert_not_called()
                    self.assertEqual(len(client.command.call_args_list), 3)
                    self.assertEqual(target.command.call_count, 0 if client_only else 4)
                    with self.assertRaises(FileExistsError):
                        ota_rf_lab.main()
                    self.assertEqual(open_client.call_count, 1)

    def test_standalone_source_guards_reject_pine_remapping_before_open(self):
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as parent:
            args = ["ota_rf_lab.py", "--artifact-dir", str(pathlib.Path(parent) / "capture"),
                    "--inspect-measurements"]
            device = mock.Mock(serial="49C5BAF21EEF44A1", by_id="/dev/serial/by-id/pine")
            with mock.patch.object(sys, "argv", args), \
                    mock.patch.object(ota_rf_lab.lab_device, "resolve", return_value=device), \
                    mock.patch.object(ota_rf_lab, "FramedSerial") as client, \
                    mock.patch.object(ota_rf_lab, "RepeaterSerial") as target, \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(AssertionError):
                    ota_rf_lab.main()
                client.assert_not_called()
                target.assert_not_called()


if __name__ == "__main__":
    unittest.main()
