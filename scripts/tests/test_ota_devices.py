import contextlib
import importlib
import io
import json
from pathlib import Path
import stat
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ota_devices as devices


PATH = "/dev/serial/by-id/synthetic-companion"
KEY = bytes(range(32))
GPS = b"GPS-HIDE"
PIN = b"PIN!"
ENDPOINT = (Path(PATH), Path("/dev/ttyACM99"), 123)
CHAR_INFO = SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=123)


def identity(name=b"attached companion"):
    frame = bytearray(58)
    frame[:2] = bytes([5, 1])
    frame[4:36] = KEY
    frame[36:44] = GPS
    return bytes(frame) + name


def model(protocol=13):
    frame = bytearray(82)
    frame[:2] = bytes([13, protocol])
    frame[4:8] = PIN
    frame[20:60] = b"Seeed Xiao S3 WIO".ljust(40, b"\0")
    frame[60:80] = b"v1.14.0".ljust(20, b"\0")
    frame[81] = 2
    return bytes(frame)


def node_with(*frames):
    node = mock.Mock(name="companion")
    node.name = "companion"
    node.command.side_effect = frames
    return node


class IdentityTests(unittest.TestCase):
    def test_verified_protocol_versions_share_the_public_device_info_layout(self):
        for protocol in range(10, 15):
            with self.subTest(protocol=protocol):
                info = devices.identify_companion(node_with(identity(), model(protocol)))
                self.assertEqual(info["protocol_version"], protocol)
                self.assertEqual(info["board"], "Seeed Xiao S3 WIO")
                self.assertEqual(info["pubkey"], KEY.hex())

    def test_only_public_fields_and_two_normal_read_commands(self):
        node = node_with(identity(), model())
        with mock.patch.object(devices.time, "monotonic", side_effect=[0, 0.25]):
            info = devices.identify_companion(node, timeout=5)
        self.assertEqual(info, {
            "role": "companion", "name": "attached companion", "pubkey": KEY.hex(),
            "board": "Seeed Xiao S3 WIO", "fwversion": "v1.14.0", "protocol_version": 13,
        })
        self.assertEqual(node.command.call_args_list, [
            mock.call(b"\1" + bytes(7) + b"ota", expected=(5, 1), timeout=5),
            mock.call(b"\x16\x0d", expected=(13, 1), timeout=4.75),
        ])
        self.assertNotIn(GPS.decode(), json.dumps(info))
        self.assertNotIn(PIN.decode(), json.dumps(info))
        self.assertNotIn("ota_capable", info)

    def test_malformed_self_identity_is_not_a_companion(self):
        frames = [identity()[:57], bytes([1, 1]), identity(b"bad\0name"),
                  identity(b"\xff"), identity(b"bad\nname"), identity(b"x" * 32)]
        for offset, value in ((1, 2),):
            frame = bytearray(identity())
            frame[offset] = value
            frames.append(bytes(frame))
        frame = bytearray(identity())
        frame[4:36] = bytes(32)
        frames.append(bytes(frame))
        for frame in frames:
            with self.subTest(frame_length=len(frame)):
                node = node_with(frame)
                with self.assertRaises((RuntimeError, ValueError)):
                    devices.identify_companion(node)
                self.assertEqual(node.command.call_count, 1)

    def test_strict_device_info_layout_and_public_strings(self):
        frames = [model()[:81], model() + b"\0"]
        for offset, value in ((0, 1), (1, 9), (1, 15), (1, 255), (80, 2), (81, 3)):
            frame = bytearray(model())
            frame[offset] = value
            frames.append(bytes(frame))
        for start, end, value in ((20, 60, b"x" * 40), (60, 80, b"x" * 20),
                                  (20, 60, b"\xff\0"), (60, 80, b"bad\n\0"),
                                  (20, 60, b"\0")):
            frame = bytearray(model())
            frame[start:end] = value.ljust(end - start, b"\0")
            frames.append(bytes(frame))
        for frame in frames:
            with self.subTest(frame_length=len(frame)):
                with self.assertRaises(ValueError):
                    devices.identify_companion(node_with(identity(), frame))

    def test_invalid_deadline_rejected_before_io(self):
        for timeout in (0, -1, float("nan"), float("inf"), 61):
            node = node_with()
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                devices.identify_companion(node, timeout=timeout)
            node.command.assert_not_called()

    def test_no_fallback_after_missing_response_or_spent_deadline(self):
        node = node_with(TimeoutError("companion: no self-info response"))
        with self.assertRaisesRegex(TimeoutError, "no self-info"):
            devices.identify_companion(node, timeout=0.5)
        self.assertEqual(node.command.call_count, 1)
        node = node_with(identity())
        with mock.patch.object(devices.time, "monotonic", side_effect=[0, 0.6]):
            with self.assertRaisesRegex(TimeoutError, "deadline expired"):
                devices.identify_companion(node, timeout=0.5)
        self.assertEqual(node.command.call_count, 1)

    def test_cli_public_output_and_failure_closes_without_artifacts(self):
        for failure in (None, TimeoutError("no companion reply"), PermissionError("permission denied")):
            node = node_with(identity(), model())
            stdout, stderr = io.StringIO(), io.StringIO()
            stream = mock.MagicMock()
            stream.__enter__.return_value = node
            if failure is not None:
                node.command.side_effect = failure
            with mock.patch.object(devices, "open_companion", return_value=stream), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = devices.main(["inspect", "--by-id", PATH, "--timeout", "1"])
            self.assertEqual(result, int(failure is not None))
            stream.__exit__.assert_called_once()
            if failure:
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(str(failure), stderr.getvalue())
            else:
                self.assertEqual(json.loads(stdout.getvalue())["pubkey"], KEY.hex())
                self.assertEqual(stderr.getvalue(), "")
            self.assertNotIn(GPS.hex(), stdout.getvalue() + stderr.getvalue())
            self.assertNotIn(PIN.hex(), stdout.getvalue() + stderr.getvalue())


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.port = SimpleNamespace(port=None, dtr=True, rts=True, fileno=lambda: 10,
                                    open=mock.Mock(), close=mock.Mock(), write=mock.Mock())
        self.factory = mock.Mock(return_value=self.port)
        self.serial = SimpleNamespace(Serial=self.factory)

    def test_import_never_opens_serial(self):
        with mock.patch.dict(sys.modules, serial=self.serial), \
                mock.patch.object(devices.os, "open") as opening:
            importlib.reload(devices)
        self.factory.assert_not_called()
        opening.assert_not_called()

    def test_no_reset_selected_before_open_and_exclusive_close(self):
        def opened():
            self.assertEqual((self.port.port, self.port.dtr, self.port.rts), (PATH, False, False))
        self.port.open.side_effect = opened
        with mock.patch.dict(sys.modules, serial=self.serial), \
                mock.patch.object(devices, "_endpoint", return_value=ENDPOINT), \
                mock.patch.object(devices.os, "fstat", return_value=CHAR_INFO), \
                mock.patch.object(devices.lab.fcntl, "flock") as lock:
            with devices.open_companion(PATH) as node:
                self.assertIsInstance(node, devices.lab.FramedSerial)
                self.assertTrue(node.no_reset)
                lock.assert_called_once_with(10, devices.lab.fcntl.LOCK_EX | devices.lab.fcntl.LOCK_NB)
                self.port.close.assert_not_called()
            node.close()
        self.factory.assert_called_once_with(port=None, baudrate=115200, timeout=0,
                                             write_timeout=2.0, exclusive=True)
        self.port.close.assert_called_once()

    def test_explicit_dtr_cli_opt_in_is_set_before_open_and_never_toggled(self):
        events = []

        class Port(SimpleNamespace):
            def __setattr__(self, name, value):
                if name in ("dtr", "rts"):
                    events.append((name, value))
                super().__setattr__(name, value)

        def opened():
            self.assertEqual((self.port.port, self.port.dtr, self.port.rts), (PATH, True, False))
            self.assertEqual(events, [("dtr", True), ("rts", False)])
            events.append(("open", None))

        self.port = Port(port=None, fileno=lambda: 10, open=mock.Mock(side_effect=opened),
                         close=mock.Mock(side_effect=lambda: events.append(("close", None))))
        self.factory.return_value = self.port
        with mock.patch.dict(sys.modules, serial=self.serial), \
                mock.patch.object(devices, "_endpoint", return_value=ENDPOINT), \
                mock.patch.object(devices.os, "fstat", return_value=CHAR_INFO), \
                mock.patch.object(devices.lab.fcntl, "flock") as lock, \
                mock.patch.object(devices, "identify_companion", return_value={"pubkey": KEY.hex()}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(devices.main(["inspect", "--by-id", PATH, "--dtr"]), 0)
        self.assertEqual(events, [("dtr", True), ("rts", False), ("open", None), ("close", None)])
        self.factory.assert_called_once_with(port=None, baudrate=115200, timeout=0,
                                             write_timeout=2.0, exclusive=True)
        lock.assert_called_once_with(10, devices.lab.fcntl.LOCK_EX | devices.lab.fcntl.LOCK_NB)
        self.port.close.assert_called_once()

    def test_open_lock_and_disconnect_failures_close_port(self):
        for stage in ("open", "lock", "identity", "read"):
            self.port.open.reset_mock()
            self.port.open.side_effect = PermissionError("open denied") if stage == "open" else None
            self.port.close.reset_mock()
            lock = mock.Mock(side_effect=BlockingIOError("reader busy") if stage == "lock" else None)
            info = SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=456) if stage == "identity" else CHAR_INFO
            with self.subTest(stage=stage), mock.patch.dict(sys.modules, serial=self.serial), \
                    mock.patch.object(devices, "_endpoint", return_value=ENDPOINT), \
                    mock.patch.object(devices.os, "fstat", return_value=info), \
                    mock.patch.object(devices.lab.fcntl, "flock", lock):
                with self.assertRaises((OSError, RuntimeError)):
                    with devices.open_companion(PATH):
                        raise ConnectionError("disconnected")
            self.port.close.assert_called_once()

    def test_unstable_and_noncharacter_endpoints_never_open(self):
        for path in ("/dev/ttyACM0", "usb-id", "/dev/serial/by-id/../ttyACM0"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                with devices.open_companion(path):
                    self.fail("unexpected USB access")
        with mock.patch.object(Path, "is_symlink", return_value=True), \
                mock.patch.object(Path, "resolve", return_value=Path("/dev/ttyACM99")), \
                mock.patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFREG)):
            with self.assertRaisesRegex(ValueError, "character device"):
                with devices.open_companion(PATH):
                    self.fail("unexpected USB access")
        self.factory.assert_not_called()

    def test_no_reset_frames_redact_gps_and_pin_even_with_logger(self):
        node = devices.lab.FramedSerial.__new__(devices.lab.FramedSerial)
        node.name, node.no_reset = "companion", True
        node.buffer, node.pending = bytearray(), []
        node.evidence = mock.Mock()
        node._read_bytes = mock.Mock(return_value=b"".join(
            b">" + struct.pack("<H", len(frame)) + frame for frame in (identity(), model())))
        node.poll()
        self.assertEqual([frame for _, frame in node.pending], [identity(), model()])
        for call in node.evidence.log.call_args_list:
            self.assertTrue(call.kwargs["redacted"])
            self.assertNotIn("hex", call.kwargs)
        logged = repr(node.evidence.log.call_args_list)
        self.assertNotIn(GPS.hex(), logged)
        self.assertNotIn(PIN.hex(), logged)

    def test_no_reset_timeout_and_oversize_response_are_bounded(self):
        node = devices.lab.FramedSerial.__new__(devices.lab.FramedSerial)
        node.name, node.no_reset, node.stream = "companion", True, self.port
        node.buffer, node.pending = bytearray(), []
        node.evidence = mock.Mock()
        node._read_bytes = mock.Mock(return_value=b"")
        self.port.write.return_value = 5
        with mock.patch.object(devices.lab.time, "monotonic",
                               side_effect=[0, 0, 0, 0, 0.3]):
            with self.assertRaisesRegex(TimeoutError, "no frame"):
                node.command(b"\x16\x0d", expected=(13,), timeout=0.25)
        self.assertEqual(self.port.write_timeout, 0.25)
        self.port.write.assert_called_once_with(b"<\x02\0\x16\x0d")
        for size in (0, 177, 65535):
            node.buffer = bytearray(b">" + struct.pack("<H", size))
            with self.subTest(size=size), self.assertRaisesRegex(ValueError, "response length"):
                node._extract()


if __name__ == "__main__":
    unittest.main()
