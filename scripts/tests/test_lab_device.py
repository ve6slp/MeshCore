import argparse
import contextlib
import errno
import io
import json
import pathlib
import sys
import tempfile
import types
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import lab_device
import ota_rf_lab


class ActivePairResolutionTests(unittest.TestCase):
    def setUp(self):
        scratch = lab_device.REPO_ROOT / ".tmp"
        scratch.mkdir(exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.scratch.cleanup)
        self.config = pathlib.Path(self.scratch.name) / "devices.ini"
        self.config.write_text(
            "[roles]\nclient = 4186AE911D94CDB1\ntarget = 77CD44653A967172\n"
            "[protected]\npine = 49C5BAF21EEF44A1\n"
            "[recovery]\ntarget = 3BE94917B92DC5E9\n")

    def test_new_active_pair_is_literal_and_recovery_is_not_an_operational_role(self):
        with mock.patch.object(lab_device, "CONFIG_PATH", self.config), \
                mock.patch.dict(lab_device.os.environ, {}, clear=True):
            self.assertEqual(lab_device.load_roles(),
                             {"client": "4186AE911D94CDB1", "target": "77CD44653A967172"})
            self.assertEqual(lab_device.load_protected(), {"pine": "49C5BAF21EEF44A1"})
            self.assertEqual(lab_device.APPROVED_ADMIN_PAIR, lab_device.load_roles())
            self.assertIs(ota_rf_lab.APPROVED_ADMIN_PAIR, lab_device.APPROVED_ADMIN_PAIR)

    def test_resolution_selects_only_exact_new_pair_from_inventory_with_failed_target_and_pine(self):
        devices = [argparse.Namespace(serial=serial, mode=lab_device.MODE_APP)
                   for serial in ("4186AE911D94CDB1", "77CD44653A967172",
                                  "3BE94917B92DC5E9", "49C5BAF21EEF44A1")]
        with mock.patch.object(lab_device, "CONFIG_PATH", self.config), \
                mock.patch.dict(lab_device.os.environ, {}, clear=True), \
                mock.patch.object(lab_device, "discover", return_value=devices):
            self.assertIs(lab_device.resolve("client", lab_device.MODE_APP), devices[0])
            self.assertIs(lab_device.resolve("target", lab_device.MODE_APP), devices[1])

    def test_failed_protected_swapped_or_arbitrary_serial_cannot_redirect_active_roles_before_discovery(self):
        for role, serial in (("target", "3BE94917B92DC5E9"), ("target", "49C5BAF21EEF44A1"),
                             ("target", "4186AE911D94CDB1"), ("target", "other"),
                             ("client", "77CD44653A967172"), ("client", "3BE94917B92DC5E9")):
            with self.subTest(role=role, serial=serial), \
                    mock.patch.object(lab_device, "load_roles", return_value={role: serial}), \
                    mock.patch.object(lab_device, "discover") as discover:
                with self.assertRaisesRegex(SystemExit, "unapproved active lab role"):
                    lab_device.resolve(role)
                discover.assert_not_called()

    def test_environment_override_or_recovery_alias_cannot_substitute_failed_target(self):
        for role, environment in (
            ("target", {"MESHCORE_LAB_TARGET_SERIAL": "3BE94917B92DC5E9"}),
            ("recovery", {"MESHCORE_LAB_RECOVERY_SERIAL": "3BE94917B92DC5E9"}),
            ("other", {"MESHCORE_LAB_OTHER_SERIAL": "77CD44653A967172"}),
        ):
            with self.subTest(role=role), mock.patch.object(lab_device, "CONFIG_PATH", self.config), \
                    mock.patch.dict(lab_device.os.environ, environment, clear=True), \
                    mock.patch.object(lab_device, "discover") as discover:
                with self.assertRaisesRegex(SystemExit, "unapproved active lab role"):
                    lab_device.resolve(role)
                discover.assert_not_called()

    def test_stock_bootloader_presence_is_not_an_application_or_install_capability(self):
        device = argparse.Namespace(serial="77CD44653A967172", mode=lab_device.MODE_BOOT)
        with mock.patch.object(lab_device, "load_roles", return_value={"target": device.serial}), \
                mock.patch.object(lab_device, "discover", return_value=[device]):
            with self.assertRaisesRegex(SystemExit, "not app"):
                lab_device.resolve("target", lab_device.MODE_APP)

    def test_failed_target_or_pine_cannot_reach_power_control_or_sysfs_resolution(self):
        for serial in ("3BE94917B92DC5E9", "49C5BAF21EEF44A1"):
            with self.subTest(serial=serial), \
                    mock.patch.object(lab_device, "load_roles", return_value={"target": serial}), \
                    mock.patch.object(lab_device, "sysfs_for_serial") as sysfs, \
                    mock.patch.object(lab_device, "_run") as run:
                with self.assertRaisesRegex(SystemExit, "unapproved active lab role"):
                    lab_device.cmd_power_cycle(argparse.Namespace(role="target"))
                sysfs.assert_not_called()
                run.assert_not_called()


class UnsupportedUsbDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        scratch = lab_device.REPO_ROOT / ".tmp"
        scratch.mkdir(exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        self.usb = self.root / "usb"
        self.by_id = self.root / "dev" / "serial" / "by-id"
        self.usb.mkdir()
        self.by_id.mkdir(parents=True)
        self.roles = {"client": "4186AE911D94CDB1", "target": "77CD44653A967172"}
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in (("USB_DEVICES", self.usb), ("BY_ID_DIR", self.by_id)):
            self.stack.enter_context(mock.patch.object(lab_device, name, value))
        self.stack.enter_context(mock.patch.object(lab_device, "load_roles", return_value=self.roles))
        self.stack.enter_context(mock.patch.object(lab_device, "load_protected",
                                                   return_value={"pine": "49C5BAF21EEF44A1"}))
        self.target = self.add_usb("1-4.2.3", self.roles["target"], "239a", "810b",
                                   "XIAO-BOOT", "ttyACM5")

    def add_usb(self, name, serial, vendor, product_id, product, tty):
        node = self.usb / name
        node.mkdir()
        for field, value in (("serial", serial), ("idVendor", vendor),
                             ("idProduct", product_id), ("product", product),
                             ("manufacturer", "Seeed Studio")):
            (node / field).write_text(value)
        for suffix, interface_class, subclass in (("1.0", "02", "02"), ("1.1", "0a", "00")):
            interface = node / f"{name}:{suffix}"
            interface.mkdir()
            for field, value in (("bInterfaceClass", interface_class),
                                 ("bInterfaceSubClass", subclass), ("bInterfaceProtocol", "00")):
                (interface / field).write_text(value)
            if suffix == "1.0":
                (interface / "tty" / tty).mkdir(parents=True)
        endpoint = self.root / "dev" / tty
        endpoint.touch()
        (self.by_id / f"usb-Seeed_Studio_{product}_{serial}-if00").symlink_to(endpoint)
        return node

    def list_output(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = lab_device.cmd_list(argparse.Namespace())
        return result, stdout.getvalue(), stderr.getvalue()

    def test_stable_cdc_239a_profile_is_presence_only_despite_product_name_and_pid_bit(self):
        self.assertEqual(lab_device.discover(), [])
        self.assertEqual(lab_device._seeed_nodes(), [])
        self.assertIsNone(lab_device.sysfs_for_serial(self.roles["target"]))
        for product_id in ("810b", "010b"):
            with self.subTest(product_id=product_id):
                (self.target / "idProduct").write_text(product_id)
                for mode in ("any", lab_device.MODE_APP, lab_device.MODE_BOOT):
                    with self.subTest(mode=mode):
                        with self.assertRaisesRegex(SystemExit, "attached but unavailable") as error:
                            lab_device.resolve("target", mode)
                        text = str(error.exception)
                        self.assertIn(f"VID=239a PID={product_id}", text)
                        self.assertIn("product='XIAO-BOOT'", text)
                        self.assertIn("unsupported USB profile", text)
                        self.assertIn("mode/firmware unproven", text)
                        self.assertNotIn("is not attached", text)

    def test_list_separates_attached_unsupported_target_from_absent_client(self):
        result, stdout, stderr = self.list_output()
        self.assertEqual(result, 1)
        self.assertIn("no operationally discoverable", stdout)
        self.assertNotIn("boards attached", stdout)
        self.assertIn("configured and attached but unavailable", stderr)
        self.assertIn("target (serial 77CD44653A967172)", stderr)
        self.assertIn("1-4.2.3: VID=239a PID=810b", stderr)
        self.assertIn("mode/firmware unproven", stderr)
        self.assertIn("configured but not attached: client", stderr)
        self.assertNotIn("configured but not attached: client, target", stderr)

    def test_list_preserves_qualified_client_and_does_not_call_unsupported_target_absent(self):
        self.add_usb("1-4.2.4", self.roles["client"], "2886", "8044", "Runtime", "ttyACM4")
        result, stdout, stderr = self.list_output()
        self.assertEqual(result, 1)
        self.assertIn("4186AE911D94CDB1", stdout)
        self.assertIn("app", stdout)
        self.assertIn("target (serial 77CD44653A967172)", stderr)
        self.assertNotIn("configured but not attached", stderr)

    def test_true_absence_remains_absence(self):
        self.target.rename(self.root / "detached")
        result, stdout, stderr = self.list_output()
        self.assertEqual(result, 1)
        self.assertIn("no XIAO nRF52840 boards attached", stdout)
        self.assertIn("configured but not attached: client, target", stderr)
        self.assertNotIn("unsupported USB profile", stderr)
        with self.assertRaisesRegex(SystemExit, "is not attached"):
            lab_device.resolve("target")

    def test_known_vendor_without_stable_identity_is_attached_but_not_ready(self):
        (self.target / "idVendor").write_text("2886")
        next(self.by_id.iterdir()).unlink()
        self.assertEqual(lab_device.discover(), [])
        with self.assertRaisesRegex(SystemExit, "not ready for guarded discovery") as error:
            lab_device.resolve("target")
        self.assertNotIn("unsupported USB profile", str(error.exception))
        self.assertIn("mode/firmware unproven", str(error.exception))

    def test_existing_2886_app_and_boot_discovery_are_unchanged(self):
        client = self.add_usb("1-4.2.4", self.roles["client"], "2886", "8044",
                              "Runtime", "ttyACM4")
        for product_id, mode in (("8044", lab_device.MODE_APP), ("0044", lab_device.MODE_BOOT)):
            with self.subTest(product_id=product_id):
                (client / "idProduct").write_text(product_id)
                devices = lab_device.discover()
                self.assertEqual([(device.serial, device.mode) for device in devices],
                                 [(self.roles["client"], mode)])
                self.assertEqual(lab_device.resolve("client", mode).serial, self.roles["client"])

    def test_diagnostic_presence_cannot_open_reset_enter_bootloader_flash_or_control_power(self):
        package, nrfutil = self.root / "application.zip", self.root / "adafruit-nrfutil.py"
        package.touch()
        nrfutil.touch()
        args = argparse.Namespace(role="target", mode="any", timeout=1,
                                  protocol="repeater", package=str(package))
        serial_factory = mock.Mock()
        with mock.patch.dict(sys.modules, {"serial": types.SimpleNamespace(Serial=serial_factory)}), \
                mock.patch.dict(lab_device.os.environ, {"ADAFRUIT_NRFUTIL": str(nrfutil)}), \
                mock.patch.object(lab_device, "validate_application_package", return_value=b"image"), \
                mock.patch.object(lab_device, "_touch_1200") as touch, \
                mock.patch.object(lab_device, "_uf2_repeater_request") as uf2_request, \
                mock.patch.object(lab_device, "_run") as power, \
                mock.patch.object(lab_device.subprocess, "run") as dfu:
            for command in (lab_device.cmd_path, lab_device.cmd_reset, lab_device.cmd_bootloader,
                            lab_device.cmd_bootloader_uf2, lab_device.cmd_flash,
                            lab_device.cmd_power_cycle):
                with self.subTest(command=command.__name__):
                    with self.assertRaisesRegex(SystemExit, "attached but unavailable"):
                        command(args)
            serial_factory.assert_not_called()
            touch.assert_not_called()
            uf2_request.assert_not_called()
            power.assert_not_called()
            dfu.assert_not_called()

    def test_presence_fallback_never_scans_for_pine_failed_target_or_unapproved_serial(self):
        for serial in ("49C5BAF21EEF44A1", "3BE94917B92DC5E9", "other"):
            with self.subTest(serial=serial), mock.patch.object(lab_device, "USB_DEVICES") as usb:
                self.assertEqual(lab_device._attached_usb_diagnostics(serial), [])
                usb.glob.assert_not_called()


class ApplicationResetTests(unittest.TestCase):
    def reset_fixture(self, protocol, frame):
        device = argparse.Namespace(by_id="/dev/serial/by-id/authorized-target")
        args = argparse.Namespace(role="target", timeout=30, protocol=protocol)
        serial_factory = mock.MagicMock()
        port = serial_factory.return_value.__enter__.return_value
        port.write.return_value = len(frame)
        with mock.patch.dict(sys.modules, {"serial": types.SimpleNamespace(Serial=serial_factory)}), \
                mock.patch.object(lab_device, "resolve", return_value=device), \
                mock.patch.object(lab_device, "wait_for", return_value=device) as wait, \
                mock.patch("builtins.print"):
            self.assertEqual(lab_device.cmd_reset(args), 0)
        port.write.assert_called_once_with(frame)
        wait.assert_called_once_with("target", lab_device.MODE_APP, 30, absent_first=True)

    def test_companion_reset_uses_binary_reboot_and_requires_reenumeration(self):
        self.reset_fixture("companion", b"<\x07\x00\x13reboot")

    def test_repeater_reset_uses_text_reboot_and_requires_reenumeration(self):
        self.reset_fixture("repeater", b"reboot\r")

    def test_unknown_protocol_is_rejected_before_device_access(self):
        with mock.patch.object(lab_device, "resolve") as resolve:
            with self.assertRaisesRegex(SystemExit, "explicit companion or repeater"):
                lab_device.cmd_reset(argparse.Namespace(role="target", protocol="unknown"))
        resolve.assert_not_called()

    def test_short_reboot_write_does_not_claim_success(self):
        device = argparse.Namespace(by_id="/dev/serial/by-id/authorized-target")
        factory = mock.MagicMock()
        factory.return_value.__enter__.return_value.write.return_value = 3
        for protocol in ("companion", "repeater"):
            with self.subTest(protocol=protocol), \
                    mock.patch.dict(sys.modules, {"serial": types.SimpleNamespace(Serial=factory)}), \
                    mock.patch.object(lab_device, "resolve", return_value=device), \
                    mock.patch.object(lab_device, "wait_for") as wait:
                with self.assertRaisesRegex(SystemExit, "short reboot"):
                    lab_device.cmd_reset(argparse.Namespace(role="target", timeout=30,
                                                           protocol=protocol))
                wait.assert_not_called()

    def test_a_port_that_never_disappears_is_not_a_successful_reset(self):
        with mock.patch.object(lab_device.time, "monotonic", side_effect=[0, 0, 6]), \
                mock.patch.object(lab_device, "resolve") as resolve:
            with self.assertRaisesRegex(SystemExit, "did not disconnect"):
                lab_device.wait_for("target", lab_device.MODE_APP, 10, absent_first=True)
        resolve.assert_not_called()


class Uf2EntryTests(unittest.TestCase):
    def setUp(self):
        scratch = lab_device.REPO_ROOT / ".tmp"
        scratch.mkdir(exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        self.by_id = self.root / "dev" / "serial" / "by-id"
        self.by_id.mkdir(parents=True)
        self.serial = "77CD44653A967172"
        self.sysfs = self.root / "sys" / "1-4.2.3"
        self.sysfs.mkdir(parents=True)
        (self.sysfs / "serial").write_text(self.serial)
        for suffix, interface_class in (("1.0", "02"), ("1.1", "0a")):
            self.add_interface(self.sysfs, suffix, interface_class)
        self.app = self.device("ttyACM4", lab_device.MODE_APP, "Runtime")
        self.boot = self.device("ttyACM99", lab_device.MODE_BOOT, "XIAO_nRF52840_Sense")
        self.args = argparse.Namespace(role="target", timeout=1.0)
        self.now = 0.0
        self.on_sleep = lambda: None
        self.node = ota_rf_lab.RepeaterSerial.__new__(ota_rf_lab.RepeaterSerial)
        self.node.name = "target"
        self.node.buffer = bytearray()
        self.node.pending = []
        self.node.evidence = mock.Mock()
        self.node._write_bytes = mock.Mock()
        self.node.close = mock.Mock()

    def device(self, tty, mode, product):
        tty_path = self.root / "dev" / tty
        tty_path.touch()
        by_id = self.by_id / f"usb-Seeed_{product}_{self.serial}-if00"
        by_id.symlink_to(tty_path)
        return lab_device.Device(self.serial, mode, tty, self.sysfs, product, by_id)

    def add_interface(self, sysfs, suffix, interface_class):
        interface = sysfs / f"{sysfs.name}:{suffix}"
        interface.mkdir(exist_ok=True)
        (interface / "bInterfaceClass").write_text(interface_class)
        return interface

    @contextlib.contextmanager
    def session(self, *, reply="OK - rebooting UF2", presence=None, chunks=None):
        if presence is None:
            presence = (self.sysfs, None, self.sysfs)
        presence = iter(presence)
        last_usb = next(presence)
        removed_usb = self.root / "disconnected-usb"

        def usb_for_serial(serial):
            self.assertEqual(serial, self.serial)
            self.assertTrue(self.node.close.called)
            return last_usb

        if chunks is None:
            chunks = [b"  -> OK - rebooting UF2\r\n", f"reboot uf2\r\n  -> {reply}\r\n".encode()]
        chunks = iter(chunks)

        def read_bytes(timeout):
            self.now += max(0.01, timeout)
            return next(chunks, b"")

        def sleep(duration):
            nonlocal last_usb
            self.now += duration
            last_usb = next(presence, last_usb)
            if last_usb is None and self.sysfs.exists():
                self.sysfs.rename(removed_usb)
            elif last_usb is not None and removed_usb.exists():
                removed_usb.rename(self.sysfs)
            self.on_sleep()

        self.node._read_bytes = mock.Mock(side_effect=read_bytes)
        with mock.patch.object(lab_device, "BY_ID_DIR", self.by_id), \
                mock.patch.object(lab_device, "resolve", return_value=self.app) as resolve, \
                mock.patch.object(lab_device, "sysfs_for_serial", side_effect=usb_for_serial) as usb, \
                mock.patch.object(lab_device, "discover", return_value=[self.boot]) as discover, \
                mock.patch.object(lab_device, "_touch_1200") as touch, \
                mock.patch.object(ota_rf_lab, "RepeaterSerial", return_value=self.node) as transport, \
                mock.patch.object(ota_rf_lab.os, "open", side_effect=AssertionError("physical open")), \
                mock.patch.object(lab_device.time, "monotonic", side_effect=lambda: self.now), \
                mock.patch.object(lab_device.time, "sleep", side_effect=sleep), \
                mock.patch("builtins.print") as output:
            yield argparse.Namespace(resolve=resolve, usb=usb, discover=discover,
                                     touch=touch, transport=transport, output=output)
            touch.assert_not_called()

    def test_reboot_ack_disconnect_and_matching_msc_return_new_stable_path(self):
        self.add_interface(self.sysfs, "1.2", "08")
        with self.session() as calls:
            self.assertEqual(lab_device.cmd_bootloader_uf2(self.args), 0)
            calls.resolve.assert_called_once_with("target", lab_device.MODE_APP)
            calls.output.assert_called_once_with(self.boot.by_id)
            self.assertEqual(calls.usb.call_count, 2)
            calls.transport.assert_called_once_with("target", str(self.app.by_id), mock.ANY)
            self.node._write_bytes.assert_called_once_with(b"reboot uf2\r")
            self.node.close.assert_called_once()

    def test_split_current_echo_and_ack_use_existing_repeater_parser(self):
        self.add_interface(self.sysfs, "1.2", "08")
        with self.session(chunks=[b"  -> OK - rebooting UF2\r\n", b"reboot u",
                                  b"f2\r\n  -> OK - reboo", b"ting UF2\r", b"\n"]):
            self.assertEqual(lab_device.cmd_bootloader_uf2(self.args), 0)
        self.node._write_bytes.assert_called_once_with(b"reboot uf2\r")

    def test_default_timeout_allows_reply_grace_and_ordinary_queue_deadline(self):
        self.args.timeout = 30.0
        self.add_interface(self.sysfs, "1.2", "08")
        with self.session(presence=(self.sysfs,) * 171 + (None, self.sysfs)) as calls:
            self.assertEqual(lab_device.cmd_bootloader_uf2(self.args), 0)
            calls.output.assert_called_once_with(self.boot.by_id)
        self.assertGreater(self.now, 17.0)
        self.assertLess(self.now, self.args.timeout)

    def test_stale_ack_without_current_echo_cannot_trigger_wait_or_success(self):
        with self.session(chunks=[b"", b"  -> OK - rebooting UF2\r\n"]) as calls:
            with self.assertRaisesRegex(SystemExit, "no repeater CLI reply"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.usb.assert_not_called()
            calls.output.assert_not_called()
            self.node.close.assert_called_once()

    def test_missing_reply_is_a_clear_timeout_and_closes_transport(self):
        with self.session(chunks=[b"", b"reboot uf2\r\n"]) as calls:
            with self.assertRaisesRegex(SystemExit, "no repeater CLI reply"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.usb.assert_not_called()
            self.node.close.assert_called_once()

    def test_failed_or_nonexact_ack_is_not_a_reboot_success(self):
        for reply in ("Err - OTA busy", "Err - USB only", "Err - unknown command",
                      "Rebooting", "OK", "> OK - rebooting UF2", "OK - rebooting UF2 extra"):
            with self.subTest(reply=reply), self.session(reply=reply) as calls:
                with self.assertRaisesRegex(SystemExit, "UF2 reboot request failed"):
                    lab_device.cmd_bootloader_uf2(self.args)
                calls.usb.assert_not_called()
                calls.output.assert_not_called()

    def test_disconnect_before_ack_is_not_a_success(self):
        with self.session() as calls:
            self.node._read_bytes.side_effect = [b"", ConnectionError("serial disconnected")]
            with self.assertRaisesRegex(SystemExit, "command 'reboot uf2' failed.*disconnected"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.usb.assert_not_called()
            self.node.close.assert_called_once()

    def test_serial_open_failure_is_explicit_and_does_not_wait(self):
        with self.session() as calls:
            calls.transport.side_effect = OSError(errno.EACCES, "permission denied")
            with self.assertRaisesRegex(SystemExit, "UF2 command.*permission denied"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.usb.assert_not_called()
            self.node.close.assert_not_called()

    def test_existing_serial_dfu_is_rejected_before_any_command(self):
        with self.session() as calls:
            calls.resolve.side_effect = SystemExit("target is in bootloader mode, not app")
            with self.assertRaisesRegex(SystemExit, "not app"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.transport.assert_not_called()
            calls.usb.assert_not_called()

    def test_client_protected_and_unknown_roles_are_rejected_before_resolution(self):
        for role in ("client", "pine", "other"):
            with self.subTest(role=role), self.session() as calls:
                with self.assertRaisesRegex(SystemExit, "target role only"):
                    lab_device.cmd_bootloader_uf2(argparse.Namespace(role=role, timeout=1.0))
                calls.resolve.assert_not_called()
                calls.transport.assert_not_called()

    def test_target_inventory_cannot_redirect_to_a_different_serial(self):
        for serial in ("4186AE911D94CDB1", "3BE94917B92DC5E9", "49C5BAF21EEF44A1", "UNKNOWN"):
            self.app.serial = serial
            with self.subTest(serial=serial), self.session() as calls:
                with self.assertRaisesRegex(SystemExit, "requires approved target serial"):
                    lab_device.cmd_bootloader_uf2(self.args)
                calls.transport.assert_not_called()

    def test_invalid_timeout_is_rejected_before_device_access(self):
        for timeout in (0, -1, float("inf"), float("nan")):
            with self.subTest(timeout=timeout), self.session() as calls:
                with self.assertRaisesRegex(SystemExit, "finite and positive"):
                    lab_device.cmd_bootloader_uf2(
                        argparse.Namespace(role="target", timeout=timeout))
                calls.resolve.assert_not_called()
                calls.transport.assert_not_called()

    def test_unstable_regular_dangling_and_wrong_tty_paths_are_rejected(self):
        regular = self.by_id / "regular"
        regular.touch()
        dangling = self.by_id / "dangling"
        dangling.symlink_to(self.root / "missing")
        for path in (self.root / "dev" / self.app.tty, regular, dangling, self.boot.by_id):
            self.app.by_id = path
            with self.subTest(path=path), self.session() as calls:
                with self.assertRaisesRegex(SystemExit, "real stable by-id symlink"):
                    lab_device.cmd_bootloader_uf2(self.args)
                calls.transport.assert_not_called()

    def test_app_usb_ancestry_mismatch_is_rejected_before_any_command(self):
        (self.sysfs / "serial").write_text("4186AE911D94CDB1")
        with self.session() as calls:
            with self.assertRaisesRegex(SystemExit, "USB ancestry does not match"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.transport.assert_not_called()

    def test_msc_without_observed_disappearance_cannot_claim_success(self):
        self.add_interface(self.sysfs, "1.2", "08")
        with self.session(presence=(self.sysfs,)) as calls:
            with self.assertRaisesRegex(SystemExit, "did not disconnect"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.discover.assert_not_called()
            calls.output.assert_not_called()

    def test_disappeared_target_that_never_returns_times_out(self):
        with self.session(presence=(self.sysfs, None)) as calls:
            with self.assertRaisesRegex(SystemExit, "disconnected but has not re-enumerated"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.output.assert_not_called()

    def test_discovery_gap_cannot_substitute_for_actual_usb_disappearance(self):
        self.add_interface(self.sysfs, "1.2", "08")
        with self.session(presence=(self.sysfs,)) as calls:
            calls.usb.return_value = None
            calls.usb.side_effect = None
            with self.assertRaisesRegex(SystemExit, "did not disconnect"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.usb.assert_not_called()
            calls.output.assert_not_called()

    def test_usb_disconnection_read_fault_is_not_disappearance(self):
        stat = pathlib.Path.stat

        def fault(path, *args, **kwargs):
            if path == self.sysfs:
                raise OSError(errno.EIO, "read fault")
            return stat(path, *args, **kwargs)

        with self.session() as calls, \
                mock.patch.object(pathlib.Path, "stat", autospec=True, side_effect=fault):
            with self.assertRaisesRegex(SystemExit, "cannot observe target USB disconnection.*read fault"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.usb.assert_not_called()
            calls.output.assert_not_called()

    def test_reenumerated_cdc_only_bootloader_is_not_uf2(self):
        with self.session() as calls:
            with self.assertRaisesRegex(SystemExit, "CDC-only is not UF2"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.output.assert_not_called()

    def test_msc_on_another_usb_device_cannot_satisfy_target_gate(self):
        other = self.root / "sys" / "1-4.2.1"
        other.mkdir()
        self.add_interface(other, "1.2", "08")
        with self.session() as calls:
            with self.assertRaisesRegex(SystemExit, "CDC-only is not UF2"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.output.assert_not_called()

    def test_application_with_msc_is_not_bootloader_mode(self):
        self.add_interface(self.sysfs, "1.2", "08")
        with self.session() as calls:
            calls.discover.return_value = [self.app]
            with self.assertRaisesRegex(SystemExit, "returned in app mode"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.output.assert_not_called()

    def test_stable_identity_and_msc_may_finish_enumerating_after_usb_returns(self):
        self.on_sleep = lambda: self.add_interface(self.sysfs, "1.2", "08") if self.now > 0.5 else None
        with self.session() as calls:
            calls.discover.side_effect = [[], [self.boot], [self.boot], [self.boot]]
            self.assertEqual(lab_device.cmd_bootloader_uf2(self.args), 0)
            calls.output.assert_called_once_with(self.boot.by_id)

    def test_ambiguous_reenumerated_identity_is_rejected(self):
        with self.session() as calls:
            calls.discover.return_value = [self.boot, self.boot]
            with self.assertRaisesRegex(SystemExit, "ambiguous target USB identity"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.output.assert_not_called()

    def test_reenumerated_device_must_belong_to_the_matched_usb_ancestry(self):
        self.boot.sysfs = self.root / "sys" / "other"
        with self.session() as calls:
            with self.assertRaisesRegex(SystemExit, "ancestry changed unexpectedly"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.output.assert_not_called()

    def test_reenumerated_bootloader_requires_its_own_valid_stable_identity(self):
        self.add_interface(self.sysfs, "1.2", "08")
        regular = self.by_id / "regular-boot"
        regular.touch()
        dangling = self.by_id / "dangling-boot"
        dangling.symlink_to(self.root / "missing-boot")
        for path in (regular, dangling, self.app.by_id):
            self.boot.by_id = path
            with self.subTest(path=path), self.session() as calls:
                with self.assertRaisesRegex(SystemExit, "real stable by-id symlink"):
                    lab_device.cmd_bootloader_uf2(self.args)
                calls.output.assert_not_called()

    def test_ack_cannot_extend_the_overall_reboot_deadline(self):
        self.add_interface(self.sysfs, "1.2", "08")

        def delayed_ack(timeout):
            if timeout == 0:
                return b""
            self.now += 2.0
            return b"reboot uf2\r\n  -> OK - rebooting UF2\r\n"

        with self.session() as calls:
            self.node._read_bytes.side_effect = delayed_ack
            with self.assertRaisesRegex(SystemExit, "timed out waiting for target UF2 bootloader"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.usb.assert_not_called()
            calls.output.assert_not_called()

    def test_msc_read_fault_fails_explicitly_instead_of_succeeding(self):
        interface = self.add_interface(self.sysfs, "1.2", "08")
        read_text = pathlib.Path.read_text

        def fault(path, *args, **kwargs):
            if path == interface / "bInterfaceClass":
                raise OSError(errno.EIO, "read fault")
            return read_text(path, *args, **kwargs)

        with self.session() as calls, \
                mock.patch.object(pathlib.Path, "read_text", autospec=True, side_effect=fault):
            with self.assertRaisesRegex(SystemExit, "cannot inspect target USB interface.*read fault"):
                lab_device.cmd_bootloader_uf2(self.args)
            calls.output.assert_not_called()

    def test_command_line_dispatches_target_only_uf2_entry(self):
        with mock.patch.object(sys, "argv", ["lab_device.py", "bootloader-uf2", "target",
                                            "--timeout", "7"]), \
                mock.patch.object(lab_device, "cmd_bootloader_uf2", return_value=0) as execute:
            self.assertEqual(lab_device.main(), 0)
            args = execute.call_args.args[0]
            self.assertEqual((args.role, args.timeout), ("target", 7.0))

    def test_command_line_cannot_select_client_for_uf2(self):
        with mock.patch.object(sys, "argv", ["lab_device.py", "bootloader-uf2", "client"]), \
                mock.patch.object(lab_device, "resolve") as resolve, \
                mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                lab_device.main()
            resolve.assert_not_called()


class StockBootloaderInspectionTests(unittest.TestCase):
    INFO = ("UF2 Bootloader 0.6.1\r\nModel: Seeed XIAO nRF52840 Sense\r\n"
            "Board-ID: Seeed_XIAO_nRF52840_Sense\r\n"
            "Date: Jan 01 2021\r\nSoftDevice: S140 version 7.3.0\r\n")

    def setUp(self):
        scratch = lab_device.REPO_ROOT / ".tmp"
        scratch.mkdir(exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        self.usb = self.root / "usb"
        self.node = self.usb / "1-4.2.3"
        self.node.mkdir(parents=True)
        self.serial = "77CD44653A967172"
        for field, value in (("serial", self.serial), ("idVendor", "2886"),
                             ("idProduct", "0045"), ("product", "XIAO nRF52840 Sense")):
            (self.node / field).write_text(value)
        self.cdc = self.node / "1-4.2.3:1.0"
        (self.cdc / "tty" / "ttyACM5").mkdir(parents=True)
        (self.cdc / "bInterfaceClass").write_text("02")
        self.msc = self.node / "1-4.2.3:1.2"
        self.msc.mkdir()
        (self.msc / "bInterfaceClass").write_text("08")
        self.block = self.msc / "block" / "sdd"
        self.block.mkdir(parents=True)
        self.by_id = self.root / "dev" / "serial" / "by-id"
        self.by_id.mkdir(parents=True)
        self.tty = self.root / "dev" / "ttyACM5"
        self.tty.touch()
        self.port = self.by_id / f"usb-Seeed_XIAO_nRF52840_Sense_{self.serial}-if00"
        self.port.symlink_to(self.tty)
        self.char_root, self.block_root = self.root / "char", self.root / "block"
        self.char_root.mkdir()
        self.block_root.mkdir()
        (self.char_root / "0:0").symlink_to(self.cdc / "tty" / "ttyACM5")
        (self.block_root / "8:48").symlink_to(self.block)
        self.volume = self.root / "stock volume"
        self.volume.mkdir()
        self.info = self.volume / "INFO_UF2.TXT"
        self.info.write_bytes(self.INFO.encode())
        self.mountinfo = self.root / "mountinfo"
        mountpoint = str(self.volume).replace(" ", "\\040")
        self.mount_line = f"1 0 8:48 / {mountpoint} ro - vfat /dev/sdd ro\n"
        self.mountinfo.write_text(self.mount_line)
        self.args = argparse.Namespace(role="target")
        self.roles = {"client": "4186AE911D94CDB1", "target": self.serial}
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in (("USB_DEVICES", self.usb), ("BY_ID_DIR", self.by_id),
                             ("SYS_DEV_CHAR", self.char_root), ("SYS_DEV_BLOCK", self.block_root),
                             ("MOUNTINFO", self.mountinfo)):
            self.stack.enter_context(mock.patch.object(lab_device, name, value))
        self.stack.enter_context(mock.patch.object(lab_device, "load_roles", return_value=self.roles))
        sys.path.insert(0, str(lab_device.REPO_ROOT / "bootloader" / "xiao_nrf52840_ota" / "tools"))
        import install_uf2
        self.installer = install_uf2
        self.forbidden = []
        serial_factory = mock.Mock(side_effect=AssertionError("serial must never be opened"))
        self.forbidden.append(serial_factory)
        self.stack.enter_context(mock.patch.dict(sys.modules, {
            "serial": types.SimpleNamespace(Serial=serial_factory)}))
        for module, name in (
            (lab_device, "_touch_1200"), (lab_device, "_run"),
            (lab_device, "cmd_bootloader_port"), (lab_device, "wait_for"),
            (lab_device.subprocess, "run"), (install_uf2, "install"),
            (install_uf2, "validate_public_identity"), (install_uf2, "run_vendor_serial"),
            (install_uf2, "main"),
        ):
            forbidden = self.stack.enter_context(mock.patch.object(
                module, name, side_effect=AssertionError(f"{name} must never be invoked")))
            self.forbidden.append(forbidden)
        self.addCleanup(self.assert_no_mutations)

    def assert_no_mutations(self):
        for forbidden in self.forbidden:
            forbidden.assert_not_called()

    def inspect(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(lab_device.cmd_inspect_stock_bootloader(self.args), 0)
        return json.loads(output.getvalue())

    def assert_refused(self, pattern):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaisesRegex(SystemExit, pattern):
            lab_device.cmd_inspect_stock_bootloader(self.args)
        self.assertEqual(output.getvalue(), "")

    def test_exact_stock_sense_read_only_public_metadata_and_helper_reuse(self):
        with mock.patch.object(self.installer, "board_id", wraps=self.installer.board_id) as board, \
                mock.patch.object(self.installer, "validate_stock_info",
                                  wraps=self.installer.validate_stock_info) as versions, \
                mock.patch.object(self.installer, "matching_mounts",
                                  wraps=self.installer.matching_mounts) as mounts:
            record = self.inspect()
        self.assertEqual(record["serial"], self.serial)
        self.assertEqual(record["by_id"], str(self.port))
        self.assertEqual(record["sysfs"], str(self.node))
        self.assertEqual((record["usb_vid"], record["usb_pid"]), ("2886", "0045"))
        self.assertEqual(record["board_id"], "Seeed_XIAO_nRF52840_Sense")
        self.assertEqual(record["vendor_info"], self.INFO)
        self.assertEqual(record["mountpoint"], str(self.volume))
        self.assertEqual(record["stock_bootloader_version"], "0.6.1")
        self.assertEqual((record["softdevice"], record["softdevice_version"]), ("S140", "7.3.0"))
        for field in ("read_only", "public_only"):
            self.assertIs(record[field], True)
        for field in ("serial_opened", "writes", "cryptographic_installed_bytes_proof",
                      "custom_loader_qualified"):
            self.assertIs(record[field], False)
        self.assertTrue(record["observed_at"].endswith("Z"))
        self.assertIsNotNone(lab_device.datetime.fromisoformat(record["observed_at"].replace("Z", "+00:00")).tzinfo)
        board.assert_called_once()
        versions.assert_called_once()
        self.assertIs(board.call_args.args[0], versions.call_args.args[0])
        mounts.assert_called_once_with(self.serial, self.mountinfo, self.block_root)

    def test_role_guard_refuses_client_old_target_and_pine_before_discovery(self):
        with mock.patch.object(lab_device, "discover") as discover:
            self.args.role = "client"
            self.assert_refused("target role only")
            self.args.role = "target"
            for serial in ("3BE94917B92DC5E9", "49C5BAF21EEF44A1", "4186AE911D94CDB1"):
                with self.subTest(serial=serial):
                    self.roles["target"] = serial
                    self.assert_refused("unapproved active lab role")
            discover.assert_not_called()

    def test_unsupported_wrong_variant_application_and_malformed_usb_are_refused(self):
        for vendor, product_id in (("239a", "810b"), ("2886", "0044"),
                                   ("2886", "8045"), ("2886", "malformed")):
            with self.subTest(vendor=vendor, product_id=product_id):
                (self.node / "idVendor").write_text(vendor)
                (self.node / "idProduct").write_text(product_id)
                self.assert_refused("unavailable|exact Sense USB|not bootloader|refusing read-only")

    def test_by_id_must_be_real_stable_identity_not_regular_dangling_or_wrong_tty(self):
        device = lab_device.discover()[0]
        regular, dangling = self.by_id / "regular", self.by_id / "dangling"
        regular.touch()
        dangling.symlink_to(self.root / "missing")
        other = self.by_id / "other"
        other.symlink_to(self.root / "dev" / "ttyACM6")
        other.resolve().touch()
        for path in (regular, dangling, other, self.tty):
            device.by_id = path
            with self.subTest(path=path), mock.patch.object(lab_device, "resolve", return_value=device):
                self.assert_refused("real stable by-id symlink")

    def test_tty_ancestry_must_match_same_target_usb_node(self):
        foreign = self.usb / "other"
        foreign.mkdir()
        (foreign / "serial").write_text("4186AE911D94CDB1")
        (self.char_root / "0:0").unlink()
        (self.char_root / "0:0").symlink_to(foreign)
        self.assert_refused("tty ancestry")

    def test_duplicate_discovered_target_identity_is_refused(self):
        devices = lab_device.discover()
        with mock.patch.object(lab_device, "discover", return_value=devices * 2):
            self.assert_refused("unique unchanged")

    def test_own_msc_is_required_and_another_devices_msc_does_not_count(self):
        (self.msc / "bInterfaceClass").write_text("02")
        other = self.usb / "other" / "other:1.2"
        other.mkdir(parents=True)
        (other / "bInterfaceClass").write_text("08")
        self.assert_refused("own MSC class08")

    def test_no_mount_duplicate_mount_or_mount_on_other_device_is_refused(self):
        for content in ("", self.mount_line * 2, self.mount_line.replace("8:48", "8:99")):
            with self.subTest(content=content):
                self.mountinfo.write_text(content)
                self.assert_refused("exactly one ancestry-matched")

    def test_rw_conflicting_ro_subtree_or_malformed_mount_is_refused_before_info_open(self):
        for content in (self.mount_line.replace(" ro ", " rw "),
                        self.mount_line.replace(" ro ", " ro,rw "),
                        self.mount_line.replace("/dev/sdd ro", "/dev/sdd rw"),
                        self.mount_line.replace("8:48 / ", "8:48 /subdir "),
                        self.mount_line.rstrip() + " extra\n"):
            with self.subTest(content=content):
                self.mountinfo.write_text(content)
                with mock.patch.object(lab_device.os, "open") as info_open:
                    self.assert_refused("read-only|malformed target mount")
                    info_open.assert_not_called()

    def test_same_serial_mount_on_different_usb_node_is_still_refused(self):
        other = self.usb / "other"
        other.mkdir()
        (other / "serial").write_text(self.serial)
        child = other / "block" / "sdd"
        child.mkdir(parents=True)
        (self.block_root / "8:48").unlink()
        (self.block_root / "8:48").symlink_to(child)
        self.assert_refused("mounted target volume ancestry")

    def test_expected_sense_board_aliases_are_accepted_but_base_or_duplicate_ids_are_not(self):
        self.info.write_text(self.INFO.replace("Seeed_XIAO_nRF52840_Sense", "nRF52840-SeeedXiaoSense-v1"))
        self.assertEqual(self.inspect()["board_id"], "nRF52840-SeeedXiaoSense-v1")
        for text in (self.INFO.replace("Seeed_XIAO_nRF52840_Sense", "nRF52840-SeeedXiao-v1"),
                     self.INFO + "Board-ID: Seeed_XIAO_nRF52840_Sense\n",
                     self.INFO.replace("Board-ID:", "Other-ID:")):
            with self.subTest(text=text):
                self.info.write_text(text)
                self.assert_refused("Board-ID")

    def test_wrong_duplicate_truncated_stock_versions_fail_without_custom_loader_claim(self):
        for text in (self.INFO.replace("0.6.1", "0.11.0"),
                     self.INFO.replace("0.6.1", "0.6.10"),
                     self.INFO.replace("7.3.0", "7.2.0"),
                     self.INFO.replace("S140", "S132"),
                     self.INFO + "UF2 Bootloader 0.6.1\n",
                     self.INFO + "SoftDevice: S140 version 7.3.0\n",
                     self.INFO.split("SoftDevice:")[0]):
            with self.subTest(text=text):
                self.info.write_text(text)
                self.assert_refused("stock bootloader 0.6.1 and S140 7.3.0")

    def test_info_read_is_bounded_at_exact_limit_and_rejects_invalid_encoding_or_nul(self):
        exact = self.INFO.encode() + b" " * (lab_device.STOCK_INFO_MAX_BYTES - len(self.INFO.encode()))
        self.info.write_bytes(exact)
        self.assertEqual(len(self.inspect()["vendor_info"].encode()), lab_device.STOCK_INFO_MAX_BYTES)
        for data, pattern in ((exact + b" ", "exceeds 4096"),
                              (b"\xff", "refusing read-only"),
                              (self.INFO.encode() + b"\x00", "NUL"),
                              (b"SECRET_CANARY_NO_ERROR_ECHO", "Board-ID")):
            with self.subTest(pattern=pattern):
                self.info.write_bytes(data)
                output = io.StringIO()
                with contextlib.redirect_stdout(output), self.assertRaisesRegex(SystemExit, pattern) as error:
                    lab_device.cmd_inspect_stock_bootloader(self.args)
                self.assertEqual(output.getvalue(), "")
                self.assertNotIn("SECRET_CANARY", str(error.exception))

    def test_missing_symlink_and_nonregular_info_are_refused_without_following_outside_volume(self):
        self.info.unlink()
        self.assert_refused("refusing read-only")
        outside = self.root / "other-info"
        outside.write_text(self.INFO)
        self.info.symlink_to(outside)
        self.assert_refused("refusing read-only")
        self.info.unlink()
        self.info.mkdir()
        self.assert_refused("regular file")

    def test_info_permission_or_msc_read_error_is_explicit(self):
        with mock.patch.object(lab_device.os, "open", side_effect=PermissionError(errno.EACCES, "denied")):
            self.assert_refused("denied")
        read_text = pathlib.Path.read_text

        def fault(path, *args, **kwargs):
            if path == self.msc / "bInterfaceClass":
                raise OSError(errno.EIO, "MSC read fault")
            return read_text(path, *args, **kwargs)

        with mock.patch.object(pathlib.Path, "read_text", autospec=True, side_effect=fault):
            self.assert_refused("MSC read fault")

    def test_mount_change_during_info_read_refuses_success(self):
        read_text = pathlib.Path.read_text
        calls = 0

        def changed(path, *args, **kwargs):
            nonlocal calls
            if path == self.mountinfo:
                calls += 1
                return self.mount_line if calls < 3 else self.mount_line.replace(" ro ", " rw ")
            return read_text(path, *args, **kwargs)

        with mock.patch.object(pathlib.Path, "read_text", autospec=True, side_effect=changed):
            self.assert_refused("mount records changed")

    def test_cli_is_target_only_and_cannot_request_entry_reset_or_install(self):
        with mock.patch.object(sys, "argv", ["lab_device.py", "inspect-stock-bootloader", "target"]), \
                mock.patch.object(lab_device, "cmd_inspect_stock_bootloader", return_value=0) as inspect:
            self.assertEqual(lab_device.main(), 0)
            self.assertEqual(inspect.call_args.args[0].role, "target")
        for arguments in (["client"], ["target", "--reset"], ["target", "--install"],
                          ["target", "--mode", "app"]):
            with self.subTest(arguments=arguments), \
                    mock.patch.object(sys, "argv", ["lab_device.py", "inspect-stock-bootloader", *arguments]), \
                    mock.patch.object(lab_device, "resolve") as resolve, mock.patch("sys.stderr"):
                with self.assertRaises(SystemExit):
                    lab_device.main()
                resolve.assert_not_called()


class SerialDfuRegressionTests(unittest.TestCase):
    def test_existing_cdc_only_bootloader_still_needs_no_touch_or_msc(self):
        ready = argparse.Namespace(mode=lab_device.MODE_BOOT,
                                   by_id=pathlib.Path("/dev/serial/by-id/authorized-target"))
        with mock.patch.object(lab_device, "resolve", return_value=ready), \
                mock.patch.object(lab_device, "_touch_1200") as touch, \
                mock.patch.object(lab_device, "wait_for") as wait, \
                mock.patch.object(lab_device, "_has_msc_interface") as msc:
            self.assertEqual(lab_device.cmd_bootloader_port("target", 30), ready.by_id)
            touch.assert_not_called()
            wait.assert_not_called()
            msc.assert_not_called()

    def test_application_serial_dfu_still_uses_the_original_1200_touch(self):
        app = argparse.Namespace(mode=lab_device.MODE_APP, by_id="stable-app")
        boot = argparse.Namespace(by_id="stable-boot")
        with mock.patch.object(lab_device, "resolve", return_value=app), \
                mock.patch.object(lab_device, "_touch_1200") as touch, \
                mock.patch.object(lab_device, "wait_for", return_value=boot) as wait:
            self.assertEqual(lab_device.cmd_bootloader_port("target", 30), boot.by_id)
            touch.assert_called_once_with(app.by_id)
            wait.assert_called_once_with("target", lab_device.MODE_BOOT, 30)


class ProtectedPowerDomainTests(unittest.TestCase):
    def test_power_control_refuses_protected_sibling_and_descendant_before_any_action(self):
        for target_path, protected_path in (
            ("1-4.2.3", "1-4.2.1.2"),
            ("1-4.2.3", "1-4.2.1"),
            ("1-4", "1-5.1"),
        ):
            with self.subTest(target=target_path, protected=protected_path):
                paths = {"77CD44653A967172": pathlib.Path(target_path),
                         "PROTECTED": pathlib.Path(protected_path)}
                args = argparse.Namespace(role="target", delay=3, mode="app", timeout=30)
                with mock.patch.object(lab_device, "load_roles", return_value={"target": "77CD44653A967172"}), \
                        mock.patch.object(lab_device, "load_protected", return_value={"pine": "PROTECTED"}), \
                        mock.patch.object(lab_device, "sysfs_for_serial", side_effect=paths.get), \
                        mock.patch.object(lab_device, "_run") as run, \
                        mock.patch.object(lab_device, "wait_for") as wait:
                    with self.assertRaisesRegex(SystemExit, "protected device shares"):
                        lab_device.cmd_power_cycle(args)
                    run.assert_not_called()
                    wait.assert_not_called()

    def test_protected_device_on_another_bus_does_not_block_isolated_port(self):
        paths = {"77CD44653A967172": pathlib.Path("8-4.4.3"),
                 "PROTECTED": pathlib.Path("1-4.2.1.2")}
        args = argparse.Namespace(role="target", delay=3, mode="app", timeout=30)
        ready = argparse.Namespace(by_id="/dev/serial/by-id/authorized-target")
        with mock.patch.object(lab_device, "load_roles", return_value={"target": "77CD44653A967172"}), \
                mock.patch.object(lab_device, "load_protected", return_value={"pine": "PROTECTED"}), \
                mock.patch.object(lab_device, "sysfs_for_serial", side_effect=paths.get), \
                mock.patch.object(lab_device, "_run", return_value=(0, "")) as run, \
                mock.patch.object(lab_device, "wait_for", return_value=ready), \
                mock.patch("builtins.print"):
            self.assertEqual(lab_device.cmd_power_cycle(args), 0)
            run.assert_called_once_with(
                ["sudo", "-n", "uhubctl", "-f", "-l", "8-4.4", "-p", "3",
                 "-a", "cycle", "-d", "3"], lab_device.UHUBCTL_TIMEOUT)


class ApplicationPackageTests(unittest.TestCase):
    def setUp(self):
        scratch = lab_device.REPO_ROOT / ".tmp"
        scratch.mkdir(exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.scratch.cleanup)
        self.package = pathlib.Path(self.scratch.name) / "firmware.zip"

    def write_package(self, entries=None, image=b"\x00" * 32, init_packet=b"init"):
        if entries is None:
            entries = {"application": {"bin_file": "firmware.bin", "dat_file": "firmware.dat"}}
        with zipfile.ZipFile(self.package, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"manifest": {**entries, "dfu_version": 0.5}}))
            archive.writestr("firmware.bin", image)
            archive.writestr("firmware.dat", init_packet)

    def assert_rejected_before_dfu(self, message):
        args = argparse.Namespace(role="target", package=str(self.package), timeout=30)
        with mock.patch.object(lab_device, "cmd_bootloader_port") as bootloader, \
                mock.patch.object(lab_device.subprocess, "run") as run:
            with self.assertRaisesRegex(SystemExit, message):
                lab_device.cmd_flash(args)
        bootloader.assert_not_called()
        run.assert_not_called()

    def test_valid_application_package_passes_without_device_access(self):
        self.write_package()
        with mock.patch.object(lab_device, "resolve") as resolve:
            lab_device.validate_application_package(self.package)
        resolve.assert_not_called()

    def test_application_flash_selects_literal_active_roles_without_touching_existing_dfu_or_extra_regions(self):
        self.write_package()
        script = pathlib.Path(self.scratch.name) / "adafruit-nrfutil.py"
        script.touch()
        for role, serial in (("client", "4186AE911D94CDB1"), ("target", "77CD44653A967172")):
            with self.subTest(role=role):
                device = argparse.Namespace(serial=serial, mode=lab_device.MODE_BOOT,
                                            by_id=f"/dev/serial/by-id/{serial}")
                args = argparse.Namespace(role=role, package=str(self.package), timeout=30)
                with mock.patch.dict(lab_device.os.environ, {"ADAFRUIT_NRFUTIL": str(script)}), \
                        mock.patch.object(lab_device, "load_roles", return_value={role: serial}), \
                        mock.patch.object(lab_device, "discover", return_value=[device]), \
                        mock.patch.object(lab_device, "_touch_1200") as touch, \
                        mock.patch.object(lab_device, "wait_for", return_value=device) as wait, \
                        mock.patch.object(lab_device.subprocess, "run",
                                          return_value=argparse.Namespace(
                                              returncode=0, stdout=b"#\n#########Device programmed.\n", stderr=b"")) as run, \
                        mock.patch("builtins.print"), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(lab_device.cmd_flash(args), 0)
                    run.assert_called_once_with(
                        [sys.executable, str(script), "dfu", "serial", "-pkg", str(self.package),
                         "-p", device.by_id, "-b", "115200", "--singlebank"],
                        env=mock.ANY, capture_output=True)
                    touch.assert_not_called()
                    wait.assert_called_once_with(role, lab_device.MODE_APP, 30)

    def test_application_flash_refuses_failed_target_pine_and_old_device_substitution_before_dfu(self):
        self.write_package()
        script = pathlib.Path(self.scratch.name) / "adafruit-nrfutil.py"
        script.touch()
        for assigned, attached in (("3BE94917B92DC5E9", "3BE94917B92DC5E9"),
                                   ("49C5BAF21EEF44A1", "49C5BAF21EEF44A1"),
                                   ("77CD44653A967172", "3BE94917B92DC5E9")):
            with self.subTest(assigned=assigned, attached=attached):
                device = argparse.Namespace(serial=attached, mode=lab_device.MODE_BOOT, tty="ttyACM4")
                args = argparse.Namespace(role="target", package=str(self.package), timeout=30)
                with mock.patch.dict(lab_device.os.environ, {"ADAFRUIT_NRFUTIL": str(script)}), \
                        mock.patch.object(lab_device, "load_roles", return_value={"target": assigned}), \
                        mock.patch.object(lab_device, "discover", return_value=[device]), \
                        mock.patch.object(lab_device, "_attached_usb_diagnostics", return_value=[]), \
                        mock.patch.object(lab_device, "_touch_1200") as touch, \
                        mock.patch.object(lab_device, "wait_for") as wait, \
                        mock.patch.object(lab_device.subprocess, "run") as run:
                    with self.assertRaises(SystemExit):
                        lab_device.cmd_flash(args)
                    touch.assert_not_called()
                    wait.assert_not_called()
                    run.assert_not_called()

    def test_bootloader_softdevice_and_combined_packages_cannot_enter_dfu(self):
        app = {"bin_file": "firmware.bin", "dat_file": "firmware.dat"}
        for entries in ({"bootloader": app}, {"softdevice": app},
                        {"application": app, "bootloader": app}, {"softdevice_bootloader": app}):
            with self.subTest(entries=entries):
                self.write_package(entries)
                self.assert_rejected_before_dfu("application-only")

    def test_application_that_overlaps_filesystem_cannot_enter_dfu(self):
        self.write_package(image=b"\x00" * (0xAD000 + 4))
        self.assert_rejected_before_dfu("out of bounds")

    def test_incomplete_application_package_cannot_enter_dfu(self):
        self.write_package(init_packet=b"")
        self.assert_rejected_before_dfu("init packet is empty")
        self.write_package({"application": {"bin_file": "missing.bin", "dat_file": "firmware.dat"}})
        self.assert_rejected_before_dfu("missing")

    def test_extracted_image_matches_validated_package_without_device_access(self):
        image = b"\x12\x34\x56\x78" * 8
        self.write_package(image=image)
        output = pathlib.Path(self.scratch.name) / "candidate.bin"
        args = argparse.Namespace(package=str(self.package), output=str(output))
        with mock.patch.object(lab_device, "resolve") as resolve, mock.patch("builtins.print"):
            self.assertEqual(lab_device.cmd_extract_application(args), 0)
        resolve.assert_not_called()
        self.assertEqual(output.read_bytes(), image)

    def test_extraction_preserves_existing_image_and_refuses_invalid_package(self):
        self.write_package()
        output = pathlib.Path(self.scratch.name) / "candidate.bin"
        output.write_bytes(b"existing recovery image")
        args = argparse.Namespace(package=str(self.package), output=str(output))
        with self.assertRaisesRegex(SystemExit, "refusing to overwrite"):
            lab_device.cmd_extract_application(args)
        self.assertEqual(output.read_bytes(), b"existing recovery image")
        output = pathlib.Path(self.scratch.name) / "invalid.bin"
        self.write_package({"bootloader": {"bin_file": "firmware.bin", "dat_file": "firmware.dat"}})
        with self.assertRaisesRegex(SystemExit, "application-only"):
            lab_device.cmd_extract_application(
                argparse.Namespace(package=str(self.package), output=str(output)))
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
