import argparse
import contextlib
import errno
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
        self.serial = "3BE94917B92DC5E9"
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
        for serial in ("4186AE911D94CDB1", "49C5BAF21EEF44A1", "UNKNOWN"):
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
                paths = {"TARGET": pathlib.Path(target_path),
                         "PROTECTED": pathlib.Path(protected_path)}
                args = argparse.Namespace(role="target", delay=3, mode="app", timeout=30)
                with mock.patch.object(lab_device, "load_roles", return_value={"target": "TARGET"}), \
                        mock.patch.object(lab_device, "load_protected", return_value={"pine": "PROTECTED"}), \
                        mock.patch.object(lab_device, "sysfs_for_serial", side_effect=paths.get), \
                        mock.patch.object(lab_device, "_run") as run, \
                        mock.patch.object(lab_device, "wait_for") as wait:
                    with self.assertRaisesRegex(SystemExit, "protected device shares"):
                        lab_device.cmd_power_cycle(args)
                    run.assert_not_called()
                    wait.assert_not_called()

    def test_protected_device_on_another_bus_does_not_block_isolated_port(self):
        paths = {"TARGET": pathlib.Path("8-4.4.3"),
                 "PROTECTED": pathlib.Path("1-4.2.1.2")}
        args = argparse.Namespace(role="target", delay=3, mode="app", timeout=30)
        ready = argparse.Namespace(by_id="/dev/serial/by-id/authorized-target")
        with mock.patch.object(lab_device, "load_roles", return_value={"target": "TARGET"}), \
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
