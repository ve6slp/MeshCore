import argparse
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
