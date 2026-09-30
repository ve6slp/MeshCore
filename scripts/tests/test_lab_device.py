import argparse
import pathlib
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import lab_device


class CompanionResetTests(unittest.TestCase):
    def test_reset_uses_companion_reboot_and_requires_reenumeration(self):
        device = argparse.Namespace(by_id="/dev/serial/by-id/authorized-target")
        args = argparse.Namespace(role="target", timeout=30)
        serial_factory = mock.MagicMock()
        port = serial_factory.return_value.__enter__.return_value
        port.write.return_value = 10
        with mock.patch.dict(sys.modules, {"serial": types.SimpleNamespace(Serial=serial_factory)}), \
                mock.patch.object(lab_device, "resolve", return_value=device), \
                mock.patch.object(lab_device, "wait_for", return_value=device) as wait, \
                mock.patch("builtins.print"):
            self.assertEqual(lab_device.cmd_reset(args), 0)
        port.write.assert_called_once_with(b"<\x07\x00\x13reboot")
        wait.assert_called_once_with("target", lab_device.MODE_APP, 30, absent_first=True)

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


if __name__ == "__main__":
    unittest.main()
