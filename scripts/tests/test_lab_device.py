import argparse
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import lab_device


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
