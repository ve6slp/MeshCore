#!/usr/bin/env python3

import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "bootloader/xiao_nrf52840_ota/tools/install_uf2.py"
SPEC = importlib.util.spec_from_file_location("install_uf2", SCRIPT)
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)

# A board identity that exists only for this test's fake sysfs tree.
TEST_SERIAL = "LABTESTSERIAL0001"


class GuardedInstallerTest(unittest.TestCase):
    def setUp(self):
        # Authorise only the fixture board, isolated from the real inventory.
        patcher = mock.patch.object(INSTALLER, "authorized_serials",
                                    return_value={TEST_SERIAL})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.work = ROOT / ".tmp" / "test-install-uf2" / self._testMethodName
        shutil.rmtree(self.work, ignore_errors=True)
        (self.work / "dev/serial/by-id").mkdir(parents=True)
        (self.work / "dev").mkdir(exist_ok=True)
        (self.work / "sys/dev/char").mkdir(parents=True)
        (self.work / "sys/dev/block").mkdir(parents=True)
        (self.work / "sys/devices/usb/1-1/1-1:1.0").mkdir(parents=True)
        (self.work / "sys/devices/usb/1-1/serial").write_text(
            TEST_SERIAL, encoding="utf-8"
        )

        self.device = self.work / "dev/boot-device"
        self.device.touch()
        self.boot_port = (
            self.work
            / "dev/serial/by-id"
            / f"usb-Seeed_Studio_XIAO-BOOT_{TEST_SERIAL}-if00"
        )
        self.boot_port.symlink_to(self.device)
        stat_result = self.device.stat()
        char_link = self.work / "sys/dev/char" / (
            f"{os.major(stat_result.st_rdev)}:{os.minor(stat_result.st_rdev)}"
        )
        char_link.symlink_to(self.work / "sys/devices/usb/1-1/1-1:1.0")

        self.volume = self.work / "media/XIAO-BOOT"
        self.volume.mkdir(parents=True)
        (self.volume / "INFO_UF2.TXT").write_text(
            f"UF2 Bootloader\nBoard-ID: {INSTALLER.BOARD_ID}\n", encoding="utf-8"
        )
        (self.work / "sys/devices/usb/1-1/1-1:1.0/block/sdz/sdz1").mkdir(
            parents=True
        )
        (self.work / "sys/dev/block/8:99").symlink_to(
            self.work / "sys/devices/usb/1-1/1-1:1.0/block/sdz/sdz1"
        )
        self.mountinfo = self.work / "mountinfo"
        self.mountinfo.write_text(
            f"1 0 8:99 / {self.volume} rw - vfat /dev/sdz1 rw\n",
            encoding="utf-8",
        )
        self.artifact = self.work / "xiao_nrf52840_ota_noswd_update.uf2"
        block = bytearray(512)
        struct.pack_into(
            "<II",
            block,
            0,
            INSTALLER.UF2_MAGIC_START0,
            INSTALLER.UF2_MAGIC_START1,
        )
        struct.pack_into("<II", block, 20, 0, 1)
        struct.pack_into("<I", block, 508, INSTALLER.UF2_MAGIC_END)
        self.artifact.write_bytes(block)

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def args(self, **changes):
        values = dict(
            serial=TEST_SERIAL,
            boot_port=str(self.boot_port),
            artifact=str(self.artifact),
            dry_run=True,
            by_id_dir=str(self.work / "dev/serial/by-id"),
            mountinfo=str(self.mountinfo),
            sys_dev_char_root=str(self.work / "sys/dev/char"),
            sys_dev_block_root=str(self.work / "sys/dev/block"),
        )
        values.update(changes)
        return argparse.Namespace(**values)

    def test_dry_run_validates_without_copying(self):
        INSTALLER.install(self.args())
        self.assertFalse((self.volume / self.artifact.name).exists())

    def test_install_copies_only_to_validated_volume(self):
        with mock.patch.object(INSTALLER.os, "sync") as sync:
            INSTALLER.install(self.args(dry_run=False))
        self.assertEqual(
            (self.volume / self.artifact.name).read_bytes(),
            self.artifact.read_bytes(),
        )
        sync.assert_called_once_with()

    def test_rejects_unauthorized_serial(self):
        with self.assertRaisesRegex(ValueError, "not a configured lab board"):
            INSTALLER.install(self.args(serial="OTHER"))

    def test_rejects_wrong_board(self):
        (self.volume / "INFO_UF2.TXT").write_text(
            "Board-ID: wrong-board\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "wrong UF2 board ID"):
            INSTALLER.install(self.args())

    def test_rejects_ambiguous_mounts(self):
        second = self.work / "media/SECOND"
        second.mkdir()
        self.mountinfo.write_text(
            self.mountinfo.read_text(encoding="utf-8")
            + f"2 0 8:99 / {second} rw - vfat /dev/sdz1 rw\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            INSTALLER.install(self.args())

    def test_rejects_missing_artifact(self):
        with self.assertRaisesRegex(ValueError, "missing bootloader artifact"):
            INSTALLER.install(self.args(artifact=str(self.work / "missing.uf2")))

    def test_rejects_unstable_port_name(self):
        with self.assertRaisesRegex(ValueError, "stable authorized identity"):
            INSTALLER.install(self.args(boot_port=str(self.device)))

    def test_rejects_wrong_usb_ancestry_serial(self):
        (self.work / "sys/devices/usb/1-1/serial").write_text(
            "OTHER", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "USB ancestry serial"):
            INSTALLER.install(self.args())


if __name__ == "__main__":
    unittest.main()
