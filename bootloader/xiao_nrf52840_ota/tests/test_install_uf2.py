#!/usr/bin/env python3

import argparse
import binascii
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "bootloader/xiao_nrf52840_ota/tools/install_uf2.py"
SPEC = importlib.util.spec_from_file_location("install_uf2", SCRIPT)
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)
BOOT_INFO = INSTALLER.boot_info

# A board identity that exists only for this test's fake sysfs tree.
TEST_SERIAL = "LABTESTSERIAL0001"
TEST_KEY_BYTES = bytes(range(32))


def _build_marker_bytes(board="xiao_nrf52840", key_bytes=TEST_KEY_BYTES):
    before_crc = struct.pack(
        "<IHHIIIHH32s",
        BOOT_INFO.BOOT_INFO_MAGIC, BOOT_INFO.BOOT_INFO_FORMAT_VERSION,
        BOOT_INFO.BOOT_INFO_STRUCT_BYTES, BOOT_INFO.BOARD_TARGET_VALUE[board],
        BOOT_INFO.ROLE_ANY, BOOT_INFO.CAP_QSPI_INSTALL, BOOT_INFO.KEY_ID,
        BOOT_INFO.ALGORITHM_ED25519, key_bytes,
    )
    crc = binascii.crc32(before_crc) & 0xFFFFFFFF
    return before_crc + struct.pack("<I", crc)


def _uf2_block(target_addr, payload, block_no, num_blocks,
               family_id=None):
    family_id = INSTALLER.UF2_FAMILY_ID_BOOTLOADER if family_id is None else family_id
    header = struct.pack(
        "<IIIIIIII", INSTALLER.UF2_MAGIC_START0, INSTALLER.UF2_MAGIC_START1,
        0x2000, target_addr, len(payload), block_no, num_blocks, family_id,
    )
    body = header + payload
    body += b"\x00" * (512 - len(body) - 4)
    return body + struct.pack("<I", INSTALLER.UF2_MAGIC_END)


def _genuine_uf2(marker=None, extra_blocks=()):
    """Build a small but genuinely-shaped no-SWD bootloader-update UF2:
    one block in the MBR page, one in the bootloader code region, the
    boot-info marker block at its real fixed address, one in UICR, plus
    any caller-supplied extra blocks appended at the end. Every block uses
    the real bootloader-update family ID and permitted address ranges
    unless a test deliberately overrides one via extra_blocks."""
    marker = _build_marker_bytes() if marker is None else marker
    blocks = [
        (0x0, b"\x00" * 32),
        (0xF4000, b"\x11" * 256),
        (BOOT_INFO.BOOT_INFO_ADDRESS, marker),
        (0x10001000, b"\x22" * 8),
    ]
    blocks.extend(extra_blocks)
    num_blocks = len(blocks)
    data = b"".join(
        _uf2_block(addr, payload, i, num_blocks)
        for i, (addr, payload) in enumerate(blocks)
    )
    return data


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
        self.artifact.write_bytes(_genuine_uf2())

        self.key_header = self.work / "test_public_key.h"
        self.key_header.write_text(
            "#define XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES \\\n    "
            + ", ".join(f"0x{b:02x}" for b in TEST_KEY_BYTES)
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def args(self, **changes):
        values = dict(
            serial=TEST_SERIAL,
            boot_port=str(self.boot_port),
            artifact=str(self.artifact),
            dry_run=True,
            validate_only=False,
            board="xiao_nrf52840",
            key_header=str(self.key_header),
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

    def _replace_artifact(self, data):
        artifact = self.work / "replacement.uf2"
        artifact.write_bytes(data)
        return str(artifact)

    def test_rejects_block_targeting_app_region(self):
        # 0x27000 is inside the application image / ExtraFS region, which a
        # bootloader-update UF2 must never be permitted to touch.
        data = _genuine_uf2(extra_blocks=[(0x27000, b"\xAA" * 32)])
        artifact = self._replace_artifact(data)
        with self.assertRaisesRegex(ValueError, "outside the permitted"):
            INSTALLER.install(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_rejects_block_targeting_settings_page(self):
        # 0xFF000 is the durable bootloader-settings page (bank/CRC/size
        # metadata and this project's anti-rollback floor/command records).
        data = _genuine_uf2(extra_blocks=[(0xFF000, b"\xAA" * 32)])
        artifact = self._replace_artifact(data)
        with self.assertRaisesRegex(ValueError, "outside the permitted"):
            INSTALLER.install(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_rejects_oversized_payload(self):
        block = bytearray(_uf2_block(0xF4000, b"\x11" * 32, 0, 1))
        struct.pack_into("<I", block, 16, 477)  # declare payload_size > 476
        artifact = self._replace_artifact(bytes(block))
        with self.assertRaisesRegex(ValueError, "payload_size"):
            INSTALLER.install(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_rejects_wrong_family_id(self):
        data = _genuine_uf2()
        blocks = bytearray(data)
        # Corrupt every block's family_id (offset 28 within each 512-byte
        # block) to a plausible-but-wrong value (the generic app family).
        for off in range(0, len(blocks), 512):
            struct.pack_into("<I", blocks, off + 28, 0xADA52840)
        artifact = self._replace_artifact(bytes(blocks))
        with self.assertRaisesRegex(ValueError, "family_id"):
            INSTALLER.install(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_rejects_wrong_boot_info_board(self):
        data = _genuine_uf2(marker=_build_marker_bytes(board="sensecap_solar_p1"))
        artifact = self._replace_artifact(data)
        with self.assertRaisesRegex(ValueError, "boot-info marker"):
            INSTALLER.install(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_rejects_wrong_boot_info_key(self):
        data = _genuine_uf2(marker=_build_marker_bytes(key_bytes=bytes(range(1, 33))))
        artifact = self._replace_artifact(data)
        with self.assertRaisesRegex(ValueError, "boot-info marker"):
            INSTALLER.install(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_validate_only_needs_no_serial_or_device_resolution(self):
        # --validate-only must accept a genuine artifact with no serial,
        # boot port, or mounted-volume resolution: point those fields at
        # values that do not exist and confirm nothing is touched.
        args = self.args(
            validate_only=True,
            serial=None,
            boot_port=str(self.work / "no-such-boot-port"),
            mountinfo=str(self.work / "no-such-mountinfo"),
        )
        INSTALLER.install(args)  # must not raise
        self.assertFalse((self.volume / self.artifact.name).exists())

    def test_validate_only_still_rejects_bad_artifact(self):
        data = _genuine_uf2(extra_blocks=[(0x27000, b"\xAA" * 32)])
        artifact = self._replace_artifact(data)
        args = self.args(
            artifact=artifact,
            validate_only=True,
            serial=None,
            boot_port=str(self.work / "no-such-boot-port"),
            mountinfo=str(self.work / "no-such-mountinfo"),
        )
        with self.assertRaisesRegex(ValueError, "outside the permitted"):
            INSTALLER.install(args)

    def test_parse_args_requires_serial_and_port_unless_validate_only(self):
        with mock.patch.object(
            sys, "argv",
            ["install_uf2.py", "--artifact", str(self.artifact)],
        ):
            with self.assertRaises(SystemExit):
                INSTALLER.parse_args()

    def test_parse_args_allows_validate_only_without_serial_or_port(self):
        with mock.patch.object(
            sys, "argv",
            ["install_uf2.py", "--artifact", str(self.artifact), "--validate-only"],
        ):
            args = INSTALLER.parse_args()
        self.assertTrue(args.validate_only)
        self.assertIsNone(args.serial)
        self.assertIsNone(args.boot_port)


if __name__ == "__main__":
    unittest.main()
