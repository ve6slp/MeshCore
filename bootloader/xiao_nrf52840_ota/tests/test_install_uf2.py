#!/usr/bin/env python3

import argparse
import binascii
from datetime import datetime, timedelta, timezone
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import sys
import unittest
from unittest import mock
import subprocess
import zipfile
import json


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "bootloader/xiao_nrf52840_ota/tools/install_uf2.py"
SPEC = importlib.util.spec_from_file_location("install_uf2", SCRIPT)
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)
BOOT_INFO = INSTALLER.boot_info

# A board identity that exists only for this test's fake sysfs tree.
TEST_SERIAL = "LABTESTSERIAL0001"
TEST_KEY_BYTES = bytes(range(32))


def _build_marker_bytes(board="xiao_nrf52840", key_bytes=TEST_KEY_BYTES, role_id=0):
    before_crc = struct.pack(
        "<IHHIIIHH32s",
        BOOT_INFO.BOOT_INFO_MAGIC, BOOT_INFO.BOOT_INFO_FORMAT_VERSION,
        BOOT_INFO.BOOT_INFO_STRUCT_BYTES, BOOT_INFO.BOARD_TARGET_VALUE[board],
        role_id, BOOT_INFO.CAP_QSPI_INSTALL, BOOT_INFO.KEY_ID,
        BOOT_INFO.ALGORITHM_ED25519, key_bytes,
    )
    crc = binascii.crc32(before_crc) & 0xFFFFFFFF
    return before_crc + struct.pack("<I", crc)


def _uf2_block(target_addr, payload, block_no, num_blocks,
               family_id=None, flags=0x2000):
    family_id = INSTALLER.UF2_FAMILY_ID_BOOTLOADER if family_id is None else family_id
    header = struct.pack(
        "<IIIIIIII", INSTALLER.UF2_MAGIC_START0, INSTALLER.UF2_MAGIC_START1,
        flags, target_addr, len(payload), block_no, num_blocks, family_id,
    )
    body = header + payload
    body += b"\x00" * (512 - len(body) - 4)
    return body + struct.pack("<I", INSTALLER.UF2_MAGIC_END)


def _cf2_bytes(boot_id=0x28860044):
    pairs = ((204, 0x100000), (205, 0x40000), (208, boot_id),
             (209, 0xADA52840), (210, 0x20))
    return struct.pack("<IIII", 0x1E9E10F1, 0x20227A79, len(pairs), 100) + b"".join(
        struct.pack("<II", *pair) for pair in pairs)


def _genuine_uf2(marker=None, extra_blocks=(), cf2_id=0x28860044, cf2=None):
    """Build a small but genuinely-shaped no-SWD bootloader-update UF2:
    one block in the MBR page, one in the bootloader code region, the
    public CF2 identity, the boot-info marker at its real fixed address, one in UICR, plus
    any caller-supplied extra blocks appended at the end. Every block uses
    the real bootloader-update family ID and permitted address ranges
    unless a test deliberately overrides one via extra_blocks."""
    marker = _build_marker_bytes() if marker is None else marker
    blocks = [
        (0x0, b"\x00" * 32),
        (0xF4000, struct.pack("<II", 0x20040000, 0xF4081) + b"\x11" * 248),
        (0xFD800, _cf2_bytes(cf2_id) if cf2 is None else cf2),
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


def _hex_from_uf2(data):
    def record(address, kind, payload):
        raw = bytes([len(payload)]) + struct.pack(">H", address) + bytes([kind]) + payload
        return ":" + (raw + bytes([-sum(raw) & 0xFF])).hex().upper() + "\n"

    output = ""
    for offset in range(0, len(data), 512):
        address, size = struct.unpack_from("<II", data, offset + 12)
        output += record(0, 4, struct.pack(">H", address >> 16))
        for start in range(0, size, 16):
            output += record((address + start) & 0xFFFF, 0,
                             data[offset + 32 + start:offset + 32 + min(start + 16, size)])
    return output + record(0, 1, b"")


def _arm_elf(raw, version=None):
    version = INSTALLER.preparation.BOOTLOADER_VERSION if version is None else version
    strings = b"\0" + INSTALLER.preparation.VERSION_SYMBOL.encode("ascii") + b"\0"
    load_offset = 84
    string_offset = load_offset + len(raw)
    sym_offset = string_offset + len(strings)
    symbols = b"\0" * 16 + struct.pack("<IIIBBH", 1, version, 0, 0x10, 0, 0xFFF1)
    shoff = sym_offset + len(symbols)
    header = b"\x7fELF\x01\x01\x01" + b"\0" * 9 + struct.pack(
        "<HHIIIIIHHHHHH", 2, 40, 1, 0xF4081, 52, shoff, 0x05000000, 52, 32, 1, 40, 6, 0)
    program = struct.pack("<8I", 1, load_offset, INSTALLER.BOOT_START,
                          INSTALLER.BOOT_START, len(raw), len(raw), 5, 4)
    sections = b"\0" * 40 + struct.pack(
        "<10I", 0, 3, 0, 0, string_offset, len(strings), 0, 0, 1, 0) + struct.pack(
        "<10I", 0, 2, 0, 0, sym_offset, len(symbols), 1, 0, 4, 16)
    for address, size in ((0xF4000, 0x9800), (0xFD800, 0x400), (0xFDC00, 0x100)):
        sections += struct.pack("<10I", 0, 1, 2, address,
                                load_offset + address - INSTALLER.BOOT_START, size, 0, 0, 4, 0)
    return header + program + raw + strings + symbols + sections


class GuardedInstallerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package_work = ROOT / ".tmp/test-install-serial-package"
        shutil.rmtree(cls.package_work, ignore_errors=True)
        cls.package_work.mkdir(parents=True)
        cls.addClassCleanup(shutil.rmtree, cls.package_work)
        data = _genuine_uf2(marker=_build_marker_bytes(
            board="xiao_nrf52840_sense", role_id=1), cf2_id=0x28860045)
        cls.package_artifact = cls.package_work / "source.uf2"
        cls.package_artifact.write_bytes(data)
        cls.package_hex = cls.package_work / "source.hex"
        cls.package_hex.write_text(_hex_from_uf2(data))
        cls.package_raw = BOOT_INFO.read_uf2_bytes(
            cls.package_artifact, INSTALLER.BOOT_START, INSTALLER.BOOT_BYTES)
        cls.package_elf = cls.package_work / "source.elf"
        cls.package_elf.write_bytes(_arm_elf(cls.package_raw))
        cls.nrfutil = Path.home() / ".platformio/packages/tool-adafruit-nrfutil/adafruit-nrfutil.py"
        args = argparse.Namespace(
            artifact=cls.package_artifact, hex_artifact=cls.package_hex,
            elf_artifact=cls.package_elf, board="xiao_nrf52840_sense", role_id=1,
            validate_only=False, emit_serial_package=cls.package_work / "output",
            nrfutil=cls.nrfutil)
        # Exercise the actual installed vendor generator, never a parallel ZIP generator.
        INSTALLER.install(args)
        cls.package_zip = args.emit_serial_package / "bootloader.zip"

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
        patcher = mock.patch.object(INSTALLER, "SERIAL_LOG_ROOT", self.work)
        patcher.start()
        self.addCleanup(patcher.stop)
        (self.work / "sys/dev/char").mkdir(parents=True)
        (self.work / "sys/dev/block").mkdir(parents=True)
        (self.work / "sys/devices/usb/1-1/1-1:1.0").mkdir(parents=True)
        (self.work / "sys/devices/usb/1-1/serial").write_text(
            TEST_SERIAL, encoding="utf-8"
        )
        (self.work / "sys/devices/usb/1-1/idVendor").write_text("2886")
        (self.work / "sys/devices/usb/1-1/idProduct").write_text("0044")
        (self.work / "sys/devices/usb/1-1/product").write_text("XIAO-BOOT")
        (self.work / "sys/devices/usb/1-1/1-1:1.0/tty/boot-device").mkdir(
            parents=True
        )
        for attribute, value in (
            ("BY_ID_DIR", self.work / "dev/serial/by-id"),
            ("USB_DEVICES", self.work / "sys/devices/usb"),
        ):
            patcher = mock.patch.object(INSTALLER.lab_device, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)

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
        INSTALLER.validate_public_identity(self.args())
        self.assertFalse((self.volume / self.artifact.name).exists())

    def test_public_identity_probe_never_copies_to_validated_volume(self):
        with mock.patch.object(INSTALLER.os, "sync") as sync:
            INSTALLER.validate_public_identity(self.args(dry_run=False))
        self.assertFalse((self.volume / self.artifact.name).exists())
        sync.assert_not_called()

    def test_rejects_unauthorized_serial(self):
        with self.assertRaisesRegex(ValueError, "not a configured lab board"):
            INSTALLER.validate_public_identity(self.args(serial="OTHER"))

    def test_rejects_wrong_board(self):
        (self.volume / "INFO_UF2.TXT").write_text(
            "Board-ID: wrong-board\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "wrong UF2 board ID"):
            INSTALLER.validate_public_identity(self.args())

    def test_rejects_ambiguous_mounts(self):
        second = self.work / "media/SECOND"
        second.mkdir()
        self.mountinfo.write_text(
            self.mountinfo.read_text(encoding="utf-8")
            + f"2 0 8:99 / {second} rw - vfat /dev/sdz1 rw\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            INSTALLER.validate_public_identity(self.args())

    def test_rejects_missing_artifact(self):
        with self.assertRaisesRegex(ValueError, "missing bootloader artifact"):
            INSTALLER.validate_public_identity(self.args(artifact=str(self.work / "missing.uf2")))

    def test_rejects_unstable_port_name(self):
        with self.assertRaisesRegex(ValueError, "stable authorized identity"):
            INSTALLER.validate_public_identity(self.args(boot_port=str(self.device)))

    def _use_sense_identity(self, pid="0045"):
        self.boot_port.unlink()
        self.boot_port = (
            self.work / "dev/serial/by-id"
            / f"usb-Seeed_XIAO_nRF52840_Sense_{TEST_SERIAL}-if00"
        )
        self.boot_port.symlink_to(self.device)
        (self.work / "sys/devices/usb/1-1/idProduct").write_text(pid)
        (self.work / "sys/devices/usb/1-1/product").write_text("XIAO nRF52840 Sense")

    def test_sense_vendor_identity_uses_shared_discovery(self):
        self._use_sense_identity(pid="0044")
        INSTALLER.validate_public_identity(self.args())
        self.assertFalse((self.volume / self.artifact.name).exists())
        with mock.patch.object(INSTALLER.os, "sync"):
            INSTALLER.validate_public_identity(self.args(dry_run=False))
        self.assertFalse((self.volume / self.artifact.name).exists())

    def test_sense_product_does_not_bypass_board_id_guard(self):
        self._use_sense_identity(pid="0044")
        (self.volume / "INFO_UF2.TXT").write_text(
            "Board-ID: nRF52840-SeeedXiaoSense-v1\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "wrong UF2 board ID"):
            INSTALLER.validate_public_identity(self.args(dry_run=False))
        self.assertFalse((self.volume / self.artifact.name).exists())

    def _sense_artifact(self, role_id=1):
        data = _genuine_uf2(
            marker=_build_marker_bytes(board="xiao_nrf52840_sense", role_id=role_id),
            cf2_id=0x28860045)
        return self._replace_artifact(data)

    def _sense_volume(self, board_id="Seeed_XIAO_nRF52840_Sense"):
        self._use_sense_identity()
        (self.volume / "INFO_UF2.TXT").write_text(
            "UF2 Bootloader 0.6.1 lib/nrfx (v2.0.0) lib/tinyusb (0.10.1-293-gaf8e5a90) "
            "lib/uf2 (remotes/origin/configupdate-9-gadbb8c7)\n"
            "Model: Seeed XIAO nRF52840\n"
            f"Board-ID: {board_id}\n"
            "SoftDevice: S140 version 7.3.0\n"
            "Date: Nov 12 2021\n")

    def test_sense_profile_matches_legacy_and_pinned_board_ids_without_copying(self):
        artifact = self._sense_artifact()
        self._sense_volume()
        for board_id in INSTALLER.BOARD_IDS["xiao_nrf52840_sense"]:
            with self.subTest(board_id=board_id):
                (self.volume / "INFO_UF2.TXT").write_text(f"Board-ID: {board_id}\n")
                args = self.args(board="xiao_nrf52840_sense", role_id=1, artifact=artifact)
                INSTALLER.validate_public_identity(args)
                self.assertFalse((self.volume / "replacement.uf2").exists())
        with mock.patch.object(INSTALLER.os, "sync"):
            INSTALLER.validate_public_identity(self.args(board="xiao_nrf52840_sense", role_id=1,
                                        artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_base_artifact_cannot_be_relabelled_as_sense_even_in_validate_only(self):
        with self.assertRaisesRegex(ValueError, "artifact CF2.*28860044"):
            INSTALLER.validate_public_identity(self.args(board="xiao_nrf52840_sense", validate_only=True))
        self.assertFalse((self.volume / self.artifact.name).exists())

    def test_sense_artifact_cannot_be_relabelled_as_base(self):
        artifact = self._sense_artifact(role_id=0)
        with self.assertRaisesRegex(ValueError, "artifact CF2.*28860045"):
            INSTALLER.validate_public_identity(self.args(artifact=artifact, validate_only=True))

    def test_sense_validate_only_does_not_read_current_media(self):
        artifact = self._sense_artifact()
        with mock.patch.object(INSTALLER, "matching_mounts") as mounts, \
                mock.patch.object(INSTALLER.lab_device, "discover") as discover:
            INSTALLER.validate_public_identity(self.args(board="xiao_nrf52840_sense", role_id=1,
                                        artifact=artifact, validate_only=True))
        mounts.assert_not_called()
        discover.assert_not_called()

    def test_base_artifact_is_rejected_on_live_sense_usb_even_with_base_info(self):
        self._use_sense_identity()
        with self.assertRaisesRegex(ValueError, "USB VID/PID.*28860045"):
            INSTALLER.validate_public_identity(self.args(dry_run=False))
        self.assertFalse((self.volume / self.artifact.name).exists())

    def test_sense_artifact_is_rejected_on_base_usb_even_with_sense_info(self):
        artifact = self._sense_artifact()
        (self.volume / "INFO_UF2.TXT").write_text("Board-ID: Seeed_XIAO_nRF52840_Sense\n")
        with self.assertRaisesRegex(ValueError, "USB VID/PID.*28860044"):
            INSTALLER.validate_public_identity(self.args(board="xiao_nrf52840_sense", role_id=1,
                                        artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_sense_profile_refuses_base_and_unknown_current_board_ids(self):
        artifact = self._sense_artifact()
        self._sense_volume()
        for board_id in (INSTALLER.BOARD_ID, "Seeed_XIAO_nRF52840_Sense_unknown", "unknown"):
            with self.subTest(board_id=board_id):
                (self.volume / "INFO_UF2.TXT").write_text(f"Board-ID: {board_id}\n")
                with self.assertRaisesRegex(ValueError, "wrong UF2 board ID"):
                    INSTALLER.validate_public_identity(self.args(board="xiao_nrf52840_sense", role_id=1,
                                                artifact=artifact, dry_run=False))
                self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_sense_identity_matches_with_app_only_current_without_reading_it_or_claiming_live_cf2(self):
        artifact = self._sense_artifact()
        self._sense_volume()
        current = self.volume / "CURRENT.UF2"
        addresses = range(0x1000, 0xEA000, 256)
        current.write_bytes(b"".join(
            _uf2_block(address, b"\xA9" * 256, index, len(addresses), family_id=0xADA52840)
            for index, address in enumerate(addresses)))
        self.assertEqual(current.stat().st_size, 1908736)
        original_open = Path.open

        def reject_current(path, *args, **kwargs):
            if path == current:
                raise AssertionError("installer must not read CURRENT.UF2")
            return original_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", reject_current), \
                mock.patch.object(BOOT_INFO, "read_cf2_bootloader_id",
                                  wraps=BOOT_INFO.read_cf2_bootloader_id) as cf2, \
                mock.patch("builtins.print") as output:
            INSTALLER.validate_public_identity(self.args(board="xiao_nrf52840_sense", role_id=1, artifact=artifact))
        cf2.assert_called_once_with(Path(artifact))
        text = "\n".join(call.args[0] for call in output.call_args_list)
        self.assertIn("artifact CF2 0x28860045 matches observed USB VID/PID", text)
        self.assertIn("current bootloader CF2 remains unverified (not read)", text)
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_missing_or_damaged_artifact_cf2_cannot_reach_copy(self):
        for cf2 in (b"\xff" * 56, _cf2_bytes()[:32]):
            with self.subTest(cf2=cf2.hex()):
                artifact = self._replace_artifact(_genuine_uf2(cf2=cf2))
                with self.assertRaisesRegex(ValueError, "CF2"):
                    INSTALLER.validate_public_identity(self.args(artifact=artifact, dry_run=False))
                self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_matching_sense_identity_probe_ignores_unreadable_current(self):
        artifact = self._sense_artifact()
        self._sense_volume()
        original_open = Path.open
        current = self.volume / "CURRENT.UF2"
        current.write_bytes(b"unreadable fixture")

        def fail_current(path, *args, **kwargs):
            if path == current:
                raise OSError("simulated current CF2 read failure")
            return original_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", fail_current), \
                mock.patch.object(INSTALLER.os, "sync"):
            INSTALLER.validate_public_identity(self.args(board="xiao_nrf52840_sense", role_id=1,
                                        artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_cf2_duplicate_id_bad_magic_and_out_of_bounds_counts_are_rejected(self):
        duplicate = struct.pack("<IIIIIIII", 0x1E9E10F1, 0x20227A79, 2, 100,
                                208, 0x28860044, 208, 0x28860044)
        bad_magic = b"\x00" * 4 + _cf2_bytes()[4:]
        bad_count = struct.pack("<IIII", 0x1E9E10F1, 0x20227A79, 127, 127)
        for cf2 in (duplicate, bad_magic, bad_count):
            with self.subTest(cf2=cf2.hex()):
                artifact = self._replace_artifact(_genuine_uf2(cf2=cf2))
                with self.assertRaisesRegex(ValueError, "CF2"):
                    INSTALLER.validate_public_identity(self.args(artifact=artifact, dry_run=False))
                self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_sense_profile_does_not_change_exact_role_gate(self):
        artifact = self._sense_artifact(role_id=0)
        with self.assertRaisesRegex(ValueError, "role_id"):
            INSTALLER.validate_public_identity(self.args(board="xiao_nrf52840_sense", role_id=1,
                                        artifact=artifact, validate_only=True))

    def test_unknown_profile_is_explicitly_rejected_before_device_resolution(self):
        with mock.patch.object(INSTALLER.lab_device, "discover") as discover:
            with self.assertRaisesRegex(ValueError, "unknown bootloader board profile"):
                INSTALLER.validate_public_identity(self.args(board="unknown", dry_run=False))
        discover.assert_not_called()

    def test_sense_profile_cli_keeps_explicit_role_and_no_device_validation(self):
        with mock.patch.object(sys, "argv", ["install_uf2.py", "--artifact", str(self.artifact),
                                             "--board", "xiao_nrf52840_sense", "--role-id", "1",
                                             "--validate-only"]):
            args = INSTALLER.parse_args()
        self.assertEqual((args.board, args.role_id), ("xiao_nrf52840_sense", 1))

    def test_rejects_non_seeed_usb_vendor(self):
        (self.work / "sys/devices/usb/1-1/idVendor").write_text("1234")
        with self.assertRaisesRegex(ValueError, "discovered Seeed"):
            INSTALLER.validate_public_identity(self.args(dry_run=False))
        self.assertFalse((self.volume / self.artifact.name).exists())

    def test_rejects_application_usb_mode(self):
        (self.work / "sys/devices/usb/1-1/idProduct").write_text("8045")
        with self.assertRaisesRegex(ValueError, "not bootloader mode"):
            INSTALLER.validate_public_identity(self.args(dry_run=False))
        self.assertFalse((self.volume / self.artifact.name).exists())

    def test_rejects_alias_not_selected_by_shared_discovery(self):
        alias = self.work / "dev/serial/by-id" / f"usb-Zalias_{TEST_SERIAL}-if00"
        alias.symlink_to(self.device)
        with self.assertRaisesRegex(ValueError, "discovered Seeed"):
            INSTALLER.validate_public_identity(self.args(boot_port=str(alias), dry_run=False))
        self.assertFalse((self.volume / self.artifact.name).exists())

    def test_rejects_regular_file_in_by_id_directory(self):
        port = self.work / "dev/serial/by-id" / f"usb-Fake_{TEST_SERIAL}-if00"
        port.touch()
        with self.assertRaisesRegex(ValueError, "identity symlink"):
            INSTALLER.validate_public_identity(self.args(boot_port=str(port), dry_run=False))
        self.assertFalse((self.volume / self.artifact.name).exists())

    def test_rejects_volume_from_different_usb_serial(self):
        other = self.work / "sys/devices/usb/other/block/sdz/sdz1"
        other.mkdir(parents=True)
        (self.work / "sys/devices/usb/other/serial").write_text("OTHER")
        link = self.work / "sys/dev/block/8:99"
        link.unlink()
        link.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            INSTALLER.validate_public_identity(self.args(dry_run=False))
        self.assertFalse((self.volume / self.artifact.name).exists())

    def test_rejects_wrong_usb_ancestry_serial(self):
        (self.work / "sys/devices/usb/1-1/serial").write_text(
            "OTHER", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "USB ancestry serial"):
            INSTALLER.validate_public_identity(self.args())

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
            INSTALLER.validate_public_identity(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_rejects_block_targeting_settings_page(self):
        # 0xFF000 is the durable bootloader-settings page (bank/CRC/size
        # metadata only, internal flash) -- the anti-rollback floor/command
        # journal is a separate region on the EXTERNAL QSPI chip
        # (0x18C000..0x194000), a UF2 (internal-flash-only) can never reach
        # it regardless.
        data = _genuine_uf2(extra_blocks=[(0xFF000, b"\xAA" * 32)])
        artifact = self._replace_artifact(data)
        with self.assertRaisesRegex(ValueError, "outside the permitted"):
            INSTALLER.validate_public_identity(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_rejects_oversized_payload(self):
        block = bytearray(_uf2_block(0xF4000, b"\x11" * 32, 0, 1))
        struct.pack_into("<I", block, 16, 477)  # declare payload_size > 476
        artifact = self._replace_artifact(bytes(block))
        with self.assertRaisesRegex(ValueError, "payload_size"):
            INSTALLER.validate_public_identity(self.args(artifact=artifact, dry_run=False))
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
            INSTALLER.validate_public_identity(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_rejects_not_main_flash_block(self):
        # A block with this flag set (0x00000001) would otherwise look
        # structurally identical to a real one (correct magic, address,
        # family, and marker bytes) -- but a real UF2 bootloader skips
        # writing it to flash entirely, so this artifact would not
        # actually program what its address map appears to promise.
        block = bytearray(_uf2_block(0xF4000, b"\x11" * 32, 0, 1))
        struct.pack_into("<I", block, 8, 0x00002001)  # familyID present + not-main-flash
        artifact = self._replace_artifact(bytes(block))
        with self.assertRaisesRegex(ValueError, "not main flash"):
            INSTALLER.validate_public_identity(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_rejects_file_container_block(self):
        block = bytearray(_uf2_block(0xF4000, b"\x11" * 32, 0, 1))
        struct.pack_into("<I", block, 8, 0x00003000)  # familyID present + file-container
        artifact = self._replace_artifact(bytes(block))
        with self.assertRaisesRegex(ValueError, "file container"):
            INSTALLER.validate_public_identity(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_rejects_missing_family_id_present_flag(self):
        # Without this bit, offset 28 is a fileSize per the UF2 spec, not
        # a family ID -- the family_id check elsewhere would be checking
        # the wrong semantic field entirely.
        block = bytearray(_uf2_block(0xF4000, b"\x11" * 32, 0, 1, flags=0))
        artifact = self._replace_artifact(bytes(block))
        with self.assertRaisesRegex(ValueError, "familyID present"):
            INSTALLER.validate_public_identity(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_rejects_wrong_boot_info_board(self):
        data = _genuine_uf2(marker=_build_marker_bytes(board="sensecap_solar_p1"))
        artifact = self._replace_artifact(data)
        with self.assertRaisesRegex(ValueError, "boot-info marker"):
            INSTALLER.validate_public_identity(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_rejects_wrong_boot_info_key(self):
        data = _genuine_uf2(marker=_build_marker_bytes(key_bytes=bytes(range(1, 33))))
        artifact = self._replace_artifact(data)
        with self.assertRaisesRegex(ValueError, "boot-info marker"):
            INSTALLER.validate_public_identity(self.args(artifact=artifact, dry_run=False))
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_omitted_key_header_accepts_mismatched_marker_key(self):
        """key_header is purely an opt-in build-provenance cross-check, with
        no compiled/default fallback: with it omitted (None), even an
        artifact whose marker key differs from this test's own key_header
        fixture must pass the public probe -- the reference-signer field is never a
        runtime trust gate."""
        data = _genuine_uf2(marker=_build_marker_bytes(key_bytes=bytes(range(1, 33))))
        artifact = self._replace_artifact(data)
        with mock.patch.object(INSTALLER.os, "sync"):
            INSTALLER.validate_public_identity(
                self.args(artifact=artifact, key_header=None, dry_run=False)
            )
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_physical_install_rejects_non_xiao_board_even_with_valid_marker(self):
        # A --board sensecap_solar_p1 artifact whose own boot-info marker
        # validates correctly for that profile must still never reach
        # volume-copy: physical installs here are only ever authorized
        # against the real mounted XIAO lab board.
        data = _genuine_uf2(marker=_build_marker_bytes(board="sensecap_solar_p1"))
        artifact = self._replace_artifact(data)
        with self.assertRaisesRegex(ValueError, "only authorized"):
            INSTALLER.validate_public_identity(
                self.args(artifact=artifact, board="sensecap_solar_p1", dry_run=False)
            )
        self.assertFalse((self.volume / "replacement.uf2").exists())

    def test_validate_only_allows_non_xiao_board_artifact_check(self):
        # --validate-only must still pass for a genuine sensecap artifact:
        # the board restriction only guards the physical volume-copy path.
        data = _genuine_uf2(marker=_build_marker_bytes(board="sensecap_solar_p1"))
        artifact = self._replace_artifact(data)
        args = self.args(
            artifact=artifact,
            board="sensecap_solar_p1",
            validate_only=True,
            serial=None,
            boot_port=str(self.work / "no-such-boot-port"),
            mountinfo=str(self.work / "no-such-mountinfo"),
        )
        INSTALLER.validate_public_identity(args)  # must not raise
        self.assertFalse((self.volume / self.artifact.name).exists())

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
        INSTALLER.validate_public_identity(args)  # must not raise
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
            INSTALLER.validate_public_identity(args)

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

    def serial_args(self, **changes):
        self.artifact.write_bytes(self.package_artifact.read_bytes())
        self._sense_volume()
        (self.work / "sys/devices/usb/1-1/1-1:1.0/bInterfaceClass").write_text("08")
        self.mountinfo.write_text(f"1 0 8:99 / {self.volume} ro - vfat /dev/sdz1 ro\n")
        patcher = mock.patch.object(INSTALLER, "TARGET_SERIAL", TEST_SERIAL)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(INSTALLER.lab_device, "load_roles",
                                    return_value={"target": TEST_SERIAL, "client": "LABOTHER"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.evidence = self.work / "addresses.json"
        self.evidence_data = dict(serial=TEST_SERIAL, role_id=1,
                                 observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                                 mbr8="FFFFFFFF", mbrc="FFFFFFFF", uicrb="000F4000",
                                 uicrp="000FE000", boot="000F4000", params="000FE000")
        self.evidence.write_text(json.dumps(self.evidence_data))
        values = dict(
            board="xiao_nrf52840_sense", role_id=1, route="serial",
            hex_artifact=self.package_hex, elf_artifact=self.package_elf,
            package=self.package_zip, address_evidence=self.evidence,
            nrfutil=self.nrfutil)
        values.update(changes)
        return self.args(**values)

    def test_actual_nrfutil_emits_only_exact_boot_span_and_v05_init(self):
        raw, version = INSTALLER.serial_payload(self.serial_args())
        self.assertEqual(len(raw), 40192)
        self.assertEqual(raw, (self.package_zip.parent / "bootloader.bin").read_bytes())
        self.assertEqual(version, INSTALLER.preparation.BOOTLOADER_VERSION)
        INSTALLER.validate_serial_package(self.package_zip, raw, version)
        with zipfile.ZipFile(self.package_zip) as archive:
            self.assertEqual(set(archive.namelist()), {"bootloader.bin", "bootloader.dat", "manifest.json"})
            self.assertEqual(struct.unpack("<HHIHHH", archive.read("bootloader.dat")),
                             (0x0052, 52840, INSTALLER.preparation.BOOTLOADER_VERSION, 1, 0x0123,
                              binascii.crc_hqx(raw, 0xFFFF)))
        # The transmitted bin contains neither source MBR nor source UICR bytes.
        self.assertEqual(raw[:8], struct.pack("<II", 0x20040000, 0xF4081))
        self.assertEqual(raw[0xD000 - 0xC000:0xD000 - 0xC000 + 8], b"\xff" * 8)

    def test_real_existing_arm_product_matches_hex_uf2_despite_segment_padding_and_data_lma(self):
        artifacts = os.environ.get("XIAO_OTA_TEST_ARM_ARTIFACT_DIR")
        if artifacts is not None:
            bundle = Path(artifacts)
            stem = bundle / "custom-noswd/xiao_nrf52840_sense_ota_role1_noswd"
            elf, hex_path = stem.with_suffix(".elf"), stem.with_suffix(".hex")
            uf2 = Path(str(stem) + "_update.uf2")
            raw_path, package = bundle / "serial/bootloader.bin", bundle / "serial/bootloader.zip"
            # An explicit qualification bundle must never silently skip or acquire test-only metadata.
            for path in (elf, hex_path, uf2, raw_path, package):
                self.assertTrue(path.is_file(), f"required ARM qualification artifact is missing: {path}")
            INSTALLER.validate_artifact(uf2, "xiao_nrf52840_sense", None, 1)
            raw, version = INSTALLER.serial_payload(argparse.Namespace(
                artifact=uf2, hex_artifact=hex_path, elf_artifact=elf))
            self.assertEqual(version, INSTALLER.preparation.BOOTLOADER_VERSION)
            self.assertEqual(len(raw), 40192)
            self.assertEqual(raw, raw_path.read_bytes())
            INSTALLER.validate_serial_package(package, raw, version)
            return
        stem = ROOT / ".tmp/xiao_nrf52840_ota_artifacts/custom-noswd/xiao_nrf52840_ota_noswd"
        elf, hex_path, uf2 = stem.with_suffix(".elf"), stem.with_suffix(".hex"), Path(str(stem) + "_update.uf2")
        if not all(path.is_file() for path in (elf, hex_path, uf2)):
            self.skipTest("previous ARM qualification product is not present")
        copied = self.work / "real-arm.elf"
        # Add test-only ELF metadata without recompiling or attesting the old
        # product's runtime version. This test exercises real section/LMA bytes.
        symbol = "__test_bootloader_version"
        subprocess.run(["arm-none-eabi-objcopy", f"--add-symbol={symbol}=0xB00,global",
                        str(elf), str(copied)], check=True, capture_output=True)
        with mock.patch.object(INSTALLER.preparation, "VERSION_SYMBOL", symbol):
            with self.assertRaisesRegex(ValueError, "version symbol"):
                INSTALLER.compiled_boot_span(copied)
            # Preserve the old real padding/LMA fixture without relabeling
            # its 0.11 code as the selected OTAFIX source.
            with mock.patch.object(INSTALLER.preparation, "BOOTLOADER_VERSION", 0xB00):
                raw, version = INSTALLER.compiled_boot_span(copied)
        self.assertEqual(version, 0xB00)
        self.assertEqual(raw, BOOT_INFO.read_uf2_bytes(uf2, INSTALLER.BOOT_START, INSTALLER.BOOT_BYTES))
        self.assertEqual(raw, BOOT_INFO.read_intel_hex_bytes(hex_path, INSTALLER.BOOT_START, INSTALLER.BOOT_BYTES))

    def test_compiled_data_lma_overflow_is_rejected_not_hidden_by_text_size(self):
        args = self.serial_args(dry_run=False)
        copied = self.work / "lma-overflow.elf"
        data = bytearray(self.package_elf.read_bytes())
        shoff = struct.unpack_from("<I", data, 32)[0]
        # The first allocated section now spills one byte into the CF2 slot.
        struct.pack_into("<I", data, shoff + 3 * 40 + 20, 0x9801)
        copied.write_bytes(data)
        args.elf_artifact = copied
        with mock.patch.object(INSTALLER, "run_vendor_serial") as run:
            with self.assertRaisesRegex(ValueError, "code or .data LMA exceeds"):
                INSTALLER.install(args)
            run.assert_not_called()

    def test_all_physical_uf2_routes_refuse_indirect_extrafs_erasure(self):
        for changes in ({}, {"dry_run": False}, {"route": "uf2", "dry_run": False}):
            with self.subTest(changes=changes), \
                    mock.patch.object(INSTALLER, "run_vendor_serial") as run:
                with self.assertRaisesRegex(ValueError, "0xE0000..0xEA000 inside protected ExtraFS"):
                    INSTALLER.install(self.args(**changes))
                run.assert_not_called()
                self.assertFalse((self.volume / self.artifact.name).exists())

    def test_serial_dry_run_proves_footprint_without_vendor_subprocess_or_current_read(self):
        args = self.serial_args()
        current = self.volume / "CURRENT.UF2"
        current.write_bytes(b"never read this")
        original_open = Path.open

        def no_current(path, *args, **kwargs):
            if path == current:
                raise AssertionError("CURRENT/private media must not be read")
            return original_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", no_current), \
                mock.patch.object(INSTALLER, "run_vendor_serial") as run, \
                mock.patch("builtins.print") as output:
            INSTALLER.install(args)
        run.assert_not_called()
        text = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("0x27000..0x31000", text)
        self.assertIn("BEFORE later init/CRC checks", text)
        self.assertIn("restoration is mandatory", text)
        self.assertIn("no port opened", text)
        self.assertNotIn("would copy", text)

    def test_serial_invokes_only_standard_vendor_command_with_bounded_timeout(self):
        args = self.serial_args(dry_run=False)

        def completed(command, environment):
            self.assertEqual(Path(command[5]).read_bytes(), self.package_zip.read_bytes())
            self.assertEqual(environment["TMPDIR"], str(Path(command[5]).parent))

        with mock.patch.object(INSTALLER, "run_vendor_serial", side_effect=completed) as run, \
                mock.patch("builtins.print") as output:
            INSTALLER.install(args)
        command = run.call_args.args[0]
        self.assertEqual(command[2:4], ["dfu", "serial"])
        self.assertEqual(Path(command[5]).name, "bootloader.zip")
        self.assertTrue(Path(command[5]).is_relative_to(ROOT / ".tmp"))
        self.assertEqual(command[4:], ["--package", command[5],
                                      "--port", str(self.boot_port), "--baudrate", "115200"])
        self.assertEqual(INSTALLER.DFU_TIMEOUT, 120)
        self.assertNotIn("--touch", command)
        self.assertNotIn("--singlebank", command)
        text = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("transport reported completion ONLY", text)
        self.assertIn("loader activation/genesis not verified", text)
        self.assertFalse((self.volume / self.artifact.name).exists())

    def test_vendor_receives_validated_snapshot_even_if_input_package_changes(self):
        args = self.serial_args(dry_run=False)
        mutable = self.work / "input.zip"
        mutable.write_bytes(self.package_zip.read_bytes())
        args.package = mutable
        original = INSTALLER.validate_public_identity
        probes = []

        def mutate_after_validation(args):
            probes.append(True)
            mutable.write_bytes(b"changed after validation; must never reach vendor")
            return original(args)

        def vendor(command, environment):
            self.assertEqual(Path(command[5]).read_bytes(), self.package_zip.read_bytes())
            INSTALLER.validate_serial_package(command[5], self.package_raw,
                                              INSTALLER.preparation.BOOTLOADER_VERSION)

        with mock.patch.object(INSTALLER, "validate_public_identity", side_effect=mutate_after_validation), \
                mock.patch.object(INSTALLER, "run_vendor_serial", side_effect=vendor) as run:
            INSTALLER.install(args)
        self.assertEqual(len(probes), 2)
        run.assert_called_once()

    def test_serial_requires_actual_target_msc_and_read_only_mount(self):
        args = self.serial_args(dry_run=False)
        interface = self.work / "sys/devices/usb/1-1/1-1:1.0/bInterfaceClass"
        interface.write_text("02")
        with mock.patch.object(INSTALLER, "run_vendor_serial") as run:
            with self.assertRaisesRegex(ValueError, "own MSC class08"):
                INSTALLER.install(args)
            run.assert_not_called()
        # An unrelated MSC device cannot satisfy the target's own ancestry.
        other = self.work / "sys/devices/usb/other/other:1.0"
        other.mkdir(parents=True)
        (other / "bInterfaceClass").write_text("08")
        with self.assertRaisesRegex(ValueError, "own MSC class08"):
            INSTALLER.install(args)
        interface.write_text("08")
        self.mountinfo.write_text(f"1 0 8:99 / {self.volume} rw - vfat /dev/sdz1 rw\n")
        with mock.patch.object(INSTALLER, "run_vendor_serial") as run:
            with self.assertRaisesRegex(ValueError, "read-only mounted volume"):
                INSTALLER.install(args)
            run.assert_not_called()

    def console_command(self, stdout=b"", stderr=b"", code=0, delay=0):
        return [sys.executable, "-c",
                f"import sys,time; sys.stdout.buffer.write({stdout!r}); sys.stdout.flush(); "
                f"sys.stderr.buffer.write({stderr!r}); sys.stderr.flush(); "
                f"time.sleep({delay}); sys.exit({code})"]

    def test_zero_exit_vendor_failure_missing_ack_and_timeout_preserve_logs(self):
        args = self.serial_args(dry_run=False)
        original = INSTALLER.run_vendor_serial
        cases = (
            (b"Failed to upgrade target. Error is: CRC\n", b"", 0),
            (b"no completion\n", b"", 0),
            (b"Device programmed.\n", b"", 1),
            (b"Device programmed.\nTraceback\n", b"", 0),
            (b"Device programmed.\n", b"ERROR: vendor returned false\n", 0),
            (b"Device programmed.\nFalse\n", b"", 0),
            (b"prefix Device programmed.\n", b"", 0),
            (b"Device programmed. \n", b"", 0),
            (b"", b"Device programmed.\n", 0),
        )
        for stdout, stderr, code in cases:
            command = self.console_command(stdout, stderr, code)
            before = set(self.work.glob("nrfutil-serial-logs-*"))
            with self.subTest(stdout=stdout, stderr=stderr, code=code), \
                    mock.patch.object(INSTALLER, "run_vendor_serial",
                                      side_effect=lambda _, env: original(command, env)) as run, \
                    mock.patch("builtins.print") as output:
                with self.assertRaisesRegex(ValueError, "APP restoration remains mandatory") as raised:
                    INSTALLER.install(args)
                run.assert_called_once()
                logs, = set(self.work.glob("nrfutil-serial-logs-*")) - before
                self.assertEqual((logs / "stdout.log").read_bytes(), stdout)
                self.assertEqual((logs / "stderr.log").read_bytes(), stderr)
                self.assertIn(str(logs), str(raised.exception))
                self.assertIn("ROOT must first observe BOOT/enumeration/version/proofs", str(raised.exception))
                self.assertFalse(any("transport reported completion ONLY" in str(call.args[0])
                                     for call in output.call_args_list))
        command = self.console_command(b"before timeout\n", b"stderr before timeout\n", delay=2)
        before = set(self.work.glob("nrfutil-serial-logs-*"))
        with mock.patch.object(INSTALLER, "DFU_TIMEOUT", 0.5), \
                mock.patch.object(INSTALLER, "run_vendor_serial",
                                  side_effect=lambda _, env: original(command, env)):
            with self.assertRaisesRegex(ValueError, "timed out; bounded logs preserved"):
                INSTALLER.install(args)
        logs, = set(self.work.glob("nrfutil-serial-logs-*")) - before
        self.assertEqual((logs / "stdout.log").read_bytes(), b"before timeout\n")
        self.assertEqual((logs / "stderr.log").read_bytes(), b"stderr before timeout\n")

    def test_vendor_clean_exact_completion_is_only_transport_proof(self):
        args = self.serial_args(dry_run=False)
        original = INSTALLER.run_vendor_serial
        command = self.console_command(b"progress\nDevice programmed.\r\n", b"diagnostic\n")
        with mock.patch.object(INSTALLER, "run_vendor_serial",
                               side_effect=lambda _, env: original(command, env)), \
                mock.patch("builtins.print") as output:
            INSTALLER.install(args)
        text = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("transport reported completion ONLY", text)
        self.assertIn("loader activation/genesis not verified", text)
        self.assertIn("No automatic APP restoration", text)
        self.assertIn("ROOT must observe BOOT/enumeration/version/proofs", text)
        logs, = self.work.glob("nrfutil-serial-logs-*")
        self.assertEqual((logs / "stdout.log").read_bytes(), b"progress\nDevice programmed.\r\n")
        self.assertEqual((logs / "stderr.log").read_bytes(), b"diagnostic\n")

    def test_both_vendor_streams_are_bounded_and_excess_never_becomes_success(self):
        for name in ("stdout", "stderr"):
            with self.subTest(stream=name):
                before = set(self.work.glob("nrfutil-serial-logs-*"))
                command = [sys.executable, "-c",
                           f"import sys; sys.{name}.buffer.write(b'x' * 70000); sys.{name}.flush()"]
                with self.assertRaisesRegex(ValueError, f"{name} exceeded the 65536-byte output limit"):
                    INSTALLER.run_vendor_serial(command, dict(os.environ))
                logs, = set(self.work.glob("nrfutil-serial-logs-*")) - before
                self.assertEqual((logs / f"{name}.log").stat().st_size, 65536)
                other = "stderr" if name == "stdout" else "stdout"
                self.assertLessEqual((logs / f"{other}.log").stat().st_size, 65536)

    def test_output_limit_exact_boundary_and_post_pipe_exit_timeout(self):
        prefix = b"Device programmed.\n"
        for size in (65536, 65537):
            with self.subTest(size=size):
                payload = prefix + b"x" * (size - len(prefix))
                before = set(self.work.glob("nrfutil-serial-logs-*"))
                command = [sys.executable, "-c",
                           f"import sys; sys.stdout.buffer.write(b'Device programmed.\\n' + b'x' * "
                           f"{size - len(prefix)}); sys.stdout.flush()"]
                if size == 65536:
                    INSTALLER.run_vendor_serial(command, dict(os.environ))
                else:
                    with self.assertRaisesRegex(ValueError, "output limit"):
                        INSTALLER.run_vendor_serial(command, dict(os.environ))
                logs, = set(self.work.glob("nrfutil-serial-logs-*")) - before
                self.assertEqual((logs / "stdout.log").read_bytes(), payload[:65536])
        command = [sys.executable, "-c", "import os,time; os.close(1); os.close(2); time.sleep(2)"]
        with mock.patch.object(INSTALLER, "DFU_TIMEOUT", 0.5):
            with self.assertRaisesRegex(ValueError, "timed out; bounded logs preserved"):
                INSTALLER.run_vendor_serial(command, dict(os.environ))

    def test_missing_vendor_process_preserves_explicit_failure_logs(self):
        with self.assertRaisesRegex(ValueError, "could not run or capture output") as raised:
            INSTALLER.run_vendor_serial([str(self.work / "no-such-vendor")], dict(os.environ))
        logs, = self.work.glob("nrfutil-serial-logs-*")
        self.assertTrue((logs / "stdout.log").is_file())
        self.assertTrue((logs / "stderr.log").is_file())
        self.assertIn(str(logs), str(raised.exception))

    def test_crc_mismatch_fails_before_any_vendor_process_or_identity_probe(self):
        args = self.serial_args(dry_run=False)
        bad = self.work / "bad-crc.zip"
        with zipfile.ZipFile(self.package_zip) as source, zipfile.ZipFile(bad, "w") as archive:
            for name in source.namelist():
                content = source.read(name)
                if name == "bootloader.dat":
                    content = content[:-1] + bytes([content[-1] ^ 1])
                archive.writestr(name, content)
        args.package = bad
        with mock.patch.object(INSTALLER.subprocess, "Popen") as popen, \
                mock.patch.object(INSTALLER.subprocess, "run") as run, \
                mock.patch.object(INSTALLER, "validate_public_identity") as probe, \
                mock.patch.object(INSTALLER, "run_vendor_serial") as serial:
            with self.assertRaisesRegex(ValueError, "init packet CRC/version/device/SoftDevice mismatch"):
                INSTALLER.install(args)
        popen.assert_not_called()
        run.assert_not_called()
        probe.assert_not_called()
        serial.assert_not_called()

    def test_every_address_evidence_word_serial_role_and_age_fails_before_hardware(self):
        args = self.serial_args(dry_run=False)
        mutations = [(key, "00000000") for key in ("mbr8", "mbrc", "uicrb", "uicrp", "boot", "params")]
        mutations += [("serial", "OTHER"), ("role_id", 0), ("role_id", True),
                      ("observed_at", (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat().replace("+00:00", "Z")),
                      ("observed_at", (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")),
                      ("observed_at", "2026-01-01T01:00:00"), ("observed_at", "20260101Z")]
        for key, value in mutations:
            with self.subTest(key=key, value=value), \
                    mock.patch.object(INSTALLER, "run_vendor_serial") as run:
                self.evidence.write_text(json.dumps(dict(self.evidence_data, **{key: value})))
                with self.assertRaises(ValueError):
                    INSTALLER.install(args)
                run.assert_not_called()

    def test_serial_rejects_nonapproved_target_wrong_role_and_profile(self):
        args = self.serial_args(dry_run=False)
        with mock.patch.object(INSTALLER, "TARGET_SERIAL", "REAL-APPROVED-TARGET"), \
                mock.patch.object(INSTALLER, "run_vendor_serial") as run:
            with self.assertRaisesRegex(ValueError, "approved inventory target"):
                INSTALLER.install(args)
            run.assert_not_called()
        with mock.patch.object(INSTALLER.lab_device, "load_roles", return_value={"client": TEST_SERIAL}):
            with self.assertRaisesRegex(ValueError, "approved inventory target"):
                INSTALLER.install(args)
        for board, role, cf2_id in (("xiao_nrf52840_sense", 0, 0x28860045),
                                    ("xiao_nrf52840", 1, 0x28860044)):
            with self.subTest(board=board, role=role):
                self.artifact.write_bytes(_genuine_uf2(
                    marker=_build_marker_bytes(board=board, role_id=role), cf2_id=cf2_id))
                args.board, args.role_id = board, role
                with mock.patch.object(INSTALLER, "run_vendor_serial") as run:
                    with self.assertRaisesRegex(ValueError, "Sense profile and explicit role 1"):
                        INSTALLER.install(args)
                    run.assert_not_called()

    def test_nonblank_payload_past_exact_span_invalid_vector_and_missing_inputs_refuse_serial(self):
        args = self.serial_args(dry_run=False)
        extra = _genuine_uf2(marker=_build_marker_bytes(
            board="xiao_nrf52840_sense", role_id=1), cf2_id=0x28860045,
            extra_blocks=[(INSTALLER.BOOT_STOP, b"\xAA")])
        self.artifact.write_bytes(extra)
        with mock.patch.object(INSTALLER, "run_vendor_serial") as run:
            with self.assertRaisesRegex(ValueError, "beyond reviewed"):
                INSTALLER.install(args)
            run.assert_not_called()
        bad_vector = bytearray(self.package_artifact.read_bytes())
        # Second UF2 block is the bootloader vector: set the reset vector even.
        struct.pack_into("<I", bad_vector, 512 + 36, 0xF4080)
        self.artifact.write_bytes(bad_vector)
        args.hex_artifact = self.work / "even.hex"
        args.hex_artifact.write_text(_hex_from_uf2(bad_vector))
        raw = BOOT_INFO.read_uf2_bytes(self.artifact, INSTALLER.BOOT_START, INSTALLER.BOOT_BYTES)
        args.elf_artifact = self.work / "even.elf"
        args.elf_artifact.write_bytes(_arm_elf(raw))
        with self.assertRaisesRegex(ValueError, "valid bootloader vector"):
            INSTALLER.install(args)
        args.hex_artifact = None
        with self.assertRaisesRegex(ValueError, "--hex-artifact"):
            INSTALLER.install(args)

    def test_compiled_version_and_elf_payload_must_match_before_hardware(self):
        args = self.serial_args(dry_run=False)
        bad_elf = self.work / "bad.elf"
        for content in (_arm_elf(self.package_raw, version=0), _arm_elf(self.package_raw, version=0x601),
                        _arm_elf(bytes([self.package_raw[0] ^ 1]) + self.package_raw[1:]), b"not ELF"):
            with self.subTest(content=content[:16]), mock.patch.object(INSTALLER, "run_vendor_serial") as run:
                bad_elf.write_bytes(content)
                args.elf_artifact = bad_elf
                with self.assertRaises(ValueError):
                    INSTALLER.install(args)
                run.assert_not_called()

    def test_hex_and_uf2_bytes_mismatch_and_conflicting_hex_fail_before_hardware(self):
        args = self.serial_args(dry_run=False)
        bad_hex = self.work / "bad.hex"
        data = _genuine_uf2(marker=_build_marker_bytes(
            board="xiao_nrf52840_sense", role_id=1), cf2_id=0x28860045,
            extra_blocks=[(0xF4010, b"\xaa")])
        for hex_text in (_hex_from_uf2(data),
                         self.package_hex.read_text().replace("11", "12", 1)):
            with self.subTest(hex_text=hex_text[:80]), mock.patch.object(INSTALLER, "run_vendor_serial") as run:
                bad_hex.write_text(hex_text)
                args.hex_artifact = bad_hex
                with self.assertRaises((ValueError, SystemExit)):
                    INSTALLER.install(args)
                run.assert_not_called()

    def test_malformed_zip_extra_images_wrong_raw_crc_version_and_schema_fail_before_hardware(self):
        args = self.serial_args(dry_run=False)
        with zipfile.ZipFile(self.package_zip) as source:
            original = {name: source.read(name) for name in source.namelist()}
        cases = [
            dict(original, **{"application.bin": b"extra"}),
            dict(original, **{"softdevice.bin": b"extra"}),
            dict(original, **{"bootloader.bin": self.package_raw[:-4]}),
            dict(original, **{"bootloader.bin": self.package_raw + b"\xff" * 4}),
            dict(original, **{"bootloader.bin": bytes([self.package_raw[0] ^ 1]) + self.package_raw[1:]}),
            dict(original, **{"bootloader.dat": b"\0" * 14}),
        ]
        manifest = json.loads(original["manifest.json"])
        for key, value in (("application_version", 0x601), ("device_type", 0),
                           ("device_revision", 0), ("softdevice_req", [0xFFFE]),
                           ("firmware_crc16", 0)):
            modified = json.loads(original["manifest.json"])
            modified["manifest"]["bootloader"]["init_packet_data"][key] = value
            cases.append(dict(original, **{"manifest.json": json.dumps(modified).encode()}))
        manifest["manifest"]["application"] = manifest["manifest"]["bootloader"]
        cases.append(dict(original, **{"manifest.json": json.dumps(manifest).encode()}))
        bad = self.work / "bad.zip"
        for index, members in enumerate(cases):
            with self.subTest(case=index), mock.patch.object(INSTALLER, "run_vendor_serial") as run, \
                    mock.patch.object(INSTALLER.lab_device, "discover") as discover:
                with zipfile.ZipFile(bad, "w") as archive:
                    for name, content in members.items():
                        archive.writestr(name, content)
                args.package = bad
                with self.assertRaises(ValueError):
                    INSTALLER.install(args)
                run.assert_not_called()
                discover.assert_not_called()
        for content in (b"not a zip", b"\xff" * 65537):
            bad.write_bytes(content)
            args.package = bad
            with mock.patch.object(INSTALLER, "run_vendor_serial") as run:
                with self.assertRaises(ValueError):
                    INSTALLER.install(args)
                run.assert_not_called()

    def test_duplicate_package_manifest_and_root_address_fields_are_explicitly_rejected(self):
        args = self.serial_args(dry_run=False)
        self.evidence.write_text(
            json.dumps(self.evidence_data)[:-1] + ', "boot": "000F4000"}')
        with mock.patch.object(INSTALLER, "run_vendor_serial") as run:
            with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
                INSTALLER.install(args)
            run.assert_not_called()
        self.evidence.write_text(json.dumps(self.evidence_data))
        bad = self.work / "duplicates.zip"
        with zipfile.ZipFile(self.package_zip) as source, zipfile.ZipFile(bad, "w") as archive:
            for name in source.namelist():
                content = source.read(name)
                if name == "manifest.json":
                    content = content.replace(b'"dfu_version":', b'"dfu_version": 0.5, "dfu_version":', 1)
                archive.writestr(name, content)
        args.package = bad
        with mock.patch.object(INSTALLER, "run_vendor_serial") as run:
            with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
                INSTALLER.install(args)
            run.assert_not_called()

    def test_physical_serial_checks_stock_version_softdevice_and_changed_identity(self):
        args = self.serial_args(dry_run=False)
        correct = (self.volume / "INFO_UF2.TXT").read_text()
        for info in (
                correct.replace("0.6.1", "0.11.0"),
                correct.replace("0.6.1", "0.6.10"),
                correct.replace("0.6.1", "0.6.1-extra"),
                correct.replace("UF2 Bootloader", "prefix UF2 Bootloader"),
                correct.replace("UF2 Bootloader", " UF2 Bootloader"),
                correct.replace("lib/nrfx (v2.0.0)", "lib/nrfx v2.0.0"),
                correct.replace("S140", "S132"),
                correct.replace("S140 version", "S140"),
                correct.replace("7.3.0", "6.1.1"),
                correct.replace("7.3.0", "7.3.00"),
                correct.replace("7.3.0", "7.3.0 extra"),
                correct.replace("SoftDevice:", "prefix SoftDevice:"),
                correct + "UF2 Bootloader 0.6.1\n",
                correct + "UF2 Bootloader 0.11.0\n",
                correct + "SoftDevice: S140 version 7.3.0\n",
                correct + "SoftDevice: S140 version 6.1.1\n"):
            with self.subTest(info=info), mock.patch.object(INSTALLER, "run_vendor_serial") as run:
                (self.volume / "INFO_UF2.TXT").write_text(info)
                with self.assertRaisesRegex(ValueError, "INFO must prove stock"):
                    INSTALLER.install(args)
                run.assert_not_called()
        (self.volume / "INFO_UF2.TXT").write_text(correct + "Board-ID: unknown\n")
        with mock.patch.object(INSTALLER, "run_vendor_serial") as run:
            with self.assertRaisesRegex(ValueError, "exactly one nonblank Board-ID"):
                INSTALLER.install(args)
            run.assert_not_called()
        (self.volume / "INFO_UF2.TXT").write_text(correct)
        original = INSTALLER.validate_public_identity
        calls = []

        def changed_identity(args):
            if calls:
                self.boot_port.unlink()
            calls.append(True)
            return original(args)

        with mock.patch.object(INSTALLER, "validate_public_identity", side_effect=changed_identity), \
                mock.patch.object(INSTALLER, "run_vendor_serial") as run:
            with self.assertRaisesRegex(ValueError, "stable authorized identity symlink"):
                INSTALLER.install(args)
            run.assert_not_called()

    def test_package_only_cli_needs_no_identity_and_refuses_mixed_modes(self):
        command = ["install_uf2.py", "--artifact", str(self.package_artifact),
                   "--emit-serial-package", str(self.work / "output"),
                   "--hex-artifact", str(self.package_hex), "--elf-artifact", str(self.package_elf),
                   "--board", "xiao_nrf52840_sense", "--role-id", "1"]
        with mock.patch.object(sys, "argv", command):
            args = INSTALLER.parse_args()
        with mock.patch.object(INSTALLER.lab_device, "discover") as discover:
            INSTALLER.install(args)
        discover.assert_not_called()
        with self.assertRaisesRegex(ValueError, "already exists"):
            INSTALLER.install(args)
        for flag in ("--dry-run", "--validate-only"):
            with mock.patch.object(sys, "argv", command + [flag]), self.assertRaises(SystemExit):
                INSTALLER.parse_args()


if __name__ == "__main__":
    unittest.main()
