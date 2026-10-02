#!/usr/bin/env python3
"""Product tests for artifact readers, safe pinned-source preparation and BSP
binding, vendor UF2 metadata, and the shared canonical descriptor tools.
Invoked by the existing Makefile's unittest discovery for test_tools.py.
"""

import binascii
import hashlib
import importlib.util
import os
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
(ROOT / ".tmp").mkdir(parents=True, exist_ok=True)
SCRIPT = ROOT / "bootloader/xiao_nrf52840_ota/tools/verify_boot_info_artifact.py"
SPEC = importlib.util.spec_from_file_location("verify_boot_info_artifact", SCRIPT)
VBI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VBI)

PREPARE_SCRIPT = ROOT / "bootloader/xiao_nrf52840_ota/tools/prepare_upstream.py"
PREPARE_SPEC = importlib.util.spec_from_file_location("prepare_upstream", PREPARE_SCRIPT)
PREPARE = importlib.util.module_from_spec(PREPARE_SPEC)
PREPARE_SPEC.loader.exec_module(PREPARE)

SIGN_SCRIPT = ROOT / "bootloader/xiao_nrf52840_ota/tools/sign_image.py"
SIGN_SPEC = importlib.util.spec_from_file_location("sign_image", SIGN_SCRIPT)
SIGN = importlib.util.module_from_spec(SIGN_SPEC)
SIGN_SPEC.loader.exec_module(SIGN)

BUILD_MANIFEST_SCRIPT = ROOT / "bootloader/xiao_nrf52840_ota/tools/build_manifest.py"
BUILD_MANIFEST_SPEC = importlib.util.spec_from_file_location("build_manifest", BUILD_MANIFEST_SCRIPT)
BUILD_MANIFEST = importlib.util.module_from_spec(BUILD_MANIFEST_SPEC)
BUILD_MANIFEST_SPEC.loader.exec_module(BUILD_MANIFEST)

DESCRIPTOR_SCRIPT = ROOT / "bootloader/xiao_nrf52840_ota/tools/xiao_ota_descriptor.py"
DESCRIPTOR_SPEC = importlib.util.spec_from_file_location("xiao_ota_descriptor", DESCRIPTOR_SCRIPT)
DESCRIPTOR = importlib.util.module_from_spec(DESCRIPTOR_SPEC)
DESCRIPTOR_SPEC.loader.exec_module(DESCRIPTOR)

ADDRESS = VBI.BOOT_INFO_ADDRESS
LENGTH = VBI.BOOT_INFO_STRUCT_BYTES


def _build_marker_bytes(board_target=None, key_bytes=None, bad_crc=False, role_id=0):
    board_target = board_target if board_target is not None else VBI.BOARD_TARGET_VALUE["xiao_nrf52840"]
    key_bytes = key_bytes if key_bytes is not None else bytes(range(32))
    before_crc = struct.pack(
        "<IHHIIIHH32s",
        VBI.BOOT_INFO_MAGIC, VBI.BOOT_INFO_FORMAT_VERSION, VBI.BOOT_INFO_STRUCT_BYTES,
        board_target, role_id, VBI.CAP_QSPI_INSTALL, VBI.KEY_ID,
        VBI.ALGORITHM_ED25519, key_bytes,
    )
    crc = binascii.crc32(before_crc) & 0xFFFFFFFF
    if bad_crc:
        crc ^= 1
    return before_crc + struct.pack("<I", crc)


def _hex_record(byte_count, addr16, rec_type, payload, bad_checksum=False):
    body = bytes([byte_count, addr16 >> 8, addr16 & 0xFF, rec_type]) + payload
    checksum = (-(sum(body))) & 0xFF
    if bad_checksum:
        checksum ^= 1
    return ":" + (body + bytes([checksum])).hex().upper()


def _write_hex_covering(path, marker_bytes, address=ADDRESS, extra_lines=()):
    lines = [_hex_record(2, 0, 0x04, bytes([(address >> 24) & 0xFF, (address >> 16) & 0xFF]))]
    lo = address & 0xFFFF
    # Single data record covering the whole 60-byte marker (well under the
    # 16-bit low-address wraparound and under typical 16/32-byte chunking --
    # this reader does not care about chunk size).
    lines.append(_hex_record(len(marker_bytes), lo, 0x00, marker_bytes))
    lines.extend(extra_lines)
    lines.append(_hex_record(0, 0, 0x01, b""))
    path.write_text("\n".join(lines) + "\n")


def _uf2_block(target_addr, payload, block_no=0, num_blocks=1,
               flags=0x00002000):
    header = struct.pack("<IIIIIIII", 0x0A324655, 0x9E5D5157, flags,
                          target_addr, len(payload), block_no, num_blocks, 0)
    body = header + payload
    body += b"\x00" * (512 - len(body) - 4)
    return body + struct.pack("<I", 0x0AB16F30)


class SenseProfilePreparationTest(unittest.TestCase):
    def setUp(self):
        if not (PREPARE.DEFAULT_SOURCE / "src/boards/xiao_nrf52840_ble_sense/board.h").is_file():
            self.skipTest("pinned SDK board sources are not present")
        self.scratch = tempfile.TemporaryDirectory(dir=ROOT / ".tmp")
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name)
        self.source = self.directory / "source"
        (self.source / ".git").mkdir(parents=True)
        (self.source / "linker").mkdir()
        for name in ("Makefile", "src/main.c", "src/usb/uf2/ghostfat.c",
                     "src/usb/uf2/configkeys.h"):
            destination = self.source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(PREPARE.DEFAULT_SOURCE / name, destination)
        for board in ("xiao_nrf52840_ble", "xiao_nrf52840_ble_sense"):
            shutil.copytree(PREPARE.DEFAULT_SOURCE / "src/boards" / board,
                            self.source / "src/boards" / board)

    def prepare(self, board="xiao_nrf52840_sense", role_id=1, no_ble=True):
        work = self.directory / "ota-boot-builds" / f"{board}-role{role_id}-{no_ble}"
        args = ["--board", board, "--role-id", str(role_id),
                "--source-dir", str(self.source), "--work-dir", str(work)]
        if no_ble:
            args.append("--no-ble")
        with mock.patch.object(PREPARE.subprocess, "check_call") as git, \
                mock.patch.object(PREPARE, "run", return_value=PREPARE.PIN), \
                mock.patch("builtins.print"):
            self.assertEqual(PREPARE.main(args), work)
        self.assertTrue(all(call.args[0][0] == "git" for call in git.call_args_list))
        return work

    def test_sense_no_swd_binds_real_vendor_board_and_stock_geometry_for_both_roles(self):
        for role in (0, 1):
            with self.subTest(role=role):
                work = self.prepare(role_id=role)
                text = (work / "Makefile").read_text()
                self.assertIn("BOARD ?= xiao_nrf52840_ble_sense", text)
                self.assertIn("XIAO_OTA_BOARD_TARGET=0x584E3430u", text)
                self.assertIn(f"XIAO_OTA_COMPILED_ROLE_ID={role}u", text)
                self.assertIn("BOOTLOADER_REGION_START=0xF4000", text)
                self.assertIn("LD_FILE = linker/nrf52840_xiao_ota_noswd.ld", text)
                self.assertNotIn("BOOTLOADER_REGION_START=0xED000", text)
                self.assertEqual((work / "src/xiao_ota/xiao_ota_boot_io.c").read_bytes(),
                                 (PREPARE.OVERLAY / "src/xiao_ota_boot_io.c").read_bytes())
                output = subprocess.check_output(
                    ["make", "--no-print-directory", "-s", "-C", str(work),
                     "print-BOARD", "print-LD_FILE", "print-CFLAGS"], text=True)
                self.assertIn("BOARD = xiao_nrf52840_ble_sense", output)
                self.assertIn("LD_FILE = linker/nrf52840_xiao_ota_noswd.ld", output)
                self.assertIn("BOOTLOADER_REGION_START=0xF4000", output)
                wrong = subprocess.run(
                    ["make", "--no-print-directory", "-s", "-C", str(work),
                     "BOARD=xiao_nrf52840_ble", "print-BOARD"],
                    capture_output=True, text=True)
                self.assertNotEqual(wrong.returncode, 0)
                self.assertIn("requires BOARD=xiao_nrf52840_ble_sense", wrong.stderr)

    def test_real_prepared_vendor_version_compiles_and_links_as_verified_release(self):
        work = self.prepare()
        output = subprocess.check_output(
            ["make", "--no-print-directory", "-s", "-C", str(work),
             "print-CFLAGS", "print-LDFLAGS", "print-GIT_VERSION"], text=True)
        cflags = next(line.split(" = ", 1)[1] for line in output.splitlines()
                      if line.startswith("CFLAGS = "))
        ldflags = next(line.split(" = ", 1)[1] for line in output.splitlines()
                       if line.startswith("LDFLAGS = "))
        version_flag = next(flag for flag in shlex.split(cflags)
                            if flag.startswith("-DMK_BOOTLOADER_VERSION="))
        symbol_flag = next(flag for flag in shlex.split(ldflags)
                           if flag.startswith(f"-Wl,--defsym={PREPARE.VERSION_SYMBOL}="))
        self.assertIn(f"GIT_VERSION = {PREPARE.PIN_RELEASE}-{PREPARE.PIN[:12]}", output)
        self.assertIn(f"_Static_assert(MK_BOOTLOADER_VERSION == 0x{PREPARE.BOOTLOADER_VERSION:08X}u",
                      (work / "src/main.c").read_text())
        source = self.directory / "vendor-version.c"
        source.write_text(
            '#include <stdio.h>\n'
            f'_Static_assert(MK_BOOTLOADER_VERSION == 0x{PREPARE.BOOTLOADER_VERSION:08X}u, "version");\n'
            'int main(void) { printf("%u\\n", MK_BOOTLOADER_VERSION); }\n')
        binary = self.directory / "vendor-version"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Werror", version_flag, symbol_flag,
                        str(source), "-o", str(binary)], check=True, capture_output=True,
                       env=dict(os.environ, TMPDIR=str(self.directory)))
        self.assertEqual(int(subprocess.check_output([str(binary)])), PREPARE.BOOTLOADER_VERSION)
        symbols = subprocess.check_output(["nm", "--defined-only", str(binary)], text=True)
        line = next(line for line in symbols.splitlines() if line.endswith(PREPARE.VERSION_SYMBOL))
        value, kind, _ = line.split()
        self.assertEqual((int(value, 16), kind), (0xB00, "A"))
        self.assertGreater(PREPARE.BOOTLOADER_VERSION, 0x601)

    def test_wrong_semantic_release_tag_refuses_preparation_before_source_copy(self):
        work = self.directory / "ota-boot-builds/tag-mismatch"
        with mock.patch.object(PREPARE.subprocess, "check_call"), \
                mock.patch.object(PREPARE, "run", side_effect=[PREPARE.PIN, "0" * 40]), \
                mock.patch.object(PREPARE.shutil, "copytree") as copy:
            with self.assertRaisesRegex(SystemExit, "semantic release mismatch"):
                PREPARE.main(["--board", "xiao_nrf52840_sense", "--role-id", "1",
                              "--source-dir", str(self.source), "--work-dir", str(work), "--no-ble"])
        copy.assert_not_called()

    def test_real_selected_sense_pinconfig_compiles_to_cf2_45_not_base_44(self):
        work = self.prepare()
        harness = self.directory / "cf2"
        harness.mkdir()
        (harness / "boards.h").write_text('#include <stdint.h>\n#include "board.h"\n')
        (harness / "main.c").write_text(
            '#include <stdint.h>\n#include <stdio.h>\n'
            'extern const uint32_t bootloaderConfig[];\n'
            'int main(void) { return fwrite(bootloaderConfig, 4, 14, stdout) == 14 ? 0 : 1; }\n')
        board = work / "src/boards/xiao_nrf52840_ble_sense"
        binary = harness / "cf2-test"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-I", str(harness), "-I", str(board), "-I", str(work / "src/usb"),
                        str(board / "pinconfig.c"), str(harness / "main.c"),
                        "-o", str(binary)], check=True, capture_output=True,
                       env=dict(os.environ, TMPDIR=str(harness)))
        cf2 = subprocess.check_output([str(binary)])
        artifact = harness / "sense.uf2"
        artifact.write_bytes(_uf2_block(VBI.CF2_ADDRESS, cf2))
        self.assertEqual(VBI.read_cf2_bootloader_id(artifact), 0x28860045)

    def test_sense_ble_profile_uses_sense_board_without_changing_existing_ble_geometry(self):
        work = self.prepare(no_ble=False)
        text = (work / "Makefile").read_text()
        self.assertIn("BOARD ?= xiao_nrf52840_ble_sense", text)
        self.assertIn("BOOTLOADER_REGION_START=0xED000", text)
        self.assertIn("LD_FILE = linker/nrf52840_xiao_ota.ld", text)

    def test_base_and_sensecap_keep_their_vendor_board_and_distinct_app_families(self):
        for board, target in (("xiao_nrf52840", "584E3430"),
                              ("sensecap_solar_p1", "53435031")):
            with self.subTest(board=board):
                work = self.prepare(board=board)
                text = (work / "Makefile").read_text()
                self.assertIn("BOARD ?= xiao_nrf52840_ble\n", text)
                self.assertIn(f"XIAO_OTA_BOARD_TARGET=0x{target}u", text)
                self.assertIn("BOOTLOADER_REGION_START=0xF4000", text)

    def test_missing_sense_board_is_rejected_before_removing_owned_work(self):
        (self.source / "src/boards/xiao_nrf52840_ble_sense/pinconfig.c").unlink()
        with mock.patch.object(PREPARE.shutil, "rmtree") as remove, \
                self.assertRaisesRegex(SystemExit, "pinned vendor board.*lacks pinconfig.c"):
            self.prepare()
        remove.assert_not_called()


class HexReaderTest(unittest.TestCase):
    def test_valid_hex_extracts_marker(self):
        marker = _build_marker_bytes()
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            p = Path(td) / "a.hex"
            _write_hex_covering(p, marker)
            raw = VBI.read_intel_hex_bytes(p, ADDRESS, LENGTH)
            self.assertEqual(raw, marker)

    def test_bad_checksum_rejected(self):
        marker = _build_marker_bytes()
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            p = Path(td) / "a.hex"
            lines = [_hex_record(2, 0, 0x04,
                                  bytes([(ADDRESS >> 24) & 0xFF, (ADDRESS >> 16) & 0xFF]))]
            lines.append(_hex_record(len(marker), ADDRESS & 0xFFFF, 0x00, marker,
                                      bad_checksum=True))
            p.write_text("\n".join(lines) + "\n")
            with self.assertRaisesRegex(SystemExit, "checksum mismatch"):
                VBI.read_intel_hex_bytes(p, ADDRESS, LENGTH)

    def test_truncated_record_length_rejected(self):
        marker = _build_marker_bytes()
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            p = Path(td) / "a.hex"
            lines = [_hex_record(2, 0, 0x04,
                                  bytes([(ADDRESS >> 24) & 0xFF, (ADDRESS >> 16) & 0xFF]))]
            # Declare a byte_count larger than the payload actually present.
            good = _hex_record(len(marker), ADDRESS & 0xFFFF, 0x00, marker)
            # Chop off the last two payload hex-chars (one byte) but keep the
            # original byte_count field, producing a length mismatch.
            truncated = good[:-4] + good[-2:]
            lines.append(truncated)
            p.write_text("\n".join(lines) + "\n")
            with self.assertRaisesRegex(SystemExit, "byte_count"):
                VBI.read_intel_hex_bytes(p, ADDRESS, LENGTH)

    def test_unsupported_address_record_type_rejected(self):
        marker = _build_marker_bytes()
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            p = Path(td) / "a.hex"
            # Type 0x02 (Extended Segment Address) is a real, but unsupported
            # here, address-record type -- must not be silently ignored.
            _write_hex_covering(p, marker, extra_lines=[_hex_record(2, 0, 0x02, b"\x00\x00")])
            with self.assertRaisesRegex(SystemExit, "unsupported HEX record type"):
                VBI.read_intel_hex_bytes(p, ADDRESS, LENGTH)


class Uf2ReaderTest(unittest.TestCase):
    def test_cf2_reader_skips_unrequested_payloads_including_partial_blocks(self):
        cf2 = struct.pack("<IIIIIIIIIIIIII", *VBI.CF2_MAGIC, 5, 100,
                          204, 0x100000, 205, 0x40000, 208, 0x28860045,
                          209, 0xADA52840, 210, 0x20)
        blocks = ((0x27000, b"\xA9" * 256),
                  (VBI.CF2_ADDRESS - 16, b"\xA9" * 16 + cf2[:16]),
                  (VBI.CF2_ADDRESS + 16, cf2[16:]),
                  (ADDRESS, b"\xA9" * LENGTH))
        with tempfile.TemporaryDirectory(dir=ROOT / ".tmp") as td:
            path = Path(td) / "range-fixture.uf2"
            path.write_bytes(b"".join(
                _uf2_block(address, payload, index, len(blocks))
                for index, (address, payload) in enumerate(blocks)))
            allowed = [(index * 512, index * 512 + 32) for index in range(len(blocks))]
            allowed += [(index * 512 + 508, (index + 1) * 512) for index in range(len(blocks))]
            allowed += [(512 + 48, 512 + 64), (1024 + 32, 1024 + 32 + len(cf2[16:]))]
            with path.open("rb") as stream:
                reader = mock.Mock()
                reader.seek.side_effect = stream.seek

                def read_public_only(size):
                    start = stream.tell()
                    self.assertGreater(size, 0)
                    self.assertTrue(any(lo <= start and start + size <= hi for lo, hi in allowed),
                                    f"nonpublic payload read at {start} for {size} bytes")
                    return stream.read(size)

                reader.read.side_effect = read_public_only
                context = mock.MagicMock()
                context.__enter__.return_value = reader
                with mock.patch.object(Path, "open", return_value=context), \
                        mock.patch.object(Path, "read_bytes",
                                          side_effect=AssertionError("whole UF2 read")):
                    self.assertEqual(VBI.read_cf2_bootloader_id(path), 0x28860045)
                self.assertEqual(reader.read.call_count, 2 * len(blocks) + 2)

    def test_valid_uf2_extracts_marker(self):
        marker = _build_marker_bytes()
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            p = Path(td) / "a.uf2"
            p.write_bytes(_uf2_block(ADDRESS, marker))
            raw = VBI.read_uf2_bytes(p, ADDRESS, LENGTH)
            self.assertEqual(raw, marker)

    def test_oversized_payload_rejected(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            p = Path(td) / "a.uf2"
            header = struct.pack("<IIIIIIII", 0x0A324655, 0x9E5D5157, 0x2000, ADDRESS,
                                 477, 0, 1, 0)
            body = header + (b"\x00" * 477)
            body = body[:508] + struct.pack("<I", 0x0AB16F30)
            p.write_bytes(body)
            with self.assertRaisesRegex(SystemExit, "payload_size"):
                VBI.read_uf2_bytes(p, ADDRESS, LENGTH)

    def test_conflicting_overlapping_blocks_rejected(self):
        marker = _build_marker_bytes()
        tampered = bytearray(marker)
        tampered[0] ^= 0xFF
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            p = Path(td) / "a.uf2"
            p.write_bytes(_uf2_block(ADDRESS, marker, 0, 2) +
                          _uf2_block(ADDRESS, bytes(tampered), 1, 2))
            with self.assertRaisesRegex(SystemExit, "conflicting bytes"):
                VBI.read_uf2_bytes(p, ADDRESS, LENGTH)

    def test_bad_trailing_magic_rejected(self):
        marker = _build_marker_bytes()
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            p = Path(td) / "a.uf2"
            block = bytearray(_uf2_block(ADDRESS, marker))
            block[-1] ^= 0xFF
            p.write_bytes(bytes(block))
            with self.assertRaisesRegex(SystemExit, "trailing magic"):
                VBI.read_uf2_bytes(p, ADDRESS, LENGTH)

    def test_not_main_flash_block_rejected(self):
        # A block with this flag set (0x00000001) carries marker-shaped
        # bytes that would pass a naive address/payload comparison, but a
        # real UF2 bootloader skips writing it to flash entirely -- the
        # verifier must reject it outright rather than trust its payload.
        marker = _build_marker_bytes()
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            p = Path(td) / "a.uf2"
            p.write_bytes(_uf2_block(ADDRESS, marker, flags=0x00002001))
            with self.assertRaisesRegex(SystemExit, "not main flash"):
                VBI.read_uf2_bytes(p, ADDRESS, LENGTH)

    def test_file_container_block_rejected(self):
        marker = _build_marker_bytes()
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            p = Path(td) / "a.uf2"
            p.write_bytes(_uf2_block(ADDRESS, marker, flags=0x00003000))
            with self.assertRaisesRegex(SystemExit, "file container"):
                VBI.read_uf2_bytes(p, ADDRESS, LENGTH)

    def test_missing_family_id_present_flag_rejected(self):
        # flags=0 is exactly what an UNMODIFIED older/other-tool-produced
        # UF2 block could look like; without the familyID-present bit the
        # trailing family_id field is undefined (a fileSize per the UF2
        # spec), so this must be refused rather than silently trusted.
        marker = _build_marker_bytes()
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            p = Path(td) / "a.uf2"
            p.write_bytes(_uf2_block(ADDRESS, marker, flags=0))
            with self.assertRaisesRegex(SystemExit, "familyID present"):
                VBI.read_uf2_bytes(p, ADDRESS, LENGTH)


class PublicKeyParseTest(unittest.TestCase):
    def test_parses_real_header(self):
        key = VBI.parse_public_key_header(
            ROOT / "bootloader/xiao_nrf52840_ota/include/xiao_ota_public_key.h")
        self.assertEqual(len(key), 32)

    def test_does_not_pick_up_unrelated_macro_bytes(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            p = Path(td) / "key.h"
            p.write_text(
                "#define SOME_OTHER_TARGET_ID UINT32_C(0x584E3430)\n\n"
                "#define XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES \\\n"
                "    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, \\\n"
                "    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \\\n"
                "    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, \\\n"
                "    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f\n\n"
                "#define ANOTHER_UNRELATED_HEX 0xAA, 0xBB\n"
            )
            key = VBI.parse_public_key_header(p)
            self.assertEqual(key, bytes(range(32)))


class CheckArtifactTest(unittest.TestCase):
    def _write_key_header(self, path, key_bytes):
        body = ", ".join(f"0x{b:02x}" for b in key_bytes)
        path.write_text(
            "#define XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES \\\n"
            f"    {body}\n"
        )

    def test_valid_artifact_passes(self):
        key_bytes = bytes(range(32))
        marker = _build_marker_bytes(key_bytes=key_bytes)
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            hex_path = Path(td) / "a.hex"
            key_path = Path(td) / "key.h"
            _write_hex_covering(hex_path, marker)
            self._write_key_header(key_path, key_bytes)
            errors = VBI.check_artifact(hex_path, "xiao_nrf52840", key_path, 0)
            self.assertEqual(errors, [])

    def test_valid_role1_artifact_passes_with_matching_expected_role(self):
        # A genuine role-1 (repeater) artifact must pass when --role-id 1
        # is supplied to match it -- role is now a real, checked field, not
        # a fixed golden constant.
        key_bytes = bytes(range(32))
        marker = _build_marker_bytes(key_bytes=key_bytes, role_id=1)
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            hex_path = Path(td) / "a.hex"
            key_path = Path(td) / "key.h"
            _write_hex_covering(hex_path, marker)
            self._write_key_header(key_path, key_bytes)
            errors = VBI.check_artifact(hex_path, "xiao_nrf52840", key_path, 1)
            self.assertEqual(errors, [])

    def test_role_mismatch_rejected_both_directions(self):
        # A role-0 artifact checked against an expected role of 1 (and vice
        # versa) must be rejected -- crossed-role interop must never pass.
        key_bytes = bytes(range(32))
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            hex_path = Path(td) / "a.hex"
            key_path = Path(td) / "key.h"
            self._write_key_header(key_path, key_bytes)

            marker_role0 = _build_marker_bytes(key_bytes=key_bytes, role_id=0)
            _write_hex_covering(hex_path, marker_role0)
            errors = VBI.check_artifact(hex_path, "xiao_nrf52840", key_path, 1)
            self.assertTrue(any("role_id" in e for e in errors))

            marker_role1 = _build_marker_bytes(key_bytes=key_bytes, role_id=1)
            _write_hex_covering(hex_path, marker_role1)
            errors = VBI.check_artifact(hex_path, "xiao_nrf52840", key_path, 0)
            self.assertTrue(any("role_id" in e for e in errors))

    def test_wrong_board_target_rejected(self):
        key_bytes = bytes(range(32))
        marker = _build_marker_bytes(key_bytes=key_bytes)
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            hex_path = Path(td) / "a.hex"
            key_path = Path(td) / "key.h"
            _write_hex_covering(hex_path, marker)
            self._write_key_header(key_path, key_bytes)
            errors = VBI.check_artifact(hex_path, "sensecap_solar_p1", key_path, 0)
            self.assertTrue(any("board_target_id" in e for e in errors))

    def test_wrong_key_rejected(self):
        key_bytes = bytes(range(32))
        marker = _build_marker_bytes(key_bytes=key_bytes)
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            hex_path = Path(td) / "a.hex"
            key_path = Path(td) / "key.h"
            _write_hex_covering(hex_path, marker)
            self._write_key_header(key_path, bytes(range(1, 33)))  # different key
            errors = VBI.check_artifact(hex_path, "xiao_nrf52840", key_path, 0)
            self.assertTrue(any("reference_signer_public_key_ed25519 mismatch" in e for e in errors))

    def test_omitted_key_header_skips_key_check_without_error(self):
        """No --key-header means no compiled/default key is substituted and
        no requirement is enforced: the reference-signer field is purely
        informational, never a runtime trust gate, so its absence/mismatch
        must never block an otherwise-valid artifact."""
        key_bytes = bytes(range(32))
        marker = _build_marker_bytes(key_bytes=key_bytes)
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            hex_path = Path(td) / "a.hex"
            _write_hex_covering(hex_path, marker)
            errors = VBI.check_artifact(hex_path, "xiao_nrf52840", None, 0)
            self.assertEqual(errors, [])

    def test_bad_crc_rejected(self):
        key_bytes = bytes(range(32))
        marker = _build_marker_bytes(key_bytes=key_bytes, bad_crc=True)
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            hex_path = Path(td) / "a.hex"
            key_path = Path(td) / "key.h"
            _write_hex_covering(hex_path, marker)
            self._write_key_header(key_path, key_bytes)
            errors = VBI.check_artifact(hex_path, "xiao_nrf52840", key_path, 0)
            self.assertTrue(any("crc32 field" in e for e in errors))

    def test_valid_uf2_artifact_passes(self):
        key_bytes = bytes(range(32))
        marker = _build_marker_bytes(key_bytes=key_bytes)
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            uf2_path = Path(td) / "a.uf2"
            key_path = Path(td) / "key.h"
            uf2_path.write_bytes(_uf2_block(ADDRESS, marker))
            self._write_key_header(key_path, key_bytes)
            errors = VBI.check_artifact(uf2_path, "xiao_nrf52840", key_path, 0)
            self.assertEqual(errors, [])


class PrepareWorkDirSafetyTest(unittest.TestCase):
    """--work-dir is unconditionally shutil.rmtree()'d before use; a
    caller-controlled path here must be rejected before ANY subprocess or
    delete action runs, not just documented as unsafe."""

    def test_default_work_paths_keep_board_role_and_recovery_variant_distinct(self):
        for board in PREPARE.UPSTREAM_BOARDS:
            for role in (0, 1):
                for no_ble in (False, True):
                    with self.subTest(board=board, role=role, no_ble=no_ble):
                        args = ["--board", board, "--role-id", str(role)]
                        if no_ble:
                            args.append("--no-ble")
                        suffix = (f"_role{role}" if role else "") + ("_noswd" if no_ble else "")
                        expected = (ROOT / ".tmp" / PREPARE.WORK_DIR_NAMESPACE
                                    / f"{board}_ota{suffix}_upstream")
                        with mock.patch.object(PREPARE, "check_work_dir_ownership",
                                               side_effect=RuntimeError("stop before checkout")) as ownership, \
                                mock.patch.object(PREPARE.subprocess, "check_call") as git:
                            with self.assertRaisesRegex(RuntimeError, "stop before checkout"):
                                PREPARE.main(args)
                        self.assertEqual(ownership.call_args.args, (expected.resolve(),
                                                                    PREPARE.DEFAULT_SOURCE.resolve()))
                        git.assert_not_called()

    def _blocked(self):
        return (
            mock.patch.object(PREPARE.subprocess, "check_call",
                              side_effect=AssertionError("subprocess.check_call must not "
                                                          "run for a rejected --work-dir")),
            mock.patch.object(PREPARE.shutil, "rmtree",
                              side_effect=AssertionError("rmtree must not run for a "
                                                          "rejected --work-dir")),
        )

    def _assert_rejected(self, work_arg):
        blocked_subprocess, blocked_rmtree = self._blocked()
        with blocked_subprocess, blocked_rmtree:
            with self.assertRaises(SystemExit):
                PREPARE.main(["--work-dir", work_arg])

    def test_absolute_path_outside_tmp_rejected(self):
        self._assert_rejected("/etc")

    def test_repo_root_itself_rejected(self):
        self._assert_rejected(str(PREPARE.ROOT))

    def test_tmp_dir_itself_rejected(self):
        self._assert_rejected(str(PREPARE.ROOT / ".tmp"))

    def test_source_clone_path_rejected(self):
        self._assert_rejected(str(PREPARE.DEFAULT_SOURCE))

    def test_source_clone_descendant_rejected(self):
        # A subdirectory INSIDE the pinned upstream clone (e.g. a vendored
        # SDK/nrfx path) must be rejected too, not just the clone root
        # itself -- otherwise --work-dir could rmtree SDK/source content
        # and then recursively copy SOURCE into itself.
        self._assert_rejected(str(PREPARE.DEFAULT_SOURCE / "lib" / "nrfx"))

    def test_traversal_escaping_tmp_rejected(self):
        self._assert_rejected("../../../etc/passwd")

    def test_symlink_escape_rejected(self):
        link = PREPARE.ROOT / ".tmp" / "test_tools_escape_symlink"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to("/etc")
        try:
            self._assert_rejected(str(link / "sub"))
        finally:
            link.unlink()

    def test_symlink_to_source_descendant_rejected(self):
        # A .tmp-resident symlink that resolves INTO the pinned upstream
        # clone must also be rejected -- resolving must catch this the same
        # way it catches a direct SOURCE-descendant path.
        link = PREPARE.ROOT / ".tmp" / "test_tools_source_symlink"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(PREPARE.DEFAULT_SOURCE)
        try:
            self._assert_rejected(str(link / "lib" / "nrfx"))
        finally:
            link.unlink()

    def test_real_tmp_descendant_accepted_by_validator(self):
        # The validator itself (not the full main() pipeline, which would
        # still hit real git/network calls) must accept a genuine
        # descendant of the dedicated ota-boot-builds namespace.
        candidate = PREPARE.ROOT / ".tmp" / PREPARE.WORK_DIR_NAMESPACE / "some_valid_subdir"
        accepted = PREPARE.validate_work_dir(candidate, PREPARE.DEFAULT_SOURCE)
        self.assertEqual(accepted, candidate.resolve())

    def test_plain_tmp_descendant_outside_namespace_rejected(self):
        # A path that is a perfectly fine ROOT/.tmp descendant but does NOT
        # fall under the dedicated ota-boot-builds namespace must now be
        # rejected -- this is the root-cause fix for the HIGH finding: the
        # old check only verified "inside ROOT/.tmp", which still let a
        # caller point --work-dir at an unrelated .tmp subdirectory (e.g.
        # a durable archive/index directory) that rmtree() would then
        # erase.
        self._assert_rejected(str(PREPARE.ROOT / ".tmp" / "some_valid_subdir"))

    def test_reserved_ota_index_component_rejected(self):
        # The reserved "ota-index" path component must be rejected no
        # matter where it appears in the relative path, even nested
        # legitimately-looking inside the dedicated namespace.
        self._assert_rejected(str(PREPARE.ROOT / ".tmp" / "ota-index"))
        self._assert_rejected(
            str(PREPARE.ROOT / ".tmp" / PREPARE.WORK_DIR_NAMESPACE / "ota-index" / "leaf"))

    def test_namespace_root_itself_rejected(self):
        # WORK must never be the dedicated namespace directory itself --
        # only a strict descendant of it.
        self._assert_rejected(str(PREPARE.ROOT / ".tmp" / PREPARE.WORK_DIR_NAMESPACE))

    def test_namespace_ancestor_rejected(self):
        # Any ancestor of the dedicated namespace (other than one that
        # also happens to reach down INTO it) must be rejected -- this is
        # exactly the geometry a caller could otherwise exploit to rmtree
        # sibling content under ROOT/.tmp.
        self._assert_rejected(str(PREPARE.ROOT / ".tmp"))

    def test_nonempty_unowned_existing_work_dir_rejected(self):
        # A WORK path that satisfies the namespace/geometry check AND
        # already exists non-empty, but has no ownership sentinel (or a
        # mismatched one), must be refused before any git/copy/delete --
        # this proves an unrelated pre-existing directory that merely
        # happens to satisfy the geometry rule is never silently
        # rmtree()'d.
        with tempfile.TemporaryDirectory(dir=str(PREPARE.ROOT / ".tmp")) as td:
            work = Path(td) / PREPARE.WORK_DIR_NAMESPACE / "unowned_leaf"
            work.mkdir(parents=True)
            sentinel_stand_in = work / "not_mine.txt"
            sentinel_stand_in.write_text("unrelated owner's data")

            blocked_subprocess, blocked_rmtree = self._blocked()
            with blocked_subprocess, blocked_rmtree:
                with self.assertRaises(SystemExit):
                    PREPARE.main(["--work-dir", str(work)])

            # Refused BEFORE any delete -- the unrelated content must still
            # be fully intact afterwards.
            self.assertTrue(work.is_dir())
            self.assertEqual(sentinel_stand_in.read_text(), "unrelated owner's data")

        # A mismatched sentinel (right filename, wrong contents -- e.g. a
        # different SOURCE/pin/root) must be refused the same way, not
        # just a missing one.
        with tempfile.TemporaryDirectory(dir=str(PREPARE.ROOT / ".tmp")) as td:
            work = Path(td) / PREPARE.WORK_DIR_NAMESPACE / "mismatched_leaf"
            work.mkdir(parents=True)
            (work / PREPARE.WORK_DIR_SENTINEL_NAME).write_text("not the real sentinel format")
            (work / "other_file.txt").write_text("also unrelated owner's data")

            blocked_subprocess, blocked_rmtree = self._blocked()
            with blocked_subprocess, blocked_rmtree:
                with self.assertRaises(SystemExit):
                    PREPARE.main(["--work-dir", str(work)])
            self.assertEqual(
                (work / "other_file.txt").read_text(), "also unrelated owner's data")

    def test_empty_new_work_dir_needs_no_sentinel(self):
        # A brand-new, not-yet-existing (or already-empty) WORK needs no
        # sentinel at all -- there is nothing to protect yet.
        with tempfile.TemporaryDirectory(dir=str(PREPARE.ROOT / ".tmp")) as td:
            work = Path(td) / PREPARE.WORK_DIR_NAMESPACE / "fresh_leaf"
            # Does not exist yet.
            PREPARE.check_work_dir_ownership(work, PREPARE.DEFAULT_SOURCE)
            # Exists but empty.
            work.mkdir(parents=True)
            PREPARE.check_work_dir_ownership(work, PREPARE.DEFAULT_SOURCE)

    def test_owned_matching_sentinel_repeated_prepare_accepted(self):
        # A WORK dir that already carries THIS script's own valid,
        # matching ownership sentinel from a prior run must be accepted
        # for a repeat prepare (i.e. check_work_dir_ownership() must not
        # raise) -- proving the fix protects unowned content without
        # blocking this script's own legitimate re-run/idempotent usage.
        with tempfile.TemporaryDirectory(dir=str(PREPARE.ROOT / ".tmp")) as td:
            source = Path(td) / "source_stand_in"
            source.mkdir()
            work = Path(td) / PREPARE.WORK_DIR_NAMESPACE / "owned_leaf"
            work.mkdir(parents=True)
            (work / PREPARE.WORK_DIR_SENTINEL_NAME).write_text(
                PREPARE._work_dir_sentinel_contents(source))
            (work / "previous_build_artifact.txt").write_text("leftover from prior run")
            # Must not raise.
            PREPARE.check_work_dir_ownership(work, source)

    def test_work_dir_inside_relocated_source_rejected(self):
        # --work-dir safety must track a caller-relocated --source-dir, not
        # just the fixed default clone location -- otherwise a namespaced
        # --source-dir (e.g. a per-owner TMPDIR override) would silently
        # stop protecting its own clone from being rmtree()'d as a WORK dir.
        relocated_source = PREPARE.ROOT / ".tmp" / "test_tools_relocated_source"
        with self.assertRaises(SystemExit):
            PREPARE.validate_work_dir(relocated_source / "lib" / "nrfx", relocated_source)

    def test_work_dir_ancestor_of_source_rejected(self):
        # The reverse direction of the check above: a caller picking
        # --work-dir as an ANCESTOR of --source-dir (e.g. a namespaced,
        # per-owner --work-dir=.tmp/owner with --source-dir=.tmp/owner/src)
        # must be rejected just as strictly. Before this fix,
        # validate_work_dir() only ever checked WORK==SOURCE or WORK
        # nested inside SOURCE -- this exact ancestor case slipped through,
        # so the unconditional shutil.rmtree(WORK) in main() would silently
        # erase the pinned upstream clone (and anything else already
        # present under that ancestor) before main() ever reached the
        # copytree step. Uses a real, pre-existing, owned .tmp-descendant
        # "sentinel" directory tree (never actually passed to main()/
        # rmtree -- only to the pure validator function) to prove the
        # rejection happens with the sentinel path still fully intact
        # afterwards; no subprocess/network/rmtree call is exercised here
        # at all, real or mocked, since validate_work_dir() must raise
        # before any of those would even be reached.
        with tempfile.TemporaryDirectory(dir=str(PREPARE.ROOT / ".tmp")) as td:
            owner_ancestor = Path(td)
            source_descendant = owner_ancestor / "src"
            source_descendant.mkdir()
            sentinel = source_descendant / "sentinel.txt"
            sentinel.write_text("owned-do-not-delete")

            with self.assertRaises(SystemExit):
                PREPARE.validate_work_dir(owner_ancestor, source_descendant)

            # The validator must have raised before touching anything --
            # the sentinel (standing in for the pinned upstream clone)
            # must still exist, byte-for-byte, and the ancestor directory
            # itself must not have been removed.
            self.assertTrue(owner_ancestor.is_dir())
            self.assertEqual(sentinel.read_text(), "owned-do-not-delete")

        # Identity (WORK == SOURCE) and true nesting (WORK inside SOURCE)
        # must remain rejected too -- this fix must not have narrowed
        # either of the pre-existing directions while adding the new one.
        same = PREPARE.ROOT / ".tmp" / "test_tools_ancestor_same"
        with self.assertRaises(SystemExit):
            PREPARE.validate_work_dir(same, same)


class PrepareSourceDirSafetyTest(unittest.TestCase):
    """--source-dir must be constrained the same way --work-dir is (a
    strict ROOT/.tmp descendant): it is never rmtree()'d, but this script
    must never be pointed at durable, Root-managed storage living outside
    build scratch (e.g. a persistent archive) -- only disposable,
    re-clonable build-scratch paths belong here."""

    def _blocked(self):
        return (
            mock.patch.object(PREPARE.subprocess, "check_call",
                              side_effect=AssertionError("subprocess.check_call must not "
                                                          "run for a rejected --source-dir")),
            mock.patch.object(PREPARE.shutil, "rmtree",
                              side_effect=AssertionError("rmtree must not run for a "
                                                          "rejected --source-dir")),
        )

    def _assert_rejected(self, source_arg):
        blocked_subprocess, blocked_rmtree = self._blocked()
        with blocked_subprocess, blocked_rmtree:
            with self.assertRaises(SystemExit):
                PREPARE.main(["--source-dir", source_arg])

    def test_absolute_path_outside_tmp_rejected(self):
        self._assert_rejected("/etc")

    def test_repo_root_itself_rejected(self):
        self._assert_rejected(str(PREPARE.ROOT))

    def test_tmp_dir_itself_rejected(self):
        self._assert_rejected(str(PREPARE.ROOT / ".tmp"))

    def test_traversal_escaping_tmp_rejected(self):
        self._assert_rejected("../../../etc/passwd")

    def test_relocated_source_dir_is_actually_used(self):
        # Behavioural proof (not just acceptance/rejection) that a caller
        # --source-dir actually relocates where this script clones/reads
        # the pinned upstream from, instead of silently falling back to
        # DEFAULT_SOURCE. mock out the network clone/checkout plumbing and
        # assert the resolved SOURCE path passed to git is the caller's,
        # not the default.
        relocated = PREPARE.ROOT / ".tmp" / "test_tools_relocated_source_used"
        relocated.mkdir(parents=True, exist_ok=True)
        (relocated / ".git").mkdir(exist_ok=True)
        board = relocated / "src/boards/xiao_nrf52840_ble"
        board.mkdir(parents=True, exist_ok=True)
        for name in ("board.h", "board.mk", "pinconfig.c"):
            (board / name).touch()
        seen_paths = []

        def fake_check_call(cmd, *a, **kw):
            seen_paths.append(cmd)
            return 0

        def fake_run(*args):
            if "rev-parse" in args:
                return PREPARE.PIN
            return ""

        work = (PREPARE.ROOT / ".tmp" / PREPARE.WORK_DIR_NAMESPACE
                / "test_tools_relocated_source_used_work")
        try:
            with mock.patch.object(PREPARE.subprocess, "check_call", side_effect=fake_check_call), \
                 mock.patch.object(PREPARE, "run", side_effect=fake_run), \
                 mock.patch.object(PREPARE.shutil, "copytree",
                                   side_effect=RuntimeError("stop at source copy")) as copytree_mock, \
                 mock.patch.object(PREPARE.shutil, "copy2"), \
                 mock.patch("builtins.open", mock.mock_open(read_data="X" * 512)):
                with self.assertRaisesRegex(RuntimeError, "stop at source copy"):
                    PREPARE.main(["--source-dir", str(relocated), "--work-dir", str(work)])
            git_c_calls = [c for c in seen_paths
                           if isinstance(c, list) and "-C" in c]
            self.assertTrue(git_c_calls, "expected at least one 'git -C <SOURCE> ...' call")
            for call in git_c_calls:
                idx = call.index("-C")
                self.assertEqual(Path(call[idx + 1]).resolve(), relocated.resolve())
            copytree_mock.assert_called_once()
            src_arg = copytree_mock.call_args[0][0]
            self.assertEqual(Path(src_arg).resolve(), relocated.resolve())
        finally:
            shutil = PREPARE.shutil
            if relocated.exists():
                shutil.rmtree(relocated, ignore_errors=True)
            if work.exists():
                shutil.rmtree(work, ignore_errors=True)


class SignImageActiveExtentBoundTest(unittest.TestCase):
    """sign_image.py's --active-image bound must match the bootloader's own
    admission check (xiao_ota_record.c's active_image_extent bound, the
    same XIAO_OTA_INSTALL_MAX_SIZE/0xAD000 destructive-write capacity as
    the candidate image), never the larger BACKUP_MAX_SIZE/0xC6000
    physical bank stride -- an active-image sized between the two would
    otherwise sign successfully and then be unconditionally refused by
    the bootloader at install time."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(dir=str(ROOT / ".tmp")))
        cls.addClassCleanup(shutil.rmtree, cls.tmp)
        cls.private_key = cls.tmp / "private.pem"
        subprocess.check_call(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(cls.private_key)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        cls.image = cls.tmp / "candidate.bin"
        cls.image.write_bytes(b"\x00" * 64)

    def _sign(self, active_size):
        active = self.tmp / f"active_{active_size:x}.bin"
        if not active.exists():
            with open(active, "wb") as f:
                f.truncate(active_size)
        out_dir = self.tmp / f"out_{active_size:x}"
        argv = [
            "sign_image.py",
            "--image", str(self.image),
            "--active-image", str(active),
            "--private-key", str(self.private_key),
            "--counter", "1",
            "--output-dir", str(out_dir),
        ]
        with mock.patch.object(sys, "argv", argv):
            SIGN.main()

    def test_active_image_above_install_max_below_backup_max_rejected(self):
        # Exactly the previously-silently-accepted, actually-uninstallable
        # gap: INSTALL_MAX_SIZE < size <= BACKUP_MAX_SIZE.
        oversized = SIGN.INSTALL_MAX_SIZE + 4
        self.assertLessEqual(oversized, SIGN.BACKUP_MAX_SIZE)
        with self.assertRaises(SystemExit):
            self._sign(oversized)

    def test_active_image_exactly_0xAE000_rejected(self):
        # The exact concrete value called out as the uninstallable gap:
        # 0xAD000 (INSTALL_MAX_SIZE) + 0x1000 == 0xAE000, still comfortably
        # under BACKUP_MAX_SIZE (0xC6000) and still word-aligned, so only
        # the INSTALL_MAX_SIZE bound can be what refuses it.
        oversized = SIGN.INSTALL_MAX_SIZE + 0x1000
        self.assertEqual(oversized, 0xAE000)
        self.assertLess(oversized, SIGN.BACKUP_MAX_SIZE)
        with self.assertRaises(SystemExit):
            self._sign(oversized)

    def test_active_image_above_backup_max_still_rejected(self):
        with self.assertRaises(SystemExit):
            self._sign(SIGN.BACKUP_MAX_SIZE + 4)

    def test_active_image_at_legal_max_accepted(self):
        # Must not raise: exactly INSTALL_MAX_SIZE is the legal maximum,
        # matching xiao_ota_record.c's `active_image_extent >
        # XIAO_OTA_INSTALL_MAX_SIZE` (strictly-greater) rejection.
        self._sign(SIGN.INSTALL_MAX_SIZE)
        out_dir = self.tmp / f"out_{SIGN.INSTALL_MAX_SIZE:x}"
        self.assertTrue((out_dir / "install-command.bin").is_file())

    def _sign_candidate(self, image_size):
        image = self.tmp / f"candidate_{image_size:x}.bin"
        if not image.exists():
            with open(image, "wb") as f:
                f.truncate(image_size)
        active = self.tmp / "active_small.bin"
        if not active.exists():
            active.write_bytes(b"\x00" * 64)
        out_dir = self.tmp / f"candout_{image_size:x}"
        argv = [
            "sign_image.py",
            "--image", str(image),
            "--active-image", str(active),
            "--private-key", str(self.private_key),
            "--counter", "1",
            "--output-dir", str(out_dir),
        ]
        with mock.patch.object(sys, "argv", argv):
            SIGN.main()
        return out_dir

    def test_candidate_image_at_legal_max_accepted(self):
        # The candidate/install image itself is bounded by the SAME
        # INSTALL_MAX_SIZE -- exactly the legal maximum must sign cleanly.
        out_dir = self._sign_candidate(SIGN.INSTALL_MAX_SIZE)
        self.assertTrue((out_dir / "install-command.bin").is_file())

    def test_candidate_image_above_legal_max_rejected(self):
        with self.assertRaises(SystemExit):
            self._sign_candidate(SIGN.INSTALL_MAX_SIZE + 4)


class GhostFatSoftDeviceMetadataTest(unittest.TestCase):
    """Behavioural (not just textual-diff) proof that the ghostfat.c
    infoUf2File flash-cost patch (see prepare_upstream.py's
    GHOSTFAT_INFO_DECL_*/GHOSTFAT_UF2_INIT_OPEN_* constants) produces
    byte-identical INFO_UF2TXT metadata -- content, length, zero padding,
    and buffer capacity -- to the original single-initializer form, for
    BOTH the SoftDevice-present and SoftDevice-absent uf2_init() paths,
    compiled and RUN natively (not just diffed as text).

    This reuses the REAL patched ghostfat.c produced by an already-run
    `make build-xiao-ota-bootloader-noswd` (or similar) in the current
    TMPDIR/XIAO_OTA_BOARD -- it does not fetch or fabricate upstream
    source itself. If that prepared tree is not present, the test skips
    with an explicit reason rather than fabricating a result.
    """

    @staticmethod
    def _find_prepared_ghostfat():
        tmpdir = Path(os.environ.get("TMPDIR", str(ROOT / ".tmp")))
        board = os.environ.get("XIAO_OTA_BOARD", "xiao_nrf52840")
        # Match prepare_upstream.py's/the Makefile's own ROLE_SUFFIX
        # convention exactly ("" for role 0, "_role{N}" otherwise) so this
        # harness looks for the tree that was ACTUALLY prepared for the
        # selected XIAO_OTA_ROLE_ID, never silently falling back to a
        # stale/unrelated role-0 tree when XIAO_OTA_ROLE_ID=1 is selected.
        try:
            role_id = int(os.environ.get("XIAO_OTA_ROLE_ID", "0"))
        except ValueError:
            role_id = 0
        role_suffix = "" if role_id == 0 else f"_role{role_id}"
        # Both the SWD and no-SWD prepare_upstream.py --work-dir targets
        # apply the identical ghostfat.c patch step; either is acceptable
        # evidence, no-SWD is tried first since it is this project's
        # primary installable artifact.
        candidates = [
            tmpdir / "ota-boot-builds" / f"{board}_ota{role_suffix}_noswd_upstream" / "src" / "usb" / "uf2" / "ghostfat.c",
            tmpdir / "ota-boot-builds" / f"{board}_ota{role_suffix}_upstream" / "src" / "usb" / "uf2" / "ghostfat.c",
            # Older/direct --work-dir layouts (no ota-boot-builds/ nesting).
            tmpdir / f"{board}_ota{role_suffix}_noswd_upstream" / "src" / "usb" / "uf2" / "ghostfat.c",
            tmpdir / f"{board}_ota{role_suffix}_upstream" / "src" / "usb" / "uf2" / "ghostfat.c",
        ]
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        return None

    @staticmethod
    def _extract_balanced_body(text, open_marker):
        """Return the text strictly between open_marker's trailing '{' and
        its matching '}' (exclusive of both braces), given open_marker
        itself ends in an unmatched '{' (true for both
        GHOSTFAT_UF2_INIT_OPEN_OLD/NEW)."""
        start = text.index(open_marker)
        if start < 0:
            raise AssertionError(f"marker not found: {open_marker!r}")
        body_start = start + len(open_marker)
        depth = 1
        i = body_start
        while depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        return text[body_start:i - 1]

    def test_sd_present_and_absent_metadata_byte_identical_to_pre_patch(self):
        ghostfat_c = self._find_prepared_ghostfat()
        if ghostfat_c is None:
            reason = (
                "no prepared upstream ghostfat.c found under "
                "$TMPDIR/ota-boot-builds/$XIAO_OTA_BOARD_ota"
                "{}_noswd_upstream (role {}) -- run "
                "'make build-xiao-ota-bootloader-noswd' (or the SWD "
                "equivalent) with matching XIAO_OTA_BOARD/XIAO_OTA_ROLE_ID "
                "in this TMPDIR first; not fabricating a result".format(
                    "" if os.environ.get("XIAO_OTA_ROLE_ID", "0") == "0" else
                    "_role" + os.environ.get("XIAO_OTA_ROLE_ID", "0"),
                    os.environ.get("XIAO_OTA_ROLE_ID", "0"),
                )
            )
            # OTA_REQUIRE_PREPARED_GHOSTFAT=1 is an explicit qualification
            # opt-in: when set, a missing prepared tree for the SELECTED
            # board/role is a hard failure, not a silent skip -- so a final
            # qualification run can never pass by accident via a
            # role/board-mismatched or absent tree.
            if os.environ.get("OTA_REQUIRE_PREPARED_GHOSTFAT") == "1":
                self.fail(reason)
            self.skipTest(reason)
        patched_text = ghostfat_c.read_text()
        self.assertIn(
            PREPARE.GHOSTFAT_INFO_DECL_NEW, patched_text,
            "prepared ghostfat.c does not contain the expected patched "
            "declaration -- stale or unpatched tree?",
        )
        self.assertIn(
            PREPARE.GHOSTFAT_UF2_INIT_OPEN_NEW, patched_text,
            "prepared ghostfat.c does not contain the expected patched "
            "uf2_init() opening -- stale or unpatched tree?",
        )

        # The REAL, currently-shipping SoftDevice-formatting logic (the part
        # the patch does NOT touch), extracted verbatim from the live
        # prepared file -- not hand re-typed -- so both the old- and new-
        # style harness bodies below exercise the exact same real code.
        rest_of_body = self._extract_balanced_body(
            patched_text, PREPARE.GHOSTFAT_UF2_INIT_OPEN_NEW
        )
        self.assertIn("is_sd_existed", rest_of_body)
        self.assertIn("SD_ID_GET", rest_of_body)

        new_header = PREPARE.GHOSTFAT_UF2_INIT_OPEN_NEW.replace(
            "void uf2_init(void)", "void new_uf2_init(void)"
        ).replace("kInfoUf2FilePrefix", "kInfoUf2FilePrefix_new").replace(
            "infoUf2File", "g_new_buf"
        )
        old_header = PREPARE.GHOSTFAT_UF2_INIT_OPEN_OLD.replace(
            "void uf2_init(void)", "void old_uf2_init(void)"
        ).replace("infoUf2File", "g_old_buf")
        new_body = rest_of_body.replace("infoUf2File", "g_new_buf")
        old_body = rest_of_body.replace("infoUf2File", "g_old_buf")

        new_decl = (
            PREPARE.GHOSTFAT_INFO_DECL_NEW
            .replace("kInfoUf2FilePrefix", "kInfoUf2FilePrefix_new")
            .replace("infoUf2File", "g_new_buf")
        )
        old_decl = (
            PREPARE.GHOSTFAT_INFO_DECL_OLD
            .replace("infoUf2File", "g_old_buf")
        )

        harness = f"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define UF2_VERSION "v0.0-test"
#define UF2_PRODUCT_NAME "TestBoard"
#define UF2_BOARD_ID "TestBoard-v1"
#define MBR_SIZE 0

static bool g_fake_sd_present;
static uint32_t g_fake_sd_id;
static uint32_t g_fake_sd_version;

static bool is_sd_existed(void) {{ return g_fake_sd_present; }}
static uint32_t SD_ID_GET(uint32_t base) {{ (void)base; return g_fake_sd_id; }}
static uint32_t SD_VERSION_GET(uint32_t base) {{ (void)base; return g_fake_sd_version; }}
static char *utoa(unsigned value, char *buf, int base) {{
  (void)base;
  sprintf(buf, "%u", value);
  return buf;
}}

{new_decl}
{old_decl}

{new_header}{new_body}}}

{old_header}{old_body}}}

static int check_scenario(bool sd_present, uint32_t sd_id, uint32_t sd_version) {{
  g_fake_sd_present = sd_present;
  g_fake_sd_id = sd_id;
  g_fake_sd_version = sd_version;
  /* Emulate a fresh boot for both buffers: g_new_buf is BSS (zero at
     load, exactly like the real patched bootloader), g_old_buf carries
     its real static initializer content (prefix + implicit zero
     padding), exactly like the real pre-patch bootloader -- reproduced
     here since this process calls check_scenario() more than once but
     a real device only calls uf2_init() once per boot. */
  memset(g_new_buf, 0, sizeof(g_new_buf));
  {{
    static const char kOldPrefixReseed[] =
        "UF2 Bootloader " UF2_VERSION "\\r\\n"
        "Model: " UF2_PRODUCT_NAME "\\r\\n"
        "Board-ID: " UF2_BOARD_ID "\\r\\n"
        "Date: " __DATE__ "\\r\\n";
    memset(g_old_buf, 0, sizeof(g_old_buf));
    memcpy(g_old_buf, kOldPrefixReseed, sizeof(kOldPrefixReseed));
  }}

  new_uf2_init();
  old_uf2_init();

  if (sizeof(g_new_buf) != 128*3 || sizeof(g_old_buf) != 128*3) {{
    fprintf(stderr, "FAIL: capacity mismatch\\n");
    return 1;
  }}
  if (strcmp(g_new_buf, g_old_buf) != 0) {{
    fprintf(stderr, "FAIL: content mismatch new=%s old=%s\\n", g_new_buf, g_old_buf);
    return 1;
  }}
  size_t used = strlen(g_new_buf) + 1;
  for (size_t i = used; i < sizeof(g_new_buf); ++i) {{
    if (g_new_buf[i] != 0) {{
      fprintf(stderr, "FAIL: new buffer not zero-padded at %zu\\n", i);
      return 1;
    }}
    if (g_old_buf[i] != 0) {{
      fprintf(stderr, "FAIL: old buffer not zero-padded at %zu\\n", i);
      return 1;
    }}
  }}
  return 0;
}}

int main(void) {{
  int rc = 0;
  rc |= check_scenario(false, 0, 0);
  rc |= check_scenario(true, 140, 7003000);
  rc |= check_scenario(true, 140, 6111000);
  if (rc == 0) {{
    printf("PASS\\n");
  }}
  return rc;
}}
"""
        tmp_root = Path(os.environ.get("TMPDIR", str(ROOT / ".tmp")))
        work_dir = tmp_root / "xiao-ota-ghostfat-metadata-test"
        work_dir.mkdir(parents=True, exist_ok=True)
        src_path = work_dir / "harness.c"
        bin_path = work_dir / "harness"
        src_path.write_text(harness)
        cc = os.environ.get("CC", "cc")
        subprocess.run(
            [cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
             str(src_path), "-o", str(bin_path)],
            check=True,
        )
        result = subprocess.run([str(bin_path)], capture_output=True, text=True)
        self.assertEqual(
            result.returncode, 0,
            f"ghostfat metadata harness failed: stdout={result.stdout!r} "
            f"stderr={result.stderr!r}",
        )
        self.assertEqual(result.stdout.strip(), "PASS")


if __name__ == "__main__":
    unittest.main()


class BuildManifestToolTest(unittest.TestCase):
    """tools/build_manifest.py: bare, UNSIGNED canonical59 descriptor only
    -- no private key, no --active-image, no install command, no
    signature -- built via the SAME shared codec sign_image.py uses, so
    its output must be byte-for-byte identical to sign_image.py's own
    descriptor.bin for matching inputs."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(dir=str(ROOT / ".tmp")))
        cls.addClassCleanup(shutil.rmtree, cls.tmp)
        cls.private_key = cls.tmp / "private.pem"
        subprocess.check_call(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(cls.private_key)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        cls.image = cls.tmp / "candidate.bin"
        cls.image.write_bytes(b"\xAB" * 512)
        cls.active = cls.tmp / "active.bin"
        cls.active.write_bytes(b"\x00" * 64)

    def _build_manifest(self, output, board="xiao_nrf52840", role_id=0, counter=1, image=None):
        BUILD_MANIFEST.main([
            "--image", str(image if image is not None else self.image),
            "--board", board,
            "--role-id", str(role_id),
            "--counter", str(counter),
            "--output", str(output),
        ])

    def _sign(self, out_dir, board="xiao_nrf52840", role_id=0, counter=1, image=None):
        argv = [
            "sign_image.py",
            "--image", str(image if image is not None else self.image),
            "--active-image", str(self.active),
            "--private-key", str(self.private_key),
            "--counter", str(counter),
            "--role-id", str(role_id),
            "--board", board,
            "--output-dir", str(out_dir),
        ]
        with mock.patch.object(sys, "argv", argv):
            SIGN.main()

    def test_bare_descriptor_matches_sign_images_descriptor_byte_for_byte(self):
        out_dir = self.tmp / "sign_out_for_match"
        self._sign(out_dir, role_id=1, counter=7)
        output = self.tmp / "manifest_match.bin"
        self._build_manifest(output, role_id=1, counter=7)
        self.assertEqual(output.read_bytes(), (out_dir / "descriptor.bin").read_bytes())

    def test_sense_keeps_xiao_family_manifest_and_signed_command_bytes_for_both_roles(self):
        for role in (0, 1):
            with self.subTest(role=role), \
                    mock.patch.object(SIGN.secrets, "randbits", return_value=0x0123456789ABCDEF):
                base = self.tmp / f"base-role{role}"
                sense = self.tmp / f"sense-role{role}"
                self._sign(base, role_id=role, counter=7)
                self._sign(sense, board="xiao_nrf52840_sense", role_id=role, counter=7)
                manifest = self.tmp / f"sense-role{role}.manifest"
                self._build_manifest(manifest, board="xiao_nrf52840_sense",
                                     role_id=role, counter=7)
                self.assertEqual(manifest.read_bytes(), (base / "descriptor.bin").read_bytes())
                for name in ("descriptor.bin", "descriptor.sig", "install-command.bin"):
                    self.assertEqual((base / name).read_bytes(), (sense / name).read_bytes())

    def test_output_is_exactly_59_bytes(self):
        output = self.tmp / "manifest_59.bin"
        self._build_manifest(output)
        self.assertEqual(len(output.read_bytes()), 59)
        self.assertEqual(len(output.read_bytes()), BUILD_MANIFEST.WIRE_DESCRIPTOR_SIZE)

    def test_output_directory_has_no_other_artifacts(self):
        out_dir = self.tmp / "manifest_lonely_dir"
        output = out_dir / "manifest.bin"
        self._build_manifest(output)
        produced = sorted(p.name for p in out_dir.iterdir())
        self.assertEqual(produced, ["manifest.bin"])
        self.assertFalse((out_dir / "candidate.bin").exists())
        self.assertFalse((out_dir / "install-command.bin").exists())
        self.assertFalse((out_dir / "descriptor.sig").exists())

    def test_invalid_role_id_rejected_before_any_output_write(self):
        output = self.tmp / "manifest_bad_role.bin"
        with self.assertRaises(SystemExit):
            self._build_manifest(output, role_id=2)
        self.assertFalse(output.exists())

    def test_zero_counter_rejected_before_any_output_write(self):
        # The bootloader's floor starts at 0 and rejects
        # monotonic_counter <= counter_floor, so counter 0 can never
        # install on any real device -- reject it up front.
        output = self.tmp / "manifest_zero_counter.bin"
        with self.assertRaises(SystemExit):
            self._build_manifest(output, counter=0)
        self.assertFalse(output.exists())

    def test_negative_counter_rejected(self):
        output = self.tmp / "manifest_negative_counter.bin"
        with self.assertRaises(SystemExit):
            self._build_manifest(output, counter=-1)
        self.assertFalse(output.exists())

    def test_counter_above_uint32_rejected(self):
        output = self.tmp / "manifest_overflow_counter.bin"
        with self.assertRaises(SystemExit):
            self._build_manifest(output, counter=1 << 32)
        self.assertFalse(output.exists())

    def test_oversized_image_rejected(self):
        oversized = self.tmp / "oversized.bin"
        with open(oversized, "wb") as f:
            f.truncate(DESCRIPTOR.INSTALL_MAX_SIZE + 4)
        output = self.tmp / "manifest_oversized.bin"
        with self.assertRaises(SystemExit):
            self._build_manifest(output, image=oversized)
        self.assertFalse(output.exists())

    def test_misaligned_image_rejected(self):
        misaligned = self.tmp / "misaligned.bin"
        misaligned.write_bytes(b"\x01" * 61)
        output = self.tmp / "manifest_misaligned.bin"
        with self.assertRaises(SystemExit):
            self._build_manifest(output, image=misaligned)
        self.assertFalse(output.exists())

    def test_empty_image_rejected(self):
        empty = self.tmp / "empty.bin"
        empty.write_bytes(b"")
        output = self.tmp / "manifest_empty.bin"
        with self.assertRaises(SystemExit):
            self._build_manifest(output, image=empty)
        self.assertFalse(output.exists())

    def test_both_board_profiles_encode_distinct_family_variant_bytes(self):
        xiao_output = self.tmp / "manifest_xiao.bin"
        sensecap_output = self.tmp / "manifest_sensecap.bin"
        self._build_manifest(xiao_output, board="xiao_nrf52840")
        self._build_manifest(sensecap_output, board="sensecap_solar_p1")
        xiao_bytes = xiao_output.read_bytes()
        sensecap_bytes = sensecap_output.read_bytes()
        self.assertNotEqual(xiao_bytes[:4], sensecap_bytes[:4])
        self.assertEqual(
            struct.unpack(">HH", xiao_bytes[:4]),
            (BUILD_MANIFEST.BOARD_TARGETS["xiao_nrf52840"] >> 16,
             BUILD_MANIFEST.BOARD_TARGETS["xiao_nrf52840"] & 0xFFFF),
        )
        self.assertEqual(
            struct.unpack(">HH", sensecap_bytes[:4]),
            (BUILD_MANIFEST.BOARD_TARGETS["sensecap_solar_p1"] >> 16,
             BUILD_MANIFEST.BOARD_TARGETS["sensecap_solar_p1"] & 0xFFFF),
        )

    def test_esp_descriptor_has_exact_target_role_geometry_hash_and_policy(self):
        for role in (0, 1):
            with self.subTest(role=role):
                output = self.tmp / f"esp-role{role}.manifest"
                self._build_manifest(output, board="xiao_s3_wio", role_id=role, counter=9)
                canonical = output.read_bytes()
                self.assertEqual(len(canonical), 59)
                self.assertEqual(
                    struct.unpack(">HHBII32sIIHHH", canonical),
                    (0x4553, 0x5333, role, 0x10000, 512,
                     hashlib.sha256(self.image.read_bytes()).digest(), 9, 1, 1, 1, 1),
                )

    def test_esp_capacity_is_not_limited_to_nordic_image_geometry(self):
        image = self.tmp / "esp-max.bin"
        with image.open("wb") as stream:
            stream.truncate(2749824)
        output = self.tmp / "esp-max.manifest"
        self._build_manifest(output, board="xiao_s3_wio", image=image)
        self.assertEqual(struct.unpack_from(">I", output.read_bytes(), 9)[0], 2749824)

    def test_esp_empty_and_over_capacity_images_leave_output_untouched(self):
        image = self.tmp / "esp-invalid.bin"
        for size in (0, 2749825):
            with self.subTest(size=size):
                with image.open("wb") as stream:
                    stream.truncate(size)
                output = self.tmp / f"esp-invalid-{size}.manifest"
                with self.assertRaisesRegex(SystemExit, "1..2749824"):
                    self._build_manifest(output, board="xiao_s3_wio", image=image)
                self.assertFalse(output.exists())

    def test_esp_profile_cannot_build_a_nordic_boot_install_command(self):
        output = self.tmp / "esp-not-nordic-command"
        with self.assertRaises(SystemExit):
            self._sign(output, board="xiao_s3_wio")
        self.assertFalse(output.exists())

    def test_no_private_key_argument_accepted(self):
        # The CLI must have no --private-key flag at all: an unrecognized
        # argument makes argparse SystemExit(2) before --output is ever
        # written, proving this tool structurally cannot sign anything.
        output = self.tmp / "manifest_rejects_private_key.bin"
        argv = [
            "--image", str(self.image),
            "--counter", "1",
            "--output", str(output),
            "--private-key", str(self.private_key),
        ]
        with self.assertRaises(SystemExit):
            BUILD_MANIFEST.main(argv)
        self.assertFalse(output.exists())
