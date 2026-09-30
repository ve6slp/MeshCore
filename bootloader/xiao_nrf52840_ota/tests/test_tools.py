#!/usr/bin/env python3
"""Behavioural tests for bootloader/xiao_nrf52840_ota/tools/*.py.

Covers two independently-scoped tool behaviours in one file (per the
Makefile's `unittest discover -p test_tools.py` wiring):

1. verify_boot_info_artifact.py: builds small synthetic Intel HEX and UF2
   files (never relying on a real compiled build) and checks both real
   positive marker extraction and specific malformed/adversarial-input
   rejections (bad checksum, truncated record length, unsupported address
   record type, oversized UF2 payload, conflicting overlapping UF2 blocks).
2. prepare_upstream.py's --work-dir path-traversal safety: proves a
   caller-controlled --work-dir outside ROOT/.tmp (or resolving to .tmp
   itself, the repo root, the pinned upstream clone, or escaping via a
   symlink) is rejected before any subprocess/rmtree call, since WORK is
   unconditionally shutil.rmtree()'d.
"""

import binascii
import importlib.util
import struct
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

ADDRESS = VBI.BOOT_INFO_ADDRESS
LENGTH = VBI.BOOT_INFO_STRUCT_BYTES


def _build_marker_bytes(board_target=None, key_bytes=None, bad_crc=False):
    board_target = board_target if board_target is not None else VBI.BOARD_TARGET_VALUE["xiao_nrf52840"]
    key_bytes = key_bytes if key_bytes is not None else bytes(range(32))
    before_crc = struct.pack(
        "<IHHIIIHH32s",
        VBI.BOOT_INFO_MAGIC, VBI.BOOT_INFO_FORMAT_VERSION, VBI.BOOT_INFO_STRUCT_BYTES,
        board_target, VBI.ROLE_ANY, VBI.CAP_QSPI_INSTALL, VBI.KEY_ID,
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


def _uf2_block(target_addr, payload, block_no=0, num_blocks=1):
    header = struct.pack("<IIIIIIII", 0x0A324655, 0x9E5D5157, 0, target_addr,
                          len(payload), block_no, num_blocks, 0)
    body = header + payload
    body += b"\x00" * (512 - len(body) - 4)
    return body + struct.pack("<I", 0x0AB16F30)


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
            header = struct.pack("<IIIIIIII", 0x0A324655, 0x9E5D5157, 0, ADDRESS,
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
            errors = VBI.check_artifact(hex_path, "xiao_nrf52840", key_path)
            self.assertEqual(errors, [])

    def test_wrong_board_target_rejected(self):
        key_bytes = bytes(range(32))
        marker = _build_marker_bytes(key_bytes=key_bytes)
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            hex_path = Path(td) / "a.hex"
            key_path = Path(td) / "key.h"
            _write_hex_covering(hex_path, marker)
            self._write_key_header(key_path, key_bytes)
            errors = VBI.check_artifact(hex_path, "sensecap_solar_p1", key_path)
            self.assertTrue(any("board_target_id" in e for e in errors))

    def test_wrong_key_rejected(self):
        key_bytes = bytes(range(32))
        marker = _build_marker_bytes(key_bytes=key_bytes)
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            hex_path = Path(td) / "a.hex"
            key_path = Path(td) / "key.h"
            _write_hex_covering(hex_path, marker)
            self._write_key_header(key_path, bytes(range(1, 33)))  # different key
            errors = VBI.check_artifact(hex_path, "xiao_nrf52840", key_path)
            self.assertTrue(any("trusted_public_key mismatch" in e for e in errors))

    def test_bad_crc_rejected(self):
        key_bytes = bytes(range(32))
        marker = _build_marker_bytes(key_bytes=key_bytes, bad_crc=True)
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            hex_path = Path(td) / "a.hex"
            key_path = Path(td) / "key.h"
            _write_hex_covering(hex_path, marker)
            self._write_key_header(key_path, key_bytes)
            errors = VBI.check_artifact(hex_path, "xiao_nrf52840", key_path)
            self.assertTrue(any("crc32 field" in e for e in errors))

    def test_valid_uf2_artifact_passes(self):
        key_bytes = bytes(range(32))
        marker = _build_marker_bytes(key_bytes=key_bytes)
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.tmp')) as td:
            uf2_path = Path(td) / "a.uf2"
            key_path = Path(td) / "key.h"
            uf2_path.write_bytes(_uf2_block(ADDRESS, marker))
            self._write_key_header(key_path, key_bytes)
            errors = VBI.check_artifact(uf2_path, "xiao_nrf52840", key_path)
            self.assertEqual(errors, [])


class PrepareWorkDirSafetyTest(unittest.TestCase):
    """--work-dir is unconditionally shutil.rmtree()'d before use; a
    caller-controlled path here must be rejected before ANY subprocess or
    delete action runs, not just documented as unsafe."""

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
        self._assert_rejected(str(PREPARE.SOURCE))

    def test_source_clone_descendant_rejected(self):
        # A subdirectory INSIDE the pinned upstream clone (e.g. a vendored
        # SDK/nrfx path) must be rejected too, not just the clone root
        # itself -- otherwise --work-dir could rmtree SDK/source content
        # and then recursively copy SOURCE into itself.
        self._assert_rejected(str(PREPARE.SOURCE / "lib" / "nrfx"))

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
        link.symlink_to(PREPARE.SOURCE)
        try:
            self._assert_rejected(str(link / "lib" / "nrfx"))
        finally:
            link.unlink()

    def test_real_tmp_descendant_accepted_by_validator(self):
        # The validator itself (not the full main() pipeline, which would
        # still hit real git/network calls) must accept a genuine .tmp
        # descendant.
        accepted = PREPARE.validate_work_dir(PREPARE.ROOT / ".tmp" / "some_valid_subdir")
        self.assertEqual(accepted, (PREPARE.ROOT / ".tmp" / "some_valid_subdir").resolve())


if __name__ == "__main__":
    unittest.main()
