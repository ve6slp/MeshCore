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
                "#define XIAO_OTA_REFERENCE_PUBLIC_KEY_ED25519_BYTES \\\n"
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
            "#define XIAO_OTA_REFERENCE_PUBLIC_KEY_ED25519_BYTES \\\n"
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






class SignImageActiveExtentBoundTest(unittest.TestCase):
    """sign_image.py's --active-image bound must match the bootloader's own
    admission check (xiao_ota_record.c's active_image_extent bound, the
    same XIAO_OTA_INSTALL_MAX_SIZE/0x9D000 destructive-write capacity as
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

    def test_active_image_exactly_0x9E000_rejected(self):
        # The exact concrete value called out as the uninstallable gap:
        # 0x9D000 (INSTALL_MAX_SIZE) + 0x1000 == 0x9E000, still comfortably
        # under BACKUP_MAX_SIZE (0xC6000) and still word-aligned, so only
        # the INSTALL_MAX_SIZE bound can be what refuses it.
        oversized = SIGN.INSTALL_MAX_SIZE + 0x1000
        self.assertEqual(oversized, 0x9E000)
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
