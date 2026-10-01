import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import ota_boot_catalogue as cat  # noqa: E402

# Scratch workspace for this test module's own generated fixtures/builds.
# Fixed, non-random, never deleted by this suite -- files are simply
# overwritten on each run.
TEST_WORK = REPO_ROOT / ".tmp" / "boot-catalogue-hydra" / "test-work"
TEST_WORK.mkdir(parents=True, exist_ok=True)


def _env_path(var_name, default_path):
    """Resolve an input location, allowing an explicit environment
    override so a caller (e.g. Root's Make selector, operating on a
    frozen/relocated product tree) can point real-case tests at the
    actual absolute public-artifact paths instead of this agent's own
    private scratch layout. Falls back to the ordinary in-repo .tmp
    default when the override is not set."""
    override = os.environ.get(var_name)
    return Path(override).resolve() if override else default_path


# The clean, pinned PUBLIC upstream checkout (read-only). Tests that need
# REAL public MBR/SoftDevice artifacts use this; they are skipped (not
# faked) if it is not present in this environment -- unless strict
# qualification (see OTA_BOOT_CATALOGUE_REQUIRE_REAL_ARTIFACTS below) is
# requested, in which case a missing input is a hard failure, not a skip.
#
# Overridable via env vars (defaults are this agent's own ordinary
# in-repo .tmp/Adafruit_nRF52_Bootloader scratch, NOT private/ephemeral
# paths):
#   OTA_BOOT_CATALOGUE_PUBLIC_UPSTREAM      -- pinned public checkout root
#   OTA_BOOT_CATALOGUE_PUBLIC_MBR_HEX       -- public MBR hex file
#   OTA_BOOT_CATALOGUE_PUBLIC_SOFTDEVICE_HEX -- public S140 SoftDevice hex file
PUBLIC_UPSTREAM = _env_path(
    "OTA_BOOT_CATALOGUE_PUBLIC_UPSTREAM",
    REPO_ROOT / ".tmp" / "Adafruit_nRF52_Bootloader")
PUBLIC_MBR_HEX = _env_path(
    "OTA_BOOT_CATALOGUE_PUBLIC_MBR_HEX",
    PUBLIC_UPSTREAM / "lib" / "softdevice" / "mbr" / "hex" / "mbr_nrf52_2.4.1_mbr.hex")
PUBLIC_SOFTDEVICE_HEX = _env_path(
    "OTA_BOOT_CATALOGUE_PUBLIC_SOFTDEVICE_HEX",
    PUBLIC_UPSTREAM / "lib" / "softdevice" / "s140_nrf52_7.3.0" / "s140_nrf52_7.3.0_softdevice.hex")

HAVE_PUBLIC_UPSTREAM = PUBLIC_MBR_HEX.is_file() and PUBLIC_SOFTDEVICE_HEX.is_file()
HAVE_ARM_TOOLCHAIN = (
    shutil.which("arm-none-eabi-as") and shutil.which("arm-none-eabi-ld") and
    shutil.which("arm-none-eabi-readelf"))

# Root's real, Make-driven STOCK bootloader build for the pinned commit
# (unmodified upstream, no OTA overlay). Produced by
# `make build-xiao-stock-bootloader TMPDIR=.../main-stock-catalogue`.
# Tests using this are skipped (not faked) if that build hasn't completed
# in this environment/session -- unless strict qualification is requested
# (see OTA_BOOT_CATALOGUE_REQUIRE_REAL_ARTIFACTS below).
#
# Overridable via env vars (defaults are this agent's own ordinary
# in-repo .tmp/main-stock-catalogue scratch):
#   OTA_BOOT_CATALOGUE_STOCK_BUILD_DIR -- stock build root (used only to
#                                         derive the defaults below)
#   OTA_BOOT_CATALOGUE_STOCK_HEX       -- exact packaged stock HEX path
#   OTA_BOOT_CATALOGUE_STOCK_ELF       -- exact stock bootloader ELF (.out) path
MAIN_STOCK_CATALOGUE = _env_path(
    "OTA_BOOT_CATALOGUE_STOCK_BUILD_DIR", REPO_ROOT / ".tmp" / "main-stock-catalogue")
MAIN_STOCK_HEX = _env_path(
    "OTA_BOOT_CATALOGUE_STOCK_HEX",
    MAIN_STOCK_CATALOGUE / "xiao_nrf52840_ota_artifacts" / "stock" /
    "xiao_nrf52840_ble_stock_c67f0bcf0fa8e841426335b1bbde91cda6ca1f50_nosd.hex")
MAIN_STOCK_ELF = _env_path(
    "OTA_BOOT_CATALOGUE_STOCK_ELF",
    MAIN_STOCK_CATALOGUE / "Adafruit_nRF52_Bootloader" / "_build" / "build-xiao_nrf52840_ble" /
    "xiao_nrf52840_ble_bootloader-0.11.0.out")
HAVE_REAL_STOCK_BUILD = MAIN_STOCK_HEX.is_file() and MAIN_STOCK_ELF.is_file()

# Strict qualification opt-in: when set to "1", any missing real-artifact
# input (public upstream HEX, real stock build HEX/ELF, or the ARM
# toolchain) is a hard failure at collection time, NOT a silent skip.
# This exists so a frozen-product/CI invocation (e.g. Root's Make
# selector, after passing in actual public artifact absolute paths) can
# never observe "all green" while the real-artifact cases were actually
# skipped for missing inputs.
REQUIRE_REAL_ARTIFACTS = os.environ.get("OTA_BOOT_CATALOGUE_REQUIRE_REAL_ARTIFACTS") == "1"
if REQUIRE_REAL_ARTIFACTS:
    _missing_real_inputs = []
    if not HAVE_PUBLIC_UPSTREAM:
        _missing_real_inputs.append(
            "public upstream MBR/SoftDevice HEX not found "
            f"(PUBLIC_MBR_HEX={PUBLIC_MBR_HEX}, PUBLIC_SOFTDEVICE_HEX={PUBLIC_SOFTDEVICE_HEX}; "
            "override with OTA_BOOT_CATALOGUE_PUBLIC_UPSTREAM/_PUBLIC_MBR_HEX/_PUBLIC_SOFTDEVICE_HEX)")
    if not HAVE_ARM_TOOLCHAIN:
        _missing_real_inputs.append(
            "arm-none-eabi-as/-ld/-readelf not found on PATH")
    if not HAVE_REAL_STOCK_BUILD:
        _missing_real_inputs.append(
            "real stock build HEX/ELF not found "
            f"(MAIN_STOCK_HEX={MAIN_STOCK_HEX}, MAIN_STOCK_ELF={MAIN_STOCK_ELF}; "
            "override with OTA_BOOT_CATALOGUE_STOCK_HEX/_STOCK_ELF)")
    if _missing_real_inputs:
        raise RuntimeError(
            "OTA_BOOT_CATALOGUE_REQUIRE_REAL_ARTIFACTS=1 was set but real-artifact "
            "inputs are missing (refusing to silently skip real cases):\n  - " +
            "\n  - ".join(_missing_real_inputs))


def checksummed_record(length, address, record_type, payload=b""):
    body = bytes([length, (address >> 8) & 0xFF, address & 0xFF, record_type]) + payload
    checksum = (-(sum(body))) & 0xFF
    return ":" + body.hex().upper() + f"{checksum:02X}"


def eof_record():
    return checksummed_record(0, 0, 0x01)


def write_hex(path: Path, lines):
    path.write_text("\n".join(lines) + "\n")


def make_valid_cf2_bytes():
    """Builds a CF2 block that satisfies every field validate_cf2() checks,
    per the confirmed real tagged-word layout."""
    cf2 = bytearray([0xFF] * cat.CF2_SIZE)
    struct.pack_into("<I", cf2, 0, cat.CF2_MAGIC_START)
    struct.pack_into("<I", cf2, 4, cat.CF2_MAGIC_END)
    struct.pack_into("<I", cf2, 8, cat.CF2_COUNTS[0])
    struct.pack_into("<I", cf2, 12, cat.CF2_COUNTS[1])
    struct.pack_into("<I", cf2, 16, cat.CF2_FLASH_SIZE_TAG)
    struct.pack_into("<I", cf2, 20, cat.CF2_FLASH_SIZE)
    struct.pack_into("<I", cf2, 24, cat.CF2_RAM_SIZE_TAG)
    struct.pack_into("<I", cf2, 28, cat.CF2_RAM_SIZE)
    struct.pack_into("<I", cf2, 32, cat.CF2_BOARD_ID_TAG)
    struct.pack_into("<I", cf2, 36, cat.CF2_BOARD_ID)
    struct.pack_into("<I", cf2, 40, cat.CF2_UF2_FAMILY_TAG)
    struct.pack_into("<I", cf2, 44, cat.CF2_UF2_FAMILY)
    struct.pack_into("<I", cf2, 48, cat.CF2_PORT_SIZE_TAG)
    struct.pack_into("<I", cf2, 52, cat.CF2_PORT_SIZE)
    return bytes(cf2)


class IntelHexParserTests(unittest.TestCase):
    def test_simple_valid_round_trip(self):
        path = TEST_WORK / "valid_simple.hex"
        write_hex(path, [
            checksummed_record(4, 0x0000, 0x00, bytes([0xDE, 0xAD, 0xBE, 0xEF])),
            eof_record(),
        ])
        image = cat.parse_intel_hex(path)
        self.assertEqual(image.read(0, 4), bytes([0xDE, 0xAD, 0xBE, 0xEF]))
        self.assertTrue(image.eof_seen)

    def test_checksum_mismatch_rejected(self):
        path = TEST_WORK / "bad_checksum.hex"
        good = checksummed_record(4, 0x0000, 0x00, bytes([0xDE, 0xAD, 0xBE, 0xEF]))
        corrupted = good[:-2] + "00"
        write_hex(path, [corrupted, eof_record()])
        with self.assertRaises(cat.CorruptHexError):
            cat.parse_intel_hex(path)

    def test_data_after_eof_rejected(self):
        path = TEST_WORK / "data_after_eof.hex"
        write_hex(path, [
            eof_record(),
            checksummed_record(1, 0x0000, 0x00, bytes([0x01])),
        ])
        with self.assertRaises(cat.CorruptHexError):
            cat.parse_intel_hex(path)

    def test_missing_eof_rejected(self):
        path = TEST_WORK / "missing_eof.hex"
        write_hex(path, [checksummed_record(1, 0x0000, 0x00, bytes([0x01]))])
        with self.assertRaises(cat.CorruptHexError):
            cat.parse_intel_hex(path)

    def test_malformed_record_rejected(self):
        path = TEST_WORK / "malformed.hex"
        write_hex(path, ["this is not a hex record", eof_record()])
        with self.assertRaises(cat.CorruptHexError):
            cat.parse_intel_hex(path)

    def test_declared_length_mismatch_rejected(self):
        path = TEST_WORK / "length_mismatch.hex"
        # Claim length 4 but only supply 2 payload bytes before checksum.
        write_hex(path, [":0400000000ADDE00", eof_record()])
        with self.assertRaises(cat.CorruptHexError):
            cat.parse_intel_hex(path)

    def test_conflicting_overlap_rejected(self):
        path = TEST_WORK / "conflicting_overlap.hex"
        write_hex(path, [
            checksummed_record(2, 0x0000, 0x00, bytes([0x11, 0x22])),
            checksummed_record(2, 0x0001, 0x00, bytes([0xFF, 0xFF])),  # byte at 0x0001 conflicts (0x22 vs 0xFF)
            eof_record(),
        ])
        with self.assertRaises(cat.CorruptHexError):
            cat.parse_intel_hex(path)

    def test_consistent_overlap_is_allowed(self):
        path = TEST_WORK / "consistent_overlap.hex"
        write_hex(path, [
            checksummed_record(2, 0x0000, 0x00, bytes([0x11, 0x22])),
            checksummed_record(2, 0x0001, 0x00, bytes([0x22, 0x33])),  # byte at 0x0001 agrees (0x22 == 0x22)
            eof_record(),
        ])
        image = cat.parse_intel_hex(path)
        self.assertEqual(image.read(0, 3), bytes([0x11, 0x22, 0x33]))

    def test_unsupported_record_type_rejected(self):
        path = TEST_WORK / "unsupported_type.hex"
        write_hex(path, [checksummed_record(0, 0x0000, 0x06), eof_record()])
        with self.assertRaises(cat.CorruptHexError):
            cat.parse_intel_hex(path)

    def test_extended_linear_address_overflow_rejected(self):
        path = TEST_WORK / "overflow.hex"
        write_hex(path, [
            checksummed_record(2, 0x0000, 0x04, bytes([0xFF, 0xFF])),  # base = 0xFFFF0000
            # 0xFFFF0000 + 0xFFFF + byte offset 1 == 0x100000000, overflowing 32 bits.
            checksummed_record(2, 0xFFFF, 0x00, bytes([0x01, 0x02])),
            eof_record(),
        ])
        with self.assertRaises(cat.CorruptHexError):
            cat.parse_intel_hex(path)

    def test_extended_linear_and_segment_address_records(self):
        path = TEST_WORK / "extended_addresses.hex"
        write_hex(path, [
            checksummed_record(2, 0x0000, 0x04, bytes([0x10, 0x00])),  # linear base 0x10000000
            checksummed_record(1, 0x0000, 0x00, bytes([0xAA])),
            checksummed_record(2, 0x0000, 0x02, bytes([0x20, 0x00])),  # segment base resets, = 0x2000 << 4 = 0x20000
            checksummed_record(1, 0x0000, 0x00, bytes([0xBB])),
            eof_record(),
        ])
        image = cat.parse_intel_hex(path)
        self.assertEqual(image.read(0x10000000, 1), bytes([0xAA]))
        self.assertEqual(image.read(0x20000, 1), bytes([0xBB]))

    def test_missing_file_reports_missing_artifact(self):
        with self.assertRaises(cat.MissingArtifactError):
            cat.parse_intel_hex(TEST_WORK / "does_not_exist.hex")


class RealPublicArtifactTests(unittest.TestCase):
    """Validates the producer against the REAL, pinned public MBR/S140
    artifacts (not synthetic data). Skipped only if that read-only
    checkout is not present in this environment -- never faked."""

    @unittest.skipUnless(HAVE_PUBLIC_UPSTREAM, "pinned public Adafruit_nRF52_Bootloader checkout not present")
    def test_mbr_reference_hash_and_vectors(self):
        image = cat.parse_intel_hex(PUBLIC_MBR_HEX)
        sha256, vectors = cat.validate_mbr(image)
        self.assertEqual(sha256, cat.MBR_BODY_REFERENCE_SHA256)
        self.assertEqual(vectors, cat.MBR_VECTORS)

    @unittest.skipUnless(HAVE_PUBLIC_UPSTREAM, "pinned public Adafruit_nRF52_Bootloader checkout not present")
    def test_softdevice_reference_hash_vectors_and_info(self):
        image = cat.parse_intel_hex(PUBLIC_SOFTDEVICE_HEX)
        (sha256, vectors, magic, size, fwid, variant, version, unique_id) = cat.validate_softdevice(image)
        self.assertEqual(sha256, cat.SOFTDEVICE_730_REFERENCE_SHA256)
        self.assertEqual(vectors, cat.SOFTDEVICE_VECTORS)
        self.assertEqual(magic, cat.SOFTDEVICE_INFO_EXPECTED_MAGIC)
        self.assertEqual(size, cat.SOFTDEVICE_INFO_EXPECTED_SIZE)
        self.assertEqual(fwid, cat.SOFTDEVICE_INFO_EXPECTED_FWID)
        self.assertEqual(variant, cat.SOFTDEVICE_INFO_EXPECTED_VARIANT)
        self.assertEqual(version, cat.SOFTDEVICE_INFO_EXPECTED_VERSION)
        self.assertEqual(unique_id.hex(), "7a2e9ac67db66cfaf35721ccc310d5e51471fb3c")

    @unittest.skipUnless(HAVE_PUBLIC_UPSTREAM, "pinned public Adafruit_nRF52_Bootloader checkout not present")
    def test_mbr_body_corruption_is_rejected(self):
        image = cat.parse_intel_hex(PUBLIC_MBR_HEX)
        image.memory[0] ^= 0xFF  # flip first byte: corrupt a real artifact in memory
        with self.assertRaises(cat.RegionMismatchError):
            cat.validate_mbr(image)


def build_fixture_elf(name, asm_source, linker_script, extra_files=None):
    work = TEST_WORK / name
    work.mkdir(parents=True, exist_ok=True)
    for fname, content in (extra_files or {}).items():
        (work / fname).write_bytes(content) if isinstance(content, bytes) else (work / fname).write_text(content)
    (work / "src.s").write_text(asm_source)
    (work / "link.ld").write_text(linker_script)
    subprocess.run(
        ["arm-none-eabi-as", "-mcpu=cortex-m4", "-mthumb", "src.s", "-o", "src.o"],
        cwd=work, check=True, capture_output=True)
    subprocess.run(
        ["arm-none-eabi-ld", "-T", "link.ld", "src.o", "-o", "fixture.elf"],
        cwd=work, check=True, capture_output=True)
    return work / "fixture.elf"


@unittest.skipUnless(HAVE_ARM_TOOLCHAIN, "arm-none-eabi toolchain not present")
class ElfLmaExtractionTests(unittest.TestCase):
    def test_data_section_uses_physical_lma_not_vma(self):
        asm = textwrap.dedent("""
            .syntax unified
            .section .vectors, "a"
            .word 0x20000400
            .word 0x00000101
            .section .text, "ax"
            .thumb_func
            reset_handler:
              movs r0, #0
              loop: b loop
            .section .data, "aw"
            .word 0xDEADBEEF
            .word 0x12345678
            """)
        ld = textwrap.dedent("""
            MEMORY
            {
              FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 0x2000
              RAM   (rwx): ORIGIN = 0x20000000, LENGTH = 0x1000
            }
            SECTIONS
            {
              .vectors 0x00000000 : { KEEP(*(.vectors)) } > FLASH
              .text    0x00000100 : { *(.text) } > FLASH
              .data    0x20000200 : AT(0x00000400) { *(.data) } > RAM
            }
            """)
        elf_path = build_fixture_elf("elf_lma", asm, ld)
        # VMA of .data is 0x20000200 -- extracting by VMA would be wrong/empty
        # here. The real physical LMA is 0x400, where the file-backed bytes
        # genuinely live.
        extracted = cat.extract_elf_region_bytes(elf_path, 0x400, 0x408)
        self.assertEqual(extracted, struct.pack("<II", 0xDEADBEEF, 0x12345678))

        vector_bytes = cat.extract_elf_region_bytes(elf_path, 0x0, 0x8)
        self.assertEqual(struct.unpack("<II", vector_bytes), (0x20000400, 0x101))


def build_binary_region_elf(name, data: bytes, load_address: int):
    """Wrap a raw byte blob into a minimal ELF with ONE LOAD segment whose
    VMA==LMA==load_address, via a tiny assembler stub (.incbin), so the
    region has a genuine, toolchain-produced physical load address rather
    than a hand-crafted ELF."""
    asm = f'.section .blob, "a"\n.incbin "blob.bin"\n'
    ld = f"SECTIONS {{ .blob {load_address:#x} : {{ *(.blob) }} }}\n"
    return build_fixture_elf(name, asm, ld, extra_files={"blob.bin": data})


@unittest.skipUnless(HAVE_ARM_TOOLCHAIN, "arm-none-eabi toolchain not present")
@unittest.skipUnless(HAVE_PUBLIC_UPSTREAM, "pinned public Adafruit_nRF52_Bootloader checkout not present")
class ProducerEndToEndTests(unittest.TestCase):
    """Exercises the full build_catalogue_row() pipeline against the REAL
    public MBR/S140 inputs plus a SYNTHETIC stock-bootloader HEX/ELF pair.
    The synthetic stock region is clearly fabricated test data; it must
    NEVER be written into the generated production header (this test
    never calls main()/render_header() with it, and only checks the
    producer's internal validation logic)."""

    @classmethod
    def setUpClass(cls):
        cls.stock_code = bytes((i * 7 + 3) & 0xFF for i in range(cat.STOCK_CODE_SIZE))
        cls.cf2_bytes = make_valid_cf2_bytes()
        blob = cls.stock_code + cls.cf2_bytes
        cls.stock_hex = TEST_WORK / "synthetic_stock.hex"
        cls._write_stock_hex(cls.stock_hex, blob)
        cls.stock_elf_consistent = build_binary_region_elf("stock_elf_consistent", blob, cat.STOCK_CODE_OFFSET)
        tampered = bytearray(blob)
        tampered[0] ^= 0xFF
        cls.stock_elf_tampered = build_binary_region_elf("stock_elf_tampered", bytes(tampered),
                                                           cat.STOCK_CODE_OFFSET)

    @staticmethod
    def _write_stock_hex(path, blob):
        lines = []
        base = cat.STOCK_CODE_OFFSET
        lines.append(checksummed_record(2, 0x0000, 0x04, struct.pack(">H", base >> 16)))
        low16_base = base & 0xFFFF
        offset = 0
        while offset < len(blob):
            addr = (low16_base + offset) & 0xFFFF
            # Guard: this synthetic region fits entirely within one 64 KiB
            # linear window from STOCK_CODE_OFFSET, so no extra extended
            # linear address record is required mid-stream.
            chunk = blob[offset:offset + 16]
            lines.append(checksummed_record(len(chunk), addr, 0x00, chunk))
            offset += len(chunk)
        lines.append(eof_record())
        write_hex(path, lines)

    def test_stock_hex_matches_consistent_elf_and_cf2_valid(self):
        row = cat.build_catalogue_row(
            PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, self.stock_hex, self.stock_elf_consistent,
            "arm-none-eabi-readelf")
        self.assertEqual(row["stock_code_sha256"], hashlib.sha256(self.stock_code).digest())
        self.assertEqual(row["cf2_sha256"], hashlib.sha256(self.cf2_bytes).digest())
        self.assertEqual(row["target_id"], cat.TARGET_XIAO_NRF52840)
        self.assertEqual(row["profile_id"], cat.PROFILE_XIAO)

    def test_stock_hex_vs_elf_mismatch_rejected(self):
        with self.assertRaises(cat.RegionMismatchError):
            cat.build_catalogue_row(
                PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, self.stock_hex, self.stock_elf_tampered,
                "arm-none-eabi-readelf")

    def test_two_generations_from_same_inputs_are_identical(self):
        row_a = cat.build_catalogue_row(
            PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, self.stock_hex, self.stock_elf_consistent,
            "arm-none-eabi-readelf")
        row_b = cat.build_catalogue_row(
            PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, self.stock_hex, self.stock_elf_consistent,
            "arm-none-eabi-readelf")
        self.assertEqual(row_a, row_b)

        provenance = {
            "board": "xiao_nrf52840_ble", "toolchain": "arm-none-eabi-gcc-test",
            "source_date_epoch": 1779344629,
            "submodule_pins": {"Adafruit_nRF52_Bootloader": "c67f0bcf0fa8e841426335b1bbde91cda6ca1f50"},
            "artifact_sha256": {
                "mbr_hex": cat.file_sha256(PUBLIC_MBR_HEX),
                "softdevice_hex": cat.file_sha256(PUBLIC_SOFTDEVICE_HEX),
                "stock_hex": cat.file_sha256(self.stock_hex),
                "stock_elf": cat.file_sha256(self.stock_elf_consistent),
            },
        }
        header_a = cat.render_header([row_a], provenance)
        header_b = cat.render_header([row_b], provenance)
        self.assertEqual(header_a, header_b)
        self.assertNotIn(str(REPO_ROOT), header_a)  # no private/absolute paths leak into deterministic output
        self.assertNotIn("1779344630", header_a)


@unittest.skipUnless(HAVE_PUBLIC_UPSTREAM, "pinned public Adafruit_nRF52_Bootloader checkout not present")
@unittest.skipUnless(HAVE_REAL_STOCK_BUILD, "Root's real stock bootloader build not present in this environment")
class RealStockCatalogueRowTests(unittest.TestCase):
    """Builds the catalogue row from the REAL stock bootloader build plus
    REAL public MBR/S140 artifacts -- the actual production inputs, not
    synthetic data. If this build is absent, these tests are skipped, not
    faked."""

    @classmethod
    def setUpClass(cls):
        cls.row = cat.build_catalogue_row(
            PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, MAIN_STOCK_HEX, MAIN_STOCK_ELF, "arm-none-eabi-readelf")

    def test_target_and_profile(self):
        self.assertEqual(self.row["target_id"], cat.TARGET_XIAO_NRF52840)
        self.assertEqual(self.row["profile_id"], cat.PROFILE_XIAO)

    def test_mbr_and_softdevice_hashes_match_pinned_references(self):
        self.assertEqual(self.row["mbr_sha256"].hex(), cat.MBR_BODY_REFERENCE_SHA256)
        self.assertEqual(self.row["softdevice_sha256"].hex(), cat.SOFTDEVICE_730_REFERENCE_SHA256)

    def test_two_generations_from_the_real_build_are_identical(self):
        row_again = cat.build_catalogue_row(
            PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, MAIN_STOCK_HEX, MAIN_STOCK_ELF, "arm-none-eabi-readelf")
        self.assertEqual(self.row, row_again)

    def test_elf_load_segment_prefix_before_text_is_not_treated_as_flash_image(self):
        # Reproduces the real genuine-ELF nuance: LOAD segment 01 in this
        # build has file Offset=0x0/VirtAddr=0xF0000 (ELF header + 0x4000
        # bytes of toolchain alignment preface), while the actual .text
        # ALLOC section only starts at VirtAddr=0xF4000/file Offset=0x4000.
        # Asking for bytes strictly below .text's real section address
        # (anywhere in that pre-.text LOAD-segment prefix) must NOT return
        # raw copied-from-file-offset-0 header/padding bytes -- there is no
        # ALLOC section claiming that address range, so it must come back
        # as uncovered (0xFF) fill, never fabricated "flash content".
        prefix_lo, prefix_hi = 0xF0000, cat.STOCK_CODE_OFFSET  # [0xF0000, 0xF4000)
        prefix = cat.extract_elf_region_bytes(MAIN_STOCK_ELF, prefix_lo, prefix_hi)
        self.assertEqual(prefix, b"\xff" * (prefix_hi - prefix_lo))
        # Raw file bytes at offset 0 (the real ELF magic) are NOT what got
        # returned -- proves we never fell back to copying the raw LOAD
        # segment's file-offset range.
        raw_file_prefix = MAIN_STOCK_ELF.read_bytes()[0:prefix_hi - prefix_lo]
        self.assertNotEqual(prefix, raw_file_prefix)
        self.assertEqual(raw_file_prefix[:4], b"\x7fELF")

        # Meanwhile the real .text bytes immediately at 0xF4000 ARE genuine,
        # section-backed, file content (the actual loader reset vectors).
        text_start = cat.extract_elf_region_bytes(MAIN_STOCK_ELF, cat.STOCK_CODE_OFFSET, cat.STOCK_CODE_OFFSET + 8)
        self.assertEqual(struct.unpack("<II", text_start), self.row["loader_vectors"])

    def test_unmapped_gap_between_sections_is_verified_against_real_hex(self):
        # Between the .data section's LMA end and the CF2 config start there
        # is a real gap in this build backed by no ALLOC section (reserved/
        # erased flash). The producer must not silently assume this is safe
        # padding -- it must match the REAL stock HEX byte-for-byte here too
        # (already enforced by build_catalogue_row's hex_code==elf_code
        # check); this test makes that specific window's agreement explicit.
        gap_lo, gap_hi = 0xFC5A8, cat.CF2_OFFSET
        elf_gap = cat.extract_elf_region_bytes(MAIN_STOCK_ELF, gap_lo, gap_hi)
        hex_image = cat.parse_intel_hex(MAIN_STOCK_HEX)
        hex_gap = hex_image.read(gap_lo, gap_hi - gap_lo)
        self.assertEqual(elf_gap, hex_gap)
        self.assertEqual(elf_gap, b"\xff" * (gap_hi - gap_lo))


class RealUnapprovedCustomArtifactTests(unittest.TestCase):
    """Exercises extract_custom_artifact_fields() against REAL (but
    explicitly NOT-approved-for-installation) Boot overlay 1bf73e7 build
    outputs for all 4 board/role variants. 1bf73e7's positive floor lacks
    lifetime-role binding (Sol: HIGH) -- a loader-only role0->1 replacement
    can pair with a signed role1 "next" command -- so these artifacts are
    held pending Boot/FW's root fix and must NEVER be promoted/frozen as
    approved regardless of having passed their four build fits. These
    fixtures are another agent's scratch tree, not guaranteed stable
    across environments/runs -- tests here are SKIPPED (not faked) when
    absent, consistent with the existing _env_path() convention, and are
    deliberately kept OUT of the OTA_BOOT_CATALOGUE_REQUIRE_REAL_ARTIFACTS
    strict gate (that gate is about the real APPROVED stock-only
    generation pipeline; these fixtures are explicitly unapproved
    extraction-only inputs per MAIN's instruction and must never be
    embedded in the real generated header). Once the fix lands, custom
    rows must be generated from the NEW independently qualified artifacts,
    not by reclassifying these.

    This class calls extract_custom_artifact_fields() directly (the pure,
    ungated extraction function) -- NEVER build_custom_catalogue_row()
    with a fabricated "approved" qualification_status. No assertion here
    pins any of this artifact's own measured hash bytes as an expected/
    golden/reference value -- only shape, determinism, and gate-refusal
    are checked, so nothing here could accidentally "freeze" a vulnerable
    hash as approved."""

    FIXTURE_ROOT = _env_path(
        "OTA_BOOT_CATALOGUE_UNAPPROVED_CUSTOM_FIXTURES",
        REPO_ROOT / ".tmp" / "boot-hydra-finalqual-cli")
    KEY_HEADER = REPO_ROOT / "bootloader" / "xiao_nrf52840_ota" / "include" / "xiao_ota_public_key.h"

    VARIANTS = {
        ("xiao_nrf52840", 0): (
            "ota-boot-builds/xiao_nrf52840_ota_noswd_upstream/_build/build-xiao_nrf52840_ble/"
            "xiao_nrf52840_ble_bootloader-c67f0bcf0fa8.out",
            "xiao_nrf52840_ota_artifacts/custom-noswd/xiao_nrf52840_ota_noswd.hex",
            "xiao_nrf52840_ota_artifacts/custom-noswd/xiao_nrf52840_ota_noswd_update.uf2"),
        ("xiao_nrf52840", 1): (
            "ota-boot-builds/xiao_nrf52840_ota_role1_noswd_upstream/_build/build-xiao_nrf52840_ble/"
            "xiao_nrf52840_ble_bootloader-c67f0bcf0fa8.out",
            "xiao_nrf52840_ota_role1_artifacts/custom-noswd/xiao_nrf52840_ota_role1_noswd.hex",
            "xiao_nrf52840_ota_role1_artifacts/custom-noswd/xiao_nrf52840_ota_role1_noswd_update.uf2"),
        ("sensecap_solar_p1", 0): (
            "ota-boot-builds/sensecap_solar_p1_ota_noswd_upstream/_build/build-xiao_nrf52840_ble/"
            "xiao_nrf52840_ble_bootloader-c67f0bcf0fa8.out",
            "sensecap_solar_p1_ota_artifacts/custom-noswd/sensecap_solar_p1_ota_noswd.hex",
            "sensecap_solar_p1_ota_artifacts/custom-noswd/sensecap_solar_p1_ota_noswd_update.uf2"),
        ("sensecap_solar_p1", 1): (
            "ota-boot-builds/sensecap_solar_p1_ota_role1_noswd_upstream/_build/build-xiao_nrf52840_ble/"
            "xiao_nrf52840_ble_bootloader-c67f0bcf0fa8.out",
            "sensecap_solar_p1_ota_role1_artifacts/custom-noswd/sensecap_solar_p1_ota_role1_noswd.hex",
            "sensecap_solar_p1_ota_role1_artifacts/custom-noswd/sensecap_solar_p1_ota_role1_noswd_update.uf2"),
    }

    @classmethod
    def setUpClass(cls):
        if not HAVE_PUBLIC_UPSTREAM:
            raise unittest.SkipTest("pinned public Adafruit_nRF52_Bootloader checkout not present")
        if not HAVE_ARM_TOOLCHAIN:
            raise unittest.SkipTest("arm-none-eabi-as/-ld/-readelf not found on PATH")
        if not cls.FIXTURE_ROOT.is_dir():
            raise unittest.SkipTest(
                f"unapproved Boot overlay 1bf73e7 fixture tree not present at {cls.FIXTURE_ROOT} "
                "(override with OTA_BOOT_CATALOGUE_UNAPPROVED_CUSTOM_FIXTURES)")
        if not cls.KEY_HEADER.is_file():
            raise unittest.SkipTest(f"public key header not present at {cls.KEY_HEADER}")
        missing = []
        for (board, role), (elf_rel, hex_rel, uf2_rel) in cls.VARIANTS.items():
            for rel in (elf_rel, hex_rel, uf2_rel):
                if not (cls.FIXTURE_ROOT / rel).is_file():
                    missing.append(str(cls.FIXTURE_ROOT / rel))
        if missing:
            raise unittest.SkipTest("missing unapproved-fixture files: " + ", ".join(missing))

    def _descriptor(self, board, role_id):
        elf_rel, hex_rel, uf2_rel = self.VARIANTS[(board, role_id)]
        return {
            "logical_board": board,
            "role_id": role_id,
            "elf": str(self.FIXTURE_ROOT / elf_rel),
            "hex": str(self.FIXTURE_ROOT / hex_rel),
            "uf2": str(self.FIXTURE_ROOT / uf2_rel),
            "key_header": str(self.KEY_HEADER),
            # Honest, non-fabricated provenance strings identifying this
            # EXACT real-but-unapproved overlay tree -- never a claim of
            # "unmodified upstream" or a fake pin.
            "overlay_revision": "1bf73e7",
            "overlay_scope_digest": "unapproved-extraction-test-fixture",
            "public_source_pin": "c67f0bcf0fa8e841426335b1bbde91cda6ca1f50",
            "qualification_status": "test_only",
        }

    def test_extraction_succeeds_for_all_four_board_role_variants(self):
        for board, role_id in self.VARIANTS:
            with self.subTest(board=board, role_id=role_id):
                descriptor = self._descriptor(board, role_id)
                row = cat.extract_custom_artifact_fields(
                    descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")
                target_id, profile_id = cat.CUSTOM_BOARD_ROLE_MATRIX[(board, role_id)]
                self.assertEqual(row["target_id"], target_id)
                self.assertEqual(row["profile_id"], profile_id)
                self.assertEqual(row["loader_kind"], cat.LOADER_KIND_MESHCORE_OTA)
                self.assertEqual(row["role_binding"], cat.ROLE_BINDING_EXACT)
                self.assertEqual(row["expected_role_id"], role_id)
                self.assertEqual(len(row["expected_boot_info"]), cat.BOOT_INFO_SIZE)
                self.assertEqual(row["mbr_sha256"].hex(), cat.MBR_BODY_REFERENCE_SHA256)
                self.assertEqual(row["softdevice_sha256"].hex(), cat.SOFTDEVICE_730_REFERENCE_SHA256)

    def test_extraction_is_deterministic(self):
        descriptor = self._descriptor("xiao_nrf52840", 0)
        row_a = cat.extract_custom_artifact_fields(
            descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")
        row_b = cat.extract_custom_artifact_fields(
            descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")
        self.assertEqual(row_a, row_b)

    def test_rejected_larger_profile_code_start_is_detected_as_distinct_from_real_fixtures(self):
        # The real fixtures all start their loader code at the required
        # 0xF4000 window. Build a genuine, toolchain-produced synthetic
        # ELF whose code instead starts at the explicitly rejected larger
        # BLE/custom-profile bank address, and confirm the producer
        # actually refuses it (not dead/unexercised code).
        self.assertNotEqual(cat.REJECTED_LARGER_PROFILE_CODE_START, cat.STOCK_CODE_OFFSET)
        rejected_elf = build_binary_region_elf(
            "rejected_profile_start", b"\x00" * 16, cat.REJECTED_LARGER_PROFILE_CODE_START)
        with self.assertRaises(cat.RegionMismatchError):
            cat.validate_elf_code_start(rejected_elf, "arm-none-eabi-readelf")

    def test_unknown_board_role_combination_rejected(self):
        descriptor = self._descriptor("xiao_nrf52840", 0)
        descriptor["logical_board"] = "not_a_real_board"
        with self.assertRaises(cat.RegionMismatchError):
            cat.extract_custom_artifact_fields(
                descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")

    def test_build_custom_catalogue_row_refuses_non_approved_status(self):
        # The real fixture is explicitly "test_only" (per MAIN: Boot tree
        # 1bf73e7's positive floor lacks lifetime-role binding -- Sol
        # HIGH -- so it is NOT approved for installation regardless of
        # having passed its four build fits).
        # The hard gate must refuse it, never silently embedding it.
        descriptor = self._descriptor("xiao_nrf52840", 1)
        self.assertEqual(descriptor["qualification_status"], "test_only")
        with self.assertRaises(cat.UnapprovedOverlayError):
            cat.build_custom_catalogue_row(
                descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")

    def test_build_custom_catalogue_row_accepts_only_when_explicitly_approved(self):
        # Still using the SAME real (unapproved) artifact bytes -- this
        # only tests the gate's mechanics, and the resulting row is never
        # written into the real tracked generated header by this suite.
        descriptor = self._descriptor("sensecap_solar_p1", 0)
        descriptor["qualification_status"] = "approved"
        row = cat.build_custom_catalogue_row(
            descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")
        expected_row = cat.extract_custom_artifact_fields(
            descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")
        self.assertEqual(row, expected_row)

    def test_four_variants_produce_independent_rows(self):
        rows = {}
        for board, role_id in self.VARIANTS:
            descriptor = self._descriptor(board, role_id)
            rows[(board, role_id)] = cat.extract_custom_artifact_fields(
                descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")
        # All four real builds must be distinguishable by at least
        # target/profile/role projection (never a single cloned row).
        projections = {
            (r["target_id"], r["profile_id"], r["expected_role_id"]) for r in rows.values()
        }
        self.assertEqual(len(projections), 4)

    # -- Sol's review: parse_uf2 previously ignored the UF2 block flags/
    # block_no/num_blocks/family_id fields entirely. These regressions
    # mutate a COPY of a real, otherwise-exact packaged fixture's UF2 bytes
    # (never the fixture itself) one field at a time and confirm the
    # producer now refuses each malformed/contradictory case explicitly --
    # never silently coercing it into looking like a valid package. 1bf's
    # real bytes are still never promoted/approved by these tests.

    def _mutated_uf2_copy(self, name, block_index=0, field_overrides=None):
        """Copies the real xiao_nrf52840 role0 fixture's UF2 bytes into
        TEST_WORK and overwrites one or more little-endian uint32 fields
        (by byte offset within the 512-byte block) at the given block
        index, leaving every other byte -- including all other blocks --
        untouched."""
        src = self.FIXTURE_ROOT / self.VARIANTS[("xiao_nrf52840", 0)][2]
        data = bytearray(src.read_bytes())
        offset = block_index * cat._UF2_BLOCK_SIZE
        for field_offset, value in (field_overrides or {}).items():
            struct.pack_into("<I", data, offset + field_offset, value)
        work = TEST_WORK / "uf2_mutation"
        work.mkdir(parents=True, exist_ok=True)
        out_path = work / name
        out_path.write_bytes(bytes(data))
        return out_path

    def test_noflash_flag_on_otherwise_matching_block_is_rejected(self):
        mutated = self._mutated_uf2_copy(
            "noflash.uf2", block_index=0,
            field_overrides={8: cat._UF2_FLAG_FAMILY_ID_PRESENT | cat._UF2_FLAG_NOT_MAIN_FLASH})
        descriptor = self._descriptor("xiao_nrf52840", 0)
        descriptor["uf2"] = str(mutated)
        with self.assertRaisesRegex(cat.CorruptHexError, "NOT_MAIN_FLASH"):
            cat.extract_custom_artifact_fields(
                descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")

    def test_unsupported_flag_bit_is_rejected(self):
        mutated = self._mutated_uf2_copy(
            "unsupported_flags.uf2", block_index=0,
            field_overrides={8: cat._UF2_FLAG_FAMILY_ID_PRESENT | cat._UF2_FLAG_FILE_CONTAINER})
        descriptor = self._descriptor("xiao_nrf52840", 0)
        descriptor["uf2"] = str(mutated)
        with self.assertRaisesRegex(cat.CorruptHexError, "unsupported UF2 flags"):
            cat.extract_custom_artifact_fields(
                descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")

    def test_contradictory_num_blocks_is_rejected(self):
        mutated = self._mutated_uf2_copy("bad_num_blocks.uf2", block_index=1, field_overrides={24: 999999})
        descriptor = self._descriptor("xiao_nrf52840", 0)
        descriptor["uf2"] = str(mutated)
        with self.assertRaisesRegex(cat.CorruptHexError, "num_blocks"):
            cat.extract_custom_artifact_fields(
                descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")

    def test_duplicate_block_no_is_rejected(self):
        # Block 1 claims the same block_no (0) as block 0.
        mutated = self._mutated_uf2_copy("dup_block_no.uf2", block_index=1, field_overrides={20: 0})
        descriptor = self._descriptor("xiao_nrf52840", 0)
        descriptor["uf2"] = str(mutated)
        with self.assertRaisesRegex(cat.CorruptHexError, "duplicate or out-of-range block_no"):
            cat.extract_custom_artifact_fields(
                descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")

    def test_wrong_family_id_is_rejected(self):
        mutated = self._mutated_uf2_copy(
            "wrong_family.uf2", block_index=0, field_overrides={28: cat.CF2_UF2_FAMILY})
        descriptor = self._descriptor("xiao_nrf52840", 0)
        descriptor["uf2"] = str(mutated)
        with self.assertRaisesRegex(cat.CorruptHexError, "UF2_FAMILY_ID_BOOTLOADER"):
            cat.extract_custom_artifact_fields(
                descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")

    def test_address_overflow_is_rejected(self):
        mutated = self._mutated_uf2_copy("addr_overflow.uf2", block_index=0, field_overrides={12: 0xFFFFFFF0})
        descriptor = self._descriptor("xiao_nrf52840", 0)
        descriptor["uf2"] = str(mutated)
        with self.assertRaisesRegex(cat.CorruptHexError, "overflow"):
            cat.extract_custom_artifact_fields(
                descriptor, PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, "arm-none-eabi-readelf")

    def test_cli_noflash_mutated_package_refused_with_both_sentinel_outputs_unchanged(self):
        # Full CLI/aggregate-manifest level regression, per Sol's exact
        # request: a NOFLASH-mutated COPY of an otherwise-matching real
        # packaged fixture must make the WHOLE run refuse, leaving BOTH
        # pre-existing out_header/out_provenance sentinel contents
        # unchanged -- never a partial publish. qualification_status is
        # set to "approved" on the three untouched real 1bf73e7 fixtures
        # here ONLY to reach the extraction stage in this one deliberately
        # failing in-process run (never written to disk, since the whole
        # run exits non-zero before any output write) -- this does not
        # promote/freeze 1bf73e7 as an approved row; see class docstring.
        if not HAVE_REAL_STOCK_BUILD:
            raise unittest.SkipTest("Root's real stock bootloader build not present in this environment")
        work = TEST_WORK / "cli_noflash_regression"
        work.mkdir(parents=True, exist_ok=True)
        out_header = work / "Nrf52ApprovedBootCatalogue.h"
        out_provenance = work / "provenance.json"
        sentinel_header = "// sentinel: previously published header, must not change\n"
        sentinel_provenance = json.dumps({"sentinel": True}) + "\n"
        out_header.write_text(sentinel_header)
        out_provenance.write_text(sentinel_provenance)

        mutated_uf2 = self._mutated_uf2_copy(
            "cli_noflash.uf2", block_index=0,
            field_overrides={8: cat._UF2_FLAG_FAMILY_ID_PRESENT | cat._UF2_FLAG_NOT_MAIN_FLASH})

        descriptors = []
        for board, role_id in self.VARIANTS:
            descriptor = self._descriptor(board, role_id)
            descriptor["qualification_status"] = "approved"
            if (board, role_id) == ("xiao_nrf52840", 0):
                descriptor["uf2"] = str(mutated_uf2)
            descriptors.append(descriptor)
        manifest_path = work / "manifest.json"
        manifest_path.write_text(json.dumps({"descriptors": descriptors}))

        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "ota_boot_catalogue.py"),
             "--mbr-hex", str(PUBLIC_MBR_HEX), "--softdevice-hex", str(PUBLIC_SOFTDEVICE_HEX),
             "--stock-hex", str(MAIN_STOCK_HEX), "--stock-elf", str(MAIN_STOCK_ELF),
             "--board", "xiao_nrf52840_ble", "--toolchain", "arm-none-eabi-gcc-test",
             "--source-date-epoch", "1779344629", "--readelf", "arm-none-eabi-readelf",
             "--out-header", str(out_header), "--out-provenance", str(out_provenance),
             "--custom-manifest", str(manifest_path)],
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NOT_MAIN_FLASH", result.stderr)
        self.assertEqual(out_header.read_text(), sentinel_header)
        self.assertEqual(out_provenance.read_text(), sentinel_provenance)


class MultiRowHeaderAndCliTests(unittest.TestCase):
    """Exercises render_header()'s schema-v2 multi-row shape and the
    full --custom-descriptor CLI path, using the REAL public MBR/S140
    inputs and REAL stock build plus a synthetic (clearly-fabricated,
    explicitly test-only) custom descriptor -- never real unapproved
    overlay bytes claimed as "approved" for CLI plumbing checks."""

    @classmethod
    def setUpClass(cls):
        if not HAVE_PUBLIC_UPSTREAM:
            raise unittest.SkipTest("pinned public Adafruit_nRF52_Bootloader checkout not present")
        if not HAVE_ARM_TOOLCHAIN:
            raise unittest.SkipTest("arm-none-eabi toolchain not present")
        if not HAVE_REAL_STOCK_BUILD:
            raise unittest.SkipTest("Root's real stock bootloader build not present in this environment")
        cls.stock_row = cat.build_catalogue_row(
            PUBLIC_MBR_HEX, PUBLIC_SOFTDEVICE_HEX, MAIN_STOCK_HEX, MAIN_STOCK_ELF, "arm-none-eabi-readelf")
        cls.provenance = {
            "board": "xiao_nrf52840_ble", "toolchain": "arm-none-eabi-gcc-test",
            "source_date_epoch": 1779344629,
            "submodule_pins": {"Adafruit_nRF52_Bootloader": "c67f0bcf0fa8e841426335b1bbde91cda6ca1f50"},
            "artifact_sha256": {
                "mbr_hex": cat.file_sha256(PUBLIC_MBR_HEX),
                "softdevice_hex": cat.file_sha256(PUBLIC_SOFTDEVICE_HEX),
                "stock_hex": cat.file_sha256(MAIN_STOCK_HEX),
                "stock_elf": cat.file_sha256(MAIN_STOCK_ELF),
            },
        }

    def test_stock_only_header_has_schema_version_and_single_row(self):
        header = cat.render_header([self.stock_row], self.provenance)
        self.assertIn(f"schema_version={cat.SCHEMA_VERSION}", header)
        self.assertIn("kNrf52BootCatalogueSchemaVersion", header)
        self.assertIn("static_assert", header)
        self.assertEqual(header.count("Nrf52LoaderKind::VendorStock"), 1)
        self.assertNotIn("Nrf52LoaderKind::MeshCoreOta", header)

    def test_multi_row_header_contains_both_rows_sorted_deterministically(self):
        custom_row = dict(self.stock_row)
        custom_row["target_id"] = cat.TARGET_SENSECAP_SOLAR_P1
        custom_row["profile_id"] = cat.PROFILE_SENSECAP
        custom_row["loader_kind"] = cat.LOADER_KIND_MESHCORE_OTA
        custom_row["role_binding"] = cat.ROLE_BINDING_EXACT
        custom_row["expected_role_id"] = 1
        rows = sorted([self.stock_row, custom_row], key=cat._row_sort_key)
        header_a = cat.render_header(rows, self.provenance)
        header_b = cat.render_header(list(reversed(rows)), self.provenance)
        # Deterministic regardless of INPUT order, because render_header
        # is expected to be fed an already-sorted list by main() -- but
        # explicitly confirm the two fixed row orders used here both
        # still contain both rows (sorting is main()'s responsibility,
        # exercised separately by the CLI tests below).
        self.assertEqual(header_a.count("kApprovedBootCatalogueRowCount"), header_b.count(
            "kApprovedBootCatalogueRowCount"))
        self.assertIn("Nrf52LoaderKind::VendorStock", header_a)
        self.assertIn("Nrf52LoaderKind::MeshCoreOta", header_a)

    def _write_descriptor(self, path: Path, qualification_status: str):
        descriptor = {
            "logical_board": "xiao_nrf52840",
            "role_id": 1,
            "elf": str(MAIN_STOCK_ELF),
            "hex": str(MAIN_STOCK_HEX),
            "uf2": str(MAIN_STOCK_HEX),  # deliberately wrong/unused path; see note below
            "key_header": str(REPO_ROOT / "bootloader" / "xiao_nrf52840_ota" / "include" /
                               "xiao_ota_public_key.h"),
            "overlay_revision": "synthetic-test-only",
            "overlay_scope_digest": "synthetic-test-only",
            "public_source_pin": "c67f0bcf0fa8e841426335b1bbde91cda6ca1f50",
            "qualification_status": qualification_status,
        }
        path.write_text(json.dumps(descriptor))
        return descriptor

    def _cli_args(self, out_header, out_provenance, extra=()):
        return [
            sys.executable, str(REPO_ROOT / "scripts" / "ota_boot_catalogue.py"),
            "--mbr-hex", str(PUBLIC_MBR_HEX), "--softdevice-hex", str(PUBLIC_SOFTDEVICE_HEX),
            "--stock-hex", str(MAIN_STOCK_HEX), "--stock-elf", str(MAIN_STOCK_ELF),
            "--board", "xiao_nrf52840_ble", "--toolchain", "arm-none-eabi-gcc-test",
            "--source-date-epoch", "1779344629",
            "--readelf", "arm-none-eabi-readelf",
            "--out-header", str(out_header), "--out-provenance", str(out_provenance),
            *extra,
        ]

    def test_cli_stock_only_default_succeeds(self):
        work = TEST_WORK / "cli_stock_only"
        work.mkdir(parents=True, exist_ok=True)
        out_header = work / "Nrf52ApprovedBootCatalogue.h"
        out_provenance = work / "provenance.json"
        result = subprocess.run(self._cli_args(out_header, out_provenance),
                                 capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(out_header.is_file())
        self.assertIn("VendorStock", out_header.read_text())
        self.assertNotIn("MeshCoreOta", out_header.read_text())

    def test_cli_non_approved_custom_descriptor_refused_with_no_output(self):
        work = TEST_WORK / "cli_non_approved"
        work.mkdir(parents=True, exist_ok=True)
        out_header = work / "Nrf52ApprovedBootCatalogue.h"
        out_provenance = work / "provenance.json"
        if out_header.exists():
            out_header.unlink()
        descriptor_path = work / "descriptor.json"
        self._write_descriptor(descriptor_path, "test_only")
        result = subprocess.run(
            self._cli_args(out_header, out_provenance, extra=["--custom-descriptor", str(descriptor_path)]),
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UnapprovedOverlayError", result.stderr)
        self.assertFalse(out_header.exists())

    def test_cli_malformed_json_descriptor_refused(self):
        work = TEST_WORK / "cli_malformed"
        work.mkdir(parents=True, exist_ok=True)
        out_header = work / "Nrf52ApprovedBootCatalogue.h"
        out_provenance = work / "provenance.json"
        descriptor_path = work / "descriptor.json"
        descriptor_path.write_text("{not valid json")
        result = subprocess.run(
            self._cli_args(out_header, out_provenance, extra=["--custom-descriptor", str(descriptor_path)]),
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(out_header.exists())

    def test_cli_missing_descriptor_file_refused(self):
        work = TEST_WORK / "cli_missing_descriptor"
        work.mkdir(parents=True, exist_ok=True)
        out_header = work / "Nrf52ApprovedBootCatalogue.h"
        out_provenance = work / "provenance.json"
        missing_path = work / "does_not_exist.json"
        result = subprocess.run(
            self._cli_args(out_header, out_provenance, extra=["--custom-descriptor", str(missing_path)]),
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("MissingArtifactError", result.stderr)
        self.assertFalse(out_header.exists())

    def _write_manifest_descriptor(self, logical_board, role_id, qualification_status="test_only"):
        return {
            "logical_board": logical_board,
            "role_id": role_id,
            "elf": str(MAIN_STOCK_ELF),
            "hex": str(MAIN_STOCK_HEX),
            "uf2": str(MAIN_STOCK_HEX),
            "key_header": str(REPO_ROOT / "bootloader" / "xiao_nrf52840_ota" / "include" /
                               "xiao_ota_public_key.h"),
            "overlay_revision": "synthetic-test-only",
            "overlay_scope_digest": "synthetic-test-only",
            "public_source_pin": "c67f0bcf0fa8e841426335b1bbde91cda6ca1f50",
            "qualification_status": qualification_status,
        }

    def test_load_custom_manifest_accepts_exactly_the_required_four(self):
        work = TEST_WORK / "manifest_complete"
        work.mkdir(parents=True, exist_ok=True)
        manifest_path = work / "manifest.json"
        descriptors = [
            self._write_manifest_descriptor("xiao_nrf52840", 0),
            self._write_manifest_descriptor("xiao_nrf52840", 1),
            self._write_manifest_descriptor("sensecap_solar_p1", 0),
            self._write_manifest_descriptor("sensecap_solar_p1", 1),
        ]
        manifest_path.write_text(json.dumps({"descriptors": descriptors}))
        loaded = cat.load_custom_manifest(manifest_path)
        self.assertEqual(len(loaded), 4)

    def test_load_custom_manifest_rejects_missing_entry(self):
        work = TEST_WORK / "manifest_partial"
        work.mkdir(parents=True, exist_ok=True)
        manifest_path = work / "manifest.json"
        descriptors = [
            self._write_manifest_descriptor("xiao_nrf52840", 0),
            self._write_manifest_descriptor("xiao_nrf52840", 1),
            self._write_manifest_descriptor("sensecap_solar_p1", 0),
        ]
        manifest_path.write_text(json.dumps({"descriptors": descriptors}))
        with self.assertRaises(cat.IncompleteCustomManifestError):
            cat.load_custom_manifest(manifest_path)

    def test_load_custom_manifest_rejects_duplicate_entry(self):
        work = TEST_WORK / "manifest_duplicate"
        work.mkdir(parents=True, exist_ok=True)
        manifest_path = work / "manifest.json"
        descriptors = [
            self._write_manifest_descriptor("xiao_nrf52840", 0),
            self._write_manifest_descriptor("xiao_nrf52840", 0),
            self._write_manifest_descriptor("sensecap_solar_p1", 0),
            self._write_manifest_descriptor("sensecap_solar_p1", 1),
        ]
        manifest_path.write_text(json.dumps({"descriptors": descriptors}))
        with self.assertRaises(cat.IncompleteCustomManifestError):
            cat.load_custom_manifest(manifest_path)

    def test_load_custom_manifest_rejects_unrecognized_board_role(self):
        work = TEST_WORK / "manifest_unknown"
        work.mkdir(parents=True, exist_ok=True)
        manifest_path = work / "manifest.json"
        descriptors = [
            self._write_manifest_descriptor("xiao_nrf52840", 0),
            self._write_manifest_descriptor("xiao_nrf52840", 1),
            self._write_manifest_descriptor("sensecap_solar_p1", 0),
            self._write_manifest_descriptor("unknown_board", 0),
        ]
        manifest_path.write_text(json.dumps({"descriptors": descriptors}))
        with self.assertRaises(cat.IncompleteCustomManifestError):
            cat.load_custom_manifest(manifest_path)

    def test_cli_custom_manifest_and_custom_descriptor_mutually_exclusive(self):
        work = TEST_WORK / "cli_manifest_exclusive"
        work.mkdir(parents=True, exist_ok=True)
        out_header = work / "Nrf52ApprovedBootCatalogue.h"
        out_provenance = work / "provenance.json"
        manifest_path = work / "manifest.json"
        manifest_path.write_text(json.dumps({"descriptors": []}))
        descriptor_path = work / "descriptor.json"
        self._write_descriptor(descriptor_path, "test_only")
        result = subprocess.run(
            self._cli_args(out_header, out_provenance, extra=[
                "--custom-descriptor", str(descriptor_path),
                "--custom-manifest", str(manifest_path),
            ]),
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mutually exclusive", result.stderr)
        self.assertFalse(out_header.exists())

    def test_cli_custom_manifest_partial_set_refused_with_no_output(self):
        work = TEST_WORK / "cli_manifest_partial"
        work.mkdir(parents=True, exist_ok=True)
        out_header = work / "Nrf52ApprovedBootCatalogue.h"
        out_provenance = work / "provenance.json"
        manifest_path = work / "manifest.json"
        descriptors = [
            self._write_manifest_descriptor("xiao_nrf52840", 0),
            self._write_manifest_descriptor("xiao_nrf52840", 1),
        ]
        manifest_path.write_text(json.dumps({"descriptors": descriptors}))
        result = subprocess.run(
            self._cli_args(out_header, out_provenance, extra=["--custom-manifest", str(manifest_path)]),
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("IncompleteCustomManifestError", result.stderr)
        self.assertFalse(out_header.exists())

    def test_cli_custom_manifest_complete_but_non_approved_refused_with_no_output(self):
        work = TEST_WORK / "cli_manifest_non_approved"
        work.mkdir(parents=True, exist_ok=True)
        out_header = work / "Nrf52ApprovedBootCatalogue.h"
        out_provenance = work / "provenance.json"
        manifest_path = work / "manifest.json"
        descriptors = [
            self._write_manifest_descriptor("xiao_nrf52840", 0, "test_only"),
            self._write_manifest_descriptor("xiao_nrf52840", 1, "test_only"),
            self._write_manifest_descriptor("sensecap_solar_p1", 0, "test_only"),
            self._write_manifest_descriptor("sensecap_solar_p1", 1, "test_only"),
        ]
        manifest_path.write_text(json.dumps({"descriptors": descriptors}))
        result = subprocess.run(
            self._cli_args(out_header, out_provenance, extra=["--custom-manifest", str(manifest_path)]),
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UnapprovedOverlayError", result.stderr)
        self.assertFalse(out_header.exists())

    def test_load_custom_manifest_rejects_non_string_logical_board(self):
        work = TEST_WORK / "manifest_bad_board_type"
        work.mkdir(parents=True, exist_ok=True)
        manifest_path = work / "manifest.json"
        descriptors = [
            self._write_manifest_descriptor("xiao_nrf52840", 0),
            self._write_manifest_descriptor("xiao_nrf52840", 1),
            self._write_manifest_descriptor("sensecap_solar_p1", 0),
            self._write_manifest_descriptor(["not", "a", "string"], 1),
        ]
        manifest_path.write_text(json.dumps({"descriptors": descriptors}))
        with self.assertRaises(cat.IncompleteCustomManifestError):
            cat.load_custom_manifest(manifest_path)

    def test_load_custom_manifest_rejects_bool_role_id_not_aliased_to_int(self):
        # type(True) is bool, not int; a JSON `true`/`false` role_id must be
        # a typed refusal here, never silently compared equal to role_id 1/0.
        work = TEST_WORK / "manifest_bool_role"
        work.mkdir(parents=True, exist_ok=True)
        manifest_path = work / "manifest.json"
        descriptors = [
            self._write_manifest_descriptor("xiao_nrf52840", 0),
            self._write_manifest_descriptor("xiao_nrf52840", True),
            self._write_manifest_descriptor("sensecap_solar_p1", 0),
            self._write_manifest_descriptor("sensecap_solar_p1", 1),
        ]
        manifest_path.write_text(json.dumps({"descriptors": descriptors}))
        with self.assertRaises(cat.IncompleteCustomManifestError):
            cat.load_custom_manifest(manifest_path)

    def test_load_custom_manifest_rejects_non_int_role_id(self):
        work = TEST_WORK / "manifest_float_role"
        work.mkdir(parents=True, exist_ok=True)
        manifest_path = work / "manifest.json"
        descriptors = [
            self._write_manifest_descriptor("xiao_nrf52840", 0),
            self._write_manifest_descriptor("xiao_nrf52840", 1),
            self._write_manifest_descriptor("sensecap_solar_p1", 0),
            self._write_manifest_descriptor("sensecap_solar_p1", 1.0),
        ]
        manifest_path.write_text(json.dumps({"descriptors": descriptors}))
        with self.assertRaises(cat.IncompleteCustomManifestError):
            cat.load_custom_manifest(manifest_path)

    def test_load_custom_manifest_rejects_dict_shaped_descriptor_entry(self):
        # A descriptor list entry that is itself a nested list/non-dict must
        # not reach set()/hash construction and raise an uncaught TypeError.
        work = TEST_WORK / "manifest_list_entry"
        work.mkdir(parents=True, exist_ok=True)
        manifest_path = work / "manifest.json"
        descriptors = [
            self._write_manifest_descriptor("xiao_nrf52840", 0),
            self._write_manifest_descriptor("xiao_nrf52840", 1),
            self._write_manifest_descriptor("sensecap_solar_p1", 0),
            ["not", "a", "descriptor", "dict"],
        ]
        manifest_path.write_text(json.dumps({"descriptors": descriptors}))
        with self.assertRaises(cat.IncompleteCustomManifestError):
            cat.load_custom_manifest(manifest_path)

    def test_cli_failed_manifest_run_leaves_preexisting_sentinel_outputs_unchanged(self):
        # Regression for the write-ordering fix: a pre-existing out_header/
        # out_provenance pair (simulating a prior successful publish) must
        # remain byte-for-byte unchanged after a run that fails validation
        # -- not merely "absent in an empty directory".
        work = TEST_WORK / "cli_manifest_sentinel_unchanged"
        work.mkdir(parents=True, exist_ok=True)
        out_header = work / "Nrf52ApprovedBootCatalogue.h"
        out_provenance = work / "provenance.json"
        sentinel_header = "// sentinel: previously published header, must not change\n"
        sentinel_provenance = json.dumps({"sentinel": True}) + "\n"
        out_header.write_text(sentinel_header)
        out_provenance.write_text(sentinel_provenance)

        manifest_path = work / "manifest.json"
        descriptors = [
            self._write_manifest_descriptor("xiao_nrf52840", 0, "test_only"),
            self._write_manifest_descriptor("xiao_nrf52840", 1, "test_only"),
            self._write_manifest_descriptor("sensecap_solar_p1", 0, "test_only"),
            self._write_manifest_descriptor("sensecap_solar_p1", 1, "test_only"),
        ]
        manifest_path.write_text(json.dumps({"descriptors": descriptors}))
        result = subprocess.run(
            self._cli_args(out_header, out_provenance, extra=["--custom-manifest", str(manifest_path)]),
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UnapprovedOverlayError", result.stderr)
        self.assertEqual(out_header.read_text(), sentinel_header)
        self.assertEqual(out_provenance.read_text(), sentinel_provenance)

    def test_cli_successful_run_publishes_both_header_and_provenance(self):
        work = TEST_WORK / "cli_success_both_outputs"
        work.mkdir(parents=True, exist_ok=True)
        out_header = work / "Nrf52ApprovedBootCatalogue.h"
        out_provenance = work / "provenance.json"
        result = subprocess.run(self._cli_args(out_header, out_provenance),
                                 capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(out_header.is_file())
        self.assertTrue(out_provenance.is_file())
        manifest = json.loads(out_provenance.read_text())
        self.assertIn("rows", manifest)
        self.assertEqual(len(manifest["rows"]), 1)


class CF2ValidationTests(unittest.TestCase):
    def test_fully_valid_cf2_block_accepted(self):
        cf2 = make_valid_cf2_bytes()
        sha = cat.validate_cf2(cf2)
        self.assertEqual(sha, hashlib.sha256(cf2).hexdigest())

    def test_wrong_cf2_magic_rejected(self):
        cf2 = bytearray(make_valid_cf2_bytes())
        struct.pack_into("<I", cf2, 0, 0x00000000)
        with self.assertRaises(cat.RegionMismatchError):
            cat.validate_cf2(bytes(cf2))

    def test_wrong_flash_size_rejected(self):
        cf2 = bytearray(make_valid_cf2_bytes())
        struct.pack_into("<I", cf2, 20, 0x80000)  # plausible-looking but wrong flash size
        with self.assertRaises(cat.RegionMismatchError):
            cat.validate_cf2(bytes(cf2))

    def test_wrong_board_id_rejected(self):
        cf2 = bytearray(make_valid_cf2_bytes())
        struct.pack_into("<I", cf2, 36, 0x12340044)  # cross-profile-looking board id
        with self.assertRaises(cat.RegionMismatchError):
            cat.validate_cf2(bytes(cf2))

    def test_wrong_cf2_size_rejected(self):
        with self.assertRaises(cat.RegionMismatchError):
            cat.validate_cf2(b"\xff" * (cat.CF2_SIZE - 1))


class ConfigPolicyTests(unittest.TestCase):
    def test_config_mbr_blank_uicr_set(self):
        config_id = cat.resolve_boot_config_policy(
            (cat.MBR_FIELD_UNSET, cat.MBR_FIELD_UNSET), (0xF4000, 0xFE000))
        self.assertEqual(config_id, cat.CONFIG_ID_MBR_BLANK_UICR_SET)
        self.assertEqual(config_id, 0x00010001)

    def test_config_mbr_set_uicr_mirror(self):
        config_id = cat.resolve_boot_config_policy((0xF4000, 0xFE000), (0xF4000, 0xFE000))
        self.assertEqual(config_id, cat.CONFIG_ID_MBR_SET_UICR_MIRROR)
        self.assertEqual(config_id, 0x00010002)

    def test_mixed_conflicting_tuple_is_unsupported(self):
        # MBR fields present but UICR fields absent -- not a listed policy.
        config_id = cat.resolve_boot_config_policy((0xF4000, 0xFE000), (cat.MBR_FIELD_UNSET, cat.MBR_FIELD_UNSET))
        self.assertIsNone(config_id)

    def test_zero_value_is_not_treated_as_unset(self):
        # An explicit 0 in the MBR fields must not accidentally match the
        # "blank" (kNrf52BootFieldUnset) policy.
        config_id = cat.resolve_boot_config_policy((0, 0), (0xF4000, 0xFE000))
        self.assertIsNone(config_id)


class CppMatcherProductTests(unittest.TestCase):
    """Compiles and runs a tiny host program against the REAL
    src/ota/platform/Nrf52BootCatalogue.h pure DTO/matcher (the actual
    product header, not a reimplementation), to verify typed outcomes:
    Approved / Mismatch / Unsupported (non-blank param page, bad policy
    tuple, cross-profile/no-row-for-target) / IoError / MissingCatalogue."""

    HEADER = REPO_ROOT / "src" / "ota" / "platform" / "Nrf52BootCatalogue.h"

    @classmethod
    def setUpClass(cls):
        if not cls.HEADER.is_file():
            raise unittest.SkipTest("Nrf52BootCatalogue.h not present")
        cls.work = TEST_WORK / "cpp_matcher"
        cls.work.mkdir(parents=True, exist_ok=True)
        cls.binary = cls.work / "matcher_test"
        cpp_source = cls.work / "matcher_test.cpp"
        cpp_source.write_text(_CPP_MATCHER_TEST_SOURCE)
        subprocess.run(
            ["g++", "-std=c++17", "-Wall", "-Wextra", "-I", str(cls.HEADER.parent),
             str(cpp_source), "-o", str(cls.binary)],
            check=True, capture_output=True, text=True)

    def _run(self, scenario):
        result = subprocess.run([str(self.binary), scenario], check=True, capture_output=True, text=True)
        return result.stdout.strip()

    def test_missing_catalogue(self):
        self.assertEqual(self._run("missing_catalogue"), "MissingCatalogue")

    def test_io_error(self):
        self.assertEqual(self._run("io_error"), "IoError")

    def test_approved_mbr_set_uicr_mirror(self):
        # Config 0x00010002: MBR selectors explicitly set, matching UICR.
        self.assertEqual(self._run("approved_mirror"), "Approved:65538")

    def test_approved_default_selectors_mbr_blank_uicr_set(self):
        # Config 0x00010001: MBR selectors blank (unset), falls back to
        # UICR. This is the policy that was previously UNREACHABLE due to
        # the effective-vs-raw comparison bug -- this test locks in the fix.
        self.assertEqual(self._run("approved_default_selectors"), "Approved:65537")

    def test_mismatch_same_target_same_profile_different_hash(self):
        self.assertEqual(self._run("mismatch"), "Mismatch")

    def test_unsupported_different_target(self):
        self.assertEqual(self._run("different_target"), "Unsupported")

    def test_unsupported_profile_mismatch_never_approved(self):
        # Same target_id, but raw.profile_id does not match the row's
        # profile_id -- must never inherit the row by target_id alone.
        self.assertEqual(self._run("profile_mismatch"), "Unsupported")

    def test_unsupported_non_blank_param_page(self):
        self.assertEqual(self._run("non_blank_param_page"), "Unsupported")

    def test_unsupported_bad_policy_tuple(self):
        self.assertEqual(self._run("bad_policy_tuple"), "Unsupported")

    def test_unsupported_zero_value_not_treated_as_unset(self):
        self.assertEqual(self._run("zero_value"), "Unsupported")

    def test_unsupported_mixed_tuple_even_if_effective_looks_correct(self):
        # Regression for the fixed effective-vs-raw comparison bug: a MIXED raw tuple
        # whose effective resolution happens to compute (0xF4000,0xFE000)
        # must STILL be Unsupported, because the raw tuple itself was
        # never one of the two listed policies.
        self.assertEqual(self._run("mixed_ignored_override"), "Unsupported")

    def test_unsupported_conflicting_uicr_override_refused(self):
        # MBR selectors fully blank (the 0x00010001 shape), but UICR
        # nrffw0 disagrees with the required 0xF4000 -- a conflicting
        # overridden UICR value must be refused (Unsupported), never
        # silently accepted because MBR happened to be blank.
        self.assertEqual(self._run("conflicting_uicr_override"), "Unsupported")

    # ------------------------------------------------------------------
    # Schema v2 (custom-loader catalogue extension) scenarios.
    # ------------------------------------------------------------------
    def test_vendor_stock_approved_role0_and_role1(self):
        # A VendorStock row is explicitly ROLE-NEUTRAL: an unchanged stock
        # row must match for EITHER supported compiled application role.
        self.assertEqual(self._run("vendor_stock_role0"), "Approved:65538")
        self.assertEqual(self._run("vendor_stock_role1"), "Approved:65538")

    def test_meshcore_ota_exact_role_approved(self):
        # A MeshCoreOta row bound to role 1 approves only an exact role-1
        # measurement with its own exact custom-loader identity/marker.
        self.assertEqual(self._run("meshcore_ota_role1_approved"), "Approved:65538")

    def test_meshcore_ota_wrong_role_is_unsupported_not_mismatch(self):
        # With only ONE role-bound (Exact, role=1) row compiled in, a
        # role-0 measurement is never "applicable" to it at all -- the
        # catalogue has nothing to say about this role, so the result is
        # Unsupported (not a false Mismatch, which would wrongly imply
        # "applicable but wrong").
        self.assertEqual(self._run("meshcore_ota_wrong_role_single_row"), "Unsupported")

    def test_copied_valid_marker_into_unknown_code_fails(self):
        # A genuinely-approved marker/CF2 byte-for-byte match can NEVER
        # substitute for the code/config identity fields: corrupting only
        # stock_code_sha256 while keeping a byte-perfect approved marker
        # must still be Mismatch, not Approved.
        self.assertEqual(self._run("meshcore_ota_valid_marker_wrong_code"), "Mismatch")

    def test_boot_info_not_captured_is_denied(self):
        # A capture that is NotCaptured/Unreadable can never satisfy
        # either loader kind -- even if every other field would otherwise
        # match -- and must never be silently treated as an all-0xFF
        # erased marker.
        self.assertEqual(self._run("boot_info_not_captured"), "Mismatch")

    def test_invalid_catalogue_unknown_loader_kind(self):
        # An Unknown (default/under-initialized) loader_kind row is ALWAYS
        # invalid; a single malformed row invalidates the WHOLE compiled
        # catalogue (fail-closed), never a partial/best-effort match.
        self.assertEqual(self._run("invalid_catalogue_unknown_kind"), "InvalidCatalogue")

    def test_invalid_catalogue_ambiguous_same_projection_different_binding(self):
        # Two rows sharing the SAME baseline-signed projection (target,
        # profile, role_binding, expected_role_id, stock_code_sha256) but
        # disagreeing on CF2/marker binding is an irreducibly ambiguous
        # compiled catalogue -- InvalidCatalogue, never "first row wins".
        self.assertEqual(self._run("invalid_catalogue_ambiguous_projection"), "InvalidCatalogue")

    def test_multi_row_alternatives_never_take_first_match(self):
        # Multiple applicable-looking rows (different targets) are tried
        # as alternatives; a measurement for the SECOND target/profile
        # must still be Approved even though it is not the first row in
        # the compiled array.
        self.assertEqual(self._run("multi_row_second_target_approved"), "Approved:65538")


_CPP_MATCHER_TEST_SOURCE = r"""
#include "Nrf52BootCatalogue.h"
#include <cstdio>
#include <cstring>
#include <string>

using namespace ota::platform;

static Nrf52ApprovedBootRow make_row() {
  Nrf52ApprovedBootRow row;
  row.target_id = kNrf52BootTargetXiaoNrf52840;
  row.profile_id = kNrf52BootProfileXiao;
  // Schema v2: this fixture models the VendorStock row shape used by all
  // the pre-existing (pre-schema-v2) scenarios below -- role-neutral,
  // with the canonical erased/0xFF expected boot-info marker (what the
  // real stock artifact genuinely measures at that offset).
  row.loader_kind = Nrf52LoaderKind::VendorStock;
  row.role_binding = Nrf52RoleBinding::NotApplicable;
  row.expected_role_id = kNrf52BootFieldUnset;
  std::memset(row.expected_boot_info, 0xFF, kNrf52BootInfoSize);
  std::memset(row.stock_code_sha256, 0xAA, 32);
  std::memset(row.cf2_sha256, 0xBB, 32);
  std::memset(row.mbr_sha256, 0xCC, 32);
  std::memset(row.softdevice_sha256, 0xDD, 32);
  row.mbr_vectors = {0x20000400u, 0x00000A81u};
  row.softdevice_vectors = {0x200013C8u, 0x00025E39u};
  row.loader_vectors = {0x20040000u, 0x000F4123u};
  row.ficr_geometry = {kNrf52ExpectedCodePageSize, kNrf52ExpectedCodeSize};
  row.softdevice_info_magic = 0x51B1E5DBu;
  row.softdevice_info_size = 0x27000u;
  row.softdevice_fwid = 0x0123u;
  row.softdevice_variant = 140u;
  row.softdevice_version = 7003000u;
  std::memset(row.softdevice_unique_id, 0xEE, 20);
  return row;
}

static Nrf52RawBootMeasurement make_matching_raw(const Nrf52ApprovedBootRow &row) {
  Nrf52RawBootMeasurement raw;
  raw.have_measurement = true;
  raw.target_id = row.target_id;
  raw.profile_id = row.profile_id;
  // A VendorStock row is role-neutral but still requires current_role_id
  // to be one of the genuinely supported roles (never the unset sentinel).
  raw.current_role_id = 0u;
  raw.boot_info_capture_status = Nrf52BootInfoCaptureStatus::Captured;
  std::memcpy(raw.boot_info, row.expected_boot_info, kNrf52BootInfoSize);
  std::memcpy(raw.stock_code_sha256, row.stock_code_sha256, 32);
  std::memcpy(raw.cf2_sha256, row.cf2_sha256, 32);
  std::memcpy(raw.mbr_sha256, row.mbr_sha256, 32);
  std::memcpy(raw.softdevice_sha256, row.softdevice_sha256, 32);
  raw.mbr_vectors = row.mbr_vectors;
  raw.softdevice_vectors = row.softdevice_vectors;
  raw.loader_vectors = row.loader_vectors;
  raw.ficr_geometry = row.ficr_geometry;
  raw.softdevice_info_magic = row.softdevice_info_magic;
  raw.softdevice_info_size = row.softdevice_info_size;
  raw.softdevice_fwid = row.softdevice_fwid;
  raw.softdevice_variant = row.softdevice_variant;
  raw.softdevice_version = row.softdevice_version;
  std::memcpy(raw.softdevice_unique_id, row.softdevice_unique_id, 20);
  // Config 0x00010002 (MbrSetUicrMirror): both RAW MBR selector fields AND
  // RAW UICR fields present and equal.
  raw.mbr_selectors = {0x000F4000u, 0x000FE000u};
  raw.uicr = {0x000F4000u, 0x000FE000u};
  raw.params_page_blank = true;
  return raw;
}

// Schema v2: a role-bound custom-loader row (MeshCoreOta, role 1), sharing
// the SAME target/profile as the stock XIAO row (per the real applicability
// matrix: a custom build for the same logical board keeps the same
// target/profile, differentiated only by role_binding/expected_role_id),
// but with its OWN distinct code/config identity and boot-info marker.
static Nrf52ApprovedBootRow make_meshcore_ota_role1_row() {
  Nrf52ApprovedBootRow row;
  row.target_id = kNrf52BootTargetXiaoNrf52840;
  row.profile_id = kNrf52BootProfileXiao;
  row.loader_kind = Nrf52LoaderKind::MeshCoreOta;
  row.role_binding = Nrf52RoleBinding::Exact;
  row.expected_role_id = 1u;
  std::memset(row.expected_boot_info, 0x42, kNrf52BootInfoSize);  // distinct genuine marker bytes
  std::memset(row.stock_code_sha256, 0x11, 32);
  std::memset(row.cf2_sha256, 0x22, 32);
  std::memset(row.mbr_sha256, 0xCC, 32);       // MBR/SD references are shared public artifacts
  std::memset(row.softdevice_sha256, 0xDD, 32);
  row.mbr_vectors = {0x20000400u, 0x00000A81u};
  row.softdevice_vectors = {0x200013C8u, 0x00025E39u};
  row.loader_vectors = {0x20040000u, 0x000FC479u};  // this row's own actual reset vector
  row.ficr_geometry = {kNrf52ExpectedCodePageSize, kNrf52ExpectedCodeSize};
  row.softdevice_info_magic = 0x51B1E5DBu;
  row.softdevice_info_size = 0x27000u;
  row.softdevice_fwid = 0x0123u;
  row.softdevice_variant = 140u;
  row.softdevice_version = 7003000u;
  std::memset(row.softdevice_unique_id, 0xEE, 20);
  return row;
}

int main(int argc, char **argv) {
  if (argc != 2) { std::fprintf(stderr, "usage: matcher_test <scenario>\n"); return 2; }
  std::string scenario = argv[1];
  Nrf52ApprovedBootRow row = make_row();

  if (scenario == "missing_catalogue") {
    Nrf52RawBootMeasurement raw = make_matching_raw(row);
    auto result = match_boot_catalogue(raw, nullptr, 0);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::MissingCatalogue ? "MissingCatalogue" : "WRONG");
    return 0;
  }
  if (scenario == "io_error") {
    Nrf52RawBootMeasurement raw;  // have_measurement stays false
    auto result = match_boot_catalogue(raw, &row, 1);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::IoError ? "IoError" : "WRONG");
    return 0;
  }
  if (scenario == "approved_mirror") {
    Nrf52RawBootMeasurement raw = make_matching_raw(row);  // config 0x00010002
    auto result = match_boot_catalogue(raw, &row, 1);
    if (result.outcome == BootCatalogueOutcome::Approved) {
      std::printf("Approved:%u\n", result.matched_config_id);
    } else {
      std::printf("WRONG\n");
    }
    return 0;
  }
  if (scenario == "approved_default_selectors") {
    // Config 0x00010001 (MbrBlankUicrSet): RAW MBR selectors are BOTH
    // unset, falling back entirely to UICR. Previously unreachable due to
    // the effective-vs-raw comparison bug; now must resolve correctly.
    Nrf52RawBootMeasurement raw = make_matching_raw(row);
    raw.mbr_selectors = {kNrf52BootFieldUnset, kNrf52BootFieldUnset};
    raw.uicr = {0x000F4000u, 0x000FE000u};
    auto result = match_boot_catalogue(raw, &row, 1);
    if (result.outcome == BootCatalogueOutcome::Approved) {
      std::printf("Approved:%u\n", result.matched_config_id);
    } else {
      std::printf("WRONG\n");
    }
    return 0;
  }
  if (scenario == "mismatch") {
    Nrf52RawBootMeasurement raw = make_matching_raw(row);
    raw.stock_code_sha256[0] ^= 0xFF;  // same target+profile, differing measured hash
    auto result = match_boot_catalogue(raw, &row, 1);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::Mismatch ? "Mismatch" : "WRONG");
    return 0;
  }
  if (scenario == "different_target") {
    Nrf52RawBootMeasurement raw = make_matching_raw(row);
    raw.target_id = 0x53454E53u;  // a different target id; no row exists for it
    auto result = match_boot_catalogue(raw, &row, 1);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::Unsupported ? "Unsupported" : "WRONG");
    return 0;
  }
  if (scenario == "profile_mismatch") {
    // Same target_id as the row, but a DIFFERENT profile_id -- must never
    // inherit row 1's content by target_id alone.
    Nrf52RawBootMeasurement raw = make_matching_raw(row);
    raw.profile_id = row.profile_id + 1;
    auto result = match_boot_catalogue(raw, &row, 1);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::Unsupported ? "Unsupported" : "WRONG");
    return 0;
  }
  if (scenario == "non_blank_param_page") {
    Nrf52RawBootMeasurement raw = make_matching_raw(row);
    raw.params_page_blank = false;  // fresh/erased precondition violated
    auto result = match_boot_catalogue(raw, &row, 1);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::Unsupported ? "Unsupported" : "WRONG");
    return 0;
  }
  if (scenario == "bad_policy_tuple") {
    Nrf52RawBootMeasurement raw = make_matching_raw(row);
    raw.mbr_selectors = {kNrf52BootFieldUnset, kNrf52BootFieldUnset};
    raw.uicr = {kNrf52BootFieldUnset, kNrf52BootFieldUnset};  // not a listed policy tuple
    auto result = match_boot_catalogue(raw, &row, 1);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::Unsupported ? "Unsupported" : "WRONG");
    return 0;
  }
  if (scenario == "zero_value") {
    // Explicit 0 in the MBR selector fields must NOT be treated as unset
    // (would otherwise be misclassified as the "blank" 0x00010001 policy).
    Nrf52RawBootMeasurement raw = make_matching_raw(row);
    raw.mbr_selectors = {0u, 0u};
    raw.uicr = {0x000F4000u, 0x000FE000u};
    auto result = match_boot_catalogue(raw, &row, 1);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::Unsupported ? "Unsupported" : "WRONG");
    return 0;
  }
  if (scenario == "mixed_ignored_override") {
    // MIXED raw tuple: MBR bootloader_addr explicitly set (0xF4000), MBR
    // params_page_addr left unset (falls back to UICR nrffw1=0xFE000), and
    // UICR nrffw0 is some unrelated value. The EFFECTIVE resolution here
    // computes exactly (0xF4000,0xFE000) -- the "correct-looking" answer
    // -- but the RAW tuple matches neither listed policy, so this MUST
    // still be Unsupported (regression for the fixed effective-vs-raw
    // comparison bug).
    Nrf52RawBootMeasurement raw = make_matching_raw(row);
    raw.mbr_selectors = {0x000F4000u, kNrf52BootFieldUnset};
    raw.uicr = {0x99999999u, 0x000FE000u};
    auto result = match_boot_catalogue(raw, &row, 1);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::Unsupported ? "Unsupported" : "WRONG");
    return 0;
  }
  if (scenario == "conflicting_uicr_override") {
    // MBR fully blank (the 0x00010001 shape) but UICR nrffw0 disagrees
    // with the required 0xF4000 -- a conflicting overridden UICR value,
    // not a listed policy tuple; must be refused.
    Nrf52RawBootMeasurement raw = make_matching_raw(row);
    raw.mbr_selectors = {kNrf52BootFieldUnset, kNrf52BootFieldUnset};
    raw.uicr = {0x99999999u, 0x000FE000u};
    auto result = match_boot_catalogue(raw, &row, 1);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::Unsupported ? "Unsupported" : "WRONG");
    return 0;
  }
  if (scenario == "vendor_stock_role0" || scenario == "vendor_stock_role1") {
    Nrf52RawBootMeasurement raw = make_matching_raw(row);
    raw.current_role_id = (scenario == "vendor_stock_role1") ? 1u : 0u;
    auto result = match_boot_catalogue(raw, &row, 1);
    if (result.outcome == BootCatalogueOutcome::Approved) {
      std::printf("Approved:%u\n", result.matched_config_id);
    } else {
      std::printf("WRONG\n");
    }
    return 0;
  }
  if (scenario == "meshcore_ota_role1_approved") {
    Nrf52ApprovedBootRow ota_row = make_meshcore_ota_role1_row();
    Nrf52ApprovedBootRow rows[2] = {row, ota_row};
    Nrf52RawBootMeasurement raw = make_matching_raw(ota_row);
    raw.current_role_id = 1u;
    auto result = match_boot_catalogue(raw, rows, 2);
    if (result.outcome == BootCatalogueOutcome::Approved) {
      std::printf("Approved:%u\n", result.matched_config_id);
    } else {
      std::printf("WRONG\n");
    }
    return 0;
  }
  if (scenario == "meshcore_ota_wrong_role_single_row") {
    // Only the role-1-bound row is compiled in; a role-0 measurement is
    // never "applicable" to it at all -- Unsupported, not Mismatch.
    Nrf52ApprovedBootRow ota_row = make_meshcore_ota_role1_row();
    Nrf52RawBootMeasurement raw = make_matching_raw(ota_row);
    raw.current_role_id = 0u;
    auto result = match_boot_catalogue(raw, &ota_row, 1);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::Unsupported ? "Unsupported" : "WRONG");
    return 0;
  }
  if (scenario == "meshcore_ota_valid_marker_wrong_code") {
    // Applicable (role matches), byte-perfect approved marker, but the
    // measured code hash is wrong: must be Mismatch, never Approved --
    // a valid marker copied onto unknown code is never sufficient.
    Nrf52ApprovedBootRow ota_row = make_meshcore_ota_role1_row();
    Nrf52RawBootMeasurement raw = make_matching_raw(ota_row);
    raw.current_role_id = 1u;
    raw.stock_code_sha256[0] ^= 0xFF;
    auto result = match_boot_catalogue(raw, &ota_row, 1);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::Mismatch ? "Mismatch" : "WRONG");
    return 0;
  }
  if (scenario == "boot_info_not_captured") {
    // Applicable and every other field would otherwise match, but the
    // capture itself is NotCaptured -- must never be treated as an
    // implicit all-0xFF erased marker; must be Mismatch.
    Nrf52ApprovedBootRow ota_row = make_meshcore_ota_role1_row();
    Nrf52RawBootMeasurement raw = make_matching_raw(ota_row);
    raw.current_role_id = 1u;
    raw.boot_info_capture_status = Nrf52BootInfoCaptureStatus::NotCaptured;
    auto result = match_boot_catalogue(raw, &ota_row, 1);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::Mismatch ? "Mismatch" : "WRONG");
    return 0;
  }
  if (scenario == "invalid_catalogue_unknown_kind") {
    // A row whose loader_kind is left at the default Unknown value is
    // always invalid; a single malformed row invalidates the WHOLE
    // compiled catalogue, fail-closed.
    Nrf52ApprovedBootRow bad_row;  // loader_kind defaults to Unknown
    bad_row.target_id = row.target_id;
    bad_row.profile_id = row.profile_id;
    Nrf52RawBootMeasurement raw = make_matching_raw(row);
    Nrf52ApprovedBootRow rows[2] = {row, bad_row};
    auto result = match_boot_catalogue(raw, rows, 2);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::InvalidCatalogue ? "InvalidCatalogue" : "WRONG");
    return 0;
  }
  if (scenario == "invalid_catalogue_ambiguous_projection") {
    // Two rows share the SAME baseline-signed projection (target,
    // profile, role_binding, expected_role_id, stock_code_sha256) but
    // disagree on CF2 binding -- irreducibly ambiguous, InvalidCatalogue.
    Nrf52ApprovedBootRow ota_row = make_meshcore_ota_role1_row();
    Nrf52ApprovedBootRow ota_row_conflict = ota_row;
    ota_row_conflict.cf2_sha256[0] ^= 0xFF;  // same projection, different CF2 binding
    Nrf52RawBootMeasurement raw = make_matching_raw(ota_row);
    raw.current_role_id = 1u;
    Nrf52ApprovedBootRow rows[2] = {ota_row, ota_row_conflict};
    auto result = match_boot_catalogue(raw, rows, 2);
    std::printf("%s\n", result.outcome == BootCatalogueOutcome::InvalidCatalogue ? "InvalidCatalogue" : "WRONG");
    return 0;
  }
  if (scenario == "multi_row_second_target_approved") {
    // A second row with a DIFFERENT target/profile (modeling the separate
    // SenseCAP custom row) must still be found and Approved even though
    // it is not the first row in the compiled array -- alternatives are
    // compared fully, never "take the first target/profile".
    Nrf52ApprovedBootRow other_row = make_meshcore_ota_role1_row();
    other_row.target_id = 0x53435031u;  // distinct logical target (modeling SenseCAP)
    other_row.profile_id = 2u;
    other_row.expected_role_id = 0u;
    Nrf52RawBootMeasurement raw = make_matching_raw(other_row);
    raw.target_id = other_row.target_id;
    raw.profile_id = other_row.profile_id;
    raw.current_role_id = 0u;
    Nrf52ApprovedBootRow rows[2] = {row, other_row};
    auto result = match_boot_catalogue(raw, rows, 2);
    if (result.outcome == BootCatalogueOutcome::Approved) {
      std::printf("Approved:%u\n", result.matched_config_id);
    } else {
      std::printf("WRONG\n");
    }
    return 0;
  }
  std::fprintf(stderr, "unknown scenario\n");
  return 2;
}
"""


if __name__ == "__main__":
    unittest.main()
