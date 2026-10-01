#!/usr/bin/env python3
"""Produce the nRF52840 boot catalogue (MBR / SoftDevice / stock bootloader
"code" region identity) from pinned PUBLIC artifacts only.

This script performs NO hardware access and NO network access. It:
  1. Parses Intel HEX inputs with a STRICT parser (record length/checksum/
     type/EOF-ordering/address-overflow/overlap validation).
  2. Parses an ELF32 stock-bootloader build with `arm-none-eabi-readelf`
     to find each section's REAL file-backed physical load address (LMA),
     not its runtime VMA -- so the "stock code" region extent/hashes can
     never be fabricated from text-only assumptions.
  3. Extracts and hashes the fixed flash regions described in
     src/ota/platform/Nrf52BootCatalogue.h, validates the CF2 board-info
     block, the public MBR/SoftDevice reference extents, the SoftDevice
     information struct at 0x3000, and the MBR-parameter / UICR upgrade
     field config-id policy.
  4. Emits ONE deterministic generated header
     (src/ota/platform/Nrf52ApprovedBootCatalogue.h) plus a JSON provenance
     sidecar recording exact source pins, board, toolchain, options and
     artifact-file SHA-256 -- with no private paths, timestamps, or random
     data (SOURCE_DATE_EPOCH only, supplied explicitly by the caller).

If any REQUIRED real public input is missing or fails validation, this
script reports a precise, typed error and refuses to write the generated
header -- it never emits a placeholder/fabricated row.
"""

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_BOOT_INFO_VERIFY_TOOL_PATH = (
    REPO_ROOT / "bootloader" / "xiao_nrf52840_ota" / "tools" / "verify_boot_info_artifact.py")


def _load_boot_info_verify_module():
    """Dynamically import Boot-owned verify_boot_info_artifact.py's
    check_artifact()/read_intel_hex_bytes() by file path -- used read-only
    as a library call (never a subprocess test invocation, never edited)
    so a custom row's boot-info marker is cross-checked against Boot's own
    independent golden-constant validator rather than re-implementing it
    here."""
    if not _BOOT_INFO_VERIFY_TOOL_PATH.is_file():
        raise MissingArtifactError(
            f"required Boot-owned tool not found: {_BOOT_INFO_VERIFY_TOOL_PATH}")
    spec = importlib.util.spec_from_file_location(
        "_xiao_ota_boot_info_verify", _BOOT_INFO_VERIFY_TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# ---------------------------------------------------------------------
# Fixed flash geometry/constants. These MUST stay in lockstep with
# src/ota/platform/Nrf52BootCatalogue.h (the shared pure DTO); there is
# intentionally no runtime coupling (that header has zero Python
# dependency), so if either changes the other must be reviewed by hand.
# ---------------------------------------------------------------------
STOCK_CODE_OFFSET = 0xF4000
STOCK_CODE_SIZE = 0x9800  # ends 0xFD800
CF2_OFFSET = 0xFD800
CF2_SIZE = 0x800  # ends 0xFE000
MBR_PARAM_PAGE_OFFSET = 0xFE000
MBR_PARAM_PAGE_SIZE = 0x1000  # ends 0xFF000
BOOTLOADER_SETTINGS_OFFSET = 0xFF000
BOOTLOADER_SETTINGS_SIZE = 0x1000  # ends 0x100000

MBR_BODY_RANGE_END = 0xFF8  # [0, 0xFF8) within the public MBR hex file itself
SOFTDEVICE_RANGE_START = 0x1000
SOFTDEVICE_RANGE_END = 0x27000  # [0x1000, 0x27000) within the public S140 hex file

MBR_BODY_REFERENCE_SHA256 = "f428cee00ece4d8323b9bc07b1be888b209fcfa1c60ca15f833419dfb7785849"
SOFTDEVICE_730_REFERENCE_SHA256 = "52102c1f530069395431dab626cf618310dd54ce579b8bf25aba1908526afd0b"

MBR_VECTORS = (0x20000400, 0x00000A81)
SOFTDEVICE_VECTORS = (0x200013C8, 0x00025E39)

SOFTDEVICE_INFO_OFFSET = 0x3000
SOFTDEVICE_INFO_EXPECTED_LENGTH = 0x2C
SOFTDEVICE_INFO_EXPECTED_MAGIC = 0x51B1E5DB
SOFTDEVICE_INFO_EXPECTED_SIZE = 0x27000
SOFTDEVICE_INFO_EXPECTED_FWID = 0x0123
SOFTDEVICE_INFO_EXPECTED_VARIANT = 140
SOFTDEVICE_INFO_EXPECTED_VERSION = 7003000

FICR_CODE_PAGE_SIZE = 0x1000
FICR_CODE_SIZE = 0x100

TARGET_XIAO_NRF52840 = 0x584E3430
PROFILE_XIAO = 1
TARGET_SENSECAP_SOLAR_P1 = 0x53435031
PROFILE_SENSECAP = 2

MBR_FIELD_UNSET = 0xFFFFFFFF
# Config IDs are the exact 32-bit values pinned by the approved Astra
# contract: 0x00010001 / 0x00010002 (hex). These are NOT the decimal
# digits "10001"/"10002" -- that would be a different, incorrect value.
CONFIG_ID_MBR_BLANK_UICR_SET = 0x00010001
CONFIG_ID_MBR_SET_UICR_MIRROR = 0x00010002
APPROVED_CONFIG_POLICIES = {
    CONFIG_ID_MBR_BLANK_UICR_SET: {"mbr": (MBR_FIELD_UNSET, MBR_FIELD_UNSET), "uicr": (0xF4000, 0xFE000)},
    CONFIG_ID_MBR_SET_UICR_MIRROR: {"mbr": (0xF4000, 0xFE000), "uicr": (0xF4000, 0xFE000)},
}

# XIAO BLE stock CF2 / board-info reference fields, per the approved astra
# contract. This exact tagged-word layout (magicStart@0, magicEnd@4,
# count0@8, count1@12, then four (tag:u32, value:u32) pairs for
# flash-size/RAM-size/board-id/UF2-family, then a final (tag, port-size)
# pair) was confirmed byte-for-byte against the REAL compiled stock
# xiao_nrf52840_ble bootloader build (not guessed/assumed):
#   bytes 0..63 == f1109e1e 797a2220 00000005 00000064
#                  000000cc 00100000 000000cd 00040000
#                  000000d0 28860044 000000d1 ada52840
#                  000000d2 00000020 00000000 00000000
CF2_MAGIC_START = 0x1E9E10F1
CF2_MAGIC_END = 0x20227A79
CF2_COUNTS = (5, 100)
CF2_FLASH_SIZE_TAG = 0xCC
CF2_FLASH_SIZE = 0x100000
CF2_RAM_SIZE_TAG = 0xCD
CF2_RAM_SIZE = 0x40000
CF2_BOARD_ID_TAG = 0xD0
CF2_BOARD_ID = 0x28860044
CF2_UF2_FAMILY_TAG = 0xD1
CF2_UF2_FAMILY = 0xADA52840
CF2_PORT_SIZE_TAG = 0xD2
CF2_PORT_SIZE = 32

# ---------------------------------------------------------------------
# Schema v2 (custom-loader catalogue extension). Must stay in lockstep
# with src/ota/platform/Nrf52BootCatalogue.h's kNrf52BootCatalogueSchemaVersion
# and the Nrf52LoaderKind/Nrf52RoleBinding enumerators.
# ---------------------------------------------------------------------
SCHEMA_VERSION = 2
BOOT_INFO_OFFSET = 0xFDC00  # within [0xFD800, 0xFE000); matches kNrf52BootInfoOffset
BOOT_INFO_SIZE = 60

LOADER_KIND_VENDOR_STOCK = "VendorStock"
LOADER_KIND_MESHCORE_OTA = "MeshCoreOta"
ROLE_BINDING_NOT_APPLICABLE = "NotApplicable"
ROLE_BINDING_EXACT = "Exact"

# Fixed, explicit (logical_board, role_id) -> (target_id, profile_id)
# applicability matrix for the custom-loader increment. This is NEVER
# inferred from the upstream Adafruit BOARD=xiao_nrf52840_ble name or its
# CF2 board-info identity -- all custom variants share that same upstream
# board/CF2 regardless of their real logical MeshCore target.
CUSTOM_BOARD_ROLE_MATRIX = {
    ("xiao_nrf52840", 0): (TARGET_XIAO_NRF52840, PROFILE_XIAO),
    ("xiao_nrf52840", 1): (TARGET_XIAO_NRF52840, PROFILE_XIAO),
    ("sensecap_solar_p1", 0): (TARGET_SENSECAP_SOLAR_P1, PROFILE_SENSECAP),
    ("sensecap_solar_p1", 1): (TARGET_SENSECAP_SOLAR_P1, PROFILE_SENSECAP),
}

# --board argument expected by verify_boot_info_artifact.py::check_artifact
# for each logical board (that script's own BOARD_TARGET_VALUE keys).
BOOT_INFO_CHECK_BOARD_NAME = {
    "xiao_nrf52840": "xiao_nrf52840",
    "sensecap_solar_p1": "sensecap_solar_p1",
}

# A different, larger BLE/custom-profile candidate-bank code start this
# producer must explicitly REJECT (never silently accept as if it were
# the required 0xF4000 stock-code-window start).
REJECTED_LARGER_PROFILE_CODE_START = 0xED000

# Packaged no-SWD custom-loader HEX/UF2 artifacts legitimately include the
# unmodified public MBR body, the unmodified public SoftDevice, the
# loader-code window and its CF2/config block (everything needed to flash
# the device with no external debug probe), plus exactly the two UICR
# forward-address selector words. They must NEVER populate the app/
# userdata region, the MBR-parameter blank-scan scratch page, the
# bootloader-settings/SDK page, or any other UICR word.
ALLOWED_PACKAGED_FLASH_RANGES = (
    (0, MBR_BODY_RANGE_END),                       # public MBR body [0, 0xFF8)
    (SOFTDEVICE_RANGE_START, SOFTDEVICE_RANGE_END),  # public SoftDevice [0x1000, 0x27000)
    (STOCK_CODE_OFFSET, CF2_OFFSET + CF2_SIZE),      # loader code + CF2/config [0xF4000, 0xFE000)
)
ALLOWED_PACKAGED_UICR_WORDS = (0x10001014, 0x10001018)  # NRFFW0 / NRFFW1, 4 bytes each
# UF2 packaging writes UICR in whole fixed-size page blocks (unlike a HEX
# file, which can list just the two exact words) -- the rest of that same
# page is legitimately erased-pattern (0xFF) filler accompanying the real
# write, not a separate disallowed UICR value.
UICR_PAGE_RANGE = (0x10001000, 0x10001100)


class BootCatalogueError(Exception):
    """Base class for all typed producer errors."""


class MissingArtifactError(BootCatalogueError):
    """A required real public input file was not supplied or not found."""


class CorruptHexError(BootCatalogueError):
    """An Intel HEX input failed strict structural validation."""


class ElfExtractionError(BootCatalogueError):
    """readelf output could not be parsed, or a required section is absent."""


class RegionMismatchError(BootCatalogueError):
    """A measured region/field did not match its required reference value."""


class PackagedAddressWhitelistError(BootCatalogueError):
    """A packaged custom HEX/UF2 artifact populates a flash/UICR address
    outside the allowed MBR/SoftDevice/loader-code/CF2/forward-address
    window (e.g. app, userdata, SDK-settings, or MBR-scratch areas)."""


class UnapprovedOverlayError(BootCatalogueError):
    """A custom-row descriptor's qualification_status is not 'approved' --
    refusing to embed its extracted fields as an approved catalogue row.
    Its real artifacts may still be used directly (via
    extract_custom_artifact_fields) to exercise producer extraction logic
    in tests, but must never flow into the generated header via this
    gate."""


class IncompleteCustomManifestError(BootCatalogueError):
    """A --custom-manifest did not contain exactly the fixed set of four
    (logical_board, role_id) applicability-matrix entries (one descriptor
    each for xiao_nrf52840 role0/role1 and sensecap_solar_p1 role0/role1).
    A partial, missing, duplicated, or unrecognized custom set must fail
    the whole run -- never silently publish a header that LOOKS like the
    complete stock-plus-four set but actually has fewer/duplicate rows."""


# ---------------------------------------------------------------------
# Strict Intel HEX parser
# ---------------------------------------------------------------------
class IntelHexImage:
    """A flat byte-addressed memory image parsed from an Intel HEX file,
    with strict structural validation. Addresses not present in any data
    record are considered unpopulated (the caller decides fill policy)."""

    def __init__(self):
        self.memory = {}  # absolute address -> int (0-255)
        self.eof_seen = False

    def populated_range(self):
        if not self.memory:
            return None
        return min(self.memory), max(self.memory) + 1

    def read(self, address, length, fill=0xFF):
        return bytes(self.memory.get(address + i, fill) for i in range(length))


_HEX_LINE_RE = re.compile(r"^:[0-9A-Fa-f]+$")


def parse_intel_hex(path: Path) -> IntelHexImage:
    image = IntelHexImage()
    base_linear = 0
    base_segment = 0
    line_no = 0
    try:
        text = path.read_text()
    except OSError as exc:
        raise MissingArtifactError(f"{path}: could not read HEX input ({exc})") from exc

    for raw_line in text.splitlines():
        line_no += 1
        line = raw_line.strip()
        if line == "":
            continue
        if image.eof_seen:
            raise CorruptHexError(f"{path}:{line_no}: data after EOF record is not allowed")
        if not _HEX_LINE_RE.match(line):
            raise CorruptHexError(f"{path}:{line_no}: malformed record (not ':' + hex digits)")
        hex_body = line[1:]
        if len(hex_body) % 2 != 0:
            raise CorruptHexError(f"{path}:{line_no}: odd number of hex digits")
        try:
            data = bytes.fromhex(hex_body)
        except ValueError as exc:
            raise CorruptHexError(f"{path}:{line_no}: invalid hex digits ({exc})") from exc
        if len(data) < 5:
            raise CorruptHexError(f"{path}:{line_no}: record too short")

        length = data[0]
        address = (data[1] << 8) | data[2]
        record_type = data[3]
        expected_len = 4 + length + 1
        if len(data) != expected_len:
            raise CorruptHexError(
                f"{path}:{line_no}: declared length {length} does not match record size")
        payload = data[4:4 + length]
        checksum = data[4 + length]
        computed_checksum = (-(sum(data[:4 + length]))) & 0xFF
        if computed_checksum != checksum:
            raise CorruptHexError(
                f"{path}:{line_no}: checksum mismatch (expected {computed_checksum:#04x}, "
                f"got {checksum:#04x})")

        if record_type == 0x00:  # data
            full_base = base_linear + base_segment
            for offset, byte in enumerate(payload):
                full_address = full_base + address + offset
                if full_address > 0xFFFFFFFF:
                    raise CorruptHexError(f"{path}:{line_no}: address overflow past 32 bits")
                if full_address in image.memory and image.memory[full_address] != byte:
                    raise CorruptHexError(
                        f"{path}:{line_no}: conflicting overlapping data at "
                        f"address {full_address:#010x}")
                image.memory[full_address] = byte
        elif record_type == 0x01:  # EOF
            if length != 0:
                raise CorruptHexError(f"{path}:{line_no}: EOF record must have zero length")
            image.eof_seen = True
        elif record_type == 0x02:  # extended segment address
            if length != 2:
                raise CorruptHexError(f"{path}:{line_no}: segment address record must be 2 bytes")
            base_segment = ((payload[0] << 8) | payload[1]) << 4
            base_linear = 0
        elif record_type == 0x03:  # start segment address (informational, ignored)
            if length != 4:
                raise CorruptHexError(f"{path}:{line_no}: start segment address must be 4 bytes")
        elif record_type == 0x04:  # extended linear address
            if length != 2:
                raise CorruptHexError(f"{path}:{line_no}: linear address record must be 2 bytes")
            base_linear = ((payload[0] << 8) | payload[1]) << 16
            base_segment = 0
        elif record_type == 0x05:  # start linear address (informational, ignored)
            if length != 4:
                raise CorruptHexError(f"{path}:{line_no}: start linear address must be 4 bytes")
        else:
            raise CorruptHexError(f"{path}:{line_no}: unsupported record type {record_type:#04x}")

    if not image.eof_seen:
        raise CorruptHexError(f"{path}: missing EOF record")
    return image


_UF2_BLOCK_SIZE = 512
_UF2_MAGIC_START0 = 0x0A324655
_UF2_MAGIC_START1 = 0x9E5D5157
_UF2_MAGIC_END = 0x0AB16F30

# UF2 flag bits defined by the public UF2 format used by the pinned
# Adafruit_nRF52_Bootloader's own packaging tooling. NOT_MAIN_FLASH is the
# bit a real review (Sol) flagged: a block with it set instructs the HOST
# tool to NOT write that block's payload to the device's main flash at all.
# Treating such a block's bytes as equivalent to a real programmed byte
# would let an otherwise-exact-looking package "match" an approved row
# while some of its covered addresses are never actually written.
_UF2_FLAG_NOT_MAIN_FLASH = 0x00000001
_UF2_FLAG_FILE_CONTAINER = 0x00001000
_UF2_FLAG_FAMILY_ID_PRESENT = 0x00002000
_UF2_FLAG_MD5_PRESENT = 0x00004000
_UF2_FLAG_EXT_TAGS_PRESENT = 0x00008000
# The only flags value this producer accepts: a plain single-family
# packaged image (family-ID word present, no NOFLASH blocks, no file-
# container/MD5/extension-tag framing this parser does not interpret).
# Any other combination is an explicit, typed refusal rather than a
# silently-ignored byte.
_UF2_SUPPORTED_FLAGS = _UF2_FLAG_FAMILY_ID_PRESENT

# Pinned from the real public Adafruit_nRF52_Bootloader source itself
# (src/usb/uf2/uf2cfg.h: CFG_UF2_FAMILY_BOOT_ID, matching the Makefile/
# CMakeLists.txt UF2_FAMILY_ID_BOOTLOADER constant) -- the bootloader-image
# UF2 family, distinct from the CF2 config block's application UF2-family
# field (CF2_UF2_FAMILY, 0xADA52840).
UF2_FAMILY_ID_BOOTLOADER = 0xD663823C


def parse_uf2(path: Path) -> IntelHexImage:
    """Strict UF2 reader producing the same flat byte-addressed image
    interface as parse_intel_hex. Validates each 512-byte block's start/
    trailing magic and payload_size <= 476, explicitly rejects (rather
    than silently overwrites) two blocks that disagree about the same
    address, and -- per Sol's review -- validates the block-structure
    fields a bare magic/payload-size check ignores: flags (rejecting
    NOT_MAIN_FLASH and any unsupported bit outright, never silently
    accepting a block the host tool would skip flashing), a single
    consistent declared family ID equal to the pinned public
    UF2_FAMILY_ID_BOOTLOADER, a num_blocks value that agrees both with
    every other block in the file AND with the file's actual block count,
    and block_no values that are unique and exactly cover
    [0, num_blocks) (no duplicate/missing block numbers), plus a
    target_addr+payload_size 32-bit address-overflow check. A malformed/
    contradictory package fails here, before any cross-format byte
    comparison -- it is never silently coerced into looking like a valid
    one."""
    image = IntelHexImage()
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise MissingArtifactError(f"{path}: could not read UF2 input ({exc})") from exc
    if len(data) == 0 or len(data) % _UF2_BLOCK_SIZE != 0:
        raise CorruptHexError(f"{path}: not a whole number of 512-byte UF2 blocks")
    total_blocks = len(data) // _UF2_BLOCK_SIZE
    seen_block_numbers = set()
    declared_num_blocks = None
    declared_family = None
    for offset in range(0, len(data), _UF2_BLOCK_SIZE):
        block = data[offset:offset + _UF2_BLOCK_SIZE]
        magic0 = int.from_bytes(block[0:4], "little")
        magic1 = int.from_bytes(block[4:8], "little")
        flags = int.from_bytes(block[8:12], "little")
        magic_end = int.from_bytes(block[508:512], "little")
        if magic0 != _UF2_MAGIC_START0 or magic1 != _UF2_MAGIC_START1:
            raise CorruptHexError(f"{path}: bad UF2 start magic at block offset {offset:#x}")
        if magic_end != _UF2_MAGIC_END:
            raise CorruptHexError(f"{path}: bad UF2 trailing magic at block offset {offset:#x}")
        if flags & _UF2_FLAG_NOT_MAIN_FLASH:
            raise CorruptHexError(
                f"{path}: block at offset {offset:#x} sets NOT_MAIN_FLASH (flags={flags:#010x}); "
                "an otherwise-exact packaged artifact that flips this bit on any block never "
                "actually programs that block's bytes to device flash, so its payload must never "
                "be treated as equivalent to a real programmed byte")
        if flags != _UF2_SUPPORTED_FLAGS:
            raise CorruptHexError(
                f"{path}: block at offset {offset:#x} has unsupported UF2 flags {flags:#010x} "
                f"(only {_UF2_SUPPORTED_FLAGS:#010x} -- family-ID-present, single plain image -- "
                "is a supported package-block structure)")
        target_addr = int.from_bytes(block[12:16], "little")
        payload_size = int.from_bytes(block[16:20], "little")
        block_no = int.from_bytes(block[20:24], "little")
        num_blocks = int.from_bytes(block[24:28], "little")
        family_id = int.from_bytes(block[28:32], "little")
        if payload_size > 476:
            raise CorruptHexError(
                f"{path}: block at {offset:#x} declares payload_size {payload_size} > 476")
        if target_addr + payload_size > 0xFFFFFFFF:
            raise CorruptHexError(
                f"{path}: block at {offset:#x} target address {target_addr:#010x} + payload_size "
                f"{payload_size} overflows the 32-bit address space")
        if num_blocks != total_blocks:
            raise CorruptHexError(
                f"{path}: block at {offset:#x} declares num_blocks={num_blocks}, contradicting the "
                f"actual {total_blocks} 512-byte blocks present in this file")
        if declared_num_blocks is None:
            declared_num_blocks = num_blocks
        elif num_blocks != declared_num_blocks:
            raise CorruptHexError(
                f"{path}: block at {offset:#x} declares num_blocks={num_blocks}, contradicting an "
                f"earlier block's num_blocks={declared_num_blocks}")
        if block_no >= total_blocks or block_no in seen_block_numbers:
            raise CorruptHexError(
                f"{path}: block at {offset:#x} has a duplicate or out-of-range block_no={block_no} "
                f"(expected a distinct value in [0,{total_blocks}))")
        seen_block_numbers.add(block_no)
        if declared_family is None:
            declared_family = family_id
        elif family_id != declared_family:
            raise CorruptHexError(
                f"{path}: block at {offset:#x} declares family_id={family_id:#010x}, contradicting "
                f"an earlier block's family_id={declared_family:#010x}")
        if family_id != UF2_FAMILY_ID_BOOTLOADER:
            raise CorruptHexError(
                f"{path}: block at {offset:#x} declares family_id={family_id:#010x}, not the "
                f"pinned public Adafruit_nRF52_Bootloader UF2_FAMILY_ID_BOOTLOADER "
                f"({UF2_FAMILY_ID_BOOTLOADER:#010x})")
        payload = block[32:32 + payload_size]
        for i, byte in enumerate(payload):
            addr = target_addr + i
            if addr in image.memory and image.memory[addr] != byte:
                raise CorruptHexError(f"{path}: conflicting UF2 bytes at address {addr:#010x}")
            image.memory[addr] = byte
    image.eof_seen = True  # UF2 has no EOF-record concept; whole-file parse marks completion
    return image


def validate_packaged_address_whitelist(image: IntelHexImage, label: str):
    """Reject any populated byte outside the allowed MBR/SoftDevice/
    loader-code/CF2 windows or the two UICR forward-address selector
    words -- a packaged no-SWD custom-loader artifact must never program
    the app/userdata region, the MBR-parameter blank-scan scratch page,
    the bootloader-settings/SDK page, or any other UICR word. A UF2's
    whole-page UICR write may legitimately carry 0xFF erased-pattern
    filler bytes around those two words (block-granular packaging, not a
    HEX file's exact-byte listing) -- those are not a separate violation,
    but any OTHER non-0xFF byte in that same UICR page is."""
    for addr in image.memory:
        if any(lo <= addr < hi for lo, hi in ALLOWED_PACKAGED_FLASH_RANGES):
            continue
        if any(word <= addr < word + 4 for word in ALLOWED_PACKAGED_UICR_WORDS):
            continue
        if UICR_PAGE_RANGE[0] <= addr < UICR_PAGE_RANGE[1] and image.memory[addr] == 0xFF:
            continue
        raise PackagedAddressWhitelistError(
            f"{label}: populates disallowed flash/UICR address {addr:#010x} "
            "(app/userdata/SDK-settings/MBR-parameter-scratch regions and any "
            "non-erased UICR byte other than NRFFW0/NRFFW1 must never be programmed "
            "by a packaged no-SWD custom-loader artifact)")


def validate_packaged_region_agrees_with_reference(image: IntelHexImage, lo: int, hi: int,
                                                    reference: bytes, label: str) -> bool:
    """If `image` populates ANY byte within [lo, hi), every populated byte
    in that range must agree with the corresponding `reference` byte.
    Unpopulated bytes are not compared -- a packaged no-SWD artifact may
    legitimately include or omit the public MBR/SoftDevice bytes from its
    own HEX/UF2. Returns whether the region was populated at all."""
    populated = False
    for i in range(hi - lo):
        addr = lo + i
        if addr in image.memory:
            populated = True
            got = image.memory[addr]
            want = reference[i]
            if got != want:
                raise RegionMismatchError(
                    f"{label}: byte at {addr:#010x} disagrees with the public reference "
                    f"(got {got:#04x}, expected {want:#04x})")
    return populated


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    try:
        return sha256_hex(path.read_bytes())
    except OSError as exc:
        raise MissingArtifactError(f"{path}: could not read artifact file ({exc})") from exc


def u16le(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def u32le(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)


# ---------------------------------------------------------------------
# ELF32 physical-load-address (LMA) extraction via arm-none-eabi-readelf.
# We deliberately use `readelf -S` (section headers, which carry both the
# VMA and the file-backed LMA/physical address columns only via `-l`
# program headers cross-referenced with sections) rather than any
# VMA/text-only assumption.
# ---------------------------------------------------------------------
def readelf_section_headers(elf_path: Path, readelf="arm-none-eabi-readelf"):
    try:
        proc = subprocess.run(
            [readelf, "-S", "-W", str(elf_path)], check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise ElfExtractionError(f"required tool '{readelf}' not found") from exc
    except subprocess.CalledProcessError as exc:
        raise ElfExtractionError(f"{elf_path}: readelf -S failed: {exc.stderr}") from exc
    sections = {}
    row_re = re.compile(
        r"^\s*\[\s*\d+\]\s+(\S*)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"
        r"([0-9a-fA-F]+)\s+([A-Za-z]*)\s+\d+\s+\d+\s+\d+\s*$")
    for line in proc.stdout.splitlines():
        m = row_re.match(line)
        if not m:
            continue
        name, sect_type, addr, offset, size, _es, flags = m.groups()
        if "A" not in flags:  # only SHF_ALLOC sections occupy real flash addresses
            continue
        if sect_type == "NOBITS":  # .bss-like: no file-backed bytes to extract
            continue
        sections[name] = {"addr": int(addr, 16), "offset": int(offset, 16), "size": int(size, 16)}
    if not sections:
        raise ElfExtractionError(f"{elf_path}: no sections parsed from readelf output")
    return sections


def readelf_program_headers(elf_path: Path, readelf="arm-none-eabi-readelf"):
    """Returns list of (vaddr, paddr, filesz) for LOAD segments -- the LMA
    (paddr) is the real file-backed PHYSICAL load address, used to resolve
    a section's LMA when its VMA differs (e.g. initialized .data)."""
    try:
        proc = subprocess.run(
            [readelf, "-l", "-W", str(elf_path)], check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise ElfExtractionError(f"required tool '{readelf}' not found") from exc
    except subprocess.CalledProcessError as exc:
        raise ElfExtractionError(f"{elf_path}: readelf -l failed: {exc.stderr}") from exc
    segments = []
    for line in proc.stdout.splitlines():
        m = re.match(
            r"\s*LOAD\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)",
            line)
        if not m:
            continue
        _offset, vaddr, paddr, filesz, _memsz = m.groups()
        segments.append((int(vaddr, 16), int(paddr, 16), int(filesz, 16)))
    if not segments:
        raise ElfExtractionError(f"{elf_path}: no LOAD program headers parsed")
    return segments


def section_lma(section, segments):
    """Resolve a section's real physical load address (LMA) by finding the
    LOAD segment whose VMA range contains the section's VMA, then
    translating via that segment's (vaddr -> paddr) offset. This correctly
    follows initialized .data's LMA rather than its (different) VMA."""
    vaddr = section["addr"]
    size = section["size"]
    if size == 0:
        return vaddr
    for seg_vaddr, seg_paddr, seg_filesz in segments:
        if seg_vaddr <= vaddr < seg_vaddr + max(seg_filesz, 1):
            return seg_paddr + (vaddr - seg_vaddr)
    raise ElfExtractionError(f"no LOAD segment contains section VMA {vaddr:#010x}")


def _allocated_file_backed_sections(elf_path: Path, readelf: str):
    sections = readelf_section_headers(elf_path, readelf)
    segments = readelf_program_headers(elf_path, readelf)
    out = []
    for name, sect in sections.items():
        if name == ".bss" or sect["size"] == 0:
            continue
        lma = section_lma(sect, segments)
        out.append((name, sect, lma))
    if not out:
        raise ElfExtractionError(f"{elf_path}: no allocated file-backed sections found")
    return out


def validate_elf_code_start(elf_path: Path, readelf="arm-none-eabi-readelf"):
    """Reject a build whose lowest allocated, file-backed section LMA is
    not at (or after) the required stock-code-window start -- in
    particular, explicitly reject the larger BLE/custom-profile candidate-
    bank start 0xED000 rather than silently accepting it."""
    sections = _allocated_file_backed_sections(elf_path, readelf)
    min_lma = min(lma for _name, _sect, lma in sections)
    if min_lma == REJECTED_LARGER_PROFILE_CODE_START:
        raise RegionMismatchError(
            f"{elf_path}: loader code starts at the REJECTED larger BLE/custom "
            f"profile address {REJECTED_LARGER_PROFILE_CODE_START:#x}, not the "
            f"required stock-code-window start {STOCK_CODE_OFFSET:#x}")
    if min_lma < STOCK_CODE_OFFSET:
        raise RegionMismatchError(
            f"{elf_path}: loader code starts at {min_lma:#x}, before the required "
            f"stock-code-window start {STOCK_CODE_OFFSET:#x}")


def validate_data_lma_within_code_window(elf_path: Path, readelf="arm-none-eabi-readelf"):
    """Confirm every initialized section whose LMA differs from its VMA
    (i.e. genuine initialized .data, copied from flash to RAM at startup)
    has its flash LMA end strictly at or below the code-window end
    (0xFD800) -- it must never spill into the CF2/config region. BSS
    (NOBITS, already excluded by _allocated_file_backed_sections) is never
    treated as a flash initializer."""
    for name, sect, lma in _allocated_file_backed_sections(elf_path, readelf):
        if lma == sect["addr"]:
            continue  # VMA == LMA: not an initialized/copied section
        lma_end = lma + sect["size"]
        if lma_end > STOCK_CODE_OFFSET + STOCK_CODE_SIZE:
            raise RegionMismatchError(
                f"{elf_path}: initialized section {name} LMA end {lma_end:#x} extends "
                f"past the code-window end {STOCK_CODE_OFFSET + STOCK_CODE_SIZE:#x}")


def extract_elf_region_bytes(elf_path: Path, lo: int, hi: int, readelf="arm-none-eabi-readelf"):
    """Extract [lo, hi) by physical LMA across all allocated, file-backed
    sections, validating there is no gap/overlap conflict with the HEX
    cross-check performed by the caller."""
    sections = readelf_section_headers(elf_path, readelf)
    segments = readelf_program_headers(elf_path, readelf)
    try:
        raw = elf_path.read_bytes()
    except OSError as exc:
        raise MissingArtifactError(f"{elf_path}: could not read ELF file ({exc})") from exc

    out = bytearray([0xFF] * (hi - lo))
    covered = bytearray(hi - lo)
    for name, sect in sections.items():
        if name in (".bss",) or sect["size"] == 0:
            continue
        try:
            lma = section_lma(sect, segments)
        except ElfExtractionError:
            continue
        sect_lo, sect_hi = lma, lma + sect["size"]
        ov_lo, ov_hi = max(lo, sect_lo), min(hi, sect_hi)
        if ov_lo >= ov_hi:
            continue
        file_off = sect["offset"] + (ov_lo - sect_lo)
        chunk = raw[file_off:file_off + (ov_hi - ov_lo)]
        if len(chunk) != (ov_hi - ov_lo):
            raise ElfExtractionError(f"{elf_path}: section {name} file data truncated")
        for i, byte in enumerate(chunk):
            idx = (ov_lo - lo) + i
            if covered[idx] and out[idx] != byte:
                raise ElfExtractionError(
                    f"{elf_path}: conflicting overlapping ELF sections at {ov_lo + i:#010x}")
            out[idx] = byte
            covered[idx] = 1
    return bytes(out)


# ---------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------
def validate_mbr(mbr_image: IntelHexImage):
    body = mbr_image.read(0, MBR_BODY_RANGE_END)
    got = sha256_hex(body)
    if got != MBR_BODY_REFERENCE_SHA256:
        raise RegionMismatchError(
            f"MBR body [0,{MBR_BODY_RANGE_END:#x}) sha256 mismatch: got {got}, "
            f"expected {MBR_BODY_REFERENCE_SHA256}")
    vectors = (u32le(body, 0), u32le(body, 4))
    if vectors != MBR_VECTORS:
        raise RegionMismatchError(f"MBR vectors mismatch: got {vectors!r}, expected {MBR_VECTORS!r}")
    return got, vectors


def validate_softdevice(sd_image: IntelHexImage):
    region = sd_image.read(SOFTDEVICE_RANGE_START, SOFTDEVICE_RANGE_END - SOFTDEVICE_RANGE_START)
    got = sha256_hex(region)
    if got != SOFTDEVICE_730_REFERENCE_SHA256:
        raise RegionMismatchError(
            f"SoftDevice [{SOFTDEVICE_RANGE_START:#x},{SOFTDEVICE_RANGE_END:#x}) sha256 mismatch: "
            f"got {got}, expected {SOFTDEVICE_730_REFERENCE_SHA256}")
    vectors = (u32le(region, 0), u32le(region, 4))
    if vectors != SOFTDEVICE_VECTORS:
        raise RegionMismatchError(
            f"SoftDevice vectors mismatch: got {vectors!r}, expected {SOFTDEVICE_VECTORS!r}")

    info = sd_image.read(SOFTDEVICE_INFO_OFFSET, 0x2C)
    length = info[0]
    magic = u32le(info, 4)
    size = u32le(info, 8)
    fwid = u16le(info, 12)
    variant = u32le(info, 16)
    version = u32le(info, 20)
    unique_id = info[24:44]
    if length != SOFTDEVICE_INFO_EXPECTED_LENGTH:
        raise RegionMismatchError(f"SoftDevice info length mismatch: got {length:#x}")
    if magic != SOFTDEVICE_INFO_EXPECTED_MAGIC:
        raise RegionMismatchError(f"SoftDevice info magic mismatch: got {magic:#010x}")
    if size != SOFTDEVICE_INFO_EXPECTED_SIZE:
        raise RegionMismatchError(f"SoftDevice info size mismatch: got {size:#010x}")
    if fwid != SOFTDEVICE_INFO_EXPECTED_FWID:
        raise RegionMismatchError(f"SoftDevice info FWID mismatch: got {fwid:#06x}")
    if variant != SOFTDEVICE_INFO_EXPECTED_VARIANT:
        raise RegionMismatchError(f"SoftDevice info variant mismatch: got {variant}")
    if version != SOFTDEVICE_INFO_EXPECTED_VERSION:
        raise RegionMismatchError(f"SoftDevice info version mismatch: got {version}")
    return got, vectors, magic, size, fwid, variant, version, unique_id


def resolve_boot_config_policy(mbr_fields, uicr_fields):
    for config_id, policy in APPROVED_CONFIG_POLICIES.items():
        if policy["mbr"] == mbr_fields and policy["uicr"] == uicr_fields:
            return config_id
    return None


def validate_cf2(cf2_bytes: bytes):
    """Validate the COMPLETE CF2 board-info block, field-for-field, against
    the approved astra-contract reference values (layout confirmed against
    the real compiled stock bootloader -- see the CF2_* constants above).
    Returns the sha256 of the whole block."""
    if len(cf2_bytes) != CF2_SIZE:
        raise RegionMismatchError(f"CF2 block wrong size: got {len(cf2_bytes)}, expected {CF2_SIZE}")

    def expect(offset, expected, label):
        got = u32le(cf2_bytes, offset)
        if got != expected:
            raise RegionMismatchError(
                f"CF2 {label} @ {offset:#x} mismatch: got {got:#010x}, expected {expected:#010x}")

    expect(0, CF2_MAGIC_START, "magic-start")
    expect(4, CF2_MAGIC_END, "magic-end")
    expect(8, CF2_COUNTS[0], "count0")
    expect(12, CF2_COUNTS[1], "count1")
    expect(16, CF2_FLASH_SIZE_TAG, "flash-size tag")
    expect(20, CF2_FLASH_SIZE, "flash-size value")
    expect(24, CF2_RAM_SIZE_TAG, "ram-size tag")
    expect(28, CF2_RAM_SIZE, "ram-size value")
    expect(32, CF2_BOARD_ID_TAG, "board-id tag")
    expect(36, CF2_BOARD_ID, "board-id value")
    expect(40, CF2_UF2_FAMILY_TAG, "uf2-family tag")
    expect(44, CF2_UF2_FAMILY, "uf2-family value")
    expect(48, CF2_PORT_SIZE_TAG, "port-size tag")
    expect(52, CF2_PORT_SIZE, "port-size value")
    return sha256_hex(cf2_bytes)


# ---------------------------------------------------------------------
# Deterministic header rendering
# ---------------------------------------------------------------------
def c_bytes_literal(data: bytes) -> str:
    return ", ".join(f"0x{b:02X}" for b in data)


def render_header(rows: list, provenance: dict) -> str:
    lines = []
    lines.append("// GENERATED FILE -- DO NOT EDIT BY HAND.")
    lines.append("// Produced by scripts/ota_boot_catalogue.py from pinned PUBLIC artifacts only.")
    lines.append(f"// schema_version={SCHEMA_VERSION}")
    lines.append(f"// source_date_epoch={provenance['source_date_epoch']}")
    lines.append(f"// board={provenance['board']}")
    lines.append(f"// toolchain={provenance['toolchain']}")
    if provenance.get("out_name"):
        lines.append(f"// out_name={provenance['out_name']}")
    for name in sorted(provenance["submodule_pins"]):
        lines.append(f"// submodule_pin[{name}]={provenance['submodule_pins'][name]}")
    for option in provenance.get("build_options", []):
        lines.append(f"// build_option={option}")
    for name in sorted(provenance["artifact_sha256"]):
        lines.append(f"// artifact_sha256[{name}]={provenance['artifact_sha256'][name]}")
    for custom in provenance.get("custom_rows", []):
        lines.append(
            f"// custom_row[{custom['logical_board']}/role{custom['role_id']}]: "
            f"overlay_revision={custom['overlay_revision']} "
            f"overlay_scope_digest={custom['overlay_scope_digest']}")
    lines.append("#pragma once")
    lines.append("")
    lines.append('#include "Nrf52BootCatalogue.h"')
    lines.append("")
    lines.append(
        "static_assert(::ota::platform::kNrf52BootCatalogueSchemaVersion == "
        f"{SCHEMA_VERSION}u,")
    lines.append(
        '              "generated Nrf52ApprovedBootCatalogue.h schema version does not match '
        'the DTO header; regenerate via scripts/ota_boot_catalogue.py");')
    lines.append("")
    lines.append("namespace ota {")
    lines.append("namespace platform {")
    lines.append("")
    lines.append("inline constexpr Nrf52ApprovedBootRow kApprovedBootCatalogueRows[] = {")
    for row in rows:
        lines.append("  {")
        lines.append(f"    /* target_id */ {row['target_id']:#010x},")
        lines.append(f"    /* profile_id */ {row['profile_id']},")
        lines.append(f"    /* loader_kind */ ::ota::platform::Nrf52LoaderKind::{row['loader_kind']},")
        lines.append(f"    /* role_binding */ ::ota::platform::Nrf52RoleBinding::{row['role_binding']},")
        if row["expected_role_id"] == MBR_FIELD_UNSET:
            lines.append("    /* expected_role_id */ ::ota::platform::kNrf52BootFieldUnset,")
        else:
            lines.append(f"    /* expected_role_id */ {row['expected_role_id']},")
        lines.append(f"    /* expected_boot_info */ {{{c_bytes_literal(row['expected_boot_info'])}}},")
        lines.append(f"    /* stock_code_sha256 */ {{{c_bytes_literal(row['stock_code_sha256'])}}},")
        lines.append(f"    /* cf2_sha256 */ {{{c_bytes_literal(row['cf2_sha256'])}}},")
        lines.append(f"    /* mbr_sha256 */ {{{c_bytes_literal(row['mbr_sha256'])}}},")
        lines.append(f"    /* softdevice_sha256 */ {{{c_bytes_literal(row['softdevice_sha256'])}}},")
        lines.append(
            f"    /* mbr_vectors */ {{{row['mbr_vectors'][0]:#010x}, {row['mbr_vectors'][1]:#010x}}},")
        lines.append(
            f"    /* softdevice_vectors */ {{{row['softdevice_vectors'][0]:#010x}, "
            f"{row['softdevice_vectors'][1]:#010x}}},")
        lines.append(
            f"    /* loader_vectors */ {{{row['loader_vectors'][0]:#010x}, "
            f"{row['loader_vectors'][1]:#010x}}},")
        lines.append(f"    /* ficr_geometry */ {{{FICR_CODE_PAGE_SIZE:#010x}, {FICR_CODE_SIZE:#010x}}},")
        lines.append(f"    /* softdevice_info_magic */ {row['softdevice_info_magic']:#010x},")
        lines.append(f"    /* softdevice_info_size */ {row['softdevice_info_size']:#010x},")
        lines.append(f"    /* softdevice_fwid */ {row['softdevice_fwid']:#06x},")
        lines.append(f"    /* softdevice_variant */ {row['softdevice_variant']},")
        lines.append(f"    /* softdevice_version */ {row['softdevice_version']},")
        lines.append(
            f"    /* softdevice_unique_id */ {{{c_bytes_literal(row['softdevice_unique_id'])}}},")
        lines.append("  },")
    lines.append("};")
    lines.append(
        "inline constexpr size_t kApprovedBootCatalogueRowCount = "
        "sizeof(kApprovedBootCatalogueRows) / sizeof(kApprovedBootCatalogueRows[0]);")
    lines.append("")
    lines.append("}  // namespace platform")
    lines.append("}  // namespace ota")
    lines.append("")
    return "\n".join(lines)


def _row_sort_key(row: dict):
    return (row["target_id"], row["profile_id"], row["role_binding"], row["expected_role_id"])


def build_catalogue_row(mbr_path: Path, softdevice_path: Path, stock_hex_path: Path, stock_elf_path: Path,
                         readelf: str) -> dict:
    mbr_image = parse_intel_hex(mbr_path)
    softdevice_image = parse_intel_hex(softdevice_path)
    stock_hex_image = parse_intel_hex(stock_hex_path)

    mbr_sha256, mbr_vectors = validate_mbr(mbr_image)
    (softdevice_sha256, softdevice_vectors, sd_magic, sd_size, sd_fwid, sd_variant, sd_version,
     sd_unique_id) = validate_softdevice(softdevice_image)

    # Stock code region: cross-check the stock HEX against the stock ELF's
    # real physical (LMA) bytes for the same extent -- so vector/section
    # exactness can never be fabricated from one source alone.
    hex_code = stock_hex_image.read(STOCK_CODE_OFFSET, STOCK_CODE_SIZE)
    elf_code = extract_elf_region_bytes(
        stock_elf_path, STOCK_CODE_OFFSET, STOCK_CODE_OFFSET + STOCK_CODE_SIZE, readelf)
    if hex_code != elf_code:
        raise RegionMismatchError(
            "stock code region differs between stock HEX and stock ELF (LMA) bytes; "
            "refusing to approve an unverifiable code image")
    stock_code_sha256 = sha256_hex(hex_code)

    loader_vectors = (u32le(hex_code, 0), u32le(hex_code, 4))

    cf2_bytes = stock_hex_image.read(CF2_OFFSET, CF2_SIZE)
    cf2_sha256 = validate_cf2(cf2_bytes)

    # The GENUINE bytes measured from the real stock artifact at the
    # boot-info offset -- expected to be erased/0xFF (the stock image
    # never writes a MeshCore Boot marker there), never a hand-written
    # placeholder. VendorStock is role-neutral: role_binding=NotApplicable
    # and expected_role_id is the canonical "role-neutral" sentinel, NOT
    # role 0 used as a wildcard.
    boot_info_lo = BOOT_INFO_OFFSET - CF2_OFFSET
    expected_boot_info = cf2_bytes[boot_info_lo:boot_info_lo + BOOT_INFO_SIZE]

    return {
        "target_id": TARGET_XIAO_NRF52840,
        "profile_id": PROFILE_XIAO,
        "loader_kind": LOADER_KIND_VENDOR_STOCK,
        "role_binding": ROLE_BINDING_NOT_APPLICABLE,
        "expected_role_id": MBR_FIELD_UNSET,
        "expected_boot_info": expected_boot_info,
        "stock_code_sha256": bytes.fromhex(stock_code_sha256),
        "cf2_sha256": bytes.fromhex(cf2_sha256),
        "mbr_sha256": bytes.fromhex(mbr_sha256),
        "softdevice_sha256": bytes.fromhex(softdevice_sha256),
        "mbr_vectors": mbr_vectors,
        "softdevice_vectors": softdevice_vectors,
        "loader_vectors": loader_vectors,
        "softdevice_info_magic": sd_magic,
        "softdevice_info_size": sd_size,
        "softdevice_fwid": sd_fwid,
        "softdevice_variant": sd_variant,
        "softdevice_version": sd_version,
        "softdevice_unique_id": sd_unique_id,
    }


def extract_custom_artifact_fields(descriptor: dict, mbr_path: Path, softdevice_path: Path,
                                    readelf: str = "arm-none-eabi-readelf") -> dict:
    """Pure extraction (no qualification-status gating) over one custom-
    build descriptor's real ELF/HEX/UF2 inputs. Usable directly by tests
    to exercise real-but-UNAPPROVED overlay artifacts (e.g. Boot tree
    1bf73e7, which passed four fits but is NOT approved for installation
    -- Sol flagged its positive floor as lacking lifetime-role binding,
    letting a loader-only role0->1 replacement pair with a signed role1
    "next" command; passing the four fits never substitutes for that root
    fix landing) without ever producing an approved row.
    build_custom_catalogue_row() wraps this with the qualification-status
    gate required before a row may be embedded in the generated header.

    descriptor keys (all required): logical_board, role_id, elf, hex, uf2,
    key_header, overlay_revision, overlay_scope_digest, public_source_pin,
    qualification_status.
    """
    required = ("logical_board", "role_id", "elf", "hex", "uf2", "key_header",
                "overlay_revision", "overlay_scope_digest", "public_source_pin",
                "qualification_status")
    for key in required:
        if key not in descriptor:
            raise MissingArtifactError(f"custom descriptor missing required field {key!r}")

    logical_board = descriptor["logical_board"]
    role_id = descriptor["role_id"]
    matrix_key = (logical_board, role_id)
    if matrix_key not in CUSTOM_BOARD_ROLE_MATRIX:
        raise RegionMismatchError(
            f"no fixed (target,profile) entry for logical_board={logical_board!r} "
            f"role_id={role_id!r}; the board/role applicability matrix is explicit "
            "and fixed, never inferred from the upstream BOARD or CF2 identity")
    target_id, profile_id = CUSTOM_BOARD_ROLE_MATRIX[matrix_key]
    label = f"{logical_board} role{role_id}"

    elf_path = Path(descriptor["elf"])
    hex_path = Path(descriptor["hex"])
    uf2_path = Path(descriptor["uf2"])
    key_header_path = Path(descriptor["key_header"])
    for field_label, path in (("elf", elf_path), ("hex", hex_path), ("uf2", uf2_path),
                              ("key_header", key_header_path)):
        if not path.is_file():
            raise MissingArtifactError(f"{label}: custom descriptor {field_label} not found: {path}")

    hex_image = parse_intel_hex(hex_path)
    uf2_image = parse_uf2(uf2_path)
    validate_packaged_address_whitelist(hex_image, f"{label} packaged HEX ({hex_path})")
    validate_packaged_address_whitelist(uf2_image, f"{label} packaged UF2 ({uf2_path})")

    validate_elf_code_start(elf_path, readelf)
    validate_data_lma_within_code_window(elf_path, readelf)

    # Cross-check the FULL code and FULL config windows between the
    # artifact's own ELF file-backed LMAs, its packaged HEX and its
    # packaged UF2 -- so vector/section exactness cannot be fabricated
    # from any single source.
    elf_code = extract_elf_region_bytes(elf_path, STOCK_CODE_OFFSET, STOCK_CODE_OFFSET + STOCK_CODE_SIZE, readelf)
    hex_code = hex_image.read(STOCK_CODE_OFFSET, STOCK_CODE_SIZE)
    uf2_code = uf2_image.read(STOCK_CODE_OFFSET, STOCK_CODE_SIZE)
    if not (elf_code == hex_code == uf2_code):
        raise RegionMismatchError(
            f"{label}: custom code region [{STOCK_CODE_OFFSET:#x},"
            f"{STOCK_CODE_OFFSET + STOCK_CODE_SIZE:#x}) differs between ELF/HEX/UF2 bytes")
    stock_code_sha256 = sha256_hex(elf_code)

    elf_cf2 = extract_elf_region_bytes(elf_path, CF2_OFFSET, CF2_OFFSET + CF2_SIZE, readelf)
    hex_cf2 = hex_image.read(CF2_OFFSET, CF2_SIZE)
    uf2_cf2 = uf2_image.read(CF2_OFFSET, CF2_SIZE)
    if not (elf_cf2 == hex_cf2 == uf2_cf2):
        raise RegionMismatchError(
            f"{label}: custom config region [{CF2_OFFSET:#x},{CF2_OFFSET + CF2_SIZE:#x}) "
            "differs between ELF/HEX/UF2 bytes")
    # Honest record, not a vendor-stock grant: current preparation inherits
    # the upstream xiao_nrf52840_ble board's CF2 contents even for a
    # SenseCAP logical target -- this validates THIS build's actual
    # approved configuration profile, it never uses the CF2 board-ID to
    # license a SenseCAP vendor-stock row.
    cf2_sha256 = validate_cf2(elf_cf2)

    loader_vectors = (u32le(elf_code, 0), u32le(elf_code, 4))
    msp, reset = loader_vectors
    if not (0x20000000 <= msp <= 0x20040000):
        raise RegionMismatchError(f"{label}: loader MSP {msp:#010x} is not a valid RAM address")
    if reset % 2 != 1:
        raise RegionMismatchError(f"{label}: loader reset vector {reset:#010x} is not Thumb-encoded")
    reset_target = reset & ~1
    if not (STOCK_CODE_OFFSET <= reset_target < STOCK_CODE_OFFSET + STOCK_CODE_SIZE):
        raise RegionMismatchError(
            f"{label}: loader reset vector target {reset_target:#010x} outside this "
            "artifact's own executable code window")

    # Retain the public MBR/SoftDevice reference validation: the SAME
    # shared public reference bytes/hashes/info/vectors used for the
    # vendor-stock row apply here too. If the packaged HEX/UF2 happens to
    # also program any MBR/SoftDevice byte (expected for a no-SWD package
    # that must be flashable with no external debug probe), it must agree
    # with those references.
    mbr_image = parse_intel_hex(mbr_path)
    softdevice_image = parse_intel_hex(softdevice_path)
    mbr_sha256, mbr_vectors = validate_mbr(mbr_image)
    (softdevice_sha256, softdevice_vectors, sd_magic, sd_size, sd_fwid, sd_variant, sd_version,
     sd_unique_id) = validate_softdevice(softdevice_image)
    mbr_reference_bytes = mbr_image.read(0, MBR_BODY_RANGE_END)
    softdevice_reference_bytes = softdevice_image.read(
        SOFTDEVICE_RANGE_START, SOFTDEVICE_RANGE_END - SOFTDEVICE_RANGE_START)
    validate_packaged_region_agrees_with_reference(
        hex_image, 0, MBR_BODY_RANGE_END, mbr_reference_bytes, f"{label} packaged HEX MBR region")
    validate_packaged_region_agrees_with_reference(
        uf2_image, 0, MBR_BODY_RANGE_END, mbr_reference_bytes, f"{label} packaged UF2 MBR region")
    validate_packaged_region_agrees_with_reference(
        hex_image, SOFTDEVICE_RANGE_START, SOFTDEVICE_RANGE_END, softdevice_reference_bytes,
        f"{label} packaged HEX SoftDevice region")
    validate_packaged_region_agrees_with_reference(
        uf2_image, SOFTDEVICE_RANGE_START, SOFTDEVICE_RANGE_END, softdevice_reference_bytes,
        f"{label} packaged UF2 SoftDevice region")

    # Boot-info marker: both windows must agree, and BOTH the packaged HEX
    # and the packaged UF2 must independently pass Boot's own
    # verify_boot_info_artifact.py::check_artifact (magic/format/length/
    # target/role/capability/key-ID/algorithm/public-key/CRC32) for the
    # exact logical board and role -- never adopting whatever key the
    # artifact happens to carry as its own expected trust anchor (Boot's
    # validator parses the real committed public-key header independently).
    boot_info_lo = BOOT_INFO_OFFSET - CF2_OFFSET
    hex_boot_info = hex_cf2[boot_info_lo:boot_info_lo + BOOT_INFO_SIZE]
    uf2_boot_info = uf2_cf2[boot_info_lo:boot_info_lo + BOOT_INFO_SIZE]
    if hex_boot_info != uf2_boot_info:
        raise RegionMismatchError(f"{label}: boot-info marker differs between packaged HEX and UF2")

    verify_mod = _load_boot_info_verify_module()
    check_board = BOOT_INFO_CHECK_BOARD_NAME.get(logical_board)
    if check_board is None:
        raise RegionMismatchError(
            f"{label}: no verify_boot_info_artifact.py --board mapping for {logical_board!r}")
    for artifact_label, artifact_path in (("packaged HEX", hex_path), ("packaged UF2", uf2_path)):
        errors = verify_mod.check_artifact(artifact_path, check_board, key_header_path, role_id)
        if errors:
            raise RegionMismatchError(
                f"{label}: {artifact_label} failed boot-info artifact check: " + "; ".join(errors))

    return {
        "target_id": target_id,
        "profile_id": profile_id,
        "loader_kind": LOADER_KIND_MESHCORE_OTA,
        "role_binding": ROLE_BINDING_EXACT,
        "expected_role_id": role_id,
        "expected_boot_info": hex_boot_info,
        "stock_code_sha256": bytes.fromhex(stock_code_sha256),
        "cf2_sha256": bytes.fromhex(cf2_sha256),
        "mbr_sha256": bytes.fromhex(mbr_sha256),
        "softdevice_sha256": bytes.fromhex(softdevice_sha256),
        "mbr_vectors": mbr_vectors,
        "softdevice_vectors": softdevice_vectors,
        "loader_vectors": loader_vectors,
        "softdevice_info_magic": sd_magic,
        "softdevice_info_size": sd_size,
        "softdevice_fwid": sd_fwid,
        "softdevice_variant": sd_variant,
        "softdevice_version": sd_version,
        "softdevice_unique_id": sd_unique_id,
        "_descriptor": {
            "logical_board": logical_board,
            "role_id": role_id,
            "overlay_revision": descriptor["overlay_revision"],
            "overlay_scope_digest": descriptor["overlay_scope_digest"],
            "public_source_pin": descriptor["public_source_pin"],
        },
    }


def build_custom_catalogue_row(descriptor: dict, mbr_path: Path, softdevice_path: Path,
                                readelf: str = "arm-none-eabi-readelf") -> dict:
    """Wraps extract_custom_artifact_fields with the qualification-status
    gate required before a custom row may be embedded in the generated
    header: only descriptor["qualification_status"] == "approved" may ever
    reach the real generated Nrf52ApprovedBootCatalogue.h. A real,
    four-fit-passing, but not-yet-approved overlay build (e.g. Boot tree
    1bf73e7 -- held because its positive floor lacks lifetime-role binding,
    allowing a loader-only role0->1 replacement plus a signed role1 "next"
    command; Boot/FW are shipping a root fix using the existing signed
    manifest238+commission117 receipt's role evidence, gated before repair/
    admission and preserved across every floor-sector erase) must raise
    UnapprovedOverlayError here, never silently produce a placeholder or
    partial row. Once Boot/FW's fix lands, custom rows must be generated
    from the NEW independently qualified artifacts -- 1bf73e7 passing its
    four fits does NOT itself qualify it; this gate must never be used to
    freeze/promote a vulnerable custom artifact's hash as approved."""
    status = descriptor.get("qualification_status")
    if status != "approved":
        raise UnapprovedOverlayError(
            f"custom descriptor for {descriptor.get('logical_board')}/"
            f"role{descriptor.get('role_id')} has qualification_status={status!r}, "
            "not 'approved'; refusing to embed its extracted fields as an approved "
            "catalogue row (its real artifacts may still be used directly via "
            "extract_custom_artifact_fields for producer-extraction tests)")
    return extract_custom_artifact_fields(descriptor, mbr_path, softdevice_path, readelf)


# The fixed, complete applicability set a --custom-manifest must contain
# exactly -- one descriptor per (logical_board, role_id) matrix entry, no
# more, no fewer, no duplicates.
REQUIRED_CUSTOM_BOARD_ROLES = frozenset(CUSTOM_BOARD_ROLE_MATRIX.keys())


def load_custom_manifest(path: Path) -> list:
    """Load and structurally validate a single --custom-manifest JSON file:
    a top-level object with a "descriptors" array containing EXACTLY one
    descriptor per entry of REQUIRED_CUSTOM_BOARD_ROLES (the fixed four
    xiao_nrf52840/sensecap_solar_p1 x role0/role1 combinations) -- no
    partial subset, no duplicate/unknown board-role pair. This is the
    single-manifest aggregate path Root's Make target is expected to use;
    it never itself grants approval -- build_custom_catalogue_row() still
    independently gates each descriptor's qualification_status before any
    row may be embedded."""
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise MissingArtifactError(f"could not read/parse custom manifest {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("descriptors"), list):
        raise IncompleteCustomManifestError(
            f"{path}: custom manifest must be a JSON object with a \"descriptors\" array")
    descriptors = payload["descriptors"]
    seen_keys = []
    for index, descriptor in enumerate(descriptors):
        if not isinstance(descriptor, dict) or "logical_board" not in descriptor or "role_id" not in descriptor:
            raise IncompleteCustomManifestError(
                f"{path}: descriptors[{index}] is missing logical_board/role_id")
        logical_board = descriptor["logical_board"]
        role_id = descriptor["role_id"]
        # Reject non-str logical_board and non-int role_id (explicitly
        # including bool, since type(True) is bool not int and must not
        # silently alias role_id==1) before they ever reach a set/hash
        # comparison -- a malformed scalar type must be a typed structural
        # refusal here, not an uncaught TypeError from set()/sorted() or a
        # bool-equals-int false "match" against the required matrix.
        if not isinstance(logical_board, str) or type(role_id) is not int:
            raise IncompleteCustomManifestError(
                f"{path}: descriptors[{index}] logical_board must be a string and role_id must be "
                f"a plain integer, got logical_board={logical_board!r} "
                f"({type(logical_board).__name__}), role_id={role_id!r} ({type(role_id).__name__})")
        seen_keys.append((logical_board, role_id))
    seen_set = set(seen_keys)
    duplicates = {key for key in seen_keys if seen_keys.count(key) > 1}
    missing = REQUIRED_CUSTOM_BOARD_ROLES - seen_set
    unknown = seen_set - REQUIRED_CUSTOM_BOARD_ROLES
    if duplicates or missing or unknown:
        problems = []
        if missing:
            problems.append(f"missing={sorted(missing)}")
        if duplicates:
            problems.append(f"duplicate={sorted(duplicates)}")
        if unknown:
            problems.append(f"unrecognized={sorted(unknown)}")
        raise IncompleteCustomManifestError(
            f"{path}: custom manifest must contain EXACTLY the four required "
            f"(logical_board, role_id) entries {sorted(REQUIRED_CUSTOM_BOARD_ROLES)}; "
            "a partial, missing, duplicated, or unrecognized custom set must fail the "
            "whole run, never silently publish a header that looks like the complete "
            f"stock-plus-four set ({'; '.join(problems)})")
    return descriptors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mbr-hex", required=True, type=Path,
                         help="public MBR Intel HEX (e.g. mbr_nrf52_2.4.1_mbr.hex)")
    parser.add_argument("--softdevice-hex", required=True, type=Path,
                         help="public S140 7.3.0 Intel HEX")
    parser.add_argument("--stock-hex", required=True, type=Path,
                         help="compiled STOCK bootloader Intel HEX (unmodified upstream build)")
    parser.add_argument("--stock-elf", required=True, type=Path,
                         help="compiled STOCK bootloader ELF (same build as --stock-hex)")
    parser.add_argument("--board", required=True, help="exact board identifier used for the stock build")
    parser.add_argument("--toolchain", required=True,
                         help="exact toolchain identifier/version used for the stock build")
    parser.add_argument("--submodule-pin", action="append", default=[], metavar="NAME=COMMIT",
                         help="repeatable; records an exact submodule pin, e.g. "
                              "Adafruit_nRF52_Bootloader=c67f0bcf0fa8e841426335b1bbde91cda6ca1f50")
    parser.add_argument("--source-date-epoch", required=True, type=int,
                         help="fixed epoch recorded in provenance (Root-owned build value)")
    parser.add_argument("--out-name", default=None,
                         help="exact build output name, e.g. xiao_nrf52840_ble_bootloader-0.11.0")
    parser.add_argument("--build-option", action="append", default=[], metavar="FLAG",
                         help="repeatable; records one exact effective compiler/build option string "
                              "(e.g. a single CFLAGS/ASFLAGS/LDFLAGS token) verbatim, in the order given")
    parser.add_argument("--readelf", default="arm-none-eabi-readelf")
    parser.add_argument("--custom-descriptor", action="append", default=[], type=Path, metavar="PATH",
                         help="repeatable; path to a JSON custom-row descriptor (logical_board, "
                              "role_id, elf, hex, uf2, key_header, overlay_revision, "
                              "overlay_scope_digest, public_source_pin, qualification_status). "
                              "Only qualification_status=='approved' descriptors are embedded as "
                              "approved rows; anything else is a typed refusal "
                              "(UnapprovedOverlayError), never a placeholder or partial row. "
                              "Mutually exclusive with --custom-manifest. Omit both for stock-only "
                              "generation.")
    parser.add_argument("--custom-manifest", default=None, type=Path, metavar="PATH",
                         help="path to a single JSON manifest ({\"descriptors\": [...]}) containing "
                              "EXACTLY the four fixed board/role descriptors (xiao_nrf52840 role0/"
                              "role1, sensecap_solar_p1 role0/role1) -- the preferred aggregate path "
                              "for Root's Make target. A partial/missing/duplicated custom set is a "
                              "typed refusal (IncompleteCustomManifestError), never a silently "
                              "partial header. Each entry still independently requires "
                              "qualification_status=='approved' to be embedded. Mutually exclusive "
                              "with --custom-descriptor.")
    parser.add_argument("--out-header", required=True, type=Path,
                         help="output path for generated Nrf52ApprovedBootCatalogue.h")
    parser.add_argument("--out-provenance", required=True, type=Path,
                         help="output path for the JSON provenance sidecar")
    args = parser.parse_args(argv)

    if args.custom_descriptor and args.custom_manifest:
        print("error: --custom-descriptor and --custom-manifest are mutually exclusive", file=sys.stderr)
        return 2

    for label, path in (
        ("--mbr-hex", args.mbr_hex), ("--softdevice-hex", args.softdevice_hex),
        ("--stock-hex", args.stock_hex), ("--stock-elf", args.stock_elf),
    ):
        if not path.is_file():
            print(f"MissingArtifactError: {label} not found: {path}", file=sys.stderr)
            return 2

    submodule_pins = {}
    for entry in args.submodule_pin:
        if "=" not in entry:
            print(f"error: --submodule-pin must be NAME=COMMIT, got {entry!r}", file=sys.stderr)
            return 2
        name, commit = entry.split("=", 1)
        submodule_pins[name] = commit

    try:
        stock_row = build_catalogue_row(
            args.mbr_hex, args.softdevice_hex, args.stock_hex, args.stock_elf, args.readelf)
    except BootCatalogueError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    # Gather (label, descriptor-dict) pairs from whichever source was given
    # -- the single aggregate manifest (preferred; validated as a complete,
    # non-partial, non-duplicate four-entry set before any row is built) or
    # the lower-level repeatable --custom-descriptor flag (ad-hoc/test use,
    # no completeness requirement). Nothing is written to --out-header/
    # --out-provenance until EVERY descriptor from whichever source has
    # been validated and built.
    pending_descriptors = []
    if args.custom_manifest:
        if not args.custom_manifest.is_file():
            print(f"MissingArtifactError: --custom-manifest not found: {args.custom_manifest}", file=sys.stderr)
            return 2
        try:
            manifest_descriptors = load_custom_manifest(args.custom_manifest)
        except BootCatalogueError as exc:
            print(f"{type(exc).__name__}: {args.custom_manifest}: {exc}", file=sys.stderr)
            return 1
        for descriptor in manifest_descriptors:
            label = f"{args.custom_manifest}[{descriptor.get('logical_board')}/role{descriptor.get('role_id')}]"
            pending_descriptors.append((label, descriptor))
    else:
        for descriptor_path in args.custom_descriptor:
            if not descriptor_path.is_file():
                print(f"MissingArtifactError: --custom-descriptor not found: {descriptor_path}", file=sys.stderr)
                return 2
            try:
                descriptor = json.loads(descriptor_path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                print(f"MissingArtifactError: could not read/parse {descriptor_path}: {exc}", file=sys.stderr)
                return 2
            pending_descriptors.append((str(descriptor_path), descriptor))

    rows = [stock_row]
    custom_provenance = []
    for label, descriptor in pending_descriptors:
        try:
            custom_row = build_custom_catalogue_row(
                descriptor, args.mbr_hex, args.softdevice_hex, args.readelf)
        except BootCatalogueError as exc:
            print(f"{type(exc).__name__}: {label}: {exc}", file=sys.stderr)
            return 1
        custom_meta = custom_row.pop("_descriptor")
        rows.append(custom_row)
        custom_provenance.append(custom_meta)

    rows.sort(key=_row_sort_key)

    provenance = {
        "board": args.board,
        "toolchain": args.toolchain,
        "source_date_epoch": args.source_date_epoch,
        "out_name": args.out_name,
        "submodule_pins": submodule_pins,
        "build_options": list(args.build_option),
        "artifact_sha256": {
            "mbr_hex": file_sha256(args.mbr_hex),
            "softdevice_hex": file_sha256(args.softdevice_hex),
            "stock_hex": file_sha256(args.stock_hex),
            "stock_elf": file_sha256(args.stock_elf),
        },
        "custom_rows": custom_provenance,
    }

    header_text = render_header(rows, provenance)

    def _row_manifest(row):
        return {
            "target_id": row["target_id"],
            "profile_id": row["profile_id"],
            "loader_kind": row["loader_kind"],
            "role_binding": row["role_binding"],
            "expected_role_id": row["expected_role_id"],
            "expected_boot_info": row["expected_boot_info"].hex()
            if isinstance(row["expected_boot_info"], (bytes, bytearray))
            else bytes(row["expected_boot_info"]).hex(),
            "stock_code_sha256": row["stock_code_sha256"].hex(),
            "cf2_sha256": row["cf2_sha256"].hex(),
            "mbr_sha256": row["mbr_sha256"].hex(),
            "softdevice_sha256": row["softdevice_sha256"].hex(),
            "mbr_vectors": list(row["mbr_vectors"]),
            "softdevice_vectors": list(row["softdevice_vectors"]),
            "loader_vectors": list(row["loader_vectors"]),
            "softdevice_info_magic": row["softdevice_info_magic"],
            "softdevice_info_size": row["softdevice_info_size"],
            "softdevice_fwid": row["softdevice_fwid"],
            "softdevice_variant": row["softdevice_variant"],
            "softdevice_version": row["softdevice_version"],
            "softdevice_unique_id": row["softdevice_unique_id"].hex(),
        }

    manifest = dict(provenance)
    manifest["rows"] = [_row_manifest(row) for row in rows]
    provenance_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"

    # Both outputs are fully constructed and serialized to text BEFORE
    # either is written to disk: a failure in render_header()/_row_manifest()/
    # json.dumps() must never leave one output on disk while the other is
    # missing or stale. This guarantees "all descriptors valid" and "both
    # outputs published" are the same event, not two sequential writes that
    # could diverge on a mid-run exception. (The actual filesystem write
    # calls themselves are not made atomic/transactional here -- a caller
    # that must tolerate a crash between the two write_text() calls below
    # should write into distinct staging paths and only consume/publish
    # them after this process exits 0, rather than writing directly to
    # final published paths.)
    args.out_header.parent.mkdir(parents=True, exist_ok=True)
    args.out_provenance.parent.mkdir(parents=True, exist_ok=True)
    args.out_header.write_text(header_text)
    args.out_provenance.write_text(provenance_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
