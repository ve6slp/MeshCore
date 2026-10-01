#!/usr/bin/env python3
"""Shared canonical59 wire-descriptor construction, geometry/alignment
policy, and board-target table.

This is the SINGLE place that builds the real LoRa OTA transport canonical
wire descriptor (src/ota/protocol/OtaDescriptor.h,
encodeOtaDescriptorCanonical): boardFamily u16, boardVariant u16, role u8,
appAddress u32, exactSizeBytes u32, sha256[32], securityCounter u32,
minBootloaderCapabilities u32, formatId u16, keyId u16, algorithmId u16 --
all big-endian, 59 bytes total, field-by-field (no struct padding). Both
tools/sign_image.py (which additionally signs this descriptor and builds a
full durable install command) and tools/build_manifest.py (which emits
ONLY this bare unsigned descriptor, for host-side CMD33/34/35 signing) call
build_descriptor() below -- there is exactly one descriptor codec in this
tree, never two independently-maintained copies.
"""

import hashlib
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CANONICAL_LAYOUT_CONTRACT = ROOT / "src" / "ota" / "platform" / "Nrf52FlashLayoutContract.h"

# Must stay byte-for-byte identical to the same-named constants in
# bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h -- these are what
# the compiled bootloader's install-command policy check actually enforces
# per --board (see tools/prepare_upstream.py's matching BOARD_TARGET_VALUE
# table and its cross-check against xiao_ota_record.h).
BOARD_TARGETS = {
    "xiao_nrf52840": 0x584E3430,
    # A real, distinct target id sharing the same P25Q16H QSPI pinout family
    # as the XIAO profile, but NOT physically qualified on hardware -- any
    # descriptor built with this profile is build-only until a real board
    # confirms it works.
    "sensecap_solar_p1": 0x53435031,
}
MANIFEST_BOARD_TARGETS = {**BOARD_TARGETS, "xiao_s3_wio": 0x45535333}
ESP_APP_START = 0x10000
# Esp32OtaPolicy: one CRC-protected 4 KiB bitmap, 84-byte USB/RF blocks.
ESP_INSTALL_MAX_SIZE = (4096 - 4) * 8 * 84
CAP_QSPI_INSTALL = 1
APP_START = 0x27000
# Full internal app-region extent (0x27000..0xED000): the largest size
# active_extent_from_settings() (xiao_ota_boot_io.c) will ever itself
# derive/read+copy for an actual physical backup at runtime. It is NOT,
# by itself, a valid bound for the SIGNED active_image_extent field a
# durable install command carries (see sign_image.py) -- that field is
# bounded by the stricter INSTALL_MAX_SIZE below. BACKUP_MAX_SIZE remains
# meaningful only as the fixed physical bank-to-bank placement stride
# cross-checked against the canonical layout contract's
# OTA_NRF52_PHYSICAL_BANK_STRIDE_BYTES.
BACKUP_MAX_SIZE = 0xC6000
# Candidate/install cap (0x27000..0xD4000 = 708,608 bytes): the actual
# code region, distinct from and smaller than BACKUP_MAX_SIZE.
# 0xD4000..0xED000 is where the internal filesystem (LittleFS/ExtraFS)
# lives today; a descriptor up to the full BACKUP_MAX_SIZE would let an
# otherwise-legitimate install erase/overwrite into that region, since
# nothing else in the wire contract enforces a smaller bound. This is a
# safety cap, not a new wire-format field: no schema, role/target/format-
# signature change. Do not raise this until an explicit filesystem-
# relocation migration proves the FS no longer lives in 0xD4000..0xED000;
# no such migration-complete signal exists yet.
INSTALL_MAX_SIZE = 0xAD000
WIRE_DESCRIPTOR_SIZE = 59
# Must stay byte-for-byte identical to XIAO_OTA_COMPILED_ROLE_ID's
# compile-time _Static_assert in xiao_ota_record.h: 0 (companion) or 1
# (repeater), never a third value.
ROLE_IDS = (0, 1)
MAX_SECURITY_COUNTER = 0xFFFFFFFF


def _canonical_hex_define(header_text, macro):
    m = re.search(rf"#define\s+{re.escape(macro)}\s+(0[xX][0-9A-Fa-f]+)u?\b", header_text)
    if not m:
        raise SystemExit(
            f"canonical shared layout contract {CANONICAL_LAYOUT_CONTRACT} no longer "
            f"defines {macro} -- update xiao_ota_descriptor.py's cross-check"
        )
    return int(m.group(1), 16)


def assert_matches_canonical_layout_contract():
    """Refuse to build anything if this module's own APP_START/
    INSTALL_MAX_SIZE/BACKUP_MAX_SIZE literals have silently drifted from
    the single, authoritative shared contract
    (src/ota/platform/Nrf52FlashLayoutContract.h, owned by MAIN, never
    edited here). A missing canonical header is a hard error, never a
    silent fallback to these locally duplicated literals -- they exist
    only because a Python tool cannot #include a C header, and must
    always be re-verified against the live contract, not trusted on
    their own."""
    if not CANONICAL_LAYOUT_CONTRACT.is_file():
        raise SystemExit(
            f"canonical shared layout contract missing: {CANONICAL_LAYOUT_CONTRACT} "
            "-- refusing to build against possibly-stale local literals"
        )
    text = CANONICAL_LAYOUT_CONTRACT.read_text()
    checks = (
        ("OTA_NRF52_INTERNAL_IMAGE_OFFSET", APP_START),
        ("OTA_NRF52_IMAGE_CAPACITY_BYTES", INSTALL_MAX_SIZE),
        ("OTA_NRF52_PHYSICAL_BANK_STRIDE_BYTES", BACKUP_MAX_SIZE),
    )
    for macro, expected in checks:
        actual = _canonical_hex_define(text, macro)
        if actual != expected:
            raise SystemExit(
                f"xiao_ota_descriptor.py's {expected:#x} no longer matches canonical "
                f"{macro}={actual:#x} in {CANONICAL_LAYOUT_CONTRACT} -- update "
                "xiao_ota_descriptor.py's local constant, do not build against a stale value"
            )


def validate_role_id(role_id):
    if role_id not in ROLE_IDS:
        raise SystemExit(
            f"--role-id must be one of {ROLE_IDS} (0=companion, 1=repeater), got {role_id}"
        )


def validate_security_counter(counter):
    # A device's anti-rollback floor starts at 0 and the bootloader rejects
    # any command whose monotonic_counter <= counter_floor
    # (xiao_ota_install_command_admission_valid(), xiao_ota_record.c) --
    # counter 0 can therefore never pass that check on any real device, so
    # reject it here as a clearly-unusable input rather than silently
    # emitting a descriptor that can never install.
    if not (0 < counter <= MAX_SECURITY_COUNTER):
        raise SystemExit(
            f"--counter must satisfy 0 < counter <= {MAX_SECURITY_COUNTER} "
            "(uint32, and strictly greater than 0 since the bootloader's "
            f"anti-rollback floor starts at 0), got {counter}"
        )


def validate_image_geometry(image_bytes, what="image"):
    if not image_bytes or len(image_bytes) > INSTALL_MAX_SIZE or len(image_bytes) % 4:
        raise SystemExit(
            f"{what} must be word aligned and in 1..{INSTALL_MAX_SIZE} "
            f"(0x{INSTALL_MAX_SIZE:X}) bytes -- the internal filesystem region "
            "(0xD4000..0xED000) is out of bounds for a candidate install until "
            "an explicit migration proof allows raising this cap"
        )


def build_descriptor(board, role_id, counter, image_bytes):
    """Validate --board/--role-id/--counter/image geometry, then build and
    return the exact 59-byte canonical big-endian wire descriptor. Raises
    SystemExit (not a silent truncation/fallback) on any invalid input."""
    if board not in MANIFEST_BOARD_TARGETS:
        raise SystemExit(f"--board must be one of {tuple(MANIFEST_BOARD_TARGETS)}, got {board!r}")
    validate_role_id(role_id)
    validate_security_counter(counter)
    if board == "xiao_s3_wio":
        if not image_bytes or len(image_bytes) > ESP_INSTALL_MAX_SIZE:
            raise SystemExit(f"ESP application image must be in 1..{ESP_INSTALL_MAX_SIZE} bytes")
        app_start = ESP_APP_START
    else:
        validate_image_geometry(image_bytes)
        app_start = APP_START

    target = MANIFEST_BOARD_TARGETS[board]
    board_family = target >> 16
    board_variant = target & 0xFFFF
    descriptor = struct.pack(
        ">HHBII",
        board_family, board_variant, role_id, app_start, len(image_bytes),
    ) + hashlib.sha256(image_bytes).digest() + struct.pack(
        ">IIHHH", counter, CAP_QSPI_INSTALL, 1, 1, 1,
    )
    assert len(descriptor) == WIRE_DESCRIPTOR_SIZE
    return descriptor
