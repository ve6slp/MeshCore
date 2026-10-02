#!/usr/bin/env python3
"""Independent artifact-level check of the immutable boot-info marker.

This deliberately does NOT call xiao_ota_boot_info_build()/_valid() (the C
helpers under src/xiao_ota_boot_info.c) or reuse prepare_upstream.py's
CRC-patch logic. It parses the *actual packaged* Intel HEX or UF2 bytes at
XIAO_OTA_BOOT_INFO_ADDRESS produced by a real build, decodes them against a
plain, independently-declared 60-byte little-endian layout, and separately
recomputes and checks the CRC-32 and every profile/key field.

The marker's embedded public key (reference_signer_public_key_ed25519) is a
build-identity/provenance fact only -- "which static placeholder value
include/xiao_ota_public_key.h held, as embedded by prepare_upstream.py's
CRC-patch step for this specific build" -- NOT a runtime install-command
trust anchor: the bootloader verifies each install command
against THAT command's own embedded admitted_signer_public_key_ed25519
(xiao_ota_command_v2_t), never against this marker. --key-header is
OPTIONAL and purely an opt-in cross-check of that provenance fact against a
header file you expected the build to use; omitting it skips the check
entirely (there is no compiled/default key substituted, and omission is not
a failure). This never substitutes for or implies anything about the
bootloader's actual install-time trust decision. If
prepare_upstream.py's patch step and this validator ever silently agreed on
the same wrong value (a shared-code bug), or the linker placed the section
somewhere else, or a real board_target value ever drifted from what a
release actually intends to ship, this script -- run against the real
compiled artifact, not against in-process C helpers -- is meant to still
catch it.

Usage:
    verify_boot_info_artifact.py --board xiao_nrf52840 \\
        path/to/xiao_nrf52840_ota_noswd.hex
    verify_boot_info_artifact.py --board sensecap_solar_p1 --key-header \\
        bootloader/xiao_nrf52840_ota/include/xiao_ota_public_key.h \\
        path/to/xiao_nrf52840_ota_noswd.uf2

Exits non-zero with a specific reason on any mismatch. Never writes
anything; read-only over the given artifact file.
"""

from __future__ import annotations

from pathlib import Path
import argparse
import binascii
import re
import struct
import sys

# Independent golden constants. Deliberately NOT imported from
# include/xiao_ota_boot_info.h or include/xiao_ota_record.h: this file is
# meant to notice if those headers' real values ever drift from what a
# release build is supposed to ship, so it re-declares its own copies
# rather than trusting the same source the firmware was compiled from.
BOOT_INFO_ADDRESS = 0xFDC00
BOOT_INFO_MAGIC = 0x584F4249  # "XOBI"
BOOT_INFO_FORMAT_VERSION = 1
BOOT_INFO_STRUCT_BYTES = 60
# role_id's expected value is now a caller-supplied --role-id (0=companion,
# 1=repeater), not a single fixed golden constant -- see check_artifact()'s
# expected_role parameter. There is no separate "any role" golden value.
CAP_QSPI_INSTALL = 1
KEY_ID = 1
ALGORITHM_ED25519 = 1

BOARD_TARGET_VALUE = {
    "xiao_nrf52840": 0x584E3430,
    "xiao_nrf52840_sense": 0x584E3430,
    "sensecap_solar_p1": 0x53435031,
}
CF2_ADDRESS = 0xFD800
CF2_BYTES = BOOT_INFO_ADDRESS - CF2_ADDRESS
CF2_MAGIC = (0x1E9E10F1, 0x20227A79)
CF2_BOOTLOADER_BOARD_ID = 208

# UF2 block flags (offset 8; see https://github.com/microsoft/uf2). Every
# block a real build of this artifact emits sets exactly
# UF2_FLAG_FAMILY_ID_PRESENT -- checked here so a crafted marker block
# cannot pass this independent verifier by looking byte-correct while
# carrying a flag that tells a real UF2 bootloader to never actually write
# it to flash.
UF2_FLAG_NOT_MAIN_FLASH = 0x00000001
UF2_FLAG_FILE_CONTAINER = 0x00001000
UF2_FLAG_FAMILY_ID_PRESENT = 0x00002000

# magic, format_version, struct_bytes, board_target_id, role_id,
# capability_flags, key_id, algorithm_id,
# reference_signer_public_key_ed25519[32], crc32
_LAYOUT = "<IHHIIIHH32sI"
assert struct.calcsize(_LAYOUT) == BOOT_INFO_STRUCT_BYTES, (
    f"golden layout size {struct.calcsize(_LAYOUT)} != "
    f"{BOOT_INFO_STRUCT_BYTES}; this validator's own layout constant is "
    "stale relative to itself"
)


def read_intel_hex_bytes(path: Path, address: int, length: int) -> bytes:
    """Minimal Intel HEX reader: flat linear (:04 Extended Linear Address)
    plus data (:00), EOF (:01), and start-address (:03/:05, entry-point
    metadata that never affects data placement) records -- all
    arm-none-eabi-objcopy ever emits for this target. Validates each
    record's declared byte count against its actual payload length and its
    checksum, and explicitly rejects (rather than silently ignores) any
    other record type, including Extended Segment Address (:02, a real
    address-affecting scheme this reader does not implement) -- a
    silently-skipped address record could otherwise misplace every
    following byte without any error."""
    out = bytearray(b"\xff" * length)
    seen = {}
    found_any = False
    upper = 0
    with path.open("r", encoding="ascii") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            if not line.startswith(":"):
                raise SystemExit(f"{path}:{lineno}: HEX record missing ':' prefix")
            try:
                raw = bytes.fromhex(line[1:])
            except ValueError as e:
                raise SystemExit(f"{path}:{lineno}: malformed hex digits: {e}")
            if len(raw) < 5:
                raise SystemExit(f"{path}:{lineno}: truncated HEX record (too short)")
            byte_count, addr_lo, rec_type = raw[0], (raw[1] << 8) | raw[2], raw[3]
            if len(raw) != byte_count + 5:
                raise SystemExit(
                    f"{path}:{lineno}: declared byte_count {byte_count} does not match "
                    f"actual record length {len(raw) - 5}"
                )
            checksum = (-(sum(raw[:-1]))) & 0xFF
            if checksum != raw[-1]:
                raise SystemExit(
                    f"{path}:{lineno}: checksum mismatch (expected 0x{checksum:02X}, "
                    f"record has 0x{raw[-1]:02X})"
                )
            payload = raw[4:4 + byte_count]
            if rec_type in (0x01, 0x03, 0x05):
                # EOF / Start Segment Address / Start Linear Address: none
                # of these affect data addressing (only entry-point/CS:IP
                # metadata), so they are safely no-ops here.
                if rec_type == 0x01:
                    break
                continue
            if rec_type == 0x04:  # Extended Linear Address
                if byte_count != 2:
                    raise SystemExit(
                        f"{path}:{lineno}: Extended Linear Address record must carry "
                        f"2 bytes, got {byte_count}"
                    )
                upper = (payload[0] << 24) | (payload[1] << 16)
                continue
            if rec_type != 0x00:
                raise SystemExit(
                    f"{path}:{lineno}: unsupported HEX record type 0x{rec_type:02X} "
                    "(only data/EOF/extended-linear-address/start-address are "
                    "handled; refusing to silently misparse an address scheme "
                    "this reader does not implement, e.g. Extended Segment "
                    "Address 0x02)"
                )
            abs_addr = upper | addr_lo
            for i, b in enumerate(payload):
                a = abs_addr + i
                if address <= a < address + length:
                    if a in seen and seen[a] != b:
                        raise SystemExit(f"{path}:{lineno}: conflicting HEX bytes at 0x{a:X}")
                    seen[a] = b
                    out[a - address] = b
                    found_any = True
    if not found_any:
        raise SystemExit(
            f"no HEX record covered address range 0x{address:X}.."
            f"0x{address + length:X} in {path}"
        )
    return bytes(out)


def read_uf2_bytes(path: Path, address: int, length: int) -> bytes:
    """Minimal UF2 reader: standard 512-byte blocks. Validates start/end
    magic, the per-block flags word (rejecting "not main flash"/"file
    container" blocks and requiring "familyID present", since a crafted
    file can leave the address map and marker payload bytes looking
    byte-correct while flagging a block so a real UF2 bootloader never
    actually writes it to flash), payload_size <= 476 (the maximum a
    512-byte block can carry: 512 - 32-byte header - 4-byte trailing
    magic), and rejects (rather than silently overwrites) two blocks that
    disagree about the same address inside our target range. Only headers,
    trailers and the requested payload range are read, never other payloads."""
    size = path.stat().st_size
    if size % 512 != 0:
        raise SystemExit(f"{path}: not a whole number of 512-byte UF2 blocks")
    out = bytearray(b"\xff" * length)
    written_from = {}
    with path.open("rb") as stream:
        for off in range(0, size, 512):
            stream.seek(off)
            header = stream.read(32)
            stream.seek(off + 508)
            trailer = stream.read(4)
            if len(header) != 32 or len(trailer) != 4:
                raise SystemExit(f"{path}: truncated UF2 block at offset {off}")
            magic0, magic1 = struct.unpack_from("<II", header, 0)
            magic_end, = struct.unpack("<I", trailer)
            if magic0 != 0x0A324655 or magic1 != 0x9E5D5157:
                raise SystemExit(f"{path}: bad UF2 start magic at offset {off}")
            if magic_end != 0x0AB16F30:
                raise SystemExit(f"{path}: bad UF2 trailing magic at offset {off}")
            flags, = struct.unpack_from("<I", header, 8)
            # Checked independently of whether the payload bytes below happen
            # to look like a correct marker: a real UF2 bootloader skips any
            # block with "not main flash" set (never writes it to flash) and
            # treats "file container" blocks as a virtual filesystem entry, not
            # a flash write -- either flag would mean this verifier is reading
            # bytes that would never actually reach the device.
            if flags & UF2_FLAG_NOT_MAIN_FLASH:
                raise SystemExit(
                    f"{path}: block at offset {off} sets UF2 flag "
                    f"0x{UF2_FLAG_NOT_MAIN_FLASH:08X} (not main flash) -- a real UF2 "
                    "bootloader never writes this block to flash, so its payload "
                    "bytes cannot be trusted as what the device will actually hold"
                )
            if flags & UF2_FLAG_FILE_CONTAINER:
                raise SystemExit(
                    f"{path}: block at offset {off} sets UF2 flag "
                    f"0x{UF2_FLAG_FILE_CONTAINER:08X} (file container), not a flash "
                    "write"
                )
            if not (flags & UF2_FLAG_FAMILY_ID_PRESENT):
                raise SystemExit(
                    f"{path}: block at offset {off} does not set UF2 flag "
                    f"0x{UF2_FLAG_FAMILY_ID_PRESENT:08X} (familyID present) -- a "
                    "genuine artifact from this project's packaging step always "
                    "sets it"
                )
            target_addr, payload_size = struct.unpack_from("<II", header, 12)
            if payload_size > 476:
                raise SystemExit(
                    f"{path}: block at offset {off} declares payload_size "
                    f"{payload_size} > 476 (max for a 512-byte UF2 block)"
                )
            start = max(address, target_addr)
            stop = min(address + length, target_addr + payload_size)
            if start >= stop:
                continue
            stream.seek(off + 32 + start - target_addr)
            payload = stream.read(stop - start)
            if len(payload) != stop - start:
                raise SystemExit(f"{path}: truncated UF2 payload at offset {off}")
            for i, b in enumerate(payload):
                a = start + i
                rel = a - address
                if rel in written_from and out[rel] != b:
                    raise SystemExit(
                        f"{path}: conflicting bytes at address 0x{a:X}: block at "
                        f"offset {written_from[rel]} wrote 0x{out[rel]:02X}, block "
                        f"at offset {off} writes 0x{b:02X}"
                    )
                out[rel] = b
                written_from[rel] = off
    if not written_from:
        raise SystemExit(
            f"no UF2 block covered address range 0x{address:X}.."
            f"0x{address + length:X} in {path}"
        )
    return bytes(out)


def read_cf2_bootloader_id(path: Path) -> int:
    """Extract an artifact's public CF2 ID, reading only the requested UF2 payloads."""
    if path.suffix.lower() == ".uf2":
        raw = read_uf2_bytes(path, CF2_ADDRESS, CF2_BYTES)
    elif path.suffix.lower() == ".hex":
        raw = read_intel_hex_bytes(path, CF2_ADDRESS, CF2_BYTES)
    else:
        raise ValueError(f"unrecognized CF2 artifact extension: {path}")
    magic0, magic1, used, capacity = struct.unpack_from("<IIII", raw)
    if (magic0, magic1) != CF2_MAGIC:
        raise ValueError(f"invalid CF2 magic in {path}")
    if not 0 < used <= capacity <= (CF2_BYTES - 16) // 8:
        raise ValueError(f"invalid CF2 entry count/capacity in {path}")
    boot_ids = [value for key, value in struct.iter_unpack("<II", raw[16:16 + used * 8])
                if key == CF2_BOOTLOADER_BOARD_ID]
    if len(boot_ids) != 1:
        raise ValueError(f"CF2 must contain exactly one bootloader board ID in {path}")
    return boot_ids[0]


def parse_public_key_header(path: Path) -> bytes:
    """Independently parse the 32-byte public key literal straight out of
    the real #define block in the committed header text -- not a fixed
    character window (which could pick up unrelated 0xNN tokens from a
    neighbouring macro), and without importing/executing any Python module
    that also feeds prepare_upstream.py's patch step."""
    text = path.read_text()
    match = re.search(
        r"#define[ \t]+XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES[ \t]*\\\r?\n"
        r"((?:[^\n]*\\\r?\n)*[^\n]*)",
        text,
    )
    if not match:
        raise SystemExit(
            f"could not find a '#define XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES \\' "
            f"macro block in {path}"
        )
    values = re.findall(r"0x([0-9A-Fa-f]{2})", match.group(1))
    if len(values) != 32:
        raise SystemExit(
            f"expected exactly 32 public key bytes in {path}'s macro block, "
            f"found {len(values)}"
        )
    return bytes(int(v, 16) for v in values)


def check_artifact(artifact: Path, board: str, key_header: Path | None,
                   expected_role: int) -> list[str]:
    """Decode the boot-info marker out of a real .hex/.uf2 artifact and
    return a list of mismatch descriptions (empty list == pass).

    key_header is OPTIONAL and purely an opt-in build-provenance
    cross-check: if given, the artifact's reference_signer_public_key_ed25519
    is compared against that header's key as "did this specific build embed
    the static placeholder value I expected (include/xiao_ota_public_key.h,
    patched in by prepare_upstream.py)." If key_header is None, that check
    is skipped entirely (not an error, not a pass-by-default fallback) --
    there is no compiled/default key this tool requires or substitutes.
    This field is NEVER what the bootloader actually verifies install
    commands against at runtime (that is each command's own embedded
    admitted_signer_public_key_ed25519); a mismatch or absence here says
    nothing about whether a given signed update will be accepted on-device.
    """
    suffix = artifact.suffix.lower()
    if suffix == ".hex":
        raw = read_intel_hex_bytes(artifact, BOOT_INFO_ADDRESS, BOOT_INFO_STRUCT_BYTES)
    elif suffix == ".uf2":
        raw = read_uf2_bytes(artifact, BOOT_INFO_ADDRESS, BOOT_INFO_STRUCT_BYTES)
    else:
        raise SystemExit(f"unrecognized artifact extension: {artifact}")

    (magic, format_version, struct_bytes, board_target_id, role_id,
     capability_flags, key_id, algorithm_id, reference_signer_public_key,
     crc32_field) = struct.unpack(_LAYOUT, raw)

    errors = []
    if magic != BOOT_INFO_MAGIC:
        errors.append(f"magic 0x{magic:08X} != golden 0x{BOOT_INFO_MAGIC:08X}")
    if format_version != BOOT_INFO_FORMAT_VERSION:
        errors.append(f"format_version {format_version} != golden {BOOT_INFO_FORMAT_VERSION}")
    if struct_bytes != BOOT_INFO_STRUCT_BYTES:
        errors.append(f"struct_bytes {struct_bytes} != golden {BOOT_INFO_STRUCT_BYTES}")

    expected_target = BOARD_TARGET_VALUE[board]
    if board_target_id != expected_target:
        errors.append(
            f"board_target_id 0x{board_target_id:08X} != golden 0x{expected_target:08X} "
            f"for --board {board}"
        )
    if role_id != expected_role:
        errors.append(f"role_id {role_id} != expected {expected_role} (--role-id)")
    if capability_flags != CAP_QSPI_INSTALL:
        errors.append(f"capability_flags 0x{capability_flags:X} != golden 0x{CAP_QSPI_INSTALL:X}")
    if key_id != KEY_ID:
        errors.append(f"key_id {key_id} != golden {KEY_ID}")
    if algorithm_id != ALGORITHM_ED25519:
        errors.append(f"algorithm_id {algorithm_id} != golden {ALGORITHM_ED25519}")

    if key_header is not None:
        expected_key = parse_public_key_header(key_header)
        if reference_signer_public_key != expected_key:
            errors.append(
                f"reference_signer_public_key_ed25519 mismatch vs {key_header} "
                f"(artifact={reference_signer_public_key.hex()}, expected={expected_key.hex()}) "
                "-- this is an optional build-provenance cross-check only, "
                "NOT a runtime trust failure: install-command verification "
                "always uses that command's own embedded "
                "admitted_signer_public_key_ed25519, never this marker"
            )

    recomputed_crc = binascii.crc32(raw[:56]) & 0xFFFFFFFF
    if crc32_field != recomputed_crc:
        errors.append(
            f"crc32 field 0x{crc32_field:08X} != independently recomputed "
            f"0x{recomputed_crc:08X} over the artifact's own 56 pre-CRC bytes "
            "(prepare_upstream.py's CRC-placeholder patch step did not run, "
            "or ran against different bytes than what was actually compiled)"
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path,
                        help="packaged .hex or .uf2 file from a real build")
    parser.add_argument("--board", choices=sorted(BOARD_TARGET_VALUE),
                        required=True,
                        help="board profile the artifact was built for")
    parser.add_argument("--key-header", type=Path, default=None,
                        help="OPTIONAL build-provenance cross-check: path to "
                             "an xiao_ota_public_key.h to compare against "
                             "this artifact's reference_signer_public_key_ed25519. "
                             "Omit to skip the check entirely -- there is no "
                             "compiled/default key here, and this value is "
                             "never what the bootloader trusts at runtime "
                             "(that is per-command, see "
                             "admitted_signer_public_key_ed25519).")
    parser.add_argument("--role-id", type=int, choices=[0, 1], default=0,
                        help="compiled role identity (XIAO_OTA_COMPILED_ROLE_ID) "
                             "this artifact was built with: 0 (companion, "
                             "default) or 1 (repeater). Must match the "
                             "--role-id passed to prepare_upstream.py/"
                             "sign_image.py for this exact artifact.")
    args = parser.parse_args()

    errors = check_artifact(args.artifact, args.board, args.key_header, args.role_id)

    if errors:
        for e in errors:
            print(f"FAIL: {e}", file=sys.stderr)
        print(
            f"boot-info marker at 0x{BOOT_INFO_ADDRESS:X} in {args.artifact} "
            f"FAILED independent artifact verification ({len(errors)} issue(s))",
            file=sys.stderr,
        )
        return 1

    print(
        f"boot-info marker at 0x{BOOT_INFO_ADDRESS:X} in {args.artifact} "
        f"PASSED independent artifact verification for --board {args.board} "
        f"--role-id {args.role_id} "
        "(magic/format/size/CRC/target/role/cap all match golden values"
        + (
            "; reference_signer_public_key_ed25519 matched --key-header "
            f"{args.key_header})"
            if args.key_header is not None
            else "; reference_signer_public_key_ed25519 NOT checked, no "
                 "--key-header given)"
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
