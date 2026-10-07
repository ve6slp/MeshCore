#!/usr/bin/env python3
"""Offline bootloader artifact validation. Never discovers, opens or flashes a device.

Bootloader UF2 self-update indirectly erases protected ExtraFS. Validation of
output addresses is not permission to copy an update UF2 to a physical board.
Use the paired bootstrap's standard serial DFU packages and recovery recipe.
"""
import argparse
import binascii
import json
from pathlib import Path
import struct
import sys
import zipfile

import verify_boot_info_artifact as boot_info

BOOT_START = 0xF4000
BOOT_STOP = 0xFDD00
BOOT_BYTES = BOOT_STOP - BOOT_START
DFU_TIMEOUT = 120
BOOTLOADER_VERSION = 0x902
VERSION_SYMBOL = "__meshcore_vendor_bootloader_version"
USB_BOARD_IDS = {"xiao_nrf52840": 0x28860044, "xiao_nrf52840_sense": 0x28860045}
UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
UF2_PAYLOAD_MAX_SIZE = 476
UF2_FAMILY_ID_BOOTLOADER = 0xD663823C
UF2_FLAG_NOT_MAIN_FLASH = 1
UF2_FLAG_FILE_CONTAINER = 0x1000
UF2_FLAG_FAMILY_ID_PRESENT = 0x2000
PERMITTED_ADDRESS_RANGES = ((0, 0x1000), (0xF4000, 0xFE000), (0x10001000, 0x10001100))

def _address_range_permitted(target_addr, payload_size):
    if payload_size == 0:
        return False
    end = target_addr + payload_size  # exclusive
    for start, stop in PERMITTED_ADDRESS_RANGES:
        if target_addr >= start and end <= stop:
            return True
    return False

def validate_uf2(path):
    if not path.is_file():
        raise ValueError(f"missing bootloader artifact: {path}")
    size = path.stat().st_size
    if size == 0 or size % 512:
        raise ValueError(f"invalid UF2 size: {size}")

    expected_blocks = size // 512
    seen = set()
    with path.open("rb") as stream:
        for index in range(expected_blocks):
            block = stream.read(512)
            start0, start1 = struct.unpack_from("<II", block, 0)
            flags = struct.unpack_from("<I", block, 8)[0]
            target_addr, payload_size = struct.unpack_from("<II", block, 12)
            block_number, block_count = struct.unpack_from("<II", block, 20)
            family_id = struct.unpack_from("<I", block, 28)[0]
            end_magic = struct.unpack_from("<I", block, 508)[0]
            if (start0, start1, end_magic) != (
                UF2_MAGIC_START0,
                UF2_MAGIC_START1,
                UF2_MAGIC_END,
            ):
                raise ValueError(f"invalid UF2 magic in block {index}")
            if block_count != expected_blocks or block_number >= block_count:
                raise ValueError(f"invalid UF2 block numbering in block {index}")
            # A crafted file can change only this flags word and leave the
            # address map, marker bytes, and every other field looking
            # exactly like a genuine artifact, while a real UF2 bootloader
            # silently skips writing that block to flash (or treats it as
            # a virtual-filesystem file container, not a flash write at
            # all) -- so these bits must be checked independently of the
            # address/family/marker comparisons below, never inferred from
            # them passing.
            if flags & UF2_FLAG_NOT_MAIN_FLASH:
                raise ValueError(
                    f"block {index} sets UF2 flag 0x{UF2_FLAG_NOT_MAIN_FLASH:08X} "
                    "(not main flash) -- a real UF2 bootloader skips writing this "
                    "block to flash entirely, so this artifact would not actually "
                    "program what its address map/marker appear to promise"
                )
            if flags & UF2_FLAG_FILE_CONTAINER:
                raise ValueError(
                    f"block {index} sets UF2 flag 0x{UF2_FLAG_FILE_CONTAINER:08X} "
                    "(file container) -- this artifact must be a flat flash image, "
                    "never a virtual-filesystem file container block"
                )
            if not (flags & UF2_FLAG_FAMILY_ID_PRESENT):
                raise ValueError(
                    f"block {index} does not set UF2 flag "
                    f"0x{UF2_FLAG_FAMILY_ID_PRESENT:08X} (familyID present) -- "
                    "without it, offset 28 is a fileSize, not a family ID, which "
                    "would make the family_id check below meaningless"
                )
            if family_id != UF2_FAMILY_ID_BOOTLOADER:
                raise ValueError(
                    f"block {index} declares family_id 0x{family_id:08X}, "
                    f"expected the bootloader-update family 0x{UF2_FAMILY_ID_BOOTLOADER:08X}"
                )
            if payload_size == 0 or payload_size > UF2_PAYLOAD_MAX_SIZE:
                raise ValueError(
                    f"block {index} declares payload_size {payload_size}, "
                    f"expected 1..{UF2_PAYLOAD_MAX_SIZE}"
                )
            if not _address_range_permitted(target_addr, payload_size):
                raise ValueError(
                    f"block {index} targets 0x{target_addr:X}..0x{target_addr + payload_size:X}, "
                    "which is outside the permitted bootloader/config/UICR ranges "
                    "(payload targets must exclude the application and settings)"
                )
            seen.add(block_number)
    if seen != set(range(expected_blocks)):
        raise ValueError("UF2 block sequence is incomplete or duplicated")

def validate_artifact(artifact_path, board, key_header, role_id=0):
    """Artifact-only checks: UF2 structure/whitelist plus the boot-info
    marker/family/role/capability and profile-specific CF2 bootloader board ID.
    Runs with no serial, port, or mounted-device
    resolution -- callable standalone (e.g. in CI, before any board is
    connected) via --validate-only.

    key_header is OPTIONAL (may be None): see
    verify_boot_info_artifact.check_artifact() -- it is only an opt-in
    build-provenance cross-check of the marker's
    reference_signer_public_key_ed25519, never a runtime trust requirement
    and never defaulted to a compiled key here.
    """
    if board not in boot_info.BOARD_TARGET_VALUE:
        raise ValueError(f"unknown bootloader board profile: {board!r}")
    artifact = Path(artifact_path)
    validate_uf2(artifact)
    marker_errors = boot_info.check_artifact(
        artifact, board, Path(key_header) if key_header is not None else None, role_id)
    if marker_errors:
        raise ValueError(
            "boot-info marker in artifact failed independent verification: "
            + "; ".join(marker_errors)
        )
    if board in USB_BOARD_IDS:
        actual_id = boot_info.read_cf2_bootloader_id(artifact)
        expected_id = USB_BOARD_IDS[board]
        if actual_id != expected_id:
            raise ValueError(f"artifact CF2 bootloader board ID 0x{actual_id:08X} "
                             f"does not match {board} (0x{expected_id:08X})")

def compiled_boot_span(elf_path):
    """Read the ARM ELF load bytes and the build-only absolute version symbol."""
    data = Path(elf_path).read_bytes()
    if len(data) < 52 or data[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("expected a little-endian ELF32 compiled bootloader")
    header = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
    kind, machine, version, _, phoff, shoff, _, ehsize, phsize, phcount, shsize, shcount, _ = header
    if (kind, machine, version, ehsize, phsize, shsize) != (2, 40, 1, 52, 32, 40):
        raise ValueError("expected an executable ARM ELF32 with standard headers")

    def bounded(offset, length):
        if offset < 0 or length < 0 or offset + length > len(data):
            raise ValueError("compiled ELF contains an out-of-bounds table or segment")
        return data[offset:offset + length]

    bounded(phoff, phsize * phcount)
    bounded(shoff, shsize * shcount)
    raw = bytearray(b"\xff" * BOOT_BYTES)
    seen = {}
    loads = []
    for index in range(phcount):
        ptype, offset, vaddr, address, size, memsize, _, _ = struct.unpack_from(
            "<8I", data, phoff + index * phsize)
        if ptype != 1:
            continue
        bounded(offset, size)
        if size > memsize:
            raise ValueError("compiled ELF load file size exceeds its memory size")
        loads.append((offset, vaddr, address, size, memsize))
    sections = [struct.unpack_from("<10I", data, shoff + index * shsize)
                for index in range(shcount)]
    # PT_LOAD includes ELF/header/alignment padding, which objcopy does not
    # emit. Use file-backed allocated sections, mapping RAM .data to its LMA.
    for section in sections:
        _, stype, flags, vaddr, offset, size, _, _, _, _ = section
        if not flags & 2 or stype == 8 or not size:  # SHF_ALLOC / SHT_NOBITS
            continue
        addresses = [
            paddr + vaddr - p_vaddr for p_offset, p_vaddr, paddr, p_size, p_memsize in loads
            if p_offset <= offset and offset + size <= p_offset + p_size
            and p_vaddr <= vaddr and vaddr + size <= p_vaddr + p_memsize
            and offset - p_offset == vaddr - p_vaddr
        ]
        if len(addresses) != 1:
            raise ValueError("compiled ELF allocated section lacks a unique load address")
        address = addresses[0]
        if BOOT_START <= address < 0xFD800 and address + size > 0xFD800:
            raise ValueError("compiled code or .data LMA exceeds the 38912-byte no-SWD slot")
        payload = bounded(offset, size)
        for pos in range(max(address, BOOT_START), min(address + size, BOOT_STOP)):
            value = payload[pos - address]
            if pos in seen and seen[pos] != value:
                raise ValueError("compiled ELF has conflicting boot load bytes")
            seen[pos] = value
            raw[pos - BOOT_START] = value
    symbols = []
    for section in sections:
        if section[1] != 2:  # SHT_SYMTAB
            continue
        if section[9] != 16 or section[5] % 16 or section[6] >= shcount:
            raise ValueError("compiled ELF has an invalid symbol table")
        strings = sections[section[6]]
        if strings[1] != 3:
            raise ValueError("compiled ELF symbol names require SHT_STRTAB")
        names = bounded(strings[4], strings[5])
        table = bounded(section[4], section[5])
        for offset in range(0, len(table), 16):
            name, value, _, _, _, shindex = struct.unpack_from("<IIIBBH", table, offset)
            if name >= len(names) or b"\0" not in names[name:]:
                raise ValueError("compiled ELF has an invalid symbol name")
            if names[name:].split(b"\0", 1)[0] == VERSION_SYMBOL.encode("ascii"):
                if shindex != 0xFFF1:
                    raise ValueError("compiled vendor version symbol is not absolute")
                symbols.append(value)
    if symbols != [BOOTLOADER_VERSION]:
        raise ValueError("compiled vendor version symbol is missing, duplicated or mismatched")
    if BOOTLOADER_VERSION <= 0x00000601:
        raise ValueError("compiled vendor version does not upgrade stock 0.6.1")
    return bytes(raw), symbols[0]

def validate_serial_package(package_path, raw, version):
    expected_init = struct.pack("<HHIHHH", 0x0052, 52840, version, 1, 0x0123,
                                binascii.crc_hqx(raw, 0xFFFF))
    try:
        with zipfile.ZipFile(package_path) as archive:
            members = archive.infolist()
            sizes = {"bootloader.bin": BOOT_BYTES, "bootloader.dat": 14}
            if len(members) != 3 or {entry.filename for entry in members} != {
                    "manifest.json", *sizes}:
                raise ValueError("serial package must contain exactly one bootloader image and manifest")
            for entry in members:
                limit = 4096 if entry.filename == "manifest.json" else sizes[entry.filename]
                if (entry.flag_bits & 1 or entry.file_size > limit
                        or entry.filename in sizes and entry.file_size != limit):
                    raise ValueError("serial package has encrypted or incorrectly sized members")
            expected = {
                "manifest": {
                    "dfu_version": 0.5,
                    "bootloader": {
                        "bin_file": "bootloader.bin", "dat_file": "bootloader.dat",
                        "init_packet_data": {
                            "application_version": version, "device_type": 0x0052,
                            "device_revision": 52840, "softdevice_req": [0x0123],
                            "firmware_crc16": binascii.crc_hqx(raw, 0xFFFF),
                        },
                    },
                },
            }
            manifest = json.loads(archive.read("manifest.json"), object_pairs_hook=unique_json_fields)
            if manifest != expected:
                raise ValueError("serial package manifest is not exact legacy v0.5 bootloader-only schema")
            if any(type(value) is not int for key, value in
                   manifest["manifest"]["bootloader"]["init_packet_data"].items()
                   if key != "softdevice_req"):
                raise ValueError("serial package init fields must be integer values")
            if archive.read("bootloader.bin") != raw:
                raise ValueError("serial package bootloader differs from validated raw artifact")
            if archive.read("bootloader.dat") != expected_init:
                raise ValueError("serial package init packet CRC/version/device/SoftDevice mismatch")
    except zipfile.BadZipFile as error:
        raise ValueError(f"invalid serial package ZIP: {error}") from error

def nrfutil_command(args):
    tool = Path(args.nrfutil).resolve()
    if not tool.is_file():
        raise ValueError(f"existing vendor nrfutil tool is missing: {tool}")
    return [sys.executable, str(tool)]

def unique_json_fields(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"ambiguous duplicate JSON field: {name}")
        result[name] = value
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--board", choices=tuple(boot_info.BOARD_TARGET_VALUE), required=True)
    parser.add_argument("--role-id", type=int, choices=(0, 1), required=True)
    parser.add_argument("--key-header", type=Path)
    args = parser.parse_args()
    validate_artifact(args.artifact, args.board, args.key_header, args.role_id)
    print("Artifact valid; no device accessed. Physical bootloader UF2 copying is unsafe.")

if __name__ == "__main__":
    main()
