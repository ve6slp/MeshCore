#!/usr/bin/env python3
"""Validate no-SWD artifacts; commission the approved target using vendor serial DFU."""

import argparse
import binascii
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_device  # noqa: E402
import verify_boot_info_artifact as boot_info  # noqa: E402
import prepare_upstream as preparation  # noqa: E402

BOARD_ID = "nRF52840-SeeedXiao-v1"
BOARD_IDS = {
    "xiao_nrf52840": (BOARD_ID,),
    "xiao_nrf52840_sense": (
        "Seeed_XIAO_nRF52840_Sense",
        "nRF52840-SeeedXiaoSense-v1",
    ),
}
USB_BOARD_IDS = {
    "xiao_nrf52840": 0x28860044,
    "xiao_nrf52840_sense": 0x28860045,
}
TARGET_SERIAL = "3BE94917B92DC5E9"
BOOT_START = 0xF4000
BOOT_STOP = 0xFDD00
BOOT_BYTES = BOOT_STOP - BOOT_START
DFU_TIMEOUT = 120
SERIAL_OUTPUT_LIMIT = 65536
SERIAL_LOG_ROOT = preparation.ROOT / ".tmp"
ADDRESS_EVIDENCE_MAX_AGE = 7200
APP_RESTORATION_WARNING = (
    "WARNING: vendor SINGLEBANK bootloader-only mode 0x02 prepares/erases "
    "bank0 at 0x27000..0x31000 BEFORE later init/CRC checks. "
    "Immutable 47b40e595ac876bbb5cfcad5406a1c7c343b9f74 APP restoration "
    "is mandatory even after DFU rejection, timeout or failure. "
    "No automatic APP restoration: ROOT must first observe BOOT/enumeration/"
    "version/proofs, then separately choose known APP recovery. "
    "Boot destination page erasure: 0xF4000..0xFE000; ordinary MBR parameters "
    "0xFE000 and SDK settings 0xFF000 can change. "
    "Neither protected ExtraFS 0xD4000..0xED000 nor InternalFS "
    "0xED000..0xF4000 is in this verified SINGLEBANK staging path. "
    "No --singlebank flag is used to select device banking. "
    "Exact installed Seeed stock-source lineage and physical power-failure "
    "behavior remain unverified."
)
UF2_COPY_REFUSAL = (
    "physical UF2 copying is forbidden: vendor self-update remaps the "
    "0xF4000..0xFDD00 payload to 0xE0000..0xE9D00, erasing pages "
    "0xE0000..0xEA000 inside protected ExtraFS; whitelisted UF2 output "
    "addresses do not constrain these indirect writes. Use the reviewed "
    "--route serial with a validated bootloader-only package."
)
UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
UF2_PAYLOAD_MAX_SIZE = 476
# The "self bootloader update" UF2 family ID this Makefile packages with
# (see .tmp/Adafruit_nRF52_Bootloader/Makefile UF2_FAMILY_ID_BOOTLOADER).
# It is NOT the generic NRF52840 application family ID (0xADA52840): a
# block claiming any other family here means this file was never actually
# produced by this project's bootloader packaging step.
UF2_FAMILY_ID_BOOTLOADER = 0xD663823C

# UF2 block flags (offset 8 in each 512-byte block; see
# https://github.com/microsoft/uf2#file-containers). Every block this
# project's packaging step actually emits sets exactly
# UF2_FLAG_FAMILY_ID_PRESENT and nothing else (confirmed against real
# packaged artifacts).
UF2_FLAG_NOT_MAIN_FLASH = 0x00000001
UF2_FLAG_FILE_CONTAINER = 0x00001000
UF2_FLAG_FAMILY_ID_PRESENT = 0x00002000

# Address ranges a genuine no-SWD bootloader-update UF2 is allowed to
# target, derived from (a) this target's documented flash layout and (b) a
# byte-exact read of a real packaged artifact
# (.tmp/xiao_nrf52840_ota_artifacts/custom-noswd/*_update.uf2): MBR/vector
# table, the 38KiB bootloader code region, the 2KiB bootloader-config slot
# (which holds the boot-info marker at 0xFDC00), and the two UICR words the
# bootloader reads at boot. Each tuple is a half-open [start, stop) byte
# range (stop is exclusive, never itself written). The UICR range below is
# [0x10001000, 0x10001100): its last WRITTEN byte is 0x100010FF, not
# 0x100011FF -- read this as "up to but not including 0x10001100", never as
# an inclusive endpoint.
#
# Deliberately EXCLUDED even though they sit between the bootloader and
# UICR ranges above: the MBR Params Page (0xFE000..0xFF000) and the
# Bootloader Settings page (0xFF000..0x100000, durable bank/CRC/size
# metadata only) -- an update artifact must never be able to overwrite
# either, and neither appears in a real packaged UF2. Also excluded: the
# application region and external QSPI addressing. This is ONLY an artifact
# payload whitelist: vendor UF2 self-update's indirect internal-flash staging
# overlaps protected ExtraFS. Physical UF2 copying is therefore forbidden.
PERMITTED_ADDRESS_RANGES = (
    (0x00000, 0x01000),        # MBR / vector table page
    (0xF4000, 0xFE000),        # bootloader code (38KiB) + bootloader config (2KiB)
    (0x10001000, 0x10001100),  # UICR words this bootloader reads: [.., ..) half-open, last byte 0x100010FF
)


def _address_range_permitted(target_addr, payload_size):
    if payload_size == 0:
        return False
    end = target_addr + payload_size  # exclusive
    for start, stop in PERMITTED_ADDRESS_RANGES:
        if target_addr >= start and end <= stop:
            return True
    return False


def usb_serial_ancestor(path):
    path = Path(path).resolve()
    for node in (path, *path.parents):
        serial_file = node / "serial"
        if serial_file.is_file():
            value = serial_file.read_text(encoding="utf-8").strip()
            if value:
                return value
    return None


def decode_mount_field(value):
    for encoded, decoded in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        value = value.replace(encoded, decoded)
    return value


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


def device_sysfs_link(device_path, root):
    stat_result = device_path.stat()
    return root / f"{os.major(stat_result.st_rdev)}:{os.minor(stat_result.st_rdev)}"


def matching_mounts(serial, mountinfo_path, sys_dev_block_root):
    matches = []
    for line in mountinfo_path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            continue
        major_minor = fields[2]
        mountpoint = Path(decode_mount_field(fields[4]))
        sysfs_link = sys_dev_block_root / major_minor
        if sysfs_link.exists() and usb_serial_ancestor(sysfs_link) == serial:
            matches.append(mountpoint)
    return matches


def board_id(mountpoint):
    info = mountpoint / "INFO_UF2.TXT"
    if not info.is_file():
        raise ValueError(f"mounted UF2 volume lacks INFO_UF2.TXT: {mountpoint}")
    ids = [line.split(":", 1)[1].strip()
           for line in info.read_text(encoding="utf-8").splitlines()
           if line.lower().startswith("board-id:")]
    if len(ids) != 1 or not ids[0]:
        raise ValueError(f"INFO_UF2.TXT requires exactly one nonblank Board-ID: {mountpoint}")
    return ids[0]


def authorized_serials():
    """Serials of boards declared in the lab inventory.

    Authorising against the inventory keeps this guard correct when boards are
    swapped, instead of pinning a literal serial that silently goes stale.
    """
    return set(lab_device.load_roles().values())


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


def validate_public_identity(args):
    board = getattr(args, "board", "xiao_nrf52840")
    key_header = getattr(args, "key_header", None)
    role_id = getattr(args, "role_id", 0)
    validate_artifact(args.artifact, board, key_header, role_id)

    if args.validate_only:
        print(f"VALIDATE-ONLY: artifact {args.artifact} passed all artifact checks")
        return

    # This is a read-only compatibility probe, never a UF2 volume copy.
    if board not in BOARD_IDS:
        raise ValueError(
            f"physical install is only authorized for board profile "
            f"{tuple(BOARD_IDS)} (the XIAO lab target); got {board!r} -- "
            "other board profiles may only be checked with --validate-only, "
            "never physically installed"
        )

    permitted = authorized_serials()
    if args.serial not in permitted:
        raise ValueError(
            f"serial {args.serial!r} is not a configured lab board; "
            f"authorized: {', '.join(sorted(permitted)) or '<none>'}"
        )

    boot_port = Path(args.boot_port)
    if boot_port.parent != Path(args.by_id_dir) or not boot_port.is_symlink():
        raise ValueError(
            f"boot port must be a stable authorized identity symlink in {args.by_id_dir}"
        )
    if not boot_port.exists():
        raise ValueError(f"stable bootloader identity is missing: {boot_port}")

    tty_link = device_sysfs_link(boot_port, Path(args.sys_dev_char_root))
    if not tty_link.exists():
        raise ValueError(f"no sysfs device ancestry for bootloader identity: {boot_port}")
    tty_serial = usb_serial_ancestor(tty_link)
    if tty_serial != args.serial:
        raise ValueError(
            f"bootloader USB ancestry serial is {tty_serial!r}, expected {args.serial!r}"
        )
    devices = [
        device for device in lab_device.discover()
        if device.serial == args.serial and device.by_id == boot_port
    ]
    if len(devices) != 1:
        raise ValueError(
            f"boot port is not a unique discovered Seeed stable authorized identity: {boot_port}"
        )
    if devices[0].mode != lab_device.MODE_BOOT:
        raise ValueError(
            f"authorized USB identity is in {devices[0].mode} mode, not bootloader mode"
        )
    usb = devices[0].sysfs
    usb_id = (int((usb / "idVendor").read_text().strip(), 16) << 16
              | int((usb / "idProduct").read_text().strip(), 16))
    if usb_id != USB_BOARD_IDS[board]:
        raise ValueError(f"bootloader USB VID/PID 0x{usb_id:08X} does not match "
                         f"{board} (0x{USB_BOARD_IDS[board]:08X})")
    if getattr(args, "route", None) == "serial" and not lab_device._has_msc_interface(devices[0]):
        raise ValueError("approved bootloader USB device lacks its own MSC class08 interface")

    volumes = matching_mounts(
        args.serial, Path(args.mountinfo), Path(args.sys_dev_block_root)
    )
    if len(volumes) != 1:
        raise ValueError(
            f"expected exactly one mounted UF2 volume for {args.serial}, found {len(volumes)}"
        )
    volume = volumes[0]
    if getattr(args, "route", None) == "serial":
        read_only = [
            fields for line in Path(args.mountinfo).read_text(encoding="utf-8").splitlines()
            if len(fields := line.split()) >= 10
            and Path(decode_mount_field(fields[4])) == volume
            and "ro" in fields[5].split(",")
        ]
        if len(read_only) != 1:
            raise ValueError("current target INFO probe requires exactly one read-only mounted volume")
    actual_board_id = board_id(volume)
    if actual_board_id not in BOARD_IDS[board]:
        raise ValueError(
            f"wrong UF2 board ID {actual_board_id!r}, expected {BOARD_IDS[board]!r}"
        )
    print(f"COMPATIBILITY: artifact CF2 0x{usb_id:08X} matches observed USB VID/PID "
          f"and exact UF2 Board-ID {actual_board_id!r}; "
          "current bootloader CF2 remains unverified (not read)")

    return boot_port, volume


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
            if names[name:].split(b"\0", 1)[0] == preparation.VERSION_SYMBOL.encode("ascii"):
                if shindex != 0xFFF1:
                    raise ValueError("compiled vendor version symbol is not absolute")
                symbols.append(value)
    if symbols != [preparation.BOOTLOADER_VERSION]:
        raise ValueError("compiled vendor version symbol is missing, duplicated or mismatched")
    if preparation.BOOTLOADER_VERSION <= 0x00000601:
        raise ValueError("compiled vendor version does not upgrade stock 0.6.1")
    return bytes(raw), symbols[0]


def serial_payload(args):
    if not getattr(args, "hex_artifact", None) or not getattr(args, "elf_artifact", None):
        raise ValueError("serial packaging/execution requires --hex-artifact and --elf-artifact")
    artifact = Path(args.artifact)
    raw = boot_info.read_uf2_bytes(artifact, BOOT_START, BOOT_BYTES)
    hex_raw = boot_info.read_intel_hex_bytes(Path(args.hex_artifact), BOOT_START, BOOT_BYTES)
    elf_raw, version = compiled_boot_span(args.elf_artifact)
    if raw != hex_raw or raw != elf_raw:
        raise ValueError("exact 40192-byte boot span differs between UF2, HEX and compiled ELF")
    stack, reset = struct.unpack_from("<II", raw)
    if not (0x20000000 < stack <= 0x20040000 and stack % 8 == 0
            and reset & 1 and BOOT_START <= (reset & ~1) < 0xFD800):
        raise ValueError("serial boot span lacks a valid bootloader vector")
    with artifact.open("rb") as stream:
        for block in iter(lambda: stream.read(512), b""):
            address, size = struct.unpack_from("<II", block, 12)
            for index, value in enumerate(block[32:32 + size]):
                if BOOT_STOP <= address + index < 0xFE000 and value != 0xFF:
                    raise ValueError("nonblank boot payload extends beyond reviewed 0xFDD00 span")
    return raw, version


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


def emit_serial_package(args, raw, version):
    output = Path(args.emit_serial_package).resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary, package = output / "bootloader.bin", output / "bootloader.zip"
    if binary.exists() or package.exists():
        raise ValueError("serial package output already exists; refusing to overwrite frozen artifacts")
    command = nrfutil_command(args) + [
        "dfu", "genpkg", "--bootloader", str(binary), "--application-version", str(version),
        "--dev-type", "0x0052", "--dev-revision", "52840", "--sd-req", "0x0123",
        "--dfu-ver", "0.5", str(package),
    ]
    with binary.open("xb") as stream:
        stream.write(raw)
    scratch = preparation.ROOT / ".tmp"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nrfutil-boot-package-", dir=scratch) as work:
        environment = dict(os.environ, TMPDIR=work)
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=DFU_TIMEOUT,
                                    env=environment)
        except subprocess.TimeoutExpired as error:
            raise ValueError("offline vendor nrfutil package generation timed out") from error
    if result.returncode != 0:
        raise ValueError(f"offline nrfutil package generation failed: {result.stdout}\n{result.stderr}")
    validate_serial_package(package, raw, version)
    print(f"PACKAGE-ONLY: {binary} ({BOOT_BYTES} bytes, SHA256 {hashlib.sha256(raw).hexdigest()}); "
          f"{package}; compiled vendor {preparation.PIN_RELEASE} (0x{version:08X}); "
          "UF2/HEX/ELF boot bytes identical; no device accessed")


def validate_address_evidence(path, serial):
    evidence = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_json_fields)
    if not isinstance(evidence, dict):
        raise ValueError("ROOT address evidence must be a JSON object")
    expected = dict(mbr8="FFFFFFFF", mbrc="FFFFFFFF", uicrb="000F4000",
                    uicrp="000FE000", boot="000F4000", params="000FE000")
    if (evidence.get("serial") != serial or type(evidence.get("role_id")) is not int
            or evidence["role_id"] != 1 or any(evidence.get(key) != value
                                              for key, value in expected.items())):
        raise ValueError("ROOT address evidence serial/role/raw/effective address tuple mismatch")
    observed = evidence.get("observed_at")
    if not isinstance(observed, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", observed):
        raise ValueError("ROOT address evidence requires observed_at in UTC ending Z")
    observed_at = datetime.fromisoformat(observed[:-1] + "+00:00")
    age = (datetime.now(timezone.utc) - observed_at).total_seconds()
    if not 0 <= age <= ADDRESS_EVIDENCE_MAX_AGE:
        raise ValueError("ROOT address evidence is future-dated or older than two hours")


def validate_stock_info(volume):
    info = (volume / "INFO_UF2.TXT").read_text(encoding="utf-8").splitlines()
    bootloader = [line for line in info if line.lstrip().startswith("UF2 Bootloader")]
    softdevice = [line for line in info if line.lstrip().startswith("SoftDevice:")]
    if (len(bootloader) != 1 or not re.fullmatch(
            r"UF2 Bootloader 0\.6\.1"
            r"(?: lib/nrfx \([^()\s]+\) lib/tinyusb \([^()\s]+\) lib/uf2 \([^()\s]+\))?",
            bootloader[0])
            or softdevice != ["SoftDevice: S140 version 7.3.0"]):
        raise ValueError("current INFO must prove stock bootloader 0.6.1 and S140 7.3.0")


def run_vendor_serial(command, environment):
    """Bound both output streams and retain diagnostics independently of the package snapshot."""
    logs = Path(tempfile.mkdtemp(prefix="nrfutil-serial-logs-", dir=SERIAL_LOG_ROOT))
    paths = {"stdout": logs / "stdout.log", "stderr": logs / "stderr.log"}
    failure = None
    process = None
    deadline = time.monotonic() + DFU_TIMEOUT
    with paths["stdout"].open("xb") as stdout_log, paths["stderr"].open("xb") as stderr_log:
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=environment)
            with selectors.DefaultSelector() as selector:
                for stream, name, log in ((process.stdout, "stdout", stdout_log),
                                          (process.stderr, "stderr", stderr_log)):
                    selector.register(stream, selectors.EVENT_READ, (name, log))
                counts = dict(stdout=0, stderr=0)
                while selector.get_map() and failure is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        failure = "timed out"
                        break
                    for key, _ in selector.select(timeout=remaining):
                        name, log = key.data
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        available = SERIAL_OUTPUT_LIMIT - counts[name]
                        log.write(chunk[:available])
                        counts[name] += min(len(chunk), available)
                        if len(chunk) > available:
                            failure = f"{name} exceeded the {SERIAL_OUTPUT_LIMIT}-byte output limit"
                            break
                if failure is None:
                    try:
                        process.wait(timeout=max(0, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        failure = "timed out"
        except OSError as error:
            failure = f"could not run or capture output: {error}"
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    failure = f"could not reap vendor process PID {process.pid} after stopping it"
                for stream in (process.stdout, process.stderr):
                    stream.close()
    stdout = paths["stdout"].read_bytes()
    stderr = paths["stderr"].read_bytes()
    if failure is None and (
            process.returncode != 0 or b"Device programmed." not in stdout.splitlines()
            or re.search(rb"(?im)failed to upgrade target|traceback|error|exception|^\s*false\s*$",
                         stdout + b"\n" + stderr)):
        failure = f"did not prove transport completion (exit {process.returncode})"
    print(f"VENDOR LOGS: stdout={paths['stdout']} stderr={paths['stderr']}", flush=True)
    if failure is not None:
        raise ValueError(
            f"vendor serial DFU {failure}; bounded logs preserved: "
            f"{paths['stdout']} and {paths['stderr']}. "
            "No automatic APP restoration. ROOT must first observe BOOT/enumeration/"
            "version/proofs before separate known APP recovery; APP restoration remains mandatory."
        )


def install(args):
    board = getattr(args, "board", "xiao_nrf52840")
    role_id = getattr(args, "role_id", 0)
    validate_artifact(args.artifact, board, getattr(args, "key_header", None), role_id)
    if args.validate_only:
        print(f"VALIDATE-ONLY: artifact {args.artifact} passed all artifact checks")
        return
    if getattr(args, "emit_serial_package", None):
        raw, version = serial_payload(args)
        emit_serial_package(args, raw, version)
        return
    if getattr(args, "route", "uf2") != "serial":
        raise ValueError(UF2_COPY_REFUSAL)
    if board != "xiao_nrf52840_sense" or role_id != 1:
        raise ValueError("physical serial commissioning requires the Sense profile and explicit role 1")
    if args.serial != TARGET_SERIAL or lab_device.load_roles().get("target") != TARGET_SERIAL:
        raise ValueError("serial commissioning is restricted to the approved inventory target")
    if not getattr(args, "package", None) or not getattr(args, "address_evidence", None):
        raise ValueError("serial commissioning requires --package and fresh --address-evidence")
    raw, version = serial_payload(args)
    with Path(args.package).open("rb") as stream:
        package_bytes = stream.read(65537)
    if len(package_bytes) > 65536:
        raise ValueError("bootloader-only serial package exceeds the bounded 64KiB ZIP size")
    validate_serial_package(io.BytesIO(package_bytes), raw, version)
    validate_address_evidence(args.address_evidence, args.serial)
    command = nrfutil_command(args) + [
        "dfu", "serial", "--package", str(Path(args.package).resolve()),
        "--port", str(Path(args.boot_port)), "--baudrate", "115200",
    ]
    boot_port, volume = validate_public_identity(args)
    validate_stock_info(volume)
    try:
        with tempfile.TemporaryDirectory(prefix="nrfutil-boot-serial-", dir=preparation.ROOT / ".tmp") as work:
            snapshot = Path(work) / "bootloader.zip"
            with snapshot.open("xb") as stream:
                stream.write(package_bytes)
            command[5] = str(snapshot)
            print(APP_RESTORATION_WARNING, flush=True)
            print(f"Boot-only bytes {BOOT_BYTES}, device 0x0052/rev52840/SDreq0x0123, "
                  f"CRC16 0x{binascii.crc_hqx(raw, 0xFFFF):04X}, compiled version 0x{version:08X}; "
                  f"staging writes 0x27000..0x30D00; command: {shlex.join(command)}", flush=True)
            if args.dry_run:
                print("DRY RUN: all package/public-identity/address guards passed; no port opened or DFU invoked")
                return
            # Transfer only the validated snapshot; recheck the live gate before opening a port.
            final_port, final_volume = validate_public_identity(args)
            if final_port != boot_port or final_volume != volume:
                raise ValueError("stable bootloader identity changed before serial DFU")
            validate_stock_info(final_volume)
            validate_address_evidence(args.address_evidence, args.serial)
            run_vendor_serial(command, dict(os.environ, TMPDIR=work))
    except OSError as error:
        raise ValueError(f"vendor serial DFU could not run; APP restoration remains mandatory: {error}") from error
    print("Vendor SERIAL DFU transport reported completion ONLY; loader activation/genesis "
          "not verified. No automatic APP restoration. ROOT must observe BOOT/enumeration/"
          "version/proofs before separate immutable 47APP recovery, then read back healthy "
          "image/SDK, unchanged configuration/identity and PRESENT valid floor0 with unknown image hash.")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=False)
    parser.add_argument("--boot-port", required=False)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--route", choices=("uf2", "serial"), default="uf2",
                        help="physical UF2 copying is forbidden; serial is explicit and target-only")
    parser.add_argument("--hex-artifact", type=Path)
    parser.add_argument("--elf-artifact", type=Path)
    parser.add_argument("--emit-serial-package", type=Path,
                        help="offline bootloader.bin/bootloader.zip output directory; no device access")
    parser.add_argument("--package", type=Path)
    parser.add_argument("--address-evidence", type=Path,
                        help="ROOT JSON: serial, role_id=1, observed_at UTC Z within two hours, "
                             "and mbr8/mbrc/uicrb/uicrp/boot/params as uppercase eight-digit hex")
    parser.add_argument("--nrfutil", type=Path,
                        default=Path.home() / ".platformio/packages/tool-adafruit-nrfutil/adafruit-nrfutil.py")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--validate-only", action="store_true",
        help="only run artifact checks (UF2 structure/whitelist, boot-info "
             "marker/family/role/key and profile CF2 ID); no serial, port, or mounted-device "
             "resolution is performed or required",
    )
    parser.add_argument("--board", choices=sorted(boot_info.BOARD_TARGET_VALUE),
                        default="xiao_nrf52840",
                        help="board profile the artifact marker/CF2 and observed USB/Board-ID "
                             "must match; current bootloader CF2 is not read or verified")
    parser.add_argument("--role-id", type=int, choices=[0, 1], default=0,
                        help="compiled role identity (XIAO_OTA_COMPILED_ROLE_ID) "
                             "the artifact's boot-info marker must match: 0 "
                             "(companion, default) or 1 (repeater)")
    parser.add_argument(
        "--key-header", type=Path, default=None,
        help="OPTIONAL: public key header to cross-check against the "
             "artifact's boot-info marker reference_signer_public_key_ed25519 "
             "field (a build-provenance check only). Omit to skip the check "
             "entirely -- there is no compiled/default key here, and this "
             "is never the bootloader's actual install-command trust key "
             "(that key is read per-command from "
             "admitted_signer_public_key_ed25519)",
    )
    parser.add_argument("--by-id-dir", default="/dev/serial/by-id")
    parser.add_argument("--mountinfo", default="/proc/self/mountinfo")
    parser.add_argument("--sys-dev-char-root", default="/sys/dev/char")
    parser.add_argument("--sys-dev-block-root", default="/sys/dev/block")
    args = parser.parse_args()
    if args.validate_only and args.emit_serial_package:
        parser.error("--validate-only and --emit-serial-package are mutually exclusive")
    if args.emit_serial_package and args.dry_run:
        parser.error("--emit-serial-package already has no hardware access; do not combine with --dry-run")
    if not args.validate_only and not args.emit_serial_package and (not args.serial or not args.boot_port):
        parser.error("--serial and --boot-port are required unless validating or packaging offline")
    return args


def main():
    try:
        install(parse_args())
    except (OSError, ValueError) as error:
        raise SystemExit(f"refusing bootloader install: {error}")


if __name__ == "__main__":
    main()
