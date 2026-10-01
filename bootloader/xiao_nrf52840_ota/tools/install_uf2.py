#!/usr/bin/env python3
"""Guarded installer for the XIAO no-SWD bootloader-update UF2."""

import argparse
import os
from pathlib import Path
import shutil
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_device  # noqa: E402
import verify_boot_info_artifact as boot_info  # noqa: E402

BOARD_ID = "nRF52840-SeeedXiao-v1"
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
# application image region (0x27000..0xED000) and any external-flash
# addressing -- a UF2 targets only the internal-flash address space, so it
# can never reach the anti-rollback floor/command-record journal or
# ExtraFS at all (both live on the separate EXTERNAL QSPI chip, addressed
# 0x18C000..0x194000 and 0x194000.. respectively, a distinct address space
# from every internal-flash range above/below) -- but any block claiming
# to target the application region must still always be rejected.
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
                    "(this never touches the application image, ExtraFS, or the "
                    "durable bootloader settings page)"
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
    for line in info.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.lower().startswith("board-id:"):
            return line.split(":", 1)[1].strip()
    raise ValueError(f"INFO_UF2.TXT lacks Board-ID: {mountpoint}")


def authorized_serials():
    """Serials of boards declared in the lab inventory.

    Authorising against the inventory keeps this guard correct when boards are
    swapped, instead of pinning a literal serial that silently goes stale.
    """
    return set(lab_device.load_roles().values())


def validate_artifact(artifact_path, board, key_header, role_id=0):
    """Artifact-only checks: UF2 structure/whitelist plus the boot-info
    marker/board/key/role. Runs with no serial, port, or mounted-device
    resolution -- callable standalone (e.g. in CI, before any board is
    connected) via --validate-only.
    """
    artifact = Path(artifact_path)
    validate_uf2(artifact)
    marker_errors = boot_info.check_artifact(artifact, board, Path(key_header), role_id)
    if marker_errors:
        raise ValueError(
            "boot-info marker in artifact failed independent verification: "
            + "; ".join(marker_errors)
        )


def install(args):
    board = getattr(args, "board", "xiao_nrf52840")
    key_header = getattr(
        args, "key_header",
        Path(__file__).resolve().parents[1] / "include/xiao_ota_public_key.h",
    )
    role_id = getattr(args, "role_id", 0)
    validate_artifact(args.artifact, board, key_header, role_id)

    if args.validate_only:
        print(f"VALIDATE-ONLY: artifact {args.artifact} passed all artifact checks")
        return

    # Physical installs are authorized for the XIAO lab board only: the
    # mounted UF2 volume and lab inventory below are always for a real XIAO
    # (BOARD_ID check further down), so a --board sensecap_solar_p1 artifact
    # (even one whose own boot-info marker validates correctly for that
    # profile) must never reach volume-copy against it. SenseCAP artifacts
    # may only ever be checked with --validate-only.
    if board != "xiao_nrf52840":
        raise ValueError(
            f"physical install is only authorized for board profile "
            f"'xiao_nrf52840' (the XIAO lab target); got {board!r} -- "
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
    expected_name = f"usb-Seeed_Studio_XIAO-BOOT_{args.serial}-if00"
    if boot_port.parent != Path(args.by_id_dir) or boot_port.name != expected_name:
        raise ValueError(
            f"boot port must be the stable authorized identity {Path(args.by_id_dir) / expected_name}"
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

    artifact = Path(args.artifact)
    volumes = matching_mounts(
        args.serial, Path(args.mountinfo), Path(args.sys_dev_block_root)
    )
    if len(volumes) != 1:
        raise ValueError(
            f"expected exactly one mounted UF2 volume for {args.serial}, found {len(volumes)}"
        )
    volume = volumes[0]
    actual_board_id = board_id(volume)
    if actual_board_id != BOARD_ID:
        raise ValueError(
            f"wrong UF2 board ID {actual_board_id!r}, expected {BOARD_ID!r}"
        )

    destination = volume / artifact.name
    if args.dry_run:
        print(f"DRY RUN: validated {boot_port} and {volume}; would copy {artifact} to {destination}")
        return

    with artifact.open("rb") as source, destination.open("xb") as target:
        shutil.copyfileobj(source, target)
        target.flush()
        os.fsync(target.fileno())
    os.sync()
    print(f"installed {artifact} on authorized XIAO {args.serial} via {volume}")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=False)
    parser.add_argument("--boot-port", required=False)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--validate-only", action="store_true",
        help="only run artifact checks (UF2 structure/whitelist, boot-info "
             "marker/board/key); no serial, port, or mounted-device "
             "resolution is performed or required",
    )
    parser.add_argument("--board", choices=sorted(boot_info.BOARD_TARGET_VALUE),
                        default="xiao_nrf52840",
                        help="board profile the artifact's boot-info marker must match")
    parser.add_argument("--role-id", type=int, choices=[0, 1], default=0,
                        help="compiled role identity (XIAO_OTA_COMPILED_ROLE_ID) "
                             "the artifact's boot-info marker must match: 0 "
                             "(companion, default) or 1 (repeater)")
    parser.add_argument(
        "--key-header", type=Path,
        default=Path(__file__).resolve().parents[1] / "include/xiao_ota_public_key.h",
        help="public key header the artifact's trusted_public_key field must match",
    )
    parser.add_argument("--by-id-dir", default="/dev/serial/by-id")
    parser.add_argument("--mountinfo", default="/proc/self/mountinfo")
    parser.add_argument("--sys-dev-char-root", default="/sys/dev/char")
    parser.add_argument("--sys-dev-block-root", default="/sys/dev/block")
    args = parser.parse_args()
    if not args.validate_only and (not args.serial or not args.boot_port):
        parser.error("--serial and --boot-port are required unless --validate-only is given")
    return args


def main():
    try:
        install(parse_args())
    except (OSError, ValueError) as error:
        raise SystemExit(f"refusing bootloader install: {error}")


if __name__ == "__main__":
    main()
