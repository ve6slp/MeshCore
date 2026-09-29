#!/usr/bin/env python3
"""Guarded installer for the XIAO no-SWD bootloader-update UF2."""

import argparse
import os
from pathlib import Path
import shutil
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
import lab_device  # noqa: E402

BOARD_ID = "nRF52840-SeeedXiao-v1"
UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30


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
            block_number, block_count = struct.unpack_from("<II", block, 20)
            end_magic = struct.unpack_from("<I", block, 508)[0]
            if (start0, start1, end_magic) != (
                UF2_MAGIC_START0,
                UF2_MAGIC_START1,
                UF2_MAGIC_END,
            ):
                raise ValueError(f"invalid UF2 magic in block {index}")
            if block_count != expected_blocks or block_number >= block_count:
                raise ValueError(f"invalid UF2 block numbering in block {index}")
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


def install(args):
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
    validate_uf2(artifact)
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
    parser.add_argument("--serial", required=True)
    parser.add_argument("--boot-port", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--by-id-dir", default="/dev/serial/by-id")
    parser.add_argument("--mountinfo", default="/proc/self/mountinfo")
    parser.add_argument("--sys-dev-char-root", default="/sys/dev/char")
    parser.add_argument("--sys-dev-block-root", default="/sys/dev/block")
    return parser.parse_args()


def main():
    try:
        install(parse_args())
    except (OSError, ValueError) as error:
        raise SystemExit(f"refusing bootloader install: {error}")


if __name__ == "__main__":
    main()
