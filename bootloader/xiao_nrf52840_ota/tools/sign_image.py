#!/usr/bin/env python3
"""Create candidate and durable command records from a raw application image."""

import argparse
import binascii
import hashlib
from pathlib import Path
import secrets
import struct
import subprocess

MAGIC = 0x584F5441
COMMIT = 0x434F4D54
# Must stay byte-for-byte identical to the same-named constants in
# bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h -- these are what
# the compiled bootloader's install-command policy check actually enforces
# per --board (see tools/prepare_upstream.py's matching BOARD_TARGET_VALUE
# table and its cross-check against xiao_ota_record.h).
BOARD_TARGETS = {
    "xiao_nrf52840": 0x584E3430,
    # A real, distinct target id sharing the same P25Q16H QSPI pinout family
    # as the XIAO profile, but NOT physically qualified on hardware -- any
    # descriptor signed with this profile is build-only until a real board
    # confirms it works.
    "sensecap_solar_p1": 0x53435031,
}
CAP_QSPI_INSTALL = 1
APP_START = 0x27000
# Full internal app-region extent (0x27000..0xED000): safe as a BACKUP/
# active-image reference size (see xiao_ota_boot.c's
# active_extent_from_settings() -- backing up this many bytes is just a
# protective read+copy of whatever is really there, filesystem included).
BACKUP_MAX_SIZE = 0xC6000
# Candidate/install cap (0x27000..0xD4000 = 708,608 bytes): v1.17's actual
# code region, distinct from and smaller than BACKUP_MAX_SIZE.
# 0xD4000..0xED000 is where v1.17's own internal filesystem (LittleFS/
# ExtraFS) lives today; a signed candidate up to the full BACKUP_MAX_SIZE
# would let an otherwise-legitimate install erase/overwrite into that
# region, since nothing else in the wire contract enforces a smaller
# bound. This is a safety cap, not a new wire-format field: no schema,
# role/target/format-signature change. Do not raise this until an
# explicit filesystem-relocation migration proves the FS no longer lives
# in 0xD4000..0xED000; no such migration-complete signal exists yet.
INSTALL_MAX_SIZE = 0xAD000
COMMAND_VERSION_LEGACY_V1 = 1
COMMAND_VERSION_WIRE_V2 = 2
WIRE_DESCRIPTOR_SIZE = 59


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--active-image", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--counter", required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--device-address", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--role-id", type=lambda x: int(x, 0), default=0)
    parser.add_argument(
        "--board", choices=tuple(BOARD_TARGETS), default="xiao_nrf52840",
        help=(
            "board profile to sign the descriptor's target/family/variant "
            "for; must match the --board the bootloader binary was compiled "
            "with (tools/prepare_upstream.py --board). sensecap_solar_p1 is "
            "build-only, not physically qualified."
        ),
    )
    parser.add_argument(
        "--command-version", type=int, choices=(1, 2), default=1,
        help=(
            "1 (default): legacy 71-byte little-endian bootloader-only "
            "descriptor, supports per-device targeting via --device-address. "
            "2: the real LoRa OTA transport's 59-byte big-endian canonical "
            "wire descriptor (encodeOtaDescriptorCanonical layout) signed "
            "and verified verbatim by the bootloader; always broadcast, "
            "--device-address is ignored for the signed message (kept only "
            "for the legacy field, which command v2 does not use)."
        ),
    )
    args = parser.parse_args()
    target = BOARD_TARGETS[args.board]
    board_family = target >> 16
    board_variant = target & 0xFFFF

    image = args.image.read_bytes()
    active = args.active_image.read_bytes()
    if not image or len(image) > INSTALL_MAX_SIZE or len(image) % 4:
        raise SystemExit(
            f"candidate image must be word aligned and in 1..{INSTALL_MAX_SIZE} "
            f"(0x{INSTALL_MAX_SIZE:X}) bytes -- the internal filesystem region "
            "(0xD4000..0xED000) is out of bounds for a candidate install until "
            "an explicit migration proof allows raising this cap"
        )
    if not active or len(active) > BACKUP_MAX_SIZE or len(active) % 4:
        raise SystemExit(
            f"active-image reference must be word aligned and in "
            f"1..{BACKUP_MAX_SIZE} (0x{BACKUP_MAX_SIZE:X}) bytes"
        )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    candidate = args.output_dir / "candidate.bin"
    message = args.output_dir / "descriptor.bin"
    signature = args.output_dir / "descriptor.sig"
    candidate.write_bytes(image)

    if args.command_version == COMMAND_VERSION_WIRE_V2:
        # Real LoRa OTA transport canonical wire descriptor (see
        # src/ota/protocol/OtaDescriptor.h encodeOtaDescriptorCanonical):
        # boardFamily u16, boardVariant u16, role u8, appAddress u32,
        # exactSizeBytes u32, sha256[32], securityCounter u32,
        # minBootloaderCapabilities u32, formatId u16, keyId u16,
        # algorithmId u16 -- all big-endian, 59 bytes total. This is
        # signed and verified byte-for-byte identical to what the
        # transport itself verifies; command v2 has no per-device
        # targeting field, so --device-address is not part of the
        # signed message (the bootloader always treats a v2 command as
        # broadcast-installable).
        descriptor = struct.pack(
            ">HHBII",
            board_family, board_variant, args.role_id, APP_START, len(image),
        ) + hashlib.sha256(image).digest() + struct.pack(
            ">IIHHH", args.counter, CAP_QSPI_INSTALL, 1, 1, 1,
        )
        assert len(descriptor) == WIRE_DESCRIPTOR_SIZE
    else:
        descriptor = struct.pack(
            "<32sIIQBIIIIHHH",
            hashlib.sha256(image).digest(),
            target,
            args.role_id,
            args.device_address,
            1 if args.device_address == 0 else 0,
            CAP_QSPI_INSTALL,
            args.counter,
            len(image),
            APP_START,
            1, 1, 1,
        )
        assert len(descriptor) == 71
    message.write_bytes(descriptor)
    subprocess.check_call([
        "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(args.private_key),
        "-in", str(message), "-out", str(signature),
    ])
    sig = signature.read_bytes()
    if len(sig) != 64:
        raise SystemExit("unexpected Ed25519 signature size")

    if args.command_version == COMMAND_VERSION_WIRE_V2:
        prefix = struct.pack(
            "<IHHIQ", MAGIC, COMMAND_VERSION_WIRE_V2, 188, 1, secrets.randbits(64)
        )
        body = (prefix + descriptor + sig + struct.pack("<I", len(active))
                + hashlib.sha256(active).digest() + b"\x00")
        assert len(body) == 180
        crc = binascii.crc32(body) & 0xFFFFFFFF
        command = body + struct.pack("<II", crc, COMMIT)
        assert len(command) == 188
    else:
        prefix = struct.pack(
            "<IHHIQ", MAGIC, COMMAND_VERSION_LEGACY_V1, 200, 1, secrets.randbits(64)
        )
        body = (prefix + descriptor + sig + struct.pack("<I", len(active))
                + hashlib.sha256(active).digest() + b"\x00")
        assert len(body) == 192
        crc = binascii.crc32(body) & 0xFFFFFFFF
        command = body + struct.pack("<II", crc, COMMIT)
        assert len(command) == 200
    (args.output_dir / "install-command.bin").write_bytes(command)
    print(f"candidate: {candidate} ({len(image)} bytes)")
    print(f"command:   {args.output_dir / 'install-command.bin'} "
          f"({len(command)} bytes, v{args.command_version})")
    print(f"sha256:    {hashlib.sha256(image).hexdigest()}")


if __name__ == "__main__":
    main()
