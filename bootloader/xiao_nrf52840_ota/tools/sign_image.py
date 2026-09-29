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
TARGET = 0x584E3430
CAP_QSPI_INSTALL = 1
APP_START = 0x27000
MAX_SIZE = 0xC6000


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--active-image", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--counter", required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--device-address", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--role-id", type=lambda x: int(x, 0), default=0)
    args = parser.parse_args()

    image = args.image.read_bytes()
    active = args.active_image.read_bytes()
    if (not image or len(image) > MAX_SIZE or not active or len(active) > MAX_SIZE
            or len(image) % 4 or len(active) % 4):
        raise SystemExit("image extent must be word aligned and in 1..0xC6000 bytes")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    candidate = args.output_dir / "candidate.bin"
    message = args.output_dir / "descriptor.bin"
    signature = args.output_dir / "descriptor.sig"
    candidate.write_bytes(image)

    descriptor = struct.pack(
        "<32sIIQBIIIIHHH",
        hashlib.sha256(image).digest(),
        TARGET,
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

    prefix = struct.pack("<IHHIQ", MAGIC, 1, 200, 1, secrets.randbits(64))
    body = (prefix + descriptor + sig + struct.pack("<I", len(active))
            + hashlib.sha256(active).digest() + b"\x00")
    assert len(body) == 192
    crc = binascii.crc32(body) & 0xFFFFFFFF
    command = body + struct.pack("<II", crc, COMMIT)
    assert len(command) == 200
    (args.output_dir / "install-command.bin").write_bytes(command)
    print(f"candidate: {candidate} ({len(image)} bytes)")
    print(f"command:   {args.output_dir / 'install-command.bin'} ({len(command)} bytes)")
    print(f"sha256:    {hashlib.sha256(image).hexdigest()}")


if __name__ == "__main__":
    main()
