#!/usr/bin/env python3
"""Create candidate and durable command records from a raw application image."""

import argparse
import binascii
import hashlib
from pathlib import Path
import secrets
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from xiao_ota_descriptor import (  # noqa: E402
    BACKUP_MAX_SIZE,
    BOARD_TARGETS,
    INSTALL_MAX_SIZE,
    WIRE_DESCRIPTOR_SIZE,
    assert_matches_canonical_layout_contract,
    build_descriptor,
    validate_image_geometry,
)

MAGIC = 0x584F5441
COMMIT = 0x434F4D54
COMMAND_VERSION_CURRENT = 3


def main() -> None:
    assert_matches_canonical_layout_contract()
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--active-image", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--counter", required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
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
    args = parser.parse_args()

    image = args.image.read_bytes()
    active = args.active_image.read_bytes()
    # active_image_extent (the signed, durable byte-count of the OLD/backup
    # image the bootloader will restore on rollback) is written verbatim
    # from len(active) below. The bootloader's own admission check
    # (xiao_ota_install_command_static_identity_valid(), xiao_ota_record.c)
    # bounds that field by XIAO_OTA_INSTALL_MAX_SIZE (0xAD000) -- the SAME
    # destructive-write capacity bound as the candidate image above -- NOT
    # by BACKUP_MAX_SIZE/0xC6000, which is only the fixed physical bank-to-
    # bank placement stride, never itself an accepted extent value. An
    # --active-image between INSTALL_MAX_SIZE and BACKUP_MAX_SIZE (e.g.
    # exactly 0xAE000) would otherwise pass this check, get validly signed,
    # and then be unconditionally refused by the bootloader at install
    # time -- a signed-but-permanently-uninstallable artifact. Reject it
    # here instead, before signing.
    validate_image_geometry(active, what=(
        f"active-image reference (bounded the same as a candidate image, "
        f"1..{INSTALL_MAX_SIZE} (0x{INSTALL_MAX_SIZE:X}) bytes word aligned -- "
        f"{BACKUP_MAX_SIZE:#x} is only the physical bank stride, not an "
        "accepted active_image_extent value; the bootloader refuses "
        "anything larger than the shared install-capacity bound)"
    ))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    candidate = args.output_dir / "candidate.bin"
    message = args.output_dir / "descriptor.bin"
    signature = args.output_dir / "descriptor.sig"
    candidate.write_bytes(image)

    # Real LoRa OTA transport canonical wire descriptor (see
    # src/ota/protocol/OtaDescriptor.h encodeOtaDescriptorCanonical), built
    # by the single shared codec in xiao_ota_descriptor.py. This is signed
    # and verified byte-for-byte identical to what the transport itself
    # verifies; the command has no per-device targeting field (the
    # bootloader always treats a command as broadcast-installable).
    descriptor = build_descriptor(args.board, args.role_id, args.counter, image)
    assert len(descriptor) == WIRE_DESCRIPTOR_SIZE
    message.write_bytes(descriptor)
    subprocess.check_call([
        "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(args.private_key),
        "-in", str(message), "-out", str(signature),
    ])
    sig = signature.read_bytes()
    if len(sig) != 64:
        raise SystemExit("unexpected Ed25519 signature size")

    # admitted_signer_public_key_ed25519: the key the real running app
    # durably admits (via its own pre-existing MeshCore admin-identity
    # trust mechanism) at explicit COMMIT, alongside the signed manifest.
    # This lab/CLI tool has no separate admission step of its own, so it
    # derives the admitted key directly from --private-key's own public
    # half -- the signer and the admitted key are the same keypair here,
    # which is the correct lab/test-tooling analogue of "the running app
    # just finished verifying this exact signer and is now snapshotting
    # its key". A real RF/app-side COMMIT flow supplies whatever key it
    # actually admitted for this specific manifest (ordinarily the same
    # signer, but this tool does not assume that in general).
    admitted_public_key_der = subprocess.check_output([
        "openssl", "pkey", "-in", str(args.private_key), "-pubout", "-outform", "DER",
    ])
    admitted_public_key = admitted_public_key_der[-32:]
    if len(admitted_public_key) != 32:
        raise SystemExit("unexpected Ed25519 public key size")

    prefix = struct.pack(
        "<IHHIQ", MAGIC, COMMAND_VERSION_CURRENT, 220, 1, secrets.randbits(64)
    )
    body = (prefix + descriptor + admitted_public_key + sig
            + struct.pack("<I", len(active))
            + hashlib.sha256(active).digest() + b"\x00")
    assert len(body) == 212
    crc = binascii.crc32(body) & 0xFFFFFFFF
    command = body + struct.pack("<II", crc, COMMIT)
    assert len(command) == 220
    (args.output_dir / "install-command.bin").write_bytes(command)
    print(f"candidate: {candidate} ({len(image)} bytes)")
    print(f"command:   {args.output_dir / 'install-command.bin'} "
          f"({len(command)} bytes, v{COMMAND_VERSION_CURRENT})")
    print(f"sha256:    {hashlib.sha256(image).hexdigest()}")


if __name__ == "__main__":
    main()
