#!/usr/bin/env python3
"""Offline, explicit compound-preload validation; no transport or device control."""
import argparse
from collections.abc import Callable
from pathlib import Path

import package_pair as paired

APP_START = 0x27000
STAGE_START = 0xC4000
STAGE_END = 0xD4000


def validate_compound_preload_package(package: Path, pair_manifest: Path) -> bytes:
    """Validate only the matched commissioning compound, not an ordinary APP."""
    return _validate_compound(package, pair_manifest)


def _validate_compound(package: Path, pair_manifest: Path, *, client41=False) -> bytes:
    paired.require(pair_manifest.name == "pair-manifest.json",
                    "requires the build pair-manifest.json")
    _, stage, _ = (paired.verify_pair(pair_manifest.parent, client41=True) if client41 else
                   paired.verify_pair(pair_manifest.parent))
    raw, init = paired.package_payload(package, "application")
    paired.require(
        init["application_version"] == 0xFFFFFFFF and
        init["device_revision"] == 0xFFFF,
        "compound standard init differs from immutable CURRENT APP")
    size = paired.CLIENT_APP_BYTES if client41 else paired.CURRENT_APP_BYTES
    expected = paired.compound_payload(raw[:size], stage, client41=client41)
    paired.require(raw == expected, "package is not the exact matched compound preload")
    return raw


def validate_client_preload_packages(
        package: Path, pair_manifest: Path, restore_package: Path) -> bytes:
    """Only literal client41 ROLE0 compound plus its exact selected ordinary ZIP."""
    paired.require(paired.build.sha(restore_package) == paired.CLIENT_APP_ZIP_SHA256,
                   "ordinary restore ZIP is not the immutable approved client41 package")
    app, init = paired.package_payload(restore_package, "application")
    paired.require(
        len(app) == paired.CLIENT_APP_BYTES and paired.digest(app) == paired.CLIENT_APP_SHA256 and
        init["application_version"] == 0xFFFFFFFF and init["device_revision"] == 0xFFFF,
        "ordinary restore APP is not the immutable approved client41 image/profile")
    raw = _validate_compound(package, pair_manifest, client41=True)
    paired.require(raw[:len(app)] == app, "compound and ordinary restore prefixes differ")
    return raw


def verify_compound_preload_readback(
        read_at: Callable[[int, int], bytes], expected: bytes) -> None:
    """Compare validated preload bytes through a bounded memory-reader callback."""
    paired.require(
        STAGE_START - APP_START < len(expected) <= STAGE_END - APP_START and
        len(expected) % 4 == 0 and
        ((APP_START + len(expected) + 4095) & ~4095) <= STAGE_END,
        "expected readback is outside compound APP/installer bounds")
    for offset in range(0, len(expected), 4096):
        count = min(4096, len(expected) - offset)
        address = APP_START + offset
        actual = bytes(read_at(address, count))
        paired.require(len(actual) == count,
                        f"short compound readback at 0x{address:05X}")
        paired.require(actual == expected[offset:offset + count],
                        f"compound readback mismatch at 0x{address:05X}")


def verify_client_preload_readback(
        read_at: Callable[[int, int], bytes], expected: bytes, baseline_slot: bytes) -> None:
    """Verify the whole compound AND installer slot, retaining its captured tail."""
    paired.require(len(baseline_slot) == STAGE_END - STAGE_START,
                   "client41 requires an actual full 64KiB installer baseline")
    verify_compound_preload_readback(read_at, expected)
    installed = expected[STAGE_START - APP_START:]
    erased = ((APP_START + len(expected) + 4095) & ~4095) - STAGE_START
    slot = installed + b"\xff" * (erased - len(installed)) + baseline_slot[erased:]
    paired.require(len(slot) == STAGE_END - STAGE_START, "invalid client installer slot bounds")
    for offset in range(0, len(slot), 4096):
        address = STAGE_START + offset
        actual = bytes(read_at(address, 4096))
        paired.require(len(actual) == 4096, f"short installer slot readback at 0x{address:05X}")
        paired.require(actual == slot[offset:offset + 4096],
                       f"installer slot/baseline readback mismatch at 0x{address:05X}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--pair-manifest", type=Path, required=True)
    args = parser.parse_args()
    raw = validate_compound_preload_package(args.package, args.pair_manifest)
    print(f"VERIFIED explicit compound preload {len(raw)}B; SHA256 {paired.digest(raw)}; "
          "ordinary APP gate unchanged; no device accessed")


if __name__ == "__main__":
    main()
