#!/usr/bin/env python3
"""Validate a compound preload against its selected pair and ordinary recovery APP.

No transport/device control. A package is not proof that a board was flashed.
"""

import argparse
from pathlib import Path

import package_pair as paired

APP_START = 0x27000
STAGE_START = 0xC4000
STAGE_END = 0xD4000


def validate_compound_preload_package(package, pair_manifest, restore_package):
    paired.require(pair_manifest.name == "pair-manifest.json", "requires pair-manifest.json")
    _, stage, _ = paired.verify_pair(pair_manifest.parent)
    raw, init = paired.package_payload(package, "application")
    app, original_init = paired.package_payload(restore_package, "application")
    paired.require({k: v for k, v in init.items() if k != "firmware_crc16"} ==
                   {k: v for k, v in original_init.items() if k != "firmware_crc16"},
                   "compound and ordinary recovery APP init profiles differ")
    paired.require(raw == paired.compound_payload(app, stage),
                   "package is not the exact matched compound preload")
    return raw


def verify_compound_preload_readback(read_at, expected):
    """Check a caller-provided memory reader; no USB discovery or resets."""
    paired.require(STAGE_START - APP_START < len(expected) <= STAGE_END - APP_START
                   and len(expected) % 4 == 0
                   and ((APP_START + len(expected) + 4095) & ~4095) <= STAGE_END,
                   "expected readback is outside compound APP/installer bounds")
    for offset in range(0, len(expected), 4096):
        count = min(4096, len(expected) - offset)
        actual = bytes(read_at(APP_START + offset, count))
        paired.require(len(actual) == count, "short compound readback")
        paired.require(actual == expected[offset:offset + count], "compound readback mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--pair-manifest", type=Path, required=True)
    parser.add_argument("--restore-package", type=Path, required=True)
    args = parser.parse_args()
    raw = validate_compound_preload_package(args.package, args.pair_manifest, args.restore_package)
    print(f"VERIFIED selected compound {len(raw)}B; SHA256 {paired.digest(raw)}; no device accessed")


if __name__ == "__main__":
    main()
