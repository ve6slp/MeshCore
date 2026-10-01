#!/usr/bin/env python3
"""Build the bare, UNSIGNED canonical59 wire descriptor for a candidate
image -- nothing else.

This tool deliberately touches NO private key, no --active-image
reference, no durable install command, and no signature: it produces
exactly (and only) the 59 raw descriptor bytes a production host signs via
the existing companion protocol (CMD33 start / CMD34 raw message bytes /
CMD35 finish). That companion protocol signs EXACTLY these bytes -- no
domain prefix, no NUL terminator, no extra hashing/wrapping -- and returns
a 64-byte Ed25519 signature over them. The running app, not this tool,
decides which key to admit and performs the actual durable COMMIT (see
tools/sign_image.py for how a full signed install command is later
assembled from a signature over this same descriptor).

Uses the single shared descriptor codec in xiao_ota_descriptor.py -- the
exact same code tools/sign_image.py uses -- so there is one and only one
place that encodes a canonical59 descriptor in this tree.
"""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from xiao_ota_descriptor import (  # noqa: E402
    MANIFEST_BOARD_TARGETS as BOARD_TARGETS,
    WIRE_DESCRIPTOR_SIZE,
    assert_matches_canonical_layout_contract,
    build_descriptor,
)


def main(argv=None) -> int:
    assert_matches_canonical_layout_contract()
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", required=True, type=Path,
                         help="candidate application image to describe (not modified, not signed)")
    parser.add_argument(
        "--board", choices=tuple(BOARD_TARGETS), default="xiao_nrf52840",
        help=(
            "board profile to encode the descriptor's target/family/variant "
            "for; must match the target application and recovery profile. "
            "ESP uses its logical app0 address, not the SDK-selected inactive "
            "slot's physical address. No profile is production-qualified."
        ),
    )
    parser.add_argument("--role-id", type=lambda x: int(x, 0), default=0,
                         help="0 (companion) or 1 (repeater); rejected if any other value")
    parser.add_argument(
        "--counter", required=True, type=int,
        help=(
            "anti-rollback security counter; must be strictly greater than 0 "
            "(a device's floor starts at 0 and the bootloader rejects "
            "monotonic_counter <= counter_floor, so 0 can never install on "
            "any real device) and fit a uint32"
        ),
    )
    parser.add_argument("--output", required=True, type=Path,
                         help="path to write the bare 59-byte unsigned descriptor to")
    args = parser.parse_args(argv)

    image = args.image.read_bytes()
    # build_descriptor() itself validates --board/--role-id/--counter/image
    # geometry (raising SystemExit on any violation) before encoding
    # anything; nothing is written to --output until every check passes.
    descriptor = build_descriptor(args.board, args.role_id, args.counter, image)
    assert len(descriptor) == WIRE_DESCRIPTOR_SIZE

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(descriptor)
    print(f"descriptor: {args.output} ({len(descriptor)} bytes, UNSIGNED, canonical59 v1)")
    print(
        "Sign EXACTLY these bytes via the existing host companion protocol "
        "(CMD33 start / CMD34 raw message bytes / CMD35 finish) -- no domain "
        "prefix, no NUL terminator, no extra hashing/wrapping."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
