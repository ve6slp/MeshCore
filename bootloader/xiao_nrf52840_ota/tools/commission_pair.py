#!/usr/bin/env python3
"""Validate selected pair/APP packages, optionally sending one explicit USB bench phase.

No port discovery or reset control. A package is not proof that a board was flashed.
"""

import argparse
import site
import sys
from pathlib import Path

import package_pair as paired

APP_START = 0x27000
STAGE_START = 0xC4000
STAGE_END = 0xD4000
BENCH_ACK_TIMEOUT = 1800.0


def send_verified_usb_package(nrfutil, port, package):
    paired.require(nrfutil.is_file(), "requires the supplied Adafruit nrfutil Python entrypoint")
    original_path = sys.path[:]
    transport = None
    backend = None
    try:
        dependencies = str(nrfutil.resolve().parent / "site-packages")
        site.addsitedir(dependencies)
        sys.path.insert(0, dependencies)
        from nordicsemi.dfu.dfu_transport_serial import DfuTransportSerial
        from nordicsemi.dfu.dfu_transport import DfuEvent
        from nordicsemi.dfu.dfu import Dfu
        previous_timeout = DfuTransportSerial.ACK_PACKET_TIMEOUT
        transport = DfuTransportSerial
        # 512 bounded sector erases can precede the next serial ACK. Keep the
        # vendor protocol unchanged; its normal one-second deadline is too short.
        transport.ACK_PACKET_TIMEOUT = BENCH_ACK_TIMEOUT
        # Negative touch suppresses both vendor touch-open and DTR reset paths.
        backend = transport(port, baud_rate=115200, touch=-1)
        operation = Dfu(str(package), dfu_transport=backend)
        def failed(log_message=""):
            raise RuntimeError("USB DFU failed: " + log_message)
        backend.register_events_callback(DfuEvent.TIMEOUT_EVENT, failed)
        backend.register_events_callback(DfuEvent.ERROR_EVENT, failed)
        paired.require(operation.dfu_send_images() is None,
                       "vendor DFU reported transfer failure or an unknown API result")
        print("Vendor transfer completed; cold installation/qualification NOT verified.")
    finally:
        try:
            if backend is not None and backend.is_open():
                backend.close()
        finally:
            if transport is not None:
                transport.ACK_PACKET_TIMEOUT = previous_timeout
            sys.path[:] = original_path


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
    parser.add_argument("--usb-phase", choices=("compound", "bootloader", "application"))
    parser.add_argument("--boot-policy", choices=("ordinary-vendor", "physical-usb-bench"))
    parser.add_argument("--usb-port")
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--nrfutil", type=Path)
    parser.add_argument("--board", choices=tuple(paired.build.BSP))
    parser.add_argument("--role", type=int, choices=(0, 1))
    parser.add_argument("--app-context", type=Path)
    args = parser.parse_args()
    paired.require(not (args.usb_port or args.fresh or args.nrfutil) or
                   (args.usb_phase and args.usb_port and args.fresh and args.nrfutil),
                   "USB sending requires an explicit phase, port, --fresh and --nrfutil")
    if args.usb_phase:
        paired.require(args.board is not None and args.role is not None and args.app_context is not None,
                       "select explicit board/ROLE and actual APP build context before USB")
        paired.require(args.boot_policy is not None,
                       "select the actual BOOT policy; legacy locked pairs have no USB BOOT path")
        primary, stage, public = paired.verify_pair(args.pair_manifest.parent,
                                                   board=args.board, role=args.role)
        paired.verify_app_context(args.app_context, args.restore_package,
                                  board=args.board, role=args.role)
        paired.require(public["usb_bench"] == paired.build.USB_BENCH,
                       "requires a future physical-USB-bench pair, not a legacy locked pair")
        app, original_init = paired.package_payload(args.restore_package, "application")
        paired.compound_payload(app, stage)
        if args.usb_phase == "compound":
            raw = validate_compound_preload_package(args.package, args.pair_manifest, args.restore_package)
        elif args.usb_phase == "bootloader":
            raw, init = paired.package_payload(args.package, "bootloader", primary)
            paired.require(init["application_version"] == 0x902, "wrong selected BOOT init version")
        else:
            raw, init = paired.package_payload(args.package, "application", app)
            paired.require(init == original_init, "ordinary APP init profile differs")
        print(f"VERIFIED {args.usb_phase}: {len(raw)}B SHA256 {paired.digest(raw)}; "
              "explicit vendor USB recovery required; fresh userdata/floors; no device accessed. "
              "NOT a legacy locked-pair conversion or installation proof.")
        if args.usb_port:
            send_verified_usb_package(args.nrfutil, args.usb_port, args.package)
        return
    raw = validate_compound_preload_package(args.package, args.pair_manifest, args.restore_package)
    print(f"VERIFIED selected compound {len(raw)}B; SHA256 {paired.digest(raw)}; no device accessed")


if __name__ == "__main__":
    main()
