#!/usr/bin/env python3

import argparse
import pathlib
import sys
import time

import serial

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import lab_device  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--role",
        default="target",
        help="Lab role to exercise, resolved through lab/devices.ini",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=float, default=90.0)
    args = parser.parse_args()

    device_info = lab_device.wait_for(args.role, lab_device.MODE_APP,
                                      min(args.timeout, 30.0))
    port = device_info.by_id
    print(f"QSPI harness on role '{args.role}' (serial {device_info.serial}) via {port}")

    lines = []
    passed = False
    with serial.Serial(str(port), 115200, timeout=0.25) as device:
        device.reset_input_buffer()
        device.write(b"run\n")
        device.flush()
        while time.monotonic() < deadline:
            raw = device.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").rstrip()
            print(line, flush=True)
            lines.append(line)
            if line == "OTA_QSPI_TEST RESULT PASS":
                passed = True
                break
            if line == "OTA_QSPI_TEST RESULT FAIL":
                break

    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0 if passed else 4


if __name__ == "__main__":
    raise SystemExit(main())
