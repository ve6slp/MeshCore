#!/usr/bin/env python3

import argparse
import os
import pathlib
import select
import sys
import termios
import time

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
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        attrs = termios.tcgetattr(fd)
        attrs[0] = 0
        attrs[1] = 0
        attrs[2] = termios.CS8 | termios.CLOCAL | termios.CREAD
        attrs[3] = 0
        attrs[4] = termios.B115200
        attrs[5] = termios.B115200
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        termios.tcflush(fd, termios.TCIOFLUSH)
        time.sleep(2.0)
        _, writable, _ = select.select([], [fd], [], 2.0)
        if not writable:
            raise RuntimeError("target serial endpoint did not become writable")
        if os.write(fd, b"run\n") != 4:
            raise RuntimeError("short write sending QSPI test command")
        deadline = time.monotonic() + args.timeout
        pending = bytearray()
        while time.monotonic() < deadline:
            readable, _, _ = select.select([fd], [], [], 0.25)
            if not readable:
                continue
            raw = os.read(fd, 1024)
            if not raw:
                continue
            pending.extend(raw)
            while b"\n" in pending:
                raw_line, _, pending = pending.partition(b"\n")
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r")
                print(line, flush=True)
                lines.append(line)
                if line == "OTA_QSPI_TEST RESULT PASS":
                    passed = True
                    break
                if line == "OTA_QSPI_TEST RESULT FAIL":
                    break
            if lines and lines[-1].startswith("OTA_QSPI_TEST RESULT "):
                break
    finally:
        os.close(fd)

    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0 if passed else 4


if __name__ == "__main__":
    raise SystemExit(main())
