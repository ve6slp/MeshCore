#!/usr/bin/env python3
"""Read a companion's public identity through an explicit stable USB endpoint.

    python3 scripts/ota_devices.py inspect --by-id /dev/serial/by-id/usb-... --timeout 5

USB vendor/product strings are not board or radio identity. Only normal framed
AppStart and DeviceQuery are sent; no settings, resets or firmware writes occur.
DeviceQuery does not advertise OTA capability, so none is inferred or reported.
Importing this module does not open devices. open_companion() also supplies the
existing FramedSerial command interface for callers performing an OTA deployment.
ESP defaults to DTR/RTS false; --dtr opts into DTR true for nRF TinyUSB firmware.
The selected DTR state is set before opening, never toggled by this helper.
"""

import argparse
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

import ota_rf_lab as lab


class _Quiet:
    def log(self, *_args, **_kwargs):
        pass


def _endpoint(by_id):
    path = Path(by_id)
    if not path.is_absolute() or path.parent != Path("/dev/serial/by-id"):
        raise ValueError("explicit /dev/serial/by-id endpoint required")
    if not path.is_symlink():
        raise ValueError("USB endpoint must be an existing stable by-id symlink")
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if (resolved.parent != Path("/dev") or not re.fullmatch(r"tty(?:ACM|USB)[0-9]+", resolved.name)
            or not stat.S_ISCHR(info.st_mode)):
        raise ValueError("by-id endpoint does not resolve to a USB serial character device")
    return path, resolved, info.st_rdev


@contextmanager
def open_companion(by_id, *, name="companion", evidence=None, dtr: bool = False):
    """Yield a locked FramedSerial with DTR selected and RTS false before opening."""
    path, resolved, device_id = _endpoint(by_id)
    node = lab.FramedSerial(name, str(path), evidence if evidence is not None else _Quiet(),
                            no_reset=True, dtr=dtr)
    try:
        opened = os.fstat(node.fd)
        if (_endpoint(path) != (path, resolved, device_id)
                or not stat.S_ISCHR(opened.st_mode) or opened.st_rdev != device_id):
            raise RuntimeError("USB endpoint changed during open")
        yield node
    finally:
        node.close()


def _public_text(data, label, *, terminated=False):
    if terminated:
        end = data.find(b"\0")
        if end < 0:
            raise ValueError(f"unterminated {label} in companion response")
        data = data[:end]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"invalid UTF-8 {label} in companion response") from None
    if not text or any(not char.isprintable() for char in text):
        raise ValueError(f"invalid public {label} in companion response")
    return text


def identify_companion(node, *, timeout=5.0):
    """Return public companion fields only; unsupported/malformed replies fail."""
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("inspection timeout must be finite and in (0, 60] seconds")
    deadline = time.monotonic() + timeout
    info = lab.app_info(node, timeout=timeout)
    name_bytes = info["name"].encode("utf-8")
    if len(name_bytes) > 31:
        raise ValueError("oversized companion name")
    name = _public_text(name_bytes, "name")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("companion identification deadline expired")
    frame = node.command(bytes([lab.CMD_DEVICE_QUERY, 13]),
                         expected=(lab.RESP_DEVICE_INFO, lab.RESP_ERR), timeout=remaining)
    if (len(frame) != 82 or frame[0] != lab.RESP_DEVICE_INFO
            or not 10 <= frame[1] <= 13 or frame[80] not in (0, 1)
            or frame[81] not in (0, 1, 2)):
        raise ValueError("unsupported or malformed companion DeviceQuery response")
    return {
        "role": info["role"],
        "name": name,
        "pubkey": info["pubkey"],
        "board": _public_text(frame[20:60], "board", terminated=True),
        "fwversion": _public_text(frame[60:80], "firmware version", terminated=True),
        "protocol_version": frame[1],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("operation", choices=("inspect",))
    parser.add_argument("--by-id", required=True)
    parser.add_argument("--dtr", action="store_true",
                        help="assert DTR before opening for nRF TinyUSB; RTS stays false")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="total response deadline in seconds (maximum 60)")
    args = parser.parse_args(argv)
    try:
        if not math.isfinite(args.timeout) or not 0 < args.timeout <= 60:
            raise ValueError("inspection timeout must be finite and in (0, 60] seconds")
        with open_companion(args.by_id, dtr=args.dtr) as node:
            info = identify_companion(node, timeout=args.timeout)
        print(json.dumps(info, sort_keys=True))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ota_devices: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
