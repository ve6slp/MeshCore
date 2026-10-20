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
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time

import ota_common as lab


def quiet_serial_factory(*args, **options):
    """One combined modem update; no intermediate ESP reset state."""
    if sys.platform != "linux":
        raise lab.Error("quiet UART requires Linux combined modem control")
    import serial.serialposix
    import termios

    class QuietSerial(serial.serialposix.Serial):
        def _reconfigure_port(self, force_update=False):
            super()._reconfigure_port(force_update)
            attributes = termios.tcgetattr(self.fd)
            if attributes[2] & termios.HUPCL:
                attributes[2] &= ~termios.HUPCL
                termios.tcsetattr(self.fd, termios.TCSANOW, attributes)
                if termios.tcgetattr(self.fd)[2] & termios.HUPCL:
                    raise lab.Error("UART HUPCL disable readback failed")

        def _update_modem_state(self):
            mask = termios.TIOCM_DTR | termios.TIOCM_RTS
            try:
                current = struct.unpack("i", fcntl.ioctl(self.fd, termios.TIOCMGET, struct.pack("i", 0)))[0]
                requested = ((termios.TIOCM_DTR if self._dtr_state else 0)
                             | (termios.TIOCM_RTS if self._rts_state else 0))
                desired = (current & ~mask) | requested
                if desired != current:
                    fcntl.ioctl(self.fd, termios.TIOCMSET, struct.pack("i", desired))
                actual = struct.unpack("i", fcntl.ioctl(self.fd, termios.TIOCMGET, struct.pack("i", 0)))[0]
                if actual & mask != requested:
                    raise lab.Error("combined UART modem-state readback mismatch")
            except OSError as exc:
                raise lab.Error("combined UART modem control unavailable; no sequential fallback") from exc

        def _update_dtr_state(self):
            self._update_modem_state()

        def _update_rts_state(self):
            self._update_modem_state()

    return QuietSerial(*args, **options)


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


def physical_endpoint(by_id, serial, *, by_path=None, id_path=None, vid=None, pid=None,
                      sys_tty=Path("/sys/class/tty"), sys_usb=Path("/sys/bus/usb/devices"),
                      udev_data=Path("/run/udev/data")):
    if not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", serial):
        raise ValueError("explicit physical USB serial required")
    if by_path is None:
        endpoint = _endpoint(by_id)
    else:
        path = Path(by_path)
        if Path(by_id).parent != Path("/dev/serial/by-id"):
            raise ValueError("informational by-id must use /dev/serial/by-id")
        if (path.parent != Path("/dev/serial/by-path") or not id_path
                or path.name != id_path + "-port0" or vid is None or pid is None
                or not path.is_symlink()):
            raise ValueError("exact by-path/ID_PATH/VID/PID binding required")
        tty = path.resolve(strict=True)
        info = tty.stat()
        if tty.parent != Path("/dev") or not re.fullmatch(r"tty(?:ACM|USB)[0-9]+", tty.name) or not stat.S_ISCHR(info.st_mode):
            raise ValueError("invalid physical USB endpoint")
        endpoint = path, tty, info.st_rdev
    path, tty, device_id = endpoint
    device = (sys_tty / tty.name / "device").resolve(strict=True)
    owners = [p for p in (device, *device.parents) if (p / "idVendor").is_file() and (p / "idProduct").is_file()]
    if not owners:
        raise ValueError("selected tty has no USB physical owner")
    owner = owners[0]
    if (owner / "serial").read_text().strip() != serial:
        raise ValueError("physical USB serial mismatch")
    if by_path is None:
        matches = [p.resolve(strict=True) for p in sys_usb.iterdir()
                   if ":" not in p.name and (p / "serial").is_file()
                   and (p / "serial").read_text().strip() == serial]
        if matches != [owner]:
            raise ValueError("duplicate USB serial requires an explicit physical by-path binding")
    else:
        observed = (int((owner / "idVendor").read_text().strip(), 16),
                    int((owner / "idProduct").read_text().strip(), 16))
        data = (udev_data / f"c{os.major(device_id)}:{os.minor(device_id)}").read_text()
        properties = dict(line[2:].split("=", 1) for line in data.splitlines() if line.startswith("E:") and "=" in line)
        if (observed != (vid, pid) or properties.get("ID_PATH") != id_path
                or properties.get("ID_SERIAL_SHORT") != serial
                or properties.get("ID_VENDOR_ID", "").lower() != f"{vid:04x}"
                or properties.get("ID_MODEL_ID", "").lower() != f"{pid:04x}"):
            raise ValueError("physical USB path/serial/VID/PID mismatch")
    return endpoint


@contextmanager
def open_companion(by_id, *, name="companion", evidence=None, dtr: bool = False,
                   serial=None, by_path=None, id_path=None, vid=None, pid=None):
    """Yield a locked FramedSerial with DTR selected and RTS false before opening."""
    if serial is None and any(x is not None for x in (by_path, id_path, vid, pid)):
        raise ValueError("physical USB metadata requires explicit serial")
    def resolve():
        return (_endpoint(by_id) if serial is None else
                physical_endpoint(by_id, serial, by_path=by_path, id_path=id_path, vid=vid, pid=pid))
    path, resolved, device_id = resolve()
    node = lab.FramedSerial(name, str(path), evidence if evidence is not None else _Quiet(),
                            no_reset=True, dtr=dtr)
    try:
        opened = os.fstat(node.fd)
        if (resolve() != (path, resolved, device_id)
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
            or not 10 <= frame[1] <= 14 or frame[80] not in (0, 1)
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
