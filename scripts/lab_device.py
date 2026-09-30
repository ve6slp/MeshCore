#!/usr/bin/env python3
"""Single entry point for MeshCore OTA lab device management.

Every lab operation that touches a physical board goes through this tool so the
workflow stays identical from run to run: roles are pinned to USB serials,
ttyACM renumbering is irrelevant, and resets/power cycles use one agreed
escalation order instead of ad-hoc commands.

  ./scripts/lab_device.py list
  ./scripts/lab_device.py path target
  ./scripts/lab_device.py reset target
  ./scripts/lab_device.py bootloader target
  ./scripts/lab_device.py power-cycle target
  ./scripts/lab_device.py wait target --mode app

Prefer the `make lab-*` targets, which wrap these subcommands.
"""

from __future__ import annotations

import argparse
import configparser
import glob
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(os.environ.get("MESHCORE_LAB_CONFIG", REPO_ROOT / "lab" / "devices.ini"))

BY_ID_DIR = Path("/dev/serial/by-id")
USB_DEVICES = Path("/sys/bus/usb/devices")

# Seeed's USB vendor ID. Both XIAO nRF52840 variants enumerate under it.
SEEED_VID = 0x2886

# Adafruit nRF52 convention: the running application sets bit 15 of the
# product ID, the serial-DFU bootloader clears it (e.g. app 0x8044 vs
# bootloader 0x0044). Matching on the bit works across board variants,
# unlike the USB product strings, which differ per unit.
APP_PID_BIT = 0x8000

MODE_APP = "app"
MODE_BOOT = "bootloader"

# uhubctl can wedge when the USB stack is busy; never block the lab on it.
UHUBCTL_TIMEOUT = 25.0


@dataclass
class Device:
    serial: str
    mode: str
    tty: str
    sysfs: Path
    product: str
    by_id: Path


def _read(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return ""


def _tty_for(sysfs: Path) -> str | None:
    for iface in sorted(sysfs.glob(f"{sysfs.name}:*")):
        tty_dir = iface / "tty"
        if tty_dir.is_dir():
            names = sorted(p.name for p in tty_dir.iterdir())
            if names:
                return names[0]
    return None


def _by_id_map() -> dict[str, Path]:
    """tty name -> stable by-id symlink, as published by udev."""
    mapping: dict[str, Path] = {}
    if BY_ID_DIR.is_dir():
        for link in sorted(BY_ID_DIR.glob("*")):
            try:
                mapping.setdefault(link.resolve().name, link)
            except OSError:
                continue
    return mapping


def _seeed_nodes() -> list[Path]:
    """Every Seeed USB device node in sysfs, whether or not it has a tty."""
    nodes = []
    for node in sorted(USB_DEVICES.glob("*")):
        if ":" in node.name or not (node / "idVendor").exists():
            continue
        if _read(node / "idVendor").lower() == f"{SEEED_VID:04x}":
            nodes.append(node)
    return nodes


def sysfs_for_serial(serial: str) -> Path | None:
    """Locate a board in sysfs by serial even when it exposes no tty.

    Needed for recovery: a board whose USB stack has wedged still has a sysfs
    node, and that node is what identifies the hub port to power-cycle.
    """
    for node in _seeed_nodes():
        if _read(node / "serial") == serial:
            return node
    return None


def discover() -> list[Device]:
    """Every attached XIAO nRF52840 that udev has finished setting up.

    A board is only reported once its stable by-id symlink exists. Reporting it
    earlier races udev: the raw /dev/ttyACMn node briefly exists with default
    root-only permissions, which makes opens fail with EACCES.
    """
    by_id = _by_id_map()
    devices: list[Device] = []
    for node in _seeed_nodes():
        serial = _read(node / "serial")
        pid_text = _read(node / "idProduct")
        if not serial or not pid_text:
            continue
        tty = _tty_for(node)
        if tty is None or tty not in by_id:
            continue
        mode = MODE_APP if int(pid_text, 16) & APP_PID_BIT else MODE_BOOT
        devices.append(Device(serial=serial, mode=mode, tty=tty, sysfs=node,
                              product=_read(node / "product"), by_id=by_id[tty]))
    return devices


def load_roles() -> dict[str, str]:
    """Role -> USB serial. Environment overrides the committed inventory."""
    roles: dict[str, str] = {}
    protected: dict[str, str] = {}
    if CONFIG_PATH.is_file():
        parser = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
        parser.read(CONFIG_PATH)
        if parser.has_section("roles"):
            roles.update({k: v.strip() for k, v in parser.items("roles") if v.strip()})
        if parser.has_section("protected"):
            protected.update({k: v.strip() for k, v in parser.items("protected") if v.strip()})
    for key, value in os.environ.items():
        if key.startswith("MESHCORE_LAB_") and key.endswith("_SERIAL") and value.strip():
            roles[key[len("MESHCORE_LAB_"):-len("_SERIAL")].lower()] = value.strip()
    protected_by_serial = {serial: name for name, serial in protected.items()}
    conflicts = [(role, protected_by_serial[serial])
                 for role, serial in roles.items() if serial in protected_by_serial]
    if conflicts:
        details = ", ".join(f"{role} is protected as {name}" for role, name in conflicts)
        raise SystemExit(f"refusing protected lab device assignment: {details}")
    return roles


def load_protected() -> dict[str, str]:
    """Protected name -> USB serial. These devices must never be lab targets."""
    if not CONFIG_PATH.is_file():
        return {}
    parser = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    parser.read(CONFIG_PATH)
    if not parser.has_section("protected"):
        return {}
    return {k: v.strip() for k, v in parser.items("protected") if v.strip()}


def resolve(role: str, mode: str = "any") -> Device:
    roles = load_roles()
    if role not in roles:
        known = ", ".join(sorted(roles)) or "<none configured>"
        raise SystemExit(f"unknown lab role '{role}'; configured roles: {known}\n"
                         f"edit {CONFIG_PATH} or export MESHCORE_LAB_{role.upper()}_SERIAL")
    serial = roles[role]
    attached = discover()
    matches = [d for d in attached if d.serial == serial]
    if not matches:
        listing = "\n".join(f"  {d.serial}  {d.mode:<10} {d.tty}" for d in attached) or "  (none)"
        raise SystemExit(f"lab role '{role}' (serial {serial}) is not attached.\n"
                         f"attached XIAO nRF52840 boards:\n{listing}")
    if mode != "any":
        wanted = [d for d in matches if d.mode == mode]
        if not wanted:
            have = ", ".join(d.mode for d in matches)
            raise SystemExit(f"lab role '{role}' is in {have} mode, not {mode}")
        return wanted[0]
    # Bootloader mode wins when a board somehow presents both.
    matches.sort(key=lambda d: d.mode != MODE_BOOT)
    return matches[0]


def wait_for(role: str, mode: str, timeout: float, absent_first: bool = False) -> Device:
    """Block until `role` presents itself in `mode`."""
    deadline = time.monotonic() + timeout
    if absent_first:
        # Give the board a moment to drop off the bus so we do not immediately
        # re-match the pre-reset enumeration.
        gone_by = time.monotonic() + min(5.0, timeout)
        while time.monotonic() < gone_by:
            try:
                resolve(role, mode)
            except SystemExit:
                break
            time.sleep(0.1)
        else:
            raise SystemExit(f"role '{role}' did not disconnect after reset; physical reset required")
    last: SystemExit | None = None
    while time.monotonic() < deadline:
        try:
            return resolve(role, mode)
        except SystemExit as exc:
            last = exc
            time.sleep(0.2)
    raise SystemExit(f"timed out after {timeout:.0f}s waiting for role '{role}' in {mode} mode\n{last}")


def _touch_1200(port: Path) -> None:
    """Request DFU entry: open at 1200 baud, then drop DTR.

    The Adafruit nRF52 core triggers its bootloader on the 1200-baud DTR
    high->low edge, so the port must be *opened* at 1200 and DTR toggled
    explicitly. Merely re-rating an open port with termios is unreliable.
    The board disconnects mid-sequence, so a dropped endpoint means success.
    """
    try:
        import serial  # type: ignore
    except ImportError:
        raise SystemExit("pyserial is required to enter the bootloader")
    handle = serial.Serial()
    handle.port = str(port)
    handle.baudrate = 1200
    try:
        handle.open()
        handle.dtr = True
        time.sleep(0.1)
        handle.dtr = False
        time.sleep(0.3)
    except (OSError, serial.SerialException):
        pass  # the board reset out from under us, which is the desired outcome
    finally:
        try:
            handle.close()
        except (OSError, serial.SerialException):
            pass


def cmd_list(args: argparse.Namespace) -> int:
    roles = load_roles()
    by_serial = {serial: role for role, serial in roles.items()}
    protected_by_serial = {serial: f"protected:{name}"
                           for name, serial in load_protected().items()}
    devices = discover()
    if not devices:
        print("no XIAO nRF52840 boards attached")
    else:
        print(f"{'ROLE':<14} {'SERIAL':<18} {'MODE':<11} {'TTY':<10} {'USB':<10} PRODUCT")
        labels = {**protected_by_serial, **by_serial}
        for d in sorted(devices, key=lambda d: (labels.get(d.serial, "~"), d.serial)):
            print(f"{labels.get(d.serial, '-'):<14} {d.serial:<18} {d.mode:<11} "
                  f"{d.tty:<10} {d.sysfs.name:<10} {d.product}")
    missing = [r for r, s in roles.items() if not any(d.serial == s for d in devices)]
    if missing:
        print(f"\nconfigured but not attached: {', '.join(sorted(missing))}", file=sys.stderr)
        return 1
    return 0


def cmd_path(args: argparse.Namespace) -> int:
    print(resolve(args.role, args.mode).by_id)
    return 0


def cmd_serial(args: argparse.Namespace) -> int:
    # Resolved from the inventory alone so artifact names stay stable even
    # when the board is detached or in recovery.
    roles = load_roles()
    if args.role not in roles:
        raise SystemExit(f"unknown lab role '{args.role}'; edit {CONFIG_PATH}")
    print(roles[args.role])
    return 0


def cmd_wait(args: argparse.Namespace) -> int:
    device = wait_for(args.role, args.mode, args.timeout)
    print(device.by_id)
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    """Restart companion firmware using its binary reboot command."""
    device = resolve(args.role, MODE_APP)
    try:
        import serial  # type: ignore
    except ImportError:
        raise SystemExit("pyserial is required for `reset`")
    with serial.Serial(str(device.by_id), 115200, timeout=1, write_timeout=2) as port:
        frame = b"<\x07\x00\x13reboot"
        if port.write(frame) != len(frame):
            raise SystemExit(f"short reboot command write for role '{args.role}'")
    ready = wait_for(args.role, MODE_APP, args.timeout, absent_first=True)
    print(ready.by_id)
    return 0


def cmd_bootloader_port(role: str, timeout: float) -> Path:
    """Put `role` into the serial DFU bootloader and return its port."""
    device = resolve(role)
    if device.mode == MODE_BOOT:
        return device.by_id
    _touch_1200(device.by_id)
    return wait_for(role, MODE_BOOT, timeout).by_id


def cmd_bootloader(args: argparse.Namespace) -> int:
    """1200-baud touch, the documented DFU entry for this board."""
    print(cmd_bootloader_port(args.role, args.timeout))
    return 0


def cmd_flash(args: argparse.Namespace) -> int:
    """Flash a DFU package to a role.

    PlatformIO's own uploader is not used here: it always issues a 1200-baud
    touch and then rediscovers the port by scanning, which fails whenever the
    board is already in DFU or when ttyACM numbering shifts mid-upload. Driving
    adafruit-nrfutil against an already-resolved DFU port is deterministic.
    """
    package = Path(args.package)
    if not package.is_file():
        raise SystemExit(f"DFU package not found: {package}\nbuild it first (make build-xiao-nrf52-lab)")

    nrfutil = Path(os.environ.get("ADAFRUIT_NRFUTIL",
                                  Path.home() / ".platformio/packages/tool-adafruit-nrfutil"))
    script = nrfutil / "adafruit-nrfutil.py" if nrfutil.is_dir() else nrfutil
    if not script.is_file():
        raise SystemExit(f"adafruit-nrfutil not found at {script}; set ADAFRUIT_NRFUTIL")

    port = cmd_bootloader_port(args.role, args.timeout)
    print(f"flashing {args.role} ({package}) via {port}")

    env = dict(os.environ)
    site = script.parent / "site-packages"
    if site.is_dir():
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(site), env.get("PYTHONPATH", "")]))
    proc = subprocess.run([sys.executable, str(script), "dfu", "serial",
                           "-pkg", str(package), "-p", str(port),
                           "-b", "115200", "--singlebank"], env=env)
    if proc.returncode != 0:
        raise SystemExit(f"adafruit-nrfutil failed with exit {proc.returncode}")

    print(wait_for(args.role, MODE_APP, args.timeout).by_id)
    return 0


def _run(cmd: list[str], timeout: float) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout:.0f}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return 127, f"not installed: {cmd[0]}"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _protected_on_hub(hub: str) -> list[str]:
    prefix = hub + ("-" if hub.isdigit() else ".")
    members = []
    for name, serial in load_protected().items():
        device = sysfs_for_serial(serial)
        if device is not None and device.name.startswith(prefix):
            members.append(f"{name} ({serial})")
    return members


def cmd_power_cycle(args: argparse.Namespace) -> int:
    """Cut and restore USB port power, then wait for re-enumeration.

    uhubctl is the only mechanism used. The sysfs `authorized` toggle is
    deliberately *not* a fallback: on these boards it leaves the USB stack
    wedged ("can't set config #1, error -32") and recoverable only by a real
    power cut or a physical reset.

    Bench hubs report ganged power switching, so forced port control may
    affect siblings. Never force power control on a hub containing a
    protected device.
    """
    roles = load_roles()
    if args.role not in roles:
        raise SystemExit(f"unknown lab role '{args.role}'; edit {CONFIG_PATH}")
    sysfs = sysfs_for_serial(roles[args.role])
    if sysfs is None:
        raise SystemExit(f"role '{args.role}' (serial {roles[args.role]}) is not on the USB bus "
                         f"at all; re-seat the cable")
    location = sysfs.name  # e.g. "8-4.4.3" or "1-10"
    separator = "." if "." in location else "-"
    hub, _, port = location.rpartition(separator)
    protected = _protected_on_hub(hub)
    if protected:
        raise SystemExit(
            f"refusing to power-cycle hub {hub}: protected device shares its power domain: "
            f"{', '.join(protected)}\n"
            f"physically reset or reattach role '{args.role}' instead")

    rc, out = _run(["sudo", "-n", "uhubctl", "-f", "-l", hub, "-p", port,
                    "-a", "cycle", "-d", str(args.delay)], UHUBCTL_TIMEOUT)
    if rc != 0:
        raise SystemExit(
            f"uhubctl could not power-cycle {location} (hub {hub} port {port}):\n"
            f"  {out or f'exit {rc}'}\n"
            f"this port has no software power control; press reset on the board instead")
    print(f"power-cycled {args.role} via uhubctl hub {hub} port {port}")

    print(wait_for(args.role, args.mode, args.timeout).by_id)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    ok = cmd_list(args) == 0
    rc, _ = _run(["sudo", "-n", "true"], 10.0)
    sudo_ok = rc == 0
    print(f"\npasswordless sudo (power-cycle): {'yes' if sudo_ok else 'no'}")
    rc, _ = _run(["sh", "-c", "command -v uhubctl"], 10.0)
    uhubctl_ok = rc == 0
    print(f"uhubctl installed: {'yes' if uhubctl_ok else 'no'}")
    try:
        import serial  # noqa: F401
        print("pyserial available: yes")
    except ImportError:
        print("pyserial available: no (reset/monitor unavailable)")
        ok = False

    if sudo_ok and uhubctl_ok:
        for role in sorted(load_roles()):
            try:
                location = resolve(role).sysfs.name
            except SystemExit:
                continue
            separator = "." if "." in location else "-"
            hub, _, port = location.rpartition(separator)
            if _protected_on_hub(hub):
                print(f"power-cycle {role} (hub {hub} port {port}): "
                      "no - protected device shares hub; physical reset required")
                continue
            rc, _ = _run(["sudo", "-n", "uhubctl", "-f", "-l", hub, "-p", port],
                         UHUBCTL_TIMEOUT)
            print(f"power-cycle {role} (hub {hub} port {port}): "
                  f"{'yes' if rc == 0 else 'no - physical reset required'}")

    print(f"inventory: {CONFIG_PATH}")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_role_command(name: str, handler, *, mode_default: str = "any", help_text: str = "") -> None:
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("role")
        cmd.add_argument("--mode", choices=[MODE_APP, MODE_BOOT, "any"], default=mode_default)
        cmd.add_argument("--timeout", type=float, default=30.0)
        cmd.set_defaults(func=handler)
        return cmd

    listing = sub.add_parser("list", help="show attached boards and their roles")
    listing.set_defaults(func=cmd_list)

    doctor = sub.add_parser("doctor", help="check the lab host can drive the boards")
    doctor.set_defaults(func=cmd_doctor)

    add_role_command("path", cmd_path, help_text="print the stable by-id path for a role")
    add_role_command("serial", cmd_serial, help_text="print the USB serial pinned to a role")
    add_role_command("wait", cmd_wait, mode_default=MODE_APP,
                     help_text="block until a role enumerates")
    add_role_command("reset", cmd_reset, mode_default=MODE_APP,
                     help_text="restart the application firmware")
    add_role_command("bootloader", cmd_bootloader, mode_default=MODE_BOOT,
                     help_text="enter the serial DFU bootloader (1200-baud touch)")
    flash = add_role_command("flash", cmd_flash, mode_default=MODE_APP,
                             help_text="flash a DFU package and return to the application")
    flash.add_argument("--package", required=True, help="path to firmware.zip")
    cycle = add_role_command("power-cycle", cmd_power_cycle, mode_default=MODE_APP,
                             help_text="cut and restore USB port power")
    cycle.add_argument("--delay", type=int, default=3, help="seconds to stay powered down")

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
