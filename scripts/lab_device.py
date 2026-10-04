#!/usr/bin/env python3
"""Single entry point for MeshCore OTA lab device management.

Every lab operation that touches a physical board goes through this tool so the
workflow stays identical from run to run: roles are pinned to USB serials,
ttyACM renumbering is irrelevant, and resets/power cycles use one agreed
escalation order instead of ad-hoc commands.

  ./scripts/lab_device.py list
  ./scripts/lab_device.py path target
  ./scripts/lab_device.py reset target --protocol repeater
  ./scripts/lab_device.py bootloader target
  ./scripts/lab_device.py bootloader-uf2 target
  ./scripts/lab_device.py mount-commission-uf2 target
  ./scripts/lab_device.py commission-compound target --package compound.zip --pair-manifest pair-manifest.json
  ./scripts/lab_device.py commission-primary target --package bootloader.zip --preload-package compound.zip --pair-manifest pair-manifest.json
  ./scripts/lab_device.py power-cycle target
  ./scripts/lab_device.py wait target --mode app

Prefer the `make lab-*` targets, which wrap these subcommands.
"""

from __future__ import annotations

import argparse
import configparser
from datetime import datetime, timezone
import glob
import hashlib
import json
import math
import os
import re
import stat
import struct
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(os.environ.get("MESHCORE_LAB_CONFIG", REPO_ROOT / "lab" / "devices.ini"))

BY_ID_DIR = Path("/dev/serial/by-id")
DEV_DIR = Path("/dev")
USB_DEVICES = Path("/sys/bus/usb/devices")
MOUNTINFO = Path("/proc/self/mountinfo")
SYS_DEV_CHAR = Path("/sys/dev/char")
SYS_DEV_BLOCK = Path("/sys/dev/block")
STOCK_INFO_MAX_BYTES = 4096

# Existing guarded Seeed USB vendor ID; other VIDs are diagnostic-only.
SEEED_VID = 0x2886

# Adafruit nRF52 convention: the running application sets bit 15 of the
# product ID, the serial-DFU bootloader clears it (e.g. app 0x8044 vs
# bootloader 0x0044). Matching on the bit works across board variants,
# unlike the USB product strings, which differ per unit. This convention is
# not applied to diagnostic-only USB profiles.
APP_PID_BIT = 0x8000

MODE_APP = "app"
MODE_BOOT = "bootloader"

APPROVED_ADMIN_PAIR = {"client": "4186AE911D94CDB1", "target": "77CD44653A967172"}

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
    """Every guarded Seeed-VID XIAO nRF52840 that udev has finished setting up.

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


def _attached_usb_diagnostics(serial: str) -> list[str]:
    """Presence-only diagnostics, never an operational device or power-control path."""
    if serial not in APPROVED_ADMIN_PAIR.values():
        return []
    details = []
    for node in sorted(USB_DEVICES.glob("*")):
        if ":" in node.name or not (node / "idVendor").exists():
            continue
        if _read(node / "serial") != serial:
            continue
        vendor = _read(node / "idVendor").lower()
        product_id = _read(node / "idProduct").lower()
        reason = ("unsupported USB profile" if vendor != f"{SEEED_VID:04x}"
                  else "not ready for guarded discovery")
        details.append(f"{node.name}: VID={vendor or 'unknown'} PID={product_id or 'unknown'} "
                       f"product={_read(node / 'product')!r}; {reason}; mode/firmware unproven")
    return details


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
    if role not in APPROVED_ADMIN_PAIR or serial != APPROVED_ADMIN_PAIR[role]:
        raise SystemExit(f"refusing unapproved active lab role '{role}' (serial {serial}); "
                         "only the approved client and replacement target are operational")
    attached = discover()
    matches = [d for d in attached if d.serial == serial]
    if not matches:
        diagnostics = _attached_usb_diagnostics(serial)
        if diagnostics:
            raise SystemExit(f"lab role '{role}' (serial {serial}) is attached but unavailable "
                             "for guarded lab operations:\n  " + "\n  ".join(diagnostics))
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
    missing = [r for r, s in roles.items() if not any(d.serial == s for d in devices)]
    unavailable = {role: details for role in missing
                   if (details := _attached_usb_diagnostics(roles[role]))}
    if not devices:
        print("no operationally discoverable XIAO nRF52840 boards" if unavailable
              else "no XIAO nRF52840 boards attached")
    else:
        print(f"{'ROLE':<14} {'SERIAL':<18} {'MODE':<11} {'TTY':<10} {'USB':<10} PRODUCT")
        labels = {**protected_by_serial, **by_serial}
        for d in sorted(devices, key=lambda d: (labels.get(d.serial, "~"), d.serial)):
            print(f"{labels.get(d.serial, '-'):<14} {d.serial:<18} {d.mode:<11} "
                  f"{d.tty:<10} {d.sysfs.name:<10} {d.product}")
    if unavailable:
        print("\nconfigured and attached but unavailable for guarded lab operations:", file=sys.stderr)
        for role, details in sorted(unavailable.items()):
            print(f"  {role} (serial {roles[role]}):\n    " + "\n    ".join(details), file=sys.stderr)
    absent = [role for role in missing if role not in unavailable]
    if absent:
        print(f"\nconfigured but not attached: {', '.join(sorted(absent))}", file=sys.stderr)
    if missing:
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
    """Restart the selected application through its actual serial protocol."""
    commands = {
        "companion": b"<\x07\x00\x13reboot",
        "repeater": b"reboot\r",
    }
    if args.protocol not in commands:
        raise SystemExit("reset requires an explicit companion or repeater protocol")
    device = resolve(args.role, MODE_APP)
    try:
        import serial  # type: ignore
    except ImportError:
        raise SystemExit("pyserial is required for `reset`")
    with serial.Serial(str(device.by_id), 115200, timeout=1, write_timeout=2) as port:
        frame = commands[args.protocol]
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


def _validate_uf2_identity(device: Device, serial: str) -> None:
    if device.serial != serial:
        raise SystemExit(f"UF2 commissioning requires approved target serial {serial}, "
                         f"not {device.serial}")
    if (device.by_id.parent != BY_ID_DIR or not device.by_id.is_symlink()
            or not device.by_id.exists() or device.by_id.resolve().name != device.tty):
        raise SystemExit(f"UF2 commissioning requires a real stable by-id symlink "
                         f"for {device.tty}: {device.by_id}")
    if _read(device.sysfs / "serial") != serial:
        raise SystemExit(f"UF2 commissioning USB ancestry does not match target {serial}: "
                         f"{device.sysfs}")


def _uf2_target(args: argparse.Namespace) -> Device:
    if args.role != "target":
        raise SystemExit("UF2 commissioning is authorized for the target role only")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise SystemExit("UF2 commissioning timeout must be finite and positive")
    device = resolve(args.role, MODE_APP)
    _validate_uf2_identity(device, APPROVED_ADMIN_PAIR["target"])
    return device


def _uf2_repeater_request(device: Device, command: str, timeout: float) -> str:
    from ota_rf_lab import RepeaterSerial

    evidence = argparse.Namespace(log=lambda event, **fields: print(
        json.dumps({"event": event, **fields}, sort_keys=True), file=sys.stderr))
    node = None
    try:
        node = RepeaterSerial("target", str(device.by_id), evidence)
        return node.command(command, timeout=timeout)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(f"target UF2 command {command!r} failed: {exc}") from exc
    finally:
        if node is not None:
            node.close()


def _has_msc_interface(device: Device) -> bool:
    for interface in sorted(device.sysfs.glob(f"{device.sysfs.name}:*")):
        try:
            interface_class = (interface / "bInterfaceClass").read_text().strip()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SystemExit(f"cannot inspect target USB interface {interface}: {exc}") from exc
        if interface_class.lower() == "08":
            return True
    return False


@dataclass(frozen=True)
class _StockInfoSnapshot:
    """Give existing Path-based validators the same single bounded INFO read."""
    text: str

    def __truediv__(self, name: str) -> _StockInfoSnapshot:
        if name != "INFO_UF2.TXT":
            raise ValueError("only INFO_UF2.TXT is available in the stock INFO snapshot")
        return self

    def is_file(self) -> bool:
        return True

    def read_text(self, *, encoding: str) -> str:
        return self.text

    def __str__(self) -> str:
        return "bounded INFO_UF2.TXT snapshot"


def _sense_target_device(mode: str = MODE_BOOT) -> Device:
    tools = REPO_ROOT / "bootloader" / "xiao_nrf52840_ota" / "tools"
    sys.path.insert(0, str(tools))
    import install_uf2

    device = resolve("target", mode)
    serial = APPROVED_ADMIN_PAIR["target"]
    _validate_uf2_identity(device, serial)
    matches = [candidate for candidate in discover() if candidate.serial == serial]
    if len(matches) != 1 or matches[0] != device:
        raise ValueError("target requires one unique unchanged discovered target identity")
    tty_link = install_uf2.device_sysfs_link(device.by_id, SYS_DEV_CHAR)
    if (not tty_link.exists() or install_uf2.usb_serial_ancestor(tty_link) != serial
            or device.sysfs.resolve() not in tty_link.resolve().parents):
        raise ValueError("target tty ancestry does not match the approved target USB node")
    vendor = int((device.sysfs / "idVendor").read_text().strip(), 16)
    product_id = int((device.sysfs / "idProduct").read_text().strip(), 16)
    # The approved Sense target's immutable working APP advertises base-Xiao PID 8044.
    expected_pids = (0x8044, 0x8045) if device.mode == MODE_APP else (0x0045,)
    if vendor != SEEED_VID or product_id not in expected_pids:
        profile = ("approved APP USB 2886:8044 or 2886:8045" if device.mode == MODE_APP
                   else "exact Sense USB 2886:0045")
        raise ValueError(f"target requires {profile}")
    return device


@dataclass(frozen=True)
class _ReadOnlyTargetVolume:
    path: Path
    mount_text: str
    options: list[str]
    super_options: list[str]
    block_link: Path


def _read_only_target_volume(device: Device) -> _ReadOnlyTargetVolume:
    import install_uf2

    serial = APPROVED_ADMIN_PAIR["target"]
    if not _has_msc_interface(device):
        raise ValueError("approved target bootloader must expose its own MSC class08 interface")
    volumes = install_uf2.matching_mounts(serial, MOUNTINFO, SYS_DEV_BLOCK)
    if len(volumes) != 1:
        raise ValueError(f"expected exactly one ancestry-matched mounted target volume, found {len(volumes)}")
    volume = volumes[0]
    mount_text = MOUNTINFO.read_text(encoding="utf-8")
    rows = [fields for line in mount_text.splitlines()
            if len(fields := line.split()) >= 10 and "-" in fields
            and Path(install_uf2.decode_mount_field(fields[4])) == volume]
    if len(rows) != 1:
        raise ValueError("target volume must have exactly one unambiguous mount record")
    fields = rows[0]
    separator = fields.index("-")
    if separator < 6 or len(fields) != separator + 4:
        raise ValueError("malformed target mount record")
    options, super_options = fields[5].split(","), fields[separator + 3].split(",")
    if (fields[3] != "/" or "ro" not in options or "rw" in options
            or "ro" not in super_options or "rw" in super_options):
        raise ValueError("target requires a whole-volume read-only mount and read-only superblock")
    block_link = SYS_DEV_BLOCK / fields[2]
    if (install_uf2.usb_serial_ancestor(block_link) != serial
            or device.sysfs.resolve() not in block_link.resolve().parents):
        raise ValueError("mounted target volume ancestry does not match the approved target USB node")
    return _ReadOnlyTargetVolume(volume, mount_text, options, super_options, block_link)


def cmd_inspect_stock_bootloader(args: argparse.Namespace) -> int:
    """Read public stock Sense boot metadata; never enter or install a loader."""
    if args.role != "target":
        raise SystemExit("stock bootloader inspection is authorized for the target role only")
    try:
        device = _sense_target_device()
        import install_uf2

        serial = APPROVED_ADMIN_PAIR["target"]
        vendor = (device.sysfs / "idVendor").read_text().strip().lower()
        product_id = (device.sysfs / "idProduct").read_text().strip().lower()
        board = "xiao_nrf52840_sense"
        mounted = _read_only_target_volume(device)
        volume = mounted.path
        info_path = volume / "INFO_UF2.TXT"
        descriptor = os.open(info_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("INFO_UF2.TXT must be a regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(STOCK_INFO_MAX_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(data) > STOCK_INFO_MAX_BYTES:
            raise ValueError(f"INFO_UF2.TXT exceeds {STOCK_INFO_MAX_BYTES} bytes")
        text = data.decode("utf-8")
        if "\x00" in text:
            raise ValueError("INFO_UF2.TXT contains NUL bytes")
        snapshot = _StockInfoSnapshot(text)
        actual_board_id = install_uf2.board_id(snapshot)
        if actual_board_id not in install_uf2.BOARD_IDS[board]:
            raise ValueError("stock INFO Board-ID does not match the Sense profile")
        install_uf2.validate_stock_info(snapshot)
        if MOUNTINFO.read_text(encoding="utf-8") != mounted.mount_text:
            raise ValueError("mount records changed during stock INFO inspection")
    except (OSError, ValueError) as exc:
        raise SystemExit(f"refusing read-only stock bootloader inspection: {exc}") from exc
    print(json.dumps({
        "schema": "meshcore.lab.stock-bootloader-info.v1",
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "role": "target", "serial": serial, "by_id": str(device.by_id),
        "sysfs": str(device.sysfs), "usb_vid": vendor, "usb_pid": product_id,
        "product": device.product, "board_id": actual_board_id, "vendor_info": text,
        "mountpoint": str(volume), "mount_options": mounted.options,
        "superblock_options": mounted.super_options,
        "stock_bootloader_version": "0.6.1", "softdevice": "S140", "softdevice_version": "7.3.0",
        "read_only": True, "public_only": True, "serial_opened": False, "writes": False,
        "cryptographic_installed_bytes_proof": False, "custom_loader_qualified": False,
    }, sort_keys=True))
    return 0


def _wait_for_uf2(source: Device, timeout: float) -> Device:
    deadline = time.monotonic() + timeout
    serial = source.serial
    disconnected = False
    last = "target did not disconnect after the UF2 reboot request"
    while time.monotonic() < deadline:
        if not disconnected:
            try:
                source.sysfs.stat()
            except FileNotFoundError:
                disconnected = True
            except OSError as exc:
                raise SystemExit(f"cannot observe target USB disconnection: {exc}") from exc
        if disconnected:
            usb = sysfs_for_serial(serial)
            if usb is None:
                last = "target disconnected but has not re-enumerated"
                time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
                continue
            matches = [device for device in discover() if device.serial == serial]
            if len(matches) > 1:
                raise SystemExit(f"ambiguous target USB identity for {serial}")
            if not matches:
                last = "target USB is present but its stable by-id identity is not ready"
            else:
                device = matches[0]
                if device.sysfs.resolve() != usb.resolve():
                    raise SystemExit(f"target USB ancestry changed unexpectedly for {serial}")
                _validate_uf2_identity(device, serial)
                if device.mode != MODE_BOOT:
                    last = f"target returned in {device.mode} mode, not UF2 bootloader mode"
                elif _has_msc_interface(device):
                    return device
                else:
                    last = "target bootloader has no MSC interface (USB class 08); CDC-only is not UF2"
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    raise SystemExit(f"timed out waiting for target UF2 bootloader: {last}")


def cmd_bootloader_uf2(args: argparse.Namespace) -> int:
    """Request vendor UF2 entry and verify a new target bootloader with MSC."""
    device = _uf2_target(args)
    deadline = time.monotonic() + args.timeout
    reply = _uf2_repeater_request(device, "reboot uf2", min(5.0, args.timeout))
    if reply != "OK - rebooting UF2":
        raise SystemExit(f"target UF2 reboot request failed: {reply!r}")
    ready = _wait_for_uf2(device, max(0.0, deadline - time.monotonic()))
    print(ready.by_id)
    return 0


def validate_application_package(package: Path) -> bytes:
    tools = REPO_ROOT / "bootloader" / "xiao_nrf52840_ota" / "tools"
    sys.path.insert(0, str(tools))
    from xiao_ota_descriptor import (
        CANONICAL_LAYOUT_CONTRACT, _canonical_hex_define,
        assert_matches_canonical_layout_contract, validate_image_geometry,
    )

    assert_matches_canonical_layout_contract()
    app_limit = _canonical_hex_define(CANONICAL_LAYOUT_CONTRACT.read_text(),
                                      "OTA_NRF52_INTERNAL_IMAGE_SIZE")
    if app_limit != 643072:
        raise SystemExit("ordinary DFU application ceiling must remain 643072 bytes (0x27000..0xC4000)")
    try:
        with zipfile.ZipFile(package) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise SystemExit("DFU package contains duplicate entries")
            manifest = json.loads(archive.read("manifest.json"))
            contents = manifest.get("manifest") if isinstance(manifest, dict) else None
            if not isinstance(contents, dict) or set(contents) - {"dfu_version"} != {"application"}:
                raise SystemExit("flash requires an application-only DFU package; use the guarded bootloader installer")
            application = contents["application"]
            if not isinstance(application, dict):
                raise SystemExit("invalid DFU application manifest")
            binary = application.get("bin_file")
            init_packet = application.get("dat_file")
            if (not isinstance(binary, str) or not isinstance(init_packet, str)
                    or binary == init_packet or binary not in names or init_packet not in names):
                raise SystemExit("DFU package is missing its application binary or init packet")
            image = archive.read(binary)
            validate_image_geometry(image, "DFU application")
            if len(image) > app_limit:
                raise SystemExit(f"DFU application exceeds {app_limit} bytes; fixed installer is out of bounds")
            if not archive.read(init_packet):
                raise SystemExit("DFU application init packet is empty")
            return image
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, KeyError) as exc:
        raise SystemExit(f"invalid application DFU package: {exc}") from exc


def cmd_extract_application(args: argparse.Namespace) -> int:
    image = validate_application_package(Path(args.package))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(image)
    except FileExistsError as exc:
        raise SystemExit(f"refusing to overwrite application image: {output}") from exc
    print(f"application image: {output} ({len(image)} bytes, SHA-256 {hashlib.sha256(image).hexdigest()})")
    return 0


def _nrfutil_script() -> Path:
    nrfutil = Path(os.environ.get("ADAFRUIT_NRFUTIL",
                                  Path.home() / ".platformio/packages/tool-adafruit-nrfutil"))
    script = nrfutil / "adafruit-nrfutil.py" if nrfutil.is_dir() else nrfutil
    if not script.is_file():
        raise SystemExit(f"adafruit-nrfutil not found at {script}; set ADAFRUIT_NRFUTIL")
    return script


def _echo_dfu_output(stdout: bytes, stderr: bytes) -> None:
    for stream, data in ((sys.stdout, stdout), (sys.stderr, stderr)):
        if hasattr(stream, "buffer"):
            stream.buffer.write(data)
        else:
            stream.write(data.decode("utf-8", errors="replace"))
        stream.flush()


def _serial_dfu(package: Path, port: Path, script: Path, *, timeout: float | None = None) -> None:
    """Require vendor transport completion, not activation or installed-byte proof."""
    env = dict(os.environ)
    site = script.parent / "site-packages"
    if site.is_dir():
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(site), env.get("PYTHONPATH", "")]))
    kwargs = {} if timeout is None else {"timeout": timeout}
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        proc = subprocess.run([sys.executable, str(script), "dfu", "serial",
                               "-pkg", str(package), "-p", str(port),
                               "-b", "115200", "--singlebank"], env=env, capture_output=True, **kwargs)
    except subprocess.TimeoutExpired as exc:
        _echo_dfu_output(exc.stdout or b"", exc.stderr or b"")
        raise SystemExit("adafruit-nrfutil transport timed out; outcome unverified; no automatic retry") from exc
    _echo_dfu_output(proc.stdout, proc.stderr)
    if proc.returncode != 0:
        raise SystemExit(f"adafruit-nrfutil failed with exit {proc.returncode}")
    # Legacy nrfutil can exit zero after failures; path words are not diagnostics.
    if re.search(rb"(?im)^[ \t]*(?:failed to upgrade target\b|"
                 rb"traceback(?:[ \t]*[:(]|[ \t]*\r?$)|"
                 rb"(?:[\w.]*error|[\w.]*exception)[ \t]*:|false[ \t]*\r?$)",
                 proc.stdout + b"\n" + proc.stderr):
        raise SystemExit("adafruit-nrfutil reported transport failure despite exit 0; "
                         "outcome unverified; no automatic retry")
    # The final progress hashes have no newline before click's completion message.
    last_line = next((line for line in reversed(proc.stdout.splitlines()) if line), b"")
    if re.fullmatch(rb"#*Device programmed\.", last_line) is None:
        raise SystemExit("adafruit-nrfutil did not prove transport completion: "
                         "missing 'Device programmed.' (exit 0); outcome unverified; no automatic retry")


def cmd_flash(args: argparse.Namespace) -> int:
    """Flash an ordinary application through the resolved, pinned DFU port."""
    package = Path(args.package)
    if not package.is_file():
        raise SystemExit(f"DFU package not found: {package}\nbuild it first (make build-xiao-nrf52-lab)")
    validate_application_package(package)
    script = _nrfutil_script()
    port = cmd_bootloader_port(args.role, args.timeout)
    print(f"flashing {args.role} ({package}) via {port}", flush=True)
    _serial_dfu(package, port, script)
    print(wait_for(args.role, MODE_APP, args.timeout).by_id)
    return 0


def _commission_guard(args: argparse.Namespace) -> None:
    if args.role != "target":
        raise SystemExit("paired commissioning is authorized for the target role only")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise SystemExit("paired commissioning timeout must be finite and positive")
    if load_roles().get("target") != APPROVED_ADMIN_PAIR["target"]:
        raise SystemExit("paired commissioning requires the literal approved target serial 77CD44653A967172")


def _commission_preload(args: argparse.Namespace, package: Path) -> bytes:
    tools = REPO_ROOT / "bootloader" / "xiao_nrf52840_ota" / "tools"
    sys.path.insert(0, str(tools))
    from commission_pair import validate_compound_preload_package

    return validate_compound_preload_package(package, Path(args.pair_manifest))


def cmd_commission_compound(args: argparse.Namespace) -> int:
    """Explicitly preload only the verified CURRENT prefix + gap + matched stage."""
    _commission_guard(args)
    try:
        package = Path(args.package)
        expected = _commission_preload(args, package)
        script = _nrfutil_script()
        _sense_target_device("any")
        port = cmd_bootloader_port("target", args.timeout)
        if _sense_target_device().by_id != port:
            raise ValueError("target DFU port changed before compound transfer")
        print("WARNING: temporary compound prefix; no OTA/RF until ordinary APP restoration.",
              file=sys.stderr, flush=True)
        _serial_dfu(package, port, script, timeout=args.timeout)
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, struct.error) as exc:
        raise SystemExit(f"refusing paired compound commissioning: {exc}") from exc
    print(f"compound preload transport complete ({len(expected)} bytes); installed bytes not yet verified. "
          "Enter UF2 and arrange an ancestry-matched read-only mount before commission-primary.")
    return 0


def _identity_token(path: Path, *, follow: bool = True) -> tuple[int, int, int, int]:
    metadata = path.stat() if follow else path.lstat()
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_rdev


def _volume_identity(device: Device, mounted: _ReadOnlyTargetVolume) -> tuple:
    import install_uf2

    tty_link = install_uf2.device_sysfs_link(device.by_id, SYS_DEV_CHAR)
    return tuple((_identity_token(path, follow=False), _identity_token(path),
                  str(path.resolve(strict=True)))
                 for path in (device.sysfs, device.by_id, tty_link,
                              mounted.block_link, mounted.path))


def _commission_block_device(device: Device) -> tuple[Path, Path]:
    import install_uf2

    if not _has_msc_interface(device):
        raise ValueError("approved target bootloader must expose its own MSC class08 interface")
    node = device.sysfs.resolve(strict=True)
    links = [link for link in SYS_DEV_BLOCK.iterdir()
             if node in link.resolve(strict=True).parents]
    if len(links) != 1:
        raise ValueError(f"expected one unambiguous target USB block device, found {len(links)}")
    link = links[0]
    if install_uf2.usb_serial_ancestor(link) != APPROVED_ADMIN_PAIR["target"]:
        raise ValueError("block device ancestry does not match the approved target serial")
    block = link.resolve(strict=True)
    fields = {}
    for line in (block / "uevent").read_text().splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise ValueError("malformed target block uevent")
        fields[key] = value
    name = fields.get("DEVNAME", "")
    if (fields.get("DEVTYPE") != "disk" or (block / "partition").exists()
            or not name.isascii() or not name.isalnum() or name != block.name
            or (block / "dev").read_text().strip() != link.name):
        raise ValueError("target must expose exactly one whole USB disk with a safe kernel device name")
    major, minor = (int(value) for value in link.name.split(":"))
    path = DEV_DIR / name
    metadata = path.lstat()
    if not stat.S_ISBLK(metadata.st_mode) or metadata.st_rdev != os.makedev(major, minor):
        raise ValueError("target device path must be a real matching block node, not a symlink")
    return path, link


def cmd_mount_commission_uf2(args: argparse.Namespace) -> int:
    """Mount only the approved already-BOOT+MSC target read-only; never remount."""
    _commission_guard(args)
    try:
        device = _sense_target_device()
        import install_uf2

        block, link = _commission_block_device(device)
        tty_link = install_uf2.device_sysfs_link(device.by_id, SYS_DEV_CHAR)
        paths = (device.sysfs, device.by_id, tty_link, link, block)
        identity = tuple((_identity_token(path, follow=False), _identity_token(path))
                         for path in paths)
        mounts = install_uf2.matching_mounts(
            APPROVED_ADMIN_PAIR["target"], MOUNTINFO, SYS_DEV_BLOCK)
        existing = None
        if mounts:
            try:
                existing = _read_only_target_volume(device)
            except ValueError as exc:
                raise ValueError(f"existing target mount refused; no automatic unmount/remount: {exc}") from exc
        else:
            rc, output = _run(["udisksctl", "mount", "--block-device", str(block),
                              "--options", "ro"], args.timeout)
            if rc != 0:
                raise ValueError(f"udisksctl read-only mount failed (exit {rc}); "
                                 f"no retry or remount: {output}")
        final_device = _sense_target_device()
        if (final_device != device or _commission_block_device(final_device) != (block, link)
                or tuple((_identity_token(path, follow=False), _identity_token(path))
                         for path in paths) != identity):
            raise ValueError("target USB/block identity changed during read-only mounting")
        mounted = _read_only_target_volume(final_device)
        if existing is not None and mounted != existing:
            raise ValueError("existing read-only target mount records changed")
    except (OSError, ValueError) as exc:
        raise SystemExit(f"refusing target read-only commissioning mount: {exc}") from exc
    print(mounted.path)
    return 0


def _read_compound_current(expected: bytes) -> Device:
    """Seek only to APP/installer UF2 blocks; never read the virtual filesystem spans."""
    from commission_pair import APP_START, STAGE_END, verify_compound_preload_readback
    import install_uf2

    device = _sense_target_device()
    mounted = _read_only_target_volume(device)
    identity = _volume_identity(device, mounted)
    current = mounted.path / "CURRENT.UF2"
    descriptor = os.open(current, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        blocks = (0xEA000 - 0x1000) // 256
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != blocks * 512:
            raise ValueError("CURRENT.UF2 must be a regular file with exact virtual 0x1000..0xEA000 geometry")

        def read_at(address: int, count: int) -> bytes:
            if (type(address) is not int or type(count) is not int or not 0 < count <= 4096
                    or address < APP_START or address + count > APP_START + len(expected)
                    or address + count > STAGE_END):
                raise ValueError("CURRENT.UF2 callback exceeds authorized bounded APP/installer read")
            result = bytearray()
            stop = address + count
            for target in range(address & ~255, stop, 256):
                index = (target - 0x1000) // 256
                block = os.pread(descriptor, 512, index * 512)
                if len(block) != 512:
                    raise ValueError(f"short CURRENT.UF2 block at 0x{target:05X}")
                header = struct.unpack_from("<8I", block)
                if (header != (install_uf2.UF2_MAGIC_START0, install_uf2.UF2_MAGIC_START1,
                               install_uf2.UF2_FLAG_FAMILY_ID_PRESENT, target, 256,
                               index, blocks, install_uf2.USB_BOARD_IDS["xiao_nrf52840_sense"])
                        or struct.unpack_from("<I", block, 508)[0] != install_uf2.UF2_MAGIC_END):
                    raise ValueError(f"invalid CURRENT.UF2 magic/flags/address/block/family at 0x{target:05X}")
                first, last = max(address, target) - target, min(stop, target + 256) - target
                result.extend(block[32 + first:32 + last])
            return bytes(result)

        verify_compound_preload_readback(read_at, expected)
        if MOUNTINFO.read_text(encoding="utf-8") != mounted.mount_text:
            raise ValueError("mount records changed during compound readback")
        final_device = _sense_target_device()
        final_mount = _read_only_target_volume(final_device)
        if (final_device != device or final_mount != mounted
                or _volume_identity(final_device, final_mount) != identity
                or _identity_token(current, follow=False) != (
                    metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_rdev)
                or os.fstat(descriptor).st_size != metadata.st_size):
            raise ValueError("mount/device/CURRENT identity changed during compound readback")
    finally:
        os.close(descriptor)
    return device


def cmd_commission_primary(args: argparse.Namespace) -> int:
    """Verify the live compound, then transfer its exact bootloader-only primary."""
    _commission_guard(args)
    try:
        package = Path(args.package)
        expected = _commission_preload(args, Path(args.preload_package))
        import package_pair

        pair_manifest = Path(args.pair_manifest)
        primary, stage, _ = package_pair.verify_pair(pair_manifest.parent)
        if package_pair.compound_payload(expected[:package_pair.CURRENT_APP_BYTES], stage) != expected:
            raise ValueError("verified pair stage changed since compound package validation")
        if len(primary) != 40960:
            raise ValueError("matched primary RAW must be exactly 40960 bytes")
        _, init = package_pair.package_payload(package, "bootloader", primary)
        if init["application_version"] != 0x902 or init["device_revision"] != 52840:
            raise ValueError("bootloader standard init does not match the Sense ROLE1 pair")
        script = _nrfutil_script()
        device = _read_compound_current(expected)
        print(f"live compound CURRENT.UF2 readback verified ({len(expected)} bytes); "
              "transferring matched bootloader-only primary.", flush=True)
        _serial_dfu(package, device.by_id, script, timeout=args.timeout)
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, struct.error) as exc:
        raise SystemExit(f"refusing paired primary commissioning: {exc}") from exc
    print("bootloader-only transport complete; activation not yet verified. "
          "Expected E1: first new-primary boot may advertise BLE indefinitely WITHOUT USB. "
          "ROOT: request ONE physical pin reset, then check persistent R1 UF2 USB. "
          "Do not retry loader writes or power-cycle. "
          "CURRENT.UF2 and ACK/INFO do not expose the installed-primary SHA-256.")
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
    if args.role not in APPROVED_ADMIN_PAIR or roles[args.role] != APPROVED_ADMIN_PAIR[args.role]:
        raise SystemExit(f"refusing unapproved active lab role '{args.role}' "
                         f"(serial {roles[args.role]})")
    sysfs = sysfs_for_serial(roles[args.role])
    if sysfs is None:
        diagnostics = _attached_usb_diagnostics(roles[args.role])
        if diagnostics:
            raise SystemExit(f"role '{args.role}' is attached but unavailable for guarded power "
                             "control:\n  " + "\n  ".join(diagnostics))
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

    extract = sub.add_parser("extract-application",
                             help="extract the validated raw application from an existing DFU package; no board access")
    extract.add_argument("--package", required=True)
    extract.add_argument("--output", required=True)
    extract.set_defaults(func=cmd_extract_application)

    add_role_command("path", cmd_path, help_text="print the stable by-id path for a role")
    add_role_command("serial", cmd_serial, help_text="print the USB serial pinned to a role")
    add_role_command("wait", cmd_wait, mode_default=MODE_APP,
                     help_text="block until a role enumerates")
    reset = add_role_command("reset", cmd_reset, mode_default=MODE_APP,
                             help_text="restart the application firmware")
    reset.add_argument("--protocol", choices=["companion", "repeater"], required=True,
                       help="serial protocol of the installed application")
    add_role_command("bootloader", cmd_bootloader, mode_default=MODE_BOOT,
                     help_text="enter the serial DFU bootloader (1200-baud touch)")
    uf2 = sub.add_parser("bootloader-uf2",
                         help="reboot the approved target application into UF2 and require MSC")
    uf2.add_argument("role", choices=["target"])
    uf2.add_argument("--timeout", type=float, default=30.0)
    uf2.set_defaults(func=cmd_bootloader_uf2)
    mount = sub.add_parser("mount-commission-uf2",
                           help="mount only approved already-BOOT+MSC target read-only via udisksctl; existing RW mount refused")
    mount.add_argument("role", choices=["target"])
    mount.add_argument("--timeout", type=float, default=30.0)
    mount.set_defaults(func=cmd_mount_commission_uf2)
    stock = sub.add_parser("inspect-stock-bootloader",
                           help="read approved target stock Sense INFO from an already read-only mounted MSC; no serial or writes")
    stock.add_argument("role", choices=["target"])
    stock.set_defaults(func=cmd_inspect_stock_bootloader)
    flash = add_role_command("flash", cmd_flash, mode_default=MODE_APP,
                             help_text="flash a DFU package and return to the application")
    flash.add_argument("--package", required=True, help="path to firmware.zip")
    for name, handler, help_text in (
            ("commission-compound", cmd_commission_compound,
             "explicit matched Sense ROLE1 compound preload; ordinary flash gate unchanged"),
            ("commission-primary", cmd_commission_primary,
             "live bounded compound readback on already read-only MSC, then matched boot-only DFU; no APP/USB wait")):
        commission = sub.add_parser(name, help=help_text)
        commission.add_argument("role", choices=["target"])
        commission.add_argument("--package", required=True)
        commission.add_argument("--pair-manifest", required=True)
        commission.add_argument("--timeout", type=float, default=120.0)
        if name == "commission-primary":
            commission.add_argument("--preload-package", required=True)
        commission.set_defaults(func=handler)
    cycle = add_role_command("power-cycle", cmd_power_cycle, mode_default=MODE_APP,
                             help_text="cut and restore USB port power")
    cycle.add_argument("--delay", type=int, default=3, help="seconds to stay powered down")

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
