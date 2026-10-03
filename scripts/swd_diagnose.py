#!/usr/bin/env python3
"""Bounded, non-erasing SWD diagnosis for the one approved inaccessible target."""

from __future__ import annotations

import argparse
import configparser
import importlib.metadata
import json
from pathlib import Path
import re
import sys
import time
from datetime import datetime, timezone
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
APPROVED_SERIAL = "3BE94917B92DC5E9"
PYOCD_VERSION = "0.43.1"
DHCSR = 0xE000EDF0
DBGKEY = 0xA05F0000
OPTIONS = {
    "target_override": "nrf52840",
    "connect_mode": "attach",
    "auto_unlock": False,
    "resume_on_disconnect": False,
    "no_config": True,
    "pack": None,
    "cbuild_run": None,
    "dap_protocol": "swd",
    "frequency": 100000,
    "scan_all_aps": False,
    "cache.enable_memory": False,
    "cache.enable_register": False,
    "cache.read_code_from_elf": False,
    "project_dir": str(ROOT),
}
EXPECTED_ADDRESSES = {
    "mbr_boot": "0xFFFFFFFF", "mbr_params": "0xFFFFFFFF",
    "uicr_boot": "0x000F4000", "uicr_params": "0x000FE000",
    "effective_boot": "0x000F4000", "effective_params": "0x000FE000",
}
PUBLIC_WORDS = {
    0x10000060, 0x10000064, 0x10000100, 0x10000104, 0x10000108,
    0x00000FF8, 0x00000FFC, 0x10001014, 0x10001018,
    *range(0xFF000, 0xFF01C, 4),
    *range(0xFDC00, 0xFDC10, 4),
    0xE000ED08, 0xE000ED24, 0xE000ED28, 0xE000ED2C,
    0xE000ED30, 0xE000ED34, 0xE000ED38, 0xE000ED3C,
    0x40010400, 0x4001050C, 0x40010504,  # WDT RUNSTATUS, CONFIG, CRV.
    0x40000400, 0x4000051C, 0x20007F7C,  # RESETREAS, GPREGRET, reserved double-reset word.
    DHCSR,
}
CPU_REGISTERS = ("pc", "sp", "lr", "xpsr", "msp", "psp")


class Refusal(RuntimeError):
    pass


class VectorPolicyRefusal(Refusal):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def hex32(value):
    return f"0x{value:08X}"


def load_pyocd():
    try:
        dist = importlib.metadata.distribution("pyocd")
    except importlib.metadata.PackageNotFoundError as exc:
        raise Refusal(f"optional dependency missing; install pyocd=={PYOCD_VERSION}") from exc
    if dist.version != PYOCD_VERSION:
        raise Refusal(f"unsupported pyOCD {dist.version}; qualified API version is {PYOCD_VERSION}")
    from pyocd.core.session import Session
    from pyocd.core.target import Target
    from pyocd.probe.cmsis_dap_probe import CMSISDAPProbe
    from pyocd.target.builtin.target_nRF52840_xxAA import NRF52840
    import pyocd

    package = dist.locate_file("pyocd")
    if Path(pyocd.__file__).resolve().parent != package.resolve():
        raise Refusal("imported pyOCD differs from the qualified installed package; no attach allowed")

    # no_config does NOT disable pyocd_user.py. Suppress that separate loader entirely.
    class DiagnosisSession(Session):
        def _load_user_script(self):
            pass

    return SimpleNamespace(Session=DiagnosisSession, Probe=CMSISDAPProbe,
                           State=Target.State, NRF52840=NRF52840)


def validate_request(args):
    if not args.probe_uid or args.probe_uid.strip() != args.probe_uid:
        raise Refusal("an explicit complete probe UID is required (no first-available selection)")
    if args.role != "target" or args.target_serial != APPROVED_SERIAL:
        raise Refusal("only the explicitly approved target role/serial may be diagnosed")
    config = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    with args.config.open() as stream:
        config.read_file(stream)
    # A present recovery section is authoritative, even when its target is missing.
    target_section = "recovery" if config.has_section("recovery") else "roles"
    if "target" in config.defaults():
        raise Refusal("inventory target must be explicit, not inherited from DEFAULT")
    if config.get(target_section, "target", fallback="").strip() != args.target_serial:
        raise Refusal(f"approved target serial does not match lab [{target_section}] inventory; "
                      "environment overrides ignored")
    other_serials = [
        value.strip()
        for section in ("roles", "recovery", "protected") if config.has_section(section)
        for key, value in config.items(section)
        if (section, key) != (target_section, "target")
    ]
    if args.target_serial in other_serials:
        raise Refusal("target is also assigned to a protected or other role")
    if not re.fullmatch(r"[0-9A-F]{16}", args.target_serial):
        raise Refusal("target serial must be the full uppercase vendor USB serial")


class Readout:
    def __init__(self, result):
        self.result = result
        self.vector_words = set()

    def word(self, reader, address, label):
        if address not in PUBLIC_WORDS and address not in self.vector_words:
            raise Refusal(f"read outside bounded public whitelist: {hex32(address)}")
        value = reader.read32(address)
        self.result["reads"].append({"label": label, "address": hex32(address), "value": hex32(value)})
        return value

    def vector(self, reader, address):
        # Never chase an untrusted pointer into application data, FS, QSPI, RAM, or journals.
        if address % 0x1000 or not 0xF4000 <= address <= 0xFD000:
            raise VectorPolicyRefusal(f"effective boot vector outside approved boot span: {hex32(address)}")
        self.vector_words = {address, address + 4}
        return [self.word(reader, address, "boot_msp"),
                self.word(reader, address + 4, "boot_reset_handler")]


class DiagnosisInit:
    def __init__(self, readout, serial):
        self.readout = readout
        self.serial = serial
        self.identity_verified = False

    def will_init_target(self, target, init_sequence):
        for name in ("unlock_device", "create_flash", "load_svd"):
            init_sequence.remove_task(name)

        def restrict_discovery(seq):
            # Check APPROTECT before any system-memory access. Replace rather than rely on auto_unlock.
            seq.replace_task("check_ctrl_ap_idr", lambda: self.check_ctrl_ap(target))
            seq.replace_task("check_flash_security", lambda: self.check_security(target))
            seq.remove_task("persist_unlock").remove_task("check_part_info")
            seq.remove_task("create_components")  # Do not disable existing FPB/DWT instrumentation.
            seq.insert_before("find_components", ("diagnosis_identity", lambda: self.identity(target)))
            return seq

        init_sequence.wrap_task("discovery", restrict_discovery)

    def start_debug_core(self, core):
        # Suppress attach's DHCSR rewrite, including C_HALT bits unknown when C_DEBUGEN is clear.
        # An already halted core has debug enabled; our later explicit halt enables it otherwise.
        return True

    def check_ctrl_ap(self, target):
        target.ctrl_ap = target.aps.get(1)
        if target.ctrl_ap is None:
            raise Refusal("Nordic CTRL-AP unavailable; no debug/recovery/reset fallback")
        if (target.ctrl_ap.idr & 0x0FFFFFFF) != 0x02880000:
            raise Refusal("unexpected Nordic CTRL-AP identity; no unlock/reset/erase attempted")

    def check_security(self, target):
        status = target.ctrl_ap.read_reg(0x00C)
        self.readout.result["identity"]["approtect_status"] = hex32(status)
        if status != 1:
            raise Refusal("APPROTECT enabled or debug unavailable; never recover, unlock, or mass erase")

    def identity(self, target):
        ahb = target.aps.get(0)
        if ahb is None:
            raise Refusal("AHB-AP debug access unavailable; no unlock/recovery/reset fallback")
        low = self.readout.word(ahb, 0x10000060, "ficr_deviceid0")
        high = self.readout.word(ahb, 0x10000064, "ficr_deviceid1")
        # Pinned vendor usb_desc_init reverses eight little-endian DEVICEID bytes into hex.
        serial = f"{high:08X}{low:08X}"
        self.readout.result["identity"].update(observed_serial=serial, deviceid=[hex32(low), hex32(high)])
        part = self.readout.word(ahb, 0x10000100, "ficr_part")
        self.readout.result["identity"]["part"] = hex32(part)
        if serial != self.serial or part != 0x52840:
            raise Refusal("FICR target identity mismatch; stopped before core creation/halt/resume")
        self.readout.word(ahb, 0x10000104, "ficr_variant")
        self.readout.word(ahb, 0x10000108, "ficr_package")
        self.identity_verified = True


def acquire(target, readout):
    addresses = {}
    for label, address in (("mbr_boot", 0xFF8), ("mbr_params", 0xFFC),
                           ("uicr_boot", 0x10001014), ("uicr_params", 0x10001018)):
        addresses[label] = readout.word(target, address, label)
    addresses["effective_boot"] = (addresses["uicr_boot"] if addresses["mbr_boot"] == 0xFFFFFFFF
                                   else addresses["mbr_boot"])
    addresses["effective_params"] = (addresses["uicr_params"] if addresses["mbr_params"] == 0xFFFFFFFF
                                     else addresses["mbr_params"])
    readout.result["actual_addresses"] = {k: hex32(v) for k, v in addresses.items()}
    for label, actual in readout.result["actual_addresses"].items():
        if actual != EXPECTED_ADDRESSES[label]:
            readout.result["observations"].append(f"{label} differs from EXPECTED; no repair attempted")
    readout.result["boot_vector"] = None
    try:
        readout.result["boot_vector"] = [hex32(v) for v in readout.vector(target, addresses["effective_boot"])]
    except VectorPolicyRefusal as exc:
        readout.result["errors"].append({
            "phase": "boot_vector", "address": hex32(addresses["effective_boot"]), "message": str(exc),
        })
    sdk = [readout.word(target, address, "sdk_settings_header")
           for address in range(0xFF000, 0xFF01C, 4)]
    readout.result["sdk_header_reference_layout"] = {
        "bank_0_code": sdk[0] & 0xFFFF, "bank_0_crc": sdk[0] >> 16, "bank_1_code": sdk[1] & 0xFFFF,
        "bank_0_size": sdk[2], "sd_image_size": sdk[3], "bl_image_size": sdk[4],
        "app_image_size": sdk[5], "sd_image_start": hex32(sdk[6]),
    }
    for address in range(0xFDC00, 0xFDC10, 4):
        readout.word(target, address, "ota_marker_header")
    for label, address in (("vtor", 0xE000ED08), ("shcsr", 0xE000ED24), ("cfsr", 0xE000ED28),
                           ("hfsr", 0xE000ED2C), ("dfsr", 0xE000ED30), ("mmfar", 0xE000ED34),
                           ("bfar", 0xE000ED38), ("afsr", 0xE000ED3C)):
        readout.word(target, address, label)
    runstatus = readout.word(target, 0x40010400, "wdt_runstatus")
    config = readout.word(target, 0x4001050C, "wdt_config")
    crv = readout.word(target, 0x40010504, "wdt_crv")
    readout.result["watchdog"] = {
        "runstatus": hex32(runstatus), "config": hex32(config), "crv": hex32(crv),
        "running": bool(runstatus & 1), "halt_behavior": "run" if config & 8 else "pause",
    }
    readout.result["boot_metadata"] = {
        label: hex32(readout.word(target, address, label))
        for label, address in (("resetreas", 0x40000400), ("gpregret", 0x4000051C),
                               ("double_reset_word", 0x20007F7C))
    }


def restore_cpu(target, readout, api, original, original_debug_enabled, halt_requested):
    result = readout.result
    cpu = result["cpu"]
    runnable = (api.State.RUNNING, api.State.SLEEPING)
    resume_ok = False
    if halt_requested:
        try:
            if target.get_state() == api.State.HALTED:
                target.resume()
            if target.get_state() not in runnable:
                raise Refusal("CPU did not resume normally; no forced resume or reset fallback")
            resume_ok = True
        except (Exception, KeyboardInterrupt) as exc:
            result["errors"].append({"phase": "state_restore", "message": str(exc)})
    if original_debug_enabled is not None:
        if halt_requested and resume_ok and not original_debug_enabled:
            try:
                if target.get_state() not in runnable:
                    raise Refusal("CPU is no longer runnable; refusing DHCSR clear that could force resume")
                # The only direct write: restore halting debug off after normal resume, never DEMCR.
                target.write32(DHCSR, DBGKEY)
                target.flush()
            except (Exception, KeyboardInterrupt) as exc:
                result["errors"].append({"phase": "debug_enable_restore", "message": str(exc)})
        try:
            final_dhcsr = readout.word(target, DHCSR, "dhcsr_final")
            cpu["final_dhcsr"] = hex32(final_dhcsr)
            cpu["final_debug_enabled"] = bool(final_dhcsr & 1)
            cpu["debug_enable_restored"] = cpu["final_debug_enabled"] == original_debug_enabled
            if not cpu["debug_enable_restored"]:
                raise Refusal("original C_DEBUGEN not restored; no forced resume or reset fallback")
        except (Exception, KeyboardInterrupt) as exc:
            result["errors"].append({"phase": "debug_enable_restore", "message": str(exc)})
    try:
        final = target.get_state()
        cpu["final_state"] = final.name
        cpu["state_restored"] = final in runnable if original in runnable else final == original
        if not cpu["state_restored"]:
            raise Refusal("original CPU run/halt state not restored; no reset fallback")
    except (Exception, KeyboardInterrupt) as exc:
        result["errors"].append({"phase": "state_restore", "message": str(exc)})


def diagnose(args):
    result = {
        "schema": "meshcore-swd-diagnosis-v1", "ok": False, "status": "acquisition_failed",
        "started_at": utc_now(), "completed_at": None,
        "identity": {"role": args.role, "approved_serial": args.target_serial, "target_type": "nrf52840",
                     "observed_serial": None, "probe_uid_requested": args.probe_uid, "probe_uid": None},
        "expected_addresses": EXPECTED_ADDRESSES.copy(), "actual_addresses": None,
        "reads": [], "cpu": {}, "errors": [], "observations": [],
        "limitations": [
            "Expected addresses are not measurements; prior address evidence is expired.",
            "Readout is not an installed image hash, commissioning acceptance, or cause determination.",
            "SDK header/OTA marker may be malformed; raw words are not an image validation.",
            "Halt/resume affects volatile debug state and timing; no reset or nonvolatile writes.",
        ],
    }
    session = target = None
    original = None
    original_debug_enabled = None
    halt_requested = False
    phase = "request"
    try:
        validate_request(args)
        phase = "api"
        api = load_pyocd()
        result["pyocd_version"] = PYOCD_VERSION
        phase = "probe_selection"
        probes = api.Probe.get_all_connected_probes(unique_id=args.probe_uid, is_explicit=True)
        matches = [p for p in probes if p.unique_id == args.probe_uid]
        if len(matches) != 1:
            raise Refusal("exact CMSIS-DAP probe UID absent or ambiguous; no fallback or retry")
        probe = matches[0]
        result["identity"].update(probe_uid=probe.unique_id, probe_vendor=probe.vendor_name,
                                  probe_product=probe.product_name)
        phase = "attach"
        session = api.Session(probe, auto_open=False, options=OPTIONS.copy())
        target = session.target
        if type(target) is not api.NRF52840:
            raise Refusal("not the qualified built-in NRF52840 target; no attach allowed")
        for name, value in OPTIONS.items():
            if session.options.get(name) != value:
                raise Refusal(f"unsafe effective pyOCD option: {name}")
        readout = Readout(result)
        guard = DiagnosisInit(readout, args.target_serial)
        session.delegate = guard
        session.open()
        if not guard.identity_verified:
            raise Refusal("init did not verify full FICR identity; no halt permitted")
        phase = "readout"
        original = target.get_state()
        result["cpu"].update(original_state=original.name, final_state=None, state_restored=False,
                              original_debug_enabled=None, final_debug_enabled=None,
                              debug_enable_restored=False)
        original_dhcsr = readout.word(target, DHCSR, "dhcsr_original")
        original_debug_enabled = bool(original_dhcsr & 1)
        result["cpu"].update(original_dhcsr=hex32(original_dhcsr),
                              original_debug_enabled=original_debug_enabled)
        acquire(target, readout)  # Capture SCB fault status before our halt changes DFSR.
        runnable = (api.State.RUNNING, api.State.SLEEPING)
        if original not in (*runnable, api.State.HALTED):
            raise Refusal(f"CPU state {original.name}: no halt/resume/reset attempted")
        if original in runnable:
            watchdog = result["watchdog"]
            if watchdog["runstatus"] not in ("0x00000000", "0x00000001"):
                raise Refusal("unrecognized watchdog status; CPU snapshot refused without feed/reconfiguration")
            if watchdog["running"] and watchdog["halt_behavior"] == "run":
                raise Refusal("active watchdog runs during debug halt; CPU snapshot refused; no feed/reconfiguration")
            halt_requested = True
            target.halt()
            deadline = time.monotonic() + 1.0
            while target.get_state() != api.State.HALTED:
                if time.monotonic() >= deadline:
                    raise Refusal("CPU did not halt; no reset/recovery attempted")
                time.sleep(0.01)
        result["cpu"]["registers"] = {name: hex32(target.read_core_register_raw(name))
                                      for name in CPU_REGISTERS}
    except (Exception, KeyboardInterrupt) as exc:
        result["errors"].append({"phase": phase, "message": str(exc) or type(exc).__name__})
    finally:
        if target is not None and original is not None:
            restore_cpu(target, readout, api, original, original_debug_enabled, halt_requested)
        if session is not None and session.probe.is_open:
            # Session.close() swallows transport errors. Surface each teardown failure instead.
            for label, action in (("detach", lambda: target.disconnect(resume=False)),
                                  ("probe_disconnect", session.probe.disconnect),
                                  ("probe_close", session.probe.close)):
                try:
                    action()
                except (Exception, KeyboardInterrupt) as exc:
                    result["errors"].append({"phase": label, "message": str(exc)})
        result["completed_at"] = utc_now()
    result["ok"] = not result["errors"]
    if result["ok"]:
        result["status"] = "acquired_not_installation_proof"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    physical = sub.add_parser("diagnose", help="PHYSICAL: only after explicit authorization and fixture identification")
    physical.add_argument("--probe-uid", required=True)
    physical.add_argument("--role", required=True, choices=("target",))
    physical.add_argument("--target-serial", required=True)
    physical.add_argument("--config", type=Path, default=ROOT / "lab" / "devices.ini")
    args = parser.parse_args(argv)
    result = diagnose(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
