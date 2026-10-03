#!/usr/bin/env python3
"""Configure, monitor, inspect normal channels/OTA diagnostics, or grant administrator access.

Configuration preserves existing identities and ACLs. Readbacks describe current
settings, not active RF, reboot persistence, transfer, install, or trial evidence.
Repeater settings are preference readbacks; radio application requires a separate
reboot. This helper never reboots.
Only --grant-client-admin changes an ACL, using the existing normal text CLI.
Use ota_uploader.py for the signed USB uploader and its explicit commit operation.
--inspect-channels only reads the approved companion's advertised channel table.
Channel response secrets are never logged; inventory contains public names/indices.
--inspect-measurements reads approved USB-local driver-applied radio and completed
software airtime diagnostics. It does not qualify PHY registers or a duty guarantee.
"""

import argparse
import json
import math
import os
import re
import select
import struct
import sys
import termios
import time
from datetime import datetime, timezone
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_device  # noqa: E402

# Boards are addressed by lab role (see lab/devices.ini), never by a literal
# serial or ttyACMn, so the lab survives re-cabling and board swaps.
CLIENT_ROLE = os.environ.get("MESHCORE_LAB_CLIENT_ROLE", "client")
TARGET_ROLE = os.environ.get("MESHCORE_LAB_TARGET_ROLE", "target")
APPROVED_ADMIN_PAIR = lab_device.APPROVED_ADMIN_PAIR
CLIENT_ACL_ADMIN = 3
ACL_LAZY_SAVE_WAIT_SECONDS = 6.0

CMD_APP_START = 1
CMD_SET_ADVERT_NAME = 8
CMD_SET_RADIO_PARAMS = 11
CMD_DEVICE_QUERY = 22
CMD_GET_CHANNEL = 31
CMD_SIGN_START = 33
CMD_SIGN_DATA = 34
CMD_SIGN_FINISH = 35
CMD_SET_PATH_HASH_MODE = 61
CMD_OTA_CONTROL = 66  # Existing USB uploader ABI, implemented only by ota_uploader.py.

RESP_OK = 0
RESP_ERR = 1
RESP_SELF_INFO = 5
RESP_DEVICE_INFO = 13
RESP_CHANNEL_INFO = 18
RESP_OTA_STATUS = 29
RESP_SIGN_START = 19
RESP_SIGNATURE = 20
MAX_SERIAL_FRAME_SIZE = 176
ADV_TYPE_CHAT = 1  # src/helpers/AdvertDataHelpers.h

NORMAL_RADIO = (907525, 62500, 7, 5)
SUPPORTED_LORA_BANDWIDTHS_HZ = (
    7800, 10400, 15600, 20800, 31250, 41700, 62500, 125000, 250000, 500000,
)
PATH_HASH_MODE = 2
CLIENT_NAME = "OTA-LAB-CLIENT"
TARGET_NAME = "OTA-LAB-TARGET"
RADIO_MEASUREMENT_FIELDS = ("f", "b", "s", "c", "v", "a", "e", "d", "r", "td", "tr", "h", "x", "af", "n")
BUDGET_MEASUREMENT_FIELDS = ("n", "w", "b", "u", "tx", "to", "af")
RADIO_MEASUREMENT_PATTERN = re.compile(
    r"src=driver-applied f=(0|[1-9][0-9]*) b=(0|[1-9][0-9]*) s=(0|[1-9][0-9]*) "
    r"c=(0|[1-9][0-9]*) v=([01]) a=([01]) e=([0-9A-F]{8}) d=([0-9A-F]{8}) "
    r"r=([0-9A-F]{8}) td=([0-9A-F]{8}) tr=([0-9A-F]{8}) h=([01]) x=([0-9A-F]{8}) "
    r"af=([0-9A-F]{8}) n=([0-9A-F]{8})")
BUDGET_MEASUREMENT_PATTERN = re.compile(
    " ".join(field + r"=([0-9A-F]{8})" for field in BUDGET_MEASUREMENT_FIELDS))


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class Evidence:
    def __init__(self, directory, *, exclusive=False):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=not exclusive)
        self.events_path = self.directory / "serial-events.jsonl"
        self.summary_path = self.directory / "summary.json"
        self.events = self.events_path.open("a", encoding="utf-8")
        self.summary = {"started_at": utc_now(), "checks": {}, "measurements": {}}

    def log(self, event, **fields):
        row = {"time": utc_now(), "monotonic": time.monotonic(), "event": event, **fields}
        self.events.write(json.dumps(row, sort_keys=True) + "\n")
        self.events.flush()
        print(json.dumps(row, sort_keys=True), flush=True)

    def check(self, name, passed, **details):
        self.summary["checks"][name] = {"passed": bool(passed), **details}
        self.log("check", name=name, passed=bool(passed), **details)
        if not passed:
            raise AssertionError(f"{name}: {details}")

    def finish(self, error=None):
        self.summary["finished_at"] = utc_now()
        self.summary["error"] = error
        self.summary_path.write_text(json.dumps(self.summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.events.close()


class LabSerial:
    def __init__(self, name, path, evidence):
        if not str(path).startswith("/dev/serial/by-id/"):
            raise RuntimeError(f"refusing unstable device path: {path}")
        self.name = name
        self.path = path
        self.evidence = evidence
        self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        attrs = termios.tcgetattr(self.fd)
        attrs[0] = 0
        attrs[1] = 0
        attrs[2] = termios.CS8 | termios.CLOCAL | termios.CREAD
        attrs[3] = 0
        attrs[4] = termios.B115200
        attrs[5] = termios.B115200
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = 0
        termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
        termios.tcflush(self.fd, termios.TCIOFLUSH)
        evidence.log("serial_open", node=name, path=path, resolved=os.path.realpath(path))

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def _write_bytes(self, frame):
        offset = 0
        while offset < len(frame):
            _, writable, _ = select.select([], [self.fd], [], 2.0)
            if not writable:
                raise TimeoutError(f"{self.name}: serial write timeout")
            written = os.write(self.fd, frame[offset:])
            if written == 0:
                raise ConnectionError(f"{self.name}: serial write made no progress")
            offset += written

    def _read_bytes(self, timeout):
        readable, _, _ = select.select([self.fd], [], [], timeout)
        if not readable:
            return b""
        chunk = os.read(self.fd, 4096)
        if not chunk:
            raise ConnectionError(f"{self.name}: serial disconnected")
        return chunk


def public_channel_info(frame):
    if len(frame) != 50 or frame[0] != RESP_CHANNEL_INFO or frame[1] == 255:
        raise ValueError("malformed channel response: expected code 18, index 0..254 and 50 bytes")
    name_field = frame[2:34]
    terminator = name_field.find(b"\x00")
    if terminator < 0:
        raise ValueError("malformed channel response: unterminated name")
    try:
        name = name_field[:terminator].decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("malformed channel response: invalid UTF-8 name") from None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
        raise ValueError("malformed channel response: control character in name")
    # The producer uses strcpy, so bytes after the name's NUL are not padding.
    return {"index": frame[1], "name": name, "configured": bool(name)}


class FramedSerial(LabSerial):
    def __init__(self, name, path, evidence):
        super().__init__(name, path, evidence)
        self.buffer = bytearray()
        self.pending = []

    def write_frame(self, payload):
        if len(payload) > MAX_SERIAL_FRAME_SIZE:
            raise ValueError(f"serial frame too large: {len(payload)}")
        self._write_bytes(b"<" + struct.pack("<H", len(payload)) + payload)
        self.evidence.log("serial_tx", node=self.name, length=len(payload), hex=payload.hex())

    def _extract(self):
        frames = []
        while True:
            marker = self.buffer.find(b">")
            if marker < 0:
                self.buffer.clear()
                break
            if marker:
                del self.buffer[:marker]
            if len(self.buffer) < 3:
                break
            length = self.buffer[1] | (self.buffer[2] << 8)
            if len(self.buffer) < 3 + length:
                break
            payload = bytes(self.buffer[3:3 + length])
            del self.buffer[:3 + length]
            frames.append(payload)
        return frames

    def poll(self, timeout=0.0):
        self.buffer.extend(self._read_bytes(timeout))
        for payload in self._extract():
            self.pending.append((time.monotonic(), payload))
            fields = {"node": self.name, "length": len(payload), "code": payload[0] if payload else None}
            if payload and payload[0] == RESP_CHANNEL_INFO:
                fields["redacted"] = True
                try:
                    public = public_channel_info(payload)
                except ValueError:
                    fields["malformed"] = True
                else:
                    fields.update(public)
            else:
                fields["hex"] = payload.hex()
            self.evidence.log("serial_rx", **fields)

    def wait_frame(self, codes, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.poll(min(0.1, deadline - time.monotonic()))
            for index, (_, payload) in enumerate(self.pending):
                if payload and payload[0] in codes:
                    self.pending.pop(index)
                    return payload
        raise TimeoutError(f"{self.name}: no frame with code {sorted(codes)}")

    def command(self, payload, expected=(RESP_OK, RESP_ERR), timeout=5.0):
        self.write_frame(payload)
        return self.wait_frame(set(expected), timeout)

    def collect(self, duration):
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            self.poll(min(0.1, deadline - time.monotonic()))

    def take_pending(self, codes):
        found = []
        kept = []
        for timestamp, payload in self.pending:
            if payload and payload[0] in codes:
                found.append((timestamp, payload))
            else:
                kept.append((timestamp, payload))
        self.pending = kept
        return found


class RepeaterSerial(LabSerial):
    MAX_COMMAND_BYTES = 158
    MAX_LINE_BYTES = 4096
    REPLY_PREFIX = "  -> "

    def __init__(self, name, path, evidence):
        super().__init__(name, path, evidence)
        self.buffer = bytearray()
        self.pending = []

    def _extract_lines(self):
        lines = []
        while True:
            newline = self.buffer.find(b"\n")
            if newline < 0:
                if len(self.buffer) > self.MAX_LINE_BYTES:
                    raise ValueError(f"{self.name}: oversized repeater serial line")
                return lines
            if newline > self.MAX_LINE_BYTES:
                raise ValueError(f"{self.name}: oversized repeater serial line")
            line = bytes(self.buffer[:newline]).rstrip(b"\r").decode("utf-8")
            del self.buffer[:newline + 1]
            lines.append(line)

    def poll(self, timeout=0.0):
        self.buffer.extend(self._read_bytes(timeout))
        for line in self._extract_lines():
            self.pending.append(line)
            self.evidence.log("serial_rx", node=self.name, text=line)

    def _start_command(self, command):
        payload = command.encode("ascii")
        if (not payload or len(payload) > self.MAX_COMMAND_BYTES
                or any(byte < 0x20 or byte > 0x7E for byte in payload)):
            raise ValueError("repeater command must be one bounded printable ASCII line")
        self.poll()
        self.pending.clear()
        self.buffer.clear()
        self._write_bytes(payload + b"\r")
        self.evidence.log("serial_tx", node=self.name, text=command)

    def command(self, command, timeout=5.0):
        self._start_command(command)
        deadline = time.monotonic() + timeout
        echoed = False
        while time.monotonic() < deadline:
            self.poll(max(0.0, min(0.1, deadline - time.monotonic())))
            while self.pending:
                line = self.pending.pop(0)
                if line == command:
                    echoed = True
                elif echoed and line.startswith(self.REPLY_PREFIX):
                    return line[len(self.REPLY_PREFIX):]
        raise TimeoutError(f"{self.name}: no repeater CLI reply for {command!r}")

    def get_acl(self, timeout=5.0):
        self._start_command("get acl")
        deadline = time.monotonic() + timeout
        echoed = False
        collecting = False
        barrier_echoed = False
        entries = {}
        while time.monotonic() < deadline:
            self.poll(max(0.0, min(0.1, deadline - time.monotonic())))
            while self.pending:
                line = self.pending.pop(0)
                if line == "get acl" and not collecting:
                    echoed = True
                elif echoed and line == "ACL:" and not collecting:
                    collecting = True
                    # ACL has no end marker. A later command brackets the complete list.
                    self._write_bytes(b"get role\r")
                    self.evidence.log("serial_tx", node=self.name, text="get role")
                elif collecting and line == "get role":
                    barrier_echoed = True
                elif echoed and line.startswith(self.REPLY_PREFIX):
                    reply = line[len(self.REPLY_PREFIX):]
                    if collecting and barrier_echoed and reply == "> repeater":
                        return entries
                    raise RuntimeError(f"{self.name}: unexpected ACL reply: {reply!r}")
                elif collecting:
                    row = re.fullmatch(r"([0-9a-fA-F]{2}) ([0-9a-fA-F]{64})", line)
                    if row and not barrier_echoed:
                        permissions, key = row.groups()
                        key = key.lower()
                        if key == "00" * 32:
                            raise ValueError(f"{self.name}: invalid zero ACL public key")
                        if key in entries:
                            raise ValueError(f"{self.name}: duplicate ACL public key")
                        entries[key] = int(permissions, 16)
                    elif line and not re.match(r"^[0-9]{2}:[0-9]{2}:[0-9]{2}\b", line):
                        raise ValueError(f"{self.name}: malformed ACL row: {line!r}")
        raise TimeoutError(f"{self.name}: incomplete repeater ACL response")


def app_info(node):
    payload = bytes([CMD_APP_START]) + bytes(7) + b"ota-rf-lab"
    frame = node.command(payload, expected=(RESP_SELF_INFO,))
    if len(frame) < 58:
        raise RuntimeError(f"{node.name}: short self-info frame")
    if frame[0] != RESP_SELF_INFO:
        raise RuntimeError(f"{node.name}: invalid self-info response code")
    if frame[1] != ADV_TYPE_CHAT:
        raise RuntimeError(f"{node.name}: expected companion role, advert type is {frame[1]}")
    if frame[4:36] == bytes(32):
        raise RuntimeError(f"{node.name}: invalid zero public key")
    name = frame[58:].decode("utf-8")
    if "\x00" in name:
        raise ValueError(f"{node.name}: malformed self-info name")
    return {
        "role": "companion",
        "advert_type": frame[1],
        "pubkey": frame[4:36].hex(),
        "pubkey_bytes": frame[4:36],
        "freq_khz": struct.unpack_from("<I", frame, 48)[0],
        "bw_hz": struct.unpack_from("<I", frame, 52)[0],
        "sf": frame[56],
        "cr": frame[57],
        "name": name,
    }


def require_ok(node, payload, timeout=None):
    options = {} if timeout is None else {"timeout": timeout}
    frame = node.command(payload, **options)
    if frame != bytes([RESP_OK]):
        raise RuntimeError(f"{node.name}: command failed: {frame.hex()}")


def sign_manifest(node, canonical, owner_public_key, deadline=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if len(canonical) != 59:
        raise ValueError("OTA manifest signing requires exactly 59 canonical bytes")
    verifier = Ed25519PublicKey.from_public_bytes(owner_public_key)

    def command_options():
        if deadline is None:
            return {}
        remaining = deadline - time.monotonic()
        if not math.isfinite(remaining) or remaining <= 0:
            raise TimeoutError("OTA manifest signing deadline expired")
        return {"timeout": min(5.0, remaining)}

    frame = node.command(bytes([CMD_SIGN_START]), expected=(RESP_SIGN_START, RESP_ERR),
                         **command_options())
    if len(frame) != 6 or frame[:2] != bytes([RESP_SIGN_START, 0]):
        raise RuntimeError(f"{node.name}: invalid signing-start reply: {frame.hex()}")
    if struct.unpack_from("<I", frame, 2)[0] < len(canonical):
        raise RuntimeError(f"{node.name}: signing buffer cannot hold the OTA manifest")
    require_ok(node, bytes([CMD_SIGN_DATA]) + canonical, **command_options())
    frame = node.command(bytes([CMD_SIGN_FINISH]), expected=(RESP_SIGNATURE, RESP_ERR),
                         **command_options())
    if len(frame) != 65 or frame[0] != RESP_SIGNATURE:
        raise RuntimeError(f"{node.name}: invalid signature reply: {frame.hex()}")
    signature = frame[1:]
    verifier.verify(signature, canonical)
    return signature


def serializable_app_info(info):
    return {key: value for key, value in info.items() if key != "pubkey_bytes"}


def companion_info(node):
    info = app_info(node)
    frame = node.command(bytes([CMD_DEVICE_QUERY, 13]), expected=(RESP_DEVICE_INFO,))
    if len(frame) < 82 or frame[0] != RESP_DEVICE_INFO or frame[1] < 10:
        raise RuntimeError(f"{node.name}: invalid device-info path hash readback")
    if frame[81] not in (0, 1, 2):
        raise RuntimeError(f"{node.name}: invalid path hash mode: {frame[81]}")
    return {**info, "path_hash_mode": frame[81],
            "settings_readback_scope": "companion_self_info_and_device_info"}


def repeater_value(node, command):
    reply = node.command(command)
    if not reply.startswith("> "):
        raise RuntimeError(f"{node.name}: invalid repeater reply for {command!r}: {reply!r}")
    return reply[2:]


def repeater_identity(node):
    role = repeater_value(node, "get role")
    if role != "repeater":
        raise RuntimeError(f"{node.name}: expected repeater role, got {role!r}")
    key = repeater_value(node, "get public.key")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", key) or key == "00" * 32:
        raise RuntimeError(f"{node.name}: invalid full repeater public key: {key!r}")
    return {"role": role, "pubkey": key.lower()}


def repeater_frequency_khz(value):
    mhz = Decimal(value)
    if not mhz.is_finite() or not 150 <= mhz <= 2500:
        raise ValueError(f"invalid repeater frequency readback: {value!r}")
    khz = mhz * 1000
    normalized = khz.to_integral_value(rounding=ROUND_HALF_UP)
    if khz != normalized:
        # MyMesh rounds to integer kHz. Only accept that kHz's float32 MHz
        # rendered by StrHelper::ftoa (truncated to seven decimal places).
        stored = struct.unpack("<f", struct.pack("<f", int(normalized) / 1000))[0]
        displayed = Decimal.from_float(stored).quantize(Decimal("0.0000001"), rounding=ROUND_DOWN)
        if mhz != displayed:
            raise ValueError(f"invalid repeater frequency readback: {value!r}")
    return int(normalized)


def repeater_info(node):
    info = repeater_identity(node)
    name = repeater_value(node, "get name")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
        raise ValueError(f"{node.name}: malformed repeater name")
    radio = repeater_value(node, "get radio")
    fields = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?),([0-9]+(?:\.[0-9]+)?),([0-9]+),([0-9]+)", radio)
    if not fields:
        raise ValueError(f"{node.name}: malformed repeater radio readback: {radio!r}")
    freq = repeater_frequency_khz(fields.group(1))
    bw = Decimal(fields.group(2)) * 1000
    sf, cr = (int(value) for value in fields.groups()[2:])
    if (bw != bw.to_integral_value()
            or not 150000 <= freq <= 2500000 or not 7800 <= bw <= 500000
            or not 5 <= sf <= 12 or not 5 <= cr <= 8):
        raise ValueError(f"{node.name}: invalid repeater radio readback: {radio!r}")
    mode = repeater_value(node, "get path.hash.mode")
    if mode not in ("0", "1", "2"):
        raise ValueError(f"{node.name}: invalid repeater path hash mode: {mode!r}")
    return {**info, "name": name, "freq_khz": int(freq), "bw_hz": int(bw),
            "sf": sf, "cr": cr, "path_hash_mode": int(mode),
            "settings_readback_scope": "preferences"}


def require_repeater_ok(node, command, expected="OK"):
    reply = node.command(command)
    if reply != expected:
        raise RuntimeError(f"{node.name}: repeater command failed for {command!r}: {reply!r}")


def configure_repeater(node, before=None, radio=NORMAL_RADIO):
    if before is None:
        before = repeater_info(node)
    require_repeater_ok(node, f"set name {TARGET_NAME}")
    freq, bw, sf, cr = radio
    require_repeater_ok(node, f"set radio {freq / 1000:g},{bw / 1000:g},{sf},{cr}",
                        expected="OK - reboot to apply")
    require_repeater_ok(node, f"set path.hash.mode {PATH_HASH_MODE}")
    info = repeater_info(node)
    if info["pubkey"] != before["pubkey"]:
        raise RuntimeError(f"{node.name}: repeater identity changed during configuration")
    return info


def configure_node(node, name, before=None, radio=NORMAL_RADIO):
    if not re.fullmatch(r"[\x20-\x7e]{1,31}", name):
        raise ValueError("companion name must be 1..31 printable ASCII bytes")
    if before is None:
        before = companion_info(node)
    require_ok(node, bytes([CMD_SET_ADVERT_NAME]) + name.encode("ascii"))
    freq, bw, sf, cr = radio
    require_ok(node, bytes([CMD_SET_RADIO_PARAMS]) + struct.pack("<II", freq, bw) + bytes([sf, cr, 0]))
    require_ok(node, bytes([CMD_SET_PATH_HASH_MODE, 0, PATH_HASH_MODE]))
    info = companion_info(node)
    if info["pubkey"] != before["pubkey"]:
        raise RuntimeError(f"{node.name}: companion identity changed during configuration")
    return info


def record_configuration(evidence, role, before, info, name, radio=NORMAL_RADIO):
    observed = serializable_app_info(info)
    evidence.check(f"identity-{role}-preserved", info["pubkey"] == before["pubkey"],
                   before=before["pubkey"], after=info["pubkey"])
    evidence.check(f"default-radio-{role}",
                   (info["freq_khz"], info["bw_hz"], info["sf"], info["cr"]) == radio,
                   observed=observed, expected_radio=list(radio), active_rf_verified=False)
    evidence.check(f"configured-name-{role}", info["name"] == name, observed=observed)
    evidence.check(f"path-hash-mode-{role}", info["path_hash_mode"] == PATH_HASH_MODE,
                   observed=observed, bytes_per_hash=3, physical_path_verified=False)
    evidence.summary["measurements"].setdefault("configured", {})[role] = observed
    evidence.log("configuration_readback", node=role, observed=observed, expected_radio=list(radio),
                 settings_readback_scope=info["settings_readback_scope"],
                 reboot_persistence_verified=False, active_rf_verified=False)


def run_configure_client(client, evidence, before=None, radio=NORMAL_RADIO):
    evidence.summary["measurements"]["configuration_expected_radio"] = list(radio)
    if before is None:
        before = companion_info(client)
    evidence.summary["measurements"].setdefault("configuration_before", {})["client"] = (
        serializable_app_info(before))
    client_info = configure_node(client, CLIENT_NAME, before=before, radio=radio)
    record_configuration(evidence, "client", before, client_info, CLIENT_NAME, radio=radio)
    return client_info


def run_configure(client, target, evidence, radio=NORMAL_RADIO):
    evidence.summary["measurements"]["configuration_expected_radio"] = list(radio)
    client_before = companion_info(client)
    target_before = repeater_info(target)
    evidence.check("node-identities-are-distinct",
                   client_before["pubkey"] != target_before["pubkey"],
                   client=client_before["pubkey"], target=target_before["pubkey"])
    acl_before = target.get_acl()
    evidence.summary["measurements"]["acl_before"] = acl_before
    evidence.summary["measurements"].setdefault("configuration_before", {})["target"] = (
        serializable_app_info(target_before))
    client_info = run_configure_client(client, evidence, before=client_before, radio=radio)
    target_info = configure_repeater(target, before=target_before, radio=radio)
    acl_after = target.get_acl()
    evidence.summary["measurements"]["acl_after"] = acl_after
    evidence.check("repeater-acl-preserved", acl_after == acl_before,
                   before=acl_before, after=acl_after, admin_provisioned=False,
                   reboot_persistence_verified=False)
    record_configuration(evidence, "target", target_before, target_info, TARGET_NAME, radio=radio)
    evidence.log("repeater_radio_application_pending", reboot_required=True,
                 reboot_requested=False, active_rf_verified=False)
    return client_info, target_info


def run_grant_client_admin(client, target, evidence):
    client_before = serializable_app_info(companion_info(client))
    target_before = repeater_info(target)
    record = {
        "normal_identities_before": {"client": client_before, "target": target_before},
        "permission": CLIENT_ACL_ADMIN,
        "command_attempted": False,
        "mutation_acknowledged": False,
        "lazy_save_wait_seconds": 0,
        "live_acl_verified": False,
        "reboot_requested": False,
        "reboot_persistence_verified": False,
    }
    evidence.summary["measurements"]["admin_grant"] = record
    evidence.check("node-identities-are-distinct",
                   client_before["pubkey"] != target_before["pubkey"],
                   client=client_before["pubkey"], target=target_before["pubkey"])
    key = client_before["pubkey"]
    acl_before = target.get_acl()
    record["acl_before"] = acl_before
    evidence.log("normal_admin_grant_baseline", **record)
    if acl_before.get(key) != CLIENT_ACL_ADMIN:
        command = f"setperm {key} {CLIENT_ACL_ADMIN}"
        record["command_attempted"] = True
        require_repeater_ok(target, command)
        record["mutation_acknowledged"] = True
        evidence.log("normal_admin_grant_acknowledged", command=command,
                     reboot_persistence_verified=False)
        # Dirty contacts save after 5000 ms since the latest update, subject to
        # the destructive-write gate. This wait is an opportunity, not proof.
        time.sleep(ACL_LAZY_SAVE_WAIT_SECONDS)
        record["lazy_save_wait_seconds"] = ACL_LAZY_SAVE_WAIT_SECONDS
    acl_after = target.get_acl()
    record["acl_after"] = acl_after
    evidence.check("normal-client-admin-live", acl_after.get(key) == CLIENT_ACL_ADMIN,
                   public_key=key, permission=acl_after.get(key),
                   reboot_persistence_verified=False)
    unrelated_before = {pk: permission for pk, permission in acl_before.items() if pk != key}
    unrelated_after = {pk: permission for pk, permission in acl_after.items() if pk != key}
    evidence.check("unrelated-repeater-acl-preserved", unrelated_after == unrelated_before,
                   before=unrelated_before, after=unrelated_after)
    identities_after = {"client": serializable_app_info(companion_info(client)),
                        "target": repeater_info(target)}
    record["normal_identities_after"] = identities_after
    for role, before in record["normal_identities_before"].items():
        evidence.check(f"normal-admin-grant-{role}-unchanged",
                       identities_after[role] == before,
                       before=before, after=identities_after[role])
    record["live_acl_verified"] = True
    evidence.log("normal_admin_grant_live_readback", **record)
    return record


def parse_ota_floor_observation(reason):
    floor = {"state": "missing", "seq": None, "ctr": None, "ext": None, "sha": None, "io": None}
    fields = r"\b(?:floor|seq|ctr|ext|sha|io)\s*="
    if not re.search(fields, reason, re.IGNORECASE):
        return floor
    start = re.search(r"(?:^| )floor=", reason)
    if not start or re.search(fields, reason[:start.start()], re.IGNORECASE):
        raise ValueError("malformed or incomplete OTA floor observation")
    suffix = reason[start.start():].lstrip(" ")
    if suffix == "floor=unavailable io=buffer":
        return {**floor, "state": "unavailable", "io": "buffer"}
    match = re.fullmatch(
        r"floor=(present|blank|corrupt|read-error|unavailable) "
        r"seq=([0-9A-F]{8}|\?) ctr=([0-9A-F]{8}|\?) ext=([0-9A-F]{8}|\?) "
        r"sha=([0-9A-F]{64}|\?) io=(ok|read-error|geometry)", suffix)
    if not match:
        raise ValueError("malformed, truncated or duplicate OTA floor tuple")
    state, seq, ctr, ext, sha, io = match.groups()
    if state == "present":
        if "?" in (seq, ctr, ext, sha) or io != "ok":
            raise ValueError("incomplete or inconsistent present OTA floor tuple")
        return {"state": state, "seq": int(seq, 16), "ctr": int(ctr, 16),
                "ext": int(ext, 16), "sha": sha, "io": io}
    expected_io = {"blank": "ok", "corrupt": "ok", "read-error": "read-error",
                   "unavailable": "geometry"}
    if (seq, ctr, ext, sha) != ("?", "?", "?", "?") or io != expected_io[state]:
        raise ValueError("inconsistent nonpresent OTA floor tuple")
    return {**floor, "state": state, "io": io}


def parse_ota_preflight_diagnostic(text, kind):
    if not re.fullmatch(rf"[\x20-\x7e]{{1,{MAX_SERIAL_FRAME_SIZE - 1}}}", text):
        raise ValueError("OTA diagnostic must be bounded printable ASCII")
    match = re.fullmatch(r"writes=(allowed|blocked) (.+)", text)
    if not match:
        raise ValueError("missing OTA write-latch diagnostic; legacy lifecycle status is not supported")
    writes, detail = match.groups()
    result = {"text": text, "writes_allowed": writes == "allowed"}
    if kind == "preflight":
        marker = r"marker=(?:blank|corrupt|qualified|mismatch) proof=[a-z][a-z0-9-]*"
        # Consume the frozen formatter's shapes, not the firmware's proof logic.
        formats = (
            r"proof=(?:not-run|backend-unavailable|qspi-layout|qspi-read)",
            r"proof=jedec observed=[0-9A-F]{6}",
            marker + r" sdk=unread",
            marker + r" off=(?:[0-9A-F]{8}|\?) bank0=[0-9A-F]+ bank1=[0-9A-F]+ "
                     r"size=[0-9]+ crc=[0-9A-F]{4}/(?:[0-9A-F]{4}|\?) tail=[01]",
            r"marker=qualified proof=qualified-state"
            r"(?: state=[0-9]+ phase=[0-9]+ decision=[0-9]+)?",
        )
        if not any(re.fullmatch(pattern, detail) for pattern in formats):
            raise ValueError("unrecognized or incomplete OTA early-preflight diagnostic")
        result["early_proof"] = dict(field.split("=", 1) for field in detail.split(" "))
    elif kind == "capability":
        capability = re.fullmatch(
            r"(CACHE_ONLY|CACHE_UNAVAILABLE|STAGING_ONLY|INSTALL_CAPABLE): (\S(?:.*\S)?)", detail)
        if not capability:
            raise ValueError("unrecognized or incomplete OTA capability diagnostic")
        result["capability"], result["reason"] = capability.groups()
        result["floor"] = parse_ota_floor_observation(result["reason"])
    else:
        raise ValueError(f"unknown OTA diagnostic kind: {kind!r}")
    return result


def parse_ota_boot_addresses(text):
    if text.startswith("Err - "):
        raise RuntimeError(f"target bootloader address readback refused: {text}")
    fields = ("mbr8", "mbrc", "uicrb", "uicrp", "boot", "params")
    pattern = " ".join(rf"{field}=([0-9A-F]{{8}})" for field in fields)
    match = re.fullmatch(pattern, text)
    if not match:
        raise ValueError("malformed, truncated or duplicate bootloader address tuple")
    hex_words = dict(zip(fields, match.groups()))
    values = {field: int(value, 16) for field, value in hex_words.items()}
    boot = values["uicrb"] if values["mbr8"] == 0xFFFFFFFF else values["mbr8"]
    params = values["uicrp"] if values["mbrc"] == 0xFFFFFFFF else values["mbrc"]
    if (values["boot"], values["params"]) != (boot, params):
        raise ValueError("reported bootloader addresses disagree with current MBR/UICR words")
    return {"text": text, "hex": hex_words, **values}


def run_inspect_ota_preflight(client, target, evidence, require_target_genesis_floor=False,
                             require_target_boot_addresses=False):
    if require_target_boot_addresses and target is None:
        raise ValueError("bootloader address inspection requires the approved target")
    record = {"read_only": True, "inspection_complete": False, "nodes": {},
              "target_genesis_floor_required": require_target_genesis_floor,
              "target_genesis_floor_verified": False,
              "target_boot_addresses_required": require_target_boot_addresses,
              "target_boot_addresses_verified": False}
    if target is None:
        record.update(scope="client_only", target_inspected=False, qualification_verified=False)
    evidence.summary["measurements"]["ota_preflight"] = record
    identities = {"client": serializable_app_info(app_info(client))}
    if target is not None:
        identities["target"] = repeater_identity(target)
        evidence.check("node-identities-are-distinct",
                       identities["client"]["pubkey"] != identities["target"]["pubkey"],
                       client=identities["client"]["pubkey"], target=identities["target"]["pubkey"])
    record["identities"] = identities
    # Retain all raw readbacks before validation, including old firmware fallback.
    for role, node in (("client", client), ("target", target)):
        if node is None:
            continue
        diagnostics = record["nodes"][role] = {}
        for selector, kind in ((1, "preflight"), (2, "capability")):
            row = diagnostics[kind] = {}
            if role == "client":
                request = bytes([CMD_OTA_CONTROL, 0, selector])
                row["request_hex"] = request.hex()
                frame = node.command(request, expected=(RESP_OTA_STATUS, RESP_ERR))
                row["response_hex"] = frame.hex()
            else:
                row["command"] = f"ota {kind}"
                row["text"] = node.command(row["command"])
            evidence.log("ota_preflight_raw_readback", node=role, kind=kind, **row)
        if role == "target" and require_target_boot_addresses:
            row = diagnostics["bootloader"] = {"command": "ota bootloader"}
            row["text"] = node.command(row["command"])
            evidence.log("ota_preflight_raw_readback", node=role, kind="bootloader", **row)
    for role, diagnostics in record["nodes"].items():
        for kind, row in diagnostics.items():
            try:
                if role == "client":
                    frame = bytes.fromhex(row["response_hex"])
                    if not frame or frame[0] != RESP_OTA_STATUS:
                        raise RuntimeError(f"companion OTA diagnostic refused: {frame.hex()}")
                    row["text"] = frame[1:].decode("ascii")
                row.update(parse_ota_boot_addresses(row["text"]) if kind == "bootloader"
                           else parse_ota_preflight_diagnostic(row["text"], kind))
            except (ValueError, RuntimeError) as exc:
                row["error"] = f"{type(exc).__name__}: {exc}"
                raise
            evidence.log("ota_preflight_diagnostic", node=role, kind=kind, **row)
    record["inspection_complete"] = True
    if require_target_boot_addresses:
        diagnostics = record["nodes"]["target"]
        observed = diagnostics["bootloader"]
        early_writes_allowed = diagnostics["preflight"]["writes_allowed"]
        writes_allowed = diagnostics["capability"]["writes_allowed"]
        expected = {"boot": 0xF4000, "params": 0xFE000}
        evidence.check("target-boot-addresses",
                       observed["boot"] == expected["boot"]
                       and observed["params"] == expected["params"]
                       and early_writes_allowed and writes_allowed,
                       observed=observed, expected=expected,
                       early_writes_allowed=early_writes_allowed,
                       writes_allowed=writes_allowed, read_only=True,
                       board_id_verified=False, cf2_verified=False, loader_installed_verified=False)
        record["target_boot_addresses_verified"] = True
    if require_target_genesis_floor:
        capability = record["nodes"]["target"]["capability"]
        early_writes_allowed = record["nodes"]["target"]["preflight"]["writes_allowed"]
        expected = {"state": "present", "seq": 1, "ctr": 0, "ext": 0, "sha": "0" * 64, "io": "ok"}
        evidence.check("target-genesis-floor",
                       capability["capability"] == "INSTALL_CAPABLE"
                       and early_writes_allowed and capability["writes_allowed"]
                       and capability["floor"] == expected,
                       capability=capability["capability"], writes_allowed=capability["writes_allowed"],
                       early_writes_allowed=early_writes_allowed,
                       observed_floor=capability["floor"], expected_floor=expected, read_only=True)
        record["target_genesis_floor_verified"] = True
    evidence.log("ota_preflight_inspection_complete", read_only=True,
                 qualification_verified=False, install_authority_verified=False)
    return record


def run_inspect_configuration(client, target, evidence):
    record = {"read_only": True, "inspection_complete": False, "acl_complete": False,
              "nodes": {}, "raw_serial_events": "serial-events.jsonl",
              "reboot_requested": False, "reboot_persistence_verified": False}
    if target is None:
        record.update(scope="client_only", target_inspected=False, target_acl_inspected=False,
                      qualification_verified=False)
    evidence.summary["measurements"]["configuration_inspection"] = record
    for role, node, reader in (("client", client, companion_info), ("target", target, repeater_info)):
        if node is None:
            continue
        observed = serializable_app_info(reader(node))
        record["nodes"][role] = observed
        evidence.log("configuration_inspection_node", node=role, observed=observed, read_only=True)
    if target is not None:
        nodes = record["nodes"]
        evidence.check("node-identities-are-distinct",
                       nodes["client"]["pubkey"] != nodes["target"]["pubkey"],
                       client=nodes["client"]["pubkey"], target=nodes["target"]["pubkey"])
        record["acl"] = target.get_acl()
        record["acl_complete"] = True
        record["client_permission"] = record["acl"].get(nodes["client"]["pubkey"])
    record["inspection_complete"] = True
    evidence.log("configuration_inspection_complete", **record)
    return record


def run_inspect_channels(client, evidence):
    record = {"read_only": True, "inspection_complete": False, "client": {},
              "capacity": None, "channels": [], "configured_indices": [],
              "receiver_membership_verified": False, "serial_events": "serial-events.jsonl"}
    evidence.summary["measurements"]["channel_inventory"] = record
    record["client"] = serializable_app_info(app_info(client))
    frame = client.command(bytes([CMD_DEVICE_QUERY, 13]), expected=(RESP_DEVICE_INFO, RESP_ERR))
    if frame and frame[0] == RESP_ERR:
        raise RuntimeError("client: channel capacity query refused by backend")
    if len(frame) < 80 or frame[0] != RESP_DEVICE_INFO or frame[1] < 3:
        raise ValueError("client: malformed channel capacity device-info response")
    minimum_length = 82 if frame[1] >= 10 else 81 if frame[1] >= 9 else 80
    if len(frame) < minimum_length:
        raise ValueError("client: truncated channel capacity device-info response")
    record["capacity"] = frame[3]
    if record["capacity"] == 0:
        raise RuntimeError("client: channel table unavailable (advertised capacity is zero)")
    del frame
    for index in range(record["capacity"]):
        frame = client.command(bytes([CMD_GET_CHANNEL, index]), expected=(RESP_CHANNEL_INFO, RESP_ERR))
        if frame and frame[0] == RESP_ERR:
            raise RuntimeError(f"client: channel {index} read refused by backend")
        public = public_channel_info(frame)
        del frame
        if public["index"] != index:
            raise ValueError(f"client: channel response index mismatch (requested {index})")
        record["channels"].append(public)
        if public["configured"]:
            record["configured_indices"].append(index)
        evidence.log("channel_inventory_entry", **public, read_only=True)
    record["inspection_complete"] = True
    evidence.log("channel_inventory_complete", **record)
    return record


def parse_ota_radio_measurement(text):
    match = RADIO_MEASUREMENT_PATTERN.fullmatch(text)
    if match is None:
        raise ValueError("malformed OTA radio measurement schema")
    values = dict(zip(RADIO_MEASUREMENT_FIELDS, match.groups()))
    decimals = {"f", "b", "s", "c", "v", "a", "h"}
    result = {field: int(value, 10 if field in decimals else 16) for field, value in values.items()}
    radio = tuple(result[field] for field in ("f", "b", "s", "c"))
    if radio == (0, 0, 0, 0):
        valid_tuple = not result["v"] and not result["h"]
    else:
        valid_tuple = (150000 <= result["f"] <= 2500000
                       and result["b"] in SUPPORTED_LORA_BANDWIDTHS_HZ
                       and 5 <= result["s"] <= 12 and 5 <= result["c"] <= 8)
    if not valid_tuple or (result["h"] and not result["v"]):
        raise ValueError("out-of-range or inconsistent OTA radio measurement")
    return {"src": "driver-applied", **result}


def parse_ota_budget_measurement(text):
    match = BUDGET_MEASUREMENT_PATTERN.fullmatch(text)
    if match is None:
        raise ValueError("malformed OTA budget measurement schema")
    return dict(zip(BUDGET_MEASUREMENT_FIELDS, (int(value, 16) for value in match.groups())))


def read_ota_measurement(node, role, kind, timeout=5):
    if role not in ("client", "target") or kind not in ("radio", "budget"):
        raise ValueError("invalid OTA measurement role or kind")
    if role == "client":
        selector = 3 if kind == "radio" else 4
        frame = node.command(bytes([CMD_OTA_CONTROL, 0, selector]),
                             expected=(RESP_OTA_STATUS, RESP_ERR), timeout=timeout)
        if frame[:1] != bytes([RESP_OTA_STATUS]):
            raise RuntimeError(f"client: OTA {kind} measurement unavailable or refused")
        try:
            text = frame[1:].decode("ascii")
        except UnicodeDecodeError:
            raise ValueError(f"client: non-ASCII OTA {kind} measurement") from None
    else:
        text = node.command("ota " + kind, timeout=timeout)
        if text.startswith("Err"):
            raise RuntimeError(f"target: OTA {kind} measurement refused by backend")
    parser = parse_ota_radio_measurement if kind == "radio" else parse_ota_budget_measurement
    return parser(text)


def read_ota_measurements(client, target, evidence, phase, timeout=5):
    record = {"phase": phase, "started_monotonic": time.monotonic(), "nodes": {},
              "driver_applied_not_phy_readback": True, "duty_guarantee_verified": False}
    for role, node in (("client", client), ("target", target)):
        if node is None:
            continue
        record["nodes"][role] = {}
        for kind in ("radio", "budget"):
            values = read_ota_measurement(node, role, kind, timeout=timeout)
            record["nodes"][role][kind] = values
            evidence.log("ota_measurement", node=role, phase=phase, kind=kind, values=values,
                         driver_applied_not_phy_readback=True, duty_guarantee_verified=False)
    record["finished_monotonic"] = time.monotonic()
    return record


def run_inspect_measurements(client, target, evidence):
    record = {"read_only": True, "inspection_complete": False, "identities": {}, "samples": [],
              "qualification_verified": False, "hardware_phy_readback": False}
    evidence.summary["measurements"]["ota_measurement_inspection"] = record
    record["identities"]["client"] = serializable_app_info(app_info(client))
    if target is not None:
        record["identities"]["target"] = repeater_identity(target)
        evidence.check("measurement-identities-are-distinct",
                       record["identities"]["client"]["pubkey"] != record["identities"]["target"]["pubkey"])
    record["samples"].append(read_ota_measurements(client, target, evidence, "inspection"))
    record["inspection_complete"] = True
    evidence.log("ota_measurement_inspection_complete", **record)
    return record


def resolve_roles(evidence, client_only=False):
    """Resolve each lab role to a live board and record the evidence."""
    evidence.check("approved-active-lab-roles",
                   CLIENT_ROLE == "client" and (client_only or TARGET_ROLE == "target"),
                   client_role=CLIENT_ROLE, target_role=TARGET_ROLE, client_only=client_only)
    roles = [CLIENT_ROLE] if client_only else [CLIENT_ROLE, TARGET_ROLE]
    resolved = {}
    for role in roles:
        device = lab_device.resolve(role, mode=lab_device.MODE_APP)
        evidence.check(f"approved-active-lab-{role}", device.serial == APPROVED_ADMIN_PAIR[role],
                       expected_serial=APPROVED_ADMIN_PAIR[role], observed_serial=device.serial)
        resolved[role] = device
        evidence.check(f"device-{role}", True, role=role, serial=device.serial,
                       path=str(device.by_id), resolved=os.path.realpath(device.by_id))
    serials = {role: d.serial for role, d in resolved.items()}
    evidence.check("roles-are-distinct", len(set(serials.values())) == len(serials),
                   **serials)
    return resolved


def resolve_admin_grant_roles(evidence):
    evidence.check("approved-admin-grant-roles",
                   (CLIENT_ROLE, TARGET_ROLE) == ("client", "target"),
                   client_role=CLIENT_ROLE, target_role=TARGET_ROLE)
    devices = resolve_roles(evidence)
    for role, serial in APPROVED_ADMIN_PAIR.items():
        evidence.check(f"approved-admin-grant-{role}", devices[role].serial == serial,
                       expected_serial=serial, observed_serial=devices[role].serial)
    return devices


def resolve_preflight_roles(evidence, client_only=False):
    evidence.check("approved-ota-preflight-roles",
                   CLIENT_ROLE == "client" and (client_only or TARGET_ROLE == "target"),
                   client_role=CLIENT_ROLE, target_role=TARGET_ROLE, client_only=client_only)
    devices = resolve_roles(evidence, client_only=client_only)
    for role, device in devices.items():
        evidence.check(f"approved-ota-preflight-{role}", device.serial == APPROVED_ADMIN_PAIR[role],
                       expected_serial=APPROVED_ADMIN_PAIR[role], observed_serial=device.serial)
    return devices


def resolve_configuration_inspection_roles(evidence):
    evidence.check("approved-configuration-inspection-roles",
                   (CLIENT_ROLE, TARGET_ROLE) == ("client", "target"),
                   client_role=CLIENT_ROLE, target_role=TARGET_ROLE)
    devices = resolve_roles(evidence)
    for role, serial in APPROVED_ADMIN_PAIR.items():
        evidence.check(f"approved-configuration-inspection-{role}", devices[role].serial == serial,
                       expected_serial=serial, observed_serial=devices[role].serial)
    return devices


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--client-only", action="store_true")
    parser.add_argument("--require-target-genesis-floor", action="store_true",
                       help="paired preflight only: require target INSTALL_CAPABLE, allowed writes "
                            "and freshly observed present genesis floor")
    parser.add_argument("--require-target-boot-addresses", action="store_true",
                       help="paired preflight only: require fresh matching MBR/UICR boot addresses "
                            "and allowed ordinary writes; never reset or install")
    parser.add_argument("--bandwidth-hz", type=int, choices=SUPPORTED_LORA_BANDWIDTHS_HZ,
                       help="configure-only LoRa bandwidth in integer Hz (default: 62500)")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--configure-only", action="store_true",
                       help="configure ordinary radio/name/path settings; never provision ADMIN or run OTA")
    scope.add_argument("--monitor-seconds", type=float, default=0,
                       help="read-only role-checked serial monitoring for a positive duration")
    scope.add_argument("--grant-client-admin", action="store_true",
                       help="explicit normal CLI grant of permission 03 to the approved companion; "
                            "live ACL verification only, no reboot or OTA")
    scope.add_argument("--inspect-ota-preflight", action="store_true",
                       help="read-only early preflight, write-latch and capability diagnostics")
    scope.add_argument("--inspect-configuration", action="store_true",
                       help="read-only approved pair settings and complete repeater ACL, or client "
                            "settings only with --client-only; "
                            "no setters, grants or reboot")
    scope.add_argument("--inspect-channels", action="store_true",
                       help="read-only approved companion channel names/indices; implicitly client-only, "
                            "fresh artifact directory required, no secrets or receiver membership claim")
    scope.add_argument("--inspect-measurements", action="store_true",
                       help="read-only approved USB-local applied radio/budget diagnostics; fresh evidence "
                            "directory, no setters, OTA transfer or PHY/duty qualification")
    args = parser.parse_args()
    if args.require_target_genesis_floor and (not args.inspect_ota_preflight or args.client_only):
        parser.error("--require-target-genesis-floor requires --inspect-ota-preflight "
                     "with both approved roles; not --client-only or another mode")
    if args.require_target_boot_addresses and (not args.inspect_ota_preflight or args.client_only):
        parser.error("--require-target-boot-addresses requires --inspect-ota-preflight "
                     "with both approved roles; not --client-only or another mode")
    if not math.isfinite(args.monitor_seconds) or args.monitor_seconds < 0:
        parser.error("--monitor-seconds must be finite and non-negative")
    if args.grant_client_admin and args.client_only:
        parser.error("--grant-client-admin requires both approved roles; not --client-only")
    if args.bandwidth_hz is not None and not args.configure_only:
        parser.error("--bandwidth-hz requires --configure-only")
    if not (args.configure_only or args.monitor_seconds > 0 or args.grant_client_admin
            or args.inspect_ota_preflight or args.inspect_configuration or args.inspect_channels
            or args.inspect_measurements):
        parser.error("RF/OTA qualification is not supported by this configuration/monitor helper; "
                     "select --configure-only, --grant-client-admin, --inspect-ota-preflight, "
                     "--inspect-configuration, --inspect-channels, --inspect-measurements "
                     "or a positive --monitor-seconds. "
                     "Signed transfers use ota_uploader.py with a separate explicit commit")

    if args.inspect_channels:
        args.client_only = True
    radio = (NORMAL_RADIO if args.bandwidth_hz is None
             else (NORMAL_RADIO[0], args.bandwidth_hz, *NORMAL_RADIO[2:]))
    evidence = (Evidence(args.artifact_dir, exclusive=True)
                if args.inspect_channels or args.inspect_measurements
                or (args.client_only and (args.inspect_configuration or args.inspect_ota_preflight))
                else Evidence(args.artifact_dir))
    client = target = None
    error = None
    try:
        if args.grant_client_admin:
            devices = resolve_admin_grant_roles(evidence)
        elif (args.inspect_ota_preflight or args.inspect_channels or args.inspect_measurements
              or (args.inspect_configuration and args.client_only)):
            devices = resolve_preflight_roles(evidence, client_only=args.client_only)
        elif args.inspect_configuration:
            devices = resolve_configuration_inspection_roles(evidence)
        else:
            devices = resolve_roles(evidence, client_only=args.client_only)
        client_device = devices[CLIENT_ROLE]
        client = FramedSerial(f"{CLIENT_ROLE}-{client_device.serial}",
                              str(client_device.by_id), evidence)
        if not args.client_only:
            target_device = devices[TARGET_ROLE]
            target = RepeaterSerial(f"{TARGET_ROLE}-{target_device.serial}",
                                    str(target_device.by_id), evidence)
        time.sleep(2.0)
        if args.monitor_seconds > 0:
            identities = {"client": serializable_app_info(app_info(client))}
            if target:
                identities["target"] = repeater_identity(target)
            evidence.summary["measurements"]["identities"] = identities
            deadline = time.monotonic() + args.monitor_seconds
            while time.monotonic() < deadline:
                client.poll(0.05)
                client.pending.clear()
                if target:
                    target.poll(0.05)
                    target.pending.clear()
        elif args.grant_client_admin:
            run_grant_client_admin(client, target, evidence)
        elif args.inspect_ota_preflight:
            run_inspect_ota_preflight(client, target, evidence,
                                     require_target_genesis_floor=args.require_target_genesis_floor,
                                     require_target_boot_addresses=args.require_target_boot_addresses)
        elif args.inspect_configuration:
            run_inspect_configuration(client, target, evidence)
        elif args.inspect_channels:
            run_inspect_channels(client, evidence)
        elif args.inspect_measurements:
            run_inspect_measurements(client, target, evidence)
        else:
            if args.client_only:
                run_configure_client(client, evidence, radio=radio)
            else:
                run_configure(client, target, evidence, radio=radio)
    except (Exception, SystemExit) as exc:
        error = f"{type(exc).__name__}: {exc}"
        evidence.log("fatal", error=error)
        raise
    finally:
        if client:
            client.close()
        if target:
            target.close()
        evidence.finish(error)


if __name__ == "__main__":
    main()
