#!/usr/bin/env python3
"""Host-managed, zero-hop OTA through an unchanged MeshCore 1.17.1 companion.

upload stops at informational RF READY; commit is a separate signed operation.
No CMD66, local staging, contact/key changes, bootloader commands or reset.
SIGKILL cannot restore a stock radio: retain original-radio.json for restore.
RF census has no signature or nonce: a post-poll observation is not authenticated
freshness or installation proof, and indistinguishable on-air replays cannot be
rejected by this unchanged protocol. Only direct ACK and authority are signed.
The stock radio readback is saved settings, not a physical RF-profile measurement.
Stock TX statistics are aggregate counters, not per-packet completion tokens:
exclusive host access/pacing detects obvious concurrent TX, not all RF ambiguity.
This driver requires 30000..60000ms leases for conservative USB/TX/reply margins
(the unchanged receiver's wire minimum remains 250ms).

ROOT supplies a private binding JSON, not this program:
{"schema":1,"authorized":true,"serial":"FULL_USB_SERIAL",
 "sender_public_key":"64 hex","target_public_key":"64 hex",
 "stock_version":"1.17.1","floor":0,"min_generation":10,
 "normal_profile":[907525,250000,7,5],"image_kind":"ordinary-app",
 "image_sha256":"64 hex","manifest_hash":"64 hex"}
floor and min_generation MUST be measured/approved for the target by ROOT.
ROOT also approves the pure APP build provenance and exact image/manifest hashes;
vectors/size alone cannot establish the semantic role of arbitrary firmware.
For a ROOT-aborted candidate only, ROOT adds "allow_reupload":true. Upload
additionally requires --reupload: fresh signed AUTH -> fresh RF pending
ABORTED/new hash -> signed target/RF-OBSERVED-generation REUPLOAD -> Receiving
observed generation+1 with ZERO received/bitmap. No auto-ABORT,
cache promotion or USB staging; the receiver needs the separately qualified
aborted-local-cache purpose-transition fix. Already-active candidates resume
without sending REUPLOAD again. Without both opt-ins, pending ABORTED fails.
min_generation is only ROOT's admission lower bound, not a USB/current-generation
proof. ABORT can advance generation; never assume the sealed-cache generation.
The legacy --reupload-generation/ROOT field is an optional strict expectation,
not the signing source; prefer generation-free --reupload and allow_reupload.
The host must receive the fresh new-hash pending census before REUPLOAD.
Later eligible ROLE0 candidates use ordinary AUTH/terminal admission, without
--reupload; do not treat every new upload as cache retirement.
The normal profile excludes repeat; repeat is read from the stock companion.
The binding does not commission the receiver or discard its existing cache.
normal_profile is the TARGET's normal channel, not the stock's original radio:
capture stock wire CR/repeat/TX power, temporarily join target normal, then direct,
and restore the exact stock profile. Never translate a UI coding-rate label.
ROOT must use the recipient's freshly measured user-configured profile, never
a firmware-default guess. Confirmed healthy41 normal is [907525,250000,7,5],
matching this stock's original radio; the prior 62500 assumption was incorrect.
All normal-channel sends, pacing and lease returns use this explicit binding.
For duplicate/short USB serials, ROOT must additionally bind by_path, id_path,
usb_vid and usb_pid (four hex digits). --by-path must match that binding:
{"serial":"0001","by_path":"/dev/serial/by-path/ROOT_ID_PATH-port0",
 "id_path":"ROOT_ID_PATH","usb_vid":"10c4","usb_pid":"ea60",
 "sender_name":"lab-stock", ...}
In this case --by-id is informational only: it is NEVER resolved/selected.
CP2102 requires by-path, exact udev/sysfs USB metadata and full public identity.
No raw USB logging: SelfInfo GPS and DeviceQuery BLE PIN are not decoded/logged.
CP2102 bindings also require public sender_name, e.g. "lab-stock"; an optional
--sender-name must agree. validated_stock_uart opens the authorized anchor
DIRECTLY (never an ambiguous by-id or resolved tty substitute), leaves DTR/RTS
false, rechecks physical binding, and settles 2s. It is an explicit adapter, not
a LabSerial parent-variable bypass. APP_START precedes DeviceQuery; only a missing
APP_START response is retried once (each command <=3s). No DTR/RTS toggle/reset,
baud fallback or inference of firmware/hardware type from the USB bridge.
sender_name is the ROOT/user-approved PUBLIC SelfInfo name, not an assumed
operator alias or hardware model; ROOT must establish that distinction.
inspect is read-only: it never enters radio_guard or signs/transmits RF. Missing
or mismatched replies produce no successful identity/profile/readiness result.
The release guard accepts ONLY full v?1.17.1 with an optional -HEX Git build
suffix (e.g. v1.17.1-d929643), not substring matches, dirty/dev/prerelease tags
or other releases. ROOT binding stock_version remains semantic "1.17.1".
inspect preserves the accepted reported version; it does not normalize away
the Git suffix or turn identity/profile readback into RF readiness.

Runtime dependencies: existing pyserial and cryptography. Tests use unittest
and fake transports; importing this module never opens hardware.
"""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import struct
import sys
import time

MAX_FRAME = 176
BLOCK = 84
MIN_LEASE = 30000
DIRECT_DOMAIN = b"MeshCore/OTA/direct/v1"
COMMIT_DOMAIN = b"MeshCore/OTA/commit/v1"
REUPLOAD_DOMAIN = b"MeshCore/OTA/reupload/v1"
DENIED_SERIALS = {"49C5BAF21EEF44A1", "4186AE911D94CDB1", "77CD44653A967172"}


class Error(RuntimeError):
    pass


class LeaseExpired(Error):
    pass


class NoCensus(Error):
    pass


class NoUsbResponse(Error):
    pass


class Refused(Error):
    pass


def full_key(text):
    if not isinstance(text, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", text):
        raise Error("full 32-byte public key required")
    key = bytes.fromhex(text)
    if key == bytes(32):
        raise Error("zero identity forbidden")
    return key


def verify(key, message, signature):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
    except (InvalidSignature, ValueError) as exc:
        raise Error("Ed25519 signature/identity mismatch") from exc


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
            raise Error("artifact/binding must be an owned regular 0600 file")
        with os.fdopen(fd, "r", closefd=False) as stream:
            return json.load(stream)
    finally:
        os.close(fd)


def private_write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@dataclass(frozen=True)
class Binding:
    serial: str
    sender: bytes
    target: bytes
    floor: int
    min_generation: int
    normal: tuple
    image_hash: bytes
    manifest_hash: bytes
    reupload_generation: int | None = None
    by_path: str | None = None
    id_path: str | None = None
    usb_vid: int | None = None
    usb_pid: int | None = None
    sender_name: str | None = None
    allow_reupload: bool = False

    @classmethod
    def load(cls, path, serial, sender, target, by_path=None, sender_name=None):
        if (not re.fullmatch(r"[A-Za-z0-9]{1,64}", serial) or serial.upper() in DENIED_SERIALS
                or (len(serial) < 12 and by_path is None)):
            raise Error("explicit full authorized stock serial required; protected board refused")
        value = private_read(path)
        if (value.get("schema") != 1 or value.get("authorized") is not True
                or value.get("stock_version") != "1.17.1" or value.get("serial") != serial
                or value.get("image_kind") != "ordinary-app"
                or full_key(value.get("sender_public_key")) != sender
                or full_key(value.get("target_public_key")) != target or sender == target):
            raise Error("ROOT binding does not authorize this sender/target/version")
        if value.get("by_path") != by_path:
            raise Error("explicit --by-path must match ROOT binding, never inferred from serial/by-id")
        id_path, vid, pid = value.get("id_path"), value.get("usb_vid"), value.get("usb_pid")
        if by_path is not None:
            anchor = Path(by_path)
            if (anchor.parent != Path("/dev/serial/by-path") or not isinstance(id_path, str)
                    or anchor.name != id_path + "-port0"
                    or not all(isinstance(x, str) and re.fullmatch(r"[0-9a-fA-F]{4}", x) for x in (vid, pid))):
                raise Error("ROOT by-path/ID_PATH/full USB VID/PID binding required")
            vid, pid = int(vid, 16), int(pid, 16)
        elif any(x is not None for x in (id_path, vid, pid)):
            raise Error("USB path metadata requires explicit ROOT-bound --by-path")
        name = value.get("sender_name")
        if ((name is not None and (not isinstance(name, str) or not 0 < len(name.encode("utf-8")) <= 31 or "\x00" in name))
                or (sender_name is not None and sender_name != name)
                or ((vid, pid) == (0x10C4, 0xEA60) and name is None)):
            raise Error("ROOT-approved public sender_name required; explicit name must match binding")
        floor, generation = value.get("floor"), value.get("min_generation")
        if (type(floor) is not int or not 0 <= floor < 0xFFFFFFFF
                or type(generation) is not int or not 0 < generation <= 0xFFFFFFFF):
            raise Error("measured target floor and positive generation guard required")
        profile = value.get("normal_profile")
        validate_profile(profile + [0] if isinstance(profile, list) else ())
        old_generation = value.get("reupload_generation")
        if old_generation is not None and (type(old_generation) is not int or not 0 < old_generation < 0xFFFFFFFF
                                           or generation != old_generation + 1):
            raise Error("ROOT REUPLOAD approval requires exact old generation and min_generation=old+1")
        allow_reupload = value.get("allow_reupload", False)
        if type(allow_reupload) is not bool:
            raise Error("ROOT allow_reupload must be an explicit boolean")
        return cls(serial, sender, target, floor, generation, tuple(profile),
                   full_key(value.get("image_sha256")), full_key(value.get("manifest_hash")), old_generation,
                   by_path, id_path, vid, pid, name, allow_reupload)

    def approve(self, candidate):
        if (hashlib.sha256(candidate.image).digest() != self.image_hash
                or candidate.digest != self.manifest_hash):
            raise Error("image/manifest not the exact ROOT-approved ordinary APP build")

    def permit_reupload(self, generation, reupload=False):
        if type(reupload) is not bool or (reupload and (not self.allow_reupload or generation is not None)):
            raise Error("explicit --reupload requires ROOT allow_reupload:true and no fixed generation")
        if generation is not None and (type(generation) is not int or not 0 < generation < 0xFFFFFFFF
                                       or generation != self.reupload_generation or self.min_generation != generation + 1):
            raise Error("explicit REUPLOAD generation does not match ROOT binding/new-generation guard")


def validate_profile(profile):
    if (len(profile) != 5 or any(type(x) is not int for x in profile)
            or not 150000 <= profile[0] <= 2500000 or not 7000 <= profile[1] <= 500000
            or not 5 <= profile[2] <= 12 or not 5 <= profile[3] <= 8 or profile[4] not in (0, 1)):
        raise Error("invalid stock radio profile")


@dataclass(frozen=True)
class Candidate:
    canonical: bytes
    image: bytes
    digest: bytes
    counter: int
    total: int

    @classmethod
    def build(cls, canonical, image, floor):
        if len(canonical) != 59 or canonical[:5] != b"XN40\x00":
            raise Error("requires canonical59 XN40 ROLE0 companion APP, not ROLE1 cache")
        address, size = struct.unpack_from(">II", canonical, 5)
        counter, caps, fmt, key, algorithm = struct.unpack_from(">IIHHH", canonical, 45)
        if (address != 0x27000 or not 8 <= size <= 0x9D000 or size % 4
                or len(image) != size or canonical[13:45] != hashlib.sha256(image).digest()
                or caps != 1 or (fmt, key, algorithm) != (1, 1, 1) or not floor < counter):
            raise Error("APP geometry/hash/policy or measured anti-rollback floor mismatch")
        stack, reset = struct.unpack_from("<II", image)
        if (not 0x20000000 < stack <= 0x20040000 or stack % 8 or not reset & 1
                or not address <= (reset & ~1) < address + size):
            raise Error("ordinary APP vector required; UF2/ZIP/compound/boot images refused")
        return cls(canonical, image, hashlib.sha256(canonical).digest(), counter, (size + 83) // 84)


def packet(payload):
    # Packet::writeTo: version 0, type 0x0c, direct route 2, zero path.
    raw = b"\x32\x00" + payload
    if not payload or len(raw) + 2 > MAX_FRAME:
        raise Error("CMD65 exceeds stock 176-byte frame")
    return raw


def raw_rx(frame):
    if len(frame) > MAX_FRAME:
        raise Error("oversize stock USB frame")
    if len(frame) < 6 or frame[:1] != b"\x88":
        return None
    header, path = frame[3], frame[4]
    if header >> 6 or (header >> 2) & 15 != 12 or header & 3 not in (1, 2):
        return None
    hash_size, count = (path >> 6) + 1, path & 63
    path_bytes = hash_size * count
    offset = 5 + path_bytes
    # Normal-channel receiver control is flood; leased control is direct.
    # Match Packet::isValidPathLen and skip hashes, never transport codes.
    if hash_size == 4 or path_bytes > 64 or offset >= len(frame):
        return None
    return frame[offset:]


def rf_metadata(frame, payload, target, manifest):
    header = frame[3] if len(frame) >= 5 else None
    kind = payload[0] if payload else None
    target_offset = {11: 1, 13: 33}.get(kind)
    hash_offset = {11: 33, 13: 65}.get(kind)
    return {"usb_length": len(frame), "packet_length": max(0, len(frame) - 3),
            "route": header & 3 if header is not None else None,
            "version": header >> 6 if header is not None else None,
            "payload_type": (header >> 2) & 15 if header is not None else None,
            "decoded": payload is not None, "kind": kind,
            "payload_length": len(payload) if payload is not None else None,
            "target_match": payload[target_offset:target_offset + 32] == target
            if target_offset is not None and target is not None else None,
            "manifest_match": payload[hash_offset:hash_offset + 32] == manifest
            if hash_offset is not None and manifest is not None else None}


def public_event(event):
    print(json.dumps(event, sort_keys=True), flush=True)


def block_message(candidate, index):
    if not 0 <= index < candidate.total:
        raise Error("block index outside candidate")
    data = candidate.image[index * BLOCK:(index + 1) * BLOCK]
    message = candidate.digest + b"\x01" + struct.pack(">HB", index, len(data)) + data
    prefix = b"\x01" + candidate.digest[:4] + struct.pack(">H", index) + data
    return message, prefix


class Frames:
    """Bounded stock USB framing; no logging of opaque USB/DeviceQuery fields."""
    def __init__(self, stream, clock=time.monotonic):
        self.stream, self.clock = stream, clock
        self.buffer = bytearray()
        self.pending = []

    def feed(self, data):
        self.buffer.extend(data)
        while self.buffer:
            marker = self.buffer.find(b">")
            if marker < 0:
                self.buffer.clear()
                return
            del self.buffer[:marker]
            if len(self.buffer) < 3:
                return
            length = struct.unpack_from("<H", self.buffer, 1)[0]
            if not 1 <= length <= MAX_FRAME:
                raise Error("invalid/oversize USB response length")
            if len(self.buffer) < 3 + length:
                return
            frame = bytes(self.buffer[3:3 + length])
            del self.buffer[:3 + length]
            if len(self.pending) >= 256:
                raise Error("USB response backlog overflow")
            self.pending.append((self.clock(), frame))

    def poll(self, timeout):
        self.stream.timeout = max(0, timeout)
        data = self.stream.read(1)
        available = self.stream.in_waiting
        if available:
            self.stream.timeout = 0
            data += self.stream.read(min(MAX_FRAME * 2, available))
        self.feed(data)

    def command(self, payload, expected=(0, 1), timeout=3):
        if not 1 <= len(payload) <= MAX_FRAME:
            raise Error("invalid USB command length")
        self.poll(0)
        self.pending = [(t, f) for t, f in self.pending if f[0] not in expected]
        wire = b"<" + struct.pack("<H", len(payload)) + payload
        if self.stream.write(wire) != len(wire):
            raise Error("short USB write")
        deadline = self.clock() + timeout
        while self.clock() < deadline:
            for i, (_, frame) in enumerate(self.pending):
                if frame[0] in expected:
                    self.pending.pop(i)
                    return frame
            self.poll(min(0.1, deadline - self.clock()))
        raise NoUsbResponse("USB command deadline; no response")

    def discard_rf(self, observer=None, target=None, manifest=None):
        self.poll(0)
        if observer is not None:
            for _, frame in self.pending:
                if frame[0] == 0x88:
                    observer({"event": "rf_discard", **rf_metadata(frame, raw_rx(frame), target, manifest)})
        self.pending = [(t, f) for t, f in self.pending if f[0] != 0x88]

    def receive(self, predicate, since, deadline, observer=None, target=None, manifest=None):
        while self.clock() < deadline:
            for i, (timestamp, frame) in enumerate(self.pending):
                if frame[0] == 0x88:
                    self.pending.pop(i)
                    payload = raw_rx(frame)
                    if observer is not None:
                        observer({"event": "rf_rx", "fresh": timestamp >= since,
                                  **rf_metadata(frame, payload, target, manifest)})
                    if timestamp >= since and payload is not None and predicate(payload):
                        return timestamp, payload
                    break
            else:
                self.poll(min(0.1, deadline - self.clock()))
        raise TimeoutError("no fresh matching RF response")


class Stock:
    def __init__(self, frames, key, clock=time.monotonic, sleep=time.sleep, expected_name=None):
        self.frames, self.key, self.clock = frames, key, clock
        self.sleep, self.pending_tx = sleep, None
        self.identified, self.tx_power = False, None
        self.expected_name, self.name, self.version = expected_name, None, None

    def command(self, payload, expected=(0, 1), deadline=None):
        if not payload or payload[0] not in (1, 11, 22, 33, 34, 35, 56, 65):
            raise Error("command outside stock OTA allowlist; no key/contact/reset/flash/USB-stage access")
        if payload[0] in (11, 33, 34, 35, 65) and not self.identified:
            self.identify(deadline)
        remaining = 3 if deadline is None else min(3, deadline - self.clock())
        if remaining <= 0:
            raise Error("protocol deadline expired")
        frame = self.frames.command(payload, expected=expected, timeout=remaining)
        if frame[0] == 1:
            if len(frame) != 2:
                raise Error("malformed stock error response; raw USB fields withheld")
            raise Refused(f"stock CMD{payload[0]} refused (code {frame[1]})")
        return frame

    def ok(self, payload, deadline=None):
        if self.command(payload, deadline=deadline) != b"\x00":
            raise Error("malformed stock OK")

    def identify(self, deadline=None):
        self.identified = False
        self.name, self.version = None, None
        # APP_START is the standard connection bootstrap; do not assume an
        # unsolicited DeviceQuery reply from an unverified UART endpoint.
        for attempt in range(2):
            try:
                info = self.command(b"\x01" + bytes(7) + b"ota-stock-host", (5, 1), deadline)
                break
            except NoUsbResponse:
                if attempt:
                    raise
        if len(info) < 58 or info[1] != 1 or info[4:36] != self.key:
            raise Error("stock companion full public identity mismatch")
        try:
            name = info[58:].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Error("malformed public sender name; raw SelfInfo fields withheld") from exc
        if "\x00" in name or (self.expected_name is not None and name != self.expected_name):
            raise Error("stock public sender name does not match ROOT/user label guard")
        device = self.command(b"\x16\x0a", (13, 1), deadline)
        # DeviceQuery includes a PIN at [4:8]. Never decode, persist or log it.
        if len(device) != 82 or device[1] != 13 or device[80] not in (0, 1):
            raise Error("requires stock MeshCore 1.17.1 DeviceQuery/repeat readback")
        version = device[60:80].split(b"\x00", 1)[0]
        if re.fullmatch(rb"v?1\.17\.1(?:-[0-9a-fA-F]+)?", version) is None:
            raise Error("requires stock MeshCore release 1.17.1 with optional hex build suffix")
        profile = (*struct.unpack_from("<II", info, 48), info[56], info[57], device[80])
        validate_profile(profile)
        power = struct.unpack_from("<b", info, 2)[0]
        if self.tx_power is not None and power != self.tx_power:
            raise Error("stock TX power changed; driver never changes TX power")
        self.tx_power, self.name, self.version, self.identified = power, name, version.decode("ascii"), True
        return profile

    def radio(self, profile):
        validate_profile(profile)
        if self.pending_tx is not None:
            deadline = self.clock() + 8
            while self.clock() < deadline:
                queue, sent, direct, _ = self.stats(deadline)
                ds = (sent - self.pending_tx[0]) & 0xFFFFFFFF
                dd = (direct - self.pending_tx[1]) & 0xFFFFFFFF
                if ds > 1 or dd > 1:
                    raise Error("cannot restore/change radio during unattributable TX")
                if not queue and ds == dd == 1:
                    self.pending_tx = None
                    break
                self.sleep(0.25)
            if self.pending_tx is not None:
                raise Error("cannot restore/change radio: outstanding physical TX unconfirmed")
        self.ok(b"\x0b" + struct.pack("<II", *profile[:2]) + bytes(profile[2:]))
        if self.identify() != tuple(profile):
            raise Error("stock radio/repeat readback mismatch")

    def sign(self, message, deadline):
        start = self.command(b"\x21", (19, 1), deadline)
        if len(start) != 6 or start[:2] != b"\x13\x00" or struct.unpack_from("<I", start, 2)[0] < len(message):
            raise Error("stock signing buffer unavailable")
        for offset in range(0, len(message), 175):
            self.ok(b"\x22" + message[offset:offset + 175], deadline)
        response = self.command(b"\x23", (20, 1), deadline)
        if len(response) != 65:
            raise Error("malformed stock signature")
        verify(self.key, message, response[1:])
        return response[1:]

    def stats(self, deadline):
        core = self.command(b"\x38\x00", (24, 1), deadline)
        packets = self.command(b"\x38\x02", (24, 1), deadline)
        radio = self.command(b"\x38\x01", (24, 1), deadline)
        if (len(core) != 11 or core[:2] != b"\x18\x00" or len(packets) != 30
                or packets[:2] != b"\x18\x02" or len(radio) != 14 or radio[:2] != b"\x18\x01"):
            raise Error("required stock queue/physical TX/radio statistics unavailable")
        return core[10], struct.unpack_from("<I", packets, 6)[0], struct.unpack_from("<I", packets, 14)[0], struct.unpack_from("<I", radio, 6)[0]


def airtime(raw_length, profile):
    _, bw, sf, cr, _ = profile
    symbol = 2 ** sf / bw
    de = int(symbol >= 0.016)
    preamble = 32 if sf <= 8 else 16
    payload_symbols = 8 + max(0, math.ceil((8 * raw_length - 4 * sf + 28 + 16) / (4 * (sf - 2 * de))) * cr)
    # Margin covers driver/low-SF differences; stats supply actual elapsed TX.
    return (preamble + 4.25 + payload_symbols) * symbol * 1.5


class Sender:
    def __init__(self, stock, binding, candidate, profile, deadline, frequency, lease_ms=60000,
                 duty=0.02, clock=time.monotonic, sleep=time.sleep, reupload_generation=None, reupload=False,
                 event_callback=None):
        if not MIN_LEASE <= lease_ms <= 60000 or not 150000 <= frequency <= 2500000 or frequency == binding.normal[0]:
            raise Error("off-normal frequency and host lease 30000..60000ms required")
        if not math.isfinite(duty) or not 0 < duty <= 1:
            raise Error("normal-channel duty must be in (0,1]")
        binding.approve(candidate)
        binding.permit_reupload(reupload_generation, reupload)
        self.stock, self.binding, self.candidate = stock, binding, candidate
        self.original, self.normal = tuple(profile), (*binding.normal, 0)
        self.profile, self.deadline = self.normal, deadline
        self.frequency, self.lease_ms, self.duty = frequency, lease_ms, duty
        self.clock, self.sleep = clock, sleep
        self.next_normal = clock()
        self.lease_end = 0
        self.target_normal_after = 0
        self.generation = None
        self.previous = {}
        self.received = 0
        self.attempts = {}
        self.reupload_generation = reupload_generation
        self.reupload_enabled = reupload or reupload_generation is not None
        self.pending_generation = None
        self.activation_generation = None
        self.pending_reupload = False
        self.event_callback, self.event_start = event_callback, clock()

    def emit(self, event, **fields):
        if self.event_callback is not None:
            self.event_callback({"event": event, "elapsed_s": round(self.clock() - self.event_start, 3), **fields})

    def rf_observer(self, phase):
        return (lambda data: self.emit(phase=phase, **data)) if self.event_callback is not None else None

    def wait_until(self, when):
        if when >= self.deadline:
            raise Error("campaign deadline expired")
        if when > self.clock():
            self.sleep(when - self.clock())

    def room(self, seconds):
        if self.clock() + seconds >= self.deadline:
            raise Error("campaign deadline expired")
        if self.lease_end and self.clock() + seconds >= self.lease_end:
            raise LeaseExpired("direct lease operation margin exhausted")

    def send(self, payload):
        self.room(9)
        command = b"\x41\x00" + packet(payload)
        normal = self.profile == self.normal
        if normal:
            self.wait_until(self.next_normal)
        deadline = min(self.deadline, self.clock() + 8, self.lease_end or self.deadline)
        before = self.stock.stats(deadline)
        if before[0]:
            raise Error("stock outbound queue not exclusive/idle")
        started = self.clock()
        estimate = airtime(len(payload) + 2, self.profile)
        self.stock.pending_tx = before[1:3]
        try:
            self.stock.ok(command, deadline)
        except Refused:
            self.stock.pending_tx = None
            raise
        # CMD65 OK only admits to a queue. Require physical sent + direct TX
        # completion, not merely a drained queue; unexpected activity fails closed.
        while self.clock() < deadline:
            after = self.stock.stats(deadline)
            sent = (after[1] - before[1]) & 0xFFFFFFFF
            direct = (after[2] - before[2]) & 0xFFFFFFFF
            if sent > 1 or direct > 1:
                raise Error("concurrent/unattributable stock radio traffic")
            if not after[0] and sent == direct == 1:
                self.stock.pending_tx = None
                spent = max(estimate, self.clock() - started,
                            (after[3] - before[3]) & 0xFFFFFFFF)
                if normal:
                    self.next_normal = self.clock() + spent * (1 / self.duty - 1)
                else:
                    self.sleep(max(0.05, spent))
                return started
            self.sleep(max(0.05, min(0.25, estimate / 2)))
        raise Error("no measured physical stock TX completion")

    def census(self, first=0, retries=3, allow_pending=False):
        self.room(15)
        c, b = self.candidate, self.binding
        observer = self.rf_observer("census")
        for attempt in range(1, retries + 1):
            self.stock.frames.discard_rf(observer, b.target, c.digest)
            self.emit("census_request", attempt=attempt, first=first, allow_pending=allow_pending,
                      channel="direct" if self.lease_end else "normal")
            since = self.send(b"\x0a" + b.target + c.digest + struct.pack(">H", first))
            self.emit("census_sent", attempt=attempt, first=first, tx_evidence="aggregate-counters")
            try:
                reply_wait = 4 if self.lease_end else 25
                _, frame = self.stock.frames.receive(
                    lambda p: p[:1] == b"\x0b", since,
                    min(self.deadline, self.clock() + reply_wait, self.lease_end or self.deadline),
                    observer, b.target, c.digest)
            except TimeoutError:
                self.emit("census_timeout", attempt=attempt, first=first)
                self.room(15)
                if attempt < retries:
                    self.emit("census_retry", next_attempt=attempt + 1, first=first)
                continue
            try:
                report = self.parse_census(frame, first, allow_pending)
            except Error as exc:
                self.emit("census_rejected", first=first, reason=str(exc))
                raise
            self.emit("census_parsed", first=report["first"], lifecycle=report["lifecycle"],
                      generation=report["generation"], phase=report["phase"],
                      received=report["received"], total=report["total"], bitmap_count=report["bits"].bit_count())
            return report
        self.emit("census_exhausted", first=first, attempts=retries)
        raise NoCensus("fresh RF census deadline/retries exhausted")

    def parse_census(self, frame, first, allow_pending=False):
        c, b = self.candidate, self.binding
        if len(frame) != 102 or frame[:1] != b"\x0b" or frame[1:33] != b.target or frame[33:65] != c.digest:
            raise Error("RF census target/full manifest mismatch or legacy status")
        start = struct.unpack_from(">H", frame, 65)[0]
        received, total, phase, generation, lifecycle, known, floor, counter = struct.unpack_from(">HHBIBBII", frame, 83)
        bits = int.from_bytes(frame[67:83], "little")
        count = min(128, c.total - first)
        previous = self.previous.get(first)
        if lifecycle == 9:
            if not allow_pending or not self.reupload_enabled:
                raise Error("pending ABORTED requires explicit ROOT-approved REUPLOAD; no auto-abort/clear")
            if (start != first or first != 0 or total != c.total or received or bits or phase != 5
                    or not 0 < generation < 0xFFFFFFFF or generation + 1 < b.min_generation
                    or (self.reupload_generation is not None and generation != self.reupload_generation)
                    or (self.pending_generation is not None and generation != self.pending_generation)
                    or known != 1 or floor != b.floor
                    or counter != c.counter or self.generation is not None):
                raise Error("pending REUPLOAD hash/phase/old-generation/zero-progress/floor mismatch")
            self.pending_reupload = True
            self.pending_generation = generation
            self.activation_generation = generation + 1
            return {"first": first, "bits": 0, "received": 0, "total": total,
                    "generation": generation, "lifecycle": lifecycle, "phase": phase}
        if (start != first or first >= c.total or total != c.total or received > total or received < self.received
                or phase not in (1, 2, 3) or generation < b.min_generation
                or (self.reupload_generation is not None and generation != self.reupload_generation + 1)
                or (self.activation_generation is not None and generation != self.activation_generation)
                or lifecycle not in (2, 3, 4, 5) or known != 1 or floor != b.floor or counter != c.counter
                or (self.generation is not None and generation != self.generation)
                or bits >> count or bits.bit_count() > received
                or (previous and (received < previous["received"] or bits & previous["bits"] != previous["bits"]))
                or (lifecycle == 5 and (phase != 3 or received != total or bits != (1 << count) - 1))):
            raise Error("RF progress/generation/cache/floor/bitmap mismatch")
        self.generation = generation
        self.received = received
        self.pending_reupload = False
        report = {"first": first, "bits": bits, "received": received, "total": total,
                  "generation": generation, "lifecycle": lifecycle, "phase": phase}
        self.previous[first] = report
        return report

    def leave_direct(self):
        if self.lease_end:
            self.stock.radio(self.normal)
            self.profile, self.lease_end = self.normal, 0
            self.emit("lease_leave", frequency_khz=self.normal[0])
        self.wait_until(max(self.target_normal_after, self.next_normal))

    def negotiate(self):
        # Receiver ignores in-flight renewals. Wait out the old bounded lease,
        # then negotiate on normal frequency with a new signed token.
        self.leave_direct()
        c, b = self.candidate, self.binding
        self.room(30)
        prefix = (b"\x0c" + b.sender + b.target + c.digest
                  + struct.pack(">IHI", self.frequency, self.lease_ms, secrets.randbits(32)))
        request = prefix + self.stock.sign(DIRECT_DOMAIN + prefix, self.deadline)
        observer = self.rf_observer("lease")
        for attempt in range(1, 4):
            self.stock.frames.discard_rf(observer, b.target, c.digest)
            self.emit("lease_request", attempt=attempt, frequency_khz=self.frequency, lease_ms=self.lease_ms)
            since = self.send(request)
            self.emit("lease_sent", attempt=attempt, tx_evidence="aggregate-counters")
            # A lost ACK may still switch the receiver. Never invent a switch
            # or immediately retry during that unobserved lease.
            self.target_normal_after = self.clock() + 20 + self.lease_ms / 1000 + 2
            try:
                timestamp, ack = self.stock.frames.receive(
                    lambda p: p[:1] == b"\x0d", since, min(self.deadline, self.clock() + 22),
                    observer, b.target, c.digest)
            except TimeoutError:
                self.emit("lease_timeout", attempt=attempt)
                self.wait_until(max(self.target_normal_after, self.next_normal))
                prefix = prefix[:103] + struct.pack(">I", secrets.randbits(32))
                request = prefix + self.stock.sign(DIRECT_DOMAIN + prefix, self.deadline)
                continue
            if len(ack) != 171 or ack[1:107] != request[1:107]:
                raise Error("direct ACK target/owner/manifest/profile/token mismatch")
            verify(b.target, DIRECT_DOMAIN + ack[:107], ack[107:])
            self.emit("lease_ack_verified", attempt=attempt)
            self.target_normal_after = timestamp + 20 + self.lease_ms / 1000 + 2
            self.wait_until(timestamp + 5.5)
            self.stock.radio((self.frequency, 250000, 5, 5, 0))
            self.profile = (self.frequency, 250000, 5, 5, 0)
            self.lease_end = timestamp + 5 + self.lease_ms / 1000 - 2
            self.emit("lease_active", frequency_khz=self.frequency, lease_ms=self.lease_ms)
            return
        raise Error("signed normal-channel direct ACK retries exhausted")

    def authorize(self):
        c, b = self.candidate, self.binding
        signature = self.stock.sign(c.canonical, self.deadline)
        frame = b"\x08" + hashlib.sha256(b.target).digest()[:8] + b.sender + c.canonical + signature
        for attempt in range(1, 4):
            self.emit("auth_request", attempt=attempt, counter=c.counter, total=c.total)
            self.send(frame)
            self.emit("auth_sent", attempt=attempt, tx_evidence="aggregate-counters")
            try:
                return self.census(allow_pending=True)
            except NoCensus:
                self.emit("auth_no_census", attempt=attempt)
        self.emit("auth_exhausted", attempts=3)
        raise Error("target did not admit candidate; ROOT must resolve cache/admin state")

    def activate_prepared(self):
        if not self.pending_reupload or not self.reupload_enabled or self.pending_generation is None:
            raise Error("explicit REUPLOAD requires freshly observed prepared ABORTED descriptor")
        c, b = self.candidate, self.binding
        prefix = b"\x0e" + b.sender + b.target + c.digest + struct.pack(">I", self.pending_generation)
        frame = prefix + self.stock.sign(REUPLOAD_DOMAIN + prefix, self.deadline)
        for attempt in range(1, 4):
            if self.pending_reupload:
                self.emit("reupload_request", attempt=attempt, observed_generation=self.pending_generation)
                self.send(frame)
                self.emit("reupload_sent", attempt=attempt, observed_generation=self.pending_generation,
                          expected_generation=self.activation_generation, tx_evidence="aggregate-counters")
            try:
                report = self.census(allow_pending=True)
            except NoCensus:
                continue
            if report["lifecycle"] == 9:
                continue
            if report["received"] or report["bits"] or report["phase"] != 1:
                raise Error("REUPLOAD did not create a fresh remote candidate with zero bitmap")
            if report["lifecycle"] == 3:
                self.emit("reupload_receiving", generation=report["generation"])
                return report
            if report["lifecycle"] != 2:
                raise Error("REUPLOAD requires generation+1 Receiving, never old-cache promotion")
        raise Error("REUPLOAD activation/Receiving deadline exhausted")

    def upload(self):
        report = self.authorize()
        if report["lifecycle"] == 9:
            self.activate_prepared()
        self.negotiate()
        first = 0
        ready_windows = set()
        windows = tuple(range(0, self.candidate.total, 128))
        while True:
            try:
                report = self.census(first)
                if report["lifecycle"] == 5:
                    ready_windows.add(first)
                else:
                    ready_windows.discard(first)
                missing = [i for i in range(first, min(first + 128, self.candidate.total))
                           if not report["bits"] & (1 << (i - first))]
                for index in missing[:4]:
                    self.room(22)
                    self.attempts[index] = self.attempts.get(index, 0) + 1
                    if self.attempts[index] > 8:
                        raise Error("RF block repair retries exhausted")
                    message, prefix = block_message(self.candidate, index)
                    signature = self.stock.sign(message, min(self.deadline, self.lease_end))
                    self.send(prefix + signature)
                    self.emit("block_sent", index=index, attempt=self.attempts[index], total=self.candidate.total,
                              tx_evidence="aggregate-counters")
                # Retain the window cursor across leases; restarting at zero can
                # starve the tail of a real application with many bitmap windows.
                first = first + 128 if first + 128 < self.candidate.total else 0
                if len(ready_windows) == len(windows):
                    self.leave_direct()
                    for window in windows:
                        if self.census(window)["lifecycle"] != 5:
                            raise Error("READY lost after direct lease expiry")
                    self.emit("ready_observed_unsigned", generation=self.generation, total=self.candidate.total)
                    return self.receipt("ready-observed-unsigned")
            except LeaseExpired:
                self.emit("lease_margin_exhausted")
                self.negotiate()
            # Polling is bounded by stock TX completion and receiver reply wait.

    def receipt(self, outcome):
        return {"schema": 1, "outcome": outcome, "serial": self.binding.serial,
                "sender_public_key": self.binding.sender.hex(), "target_public_key": self.binding.target.hex(),
                "manifest_hash": self.candidate.digest.hex(), "counter": self.candidate.counter,
                "generation": self.generation, "installation_confirmed": False}

    def commit(self, receipt):
        expected = self.receipt("ready-observed-unsigned")
        expected["generation"] = receipt.get("generation")
        if (receipt != expected or type(receipt.get("generation")) is not int
                or receipt["generation"] < self.binding.min_generation):
            raise Error("commit requires matching target/owner/manifest/counter READY receipt")
        self.generation = receipt["generation"]
        # No admission/reupload in commit. Obtain current full-manifest RF READY.
        for first in range(0, self.candidate.total, 128):
            if self.census(first)["lifecycle"] != 5:
                raise Error("fresh READY required before separate signed COMMIT")
        body = self.binding.target + self.candidate.digest + struct.pack(">I", self.candidate.counter)
        signature = self.stock.sign(COMMIT_DOMAIN + body, self.deadline)
        self.emit("commit_request", generation=self.generation, counter=self.candidate.counter)
        self.send(b"\x03" + body + signature)
        self.emit("commit_sent", tx_evidence="aggregate-counters", installation_confirmed=False)
        return self.receipt("signed-commit-aggregate-tx-observed-not-install-confirmed")


@contextmanager
def radio_guard(stock, binding, directory, restoring=False):
    stock.expected_name = binding.sender_name
    original = stock.identify()
    path = directory / "original-radio.json"
    if restoring:
        saved = private_read(path)
        if (saved.get("schema") != 1 or saved.get("serial") != binding.serial
                or saved.get("sender_public_key") != binding.sender.hex()
                or saved.get("by_path") != binding.by_path or saved.get("id_path") != binding.id_path
                or saved.get("usb_vid") != binding.usb_vid or saved.get("usb_pid") != binding.usb_pid
                or ("tx_power_dbm" in saved and saved["tx_power_dbm"] != stock.tx_power)):
            raise Error("restore artifact not bound to this exact stock serial/public identity")
        profile = tuple(saved["profile"])
        validate_profile(profile)
        restore_radio(stock, profile)
        yield profile
        return
    private_write(path, {"schema": 1, "serial": binding.serial,
                         "sender_public_key": binding.sender.hex(), "profile": original,
                         "by_path": binding.by_path, "id_path": binding.id_path,
                         "usb_vid": binding.usb_vid, "usb_pid": binding.usb_pid, "tx_power_dbm": stock.tx_power})
    try:
        stock.radio((*binding.normal, 0))
        yield original
    finally:
        # Do not swallow failures: recovery must be explicit and artifact retained.
        restore_radio(stock, original)
        private_write(directory / "restored.json", {"restored": True})


def restore_radio(stock, profile):
    old = {s: signal.signal(s, signal.SIG_IGN) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        stock.radio(profile)
    finally:
        for signum, handler in old.items():
            signal.signal(signum, handler)


@dataclass(frozen=True)
class PortSelection:
    anchor: Path
    tty: Path
    device_id: int
    usb_device: Path
    id_path: str | None


def resolve_stock(serial, by_id, sys_devices=Path("/sys/bus/usb/devices"), *, by_path=None,
                  id_path=None, usb_vid=None, usb_pid=None, sys_tty=Path("/sys/class/tty"),
                  udev_data=Path("/run/udev/data")):
    if serial.upper() in DENIED_SERIALS:
        raise Error("explicit stable /dev/serial/by-id symlink required")
    # A colliding by-id is descriptive ONLY. Never even resolve it when the
    # explicitly authorized physical by-path anchor is present.
    path = Path(by_path) if by_path is not None else Path(by_id)
    if by_path is not None:
        if (path.parent != Path("/dev/serial/by-path") or not id_path or path.name != id_path + "-port0"
                or usb_vid is None or usb_pid is None):
            raise Error("exact authorized by-path/ID_PATH/VID/PID required")
    elif len(serial) < 12:
        raise Error("short/nonunique serial requires explicit ROOT-authorized by-path")
    elif not path.is_absolute() or path.parent != Path("/dev/serial/by-id"):
        raise Error("explicit stable /dev/serial/by-id symlink required")
    if not path.is_symlink():
        raise Error("authorized USB anchor is not a stable symlink")
    tty = path.resolve(strict=True)
    info = tty.stat()
    if tty.parent != Path("/dev") or not re.fullmatch(r"tty(ACM|USB)[0-9]+", tty.name) or not stat.S_ISCHR(info.st_mode):
        raise Error("invalid stable USB tty")
    device = (sys_tty / tty.name / "device").resolve(strict=True)
    owners = [p for p in (device, *device.parents) if (p / "idVendor").is_file() and (p / "idProduct").is_file()]
    if not owners:
        raise Error("selected tty has no USB physical owner")
    owner = owners[0]
    vid, pid = int((owner / "idVendor").read_text().strip(), 16), int((owner / "idProduct").read_text().strip(), 16)
    if (owner / "serial").read_text().strip() != serial:
        raise Error("physical USB serial does not match ROOT binding")
    cp2102 = (vid, pid) == (0x10C4, 0xEA60)
    if not cp2102 and (vid not in (0x2886, 0x239A) or not pid & 0x8000):
        raise Error("unknown/BOOT USB profile refused")
    if cp2102 and by_path is None:
        raise Error("CP2102 requires explicit by-path; by-id serial may collide")
    if by_path is not None:
        data = (udev_data / f"c{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}").read_text()
        properties = dict(line[2:].split("=", 1) for line in data.splitlines() if line.startswith("E:") and "=" in line)
        if ((vid, pid) != (usb_vid, usb_pid) or properties.get("ID_PATH") != id_path
                or properties.get("ID_SERIAL_SHORT") != serial
                or properties.get("ID_VENDOR_ID", "").lower() != f"{vid:04x}"
                or properties.get("ID_MODEL_ID", "").lower() != f"{pid:04x}"):
            raise Error("selected physical USB ID_PATH/serial/VID/PID changed or unauthorized")
        # Only after physical by-path validation, check the descriptive argument
        # syntax. Do not inspect/resolve its potentially colliding symlink.
        requested_id = Path(by_id)
        if not requested_id.is_absolute() or requested_id.parent != Path("/dev/serial/by-id"):
            raise Error("--by-id is informational only and must use /dev/serial/by-id")
        return PortSelection(path, tty, info.st_rdev, owner, id_path)
    matches = []
    for node in sys_devices.iterdir():
        serial_path = node / "serial"
        if ":" in node.name or not serial_path.is_file() or serial_path.read_text().strip() != serial:
            continue
        matches.append(node.resolve(strict=True))
    if matches != [owner]:
        raise Error("by-id USB serial not unique/exact; explicit authorized by-path required")
    return PortSelection(path, tty, info.st_rdev, owner, None)


def check_open_selection(stream, selection, current):
    info = os.fstat(stream.fileno())
    if (selection != current or info.st_rdev != selection.device_id or not stat.S_ISCHR(info.st_mode)):
        raise Error("authorized physical USB binding changed during open; no radio/sign/RF writes")

@contextmanager
def validated_stock_uart(binding, by_id, serial_factory=None, sleep=time.sleep):
    """Physical-bound quiet UART, not protocol verification or RF readiness."""
    def resolve():
        return resolve_stock(binding.serial, by_id, by_path=binding.by_path, id_path=binding.id_path,
                             usb_vid=binding.usb_vid, usb_pid=binding.usb_pid)
    selected = resolve()
    if serial_factory is None:
        import serial
        serial_factory = serial.Serial
    stream = serial_factory(port=None, baudrate=115200, timeout=0.1, exclusive=True)
    stream.dtr = False
    stream.rts = False
    stream.port = str(selected.anchor)
    try:
        stream.open()
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_open_selection(stream, selected, resolve())
        sleep(2.0)
        check_open_selection(stream, selected, resolve())
        yield stream
    finally:
        stream.close()


@contextmanager
def termination_cleanup():
    old = {}
    def interrupted(signum, _frame):
        # Subsequent TERM/INT cannot interrupt radio restoration.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise Error(f"interrupted by signal {signum}; closing UART, restoring radio only if its guard is active")
    for signum in (signal.SIGINT, signal.SIGTERM):
        old[signum] = signal.signal(signum, interrupted)
    try:
        yield
    finally:
        for signum, handler in old.items():
            signal.signal(signum, handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("operation", choices=("upload", "commit", "restore", "inspect"))
    parser.add_argument("--serial", required=True)
    parser.add_argument("--by-id", required=True)
    parser.add_argument("--by-path", help="explicit ROOT-bound physical anchor; required for short/duplicate CP2102 serial")
    parser.add_argument("--sender-key", required=True, type=full_key)
    parser.add_argument("--sender-name", help="optional explicit public label guard; must match ROOT sender_name")
    parser.add_argument("--target", required=True, type=full_key)
    parser.add_argument("--binding", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path, help="exclusive new 0700 directory (including inspect); existing only for restore")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--image", type=Path, help="pure ordinary APP .bin only")
    parser.add_argument("--ready-receipt", type=Path)
    retirement = parser.add_mutually_exclusive_group()
    retirement.add_argument("--reupload", action="store_true", help="upload only; ROOT allow_reupload:true, generation learned only from fresh RF census")
    retirement.add_argument("--reupload-generation", type=int, help="legacy upload-only strict expectation; signing still uses fresh RF-observed generation")
    parser.add_argument("--frequency-khz", type=int)
    parser.add_argument("--lease-ms", type=int, default=60000)
    parser.add_argument("--normal-duty-percent", type=float, default=2)
    parser.add_argument("--timeout", type=float, default=14400)
    args = parser.parse_args(argv)
    binding = Binding.load(args.binding, args.serial, args.sender_key, args.target, args.by_path, args.sender_name)
    if (args.reupload or args.reupload_generation is not None) and args.operation != "upload":
        raise Error("explicit REUPLOAD is supported only by upload, never COMMIT/restore")
    binding.permit_reupload(args.reupload_generation, args.reupload)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise Error("positive finite campaign timeout required")
    candidate = None
    receipt = None
    if args.operation in ("upload", "commit"):
        if not args.manifest or not args.image or args.frequency_khz is None:
            raise Error("upload/commit require manifest, ordinary APP image, direct frequency")
        if args.image.suffix != ".bin" or not args.image.is_file() or not args.manifest.is_file():
            raise Error("regular .bin APP and canonical59 manifest required; packages refused")
        candidate = Candidate.build(args.manifest.read_bytes(), args.image.read_bytes(), binding.floor)
        binding.approve(candidate)
        if (not MIN_LEASE <= args.lease_ms <= 60000 or not 150000 <= args.frequency_khz <= 2500000
                or args.frequency_khz == binding.normal[0] or not math.isfinite(args.normal_duty_percent)
                or not 0 < args.normal_duty_percent <= 100):
            raise Error("invalid direct lease/frequency/normal budget")
        if args.operation == "commit":
            if not args.ready_receipt:
                raise Error("separate COMMIT requires explicit READY receipt")
            receipt = private_read(args.ready_receipt)
        args.artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    elif args.operation == "inspect":
        args.artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    directory = args.artifacts
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise Error("owned private 0700 exclusive artifact directory required")
    with termination_cleanup():
        with validated_stock_uart(binding, args.by_id) as stream:
            stock = Stock(Frames(stream), binding.sender, expected_name=binding.sender_name)
            if args.operation == "inspect":
                profile = stock.identify()
                result = {"outcome": "read-only-identity-profile-match-no-rf-readiness",
                          "serial": binding.serial, "by_path": binding.by_path,
                          "public_key": binding.sender.hex(), "name": stock.name, "version": stock.version,
                          "radio_profile": profile, "tx_power_dbm": stock.tx_power,
                          "hardware_readiness_confirmed": False}
                private_write(directory / "result.json", result)
                print(json.dumps(result, sort_keys=True))
                return
            result = None
            with radio_guard(stock, binding, directory, args.operation == "restore") as profile:
                if candidate:
                    sender = Sender(stock, binding, candidate, profile, time.monotonic() + args.timeout,
                                    args.frequency_khz, args.lease_ms, args.normal_duty_percent / 100,
                                    reupload_generation=args.reupload_generation, reupload=args.reupload,
                                    event_callback=public_event)
                    result = sender.upload() if args.operation == "upload" else sender.commit(receipt)
            if result is not None:
                private_write(directory / "result.json", result)
                print(json.dumps(result, sort_keys=True))
            else:
                print("Original stock radio and repeat setting restored and read back.")


if __name__ == "__main__":
    try:
        main()
    except (Error, OSError, ValueError, TimeoutError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
