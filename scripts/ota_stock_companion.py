#!/usr/bin/env python3
"""Signed direct, directed or shared-flood OTA through a stock 1.17.1 companion.

Uses normal USB identity, signing, raw packet and measured-TX commands; never
native OTA CMD67, key export, contact mutation, reset or flash operations.
A caller-owned binding supplies exact sender/target identities, receiver normal
radio, confirmed floor and optional candidate hash/generation guards. No lab
inventory, approval ledger or private build provenance is used.

Deploy admits and transfers the selected board/role/image/counter, requires
fresh complete READY, signs one COMMIT and waits for matching native Installed
and confirmed floor. RF lifecycle reports are unsigned; output explicitly says
status_authenticated:false and installation_confirmed:false. Queue admission
and signed COMMIT alone never mean installation succeeded.

Direct mode persists, restores and reads back original radio/repeat settings.
Directed mode requires the sender already on the bound normal profile, never
retunes and accepts only attempt-matched reply floods bearing the selected
relay's path prefix. These path observations, like status, are unsigned.
Explicit restore reuses the original-settings artifact.
Background mode requires exactly two deployment-bound targets with the same
image/descriptor and normal profile. One initial block flood serves both, then
the union of their missing bitmaps drives common selective repairs. Individual
COMMITs bind each target's own generation/nonce. Channel 255 is an unscoped
normal-radio flood, not a native companion's configured multicast channel.
It never retunes, re-BEGINs, REUPLOADs, takes over or resets a target.
Explicit paired schema-3 attempt receipts can resume the same two Receiving
or READY candidates. Both receipts and fresh attempt-bound censuses are checked
before signing data; resume sends only their common missing-block union.
Selective repairs use the existing four-block burst limit, refreshing both
targets after each burst and rotating bitmap windows rather than draining an
entire missing-image pass without receiver feedback. Validated windows complete
on both targets are skipped during repair, with fresh READY validation at the end.
Cancellation stops the whole campaign immediately, retaining prior unsigned
outcomes in a non-success result before normal-profile/UART cleanup.
Valid unsolicited stock pushes and OTA data/request echoes are counted with
bounded metadata-only logging, not queued as replies. Census/lease replies
remain pending. Cleanup readback failure is recorded, never assumed unchanged.
Stable USB selection and flock prevent endpoint races/concurrent readers; normal
115200 serial is opened with RTS false and caller-selected DTR before open.
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
import signal
import stat
import struct
import sys
import time

MAX_FRAME = 176
BLOCK = 84
MIN_LEASE = 30000
# OTA wire version 3: census reports carry the receiver's durable per-BEGIN
# nonce and a single-use lease challenge; COMMIT binds generation + nonce.
WIRE_VERSION = 3
CENSUS_REPORT_BYTES = 123
NONCE_BYTES = 16
DIRECT_DOMAIN = b"MeshCore/OTA/direct/v3"
DIRECT_PROFILE_DOMAIN = b"MeshCore/OTA/direct-profile/v3"
COMMIT_DOMAIN = b"MeshCore/OTA/commit/v2"
REUPLOAD_DOMAIN = b"MeshCore/OTA/reupload/v1"
RECEIPT_SCHEMA = 2
ATTEMPT_RECEIPT_SCHEMA = 3


class Error(RuntimeError):
    pass


class Cancelled(Error):
    pass


class LeaseExpired(Error):
    pass


class DeadlineExpired(Error, TimeoutError):
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
    image_hash: bytes | None = None
    manifest_hash: bytes | None = None
    reupload_generation: int | None = None
    by_path: str | None = None
    id_path: str | None = None
    usb_vid: int | None = None
    usb_pid: int | None = None
    sender_name: str | None = None
    allow_reupload: bool = False

    @classmethod
    def load(cls, path, serial, sender, target, by_path=None, sender_name=None):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", serial):
            raise Error("explicit stock USB serial required")
        value = private_read(path)
        if (value.get("schema") != 1 or value.get("serial") != serial
                or full_key(value.get("sender_public_key")) != sender
                or full_key(value.get("target_public_key")) != target or sender == target):
            raise Error("deployment binding does not match this sender/target")
        if value.get("by_path") != by_path:
            raise Error("explicit --by-path must match the deployment binding")
        id_path, vid, pid = value.get("id_path"), value.get("usb_vid"), value.get("usb_pid")
        if by_path is not None:
            anchor = Path(by_path)
            if (anchor.parent != Path("/dev/serial/by-path") or not isinstance(id_path, str)
                    or anchor.name != id_path + "-port0"
                    or not all(isinstance(x, str) and re.fullmatch(r"[0-9a-fA-F]{4}", x) for x in (vid, pid))):
                raise Error("by-path/ID_PATH/full USB VID/PID binding required")
            vid, pid = int(vid, 16), int(pid, 16)
        elif any(x is not None for x in (id_path, vid, pid)):
            raise Error("USB path metadata requires explicit deployment-bound --by-path")
        name = value.get("sender_name")
        if ((name is not None and (not isinstance(name, str) or not 0 < len(name.encode("utf-8")) <= 31 or "\x00" in name))
                or (sender_name is not None and sender_name != name)
               ):
            raise Error("public sender_name guard must match the deployment binding")
        floor, generation = value.get("floor"), value.get("min_generation")
        if (type(floor) is not int or not 0 <= floor < 0xFFFFFFFF
                or type(generation) is not int or not 0 < generation <= 0xFFFFFFFF):
            raise Error("measured target floor and positive generation guard required")
        profile = value.get("normal_profile")
        validate_profile(profile + [0] if isinstance(profile, list) else ())
        old_generation = value.get("reupload_generation")
        if old_generation is not None and (type(old_generation) is not int or not 0 < old_generation < 0xFFFFFFFF
                                           or generation != old_generation + 1):
            raise Error("REUPLOAD requires exact old generation and min_generation=old+1")
        allow_reupload = value.get("allow_reupload", False)
        if type(allow_reupload) is not bool:
            raise Error("allow_reupload must be an explicit boolean")
        return cls(serial, sender, target, floor, generation, tuple(profile),
                   full_key(value["image_sha256"]) if "image_sha256" in value else None,
                   full_key(value["manifest_hash"]) if "manifest_hash" in value else None, old_generation,
                   by_path, id_path, vid, pid, name, allow_reupload)

    def check_candidate(self, candidate):
        if ((self.image_hash is not None and hashlib.sha256(candidate.image).digest() != self.image_hash)
                or (self.manifest_hash is not None and candidate.digest != self.manifest_hash)):
            raise Error("image/manifest does not match the optional deployment binding")

    def permit_reupload(self, generation, reupload=False):
        if type(reupload) is not bool or (reupload and (not self.allow_reupload or generation is not None)):
            raise Error("explicit --reupload requires allow_reupload:true and no fixed generation")
        if generation is not None and (type(generation) is not int or not 0 < generation < 0xFFFFFFFF
                                       or generation != self.reupload_generation or self.min_generation != generation + 1):
            raise Error("explicit REUPLOAD generation does not match binding/new-generation guard")


def validate_profile(profile):
    if (len(profile) != 5 or any(type(x) is not int for x in profile)
            or not 150000 <= profile[0] <= 2500000 or not 7000 <= profile[1] <= 500000
            or not 5 <= profile[2] <= 12 or not 5 <= profile[3] <= 8 or profile[4] not in (0, 1)):
        raise Error("invalid stock radio profile")


def validate_transport(mode, frequency, lease_ms, channel, relay, path_hash_bytes, binding=None):
    if mode not in ("direct", "directed", "background") or channel != 255:
        raise Error("stock supports direct/directed/background on the existing radio channel (channel 255) only")
    if path_hash_bytes not in (1, 2, 3):
        raise Error("MeshCore path hashes must be 1, 2 or 3 bytes")
    if mode == "direct":
        if relay is not None or path_hash_bytes != 1:
            raise Error("explicit relay/path requires directed mode")
        if (type(frequency) is not int or not 150000 <= frequency <= 2500000
                or not MIN_LEASE <= lease_ms <= 60000
                or (binding is not None and frequency == binding.normal[0])):
            raise Error("off-normal frequency and host lease 30000..60000ms required")
    elif mode == "directed":
        if frequency != 0 or lease_ms != 0:
            raise Error("directed mode requires zero frequency/lease; no retune or lease fallback")
        if not isinstance(relay, bytes) or len(relay) != 32 or not any(relay):
            raise Error("directed mode requires one explicit full --relay-key")
        if binding is not None and any(relay[:1] == key[:1] for key in (binding.sender, binding.target)):
            raise Error("relay hash must be distinct from sender/target for width-1 reply evidence")
    elif frequency != 0 or lease_ms != 0 or relay is not None or path_hash_bytes != 1:
        raise Error("background requires normal-channel flood: zero frequency/lease, no relay/path override")


@dataclass(frozen=True)
class Candidate:
    canonical: bytes
    image: bytes
    digest: bytes
    counter: int
    total: int

    @classmethod
    def build(cls, canonical, image, floor, *, board=None, role_id=None, counter=None):
        if board is not None:
            from ota_uploader import deploy_manifest
            canonical = deploy_manifest(image, board, role_id, counter, canonical)
            security_counter = struct.unpack_from(">I", canonical, 45)[0]
            if not floor < security_counter:
                raise Error("candidate counter must exceed the measured anti-rollback floor")
            if board != "xiao_s3_wio":
                address = struct.unpack_from(">I", canonical, 5)[0]
                if len(image) < 8:
                    raise Error("ordinary APP vector required")
                stack, reset = struct.unpack_from("<II", image)
                if (not 0x20000000 < stack <= 0x20040000 or stack % 8 or not reset & 1
                        or not address <= (reset & ~1) < address + len(image)):
                    raise Error("ordinary APP vector required; packages/boot images refused")
            return cls(canonical, image, hashlib.sha256(canonical).digest(), security_counter,
                       (len(image) + BLOCK - 1) // BLOCK)
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


def packet(payload, path=b"", hash_size=1, *, route=2):
    if route not in (1, 2) or (route == 1 and (path or hash_size != 1)):
        raise Error("stock flood requires an empty width-1 path")
    if (hash_size not in (1, 2, 3) or len(path) > 64 or len(path) % hash_size
            or len(path) // hash_size > 63):
        raise Error("invalid MeshCore path hash width/count")
    encoded = ((hash_size - 1) << 6) | (len(path) // hash_size)
    raw = bytes([0x30 | route, encoded]) + path + payload
    if not payload or len(raw) + 2 > MAX_FRAME:
        raise Error("CMD65 exceeds stock 176-byte frame")
    return raw


def rf_packet(frame):
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
    if hash_size == 4 or path_bytes > 64 or offset >= len(frame):
        return None
    return header & 3, hash_size, frame[5:offset], frame[offset:]


def retry_frame(payload, attempt, repair=False):
    if (type(attempt) is not int or not 0 < attempt <= 0xFFFFFFFF
            or not valid_retry_inner(payload) or len(payload) + 5 > 171
            or (repair and payload[0] != 1)):
        raise Error("invalid existing OTA retry attempt/inner frame")
    return bytes([0x12 if repair else 0x11]) + struct.pack(">I", attempt) + payload


def valid_retry_inner(payload):
    if not payload:
        return False
    sizes = {2: 156, 3: 153, 4: 165, 6: 42, 7: 5, 8: 164, 10: 67,
             11: CENSUS_REPORT_BYTES, 14: 165}
    return (72 <= len(payload) <= 155 if payload[0] == 1
            else len(payload) == sizes.get(payload[0]))


def retry_payload(payload):
    if payload[:1] not in (b"\x11", b"\x12"):
        return None, payload
    if not 5 < len(payload) <= 171:
        return None, None
    attempt = struct.unpack_from(">I", payload, 1)[0]
    inner = payload[5:]
    if not attempt or not valid_retry_inner(inner) or (payload[0] == 0x12 and inner[0] != 1):
        return None, None
    return attempt, inner


def raw_rx(frame):
    decoded = rf_packet(frame)
    return retry_payload(decoded[3])[1] if decoded is not None else None


def rf_metadata(frame, payload, target, manifest):
    header = frame[3] if len(frame) >= 5 else None
    kind = payload[0] if payload else None
    target_offset = {11: 1, 13: 33, 16: 33}.get(kind)
    hash_offset = {11: 33, 13: 65, 16: 65}.get(kind)
    decoded = rf_packet(frame)
    attempt = retry_payload(decoded[3])[0] if decoded is not None else None
    return {"usb_length": len(frame), "packet_length": max(0, len(frame) - 3),
            "path_hash_bytes": decoded[1] if decoded is not None else None,
            "path": decoded[2].hex() if decoded is not None else None,
            "retry_attempt": attempt,
            "route": header & 3 if header is not None else None,
            "version": header >> 6 if header is not None else None,
            "payload_type": (header >> 2) & 15 if header is not None else None,
            "decoded": payload is not None, "kind": kind,
            "payload_length": len(payload) if payload is not None else None,
            "block_index": struct.unpack_from(">H", payload, 5)[0]
            if kind == 1 and len(payload) >= 7 else None,
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


# Ordinary MeshCore 1.17.1 companion pushes (examples/companion_radio/MyMesh.cpp)
# that this uploader never consumes, with the exact lengths that firmware emits.
# 0x88 LOG_RX_DATA needs payload-aware demux: it also carries census/ACK replies.
UNUSED_PUSH_LENGTHS = {
    0x80: range(33, 34),              # ADVERT: code + public key
    0x81: range(33, 34),              # PATH_UPDATED: code + public key
    0x82: range(9, 10),               # SEND_CONFIRMED: code + ack + trip time
    0x83: range(1, 2),                # MSG_WAITING
    0x84: range(4, MAX_FRAME + 1),    # RAW_DATA: code + SNR + RSSI + reserved + payload
    0x85: (8, 14),                    # LOGIN_SUCCESS: legacy or v7
    0x86: range(8, 9),                # LOGIN_FAIL
    0x87: range(9, MAX_FRAME + 1),    # STATUS_RESPONSE
    0x89: range(13, MAX_FRAME + 1),   # TRACE_DATA
    0x8A: range(148, 149),            # NEW_ADVERT: full contact record
    0x8B: range(8, MAX_FRAME + 1),    # TELEMETRY_RESPONSE
    0x8C: range(7, MAX_FRAME + 1),    # BINARY_RESPONSE
    0x8D: range(10, MAX_FRAME + 1),   # PATH_DISCOVERY_RESPONSE
    0x8E: range(4, MAX_FRAME + 1),    # CONTROL_DATA
    0x8F: range(33, 34),              # CONTACT_DELETED: code + public key
    0x90: range(1, 2),                # CONTACTS_FULL
}
PENDING_LIMIT = 256


def ota_nonreply(payload):
    if not payload or payload[0] in (11, 13, 16):
        return False
    return (valid_retry_inner(payload) or
            (payload[0] in (12, 15) and len(payload) == 171) or
            (payload[0] == 9 and 100 <= len(payload) <= 183))


def unused_push(frame):
    """True only for well-formed pushes that can never answer an OTA exchange.

    Ordinary pushes and valid OTA requests/data echoes cannot answer a host
    exchange. Census/lease replies, malformed and unknown frames stay queued.
    """
    code = frame[0]
    if code == 0x88:
        if len(frame) < 5 or frame[3] >> 6:
            return False
        return (frame[3] >> 2) & 15 != 12 or ota_nonreply(raw_rx(frame))
    lengths = UNUSED_PUSH_LENGTHS.get(code)
    if lengths is None:
        return False
    if len(frame) not in lengths:
        raise Error(f"malformed stock push 0x{code:02x}; raw USB fields withheld")
    return True


class Frames:
    """Bounded stock USB framing; no logging of opaque USB/DeviceQuery fields."""
    def __init__(self, stream, clock=time.monotonic, *, event_callback=None, keep_login_pushes=False):
        self.stream, self.clock = stream, clock
        self.buffer = bytearray()
        self.pending = []
        self.ignored = {}
        self.unsolicited = {}
        self.event_callback = event_callback
        self.keep_login_pushes = keep_login_pushes

    def observe_unused(self, frame):
        self.ignored[frame[0]] = self.ignored.get(frame[0], 0) + 1
        payload = raw_rx(frame) if frame[0] == 0x88 else None
        kind = payload[0] if payload else None
        key = f"0x{frame[0]:02x}" + (f"/ota-{kind}" if kind is not None else "")
        count = self.unsolicited[key] = self.unsolicited.get(key, 0) + 1
        # First observation and powers of two bound log volume independently
        # of image size. Final aggregate artifacts retain the exact counts.
        if self.event_callback is not None and count & (count - 1) == 0:
            event = {"event": "usb_unsolicited_observed", "usb_code": frame[0],
                     "usb_length": len(frame), "count": count, "counter_key": key}
            if frame[0] == 0x88:
                event.update(rf_metadata(frame, payload, None, None))
            self.event_callback(event)

    def backlog(self):
        codes, kinds = {}, {}
        for _, frame in self.pending:
            code = f"0x{frame[0]:02x}"
            codes[code] = codes.get(code, 0) + 1
            if frame[0] == 0x88:
                payload = raw_rx(frame)
                kind = str(payload[0]) if payload else "unparsed"
                kinds[kind] = kinds.get(kind, 0) + 1
        return {"pending_limit": PENDING_LIMIT, "pending_count": len(self.pending),
                "pending_codes": codes, "pending_ota_kinds": kinds}

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
            if unused_push(frame) and not (self.keep_login_pushes and frame[0] in (0x85, 0x86)):
                self.observe_unused(frame)
                continue
            if len(self.pending) >= PENDING_LIMIT:
                if self.event_callback is not None:
                    self.event_callback({"event": "usb_backlog_overflow", "incoming_code": frame[0],
                                         "incoming_length": len(frame), **self.backlog()})
                raise Error("USB response backlog overflow")
            self.pending.append((self.clock(), frame))

    def wait(self, expected, since, deadline):
        """Receive a fresh USB reply without transmitting or clearing peers."""
        while self.clock() < deadline:
            for index, (timestamp, frame) in enumerate(self.pending):
                if frame[0] in expected:
                    self.pending.pop(index)
                    if timestamp >= since:
                        return frame
                    break
            else:
                self.poll(min(0.1, deadline - self.clock()))
        raise NoUsbResponse("USB asynchronous response deadline")

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
        deadline = self.clock() + timeout
        self.poll(0)
        self.pending = [(t, f) for t, f in self.pending if f[0] not in expected]
        wire = b"<" + struct.pack("<H", len(payload)) + payload
        self.stream.write_timeout = max(0, deadline - self.clock())
        if self.stream.write_timeout <= 0:
            raise NoUsbResponse("USB write deadline")
        if self.stream.write(wire) != len(wire):
            raise Error("short USB write")
        while self.clock() < deadline:
            for i, (_, frame) in enumerate(self.pending):
                if frame[0] in expected:
                    self.pending.pop(i)
                    return frame
            self.poll(min(0.1, deadline - self.clock()))
        raise NoUsbResponse("USB command deadline; no response")

    def discard_rf(self, observer=None, target=None, manifest=None, *, preserve_other_targets=False):
        self.poll(0)
        kept = []
        for timestamp, frame in self.pending:
            if frame[0] == 0x88:
                payload = raw_rx(frame)
                offset = {11: 1, 13: 33, 16: 33}.get(payload[0]) if payload else None
                if (preserve_other_targets and offset is not None
                        and payload[offset:offset + 32] != target):
                    kept.append((timestamp, frame))
                    continue
                if observer is not None:
                    observer({"event": "rf_discard", **rf_metadata(frame, raw_rx(frame), target, manifest)})
            else:
                kept.append((timestamp, frame))
        self.pending = kept

    def receive(self, predicate, since, deadline, observer=None, target=None, manifest=None,
                route_predicate=None, preserve_unmatched=False):
        while self.clock() < deadline:
            for i, (timestamp, frame) in enumerate(self.pending):
                if frame[0] == 0x88:
                    payload = raw_rx(frame)
                    if (preserve_unmatched and payload and payload[0] in (11, 13, 16)
                            and timestamp >= since and not predicate(payload)):
                        continue
                    self.pending.pop(i)
                    if observer is not None:
                        observer({"event": "rf_rx", "fresh": timestamp >= since,
                                  **rf_metadata(frame, payload, target, manifest)})
                    if (timestamp >= since and payload is not None
                            and (route_predicate is None or route_predicate(frame))
                            and predicate(payload)):
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
            raise Error("stock public sender name does not match public label guard")
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

    def radio(self, profile, deadline=None):
        validate_profile(profile)
        if self.pending_tx is not None:
            drain_deadline = min(deadline, self.clock() + 8) if deadline is not None else self.clock() + 8
            while self.clock() < drain_deadline:
                queue, sent, direct, _ = self.stats(drain_deadline)
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
        self.ok(b"\x0b" + struct.pack("<II", *profile[:2]) + bytes(profile[2:]), deadline)
        if self.identify(deadline) != tuple(profile):
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

    def stats(self, deadline, include_airtime=True):
        core = self.command(b"\x38\x00", (24, 1), deadline)
        packets = self.command(b"\x38\x02", (24, 1), deadline)
        if (len(core) != 11 or core[:2] != b"\x18\x00" or len(packets) != 30
                or packets[:2] != b"\x18\x02"):
            raise Error("required stock queue/physical TX/radio statistics unavailable")
        air = self.tx_airtime(deadline) if include_airtime else 0
        return core[10], struct.unpack_from("<I", packets, 6)[0], struct.unpack_from("<I", packets, 14)[0], air

    def tx_airtime(self, deadline):
        radio = self.command(b"\x38\x01", (24, 1), deadline)
        if len(radio) != 14 or radio[:2] != b"\x18\x01":
            raise Error("required stock radio statistics unavailable")
        return struct.unpack_from("<I", radio, 6)[0]


def airtime(raw_length, profile):
    _, bw, sf, cr, _ = profile
    symbol = 2 ** sf / bw
    de = int(symbol >= 0.016)
    preamble = 32 if sf <= 8 else 16
    payload_symbols = 8 + max(0, math.ceil((8 * raw_length - 4 * sf + 28 + 16) / (4 * (sf - 2 * de))) * cr)
    # Margin covers driver/low-SF differences; stats supply actual elapsed TX.
    return (preamble + 4.25 + payload_symbols) * symbol * 1.5


def attempt_fields(binding, candidate, profile, tx_power, duty, report):
    return {"schema": ATTEMPT_RECEIPT_SCHEMA,
            "image_sha256": hashlib.sha256(candidate.image).hexdigest(),
            "image_size": len(candidate.image), "total_blocks": candidate.total,
            "floor": binding.floor, "min_generation": binding.min_generation,
            "normal_duty_percent": duty * 100,
            "normal_profile": list(binding.normal), "sender_profile": list(profile),
            "tx_power_dbm": tx_power, "by_path": binding.by_path,
            "id_path": binding.id_path, "usb_vid": binding.usb_vid, "usb_pid": binding.usb_pid,
            "sender_name": binding.sender_name,
            "first": report["first"], "received_blocks": report["received"],
            "bitmap": report["bits"].to_bytes(16, "little").hex(),
            "status_authenticated": False}


def resume_progress(receipt, binding, candidate):
    if not isinstance(receipt, dict):
        raise Error("resume requires an original attempt receipt")
    generation, nonce = receipt.get("generation"), receipt.get("begin_nonce")
    received, bitmap = receipt.get("received_blocks"), receipt.get("bitmap")
    old_duty = receipt.get("normal_duty_percent")
    if (type(generation) is not int or not binding.min_generation <= generation <= 0xFFFFFFFF
            or not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or not any(bytes.fromhex(nonce))
            or type(received) is not int or not 0 <= received <= candidate.total
            or type(old_duty) not in (int, float) or not math.isfinite(old_duty) or not 0 < old_duty <= 100
            or not isinstance(bitmap, str) or not re.fullmatch(r"[0-9a-f]{32}", bitmap)):
        raise Error("resume requires original generation, BEGIN nonce and bounded progress")
    bits = int.from_bytes(bytes.fromhex(bitmap), "little")
    if bits >> min(128, candidate.total) or bits.bit_count() > received:
        raise Error("resume receipt bitmap/progress mismatch")
    return generation, nonce, old_duty, {"first": 0, "received": received, "bits": bits}


class Sender:
    def __init__(self, stock, binding, candidate, profile, deadline, frequency, lease_ms=60000,
                 duty=0.02, clock=time.monotonic, sleep=time.sleep, reupload_generation=None, reupload=False,
                 event_callback=None, *, mode="direct", relay=None, path_hash_bytes=1, channel=255,
                 attempt_callback=None):
        validate_transport(mode, frequency, lease_ms, channel, relay, path_hash_bytes, binding)
        validate_profile(profile)
        if mode != "direct" and tuple(profile[:4]) != binding.normal:
            raise Error(f"{mode} sender must already match the bound normal radio profile; no retune")
        if not math.isfinite(duty) or not 0 < duty <= 1:
            raise Error("normal-channel duty must be in (0,1]")
        binding.check_candidate(candidate)
        binding.permit_reupload(reupload_generation, reupload)
        self.stock, self.binding, self.candidate = stock, binding, candidate
        self.mode, self.relay, self.path_hash_bytes = mode, relay, path_hash_bytes
        self.path = relay[:path_hash_bytes] if relay is not None else b""
        self.next_attempt = (int.from_bytes(os.urandom(4), "big") or 1) if mode != "direct" else None
        self.last_tx_attempt = None
        self.original = tuple(profile)
        self.normal = self.original if mode != "direct" else (*binding.normal, 0)
        self.profile, self.deadline = self.normal, deadline
        self.frequency, self.lease_ms, self.duty = frequency, lease_ms, duty
        self.direct_bandwidth = 250000
        self.burst_blocks = 4
        self.clock, self.sleep = clock, sleep
        self.next_normal = clock()
        self.lease_end = 0
        self.target_normal_after = 0
        self.generation = None
        self.begin_nonce = None
        self.challenge = None
        self.previous = {}
        self.received = 0
        self.attempts = {}
        self.reupload_generation = reupload_generation
        self.reupload_enabled = reupload or reupload_generation is not None
        self.pending_generation = None
        self.activation_generation = None
        self.pending_reupload = False
        self.event_callback, self.event_start = event_callback, clock()
        self.attempt_callback, self.attempt_recorded = attempt_callback, False

    def emit(self, event, **fields):
        if self.event_callback is not None:
            self.event_callback({"event": event, "elapsed_s": round(self.clock() - self.event_start, 3), **fields})

    def rf_observer(self, phase):
        return (lambda data: self.emit(phase=phase, **data)) if self.event_callback is not None else None

    def wait_until(self, when):
        if when >= self.deadline:
            raise DeadlineExpired("campaign deadline expired")
        if when > self.clock():
            self.sleep(when - self.clock())

    def room(self, seconds):
        if self.clock() + seconds >= self.deadline:
            raise DeadlineExpired("campaign deadline expired")
        if self.lease_end and self.clock() + seconds >= self.lease_end:
            raise LeaseExpired("direct lease operation margin exhausted")

    def send(self, payload, *, repair=None):
        self.room(9)
        if not payload:
            raise Error("empty OTA payload")
        inner_kind = payload[0]
        attempt = None
        if self.mode != "direct":
            if self.next_attempt > 0xFFFFFFFF:
                raise Error("OTA retry attempts exhausted; no wrap/replay fallback")
            attempt = self.next_attempt
            payload = retry_frame(payload, attempt, repair=inner_kind == 1 if repair is None else repair)
            self.next_attempt += 1
        route = 1 if self.mode == "background" else 2
        raw = packet(payload, self.path, self.path_hash_bytes, route=route)
        command = bytes([65, 250 if self.mode != "direct" else 0]) + raw
        normal = self.profile == self.normal
        if normal:
            self.wait_until(self.next_normal)
        deadline = min(self.deadline, self.clock() + 8, self.lease_end or self.deadline)
        if self.mode != "direct" and self.stock.identify(deadline) != self.original:
            raise Error(f"{self.mode} sender normal radio/repeat profile changed; no retune")
        before = self.stock.stats(deadline)
        if before[0]:
            raise Error("stock outbound queue not exclusive/idle")
        started = self.clock()
        estimate = airtime(len(raw), self.profile)
        self.last_tx_attempt = attempt
        self.emit("rf_tx_request", mode=self.mode, route=route, path_hash_bytes=self.path_hash_bytes,
                  path=self.path.hex(), retry_attempt=attempt, kind=inner_kind,
                  packet_length=len(raw), frequency_khz=self.profile[0], normal_duty_percent=self.duty * 100)
        self.stock.pending_tx = before[1:3]
        try:
            self.stock.ok(command, deadline)
        except Refused:
            self.stock.pending_tx = None
            raise
        # CMD65 OK only admits to a queue. Require one physical TX and the
        # matching direct/non-direct counter delta, not merely a drained queue.
        while self.clock() < deadline:
            after = self.stock.stats(deadline)
            sent = (after[1] - before[1]) & 0xFFFFFFFF
            direct = (after[2] - before[2]) & 0xFFFFFFFF
            if sent > 1 or direct > 1:
                raise Error("concurrent/unattributable stock radio traffic")
            if not after[0] and sent == 1 and direct == (route == 2):
                self.stock.pending_tx = None
                actual_air = after[3]
                spent = max(estimate, self.clock() - started,
                            (actual_air - before[3]) & 0xFFFFFFFF)
                if normal:
                    self.next_normal = self.clock() + spent * (1 / self.duty - 1)
                else:
                    guard = max(0.05, spent)
                    self.room(guard)
                    self.sleep(guard)
                return started
            self.sleep(max(0.05, min(0.25, estimate / 2)))
        raise Error("no measured physical stock TX completion")

    def reply_route(self, frame):
        if self.mode == "direct":
            return True
        decoded = rf_packet(frame)
        if decoded is None:
            return False
        route, width, path, payload = decoded
        attempt, inner = retry_payload(payload)
        # Mesh::pumpOtaControl emits width-1 floods on the normal channel.
        # Directed mode also requires the selected relay's reply trail.
        matched = (route == 1 and width == 1
                   and (self.mode == "background" or path == self.relay[:1]) and attempt is not None
                   and attempt == self.last_tx_attempt and inner is not None)
        self.emit("rf_reply_route", route=route, path_hash_bytes=width, path=path.hex(),
                  retry_attempt=attempt, expected_attempt=self.last_tx_attempt,
                  selected_relay_match=matched if self.mode == "directed" else None,
                  attempt_route_match=matched, evidence_authenticated=False)
        return matched

    def census(self, first=0, retries=3, allow_pending=False, post_commit=False):
        self.room(15)
        c, b = self.candidate, self.binding
        observer = self.rf_observer("census")
        for attempt in range(1, retries + 1):
            self.stock.frames.discard_rf(observer, b.target, c.digest,
                                         preserve_other_targets=self.mode == "background")
            self.emit("census_request", attempt=attempt, first=first, allow_pending=allow_pending,
                      channel="direct" if self.lease_end else "normal")
            since = self.send(b"\x0a" + b.target + c.digest + struct.pack(">H", first))
            self.emit("census_sent", attempt=attempt, first=first, tx_evidence="aggregate-counters")
            try:
                reply_wait = 4 if self.lease_end else 25
                _, frame = self.stock.frames.receive(
                    lambda p: p[:1] == b"\x0b" and (self.mode != "background" or p[1:33] == b.target), since,
                    min(self.deadline, self.clock() + reply_wait, self.lease_end or self.deadline),
                    observer, b.target, c.digest, route_predicate=self.reply_route,
                    preserve_unmatched=self.mode == "background")
            except TimeoutError:
                self.emit("census_timeout", attempt=attempt, first=first)
                self.room(15)
                if attempt < retries:
                    self.emit("census_retry", next_attempt=attempt + 1, first=first)
                continue
            try:
                report = self.parse_census(frame, first, allow_pending, post_commit)
            except Error as exc:
                self.emit("census_rejected", first=first, reason=str(exc))
                raise
            self.emit("census_parsed", first=report["first"], lifecycle=report["lifecycle"],
                      generation=report["generation"], phase=report["phase"],
                      received=report["received"], total=report["total"], bitmap_count=report["bits"].bit_count(),
                      begin_nonce=None if self.begin_nonce is None else self.begin_nonce.hex(),
                      bitmap=report["bits"].to_bytes(16, "little").hex(), status_authenticated=False)
            if (self.attempt_callback is not None and not self.attempt_recorded
                    and not post_commit and not self.pending_reupload and self.begin_nonce is not None):
                self.attempt_callback(self.attempt_receipt(report))
                self.attempt_recorded = True
            return report
        self.emit("census_exhausted", first=first, attempts=retries)
        raise NoCensus("fresh RF census deadline/retries exhausted")

    def parse_census(self, frame, first, allow_pending=False, post_commit=False):
        c, b = self.candidate, self.binding
        if frame[:1] != b"\x0b" or frame[1:33] != b.target or frame[33:65] != c.digest:
            raise Error("RF census target/full manifest mismatch")
        if len(frame) != CENSUS_REPORT_BYTES or frame[102] != WIRE_VERSION:
            raise Error("receiver OTA wire version is unsupported (legacy census report); "
                        "update the receiver firmware before uploading")
        start = struct.unpack_from(">H", frame, 65)[0]
        received, total, phase, generation, lifecycle, known, floor, counter = struct.unpack_from(">HHBIBBII", frame, 83)
        nonce = frame[103:119]
        self.challenge = struct.unpack_from(">I", frame, 119)[0] or None
        bits = int.from_bytes(frame[67:83], "little")
        count = min(128, c.total - first)
        previous = self.previous.get(first)
        if post_commit:
            if (start != first or not 0 <= first < c.total or total != c.total or received > total
                    or bits >> count or bits.bit_count() > received or counter != c.counter
                    or generation != self.generation or generation < b.min_generation or known not in (0, 1)):
                raise Error("post-COMMIT native status target/manifest/generation/geometry mismatch")
            if lifecycle == 10:
                raise Error("native FAILED: candidate installation failed or rolled back")
            if lifecycle == 9:
                raise Error("native ABORTED: candidate was not installed")
            if (lifecycle not in (5, 6, 7, 8) or phase not in (3, 4)
                    or received != total or bits != (1 << count) - 1
                    or (known and floor not in (b.floor, c.counter))):
                raise Error("invalid post-COMMIT native lifecycle/progress/floor")
            if lifecycle == 8 and (known != 1 or floor != c.counter):
                raise Error("native INSTALLED requires matching confirmed floor")
            if self.begin_nonce is None or nonce != self.begin_nonce or not any(nonce):
                raise Error("post-COMMIT status belongs to a different BEGIN attempt")
            return {"first": first, "bits": bits, "received": received, "total": total,
                    "generation": generation, "lifecycle": lifecycle, "phase": phase,
                    "floor_known": bool(known), "confirmed_floor": floor}
        if lifecycle == 9:
            if not allow_pending or not self.reupload_enabled:
                raise Error("pending ABORTED requires explicit REUPLOAD; no auto-abort/clear")
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
        if not any(nonce) or (self.begin_nonce is not None and nonce != self.begin_nonce):
            raise Error("RF census belongs to an unbound or different BEGIN attempt")
        self.begin_nonce = nonce
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
        if self.mode != "direct":
            return
        # Receiver ignores in-flight renewals. Wait out the old bounded lease,
        # then negotiate on normal frequency with a new signed token.
        self.leave_direct()
        c, b = self.candidate, self.binding
        self.room(30)
        kind, ack_kind = b"\x0c", b"\x0d"
        domain = DIRECT_DOMAIN
        frequency_word = self.frequency
        observer = self.rf_observer("lease")
        for attempt in range(1, 4):
            # The token is the receiver's current single-use challenge from a
            # census report; it rotates on every accepted request, BEGIN and boot.
            if self.challenge is None:
                self.census()
            if self.challenge is None:
                self.emit("lease_no_challenge", attempt=attempt)
                continue
            prefix = (kind + b.sender + b.target + c.digest
                      + struct.pack(">IHI", frequency_word, self.lease_ms, self.challenge))
            self.challenge = None
            request = prefix + self.stock.sign(domain + prefix, self.deadline)
            self.stock.frames.discard_rf(observer, b.target, c.digest)
            self.emit("lease_request", attempt=attempt, frequency_khz=self.frequency, lease_ms=self.lease_ms,
                      bandwidth_hz=self.direct_bandwidth)
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
                continue
            if len(ack) != 171 or ack[:1] != ack_kind or ack[1:107] != request[1:107]:
                raise Error("direct ACK target/owner/manifest/profile/token mismatch")
            verify(b.target, domain + ack[:107], ack[107:])
            self.emit("lease_ack_verified", attempt=attempt)
            self.target_normal_after = timestamp + 20 + self.lease_ms / 1000 + 2
            self.wait_until(timestamp + 5.5)
            self.lease_end = timestamp + 5 + self.lease_ms / 1000 - 2
            self.room(9)
            self.stock.radio((self.frequency, self.direct_bandwidth, 5, 5, 0),
                             deadline=min(self.deadline, self.lease_end))
            self.profile = (self.frequency, self.direct_bandwidth, 5, 5, 0)
            self.emit("lease_active", frequency_khz=self.frequency, lease_ms=self.lease_ms,
                      bandwidth_hz=self.direct_bandwidth)
            return
        raise Error("signed normal-channel direct ACK retries exhausted")

    def authorize(self, retries=3):
        c, b = self.candidate, self.binding
        signature = self.stock.sign(c.canonical, self.deadline)
        frame = b"\x08" + hashlib.sha256(b.target).digest()[:8] + b.sender + c.canonical + signature
        for attempt in range(1, retries + 1):
            self.emit("auth_request", attempt=attempt, counter=c.counter, total=c.total)
            self.send(frame)
            self.emit("auth_sent", attempt=attempt, tx_evidence="aggregate-counters")
            try:
                return self.census(allow_pending=True)
            except NoCensus:
                self.emit("auth_no_census", attempt=attempt)
        self.emit("auth_exhausted", attempts=retries)
        raise Error("target did not admit candidate; operator must resolve cache/admin state")

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

    def upload(self, *, ready_once=False, resume_receipt=None):
        if resume_receipt is None:
            report = self.authorize()
        else:
            self.bind_resume(resume_receipt)
            report = self.census()
            self.emit("resume_matched_unsigned", generation=self.generation, received=report["received"],
                      total=report["total"], begin_nonce=self.begin_nonce.hex(), status_authenticated=False)
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
                for index in missing[:self.burst_blocks]:
                    self.room(22)
                    self.attempts[index] = self.attempts.get(index, 0) + 1
                    if self.attempts[index] > 8:
                        raise Error("RF block repair retries exhausted")
                    message, prefix = block_message(self.candidate, index)
                    signature = self.stock.sign(message, min(self.deadline, self.lease_end or self.deadline))
                    self.send(prefix + signature)
                    self.emit("block_sent", index=index, attempt=self.attempts[index], total=self.candidate.total,
                              tx_evidence="aggregate-counters")
                # Retain the window cursor across leases; restarting at zero can
                # starve the tail of a real application with many bitmap windows.
                first = first + 128 if first + 128 < self.candidate.total else 0
                if ((ready_once and report["lifecycle"] == 5)
                        or len(ready_windows) == len(windows)):
                    self.leave_direct()
                    for window in ((0,) if ready_once else windows):
                        if self.census(window)["lifecycle"] != 5:
                            raise Error("READY lost on final normal-channel census")
                    self.emit("ready_observed_unsigned", generation=self.generation, total=self.candidate.total)
                    return self.receipt("ready-observed-unsigned")
            except LeaseExpired:
                self.emit("lease_margin_exhausted")
                self.negotiate()
            # Polling is bounded by stock TX completion and receiver reply wait.

    def receipt(self, outcome):
        result = {"schema": RECEIPT_SCHEMA, "outcome": outcome, "serial": self.binding.serial,
                "sender_public_key": self.binding.sender.hex(), "target_public_key": self.binding.target.hex(),
                "manifest_hash": self.candidate.digest.hex(), "counter": self.candidate.counter,
                "generation": self.generation,
                "begin_nonce": None if self.begin_nonce is None else self.begin_nonce.hex(),
                "installation_confirmed": False}
        if self.mode == "directed":
            result.update(mode="directed", relay_public_key=self.relay.hex(),
                          request_path=self.path.hex(), path_hash_bytes=self.path_hash_bytes,
                          reply_route="flood", reply_path=self.relay[:1].hex(),
                          reply_path_hash_bytes=1, status_authenticated=False)
        elif self.mode == "background":
            result.update(mode="background", request_route="flood", channel=255,
                          floor=self.binding.floor, min_generation=self.binding.min_generation,
                          normal_profile=list(self.binding.normal), status_authenticated=False)
        return result

    def attempt_receipt(self, report):
        result = self.receipt("attempt-observed-unsigned")
        result.update(attempt_fields(self.binding, self.candidate, self.original,
                                     self.stock.tx_power, self.duty, report))
        return result

    def bind_resume(self, receipt):
        if self.mode not in ("directed", "background") or self.reupload_enabled:
            raise Error("resume requires directed/background mode without REUPLOAD; no admission fallback")
        generation, nonce, old_duty, report = resume_progress(receipt, self.binding, self.candidate)
        expected = self.attempt_receipt(report)
        expected.update(generation=generation, begin_nonce=nonce, normal_duty_percent=old_duty)
        if receipt != expected or (self.mode == "background" and old_duty != self.duty * 100):
            raise Error("resume receipt identity/image/manifest/profile/floor/route binding mismatch")
        self.generation, self.begin_nonce, self.received = generation, bytes.fromhex(nonce), report["received"]
        self.previous[0] = report
        self.emit("resume_expected", generation=generation, begin_nonce=nonce, received=report["received"],
                  previous_duty_percent=old_duty, normal_duty_percent=self.duty * 100, status_authenticated=False)

    def capture_resume(self, original_radio, expected_generation, *, min_received=0):
        """Read-only RF capture for older hosts that never persisted an attempt receipt."""
        if (self.mode != "directed" or self.reupload_enabled or self.begin_nonce is not None
                or self.generation is not None):
            raise Error("resume capture requires a fresh directed sender without admission or nonce replacement")
        expected_radio = {"schema": 1, "serial": self.binding.serial,
                          "sender_public_key": self.binding.sender.hex(), "profile": list(self.original),
                          "by_path": self.binding.by_path, "id_path": self.binding.id_path,
                          "usb_vid": self.binding.usb_vid, "usb_pid": self.binding.usb_pid,
                          "tx_power_dbm": self.stock.tx_power}
        if original_radio != expected_radio:
            raise Error("resume capture original sender identity/physical binding/profile/TX power mismatch")
        if (type(expected_generation) is not int
                or not self.binding.min_generation <= expected_generation <= 0xFFFFFFFF
                or type(min_received) is not int or not 0 <= min_received <= self.candidate.total):
            raise Error("resume capture requires an explicit bounded generation/progress expectation")
        self.generation, self.received = expected_generation, min_received
        report = self.census(retries=1)
        if report["lifecycle"] != 3 or report["phase"] != 1:
            raise Error("resume capture requires current Receiving; no admission or terminal fallback")
        self.emit("resume_capture_receiving_unsigned", generation=self.generation,
                  begin_nonce=self.begin_nonce.hex(), received=report["received"], total=report["total"],
                  status_authenticated=False, historical_nonce_verified=False)
        return self.attempt_receipt(report)

    def commit(self, receipt):
        expected = self.receipt("ready-observed-unsigned")
        expected["generation"] = receipt.get("generation")
        expected["begin_nonce"] = receipt.get("begin_nonce")
        nonce = receipt.get("begin_nonce")
        if (receipt != expected or type(receipt.get("generation")) is not int
                or receipt["generation"] < self.binding.min_generation
                or type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce)
                or not any(bytes.fromhex(nonce))):
            raise Error("commit requires matching target/owner/manifest/counter/attempt READY receipt")
        self.generation = receipt["generation"]
        # Fresh census must show this exact BEGIN attempt; an ABORT/reupload since
        # the receipt has a new nonce and is refused here and by the receiver.
        self.begin_nonce = bytes.fromhex(nonce)
        # No admission/reupload in commit. Obtain current full-manifest RF READY.
        for first in range(0, self.candidate.total, 128):
            if self.census(first)["lifecycle"] != 5:
                raise Error("fresh READY required before separate signed COMMIT")
        return self._send_commit()

    def _send_commit(self):
        if self.generation is None or self.begin_nonce is None or not any(self.begin_nonce):
            raise Error("COMMIT requires the generation and BEGIN nonce of an observed READY attempt")
        body = (self.binding.target + self.candidate.digest
                + struct.pack(">II", self.candidate.counter, self.generation) + self.begin_nonce)
        signature = self.stock.sign(COMMIT_DOMAIN + body, self.deadline)
        self.emit("commit_request", generation=self.generation, counter=self.candidate.counter,
                  begin_nonce=self.begin_nonce.hex())
        self.send(b"\x03" + body + signature)
        self.emit("commit_sent", tx_evidence="aggregate-counters", installation_confirmed=False)
        return self.receipt("signed-commit-aggregate-tx-observed-not-install-confirmed")

    def wait_installed(self, install_timeout=300):
        if not math.isfinite(install_timeout) or install_timeout <= 0:
            raise Error("positive finite installation timeout required")
        self.deadline = min(self.deadline, self.clock() + install_timeout)
        try:
            while self.clock() < self.deadline:
                try:
                    report = self.census(retries=1, post_commit=True)
                except NoCensus:
                    continue
                self.emit("native_install_status", lifecycle=report["lifecycle"],
                          generation=report["generation"], floor_known=report["floor_known"],
                          confirmed_floor=report["confirmed_floor"], status_authenticated=False)
                if report["lifecycle"] == 8:
                    result = self.receipt("native-installed-reported-unsigned")
                    result.update(native_installed=True, lifecycle=8,
                                  confirmed_floor=report["confirmed_floor"], status_authenticated=False)
                    return result
        except DeadlineExpired as exc:
            raise TimeoutError("installation timeout: no matching native INSTALLED report") from exc
        raise TimeoutError("installation timeout: no matching native INSTALLED report")

    def deploy(self, install_timeout=300, *, resume_receipt=None):
        if not math.isfinite(install_timeout) or install_timeout <= 0:
            raise Error("positive finite installation timeout required")
        self.upload(ready_once=True, resume_receipt=resume_receipt)
        self._send_commit()
        return self.wait_installed(install_timeout)


class BackgroundTarget(Sender):
    """Independent census/attempt state, sharing one physical transmitter."""
    def __init__(self, transport, binding, **options):
        super().__init__(transport.stock, binding, transport.candidate, transport.original,
                         transport.deadline, 0, 0, transport.duty, transport.clock, transport.sleep,
                         mode="background", **options)
        self.transport = transport

    def send(self, payload):
        if getattr(self.transport, "failed_tx", False):
            raise Error("shared transmitter failed; no further RF writes")
        try:
            since = self.transport.send(payload)
        except (Error, TimeoutError):
            self.transport.failed_tx = True
            raise
        self.last_tx_attempt = self.transport.last_tx_attempt
        return since

    def emit(self, event, **fields):
        super().emit(event, target_public_key=self.binding.target.hex(), **fields)


class BackgroundCampaign:
    @staticmethod
    def validate_bindings(bindings, candidate):
        if (len(bindings) != 2 or len({b.target for b in bindings}) != 2
                or any(len(b.target) != 32 or not any(b.target) or b.target == b.sender for b in bindings)):
            raise Error("background requires exactly two distinct full target identities")
        first = bindings[0]
        common = ("serial", "sender", "normal", "by_path", "id_path", "usb_vid", "usb_pid", "sender_name")
        if any(any(getattr(b, key) != getattr(first, key) for key in common) for b in bindings):
            raise Error("background targets require the same stock endpoint/sender and normal radio profile")
        for b in bindings:
            b.check_candidate(candidate)
            if not b.floor < candidate.counter:
                raise Error("common candidate counter must exceed both measured target floors")

    @staticmethod
    def validate_resume_receipts(bindings, candidate, receipts, duty, *, profile=None, tx_power=None):
        BackgroundCampaign.validate_bindings(bindings, candidate)
        if not isinstance(receipts, (list, tuple)) or len(receipts) != 2:
            raise Error("background resume requires both original schema-3 attempt receipts")
        sender_profiles, powers = [], []
        for binding, receipt in zip(bindings, receipts):
            generation, nonce, old_duty, report = resume_progress(receipt, binding, candidate)
            saved_profile, saved_power = receipt.get("sender_profile"), receipt.get("tx_power_dbm")
            if not isinstance(saved_profile, list):
                raise Error("background resume requires the original sender profile")
            validate_profile(saved_profile)
            if (tuple(saved_profile[:4]) != binding.normal
                    or type(saved_power) is not int or not -128 <= saved_power <= 127
                    or old_duty != duty * 100
                    or (profile is not None and tuple(saved_profile) != tuple(profile))
                    or (tx_power is not None and saved_power != tx_power)):
                raise Error("background resume sender profile/TX power/duty budget mismatch")
            expected = {"schema": RECEIPT_SCHEMA, "outcome": "attempt-observed-unsigned",
                        "serial": binding.serial, "sender_public_key": binding.sender.hex(),
                        "target_public_key": binding.target.hex(), "manifest_hash": candidate.digest.hex(),
                        "counter": candidate.counter, "generation": generation, "begin_nonce": nonce,
                        "installation_confirmed": False, "mode": "background", "request_route": "flood",
                        "channel": 255}
            expected.update(attempt_fields(binding, candidate, saved_profile, saved_power, duty, report))
            expected["normal_duty_percent"] = old_duty
            normal = receipt.get("normal_profile")
            validate_profile(normal + [0] if isinstance(normal, list) else ())
            if (receipt.keys() != expected.keys()
                    or any(type(receipt[key]) is not type(value) or receipt[key] != value
                           for key, value in expected.items())):
                raise Error("background resume receipt identity/image/manifest/physical/floor/route binding mismatch")
            sender_profiles.append(saved_profile)
            powers.append(saved_power)
        if sender_profiles[0] != sender_profiles[1] or powers[0] != powers[1]:
            raise Error("background resume receipts must bind the same sender profile and TX power")

    def __init__(self, stock, bindings, candidate, profile, deadline, duty=0.02,
                 clock=time.monotonic, sleep=time.sleep, event_callback=None, attempt_callback=None):
        self.validate_bindings(bindings, candidate)
        first = bindings[0]
        self.transport = Sender(stock, first, candidate, profile, deadline, 0, 0, duty, clock, sleep,
                                mode="background", event_callback=event_callback)
        self.targets = [
            BackgroundTarget(self.transport, b, event_callback=event_callback,
                             attempt_callback=attempt_callback)
            for b in bindings
        ]
        self.initial_sent = self.repair_sent = 0
        self.repairs = {}
        self.outcomes = [None, None]
        self.stage = "admission"
        self.error = None
        self.resuming = False

    def result(self, outcome, complete=False):
        return {"schema": 1, "mode": "background", "outcome": outcome, "operation_complete": complete,
                "sender_public_key": self.transport.binding.sender.hex(),
                "manifest_hash": self.transport.candidate.digest.hex(),
                "image_sha256": hashlib.sha256(self.transport.candidate.image).hexdigest(),
                "counter": self.transport.candidate.counter, "channel": 255, "target_count": 2,
                "initial_block_transmissions": self.initial_sent,
                "repair_block_transmissions": self.repair_sent,
                "transfer_strategy": "shared-missing-union-resume" if self.resuming else "shared-initial-flood",
                "usb_unsolicited_counts": dict(self.transport.stock.frames.unsolicited),
                "usb_backlog": self.transport.stock.frames.backlog(),
                "error": self.error,
                "status_authenticated": False, "installation_confirmed": False,
                "targets": [
                    result if result is not None else target.receipt("not-completed")
                    for target, result in zip(self.targets, self.outcomes)
                ]}

    def failed(self, index, exc):
        result = self.targets[index].receipt("failed")
        result.update(stage=self.stage, error=str(exc))
        self.outcomes[index] = result

    def cancel(self, exc):
        self.transport.failed_tx = True
        self.error = {"stage": self.stage, "reason": str(exc), "cancelled": True}

    def send_block(self, index, *, initial, needed_by):
        wire = self.transport
        wire.room(22)
        message, prefix = block_message(wire.candidate, index)
        signature = wire.stock.sign(message, wire.deadline)
        wire.send(prefix + signature, repair=not initial)
        if initial:
            self.initial_sent += 1
        else:
            self.repair_sent += 1
        wire.emit("shared_block_sent", index=index, initial=initial, needed_by=needed_by,
                  total=wire.candidate.total, tx_evidence="aggregate-counters",
                  initial_block_transmissions=self.initial_sent, repair_block_transmissions=self.repair_sent)

    def upload_partial(self, blocks, *, restart_receipts=None):
        """Explicit new BEGIN pair and bounded prefix; never repair or COMMIT.

        This deliberate stop is not cancellation and does not abort receivers.
        Attempt callbacks persist both contexts before the first data block.
        """
        if type(blocks) is not int or not 1 <= blocks <= 32 or blocks >= self.transport.candidate.total:
            raise Error("partial pair requires 1..32 blocks, fewer than the whole image")
        if any(target.generation is not None for target in self.targets) or self.initial_sent:
            raise Error("partial pair requires a fresh explicitly selected campaign")
        if restart_receipts is not None:
            validate_partial_restart([target.binding for target in self.targets], self.transport.candidate,
                                     restart_receipts)
            for target, old in zip(self.targets, restart_receipts):
                target.binding.permit_reupload(None, True)
                target.reupload_generation = old["generation"] + 1
                target.reupload_enabled = True
        current = 0
        try:
            if restart_receipts is not None:
                self.stage = "restart-aborted-preflight"
                for current, target in enumerate(self.targets):
                    report = target.authorize(retries=1)
                    if report["lifecycle"] != 9 or not target.pending_reupload:
                        raise Error("explicit restart requires BOTH prior durable ABORTED generations; no resume fallback")
                self.stage = "restart-signed-reupload"
                for current, (target, old) in enumerate(zip(self.targets, restart_receipts)):
                    target.activate_prepared()
                    if (target.generation != old["generation"] + 2
                            or target.begin_nonce.hex() == old["begin_nonce"]):
                        raise Error("explicit restart did not create its exact new generation/fresh nonce")
            else:
                for current, target in enumerate(self.targets):
                    report = target.authorize(retries=1)
                    while report["lifecycle"] == 2:
                        report = target.census()
                    if report["received"] != 0 or report["lifecycle"] != 3:
                        raise Error("partial new attempt requires empty Receiving candidates; use strict resume separately")
            self.stage = "partial-shared-flood"
            current = None
            keys = [target.binding.target.hex() for target in self.targets]
            for index in range(blocks):
                self.send_block(index, initial=True, needed_by=keys)
                if (index + 1) % self.transport.burst_blocks == 0 or index + 1 == blocks:
                    for current, target in enumerate(self.targets):
                        target.census()
                    current = None
            self.outcomes = [target.receipt("partial-observed-unsigned") for target in self.targets]
            result = self.result("shared-partial-observed-unsigned", complete=True)
            result.update(transfer_complete=False, commit_sent=False, receiver_abort_sent=False,
                          requested_initial_blocks=blocks)
            return result
        except Cancelled as exc:
            self.cancel(exc)
            raise
        except (Error, TimeoutError) as exc:
            if current is None:
                self.error = {"stage": self.stage, "reason": str(exc)}
            else:
                self.failed(current, exc)
            return self.result("shared-campaign-incomplete")

    def upload(self, *, resume_receipts=None):
        current = 0
        try:
            if resume_receipts is not None:
                self.resuming = True
                self.stage = "resume-validation"
                current = None
                self.validate_resume_receipts(
                    [target.binding for target in self.targets], self.transport.candidate, resume_receipts,
                    self.transport.duty, profile=self.transport.original, tx_power=self.transport.stock.tx_power)
                for target, receipt in zip(self.targets, resume_receipts):
                    target.bind_resume(receipt)
                self.stage = "resume-census-preflight"
                for current, target in enumerate(self.targets):
                    report = target.census()
                    if report["lifecycle"] not in (3, 5):
                        raise Error("background resume requires the same Receiving or READY attempt; no terminal fallback")
                    target.emit("resume_matched_unsigned", generation=target.generation,
                                received=report["received"], total=report["total"],
                                begin_nonce=target.begin_nonce.hex(), status_authenticated=False)
            else:
                for current, target in enumerate(self.targets):
                    # Only one BEGIN per target. Missing permission/census never
                    # triggers another BEGIN, takeover or retirement operation.
                    report = target.authorize(retries=1)
                    while report["lifecycle"] == 2:
                        report = target.census()
                self.stage = "initial-shared-flood"
                current = None
                keys = [target.binding.target.hex() for target in self.targets]
                for index in range(self.transport.candidate.total):
                    self.send_block(index, initial=True, needed_by=keys)
            self.stage = "census-selective-repair"
            windows = tuple(range(0, self.transport.candidate.total, 128))
            # Validate every window of both attempts before any repair, even
            # when the mismatch is beyond the original first-window receipt.
            for first in windows:
                for current, target in enumerate(self.targets):
                    target.census(first)
            while True:
                for first in windows:
                    mask = (1 << min(128, self.transport.candidate.total - first)) - 1
                    if all(target.previous[first]["bits"] == mask for target in self.targets):
                        continue
                    missing = {}
                    reports = []
                    for current, target in enumerate(self.targets):
                        report = target.census(first)
                        reports.append(report)
                        for index in range(first, min(first + 128, target.candidate.total)):
                            if not report["bits"] & (1 << (index - first)):
                                missing.setdefault(index, []).append(target.binding.target.hex())
                    for index, needed_by in sorted(missing.items())[:self.transport.burst_blocks]:
                        current = None
                        self.repairs[index] = self.repairs.get(index, 0) + 1
                        if self.repairs[index] > 8:
                            raise Error("shared RF block repair retries exhausted")
                        self.send_block(index, initial=False, needed_by=needed_by)
                    # Both fresh checkpoints must succeed before any more
                    # blocks. Rotate windows so a lossy prefix cannot starve
                    # the tail; the campaign deadline and retry bounds remain.
                    if missing:
                        reports = []
                        for current, target in enumerate(self.targets):
                            reports.append(target.census(first))
                    for target, report in zip(self.targets, reports):
                        target.emit("shared_repair_checkpoint", first=first,
                                    received=report["received"], total=report["total"],
                                    lifecycle=report["lifecycle"], generation=target.generation,
                                    begin_nonce=target.begin_nonce.hex(),
                                    bitmap=report["bits"].to_bytes(16, "little").hex(),
                                    repair_block_transmissions=self.repair_sent,
                                    status_authenticated=False)
                if any(target.previous[first]["bits"] != (1 << min(
                        128, self.transport.candidate.total - first)) - 1
                       for first in windows for target in self.targets):
                    continue
                # Complete cached bitmaps only suppress repair work; they
                # cannot authorize READY or signed COMMIT.
                all_ready = True
                for first in windows:
                    for current, target in enumerate(self.targets):
                        report = target.census(first)
                        all_ready &= report["lifecycle"] == 5
                if all_ready:
                    break
            self.outcomes = [target.receipt("ready-observed-unsigned") for target in self.targets]
            return self.result("shared-ready-observed-unsigned", complete=True)
        except Cancelled as exc:
            self.cancel(exc)
            raise
        except (Error, TimeoutError) as exc:
            if current is None:
                self.error = {"stage": self.stage, "reason": str(exc)}
            else:
                self.failed(current, exc)
            return self.result("shared-campaign-incomplete")

    def commit(self, receipt):
        c = self.transport.candidate
        strategy = receipt.get("transfer_strategy", "shared-initial-flood") if isinstance(receipt, dict) else None
        if (not isinstance(receipt, dict) or receipt.get("schema") != 1
                or receipt.get("mode") != "background" or receipt.get("target_count") != 2
                or receipt.get("outcome") != "shared-ready-observed-unsigned"
                or receipt.get("operation_complete") is not True
                or receipt.get("sender_public_key") != self.transport.binding.sender.hex()
                or receipt.get("manifest_hash") != c.digest.hex()
                or receipt.get("image_sha256") != hashlib.sha256(c.image).hexdigest()
                or receipt.get("counter") != c.counter or receipt.get("channel") != 255
                or receipt.get("status_authenticated") is not False
                or receipt.get("installation_confirmed") is not False
                or not isinstance(receipt.get("targets"), list) or len(receipt["targets"]) != 2
                or strategy not in ("shared-initial-flood", "shared-missing-union-resume")
                or type(receipt.get("initial_block_transmissions")) is not int
                or receipt["initial_block_transmissions"] != (0 if strategy == "shared-missing-union-resume" else c.total)
                or type(receipt.get("repair_block_transmissions")) is not int
                or receipt["repair_block_transmissions"] < 0):
            raise Error("background COMMIT requires this common-image two-target READY receipt")
        # Prevalidate BOTH READY bindings before either COMMIT is signed.
        for target, ready in zip(self.targets, receipt["targets"]):
            if not isinstance(ready, dict):
                raise Error("background COMMIT requires two individual READY receipts")
            expected = target.receipt("ready-observed-unsigned")
            expected.update(generation=ready.get("generation"), begin_nonce=ready.get("begin_nonce"))
            nonce = ready.get("begin_nonce")
            if (ready != expected or type(ready.get("generation")) is not int
                    or not target.binding.min_generation <= ready["generation"] <= 0xFFFFFFFF
                    or not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce)
                    or not any(bytes.fromhex(nonce))):
                raise Error("background COMMIT individual identity/floor/attempt READY mismatch")
        self.initial_sent = receipt["initial_block_transmissions"]
        self.repair_sent = receipt["repair_block_transmissions"]
        self.resuming = strategy == "shared-missing-union-resume"
        self.stage = "individual-signed-commit"
        for current, (target, ready) in enumerate(zip(self.targets, receipt["targets"])):
            try:
                self.outcomes[current] = target.commit(ready)
            except Cancelled as exc:
                self.cancel(exc)
                raise
            except (Error, TimeoutError) as exc:
                self.failed(current, exc)
        complete = all(result["outcome"] == "signed-commit-aggregate-tx-observed-not-install-confirmed"
                       for result in self.outcomes)
        return self.result("shared-signed-commits-not-install-confirmed" if complete
                           else "shared-campaign-incomplete", complete=complete)

    def deploy(self, install_timeout=300, *, resume_receipts=None):
        if not math.isfinite(install_timeout) or install_timeout <= 0:
            raise Error("positive finite installation timeout required")
        ready = self.upload(resume_receipts=resume_receipts)
        if not ready["operation_complete"]:
            return ready
        committed = self.commit(ready)
        self.stage = "individual-installed-status"
        # Installation deadlines start together, after both COMMIT attempts.
        install_deadline = min(self.transport.deadline, self.transport.clock() + install_timeout)
        waiting = {i for i, result in enumerate(committed["targets"])
                   if result["outcome"] == "signed-commit-aggregate-tx-observed-not-install-confirmed"}
        while waiting:
            for current in sorted(waiting):
                target = self.targets[current]
                target.deadline = install_deadline
                try:
                    report = target.census(retries=1, post_commit=True)
                    if report["lifecycle"] == 8:
                        result = target.receipt("native-installed-reported-unsigned")
                        result.update(native_installed=True, lifecycle=8,
                                      confirmed_floor=report["confirmed_floor"], status_authenticated=False)
                        self.outcomes[current] = result
                        waiting.remove(current)
                except NoCensus:
                    continue
                except Cancelled as exc:
                    self.cancel(exc)
                    raise
                except (Error, TimeoutError) as exc:
                    self.failed(current, exc)
                    waiting.remove(current)
        complete = all(result["outcome"] == "native-installed-reported-unsigned" for result in self.outcomes)
        return self.result("shared-native-installed-reported-unsigned" if complete
                           else "shared-campaign-incomplete", complete=complete)


def validate_partial_restart(bindings, candidate, receipts):
    """Validate explicit NEW-attempt history, never reinterpret it as resume."""
    if not isinstance(receipts, list) or len(receipts) != 2:
        raise Error("restart needs both original attempt receipts, not a single-target guess")
    for binding, receipt in zip(bindings, receipts):
        if (not isinstance(receipt, dict) or receipt.get("schema") != ATTEMPT_RECEIPT_SCHEMA
                or receipt.get("target_public_key") != binding.target.hex()
                or receipt.get("sender_public_key") != binding.sender.hex()
                or receipt.get("serial") != binding.serial
                or receipt.get("manifest_hash") != candidate.digest.hex()
                or receipt.get("counter") != candidate.counter
                or receipt.get("image_sha256") != hashlib.sha256(candidate.image).hexdigest()
                or type(receipt.get("generation")) is not int
                or not 0 < receipt["generation"] <= 0xFFFFFFFD
                or binding.min_generation != receipt["generation"] + 2
                or binding.allow_reupload is not True
                or binding.reupload_generation not in (None, receipt["generation"] + 1)
                or receipt.get("mode") != "background"
                or receipt.get("floor") != binding.floor
                or any(receipt.get(key) != getattr(binding, key) for key in
                       ("by_path", "id_path", "usb_vid", "usb_pid", "sender_name"))):
            raise Error("new-attempt restart receipt identity/image/counter/generation guard mismatch")
        nonce = receipt.get("begin_nonce")
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce) or not any(bytes.fromhex(nonce)):
            raise Error("new-attempt restart needs an original nonzero BEGIN nonce")


def partial_background_operation(stock, bindings, candidate, artifacts, blocks=16, timeout=1800, duty=0.02,
                                 restart_receipts=None, *, clock=time.monotonic, event_callback=None):
    """Persist bounded partial-pair results; no COMMIT, ABORT or resume fallback."""
    BackgroundCampaign.validate_bindings(bindings, candidate)
    if (type(blocks) is not int or not 1 <= blocks <= 32 or blocks >= candidate.total
            or not math.isfinite(timeout) or not 0 < timeout <= 14400
            or not math.isfinite(duty) or not 0 < duty <= 1):
        raise Error("bounded partial blocks, finite timeout and duty required")
    if restart_receipts is not None:
        validate_partial_restart(bindings, candidate, restart_receipts)
    campaign = result = None
    try:
        with radio_guard(stock, bindings[0], artifacts, mode="background") as profile:
            def observed(receipt):
                if restart_receipts is not None:
                    previous = next(item for item in restart_receipts
                                    if item["target_public_key"] == receipt["target_public_key"])
                    if (receipt["generation"] != previous["generation"] + 2
                            or receipt["begin_nonce"] == previous["begin_nonce"]):
                        raise Error("restart did not create a distinct generation/nonce; no data permitted")
                private_write(artifacts / ("attempt-" + receipt["target_public_key"] + ".json"), receipt)
            campaign = BackgroundCampaign(stock, bindings, candidate, profile, clock() + timeout,
                                          duty, clock=clock, sleep=stock.sleep,
                                          event_callback=event_callback, attempt_callback=observed)
            result = campaign.upload_partial(blocks, restart_receipts=restart_receipts)
            if result["operation_complete"]:
                for target in campaign.targets:
                    private_write(artifacts / ("checkpoint-" + target.binding.target.hex() + ".json"),
                                  target.attempt_receipt(target.previous[0]))
    except (Error, OSError, ValueError, TimeoutError) as exc:
        failed_stage = "radio-cleanup" if result is not None else (campaign.stage if campaign else "identity")
        if campaign is not None:
            if isinstance(exc, Cancelled):
                campaign.cancel(exc)
            result = campaign.result("shared-partial-cancelled" if isinstance(exc, Cancelled)
                                     else "shared-partial-incomplete")
            if result["error"] is None:
                result["error"] = {"stage": failed_stage, "reason": str(exc)}
        else:
            result = {"outcome": "shared-partial-incomplete", "error": str(exc),
                      "operation_complete": False}
        result.update(receiver_abort_sent=False, commit_sent=False, transfer_complete=False)
        cleanup_path = artifacts / "radio-cleanup-failed.json"
        result["radio_cleanup"] = (private_read(cleanup_path) if cleanup_path.exists()
                                   else {"normal_profile_unchanged": (artifacts / "radio-unchanged.json").exists()})
        private_write(artifacts / "result.json", result)
        raise
    result.update(restart_selected=restart_receipts is not None, receiver_abort_sent=False,
                  commit_sent=False, transfer_complete=False)
    result["radio_cleanup"] = {"normal_profile_unchanged": True, "readback_available": True}
    private_write(artifacts / "result.json", result)
    return result


@contextmanager
def radio_guard(stock, binding, directory, restoring=False, mode="direct"):
    stock.expected_name = binding.sender_name
    original = stock.identify()
    if mode != "direct" and original[:4] != binding.normal:
        raise Error(f"{mode} sender must already match the bound normal radio profile; no retune")
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
        if mode == "direct":
            stock.radio((*binding.normal, 0))
        yield original
    finally:
        if mode == "direct":
            restore_radio(stock, original)
            private_write(directory / "restored.json", {"restored": True})
        else:
            primary_error = sys.exc_info()[1]
            readback_available = False
            try:
                current = stock.identify()
                readback_available = True
                if current != original:
                    raise Error(f"{mode} sender radio/repeat changed; not restored or retuned")
                private_write(directory / "radio-unchanged.json", {"normal_profile_unchanged": True})
            except (Error, OSError, ValueError, TimeoutError) as exc:
                if mode != "background":
                    raise
                private_write(directory / "radio-cleanup-failed.json",
                              {"normal_profile_unchanged": False, "readback_available": readback_available,
                               "error": str(exc)})
                if primary_error is None:
                    raise


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
    # A colliding by-id is descriptive ONLY. Never even resolve it when the
    # explicitly authorized physical by-path anchor is present.
    path = Path(by_path) if by_path is not None else Path(by_id)
    if by_path is not None:
        if (path.parent != Path("/dev/serial/by-path") or not id_path or path.name != id_path + "-port0"
                or usb_vid is None or usb_pid is None):
            raise Error("exact authorized by-path/ID_PATH/VID/PID required")
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
        raise Error("physical USB serial does not match deployment binding")
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
def validated_stock_uart(binding, by_id, serial_factory=None, sleep=time.sleep, *, dtr=False):
    """Physical-bound quiet UART, not protocol verification or RF readiness."""
    def resolve():
        return resolve_stock(binding.serial, by_id, by_path=binding.by_path, id_path=binding.id_path,
                             usb_vid=binding.usb_vid, usb_pid=binding.usb_pid)
    selected = resolve()
    if serial_factory is None:
        import serial
        serial_factory = serial.Serial
    stream = serial_factory(port=None, baudrate=115200, timeout=0.1,
                            write_timeout=2.0, exclusive=True)
    stream.dtr = dtr
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
        raise Cancelled(f"interrupted by signal {signum}; closing UART, restoring radio only if its guard is active")
    for signum in (signal.SIGINT, signal.SIGTERM):
        old[signum] = signal.signal(signum, interrupted)
    try:
        yield
    finally:
        for signum, handler in old.items():
            signal.signal(signum, handler)


def background_operation(stock, bindings, candidate, args, receipt):
    campaign = result = None
    try:
        with radio_guard(stock, bindings[0], args.artifacts, mode="background") as profile:
            campaign = BackgroundCampaign(
                stock, bindings, candidate, profile, time.monotonic() + args.timeout,
                args.normal_duty_percent / 100, event_callback=public_event,
                attempt_callback=lambda observed: private_write(
                    args.artifacts / ("attempt-" + observed["target_public_key"] + ".json"), observed))
            try:
                resume_options = {"resume_receipts": receipt} if args.resume_receipt is not None else {}
                result = (campaign.deploy(args.install_timeout, **resume_options) if args.operation == "deploy" else
                          campaign.upload(**resume_options) if args.operation == "upload" else campaign.commit(receipt))
            except Cancelled as exc:
                campaign.cancel(exc)
                result = campaign.result("shared-campaign-cancelled")
                raise
    except (Error, OSError, ValueError, TimeoutError) as exc:
        if campaign is not None:
            stage = "radio-cleanup" if result is not None else campaign.stage
            result = result or campaign.result("shared-campaign-incomplete")
            result["operation_complete"] = False
            if result["outcome"] != "shared-campaign-cancelled":
                result["outcome"] = "shared-campaign-incomplete"
            if result["error"] is None:
                result["error"] = {"stage": stage, "reason": str(exc)}
            failed_readback = args.artifacts / "radio-cleanup-failed.json"
            if failed_readback.exists():
                result["radio_cleanup"] = private_read(failed_readback)
            else:
                unchanged = (args.artifacts / "radio-unchanged.json").exists()
                result["radio_cleanup"] = {"normal_profile_unchanged": unchanged,
                                           "readback_available": unchanged}
            result["usb_unsolicited_counts"] = dict(stock.frames.unsolicited)
            result["usb_backlog"] = stock.frames.backlog()
            private_write(args.artifacts / "result.json", result)
            print(json.dumps(result, sort_keys=True))
        raise
    result["radio_cleanup"] = {"normal_profile_unchanged": True, "readback_available": True}
    result["usb_unsolicited_counts"] = dict(stock.frames.unsolicited)
    result["usb_backlog"] = stock.frames.backlog()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("operation", choices=("upload", "commit", "deploy", "restore", "inspect"))
    parser.add_argument("--serial", required=True)
    parser.add_argument("--by-id", required=True)
    parser.add_argument("--client-dtr", action="store_true",
                        help="assert DTR before open for nRF TinyUSB; RTS stays false")
    parser.add_argument("--by-path", help="explicit deployment-bound physical anchor; required for short/duplicate CP2102 serial")
    parser.add_argument("--sender-key", required=True, type=full_key)
    parser.add_argument("--sender-name", help="optional explicit public label guard; must match configured sender_name")
    parser.add_argument("--target", required=True, type=full_key)
    parser.add_argument("--binding", required=True, type=Path)
    parser.add_argument("--second-target", type=full_key, help="background only: exactly one additional full target identity")
    parser.add_argument("--second-binding", type=Path, help="background only: additional target's owned 0600 binding")
    parser.add_argument("--artifacts", required=True, type=Path, help="exclusive new 0700 directory (including inspect); existing only for restore")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--image", type=Path, help="pure ordinary APP .bin only")
    parser.add_argument("--board", choices=("xiao_nrf52840", "xiao_nrf52840_sense", "sensecap_solar_p1", "xiao_s3_wio"))
    parser.add_argument("--role-id", type=int, choices=(0, 1))
    parser.add_argument("--counter", type=int)
    parser.add_argument("--install-timeout", type=float, default=300)
    parser.add_argument("--ready-receipt", type=Path)
    parser.add_argument("--resume-receipt", type=Path,
                        help="directed/background upload/deploy: original schema-3 attempt receipt; no BEGIN/REUPLOAD")
    parser.add_argument("--second-resume-receipt", type=Path,
                        help="background resume only: second target's original owned 0600 schema-3 attempt receipt")
    retirement = parser.add_mutually_exclusive_group()
    retirement.add_argument("--reupload", action="store_true", help="upload only; binding allow_reupload:true, generation learned only from fresh RF census")
    retirement.add_argument("--reupload-generation", type=int, help="legacy upload-only strict expectation; signing still uses fresh RF-observed generation")
    parser.add_argument("--frequency-khz", type=int)
    parser.add_argument("--mode", choices=("direct", "directed", "background"), default="direct")
    parser.add_argument("--channel", type=int, default=255, help="255 means existing normal radio; no channel override")
    parser.add_argument("--lease-ms", type=int, help="direct default 60000; on-mesh requires 0")
    parser.add_argument("--relay-key", type=full_key, help="directed: full identity of the single mandatory relay")
    parser.add_argument("--path-hash-bytes", type=int, default=1, choices=(1, 2, 3),
                        help="directed request path uses this many public-key prefix bytes")
    parser.add_argument("--routed-retry", action="store_true", help="redundant in on-mesh modes; refused in direct mode")
    parser.add_argument("--no-routed-retry", action="store_true", help="refused in on-mesh modes; direct remains unframed")
    parser.add_argument("--normal-duty-percent", type=float, default=2)
    parser.add_argument("--timeout", type=float, default=14400)
    args = parser.parse_args(argv)
    if args.mode == "background":
        if (args.operation not in ("upload", "commit", "deploy")
                or args.second_target is None or args.second_binding is None
                or args.reupload or args.reupload_generation is not None):
            raise Error("background requires two explicit targets/bindings and upload/commit/deploy; no REUPLOAD")
        if args.second_target == args.target:
            raise Error("background requires exactly two distinct targets")
        if (args.resume_receipt is None) != (args.second_resume_receipt is None):
            raise Error("background resume requires both --resume-receipt and --second-resume-receipt")
    elif args.second_target is not None or args.second_binding is not None or args.second_resume_receipt is not None:
        raise Error("second target/binding/resume receipt requires background mode")
    if args.resume_receipt is not None and (
            args.operation not in ("upload", "deploy") or args.mode not in ("directed", "background")
            or args.reupload or args.reupload_generation is not None):
        raise Error("resume requires directed/background upload/deploy without REUPLOAD")
    if args.routed_retry and args.mode == "direct":
        raise Error("routed-retry requires directed/background mode; no legacy fallback")
    if args.no_routed_retry and args.mode != "direct":
        raise Error(f"{args.mode} OTA requires attempt-diverse framing; no legacy fallback")
    if args.operation in ("inspect", "restore") and (
            args.mode != "direct" or args.relay_key is not None or args.path_hash_bytes != 1):
        raise Error("inspect/restore do not select an RF route")
    frequency = args.frequency_khz if args.frequency_khz is not None else (0 if args.mode != "direct" else None)
    lease_ms = args.lease_ms if args.lease_ms is not None else (0 if args.mode != "direct" else 60000)
    if (args.reupload or args.reupload_generation is not None) and args.operation not in ("upload", "deploy"):
        raise Error("explicit REUPLOAD is supported only by upload, never COMMIT/restore")
    if args.operation in ("upload", "commit", "deploy"):
        validate_transport(args.mode, frequency, lease_ms, args.channel, args.relay_key, args.path_hash_bytes)
    binding = Binding.load(args.binding, args.serial, args.sender_key, args.target, args.by_path, args.sender_name)
    binding.permit_reupload(args.reupload_generation, args.reupload)
    second_binding = (Binding.load(args.second_binding, args.serial, args.sender_key, args.second_target,
                                   args.by_path, args.sender_name) if args.mode == "background" else None)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise Error("positive finite campaign timeout required")
    candidate = None
    receipt = None
    if args.operation in ("upload", "commit", "deploy"):
        if (not args.image
                or (args.operation != "deploy" and not args.manifest)):
            raise Error("upload/commit/deploy require ordinary APP image; upload/commit also require manifest")
        if (args.image.suffix != ".bin" or not args.image.is_file()
                or (args.manifest is not None and not args.manifest.is_file())):
            raise Error("regular .bin APP and canonical59 manifest required; packages refused")
        canonical = args.manifest.read_bytes() if args.manifest else None
        if args.operation == "deploy" or any(value is not None for value in (args.board, args.role_id, args.counter)):
            if args.board is None or args.role_id is None or args.counter is None:
                raise Error("board selection requires explicit --board, --role-id and --counter")
            if args.operation == "deploy" and (not math.isfinite(args.install_timeout) or args.install_timeout <= 0):
                raise Error("positive finite installation timeout required")
            candidate = Candidate.build(canonical, args.image.read_bytes(), binding.floor,
                                        board=args.board, role_id=args.role_id, counter=args.counter)
        else:
            candidate = Candidate.build(canonical, args.image.read_bytes(), binding.floor)
        binding.check_candidate(candidate)
        if second_binding is not None:
            BackgroundCampaign.validate_bindings([binding, second_binding], candidate)
        validate_transport(args.mode, frequency, lease_ms, args.channel, args.relay_key, args.path_hash_bytes, binding)
        if (not math.isfinite(args.normal_duty_percent)
                or not 0 < args.normal_duty_percent <= 100):
            raise Error("invalid normal-channel duty budget")
        if args.operation == "commit":
            if not args.ready_receipt:
                raise Error("separate COMMIT requires explicit READY receipt")
            receipt = private_read(args.ready_receipt)
        elif args.resume_receipt is not None:
            receipt = private_read(args.resume_receipt)
            if args.mode == "background":
                receipt = [receipt, private_read(args.second_resume_receipt)]
                BackgroundCampaign.validate_resume_receipts([binding, second_binding], candidate, receipt,
                                                              args.normal_duty_percent / 100)
        args.artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
        if args.resume_receipt is not None:
            sources = ([(args.resume_receipt, receipt[0], "resume-source.json"),
                        (args.second_resume_receipt, receipt[1], "second-resume-source.json")]
                       if args.mode == "background" else [(args.resume_receipt, receipt, "resume-source.json")])
            for source, saved, name in sources:
                encoded = json.dumps(saved, sort_keys=True, separators=(",", ":")).encode("utf-8")
                private_write(args.artifacts / name,
                              {"source_receipt": str(source.resolve()),
                               "canonical_json_sha256": hashlib.sha256(encoded).hexdigest(), "receipt": saved})
    elif args.operation == "inspect":
        args.artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    directory = args.artifacts
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise Error("owned private 0700 exclusive artifact directory required")
    with termination_cleanup():
        with validated_stock_uart(binding, args.by_id, dtr=args.client_dtr) as stream:
            stock = Stock(Frames(stream), binding.sender, expected_name=binding.sender_name)
            stock.frames.event_callback = public_event
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
            guard_options = {"mode": args.mode} if args.mode != "direct" else {}
            if candidate and args.mode == "background":
                result = background_operation(stock, [binding, second_binding], candidate, args, receipt)
            else:
                with radio_guard(stock, binding, directory, args.operation == "restore", **guard_options) as profile:
                    if not candidate:
                        print("Original stock radio and repeat setting restored and read back.")
                        return
                    sender = Sender(stock, binding, candidate, profile, time.monotonic() + args.timeout,
                                    frequency, lease_ms, args.normal_duty_percent / 100,
                                    reupload_generation=args.reupload_generation, reupload=args.reupload,
                                    event_callback=public_event, mode=args.mode, relay=args.relay_key,
                                    path_hash_bytes=args.path_hash_bytes, channel=args.channel,
                                    attempt_callback=(lambda observed: private_write(directory / "attempt-receipt.json", observed))
                                    if args.mode == "directed" else None)
                    resume_options = {"resume_receipt": receipt} if args.resume_receipt is not None else {}
                    if args.operation == "deploy":
                        result = sender.deploy(args.install_timeout, **resume_options)
                    else:
                        result = sender.upload(**resume_options) if args.operation == "upload" else sender.commit(receipt)
            if result is not None:
                private_write(directory / "result.json", result)
                print(json.dumps(result, sort_keys=True))
                if args.mode == "background" and not result["operation_complete"]:
                    raise Error("shared campaign incomplete; individual unsigned outcomes saved in result.json")
            else:
                print("Original stock radio and repeat setting restored and read back.")


if __name__ == "__main__":
    try:
        main()
    except (Error, OSError, ValueError, TimeoutError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
