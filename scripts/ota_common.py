"""OTA v4 wire objects, bounded companion framing and public signing.

No imports open devices. Opaque companion responses are never logged.
"""
from dataclasses import dataclass
from enum import IntEnum
import fcntl
import math
import os
import select
import struct
import time
import zlib

CHUNK_BYTES = 8192
SLICE_BYTES = 128
MAX_CHUNKS = 128
MAX_MANIFEST = 8192
MAX_FRAME = 151
MAX_SERIAL_FRAME_SIZE = 176
ZERO_HASH = bytes(32)
CMD_APP_START = 1
CMD_DEVICE_QUERY = 22
CMD_SIGN_START, CMD_SIGN_DATA, CMD_SIGN_FINISH = 33, 34, 35
RESP_OK, RESP_ERR, RESP_SELF_INFO, RESP_DEVICE_INFO = 0, 1, 5, 13
RESP_SIGN_START, RESP_SIGNATURE = 19, 20


class Error(RuntimeError):
    pass


class Kind(IntEnum):
    QUERY = 1
    STATUS = 2
    MANIFEST = 3
    ADMIT = 4
    DATA = 5
    PROGRESS_QUERY = 6
    PROGRESS = 7
    ACTIVATE = 8
    ABORT = 9
    LEASE = 10
    REPAIR = 11


class Phase(IntEnum):
    IDLE = 0
    RECEIVING = 1
    VERIFYING = 2
    READY = 3
    ACTIVATION_PENDING = 4
    TRIAL = 5
    CONFIRMED = 6
    ABORTED = 7
    FAILED = 8
    METADATA_FAULT = 9


class Result(IntEnum):
    OK = 0
    INVALID = 1
    DENIED = 2
    BUSY = 3
    STATE = 4
    INTEGRITY = 5
    IO = 6
    UNSUPPORTED = 7
    REPLAY = 8


def domain(action):
    return f"MeshCore OTA {action} v4\0".encode("ascii")


def public_key(text):
    try:
        value = bytes.fromhex(text)
    except (ValueError, TypeError):
        raise ValueError("full hexadecimal public key required") from None
    if len(value) != 32 or not any(value):
        raise ValueError("nonzero full 32-byte public key required")
    return value


def verify(key, message, signature):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(bytes(key)).verify(bytes(signature), bytes(message))
    except (InvalidSignature, ValueError) as exc:
        raise Error("Ed25519 signature/identity mismatch") from exc


def remaining(deadline, clock=None):
    clock = time.monotonic if clock is None else clock
    value = deadline - clock()
    if not math.isfinite(value) or value <= 0:
        raise TimeoutError("OTA operation deadline expired")
    return value


def slice_mask(total):
    if not 0 < total <= CHUNK_BYTES:
        raise ValueError("object length outside v4 bounds")
    return (1 << ((total + SLICE_BYTES - 1) // SLICE_BYTES)) - 1


@dataclass(frozen=True)
class Frame:
    kind: Kind
    attempt: int
    tag: bytes
    object: int
    total: int
    slice: int
    data: bytes

    def encode(self):
        if (not 0 < self.attempt <= 0xFFFFFFFF or len(self.tag) != 8
                or not 0 <= self.object <= 0xFFFF or not 0 < self.total <= CHUNK_BYTES
                or not 0 <= self.slice < (self.total + 127) // 128
                or len(self.data) != min(128, self.total - self.slice * 128)):
            raise ValueError("invalid v4 frame geometry")
        prefix = struct.pack(">BBI8sHHB", 0xD4, Kind(self.kind), self.attempt,
                             self.tag, self.object, self.total, self.slice) + self.data
        return prefix + struct.pack(">I", zlib.crc32(prefix))

    @classmethod
    def decode(cls, data):
        if not 24 <= len(data) <= MAX_FRAME or data[0] != 0xD4:
            raise Error("invalid v4 frame size/magic")
        if zlib.crc32(data[:-4]) != struct.unpack_from(">I", data, len(data) - 4)[0]:
            raise Error("v4 frame CRC mismatch")
        try:
            _, kind, attempt, tag, obj, total, index = struct.unpack_from(">BBI8sHHB", data)
            frame = cls(Kind(kind), attempt, tag, obj, total, index, data[19:-4])
            frame.encode()
            return frame
        except (ValueError, struct.error) as exc:
            raise Error("invalid v4 frame fields") from exc


class Assembly:
    """One bounded object; transmission attempt is deliberately not its identity."""
    def __init__(self, kind, tag, obj, maximum=512):
        self.kind, self.tag, self.object = kind, tag, obj
        self.maximum, self.total = maximum, None
        self.parts = {}

    def feed(self, frame):
        if (frame.kind != self.kind or frame.object != self.object
                or (self.tag is not None and frame.tag != self.tag)):
            return None
        if frame.total > self.maximum or (self.total is not None and frame.total != self.total):
            raise Error("inconsistent or oversized response object")
        self.total = frame.total
        previous = self.parts.get(frame.slice)
        if previous is not None and previous != frame.data:
            raise Error("conflicting response slices")
        self.parts[frame.slice] = frame.data
        if len(self.parts) == (self.total + 127) // 128:
            return b"".join(self.parts[i] for i in range(len(self.parts)))
        return None


@dataclass(frozen=True)
class Status:
    target: bytes
    query_nonce: bytes
    challenge: bytes
    package: bytes
    transaction: bytes
    generation: int
    counter: int
    floor: int
    phase: Phase
    result: Result
    next_chunk: int
    missing: int
    running_hash: bytes
    evidence: int
    signed: bytes

    @classmethod
    def decode(cls, body, target, nonce):
        body = bytes(body)
        if len(body) != 233 or body[:32] != target or body[32:48] != nonce:
            raise Error("status target/query nonce mismatch")
        verify(target, domain("status") + body[:169], body[169:])
        try:
            generation, counter, floor, phase, result, chunk, missing = struct.unpack_from(">IIIBBHQ", body, 112)
            value = cls(target, nonce, body[48:64], body[64:96], body[96:112],
                        generation, counter, floor, Phase(phase), Result(result), chunk,
                        missing, body[136:168], body[168], body)
        except ValueError as exc:
            raise Error("unknown status phase/result") from exc
        if value.evidence & ~7 or value.next_chunk > MAX_CHUNKS or not any(value.challenge):
            raise Error("invalid status evidence/challenge/progress")
        return value

    def installed(self, package):
        return (self.package == package.digest and self.counter == package.counter
                and self.phase == Phase.CONFIRMED
                and self.evidence == 7 and self.floor >= package.counter
                and self.running_hash == package.raw_hash and any(self.transaction))


def signed_command(kind, owner, target, package_hash, nonce, generation, signer, lease=None):
    actions = {Kind.ADMIT: "admit", Kind.ACTIVATE: "activate", Kind.ABORT: "abort",
               Kind.REPAIR: "repair", Kind.LEASE: "lease"}
    if (kind not in actions or len(owner) != 32 or not any(owner) or len(target) != 32
            or not any(target) or len(package_hash) != 32 or len(nonce) != 16 or not any(nonce)
            or not 0 <= generation <= 0xFFFFFFFF):
        raise ValueError("invalid signed command context")
    body = owner + target + package_hash + nonce + struct.pack(">I", generation)
    if kind == Kind.LEASE:
        if lease is None or len(lease) != 14:
            raise ValueError("exact 14-byte lease parameters required")
        frequency, bandwidth, sf, cr, duration = struct.unpack(">IIBBI", lease)
        if (not 150000 <= frequency <= 2500000 or not 7000 <= bandwidth <= 500000
                or not 5 <= sf <= 12 or not 5 <= cr <= 8 or duration > 60000):
            raise ValueError("invalid transient lease parameters")
        body += lease
    elif lease is not None:
        raise ValueError("lease parameters on non-lease command")
    signature = signer(domain(actions[kind]) + body)
    verify(owner, domain(actions[kind]) + body, signature)
    return body + signature


def physical_airtime(size, bandwidth=62500, sf=7, cr=5):
    if not 1 <= size <= 255 or not 7000 <= bandwidth <= 500000 or not 5 <= sf <= 12 or not 5 <= cr <= 8:
        raise ValueError("invalid LoRa airtime inputs")
    symbol = (1 << sf) / bandwidth
    de = int(symbol >= .016)
    payload = 8 + max(0, math.ceil((8 * size - 4 * sf + 44) / (4 * (sf - 2 * de)))) * cr
    return ((32 if sf <= 8 else 16) + 4.25 + payload) * symbol


class FramedSerial:
    def __init__(self, name, path, evidence=None, *, no_reset=True, dtr=False):
        if not no_reset:
            raise ValueError("OTA serial access never resets the companion")
        from ota_devices import quiet_serial_factory
        self.name, self.path, self.evidence = name, path, evidence
        self.no_reset = True
        self.stream = quiet_serial_factory(port=None, baudrate=115200, timeout=0,
                                           write_timeout=2, exclusive=True)
        self.fd = None
        self.buffer, self.pending = bytearray(), []
        try:
            self.stream.dtr, self.stream.rts, self.stream.port = dtr, False, str(path)
            self.stream.open()
            self.fd = self.stream.fileno()
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.stream is not None:
            self.stream.close()
            self.stream = None
            self.fd = None

    def _write_bytes(self, data):
        if self.stream.write(data) != len(data):
            raise ConnectionError("incomplete companion serial write")

    def _read_bytes(self, timeout):
        if not select.select([self.fd], [], [], timeout)[0]:
            return b""
        data = os.read(self.fd, 4096)
        if not data:
            raise ConnectionError("companion disconnected")
        return data

    def write_frame(self, payload):
        if not 1 <= len(payload) <= MAX_SERIAL_FRAME_SIZE:
            raise ValueError("serial frame length out of range")
        self._write_bytes(b"<" + struct.pack("<H", len(payload)) + payload)

    def poll(self, timeout=0):
        self.buffer.extend(self._read_bytes(timeout))
        while self.buffer:
            marker = self.buffer.find(b">")
            if marker < 0:
                self.buffer.clear()
                break
            del self.buffer[:marker]
            if len(self.buffer) < 3:
                break
            length = struct.unpack_from("<H", self.buffer, 1)[0]
            if not 1 <= length <= MAX_SERIAL_FRAME_SIZE:
                raise Error("invalid companion frame length")
            if len(self.buffer) < length + 3:
                break
            payload = bytes(self.buffer[3:length + 3])
            del self.buffer[:length + 3]
            # Only raw RF/native bridge pushes belong to this client.
            if 0x80 <= payload[0] <= 0x90 and payload[0] != 0x88:
                continue
            if payload[0] == 0x88:
                if len(payload) < 6:
                    raise Error("malformed RF diagnostic push")
                width, count = (payload[4] >> 6) + 1, payload[4] & 63
                offset = 5 + width * count
                if ((payload[3] >> 2) & 15 != 12 or width > 3 or width * count > 64
                        or offset + 1 >= len(payload) or payload[offset] != 0xD4
                        or payload[offset + 1] not in (Kind.STATUS, Kind.PROGRESS)):
                    continue
            if len(self.pending) >= 256:
                raise Error("companion response backlog overflow")
            self.pending.append((time.monotonic(), payload))

    def take_pending(self, codes):
        found = [x for x in self.pending if x[1][0] in codes]
        self.pending = [x for x in self.pending if x[1][0] not in codes]
        return found

    def command(self, payload, expected=(0, 1), timeout=5):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("positive finite command timeout required")
        deadline = time.monotonic() + timeout
        self.poll()
        self.take_pending(set(expected))
        self.stream.write_timeout = remaining(deadline)
        self.write_frame(payload)
        while time.monotonic() < deadline:
            for _, frame in self.take_pending(set(expected)):
                return frame
            self.poll(min(.1, remaining(deadline)))
        raise TimeoutError("companion response deadline expired")


def app_info(node, *, timeout=5):
    frame = node.command(bytes([CMD_APP_START]) + bytes(7) + b"ota-v4",
                         expected=(RESP_SELF_INFO, RESP_ERR), timeout=timeout)
    if len(frame) < 58 or frame[:2] != b"\x05\x01" or not any(frame[4:36]):
        raise Error("malformed companion SelfInfo")
    name = frame[58:].decode("utf-8")
    if "\0" in name or any(not c.isprintable() for c in name):
        raise Error("invalid companion public name")
    return {"role": "companion", "pubkey": frame[4:36].hex(),
            "pubkey_bytes": frame[4:36], "name": name,
            "profile": (*struct.unpack_from("<II", frame, 48), frame[56], frame[57])}


def sign(node, message, owner, deadline, *, clock=None):
    def command(body, expected=(0, 1)):
        return node.command(body, expected=expected, timeout=min(5, remaining(deadline, clock)))
    start = command(b"\x21", (19, 1))
    if len(start) != 6 or start[:2] != b"\x13\x00" or struct.unpack_from("<I", start, 2)[0] < len(message):
        raise Error("companion signing buffer too small for this authenticated object")
    for offset in range(0, len(message), 175):
        if command(b"\x22" + message[offset:offset + 175]) != b"\0":
            raise Error("companion rejected signing data")
    result = command(b"\x23", (20, 1))
    if len(result) != 65 or result[0] != 20:
        raise Error("invalid companion signature response")
    verify(owner, message, result[1:])
    return result[1:]
