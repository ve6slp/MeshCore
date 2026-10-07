"""Bounded companion USB framing and Ed25519 descriptor signing.

Only public operation summaries are logged. Opaque responses may contain GPS,
channel keys or uninitialised padding and must never be dumped.
"""

import fcntl
import json
import math
import os
from pathlib import Path
import select
import struct
import time

CMD_APP_START = 1
CMD_DEVICE_QUERY = 22
CMD_SIGN_START = 33
CMD_SIGN_DATA = 34
CMD_SIGN_FINISH = 35
CMD_OTA_CONTROL = 67
RESP_OK = 0
RESP_ERR = 1
RESP_SELF_INFO = 5
RESP_DEVICE_INFO = 13
RESP_SIGN_START = 19
RESP_SIGNATURE = 20
MAX_SERIAL_FRAME_SIZE = 176
ASYNC_PUSH_CODES = frozenset(range(0x80, 0x91))


class Evidence:
    """Optional local operation log, not an approval or qualification ledger."""

    def __init__(self, directory=None, exclusive=False):
        self.events = None
        if directory is not None:
            path = Path(directory)
            path.mkdir(parents=True, mode=0o700, exist_ok=not exclusive)
            self.events = (path / "events.jsonl").open("x", encoding="utf-8")

    def log(self, event, **fields):
        value = {"event": event, **fields}
        if self.events is not None:
            self.events.write(json.dumps(value, sort_keys=True) + "\n")
            self.events.flush()
        if event in ("ota_command_result", "fatal"):
            print(json.dumps(value, sort_keys=True))

    def finish(self, error=None):
        if self.events is not None:
            self.events.close()


class FramedSerial:
    def __init__(self, name, path, evidence, *, no_reset=True, dtr=False):
        if not no_reset:
            raise ValueError("OTA serial access never resets the companion")
        self.name, self.path, self.evidence = name, path, evidence
        self.no_reset = True
        self.stream = None
        self.fd = None
        self.buffer = bytearray()
        self.pending = []
        import serial
        self.stream = serial.Serial(port=None, baudrate=115200, timeout=0,
                                    write_timeout=2.0, exclusive=True)
        try:
            self.stream.dtr = dtr
            self.stream.rts = False
            self.stream.port = str(path)
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

    def _write_bytes(self, frame):
        if self.stream.write(frame) != len(frame):
            raise ConnectionError(f"{self.name}: incomplete serial write")

    def _read_bytes(self, timeout):
        readable, _, _ = select.select([self.fd], [], [], timeout)
        if not readable:
            return b""
        chunk = os.read(self.fd, 4096)
        if not chunk:
            raise ConnectionError(f"{self.name}: serial disconnected")
        return chunk

    def write_frame(self, payload):
        if not 1 <= len(payload) <= MAX_SERIAL_FRAME_SIZE:
            raise ValueError("serial frame length out of range")
        self._write_bytes(b"<" + struct.pack("<H", len(payload)) + payload)

    def _extract(self):
        frames = []
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
                raise ValueError(f"{self.name}: invalid serial response length")
            if len(self.buffer) < 3 + length:
                break
            frames.append(bytes(self.buffer[3:3 + length]))
            del self.buffer[:3 + length]
        return frames

    def poll(self, timeout=0.0):
        self.buffer.extend(self._read_bytes(timeout))
        for payload in self._extract():
            # Native OTA/inspection/signing do not consume regular MeshCore pushes.
            if payload[0] in ASYNC_PUSH_CODES:
                if payload[0] == 0x88 and len(payload) < 3:
                    raise ValueError(f"{self.name}: malformed RF diagnostic push")
                continue
            if len(self.pending) >= 256:
                raise ValueError(f"{self.name}: serial response backlog overflow")
            self.pending.append((time.monotonic(), payload))

    def take_pending(self, codes):
        found = [entry for entry in self.pending if entry[1][0] in codes]
        self.pending = [entry for entry in self.pending if entry[1][0] not in codes]
        return found

    def wait_frame(self, codes, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.poll(max(0, min(0.1, deadline - time.monotonic())))
            for index, (_, payload) in enumerate(self.pending):
                if payload[0] in codes:
                    self.pending.pop(index)
                    return payload
        raise TimeoutError(f"{self.name}: no frame with code {sorted(codes)}")

    def command(self, payload, expected=(RESP_OK, RESP_ERR), timeout=5.0):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("serial command timeout must be finite and positive")
        deadline = time.monotonic() + timeout
        self.poll(0)
        self.take_pending(set(expected))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"{self.name}: serial command deadline expired")
        self.stream.write_timeout = min(2.0, remaining)
        self.write_frame(payload)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"{self.name}: serial command deadline expired")
        return self.wait_frame(set(expected), remaining)


def app_info(node, *, timeout=5.0):
    frame = node.command(bytes([CMD_APP_START]) + bytes(7) + b"ota",
                         expected=(RESP_SELF_INFO, RESP_ERR), timeout=timeout)
    if len(frame) < 58 or frame[0] != RESP_SELF_INFO or frame[1] != 1 or frame[4:36] == bytes(32):
        raise ValueError("malformed companion SelfInfo")
    name = frame[58:].decode("utf-8")
    if "\0" in name or any(not char.isprintable() for char in name):
        raise ValueError("malformed public companion name")
    return {"role": "companion", "pubkey": frame[4:36].hex(),
            "pubkey_bytes": frame[4:36], "name": name}


def sign_manifest(node, canonical, owner_public_key, deadline=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if len(canonical) != 59 or len(owner_public_key) != 32 or owner_public_key == bytes(32):
        raise ValueError("canonical descriptor and nonzero owner public key required")
    verifier = Ed25519PublicKey.from_public_bytes(owner_public_key)

    def options():
        remaining = 5.0 if deadline is None else deadline - time.monotonic()
        if not math.isfinite(remaining) or remaining <= 0:
            raise TimeoutError("OTA manifest signing deadline expired")
        return {"timeout": min(5.0, remaining)}

    frame = node.command(bytes([CMD_SIGN_START]), expected=(RESP_SIGN_START, RESP_ERR), **options())
    if (len(frame) != 6 or frame[:2] != bytes([RESP_SIGN_START, 0])
            or struct.unpack_from("<I", frame, 2)[0] < len(canonical)):
        raise RuntimeError("invalid signing-start reply or insufficient signing buffer")
    if node.command(bytes([CMD_SIGN_DATA]) + canonical, **options()) != bytes([RESP_OK]):
        raise RuntimeError("companion rejected descriptor signing data")
    frame = node.command(bytes([CMD_SIGN_FINISH]), expected=(RESP_SIGNATURE, RESP_ERR), **options())
    if len(frame) != 65 or frame[0] != RESP_SIGNATURE:
        raise RuntimeError("invalid signature reply")
    verifier.verify(frame[1:], canonical)
    return frame[1:]
