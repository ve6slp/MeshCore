"""Thin native v4 serial bridge and shared MeshCore packet boundaries."""
from dataclasses import dataclass
import struct
import time

from ota_common import Error, app_info, remaining, sign


@dataclass(frozen=True)
class Route:
    flood: bool = False
    path: bytes = b""
    width: int = 1
    max_path_bytes: int = 0
    return_path: bytes | None = None
    return_width: int | None = None

    def validate(self):
        if (self.width not in (1, 2, 3) or len(self.path) % self.width
                or len(self.path) > self.max_path_bytes or not 0 <= self.max_path_bytes <= 20
                or (self.flood and (self.path or self.width != 1))):
            raise ValueError("stock-safe route requires explicit maximum path growth of 0..20 bytes")
        width = self.width if self.return_width is None else self.return_width
        if (self.return_path is None and self.return_width is not None
                or width not in (1, 2, 3)
                or (self.return_path is not None and
                    (len(self.return_path) % width or len(self.return_path) > self.max_path_bytes))):
            raise ValueError("return path requires whole 1..3-byte hashes within the maximum path budget")

    def reply_path(self):
        self.validate()
        if self.return_path is None:
            if self.flood or not self.path:
                return b""
            path = b"".join(self.path[i:i + self.width]
                            for i in range(len(self.path) - self.width, -1, -self.width))
            width = self.width
        else:
            path = self.return_path
            width = self.width if self.return_width is None else self.return_width
        return bytes([((width - 1) << 6) | (len(path) // width)]) + path

    def packet(self, frame):
        self.validate()
        if not 24 <= len(frame) <= 151:
            raise ValueError("v4 frame outside fixed transport bounds")
        return (bytes([0x31 if self.flood else 0x32,
                       ((self.width - 1) << 6) | (len(self.path) // self.width)])
                + self.path + frame)

    def policy(self):
        policy = {"flood": self.flood, "path": self.path.hex(), "width": self.width,
                  "max_path_bytes": self.max_path_bytes}
        if self.return_path is not None:
            policy.update(return_path=self.return_path.hex(), return_width=self.return_width)
        return policy

    @classmethod
    def from_policy(cls, value):
        route = cls(value["flood"], bytes.fromhex(value["path"]), value["width"], value["max_path_bytes"],
                    bytes.fromhex(value["return_path"]) if "return_path" in value else None,
                    value.get("return_width"))
        route.validate()
        return route


def packet_payload(packet, bound=20, *, require_delivered=False):
    if len(packet) < 3:
        return None
    header, encoded = packet[:2]
    width, count = (encoded >> 6) + 1, encoded & 63
    path = width * count
    if (header >> 6 or (header >> 2) & 15 != 12 or header & 3 not in (1, 2)
            or width > 3 or path > bound or 2 + path >= len(packet)):
        return None
    if require_delivered and header & 3 == 2 and count:
        return None
    return packet[2 + path:]


@dataclass(frozen=True)
class TxReceipt:
    airtime: float
    wire_bytes: int
    serial_bytes: int = 0


class NativeTransport:
    """No cache or campaign state: one physical TX or one local receiver feed."""
    local = False
    serial_command_bytes = 3

    def __init__(self, node, owner, route, *, local=False, clock=time.monotonic, sleep=time.sleep):
        route.validate()
        self.node, self.owner, self.route = node, owner, route
        self.local, self.clock, self.sleep = local, clock, sleep
        self.profile = None
        self.original = None

    def _bridge(self, op, payload, deadline):
        self.node.poll()
        self.node.pending = [(t, f) for t, f in self.node.pending
                             if not (f[0] == 30 and (len(f) < 3 or f[2] != 3))]
        self.node.stream.write_timeout = min(3, remaining(deadline, self.clock))
        self.node.write_frame(bytes([67, 4, op]) + payload)
        while remaining(deadline, self.clock):
            for index, (_, frame) in enumerate(self.node.pending):
                if frame[0] == 0x88 or (self.local and frame[0] == 0x91):
                    self.node.pending.pop(index)
                    break
                if frame[0] == 1:
                    self.node.pending.pop(index)
                    raise Error("native bridge request refused")
                if frame[:3] == bytes([30, 4, op]):
                    self.node.pending.pop(index)
                    if len(frame) < 4 or frame[3]:
                        raise Error("native bridge did not confirm completion")
                    return frame
            self.node.poll(min(.1, remaining(deadline, self.clock)))

    def identify(self, deadline):
        info = app_info(self.node, timeout=min(5, remaining(deadline, self.clock)))
        if info["pubkey_bytes"] != self.owner:
            raise Error("native full companion identity mismatch")
        if self._bridge(0, b"", deadline) != bytes([30, 4, 0, 0]):
            raise Error("unsupported native bridge ABI")
        device = self.node.command(b"\x16\x0d", expected=(13, 1),
                                   timeout=min(5, remaining(deadline, self.clock)))
        if len(device) != 82 or device[0] != 13 or device[80] not in (0, 1):
            raise Error("native ordinary forwarding readback unavailable")
        self.profile = (*info["profile"], device[80])
        if self.original is None:
            self.original = self.profile
        elif self.profile != self.original:
            raise Error("ordinary companion radio changed; no settings mutation or assumed restoration")
        return info

    def sign(self, message, deadline):
        return sign(self.node, message, self.owner, deadline, clock=self.clock)

    def send(self, frame, deadline):
        raw = frame if self.local else self.route.packet(frame)
        reply = self._bridge(2 if self.local else 1, raw, deadline)
        if self.local:
            if len(reply) != 4:
                raise Error("invalid local-feed reply")
            return TxReceipt(0, 0, len(raw) + 3)
        if len(reply) != 8:
            raise Error("native bridge did not provide physical TX airtime")
        return TxReceipt(struct.unpack_from(">I", reply, 4)[0] / 1_000_000, len(raw), len(raw) + 3)

    def receive(self, deadline):
        while self.clock() < deadline:
            for index, (_, frame) in enumerate(self.node.pending):
                if frame[0] == 0x88 or (self.local and frame[0] == 0x91):
                    self.node.pending.pop(index)
                    break
                if self.local and frame[:3] == bytes([30, 4, 3]):
                    self.node.pending.pop(index)
                    self.last_rx_bytes = (0, len(frame))
                    return frame[3:]
                if not self.local and frame[0] == 0x91:
                    self.node.pending.pop(index)
                    payload = packet_payload(frame[1:], self.route.max_path_bytes, require_delivered=True)
                    if payload is not None:
                        self.last_rx_bytes = (len(frame) - 1, len(frame))
                        return payload
                    break
            else:
                self.node.poll(min(.1, deadline - self.clock()))
        return None

    def cleanup(self, deadline):
        self.identify(deadline)

    def acquire_lease(self, *_):
        raise Error("raw serial bridge has no sender radio-lease operation; normal radio only")

    def release_lease(self, *_):
        raise Error("no sender radio lease was acquired")
