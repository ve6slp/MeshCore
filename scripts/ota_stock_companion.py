"""Stock 1.17.1/1.18.0 framing/signing/physical-TX adapter, never an upload engine."""
import re
import struct
import time

from ota_common import Error, app_info, physical_airtime, remaining, sign
from ota_transport import TxReceipt, packet_payload

RELEASES = {b"1.17.1": 13, b"1.18.0": 14}


class StockTransport:
    local = False
    serial_command_bytes = 2

    def __init__(self, node, owner, route, *, clock=time.monotonic, sleep=time.sleep):
        route.validate()
        self.node, self.owner, self.route = node, owner, route
        self.clock, self.sleep = clock, sleep
        self.profile = self.original = None
        self.pending_tx = None

    def command(self, body, expected=(0, 1), deadline=None):
        if body[0] not in (1, 22, 33, 34, 35, 56, 65):
            raise Error("command outside stock v4 transport allowlist")
        timeout = 3 if deadline is None else min(3, remaining(deadline, self.clock))
        frame = self.node.command(body, expected=expected, timeout=timeout)
        if frame[0] == 1:
            raise Error("stock command refused; opaque response withheld")
        return frame

    def identify(self, deadline):
        info = app_info(self.node, timeout=min(5, remaining(deadline, self.clock)))
        if info["pubkey_bytes"] != self.owner:
            raise Error("stock full companion identity mismatch")
        device = self.command(b"\x16\x0a", (13, 1), deadline)
        if len(device) != 82 or device[80] not in (0, 1):
            raise Error("malformed stock DeviceQuery")
        release = re.fullmatch(rb"v?(1\.17\.1|1\.18\.0)(?:-[0-9a-fA-F]+)?",
                               device[60:80].split(b"\0", 1)[0])
        if release is None or device[1] != RELEASES[release[1]]:
            raise Error("unsupported stock release/protocol")
        self.profile = (*info["profile"], device[80])
        if self.original is None:
            self.original = self.profile
        elif self.profile != self.original:
            raise Error("stock ordinary radio/forwarding changed; not silently restored")
        return info

    def sign(self, message, deadline):
        return sign(self.node, message, self.owner, deadline, clock=self.clock)

    def stats(self, deadline):
        core = self.command(b"\x38\x00", (24, 1), deadline)
        packets = self.command(b"\x38\x02", (24, 1), deadline)
        radio = self.command(b"\x38\x01", (24, 1), deadline)
        if (len(core) != 11 or core[:2] != b"\x18\x00" or len(packets) != 30
                or packets[:2] != b"\x18\x02" or len(radio) != 14 or radio[:2] != b"\x18\x01"):
            raise Error("stock physical TX statistics unavailable")
        return (core[10], struct.unpack_from("<I", packets, 6)[0],
                struct.unpack_from("<I", packets, 14)[0], struct.unpack_from("<I", radio, 6)[0])

    def send(self, frame, deadline):
        if self.profile is None:
            raise Error("stock transport has not been identified")
        raw = self.route.packet(frame)
        before = self.stats(deadline)
        if before[0] or self.pending_tx is not None:
            raise Error("stock physical transmitter is not exclusive/idle")
        self.pending_tx = before
        started = self.clock()
        if self.command(bytes([65, 250]) + raw, deadline=deadline) != b"\0":
            raise Error("malformed stock raw-send admission")
        end = min(deadline, self.clock() + max(8, physical_airtime(len(raw), *self.profile[1:4]) * 1.5 + 3))
        while self.clock() < end:
            after = self.stats(end)
            sent, direct = ((after[i] - before[i]) & 0xFFFFFFFF for i in (1, 2))
            if sent > 1 or direct > 1:
                raise Error("concurrent/unattributable stock TX")
            if not after[0] and sent == 1 and direct == (not self.route.flood):
                self.pending_tx = None
                modeled = physical_airtime(len(raw), *self.profile[1:4]) * 1.5
                observed = (after[3] - before[3]) & 0xFFFFFFFF
                return TxReceipt(max(modeled, observed, self.clock() - started), len(raw), len(raw) + 2)
            self.sleep(min(.1, remaining(end, self.clock)))
        raise TimeoutError("stock queue admission never became a physical TX")

    def receive(self, deadline):
        while self.clock() < deadline:
            for index, (_, frame) in enumerate(self.node.pending):
                if frame[0] == 0x88:
                    self.node.pending.pop(index)
                    payload = packet_payload(frame[3:], self.route.max_path_bytes)
                    if payload is not None:
                        self.last_rx_bytes = (len(frame) - 3, len(frame))
                        return payload
                    break
            else:
                self.node.poll(min(.1, deadline - self.clock()))
        return None

    def cleanup(self, deadline):
        if self.pending_tx is not None:
            raise Error("stock physical TX outcome unresolved; sender radio was never changed")
        self.identify(deadline)

    def acquire_lease(self, *_):
        raise Error("stock has no transient sender radio lease; persistent CMD11 is prohibited")

    def release_lease(self, *_):
        raise Error("stock sender radio was never leased or retuned")
