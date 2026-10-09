"""Focused host protocol tests. No serial open, lab lookup, device or key files."""
import hashlib
import io
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import struct
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ota_stock_companion as ota

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]

# Synthetic deterministic test keys, not hardware identities.
OWNER_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
TARGET_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32)
OWNER = OWNER_PRIVATE.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
TARGET = TARGET_PRIVATE.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
RELAY = bytes.fromhex("739194" + "42" * 29)
NORMAL = (918000, 62500, 7, 5, 1)
STOCK_ID = "/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0"
STOCK_PATH = "/dev/serial/by-path/pci-0000:00:00.0-usb-0:1.1:1.0-port0"
STOCK_ID_PATH = "pci-0000:00:00.0-usb-0:1.1:1.0"
STOCK_TTY = Path("/dev/ttyUSB1")
OLD_TTY = Path("/dev/ttyUSB0")


def candidate(size=168):
    image = struct.pack("<II", 0x20010000, 0x27009) + bytes((i % 251 for i in range(size - 8)))
    canonical = (b"XN40\x00" + struct.pack(">II", 0x27000, size) + hashlib.sha256(image).digest()
                 + struct.pack(">IIHHH", 5, 1, 1, 1, 1))
    return ota.Candidate.build(canonical, image, 4)


def binding(c=None):
    c = c or candidate()
    return ota.Binding("ABCDEF0123456789", OWNER, TARGET, 4, 10, NORMAL[:4],
                       hashlib.sha256(c.image).digest(), c.digest)


BINDING = binding()


NONCE = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
CHALLENGE = 0x5EED0001


def census(c, first=0, received=None, generation=10, lifecycle=None, floor=4, nonce=NONCE,
           challenge=CHALLENGE):
    if received is None:
        received = set(range(c.total))
    bits = sum(1 << (i - first) for i in received if first <= i < first + 128)
    ready = len(received) == c.total
    return (b"\x0b" + TARGET + c.digest + struct.pack(">H", first) + bits.to_bytes(16, "little")
            + struct.pack(">HHBIBBII", len(received), c.total, 3 if ready else 1, generation,
                          (5 if ready else 3) if lifecycle is None else lifecycle, 1, floor, c.counter)
            + bytes([ota.WIRE_VERSION]) + nonce + struct.pack(">I", challenge))


def legacy_census(c, **options):
    return census(c, **options)[:102]


def pending_census(c, generation=9, floor=4, nonce=NONCE):
    frame = census(c, received=set(), generation=generation, lifecycle=9, floor=floor, nonce=nonce,
                   challenge=0)
    return frame[:87] + b"\x05" + frame[88:]


# Well-formed ordinary MeshCore 1.17.1 pushes the stock uploader never consumes.
ORDINARY_PUSHES = (
    b"\x80" + bytes(32), b"\x81" + bytes(32), b"\x82" + bytes(8), b"\x83",
    b"\x84\x10\xc0\xff" + bytes(10), b"\x85" + bytes(7), b"\x85" + bytes(13), b"\x86" + bytes(7),
    b"\x87" + bytes(20), b"\x89" + bytes(14), b"\x8a" + bytes(147), b"\x8b" + bytes(12),
    b"\x8c" + bytes(9), b"\x8d" + bytes(11), b"\x8e\x10\xc0\x00" + bytes(6), b"\x8f" + bytes(32),
    b"\x90",
    b"\x88\x10\xc0\x11\x00" + bytes(100),  # ordinary flood ADVERT RF log, not OTA payload type 0x0C
)


class Clock:
    def __init__(self):
        self.now = 1.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeSerial:
    """Stock USB + RF receiver model including delayed physical TX/leases."""
    def __init__(self, clock, c, received=()):
        self.clock, self.candidate = clock, c
        self.profile = NORMAL
        self.target_normal = NORMAL[:4]
        self.direct_frequency = 919000
        self.direct_bandwidth = 250000
        self.supports_profile = True
        self.command_delay = self.sign_delay = 0
        self.tx_power = 2
        self.path_hash_bytes = 2
        self.received = set(received)
        self.events = []
        self.output = bytearray()
        self.timeout = 0.1
        self.commands = []
        self.rf_packets = []
        self.raw_packets = []
        self.queue = self.sent = self.direct = self.air = 0
        self.admitted = False
        self.signing = bytearray()
        self.switch = self.expiry = 0
        self.tokens = []
        self.rejected_tokens = []
        self.nonce = NONCE
        self.challenge = CHALLENGE
        self.legacy_receiver = False
        self.commit_count = 0
        self.denied_commits = 0
        self.drop_census = self.drop_blocks = 0
        self.drop_ack = 0
        self.bad_ack = False
        self.ack_mutator = None
        self.tx_fails = False
        self.fail_restore = False
        self.version = b"v1.17.1"
        self.wrong_identity = False
        self.name = b"synthetic-stock"
        self.drop_start = 0
        self.sign_with_target = False
        self.generation = 10
        self.floor = 4
        self.last_census = None
        self.local_cache = self.aborted = self.prepared = False
        self.supports_purpose_transition = True
        self.reupload_count = self.drop_reupload = 0
        self.drop_activation_census = 0
        self.activation_reports = []
        self.census_hash_size, self.census_path = 1, b""
        self.rx_packets = []

    def schedule(self, delay, action):
        self.events.append((self.clock() + delay, action))
        self.events.sort(key=lambda pair: pair[0])

    def reply(self, data):
        self.output.extend(b">" + struct.pack("<H", len(data)) + data)

    def push(self, payload):
        census_frame = payload[0] == 11
        leased = self.switch <= self.clock() < self.expiry
        header = 0x31 if census_frame and not leased else 0x32
        size, path = (self.census_hash_size, self.census_path) if census_frame else (1, b"")
        encoded = ((size - 1) << 6) | (len(path) // size)
        packet = bytes([header, encoded]) + path + payload
        self.rx_packets.append((self.clock(), self.profile, packet, payload))
        self.reply(b"\x88\x08\x40" + packet)

    def run_events(self):
        while self.events and self.events[0][0] <= self.clock():
            _, action = self.events.pop(0)
            action()

    def read(self, count):
        self.run_events()
        if not self.output and self.timeout:
            self.clock.sleep(min(self.timeout, max(0, self.events[0][0] - self.clock()) if self.events else self.timeout))
            self.run_events()
        result = bytes(self.output[:count])
        del self.output[:count]
        return result

    @property
    def in_waiting(self):
        self.run_events()
        return len(self.output)

    def write(self, wire):
        assert wire[:1] == b"<" and len(wire) == 3 + struct.unpack_from("<H", wire, 1)[0]
        payload = wire[3:]
        assert len(payload) <= 176
        self.commands.append(payload)
        cmd = payload[0]
        self.clock.sleep(self.command_delay + (self.sign_delay if cmd == 35 else 0))
        if cmd == 22:
            frame = bytearray(82)
            frame[:2] = b"\x0d\x0d"
            frame[4:8] = b"\x99\x88\x77\x66"  # Synthetic PIN sentinel; never logged.
            frame[60:60 + len(self.version)] = self.version
            frame[80] = self.profile[4]
            self.reply(frame)
        elif cmd == 1:
            if self.drop_start:
                self.drop_start -= 1
                return len(wire)
            frame = bytearray(58)
            frame[:2] = b"\x05\x01"
            frame[2] = self.tx_power & 0xFF
            frame[3] = self.path_hash_bytes
            frame[4:36] = TARGET if self.wrong_identity else OWNER
            frame[36:44] = b"GPS-HIDE"
            frame[48:58] = struct.pack("<II", *self.profile[:2]) + bytes(self.profile[2:4])
            self.reply(frame + self.name)
        elif cmd == 11:
            profile = (*struct.unpack_from("<II", payload, 1), *payload[9:])
            if self.fail_restore and profile == NORMAL:
                self.reply(b"\x01\x02")
            else:
                self.profile = profile
                self.reply(b"\x00")
        elif cmd == 33:
            self.signing = bytearray()
            self.reply(b"\x13\x00" + struct.pack("<I", 512))
        elif cmd == 34:
            self.signing.extend(payload[1:])
            self.reply(b"\x00")
        elif cmd == 35:
            signer = TARGET_PRIVATE if self.sign_with_target else OWNER_PRIVATE
            self.reply(b"\x14" + signer.sign(bytes(self.signing)))
        elif cmd == 56:
            subtype = payload[1]
            if subtype == 0:
                self.reply(b"\x18\x00" + bytes(8) + bytes([self.queue]))
            elif subtype == 1:
                self.reply(b"\x18\x01" + bytes(4) + struct.pack("<II", self.air, 0))
            elif subtype == 2:
                self.reply(b"\x18\x02" + struct.pack("<IIIIIII", 0, self.sent, 0, self.direct, 0, 0, 0))
        elif cmd == 65:
            assert payload[2] == 0x32
            encoded = payload[3]
            width, count = (encoded >> 6) + 1, encoded & 63
            assert width <= 3 and width * count <= 64
            self.queue += 1
            self.raw_packets.append(payload[2:])
            rf = payload[4 + width * count:]
            self.rf_packets.append((self.clock(), self.profile, rf))
            self.reply(b"\x00")
            def finish():
                self.queue -= 1
                if not self.tx_fails:
                    self.sent += 1
                    self.direct += 1
                    self.remote(rf)
            self.schedule(0.15, finish)
        else:
            raise AssertionError(f"forbidden/unknown USB command {cmd}")
        return len(wire)

    def remote(self, rf):
        off = self.switch <= self.clock() < self.expiry
        expected = (self.direct_frequency, self.direct_bandwidth, 5, 5) if off else self.target_normal
        if self.profile[:4] != expected:
            return
        c = self.candidate
        if rf[0] == 8:
            assert len(rf) == 164
            assert rf[1:9] == hashlib.sha256(TARGET).digest()[:8]
            assert rf[9:41] == OWNER and rf[41:100] == c.canonical
            ota.verify(OWNER, c.canonical, rf[100:])
            if self.local_cache:
                if not self.aborted or not self.supports_purpose_transition:
                    return
                self.prepared = True
                return
            self.admitted = True
        elif rf[0] == 10:
            if self.drop_census:
                self.drop_census -= 1
                return
            if not self.admitted and not self.prepared:
                return
            if self.reupload_count and self.drop_activation_census:
                self.drop_activation_census -= 1
                return
            assert rf[1:33] == TARGET and rf[33:65] == c.digest
            first = struct.unpack_from(">H", rf, 65)[0]
            if self.prepared:
                report = pending_census(c, self.generation, self.floor, self.nonce)
            else:
                report = census(c, first, self.received, self.generation, floor=self.floor,
                                nonce=self.nonce, challenge=self.challenge)
            if self.legacy_receiver:
                report = report[:102]
            if self.activation_reports and self.reupload_count:
                report = self.activation_reports.pop(0)
            self.last_census = report
            self.schedule(0.1, lambda: self.push(report))
        elif rf[0] in (12, 15):
            if rf[0] == 15 and not self.supports_profile:
                return
            assert self.admitted and rf[1:33] == OWNER and rf[33:65] == TARGET and rf[65:97] == c.digest
            domain = ota.DIRECT_PROFILE_DOMAIN if rf[0] == 15 else ota.DIRECT_DOMAIN
            ota.verify(OWNER, domain + rf[:107], rf[107:])
            frequency_word = struct.unpack_from(">I", rf, 97)[0]
            if rf[0] == 15:
                assert rf[97] in (1, 2)
                self.direct_bandwidth = 500000 if rf[97] == 2 else 250000
                frequency_word &= 0xFFFFFF
            else:
                self.direct_bandwidth = 250000
            assert frequency_word == self.direct_frequency
            token = struct.unpack_from(">I", rf, 103)[0]
            if token != self.challenge:
                # Replayed, stale or guessed challenge: no ACK and no retune.
                self.rejected_tokens.append(token)
                return
            assert token not in self.tokens
            self.tokens.append(token)
            self.challenge = (self.challenge * 1103515245 + 12345) & 0xFFFFFFFF or 1
            ack = (b"\x10" if rf[0] == 15 else b"\x0d") + rf[1:107]
            signer = OWNER_PRIVATE if self.bad_ack else TARGET_PRIVATE
            ack += signer.sign(domain + ack)
            if self.ack_mutator:
                ack = self.ack_mutator(ack)
            self.switch = self.clock() + 5
            self.expiry = self.switch + struct.unpack_from(">H", rf, 101)[0] / 1000
            if self.drop_ack:
                self.drop_ack -= 1
            else:
                self.schedule(0.01, lambda: self.push(ack))
        elif rf[0] == 1:
            index = struct.unpack_from(">H", rf, 5)[0]
            message, prefix = ota.block_message(c, index)
            assert rf[:-64] == prefix
            ota.verify(OWNER, message, rf[-64:])
            if self.drop_blocks:
                self.drop_blocks -= 1
            else:
                self.received.add(index)
        elif rf[0] == 3:
            assert len(rf) == 153
            assert self.received == set(range(c.total))
            assert rf[1:33] == TARGET and rf[33:65] == c.digest
            assert struct.unpack_from(">I", rf, 65)[0] == c.counter
            ota.verify(OWNER, b"MeshCore/OTA/commit/v2" + rf[1:89], rf[89:])
            if rf[69:89] != struct.pack(">I", self.generation) + self.nonce:
                self.denied_commits += 1
                return
            self.commit_count += 1
        elif rf[0] == 14:
            assert len(rf) == 165
            ota.verify(OWNER, ota.REUPLOAD_DOMAIN + rf[:101], rf[101:])
            assert rf[1:33] == OWNER and rf[33:65] == TARGET and rf[65:97] == c.digest
            if self.drop_reupload:
                self.drop_reupload -= 1
                return
            if not self.prepared or not self.aborted or struct.unpack_from(">I", rf, 97)[0] != self.generation:
                return
            self.local_cache = self.aborted = self.prepared = False
            self.generation += 1
            self.nonce = hashlib.sha256(self.nonce).digest()[:16]
            self.challenge = (self.challenge ^ 0xA5A5A5A5) or 1
            self.received.clear()
            self.admitted = True
            self.reupload_count += 1
        elif rf[0] == 7:
            pass
        else:
            raise AssertionError(f"unexpected RF kind {rf[0]}")


class RelaySerial(FakeSerial):
    """A consumptive direct hop, deduplicating relay and v3 target replies."""
    def __init__(self, clock, c, received=()):
        super().__init__(clock, c, received)
        self.relay_enabled = True
        self.seen_requests, self.seen_replies = set(), set()
        self.forwarded_requests = []
        self.reply_attempt = None
        self.reply_mode = "relay"
        self.install_lifecycle = 8
        self.reply_mutator = None

    def remote(self, wire):
        raw = self.raw_packets[-1]
        width, count = (raw[1] >> 6) + 1, raw[1] & 63
        # Targets hearing the sender cannot consume a nonempty direct path.
        if (not self.relay_enabled or count != 1 or raw[2:2 + width] != RELAY[:width]
                or hashlib.sha256(bytes([12]) + wire).digest() in self.seen_requests):
            return
        self.seen_requests.add(hashlib.sha256(bytes([12]) + wire).digest())
        forwarded = bytes([0x32, (width - 1) << 6]) + wire
        self.forwarded_requests.append(forwarded)
        # The existing firmware unwraps, verifies and echoes BE32 attempts.
        assert wire[0] in (17, 18) and len(wire) <= 171
        self.reply_attempt = struct.unpack_from(">I", wire, 1)[0]
        assert self.reply_attempt
        inner = wire[5:]
        assert wire[0] != 18 or inner[0] == 1
        super().remote(inner)

    def push(self, payload):
        if self.commit_count and payload[0] == 11:
            payload = census(self.candidate, generation=self.generation, lifecycle=self.install_lifecycle,
                             floor=self.candidate.counter, nonce=self.nonce)
        wire = b"\x11" + struct.pack(">I", self.reply_attempt) + payload
        if self.reply_mutator is not None:
            wire = self.reply_mutator(wire)
        # Stock RF logs occur before mesh dedup: a directly heard flood and
        # the later forwarded copy are both available to the host.
        for path in ((b"", RELAY[:1]) if self.reply_mode == "relay" else
                     (b"",) if self.reply_mode == "bypass" else (b"\x99",)):
            if path:
                digest = hashlib.sha256(bytes([12]) + wire).digest()
                if digest in self.seen_replies:
                    continue
                self.seen_replies.add(digest)
            raw = bytes([0x31, len(path)]) + path + wire
            self.rx_packets.append((self.clock(), self.profile, raw, payload))
            self.reply(b"\x88\x08\x40" + raw)


def routed_setup(c=None, received=(), width=1, duty=0.02, reupload=False):
    c = c or candidate()
    clock = Clock()
    stream = RelaySerial(clock, c, received)
    stock = ota.Stock(ota.Frames(stream, clock), OWNER, clock, clock.sleep)
    approved = replace(binding(c), allow_reupload=reupload)
    sender = ota.Sender(stock, approved, c, NORMAL, clock() + 10000, 0, 0, duty,
                        clock, clock.sleep, reupload=reupload, mode="directed", relay=RELAY,
                        path_hash_bytes=width)
    return clock, stream, stock, sender


def setup(c=None, received=(), lease=60000, duty=0.02, reupload_generation=None):
    c = c or candidate()
    clock = Clock()
    serial = FakeSerial(clock, c, received)
    frames = ota.Frames(serial, clock)
    stock = ota.Stock(frames, OWNER, clock, clock.sleep)
    approved = binding(c)
    if reupload_generation is not None:
        approved = replace(approved, reupload_generation=reupload_generation)
    sender = ota.Sender(stock, approved, c, NORMAL, clock() + 10000, 919000,
                        lease, duty, clock, clock.sleep, reupload_generation)
    return clock, serial, stock, sender


class Scratch(unittest.TestCase):
    def setUp(self):
        self.directory = ROOT / ".tmp" / f"stock-companion-test-{os.getpid()}-{self.id().split('.')[-1]}"
        self.directory.parent.mkdir(exist_ok=True)
        self.directory.mkdir(mode=0o700)

    def tearDown(self):
        shutil.rmtree(self.directory)


class PathBindingTests(Scratch):
    def binding_value(self):
        return {"schema": 1, "authorized": True, "serial": "0001",
                "sender_public_key": OWNER.hex(), "target_public_key": TARGET.hex(),
                "stock_version": "1.17.1", "floor": 4, "min_generation": 10,
                "normal_profile": [907525, 62500, 7, 5], "image_kind": "ordinary-app",
                "image_sha256": BINDING.image_hash.hex(), "manifest_hash": BINDING.manifest_hash.hex(),
                "by_path": STOCK_PATH, "id_path": STOCK_ID_PATH, "usb_vid": "10c4", "usb_pid": "ea60",
                "sender_name": "synthetic-stock"}

    @contextmanager
    def metadata(self, selected=STOCK_TTY, actual_id_path=STOCK_ID_PATH, serial="0001", pid="ea60"):
        # All metadata files/symlinks are synthetic, inside the owned source
        # workspace. No /dev, /sys or /run files are read/opened.
        usb = self.directory / "usb"
        usb.mkdir()
        owner = usb / "1-4.2.4"
        owner.mkdir()
        other = usb / "1-4.1"
        other.mkdir()
        for node in (owner, other):
            (node / "idVendor").write_text("10c4")
            (node / "idProduct").write_text(pid)
            (node / "serial").write_text(serial)
        leaf = owner / "1-4.2.4:1.0" / selected.name
        leaf.mkdir(parents=True)
        sys_tty = self.directory / "tty"
        (sys_tty / selected.name).mkdir(parents=True)
        (sys_tty / selected.name / "device").symlink_to(leaf)
        udev = self.directory / "udev"
        udev.mkdir()
        rdev = os.makedev(188, int(selected.name.removeprefix("ttyUSB")))
        (udev / f"c188:{os.minor(rdev)}").write_text(
            f"E:ID_PATH={actual_id_path}\nE:ID_SERIAL_SHORT={serial}\n"
            f"E:ID_VENDOR_ID=10c4\nE:ID_MODEL_ID={pid}\n")
        original_resolve, original_stat, original_link = Path.resolve, Path.stat, Path.is_symlink
        def resolve(path, *args, **kwargs):
            if path == Path(STOCK_ID):
                raise AssertionError("colliding by-id must NEVER be resolved")
            if path == Path(STOCK_PATH):
                return selected
            return original_resolve(path, *args, **kwargs)
        def file_stat(path, *args, **kwargs):
            if path in (STOCK_TTY, OLD_TTY):
                self.assertEqual(path, selected)
                return SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=rdev)
            if path.name in ("idVendor", "idProduct") and not path.is_relative_to(self.directory):
                return SimpleNamespace(st_mode=0)
            return original_stat(path, *args, **kwargs)
        def is_link(path):
            if path == Path(STOCK_ID):
                raise AssertionError("colliding by-id must NEVER be inspected")
            return True if path == Path(STOCK_PATH) else original_link(path)
        with patch.object(Path, "resolve", resolve), patch.object(Path, "stat", file_stat), patch.object(Path, "is_symlink", is_link):
            yield {"sys_devices": usb, "sys_tty": sys_tty, "udev_data": udev,
                   "by_path": STOCK_PATH, "id_path": STOCK_ID_PATH, "usb_vid": 0x10C4, "usb_pid": 0xEA60}

    def test_duplicate_serial_uses_only_explicit_physical_path_never_colliding_by_id(self):
        with self.metadata() as kwargs:
            selection = ota.resolve_stock("0001", STOCK_ID, **kwargs)
        self.assertEqual(selection.tty, STOCK_TTY)
        self.assertEqual(selection.anchor, Path(STOCK_PATH))
        self.assertEqual(selection.id_path, STOCK_ID_PATH)
        self.assertEqual(selection.device_id, os.makedev(188, 1))

    def test_wrong_old_physical_path_rejected_without_opening_either_tty(self):
        with self.metadata(selected=OLD_TTY, actual_id_path="pci-OLD-UNAPPROVED") as kwargs:
            with self.assertRaisesRegex(ota.Error, "ID_PATH"):
                ota.resolve_stock("0001", STOCK_ID, **kwargs)


    def test_bound_usb_serial_vid_pid_and_id_path_are_all_checked(self):
        for field, wrong in (("id_path", "pci-WRONG"), ("usb_vid", 0x239A), ("usb_pid", 0xEA61)):
            directory = self.directory / field
            directory.mkdir()
            original_directory = self.directory
            self.directory = directory
            try:
                with self.metadata() as kwargs:
                    kwargs[field] = wrong
                    with self.subTest(field=field), self.assertRaises(ota.Error):
                        ota.resolve_stock("0001", STOCK_ID, **kwargs)
            finally:
                self.directory = original_directory
        with self.metadata(serial="0002") as kwargs:
            with self.assertRaisesRegex(ota.Error, "serial"):
                ota.resolve_stock("0001", STOCK_ID, **kwargs)

    def test_root_file_and_cli_both_pin_anchor_and_full_key_before_selection(self):
        value = self.binding_value()
        path = self.directory / "binding.json"
        ota.private_write(path, value)
        approved = ota.Binding.load(path, "0001", OWNER, TARGET, STOCK_PATH)
        self.assertEqual(approved.by_path, STOCK_PATH)
        self.assertEqual((approved.usb_vid, approved.usb_pid), (0x10C4, 0xEA60))
        for anchor, key in ((None, OWNER), (STOCK_PATH + "-wrong", OWNER), (STOCK_PATH, TARGET)):
            with self.assertRaises(ota.Error):
                ota.Binding.load(path, "0001", key, TARGET, anchor)

    def test_post_open_recheck_detects_node_or_anchor_race_before_protocol_actions(self):
        selected = ota.PortSelection(Path(STOCK_PATH), STOCK_TTY, os.makedev(188, 1), Path("/synthetic/usb"), STOCK_ID_PATH)
        stream = SimpleNamespace(fileno=lambda: 12345)
        info = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=selected.device_id)
        with patch.object(ota.os, "fstat", return_value=info):
            ota.check_open_selection(stream, selected, selected)
            with self.assertRaises(ota.Error):
                ota.check_open_selection(stream, selected, replace(selected, tty=OLD_TTY))
        with patch.object(ota.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(188, 0))):
            with self.assertRaisesRegex(ota.Error, "no radio/sign/RF"):
                ota.check_open_selection(stream, selected, selected)

    def test_optional_public_name_guard_requires_cli_agreement(self):
        value = self.binding_value()
        path = self.directory / "binding.json"
        ota.private_write(path, value)
        self.assertEqual(ota.Binding.load(path, "0001", OWNER, TARGET, STOCK_PATH, "synthetic-stock").sender_name, "synthetic-stock")
        with self.assertRaisesRegex(ota.Error, "sender_name"):
            ota.Binding.load(path, "0001", OWNER, TARGET, STOCK_PATH, "unapproved")
        for i, name in enumerate(("", "x" * 32, "synthetic\x00stock", 1)):
            invalid = self.directory / f"invalid-{i}.json"
            ota.private_write(invalid, dict(value, sender_name=name))
            with self.subTest(name=name), self.assertRaisesRegex(ota.Error, "sender_name"):
                ota.Binding.load(invalid, "0001", OWNER, TARGET, STOCK_PATH)

    def test_explicit_adapter_opens_authorized_anchor_not_resolved_tty_and_settles_before_use(self):
        selected = ota.PortSelection(Path(STOCK_PATH), STOCK_TTY, os.makedev(188, 1), Path("/synthetic/usb"), STOCK_ID_PATH)
        events = []
        stream = SimpleNamespace(port=None, dtr=True, rts=True, fileno=lambda: 12345,
                                 close=lambda: events.append("close"))
        def opened():
            self.assertEqual((stream.port, stream.dtr, stream.rts), (STOCK_PATH, False, False))
            events.append("open")
        stream.open = opened
        factory = Mock(return_value=stream)
        approved = replace(BINDING, serial="0001", by_path=STOCK_PATH, id_path=STOCK_ID_PATH,
                           usb_vid=0x10C4, usb_pid=0xEA60, sender_name="synthetic-stock")
        info = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=selected.device_id)
        with patch.object(ota, "resolve_stock", return_value=selected) as resolve, \
                patch.object(ota.os, "fstat", return_value=info), patch.object(ota.fcntl, "flock"):
            with ota.validated_stock_uart(approved, STOCK_ID, factory, lambda seconds: events.append(seconds)) as uart:
                self.assertIs(uart, stream)
                self.assertEqual(events, ["open", 2.0])
            self.assertEqual(resolve.call_count, 3)
            self.assertEqual(resolve.call_args.kwargs["by_path"], STOCK_PATH)
        factory.assert_called_once_with(port=None, baudrate=115200, timeout=0.1,
                                        write_timeout=2.0, exclusive=True)
        self.assertEqual(events, ["open", 2.0, "close"])

    def test_stock_nrf_dtr_is_selected_before_open_without_reset_or_rts(self):
        selected = ota.PortSelection(Path(STOCK_PATH), STOCK_TTY, os.makedev(188, 1),
                                     Path("/synthetic/usb"), STOCK_ID_PATH)
        events = []
        stream = SimpleNamespace(port=None, dtr=False, rts=True, fileno=lambda: 12345,
                                 close=lambda: events.append("close"))
        def opened():
            self.assertEqual((stream.dtr, stream.rts), (True, False))
            events.append("open")
        stream.open = opened
        with patch.object(ota, "resolve_stock", return_value=selected), \
                patch.object(ota.os, "fstat", return_value=SimpleNamespace(
                    st_mode=stat.S_IFCHR, st_rdev=selected.device_id)), \
                patch.object(ota.fcntl, "flock"):
            with ota.validated_stock_uart(BINDING, STOCK_ID, Mock(return_value=stream),
                                          lambda seconds: None, dtr=True):
                self.assertEqual(events, ["open"])
        self.assertEqual(events, ["open", "close"])

    def test_adapter_refuses_invalid_binding_before_constructor_and_closes_on_settle_race(self):
        factory = Mock()
        with patch.object(ota, "resolve_stock", side_effect=ota.Error("unauthorized")):
            with self.assertRaisesRegex(ota.Error, "unauthorized"):
                with ota.validated_stock_uart(BINDING, STOCK_ID, factory):
                    self.fail("invalid transport yielded")
        factory.assert_not_called()
        selected = ota.PortSelection(Path(STOCK_PATH), STOCK_TTY, os.makedev(188, 1), Path("/synthetic/usb"), STOCK_ID_PATH)
        stream = SimpleNamespace(open=Mock(), close=Mock(), fileno=lambda: 12345)
        factory.return_value = stream
        info = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=selected.device_id)
        with patch.object(ota, "resolve_stock", side_effect=[selected, selected, replace(selected, tty=OLD_TTY)]), \
                patch.object(ota.os, "fstat", return_value=info), patch.object(ota.fcntl, "flock"), \
                self.assertRaisesRegex(ota.Error, "changed"):
            with ota.validated_stock_uart(BINDING, STOCK_ID, factory, lambda seconds: None):
                self.fail("settling anchor race yielded")
        stream.close.assert_called_once()

    def inspect_setup(self, directory):
        path = self.directory / "binding.json"
        if not path.exists():
            ota.private_write(path, self.binding_value())
        argv = ["inspect", "--serial", "0001", "--by-id", STOCK_ID, "--by-path", STOCK_PATH,
                "--sender-key", OWNER.hex(), "--sender-name", "synthetic-stock", "--target", TARGET.hex(),
                "--binding", str(path), "--artifacts", str(directory)]
        clock, stream, _, _ = setup()
        stream.profile = (907525, 250000, 7, 8, 1)
        return argv, clock, stream

    def test_inspect_only_starts_queries_and_publishes_redacted_public_summary_without_radio_guard(self):
        directory = self.directory / "inspect"
        argv, clock, stream = self.inspect_setup(directory)
        stream.version = b"v1.17.1-d929643"
        @contextmanager
        def uart(*args, **kwargs):
            yield stream
        frames = ota.Frames
        output = io.StringIO()
        with patch.object(ota, "validated_stock_uart", uart), \
                patch.object(ota, "Frames", side_effect=lambda port: frames(port, clock)), \
                patch.object(ota, "radio_guard", side_effect=AssertionError("read-only must not mutate radio")), \
                redirect_stdout(output), redirect_stderr(output):
            ota.main(argv)
        result = ota.private_read(directory / "result.json")
        self.assertEqual([command[0] for command in stream.commands], [1, 22])
        self.assertEqual(result["name"], "synthetic-stock")
        self.assertEqual(result["version"], "v1.17.1-d929643")
        self.assertEqual(result["radio_profile"], [907525, 250000, 7, 8, 1])
        self.assertFalse(result["hardware_readiness_confirmed"])
        self.assertEqual(sorted(path.name for path in directory.iterdir()), ["result.json"])
        text = output.getvalue() + json.dumps(result)
        for secret in ("GPS-HIDE", "99887766", "4750532d48494445"):
            self.assertNotIn(secret, text)

    def test_inspect_missing_or_mismatched_reply_produces_no_success_artifact_or_mutation(self):
        frames = ota.Frames
        for fault in ("missing", "key", "name", "version"):
            directory = self.directory / fault
            argv, clock, stream = self.inspect_setup(directory)
            if fault == "missing":
                stream.drop_start = 2
            elif fault == "key":
                stream.wrong_identity = True
            elif fault == "name":
                stream.name = b"unapproved"
            else:
                stream.version = b"v1.17.0"
            @contextmanager
            def uart(*args, **kwargs):
                yield stream
            with self.subTest(fault=fault), patch.object(ota, "validated_stock_uart", uart), \
                    patch.object(ota, "Frames", side_effect=lambda port: frames(port, clock)), \
                    patch.object(ota, "radio_guard", side_effect=AssertionError("unexpected radio guard")), \
                    self.assertRaises(ota.Error):
                ota.main(argv)
            self.assertFalse(any(command[0] in (11, 33, 34, 35, 65) for command in stream.commands))
            self.assertFalse(list(directory.iterdir()))


class ResumeTests(Scratch):
    def original_attempt(self):
        original = candidate(336)
        canonical = original.canonical[:45] + struct.pack(">I", 2) + original.canonical[49:]
        c = ota.Candidate.build(canonical, original.image, 1)
        clock, stream, stock, _ = routed_setup(c, received={0, 2})
        approved = replace(binding(c), floor=1, min_generation=2)
        stream.floor, stream.generation = 1, 2
        sender = ota.Sender(stock, approved, c, NORMAL, clock() + 10000, 0, 0, clock=clock,
                            sleep=clock.sleep, mode="directed", relay=RELAY)
        observed = sender.authorize()
        return clock, stream, stock, sender, sender.attempt_receipt(observed)

    def resumed(self, clock, stock, original, **options):
        return ota.Sender(stock, original.binding, original.candidate, NORMAL, clock() + 10000,
                          0, 0, clock=clock, sleep=clock.sleep, mode="directed", relay=RELAY, **options)

    def original_radio(self, original, stock):
        b = original.binding
        return {"schema": 1, "serial": b.serial, "sender_public_key": b.sender.hex(),
                "profile": list(original.original), "by_path": b.by_path, "id_path": b.id_path,
                "usb_vid": b.usb_vid, "usb_pid": b.usb_pid, "tx_power_dbm": stock.tx_power}

    def test_legacy_host_capture_observes_existing_receiving_nonce_without_admission(self):
        clock, stream, stock, original, _ = self.original_attempt()
        before, nonce, generation = len(stream.rf_packets), stream.nonce, stream.generation
        events = []
        capture = self.resumed(clock, stock, original, event_callback=events.append)
        receipt = capture.capture_resume(self.original_radio(original, stock), 2, min_received=2)
        self.assertEqual(len(stream.rf_packets) - before, 1)
        self.assertEqual(stream.rf_packets[-1][2][5], 10)
        self.assertEqual((stream.generation, stream.nonce), (generation, nonce))
        self.assertEqual(receipt["begin_nonce"], nonce.hex())
        self.assertEqual(receipt["received_blocks"], 2)
        evidence = next(event for event in events if event["event"] == "resume_capture_receiving_unsigned")
        self.assertFalse(evidence["status_authenticated"])
        self.assertFalse(evidence["historical_nonce_verified"])
        resumed = self.resumed(clock, stock, original, duty=0.8)
        resumed.deploy(300, resume_receipt=receipt)
        self.assertTrue(all(payload[5] not in (8, 14) for _, _, payload in stream.rf_packets[before:]))
        self.assertEqual(stream.commit_count, 1)
        self.assertEqual(stream.nonce, nonce)

    def test_capture_requires_original_profile_and_explicit_generation_before_poll(self):
        clock, stream, stock, original, _ = self.original_attempt()
        radio = self.original_radio(original, stock)
        for field, value in (("profile", [*NORMAL[:4], 0]), ("sender_public_key", TARGET.hex()),
                             ("serial", "other"), ("by_path", STOCK_PATH), ("tx_power_dbm", 3)):
            before = len(stream.commands)
            capture = self.resumed(clock, stock, original)
            with self.subTest(field=field), self.assertRaises(ota.Error):
                capture.capture_resume({**radio, field: value}, 2, min_received=2)
            self.assertEqual(len(stream.commands), before)
        for generation, received in ((1, 2), (True, 2), (2, 5), (2, -1)):
            before = len(stream.commands)
            capture = self.resumed(clock, stock, original)
            with self.assertRaises(ota.Error):
                capture.capture_resume(radio, generation, min_received=received)
            self.assertEqual(len(stream.commands), before)

    def test_capture_rejects_changed_generation_progress_terminal_or_unrouted_status(self):
        for fault in ("generation", "regression", "ready", "aborted", "bypass"):
            clock, stream, stock, original, _ = self.original_attempt()
            if fault == "generation":
                stream.generation = 3
            elif fault == "regression":
                stream.received = {0}
            elif fault == "ready":
                stream.received = {0, 1, 2, 3}
            elif fault == "aborted":
                stream.prepared = stream.aborted = True
            else:
                stream.reply_mode = "bypass"
            before = len(stream.rf_packets)
            capture = self.resumed(clock, stock, original)
            with self.subTest(fault=fault), self.assertRaises(ota.Error):
                capture.capture_resume(self.original_radio(original, stock), 2, min_received=2)
            self.assertEqual(len(stream.rf_packets) - before, 1)
            self.assertEqual(stream.rf_packets[-1][2][5], 10)
            self.assertFalse(stream.commit_count)

    def test_eighty_percent_resume_preserves_progress_attempt_and_single_commit(self):
        clock, stream, stock, original, receipt = self.original_attempt()
        before, nonce, generation = len(stream.rf_packets), stream.nonce, stream.generation
        stream.drop_blocks = 1
        events = []
        resumed = self.resumed(clock, stock, original, duty=0.8, event_callback=events.append)
        with ota.radio_guard(stock, original.binding, self.directory, mode="directed"):
            result = resumed.deploy(300, resume_receipt=receipt)
        wire = [payload for _, _, payload in stream.rf_packets[before:]]
        self.assertTrue(all(payload[5] not in (8, 14, 12, 15) for payload in wire))
        blocks = [struct.unpack_from(">H", payload, 10)[0] for payload in wire if payload[5] == 1]
        self.assertEqual(blocks, [1, 3, 1])
        repairs = [payload for payload in wire if payload[5] == 1 and payload[10:12] == b"\x00\x01"]
        self.assertEqual(repairs[0][5:], repairs[1][5:])
        self.assertNotEqual(repairs[0][:5], repairs[1][:5])
        self.assertEqual((stream.generation, stream.nonce), (generation, nonce))
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["begin_nonce"], receipt["begin_nonce"])
        self.assertEqual(result["counter"], 2)
        self.assertEqual(stream.commit_count, 1)
        self.assertFalse(result["status_authenticated"])
        self.assertFalse(result["installation_confirmed"])
        self.assertEqual(stream.profile, NORMAL)
        self.assertFalse(any(command[0] == 11 for command in stream.commands))
        self.assertTrue(ota.private_read(self.directory / "radio-unchanged.json")["normal_profile_unchanged"])
        matched = [event for event in events if event["event"] == "resume_matched_unsigned"]
        self.assertEqual(matched[0]["received"], 2)
        tx = [event for event in events if event["event"] == "rf_tx_request"]
        self.assertTrue(all(event["normal_duty_percent"] == 80 for event in tx))
        self.assertEqual(receipt["normal_duty_percent"], 2)

    def test_resume_source_static_mismatches_refuse_before_rf_or_signing(self):
        mutations = {
            "sender_public_key": TARGET.hex(), "target_public_key": OWNER.hex(),
            "manifest_hash": "ff" * 32, "image_sha256": "ff" * 32, "image_size": 340,
            "total_blocks": 5, "counter": 3, "floor": 0, "min_generation": 1,
            "normal_profile": [919000, *NORMAL[1:4]], "sender_profile": [*NORMAL[:4], 0],
            "tx_power_dbm": 3, "relay_public_key": TARGET.hex(), "request_path": "99",
            "path_hash_bytes": 2, "reply_path": "99", "by_path": STOCK_PATH,
            "id_path": STOCK_ID_PATH, "usb_vid": 0x239A, "usb_pid": 0x8029,
            "sender_name": "different", "schema": 2, "outcome": "ready-observed-unsigned",
            "begin_nonce": "00" * 16, "generation": 1, "received_blocks": 5,
            "bitmap": "ff" * 16, "normal_duty_percent": float("nan"),
            "status_authenticated": True, "installation_confirmed": True,
        }
        clock, stream, stock, original, receipt = self.original_attempt()
        for field, value in mutations.items():
            before = len(stream.commands)
            resumed = self.resumed(clock, stock, original, duty=0.8)
            with self.subTest(field=field), self.assertRaises(ota.Error):
                resumed.upload(resume_receipt={**receipt, field: value})
            self.assertFalse(any(command[0] in (33, 34, 35, 65, 11) for command in stream.commands[before:]))

    def test_fresh_nonce_generation_and_progress_mismatch_never_authorize_or_send_data(self):
        for fault in ("nonce", "generation", "floor", "received", "bitmap"):
            clock, stream, stock, original, receipt = self.original_attempt()
            if fault == "nonce":
                stream.nonce = bytes([7]) * 16
            elif fault == "generation":
                stream.generation += 1
            elif fault == "floor":
                stream.floor = 0
            elif fault == "received":
                stream.received = {0}
            else:
                stream.received = {0, 1}
            before = len(stream.rf_packets)
            resumed = self.resumed(clock, stock, original, duty=0.8)
            with self.subTest(fault=fault), self.assertRaises(ota.Error):
                resumed.deploy(300, resume_receipt=receipt)
            self.assertTrue(all(payload[5] == 10 for _, _, payload in stream.rf_packets[before:]))
            self.assertEqual(stream.commit_count, 0)

    def test_resume_missing_routed_census_never_falls_back_to_admission_or_direct(self):
        clock, stream, stock, original, receipt = self.original_attempt()
        stream.reply_mode = "bypass"
        before = len(stream.rf_packets)
        resumed = self.resumed(clock, stock, original, duty=0.8)
        with self.assertRaises(ota.NoCensus):
            resumed.upload(resume_receipt=receipt)
        payloads = [payload for _, _, payload in stream.rf_packets[before:]]
        self.assertEqual(len(payloads), 3)
        self.assertTrue(all(payload[5] == 10 for payload in payloads))
        self.assertEqual(len({payload[:5] for payload in payloads}), 3)
        self.assertFalse(stream.commit_count)

    def test_receipt_is_published_only_after_fresh_verified_resume_and_is_frozen(self):
        clock, stream, stock, original, receipt = self.original_attempt()
        observed = []
        resumed = self.resumed(clock, stock, original, duty=0.8, attempt_callback=observed.append)
        resumed.upload(resume_receipt=receipt)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["begin_nonce"], receipt["begin_nonce"])
        self.assertEqual(observed[0]["generation"], 2)
        self.assertEqual(observed[0]["received_blocks"], 2)
        self.assertEqual(observed[0]["normal_duty_percent"], 80)
        self.assertEqual(receipt["received_blocks"], 2)
        self.assertFalse(stream.commit_count)

    def test_resume_is_not_reupload_and_cannot_be_selected_for_inspect_or_commit(self):
        base = ["--serial", BINDING.serial, "--by-id", "/dev/serial/by-id/NOT_OPENED",
                "--sender-key", OWNER.hex(), "--target", TARGET.hex(),
                "--binding", "NOT_READ", "--artifacts", "NOT_CREATED", "--resume-receipt", "NOT_READ"]
        options = (["inspect"], ["commit", "--mode", "directed"], ["deploy"],
                   ["deploy", "--mode", "directed", "--reupload"],
                   ["deploy", "--mode", "directed", "--reupload-generation", "2"])
        for flags in options:
            with self.subTest(flags=flags), patch.object(ota.Binding, "load") as load, \
                    patch.object(ota, "validated_stock_uart") as uart, self.assertRaises(ota.Error):
                ota.main(flags + base)
            load.assert_not_called()
            uart.assert_not_called()

    def test_cli_resume_persists_source_and_new_receipt_without_overwriting_old_artifacts(self):
        clock, stream, stock, original, receipt = self.original_attempt()
        path = self.directory / "binding.json"
        b = original.binding
        ota.private_write(path, {"schema": 1, "serial": b.serial,
                                 "sender_public_key": OWNER.hex(), "target_public_key": TARGET.hex(),
                                 "floor": 1, "min_generation": 2, "normal_profile": list(NORMAL[:4])})
        image, source = self.directory / "ordinary.bin", self.directory / "original-attempt.json"
        image.write_bytes(original.candidate.image)
        ota.private_write(source, receipt)
        source_bytes = source.read_bytes()
        directory = self.directory / "resume"
        argv = ["deploy", "--serial", b.serial, "--by-id", "/dev/serial/by-id/NOT_OPENED",
                "--sender-key", OWNER.hex(), "--target", TARGET.hex(), "--binding", str(path),
                "--artifacts", str(directory), "--image", str(image), "--board", "xiao_nrf52840",
                "--role-id", "0", "--counter", "2", "--mode", "directed", "--relay-key", RELAY.hex(),
                "--resume-receipt", str(source), "--normal-duty-percent", "80"]
        @contextmanager
        def uart(*args, **kwargs):
            yield stream
        frames, stock_cls, sender_cls = ota.Frames, ota.Stock, ota.Sender
        before = len(stream.rf_packets)
        with patch.object(ota, "validated_stock_uart", uart), \
                patch.object(ota, "Frames", side_effect=lambda port: frames(port, clock)), \
                patch.object(ota, "Stock", side_effect=lambda f, key, **kw: stock_cls(f, key, clock, clock.sleep, **kw)), \
                patch.object(ota, "Sender", side_effect=lambda *a, **kw: sender_cls(*a, clock=clock, sleep=clock.sleep, **kw)), \
                patch.object(ota.time, "monotonic", clock), redirect_stdout(io.StringIO()):
            ota.main(argv)
        reference = ota.private_read(directory / "resume-source.json")
        self.assertEqual(reference["source_receipt"], str(source.resolve()))
        self.assertEqual(reference["receipt"], receipt)
        canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(reference["canonical_json_sha256"], hashlib.sha256(canonical).hexdigest())
        self.assertEqual(source.read_bytes(), source_bytes)
        new = ota.private_read(directory / "attempt-receipt.json")
        self.assertEqual((new["generation"], new["begin_nonce"], new["normal_duty_percent"]),
                         (2, receipt["begin_nonce"], 80))
        self.assertEqual(ota.private_read(directory / "result.json")["outcome"], "native-installed-reported-unsigned")
        self.assertTrue(all(payload[5] not in (8, 14) for _, _, payload in stream.rf_packets[before:]))
        self.assertFalse(any(command[0] == 11 for command in stream.commands))


class DirectedTests(Scratch):
    def test_retry_and_path_limits_reject_malformed_nested_and_exhausted_attempts(self):
        report = census(candidate())
        for wire in (b"\x11", b"\x11" + bytes(4) + report,
                     b"\x11\x00\x00\x00\x01" + report[:-1],
                     b"\x12\x00\x00\x00\x01" + report,
                     b"\x11\x00\x00\x00\x01" + ota.retry_frame(report, 2)):
            with self.subTest(wire=wire[:6].hex()):
                self.assertIsNone(ota.raw_rx(b"\x88\x08\x40\x31\x01" + RELAY[:1] + wire))
        for inner in (bytes([1]) + bytes(70), bytes([1]) + bytes(155),
                      bytes([12]) + bytes(170), ota.retry_frame(report, 2)):
            with self.assertRaises(ota.Error):
                ota.retry_frame(inner, 1)
        with self.assertRaises(ota.Error):
            ota.packet(bytes(169), bytes(4))
        for width, path in ((4, b""), (2, bytes(3)), (1, bytes(64)), (3, bytes(66))):
            with self.assertRaises(ota.Error):
                ota.packet(b"\x07", path, width)
        _, stream, _, sender = routed_setup()
        sender.next_attempt = 0xFFFFFFFF
        poll = b"\x0a" + TARGET + sender.candidate.digest + b"\x00\x00"
        sender.send(poll)
        with self.assertRaisesRegex(ota.Error, "exhausted"):
            sender.send(poll)
        self.assertEqual(len(stream.raw_packets), 1)
        self.assertEqual(stream.raw_packets[0][3:8], b"\x11\xff\xff\xff\xff")

    def test_cli_separate_role1_upload_and_commit_share_manifest_and_route_receipt(self):
        import ota_uploader as native
        original = candidate()
        canonical = native.deploy_manifest(original.image, "xiao_nrf52840_sense", 1, 5, None)
        c = ota.Candidate.build(canonical, original.image, 4, board="xiao_nrf52840_sense", role_id=1, counter=5)
        clock, stream, _, _ = routed_setup(c)
        path = self.directory / "binding.json"
        ota.private_write(path, {"schema": 1, "serial": BINDING.serial,
                                 "sender_public_key": OWNER.hex(), "target_public_key": TARGET.hex(),
                                 "floor": 4, "min_generation": 10, "normal_profile": list(NORMAL[:4])})
        image, manifest = self.directory / "ordinary.bin", self.directory / "manifest.bin"
        image.write_bytes(c.image)
        manifest.write_bytes(c.canonical)
        common = ["--serial", BINDING.serial, "--by-id", "/dev/serial/by-id/NOT_OPENED",
                  "--sender-key", OWNER.hex(), "--target", TARGET.hex(), "--binding", str(path),
                  "--image", str(image), "--manifest", str(manifest), "--board", "xiao_nrf52840_sense",
                  "--role-id", "1", "--counter", "5", "--mode", "directed", "--relay-key", RELAY.hex()]
        @contextmanager
        def uart(*args, **kwargs):
            yield stream
        frames, stock, sender = ota.Frames, ota.Stock, ota.Sender
        with patch.object(ota, "validated_stock_uart", uart), \
                patch.object(ota, "Frames", side_effect=lambda port: frames(port, clock)), \
                patch.object(ota, "Stock", side_effect=lambda f, key, **kw: stock(f, key, clock, clock.sleep, **kw)), \
                patch.object(ota, "Sender", side_effect=lambda *a, **kw: sender(*a, clock=clock, sleep=clock.sleep, **kw)), \
                patch.object(ota.time, "monotonic", clock), redirect_stdout(io.StringIO()):
            ota.main(["upload"] + common + ["--artifacts", str(self.directory / "upload")])
            self.assertEqual(stream.commit_count, 0)
            receipt = self.directory / "upload" / "result.json"
            ota.main(["commit"] + common + ["--artifacts", str(self.directory / "commit"), "--ready-receipt", str(receipt)])
        self.assertEqual(stream.commit_count, 1)
        self.assertEqual(ota.private_read(receipt)["manifest_hash"], c.digest.hex())
        self.assertFalse(ota.private_read(self.directory / "commit" / "result.json")["installation_confirmed"])
        self.assertFalse(any(command[0] == 11 for command in stream.commands))

    def test_cli_directed_deploy_generates_repeater_manifest_and_uses_bound_transport(self):
        import ota_uploader as native
        original = candidate()
        canonical = native.deploy_manifest(original.image, "xiao_nrf52840_sense", 1, 5, None)
        c = ota.Candidate.build(canonical, original.image, 4, board="xiao_nrf52840_sense", role_id=1, counter=5)
        clock, stream, _, _ = routed_setup(c)
        path = self.directory / "binding.json"
        ota.private_write(path, {"schema": 1, "serial": BINDING.serial,
                                 "sender_public_key": OWNER.hex(), "target_public_key": TARGET.hex(),
                                 "floor": 4, "min_generation": 10, "normal_profile": list(NORMAL[:4])})
        image = self.directory / "ordinary.bin"
        image.write_bytes(c.image)
        directory = self.directory / "run"
        argv = ["deploy", "--serial", BINDING.serial, "--by-id", "/dev/serial/by-id/NOT_OPENED",
                "--sender-key", OWNER.hex(), "--target", TARGET.hex(), "--binding", str(path),
                "--artifacts", str(directory), "--image", str(image),
                "--board", "xiao_nrf52840_sense", "--role-id", "1", "--counter", "5",
                "--mode", "directed", "--relay-key", RELAY.hex(), "--path-hash-bytes", "3",
                "--routed-retry"]
        @contextmanager
        def uart(*args, **kwargs):
            yield stream
        frames, stock, sender = ota.Frames, ota.Stock, ota.Sender
        output = io.StringIO()
        with patch.object(ota, "validated_stock_uart", uart), \
                patch.object(ota, "Frames", side_effect=lambda port: frames(port, clock)), \
                patch.object(ota, "Stock", side_effect=lambda f, key, **kw: stock(f, key, clock, clock.sleep, **kw)), \
                patch.object(ota, "Sender", side_effect=lambda *a, **kw: sender(*a, clock=clock, sleep=clock.sleep, **kw)), \
                patch.object(ota.time, "monotonic", clock), redirect_stdout(output):
            ota.main(argv)
        result = ota.private_read(directory / "result.json")
        self.assertEqual(result["manifest_hash"], c.digest.hex())
        self.assertEqual(result["outcome"], "native-installed-reported-unsigned")
        self.assertFalse(result["installation_confirmed"])
        self.assertEqual(stream.commit_count, 1)
        self.assertTrue(ota.private_read(directory / "radio-unchanged.json")["normal_profile_unchanged"])
        self.assertFalse(any(command[0] == 11 for command in stream.commands))

    def test_one_hop_deploy_all_hash_widths_preserves_normal_and_unsigned_install(self):
        for width in (1, 2, 3):
            _, stream, _, sender = routed_setup(width=width)
            events = []
            sender.event_callback = events.append
            result = sender.deploy(300)
            self.assertEqual(result["outcome"], "native-installed-reported-unsigned")
            self.assertEqual(result["relay_public_key"], RELAY.hex())
            self.assertEqual(result["request_path"], RELAY[:width].hex())
            self.assertEqual(result["reply_path"], RELAY[:1].hex())
            self.assertEqual(result["confirmed_floor"], sender.candidate.counter)
            self.assertFalse(result["status_authenticated"])
            self.assertFalse(result["installation_confirmed"])
            self.assertEqual(stream.commit_count, 1)
            self.assertEqual(stream.profile, NORMAL)
            self.assertFalse(any(command[0] == 11 for command in stream.commands))
            self.assertFalse(stream.tokens)
            attempts = []
            for raw in stream.raw_packets:
                self.assertEqual(raw[:2], bytes([0x32, ((width - 1) << 6) | 1]))
                self.assertEqual(raw[2:2 + width], RELAY[:width])
                wire = raw[2 + width:]
                attempts.append(struct.unpack_from(">I", wire, 1)[0])
                self.assertNotIn(wire[5], (12, 15))
                if wire[5] == 8:
                    self.assertEqual(len(raw) + 2, 173 + width)
                self.assertLessEqual(len(raw) + 2, ota.MAX_FRAME)
            self.assertEqual(len(attempts), len(set(attempts)))
            self.assertTrue(all(b == a + 1 for a, b in zip(attempts, attempts[1:])))
            self.assertTrue(all(command[1] == 250 for command in stream.commands if command[0] == 65))
            self.assertTrue(all(raw[1] & 63 == 0 for raw in stream.forwarded_requests))
            evidence = [event for event in events if event["event"] == "rf_reply_route"]
            self.assertTrue(any(event["selected_relay_match"] for event in evidence))
            self.assertTrue(any(not event["selected_relay_match"] and event["path"] == "" for event in evidence))

    def test_attempt_diverse_poll_and_block_repair_pass_relay_dedup(self):
        _, stream, _, sender = routed_setup()
        stream.drop_census = stream.drop_blocks = 1
        sender.upload()
        payloads = [raw[3:] for raw in stream.raw_packets]
        polls = [wire for wire in payloads if wire[5] == 10]
        blocks = [wire for wire in payloads if wire[5] == 1]
        repaired = [wire for wire in blocks if wire[10:12] == b"\x00\x00"]
        self.assertGreaterEqual(len(polls), 2)
        self.assertEqual(len(repaired), 2)
        self.assertEqual(repaired[0][5:], repaired[1][5:])
        self.assertNotEqual(repaired[0][:5], repaired[1][:5])
        self.assertTrue(all(wire[0] == 18 for wire in blocks))
        self.assertEqual(len(stream.seen_requests), len(payloads))
        self.assertEqual(stream.received, {0, 1})
        self.assertEqual(stream.commit_count, 0)

    def test_missing_selected_relay_cannot_deliver_even_when_target_hears_sender(self):
        _, stream, _, sender = routed_setup()
        stream.relay_enabled = False
        with self.assertRaisesRegex(ota.Error, "did not admit"):
            sender.upload()
        self.assertFalse(stream.admitted)
        self.assertFalse(stream.forwarded_requests)
        self.assertTrue(all(raw[1] & 63 == 1 and raw[2:3] == RELAY[:1] for raw in stream.raw_packets))
        self.assertFalse(any(raw[8] in (1, 3) for raw in stream.raw_packets))
        self.assertFalse(any(command[0] == 11 for command in stream.commands))

    def test_only_selected_relay_return_trail_is_accepted(self):
        for mode in ("bypass", "wrong"):
            _, stream, _, sender = routed_setup()
            stream.reply_mode = mode
            with self.subTest(mode=mode), self.assertRaisesRegex(ota.Error, "did not admit"):
                sender.upload()
            self.assertTrue(stream.admitted)
            self.assertEqual(stream.received, set())
            self.assertIsNone(sender.generation)
            self.assertFalse(stream.commit_count)

    def test_return_attempt_must_match_latest_poll_not_unwrapped_or_prior_attempt(self):
        for mutation in (lambda wire: wire[5:],
                         lambda wire: wire[:1] + struct.pack(">I", struct.unpack_from(">I", wire, 1)[0] - 1) + wire[5:]):
            _, stream, _, sender = routed_setup()
            sender.next_attempt = 100
            stream.reply_mutator = mutation
            with self.assertRaisesRegex(ota.Error, "did not admit"):
                sender.upload()
            self.assertIsNone(sender.begin_nonce)
            self.assertFalse(stream.received)

    def test_transport_options_are_fail_closed_before_binding_or_uart(self):
        base = ["deploy", "--serial", BINDING.serial, "--by-id", "/dev/serial/by-id/NOT_OPENED",
                "--sender-key", OWNER.hex(), "--target", TARGET.hex(),
                "--binding", "NOT_READ", "--artifacts", "NOT_CREATED"]
        options = (
            ["--mode", "directed"],
            ["--mode", "directed", "--relay-key", RELAY.hex(), "--frequency-khz", "919000"],
            ["--mode", "directed", "--relay-key", RELAY.hex(), "--lease-ms", "60000"],
            ["--mode", "directed", "--relay-key", RELAY.hex(), "--channel", "0"],
            ["--mode", "directed", "--relay-key", RELAY.hex(), "--no-routed-retry"],
            ["--relay-key", RELAY.hex(), "--frequency-khz", "919000"],
        )
        for flags in options:
            with self.subTest(flags=flags), patch.object(ota.Binding, "load") as load, \
                    patch.object(ota, "validated_stock_uart") as uart, self.assertRaises(ota.Error):
                ota.main(base + flags)
            load.assert_not_called()
            uart.assert_not_called()
        for key in (OWNER, TARGET, OWNER[:1] + RELAY[1:], TARGET[:1] + RELAY[1:]):
            with self.assertRaisesRegex(ota.Error, "distinct"):
                ota.validate_transport("directed", 0, 0, 255, key, 3, BINDING)

    def test_normal_profile_mismatch_never_retunes_signs_or_sends(self):
        for field in range(4):
            clock, stream, stock, sender = routed_setup()
            wrong = list(NORMAL)
            wrong[field] += 1
            stream.profile = tuple(wrong)
            with self.subTest(field=field), self.assertRaisesRegex(ota.Error, "normal radio"):
                with ota.radio_guard(stock, BINDING, self.directory, mode="directed"):
                    self.fail("mismatched sender yielded")
            with self.assertRaisesRegex(ota.Error, "normal radio"):
                ota.Sender(stock, BINDING, sender.candidate, tuple(wrong), clock() + 100, 0, 0,
                           mode="directed", relay=RELAY)
            self.assertFalse(any(command[0] in (11, 33, 34, 35, 65) for command in stream.commands))
            self.assertFalse(list(self.directory.iterdir()))

    def test_profile_drift_after_selection_fails_without_radio_override(self):
        _, stream, _, sender = routed_setup()
        stream.profile = (*NORMAL[:2], 8, NORMAL[3], NORMAL[4])
        with self.assertRaisesRegex(ota.Error, "profile changed"):
            sender.census(retries=1)
        self.assertFalse(any(command[0] in (11, 65) for command in stream.commands))

    def test_on_channel_duty_counts_retry_and_path_overhead_on_every_send(self):
        clock, stream, _, sender = routed_setup(width=3, duty=0.01)
        poll = b"\x0a" + TARGET + sender.candidate.digest + b"\x00\x00"
        sender.send(poll)
        finished = clock()
        estimate = ota.airtime(2 + 3 + 5 + len(poll), NORMAL)
        sender.send(poll)
        self.assertGreaterEqual(stream.rf_packets[1][0], finished + estimate * 99)
        self.assertGreater(estimate, ota.airtime(2 + len(poll), NORMAL))
        self.assertEqual(stream.profile, NORMAL)
        for duty in (0, -1, float("nan"), float("inf"), 1.1):
            with self.assertRaisesRegex(ota.Error, "duty"):
                routed_setup(duty=duty)

    def test_directed_guard_never_writes_radio_even_on_failure_or_signal(self):
        for failure in (False, True):
            directory = self.directory / str(failure)
            directory.mkdir(mode=0o700)
            _, stream, stock, _ = routed_setup()
            try:
                with ota.radio_guard(stock, BINDING, directory, mode="directed"):
                    if failure:
                        raise ota.Error("interrupted")
            except ota.Error:
                self.assertTrue(failure)
            self.assertEqual(stream.profile, NORMAL)
            self.assertFalse(any(command[0] == 11 for command in stream.commands))
            self.assertTrue(ota.private_read(directory / "radio-unchanged.json")["normal_profile_unchanged"])
            self.assertFalse((directory / "restored.json").exists())

    def test_directed_tx_queue_ok_is_not_measured_completion(self):
        _, stream, _, sender = routed_setup()
        stream.tx_fails = True
        with self.assertRaisesRegex(ota.Error, "physical stock TX"):
            sender.census(retries=1)
        self.assertFalse(stream.forwarded_requests)
        self.assertFalse(any(command[0] == 11 for command in stream.commands))

    def test_nonce_binding_and_separate_commit_keep_exact_selected_route(self):
        clock, stream, stock, sender = routed_setup()
        receipt = sender.upload()
        fresh = ota.Sender(stock, BINDING, sender.candidate, NORMAL, clock() + 10000, 0, 0,
                           clock=clock, sleep=clock.sleep, mode="directed", relay=RELAY)
        stream.nonce = bytes([3]) * 16
        with self.assertRaisesRegex(ota.Error, "BEGIN"):
            fresh.commit(receipt)
        self.assertEqual(stream.commit_count, 0)
        stream.nonce = NONCE
        different = ota.Sender(stock, BINDING, sender.candidate, NORMAL, clock() + 10000, 0, 0,
                               clock=clock, sleep=clock.sleep, mode="directed", relay=RELAY,
                               path_hash_bytes=2)
        with self.assertRaisesRegex(ota.Error, "matching"):
            different.commit(receipt)

    def test_reupload_signs_observed_generation_and_new_nonce_through_relay(self):
        _, stream, _, sender = routed_setup(reupload=True)
        stream.local_cache = stream.aborted = True
        stream.generation = 9
        receipt = sender.upload()
        self.assertEqual(stream.reupload_count, 1)
        self.assertEqual(receipt["generation"], 10)
        self.assertNotEqual(receipt["begin_nonce"], NONCE.hex())
        controls = [wire for _, _, wire in stream.rf_packets if wire[5] == 14]
        self.assertEqual(struct.unpack_from(">I", controls[0], 102)[0], 9)
        self.assertFalse(stream.commit_count)

    def test_post_commit_wrong_nonce_and_failed_report_are_failures_not_fallback(self):
        for fault in ("nonce", "failed", "missing"):
            _, stream, _, sender = routed_setup()
            sender.upload()
            sender._send_commit()
            if fault == "nonce":
                stream.nonce = bytes([3]) * 16
            elif fault == "failed":
                stream.install_lifecycle = 10
            else:
                stream.reply_mode = "bypass"
            with self.subTest(fault=fault), self.assertRaises((ota.Error, TimeoutError)):
                sender.wait_installed(100)
            self.assertEqual(stream.commit_count, 1)
            self.assertFalse(any(command[0] == 11 for command in stream.commands))


class ProtocolTests(unittest.TestCase):
    def test_routed_retry_explicitly_refused_before_binding_or_transport_access(self):
        argv = ["upload", "--routed-retry", "--serial", BINDING.serial,
                "--by-id", "/dev/serial/by-id/NOT_OPENED", "--sender-key", OWNER.hex(),
                "--target", TARGET.hex(), "--binding", "NOT_READ", "--artifacts", "NOT_CREATED"]
        with patch.object(ota.Binding, "load") as load, patch.object(ota, "validated_stock_uart") as uart, \
                self.assertRaisesRegex(ota.Error, "no legacy fallback"):
            ota.main(argv)
        load.assert_not_called()
        uart.assert_not_called()

    def test_frame_boundaries_and_zero_hop_rx(self):
        rf = bytes([13]) + bytes(170)
        self.assertEqual(len(b"\x41\x00" + ota.packet(rf)), 175)
        logged = b"\x88\x08\x40" + ota.packet(rf)
        self.assertEqual(len(logged), 176)
        self.assertEqual(ota.raw_rx(logged), rf)
        with self.assertRaises(ota.Error):
            ota.packet(bytes(173))
        with self.assertRaises(ota.Error):
            ota.raw_rx(logged + b"\x00")
        self.assertEqual(ota.raw_rx(b"\x88\x00\x00\x31\x00" + rf), rf)
        self.assertEqual(ota.raw_rx(b"\x88\x00\x00\x32\x01\x99" + rf[:-1]), rf[:-1])
        self.assertIsNone(ota.raw_rx(b"\x88\x00\x00\x32\x02\x99"))

    def test_rx_flood_direct_encoded_paths_and_native_path_boundaries(self):
        payload = census(candidate())
        for route in (1, 2):
            # A 123-byte v3 report leaves 48 path bytes inside stock's 176-byte frame.
            for size, count in ((1, 0), (2, 0), (3, 0), (1, 2), (2, 2), (3, 2), (1, 48), (2, 24), (3, 16)):
                path = bytes(i % 256 for i in range(size * count))
                packet = bytes([0x30 | route, ((size - 1) << 6) | count]) + path + payload
                with self.subTest(route=route, size=size, count=count):
                    self.assertEqual(len(b"\x88\x08\x40" + packet) <= ota.MAX_FRAME, True)
                    self.assertEqual(ota.raw_rx(b"\x88\x08\x40" + packet), payload)
            with self.assertRaisesRegex(ota.Error, "oversize"):
                ota.raw_rx(b"\x88\x08\x40" + bytes([0x30 | route, 49]) + bytes(49) + payload)
        for encoded in (0xC0, 0xC1, 0x7F, 0x96):
            with self.subTest(encoded=encoded):
                self.assertIsNone(ota.raw_rx(b"\x88\x08\x40\x31" + bytes([encoded]) + payload))

    def test_rx_rejects_version_type_transport_flags_truncated_paths_and_oversize(self):
        payload = census(candidate())
        for header in (0x30, 0x33, 0x71, 0x72, 0xB1, 0xB2, 0xF1, 0xF2, 0x3D, 0x3E, 0x2D, 0x2E):
            with self.subTest(header=header):
                self.assertIsNone(ota.raw_rx(b"\x88\x08\x40" + bytes([header, 0]) + payload))
        for frame in (b"", b"\x88", b"\x88\x08\x40\x31", b"\x88\x08\x40\x31\x00",
                      b"\x88\x08\x40\x31\x42" + bytes(3),
                      b"\x88\x08\x40\x32\x82" + bytes(5),
                      b"\x88\x08\x40\x31\x82" + bytes(6),
                      b"\x84\x08\x40\x31\x00" + payload):
            with self.subTest(frame=frame):
                self.assertIsNone(ota.raw_rx(frame))
        with self.assertRaisesRegex(ota.Error, "oversize"):
            ota.raw_rx(b"\x88\x08\x40\x31\x00" + bytes(172))

    def test_split_frames_and_oversize_rejected_immediately(self):
        clock, stream, _, _ = setup()
        frames = ota.Frames(stream, clock)
        wire = b"noise>" + struct.pack("<H", 176) + b"\x88\x00\x00\x32\x00" + bytes(171)
        for byte in wire:
            frames.feed(bytes([byte]))
        self.assertEqual(len(frames.pending[0][1]), 176)
        self.assertFalse(frames.buffer)
        for length in (0, 177, 65535):
            with self.subTest(length=length), self.assertRaises(ota.Error):
                ota.Frames(stream, clock).feed(b">" + struct.pack("<H", length))

    def test_recognized_unused_pushes_are_discarded_before_the_bound(self):
        clock, stream, stock, _ = setup()
        frames = ota.Frames(stream, clock)
        for _ in range(ota.PENDING_LIMIT * 2):
            for push in ORDINARY_PUSHES:
                frames.feed(b">" + struct.pack("<H", len(push)) + push)
        self.assertEqual(frames.pending, [])
        expected = {}
        for push in ORDINARY_PUSHES:
            expected[push[0]] = expected.get(push[0], 0) + ota.PENDING_LIMIT * 2
        self.assertEqual(frames.ignored, expected)

    def test_rf_census_ack_errors_signatures_and_unknown_frames_are_retained(self):
        clock, stream, _, _ = setup()
        c = candidate()
        frames = ota.Frames(stream, clock)
        kept = [b"\x88\x08\x40\x31\x00" + census(c),            # OTA census reply
                b"\x88\x08\x40\x32\x00" + b"\x0d" + bytes(170),  # OTA lease ACK
                b"\x88\x08\x40\x31", b"\x88\x08\x40\x71\x00" + bytes(4),  # malformed/unknown-version RF
                b"\x01\x03", b"\x14" + bytes(64), b"\x00",            # sync error, signature, OK
                b"\x91\x00", b"\xff"]                                 # unknown/future pushes
        for frame in kept:
            frames.feed(b">" + struct.pack("<H", len(frame)) + frame)
        self.assertEqual([frame for _, frame in frames.pending], kept)
        self.assertEqual(frames.ignored, {})

    def test_malformed_recognized_push_is_fatal_not_silently_eaten(self):
        clock, stream, _, _ = setup()
        for push in (b"\x80" + bytes(31), b"\x82" + bytes(9), b"\x83\x00", b"\x85" + bytes(8),
                     b"\x8a" + bytes(146), b"\x84\x00\x00", b"\x90\x00"):
            with self.subTest(code=push[0]), self.assertRaisesRegex(ota.Error, "malformed stock push"):
                ota.Frames(stream, clock).feed(b">" + struct.pack("<H", len(push)) + push)

    def test_unknown_async_backlog_remains_bounded(self):
        clock, stream, _, _ = setup()
        frames = ota.Frames(stream, clock)
        for _ in range(ota.PENDING_LIMIT):
            frames.feed(b">\x01\x00\x91")
        with self.assertRaisesRegex(ota.Error, "backlog overflow"):
            frames.feed(b">\x01\x00\x91")

    def test_refusal_and_signature_survive_interleaved_ordinary_pushes(self):
        _, stream, stock, _ = setup()
        original = stream.reply

        def noisy(data):
            for push in ORDINARY_PUSHES:
                original(push)
            original(data)
        stream.reply = noisy
        signature = stock.sign(b"message", 1000)
        ota.verify(OWNER, b"message", signature)
        stream.fail_restore = True
        with self.assertRaises(ota.Refused):
            stock.ok(b"\x0b" + struct.pack("<II", *NORMAL[:2]) + bytes(NORMAL[2:]))
        self.assertEqual([frame[0] for _, frame in stock.frames.pending], [])

    def test_stale_usb_response_not_used(self):
        _, stream, stock, _ = setup()
        stream.reply(b"\x01\x03")
        stock.ok(b"\x22data")

    def test_compact84_signing_and_wrong_signatures(self):
        c = candidate()
        message, prefix = ota.block_message(c, 0)
        self.assertEqual(len(message), 120)
        self.assertEqual(message[:36], c.digest + b"\x01\x00\x00\x54")
        signature = OWNER_PRIVATE.sign(message)
        self.assertEqual(len(prefix + signature), 155)
        ota.verify(OWNER, message, signature)
        for key, msg, sig in ((TARGET, message, signature), (OWNER, message[:-1] + b"!", signature),
                              (OWNER, message, bytes(64))):
            with self.assertRaises(ota.Error):
                ota.verify(key, msg, sig)
        _, _, stock, sender = setup()
        self.assertEqual(stock.sign(message, sender.deadline), signature)

    def test_stock_identity_version_and_signer_readback(self):
        _, stream, stock, sender = setup()
        self.assertEqual(stock.identify(), NORMAL)
        for version in (b"v1.17.0", b"v1.18.0"):
            stream.version = version
            with self.assertRaises(ota.Error):
                stock.identify()
        stream.version = b"v1.17.1"
        stream.wrong_identity = True
        with self.assertRaises(ota.Error):
            stock.identify()
        stream.wrong_identity = False
        stream.sign_with_target = True
        with self.assertRaises(ota.Error):
            stock.sign(b"message", sender.deadline)

    def test_release_version_accepts_only_full_1171_optional_v_and_hex_build_suffix(self):
        for version in (b"v1.17.1", b"1.17.1", b"v1.17.1-d929643",
                        b"1.17.1-d929643", b"v1.17.1-ABCDEF"):
            _, stream, stock, _ = setup()
            stream.version = version
            with self.subTest(version=version):
                self.assertEqual(stock.identify(), NORMAL)
                self.assertEqual(stock.version, version.decode("ascii"))
                self.assertTrue(stock.identified)
                self.assertEqual([cmd[0] for cmd in stream.commands], [1, 22])
        invalid = (b"", b"v1.17.0-d929643", b"v1.18.0", b"v1.17.10", b"v11.17.1",
                   b"V1.17.1", b" v1.17.1", b"v1.17.1 ", b"v1.17.1\n", b"v1.17.1-",
                   b"v1.17.1-main", b"v1.17.1-abc-dirty", b"v1.17.1+abc",
                   b"v1.17.1-rc1", b"v1.17.1\xff", b"prefix1.17.1")
        for version in invalid:
            _, stream, stock, _ = setup()
            stock.identify()
            stream.version = version
            with self.subTest(version=version), self.assertRaises(ota.Error):
                stock.identify()
            self.assertFalse(stock.identified)
            self.assertIsNone(stock.version)

    def test_non_release_versions_block_radio_sign_and_rf_with_no_startup_fallback(self):
        for version in (b"v1.17.1-main", b"v1.17.1-abc-dirty", b"v1.17.10", b"v1.17.1+abc"):
            for action in ("radio", "sign", "raw"):
                _, stream, stock, sender = setup()
                stream.version = version
                with self.subTest(version=version, action=action), self.assertRaises(ota.Error):
                    if action == "radio":
                        stock.radio((919000, 250000, 5, 5, 0))
                    elif action == "sign":
                        stock.sign(b"message", sender.deadline)
                    else:
                        stock.ok(b"\x41\x00" + ota.packet(b"\x07" + sender.candidate.digest[:4]))
                self.assertEqual([cmd[0] for cmd in stream.commands], [1, 22])
                self.assertFalse(stock.identified)

    def test_app_start_is_first_and_only_no_response_is_retried_once(self):
        clock, stream, stock, _ = setup()
        stream.drop_start = 1
        stock.expected_name = "synthetic-stock"
        self.assertEqual(stock.identify(), NORMAL)
        self.assertEqual([command[0] for command in stream.commands], [1, 1, 22])
        self.assertLess(clock(), 5)
        _, stream, stock, _ = setup()
        stream.drop_start = 2
        with self.assertRaises(ota.NoUsbResponse):
            stock.identify()
        self.assertEqual([command[0] for command in stream.commands], [1, 1])
        self.assertFalse(stock.identified)

    def test_name_guard_rejects_every_radio_sign_rf_write_and_bad_names_without_private_logs(self):
        for action in ("radio", "sign", "raw"):
            _, stream, stock, sender = setup()
            stock.expected_name = "synthetic-stock"
            stream.name = b"unapproved"
            with self.subTest(action=action), self.assertRaisesRegex(ota.Error, "label guard"):
                if action == "radio":
                    stock.radio((919000, 250000, 5, 5, 0))
                elif action == "sign":
                    stock.sign(b"message", sender.deadline)
                else:
                    stock.ok(b"\x41\x00" + ota.packet(b"\x07" + sender.candidate.digest[:4]))
            self.assertEqual([command[0] for command in stream.commands], [1])
            self.assertFalse(stock.identified)
        for name in (b"\xff", b"synthetic\x00stock"):
            _, stream, stock, _ = setup()
            stream.name = name
            with self.assertRaises(ota.Error) as caught:
                stock.identify()
            self.assertNotIn("GPS-HIDE", str(caught.exception))
            self.assertNotIn("99887766", str(caught.exception))

    def test_radio_sign_rf_guard_identity_and_version_before_any_mutating_write(self):
        for action in ("radio", "sign", "raw"):
            for wrong_identity in (False, True):
                _, stream, stock, sender = setup()
                stream.wrong_identity = wrong_identity
                stream.version = b"v1.17.1" if wrong_identity else b"v1.17.0"
                with self.subTest(action=action, wrong_identity=wrong_identity), self.assertRaises(ota.Error):
                    if action == "radio":
                        stock.radio((919000, 250000, 5, 5, 0))
                    elif action == "sign":
                        stock.sign(b"message", sender.deadline)
                    else:
                        stock.ok(b"\x41\x00" + ota.packet(b"\x07" + sender.candidate.digest[:4]))
                self.assertFalse(any(cmd[0] in (11, 33, 34, 35, 65) for cmd in stream.commands))

    def test_power_key_contact_reset_flash_and_usb_stage_commands_are_not_available(self):
        _, stream, stock, _ = setup()
        for command in (8, 9, 12, 19, 23, 24, 51, 66):
            with self.subTest(command=command), self.assertRaisesRegex(ota.Error, "allowlist"):
                stock.command(bytes([command]))
        self.assertFalse(stream.commands)

    def test_sensitive_self_device_fields_never_enter_logs_or_error_text(self):
        _, stream, stock, _ = setup()
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            stock.identify()
            stream.version = b"v1.17.0"
            try:
                stock.identify()
            except ota.Error as exc:
                print(str(exc))
            with patch.object(stock.frames, "command", return_value=b"\x01" + b"GPS-HIDE\x99\x88\x77\x66"):
                try:
                    stock.command(b"\x16\x0a", (13, 1))
                except ota.Error as exc:
                    print(str(exc))
        text = output.getvalue()
        self.assertNotIn("GPS-HIDE", text)
        self.assertNotIn("99887766", text)
        self.assertNotIn("4750532d48494445", text)

    def test_fresh_matching_census_validation(self):
        _, _, _, sender = setup()
        report = census(sender.candidate)
        self.assertEqual(sender.parse_census(report, 0)["lifecycle"], 5)
        mutations = {
            "wrong target": (1, bytes(32)), "wrong full hash": (33, bytes(32)),
            "wrong window": (65, b"\x00\x01"), "overshoot received": (83, b"\xff\xff"),
            "wrong total": (85, b"\x00\x03"), "wrong generation": (88, struct.pack(">I", 11)),
            "stale generation": (88, struct.pack(">I", 9)), "cache": (92, b"\x0b"),
            "installed": (92, b"\x08"), "unknown floor": (93, b"\x00"),
            "wrong floor": (94, struct.pack(">I", 5)), "wrong counter": (98, struct.pack(">I", 6)),
            "impossible bitmap": (67, b"\xff"), "false ready": (67, b"\x01"),
            "regressed phase": (87, b"\x01"),
        }
        for reason, (offset, value) in mutations.items():
            changed = report[:offset] + value + report[offset + len(value):]
            with self.subTest(reason=reason), self.assertRaises(ota.Error):
                sender.parse_census(changed, 0)
        with self.assertRaises(ota.Error):
            sender.parse_census(report[:92], 0)

    def test_census_monotonic_bitmap_and_global_progress(self):
        _, _, _, sender = setup(candidate(84 * 130))
        sender.parse_census(census(sender.candidate, 0, {0, 1}), 0)
        with self.assertRaises(ota.Error):
            sender.parse_census(census(sender.candidate, 0, {1, 2}), 0)
        with self.assertRaises(ota.Error):
            sender.parse_census(census(sender.candidate, 128, {128}), 128)

    def test_unsolicited_cached_rf_is_drained_and_status_retried(self):
        _, stream, _, sender = setup()
        stream.admitted = True
        stream.push(census(sender.candidate))
        stream.drop_census = 1
        report = sender.census()
        self.assertEqual(report["received"], 0)
        self.assertEqual(sum(rf[0] == 10 for _, _, rf in stream.rf_packets), 2)

    def test_usb_queue_admission_is_not_tx_completion(self):
        clock, stream, _, sender = setup()
        stream.tx_fails = True
        with self.assertRaisesRegex(ota.Error, "physical"):
            sender.send(b"\x07" + sender.candidate.digest[:4])
        self.assertGreaterEqual(clock(), 9)

    def test_budget_uses_airtime_and_measured_physical_stats(self):
        clock, stream, _, sender = setup()
        sender.send(b"\x07" + sender.candidate.digest[:4])
        spent = sender.next_normal - clock()
        self.assertGreater(spent, 7)
        sender.send(b"\x07" + sender.candidate.digest[:4])
        self.assertGreaterEqual(stream.rf_packets[1][0] - stream.rf_packets[0][0], spent)

    def test_wrong_ack_key_is_rejected_before_radio_change(self):
        _, stream, _, sender = setup()
        stream.admitted = True
        stream.bad_ack = True
        with self.assertRaisesRegex(ota.Error, "signature"):
            sender.negotiate()
        self.assertEqual(stream.profile, NORMAL)

    def test_ack_bound_to_owner_target_hash_frequency_lease_and_token(self):
        for offset in (1, 33, 65, 97, 101, 103):
            _, stream, _, sender = setup()
            stream.admitted = True
            stream.ack_mutator = lambda ack, i=offset: ack[:i] + bytes([ack[i] ^ 1]) + ack[i + 1:]
            with self.subTest(offset=offset), self.assertRaisesRegex(ota.Error, "ACK target"):
                sender.negotiate()
            self.assertEqual(stream.profile, NORMAL)

    def test_lost_ack_waits_expiry_and_uses_new_token(self):
        clock, stream, _, sender = setup(duty=1)
        stream.admitted = True
        stream.drop_ack = 1
        sender.negotiate()
        self.assertEqual(len(set(stream.tokens)), 2)
        self.assertEqual(stream.rejected_tokens, [])
        # The lost-ACK lease consumed the challenge; a new census supplies the next one.
        kinds = [rf[0] for _, _, rf in stream.rf_packets]
        self.assertEqual(kinds[kinds.index(12) + 1:kinds.index(12, kinds.index(12) + 1)], [10])
        requests = [t for t, _, rf in stream.rf_packets if rf[0] == 12]
        self.assertGreaterEqual(requests[1] - requests[0], 82)
        self.assertGreater(clock(), 87)

    def test_lease_bounds_expiry_and_repeated_normal_handshake(self):
        clock, stream, stock, sender = setup(lease=30000, duty=1)
        for lease in (249, 250, 29999, 60001):
            with self.assertRaises(ota.Error):
                ota.Sender(stock, BINDING, sender.candidate, NORMAL, 100, 919000, lease)
        stream.admitted = True
        sender.negotiate()
        self.assertEqual(stream.profile, (919000, 250000, 5, 5, 0))
        clock.now = sender.lease_end - 1
        with self.assertRaises(ota.LeaseExpired):
            sender.send(b"\x07" + sender.candidate.digest[:4])
        sender.negotiate()
        self.assertEqual(len(stream.tokens), 2)
        requests = [(t, profile) for t, profile, rf in stream.rf_packets if rf[0] == 12]
        self.assertTrue(all(profile == (*NORMAL[:4], 0) or profile == NORMAL for _, profile in requests))
        self.assertGreaterEqual(requests[1][0] - requests[0][0], 52)

    def test_ready_upload_repairs_dropped_block_without_auto_commit(self):
        _, stream, _, sender = setup()
        stream.drop_blocks = 1
        receipt = sender.upload()
        self.assertEqual(receipt["outcome"], "ready-observed-unsigned")
        self.assertFalse(receipt["installation_confirmed"])
        self.assertEqual(stream.received, {0, 1})
        self.assertEqual(stream.commit_count, 0)
        self.assertEqual(stream.profile, (*NORMAL[:4], 0))
        blocks = [struct.unpack_from(">H", rf, 5)[0] for _, _, rf in stream.rf_packets if rf[0] == 1]
        self.assertEqual(blocks.count(0), 2)
        self.assertEqual(blocks.count(1), 1)
        self.assertTrue(all(cmd[0] in (1, 11, 22, 33, 34, 35, 56, 65) for cmd in stream.commands))

    def test_resume_skips_durable_blocks_and_separate_signed_commit(self):
        _, stream, _, sender = setup(received={0})
        receipt = sender.upload()
        indices = [struct.unpack_from(">H", rf, 5)[0] for _, _, rf in stream.rf_packets if rf[0] == 1]
        self.assertEqual(indices, [1])
        result = sender.commit(receipt)
        self.assertEqual(stream.commit_count, 1)
        self.assertEqual(result["outcome"], "signed-commit-aggregate-tx-observed-not-install-confirmed")
        self.assertFalse(result["installation_confirmed"])
        self.assertEqual(sum(rf[0] == 8 for _, _, rf in stream.rf_packets), 1)

    def test_interrupted_upload_resumes_idempotently_with_new_sender(self):
        clock, stream, stock, sender = setup()
        real_sign = stock.sign
        def interrupted(message, deadline):
            if message == ota.block_message(sender.candidate, 1)[0]:
                raise ota.Error("simulated host disconnect")
            return real_sign(message, deadline)
        with patch.object(stock, "sign", side_effect=interrupted), self.assertRaises(ota.Error):
            sender.upload()
        self.assertEqual(stream.received, {0})
        stock.radio(NORMAL)
        clock.sleep(100)
        resumed = ota.Sender(stock, BINDING, sender.candidate, NORMAL, clock() + 10000, 919000,
                             clock=clock, sleep=clock.sleep)
        result = resumed.upload()
        indices = [struct.unpack_from(">H", rf, 5)[0] for _, _, rf in stream.rf_packets if rf[0] == 1]
        self.assertEqual(indices, [0, 1])
        self.assertEqual(result["generation"], 10)

    def test_multichunk_signer_preserves_176_limit(self):
        _, stream, stock, sender = setup()
        message = bytes(range(256)) + b"more"
        self.assertEqual(stock.sign(message, sender.deadline), OWNER_PRIVATE.sign(message))
        chunks = [cmd for cmd in stream.commands if cmd[0] == 34]
        self.assertEqual([len(cmd) for cmd in chunks], [176, 86])

    def test_bitmap_window_cursor_survives_lease_expiry(self):
        clock, stream, _, sender = setup(candidate(400 * 84), received=set(range(384)), duty=1)
        original_census = sender.census
        def slow_census(first=0, retries=3, allow_pending=False):
            report = original_census(first, retries, allow_pending)
            if first < 384 and sender.lease_end:
                clock.sleep(16)
            return report
        with patch.object(sender, "census", side_effect=slow_census):
            result = sender.upload()
        self.assertEqual(result["outcome"], "ready-observed-unsigned")
        indices = [struct.unpack_from(">H", rf, 5)[0] for _, _, rf in stream.rf_packets if rf[0] == 1]
        self.assertEqual(set(indices), set(range(384, 400)))
        self.assertGreater(len(stream.tokens), 1)

    def test_block_repair_retries_bounded(self):
        _, stream, _, sender = setup(duty=1)
        stream.drop_blocks = 100
        with self.assertRaisesRegex(ota.Error, "repair retries"):
            sender.upload()
        self.assertEqual(stream.commit_count, 0)

    def test_commit_wrong_receipt_and_not_ready(self):
        _, stream, _, sender = setup()
        receipt = sender.receipt("ready-observed-unsigned")
        receipt.update(generation=10, begin_nonce=NONCE.hex())
        for field, value in (("target_public_key", OWNER.hex()), ("sender_public_key", TARGET.hex()),
                             ("manifest_hash", bytes(32).hex()), ("counter", 6), ("generation", 9),
                             ("begin_nonce", None), ("begin_nonce", bytes(16).hex()),
                             ("begin_nonce", NONCE.hex().upper()), ("schema", 1)):
            wrong = dict(receipt, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ota.Error, "receipt"):
                sender.commit(wrong)
        stream.admitted = True
        with self.assertRaisesRegex(ota.Error, "fresh READY required"):
            sender.commit(receipt)
        self.assertEqual(stream.commit_count, 0)
        self.assertFalse(any(rf[0] == 3 for _, _, rf in stream.rf_packets))

    def test_commit_binds_observed_attempt_and_is_idempotent_across_reset(self):
        clock, stream, stock, sender = setup()
        receipt = sender.upload()
        self.assertEqual((receipt["schema"], receipt["begin_nonce"]), (2, NONCE.hex()))
        # A fresh process after host/receiver reset: same durable nonce, new lease challenge.
        stream.challenge = 0x0BADC0DE
        for _ in range(2):
            fresh = ota.Sender(stock, BINDING, sender.candidate, NORMAL, clock() + 10000, 919000,
                               clock=clock, sleep=clock.sleep)
            fresh.commit(receipt)
        commits = [rf for _, _, rf in stream.rf_packets if rf[0] == 3]
        self.assertEqual([len(rf) for rf in commits], [153, 153])
        self.assertEqual(commits[0][65:89], struct.pack(">II", 5, 10) + NONCE)
        self.assertEqual((stream.commit_count, stream.denied_commits), (2, 0))

    def test_commit_after_abort_and_identical_reupload_is_refused_and_replay_denied(self):
        clock, stream, stock, sender = setup()
        receipt = sender.upload()
        captured = None
        fresh = ota.Sender(stock, BINDING, sender.candidate, NORMAL, clock() + 10000, 919000,
                           clock=clock, sleep=clock.sleep)
        fresh.commit(receipt)
        captured = [rf for _, _, rf in stream.rf_packets if rf[0] == 3][-1]
        # ABORT + reupload of the identical image draws a new BEGIN nonce.
        stream.nonce = bytes(reversed(NONCE))
        stream.commit_count = 0
        before = len(stream.rf_packets)
        stale = ota.Sender(stock, BINDING, sender.candidate, NORMAL, clock() + 10000, 919000,
                           clock=clock, sleep=clock.sleep)
        with self.assertRaisesRegex(ota.Error, "different BEGIN attempt"):
            stale.commit(receipt)
        self.assertFalse(any(rf[0] == 3 for _, _, rf in stream.rf_packets[before:]))
        stream.remote(captured)
        self.assertEqual((stream.commit_count, stream.denied_commits), (0, 1))

    def test_legacy_receiver_is_refused_on_first_census_before_lease_or_blocks(self):
        _, stream, _, sender = setup()
        stream.legacy_receiver = True
        with self.assertRaisesRegex(ota.Error, "wire version is unsupported"):
            sender.upload()
        kinds = [rf[0] for _, _, rf in stream.rf_packets]
        self.assertEqual(kinds, [8, 10])
        for frame in (census(sender.candidate)[:102], census(sender.candidate)[:102] + bytes(21),
                      census(sender.candidate)[:102] + b"\x02" + census(sender.candidate)[103:],
                      census(sender.candidate) + b"\x00"):
            with self.subTest(length=len(frame), version=frame[102:103]), \
                    self.assertRaisesRegex(ota.Error, "wire version"):
                sender.parse_census(frame, 0)

    def test_unbound_or_changed_nonce_census_is_refused(self):
        _, _, _, sender = setup()
        with self.assertRaisesRegex(ota.Error, "unbound or different"):
            sender.parse_census(census(sender.candidate, nonce=bytes(16)), 0)
        sender.parse_census(census(sender.candidate), 0)
        with self.assertRaisesRegex(ota.Error, "unbound or different"):
            sender.parse_census(census(sender.candidate, nonce=bytes(reversed(NONCE))), 0)

    def test_lease_token_is_single_use_receiver_challenge(self):
        clock, stream, _, sender = setup(duty=1)
        stream.admitted = True
        sender.authorize()
        first_challenge = stream.challenge
        sender.negotiate()
        requests = [rf for _, _, rf in stream.rf_packets if rf[0] == 12]
        self.assertEqual(struct.unpack_from(">I", requests[0], 103)[0], first_challenge)
        self.assertNotEqual(stream.challenge, first_challenge)
        # Captured request replay (A/B/A) and identical retry: no ACK and no retune.
        stream.switch = stream.expiry = 0
        stream.profile = NORMAL
        acks = len(stream.rx_packets)
        stream.remote(requests[0])
        self.assertEqual(len(stream.rx_packets), acks)
        self.assertEqual(stream.rejected_tokens, [first_challenge])
        self.assertEqual(stream.switch, 0)

    def test_stale_challenge_after_receiver_reset_recensuses_for_new_token(self):
        clock, stream, _, sender = setup(duty=1)
        stream.admitted = True
        sender.authorize()
        stale = stream.challenge
        stream.challenge = 0x0BADC0DE  # receiver rebooted after reporting the old challenge
        sender.negotiate()
        tokens = [struct.unpack_from(">I", rf, 103)[0] for _, _, rf in stream.rf_packets if rf[0] == 12]
        self.assertEqual(tokens, [stale, 0x0BADC0DE])
        self.assertEqual(stream.rejected_tokens, [stale])
        self.assertEqual(stream.profile[:4], (919000, 250000, 5, 5))

    def test_block_geometry_role_package_floor_guards(self):
        c = candidate()
        cases = [(c.canonical[:4] + b"\x01" + c.canonical[5:], c.image, 4),
                 (c.canonical, b"PK\x03\x04" + c.image[4:], 4),
                 (c.canonical, c.image, 5), (c.canonical[:-1], c.image, 4),
                 (c.canonical, c.image + b"\x00", 4)]
        for canonical, image, floor in cases:
            with self.assertRaises(ota.Error):
                ota.Candidate.build(canonical, image, floor)
        with self.assertRaises(ota.Error):
            ota.block_message(c, c.total)
        last = candidate(88)
        message, prefix = ota.block_message(last, 1)
        self.assertEqual(message[35], 4)
        self.assertEqual(len(prefix) - 7, 4)






class EventTests(unittest.TestCase):
    def test_complete_retirement_ready_commit_events_are_public_and_ordered(self):
        clock, stream, stock, _ = setup(received={0, 1})
        stream.local_cache = stream.aborted = True
        stream.generation = 10
        approved = replace(BINDING, min_generation=1, allow_reupload=True)
        events = []
        sender = ota.Sender(stock, approved, candidate(), NORMAL, clock() + 10000, 919000,
                            clock=clock, sleep=clock.sleep, reupload=True, event_callback=events.append)
        receipt = sender.upload()
        committer = ota.Sender(stock, approved, candidate(), NORMAL, clock() + 10000, 919000,
                               clock=clock, sleep=clock.sleep, event_callback=events.append)
        committer.commit(receipt)
        names = [event["event"] for event in events]
        for name in ("auth_sent", "census_request", "census_sent", "rf_rx", "census_parsed",
                     "reupload_sent", "reupload_receiving", "lease_request", "lease_ack_verified",
                     "lease_active", "block_sent", "lease_leave", "ready_observed_unsigned", "commit_sent"):
            self.assertIn(name, names)
        self.assertLess(names.index("auth_sent"), names.index("reupload_sent"))
        self.assertLess(names.index("reupload_sent"), names.index("lease_active"))
        self.assertLess(names.index("ready_observed_unsigned"), names.index("commit_sent"))
        reupload = next(event for event in events if event["event"] == "reupload_sent")
        self.assertEqual((reupload["observed_generation"], reupload["expected_generation"]), (10, 11))
        received = [event for event in events if event["event"] == "rf_rx"]
        self.assertTrue(any(event["route"] == 1 and event["kind"] == 11 for event in received))
        self.assertTrue(any(event["route"] == 2 and event["kind"] == 11 for event in received))
        self.assertTrue(any(event["kind"] == 13 and event["payload_length"] == 171 for event in received))
        self.assertTrue(all(event["target_match"] and event["manifest_match"] for event in received))
        self.assertTrue(all(event["tx_evidence"] == "aggregate-counters" for event in events if "tx_evidence" in event))
        self.assertEqual(sum(event["event"] == "block_sent" for event in events), 2)
        text = json.dumps(events)
        for forbidden in ("GPS-HIDE", "99887766", "signature", "private_key", "SelfInfo", "DeviceInfo"):
            self.assertNotIn(forbidden, text)

    def test_no_reply_diagnostics_preserve_auth_retry_count_packets_and_pacing(self):
        outcomes = []
        events = []
        for enabled in (False, True):
            clock, stream, _, sender = setup()
            stream.drop_census = 100
            sender.event_callback = events.append if enabled else None
            with self.assertRaisesRegex(ota.Error, "target did not admit"):
                sender.upload()
            outcomes.append((stream.commands, stream.rf_packets, clock()))
        self.assertEqual(outcomes[0], outcomes[1])
        names = [event["event"] for event in events]
        self.assertEqual(names.count("auth_sent"), 3)
        self.assertEqual(names.count("census_request"), 9)
        self.assertEqual(names.count("census_timeout"), 9)
        self.assertEqual(names.count("census_retry"), 6)
        self.assertEqual(names.count("auth_no_census"), 3)
        self.assertEqual(names[-1], "auth_exhausted")
        self.assertNotIn("reupload_sent", names)

    def test_rf_metadata_wrong_target_stale_and_other_packet_types_never_log_bodies(self):
        clock, stream, stock, sender = setup()
        c = sender.candidate
        stale = b"\x88\x08\x40\x31\x00" + census(c)
        wrong = b"\x88\x08\x40\x31\x00" + (b"\x0b" + OWNER + census(c)[33:])
        secret = b"PSK-HIDE SIGNATURE-HIDE PRIVATE-KEY-HIDE GPS-HIDE PIN-HIDE"
        custom = b"\x88\x08\x40\x3e\x00" + secret
        stock.frames.pending.extend([(clock(), b"\x05" + secret), (clock(), b"\x0d" + secret),
                                     (clock() - 1, stale), (clock(), wrong), (clock(), custom)])
        events = []
        with self.assertRaises(TimeoutError):
            stock.frames.receive(lambda payload: False, clock(), clock() + 1,
                                 events.append, TARGET, c.digest)
        self.assertEqual(len(events), 3)
        self.assertFalse(events[0]["fresh"])
        self.assertFalse(events[1]["target_match"])
        self.assertTrue(events[1]["manifest_match"])
        self.assertFalse(events[2]["decoded"])
        self.assertEqual(events[2]["payload_type"], 15)
        text = json.dumps(events)
        for value in secret.decode().split():
            self.assertNotIn(value, text)
            self.assertNotIn(value.encode().hex(), text)
        discarded = []
        stream.push(census(c))
        stock.frames.discard_rf(discarded.append, TARGET, c.digest)
        self.assertEqual(discarded[0]["event"], "rf_discard")
        self.assertTrue(discarded[0]["target_match"])

    def test_census_refusal_event_does_not_bypass_target_guard(self):
        _, stream, _, sender = setup()
        stream.admitted = True
        events = []
        sender.event_callback = events.append
        original_push = stream.push
        def wrong_target(payload):
            original_push(payload[:1] + OWNER + payload[33:])
        with patch.object(stream, "push", side_effect=wrong_target), self.assertRaisesRegex(ota.Error, "target"):
            sender.census()
        self.assertFalse(next(event for event in events if event["event"] == "rf_rx")["target_match"])
        self.assertEqual(events[-1]["event"], "census_rejected")
        self.assertNotIn("census_parsed", [event["event"] for event in events])

    def test_cli_public_event_serializes_one_json_line_and_flushes(self):
        event = {"event": "auth_sent", "attempt": 1, "elapsed_s": 2.5, "tx_evidence": "aggregate-counters"}
        with patch("builtins.print") as printed:
            ota.public_event(event)
        args, kwargs = printed.call_args
        self.assertEqual(json.loads(args[0]), event)
        self.assertEqual(kwargs, {"flush": True})


class ReuploadTests(unittest.TestCase):
    def test_outside_lease_flood_pending_to_direct_transfer_to_flood_ready_and_separate_commit(self):
        for size, path in ((1, b""), (2, b"abcd"), (3, b"abcdef")):
            clock, stream, stock, sender = self.dynamic_setup()
            stream.census_hash_size, stream.census_path = size, path
            receipt = sender.upload()
            records = [(raw, payload) for _, _, raw, payload in stream.rx_packets if payload[0] == 11]
            self.assertTrue(any(raw[0] == 0x31 and payload[92] == 9 for raw, payload in records))
            self.assertTrue(any(raw[0] == 0x32 for raw, _ in records))
            self.assertEqual(records[-1][0][0], 0x31)
            self.assertEqual(records[-1][1][92], 5)
            self.assertEqual(receipt["outcome"], "ready-observed-unsigned")
            self.assertEqual(stream.commit_count, 0)
            committer = ota.Sender(stock, sender.binding, sender.candidate, NORMAL, clock() + 10000,
                                   919000, clock=clock, sleep=clock.sleep)
            result = committer.commit(receipt)
            self.assertEqual(stream.commit_count, 1)
            self.assertEqual(result["outcome"], "signed-commit-aggregate-tx-observed-not-install-confirmed")
            self.assertEqual(stream.rx_packets[-1][2][0], 0x31)
            self.assertTrue(all(command[2:4] == b"\x32\x00" for command in stream.commands if command[0] == 65))

    def dynamic_setup(self, generation=10):
        old = candidate()
        canonical = old.canonical[:45] + struct.pack(">I", 1) + old.canonical[49:]
        c = ota.Candidate.build(canonical, old.image, 0)
        clock, stream, stock, _ = setup(c, received={0, 1})
        stream.local_cache = stream.aborted = True
        stream.generation, stream.floor = generation, 0
        approved = replace(binding(c), floor=0, min_generation=1, allow_reupload=True)
        sender = ota.Sender(stock, approved, c, NORMAL, clock() + 10000, 919000,
                            clock=clock, sleep=clock.sleep, reupload=True)
        return clock, stream, stock, sender

    def test_generation_free_reupload_signs_only_fresh_rf_observed_generation_after_abort(self):
        for observed in (10, 37):
            _, stream, _, sender = self.dynamic_setup(observed)
            self.assertIsNone(sender.pending_generation)
            self.assertIsNone(sender.reupload_generation)
            result = sender.upload()
            self.assertEqual(result["generation"], observed + 1)
            self.assertEqual(sender.pending_generation, observed)
            controls = [rf for _, _, rf in stream.rf_packets if rf[0] == 14]
            self.assertEqual(len(controls), 1)
            self.assertEqual(struct.unpack_from(">I", controls[0], 97)[0], observed)
            ota.verify(OWNER, ota.REUPLOAD_DOMAIN + controls[0][:101], controls[0][101:])
            kinds = [rf[0] for _, _, rf in stream.rf_packets]
            self.assertLess(kinds.index(10), kinds.index(14))
            self.assertEqual(stream.received, {0, 1})
            self.assertEqual(stream.commit_count, 0)

    def test_dynamic_generation_cannot_be_obtained_from_usb_or_locally_queued_pending_rf(self):
        for queued in (False, True):
            _, stream, _, sender = self.dynamic_setup()
            stream.supports_purpose_transition = False
            stream.reply(b"\x1f" + bytes(85) + struct.pack(">I", 10))
            if queued:
                stream.push(pending_census(sender.candidate, 10, floor=0))
            with self.subTest(queued=queued), self.assertRaises(ota.Error):
                sender.upload()
            self.assertIsNone(sender.pending_generation)
            self.assertIsNone(sender.activation_generation)
            self.assertFalse(any(rf[0] in (1, 3, 4, 12, 14) for _, _, rf in stream.rf_packets))

    def test_dynamic_activation_requires_observed_plus_one_zero_bitmap_and_stable_pending_generation(self):
        for generation, received in ((10, set()), (12, set()), (11, {0, 1})):
            _, stream, _, sender = self.dynamic_setup()
            stream.activation_reports = [census(sender.candidate, generation=generation, received=received, floor=0)]
            with self.subTest(generation=generation, received=received), self.assertRaises(ota.Error):
                sender.upload()
            self.assertFalse(any(rf[0] in (1, 3, 12) for _, _, rf in stream.rf_packets))
        _, _, _, sender = self.dynamic_setup()
        def pending(generation):
            data = pending_census(sender.candidate, generation)
            return data[:94] + struct.pack(">I", 0) + data[98:]
        for generation in (0, 0xFFFFFFFF):
            with self.assertRaises(ota.Error):
                sender.parse_census(pending(generation), 0, allow_pending=True)
        sender.parse_census(pending(10), 0, allow_pending=True)
        with self.assertRaises(ota.Error):
            sender.parse_census(pending(11), 0, allow_pending=True)

    def test_dynamic_resume_uses_fresh_active_rf_generation_without_reupload_again(self):
        clock, stream, stock, sender = self.dynamic_setup()
        original_sign = stock.sign
        def interrupted(message, deadline):
            if message == ota.block_message(sender.candidate, 1)[0]:
                raise ota.Error("disconnect after new generation block0")
            return original_sign(message, deadline)
        with patch.object(stock, "sign", side_effect=interrupted), self.assertRaises(ota.Error):
            sender.upload()
        stock.radio(NORMAL)
        clock.sleep(100)
        resumed = ota.Sender(stock, sender.binding, sender.candidate, NORMAL, clock() + 10000, 919000,
                             clock=clock, sleep=clock.sleep, reupload=True)
        result = resumed.upload()
        self.assertEqual(result["generation"], 11)
        self.assertIsNone(resumed.pending_generation)
        self.assertEqual(stream.reupload_count, 1)
        self.assertEqual(sum(rf[0] == 14 for _, _, rf in stream.rf_packets), 1)

    def test_dynamic_retirement_requires_both_opt_ins_before_signing(self):
        clock, stream, stock, sender = self.dynamic_setup()
        with self.assertRaises(ota.Error):
            ota.Sender(stock, replace(sender.binding, allow_reupload=False), sender.candidate, NORMAL,
                       sender.deadline, 919000, reupload=True)
        self.assertFalse(stream.commands)
        no_opt = ota.Sender(stock, sender.binding, sender.candidate, NORMAL, sender.deadline, 919000,
                            clock=clock, sleep=clock.sleep)
        with self.assertRaisesRegex(ota.Error, "explicit"):
            no_opt.upload()
        self.assertFalse(any(rf[0] in (4, 14) for _, _, rf in stream.rf_packets))

    def prepared_setup(self, opted=True):
        clock, stream, stock, sender = setup(received={0, 1}, reupload_generation=9 if opted else None)
        stream.local_cache = stream.aborted = True
        stream.generation = 9
        return clock, stream, stock, sender

    def test_root_aborted_local_cache_requires_fresh_auth_explicit_reupload_and_zero_new_generation(self):
        _, stream, _, sender = self.prepared_setup()
        result = sender.upload()
        self.assertEqual(result["generation"], 10)
        self.assertEqual(stream.reupload_count, 1)
        self.assertFalse(stream.local_cache)
        self.assertEqual(stream.commit_count, 0)
        kinds = [rf[0] for _, _, rf in stream.rf_packets]
        self.assertLess(kinds.index(8), kinds.index(14))
        self.assertLess(kinds.index(14), kinds.index(12))
        self.assertNotIn(4, kinds)
        blocks = [struct.unpack_from(">H", rf, 5)[0] for _, _, rf in stream.rf_packets if rf[0] == 1]
        self.assertEqual(blocks, [0, 1])  # Old sealed cache bits are NOT promoted.
        rf = next(rf for _, _, rf in stream.rf_packets if rf[0] == 14)
        self.assertEqual(len(rf), 165)
        self.assertEqual(rf[:101], b"\x0e" + OWNER + TARGET + sender.candidate.digest + struct.pack(">I", 9))
        ota.verify(OWNER, ota.REUPLOAD_DOMAIN + rf[:101], rf[101:])

    def test_without_cli_opt_in_pending_aborted_never_reuploads(self):
        _, stream, _, sender = self.prepared_setup(opted=False)
        sender.binding = replace(sender.binding, reupload_generation=9)  # A fixed host generation alone is insufficient.
        with self.assertRaisesRegex(ota.Error, "explicit"):
            sender.upload()
        self.assertEqual(stream.received, {0, 1})
        self.assertTrue(stream.local_cache and stream.aborted)
        self.assertFalse(any(rf[0] in (4, 14) for _, _, rf in stream.rf_packets))

    def test_cli_generation_requires_matching_root_binding_before_signing(self):
        _, stream, stock, sender = setup()
        for generation in (9, 0, 0xFFFFFFFF, True):
            with self.subTest(generation=generation), self.assertRaises(ota.Error):
                ota.Sender(stock, BINDING, sender.candidate, NORMAL, sender.deadline, 919000,
                           reupload_generation=generation)
        self.assertFalse(stream.commands)
        approved = replace(BINDING, reupload_generation=9)
        with self.assertRaises(ota.Error):
            approved.permit_reupload(8)
        _, _, stock, sender = self.prepared_setup()
        with self.assertRaisesRegex(ota.Error, "freshly observed"):
            sender.activate_prepared()
        self.assertFalse(stock.frames.stream.commands)

    def test_pending_census_old_generation_is_exception_only_for_preparation(self):
        _, _, _, sender = self.prepared_setup()
        frame = pending_census(sender.candidate)
        with self.assertRaisesRegex(ota.Error, "explicit"):
            sender.parse_census(frame, 0)
        report = sender.parse_census(frame, 0, allow_pending=True)
        self.assertEqual(report["generation"], 9)
        self.assertIsNone(sender.generation)
        self.assertFalse(sender.previous)
        for offset, value in ((1, OWNER), (33, bytes(32)), (67, b"\x01"), (83, b"\x00\x01"),
                              (87, b"\x01"), (88, struct.pack(">I", 8)), (94, struct.pack(">I", 5))):
            wrong = frame[:offset] + value + frame[offset + len(value):]
            with self.subTest(offset=offset), self.assertRaises(ota.Error):
                sender.parse_census(wrong, 0, allow_pending=True)
        sender.parse_census(census(sender.candidate, received=set()), 0)
        with self.assertRaises(ota.Error):
            sender.parse_census(frame, 0, allow_pending=True)

    def test_reupload_rejects_old_wrong_generation_or_promoted_cache_ready(self):
        for frame in (census(candidate(), received=set(), generation=9),
                      census(candidate(), received=set(), generation=11), census(candidate())):
            _, stream, _, sender = self.prepared_setup()
            stream.activation_reports = [frame]
            with self.assertRaises(ota.Error):
                sender.upload()
            self.assertFalse(any(rf[0] in (1, 3, 12) for _, _, rf in stream.rf_packets))

    def test_activation_waits_erasing_to_receiving_without_reuploading_new_generation(self):
        _, stream, _, sender = self.prepared_setup()
        fresh_nonce = hashlib.sha256(stream.nonce).digest()[:16]  # REUPLOAD draws a new BEGIN nonce
        stream.activation_reports = [census(sender.candidate, received=set(), lifecycle=2, nonce=fresh_nonce)]
        sender.upload()
        self.assertEqual(stream.reupload_count, 1)
        self.assertEqual(sum(rf[0] == 14 for _, _, rf in stream.rf_packets), 1)

    def test_reupload_and_activation_status_loss_are_idempotently_retried(self):
        for drop_frame, drop_status in ((1, 0), (0, 3)):
            _, stream, _, sender = self.prepared_setup()
            stream.drop_reupload, stream.drop_activation_census = drop_frame, drop_status
            sender.upload()
            self.assertEqual(stream.reupload_count, 1)
            self.assertEqual(stream.generation, 10)
            self.assertEqual(sum(rf[0] == 14 for _, _, rf in stream.rf_packets), 2)

    def test_resume_active_generation_plus_one_never_reuploads_again(self):
        clock, stream, stock, sender = self.prepared_setup()
        real_sign = stock.sign
        def interrupted(message, deadline):
            if message == ota.block_message(sender.candidate, 1)[0]:
                raise ota.Error("interrupted after new generation first block")
            return real_sign(message, deadline)
        with patch.object(stock, "sign", side_effect=interrupted), self.assertRaises(ota.Error):
            sender.upload()
        self.assertEqual(stream.received, {0})
        stock.radio(NORMAL)
        clock.sleep(100)
        resumed = ota.Sender(stock, sender.binding, sender.candidate, NORMAL, clock() + 10000, 919000,
                             clock=clock, sleep=clock.sleep, reupload_generation=9)
        resumed.upload()
        self.assertEqual(stream.reupload_count, 1)
        self.assertEqual(sum(rf[0] == 14 for _, _, rf in stream.rf_packets), 1)
        self.assertEqual([struct.unpack_from(">H", rf, 5)[0] for _, _, rf in stream.rf_packets if rf[0] == 1], [0, 1])

    def test_pending_abort_or_unsupported_receiver_cannot_promote_cache(self):
        for aborted, qualified in ((False, True), (True, False)):
            _, stream, _, sender = self.prepared_setup()
            stream.aborted, stream.supports_purpose_transition = aborted, qualified
            with self.assertRaises(ota.Error):
                sender.upload()
            self.assertTrue(stream.local_cache)
            self.assertEqual(stream.received, {0, 1})
            self.assertFalse(any(rf[0] in (1, 3, 4, 14) for _, _, rf in stream.rf_packets))

    def test_root_usb_generation_or_queued_pending_census_cannot_replace_fresh_rf_observation(self):
        for stale_rf in (False, True):
            _, stream, _, sender = self.prepared_setup()
            stream.supports_purpose_transition = False  # No fresh prepared-new-hash RF census.
            usb = bytearray(90)
            usb[0] = 31
            usb[86:90] = struct.pack(">I", 9)
            stream.reply(usb)  # Local USB generation is not RF evidence.
            if stale_rf:
                stream.push(pending_census(sender.candidate))
            with self.subTest(stale_rf=stale_rf), self.assertRaises(ota.Error):
                sender.upload()
            self.assertFalse(sender.pending_reupload)
            self.assertIsNone(sender.generation)
            self.assertEqual(stream.received, {0, 1})
            self.assertFalse(any(rf[0] in (1, 3, 4, 12, 14) for _, _, rf in stream.rf_packets))
            self.assertFalse(any(cmd[0] == 66 for cmd in stream.commands))

    def test_only_new_role0_manifest_is_polled_and_old_cache_hash_cannot_activate(self):
        _, stream, _, sender = self.prepared_setup()
        canonical = sender.candidate.canonical
        old_local_role1_hash = hashlib.sha256(canonical[:4] + b"\x01" + canonical[5:]).digest()
        self.assertNotEqual(old_local_role1_hash, sender.candidate.digest)
        original_push = stream.push
        def wrong_cached_status(frame):
            if frame[0] == 11:
                frame = frame[:33] + old_local_role1_hash + frame[65:]
            original_push(frame)
        with patch.object(stream, "push", side_effect=wrong_cached_status), self.assertRaisesRegex(ota.Error, "manifest"):
            sender.upload()
        polls = [rf for _, _, rf in stream.rf_packets if rf[0] == 10]
        self.assertTrue(polls)
        self.assertTrue(all(rf[33:65] == sender.candidate.digest for rf in polls))
        self.assertFalse(any(rf[0] in (1, 3, 4, 14) for _, _, rf in stream.rf_packets))

    def test_later_confirmed_role0_candidate_uses_normal_auth_not_abort_or_generation_reupload(self):
        old = candidate()
        image = old.image[:-1] + bytes([old.image[-1] ^ 1])
        canonical = (old.canonical[:13] + hashlib.sha256(image).digest() + struct.pack(">I", 6)
                     + old.canonical[49:])
        next_candidate = ota.Candidate.build(canonical, image, 5)
        clock, stream, stock, _ = setup(next_candidate)
        stream.floor, stream.generation = 5, 11
        # A confirmed terminal state permits ordinary fresh Begin;
        # receiver terminal/policy implementation belongs to APP owner.
        approved = replace(binding(next_candidate), floor=5, min_generation=11)
        sender = ota.Sender(stock, approved, next_candidate, NORMAL, clock() + 10000, 919000,
                            clock=clock, sleep=clock.sleep)
        result = sender.upload()
        self.assertEqual(result["counter"], 6)
        self.assertEqual(result["generation"], 11)
        kinds = [rf[0] for _, _, rf in stream.rf_packets]
        self.assertIn(8, kinds)
        self.assertNotIn(4, kinds)
        self.assertNotIn(14, kinds)
        self.assertEqual(stream.reupload_count, 0)
        with self.assertRaises(ota.Error):
            ota.Candidate.build(old.canonical, old.image, 5)  # Measured confirmed floor, no inferred rollback.
        with self.assertRaises(ota.Error):
            ota.Candidate.build(canonical[:4] + b"\x01" + canonical[5:], image, 5)


class ArtifactTests(Scratch):
    def test_ordinary_binding_needs_no_approval_ledger_or_candidate_capsule(self):
        path = self.directory / "ordinary-binding.json"
        ota.private_write(path, {
            "schema": 1, "serial": BINDING.serial,
            "sender_public_key": OWNER.hex(), "target_public_key": TARGET.hex(),
            "floor": BINDING.floor, "min_generation": BINDING.min_generation,
            "normal_profile": list(BINDING.normal),
        })
        selected = ota.Binding.load(path, BINDING.serial, OWNER, TARGET)
        self.assertIsNone(selected.image_hash)
        self.assertIsNone(selected.manifest_hash)
        selected.check_candidate(candidate())
        with self.assertRaisesRegex(ota.Error, "sender/target"):
            ota.Binding.load(path, BINDING.serial, TARGET, OWNER)

    def test_cli_upload_wires_public_json_event_callback_without_hardware(self):
        c = candidate()
        path = self.directory / "binding.json"
        ota.private_write(path, {"schema": 1, "authorized": True, "serial": BINDING.serial,
                                 "sender_public_key": OWNER.hex(), "target_public_key": TARGET.hex(),
                                 "stock_version": "1.17.1", "floor": 4, "min_generation": 10,
                                 "normal_profile": list(NORMAL[:4]), "image_kind": "ordinary-app",
                                 "image_sha256": BINDING.image_hash.hex(), "manifest_hash": c.digest.hex()})
        image, manifest = self.directory / "ordinary.bin", self.directory / "canonical.bin"
        image.write_bytes(c.image)
        manifest.write_bytes(c.canonical)
        _, stream, _, _ = setup()
        @contextmanager
        def uart(*args, **kwargs):
            yield stream
        @contextmanager
        def guard(*args):
            yield NORMAL
        def sender_factory(*args, **kwargs):
            self.assertIs(kwargs["event_callback"], ota.public_event)
            def upload():
                kwargs["event_callback"]({"event": "auth_sent", "attempt": 1, "tx_evidence": "aggregate-counters"})
                return {"outcome": "synthetic-test-only"}
            return SimpleNamespace(upload=upload)
        argv = ["upload", "--serial", BINDING.serial, "--by-id", "/dev/serial/by-id/NOT_OPENED",
                "--sender-key", OWNER.hex(), "--target", TARGET.hex(), "--binding", str(path),
                "--artifacts", str(self.directory / "run"), "--image", str(image), "--manifest", str(manifest),
                "--frequency-khz", "919000"]
        output = io.StringIO()
        with patch.object(ota, "validated_stock_uart", uart), patch.object(ota, "radio_guard", guard), \
                patch.object(ota, "Sender", side_effect=sender_factory), redirect_stdout(output):
            ota.main(argv)
        lines = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(lines[0]["event"], "auth_sent")
        self.assertEqual(lines[1]["outcome"], "synthetic-test-only")
        self.assertFalse(stream.commands)

    def test_generation_free_root_binding_and_upload_only_cli_flag(self):
        value = {"schema": 1, "authorized": True, "serial": BINDING.serial,
                 "sender_public_key": OWNER.hex(), "target_public_key": TARGET.hex(),
                 "stock_version": "1.17.1", "floor": 0, "min_generation": 1,
                 "normal_profile": [907525, 250000, 7, 5], "image_kind": "ordinary-app",
                 "image_sha256": BINDING.image_hash.hex(), "manifest_hash": BINDING.manifest_hash.hex(),
                 "allow_reupload": True}
        path = self.directory / "dynamic-binding.json"
        ota.private_write(path, value)
        approved = ota.Binding.load(path, BINDING.serial, OWNER, TARGET)
        self.assertTrue(approved.allow_reupload)
        self.assertIsNone(approved.reupload_generation)
        approved.permit_reupload(None, True)
        for operation in ("commit", "restore", "inspect"):
            argv = [operation, "--serial", BINDING.serial, "--by-id", "/dev/serial/by-id/NOT_OPENED",
                    "--sender-key", OWNER.hex(), "--target", TARGET.hex(), "--binding", str(path),
                    "--artifacts", str(self.directory / "NOT_CREATED"), "--reupload"]
            with patch.object(ota, "resolve_stock") as resolve, self.assertRaisesRegex(ota.Error, "upload"):
                ota.main(argv)
            resolve.assert_not_called()
        bad = self.directory / "invalid-allow.json"
        ota.private_write(bad, dict(value, allow_reupload=1))
        with self.assertRaises(ota.Error):
            ota.Binding.load(bad, BINDING.serial, OWNER, TARGET)

    def test_measured_matching_250khz_normal_upload_ready_never_applies_62500_and_restores(self):
        clock, stream, stock, _ = setup()
        original = (907525, 250000, 7, 5, 0)
        stream.profile, stream.target_normal, stream.direct_frequency = original, original[:4], 908000
        stream.version, stream.floor = b"v1.17.1-d929643", 0
        approved = replace(BINDING, serial="0001", normal=original[:4], floor=0,
                           by_path=STOCK_PATH, id_path=STOCK_ID_PATH, usb_vid=0x10C4, usb_pid=0xEA60,
                           sender_name="synthetic-stock")
        with ota.radio_guard(stock, approved, self.directory) as captured:
            sender = ota.Sender(stock, approved, candidate(), captured, clock() + 10000, 908000,
                                clock=clock, sleep=clock.sleep)
            result = sender.upload()
            self.assertEqual(sender.normal, original)
            self.assertEqual(result["outcome"], "ready-observed-unsigned")
        self.assertEqual(stream.profile, original)
        self.assertEqual((stream.tx_power, stream.path_hash_bytes, stream.commit_count), (2, 2, 0))
        self.assertEqual(ota.private_read(self.directory / "original-radio.json")["profile"], list(original))
        settings = [command for command in stream.commands if command[0] == 11]
        self.assertTrue(settings)
        self.assertTrue(all(struct.unpack_from("<I", command, 5)[0] == 250000 for command in settings))
        for _, profile, rf in stream.rf_packets:
            fast = (908000, 250000, 5, 5, 0)
            self.assertIn(profile, (original, fast))
            if rf[0] in (1, 8, 12):
                self.assertEqual(profile, fast if rf[0] == 1 else original)

    def stock_profile_setup(self):
        clock, stream, stock, sender = setup()
        original = (907525, 250000, 7, 8, 0)  # Synthetic wireCR8 fixture, not a hardware observation.
        normal = (907525, 62500, 7, 5)
        stream.profile, stream.target_normal, stream.direct_frequency = original, normal, 908000
        approved = replace(BINDING, serial="0001", normal=normal, by_path=STOCK_PATH, id_path=STOCK_ID_PATH,
                           usb_vid=0x10C4, usb_pid=0xEA60)
        return clock, stream, stock, approved, original

    def test_temporary_target_normal_then_fast_then_exact_stock_wire_profile_and_power_restore(self):
        clock, stream, stock, approved, original = self.stock_profile_setup()
        with ota.radio_guard(stock, approved, self.directory) as captured:
            self.assertEqual(captured, original)
            self.assertEqual(stream.profile, (*approved.normal, 0))
            sender = ota.Sender(stock, approved, candidate(), captured, clock() + 10000, 908000,
                                clock=clock, sleep=clock.sleep)
            self.assertEqual(sender.normal, (*approved.normal, 0))
            result = sender.upload()
            self.assertEqual(result["outcome"], "ready-observed-unsigned")
        self.assertEqual(stream.profile, original)
        self.assertEqual(stream.tx_power, 2)
        self.assertFalse(any(cmd[0] == 12 for cmd in stream.commands))
        for _, profile, rf in stream.rf_packets:
            expected = (908000, 250000, 5, 5, 0) if rf[0] == 1 else (*approved.normal, 0)
            if rf[0] in (1, 8, 12):
                self.assertEqual(profile, expected)
        saved = ota.private_read(self.directory / "original-radio.json")
        self.assertEqual(saved["profile"], list(original))
        self.assertEqual(saved["by_path"], STOCK_PATH)
        self.assertEqual(saved["id_path"], STOCK_ID_PATH)
        self.assertEqual(saved["tx_power_dbm"], 2)

    def test_join_failure_sign_error_restores_original_not_target_normal(self):
        _, stream, stock, approved, original = self.stock_profile_setup()
        with self.assertRaisesRegex(ota.Error, "signature"):
            with ota.radio_guard(stock, approved, self.directory):
                stream.sign_with_target = True
                stock.sign(candidate().canonical, 1000)
        self.assertEqual(stream.profile, original)
        self.assertEqual(stream.tx_power, 2)

    def test_guarded_recovery_uses_exact_original_profile_and_physical_anchor(self):
        _, stream, stock, approved, original = self.stock_profile_setup()
        with ota.radio_guard(stock, approved, self.directory):
            pass
        stream.profile = (908000, 250000, 5, 5, 0)
        with ota.radio_guard(stock, approved, self.directory, restoring=True):
            pass
        self.assertEqual(stream.profile, original)
        before = len(stream.commands)
        wrong = replace(approved, by_path=STOCK_PATH + "-OTHER")
        with self.assertRaisesRegex(ota.Error, "bound"):
            with ota.radio_guard(stock, wrong, self.directory, restoring=True):
                pass
        self.assertFalse(any(cmd[0] == 11 for cmd in stream.commands[before:]))

    def test_unknown_wire_cr_is_rejected_without_guessing_or_radio_changes(self):
        _, stream, stock, approved, _ = self.stock_profile_setup()
        stream.profile = (907525, 250000, 7, 4, 0)
        with self.assertRaisesRegex(ota.Error, "profile"):
            with ota.radio_guard(stock, approved, self.directory):
                pass
        self.assertFalse(any(cmd[0] in (11, 33, 34, 35, 65) for cmd in stream.commands))
        self.assertFalse((self.directory / "original-radio.json").exists())

    def test_radio_restored_including_repeat_on_success_and_failure(self):
        for failed in (False, True):
            directory = self.directory / str(failed)
            directory.mkdir(mode=0o700)
            _, stream, stock, _ = setup()
            try:
                with ota.radio_guard(stock, BINDING, directory):
                    stock.radio((919000, 250000, 5, 5, 0))
                    if failed:
                        raise ota.Error("interrupted transfer")
            except ota.Error:
                self.assertTrue(failed)
            self.assertEqual(stream.profile, NORMAL)
            saved = ota.private_read(directory / "original-radio.json")
            self.assertEqual(saved["profile"], list(NORMAL))
            self.assertEqual(saved["serial"], BINDING.serial)
            self.assertEqual(saved["sender_public_key"], OWNER.hex())
            self.assertEqual((directory / "original-radio.json").stat().st_mode & 0o777, 0o600)
            self.assertTrue(ota.private_read(directory / "restored.json")["restored"])

    def test_restore_waits_for_interrupted_outstanding_physical_tx(self):
        clock, stream, stock, sender = setup()
        with self.assertRaises(ota.Error):
            with ota.radio_guard(stock, BINDING, self.directory):
                stock.radio((919000, 250000, 5, 5, 0))
                before = stock.stats(sender.deadline)
                stock.pending_tx = before[1:3]
                stock.ok(b"\x41\x00" + ota.packet(b"\x07" + sender.candidate.digest[:4]))
                raise ota.Error("signal during TX")
        self.assertEqual(stream.profile, NORMAL)
        self.assertIsNone(stock.pending_tx)
        self.assertGreater(clock(), 1)

    def test_restore_fails_explicitly_if_physical_tx_unknown(self):
        _, stream, stock, _ = setup()
        with self.assertRaisesRegex(ota.Error, "physical TX unconfirmed"):
            with ota.radio_guard(stock, BINDING, self.directory):
                stock.radio((919000, 250000, 5, 5, 0))
                stock.pending_tx = (0, 0)
        self.assertEqual(stream.profile, (919000, 250000, 5, 5, 0))
        self.assertFalse((self.directory / "restored.json").exists())

    def test_restoration_failure_explicit_and_guarded_recovery(self):
        _, stream, stock, _ = setup()
        with self.assertRaisesRegex(ota.Error, "refused"):
            with ota.radio_guard(stock, BINDING, self.directory):
                stock.radio((919000, 250000, 5, 5, 0))
                stream.fail_restore = True
        self.assertTrue((self.directory / "original-radio.json").exists())
        self.assertFalse((self.directory / "restored.json").exists())
        stream.fail_restore = False
        with ota.radio_guard(stock, BINDING, self.directory, restoring=True):
            pass
        self.assertEqual(stream.profile, NORMAL)
        wrong = replace(BINDING, serial=BINDING.serial + "0")
        with self.assertRaisesRegex(ota.Error, "bound"):
            with ota.radio_guard(stock, wrong, self.directory, restoring=True):
                pass

    def test_private_artifact_exclusive_no_overwrite_or_symlink(self):
        path = self.directory / "a.json"
        ota.private_write(path, {"a": 1})
        with self.assertRaises(FileExistsError):
            ota.private_write(path, {"a": 2})
        os.chmod(path, 0o644)
        with self.assertRaises(ota.Error):
            ota.private_read(path)
        link = self.directory / "link"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            ota.private_read(link)


    def test_signal_cleanup_runs_restore(self):
        _, stream, stock, _ = setup()
        with self.assertRaisesRegex(ota.Error, "signal"):
            with ota.termination_cleanup():
                with ota.radio_guard(stock, BINDING, self.directory):
                    stock.radio((919000, 250000, 5, 5, 0))
                    signal.raise_signal(signal.SIGTERM)
        self.assertEqual(stream.profile, NORMAL)

    def test_root_reupload_binding_requires_exact_next_generation_and_upload_only(self):
        value = {"schema": 1, "authorized": True, "serial": BINDING.serial,
                 "sender_public_key": OWNER.hex(), "target_public_key": TARGET.hex(),
                 "stock_version": "1.17.1", "floor": 4, "min_generation": 10,
                 "normal_profile": list(NORMAL[:4]), "image_kind": "ordinary-app",
                 "image_sha256": BINDING.image_hash.hex(), "manifest_hash": BINDING.manifest_hash.hex(),
                 "reupload_generation": 9}
        path = self.directory / "reupload-binding.json"
        ota.private_write(path, value)
        approved = ota.Binding.load(path, BINDING.serial, OWNER, TARGET)
        self.assertEqual(approved, replace(BINDING, reupload_generation=9))
        for operation in ("commit", "restore"):
            argv = [operation, "--serial", BINDING.serial, "--by-id", "/dev/serial/by-id/NOT_OPENED",
                    "--sender-key", OWNER.hex(), "--target", TARGET.hex(), "--binding", str(path),
                    "--artifacts", str(self.directory / "NOT_CREATED"), "--reupload-generation", "9"]
            with patch.object(ota, "resolve_stock") as resolve, self.assertRaisesRegex(ota.Error, "upload"):
                ota.main(argv)
            resolve.assert_not_called()
        for generation, minimum in ((9, 11), (0, 1), (True, 2), (0xFFFFFFFF, 0xFFFFFFFF)):
            invalid = self.directory / f"invalid-{generation}-{minimum}.json"
            ota.private_write(invalid, dict(value, reupload_generation=generation, min_generation=minimum))
            with self.assertRaises(ota.Error):
                ota.Binding.load(invalid, BINDING.serial, OWNER, TARGET)


class GoldenCppTests(Scratch):
    def test_existing_cpp_encoders_and_signing_domains(self):
        # Compile the existing header-only encoders, never edit protocol sources.
        cpp = r'''
#include <cstdio>
#include <Packet.h>
#include <helpers/ota/OtaRfFrames.h>
#include <ota/protocol/OtaDescriptor.h>
using namespace mesh::ota;
void dump(const unsigned char* p, size_t n) {
  for (size_t i=0;i<n;++i) std::printf("%02x",p[i]);
  std::puts("");
}
int main() {
  unsigned char owner[32], target[32], hash[32], canonical[59], sig[64], data[84], out[256], msg[256];
  unsigned char nonce[16];
  for(int i=0;i<16;i++)nonce[i]=i+200;
  for(int i=0;i<32;i++){owner[i]=i;target[i]=i+32;hash[i]=i+64;}
  for(int i=0;i<59;i++)canonical[i]=i;
  for(int i=0;i<64;i++)sig[i]=i+128;
  for(int i=0;i<84;i++)data[i]=i+1;
  size_t n=encodeOtaTargetAuthorization(target,owner,canonical,sig,out,sizeof(out)); dump(out,n);
  n=buildOtaBlockSignedMessage(hash,1,0x1234,data,84,msg); dump(msg,n);
  encodeOtaSignedBlockFrame(1,hash,0x1234,data,84,sig,out,sizeof(out),n); dump(out,n);
  n=encodeOtaDirectFrame(12,owner,target,hash,919000,60000,0x12345678,out,sizeof(out));
  dump(out,107);std::memcpy(out+107,sig,64);dump(out,n);
  n=buildOtaDirectMessage(out,msg); dump(msg,n);
  out[0]=13; n=buildOtaDirectMessage(out,msg); dump(msg,n);
  mesh::Packet ack;ack.header=0x32;ack.path_len=0;ack.payload_len=171;std::memcpy(ack.payload,out,171);
  unsigned char ackwire[256];n=ack.writeTo(ackwire);dump(ackwire,n);
  n=usb::buildCommitSignedMessage(target,hash,5,0x0A0B0C0D,nonce,msg); dump(msg,n);
  n=encodeOtaCommitFrame(target,hash,5,0x0A0B0C0D,nonce,sig,out,sizeof(out)); dump(out,n);
  n=encodeOtaCensusPoll(target,hash,128,out,sizeof(out)); dump(out,n);
  OtaCensusReport r; std::memcpy(r.reporter,target,32); std::memcpy(r.manifestHash,hash,32);
  r.first=128;r.bitmap[0]=3;r.received=2;r.total=130;r.phase=1;r.generation=10;
  r.lifecyclePhase=usb::UsbOtaPhase::Receiving;r.floorKnown=true;r.confirmedFloor=4;r.counter=5;
  std::memcpy(r.beginNonce,nonce,16);r.leaseChallenge=0x5EED0001;
  n=encodeOtaCensusReport(r,out,sizeof(out));dump(out,n);
  mesh::Packet p;p.header=0x32;p.path_len=0;p.payload_len=n;std::memcpy(p.payload,out,n);
  unsigned char wire[256];n=p.writeTo(wire);dump(wire,n);
  meshcore::ota::protocol::OtaDescriptor d;
  d.boardFamily=0x584e;d.boardVariant=0x3430;d.role=0;d.appAddress=0x27000;d.exactSizeBytes=168;
  d.securityCounter=5;d.minBootloaderCapabilities=1;d.formatId=1;d.keyId=1;d.algorithmId=1;
  unsigned char image[168]={0,0,1,0x20,9,0x70,2,0};
  for(int i=8;i<168;i++)image[i]=(i-8)%251;
  ::ota::trust::Sha256::hash(image,168,d.sha256);
  meshcore::ota::protocol::encodeOtaDescriptorCanonical(d,out,sizeof(out),n);dump(out,n);
  out[0]=14;std::memcpy(out+1,owner,32);std::memcpy(out+33,target,32);std::memcpy(out+65,hash,32);
  usb::putBE32(out+97,9);dump(out,101);n=buildOtaReuploadMessage(out,msg);dump(msg,n);
  std::memcpy(out+101,sig,64);dump(out,165);
  n=encodeOtaDirectProfileFrame(15,OtaDirectProfile::Bw500,owner,target,hash,919000,60000,0x12345678,out,sizeof(out));
  n=buildOtaDirectMessage(out,msg); dump(msg,n);
  usb::UsbOtaReply u; u.requestOp=0x17; u.result=usb::UsbOtaResult::Ok; u.phase=usb::UsbOtaPhase::Ready;
  u.flags=usb::kReplyFlagSnapshotValid|usb::kReplyFlagRemote; std::memcpy(u.target,target,32);
  std::memcpy(u.manifestHash,hash,32); u.durableReceivedBlocks=2; u.totalBlocks=2; u.counter=5;
  u.statusAgeMs=0; u.retryAfterMs=0; u.generation=0x0A0B0C0D; std::memcpy(u.beginNonce,nonce,16);
  u.wireVersion=usb::kOtaWireVersion; n=usb::encodeUsbOtaReply(u,out); dump(out,n);
  unsigned char inner[184];
  size_t inner_n=encodeOtaTargetAuthorization(target,owner,canonical,sig,inner,sizeof(inner));
  n=encodeOtaRetryAttempt(0x11223344,inner,inner_n,out,sizeof(out));dump(out,n);
  mesh::Packet routed;routed.header=0x32;routed.setPathHashSizeAndCount(3,1);
  routed.path[0]=0x73;routed.path[1]=0x91;routed.path[2]=0x94;
  routed.payload_len=n;std::memcpy(routed.payload,out,n);n=routed.writeTo(wire);dump(wire,n);
  encodeOtaSignedBlockFrame(1,hash,0x1234,data,84,sig,inner,sizeof(inner),inner_n);
  n=encodeOtaRetryAttempt(0x11223345,inner,inner_n,out,sizeof(out),true);dump(out,n);
  inner_n=encodeOtaCensusReport(r,inner,sizeof(inner));
  n=encodeOtaRetryAttempt(0x11223346,inner,inner_n,out,sizeof(out));dump(out,n);
  routed.header=0x31;routed.setPathHashSizeAndCount(1,1);routed.payload_len=n;
  std::memcpy(routed.payload,out,n);n=routed.writeTo(wire);dump(wire,n);
}'''
        path = self.directory / "golden.cpp"
        path.write_text(cpp)
        binary = self.directory / "golden"
        subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                        "-I", str(ROOT / "src"), "-I", str(ROOT / "test/mocks"),
                        str(path), str(ROOT / "src/Packet.cpp"), "-o", str(binary)],
                       check=True, capture_output=True, text=True,
                       env=dict(os.environ, TMPDIR=str(self.directory)))
        actual = subprocess.check_output([str(binary)], text=True).splitlines()
        owner, target, digest = bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))
        canonical, signature, data = bytes(range(59)), bytes(range(128, 192)), bytes(range(1, 85))
        direct = b"\x0c" + owner + target + digest + struct.pack(">IHI", 919000, 60000, 0x12345678)
        nonce = bytes(range(200, 216))
        body = target + digest + struct.pack(">II", 5, 0x0A0B0C0D) + nonce
        report = (b"\x0b" + target + digest + struct.pack(">H", 128) + b"\x03" + bytes(15)
                  + struct.pack(">HHBIBBII", 2, 130, 1, 10, 3, 1, 4, 5)
                  + b"\x03" + nonce + struct.pack(">I", 0x5EED0001))
        profile = b"\x0f" + owner + target + digest + struct.pack(">IHI", 0x020E05D8, 60000, 0x12345678)
        reply = (bytes([30, 3, 0x17, 0, 5, 3]) + target + digest
                 + struct.pack(">HHIIII", 2, 2, 5, 0, 0, 0x0A0B0C0D) + nonce + b"\x03")
        fixture_candidate = ota.Candidate(canonical, bytes(84 * 0x1234) + data, digest, 5, 0x1235)
        block_message, block_prefix = ota.block_message(fixture_candidate, 0x1234)
        expected = [
            b"\x08" + hashlib.sha256(target).digest()[:8] + owner + canonical + signature,
            block_message, block_prefix + signature,
            direct, direct + signature, ota.DIRECT_DOMAIN + direct, ota.DIRECT_DOMAIN + b"\x0d" + direct[1:],
            ota.packet(b"\x0d" + direct[1:] + signature),
            ota.COMMIT_DOMAIN + body, b"\x03" + body + signature,
            b"\x0a" + target + digest + struct.pack(">H", 128), report, ota.packet(report),
            candidate().canonical,
            b"\x0e" + owner + target + digest + struct.pack(">I", 9),
            ota.REUPLOAD_DOMAIN + b"\x0e" + owner + target + digest + struct.pack(">I", 9),
            b"\x0e" + owner + target + digest + struct.pack(">I", 9) + signature,
            ota.DIRECT_PROFILE_DOMAIN + profile, reply,
            ota.retry_frame(b"\x08" + hashlib.sha256(target).digest()[:8] + owner + canonical + signature, 0x11223344),
            ota.packet(ota.retry_frame(b"\x08" + hashlib.sha256(target).digest()[:8] + owner + canonical + signature,
                                       0x11223344), RELAY[:3], 3),
            ota.retry_frame(block_prefix + signature, 0x11223345, repair=True),
            ota.retry_frame(report, 0x11223346),
            b"\x31\x01" + RELAY[:1] + ota.retry_frame(report, 0x11223346),
        ]
        self.assertEqual(actual, [blob.hex() for blob in expected])
        # Exact wire sizes and the 176-byte stock frame ceiling.
        self.assertEqual((len(ota.COMMIT_DOMAIN + body), len(b"\x03" + body + signature), len(report), len(reply)),
                         (110, 153, 123, 107))
        self.assertLessEqual(len(ota.packet(report)) + 3, ota.MAX_FRAME)
        import ota_uploader as native
        decoded = native.decode_reply(reply)
        self.assertEqual((decoded.generation, decoded.begin_nonce, decoded.wire_version, decoded.attempt_bound),
                         (0x0A0B0C0D, nonce, 3, True))


if __name__ == "__main__":
    unittest.main()
