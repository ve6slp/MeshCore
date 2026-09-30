#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import re
import select
import struct
import sys
import termios
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_device  # noqa: E402

# Boards are addressed by lab role (see lab/devices.ini), never by a literal
# serial or ttyACMn, so the lab survives re-cabling and board swaps.
CLIENT_ROLE = os.environ.get("MESHCORE_LAB_CLIENT_ROLE", "client")
TARGET_ROLE = os.environ.get("MESHCORE_LAB_TARGET_ROLE", "target")

CMD_APP_START = 1
CMD_SEND_SELF_ADVERT = 7
CMD_SET_ADVERT_NAME = 8
CMD_SET_RADIO_PARAMS = 11
CMD_DEVICE_QUERY = 22
CMD_SET_PATH_HASH_MODE = 61
CMD_SEND_RAW_PACKET = 65
CMD_OTA_CONTROL = 66
CMD_OTA_LAB = 67

RESP_OK = 0
RESP_ERR = 1
ERR_TABLE_FULL = 3
RESP_SELF_INFO = 5
RESP_DEVICE_INFO = 13
RESP_OTA_STATUS = 29
PUSH_ADVERT = 0x80
PUSH_RAW_LOG = 0x88
PUSH_NEW_ADVERT = 0x8A
PUSH_OTA_EVENT = 0x91

OTA_GET_STATUS = 0
OTA_SET_MODE = 1
OTA_SET_DUTY = 2
OTA_ABORT = 3
OTA_DIRECT_LEASE = 5

OTA_DESCRIPTOR = 1
OTA_CHUNK = 3
OTA_ABORT_MESSAGE = 5
OTA_LEASE = 6
OTA_ANNOUNCEMENT = 7
OTA_CENSUS = 8
OTA_COHORT = 9
OTA_MISSING = 10
OTA_COMMIT = 11

ROUTE_FLOOD = 1
ROUTE_DIRECT = 2
PAYLOAD_TYPE_LORA_OTA = 0x0C
OTA_PRIORITY = 4
OTA_CHUNK_BYTES = 128
MAX_SERIAL_FRAME_SIZE = 176


class OtaQueueFull(RuntimeError):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class Evidence:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
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


class FramedSerial:
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
        self.buffer = bytearray()
        self.pending = []
        evidence.log("serial_open", node=name, path=path, resolved=os.path.realpath(path))

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def write_frame(self, payload):
        if len(payload) > MAX_SERIAL_FRAME_SIZE:
            raise ValueError(f"serial frame too large: {len(payload)}")
        frame = b"<" + struct.pack("<H", len(payload)) + payload
        offset = 0
        while offset < len(frame):
            _, writable, _ = select.select([], [self.fd], [], 2.0)
            if not writable:
                raise TimeoutError(f"{self.name}: serial write timeout")
            offset += os.write(self.fd, frame[offset:])
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
        readable, _, _ = select.select([self.fd], [], [], timeout)
        if readable:
            chunk = os.read(self.fd, 4096)
            if chunk:
                self.buffer.extend(chunk)
        for payload in self._extract():
            self.pending.append((time.monotonic(), payload))
            self.evidence.log("serial_rx", node=self.name, length=len(payload), code=payload[0] if payload else None,
                              hex=payload.hex())

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


def parse_status(frame):
    text = frame[1:].decode("ascii", errors="replace")
    values = {"raw": text}
    for key, value in re.findall(r"([a-z]+)=([^ ]+)", text):
        value = value.rstrip("%")
        if "/" in value:
            left, right = value.split("/", 1)
            values[key] = int(left)
            values[key + "_limit"] = int(right)
        else:
            try:
                values[key] = float(value) if "." in value else int(value)
            except ValueError:
                values[key] = value
    return values


def status(node):
    return parse_status(node.command(bytes([CMD_OTA_CONTROL, OTA_GET_STATUS]), expected=(RESP_OTA_STATUS,)))


def app_info(node):
    payload = bytes([CMD_APP_START]) + bytes(7) + b"ota-rf-lab"
    frame = node.command(payload, expected=(RESP_SELF_INFO,))
    if len(frame) < 58:
        raise RuntimeError(f"{node.name}: short self-info frame")
    return {
        "pubkey": frame[4:36].hex(),
        "pubkey_bytes": frame[4:36],
        "freq_khz": struct.unpack_from("<I", frame, 48)[0],
        "bw_hz": struct.unpack_from("<I", frame, 52)[0],
        "sf": frame[56],
        "cr": frame[57],
        "name": frame[58:].decode("utf-8", errors="replace"),
    }


def require_ok(node, payload):
    frame = node.command(payload)
    if frame[0] != RESP_OK:
        raise RuntimeError(f"{node.name}: command failed: {frame.hex()}")


def serializable_app_info(info):
    return {key: value for key, value in info.items() if key != "pubkey_bytes"}


def configure_node(node, name):
    node.command(bytes([CMD_DEVICE_QUERY, 13]), expected=(RESP_DEVICE_INFO,))
    require_ok(node, bytes([CMD_SET_ADVERT_NAME]) + name.encode("ascii"))
    require_ok(node, bytes([CMD_SET_RADIO_PARAMS]) + struct.pack("<II", 907525, 62500) + bytes([7, 5, 0]))
    require_ok(node, bytes([CMD_SET_PATH_HASH_MODE, 0, 2]))
    require_ok(node, bytes([CMD_OTA_CONTROL, OTA_SET_DUTY]) + struct.pack("<I", 2000))
    require_ok(node, bytes([CMD_OTA_CONTROL, OTA_SET_MODE, 2]))
    return app_info(node), status(node)


def ota_envelope(message_type, campaign, session, attempt, payload=b"", namespace=0x4F54):
    return struct.pack(">HBBIIHBH", namespace, 1, message_type, campaign, session, attempt, 0, len(payload)) + payload


def descriptor_fragment(image, security_counter):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not image or security_counter <= 0:
        raise ValueError("a descriptor requires an image and a positive security counter")
    descriptor = (
        struct.pack(">HHBII", 0x584E, 0x3430, 0, 0x27000, len(image)) +
        hashlib.sha256(image).digest() +
        struct.pack(">IIHHH", security_counter, 1, 1, 1, 1)
    )
    # Publicly reproducible lab fixture; never use this key on deployed nodes.
    signature = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).sign(descriptor)
    blob = descriptor + signature
    return bytes([0, 1]) + struct.pack(">HH", len(blob), len(blob)) + blob


def chunk_payload(image, chunk_index):
    if chunk_index < 0:
        raise ValueError("chunk index must not be negative")
    offset = chunk_index * OTA_CHUNK_BYTES
    data = image[offset:offset + OTA_CHUNK_BYTES]
    if not data:
        raise ValueError("chunk index is outside the image")
    return struct.pack(">IH", chunk_index, len(data)) + data


def announcement_payload(campaign):
    return struct.pack(">IHBI", campaign, 123, OTA_PRIORITY, 3600000)


def lease_payload(subtype, lease_id):
    return struct.pack(">BIIB", subtype, lease_id, 60000, 1)


def budget_chunk_payload(index):
    data = struct.pack(">I", index) + bytes(OTA_CHUNK_BYTES - 4)
    return struct.pack(">IH", index, len(data)) + data


def send_ota(node, route, message_type, campaign, session=1, attempt=1, payload=b"", namespace=0x4F54):
    if message_type == OTA_ANNOUNCEMENT and not payload:
        payload = announcement_payload(campaign)
    envelope = ota_envelope(message_type, campaign, session, attempt, payload, namespace)
    header = route | (PAYLOAD_TYPE_LORA_OTA << 2)
    raw = bytes([header, 0x80]) + envelope
    response = node.command(bytes([CMD_SEND_RAW_PACKET, OTA_PRIORITY]) + raw, timeout=8.0)
    if response == bytes([RESP_ERR, ERR_TABLE_FULL]):
        raise OtaQueueFull(f"{node.name}: OTA packet pool full")
    if response[0] != RESP_OK:
        raise RuntimeError(f"{node.name}: OTA packet queue failed: {response.hex()}")


def wait_ota_event(node, message_type, timeout=12.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            frame = node.wait_frame({PUSH_OTA_EVENT}, timeout=min(1.0, deadline - time.monotonic()))
        except TimeoutError:
            continue
        if len(frame) >= 2 and frame[1] == message_type:
            return frame
    raise TimeoutError(f"{node.name}: no OTA event type {message_type}")


def wait_advert(node, timeout=15.0):
    return node.wait_frame({PUSH_ADVERT, PUSH_NEW_ADVERT}, timeout=timeout)


def wait_raw_packet(node, predicate, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        frame = node.wait_frame({PUSH_RAW_LOG}, timeout=deadline - time.monotonic())
        if predicate(frame[3:]):
            return frame[3:]
    raise TimeoutError(f"{node.name}: no matching raw radio packet")


def wait_advert_from(node, public_key, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        frame = wait_advert(node, timeout=deadline - time.monotonic())
        if frame[1:33] == public_key:
            return frame
    raise TimeoutError(f"{node.name}: no fresh advert from {public_key.hex()}")


def run_airtime_test(client, target, client_info, evidence, duty_timeout):
    require_ok(client, bytes([CMD_OTA_CONTROL, OTA_SET_DUTY]) + struct.pack("<I", 2000))
    require_ok(client, bytes([CMD_OTA_CONTROL, OTA_SET_MODE, 2]))
    start = last_progress = time.monotonic()
    sent = refused = 0
    packet_cost = None
    previous = status(client)
    reached = False
    while time.monotonic() - start < duty_timeout:
        try:
            send_ota(client, ROUTE_FLOOD, OTA_CHUNK, 5000,
                     payload=budget_chunk_payload(sent))
            sent += 1
        except OtaQueueFull as exc:
            refused += 1
            evidence.log("ota_backpressure", error=str(exc), refused=refused)
        target.poll(0.05)
        target.take_pending({PUSH_OTA_EVENT})
        time.sleep(0.25)
        current = status(client)
        increment = current["used"] - previous["used"]
        if increment > 0:
            packet_cost = increment if packet_cost is None else min(packet_cost, increment)
            last_progress = time.monotonic()
        if sent % 12 == 0 or current["used"] != previous["used"]:
            evidence.log("duty_progress", sent=sent, refused=refused, status=current,
                         observed_packet_cost_ms=packet_cost)
        evidence.check("airtime-cap-not-exceeded",
                       current["used_limit"] == 72000 and current["used"] <= 72000,
                       status=current)
        previous = current
        remaining = current["used_limit"] - current["used"]
        if packet_cost is not None and remaining < packet_cost and time.monotonic() - last_progress >= 15:
            reached = True
            break
    evidence.check("airtime-budget-exhausted", reached, sent=sent, refused=refused,
                   status=previous, observed_packet_cost_ms=packet_cost,
                   synthetic_load=True, install_or_boot_claim=False)

    target.poll(0.1)
    target.take_pending({PUSH_OTA_EVENT, PUSH_ADVERT, PUSH_NEW_ADVERT})
    target_before = status(target)["rx"]
    for index in range(8):
        try:
            send_ota(client, ROUTE_FLOOD, OTA_CHUNK, 5000,
                     payload=budget_chunk_payload(sent + index))
        except OtaQueueFull as exc:
            refused += 1
            evidence.log("ota_backpressure", error=str(exc), refused=refused)
        target.poll(0.1)
        target.take_pending({PUSH_OTA_EVENT})
    target.collect(15.0)
    blocked = status(client)
    evidence.check("ota-remains-budget-blocked",
                   blocked["used"] == previous["used"] and status(target)["rx"] == target_before,
                   before=previous, after=blocked)

    target.take_pending({PUSH_ADVERT, PUSH_NEW_ADVERT})
    request_time = time.monotonic()
    advert_response = client.command(bytes([CMD_SEND_SELF_ADVERT, 1]))
    evidence.check("normal-advert-allocates-after-ota-cap",
                   advert_response == bytes([RESP_OK]), response=advert_response.hex(),
                   status=blocked)
    advert = wait_advert_from(target, client_info["pubkey_bytes"])
    after_advert = status(client)
    evidence.check("normal-advert-after-ota-cap",
                   after_advert["used"] == blocked["used"],
                   sender=client_info["pubkey"], received_frame=advert.hex(),
                   delay_seconds=time.monotonic() - request_time,
                   before=blocked, after=after_advert)
    evidence.check("airtime-two-percent-enforced",
                   after_advert["used"] <= 72000 and after_advert["used_limit"] == 72000,
                   sent=sent, refused=refused, observed_packet_cost_ms=packet_cost,
                   remaining_ms=after_advert["used_limit"] - after_advert["used"])


def run_configure(client, target, evidence):
    client_info = run_configure_client(client, evidence)
    target_info, target_status = configure_node(target, "OTA-LAB-TARGET")
    evidence.summary["measurements"]["configured"] = {
        **evidence.summary["measurements"]["configured"],
        "target": serializable_app_info(target_info),
        "target_status": target_status,
    }
    expected = (907525, 62500, 7, 5)
    evidence.check("default-radio-target",
                   (target_info["freq_khz"], target_info["bw_hz"], target_info["sf"], target_info["cr"]) == expected,
                   observed=serializable_app_info(target_info))
    return client_info, target_info


def run_configure_client(client, evidence):
    client_info, client_status = configure_node(client, "OTA-LAB-CLIENT")
    evidence.summary["measurements"]["configured"] = {
        "client": serializable_app_info(client_info),
        "client_status": client_status,
    }
    expected = (907525, 62500, 7, 5)
    evidence.check("default-radio-client",
                   (client_info["freq_khz"], client_info["bw_hz"], client_info["sf"], client_info["cr"]) == expected,
                   observed=serializable_app_info(client_info))
    evidence.log("path_hash_mode_configured", mode=2, bytes_per_hash=3,
                 radio_verification_pending=True)
    return client_info


def run_hardware_test(client, target, evidence, duty_timeout, staging_only=False, airtime_only=False):
    client_info, target_info = run_configure(client, target, evidence)

    require_ok(client, bytes([CMD_SEND_SELF_ADVERT, 1]))
    advert_ct = wait_raw_packet(
        target, lambda raw: len(raw) >= 34 and raw[0] >> 2 & 15 == 4
        and raw[2:34] == client_info["pubkey_bytes"])
    wait_advert(target)
    require_ok(target, bytes([CMD_SEND_SELF_ADVERT, 1]))
    advert_tc = wait_raw_packet(
        client, lambda raw: len(raw) >= 34 and raw[0] >> 2 & 15 == 4
        and raw[2:34] == target_info["pubkey_bytes"])
    wait_advert(client)
    evidence.check("three-byte-path-mode",
                   (advert_ct[1] >> 6) + 1 == 3 and (advert_tc[1] >> 6) + 1 == 3,
                   client_path_header=advert_ct[1], target_path_header=advert_tc[1],
                   physical_multi_hop_claim=False)
    evidence.check("bidirectional-advert-rf", True, frequency_khz=907525, bandwidth_hz=62500, sf=7, cr=5)

    if not staging_only and not airtime_only:
        run_transport_probes(client, target, client_info["pubkey_bytes"], evidence)
    if not airtime_only:
        run_signed_staging(client, target, evidence)
    if not staging_only:
        run_airtime_test(client, target, client_info, evidence, duty_timeout)
    evidence.summary["measurements"]["final"] = {
        "client": status(client),
        "target": status(target),
        "client_identity": client_info["pubkey"],
        "target_identity": target_info["pubkey"],
    }


def run_precedence_probe(client, target, client_public_key, evidence):
    # Avoid identical signed adverts when the board's RTC has not advanced.
    fresh_name = b"OTA-LAB-CLIENT-" + os.urandom(4).hex().encode("ascii")
    require_ok(client, bytes([CMD_SET_ADVERT_NAME]) + fresh_name)
    try:
        return observe_precedence_probe(client, target, client_public_key, evidence)
    finally:
        require_ok(client, bytes([CMD_SET_ADVERT_NAME]) + b"OTA-LAB-CLIENT")


def observe_precedence_probe(client, target, client_public_key, evidence):
    event_codes = {PUSH_ADVERT, PUSH_NEW_ADVERT, PUSH_OTA_EVENT}
    target.poll(0.2)
    target.take_pending(event_codes)
    require_ok(client, bytes([CMD_OTA_LAB, 0]))
    deadline = time.monotonic() + 15.0
    ordered = []
    observed_types = set()
    while time.monotonic() < deadline and len(observed_types) < 2:
        target.poll(0.2)
        for timestamp, payload in target.take_pending(event_codes):
            if payload[0] in (PUSH_ADVERT, PUSH_NEW_ADVERT):
                if payload[1:33] != client_public_key:
                    continue
                kind = "normal-advert"
            elif len(payload) >= 2 and payload[1] == OTA_ANNOUNCEMENT:
                kind = "ota-announcement"
            else:
                continue
            ordered.append((timestamp, kind, payload.hex()))
            observed_types.add(kind)
    evidence.check("normal-traffic-precedence",
                   len(observed_types) == 2 and ordered[0][1] == "normal-advert",
                   observed=ordered, expected_sender=client_public_key.hex())


def run_transport_probes(client, target, client_public_key, evidence):
    send_ota(client, ROUTE_FLOOD, OTA_ANNOUNCEMENT, 1001)
    event_ct = wait_ota_event(target, OTA_ANNOUNCEMENT)
    send_ota(target, ROUTE_FLOOD, OTA_ANNOUNCEMENT, 1002)
    event_tc = wait_ota_event(client, OTA_ANNOUNCEMENT)
    evidence.check("bidirectional-ota-rf", True, client_to_target=event_ct.hex(), target_to_client=event_tc.hex())

    run_precedence_probe(client, target, client_public_key, evidence)

    for node in (client, target):
        require_ok(node, bytes([CMD_OTA_CONTROL, OTA_SET_MODE, 0]))
        lease = bytes([CMD_OTA_CONTROL, OTA_DIRECT_LEASE]) + struct.pack("<II", 907525, 250000) + bytes([7, 5]) + struct.pack("<H", 1)
        require_ok(node, lease)
    time.sleep(3.0)
    direct_client = app_info(client)
    direct_target = app_info(target)
    evidence.check("direct-high-speed-lease-active",
                   direct_client["bw_hz"] == 250000 and direct_target["bw_hz"] == 250000,
                   client=serializable_app_info(direct_client),
                   target=serializable_app_info(direct_target))
    for sender, receiver, lease_id in ((client, target, 2001), (target, client, 2002)):
        before_lease = status(receiver)
        for subtype in (1, 2):
            send_ota(sender, ROUTE_DIRECT, OTA_LEASE, lease_id,
                     payload=lease_payload(subtype, lease_id))
            wait_ota_event(receiver, OTA_LEASE)
        after_lease = status(receiver)
        evidence.check(f"typed-lease-probe-{receiver.name}",
                       after_lease["bad"] == before_lease["bad"],
                       before=before_lease, after=after_lease)
    evidence.check("direct-high-speed-bidirectional", True, bandwidth_hz=250000,
                   route="direct-zero-hop", frequency_khz=907525, sf=7, cr=5,
                   remote_radio_negotiation_claim=False)

    before_bad = status(target)
    send_ota(client, ROUTE_DIRECT, OTA_ANNOUNCEMENT, 2100, namespace=0x0000)
    wait_ota_event(target, OTA_ANNOUNCEMENT)
    after_bad = status(target)
    evidence.check("corruption-rejection", after_bad["bad"] == before_bad["bad"] + 1,
                   before=before_bad, after=after_bad)

    remaining = 65.0 - 3.0
    evidence.log("lease_revert_wait", seconds=remaining)
    time.sleep(remaining)
    reverted_client = app_info(client)
    reverted_target = app_info(target)
    evidence.check("radio-lease-auto-revert",
                   reverted_client["bw_hz"] == 62500 and reverted_target["bw_hz"] == 62500,
                   client=serializable_app_info(reverted_client),
                   target=serializable_app_info(reverted_target))

    require_ok(target, bytes([CMD_OTA_CONTROL, OTA_ABORT]))
    require_ok(target, bytes([CMD_OTA_CONTROL, OTA_SET_MODE, 2]))
    campaign = 3001
    progression = []
    probes = (
        (OTA_ANNOUNCEMENT, announcement_payload(campaign)),
        (OTA_CENSUS, struct.pack(">IBIH", campaign, 0, 0, 1)),
        (OTA_CENSUS, struct.pack(">IBIH", campaign, 1, 0, 1)),
        (OTA_COHORT, struct.pack(">IHHH", campaign, 1, 1, 0)),
        (OTA_CENSUS, struct.pack(">IBIH", campaign, 1, 128, 1)),
        (OTA_MISSING, struct.pack(">III", campaign, 1, 1)),
    )
    for message_type, payload in probes:
        send_ota(client, ROUTE_FLOOD, message_type, campaign, payload=payload)
        wait_ota_event(target, message_type)
        progression.append({"type": message_type, "status": status(target)})
    fleet_before_abort = progression[-1]["status"]["fleet"]
    send_ota(client, ROUTE_FLOOD, OTA_ABORT_MESSAGE, campaign + 99, session=99, payload=bytes(5))
    wait_ota_event(target, OTA_ABORT_MESSAGE)
    fleet_after_abort = status(target)["fleet"]
    evidence.check("fleet-control-state-probes", len({row["status"]["fleet"] for row in progression}) >= 3,
                   progression=progression, full_fleet_update_claim=False)
    evidence.check("foreign-abort-rejection", fleet_after_abort == fleet_before_abort,
                   before=fleet_before_abort, after=fleet_after_abort)


def run_signed_staging(client, target, evidence):
    require_ok(target, bytes([CMD_OTA_CONTROL, OTA_ABORT]))
    image = bytes((index * 37 + 0x5A) & 0xFF for index in range(320))
    security_counter = 1
    send_ota(client, ROUTE_DIRECT, OTA_DESCRIPTOR, 4001,
             payload=descriptor_fragment(image, security_counter))
    wait_ota_event(target, OTA_DESCRIPTOR, timeout=60.0)
    descriptor_status = status(target)
    evidence.check("signed-descriptor-accepted",
                   descriptor_status["backend"] == 1 and descriptor_status["recv"] == 2,
                   status=descriptor_status, receiver_state_awaiting_authorization=2)

    authorization = struct.pack(">BIIH", 1, 1, 60000, 2)
    send_ota(client, ROUTE_DIRECT, 2, 4001, payload=authorization)
    wait_ota_event(target, 2)
    authorized_status = status(target)
    evidence.check("transfer-authorized", authorized_status["recv"] == 3,
                   status=authorized_status, receiver_state_receiving=3)

    first_chunk = chunk_payload(image, 0)
    send_ota(client, ROUTE_DIRECT, OTA_CHUNK, 4001, payload=first_chunk)
    wait_ota_event(target, OTA_CHUNK)
    progress_before_resume = status(target)
    time.sleep(1.0)
    target.take_pending({PUSH_RAW_LOG})
    send_ota(client, ROUTE_DIRECT, OTA_CHUNK, 4001, payload=first_chunk)
    duplicate_raw = bytes([ROUTE_DIRECT | PAYLOAD_TYPE_LORA_OTA << 2, 0x80]) + \
        ota_envelope(OTA_CHUNK, 4001, 1, 1, first_chunk)
    wait_raw_packet(target, lambda raw: raw == duplicate_raw)
    progress_after_resume = status(target)
    evidence.check("radio-duplicate-chunk-rejection",
                   progress_after_resume["rx"] == progress_before_resume["rx"] and
                   progress_after_resume["recv"] == 3 and
                   progress_after_resume["bad"] == progress_before_resume["bad"],
                   before=progress_before_resume, after=progress_after_resume,
                   receiver_duplicate_handler_claim=False)
    chunk_count = (len(image) + OTA_CHUNK_BYTES - 1) // OTA_CHUNK_BYTES
    for chunk_index in range(1, chunk_count):
        send_ota(client, ROUTE_DIRECT, OTA_CHUNK, 4001,
                 payload=chunk_payload(image, chunk_index))
        wait_ota_event(target, OTA_CHUNK)
    commit = struct.pack(">IBI", 4001, 1, security_counter)
    send_ota(client, ROUTE_DIRECT, OTA_COMMIT, 4001, payload=commit)
    wait_ota_event(target, OTA_COMMIT)
    staged = status(target)
    evidence.check("signed-rf-qspi-stage",
                   progress_before_resume["recv"] == 3 and
                   progress_after_resume["recv"] == 3 and
                   staged["recv"] == 6,
                   before_resume=progress_before_resume,
                   after_resume=progress_after_resume,
                   staged=staged,
                   receiver_state_complete_staging=6,
                   bytes_staged=len(image), sha256=hashlib.sha256(image).hexdigest(),
                   reboot_resume_claim=False,
                   install_or_boot_claim=False)

def resolve_roles(evidence, client_only=False):
    """Resolve each lab role to a live board and record the evidence."""
    roles = [CLIENT_ROLE] if client_only else [CLIENT_ROLE, TARGET_ROLE]
    resolved = {}
    for role in roles:
        device = lab_device.resolve(role, mode=lab_device.MODE_APP)
        resolved[role] = device
        evidence.check(f"device-{role}", True, role=role, serial=device.serial,
                       path=str(device.by_id), resolved=os.path.realpath(device.by_id))
    serials = {role: d.serial for role, d in resolved.items()}
    evidence.check("roles-are-distinct", len(set(serials.values())) == len(serials),
                   **serials)
    return resolved


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--client-only", action="store_true")
    parser.add_argument("--configure-only", action="store_true")
    parser.add_argument("--monitor-seconds", type=float, default=0)
    parser.add_argument("--duty-timeout", type=float, default=420)
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--staging-only", action="store_true")
    scope.add_argument("--airtime-only", action="store_true")
    args = parser.parse_args()
    if args.client_only and not (args.configure_only or args.monitor_seconds > 0):
        parser.error("--client-only requires --configure-only or --monitor-seconds")
    if (args.staging_only or args.airtime_only) and (args.configure_only or args.monitor_seconds > 0):
        parser.error("a qualification scope cannot be combined with configuration or monitoring")

    evidence = Evidence(args.artifact_dir)
    client = target = None
    error = None
    try:
        devices = resolve_roles(evidence, client_only=args.client_only)
        client_device = devices[CLIENT_ROLE]
        client = FramedSerial(f"{CLIENT_ROLE}-{client_device.serial}",
                              str(client_device.by_id), evidence)
        if not args.client_only:
            target_device = devices[TARGET_ROLE]
            target = FramedSerial(f"{TARGET_ROLE}-{target_device.serial}",
                                  str(target_device.by_id), evidence)
        time.sleep(2.0)
        if args.monitor_seconds > 0:
            deadline = time.monotonic() + args.monitor_seconds
            while time.monotonic() < deadline:
                client.poll(0.05)
                if target:
                    target.poll(0.05)
        elif args.configure_only:
            if args.client_only:
                run_configure_client(client, evidence)
            else:
                run_configure(client, target, evidence)
        else:
            run_hardware_test(client, target, evidence, args.duty_timeout,
                              args.staging_only, args.airtime_only)
    except Exception as exc:
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
