#!/usr/bin/env python3
"""Signed, single-target HOST HARDWARE campaign; stage never auto-commits.

probe-peer is a separate, explicit ordinary RF test, usable on stock firmware:

    python3 scripts/ota_signed_lab.py --artifact-dir .tmp/new-normal-peer \
      probe-peer --probe-timeout 30

It reads approved-role identities/settings/ACL, drains pre-request serial
events, requests the target's ordinary zero-hop advert and requires a fresh
native advert push or signature-verified raw advert bound to the actual full
target public key. It repeats
the configuration/ACL readbacks and writes normal-peer.json. This is NOT
read-only: an ordinary RF advert is explicitly requested. It never queries OTA
status/floor, signs/caches an image, grants permissions, aborts, commits or
reboots. The result proves only target-to-client ordinary peer reception,
not bidirectional, multihop, airtime fairness or signed OTA qualification.
Client path mode 2 is required; target path mode is not a prerequisite and is
not claimed observed when absent from the existing target inspection API.
The normal APP_START handshake is repeated before the RF request. Native
0x80/0x8A advert notifications are preferred. Firmware may suppress them after
its duplicate/contact timestamp filters; APP_START does not override those.
A fresh 0x88 LOG_RX is eligible only after exact packet/path/app-data parsing
and Ed25519 verification of the existing signed advert against the live target
public key. Evidence distinguishes host signature verification from observed
companion PKI acceptance. Freshness is host receive-after-request, NOT proof
of fresh emission, replay resistance or a challenge response.
--probe-timeout bounds the entire probe (default 30s); the global --timeout,
if shorter, remains the outer bound. Evidence directories must be new.
Up to three ordinary advert requests are made, at least two seconds after the
previous ACK, stopping on authenticated reception. No ACK or counter delta
qualifies reception. Before/after packet and radio stats use normal read-only
CMD_GET_STATS (56, subtypes 2/1) and stats-packets/stats-radio CLI queries.
Unavailable stats are explicit; aggregates cannot identify an individual
advert or diagnose saturation. Part of the same deadline is reserved for the
after-stats and preserved-configuration reads. No power/clock setters are used.

MAIN integration handoff (do not retire the legacy transport refusal):

    OTA_SIGNED_LAB_MODE ?= directed
    OTA_SIGNED_LAB_DUTY ?= 2000
    OTA_SIGNED_LAB_CHANNEL ?= 255
    OTA_SIGNED_LAB_TIMEOUT ?= 86400
    OTA_SIGNED_LAB_REBOOT_TIMEOUT ?= 120
    OTA_SIGNED_LAB_TRIAL_TIMEOUT ?= 30
    OTA_SIGNED_LAB_INSTALL_TIMEOUT ?= 300
    OTA_SIGNED_LAB_EXTRA ?=
    .PHONY: qualify-xiao-nrf52-signed-stage qualify-xiao-nrf52-signed-commit
    qualify-xiao-nrf52-signed-stage: tmpdir
        python3 scripts/ota_signed_lab.py --artifact-dir "$(OTA_LAB_ARTIFACT_DIR)" \
          --timeout "$(OTA_SIGNED_LAB_TIMEOUT)" stage \
          --manifest "$(OTA_UPLOAD_MANIFEST)" --image "$(OTA_UPLOAD_IMAGE)" \
          --image-sha256 "$(OTA_SIGNED_LAB_IMAGE_SHA256)" \
          --counter "$(OTA_SIGNED_LAB_COUNTER)" \
          --provenance "$(OTA_SIGNED_LAB_PROVENANCE)" \
          --commissioning-evidence "$(OTA_SIGNED_LAB_COMMISSIONING)" \
          --mode "$(OTA_SIGNED_LAB_MODE)" --channel "$(OTA_SIGNED_LAB_CHANNEL)" \
          --duty-milli-percent "$(OTA_SIGNED_LAB_DUTY)" $(OTA_SIGNED_LAB_EXTRA)
    qualify-xiao-nrf52-signed-commit: tmpdir
        python3 scripts/ota_signed_lab.py --artifact-dir "$(OTA_LAB_ARTIFACT_DIR)" \
          --timeout "$(OTA_SIGNED_LAB_TIMEOUT)" commit --qualified-commit \
          --ready-record "$(OTA_SIGNED_LAB_READY_RECORD)" \
          --manifest "$(OTA_UPLOAD_MANIFEST)" --image "$(OTA_UPLOAD_IMAGE)" \
          --image-sha256 "$(OTA_SIGNED_LAB_IMAGE_SHA256)" \
          --counter "$(OTA_SIGNED_LAB_COUNTER)" \
          --provenance "$(OTA_SIGNED_LAB_PROVENANCE)" \
          --commissioning-evidence "$(OTA_SIGNED_LAB_COMMISSIONING)" \
          --reboot-timeout "$(OTA_SIGNED_LAB_REBOOT_TIMEOUT)" \
          --trial-timeout "$(OTA_SIGNED_LAB_TRIAL_TIMEOUT)" \
          --install-timeout "$(OTA_SIGNED_LAB_INSTALL_TIMEOUT)"

Use literal TABs for the two Make recipes. Each invocation needs a NEW artifact
directory. Pass immutable qualified repeater BIN/canonical59, explicit SHA256,
counter, build/package provenance and independently approved commissioning
evidence. Existing mesh ACLs only: no key export, grants, auth registry, nonce
scheme, encryption, flash/reset/power commands, or automatic ABORT. Commissioning
is NOT performed here. The original public-key baseline was not captured;
capture current identities before any candidate install. Never claim that the
original application image was recovered.

Stage writes baseline.json BEFORE caching and ready.json ONLY after fresh,
full-image READY, with no COMMIT. Resume a timed-out attempt using the same
inputs and --baseline-record path/to/baseline.json; evidence and durable progress
are preserved. Conflicts fail, never force-overwrite. A different local cache
needs an independently explicit ota_uploader.py abort-cache first. Only a fresh,
valid LOCAL ABORTED snapshot consistent with the companion lifecycle enables
CacheBegin reupload=1, after writing the new baseline. All other caches remain
locked to their candidate. This runner never sends ABORT and has no override.

Commit consumes ready.json, rechecks identities/config/ACL/floor and fresh READY,
then sends exactly one explicit COMMIT. It observes USB disconnect/re-enumeration
and application-managed trial/confirmation reboot(s), never requests a reset.
Fresh remote Trial AND Installed, bound to the actual target/manifest/counter
(signed provenance checked by the application), PLUS verified running
SHA256/counter/floor are required; COMMIT ACK and physical text Trial alone are
not proof. Missing fresh remote Trial does not stop Installed/preservation/peer
evidence collection: installed.json records remote_trial_not_observed and
remote_install_qualified=false, then the strict qualification command fails.
Reboot/trial/install timeouts are HOST observation bounds, not claimed device
capabilities. A target that does not reboot after remote COMMIT is explicitly
BLOCKED within --reboot-timeout (default 120s); no USB reset fallback exists.
Manual USB reboot would be assisted commissioning, not remote-install
qualification. Firmware must first wire a deferred reboot after a proven,
durable individual remote COMMIT, never after READY/rejection/uncertain writes.

Run directed/direct/background sequentially with increasing explicit counters,
new artifact directories, and separately qualified commits. Background requires
an EXISTING configured channel index (0..254); no fleet/multihop claim. Direct
requests 908525 kHz/60000 ms; production uploader firmware repeats bounded leases
only through restored normal service, a fresh handshake and bitmap resume, never
indefinitely extending an active lease. The app owns SF5, not this host.
USB-local driver-applied radio/budget samples are collected before caching,
between remote status polls, at READY and after restoration. These are not PHY
register readbacks. The status ABI exposes durable bitmap counts, not bitmap
bits or the direct handshake token/ACK; those limits remain explicit.
After READY wait a full lease before testing
ordinary peer advert reception. Default 2000 milli-percent is 2%; explicitly
passing 95000 or 100000 AND --supervised-full-image-smoke is 95% or 100%
supervised smoke, NEVER 2% acceptance. The approved normal pair may use
62.5 kHz or 250 kHz bandwidth at 907.525 MHz/SF7/CR5/path3; both peers must
agree and retain their actual captured configuration. This runner does not
configure radio settings. Sampled software budgets and completed TX accounting
do not establish a continuous physical duty guarantee or fairness. A 2% sampled
window needs complete periodic coverage of at least a full window; before/after
totals alone are incomplete. Timeouts, lost accounting and driver failures reject
qualification. Ordinary peer reception during on-mesh transfer is independently
bracketed by fresh candidate progress, not inferred from TX totals.
No multihop, fleet, power-cut, rollback or full-configuration-media qualification.
MAIN must close the current commissioning/recovery gate and use qualified role
packages before hardware execution; bench application readbacks are not OTA
qualification.
The earlier frozen uploader snapshot had CacheBegin owner32 and remote COMMIT
no-snapshot echo ABI mismatches; MAIN must use the owner's corrected production
helper before running hardware. The receiver's missing automatic remote-COMMIT
reboot and N1 pre-admission COMMIT rejection/reflash recovery remain explicit
integration prerequisites. This runner patches no protocol, resets no board
and never bypasses failed or uncertain admission/commit outcomes.
"""

import argparse
from dataclasses import dataclass
import errno
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import lab_device
import ota_rf_lab as lab
import ota_uploader as ota


APPROVED = lab.APPROVED_ADMIN_PAIR
APPROVED_RADIOS = ((907525, 62500, 7, 5), (907525, 250000, 7, 5))
RECORD_VERSION = 1
ACTIVE_PHASES = {"erasing", "receiving", "verifying", "ready"}
PUSH_ADVERT = 0x80
PUSH_LOG_RX_DATA = 0x88
PUSH_NEW_ADVERT = 0x8A
PEER_PUSH_CODES = {PUSH_ADVERT, PUSH_LOG_RX_DATA, PUSH_NEW_ADVERT}
CMD_GET_STATS = 56
RESP_STATS = 24
PACKET_STATS_FIELDS = ("recv", "sent", "flood_tx", "direct_tx", "flood_rx", "direct_rx", "recv_errors")
BOOT_PATTERN = re.compile(
    r"boot=(unknown|trial|confirmed|failed) "
    r"phase=(unknown|idle|erasing|receiving|verifying|ready|commit-pending|trial|installed|aborted|failed|cache-sealed) "
    r"floor=(unknown|[0-9]+) counter=([0-9]+) verified=([01]) image=(unknown|[0-9a-f]{64})")


class QualificationError(ota.UploaderError):
    pass


def require(condition, message):
    if not condition:
        raise QualificationError(message)


def write_record(path, record):
    with Path(path).open("x", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")


def read_record(path, kind):
    record = json.loads(Path(path).read_text(encoding="utf-8"))
    require(record.get("version") == RECORD_VERSION and record.get("kind") == kind,
            f"invalid {kind} qualification record")
    require(record.get("serials") == APPROVED, "record does not belong to the approved pair")
    return record


@dataclass(frozen=True)
class Candidate:
    canonical: bytes
    image: bytes
    metadata: dict

    @property
    def manifest_hash(self):
        return hashlib.sha256(self.canonical).digest()

    @property
    def counter(self):
        return self.metadata["counter"]

    @property
    def blocks(self):
        return (len(self.image) + ota.BLOCK_BYTES - 1) // ota.BLOCK_BYTES


def load_candidate(args):
    canonical, image = args.manifest.read_bytes(), args.image.read_bytes()
    ota.validate_image(canonical, image)
    family, variant, role, address, size = struct.unpack_from(">HHBII", canonical)
    counter, capabilities, format_id, key_id, algorithm = struct.unpack_from(">IIHHH", canonical, 45)
    require((family, variant, role, address) == (0x584E, 0x3430, 1, 0x27000),
            "candidate must be an XIAO nRF52840 role-1 repeater application at 0x27000")
    require(8 <= size <= 0xED000 - address, "candidate does not fit the application region")
    stack, reset = struct.unpack_from("<II", image)
    require(0x20000000 < stack <= 0x20040000 and stack % 4 == 0
            and reset & 1 and address <= (reset & ~1) < address + size,
            "candidate has invalid application vectors, not a runnable full application")
    require(counter == args.counter and 0 < counter <= 0xFFFFFFFF,
            "manifest counter must match the explicit nonzero --counter")
    require(capabilities == 1 and format_id == 1 and key_id > 0 and algorithm == 1,
            "unsupported manifest capability/format/key/algorithm")
    digest = hashlib.sha256(image).hexdigest()
    require(re.fullmatch(r"[0-9a-fA-F]{64}", args.image_sha256) is not None
            and digest == args.image_sha256.lower(), "immutable BIN SHA256 mismatch")
    require(args.provenance.strip() and args.commissioning_evidence.strip(),
            "explicit immutable-image provenance and approved commissioning evidence are required")
    return Candidate(canonical, image, {
        "manifest_sha256": hashlib.sha256(canonical).hexdigest(), "image_sha256": digest,
        "image_bytes": len(image), "counter": counter, "provenance": args.provenance,
        "commissioning_evidence": args.commissioning_evidence,
    })


def boot_status(text):
    match = BOOT_PATTERN.fullmatch(text)
    require(match is not None, f"unknown or malformed lifecycle status: {text!r}")
    boot, phase, floor, counter, verified, image = match.groups()
    require(floor == "unknown" or int(floor) <= 0xFFFFFFFF, "invalid floor counter")
    require(int(counter) <= 0xFFFFFFFF, "invalid lifecycle counter")
    require((verified == "1") == (image != "unknown"), "inconsistent running-image proof")
    return {"boot": boot, "phase": phase, "floor": None if floor == "unknown" else int(floor),
            "counter": int(counter), "verified": verified == "1", "image": image}


def target_status(target, evidence, deadline):
    remaining = deadline - time.monotonic()
    require(remaining > 0, "campaign deadline expired")
    status = boot_status(target.command("ota status", timeout=min(5, remaining)))
    evidence.log("target_lifecycle", **status)
    return status


def check_floor(status, candidate):
    require(status["floor"] is not None, "target confirmed-counter floor is unproven")
    require(status["boot"] not in ("trial", "failed")
            and status["phase"] not in ("trial", "failed", "aborted", "commit-pending"),
            "target has an active trial, failed/ABORTed candidate or pending commit; preserve it")
    require(candidate.counter > status["floor"], "candidate counter must exceed the proven floor")
    if status["phase"] in ACTIVE_PHASES:
        require(status["counter"] == candidate.counter, "target has a conflicting candidate counter")
    elif status["phase"] == "installed":
        require(status["boot"] == "confirmed" and status["verified"]
                and status["counter"] == status["floor"], "baseline Installed is not proven")
    else:
        require(status["phase"] in ("idle", "unknown") and status["counter"] == 0
                and status["boot"] == "unknown" and status["floor"] == 0,
                "unknown target baseline; independent commissioning closure required")


def profile(args):
    require(args.duty_milli_percent in (2000, 95000, 100000),
            "use 2000 (2%) or explicit 95000/100000 supervised smoke")
    require(args.duty_milli_percent == 2000 or args.supervised_full_image_smoke,
            "95%/100% smoke requires --supervised-full-image-smoke")
    frequency, lease = (908525, 60000) if args.mode == "direct" else (0, 0)
    body = ota.start_body(args.mode, args.channel, frequency, lease, args.duty_milli_percent)
    return body, {"mode": args.mode, "channel": args.channel, "frequency_khz": frequency,
                  "lease_ms": lease, "duty_milli_percent": args.duty_milli_percent,
                  "budget_class": "2_percent_requested_not_measured" if args.duty_milli_percent == 2000
                  else f"{args.duty_milli_percent // 1000}_percent_supervised_smoke_not_2_percent_acceptance"}


def approved_device(role):
    device = lab_device.resolve(role, mode=lab_device.MODE_APP)
    require(device.serial == APPROVED[role], f"refusing unapproved {role} USB serial")
    return device


class DeadlineSerial:
    """Bound ordinary helper commands to the same campaign deadline."""

    def __init__(self, node, deadline):
        self.node, self.deadline = node, deadline

    def __getattr__(self, name):
        return getattr(self.node, name)

    def remaining(self, timeout):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("campaign deadline expired; progress preserved")
        return min(timeout, remaining)

    def command(self, payload, **options):
        options["timeout"] = self.remaining(options.get("timeout", 5))
        return self.node.command(payload, **options)

    def get_acl(self):
        return self.node.get_acl(timeout=self.remaining(5))

    def poll(self, timeout=0):
        return self.node.poll(self.remaining(timeout))


class Pair:
    def __init__(self, evidence, deadline):
        self.evidence, self.deadline = evidence, deadline
        self.client = self.target = None
        # Resolve BOTH before opening either; environment overrides cannot widen scope.
        devices = {role: approved_device(role) for role in APPROVED}
        try:
            self.client = DeadlineSerial(
                lab.FramedSerial("client", str(devices["client"].by_id), evidence), deadline)
            self.target = DeadlineSerial(
                lab.RepeaterSerial("target", str(devices["target"].by_id), evidence), deadline)
        except BaseException:
            self.close()
            raise

    def close(self):
        for node in (self.client, self.target):
            if node is not None:
                node.close()

    def reenumerate(self, deadline, transport_disconnected=False):
        self.target.close()
        self.target = None
        absent = transport_disconnected
        if absent:
            self.evidence.log("target_disconnect", source="serial_endpoint")
        while time.monotonic() < deadline:
            present = any(d.serial == APPROVED["target"] and d.mode == lab_device.MODE_APP
                          for d in lab_device.discover())
            if not present and not absent:
                absent = True
                self.evidence.log("target_disconnect", source="usb_discovery")
            if absent and present:
                device = approved_device("target")
                self.target = DeadlineSerial(
                    lab.RepeaterSerial("target", str(device.by_id), self.evidence), self.deadline)
                self.evidence.log("target_reenumerated", serial=device.serial, path=str(device.by_id))
                return
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        raise TimeoutError("target did not observably disconnect and re-enumerate before deadline")


def aborted_local_cache(local, client_boot, since):
    require(local.result == ota.Result.OK and local.valid and local.target == ota.LOCAL_TARGET
            and not local.flags & ota.REMOTE and local.phase == ota.Phase.ABORTED
            and local.fresh_since(since, time.monotonic()) and local.manifest_hash != bytes(32)
            and local.counter > 0 and local.total > 0,
            "local ABORT is missing, stale, unproven or wrong-scope; no replacement permitted")
    require(client_boot["boot"] not in ("trial", "failed") and client_boot["phase"] == "aborted"
            and client_boot["counter"] == local.counter,
            "local ABORT snapshot disagrees with companion lifecycle; no replacement permitted")


def capture(pair, candidate, evidence, deadline, uploader=None):
    client = lab.serializable_app_info(lab.companion_info(pair.client))
    target = lab.repeater_info(pair.target)
    require(client["pubkey"] != target["pubkey"], "client and target public keys collide")
    for role, info in (("client", client), ("target", target)):
        require(tuple(info[k] for k in ("freq_khz", "bw_hz", "sf", "cr")) in APPROVED_RADIOS
                and info["path_hash_mode"] == lab.PATH_HASH_MODE,
                f"{role} is not configured for approved 907.525/BW62.5 or BW250/SF7/CR5/path3")
    require(tuple(client[k] for k in ("freq_khz", "bw_hz", "sf", "cr"))
            == tuple(target[k] for k in ("freq_khz", "bw_hz", "sf", "cr")),
            "approved client and target normal radio configurations disagree")
    acl = pair.target.get_acl()
    require(acl.get(client["pubkey"], 0) & 3 == 3,
            "actual companion public key lacks existing target ADMIN ACL; no grant attempted")
    client_frame = pair.client.command(bytes([lab.CMD_OTA_CONTROL, 0]), expected=(29, lab.RESP_ERR))
    require(client_frame[:1] == b"\x1d", "companion lifecycle readback unavailable")
    client_boot = boot_status(client_frame[1:].decode("ascii"))
    require(client_boot["boot"] not in ("trial", "failed")
            and client_boot["phase"] not in ("trial", "commit-pending", "failed"),
            "companion current trial/candidate prevents qualification")
    status = target_status(pair.target, evidence, deadline)
    check_floor(status, candidate)
    local = None
    if uploader is not None:
        since = time.monotonic()
        local = uploader.status(timeout=uploader.remaining(deadline))
        if local.phase == ota.Phase.ABORTED or client_boot["phase"] == "aborted":
            aborted_local_cache(local, client_boot, since)
    require(client_boot["phase"] != "aborted" or local is not None,
            "companion current trial/candidate prevents qualification")
    baseline = {"version": RECORD_VERSION, "kind": "baseline", "serials": APPROVED,
                "candidate": candidate.metadata, "client": client, "target": target,
                "acl": acl, "floor": status["floor"], "target_status": status,
                "client_status": client_boot,
                "local_cache_before": None if local is None else local.summary(),
                "captured_at": lab.utc_now(), "original_public_key_baseline_captured": False}
    evidence.log("baseline_capture", **baseline)
    return baseline


def preserved(before, after):
    require(before["candidate"] == after["candidate"], "candidate/provenance differs from saved baseline")
    for field in ("client", "target", "acl", "floor"):
        require(before[field] == after[field], f"{field} differs from saved baseline; preserve progress")


def bound_snapshot(reply, candidate, target, complete=False):
    require(reply.valid and reply.target == target and bool(reply.flags & ota.REMOTE) == (target != ota.LOCAL_TARGET),
            "missing or wrong-scope OTA snapshot")
    require(reply.manifest_hash == candidate.manifest_hash and reply.counter == candidate.counter,
            "conflicting candidate/cache; explicit separate local ABORT required before replacement")
    require(reply.total == candidate.blocks, "durable block total differs from the full immutable image")
    if complete:
        require(reply.received == candidate.blocks, "full-image durable blocks are incomplete")


def verified_raw_advert(frame, target_key):
    """Decode Packet::writeTo and verify Mesh::createAdvert's existing signature."""
    if len(frame) < 5 or frame[0] != PUSH_LOG_RX_DATA:
        raise ValueError("not a complete LOG_RX frame")
    raw = frame[3:]  # LOG_RX's code, signed SNR*4 and RSSI are not part of Packet.
    header = raw[0]
    if header >> 6 != 0 or (header >> 2) & 15 != 4:
        raise ValueError("not a version-1 ordinary advertisement")
    route = header & 3
    offset = 5 if route in (0, 3) else 1
    if len(raw) <= offset:
        raise ValueError("truncated packet transport/path header")
    encoded_path = raw[offset]
    hash_size, count = (encoded_path >> 6) + 1, encoded_path & 63
    path_bytes = hash_size * count
    if hash_size == 4 or path_bytes > 64:
        raise ValueError("invalid packet path encoding")
    offset += 1 + path_bytes
    body = raw[offset:]
    if not 102 <= len(body) <= 132:
        raise ValueError("truncated or oversized signed advert body")
    public_key, emitted_time, signature, app = body[:32], body[32:36], body[36:100], body[100:]
    if public_key != target_key:
        raise ValueError("wrong peer full public key")
    name_offset = 1 + (8 if app[0] & 0x10 else 0) + (2 if app[0] & 0x20 else 0) \
        + (2 if app[0] & 0x40 else 0)
    if app[0] & 15 != 2 or not app[0] & 0x80 or name_offset >= len(app):
        raise ValueError("invalid or unnamed repeater advert data")
    name = app[name_offset:].decode("utf-8")
    if "\x00" in name or any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
        raise ValueError("malformed signed advert name")
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, public_key + emitted_time + app)
    return {"target": public_key.hex(), "advert_timestamp": struct.unpack("<I", emitted_time)[0],
            "advert_name": name, "route_type": route, "path_hash_size": hash_size,
            "path_hash_count": count, "signature_verified": True,
            "reported_snr_db": struct.unpack("b", frame[1:2])[0] / 4,
            "reported_rssi_dbm": struct.unpack("b", frame[2:3])[0],
            "verification_source": "MeshCore_Ed25519_pubkey_timestamp_app_data"}


def normal_peer_stats(pair, evidence, deadline, phase):
    snapshots = {}
    for role, node in (("client", pair.client), ("target", pair.target)):
        snapshots[role] = {}
        for subtype, kind in ((2, "packets"), (1, "radio")):
            row = snapshots[role][kind] = {"available": False, "aggregate_only_not_peer_proof": True}
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("probe deadline expired; no stats request sent")
                if role == "client":
                    request = bytes([CMD_GET_STATS, subtype])
                    row["request_hex"] = request.hex()
                    frame = node.command(request, expected=(RESP_STATS, lab.RESP_ERR),
                                         timeout=min(0.5, remaining))
                    row["response_hex"] = frame.hex()
                    expected_size = 30 if subtype == 2 else 14
                    if len(frame) != expected_size or frame[:2] != bytes([RESP_STATS, subtype]):
                        raise ValueError("unsupported, refused or malformed normal stats reply")
                    if subtype == 2:
                        values = dict(zip(PACKET_STATS_FIELDS, struct.unpack("<7I", frame[2:])))
                    else:
                        noise, rssi, snr, tx, rx = struct.unpack("<hbbII", frame[2:])
                        values = {"noise_floor": noise, "last_rssi": rssi, "last_snr": snr / 4,
                                  "tx_air_secs": tx, "rx_air_secs": rx}
                else:
                    row["command"] = "stats-" + kind
                    row["response_text"] = node.command(row["command"], timeout=min(0.5, remaining))
                    values = json.loads(row["response_text"])
                    if not isinstance(values, dict):
                        raise ValueError("normal stats reply is not an object")
                    fields = PACKET_STATS_FIELDS if subtype == 2 else (
                        "noise_floor", "last_rssi", "last_snr", "tx_air_secs", "rx_air_secs")
                    if set(values) != set(fields):
                        raise ValueError("unsupported or incomplete normal stats fields")
                    if any(type(value) not in (int, float) or not math.isfinite(value)
                           for value in values.values()):
                        raise ValueError("invalid normal stats values")
                    counts = fields if subtype == 2 else ("tx_air_secs", "rx_air_secs")
                    if any(type(values[field]) is not int or not 0 <= values[field] <= 0xFFFFFFFF
                           for field in counts):
                        raise ValueError("invalid normal stats counters")
                row.update(available=True, values=values)
            except (TimeoutError, OSError, ValueError) as exc:
                row["error"] = f"{type(exc).__name__}: {exc}"
            evidence.log("normal_peer_stats_readback", node=role, phase=phase, kind=kind, **row)
    return snapshots


def ordinary_peer(pair, target_key, evidence, deadline):
    session = lab.serializable_app_info(lab.app_info(pair.client))
    evidence.log("ordinary_peer_session_started", client=session["pubkey"],
                 target=target_key.hex(), protocol="CMD_APP_START")
    drain_peer_events(pair.client, evidence, deadline)
    since = time.monotonic()
    requests = evidence.summary["measurements"]["ordinary_peer_requests"] = []
    raw_witness, native_wait_until = None, None

    def request_advert():
        if time.monotonic() >= deadline:
            raise TimeoutError("peer deadline expired; no advert request sent")
        row = {"attempt": len(requests) + 1, "command": "advert.zerohop", "target": target_key.hex(),
               "request_monotonic": time.monotonic(), "rf_request_attempted": True, "ack_is_peer_proof": False}
        requests.append(row)
        evidence.log("ordinary_peer_advert_requested", **row)
        probe_record = evidence.summary["measurements"].get("normal_peer_probe")
        if probe_record is not None:
            probe_record["rf_request_attempted"] = True
        lab.require_repeater_ok(pair.target, "advert.zerohop", expected="OK - zerohop advert sent")
        row["ack_monotonic"] = time.monotonic()
        evidence.log("ordinary_peer_advert_ack", **row)
        return row["ack_monotonic"] + 2

    def received(witness):
        witness["elapsed_seconds"] = time.monotonic() - since
        witness["attempts_requested"] = len(requests)
        evidence.log("ordinary_peer_advert_received", **witness)
        return witness

    next_request = request_advert()
    while time.monotonic() < deadline:
        pair.client.poll(min(0.1, max(0, deadline - time.monotonic())))
        for timestamp, frame in pair.client.take_pending(PEER_PUSH_CODES):
            if frame[0] == PUSH_LOG_RX_DATA:
                if timestamp < since:
                    evidence.log("ordinary_peer_raw_advert_ignored", frame_hex=frame.hex(), reason="stale",
                                 received_monotonic=timestamp, request_monotonic=since)
                    continue
                try:
                    authenticated = verified_raw_advert(frame, target_key)
                    if authenticated["route_type"] != 2 or authenticated["path_hash_count"] != 0:
                        raise ValueError("not the requested zero-hop direct advert")
                except (ValueError, InvalidSignature) as exc:
                    evidence.log("ordinary_peer_raw_advert_ignored", frame_hex=frame.hex(),
                                 reason="signature_invalid" if isinstance(exc, InvalidSignature) else str(exc),
                                 received_monotonic=timestamp, request_monotonic=since,
                                 authenticated_peer_proof=False)
                    continue
                raw_witness = {**authenticated, "frame_hex": frame.hex(), "code": frame[0],
                               "request_monotonic": since, "received_monotonic": timestamp,
                               "fresh_after_request": True, "source": "host_verified_signed_advert",
                               "companion_pki_acceptance_observed": False,
                               "emission_freshness_verified": False, "multihop_verified": False}
                if native_wait_until is None:
                    native_wait_until = min(deadline, time.monotonic() + 1)
                evidence.log("ordinary_peer_raw_advert_signature_verified", **raw_witness)
                continue
            valid_shape = (frame[0] == PUSH_ADVERT and len(frame) == 33
                           or frame[0] == PUSH_NEW_ADVERT and len(frame) == 148 and frame[33] == 2)
            if timestamp >= since and valid_shape and frame[1:33] == target_key:
                witness = {"target": target_key.hex(), "frame_hex": frame.hex(), "code": frame[0],
                           "request_monotonic": since, "received_monotonic": timestamp,
                           "fresh_after_request": True, "source": "companion_advert_push",
                           "companion_pki_acceptance_observed": True,
                           "emission_freshness_verified": False, "multihop_verified": False}
                if raw_witness is not None:
                    witness["signed_raw_advert"] = raw_witness
                return received(witness)
            evidence.log("ordinary_peer_advert_ignored", frame_hex=frame.hex(),
                         received_monotonic=timestamp, request_monotonic=since,
                         expected_target=target_key.hex(),
                         reason="malformed" if not valid_shape else
                         "stale" if timestamp < since else "wrong_peer")
        if raw_witness is not None and time.monotonic() >= native_wait_until:
            return received(raw_witness)
        if raw_witness is None and len(requests) < 3 and time.monotonic() >= next_request:
            if time.monotonic() < deadline:
                next_request = request_advert()
    if raw_witness is not None:
        return received(raw_witness)
    raise TimeoutError("no fresh ordinary advert from the actual target on the restored mesh")


def drain_peer_events(client, evidence, deadline):
    while time.monotonic() < deadline:
        before_count = len(client.pending)
        before_buffer = bytes(getattr(client, "buffer", b""))
        client.poll(min(0.05, max(0, deadline - time.monotonic())))
        after_count = len(client.pending)
        after_buffer = bytes(getattr(client, "buffer", b""))
        for timestamp, frame in client.take_pending(PEER_PUSH_CODES):
            evidence.log("normal_peer_pre_request_discard", frame_hex=frame.hex(),
                         received_monotonic=timestamp, peer_proof=False)
        if before_count == after_count and before_buffer == after_buffer:
            require(not after_buffer, "incomplete pre-request serial frame; fresh peer event is unproven")
            return
    raise TimeoutError("companion serial did not become quiet before the normal peer request")


def normal_peer_configuration(pair, evidence):
    inspected = lab.run_inspect_configuration(pair.client, pair.target, evidence)
    nodes = inspected["nodes"]
    for role, info in nodes.items():
        require(tuple(info[k] for k in ("freq_khz", "bw_hz", "sf", "cr")) in APPROVED_RADIOS,
                f"{role} has an unapproved normal radio configuration")
    require(nodes["client"].get("path_hash_mode") == lab.PATH_HASH_MODE,
            "client has an unapproved or unavailable normal path hash mode; requires mode 2")
    evidence.log("normal_peer_path_observability", client_path_hash_mode=nodes["client"]["path_hash_mode"],
                 target_path_hash_mode_observed="path_hash_mode" in nodes["target"])
    require(tuple(nodes["client"][k] for k in ("freq_khz", "bw_hz", "sf", "cr"))
            == tuple(nodes["target"][k] for k in ("freq_khz", "bw_hz", "sf", "cr")),
            "approved client and target normal radio configurations disagree")
    require(inspected["acl"].get(nodes["client"]["pubkey"], 0) & 3 == 3,
            "actual companion public key lacks existing target ADMIN ACL; no grant attempted")
    return {"client": nodes["client"], "target": nodes["target"], "acl": inspected["acl"]}


def probe_peer(pair, evidence, deadline):
    record = {"version": RECORD_VERSION, "kind": "normal-peer-probe", "serials": APPROVED,
              "read_only": False, "rf_request_attempted": False, "probe_complete": False,
              "scope": "target_to_client_ordinary_zerohop_advert", "signed_ota_qualified": False,
              "raw_serial_events": "serial-events.jsonl"}
    evidence.summary["measurements"]["normal_peer_probe"] = record
    before = normal_peer_configuration(pair, evidence)
    record["configuration_before"] = before
    evidence.log("normal_peer_probe_configuration", **before, serials=APPROVED)
    stats = record["statistics"] = {}
    stats["before"] = normal_peer_stats(pair, evidence, deadline, "before")
    remaining = max(0, deadline - time.monotonic())
    receive_deadline = deadline - min(5, remaining / 3)
    try:
        witness = ordinary_peer(pair, bytes.fromhex(before["target"]["pubkey"]), evidence, receive_deadline)
    finally:
        stats["after"] = normal_peer_stats(pair, evidence, deadline, "after")
    record["peer_receive"] = witness
    after = normal_peer_configuration(pair, evidence)
    record["configuration_after"] = after
    require(after == before, "normal peer identity/configuration/ACL changed during the probe")
    record.update(probe_complete=True, identity_config_acl_preserved=True,
                  ordinary_peer_received=True, outcome="normal_peer_received")
    write_record(evidence.directory / "normal-peer.json", record)
    evidence.summary["measurements"]["outcome"] = record["outcome"]
    evidence.log("normal_peer_probe_complete", **record)
    return record


def fresh_candidate(uploader, candidate, target_key, deadline):
    since = time.monotonic()
    while time.monotonic() < deadline:
        observed = uploader.status(target_key, timeout=uploader.remaining(deadline))
        now = time.monotonic()
        if observed.fresh_since(since, now):
            bound_snapshot(observed, candidate, target_key)
            require(observed.phase in (ota.Phase.ERASING, ota.Phase.RECEIVING,
                                       ota.Phase.VERIFYING, ota.Phase.READY),
                    "existing candidate is not resumable; no abort or replacement attempted")
            return observed
        time.sleep(min(max(0.1, observed.retry_after_ms / 1000), max(0, deadline - now)))
    raise TimeoutError("existing candidate has no fresh, identity-bound resumable snapshot")


def measurement_health(sample):
    for role, node in sample["nodes"].items():
        radio, budget = node["radio"], node["budget"]
        require(radio["v"] == radio["h"] == 1 and radio["x"] == radio["af"] == 0,
                f"{role}: invalid/unhealthy applied radio or nonzero driver/apply failure count")
        require(budget["to"] == budget["af"] == 0,
                f"{role}: TX timeout or lost-accounting counter is nonzero")
        require(0 < budget["w"] <= 0x7FFFFFFF and 0 <= budget["u"] <= budget["b"] <= budget["w"]
                and budget["b"] > 0,
                f"{role}: inconsistent rolling OTA window/budget/used accounting")


def ms_delta(later, earlier):
    return (later - earlier) & 0xFFFFFFFF


class TransferMeasurements:
    """Observe at idle command boundaries; never re-enter an uploader exchange."""

    def __init__(self, pair, candidate, requested, baseline, evidence, deadline, interval):
        self.pair, self.candidate, self.requested = pair, candidate, requested
        self.baseline, self.evidence, self.deadline, self.interval = baseline, evidence, deadline, interval
        self.samples, self.peer = [], None
        self.record = {"samples": self.samples, "ordinary_peer_during_transfer": None,
                       "candidate": candidate.metadata, "serials": APPROVED,
                       "public_keys": {role: baseline[role]["pubkey"] for role in ("client", "target")},
                       "requested_profile": requested,
                       "driver_applied_not_phy_readback": True, "duty_guarantee_verified": False,
                       "bitmap_bits_exposed": False, "fresh_handshake_wire_observed": False}
        evidence.summary["measurements"]["transfer_measurements"] = self.record

    def observe(self, phase, remote=None, since=None, remote_at=None):
        if remote is not None:
            remote_at = time.monotonic() if remote_at is None else remote_at
            fresh = remote.fresh_since(since, remote_at)
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "measurement deadline expired; progress preserved")
        sample = lab.read_ota_measurements(self.pair.client, self.pair.target, self.evidence, phase,
                                           timeout=min(5, remaining))
        sample["remote"] = None
        sample["fresh_remote_progress"] = False
        if remote is not None:
            sample["remote"] = remote.summary()
            sample["remote_received_monotonic"] = remote_at
            sample["remote_snapshot_monotonic"] = (
                remote_at - remote.age_ms / 1000 if remote.valid and remote.age_ms != ota.AGE_UNKNOWN else None)
            if fresh:
                bound_snapshot(remote, self.candidate, bytes.fromhex(self.baseline["target"]["pubkey"]))
                sample["fresh_remote_progress"] = True
                previous = next((s for s in reversed(self.samples) if s["fresh_remote_progress"]), None)
                if previous is not None:
                    require(remote.received >= previous["remote"]["received"],
                            "fresh durable bitmap count regressed; preserve progress")
        self.samples.append(sample)
        self.evidence.log("transfer_measurement_sample", **sample)
        measurement_health(sample)
        for role, values in sample["nodes"].items():
            radio = values["radio"]
            normal = tuple(self.baseline[role][key] for key in ("freq_khz", "bw_hz", "sf", "cr"))
            expected = (self.requested["frequency_khz"], 250000, 5, 5) if radio["a"] else normal
            require(tuple(radio[key] for key in ("f", "b", "s", "c")) == expected,
                    f"{role}: applied radio differs from saved baseline normal/direct tuple")
            if radio["a"]:
                require(self.requested["mode"] == "direct"
                        and 0 < ms_delta(radio["e"], radio["n"]) <= self.requested["lease_ms"],
                        f"{role}: unbounded/expired direct interval or direct active in on-mesh mode")
            if len(self.samples) > 1:
                previous = self.samples[-2]["nodes"][role]
                require(ms_delta(radio["n"], previous["radio"]["n"]) < 0x80000000
                        and ms_delta(values["budget"]["n"], previous["budget"]["n"]) < 0x80000000,
                        f"{role}: device clock reset/regressed during transfer measurements")
                for field in ("d", "r"):
                    require(ms_delta(radio[field], previous["radio"][field]) < 0x80000000,
                            f"{role}: applied radio counter regressed")
        return sample

    def report(self):
        transfer = [s for s in self.samples if s["phase"] in ("transfer", "ready", "peer-after")]
        reasons = []
        if not self.samples or self.samples[0]["phase"] != "baseline":
            reasons.append("baseline_measurements_missing")
        if not self.samples or self.samples[-1]["phase"] != "end":
            reasons.append("end_measurements_missing")
        direct_sequence = False
        if self.requested["mode"] == "direct":
            first = restored = None
            for sample in transfer:
                radios = [sample["nodes"][role]["radio"] for role in ("client", "target")]
                fresh = sample["fresh_remote_progress"]
                if first is None and all(r["a"] for r in radios) and fresh:
                    first = sample
                elif first is not None and all(not r["a"] for r in radios):
                    if all(ms_delta(sample["nodes"][role]["radio"]["r"],
                                    first["nodes"][role]["radio"]["r"]) > 0
                           for role in ("client", "target")):
                        restored = sample
                elif restored is not None and all(r["a"] for r in radios) and fresh:
                    advanced = all(0 < ms_delta(sample["nodes"][role]["radio"]["d"],
                                                first["nodes"][role]["radio"]["d"]) < 0x80000000
                                   and ms_delta(sample["nodes"][role]["radio"]["td"],
                                                restored["nodes"][role]["radio"]["tr"]) < 0x80000000
                                   for role in ("client", "target"))
                    direct_sequence = (advanced
                                       and sample["remote_snapshot_monotonic"] >= restored["finished_monotonic"]
                                       and sample["remote"]["received"] > first["remote"]["received"])
                    if direct_sequence:
                        break
            if not direct_sequence:
                reasons.append("two_applied_intervals_restoration_and_bitmap_continuation_not_observed")
            reasons.append("fresh_direct_handshake_token_ack_not_exposed_by_existing_status_api")
        else:
            for sample in transfer:
                budget = sample["nodes"]["client"]["budget"]
                require(budget["b"] == budget["w"] * self.requested["duty_milli_percent"] // 100000,
                        "sender applied budget does not match the requested share")
            if len(transfer) < 3 or not any(s["fresh_remote_progress"] for s in transfer):
                reasons.append("periodic_fresh_progress_samples_incomplete")
            progress = [s["remote"]["received"] for s in transfer if s["fresh_remote_progress"]]
            if len(progress) < 2 or max(progress) <= min(progress):
                reasons.append("fresh_durable_bitmap_progress_not_observed")
            if self.peer is None:
                reasons.append("ordinary_peer_not_freshly_bracketed_during_transfer")
            if not any(s["nodes"]["client"]["budget"]["u"] > 0 for s in transfer):
                reasons.append("completed_on_mesh_ota_airtime_not_observed")
            used = [s["nodes"]["client"]["budget"]["u"] for s in self.samples]
            if not used or not any(later > earlier for earlier, later in zip(used, used[1:])):
                reasons.append("new_completed_on_mesh_ota_charges_not_observed")
        covered_window = False
        if self.requested["mode"] != "direct" and transfer:
            start = transfer[0]
            previous = start
            for sample in transfer[1:]:
                compatible = all(
                    sample["nodes"][role]["budget"]["w"] == previous["nodes"][role]["budget"]["w"]
                    and sample["nodes"][role]["budget"]["b"] == previous["nodes"][role]["budget"]["b"]
                    and ms_delta(sample["nodes"][role]["budget"]["n"],
                                 previous["nodes"][role]["budget"]["n"]) <= int(self.interval * 2000)
                    for role in ("client", "target"))
                if not compatible:
                    start = sample
                if all(ms_delta(sample["nodes"][role]["budget"]["n"],
                                start["nodes"][role]["budget"]["n"]) >= sample["nodes"][role]["budget"]["w"]
                       for role in ("client", "target")):
                    covered_window = True
                previous = sample
            if self.requested["duty_milli_percent"] == 2000:
                if not covered_window:
                    reasons.append("full_rolling_window_periodic_coverage_incomplete")
                if any(s["nodes"][role]["budget"]["b"] * 100000
                       > s["nodes"][role]["budget"]["w"] * 2000
                       for s in transfer for role in ("client", "target")):
                    reasons.append("observed_budget_exceeds_two_percent")
        result = {"measurement_outcome": "incomplete" if reasons else "sampled_software_measurements_verified",
                  "incomplete_reasons": reasons, "measurement_qualified": not reasons,
                  "two_applied_intervals_restoration_bitmap_continuation_observed": direct_sequence,
                  "full_window_periodic_coverage_observed": covered_window,
                  "sampled_two_percent_budget_qualified": not reasons
                  and self.requested["duty_milli_percent"] == 2000,
                  "requested_duty_milli_percent": self.requested["duty_milli_percent"],
                  "duty_guarantee_verified": False, "hardware_phy_readback": False,
                  "ordinary_peer_during_transfer": self.peer}
        self.record.update(result)
        self.evidence.log("transfer_measurement_outcome", **result)
        return result


def wait_observed_ready(pair, uploader, candidate, target_key, since, deadline, observer):
    peer_attempted = False
    while time.monotonic() < deadline:
        remote = uploader.status(target_key, timeout=uploader.remaining(deadline))
        remote_at = time.monotonic()
        fresh = remote.fresh_since(since, remote_at)
        if remote.valid:
            require(remote.target == target_key and remote.flags & ota.REMOTE,
                    "OTA transfer status has the wrong remote scope")
        if fresh:
            bound_snapshot(remote, candidate, target_key)
            require(remote.phase not in (ota.Phase.FAILED, ota.Phase.ABORTED),
                    "OTA candidate failed/ABORTed; preserve progress")
            require(remote.phase in (ota.Phase.ERASING, ota.Phase.RECEIVING,
                                     ota.Phase.VERIFYING, ota.Phase.READY),
                    "unexpected remote phase during transfer observation")
        observer.observe("ready" if fresh and remote.phase == ota.Phase.READY else "transfer",
                         remote, since, remote_at)
        if fresh and remote.phase == ota.Phase.READY:
            bound_snapshot(remote, candidate, target_key, complete=True)
            return remote
        if (not peer_attempted and observer.requested["mode"] != "direct" and fresh
                and remote.phase == ota.Phase.RECEIVING and remote.received < remote.total):
            peer_attempted = True
            peer_since = time.monotonic()
            witness = ordinary_peer(pair, target_key, observer.evidence, min(deadline, peer_since + 30))
            after = uploader.status(target_key, timeout=uploader.remaining(deadline))
            after_at = time.monotonic()
            observer.observe("peer-after", after, peer_since, after_at)
            if after.fresh_since(peer_since, after_at):
                bound_snapshot(after, candidate, target_key)
                require(after.phase not in (ota.Phase.FAILED, ota.Phase.ABORTED),
                        "OTA candidate failed/ABORTed during ordinary peer observation")
                if (after.phase == ota.Phase.RECEIVING and remote.received <= after.received < after.total):
                    observer.peer = {"witness": witness, "before": remote.summary(), "after": after.summary(),
                                     "tx_totals_are_not_peer_proof": True}
            observer.record["ordinary_peer_during_transfer"] = observer.peer
        time.sleep(min(observer.interval, max(0, deadline - time.monotonic())))
    raise TimeoutError("no fresh READY before campaign deadline; measurements and progress preserved")


def stage(pair, uploader, candidate, args, evidence, deadline):
    body, requested = profile(args)
    require(math.isfinite(args.measurement_interval) and 0.1 <= args.measurement_interval <= 5,
            "--measurement-interval must be finite and in 0.1..5 seconds")
    baseline = capture(pair, candidate, evidence, deadline, uploader=uploader)
    if args.baseline_record:
        preserved(read_record(args.baseline_record, "baseline"), baseline)
    write_record(evidence.directory / "baseline.json", baseline)
    observer = TransferMeasurements(pair, candidate, requested, baseline, evidence, deadline,
                                    args.measurement_interval)
    observer.observe("baseline")
    target_key = bytes.fromhex(baseline["target"]["pubkey"])
    since = time.monotonic()
    local = uploader.status(timeout=uploader.remaining(deadline))
    captured = baseline["local_cache_before"]
    reupload = bool(captured and captured["phase"] == "ABORTED")
    if reupload:
        aborted_local_cache(local, baseline["client_status"], since)
        require(captured is not None and all(captured[field] == local.summary()[field] for field in
                ("phase", "target", "hash", "counter", "received", "total", "remote")),
                "local ABORT changed after baseline capture; no replacement permitted")
        evidence.log("explicit_local_abort_observed", previous=local.summary(), reupload=True,
                     abort_sent=False)
    elif local.valid:
        bound_snapshot(local, candidate, ota.LOCAL_TARGET)
        require(local.phase in (ota.Phase.ERASING, ota.Phase.RECEIVING,
                                ota.Phase.VERIFYING, ota.Phase.CACHE_SEALED),
                "local cache cannot be safely resumed; no ABORT/reupload attempted")
    if baseline["target_status"]["phase"] in ACTIVE_PHASES:
        require(local.valid and not reupload,
                "existing target candidate cannot be bound without the same local cache")
        fresh_candidate(uploader, candidate, target_key, deadline)
    evidence.log("campaign_requested", **requested, measured_duty_evidence_available=False,
                 direct_sf5_observed=False, automatic_lease_renewal_observed=False)
    cache = uploader.cache(candidate.canonical, candidate.image,
                           bytes.fromhex(baseline["client"]["pubkey"]), deadline, reupload=reupload)
    bound_snapshot(cache, candidate, ota.LOCAL_TARGET, complete=True)
    since = time.monotonic()
    uploader.start([target_key], body, args.mode, deadline)
    ready = wait_observed_ready(pair, uploader, candidate, target_key, since, deadline, observer)
    bound_snapshot(ready, candidate, target_key, complete=True)
    evidence.log("full_image_ready_without_commit", **ready.summary())
    # READY stops the firmware transfer; allow the last bounded direct lease to expire.
    if args.mode == "direct":
        require(deadline - time.monotonic() > 62, "READY preserved; insufficient deadline for lease restoration")
        restore_until = time.monotonic() + 62
        while time.monotonic() < restore_until:
            time.sleep(min(args.measurement_interval, restore_until - time.monotonic()))
            observer.observe("restoration")
    after = capture(pair, candidate, evidence, deadline)
    preserved(baseline, after)
    require(after["target_status"]["phase"] == "ready", "target no longer READY; no commit attempted")
    ordinary_peer(pair, target_key, evidence, min(deadline, time.monotonic() + 30))
    observer.observe("end")
    measurements = observer.report()
    record = {**baseline, "kind": "ready", "profile": requested, "ready": ready.summary(),
              "ready_observed_at": lab.utc_now(), "auto_commit": False,
              "transfer_measurements": measurements}
    write_record(evidence.directory / "ready.json", record)
    evidence.summary["measurements"]["outcome"] = "full_image_ready_no_commit"
    return record


def remote_trial(uploader, candidate, target_key, since, deadline):
    while time.monotonic() < deadline:
        observed = uploader.status(target_key, timeout=uploader.remaining(deadline))
        now = time.monotonic()
        if observed.valid:
            require(observed.target == target_key and observed.flags & ota.REMOTE,
                    "remote Trial observation has the wrong scope")
        if observed.fresh_since(since, now):
            bound_snapshot(observed, candidate, target_key)
            require(observed.phase not in (ota.Phase.FAILED, ota.Phase.ABORTED),
                    "remote candidate failed/ABORTed during trial observation")
            require(observed.phase in (ota.Phase.READY, ota.Phase.COMMIT_PENDING,
                                       ota.Phase.TRIAL, ota.Phase.INSTALLED),
                    "unexpected remote phase during postcommit trial observation")
            if observed.phase in (ota.Phase.TRIAL, ota.Phase.INSTALLED):
                bound_snapshot(observed, candidate, target_key, complete=True)
                return observed
        time.sleep(min(max(0.1, observed.retry_after_ms / 1000), max(0, deadline - now)))
    return None


def incomplete_trial(evidence, reason, observed=None):
    evidence.summary["measurements"]["trial_observation_incomplete"] = {
        "reason": reason, "remote": None if observed is None else observed.summary()}
    evidence.log("trial_observation_incomplete",
                 **evidence.summary["measurements"]["trial_observation_incomplete"])


def observe_install(pair, uploader, candidate, target_key, evidence, deadline,
                    reboot_timeout=120, trial_timeout=30, install_timeout=300):
    deadline = min(deadline, time.monotonic() + install_timeout)
    try:
        pair.reenumerate(min(deadline, time.monotonic() + reboot_timeout))
    except TimeoutError as exc:
        evidence.summary["measurements"]["outcome"] = "blocked_remote_commit_did_not_reboot"
        evidence.log("remote_install_blocked", reason="no_observed_remote_commit_reboot",
                     usb_reset_sent=False, assisted_commissioning=False, remote_install_qualified=False)
        raise QualificationError(
            "remote install blocked: receiver did not reboot/disconnect/re-enumerate after remote COMMIT; "
            "no USB reset issued; manual USB reboot would be assisted commissioning only") from exc
    trial = None
    trial_attempted = False
    while time.monotonic() < deadline:
        try:
            status = target_status(pair.target, evidence, deadline)
        except (ConnectionError, OSError) as exc:
            if not isinstance(exc, ConnectionError) and exc.errno not in (errno.EIO, errno.ENODEV):
                raise
            evidence.log("target_serial_disconnected", error=str(exc))
            pair.reenumerate(deadline, transport_disconnected=True)
            continue
        require(status["floor"] is not None, "postcommit floor unproven; installation not qualified")
        require(status["boot"] != "failed" and status["phase"] not in ("failed", "aborted"),
                "installation failed/rolled back; preserve all evidence")
        if status["boot"] == "trial":
            bound_trial = status["phase"] == "trial" and status["counter"] == candidate.counter
            evidence.log("trial_boot_observed", candidate_binding_available=bound_trial, **status)
            if bound_trial and not trial_attempted:
                trial_attempted = True
                since = time.monotonic()
                observed = remote_trial(uploader, candidate, target_key, since,
                                        min(deadline, since + trial_timeout))
                if observed is None:
                    incomplete_trial(evidence, "no_fresh_remote_trial_before_observation_bound")
                elif observed.phase == ota.Phase.INSTALLED:
                    incomplete_trial(evidence, "remote_already_installed", observed)
                else:
                    trial = observed.summary()
                    evidence.summary["measurements"]["trial"] = {
                        "remote": trial, "physical_text": status, "candidate": candidate.metadata}
                    evidence.log("fresh_remote_trial_verified",
                                 **evidence.summary["measurements"]["trial"])
        if status["phase"] == "installed":
            require(status["boot"] == "confirmed" and status["verified"]
                    and status["image"] == candidate.metadata["image_sha256"]
                    and status["counter"] == candidate.counter and status["floor"] == candidate.counter,
                    "Installed does not prove the actual immutable running image/counter/floor")
            since = time.monotonic()
            remote = uploader.wait_phase(target_key, ota.Phase.INSTALLED, candidate.manifest_hash,
                                         candidate.counter, since, deadline)
            bound_snapshot(remote, candidate, target_key, complete=True)
            require(remote.phase == ota.Phase.INSTALLED
                    and remote.fresh_since(since, time.monotonic()),
                    "remote Installed is stale or has the wrong phase; remote install not qualified")
            evidence.summary["measurements"]["installed"] = {
                **status, "remote": remote.summary(), "candidate": candidate.metadata,
                "trial_observed": trial is not None, "remote_trial": trial,
                "signed_provenance_scope": "application_checked_remote_Installed"}
            evidence.log("running_install_verified", **evidence.summary["measurements"]["installed"])
            if trial is None and "trial_observation_incomplete" not in evidence.summary["measurements"]:
                incomplete_trial(evidence, "local_trial_not_observed_or_not_candidate_bound")
            return status
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))
    raise TimeoutError("no proven running Installed/counter/floor before deadline")


def commit(pair, uploader, candidate, args, evidence, deadline):
    record = read_record(args.ready_record, "ready")
    require(record["candidate"] == candidate.metadata and record.get("auto_commit") is False,
            "explicit commit inputs do not match the saved READY provenance")
    require(record["ready"]["phase"] == "READY"
            and record["ready"]["received"] == record["ready"]["total"] == candidate.blocks,
            "saved record does not contain full-image READY")
    before = capture(pair, candidate, evidence, deadline)
    preserved(record, before)
    require(before["target_status"]["phase"] == "ready", "explicit commit requires current target READY")
    measurements = lab.read_ota_measurements(pair.client, pair.target, evidence, "pre-commit")
    measurement_health(measurements)
    for role, values in measurements["nodes"].items():
        radio = values["radio"]
        normal = tuple(before[role][key] for key in ("freq_khz", "bw_hz", "sf", "cr"))
        require(not radio["a"] and tuple(radio[key] for key in ("f", "b", "s", "c")) == normal,
                f"{role}: COMMIT requires healthy driver-applied restored normal service")
    evidence.summary["measurements"]["pre_commit_measurements"] = measurements
    target_key = bytes.fromhex(before["target"]["pubkey"])
    local = uploader.status(timeout=uploader.remaining(deadline))
    bound_snapshot(local, candidate, ota.LOCAL_TARGET, complete=True)
    require(local.phase == ota.Phase.CACHE_SEALED, "commit requires the unchanged sealed local cache")
    evidence.log("explicit_qualified_commit_requested", target=target_key.hex(), candidate=candidate.metadata)
    reply = uploader.commit(target_key, candidate.canonical, deadline)
    evidence.log("commit_ack_not_install_proof", **reply.summary())
    installed = observe_install(pair, uploader, candidate, target_key, evidence, deadline,
                                args.reboot_timeout, args.trial_timeout, args.install_timeout)
    after_client = lab.serializable_app_info(lab.companion_info(pair.client))
    after_target, acl = lab.repeater_info(pair.target), pair.target.get_acl()
    require(after_client == before["client"] and after_target == before["target"],
            "identity/name/radio/path readbacks changed across installation")
    require(acl == before["acl"], "complete ADMIN ACL did not survive installation reboot")
    ordinary_peer(pair, target_key, evidence, min(deadline, time.monotonic() + 30))
    measurements = lab.read_ota_measurements(pair.client, pair.target, evidence, "installed-end")
    measurement_health(measurements)
    evidence.summary["measurements"]["installed_end_measurements"] = measurements
    trial = evidence.summary["measurements"]["installed"]["remote_trial"]
    qualified = trial is not None
    result = "running_installed_lifecycle_and_peer_verified" if qualified else "remote_trial_not_observed"
    outcome = {"version": RECORD_VERSION, "kind": "installed", "serials": APPROVED,
               "candidate": candidate.metadata, "profile": record["profile"], "lifecycle": installed,
               "remote_installed": evidence.summary["measurements"]["installed"]["remote"],
               "outcome": result, "trial_observation_incomplete": not qualified,
               "identity_config_acl_preserved": True, "ordinary_peer_received": True,
               "trial_observed": qualified, "remote_trial": trial,
               "usb_reset_sent": False, "remote_install_qualified": qualified,
               "measured_duty_evidence_available": False,
               "transfer_measurements": record.get("transfer_measurements"),
               "hardware_campaign_qualified": qualified
               and bool(record.get("transfer_measurements", {}).get("measurement_qualified")),
               "multihop_fleet_powercut_qualified": False}
    write_record(evidence.directory / "installed.json", outcome)
    evidence.summary["measurements"]["outcome"] = result
    require(qualified, "running install/preservation/peer verified but fresh remote Trial not observed; "
            "remote_install_qualified=false; completed evidence preserved in installed.json")
    return outcome


def parser():
    root = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
                                   formatter_class=argparse.RawDescriptionHelpFormatter)
    root.add_argument("--artifact-dir", required=True, type=Path)
    root.add_argument("--timeout", type=float, default=86400)
    commands = root.add_subparsers(dest="command", required=True)
    probe = commands.add_parser("probe-peer", allow_abbrev=False,
                                help="explicit ordinary RF advert/receive probe; no OTA status, image or reboot")
    probe.add_argument("--probe-timeout", type=float, default=30,
                       help="finite positive bound for the entire normal peer probe, including readbacks")
    for name in ("stage", "commit"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--manifest", required=True, type=Path)
        command.add_argument("--image", required=True, type=Path)
        command.add_argument("--image-sha256", required=True)
        command.add_argument("--counter", required=True, type=int)
        command.add_argument("--provenance", required=True)
        command.add_argument("--commissioning-evidence", required=True)
        if name == "stage":
            command.add_argument("--mode", choices=tuple(ota.MODES), default="directed")
            command.add_argument("--channel", type=int, default=255)
            command.add_argument("--duty-milli-percent", type=int, default=2000)
            command.add_argument("--supervised-full-image-smoke", action="store_true")
            command.add_argument("--baseline-record", type=Path)
            command.add_argument("--measurement-interval", type=float, default=5,
                                 help="periodic USB measurement/status polling in 0.1..5 seconds; "
                                      "not a continuous duty guarantee")
        else:
            command.add_argument("--ready-record", required=True, type=Path)
            command.add_argument("--qualified-commit", action="store_true", required=True)
            command.add_argument("--reboot-timeout", type=float, default=120)
            command.add_argument("--trial-timeout", type=float, default=30)
            command.add_argument("--install-timeout", type=float, default=300)
    return root


def main(argv=None):
    arguments = parser()
    args = arguments.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        arguments.error("--timeout must be finite and positive")
    if args.command == "probe-peer" and (not math.isfinite(args.probe_timeout) or args.probe_timeout <= 0):
        arguments.error("--probe-timeout must be finite and positive")
    if args.command == "commit":
        for option in ("reboot_timeout", "trial_timeout", "install_timeout"):
            value = getattr(args, option)
            if not math.isfinite(value) or value <= 0:
                arguments.error(f"--{option.replace('_', '-')} must be finite and positive")
    candidate = None if args.command == "probe-peer" else load_candidate(args)
    if args.command == "stage":
        profile(args)
        require(math.isfinite(args.measurement_interval) and 0.1 <= args.measurement_interval <= 5,
                "--measurement-interval must be finite and in 0.1..5 seconds")
    elif args.command == "commit":
        record = read_record(args.ready_record, "ready")
        require(record["candidate"] == candidate.metadata, "READY record candidate mismatch")
    require(not args.artifact_dir.exists(), "use a new artifact directory; never overwrite prior evidence")
    evidence = lab.Evidence(args.artifact_dir)
    pair, error = None, None
    try:
        timeout = min(args.timeout, args.probe_timeout) if args.command == "probe-peer" else args.timeout
        deadline = time.monotonic() + timeout
        pair = Pair(evidence, deadline)
        if args.command == "probe-peer":
            probe_peer(pair, evidence, deadline)
        else:
            uploader = ota.Uploader(pair.client, evidence, command_timeout=min(10, args.timeout))
            operation = stage if args.command == "stage" else commit
            operation(pair, uploader, candidate, args, evidence, deadline)
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
        evidence.log("fatal_preserving_progress", error=error, abort_sent=False, force_overwrite=False)
        raise
    finally:
        if pair is not None:
            pair.close()
        evidence.finish(error)


if __name__ == "__main__":
    main()
