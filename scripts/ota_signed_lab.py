#!/usr/bin/env python3
"""Signed, single-target HOST HARDWARE campaign; stage never auto-commits.

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
requests 908525 kHz/60000 ms; production uploader firmware renews bounded leases
and resumes the bitmap, and the app owns SF5, not this host. Active SF5 and lease
renewal are NOT measured here. After READY wait a full lease before testing
ordinary peer advert reception. Default 2000 milli-percent is 2%; explicitly
passing 95000 or 100000 AND --supervised-full-image-smoke is 95% or 100%
supervised smoke, NEVER 2% acceptance. The approved normal pair may use
62.5 kHz or 250 kHz bandwidth at 907.525 MHz/SF7/CR5/path3; both peers must
agree and retain their actual captured configuration. This runner does not
configure radio settings. No measured-duty/budget-saturation counters are exposed by
these status APIs; requested share and peer reception do not prove fairness.
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

import lab_device
import ota_rf_lab as lab
import ota_uploader as ota


APPROVED = {"client": "4186AE911D94CDB1", "target": "3BE94917B92DC5E9"}
APPROVED_RADIOS = ((907525, 62500, 7, 5), (907525, 250000, 7, 5))
RECORD_VERSION = 1
ACTIVE_PHASES = {"erasing", "receiving", "verifying", "ready"}
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


def ordinary_peer(pair, target_key, evidence, deadline):
    pair.client.poll()
    pair.client.take_pending({0x80, 0x8A})
    since = time.monotonic()
    lab.require_repeater_ok(pair.target, "advert.zerohop", expected="OK - zerohop advert sent")
    while time.monotonic() < deadline:
        pair.client.poll(min(0.1, max(0, deadline - time.monotonic())))
        for timestamp, frame in pair.client.take_pending({0x80, 0x8A}):
            valid_shape = (frame[0] == 0x80 and len(frame) == 33
                           or frame[0] == 0x8A and len(frame) >= 36)
            if timestamp >= since and valid_shape and frame[1:33] == target_key:
                evidence.log("ordinary_peer_advert_received", target=target_key.hex(),
                             elapsed_seconds=time.monotonic() - since, multihop_verified=False)
                return
    raise TimeoutError("no fresh ordinary advert from the actual target on the restored mesh")


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


def stage(pair, uploader, candidate, args, evidence, deadline):
    body, requested = profile(args)
    baseline = capture(pair, candidate, evidence, deadline, uploader=uploader)
    if args.baseline_record:
        preserved(read_record(args.baseline_record, "baseline"), baseline)
    write_record(evidence.directory / "baseline.json", baseline)
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
    ready = uploader.wait_phase(target_key, ota.Phase.READY, candidate.manifest_hash,
                                candidate.counter, since, deadline)
    bound_snapshot(ready, candidate, target_key, complete=True)
    evidence.log("full_image_ready_without_commit", **ready.summary())
    # READY stops the firmware transfer; allow the last bounded direct lease to expire.
    if args.mode == "direct":
        require(deadline - time.monotonic() > 62, "READY preserved; insufficient deadline for lease restoration")
        time.sleep(62)
    after = capture(pair, candidate, evidence, deadline)
    preserved(baseline, after)
    require(after["target_status"]["phase"] == "ready", "target no longer READY; no commit attempted")
    ordinary_peer(pair, target_key, evidence, min(deadline, time.monotonic() + 30))
    record = {**baseline, "kind": "ready", "profile": requested, "ready": ready.summary(),
              "ready_observed_at": lab.utc_now(), "auto_commit": False}
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
    if args.command == "commit":
        for option in ("reboot_timeout", "trial_timeout", "install_timeout"):
            value = getattr(args, option)
            if not math.isfinite(value) or value <= 0:
                arguments.error(f"--{option.replace('_', '-')} must be finite and positive")
    candidate = load_candidate(args)
    if args.command == "stage":
        profile(args)
    else:
        record = read_record(args.ready_record, "ready")
        require(record["candidate"] == candidate.metadata, "READY record candidate mismatch")
    require(not args.artifact_dir.exists(), "use a new artifact directory; never overwrite prior evidence")
    evidence = lab.Evidence(args.artifact_dir)
    pair, error = None, None
    try:
        deadline = time.monotonic() + args.timeout
        pair = Pair(evidence, deadline)
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
