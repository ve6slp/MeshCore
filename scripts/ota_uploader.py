#!/usr/bin/env python3
"""Drive the signed OTA uploader through an approved lab companion.

cache only signs/stages a local image and observes CACHE_SEALED. It never starts
RF, selects a remote target, commits or proves installation/airtime.
ABORT requires ABI2 fresh STATUS generation and durable ABORTED readback.
"""

import argparse
from dataclasses import dataclass
from enum import IntEnum
import hashlib
import math
from pathlib import Path
import struct
import time

import lab_device
import ota_rf_lab as lab


class Op(IntEnum):
    CACHE_BEGIN = 0x10
    CACHE_PUT = 0x11
    CACHE_SEAL = 0x12
    ADD_TARGET = 0x13
    START = 0x14
    COMMIT = 0x15
    ABORT = 0x16
    STATUS = 0x17
    SET_ADMIN = 0x18


class Result(IntEnum):
    OK = 0
    PENDING = 1
    BUSY = 2
    BAD_REQUEST = 3
    DENIED = 4
    UNAVAILABLE = 5
    IO_ERROR = 6
    MISMATCH = 7
    INCOMPLETE = 8
    NOT_FOUND = 9
    TOO_LATE = 10
    BUDGET_DENIED = 11
    UNSUPPORTED = 12


class Phase(IntEnum):
    UNKNOWN = 0
    IDLE = 1
    ERASING = 2
    RECEIVING = 3
    VERIFYING = 4
    READY = 5
    COMMIT_PENDING = 6
    TRIAL = 7
    INSTALLED = 8
    ABORTED = 9
    FAILED = 10
    CACHE_SEALED = 11


REPLY_CODE = 31
ABI_VERSION = 2
REPLY_BYTES = 90
BLOCK_BYTES = 84
LOCAL_TARGET = bytes(32)
SNAPSHOT_VALID = 1
REMOTE = 2
AGE_UNKNOWN = 0xFFFFFFFF
MODES = {"direct": 0, "directed": 1, "background": 2}


class UploaderError(RuntimeError):
    pass


@dataclass(frozen=True)
class Reply:
    op: Op
    result: Result
    phase: Phase
    flags: int
    target: bytes
    manifest_hash: bytes
    received: int
    total: int
    counter: int
    age_ms: int
    retry_after_ms: int
    generation: int

    @property
    def valid(self):
        return bool(self.flags & SNAPSHOT_VALID)

    def fresh_since(self, since, now):
        return self.valid and self.age_ms != AGE_UNKNOWN and now - self.age_ms / 1000 >= since

    def summary(self):
        return {
            "op": self.op.name, "result": self.result.name, "phase": self.phase.name,
            "target": self.target.hex(), "hash": self.manifest_hash.hex(),
            "received": self.received, "total": self.total, "counter": self.counter,
            "snapshot_valid": self.valid, "remote": bool(self.flags & REMOTE),
            "snapshot_age_ms": self.age_ms, "retry_after_ms": self.retry_after_ms,
            "generation": self.generation,
        }


def decode_reply(frame):
    if len(frame) != REPLY_BYTES or frame[:2] != bytes([REPLY_CODE, ABI_VERSION]):
        raise UploaderError("invalid OTA reply length, code or ABI version")
    try:
        op, result, phase = Op(frame[2]), Result(frame[3]), Phase(frame[4])
    except ValueError as exc:
        raise UploaderError("unknown OTA reply opcode, result or phase") from exc
    received, total, counter, age, retry = struct.unpack_from(">HHIII", frame, 70)
    reply = Reply(op, result, phase, frame[5], frame[6:38], frame[38:70],
                  received, total, counter, age, retry, struct.unpack_from(">I", frame, 86)[0])
    if reply.flags & ~(SNAPSHOT_VALID | REMOTE) or received > total:
        raise UploaderError("invalid OTA reply flags or durable block counts")
    if not reply.valid:
        if (phase != Phase.UNKNOWN or reply.manifest_hash != bytes(32)
                or received or total or counter or age != AGE_UNKNOWN or reply.generation):
            raise UploaderError("invalid OTA no-snapshot reply")
    elif age == AGE_UNKNOWN:
        raise UploaderError("OTA snapshot has no known age")
    return reply


def full_key(text):
    if len(text) != 64:
        raise argparse.ArgumentTypeError("use the full 64-digit node public key")
    try:
        key = bytes.fromhex(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("node public key must be hexadecimal") from exc
    if len(key) != 32 or key == LOCAL_TARGET:
        raise argparse.ArgumentTypeError("use a nonzero 32-byte node public key")
    return key


def validate_image(canonical, image):
    if len(canonical) != 59:
        raise ValueError("manifest must contain exactly 59 canonical bytes")
    if not image or len(image) > BLOCK_BYTES * 65535:
        raise ValueError("image does not fit the uploader block geometry")
    if struct.unpack_from(">I", canonical, 9)[0] != len(image):
        raise ValueError("image size does not match the manifest")
    if canonical[13:45] != hashlib.sha256(image).digest():
        raise ValueError("image SHA-256 does not match the manifest")


def start_body(mode, channel, frequency_khz, lease_ms, duty_milli_percent):
    if mode not in MODES or not 0 <= channel <= 255:
        raise ValueError("invalid OTA mode or channel")
    if not 0 < duty_milli_percent <= 100000:
        raise ValueError("airtime share must be in 1..100000 milli-percent")
    if mode == "direct":
        if channel != 255 or not 150000 <= frequency_khz <= 2500000 or not 250 <= lease_ms <= 60000:
            raise ValueError("direct mode requires channel 255, an explicit frequency and a 250..60000 ms lease")
    elif frequency_khz != 0 or lease_ms != 0 or (mode == "directed" and channel != 255):
        raise ValueError("on-mesh mode requires zero frequency/lease and directed mode requires channel 255")
    elif mode == "background" and channel == 255:
        raise ValueError("background mode requires a configured multicast channel")
    return struct.pack(">BBIHI", MODES[mode], channel, frequency_khz, lease_ms, duty_milli_percent)


class Uploader:
    def __init__(self, node, evidence, command_timeout=10.0):
        self.node = node
        self.evidence = evidence
        self.command_timeout = command_timeout

    def exchange(self, op, body=b"", target=LOCAL_TARGET, timeout=None):
        timeout = self.command_timeout if timeout is None else timeout
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("OTA command timeout must be finite and positive")
        self.node.poll()
        self.node.take_pending({REPLY_CODE, lab.RESP_ERR})
        sent = time.monotonic()
        self.node.write_frame(bytes([lab.CMD_OTA_CONTROL, op]) + body)
        deadline = sent + timeout
        while time.monotonic() < deadline:
            self.node.poll(max(0.0, min(0.1, deadline - time.monotonic())))
            for timestamp, frame in self.node.take_pending({REPLY_CODE, lab.RESP_ERR}):
                if timestamp < sent:
                    continue
                if frame[0] == lab.RESP_ERR:
                    raise UploaderError(f"companion rejected {op.name}: {frame.hex()}")
                reply = decode_reply(frame)
                if reply.op != op or reply.target != target:
                    self.evidence.log("ota_unmatched_reply", **reply.summary())
                    continue
                self.evidence.log("ota_reply", **reply.summary())
                return reply
        raise TimeoutError(f"no matching OTA reply for {op.name}, target {target.hex()}")

    @staticmethod
    def require_result(reply):
        if reply.result not in (Result.OK, Result.PENDING):
            raise UploaderError(f"{reply.op.name}: {reply.result.name}")
        return reply

    @classmethod
    def require_accepted(cls, reply):
        cls.require_result(reply)
        if reply.phase == Phase.FAILED:
            raise UploaderError(f"{reply.op.name}: remote or cache failure")
        return reply

    def status(self, target=LOCAL_TARGET, timeout=None):
        return self.require_result(self.exchange(Op.STATUS, target, target, timeout))

    def remaining(self, deadline):
        remaining = deadline - time.monotonic()
        if not math.isfinite(remaining) or remaining <= 0:
            raise TimeoutError("OTA operation deadline expired")
        return min(self.command_timeout, remaining)

    def wait_phase(self, target, phase, manifest_hash, counter, since, deadline, generation=None,
                   prior_generation=None):
        while time.monotonic() < deadline:
            reply = self.status(target, timeout=self.remaining(deadline))
            if reply.valid and bool(reply.flags & REMOTE) != (target != LOCAL_TARGET):
                raise UploaderError("OTA snapshot has the wrong local/remote scope")
            now = time.monotonic()
            fresh = reply.fresh_since(since, now)
            if fresh and (reply.manifest_hash != manifest_hash or reply.counter != counter):
                raise UploaderError("OTA status belongs to a different manifest or counter")
            if (fresh and generation is not None and reply.generation != generation
                    and not (phase == Phase.ABORTED and prior_generation is not None
                             and reply.generation == prior_generation and reply.phase != Phase.ABORTED)):
                raise UploaderError("OTA status belongs to a different generation")
            if fresh and (reply.phase == Phase.FAILED
                          or (reply.phase == Phase.ABORTED and phase != Phase.ABORTED)):
                raise UploaderError(f"OTA candidate is {reply.phase.name}")
            if reply.phase == phase and fresh and (phase != Phase.ABORTED or reply.result == Result.OK):
                if phase in (Phase.READY, Phase.CACHE_SEALED) and (reply.total == 0 or reply.received != reply.total):
                    raise UploaderError("completed OTA phase has incomplete durable blocks")
                return reply
            time.sleep(min(max(0.1, reply.retry_after_ms / 1000), max(0.0, deadline - now)))
        raise TimeoutError(f"no fresh {phase.name} snapshot for target {target.hex()}")

    def cache(self, canonical, image, owner_public_key, deadline, reupload=False):
        validate_image(canonical, image)
        self.remaining(deadline)
        signature = lab.sign_manifest(self.node, canonical, owner_public_key, deadline=deadline)
        manifest_hash = hashlib.sha256(canonical).digest()
        counter = struct.unpack_from(">I", canonical, 45)[0]
        since = time.monotonic()
        reply = self.require_accepted(self.exchange(
            Op.CACHE_BEGIN, bytes([int(reupload)]) + owner_public_key + canonical + signature,
            timeout=self.remaining(deadline)))
        if reply.phase in (Phase.VERIFYING, Phase.CACHE_SEALED):
            return self.wait_phase(LOCAL_TARGET, Phase.CACHE_SEALED, manifest_hash, counter, since, deadline)
        if reply.result == Result.PENDING:
            self.wait_phase(LOCAL_TARGET, Phase.RECEIVING, manifest_hash, counter, since, deadline)
        for index, offset in enumerate(range(0, len(image), BLOCK_BYTES)):
            data = image[offset:offset + BLOCK_BYTES]
            body = struct.pack(">HB", index, len(data)) + data
            while time.monotonic() < deadline:
                reply = self.require_accepted(self.exchange(Op.CACHE_PUT, body, timeout=self.remaining(deadline)))
                if reply.result == Result.OK:
                    break
                time.sleep(min(max(0.1, reply.retry_after_ms / 1000),
                               max(0.0, deadline - time.monotonic())))
            else:
                raise TimeoutError(f"cache block {index} was not durably acknowledged")
        self.require_accepted(self.exchange(Op.CACHE_SEAL, timeout=self.remaining(deadline)))
        return self.wait_phase(LOCAL_TARGET, Phase.CACHE_SEALED, manifest_hash, counter, since, deadline)

    def start(self, targets, body, mode, deadline):
        if (not targets or len(targets) > 32 or len(set(targets)) != len(targets)
                or any(len(target) != 32 or target == LOCAL_TARGET for target in targets)):
            raise ValueError("select 1..32 distinct full target identities")
        if mode != "background" and len(targets) != 1:
            raise ValueError("direct and directed campaigns require exactly one target")
        if mode not in MODES or len(body) != 12 or body[0] != MODES[mode]:
            raise ValueError("campaign mode does not match the START body")
        for target in targets:
            self.require_accepted(self.exchange(Op.ADD_TARGET, target, target, self.remaining(deadline)))
        return self.require_accepted(self.exchange(Op.START, body, timeout=self.remaining(deadline)))

    def commit(self, target, canonical, deadline):
        if len(target) != 32 or target == LOCAL_TARGET or len(canonical) != 59:
            raise ValueError("commit requires a full target identity and canonical manifest")
        manifest_hash = hashlib.sha256(canonical).digest()
        counter = struct.unpack_from(">I", canonical, 45)[0]
        since = time.monotonic()
        self.wait_phase(target, Phase.READY, manifest_hash, counter, since, deadline)
        return self.require_accepted(self.exchange(
            Op.COMMIT, target + manifest_hash + struct.pack(">I", counter), target, self.remaining(deadline)))

    def abort(self, target, image_hash, deadline=None):
        if len(target) != 32 or len(image_hash) != 32:
            raise ValueError("abort requires a target identity or local cache and image SHA-256")
        since = time.monotonic()
        deadline = since + self.command_timeout if deadline is None else deadline
        self.remaining(deadline)
        while time.monotonic() < deadline:
            observed = self.status(target, timeout=self.remaining(deadline))
            if observed.op != Op.STATUS or observed.target != target:
                raise UploaderError("abort STATUS has the wrong opcode or target")
            if observed.valid and bool(observed.flags & REMOTE) != (target != LOCAL_TARGET):
                raise UploaderError("abort STATUS has the wrong local/remote scope")
            now = time.monotonic()
            if observed.fresh_since(since, now):
                if observed.phase in (Phase.UNKNOWN, Phase.IDLE):
                    raise UploaderError("abort STATUS does not identify a candidate")
                break
            time.sleep(min(max(0.1, observed.retry_after_ms / 1000), max(0.0, deadline - now)))
        else:
            raise TimeoutError("no fresh valid STATUS generation for abort")
        generation = (observed.generation if observed.phase == Phase.ABORTED
                      else (observed.generation + 1) & 0xFFFFFFFF)
        since = time.monotonic()
        self.require_accepted(self.exchange(
            Op.ABORT, target + image_hash + struct.pack(">I", observed.generation),
            target, self.remaining(deadline)))
        return self.wait_phase(target, Phase.ABORTED, observed.manifest_hash, observed.counter,
                               since, deadline, generation=generation,
                               prior_generation=(None if observed.phase == Phase.ABORTED
                                                 else observed.generation))


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--artifact-dir", required=True)
    root.add_argument("--client-role", default=lab.CLIENT_ROLE)
    root.add_argument("--timeout", type=float, default=300)
    commands = root.add_subparsers(dest="command", required=True)
    upload = commands.add_parser("upload", help="cache and start; never commit automatically")
    cache = commands.add_parser("cache", help="local signed cache only; no remote START, READY or install")
    for command in (upload, cache):
        command.add_argument("--manifest", required=True, type=Path)
        command.add_argument("--image", required=True, type=Path)
        command.add_argument("--reupload", action="store_true")
    upload.add_argument("--target", required=True, type=full_key, action="append")
    upload.add_argument("--mode", choices=tuple(MODES), default="directed")
    upload.add_argument("--channel", type=int, default=255)
    upload.add_argument("--frequency-khz", type=int, default=0)
    upload.add_argument("--lease-ms", type=int, default=0)
    upload.add_argument("--duty-milli-percent", type=int, default=2000)
    upload.add_argument("--wait-ready", action="store_true")
    status = commands.add_parser("status")
    status.add_argument("--target", type=full_key, default=LOCAL_TARGET)
    commit = commands.add_parser("commit", help="explicitly commit one READY target")
    commit.add_argument("--target", required=True, type=full_key)
    commit.add_argument("--manifest", required=True, type=Path)
    abort = commands.add_parser("abort", help="generation-bound abort; fresh STATUS and durable readback required")
    abort.add_argument("--target", required=True, type=full_key)
    abort.add_argument("--image", required=True, type=Path)
    abort_cache = commands.add_parser("abort-cache", help="generation-bound local cache abort; never remote")
    abort_cache.add_argument("--image", required=True, type=Path)
    admin = commands.add_parser("admin")
    admin.add_argument("--target", required=True, type=full_key)
    admin.add_argument("--enabled", required=True, type=int, choices=(0, 1))
    return root


def main():
    arguments = parser()
    args = arguments.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        arguments.error("--timeout must be finite and positive")
    if args.client_role != "client":
        arguments.error("uploader requires the approved client role; no role override")
    canonical = args.manifest.read_bytes() if hasattr(args, "manifest") else None
    image = args.image.read_bytes() if hasattr(args, "image") else None
    if canonical is not None and len(canonical) != 59:
        arguments.error("--manifest must contain exactly 59 canonical bytes")
    body = None
    if args.command in ("upload", "cache"):
        validate_image(canonical, image)
    if args.command == "upload":
        body = start_body(args.mode, args.channel, args.frequency_khz, args.lease_ms, args.duty_milli_percent)
        if len(set(args.target)) != len(args.target) or len(args.target) > 32:
            arguments.error("select at most 32 distinct targets")
        if args.mode != "background" and len(args.target) != 1:
            arguments.error("direct and directed modes require exactly one target")
    elif args.command in ("abort", "abort-cache") and not image:
        arguments.error("--image must not be empty")
    evidence = (lab.Evidence(args.artifact_dir, exclusive=True) if args.command == "cache"
                else lab.Evidence(args.artifact_dir))
    node = None
    error = None
    try:
        device = lab_device.resolve(args.client_role, mode=lab_device.MODE_APP)
        evidence.check("approved-uploader-client", device.serial == lab.APPROVED_ADMIN_PAIR["client"],
                       expected_serial=lab.APPROVED_ADMIN_PAIR["client"], observed_serial=device.serial)
        node = lab.FramedSerial(f"{args.client_role}-{device.serial}", str(device.by_id), evidence)
        time.sleep(2)
        uploader = Uploader(node, evidence, command_timeout=min(10, args.timeout))
        deadline = time.monotonic() + args.timeout
        if args.command in ("upload", "cache"):
            identity = lab.app_info(node)["pubkey_bytes"]
            since = time.monotonic()
            reply = uploader.cache(canonical, image, identity, deadline, args.reupload)
            if args.command == "cache":
                blocks = (len(image) + BLOCK_BYTES - 1) // BLOCK_BYTES
                if not (reply.target == LOCAL_TARGET and not reply.flags & REMOTE
                        and reply.phase == Phase.CACHE_SEALED
                        and reply.manifest_hash == hashlib.sha256(canonical).digest()
                        and reply.counter == struct.unpack_from(">I", canonical, 45)[0]
                        and reply.received == reply.total == blocks
                        and reply.fresh_since(since, time.monotonic())):
                    raise UploaderError("cache did not return fresh, complete, image-bound local CACHE_SEALED")
            else:
                started = time.monotonic()
                reply = uploader.start(args.target, body, args.mode, deadline)
                if args.wait_ready:
                    for target in args.target:
                        reply = uploader.wait_phase(target, Phase.READY, hashlib.sha256(canonical).digest(),
                                                    struct.unpack_from(">I", canonical, 45)[0], started, deadline)
        elif args.command == "commit":
            reply = uploader.commit(args.target, canonical, deadline)
        elif args.command == "abort":
            reply = uploader.abort(args.target, hashlib.sha256(image).digest(), deadline)
        elif args.command == "abort-cache":
            reply = uploader.abort(LOCAL_TARGET, hashlib.sha256(image).digest(), deadline)
        elif args.command == "admin":
            reply = uploader.require_accepted(uploader.exchange(
                Op.SET_ADMIN, args.target + bytes([args.enabled]), args.target))
            if reply.result != Result.OK:
                raise UploaderError("administrator permission has not been durably saved")
        else:
            reply = uploader.status(args.target)
        evidence.log("ota_command_result", command=args.command, **reply.summary())
    except (Exception, SystemExit, KeyboardInterrupt) as exc:
        error = f"{type(exc).__name__}: {exc}"
        evidence.log("fatal", error=error)
        raise
    finally:
        if node is not None:
            node.close()
        evidence.finish(error)


if __name__ == "__main__":
    main()
