#!/usr/bin/env python3
"""One OTA v4 package, durable host job and transmitter-wide scheduler.

build signs a package; deploy stages and explicitly activates it. --stage-only
never activates. Reopening a job always authenticates fresh receiver state.
No private keys are read and no serial port is selected implicitly.
"""
import argparse
from contextlib import ExitStack
import json
import math
import os
from pathlib import Path
import struct
import sys
import time

from ota_common import (Assembly, Error, Frame, Kind, Phase, Result, Status, ZERO_HASH,
                        physical_airtime, public_key, remaining, signed_command, slice_mask)
from ota_compression import Package, descriptor
from ota_job import JobStore, write_exclusive
from ota_transport import NativeTransport, Route
from ota_stock_companion import StockTransport


class Scheduler:
    def __init__(self, job, transport, *, clock=time.monotonic, sleep=time.sleep):
        self.job, self.transport, self.clock, self.sleep = job, transport, clock, sleep
        self.package = job.package
        if transport.owner != job.owner:
            raise Error("companion does not own this durable job")
        policy = job.policy
        self.duty = policy["duty"]
        if not math.isfinite(self.duty) or not 0 < self.duty <= 1:
            raise Error("invalid transmitter duty share")
        cooldown = job.db.execute("SELECT value FROM meta WHERE key='cooldown'").fetchone()
        self.next_tx = clock() + (float(cooldown[0]) if cooldown else 0)
        self.statuses = {}
        self.metrics = json.loads(job.get("metrics")) if self._has_metrics() else {
            "tx": {}, "rx": {}, "tx_attempts": {}, "physical_or_guarded_air_s": 0.0,
            "elapsed_s": 0.0, "repair_frames": 0}
        self.started = clock()

    def _has_metrics(self):
        return self.job.db.execute("SELECT 1 FROM meta WHERE key='metrics'").fetchone() is not None

    def _metrics(self):
        self.metrics["elapsed_s"] += self.clock() - self.started
        self.started = self.clock()
        with self.job.db:
            self.job.db.execute("INSERT OR REPLACE INTO meta VALUES('metrics',?)",
                                (json.dumps(self.metrics, sort_keys=True).encode(),))

    def _count(self, direction, frame, packet_bytes, serial_bytes):
        counts = self.metrics[direction].setdefault(frame.kind.name.lower(),
                                                   {"frames": 0, "ota_bytes": 0, "mesh_bytes": 0,
                                                    "serial_payload_bytes": 0, "serial_wire_bytes": 0})
        counts["frames"] += 1
        counts["ota_bytes"] += len(frame.encode())
        counts["mesh_bytes"] += packet_bytes
        counts["serial_payload_bytes"] += serial_bytes
        counts["serial_wire_bytes"] += serial_bytes + (3 if serial_bytes else 0)

    def _cooldown(self, seconds):
        with self.job.db:
            self.job.db.execute("INSERT OR REPLACE INTO meta VALUES('cooldown',?)",
                                (str(seconds).encode(),))

    def _send(self, kind, body, deadline, *, obj=0, tag=None, indices=None, repair=False):
        tag = self.package.tag if tag is None else tag
        slices = range((len(body) + 127) // 128) if indices is None else indices
        for index in slices:
            wait = self.next_tx - self.clock()
            if wait > 0:
                if wait >= remaining(deadline, self.clock):
                    raise TimeoutError("duty pacing exceeds operation deadline")
                self.sleep(wait)
            frame = Frame(kind, self.job.attempt(), tag, obj, len(body), index, body[index * 128:(index + 1) * 128])
            raw_size = 0 if self.transport.local else len(self.transport.route.packet(frame.encode()))
            serial = (len(frame.encode()) if self.transport.local else raw_size) + getattr(
                self.transport, "serial_command_bytes", 0)
            self._count("tx_attempts", frame, raw_size, serial)
            if not self.transport.local:
                reserve = physical_airtime(raw_size, *self.transport.profile[1:4]) * 1.5 / self.duty
                # Reserve before device I/O: a crash after physical TX but before
                # its reply must not reset the transmitter-wide airtime budget.
                self._cooldown(reserve)
            self._metrics()
            receipt = self.transport.send(frame.encode(), deadline)
            air = receipt.airtime
            if not self.transport.local:
                profile = self.transport.profile
                model = physical_airtime(receipt.wire_bytes, *profile[1:4])
                air = max(air, model)
                self.next_tx = self.clock() + air * (1 / self.duty - 1)
                self._cooldown(max(0, self.next_tx - self.clock()))
            self.metrics["physical_or_guarded_air_s"] += air
            self.metrics["repair_frames"] += int(repair)
            serial = getattr(receipt, "serial_bytes", 0)
            self._count("tx", frame, receipt.wire_bytes, serial)
            self._metrics()

    def _receive(self, kind, request, deadline, tag=None):
        assembly = Assembly(kind, tag, request)
        while self.clock() < deadline:
            raw = self.transport.receive(deadline)
            if raw is None:
                break
            try:
                frame = Frame.decode(raw)
            except Error:
                continue
            packet, serial = getattr(self.transport, "last_rx_bytes", (0, 0))
            self._count("rx", frame, packet, serial)
            body = assembly.feed(frame)
            if body is not None:
                self._metrics()
                return body, frame.tag
        raise TimeoutError(f"no complete {kind.name.lower()} response")

    def query(self, target, deadline, *, persist=True):
        if target not in self.job.targets:
            raise ValueError("query target is outside the durable job")
        for attempt in range(3):
            request, nonce = self.job.request(), os.urandom(16)
            self._send(Kind.QUERY, target + nonce, deadline, obj=request, tag=bytes(8))
            try:
                body, tag = self._receive(Kind.STATUS, request, min(deadline, self.clock() + 30))
                break
            except TimeoutError:
                if attempt == 2:
                    raise
        status = Status.decode(body, target, nonce)
        if tag != status.package[:8]:
            raise Error("signed status/header package mismatch")
        if persist:
            self.job.status(status)
        self.statuses[target] = status
        return status

    def reconcile(self, deadline, *, allow_reset=False):
        previous = {t: self.job.previous_status(t) for t in self.job.targets}
        statuses = [self.query(t, deadline, persist=False) for t in self.job.targets]
        resolved = []
        for status in statuses:
            owned_reset = False
            for kind in (Kind.ABORT, Kind.REPAIR):
                for (operation,) in self.job.uncertain(status.target, kind):
                    body = self.job.db.execute("SELECT body FROM operations WHERE id=?", (operation,)).fetchone()[0]
                    if len(body) != 180 or body[32:64] != status.target:
                        raise Error("invalid durable mutation intent")
                    advanced = status.generation == struct.unpack_from(">I", body, 112)[0] + 1
                    aborted = (kind == Kind.ABORT and status.phase == Phase.ABORTED
                               and status.package == body[64:96] and status.transaction == body[96:112])
                    repaired = (kind == Kind.REPAIR and status.phase == Phase.IDLE
                                and status.package == ZERO_HASH and not any(status.transaction))
                    if advanced and (aborted or repaired):
                        owned_reset = True
                        resolved.append(operation)
            old = previous[status.target]
            if old is not None:
                prior = Status.decode(old, status.target, old[32:48])
                if (prior.package == self.package.digest and any(prior.transaction)
                        and (status.package != self.package.digest
                             or prior.transaction != status.transaction or prior.generation != status.generation)
                        and prior.phase not in (Phase.IDLE, Phase.ABORTED, Phase.FAILED)
                        and not owned_reset and not allow_reset):
                    raise Error("receiver transaction changed; refusing implicit re-admission")
        for status in statuses:
            self.job.status(status)
            if status.phase in (Phase.ACTIVATION_PENDING, Phase.TRIAL, Phase.CONFIRMED):
                for (operation,) in self.job.uncertain(status.target, Kind.ACTIVATE):
                    body = self.job.db.execute("SELECT body FROM operations WHERE id=?", (operation,)).fetchone()[0]
                    if (body[64:96] == status.package and body[96:112] == status.transaction
                            and struct.unpack_from(">I", body, 112)[0] == status.generation):
                        self.job.resolve(operation, "authenticated")
        for operation in resolved:
            self.job.resolve(operation, "authenticated")
        return statuses

    def _command(self, kind, target, status, deadline):
        nonce = status.challenge if kind in (Kind.ADMIT, Kind.REPAIR) else status.transaction
        digest = ZERO_HASH if kind == Kind.REPAIR else self.package.digest
        body = signed_command(kind, self.job.owner, target, digest, nonce, status.generation,
                              lambda message: self.transport.sign(message, deadline))
        operation = self.job.intent(target, kind, body)
        self._send(kind, body, deadline, tag=digest[:8])
        after = self.query(target, deadline, persist=False)
        return operation, after

    def _check_active(self, status):
        package = self.package
        if (status.package != package.digest or status.counter != package.counter
                or not any(status.transaction) or status.next_chunk > len(package.chunks)):
            raise Error("receiver does not have this exact package/transaction "
                        f"(target={status.target.hex()} phase={status.phase.name.lower()} "
                        f"result={status.result.name.lower()} generation={status.generation} "
                        f"counter={status.counter})")
        if status.phase in (Phase.ABORTED, Phase.FAILED, Phase.METADATA_FAULT):
            raise Error(f"receiver candidate is {status.phase.name.lower()}")
        if status.next_chunk < len(package.chunks):
            if status.missing & ~slice_mask(len(package.chunks[status.next_chunk].stored)):
                raise Error("authenticated bitmap outside current chunk")
        elif status.missing:
            raise Error("completed cursor has a nonempty missing bitmap")

    def _admit(self, status, deadline):
        target = status.target
        if status.package == self.package.digest and status.phase not in (Phase.IDLE, Phase.ABORTED):
            self._check_active(status)
            admissions = self.job.db.execute("SELECT id,body FROM operations WHERE target=? AND kind=?",
                                              (target, int(Kind.ADMIT))).fetchall()
            matching = [(op, body) for op, body in admissions
                        if len(body) == 180 and body[:32] == self.job.owner
                        and body[32:64] == target and body[64:96] == self.package.digest
                        and struct.unpack_from(">I", body, 112)[0] + 1 == status.generation
                        and body[96:112] != status.transaction]
            if not matching:
                raise Error("active receiver was not admitted by this durable job")
            for op, _ in matching:
                self.job.resolve(op, "authenticated")
            return status
        if status.phase not in (Phase.IDLE, Phase.CONFIRMED):
            raise Error("non-idle receiver requires explicit abort/repair, never takeover")
        for (op,) in self.job.uncertain(target, Kind.ADMIT):
            body = self.job.db.execute("SELECT body FROM operations WHERE id=?", (op,)).fetchone()[0]
            if struct.unpack_from(">I", body, 112)[0] != status.generation:
                raise Error("uncertain admission does not match fresh idle generation")
            self.job.resolve(op, "not-accepted")
        for attempt in range(3):
            if not status.evidence & 1 or self.package.counter <= status.floor:
                raise Error("package must exceed authenticated confirmed floor")
            operation, after = self._command(Kind.ADMIT, target, status, deadline)
            unchanged = (after.phase == status.phase and after.generation == status.generation
                         and after.package == status.package and after.transaction == status.transaction
                         and after.counter == status.counter)
            if unchanged:
                self.job.resolve(operation, "not-accepted")
                if attempt < 2:
                    self._send(Kind.MANIFEST, self.package.manifest, deadline, repair=True)
                    refreshed = self.query(target, deadline)
                    if (refreshed.phase != after.phase or refreshed.generation != after.generation
                            or refreshed.package != after.package or refreshed.transaction != after.transaction
                            or refreshed.counter != after.counter):
                        raise Error("receiver transaction changed while retrying unaccepted admission")
                    status = refreshed
                    continue
            self._check_active(after)
            if after.generation != status.generation + 1 or after.transaction == status.challenge:
                raise Error("admission did not create a distinct new transaction")
            self.job.resolve(operation, "authenticated")
            self.job.status(after)
            return after

    def progress(self, target, deadline):
        for attempt in range(3):
            request = self.job.request()
            self._send(Kind.PROGRESS_QUERY, target, deadline, obj=request)
            try:
                body, _ = self._receive(Kind.PROGRESS, request, min(deadline, self.clock() + 30), self.package.tag)
                break
            except TimeoutError:
                if attempt == 2:
                    raise
        if len(body) != 48 or body[:32] != target:
            raise Error("invalid progress object")
        generation, chunk, missing, phase, result = struct.unpack_from(">IHQBB", body, 32)
        known = self.statuses[target]
        if generation != known.generation or chunk > len(self.package.chunks):
            raise Error("progress generation/cursor mismatch")
        try:
            phase, result = Phase(phase), Result(result)
        except ValueError as exc:
            raise Error("invalid progress phase/result") from exc
        if chunk < len(self.package.chunks) and missing & ~slice_mask(len(self.package.chunks[chunk].stored)):
            raise Error("progress bitmap outside current stored chunk")
        # Last-result is diagnostic and can reflect unrelated/hostile packets.
        # Unsigned progress cannot establish either permission or failure.
        return chunk, missing, phase

    def stage(self, deadline):
        self.reconcile(deadline)
        # Manifest is shared once. Recovery resupplies exact authenticated bytes,
        # without changing the receiver's admitted transaction.
        self._send(Kind.MANIFEST, self.package.manifest, deadline)
        # Signature checks can outlast the next RF packet. Wait for a signed
        # response before sending admission fragments, rather than guessing a delay.
        statuses = self.reconcile(deadline)
        active = {}
        for status in statuses:
            if status.installed(self.package):
                active[status.target] = (len(self.package.chunks), 0, status.phase)
            else:
                status = self._admit(status, deadline)
                self.statuses[status.target] = status
                active[status.target] = (status.next_chunk, status.missing, status.phase)
        attempts, cycles = {}, 0
        while True:
            remaining(deadline, self.clock)
            unfinished = [p[0] for p in active.values() if p[0] < len(self.package.chunks)]
            if not unfinished:
                fresh = self.reconcile(deadline)
                if all(s.phase == Phase.READY or s.installed(self.package) for s in fresh):
                    for status in fresh:
                        self._check_active(status)
                    return fresh
                for s in fresh:
                    self._check_active(s)
                    active[s.target] = (s.next_chunk, s.missing, s.phase)
                self.sleep(min(.05, remaining(deadline, self.clock)))
                continue
            chunk = min(unfinished)
            stored = self.package.chunks[chunk].stored
            mask = 0
            for cursor, missing, phase in active.values():
                if cursor == chunk and phase == Phase.RECEIVING:
                    mask |= missing
            if mask:
                indices = [i for i in range((len(stored) + 127) // 128) if mask & (1 << i)][:16]
                for index in indices:
                    key = chunk, index
                    attempts[key] = attempts.get(key, 0) + 1
                    if attempts[key] > 12:
                        raise Error("selective repair limit exhausted")
                    self._send(Kind.DATA, stored, deadline, obj=chunk, indices=[index],
                               repair=attempts[key] > 1)
            for target in active:
                if active[target][2] != Phase.CONFIRMED:
                    active[target] = self.progress(target, deadline)
            cycles += 1
            if cycles % 8 == 0:
                for status in self.reconcile(deadline):
                    self._check_active(status)
                    active[status.target] = (status.next_chunk, status.missing, status.phase)

    def apply(self, deadline):
        fresh = self.reconcile(deadline)
        # Validate the entire fleet before authorizing any activation.
        for status in fresh:
            self._check_active(status)
            if status.phase not in (Phase.READY, Phase.ACTIVATION_PENDING, Phase.TRIAL, Phase.CONFIRMED):
                raise Error("fresh authenticated READY required for activation")
            if status.phase == Phase.CONFIRMED and not status.installed(self.package):
                raise Error("confirmed receiver does not prove the expected running hash/floor")
        for status in fresh:
            if status.installed(self.package):
                continue
            if status.phase == Phase.READY:
                if self.job.uncertain(status.target, Kind.ACTIVATE):
                    raise Error("uncertain activation needs explicit reconciliation; not blindly repeated")
                operation, after = self._command(Kind.ACTIVATE, status.target, status, deadline)
                if after.phase not in (Phase.ACTIVATION_PENDING, Phase.TRIAL, Phase.CONFIRMED):
                    raise Error("activation was not authenticated as accepted")
                self.job.resolve(operation, "authenticated")
                self.job.status(after)
        while True:
            statuses = self.reconcile(deadline)
            for status in statuses:
                self._check_active(status)
            if all(s.installed(self.package) for s in statuses):
                return statuses
            self.sleep(min(.2, remaining(deadline, self.clock)))

    def mutate(self, kind, deadline):
        statuses = self.reconcile(deadline, allow_reset=kind == Kind.REPAIR)
        for status in statuses:
            if kind == Kind.ABORT:
                if (status.phase == Phase.ABORTED and status.package == self.package.digest
                        and status.counter == self.package.counter and any(status.transaction)):
                    continue
                self._check_active(status)
                if status.phase not in (Phase.RECEIVING, Phase.VERIFYING, Phase.READY):
                    raise Error("cannot abort an activation or confirmed image")
            operation, after = self._command(kind, status.target, status, deadline)
            expected = Phase.ABORTED if kind == Kind.ABORT else Phase.IDLE
            if after.phase != expected:
                raise Error("guarded mutation not authenticated by readback")
            self.job.resolve(operation, "authenticated")
            self.job.status(after)
        return [self.statuses[t] for t in self.job.targets]

    def result(self):
        self._metrics()
        return {"package": self.package.digest.hex(), "metrics": self.metrics,
                "unconfirmed_tx_attempts": sum(v["frames"] for v in self.metrics["tx_attempts"].values())
                - sum(v["frames"] for v in self.metrics["tx"].values()),
                "airtime_scope": "confirmed host TX physical measurements or conservative guard, not total fleet airtime",
                "targets": [{"target": t.hex(), "phase": s.phase.name.lower(),
                             "generation": s.generation, "floor": s.floor,
                             "last_result": s.result.name.lower(),
                             "status_authenticated": True, "installation_confirmed": s.installed(self.package)}
                            for t, s in self.statuses.items()]}


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build one signed immutable package")
    build.add_argument("--image", type=Path, required=True)
    build.add_argument("--board", required=True, choices=("xiao_nrf52840", "xiao_nrf52840_sense",
                                                        "sensecap_solar_p1", "xiao_s3_wio"))
    build.add_argument("--role-id", type=int, choices=(0, 1), required=True)
    build.add_argument("--counter", type=int, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--raw", action="store_true")
    for name in ("deploy", "status", "abort", "repair"):
        command = commands.add_parser(name)
        command.add_argument("--job", type=Path, required=True)
        if name == "deploy":
            command.add_argument("--package", type=Path)
            command.add_argument("--target", type=public_key, action="append", default=[])
            command.add_argument("--stage-only", action="store_true")
        command.add_argument("--duty", type=float)
        command.add_argument("--flood", action="store_true", default=None)
        command.add_argument("--path", help="explicit path bytes in hex")
        command.add_argument("--path-width", type=int, choices=(1, 2, 3))
        command.add_argument("--max-path-bytes", type=int,
                             help="explicit maximum grown RX/TX path, at most20")
    for command in commands.choices.values():
        command.add_argument("--by-id", required=True)
        command.add_argument("--usb-serial", help="physical serial; required for stock")
        command.add_argument("--by-path", help="physical anchor for duplicate USB serials")
        command.add_argument("--id-path")
        command.add_argument("--usb-vid", type=lambda s: int(s, 16))
        command.add_argument("--usb-pid", type=lambda s: int(s, 16))
        command.add_argument("--dtr", action="store_true")
        command.add_argument("--owner", required=True, type=public_key)
        command.add_argument("--transport", choices=("native", "stock"), default="native")
        command.add_argument("--local", action="store_true", help="native local receiver, same transaction engine")
        command.add_argument("--timeout", type=float, default=3600)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ValueError("positive finite timeout required")
    if args.local and args.transport != "native":
        raise ValueError("local receiver feed requires native bridge")
    if args.transport == "stock" and not args.usb_serial:
        raise ValueError("stock transport requires explicit --usb-serial")
    from ota_devices import open_companion
    with ExitStack() as stack:
        job = None
        route = Route()
        if args.command != "build":
            if args.job.exists():
                job = stack.enter_context(JobStore.open(args.job))
                policy = job.policy
                if policy["transport"] != args.transport or policy["local"] != args.local:
                    raise Error("resume must preserve transport/local routing policy")
                if getattr(args, "target", []) and args.target != job.targets:
                    raise Error("resume cannot replace the target set")
                route = Route.from_policy(policy["route"])
                selected = {"flood": args.flood, "path": args.path, "width": args.path_width,
                            "max_path_bytes": args.max_path_bytes}
                if ((args.duty is not None and args.duty != policy["duty"])
                        or any(value is not None and value != policy["route"][key]
                               for key, value in selected.items())):
                    raise Error("resume cannot silently change route or airtime policy")
                if getattr(args, "package", None) is not None and Package.open(args.package).encode() != job.package.encode():
                    raise Error("resume cannot replace the immutable package")
            else:
                if args.command != "deploy" or args.package is None or not args.target:
                    raise Error("new job requires deploy --package and explicit --target")
                duty = .02 if args.duty is None else args.duty
                if not math.isfinite(duty) or not 0 < duty <= 1:
                    raise ValueError("duty share must be in (0,1]")
                if args.local and args.target != [args.owner]:
                    raise ValueError("native local feed requires the companion's own full target key")
                route = Route(bool(args.flood), bytes.fromhex(args.path or ""), args.path_width or 1,
                              args.max_path_bytes or 0)
                route.validate()
                policy = {"duty": duty, "route": route.policy(), "transport": args.transport, "local": args.local}
                job = stack.enter_context(JobStore.create(args.job, Package.open(args.package), args.owner,
                                                         args.target, policy))
        node = stack.enter_context(open_companion(
            args.by_id, dtr=args.dtr, serial=args.usb_serial, by_path=args.by_path,
            id_path=args.id_path, vid=args.usb_vid, pid=args.usb_pid))
        transport = (NativeTransport(node, args.owner, route, local=args.local)
                     if args.transport == "native" else StockTransport(node, args.owner, route))
        deadline = time.monotonic() + args.timeout
        transport.identify(deadline)
        if job is not None:
            profile = json.dumps(list(transport.profile)).encode()
            previous = job.db.execute("SELECT value FROM meta WHERE key='ordinary_profile'").fetchone()
            if previous is not None and previous[0] != profile:
                raise Error("ordinary radio/forwarding differs from the durable job; no retune")
            with job.db:
                job.db.execute("INSERT OR REPLACE INTO meta VALUES('ordinary_profile',?)", (profile,))
        error, result = None, None
        try:
            if args.command == "build":
                image = args.image.read_bytes()
                canonical = descriptor(image, args.board, args.role_id, args.counter)
                package = Package.build(image, canonical, args.owner, lambda msg: transport.sign(msg, deadline),
                                        compress=not args.raw)
                write_exclusive(args.output, package.encode())
                result = {"package": package.digest.hex(), "manifest_bytes": len(package.manifest),
                          "image_bytes": len(image), "chunks": len(package.chunks)}
            else:
                scheduler = Scheduler(job, transport)
                if args.command == "deploy":
                    scheduler.stage(deadline)
                    if not args.stage_only:
                        scheduler.apply(deadline)
                elif args.command == "status":
                    scheduler.reconcile(deadline)
                else:
                    scheduler.mutate(Kind.ABORT if args.command == "abort" else Kind.REPAIR, deadline)
                result = scheduler.result()
        except BaseException as exc:
            error = exc
            raise
        finally:
            cleanup = "ordinary-profile-unchanged"
            try:
                transport.cleanup(time.monotonic() + 15)
            except BaseException as exc:
                cleanup = f"readback-unavailable:{type(exc).__name__}"
                if error is None:
                    raise
                error.add_note("ordinary radio cleanup readback also failed; no sender settings were mutated")
            finally:
                if job is not None:
                    with job.db:
                        job.db.execute("INSERT OR REPLACE INTO meta VALUES('radio_cleanup',?)", (cleanup.encode(),))
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (Error, OSError, ValueError, TimeoutError, KeyboardInterrupt) as exc:
        print(f"ota_v4: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
