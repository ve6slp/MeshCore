"""Production Python -> real native C++ receiver; no model of receiver business logic."""
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct
from types import SimpleNamespace
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from test_ota_uploader import ADMIN, ADMIN_PRIVATE, POLICY, Scratch, TARGET, canonical, package
from test_ota_stock_companion import Clock
from ota_common import Error, Frame, FramedSerial, Kind, Phase, physical_airtime
from ota_job import JobStore
from ota_compression import Package
from ota_compression_report import measure
from ota_stock_companion import StockTransport
from ota_transport import NativeTransport, Route, TxReceipt, packet_payload
from ota_uploader import Scheduler

DRIVER = os.environ.get("OTA_V4_DRIVER")


class Driver:
    def __init__(self, binary, directory, seed):
        self.arguments = [binary, str(directory), ADMIN.hex(), seed.hex()]
        self.process = subprocess.Popen(self.arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, bufsize=1)

    def exchange(self, request):
        self.process.stdin.write(request + "\n")
        self.process.stdin.flush()
        replies = []
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise Error("native receiver driver exited unexpectedly")
            if line.strip() == ".":
                return replies
            replies.append(bytes.fromhex(line.strip()))

    def restart(self):
        self.close()
        self.__init__(*([self.arguments[0], Path(self.arguments[1]), bytes.fromhex(self.arguments[3])]))

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=10)
        self.process.stdout.close()


class DriverTransport:
    """Only I/O and deterministic radio loss, never receiver state emulation."""
    owner, local = ADMIN, False
    serial_command_bytes = 3
    profile = (918000, 62500, 7, 5, 1)
    route = Route(flood=True, max_path_bytes=1)

    def __init__(self, drivers, clock):
        self.drivers, self.clock, self.queue = drivers, clock, deque()
        self.sent, self.drop, self.dropped = [], set(), set()
        self.interrupt_after = None
        self.interrupt_activate = False
        self.interrupt_kind = None
        self.auto_confirm = True
        self.auto_rollback = False

    def sign(self, message, _):
        return ADMIN_PRIVATE.sign(message)

    def send(self, raw, _):
        frame = Frame.decode(raw)
        self.sent.append(frame)
        for index, driver in enumerate(self.drivers):
            key = index, frame.object, frame.slice
            if frame.kind == Kind.DATA and key in self.drop and key not in self.dropped:
                self.dropped.add(key)
                continue
            self.queue.extend(driver.exchange(raw.hex()))
            if self.auto_confirm and frame.kind == Kind.ACTIVATE and frame.slice == (frame.total - 1) // 128:
                self.queue.extend(driver.exchange("confirm"))
            if self.auto_rollback and frame.kind == Kind.ACTIVATE and frame.slice == (frame.total - 1) // 128:
                self.queue.extend(driver.exchange("rollback"))
        self.clock.sleep(.001)
        if ((self.interrupt_activate and frame.kind == Kind.ACTIVATE) or frame.kind == self.interrupt_kind) \
                and frame.slice == (frame.total - 1) // 128:
            self.interrupt_activate = False
            self.interrupt_kind = None
            raise ConnectionError("synthetic lost mutation response")
        if self.interrupt_after is not None and sum(f.kind == Kind.DATA for f in self.sent) >= self.interrupt_after:
            self.interrupt_after = None
            raise ConnectionError("synthetic host interruption after receiver I/O")
        size = len(self.route.packet(raw))
        return TxReceipt(physical_airtime(size), size, size + 3)

    def receive(self, deadline):
        if self.queue:
            raw = self.queue.popleft()
            self.last_rx_bytes = (len(raw) + 3, len(raw) + 4)
            return raw
        self.clock.sleep(max(0, deadline - self.clock()))
        return None


class CompanionUSB:
    """USB/physical-TX device facade only; every OTA object reaches real C++."""
    def __init__(self, driver, clock, native):
        self.driver, self.clock, self.native = driver, clock, native
        self.output, self.signing, self.commands = bytearray(), bytearray(), []
        self.sent = self.direct = 0
        self.node = FramedSerial.__new__(FramedSerial)
        self.node.name, self.node.buffer, self.node.pending = "synthetic USB", bytearray(), []
        self.node.stream = SimpleNamespace(write_timeout=0)
        self.node._write_bytes, self.node._read_bytes = self.write, self.read

    def push(self, payload):
        self.output.extend(b">" + struct.pack("<H", len(payload)) + payload)

    def read(self, timeout):
        if not self.output:
            self.clock.sleep(timeout)
        data = bytes(self.output[:4096])
        del self.output[:4096]
        return data

    def write(self, wire):
        if wire[:1] != b"<" or len(wire) != struct.unpack_from("<H", wire, 1)[0] + 3:
            raise AssertionError("invalid production USB framing")
        body = wire[3:]
        if len(body) > 176:
            raise AssertionError("USB frame overflow")
        self.commands.append(body)
        command = body[0]
        if command == 1:
            info = bytearray(58)
            info[:2] = b"\x05\x01"
            info[4:36] = ADMIN
            info[48:58] = struct.pack("<IIBB", 918000, 62500, 7, 5)
            self.push(info + b"synthetic companion")
        elif command == 22:
            info = bytearray(82)
            info[:2], info[80] = b"\x0d\x0e", 1
            info[60:66] = b"1.18.0"
            self.push(info)
        elif command == 33:
            self.signing.clear()
            self.push(b"\x13\0" + struct.pack("<I", 8192))
        elif command == 34:
            self.signing.extend(body[1:])
            self.push(b"\0")
        elif command == 35:
            self.push(b"\x14" + ADMIN_PRIVATE.sign(bytes(self.signing)))
        elif command == 56:
            if body[1] == 0:
                self.push(b"\x18\0" + bytes(9))
            elif body[1] == 1:
                self.push(b"\x18\x01" + bytes(12))
            else:
                self.push(b"\x18\x02" + struct.pack("<IIIIIII", 0, self.sent, 0, self.direct, 0, 0, 0))
        elif command in (65, 67):
            op = body[2] if command == 67 else 1
            if command == 67 and op == 0:
                self.push(bytes([30, 4, 0, 0]))
                return
            local = command == 67 and op == 2
            raw = body[3:] if command == 67 else body[2:]
            frame = raw if local else packet_payload(raw)
            replies = self.driver.exchange(frame.hex())
            decoded = Frame.decode(frame)
            if decoded.kind == Kind.ACTIVATE and decoded.slice == (decoded.total - 1) // 128:
                replies += self.driver.exchange("confirm")
            self.sent += int(not local)
            self.direct += int(not local and raw[0] & 3 == 2)
            if command == 65:
                self.push(b"\0")
            else:
                self.push(bytes([30, 4, op, 0]) + (struct.pack(">I", 1000) if op == 1 else b""))
            for reply in replies:
                if local:
                    self.push(bytes([30, 4, 3]) + reply)
                else:
                    packet = b"\x31\0" + reply
                    self.push((b"\x91" if self.native else b"\x88\x08\xc0") + packet)
        else:
            raise AssertionError(f"forbidden device operation {command}")
        self.clock.sleep(.001)


@unittest.skipUnless(DRIVER, "parent Make target sets OTA_V4_DRIVER to the real native receiver")
class NativeEndToEndTests(Scratch):
    def setup_job(self, image, count=1, compress=True, local=False):
        pkg, clock = package(image, compress), Clock()
        drivers, targets = [], []
        for index in range(count):
            seed = bytes([1 if local else index + 2]) * 32
            key = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            directory = self.directory / f"receiver-{index}"
            directory.mkdir()
            driver = Driver(DRIVER, directory, seed)
            self.addCleanup(driver.close)
            drivers.append(driver)
            targets.append(key)
        policy = {**POLICY, "local": local}
        job = JobStore.create(self.directory / "job", pkg, ADMIN, targets, policy)
        self.addCleanup(job.close)
        transport = DriverTransport(drivers, clock)
        return pkg, job, transport, clock

    def test_no_loss_fleet_report_matches_executed_control_and_data_frames(self):
        image = hashlib.shake_256(b"native v4 frame accounting").digest(24000)
        pkg, job, transport, clock = self.setup_job(image, 2, compress=False)
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 1000)
        statuses = scheduler.apply(clock() + 1000)
        self.assertTrue(all(status.installed(pkg) for status in statuses))
        report = measure(pkg, transport.route, len(job.targets))
        metrics = scheduler.result()["metrics"]
        for key, modeled in report["counts"].items():
            direction, kind = key.split("/")
            actual = metrics[direction][kind]
            with self.subTest(key=key):
                self.assertEqual(modeled["frames"], actual["frames"])
                self.assertEqual(modeled["ota_bytes"], actual["ota_bytes"])

    def test_routed_queries_reach_real_receiver_with_nonce_and_reply_route_intact(self):
        pkg, job, transport, clock = self.setup_job(b"routed image" * 1000)
        transport.route = Route(path=bytes.fromhex("11223344"), width=2, max_path_bytes=6)
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 1000)
        self.assertTrue(all(s.installed(pkg) for s in scheduler.apply(clock() + 1000)))
        queries = [f for f in transport.sent if f.kind in (Kind.QUERY, Kind.PROGRESS_QUERY)]
        self.assertTrue(queries)
        for frame in queries:
            base = 48 if frame.kind == Kind.QUERY else 32
            self.assertEqual(TARGET, frame.data[:32])
            self.assertEqual(bytes.fromhex("4233441122"), frame.data[base:])
        report = measure(pkg, transport.route)
        self.assertEqual(76, report["counts"]["tx/query"]["ota_bytes"] //
                         report["counts"]["tx/query"]["frames"])

    def test_raw_fleet_lost_slices_shared_once_then_selective_repair_and_signed_installation(self):
        image = hashlib.shake_256(b"native v4 fleet").digest(20000)
        pkg, job, transport, clock = self.setup_job(image, 2, compress=False)
        transport.drop = {(0, 0, 2), (1, 0, 3)}
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 1000)
        statuses = scheduler.apply(clock() + 1000)
        self.assertTrue(all(s.installed(pkg) for s in statuses))
        initial = sum((len(c.stored) + 127) // 128 for c in pkg.chunks)
        sent = [f for f in transport.sent if f.kind == Kind.DATA]
        self.assertEqual(len(sent), initial + 2)
        self.assertEqual(scheduler.result()["metrics"]["repair_frames"], 2)
        self.assertEqual(len({(f.object, f.slice) for f in sent}), initial)

    def test_lost_manifest_slice_is_repaired_without_readmitting_the_other_receiver(self):
        pkg, job, transport, clock = self.setup_job(b"firmware" * 2000, 2)
        send = transport.send
        lost = False

        def lose_manifest(raw, deadline):
            nonlocal lost
            frame = Frame.decode(raw)
            if frame.kind == Kind.MANIFEST and frame.slice == 0 and not lost:
                lost = True
                transport.sent.append(frame)
                transport.queue.extend(transport.drivers[0].exchange(raw.hex()))
                size = len(transport.route.packet(raw))
                return TxReceipt(physical_airtime(size), size, size + 3)
            return send(raw, deadline)

        transport.send = lose_manifest
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 1000)
        self.assertTrue(lost)
        self.assertEqual([s.generation for s in scheduler.statuses.values()], [1, 1])
        states = [row[0] for row in job.db.execute("SELECT state FROM operations")]
        self.assertEqual(states.count("authenticated"), 2)
        self.assertEqual(states.count("not-accepted"), 1)
        self.assertTrue(all(s.installed(pkg) for s in scheduler.apply(clock() + 1000)))

    def test_unreceived_admission_is_retried_but_persistent_loss_stops(self):
        _, job, transport, clock = self.setup_job(b"firmware" * 2000)
        send = transport.send

        def lose_admission(raw, deadline):
            frame = Frame.decode(raw)
            if frame.kind == Kind.ADMIT and frame.slice == 1:
                transport.sent.append(frame)
                size = len(transport.route.packet(raw))
                return TxReceipt(physical_airtime(size), size, size + 3)
            return send(raw, deadline)

        transport.send = lose_admission
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        with self.assertRaisesRegex(Error, "phase=idle.*generation=0"):
            scheduler.stage(clock() + 1000)
        states = [row[0] for row in job.db.execute("SELECT state FROM operations")]
        self.assertEqual(states, ["not-accepted"] * 3)
        self.assertFalse(any(f.kind in (Kind.DATA, Kind.ACTIVATE) for f in transport.sent))

    def test_host_and_receiver_restart_resume_without_second_admission(self):
        image = hashlib.shake_256(b"native v4 restart").digest(24000)
        pkg, job, transport, clock = self.setup_job(image, compress=False)
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        transport.interrupt_after = 70
        with self.assertRaises(ConnectionError):
            scheduler.stage(clock() + 1000)
        self.assertEqual(scheduler.result()["unconfirmed_tx_attempts"], 1)
        admitted = sum(f.kind == Kind.ADMIT for f in transport.sent)
        job.close()
        transport.drivers[0].restart()
        transport.queue.clear()
        with JobStore.open(self.directory / "job") as resumed:
            scheduler = Scheduler(resumed, transport, clock=clock, sleep=clock.sleep)
            self.assertGreater(scheduler.next_tx, clock())
            scheduler.stage(clock() + 1000)
            self.assertEqual(sum(f.kind == Kind.ADMIT for f in transport.sent), admitted)
            self.assertTrue(all(s.installed(pkg) for s in scheduler.apply(clock() + 1000)))

    def test_immediate_rollback_is_saved_as_failure_without_repeating_activation(self):
        _, job, transport, clock = self.setup_job(b"firmware" * 2000)
        transport.auto_confirm, transport.auto_rollback = False, True
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 1000)
        with self.assertRaisesRegex(Error, "reports failed candidate after activation"):
            scheduler.apply(clock() + 1000)
        saved = job.previous_status(TARGET)
        self.assertEqual(saved[124], Phase.FAILED)
        self.assertFalse(job.uncertain(TARGET, Kind.ACTIVATE))
        activations = sum(f.kind == Kind.ACTIVATE for f in transport.sent)
        with self.assertRaisesRegex(Error, "candidate is failed"):
            scheduler.apply(clock() + 1000)
        self.assertEqual(sum(f.kind == Kind.ACTIVATE for f in transport.sent), activations)

    def test_uncertain_activation_reconciles_terminal_failure_without_replay(self):
        _, job, transport, clock = self.setup_job(b"firmware" * 2000)
        transport.auto_confirm, transport.auto_rollback = False, True
        transport.interrupt_activate = True
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 1000)
        with self.assertRaises(ConnectionError):
            scheduler.apply(clock() + 1000)
        self.assertTrue(job.uncertain(TARGET, Kind.ACTIVATE))
        activations = sum(f.kind == Kind.ACTIVATE for f in transport.sent)
        self.assertEqual(scheduler.reconcile(clock() + 1000)[0].phase, Phase.FAILED)
        self.assertFalse(job.uncertain(TARGET, Kind.ACTIVATE))
        self.assertEqual(sum(f.kind == Kind.ACTIVATE for f in transport.sent), activations)

    def test_admission_waits_for_receiver_after_manifest_verification(self):
        _, job, transport, clock = self.setup_job(b"firmware" * 2000)
        send = transport.send
        verifying = False
        dropped = []

        def delayed_receiver(raw, deadline):
            nonlocal verifying
            frame = Frame.decode(raw)
            if verifying and frame.kind in (Kind.ADMIT, Kind.QUERY):
                dropped.append(frame.kind)
                transport.sent.append(frame)
                if frame.kind == Kind.QUERY:
                    verifying = False
                size = len(transport.route.packet(raw))
                return TxReceipt(physical_airtime(size), size, size + 3)
            receipt = send(raw, deadline)
            if frame.kind == Kind.MANIFEST and frame.slice == (frame.total - 1) // 128:
                verifying = True
            return receipt

        transport.send = delayed_receiver
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        ready = scheduler.stage(clock() + 1000)
        self.assertEqual(ready[0].phase, Phase.READY)
        self.assertEqual(dropped, [Kind.QUERY])

    def test_next_package_upgrades_confirmed_receiver_without_repair(self):
        first, job, transport, clock = self.setup_job(b"first installed firmware" * 500)
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 1000)
        installed = scheduler.apply(clock() + 1000)[0]
        self.assertTrue(installed.installed(first))
        image = b"next installed firmware" * 600
        next_package = Package.build(image, canonical(image, counter=first.counter + 1),
                                     ADMIN, ADMIN_PRIVATE.sign)
        with JobStore.create(self.directory / "next-job", next_package, ADMIN, [TARGET], POLICY) as next_job:
            scheduler = Scheduler(next_job, transport, clock=clock, sleep=clock.sleep)
            ready = scheduler.stage(clock() + 1000)[0]
            self.assertEqual((ready.phase, ready.floor, ready.generation),
                             (Phase.READY, first.counter, installed.generation + 1))
            self.assertNotEqual(ready.transaction, installed.transaction)
            self.assertTrue(scheduler.apply(clock() + 1000)[0].installed(next_package))
        self.assertFalse(any(f.kind in (Kind.REPAIR, Kind.ABORT) for f in transport.sent))

    def test_compressed_independent_chunks_use_real_decoder_and_raw_hash(self):
        branch_bytes = bytearray()
        for offset in range(0, 20000, 4):
            value = (0x70000 - (offset % 8192) - 4) >> 1
            branch_bytes.extend(((value >> 11) & 255, 0xF0 | ((value >> 19) & 7),
                                 value & 255, 0xF8 | ((value >> 8) & 7)))
        image = bytes(branch_bytes)
        pkg, job, transport, clock = self.setup_job(image)
        self.assertTrue(any(c.codec == 2 for c in pkg.chunks))
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 1000)
        self.assertTrue(all(s.installed(pkg) for s in scheduler.apply(clock() + 1000)))

    @unittest.skipUnless(os.environ.get("OTA_V4_IMAGE"), "explicit genuine firmware image target")
    def test_genuine_firmware_image_reaches_byte_exact_signed_confirmed_state(self):
        image = Path(os.environ["OTA_V4_IMAGE"]).read_bytes()
        pkg, job, transport, clock = self.setup_job(image)
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 100000)
        statuses = scheduler.apply(clock() + 100000)
        self.assertTrue(all(status.installed(pkg) for status in statuses))
        report = measure(pkg, transport.route)
        report["execution"] = scheduler.result()
        report["execution_scope"] = (
            "genuine image through production host, real-crypto native C++ receiver and file-backed "
            "staging; synthetic test signing keys and simulated boot confirmation, not physical hardware")
        output = Path(os.environ["OTA_V4_IMAGE_EVIDENCE"])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    def test_explicit_abort_and_repair_preserve_confirmed_floor(self):
        _, job, transport, clock = self.setup_job(b"a" * 8192)
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 1000)
        aborted = scheduler.mutate(Kind.ABORT, clock() + 1000)
        self.assertEqual(aborted[0].phase, Phase.ABORTED)
        repaired = scheduler.mutate(Kind.REPAIR, clock() + 1000)
        self.assertEqual((repaired[0].phase, repaired[0].floor), (Phase.IDLE, aborted[0].floor))

    def test_current_admin_revocation_prevents_activation_and_never_claims_installation(self):
        pkg, job, transport, clock = self.setup_job(b"admin bound" * 1000)
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 1000)
        transport.drivers[0].exchange("fault admin")
        with self.assertRaisesRegex(Error, "activation"):
            scheduler.apply(clock() + 1000)
        self.assertFalse(scheduler.statuses[TARGET].installed(pkg))
        self.assertTrue(job.uncertain(TARGET, Kind.ACTIVATE))

    def test_lost_activation_response_reconciles_confirmed_without_blind_activation(self):
        pkg, job, transport, clock = self.setup_job(b"activation crash" * 1000)
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 1000)
        transport.interrupt_activate = True
        with self.assertRaises(ConnectionError):
            scheduler.apply(clock() + 1000)
        activations = sum(f.kind == Kind.ACTIVATE for f in transport.sent)
        job.close()
        transport.drivers[0].restart()
        transport.queue.clear()
        with JobStore.open(self.directory / "job") as resumed:
            recovered = Scheduler(resumed, transport, clock=clock, sleep=clock.sleep)
            self.assertTrue(all(s.installed(pkg) for s in recovered.apply(clock() + 1000)))
            self.assertEqual(sum(f.kind == Kind.ACTIVATE for f in transport.sent), activations)

    def serial_case(self, native, local=False):
        pkg, job, driver_transport, clock = self.setup_job(b"production serial transport" * 700, local=local)
        usb = CompanionUSB(driver_transport.drivers[0], clock, native)
        transport = (NativeTransport(usb.node, ADMIN, DriverTransport.route, local=local,
                                     clock=clock, sleep=clock.sleep) if native else
                     StockTransport(usb.node, ADMIN, DriverTransport.route, clock=clock, sleep=clock.sleep))
        transport.identify(clock() + 1000)
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        scheduler.stage(clock() + 1000)
        self.assertTrue(all(s.installed(pkg) for s in scheduler.apply(clock() + 1000)))
        transport.cleanup(clock() + 1000)
        self.assertFalse(any(c[0] == 11 for c in usb.commands))
        self.assertEqual(scheduler.result()["unconfirmed_tx_attempts"], 0)
        if local:
            self.assertEqual(scheduler.result()["metrics"]["physical_or_guarded_air_s"], 0)

    def test_stock_usb_framing_signing_physical_tx_and_actual_cpp_install(self):
        self.serial_case(False)

    def test_native_radio_bridge_framing_and_actual_cpp_install(self):
        self.serial_case(True)

    def test_native_local_bridge_uses_same_actual_cpp_transaction_without_rf(self):
        self.serial_case(True, local=True)

    def test_lost_abort_and_repair_responses_reconcile_owned_generation_changes(self):
        _, job, transport, clock = self.setup_job(b"mutation recovery" * 1000)
        scheduler = Scheduler(job, transport, clock=clock, sleep=clock.sleep)
        ready = scheduler.stage(clock() + 1000)[0]
        transport.interrupt_kind = Kind.ABORT
        with self.assertRaises(ConnectionError):
            scheduler.mutate(Kind.ABORT, clock() + 1000)
        abort_frames = sum(f.kind == Kind.ABORT for f in transport.sent)
        transport.queue.clear()
        aborted = scheduler.mutate(Kind.ABORT, clock() + 1000)[0]
        self.assertEqual(aborted.generation, ready.generation + 1)
        self.assertEqual(sum(f.kind == Kind.ABORT for f in transport.sent), abort_frames)
        self.assertFalse(job.uncertain(TARGET, Kind.ABORT))
        transport.interrupt_kind = Kind.REPAIR
        with self.assertRaises(ConnectionError):
            scheduler.mutate(Kind.REPAIR, clock() + 1000)
        job.close()
        transport.drivers[0].restart()
        transport.queue.clear()
        with JobStore.open(self.directory / "job") as resumed:
            recovered = Scheduler(resumed, transport, clock=clock, sleep=clock.sleep)
            idle = recovered.reconcile(clock() + 1000)[0]
            self.assertEqual((idle.phase, idle.generation), (Phase.IDLE, aborted.generation + 1))
            self.assertFalse(resumed.uncertain(TARGET, Kind.REPAIR))


if __name__ == "__main__":
    unittest.main()
