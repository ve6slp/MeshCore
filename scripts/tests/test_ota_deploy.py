"""Production deploy paths with synthetic companion/receiver I/O; no hardware."""
from contextlib import contextmanager, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ota_uploader as native
import ota_stock_companion as stock
import test_ota_uploader as native_fixture
import test_ota_stock_companion as stock_fixture


class NativeDeployTests(unittest.TestCase):
    def setUp(self):
        self.f = native_fixture.CliLifecycleTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.image = struct.pack("<II", 0x20010000, 0x27009) + bytes(160)
        self.set_image("xiao_nrf52840", 0)
        self.sequence = []
        self.after_commit = native.Phase.INSTALLED
        self.commits = 0
        self.mutate_installed = None
        original = self.f.node.write_frame.side_effect

        def write(payload):
            op = native.Op(payload[1])
            if op == native.Op.CACHE_BEGIN:
                self.f.private_key.public_key().verify(payload[-64:], self.f.canonical)
            original(payload)
            if op == native.Op.COMMIT:
                self.assertEqual(payload[2:], native_fixture.TARGET + self.f.manifest_hash
                                 + struct.pack(">I", 9))
                self.commits += 1
                self.f.remote_phase = self.after_commit
            if op == native.Op.STATUS and payload[2:34] == native_fixture.TARGET:
                response = self.f.pending[-1][1]
                decoded = native.decode_reply(response)
                self.sequence.append(decoded.phase)
                if decoded.phase == native.Phase.INSTALLED and self.mutate_installed is not None:
                    self.f.pending[-1] = (self.f.pending[-1][0], self.mutate_installed(response))
        self.f.node.write_frame.side_effect = write

    def set_image(self, board, role):
        self.board, self.role = board, role
        self.f.canonical = native.deploy_manifest(self.f.image, board, role, 9)
        self.f.manifest_hash = hashlib.sha256(self.f.canonical).digest()
        self.f.image_path.write_bytes(self.f.image)
        self.f.manifest_path.write_bytes(self.f.canonical)

    def args(self):
        return ["deploy", "--image", str(self.f.image_path), "--board", self.board,
                "--role-id", str(self.role), "--counter", "9", "--target", native_fixture.TARGET.hex()]

    def test_transfer_ready_commit_installed_for_nrf_and_esp_roles(self):
        for board, role in (("xiao_nrf52840", 0), ("xiao_nrf52840_sense", 1),
                            ("sensecap_solar_p1", 0), ("xiao_s3_wio", 0), ("xiao_s3_wio", 1)):
            with self.subTest(board=board, role=role):
                self.setUp()
                if board == "xiao_s3_wio":
                    self.f.image = b"\xe9" + bytes(170)
                self.set_image(board, role)
                self.f.run_cli(self.args())
                operations = [payload[1] for payload in self.f.sent_payloads()]
                self.assertIn(native.Op.CACHE_PUT, operations)
                self.assertLess(operations.index(native.Op.CACHE_SEAL), operations.index(native.Op.START))
                self.assertEqual(self.sequence, [native.Phase.READY, native.Phase.INSTALLED])
                self.assertEqual(self.commits, 1)
                self.assertEqual(self.f.evidence.log.call_args.kwargs["phase"], "INSTALLED")
                self.f.node.close.assert_called_once()

    def test_failed_rollback_and_aborted_are_terminal_after_one_commit(self):
        for phase in (native.Phase.FAILED, native.Phase.ABORTED):
            with self.subTest(phase=phase):
                self.setUp()
                self.after_commit = phase
                with self.assertRaisesRegex(native.UploaderError, phase.name):
                    self.f.run_cli(self.args())
                self.assertEqual(self.commits, 1)
                self.assertIsNotNone(self.f.evidence.finish.call_args.args[0])

    def test_ready_or_pending_without_installed_times_out_not_success(self):
        self.after_commit = native.Phase.COMMIT_PENDING
        with self.assertRaisesRegex(TimeoutError, "INSTALLED"):
            self.f.run_cli([*self.args(), "--install-timeout", "1"])
        self.assertEqual(self.commits, 1)
        self.assertEqual(self.f.evidence.log.call_args.args, ("fatal",))

    def test_not_ready_never_commits(self):
        self.f.remote_phase = native.Phase.RECEIVING
        with self.assertRaisesRegex(TimeoutError, "READY"):
            self.f.run_cli(self.args())
        self.assertEqual(self.commits, 0)

    def test_wrong_generation_hash_counter_and_scope_cannot_report_installed(self):
        for offset in (5, 38, 74, 86):
            with self.subTest(offset=offset):
                self.setUp()
                def change(response):
                    data = bytearray(response)
                    data[offset] ^= 2 if offset == 5 else 1
                    return bytes(data)
                self.mutate_installed = change
                with self.assertRaises(native.UploaderError):
                    self.f.run_cli(self.args())

    def test_explicit_manifest_must_match_board_role_counter_before_open(self):
        wrong = native.deploy_manifest(self.f.image, self.board, 1, 9)
        self.f.manifest_path.write_bytes(wrong)
        with self.assertRaisesRegex(ValueError, "board, role, image and counter"):
            self.f.run_cli([*self.args(), "--manifest", str(self.f.manifest_path)])
        self.f.resolve.assert_not_called()
        self.f.client_open.assert_not_called()

    def test_explicit_esp_companion_port_uses_public_identity_not_nrf_lab_role(self):
        import ota_devices
        original = self.f.node.command.side_effect
        def command(payload, **options):
            if payload[0] == native.lab.CMD_APP_START:
                return original(payload, **options) + b"synthetic-ESP"
            if payload[0] == native.lab.CMD_DEVICE_QUERY:
                frame = bytearray(82)
                frame[:2] = bytes([native.lab.RESP_DEVICE_INFO, 13])
                frame[20:31] = b"Xiao_S3_WIO"
                frame[60:66] = b"v1.17.1"[:6]
                return bytes(frame)
            return original(payload, **options)
        self.f.node.command.side_effect = command
        @contextmanager
        def open_node(*args, **kwargs):
            self.assertEqual(args, (Path("/dev/serial/by-id/synthetic-esp"),))
            self.assertIs(kwargs["evidence"], self.f.evidence)
            self.assertIs(kwargs["dtr"], False)
            try:
                yield self.f.node
            finally:
                self.f.node.close()
        with patch.object(ota_devices, "open_companion", open_node), \
                patch.object(ota_devices, "time", self.f.clock):
            self.f.run_cli([*self.args(), "--client-port", "/dev/serial/by-id/synthetic-esp"])
        self.f.resolve.assert_not_called()
        self.f.client_open.assert_not_called()
        self.f.node.close.assert_called_once()
        self.assertEqual(self.commits, 1)

    def test_native_nrf_dtr_selection_explicit_and_lab_fallback(self):
        self.f.run_cli(self.args())
        self.assertEqual(self.f.client_open.call_args.kwargs, {"no_reset": True, "dtr": True})
        self.assertEqual(self.commits, 1)

        self.setUp()
        import ota_devices
        @contextmanager
        def open_node(*args, **kwargs):
            self.assertEqual(args, (Path("/dev/serial/by-id/synthetic-nrf"),))
            self.assertIs(kwargs["dtr"], True)
            try:
                yield self.f.node
            finally:
                self.f.node.close()
        with patch.object(ota_devices, "open_companion", open_node), \
                patch.object(ota_devices, "identify_companion", return_value={
                    "role": "companion", "pubkey": self.f.public_key.hex()}):
            self.f.run_cli([*self.args(), "--client-port",
                            "/dev/serial/by-id/synthetic-nrf", "--client-dtr"])
        self.f.resolve.assert_not_called()
        self.f.node.close.assert_called_once()
        self.assertEqual(self.commits, 1)


class DeploySerial(stock_fixture.FakeSerial):
    def __init__(self, clock, candidate):
        super().__init__(clock, candidate)
        self.install_lifecycle = 6
        self.install_result = 8
        self.status_mutator = None

    def remote(self, rf):
        if rf[0] == 10 and self.commit_count:
            report = bytearray(stock_fixture.census(self.candidate, generation=self.generation,
                lifecycle=self.install_lifecycle,
                floor=self.candidate.counter if self.install_lifecycle == 8 else self.floor))
            report[87] = 6 if self.install_lifecycle == 10 else 4
            if self.status_mutator is not None:
                report = self.status_mutator(report)
            self.schedule(.1, lambda: self.push(bytes(report)))
            return
        super().remote(rf)
        if rf[0] == 3:
            self.schedule(.2, lambda: setattr(self, "install_lifecycle", 7))
            self.schedule(3, lambda: setattr(self, "install_lifecycle", self.install_result))


class StockDeployTests(stock_fixture.Scratch):
    def setUp(self):
        super().setUp()
        self.clock = stock_fixture.Clock()
        self.candidate = stock_fixture.candidate()
        self.serial = DeploySerial(self.clock, self.candidate)
        self.stock = stock.Stock(stock.Frames(self.serial, self.clock), stock_fixture.OWNER,
                                 self.clock, self.clock.sleep)
        self.sender = stock.Sender(self.stock, stock_fixture.binding(self.candidate), self.candidate,
            stock_fixture.NORMAL, self.clock() + 10000, 919000, duty=1,
            clock=self.clock, sleep=self.clock.sleep)
        self.artifacts = self.directory / "run"
        self.artifacts.mkdir(mode=0o700)

    def guarded_deploy(self, timeout=300):
        with stock.radio_guard(self.stock, self.sender.binding, self.artifacts):
            return self.sender.deploy(timeout)

    def test_actual_signed_transfer_ready_commit_native_installed_restores(self):
        result = self.guarded_deploy()
        self.assertEqual(self.serial.received, set(range(self.candidate.total)))
        self.assertEqual(self.serial.commit_count, 1)
        self.assertEqual(result["lifecycle"], 8)
        self.assertEqual(result["confirmed_floor"], self.candidate.counter)
        self.assertTrue(result["native_installed"])
        self.assertFalse(result["installation_confirmed"])
        self.assertFalse(result["status_authenticated"])
        self.assertEqual(self.serial.profile, stock_fixture.NORMAL)
        self.assertTrue((self.artifacts / "restored.json").exists())

    def test_deploy_one_complete_ready_and_one_normal_return_census_no_bitmap_rescan(self):
        self.candidate = stock_fixture.candidate(size=84 * 257)
        self.serial = DeploySerial(self.clock, self.candidate)
        self.serial.received = set(range(self.candidate.total))
        self.stock = stock.Stock(stock.Frames(self.serial, self.clock), stock_fixture.OWNER,
                                 self.clock, self.clock.sleep)
        self.sender = stock.Sender(self.stock, stock_fixture.binding(self.candidate), self.candidate,
            stock_fixture.NORMAL, self.clock() + 10000, 919000, duty=1,
            clock=self.clock, sleep=self.clock.sleep)
        result = self.guarded_deploy()
        commit = next(i for i, (_, _, frame) in enumerate(self.serial.rf_packets) if frame[0] == 3)
        polls = [(profile, frame) for _, profile, frame in self.serial.rf_packets[:commit] if frame[0] == 10]
        self.assertTrue(all(struct.unpack_from(">H", frame, 65)[0] == 0 for _, frame in polls))
        self.assertEqual(sum(profile[:4] == self.serial.target_normal for profile, _ in polls), 2)
        self.assertEqual(sum(profile[:4] != self.serial.target_normal for profile, _ in polls), 1)
        self.assertEqual(self.serial.commit_count, 1)
        self.assertEqual(result["lifecycle"], 8)
        self.assertEqual(self.serial.profile, stock_fixture.NORMAL)

    def test_failure_rollback_and_timeout_restore_without_retry(self):
        for result in (10, 9, 6):
            with self.subTest(result=result):
                # Separate artifact namespace for each independent synthetic run.
                self.clock = stock_fixture.Clock()
                self.serial = DeploySerial(self.clock, self.candidate)
                self.serial.install_result = result
                self.stock = stock.Stock(stock.Frames(self.serial, self.clock), stock_fixture.OWNER,
                                         self.clock, self.clock.sleep)
                self.sender = stock.Sender(self.stock, stock_fixture.binding(self.candidate), self.candidate,
                    stock_fixture.NORMAL, self.clock() + 10000, 919000, duty=1,
                    clock=self.clock, sleep=self.clock.sleep)
                self.artifacts = self.directory / str(result)
                self.artifacts.mkdir(mode=0o700)
                with self.assertRaises((stock.Error, TimeoutError)) as error:
                    self.guarded_deploy(100)
                self.assertIn("FAILED" if result == 10 else "ABORTED" if result == 9 else "timeout",
                              str(error.exception))
                self.assertEqual(self.serial.commit_count, 1)
                self.assertEqual(self.serial.profile, stock_fixture.NORMAL)

    def test_installed_without_matching_new_floor_or_valid_candidate_rejected(self):
        self.sender.generation = 10
        for offset, value in ((93, 0), (87, 1), (98, 1), (88, 1)):
            with self.subTest(offset=offset):
                report = bytearray(stock_fixture.census(self.candidate, lifecycle=8,
                                                       floor=self.candidate.counter))
                report[87] = 4
                report[offset] = value
                with self.assertRaises(stock.Error):
                    self.sender.parse_census(bytes(report), 0, post_commit=True)
        report = stock_fixture.census(self.candidate, lifecycle=8, floor=self.candidate.counter)
        self.assertEqual(self.sender.parse_census(report, 0, post_commit=True)["lifecycle"], 8)

    def test_deploy_candidate_uses_shared_board_role_codec_and_floor(self):
        image = self.candidate.image
        for board, role in (("xiao_nrf52840", 0), ("xiao_nrf52840_sense", 1),
                            ("sensecap_solar_p1", 1), ("xiao_s3_wio", 0), ("xiao_s3_wio", 1)):
            raw = b"\xe9" + bytes(168) if board == "xiao_s3_wio" else image
            candidate = stock.Candidate.build(None, raw, 4, board=board, role_id=role, counter=9)
            self.assertEqual(candidate.canonical, native.deploy_manifest(raw, board, role, 9))
        with self.assertRaisesRegex(stock.Error, "anti-rollback"):
            stock.Candidate.build(None, image, 9, board="xiao_nrf52840", role_id=0, counter=9)

    def test_stock_deploy_cli_needs_no_external_ready_receipt_and_restores(self):
        image = self.directory / "app.bin"
        image.write_bytes(self.candidate.image)
        binding = self.directory / "binding.json"
        stock.private_write(binding, {"schema": 1, "authorized": True, "serial": "ABCDEF0123456789",
            "sender_public_key": stock_fixture.OWNER.hex(), "target_public_key": stock_fixture.TARGET.hex(),
            "stock_version": "1.17.1", "floor": 4, "min_generation": 10,
            "normal_profile": list(stock_fixture.NORMAL[:4]), "image_kind": "ordinary-app",
            "image_sha256": hashlib.sha256(self.candidate.image).hexdigest(),
            "manifest_hash": self.candidate.digest.hex()})
        @contextmanager
        def uart(*_):
            yield self.serial
        artifacts = self.directory / "cli"
        with patch.object(stock, "validated_stock_uart", uart), \
                patch.object(stock.time, "monotonic", self.clock), \
                patch.object(stock.time, "sleep", self.clock.sleep), \
                patch.object(stock.Frames.__init__, "__defaults__", (self.clock,)), \
                patch.object(stock.Stock.__init__, "__defaults__", (self.clock, self.clock.sleep, None)), \
                patch.object(stock.Sender.__init__, "__defaults__",
                    (60000, .02, self.clock, self.clock.sleep, None, False, None, False)), \
                redirect_stdout(io.StringIO()):
            stock.main(["deploy", "--serial", "ABCDEF0123456789", "--by-id", "unused",
                "--sender-key", stock_fixture.OWNER.hex(), "--target", stock_fixture.TARGET.hex(),
                "--binding", str(binding), "--artifacts", str(artifacts), "--image", str(image),
                "--board", "xiao_nrf52840", "--role-id", "0", "--counter", "5",
                "--frequency-khz", "919000", "--normal-duty-percent", "100", "--timeout", "10000"])
        result = stock.private_read(artifacts / "result.json")
        self.assertEqual(result["lifecycle"], 8)
        self.assertEqual(self.serial.commit_count, 1)
        self.assertEqual(self.serial.profile, stock_fixture.NORMAL)


if __name__ == "__main__":
    unittest.main()
