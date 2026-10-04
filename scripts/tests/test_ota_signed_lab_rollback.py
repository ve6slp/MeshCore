import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import unittest
from unittest import mock
import uuid

from test_ota_signed_lab import Clock, ProductCompanion, image_manifest, signed


ota, lab = signed.ota, signed.lab


class RollbackCompanion(ProductCompanion):
    """Existing ABI2 product peer; no new runtime fields or local installer API."""

    def __init__(self):
        super().__init__()
        image, canonical = image_manifest(counter=1, image=struct.pack("<II", 0x20040000, 0x27009) + b"\x11" * 245)
        self.baseline = signed.Candidate(canonical, image, {"counter": 1})
        self.target.installed = self.baseline
        self.target.phase, self.target.counter, self.target.floor = "installed", 1, 1
        self.floor = {"seq": 7, "ctr": 1, "ext": len(image), "sha": hashlib.sha256(image).hexdigest().upper()}
        self.startup_phase = 6
        self.decision, self.writes = 0, "allowed"
        self.lifecycle_override = None
        self.remote_mutator = None
        self.commit_phase = "trial"
        self.reconnects = 0
        ordinary_command = self.target.command

        def command(value, **options):
            if value == "ota preflight":
                self.target.commands.append(value)
                return (f"writes={self.writes} marker=qualified proof=qualified-state "
                        f"state=1 phase={self.startup_phase} decision={self.decision}")
            if value == "ota capability":
                self.target.commands.append(value)
                return (f"writes={self.writes} INSTALL_CAPABLE: floor=present seq={self.floor['seq']:08X} "
                        f"ctr={self.floor['ctr']:08X} ext={self.floor['ext']:08X} sha={self.floor['sha']} io=ok")
            if value == "ota status" and (self.target.phase in ("trial", "failed") or self.lifecycle_override):
                self.target.commands.append(value)
                return self.lifecycle_override or (
                    f"boot={self.target.phase} phase={self.target.phase} floor={self.target.floor} "
                    f"counter={self.target.counter} verified=0 image=unknown")
            return ordinary_command(value, **options)

        self.target.command = command

    def poll(self, timeout=0):
        signed.time.sleep(timeout)
        return None

    def write_frame(self, packet):
        super().write_frame(packet)
        if packet[:2] == bytes([66, ota.Op.COMMIT]):
            self.target.phase = self.commit_phase
            self.target.floor = 1
            self.startup_phase = 5
            self.decision, self.writes = 1, "blocked"
        elif packet[:2] == bytes([66, ota.Op.STATUS]) and packet[2:] == self.target.key and self.remote_mutator:
            received, frame = self.pending[-1]
            self.pending[-1] = (received, self.remote_mutator(frame))

    def reenumerate(self, deadline, transport_disconnected=False):
        self.reconnects += 1
        if self.reconnects == 2:
            self.target.installed = self.baseline
            self.target.phase = "failed"
            self.startup_phase = 8
            self.decision, self.writes = 0, "allowed"


class SignedRollbackTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).resolve().parents[2] / ".tmp" / ("signed-rollback-" + uuid.uuid4().hex)
        self.directory.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.directory)
        self.clock = Clock()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(signed.time, "monotonic", self.clock.monotonic).start()
        mock.patch.object(signed.time, "sleep", self.clock.sleep).start()
        mock.patch("sys.stdout", io.StringIO()).start()
        image, canonical = image_manifest(counter=2)
        (self.directory / "image.bin").write_bytes(image)
        (self.directory / "canonical.bin").write_bytes(canonical)
        self.inputs = ["--manifest", str(self.directory / "canonical.bin"),
                       "--image", str(self.directory / "image.bin"),
                       "--image-sha256", hashlib.sha256(image).hexdigest(), "--counter", "2",
                       "--provenance", "nonconfirming-test-candidate", "--commissioning-evidence", "test-commissioning"]
        self.stage_args = signed.parser().parse_args(
            ["--artifact-dir", str(self.directory / "stage"), "stage"] + self.inputs)
        self.candidate = signed.load_candidate(self.stage_args)
        self.stage_evidence = lab.Evidence(self.stage_args.artifact_dir)
        self.addCleanup(self.stage_evidence.events.close)
        self.node = RollbackCompanion()
        self.node.baseline_path = self.stage_evidence.directory / "baseline.json"
        self.pair = mock.Mock(client=self.node, target=self.node.target)
        self.pair.reenumerate.side_effect = self.node.reenumerate
        self.uploader = ota.Uploader(self.node, self.stage_evidence)
        self.deadline = self.clock.now + 300

    def prepare(self, resume=False):
        if resume:
            signed.stage(self.pair, self.uploader, self.candidate, self.stage_args,
                         self.stage_evidence, self.deadline)
            self.stage_evidence = lab.Evidence(self.directory / "stage-resume")
            self.addCleanup(self.stage_evidence.events.close)
            self.node.baseline_path = self.stage_evidence.directory / "baseline.json"
            self.uploader.evidence = self.stage_evidence
        record = signed.stage(self.pair, self.uploader, self.candidate, self.stage_args,
                              self.stage_evidence, self.deadline)
        self.args = signed.parser().parse_args(
            ["--artifact-dir", str(self.directory / "commit"), "commit", "--qualified-commit", "--expect-rollback",
             "--ready-record", str(self.stage_evidence.directory / "ready.json")] + self.inputs)
        self.evidence = lab.Evidence(self.args.artifact_dir)
        self.addCleanup(self.evidence.events.close)
        self.uploader.evidence = self.evidence
        return record

    def commit(self):
        return signed.commit(self.pair, self.uploader, self.candidate, self.args, self.evidence, self.deadline)

    def assert_no_qualification(self):
        self.assertFalse((self.evidence.directory / "rollback.json").exists())
        self.assertFalse((self.evidence.directory / "installed.json").exists())
        self.assertTrue(self.args.ready_record.exists())
        self.assertNotIn(ota.Op.ABORT, [packet[1] for packet in self.node.packets])
        self.assertFalse(any(command in ("reboot", "ota rollback", "ota abort") for command in self.node.target.commands))

    def test_product_trial_rollback_preserves_real_contract_baseline_and_peer(self):
        record = self.prepare()
        self.assertEqual(record["target_status"]["phase"], "installed")
        outcome = self.commit()
        self.assertTrue(outcome["remote_rollback_qualified"])
        self.assertFalse(outcome["remote_install_qualified"])
        self.assertEqual(self.pair.reenumerate.call_count, 2)
        packets = [packet for packet in self.node.packets if packet[1] == ota.Op.COMMIT]
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0], bytes([66, ota.Op.COMMIT]) + self.node.target.key
                         + self.candidate.manifest_hash + struct.pack(">I", 2))
        self.assertEqual(outcome["remote_trial"]["phase"], "TRIAL")
        self.assertEqual(outcome["remote_trial"]["hash"], self.candidate.manifest_hash.hex())
        self.assertEqual(outcome["rollback"]["remote"]["phase"], "FAILED")
        self.assertEqual(outcome["rollback"]["remote"]["counter"], 2)
        self.assertEqual(outcome["lifecycle"], {"boot": "failed", "phase": "failed", "floor": 1,
                                               "counter": 2, "verified": False, "image": "unknown"})
        baseline = outcome["rollback"]["baseline"]
        self.assertEqual(baseline["image_sha256"], hashlib.sha256(self.node.baseline.image).hexdigest())
        self.assertEqual(outcome["rollback"]["restored_running_image_sha256"], baseline["image_sha256"])
        self.assertEqual(outcome["rollback"]["restored_confirmed_counter"], 1)
        self.assertEqual(baseline["counter"], 1)
        self.assertEqual(baseline["image_extent"], len(self.node.baseline.image))
        self.assertIsNone(baseline["sdk28"])
        self.assertIsNone(baseline["sdk_crc"])
        self.assertEqual(outcome["end_diagnostics"]["capability"]["floor"], baseline["confirmed_floor"])
        self.assertEqual(outcome["preserved_readbacks"]["client"], record["client"])
        self.assertEqual(outcome["preserved_readbacks"]["target"], record["target"])
        self.assertEqual(outcome["preserved_readbacks"]["acl"], record["acl"])
        self.assertTrue(outcome["identity_config_acl_preserved"])
        self.assertTrue(outcome["ordinary_peer_received"])
        self.assertIn("rollback_end_measurements", self.evidence.summary["measurements"])
        self.assertTrue((self.evidence.directory / "rollback.json").exists())
        self.assertFalse((self.evidence.directory / "installed.json").exists())
        self.assertFalse(outcome["usb_reset_sent"])
        self.assertNotIn(ota.Op.ABORT, [packet[1] for packet in self.node.packets])
        self.assertEqual(self.node.target.commands.count("advert.zerohop"), 2)

    def test_product_ready_resume_uses_original_running_image_not_candidate_counter(self):
        record = self.prepare(resume=True)
        self.assertEqual(record["target_status"]["phase"], "ready")
        self.assertEqual(record["target_status"]["counter"], 2)
        self.assertEqual(record["target_status"]["floor"], 1)
        self.assertEqual(record["target_status"]["image"], hashlib.sha256(self.node.baseline.image).hexdigest())
        self.assertTrue(self.commit()["remote_rollback_qualified"])

    def test_parser_opt_in_is_commit_only_and_default_still_refuses_failed_install(self):
        self.prepare()
        args = signed.parser().parse_args(
            ["--artifact-dir", "unused", "commit", "--qualified-commit",
             "--ready-record", str(self.args.ready_record)] + self.inputs)
        self.assertFalse(args.expect_rollback)
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            signed.parser().parse_args(["--artifact-dir", "unused", "stage"] + self.inputs + ["--expect-rollback"])
        self.args.expect_rollback = False
        original = self.node.write_frame

        def fail(packet):
            original(packet)
            if packet[:2] == bytes([66, ota.Op.COMMIT]):
                self.node.target.phase = "failed"

        self.node.write_frame = fail
        with self.assertRaisesRegex(signed.QualificationError, "failed/rolled back"):
            self.commit()
        self.assert_no_qualification()

    def test_failed_before_trial_cannot_qualify_even_with_baseline_bytes(self):
        self.prepare()
        self.node.commit_phase = "failed"
        with self.assertRaisesRegex(signed.QualificationError, "failed/ABORTed"):
            self.commit()
        self.assertEqual(self.pair.reenumerate.call_count, 1)
        self.assert_no_qualification()

    def test_ack_or_baseline_hash_without_trial_does_not_qualify(self):
        self.prepare()
        self.node.commit_phase = "ready"
        self.args.trial_timeout = 0.5
        with self.assertRaisesRegex(signed.QualificationError, "fresh candidate-bound remote TRIAL"):
            self.commit()
        self.assertEqual(self.pair.reenumerate.call_count, 1)
        self.assert_no_qualification()

    def test_confirmed_candidate_is_not_expected_rollback(self):
        self.prepare()
        self.node.commit_phase = "installed"
        with self.assertRaisesRegex(signed.QualificationError, "remote TRIAL"):
            self.commit()
        self.assert_no_qualification()

    def test_product_remote_trial_binding_and_freshness_are_required(self):
        for defect in ("stale", "hash", "counter", "target", "scope", "partial"):
            with self.subTest(defect=defect):
                self.setUp()
                self.prepare()
                self.args.trial_timeout = 0.5

                def corrupt(frame):
                    if frame[4] != ota.Phase.TRIAL:
                        return frame
                    data = bytearray(frame)
                    if defect == "stale":
                        struct.pack_into(">I", data, 78, 60000)
                    elif defect == "hash":
                        data[38] ^= 1
                    elif defect == "counter":
                        struct.pack_into(">I", data, 74, 3)
                    elif defect == "target":
                        data[6] ^= 1
                    elif defect == "scope":
                        data[5] &= ~ota.REMOTE
                    else:
                        struct.pack_into(">H", data, 70, self.candidate.blocks - 1)
                    return bytes(data)

                self.node.remote_mutator = corrupt
                with self.assertRaises((signed.QualificationError, ota.UploaderError, TimeoutError)):
                    self.commit()
                self.assertEqual(self.pair.reenumerate.call_count, 1)
                self.assert_no_qualification()

    def test_product_remote_failed_binding_and_freshness_are_required(self):
        for defect in ("stale", "hash", "counter", "scope", "phase"):
            with self.subTest(defect=defect):
                self.setUp()
                self.prepare()
                self.args.install_timeout = 1

                def corrupt(frame):
                    if frame[4] != ota.Phase.FAILED:
                        return frame
                    data = bytearray(frame)
                    if defect == "stale":
                        struct.pack_into(">I", data, 78, 60000)
                    elif defect == "hash":
                        data[38] ^= 1
                    elif defect == "counter":
                        struct.pack_into(">I", data, 74, 1)
                    elif defect == "scope":
                        data[5] &= ~ota.REMOTE
                    else:
                        data[4] = ota.Phase.ABORTED
                    return bytes(data)

                self.node.remote_mutator = corrupt
                with self.assertRaises((signed.QualificationError, ota.UploaderError, TimeoutError)):
                    self.commit()
                self.assert_no_qualification()

    def test_changed_floor_history_or_missing_running_original_proof_cannot_qualify(self):
        for defect in ("floor", "sequence", "extent", "hash", "wrong-running", "missing-disposition",
                       "wrong-counter", "fabricated-verified-image"):
            with self.subTest(defect=defect):
                self.setUp()
                self.prepare()
                original = self.node.reenumerate

                def reconnect(*args, **options):
                    original(*args, **options)
                    if self.node.reconnects != 2:
                        return
                    if defect == "floor":
                        self.node.target.floor = 2
                    elif defect == "sequence":
                        self.node.floor["seq"] += 1
                    elif defect == "extent":
                        self.node.floor["ext"] += 4
                    elif defect == "hash":
                        self.node.floor["sha"] = "AA" * 32
                    elif defect == "wrong-running":
                        self.node.decision, self.node.writes = 2, "blocked"
                    elif defect == "missing-disposition":
                        self.node.startup_phase = 6
                    elif defect == "wrong-counter":
                        self.node.target.counter = 1
                    else:
                        self.node.lifecycle_override = (
                            "boot=failed phase=failed floor=1 counter=2 verified=1 image=" + "aa" * 32)

                self.pair.reenumerate.side_effect = reconnect
                with self.assertRaises(signed.QualificationError):
                    self.commit()
                self.assert_no_qualification()

    def test_baseline_rejections_precede_any_commit_and_keep_floor_guard(self):
        for defect in ("unverified", "running-image-changed", "candidate-counter", "floor-hash", "baseline-startup",
                       "failed-preexisting", "aborted-preexisting"):
            with self.subTest(defect=defect):
                self.setUp()
                self.prepare()
                record = json.loads(self.args.ready_record.read_text())
                if defect == "unverified":
                    record["target_status"]["verified"], record["target_status"]["image"] = False, "unknown"
                    self.args.ready_record.write_text(json.dumps(record))
                elif defect == "running-image-changed":
                    self.node.target.installed = self.candidate
                elif defect == "candidate-counter":
                    metadata = {**self.candidate.metadata, "counter": 3}
                    self.candidate = signed.Candidate(self.candidate.canonical, self.candidate.image, metadata)
                    record["candidate"] = metadata
                    self.args.ready_record.write_text(json.dumps(record))
                    self.node.target.counter = 3
                elif defect == "floor-hash":
                    self.node.floor["sha"] = "AA" * 32
                elif defect == "baseline-startup":
                    self.node.decision = 2
                else:
                    phase = "failed" if defect == "failed-preexisting" else "aborted"
                    self.node.lifecycle_override = (
                        f"boot=confirmed phase={phase} floor=1 counter=2 verified=1 image="
                        + hashlib.sha256(self.node.baseline.image).hexdigest())
                with self.assertRaises(signed.QualificationError):
                    self.commit()
                self.assertNotIn(ota.Op.COMMIT, [packet[1] for packet in self.node.packets])
                self.assert_no_qualification()

    def test_automatic_reconnect_failures_are_bounded_without_reset_assistance(self):
        for failed_reconnect in (1, 2):
            with self.subTest(failed_reconnect=failed_reconnect):
                self.setUp()
                self.prepare()
                self.args.reboot_timeout = 0.25

                def reconnect(deadline, **options):
                    self.assertLessEqual(deadline, self.clock.now + 0.25)
                    if self.pair.reenumerate.call_count == failed_reconnect:
                        raise TimeoutError("automatic reboot not observed")
                    self.node.reenumerate(deadline, **options)

                self.pair.reenumerate.side_effect = reconnect
                with self.assertRaises((signed.QualificationError, TimeoutError)):
                    self.commit()
                self.assertEqual(self.pair.reenumerate.call_count, failed_reconnect)
                self.assert_no_qualification()

    def test_rollback_timeout_validation_precedes_opening_any_port(self):
        self.prepare()
        for option in ("--reboot-timeout", "--trial-timeout", "--install-timeout"):
            for value in ("nan", "inf", "0", "-1"):
                with self.subTest(option=option, value=value), mock.patch("sys.stderr", io.StringIO()), \
                        mock.patch.object(signed, "Pair") as opened:
                    with self.assertRaises(SystemExit):
                        signed.main(["--artifact-dir", str(self.directory / "invalid"), "commit",
                                     "--qualified-commit", "--expect-rollback",
                                     "--ready-record", str(self.args.ready_record)] + self.inputs + [option, value])
                    opened.assert_not_called()

    def test_repeated_automatic_serial_disconnect_reconnect_is_read_only(self):
        self.prepare()
        ordinary = self.node.target.command
        disconnected = False

        def command(value, **options):
            nonlocal disconnected
            if value == "ota status" and self.node.reconnects == 2 and not disconnected:
                disconnected = True
                raise OSError(5, "automatic reboot endpoint disappeared")
            return ordinary(value, **options)

        self.node.target.command = command
        self.assertTrue(self.commit()["remote_rollback_qualified"])
        self.assertEqual(self.pair.reenumerate.call_count, 3)
        self.assertTrue(self.pair.reenumerate.call_args.kwargs["transport_disconnected"])

    def test_post_rollback_permission_failure_is_not_treated_as_reboot(self):
        self.prepare()
        ordinary = self.node.target.command

        def command(value, **options):
            if value == "ota status" and self.node.reconnects == 2:
                raise PermissionError(13, "permission denied")
            return ordinary(value, **options)

        self.node.target.command = command
        with self.assertRaises(PermissionError):
            self.commit()
        self.assertEqual(self.pair.reenumerate.call_count, 2)
        self.assert_no_qualification()

    def test_post_rollback_identity_preferences_acl_radio_or_peer_loss_refuses_artifact(self):
        for defect in ("identity", "preferences", "acl", "radio", "peer", "end-floor"):
            with self.subTest(defect=defect):
                self.setUp()
                self.prepare()
                original = self.node.reenumerate

                def reconnect(*args, **options):
                    original(*args, **options)
                    if self.node.reconnects != 2:
                        return
                    if defect == "identity":
                        self.node.target.key = b"\xaa" * 32
                    elif defect == "preferences":
                        self.node.target.app_name = "changed-name"
                    elif defect == "acl":
                        self.node.target.acl.clear()
                    elif defect == "radio":
                        self.node.target.measurement_overrides["radio"] = (
                            "src=driver-applied f=908525 b=250000 s=5 c=5 v=1 a=1 "
                            "e=00000000 d=00000000 r=00000000 td=00000000 tr=00000000 h=1 "
                            "x=00000000 af=00000000 n=00000001")
                    elif defect == "peer":
                        self.node.target.peer = mock.Mock(pending=[])
                        self.node.poll = lambda timeout=0: self.clock.sleep(max(0.01, timeout))
                    else:
                        ordinary = self.node.target.command

                        def command(value, **kwargs):
                            result = ordinary(value, **kwargs)
                            if value == "advert.zerohop":
                                self.node.floor["seq"] += 1
                            return result

                        self.node.target.command = command

                self.pair.reenumerate.side_effect = reconnect
                with self.assertRaises((signed.QualificationError, ota.UploaderError, TimeoutError)):
                    self.commit()
                self.assert_no_qualification()
