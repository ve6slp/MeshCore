import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
import zlib
import lzma
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ota_compression as codec
import ota_stock_companion as stock
import ota_uploader as native
import ota_management as management
from test_ota_stock_companion import (Clock, FakeSerial, NORMAL, NONCE, OWNER, OWNER_PRIVATE, TARGET,
                                     RELAY, RelaySerial, Scratch, binding, candidate)


class CompressionSerial(FakeSerial):
    def __init__(self, *args):
        super().__init__(*args)
        self.groups = codec.groups(self.candidate.image, arm_thumb=codec.manifest_thumb(self.candidate.canonical))
        self.buffers = {}
        self.drop_fragment = True
        self.fragments = 0
        self.reply_attempt, self.reply_mode, self.reply_mutator = None, "relay", None
        self.seen_replies = set()

    def remote(self, frame):
        if frame[0] in (17, 18):
            self.reply_attempt, frame = stock.retry_payload(frame)
            assert self.reply_attempt and frame is not None
        if frame[0] == codec.POLL:
            index = struct.unpack_from(">H", frame, 85)[0]
            group = self.groups[index]
            complete = all(i in self.received for i in range(index * 96, min(
                (index + 1) * 96, self.candidate.total)))
            report = (bytes([codec.REPORT]) + frame[1:87] +
                      struct.pack(">HBBHBB", len(self.buffers.get(index, b"")), int(complete),
                                  codec.LZMA_THUMB if codec.manifest_thumb(self.candidate.canonical) else codec.LZMA,
                                  codec.GROUP, 0, 0))
            self.schedule(.1, lambda: self.push(report))
        elif frame[0] == codec.FRAGMENT:
            prefix = frame[:-64]
            stock.verify(OWNER, codec.signed_message(TARGET, self.candidate.digest, self.generation,
                                                    self.nonce, prefix), frame[-64:])
            self.fragments += 1
            if self.drop_fragment:
                self.drop_fragment = False
                return
            index, stored, raw, crc, profile, offset = struct.unpack_from(">HHHIBH", frame, 5)
            group = self.groups[index]
            self.assert_group = (raw == group.raw_bytes and stored == len(group.stored))
            current = self.buffers.get(index, b"")
            if offset != len(current):
                return
            current += prefix[18:]
            self.buffers[index] = current
            if len(current) == stored:
                decoded = (lzma.decompress(current, format=lzma.FORMAT_RAW,
                                          filters=codec.filters(profile == codec.LZMA_THUMB, index * codec.GROUP))
                           if profile != codec.RAW else current)
                assert len(decoded) == raw and zlib.crc32(decoded) == crc
                assert decoded == self.candidate.image[index * codec.GROUP:index * codec.GROUP + raw]
                self.received.update(range(index * 96, min((index + 1) * 96, self.candidate.total)))
        else:
            super().remote(frame)

    def push(self, payload):
        if self.reply_attempt is None:
            super().push(payload)
        else:
            RelaySerial.push(self, payload)


class CompressionTests(unittest.TestCase):
    def test_selected_sdk_sources_and_license_match_pinned_upstream_hashes(self):
        root = Path(__file__).resolve().parents[2] / "src/helpers/ota/third_party/lzma"
        for source in json.loads((root / "sources.json").read_text()):
            with self.subTest(source=source["path"]):
                self.assertIn("/26.04/", source["url"])
                self.assertEqual(source["sha256"],hashlib.sha256((root / source["path"]).read_bytes()).hexdigest())

    def test_architecture_and_resource_schema_are_explicit_not_version_or_image_heuristics(self):
        for board in (b"SCP1", b"XN40"):
            self.assertTrue(codec.manifest_thumb(board + bytes(55)))
        self.assertFalse(codec.manifest_thumb(b"ESS3" + bytes(55)))
        self.assertFalse(codec.manifest_thumb(b"????" + bytes(55)))
        self.assertEqual(8192,codec.filters(False)[0]["dict_size"])
        self.assertEqual((0,1,1),tuple(codec.filters(False)[0][name] for name in ("lc","lp","pb")))
        text = ("codec=lzma1-g8064 thumb=1 measured=1 groups=4 slices=600 "
                "slice_us=100 group_us=15000 heap=100000 stack=1800")
        self.assertEqual("100",management.fields("codec",text)["slice_us"])
        for bad in (text.replace("thumb=1","thumb=2"),text.replace("measured=1","measured=2"),
                    text.replace("groups=4","groups=4294967296"),
                    text.replace("lzma1-g8064","unknown"),text+" extra=0"):
            with self.assertRaises(stock.Error):
                management.fields("codec",bad)

    def test_all_route_width_boundary_capacities_use_exact_rx_limit(self):
        for width in (1, 2, 3):
            for hops in range(64):
                for retry in (False, True):
                    for codes in (False, True):
                        if width * hops > 64:
                            with self.assertRaises(ValueError):
                                codec.fragment_capacity(width, hops, retry, codes)
                            continue
                        cap = codec.fragment_capacity(width, hops, retry, codes)
                        self.assertEqual(176, 3 + 2 + width * hops + 5 * retry + 4 * codes + 82 + cap)
        self.assertEqual(89, codec.fragment_capacity(1, 0, False))
        self.assertEqual(83, codec.fragment_capacity(1, 1, True))
        self.assertEqual(81, codec.fragment_capacity(3, 1, True))

    def test_random_whole_transfer_selects_raw_and_group_fallback_is_explicit(self):
        image = hashlib.shake_256(b"deterministic random synthetic control").digest(510388)
        groups, plan = codec.plan(image)
        self.assertEqual("raw", plan["selected"])
        self.assertTrue(all(g.profile == codec.RAW for g in groups))
        self.assertGreater(plan["compressed_data_packets"], plan["raw_data_packets"])

    def test_selected_stream_rejects_legacy_control_overflow_before_admission(self):
        c, clock = candidate(16384), Clock()
        serial = CompressionSerial(clock,c)
        transport = stock.Stock(stock.Frames(serial,clock),OWNER,clock,clock.sleep)
        with self.assertRaisesRegex(stock.Error,"admission"):
            stock.Sender(transport,binding(c),c,NORMAL,clock()+10000,0,0,.5,clock,clock.sleep,
                         compression_mode="lzma",mode="directed",relay=RELAY,path_hash_bytes=3)
        self.assertEqual([],serial.raw_packets)

    def test_real_encoder_metadata_is_inside_every_signature_and_variable_tail(self):
        c = candidate(16384)
        groups, plan = codec.plan(c.image)
        self.assertEqual("lzma", plan["selected"])
        for group in groups:
            for prefix in group.fragments(c.digest, plan["capacity"]):
                message = codec.signed_message(TARGET, c.digest, 10, NONCE, prefix)
                signature = OWNER_PRIVATE.sign(message)
                stock.verify(OWNER, message, signature)
                packet = stock.retry_frame(prefix + signature, 1, True)
                self.assertLessEqual(len(stock.packet(packet, b"\x73")) + 3, 176)
        self.assertLess(len(groups[-1].fragments(c.digest, plan["capacity"])[-1]), 18 + plan["capacity"])

    def test_stock_sender_deploy_uses_real_signing_and_recovers_lost_fragment(self):
        c = candidate(16384)
        clock = Clock()
        serial = CompressionSerial(clock, c)
        transport = stock.Stock(stock.Frames(serial, clock), OWNER, clock, clock.sleep)
        sender = stock.Sender(transport, binding(c), c, NORMAL, clock() + 10000, 919000,
                              60000, .5, clock, clock.sleep, compression_mode="lzma")
        result = sender.upload()
        self.assertEqual("lzma1-g8064-armt", result["transfer_encoding"])
        self.assertEqual(set(range(c.total)), serial.received)
        self.assertGreater(serial.fragments, sender.compression_plan["compressed_data_packets"])
        self.assertFalse(any(frame[0] == 67 for frame in serial.commands))
        self.assertTrue(all(len(frame) <= 176 for frame in serial.commands))

    def test_capability_progress_rejects_wrong_algorithm_attempt_and_codec_failure(self):
        c = candidate()
        frame = (bytes([codec.REPORT]) + TARGET + c.digest + struct.pack(">I", 10) + NONCE +
                 struct.pack(">HHBBHBB", 0, 0, 0, codec.LZMA, codec.GROUP, 0, 0))
        self.assertEqual((0, False), codec.report(frame, TARGET, c.digest, 10, NONCE, 0, 10))
        for offset in (1, 33, 65, 69, 85, 90, 91, 93, 94):
            bad = bytearray(frame)
            bad[offset] ^= 1
            if offset == 90:
                bad[offset] = 0xff
            with self.assertRaises(ValueError):
                codec.report(bad, TARGET, c.digest, 10, NONCE, 0, 10)

    def test_requested_compression_that_loses_truthfully_runs_unchanged_raw(self):
        image = struct.pack("<II", 0x20010000, 0x27009) + hashlib.shake_256(b"random RAW").digest(2040)
        canonical = native.deploy_manifest(image, "xiao_nrf52840", 0, 5)
        c = stock.Candidate.build(canonical, image, 4)
        clock = Clock()
        serial = CompressionSerial(clock, c)
        transport = stock.Stock(stock.Frames(serial, clock), OWNER, clock, clock.sleep)
        sender = stock.Sender(transport, binding(c), c, NORMAL, clock() + 10000, 919000,
                              60000, .5, clock, clock.sleep, compression_mode="lzma")
        result = sender.upload()
        self.assertEqual("raw", result["transfer_encoding"])
        self.assertEqual(0, serial.fragments)
        self.assertEqual(set(range(c.total)), serial.received)


class NativeCompressionTests(Scratch):
    def test_cli_selects_host_stream_only_after_abi_probe_and_truthful_raw_fallback_keeps_cache(self):
        from test_ota_uploader import CliLifecycleTests
        for random_control in (False,True):
            helper=CliLifecycleTests(methodName="runTest")
            helper.setUp()
            self.addCleanup(helper.doCleanups)
            if random_control:
                image=struct.pack("<II",0x20010000,0x27009)+hashlib.shake_256(b"CLI random RAW").digest(2040)
                canonical=native.deploy_manifest(image,"xiao_nrf52840",0,5)
            else:
                c=candidate(16384)
                image,canonical=c.image,c.canonical
            helper.image,helper.canonical=image,canonical
            helper.manifest_hash=hashlib.sha256(canonical).digest()
            helper.image_path.write_bytes(image); helper.manifest_path.write_bytes(canonical)
            arguments=helper.upload_arguments()+[
                "--compression","lzma","--mode","directed","--frequency-khz","0","--lease-ms","0",
                "--stream-binding",str(self.directory/"unused-binding.json"),"--relay-key",RELAY.hex()]
            with patch.object(native,"compressed_host_stream") as stream, patch("builtins.print") as notice:
                helper.run_cli(arguments)
            operations=[native.Op(call.args[0][1]) for call in helper.node.write_frame.call_args_list]
            self.assertIn(native.Op.STATUS,operations)
            if random_control:
                stream.assert_not_called()
                self.assertIn(native.Op.CACHE_BEGIN,operations)
                self.assertTrue(any("raw cache/START retained" in str(call) for call in notice.call_args_list))
            else:
                stream.assert_called_once()
                self.assertEqual([native.Op.STATUS],operations)

    def test_native_frontend_uses_same_signed_stream_and_resumes_without_cache_start_or_begin(self):
        c, clock = candidate(16384), Clock()
        serial = CompressionSerial(clock, c)
        bound = self.directory / "binding.json"
        stock.private_write(bound, {"schema": 1, "serial": "synthetic", "stock_version": "1.17.1",
                                   "sender_public_key": OWNER.hex(), "target_public_key": TARGET.hex(),
                                   "floor": 4, "min_generation": 10, "normal_profile": list(NORMAL[:4]),
                                   "image_sha256": hashlib.sha256(c.image).hexdigest(),
                                   "manifest_hash": c.digest.hex()})
        args = SimpleNamespace(stream_binding=[bound], target=[TARGET], mode="directed",
                               artifact_dir=self.directory, stream_resume_receipt=[], reupload=False,
                               frequency_khz=0, lease_ms=0, duty_milli_percent=50000,
                               relay_key=RELAY, path_hash_bytes=1, max_relay_hops=1,
                               command="upload", channel=255, routed_retry=True)
        real_stock, real_frames = stock.Stock, stock.Frames
        def run():
            node = SimpleNamespace(stream=serial, buffer=bytearray())
            with patch.object(stock, "Stock", side_effect=lambda frames, key: real_stock(
                    frames, key, clock, clock.sleep)), patch.object(
                    stock, "Frames", side_effect=lambda stream: real_frames(stream, clock)):
                return native.compressed_host_stream(node, Mock(), args, c.canonical, c.image,
                                                     OWNER, clock() + 10000)
        original_remote = serial.remote
        def interrupted(frame):
            if serial.fragments >= 3:
                raise TimeoutError("explicit sender interruption")
            return original_remote(frame)
        with patch.object(serial,"remote",side_effect=interrupted), self.assertRaises(TimeoutError):
            run()
        original_attempt = self.directory / ("attempt-" + TARGET.hex() + ".json")
        self.assertTrue(original_attempt.is_file())
        self.assertNotEqual(set(range(c.total)),serial.received)
        # Receiver reboot drops only ephemeral partial-group RAM.
        serial.buffers.clear()
        restart = self.directory / "restart"
        restart.mkdir(mode=0o700)
        args.artifact_dir = restart
        args.stream_resume_receipt = [original_attempt]
        before_restart = len(serial.raw_packets)
        result = run()
        self.assertEqual("lzma1-g8064-armt", result["transfer_encoding"])
        self.assertEqual(set(range(c.total)), serial.received)
        before = len(serial.raw_packets)
        resumed = self.directory / "resumed"
        resumed.mkdir(mode=0o700)
        args.artifact_dir = resumed
        args.stream_resume_receipt = [restart / ("attempt-" + TARGET.hex() + ".json")]
        second = run()
        self.assertEqual(result["generation"], second["generation"])
        self.assertEqual(result["begin_nonce"], second["begin_nonce"])
        self.assertTrue((resumed / "stream-result.json").is_file())
        self.assertFalse(any(command[0] == 67 for command in serial.commands))
        # Re-admission/REUPLOAD is never part of strict resume.
        new_rf = [stock.raw_rx(b"\x88\x00\x00" + raw) for raw in serial.raw_packets[before_restart:]]
        new_rf = [stock.retry_payload(frame)[1] if frame[0] in (17,18) else frame for frame in new_rf]
        self.assertFalse(any(frame[:1] in (b"\x02", b"\x08") for frame in new_rf))


if __name__ == "__main__":
    unittest.main()
