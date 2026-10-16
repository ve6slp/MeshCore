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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ota_compression as codec
import ota_stock_companion as stock
import ota_uploader as native
import ota_management as management
from test_ota_stock_companion import (Clock, FakeSerial, NORMAL, NONCE, OWNER, OWNER_PRIVATE, TARGET,
                                     TARGET2, TARGET_PRIVATE, RELAY, RelaySerial, Scratch, binding,
                                     candidate, census)


class CompressionSerial(FakeSerial):
    def __init__(self, *args):
        super().__init__(*args)
        self.groups = codec.groups(self.candidate.image, arm_thumb=codec.manifest_thumb(self.candidate.canonical))
        self.buffers = {}
        self.drop_fragment = True
        self.fragments = 0
        self.reply_attempt, self.reply_mode, self.reply_mutator = None, "relay", None
        self.seen_replies = set()
        self.target, self.target_private = TARGET, TARGET_PRIVATE
        self.capability_mutator = None

    def remote(self, frame):
        if frame[0] in (17, 18):
            self.reply_attempt, frame = stock.retry_payload(frame)
            assert self.reply_attempt and frame is not None
        if frame[0] == codec.CAPABILITY_REQUEST:
            prefix = bytes([codec.CAPABILITY_REPORT]) + frame[1:] + struct.pack(">HH",codec.GROUP,8192)
            response = prefix + self.target_private.sign(codec.CAPABILITY_DOMAIN + prefix)
            if self.capability_mutator:
                response = self.capability_mutator(response)
            self.schedule(.1, lambda: self.push(response))
        elif frame[0] == codec.POLL:
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
            stock.verify(OWNER, codec.signed_message(self.target, self.candidate.digest, self.generation,
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

class FleetCompressionSerial(CompressionSerial):
    """Two receiver states behind one actual USB transmitter/clock."""
    def __init__(self, clock, c):
        super().__init__(clock,c)
        self.keys = {TARGET: TARGET_PRIVATE,
                     TARGET2: Ed25519PrivateKey.from_private_bytes(bytes([3])*32)}
        self.received_by = {target: set() for target in self.keys}
        self.buffers_by = {target: {} for target in self.keys}
        self.admitted_targets = set()
        self.unsupported = set()

    def remote(self, frame):
        if frame[0] in (17,18):
            self.reply_attempt, frame = stock.retry_payload(frame)
        if frame[0] == 8:
            self.target = next(target for target in self.keys
                               if hashlib.sha256(target).digest()[:8] == frame[1:9])
            stock.verify(OWNER,self.candidate.canonical,frame[-64:])
            self.admitted_targets.add(self.target)
        elif frame[0] in (10,codec.CAPABILITY_REQUEST,codec.POLL):
            self.target = frame[1:33]
        self.received = self.received_by[self.target]
        self.buffers = self.buffers_by[self.target]
        self.target_private = self.keys[self.target]
        if frame[0] == codec.CAPABILITY_REQUEST and self.target in self.unsupported:
            return
        if frame[0] in (8,10):
            first = struct.unpack_from(">H",frame,65)[0] if frame[0] == 10 else 0
            response = census(self.candidate,first=first,received=self.received,target=self.target)
            self.schedule(.1,lambda: self.push(response))
        else:
            super().remote(frame)


class CompressionTests(unittest.TestCase):
    def test_raw_only_receiver_rejects_lzma_before_authorize_override_signing_or_lease(self):
        c = candidate(16384)
        for mode in ("direct","directed"):
            clock = Clock()
            serial = FakeSerial(clock,c) if mode == "direct" else RelaySerial(clock,c)
            transport = stock.Stock(stock.Frames(serial,clock),OWNER,clock,clock.sleep)
            sender = stock.Sender(transport,binding(c),c,NORMAL,clock()+10000,
                                  919000 if mode == "direct" else 0,
                                  60000 if mode == "direct" else 0,.02,clock,clock.sleep,
                                  compression_mode="lzma",mode=mode,
                                  relay=None if mode == "direct" else RELAY)
            original_remote = serial.remote
            def raw_only(frame):
                _, inner = stock.retry_payload(frame)
                if inner[0] != codec.CAPABILITY_REQUEST:
                    return original_remote(frame)
            with patch.object(serial,"remote",side_effect=raw_only), patch.object(
                    sender,"authorize",wraps=sender.authorize) as authorize:
                with self.assertRaisesRegex(stock.Error,"preflight.*unsupported"):
                    sender.upload()
            authorize.assert_not_called()
            self.assertFalse(serial.admitted)
            self.assertFalse(serial.received)
            self.assertFalse(any(command[0] in (11,33,34,35) for command in serial.commands))
            inners = [stock.retry_payload(frame)[1] for _,_,frame in serial.rf_packets]
            self.assertTrue(inners)
            self.assertTrue(all(frame[0] == codec.CAPABILITY_REQUEST for frame in inners))

    def test_stateless_capability_full_context_bounds_and_target_signature_fail_closed(self):
        c = candidate(16384)
        for offset in (1,33,65,81,82,83,85,150):
            clock = Clock()
            serial = CompressionSerial(clock,c)
            def corrupt(frame):
                bad = bytearray(frame); bad[offset] ^= 1
                return bytes(bad)
            serial.capability_mutator = corrupt
            sender = stock.Sender(stock.Stock(stock.Frames(serial,clock),OWNER,clock,clock.sleep),
                                  binding(c),c,NORMAL,clock()+10000,0,0,.5,clock,clock.sleep,
                                  compression_mode="lzma",mode="directed",relay=RELAY)
            with self.assertRaises(stock.Error):
                sender.authorize()
            self.assertFalse(serial.admitted)
            self.assertFalse(any(command[0] in (33,34,35) for command in serial.commands))

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

    def test_fresh_separate_commit_preflights_before_census_or_signing_without_readmission(self):
        c = candidate(16384)
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt):
                clock = Clock()
                serial = CompressionSerial(clock,c)
                transport = stock.Stock(stock.Frames(serial,clock),OWNER,clock,clock.sleep)
                def fresh_sender():
                    return stock.Sender(transport,binding(c),c,NORMAL,clock()+10000,0,0,.5,
                                        clock,clock.sleep,compression_mode="lzma",
                                        mode="directed",relay=RELAY)
                uploader = fresh_sender()
                attempt = uploader.attempt_receipt(uploader.authorize())
                ready = uploader.upload(resume_receipt=attempt)
                committer = fresh_sender()
                committer.bind_resume(attempt)
                before = len(serial.rf_packets)
                commands = len(serial.commands)
                if corrupt:
                    serial.capability_mutator = lambda frame: frame[:-1] + bytes([frame[-1] ^ 1])
                    with self.assertRaises(stock.Error):
                        committer.commit(ready)
                    self.assertEqual(0,serial.commit_count)
                    self.assertFalse(any(command[0] in (33,34,35) for command in serial.commands[commands:]))
                else:
                    committer.commit(ready)
                    self.assertEqual(1,serial.commit_count)
                frames = [stock.retry_payload(frame)[1] for _,_,frame in serial.rf_packets[before:]]
                self.assertEqual(codec.CAPABILITY_REQUEST,frames[0][0])
                self.assertFalse(any(frame[0] in (8,codec.FRAGMENT) for frame in frames))

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
    def stream_setup(self, c, clock, serial, targets=(TARGET,), mode="background"):
        paths = []
        for index,target in enumerate(targets):
            path = self.directory / ("binding-" + str(index) + ".json")
            stock.private_write(path,{"schema":1,"serial":"synthetic","stock_version":"1.17.1",
                                     "sender_public_key":OWNER.hex(),"target_public_key":target.hex(),
                                     "floor":4,"min_generation":10,"normal_profile":list(NORMAL[:4]),
                                     "image_sha256":hashlib.sha256(c.image).hexdigest(),
                                     "manifest_hash":c.digest.hex()})
            paths.append(path)
        args = SimpleNamespace(stream_binding=paths,target=list(targets),mode=mode,
                               artifact_dir=self.directory,stream_resume_receipt=[],reupload=False,
                               frequency_khz=919000 if mode == "direct" else 0,
                               lease_ms=60000 if mode == "direct" else 0,duty_milli_percent=2000,
                               relay_key=RELAY if mode == "directed" else None,path_hash_bytes=1,
                               max_relay_hops=0 if mode == "direct" else 1,
                               command="upload",channel=255,routed_retry=True)
        real_stock, real_frames = stock.Stock, stock.Frames
        def run(deadline):
            with patch.object(stock,"Stock",side_effect=lambda frames,key: real_stock(
                    frames,key,clock,clock.sleep)), patch.object(stock,"Frames",
                    side_effect=lambda stream: real_frames(stream,clock)):
                return native.compressed_host_stream(
                    SimpleNamespace(stream=serial,buffer=bytearray()),Mock(),args,c.canonical,c.image,OWNER,deadline)
        return run

    def test_expired_direct_campaign_restores_exact_original_repeat_on_with_own_cleanup_budget(self):
        c, clock = candidate(16384), Clock()
        serial = CompressionSerial(clock,c)
        run = self.stream_setup(c,clock,serial,mode="direct")
        def expired(sender, **options):
            serial.profile = sender.profile = (919000,250000,5,5,0)
            clock.now = sender.deadline + 1
            sender.lease_end = clock()+30
            sender.target_normal_after = clock()+40
            raise stock.DeadlineExpired("injected expired campaign")
        with patch.object(stock.Sender,"upload",expired), self.assertRaisesRegex(
                stock.DeadlineExpired,"injected expired campaign"):
            run(clock()+1000)
        self.assertEqual(NORMAL,serial.profile)
        writes = [command for command in serial.commands if command[0] == 11]
        self.assertEqual([0,1],[command[-1] for command in writes])

    def test_leave_timeout_still_unconditionally_attempts_original_profile_restore(self):
        c, clock = candidate(16384), Clock()
        serial = CompressionSerial(clock,c)
        run = self.stream_setup(c,clock,serial,mode="direct")
        def expired(sender, **options):
            serial.profile = sender.profile = (919000,250000,5,5,0)
            clock.now = sender.deadline + 1
            sender.lease_end = clock()+30
            sender.target_normal_after = clock()+200
            raise stock.DeadlineExpired("injected expired campaign")
        with patch.object(stock.Sender,"upload",expired), self.assertRaises(stock.DeadlineExpired):
            run(clock()+1000)
        self.assertEqual(NORMAL,serial.profile)
        self.assertEqual(1,[c[-1] for c in serial.commands if c[0] == 11][-1])

    def test_native_fleet_shares_physical_duty_including_authorization_and_group_boundaries(self):
        c, clock = candidate(16384), Clock()
        serial = FleetCompressionSerial(clock,c)
        run = self.stream_setup(c,clock,serial,targets=(TARGET,TARGET2))
        result = run(clock()+10000)
        self.assertEqual({TARGET,TARGET2},serial.admitted_targets)
        self.assertTrue(all(bits == set(range(c.total)) for bits in serial.received_by.values()))
        self.assertTrue(all(r["transfer_encoding"] == "lzma1-g8064-armt" for r in result["targets"]))
        inners = [stock.retry_payload(frame)[1] for _,_,frame in serial.rf_packets]
        self.assertEqual(2,sum(frame[0] == 8 for frame in inners))
        groups = {struct.unpack_from(">H",frame,5)[0] for frame in inners if frame[0] == codec.FRAGMENT}
        self.assertGreater(len(groups),1)
        for index,((before,profile,_),(after,_,_)) in enumerate(zip(serial.rf_packets,serial.rf_packets[1:])):
            quiet = max(.15,stock.airtime(len(serial.raw_packets[index]),profile))*(1/.02-1)
            self.assertGreaterEqual(after+1e-6,before+.15+quiet)

    def test_unsupported_second_fleet_target_causes_zero_auth_for_both(self):
        c, clock = candidate(16384), Clock()
        serial = FleetCompressionSerial(clock,c)
        serial.unsupported.add(TARGET2)
        run = self.stream_setup(c,clock,serial,targets=(TARGET,TARGET2))
        with self.assertRaisesRegex(stock.Error,"preflight.*unsupported"):
            run(clock()+10000)
        self.assertEqual(set(),serial.admitted_targets)
        self.assertFalse(any(command[0] in (33,34,35) for command in serial.commands))

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
