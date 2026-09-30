import hashlib
import pathlib
import struct
import sys
import unittest
from unittest import mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import ota_rf_lab


class PrecedenceEvidenceTests(unittest.TestCase):
    public_key = bytes(range(32))
    own_advert = bytes([ota_rf_lab.PUSH_ADVERT]) + public_key
    announcement = bytes([ota_rf_lab.PUSH_OTA_EVENT, ota_rf_lab.OTA_ANNOUNCEMENT])

    def run_fixture(self, frames, stale_frames=()):
        clock = mock.Mock()
        clock.now = 0.0
        clock.monotonic.side_effect = lambda: clock.now

        def advance(duration):
            clock.now += duration

        client = mock.Mock()
        client.command.return_value = bytes([ota_rf_lab.RESP_OK])
        target = mock.Mock()
        target.poll.side_effect = advance
        batches = iter([
            [(0.0, payload) for payload in stale_frames],
            [(1.0 + index, payload) for index, payload in enumerate(frames)],
        ])
        target.take_pending.side_effect = lambda codes: next(batches, [])
        evidence = mock.Mock()

        def check(name, passed, **details):
            self.assertEqual(name, "normal-traffic-precedence")
            self.assertTrue(passed, details)

        evidence.check.side_effect = check
        with mock.patch.object(ota_rf_lab, "time", clock):
            ota_rf_lab.run_precedence_probe(client, target, self.public_key, evidence)

    def test_expected_normal_advert_before_ota_passes(self):
        self.run_fixture([self.own_advert, self.announcement])

    def test_foreign_advert_does_not_prove_normal_precedence(self):
        foreign_advert = bytes([ota_rf_lab.PUSH_ADVERT]) + bytes(reversed(range(32)))
        with self.assertRaises(AssertionError):
            self.run_fixture([foreign_advert, self.announcement])

    def test_two_normal_adverts_do_not_substitute_for_ota_reception(self):
        with self.assertRaises(AssertionError):
            self.run_fixture([self.own_advert, self.own_advert])

    def test_ota_first_fails_even_when_normal_advert_arrives(self):
        with self.assertRaises(AssertionError):
            self.run_fixture([self.announcement, self.own_advert])

    def test_stale_normal_advert_does_not_prove_current_precedence(self):
        with self.assertRaises(AssertionError):
            self.run_fixture([self.announcement], stale_frames=[self.own_advert])


class AirtimeEvidenceTests(unittest.TestCase):
    def run_pressure_fixture(self, advert_response, advert_sender):
        clock = mock.Mock()
        clock.now = 0.0
        clock.monotonic.side_effect = lambda: clock.now

        def advance(duration):
            clock.now += duration

        clock.sleep.side_effect = advance
        client = mock.Mock(name="client")
        client.name = "client"
        client.raw_requests = 0
        client.advert_requested = False
        target = mock.Mock(name="target")
        target.name = "target"
        target.poll.side_effect = advance
        target.collect.side_effect = advance
        target.take_pending.return_value = []
        target.command.return_value = b"\x1drx=129"

        def client_command(payload, **kwargs):
            if payload == bytes([ota_rf_lab.CMD_OTA_CONTROL, ota_rf_lab.OTA_GET_STATUS]):
                used = 71851 if client.raw_requests else 71298
                return b"\x1d" + f"used={used}/72000".encode("ascii")
            if payload[0] == ota_rf_lab.CMD_SEND_RAW_PACKET:
                client.raw_requests += 1
                return b"\x00" if client.raw_requests == 1 else b"\x01\x03"
            if payload[0] == ota_rf_lab.CMD_SEND_SELF_ADVERT:
                client.advert_requested = True
                return advert_response
            return b"\x00"

        def receive_advert(codes, timeout):
            self.assertTrue(client.advert_requested)
            advance(1.0)
            return bytes([ota_rf_lab.PUSH_ADVERT]) + advert_sender

        client.command.side_effect = client_command
        target.wait_frame.side_effect = receive_advert
        evidence = mock.Mock()
        evidence.results = {}

        def check(name, passed, **details):
            evidence.results[name] = passed
            if not passed:
                raise AssertionError(name)

        evidence.check.side_effect = check
        public_key = bytes(range(32))
        with mock.patch.object(ota_rf_lab, "time", clock):
            ota_rf_lab.run_airtime_test(
                client, target, {"pubkey": public_key.hex(), "pubkey_bytes": public_key},
                evidence, 90)
        return evidence.results

    def test_quota_exhaustion_does_not_pass_when_normal_allocation_fails(self):
        with self.assertRaisesRegex(AssertionError, "normal-advert-allocates-after-ota-cap"):
            self.run_pressure_fixture(b"\x01\x03", bytes(range(32)))

    def test_another_nodes_advert_does_not_prove_ordinary_service(self):
        with self.assertRaisesRegex(TimeoutError, "no fresh advert"):
            self.run_pressure_fixture(b"\x00", bytes(reversed(range(32))))

    def test_complete_gate_requires_quota_plateau_and_expected_normal_advert(self):
        results = self.run_pressure_fixture(b"\x00", bytes(range(32)))
        self.assertTrue(results["airtime-budget-exhausted"])
        self.assertTrue(results["ota-remains-budget-blocked"])
        self.assertTrue(results["normal-advert-after-ota-cap"])
        self.assertTrue(results["airtime-two-percent-enforced"])


class OtaHostWireTests(unittest.TestCase):
    def test_descriptor_uses_big_endian_fragment_geometry_and_signed_wire_fields(self):
        image = bytes(range(256))
        fragment = ota_rf_lab.descriptor_fragment(image, 1)
        self.assertEqual(fragment[:6], b"\x00\x01\x00\x7b\x00\x7b")
        descriptor, signature = fragment[6:65], fragment[65:]
        self.assertEqual(len(descriptor), 59)
        self.assertEqual(len(signature), 64)
        self.assertEqual(
            descriptor[:13],
            bytes.fromhex("584e3430000002700000000100"),
        )
        self.assertEqual(descriptor[13:45], hashlib.sha256(image).digest())
        self.assertEqual(descriptor[45:], bytes.fromhex("0000000100000001000100010001"))
        public_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key()
        public_key.verify(signature, descriptor)
        mutated = bytearray(descriptor)
        mutated[5] ^= 1
        with self.assertRaises(InvalidSignature):
            public_key.verify(signature, bytes(mutated))

    def test_chunk_frames_fit_existing_serial_limit_and_preserve_short_tail(self):
        image = bytes(index & 255 for index in range(320))
        chunks = [ota_rf_lab.chunk_payload(image, index) for index in range(3)]
        self.assertEqual([struct.unpack(">IH", chunk[:6]) for chunk in chunks],
                         [(0, 128), (1, 128), (2, 64)])
        self.assertEqual(b"".join(chunk[6:] for chunk in chunks), image)
        for chunk in chunks:
            envelope = ota_rf_lab.ota_envelope(ota_rf_lab.OTA_CHUNK, 4001, 1, 1, chunk)
            # Command, packet header, and one three-byte directed path hash.
            serial_length = 2 + 2 + 3 + len(envelope)
            self.assertLessEqual(serial_length, ota_rf_lab.MAX_SERIAL_FRAME_SIZE)

    def test_empty_images_and_out_of_range_chunks_are_rejected(self):
        with self.assertRaises(ValueError):
            ota_rf_lab.descriptor_fragment(b"", 1)
        with self.assertRaises(ValueError):
            ota_rf_lab.descriptor_fragment(b"image", 0)
        for index in (-1, 1):
            with self.assertRaises(ValueError):
                ota_rf_lab.chunk_payload(b"image", index)

    def test_control_probes_and_budget_load_have_actual_wire_shapes(self):
        self.assertEqual(ota_rf_lab.announcement_payload(3001),
                         bytes.fromhex("00000bb9007b040036ee80"))
        self.assertEqual(ota_rf_lab.lease_payload(1, 2001),
                         bytes.fromhex("01000007d10000ea6001"))
        payload = ota_rf_lab.budget_chunk_payload(7)
        self.assertEqual(struct.unpack(">IH", payload[:6]), (7, 128))
        self.assertEqual(payload[6:10], struct.pack(">I", 7))
        self.assertEqual(len(payload), 134)
        envelope = ota_rf_lab.ota_envelope(3, 5000, 1, 1, payload)
        self.assertLessEqual(4 + len(envelope), ota_rf_lab.MAX_SERIAL_FRAME_SIZE)

    def test_serial_backpressure_is_distinct_from_invalid_packet_errors(self):
        node = mock.Mock()
        node.name = "node"
        node.command.return_value = b"\x01\x03"
        with self.assertRaises(ota_rf_lab.OtaQueueFull):
            ota_rf_lab.send_ota(node, 1, 3, 5000, payload=ota_rf_lab.budget_chunk_payload(0))
        node.command.return_value = b"\x01\x06"
        with self.assertRaisesRegex(RuntimeError, "queue failed"):
            ota_rf_lab.send_ota(node, 1, 3, 5000, payload=ota_rf_lab.budget_chunk_payload(0))


if __name__ == "__main__":
    unittest.main()
