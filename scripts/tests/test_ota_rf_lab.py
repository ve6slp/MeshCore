import hashlib
import pathlib
import struct
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import ota_rf_lab


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


if __name__ == "__main__":
    unittest.main()
