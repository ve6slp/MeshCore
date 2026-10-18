import hashlib
import struct
import unittest

from test_ota_uploader import ADMIN, ADMIN_PRIVATE, canonical, package
from ota_common import Error, domain
from ota_compression import LZMA, LZMA_THUMB, Package, RAW
from ota_compression_report import measure
from ota_transport import Route


class PackageTests(unittest.TestCase):
    def test_independent_compression_raw_fallback_and_variable_tail_roundtrip(self):
        raw = hashlib.shake_256(b"incompressible v4").digest(8192)
        repetitive = b"MeshCore bounded v4" * 500
        pkg = package(raw + repetitive + b"tail")
        self.assertEqual(pkg.raw, raw + repetitive + b"tail")
        self.assertEqual(pkg.chunks[0].codec, RAW)
        self.assertTrue(any(c.codec in (LZMA, LZMA_THUMB) for c in pkg.chunks[1:]))
        self.assertEqual(len(pkg.manifest), 227 + 35 * len(pkg.chunks))
        self.assertEqual(Package.decode(pkg.encode()), pkg)

    def test_signed_hash_list_and_canonical_signature_fail_closed(self):
        pkg = package(b"x" * 17000)
        for offset in (50, 110, 166, len(pkg.manifest) - 1, len(pkg.encode()) - 1):
            changed = bytearray(pkg.encode())
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(Error):
                Package.decode(changed)
        with self.assertRaisesRegex(Error, "trailing"):
            Package.decode(pkg.encode() + b"untrusted")

    def test_signed_malformed_encoded_stream_has_no_trailing_or_output_overflow(self):
        pkg = package(b"a" * 8192)
        unsigned = bytearray(pkg.manifest[:-64])
        stored = pkg.chunks[0].stored + b"\0"
        struct.pack_into(">H", unsigned, 164, len(stored))
        manifest = bytes(unsigned) + ADMIN_PRIVATE.sign(domain("package") + unsigned)
        with self.assertRaisesRegex(Error, "trailing"):
            Package.decode(manifest + stored)

    def test_manifest_limit_rejects_oversize_image_before_signing(self):
        image = bytes(8192 * 128 + 1)
        with self.assertRaises(Error):
            Package.build(image, canonical(image), ADMIN, lambda _: self.fail("must not sign invalid geometry"))

    def test_report_counts_shared_data_and_per_target_control_with_exact_wire_overhead(self):
        pkg = package(b"a" * 16384)
        single = measure(pkg, Route(max_path_bytes=3), 1)
        fleet = measure(pkg, Route(max_path_bytes=3), 2)
        self.assertEqual(single["counts"]["tx/data"], fleet["counts"]["tx/data"])
        self.assertEqual(fleet["counts"]["tx/admit"]["frames"], 2 * single["counts"]["tx/admit"]["frames"])
        entry = fleet["counts"]["tx/data"]
        self.assertEqual(entry["mesh_bytes"] - entry["ota_bytes"], entry["frames"] * 5)
        self.assertEqual(entry["stock_serial_wire_bytes"] - entry["mesh_bytes"], entry["frames"] * 5)
        self.assertFalse(fleet["physical_measurement"])


if __name__ == "__main__":
    unittest.main()
