"""Generic paired bootstrap geometry, artifact binding and recovery APP tests."""
import argparse
import binascii
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import package_pair as package
import commission_pair as commission

ROOT = Path(__file__).resolve().parents[3]


def app_image(size=168):
    return struct.pack("<II", 0x20010000, 0x27009) + bytes(size - 8)


def write_app(path, app, extra=False):
    crc = binascii.crc_hqx(app, 0xFFFF)
    init = {"application_version": 0xFFFFFFFF, "device_type": 0x52,
            "device_revision": 0xFFFF, "softdevice_req": [0x123], "firmware_crc16": crc}
    manifest = {"manifest": {"dfu_version": 0.5, "application": {
        "bin_file": "app.bin", "dat_file": "app.dat", "init_packet_data": init}}}
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("app.bin", app)
        archive.writestr("app.dat", struct.pack("<HHIHHH", 0x52, 0xFFFF, 0xFFFFFFFF, 1, 0x123, crc))
        if extra:
            archive.writestr("softdevice.bin", b"unexpected")


class GeometryTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(dir=ROOT / ".tmp")
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)
        self.app = app_image()
        self.stage = bytes(64)

    def test_selected_app_and_installer_are_byte_exact_with_erased_gap(self):
        raw = package.compound_payload(self.app, self.stage)
        offset = 0xC4000 - 0x27000
        self.assertEqual(raw[:len(self.app)], self.app)
        self.assertEqual(raw[len(self.app):offset], b"\xff" * (offset - len(self.app)))
        self.assertEqual(raw[offset:], self.stage)
        self.assertEqual(len(raw) % 4, 0)
        self.assertLessEqual((0x27000 + len(raw) + 4095) & ~4095, 0xD4000)

    def test_invalid_vectors_oversized_app_or_installer_are_refused(self):
        for app, stage in ((self.app[:-1], self.stage), (bytes(len(self.app)), self.stage),
                           (app_image(0x9D004), self.stage), (self.app, bytes(65537)),
                           (self.app, bytes(35)), (b"", self.stage)):
            with self.subTest(sizes=(len(app), len(stage))), self.assertRaises(ValueError):
                package.compound_payload(app, stage)

    def test_zip_binds_standard_init_crc_and_single_application(self):
        path = self.work / "app.zip"
        write_app(path, self.app)
        self.assertEqual(package.package_payload(path, "application")[0], self.app)
        write_app(path, self.app, extra=True)
        with self.assertRaisesRegex(ValueError, "extra"):
            package.package_payload(path, "application")

    def test_preload_is_bound_to_selected_ordinary_recovery_app(self):
        app = self.work / "app.zip"
        preload = self.work / "preload.zip"
        write_app(app, self.app)
        raw = package.compound_payload(self.app, self.stage)
        write_app(preload, raw)
        with patch.object(package, "verify_pair", return_value=(b"", self.stage, {})):
            self.assertEqual(commission.validate_compound_preload_package(
                preload, self.work / "pair-manifest.json", app), raw)
            write_app(app, self.app[:-4])
            with self.assertRaisesRegex(ValueError, "exact matched"):
                commission.validate_compound_preload_package(
                    preload, self.work / "pair-manifest.json", app)

    def test_bounded_readback_rejects_short_or_changed_preload(self):
        raw = package.compound_payload(self.app, self.stage)
        reads = []
        def read(address, count):
            reads.append((address, count))
            self.assertLessEqual(count, 4096)
            return raw[address - 0x27000:address - 0x27000 + count]
        commission.verify_compound_preload_readback(read, raw)
        self.assertEqual(sum(count for _, count in reads), len(raw))
        for reader in (lambda address, count: b"", lambda address, count: bytes(count)):
            with self.assertRaises(ValueError):
                commission.verify_compound_preload_readback(reader, raw)


@unittest.skipUnless(os.environ.get("XIAO_TEST_PAIR_DIR"), "requires make test-xiao-ota-bootloader-pair")
class BuiltPairTests(unittest.TestCase):
    def test_real_creator_preserves_selected_app_and_verifies_matching_pair(self):
        pair = Path(os.environ["XIAO_TEST_PAIR_DIR"])
        selected = package.read_json(pair / "pair-manifest.json")
        with tempfile.TemporaryDirectory(dir=pair / "scratch") as work:
            supplied_app = os.environ.get("XIAO_TEST_APP_PACKAGE")
            app = Path(supplied_app) if supplied_app else Path(work) / "synthetic-app.zip"
            if not supplied_app:
                write_app(app, app_image())
            args = argparse.Namespace(pair=pair, app_package=app, output=Path(work) / "packages",
                nrfutil=os.environ["XIAO_TEST_NRFUTIL"], verify_only=False,
                board=selected["board_profile"], role=selected["role"])
            original = hashlib.sha256(app.read_bytes()).digest()
            package.run(args)
            args.verify_only = True
            package.run(args)
            commission.validate_compound_preload_package(
                args.output / "compound.zip", pair / "pair-manifest.json", app)
            self.assertEqual(hashlib.sha256(app.read_bytes()).digest(), original)
            with self.assertRaisesRegex(ValueError, "ROLE"):
                package.verify_pair(pair, role=1 - selected["role"])
            binary = args.output / "compound.bin"
            binary.write_bytes(bytes(binary.stat().st_size))
            with self.assertRaisesRegex(ValueError, "binding"):
                package.run(args)


if __name__ == "__main__":
    unittest.main()
