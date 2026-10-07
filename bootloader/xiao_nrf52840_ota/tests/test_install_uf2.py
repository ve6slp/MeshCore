"""Offline artifact/package safety; no USB discovery or hardware access."""
import binascii
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import install_uf2 as host


class PackageValidationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(
            dir=Path(__file__).resolve().parents[3] / ".tmp")
        self.addCleanup(self.scratch.cleanup)
        self.path = Path(self.scratch.name) / "boot.zip"
        self.raw = bytes([0xAB]) * host.BOOT_BYTES
        crc = binascii.crc_hqx(self.raw, 0xFFFF)
        self.dat = struct.pack("<HHIHHH", 0x52, 52840, host.BOOTLOADER_VERSION, 1, 0x123, crc)
        self.manifest = {"manifest": {"dfu_version": 0.5, "bootloader": {
            "bin_file": "bootloader.bin", "dat_file": "bootloader.dat",
            "init_packet_data": {"application_version": host.BOOTLOADER_VERSION,
                "device_type": 0x52, "device_revision": 52840, "softdevice_req": [0x123],
                "firmware_crc16": crc}}}}

    def write(self, *, raw=None, dat=None, extra=False):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("manifest.json", json.dumps(self.manifest))
            archive.writestr("bootloader.bin", self.raw if raw is None else raw)
            archive.writestr("bootloader.dat", self.dat if dat is None else dat)
            if extra:
                archive.writestr("application.bin", b"unexpected image")

    def test_exact_bootloader_only_package_matches_raw_crc_and_version(self):
        self.write()
        host.validate_serial_package(self.path, self.raw, host.BOOTLOADER_VERSION)

    def test_changed_raw_dat_version_or_additional_images_are_refused(self):
        for fields in ({"raw": self.raw[:-1]}, {"raw": bytes(len(self.raw))},
                       {"dat": bytes(len(self.dat))}, {"extra": True}):
            with self.subTest(fields=list(fields)):
                self.write(**fields)
                with self.assertRaises(ValueError):
                    host.validate_serial_package(self.path, self.raw, host.BOOTLOADER_VERSION)
        self.write()
        with self.assertRaises(ValueError):
            host.validate_serial_package(self.path, self.raw, host.BOOTLOADER_VERSION + 1)

    def test_duplicate_json_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            json.loads('{"role":0,"role":1}', object_pairs_hook=host.unique_json_fields)

    def test_malformed_or_truncated_arm_elf_is_refused(self):
        for data in (b"", b"\x7fELF", bytes(52),
                     b"\x7fELF\x01\x01\x01" + bytes(45)):
            self.path.write_bytes(data)
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                host.compiled_boot_span(self.path)


if __name__ == "__main__":
    unittest.main()
