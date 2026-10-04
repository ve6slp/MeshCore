import argparse
import binascii
import copy
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import package_pair as package
import commission_pair as commission


class PackagePairTest(unittest.TestCase):
    def setUp(self):
        self.pair = Path(os.environ["XIAO_TEST_PAIR_DIR"])
        self.app = Path(os.environ["XIAO_TEST_APP_PACKAGE"])
        self.workspace = tempfile.TemporaryDirectory(dir=self.pair / "scratch")
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)

    def arguments(self, output="packages"):
        return argparse.Namespace(
            pair=self.pair, app_package=self.app, output=self.work / output,
            nrfutil=os.environ["XIAO_TEST_NRFUTIL"], verify_only=False)

    def test_real_creator_exact_pair_payload_and_standard_init(self):
        args = self.arguments()
        original = self.app.read_bytes()
        package.run(args)
        manifest = package.read_json(args.output / "package-manifest.json")
        app, init = package.package_payload(self.app, "application")
        stage = (self.pair / "stage2/stage2.bin").read_bytes()
        compound, emitted = package.package_payload(args.output / "compound.zip", "application")
        offset = 0xC4000 - 0x27000
        self.assertEqual(compound[:len(app)], app)
        self.assertEqual(compound[len(app):offset], b"\xff" * (offset - len(app)))
        self.assertEqual(compound[offset:offset + len(stage)], stage)
        self.assertEqual(emitted["application_version"], init["application_version"])
        self.assertEqual(emitted["device_revision"], init["device_revision"])
        self.assertEqual(manifest["stage_bytes"], len(stage))
        self.assertLessEqual(manifest["erase_end"], 0xD4000)
        boot, _ = package.package_payload(args.output / "bootloader.zip", "bootloader")
        self.assertEqual(boot, (self.pair / "primary-boot-only.bin").read_bytes())
        self.assertEqual(self.app.read_bytes(), original)
        self.assertEqual(commission.validate_compound_preload_package(
            args.output / "compound.zip", self.pair / "pair-manifest.json"), compound)
        with self.assertRaises(ValueError):
            commission.validate_compound_preload_package(
                args.output / "bootloader.zip", self.pair / "pair-manifest.json")
        with self.assertRaisesRegex(ValueError, "exact matched"):
            commission.validate_compound_preload_package(
                self.app, self.pair / "pair-manifest.json")
        self.check_preload_readback(compound)
        for offset in (len(app), offset):
            changed = bytearray(compound)
            changed[offset] ^= 1
            path = self.work / f"corrupt-{offset}.zip"
            self.rewrite_application_zip(args.output / "compound.zip", path, changed)
            with self.assertRaisesRegex(ValueError, "exact matched"):
                commission.validate_compound_preload_package(
                    path, self.pair / "pair-manifest.json")
        args.verify_only = True
        package.run(args)
        with self.assertRaisesRegex(ValueError, "overwrite"):
            args.verify_only = False
            package.run(args)
        args.verify_only = True
        binary = args.output / "compound.bin"
        damaged = bytearray(binary.read_bytes())
        damaged[0] ^= 1
        binary.write_bytes(damaged)
        with self.assertRaisesRegex(ValueError, "binding"):
            package.run(args)

    def rewrite_application_zip(self, source, output, raw):
        with zipfile.ZipFile(source) as original, zipfile.ZipFile(output, "w") as changed:
            manifest = json.loads(original.read("manifest.json"))
            image = manifest["manifest"]["application"]
            crc = binascii.crc_hqx(raw, 0xFFFF)
            image["init_packet_data"]["firmware_crc16"] = crc
            changed.writestr("manifest.json", json.dumps(manifest))
            changed.writestr(image["bin_file"], raw)
            changed.writestr(image["dat_file"],
                             original.read(image["dat_file"])[:-2] + struct.pack("<H", crc))

    def check_preload_readback(self, compound):
        reads = []

        def read_at(address, count):
            self.assertGreaterEqual(address, 0x27000)
            self.assertLessEqual(address + count, 0x27000 + len(compound))
            self.assertLessEqual(count, 4096)
            reads.append((address, count))
            offset = address - 0x27000
            return compound[offset:offset + count]

        commission.verify_compound_preload_readback(read_at, compound)
        self.assertEqual(reads[0][0], 0x27000)
        self.assertEqual(sum(count for _, count in reads), len(compound))
        self.assertEqual(reads[-1][0] + reads[-1][1], 0x27000 + len(compound))
        with self.assertRaisesRegex(ValueError, "short"):
            commission.verify_compound_preload_readback(lambda address, count: b"", compound)
        with self.assertRaisesRegex(ValueError, "mismatch"):
            commission.verify_compound_preload_readback(
                lambda address, count: b"\0" * count, compound)
        with self.assertRaisesRegex(ValueError, "bounds"):
            commission.verify_compound_preload_readback(read_at, compound[:0x9D000])

    def test_current_prefix_and_stage_bounds_fail_before_output(self):
        app, _ = package.package_payload(self.app, "application")
        with self.assertRaisesRegex(ValueError, "CURRENT538360"):
            package.compound_payload(app[:-4], b"\xff" * 36)
        with self.assertRaisesRegex(ValueError, "beyond"):
            package.compound_payload(app, b"\xff" * (65536 + 4))
        self.assertEqual(len(package.compound_payload(app, b"\xff" * 65536)),
                         0xD4000 - 0x27000)

    def test_wrong_role_and_stage_corruption_rejected(self):
        clone = self.work / "pair"
        clone.mkdir()
        for name in ("pair-manifest.json", "primary.elf", "primary.hex", "primary-boot-only.bin"):
            shutil.copy2(self.pair / name, clone / name)
        (clone / "stage2").mkdir()
        shutil.copy2(self.pair / "stage2/stage2.bin", clone / "stage2/stage2.bin")
        original = package.read_json(clone / "pair-manifest.json")
        wrong = copy.deepcopy(original)
        wrong["role"] = 0
        (clone / "pair-manifest.json").write_text(json.dumps(wrong))
        with self.assertRaisesRegex(ValueError, "ROLE1"):
            package.verify_pair(clone)
        (clone / "pair-manifest.json").write_text(json.dumps(original))
        (clone / "stage2/stage2.bin").write_bytes(b"\xff" * original["stage2"]["extent"])
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            package.verify_pair(clone)

    def test_sd_bl_or_extra_zip_member_refused(self):
        corrupted = self.work / "extra.zip"
        with zipfile.ZipFile(self.app) as original, zipfile.ZipFile(corrupted, "w") as changed:
            for name in original.namelist():
                changed.writestr(name, original.read(name))
            changed.writestr("softdevice.bin", b"\xff" * 4)
        with self.assertRaisesRegex(ValueError, "extra"):
            package.package_payload(corrupted, "application")


if __name__ == "__main__":
    unittest.main()
