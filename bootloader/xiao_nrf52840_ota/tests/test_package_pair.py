"""Generic paired bootstrap geometry, artifact binding and recovery APP tests."""
import argparse
import binascii
import hashlib
import contextlib
import gc
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
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
        self.addCleanup(gc.collect)
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

    def vendor_api(self):
        tool = Path(os.environ.get("XIAO_TEST_NRFUTIL",
            str(Path.home() / ".platformio/packages/tool-adafruit-nrfutil/adafruit-nrfutil.py")))
        sys.path.insert(0, str(tool.parent / "site-packages"))
        from nordicsemi.dfu.dfu_transport_serial import DfuTransportSerial
        from nordicsemi.dfu.dfu_transport import DfuEvent
        from nordicsemi.dfu.dfu import Dfu
        from nordicsemi import __main__ as cli
        sys.path.pop(0)
        return tool, DfuTransportSerial, DfuEvent, Dfu, cli

    def test_actual_vendor_api_propagates_endpoint_reject_and_interruption(self):
        tool, transport, event, _, _ = self.vendor_api()
        app = self.work / "app.zip"
        write_app(app, self.app)
        original_path, original_timeout = sys.path[:], transport.ACK_PACKET_TIMEOUT
        closed = []
        def opened(backend):
            self.assertEqual(backend.touch, -1)
            self.assertEqual(backend.baud_rate, 115200)
            self.assertEqual(transport.ACK_PACKET_TIMEOUT, 1800.0)
            state = [True]
            def close():
                closed.append(True); state[0] = False
            backend.serial_port = SimpleNamespace(isOpen=lambda: state[0], close=close)
        def rejected(backend, packet):
            backend._send_event(event.ERROR_EVENT, log_message="simulated target reject")
        for failure in ("endpoint", "reject", "interrupted"):
            opening = (patch.object(transport, "open", side_effect=RuntimeError("bad endpoint"))
                       if failure == "endpoint" else patch.object(transport, "open", new=opened))
            sending = (patch.object(transport, "send_init_packet", new=rejected)
                       if failure == "reject" else
                       patch.object(transport, "send_init_packet", side_effect=KeyboardInterrupt()))
            with self.subTest(failure=failure), \
                 patch.object(tempfile, "tempdir", str(self.work)), \
                 opening:
                with patch.object(transport, "send_start_dfu", return_value=None), \
                     sending:
                    with self.assertRaises(RuntimeError if failure != "interrupted" else KeyboardInterrupt):
                        commission.send_verified_usb_package(tool, "explicit-no-device", app)
            self.assertEqual(transport.ACK_PACKET_TIMEOUT, original_timeout)
            self.assertEqual(sys.path, original_path)
        self.assertEqual(len(closed), 2)

    def test_actual_vendor_open_suppresses_touch_and_dtr_in_physical_bench(self):
        _, transport, _, _, _ = self.vendor_api()
        module = sys.modules[transport.__module__]
        with patch.object(module, "Serial") as serial, patch.object(module.time, "sleep"):
            backend = transport("explicit-no-device", baud_rate=115200, touch=-1)
            backend.open()
            serial.assert_called_once()
            serial.return_value.setDTR.assert_not_called()
            backend.close()

    def test_actual_vendor_cli_false_contract_cannot_become_commission_success(self):
        tool, _, _, dfu, cli = self.vendor_api()
        app = self.work / "app.zip"; write_app(app, self.app)
        with patch.object(tempfile, "tempdir", str(self.work)), \
             patch.object(dfu, "dfu_send_images", side_effect=RuntimeError("target rejected")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertIs(cli.serial.callback(str(app), "explicit-no-device", 115200, False, False, -1), False)
            with self.assertRaisesRegex(RuntimeError, "target rejected"):
                commission.send_verified_usb_package(tool, "explicit-no-device", app)
        with patch.object(tempfile, "tempdir", str(self.work)), \
             patch.object(dfu, "dfu_send_images", return_value=False):
            with self.assertRaisesRegex(ValueError, "transfer failure"):
                commission.send_verified_usb_package(tool, "explicit-no-device", app)

    def test_usb_send_requires_all_explicit_authorizations_before_validation(self):
        base = ["commission_pair.py", "--package", "unused.zip",
                "--pair-manifest", "pair-manifest.json", "--restore-package", "unused.zip"]
        with patch.object(sys, "argv", base + ["--usb-port", "explicit-test-port"]):
            with self.assertRaisesRegex(ValueError, "explicit phase"):
                commission.main()


@unittest.skipUnless(all(os.environ.get(k) for k in
    ("XIAO_TEST_PAIR_DIR", "XIAO_TEST_APP_PACKAGE", "XIAO_TEST_APP_CONTEXT")),
    "requires matching real APP package/build context and selected pair")
class BuiltPairTests(unittest.TestCase):
    def test_real_creator_preserves_selected_app_and_verifies_matching_pair(self):
        pair = Path(os.environ["XIAO_TEST_PAIR_DIR"])
        selected = package.read_json(pair / "pair-manifest.json")
        with tempfile.TemporaryDirectory(dir=pair / "scratch") as work:
            app = Path(os.environ["XIAO_TEST_APP_PACKAGE"])
            app_context = Path(os.environ["XIAO_TEST_APP_CONTEXT"])
            args = argparse.Namespace(pair=pair, app_package=app, output=Path(work) / "packages",
                nrfutil=os.environ["XIAO_TEST_NRFUTIL"], verify_only=False,
                board=selected["board_profile"], role=selected["role"], app_context=app_context)
            original = hashlib.sha256(app.read_bytes()).digest()
            package.run(args)
            args.verify_only = True
            package.run(args)
            commission.validate_compound_preload_package(
                args.output / "compound.zip", pair / "pair-manifest.json", app)
            for phase, path in (("compound", args.output / "compound.zip"),
                                ("bootloader", args.output / "bootloader.zip"),
                                ("application", app)):
                with patch.object(sys, "argv", ["commission_pair.py",
                        "--package", str(path), "--pair-manifest", str(pair / "pair-manifest.json"),
                        "--restore-package", str(app), "--usb-phase", phase,
                        "--board", args.board, "--role", str(args.role), "--app-context", str(app_context),
                        "--boot-policy", "physical-usb-bench"]):
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        commission.main()
                    self.assertIn("explicit vendor USB recovery required", output.getvalue())
                    self.assertNotIn("double reset", output.getvalue())
            self.assertEqual(hashlib.sha256(app.read_bytes()).digest(), original)
            with self.assertRaisesRegex(ValueError, "ROLE"):
                package.verify_pair(pair, role=1 - selected["role"])
            binary = args.output / "compound.bin"
            binary.write_bytes(bytes(binary.stat().st_size))
            with self.assertRaisesRegex(ValueError, "binding"):
                package.run(args)

    def test_real_app_wrong_board_role_image_and_other_pair_refused_before_send(self):
        pair = Path(os.environ["XIAO_TEST_PAIR_DIR"])
        app = Path(os.environ["XIAO_TEST_APP_PACKAGE"])
        ctx = Path(os.environ["XIAO_TEST_APP_CONTEXT"])
        selected = package.read_json(pair / "pair-manifest.json")
        with tempfile.TemporaryDirectory(dir=pair / "scratch") as folder:
            folder = Path(folder)
            altered = folder / "different-app.zip"
            raw, _ = package.package_payload(app, "application")
            write_app(altered, raw[:-1] + bytes([raw[-1] ^ 1]))
            base = ["commission_pair.py", "--package", str(app), "--pair-manifest",
                str(pair / "pair-manifest.json"), "--restore-package", str(app),
                "--usb-phase", "application", "--boot-policy", "physical-usb-bench",
                "--board", selected["board_profile"], "--role", str(selected["role"]),
                "--app-context", str(ctx), "--usb-port", "explicit-no-device", "--fresh",
                "--nrfutil", os.environ["XIAO_TEST_NRFUTIL"]]
            cases = [("--board", "xiao_nrf52840"), ("--role", str(1 - selected["role"])),
                     ("--restore-package", str(altered))]
            alternate = os.environ.get("XIAO_TEST_ALTERNATE_PAIR_DIR")
            if alternate:
                cases.append(("--pair-manifest", str(Path(alternate) / "pair-manifest.json")))
            for flag, value in cases:
                argv = base[:]; argv[argv.index(flag) + 1] = value
                if flag == "--pair-manifest":
                    argv[argv.index("--role") + 1] = str(1 - selected["role"])
                with self.subTest(flag=flag), patch.object(sys, "argv", argv), \
                     patch.object(commission, "send_verified_usb_package") as sending:
                    with self.assertRaises(ValueError):
                        commission.main()
                    sending.assert_not_called()


if __name__ == "__main__":
    unittest.main()
