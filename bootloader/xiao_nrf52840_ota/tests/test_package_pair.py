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
import subprocess
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
import record_app_context as capture

ROOT = Path(__file__).resolve().parents[3]


def app_image(size=168):
    return struct.pack("<II", 0x20010000, 0x27009) + bytes(size - 8)


def write_app(path, app, extra=False, kind="application", version=0xFFFFFFFF):
    crc = binascii.crc_hqx(app, 0xFFFF)
    init = {"application_version": version, "device_type": 0x52,
            "device_revision": 0xFFFF, "softdevice_req": [0x123], "firmware_crc16": crc}
    manifest = {"manifest": {"dfu_version": 0.5, kind: {
        "bin_file": "app.bin", "dat_file": "app.dat", "init_packet_data": init}}}
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("app.bin", app)
        archive.writestr("app.dat", struct.pack("<HHIHHH", 0x52, 0xFFFF, version, 1, 0x123, crc))
        if extra:
            archive.writestr("softdevice.bin", b"unexpected")


class AppContextTests(unittest.TestCase):
    def setUp(self):
        namespace = ROOT / ".tmp/ota-boot-builds"
        namespace.mkdir(parents=True, exist_ok=True)
        workspace = tempfile.TemporaryDirectory(dir=namespace)
        self.addCleanup(workspace.cleanup)
        self.work = Path(workspace.name)
        self.build_dir = self.work / "build"
        self.build_dir.mkdir()
        self.app = app_image()
        write_app(self.build_dir / "firmware.zip", self.app)
        (self.build_dir / "firmware.elf").write_bytes(b"selected compiler ELF")
        self.output = self.work / "frozen"
        self.defines = [("MESHCORE_LORA_OTA", 1), ("SENSECAP_OTA_COMPILED_ROLE_ID", 1),
                        ("LORA_FREQ", 910.525), ("LORA_BW", 62.5), ("LORA_SF", 7),
                        ("LORA_CR", 5), ("LORA_TX_POWER", 22)]

    def freeze(self, board="sensecap_solar_p1", role=1, pio_board="seeed_sensecap_solar",
               mcu="nrf52840", defines=None):
        substitutions = {"$PROJECT_DIR": str(ROOT), "$BUILD_DIR": str(self.build_dir),
                         "${PROGNAME}": "firmware"}
        env = SimpleNamespace(
            subst=lambda key: substitutions[key], GetProjectOption=lambda key: pio_board,
            BoardConfig=lambda: {"build.mcu": mcu})
        class Environment(dict):
            subst = staticmethod(env.subst)
            GetProjectOption = staticmethod(env.GetProjectOption)
            BoardConfig = staticmethod(env.BoardConfig)
        actual = Environment(CPPDEFINES=self.defines if defines is None else defines,
                             PIOENV="deliberately-not-a-board-or-role-name")
        with patch.dict(os.environ, XIAO_OTA_APP_BOARD=board, XIAO_OTA_APP_ROLE=str(role),
                        XIAO_OTA_APP_FREEZE=str(self.output)), \
             contextlib.redirect_stdout(io.StringIO()):
            capture.freeze([], [], actual)
        return package.read_json(self.output / "app-build.json")

    def test_actual_solar_and_legacy_xiao_capture_bind_board_role_radio_and_all_bytes(self):
        for board in ("sensecap_solar_p1", "xiao_nrf52840", "xiao_nrf52840_sense"):
            for role in (0, 1):
                solar = board == "sensecap_solar_p1"
                defines = [item for item in self.defines
                           if item[0] != "SENSECAP_OTA_COMPILED_ROLE_ID"]
                defines += [("SENSECAP_OTA_COMPILED_ROLE_ID" if solar else
                             "XIAO_OTA_COMPILED_ROLE_ID", role)]
                if not solar:
                    defines += ["XIAO_NRF52"]
                self.output = self.work / (board + str(role))
                with self.subTest(board=board, role=role):
                    context = self.freeze(board, role, "seeed_sensecap_solar" if solar else
                                          "seeed-xiao-afruitnrf52-nrf52840", defines=defines)
                    self.assertEqual(package.verify_app_context(
                        self.output / "app-build.json", self.output / "firmware.zip",
                        board=board, role=role), context)
                    self.assertEqual(context["radio_defaults"], dict(
                        LORA_FREQ=910.525, LORA_BW=62.5, LORA_SF=7, LORA_CR=5,
                        LORA_TX_POWER=22))
                    self.assertEqual(context["image_bytes"], len(self.app))
                    self.assertEqual(context["image_sha256"], package.digest(self.app))
                    self.assertEqual(context["elf_sha256"],
                                     package.build.sha(self.build_dir / "firmware.elf"))
                    self.assertEqual(context["zip_sha256"],
                                     package.build.sha(self.build_dir / "firmware.zip"))
                    self.assertEqual((self.output / "firmware.bin").read_bytes(), self.app)
                    self.assertNotIn("XIAO_NRF52" if solar else
                                     "SENSECAP_OTA_COMPILED_ROLE_ID", context["compiler"])

    def test_capture_rejects_wrong_actual_board_role_mcu_disabled_and_mixed_profiles(self):
        for arguments in (
                {"board": "xiao_nrf52840"}, {"role": 0}, {"role": 2},
                {"pio_board": "seeed-xiao-afruitnrf52-nrf52840"}, {"mcu": "nrf52832"},
                {"defines": self.defines + ["XIAO_NRF52"]},
                {"defines": self.defines + [("XIAO_OTA_COMPILED_ROLE_ID", 1)]},
                {"defines": [d for d in self.defines if d[0] != "SENSECAP_OTA_COMPILED_ROLE_ID"]},
                {"defines": [d for d in self.defines if d[0] != "MESHCORE_LORA_OTA"]},
                {"defines": [("MESHCORE_LORA_OTA", 0)] + self.defines[1:]}):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(ValueError, "board/ROLE"):
                self.freeze(**arguments)
            self.assertFalse(self.output.exists())

    def test_conflicting_actual_defines_are_not_silently_relabelled(self):
        for define in (("SENSECAP_OTA_COMPILED_ROLE_ID", 0), ("LORA_FREQ", 907.525)):
            with self.subTest(define=define), self.assertRaisesRegex(ValueError, "conflicting"):
                self.freeze(defines=self.defines + [define])
        context = self.freeze(defines=[d for d in self.defines if d[0] != "LORA_CR"])
        self.assertEqual(context["radio_defaults"]["LORA_CR"], 5)
        with self.assertRaisesRegex(ValueError, "new project-owned"):
            self.freeze()

    def test_context_rejects_cross_board_cross_role_and_changed_zip_image_or_elf(self):
        context = self.freeze()
        path, app = self.output / "app-build.json", self.output / "firmware.zip"
        for board, role in (("xiao_nrf52840", 1), ("xiao_nrf52840_sense", 1),
                            ("sensecap_solar_p1", 0)):
            with self.subTest(board=board, role=role), self.assertRaisesRegex(ValueError, "board/ROLE"):
                package.verify_app_context(path, app, board=board, role=role)
        for changes in ({"pio_board": "seeed-xiao-afruitnrf52-nrf52840"},
                        {"mcu": "nrf52832"},
                        {"compiler": {"MESHCORE_LORA_OTA": 1, "XIAO_NRF52": 1,
                                      "XIAO_OTA_COMPILED_ROLE_ID": 1}},
                        {"compiler": dict(context["compiler"], SENSECAP_OTA_COMPILED_ROLE_ID=0)},
                        {"compiler": dict(context["compiler"], SENSECAP_OTA_COMPILED_ROLE_ID=True)},
                        {"image_bytes": len(self.app) + 4}, {"image_sha256": "0" * 64},
                        {"zip_sha256": "0" * 64}, {"elf_sha256": "0" * 64}):
            path.write_text(json.dumps(dict(context, **changes)))
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                package.verify_app_context(path, app, board="sensecap_solar_p1", role=1)
        path.write_text(json.dumps(context))
        with zipfile.ZipFile(app, "a") as archive:
            archive.comment = b"changed ZIP, identical APP bytes"
        with self.assertRaisesRegex(ValueError, "image/ZIP"):
            package.verify_app_context(path, app, board="sensecap_solar_p1", role=1)
        app.write_bytes((self.build_dir / "firmware.zip").read_bytes())
        (self.output / "firmware.elf").write_bytes(b"different ELF")
        with self.assertRaisesRegex(ValueError, "ELF"):
            package.verify_app_context(path, app, board="sensecap_solar_p1", role=1)

    def test_solar_compound_boot_and_restore_use_shared_context_gate_before_any_send(self):
        self.freeze()
        primary, stage = bytes(0xA000), bytes(64)
        compound, boot = self.work / "compound.zip", self.work / "boot.zip"
        write_app(compound, package.compound_payload(self.app, stage))
        write_app(boot, primary, kind="bootloader", version=0x902)
        app, context = self.output / "firmware.zip", self.output / "app-build.json"
        base = ["commission_pair.py", "--pair-manifest", str(self.work / "pair-manifest.json"),
                "--restore-package", str(app), "--boot-policy", "physical-usb-bench",
                "--board", "sensecap_solar_p1", "--role", "1", "--app-context", str(context)]
        pair = (primary, stage, {"usb_bench": package.build.USB_BENCH})
        with patch.object(package, "verify_pair", return_value=pair), \
             patch.object(commission, "send_verified_usb_package") as sending:
            for phase, archive in (("compound", compound), ("bootloader", boot), ("application", app)):
                argv = base + ["--usb-phase", phase, "--package", str(archive)]
                with self.subTest(phase=phase), patch.object(sys, "argv", argv), \
                     contextlib.redirect_stdout(io.StringIO()):
                    commission.main()
                sending.assert_not_called()
                for changes in ({"board_profile": "xiao_nrf52840_sense"}, {"role": 0},
                                {"pio_board": "seeed-xiao-afruitnrf52-nrf52840"},
                                {"image_sha256": "0" * 64}, {"elf_sha256": "0" * 64}):
                    original = package.read_json(context)
                    context.write_text(json.dumps(dict(original, **changes)))
                    with self.subTest(phase=phase, changes=changes), \
                         patch.object(sys, "argv", argv + ["--usb-port", "explicit-no-device",
                             "--fresh", "--nrfutil", "unused-offline-test"]), \
                         self.assertRaises(ValueError):
                        commission.main()
                    sending.assert_not_called()
                    context.write_text(json.dumps(original))

    def test_private_configuration_overrides_survive_capture_and_cannot_be_overwritten(self):
        config = self.work / "private.ini"
        private = (ROOT / "platformio.ini").read_text().replace(
            "-D LORA_FREQ=869.618", "-D LORA_FREQ=910.525").replace(
            "-D LORA_SF=8", "-D LORA_SF=7")
        config.write_text(private)
        output = self.work / "capture.ini"
        command = [sys.executable, str(ROOT / "bootloader/xiao_nrf52840_ota/tools/record_app_context.py"),
                   "--config-input", str(config), "--config-output", str(output),
                   "--environment", "SenseCap_Solar_repeater_ota_usb"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.read_text().startswith(private))
        self.assertIn("post:bootloader/xiao_nrf52840_ota/tools/record_app_context.py", output.read_text())
        config.write_text(private + "\n; different config\n")
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to overwrite", result.stderr)

    def test_solar_packaging_binds_real_creator_output_to_frozen_app_context(self):
        self.freeze()
        pair = self.work / "pair"
        pair.mkdir()
        (pair / "pair-manifest.json").write_text(json.dumps({"source_date_epoch": 1700000000}))
        args = argparse.Namespace(
            pair=pair, app_package=self.output / "firmware.zip",
            app_context=self.output / "app-build.json", output=self.work / "packages",
            nrfutil=os.environ.get("XIAO_TEST_NRFUTIL", str(
                Path.home() / ".platformio/packages/tool-adafruit-nrfutil/adafruit-nrfutil.py")),
            board="sensecap_solar_p1", role=1, verify_only=False)
        with patch.object(package, "verify_pair", return_value=(bytes(0xA000), bytes(64),
                {"usb_bench": package.build.USB_BENCH})) as pair_check, \
             contextlib.redirect_stdout(io.StringIO()):
            package.run(args)
            pair_check.assert_called_once_with(pair, board="sensecap_solar_p1", role=1)
            manifest = package.read_json(args.output / "package-manifest.json")
            self.assertEqual(manifest["app_build"]["board_profile"], "sensecap_solar_p1")
            self.assertEqual(manifest["app_build_context_sha256"],
                             package.build.sha(args.app_context))
            self.assertEqual(manifest["app_prefix_sha256"], package.digest(self.app))
            args.verify_only = True
            package.run(args)
            args.output, args.role, args.verify_only = self.work / "wrong-role", 0, False
            with self.assertRaisesRegex(ValueError, "board/ROLE"):
                package.run(args)
            self.assertFalse(args.output.exists())

    def test_pair_verifier_rejects_unmatched_or_ambiguous_solar_cf2_before_elf(self):
        pair = self.work / "pair"
        (pair / "stage2").mkdir(parents=True)
        product = self.work / "product"
        product.mkdir()
        source = {"canonical-layout": package.build.sha(
            ROOT / "src/ota/platform/Nrf52FlashLayoutContract.h")}
        stage = struct.pack("<9I", 0x3253464F, 1, 36, 0x53435031, 1, 64, 0xC4041,
                            0x20020000, 0x20030000) + bytes(28)
        (pair / "stage2/stage2.bin").write_bytes(stage)
        manifest = dict(board_profile="sensecap_solar_p1", role=1,
            vendor_pin=package.build.PIN, vendor_release=package.build.RELEASE,
            actual_vendor_bsp="sensecap_solar_p1", logical_board="sensecap_solar_p1",
            architecture="fixed-otafix-primary-secondary", optional_fault_layer="excluded",
            usb_bench=package.build.USB_BENCH, source_fingerprints=source, files={},
            currentSourceRelease=package.digest(json.dumps(dict(
                vendor_pin=package.build.PIN, source=source), sort_keys=True).encode()),
            stage2=dict(extent=64, crc32=binascii.crc32(stage) & 0xFFFFFFFF, entry=0xC4041))
        (pair / "pair-manifest.json").write_text(json.dumps(manifest))
        for ids in ([0x28860045], [0x28860059], [0x28860044, 0x28860044], [0x28860044]):
            primary = bytearray(b"\xff" * 0xA000)
            struct.pack_into("<4I", primary, 0x9800, *package.host.boot_info.CF2_MAGIC, len(ids), 126)
            for index, value in enumerate(ids):
                struct.pack_into("<II", primary, 0x9810 + 8 * index,
                                 package.host.boot_info.CF2_BOOTLOADER_BOARD_ID, value)
            (pair / "primary-boot-only.bin").write_bytes(primary)
            memory = {0xF4000 + offset: byte for offset, byte in enumerate(primary)}
            with self.subTest(ids=ids), patch.object(package.build, "PRODUCT", product), \
                 patch.object(package.build, "ihex", return_value=memory), \
                 patch.object(package.build, "loads", side_effect=RuntimeError("reached ELF")) as loads:
                if ids == [0x28860044]:
                    with self.assertRaisesRegex(RuntimeError, "reached ELF"):
                        package.verify_pair(pair, board="sensecap_solar_p1", role=1)
                    loads.assert_called_once()
                else:
                    with self.assertRaisesRegex(ValueError, "CF2"):
                        package.verify_pair(pair, board="sensecap_solar_p1", role=1)
                    loads.assert_not_called()


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
            wrong_board = ("sensecap_solar_p1" if selected["board_profile"] == "xiao_nrf52840"
                           else "xiao_nrf52840")
            cases = [("--board", wrong_board), ("--role", str(1 - selected["role"])),
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
