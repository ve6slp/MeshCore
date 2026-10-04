import argparse
import binascii
import contextlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lab_device

sys.path.insert(0, str(lab_device.REPO_ROOT / "bootloader/xiao_nrf52840_ota/tools"))
import commission_pair
import install_uf2
import package_pair


class CommissioningTests(unittest.TestCase):
    def setUp(self):
        scratch = lab_device.REPO_ROOT / ".tmp"
        scratch.mkdir(exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.serial = "77CD44653A967172"
        self.config = self.root / "devices.ini"
        self.config.write_text(
            f"[roles]\ntarget = {self.serial}\nclient = 4186AE911D94CDB1\n"
            "[protected]\npine = 49C5BAF21EEF44A1\n")
        self.usb = self.root / "usb"
        self.node = self.usb / "1-4.2.3"
        self.node.mkdir(parents=True)
        for field, value in (("serial", self.serial), ("idVendor", "2886"),
                             ("idProduct", "0045"), ("product", "Sense")):
            (self.node / field).write_text(value)
        self.cdc = self.node / "1-4.2.3:1.0"
        (self.cdc / "tty" / "ttyACM5").mkdir(parents=True)
        (self.cdc / "bInterfaceClass").write_text("02")
        self.msc = self.node / "1-4.2.3:1.2"
        self.block = self.msc / "block/sdd"
        self.block.mkdir(parents=True)
        (self.block / "uevent").write_text("DEVNAME=sdd\nDEVTYPE=disk\n")
        (self.block / "dev").write_text("8:48\n")
        (self.msc / "bInterfaceClass").write_text("08")
        self.by_id = self.root / "dev/serial/by-id"
        self.by_id.mkdir(parents=True)
        self.tty = self.root / "dev/ttyACM5"
        self.tty.touch()
        self.disk = self.root / "dev/sdd"
        self.disk.touch()
        self.port = self.by_id / f"usb-Sense_{self.serial}-if00"
        self.port.symlink_to(self.tty)
        self.char_root, self.block_root = self.root / "char", self.root / "block"
        self.char_root.mkdir()
        self.block_root.mkdir()
        (self.char_root / "0:0").symlink_to(self.cdc / "tty/ttyACM5")
        (self.block_root / "8:48").symlink_to(self.block)
        self.volume = self.root / "read only volume"
        self.volume.mkdir()
        self.mountinfo = self.root / "mountinfo"
        mountpoint = str(self.volume).replace(" ", "\\040")
        self.mount_line = f"1 0 8:48 / {mountpoint} ro - vfat /dev/sdd ro\n"
        self.mountinfo.write_text(self.mount_line)
        self.current = self.volume / "CURRENT.UF2"
        self.pair = self.root / "pair"
        self.pair.mkdir()
        self.pair_manifest = self.pair / "pair-manifest.json"
        self.pair_manifest.write_text("{}")
        self.primary = b"\x42" * 40960
        self.stage = b"\x53" * 16476
        self.prefix = struct.pack("<II", 0x20040000, 0x27009) + b"\x41" * 56
        self.real_verify_pair = package_pair.verify_pair
        self.verified_pair = self.stack.enter_context(mock.patch.object(
            package_pair, "verify_pair", return_value=(self.primary, self.stage, {})))
        self.stack.enter_context(mock.patch.object(package_pair, "CURRENT_APP_BYTES", len(self.prefix)))
        self.stack.enter_context(mock.patch.object(package_pair, "CURRENT_APP_SHA256",
                                                   package_pair.digest(self.prefix)))
        self.compound = package_pair.compound_payload(self.prefix, self.stage)
        self.preload_package, self.boot_package = self.root / "compound.zip", self.root / "bootloader.zip"
        self.write_package(self.preload_package, "application", self.compound)
        self.write_package(self.boot_package, "bootloader", self.primary)
        self.write_current()
        self.script = self.root / "adafruit-nrfutil.py"
        self.script.touch()
        for name, value in (("CONFIG_PATH", self.config), ("USB_DEVICES", self.usb),
                             ("BY_ID_DIR", self.by_id), ("SYS_DEV_CHAR", self.char_root),
                             ("DEV_DIR", self.root / "dev"),
                             ("SYS_DEV_BLOCK", self.block_root), ("MOUNTINFO", self.mountinfo)):
            self.stack.enter_context(mock.patch.object(lab_device, name, value))
        self.stack.enter_context(mock.patch.dict(lab_device.os.environ, {
            "ADAFRUIT_NRFUTIL": str(self.script)}, clear=True))
        self.dfu = self.stack.enter_context(mock.patch.object(
            lab_device.subprocess, "run", return_value=argparse.Namespace(
                returncode=0, stdout=b"#\n#########Device programmed.\n", stderr=b"")))
        self.touch = self.stack.enter_context(mock.patch.object(
            lab_device, "_touch_1200", side_effect=AssertionError("unexpected 1200 touch")))
        self.wait = self.stack.enter_context(mock.patch.object(
            lab_device, "wait_for", side_effect=AssertionError("unexpected APP/USB wait")))
        self.power = self.stack.enter_context(mock.patch.object(
            lab_device, "_run", side_effect=AssertionError("unexpected power command")))

    def write_package(self, path, kind, raw, *, init_changes=None, extra=None, corrupt_dat=False):
        init = dict(application_version=0x902 if kind == "bootloader" else 0xFFFFFFFF,
                    device_type=0x52, device_revision=52840 if kind == "bootloader" else 0xFFFF,
                    softdevice_req=[0x123], firmware_crc16=binascii.crc_hqx(raw, 0xFFFF))
        init.update(init_changes or {})
        dat = struct.pack("<HHIHHH", init["device_type"], init["device_revision"],
                          init["application_version"], 1, init["softdevice_req"][0],
                          init["firmware_crc16"])
        item = dict(bin_file="firmware.bin", dat_file="firmware.dat", init_packet_data=init)
        body = dict(dfu_version=0.5, **{kind: item})
        body.update(extra or {})
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"manifest": body}))
            archive.writestr("firmware.bin", raw)
            archive.writestr("firmware.dat", b"bad" if corrupt_dat else dat)

    def uf2_block(self, address, data):
        block = bytearray(512)
        struct.pack_into("<8I", block, 0,
                         install_uf2.UF2_MAGIC_START0, install_uf2.UF2_MAGIC_START1,
                         install_uf2.UF2_FLAG_FAMILY_ID_PRESENT, address, 256,
                         (address - 0x1000) // 256, (0xEA000 - 0x1000) // 256,
                         install_uf2.USB_BOARD_IDS["xiao_nrf52840_sense"])
        block[32:288] = data.ljust(256, b"\xff")
        struct.pack_into("<I", block, 508, install_uf2.UF2_MAGIC_END)
        return block

    def write_current(self):
        with self.current.open("wb") as stream:
            stream.truncate((0xEA000 - 0x1000) // 256 * 512)
            for offset in range(0, len(self.compound), 256):
                address = 0x27000 + offset
                stream.seek((address - 0x1000) // 256 * 512)
                stream.write(self.uf2_block(address, self.compound[offset:offset + 256]))
            stream.seek((0xD4000 - 0x1000) // 256 * 512)
            stream.write(self.uf2_block(0xD4000, b"FILESYSTEM_SECRET_CANARY"))

    def args(self, *, primary=False):
        return argparse.Namespace(role="target", timeout=3.0, pair_manifest=str(self.pair_manifest),
                                  package=str(self.boot_package if primary else self.preload_package),
                                  preload_package=str(self.preload_package))

    def invoke(self, *, primary=False, args=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            command = lab_device.cmd_commission_primary if primary else lab_device.cmd_commission_compound
            self.assertEqual(command(args or self.args(primary=primary)), 0)
        return output.getvalue()

    def refuse(self, pattern, *, primary=True, args=None):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaisesRegex(SystemExit, pattern):
            command = lab_device.cmd_commission_primary if primary else lab_device.cmd_commission_compound
            command(args or self.args(primary=primary))
        self.dfu.assert_not_called()
        self.touch.assert_not_called()
        self.wait.assert_not_called()
        self.power.assert_not_called()

    def test_compound_is_explicit_and_cannot_use_ordinary_application_gate(self):
        args = self.args()
        with mock.patch.object(lab_device, "cmd_bootloader_port") as boot:
            with self.assertRaisesRegex(SystemExit, "maximum|exceeds|too large"):
                lab_device.cmd_flash(args)
            boot.assert_not_called()
        self.dfu.assert_not_called()
        with mock.patch.object(commission_pair, "validate_compound_preload_package",
                               wraps=commission_pair.validate_compound_preload_package) as validate, \
                mock.patch.object(lab_device, "validate_application_package",
                                  side_effect=AssertionError("ordinary gate must not be relaxed")):
            output = self.invoke()
        validate.assert_called_once_with(self.preload_package, self.pair_manifest)
        command = self.dfu.call_args.args[0]
        self.assertEqual(command, [sys.executable, str(self.script), "dfu", "serial",
                                   "-pkg", str(self.preload_package), "-p", str(self.port),
                                   "-b", "115200", "--singlebank"])
        self.assertEqual(self.dfu.call_args.kwargs["timeout"], 3.0)
        self.assertIn("transport complete", output)
        self.assertIn("installed bytes not yet verified", output)
        self.wait.assert_not_called()

    def test_ordinary_application_limit_is_c4000_not_transport_staging_capacity(self):
        self.write_package(self.preload_package, "application", b"\x00" * 643072)
        self.assertEqual(len(lab_device.validate_application_package(self.preload_package)), 643072)
        self.write_package(self.preload_package, "application", b"\x00" * 643076)
        with mock.patch.object(lab_device, "cmd_bootloader_port") as boot:
            with self.assertRaisesRegex(SystemExit, "fixed installer is out of bounds"):
                lab_device.cmd_flash(self.args())
            boot.assert_not_called()
        self.dfu.assert_not_called()

    def test_compound_8044_or_8045_app_uses_pinned_touch_then_exact_sense0045_boot(self):
        self.touch.side_effect = lambda port: (self.node / "idProduct").write_text("0045")
        self.wait.side_effect = lambda role, mode, timeout: lab_device.resolve(role, mode)
        for product_id in ("8044", "8045"):
            with self.subTest(product_id=product_id):
                self.touch.reset_mock()
                self.wait.reset_mock()
                self.dfu.reset_mock()
                (self.node / "idProduct").write_text(product_id)
                self.invoke()
                self.touch.assert_called_once_with(self.port)
                self.wait.assert_called_once_with("target", lab_device.MODE_BOOT, 3.0)
                self.dfu.assert_called_once()
                self.assertEqual(self.dfu.call_args.args[0][7], str(self.port))

    def test_compound_unapproved_app_pid_refuses_before_touch(self):
        for product_id in ("8043", "8046", "8000", "810b"):
            with self.subTest(product_id=product_id):
                (self.node / "idProduct").write_text(product_id)
                self.refuse("approved APP USB 2886:8044 or 2886:8045", primary=False)

    def test_known8044_app_cannot_transfer_if_touch_returns_non_sense0044_boot(self):
        (self.node / "idProduct").write_text("8044")
        self.touch.side_effect = lambda port: (self.node / "idProduct").write_text("0044")
        self.wait.side_effect = lambda role, mode, timeout: lab_device.resolve(role, mode)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaisesRegex(SystemExit, "exact Sense USB 2886:0045"):
            lab_device.cmd_commission_compound(self.args())
        self.touch.assert_called_once_with(self.port)
        self.wait.assert_called_once_with("target", lab_device.MODE_BOOT, 3.0)
        self.dfu.assert_not_called()
        self.power.assert_not_called()

    def test_compound_prefix_gap_stage_and_standard_init_are_validated_before_any_device_access(self):
        original = self.compound
        mutations = ((0, "CURRENT"), (100, "exact matched"), (len(original) - 1, "exact matched"))
        for offset, pattern in mutations:
            with self.subTest(offset=offset):
                raw = bytearray(original)
                raw[offset] ^= 1
                self.write_package(self.preload_package, "application", bytes(raw))
                with mock.patch.object(lab_device, "resolve") as resolve:
                    self.refuse(pattern, primary=False)
                    resolve.assert_not_called()
        self.write_package(self.preload_package, "application", original,
                           init_changes={"application_version": 1})
        with mock.patch.object(lab_device, "resolve") as resolve:
            self.refuse("compound standard init", primary=False)
            resolve.assert_not_called()

    def test_wrong_pair_filename_and_manifest_board_role_fail_before_device_access(self):
        args = self.args(primary=True)
        args.pair_manifest = str(self.root / "package-manifest.json")
        with mock.patch.object(lab_device, "resolve") as resolve:
            self.refuse("build pair-manifest", args=args)
            resolve.assert_not_called()
        self.verified_pair.side_effect = self.real_verify_pair
        header = dict(vendor_pin=package_pair.build.PIN, vendor_release=package_pair.build.RELEASE,
                      actual_vendor_bsp="xiao_nrf52840_ble_sense", logical_board="xiao_nrf52840",
                      role=1)
        for field, value in (("role", 2), ("actual_vendor_bsp", "xiao_nrf52840"),
                             ("logical_board", "pine"), ("vendor_pin", "different")):
            with self.subTest(field=field), mock.patch.object(lab_device, "resolve") as resolve:
                self.pair_manifest.write_text(json.dumps(dict(header, **{field: value})))
                self.refuse("genuine pinned Sense BSP")
                resolve.assert_not_called()

    def test_role_serial_environment_and_protected_guards_precede_discovery(self):
        for primary in (False, True):
            for role in ("client", "recovery", "pine"):
                args = self.args(primary=primary)
                args.role = role
                with self.subTest(primary=primary, role=role), \
                        mock.patch.object(lab_device, "discover") as discover:
                    self.refuse("target role only", primary=primary, args=args)
                    discover.assert_not_called()
            for serial in ("4186AE911D94CDB1", "3BE94917B92DC5E9", "49C5BAF21EEF44A1", "other"):
                with self.subTest(primary=primary, serial=serial), \
                        mock.patch.dict(lab_device.os.environ, {"MESHCORE_LAB_TARGET_SERIAL": serial}), \
                        mock.patch.object(lab_device, "discover") as discover:
                    self.refuse("literal approved|protected", primary=primary)
                    discover.assert_not_called()
        self.config.write_text(f"[roles]\ntarget = {self.serial}\n[protected]\nreserved = {self.serial}\n")
        with mock.patch.object(lab_device, "discover") as discover:
            self.refuse("protected lab device assignment")
            discover.assert_not_called()

    def test_timeout_requires_finite_positive_value_before_device_access(self):
        for primary in (False, True):
            for timeout in (0, -1, float("inf"), float("-inf"), float("nan")):
                args = self.args(primary=primary)
                args.timeout = timeout
                with self.subTest(primary=primary, timeout=timeout), \
                        mock.patch.object(lab_device, "resolve") as resolve:
                    self.refuse("finite and positive", primary=primary, args=args)
                    resolve.assert_not_called()

    def test_primary_reads_only_authorized_blocks_then_transport_without_app_or_usb_wait(self):
        pread = lab_device.os.pread
        addresses = []
        events = []

        def bounded(fd, count, offset):
            self.assertEqual(count, 512)
            address = 0x1000 + offset // 512 * 256
            self.assertGreaterEqual(address, 0x27000)
            self.assertLess(address, 0x27000 + len(self.compound))
            self.assertLessEqual(address + 256, 0xD4000)
            addresses.append(address)
            events.append("read")
            return pread(fd, count, offset)

        def transport(*args, **kwargs):
            events.append("dfu")
            return argparse.Namespace(returncode=0, stdout=b"Device programmed.\n", stderr=b"")

        self.dfu.side_effect = transport
        with mock.patch.object(lab_device.os, "pread", side_effect=bounded), \
                mock.patch.object(commission_pair, "verify_compound_preload_readback",
                                  wraps=commission_pair.verify_compound_preload_readback) as verify, \
                mock.patch.object(lab_device, "cmd_bootloader_port",
                                  side_effect=AssertionError("primary must not request entry")) as boot:
            output = self.invoke(primary=True)
        self.assertEqual(addresses, list(range(0x27000, 0x27000 + len(self.compound), 256)))
        self.assertEqual(events[-1], "dfu")
        self.assertEqual(events.count("dfu"), 1)
        verify.assert_called_once()
        boot.assert_not_called()
        self.dfu.assert_called_once()
        self.assertEqual(self.dfu.call_args.kwargs["timeout"], 3.0)
        self.assertIn("live compound CURRENT.UF2 readback verified", output)
        self.assertIn("activation not yet verified", output)
        self.assertIn("WITHOUT USB", output)
        self.assertIn("ONE physical pin reset", output)
        self.assertIn("Do not retry loader writes or power-cycle", output)
        self.assertIn("do not expose the installed-primary SHA-256", output)
        self.assertNotIn("FILESYSTEM_SECRET", output)
        self.touch.assert_not_called()
        self.wait.assert_not_called()
        self.power.assert_not_called()

    def test_malformed_mismatched_primary_or_extra_regions_fail_before_current_or_dfu(self):
        for kwargs, pattern in (
                (dict(raw=self.primary[:-4]), "matching RAW"),
                (dict(raw=b"\x43" * 40960), "matching RAW"),
                (dict(raw=self.primary, kind="application"), "bootloader-only"),
                (dict(raw=self.primary, extra={"softdevice": {}}), "bootloader-only"),
                (dict(raw=self.primary, extra={"application": {}}), "bootloader-only"),
                (dict(raw=self.primary, extra={"uicr": {}}), "bootloader-only"),
                (dict(raw=self.primary, extra={"filesystem": {}}), "bootloader-only"),
                (dict(raw=self.primary, extra={"sdk_settings": {}}), "bootloader-only"),
                (dict(raw=self.primary, init_changes={"application_version": 1}), "standard init"),
                (dict(raw=self.primary, init_changes={"device_revision": 0xFFFF}), "standard init"),
                (dict(raw=self.primary, corrupt_dat=True), "standard init packet"),
                (dict(raw=self.primary, init_changes={"firmware_crc16": 0}), "CRC")):
            with self.subTest(kwargs=list(kwargs)):
                options = dict(kind="bootloader", **kwargs) if "kind" not in kwargs else kwargs
                self.write_package(self.boot_package, **options)
                with mock.patch.object(lab_device, "resolve") as resolve, \
                        mock.patch.object(lab_device.os, "pread") as read:
                    self.refuse(pattern)
                    resolve.assert_not_called()
                    read.assert_not_called()
        self.boot_package.write_bytes(b"not a ZIP")
        self.refuse("File is not a zip file")

    def test_extra_sdk_zip_member_is_not_a_bootloader_only_package(self):
        with zipfile.ZipFile(self.boot_package, "a") as archive:
            archive.writestr("sdk-settings.bin", b"\xff" * 4096)
        with mock.patch.object(lab_device, "resolve") as resolve:
            self.refuse("extra/duplicate ZIP")
            resolve.assert_not_called()

    def test_bad_preload_package_prevents_even_primary_device_access(self):
        self.write_package(self.preload_package, "application", self.compound[:-4])
        with mock.patch.object(lab_device, "resolve") as resolve:
            self.refuse("exact matched")
            resolve.assert_not_called()

    def test_primary_raw_must_be_full40960_matched_pair(self):
        self.verified_pair.return_value = (self.primary[:-4], self.stage, {})
        with mock.patch.object(lab_device, "resolve") as resolve:
            self.refuse("exactly 40960")
            resolve.assert_not_called()

    def test_changed_pair_stage_between_offline_checks_cannot_authorize_primary(self):
        self.verified_pair.side_effect = (
            (self.primary, self.stage, {}), (self.primary, b"\x54" * len(self.stage), {}))
        with mock.patch.object(lab_device, "resolve") as resolve:
            self.refuse("pair stage changed")
            resolve.assert_not_called()

    def test_current_magic_flags_target_payload_number_count_family_and_end_magic_fail_before_dfu(self):
        first = (0x27000 - 0x1000) // 256 * 512
        for field, value in ((0, 0), (4, 0), (8, 0), (8, 0x2001), (12, 0xD4000),
                             (16, 128), (20, 0), (24, 1), (28, 0xADA52840), (508, 0)):
            with self.subTest(field=field, value=value):
                self.write_current()
                with self.current.open("r+b") as stream:
                    stream.seek(first + field)
                    stream.write(struct.pack("<I", value))
                self.refuse("magic/flags/address/block/family")

    def test_bad_current_payload_and_short_read_fail_before_dfu(self):
        first = (0x27000 - 0x1000) // 256 * 512
        with self.current.open("r+b") as stream:
            stream.seek(first + 32)
            stream.write(b"\xff")
        self.refuse("compound readback mismatch")
        self.write_current()
        pread = lab_device.os.pread
        with mock.patch.object(lab_device.os, "pread",
                               side_effect=lambda fd, count, offset: pread(fd, count - 1, offset)):
            self.refuse("short CURRENT.UF2 block")

    def test_current_requires_exact_size_regular_file_nofollow_and_readonly_open(self):
        opened = lab_device.os.open
        with mock.patch.object(lab_device.os, "open", wraps=opened) as opening:
            self.invoke(primary=True)
        opening.assert_called_once_with(
            self.current, lab_device.os.O_RDONLY | lab_device.os.O_NOFOLLOW | lab_device.os.O_NONBLOCK)
        self.dfu.reset_mock()
        self.current.write_bytes(b"short")
        self.refuse("exact virtual")
        self.current.unlink()
        self.current.mkdir()
        self.refuse("regular file")
        self.current.rmdir()
        outside = self.root / "outside.uf2"
        outside.touch()
        self.current.symlink_to(outside)
        self.refuse("refusing paired primary")

    def test_read_callback_is_bounded_and_cannot_read_softdevice_filesystem_or_primary(self):
        def forbidden(read_at, expected):
            for address, count in ((0x1000, 256), (0xD4000, 256), (0xF4000, 256),
                                   (0x27000, 4097), (0x27000, 0), (0x27000, -1),
                                   (0x27000 + len(expected) - 1, 2)):
                with self.subTest(address=address, count=count), \
                        self.assertRaisesRegex(ValueError, "authorized bounded"):
                    read_at(address, count)
            raise ValueError("bounded callback tested")

        with mock.patch.object(commission_pair, "verify_compound_preload_readback", side_effect=forbidden), \
                mock.patch.object(lab_device.os, "pread") as read:
            self.refuse("bounded callback tested")
            read.assert_not_called()

    def test_rw_subtree_duplicate_or_absent_mount_refuse_before_opening_current(self):
        for text in ("", self.mount_line * 2, self.mount_line.replace(" ro ", " rw "),
                     self.mount_line.replace("/dev/sdd ro", "/dev/sdd rw"),
                     self.mount_line.replace("8:48 / ", "8:48 /subtree ")):
            with self.subTest(text=text), mock.patch.object(lab_device.os, "open") as opening:
                self.mountinfo.write_text(text)
                self.refuse("ancestry-matched|read-only")
                opening.assert_not_called()

    def test_mount_records_change_during_readback_prevents_primary_transfer(self):
        real_verify = commission_pair.verify_compound_preload_readback

        def changed(reader, expected):
            real_verify(reader, expected)
            self.mountinfo.write_text(self.mount_line.replace(" ro ", " rw "))

        with mock.patch.object(commission_pair, "verify_compound_preload_readback", side_effect=changed):
            self.refuse("mount records changed")

    def test_device_or_current_path_replacement_during_readback_prevents_transfer(self):
        real_verify = commission_pair.verify_compound_preload_readback
        for name in ("tty", "current", "volume"):
            self.write_current()

            def changed(reader, expected):
                real_verify(reader, expected)
                if name == "tty":
                    self.tty.rename(self.root / "old-tty")
                    self.tty.touch()
                elif name == "current":
                    self.current.rename(self.root / "old-current")
                    self.write_current()
                else:
                    self.volume.rename(self.root / "old-volume")
                    self.volume.mkdir()
                    self.write_current()

            with self.subTest(name=name), mock.patch.object(
                    commission_pair, "verify_compound_preload_readback", side_effect=changed):
                self.refuse("identity changed")

    def test_wrong_variant_serial_ancestry_or_missing_msc_prevents_transfer(self):
        for primary in (False, True):
            for field, value in (("idProduct", "0044"), ("serial", "3BE94917B92DC5E9")):
                with self.subTest(primary=primary, field=field):
                    old = (self.node / field).read_text()
                    (self.node / field).write_text(value)
                    self.refuse("exact Sense|not attached", primary=primary)
                    (self.node / field).write_text(old)
        (self.msc / "bInterfaceClass").write_text("02")
        self.refuse("own MSC")

    def test_same_serial_block_node_on_other_usb_device_is_not_authority(self):
        other = self.usb / "other"
        other.mkdir()
        (other / "serial").write_text(self.serial)
        block = other / "block/sdd"
        block.mkdir(parents=True)
        (self.block_root / "8:48").unlink()
        (self.block_root / "8:48").symlink_to(block)
        self.refuse("mounted target volume ancestry")

    def test_modern_info_never_qualifies_as_stock_and_does_not_substitute_for_live_readback(self):
        info = self.volume / "INFO_UF2.TXT"
        info.write_text("UF2 Bootloader 0.9.2\nBoard-ID: Seeed_XIAO_nRF52840_Sense\n"
                        "SoftDevice: S140 version 7.3.0\n")
        with self.assertRaisesRegex(SystemExit, "stock bootloader 0.6.1"):
            lab_device.cmd_inspect_stock_bootloader(argparse.Namespace(role="target"))
        info.unlink()
        self.invoke(primary=True)
        self.dfu.assert_called_once()

    def test_nonzero_and_timeout_transport_have_no_retry_reset_power_or_activation_claim(self):
        for primary in (False, True):
            for failure in (17, lab_device.subprocess.TimeoutExpired("dfu", 3)):
                self.dfu.reset_mock()
                self.dfu.side_effect = failure if isinstance(failure, Exception) else None
                self.dfu.return_value = argparse.Namespace(
                    returncode=failure, stdout=b"Device programmed.\n", stderr=b"")
                output = io.StringIO()
                with self.subTest(primary=primary, failure=failure), \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()), \
                        self.assertRaisesRegex(SystemExit, "exit 17|timed out"):
                    command = lab_device.cmd_commission_primary if primary else lab_device.cmd_commission_compound
                    command(self.args(primary=primary))
                self.dfu.assert_called_once()
                self.assertNotIn("transport complete", output.getvalue())
                self.touch.assert_not_called()
                self.wait.assert_not_called()
                self.power.assert_not_called()

    def transport_routes(self):
        ordinary = self.root / "ordinary.zip"
        self.write_package(ordinary, "application", self.prefix)
        flash = self.args()
        flash.package = str(ordinary)
        return (("flash", lab_device.cmd_flash, flash),
                ("compound", lab_device.cmd_commission_compound, self.args()),
                ("primary", lab_device.cmd_commission_primary, self.args(primary=True)))

    def test_zero_exit_vendor_failure_is_explicit_and_never_waits_or_retries(self):
        failures = (
            (b"Failed to upgrade target. Error is: write failed: [Errno 5] Input/output error\n",
             b"Traceback (most recent call last):\nINIT failed\n"),
            (b"Device programmed.\n", b"ERROR: vendor returned false\n"),
            (b"Device programmed.\nTraceback\n", b""),
            (b"Device programmed.\nFalse\n", b""),
            (b"#\n#########Device programmed.\n", b"Exception: transport failed\n"),
            (b"#\n#########Device programmed.\n", b"serial.SerialException: write failed\n"),
            (b"Traceback\r\n#\n#########Device programmed.\n", b""),
            (b"False\r\n#\n#########Device programmed.\n", b""),
        )
        for route, command, args in self.transport_routes():
            for stdout, stderr in failures:
                self.dfu.reset_mock()
                self.dfu.return_value = argparse.Namespace(returncode=0, stdout=stdout, stderr=stderr)
                output, errors = io.StringIO(), io.StringIO()
                with self.subTest(route=route, stdout=stdout, stderr=stderr), \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), \
                        self.assertRaisesRegex(SystemExit, "transport failure despite exit 0"):
                    command(args)
                self.assertTrue(output.getvalue().endswith(stdout.decode()))
                self.assertTrue(errors.getvalue().endswith(stderr.decode()))
                self.assertNotIn("transport complete", output.getvalue())
                self.assertNotIn("activation not yet verified", output.getvalue())
                self.dfu.assert_called_once()
                self.wait.assert_not_called()
                self.touch.assert_not_called()
                self.power.assert_not_called()

    def test_zero_exit_without_exact_stdout_completion_never_waits_or_succeeds(self):
        for route, command, args in self.transport_routes():
            for stdout, stderr in ((b"", b""), (b"INIT completed\n", b""),
                                   (b"prefix Device programmed.\n", b""),
                                   (b"Device programmed. \n", b""),
                                   (b"#########Device programmed. \n", b""),
                                   (b"# Device programmed.\n", b""),
                                   (b"#\n#########Device programmed.\nnot the final line\n", b""),
                                   (b"", b"Device programmed.\n")):
                self.dfu.reset_mock()
                self.dfu.return_value = argparse.Namespace(returncode=0, stdout=stdout, stderr=stderr)
                output = io.StringIO()
                with self.subTest(route=route, stdout=stdout, stderr=stderr), \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()), \
                        self.assertRaisesRegex(SystemExit, "missing 'Device programmed.'"):
                    command(args)
                self.assertNotIn("transport complete", output.getvalue())
                self.dfu.assert_called_once()
                self.wait.assert_not_called()
                self.touch.assert_not_called()
                self.power.assert_not_called()

    def test_pinned_cli_real_progress_completion_succeeds_on_all_three_routes(self):
        for route, command, args in self.transport_routes():
            for stdout in (b"#\n#########Device programmed.\n",
                           b"#\n#########Device programmed.\n\n"):
                self.dfu.reset_mock()
                self.wait.reset_mock()
                self.dfu.return_value = argparse.Namespace(returncode=0, stdout=stdout, stderr=b"")
                self.wait.side_effect = None if route == "flash" else AssertionError("unexpected APP wait")
                self.wait.return_value = argparse.Namespace(by_id=self.port)
                output = io.StringIO()
                with self.subTest(route=route, stdout=stdout), contextlib.redirect_stdout(output), \
                        contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(command(args), 0)
                self.assertIn(stdout.decode(), output.getvalue())
                self.dfu.assert_called_once()
                if route == "flash":
                    self.wait.assert_called_once_with("target", lab_device.MODE_APP, 3.0)
                else:
                    self.wait.assert_not_called()
                    self.assertIn("transport complete", output.getvalue())
                self.touch.assert_not_called()
                self.power.assert_not_called()

    def test_incidental_error_exception_traceback_paths_do_not_mask_real_success(self):
        directory = self.root / "exception-directory" / "traceback-directory"
        directory.mkdir(parents=True)
        port = self.by_id / "usb-error-exception-traceback-target"
        self.port.rename(port)
        self.port = port
        for route, command, args in self.transport_routes():
            package = directory / (route + "-firmware-error-correction.zip")
            package.write_bytes(Path(args.package).read_bytes())
            args.package = str(package)
            stdout = (f"Upgrading target on {self.port} with DFU package {package}.\n".encode()
                      + b"#\n#########Device programmed.\n")
            self.dfu.reset_mock()
            self.wait.reset_mock()
            self.dfu.return_value = argparse.Namespace(returncode=0, stdout=stdout, stderr=b"")
            self.wait.side_effect = None if route == "flash" else AssertionError("unexpected APP wait")
            self.wait.return_value = argparse.Namespace(by_id=self.port)
            with self.subTest(route=route), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(command(args), 0)
            self.dfu.assert_called_once()
            self.assertEqual(self.dfu.call_args.args[0][7], str(self.port))
            if route == "flash":
                self.wait.assert_called_once_with("target", lab_device.MODE_APP, 3.0)
            else:
                self.wait.assert_not_called()
            self.touch.assert_not_called()
            self.power.assert_not_called()

    def test_nonzero_exit_overrides_even_valid_completion_on_every_route(self):
        for route, command, args in self.transport_routes():
            self.dfu.reset_mock()
            self.dfu.return_value = argparse.Namespace(
                returncode=9, stdout=b"Device programmed.\n", stderr=b"")
            with self.subTest(route=route), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(SystemExit, "exit 9"):
                command(args)
            self.dfu.assert_called_once()
            self.wait.assert_not_called()
            self.touch.assert_not_called()
            self.power.assert_not_called()

    def test_real_completion_echoes_exact_bytes_before_preserved_default_app_wait(self):
        _, command, args = self.transport_routes()[0]
        (self.root / "site-packages").mkdir()
        stdout, stderr = b"progress\r\nDevice programmed.\r\n", b"diagnostic:\xff\r\n"
        output_bytes, error_bytes = io.BytesIO(), io.BytesIO()
        output, errors = io.TextIOWrapper(output_bytes), io.TextIOWrapper(error_bytes)
        self.addCleanup(output.close)
        self.addCleanup(errors.close)

        def complete(*command_args, **kwargs):
            self.assertIn(b"flashing target", output_bytes.getvalue())
            return argparse.Namespace(returncode=0, stdout=stdout, stderr=stderr)

        def app_ready(role, mode, timeout):
            self.assertTrue(output_bytes.getvalue().endswith(stdout))
            self.assertEqual(error_bytes.getvalue(), stderr)
            return argparse.Namespace(by_id=self.port)

        self.dfu.side_effect = complete
        self.wait.side_effect = app_ready
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), \
                mock.patch.dict(lab_device.os.environ, {"PYTHONPATH": "previous"}), \
                mock.patch("builtins.print", wraps=print) as printed:
            self.assertEqual(command(args), 0)
        flashing = [call for call in printed.call_args_list if str(call.args[0]).startswith("flashing ")]
        self.assertEqual(len(flashing), 1)
        self.assertIs(flashing[0].kwargs["flush"], True)
        self.wait.assert_called_once_with("target", lab_device.MODE_APP, 3.0)
        self.dfu.assert_called_once_with(
            [sys.executable, str(self.script), "dfu", "serial", "-pkg", args.package,
             "-p", str(self.port), "-b", "115200", "--singlebank"],
            env=mock.ANY, capture_output=True)
        self.assertEqual(self.dfu.call_args.kwargs["env"]["PYTHONPATH"],
                         lab_device.os.pathsep.join((str(self.root / "site-packages"), "previous")))
        self.touch.assert_not_called()
        self.power.assert_not_called()

    def test_live_readback_progress_is_flushed_before_primary_transport(self):
        output = io.StringIO()

        def complete(*args, **kwargs):
            self.assertIn("live compound CURRENT.UF2 readback verified", output.getvalue())
            return argparse.Namespace(returncode=0, stdout=b"Device programmed.\n", stderr=b"")

        self.dfu.side_effect = complete
        with contextlib.redirect_stdout(output), mock.patch("builtins.print", wraps=print) as printed:
            self.assertEqual(lab_device.cmd_commission_primary(self.args(primary=True)), 0)
        verified = [call for call in printed.call_args_list
                    if str(call.args[0]).startswith("live compound CURRENT.UF2")]
        self.assertEqual(len(verified), 1)
        self.assertIs(verified[0].kwargs["flush"], True)
        self.assertLess(output.getvalue().index("live compound"),
                        output.getvalue().index("Device programmed."))
        self.assertIn("transport complete; activation not yet verified", output.getvalue())
        self.wait.assert_not_called()

    def test_timeout_echoes_partial_cli_output_and_has_no_retry(self):
        self.dfu.side_effect = lab_device.subprocess.TimeoutExpired(
            "dfu", 3, output=b"INIT progress\r\n", stderr=b"write interrupted\r\n")
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), \
                self.assertRaisesRegex(SystemExit, "transport timed out.*no automatic retry"):
            lab_device._serial_dfu(self.boot_package, self.port, self.script, timeout=3.0)
        self.assertEqual(output.getvalue(), "INIT progress\r\n")
        self.assertEqual(errors.getvalue(), "write interrupted\r\n")
        self.dfu.assert_called_once()
        self.wait.assert_not_called()
        self.touch.assert_not_called()
        self.power.assert_not_called()

    def test_cli_commands_require_explicit_matched_packages_and_only_target_role(self):
        for command, handler in (("commission-compound", "cmd_commission_compound"),
                                 ("commission-primary", "cmd_commission_primary")):
            arguments = [command, "target", "--package", "chosen.zip", "--pair-manifest", "pair-manifest.json"]
            if command == "commission-primary":
                arguments += ["--preload-package", "compound.zip"]
            with mock.patch.object(sys, "argv", ["lab_device.py", *arguments]), \
                    mock.patch.object(lab_device, handler, return_value=0) as invoked:
                self.assertEqual(lab_device.main(), 0)
                args = invoked.call_args.args[0]
                self.assertEqual(args.role, "target")
                self.assertEqual(args.timeout, 120)
            for invalid in ([command, "client"], [command, "target"],
                            [*arguments, "--reset"], [*arguments, "--mode", "app"]):
                with self.subTest(command=command, invalid=invalid), \
                        mock.patch.object(sys, "argv", ["lab_device.py", *invalid]), \
                        mock.patch.object(lab_device, "resolve") as resolve, mock.patch("sys.stderr"):
                    with self.assertRaises(SystemExit):
                        lab_device.main()
                    resolve.assert_not_called()

    @contextlib.contextmanager
    def block_metadata(self, *, rdev=None):
        original = Path.stat

        def metadata(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if path != self.disk:
                return value
            return types.SimpleNamespace(
                st_dev=value.st_dev, st_ino=value.st_ino, st_mode=lab_device.stat.S_IFBLK | 0o660,
                st_rdev=lab_device.os.makedev(8, 48) if rdev is None else rdev)

        with mock.patch.object(Path, "stat", autospec=True, side_effect=metadata):
            yield

    def mount_target(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(lab_device.cmd_mount_commission_uf2(self.args()), 0)
        self.dfu.assert_not_called()
        self.touch.assert_not_called()
        self.wait.assert_not_called()
        return output.getvalue().strip()

    def refuse_mount(self, pattern):
        with self.assertRaisesRegex(SystemExit, pattern):
            lab_device.cmd_mount_commission_uf2(self.args())
        self.dfu.assert_not_called()
        self.touch.assert_not_called()
        self.wait.assert_not_called()

    def test_mount_command_selects_exact_ancestry_block_and_only_udisks_ro(self):
        self.mountinfo.write_text("")

        def mounted(command, timeout):
            self.assertEqual(command, ["udisksctl", "mount", "--block-device", str(self.disk),
                                       "--options", "ro"])
            self.assertEqual(timeout, 3.0)
            self.mountinfo.write_text(self.mount_line)
            return 0, "Mounted approved target"

        self.power.side_effect = mounted
        with self.block_metadata():
            self.assertEqual(self.mount_target(), str(self.volume))
        self.power.assert_called_once()

    def test_existing_readonly_mount_is_reused_without_a_command(self):
        with self.block_metadata():
            self.assertEqual(self.mount_target(), str(self.volume))
        self.power.assert_not_called()

    def test_existing_rw_or_ambiguous_mount_refuses_without_unmount_or_remount(self):
        for text in (self.mount_line.replace(" ro ", " rw "),
                     self.mount_line.replace("/dev/sdd ro", "/dev/sdd rw"),
                     self.mount_line * 2):
            with self.subTest(text=text), self.block_metadata():
                self.mountinfo.write_text(text)
                self.refuse_mount("existing target mount refused; no automatic unmount/remount")
                self.power.assert_not_called()

    def test_existing_readonly_mount_record_change_is_rejected(self):
        original = lab_device._read_only_target_volume
        calls = 0

        def changed(device):
            nonlocal calls
            mounted = original(device)
            calls += 1
            if calls == 1:
                self.mountinfo.write_text(self.mount_line.replace("1 0 ", "2 0 "))
            return mounted

        with self.block_metadata(), mock.patch.object(
                lab_device, "_read_only_target_volume", side_effect=changed):
            self.refuse_mount("mount records changed")
        self.power.assert_not_called()

    def test_mount_requires_already_boot_msc_without_entry_or_reset(self):
        (self.node / "idProduct").write_text("8045")
        self.refuse_mount("not bootloader")
        (self.node / "idProduct").write_text("0045")
        (self.msc / "bInterfaceClass").write_text("02")
        self.refuse_mount("own MSC")
        self.power.assert_not_called()

    def test_mount_refuses_missing_or_multiple_target_block_devices(self):
        link = self.block_root / "8:48"
        link.unlink()
        self.refuse_mount("block device, found 0")
        link.symlink_to(self.block)
        extra = self.msc / "block/sde"
        extra.mkdir()
        (self.block_root / "8:64").symlink_to(extra)
        self.refuse_mount("block device, found 2")
        self.power.assert_not_called()

    def test_mount_does_not_read_other_block_devices_uevent_or_payload(self):
        foreign = self.root / "foreign-block"
        foreign.mkdir()
        (foreign / "uevent").write_text("SECRET_OTHER_DEVICE")
        (self.block_root / "8:64").symlink_to(foreign)
        read_text = Path.read_text

        def bounded(path, *args, **kwargs):
            if foreign == path or foreign in path.parents:
                raise AssertionError("other block device contents must not be inspected")
            return read_text(path, *args, **kwargs)

        with self.block_metadata(), mock.patch.object(
                Path, "read_text", autospec=True, side_effect=bounded):
            self.assertEqual(self.mount_target(), str(self.volume))
        self.power.assert_not_called()

    def test_mount_refuses_regular_symlink_or_mismatched_block_device_path(self):
        self.refuse_mount("real matching block node")
        with self.block_metadata(rdev=lab_device.os.makedev(8, 99)):
            self.refuse_mount("real matching block node")
        self.disk.unlink()
        self.disk.symlink_to(self.tty)
        self.refuse_mount("real matching block node")
        self.power.assert_not_called()

    def test_mount_refuses_partition_unsafe_name_or_malformed_target_uevent(self):
        with self.block_metadata():
            for text in ("DEVNAME=../sdd\nDEVTYPE=disk\n",
                         "DEVNAME=sdd\nDEVTYPE=partition\n",
                         "DEVNAME=sdd\nDEVNAME=sdd\nDEVTYPE=disk\n"):
                with self.subTest(text=text):
                    (self.block / "uevent").write_text(text)
                    self.refuse_mount("safe kernel|malformed target block")
            (self.block / "uevent").write_text("DEVNAME=sdd\nDEVTYPE=disk\n")
            (self.block / "partition").write_text("1")
            self.refuse_mount("whole USB disk")
        self.power.assert_not_called()

    def test_mount_rechecks_block_identity_and_readonly_result_without_remediation(self):
        for outcome in ("rw", "replace"):
            self.mountinfo.write_text("")
            self.power.reset_mock()

            def changed(command, timeout):
                self.mountinfo.write_text(self.mount_line.replace(" ro ", " rw ")
                                          if outcome == "rw" else self.mount_line)
                if outcome == "replace":
                    self.disk.rename(self.root / "old-disk")
                    self.disk.touch()
                return 0, "mounted"

            self.power.side_effect = changed
            with self.subTest(outcome=outcome), self.block_metadata():
                self.refuse_mount("read-only|identity changed")
                self.power.assert_called_once_with(
                    ["udisksctl", "mount", "--block-device", str(self.disk), "--options", "ro"], 3.0)

    def test_mount_nonzero_and_timeout_have_no_retry_or_power_action(self):
        self.mountinfo.write_text("")
        self.power.side_effect = None
        for rc in (1, 124):
            self.power.reset_mock()
            self.power.return_value = rc, "failed"
            with self.subTest(rc=rc), self.block_metadata():
                self.refuse_mount(f"exit {rc}.*no retry or remount")
                self.power.assert_called_once_with(
                    ["udisksctl", "mount", "--block-device", str(self.disk), "--options", "ro"], 3.0)

    def test_mount_role_serial_and_timeout_guards_precede_discovery(self):
        for changes in ({"role": "client"}, {"timeout": 0}, {"timeout": float("inf")}):
            args = self.args()
            vars(args).update(changes)
            with self.subTest(changes=changes), mock.patch.object(lab_device, "discover") as discover:
                with self.assertRaisesRegex(SystemExit, "target role only|finite and positive"):
                    lab_device.cmd_mount_commission_uf2(args)
                discover.assert_not_called()
        with mock.patch.dict(lab_device.os.environ, {"MESHCORE_LAB_TARGET_SERIAL": "3BE94917B92DC5E9"}), \
                mock.patch.object(lab_device, "discover") as discover:
            self.refuse_mount("literal approved")
            discover.assert_not_called()
        self.power.assert_not_called()

    def test_mount_cli_is_target_only_and_cannot_request_rw_reset_or_remount(self):
        with mock.patch.object(sys, "argv", ["lab_device.py", "mount-commission-uf2", "target"]), \
                mock.patch.object(lab_device, "cmd_mount_commission_uf2", return_value=0) as mounted:
            self.assertEqual(lab_device.main(), 0)
            self.assertEqual(mounted.call_args.args[0].timeout, 30.0)
        for arguments in (["client"], ["target", "--options", "rw"], ["target", "--remount"],
                          ["target", "--reset"], ["target", "--mode", "app"]):
            with self.subTest(arguments=arguments), \
                    mock.patch.object(sys, "argv", ["lab_device.py", "mount-commission-uf2", *arguments]), \
                    mock.patch.object(lab_device, "resolve") as resolve, mock.patch("sys.stderr"):
                with self.assertRaises(SystemExit):
                    lab_device.main()
                resolve.assert_not_called()


class ClientCommissioningTests(unittest.TestCase):
    write_package = CommissioningTests.write_package
    uf2_block = CommissioningTests.uf2_block
    write_current = CommissioningTests.write_current
    block_metadata = CommissioningTests.block_metadata

    def setUp(self):
        CommissioningTests.setUp(self)
        self.serial = "4186AE911D94CDB1"
        (self.node / "serial").write_text(self.serial)
        new_port = self.by_id / f"usb-Sense_{self.serial}-if00"
        self.port.rename(new_port)
        self.port = new_port
        self.stack.enter_context(mock.patch.object(package_pair, "CLIENT_APP_BYTES", len(self.prefix)))
        self.stack.enter_context(mock.patch.object(
            package_pair, "CLIENT_APP_SHA256", package_pair.digest(self.prefix)))
        self.restore = self.root / "selected-ordinary.zip"
        self.write_package(self.restore, "application", self.prefix)
        self.stack.enter_context(mock.patch.object(
            package_pair, "CLIENT_APP_ZIP_SHA256", package_pair.build.sha(self.restore)))
        self.baseline = bytes(index % 251 for index in range(65536))
        self.baseline_file = self.root / "initial-slot.bin"
        self.baseline_file.write_bytes(self.baseline)
        erased = ((0x27000 + len(self.compound) + 4095) & ~4095) - 0xC4000
        slot = self.stage + b"\xff" * (erased - len(self.stage)) + self.baseline[erased:]
        with self.current.open("r+b") as stream:
            for offset in range(0, 65536, 256):
                address = 0xC4000 + offset
                stream.seek((address - 0x1000) // 256 * 512)
                stream.write(self.uf2_block(address, slot[offset:offset + 256]))
        self.info = self.volume / "INFO_UF2.TXT"
        self.stock_info = ("UF2 Bootloader 0.6.1\nDate: Nov 12 2021\n"
                           "Board-ID: Seeed_XIAO_nRF52840_Sense\n"
                           "SoftDevice: S140 version 7.3.0\n")
        self.info.write_text(self.stock_info)

    def args(self):
        return argparse.Namespace(
            role="client", timeout=3.0, preload_package=str(self.preload_package),
            restore_package=str(self.restore), pair_manifest=str(self.pair_manifest),
            package=str(self.boot_package), baseline_slot=str(self.baseline_file))

    def invoke(self, *, primary=False, args=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            command = (lab_device.cmd_client_commission_primary if primary else
                       lab_device.cmd_client_commission_compound)
            self.assertEqual(command(args or self.args()), 0)
        return output.getvalue()

    def refuse(self, pattern, *, primary=False, args=None):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaisesRegex(SystemExit, pattern):
            command = (lab_device.cmd_client_commission_primary if primary else
                       lab_device.cmd_client_commission_compound)
            command(args or self.args())
        self.dfu.assert_not_called()
        self.touch.assert_not_called()
        self.wait.assert_not_called()
        self.power.assert_not_called()

    def test_preload_two_app_only_transfers_and_two_app_waits_are_not_installation_proof(self):
        events = []
        (self.node / "idProduct").write_text("8044")

        def touch(port):
            self.assertEqual(port, self.port)
            events.append("touch")
            (self.node / "idProduct").write_text("0045")

        def completed(command, **kwargs):
            package = Path(command[5])
            self.assertEqual(command[7], str(self.port))
            self.assertIn(package, (self.preload_package, self.restore))
            raw, _ = package_pair.package_payload(package, "application")
            self.assertEqual(raw, self.compound if package == self.preload_package else self.prefix)
            events.append(package.name)
            return argparse.Namespace(returncode=0, stdout=b"Device programmed.\n", stderr=b"")

        def app_ready(role, mode, timeout):
            self.assertEqual((role, timeout), ("client", 3.0))
            if mode == lab_device.MODE_BOOT:
                events.append("boot")
                return lab_device.resolve(role, mode)
            events.append("app")
            (self.node / "idProduct").write_text("8044")
            return lab_device.resolve("client", lab_device.MODE_APP)

        self.touch.side_effect = touch
        self.dfu.side_effect = completed
        self.wait.side_effect = app_ready
        output = self.invoke()
        self.assertEqual(events, ["touch", "boot", "compound.zip", "app",
                                  "touch", "boot", "selected-ordinary.zip", "app"])
        self.assertEqual(self.dfu.call_count, 2)
        self.assertIn("installed bytes/SDK extent not yet verified", output)
        self.power.assert_not_called()
        self.verified_pair.assert_called_once_with(self.pair, client41=True)

    def test_both_packages_validate_before_any_device_access(self):
        self.restore.write_bytes(self.restore.read_bytes() + b"changed")
        with mock.patch.object(lab_device, "resolve") as resolve:
            self.refuse("immutable approved client41")
            resolve.assert_not_called()
        self.write_package(self.restore, "application", self.prefix)
        for raw in (self.compound[:-4], self.compound[:-1] + b"\x54"):
            self.write_package(self.preload_package, "application", raw)
            with mock.patch.object(lab_device, "resolve") as resolve:
                self.refuse("exact matched")
                resolve.assert_not_called()

    def test_client_role_serial_and_old_target_commands_remain_separate_authorities(self):
        for role in ("target", "pine", "other"):
            args = self.args()
            args.role = role
            with mock.patch.object(lab_device, "discover") as discover:
                self.refuse("client role only", args=args)
                discover.assert_not_called()
        for serial in ("77CD44653A967172", "49C5BAF21EEF44A1", "3BE94917B92DC5E9", "other"):
            with mock.patch.dict(lab_device.os.environ, {"MESHCORE_LAB_CLIENT_SERIAL": serial}), \
                    mock.patch.object(lab_device, "discover") as discover:
                self.refuse("literal approved|protected")
                discover.assert_not_called()
        for command in (lab_device.cmd_commission_compound, lab_device.cmd_commission_primary,
                        lab_device.cmd_mount_commission_uf2):
            with self.assertRaisesRegex(SystemExit, "target role only"):
                command(self.args())
        self.dfu.assert_not_called()
        self.touch.assert_not_called()

    def test_client_wrong_board_role_bsp_fail_offline_before_device_access(self):
        self.verified_pair.side_effect = self.real_verify_pair
        header = dict(vendor_pin=package_pair.build.PIN, vendor_release=package_pair.build.RELEASE,
                      actual_vendor_bsp="xiao_nrf52840_ble_sense", logical_board="xiao_nrf52840", role=0)
        for field, value in (("role", 1), ("actual_vendor_bsp", "xiao_nrf52840_ble"),
                             ("logical_board", "pine"), ("vendor_pin", "other")):
            self.pair_manifest.write_text(json.dumps(dict(header, **{field: value})))
            with mock.patch.object(lab_device, "resolve") as resolve:
                self.refuse("genuine pinned Sense BSP")
                resolve.assert_not_called()

    def test_primary_reads_full_compound_and_full_slot_before_one_boot_only_transfer(self):
        pread = lab_device.os.pread
        addresses, events = [], []

        def bounded(fd, count, offset):
            address = 0x1000 + offset // 512 * 256
            self.assertGreaterEqual(address, 0x27000)
            self.assertLess(address, 0xD4000)
            self.assertEqual(count, 512)
            addresses.append(address)
            events.append("read")
            return pread(fd, count, offset)

        def completed(command, **kwargs):
            self.assertEqual(command[5], str(self.boot_package))
            raw, _ = package_pair.package_payload(Path(command[5]), "bootloader")
            self.assertEqual(raw, self.primary)
            self.assertEqual(len(raw), 40960)
            events.append("boot")
            return argparse.Namespace(returncode=0, stdout=b"Device programmed.\n", stderr=b"")

        self.dfu.side_effect = completed
        with mock.patch.object(lab_device.os, "pread", side_effect=bounded), \
                mock.patch.object(lab_device, "cmd_bootloader_port",
                                  side_effect=AssertionError("primary must not touch")):
            output = self.invoke(primary=True)
        self.assertEqual(addresses[:len(range(0x27000, 0x27000 + len(self.compound), 256))],
                         list(range(0x27000, 0x27000 + len(self.compound), 256)))
        self.assertEqual(addresses[-256:], list(range(0xC4000, 0xD4000, 256)))
        self.assertEqual(events[-1], "boot")
        self.assertEqual(events.count("boot"), 1)
        self.assertIn("full64KiB", output)
        self.assertIn("installed primary SHA unverified", output)
        self.assertIn("27000..31000", output)
        self.touch.assert_not_called()
        self.wait.assert_not_called()
        self.power.assert_not_called()

    def test_actual_baseline_is_required_before_even_device_access(self):
        for size in (0, 65535, 65537):
            self.baseline_file.write_bytes(b"\xff" * size)
            with mock.patch.object(lab_device, "resolve") as resolve:
                self.refuse("actual full 64KiB", primary=True)
                resolve.assert_not_called()

    def test_primary_slot_ff_pad_and_unmodified_tail_are_both_checked(self):
        for address in (0xC805C, 0xC9000, 0xD3FFF):
            offset = (address - 0x1000) // 256 * 512 + 32 + address % 256
            with self.current.open("r+b") as stream:
                stream.seek(offset)
                old = stream.read(1)
                stream.seek(offset)
                stream.write(bytes([old[0] ^ 1]))
            self.refuse("slot/baseline", primary=True)
            with self.current.open("r+b") as stream:
                stream.seek(offset)
                stream.write(old)

    def test_positive_stock_profile_is_exact_and_not_modern_loader_info(self):
        for text in (self.stock_info.replace("0.6.1", "0.9.2"),
                     self.stock_info.replace("7.3.0", "7.0.0"),
                     self.stock_info.replace("_Sense", ""),
                     self.stock_info.replace("Nov 12 2021", "May 21 2026")):
            self.info.write_text(text)
            self.refuse("stock bootloader|exact observed", primary=True)

    def test_non_sense_boot_or_wrong_identity_msc_mount_refuses_primary(self):
        for field, value in (("idProduct", "0044"), ("serial", "77CD44653A967172")):
            old = (self.node / field).read_text()
            (self.node / field).write_text(value)
            self.refuse("exact Sense|not attached", primary=True)
            (self.node / field).write_text(old)
        (self.msc / "bInterfaceClass").write_text("02")
        self.refuse("own MSC", primary=True)
        (self.msc / "bInterfaceClass").write_text("08")
        for text in ("", self.mount_line.replace(" ro ", " rw "),
                     self.mount_line.replace("8:48 / ", "8:48 /subtree ")):
            self.mountinfo.write_text(text)
            self.refuse("ancestry-matched|read-only", primary=True)

    def test_bad_boot_class_geometry_or_init_never_reaches_current_or_transport(self):
        for kind, raw, init in (("application", self.primary, {}),
                                ("bootloader", self.primary[:-4], {}),
                                ("bootloader", self.primary, {"application_version": 1})):
            self.write_package(self.boot_package, kind, raw, init_changes=init)
            with mock.patch.object(lab_device, "resolve") as resolve:
                self.refuse("bootloader-only|matching RAW|standard init", primary=True)
                resolve.assert_not_called()

    def test_second_transport_failure_stops_after_first_app_wait_without_retry(self):
        def app_ready(role, mode, timeout):
            if mode == lab_device.MODE_APP:
                (self.node / "idProduct").write_text("8044")
            return lab_device.resolve(role, mode)

        self.wait.side_effect = app_ready
        self.touch.side_effect = lambda port: (self.node / "idProduct").write_text("0045")
        self.dfu.side_effect = [argparse.Namespace(returncode=0, stdout=b"Device programmed.\n", stderr=b""),
                               argparse.Namespace(returncode=0, stdout=b"Failed to upgrade target.\n", stderr=b"")]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaisesRegex(SystemExit, "transport failure despite exit 0"):
            lab_device.cmd_client_commission_compound(self.args())
        self.assertEqual(self.dfu.call_count, 2)
        self.assertEqual(self.wait.call_args_list, [
            mock.call("client", lab_device.MODE_APP, 3.0),
            mock.call("client", lab_device.MODE_BOOT, 3.0)])
        self.power.assert_not_called()

    def test_first_transport_failure_does_not_restore_wait_or_retry(self):
        for rc, output in ((1, b"send_init_packet failed\n"),
                           (0, b"Failed to upgrade target.\n"), (0, b"ACK\n")):
            self.dfu.reset_mock()
            self.dfu.return_value = argparse.Namespace(returncode=rc, stdout=output, stderr=b"")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaisesRegex(SystemExit, "nrfutil|transport|completion"):
                lab_device.cmd_client_commission_compound(self.args())
            self.dfu.assert_called_once()
            self.assertEqual(self.dfu.call_args.args[0][5], str(self.preload_package))
            self.wait.assert_not_called()
            self.touch.assert_not_called()
            self.power.assert_not_called()

    def test_literal_client_mount_reuses_ro_or_requests_only_one_initial_ro_mount(self):
        with self.block_metadata(), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(lab_device.cmd_mount_client_commission_uf2(self.args()), 0)
        self.power.assert_not_called()
        self.mountinfo.write_text("")

        def mounted(command, timeout):
            self.assertEqual(command, ["udisksctl", "mount", "--block-device",
                                       str(self.disk), "--options", "ro"])
            self.assertEqual(timeout, 3.0)
            self.mountinfo.write_text(self.mount_line)
            return 0, "mounted"

        self.power.side_effect = mounted
        with self.block_metadata(), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(lab_device.cmd_mount_client_commission_uf2(self.args()), 0)
        self.power.assert_called_once()
        self.dfu.assert_not_called()
        self.touch.assert_not_called()
        self.wait.assert_not_called()

    def test_client_mount_rejects_rw_without_unmount_or_remount(self):
        self.mountinfo.write_text(self.mount_line.replace(" ro ", " rw "))
        with self.block_metadata(), self.assertRaisesRegex(
                SystemExit, "existing target mount refused; no automatic unmount/remount"):
            lab_device.cmd_mount_client_commission_uf2(self.args())
        self.power.assert_not_called()
        self.dfu.assert_not_called()
        self.touch.assert_not_called()

    def test_client_cli_cannot_reuse_target_role_or_request_other_control_actions(self):
        for command in ("commission-client-compound", "commission-client-primary",
                        "mount-client-commission-uf2"):
            for extra in (["target"], ["client", "--reset"], ["client", "--retry"],
                          ["client", "--options", "rw"]):
                with mock.patch.object(sys, "argv", ["lab_device.py", command, *extra]), \
                        mock.patch.object(lab_device, "resolve") as resolve, mock.patch("sys.stderr"):
                    with self.assertRaises(SystemExit):
                        lab_device.main()
                    resolve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
