#!/usr/bin/env python3
"""Offline host-to-native bridge; never opens a serial port or touches a device.

Run through make ota-lab-cache with OTA_UPLOAD_COMMAND pointing here. The real
host uploader and signing protocol emit cache packets; the ESP product test
must replay every packet through production storage before claiming READY.
--qualified-build additionally proves that the exact generated app/bootloader
implement the trial contract. Omit it for stock-image capacity testing only.
Replay with ESP32_OTA_IMAGE_PATH_FIXTURE=<output> make test-ota-native
OTA_TEST_FILTER=test_lora_ota_esp32, using an isolated PLATFORMIO_BUILD_DIR.
"""

import argparse
import hashlib
import io
import os
import re
from pathlib import Path
import struct
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import ota_uploader as ota

sys.path.insert(0, str(ROOT / "bootloader/xiao_nrf52840_ota/tools"))
from xiao_ota_descriptor import build_descriptor, INSTALL_MAX_SIZE, ESP_INSTALL_MAX_SIZE

sys.path.insert(0, str(Path(os.environ.get("PLATFORMIO_CORE_DIR", Path.home() / ".platformio"))
                      / "packages/tool-esptoolpy"))
from esptool.bin_image import ELFFile, LoadFirmwareImage

SEED = bytes([0x17, 0x29, 0x53, 0x81]) + bytes(28)


class OfflineSignerAndCapture:
    name = "offline-test-signer"

    def __init__(self, canonical, image):
        self.canonical, self.image = canonical, image
        self.key = Ed25519PrivateKey.from_private_bytes(SEED)
        self.owner = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.signed_message = None
        self.frames, self.pending = [], []
        self.received = 0
        self.total = (len(image) + ota.BLOCK_BYTES - 1) // ota.BLOCK_BYTES
        self.phase = ota.Phase.RECEIVING

    def command(self, payload, **options):
        if payload == bytes([ota.lab.CMD_SIGN_START]):
            return bytes([ota.lab.RESP_SIGN_START, 0]) + struct.pack("<I", 256)
        if payload == bytes([ota.lab.CMD_SIGN_DATA]) + self.canonical:
            self.signed_message = payload[1:]
            return bytes([ota.lab.RESP_OK])
        if payload == bytes([ota.lab.CMD_SIGN_FINISH]) and self.signed_message == self.canonical:
            return bytes([ota.lab.RESP_SIGNATURE]) + self.key.sign(self.signed_message)
        raise AssertionError("unexpected signing-protocol command")

    def poll(self, timeout=0):
        pass

    def take_pending(self, codes):
        selected = [entry for entry in self.pending if entry[1][0] in codes]
        self.pending = [entry for entry in self.pending if entry[1][0] not in codes]
        return selected

    def write_frame(self, payload):
        assert payload[0] == ota.lab.CMD_OTA_CONTROL
        op = ota.Op(payload[1])
        if op == ota.Op.CACHE_BEGIN:
            assert len(payload) == 158 and payload[2] == 0
            assert payload[3:35] == self.owner and payload[35:94] == self.canonical
            self.key.public_key().verify(payload[94:], self.canonical)
        elif op == ota.Op.CACHE_PUT:
            index, size = struct.unpack_from(">HB", payload, 2)
            assert index == self.received and size == len(payload) - 5
            assert payload[5:] == self.image[index * ota.BLOCK_BYTES:(index + 1) * ota.BLOCK_BYTES]
            self.received += 1
        elif op == ota.Op.CACHE_SEAL:
            assert len(payload) == 2 and self.received == self.total
            self.phase = ota.Phase.CACHE_SEALED
        elif op != ota.Op.STATUS:
            raise AssertionError("offline cache test emitted an install or RF command")
        if op != ota.Op.STATUS:
            self.frames.append(payload)
        reply = (bytes([ota.REPLY_CODE, ota.ABI_VERSION, op, ota.Result.OK, self.phase, ota.SNAPSHOT_VALID])
                 + ota.LOCAL_TARGET + hashlib.sha256(self.canonical).digest()
                 + struct.pack(">HHIIII", self.received, self.total,
                               struct.unpack_from(">I", self.canonical, 45)[0], 0, 0, 1))
        self.pending.append((time.monotonic(), reply))


class OfflineEvidence:
    def log(self, event, **fields):
        assert event == "ota_reply"


def qualify_build(build, image, role):
    """Tie disassembled vendor rollback code to the generated bootloader bytes."""
    core = Path(os.environ.get("PLATFORMIO_CORE_DIR", Path.home() / ".platformio"))
    framework = core / "packages/framework-arduinoespressif32"
    toolchain = core / "packages/toolchain-xtensa-esp32s3/bin"
    nm = str(toolchain / "xtensa-esp32s3-elf-nm")
    objdump = str(toolchain / "xtensa-esp32s3-elf-objdump")
    vendor_elf = framework / "tools/sdk/esp32s3/bin/bootloader_qio_80m.elf"
    app_elf = build / "firmware.elf"
    boot_bin = build / "bootloader.bin"
    assert (build / "firmware.bin").read_bytes() == image, "input is not the exact qualified compiled app"
    expected_env = "Xiao_S3_WIO_companion_radio_usb" if role == 0 else "Xiao_S3_WIO_repeater_ota_usb"
    assert build.name == expected_env, "manifest role does not match the qualified build profile"
    sys.path.insert(0, str(framework / "tools"))
    from gen_esp32part import PartitionTable
    table = PartitionTable.from_binary((build / "partitions.bin").read_bytes())
    table.verify()
    table.verify_size_fits(0x800000)
    expected = [
        ("nvs", 1, 2, 0x9000, 0x5000, False),
        ("otadata", 1, 0, 0xe000, 0x2000, False),
        ("app0", 0, 0x10, 0x10000, 0x330000, False),
        ("app1", 0, 0x11, 0x340000, 0x330000, False),
        ("spiffs", 1, 0x82, 0x670000, 0x180000, False),
        ("coredump", 1, 3, 0x7f0000, 0x10000, False),
    ]
    assert sorted((p.name, p.type, p.subtype, p.offset, p.size, p.encrypted) for p in table) == sorted(expected)
    print("Actual generated partition table matches the backend's exact 8 MiB layout and protected userdata regions")

    selection = "bootloader_utility_get_selected_boot_partition"
    boot_symbols = subprocess.check_output([nm, "-S", str(vendor_elf)], text=True)
    symbol = next(line.split() for line in boot_symbols.splitlines() if line.split()[-1] == selection)
    address, size = int(symbol[0], 16), int(symbol[1], 16)
    vendor = ELFFile(str(vendor_elf))
    generated = LoadFirmwareImage("esp32s3", str(boot_bin))

    def bytes_at(segments, address, size):
        for segment in segments:
            offset = address - segment.addr
            if 0 <= offset and offset + size <= len(segment.data):
                return segment.data[offset:offset + size]
        raise AssertionError("boot selection function absent from generated bootloader")

    assert bytes_at(vendor.sections, address, size) == bytes_at(generated.segments, address, size)
    disassembly = subprocess.check_output([objdump, "-d", "--disassemble=" + selection, str(vendor_elf)], text=True)
    assert len(re.findall(r"movi\.n\s+a8,\s*4\b", disassembly)) == 2
    assert len(re.findall(r"movi\.n\s+a8,\s*1\b", disassembly)) == 1
    assert len(re.findall(r"call8.*<write_otadata>", disassembly)) == 3
    print(f"Generated bootloader contains the exact vendor NEW->PENDING_VERIFY / PENDING_VERIFY->ABORTED function: {address:#x}+{size:#x}")
    print(disassembly)
    symbols = subprocess.check_output([nm, str(app_elf)], text=True)
    assert re.search(r" T verifyRollbackLater$", symbols, re.M)
    assert re.search(r" T __wrap_nvs_flash_init$", symbols, re.M)
    sdkconfig = (framework / "tools/sdk/esp32s3/qio_opi/include/sdkconfig.h").read_text()
    assert "#define CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE 1" in sdkconfig
    assert "#define CONFIG_APP_ROLLBACK_ENABLE CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE" in sdkconfig
    init = subprocess.check_output([objdump, "-d", "--disassemble=initArduino", str(app_elf)], text=True)
    assert "call8" in init and "<verifyRollbackLater>" in init
    assert init.index("<verifyRollbackLater>") < init.index("<__wrap_nvs_flash_init>")
    print(init)
    app = ELFFile(str(app_elf))
    binary = LoadFirmwareImage("esp32s3", str(build / "firmware.bin"))
    sized_symbols = subprocess.check_output([nm, "-S", str(app_elf)], text=True)

    def app_function(name):
        symbol = next(line.split() for line in sized_symbols.splitlines() if line.split()[-1] == name)
        address, size = int(symbol[0], 16), int(symbol[1], 16)
        assert bytes_at(app.sections, address, size) == bytes_at(binary.segments, address, size)
        body = subprocess.check_output([objdump, "-d", "--disassemble=" + name, str(app_elf)], text=True)
        print(body)
        return body

    defer = app_function("verifyRollbackLater")
    assert re.search(r"movi\.n\s+a2,\s*1\b", defer) and "earlyTrialGuard" in defer
    workable = app_function("esp_ota_current_ota_is_workable")
    assert "esp_ota_check_rollback_is_possible" in workable
    for method in ("selectBoot", "validateImage", "rollbackAndRestart", "confirmHealthy"):
        name = next(line.split()[-1] for line in symbols.splitlines()
                    if ("VendorInstallApi" in line or "VendorTrialPlatform" in line) and method in line)
        body = app_function(name)
        required = {"selectBoot": "esp_ota_set_boot_partition", "validateImage": "esp_image_verify",
                    "rollbackAndRestart": "esp_ota_mark_app_invalid_rollback_and_reboot",
                    "confirmHealthy": "esp_ota_mark_app_valid_cancel_rollback"}[method]
        assert required in body
    print(f"Qualified compiled app and prebuilt vendor bootloader; no physical acceptance: {build}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--qualified-build", type=Path)
    parser.add_argument("command", choices=("cache",))
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    image, canonical = args.image.read_bytes(), args.manifest.read_bytes()
    vendor_stream = io.BytesIO(image)
    vendor_image = LoadFirmwareImage("esp32s3", vendor_stream)
    # The loader seeks back to hash the body, leaving the stream before its digest.
    assert (vendor_stream.tell() + len(vendor_image.stored_digest) == len(image)), \
        "SDK image length does not match the complete input"
    assert vendor_image.checksum == vendor_image.calculate_checksum(), "ESP image checksum mismatch"
    assert (vendor_image.append_digest and vendor_image.stored_digest == vendor_image.calc_digest), \
        "ESP image digest mismatch"
    role = canonical[4]
    assert canonical == build_descriptor("xiao_s3_wio", role, struct.unpack_from(">I", canonical, 45)[0], image)
    assert INSTALL_MAX_SIZE == 708608 and ESP_INSTALL_MAX_SIZE == 2749824
    if args.qualified_build:
        qualify_build(args.qualified_build, image, role)
    if len(image) > INSTALL_MAX_SIZE:
        try:
            build_descriptor("xiao_nrf52840", role, 1, image)
        except SystemExit:
            pass
        else:
            raise AssertionError("nRF image cap was relaxed")
    node = OfflineSignerAndCapture(canonical, image)
    reply = ota.Uploader(node, OfflineEvidence()).cache(
        canonical, image, node.owner, time.monotonic() + 120)
    assert reply.phase == ota.Phase.CACHE_SEALED and reply.received == reply.total == node.total
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as stream:
        stream.write(b"ESPIMG1\0" + struct.pack(">I", len(image)) + image)
        for frame in node.frames:
            stream.write(struct.pack(">H", len(frame)) + frame)
    print(f"OFFLINE host: image={len(image)} blocks={node.total} role={role} sha256={hashlib.sha256(image).hexdigest()}")
    print(f"Production cache packets for native durable replay: {args.output}")


if __name__ == "__main__":
    main()
