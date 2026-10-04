#!/usr/bin/env python3
"""Build the fixed returning installer and exact OTAFIX primary, with no hardware actions."""
import argparse
import binascii
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path

PRODUCT = Path(__file__).resolve().parents[1]
ROOT = PRODUCT.parents[1]
PIN = "a62825be4733f500271c89b5ec489fd609748e97"
RELEASE = "0.9.2-OTAFIX2.3-BP1.4"
BSP = {"xiao_nrf52840": "xiao_nrf52840_ble",
       "xiao_nrf52840_sense": "xiao_nrf52840_ble_sense",
       "sensecap_solar_p1": "sensecap_solar_p1"}
TARGET = {"xiao_nrf52840": 0x584E3430, "xiao_nrf52840_sense": 0x584E3430,
          "sensecap_solar_p1": 0x53435031}
FLAGS = ["-std=c11", "-Os", "-mcpu=cortex-m4", "-mthumb", "-mfloat-abi=hard",
         "-mfpu=fpv4-sp-d16", "-ffunction-sections", "-fdata-sections",
         "-fno-strict-aliasing", "-g", "-Wall", "-Wextra", "-Werror",
         "-Wno-unused-function", "-Wno-sign-compare", "-Wno-shadow",
         "-Wno-unterminated-string-initialization", "-Wno-expansion-to-defined"]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def once(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after, 1)


def run(args, cwd, log=None):
    result = subprocess.run(list(map(str, args)), cwd=cwd, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if log:
        log.write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(result.stdout)
    return result.stdout


def symbols(elf):
    return {parts[2]: int(parts[0], 16) for line in
            run(["arm-none-eabi-nm", "-n", elf], ROOT).splitlines()
            if len(parts := line.split()) == 3 and re.fullmatch("[0-9a-fA-F]+", parts[0])}


def ihex(path):
    memory, base = {}, 0
    for line in path.read_text().splitlines():
        record = bytes.fromhex(line[1:])
        assert len(record) == record[0] + 5
        assert sum(record) & 255 == 0
        address = int.from_bytes(record[1:3], "big")
        if record[3] == 4:
            base = int.from_bytes(record[4:6], "big") << 16
        elif record[3] == 2:
            base = int.from_bytes(record[4:6], "big") << 4
        elif record[3] == 0:
            memory.update((base + address + i, value)
                          for i, value in enumerate(record[4:-1]))
    return memory


def loads(elf):
    result = []
    for line in run(["arm-none-eabi-readelf", "-lW", elf], ROOT).splitlines():
        fields = line.split()
        if fields and fields[0] == "LOAD":
            result.append(dict(zip(("offset", "vaddr", "paddr", "filesz", "memsz"),
                                   (int(v, 16) for v in fields[1:6]))))
    return result


def build_stage(out, vendor, board, role):
    folder = out / "stage2"
    folder.mkdir(exist_ok=True)
    includes = [PRODUCT / "include", PRODUCT / "src", PRODUCT / "third_party/tweetnacl",
                vendor / "lib/nrfx/mdk", vendor / "lib/nrfx", vendor / "lib/nrfx/hal",
                vendor / "src/cmsis/include", vendor / "src", vendor / "src/boards",
                vendor / "src/boards" / BSP[board],
                vendor / "lib/sdk/components/libraries/util",
                vendor / "lib/sdk/components/libraries/crc16",
                ROOT / "src/ota/trust/third_party/ed25519"]
    sd = vendor / "lib/softdevice/s140_nrf52_7.3.0/s140_nrf52_7.3.0_API/include"
    includes += [sd, sd / "nrf52"]
    flags = FLAGS + [f"-I{p}" for p in includes] + [
        "-DNRF52840_XXAA", "-DNRFX_DELAY_DWT_BASED=0",
        "-DXIAO_OTA_FIXED_STAGE2_RETURNING",
        f"-DXIAO_OTA_BOARD_TARGET=0x{TARGET[board]:08X}",
        f"-DXIAO_OTA_COMPILED_ROLE_ID={role}"]
    sources = [PRODUCT / "src" / name for name in
        ("xiao_ota_boot.c", "xiao_ota_boot_io.c", "xiao_ota_record.c",
         "xiao_ota_sha256.c", "xiao_ota_ed25519_tweetnacl.c", "stage_runtime.c", "stage_entry.S")]
    sources += [PRODUCT / "third_party/tweetnacl/tweetnacl.c",
                vendor / "lib/sdk/components/libraries/crc16/crc16.c"]
    objects = []
    for source in sources:
        obj = folder / (source.stem + ".o")
        run(["arm-none-eabi-gcc", *flags, "-c", source, "-o", obj], ROOT,
            out / "logs" / (source.stem + ".compile.log"))
        objects.append(obj)
    elf = folder / "stage2.elf"
    run(["arm-none-eabi-gcc", *FLAGS, "-nostartfiles", "-specs=nano.specs",
         "-specs=nosys.specs", "-Wl,--gc-sections,--nmagic",
         "-Wl,-T," + str(PRODUCT / "linker/stage2.ld"),
         "-Wl,-Map," + str(folder / "stage2.map"), *objects, "-lc", "-lgcc", "-o", elf],
        ROOT, out / "logs/stage2.link.log")
    sym = symbols(elf)
    assert sym["stage_entry"] == 0xC4040
    binary = folder / "stage2.bin"
    run(["arm-none-eabi-objcopy", "--gap-fill=0xff", "-O", "binary", elf, binary], ROOT)
    data = bytearray(binary.read_bytes())
    assert 36 <= len(data) <= 65536
    struct.pack_into("<II", data, 20, len(data), sym["stage_entry"] | 1)
    header = folder / "header.bin"
    header.write_bytes(data[:36])
    run(["arm-none-eabi-objcopy", "--update-section", ".pair_header=" + str(header), elf], ROOT)
    run(["arm-none-eabi-objcopy", "--gap-fill=0xff", "-O", "binary", elf, binary], ROOT)
    assert binary.read_bytes() == data
    run(["arm-none-eabi-objcopy", "-O", "ihex", elf, folder / "stage2.hex"], ROOT)
    assert struct.unpack("<9I", data[:36]) == (
        0x3253464F, 1, 36, TARGET[board], role, len(data), 0xC4041,
        0x20020000, 0x20030000)
    assert sym["__data_start__"] == 0x20020000 and sym["__bss_end__"] <= 0x20030000
    assert all(0xC4000 <= segment["paddr"] <= segment["paddr"] + segment["filesz"] <= 0xD4000
               for segment in loads(elf) if segment["filesz"])
    return {"extent": len(data), "entry": sym["stage_entry"] | 1,
            "crc32": binascii.crc32(data) & 0xFFFFFFFF}


def prepare_primary(out, tree, board, role, stage):
    custom = tree / "src/xiao_ota"
    custom.mkdir()
    for path in (PRODUCT / "include").glob("*.h"):
        shutil.copy2(path, custom / path.name)
    for path in (PRODUCT / "src").glob("*.[ch]"):
        shutil.copy2(path, custom / path.name)
    shutil.copy2(ROOT / "src/ota/platform/Nrf52FlashLayoutContract.h",
                 custom / "xiao_ota_platform_layout_contract.h")
    (custom / "pair_expected.h").write_text(
        f"static const pair_expected_t paired_stage = {{0x{TARGET[board]:08X}u, "
        f"{role}u, {stage['extent']}u, 0x{stage['entry']:08X}u, 0x{stage['crc32']:08X}u}};\n")
    key = (custom / "xiao_ota_public_key.h").read_text()
    match = re.search(r"XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES\s*\\((?:.|\n)*?)\n\n", key)
    values = bytes(int(t, 16) for t in re.findall("0x[0-9a-fA-F]{2}", match[1]))
    assert len(values) == 32
    marker = struct.pack("<IHHIIIHH32s", 0x584F4249, 1, 60, TARGET[board], role, 1, 1, 1, values)
    crc = binascii.crc32(marker) & 0xFFFFFFFF
    info = custom / "xiao_ota_boot_info.c"
    info.write_text(once(info.read_text(),
        ".crc32 = 0xFFFFFFFFu, /* XIAO_OTA_BOOT_INFO_CRC32_PLACEHOLDER: patched by prepare_upstream.py */",
        f".crc32 = UINT32_C(0x{crc:08X}),"))
    main = tree / "src/main.c"
    text = once(main.read_text(), '#include "boards.h"',
        '#include "boards.h"\n#include "pair_abi.h"\n#include "pair_expected.h"\n'
        '#include "xiao_ota_primary.h"\n#include "xiao_ota_vendor.h"\n'
        '#include "xiao_ota_vendor_sdk.h"\n#include "bootloader_settings.h"\n'
        "static bool pair_intact;\n"
        "void xiao_ota_primary_invalidate_app_grant(void) { pair_intact = false; }")
    text = text.replace("static void check_dfu_mode(void)",
                        "static void check_dfu_mode(bool pair_forced_recovery)")
    text = once(text, "  sd_mbr_command(&com);",
        "  APP_ERROR_CHECK(sd_mbr_command(&com));\n  _sd_inited = true;")
    text = once(text, "  board_init();",
        "  _sd_inited = NRF_POWER->GPREGRET == DFU_MAGIC_OTA_APPJUM;\n\n"
        "  board_init();")
    text = once(text,
        "  // SD is already Initialized in case of BOOTLOADER_DFU_OTA_MAGIC\n"
        "  _sd_inited = (gpregret == DFU_MAGIC_OTA_APPJUM);",
        "  // Preserve the entry/INIT_SD phase even when recovery changes GPREGRET.")
    primary = custom / "xiao_ota_primary.c"
    primary.write_text(once(primary.read_text(),
        "sd_softdevice_is_enabled(&enabled)",
        "xiao_ota_vendor_sd_is_enabled(&enabled)"))
    text = once(text, "  bootloader_init();",
        "  bootloader_init();\n  uint32_t pair_init = xiao_ota_primary_init();")
    text = once(text, "    bootloader_dfu_sd_update_continue();\n"
        "    bootloader_dfu_sd_update_finalize();",
        "    uint32_t pending_error = pair_init;\n"
        "    if (pending_error == NRF_SUCCESS) pending_error = bootloader_dfu_sd_update_continue();\n"
        "    if (pending_error == NRF_SUCCESS) pending_error = bootloader_dfu_sd_update_finalize();\n"
        "    if (pending_error != NRF_SUCCESS) {\n"
        "      pair_init = pending_error;\n"
        "      NRF_POWER->GPREGRET = DFU_MAGIC_UF2_RESET;\n"
        "    }")
    text = once(text, "  // Check all inputs and enter DFU if needed",
        "  uint32_t const prior_marker = *dbl_reset_mem;\n"
        "  bool const pin_reset = (NRF_POWER->RESETREAS & POWER_RESETREAS_RESETPIN_Msk) != 0;\n"
        "  bool const escape = pair_explicit_escape(NRF_POWER->GPREGRET, pin_reset,\n"
        "                                          prior_marker, button_pressed(BUTTON_DFU));\n"
        "  bool const protected = pair_lock_protection();\n"
        "  pair_intact = false;\n"
        "  if (!escape && protected && pair_init == NRF_SUCCESS && !bootloader_dfu_sd_in_progress()) {\n"
        "    if (pin_reset) *dbl_reset_mem = DFU_DBL_RESET_MAGIC;\n"
        "    pair_intact = pair_call(&paired_stage) == PAIR_APP_INTACT;\n"
        "    *dbl_reset_mem = prior_marker;\n"
        "  }\n"
        "  bool const forced = (!escape && !pair_intact) || pair_init != NRF_SUCCESS;\n"
        "  if (forced) NRF_POWER->GPREGRET = DFU_MAGIC_UF2_RESET;\n\n"
        "  // Check all inputs and enter DFU if needed")
    text = once(text, "  check_dfu_mode();", "  check_dfu_mode(forced);")
    text = once(text, "  if (bootloader_app_is_valid() && !bootloader_dfu_sd_in_progress()) {",
        "  bootloader_settings_t const *sdk;\n  bootloader_util_settings_get(&sdk);\n"
        "  if (pair_app_gate(pair_intact, sdk->bank_0 == BANK_VALID_APP,\n"
        "                    bootloader_app_is_valid(), bootloader_dfu_sd_in_progress())) {")
    text = once(text,
        "  NRF_POWER->GPREGRET = 0xA8; // No application was loaded, reset the system with the OTA DFU update",
        "  if (*dbl_reset_mem != DFU_DBL_RESET_APP) *dbl_reset_mem = 0;\n"
        "  NRF_POWER->GPREGRET = 0;")
    text = once(text, "    // Initiate an update of the firmware.",
        "    xiao_ota_primary_invalidate_app_grant();\n"
        "    uint32_t dfu_error;\n\n"
        "    // Initiate an update of the firmware.")
    text = once(text, "  if (APP_ASKS_FOR_SINGLE_TAP_RESET() || uf2_dfu || serial_only_dfu) {",
        "  if (!pair_forced_recovery &&\n"
        "      (APP_ASKS_FOR_SINGLE_TAP_RESET() || uf2_dfu || serial_only_dfu)) {")
    text = once(text, "      bootloader_dfu_start(_ota_dfu, 3000, true);",
                "      dfu_error = bootloader_dfu_start(_ota_dfu, 3000, true);")
    text = once(text, "      bootloader_dfu_start(_ota_dfu, 0, false);",
                "      dfu_error = bootloader_dfu_start(_ota_dfu, 0, false);")
    text = once(text, "    if (_ota_dfu) {\n      sd_softdevice_disable();",
        "    if (dfu_error == NRF_SUCCESS) (void)xiao_ota_vendor_recovery_complete();\n\n"
        "    if (_ota_dfu) {\n      sd_softdevice_disable();")
    main.write_text(text)
    linker = tree / "linker/nrf52840.ld"
    text = linker.read_text().replace("LENGTH = 0x20040000-0x20008000",
                                     "LENGTH = 0x20020000-0x20008000")
    for name, region in (("uicrBootStartAddress", "UICR_BOOTLOADER"),
                         ("uicrMbrParamsPageAddress", "UICR_MBR_PARAM_PAGE")):
        text, count = re.subn(rf"\.{name}\s*:\s*\{{.*?\}}\s*>\s*{region}",
            f"/DISCARD/ : {{ *(.{name}) }}", text, count=1, flags=re.S)
        assert count == 1
    text = once(text, "  /* Place the bootloader settings page in flash. */",
        "  .xiao_ota_boot_info 0xFDC00 : { KEEP(*(.xiao_ota_boot_info)) } > BOOTLOADER_CONFIG\n\n"
        "  /* Place the bootloader settings page in flash. */")
    text += '\nASSERT(ADDR(.bootloaderConfig) + SIZEOF(.bootloaderConfig) <= 0xFDC00, "CF2 overlaps marker")\n'
    linker.write_text(text)
    common = tree / "linker/nrf_common.ld"
    text = common.read_text().replace("__StackTop = ORIGIN(RAM) + LENGTH(RAM);",
                                      "__StackTop = 0x20040000;")
    text = text.replace("__StackLimit = __StackTop - SIZEOF(.stack_dummy);",
                        "__StackLimit = 0x20030000;")
    text += '\nASSERT(__bss_end__ <= 0x20020000, "primary overlaps installer RAM")\n'
    common.write_text(text)
    make = tree / "Makefile"
    sources = ("pair_gate.c", "pair_protect.c", "xiao_ota_primary.c", "xiao_ota_vendor_sdk.c",
               "xiao_ota_boot.c", "xiao_ota_boot_io.c", "xiao_ota_boot_info.c",
               "xiao_ota_record.c")
    text = ("C_SRC += " + " ".join("src/xiao_ota/" + n for n in sources) +
            "\nIPATH += src/xiao_ota " + str(ROOT / "src/ota/trust/third_party/ed25519") + "\n")
    text += make.read_text()
    text += (f"\nCFLAGS += -DXIAO_OTA_BOARD_TARGET=0x{TARGET[board]:08X} "
             f"-DXIAO_OTA_COMPILED_ROLE_ID={role}\n"
             "CFLAGS += -Wno-unused-function -Wno-sign-compare -Wno-shadow\n"
             "LDFLAGS += -Wl,--nmagic,--defsym=__meshcore_vendor_bootloader_version=0x902\n")
    make.write_text(text)


def test_pair(out, vendor, board, role):
    folder = out / "tests"
    folder.mkdir(exist_ok=True)
    generated = (out / "primary-source/src/main.c").read_text()
    start = generated.index("static void mbr_init_sd(void)")
    end = generated.index("static uint32_t ble_stack_init", start)
    (folder / "generated_primary.inc").write_text(
        generated[start:end].replace("int main(void)", "int vendor_main(void)", 1))
    grant = re.search(r"static bool pair_intact;\nvoid xiao_ota_primary_invalidate_app_grant\(void\) \{[^}]*\}", generated)
    assert grant
    (folder / "primary_grant.inc").write_text(grant[0] + "\n")
    shutil.copy2(out / "primary-source/src/xiao_ota/pair_expected.h", folder / "pair_expected.h")
    flags = ["-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-function", "-Wno-sign-compare",
             "-Wno-unterminated-string-initialization",
             "-Wno-pointer-to-int-cast", "-Wno-int-to-pointer-cast", "-fno-pie", "-no-pie",
             "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
             "-DXIAO_OTA_COMPILED_ROLE_ID=" + str(role),
             f"-DXIAO_OTA_BOARD_TARGET=0x{TARGET[board]:08X}"]
    includes = [PRODUCT / "tests/qspi_mock", PRODUCT / "include", PRODUCT / "src",
                PRODUCT / "third_party/tweetnacl", PRODUCT / "tests", vendor / "lib/nrfx/mdk", folder,
                ROOT / "src/ota/trust/third_party/ed25519"]
    flags += [f"-I{path}" for path in includes]
    sources = [PRODUCT / "src" / name for name in
               ("xiao_ota_boot.c", "xiao_ota_boot_io.c", "xiao_ota_record.c",
                "xiao_ota_sha256.c", "xiao_ota_ed25519_tweetnacl.c", "stage_runtime.c",
                "pair_protect.c")]
    sources += [PRODUCT / "third_party/tweetnacl/tweetnacl.c",
                PRODUCT / "tests/crc16_host.c",
                PRODUCT / "tests/pair_adapter_bridge.c", PRODUCT / "tests/test_pair_primary.c"]
    gate = folder / "pair_gate.o"
    run(["cc", *flags, "-Dpair_call=pair_arm_call", "-c", PRODUCT / "src/pair_gate.c",
         "-o", gate], ROOT, out / "logs/pair_gate.native.compile.log")
    sources.append(gate)
    for negative in (False, True):
        executable = folder / ("legacy-reset-negative" if negative else "selected-pair")
        define = "-DPAIR_LEGACY_NEGATIVE" if negative else "-DXIAO_OTA_FIXED_STAGE2_RETURNING"
        run(["cc", *flags, define, *sources, "-o", executable], ROOT,
            out / "logs" / (executable.name + ".compile.log"))
        result = subprocess.run([str(executable), str(out / "stage2/stage2.bin")], cwd=ROOT,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (out / "logs" / (executable.name + ".test.log")).write_text(result.stdout)
        if negative:
            assert result.returncode != 0 and "dfu_calls == 1" in result.stdout, result.stdout
        else:
            assert result.returncode == 0, result.stdout
            print(result.stdout, end="")
    print("Old production reset-GP57 adapter compiles and assertion-fails: PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--board", choices=BSP, required=True)
    parser.add_argument("--role", type=int, choices=(0, 1), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--vendor", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(ROOT / ".tmp/ota-boot-builds")
    provenance = json.loads(args.provenance.read_text())
    assert provenance["commit"] == PIN and provenance["verified_git_blobs"]
    vendor = args.vendor.resolve()
    for name, fingerprint in provenance["source"].items():
        assert sha(vendor / name) == fingerprint, name
    out.mkdir(parents=True, exist_ok=True)
    (out / "logs").mkdir(exist_ok=True)
    if args.test:
        test_pair(out, vendor, args.board, args.role)
        return
    stage = build_stage(out, vendor, args.board, args.role)
    tree = out / "primary-source"
    sentinel = out / ".meshcore-pair-owner"
    if tree.exists():
        assert sentinel.read_text() == PIN
        shutil.rmtree(tree)
    sentinel.write_text(PIN)
    shutil.copytree(vendor, tree, ignore=shutil.ignore_patterns(".git", "_build", "_bin"))
    patch = PRODUCT / "patches/otafix-preserving.patch"
    assert sha(patch) == "97c539f9216bf2569937b150dfaff743a5799aa8668c3222fe16fe5b36718bb0"
    run(["git", "apply", "--check", patch], tree)
    run(["git", "apply", patch], tree)
    prepare_primary(out, tree, args.board, args.role, stage)
    bsp = BSP[args.board]
    name = f"{bsp}_bootloader-{RELEASE}"
    folder = "_build/build-" + bsp
    run(["make", "--no-print-directory", "-j2", "BOARD=" + bsp, "GIT_VERSION=" + RELEASE,
         "GIT_SUBMODULE_VERSIONS=pinned", folder + "/" + name + ".out",
         folder + "/" + name + ".hex"], tree, out / "logs/primary.build.log")
    elf, hexfile = out / "primary.elf", out / "primary.hex"
    shutil.copy2(tree / folder / (name + ".out"), elf)
    shutil.copy2(tree / folder / (name + ".hex"), hexfile)
    shutil.copy2(tree / folder / (name + ".out.map"), out / "primary.map")
    memory = ihex(hexfile)
    assert memory and all(0xF4000 <= address < 0xFE000 for address in memory)
    primary_memory = memory
    raw = bytes(primary_memory.get(a, 255) for a in range(0xF4000, 0xFE000))
    assert len(raw) == 0xA000 and not len(raw) & 3
    (out / "primary-boot-only.bin").write_bytes(raw)
    segments = loads(elf)
    assert all(0xF4000 <= s["paddr"] <= s["paddr"] + s["filesz"] <= 0xFE000
               for s in segments if s["filesz"])
    code_load = sum(s["filesz"] for s in segments if 0xF4000 <= s["paddr"] < 0xFD800)
    assert code_load <= 38912, code_load
    assert all(s["paddr"] + s["filesz"] <= 0xFD800 for s in segments
               if 0xF4000 <= s["paddr"] < 0xFD800)
    syms = symbols(elf)
    assert syms["__bss_end__"] <= 0x20020000 and syms["__StackLimit"] == 0x20030000
    assert syms["__StackTop"] == 0x20040000
    assert syms["__data_start__"] == 0x20008000
    assert syms["__meshcore_vendor_bootloader_version"] == 0x902
    assert syms["bootloaderConfig"] == 0xFD800 and syms["g_xiao_ota_boot_info"] == 0xFDC00
    assert not any(name in syms for name in (
        "stage_run", "xiao_ota_boot_process", "xiao_ota_boot_process_io",
        "hw_qspi_init", "hw_force_recovery", "crypto_sign_ed25519_tweet_open"))
    marker = raw[0x9C00:0x9C3C]
    marker_fields = struct.unpack("<IHHIIIHH32sI", marker)
    assert marker_fields[:8] == (0x584F4249, 1, 60, TARGET[args.board], args.role, 1, 1, 1)
    assert marker_fields[-1] == binascii.crc32(marker[:-4]) & 0xFFFFFFFF
    source_fingerprints = {str(p.relative_to(PRODUCT)): sha(p) for p in PRODUCT.rglob("*")
                           if p.is_file() and "__pycache__" not in p.parts}
    source_fingerprints["canonical-layout"] = sha(ROOT / "src/ota/platform/Nrf52FlashLayoutContract.h")
    source_release = hashlib.sha256(json.dumps(
        {"vendor_pin": PIN, "source": source_fingerprints}, sort_keys=True).encode()).hexdigest()
    metadata = {
        "architecture": "fixed-otafix-primary-secondary", "vendor_pin": PIN,
        "vendor_release": RELEASE,
        "logical_board": "sensecap_solar_p1" if args.board == "sensecap_solar_p1" else "xiao_nrf52840",
        "board_profile": args.board, "currentSourceRelease": source_release,
        "actual_vendor_bsp": bsp, "role": args.role, "primary_load_bytes": code_load,
        "primary_load_segments": segments, "primary_symbols": syms,
        "stage2": stage, "stage2_load_segments": loads(out / "stage2/stage2.elf"),
        "boot_only": {"start": 0xF4000, "end": 0xFE000, "bytes": len(raw),
                      "excludes": ["SoftDevice", "UICR", "APP", "FS", "MBR params", "SDK settings"]},
        "source_fingerprints": source_fingerprints,
        "generated_caller_sha256": sha(tree / "src/main.c"),
        "generated_make_sha256": sha(tree / "Makefile"),
        "generated_linker_sha256": sha(tree / "linker/nrf52840.ld"),
        "config_and_marker_sha256": hashlib.sha256(raw[0x9800:]).hexdigest(),
        "arm_gcc_version": run(["arm-none-eabi-gcc", "--version"], ROOT).splitlines()[0],
        "source_date_epoch": int(os.environ["SOURCE_DATE_EPOCH"]),
        "optional_fault_layer": "excluded",
        "files": {str(p.relative_to(out)): sha(p) for p in
            (elf, hexfile, out / "primary-boot-only.bin", out / "stage2/stage2.bin")},
        "hardware": "NOT exercised; ready for combined source/artifact review"
    }
    (out / "pair-manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Sense/profile pair built: primary LOAD {code_load}/38912; stage {stage['extent']}/65536.")


if __name__ == "__main__":
    main()
