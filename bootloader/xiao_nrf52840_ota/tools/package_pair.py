#!/usr/bin/env python3
"""Offline literal Sense ROLE1/77 or explicitly selected ROLE0/41 paired packages."""
import argparse
import binascii
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time
import zipfile

import build_pair as build
import install_uf2 as host

CURRENT_APP_SHA256 = "69c961ff66602c865a3cf8b3855478a8191cfc605ed4d811e70a7cdcc9f18fd2"
CURRENT_APP_BYTES = 538360
CLIENT_APP_BYTES = 550308
CLIENT_APP_SHA256 = "9f7f013ad118f501118aea8e7c234e5d989625443e93b5aa3349043588449733"
CLIENT_APP_ZIP_SHA256 = "4b9813fd43489232eaa158f4cda21546bb42e37f17c85595b5e1972f32d8d0d9"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=host.unique_json_fields)


def package_payload(path, kind, expected=None):
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("manifest.json"),
                              object_pairs_hook=host.unique_json_fields)
        body = manifest["manifest"]
        require(set(body) == {"dfu_version", kind} and body["dfu_version"] == 0.5,
                "package must be ordinary legacy v0.5 " + kind + "-only")
        image = body[kind]
        require(set(image) == {"bin_file", "dat_file", "init_packet_data"}, "invalid image manifest")
        names = [image["bin_file"], image["dat_file"]]
        require(all(re.fullmatch(r"[A-Za-z0-9_.-]+", n) for n in names), "unsafe ZIP member name")
        entries = archive.infolist()
        require(len(entries) == 3 and {e.filename for e in entries} ==
                {"manifest.json", *names}, "extra/duplicate ZIP images or members")
        require(all(not e.flag_bits & 1 and e.file_size <= 708608 for e in entries),
                "encrypted/oversized ZIP member")
        raw = archive.read(names[0])
        init = image["init_packet_data"]
        require(set(init) == {"application_version", "device_type", "device_revision",
                             "softdevice_req", "firmware_crc16"}, "invalid standard init fields")
        require(init["softdevice_req"] == [0x123], "unexpected SoftDevice requirement")
        require(all(type(init[k]) is int for k in init if k != "softdevice_req"),
                "init fields must be integers")
        require(init["device_type"] == 0x52 and init["device_revision"] in (0xFFFF, 52840),
                "unexpected nRF device/revision")
        require(init["firmware_crc16"] == binascii.crc_hqx(raw, 0xFFFF), "payload CRC mismatch")
        encoded = struct.pack("<HHIHHH", init["device_type"], init["device_revision"],
                              init["application_version"], 1, 0x123, init["firmware_crc16"])
        require(archive.read(names[1]) == encoded, "standard init packet differs")
        if expected is not None:
            require(raw == expected, "ZIP payload differs from matching RAW")
        return raw, init


def verify_pair(pair, *, client41=False):
    require(type(client41) is bool, "client41 must be an explicit boolean profile")
    role = 0 if client41 else 1
    manifest = read_json(pair / "pair-manifest.json")
    require((manifest["vendor_pin"], manifest["vendor_release"], manifest["actual_vendor_bsp"],
             manifest["logical_board"], manifest["role"]) ==
            (build.PIN, build.RELEASE, "xiao_nrf52840_ble_sense", "xiao_nrf52840", role),
            f"requires genuine pinned Sense BSP / logical Xiao ROLE{role} pair")
    require(manifest["architecture"] == "fixed-otafix-primary-secondary" and
            manifest["optional_fault_layer"] == "excluded", "wrong selected architecture/layer")
    known = {str(p.relative_to(build.PRODUCT)) for p in build.PRODUCT.rglob("*")
             if p.is_file() and "__pycache__" not in p.parts} | {"canonical-layout"}
    require(set(manifest["source_fingerprints"]) == known, "incomplete/stale source inventory")
    for name, fingerprint in manifest["source_fingerprints"].items():
        path = (build.ROOT / "src/ota/platform/Nrf52FlashLayoutContract.h"
                if name == "canonical-layout" else build.PRODUCT / name)
        require(build.sha(path) == fingerprint, "source changed since pair build: " + name)
    release = digest(json.dumps({"vendor_pin": build.PIN,
                                 "source": manifest["source_fingerprints"]},
                                sort_keys=True).encode())
    require(manifest["currentSourceRelease"] == release, "source-release fingerprint mismatch")
    for name, fingerprint in manifest["files"].items():
        require(build.sha(pair / name) == fingerprint, "pair artifact hash mismatch: " + name)
    stage = (pair / "stage2/stage2.bin").read_bytes()
    primary = (pair / "primary-boot-only.bin").read_bytes()
    detail = manifest["stage2"]
    require(36 <= len(stage) <= 65536 and len(stage) == detail["extent"] and
            binascii.crc32(stage) & 0xFFFFFFFF == detail["crc32"], "stage extent/CRC mismatch")
    require(struct.unpack("<9I", stage[:36]) ==
            (0x3253464F, 1, 36, 0x584E3430, role, len(stage), detail["entry"],
             0x20020000, 0x20030000) and detail["entry"] == 0xC4041,
            "wrong fixed installer header/ABI")
    memory = build.ihex(pair / "primary.hex")
    require(memory and all(0xF4000 <= a < 0xFE000 for a in memory), "non-primary HEX addresses")
    require(len(primary) == 0xA000 and primary ==
            bytes(memory.get(a, 255) for a in range(0xF4000, 0xFE000)), "RAW/HEX differ")
    cf2_raw = primary[0x9800:0x9C00]
    magic0, magic1, used, capacity = struct.unpack_from("<4I", cf2_raw)
    require((magic0, magic1) == host.boot_info.CF2_MAGIC and
            0 < used <= capacity <= (len(cf2_raw) - 16) // 8, "invalid CF2 geometry")
    ids = [value for key, value in struct.iter_unpack("<II", cf2_raw[16:16 + used * 8])
           if key == host.boot_info.CF2_BOOTLOADER_BOARD_ID]
    require(ids == [0x28860045], "artifact CF2 is not genuine Sense USB identity")
    cf2 = ids[0]
    elf = pair / "primary.elf"
    segments = build.loads(elf)
    for s in segments:
        if not s["filesz"]:
            continue
        start, stop = s["paddr"], s["paddr"] + s["filesz"]
        require(0xF4000 <= start <= stop <= 0xFE000, "forbidden primary ELF LOAD")
    # PT_LOAD padding is not an objcopy payload. Reuse the existing allocated
    # section/LMA parser, including its initialized-data and version checks.
    compiled, version = host.compiled_boot_span(elf)
    require(version == 0x902 and primary[:host.BOOT_BYTES] == compiled and
            primary[host.BOOT_BYTES:] == b"\xff" * (len(primary) - host.BOOT_BYTES),
            "ELF allocated sections/RAW differ")
    code = sum(s["filesz"] for s in segments if s["vaddr"] == s["paddr"] and
               0xF4000 <= s["paddr"] < 0xFD800)
    data = sum(s["filesz"] for s in segments if 0x20008000 <= s["vaddr"] < 0x20020000)
    require(code + data == manifest["primary_load_bytes"] and code + data <= 38912,
            "primary code+initialized-data budget mismatch")
    symbols = build.symbols(elf)
    require(symbols["__meshcore_vendor_bootloader_version"] == 0x902 and
            symbols["g_xiao_ota_boot_info"] == 0xFDC00, "vendor version/marker address mismatch")
    offset = symbols["paired_stage"] - 0xF4000
    require(struct.unpack("<5I", primary[offset:offset + 20]) ==
            (0x584E3430, role, len(stage), detail["entry"], detail["crc32"]),
            "primary compiled factory binding differs from stage")
    marker = primary[0x9C00:0x9C3C]
    fields = struct.unpack("<IHHIIIHH32sI", marker)
    require(fields[:8] == (0x584F4249, 1, 60, 0x584E3430, role, 1, 1, 1) and
            fields[-1] == binascii.crc32(marker[:-4]) & 0xFFFFFFFF, "invalid existing XOBI marker")
    public = {name: manifest[name] for name in
              ("currentSourceRelease", "vendor_pin", "vendor_release", "logical_board",
               "actual_vendor_bsp", "role", "source_fingerprints", "stage2")}
    public.update(pair_manifest_sha256=build.sha(pair / "pair-manifest.json"),
                  capabilities=fields[5], primary_code_bytes=code,
                  primary_initialized_data_bytes=data, primary_arm_load_bytes=code + data,
                  cf2_board_id=cf2, marker_address=0xFDC00,
                  marker_bytes=60, marker_sha256=digest(marker))
    return primary, stage, public


def compound_payload(app, stage, *, client41=False):
    require(type(client41) is bool, "client41 must be an explicit boolean profile")
    size, fingerprint = ((CLIENT_APP_BYTES, CLIENT_APP_SHA256) if client41 else
                         (CURRENT_APP_BYTES, CURRENT_APP_SHA256))
    require(len(app) == size and digest(app) == fingerprint,
            "APP prefix is not immutable " + ("CLIENT41550308" if client41 else "CURRENT538360"))
    stack, reset = struct.unpack_from("<II", app)
    require(0x20000000 < stack <= 0x20040000 and stack % 8 == 0 and reset & 1 and
            0x27000 <= (reset & ~1) < 0x27000 + len(app), "invalid APP vectors")
    offset = 0xC4000 - 0x27000
    result = app + b"\xff" * (offset - len(app)) + stage
    result += b"\xff" * (-len(result) % 4)
    erase_end = (0x27000 + len(result) + 4095) & ~4095
    require(len(result) % 4 == 0 and erase_end <= 0xD4000,
            "compound APP erase reaches beyond fixed installer")
    return result


def emit(args, kind, filename, raw, init):
    binary = args.output / (filename + ".bin")
    package = args.output / (filename + ".zip")
    binary.write_bytes(raw)
    command = host.nrfutil_command(args) + [
        "dfu", "genpkg", "--" + kind, str(binary),
        "--application-version", str(init["application_version"]),
        "--dev-type", str(init["device_type"]), "--dev-revision", str(init["device_revision"]),
        "--sd-req", "0x0123", "--dfu-ver", "0.5", str(package)]
    scratch = args.output / "scratch"
    scratch.mkdir()
    result = subprocess.run(command, capture_output=True, text=True, timeout=host.DFU_TIMEOUT,
                            env=dict(os.environ, TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch)))
    scratch.rmdir()
    require(result.returncode == 0, "offline DFU package creation failed: " + result.stdout + result.stderr)
    _, actual = package_payload(package, kind, raw)
    expected = copy.deepcopy(init)
    expected["firmware_crc16"] = binascii.crc_hqx(raw, 0xFFFF)
    require(actual == expected, "creator changed standard init profile")
    if args.client41:
        stamp = time.gmtime(read_json(args.pair / "pair-manifest.json")["source_date_epoch"])[:6]
        with zipfile.ZipFile(package) as archive:
            members = [(item, archive.read(item)) for item in
                       sorted(archive.infolist(), key=lambda item: item.filename)]
        with zipfile.ZipFile(package, "w") as archive:
            for item, data in members:
                item.date_time = stamp
                archive.writestr(item, data)
        require(package_payload(package, kind, raw)[1] == expected,
                "reproducible ZIP changed standard init profile")
    return {"kind": kind, "raw": binary.name, "raw_sha256": digest(raw), "bytes": len(raw),
            "zip": package.name, "zip_sha256": build.sha(package), "init": actual}


def run(args):
    client41 = args.client41
    primary, stage, public = verify_pair(args.pair, client41=client41)
    app, original_init = package_payload(args.app_package, "application")
    if client41:
        require(build.sha(args.app_package) == CLIENT_APP_ZIP_SHA256,
                "ordinary restore ZIP is not the immutable approved client41 package")
    compound = compound_payload(app, stage, client41=client41)
    binding = dict(pair=public, app_prefix_sha256=digest(app), app_prefix_bytes=len(app),
                   input_app_zip_sha256=build.sha(args.app_package), app_start=0x27000,
                   stage_start=0xC4000, stage_bytes=len(stage), primary_start=0xF4000,
                   compound_bytes=len(compound), compound_sha256=digest(compound),
                   erase_end=(0x27000 + len(compound) + 4095) & ~4095,
                   boot_only_sha256=digest(primary), boot_only_bytes=len(primary),
                   hardware="NOT accessed; package/byte verification only")
    if client41:
        binding["commission_profile"] = "sense-role0-client41"
    if args.verify_only:
        existing = read_json(args.output / "package-manifest.json")
        packages = existing.pop("packages")
        require(existing == binding, "public pair/payload binding differs")
        require(set(packages) == {"compound", "bootloader"}, "unexpected public package set")
        for name, kind, raw, init in (
                ("compound", "application", compound, original_init),
                ("bootloader", "bootloader", primary, dict(application_version=0x902,
                 device_type=0x52, device_revision=52840, softdevice_req=[0x123]))):
            item = packages[name]
            payload, actual = package_payload(args.output / (name + ".zip"), kind, raw)
            expected = dict(init, firmware_crc16=binascii.crc_hqx(payload, 0xFFFF))
            require(actual == expected and item["init"] == actual and
                    item["kind"] == kind and item["raw"] == name + ".bin" and
                    item["zip"] == name + ".zip" and
                    item["zip_sha256"] == build.sha(args.output / (name + ".zip")) and
                    item["raw_sha256"] == digest(payload) and item["bytes"] == len(payload) and
                    (args.output / (name + ".bin")).read_bytes() == payload,
                    "package manifest/RAW/ZIP binding mismatch")
        print(f"VERIFIED matching SenseROLE{0 if client41 else 1} pair + immutable APP + "
              "APP-only compound/boot-only ZIPs")
        return
    require(args.output.is_relative_to(build.ROOT / ".tmp/ota-boot-builds"),
            "output must stay in the project-owned build namespace")
    require(not args.output.exists(), "refusing to overwrite an existing package freeze")
    args.output.mkdir(parents=True)
    binding["packages"] = {
        "compound": emit(args, "application", "compound", compound, original_init),
        "bootloader": emit(args, "bootloader", "bootloader", primary,
                           dict(application_version=0x902, device_type=0x52,
                                device_revision=52840, softdevice_req=[0x123])),
    }
    (args.output / "package-manifest.json").write_text(json.dumps(binding, indent=2) + "\n")
    print(f"PACKAGE ONLY: compound {len(compound)}B, stage {len(stage)}B, "
          f"erase ends {binding['erase_end']:X}; matching boot-only {len(primary)}B; no device accessed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair", type=Path, required=True)
    parser.add_argument("--app-package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--nrfutil", required=True)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--client41", action="store_true",
                        help="only the literal approved Sense ROLE0/client41 APP/ZIP profile")
    args = parser.parse_args()
    args.pair, args.app_package, args.output = (
        p.resolve() for p in (args.pair, args.app_package, args.output))
    run(args)


if __name__ == "__main__":
    main()
