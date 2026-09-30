#!/usr/bin/env python3
"""Create a disposable, pinned upstream tree with the MeshCore overlay."""

from pathlib import Path
import argparse
import binascii
import re
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[3]
PIN = "c67f0bcf0fa8e841426335b1bbde91cda6ca1f50"
SOURCE = ROOT / ".tmp" / "Adafruit_nRF52_Bootloader"
OVERLAY = ROOT / "bootloader" / "xiao_nrf52840_ota"


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def validate_work_dir(work: Path) -> Path:
    """Reject any --work-dir that is not a strict descendant of ROOT/.tmp,
    before any git/copy/delete action. WORK is shutil.rmtree()'d unconditionally
    below, so a caller-controlled path here would be a recursive-delete
    vulnerability; this must run first and must not be bypassable via a
    symlink (Path.resolve() follows them)."""
    tmp_root = (ROOT / ".tmp").resolve()
    source_root = SOURCE.resolve()
    resolved = work.resolve()
    if resolved == tmp_root or resolved == ROOT.resolve() or resolved == source_root:
        raise SystemExit(f"--work-dir must not be {resolved} (reserved path)")
    try:
        resolved.relative_to(source_root)
        raise SystemExit(
            f"--work-dir must not be inside pinned upstream clone {source_root}, "
            f"got {resolved}")
    except ValueError:
        pass
    try:
        resolved.relative_to(tmp_root)
    except ValueError:
        raise SystemExit(f"--work-dir must resolve inside {tmp_root}, got {resolved}")
    return resolved


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-ble", action="store_true",
                        help="build the stock-address UF2/CDC recovery variant")
    parser.add_argument("--board", choices=("xiao_nrf52840", "sensecap_solar_p1"),
                        default="xiao_nrf52840",
                        help="board profile to compile the boot-info marker and install "
                             "policy target check for. sensecap_solar_p1 is a real, "
                             "distinct target id sharing the same P25Q16H QSPI pinout "
                             "family, but has NOT been physically qualified on hardware "
                             "-- treat any such build as build-only until a real board "
                             "confirms it.")
    parser.add_argument("--work-dir", default=None,
                        help="disposable build tree to copy the pinned upstream into "
                             "and compile from. Defaults to "
                             ".tmp/xiao_nrf52840_ota_{noswd_,}upstream (selected by "
                             "--no-ble). Pass a distinct --work-dir per profile when "
                             "building more than one --board in one invocation, or "
                             "they will clobber each other's tree/artifacts. Must "
                             "resolve inside ROOT/.tmp (see _validate_work_dir).")
    args = parser.parse_args(argv)
    BOARD_TARGET_MACRO = {
        "xiao_nrf52840": "XIAO_OTA_TARGET_XIAO_NRF52840",
        "sensecap_solar_p1": "XIAO_OTA_TARGET_SENSECAP_SOLAR_P1",
    }[args.board]
    # Must stay byte-for-byte identical to the same-named constants in
    # include/xiao_ota_record.h -- these numeric values are what actually get
    # compiled in (via -D below) and what the boot-info CRC patch step below
    # authenticates against.
    BOARD_TARGET_VALUE = {
        "xiao_nrf52840": 0x584E3430,
        "sensecap_solar_p1": 0x53435031,
    }[args.board]
    WORK = Path(args.work_dir) if args.work_dir else ROOT / ".tmp" / (
        "xiao_nrf52840_ota_noswd_upstream" if args.no_ble
        else "xiao_nrf52840_ota_upstream"
    )
    if not WORK.is_absolute():
        WORK = ROOT / WORK
    WORK = validate_work_dir(WORK)

    if not (SOURCE / ".git").is_dir():
        SOURCE.parent.mkdir(parents=True, exist_ok=True)
        subprocess.check_call([
            "git", "clone", "https://github.com/adafruit/Adafruit_nRF52_Bootloader.git",
            str(SOURCE),
        ])
    subprocess.check_call(["git", "-C", str(SOURCE), "checkout", "--detach", PIN])
    if run("git", "-C", str(SOURCE), "rev-parse", "HEAD") != PIN:
        raise SystemExit("pinned upstream checkout mismatch")
    # Idempotently re-asserted here (cheap no-op if the Makefile's fetch
    # target already did it) so this script is self-sufficient even on a
    # fresh non-recursive clone, where submodules like lib/nrfx (nrf.h)
    # would otherwise copy over empty and fail the build.
    subprocess.check_call([
        "git", "-C", str(SOURCE), "submodule", "update", "--init", "--recursive", "--quiet",
    ])

    if WORK.exists():
        shutil.rmtree(WORK)
    shutil.copytree(SOURCE, WORK, ignore=shutil.ignore_patterns(".git", "_build", "_bin"))

    custom = WORK / "src" / "xiao_ota"
    custom.mkdir(parents=True)
    for path in (OVERLAY / "include").glob("*.h"):
        shutil.copy2(path, custom / path.name)
    for path in (OVERLAY / "src").glob("*.[ch]"):
        shutil.copy2(path, custom / path.name)
    shutil.copy2(OVERLAY / "linker" / "nrf52840_xiao_ota.ld",
                 WORK / "linker" / "nrf52840_xiao_ota.ld")
    shutil.copy2(OVERLAY / "linker" / "nrf52840_xiao_ota_noswd.ld",
                 WORK / "linker" / "nrf52840_xiao_ota_noswd.ld")

    # Defense against BOARD_TARGET_VALUE silently drifting from the real
    # constants defined in xiao_ota_record.h (the one the compiled bootloader
    # and its install-command policy check actually use).
    record_header_text = (custom / "xiao_ota_record.h").read_text()
    expected_target_hex = f"UINT32_C(0x{BOARD_TARGET_VALUE:08X})"
    if not re.search(rf"#define\s+{re.escape(BOARD_TARGET_MACRO)}\s+{re.escape(expected_target_hex)}",
                     record_header_text):
        raise SystemExit(
            f"BOARD_TARGET_VALUE for --board {args.board} ({expected_target_hex}) no longer "
            f"matches {BOARD_TARGET_MACRO} in xiao_ota_record.h -- update prepare_upstream.py"
        )

    # Compute the real boot-info marker CRC-32 for the selected board profile
    # and patch it into the copied xiao_ota_boot_info.c, replacing the
    # deliberately-invalid placeholder committed in the repo. This must mirror
    # xiao_ota_crc32()'s exact algorithm (IEEE 802.3, reflected, init/final
    # 0xFFFFFFFF -- i.e. the same as binascii.crc32) over the packed struct's
    # exact little-endian byte layout (nRF52840/Cortex-M is little-endian), and
    # every field value here must be identical to the literal C initializer in
    # xiao_ota_boot_info.c below the placeholder (magic/format_version/
    # struct_bytes/role_id/capability_flags/key_id/algorithm_id), or the two
    # would silently diverge.
    public_key_header_text = (custom / "xiao_ota_public_key.h").read_text()
    key_match = re.search(
        r"XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES\s*\\((?:.|\n)*?)\n\n", public_key_header_text
    )
    if not key_match:
        raise SystemExit("could not locate XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES in "
                          "xiao_ota_public_key.h")
    key_bytes = bytes(int(tok, 16) for tok in re.findall(r"0x[0-9a-fA-F]{2}", key_match.group(1)))
    if len(key_bytes) != 32:
        raise SystemExit(f"expected 32 public key bytes, parsed {len(key_bytes)}")

    BOOT_INFO_MAGIC = 0x584F4249
    BOOT_INFO_FORMAT_VERSION = 1
    BOOT_INFO_STRUCT_BYTES = 60
    BOOT_INFO_ROLE_ANY = 0
    BOOT_INFO_CAP_QSPI_INSTALL = 1
    BOOT_INFO_KEY_ID = 1
    BOOT_INFO_ALGORITHM_ED25519 = 1
    boot_info_bytes_before_crc = struct.pack(
        "<IHHIIIHH32s",
        BOOT_INFO_MAGIC,
        BOOT_INFO_FORMAT_VERSION,
        BOOT_INFO_STRUCT_BYTES,
        BOARD_TARGET_VALUE,
        BOOT_INFO_ROLE_ANY,
        BOOT_INFO_CAP_QSPI_INSTALL,
        BOOT_INFO_KEY_ID,
        BOOT_INFO_ALGORITHM_ED25519,
        key_bytes,
    )
    if len(boot_info_bytes_before_crc) != BOOT_INFO_STRUCT_BYTES - 4:
        raise SystemExit(
            f"boot-info packed layout mismatch: expected "
            f"{BOOT_INFO_STRUCT_BYTES - 4} bytes before crc32, got "
            f"{len(boot_info_bytes_before_crc)} -- xiao_ota_boot_info_t layout changed?"
        )
    boot_info_crc = binascii.crc32(boot_info_bytes_before_crc) & 0xFFFFFFFF

    boot_info_c = custom / "xiao_ota_boot_info.c"
    boot_info_text = boot_info_c.read_text()
    placeholder = (
        ".crc32 = 0xFFFFFFFFu, /* XIAO_OTA_BOOT_INFO_CRC32_PLACEHOLDER: "
        "patched by prepare_upstream.py */"
    )
    if placeholder not in boot_info_text:
        raise SystemExit(
            "xiao_ota_boot_info.c CRC placeholder not found -- source format changed, "
            "update prepare_upstream.py's patch step"
        )
    boot_info_text = boot_info_text.replace(
        placeholder,
        f".crc32 = UINT32_C(0x{boot_info_crc:08X}), /* patched for --board {args.board} "
        f"by prepare_upstream.py */",
        1,
    )
    boot_info_c.write_text(boot_info_text)


    ed25519 = ROOT / "src" / "ota" / "trust" / "third_party" / "ed25519"
    for name in ("ed25519.h", "fixedint.h", "fe.h", "fe.c", "ge.h", "ge.c",
                 "sc.h", "sc.c", "sha512.h", "sha512.c", "verify.c",
                 "precomp_data.h", "LICENSE", "NOTICE.txt"):
        shutil.copy2(ed25519 / name, custom / name)

    if args.no_ble:
        tweetnacl = OVERLAY / "third_party" / "tweetnacl"
        shutil.copy2(tweetnacl / "tweetnacl.c", custom / "tweetnacl.c")
        shutil.copy2(tweetnacl / "tweetnacl.h", custom / "tweetnacl.h")

    main = WORK / "src" / "main.c"
    text = main.read_text()
    text = text.replace('#include "boards.h"\n', '#include "boards.h"\n#include "xiao_ota_boot.h"\n')
    needle = '  led_state(STATE_BOOTLOADER_STARTED);\n'
    text = text.replace(needle, needle + "\n  xiao_ota_boot_process();\n", 1)
    main.write_text(text)

    if args.no_ble:
        text = main.read_text()
        text = text.replace("static uint32_t ble_stack_init(void);\n", "", 1)
        text = text.replace(
            '  // Start Bootloader in BLE OTA mode\n'
            '  _ota_dfu = (gpregret == DFU_MAGIC_OTA_APPJUM) || '
            '(gpregret == DFU_MAGIC_OTA_RESET);\n',
            '  // BLE DFU is omitted. Legacy BLE reset requests enter CDC-only DFU.\n'
            '  _ota_dfu = false;\n',
            1,
        )
        text = text.replace(
            '  bool const serial_only_dfu = '
            '(gpregret == DFU_MAGIC_SERIAL_ONLY_RESET);\n',
            '  bool const serial_only_dfu = '
            '(gpregret == DFU_MAGIC_SERIAL_ONLY_RESET) ||\n'
            '                               '
            '(gpregret == DFU_MAGIC_OTA_APPJUM) ||\n'
            '                               '
            '(gpregret == DFU_MAGIC_OTA_RESET);\n',
            1,
        )
        text = text.replace(
            '    if (_ota_dfu) {\n'
            '      led_state(STATE_BLE_DISCONNECTED);\n'
            '      if (!_sd_inited) mbr_init_sd();\n'
            '      _sd_inited = true;\n'
            '      ble_stack_init();\n'
            '    } else {\n'
            '      led_state(STATE_USB_UNMOUNTED);\n'
            '      usb_init(serial_only_dfu);\n'
            '    }\n',
            '    led_state(STATE_USB_UNMOUNTED);\n'
            '    usb_init(serial_only_dfu);\n',
            1,
        )
        text = text.replace(
            '      bootloader_dfu_start(_ota_dfu, 3000, true);\n',
            '      bootloader_dfu_start(false, 3000, true);\n',
            1,
        )
        text = text.replace(
            '      bootloader_dfu_start(_ota_dfu, 0, false);\n',
            '      bootloader_dfu_start(false, 0, false);\n',
            1,
        )
        text = text.replace(
            '    if (_ota_dfu) {\n'
            '      disable_softdevice();\n'
            '    } else {\n'
            '      usb_teardown();\n'
            '    }\n',
            '    usb_teardown();\n',
            1,
        )
        ble_start = text.index(
            '//--------------------------------------------------------------------+\n'
            '// BLE\n'
            '//--------------------------------------------------------------------+\n'
        )
        error_start = text.index(
            '//--------------------------------------------------------------------+\n'
            '// Error Handler\n'
            '//--------------------------------------------------------------------+\n'
        )
        text = text[:ble_start] + text[error_start:]
        main.write_text(text)

    makefile = WORK / "Makefile"
    text = makefile.read_text()
    text = text.replace(
        "GIT_VERSION := $(shell git describe --dirty --always --tags)",
        f"GIT_VERSION := {PIN[:12]}",
        1,
    )
    needle = "# all files in boards\n"
    addition = f"""# MeshCore XIAO external-QSPI OTA overlay
    C_SRC += \\
      src/xiao_ota/xiao_ota_boot.c \\
      src/xiao_ota/xiao_ota_record.c \\
      src/xiao_ota/xiao_ota_boot_info.c \\
      src/xiao_ota/xiao_ota_sha256.c \\
      src/xiao_ota/fe.c \\
      src/xiao_ota/ge.c \\
      src/xiao_ota/sc.c \\
      src/xiao_ota/sha512.c \\
      src/xiao_ota/verify.c
    IPATH += src/xiao_ota
    # --board {args.board}: selects the install-policy target check and the
    # baked-in boot-info marker's board_target_id (see xiao_ota_record.h /
    # xiao_ota_boot_info.c). sensecap_solar_p1 is NOT physically qualified --
    # build-only until real hardware confirms it.
    CFLAGS += -DXIAO_OTA_BOARD_TARGET=0x{BOARD_TARGET_VALUE:08X}u

    """
    text = text.replace(needle, addition + needle, 1)
    text = text.replace(
        "-include src/boards/$(BOARD)/board.mk\n",
        "-include src/boards/$(BOARD)/board.mk\n\n"
        "ifeq ($(BOARD),xiao_nrf52840_ble)\n"
        "CFLAGS += -DBOOTLOADER_REGION_START=0xED000\n"
        "endif\n",
        1,
    )
    text = text.replace(
        "else\n  LD_FILE = linker/$(MCU_SUB_VARIANT).ld\nendif\n",
        "else\n  LD_FILE = linker/$(MCU_SUB_VARIANT).ld\nendif\n"
        "ifeq ($(BOARD),xiao_nrf52840_ble)\n"
        "LD_FILE = linker/nrf52840_xiao_ota.ld\n"
        "endif\n",
        1,
    )
    if args.no_ble:
        for source in (
            "  src/dfu_ble_svc.c \\\n",
            "C_SRC += $(SDK11_PATH)/libraries/bootloader_dfu/dfu_transport_ble.c\n",
            "C_SRC += $(SDK11_PATH)/ble/ble_services/ble_dfu/ble_dfu.c\n",
            "C_SRC += $(SDK11_PATH)/ble/ble_services/ble_dis/ble_dis.c\n",
        ):
            text = text.replace(source, "", 1)
        for source in (
            "  src/xiao_ota/fe.c \\\n",
            "  src/xiao_ota/ge.c \\\n",
            "  src/xiao_ota/sc.c \\\n",
            "  src/xiao_ota/sha512.c \\\n",
            "  src/xiao_ota/verify.c\n",
        ):
            text = text.replace(source, "", 1)
        text = text.replace(
            "  src/xiao_ota/xiao_ota_boot.c \\\n",
            "  src/xiao_ota/xiao_ota_boot.c \\\n"
            "  src/xiao_ota/xiao_ota_no_ble.c \\\n",
            1,
        )
        text = text.replace(
            "  src/xiao_ota/xiao_ota_sha256.c \\\n",
            "  src/xiao_ota/xiao_ota_sha256.c \\\n"
            "  src/xiao_ota/xiao_ota_ed25519_tweetnacl.c \\\n"
            "  src/xiao_ota/tweetnacl.c\n",
            1,
        )
        text = text.replace(
            "CFLAGS += -DBOOTLOADER_REGION_START=0xED000\n",
            "CFLAGS += -DBOOTLOADER_REGION_START=0xF4000\n"
            "CFLAGS += -flto -fuse-linker-plugin\n",
            1,
        )
        text = text.replace(
            "LD_FILE = linker/nrf52840_xiao_ota.ld\n",
            "LD_FILE = linker/nrf52840_xiao_ota_noswd.ld\n",
            1,
        )
        text += (
            "\n# TweetNaCl is externally maintained compact public-domain C.\n"
            "CFLAGS += -Wno-unused-function -Wno-sign-compare -Wno-shadow "
            "-Wno-unterminated-string-initialization\n"
        )
    makefile.write_text(text)

    print(WORK)
    return WORK


if __name__ == "__main__":
    main()
