#!/usr/bin/env python3
"""Create a disposable, pinned upstream tree with the MeshCore overlay."""

from pathlib import Path
import argparse
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
PIN = "c67f0bcf0fa8e841426335b1bbde91cda6ca1f50"
SOURCE = ROOT / ".tmp" / "Adafruit_nRF52_Bootloader"
OVERLAY = ROOT / "bootloader" / "xiao_nrf52840_ota"


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


parser = argparse.ArgumentParser()
parser.add_argument("--no-ble", action="store_true",
                    help="build the stock-address UF2/CDC recovery variant")
args = parser.parse_args()
WORK = ROOT / ".tmp" / (
    "xiao_nrf52840_ota_noswd_upstream" if args.no_ble
    else "xiao_nrf52840_ota_upstream"
)

if not (SOURCE / ".git").is_dir():
    SOURCE.parent.mkdir(parents=True, exist_ok=True)
    subprocess.check_call([
        "git", "clone", "https://github.com/adafruit/Adafruit_nRF52_Bootloader.git",
        str(SOURCE),
    ])
subprocess.check_call(["git", "-C", str(SOURCE), "checkout", "--detach", PIN])
if run("git", "-C", str(SOURCE), "rev-parse", "HEAD") != PIN:
    raise SystemExit("pinned upstream checkout mismatch")

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
addition = """# MeshCore XIAO external-QSPI OTA overlay
C_SRC += \\
  src/xiao_ota/xiao_ota_boot.c \\
  src/xiao_ota/xiao_ota_record.c \\
  src/xiao_ota/xiao_ota_sha256.c \\
  src/xiao_ota/fe.c \\
  src/xiao_ota/ge.c \\
  src/xiao_ota/sc.c \\
  src/xiao_ota/sha512.c \\
  src/xiao_ota/verify.c
IPATH += src/xiao_ota

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
