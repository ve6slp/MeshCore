# nRF52840 paired LoRa OTA bootloader

The optional nRF backend needs a matching small primary and a fixed returning
installer, not just a new application. The primary preserves ordinary vendor
USB/serial/BLE recovery; the installer processes signed QSPI transactions,
backup/install/trial/rollback and returns to that recovery path when needed.
The informational boot marker is not a signing authority: admission still uses
the receiver's current MeshCore administrator permissions.
Provision the intended sender contact and OTA-administrator permission explicitly.
Admission and COMMIT check the owner's signature and current permission; the
installer verifies `command.admitted_signer_public_key_ed25519` and delegates
administrator policy to the trusted app, not an independently pinned publisher root.
The all-zero reference marker requires no generated key header. `--key-header`
is only an optional offline artifact comparison, never command authorization.

The public vendor source is
[OTAFIX](https://github.com/oltaco/Adafruit_nRF52_Bootloader_OTAFIX), pinned to
`a62825be4733f500271c89b5ec489fd609748e97`
(`0.9.2-OTAFIX2.3-BP1.4`). The preserving patch and installer sources are in this
directory. Base XIAO, Sense XIAO and SenseCAP select their actual vendor BSP;
Sense retains its own CF2/USB identity while sharing logical Xiao OTA family.
Both role IDs are supported: companion 0, repeater 1.

## Build and package, without a device

Requirements: GNU Make, Python, Git, `arm-none-eabi-gcc`/binutils and native
`cc`; packaging uses the standard PlatformIO-installed Adafruit nrfutil script.
Select board/role and an ordinary application-only ZIP from your own build.
There are no private cached-artifact paths or approval records.

```sh
make -f bootloader/xiao_nrf52840_ota/Makefile fetch \
  BOARD=xiao_nrf52840_sense ROLE=0
make build ENV=Xiao_nrf52_companion_radio_ota_usb
make build-xiao-ota-bootloader-pair \
  XIAO_OTA_PAIR_BOARD=xiao_nrf52840_sense XIAO_OTA_PAIR_ROLE_ID=0
make package-xiao-ota-bootloader-pair \
  XIAO_OTA_PAIR_BOARD=xiao_nrf52840_sense XIAO_OTA_PAIR_ROLE_ID=0 \
  XIAO_OTA_PAIR_APP_PACKAGE="$PWD/.pio/build/Xiao_nrf52_companion_radio_ota_usb/firmware.zip"
```

Use `xiao_nrf52840` for non-Sense XIAO or `sensecap_solar_p1` for Solar; do not
relabel one board's artifact as another. `XIAO_OTA_VENDOR` selects a clean checkout
at the pinned commit with initialized clean pinned submodules.
`XIAO_OTA_PAIR_DIR` defaults to a board/role-specific path under
`.tmp/ota-boot-builds`; all scratch stays repo-local. `SOURCE_DATE_EPOCH` derives
from the pinned vendor commit and can be explicitly overridden.

Outputs include primary ELF/HEX/RAW, stage ELF/HEX/BIN, maps and
`pair-manifest.json`. Packaging verifies current source hashes, ELF/HEX/RAW
identity, stage extent/CRC and the primary's compiled matching stage tuple.
It emits standard legacy v0.5 **application-only compound** and **bootloader-only**
ZIPs plus a package manifest with exact selected APP and artifact hashes.
The compound preserves your ordinary APP bytes and init profile, pads with FF
to the installer, and contains no SoftDevice, UICR or filesystem image.
Output directories must be new; existing artifacts are never overwritten.

```sh
make verify-xiao-ota-bootloader-pair-packages \
  XIAO_OTA_PAIR_BOARD=xiao_nrf52840_sense XIAO_OTA_PAIR_ROLE_ID=0 \
  XIAO_OTA_PAIR_APP_PACKAGE="$APP_ZIP"
make test-xiao-ota-bootloader-pair \
  XIAO_OTA_PAIR_BOARD=xiao_nrf52840_sense XIAO_OTA_PAIR_ROLE_ID=0 \
  XIAO_OTA_PAIR_APP_PACKAGE="$APP_ZIP"
```

Native pair tests exercise the actual returning adapter and reject the legacy
reset adapter. Host tests create/reparse standard packages and reject changed
board/role, APP, stage, init bytes, CRC, extra images and mismatched readback.
Passing software tests are not proof of physical installation.
When no APP ZIP is supplied to the pair **test**, it uses a synthetic vector
fixture; the actual **packaging** target always requires your selected APP ZIP.

## Bootstrap and recovery constraints

The fixed layout is APP `0x27000..0xC4000`, installer `0xC4000..0xD4000`,
protected ExtraFS `0xD4000..0xED000`, InternalFS `0xED000..0xF4000`, primary
`0xF4000..0xFE000`, then vendor parameter/settings pages. A bootstrap APP must
fit below C4000. The primary load budget is 38912 bytes; the boot-only RAW covers
the whole A000-byte primary/config region, not SoftDevice or UICR.
Primary and installer use separate bounded RAM regions.

Keep your **exact ordinary APP ZIP** for recovery. The necessary bootstrap order
is compound APP preload, matching boot-only serial replacement, then ordinary
APP restore. The old single-bank bootloader can erase low APP pages while
staging a boot-only update, even if DFU later fails. Never infer APP preservation
from a rejected package or a successful vendor exit status.

Before any write, verify physical board/BSP, bootloader version, stable boot USB
endpoint, package hashes and available recovery. Enter vendor DFU manually,
then use the existing vendor serial command for each explicitly selected ZIP:

```sh
# Run separately, inspecting BOOT enumeration/readback after each step.
python3 "$NRFUTIL" dfu serial --package "$COMPOUND_ZIP" --port "$BOOT_BY_ID" --baudrate 115200
python3 "$NRFUTIL" dfu serial --package "$BOOT_ONLY_ZIP" --port "$BOOT_BY_ID" --baudrate 115200
python3 "$NRFUTIL" dfu serial --package "$APP_ZIP" --port "$BOOT_BY_ID" --baudrate 115200
```

Do not automate through an uncertain step or auto-select another USB endpoint.
Package validation is not installation confirmation; inspect the actual
bootloader/application and normal service afterward.
`tools/commission_pair.py` can validate a compound against the selected pair and
ordinary restore ZIP; its bounded readback callback does not discover hardware.

The compound preload is for the **old vendor bootloader**, before replacing
the primary. Once the paired primary is installed, serial APP recovery must use
the exact **ordinary APP-only ZIP**, not the compound: the new primary protects
the fixed installer region and rejects an application extending into it.
Do not repeat the old bootstrap sequence to recover an already paired board.

### No USB after an interrupted bootstrap

First check the target's own USB-C data cable and connector. Target power and a
working USB debug probe do not establish a USB data connection to the target.

SWD diagnosis on a non-enumerating XIAO Sense found two separate problems: a
bootloader update had displaced the ordinary APP, and the old primary trapped
before starting USB. Its early `usb_init` call queried
`sd_softdevice_is_enabled` (`SVC 0x12`) before SoftDevice interrupt forwarding
was initialized, entering the primary's default SVC handler. This was not a
HardFault or an MBR command (`SVC 0x18`). The current vendor patch uses a
phase-aware wrapper so cold-entry USB setup does not issue that premature
SoftDevice call.

When USB recovery cannot start, identify the actual board/BSP and role through
SWD before writing anything. Diagnose the executing primary and APP vectors;
do not symbolize an old physical image using a newer ELF. Preserving recovery
restores only the matching primary/config region and fixed installer region,
then uses the recovered vendor serial port to restore the ordinary APP-only
ZIP. Keep the SoftDevice, UICR, parameter/settings pages, filesystems, QSPI
transactions, public identity and confirmed counter history intact. Never use
mass erase, unlock/recover or a merged HEX as a substitute for this diagnosis.
Check normal USB service, public identity and OTA status after recovery; a
subsequent real signed LoRa installation is still required to establish OTA
operation.

On a previously confirmed device, a different APP restored over USB does not
replace the confirmed OTA image hash or counter. An image mismatch can therefore
keep userdata writes and software-requested UF2 recovery disabled even though
the application enumerates. Enter vendor recovery with the physical double
reset and restore the **exact previously confirmed APP**, or perform an
authorized compatible OTA update with a higher counter. Do not erase or lower
the confirmed floor to make an unrelated USB image appear qualified.

**Do not copy bootloader-update UF2 files to the board.** Vendor UF2 self-update
can remap writes into protected ExtraFS even when the UF2's own addresses look
safe. `tools/install_uf2.py` is now an offline artifact validator only; it does
not flash or authorize a physical UF2 copy. Mass erase is not normal recovery.

Direct nRF hardware deployment has succeeded. Solar hardware bootstrap/update,
ESP hardware behavior, routed/fleet delivery and untested power-loss conditions
are not qualified. See the [product guide](../../docs/lora_ota_users.md).
