# nRF52840 paired LoRa OTA bootloader

The optional nRF backend needs a matching small primary and a fixed returning
installer, not just a new application. The primary provides vendor CDC serial/BLE recovery; native USB serial
bench recovery additionally supports fresh pair replacement. The installer processes signed QSPI transactions,
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
  XIAO_OTA_PAIR_APP_PACKAGE="$APP_ZIP" XIAO_OTA_PAIR_APP_CONTEXT="$APP_CONTEXT"
```

Use `xiao_nrf52840` for non-Sense XIAO or `sensecap_solar_p1` for Solar pair building; do not
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
  XIAO_OTA_PAIR_APP_PACKAGE="$APP_ZIP" XIAO_OTA_PAIR_APP_CONTEXT="$APP_CONTEXT"
make test-xiao-ota-bootloader-pair \
  XIAO_OTA_PAIR_BOARD=xiao_nrf52840_sense XIAO_OTA_PAIR_ROLE_ID=0 \
  XIAO_OTA_PAIR_APP_PACKAGE="$APP_ZIP" XIAO_OTA_PAIR_APP_CONTEXT="$APP_CONTEXT"
```

Native pair tests exercise the actual returning adapter and reject the legacy
reset adapter. Host tests create/reparse standard packages and reject changed
board/role, APP, stage, init bytes, CRC, extra images and mismatched readback.
Passing software tests are not proof of physical installation.
When no actual APP ZIP/build context is supplied, real-APP packaging tests are
skipped; native pair tests still run. Deployment packaging requires both.

Capture the compiler's actual role/board and freeze ELF/ZIP/APP bytes outside
`.pio/build` using the build-only target:

```sh
make build-xiao-ota-usb-app \
  XIAO_OTA_PAIR_BOARD=xiao_nrf52840_sense XIAO_OTA_PAIR_ROLE_ID=1 \
  XIAO_OTA_APP_FREEZE_DIR="$PWD/.tmp/ota-boot-builds/my-real-app"
# APP_ZIP=my-real-app/firmware.zip; APP_CONTEXT=my-real-app/app-build.json
```

An explicit `ENV=...` selects an existing configured installer environment;
the compiler flags, not its name, must match the requested role. Capture
currently supports the XIAO family, not a Solar APP qualification contract.
The context binds the operator-trusted build's board profile, actual compiler
role, firmware/ZIP/ELF hashes and radio defaults; it is not a signature or RF
qualification. Pair/package/commission checks reject mismatches before DFU.
**Default repeater USB builds remain 869.618/BW62.5/SF8/CR5/TX22.** They are not
the nRF lab's 907.525/BW250/SF7/CR5/TX2 configuration. Review the captured defaults
and use an appropriately configured environment before bench deployment.

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
then use the guarded Make recipe below for each explicitly selected ZIP. The
vendor CLI catches failed-transfer exceptions and can exit zero; the wrapper
uses its exception-propagating DFU API instead and rejects unexpected results.

Do not automate through an uncertain step or auto-select another USB endpoint.
Package validation is not installation confirmation; inspect the actual
bootloader/application and normal service afterward.
`tools/commission_pair.py` can validate a compound against the selected pair and
ordinary restore ZIP; its bounded readback callback does not discover hardware.

The compound preload is for an **ordinary vendor bootloader** or the new
**physical USB fresh-bench mode** described below. Software-requested recovery
and BLE still accept only the ordinary APP-only ZIP below the protected
installer; they cannot replace a pair. Legacy locked pairs do not support the
new physical bench mode.

### Fresh bench commissioning versus field OTA

Bench USB commissioning may be explicitly authorized as a clean-slate operation:
keys, configuration and OTA history can be reset and the user reconfigures the
device. That is distinct from a field OTA update, which must retain identity,
configuration, durable counters and the existing signed-install/rollback safety.
No field OTA permission, role check or counter policy changes for bench use.

Newly built pairs implement `serial-usb-cdc-fresh-v2`, recorded in the source-bound
pair/package manifests. With USB attached, **one reset-button press** selects CDC
recovery, independent of retained RAM or combined reset-reason bits. Existing
software-requested vendor USB recovery is also supported. Wait for the target's
BOOT CDC endpoint and run the explicitly selected guarded phase below. No rapid
double tap, power-cycle sequence or timed dwell is required by this profile.
USB recovery has no startup expiry.

Entry or USB power alone is not fresh-write admission. The actual SDK serial
START dispatcher, compiled for native USB (not UART), admits bench only with
configured USB, VBUS, disabled SoftDevice, non-BLE mode and unlocked pair regions.
Only then does it extend the SDK's upload bound and enable the existing fresh
reset callback. GPREGRET, reset tokens and buttons cannot themselves grant it.
This trusts a local USB uploader, not an authenticated remote publisher:
the unchanged vendor wire protocol has no `--fresh` bit. The host wrapper requires
explicit fresh/device/board/role/APP context before contacting the device, but
other local serial clients can also request a destructive upload.

Normal boot establishes both ACL locks before calling the signed installer or
APP; BLE recovery establishes them before enabling BLE. USB recovery defers those
locks without giving an APP execution grant. If normal installation qualification
fails after locks have been established, the primary resets once into vendor USB
recovery rather than trying to unlock ACL. Field role/signature/floor/trial policy
is unchanged. USB MSC/UF2 is omitted to fit the fixed primary budget: use Adafruit
serial DFU ZIPs, not BOOT-update UF2 copies.

Earlier `physical-double-reset-cdc-fresh-v1` pairs retain their old entry
requirements; these new instructions do not retroactively change installed code.
Their invalid-stage unknown-marker procedure is genuine power removal, USB
power-on/new BOOT enumeration, single reset/new enumeration, then single
reset/new enumeration. The old primary writes the retained marker before USB
initialization, so no extra dwell is needed after each new enumeration; enumeration
still does not prove its grant. Do not reflash an already qualified installer
merely to adopt the new bench workflow.

Entering physical bench recovery alone performs **no erase**. The first
accepted, bounded upload resets the complete 2 MiB QSPI store (including keys,
configuration and OTA records/floors) and internal userdata `0xD4000..0xF4000`,
with readback and fail-closed I/O checks. SoftDevice, UICR and SDK/MBR parameter
pages are not part of that userdata wipe. This is deliberately destructive
bench commissioning, not a field migration. If the fixed stage is displaced,
only compound/BOOT repair uploads may defer that erase; the final ordinary APP
phase requires a matching stage and performs the fresh reset. Accepted bench
uploads also replace SDK metadata with a fresh invalid-APP receipt, permitting
an explicit retry after corrupt/interrupted pending metadata; ordinary recovery
continues to reject those cases.

Build/package the real intended APP and exact new board/role pair as above.
Then run **one phase at a time**, checking the actual BOOT USB endpoint before
each phase. If the APP is running, press reset once with USB attached to enter
the new profile's recovery:

```sh
# Set PAIR_DIR, PACKAGES, APP_ZIP and BOOT_BY_ID to your verified artifacts/device.
# Execute separately for compound, then bootloader, then application.
make commission-xiao-ota-usb \
  XIAO_OTA_PAIR_DIR="$PAIR_DIR" XIAO_OTA_PAIR_PACKAGE_DIR="$PACKAGES" \
  XIAO_OTA_PAIR_BOARD=xiao_nrf52840_sense XIAO_OTA_PAIR_ROLE_ID=1 \
  XIAO_OTA_PAIR_APP_PACKAGE="$APP_ZIP" XIAO_OTA_PAIR_APP_CONTEXT="$APP_CONTEXT" \
  XIAO_OTA_USB_PORT="$BOOT_BY_ID" \
  XIAO_OTA_USB_BOOT_POLICY=physical-usb-bench XIAO_OTA_USB_FRESH=1 \
  XIAO_OTA_USB_PHASE=compound
```

Use `ordinary-vendor` for the initial compound/BOOT phases when the actual
starting BOOT is the ordinary vendor implementation; the final APP phase uses
the newly installed physical bench pair. The target validates each ZIP against
the selected real APP/compiler context and source-bound pair before invoking
the standard vendor serial DFU API. It does not discover ports, toggle DTR,
advance automatically,
or infer installation success from package validation or nrfutil exit status.
Only this bench invocation extends the vendor serial ACK deadline to 1800 seconds:
the fresh reset may erase 512 QSPI sectors, each with an existing 3-second
hardware deadline. Field transports and vendor DFU packet formats are unchanged;
an interrupted upload remains an interrupted commissioning operation.
Do not use `physical-usb-bench` to relabel a legacy locked pair.

BOOT-only replacement uses the vendor's MBR copy primitive and an SDK padding
marker written only when a USB-admitted BOOT upload completes. After that
verified upload returns, the primary rechecks its bounded receipt and CRC and
performs the MBR copy in the same USB-admitted session; no additional physical
reset authorizes it. Wait for the new BOOT endpoint before the final APP phase.
The writable SDK marker alone never grants BOOT replacement: ordinary pending
updates still require
already-identical primary bytes. The accepted BOOT upload persists its actual
vendor-validated CRC and extent; the same-session copy guard recomputes that CRC before
copying. An interrupted BOOT phase is not silently resumed on normal or BLE
entry; explicitly re-upload the selected verified BOOT package in USB recovery.
The real SDK getter copies all 28 bytes, including the persisted marker,
rather than leaving implicit padding uninitialized. SDK padding remains
preserved when finalizing, as in ordinary recovery.
A primary update can displace
the APP, so the final ordinary APP phase is mandatory. After any failed or
interrupted phase, stay in recovery, inspect the actual USB/board/pair state and
retry the explicitly selected correct phase; do not infer a completed pair.

Verify actual new-role BOOT/stage/APP qualification, fresh public identity,
usable filesystem/configuration and a durably initialized floor0 on a cold boot.
Reconfigure the device and administrator permissions explicitly. A subsequent
real signed OTA install must still confirm normally and advance the floor; all
field role/signature/counter/rollback protections remain unchanged. Packaging
and native tests do not establish physical USB or RF qualification.

#### Legacy locked-pair limitation

Already installed legacy pairs predate this physical bench facility. Their
USB/serial/BLE recovery cannot replace the frozen pair, even with authorization
to erase configuration and counters:

- `pair_explicit_escape()` recognizes all four DFU GPREGRET values, physical
  double reset and the DFU button. Escape skips the installer; it does **not**
  skip the unconditional `pair_lock_protection()` in the generated primary
  before `check_dfu_mode()`. Both ACL write locks still apply in recovery.
- Patched serial/BLE `dfu_start_pkt_handle()` rejects any update mode other
  than `DFU_UPDATE_APP`, including BOOT-only and combined images.
- Patched `write_block()` accepts only sequential, bounded APP-family UF2
  blocks. The vendor BOOT-family remapping path was removed, not just hidden
  from the host tool.
- The pending SDK BOOT path is not an alternate update channel.
  `xiao_ota_vendor_pending_check()` requires `dfu_bl_image_validate()`, which
  performs an MBR comparison against the **already installed** primary.
  Patched `dfu_bl_image_swap()` no longer issues `SD_MBR_COMMAND_COPY_BL`.
  This can finish already-identical legacy metadata, not install different code.

This is an implementation restriction, **not** an inherent nRF52840 need for
SWD during ordinary USB commissioning. The unmodified vendor BOOT supported
BOOT updates; this overlay removed that path. Physical double reset re-enters
the same restricted policy, and a power cycle clears the ACL only until the
primary immediately establishes it again before USB DFU. The new selected-primary
test exercises protected normal/BLE boot, non-authorizing recovery entry and
actual USB START admission, including a displaced stage.

Resetting floors or configuration cannot add a missing BOOT write path.
An APP cannot rewrite either locked region, and uploading another APP cannot
change the old primary's policy on its next reset. No host package/Make target
can retrofit USB BOOT updates into that installed image. The new bench path must already be present in the installed BOOT; it cannot
retroactively modify the old primary. Recovering a legacy pair consequently requires
separately approved one-time service recovery or selecting a properly provisioned
target; SWD is not presented as a routine commissioning workflow. Do not bypass
protection, fabricate recovery success or claim an APP-only USB flash changed
the actual installer role.

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
