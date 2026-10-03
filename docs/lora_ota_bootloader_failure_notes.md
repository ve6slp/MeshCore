# nRF52840 bootloader commissioning failure notes

Target: `3BE94917B92DC5E9`. Incident: Oct. 2, 2026, `13:46:21Z`.

## Assessment

The observed failure is **no USB return after the activation request**, not a
proven failed transfer. The vendor tool printed `Activating new firmware`
and `Device programmed.`, with empty stderr. That does not prove that the
MBR completed the copy, that the new loader executed correctly, or that USB
initialization was reached.

The leading software concern is the attempted loader's early OTA startup
path: it runs before normal USB recovery and originally lacked a reset escape
from a stalled hook. A stalled peripheral wait or an early fault could therefore
leave a programmed board invisible to USB. **This is a hypothesis, not an
installed-image diagnosis.** A pending/failed MBR handoff or different installed
bytes remains a competing explanation until SWD provides current evidence.

The expected loss of the application alone is insufficient to explain the
missing USB loader. The vendor loader should still offer DFU with no valid
application. A solid red LED is not evidence of CPU execution, a particular
fault, or permanent hardware damage.

These are ranked **triage priorities**, not measured probabilities:

| Rank | Hypothesis | Evidence for and against |
|---|---|---|
| 1 | Pre-USB startup stall or fault, especially OTA/QSPI | The attempted compiled image calls the hook before pending-update handling and USB. Peripheral deadlines assume a live DWT counter, and double reset cannot bypass this early hook. Against: an ordinary QSPI error requests GPREGRET `0x57` and resets, allowing the next boot to bypass the hook; a simple read error or absent genesis alone does not explain persistent absence |
| 2 | MBR activation/copy or pending-update completion failure | Copy and finalization occur after transport acknowledgement. Against: the reference vectors, CRC and destination geometry are valid; actual installed bytes, original stock implementation and post-transfer metadata remain unknown |
| 3 | USB/HFXO startup wait before pull-up | The attempted vendor USB driver contains unconditional readiness/clock waits before enabling pull-up, capable of producing no enumeration. Against: the board's earlier stock USB operation makes a permanent hardware clock defect less compelling; it does not prove this newer driver initialized successfully |

No target writes, reset, power manipulation or probe access were performed
while preparing these notes.

## What was actually established

| Observation | Meaning and limit |
|---|---|
| `13:24:51Z`: fresh addresses selected boot `0xF4000`, parameters `0xFE000`; MBR override words erased, UICR matched | Address compatibility before the operation, not current installed state |
| `13:32:40Z`: selected application bytes from `CURRENT.UF2` matched all 536,152 bytes of the immutable `47b40e59` image | Independent pre-operation application proof; no bootloader or CF2 readback |
| Stock identity reported `Seeed_XIAO_nRF52840_Sense`, USB `2886:0045`, loader `0.6.1`, S140 `7.3.0` | Public identity matched the Sense package; exact installed stock-source lineage remains unknown |
| Guarded no-write dry run passed package, identity and address checks | The guards accepted that evidence; it did not exercise activation |
| Actual transport printed positive completion and empty stderr | Transport acknowledgement, not installed-loader or genesis proof |
| Kernel recorded disconnect at `13:46:21Z`, followed by no target re-enumeration | Activation/early boot did not yield usable USB; no CPU/fault diagnosis |
| One target-only reset and the user's disconnect/reconnect did not restore USB | Recovery attempts did not help; disconnecting USB is not proof that every power source was removed |

Kernel evidence displays `07:46:21` local time, corresponding to `13:46:21Z`.
Old address evidence must not be re-stamped or substituted for the new SWD
capture.

The attempted artifact was the immutable `e79e0f4d` Sense role-1 loader,
vendor source pin `c67f0bcf0fa8e841426335b1bbde91cda6ca1f50`, compiled
version `0x00000B00`. Its legacy initialization packet specified device
`0x0052`, revision `52840`, SoftDevice requirement `0x0123` and CRC16 `0xBA98`.

| Preserved artifact | SHA-256 |
|---|---|
| Attempted raw loader, 40,192 bytes | `abb026420db10ab473925fecc1ff2d4c19954c2292bc6e834abecdeeec704d6b` |
| Attempted serial ZIP | `060009297f9a54f145c1b708defcfb5fe97ad1e40318f17834f107cfaf5f059a` |
| Attempted ELF | `63d1ccf9015a0ac9ceec6b794950f38d58584ca6e1fe7c580ad07822511edb92` |

The console's `Dual bank` label describes a host option, not proof of preserved
application banking. Image mode `0x02` means **bootloader**, not single-bank.
The transmitted start packet contains SD/BL/APP sizes `0/40192/0`, not a
banking selector. In the inspected SINGLEBANK implementation, that route
stages bytes at `[0x27000,0x30D00)` and erases application pages through `0x31000`.
The host banner comes from `nordicsemi/__main__.py:276-293` in the installed
`tool-adafruit-nrfutil` package; it is printed before sending, not read from
the target. Its `dfu/dfu_transport_serial.py:162-181` uses the option for a
host wait-time calculation.
Its boot destination erase is `[0xF4000,0xFE000)`. The verified route avoids
ExtraFS `[0xD4000,0xED000)` and InternalFS `[0xED000,0xF4000)`, but ordinary
MBR parameters and SDK settings can change. This is the reviewed route's
geometry, **not a post-failure readback of preserved filesystems**.

Application restoration was deliberately not attempted after USB disappeared.
There was no automatic bootloader retry, journal clearing, mass erase or recovery
operation.

## Exact failed-artifact analysis

The retained RAW equals the ELF's allocated flash sections, initialized
`.data` at its flash load address, and erased padding. The ZIP contains that
same RAW and CRC16 `0xBA98`. Initial SP is `0x20040000`; the reset vector is
`0x000FC279`, pointing to Thumb entry `0xFC278`. Reference `main` is `0xFAF64`.

Code/data load occupies 38,332 bytes through exclusive end `0xFD5BC`, leaving
580 bytes before CF2 at `0xFD800`. The 40,192-byte RAW includes another 1,280
bytes of CF2, marker and padding beyond the 38,912-byte code capacity; this
is not an instruction overflow. Its exclusive end is `0xFDD00`; destination
page rounding ends at `0xFE000` without overlapping the MBR parameter page,
which the MBR uses separately by design.

Source references below use the retained artifact workspace:

```text
E = .tmp/ota-index/e79e0f4d479314af974f5958c65646cd0ce8b085
U = E/.tmp/ota-boot-builds/xiao_nrf52840_sense_ota_role1_noswd_upstream
```

| Reference evidence | Exact location |
|---|---|
| Early hook call precedes pending SDK-update test | ELF hook call `0xFB088`, subsequent test `0xFB08C`; `U/src/main.c:177-196` |
| QSPI timeout depends on advancing CYCCNT without a liveness check | `U/src/xiao_ota/xiao_ota_boot.c:48-89`; polling `0xF4372-0xF4388` |
| Double-reset marker is armed after that hook | `U/src/main.c:314-320` |
| Invalid APP normally enters USB initialization | `U/src/main.c:330-343` |
| Fault and default handlers are infinite loops | ELF `0xFC2A2` and `0xFC2B2` respectively |
| USBD READY / HFXO waits precede pull-up | ELF `0xF81A2-0xF81A8` / `0xF8236-0xF823C`; `U/lib/tinyusb/src/portable/nordic/nrf5x/dcd_nrf5x.c:1006,1065` |
| Bootloader activation records pending settings; completion is reset-driven | `U/lib/sdk11/components/libraries/bootloader_dfu/dfu_single_bank.c:250-270,736-754`; pending-copy comparison safeguard `:759-804` |
| SINGLEBANK staging erases and invalidates APP before reception | Same file `:133-171,354-382`; build selection `U/Makefile:227-230` |
| Image mode `0x02` is bootloader, not a banking selector | `U/lib/sdk11/components/libraries/bootloader_dfu/dfu_types.h:125-143` |

The later `5293427d` changes correct startup escape/order and partial-APP
gating. They neither establish this target's cause nor remove the vendor USB
waits, and were not delivered to the inaccessible board. The 60-second
watchdog is a trial-path mechanism, not protection for initial QSPI startup.

## First SWD capture

The committed helper performs bounded public-metadata acquisition; it does
not dump RAM, filesystems, QSPI contents, keys or the complete loader.
Its capture includes:

- Exact probe UID, APPROTECT and full FICR device identity before core halt.
- PC/SP/LR/xPSR/MSP/PSP, original/final CPU state and debug-enable restoration.
- VTOR and SCB fault/status registers, including CFSR/HFSR and fault addresses.
- MBR words at **`0xFF8/0xFFC`**, UICR `0x10001014/0x10001018` and effective
  boot/parameter selection. Diagnostic labels `mbr8/mbrc` are abbreviated;
  they do not mean addresses `0x8/0xC`.
- The legal effective loader's two vector words, seven SDK words at
  `[0xFF000,0xFF01C)`, and four OTA-marker words at `[0xFDC00,0xFDC10)`.
- RESETREAS, GPREGRET, reserved double-reset word `0x20007F7C`, and WDT
  RUNSTATUS/CONFIG/CRV.

| Result | Next interpretation, not an automatic repair |
|---|---|
| Thread-mode PC/LR in the reference pre-USB peripheral-wait path | Supports the startup-stall hypothesis; one sample does not prove a persistent wait or matching installed bytes |
| Active HardFault exception with relevant fault flags | Supports early fault; respect fault-address validity bits. Historical flags alone are insufficient |
| PC/VTOR in MBR or another loader, or unexpected effective addresses | Investigate activation/selection. Parameter-page address alone does not prove a pending command |
| Invalid-looking SDK app metadata | Expected staging damage may explain absent APP, but not necessarily absent loader USB |
| Rejected vector, inaccessible debug, identity mismatch or unsafe watchdog | Preserve the failure output and stop; do not chase pointers, reset or unlock |

Use the reference addresses above only for initial symbolication clues:
matching a PC range does not establish matching installed bytes. A stationary
CYCCNT while halted is normal and does not prove failure before halt.
If the PC points into a USB wait, narrowly approved USBD/clock status reads may
be useful later. If MBR continuation is implicated, the inspected single-bank
implementation can leave pending bank1 `0xAA` and BL size `0x9D00` before
finalization clears them (`U/lib/sdk11/components/libraries/bootloader_dfu/bootloader.c:304-337,360`);
those values are reference expectations, not current target observations.

Do not enlarge the capture before seeing its result. App initial MSP/reset
words, minimal verified MBR command-header fields, or exact public loader/CF2
byte comparisons may become useful later; each needs a bounded, separately
approved acquisition. A selected code-range match is not a complete installed
loader hash. The current helper captures neither the stacked faulting PC nor
an application image.

## Arrival checklist

1. Identify the actual failed target and the complete user-selected SC0889
   probe UID. Delivery or a similar USB name is not authorization to operate
   another unit. Leave the working client and Pine untouched.
2. Verify received board revisions, seating and pogo continuity. Use the
   [manufacturer-backed connector guide](hardware_lab.md#non-erasing-swd-diagnosis).
   DEBUG pins 1/2/3 are SWCLK/GND/SWDIO. J7.3 is 3.3 V and J7.6 boosted
   5 V: neither is ground or a probe-power connection.
3. Resolve the fixture's RESET contact explicitly. Its reset pogo already
   connects to K2; omitting an external reset wire does not isolate it.
   Do not press K2 or silently modify the fixture.
4. Use the verified private Python environment and the existing
   `diagnose-xiao-nrf52-target-swd` Make target. Preserve JSON and the exit
   status, including partial failed captures. No automatic retry.
5. Review the capture and reference symbolication before choosing any write.
   APP restoration, loader repair and an erase/unlock are different actions;
   none is implied by permission to diagnose.

Offline readiness verified the existing `.tmp/swd-pyocd` dependency prefix:
pyOCD `0.43.1`, builtin `NRF52840`, no probe enumeration or Session.
The alternative documented `.tmp/swd-venv` is not currently present; no
installation was needed. After, and only after, the physical gates above:

```sh
# PHYSICAL TARGET/SWD: not authorized by these notes; do not run while paused.
PYTHONPATH="$PWD/.tmp/swd-pyocd" make diagnose-xiao-nrf52-target-swd \
  SWD_DIAGNOSE_PYTHON=python3 \
  SWD_PROBE_UID='<complete user-identified probe UID>' \
  SWD_TARGET_SERIAL=3BE94917B92DC5E9 > /private/evidence/target-first-swd.json
```

The physical command was only expanded with `make -n` and an offline placeholder,
never executed. A matching package import is not a hardware/probe acceptance
result. Preserve failed JSON too; do not overwrite the first capture.

The helper refuses unsafe watchdog halts, LOCKUP/RESET/unknown CPU states,
APPROTECT and identity/API mismatches. It never resumes a preexisting halt.
For an initially runnable core it attempts normal resume, then restores an
originally disabled C_DEBUGEN only after successful resume. This does not
promise exact sleep/timing restoration. DEMCR/TRCENA are not modified.

## Recovery material already prepared

Offline Make extraction revalidated the preserved application-only recovery
ZIP; no device was accessed:

- ZIP SHA-256 `fb698a721fd72b492601d167373a26130ed1b1740d363dbafc46f434e9b2f2ee`.
- Application size 536,152 bytes; SHA-256
  `9da8a868644d80b756fbccf6ba830b56a501c0c68fb3fa947758583f3b757ab8`,
  matching the independently read pre-failure application.

The later startup corrections and four-profile boot matrix are software
qualification, not a fix delivered to this inaccessible target. Do not blindly
flash the same failed package, a corrected loader, a combined HEX, or the spare's
firmware before current evidence establishes the appropriate recovery boundary.

Private incident inputs are retained in `sense-serial-e79e0f4d`,
`commissioning-stock-info-42988482` and `pre-commission-787f3a3b`. The current
working client independently runs the reviewed `18ca2dcc` application with
healthy stock proof and verified local cache; that does not qualify target
installation, radio OTA, rollback or a genesis floor.
