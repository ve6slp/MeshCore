# nRF52840 bootloader commissioning failure notes

Target: `3BE94917B92DC5E9`. Incident: Oct. 2, 2026, `13:46:21Z`.

The replacement radio target is `77CD44653A967172`. This incident and its
paused SWD diagnosis still concern only the original failed `3BE...` unit,
bound by `[recovery] target` in the lab inventory, not the active OTA role.

On Oct. 3 the replacement successfully completed a separately reviewed
official Sense OTAFIX 2.3 bootloader-only serial update, documented in
[the hardware lab results](hardware_lab.md). USB recovery returned after
the user's double reset, and ordinary then corrected OTA applications retained
settings/identity/ACL through a final physical reset. That positive vendor-route
result on a different unit does not establish the original target's installed
bytes or explain its failed custom-loader activation.

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

## Later source review is not an incident diagnosis

The code-only review of baseline `ccc0a77b` established two separate
reliability defects: the QSPI adapter did not await physical erase/program
completion or cancel pending buffer access on timeout, and destructive APP
copies could keep the SDK bank VALID while QSPI failure handling forced
recovery even for an intact APP. Corrections require bounded physical flash
completion and a durable invalid-before-copy/valid-last boundary.

Those error paths request vendor recovery; neither finding by itself
explains persistent absence of USB on `3BE...`. The failed board has not
received the later changes, and source fixes cannot establish its installed
bytes, PC or fault state.

The [recovery architecture assessment](lora_ota_nrf52840_qspi.md#bootloader-reliability-review-and-isolation-options)
compares same-map corrections, whole-loader A/B and a frozen OTAFIX primary
with a fixed internal installer. A separate stage can isolate installer
failure from recovery after commissioning, but cannot preserve the old
primary during its first replacement or recreate a lost QSPI backup.
That assessment itself did not repartition storage or operate hardware.

The later integrated source exceeds the current boot region by 524 bytes in
all four board/role profiles. The user approved source work on the frozen
OTAFIX-primary/internal-installer direction, not a new device flash. Vendor
APP erasure before SDK invalidation is also a coupled recovery-write gap;
it must be closed before claiming global zero-CRC fallback safety. None of
these source results establishes what ran on the failed board.

### Paired-primary source review

The first private OTAFIX-primary/64 KiB installer prototype fits its assigned
regions in four ARM board/role builds. Those primaries still refuse APP writes;
their fit does **not** establish a complete USB/BLE recovery implementation.
The frozen source review found a mandatory recovery-exit defect that has not
been flashed on any unit:

| Finding | Mechanism and required outcome |
|---|---|
| P1: DFU return can strand the node in BLE DFU | An explicit escape skips the installer. When DFU returns, the primary's tail sets GPREGRET `0xA8`, which is itself another installer escape. The next boot therefore re-enters BLE DFU instead of validating the installer and APP. Clear the old double-reset marker and request a normal reset after DFU returns; the next boot must run the fresh installer gate, never reuse an earlier APP grant |
| Fault recovery remains unqualified | The inherited HardFault handler loops. An installer fault before a watchdog is running can strand a remote node; local reset escape is not proof of automatic fault recovery |

P1 is source-closed in the separate recovery-exit snapshot: an independent
Make replay passed 1,024 two-boot cases and the compiled old-`0xA8` negative
control. These are not hardware results. Preserve the vendor's app-requested
serial/UF2 timeout separately from persistent recovery forced by an unusable
installer.

The same review found R1: the production installer requested recovery by
resetting with GPREGRET `0x57`. The paired primary interprets that as an
ordinary app-requested, three-second DFU session, then retries the failing
installer. Live integration must instead return a stage-only recovery latch
through the existing runtime ABI; every force-recovery call must stop before
any subsequent write. The selected Sense role1 live pair passed the independent
actual adapter/kernel/runtime/caller replay and compiled old-reset negative
control. R1 is source-closed; physical recovery remains unqualified.

BLE APP recovery and legitimate pending-update completion must remain
available in the final primary; the limited serial/UF2 writer proof that
refuses those paths is not accepted as complete. Recovery writes must use
primary-local SDK invalidation/publication without QSPI or installer
dependencies, and successful recovery must re-enter the fresh installer gate.
The preserving vendor-writer snapshot passed an independent Make replay of
38 writer cases, five ordinary UF2 cases, four primary-only cases and 12
compiled assertion controls. Those results do not establish the combined
primary's ARM fit, integration or physical recovery behavior.
ACL/S140 coexistence and physical fault/reset timing remain unqualified.

Live integration must reduce only the nRF OTA internal install limit to
643,072 bytes (`0x27000..0xC4000`). External image regions, identity/security
tails, journal, filesystems and scratch addresses stay fixed. Generic/ESP
transfer limits and ordinary firmware linker limits must not be reduced as a
side effect. The private test snapshot's globally reduced geometry is not
evidence that those existing behaviors are preserved.

### Selected development commissioning sequence

After the user's development-hardware scope correction, Opus 5.5 and GPT-6
Astra reviewed the source and ordered rollout. Keep the measured fixed
primary/installer split and F1/F2/P1/R1 corrections; defer the optional
fault/lockup layer and generalized legacy-compatibility machinery. Manual
reset remains the first bench's fault escape, not an unattended-recovery
guarantee. SWD is not a technical prerequisite for this supervised serial
attempt, but no chaining arrangement protects the first primary replacement.
Losing all USB recovery at that step would require SWD.

Use `77CD...` as the canary and leave `4186...` as the working uploader:

1. Under its working OTAFIX primary, establish healthy SDK state with no
   pending legacy update and retain identity, preferences and the full ACL.
2. Preload an ordinary APP-only serial image containing the known working
   APP prefix, erased-byte padding and the matching fixed installer at
   `0xC4000`. Enforce an erase end no later than `0xD4000`; the old vendor
   admission ceiling is `0xEA000`, not our filesystem-preserving boundary.
3. Compare only the authorized APP/installer bytes through `CURRENT.UF2`
   before replacing the primary. Do not retain its filesystem blocks.
4. Replace the matching primary once through bootloader-only serial DFU.
   Low-APP staging erasure is expected. Its actual erase callback publishes
   bank0 INVALID, CRC0 and size0; the new primary must finalize the identical
   pending loader before the installer gate. The old loader retains GPREGRET
   `0xA8` across the MBR copy reset, so the first new-primary boot enters BLE
   advertising without USB. This is expected, not an activation failure.
   Reset only the canary once, then require persistent R1 UF2 USB recovery.
   Stop loader writes if USB still does not enumerate after that reset.
5. Restore the final ordinary APP-only firmware within 643,072 bytes. Verify
   the installed image, configuration, installer capability and genuine
   factory state, then run signed LoRa install/confirmation and rollback.

The corresponding guarded Make entry points are
`commission-xiao-nrf52-target-preload`,
`lab-bootloader-uf2-target`,
`lab-mount-xiao-nrf52-target-commission-uf2`, and
`commission-xiao-nrf52-target-primary`. Pass the same reviewed
`XIAO_OTA_PAIR_DIR` and `XIAO_OTA_PAIR_PACKAGE_DIR` throughout. The preload
target waits for the temporary APP; check its SDK is VALID, size 659,548,
CRC0, bank1 `FF`, and marker blank before requesting UF2. The primary target
validates its package and performs live bounded compound readback before
the one transfer; it deliberately does not wait for an APP or immediate USB.
After the one physical canary reset, `lab-wait-target-bootloader` and the
read-only mount command check the recovery USB path before restoring the
ordinary APP with `flash-xiao-nrf52-target`. No target retries loader writes
or requests a power cut.

The old serial APP publisher stores SDK CRC0 even when the package/transfer
CRC is nonzero. Transport completion is not installed-byte evidence. A
healthy restored APP may legitimately initialize factory counter0; an invalid
or staging APP must not write the floor, and commissioning must not erase
authoritative history or advance the counter.

The fresh read-only baseline on October 3 retained both nodes' identities,
radio preferences and the canary's complete ACL. The canary reported healthy
bank0 VALID, bank1 `FF`, APP size 538,360, SDK CRC0/computed `B968`, and boot/
parameter addresses `0xF4000`/`0xFE000`; both nodes still reported CACHE_ONLY.
This is not an installed custom pair. The selected full-BLE Sense role1
primary now uses 38,748/38,912 bytes and its installer 16,476/65,536 bytes.
Independent Make rebuilds produced identical HEX, boot-only RAW and installer
bytes. The focused old-loader-to-pair sequence passed serial and UF2 restoration;
review closed its identical pending-finalization dependency and confirmed the
first-boot BLE/single-reset expectation above. These are source/native results,
not physical USB/S140/QSPI proof. The compound packager also passed independent
Make reproduction and source review. Its host-only additions leave all runtime
source fingerprints and the measured HEX/RAW/installer bytes unchanged.
The guarded host integration and exact-command review are now source-closed.
The canary's working APP uses USB PID `8044`, while its Sense recovery loader
uses `0045`; the host admits that APP-to-loader transition without weakening
the bootloader identity check. An October 4 read-only preflight found both APPs
healthy, with blank markers, no pending bank1 and CACHE_ONLY capability.

The first supervised canary attempt then completed the 659,548-byte compound
preload. Its SDK reported VALID, CRC0/computed `D1B2`, size 659,548, bank1 `FF`
and blank marker; identity, radio settings, path mode and full ACL were unchanged.
The complete authorized compound readback matched before the one bootloader-only
transfer. Recovery USB remained present, and one operator pin reset again
produced persistent Sense recovery CDC/MSC with an ancestry-matched read-only
mount. The predicted first-boot BLE-only branch was not observed.

Restoring the ordinary 537,256-byte APP through serial DFU then failed while
sending the init packet, before image-data progress: the endpoint returned EIO
and subsequently re-enumerated in recovery mode. The transport tool printed an
error despite exiting zero; the host's APP wait correctly failed. Recovery USB
remains accessible. This is a new physical qualification blocker, not a diagnosis
of the failed original unit. No second primary write, shared-power operation or
operation on Pine occurred.

The recovery volume's public INFO text matches the selected primary's compiled
version, board, build date and SoftDevice metadata. That supports activation,
but is not a full installed-primary hash. The actual ARM return/stack review
found no ABI defect. Serial transport acknowledges START before its scheduled
DFU handler runs; a failed START result reaches an explicit reset. Consequently,
the later INIT-write EIO neither proves successful START processing nor identifies
which flash operation failed. The SDK/flash diagnosis remains open, and UF2 is
not an assumed workaround because it shares the preparation barrier.

The reviewed host correction rejects a nonzero transport exit, failure diagnostics
even with exit zero, and missing vendor completion output. The pinned CLI appends
`Device programmed.` to its final progress `#` marks, rather than necessarily
starting a new line. The last nonempty stdout line must contain only those marks
and the exact completion message. Diagnostic matching does not reject incidental
words in package or port paths. CLI output is preserved and pre-transfer messages
are flushed; failure does not proceed to an APP wait or retry. Completion still
means transport only, not activation or installed-byte verification. This host
correction does not resolve the firmware failure.

A subsequent guarded read-only capture found all 122 APP pages in
`0x31000..0xAB000` unchanged from the proven pre-BOOT compound. The lower ten
pages match the transferred bootloader RAW's staging copy, and no fully erased
APP page was observed in `0x27000..0xAB000`. The exact 16,476-byte installer
still matches its reviewed SHA-256. This provides no evidence of a successful
APP erase, but does not reveal the failed SDK/START predicate or replace a
post-BOOT, pre-START snapshot. The staging copy is not a readback of the installed
primary at `0xF4000`; SDK settings remain unavailable through CURRENT.

The next recovery input was the official
`Xiao_nrf52_repeater-v1.17.1-d929643` release, not the special OTA APP or
the Solar/ThinkNode board variants. Publisher digests matched the downloaded
ZIP (`b71d24fb9fd379207f7d888e1006d315388e0b530138350ff08466c1b6e3529a`)
and UF2 (`1abc70deec75e375f8e1d1f984ed839b443bbaf6fe03803426a710dd622cef55`).
All 1,515 UF2 records contain the 387,752-byte APP plus 88 erased padding
bytes, wholly within `0x27000..0x85B00`; no loader, SoftDevice or filesystem
image is included. The first host invocation refused before any unmount or
write because its expected INFO suffix incorrectly included the word
`version`. The pinned formatter and live INFO both say
`SoftDevice: S140 7.3.0`. A narrow host correction retained exact metadata
matching and regenerated a separate proof without changing the official UF2.

The one actual stock UF2 copy then reached the approved read-only-to-read-write
mount transition but returned EIO. A separate 30-second APP wait failed:
77 remained in Sense recovery mode. This is not stock restoration or proof
of a particular SDK failure. After a guarded same-device return to read-only,
the 05:12 UTC capture found zero of 95 APP chunks matching stock and all
132 APP page digests unchanged from the immediate pre-copy capture. The exact
installer hash still matches. The attempted copy left no observed APP change;
the SDK page and failing preparation predicate remain unobserved. Firmware
writes are stopped. SWD and additional qualification boards are still
unavailable, as confirmed by the operator. No additional primary transfer or
automatic APP retry was made.

The selected primary also synthesizes flash-backed UF2 records for raw MSC
reads beyond CURRENT's declared file length. Its read handler bounds the
payload to the physical 1 MiB flash. This allowed a guarded, read-only
`O_DIRECT` capture without SWD: SDK LBAs 4587-4602 map to
`0xFF000..0x100000`, and primary LBAs 4411-4570 map to
`0xF4000..0xFE000`. Each readback record was validated independently; these
beyond-file records are not valid programming files and must never be
copied back. Only digests and decoded SDK fields were saved.

The 05:31 UTC capture finally proves the entire installed primary matches
the reviewed boot-only RAW SHA-256
`93df3f04530d170acf097fa77a3cf5363207275882f48fbb38c6573ec8c472b5`.
The SDK has bank0 INVALID (`FF`), CRC0 and size0; bank1 remains VALID_BOOT
(`AA`), with bootloader size 40,960, SD/app sizes0 and SD image start0.
The alignment word is0 and all bytes after the 28-byte settings record are
erased. The observed pending-BOOT marker independently blocks APP
preparation. No SDK repair, reset or further firmware transfer has been
performed.

Replaying the exact captured tuple against the selected pending handlers
accepts SD image start0, validates the identical staged primary, clears
bank1, and permits APP preparation when the modeled runtime services
succeed. Changing the SDK start-address policy is therefore not justified.
The initialization-order reproduction instead exposes the defect: on cold
entry, early pending handling issues SDM SVC `0x12` before MBR service routing is
initialized. The selected bootloader's SVC handler accepts peer-data SVC0
but returns HANDLER_MISSING for that query. The strict SDK check sets sticky
poison, leaves the captured settings unchanged, and forces USB; subsequent
APP transfers also fail without writing APP data. Initializing routing
later does not clear that poison. This source/native failure matches the
physical observations; the lost hardware return code itself was not captured.

Earlier native qualification always returned SUCCESS/disabled from the SDM
leaf, supplying a runtime precondition that the real startup lacked. The
correction must explicitly preserve cold-entry and B1 APP-jump routing
state and keep initialized-service errors fatal. Unconditionally moving
INIT_SD earlier is unsafe: the MBR operation executes the SD reset function,
which must not run on a partially swapped SD. Pending-SD continuation must
retain its original ordering. The current installed primary has no
supported USB command to install the correction; reset alone repeats the
defective startup.

### Reviewed lifecycle correction, not installed

The correction captures the original B1 routing state at main entry, before
any forced-recovery marker overwrite. Cold entry knows the SoftDevice is
disabled and does not issue the unavailable query. Initialized queries remain
strict; SDK query errors still poison the driver. The existing MBR helper now
checks INIT_SD success before setting the routing latch. Pending-SD continuation
still precedes INIT_SD, and all SDK, primary, serial, UF2, flash and USB query
sites use the same policy.

Independent review closed the six-file correction. Root rebuilt its exact
prospective source tree and reproduced primary RAW SHA-256
`fbe2db4591114e4125f492daa650aa0394e8c7baedfc446318b38be38f0c38b1`,
with 38,748/38,912 LOAD bytes. Installer bytes remain unchanged
(`7809324747eda396bc25662a5f0b84498e4bc6dba1dee560970c7acc4c3b4ae7`).
The selected main/helper, packaging and boot-process gates passed, as did
seven actual-caller lifecycle cases, including the captured SDK tuple,
serial/UF2 restoration, stale-B1 refusal and pending-SD ordering.
SVC routing, MBR/NVMC and QSPI hardware leaves were modeled, not run on77.

The subsequent hardened correction supersedes that artifact: boot entry must
be explicitly recorded or queries poison and fail closed; both later routing
latch overrides are removed, and an MBR initialization failure poisons before
the latch can advance. The primary query is wired directly in its source.
Independent review closed this delta, and Root's exact-tree rebuild reproduced
RAW SHA-256
`00359046ef0b3668b1c46599933162961ce540d20e776798317c435506a438c5`,
with 38,876/38,912 LOAD bytes and the same installer. Twelve actual-caller
lifecycle cases passed, including unrecorded entry, stale B1 and failed MBR
initialization from both APP and BLE callers. Neither correction has been
installed on77.

The restoration cases use a matching corrected staged primary. They do not
establish that replacing only77's live primary is sufficient: its APP staging
copy still contains Source21. Before any physical repair, qualify that original
pending-image binding and the exact repair write set without weakening it.
77 remains on Source21 in USB recovery; no further firmware write or reset
has occurred. Delivering the correction requires the missing probe and
explicit authorization for the bounded repair, then actual stock1.17.1
version, identity, settings, full ACL and normal-peer confirmation.

The operator subsequently authorized needed writes on both approved nRF
devices, 41 and77, while continuing to exclude Pine. Write permission is no
longer the blocker; the installed77 loader still has no supported USB route
for this repair. The healthy41 remains available for APP, cache and radio
qualification independently of the missing probe.

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
