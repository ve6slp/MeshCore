# LoRa over-the-air updates: administrator guide

## Scope and status

This guide explains the update policy and experimental signed host workflow.
LoRa OTA reuses MeshCore identities and administrator permissions. There is no
separate OTA authority, signing-key registry or remote commissioning service.

**LoRa OTA is not production-ready.** Bench unit41 completed a supervised
LoRa-delivered installation and healthy confirmation through an unchanged
stock1.17.1 companion and complete reader-free500kHz delivery to READY.
Unattended installation, autonomous failed-trial rollback,
physical routed delivery and fleet fairness remain unqualified. Do not use
these controls to manage a deployed network.

The last independently confirmed unit41 baseline is `ota-41-confirm04`,
with qualified `INSTALL_CAPABLE`, confirmed counter2 and the expected image
hash. Its identity, settings,
five complete contacts including administrator permissions, and all40
channels survived installation. Both radios use the authorized2dBm.
Unit77 still enumerates in a defective modified USB bootloader and requires
external repair; no blind bootloader retry, unlock or erase is authorized.
See the [hardware lab guide](hardware_lab.md) and
[incident notes](lora_ota_bootloader_failure_notes.md#arrival-checklist).

The additional stock1.17.1 companion is a separate signing/radio endpoint,
not a receiver or locally staged uploader. It has not been flashed.
The one-hop duplicate-suppression correction is installed on41; repeated
census, full-image reception, separate signed COMMIT and actual healthy
confirmation have been observed. Both completed campaigns required a
continuously drained observer for the old receiver's USB diagnostics.
The second campaign installed corrected nonblocking diagnostics and500kHz
negotiation. A subsequent campaign obtained a target-signed500kHz profile
ACK and genuine Receiving progress with no receiver USB reader.
Receiving restart/resume subsequently passed its physical boundary: one ordinary
application restart preserved all52 bitmap windows (883/6599 blocks), the same
generation13/counter3/manifest, full confirmed floor, baseline version and
functional signed owner admission. Complete userdata matched, and MissingOnly
reader-free reception resumed on the same campaign without REUPLOAD.
The resumed reader-free transfer subsequently reached6599/6599 READY at
generation13/counter3 with a complete52-window normal-channel census.
Its4900.233-second duration starts from883 persisted blocks, not an empty
candidate. A separate signed COMMIT followed another fresh52-window READY
sweep. Stock restoration passed, but the immediate native USB witness timed
out before observing any trial or return; COMMIT TX is not installation or
rollback proof. Post-COMMIT state requires read-only diagnosis, not another
COMMIT or a reset to manufacture evidence. Recovered driver-fault increases
are explicitly reported as degradation, not continuous fault-free radio
qualification; their cause and operational impact remain unresolved.

## Update policy

The following is the required behaviour, not a hardware acceptance claim.

1. Use an identity already trusted as an administrator by each target. A
   contact or shared channel secret alone does not grant update permission.
2. Sign the image manifest with that administrator's Ed25519 private key.
   Targets verify with the public key; never distribute the private key.
3. Select direct, routed or background mode and an airtime budget. A device
   can retain only one candidate and its original owner. A competing image
   or administrator receives `BUSY`; there is no automatic takeover timeout.
4. Transfer signed blocks. Duplicates do not rewrite flash. Bad or missing
   frames preserve valid progress and normal radio service. For severe loss,
   repair missing blocks or explicitly restart the upload.
5. Wait for each target's durable `READY` result after full-image validation.
   Finishing reception does not install the image or start a reboot timer.
6. Have the original owner, still trusted as an administrator, send an
   explicit, target-bound COMMIT to each target separately. Sequence commits
   to preserve network service and confirm each device has returned before
   proceeding.

Any currently trusted administrator may abort before commit. The target
then suppresses reception of that image until an explicit restart. Abort
does not hand the staging slot to a competing uploader. Once a committed
install has begun, local boot recovery completes it or restores the previous
image; a radio abort is no longer the recovery mechanism.
Vendor boot staging must tolerate interruption and retry without discarding
the recoverable running image. This remains a physical qualification gate,
not an assurance of recovery on the current bench.

After a confirmed install or completed rollback, a subsequent update can
reuse the staging slot once the device proves the previous boot transaction
has ended. A trial or uncertain outcome remains protected. A failed
reception still belongs to its original owner; failure is not permission
for another administrator to take over.

## Signed host workflow

These experimental host commands use an OTA-enabled companion's existing MeshCore
identity. They never export its private key. Each target must already
trust that identity as an administrator through its normal MeshCore
permissions; there is no separate OTA key to commission.

For nRF52840, select a qualified raw application image and a security
counter greater than each intended target's confirmed floor. Set the
shell variables `image`, `counter` and `target_key` explicitly; the last
is the target's full 64-character public-key hex string.

```sh
make ota-lab-image XIAO_NRF52_TARGET_PACKAGE="$qualified_repeater_package" \
  OTA_UPLOAD_IMAGE="$image"
make ota-lab-manifest OTA_UPLOAD_IMAGE="$image" \
  OTA_UPLOAD_MANIFEST=.tmp/update.manifest OTA_UPLOAD_COUNTER="$counter"
make ota-lab-upload OTA_UPLOAD_IMAGE="$image" \
  OTA_UPLOAD_MANIFEST=.tmp/update.manifest OTA_UPLOAD_TARGET="$target_key" \
  OTA_UPLOAD_MODE=directed OTA_UPLOAD_DUTY_MILLI_PERCENT=2000
make ota-lab-status OTA_UPLOAD_TARGET="$target_key"
```

For nRF, `ota-lab-image` extracts the exact application BIN from an
already-qualified application-only DFU package without rebuilding or
opening a board. Set `qualified_repeater_package` to that package's path.
It refuses to overwrite an existing image. A package or extracted BIN is
not, by itself, evidence of a successful LoRa installation.

The descriptor builder defaults to the XIAO nRF52840 repeater profile.
Use `OTA_UPLOAD_BOARD=sensecap_solar_p1` for SenseCAP or
`OTA_UPLOAD_ROLE_ID=0` for a companion. It produces only the 59-byte
unsigned descriptor. Upload signs it with the attached companion, fills
and seals the companion's cache, then starts the requested campaign.
Use `OTA_UPLOAD_BOARD=xiao_s3_wio` for an ESP32-S3/Wio application.
That descriptor uses logical address `0x10000` and a maximum image size of
2,749,824 bytes; the target selects the inactive physical slot. Use the
raw application BIN, never a merged bootloader/partition-table image.
ESP build support does not establish physical installation or rollback.

`OTA_UPLOAD_MODE` selects `direct`, `directed` or `background`. Directed
and background modes use the normal mesh settings. Background accepts
several full target keys in the quoted `OTA_UPLOAD_TARGET` value and
requires `OTA_UPLOAD_CHANNEL` to identify a configured group channel.
Background uses multicast, a receiver census and selective repair; every
member must pass full-image validation for durable READY before its own
explicit commit. Direct accepts one target and requires an off-frequency
channel in `OTA_UPLOAD_FREQ_KHZ` plus a bounded `OTA_UPLOAD_LEASE_MS`.
On the approved lab mesh, the direct frequency is 908525 kHz; normal
traffic remains at 907525 kHz. Both direct and directed use channel 255
as the unused group-channel value. The uploader applies the leased direct
profile and restores normal settings afterwards.
The default bandwidth is 62.5 kHz (62500 Hz).

Upload **never commits**, including with `OTA_UPLOAD_WAIT_READY=1`.
That option waits for fresh, complete READY snapshots within
`OTA_UPLOAD_TIMEOUT`; the default returns after the campaign request
without claiming reception is complete. Long background campaigns can
be checked later. A matching complete READY permits a separate,
individually addressed commit:

```sh
make ota-lab-commit OTA_UPLOAD_TARGET="$target_key" \
  OTA_UPLOAD_MANIFEST=.tmp/update.manifest
```

The commit command waits for fresh READY before sending COMMIT. An
accepted command is not proof of installation, reboot or trial
confirmation. Confirm that node's health and normal mesh service before
committing the next one.
After a newly durable remote COMMIT, nRF firmware schedules its own
reboot; no USB reset is required. If that autonomous reboot is absent, stop:
a USB reset must not be used to turn a blocked qualification into a pass.
It gives replies a short grace period
and restores an off-frequency session first. READY, denied commands and
uncertain writes do not arm a reboot. Retrying the same accepted COMMIT
does not rewrite the intent or postpone its deadline.

To abort before commit, use `make ota-lab-abort` with the target key and
original `OTA_UPLOAD_IMAGE`. Abort identifies the firmware content hash,
not its manifest hash. The host first requires fresh target STATUS and binds
the abort to that observed upload generation. Command acceptance alone is
insufficient: success requires fresh, generation-bound durable ABORTED state.
An explicit reupload uses
`OTA_UPLOAD_REUPLOAD=1`; changing the manifest does not bypass an abort.
Reupload is not a force-overwrite option. An active candidate must retain
the same owner, image content and cache or install purpose. Abort an
obsolete candidate explicitly before replacing it with different content.
Unavailable, denied, failed or malformed replies stop the host command
explicitly. Firmware transport and physical recovery qualification remain
incomplete; these commands must not be treated as a deployment result.

The companion also retains one local upload cache. Before using different
image content, abort that cache explicitly with the **old cached BIN**:

```sh
make ota-lab-abort-cache OTA_UPLOAD_IMAGE="$old_cached_image"
```

This uses the same signed abort operation with a zero target to select the
local cache. The companion signs with its existing identity and aborts
locally; it sends no radio abort and does not cancel any remote candidate.
Abort the remote target separately when that is intended. A denied,
mismatched or unavailable local abort is an error, not permission to
overwrite the cache.

For cache-only staging without selecting a target or starting radio traffic,
use `make ota-lab-cache` as documented in the
[working-client workflow](hardware_lab.md#one-client-application-and-local-cache-validation).
`CACHE_SEALED` is local validated storage, not a remote READY or installation.
Retrying the same sealed image signs the manifest and sends BEGIN, then
requires fresh, matching local STATUS without sending PUT or SEAL again.

An nRF command refused before installation is not an active copy or
trial. If the device can prove that refusal against the original signed
command and its current valid running bank, a currently trusted
administrator may explicitly abort it. Firmware durably records the
abort and cancels the old intent before allowing replacement. Missing,
corrupt or unbound commands, inconsistent boot evidence and I/O faults
remain protected; an unknown status alone is not permission to erase.

On ESP32, uncertain version-floor persistence must not invalidate an image
already marked VALID. An ordinary restart can reconcile the floor from
signed running-image proof; a persistent fault disables OTA. The OTA-on
application prevents Arduino's automatic whole-NVS erase on initialization
failure, not an explicitly authorized factory reset. Neither behaviour is
physical recovery qualification; do not erase state to clear an OTA refusal.

## Build-time requirement

LoRa OTA is compiled in only when `MESHCORE_LORA_OTA` is enabled for a
target. It is currently enabled on these `platformio.ini` environments:

- `variants/xiao_nrf52/platformio.ini` (XIAO nRF52840 + SX1262)
- `variants/sensecap_solar/platformio.ini` (SenseCAP Solar)
- `variants/xiao_s3_wio/platformio.ini` (XIAO ESP32-S3 + Wio SX1262)

A build flag alone does not establish install capability. The running
application, signed receiver, durable storage and recovery-capable bootloader
must all be qualified together. An unsupported backend must refuse the
update explicitly without affecting ordinary mesh service.

## Unchanged stock 1.17.1 USB companion

`make ota-stock-companion` runs a separate PC-managed **zero-hop direct**
sender. It uses stock signing commands33/34/35, raw-packet command65 and
raw RX notification0x88. It never uses the custom OTA USB command66,
stages an image locally, exports a private key, changes contacts, resets a
device or flashes the companion. Do not use `ota-lab-upload` against an
unchanged stock companion. This adapter currently accepts only an
already-qualified XIAO nRF52840 **ROLE0 companion** raw APP BIN and its
canonical59 descriptor, not ROLE1, ESP32, UF2, ZIP or compound images.

The operator must supply an owned0600 JSON binding. Required fields are
`schema:1`, `authorized:true`, `stock_version:"1.17.1"`, the exact USB
`serial`, full32-byte hex `sender_public_key` and `target_public_key`,
the measured confirmed `floor`, approved positive `min_generation`,
`normal_profile:[frequency_khz,bandwidth_hz,SF,wire_CR]`,
`image_kind:"ordinary-app"`, `image_sha256` and `manifest_hash`.
The image hash covers the raw BIN; the manifest hash covers the unsigned
59-byte descriptor. The descriptor counter must exceed the measured floor.
The binding records an approval, not automatic commissioning or proof of
the recipient's current state.

CP2102 bridges can share a serial and by-id link. Such bindings also require
the authorized physical `by_path`, matching `id_path`, four-hex-digit
`usb_vid`/`usb_pid`, and exact public `sender_name`. Supply matching
`--by-path` explicitly. The driver opens that anchor, verifies its physical
USB metadata and full public identity, and **never resolves the ambiguous
by-id link**. Preserve the binding and artifacts privately; raw userdata
snapshots can contain channel secrets, location and BLE PIN.

Set `stock_args` to those explicit identity, path and binding arguments;
set `transfer_args` to `--manifest`, `--image`, an approved off-normal
`--frequency-khz` and an adequate `--timeout`. Use new artifact directories
for each operation:

```sh
make ota-stock-companion \
  OTA_STOCK_ARGS="inspect $stock_args --artifacts .tmp/stock-inspect"
make ota-stock-companion \
  OTA_STOCK_ARGS="upload $stock_args $transfer_args --artifacts .tmp/stock-upload"
make ota-stock-companion \
  OTA_STOCK_ARGS="commit $stock_args $transfer_args --ready-receipt .tmp/stock-upload/result.json --artifacts .tmp/stock-commit"
```

Inspection is read-only and does not prove RF readiness. Upload negotiates
signed30000-60000ms leases, default60000ms, on the recipient's normal
channel, then switches to the approved frequency at250kHz/SF5/wire CR5.
All normal-channel transmissions are conservatively paced by
`--normal-duty-percent`, default2; the leased off-frequency transfer is
not subject to that on-mesh share. Regulatory limits still apply. This is
not qualification of mesh-wide2% fairness or routed/fleet OTA.

### Explicit lab-fast upload

Add **only** `--lab-fast` to the stock sender's `upload` arguments for a
supervised development transfer. The default remains legacy 250 kHz/SF5/CR5
and four-block bursts. Lab-fast requires a new, target-signed profile ACK
before either host radio settings are changed: 500 kHz/SF5/wire CR5 and
at most sixteen freshly signed blocks between census polls. An old receiver
times out/refuses; the sender never assumes support or silently falls back.
The approved example is fast 908525 kHz; normal service remains on the
ROOT-bound, measured 907525 kHz/250 kHz/SF7/CR5 profile, not a guessed default.

No live lease renewal is attempted. Every bounded lease returns to normal
service before a fresh signed negotiation; normal pacing remains 2% by
default. Stock TX power, regulatory allowances, identities, image/owner/
board/role/counter/generation checks and separate COMMIT are unchanged.
Fresh census bitmaps, not aggregate TX counts, select bounded repair retries.
Stock USB signing and TX statistics still limit throughput. USB command
reads/writes and signing/TX deadlines are bounded; a failed physical-TX
confirmation must fail closed and retain `original-radio.json` for explicit
restoration, rather than retuning an unconfirmed active transmission.
SIGKILL/power loss still requires the documented manual restoration.

The native USB uploader's `scripts/ota_uploader.py upload --mode direct
--lab-fast` selects the same signed profile, without changing its native
pump or airtime share. Its receiver must also support this extension.
Software simulations show reduced elapsed time and fewer census/USB
operations. The approved stock-to41 resumed run reached complete500kHz READY
in4900.233 seconds, including repair, signing, lease returns and final normal
census; it began with883/6599 blocks already persisted. This is a measured
resumed-transfer result, not a complete-from-empty benchmark or proof of a
speedup over250kHz. Continuous radio reliability, unattended installation,
ordinary mesh fairness and legal RF operation remain separate physical gates.

For an already explicitly aborted candidate, the operator may additionally
approve `allow_reupload:true` and pass `--reupload` to **upload only**.
The sender learns the pending generation from a fresh matching RF census,
signs the target/generation-bound retirement, and requires generation+1
with an empty bitmap. It does not promote old cached bytes, abort
automatically or obtain its generation from USB. An active matching
candidate resumes without another retirement; later terminal candidates
use normal admission, not automatic `--reupload`.

Upload stops at complete observed RF READY and restores the stock profile.
COMMIT is a separate operation requiring its exact private receipt and a
new complete READY sweep. Census is unsigned and has no nonce; receipt
freshness does not authenticate an indistinguishable on-air replay.
Stock TX statistics are aggregate, not per-packet tokens. Neither a READY
receipt nor a reported signed-COMMIT transmission proves installation.
Measure the recipient's running version, confirmed floor, healthy trial
outcome and complete preserved settings/permissions independently.

The CLI prints flushed JSON phase/progress events without raw USB/RF
bytes, signatures or private device fields. `auth_sent`, `block_sent` and
`commit_sent` mean aggregate stock TX counters advanced, not recipient
acceptance. Validated census events remain unsigned telemetry; only the
direct ACK event follows verification of the target's signature.

SIGINT/SIGTERM runs restoration and reads back the exact original
frequency/bandwidth/SF/CR/repeater setting; TX power is never changed.
Keep `original-radio.json` even after an unsuccessful run. If the process
was killed without cleanup, restore explicitly with the same binding and
the **existing** upload artifact directory:

```sh
make ota-stock-companion \
  OTA_STOCK_ARGS="restore $stock_args --artifacts .tmp/stock-upload"
```

The corrected source permits already-seen OTA packets with zero path hashes
to reach the idempotent local receiver without forwarding them again.
Relayed duplicates, echoes, ordinary traffic and the packet-hash FIFO retain
their existing filtering. A receiver without this correction can stall after
a lost census reply or during the separate COMMIT READY sweep. Unit41 now
runs the corrected baseline and has accepted repeated census requests and
signed RF data. Other receivers still need matching corrected builds; clearing
packet caches, inventing a successful receipt or resetting the device is not
a qualification workaround.

The native USB uploader now has an explicit `upload --routed-retry` opt-in
for directed/background campaigns with matching upgraded receivers. It adds
a per-attempt discriminator without changing signed inner authority or native
same-attempt forwarding deduplication. Budget, busy and queue refusals retain
the same attempt; only accepted send/queue admission advances it. This option
cannot be combined with direct mode or `--lab-fast`; the stock zero-hop adapter
refuses it before hardware access. The retry flag is RAM-only: after a sender
restart, a separate COMMIT remains unwrapped unless a new routed/background
retry START has enabled the mode. See the
[wire contract](lora_ota_development.md#opt-in-routed-retry-attempts).
Actual target builds and software loss/repair cases passed; real multihop
loss/repair qualification is still required. Do not infer routed readiness
from the direct-mode hardware result.

Receiver USB diagnostics must not be required to make RF progress. The old
bench firmware stalled when its unsolicited OTA event output was not drained;
continuous USB observation restored signed-lease census and block reception.
That observer was instrumentation, not a production remedy. Corrected
nonblocking diagnostics are now installed and actual complete500kHz RF
reception to READY has passed without a receiver USB reader. Automatic rollback
and unattended installation remain separate acceptance gates despite
the completed USB-observed full-image installations. Partial Receiving restart
durability and subsequent same-campaign reader-free completion are established.
That proof requires healthy sampled driver-applied profiles and preserves the
full bitmap/session/floor, but does not certify continuous zero-fault radio
health: each complete census capture observed53 recovered lifetime faults.

## Control surface

Use the signed uploader commands above for an update. The current host ABI
is command 66, operations `0x10` to `0x18`, with ABI2 90-byte replies.
ABI1 firmware is explicitly refused; do not bypass that guard or treat
earlier ABI1 hardware evidence as qualification of the updated protocol.
It distinguishes local cache state from individually addressed target state.
The old command-66 mode/duty controls, raw fixed-key sender and binary
boot-journal cleanup are not an alternative upload workflow; their host
helpers have been removed.

### Passive radio fault attribution (separately qualified firmware)

On an OTA lab nRF52 USB companion with the diagnostic support compiled in,
GET_STATUS request bytes `[66, 0, 5]` return a **57-byte binary** payload.
Selector 4 already reports airtime budgets, so selector 5 is used rather than
repurposing it. Selectors 0–4, including selector 3's ASCII `h`/`x` profile
measurement, retain their existing wire behavior. Match all of reply code 29,
ABI 1, selector 5, and length 57; do not parse this reply as ASCII or as the
separate ABI2 uploader status. The ordinary serial envelope adds three bytes
(60 total), within the existing 176-byte payload limit.

| Payload offset | Field |
| --- | --- |
| 0, 1, 2 | response code 29, diagnostic ABI 1, selector 5 |
| 3, 4 | latest driver outcome healthy, any recorded failure (booleans) |
| 5–8, 9–12 | lifetime fault count `x`, count stamped at last failure |
| 13, 14–15 | last origin, signed RadioLib status |
| 16, 17, 18 | probe reason mask, expected mode, raw SX1262 status byte |
| 19–20, 21–24 | device-error bits, IRQ flags |
| 25–26, 27–28, 29–30 | checked device-errors / IRQ / status read statuses |
| 31, 32 | wrapper software state before and after the operation/probe |
| 33–56 | six lifetime per-origin counters, in origin order |

Multibyte fields are big-endian; signed statuses are 16-bit two's complement.
Origins are 0 unknown/unattributed, 1 `startRecv` (including CAD re-arm),
2 `readData`, 3 `recvRaw` RX re-arm, 4 `startTransmit`, 5 active checked probe.
Probe-only fields are meaningful only for origin 5. Reason bits are `01`
device-errors read failure, `02` IRQ read failure, `04` status read failure,
`08` device-error bits present, `10` unsupported chip mode, `20` mode
disagreement. A decoded register field is evidence only if its corresponding
checked-read status is zero. The primary driver status is the first failed
checked read in device-errors / IRQ / status order, or zero for a semantic
mode/device-error rejection; all three statuses remain available independently.
Expected modes are 0 idle, 1 RX, 2 TX. Actual chip mode is `status_byte & 0x70`;
supported encodings are `20` RC standby, `30` XOSC standby, `40` FS, `50` RX,
`60` TX. Software state is 0 idle, 1 RX, 3 TX-wait, with `10` interrupt-ready
ORed in (all state/mask values here are hexadecimal).

This bounded record is RAM-only, resets on reboot, and retains the last failure
and per-origin totals after healthy recovery. Success updates `h` but does not
erase history. Counts preserve the existing modulo-2^32 increment semantics;
subtract counts modulo 2^32 only within one boot and fewer than 2^32 failures.
The explicit any-failure flag distinguishes a wrapped zero from no failure.
Multiple failures between queries retain only the latest detail; per-origin
deltas reveal that the interval was not a single attributable event. This is
not an event log or proof that a latched IRQ is fresh.

The getter and encoder are passive: no new SPI transaction, packet data,
addresses, keys, GPS, PINs, flash write, or clear-device-errors operation.
The existing active health probe still performs its same three checked reads.
Neither this diagnostic nor any reason bit suppresses a fault or changes
strict trial readiness. Unsupported builds/radios return the existing
`UNSUPPORTED_CMD` error; malformed selector-5 lengths return `ILLEGAL_ARG`,
and encoding failure returns `BAD_STATE`, never a success-shaped empty record.

After the current campaign, qualify and install a **separate** diagnostic image
under the hardware owner's control; this source change is not present in the
already frozen campaign. In a later authorized bounded observation, obtain a
passive selector-5 baseline, allow one already-approved control exchange, and
obtain its post-exchange history plus existing profile guard. Require one
count increment, one matching origin-counter increment, and a retained last
count matching the post-exchange count before assigning its reason to that
interval. A mode-only probe rejection with expected TX, supported standby,
zero checked-read statuses/device errors, TX_DONE IRQ and software TX-wait
plus interrupt-ready supports a completion-transition explanation; it does
not alone prove IRQ freshness or explain the earlier observed 53 faults.
Other origins/read statuses distinguish operation and checked-read failures;
a `-705` alone still cannot distinguish chip command status from BUSY timeout.
Do not run this observation, retune, build a candidate, or add a reader during
the active immutable transfer. Software-only validation is the focused
`make test-ota-radio-fault-attribution` gate; MCU linking and physical
qualification remain separate work.

The repeater's ordinary text CLI remains the way to inspect its full public
key and existing administrator ACL. Normal permission setup uses
`setperm <full-companion-public-key> 3`, not a new OTA authority.
A live ACL readback and a six-second lazy-save opportunity do not prove
durability; a normal reboot does not flush dirty ACL entries. Verify the
complete ACL after a separately authorized restart. Do not replace the ACL or
export an administrator's private key to enable OTA.

`start ota`, the existing local firmware-update facility, is separate from
LoRa OTA. Keep using the supported local update and recovery procedure for
deployed nodes while the radio path is being qualified.
The experimental ESP OTA repeater profile disables the ordinary Wi-Fi
updater to prevent competing writes to the inactive slot. The ordinary
repeater profile is unchanged; USB recovery remains separate.

## Duty-cycle policy in practice

- Background/fleet mode defaults to a 2% airtime allowance. A 24–72-hour
  campaign is a planning window, not a completion guarantee. Ordinary
  traffic must retain scheduling priority and packet capacity even when
  the OTA allowance is exhausted.
- Routed mode may be given a higher temporary budget for an explicitly
  scheduled maintenance window.
- Routed and background transfers periodically re-offer the existing signed
  authorization during the initial DATA sweep. A successful re-offer requires
  at least 32 accepted DATA frames and 15 seconds since the previous offer.
  This lets a receiver recover a lost initial authorization before the whole
  image has been sent; ordinary-traffic priority and the airtime budget still
  apply. It does not restart an aborted candidate or authorize installation.
- Direct mode is a short, supervised session and is expected to be bounded
  by the same radio and regulatory limits as any other transmission.
- A supervised 95% or 100% full-image smoke run is not measured 2%
  acceptance and must not be reported as such.
- OTA traffic shares the same underlying MeshCore airtime/duty-cycle
  admission control as normal traffic (in `Dispatcher`); OTA does not bypass
  it. A dedicated per-region or per-sub-band legal airtime ceiling for OTA
  specifically is part of the design intent but is not a separate, already-
  implemented enforcement mechanism today.
- Unused OTA allowance expires at the end of its window; it does not carry
  over into a later burst.
- The default on-mesh allowance is 72 seconds of completed transmission
  time per sliding one-hour window, per transmitter. Short accounting
  buckets retain their latest completion for the full window; allowance
  recovery may therefore be delayed by up to 15 seconds, never advanced.
- Per-hop airtime qualification requires every participating relay to run
  firmware with `MESHCORE_LORA_OTA` enabled and its required OTA share
  configured (2% by default). Stock/OTA-off relays cannot inherit the
  sender's guarantee. Native forwarding proofs are software-only, not
  physical airtime qualification.
- Lab observations report completed on-mesh OTA usage separately from
  all-traffic transmission time. Timeout or failed-accounting observations
  prevent airtime qualification. Check ordinary peer delivery during the
  transfer as well; a budget reading alone does not prove usable service.
- An earlier 2026-09-30 pressure run reached 71,851 of 72,000 ms without
  overshoot but failed ordinary advert allocation with `ERR_TABLE_FULL`.
  A later full run at 12:26:14 UTC reached 71,822 ms and delivered an
  ordinary advert in 0.983 s without increasing OTA usage. This is
  historical evidence for the queue-capacity fix, not qualification of
  the replacement. A numerical quota pass alone is insufficient.

See the [design document's duty-cycle section](lora_ota_design.md#duty-cycle-behaviour)
for the full policy model.

## Earlier hardware evidence, not replacement qualification

- Earlier **companion-radio** lab builds supported setting mode and duty
  cycle, reading them back, and inspecting status through `CMD_OTA_CONTROL`.
  Those checks must be repeated against the replacement.
- A direct-mode radio lease correctly applies and automatically reverts
  temporary radio parameters; this was confirmed on repeated lab runs over
  real RF at 907.525 MHz, 62.5 kHz bandwidth, SF7, CR5. Earlier harness
  runs also encountered traffic-priority failures. Those
  results and later fixes are recorded in the
  [developer guide](lora_ota_development.md#current-hardware-evidence).
  None qualifies the replacement's direct-mode path.
- A historical 2026-09-30 run staged a small signed test image through the
  earlier wire protocol. Its final message completed staging; it was not
  the replacement's explicit installation COMMIT. The test image was not
  bootable firmware, and the old staging command has been removed. See the
  [developer guide](lora_ota_development.md#current-hardware-evidence) for
  specifics and dates.
- Nothing here yet results in an installed firmware update on a real device.
  Torn and partially erased cache metadata has native recovery coverage,
  not physical power-failure qualification. Preserve a validated recovery
  package before bench work;
  the lost original application and missing public-key baseline cannot be
  reconstructed by capturing new evidence.

This feature is developed on a dedicated branch and has not been merged
into upstream `main`; nothing in this guide is available in a released
build yet.

## Hardware lab reference

If you are helping validate this feature on bench hardware, board roles,
protected devices, and recovery procedures are documented in
[Hardware lab device workflow](hardware_lab.md). Do not repurpose those
procedures for a production fleet.
