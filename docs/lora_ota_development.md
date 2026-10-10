# Building and testing optional LoRa OTA

Base this feature on `dev`, keep unrelated changes out, and follow
[CONTRIBUTING](../CONTRIBUTING.md): 2-space C++ indentation,
camelCase/PascalCase, roughly 100-column lines (`.clang-format` permits 110), and
public API documentation/examples. For this embedded feature, prefer static
resources and direct helpers over new abstraction layers or runtime allocation.

Normal board environments remain OTA-disabled. Only the explicit `_ota_usb`
environments enable `MESHCORE_LORA_OTA=1`; ordinary environment RF/path defaults
are unchanged. See [the product guide](lora_ota_users.md) for environments,
installation, deployment and recovery, and [design](lora_ota_design.md) for
transaction boundaries. Soak work stays in the public fork; no upstream PR.

Bench USB conversion is fresh provisioning, not an in-field OTA transaction.
Prefer the simplest supported vendor flash workflow and allow a clean slate
with subsequent key/configuration setup. Do not require preservation-heavy
cross-role or cross-layout migration merely to adopt the firmware. SWD remains
stuck-device recovery, not a normal setup requirement. Field OTA must still
preserve identity, configuration and confirmed floors and retain its signed
transaction, trial and rollback safeguards.

The paired XIAO's `serial-usb-cdc-fresh-v2` profile uses ordinary vendor CDC
recovery and actual configured local USB START provenance, not a retained
double-reset grant. `commission-xiao-ota-usb` retains explicit fresh consent,
device selection and a board/role/hash-bound APP build context. Recovery entry
alone must not erase userdata, and merely having USB connected must not elevate
BLE or field requests. Normal boot and BLE retain the protected-region locks.
Pending primary-BOOT replacement must preserve its receipt through the SDK's
persisted settings getter and recheck its staged extent and CRC before MBR
copying in the admitted USB session. Interrupted uploads must fail closed and
require explicit re-upload. The host must propagate vendor DFU failures rather
than reporting a successful Make invocation.
See the [paired bootloader recipe](../bootloader/xiao_nrf52840_ota/README.md)
for phases, erase ranges and legacy-device recovery limits; software validation
does not qualify actual USB transfers or cold boots.

## Reproducible Make workflows

`build`, `upload` and `clean` require an explicit `ENV`; an unselected command
does not silently build every board or opt-in OTA environment.

```sh
make build ENV=Xiao_nrf52_companion_radio_usb
make build ENV=Xiao_nrf52_companion_radio_ota_usb
make build ENV=Xiao_S3_WIO_companion_radio_ota_usb
make test-ota-host
make test-xiao-ota-bootloader-tools
make test-ota-native
make test-ota-disabled
make test-ota-queue-compatibility
```

`make test` runs ordinary native and KISS-modem tests plus retained host tests.
Per-layer targets are `test-ota-protocol`, `test-ota-runtime`, `test-ota-storage`,
`test-ota-trust`, `test-ota-boot`, `test-ota-integration` and `test-ota-esp32`.
The six native OTA suites cover the shared product and ESP backend.
`test-ota-boot` runs the actual nRF C bootloader transaction/crypto tests through
`test-xiao-ota-bootloader`, not a duplicate portable installer.
`OTA_TEST_FILTER` narrows `test-ota-native`; `OTA_GTEST_FILTER` (exported as
`GTEST_FILTER`) selects Google Test cases for `test-ota-native`, the per-layer
targets, `test-ota-disabled` and `test-ota-queue-compatibility`, for example
`make test-ota-integration OTA_GTEST_FILTER='LoraOtaRoutedRetry.*'`.
`PLATFORMIO` selects the installed runner.

Focused regressions:

```sh
# Default reliable directed/background framing: real relay loss reaches READY.
make test-ota-integration OTA_GTEST_FILTER='LoraOtaRoutedRetry.AutonomousUploaderActuallyRepairsLossAcrossTwoRealRelaysAtTwoPercent:LoraOtaRfProduct.DirectedLostBeginReadmitsBeforeInitialSweepAtTwoPercent:LoraOtaRfProduct.BackgroundLostBeginReadmitsWithoutBlockingHealthyFleetAtTwoPercent'
# Startup provisioning, identity store and contact-permission migration.
make test-ota-storage OTA_GTEST_FILTER='BExampleStartupTest.*:BIdentityStoreStartupTest.*:BContactPermissionTest.*:DataStoreRecordCodecTest.*:OtaTrialSafeFilesystemMountTest.*:IdentityIntegrityCodecTest.*'
```

`make test-ota-host` covers the native and stock hosts on wire version 3. It
checks golden COMMIT (153-byte RF, 90-byte USB request), census (123-byte),
lease-domain and 107-byte USB status frames against the C++ encoders. It also
checks refusal of old companions and receivers before any upload, the default
reliable framing parser, and a stock session with more than 256 interleaved
ordinary notifications.

`make test-ota-stock-companion` also exercises exactly-two-target stock
background collection: one shared initial block flood, union-bitmap selective
repair, independent nonce-bound COMMITs, target/session mismatches and explicit
partial-failure artifacts. SIGINT/SIGTERM during admission, READY census,
COMMIT signing or Installed polling must prevent subsequent OTA operations
while retaining prior outcomes and completing profile/UART cleanup. Stock
background uses public channel-255 RAW floods, not the native host's encrypted
multicast-channel mechanism. Software coverage alone does not qualify hardware
or installer role migration; the completed two-target bench observations are
recorded separately below.

`make test-ota-management` covers the identity-bound stock remote-management
transport and bounded partial background lifecycle helpers; it is also included
in `test-ota-host`. Remote progress/candidate formatting distinguishes active
candidate evidence from confirmed boot evidence, and reports unavailable
storage explicitly within the existing 160-byte CLI reply bound. These are
ordinary encrypted admin commands, not a new OTA trust or local-owner bypass.

`test-ota-disabled` (environment `native_lora_ota_disabled`) compiles the real
`Mesh`, `Dispatcher`, `Packet` and `StaticPoolPacketManager` with
`MESHCORE_LORA_OTA=0` and checks that ordinary routing, priorities, airtime
scheduling and packet ownership match upstream `dev`; unknown payload type
`0x0C` is handled like any other unknown type. `test-ota-queue-compatibility`
(environment `native_lora_ota_queue`) runs the same fixture with OTA compiled in
to check the queue reserve, priorities and ownership. Both are part of
`make test-ota`. `build-ota-nrf52-targets` and `build-ota-esp32-targets` compile the explicit
opt-in environments; callers can override the corresponding environment lists.

### Installer-independent repeater relay

`make build ENV=Xiao_nrf52_repeater_ota_relay_usb` builds an APP-only USB
repeater with `MESHCORE_LORA_OTA=0`, `MESHCORE_LORA_OTA_RELAY=1` and
`MESHCORE_REPEATER_RELAY_PROFILE=1`. The relay gate defaults off. It classifies
payload type `0x0C` for routing/queueing only, never instantiates the installer,
staging/image storage, RF authorization, qualification or boot-command backend.
The linker ends APP at `0xC4000`; do not replace the paired bootloader, fixed
installer, stage, floor or filesystem when changing to this profile. This
profile does not become install-capable by changing its advertised role.

Directed requests consume the selected next-hop prefix (width 1/2/3).
Flood replies append that same-width relay prefix once; their original payload,
including `0x11`/`0x12` and BE32 retry attempt, is opaque and unchanged. Normal
transport, flood policy, hop limits, native packet-hash deduplication and path
capacity limits still apply. There is no direct-bypass fallback or duplicate
delivery exception at the relay. Traffic uses priority 250 and preserves four
packet buffers for ordinary traffic. The dispatcher requires the full estimated
airtime in its normal mesh budget and additionally defaults to at most 72,000 ms per
rolling hour (2%), conservatively checking the 1.5x send-timeout envelope before
TX. All opaque OTA packets share the Relay category, including control/replies.
Completed and timed-out sends are charged; accounting failure blocks further
OTA TX for this boot. Ready ordinary traffic takes precedence; budget-deferred
OTA frames retry the queue after 60 seconds without globally stalling normal
traffic. This is an airtime limit, not permission to use a restricted frequency.

The isolated profile mounts InternalFS without format-on-failure and requires
its existing `/_main.id`; absent/unreadable identities result in no mesh
dispatch, no new key and no writes. Only `/relay_prefs.json` is used for repeater
preferences, with no `/prefs.json`, `/com_prefs` or legacy companion preference
migration. Identity rekey/export, filesystem erase, ACL persistence and region
persistence are disabled in this profile. Ordinary-to-OTA repeater preference
fallback remains unchanged when this isolation opt-in is off. No ExtraFS/QSPI
mount or OTA stage/floor access is enabled.

Generic defaults inherit ordinary board settings; no lab channel, power or
identity is embedded. An operator can supply controlled `LORA_FREQ`, `LORA_BW`,
`LORA_SF`, `LORA_CR`, `LORA_TX_POWER`, `ADVERT_NAME` build overrides before the
first boot, or use the standard repeater USB CLI (`set radio`, `set tx`,
`set name`, `set repeat`, followed by `get radio`/`get tx`/`get repeat`). Existing
isolated preferences override build defaults. Changing mesh `airtime.factor`
does not raise the relay's independent OTA ceiling. To change inherited
preprocessor definitions, use an explicit local environment with matching
`build_unflags` and new `build_flags`; avoid relying on duplicate `-D` ordering.

For a private extending environment, retain the relay environment's
`build_unflags` (`-std=gnu++11 -std=gnu++14 -D EXTRAFS=1`) and remove the
inherited `-D LORA_FREQ=869.618`, `-D LORA_BW=62.5`, `-D LORA_SF=8`,
`-D LORA_TX_POWER=22` and `-D ADVERT_NAME='"Xiao_nrf52 Repeater"'` before
supplying replacements alongside the inherited `build_flags`. `LORA_CR` has
no inherited command-line definition to remove. Build with
`make build ENV=<private-relay-env>`; the APP-only DFU ZIP is
`.pio/build/<private-relay-env>/firmware.zip`. Flash APP only, preserving the
paired bootloader and userdata; verify identity, radio, name and repeat setting
again after reboot. The advertised repeater role is not a paired installer-role
qualification.

The relay-only OTA cap can be explicitly changed at compile time with
`-D MESHCORE_LORA_OTA_RELAY_DUTY_PERCENT=<integer-percent>`; valid values are
1–100 inclusive, and an omitted flag retains the production default of 2%.
Out-of-range definitions fail compilation. The existing rolling-hour limiter,
timeout accounting, queue reserve and ordinary-traffic precedence remain in
force; this flag does not enable an installer or change RF power/frequency.
For the explicitly authorized accelerated functional RF lab, add
`-D MESHCORE_LORA_OTA_RELAY_DUTY_PERCENT=80` only to the private extending
environment's `build_flags` (2,880,000 ms/hour), retaining TX2 and its existing
channel overrides. The normal mesh airtime budget is a separate, additional
limit: configure its duty to 80% through the standard repeater CLI and verify
readback. Do not infer regulatory permission from a higher software cap, and
do not change generic environment defaults or treat acceleration as a raw
throughput benchmark. The earlier hardware milestone below was at 2%, not
proof of the subsequent accelerated campaign.

For an installer receiver's native OTA CLI, `ota duty 80` changes only the
in-memory OTA airtime budget; it does not reset the candidate, generation,
BEGIN nonce or bitmap, and it is not persisted across reboot. An unwired
CommonCLI `get ota.dutycycle` callback is not readback of this native setting.
Keep critical APP-only DFU packages outside `.pio/build`: PlatformIO may
invalidate the project-wide build cache when configuration changes.

#### Parent-observed hardware milestone — 2026-10-09

A private APP-only build using 907.525 MHz, BW250, SF7, CR5 and TX2 produced a
362,868-byte APP (SHA-256 prefix `19ef6692`, exclusive flash end `0x7F974`).
The isolated name `OTA-LAB-RELAY`, 2% duty setting and repeat-on state persisted
across reboot; the existing companion public identity was retained and the
node advertised as a genuine repeater. These are private lab settings, not
generic environment defaults.

The reproducible negative/positive route probe used a stock sender with one
explicit selected-relay hop and accepted only the current poll attempt's
exact single-relay return trail. Repeat-off yielded no accepted route during
25 seconds; repeat-on yielded 5/5 v3 census replies from the target's unchanged
generation-1/floor-1 baseline (6,017 blocks). A bare target reply was received
but correctly rejected. No retune, fallback or candidate mutation was used.

The subsequent stock-sender → dedicated-repeater → target counter-2 campaign
began on the normal channel at 2% with a 172,800-second timeout. Its early
generation-2 Receiving observations established admission/progress, not
installation.

The subsequent accelerated lab run preserved the same counter-2 image and
generation. After a graceful host pause, one routed census captured 129/6,031
received blocks and the existing nonce as unsigned observations. Strict resume
then used an 80% sender budget, an APP-only relay build with the private 80%
flag (362,868 bytes, SHA-256 prefix `08096e47`, end `0x7F974`), relay mesh duty
80%, and the receiver's native `ota duty 80`. RF profile and TX2 were unchanged.

A six-second relay-forwarding outage left the four-block batch 2056-2059
missing: window 2048 still reported eight present blocks. The sender retried
those individual indices, and a later current-attempt census reported twelve
present blocks at 563.726 seconds on the resumed clock. Generation and nonce
were unchanged; no BEGIN, REUPLOAD or direct fallback was used.

The resumed campaign subsequently converged to 6,031/6,031 blocks and reported
Installed at 5,538.121 seconds, generation 2 and confirmed floor 2, through the
selected relay. Its schema-2 result remains
`native-installed-reported-unsigned`: `status_authenticated=false` and
`installation_confirmed=false`. The separate local USB observation showed
confirmed/installed, counter/floor 2, verified SHA-256
`d96a0d8b940dddb9ab85ccffd77cf145b6f994b9bca7275fc847b1ef88f95397`,
extent `0x7BA9C` (506,524 bytes), floor sequence 3 and qualified state 1/phase 6.
Those values, identity, normal radio and TX2 survived an explicit same-firmware
reboot. The post-reboot stock probe accepted 25/25 Installed census samples
through the mandatory relay; one sample needed a census retry, and bare direct
copies remained rejected. Stock radio/repeat/TX2 readbacks stayed unchanged.
Only the temporary stock authorization was revoked, preserving the original
administrator entry.

This proves a full routed single-target installation, bounded real-loss repair
and durable floor advancement, not authenticated RF status or a two-target
shared-flood installation.

The two-installer background experiment subsequently admitted both Sense
targets to the same counter-3 image and 6,031-block descriptor. Its first sender
run stopped after 187 common block transmissions because the USB response queue
overflowed, before any COMMIT. With the host queue fix, strict paired resume
matched both original schema-3 attempts using fresh censuses: generation 1 on
the newly commissioned target and generation 3 on the existing target, with
159/6,031 received blocks each. Their BEGIN nonces and previous floors were
retained. Resume repairs the union of missing bits instead of restarting the
full stream.

The resume subsequently transmitted all 5,872 common repairs, with zero
initial-pass transmissions. Its first post-pass target census exhausted three
25-second reply attempts at 3,788.308 seconds, before READY or COMMIT. The
aggregate records `shared-campaign-incomplete`; USB pending count was zero,
5,805 echoed blocks were demultiplexed, and unchanged stock profile readback
succeeded. Both targets separately remained Receiving counter 3 over USB with
their previous floors and identities and healthy retained radio diagnostics.
The first target's outbound queue contained fourteen packets with a pending
census control reply. Its normal mesh budget was 2%; the OTA limiter still had
ample budget. `Mesh::pumpOtaControl` waits for an empty outbound queue, while
`Dispatcher::checkSend` applies the normal mesh airtime budget before the
separate OTA budget. The second target had an empty queue and its existing
50% mesh duty. Current received totals require fresh censuses; transmission
counts do not establish convergence. Both installations and durable post-reboot
qualification were still outstanding at this stage. Original run artifacts
remain unchanged.

A subsequent bounded read-only census, after quiet queue drain, reported
1,016/6,031 blocks on generation-1 target 41 and 5,546/6,031 on generation-3
target 3B. Both first requests succeeded and preserved their exact BEGIN nonces
and floors 0/2. The explicitly approved co-located recovery temporarily
disabled forwarding on both receiving installers, without altering the mesh
budgets, RF profile, TX2 or candidate state. Both original forwarding-on
settings remain restoration obligations after installation; no field relay
path is being qualified by this bench adjustment.

Shared repair now refreshes both targets after at most four common blocks per
128-bit window, emits `shared_repair_checkpoint` and rotates windows. Subsequent
unions come from fresh independent bitmaps. A missing or drifting report stops
data immediately; the existing limit counts repairs per block index, not
window visits. Full-size 6,031-block coverage exercises fresh and retained
campaign convergence, including initially empty bitmap windows.

The first checkpointed hardware resume reached its 14,400-second deadline
after 4,444 common repairs, not a radio or census failure. Final fresh reports
showed 5,454/6,031 received blocks on target 41 and 5,977/6,031 on target 3B,
still Receiving with the original generations, nonces and historical floors.
USB showed healthy radios and empty queues; the approved forwarding pause
and normal mesh budgets remained unchanged. No READY or COMMIT was issued.
The incomplete aggregate preserves unchanged stock readback and zero USB
backlog. A longer continuation retains the same original attempts.

The completed run also exposed unnecessary host polling: all 135 zero-block
window visits were already complete in both validated cached bitmaps, but each
still performed paired censuses before and after selection. Those visits
consumed 1,662.71 seconds. Productive repair checkpoints remained fresh and
attempt-bound; the redundant traffic did not indicate a receiver fault.

Repair scheduling now skips validated cached windows complete on both targets
and omits a second polling pair when fresh selection finds no missing bits.
Productive chunks still require both fresh post-censuses. A fresh full paired
READY survey is required before completion; cached convergence cannot
authorize COMMIT.

The subsequent same-attempt continuation completed with 577 common repairs,
zero initial-pass transmissions and both receivers reporting 6,031/6,031.
Independent signed COMMITs were sent at 2,612.622 seconds for generation-1
target 41 and 2,633.743 for generation-3 target 3B. Matching unsigned Installed
reports arrived at 2,692.286 and 2,718.018 seconds, respectively; one post-COMMIT
poll for 3B needed a retry. The schema-1 aggregate records
`shared-native-installed-reported-unsigned`, `operation_complete=true`,
unchanged stock profile readback and zero USB backlog. RF status remains
unauthenticated, with `installation_confirmed=false`.

Independent USB readbacks confirmed counter/floor 3, verified SHA-256
`f282c09849a962b81913528a514a3bc2d136e6d8424c25959cd1987f47cf187a`,
extent `0x7BA9C`, qualified state 1/phase 6 and floor sequences 2/4. The live
lifecycle observer hashes incrementally, so an initial unknown/commit-pending
display was allowed to resolve before the retention reboot. Both receivers
retained the confirmed image, floors, identities, names, normal profile, TX2,
mesh duties 2%/50% and ACLs after guarded same-firmware reboots.

The post-reboot read-only stock probe accepted 5/5 Installed censuses per
receiver using a 2% budget. After restoring original forwarding-on settings,
a second probe accepted another 5/5 per receiver. Both used the original
generation/nonce contexts and normal RF profile, with no candidate mutation or
retune. Only temporary stock authorization was then removed: 41's original
empty ACL and 3B's original administrator entry were preserved. Final USB and
stock identity/profile/repeat/TX2 readbacks matched the required restored state.
This establishes the exactly-two-installer stock shared-flood bench outcome,
not larger fleets, native-host encrypted multicast or field-relay qualification.

Focused native routing (real Mesh/Dispatcher/StaticPool/SimpleMeshTables, installer
off), startup safety and gate-off compatibility use existing Make targets:

```sh
PLATFORMIO_BUILD_FLAGS='-D MESHCORE_LORA_OTA_RELAY=1 -D MESHCORE_REPEATER_RELAY_PROFILE=1' make test-ota-disabled
PLATFORMIO_BUILD_FLAGS='-D MESHCORE_LORA_OTA_RELAY=1 -D MESHCORE_REPEATER_RELAY_PROFILE=1 -D MESHCORE_LORA_OTA_RELAY_DUTY_PERCENT=80' make test-ota-disabled
make test-ota-storage OTA_GTEST_FILTER='RelayStartup.*:BExampleStartupTest.*'
make test-ota-disabled
make test-ota-queue-compatibility
make test-ota-native OTA_TEST_FILTER=test_config_serializer OTA_GTEST_FILTER='RepeaterPrefsMigration.*'
```

Both relay runs exercise the configured cap's admission, rolling expiry and
timeout charging alongside unchanged routing/isolation behavior. With the same
relay flags, `MESHCORE_LORA_OTA_RELAY_DUTY_PERCENT=0`, `-1` or `101` must fail
the native build at the explicit compile-time guard; these are expected build
failures, not runtime tests.

### PacketManager compatibility

Existing `PacketManager` implementations compile and behave unchanged, with or
without OTA. The legacy `allocNew()`, `void queueOutbound(...)` and
`getNextOutbound(now)` methods keep their signatures; `queueOutbound` always
takes ownership of the packet. OTA support is optional and defaults to
unsupported: `supportsOtaQueue()` is false, `allocOtaPacket()` returns `nullptr`,
`tryQueueOutbound()` returns false, `getNextOutboundWithPriority()` returns
`nullptr` and `getOutboundScheduleByIdx()` returns false. On `tryQueueOutbound`,
success transfers ownership and failure leaves it with the caller. OTA traffic
fails closed on a manager without OTA support.

`Dispatcher::sendPacket` always consumes the packet. With an OTA-capable manager
its result reports whether the packet was actually queued; with a legacy manager
`true` only means it was submitted, since a drop cannot be observed.
`Mesh::sendFlood` leaves ownership with the caller for an invalid payload type
or path, as before, and otherwise consumes the packet.

Code written against earlier feature-branch hooks migrates as follows:

| Earlier hook | Current hook |
|---|---|
| `allocNew(true)` | `allocOtaPacket()` |
| `allocNew(false)` | `allocNew()` |
| Boolean queue result | `tryQueueOutbound()`; release the packet yourself on `false` |
| Priority dequeue | `getNextOutboundWithPriority()` |
| Schedule getter | `getOutboundScheduleByIdx(i, out)` |

Standalone causal targets retain real boot transaction, descriptor/Ed25519,
radio-fault attribution and transmit-completion behavior:
`test-xiao-ota-bootloader`, `test-ota-radio-fault-attribution`,
`test-ota-radio-tx-completion` and `test-ota-rf-to-boot`.
The latter exchanges actual durable records between native RF admission and
the boot processor, including interrupted install and rollback cases. No
hardware inventory, policy campaign or observer ledger is needed.

For a real ESP application image, `test-ota-esp32-image` accepts
`ESP32_OTA_IMAGE_ARGS='--output <fixture> --qualified-build <PIO-build-dir> cache
--image <firmware.bin> --manifest <canonical59>'`. It checks the vendor image
and emits real signed cache packets for `ESP32_OTA_IMAGE_PATH_FIXTURE=<fixture>
make test-ota-esp32`; no USB/device is opened.

Build scratch is repo-local `.tmp`; PlatformIO outputs remain `.pio` or caller
selected build directories. No container framework or system `/tmp` output is
required. Host dependencies are `requirements-ota.txt`; bootstrap additionally
uses ARM GNU tools, the pinned public OTAFIX source/submodules, and standard
Adafruit nrfutil packaging.

Tests use synthetic keys and fake serial/NOR/SDK I/O. They cover signing,
board/role/counter binding, durable transfer/READY, one COMMIT, matching Installed,
refusal/timeouts, restored radio and interrupted storage/rollback semantics.
Software tests and successful builds do not qualify ESP/Solar hardware,
routed fleet delivery or power-failure behavior on an untested board.
