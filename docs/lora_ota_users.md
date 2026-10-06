# LoRa over-the-air updates: user guide

## What this is

LoRa OTA is an experimental firmware-update capability in MeshCore. It
transfers an application image over the radio rather than through a USB
cable. It has three modes:

- **Direct** — a technician with a radio close to the node pushes an update
  using a leased off-frequency radio profile, then restores normal settings.
- **Routed mesh** — an update travels to one specific, out-of-reach node over
  the existing mesh path.
- **Background fleet** — a coordinator announces an update to many nodes at
  once, and eligible devices pull it down in the background over 24–72 hours,
  using only a small, configurable share of airtime (2% by default) to leave
  capacity for normal traffic. Transfer time depends on image size, radio
  settings, relays and loss; 24–72 hours is a planning window, not a deadline.

LoRa OTA does not replace a deployed network's normal radio settings.
The lab tools default to 62.5 kHz bandwidth; supervised testing on the
approved bench pair also uses 250 kHz.

For supervised lab/development transfers only, the stock PC sender has an
explicit `--lab-fast` upload option: negotiated 500 kHz/SF5/CR5 with bounded
bursts. Both ends must support and sign the matching profile; there is no
silent fallback. It still returns periodically to the original mesh channel
and requires separate READY and COMMIT. Complete500kHz reader-free reception
to READY has been observed on the approved bench pair; installation, rollback
and continuous radio reliability remain separate gates. This is not permission
to increase TX power or legal airtime.

## Current availability: not ready for production use

LoRa OTA is under active development and is **not** a supported way to update
your node's firmware today. Treat everything below as a preview of an
in-progress feature, not a how-to.

The supervised nRF unit41 has completed three full signed LoRa updates through
an unchanged stock1.17.1 companion. The first two established actual new firmware,
healthy confirmation, confirmed image hash/counter, protocol-visible userdata
preservation and ordinary signed peer traffic afterward at2dBm. They required
a USB observer to drain old-firmware diagnostics. The third installed a healthy
diagnostic image after complete reader-free500kHz reception. Its prearmed
observer failed during installation, but a separate late read-only capture
confirmed the new running image, confirmed floor and Installed state. Continuous
installation observation and autonomous failed-trial rollback remain unqualified.
Separate post-install readbacks also established protocol-visible userdata
preservation and bidirectional ordinary signed peer reception at2dBm for this
third image.

The current software implements signed transfer in all three modes, durable
staging, explicit per-device commit and recoverable installation. It reuses
MeshCore administrator identities rather than a separate OTA signing system.
Software tests cover repeated updates, failed-trial recovery and refusal of
competing candidates. These results are not physical acceptance.

Hardware qualification remains incomplete despite those supervised installs.
The previous baseline `ota-41-confirm04` includes corrected nonblocking
diagnostics and 500 kHz negotiation. Its independently confirmed image
hash/counter and complete pre-peer userdata preservation are established;
complete500kHz reception without a receiver USB reader is now established.
A partial campaign also survived one ordinary application restart: the complete
bitmap, update session, administrator admission and all userdata were preserved,
and the same reader-free transfer resumed without restarting the campaign.
The resumed transfer reached all6599 blocks READY in81.7 minutes, starting from
883 persisted blocks; this is not a complete-from-empty transfer-time benchmark.
A separate signed COMMIT was sent after a fresh complete READY census. Its
immediate USB witness timed out before observing a trial or return, so neither
installation nor autonomous failed-trial rollback is proved by that attempt.
After that failed-candidate attempt, a separate
post-COMMIT read-only diagnosis found `ota-41-confirm04` running again,
the original confirmed floor unchanged, the candidate marked failed, and a
healthy sampled normal radio profile. This late snapshot does not recover the
missing trial history or qualify autonomous rollback.
The subsequent healthy diagnostic image also reached complete reader-free
READY, with6618 blocks and measured generation14. Its first separately prearmed
installation attempt was unsuccessful: the stock process exited with an error
and restored its radio, while the observer continued to see `ota-41-confirm04`,
the unchanged confirmed floor and the new candidate READY. The wrapper did not
retain the sender's error output, so the exact failure and whether a COMMIT was
transmitted are unknown. No retry or host reset was used in that attempt.

One subsequently admitted signed COMMIT retry preserved the same candidate,
counter4 and generation14. The stock process completed a fresh52-window READY
census, reported aggregate transmission evidence and restored its radio.
The observer failed shortly after the actual COMMIT interval was sealed.
A separate late read-only capture found `ota-41-diag-conf05` confirmed and
Installed, with sequence4/counter4, the exact555876-byte image hash and healthy
sampled normal907525kHz/BW250000/SF7/CR5/TX2 operation. No additional COMMIT,
host reset or reflash was needed. This establishes the installation, not the
missing trial/reset history; the failed observer receipt remains failed.
Separately admitted diagnostic post-install readbacks matched all exposed
identity/settings, contact and channel comparison checks against the actual
pre-upload snapshot: five contacts and40 channel slots. One ordinary zero-hop
signed advert was then received in each direction through the unchanged stock
companion at2dBm, with native acceptance events and fresh image/floor/profile
checks before and afterward. This is not complete storage/private-key
preservation or sustained service qualification. The receiver's fault count
increased from0 to1 across that peer check despite healthy sampled radio state;
separate passive diagnostics classified the retained fault as an active-probe
transmit/standby mode mismatch, with successful checked SPI reads and no device
error bits. Its triggering operation and continuous radio reliability remain
unqualified; a latched TX_DONE flag is not fresh-completion proof.

The source now services an owned, unexpired transmit completion before the
trial-health probe, using the dispatcher's ordinary completion path for
exactly-once airtime accounting, packet release and receive rearm. If its ISR
arrives during checked reads, the SX1262 wrapper can service that same owned
completion and take one fresh probe; SPI/device errors from the first probe
remain visible. The strict mode classifier is unchanged: stale TX_DONE,
unowned or expired completion, and persistent standby are not health exemptions.
Both companion and repeater trial-health paths use this service. These changes
are not installed on41 and do not establish the historical fault's cause or
continuous physical radio reliability.
A distinct healthy `ota-41-tx-conf06` APP containing this fix now exists and fits
the enrolled Sense ROLE0 layout. It is still unsigned and not installed; the
current running image remains diag-conf05. The separately admitted counter5
nonconfirming-image upload is a rollback campaign, not deployment of this fix.
That upload completed READY at native measured generation15 and restored the
stock radio. A fresh observer was armed before the separate signed COMMIT
started; COMMIT completion, installation and autonomous rollback remain
unconfirmed. Staging does not establish a new running image.
The transmit-fixed APP's exact healthy-installation observer is now qualified
in source, without changing the strict image/floor classifier. Its deployment
still requires genuine completion of the current rollback campaign and fresh,
separate ROOT admission; no signing or installation of that APP has begun.

A separate private floor4 diagnostic rollback observer profile is wired to
the unchanged ordered-trial/return observer, with bounded disconnect handling.
It requires a new ROOT-admitted signed descriptor, measured READY
generation/native nonce, fresh physical/current-state checks and separately
sealed COMMIT. Synthetic USB samples are not hardware rollback evidence; no
old attempt or failed receipt is reused.

Recovered driver-fault counter increases were observed during that restart
proof despite healthy sampled radio state; continuous fault-free radio
operation and the faults' cause remain unqualified.
Unit77 enumerates in its defective modified
USB bootloader and still needs external repair. See the
[hardware lab guide](hardware_lab.md) for current evidence and restrictions.
The 2% airtime policy and ordinary mesh service must still be verified together
during an update. Routed delivery through intermediate nodes and fleet
contention also need hardware beyond the two-node bench.

The native USB uploader has an experimental `--routed-retry` option for
routed/background campaigns with matching upgraded receivers. The per-attempt
wrapper preserves signed update authority and same-attempt forwarding
deduplication; it does not qualify physical multihop recovery. The unchanged
stock companion adapter remains zero-hop only and refuses this option.

Earlier lab firmware demonstrated radio transfers and external-flash
staging, but that transport has been retired. Those captures do not qualify
the current implementation. No target board is ready for production OTA
installs.

This feature is being developed on its own branch and has not been merged
into the main MeshCore codebase or any release.

See the [developer guide](lora_ota_development.md) for the dated evidence
and outstanding acceptance gates. Continue to
update your node's firmware the way you always have — the MeshCore Flasher,
or `start ota` over USB/BLE — until this changes.

## Supported and planned hardware

| Board | LoRa OTA status |
| --- | --- |
| Seeed Studio XIAO nRF52840 + SX1262 | Unit41 completed three healthy LoRa installations, including diagnostic firmware after reader-free500kHz reception; uninterrupted installation observation/rollback remain unqualified; unit77 needs bootloader repair |
| SenseCAP Solar (P1 Pro), nRF52840-based | Design complete; hardware qualification still pending |
| Seeed Studio XIAO ESP32-S3R8 + Wio SX1262 | SDK-backed staging and rollback implemented; physical qualification pending |
| Heltec v3/v4 | OTA receivers not qualified; unchanged Heltec v3 USB companion qualified as a signing/radio transport only |

## What an update should do

Your existing firmware keeps serving the mesh while a new image downloads.
The node accepts updates only from an administrator it already trusts through
MeshCore's existing public-key permissions and Ed25519 signatures, not a new
OTA authority. The node holds one candidate
and its original owner at a time; a competing image or owner receives `BUSY`.
It resumes durable progress after a restart.
Duplicates do not write flash again; a bad packet does not discard the
working firmware or the valid blocks already received.

After receiving and checking the entire image, the node waits in `READY`.
It does not reboot just because the last block arrived. The original
administrator, still trusted as an administrator, must send an explicit,
target-bound commit, allowing fleet upgrades to be sequenced. Any currently
trusted administrator may abort before commit and stop reception of that
image until an explicit restart.

Once installation starts, the bootloader must recover from interruption or
restore the previous image if the trial fails. These are required behaviours;
they remain unverified end to end on physical hardware.
After the device proves that install or rollback has finished, a subsequent
authorized update can reuse the staging slot. An uncertain boot outcome
does not allow another upload to overwrite it.

## Terminology you may see

- **Direct mode**: a short-lived, faster radio profile used only for the
  update session, then reverted automatically.
- **Fleet mode**: the signed-manifest admission → multicast pass →
  census → selective repair → re-census → validation → per-member commit
  sequence on an existing MeshCore channel. Each member must pass the same
  full-image validation before READY and an explicit individual commit.
- **Duty cycle budget**: the percentage of airtime OTA traffic is allowed to
  use; normal MeshCore traffic must retain priority and queue capacity
  under sustained OTA load — see the
  [administrator guide](lora_ota_administration.md#duty-cycle-policy-in-practice).
- **Rollback**: if a new image fails to start up correctly, the device is
  meant to restore the previous working image automatically. This is part of
  the design and is not yet proven end-to-end on hardware.

## Where to go next

- If you administer a fleet of nodes and want to know what controls exist
  today, see the [administrator guide](lora_ota_administration.md).
- If you want to build, test, or extend LoRa OTA, see the
  [developer guide](lora_ota_development.md).
- For the full design rationale, see the
  [LoRa OTA design document](lora_ota_design.md).
