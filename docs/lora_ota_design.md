# LoRa OTA transaction boundaries

OTA is optional and compiled out of normal environments. With
`MESHCORE_LORA_OTA=0` routing, packet priorities, airtime scheduling, companion
loop timing and `PacketManager` ownership are those of upstream `dev`; payload
type `0x0C` is treated as any other unknown type (`make test-ota-disabled`).
Existing `PacketManager` implementations need no changes; OTA queue hooks are
optional and fail closed when absent (see [development](lora_ota_development.md)).

The product uses existing MeshCore identities with a private per-contact
OTA-administrator permission that is separate from the remote-CLI flag `0x10`;
it does not use factory OTA keys, OPEN commissioning or a host approval ledger.
Records from earlier OTA builds, where `0x10` was ambiguous, migrate to no OTA
permission and no remote CLI until explicitly regranted
([product guide](lora_ota_users.md#permission-migration-from-earlier-ota-builds)).

## Admission and transfer

The shared 59-byte canonical descriptor binds board/family, role, image size,
SHA-256, security counter, capabilities, format, key identifier and Ed25519
algorithm. `bootloader/xiao_nrf52840_ota/tools/xiao_ota_descriptor.py` is the host
codec; native contract tests compare its geometry with the embedded contract.
ESP descriptors use the logical app address; partition selection belongs to
the receiver backend.

An administrator signs the descriptor using existing companion CMD33/34/35.
The receiver verifies the claimed owner against its current administrator
permissions, signature, descriptor policy and confirmed anti-rollback floor
before admitting persistent state. Blocks are individually authenticated and
bound to the admitted descriptor. Durable receipt state supports retry/resume;
READY requires complete image verification, not just received byte count.
COMMIT rechecks current OTA-administrator permission and the owner's signature.
The nRF installer verifies the command's exact admitted signer and delegates
administrator policy to the trusted application; it is not an independently
pinned publisher root. The zero-filled reference marker is not a trust anchor.
Stock local cache self-signing cannot authorize receiver installation.

A live candidate is not silently replaced. Explicit signed generation-bound
abort/reupload paths preserve owner/content/purpose checks. Counter advancement
occurs only with healthy confirmation, not staging or COMMIT admission.

## Delivery and installation

Native companion USB OTA is CMD67, reply30, fixed 107-byte ABI3 status. CMD66 and
reply29 remain the ordinary upstream CLI interface. OTA payload integers are
big-endian inside the unchanged `<`/`>` plus little-endian-length USB envelope.
The uploader filters responses by ABI, opcode, target, descriptor hash, counter,
generation, BEGIN nonce, local/remote scope and freshness. All hosts, companions and
receivers use OTA wire version 3. Earlier companions (ABI below 3) are refused
before signing or staging. Receivers that do not send the 123-byte version-3
census report are never sent blocks.

Direct delivery negotiates a signed bounded off-normal-frequency lease and
returns both radios to normal afterward. Lease requests are signed under
`MeshCore/OTA/direct/v3` or `MeshCore/OTA/direct-profile/v3`. Each carries the
receiver's current single-use RAM challenge from its latest census report. The
receiver redraws that challenge at boot, at BEGIN and on accepting a request, so
replayed, reordered and pre-reboot requests cannot retune it. Directed delivery
uses the mesh; background uses a configured channel and selective repair. Both
always use reliable attempt-diverse framing, so a retry can avoid a relay that
already suppressed a lost copy; the legacy unframed form is not offered by hosts. Airtime budgets
apply to normal-channel traffic. The stock 1.17.1 adapter uses existing signing,
raw RF and physical-TX counters, not native CMD67; it is direct/zero-hop only.

COMMIT is a separate signed action. Hosts wait for READY before one COMMIT and
then for matching Installed. Every fresh BEGIN, including ABORT followed by an
identical reupload, draws a 16-byte BEGIN nonce from hardware entropy and the
descriptor hash. If no true hardware entropy source is available at that moment
(on ESP32-S3, for example, while Wi-Fi is initialized or Bluetooth is changing
state), BEGIN is refused as Unavailable; there is no pseudo-random fallback.
The nonce is persisted in the candidate record. COMMIT signs
`MeshCore/OTA/commit/v2` over the target, descriptor hash, counter, generation
and nonce. It is therefore idempotent for the same durable attempt across resets,
and it is denied for any other attempt or an unbound (all-zero) nonce. There is
no fallback to the earlier unbound COMMIT. RF lifecycle reports are unsigned; reported
Installed is not a cryptographic attestation or independent health proof.
Timeout, failed trial/rollback, ABORTED or inconsistent state remains failure.

## Platform durability

nRF52840 uses external QSPI candidate/backup/state and a matching primary plus
fixed returning installer. The durable boot transaction binds admitted content,
active/backup extent and settings. Trial-safe filesystem/identity handling and
health confirmation precede advancing the floor; recovery restores the previous
image/settings without treating a failed candidate as confirmed.

Candidate state is tri-state: found, absent, or unreadable. Unreadable state
reports `Unavailable` with no snapshot and refuses BEGIN, ABORT, COMMIT and erase
until an authoritative reload succeeds; it is never reported as Idle. The stock
cache proof reports `InvalidCache`. These metadata slots make the store
unreadable, whatever state the commit marker is in (including fully erased):

- any non-blank slot that is not a supported, CRC-valid v1/v2 record, such as a
  torn record write or interrupted erase damage;
- a marked record with CRC or header damage.

There is no fallback to any older record, phase or authority, so a revoked
approval can never return. This availability cost is deliberate. Ordinary USB/DFU
application restoration may restore ordinary service, but it does not establish
persistent OTA metadata recovery. The nRF external-QSPI candidate record region
is not cleared by an ordinary internal APP ZIP DFU or a filesystem erase. No
supported metadata-repair procedure is currently provided for unknown, torn-body
or tombstoned ESP cases. A CRC-valid record whose marker is incomplete
is honoured as newest if its phase is Idle, Aborted or Failed, so an interrupted
ABORT, failure or retirement stays effective. A forward phase (Receiving,
Verifying, Ready, Committed) with an incomplete marker is ignored in favour of
the same attempt's previous record. A CRC-valid unmarked first BEGIN (initial
Receiving) reads as empty.

A fresh signed BEGIN or reupload resets the store. Before erasing the candidate
records sector, the reset overwrites every non-blank 256-byte record slot
(bytes 0..207) with zeros and verifies each one, leaving a "tombstone". A NOR
sector erase cut by power loss is unordered, so without this it could blank only
the newest ABORTED record and leave an older READY as newest. With tombstones,
any slot that is exactly zero shows that the device's own authenticated reset
had begun. The store then reads empty and never revives an older READY, its
nonce or a captured COMMIT; a fresh signed BEGIN with a new nonce proceeds
normally on nRF/stock. Any of the following reads Unavailable, with no supported
metadata repair:

- the cut tore the first tombstone program, so no exact zero slot exists;
- a read failure;
- any unexplained non-blank slot without a tombstone.

On ESP32-S3 a tombstoned or partly erased region is neither fully erased nor the
first-write record below, so OTA stays disabled (no supported metadata repair).
A tombstone makes the stock cache proof ask for an explicit retry/reupload,
never older ownership. The reset costs up to 16 extra 208-byte programs per BEGIN.
Arbitrary external or manual flash rollback is out of scope.

Startup only mounts storage first. It formats only after a failed mount on a
proven Normal boot with a healthy radio, and it generates an identity only
when the identity is positively absent.

ESP32-S3 requires two app slots and rollback-enabled vendor bootloader support.
Staging/state must not target the running or selected boot partition. Backend
partition identity and vendor OTA metadata are rechecked around destructive
operations. Trial confirmation uses the actual vendor validity transition;
failure requests rollback rather than claiming success from compile flags.
Unreadable or unexpected candidate metadata disables OTA. The single exception
is the exact partial record a power cut can leave during the first write of a
new BEGIN (the initial Receiving record above). It must be one unmarked,
CRC-valid, nonce-bound record, signed by its owner for this board/role, and the
whole remaining metadata region must read back erased. Only that verified record is left for the next fresh signed BEGIN
to erase. It is not a general recovery path.

See [the paired bootstrap guide](../bootloader/xiao_nrf52840_ota/README.md) and
[product guide](lora_ota_users.md). Direct nRF hardware success is established;
ESP, Solar and routed/fleet hardware behavior are not yet qualified.
