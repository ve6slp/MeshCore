# LoRa OTA transaction boundaries

OTA is optional and compiled out of normal environments. The product uses
existing MeshCore identities and administrator authority, not factory OTA keys,
OPEN/challenge commissioning, or a host approval ledger.

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

Native companion USB OTA is CMD67, reply30, fixed 90-byte ABI2 status. CMD66 and
reply29 remain the ordinary upstream CLI interface. OTA payload integers are
big-endian inside the unchanged `<`/`>` plus little-endian-length USB envelope.
The uploader filters responses by ABI, opcode, target, descriptor hash, counter,
generation, local/remote scope and freshness.

Direct delivery negotiates a signed bounded off-normal-frequency lease and
returns both radios to normal afterward. Directed delivery uses the mesh;
background uses a configured channel and selective repair. Airtime budgets
apply to normal-channel traffic. The stock 1.17.1 adapter uses existing signing,
raw RF and physical-TX counters, not native CMD67; it is direct/zero-hop only.

COMMIT is a separate signed action. Hosts wait for READY before one COMMIT and
then for matching Installed. RF lifecycle reports are unsigned; reported
Installed is not a cryptographic attestation or independent health proof.
Timeout, failed trial/rollback, ABORTED or inconsistent state remains failure.

## Platform durability

nRF52840 uses external QSPI candidate/backup/state and a matching primary plus
fixed returning installer. The durable boot transaction binds admitted content,
active/backup extent and settings. Trial-safe filesystem/identity handling and
health confirmation precede advancing the floor; recovery restores the previous
image/settings without treating a failed candidate as confirmed.

ESP32-S3 requires two app slots and rollback-enabled vendor bootloader support.
Staging/state must not target the running or selected boot partition. Backend
partition identity and vendor OTA metadata are rechecked around destructive
operations. Trial confirmation uses the actual vendor validity transition;
failure requests rollback rather than claiming success from compile flags.

See [the paired bootstrap guide](../bootloader/xiao_nrf52840_ota/README.md) and
[product guide](lora_ota_users.md). Direct nRF hardware success is established;
ESP, Solar and routed/fleet hardware behavior are not yet qualified.
