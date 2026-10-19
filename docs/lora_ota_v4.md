# MeshCore OTA v4

This is a clean-break, experimental update protocol carried by MeshCore's OTA
payload type (`0x0c`). It does not accept the earlier lab protocol. Installing
firmware is not commissioning a device: identity, administrators, preferences,
and the confirmed rollback floor are never part of an application package.

## Integrity and airtime

The package contains one signed manifest and independently compressed 8192-byte
raw-image chunks. Each chunk uses raw, LZMA, or LZMA with Thumb filtering,
whichever is smallest. LZMA uses the fixed 8192-byte dictionary, `lc=0, lp=1,
pb=1` profile; compressed data must include its end marker and have no trailing
bytes. The last raw chunk can be shorter. Incompressible chunks stay raw.

A flat list of raw chunk SHA-256 hashes is authenticated by the manifest.
For the 519940-byte Solar image there are 64 chunks: 2048 bytes of hashes,
plus three bytes per chunk for codec and stored length. A separately supplied
seven-hash Merkle proof per chunk would cost 14336 bytes. Proof caching or
multiproofs can reduce that cost, but add state and recovery complexity without
helping this bounded, full-image transfer. The manifest is bounded to 8192 bytes
and 128 chunks; there is no dynamically growing hash tree.

The complete manifest is `227 + 35 * chunk_count` bytes, including both
signatures: 2467 bytes for 64 chunks, or 20 radio slices. A maximum-size data
frame spends 23 bytes on OTA framing and 128 on image data, before MeshCore
routing overhead. This replaces the earlier 64-byte signature on each data
packet; control/status signatures remain infrequent and independently bound
to their purpose.

Data has no signatures. Each radio slice has a CRC-32 for accidental corruption;
the receiver hashes the complete decoded raw chunk before making durable
progress. It then checks the exact full raw-image SHA-256 before READY and again
at the platform's installation boundary. CRC is not an authentication mechanism.
Hostile slices can delay a transfer, but cannot authorize a different image.

## Package encoding

All integers are unsigned, big-endian. The signed manifest is:

| Field | Bytes |
|---|---:|
| ASCII `MCO4` | 4 |
| Version (`4`) | 1 |
| Raw chunk size log2 (`13`) | 1 |
| Chunk count | 2 |
| Manifest signer's public key | 32 |
| Canonical boot image descriptor | 59 |
| Real signature on the canonical boot descriptor | 64 |
| Chunk entries: codec u8, stored length u16, raw SHA-256 | 35 each |
| Manifest signature | 64 |

The manifest signature covers the domain `MeshCore OTA package v4` followed by
one NUL byte and every preceding manifest byte. The package identifier is the
SHA-256 of the complete signed manifest. Its first eight bytes are the radio
tag; complete hashes remain authoritative at admission and activation.
The canonical 59-byte descriptor is an existing boot safety ABI, not an old
radio-protocol compatibility layer. Its signature is genuine, not synthesized
by the receiver. It binds board family, board variant, role, application
address, exact raw size, raw hash, security counter and installer capabilities.
Chunks follow the manifest in entry order with exactly the stated lengths.

## Radio framing

`src/helpers/ota/OtaV4Protocol.h` is the byte-level contract. Every frame is:

| Field | Bytes |
|---|---:|
| Magic (`0xd4`) and kind | 2 |
| Nonzero transmission attempt | 4 |
| Package tag | 8 |
| Object index | 2 |
| Complete object length | 2 |
| Slice index | 1 |
| Slice bytes | 1..128 |
| IEEE CRC-32 over header and slice | 4 |

Full frames are 151 bytes with 128 useful bytes. Slices have fixed 128-byte
geometry; only the final slice is short. The object index is the raw chunk
index for DATA, zero for manifest/commands, and the request identifier for
replies. Retries get a new attempt before MeshCore duplicate suppression.
Attempts do not grant authority and do not advance durable receiver state.

Stock serial's 176-byte limit is a transport constraint, not an OTA payload
size. Adapters must account for serial command/reply bytes, the MeshCore
header, path hash width and maximum path growth before accepting a route.
They must reject a route that cannot carry these fixed slices rather than
truncate, rely on implicit fragmentation, or silently change protocols.
Native serial and stock serial carry the same OTA objects.

## Authority and transaction

One receiver engine owns `Receiving -> Verifying -> Ready ->
ActivationPending -> Trial -> Confirmed`, with explicit Aborted, Failed and
MetadataFault outcomes. No second cache receiver or RF uploader owns competing
state. The sender can distribute the same chunks once to an admitted fleet.
Receivers expose a next-chunk index and 64-bit missing-slice bitmap for repair.
Only one chunk is assembled at a time; interruption loses at most that chunk's
RAM slices, not verified durable progress.

A signed manifest alone never admits or activates an update. Admission is
signed by a current administrator, names the full receiver key and full package
hash, and binds the receiver's unpredictable boot challenge and expected
durable generation. Activation and abort name the admitted transaction nonce
and generation. Current authority is checked at every state-changing boundary,
including activation. Package-signing authority is checked before admission
and activation. Counters must exceed the confirmed floor.

Signed commands have owner key (32), target key (32), package hash (32), nonce
(16), expected generation (4), signature (64). Their domain is
`MeshCore OTA <action> v4` followed by NUL, where action is `admit`, `activate`,
`abort`, or `repair`. The signature covers the domain and the first 116 bytes.
Lease commands insert frequency kHz (u32), bandwidth Hz (u32), SF (u8), CR
denominator (u8), and duration milliseconds (u32) before the signature. Their
domain is `MeshCore OTA lease v4` followed by NUL. The duration is at most
60000 ms; zero means release. Lease and repair use the current receiver
challenge, not the admitted transaction nonce. Successful admission, abort,
repair and lease changes consume and replace that challenge. Boot also
replaces it. Replaying a lease cannot extend its expiry. A lease never persists
over ordinary radio preferences. Transmission power is not changed by a lease.

Queries supply a fresh host nonce. Receiver-signed status binds that nonce to
the full identity, current transaction, generation, confirmed floor and actual
running-image evidence. Unsigned bitmap progress is scheduling advice only;
it cannot establish authorization, READY, successful activation or installation.
An ambiguous activation response is reconciled, never automatically re-admitted
or blindly activated again.

### Query, status and repair objects

QUERY is target key (32) and fresh host nonce (16). Its header object field is
the host's request identifier; STATUS echoes that identifier. Query tags are
zero. STATUS signs `MeshCore OTA status v4` plus NUL and these exact fields:

| Offset | Field | Bytes |
|---:|---|---:|
| 0 | Receiver full public key | 32 |
| 32 | Echoed host nonce | 16 |
| 48 | Current receiver challenge | 16 |
| 64 | Admitted package SHA-256, or zero | 32 |
| 96 | Admitted transaction nonce, or zero | 16 |
| 112 | Transaction generation | 4 |
| 116 | Candidate security counter, or zero | 4 |
| 120 | Confirmed security floor | 4 |
| 124 | Phase | 1 |
| 125 | Last explicit result | 1 |
| 126 | Next raw chunk index | 2 |
| 128 | Missing-slice bitmap for that chunk | 8 |
| 136 | Actual running raw-image SHA-256, or zero if unknown | 32 |
| 168 | Evidence flags | 1 |
| 169 | Signature | 64 |

Evidence bits are 1 for known floor, 2 for known running hash, and 4 for
confirmed running image. Unknown values are not inferred from a candidate.
A successful installation requires a fresh valid signature, matching target,
host nonce and package, Confirmed phase, the expected raw hash, and all three
evidence flags with a sufficient confirmed floor.

PROGRESS_QUERY is the target key (32). PROGRESS echoes the request identifier
and contains target key (32), generation (u32), next chunk (u16), missing-slice
bitmap (u64), phase (u8), and result (u8). A set bitmap bit means that slice
is missing. Its full-package tag must match the active job; this unsigned
object does not prove success or replace fresh signed reconciliation.

REPAIR uses the standard signed-command shape, current receiver challenge,
and zero package hash. It explicitly discards only OTA staging. It is refused
while an installer command or trial is live. Metadata faults are never repaired
as a side effect of QUERY, admission, boot, or ordinary filesystem mounting.

## Durability and device personality

Verified chunk data reaches staging before its journal progress marker.
Metadata compaction writes and verifies the replacement bank and commits its
new generation before retiring the old bank. Torn records, generation ties,
and ambiguous metadata fail closed; recovery must not revive a revoked READY
record. An administrator can explicitly repair OTA staging without formatting
the personality store or resetting the confirmed floor.

A readable staging record from an earlier protocol leaves the receiver in
MetadataFault and requires explicit repair before another transfer. It does
not prevent a healthy nRF boot-owned trial from confirming its installed
image. A flash read, write or erase I/O failure still blocks trial confirmation.

The board adapter alone owns storage geometry, boot command construction,
trial confirmation, rollback and installed-image evidence. The receiver owns
the protocol transaction. The host owns one durable job and a transmitter-wide
airtime scheduler, with transports limited to framing, routing and device I/O.
After sending the manifest, the host waits for a fresh signed receiver response
before sending admission fragments. This lets the receiver finish signature
verification without relying on a fixed delay.
An owned radio override expires and restores the unchanged ordinary settings,
including the user's forwarding preference.

## Building and commissioning

Ordinary firmware remains OTA-disabled. The explicit environments are
`Xiao_nrf52_companion_radio_ota_usb`, `Xiao_nrf52_repeater_ota_usb`,
`SenseCap_Solar_companion_radio_ota_usb`,
`SenseCap_Solar_repeater_ota_usb`, `Xiao_S3_WIO_companion_radio_ota_usb`, and
`Xiao_S3_WIO_repeater_ota_usb`. The role is 0 for a companion and 1 for a
repeater. Host dependencies are declared in `requirements-ota.txt`.

Use the existing system PlatformIO and Make targets:

```sh
make build ENV=Xiao_nrf52_companion_radio_usb
make build ENV=Xiao_S3_WIO_repeater_ota_usb
make build-ota-solar OTA_IMAGE_FREEZE="$PWD/.tmp/ota-boot-builds/my-v4-solar"
make test-ota-v4-native
make test-ota-v4-decoder
make test-ota-v4-platform
make test-ota-v4-esp
make test-ota-v4-boot
make ota-v4-arm-size OTA_IMAGE_FREEZE="$PWD/.tmp/ota-boot-builds/my-v4-solar"
make ota OTA_ARGS='--help'
```

Choose a new immutable freeze directory for each Solar build. Build and test
commands do not flash hardware. `make ota` is the single host entry point;
transport selection belongs to that CLI, not separate stock/native deployment
recipes. A package is immutable; job state is separate and durable.

Commissioning an nRF bootloader/installer is a separate physical bench
operation, documented in the
[paired bootloader recipe](../bootloader/xiao_nrf52840_ota/README.md). Select
the exact board, role and physical device, and take a verified personality
backup before an explicitly destructive conversion. Merely entering USB
recovery must not erase identity, administrators or settings. An application
OTA update never invokes commissioning, resets the rollback floor, changes
identity, or silently falls back to USB/SWD.
Use the BP1.5 pair for unattended nRF nodes: failed installer attempts restart
automatically and resume installation or rollback. Updating the application
alone leaves an older pair unchanged.

Earlier v3 lab builds require a deliberate one-time bootstrap using their
frozen tools or an explicitly approved application-only recovery procedure.
The v4 product contains no v3 radio handler or automatic migration path.

## Packages and durable jobs

The host uses the explicitly selected companion's signing operation. It does
not export its private key or read a private-key file. That companion's full
public key must be a current OTA administrator on each target. For a repeater,
the existing administrator ACL supplies this authority; for a companion,
the physically trusted USB administrator operation manages it separately
from ordinary contact permissions.

The following variables represent explicit selections, not auto-discovered
devices. The stock transport also requires `--usb-serial` with its actual
physical serial. Use a stable physical-path anchor for duplicate serials.

```sh
make ota OTA_ARGS="build --by-id $PORT --owner $OWNER --transport stock --usb-serial $SERIAL \
  --image $IMAGE --board sensecap_solar_p1 --role-id 1 --counter $COUNTER --output $PACKAGE"

make ota OTA_ARGS="deploy --by-id $PORT --owner $OWNER --transport stock --usb-serial $SERIAL \
  --package $PACKAGE --job $JOB --target $TARGET --flood --max-path-bytes 1 --duty 0.02"

make ota OTA_ARGS="status --by-id $PORT --owner $OWNER --transport stock --usb-serial $SERIAL --job $JOB"
```

`$JOB` must name a new directory on first deploy. The host creates it with
mode 0700 and stores its immutable package, route/target policy, signed
observations, operation intents, transmitter cooldown and metrics separately
from the firmware package. Package files are exclusive creations, never
overwritten. Select a counter above the authenticated confirmed floor.

Repeat the same deploy command with the existing job to resume. Changing
targets, package, route, transport or duty policy while resuming is refused.
A later firmware version uses a new package and job with a counter above the
confirmed floor. A confirmed receiver accepts that signed admission without
clearing its staging metadata or resetting its floor.
A restart authenticates fresh receiver state and reconciles uncertain
operations before sending more data. `--stage-only` stops at authenticated
READY without authorizing activation. A later deploy of that same job
deliberately requests activation and waits for matching signed confirmation.
`abort --job ...` and `repair --job ...` are explicit administrator actions;
neither is an automatic timeout or admission fallback.

For an OTA-aware native companion select `--transport native`; its radio
bridge carries the same frames. `--local` feeds that companion's own receiver
without RF, using the same signed transaction and a target equal to its
full public key. This is not a separate cache/upload engine.

The default transfer leaves ordinary sender radio and forwarding preferences
unchanged. Stock CMD11 persists preferences and has no autonomous expiry:
the stock adapter refuses to call it as a supposedly temporary lease.
Sender and receiver must already share a suitable legal radio profile.
The declared maximum path growth must fit the 176-byte stock boundary in
both directions; routes outside that bound fail before admission.

## Evidence and limitations

`make test-ota-host` builds and runs the actual native C++ receiver driver
before the Python suite. Its end-to-end cases use real signatures and the
production encoder, scheduler, serial framing and receiver; deterministic
loss is injected only at the transport boundary. File-backed staging and a
simulated boot-confirmation event do not establish physical flash or RF
qualification. `make test-ota-v4-platform` exercises real journal/staging and
boot command construction against fault-injected flash models.

`make test-ota-v4-esp` runs the production ESP adapter against a native SDK
model, including its journal-only flash access and same-image, higher-counter
rollback and confirmation. `make test-ota-v4-boot` passes production host frames
through the nRF receiver, flash adapter, C installer and trial-health confirmation
for both board families and roles. `make test-ota-rf-to-boot` selects that same
v4 test. These targets use modeled media and do not transmit or flash devices.
`make test-ota` includes all three alongside the host, native and decoder checks.

The nRF main-loop task has a 4 KiB stack. Boot-record proof workspaces live in
the board adapter, and image hashing and boot-command writing keep their stack
frames separate from signature verification. When changing these paths, check
the target build's `.su` files and nested RF receive calls, including status
queries after a confirmed install.

For a genuine firmware byte-stream run and a persistent encoder/frame report:

```sh
make test-ota-v4-image OTA_V4_IMAGE=/absolute/path/to/firmware.bin
```

The report defaults to `.tmp/ota-v4/image-evidence.json`. It distinguishes
actual host execution counters, modeled RF bytes/airtime, receiver replies
and historical physical-campaign elapsed time. Synthetic test signing keys
and simulated confirmation are labeled explicitly. Historical v3 Solar
results are not v4 hardware evidence, and elapsed wall-clock time is not
measured airtime.

### Identical Solar image comparison

The genuine 519940-byte Solar image with raw SHA-256
`2f548dab7cbefea792e1ce2d73205b9a0233f3f1b5c6c95d9b73093ddfb27c85`
completed the production v4 Python-to-C++ file-backed receiver path with
byte-exact raw integrity and fresh signed simulated confirmation.

| Quantity | Prior v3 Solar campaign | V4 identical-image software run |
|---|---:|---:|
| Stored compressed bytes | 335494 | 335346 |
| Data frames | 4074 | 2650 |
| Raw chunk size | 8064 | 8192 |
| Manifest bytes | Different v3 format | 2467 |
| Host transmissions | 5490 on hardware | 2893, no-loss simulated transport |

V4 requires about 35% fewer data frames for this exact image; almost all of
that gain comes from removing packet signatures, not a compression-ratio
claim. The software run additionally sent 20 manifest slices, 189 progress
queries, 30 signed-status queries and four admission/activation slices.
Its 189 progress replies and 60 status reply frames are counted separately.

At BW62.5 kHz/SF7/CR5 with at most one path byte, the conservative size-based
model estimates 1523.948 seconds of host TX and 90.641 seconds of receiver
replies, excluding loss, contention, duty waiting and platform CPU/flash time.
These are modeled airtimes, not physical measurements; the historical v3
7505.821-second campaign duration is elapsed time and cannot serve as an
airtime denominator. The software driver's clock and boot confirmation are
synthetic, not an observed Solar installation.

## Design sources

* [RFC 9019, section 3](https://www.rfc-editor.org/rfc/rfc9019.html#section-3):
  transport-independent signed manifests, multicast distribution, decompression,
  resumable delivery and status tracking.
* [RFC 9124, section 4.2.11](https://www.rfc-editor.org/rfc/rfc9124.html#section-4.2.11):
  authentic firmware is not necessarily authorized firmware; owner/operator
  approval is a separate requirement.
* [littlefs design](https://github.com/littlefs-project/littlefs/blob/master/DESIGN.md):
  NOR erase/program constraints and bounded copy-on-write metadata recovery.

These sources inform the design; this protocol does not claim SUIT, MCUboot or
littlefs format compliance. Byte counts above are protocol arithmetic, not
physical airtime measurements or a claim of production qualification.
