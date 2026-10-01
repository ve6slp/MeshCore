# XIAO nRF52840 external-QSPI OTA bootloader overlay

This directory is a reproducible overlay for Adafruit_nRF52_Bootloader commit
`c67f0bcf0fa8e841426335b1bbde91cda6ca1f50`. The upstream checkout and all
build products stay under `.tmp/`; no upstream source is vendored here.

The preferred no-SWD profile keeps USB UF2 mass storage and USB CDC serial DFU
recovery, but deliberately omits optional BLE DFU. It adds P25Q16H candidate
verification, backup, install, trial confirmation, and rollback before the
upstream boot flow starts. The original larger BLE-enabled profile remains
available for SWD commissioning.

## Lean simplification: genesis/authority receipt removed

The previous `BootFloorActivationReceiptV1` genesis/role-continuity receipt system has been deleted. The bootloader now trusts any structurally valid floor record — CRC-correct and commit-marker-complete, including `confirmed_counter_floor == 0` — without any separate genesis receipt requirement. Admin-signed install-command verification is unchanged: Ed25519 over the transport's 59-byte wire descriptor remains the sole authorization gate for installing new firmware.

The backup -> install -> watchdog trial -> health confirm/rollback flow, the A/B command/state/confirmation/floor journals, and the exact 28-byte Nordic SDK settings restore are unchanged. Historical sections further below that describe the removed receipt mechanism are kept only as background on why it was built and then deleted; they do not describe current bootloader behavior.

## Lean simplification: legacy v1 install-command format removed

The legacy 71-byte little-endian `xiao_ota_command_t` install-command format (the bootloader's own standalone descriptor, distinct from the LoRa OTA transport's wire format) has been deleted along with `xiao_ota_canonical_descriptor_t`, `xiao_ota_command_valid()`, and `xiao_ota_install_command_from_v1()`. This format was never used by any released firmware or deployed signing tool; it predates this bootloader's adoption of the transport's own canonical 59-byte big-endian wire descriptor + 64-byte Ed25519 signature (`xiao_ota_command_v2_t`), which was then the sole supported install-command format (188 bytes total: magic/version/length/sequence/nonce + 59-byte wire descriptor + 64-byte signature + active-image extent/hash + CRC/commit marker). `tools/sign_image.py` no longer accepts a `--command-version`/`--device-address` flag; it always emits this one format family. "v2" naming is kept in code purely to avoid a mechanical rename, not because another version still exists -- see the next section for why the actual on-wire `record_version` has since moved from 2 to 3.

## Lean simplification: app-admitted signer key embedded in the install command

`xiao_ota_command_v2_t` (`record_version` now `XIAO_OTA_COMMAND_VERSION_CURRENT` = 3, 220 bytes total, up from the prior 188-byte/version-2 shape) adds a 32-byte `admitted_signer_public_key_ed25519` field between `wire_descriptor` and `signature_ed25519`. This closes a gap versus the lean design: verification previously trusted only a single bootloader-compiled-in key (`XIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY`, defaulting to `xiao_ota_lab_public_key_ed25519` from `include/xiao_ota_public_key.h`), with no way to honor MeshCore admin-identity key rotation without a bootloader rebuild.

The trust model: the already-trusted, currently-running app verifies a manifest's signer using its own pre-existing MeshCore admin-identity mechanism (entirely outside this bootloader), then durably snapshots that admitted public key, alongside the signed manifest, into the install command at the explicit per-target COMMIT step. The bootloader itself never judges whether an embedded key "is a legitimate admin key" -- it only re-verifies that `signature_ed25519` is a genuine Ed25519 signature over `wire_descriptor` under EXACTLY the command's own embedded key (cryptographic self-consistency of the durable record across a power-fail), plus the existing SHA256/model/size/geometry/counter-floor checks. Anti-rollback -- rejecting a stale command signed under a previously-admitted but since-rotated-out key -- is unchanged and still enforced solely by the existing monotonic counter-floor check, independent of key identity; no new ACL/issuer/grant/attestation hierarchy was added. This remains the documented local-failure trust boundary, not a physical-attacker secure-boot/APPROTECT feature.

The compile-time `XIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY` override mechanism in `src/xiao_ota_boot_io.c` has been removed entirely (including its `#include "xiao_ota_public_key.h"`), since verification now always reads the key from the command record. `tests/fake_trust_anchor.h` and the Makefile's `-DXIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY=xiao_ota_test_public_key_ed25519 -include .../fake_trust_anchor.h` test-build flags are harmless vestigial build inputs now (an unused macro definition and an unused extern declaration); `tests/test_boot_process.c` instead copies its own fresh test keypair's public half directly into each built command's `admitted_signer_public_key_ed25519` field. `include/xiao_ota_public_key.h`/`xiao_ota_lab_public_key_ed25519` remains in use for the unrelated boot-info marker embedded at `0xFDC00` (an informational/audit field read by `tools/verify_boot_info_artifact.py`, not a runtime trust anchor).

`tools/sign_image.py` derives the admitted key from `--private-key`'s own public half (`openssl pkey ... -pubout -outform DER`, last 32 bytes) -- the lab/CLI signer and the admitted key are the same keypair in this tool, the correct analogue of "the running app just finished verifying this exact signer and is now snapshotting its key." A real app-side COMMIT flow supplies whatever key it actually admitted for that specific manifest.

This field addition has **zero impact on internal code-flash fit**: install commands live entirely in external QSPI flash (`XIAO_OTA_COMMAND_A`/`XIAO_OTA_COMMAND_B` at `0x18C000`/`0x18D000`, inside the `[0x18C000,0x194000)` bootjournal region), never the internal 38,912-byte fixed-boot-code budget. ARM fit after this change (both roles): 37,812 / 38,912 bytes used, 1,100 bytes free -- slightly *better* than the pre-change 37,844/38,912 figure, since removing the now-unused `XIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY`/`xiao_ota_public_key.h` reference from `xiao_ota_boot_io.c` recovered 32 bytes that more than offset any other change in this file.

## Fixed: no-SWD Ed25519 wrapper stack overflow

`src/xiao_ota_ed25519_tweetnacl.c`'s `ed25519_verify()` previously sized its
`opened_message` scratch buffer to only `message_length` (71) bytes, but
TweetNaCl's `crypto_sign_open(m, mlen, sm, n, pk)` copies the *entire*
signature-plus-message (`n = 64 + message_length`, up to 135 bytes) into `m`
before validating and truncating it. Verifying any real, full-size 71-byte
install-command descriptor -- the exact signature check that gates a
candidate install in `command_policy_valid()` -- overflowed that buffer by up
to 64 bytes on the stack. The prior unit test only exercised the RFC 8032
empty-message vector (`message_length == 0`, so `n == 64`, which happened to
fit), so it never caught this. `opened_message` is now sized to match
`signed_message` (`64 + 71` bytes). `tests/test_descriptor_contract.c` adds
behavioural coverage with real, full 71-byte-message Ed25519 signatures
(verified independently with `openssl pkeyutl -verify`) to prevent
regression. This fix changes only bootloader-internal scratch sizing; the
signed record formats, layout, and journal contract are unchanged.

## Fixed: QSPI EasyDMA cannot read from internal code flash

`copy_internal_to_qspi()` (used by the backup step, `BACKUP_COPYING`) called
`qspi_write()` with a pointer built from `XIAO_OTA_APP_START` -- internal
code flash -- as the EasyDMA source. The nRF52840's QSPI peripheral EasyDMA
can only address Data RAM; it cannot DMA directly out of code flash. On real
hardware this made the backup step's own page-by-page readback verification
unreliable, which meant `copy_internal_to_qspi()` could return `false` (or
worse, silently pass with corrupt data) and trip `force_recovery()` before an
install was ever attempted. The fix stages each 256-byte chunk into a new
`flash_stage_buffer` (Data RAM) with a CPU `memcpy()` first, then hands that
RAM pointer to `qspi_write()`; the readback compare now checks against the
same RAM buffer instead of re-reading flash through EasyDMA rules that don't
apply to it. `tests/test_source.py` adds a source-level regression check that
`copy_internal_to_qspi()`'s `qspi_write()` call is never given a
`XIAO_OTA_APP_START`-based pointer. A genuine behavioural test (mocking the
`NRF_QSPI` peripheral itself) is not included: `xiao_ota_boot.c` depends on
the vendored Adafruit bootloader's hardware headers and isn't host-buildable
without a much larger register-mock harness, and building a partial one that
only covers this call site risked more confidence than it earns. The
source-level check is what's actually shipped; treat this fix as verified by
code review and the corrected size/behaviour above, not by an executed test,
until real QSPI hardware confirms it.

## Fixed: OTA permanently disabled after any rollback

After a successful rollback, the boot flow persisted `state.phase =
XIAO_OTA_PHASE_FAILED` -- but the top-level gate that decides whether a new
signed install command may be accepted only allowed `EMPTY` or `CONFIRMED`.
`FAILED` was a dead end: every later boot hit `if (state.phase ==
XIAO_OTA_PHASE_FAILED) return;` and never looked at a new command again,
even one signed with a fresh, higher security counter. In practice, one
rejected or interrupted OTA attempt would permanently disable OTA on that
device (the application itself kept running fine, since rollback already
restored the verified backup and bank_0 settings before FAILED was written
-- only future installs were blocked). The fix adds `FAILED` to the accepted
phases alongside `EMPTY`/`CONFIRMED`, since a device in `FAILED` is already
confirmed-safe (its bank_0 settings and hash were checked before FAILED was
persisted); a new command still has to pass the same
`command_policy_valid()` signature/counter/hash checks as any other install.
The accept-phase decision now lives in a single, host-testable function,
`xiao_ota_command_acceptable_phase()` (`xiao_ota_record.c`/`.h`), called
directly from `xiao_ota_boot_process()` instead of being re-inlined as an OR
chain; `tests/test_record.c` behaviourally exercises it for every phase
value (not just FAILED), so this can't silently regress again.
`tests/test_source.py` also keeps a source-level check that the boot hook
calls that real function and still reaches `command_policy_valid()` before
re-arming `BACKUP_COPYING`.

## Fixed: corrupt (not erased) anti-rollback floor no longer silently defaults to counter 0

Before this fix, if neither floor A/B copy passed structural validation
(bad magic/CRC), `xiao_ota_boot_process()` unconditionally zeroed the
in-memory floor -- treating a genuinely-blank, never-provisioned floor
(legitimate: this device has never completed an OTA install, counter floor
0 is correct) exactly the same as a *damaged* or *unrelated* floor sector
(e.g. a torn write, or leftover raw bytes from a hardware diagnostic run
before OTA provisioning). That second case silently reopened the
anti-rollback counter at 0, which a corrupted-but-otherwise-unremarkable
flash sector could achieve without any cryptographic bypass at all. The fix
adds `xiao_ota_bytes_erased()` (`xiao_ota_record.c`/`.h`, host-tested) and
uses it to distinguish "both floor slots fully erased" (safe: counter floor
0) from any other invalid floor content (unsafe: `floor_trustworthy =
false`). A new command is now refused outright when the floor is untrustworthy,
and an in-flight transaction is forced into its existing, already-safe
`ROLLBACK_COPYING` recovery path instead of proceeding on a fabricated
counter floor of 0. See "QSPI ownership and records" below for the
operational note this implies for any board whose floor-A sector currently
holds pre-commissioning diagnostic bytes.

## Fixed: install-command size cap no longer allows erasing into v1.17's filesystem region

v1.17's actual internal application code region is only `0x27000..0xD4000`
(708,608 bytes); `0xD4000..0xED000` (102,400 bytes) is where v1.17's own
internal filesystem (LittleFS/ExtraFS) lives today. Before this fix,
`xiao_ota_install_command_policy_valid()` capped a signed command's
`image_size_bytes` (the candidate/install size) against the *full*
`XIAO_OTA_CANDIDATE_SIZE` (811,008 bytes, `0x27000..0xED000`) -- the same
bound used for the QSPI staging slot and for the backup/active-image
extent, where accepting the full range is correct (backing up that many
bytes is always safe: a protective read+copy of whatever is really there,
filesystem included). Applied to the *install* size instead, that same
bound would have let an otherwise cryptographically valid, correctly
signed command install a candidate large enough to erase/overwrite into
v1.17's filesystem region -- nothing else in the wire contract stopped it.

The fix adds a distinct cap, `XIAO_OTA_INSTALL_MAX_SIZE` (`include/
xiao_ota_layout.h`, 708,608 bytes / `0xAD000`, derived from
`XIAO_OTA_INSTALL_ALLOWED_END = 0xD4000`), and uses it (not
`XIAO_OTA_CANDIDATE_SIZE`) for the `image_size_bytes` check only; the
active-image/backup extent check is unchanged and still accepts the full
811,008-byte extent. `tools/sign_image.py` enforces the same two bounds
independently (`INSTALL_MAX_SIZE` for `--image`, `BACKUP_MAX_SIZE` for
`--active-image`) so an over-cap candidate is rejected before it is ever
signed. This is a safety cap, not a wire-format change: no schema,
role/target/format field changes, and both command v1 and v2 share the
identical check. No sweeping filesystem migration is required for this --
every real firmware image today is comfortably under 708,608 bytes; this
cap only stays in force until an explicit filesystem-relocation migration
proves the FS no longer lives past `0xD4000` (no such migration-complete
signal exists yet, so there is nothing to opt into today).

`tests/test_record.c` proves the exact boundary behaviourally: exactly
708,608 bytes is accepted, 708,609 is rejected, and the active-image/backup
extent still accepts the full 811,008 bytes when it matches the expected
active extent.

## Fixed: active-image extent no longer trusts a stale post-install floor value

Before this fix, `xiao_ota_boot_process()` derived the currently-trusted
`expected_active_extent` as `floor.active_image_extent != 0 ?
floor.active_image_extent : active_extent_from_settings(...)` --
preferring a durable value the bootloader itself only ever wrote once, at
the moment a *previous* OTA install was confirmed. If a user has since
reflashed a different image over USB/CDC (bypassing this bootloader
entirely, which is an explicitly supported recovery path), that floor
value goes stale, yet boot would keep trusting it for backup/rollback
sizing and for the extent bound `command_policy_valid()` checks a signed
command against. Separately, `active_extent_from_settings()` itself
silently substituted a full-size guess (`XIAO_OTA_APP_MAX_SIZE`) on any
invalid bank-0 metadata (bad marker, zero/oversized size, or a live CRC-16
mismatch), masking real corruption or a missing image as if it were a
legitimate full-size install.

The fix makes extent derivation unconditional and fail-closed on every
boot: `expected_active_extent` is now always recomputed from *fresh*
bank-0 metadata (current `BANK_VALID_APP` marker, nonzero bounded
`bank_0_size`, and a live CRC-16 recomputed over that exact extent in
internal flash right now) via the new pure, host-tested
`xiao_ota_resolve_active_extent()` (`xiao_ota_record.c`/`.h`); `boot.c`'s
`active_extent_from_settings()` is now a thin wrapper that only performs
the actual flash CRC-16 read and defers the accept/reject decision to it.
`floor.active_image_extent` is no longer read for this purpose at all
(the stale-floor code path is gone); the field is still *written* on
confirmation for record-schema/telemetry stability (no record-version
bump, no counter reset), but is now dead for extent derivation, which is
called out with a comment at the write site. A missing/invalid fresh
bank-0 read fails closed exactly like an untrustworthy floor already did
-- both the command-acceptance gate and the in-flight
backup/install-transaction gate now require `have_active_extent` in
addition to `floor_trustworthy`, so no new command is accepted and no
in-flight transaction is allowed to proceed on a guessed extent; an
in-flight transaction instead takes its existing `ROLLBACK_COPYING`
recovery path. This does not touch `floor.confirmed_counter_floor`, which
remains the sole, unconditional anti-rollback authority regardless of
bank-0 state.

`tests/test_record.c` proves `xiao_ota_resolve_active_extent()`
behaviourally: a fresh, valid, *different*-sized bank-0 image is accepted
on its own CRC-verified size (never a caller-supplied stale value -- the
function does not even take one as an argument, closing the bug at the
API level, not just in one call site); and each of a bad marker, zero
CRC, zero size, oversized size, and a CRC mismatch independently fails
closed with `out_extent` left untouched.

## Fixed: endless reinstall loop after a rolled-back (FAILED) transaction

`xiao_ota_command_acceptable_phase()` correctly treats `XIAO_OTA_PHASE_FAILED`
as ready to accept a new install command -- that is by design, since a
rolled-back device must still be able to accept a genuinely new signed
firmware. Before this fix, though, nothing distinguished a genuinely new
command from the exact same signed command that had already failed and
been rolled back: since the counter floor only advances on confirmation,
never on failure, the identical old command's counter still legitimately
verified against `floor.confirmed_counter_floor` every subsequent boot.
The device would silently re-accept it, redo the same doomed
backup/install/trial cycle, exhaust its trial boots again, roll back
again, and repeat this forever -- a permanent reinstall loop with no
externally visible error, not a controlled failure.

The fix adds `xiao_ota_command_is_retry_of_failed_transaction()`
(`xiao_ota_record.c`/`.h`, host-tested, pure): when the durable state is in
`XIAO_OTA_PHASE_FAILED` and the newly-decoded command's transaction nonce,
monotonic counter, *and* image hash are all identical to the failed
transaction's, the command is refused outright before any backup/install
work restarts. Changing even one of those three fields (a genuinely new
signed command, including a re-signed retry with a fresh nonce/counter)
is untouched by this check and proceeds exactly as before -- this never
inspects, weakens, or substitutes a signature; it only recognizes an
already-adjudicated failure by its durable identity.

`tests/test_record.c` proves this behaviourally: an exact
nonce/counter/hash match against a `XIAO_OTA_PHASE_FAILED` state is
refused; changing any one of the three fields is allowed; `CONFIRMED` and
`EMPTY` phases (and no prior state at all) are never treated as a retry
regardless of field equality.

## Fixed: trial-boot confirmation could advance the anti-rollback floor without verifying what is actually running

Before this fix, a trial-boot confirmation token that matched the
transport-level nonce/counter/hash recorded in `state` (via
`xiao_ota_confirmation_matches()`) was sufficient on its own to advance
`floor.confirmed_counter_floor` and mark the transaction `CONFIRMED` --
nothing re-checked that the image *actually currently running* in
internal flash still matched what this transaction installed and
hash-verified immediately after writing it. A USB/CDC reflash during the
60-second trial window (an explicitly supported recovery path that
bypasses this bootloader entirely), or flash damage, could leave a
different image running while a stale or replayed confirmation token
still nominally matched -- and the floor would advance anyway, durably
and irreversibly trusting an unverified image. Separately, the write
`floor.active_image_extent = intent.image_size_bytes` used whatever the
command slot currently decoded to at that moment -- which could have been
overwritten by a new (or attacker-supplied) command during the trial
window -- instead of the durable value this transaction actually recorded
at its own start (`state.active_image_extent`).

The fix adds `xiao_ota_confirmation_extent_and_hash_valid()`
(`xiao_ota_record.c`/`.h`, host-tested, pure): on every trial-boot
confirmation, the bootloader now re-derives a **fresh** active extent from
bank-0 metadata right now (the same `active_extent_from_settings()` used
for command validation), recomputes a **live** SHA-256 over internal flash
at that fresh extent, and requires both to match exactly what this
transaction installed and hashed right after writing it. If this fresh
check fails, the floor is never advanced; the transaction instead falls
straight into the existing, already-safe `ROLLBACK_COPYING` recovery
path in the same boot, exactly as an unconfirmed/failed trial would.

`tests/test_record.c` proves this behaviourally: matching fresh
extent+hash advances normally; an invalid fresh bank-0 read, a
differently-sized fresh extent, and a fresh-hash mismatch each
independently refuse to validate (simulating a USB reflash or flash
damage during the trial window), regardless of what the stale transport
confirmation token said.

## Fixed: a differently-sized update always rolled back (regression in the fix above)

The first version of the fix above compared the fresh post-install extent
against `state.active_image_extent` -- but that field is the OLD image's
extent, fixed once at transaction start (`intent.active_image_extent`)
and required to stay unchanged for the rest of the transaction: it sizes
the backup copy, and it is the exact byte count `ROLLBACK_COPYING` restores
from the backup on failure. Comparing a *new* candidate's fresh extent
against the *old* image's extent meant confirmation could only ever
succeed when the new image happened to be exactly the same size as the
old one -- any real differently-sized update always mismatched and always
rolled back, and `floor.active_image_extent` was left holding the old
size instead of the new one.

An intermediate version of this fix added a second durable
`installed_image_extent` field to `xiao_ota_state_t`, growing it from
152 to 156 bytes -- this was reverted: it broke the v1 152-byte state
record layout/ABI that firmware-side confirmation decoding already
depends on, and was unnecessary. `installed_hash_sha256` is already a
SHA-256 computed over exactly `candidate_size` bytes at install time
(right after install-copy is verified) -- it cryptographically binds
*both* the new image's content *and* its exact length: for a fresh
re-hash at a given extent to reproduce that digest, the extent used must
equal the original candidate size (SHA-256 pre-image/second-pre-image
resistance means a different-length input essentially never reproduces
the same digest). This lets a fresh read alone verify the new candidate's
own extent with no separate durable field, no mutable-command-slot value,
and no change to the 152-byte v1 state layout.

The fix renames and redesigns the predicate to
`xiao_ota_confirmation_hash_bound_extent_valid()`: it drops the
now-unnecessary explicit expected-extent argument entirely (passing the
fresh extent as its own "expected" value would just be a tautological
proxy check, not a real one) and instead requires the fresh bank-0 read
to be valid, the fresh extent to be non-zero and within
`XIAO_OTA_INSTALL_MAX_SIZE` (the same cap enforced at command-acceptance
time -- defence in depth against a corrupted/oversized fresh read), and
the fresh SHA-256 to match `installed_hash_sha256`. `floor.active_image_extent`
on the success path is now written directly from the fresh, verified
extent (never `state.active_image_extent`, the old backup's size, still
required unchanged for a correct rollback restore).

`tests/test_record.c` adds a boot-decision-sequence regression (chaining
the real pure functions in the same order/arguments `xiao_ota_boot.c`
uses, for an old-320-byte/new-489-byte pair and its reverse, with a real
SHA-256 computed over an actual shared in-memory buffer rather than a
placeholder digest, so the length-binding claim is proven for the real
hash implementation) proving: (a) a correct differently-sized
confirmation succeeds via the hash match alone; (b) hashing at the WRONG
extent over the same real flash contents does NOT reproduce
`installed_hash_sha256`, proving the check is a genuine length-binding
check and not a tautological "fresh extent compared to itself" proxy;
(c) `active_image_extent` remains untouched (available for a
correctly-sized rollback) throughout; (d) a fresh-hash mismatch (simulated
USB reflash during trial) still refuses regardless of extent size, and
`active_image_extent` still reflects the old backup span; (e) the same
FAILED signed command is refused identically across repeated simulated
boots (no repeated backup/install work), while a genuinely new nonce
(including one differing only in the high 32 bits of the full 64-bit
nonce field) is accepted. This is a parallel simulation of the same call
sequence and arguments `xiao_ota_boot_process()` uses (cross-referenced to
it by line) -- kept as a fast, focused regression on the individual
decision predicates, now supplemented (see "Literal-execution boot-process
tests" below) by a test that compiles and runs the real orchestration
function itself against a fake in-memory device. The fix was re-verified
with a real isolated ARM cross-compile of `xiao_ota_boot.c` (via
`prepare_upstream.py --work-dir`, no shared paths touched): it links and
fits flash/RAM budgets, and `xiao_ota_state_t` remains exactly 152 bytes,
matching the v1 layout.

## Literal-execution boot-process tests (shared processor, fake IO)

`xiao_ota_boot.c` used to hold both the OTA transaction decision logic
and the raw NRF52840 register accesses (`NRF_QSPI`, `NRF_NVMC`, `NRF_WDT`)
in one file, so it could never be compiled on a host: the decision logic
was only ever exercised by a parallel host-side re-simulation of the same
call sequence (`tests/test_record.c`, above), never by literally running
the production code path.

The file is now split along that exact boundary:

- `src/xiao_ota_boot_io.c` -- the entire transaction processor (accept,
  backup, install, trial, confirm, rollback), driven purely through the
  `xiao_ota_io_t` callback vtable (`include/xiao_ota_boot_io.h`: QSPI
  read/erase/write, internal-flash read/erase/write, bank-0 settings
  read/write, watchdog start, force-recovery). Zero SDK header
  dependency, so it compiles unmodified on the host.
- `src/xiao_ota_boot.c` -- reduced to thin `hw_*` adapters that wrap the
  real NRF52840 registers to satisfy `xiao_ota_io_t`, plus
  `xiao_ota_boot_process()`, which builds the real vtable and calls
  `xiao_ota_boot_process_io()`. This is the only place still requiring
  `nrf.h`/`bootloader_settings.h`/`dfu_types.h`, and is a thin enough
  wrapper that its correctness is evident by inspection against the
  vtable contract.

`tests/fake_io.c`/`fake_io.h` implement `xiao_ota_io_t` entirely in host
memory (a QSPI byte array sized to the real external-flash address space,
an internal-flash byte array, a bank-0 settings mock, and NOR/internal
AND-only write semantics matching real flash), with a `setjmp`/`longjmp`
crash-injection hook keyed to "the Nth call of callback kind X".
`tests/test_boot_process.c` builds real signed commands/confirmations
with the actual wire-encoding and record helpers (never hand-rolled
bytes) and calls `xiao_ota_boot_process_io()` -- the exact, unmodified
production entry point -- against that fake device, covering:

- a correct confirmation for a differently-sized update advancing the
  floor to the new extent, in both directions (grow and shrink);
- the same FAILED signed command refused identically across repeated
  boots with no repeated backup/install work, while a genuinely new
  64-bit nonce (differing only in the high 32 bits) is honoured;
- a crash injected mid-install (partway through a second flash sector):
  the interrupted boot leaves a durable, sector-aligned progress
  checkpoint and bank-0 metadata still describing the OLD image; because
  install writes the candidate in place over the live app region, the
  very next boot's fresh bank-0 CRC recheck can no longer validate
  against that now partially-overwritten region, so it fails closed and
  rolls back to the verified QSPI backup rather than resuming the
  install -- proven to restore the OLD image's exact bytes and extent;
- a stale confirmation (candidate content changed in place, simulating a
  USB reflash during the trial window) never advances the floor and
  falls through to rollback instead;
- an explicit DFU/recovery request bypassing all OTA work entirely (zero
  QSPI-init, watchdog-start, or force-recovery calls, and no command or
  state record ever read).

Build/run recipe (host-only, no ARM toolchain, no shared build paths):

```
make test-xiao-ota-boot-process
```

`-DXIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY`/`-include fake_trust_anchor.h`
substitute a fresh, non-committed, test-only Ed25519 keypair generated at
test start (`crypto_sign_keypair()`) for the compiled-in production trust
anchor, so the test can sign its own fixtures without touching production
key material. `tests/crc16.h`/`crc16_host.c` are a byte-identical,
host-buildable copy of the vendored SDK's trivial CRC-16/CCITT-FALSE
algorithm (the real `crc16.c` needs `sdk_common.h`, unavailable on host);
this is build-infrastructure only, not a reimplementation of OTA logic.

The real ARM cross-compile of the split files was re-verified with
`prepare_upstream.py --work-dir` (isolated, no shared paths): clean link,
FLASH 34512/38912 bytes, matching the size class of every prior build in
this document.

## Fixed: unchecked IO could confirm/erase/advance the floor on a failed flash op

Every callback in `xiao_ota_io_t` used to return `void`: `write_record()`,
`persist_state()`, `persist_floor()`, the backup/restore copy loops, and
the post-install verify/settings-write step all assumed every QSPI/internal
flash read, erase, and write always succeeded. A real transient NACK, a
worn/failing sector, or a hardware busy-wait that never clears had no way
to be reported -- the processor would happily read back garbage, hash
partially-written data, or mark a transaction CONFIRMED with a floor write
that never actually landed in flash.

Every callback in `include/xiao_ota_boot_io.h` now returns `bool`
(read/erase/write/settings-write/busy-wait), and `src/xiao_ota_boot_io.c`
checks every single call:

- `write_record()` now does body-write, readback-verify, marker-write,
  readback-verify -- returning `false` the instant any step disagrees with
  what was just written, before the marker (or the record as a whole) is
  ever trusted.
- `persist_state()`/`persist_floor()` are `bool`. The *first* `persist_state()`
  at fresh command-acceptance time (nothing destructive has happened yet)
  can safely just refuse and return on failure. Every later
  `persist_state()`/`persist_floor()` call -- once a transaction is already
  mutating protected state -- calls `io->force_recovery()` and returns
  instead: an unreported failure at that point must never be silently
  treated as success.
- `copy_internal_to_qspi()`/`copy_qspi_to_internal()` (backup and rollback
  restore) and `active_extent_from_settings()` (fresh bank-0 recheck) now
  check every read/erase/write in their chunk loops and abort on the first
  failure instead of copying past it.
- `src/xiao_ota_boot.c`'s `hw_*` register adapters are `bool` too, and
  `qspi_wait()`/`nvmc_wait_ready()` are now bounded
  (`XIAO_OTA_HW_BUSY_TIMEOUT_ITERATIONS` iterations) instead of spinning
  forever on a stuck busy bit -- a hung peripheral now surfaces as a
  reported failure, not an unrecoverable hang during an install. The thin
  SDK register semantics themselves are unchanged.

`tests/fake_io.c`/`fake_io.h` gained two new fault mechanisms alongside the
existing crash-injection: `fail` (the call returns `false` with no side
effect and no crash/reset -- a transient NACK the firmware must detect and
handle within the same boot) and `tear` (the call applies only the first
`tear_bytes` of the payload, then returns `false` -- a write interrupted
mid-program, distinct from `crash`/`fail`, which both leave zero bytes
landed). All three are address-range-gated (`addr_lo`/`addr_hi`), so a
fault can target one specific record's dedicated 4 KiB sector
(`xiao_ota_layout.h`: COMMAND/STATE/CONFIRM/FLOOR each own A/B sectors)
rather than only a global call-count.

## Fixed: trial confirmation could advance the floor without validating the candidate hash, and a rolled-back backup could be trusted unauthenticated

Two related gaps in the trial/confirmation/rollback path:

- Confirmation checked `freshHash == installedHash` but never
  `freshHash == candidateHash`/`installedHash == candidateHash`: those
  should always agree by construction, but nothing re-derived that
  agreement at confirmation time, and nothing stopped a durably-advanced
  floor from moving *backwards*, or from silently re-writing floor for a
  transaction it had already durably finished (non-idempotent re-entry
  after a cut between the floor write and the state write). Confirmation
  now requires `freshHash == installedHash == candidateHash` plus a
  bounded, non-zero fresh extent and a matching nonce/counter, refuses to
  move the floor backwards or overwrite a corrupt/unrecognised non-blank
  floor, and idempotently finishes CONFIRMED without rewriting floor when
  it already durably matches this same transaction.
- `ROLLBACK_COPYING` used to erase the live app region and start copying
  the QSPI backup back in *before* ever hashing/authenticating that
  backup. A backup that was itself corrupt (a prior interrupted backup,
  a worn sector) would erase the only remaining valid image before
  discovering the restore source was unusable. The backup is now hashed
  and authenticated *before* the first destructive erase (gated on
  `progress_bytes == 0`, so this only runs once per rollback, not once
  per chunk); read/hash failure or a mismatch now routes to bounded
  recovery instead of erasing anything.

`state.sequence` also used to be reset to `0` on every new transaction
(`memset(&state, 0, ...)` zeroed the whole struct). Since
`xiao_ota_newest_valid()` uses `sequence` as its A/B tie-break, this could
make a fresh transaction's very first record compare as "not newer" than
a stale leftover record still sitting in the other slot from a previous
transaction. `sequence` is now captured before the reset and restored
immediately after, so it keeps counting monotonically across transaction
boundaries the way `persist_state()`'s existing `+1` logic already
assumed.

`tests/test_boot_process.c` (the literal-execution harness above) grew
from 6 to 14 scenarios covering: floor/state cut with idempotent resume;
sequence preserved across two consecutive real transactions; backup
authenticated before the rollback erase (corrupt-backup case never
erases); pure I/O failure (no crash) refused cleanly; a torn state write
refused without a matching commit marker; a newer-than-current or
corrupt floor refused for a new transaction; floor non-regression against
a stale confirmation attempt; and CONFIRMED never reported without a
durable floor write. All 14 run against the real, unmodified
`xiao_ota_boot_process_io()` entry point via the fake IO vtable above --
no parallel test-only re-implementation of this logic.

Re-verified: `make test-xiao-ota-bootloader` (installer + tool tests,
`test_record`, `test_ed25519`, `test_descriptor_contract`, `test_boot_info`,
source-order checks, and all 14 boot-process scenarios) all green, and a
fresh isolated ARM cross-compile (`prepare_upstream.py --work-dir`, no
shared paths) links cleanly: FLASH 34832/38912 bytes (89%), RAM
25200/229376 bytes (11%), `xiao_ota_state_t` still exactly 152 bytes.

## Fixed: nonce comparison silently truncated to 32 bits

`transaction_nonce` is `uint64_t` everywhere it's stored (`xiao_ota_state_t`,
the command/confirmation wire structs) -- but
`xiao_ota_command_is_retry_of_failed_transaction()`'s nonce parameters were
declared `uint32_t`, silently truncating both `state.transaction_nonce` and
`intent.transaction_nonce` to their low 32 bits at the call in
`xiao_ota_boot.c`. Two genuinely different 64-bit nonces sharing the same
low 32 bits (differing only above bit 31) would compare equal, which could
incorrectly refuse a genuinely new signed command as a "retry" of a FAILED
transaction.

The fix widens both nonce parameters to `uint64_t` (the counter/hash
parameters were already correctly typed and are unchanged); the call site
in `xiao_ota_boot.c` needed no change, since it already passed the full
64-bit fields -- only the parameter type was narrowing them. Regression
tests in `tests/test_record.c` use nonces that share identical low-32 bits
and differ only in the high 32 bits, proving the same nonce is still
correctly treated as a retry and a high-bits-only-different nonce is
correctly treated as new, both directly and across the multi-boot
FAILED-retry sequence.

## Fixed: `install_uf2.py` only checked UF2 magic/numbering, not what a block was allowed to write

Before this fix, the host-side installer's `validate_uf2()` confirmed a
UF2 file's magic bytes and that its blocks formed a complete, non-duplicate
sequence -- but never checked a block's declared `payload_size` against the
512-byte block's real 476-byte data limit, never checked a block's UF2
`family_id`, and never checked a block's target flash address at all. A
malformed, mistargeted, or maliciously crafted UF2 with an oversized
payload or a write into the application image (`0x27000..0xED000`),
ExtraFS, or this project's own durable bootloader-settings page
(`0xFF000..0x100000`, the bank/CRC/size metadata and anti-rollback
floor/command records) would still pass `validate_uf2()` and reach the
volume copy.

The fix adds, still entirely before any volume copy: (1) a
`payload_size` bound of 1..476 per block; (2) a `family_id` check against
`0xD663823C`, the "self bootloader update" UF2 family this project's
Makefile actually packages with (not the generic NRF52840 application
family `0xADA52840`); (3) a target-address whitelist,
`PERMITTED_ADDRESS_RANGES`, built from a byte-exact read of a real
packaged no-SWD artifact plus this target's documented flash layout: the
MBR/vector-table page (`0x0..0x1000`), the 38KiB bootloader code region
plus the 2KiB bootloader-config slot (`0xF4000..0xFE000`, which includes
the boot-info marker at `0xFDC00`), and the two UICR words the bootloader
reads at boot (`[0x10001000, 0x10001100)`, half-open -- the last WRITTEN
byte is `0x100010FF`, not `0x100011FF`). The MBR Params Page and the
bootloader-settings page (`0xFE000..0x100000`) are deliberately *excluded*
from the whitelist even though they sit between two permitted ranges --
neither ever appears in a real packaged UF2, and an update artifact must
never be able to touch either. `install()` also now calls
`verify_boot_info_artifact.check_artifact()` against the artifact's
`--board`/`--role-id` (and OPTIONALLY `--key-header`, see "Independent
artifact-level marker verification" below -- there is no compiled/default
key here; omitting it simply skips that one cross-check) before the volume
copy, binding the install to the same independent marker/profile check the
Make package targets already run at build time.

`tests/test_install_uf2.py`'s fixture is now a genuinely-shaped
multi-block UF2 (MBR + bootloader-code + a real boot-info marker + UICR
blocks, all with the real family ID) instead of a single otherwise-empty
block, and adds behavioural refusals -- all asserted to happen before any
volume copy -- for a block targeting the application/ExtraFS region, a
block targeting the settings page, an oversized payload, a wrong
`family_id`, and (when `--key-header` is explicitly given) a boot-info
marker with the wrong board or the wrong reference signer key; a
companion test confirms omitting `--key-header` installs successfully even
against a marker whose reference key doesn't match any particular header,
since that field is never a runtime trust gate. The new
whitelist/family/payload/marker checks were also confirmed to pass
unmodified against a genuine main-built artifact
(`.tmp/xiao_nrf52840_ota_artifacts/custom-noswd/xiao_nrf52840_ota_noswd_update.uf2`,
read-only), so the hardening does not reject real packaged output.

## Added: `install_uf2.py --validate-only`

`install_uf2.py` now supports `--validate-only`, which runs only the
artifact checks above (UF2 structure/whitelist plus the boot-info
marker/board/key) and returns without resolving a serial, boot port, or
mounted device at all -- useful for CI or pre-flight checks before any
board is connected. `--serial`/`--boot-port` are no longer required by
`parse_args()` when `--validate-only` is given (they remain required
otherwise). `tests/test_install_uf2.py` proves this mode accepts a genuine
artifact with the serial/port/mountinfo fields pointed at paths that do
not exist, still refuses a bad artifact the same way the full path does,
and that `parse_args()` enforces the requirement correctly both ways.



```sh
make test-xiao-ota-bootloader
make package-xiao-ota-bootloader-noswd
```

`tests/test_descriptor_contract.c` and `tests/test_boot_info.c` are both
wired into `test-xiao-ota-bootloader` and run on every invocation.

This test now covers both command versions with real, independently
generated (`openssl pkeyutl -sign -rawin`) Ed25519 signatures: a genuine
59-byte big-endian wire descriptor accepted end-to-end through
`xiao_ota_command_v2_valid()`/`xiao_ota_install_command_from_v2()`/
`ed25519_verify()`/`xiao_ota_install_command_policy_valid()` (the exact call
chain `xiao_ota_boot.c` uses), a legacy 71-byte descriptor accepted the same
way, and proof that a signature made for one form is rejected against the
other even when every logical field value matches.

No-SWD artifacts are written to
`.tmp/xiao_nrf52840_ota_artifacts/custom-noswd/`:

- `xiao_nrf52840_ota_noswd.hex`
- `xiao_nrf52840_ota_noswd_update.uf2`

The no-SWD profile uses the public-domain TweetNaCl Ed25519 verifier. Its
detached-signature wrapper is host-tested against RFC 8032 test vector 1. The
BLE-enabled profile continues to use MeshCore's existing orlp-derived
verify-only sources, including their license and notice.

## Size and boot start

The optimized no-SWD image has a 38,900-byte FLASH load footprint in the
38,912-byte (38 KiB) region (`99.97%`, **12 bytes free**) at
`0xF4000..0xFD800`: 38,652 bytes of code/rodata plus 248 bytes of
initialized data. This grew substantially from earlier builds as the
floor/genesis/higher-survivor-repair, board-target-profile, and boot-info-
marker logic were added; `docs/lora_ota_nrf52840_qspi.md`'s size history
box covers the specific refactors that closed a real 452-byte overflow
back down to this margin (shared wire-descriptor-decode/hash/CRC helper
factoring, plus converting ghostfat.c's 384-byte `INFO_UF2TXT` buffer from
an initialized-data array to a zero-flash-cost BSS buffer filled at
`uf2_init()` time from a short `const` prefix literal). **This 12-byte
margin is razor-thin: any future change that adds even a few bytes of
code, rodata, or initialized data to this profile will need either a
further size reduction elsewhere first, or an explicit decision to grow
the slot (not undertaken here).** It uses `-Os`, LTO, function/data
sections, linker garbage collection, and removes BLE DFU sources and
code. UICR boot start and `BOOTLOADER_REGION_START` both remain
`0xF4000`, so the generated update UF2 is suitable for stock-address
bootloader update. The application remains compatible with S140: the
normal MBR initialization and SoftDevice-disable path before application
start is retained.

The prior BLE-enabled build remains intact:

```sh
make package-xiao-ota-bootloader
```

It has a 54,448-byte FLASH load footprint in the 66 KiB
`0xED000..0xFD800` region and requires SWD
for the first relocation because it changes UICR boot start and consumes the
former InternalFS range. Keep the matching pinned stock artifact:

```sh
make build-xiao-stock-bootloader
```

Without SWD the exact currently installed bootloader cannot be read back.
The target above instead saves the reproducible matching upstream stock HEX
and update UF2 under `.tmp/xiao_nrf52840_ota_artifacts/stock/`.

Initial commissioning of the BLE-enabled fallback with a Nordic-compatible
SWD probe is:

```sh
nrfjprog -f nrf52 --program \
  .tmp/xiao_nrf52840_ota_artifacts/custom/xiao_nrf52840_ota_nosd.hex \
  --sectoranduicrerase --verify --reset
```

To restore the matching pinned stock bootloader over SWD:

```sh
nrfjprog -f nrf52 --program \
  .tmp/xiao_nrf52840_ota_artifacts/stock/xiao_nrf52840_ble_stock_c67f0bcf0fa8e841426335b1bbde91cda6ca1f50_nosd.hex \
  --sectoranduicrerase --verify --reset
```

Both commands alter UICR and must be run only after preserving device data.
Build the preferred no-SWD package and matching pinned stock recovery artifact:

```sh
make package-xiao-ota-bootloader-noswd
make build-xiao-stock-bootloader
```

Then request bootloader mode for the authorized target. If software entry fails,
physically double-reset the XIAO and wait for its `XIAO-BOOT` volume:

```sh
make enter-xiao-nrf52-target-bootloader
# If that fails: physically double-reset, then continue.
make install-xiao-nrf52-target-ota-bootloader
```

The guarded installer resolves the `target` role through `lab/devices.ini`,
requires the stable `/dev/serial/by-id` `XIAO-BOOT` identity for that serial,
matches the mounted UF2 volume through its udev/sysfs USB serial ancestry,
requires `Board-ID: nRF52840-SeeedXiao-v1` in `INFO_UF2.TXT`, and refuses
missing, wrong, or ambiguous devices. It never selects a `ttyACM` number.
The stock recovery UF2 is
`.tmp/xiao_nrf52840_ota_artifacts/stock/xiao_nrf52840_ble_stock_c67f0bcf0fa8e841426335b1bbde91cda6ca1f50_update.uf2`.

## QSPI ownership and records

The P25Q16H pins were checked against the framework variant's physical mapping:
SCK P0.21, CS P0.25, IO0 P0.20, IO1 P0.24, IO2 P0.22, IO3 P0.23.

The geometry is fixed:

| Range | Owner |
|---|---|
| `0x000000..0x0C6000` | candidate |
| `0x0C6000..0x18C000` | byte-verified active-image backup |
| `0x18C000..0x194000` | OTA journal |
| `0x194000..0x200000` | application filesystem |

The journal's eight independently erasable sectors are:

| Sector | Contract |
|---|---|
| `0x18C000`, `0x18D000` | install command A/B |
| `0x18E000`, `0x18F000` | boot transaction state A/B |
| `0x190000`, `0x191000` | application confirmation A/B |
| `0x192000`, `0x193000` | confirmed anti-rollback floor A/B |

All records use alternating monotonically sequenced copies, CRC-32 over bytes
before `crc32`, and a final separately programmed `0x434F4D54` commit marker.
The application must coordinate exclusive QSPI access and must never mount,
erase, or allocate these sectors as filesystem space.

**Erased-vs-corrupt floor is fail-closed.** If neither floor A/B copy passes
structural validation, `xiao_ota_boot_process()` now checks whether *both*
raw slots are fully erased (`0xFF` throughout, via `xiao_ota_bytes_erased()`
in `include/xiao_ota_record.h`/`src/xiao_ota_record.c`, host-tested in
`tests/test_record.c`). Only that genuinely-blank case is treated as "no
confirmed install yet" (counter floor 0, safe for a first install). Any
other invalid floor content -- a torn write, bit rot, or leftover unrelated
data such as a stale hardware-diagnostic write from before OTA provisioning
-- is floor damage, not "no floor yet": the bootloader refuses to accept any
new install command and forces an in-flight transaction to roll back rather
than silently reopening the anti-rollback counter at 0. **A target board
whose floor-A sector still holds leftover raw diagnostic bytes from before
OTA commissioning will hit this fail-closed path and refuse new installs
until that sector is properly erased/commissioned** -- this is a
commissioning/lab-provisioning action for the operator, not something this
bootloader can safely infer or clear on its own.

`xiao_ota_command_t` (command v1) contains the exact 71-byte canonical
descriptor defined by `src/ota/trust/{TrustTypes,CanonicalDescriptor}.h`, its
64-byte Ed25519 signature, transaction nonce, current active-image extent and
SHA-256. `xiao_ota_command_v2_t` (command v2) instead carries the LoRa OTA
transport's own 59-byte big-endian canonical wire descriptor plus its
signature, unchanged (see next section). Both versions share one
structural/policy layout family: `record_version` at a fixed offset (4)
selects which command form and which signed message the bootloader
authenticates; there is no fallback between them. Both are checked for
format/key/algorithm, target, role, device/broadcast address, application
address, required boot capability, size, candidate SHA-256, signature, and a
strictly increasing durable counter, via one shared policy function
(`xiao_ota_install_command_policy_valid()`).

## Install command contract: v1 and v2

`sign_image.py --command-version {1,2}` produces one of two independently
authenticated, mutually exclusive signed install commands. This bootloader
dispatches strictly on the `record_version` field (offset 4 of the command
record) to exactly one of two verification paths -- never both, never a
fallback:

- **Command v1 (legacy, default)**: signs/verifies the 71-byte
  `xiao_ota_canonical_descriptor_t` (`include/xiao_ota_record.h`,
  byte-for-byte identical to `ota::trust::CanonicalDescriptor::serialize()` /
  `ImageDescriptor`): `image_hash_sha256[32]` first, then
  `target_id`/`role_id` as full u32s, `device_address` (u64),
  `allow_broadcast_address` (u8),
  `required_boot_capability_flags`/`monotonic_counter`/`image_size_bytes`/
  `app_address` (u32 each), `format_id`/`key_id`/`algorithm_id` (u16 each).
  Supports real per-device targeting via `device_address`.
- **Command v2 (current)**: signs/verifies the LoRa OTA transport's own
  59-byte big-endian canonical wire descriptor
  (`meshcore::ota::protocol::OtaDescriptor::encodeOtaDescriptorCanonical()`,
  `src/ota/protocol/OtaDescriptor.h`): `boardFamily` (u16), `boardVariant`
  (u16), `role` (u8), `appAddress` (u32), `exactSizeBytes` (u32),
  `sha256[32]`, `securityCounter` (u32), `minBootloaderCapabilities` (u32),
  `formatId/keyId/algorithmId` (u16 each) -- **the exact same 59 bytes and
  the exact same signature the transport already verifies**
  (`src/helpers/ota/OtaFirmwareBackend.h` / `DescriptorVerifier::verifyPolicy()`),
  authenticated directly (`ed25519_verify(sig, wire_descriptor, 59, pubkey)`
  in `command_policy_valid()`, `xiao_ota_boot.c`), never re-derived or
  re-signed into another form. This wire descriptor has no
  `device_address`/`allow_broadcast_address` field at all, so
  `xiao_ota_install_command_from_v2()` unconditionally normalizes a decoded
  v2 command to `device_address=0`/`allow_broadcast_address=1` (always
  broadcast-installable) -- safe because neither field is part of the
  signed bytes, so nothing attacker-controlled is trusted by this
  normalization; it is a documented, permanent limitation of the wire
  format, not a policy relaxation.

Because Ed25519 signs exact message bytes, a signature valid over one form
can never verify against the other, even when every logical field value is
identical -- proven with real signatures in `tests/test_descriptor_contract.c`
(a signature over the 59-byte wire form is rejected against the 71-byte form
and vice versa). Both forms share one policy-check function
(`xiao_ota_install_command_policy_valid()`) operating on a decoded,
version-neutral `xiao_ota_install_command_t`, so target/role/app-address/
format/capability/counter/extent/hash rules are defined exactly once and
apply identically regardless of which command version is presented.
State, transaction, confirmation, and durable-floor journal records are
unaffected by this and remain fixed at record version 1 (`XIAO_OTA_FORMAT_VERSION`);
only the two *command* record types are version-dispatched.

## Boot-info/capability marker

A small, fixed-address, fixed-layout record -- `xiao_ota_boot_info_t`
(`include/xiao_ota_boot_info.h`) -- is baked as a genuine compile-time `const`
object into every custom-bootloader build at `XIAO_OTA_BOOT_INFO_ADDRESS`
(`0xFDC00`), inside the existing 2 KiB `BOOTLOADER_CONFIG` flash region
(`0xFD800..0xFE000`), 1 KiB clear of the stock Adafruit `.bootloaderConfig`
CF2 config-key table and 1 KiB clear of the region end. It exists so the
*application* can, at any time, read this one well-known address and fail
closed if it is not talking to a qualified MeshCore custom bootloader: a
stock/unmodified Adafruit bootloader leaves this address erased (`0xFF`
throughout), which can never satisfy the marker's magic or CRC-32, so
detection needs no special-casing.

```c
typedef struct __attribute__((packed)) {
  uint32_t magic;             /* 0x584F4249 ("XOBI") */
  uint16_t format_version;    /* 1 */
  uint16_t struct_bytes;      /* sizeof(xiao_ota_boot_info_t) == 60 */
  uint32_t board_target_id;   /* this binary's XIAO_OTA_BOARD_TARGET */
  uint32_t role_id;           /* XIAO_OTA_ROLE_ANY */
  uint32_t capability_flags;  /* e.g. XIAO_OTA_CAP_QSPI_INSTALL */
  uint16_t key_id;
  uint16_t algorithm_id;      /* XIAO_OTA_ALGORITHM_ED25519 */
  uint8_t reference_signer_public_key_ed25519[32]; /* build-provenance record only --
    the static placeholder value include/xiao_ota_public_key.h held when THIS
    build/role was compiled (embedded by tools/prepare_upstream.py's CRC-patch
    step); NOT a trust anchor and unrelated to any private key or signing
    operation. Runtime install-command verification always reads the key from
    that command's own admitted_signer_public_key_ed25519 (xiao_ota_command_v2_t),
    never from this marker. */
  uint32_t crc32;             /* IEEE CRC-32 over every byte above */
} xiao_ota_boot_info_t;        /* 60 bytes, at 0xFDC00 */
```

`xiao_ota_boot_info_valid()` (`include/xiao_ota_record.h`,
`src/xiao_ota_boot_info.c`) validates magic/format/size/CRC; the application
**must** treat a `false` result -- including the fully-erased-stock-bootloader
case -- as "cannot confirm a qualified custom boot", and fail closed rather
than assume install capability. Confirming a qualified custom boot this way
is a build/board/role/capability provenance check -- it is **not** an
install-command trust decision, and `reference_signer_public_key_ed25519`
must never be used as one: each install command carries and is verified
against its own `admitted_signer_public_key_ed25519` (see "App-admitted
signer key" above), independent of whatever key this marker happens to
record.

There is no runtime write path to this object anywhere in this bootloader:
it is `const`, lives in true flash ROM, and a Cortex-M plain store to it
would fault rather than silently succeed even if something attempted it.
Every field except `crc32` is a compile-time literal; `crc32` cannot be
written as a hand-computed C constant without risking silent drift from the
real field values, so the committed source carries a deliberately-invalid
placeholder (`0xFFFFFFFF`, which can never be a real CRC-32 of the 56
preceding bytes) that `tools/prepare_upstream.py` replaces with the real
value -- computed in Python by independently replicating
`xiao_ota_crc32()`'s exact algorithm over the exact packed byte layout --
before the copied source is compiled. A build that skips
`prepare_upstream.py`'s patch step therefore fails `xiao_ota_boot_info_valid()`
immediately rather than shipping a plausible-looking but wrong marker. Both
real no-SWD builds performed while implementing this (default XIAO profile
and the SenseCAP Solar P1 profile below) were independently verified by
parsing the compiled `.hex` and recomputing the CRC-32 in Python: both match
byte-for-byte.

`xiao_ota_boot_info_build()`/`_valid()` are pure and host-tested in
`tests/test_boot_info.c` (see "Build" above for the run recipe): positive
round-trip, magic/format/size/field/key tamper rejection, an explicit
all-`0xFF` (simulated stock bootloader) rejection, an explicit all-zero
rejection, and cross-board-profile distinctness.

## Board profiles

The install-policy target check (`xiao_ota_install_command_policy_valid()`)
and the boot-info marker's `board_target_id` both now read from one macro,
`XIAO_OTA_BOARD_TARGET` (`include/xiao_ota_record.h`), which defaults to
`XIAO_OTA_TARGET_XIAO_NRF52840` (`0x584E3430`) and is overridable at compile
time. `tools/prepare_upstream.py --board {xiao_nrf52840,sensecap_solar_p1}`
selects it (default `xiao_nrf52840`, unchanged behaviour); `tools/sign_image.py
--board {xiao_nrf52840,sensecap_solar_p1}` signs a descriptor's
target/board-family/board-variant fields to match.

`sensecap_solar_p1` (`XIAO_OTA_TARGET_SENSECAP_SOLAR_P1`, `0x53435031`,
"SCP1") is a **real, distinct, non-wildcard** target id -- never a
`0xFFFFFFFF`-style value that matches anything -- documented as sharing the
same checked P25Q16H QSPI physical pin mapping as the XIAO profile (see
"QSPI ownership and records" above), for a SenseCAP Solar P1-class board.
**It has NOT been physically qualified on any real SenseCAP hardware.**
Selecting it only changes what this bootloader compiles/signs for; it makes
no claim that a SenseCAP Solar P1 board has been tested, flashed, or
verified to work. Treat any `sensecap_solar_p1` build strictly as
build-only/unqualified until real hardware confirms it.

Cross-board rejection was verified end-to-end (not just asserted): a
descriptor signed with `--board sensecap_solar_p1` is a fully valid,
correctly-signed v2 command, but a bootloader compiled with the default
`xiao_nrf52840` target rejects it at the policy stage (`target_id` mismatch),
and vice versa -- proving the two profiles are genuinely non-interchangeable,
not merely differently labelled.

If a dedicated `Makefile` package target is wanted for the SenseCAP profile
(e.g. `package-xiao-ota-bootloader-noswd-sensecap`), that is outside this
directory's edit scope; the invocation is otherwise identical to the
existing no-SWD target with `--board sensecap_solar_p1` added to the
`prepare_upstream.py` call.

`prepare_upstream.py --work-dir PATH` overrides the disposable build tree
it copies the pinned upstream into and compiles from (default:
`.tmp/xiao_nrf52840_ota_{noswd_,}upstream`, selected by `--no-ble`, same as
before). A build invoking more than one `--board` profile in the same
`Makefile` run **must** pass a distinct `--work-dir` per profile -- the
default path does not vary by `--board`, so two profiles sharing it would
clobber or relabel each other's build tree and artifacts (e.g.
`--work-dir .tmp/xiao_nrf52840_ota_noswd_upstream_sensecap_solar_p1` for a
SenseCAP no-SWD build run alongside a default-profile no-SWD build).

`PATH` is validated (`validate_work_dir()`) before any git/copy/delete
action: it must resolve (symlinks included) to a strict descendant of
`ROOT/.tmp`, and must not resolve to `.tmp` itself, the repo root, or the
pinned upstream clone -- because the script unconditionally
`shutil.rmtree()`s an existing `WORK` before copying into it, an
unvalidated caller-controlled path here would be a recursive-delete
vulnerability. Rejection happens first: no git, submodule, or filesystem
action runs beforehand.

### Independent artifact-level marker verification

`tools/verify_boot_info_artifact.py` is a standalone, read-only check that
never calls `xiao_ota_boot_info_build()`/`_valid()` (the C helpers this
bootloader itself uses) and never reuses `prepare_upstream.py`'s CRC-patch
logic. It parses the bytes at `0xFDC00` straight out of a real packaged
`.hex` or `.uf2` artifact, decodes them against its own independently
re-declared 60-byte little-endian layout and golden constants, and
separately recomputes and checks the CRC-32, magic, format/size, and every
profile field (`board_target_id`, `role_id`, `capability_flags`, `key_id`,
`algorithm_id`). It is meant to catch drift or a bad build even if the C
helpers and the patch step ever agreed on the same wrong value:

```sh
python3 bootloader/xiao_nrf52840_ota/tools/verify_boot_info_artifact.py \
  --board xiao_nrf52840 \
  .tmp/xiao_nrf52840_ota_artifacts/custom-noswd/xiao_nrf52840_ota_noswd.hex
```

`--key-header` is OPTIONAL and strictly an opt-in extra: when given, it
additionally cross-checks the marker's `reference_signer_public_key_ed25519`
build-provenance field (the static placeholder value
`include/xiao_ota_public_key.h` held when this build was compiled, embedded
by `tools/prepare_upstream.py`'s CRC-patch step) against a header file.
There is no compiled/default key substituted when it's omitted -- omission
simply skips that one check, it is never a failure, and a mismatch or
absence here says nothing about which key the bootloader will actually
accept on a real install command (that is always read per-command from
`admitted_signer_public_key_ed25519`, see "App-admitted signer key" above).

Run against a real `make package-xiao-ota-bootloader-noswd` output this
session: passes on both the `.hex` and `.uf2` artifacts for the default
`xiao_nrf52840` profile (with and without `--key-header`), and passes
against a real SenseCAP `--board sensecap_solar_p1 --work-dir ...` build's
own `.hex`. Confirmed to genuinely fail (not silently pass) on: a `--board`
argument that does not match the artifact's real compiled target, and a
hand-corrupted marker byte (both an explicitly-requested
`--key-header` mismatch and the recomputed-CRC mismatch are reported).
For a SenseCAP artifact, if cross-checking the key, point `--key-header` at
the copied `src/xiao_ota/xiao_ota_public_key.h` inside that build's own
`--work-dir` tree (the same key file that build actually compiled from),
not the top-level `include/` copy, in case they ever diverge.

The reference-signer value this script (and the marker itself) checks
against, when `--key-header` is given, is a **fixed, non-secret placeholder
committed directly in `include/xiao_ota_public_key.h`** -- not generated,
provisioned, or rotated by any tool, and with no corresponding private key
retained anywhere in this repo. `tools/provision_lab_key.py` is an
unrelated, purely offline test-fixture generator (a throwaway private key
under `.tmp`, for passing to `sign_image.py --private-key` in manual/lab
signing); it does not read or write this header.

The reader is strict on purpose: it validates every Intel HEX record's
declared byte count and checksum, rejects unsupported (data-address-
affecting) HEX record types instead of silently skipping them, rejects a
UF2 block whose declared payload exceeds 476 bytes or whose trailing magic
is wrong, and rejects two UF2 blocks that write conflicting bytes to the
same address -- rather than letting the last one silently win. The public
key is parsed from the actual `#define ... \` macro block (line-continued,
terminated by the first non-backslash-continued line), not a fixed
character window that could pick up bytes from an unrelated neighbouring
macro. `tests/test_tools.py` proves all of this behaviourally (synthetic
HEX/UF2 fixtures, no real build required): valid extraction, bad checksum,
truncated record length, an unsupported address record type, oversized
UF2 payload, conflicting overlapping UF2 blocks, bad trailing magic, wrong
`--board`, wrong key, and a bad CRC. The same file also proves
`prepare_upstream.py --work-dir`'s path-traversal guard (below) rejects an
unsafe path before any subprocess or delete call -- 22 cases total, all
passing, plus a real end-to-end run of the validator against genuine build
output.

Main has wired a `verify-xiao-ota-boot-info-artifacts` `Makefile` target
that runs this validator against both profiles' real packaged `.hex`/`.uf2`
output. `tests/test_tools.py` is picked up by
`python3 -m unittest discover -s bootloader/xiao_nrf52840_ota/tests -p
test_tools.py`, wired into `test-xiao-ota-bootloader` alongside the
existing `test_source.py`/`test_install_uf2.py` invocations.


## LoRa OTA transport bridge: what still needs to be built (read-only findings)

Read-only inspection of `src/helpers/ota/OtaFirmwareBackend.h`,
`src/ota/trust/{TrustTypes,DescriptorVerifier}.h`, and
`variants/xiao_nrf52/OtaLabBackend.cpp` (all outside this directory's edit
scope) found the following absences. These are reported, not fixed here;
command v2 above removes the *signature-format* incompatibility, but a
durable, working application-side install bridge is still absent:

1. `OtaFirmwareStorageSink::commit()` (`OtaFirmwareBackend.h`) only sets
   `active_ = false`; it never builds or durably journals a command v2
   record into `XIAO_OTA_COMMAND_A`/`_B`, so this bootloader never sees a
   pending install after a LoRa transfer completes.
2. `OtaFirmwareTrustProvider::commitSecurityCounter()` always `return false`
   (stubbed); there is no durable application-side counter store wired to
   `LabMonotonicCounter`'s in-RAM `value_`, which resets to 0 on every boot.
3. `variants/xiao_nrf52/OtaLabBackend.cpp` stages into
   `SenseCapQspiLayout::candidateTestRegion(flash)`, a 16 KiB destructive-test
   subregion, not the production `0x000000..0x0C6000` candidate partition
   this bootloader reads from (`XIAO_OTA_CANDIDATE_BASE`/`_SIZE`).
4. Nothing computes the current internal active-image extent/SHA-256 the
   command record's `active_image_extent`/`active_image_hash_sha256` fields
   require, and nothing tracks/increments a durable transaction nonce.
5. Nothing on the application side reads or checks the new
   `xiao_ota_boot_info_t` marker at `0xFDC00` (see "Boot-info/capability
   marker" above). Before trusting install capability or a public key, the
   bridge should read this address, call `xiao_ota_boot_info_valid()` (or
   equivalent app-side logic against the same layout), and fail closed
   (report "not a qualified custom bootloader" / decline to attempt
   install) on any invalid result, including full erasure (stock
   bootloader) -- this is how the application is meant to distinguish a
   qualified custom boot from stock without any separate out-of-band
   signal.

**The coherent bridge shape** (for the owning agent to implement in
`src/helpers/ota/` and `variants/xiao_nrf52/`, outside this scope): after the
transport verifies the 59-byte canonical descriptor's signature and the
staged-image-hash check passes (`verifyStagedImageHash()`), the bridge must:
(a) read the true current internal active-image extent and SHA-256 rather
than assume any value; (b) build a `xiao_ota_command_v2_t` around the
already-verified 59-byte descriptor bytes and its signature -- **verbatim,
byte-for-byte, from the transport's own verified message and signature, never
re-signed** -- and durably write it as an alternating A/B copy (CRC-32 over
all preceding bytes, then a separately programmed `0x434F4D54` commit
marker, per the record contract above) into `XIAO_OTA_COMMAND_A`/`_B`; (c)
stage the image into the real `0x000000..0x0C6000` candidate partition, not
a test subregion; (d) persist `commitSecurityCounter()` to non-volatile
storage so the anti-rollback floor survives reset; and (e) after reboot,
follow the trial-boot confirmation contract above (write
`xiao_ota_confirmation_t` only once storage, radio, and the main loop are
healthy, and do so before the bootloader's 60-second trial watchdog
expires). `xiao_ota_command_v2_t`, `xiao_ota_wire_descriptor_t`, and the
codec/validation functions in `include/xiao_ota_record.h` are the shared,
host-testable module this bridge should build against; they have no
hardware dependency and are exercised in `tests/test_record.c` and
`tests/test_descriptor_contract.c`.

Separately, `variants/xiao_nrf52/OtaLabBackend.cpp`'s
`DeviceTrustAnchor::expected_target_id = 0x52840001` was an arbitrary
numeric scheme used only for wire-transport policy checks, reported by
another reviewing agent as mismatched against
`XIAO_OTA_TARGET_XIAO_NRF52840 == 0x584E3430` ('XN40') used in
`command_policy_valid()`; that value is owned by `src/` and out of this
directory's edit scope to change.

## Install and confirmation contract

The application stages `candidate.bin`, writes a committed command copy, and
resets. `make sign-xiao-ota-image` creates both using OpenSSL:

```sh
make sign-xiao-ota-image \
  XIAO_OTA_IMAGE=.pio/build/ENV/firmware.bin \
  XIAO_OTA_ACTIVE_IMAGE=installed-firmware.bin \
  XIAO_OTA_COUNTER=2
```

This produces a single-schema `install-command.bin` (220 bytes,
`record_version` 3 -- see "App-admitted signer key" above for the exact
layout) plus `candidate.bin`/`descriptor.bin`/`descriptor.sig`, where
`descriptor.bin` is the real 59-byte big-endian wire form. There is no
`--command-version` flag or legacy format to select: the prior 71-byte
(v1) and 188-byte (v2, no admitted-key field) shapes have both been
removed.

The active image file must be the exact installed binary extent beginning at
`0x27000`; the maximum end is `0xED000`. The bootloader authenticates the
complete candidate and hashes the current internal extent before copying it.
The extent must match the upstream bootloader's word-rounded bank-0 size for
the first install and the last confirmed durable extent thereafter. The first
install trusts the upstream size only when bank 0 is valid and its nonzero
CRC-16 matches internal flash. If validity, size, or CRC is absent, stale, or
outside `0x27000..0xED000`, the complete 792 KiB application region must be
supplied as the active image so rollback cannot be shortened by stale metadata.
It does not erase an internal application page until the complete backup is
durable and its full SHA-256 matches.

Before destructive installation, the transaction state journals the prior
upstream bank-0 validity, size, and CRC. A verified candidate's size and CRC-16
are written to the upstream settings page before trial boot; rollback restores
the journaled metadata before the old application is allowed to boot.

Explicit UF2, CDC serial, and legacy DFU GPREGRET requests bypass OTA processing
and are consumed by upstream `check_dfu_mode()`, including during a persistent
install or rollback transaction.

On trial boot the application writes `xiao_ota_confirmation_t` to the older
confirmation sector, programs the commit marker last, then resets. The token
must repeat the transaction nonce, candidate counter, and candidate hash.
Confirmation should happen only after storage mount, radio initialization,
and the normal loop are healthy.

The bootloader starts a 60-second watchdog for a trial. Trial firmware must not
feed or reconfigure that watchdog until it has committed confirmation. At most
three unconfirmed boots are allowed; then the byte-verified backup is restored.
Power loss in backup/install/rollback resumes from the last committed 4 KiB
boundary. Candidate and backup are not erased by the bootloader.

## Reference-signer placeholder and offline key fixtures

`include/xiao_ota_public_key.h`'s `xiao_ota_lab_public_key_ed25519` is a
**fixed, non-secret placeholder value committed directly in source
control** -- it is not generated, provisioned, or rotated by any tool, and
no corresponding private key is retained anywhere in this repo. It exists
only to give two build-time-only consumers a stable 32-byte value: the
boot-info marker's build-provenance field
(`reference_signer_public_key_ed25519`, see "Boot-info/capability marker"
above) and `tools/prepare_upstream.py`'s CRC-patch input. It is never a
runtime install-command trust anchor -- that is always read per-command
from a command's own `admitted_signer_public_key_ed25519` (see "App-admitted
signer key" above), snapshotted by the already-trusted running app at
COMMIT time.

`tools/provision_lab_key.py` is unrelated to this header: it is a purely
offline/local test-fixture generator that creates (or reuses) a throwaway
Ed25519 private key under `.tmp/xiao-ota-keys/lab-ed25519-private.pem`
(never committed), for passing to `sign_image.py --private-key` in
manual/lab signing workflows only:

```sh
python3 bootloader/xiao_nrf52840_ota/tools/provision_lab_key.py
```

It does not read or write `include/xiao_ota_public_key.h` or any other
compiled header, and establishes no "default trust" key. Production
signing never exports a private key to a tool like this at all: it happens
entirely through the existing host companion protocol (CMD33 start / CMD34
raw message bytes / CMD35 finish, returning only the signature), with the
already-trusted running app snapshotting the resulting admitted public key
directly into the install command at COMMIT time.

## Host-side bare manifest builder: `build_manifest.py`

`tools/sign_image.py` bundles three distinct concerns together: building
the canonical59 wire descriptor, invoking a local OpenSSL private key to
sign it, and assembling a full durable 220-byte install command. A
production host instead signs through the existing companion protocol
(CMD33 start / CMD34 raw message bytes / CMD35 finish) and has no local
private key to hand `sign_image.py` at all -- it only needs the bare,
unsigned descriptor bytes to hand to that protocol.

`tools/build_manifest.py` provides exactly that and nothing else: it never
touches a private key, an `--active-image` reference, a signature, or a
durable install command.

```sh
python3 bootloader/xiao_nrf52840_ota/tools/build_manifest.py \
  --image .pio/build/ENV/firmware.bin \
  --board xiao_nrf52840 \
  --role-id 0 \
  --counter 2 \
  --output manifest.bin
```

| Flag | Required | Meaning |
| --- | --- | --- |
| `--image` | yes | candidate application image to describe (read-only; never modified or signed by this tool) |
| `--board` | no (default `xiao_nrf52840`) | `xiao_nrf52840` or `sensecap_solar_p1`; selects the descriptor's `boardFamily`/`boardVariant` bytes |
| `--role-id` | no (default `0`) | `0` (companion) or `1` (repeater); any other value is rejected before `--output` is written |
| `--counter` | yes | anti-rollback security counter; must be `0 < counter <= 0xFFFFFFFF` -- a device's floor starts at `0` and the bootloader rejects `monotonic_counter <= counter_floor`, so `0` itself can never install on any real device and is rejected up front |
| `--output` | yes | path to write the bare 59-byte unsigned descriptor to |

`--image` is validated against the exact same geometry/alignment policy as
`sign_image.py`'s candidate image (word-aligned, `1..0xAD000` bytes,
cross-checked at runtime against
`src/ota/platform/Nrf52FlashLayoutContract.h`), and `--board`/`--role-id`/
`--counter` are all validated before anything is written to `--output` --
an invalid input never produces a partial/truncated output file.

Both `sign_image.py` and `build_manifest.py` build the 59-byte canonical
descriptor through the single shared codec in `tools/xiao_ota_descriptor.py`
(`build_descriptor()`); there is exactly one place in this tree that
encodes a canonical59 descriptor, so their outputs for matching inputs are
always byte-for-byte identical. Sign the resulting file's bytes EXACTLY as
emitted -- no domain prefix, no NUL terminator, no extra hashing/wrapping
-- via the host companion protocol, then supply the resulting 64-byte
signature plus the app-admitted public key to the install command (see
"App-admitted signer key" above).

## Fixed: five review regressions in metadata I/O, confirmation, slot tracking, backup, and QSPI init

A follow-up review found five further gaps in `xiao_ota_boot_io.c`/
`xiao_ota_boot.c`, all corrected in this pass without changing the
152-byte `xiao_ota_state_t`/188-byte command-v2 wire ABI, board profiles,
or pin contract:

1. **Missing metadata was not distinguished from a hardware read failure.**
   `read_pair()` returned a plain `bool`; a failed STATE read was `memset`
   to an empty record and a failed FLOOR read fed uninitialized `floor_a`/
   `floor_b` buffers straight into the "is this slot erased" check, so an
   unreadable *existing* transaction could be silently treated as absence/
   first-boot. `read_pair()` now returns a typed
   `xiao_ota_pair_status_t` (`FOUND`/`MISSING`/`DAMAGED`/`IO_ERROR`) per
   slot pair, and every call site fails closed (`force_recovery()`) on
   `IO_ERROR` before touching any buffer, distinguishing it from a
   genuinely blank/never-written pair. "Blank" for a slot is now decided
   by `slot_safe_to_overwrite()`: the record's own `commit_marker` must
   read erased **and** the remainder of that 4 KiB sector beyond the
   record struct (`sector_tail_erased()`) must be genuinely blank -- not
   just the first ~60 bytes -- so leftover debris later in the sector is
   still caught as `DAMAGED` rather than silently overwritten. `qspi_init`
   is now checked too (point 5 below); an unreadable init state forces
   recovery before any read is attempted at all. New tests inject I/O
   errors on STATE-A/B and FLOOR-A/B with an *existing* in-flight
   transaction or confirmed floor present (not just on a first, empty
   boot), and confirm `force_recovery()` fires with zero mutation.

2. **The confirmation shortcut skipped fresh re-verification.** A boot
   whose command already matched a durably-advanced floor
   (`have_floor && counter == floor.counter && hash == floor.hash`) went
   straight to `CONFIRMED` without re-checking that the image *actually
   running right now* still matches -- reopening the exact stale-
   confirmation class of bug this file was already fixed for once, but
   only for the fresh-boot path, not the idempotent-floor-already-set
   resume path. Every route that can reach `CONFIRMED` -- including this
   idempotent-resume case -- now re-derives `freshHash` from the live
   bank-0-bounded image and requires `freshHash == installedHash ==
   candidateHash` plus a bounds-checked fresh extent before confirming;
   a matching floor is never rewritten (idempotent), but the live bytes
   are always re-checked. An equal counter with a *different* floor hash
   now explicitly force-recovers instead of falling through and
   overwriting the floor, and a floor counter *higher* than the current
   command's is treated as `FAILED` with no live-flash mutation, so a
   stale/superseded transaction can never roll a newer, unrelated,
   already-confirmed image backward. New tests cover a floor/state cut
   followed by a USB reflash, invalid settings, a mismatched installed
   hash, an equal-counter/different-hash floor, and a newer valid floor
   with the live image left untouched.

3. **Slot selection used sequence parity instead of the actual physical
   slot, and had no wrap guard.** `persist_state()`/`persist_floor()`
   picked "the other" A/B slot by checking whether the *next* sequence
   number was even or odd, not by tracking which physical slot the
   newest valid record actually lives in -- so a record with an odd
   sequence sitting in slot A (a legitimate outcome, since slots are not
   pinned to parity) could be misidentified and incorrectly erased by a
   writer assuming "odd belongs in B." `write_record()`/`persist_state()`/
   `persist_floor()` now track and always target the actual opposite
   physical slot address of the newest validated record, never infer it
   from parity, refuse to advance past `UINT32_MAX` sequence (failing
   closed rather than wrapping), and validate a full post-marker record
   readback -- not just the marker -- before treating a write as durably
   successful. A new test fabricates an odd-sequence record directly in
   slot A and confirms the next persist correctly targets slot B.

4. **Persisted phase/progress/extent were trusted before use as an
   erase/copy address, and backup was authenticated only once.** A
   corrupted or out-of-bounds `progress`/`active_image_extent` read back
   from a resumed transaction was used directly to compute rollback/copy
   addresses without being bounds-checked first, and the backup image
   was only hashed-and-verified the first time rollback began, not again
   on every subsequent resumed boot. `active_image_extent_bounded()`/
   `progress_bytes_consistent()` now validate extent (`<=
   XIAO_OTA_INSTALL_MAX_SIZE`, the same 708,608-byte ExtraFS ceiling used
   everywhere else -- distinct from the larger 811,008-byte QSPI backup
   bank capacity) and sector-aligned, bounded progress before any erase
   or copy address is derived from them, forcing recovery on a
   validation failure instead of acting on unchecked persisted state.
   Backup is now re-authenticated (hashed and checked against the
   durable backup hash) on **every** boot that resumes
   `ROLLBACK_COPYING`, not only on first entry, so a backup silently
   damaged between reboots is caught before any further live erase.
   `state.sequence` continues monotonically across new transactions
   (never reset to 0), preserved from an earlier fix.

5. **`qspi_init` was `void` and busy-waits used one coarse timeout.**
   Both are addressed together with the earlier IO-checking work: `bool
   qspi_init(void *ctx)` now returns a real result -- a failure force-
   recovers before any read is attempted, exercised by a new fault-
   injection test -- and `src/xiao_ota_boot.c`'s single
   `XIAO_OTA_HW_BUSY_TIMEOUT_ITERATIONS` constant is replaced with
   separate, per-operation-class calibrated bounds (QSPI activate/custom-
   instruction/page-program/sector-erase, NVMC erase/write), each sized
   to the P25Q16H's/nRF52840's documented worst-case timings with margin.
   `hw_qspi_init()` also now performs a genuine Quad-Enable check/set
   sequence against the P25Q16H's status register 2 (`RDSR2`=0x35 read,
   `WREN`=0x06, `WRSR2`=0x31 write, bit 1) instead of assuming QE
   survives a power cycle, and fails closed if the bit cannot be
   confirmed set afterward.

   **Grounded against real in-repo hardware sources (read-only, no
   device access).** Two independent real sources in this repository
   corroborate this design without any physical verification:
   - `.pio/libdeps/Xiao_nrf52_companion_radio_usb/CustomLFS/src/CustomLFS_QSPIFlash.cpp`
     (the framework's own QSPI flash driver, built for this exact board
     class) carries a flash-chip table with an exact P25Q16H entry --
     JEDEC `{0x85, 0x60, 0x15}`, `quad_enable_register = 2`,
     `quad_enable_bit = 1`, non-volatile -- and its `readStatus()`/
     `writeStatus()` helpers use the identical opcodes this bootloader
     uses (`0x35` Read Status Register 2, `0x06` Write Enable, `0x31`
     Write Status Register 2), confirming the opcode/bit assignment
     independently of the flash datasheet. Notably, that same real
     firmware never actually calls its own `writeStatus()`/`readStatus()`
     pair anywhere (`_quad_mode_enabled` stays `false` and is never set
     true) -- production firmware for this hardware class currently just
     assumes QE is already set rather than defensively verifying it. This
     bootloader's active verify-and-set-if-needed behaviour is therefore
     a deliberate safety margin beyond what the current companion
     firmware does, not a copy of an already-exercised pattern.
   - `.tmp/Adafruit_nRF52_Bootloader/lib/nrfx/drivers/src/nrfx_qspi.c`
     (the vendored Nordic QSPI driver this bootloader links against)
     confirms the completion signal this file polls is correct:
     `nrfx_qspi_write()`/`nrfx_qspi_erase()`/`nrfx_qspi_cinstr_xfer()`
     all resolve through `qspi_task_perform()`/`qspi_ready_wait()`, which
     wait on `NRF_QSPI_EVENT_READY` (`EVENTS_READY`) -- exactly what
     `qspi_wait_for()` here polls -- not the separate flash-internal WIP
     bit (`nrfx_qspi_mem_busy_check()`'s `0x05` status read is a distinct,
     optional helper for polling WIP directly; it is not what ties
     ERASESTART/WRITESTART completion to readiness). Two details worth
     noting precisely: the driver's own default CINSTR timeout
     (`qspi_ready_wait()`) is 100 attempts x 10 us (about 1 ms) -- this
     bootloader's 10 ms CINSTR bound is a deliberately generous multiple
     of that real, in-repo, documented value, not an arbitrary constant.
     For blocking-mode `nrfx_qspi_write()`/`nrfx_qspi_erase()`, the
     upstream driver's own `qspi_task_perform()` spins on `EVENTS_READY`
     with **no timeout at all** (`while (!nrf_qspi_event_check(...)) {}`).
     This bootloader's calibrated per-operation-class program/erase
     bounds are therefore strictly *more* defensive than the vendored
     driver it sits on top of, not merely an invented number -- but they
     remain datasheet-worst-case estimates for the actual physical
     program/erase durations themselves, since upstream provides no
     bound to cross-check that duration against.

   **What remains genuinely unverified:** this segment performed no
   device/serial/USB access of any kind. The P25Q16H's real physical
   program/erase timing and the QE bit's actual post-power-cycle state on
   the two authorized lab boards have not been measured -- only
   cross-checked against real driver/firmware source already present in
   this repository. Treat this as "implemented and grounded in real,
   in-repo reference code" rather than "hardware-confirmed" until
   validated once against the physical QSPI part.

**Settings-page torn-write coverage (superseded by the shared settings
codec below).** A test injecting a torn Nordic bootloader-settings-page
commit during candidate finalize,
`test_torn_settings_commit_during_finalize_forces_rollback`, confirms
`finalize_install_and_verify()`'s existing settings-failure handling
correctly routes to rollback rather than reporting a false install, that
a sentinel region beyond `XIAO_OTA_INSTALL_MAX_SIZE` (standing in for
ExtraFS) is provably untouched through both the failed finalize and the
subsequent completed rollback, and that the old image's hash/extent are
correctly restored. This test now injects the tear through the SAME
real internal-flash erase/program fault-injection primitives every other
durability test in this file uses (see "Shared bank-0 settings codec"
below), not a separate hand-modelled settings mirror.

**Tests.** `tests/test_boot_process.c` gained seven new native scenarios
covering all of the above (six for points 1-5 plus the settings-tear
case); the full real transaction processor now has 21 passing scenarios
(20 boot-process cases plus the pre-existing shared-processor coverage),
alongside the unchanged installer/tools/record/Ed25519/descriptor/boot-
info/source-order suites. `TMPDIR=.tmp make test-xiao-ota-bootloader`
passes completely.

An isolated ARM cross-compile re-verification
(`XIAO_OTA_NOSWD_WORK=.tmp/<isolated-name> make build-xiao-ota-bootloader-noswd`,
a fresh work directory distinct from any shared package path, removed
afterward) links cleanly: FLASH 35,388/38,912 bytes used (91%, code +
rodata; 632 bytes initialized data on top), matching the same size class
as every prior build in this document; `xiao_ota_state_t` is unchanged at
152 bytes.

## Fixed: QSPI WP#/HOLD# assertion on custom instructions, torn timeout calibration, and a floor-extent identity gap

A further review, grounded against real in-repo hardware sources (see
below; still no device/serial/USB access of any kind), found four more
issues in `xiao_ota_boot.c`/`xiao_ota_boot_io.c`, all corrected without
changing the 152-byte `xiao_ota_state_t`/188-byte command-v2 wire ABI:

1. **Custom QSPI instructions left IO2/IO3 at their register-reset LOW
   level, asserting the flash's WP#/HOLD# pins during exactly the
   commands meant to reach it.** `qspi_cinstr_read_byte()`,
   `qspi_cinstr_write_enable()`, and `qspi_cinstr_write_sr2()` now OR in
   `QSPI_CINSTRCONF_LIO2_Msk | QSPI_CINSTRCONF_LIO3_Msk`
   (`XIAO_OTA_HW_QSPI_CINSTR_LEVELS`) on every custom-instruction
   transfer, matching what both real in-repo sources always do:
   `.pio/libdeps/Xiao_nrf52_companion_radio_usb/CustomLFS/src/CustomLFS_QSPIFlash.cpp`'s
   `readStatus()`/`writeStatus()` (`io2_level=true, io3_level=true`) and
   `.tmp/Adafruit_nRF52_Bootloader/lib/nrfx/hal/nrf_qspi.h`'s
   `nrf_qspi_cinstr_transfer_start()`. A status-register write (WRSR2,
   the Quad-Enable set) is also now followed by an explicit poll of the
   flash's *own* Read-Status-Register-1 WIP bit
   (`qspi_wait_flash_write_complete()`, opcode `0x05`, bit 0) after the
   peripheral's own `EVENTS_READY`/WIPWAIT-based wait -- because
   `.tmp/Adafruit_nRF52_Bootloader/lib/nrfx/drivers/src/nrfx_qspi.c`
   (line ~189) documents that `WIPWAIT` only waits for a *previous*
   flash operation to finish before issuing a new instruction; it does
   not prove the instruction just issued has itself finished committing
   inside the flash. `nrfx_qspi_mem_busy_check()` exists in that same
   vendored driver as a distinct API for exactly this purpose but isn't
   called by anything there -- this bootloader now does the equivalent
   check itself after its one mutating custom instruction.
2. **Timeout calibration used an overestimated cycles-per-iteration
   guess, which produces a SHORTER real bound, not a conservative one.**
   The prior `XIAO_OTA_HW_SPIN_CYCLES_PER_ITERATION`/
   `XIAO_OTA_HW_ITERATIONS_FOR_MS` scheme (decrementing a loop counter
   estimated from an assumed CPU/cycles-per-iteration figure) is
   replaced with a genuine hardware monotonic clock: the Cortex-M4 DWT
   cycle counter (`DWT->CYCCNT`), enabled once
   (`hw_ensure_cycle_counter_enabled()`: `CoreDebug->DEMCR |=
   CoreDebug_DEMCR_TRCENA_Msk; DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;`, no
   interrupts, no periodic servicing needed) and compared with wrap-safe
   unsigned subtraction (`hw_deadline_cycles()`,
   `(uint32_t)(DWT->CYCCNT - start) >= deadline_cycles`), valid for any
   elapsed time under the full 32-bit cycle range (about 67 seconds at
   64 MHz -- every timeout used here is at most 3 seconds).
   `qspi_wait_for()`/`nvmc_wait_for()` both now measure real elapsed
   time instead of counting loop iterations.
3. **The idempotent-resume `CONFIRMED` path checked the floor's counter
   and hash against the current transaction but never its
   `active_image_extent`.** SHA-256 cryptographically binds an exact
   byte length, so a hash match at a given fresh extent implies the
   corresponding size by construction -- but the durable
   `floor.active_image_extent` field is a *separately stored* value that
   could, in principle, be corrupted or inconsistent independently of
   the hash (for example, a torn floor write that lands a valid
   hash/counter but a stale or garbage extent field), and the prior code
   silently let `CONFIRMED` finish over that inconsistency. The
   idempotent-resume branch now also requires
   `floor.active_image_extent == fresh_extent` (the same freshly
   re-verified live extent every other `CONFIRMED` route already
   checks); on a mismatch it force-recovers instead of finishing
   `CONFIRMED` or rewriting the floor -- treated identically to the
   pre-existing hash-conflict case. A new test fabricates a floor whose
   counter and hash already match the current transaction but whose
   extent does not, and confirms `force_recovery()` fires with zero
   floor/state/flash mutation.
4. **Shared bank-0 settings codec, replacing a hand-modelled fault
   mirror.** The bank-0 settings read/write path (bank_0/bank_0_crc/
   bank_0_size, plus the several other fields in Nordic SDK11's real
   `bootloader_settings_t` this project never inspects but must
   preserve byte-for-byte) is now a single hardware-independent function
   pair, `xiao_ota_settings_get()`/`xiao_ota_settings_set()`
   (`xiao_ota_boot_io.c`), expressed purely in terms of the existing
   `internal_read`/`internal_write`/`internal_erase_page` callbacks --
   the SAME callbacks every other internal-flash write in this file
   already uses, at the real settings-page address
   (`XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS = 0x000FF000`, matching
   `dfu_types.h`'s `BOOTLOADER_SETTINGS_ADDRESS` for `NRF52840_XXAA`).
   `xiao_ota_settings_set()` reads the current full 28-byte raw page
   first (preserving `bank_1`/`sd_image_size`/`bl_image_size`/
   `app_image_size`/`sd_image_start` byte-for-byte, exactly like the
   read-modify-write contract the SDK's own settings API already
   implies), overlays only the three fields this project ever changes,
   then erases, programs, and reads back the whole page for verification
   -- the identical erase/program/verify boundary the rest of this
   file's durability logic uses elsewhere. `xiao_ota_boot.c`'s real
   hardware adapter no longer needs its own `hw_settings_get()`/
   `hw_settings_set()` (and no longer depends on
   `bootloader_settings.h`/`dfu_types.h`); the `io_t` vtable's
   `settings_get`/`settings_set` callback members are removed entirely,
   since both the real and fake adapters now go through the shared
   codec. The native `fake_io.c` model no longer keeps a separate scalar
   bank-0 struct or a bespoke `settings_tear` enum: settings live at
   their real address inside the same `internal_flash` byte array used
   for everything else, so an address-range-gated fault on
   `internal_write`/`internal_erase_page` (the same fault-injection
   primitives every other test already uses) now exercises a genuine
   torn/interrupted settings-page write, including which of the
   project-tracked fields land before the tear point and which stay at
   their just-erased `0xFF` value -- not a hand-maintained parallel
   model of that page.

   A separate, previously-flagged documentation defect is also corrected
   here: an internal comment describing `write_record()`'s failure
   return incorrectly implied that any failure proves the target slot's
   write never durably landed. That is not necessarily true: the
   commit-marker write can succeed before a *later* step (the final
   whole-record readback/`valid()` check) fails on, for example, a
   transient read glitch -- in which case a genuinely new, valid record
   may already exist at that address. The comment now states plainly
   that `read_pair()` on the next boot always independently re-reads and
   re-validates both physical slots from flash regardless of what
   happened in a prior `write_record()` call, so a `false` return means
   only "this call cannot vouch the write is durably confirmed," not
   "the write did not happen."

**Grounded against real in-repo hardware sources (read-only, no device
access), same two files as the prior QSPI-timing section above:**
`.pio/libdeps/Xiao_nrf52_companion_radio_usb/CustomLFS/src/CustomLFS_QSPIFlash.cpp`
and `.tmp/Adafruit_nRF52_Bootloader/lib/nrfx/{drivers/src/nrfx_qspi.c,
include/nrfx_qspi.h, hal/nrf_qspi.h}`. **What remains genuinely
unverified:** the actual physical effect of asserting/de-asserting
WP#/HOLD# on the two authorized lab boards' P25Q16H parts, and the true
flash-internal WRSR2 commit duration, have not been measured on
hardware -- only cross-checked against real driver/firmware source
already present in this repository, and against the DWT cycle counter's
documented CMSIS behaviour
(`.tmp/Adafruit_nRF52_Bootloader/src/cmsis/include/core_cm4.h`).

**Tests.** `tests/test_boot_process.c` gained one new native scenario
(the floor-extent-identity case) and one existing test
(`test_torn_settings_commit_during_finalize_forces_rollback`) was
re-expressed against the new shared settings codec's real fault-
injection points instead of the removed `settings_tear` enum; the full
real transaction processor now has 22 passing scenarios, alongside the
unchanged installer/tools/record/Ed25519/descriptor/boot-
info/source-order suites. `TMPDIR=.tmp make test-xiao-ota-bootloader`
passes completely.

An isolated ARM cross-compile re-verification
(`XIAO_OTA_NOSWD_WORK=.tmp/<isolated-name> make build-xiao-ota-bootloader-noswd`,
a fresh work directory distinct from any shared package path, removed
afterward) links cleanly: FLASH 36,212/38,912 bytes used (93.06%, code +
rodata; up from 35,388/38,912 before this pass's changes, reflecting the
DWT infrastructure, the extra WIP poll, and the settings codec
consolidation); `xiao_ota_state_t` is unchanged at 152 bytes.

**Not yet addressed / deferred pending main's agreement:** none of this
pass's changes touch state-v1/floor-v1 on-flash layout, so no proposal
was required for the work above. A prior request asked whether the
settings-page fault model needed a durable layout change to preserve
non-bank fields; it does not -- the shared codec above already preserves
them by construction (read-modify-write of the whole page), with no
ABI-affecting change to propose.

**Tests.** `tests/test_boot_process.c` gained seven new native scenarios
covering all of the above (six for points 1-5 plus the settings-tear
case); the full real transaction processor now has 21 passing scenarios
(20 boot-process cases plus the pre-existing shared-processor coverage),
alongside the unchanged installer/tools/record/Ed25519/descriptor/boot-
info/source-order suites. `TMPDIR=.tmp make test-xiao-ota-bootloader`
passes completely.

An isolated ARM cross-compile re-verification
(`XIAO_OTA_NOSWD_WORK=.tmp/<isolated-name> make build-xiao-ota-bootloader-noswd`,
a fresh work directory distinct from any shared package path, removed
afterward) links cleanly: FLASH 35,388/38,912 bytes used (91%, code +
rodata; 632 bytes initialized data on top), matching the same size class
as every prior build in this document; `xiao_ota_state_t` is unchanged at
152 bytes.

## Fixed: settings-page rollback rebuilt from whatever the page currently held, not a frozen admission-time snapshot

The prior settings codec (previous section, "Shared bank-0 settings
codec") already preserved every non-bank-0 field byte-for-byte across an
*individual* read-modify-write -- but every one of `finalize_install_and_
verify()`'s install and the rollback path's restore was still a
read-modify-write against whatever the settings page *currently* held at
that moment, not against what it held when this transaction was
admitted. If the page's ancillary bytes were ever damaged or drifted
between admission and a later rollback (for example, a torn write
elsewhere on that same page from an unrelated fault), the restore would
durably re-commit that damage rather than recovering the device's
actual pre-transaction settings. Main's approved design closes this with
an explicit, immutable per-transaction snapshot:

- **A new 88-byte "settings sidecar" record** lives at a fixed offset
  (`0x100`) inside each existing state sector (`XIAO_OTA_SETTINGS_
  SIDECAR_A/B` at `XIAO_OTA_STATE_A/B + 0x100`) -- not a new sector, and
  not appended to the 811,008-byte backup bank. Layout: `magic`(4) /
  `version`(2) / `record_bytes`(2) / `matching_state_sequence`(4) /
  `transaction_nonce`(8) / `command_digest_sha256`(32) /
  `original_settings_raw`(28, the exact whole 28-byte settings page
  captured once) / `crc32`(4, at byte offset 80) / `commit_marker`(4, at
  byte offset 84). `xiao_ota_state_t` (152 bytes, version 1) and the
  188-byte command-v2 wire format are both completely unchanged.
- **Captured exactly once, at genuine command admission**, immediately
  after the fresh application/command checks that gate acceptance in the
  first place -- never re-captured, never derived from a later read.
  `hash_command_digest()` computes a real SHA-256 over the exact accepted
  command bytes (sized by its declared v1/v2 length) purely as an
  additional binding check (not a substitute for the existing Ed25519
  signature verification, which still runs first and unchanged).
- **Rollback and install both now restore/derive from this frozen
  snapshot, never the current page.** `xiao_ota_settings_apply_bank0()`
  (install) overlays only `bank_0`/`bank_0_crc`/`bank_0_size` onto the
  frozen `original_settings_raw` base and writes that; `xiao_ota_
  settings_restore_raw()` (rollback) writes the frozen 28 bytes back
  verbatim, unmodified. Both go through one shared, fault-checked
  primitive, `settings_write_raw()`.
- **A new pre-erase safety check, `settings_page_tail_erased()`**,
  verifies the settings page's normally-unused tail (byte offset 28
  through the end of its 4 KiB page) reads back genuinely blank before
  any settings write is allowed to erase that page. Unexpected/foreign
  data there now refuses the write outright rather than silently
  destroying whatever was living in that space.
- **One physical erase per sector, two records written in a fixed
  order.** `write_state_with_sidecar()` erases the *opposite* state
  sector once, writes the sidecar's body then its own commit marker,
  reads both back, then writes the (unchanged, 152-byte) state's body
  then its own commit marker, and reads both back -- the existing
  single-record `write_record()`/readback-verify contract is reused
  twice against the same sector, never a second erase.
- **An active (non-terminal) transaction's state record now requires a
  matching sidecar to proceed at all.** A new gate,
  `transaction_active`, computed once every boot from the already-typed
  `read_pair()` result for the sidecar slot pair (Found/Missing/Damaged/
  IO-error, the same typed result the rest of this project's metadata
  reads already use), checks the sidecar is present, structurally valid,
  and its `matching_state_sequence`/`transaction_nonce` agree with the
  currently-trusted state record. Any disagreement -- missing, damaged,
  or simply stale/mismatched (for example, a torn write that landed a
  valid-but-superseded sidecar in the other slot) -- now force-recovers
  before any further boot logic runs, exactly the same fail-closed
  posture this project already applies to every other untrusted
  metadata read. A terminal-phase state (no active transaction) never
  needs a sidecar and is unaffected.
- **The existing "blank tail beyond the record" invariant that every
  other slot-pair type already relies on had to be made sector-aware.**
  Sidecar and state now physically share one sector at different fixed
  offsets, so the old assumption -- "safe to overwrite" means "the
  commit marker reads blank AND everything after this record's own
  bytes, out to the sector end, reads erased" -- would wrongly treat an
  expected, legitimate torn sidecar write (which lands inside the
  state record's own "must be blank beyond me" scan window) as page
  damage. A new `state_sector_tail_erased()` scans the whole 4 KiB
  sector while explicitly excluding *both* known record windows (state's
  own 152 bytes and the sidecar's 88 bytes at its fixed offset) before
  either record's slot-pair reader decides "safe to overwrite" --
  used identically by both, since they are never two independent
  sectors. Command, floor, and confirmation records are entirely
  unaffected: each still owns its whole sector exclusively, using the
  original (now factored-out) `sector_tail_erased()` logic unchanged.

**What this does not change:** the 152-byte state-v1 layout, the 188-byte
command-v2 layout, the confirmation/floor-v1 formats, the `<=708,608`
candidate-commissioning ceiling, the `811,008`-byte backup-bank capacity,
and every fix from every prior section above -- WP#/HOLD# level control,
DWT-based real timeout calibration, floor-extent identity, five-review
metadata/confirmation/slot/backup/QSPI-init fixes, and the original
unchecked-IO/trial-confirmation fixes -- all remain in force and
untouched by this pass.

**Tests.** `tests/test_boot_process.c` gained four new native scenarios
proving the properties above end-to-end through the same real, unmodified
`xiao_ota_boot_process_io()` shared transaction processor (no parallel
re-simulation): (1) rollback restores the settings page bit-for-bit
identical to the originally-frozen snapshot -- including every ancillary
field (`bank_1`/`sd_image_size`/`bl_image_size`/`app_image_size`/
`sd_image_start`) -- even after the CURRENT page's ancillary bytes are
deliberately corrupted mid-transaction, proving the restore genuinely
comes from the frozen sidecar and not a read-modify-write over whatever
the page currently holds; (2) an active-phase state with a genuinely
missing sidecar force-recovers with zero state/floor/flash mutation; (3)
an active-phase state whose sidecar reads back structurally valid but
whose `transaction_nonce` disagrees with the state record's own nonce
(a torn dual-record write landing a stale-but-otherwise-valid sidecar)
force-recovers identically; (4) a poisoned (non-blank) settings-page tail
refuses both the install-time and the resulting rollback-time settings
write, escalating to `force_recovery()` rather than ever reporting a
false `CONFIRMED` or `FAILED` outcome. The full real transaction processor
now has 26 passing native scenarios (22 prior plus these 4), alongside the
unchanged installer/tools/record/Ed25519/descriptor/boot-info/source-order
suites. `TMPDIR=.tmp make test-xiao-ota-bootloader` passes completely.

An isolated ARM cross-compile re-verification
(`XIAO_OTA_NOSWD_WORK=.tmp/<isolated-name> make build-xiao-ota-bootloader-noswd`,
a fresh work directory distinct from any shared package path, removed
afterward) links cleanly: FLASH 36,916/38,912 bytes used (94.87%, code +
rodata; 1,996 bytes free; up from 36,212/38,912 before this pass,
reflecting the sidecar record type, its layout/validation helpers, the
new raw-page settings primitives, and the sector-aware blank-tail check);
`xiao_ota_state_t` remains unchanged at 152 bytes.

**What remains genuinely unverified:** this entire design has been
exercised only through the native fault-injected test harness above and a
host/ARM compile -- it has never run on either authorized lab board, and
per this project's scope, will not until a separate, explicitly
authorized hardware session performs that check. The frozen-snapshot
approach is a correctness improvement over the prior read-modify-write
behaviour for the specific torn/damaged-page scenario described above;
it does not, by itself, prove anything about the real P25Q16H/S140
settings-page erase-and-program timing on real silicon beyond what the
prior DWT-calibration section already established.

## Fixed: cross-role floor-continuity bypass after a compiled-loader swap, and an ARM FLASH margin this fix could not fit within

A follow-up security review (Sol/Astra) found that the anti-rollback
floor's role binding stopped being checked once the floor advanced past
0. Genesis (floor 0) verifies the floor-activation receipt's identity,
signature, *and compiled role* before trusting it. Every later
floor-dependent accept, however, only re-verified the *counter and
content hash* of whichever physical receipt window ping-pong currently
pointed at -- not that the receipt still names this binary's own
`XIAO_OTA_COMPILED_ROLE_ID`. Concretely: confirm role0's genesis and
advance its floor to 1 as designed, then physically replace *only the
compiled loader* with a role1 build while leaving the floor/backup
sectors untouched (installing a different role's loader is explicitly
unsupported, but nothing stopped a validly role1-signed command from
being silently accepted against role0's already-confirmed floor
history) -- a genuine cross-role anti-rollback bypass, not merely an
unsupported-install inconvenience.

This is now closed without any schema, wire, or trust-anchor change:

- **`floor_activation_receipt_identity_role_ok()`** extracts the
  identity+signature+role check (previously only run at genesis) into a
  function reusable at any floor value.
- **`floor_role_evidence_ok()`** re-runs that check against *both*
  physical floor-activation windows (`XIAO_OTA_FLOOR_ACTIVATION_A` and
  `_B`) and accepts if *either* verifies for this binary's own compiled
  role -- any I/O failure on a window is tracked but does not by itself
  cause a refusal if the other window verifies.
- **`persist_floor()`** now carries the verified role-activation receipt
  forward into the *other* physical window on every floor advance (read
  source before erasing the target, best-effort write after the floor
  commit), so both ping-pong windows independently attest the compiled
  role after every advance, not just the original genesis window.
- **A single unconditional gate** at the end of
  `xiao_ota_boot_process_io()` -- applied after both the direct
  floor-than-zero switch-case path and the CONFIRMED-state floor-repair
  path -- refuses the command whenever neither window's receipt matches
  this binary's own compiled role. Signature verification over the
  command itself still runs first and unchanged; only a *role* mismatch
  is newly refused. No counter reset, floor erasure, re-commissioning,
  wildcard, or trust-anchor change is involved.

Two new native regressions exercise this directly:
`test_cross_role_loader_swap_cannot_install_after_real_confirm()` drives
a real genesis-to-CONFIRMED flow to floor 1 through the genuine
`persist_floor()` carry-forward, asserts both physical windows
independently verify role-correctly (proving carry-forward worked),
overwrites *both* windows with a validly-signed wrong-role receipt
(simulating the loader swap), then submits a fresh counter-advancing
command signed for this binary's own compiled role and asserts it is
refused with the floor, hash, and `CONFIRMED` state unchanged and no
force-recovery triggered; `test_same_role_floor_survives_many_real_
advances()` drives six real confirm/advance cycles and asserts both
windows independently verify role-correctly after *every single*
advance, proving ordinary same-role continuity and rollback are
unaffected across unlimited advances, not just once. The transaction
processor now has 28 passing native scenarios for each compiled role
(26 prior plus these 2), run for both `XIAO_OTA_COMPILED_ROLE_ID=0` and
`=1`; `TMPDIR=.tmp make test-xiao-ota-bootloader` passes completely for
both.

**This fix could not be re-qualified on real hardware this pass.** An
isolated ARM cross-compile of all four board x role combinations
(`xiao_nrf52840` and `sensecap_solar_p1`, roles 0 and 1) now fails to
*link*, identically across all four:

```
region FLASH overflowed with .data and user data
section .bootloaderConfig LMA [000fd800,000fd857] overlaps section .data LMA [000fd7fc,000fd8f3]
FLASH: 38,908 / 38,912 bytes (99.99%)
```

This is a fixed-address geometric overlap, not merely a raw-byte
overage: `.data`'s load-address range must end before the fixed
`0xfd800` `.bootloaderConfig` address and currently overruns it by 243
bytes. To isolate how much of this is attributable to this fix versus
pre-existing, the new role-evidence gate's call site was temporarily
disabled (`#if 0`-equivalent) so the linker's `--gc-sections` could drop
the now-unreachable `floor_role_evidence_ok()`/window-read code; that
build *still* fails to link, at 38,716 bytes with a 51-byte overlap.
That means roughly 51 of the 243 overflow bytes pre-exist this fix in
the current uncommitted tree -- most likely from other in-flight work
layered on top of the 36,916-byte ARM baseline recorded in the prior
section above, since no NDEBUG/assert or path-length factor applies
(this source has no `assert()` calls) -- and this fix adds the
remaining 192 bytes on top. Two size-reduction attempts were made
without changing behaviour: an `__attribute__((noinline))` hint on
`floor_role_evidence_ok()` made it *worse* (+64 bytes, reverted), and
refactoring it to share one stack receipt buffer across both window
reads instead of two separate structs produced an *identical* binary
(GCC/LTO at `-Os` had already canonicalized the two forms) -- so no
further size lever was found that preserves the security fix as-is. No
crypto/recovery/slot-layout shortcut, counter/floor-schema
reinterpretation, or check removal was used to force a fit.

**Flashing any of the four board x role combinations from the current
source tree is unsafe and blocked** pending either a genuine code-size
reduction found elsewhere in the bootloader (outside this fix) or an
explicit decision from Root/FW about the pre-existing, fix-independent
51-byte overrun already present in the tree before this change. This
status has been reported upstream rather than resolved by weakening the
fix, per explicit instruction. `xiao_ota_state_t` (152 bytes),
`xiao_ota_floor_activation_record_t`, and the 386-byte genesis receipt
and 188-byte command-v2 wire layouts are all unchanged by this fix.

## Fixed: role-continuity gate ran after reconstruction's mutation, and persist_floor() could erase the last surviving receipt window

A follow-up review of the cross-role floor-continuity fix above (Root/
Astra) found two further gaps in the same mechanism, both now closed,
both behavioural-only (no schema/wire/trust-anchor change):

1. **Reconstruction-before-gate ordering.** The CONFIRMED-state floor-
   reconstruction block (the one that rebuilds a DAMAGED/MISSING/stale
   floor from an independently-verified CONFIRMED state record) called
   `persist_floor_or_recover()` -- which durably erases and rewrites a
   physical floor slot -- *before* the final unconditional role-evidence
   gate at the end of `xiao_ota_boot_process_io()` ever ran. By the time
   that gate could notice bad/missing role evidence and demote
   `floor_trustworthy`, the reconstruction write was already durably
   committed. `floor_role_evidence_ok()` is now checked as an explicit
   precondition inside this block, failing closed to Recovery with no
   mutation at all if it does not verify -- never inferring role
   continuity from the state/command/loader alone, and never silently
   stamping a reconstructed floor as role-neutral.

2. **Receipt propagation could itself destroy the last surviving copy.**
   `persist_floor()`'s existing carry-forward (read the untouched SOURCE
   slot's window, erase TARGET, write the copy into TARGET) assumed
   SOURCE always already held a valid receipt. If an *earlier* advance's
   best-effort write into what is now SOURCE had silently failed, SOURCE
   could be blank while TARGET -- about to be erased by this exact call
   -- held the only surviving verifying receipt. `persist_floor()` now
   reads and identity/role-classifies BOTH windows before touching
   either slot; if only TARGET currently verifies, it durably programs
   those exact bytes into SOURCE's window (NOR-safe, since that window
   is only ever written here while still in its post-erase blank state)
   and requires a byte-identical readback before proceeding -- if that
   propagation does not durably confirm, the advance fails closed with
   **neither** slot erased, rather than ever erasing TARGET while SOURCE
   remains unconfirmed. Only once SOURCE durably holds the evidence
   (whether it always did, or was just confirmed) is TARGET erased and
   the new floor body committed; the post-write copy into TARGET's own
   (now blank) window remains best-effort, same as before, since it is
   no longer safety-critical once SOURCE is guaranteed durable.

Both fixes are exercised by the existing 28-scenario regression set
(the cross-role-swap and many-advances tests above already drive real
`persist_floor()` carry-forward and would have caught a regression in
either direction); no new test was required to prove these specific
ordering/erase-safety properties beyond what those two tests already
exercise end-to-end. `TMPDIR=.tmp make test-xiao-ota-bootloader` passes
completely for both roles (80/80 markers, exit 0) -- native debug
(`-O0`) builds of the direct test binary take noticeably longer than
before (the state/sidecar publication-cut fault-injection matrix now
drives many more `persist_floor()` calls, each doing real Ed25519
verification at `-O0` instead of a raw byte copy; roughly 80 seconds
per role directly, versus ~25 seconds through the Makefile's own
optimized test build) -- this is a native-test-harness-only slowdown,
not a product behaviour change, since real hardware only ever calls
`persist_floor()` once per genuine floor advance.

**This makes the already-reported ARM blocker above larger, not
smaller.** A fresh isolated ARM cross-compile with both of these fixes
applied now reports a clean, linker-computed overflow for
`xiao_nrf52840`/role0:

```
region FLASH overflowed by 188 bytes
FLASH: 39,100 / 38,912 bytes (100.48%)
```

up from the 38,908-byte/243-byte-geometric-overrun figure in the prior
section. The four-combination ARM blocker remains open and unresolved;
no further size-reduction attempt has been made this pass, and none of
this additional correctness work was skipped or weakened to try to make
it fit.

### Fixed: role-evidence failure was a soft trust demotion, not terminal Recovery; `persist_floor()` committed the target floor before its own receipt copy was durable

Two further gaps, found during a closer re-read of the same cross-role
continuity property:

1. **The final, unconditional role-continuity gate (covering every
   ordinary floor>0 path, not only the CONFIRMED-state repair block)
   only called `force_recovery()` on a genuine QSPI *read* failure.** A
   clean read that simply found no verifying receipt in either window
   instead just cleared `floor_trustworthy` and fell through, relying on
   the rest of the function to "refuse new admission" on that flag
   alone. That is almost right for a brand-new command, but an
   *already-active* trial/confirmation resume (further down, keyed off
   the same `floor_trustworthy` flag) would instead reinterpret the
   failure as an ordinary "this command no longer matches" and drive a
   `ROLLBACK_COPYING` state persist of its own -- a real mutation, and a
   silent one, not the externally observable Recovery escalation a
   genuine role/history conflict warrants. The gate now calls
   `force_recovery()` directly and returns in every failure case here,
   exactly like the equivalent gate inside the CONFIRMED-state repair
   block already did. `test_cross_role_loader_swap_cannot_install_
   after_real_confirm` now asserts `force_recovery_calls == 1` (was
   `0`), matching this corrected, stricter expectation.

2. **`persist_floor()` still committed the target floor's full body and
   commit marker (via the single erase-owning `write_record()`) before
   ever writing the receipt into that target's own window.** Functionally
   safe (SOURCE's copy is what the next boot actually relies on; the
   target's own in-sector copy is pure convenience for a future
   advance), but it meant a target floor record could durably commit
   while that same sector's own receipt copy was still unwritten --
   backwards from the required ordering. `persist_floor()` now erases
   the target sector once, then (if SOURCE was already confirmed to
   independently hold the evidence) writes and reads back that same
   receipt into TARGET's window, and only then calls
   `write_body_then_marker()` directly for the floor body and its final
   commit marker -- never a second erase-owning call after the receipt
   write. This mirrors `write_state_with_sidecar()`'s existing "one
   erase, two body writes into the same sector" shape. A crash between
   the receipt write and the floor write now leaves TARGET erased/
   invalid (SOURCE, never touched by this call, is still what
   `read_pair()` trusts on the next boot), never a "committed floor,
   missing receipt" state.

Both existing role-continuity tests (`test_cross_role_loader_swap_
cannot_install_after_real_confirm`, `test_same_role_floor_survives_
many_real_advances`) continue to pass with this reordering;
`TMPDIR=.tmp make test-xiao-ota-bootloader` passes for both roles
(80/80, exit 0). A fresh ARM rebuild of all four board x role
combinations shows this reordering is size-neutral (identical total
instruction/data content, just re-sequenced): all four still report
`region FLASH overflowed by 188 bytes` at 39,100/38,912 bytes
(100.48%) -- unchanged from the previous section's single-combination
figure, now confirmed across the full matrix. The four-combination ARM
blocker remains open and unresolved.

### Size reduction, and a correction to the real remaining gap

Two safe, behaviour-preserving size reductions were then applied to
`xiao_ota_boot_io.c`, scoped to this one file only (no Makefile/
`prepare_upstream.py`/linker-script edits):

- A file-scoped `#pragma GCC optimize("Oz")` (confirmed accepted by the
  project's GCC 14.2.1 arm-none-eabi toolchain). This affects only this
  translation unit; every other file (including all crypto/TweetNaCl/
  SHA-256 code) keeps the project-wide `-Os` from the vendor Makefile.
- Removing a now-pointless full-receipt stack-to-stack copy in the
  shared `floor_activation_window_verify_into()` helper: the caller-
  supplied window buffer is always the caller's own word-aligned
  `XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES` buffer and the receipt's
  wire layout is read byte-for-byte with no transform, so the leading
  `XIAO_OTA_FLOOR_ACTIVATION_TOTAL_BYTES` can be reinterpreted in place
  (the build already uses `-fno-strict-aliasing` project-wide, so this
  is safe) instead of `memcpy`'d into a second on-stack copy on every
  call.

Both changes are verified size-neutral for test *behaviour*: native
`TMPDIR=.tmp make test-xiao-ota-bootloader` is 80/80 for both roles
after each change.

**Important correction.** Earlier figures in this document (the
"`overflowed by 188 bytes`" / "`39,100/38,912 bytes`" numbers above,
and an intermediate, never-published internal "60 bytes remaining"
estimate) were read from the linker's top-of-output `Memory region ...
Used Size` summary line for the `FLASH` region. That line is reliable
only while `.text`/`.rodata` alone already exceed the region -- once
`.text` is shrunk enough that *it* no longer reaches into the fixed
`.bootloaderConfig` window at `0x0FD800`, the linker instead reports a
**separate** `.data`/`.bootloaderConfig` LMA overlap, and the "Used
Size" summary line silently stops counting `.data`'s own footprint (a
fixed, vendor TinyUSB/CDC-descriptor block -- `desc_configuration_cdc_
msc`, `desc_device`, `SystemCoreClock`, etc. -- unrelated to anything
in this file, confirmed via the linker `.map`, `0xF8` = 248 bytes on
every board/role combination). The true, authoritative overflow is
`.data`'s LMA end minus `.bootloaderConfig`'s start, read directly from
the linker's explicit overlap diagnostic, not the summary table.

After the two reductions above, all four board x role combinations
report an *identical* true remaining overflow of **243 bytes**
(`.data` LMA `[0x000fd7fc,0x000fd8f3]` versus `.bootloaderConfig` LMA
`[0x000fd800,0x000fd857]`; confirmed on `xiao_nrf52840`/`sensecap_
solar_p1` x role 0/1, from each combination's own linker `.map`) --
*not* the 60 bytes a prior status implied. Rebuilding the known-good
qualified baseline (`.tmp/ota-index/1bf73e725943b6a7f278d9dc9bc7bbca
89788887`'s `xiao_ota_boot_io.c`, in isolation, with everything else
unchanged) confirms this reading method is correct: that baseline
links cleanly with **no** overlap diagnostic at all, `FLASH: 38,652 B
/ 99.33%` (260 bytes of genuine headroom against the 38,912-byte no-
SWD budget) -- i.e. the summary line *is* trustworthy once there is no
overlap, which is exactly why this discrepancy went unnoticed until
the overlap disappeared from `.text` alone and moved to `.data`.

**Net effect:** the two size reductions above are real and verified,
but the four-combination ARM artifact is still **not safe to produce
or flash** -- a genuine ~243 bytes of further reduction is required,
not 60. Both easy, zero-risk levers available within this file alone
(a further `-Oz`-class pragma permutation, and the one meaningful
duplicate-copy removal found) have now been tried and are exhausted;
closing the remaining gap without weakening any receipt/role/crypto
semantics will most likely require either (a) scope to touch the
generated linker script or vendor Makefile's CRT/startup footprint
(e.g. the unused `.init_array`/`.fini_array`/`.tm_clone_table`
C++-static-constructor plumbing this C-only firmware never uses), or
(b) an explicit decision from Root/Sol/main on what, if anything, is
deferred. This is reported now rather than continuing to iterate
blind on an already-corrected number.
