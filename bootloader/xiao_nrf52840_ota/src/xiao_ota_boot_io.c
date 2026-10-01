/* Build this translation unit for minimum code size specifically
 * (GCC14's -Oz, distinct from the project-wide -Os the rest of the
 * bootloader uses) -- this file alone carries the role-continuity
 * evidence/receipt logic that pushed the no-SWD 38 KiB slot over
 * budget; -Oz here is strictly a non-semantic code-generation choice
 * (no crypto, no verification, no write-ordering behaviour is
 * weakened by it) and does not change any other translation unit's
 * own optimization level. */
#pragma GCC optimize("Oz")

#include "xiao_ota_boot_io.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ed25519.h"
#include "crc16.h"
#include "xiao_ota_layout.h"
#include "xiao_ota_public_key.h"
#include "xiao_ota_record.h"
#include "xiao_ota_sha256.h"

/*
 * Production always trusts the compiled-in lab public key. A native host
 * test that literally executes command_policy_valid() (not a parallel
 * reimplementation of it) needs to sign real commands without any
 * dependency on that committed key's actual private half, which this
 * bootloader deliberately never has access to at build time -- so the
 * test build alone may override this to a self-generated, test-only
 * keypair via -D. This does not change what a real bootloader binary
 * trusts: the override is never defined outside test builds.
 */
#ifndef XIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY
#define XIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY xiao_ota_lab_public_key_ed25519
#endif

#define COPY_CHUNK 256u

static uint8_t io_buffer[COPY_CHUNK] __attribute__((aligned(4)));
/*
 * QSPI EasyDMA (NRF_QSPI->WRITE.SRC / READ.DST) can only address Data RAM on
 * the nRF52840; it cannot DMA directly out of internal code flash. This
 * staging buffer lets copy_internal_to_qspi() read a chunk of the running
 * application (code flash) with the CPU first, then hand QSPI a RAM pointer.
 */
static uint8_t flash_stage_buffer[COPY_CHUNK] __attribute__((aligned(4)));
static uint8_t verify_buffer[COPY_CHUNK] __attribute__((aligned(4)));

/*
 * Hardware-independent transaction processor: this whole file has no
 * register/pointer access of its own -- every side effect goes through
 * `io` (xiao_ota_boot_io.h). It runs identically whether `io` is the real
 * hardware adapter (xiao_ota_boot.c) or a fake, in-memory-model xiao_ota_io_t
 * built by a native host test (tests/fake_io.c), so a test failure or pass
 * reflects this exact code path, not a hand-maintained parallel copy.
 */

/*
 * Shared streaming-hash core: hash_qspi()/hash_internal() below differ
 * ONLY in which callback streams bytes from flash (io->qspi_read vs
 * io->internal_read); both callbacks share the exact same signature
 * (xiao_ota_boot_io.h), so one generic loop parameterized by a function
 * pointer replaces two otherwise-identical copies of the same chunking/
 * hashing loop. Behaviour (chunk size, error handling, digest output) is
 * unchanged from the two loops this replaces.
 */
typedef bool (*xiao_ota_stream_read_fn)(void *ctx, uint32_t address,
                                        void *destination, size_t length);

static bool hash_stream(xiao_ota_stream_read_fn read_fn, void *ctx,
                        uint32_t address, uint32_t length,
                        uint8_t digest[32]) {
  xiao_ota_sha256_t sha;
  xiao_ota_sha256_init(&sha);
  while (length != 0) {
    uint32_t n = length > COPY_CHUNK ? COPY_CHUNK : length;
    if (!read_fn(ctx, address, io_buffer, n)) return false;
    xiao_ota_sha256_update(&sha, io_buffer, n);
    address += n;
    length -= n;
  }
  xiao_ota_sha256_final(&sha, digest);
  return true;
}

static bool hash_qspi(const xiao_ota_io_t *io, uint32_t address,
                      uint32_t length, uint8_t digest[32]) {
  return hash_stream(io->qspi_read, io->ctx, address, length, digest);
}

static bool hash_internal(const xiao_ota_io_t *io, uint32_t address,
                          uint32_t length, uint8_t digest[32]) {
  return hash_stream(io->internal_read, io->ctx, address, length, digest);
}

/* One-shot single-buffer sha256(data[0..len)) -> digest; shared by the
 * few call sites that already hold their whole input contiguously in RAM
 * (unlike hash_qspi()/hash_internal() above, which stream from flash in
 * pieces). */
static void sha256_of(const void *data, size_t len, uint8_t digest[32]) {
  xiao_ota_sha256_t sha;
  xiao_ota_sha256_init(&sha);
  xiao_ota_sha256_update(&sha, data, len);
  xiao_ota_sha256_final(&sha, digest);
}

static bool all_equal(const uint8_t a[32], const uint8_t b[32]) {
  uint8_t difference = 0;
  unsigned i;
  for (i = 0; i < 32; ++i) difference |= a[i] ^ b[i];
  return difference == 0;
}

/* Old (backup/rollback) extent bound: same XIAO_OTA_INSTALL_MAX_SIZE
 * ceiling enforced on NEW candidates at command-acceptance time, not the
 * larger XIAO_OTA_BACKUP_SIZE physical bank capacity. The physical QSPI
 * backup bank is sized to the full 811,008-byte extent so backing up
 * whatever is genuinely there is always safe, but this durable
 * state.active_image_extent value is used as a live erase/copy address
 * bound below -- an "old extent" beyond the 708,608-byte install/ExtraFS
 * ceiling should never be trusted for that, since v1.17's own filesystem
 * begins at that boundary. */
static bool active_image_extent_bounded(uint32_t extent) {
  return extent != 0 && extent <= XIAO_OTA_INSTALL_MAX_SIZE &&
         (extent & 3u) == 0;
}

/*
 * A durable progress_bytes checkpoint is only ever written by
 * copy_internal_to_qspi()/copy_qspi_to_internal() at a whole-sector
 * boundary, OR left equal to `extent` when the copy finished but the
 * phase-advance persist that should follow it did not land. Anything
 * else (out of bounds, or not sector-aligned and not exactly `extent`)
 * cannot be a genuine checkpoint this processor itself produced, and
 * must never be used as a live internal-flash erase/copy address.
 */
static bool progress_bytes_consistent(uint32_t progress, uint32_t extent) {
  if (progress > extent) return false;
  if (progress == 0 || progress == extent) return true;
  return (progress % XIAO_OTA_QSPI_SECTOR_SIZE) == 0;
}

/*
 * Structural decode + Ed25519 signature verification ONLY for a command
 * record of EITHER supported version, with no floor/extent/counter
 * context applied -- the exact subset of command_policy_valid() below
 * that is true or false independent of THIS boot's live admission state,
 * shared so a HISTORICAL (superseded but still physically present)
 * command can be cryptographically authenticated the same way a live one
 * is, without requiring it to also satisfy a floor/extent context it was
 * never evaluated against. Version dispatch/signed-byte-range rules are
 * identical to command_policy_valid(); see that function's doc-comment.
 */
static bool command_cryptographically_decoded(const xiao_ota_command_any_t *any,
                                              xiao_ota_install_command_t *out_intent) {
  uint16_t version;
  memcpy(&version, (const uint8_t *)any + 4, sizeof(version));
  if (version == XIAO_OTA_COMMAND_VERSION_LEGACY_V1) {
    if (!xiao_ota_command_valid(&any->v1)) return false;
    if (!xiao_ota_install_command_from_v1(&any->v1, out_intent)) return false;
    if (ed25519_verify(any->v1.signature_ed25519,
                       (const unsigned char *)&any->v1.descriptor,
                       sizeof(any->v1.descriptor),
                       XIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY) != 1) {
      return false;
    }
    return true;
  }
  if (version == XIAO_OTA_COMMAND_VERSION_WIRE_V2) {
    if (!xiao_ota_command_v2_valid(&any->v2)) return false;
    if (!xiao_ota_install_command_from_v2(&any->v2, out_intent)) return false;
    if (ed25519_verify(any->v2.signature_ed25519, any->v2.wire_descriptor,
                       XIAO_OTA_WIRE_DESCRIPTOR_SIZE,
                       XIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY) != 1) {
      return false;
    }
    return true;
  }
  return false;
}

/*
 * Cryptographic signature PLUS the static (context-independent) identity
 * policy -- board/role/app-address/format/key/algorithm/capability/size/
 * extent bounds/device-targeting -- for a HISTORICAL command, reusing
 * command_cryptographically_decoded() and
 * xiao_ota_install_command_static_identity_valid() exactly as
 * command_policy_valid() does for a live one below, minus the two
 * context-dependent checks (counter_floor, expected_active_extent) that
 * only make sense for THIS boot's fresh admission. This is what
 * historical_command_matches_digest() requires in addition to the
 * digest match: a bytes-match against a recorded digest alone proves
 * "these exact bytes were physically present", never "these bytes were
 * ever validly signed/targeted for this device" -- this closes that gap.
 */
static bool command_cryptographically_and_statically_authentic(
    const xiao_ota_io_t *io, const xiao_ota_command_any_t *any) {
  xiao_ota_install_command_t intent;
  if (!command_cryptographically_decoded(any, &intent)) return false;
  return xiao_ota_install_command_static_identity_valid(
      &intent, io->device_address(io->ctx));
}

/*
 * Authenticates and authorizes a command record of EITHER supported
 * version and produces the normalized install intent. Version is
 * determined at the structural-validity/decode step ONLY, from
 * record_version -- there is no signature-format fallback or "try both"
 * behaviour: v1 is checked exclusively against its own 71-byte
 * little-endian descriptor and signature; v2 is checked exclusively
 * against its own 59-byte big-endian wire descriptor and signature (the
 * SAME bytes and signature the LoRa OTA transport already verified -- see
 * xiao_ota_command_v2_t in xiao_ota_record.h). All non-cryptographic
 * policy checks (target/role/address/counter/capability/extent/device)
 * are shared in xiao_ota_install_command_policy_valid() so both versions
 * are held to the exact same install policy.
 */
static bool command_policy_valid(const xiao_ota_io_t *io,
                                 const xiao_ota_command_any_t *any,
                                 uint32_t counter_floor,
                                 uint32_t expected_active_extent,
                                 xiao_ota_install_command_t *out_intent) {
  const uint64_t device_address = io->device_address(io->ctx);
  if (!command_cryptographically_decoded(any, out_intent)) return false;
  return xiao_ota_install_command_policy_valid(out_intent, counter_floor,
                                               expected_active_extent,
                                               device_address);
}

/*
 * Distinguishes WHY a pair produced no trusted record, so a caller never
 * has to guess: FOUND (one or both slots hold a structurally valid
 * record, newest returned in `out`), MISSING (both physical erase units
 * are genuinely, fully blank -- this device has never durably written
 * this record type, safe to treat as "nothing yet"), DAMAGED (neither
 * slot validated AND at least one is not fully blank -- torn write, bit
 * rot, or leftover pre-OTA data; never safe to treat as absence), or
 * IO_ERROR (a read itself failed -- the content, if any, is simply
 * unknown this boot; never safe to treat as absence OR damage).
 */
typedef enum {
  XIAO_OTA_PAIR_FOUND = 0,
  XIAO_OTA_PAIR_MISSING,
  XIAO_OTA_PAIR_DAMAGED,
  XIAO_OTA_PAIR_IO_ERROR,
} xiao_ota_pair_status_t;

/*
 * Which (if any) extra known-legitimate window(s), besides the record's
 * own fixed-size prefix, may share this record's physical erase unit --
 * selects which sector_tail_erased()-family helper slot_safe_to_
 * overwrite() uses to decide "genuinely never written" (see that
 * function's doc-comment). NONE is the plain single-record-per-sector
 * case (command, confirmation); STATE excludes the settings sidecar
 * window (state_sector_tail_erased()); FLOOR excludes the
 * BootFloorActivationReceiptV1 window (floor_sector_tail_erased()).
 */
typedef enum {
  XIAO_OTA_SHARED_TAIL_NONE = 0,
  XIAO_OTA_SHARED_TAIL_STATE,
  XIAO_OTA_SHARED_TAIL_FLOOR,
} xiao_ota_shared_tail_t;

/* Whole physical 4 KiB erase unit blank FROM `start_offset` onward, not
 * just the fixed-size record prefix -- used below to confirm the portion
 * of the sector BEYOND the record itself (where a differently-shaped
 * leftover record from before this format existed, or unrelated debris,
 * could sit) is genuinely blank, not only the record's own bytes.
 * Returns false only on an IO failure (result then unknown, not "not
 * blank"); `*out_blank` is only meaningful when this returns true. */
/*
 * Scans an explicit [start, end) byte range at `address` for erased
 * (0xFF) bytes. Shared primitive behind both sector_tail_erased() (single
 * range, record_size..sector_end) and state_sector_tail_erased() below
 * (two explicit ranges, since a state sector's layout has two known,
 * non-adjacent record windows to exclude instead of one).
 */
static bool range_erased(const xiao_ota_io_t *io, uint32_t address,
                         uint32_t start, uint32_t end, bool *out_blank) {
  uint32_t offset = start;
  while (offset < end) {
    uint32_t n = end - offset > COPY_CHUNK ? COPY_CHUNK : end - offset;
    if (!io->qspi_read(io->ctx, address + offset, io_buffer, n)) return false;
    if (!xiao_ota_bytes_erased(io_buffer, n)) *out_blank = false;
    offset += n;
  }
  return true;
}

/* Returns false only on an IO failure (result then unknown, not "not
 * blank"); `*out_blank` is only meaningful when this returns true. */
static bool sector_tail_erased(const xiao_ota_io_t *io, uint32_t address,
                               uint32_t start_offset, bool *out_blank) {
  *out_blank = true;
  return range_erased(io, address, start_offset, XIAO_OTA_QSPI_SECTOR_SIZE,
                      out_blank);
}

/*
 * The state sector now legitimately holds TWO known, non-adjacent record
 * windows written together by write_state_with_sidecar(): the state
 * record itself at offset 0 (sizeof(xiao_ota_state_t) bytes) and its
 * settings sidecar at XIAO_OTA_SETTINGS_SIDECAR_OFFSET
 * (sizeof(xiao_ota_settings_sidecar_t) bytes). A plain "everything after
 * MY record_size" scan (sector_tail_erased() above) would misread the
 * OTHER known record's own legitimate (or genuinely torn) bytes as
 * foreign debris -- so a state read_pair() call could be fooled by an
 * in-progress sidecar write into reporting DAMAGED, or vice versa. This
 * checks every sector byte EXCEPT both known windows, shared identically
 * by the state and sidecar slot_safe_to_overwrite() checks so they always
 * agree on what "genuinely never written" means for this sector.
 */
static bool state_sector_tail_erased(const xiao_ota_io_t *io,
                                     uint32_t sector_base, bool *out_blank) {
  *out_blank = true;
  if (!range_erased(io, sector_base, sizeof(xiao_ota_state_t),
                    XIAO_OTA_SETTINGS_SIDECAR_OFFSET, out_blank)) {
    return false;
  }
  return range_erased(io, sector_base,
                      XIAO_OTA_SETTINGS_SIDECAR_OFFSET +
                          sizeof(xiao_ota_settings_sidecar_t),
                      XIAO_OTA_QSPI_SECTOR_SIZE, out_blank);
}

/*
 * The floor sector now ALSO legitimately holds a second, non-adjacent
 * known window: the floor record itself at offset 0 (sizeof(floor)
 * bytes), and a BootFloorActivationReceiptV1 (xiao_ota_record.h) at the
 * fixed XIAO_OTA_FLOOR_ACTIVATION_WINDOW_OFFSET, up to
 * XIAO_OTA_FLOOR_ACTIVATION_WINDOW_MAX_SIZE bytes -- reserved sector
 * space main's directive placed deliberately inside the SAME physical 4
 * KiB floor sector. Exactly the same reasoning as
 * state_sector_tail_erased() above: a plain "everything after my own
 * record_size" scan would misread a genuinely present (or torn)
 * genesis receipt as foreign debris, forcing a real genesis-eligible
 * pair to read DAMAGED instead of MISSING. This checks every sector
 * byte EXCEPT both known windows.
 */
static bool floor_sector_tail_erased(const xiao_ota_io_t *io,
                                     uint32_t sector_base, bool *out_blank) {
  *out_blank = true;
  if (!range_erased(io, sector_base, sizeof(xiao_ota_floor_t),
                    XIAO_OTA_FLOOR_ACTIVATION_WINDOW_OFFSET, out_blank)) {
    return false;
  }
  return range_erased(io, sector_base,
                      XIAO_OTA_FLOOR_ACTIVATION_WINDOW_OFFSET +
                          XIAO_OTA_FLOOR_ACTIVATION_WINDOW_MAX_SIZE,
                      XIAO_OTA_QSPI_SECTOR_SIZE, out_blank);
}

/*
 * A NOR flash program operation can only ever CLEAR bits (1 -> 0); it
 * never sets a bit back to 1 without a full sector erase. Starting from
 * a genuinely erased field (all-1s), a write of `XIAO_OTA_COMMIT_MARKER`
 * -- complete OR interrupted at ANY point, at ANY byte/bit granularity,
 * in ANY order the hardware happened to reach (real NOR writes are NOT
 * necessarily byte-prefix atomic on power loss) -- can only ever land in
 * a value reachable by clearing some SUBSET of the bits that need
 * clearing to reach the target: every bit where the target is 1 MUST
 * still read 1 (that bit was never touched), while bits where the
 * target is 0 may read either 0 (already applied) or 1 (not yet
 * applied). `marker & XIAO_OTA_COMMIT_MARKER == XIAO_OTA_COMMIT_MARKER`
 * is exactly that reachability test, independent of which specific
 * bits landed or in what order.
 *
 * A slot is safe to treat as "nothing trusted here" (never a discarded
 * commit) only if BOTH: (a) its commit_marker field is EITHER genuinely
 * erased OR some other value reachable purely from an interrupted write
 * of the commit marker itself -- covering both "never touched" and
 * "durably committing, but the write was torn" -- while NOT reading as
 * the exact fully-committed value (which can only mean the write did
 * durably complete); a marker value that is NOT reachable this way at
 * all (e.g. arbitrary foreign bits set that the commit marker would
 * never have set) can only be unrelated debris, never a partial write
 * of this exact record type, and must be treated as unsafe; AND (b) the
 * WHOLE physical erase unit beyond the record itself is genuinely blank
 * -- covering the entire 4 KiB unit, not just the record's own ~60
 * bytes, so a differently-shaped leftover record from before this
 * format existed (or any other debris living later in the same sector)
 * is never mistaken for "never written". A slot whose marker reads as
 * EXACTLY the committed value but still fails structural validation
 * (CRC/body mismatch), or whose tail is not blank, or whose marker holds
 * an unreachable value, can only be a previously-committed record
 * subsequently corrupted (or foreign data), and must never be silently
 * discarded.
 *
 * `shared_tail` selects state_sector_tail_erased() or
 * floor_sector_tail_erased() against `sector_base` instead of the plain
 * single-record tail check, when this record's physical erase unit is
 * known to also legitimately hold a second, non-adjacent window
 * (state+settings-sidecar, or floor+activation-receipt respectively);
 * `sector_base` is unused for XIAO_OTA_SHARED_TAIL_NONE.
 *
 * `body_valid`/`binding_ok`/`binding_ctx` resolve a DEEPER ambiguity the
 * marker-reachability test alone cannot fully close: a reachable-but-
 * not-fully-committed marker is consistent with a genuinely in-flight
 * write of THIS record, torn before its marker finished (safe to
 * discard, trust the sibling). qspi_write()'s byte stream is clocked
 * out, and can only ever be interrupted, in strict address order (see
 * fake_io.c's maybe_tear() and the real QSPI/SPI shift-register
 * hardware it models) -- so a genuinely torn marker write leaves some
 * already-landed prefix followed by a still-fully-erased suffix. An
 * EARLIER revision of this file used that byte SHAPE alone as a
 * physical prerequisite before ever consulting binding_ok(), on the
 * theory that isolated bit rot on an already-committed marker would
 * essentially never happen to also form a clean committed-prefix/
 * erased-suffix split.
 *
 * That theory is FALSE and has been proven so by a real regression
 * (see test_real_committed_retry_prefix_shaped_marker_damage_never_
 * regrants_same_trial() in tests/test_boot_process.c): NOR charge-leak
 * bit rot does not need to touch every bit independently -- an entire
 * already-programmed BYTE can legitimately drift fully back toward
 * 0xFF (the erased level) as multiple bits in it leak over a device's
 * lifetime, producing a "prefix unchanged / trailing byte(s) now all-
 * 1s" pattern that is BYTE-FOR-BYTE IDENTICAL to a genuine in-flight
 * tear that stopped exactly there. The marker bytes alone therefore
 * never carry enough information to distinguish "still being written"
 * from "already committed, then partially bit-rotted" -- no shape
 * heuristic, however plausible, can ever close that gap. This file no
 * longer attempts to: `binding_ok()` is now the ONLY gate below, and it
 * must independently and positively prove the ambiguous record's own
 * identity fields agree with an already-trusted sibling (or, when no
 * sibling exists yet, with the currently authenticated command) --
 * never with marker byte shape.
 *
 * `body_valid`, if non-NULL, checks whether the REST of the record
 * (magic/version/record_bytes/CRC) is fully self-consistent: if it is,
 * `binding_ok(record, binding_sibling, binding_ctx)` must additionally
 * prove this record positively corresponds to a transaction/identity
 * ALREADY independently trusted this boot (e.g. a floor whose counter/
 * hash match the already-read state's candidate fields, or a state
 * whose full immutable identity -- transaction_nonce, candidate_counter,
 * candidate_hash_sha256, the old/backup active_image_extent and its
 * hash, and the previous_bank_0 triad -- agrees with an already-trusted
 * sibling record). Without this binding proof, the slot is treated as
 * NOT safe (DAMAGED), never silently discarded. Even when everything
 * binds, one specific delta can still never be safely credited: an
 * ambiguous record claiming a HIGHER trial_attempts than an already-
 * trusted TRIAL_BOOT sibling would, if adopted, either legitimately
 * resume an interrupted retry OR silently regrant a trial-boot watchdog
 * cycle that bit rot alone erased evidence of already having run --
 * these two cases are provably indistinguishable from durable bytes
 * alone (same reasoning as above, applied to trial_attempts instead of
 * marker shape), so binding_ok() must refuse that specific delta
 * unconditionally and let the caller fail closed to recovery: a real,
 * safe resume is sacrificed in the rare cases where it is genuinely
 * ambiguous, but a regrant is never possible. When `body_valid` is NULL
 * (opted out by a caller for whom this deeper ambiguity is not itself a
 * durable-authority risk, e.g. the command pair, which is always
 * independently re-verified by signature and policy regardless of which
 * physical slot read_pair() happens to select), behaviour is unchanged
 * from the marker-reachability test alone -- the binding check never
 * applies.
 *
 * `xiao_ota_record_evidence_t` names exactly what an ambiguous (failed-
 * valid()) record's own bytes can prove, independent of caller type:
 *
 *   BODY_ONLY    -- the record's body/CRC is fully self-consistent (an
 *                   interrupted write can never coincidentally produce
 *                   a matching CRC over reshuffled/incomplete bytes) but
 *                   its commit_marker is not the exact committed value
 *                   (torn, bit-rotted, or fully erased). Proof this slot
 *                   WAS durably written and verified at some point --
 *                   its non-marker fields are trustworthy data.
 *   UNPROVABLE   -- body/CRC does NOT verify, AND at least one owned
 *                   byte is not in the erased state. No field here is
 *                   trustworthy: this can be an ordinary still-in-flight
 *                   torn write, OR a previously-valid record corrupted
 *                   in both body and marker. Byte shape alone can never
 *                   distinguish the two; only caller-specific binding
 *                   logic (never a blanket skip) may decide.
 *   ABSENT_BYTES -- every owned byte reads erased. No write of any kind
 *                   has ever reached this slot -- the only truly "free"
 *                   case, never requiring binding_ok() proof.
 *
 * Both BODY_ONLY and UNPROVABLE are ALWAYS routed through binding_ok()
 * uniformly for every caller (state/sidecar/floor alike) -- there is no
 * per-type opt-out of the UNPROVABLE case: it is each type's own
 * binding_ok() callback's responsibility to decide, from its own
 * durable-authority stakes and `evidence`, whether an UNPROVABLE (or
 * BODY_ONLY) candidate is safe to discard, never a generic gate-level
 * heuristic over marker shape or blank-ness alone.
 */
typedef enum {
  XIAO_OTA_EVIDENCE_BODY_ONLY,
  XIAO_OTA_EVIDENCE_UNPROVABLE,
  XIAO_OTA_EVIDENCE_ABSENT_BYTES
} xiao_ota_record_evidence_t;

static xiao_ota_record_evidence_t classify_ambiguous_record(
    const void *record, size_t record_size,
    bool (*body_valid)(const void *)) {
  if (body_valid != NULL && body_valid(record)) {
    return XIAO_OTA_EVIDENCE_BODY_ONLY;
  }
  if (xiao_ota_bytes_erased(record, record_size)) {
    return XIAO_OTA_EVIDENCE_ABSENT_BYTES;
  }
  return XIAO_OTA_EVIDENCE_UNPROVABLE;
}

static bool slot_safe_to_overwrite(const xiao_ota_io_t *io, uint32_t address,
                                   const void *record, size_t record_size,
                                   size_t commit_offset, uint32_t sector_base,
                                   xiao_ota_shared_tail_t shared_tail,
                                   bool (*body_valid)(const void *),
                                   bool (*binding_ok)(const void *, uint32_t,
                                                       xiao_ota_record_evidence_t,
                                                       const void *,
                                                       const void *, bool *),
                                   const void *binding_ctx,
                                   const void *binding_sibling,
                                   bool *out_io_error, bool *out_adopt_candidate) {
  uint32_t marker;
  bool tail_blank;
  *out_io_error = false;
  if (out_adopt_candidate != NULL) *out_adopt_candidate = false;
  memcpy(&marker, (const uint8_t *)record + commit_offset, sizeof(marker));
  if ((marker & XIAO_OTA_COMMIT_MARKER) != XIAO_OTA_COMMIT_MARKER) return false;
  if (marker == XIAO_OTA_COMMIT_MARKER) return false;
  /* `body_valid`'s presence (non-NULL), not its RESULT, is the caller's
   * opt-in signal for this deeper check -- see write_body_then_marker():
   * the marker field is left at its fully-erased value (all bits 1) in
   * the local copy right up until the SEPARATE, LATER qspi_write() that
   * actually programs it, and that write only ever runs after the body+
   * CRC write has already completed AND been read back and verified.
   * Marker SHAPE (reachable-nonexact vs. fully erased) is therefore
   * never itself trustworthy evidence of "never written" vs. "written,
   * then corrupted": NOR charge-leak bit rot can decay an
   * already-committed marker (0x434F4D54) all the way back to
   * 0xFFFFFFFF, byte-for-byte identical to genuinely untouched, while
   * the record's own body/CRC (written and verified long before,
   * untouched since) still reads perfectly valid. `classify_ambiguous_
   * record()` (see its doc-comment above) replaces marker-shape
   * inspection entirely with a byte-evidence classification that is
   * blind to marker shape: BODY_ONLY, UNPROVABLE, or ABSENT_BYTES.
   *
   * Only ABSENT_BYTES (every owned byte reads erased -- no write of any
   * kind ever reached this slot) skips binding_ok() and falls through
   * to the tail-blank check below, unconditionally safe for every
   * caller. BODY_ONLY and UNPROVABLE are ALWAYS routed through
   * binding_ok(), uniformly for every record type -- there is no
   * per-type opt-out here; it is the passed-in `evidence` plus each
   * type's own binding_ok() callback that decides, from that type's own
   * durable-authority stakes, whether a given evidence kind is safe to
   * discard (e.g. STATE's fresh-admission case treats UNPROVABLE as
   * harmless -- no confirmed fact is at risk yet -- while FLOOR's
   * callback must never treat UNPROVABLE as safe, since every floor
   * slot that ever existed was durably used the moment this device
   * completed one OTA install, so non-blank debris there can only be
   * corrupted history, never an innocent first write).
   *
   * `binding_sibling`, when non-NULL, is the OTHER slot's record, ALREADY
   * proven valid()/trustworthy by the caller (read_pair()'s "exactly one
   * slot validates" branch) -- passed through so a binding_ok() callback
   * can additionally refuse to discard a record that would silently
   * regress a durable, monotonic fact (e.g. STATE's trial_attempts) the
   * sibling does not already reflect, not just prove transaction
   * identity. NULL in every other branch/caller (no single trustworthy
   * sibling exists to compare against there). */
  if (body_valid != NULL) {
    xiao_ota_record_evidence_t evidence =
        classify_ambiguous_record(record, record_size, body_valid);
    if (evidence != XIAO_OTA_EVIDENCE_ABSENT_BYTES) {
      if (binding_ok == NULL ||
          !binding_ok(record, address, evidence, binding_sibling, binding_ctx,
                      out_adopt_candidate)) {
        return false;
      }
    }
  }
  if (shared_tail == XIAO_OTA_SHARED_TAIL_STATE) {
    if (!state_sector_tail_erased(io, sector_base, &tail_blank)) {
      *out_io_error = true;
      return false;
    }
  } else if (shared_tail == XIAO_OTA_SHARED_TAIL_FLOOR) {
    if (!floor_sector_tail_erased(io, sector_base, &tail_blank)) {
      *out_io_error = true;
      return false;
    }
  } else if (!sector_tail_erased(io, address, (uint32_t)record_size,
                                 &tail_blank)) {
    *out_io_error = true;
    return false;
  }
  return tail_blank;
}

/*
 * Reads both slots of an A/B record pair and reports FOUND/MISSING/
 * DAMAGED/IO_ERROR (see xiao_ota_pair_status_t). `out_holder_address`, if
 * non-NULL, is always set: to whichever address held the newest record on
 * FOUND, or to `b_address` on any other status (a fixed, deterministic
 * "nothing trusted yet" default so persist_state()/persist_floor() have a
 * defined starting slot to write the OTHER of). Never inspects `a`/`b`
 * beyond what was actually read: an IO_ERROR returns before either buffer
 * is used for anything, so a caller can never observe a decision made
 * from an unread buffer.
 *
 * MISSING requires BOTH slots to be safe_to_overwrite (see above) -- this
 * covers a genuinely blank whole-sector pair (fresh device) AND a pair
 * where neither slot's commit_marker was ever actually programmed and
 * the rest of the sector is genuinely blank too (an interrupted write of
 * this exact record type). Anything else that failed newest_valid() is
 * reported DAMAGED: a committed-but-now-invalid record, or non-blank
 * debris anywhere in either physical erase unit.
 *
 * When exactly ONE slot passes `valid()`, this does NOT return FOUND on
 * that alone: a slot that fails `valid()` could either be genuinely
 * never-committed (in which case trusting the sibling is exactly right,
 * the ordinary "next transaction being prepared" case) or a PREVIOUSLY
 * committed record that has since been corrupted (bit rot, a torn
 * write that landed a committed marker but mangled the body, or similar)
 * -- in which case silently falling back to whatever older record the
 * sibling slot happens to hold would resurrect stale, superseded state
 * as if it were still authoritative, hiding real corruption behind an
 * apparently-clean boot. The failing slot is therefore always classified
 * with slot_safe_to_overwrite() before the valid sibling is trusted: only
 * a genuinely safe-to-overwrite (never-committed) failing slot allows
 * FOUND; a failing slot that is NOT safe to overwrite (its commit marker
 * reads as committed, or its tail is not blank) reports DAMAGED instead,
 * regardless of how clean the sibling looks.
 *
 * `a_sector_base`/`b_sector_base` and `shared_tail` are forwarded to
 * slot_safe_to_overwrite() -- equal to `a_address`/`b_address` with
 * `shared_tail=XIAO_OTA_SHARED_TAIL_NONE` for every single-record-per-
 * sector pair (command/confirmation), the owning STATE sector's own
 * base address with `shared_tail=XIAO_OTA_SHARED_TAIL_STATE` for BOTH
 * the state and the settings-sidecar pairs (one shared physical erase
 * unit), and the owning FLOOR sector's own base address with
 * `shared_tail=XIAO_OTA_SHARED_TAIL_FLOOR` for the floor pair (shares
 * its erase unit with the BootFloorActivationReceiptV1 window).
 *
 * `body_valid`/`binding_ok`/`binding_ctx` are forwarded unchanged to
 * every slot_safe_to_overwrite() call this makes -- see that function's
 * doc-comment for what they resolve. Pass `body_valid=NULL` to opt a
 * caller out entirely (preserves the marker-reachability-only test);
 * currently only the command pair does this (see call site). The
 * "exactly one slot validates" branch additionally passes the validated
 * sibling record itself through as `binding_sibling`, so a binding_ok()
 * callback can compare against it (see slot_safe_to_overwrite()'s
 * doc-comment); the "neither slot validates" branch always passes NULL
 * (no single trustworthy sibling exists there to compare against).
 */
static xiao_ota_pair_status_t read_pair(const xiao_ota_io_t *io,
                                        uint32_t a_address, uint32_t b_address,
                                        uint32_t a_sector_base,
                                        uint32_t b_sector_base,
                                        xiao_ota_shared_tail_t shared_tail,
                                        void *a, void *b, size_t size,
                                        size_t commit_offset,
                                        bool (*valid)(const void *), void *out,
                                        uint32_t *out_holder_address,
                                        bool (*body_valid)(const void *),
                                        bool (*binding_ok)(const void *, uint32_t,
                                                            xiao_ota_record_evidence_t,
                                                            const void *,
                                                            const void *, bool *),
                                        const void *binding_ctx) {
  bool a_valid, b_valid, a_safe, b_safe, a_io_error, b_io_error;
  if (out_holder_address) *out_holder_address = b_address;
  if (!io->qspi_read(io->ctx, a_address, a, size)) return XIAO_OTA_PAIR_IO_ERROR;
  if (!io->qspi_read(io->ctx, b_address, b, size)) return XIAO_OTA_PAIR_IO_ERROR;
  a_valid = valid(a);
  b_valid = valid(b);


  if (a_valid && b_valid) {
    uint32_t a_sequence, b_sequence;
    const void *newest;
    memcpy(&a_sequence, (const uint8_t *)a + 8, sizeof(a_sequence));
    memcpy(&b_sequence, (const uint8_t *)b + 8, sizeof(b_sequence));
    newest = (int32_t)(b_sequence - a_sequence) > 0 ? b : a;
    memcpy(out, newest, size);
    if (out_holder_address) {
      *out_holder_address = (newest == a) ? a_address : b_address;
    }
    return XIAO_OTA_PAIR_FOUND;
  }

  if (a_valid != b_valid) {
    /* Exactly one slot validates. Before trusting it, confirm the OTHER
     * (failing) slot is genuinely safe to overwrite -- never committed --
     * rather than assuming that because ONE side is clean the other
     * side's failure is harmless. */
    const void *good = a_valid ? a : b;
    const void *bad = a_valid ? b : a;
    uint32_t bad_address = a_valid ? b_address : a_address;
    uint32_t good_address = a_valid ? a_address : b_address;
    uint32_t bad_sector_base = a_valid ? b_sector_base : a_sector_base;
    bool bad_safe, bad_io_error, adopt_candidate = false;
    bad_safe = slot_safe_to_overwrite(io, bad_address, bad, size, commit_offset,
                                      bad_sector_base, shared_tail,
                                      body_valid, binding_ok, binding_ctx, good,
                                      &bad_io_error, &adopt_candidate);
    if (bad_io_error) return XIAO_OTA_PAIR_IO_ERROR;
    if (!bad_safe) {
      /* Report the GOOD slot's address even on a DAMAGED return (not
       * the function-entry default of `b_address`, which is only
       * correct here by coincidence when `good` happens to be b). A
       * caller that goes on to repair a durably-known-good fact (e.g.
       * FLOOR from an independently-trusted CONFIRMED state) needs to
       * know which slot is ALREADY good so it can target its own next
       * write at the complementary (bad) slot -- persist_*()'s
       * "alternate away from the current holder" convention -- and
       * must never let that write land on the good slot instead,
       * which would erase the one durable, already-valid copy while
       * leaving the genuinely bad slot untouched and still unresolved
       * on every subsequent boot. */
      if (out_holder_address) *out_holder_address = good_address;
      return XIAO_OTA_PAIR_DAMAGED;
    }
    /* `adopt_candidate`, when set by binding_ok(), means the ambiguous
     * (bad) record is a positively-bound CONTINUATION of the trusted
     * sibling whose own (possibly more advanced) facts must dominate --
     * never a harmless, safely-discardable preparation write. Use its
     * content instead of the sibling's, and report ITS physical address
     * as the current holder so the next persist_*() naturally targets
     * the sibling's (now-superseded) slot, exactly like the ordinary
     * both-valid case above. */
    memcpy(out, adopt_candidate ? bad : good, size);
    if (out_holder_address) {
      *out_holder_address = adopt_candidate ? bad_address : good_address;
    }
    return XIAO_OTA_PAIR_FOUND;
  }

  /* Neither slot validates via valid() (exact commit marker). Before
   * falling back to independently checking each slot's own safety in
   * isolation (below), check whether BOTH classify as BODY_ONLY (fully
   * self-consistent body/CRC, just a non-exact marker on each side --
   * e.g. bit rot independently decaying both slots' markers back to
   * erased while a genuine in-flight retry's two most recent physical
   * writes, one per slot, both remain durably intact). When that is
   * true, the two records CAN be compared directly against each other,
   * exactly like the both-exact-valid case above, using body_valid's
   * self-consistency itself as proof each was genuinely, durably
   * written -- there being no single `good` side is exactly the
   * degenerate case ordinary retries continuously produce (each
   * persist_*() alternates slots), not evidence of unrelated debris.
   * The newer of the two (by sequence) must still positively prove it
   * is a legitimate continuation of the older via binding_ok() (full
   * immutable-identity agreement, the same proof a single ambiguous
   * candidate needs against a trusted sibling) before being trusted;
   * if that proof fails, this reconciliation is abandoned and control
   * falls through to the ordinary independent per-slot handling below,
   * never silently promoted on classification alone. */
  if (body_valid != NULL &&
      classify_ambiguous_record(a, size, body_valid) ==
          XIAO_OTA_EVIDENCE_BODY_ONLY &&
      classify_ambiguous_record(b, size, body_valid) ==
          XIAO_OTA_EVIDENCE_BODY_ONLY) {
    uint32_t a_sequence, b_sequence;
    const void *older = a, *newer = b;
    uint32_t newer_address = b_address;
    memcpy(&a_sequence, (const uint8_t *)a + 8, sizeof(a_sequence));
    memcpy(&b_sequence, (const uint8_t *)b + 8, sizeof(b_sequence));
    if ((int32_t)(a_sequence - b_sequence) > 0) {
      older = b;
      newer = a;
      newer_address = a_address;
    }
    if (binding_ok != NULL) {
      bool adopt_candidate = false;
      if (binding_ok(newer, newer_address, XIAO_OTA_EVIDENCE_BODY_ONLY, older,
                     binding_ctx, &adopt_candidate)) {
        memcpy(out, newer, size);
        if (out_holder_address) *out_holder_address = newer_address;
        return XIAO_OTA_PAIR_FOUND;
      }
    }
  }

  /* Neither slot validates. No single trustworthy sibling exists to
   * compare against here (see this function's doc-comment) -- pass
   * binding_sibling=NULL, unchanged from before. Each slot's own
   * binding_ok(), though, may still independently PROVE (e.g. via that
   * slot's own same-physical sidecar/historical-command authentication,
   * entirely independent of the other slot) that its ambiguous bytes are
   * a positively-bound, already-durable fact worth ADOPTING rather than
   * silently discarding as MISSING -- capture that per-slot outcome
   * here, exactly like the "exactly one slot validates" branch above,
   * instead of discarding it by passing out_adopt_candidate=NULL. */
  {
    bool a_adopt = false, b_adopt = false;
    a_safe = slot_safe_to_overwrite(io, a_address, a, size, commit_offset,
                                    a_sector_base, shared_tail,
                                    body_valid, binding_ok, binding_ctx, NULL,
                                    &a_io_error, &a_adopt);
    if (a_io_error) return XIAO_OTA_PAIR_IO_ERROR;
    b_safe = slot_safe_to_overwrite(io, b_address, b, size, commit_offset,
                                    b_sector_base, shared_tail,
                                    body_valid, binding_ok, binding_ctx, NULL,
                                    &b_io_error, &b_adopt);
    if (b_io_error) return XIAO_OTA_PAIR_IO_ERROR;
    if (!a_safe || !b_safe) return XIAO_OTA_PAIR_DAMAGED;
    if (a_adopt) {
      memcpy(out, a, size);
      if (out_holder_address) *out_holder_address = a_address;
      return XIAO_OTA_PAIR_FOUND;
    }
    if (b_adopt) {
      memcpy(out, b, size);
      if (out_holder_address) *out_holder_address = b_address;
      return XIAO_OTA_PAIR_FOUND;
    }
    return XIAO_OTA_PAIR_MISSING;
  }
}

/*
 * Binding context/callback for STATE's read_pair() call. Three cases:
 *
 * 1. `sibling == NULL` (read_pair()'s "neither slot validates" branch --
 *    no single already-trusted record exists to compare the ambiguous
 *    candidate against, e.g. a genuinely first-ever publication torn
 *    mid-write against a still-blank opposite slot), OR `sibling`'s own
 *    phase is TERMINAL (EMPTY/CONFIRMED/FAILED -- xiao_ota_command_
 *    acceptable_phase() is reused here as exactly that test). A
 *    terminal sibling has no transaction of its own still open to
 *    continue, so ANY ambiguous candidate here can only be a fresh
 *    admission's own in-flight first write, never a retry of the
 *    sibling's (already-finished) transaction -- the ONLY available
 *    proof is therefore the currently visible, structurally-decoded,
 *    signed install command: the candidate's transaction_nonce must
 *    match it exactly. A nonce that does not match (or no command
 *    visible at all this boot) proves nothing about why this ambiguous
 *    record exists and must fail closed.
 *
 * 2. `sibling` is itself mid-transaction (BACKUP_COPYING/INSTALLING/
 *    TRIAL_BOOT -- an ACTIVE phase). Since a new command can only ever
 *    be admitted while phase is terminal, an ambiguous candidate here
 *    can only be a continuation of THIS SAME transaction, never an
 *    independent new one -- but nonce agreement ALONE is not sufficient
 *    proof of that: the command's nonce stays identical across EVERY
 *    boot of the SAME transaction, so it cannot by itself distinguish
 *    "genuinely still in flight" from "already durably advanced
 *    further, then corrupted". This requires full immutable-identity
 *    agreement instead -- every field a legitimate persist_state()
 *    rewrite of the SAME transaction always carries forward unchanged:
 *    transaction_nonce, candidate_counter, candidate_hash_sha256, the
 *    old/backup active_image_extent and its backup_hash_sha256, and the
 *    previous_bank_0/_crc/_size triad. Any disagreement there can only
 *    mean this is an UNRELATED record (a different transaction, or
 *    foreign debris), never a plausible continuation of the trusted
 *    sibling -- refuse.
 *
 *    One specific delta needs an EXTRA, narrower check beyond plain
 *    identity agreement: a candidate claiming a HIGHER trial_attempts
 *    than a sibling already in XIAO_OTA_PHASE_TRIAL_BOOT. Durable bytes
 *    alone cannot tell whether that candidate's OWN watchdog cycle was
 *    ever actually armed before the tear/bit-rot that left its marker
 *    ambiguous -- but a legitimate write can only EVER advance
 *    trial_attempts by exactly +1 per persist_state() call (the boot
 *    loop always does a single `trial_attempts++`), so any candidate
 *    whose trial_attempts is NOT exactly sibling->trial_attempts + 1
 *    cannot be a genuine single-write continuation of the sibling at
 *    all (e.g. forged/fabricated debris jumping several counts ahead)
 *    and must be refused outright.
 *
 *    A candidate at EXACTLY sibling->trial_attempts + 1, though, is
 *    adopted (its facts -- including the higher trial_attempts --
 *    dominate the sibling's, never silently discarded/reverted): the
 *    approved posture here is to conservatively "burn" the one
 *    possibly-already-granted watchdog cycle for that adopted value
 *    without an explicit extra bookkeeping step, by simply adopting it
 *    and letting the existing unconditional TRIAL_BOOT increment path
 *    take over from there. That path always durably re-persists the
 *    record with trial_attempts advanced one MORE step and grants
 *    start_trial_watchdog() exactly once for THAT fresh, never-before-
 *    durable value -- it never re-invokes start_trial_watchdog() for
 *    the adopted (possibly already-armed) value itself. This bounds
 *    the total watchdog grants across any resumed-ambiguity boot to at
 *    most one, regardless of whether the ambiguous record was actually
 *    a genuine in-flight tear or an already-armed, later-corrupted one.
 *
 *    This positively-bound continuation case (sibling non-NULL and
 *    ACTIVE) additionally reports `*out_adopt = true`: its facts must
 *    dominate/replace the sibling's in the resolved record (never be
 *    silently discarded back to the sibling's older values), which is
 *    exactly what lets the caller durably preserve the higher
 *    trial_attempts fact instead of losing it. The fresh-admission
 *    case (sibling NULL or TERMINAL) leaves `*out_adopt` at its default
 *    false: an early, not-yet-fully-authenticated write of a BRAND NEW
 *    transaction carries no fact worth preserving over simply letting
 *    the next boot re-drive the same (idempotent) admission from
 *    scratch against the still-intact terminal sibling.
 *
 * `evidence` distinguishes what the candidate's OWN bytes can prove
 * (see classify_ambiguous_record()'s doc-comment): BODY_ONLY means the
 * candidate's fields (including transaction_nonce) are self-consistent
 * and trustworthy data, just not yet exactly-committed -- case 1 uses
 * them as-is. UNPROVABLE means NO field here is trustworthy (the body
 * itself fails CRC): in case 1 (fresh admission, sibling terminal/NULL)
 * this is still harmless to treat as safe-to-discard unconditionally --
 * no confirmed fact is ever at risk for a not-yet-admitted transaction,
 * so relying on a possibly-still-unwritten nonce field would only risk
 * a spurious, inconsequential recovery, never a missed regression. In
 * case 2 (active sibling, a real in-flight transaction with durable
 * facts worth protecting), UNPROVABLE can never positively bind to
 * anything and always refuses outright, before even attempting the
 * identity-field comparison (which would almost certainly fail anyway
 * over corrupt bytes, but must never be relied upon to do so).
 */
static void hash_command_digest(const xiao_ota_command_any_t *any,
                                uint8_t digest[32]);
static xiao_ota_pair_status_t classify_sidecar_slot(
    const xiao_ota_io_t *io, uint32_t sidecar_address,
    uint32_t owning_state_sector_base, bool require_unambiguous,
    xiao_ota_settings_sidecar_t *out);

typedef struct {
  bool have_command;
  uint64_t expected_transaction_nonce;
  const xiao_ota_io_t *io;
  const xiao_ota_command_any_t *command_a;
  const xiao_ota_command_any_t *command_b;
  bool command_a_valid;
  bool command_b_valid;
} state_ambiguous_binding_ctx_t;

/* Raw transaction_nonce field, valid for either command wire version --
 * both xiao_ota_command_t (v1) and xiao_ota_command_v2_t (v2) share the
 * identical magic/record_version/record_bytes/sequence/transaction_nonce
 * prefix (see their declarations), so this reads correctly regardless of
 * which union member actually applies. */
static uint64_t raw_command_transaction_nonce(const xiao_ota_command_any_t *any) {
  uint64_t nonce;
  memcpy(&nonce, (const uint8_t *)any + 12, sizeof(nonce));
  return nonce;
}

/*
 * Historical (not necessarily currently-"live"/decoded) command
 * authentication for a SAME-SLOT sidecar's recorded command_digest_
 * sha256: checks BOTH raw physical command slots independently of
 * whichever one command_status/intent decoding currently prefers,
 * since a still-physically-present but since-superseded command can
 * still authenticate an EARLIER transaction's sidecar/state pair. Only
 * a slot that itself passed xiao_ota_command_any_valid() (so its bytes
 * are structurally well-formed) AND digest-matches the sidecar's
 * recorded expected_digest AND independently passes
 * command_cryptographically_and_statically_authentic() (genuine
 * Ed25519 signature verification plus the static target/role/address/
 * format/key/algorithm/capability/size/extent-bounds/device-targeting
 * policy -- see that function's doc-comment) is ever trusted here. The
 * digest match alone only proves "these exact bytes were physically
 * present, byte for byte"; it does NOT by itself prove they were ever
 * validly signed or targeted for this device -- an attacker able to
 * write arbitrary QSPI bytes could otherwise plant a digest-matching
 * but never-actually-signed/targeted record and have it treated as a
 * trusted historical fact. The counter_floor/expected_active_extent
 * context checks inside xiao_ota_install_command_policy_valid() are
 * deliberately NOT applied here (see xiao_ota_install_command_static_
 * identity_valid()'s doc-comment): those two are only meaningful
 * against THIS boot's live admission state, not a past transaction's
 * own historical validity. */
static bool historical_slot_matches_digest(
    const xiao_ota_io_t *io, const xiao_ota_command_any_t *slot,
    bool slot_valid, uint64_t transaction_nonce,
    const uint8_t expected_digest[32]) {
  uint8_t digest[32];
  if (!slot_valid || raw_command_transaction_nonce(slot) != transaction_nonce) {
    return false;
  }
  hash_command_digest(slot, digest);
  return memcmp(digest, expected_digest, 32) == 0 &&
         command_cryptographically_and_statically_authentic(io, slot);
}

static bool historical_command_matches_digest(
    const state_ambiguous_binding_ctx_t *ctx, uint64_t transaction_nonce,
    const uint8_t expected_digest[32]) {
  return historical_slot_matches_digest(ctx->io, ctx->command_a,
                                        ctx->command_a_valid,
                                        transaction_nonce, expected_digest) ||
         historical_slot_matches_digest(ctx->io, ctx->command_b,
                                        ctx->command_b_valid,
                                        transaction_nonce, expected_digest);
}

static bool state_ambiguous_binding_ok(const void *record, uint32_t address,
                                       xiao_ota_record_evidence_t evidence,
                                       const void *sibling_v,
                                       const void *ctx_v, bool *out_adopt) {
  const xiao_ota_state_t *candidate = (const xiao_ota_state_t *)record;
  const xiao_ota_state_t *sibling = (const xiao_ota_state_t *)sibling_v;
  const state_ambiguous_binding_ctx_t *ctx =
      (const state_ambiguous_binding_ctx_t *)ctx_v;
  if (sibling == NULL ||
      xiao_ota_command_acceptable_phase(true, (xiao_ota_phase_t)sibling->phase)) {
    /* Case 1: fresh admission, no durable fact at risk yet. UNPROVABLE
     * (own body fails CRC -- no field here, including transaction_nonce,
     * is trustworthy data) is unconditionally safe to discard: the next
     * boot simply re-drives the same idempotent admission from scratch.
     * BODY_ONLY's nonce IS trustworthy (CRC over the whole body,
     * including the nonce field, verifies), so it is actually compared
     * against the currently visible signed command. */
    if (evidence == XIAO_OTA_EVIDENCE_UNPROVABLE) return true;
    if (candidate->sequence <= 1) {
      /* Provably the very first physical write this device could ever
       * have made (sequence starts at 0; the first-ever persist_state()
       * call always writes sequence=1) -- no durable fact beyond the
       * still-unwritten admission itself is at risk. Trustworthy only
       * if it agrees with the currently-live signed command (the only
       * command a first-ever write could possibly have been produced
       * from); a historical/superseded command can never apply here,
       * since a sequence<=1 record cannot postdate any earlier
       * transaction. Safe to discard otherwise, unchanged from before. */
      return ctx->have_command &&
             candidate->transaction_nonce == ctx->expected_transaction_nonce;
    }
    /* sequence > 1: this candidate's OWN CRC-valid body proves genuinely
     * advanced progress (trial_attempts/phase a fresh admission's very
     * first write could never carry) even though the sibling slot is
     * itself terminal/blank right now -- e.g. the sibling was
     * independently, provably erased afterwards mid-republish. Plain
     * nonce agreement against the still-currently-visible command is
     * NOT sufficient proof by itself here: the SAME nonce is carried,
     * unchanged, across every boot of the same transaction, so it
     * cannot distinguish a genuinely-early write from an already-far-
     * advanced one later corrupted. This path deliberately does NOT
     * require candidate->transaction_nonce == ctx->expected_transaction_
     * nonce (unlike the sequence<=1 branch above): the candidate may
     * belong to an EARLIER transaction already superseded by whatever
     * command is currently "live", and historical_command_matches_
     * digest() below is expressly designed to authenticate against
     * EITHER raw physical command slot independent of which one that
     * is -- gating on ctx->expected_transaction_nonce here would make
     * that lookup unreachable for exactly the historical case it
     * exists to handle. Require independent proof instead, via this
     * candidate's OWN same-physical-slot settings sidecar (written
     * FIRST, atomically, by the exact same write_state_with_sidecar()
     * call that produced this state record) plus that sidecar's own
     * recorded command digest, checked against EITHER raw physical
     * command slot independently of whichever one is currently
     * preferred as "live" -- a since-superseded but still physically-
     * present historical command can still authenticate an earlier
     * transaction, provided it is ALSO cryptographically and statically
     * authentic in its own right (not merely digest-matched -- a digest
     * match alone only proves these exact bytes were physically
     * present, never that they were ever validly signed/targeted for
     * this device). Only when every one of these independently agrees
     * is the candidate's higher-progress facts trusted (adopted,
     * dominating the terminal/blank sibling); otherwise fail closed
     * (never silently discard a possibly-real, already-advanced fact,
     * and never silently promote an unproven one either). */
    if (ctx->io != NULL) {
      uint32_t sidecar_address = (address == XIAO_OTA_STATE_A)
                                      ? XIAO_OTA_SETTINGS_SIDECAR_A
                                      : XIAO_OTA_SETTINGS_SIDECAR_B;
      xiao_ota_settings_sidecar_t sidecar;
      if (classify_sidecar_slot(ctx->io, sidecar_address, address, true,
                               &sidecar) == XIAO_OTA_PAIR_FOUND &&
          sidecar.matching_state_sequence == candidate->sequence &&
          sidecar.transaction_nonce == candidate->transaction_nonce &&
          historical_command_matches_digest(ctx, candidate->transaction_nonce,
                                            sidecar.command_digest_sha256)) {
        if (out_adopt != NULL) *out_adopt = true;
        return true;
      }
    }
    return false;
  }
  /* Case 2: an ACTIVE sibling has real durable facts worth protecting.
   * UNPROVABLE can never positively bind to anything -- refuse before
   * even attempting the identity comparison below (which would almost
   * certainly fail anyway over corrupt bytes, but must never be relied
   * upon to do so). */
  if (evidence == XIAO_OTA_EVIDENCE_UNPROVABLE) return false;
  if (candidate->transaction_nonce != sibling->transaction_nonce ||
      candidate->candidate_counter != sibling->candidate_counter ||
      memcmp(candidate->candidate_hash_sha256, sibling->candidate_hash_sha256,
             32) != 0 ||
      candidate->active_image_extent != sibling->active_image_extent ||
      memcmp(candidate->backup_hash_sha256, sibling->backup_hash_sha256,
             32) != 0 ||
      candidate->previous_bank_0 != sibling->previous_bank_0 ||
      candidate->previous_bank_0_crc != sibling->previous_bank_0_crc ||
      candidate->previous_bank_0_size != sibling->previous_bank_0_size) {
    return false;
  }
  if (sibling->phase == XIAO_OTA_PHASE_TRIAL_BOOT &&
      (uint32_t)candidate->trial_attempts != (uint32_t)sibling->trial_attempts + 1u) {
    /* Not the one physically-possible single-write delta -- see this
     * function's doc-comment above. */
    return false;
  }
  if (out_adopt != NULL) *out_adopt = true;
  return true;
}

/*
 * Binding context/callback for FLOOR's read_pair() call: an ambiguous
 * losing floor slot is safe to discard ONLY if its own identity fields
 * (confirmed_counter_floor, confirmed_hash_sha256) exactly match the
 * ALREADY independently-trusted STATE record's candidate identity --
 * proving it can only be this exact, currently in-flight transaction's
 * own not-yet-durable persist_floor() write, never an unrelated or
 * previously-durable (then corrupted) floor record for some other
 * counter value. A floor whose counter/hash disagree with the current
 * state has no such proof and must fail closed (DAMAGED): silently
 * discarding it could resurrect a stale, superseded floor as if it were
 * still authoritative (the exact regression this defends against).
 *
 * Counter/hash agreement ALONE is still not sufficient, though: the
 * floor-advancing write that finalizes a CONFIRMED transaction carries
 * the SAME counter/hash as that transaction's STATE record forever
 * afterwards, on every later boot, long after the floor write itself
 * durably completed. So an ambiguous floor that merely agrees with a
 * now-TERMINAL (CONFIRMED/FAILED/EMPTY) state's identity is NOT
 * evidence of a still-pending, not-yet-durable write -- any genuinely
 * in-flight persist_floor() write for that transaction could only have
 * existed on an EARLIER boot, resolved before this one. Treating such
 * agreement as proof on a later boot would let bit rot of an
 * already-durable, already-superseded floor value silently resurrect
 * it. Require the bound STATE record to still be in an ACTIVE
 * (non-terminal) phase -- i.e. an in-flight transaction whose own
 * floor-advance write could plausibly still be pending -- before
 * trusting this agreement at all.
 *
 * `evidence` is still consulted explicitly even though the counter/hash
 * comparison below would, in virtually every real case, already fail on
 * its own for an UNPROVABLE candidate (corrupt bytes rarely coincide
 * with the exact expected counter/hash) -- but "almost certainly fails
 * anyway" is never relied upon as a safety proof: UNPROVABLE refuses
 * outright, unconditionally, before the field comparison runs.
 */
typedef struct {
  bool have_state;
  bool state_phase_active;
  uint32_t state_candidate_counter;
  const uint8_t *state_candidate_hash_sha256;
} floor_ambiguous_binding_ctx_t;

static bool floor_ambiguous_binding_ok(const void *record, uint32_t address,
                                       xiao_ota_record_evidence_t evidence,
                                       const void *sibling_v,
                                       const void *ctx_v, bool *out_adopt) {
  const xiao_ota_floor_t *candidate = (const xiao_ota_floor_t *)record;
  const floor_ambiguous_binding_ctx_t *ctx =
      (const floor_ambiguous_binding_ctx_t *)ctx_v;
  (void)sibling_v;
  (void)out_adopt;
  (void)address;
  if (evidence == XIAO_OTA_EVIDENCE_UNPROVABLE) return false;
  return ctx->have_state && ctx->state_phase_active &&
         candidate->confirmed_counter_floor == ctx->state_candidate_counter &&
         memcmp(candidate->confirmed_hash_sha256,
                ctx->state_candidate_hash_sha256, 32) == 0;
}


/*
 * Binding context/callback for read_paired_sidecar()'s classify_sidecar_
 * slot() call ONLY (never the independent per-window orphan
 * classification -- see that call site's own comment for why the two
 * contexts need opposite defaults). The sidecar physically shares one
 * erase unit with its accompanying STATE record and is written FIRST,
 * fully, by write_state_with_sidecar() before that SAME call ever
 * attempts the state write -- so if the co-located STATE record's own
 * marker reads as the exact, fully-committed value (which is exactly
 * why it is the currently-trusted winning state passed in here), the
 * ENTIRE write_state_with_sidecar() call that produced it must have run
 * to completion, meaning THIS exact sidecar necessarily ALSO reached
 * its own exact commit marker at that same moment. Any ambiguity found
 * in it now can only be later, independent corruption of an already-
 * durable record -- there is no "still legitimately in flight" reading
 * available here at all, unlike every other ambiguous-record case in
 * this file. This callback therefore always refuses (never vouches for
 * safety) whenever it is invoked at all, regardless of `evidence`.
 */
static bool sidecar_paired_ambiguous_never_safe(const void *record,
                                                uint32_t address,
                                                xiao_ota_record_evidence_t evidence,
                                                const void *sibling_v,
                                                const void *ctx_v,
                                                bool *out_adopt) {
  (void)record;
  (void)address;
  (void)evidence;
  (void)sibling_v;
  (void)ctx_v;
  (void)out_adopt;
  return false;
}


/*
 * Classifies ONE physical sidecar slot on its own: FOUND (structurally
 * valid, committed record -- trustworthy regardless of whether anything
 * currently pairs with it), MISSING (genuinely never written -- safe to
 * overwrite), DAMAGED (neither: non-blank debris that never validly
 * committed, e.g. a torn write or bit rot), or IO_ERROR. `owning_state_
 * sector_base` is the STATE slot address this sidecar physically shares
 * an erase unit with (XIAO_OTA_STATE_A for SIDECAR_A, _B for _B),
 * forwarded to slot_safe_to_overwrite()'s shared_tail tail scan.
 *
 * `require_unambiguous`, when true, additionally refuses to ever treat
 * a reachable-marker-but-fully-self-consistent-body slot as safe
 * (MISSING) -- see sidecar_paired_ambiguous_never_safe()'s doc-comment;
 * used ONLY by read_paired_sidecar(). The independent per-window orphan
 * classification (sidecar_orphan_status()) passes false: a sidecar
 * physically colocated with a genuinely BLANK (not yet won) state slot
 * is wiped by the SAME sector erase that would have to precede any
 * stale prior commit there, so an ambiguous body-valid sidecar in THAT
 * context can only be this exact attempt's own in-flight write (or, if
 * it fails sidecar_orphan_status()'s own separate nonce/digest/snapshot
 * binding, is still forced to recovery there regardless).
 */
static xiao_ota_pair_status_t classify_sidecar_slot(
    const xiao_ota_io_t *io, uint32_t sidecar_address,
    uint32_t owning_state_sector_base, bool require_unambiguous,
    xiao_ota_settings_sidecar_t *out) {
  bool io_error;
  if (!io->qspi_read(io->ctx, sidecar_address, out, sizeof(*out))) {
    return XIAO_OTA_PAIR_IO_ERROR;
  }
  if (xiao_ota_settings_sidecar_valid(out)) return XIAO_OTA_PAIR_FOUND;
  {
    bool safe = slot_safe_to_overwrite(
        io, sidecar_address, out, sizeof(*out),
        offsetof(xiao_ota_settings_sidecar_t, commit_marker),
        owning_state_sector_base, true,
        require_unambiguous
            ? (bool (*)(const void *))xiao_ota_settings_sidecar_body_valid
            : NULL,
        require_unambiguous ? sidecar_paired_ambiguous_never_safe : NULL,
        NULL, NULL, &io_error, NULL);
    if (io_error) return XIAO_OTA_PAIR_IO_ERROR;
    return safe ? XIAO_OTA_PAIR_MISSING : XIAO_OTA_PAIR_DAMAGED;
  }
}

/*
 * Reads the settings sidecar from the ONE physical slot paired with the
 * already-determined winning STATE record -- XIAO_OTA_STATE_A pairs
 * exclusively with XIAO_OTA_SETTINGS_SIDECAR_A, XIAO_OTA_STATE_B
 * exclusively with XIAO_OTA_SETTINGS_SIDECAR_B -- rather than
 * independently picking whichever sidecar slot happens to hold the
 * newest-looking/best-formed record across BOTH physical sectors (what a
 * plain read_pair() call here would do). A fully-committed sidecar
 * prepared for the OTHER (not-yet-winning) state slot is expected,
 * harmless debris of an in-progress NEXT transaction's publish that was
 * torn before its own state record ever committed; treating it as though
 * it belonged to the CURRENTLY winning, still fully-intact state record
 * -- merely because it is newer or structurally cleaner -- would wrongly
 * force_recovery() an otherwise perfectly valid, already-durable
 * transaction. `state_slot_address` MUST be the exact address read_pair()
 * reported as the winning STATE slot (its `out_holder_address`), so this
 * is only ever meaningful once a winning state record is known to exist.
 */
static xiao_ota_pair_status_t read_paired_sidecar(
    const xiao_ota_io_t *io, uint32_t state_slot_address,
    xiao_ota_settings_sidecar_t *out) {
  uint32_t sidecar_address = (state_slot_address == XIAO_OTA_STATE_A)
                                 ? XIAO_OTA_SETTINGS_SIDECAR_A
                                 : XIAO_OTA_SETTINGS_SIDECAR_B;
  return classify_sidecar_slot(io, sidecar_address, state_slot_address, true,
                               out);
}


/*
 * Body first (with the commit-marker bytes still erased in this write),
 * read back and verify the body landed correctly, THEN program the commit
 * marker as a separate write. Finally, re-read the WHOLE record (not just
 * the marker word) and require it to pass the SAME `valid()` a reader
 * will apply on the next boot -- not only a byte-for-byte match against
 * the local copy, but the real structural/CRC check, so a write that
 * "looks" committed but a reader would not actually trust is caught here,
 * not discovered later. This function returns false on any failure
 * (either write, any readback mismatch, or the final valid() check) and
 * never partially claims success -- but a false return here does NOT
 * prove the target address ends up empty/untrusted: the marker write may
 * have already durably landed before a LATER step (the final whole-record
 * readback or valid() check) failed, e.g. on a transient read glitch, in
 * which case a genuinely new, valid record may already exist at
 * `target_address`. Callers must not assume "the other slot's previous
 * record is the sole survivor" from this return value alone; the next
 * boot's read_pair() always re-reads and re-validates BOTH physical slots
 * independently from flash and picks whichever genuinely validates and is
 * newest, regardless of what happened in this call. A false return only
 * means "this call cannot vouch the write is durably confirmed" -- the
 * caller's job is to stop before trusting or building on it this boot,
 * not to assume it never happened.
 *
 * Does NOT erase -- callers erase the target sector themselves
 * (write_record() below for the single-record-per-sector case,
 * write_state_with_sidecar() for the two-record-in-one-sector case) so a
 * sector holding more than one record is erased exactly ONCE per
 * transition, never once per record written into it.
 */
static bool write_body_then_marker(const xiao_ota_io_t *io, uint32_t target_address,
                                   void *record, size_t record_size,
                                   size_t crc_offset, size_t commit_offset,
                                   uint32_t sequence, bool (*valid)(const void *)) {
  uint32_t crc;
  uint32_t marker = XIAO_OTA_COMMIT_MARKER;
  uint8_t *bytes = (uint8_t *)record;

  memcpy(bytes + 8, &sequence, sizeof(sequence));
  memset(bytes + commit_offset, 0xFF, sizeof(marker));
  crc = xiao_ota_crc32(record, crc_offset);
  memcpy(bytes + crc_offset, &crc, sizeof(crc));

  if (!io->qspi_write(io->ctx, target_address, record, commit_offset)) return false;
  if (!io->qspi_read(io->ctx, target_address, verify_buffer, commit_offset)) return false;
  if (memcmp(verify_buffer, record, commit_offset) != 0) return false;

  if (!io->qspi_write(io->ctx, target_address + commit_offset, &marker, sizeof(marker))) {
    return false;
  }
  memcpy(bytes + commit_offset, &marker, sizeof(marker));

  if (!io->qspi_read(io->ctx, target_address, verify_buffer, record_size)) return false;
  if (memcmp(verify_buffer, record, record_size) != 0) return false;
  if (!valid(verify_buffer)) return false;
  return true;
}

/*
 * Single-record-per-sector writer (command/floor pairs): erase once, then
 * write_body_then_marker(). See the doc-comment previously here (now on
 * write_body_then_marker() above) for the failure/durability semantics --
 * unchanged by this split.
 */
static bool write_record(const xiao_ota_io_t *io, uint32_t target_address,
                         void *record, size_t record_size, size_t crc_offset,
                         size_t commit_offset, uint32_t sequence,
                         bool (*valid)(const void *)) {
  if (!io->qspi_erase_sector(io->ctx, target_address)) return false;
  return write_body_then_marker(io, target_address, record, record_size,
                                crc_offset, commit_offset, sequence, valid);
}

/*
 * Two-record-per-sector writer for the state sector: ONE erase of the
 * target (opposite) state sector, sidecar body+marker committed FIRST at
 * XIAO_OTA_SETTINGS_SIDECAR_OFFSET, unchanged state-v1 body+marker
 * committed SECOND at the sector base -- never two separate erase-owning
 * write_record() calls against the same sector. Both records use the SAME
 * `sequence` value (xiao_ota_settings_sidecar_t.matching_state_sequence
 * sits at the identical byte offset as every other record's `sequence`
 * field, so the shared write_body_then_marker() patches it identically).
 * A failure after the sidecar commits but before the state commits is
 * exactly the torn case the boot-time sidecar/state sequence-match check
 * (xiao_ota_boot_process_io()) is designed to detect on the next boot --
 * see its call site for what happens then.
 */
static bool write_state_with_sidecar(const xiao_ota_io_t *io, uint32_t target_address,
                                     xiao_ota_state_t *state,
                                     xiao_ota_settings_sidecar_t *sidecar,
                                     uint32_t sequence) {
  state->magic = XIAO_OTA_RECORD_MAGIC;
  state->record_version = XIAO_OTA_FORMAT_VERSION;
  state->record_bytes = sizeof(*state);
  sidecar->magic = XIAO_OTA_SIDECAR_MAGIC;
  sidecar->record_version = XIAO_OTA_FORMAT_VERSION;
  sidecar->record_bytes = sizeof(*sidecar);

  if (!io->qspi_erase_sector(io->ctx, target_address)) return false;
  if (!write_body_then_marker(io, target_address + XIAO_OTA_SETTINGS_SIDECAR_OFFSET,
                             sidecar, sizeof(*sidecar),
                             offsetof(xiao_ota_settings_sidecar_t, crc32),
                             offsetof(xiao_ota_settings_sidecar_t, commit_marker),
                             sequence,
                             (bool (*)(const void *))xiao_ota_settings_sidecar_valid)) {
    return false;
  }
  return write_body_then_marker(io, target_address, state, sizeof(*state),
                                offsetof(xiao_ota_state_t, crc32),
                                offsetof(xiao_ota_state_t, commit_marker),
                                sequence,
                                (bool (*)(const void *))xiao_ota_state_valid);
}

/*
 * `*slot_address` is the address currently holding the trusted record for
 * this pair (from the boot-time read_pair() call, or the previous
 * successful persist through this same function). The next write ALWAYS
 * targets the genuinely OTHER physical slot -- derived from that known
 * address, never from the sequence number's parity alone, so a record
 * whose sequence happens to be odd-in-A (or any other parity/location
 * combination a bug or unusual history could produce) is never mistaken
 * for "must be in the other slot" and erased out from under a reader that
 * would otherwise still trust it. `*slot_address` is only updated after a
 * fully successful write (including the final valid() readback above).
 * Always writes the accompanying settings sidecar into the SAME sector --
 * see write_state_with_sidecar() -- so the two can never drift apart.
 */
static bool persist_state(const xiao_ota_io_t *io, xiao_ota_state_t *state,
                          xiao_ota_settings_sidecar_t *sidecar,
                          uint32_t *slot_address) {
  uint32_t target;
  /* A sequence at UINT32_MAX must never silently wrap to 0 on the next
   * write -- that could resurrect a long-stale record's tie-break
   * priority. Fail explicitly, before any erase, instead. */
  if (state->sequence == UINT32_MAX) return false;
  target = (*slot_address == XIAO_OTA_STATE_A) ? XIAO_OTA_STATE_B : XIAO_OTA_STATE_A;
  if (!write_state_with_sidecar(io, target, state, sidecar, state->sequence + 1)) {
    return false;
  }
  *slot_address = target;
  return true;
}

/* Forward declaration: defined further below (with its full doc-comment)
 * alongside floor_activation_receipt_binds_floor()/floor_role_evidence_
 * ok(), which both also use it -- persist_floor() needs it earlier in
 * file order to decide what is safe to propagate/erase. */
static bool floor_activation_receipt_identity_role_ok(
    const xiao_ota_io_t *io, const xiao_ota_floor_activation_receipt_t *r);

/* Shared by persist_floor() below: reads one physical receipt window
 * into caller-supplied `window_out` (so the raw bytes stay available
 * for a later propagate/readback write) and reports whether it
 * independently identity/role-verifies, collapsing what would
 * otherwise be two duplicated read+parse+verify sequences (one per
 * window) into a single shared call site. */
static bool floor_activation_window_verify_into(
    const xiao_ota_io_t *io, uint32_t address, uint8_t *window_out,
    bool *out_read_ok) {
  /* window_out is always the caller's own word-aligned
   * XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES buffer (every call site
   * declares it `__attribute__((aligned(4)))`), and the receipt's wire
   * layout is read byte-for-byte with no transform -- reinterpreting
   * the leading XIAO_OTA_FLOOR_ACTIVATION_TOTAL_BYTES in place avoids a
   * second, otherwise-pointless full-receipt stack copy on every call. */
  *out_read_ok = io->qspi_read(io->ctx, address, window_out,
                               XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES);
  if (!*out_read_ok) return false;
  return floor_activation_receipt_identity_role_ok(
      io, (const xiao_ota_floor_activation_receipt_t *)(const void *)window_out);
}

static bool persist_floor(const xiao_ota_io_t *io, xiao_ota_floor_t *floor,
                          uint32_t *slot_address) {
  uint32_t target;
  uint32_t source;
  uint8_t source_window[XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES]
      __attribute__((aligned(4)));
  uint8_t target_window[XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES]
      __attribute__((aligned(4)));
  bool source_read_ok, target_read_ok, source_verified, target_verified;
  if (floor->sequence == UINT32_MAX) return false;
  source = *slot_address;
  target = (source == XIAO_OTA_FLOOR_A) ? XIAO_OTA_FLOOR_B : XIAO_OTA_FLOOR_A;
  /* The genesis activation-receipt window shares its physical sector
   * with this exact floor record body (XIAO_OTA_FLOOR_ACTIVATION_A/B ==
   * XIAO_OTA_FLOOR_A/B + 0x100 -- see xiao_ota_layout.h), so the
   * write_record() erase below would otherwise silently destroy
   * whatever genesis receipt the TARGET slot was carrying. Ordinary
   * ping-pong eventually revisits every slot as a future erase target,
   * so after as few as two advances TARGET may be the ONLY slot still
   * holding a verifying receipt (e.g. a prior advance's best-effort
   * carry-forward write into what is now SOURCE never durably landed).
   * Erasing TARGET first in that situation would permanently destroy
   * this device's sole durable, cryptographically verifiable proof of
   * its originally-commissioned role -- see floor_role_evidence_ok()'s
   * doc-comment for why that evidence must stay available at every
   * floor value, not only genesis. So: read BOTH windows and determine
   * which (if either) currently verifies BEFORE touching either slot.
   * If only TARGET verifies, durably program+readback those exact
   * bytes into SOURCE's window FIRST (SOURCE is never erased by this
   * call, and its window is only ever written here while still in its
   * post-erase blank state from a prior round, so this write is always
   * NOR-safe) and fail this advance closed, with NEITHER slot yet
   * erased, if that propagation does not itself durably confirm --
   * never erase TARGET while SOURCE remains unconfirmed. Only once
   * SOURCE is confirmed to independently hold the evidence is it safe
   * to erase TARGET and commit the new floor body into it. */
  source_verified = floor_activation_window_verify_into(
      io, source + XIAO_OTA_FLOOR_ACTIVATION_WINDOW_OFFSET, source_window,
      &source_read_ok);
  target_verified = floor_activation_window_verify_into(
      io, target + XIAO_OTA_FLOOR_ACTIVATION_WINDOW_OFFSET, target_window,
      &target_read_ok);
  if (target_verified && !source_verified) {
    if (!(source_read_ok &&
         memcmp(source_window, target_window, sizeof(target_window)) == 0)) {
      if (!io->qspi_write(io->ctx,
                         source + XIAO_OTA_FLOOR_ACTIVATION_WINDOW_OFFSET,
                         target_window, sizeof(target_window))) {
        return false;
      }
      if (!io->qspi_read(io->ctx,
                        source + XIAO_OTA_FLOOR_ACTIVATION_WINDOW_OFFSET,
                        source_window, sizeof(source_window)) ||
         memcmp(source_window, target_window, sizeof(target_window)) != 0) {
        return false;
      }
    }
    source_verified = true;
  }
  floor->magic = XIAO_OTA_FLOOR_MAGIC;
  floor->record_version = XIAO_OTA_FORMAT_VERSION;
  floor->record_bytes = sizeof(*floor);
  /* Single erase of the target sector, then TWO separate writes into it
   * -- the receipt window FIRST, the floor body+marker SECOND -- never
   * a second erase-owning call after the receipt lands. This mirrors
   * write_state_with_sidecar()'s own "one erase, two body writes into
   * the same sector" shape, but in the opposite priority order: by the
   * time this point is reached, SOURCE is already confirmed to durably
   * hold the role evidence (either it always did, or the propagation
   * above just confirmed it), so TARGET's own in-sector receipt copy is
   * no longer safety-critical -- it only exists to make TARGET self-
   * sufficient for a FUTURE advance's own propagate-before-erase check.
   * It is still written and read back BEFORE the floor body/marker
   * (never after), so a target floor record can never durably commit
   * while this sector's own receipt copy is left unwritten or
   * unconfirmed: a crash between the receipt write and the floor
   * write leaves TARGET erased/invalid (SOURCE, never touched, is still
   * the one read_pair() trusts next boot), not a "committed floor,
   * missing receipt" state. */
  if (!io->qspi_erase_sector(io->ctx, target)) return false;
  if (source_verified) {
    if (!io->qspi_write(io->ctx,
                        target + XIAO_OTA_FLOOR_ACTIVATION_WINDOW_OFFSET,
                        source_window, sizeof(source_window)) ||
       !io->qspi_read(io->ctx,
                      target + XIAO_OTA_FLOOR_ACTIVATION_WINDOW_OFFSET,
                      target_window, sizeof(target_window)) ||
       memcmp(target_window, source_window, sizeof(source_window)) != 0) {
      return false;
    }
  }
  if (!write_body_then_marker(io, target, floor, sizeof(*floor),
                             offsetof(xiao_ota_floor_t, crc32),
                             offsetof(xiao_ota_floor_t, commit_marker),
                             floor->sequence + 1,
                             (bool (*)(const void *))xiao_ota_floor_valid)) {
    return false;
  }
  *slot_address = target;
  return true;
}

/*
 * The boot state machine below (xiao_ota_boot_process_io) calls
 * persist_state()/persist_floor() at many decision points, and in every
 * single case a failed persist is handled identically: fail closed by
 * forcing recovery and returning immediately, never falling through to
 * any further mutation. Wrapping that always-identical two-step
 * "persist or recover" idiom here (rather than repeating the inline
 * `if (!persist_state(...)) { io->force_recovery(io->ctx); return; }`
 * at each of the many call sites) is a pure size/duplication reduction:
 * it changes nothing about *when* recovery is forced or what state is
 * left behind, only how many times the identical machine code for doing
 * so appears in the binary.
 */
static bool persist_state_or_recover(const xiao_ota_io_t *io,
                                     xiao_ota_state_t *state,
                                     xiao_ota_settings_sidecar_t *sidecar,
                                     uint32_t *slot_address) {
  if (!persist_state(io, state, sidecar, slot_address)) {
    io->force_recovery(io->ctx);
    return false;
  }
  return true;
}

static bool persist_floor_or_recover(const xiao_ota_io_t *io,
                                     xiao_ota_floor_t *floor,
                                     uint32_t *slot_address) {
  if (!persist_floor(io, floor, slot_address)) {
    io->force_recovery(io->ctx);
    return false;
  }
  return true;
}

/*
 * Host-safe byte-for-byte mirror of Nordic SDK11's bootloader_settings_t
 * (bootloader_dfu/bootloader_types.h): bank_0/bank_0_crc/bank_1 (16-bit
 * each), the compiler's own natural 2-byte pad before the first 32-bit
 * member, then bank_0_size/sd_image_size/bl_image_size/app_image_size/
 * sd_image_start (32-bit each) -- 28 bytes total on every ABI this
 * project targets (verified below). Defined locally (not by including
 * the Nordic SDK header) so this settings codec has no SDK dependency
 * and links into the native host test build exactly like the rest of
 * the portable transaction processor.
 */
typedef struct {
  uint16_t bank_0;
  uint16_t bank_0_crc;
  uint16_t bank_1;
  uint16_t reserved_pad;
  uint32_t bank_0_size;
  uint32_t sd_image_size;
  uint32_t bl_image_size;
  uint32_t app_image_size;
  uint32_t sd_image_start;
} xiao_ota_settings_raw_t;

/*
 * Used only when NEITHER physical state slot is a winner (a genuinely
 * blank device, or one whose only records so far are never-committed
 * prep) -- there is no winning state record to pair a sidecar against,
 * but that must never be read as "therefore ignore both sidecar windows
 * unconditionally". Each physical sidecar slot is independently
 * classified: a genuinely blank slot is trivially safe to ignore.
 *
 * A slot that is structurally valid and committed (FOUND) is NOT
 * automatically harmless just because its own CRC checks out: CRC32 is
 * an integrity check, not an authenticity one, so a structurally
 * "clean" sidecar could equally be leftover debris from an ENTIRELY
 * different, no-longer-visible transaction (its own command record long
 * since superseded) as it could be the genuine, harmless "next
 * transaction's publish was torn before its own state record ever
 * committed" cut. The only way to tell those apart with no state record
 * to pair against is to require the orphan to PROVABLY correspond to
 * the transaction that would legitimately be prepared for THIS device
 * right now: its recorded sequence must equal the exact next sequence a
 * genuine first admission would use, its transaction_nonce and
 * command_digest_sha256 must match the CURRENTLY visible signed command
 * exactly (`have_expected_command` false -- no command visible this
 * boot at all -- can therefore never be proven, and must fail closed),
 * and its frozen bank-0 snapshot triad must match a FRESH read of the
 * settings page taken right now (nothing has changed since a genuinely
 * torn first-publication attempt would have captured it). A FOUND slot
 * that fails ANY of these is unexplained, unprovable debris and reports
 * DAMAGED, exactly like structurally-invalid non-blank data; only a
 * slot that is blank OR provably bound is safe to treat as harmless
 * prep, out is left zeroed either way (the discarded orphan's content is
 * never reused for anything).
 */
static xiao_ota_pair_status_t sidecar_orphan_status(
    const xiao_ota_io_t *io, uint32_t expected_state_sequence,
    bool have_expected_command, const uint8_t expected_command_digest[32],
    uint64_t expected_transaction_nonce,
    const xiao_ota_settings_raw_t *expected_snapshot,
    xiao_ota_settings_sidecar_t *out) {
  xiao_ota_settings_sidecar_t sidecar_a, sidecar_b;
  xiao_ota_pair_status_t status_a =
      classify_sidecar_slot(io, XIAO_OTA_SETTINGS_SIDECAR_A, XIAO_OTA_STATE_A,
                            false, &sidecar_a);
  xiao_ota_pair_status_t status_b;
  if (status_a == XIAO_OTA_PAIR_IO_ERROR) return XIAO_OTA_PAIR_IO_ERROR;
  status_b = classify_sidecar_slot(io, XIAO_OTA_SETTINGS_SIDECAR_B,
                                   XIAO_OTA_STATE_B, false, &sidecar_b);
  if (status_b == XIAO_OTA_PAIR_IO_ERROR) return XIAO_OTA_PAIR_IO_ERROR;
  if (status_a == XIAO_OTA_PAIR_DAMAGED || status_b == XIAO_OTA_PAIR_DAMAGED) {
    return XIAO_OTA_PAIR_DAMAGED;
  }
  {
    const xiao_ota_settings_sidecar_t *found[2];
    size_t found_count = 0;
    size_t i;
    if (status_a == XIAO_OTA_PAIR_FOUND) found[found_count++] = &sidecar_a;
    if (status_b == XIAO_OTA_PAIR_FOUND) found[found_count++] = &sidecar_b;
    for (i = 0; i < found_count; ++i) {
      const xiao_ota_settings_sidecar_t *s = found[i];
      xiao_ota_settings_raw_t snapshot;
      bool bound;
      memcpy(&snapshot, s->original_settings_raw, sizeof(snapshot));
      bound = have_expected_command &&
              s->matching_state_sequence == expected_state_sequence &&
              s->transaction_nonce == expected_transaction_nonce &&
              memcmp(s->command_digest_sha256, expected_command_digest, 32) == 0 &&
              snapshot.bank_0 == expected_snapshot->bank_0 &&
              snapshot.bank_0_crc == expected_snapshot->bank_0_crc &&
              snapshot.bank_0_size == expected_snapshot->bank_0_size;
      if (!bound) return XIAO_OTA_PAIR_DAMAGED;
    }
  }
  memset(out, 0, sizeof(*out));
  return XIAO_OTA_PAIR_MISSING;
}

typedef char xiao_ota_settings_raw_size_check
    [(sizeof(xiao_ota_settings_raw_t) ==
      XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE)
         ? 1
         : -1];

static bool settings_read_raw(const xiao_ota_io_t *io,
                              xiao_ota_settings_raw_t *out) {
  return io->internal_read(io->ctx, XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS, out,
                           sizeof(*out));
}

bool xiao_ota_settings_get(const xiao_ota_io_t *io,
                           xiao_ota_bank0_settings_t *out) {
  xiao_ota_settings_raw_t raw;
  if (!settings_read_raw(io, &raw)) return false;
  out->bank_0 = raw.bank_0;
  out->bank_0_crc = raw.bank_0_crc;
  out->bank_0_size = raw.bank_0_size;
  return true;
}

/*
 * Read-modify-write over the WHOLE real settings page: read the current
 * raw page first (preserving bank_1/sd_image_size/bl_image_size/
 * app_image_size/sd_image_start byte-for-byte, exactly like the SDK's own
 * settings API contract), overlay only the three fields this project
 * ever changes, then erase+program+read-back-verify the whole page --
 * the SAME erase/program/verify boundary the rest of this file's
 * internal-flash writes use, so a fault injected on
 * internal_erase_page()/internal_write() at this address exercises a
 * genuine torn-settings-page outcome instead of a hand-modelled shortcut.
 */
bool xiao_ota_settings_set(const xiao_ota_io_t *io, uint16_t bank_0,
                           uint16_t bank_0_crc, uint32_t bank_0_size) {
  xiao_ota_settings_raw_t raw;
  xiao_ota_settings_raw_t verify;
  if (!settings_read_raw(io, &raw)) return false;
  raw.bank_0 = bank_0;
  raw.bank_0_crc = bank_0_crc;
  raw.bank_0_size = bank_0_size;
  if (!io->internal_erase_page(io->ctx, XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS)) {
    return false;
  }
  if (!io->internal_write(io->ctx, XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS, &raw,
                         sizeof(raw))) {
    return false;
  }
  if (!settings_read_raw(io, &verify)) return false;
  return memcmp(&verify, &raw, sizeof(raw)) == 0;
}

/*
 * Nordic's bootloader_settings_t occupies only the first 28 bytes of its
 * 4 KiB page; the rest is never written by anything else and must always
 * read erased. internal_erase_page() erases the WHOLE 4 KiB page, so any
 * write to this page must confirm that tail is genuinely blank BEFORE
 * erasing it -- if something unexpected occupies it, this project cannot
 * assume it is safe to destroy without at least being examined, and must
 * fail closed instead of silently erasing over unknown data. Returns
 * false only on an IO failure (result then unknown, not "not blank");
 * `*out_blank` is only meaningful when this returns true. */
static bool settings_page_tail_erased(const xiao_ota_io_t *io, bool *out_blank) {
  uint32_t offset = XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE;
  *out_blank = true;
  while (offset < XIAO_OTA_INTERNAL_PAGE_SIZE) {
    uint32_t n = XIAO_OTA_INTERNAL_PAGE_SIZE - offset > COPY_CHUNK
                     ? COPY_CHUNK : XIAO_OTA_INTERNAL_PAGE_SIZE - offset;
    if (!io->internal_read(io->ctx, XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + offset,
                           io_buffer, n)) {
      return false;
    }
    if (!xiao_ota_bytes_erased(io_buffer, n)) *out_blank = false;
    offset += n;
  }
  return true;
}

/*
 * Shared low-level whole-page writer for the two frozen-base settings
 * operations below: confirms the page tail is blank (see
 * settings_page_tail_erased() above), then erase+program+read-back-
 * verify the WHOLE page from `raw` -- never a read-modify-write over
 * whatever is CURRENTLY on the page, unlike xiao_ota_settings_set()
 * above (which remains a plain current-page read-modify-write, used only
 * to provision an initial settings page before any OTA transaction
 * exists -- e.g. by native test fixtures -- where there is no frozen
 * admission-time snapshot to use instead).
 */
static bool settings_write_raw(const xiao_ota_io_t *io,
                               const xiao_ota_settings_raw_t *raw) {
  xiao_ota_settings_raw_t verify;
  bool tail_blank;
  if (!settings_page_tail_erased(io, &tail_blank)) return false;
  if (!tail_blank) return false;
  if (!io->internal_erase_page(io->ctx, XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS)) {
    return false;
  }
  if (!io->internal_write(io->ctx, XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS, raw,
                         sizeof(*raw))) {
    return false;
  }
  if (!settings_read_raw(io, &verify)) return false;
  return memcmp(&verify, raw, sizeof(*raw)) == 0;
}

/*
 * Install: derives the new settings page from the FROZEN 28-byte snapshot
 * captured once at this transaction's admission (xiao_ota_settings_sidecar_t.
 * original_settings_raw), changing ONLY bank_0/bank_0_crc/bank_0_size --
 * never re-reading "current" settings as the base, so this can never
 * silently build on a page that changed (or was damaged) since admission.
 */
static bool xiao_ota_settings_apply_bank0(
    const xiao_ota_io_t *io,
    const uint8_t base_raw[XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE],
    uint16_t bank_0, uint16_t bank_0_crc, uint32_t bank_0_size) {
  xiao_ota_settings_raw_t raw;
  memcpy(&raw, base_raw, sizeof(raw));
  raw.bank_0 = bank_0;
  raw.bank_0_crc = bank_0_crc;
  raw.bank_0_size = bank_0_size;
  return settings_write_raw(io, &raw);
}

/*
 * Rollback: restores the settings page to EXACTLY the given original
 * 28 bytes, verbatim -- no overlay, and never reconstructed from whatever
 * the page currently holds (which may itself be this same transaction's
 * own installed settings, or -- in principle -- torn/damaged).
 */
static bool xiao_ota_settings_restore_raw(
    const xiao_ota_io_t *io,
    const uint8_t original_raw[XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE]) {
  xiao_ota_settings_raw_t raw;
  memcpy(&raw, original_raw, sizeof(raw));
  return settings_write_raw(io, &raw);
}

/* Computes SHA-256 over the exact accepted command record's bytes, using
 * its own declared v1/v2 length (sizeof(xiao_ota_command_t) or
 * sizeof(xiao_ota_command_v2_t), matching whichever version it validated
 * as) -- a pure in-memory digest, no io needed. This is an audit/binding
 * value recorded in the settings sidecar to identify which exact signed
 * command admitted a transaction; it is NOT a substitute for the
 * Ed25519 signature check already performed in command_policy_valid()
 * before this is ever called. */
static void hash_command_digest(const xiao_ota_command_any_t *any,
                                uint8_t digest[32]) {
  uint16_t version;
  size_t length;
  memcpy(&version, (const uint8_t *)any + 4, sizeof(version));
  length = (version == XIAO_OTA_COMMAND_VERSION_WIRE_V2)
               ? sizeof(any->v2) : sizeof(any->v1);
  sha256_of(any, length, digest);
}

/* Shared CRC-16 streaming-scan core: active_extent_from_settings() and
 * finalize_install_and_verify() below both recompute a running CRC-16
 * over a chunked internal-flash read using this exact same loop (only the
 * address/length differ) -- one helper replaces the two copies. A failed
 * read returns false; callers must treat that as fail-closed exactly as
 * before (never fall through with a partial/bogus CRC). */
static bool crc16_over_internal(const xiao_ota_io_t *io, uint32_t address,
                                uint32_t length, uint16_t *out_crc) {
  const uint16_t *previous = NULL;
  uint16_t running = 0xFFFFu;
  while (length != 0) {
    uint32_t n = length > COPY_CHUNK ? COPY_CHUNK : length;
    if (!io->internal_read(io->ctx, address, io_buffer, n)) return false;
    running = crc16_compute(io_buffer, n, previous);
    previous = &running;
    address += n;
    length -= n;
  }
  *out_crc = running;
  return true;
}

/* Thin wrapper: reads real bank-0 settings and a fresh CRC-16 recompute
 * over the exact bytes now in internal flash, and defers the fail-closed
 * decision to xiao_ota_resolve_active_extent() (xiao_ota_record.c), which
 * is what test_record.c exercises host-side. */
static bool active_extent_from_settings(const xiao_ota_io_t *io,
                                        uint32_t *out_extent) {
  xiao_ota_bank0_settings_t settings;
  uint16_t recomputed_crc16 = 0xFFFFu;
  if (!xiao_ota_settings_get(io, &settings)) return false;
  if (settings.bank_0 == XIAO_OTA_BANK_VALID_APP && settings.bank_0_size != 0 &&
      settings.bank_0_size <= XIAO_OTA_INSTALL_MAX_SIZE) {
    /* A failed read here can never be allowed to fall through as a
     * bogus-but-plausible CRC-16 -- fail closed (no active extent)
     * rather than risk a false-valid match against bank_0_crc. */
    if (!crc16_over_internal(io, XIAO_OTA_APP_START, settings.bank_0_size,
                             &recomputed_crc16)) {
      return false;
    }
  }
  /*
   * The app-region bound passed to xiao_ota_resolve_active_extent() here
   * MUST be XIAO_OTA_INSTALL_MAX_SIZE (the real 0xAD000 writable image
   * capacity), never XIAO_OTA_APP_MAX_SIZE (0xC6000): this extent later
   * drives copy_internal_to_qspi()'s/copy_qspi_to_internal()'s actual
   * erase/write byte counts against XIAO_OTA_BACKUP_BASE on the external
   * QSPI part. Bounding it by the larger, internal-flash-only
   * XIAO_OTA_APP_MAX_SIZE would let a maliciously/corruptly large
   * bank_0_size backup/restore straight through into the security-tail
   * region (securityB, immediately past the backup bank's own image
   * capacity) that this project must never touch -- and, on restore,
   * into v1.17's own internal filesystem region too.
   */
  return xiao_ota_resolve_active_extent(
      settings.bank_0 == XIAO_OTA_BANK_VALID_APP, settings.bank_0_crc,
      settings.bank_0_size, recomputed_crc16, XIAO_OTA_INSTALL_MAX_SIZE,
      out_extent);
}

static bool copy_internal_to_qspi(const xiao_ota_io_t *io,
                                  xiao_ota_state_t *state,
                                  xiao_ota_settings_sidecar_t *sidecar,
                                  uint32_t *state_slot_address) {
  uint32_t offset = state->progress_bytes;
  while (offset < state->active_image_extent) {
    uint32_t sector_end = (offset + XIAO_OTA_QSPI_SECTOR_SIZE) &
                          ~(XIAO_OTA_QSPI_SECTOR_SIZE - 1u);
    uint32_t end = sector_end < state->active_image_extent
                       ? sector_end : state->active_image_extent;
    if (!io->qspi_erase_sector(io->ctx, XIAO_OTA_BACKUP_BASE + offset)) return false;
    while (offset < end) {
      uint32_t n = end - offset > COPY_CHUNK ? COPY_CHUNK : end - offset;
      if (!io->internal_read(io->ctx, XIAO_OTA_APP_START + offset,
                             flash_stage_buffer, n)) {
        return false;
      }
      if (!io->qspi_write(io->ctx, XIAO_OTA_BACKUP_BASE + offset,
                          flash_stage_buffer, n)) {
        return false;
      }
      if (!io->qspi_read(io->ctx, XIAO_OTA_BACKUP_BASE + offset, io_buffer, n)) {
        return false;
      }
      if (memcmp(io_buffer, flash_stage_buffer, n) != 0) return false;
      offset += n;
    }
    state->progress_bytes = offset;
    if (!persist_state(io, state, sidecar, state_slot_address)) return false;
  }
  return true;
}

static bool copy_qspi_to_internal(const xiao_ota_io_t *io,
                                  xiao_ota_state_t *state,
                                  xiao_ota_settings_sidecar_t *sidecar,
                                  uint32_t *state_slot_address,
                                  uint32_t source, uint32_t length) {
  uint32_t offset = state->progress_bytes;
  while (offset < length) {
    uint32_t end = offset + XIAO_OTA_QSPI_SECTOR_SIZE;
    if (end > length) end = length;
    if (!io->internal_erase_page(io->ctx, XIAO_OTA_APP_START + offset)) return false;
    while (offset < end) {
      uint32_t n = end - offset > COPY_CHUNK ? COPY_CHUNK : end - offset;
      if (!io->qspi_read(io->ctx, source + offset, io_buffer, n)) return false;
      if (!io->internal_write(io->ctx, XIAO_OTA_APP_START + offset, io_buffer, n)) {
        return false;
      }
      if (!io->internal_read(io->ctx, XIAO_OTA_APP_START + offset, verify_buffer, n)) {
        return false;
      }
      if (memcmp(verify_buffer, io_buffer, n) != 0) return false;
      offset += n;
    }
    state->progress_bytes = offset;
    if (!persist_state(io, state, sidecar, state_slot_address)) return false;
  }
  return true;
}

/*
 * Verifies the just-installed candidate (fresh hash over exactly the
 * signed size) and, only if that matches, computes its CRC-16 and writes
 * bank-0 settings to point at it -- derived from the FROZEN settings
 * snapshot captured at this transaction's admission
 * (sidecar->original_settings_raw), changing only bank_0/bank_0_crc/
 * bank_0_size (xiao_ota_settings_apply_bank0()), never a fresh read of
 * "current" settings. Any read/verify/write failure here is reported as
 * "not installed" -- caller must treat exactly like a verify-mismatch
 * (roll back), never as a reason to escalate on its own.
 */
static bool finalize_install_and_verify(const xiao_ota_io_t *io,
                                        xiao_ota_state_t *state,
                                        const xiao_ota_settings_sidecar_t *sidecar,
                                        uint32_t candidate_size,
                                        uint8_t out_digest[32]) {
  uint16_t candidate_crc;

  if (!hash_internal(io, XIAO_OTA_APP_START, candidate_size, out_digest) ||
      !all_equal(out_digest, state->candidate_hash_sha256)) {
    return false;
  }
  if (!crc16_over_internal(io, XIAO_OTA_APP_START, candidate_size,
                           &candidate_crc)) {
    return false;
  }
  if (!xiao_ota_settings_apply_bank0(io, sidecar->original_settings_raw,
                                     XIAO_OTA_BANK_VALID_APP, candidate_crc,
                                     candidate_size)) {
    return false;
  }
  memcpy(state->installed_hash_sha256, out_digest, 32);
  return true;
}

/*
 * BootFloorActivationReceiptV1 verification (see xiao_ota_record.h's
 * doc-comment): true only if `r` is a fully self-consistent, genuinely
 * signed genesis-activation receipt binding THIS exact device, THIS
 * exact compiled binary's qualification, AND the ALREADY-PERSISTED,
 * already-committed `floor` record passed in here -- never a claim
 * checked against a fresh, live re-derivation of "whatever happens to
 * be running right now". A receipt is provenance for a floor body that
 * genuinely, durably exists; a live hardware match alone (current
 * running image hash/extent) is explicitly NOT proof that floor 0 was
 * ever actually provisioned, and must never substitute for an actual
 * persisted record -- see the XIAO_OTA_PAIR_FOUND/XIAO_OTA_PAIR_MISSING
 * handling in xiao_ota_boot_process_io() for why this function is only
 * ever called once a real, committed floor record is already in hand.
 *
 * original_sdk28_digest is NOT re-derived and compared HERE, inside
 * floor_activation_receipt_binds_floor() itself, against a fresh read of
 * the CURRENT settings page: the 28-byte settings page
 * (xiao_ota_settings_raw_t) includes the bank_0/bank_0_crc/bank_0_size
 * triad, which any in-flight OTA transaction legitimately, durably
 * mutates well before that transaction's own confirmation/rollback ever
 * resolves -- comparing against a fresh live read INSIDE this function
 * (which has no notion of which phase/transaction is currently active)
 * would risk spuriously flipping an already-established, still-
 * genuinely-valid genesis floor untrustworthy mid-transaction. Unlike
 * baseline_hash_sha256/baseline_extent (which this function binds
 * directly against the persisted floor record's own, transaction-
 * invariant fields), there is no equivalent persisted, transaction-
 * invariant snapshot of the settings page available to THIS function
 * alone. original_sdk28_digest IS still actively, independently checked
 * by the caller -- see genesis_sdk28_baseline_ok(), called right after
 * this function succeeds, which has the phase/sidecar context needed to
 * pick the correct baseline (live settings page, or the admission-time
 * sidecar snapshot while a transaction is active) to compare it against.
 *
 * Split into two layers: floor_activation_receipt_identity_role_ok()
 * below verifies everything about `r` that is TRUE FOREVER for this
 * exact device/binary -- genuine Ed25519 signature by the trust anchor,
 * hw_uid/target/profile/layout_id/key_id identity, and (critically)
 * current_role == XIAO_OTA_COMPILED_ROLE_ID -- entirely independent of
 * which floor value happens to be currently persisted. The content
 * binding (baseline_hash_sha256/baseline_extent against one SPECIFIC,
 * already-persisted floor body) is only meaningful for the genesis
 * (floor 0) moment itself, so it stays in floor_activation_receipt_binds_
 * floor(), the genesis-only wrapper. floor_role_evidence_ok() (further
 * below) reuses the identity/role layer alone at ANY floor value, so a
 * role-1-compiled binary can never ride on anti-rollback history that
 * was only ever genesis-certified for role 0 (or vice versa), even
 * after the floor has long since advanced past 0 -- see persist_floor()'s
 * carry-forward of this exact receipt window on every advance, which is
 * what keeps this evidence available for that check beyond genesis. */
static bool floor_activation_receipt_identity_role_ok(
    const xiao_ota_io_t *io, const xiao_ota_floor_activation_receipt_t *r) {
  uint8_t digest[32];
  uint8_t key_hash[32];

  if (!xiao_ota_floor_activation_receipt_body_valid(r)) return false;
  if (r->boot_counter_domain != XIAO_OTA_BOOT_COUNTER_DOMAIN) return false;
  if (r->hw_uid != io->device_address(io->ctx)) return false;
  if (r->target != XIAO_OTA_BOARD_TARGET) return false;
#if defined(XIAO_OTA_FLOOR_ACTIVATION_COMPILED_PROFILE)
  if (r->profile != XIAO_OTA_FLOOR_ACTIVATION_COMPILED_PROFILE) return false;
#else
  return false; /* unrecognized compiled board target: refuse, never trust */
#endif
  if (r->layout_id != XIAO_OTA_FLOOR_ACTIVATION_LAYOUT_ID) return false;
  /* The role being genesis-activated must equal THIS binary's own
   * compiled role identity (XIAO_OTA_COMPILED_ROLE_ID), never a
   * hardcoded "genesis is always role 0": a role-1 (repeater) binary
   * must only ever accept a receipt certifying role 1 at genesis, and a
   * role-0 (companion) binary only role 0 -- see
   * xiao_ota_install_command_static_identity_valid() for the identical
   * compiled-role exact-equality discipline on the install-command side.
   * There is still no 0->1 (or 1->0) runtime role TRANSITION implemented
   * here or anywhere else: this only governs which role a FIRST,
   * never-yet-committed genesis floor is allowed to certify, and that
   * role can never change for an already-committed floor (there is no
   * code path that re-derives or overwrites current_role after the
   * floor is durably persisted). */
  if (r->current_role != XIAO_OTA_COMPILED_ROLE_ID) return false;
  if (r->key_id != XIAO_OTA_KEY_ID) return false;
  /* Only genesis (floor 0) activation is implemented; any other declared
   * activation_floor value is refused rather than trusted. */
  if (r->activation_floor != 0u) return false;

  /* SHA-256 is a streaming/incremental hash: feeding the domain prefix
   * and the receipt body as two separate update() calls produces the
   * IDENTICAL digest to concatenating them into one buffer first (see
   * the same incremental-update pattern already used by
   * copy_internal_to_qspi()'s/backup hashing loops above) -- this
   * avoids a redundant 366-byte stack scratch buffer and two memcpy()
   * calls for no behavioural difference. */
  {
    xiao_ota_sha256_t sha;
    xiao_ota_sha256_init(&sha);
    xiao_ota_sha256_update(&sha, XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN,
                           XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN_LEN);
    xiao_ota_sha256_update(&sha, r,
                           offsetof(xiao_ota_floor_activation_receipt_t,
                                   signature_ed25519));
    xiao_ota_sha256_final(&sha, digest);
  }
  if (ed25519_verify(r->signature_ed25519, digest, sizeof(digest),
                     XIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY) != 1) {
    return false;
  }

  sha256_of(XIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY, 32, key_hash);
  return memcmp(r->key_fingerprint, key_hash, sizeof(r->key_fingerprint)) == 0;
}

static bool floor_activation_receipt_binds_floor(
    const xiao_ota_io_t *io, const xiao_ota_floor_activation_receipt_t *r,
    const xiao_ota_floor_t *floor) {
  if (!floor_activation_receipt_identity_role_ok(io, r)) return false;
  /* Bind against the ALREADY-PERSISTED floor record's own fields, never
   * a fresh live re-derivation -- see this function's doc-comment. */
  if (r->baseline_extent != floor->active_image_extent) return false;
  return all_equal(floor->confirmed_hash_sha256, r->baseline_hash_sha256);
}

/*
 * Role-continuity gate for ANY already-trusted floor value, genesis or
 * not: true only if AT LEAST ONE of the two FIXED, physical genesis-
 * receipt windows (XIAO_OTA_FLOOR_ACTIVATION_A/B -- read unconditionally
 * by address, independent of which floor slot is currently "winning")
 * still holds a receipt that identity/role-verifies for THIS exact
 * device and THIS exact compiled role. Deliberately does NOT re-check
 * baseline_hash_sha256/baseline_extent (see floor_activation_receipt_
 * identity_role_ok()'s doc-comment) -- those are meaningless once the
 * floor has advanced past the image the genesis receipt actually
 * describes; only identity+role need to stay true forever.
 *
 * *out_io_error distinguishes a genuine QSPI read failure (fail closed
 * to Recovery, identically to every other IO_ERROR path in this file)
 * from an ordinary "no verifying receipt in either window" result
 * (fail closed to "floor untrustworthy", identically to how a genesis
 * floor's own missing/mismatched receipt is already handled -- see the
 * XIAO_OTA_PAIR_FOUND/floor.confirmed_counter_floor==0 case above).
 * This is the sole defense against a swapped, differently-role-compiled
 * loader binary silently inheriting an existing confirmed floor/anti-
 * rollback history that was only ever genesis-certified for the OTHER
 * role: the install-command's own role_id check alone cannot catch this,
 * since a genuinely, validly signed command for the NEW compiled role
 * would otherwise pass that check on its own. (Calls
 * floor_activation_window_verify_into(), defined earlier alongside
 * persist_floor(), which also uses it.) */

/* Reads both physical activation-receipt windows and reports whether
 * EITHER one verifies as provenance for the ALREADY-PERSISTED `floor`
 * record passed in (see floor_activation_receipt_binds_floor() above);
 * *out_io_error distinguishes a genuine read failure (must fail closed
 * exactly like any other IO_ERROR) from an ordinary absent/invalid
 * receipt. Only ever called once `floor` is already a genuinely
 * committed XIAO_OTA_PAIR_FOUND record -- never to manufacture one.
 * Reuses floor_activation_window_verify_into() (defined earlier,
 * alongside persist_floor() which also needs it) rather than a second,
 * near-identical read+parse+verify helper -- both callers share the
 * exact same "read the full word-aligned physical window, parse only
 * the leading logical bytes, identity/role-verify" sequence. Reads
 * BOTH windows into ONE shared raw scratch buffer sequentially (never
 * both at once), keeping stack usage and code size down. */
/* Streams a bounded chunk at a time (never a second full-window
 * resident buffer) to compare the bytes durably stored at a FIRST,
 * already-identity/role-verified receipt window's physical address
 * against a SECOND, already-fully-resident verified window's bytes,
 * for exact byte-for-byte provenance equality over the full physical
 * window (all 386 logical signed bytes plus trailing alignment
 * padding) -- not a CRC/hash proxy, which can theoretically collide
 * for genuinely different signed content. Re-reads the first window's
 * address again (a few extra small, 4-byte-aligned QSPI reads) rather
 * than keeping it buffered whole, since this path only runs when BOTH
 * physical windows independently verify (the rare case), not on every
 * ordinary boot. */
static bool __attribute__((noinline))
floor_activation_window_content_equal(const xiao_ota_io_t *io,
                                      uint32_t address,
                                      const uint8_t *other) {
  uint8_t chunk[32] __attribute__((aligned(4)));
  size_t offset = 0;
  while (offset < XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES) {
    size_t n = XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES - offset;
    if (n > sizeof(chunk)) n = sizeof(chunk);
    if (!io->qspi_read(io->ctx, address + offset, chunk, n)) return false;
    if (memcmp(chunk, other + offset, n) != 0) return false;
    offset += n;
  }
  return true;
}

static bool __attribute__((noinline))
floor_role_evidence_ok(const xiao_ota_io_t *io, bool *out_io_error) {
  static const uint32_t kWindows[2] = {XIAO_OTA_FLOOR_ACTIVATION_A,
                                       XIAO_OTA_FLOOR_ACTIVATION_B};
  uint8_t window[XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES]
      __attribute__((aligned(4)));
  uint32_t first_verified_addr = 0;
  bool any_verified = false;
  bool read_ok;
  unsigned i;
  *out_io_error = false;
  for (i = 0; i < 2u; ++i) {
    if (floor_activation_window_verify_into(io, kWindows[i], window,
                                            &read_ok)) {
      /* A SECOND independently valid receipt must be the EXACT same
       * signed bytes as the first, never merely a matching CRC/hash --
       * legitimate steady-state operation always carries the identical
       * receipt bytes into both windows (see persist_floor()'s
       * propagate-before-erase copy), so any byte-level mismatch here
       * can only mean two distinct, separately signed genesis
       * authorizations exist for this same device/role -- a provenance
       * conflict that must never be resolved by silently picking
       * whichever window happens to verify. */
      if (any_verified && !floor_activation_window_content_equal(
                             io, first_verified_addr, window)) {
        return false;
      }
      if (!any_verified) {
        first_verified_addr = kWindows[i];
        any_verified = true;
      }
    } else if (!read_ok) {
      *out_io_error = true;
      return false;
    }
  }
  return any_verified;
}

/*
 * A verified genesis receipt's original_sdk28_digest is a signed claim
 * about the device's true factory-baseline settings page (see
 * xiao_ota_record.h's field doc-comment) -- but it is opaque unless
 * checked against the RIGHT bytes for the CURRENT boot's phase:
 *
 *  - No transaction is currently active (have_state is false, or the
 *    existing state is in a terminal phase -- EMPTY/CONFIRMED/FAILED):
 *    while confirmed_counter_floor==0, no transaction has EVER been
 *    confirmed (persist_floor() never advances it from 0 except via a
 *    prior CONFIRMED admission, which would have moved the floor off 0
 *    already), and any prior transaction that reached a terminal FAILED
 *    state was, by construction, rolled back verbatim (see
 *    test_rollback_restores_settings_raw_verbatim) -- so the LIVE
 *    settings page is provably still the true original baseline right
 *    now, safe to hash and compare directly.
 *
 *  - A transaction IS currently active (non-terminal phase, e.g.
 *    TRIAL_BOOT): the live settings page may have already been legitimately
 *    mutated by the in-flight candidate itself, so the live page must
 *    NOT be used here. Instead compare against the admission-time
 *    sidecar snapshot (sidecar.original_settings_raw), which froze the
 *    true pre-transaction baseline at the moment this very transaction
 *    began -- but ONLY when that sidecar is itself proven to be the
 *    genuine one bound to the currently-trusted state record
 *    (sidecar_matches_state), never an unrelated or stale one. If no
 *    such proof is available, the baseline is simply unverifiable this
 *    boot -- fail closed (deny genesis trust) rather than assume.
 */
static bool genesis_sdk28_baseline_ok(
    const xiao_ota_io_t *io, bool have_state, bool state_phase_active,
    bool have_sidecar, bool sidecar_matches_state,
    const xiao_ota_settings_sidecar_t *sidecar,
    const uint8_t original_sdk28_digest[32]) {
  uint8_t digest[32];
  if (have_state && state_phase_active) {
    if (!have_sidecar || !sidecar_matches_state) return false;
    xiao_ota_settings_raw_t snapshot;
    memcpy(&snapshot, sidecar->original_settings_raw, sizeof(snapshot));
    sha256_of(&snapshot, sizeof(snapshot), digest);
  } else {
    xiao_ota_settings_raw_t live;
    if (!settings_read_raw(io, &live)) return false;
    sha256_of(&live, sizeof(live), digest);
  }
  return memcmp(digest, original_sdk28_digest, 32) == 0;
}

static bool floor_genesis_receipt_matches(
    const xiao_ota_io_t *io, const xiao_ota_floor_t *floor, bool *out_io_error,
    xiao_ota_floor_activation_receipt_t *out_matched) {
  /* Needs the PARSED receipt back from BOTH windows regardless of
   * whether either verifies (floor_activation_receipt_binds_floor() is
   * checked separately, per-window, below) -- a plain word-aligned
   * raw-read-then-parse, reusing floor_activation_window_verify_into()'s
   * same read+parse shape via a throwaway raw scratch buffer rather
   * than a third distinct read helper. */
  uint8_t window[XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES]
      __attribute__((aligned(4)));
  xiao_ota_floor_activation_receipt_t ra __attribute__((aligned(4)));
  xiao_ota_floor_activation_receipt_t rb __attribute__((aligned(4)));
  bool read_ok;
  *out_io_error = false;
  (void)floor_activation_window_verify_into(io, XIAO_OTA_FLOOR_ACTIVATION_A,
                                            window, &read_ok);
  if (!read_ok) {
    *out_io_error = true;
    return false;
  }
  memcpy(&ra, window, XIAO_OTA_FLOOR_ACTIVATION_TOTAL_BYTES);
  (void)floor_activation_window_verify_into(io, XIAO_OTA_FLOOR_ACTIVATION_B,
                                            window, &read_ok);
  if (!read_ok) {
    *out_io_error = true;
    return false;
  }
  memcpy(&rb, window, XIAO_OTA_FLOOR_ACTIVATION_TOTAL_BYTES);
  if (floor_activation_receipt_binds_floor(io, &ra, floor)) {
    if (out_matched != NULL) *out_matched = ra;
    return true;
  }
  if (floor_activation_receipt_binds_floor(io, &rb, floor)) {
    if (out_matched != NULL) *out_matched = rb;
    return true;
  }
  return false;
}

/*
 * Entire OTA transaction decision sequence: command acceptance, backup,
 * install, trial-boot confirmation, rollback and recovery -- expressed
 * purely in terms of `io`. Called identically by xiao_ota_boot_process()
 * (real hardware io_t below) and by native host tests (fake io_t backed
 * by in-memory arrays), so a test failure or pass reflects this exact
 * code path, not a hand-maintained parallel copy of it.
 */
void xiao_ota_boot_process_io(const xiao_ota_io_t *io) {
  xiao_ota_command_any_t command_a __attribute__((aligned(4)));
  xiao_ota_command_any_t command_b __attribute__((aligned(4)));
  xiao_ota_command_any_t command __attribute__((aligned(4)));
  xiao_ota_install_command_t intent __attribute__((aligned(4)));
  xiao_ota_state_t state_a __attribute__((aligned(4)));
  xiao_ota_state_t state_b __attribute__((aligned(4)));
  xiao_ota_state_t state __attribute__((aligned(4)));
  xiao_ota_confirmation_t confirm_a __attribute__((aligned(4)));
  xiao_ota_confirmation_t confirm_b __attribute__((aligned(4)));
  xiao_ota_confirmation_t confirmation __attribute__((aligned(4)));
  xiao_ota_floor_t floor_a __attribute__((aligned(4)));
  xiao_ota_floor_t floor_b __attribute__((aligned(4)));
  xiao_ota_floor_t floor __attribute__((aligned(4)));
  xiao_ota_settings_sidecar_t sidecar __attribute__((aligned(4)));
  uint8_t digest[32] __attribute__((aligned(4)));
  bool have_state, have_floor, confirmed, floor_trustworthy;
  bool have_sidecar, sidecar_trustworthy, sidecar_matches_state;
  bool have_active_extent;
  uint32_t expected_active_extent = 0;
  uint32_t state_slot_address = XIAO_OTA_STATE_B;
  uint32_t floor_slot_address = XIAO_OTA_FLOOR_B;
  xiao_ota_pair_status_t command_status;
  xiao_ota_pair_status_t state_status;
  xiao_ota_pair_status_t floor_status;
  xiao_ota_pair_status_t sidecar_status;

  /*
   * Upstream consumes and clears these requests in check_dfu_mode(), which runs
   * after this hook. Never let a persistent OTA transaction intercept recovery.
   */
  if (io->explicit_dfu_requested(io->ctx)) return;

  if (!io->qspi_init(io->ctx)) {
    /* Unreadable/unresponsive QSPI at bring-up means every read below is
     * unknown, not "absent" -- fail closed before touching anything. */
    goto recover;
  }

  /*
   * Zero BOTH raw physical command buffers before read_pair() touches
   * them: read_pair() returns XIAO_OTA_PAIR_IO_ERROR immediately on the
   * FIRST failing qspi_read(), meaning the SECOND buffer may never be
   * read at all this boot. Without this, that buffer would retain
   * whatever uninitialized stack garbage happened to be there when
   * command_a_valid/command_b_valid are computed unconditionally below
   * (regardless of command_status) for the historical-command-
   * authentication path -- evaluating xiao_ota_command_any_valid()
   * against genuinely unread memory is undefined behaviour and must
   * never be relied upon to happen to fail. All-zero bytes are
   * guaranteed to fail xiao_ota_command_any_valid() (wrong magic), so a
   * short-circuited read always yields a safely-unauthenticatable slot.
   */
  memset(&command_a, 0, sizeof(command_a));
  memset(&command_b, 0, sizeof(command_b));
  command_status = read_pair(io, XIAO_OTA_COMMAND_A, XIAO_OTA_COMMAND_B,
                             XIAO_OTA_COMMAND_A, XIAO_OTA_COMMAND_B,
                             XIAO_OTA_SHARED_TAIL_NONE,
                             &command_a, &command_b, sizeof(command),
                             offsetof(xiao_ota_command_v2_t, commit_marker),
                             xiao_ota_command_any_valid, &command, NULL,
                             NULL, NULL, NULL);
  if (command_status != XIAO_OTA_PAIR_FOUND) {
    /* A missing, damaged, or unreadable command slot is always safe to
     * treat as "no signed command this boot": every field is
     * independently re-validated (structural decode, then cryptographic
     * signature + policy) before any acceptance below, so a zeroed/
     * garbage command can only ever fail those checks, never be
     * mistakenly accepted. Unlike STATE/FLOOR, this pair needs no
     * absence/damage/IO-error distinction. */
    memset(&command, 0, sizeof(command));
  }
  /* Structural-only decode (no signature check yet); zeroed on failure so
   * downstream field reads below see 0, matching the pre-refactor behaviour
   * of an all-zero `command` when decode failed. */
  if (!xiao_ota_install_command_decode(&command, &intent)) {
    memset(&intent, 0, sizeof(intent));
  }

  {
    state_ambiguous_binding_ctx_t state_binding_ctx;
    state_binding_ctx.have_command = (command_status == XIAO_OTA_PAIR_FOUND);
    state_binding_ctx.expected_transaction_nonce = intent.transaction_nonce;
    state_binding_ctx.io = io;
    state_binding_ctx.command_a = &command_a;
    state_binding_ctx.command_b = &command_b;
    state_binding_ctx.command_a_valid = xiao_ota_command_any_valid(&command_a);
    state_binding_ctx.command_b_valid = xiao_ota_command_any_valid(&command_b);
    state_status = read_pair(io, XIAO_OTA_STATE_A, XIAO_OTA_STATE_B,
                             XIAO_OTA_STATE_A, XIAO_OTA_STATE_B,
                             XIAO_OTA_SHARED_TAIL_STATE,
                             &state_a,
                             &state_b, sizeof(state),
                             offsetof(xiao_ota_state_t, commit_marker),
                             (bool (*)(const void *))xiao_ota_state_valid,
                             &state, &state_slot_address,
                             (bool (*)(const void *))xiao_ota_state_body_valid,
                             state_ambiguous_binding_ok, &state_binding_ctx);
  }
  switch (state_status) {
    case XIAO_OTA_PAIR_FOUND:
      have_state = true;
      break;
    case XIAO_OTA_PAIR_MISSING:
      have_state = false;
      memset(&state, 0, sizeof(state));
      break;
    case XIAO_OTA_PAIR_DAMAGED:
    case XIAO_OTA_PAIR_IO_ERROR:
    default:
      /* Torn/bit-rotted state (not genuinely blank) or an unreadable
       * slot must never be silently treated as "no transaction in
       * progress" -- an in-flight, only-partially-applied transaction's
       * safety invariants (backup validity, live app consistency) would
       * go completely uninspected. Fail closed before any mutation. */
      goto recover;
  }

  /* Boot-private settings sidecar (xiao_ota_layout.h): co-located inside
   * the SAME sector as its accompanying state record, always written
   * together by persist_state()/write_state_with_sidecar(). Read and
   * cross-check this BEFORE any fresh-bank/settings check below (never
   * after), so a torn write between the sidecar and state commits, or a
   * legacy transaction from before this sidecar existed, is caught here
   * -- not discovered partway through a later destructive step. Read as
   * a PHYSICAL PAIR with the already-determined winning state slot (see
   * read_paired_sidecar()), never as an independently newest-across-both-
   * slots record -- a prepared sidecar for the NOT-yet-winning opposite
   * slot must never mask or override the still fully-intact committed
   * pair actually in force this boot. */
  if (have_state) {
    sidecar_status = read_paired_sidecar(io, state_slot_address, &sidecar);
  } else {
    /* No winning state record at all: there is nothing to pair a
     * sidecar against, and the transaction_active gate below never
     * fires in this case regardless (have_state is false). That does
     * NOT mean both physical sidecar windows can be ignored
     * unconditionally, though -- sidecar_orphan_status() still tells
     * apart a genuinely blank/harmlessly-orphaned slot from unexplained
     * debris; the latter must force_recovery() immediately here, since
     * there is no later phase-gated check that would ever catch it once
     * have_state is false.
     *
     * A structurally valid FOUND orphan is only harmless if it can be
     * PROVEN to be exactly the transaction that would legitimately be
     * prepared for this device right now -- the currently visible signed
     * command's digest and declared transaction nonce, the exact next
     * sequence number a genuine first admission would use (state was
     * just memset above; state.sequence is 0), and a snapshot triad that
     * matches a FRESH settings-page read taken this instant. No visible
     * command, or an unreadable settings page, means that proof is
     * simply unavailable this boot -- fail closed rather than assume
     * harmlessness. */
    bool have_expected_command = (command_status == XIAO_OTA_PAIR_FOUND);
    uint8_t expected_command_digest[32];
    xiao_ota_settings_raw_t expected_snapshot;
    memset(expected_command_digest, 0, sizeof(expected_command_digest));
    memset(&expected_snapshot, 0, sizeof(expected_snapshot));
    if (have_expected_command) {
      hash_command_digest(&command, expected_command_digest);
    }
    if (!settings_read_raw(io, &expected_snapshot)) {
      have_expected_command = false;
    }
    sidecar_status = sidecar_orphan_status(
        io, state.sequence + 1, have_expected_command, expected_command_digest,
        intent.transaction_nonce, &expected_snapshot, &sidecar);
    if (sidecar_status == XIAO_OTA_PAIR_DAMAGED) {
      goto recover;
    }
  }
  switch (sidecar_status) {
    case XIAO_OTA_PAIR_FOUND:
      have_sidecar = true;
      sidecar_trustworthy = true;
      break;
    case XIAO_OTA_PAIR_MISSING:
      have_sidecar = false;
      sidecar_trustworthy = true;
      memset(&sidecar, 0, sizeof(sidecar));
      break;
    case XIAO_OTA_PAIR_DAMAGED:
      have_sidecar = false;
      sidecar_trustworthy = false;
      memset(&sidecar, 0, sizeof(sidecar));
      break;
    case XIAO_OTA_PAIR_IO_ERROR:
    default:
      goto recover;
  }
  /* A sidecar is only meaningful bound to the EXACT state record it was
   * written alongside: same sequence (physical write-pairing) AND same
   * full 64-bit transaction nonce (identity), both checked independently,
   * PLUS two further bindings approved for this design: (1) when the
   * command record that admitted this transaction is still present this
   * boot, the sidecar's recorded command digest must match it exactly --
   * a rollback that no longer needs (or can no longer find) that command
   * record is not blocked by this, since backup-based rollback must never
   * depend on a command record surviving; (2) the frozen bank-0 triad
   * inside the sidecar's own 28-byte snapshot must agree with the state
   * record's own previous_bank_0/_crc/_size fields -- both were captured
   * from the exact same admission-time read, so any disagreement means a
   * structurally-valid-but-WRONG snapshot (e.g. belonging to some other
   * transaction) is sitting where this one is expected, which must never
   * be trusted to restore or overlay bank-0 settings for THIS state. */
  {
    bool command_digest_matches = true;
    bool bank0_triad_matches = true;
    if (have_sidecar) {
      if (command_status == XIAO_OTA_PAIR_FOUND) {
        uint8_t live_command_digest[32];
        hash_command_digest(&command, live_command_digest);
        command_digest_matches =
            memcmp(live_command_digest, sidecar.command_digest_sha256, 32) == 0;
      }
      {
        xiao_ota_settings_raw_t snapshot;
        memcpy(&snapshot, sidecar.original_settings_raw, sizeof(snapshot));
        bank0_triad_matches =
            snapshot.bank_0 == state.previous_bank_0 &&
            snapshot.bank_0_crc == state.previous_bank_0_crc &&
            snapshot.bank_0_size == state.previous_bank_0_size;
      }
    }
    sidecar_matches_state = sidecar_trustworthy && have_sidecar &&
        sidecar.matching_state_sequence == state.sequence &&
        sidecar.transaction_nonce == state.transaction_nonce &&
        command_digest_matches && bank0_triad_matches;
  }
  /* Any ACTIVE (non-terminal) transaction needs its own frozen original-
   * settings snapshot to safely finalize an install or roll back later --
   * a missing sidecar (a transaction begun before this sidecar existed)
   * or one that fails to match the currently-trusted state record
   * (a torn sidecar/state commit pair, or damage) must never be silently
   * ignored or reconstructed from whatever the CURRENT settings page
   * holds. Terminal phases (EMPTY/CONFIRMED/FAILED) need no sidecar at
   * all -- xiao_ota_command_acceptable_phase() is reused here purely as
   * the existing "phase requires no in-flight settings recovery" test. */
  if (have_state &&
      !xiao_ota_command_acceptable_phase(true, (xiao_ota_phase_t)state.phase) &&
      !sidecar_matches_state) {
    goto recover;
  }

  {
    floor_ambiguous_binding_ctx_t floor_binding_ctx;
    floor_binding_ctx.have_state = have_state;
    floor_binding_ctx.state_phase_active =
        have_state &&
        !xiao_ota_command_acceptable_phase(true, (xiao_ota_phase_t)state.phase);
    floor_binding_ctx.state_candidate_counter = state.candidate_counter;
    floor_binding_ctx.state_candidate_hash_sha256 = state.candidate_hash_sha256;
    floor_status = read_pair(io, XIAO_OTA_FLOOR_A, XIAO_OTA_FLOOR_B,
                             XIAO_OTA_FLOOR_A, XIAO_OTA_FLOOR_B,
                             XIAO_OTA_SHARED_TAIL_FLOOR,
                             &floor_a,
                             &floor_b, sizeof(floor),
                             offsetof(xiao_ota_floor_t, commit_marker),
                             (bool (*)(const void *))xiao_ota_floor_valid,
                             &floor, &floor_slot_address,
                             (bool (*)(const void *))xiao_ota_floor_body_valid,
                             floor_ambiguous_binding_ok, &floor_binding_ctx);
  }
  switch (floor_status) {
    case XIAO_OTA_PAIR_FOUND:
      have_floor = true;
      floor_trustworthy = true;
      if (floor.confirmed_counter_floor == 0u) {
        /* Floor 0 is the one value an ordinary confirmed-transaction
         * advance never produces (persist_floor() below is only ever
         * called with a HIGHER floor derived from a prior CONFIRMED
         * state) -- it can only ever be established once, out of thin
         * air, by factory/provisioning. A fully committed, CRC-valid
         * record merely claiming 0 therefore proves nothing about its
         * own legitimacy by itself: it must be independently vouched
         * for by a verified BootFloorActivationReceiptV1 binding THIS
         * EXACT persisted floor body (never a fresh live-hardware
         * match alone -- see floor_activation_receipt_binds_floor()).
         * Absent a matching receipt, this is untrustworthy exactly
         * like DAMAGED, even though the bytes are otherwise perfectly
         * well-formed. */
        bool receipt_io_error = false;
        xiao_ota_floor_activation_receipt_t matched_receipt
            __attribute__((aligned(4)));
        bool genesis_ok = floor_genesis_receipt_matches(
            io, &floor, &receipt_io_error, &matched_receipt);
        if (receipt_io_error) {
          goto recover;
        }
        /* The receipt's own fields established structural/cryptographic
         * provenance above; additionally validate its signed
         * original_sdk28_digest claim against the true original
         * settings-page baseline for the current phase (see
         * genesis_sdk28_baseline_ok()'s doc-comment) -- a legitimate
         * receipt bound to a WRONG factory baseline must deny genesis
         * trust exactly like any other tampered/mismatched field, with
         * no mutation performed either way. */
        if (genesis_ok &&
            !genesis_sdk28_baseline_ok(
                io, have_state,
                have_state && !xiao_ota_command_acceptable_phase(
                                  true, (xiao_ota_phase_t)state.phase),
                have_sidecar, sidecar_matches_state, &sidecar,
                matched_receipt.original_sdk28_digest)) {
          genesis_ok = false;
        }
        if (!genesis_ok) {
          have_floor = false;
          floor_trustworthy = false;
          memset(&floor, 0, sizeof(floor));
        }
      }
      break;
    case XIAO_OTA_PAIR_MISSING:
      /* Genuinely blank pair of floor slots is ALWAYS untrustworthy,
       * with no exception: a BootFloorActivationReceiptV1 is provenance
       * for an already-durable, matching, committed floor body (see the
       * XIAO_OTA_PAIR_FOUND case above), never an instruction to
       * conjure one into existence from nothing. Even a receipt that
       * verifies and even a live hardware match give no proof that
       * floor 0 was ever actually, durably provisioned -- only an
       * actual persisted floor record can prove that. A CONFIRMED state
       * record below may still independently dominate and repair this,
       * same as for DAMAGED. */
      have_floor = false;
      floor_trustworthy = false;
      memset(&floor, 0, sizeof(floor));
      break;
    case XIAO_OTA_PAIR_DAMAGED:
      /* Torn write, bit rot, or leftover unrelated data from before OTA
       * provisioning: floor damage, not "no floor yet". Never silently
       * reopen the anti-rollback counter at 0. */
      have_floor = false;
      floor_trustworthy = false;
      memset(&floor, 0, sizeof(floor));
      break;
    case XIAO_OTA_PAIR_IO_ERROR:
    default:
      goto recover;
  }


  /* Always re-derive the active extent from what is actually in internal
   * flash right now (fresh XIAO_OTA_BANK_VALID_APP + nonzero bounded size + a
   * recomputed CRC-16 over that exact extent) -- never from
   * floor.active_image_extent, which only reflects whatever OTA install
   * last completed and goes stale the moment a user reflashes a different
   * image over USB/CDC without going through this bootloader at all.
   * Missing/invalid fresh metadata fails closed (have_active_extent=false)
   * rather than silently substituting a guessed extent. This does not
   * touch floor.confirmed_counter_floor, which remains the sole
   * anti-rollback authority regardless of bank-0 state. */
  have_active_extent = active_extent_from_settings(io, &expected_active_extent);
  if (have_state && state.phase == XIAO_OTA_PHASE_CONFIRMED && have_active_extent &&
      (!floor_trustworthy || !have_floor ||
       floor.confirmed_counter_floor < state.candidate_counter)) {
    /*
     * A durably-CONFIRMED state record is itself an independently-
     * trusted fact (read_pair()/state_ambiguous_binding_ok() already
     * authenticated it above, entirely separately from the floor pair)
     * that this exact counter/hash/extent was the last image genuinely
     * confirmed. If the floor pair came back untrustworthy (DAMAGED),
     * genuinely absent, or simply stale (its own counter has not yet
     * caught up to this confirmed state -- e.g. the floor-advancing
     * write that normally accompanies confirmation never durably
     * landed), that is NOT proof the device's anti-rollback floor was
     * ever actually lower: the CONFIRMED state's own candidate_counter
     * is a floor-dominating fact in its own right. Silently leaving the
     * floor unrepaired here would either (a) permanently refuse every
     * future admission once the floor pair is merely damaged (even
     * though the confirmed state proves exactly what the floor should
     * read), or (b) in the have_floor-but-stale case, let an
     * already-superseded lower floor value keep being used for fresh
     * anti-rollback admission decisions. Before trusting this state
     * enough to rebuild the floor from it, independently verify what is
     * ACTUALLY running right now still matches it -- the same
     * fresh-hash-over-fresh-extent proof used at confirmation time
     * itself, never assumed merely because the state record says so
     * (e.g. a USB/CDC reflash since confirmation must never let a
     * stale confirmed-state record resurrect a floor for an image that
     * is no longer what is genuinely installed).
     */
    uint8_t running_digest[32];
    if (hash_internal(io, XIAO_OTA_APP_START, expected_active_extent, running_digest) &&
        all_equal(running_digest, state.candidate_hash_sha256)) {
      /* This block is about to durably MUTATE the floor pair (erase one
       * physical slot and commit a reconstructed record into it) based
       * solely on the CONFIRMED state's own say-so. Checking role
       * evidence only AFTER persist_floor_or_recover() below would be
       * too late: the mutation (and persist_floor()'s own erase of
       * whichever slot it targets) would already be durably committed
       * by the time any failure here could be noticed, and a genuinely
       * role-unproven/damaged device could have a replacement-role
       * loader's reconstruction request silently stamp a floor onto
       * history that was never actually certified for it. Require
       * verified role evidence to already exist in at least one
       * physical window BEFORE any reconstruction write is attempted --
       * exactly like the final gate below, but moved ahead of this
       * specific mutation path, which that final gate (applied only
       * after this whole block runs) cannot retroactively undo. A
       * genuine read failure fails closed to Recovery, identically to
       * every other IO_ERROR path in this function; an ordinary
       * absent/non-verifying receipt (e.g. a legacy device whose floor
       * pair was damaged AND both activation windows are also lost)
       * fails closed the same way -- conservatively RoleUnproven, never
       * inferred from the floor/state/loader/command alone. */
      bool role_io_error = false;
      if (!floor_role_evidence_ok(io, &role_io_error)) {
        goto recover;
      }
      /* Mutate the already-read `floor` record in place rather than
       * building a separate zeroed copy: when !have_floor it was
       * already memset to all-zero by the DAMAGED/MISSING switch case
       * above (sequence==0, safe for persist_floor()'s +1 write for a
       * genuinely blank MISSING pair -- there is no other slot's
       * sequence to out-rank there), and when have_floor it already
       * holds a fully valid record whose other fields (sequence,
       * magic, etc.) are exactly what should be carried forward
       * unchanged -- only the three fields below need to change either
       * way.
       *
       * The DAMAGED case is different from MISSING: one physical slot
       * (floor_a or floor_b) is ALREADY a durable, structurally valid,
       * lower-counter record that persist_floor() -- via the
       * out_holder_address fix above -- will target the OTHER
       * (genuinely bad) slot to repair, leaving that existing good
       * slot as-is. For the newly-repaired record to actually be
       * recognised as the newer of the pair on the NEXT boot's
       * ordinary "both valid" comparison (which trusts sequence, not
       * confirmed_counter_floor, to rank the two slots), it must carry
       * a sequence number that out-ranks the surviving good slot's own
       * -- sequence==0 would instead let a good slot with any nonzero
       * prior sequence keep winning, silently resurrecting the stale,
       * lower floor forever. Read that good slot's own sequence field
       * directly (read_pair() does not preserve it in `floor` on a
       * DAMAGED return) so persist_floor()'s unconditional `+1`
       * dominates it. */
      if (!have_floor && floor_status == XIAO_OTA_PAIR_DAMAGED) {
        const xiao_ota_floor_t *surviving =
            xiao_ota_floor_valid(&floor_a)
                ? &floor_a
                : (xiao_ota_floor_valid(&floor_b) ? &floor_b : NULL);
        if (surviving != NULL) {
          /* The surviving slot's own confirmed_counter_floor is itself
           * durable anti-rollback history -- CONFIRMED state's
           * candidate_counter dominating it is what earns the repair,
           * not the other way around. A surviving floor at or above
           * state.candidate_counter is conflicting proof (e.g. the
           * confirmed state record is itself stale relative to a
           * higher floor already reached and durably recorded on the
           * surviving slot): repairing DOWN to (or merely equal to)
           * it would silently discard real, already-durable
           * anti-rollback history. Refuse any mutation and fail closed
           * via Recovery instead, exactly like every other conflicting-
           * proof case in this function. */
          if (state.candidate_counter <= surviving->confirmed_counter_floor) {
            goto recover;
          }
          floor.sequence = surviving->sequence;
        }
      }
      floor.confirmed_counter_floor = state.candidate_counter;
      floor.active_image_extent = expected_active_extent;
      memcpy(floor.confirmed_hash_sha256, state.candidate_hash_sha256, 32);
      if (!persist_floor_or_recover(io, &floor, &floor_slot_address)) return;
      have_floor = true;
      floor_trustworthy = true;
    }
    /* If the fresh verification does not agree, deliberately leave floor/
     * floor_trustworthy exactly as read_pair() produced them -- fail
     * closed (refuse new admission below) rather than ever repairing
     * from an unverified assumption. */
  }
  /* Final, unconditional role-continuity gate: applies to EVERY path
   * that could have left floor_trustworthy true above -- a direct
   * floor>0 XIAO_OTA_PAIR_FOUND read (which, unlike the genesis/floor==0
   * case, never itself checks a receipt), AND the CONFIRMED-state
   * repair block just above (which rebuilds floor from state.candidate_
   * counter/hash/extent with no role check of its own either). Without
   * this, a physically swapped, differently-role-compiled loader binary
   * could silently inherit an existing confirmed floor/anti-rollback
   * history that was only ever genesis-certified for the OTHER role,
   * admitting a validly signed install command for ITS OWN compiled
   * role even though THIS device's durable history belongs to the
   * other one -- the install-command's own role_id check alone cannot
   * catch that, since a genuinely signed command for the new compiled
   * role passes it trivially. A floor==0 genesis record that already
   * passed its own (strictly stronger, content-binding) receipt check
   * above trivially passes this too; nothing here weakens that path.
   *
   * Terminal, not a soft demotion: missing, corrupt, wrong-role or
   * conflicting receipt evidence (or either required window read
   * failing) must stop this boot in Recovery with nothing further
   * mutated -- not merely clear floor_trustworthy and fall through to
   * "refuse new admission" below. A soft demotion still lets an
   * already-ACTIVE/TRIAL transaction's resume logic (further down,
   * keyed off this same floor_trustworthy flag) quietly reinterpret
   * the failure as an ordinary "command no longer matches" and drive
   * a ROLLBACK_COPYING state-persist of its own -- a real mutation,
   * and not the externally-visible Recovery escalation a genuine
   * role/history conflict demands. force_recovery() every time this
   * check itself fails, exactly like the equivalent gate already does
   * inside the CONFIRMED-state repair block above. */
  if (floor_trustworthy) {
    bool role_io_error = false;
    if (!floor_role_evidence_ok(io, &role_io_error)) {
      (void)role_io_error;
      goto recover;
    }
  }
  if (xiao_ota_command_acceptable_phase(have_state, (xiao_ota_phase_t)state.phase)) {
    if (!floor_trustworthy || !have_active_extent ||
        !command_policy_valid(io, &command, floor.confirmed_counter_floor,
                              expected_active_extent, &intent)) {
      return;
    }
    /* Refuse a byte-identical retry of an already-FAILED (rolled-back)
     * transaction: its counter never advanced the floor, so it still
     * verifies every boot; without this it would silently reinstall and
     * fail forever. A genuinely different (new nonce/counter/hash) signed
     * command is untouched by this check and proceeds normally below. */
    if (xiao_ota_command_is_retry_of_failed_transaction(
            have_state, (xiao_ota_phase_t)state.phase, state.transaction_nonce,
            state.candidate_counter, state.candidate_hash_sha256,
            intent.transaction_nonce, intent.monotonic_counter,
            intent.image_hash_sha256)) {
      return;
    }
    if (!hash_qspi(io, XIAO_OTA_CANDIDATE_BASE, intent.image_size_bytes, digest) ||
        !all_equal(digest, intent.image_hash_sha256)) {
      return;
    }
    if (!hash_internal(io, XIAO_OTA_APP_START, intent.active_image_extent, digest) ||
        !all_equal(digest, intent.active_image_hash_sha256)) {
      return;
    }
    {
      /* Confirm the settings page's unused tail is genuinely blank BEFORE
       * any destructive work (backup copy, candidate install) starts for
       * this transaction -- not only later, inside finalize/rollback's
       * own settings_write_raw() call. Checking this only at finalize
       * time let an already-poisoned tail strand a transaction mid-way
       * (candidate/backup already mutated, then BOTH the install and the
       * rollback settings write refused) instead of refusing the fresh
       * admission outright with nothing touched yet.
       *
       * Unlike every OTHER admission check above (unsigned/stale/
       * mismatched command -- all perfectly ordinary "nothing to do this
       * boot, retry later" outcomes needing no diagnostic), an unreadable
       * or genuinely non-blank tail here means something already wrote
       * into a reserved, supposedly-untouched area of the settings page
       * outside this transaction's own admission -- a device anomaly, not
       * a routine "no acceptable command" outcome. Silently `return`ing
       * here would let the device boot the running app as if nothing
       * were wrong, indistinguishable from an ordinary unsigned-command
       * boot, hiding that anomaly. force_recovery() instead gives an
       * explicit, externally observable diagnostic (the same USB UF2/CDC
       * recovery escalation used for every other fail-closed case in this
       * function) -- nothing has been mutated yet, so this is still a
       * safe, non-destructive refusal; it is simply not a silent one. */
      bool tail_blank;
      if (!settings_page_tail_erased(io, &tail_blank) || !tail_blank) {
        goto recover;
      }
    }
    {
      /*
       * Preserve the durable A/B sequence counter across transactions --
       * memset-ing it to 0 here would make this transaction's first write
       * restart from sequence 1 (always the same fixed slot), which can
       * collide with an equal-or-higher stale sequence number still
       * sitting in the OTHER slot from an earlier transaction and cause
       * xiao_ota_newest_valid() to pick the wrong (stale) record on the
       * very next boot. The counter is purely a monotonic slot-alternator
       * here, not part of any transaction's identity, so carrying it
       * forward is always safe.
       */
      uint32_t previous_sequence = state.sequence;
      memset(&state, 0, sizeof(state));
      state.sequence = previous_sequence;
    }
    state.transaction_nonce = intent.transaction_nonce;
    state.phase = XIAO_OTA_PHASE_BACKUP_COPYING;
    state.active_image_extent = intent.active_image_extent;
    state.candidate_counter = intent.monotonic_counter;
    {
      /*
       * Capture the ENTIRE current settings page once, right here at
       * admission (after every fresh-bank/hash/policy check above has
       * already passed) -- both the three legacy state fields (kept for
       * ABI compatibility and as a cheap consistency cross-check) and the
       * full 28-byte frozen snapshot the sidecar carries forward for this
       * transaction's eventual install or rollback. Neither the install
       * nor the rollback path may re-read "current" settings later: this
       * is the one and only admission-time read.
       */
      xiao_ota_settings_raw_t admission_raw;
      if (!settings_read_raw(io, &admission_raw)) return;
      state.previous_bank_0 = admission_raw.bank_0;
      state.previous_bank_0_crc = admission_raw.bank_0_crc;
      state.previous_bank_0_size = admission_raw.bank_0_size;
      memset(&sidecar, 0, sizeof(sidecar));
      sidecar.matching_state_sequence = state.sequence;
      sidecar.transaction_nonce = intent.transaction_nonce;
      hash_command_digest(&command, sidecar.command_digest_sha256);
      memcpy(sidecar.original_settings_raw, &admission_raw,
            sizeof(sidecar.original_settings_raw));
    }
    memcpy(state.candidate_hash_sha256, intent.image_hash_sha256, 32);
    memcpy(state.backup_hash_sha256, intent.active_image_hash_sha256, 32);
    /*
     * Nothing destructive has happened yet for this transaction -- a
     * failed FIRST persist here just means the signed command is refused
     * for this boot cycle, untouched, and can be retried next boot. No
     * force_recovery() escalation is needed or safe to assume yet.
     */
    if (!persist_state(io, &state, &sidecar, &state_slot_address)) return;
  }

  if (state.phase == XIAO_OTA_PHASE_BACKUP_COPYING) {
    if (!active_image_extent_bounded(state.active_image_extent) ||
        !progress_bytes_consistent(state.progress_bytes, state.active_image_extent)) {
      goto recover;
    }
    if (!copy_internal_to_qspi(io, &state, &sidecar, &state_slot_address)) {
      goto recover;
    }
    if (!hash_qspi(io, XIAO_OTA_BACKUP_BASE, state.active_image_extent, digest) ||
        !all_equal(digest, state.backup_hash_sha256)) {
      goto recover;
    }
    state.phase = XIAO_OTA_PHASE_BACKUP_READY;
    state.progress_bytes = 0;
    if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
  }
  if (state.phase == XIAO_OTA_PHASE_BACKUP_READY ||
      state.phase == XIAO_OTA_PHASE_INSTALL_COPYING) {
    /* have_active_extent is re-checked explicitly (not just relying on the
     * expected_active_extent==0 default) so a bank-0 metadata failure mid-
     * transaction always rolls back, defense-in-depth alongside the
     * initial acceptance gate above. */
    if (!floor_trustworthy || !have_active_extent ||
        !command_policy_valid(io, &command, floor.confirmed_counter_floor,
                              expected_active_extent, &intent) ||
        intent.transaction_nonce != state.transaction_nonce ||
        !all_equal(intent.image_hash_sha256, state.candidate_hash_sha256)) {
      state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
      state.progress_bytes = 0;
      if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
    }
    if (state.phase != XIAO_OTA_PHASE_ROLLBACK_COPYING &&
        !progress_bytes_consistent(state.progress_bytes, intent.image_size_bytes)) {
      goto recover;
    }
    if (state.phase != XIAO_OTA_PHASE_ROLLBACK_COPYING &&
        state.progress_bytes == 0) {
      if (!hash_qspi(io, XIAO_OTA_CANDIDATE_BASE, intent.image_size_bytes, digest) ||
          !all_equal(digest, state.candidate_hash_sha256)) {
        state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
        if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
      }
    }
    if (state.phase != XIAO_OTA_PHASE_ROLLBACK_COPYING) {
      state.phase = XIAO_OTA_PHASE_INSTALL_COPYING;
      if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
      if (!copy_qspi_to_internal(io, &state, &sidecar, &state_slot_address, XIAO_OTA_CANDIDATE_BASE,
                                 intent.image_size_bytes)) {
        state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
        state.progress_bytes = 0;
        if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
      } else if (!finalize_install_and_verify(io, &state, &sidecar,
                                              intent.image_size_bytes,
                                              digest)) {
        state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
        state.progress_bytes = 0;
        if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
      } else {
        state.phase = XIAO_OTA_PHASE_TRIAL_BOOT;
        state.progress_bytes = 0;
        state.trial_attempts = 0;
        if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
        io->start_trial_watchdog(io->ctx);
        return;
      }
    }
  }

  confirmed = read_pair(io, XIAO_OTA_CONFIRM_A, XIAO_OTA_CONFIRM_B,
                        XIAO_OTA_CONFIRM_A, XIAO_OTA_CONFIRM_B,
                        XIAO_OTA_SHARED_TAIL_NONE,
                        &confirm_a, &confirm_b, sizeof(confirmation),
                        offsetof(xiao_ota_confirmation_t, commit_marker),
                        (bool (*)(const void *))xiao_ota_confirmation_valid,
                        &confirmation, NULL, NULL, NULL, NULL) ==
              XIAO_OTA_PAIR_FOUND &&
              xiao_ota_confirmation_matches(&state, &confirmation);
  if (state.phase == XIAO_OTA_PHASE_TRIAL_BOOT && confirmed) {
    /* Never advance the floor on the confirmation token alone. Re-derive a
     * FRESH extent from bank-0 right now (not intent, which reflects
     * whatever the command slot currently decodes to and may have been
     * overwritten since the trial started) and recompute a live SHA-256
     * over internal flash at that fresh extent. installed_hash_sha256 was
     * computed over exactly candidate_size bytes at install time, so it
     * cryptographically binds BOTH the new image's content and its exact
     * length -- a fresh hash at any OTHER extent essentially never
     * reproduces that digest (SHA-256 pre-image resistance), so a match
     * alone verifies the fresh extent equals the original candidate size
     * without any separate durable extent field. This never compares
     * against state.active_image_extent, which is the OLD image's extent
     * and must stay untouched for a correctly-sized rollback restore. This
     * is what actually rejects a USB/CDC reflash (or flash damage) during
     * the trial window that a transport-level confirmation match alone
     * cannot detect. */
    uint32_t fresh_extent = 0;
    bool fresh_active_extent_valid =
        active_extent_from_settings(io, &fresh_extent);
    bool fresh_hash_ok = fresh_active_extent_valid &&
        hash_internal(io, XIAO_OTA_APP_START, fresh_extent, digest);
    /* Every CONFIRMED route -- fresh advance AND idempotent resume alike
     * -- requires the SAME live verification: fresh bytes hash to BOTH
     * installed_hash_sha256 and candidate_hash_sha256 (they must always
     * agree by construction; both are re-checked independently here, not
     * assumed) at a fresh, bounded, non-zero extent. */
    bool triple_bound_ok = fresh_hash_ok &&
        xiao_ota_confirmation_hash_bound_extent_valid(
            fresh_active_extent_valid, fresh_extent,
            XIAO_OTA_INSTALL_MAX_SIZE, digest, state.installed_hash_sha256) &&
        all_equal(digest, state.candidate_hash_sha256);

    if (!floor_trustworthy) {
      /*
       * A floor that failed structural validation this boot (torn write,
       * bit rot, or pre-OTA leftover data) and isn't genuinely blank must
       * never be claimed/overwritten by finishing this confirmation.
       */
      state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
      state.progress_bytes = 0;
      if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
    } else if (have_floor && floor.confirmed_counter_floor == state.candidate_counter) {
      if (!all_equal(floor.confirmed_hash_sha256, state.candidate_hash_sha256)) {
        /*
         * Genuine identity conflict: the durable floor already claims
         * this exact counter value for a DIFFERENT image than this
         * transaction's own candidate. This must never be resolved as
         * either confirmed (it does not match the floor) or rolled back
         * (this transaction's stashed backup reference may not describe
         * whatever is genuinely running right now) -- escalate without
         * touching floor or live flash.
         */
        goto recover;
      }
      if (triple_bound_ok && floor.active_image_extent == fresh_extent) {
        /*
         * Idempotent resume: a previous boot already durably advanced the
         * floor for THIS exact transaction but crashed before persisting
         * state=CONFIRMED. Still require the SAME fresh verification as
         * every other CONFIRMED route above before finishing -- an
         * already-matching floor record is not on its own sufficient
         * proof of what is actually running right now (e.g. a USB reflash
         * between the floor cut and this boot). The floor's own
         * active_image_extent must ALSO agree with the freshly verified
         * live extent -- counter and hash matching alone is not full
         * floor identity, and a floor whose extent field disagrees with
         * a hash/counter it otherwise matches is internally inconsistent
         * committed metadata, not something safe to finish over. Finish
         * without re-deriving or rewriting the floor -- it is already
         * correct.
         */
        state.phase = XIAO_OTA_PHASE_CONFIRMED;
        if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
        return;
      }
      if (triple_bound_ok) {
        /*
         * Counter and hash match the floor, live image verifies fine, but
         * the floor's OWN active_image_extent field disagrees with the
         * freshly verified extent -- an inconsistent committed floor
         * record. This is neither a clean confirm (the floor's own extent
         * doesn't back it up) nor a safe rollback (this transaction's
         * stashed backup reference may not describe whatever is genuinely
         * running right now) -- escalate without touching floor or live
         * flash, exactly like a hash conflict.
         */
        goto recover;
      }
      /* Floor already matches this transaction's identity, but what is
       * actually running right now does not verify -- do not trust the
       * previously-advanced floor alone. */
      state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
      state.progress_bytes = 0;
      if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
    } else if (have_floor && floor.confirmed_counter_floor > state.candidate_counter) {
      /*
       * A DIFFERENT, later transaction has already durably confirmed a
       * higher counter -- the image genuinely running right now is
       * presumably that newer, already-confirmed install. Rolling back
       * using THIS stale transaction's own stashed active_image_extent/
       * backup_hash_sha256 (captured at ITS acceptance time, describing
       * whatever was running before IT installed) would destructively
       * revert a possibly-good newer running image using the wrong
       * reference point. Retire this superseded transaction record
       * without touching live flash at all.
       */
      state.phase = XIAO_OTA_PHASE_FAILED;
      if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
      return;
    } else if (triple_bound_ok) {
      floor.confirmed_counter_floor = state.candidate_counter;
      floor.active_image_extent = fresh_extent;
      memcpy(floor.confirmed_hash_sha256, state.candidate_hash_sha256, 32);
      if (!persist_floor_or_recover(io, &floor, &floor_slot_address)) return;
      state.phase = XIAO_OTA_PHASE_CONFIRMED;
      if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
      return;
    } else {
      /* Confirmation token matched at the transport layer, but what is
       * actually running right now does not match what was installed and
       * verified (or couldn't be read at all) -- treat exactly like a
       * failed/un-confirmable trial and fall through to the existing,
       * already-safe rollback path instead of ever trusting this state as
       * confirmed. */
      state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
      state.progress_bytes = 0;
      if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
    }
  } else if (state.phase == XIAO_OTA_PHASE_TRIAL_BOOT) {
    state.trial_attempts++;
    if (state.trial_attempts < XIAO_OTA_MAX_TRIAL_BOOTS) {
      if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
      io->start_trial_watchdog(io->ctx);
      return;
    }
    state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
    state.progress_bytes = 0;
    if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
  }
  if (state.phase == XIAO_OTA_PHASE_ROLLBACK_COPYING) {
    if (!active_image_extent_bounded(state.active_image_extent) ||
        !progress_bytes_consistent(state.progress_bytes, state.active_image_extent)) {
      goto recover;
    }
    /* Authenticate the backup itself BEFORE further destructive live
     * erases, on EVERY boot that (re)enters/resumes this phase -- not
     * only the very first entry: a resumed rollback must not assume a
     * backup verified on an earlier boot is still intact now. If the
     * backup is not intact, erasing more of the live (broken/
     * unconfirmed) app region would destroy the last good copy of
     * anything with no way back -- escalate to recovery instead. */
    if (!hash_qspi(io, XIAO_OTA_BACKUP_BASE, state.active_image_extent, digest) ||
        !all_equal(digest, state.backup_hash_sha256)) {
      goto recover;
    }
    if (!copy_qspi_to_internal(io, &state, &sidecar, &state_slot_address, XIAO_OTA_BACKUP_BASE,
                               state.active_image_extent)) {
      goto recover;
    }
    if (!hash_internal(io, XIAO_OTA_APP_START, state.active_image_extent, digest) ||
        !all_equal(digest, state.backup_hash_sha256)) {
      goto recover;
    }
    if (!xiao_ota_settings_restore_raw(io, sidecar.original_settings_raw)) {
      goto recover;
    }
    state.phase = XIAO_OTA_PHASE_FAILED;
    if (!persist_state_or_recover(io, &state, &sidecar, &state_slot_address)) return;
    return;
  }
  if (state.phase == XIAO_OTA_PHASE_FAILED) return;
recover:
  io->force_recovery(io->ctx);
}
