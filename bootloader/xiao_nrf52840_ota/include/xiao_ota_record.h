#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define XIAO_OTA_RECORD_MAGIC          UINT32_C(0x584F5441)
#define XIAO_OTA_CONFIRM_MAGIC         UINT32_C(0x58434E46)
#define XIAO_OTA_FLOOR_MAGIC           UINT32_C(0x58464C52)
#define XIAO_OTA_FORMAT_VERSION        1u
#define XIAO_OTA_DESCRIPTOR_FORMAT     1u
#define XIAO_OTA_KEY_ID                1u
#define XIAO_OTA_ALGORITHM_ED25519     1u
#define XIAO_OTA_TARGET_XIAO_NRF52840  UINT32_C(0x584E3430)
#define XIAO_OTA_ROLE_ANY              UINT32_C(0)
#define XIAO_OTA_CAP_QSPI_INSTALL      UINT32_C(1)
/*
 * The transport's canonical descriptor (src/ota/protocol/OtaDescriptor.h)
 * splits this same 32-bit target identity into two big-endian 16-bit wire
 * fields: boardFamily (high 16 bits) and boardVariant (low 16 bits). Derived
 * from XIAO_OTA_TARGET_XIAO_NRF52840 so the two can never drift apart.
 */
#define XIAO_OTA_BOARD_FAMILY_XIAO_NRF52840 \
  ((uint16_t)(XIAO_OTA_TARGET_XIAO_NRF52840 >> 16))
#define XIAO_OTA_BOARD_VARIANT_XIAO_NRF52840 \
  ((uint16_t)(XIAO_OTA_TARGET_XIAO_NRF52840 & 0xFFFFu))

/*
 * SenseCAP Solar P1 board profile. This is a LOGICAL, build-time-selectable
 * target identity only -- a distinct value so a XIAO-signed image can never
 * be accepted on a SenseCAP-profiled boot (and vice versa), per the shared
 * P25Q16H/pinout hardware class. It is NOT backed by any physical build or
 * bench test in this repository: there is no distinct upstream
 * Adafruit_nRF52_Bootloader BOARD= definition for it here, and this
 * bootloader overlay has never been compiled, flashed, or exercised for a
 * real SenseCAP Solar P1 device. Selecting this profile only changes which
 * XIAO_OTA_BOARD_TARGET value this bootloader's policy check compiles
 * against (see below); it is a real, distinct, non-wildcard identity, never
 * a permissive/"matches anything" (e.g. 0xFFFFFFFF) anchor. Treat any
 * artifact built with this profile as unqualified for real hardware until a
 * verified SenseCAP-specific bench test exists.
 */
#define XIAO_OTA_TARGET_SENSECAP_SOLAR_P1 UINT32_C(0x53435031) /* "SCP1" */
#define XIAO_OTA_BOARD_FAMILY_SENSECAP_SOLAR_P1 \
  ((uint16_t)(XIAO_OTA_TARGET_SENSECAP_SOLAR_P1 >> 16))
#define XIAO_OTA_BOARD_VARIANT_SENSECAP_SOLAR_P1 \
  ((uint16_t)(XIAO_OTA_TARGET_SENSECAP_SOLAR_P1 & 0xFFFFu))

/*
 * The board profile this specific bootloader binary was compiled to accept.
 * Defaults to the XIAO nRF52840 target; a build may override it (e.g.
 * `-DXIAO_OTA_BOARD_TARGET=XIAO_OTA_TARGET_SENSECAP_SOLAR_P1`) to compile a
 * profile-distinct binary for a different board in the same hardware class.
 * command_policy_valid() checks against this exact value, never a wildcard.
 */
#ifndef XIAO_OTA_BOARD_TARGET
#define XIAO_OTA_BOARD_TARGET XIAO_OTA_TARGET_XIAO_NRF52840
#endif

/*
 * This specific bootloader binary's compiled role identity: 0 (companion)
 * or 1 (repeater). This is a build-time-fixed, non-wildcard identity
 * exactly like XIAO_OTA_BOARD_TARGET above -- a role-1 binary accepts ONLY
 * role-1 install commands (xiao_ota_install_command_static_identity_valid()),
 * never role 0, and vice versa. There is no runtime role inference from
 * persisted state, and no "accepts either role" build: exactly one of
 * {0, 1} is compiled in, checked below by _Static_assert. Defaults to 0
 * (companion) so every existing build, signed artifact, and test that
 * predates role support keeps behaving identically. XIAO_OTA_ROLE_ANY
 * (above) is kept as the historical wire constant for the companion role's
 * own value (0) -- it was never actually a wildcard in the live policy
 * check, and still is not; it must never be redefined to 1 or
 * reinterpreted as "matches any role".
 */
#ifndef XIAO_OTA_COMPILED_ROLE_ID
#define XIAO_OTA_COMPILED_ROLE_ID UINT32_C(0)
#endif
_Static_assert(XIAO_OTA_COMPILED_ROLE_ID == 0u || XIAO_OTA_COMPILED_ROLE_ID == 1u,
              "XIAO_OTA_COMPILED_ROLE_ID must be exactly 0 (companion) or 1 "
              "(repeater) -- no other role is implemented or accepted, and "
              "there is no wildcard/any-role build.");

/* Command record version (xiao_ota_command_v2_t.record_version). NOT the
 * same field as XIAO_OTA_FORMAT_VERSION, which is the fixed version for
 * state/confirmation/floor records and must never change. The legacy
 * 71-byte little-endian command format (record_version 1) has been
 * removed: this is an unreleased lab prototype with no external deployed
 * artifacts, so there is no compatibility obligation to keep it. Every
 * install command is the transport's own 59-byte big-endian canonical
 * wire descriptor + 64-byte Ed25519 signature, reused byte-for-byte from
 * src/ota/protocol/OtaDescriptor.h, PLUS the 32-byte app-admitted signer
 * public key that authenticates it (added at record_version 3: the prior
 * record_version 2 shape, with no admitted-key field and a compile-time
 * fixed trust anchor instead, is also retired -- same no-deployed-
 * artifacts rationale). */
#define XIAO_OTA_COMMAND_VERSION_CURRENT   3u
#define XIAO_OTA_COMMIT_MARKER         UINT32_C(0x434F4D54)
/* NOR flash program operations only ever clear bits (1 -> 0); a genuinely
 * erased 4-byte marker field therefore always reads back as all-1s. Any
 * record writer that has not yet begun programming its commit_marker
 * field (see write_body_then_marker() in xiao_ota_boot_io.c) leaves it
 * at exactly this value -- the ONLY marker value that proves the
 * marker-write step has not started yet. */
#define XIAO_OTA_MARKER_ERASED         UINT32_C(0xFFFFFFFF)
#define XIAO_OTA_MAX_TRIAL_BOOTS       3u
#define XIAO_OTA_DFU_MAGIC_OTA_APPJUM  UINT32_C(0xB1)
#define XIAO_OTA_DFU_MAGIC_OTA_RESET   UINT32_C(0xA8)
#define XIAO_OTA_DFU_MAGIC_SERIAL      UINT32_C(0x4E)
#define XIAO_OTA_DFU_MAGIC_UF2         UINT32_C(0x57)

typedef enum {
  XIAO_OTA_PHASE_EMPTY = 0,
  XIAO_OTA_PHASE_REQUESTED = 1,
  XIAO_OTA_PHASE_BACKUP_COPYING = 2,
  XIAO_OTA_PHASE_BACKUP_READY = 3,
  XIAO_OTA_PHASE_INSTALL_COPYING = 4,
  XIAO_OTA_PHASE_TRIAL_BOOT = 5,
  XIAO_OTA_PHASE_CONFIRMED = 6,
  XIAO_OTA_PHASE_ROLLBACK_COPYING = 7,
  XIAO_OTA_PHASE_FAILED = 8,
} xiao_ota_phase_t;

#if defined(__GNUC__)
#define XIAO_OTA_PACKED __attribute__((packed))
#else
#define XIAO_OTA_PACKED
#endif

/*
 * Portable codec for the LoRa OTA transport's canonical signed descriptor
 * (src/ota/protocol/OtaDescriptor.h: OtaDescriptor /
 * encodeOtaDescriptorCanonical / kOtaDescriptorCanonicalSize). This
 * bootloader has no build dependency on the src/ota tree (it must build
 * fully
 * standalone inside the vendored Adafruit bootloader tree), so the field
 * layout and big-endian byte order are independently reimplemented here --
 * they MUST stay byte-for-byte identical to that module. Cross-checked
 * against real golden vectors produced by the actual protocol encoder in
 * tests/test_descriptor_contract.c.
 *
 * Field order, all big-endian, no padding:
 *   boardFamily u16, boardVariant u16, role u8, appAddress u32,
 *   exactSizeBytes u32, sha256[32], securityCounter u32,
 *   minBootloaderCapabilities u32, formatId u16, keyId u16, algorithmId u16.
 * Total: 2+2+1+4+4+32+4+4+2+2+2 = 59 bytes.
 */
#define XIAO_OTA_WIRE_DESCRIPTOR_SIZE 59u

typedef struct {
  uint16_t board_family;
  uint16_t board_variant;
  uint8_t role;
  uint32_t app_address;
  uint32_t exact_size_bytes;
  uint8_t sha256[32];
  uint32_t security_counter;
  uint32_t min_boot_capabilities;
  uint16_t format_id;
  uint16_t key_id;
  uint16_t algorithm_id;
} xiao_ota_wire_descriptor_t;

/* Encodes into exactly XIAO_OTA_WIRE_DESCRIPTOR_SIZE big-endian bytes. */
void xiao_ota_wire_descriptor_encode(const xiao_ota_wire_descriptor_t *d,
                                     uint8_t out[XIAO_OTA_WIRE_DESCRIPTOR_SIZE]);

/*
 * Decodes `in` into `out`. This fixed-width, big-endian, unpadded format
 * has no reserved/ignored bits and no field narrower than the bytes it
 * consumes (get_be16/get_be32/memcpy read every input bit into some
 * decoded field), so decode is total and lossless: every possible 59-byte
 * input has exactly one decoding, and re-encoding that decoding always
 * reproduces `in` byte-for-byte (proved exhaustively, one bit at a time,
 * by test_record.c's all-472-bits round-trip coverage). Decode therefore
 * always returns true; it keeps a bool return (rather than void) only so
 * existing `if (!xiao_ota_wire_descriptor_decode(...)) return false;`
 * call sites keep working unchanged if a future format revision ever
 * introduces a real rejection case (e.g. padded/variable-width fields).
 * Authenticity/tamper-rejection is NOT this function's job: a corrupted
 * wire descriptor is caught by Ed25519 signature verification over the
 * raw 59 bytes (see xiao_ota_install_command_policy_valid()), not by
 * decode() itself -- decode() cannot distinguish a legitimate field value
 * from a corrupted one that merely decodes differently.
 */
bool xiao_ota_wire_descriptor_decode(const uint8_t in[XIAO_OTA_WIRE_DESCRIPTOR_SIZE],
                                     xiao_ota_wire_descriptor_t *out);

/*
 * Command: the sole supported install-command format. Authenticates the
 * transport's own 59-byte canonical wire descriptor and Ed25519
 * signature directly -- the SAME bytes and the SAME signature the LoRa
 * OTA transport already verified (see src/helpers/ota/OtaFirmwareBackend.h /
 * src/ota/trust/DescriptorVerifier.h), never re-derived or re-signed into
 * another form. The wire descriptor carries no per-device targeting field,
 * so a command is always installable on any device that otherwise
 * matches target/role/app_address/counter/capability policy (see
 * xiao_ota_install_command_policy_valid(); device_address is forced to 0
 * and allow_broadcast_address to 1 when decoding a command --
 * xiao_ota_install_command_from_v2() -- those two fields are NOT signed
 * input, so they can never be attacker-influenced).
 *
 * admitted_signer_public_key_ed25519 is the Ed25519 public key the
 * CURRENTLY RUNNING (trusted) app already verified the manifest signer
 * against, using the app's own pre-existing MeshCore admin-identity trust
 * mechanism (entirely outside this bootloader -- there is no separate
 * bootloader-side ACL/issuer/grant/attestation hierarchy and no shared
 * admin private key here). The app durably snapshots this key, alongside
 * the signed manifest, into the command record at the explicit COMMIT
 * step. The bootloader's job is narrower: re-verify that
 * signature_ed25519 is a valid Ed25519 signature over wire_descriptor
 * under EXACTLY this embedded key (cryptographic self-consistency of the
 * durable record), plus the existing anti-rollback/model/size/geometry
 * checks -- it does NOT independently judge whether this key "is an
 * admin"; that decision was already made, once, by the running app
 * before COMMIT. This is the documented local-failure trust boundary
 * (protects against accidental corruption of the durable record across a
 * power-fail, not against a physical attacker with direct flash-write
 * access -- see xiao_ota_install_command_policy_valid()'s doc-comment and
 * the counter-floor anti-replay check, which is what actually prevents a
 * stale command -- signed under a previously-admitted but since-rotated
 * key -- from being reinstalled).
 *
 * The legacy 71-byte little-endian v1 command format, and the prior
 * record_version 2 shape (same 59-byte wire descriptor, but with a
 * compile-time fixed trust anchor instead of this field), have both been
 * removed (unreleased lab prototype, no external deployed artifacts to
 * stay compatible with); "v2"/"_v2" naming on the struct/function names
 * below is kept only to avoid a pointless mechanical rename of every call
 * site, not because another version exists.
 */
typedef struct XIAO_OTA_PACKED {
  uint32_t magic;
  uint16_t record_version; /* always XIAO_OTA_COMMAND_VERSION_CURRENT (3) */
  uint16_t record_bytes;
  uint32_t sequence;
  uint64_t transaction_nonce;
  uint8_t wire_descriptor[XIAO_OTA_WIRE_DESCRIPTOR_SIZE];
  uint8_t admitted_signer_public_key_ed25519[32];
  uint8_t signature_ed25519[64];
  uint32_t active_image_extent;
  uint8_t active_image_hash_sha256[32];
  uint8_t reserved;
  uint32_t crc32;
  uint32_t commit_marker;
} xiao_ota_command_v2_t;

/* Alias kept so existing call sites that read/validate a command slot
 * generically (before its bytes are known-good) keep working unchanged;
 * there is only one command record type now. */
typedef xiao_ota_command_v2_t xiao_ota_command_any_t;

/*
 * Fully decoded install intent, populated from xiao_ota_command_v2_t
 * (the transport's 59-byte big-endian wire descriptor) so all downstream
 * policy checks (xiao_ota_install_command_policy_valid()) are written
 * exactly once.
 */
typedef struct {
  uint64_t transaction_nonce;
  uint32_t target_id;
  uint32_t role_id;
  uint64_t device_address;
  uint8_t allow_broadcast_address;
  uint32_t required_boot_capability_flags;
  uint32_t monotonic_counter;
  uint32_t image_size_bytes;
  uint32_t app_address;
  uint16_t format_id;
  uint16_t key_id;
  uint16_t algorithm_id;
  uint8_t image_hash_sha256[32];
  uint32_t active_image_extent;
  uint8_t active_image_hash_sha256[32];
} xiao_ota_install_command_t;

bool xiao_ota_command_v2_valid(const xiao_ota_command_v2_t *record);
/* record must point to XIAO_OTA_COMMAND_ANY-sized storage. Equivalent to
 * xiao_ota_command_v2_valid() (kept as a distinct name since callers use
 * it generically, before deciding to trust the record at all). */
bool xiao_ota_command_any_valid(const void *record);
bool xiao_ota_install_command_from_v2(const xiao_ota_command_v2_t *cmd,
                                      xiao_ota_install_command_t *out);
/* Equivalent to xiao_ota_install_command_from_v2(). */
bool xiao_ota_install_command_decode(const xiao_ota_command_any_t *any,
                                     xiao_ota_install_command_t *out);
/*
 * The STATIC subset of xiao_ota_install_command_policy_valid()'s checks:
 * target/role/app_address/format/key/algorithm ids, required capability
 * bit, image size bounds, active (backup) image extent bounds (NOT its
 * match against a currently-installed extent -- that is context-
 * dependent, see below), and device targeting (exact match, or
 * broadcast). Every one of these is a property of the command's OWN
 * decoded fields alone, true or false independent of the CURRENT durable
 * floor/active-extent this boot happens to have -- unlike
 * monotonic_counter<=counter_floor and active_image_extent!=
 * expected_active_extent, which only ever make sense as a check against
 * THIS boot's live admission context. This split exists so a HISTORICAL
 * command (one already superseded by a later admission, whose bytes are
 * still physically present) can still be proven "was this ever a
 * legitimately-targeted, well-formed, signed-for-this-device command"
 * without requiring it to also satisfy a floor/extent context it was
 * never evaluated against in the first place. Does NOT verify the
 * Ed25519 signature -- callers must do that separately over the exact
 * signed bytes, under the command's own admitted_signer_public_key_
 * ed25519, before trusting this result.
 */
bool xiao_ota_install_command_static_identity_valid(
    const xiao_ota_install_command_t *cmd, uint64_t this_device_address);
/*
 * All non-cryptographic install policy checks: everything
 * xiao_ota_install_command_static_identity_valid() checks, PLUS the two
 * context-dependent checks only meaningful against THIS boot's live
 * admission state: anti-rollback counter vs. durable floor, and active
 * (backup) image extent match against the currently-installed extent.
 * Does NOT verify the Ed25519 signature -- callers must do that
 * separately over the exact signed bytes before trusting this result.
 */
bool xiao_ota_install_command_policy_valid(const xiao_ota_install_command_t *cmd,
                                           uint32_t counter_floor,
                                           uint32_t expected_active_extent,
                                           uint64_t this_device_address);

typedef struct XIAO_OTA_PACKED {
  uint32_t magic;
  uint16_t record_version;
  uint16_t record_bytes;
  uint32_t sequence;
  uint64_t transaction_nonce;
  uint32_t phase;
  uint32_t progress_bytes;
  uint32_t active_image_extent;
  uint32_t candidate_counter;
  uint16_t previous_bank_0;
  uint16_t previous_bank_0_crc;
  uint32_t previous_bank_0_size;
  uint8_t candidate_hash_sha256[32];
  uint8_t backup_hash_sha256[32];
  uint8_t installed_hash_sha256[32];
  uint8_t trial_attempts;
  uint8_t reserved[3];
  uint32_t crc32;
  uint32_t commit_marker;
} xiao_ota_state_t;

typedef struct XIAO_OTA_PACKED {
  uint32_t magic;
  uint16_t record_version;
  uint16_t record_bytes;
  uint32_t sequence;
  uint64_t transaction_nonce;
  uint32_t confirmed_counter;
  uint8_t confirmed_hash_sha256[32];
  uint32_t crc32;
  uint32_t commit_marker;
} xiao_ota_confirmation_t;

typedef struct XIAO_OTA_PACKED {
  uint32_t magic;
  uint16_t record_version;
  uint16_t record_bytes;
  uint32_t sequence;
  uint32_t confirmed_counter_floor;
  uint32_t active_image_extent;
  uint8_t confirmed_hash_sha256[32];
  uint32_t crc32;
  uint32_t commit_marker;
} xiao_ota_floor_t;

#define XIAO_OTA_SIDECAR_MAGIC UINT32_C(0x58534944) /* "XSID" */

/*
 * Boot-private settings sidecar (xiao_ota_layout.h's
 * XIAO_OTA_SETTINGS_SIDECAR_A/B): NOT part of the public state-v1 ABI --
 * it lives at a fixed offset inside the SAME physical sector as its
 * accompanying xiao_ota_state_t record, written together by
 * write_state_with_sidecar() (xiao_ota_boot_io.c) under a single sector
 * erase, sidecar body/marker committed FIRST, state body/marker SECOND.
 * `matching_state_sequence` must equal the accompanying state record's
 * own `sequence` field -- a mismatch (e.g. a tear between the two
 * commits) means the sidecar found does not actually belong to the
 * currently-trusted state record and must never be trusted for it.
 * `transaction_nonce` is the SAME full 64-bit value as
 * xiao_ota_state_t.transaction_nonce, checked independently as a second
 * binding. `command_digest_sha256` is SHA-256 over the exact accepted
 * command record's bytes (its own declared v1/v2 length) that admitted
 * this transaction -- an audit/binding value, NOT a substitute for the
 * Ed25519 signature check already performed before admission.
 * `original_settings_raw` is the verbatim 28-byte Nordic
 * bootloader_settings_t page read at admission, before this
 * transaction's own install ever touches bank_0/bank_0_crc/bank_0_size --
 * install derives its new settings page from this frozen snapshot
 * (changing only those three fields); rollback restores it verbatim.
 * Total size is fixed at 88 bytes (see the size-check in
 * xiao_ota_boot_io.c) and must never grow -- like state-v1, this is a
 * frozen wire/flash layout once shipped.
 */
typedef struct XIAO_OTA_PACKED {
  uint32_t magic;
  uint16_t record_version;
  uint16_t record_bytes;
  uint32_t matching_state_sequence;
  uint64_t transaction_nonce;
  uint8_t command_digest_sha256[32];
  uint8_t original_settings_raw[28]; /* XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE */
  uint32_t crc32;
  uint32_t commit_marker;
} xiao_ota_settings_sidecar_t;

bool xiao_ota_settings_sidecar_valid(const xiao_ota_settings_sidecar_t *record);

uint32_t xiao_ota_crc32(const void *data, size_t length);
bool xiao_ota_explicit_dfu_requested(uint32_t gpregret);
uint32_t xiao_ota_safe_backup_extent(uint32_t bank_0_size,
                                     uint32_t app_region_size);
/* Fail-closed decision for the currently-active image extent, given
 * FRESHLY read/recomputed bank-0 metadata (never a stale durable-floor
 * value, which can silently disagree with reality after a non-OTA USB
 * reflash). Returns false (out_extent left untouched) if bank_0_marker_valid
 * is false, bank_0_crc/bank_0_size is zero, bank_0_size exceeds
 * app_region_size, or recomputed_crc16 (the caller's live CRC-16 over the
 * first bank_0_size bytes of internal flash) does not match bank_0_crc --
 * i.e. any missing/invalid/mismatched fresh metadata is a hard failure,
 * never a silent fallback extent. */
bool xiao_ota_resolve_active_extent(bool bank_0_marker_valid,
                                    uint16_t bank_0_crc, uint32_t bank_0_size,
                                    uint16_t recomputed_crc16,
                                    uint32_t app_region_size,
                                    uint32_t *out_extent);
bool xiao_ota_state_valid(const xiao_ota_state_t *record);
bool xiao_ota_confirmation_valid(const xiao_ota_confirmation_t *record);
bool xiao_ota_floor_valid(const xiao_ota_floor_t *record);
/*
 * "Body-only" counterparts: every check xiao_ota_*_valid() performs
 * EXCEPT the commit-marker exact match. A record passing the body-only
 * check but failing the full check disagrees ONLY on its commit marker
 * -- which is exactly the case that cannot be safely resolved by marker-
 * reachability reasoning alone (a genuinely in-flight, not-yet-committed
 * write and a previously-committed-then-corrupted record are, by
 * construction, byte-for-byte indistinguishable at the marker field:
 * see xiao_ota_boot_io.c's slot_safe_to_overwrite() doc-comment). Any
 * caller resolving THIS specific ambiguity must fall back to an
 * independent, positive binding check (matching an already-trusted
 * sibling record/command), never to marker bits alone.
 */
bool xiao_ota_state_body_valid(const xiao_ota_state_t *record);
bool xiao_ota_floor_body_valid(const xiao_ota_floor_t *record);
bool xiao_ota_settings_sidecar_body_valid(const xiao_ota_settings_sidecar_t *record);
/*
 * True only if every byte of `data` is 0xFF -- the state a QSPI/internal
 * flash region reads as after a bulk erase and nothing else. Used by the
 * boot process to distinguish a genuinely never-provisioned record (both
 * A/B slots fully erased: legitimate "nothing recorded yet") from a record
 * slot that is present but fails structural validation (damage, a torn
 * write, or leftover unrelated data) -- the latter must never be silently
 * treated the same as "nothing recorded yet", especially for the
 * anti-rollback counter floor.
 */
bool xiao_ota_bytes_erased(const void *data, size_t length);
const void *xiao_ota_newest_valid(const void *a, const void *b, size_t size,
                                  bool (*valid)(const void *));
bool xiao_ota_confirmation_matches(const xiao_ota_state_t *state,
                                   const xiao_ota_confirmation_t *confirmation);
xiao_ota_phase_t xiao_ota_recovery_phase(const xiao_ota_state_t *state,
                                         bool confirmation_matches);
bool xiao_ota_command_acceptable_phase(bool have_state, xiao_ota_phase_t phase);
/*
 * True when the currently-decoded install command is a byte-identical
 * retry of a transaction that ALREADY failed and was rolled back
 * (state.phase == XIAO_OTA_PHASE_FAILED with the same transaction nonce,
 * counter, and image hash) -- the counter floor never advances on
 * failure, so the same signed command legitimately re-verifies forever
 * and must be refused explicitly here, not silently reinstalled every
 * boot. A genuinely new authenticated command (any different nonce,
 * counter, or image hash) always returns false and is still fully
 * honoured -- this never inspects or replaces a signature.
 */
bool xiao_ota_command_is_retry_of_failed_transaction(
    bool have_state, xiao_ota_phase_t phase,
    uint64_t state_transaction_nonce, uint32_t state_candidate_counter,
    const uint8_t state_candidate_hash[32], uint64_t intent_transaction_nonce,
    uint32_t intent_monotonic_counter, const uint8_t intent_image_hash[32]);
/*
 * True only when a trial-boot confirmation may safely advance the durable
 * anti-rollback floor. `installed_hash` is a SHA-256 computed over exactly
 * `candidate_size` bytes at install time (see xiao_ota_boot.c) -- it
 * cryptographically binds BOTH the new image's content AND its exact
 * length: for a fresh re-hash at any extent E to reproduce that digest,
 * E must equal the original candidate_size (SHA-256 pre-image/second-
 * pre-image resistance means a different-length input essentially never
 * reproduces the same digest). This lets a fresh read alone verify the
 * NEW candidate's own extent without any separate durable extent field --
 * no mutable command-slot value, no extra state layout, and no risk of
 * comparing against the wrong (old/backup) extent field.
 *
 * The caller must pass a FRESH (this-boot) bank-0 validity/extent (e.g.
 * from xiao_ota_resolve_active_extent()) and a FRESH SHA-256 recomputed
 * over internal flash at that fresh extent right now -- never anything
 * decoded from the mutable command slot, which may have been overwritten
 * by a new (or attacker-supplied) command during the trial window.
 * `max_candidate_extent` bounds the fresh extent to the same install cap
 * enforced at command-acceptance time (XIAO_OTA_INSTALL_MAX_SIZE) so a
 * corrupted/oversized fresh read can never validate. Guards against a
 * USB/CDC reflash (or flash damage) during the trial window producing a
 * confirmation token that still nominally matches nonce/counter/hash at
 * the transport layer while the image actually running is no longer the
 * one that was installed and verified.
 */
bool xiao_ota_confirmation_hash_bound_extent_valid(
    bool fresh_active_extent_valid, uint32_t fresh_active_extent,
    uint32_t max_candidate_extent, const uint8_t fresh_hash[32],
    const uint8_t installed_hash[32]);
