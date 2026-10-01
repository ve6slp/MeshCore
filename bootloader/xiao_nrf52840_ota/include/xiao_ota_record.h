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
 * role-1 install commands (xiao_ota_install_command_static_identity_valid())
 * and ONLY a role-1 genesis floor-activation receipt
 * (floor_activation_receipt_binds_floor()), never role 0, and vice versa.
 * There is no runtime role inference from the monotonic counter, a prior
 * receipt, or any other persisted state, and no "accepts either role"
 * build: exactly one of {0, 1} is compiled in, checked below by
 * _Static_assert. Defaults to 0 (companion) so every existing build,
 * signed artifact, and test that predates role support keeps behaving
 * identically. XIAO_OTA_ROLE_ANY (above) is kept as the historical wire
 * constant for the companion role's own value (0) -- it was never
 * actually a wildcard in the live policy check, and still is not; it must
 * never be redefined to 1 or reinterpreted as "matches any role".
 */
#ifndef XIAO_OTA_COMPILED_ROLE_ID
#define XIAO_OTA_COMPILED_ROLE_ID UINT32_C(0)
#endif
_Static_assert(XIAO_OTA_COMPILED_ROLE_ID == 0u || XIAO_OTA_COMPILED_ROLE_ID == 1u,
              "XIAO_OTA_COMPILED_ROLE_ID must be exactly 0 (companion) or 1 "
              "(repeater) -- no other role is implemented or accepted, and "
              "there is no wildcard/any-role build.");

/* Command record versions (xiao_ota_command_t.record_version /
 * xiao_ota_command_v2_t.record_version). NOT the same field as
 * XIAO_OTA_FORMAT_VERSION, which is the fixed version for state/
 * confirmation/floor records and must never change. */
#define XIAO_OTA_COMMAND_VERSION_LEGACY_V1 1u
#define XIAO_OTA_COMMAND_VERSION_WIRE_V2   2u
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
 * The descriptor prefix is byte-for-byte compatible with
 * ota::trust::CanonicalDescriptor::serialize(): all integers are little
 * endian and the signature covers exactly these 71 bytes.
 */
typedef struct XIAO_OTA_PACKED {
  uint8_t image_hash_sha256[32];
  uint32_t target_id_le;
  uint32_t role_id_le;
  uint64_t device_address_le;
  uint8_t allow_broadcast_address;
  uint32_t required_boot_capability_flags_le;
  uint32_t monotonic_counter_le;
  uint32_t image_size_bytes_le;
  uint32_t app_address_le;
  uint16_t format_id_le;
  uint16_t key_id_le;
  uint16_t algorithm_id_le;
} xiao_ota_canonical_descriptor_t;

typedef struct XIAO_OTA_PACKED {
  uint32_t magic;
  uint16_t record_version;
  uint16_t record_bytes;
  uint32_t sequence;
  uint64_t transaction_nonce;
  xiao_ota_canonical_descriptor_t descriptor;
  uint8_t signature_ed25519[64];
  uint32_t active_image_extent;
  uint8_t active_image_hash_sha256[32];
  uint8_t reserved;
  uint32_t crc32;
  uint32_t commit_marker;
} xiao_ota_command_t;

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
 * Command v2: authenticates the transport's own 59-byte canonical wire
 * descriptor and Ed25519 signature directly -- the SAME bytes and the SAME
 * signature the LoRa OTA transport already verified (see
 * src/helpers/ota/OtaFirmwareBackend.h /
 * src/ota/trust/DescriptorVerifier.h), never re-derived or re-signed into
 * another form. The wire descriptor carries no per-device targeting field,
 * so a v2 command is always installable on any device that otherwise
 * matches target/role/app_address/counter/capability policy (see
 * xiao_ota_install_command_policy_valid(); device_address is forced to 0
 * and allow_broadcast_address to 1 when decoding a v2 command --
 * xiao_ota_install_command_from_v2() -- those two fields are NOT signed
 * input, so they can never be attacker-influenced).
 */
typedef struct XIAO_OTA_PACKED {
  uint32_t magic;
  uint16_t record_version; /* always XIAO_OTA_COMMAND_VERSION_WIRE_V2 (2) */
  uint16_t record_bytes;
  uint32_t sequence;
  uint64_t transaction_nonce;
  uint8_t wire_descriptor[XIAO_OTA_WIRE_DESCRIPTOR_SIZE];
  uint8_t signature_ed25519[64];
  uint32_t active_image_extent;
  uint8_t active_image_hash_sha256[32];
  uint8_t reserved;
  uint32_t crc32;
  uint32_t commit_marker;
} xiao_ota_command_v2_t;

/* Sized to hold either command record version; used to read/validate a
 * command slot generically before its version is known. */
typedef union XIAO_OTA_PACKED {
  xiao_ota_command_t v1;
  xiao_ota_command_v2_t v2;
} xiao_ota_command_any_t;

/*
 * Version-neutral, fully decoded install intent. Populated from either
 * xiao_ota_command_t (v1, legacy 71-byte little-endian descriptor) or
 * xiao_ota_command_v2_t (v2, transport's 59-byte big-endian wire
 * descriptor) so that all downstream policy checks
 * (xiao_ota_install_command_policy_valid()) are written exactly once and
 * apply identically to both, regardless of signed-message format.
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
/* record must point to XIAO_OTA_COMMAND_ANY-sized storage; dispatches on the
 * record_version field (offset 4) to xiao_ota_command_valid() (version 1)
 * or xiao_ota_command_v2_valid() (version 2) with no other fallback. */
bool xiao_ota_command_any_valid(const void *record);
/* Pure structural decode, no signature check. Returns false (leaving *out
 * zeroed) only if the wire descriptor bytes are not canonical
 * (xiao_ota_wire_descriptor_decode() failure); v1 decode never fails. */
bool xiao_ota_install_command_from_v1(const xiao_ota_command_t *cmd,
                                      xiao_ota_install_command_t *out);
bool xiao_ota_install_command_from_v2(const xiao_ota_command_v2_t *cmd,
                                      xiao_ota_install_command_t *out);
/* Dispatches by record_version, as xiao_ota_command_any_valid() does. */
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
 * version-appropriate signed bytes before trusting this result.
 */
bool xiao_ota_install_command_static_identity_valid(
    const xiao_ota_install_command_t *cmd, uint64_t this_device_address);
/*
 * All non-cryptographic install policy checks, identical for v1 and v2:
 * everything xiao_ota_install_command_static_identity_valid() checks,
 * PLUS the two context-dependent checks only meaningful against THIS
 * boot's live admission state: anti-rollback counter vs. durable floor,
 * and active (backup) image extent match against the currently-installed
 * extent. Does NOT verify the Ed25519 signature -- callers must do that
 * separately over the exact version-appropriate signed bytes before
 * trusting this result.
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

/*
 * ROOT-APPROVED ABI (BootFloorActivationReceiptV1) -- this is the frozen,
 * cross-layer-agreed wire contract (386 bytes total); every offset below
 * is pinned by a _Static_assert immediately after the struct so a future
 * accidental reordering/insertion is a build failure, not a silent drift.
 * An upstream/host-tooling implementation (e.g. Python) MUST produce
 * byte-identical output at every one of these exact offsets.
 *
 * Lives in a dedicated 512-byte-MAX window at a FIXED offset 0x100 inside
 * EACH existing floor sector (XIAO_OTA_FLOOR_A/B, xiao_ota_layout.h) --
 * i.e. XIAO_OTA_FLOOR_A+0x100 / XIAO_OTA_FLOOR_B+0x100, entirely separate
 * from (and never overlapping) the 60-byte xiao_ota_floor_t record at
 * offset 0 of that same sector. Does not expand the floor sector, the
 * no-SWD slot, the softdevice region, or the FS map -- the window is
 * carved entirely out of already-reserved, already-unused sector space.
 *
 * This receipt PROVES provenance for a floor value that is ALREADY
 * DURABLY PERSISTED (an actual, fully-committed xiao_ota_floor_t body,
 * XIAO_OTA_PAIR_FOUND), never a self-contained instruction to reseed one
 * from nothing: xiao_ota_boot_io.c only ever trusts a committed
 * genesis floor==0 record when a receipt verifies AND its
 * baseline_hash_sha256/baseline_extent independently match THAT EXACT
 * PERSISTED floor body's own fields (never a fresh live-hardware
 * re-derivation standing in for a persisted record -- a live match
 * alone is explicitly NOT proof a floor was ever durably provisioned).
 * A genuinely MISSING floor pair (no body in either slot) is ALWAYS
 * untrustworthy, with no exception, even given a verifying receipt and
 * even given a live hardware match: a receipt is provenance for a
 * PRESENT, matching body, never a reseed trigger. original_sdk28_digest
 * remains checked against a fresh read of the CURRENT settings page (it
 * has no persisted counterpart inside the 60-byte floor record itself),
 * a corroborating freshness check layered on top of an already-durable
 * floor, never a substitute for one.
 *
 * Verification split (never conflated):
 *   - THIS bootloader (C) verifies: the Ed25519 signature (over a
 *     SHA-256 digest of XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN
 *     concatenated with the canonical body -- a digest, not the raw
 *     concatenation, so the existing hardened ed25519_verify() message-
 *     length cap, sized for the 71-byte legacy descriptor, never needs
 *     widening for this unrelated record type); hw_uid against this
 *     device's own compiled/FICR identity; target/profile/layout_id/
 *     current_role against THIS binary's own compiled qualification
 *     (current_role must equal XIAO_OTA_COMPILED_ROLE_ID, i.e. the role
 *     this exact binary was built for -- a role0->1 runtime TRANSITION
 *     of an already-committed floor is still an explicitly unimplemented
 *     outcome; this only governs which role a brand-new, never-yet-
 *     committed genesis floor may certify); and that activation_floor/baseline_hash_sha256/
 *     baseline_extent match the ALREADY-PERSISTED floor body being
 *     vouched for.
 *   - host/app tooling is responsible for checking local_public_key /
 *     consent_owner_public_key against whatever actual authority root it
 *     trusts, and for cross-checking prepared_root_digest against
 *     whatever it actually prepared -- this bootloader carries those
 *     fields as opaque signed bytes (bound by the signature so they can
 *     never be tampered with in transit) but does NOT itself read or
 *     validate any filesystem/manifest content; it has none.
 *     prepared_root_digest is a digest over a FIXED, PRE-ACTIVATION
 *     object (whatever was actually prepared before this receipt ever
 *     existed) -- it must never include this receipt itself or any
 *     other post-activation bytes, which would create an unresolvable
 *     hash-of-itself cycle; host/app tooling is solely responsible for
 *     defining and checking that fixed pre-activation object.
 *
 * `profile` identifies a specific board/connectivity PROFILE (an actual
 * identity, e.g. XIAO_OTA_FLOOR_ACTIVATION_PROFILE_XIAO_USB /
 * _SENSECAP_USB below), never a capability bitmask -- capability
 * validation (e.g. XIAO_OTA_CAP_QSPI_INSTALL, used by the unrelated
 * install-command descriptor) is a logically separate mechanism.
 *
 * boot_counter_domain is a FIXED literal tag (never derived from role,
 * public key, or layout) purely so this receipt type can never be
 * silently repurposed to authorize something other than the anti-
 * rollback boot counter/floor by changing an unrelated field elsewhere.
 *
 * hw_uid is the device's FULL 64-bit FICR unique id, never truncated:
 * (uint64_t)NRF_FICR->DEVICEID[1] << 32 | NRF_FICR->DEVICEID[0] (see
 * hw_device_address() in xiao_ota_boot.c, the only producer of this
 * value) -- DEVICEID[1] is the high 32 bits, DEVICEID[0] the low 32
 * bits of the resulting 64-bit value, stored here as a canonical
 * LITTLE-ENDIAN uint64_t wire field. External (host-tooling) producers
 * that display/exchange this same identity as an 8-byte BIG-ENDIAN hex
 * string (the human-readable board-serial format, e.g.
 * "3BE94917B92DC5E9") MUST explicitly BIG-ENDIAN-DECODE that string into
 * the 64-bit value and then serialize it little-endian here -- NEVER a
 * raw byte-for-byte memcpy of the BE display bytes into this LE field,
 * which would silently byte-reverse it.
 *
 * key_fingerprint is the FULL 32-byte SHA-256 digest of the trusted
 * Ed25519 public key (never truncated to a shorter prefix).
 *
 * Wire/serialization convention -- explicit, not an implicit "native
 * struct happens to be LE" assumption: every multi-byte integer field is
 * CANONICAL LITTLE-ENDIAN; byte-array fields (keys, digests, signature)
 * are opaque byte sequences with no endianness of their own and are
 * copied verbatim. This bootloader and its native host tests both build
 * for genuinely little-endian targets (nRF52840 Cortex-M4, x86_64), so
 * the raw packed struct layout below already IS this wire contract with
 * zero extra encode/decode step required in C -- the
 * _Static_assert(XIAO_OTA_HOST_IS_LITTLE_ENDIAN) immediately below turns
 * that fact into a checked, explicit build-time guarantee rather than a
 * silent assumption. Any OTHER (e.g. big-endian host, or a host whose
 * toolchain does not define __BYTE_ORDER__/__ORDER_LITTLE_ENDIAN__)
 * producer of these bytes MUST NOT reuse this struct's raw memory image
 * directly -- it must serialize every multi-byte field little-endian,
 * field-by-field in the declaration order below, with NO inter-field
 * padding (XIAO_OTA_PACKED), exactly matching the named
 * XIAO_OTA_FLOOR_ACTIVATION_OFF_* offsets, to be byte-identical to what
 * this bootloader reads, CRCs, and verifies. tools/sign_image.py and
 * tools/prepare_upstream.py already follow this exact discipline
 * (explicit struct.pack("<...") little-endian format codes) for the
 * existing 71-byte install-command/descriptor wire types; any new
 * host-side producer of this receipt type should follow the same
 * pattern.
 */
#define XIAO_OTA_FLOOR_ACTIVATION_MAGIC UINT32_C(0x58464152) /* "XFAR" */
#define XIAO_OTA_FLOOR_ACTIVATION_RECORD_VERSION 1u
#define XIAO_OTA_FLOOR_ACTIVATION_WINDOW_OFFSET UINT32_C(0x100)
#define XIAO_OTA_FLOOR_ACTIVATION_WINDOW_MAX_SIZE UINT32_C(0x200) /* 512 B */
#define XIAO_OTA_BOOT_COUNTER_DOMAIN UINT32_C(0x424F4F54)         /* "BOOT" */
#define XIAO_OTA_FLOOR_ACTIVATION_LAYOUT_ID 1u
/* Historical companion-role genesis value (still 0, unchanged): kept only
 * because it is the long-established value for every pre-existing role-0
 * receipt/artifact. The live check in floor_activation_receipt_binds_
 * floor() no longer compares current_role against this literal -- it
 * compares against THIS binary's own compiled XIAO_OTA_COMPILED_ROLE_ID
 * (0 or 1), of which this constant is simply the companion-role case. */
#define XIAO_OTA_FLOOR_ACTIVATION_ROLE_GENESIS UINT32_C(0)
#define XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN \
  "MeshCore/OTA/publisher-floor-activation/v1"
#define XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN_LEN \
  (sizeof(XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN) - 1u)

/*
 * PROPOSED profile-identity constants (`profile` field): board/
 * connectivity identity, never a capability bitmask. Sent to
 * cross-layer Authority for confirmation before interop; the compiled
 * mapping below (which value THIS binary requires of an incoming
 * receipt) follows XIAO_OTA_BOARD_TARGET so it can never silently drift
 * from the board this binary was actually built for.
 */
#define XIAO_OTA_FLOOR_ACTIVATION_PROFILE_XIAO_USB UINT32_C(1)
#define XIAO_OTA_FLOOR_ACTIVATION_PROFILE_SENSECAP_USB UINT32_C(2)
#if XIAO_OTA_BOARD_TARGET == XIAO_OTA_TARGET_XIAO_NRF52840
#define XIAO_OTA_FLOOR_ACTIVATION_COMPILED_PROFILE \
  XIAO_OTA_FLOOR_ACTIVATION_PROFILE_XIAO_USB
#elif XIAO_OTA_BOARD_TARGET == XIAO_OTA_TARGET_SENSECAP_SOLAR_P1
#define XIAO_OTA_FLOOR_ACTIVATION_COMPILED_PROFILE \
  XIAO_OTA_FLOOR_ACTIVATION_PROFILE_SENSECAP_USB
#endif

/* Named per-field offsets -- the explicit "pure C wire contract" pinned
 * below by _Static_assert(offsetof(...) == ...) for every field. */
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_MAGIC 0u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_RECORD_VERSION 4u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_RECORD_BYTES 6u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_BOOT_COUNTER_DOMAIN 8u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_HW_UID 12u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_LOCAL_PUBLIC_KEY 20u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_CONSENT_OWNER_PUBLIC_KEY 52u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_TARGET 84u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_PROFILE 88u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_LAYOUT_ID 92u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_CURRENT_ROLE 96u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_KEY_ID 100u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_KEY_FINGERPRINT 102u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_HOST_TXN_ID 134u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_AUTHORITY_TXN_DIGEST 150u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_MANIFEST_DIGEST 182u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_PREPARED_ROOT_DIGEST 214u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_ACTIVATION_FLOOR 246u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_BASELINE_HASH_SHA256 250u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_BASELINE_EXTENT 282u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_ORIGINAL_SDK28_DIGEST 286u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_CRC32 318u
#define XIAO_OTA_FLOOR_ACTIVATION_OFF_SIGNATURE_ED25519 322u
/* Signed/CRCed body length: magic..crc32 inclusive, i.e. everything
 * strictly before the signature field. */
#define XIAO_OTA_FLOOR_ACTIVATION_SIGNED_BODY_BYTES 322u
#define XIAO_OTA_FLOOR_ACTIVATION_TOTAL_BYTES 386u

typedef struct XIAO_OTA_PACKED {
  uint32_t magic;
  uint16_t record_version;
  uint16_t record_bytes;
  uint32_t boot_counter_domain; /* always XIAO_OTA_BOOT_COUNTER_DOMAIN */
  uint64_t hw_uid;               /* this device's full FICR unique id, LE */
  uint8_t local_public_key[32];       /* host/app-verified, opaque to C */
  uint8_t consent_owner_public_key[32]; /* host/app-verified, opaque to C */
  uint32_t target;       /* XIAO_OTA_TARGET_*, checked against compiled build */
  uint32_t profile;      /* XIAO_OTA_FLOOR_ACTIVATION_PROFILE_* identity */
  uint32_t layout_id;    /* XIAO_OTA_FLOOR_ACTIVATION_LAYOUT_ID */
  uint32_t current_role; /* must equal this build's XIAO_OTA_COMPILED_ROLE_ID */
  uint16_t key_id;
  uint8_t key_fingerprint[32]; /* full SHA-256(trusted pubkey) */
  uint8_t host_txn_id[16];
  uint8_t authority_txn_digest[32];
  uint8_t manifest_digest[32];
  uint8_t prepared_root_digest[32];
  uint32_t activation_floor; /* explicit; genesis activation always 0 */
  uint8_t baseline_hash_sha256[32];
  uint32_t baseline_extent;
  uint8_t original_sdk28_digest[32];
  uint32_t crc32; /* over magic..original_sdk28_digest, i.e. everything
                   * above; signature below covers this field too. */
  uint8_t signature_ed25519[64];
} xiao_ota_floor_activation_receipt_t;

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
#define XIAO_OTA_HOST_IS_LITTLE_ENDIAN \
  (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
_Static_assert(XIAO_OTA_HOST_IS_LITTLE_ENDIAN,
              "BootFloorActivationReceiptV1's raw packed struct layout is "
              "only a valid little-endian wire encoding on a genuinely "
              "little-endian build target");
#endif

#define XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(field, off)                 \
  _Static_assert(offsetof(xiao_ota_floor_activation_receipt_t, field) ==   \
                    (off),                                                  \
                "BootFloorActivationReceiptV1 wire offset drift: " #field)

XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(magic,
                                        XIAO_OTA_FLOOR_ACTIVATION_OFF_MAGIC);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    record_version, XIAO_OTA_FLOOR_ACTIVATION_OFF_RECORD_VERSION);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    record_bytes, XIAO_OTA_FLOOR_ACTIVATION_OFF_RECORD_BYTES);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    boot_counter_domain, XIAO_OTA_FLOOR_ACTIVATION_OFF_BOOT_COUNTER_DOMAIN);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(hw_uid,
                                        XIAO_OTA_FLOOR_ACTIVATION_OFF_HW_UID);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    local_public_key, XIAO_OTA_FLOOR_ACTIVATION_OFF_LOCAL_PUBLIC_KEY);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    consent_owner_public_key,
    XIAO_OTA_FLOOR_ACTIVATION_OFF_CONSENT_OWNER_PUBLIC_KEY);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(target,
                                        XIAO_OTA_FLOOR_ACTIVATION_OFF_TARGET);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    profile, XIAO_OTA_FLOOR_ACTIVATION_OFF_PROFILE);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    layout_id, XIAO_OTA_FLOOR_ACTIVATION_OFF_LAYOUT_ID);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    current_role, XIAO_OTA_FLOOR_ACTIVATION_OFF_CURRENT_ROLE);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    key_id, XIAO_OTA_FLOOR_ACTIVATION_OFF_KEY_ID);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    key_fingerprint, XIAO_OTA_FLOOR_ACTIVATION_OFF_KEY_FINGERPRINT);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    host_txn_id, XIAO_OTA_FLOOR_ACTIVATION_OFF_HOST_TXN_ID);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    authority_txn_digest, XIAO_OTA_FLOOR_ACTIVATION_OFF_AUTHORITY_TXN_DIGEST);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    manifest_digest, XIAO_OTA_FLOOR_ACTIVATION_OFF_MANIFEST_DIGEST);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    prepared_root_digest, XIAO_OTA_FLOOR_ACTIVATION_OFF_PREPARED_ROOT_DIGEST);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    activation_floor, XIAO_OTA_FLOOR_ACTIVATION_OFF_ACTIVATION_FLOOR);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    baseline_hash_sha256, XIAO_OTA_FLOOR_ACTIVATION_OFF_BASELINE_HASH_SHA256);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    baseline_extent, XIAO_OTA_FLOOR_ACTIVATION_OFF_BASELINE_EXTENT);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    original_sdk28_digest,
    XIAO_OTA_FLOOR_ACTIVATION_OFF_ORIGINAL_SDK28_DIGEST);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(crc32,
                                        XIAO_OTA_FLOOR_ACTIVATION_OFF_CRC32);
XIAO_OTA_FLOOR_ACTIVATION_OFFSET_ASSERT(
    signature_ed25519, XIAO_OTA_FLOOR_ACTIVATION_OFF_SIGNATURE_ED25519);

_Static_assert(offsetof(xiao_ota_floor_activation_receipt_t,
                        signature_ed25519) ==
                  XIAO_OTA_FLOOR_ACTIVATION_SIGNED_BODY_BYTES,
              "BootFloorActivationReceiptV1 signed-body length drift");
_Static_assert(sizeof(xiao_ota_floor_activation_receipt_t) ==
                  XIAO_OTA_FLOOR_ACTIVATION_TOTAL_BYTES,
              "BootFloorActivationReceiptV1 total size drift");
_Static_assert(sizeof(xiao_ota_floor_activation_receipt_t) <=
                  XIAO_OTA_FLOOR_ACTIVATION_WINDOW_MAX_SIZE,
              "floor activation receipt must fit the reserved 512B window");

/*
 * XIAO_OTA_FLOOR_ACTIVATION_TOTAL_BYTES (386) is the canonical WIRE
 * size: exactly what is parsed, CRCed ([0, 318)), and hashed/signed
 * ([0, 322)) -- never the physical transfer size.
 *
 * 386 is NOT a multiple of 4. The real NRF_QSPI peripheral's
 * READ.CNT/WRITE.CNT hardware registers (see hw_qspi_read()/
 * hw_qspi_write() in xiao_ota_boot.c, which program them directly from
 * the requested transfer length with no rounding of their own) require
 * that length to be a multiple of 4 bytes; issuing a 386-byte transfer
 * against the real chip is a hardware-invalid transfer that a plain
 * host-side memcpy-backed test double cannot detect. Every actual QSPI
 * read/program of this record MUST therefore move exactly
 * XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES (388 -- 386 rounded up to
 * the next multiple of 4) bytes, from/to a 4-byte-ALIGNED buffer; the
 * trailing 2 physical-only padding bytes are never part of the wire
 * format and are NEVER parsed, CRCed, or hashed -- a producer MUST leave
 * them at the erased-flash sentinel value (0xFF), and a reader MUST
 * simply discard them after copying only the first TOTAL_BYTES into the
 * canonical struct. The already-reserved 512B window comfortably fits
 * this 388-byte physical transfer with no layout change.
 */
#define XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES 388u
_Static_assert(XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES % 4u == 0u,
              "floor activation physical transfer must be word-multiple");
_Static_assert(XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES >=
                  XIAO_OTA_FLOOR_ACTIVATION_TOTAL_BYTES,
              "floor activation physical transfer must cover the wire size");
_Static_assert(XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES -
                      XIAO_OTA_FLOOR_ACTIVATION_TOTAL_BYTES <
                  4u,
              "floor activation physical padding must be the minimal round-up");
_Static_assert(XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES <=
                  XIAO_OTA_FLOOR_ACTIVATION_WINDOW_MAX_SIZE,
              "floor activation physical transfer must fit the 512B window");

/* Pure structural check: magic/version/bytes/CRC only -- no signature, no
 * device/compiled-qualification binding. Mirrors record_body_valid()'s
 * contract (see xiao_ota_record.c) for every other record type; this
 * record has no commit_marker field of its own (it is written once by
 * external provisioning tooling, never mutated in place afterwards) so a
 * torn/partial write simply fails this check -- the same fail-closed
 * outcome a missing/absent receipt produces. */
bool xiao_ota_floor_activation_receipt_body_valid(
    const xiao_ota_floor_activation_receipt_t *record);

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
bool xiao_ota_command_valid(const xiao_ota_command_t *record);
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
