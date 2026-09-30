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
/* Command record versions (xiao_ota_command_t.record_version /
 * xiao_ota_command_v2_t.record_version). NOT the same field as
 * XIAO_OTA_FORMAT_VERSION, which is the fixed version for state/
 * confirmation/floor records and must never change. */
#define XIAO_OTA_COMMAND_VERSION_LEGACY_V1 1u
#define XIAO_OTA_COMMAND_VERSION_WIRE_V2   2u
#define XIAO_OTA_COMMIT_MARKER         UINT32_C(0x434F4D54)
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
 * Decodes `in` and rejects it unless it is the unique canonical encoding of
 * the decoded fields (decode, then re-encode, then compare byte-for-byte
 * against `in`). For this fixed-width, unpadded format every input has at
 * most one valid decoding, so this is defense in depth rather than a live
 * ambiguity -- it guards against any future revision that adds
 * variable-width or padded fields without updating this check.
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
 * All non-cryptographic install policy checks, identical for v1 and v2:
 * target/role/app_address/format/key/algorithm ids, required capability
 * bit, anti-rollback counter vs. durable floor, image size bounds, active
 * (backup) image extent bounds and match against the currently-installed
 * extent, and device targeting (exact match, or broadcast). Does NOT
 * verify the Ed25519 signature -- callers must do that separately over the
 * exact version-appropriate signed bytes before trusting this result.
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
