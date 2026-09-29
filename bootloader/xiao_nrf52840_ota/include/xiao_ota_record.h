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
bool xiao_ota_command_valid(const xiao_ota_command_t *record);
bool xiao_ota_state_valid(const xiao_ota_state_t *record);
bool xiao_ota_confirmation_valid(const xiao_ota_confirmation_t *record);
bool xiao_ota_floor_valid(const xiao_ota_floor_t *record);
const void *xiao_ota_newest_valid(const void *a, const void *b, size_t size,
                                  bool (*valid)(const void *));
bool xiao_ota_confirmation_matches(const xiao_ota_state_t *state,
                                   const xiao_ota_confirmation_t *confirmation);
xiao_ota_phase_t xiao_ota_recovery_phase(const xiao_ota_state_t *state,
                                         bool confirmation_matches);
