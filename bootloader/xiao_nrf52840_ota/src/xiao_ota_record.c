#include "xiao_ota_record.h"

#include <string.h>

uint32_t xiao_ota_crc32(const void *data, size_t length) {
  const uint8_t *bytes = (const uint8_t *)data;
  uint32_t crc = UINT32_C(0xFFFFFFFF);
  size_t i;
  for (i = 0; i < length; ++i) {
    unsigned bit;
    crc ^= bytes[i];
    for (bit = 0; bit < 8; ++bit) {
      const uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
      crc = (crc >> 1) ^ (UINT32_C(0xEDB88320) & mask);
    }
  }
  return ~crc;
}

bool xiao_ota_explicit_dfu_requested(uint32_t gpregret) {
  return gpregret == XIAO_OTA_DFU_MAGIC_UF2 ||
         gpregret == XIAO_OTA_DFU_MAGIC_SERIAL ||
         gpregret == XIAO_OTA_DFU_MAGIC_OTA_RESET ||
         gpregret == XIAO_OTA_DFU_MAGIC_OTA_APPJUM;
}

uint32_t xiao_ota_safe_backup_extent(uint32_t bank_0_size,
                                     uint32_t app_region_size) {
  if (bank_0_size == 0 || bank_0_size > app_region_size ||
      bank_0_size > UINT32_MAX - 3u) {
    return app_region_size;
  }
  bank_0_size = (bank_0_size + 3u) & ~UINT32_C(3);
  return bank_0_size <= app_region_size ? bank_0_size : app_region_size;
}

static bool record_valid(const void *record, size_t size, uint32_t magic,
                         uint16_t record_bytes, size_t crc_offset,
                         size_t commit_offset) {
  const uint8_t *bytes = (const uint8_t *)record;
  uint32_t stored_crc;
  uint32_t commit;
  if (record == NULL || size != record_bytes) {
    return false;
  }
  memcpy(&stored_crc, bytes + crc_offset, sizeof(stored_crc));
  memcpy(&commit, bytes + commit_offset, sizeof(commit));
  return memcmp(bytes, &magic, sizeof(magic)) == 0 &&
         bytes[4] == XIAO_OTA_FORMAT_VERSION && bytes[5] == 0 &&
         bytes[6] == (uint8_t)record_bytes && bytes[7] == (uint8_t)(record_bytes >> 8) &&
         commit == XIAO_OTA_COMMIT_MARKER &&
         stored_crc == xiao_ota_crc32(record, crc_offset);
}

bool xiao_ota_command_valid(const xiao_ota_command_t *record) {
  return record_valid(record, sizeof(*record), XIAO_OTA_RECORD_MAGIC,
                      sizeof(*record), offsetof(xiao_ota_command_t, crc32),
                      offsetof(xiao_ota_command_t, commit_marker));
}

bool xiao_ota_state_valid(const xiao_ota_state_t *record) {
  return record_valid(record, sizeof(*record), XIAO_OTA_RECORD_MAGIC,
                      sizeof(*record), offsetof(xiao_ota_state_t, crc32),
                      offsetof(xiao_ota_state_t, commit_marker)) &&
         record->phase <= XIAO_OTA_PHASE_FAILED;
}

bool xiao_ota_confirmation_valid(const xiao_ota_confirmation_t *record) {
  return record_valid(record, sizeof(*record), XIAO_OTA_CONFIRM_MAGIC,
                      sizeof(*record), offsetof(xiao_ota_confirmation_t, crc32),
                      offsetof(xiao_ota_confirmation_t, commit_marker));
}

bool xiao_ota_floor_valid(const xiao_ota_floor_t *record) {
  return record_valid(record, sizeof(*record), XIAO_OTA_FLOOR_MAGIC,
                      sizeof(*record), offsetof(xiao_ota_floor_t, crc32),
                      offsetof(xiao_ota_floor_t, commit_marker));
}

const void *xiao_ota_newest_valid(const void *a, const void *b, size_t size,
                                  bool (*valid)(const void *)) {
  uint32_t a_sequence = 0;
  uint32_t b_sequence = 0;
  const bool a_valid = valid(a);
  const bool b_valid = valid(b);
  (void)size;
  if (!a_valid) return b_valid ? b : NULL;
  if (!b_valid) return a;
  memcpy(&a_sequence, (const uint8_t *)a + 8, sizeof(a_sequence));
  memcpy(&b_sequence, (const uint8_t *)b + 8, sizeof(b_sequence));
  return (int32_t)(b_sequence - a_sequence) > 0 ? b : a;
}

bool xiao_ota_confirmation_matches(const xiao_ota_state_t *state,
                                   const xiao_ota_confirmation_t *confirmation) {
  return xiao_ota_state_valid(state) &&
         xiao_ota_confirmation_valid(confirmation) &&
         state->phase == XIAO_OTA_PHASE_TRIAL_BOOT &&
         state->transaction_nonce == confirmation->transaction_nonce &&
         state->candidate_counter == confirmation->confirmed_counter &&
         memcmp(state->candidate_hash_sha256,
                confirmation->confirmed_hash_sha256, 32) == 0;
}

xiao_ota_phase_t xiao_ota_recovery_phase(const xiao_ota_state_t *state,
                                         bool confirmation_matches) {
  if (!xiao_ota_state_valid(state)) return XIAO_OTA_PHASE_EMPTY;
  switch ((xiao_ota_phase_t)state->phase) {
    case XIAO_OTA_PHASE_REQUESTED:
    case XIAO_OTA_PHASE_BACKUP_COPYING:
      return XIAO_OTA_PHASE_BACKUP_COPYING;
    case XIAO_OTA_PHASE_BACKUP_READY:
    case XIAO_OTA_PHASE_INSTALL_COPYING:
      return XIAO_OTA_PHASE_INSTALL_COPYING;
    case XIAO_OTA_PHASE_TRIAL_BOOT:
      if (confirmation_matches) return XIAO_OTA_PHASE_CONFIRMED;
      return state->trial_attempts >= XIAO_OTA_MAX_TRIAL_BOOTS
                 ? XIAO_OTA_PHASE_ROLLBACK_COPYING
                 : XIAO_OTA_PHASE_TRIAL_BOOT;
    case XIAO_OTA_PHASE_ROLLBACK_COPYING:
      return XIAO_OTA_PHASE_ROLLBACK_COPYING;
    default:
      return (xiao_ota_phase_t)state->phase;
  }
}
