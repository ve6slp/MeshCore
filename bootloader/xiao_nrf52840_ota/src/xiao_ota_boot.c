#include "xiao_ota_boot.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "ed25519.h"
#include "nrf.h"
#include "bootloader_settings.h"
#include "crc16.h"
#include "dfu_types.h"
#include "xiao_ota_layout.h"
#include "xiao_ota_public_key.h"
#include "xiao_ota_record.h"
#include "xiao_ota_sha256.h"

#define COPY_CHUNK 256u

static uint8_t io_buffer[COPY_CHUNK] __attribute__((aligned(4)));

static void qspi_wait(void) {
  while (NRF_QSPI->EVENTS_READY == 0) {}
  NRF_QSPI->EVENTS_READY = 0;
}

static void qspi_init(void) {
  NRF_QSPI->PSEL.SCK = XIAO_OTA_QSPI_SCK_PIN;
  NRF_QSPI->PSEL.CSN = XIAO_OTA_QSPI_CS_PIN;
  NRF_QSPI->PSEL.IO0 = XIAO_OTA_QSPI_IO0_PIN;
  NRF_QSPI->PSEL.IO1 = XIAO_OTA_QSPI_IO1_PIN;
  NRF_QSPI->PSEL.IO2 = XIAO_OTA_QSPI_IO2_PIN;
  NRF_QSPI->PSEL.IO3 = XIAO_OTA_QSPI_IO3_PIN;
  NRF_QSPI->IFCONFIG0 =
      (QSPI_IFCONFIG0_READOC_READ4O << QSPI_IFCONFIG0_READOC_Pos) |
      (QSPI_IFCONFIG0_WRITEOC_PP4O << QSPI_IFCONFIG0_WRITEOC_Pos) |
      (QSPI_IFCONFIG0_ADDRMODE_24BIT << QSPI_IFCONFIG0_ADDRMODE_Pos);
  NRF_QSPI->IFCONFIG1 =
      (3u << QSPI_IFCONFIG1_SCKFREQ_Pos) |
      (QSPI_IFCONFIG1_SPIMODE_MODE0 << QSPI_IFCONFIG1_SPIMODE_Pos);
  NRF_QSPI->ENABLE = QSPI_ENABLE_ENABLE_Enabled;
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->TASKS_ACTIVATE = 1;
  qspi_wait();
}

static void qspi_read(uint32_t address, void *destination, size_t length) {
  NRF_QSPI->READ.SRC = address;
  NRF_QSPI->READ.DST = (uint32_t)destination;
  NRF_QSPI->READ.CNT = length;
  NRF_QSPI->TASKS_READSTART = 1;
  qspi_wait();
}

static void qspi_write(uint32_t address, const void *source, size_t length) {
  NRF_QSPI->WRITE.SRC = (uint32_t)source;
  NRF_QSPI->WRITE.DST = address;
  NRF_QSPI->WRITE.CNT = length;
  NRF_QSPI->TASKS_WRITESTART = 1;
  qspi_wait();
}

static void qspi_erase_sector(uint32_t address) {
  NRF_QSPI->ERASE.PTR = address;
  NRF_QSPI->ERASE.LEN = QSPI_ERASE_LEN_LEN_4KB;
  NRF_QSPI->TASKS_ERASESTART = 1;
  qspi_wait();
}

static void internal_erase(uint32_t address) {
  NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Een;
  while (NRF_NVMC->READY == NVMC_READY_READY_Busy) {}
  NRF_NVMC->ERASEPAGE = address;
  while (NRF_NVMC->READY == NVMC_READY_READY_Busy) {}
  NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren;
}

static void internal_write(uint32_t address, const uint8_t *source, size_t length) {
  size_t i;
  NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Wen;
  while (NRF_NVMC->READY == NVMC_READY_READY_Busy) {}
  for (i = 0; i < length; i += 4) {
    uint32_t word;
    memcpy(&word, source + i, sizeof(word));
    *(volatile uint32_t *)(address + i) = word;
    while (NRF_NVMC->READY == NVMC_READY_READY_Busy) {}
  }
  NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren;
}

static void hash_qspi(uint32_t address, uint32_t length, uint8_t digest[32]) {
  xiao_ota_sha256_t sha;
  xiao_ota_sha256_init(&sha);
  while (length != 0) {
    uint32_t n = length > COPY_CHUNK ? COPY_CHUNK : length;
    qspi_read(address, io_buffer, n);
    xiao_ota_sha256_update(&sha, io_buffer, n);
    address += n;
    length -= n;
  }
  xiao_ota_sha256_final(&sha, digest);
}

static void hash_internal(uint32_t address, uint32_t length, uint8_t digest[32]) {
  xiao_ota_sha256_t sha;
  xiao_ota_sha256_init(&sha);
  xiao_ota_sha256_update(&sha, (const void *)address, length);
  xiao_ota_sha256_final(&sha, digest);
}

static bool all_equal(const uint8_t a[32], const uint8_t b[32]) {
  uint8_t difference = 0;
  unsigned i;
  for (i = 0; i < 32; ++i) difference |= a[i] ^ b[i];
  return difference == 0;
}

static bool command_policy_valid(const xiao_ota_command_t *command,
                                 uint32_t counter_floor,
                                 uint32_t expected_active_extent) {
  const xiao_ota_canonical_descriptor_t *d = &command->descriptor;
  const uint64_t device_address =
      ((uint64_t)NRF_FICR->DEVICEID[1] << 32) | NRF_FICR->DEVICEID[0];
  const uint32_t image_size = d->image_size_bytes_le;
  if (!xiao_ota_command_valid(command) ||
      d->target_id_le != XIAO_OTA_TARGET_XIAO_NRF52840 ||
      d->role_id_le != XIAO_OTA_ROLE_ANY ||
      d->app_address_le != XIAO_OTA_APP_START ||
      d->format_id_le != XIAO_OTA_DESCRIPTOR_FORMAT ||
      d->key_id_le != XIAO_OTA_KEY_ID ||
      d->algorithm_id_le != XIAO_OTA_ALGORITHM_ED25519 ||
      (d->required_boot_capability_flags_le & XIAO_OTA_CAP_QSPI_INSTALL) == 0 ||
      d->monotonic_counter_le <= counter_floor ||
      image_size == 0 || image_size > XIAO_OTA_CANDIDATE_SIZE ||
      (image_size & 3u) != 0 ||
      command->active_image_extent == 0 ||
      command->active_image_extent > XIAO_OTA_BACKUP_SIZE ||
      (command->active_image_extent & 3u) != 0 ||
      command->active_image_extent != expected_active_extent) {
    return false;
  }
  if (d->device_address_le != device_address &&
      !(d->device_address_le == 0 && d->allow_broadcast_address == 1)) {
    return false;
  }
  return ed25519_verify(command->signature_ed25519,
                        (const unsigned char *)d, sizeof(*d),
                        xiao_ota_lab_public_key_ed25519) == 1;
}

static bool read_pair(uint32_t a_address, uint32_t b_address, void *a, void *b,
                      size_t size, bool (*valid)(const void *), void *out) {
  const void *newest;
  qspi_read(a_address, a, size);
  qspi_read(b_address, b, size);
  newest = xiao_ota_newest_valid(a, b, size, valid);
  if (newest == NULL) return false;
  memcpy(out, newest, size);
  return true;
}

static void write_record(uint32_t a_address, uint32_t b_address, void *record,
                         size_t size, size_t crc_offset, size_t commit_offset,
                         uint32_t sequence) {
  uint32_t crc;
  uint32_t marker = XIAO_OTA_COMMIT_MARKER;
  uint32_t address = (sequence & 1u) ? b_address : a_address;
  uint8_t *bytes = (uint8_t *)record;
  memcpy(bytes + 8, &sequence, sizeof(sequence));
  memset(bytes + commit_offset, 0xFF, sizeof(marker));
  crc = xiao_ota_crc32(record, crc_offset);
  memcpy(bytes + crc_offset, &crc, sizeof(crc));
  qspi_erase_sector(address);
  qspi_write(address, record, commit_offset);
  qspi_write(address + commit_offset, &marker, sizeof(marker));
  memcpy(bytes + commit_offset, &marker, sizeof(marker));
  (void)size;
}

static void persist_state(xiao_ota_state_t *state) {
  state->magic = XIAO_OTA_RECORD_MAGIC;
  state->record_version = XIAO_OTA_FORMAT_VERSION;
  state->record_bytes = sizeof(*state);
  write_record(XIAO_OTA_STATE_A, XIAO_OTA_STATE_B, state, sizeof(*state),
               offsetof(xiao_ota_state_t, crc32),
               offsetof(xiao_ota_state_t, commit_marker), state->sequence + 1);
}

static void persist_floor(xiao_ota_floor_t *floor) {
  floor->magic = XIAO_OTA_FLOOR_MAGIC;
  floor->record_version = XIAO_OTA_FORMAT_VERSION;
  floor->record_bytes = sizeof(*floor);
  write_record(XIAO_OTA_FLOOR_A, XIAO_OTA_FLOOR_B, floor, sizeof(*floor),
               offsetof(xiao_ota_floor_t, crc32),
               offsetof(xiao_ota_floor_t, commit_marker), floor->sequence + 1);
}

static void force_recovery(void) {
  NRF_POWER->GPREGRET = XIAO_OTA_DFU_MAGIC_UF2;
  NVIC_SystemReset();
  while (true) {}
}

static bool write_boot_settings(uint16_t bank_0, uint16_t bank_0_crc,
                                uint32_t bank_0_size) {
  bootloader_settings_t settings __attribute__((aligned(4)));
  const bootloader_settings_t *current;
  bootloader_util_settings_get(&current);
  memcpy(&settings, current, sizeof(settings));
  settings.bank_0 = bank_0;
  settings.bank_0_crc = bank_0_crc;
  settings.bank_0_size = bank_0_size;
  internal_erase(BOOTLOADER_SETTINGS_ADDRESS);
  internal_write(BOOTLOADER_SETTINGS_ADDRESS, (const uint8_t *)&settings,
                 sizeof(settings));
  return memcmp((const void *)BOOTLOADER_SETTINGS_ADDRESS, &settings,
                sizeof(settings)) == 0;
}

static uint32_t active_extent_from_settings(
    const bootloader_settings_t *settings) {
  if (settings->bank_0 != BANK_VALID_APP ||
      settings->bank_0_crc == 0 ||
      settings->bank_0_size == 0 ||
      settings->bank_0_size > XIAO_OTA_APP_MAX_SIZE ||
      crc16_compute((const uint8_t *)XIAO_OTA_APP_START,
                    settings->bank_0_size, NULL) != settings->bank_0_crc) {
    return XIAO_OTA_APP_MAX_SIZE;
  }
  return xiao_ota_safe_backup_extent(settings->bank_0_size,
                                     XIAO_OTA_APP_MAX_SIZE);
}

static bool copy_internal_to_qspi(xiao_ota_state_t *state) {
  uint32_t offset = state->progress_bytes;
  while (offset < state->active_image_extent) {
    uint32_t sector_end = (offset + XIAO_OTA_QSPI_SECTOR_SIZE) &
                          ~(XIAO_OTA_QSPI_SECTOR_SIZE - 1u);
    uint32_t end = sector_end < state->active_image_extent
                       ? sector_end : state->active_image_extent;
    qspi_erase_sector(XIAO_OTA_BACKUP_BASE + offset);
    while (offset < end) {
      uint32_t n = end - offset > COPY_CHUNK ? COPY_CHUNK : end - offset;
      qspi_write(XIAO_OTA_BACKUP_BASE + offset,
                 (const void *)(XIAO_OTA_APP_START + offset), n);
      qspi_read(XIAO_OTA_BACKUP_BASE + offset, io_buffer, n);
      if (memcmp(io_buffer, (const void *)(XIAO_OTA_APP_START + offset), n) != 0)
        return false;
      offset += n;
    }
    state->progress_bytes = offset;
    persist_state(state);
  }
  return true;
}

static bool copy_qspi_to_internal(xiao_ota_state_t *state, uint32_t source,
                                  uint32_t length) {
  uint32_t offset = state->progress_bytes;
  while (offset < length) {
    uint32_t end = offset + XIAO_OTA_QSPI_SECTOR_SIZE;
    if (end > length) end = length;
    internal_erase(XIAO_OTA_APP_START + offset);
    while (offset < end) {
      uint32_t n = end - offset > COPY_CHUNK ? COPY_CHUNK : end - offset;
      qspi_read(source + offset, io_buffer, n);
      internal_write(XIAO_OTA_APP_START + offset, io_buffer, n);
      if (memcmp((const void *)(XIAO_OTA_APP_START + offset), io_buffer, n) != 0)
        return false;
      offset += n;
    }
    state->progress_bytes = offset;
    persist_state(state);
  }
  return true;
}

static void start_trial_watchdog(void) {
  NRF_WDT->CONFIG = WDT_CONFIG_SLEEP_Run << WDT_CONFIG_SLEEP_Pos;
  NRF_WDT->CRV = 60u * 32768u;
  NRF_WDT->RREN = WDT_RREN_RR0_Msk;
  NRF_WDT->TASKS_START = 1;
  NRF_WDT->RR[0] = WDT_RR_RR_Reload;
}

void xiao_ota_boot_process(void) {
  xiao_ota_command_t command_a __attribute__((aligned(4)));
  xiao_ota_command_t command_b __attribute__((aligned(4)));
  xiao_ota_command_t command __attribute__((aligned(4)));
  xiao_ota_state_t state_a __attribute__((aligned(4)));
  xiao_ota_state_t state_b __attribute__((aligned(4)));
  xiao_ota_state_t state __attribute__((aligned(4)));
  xiao_ota_confirmation_t confirm_a __attribute__((aligned(4)));
  xiao_ota_confirmation_t confirm_b __attribute__((aligned(4)));
  xiao_ota_confirmation_t confirmation __attribute__((aligned(4)));
  xiao_ota_floor_t floor_a __attribute__((aligned(4)));
  xiao_ota_floor_t floor_b __attribute__((aligned(4)));
  xiao_ota_floor_t floor __attribute__((aligned(4)));
  uint8_t digest[32] __attribute__((aligned(4)));
  bool have_state, have_floor, confirmed;
  uint32_t expected_active_extent;
  const bootloader_settings_t *boot_settings;

  /*
   * Upstream consumes and clears these requests in check_dfu_mode(), which runs
   * after this hook. Never let a persistent OTA transaction intercept recovery.
   */
  if (xiao_ota_explicit_dfu_requested(NRF_POWER->GPREGRET)) return;

  qspi_init();
  if (!read_pair(XIAO_OTA_COMMAND_A, XIAO_OTA_COMMAND_B, &command_a, &command_b,
                 sizeof(command), (bool (*)(const void *))xiao_ota_command_valid,
                 &command)) {
    memset(&command, 0, sizeof(command));
  }
  have_state = read_pair(XIAO_OTA_STATE_A, XIAO_OTA_STATE_B, &state_a, &state_b,
                         sizeof(state), (bool (*)(const void *))xiao_ota_state_valid,
                         &state);
  have_floor = read_pair(XIAO_OTA_FLOOR_A, XIAO_OTA_FLOOR_B, &floor_a, &floor_b,
                         sizeof(floor), (bool (*)(const void *))xiao_ota_floor_valid,
                         &floor);
  if (!have_floor) memset(&floor, 0, sizeof(floor));
  bootloader_util_settings_get(&boot_settings);
  expected_active_extent = floor.active_image_extent != 0
                               ? floor.active_image_extent
                               : active_extent_from_settings(boot_settings);
  if (!have_state || state.phase == XIAO_OTA_PHASE_EMPTY ||
      state.phase == XIAO_OTA_PHASE_CONFIRMED) {
    if (!command_policy_valid(&command, floor.confirmed_counter_floor,
                              expected_active_extent)) {
      return;
    }
    hash_qspi(XIAO_OTA_CANDIDATE_BASE, command.descriptor.image_size_bytes_le, digest);
    if (!all_equal(digest, command.descriptor.image_hash_sha256)) return;
    hash_internal(XIAO_OTA_APP_START, command.active_image_extent, digest);
    if (!all_equal(digest, command.active_image_hash_sha256)) return;
    memset(&state, 0, sizeof(state));
    state.transaction_nonce = command.transaction_nonce;
    state.phase = XIAO_OTA_PHASE_BACKUP_COPYING;
    state.active_image_extent = command.active_image_extent;
    state.candidate_counter = command.descriptor.monotonic_counter_le;
    state.previous_bank_0 = boot_settings->bank_0;
    state.previous_bank_0_crc = boot_settings->bank_0_crc;
    state.previous_bank_0_size = boot_settings->bank_0_size;
    memcpy(state.candidate_hash_sha256, command.descriptor.image_hash_sha256, 32);
    memcpy(state.backup_hash_sha256, command.active_image_hash_sha256, 32);
    persist_state(&state);
  }

  if (state.phase == XIAO_OTA_PHASE_BACKUP_COPYING) {
    if (!copy_internal_to_qspi(&state)) force_recovery();
    hash_qspi(XIAO_OTA_BACKUP_BASE, state.active_image_extent, digest);
    if (!all_equal(digest, state.backup_hash_sha256)) force_recovery();
    state.phase = XIAO_OTA_PHASE_BACKUP_READY;
    state.progress_bytes = 0;
    persist_state(&state);
  }
  if (state.phase == XIAO_OTA_PHASE_BACKUP_READY ||
      state.phase == XIAO_OTA_PHASE_INSTALL_COPYING) {
    if (!command_policy_valid(&command, floor.confirmed_counter_floor,
                              expected_active_extent) ||
        command.transaction_nonce != state.transaction_nonce ||
        !all_equal(command.descriptor.image_hash_sha256,
                   state.candidate_hash_sha256)) {
      state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
      state.progress_bytes = 0;
      persist_state(&state);
    }
    if (state.phase != XIAO_OTA_PHASE_ROLLBACK_COPYING &&
        state.progress_bytes == 0) {
      hash_qspi(XIAO_OTA_CANDIDATE_BASE,
                command.descriptor.image_size_bytes_le, digest);
      if (!all_equal(digest, state.candidate_hash_sha256)) {
        state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
        persist_state(&state);
      }
    }
    if (state.phase != XIAO_OTA_PHASE_ROLLBACK_COPYING) {
      state.phase = XIAO_OTA_PHASE_INSTALL_COPYING;
      persist_state(&state);
      if (!copy_qspi_to_internal(&state, XIAO_OTA_CANDIDATE_BASE,
                                 command.descriptor.image_size_bytes_le)) {
        state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
        state.progress_bytes = 0;
        persist_state(&state);
      } else {
        hash_internal(XIAO_OTA_APP_START,
                      command.descriptor.image_size_bytes_le, digest);
        if (!all_equal(digest, state.candidate_hash_sha256)) {
          state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
          state.progress_bytes = 0;
          persist_state(&state);
        } else {
          const uint32_t candidate_size =
              command.descriptor.image_size_bytes_le;
          const uint16_t candidate_crc =
              crc16_compute((const uint8_t *)XIAO_OTA_APP_START,
                            candidate_size, NULL);
          if (!write_boot_settings(BANK_VALID_APP, candidate_crc,
                                   candidate_size)) {
            state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
            state.progress_bytes = 0;
            persist_state(&state);
          } else {
            memcpy(state.installed_hash_sha256, digest, 32);
            state.phase = XIAO_OTA_PHASE_TRIAL_BOOT;
            state.progress_bytes = 0;
            state.trial_attempts = 0;
            persist_state(&state);
            start_trial_watchdog();
            return;
          }
        }
      }
    }
  }

  confirmed = read_pair(XIAO_OTA_CONFIRM_A, XIAO_OTA_CONFIRM_B,
                        &confirm_a, &confirm_b, sizeof(confirmation),
                        (bool (*)(const void *))xiao_ota_confirmation_valid,
                        &confirmation) &&
              xiao_ota_confirmation_matches(&state, &confirmation);
  if (state.phase == XIAO_OTA_PHASE_TRIAL_BOOT && confirmed) {
    floor.confirmed_counter_floor = state.candidate_counter;
    floor.active_image_extent = command.descriptor.image_size_bytes_le;
    memcpy(floor.confirmed_hash_sha256, state.candidate_hash_sha256, 32);
    persist_floor(&floor);
    state.phase = XIAO_OTA_PHASE_CONFIRMED;
    persist_state(&state);
    return;
  }
  if (state.phase == XIAO_OTA_PHASE_TRIAL_BOOT) {
    state.trial_attempts++;
    if (state.trial_attempts < XIAO_OTA_MAX_TRIAL_BOOTS) {
      persist_state(&state);
      start_trial_watchdog();
      return;
    }
    state.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
    state.progress_bytes = 0;
    persist_state(&state);
  }
  if (state.phase == XIAO_OTA_PHASE_ROLLBACK_COPYING) {
    if (!copy_qspi_to_internal(&state, XIAO_OTA_BACKUP_BASE,
                               state.active_image_extent))
      force_recovery();
    hash_internal(XIAO_OTA_APP_START, state.active_image_extent, digest);
    if (!all_equal(digest, state.backup_hash_sha256)) force_recovery();
    if (!write_boot_settings(state.previous_bank_0,
                             state.previous_bank_0_crc,
                             state.previous_bank_0_size))
      force_recovery();
    state.phase = XIAO_OTA_PHASE_FAILED;
    persist_state(&state);
    return;
  }
  if (state.phase == XIAO_OTA_PHASE_FAILED) return;
  force_recovery();
}
