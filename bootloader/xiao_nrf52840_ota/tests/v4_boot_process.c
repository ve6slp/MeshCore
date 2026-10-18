/* Raw flash handoff only: no radio protocol or replacement installer. */
#include "fake_io.h"
#include "crc16.h"
#include "xiao_ota_boot_info.h"
#include "xiao_ota_layout.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static fake_io_state_t flash;

void randombytes(unsigned char *out, unsigned long long size) {
  (void)out;
  (void)size;
  abort(); /* This executable verifies signatures; it never signs. */
}

static void transfer(const char *directory, const char *name, void *bytes,
                     size_t size, bool writing) {
  char path[4096];
  assert(snprintf(path, sizeof(path), "%s/%s", directory, name) < (int)sizeof(path));
  FILE *file = fopen(path, writing ? "wb" : "rb");
  assert(file);
  if (writing) assert(fwrite(bytes, 1, size, file) == size);
  else {
    assert(fread(bytes, 1, size, file) == size);
    assert(fgetc(file) == EOF);
  }
  assert(fclose(file) == 0);
}

static void media(const char *directory, bool writing) {
  transfer(directory, "qspi.bin", flash.qspi, sizeof(flash.qspi), writing);
  transfer(directory, "internal.bin", flash.internal_flash, sizeof(flash.internal_flash), writing);
}

static void initialize(void) {
  const uint32_t size = 8195;
  const uint32_t vectors[2] = {0x20040000, XIAO_OTA_APP_START + 0x101};
  uint8_t *app = flash.internal_flash + XIAO_OTA_APP_START;
  uint8_t settings[28] = {0};
  xiao_ota_boot_info_t marker;
  const uint8_t reserved[32] = {0};
  for (uint32_t i = 0; i < size; ++i) app[i] = (uint8_t)(i * 7 + 31);
  memcpy(app, vectors, sizeof(vectors));
  settings[4] = XIAO_OTA_BANK_INVALID_APP;
  fake_io_write_settings_raw(&flash, settings);
  fake_io_provision_bank0_settings(&flash, XIAO_OTA_BANK_VALID_APP,
                                   crc16_compute(app, size, NULL), size);
  xiao_ota_boot_info_build(&marker, XIAO_OTA_BOARD_TARGET, XIAO_OTA_COMPILED_ROLE_ID,
                           XIAO_OTA_CAP_QSPI_INSTALL, XIAO_OTA_KEY_ID,
                           XIAO_OTA_ALGORITHM_ED25519, reserved);
  memcpy(flash.internal_flash + XIAO_OTA_BOOT_INFO_ADDRESS, &marker, sizeof(marker));
  memset(flash.qspi + OTA_NRF52_SECURITY_A_OFFSET, 0x39, OTA_NRF52_SECURITY_A_SIZE);
  memset(flash.qspi + OTA_NRF52_SECURITY_B_OFFSET, 0xA6, OTA_NRF52_SECURITY_B_SIZE);
  memset(flash.qspi + OTA_NRF52_FILESYSTEM_OFFSET, 0x6C, OTA_NRF52_FILESYSTEM_SIZE);
  memset(flash.internal_flash + OTA_NRF52_INTERNAL_INSTALLER_OFFSET, 0x72,
         OTA_NRF52_INTERNAL_INSTALLER_SIZE);
  memset(flash.internal_flash + OTA_NRF52_INTERNAL_FS_OFFSET, 0x95,
         OTA_NRF52_INTERNAL_FS_SIZE);
  /* Genuine boot-owned factory genesis, not a fabricated confirmed floor. */
  assert(fake_io_run_boot(&flash) == 0);
}

static void hex(const uint8_t *bytes, size_t size) {
  for (size_t i = 0; i < size; ++i) printf("%02x", bytes[i]);
}

static void inspect(void) {
  xiao_ota_state_t a, b, *state = NULL;
  xiao_ota_floor_t fa, fb, *floor = NULL;
  xiao_ota_command_v2_t ca, cb, *command = NULL;
  memcpy(&a, flash.qspi + XIAO_OTA_STATE_A, sizeof(a));
  memcpy(&b, flash.qspi + XIAO_OTA_STATE_B, sizeof(b));
  if (xiao_ota_state_valid(&a)) state = &a;
  if (xiao_ota_state_valid(&b) && (!state || b.sequence > state->sequence)) state = &b;
  memcpy(&fa, flash.qspi + XIAO_OTA_FLOOR_A, sizeof(fa));
  memcpy(&fb, flash.qspi + XIAO_OTA_FLOOR_B, sizeof(fb));
  if (xiao_ota_floor_valid(&fa)) floor = &fa;
  if (xiao_ota_floor_valid(&fb) && (!floor || fb.sequence > floor->sequence)) floor = &fb;
  memcpy(&ca, flash.qspi + XIAO_OTA_COMMAND_A, sizeof(ca));
  memcpy(&cb, flash.qspi + XIAO_OTA_COMMAND_B, sizeof(cb));
  if (xiao_ota_command_v2_valid(&ca)) command = &ca;
  if (xiao_ota_command_v2_valid(&cb) && (!command || cb.sequence > command->sequence)) command = &cb;
  assert(floor);
  printf("{\"board\":%u,\"role\":%u,\"phase\":%u,\"nonce\":%llu,\"counter\":%u,"
         "\"floor\":%u,\"extent\":%u,\"watchdogs\":%d,\"recovery\":%d,"
         "\"app_erases\":%d,\"settings_erases\":%d,\"hash\":\"",
         (unsigned)XIAO_OTA_BOARD_TARGET, (unsigned)XIAO_OTA_COMPILED_ROLE_ID,
         state ? (unsigned)state->phase : 0,
         (unsigned long long)(state ? state->transaction_nonce : 0),
         state ? (unsigned)state->candidate_counter : 0,
         (unsigned)floor->confirmed_counter_floor, (unsigned)floor->active_image_extent,
         flash.watchdog_start_calls, flash.force_recovery_calls,
         flash.app_erase_calls, flash.settings_erase_calls);
  hex(floor->confirmed_hash_sha256, 32);
  printf("\",\"command_nonce\":%llu,\"candidate_hash\":\"",
         (unsigned long long)(command ? command->transaction_nonce : 0));
  if (state) hex(state->candidate_hash_sha256, 32);
  printf("\",\"installed_hash\":\"");
  if (state) hex(state->installed_hash_sha256, 32);
  puts("\"}");
}

int main(int argc, char **argv) {
  assert(argc == 3);
  fake_io_reset(&flash);
  if (!strcmp(argv[1], "init")) initialize();
  else {
    media(argv[2], false);
    flash.require_bank_invalidation = true;
    if (!strcmp(argv[1], "boot")) assert(fake_io_run_boot(&flash) == 0);
    else assert(!strcmp(argv[1], "inspect"));
  }
  media(argv[2], true);
  inspect();
  return 0;
}
