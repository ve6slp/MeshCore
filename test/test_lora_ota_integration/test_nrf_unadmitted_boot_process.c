#if defined(OTA_NRF_UNADMITTED_BOOT_PROCESS_TEST)

#define main frozen_boot_process_tests_main
#include "../../bootloader/xiao_nrf52840_ota/tests/test_boot_process.c"
#undef main

static void test_valid_usb_reflash_refuses_original_command_without_admission(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32], usb_hash[32], settings[28];
  uint8_t state_before[2 * XIAO_OTA_QSPI_SECTOR_SIZE], candidate_before[32];
  xiao_ota_floor_t floor_before, floor_after;
  xiao_ota_command_v2_t command_before;
  xiao_ota_state_t state;
  const uint32_t size = 8192;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x61, old_hash);
  write_candidate(&s, size, 0x71, candidate_hash);
  build_and_write_command(&s, 0x12345, 1, 5, size, candidate_hash, size, old_hash);
  memcpy(&command_before, s.qspi + XIAO_OTA_COMMAND_A, sizeof(command_before));
  memcpy(state_before, s.qspi + XIAO_OTA_STATE_A, sizeof(state_before));
  assert(read_floor(&s, &floor_before));
  sha256_of(s.qspi + XIAO_OTA_CANDIDATE_BASE, size, candidate_before);

  fill_pattern(s.internal_flash + XIAO_OTA_APP_START, size, 0x81);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, size, usb_hash);
  fake_io_provision_bank0_settings(&s, XIAO_OTA_BANK_VALID_APP,
      crc16_compute(s.internal_flash + XIAO_OTA_APP_START, size, NULL), size);
  fake_io_read_settings_raw(&s, settings);
  settings[4] = 0xff; settings[5] = 0;
  fake_io_write_settings_raw(&s, settings);

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(!read_state(&s, &state));
  assert(memcmp(state_before, s.qspi + XIAO_OTA_STATE_A, sizeof(state_before)) == 0);
  assert(memcmp(&command_before, s.qspi + XIAO_OTA_COMMAND_A, sizeof(command_before)) == 0);
  assert(read_floor(&s, &floor_after));
  assert(memcmp(&floor_before, &floor_after, sizeof(floor_before)) == 0);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, size, old_hash);
  assert(memcmp(usb_hash, old_hash, 32) == 0);
  sha256_of(s.qspi + XIAO_OTA_CANDIDATE_BASE, size, old_hash);
  assert(memcmp(candidate_before, old_hash, 32) == 0);
  puts("valid SDK USB reflash refuses bound old command with no admission or mutation passed");
}

static size_t read_remote_fixture(const char *prefix, const char *name, uint8_t *out, size_t capacity) {
  char path[512];
  FILE *input;
  size_t size;
  int length = snprintf(path, sizeof(path), "%s-%s.bin", prefix, name);
  assert(length > 0 && (size_t)length < sizeof(path));
  input = fopen(path, "rb");
  assert(input != NULL);
  size = fread(out, 1, capacity, input);
  assert(size > 0 && !ferror(input) && fgetc(input) == EOF);
  assert(fclose(input) == 0);
  return size;
}

static void test_exact_rf_commit_deferred_reset_handoff_installs_and_confirms(const char *prefix) {
  fake_io_state_t s;
  xiao_ota_command_v2_t command;
  xiao_ota_wire_descriptor_t descriptor;
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  uint8_t settings[28], digest[32];
  size_t candidate_size, running_size;
  fake_io_reset(&s);
  assert(read_remote_fixture(prefix, "command", (uint8_t *)&command, sizeof(command)) == sizeof(command));
  assert(xiao_ota_command_v2_valid(&command));
  assert(xiao_ota_wire_descriptor_decode(command.wire_descriptor, &descriptor));
  assert((((uint32_t)descriptor.board_family << 16) | descriptor.board_variant) == XIAO_OTA_BOARD_TARGET);
  assert(descriptor.role == XIAO_OTA_COMPILED_ROLE_ID);
  memcpy(s.qspi + XIAO_OTA_COMMAND_A, &command, sizeof(command));
  candidate_size = read_remote_fixture(prefix, "candidate", s.qspi + XIAO_OTA_CANDIDATE_BASE,
                                       XIAO_OTA_CANDIDATE_SIZE);
  running_size = read_remote_fixture(prefix, "running", s.internal_flash + XIAO_OTA_APP_START,
                                     XIAO_OTA_APP_MAX_SIZE);
  assert(candidate_size == descriptor.exact_size_bytes && running_size == command.active_image_extent);
  assert(read_remote_fixture(prefix, "sdk", settings, sizeof(settings)) == sizeof(settings));
  fake_io_write_settings_raw(&s, settings);
  assert(read_remote_fixture(prefix, "floor", s.qspi + XIAO_OTA_FLOOR_A,
                             2 * XIAO_OTA_QSPI_SECTOR_SIZE) == 2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 4);

  /* These exact bytes were exported ONLY after the real RF COMMIT path
   * durably committed and its app-loop deferred reset callback fired. */
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.transaction_nonce == command.transaction_nonce);
  assert(state.candidate_counter == descriptor.security_counter);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, candidate_size, digest);
  assert(memcmp(digest, descriptor.sha256, 32) == 0);
  assert(read_floor(&s, &floor) && floor.confirmed_counter_floor == 4);

  write_confirmation(&s, state.transaction_nonce, state.candidate_counter, digest);
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor) && floor.confirmed_counter_floor == descriptor.security_counter);
  assert(floor.active_image_extent == candidate_size);
  assert(memcmp(floor.confirmed_hash_sha256, digest, 32) == 0);
  printf("exact real RF deferred-reset handoff board=%08x role=%u nonce=%llu trial->confirmed floor=%u passed\n",
         (unsigned)XIAO_OTA_BOARD_TARGET, (unsigned)XIAO_OTA_COMPILED_ROLE_ID,
         (unsigned long long)command.transaction_nonce, floor.confirmed_counter_floor);
}

static void load_retired_campaign(fake_io_state_t *s, const char *prefix,
                                 xiao_ota_command_v2_t *previous,
                                 xiao_ota_wire_descriptor_t *next) {
  uint8_t canonical[59], settings[28], digest[32];
  xiao_ota_wire_descriptor_t old;
  xiao_ota_floor_t floor;
  size_t size;
  fake_io_reset(s);
  assert(read_remote_fixture(prefix, "retired-previous-command", (uint8_t *)previous,
                             sizeof(*previous)) == sizeof(*previous));
  assert(xiao_ota_command_v2_valid(previous));
  assert(xiao_ota_wire_descriptor_decode(previous->wire_descriptor, &old));
  assert(read_remote_fixture(prefix, "retired-canonical", canonical, sizeof(canonical)) == sizeof(canonical));
  assert(xiao_ota_wire_descriptor_decode(canonical, next));
  assert(old.security_counter == 5 && next->security_counter == 6);
  assert(memcmp(old.sha256, next->sha256, sizeof(old.sha256)) == 0);
  assert((((uint32_t)next->board_family << 16) | next->board_variant) == XIAO_OTA_BOARD_TARGET);
  assert(next->role == XIAO_OTA_COMPILED_ROLE_ID);
  assert(read_remote_fixture(prefix, "retired-command-region", s->qspi + XIAO_OTA_COMMAND_A,
                             2 * XIAO_OTA_QSPI_SECTOR_SIZE) == 2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  assert(read_remote_fixture(prefix, "retired-state-region", s->qspi + XIAO_OTA_STATE_A,
                             2 * XIAO_OTA_QSPI_SECTOR_SIZE) == 2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  assert(read_remote_fixture(prefix, "retired-floor", s->qspi + XIAO_OTA_FLOOR_A,
                             2 * XIAO_OTA_QSPI_SECTOR_SIZE) == 2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  size = read_remote_fixture(prefix, "retired-candidate", s->qspi + XIAO_OTA_CANDIDATE_BASE,
                             XIAO_OTA_CANDIDATE_SIZE);
  assert(size == next->exact_size_bytes);
  sha256_of(s->qspi + XIAO_OTA_CANDIDATE_BASE, size, digest);
  assert(memcmp(digest, old.sha256, sizeof(digest)) == 0);
  size = read_remote_fixture(prefix, "retired-running", s->internal_flash + XIAO_OTA_APP_START,
                             XIAO_OTA_APP_MAX_SIZE);
  assert(size == previous->active_image_extent);
  sha256_of(s->internal_flash + XIAO_OTA_APP_START, size, digest);
  assert(memcmp(digest, previous->active_image_hash_sha256, sizeof(digest)) == 0);
  assert(read_remote_fixture(prefix, "retired-sdk", settings, sizeof(settings)) == sizeof(settings));
  fake_io_write_settings_raw(s, settings);
  assert(read_floor(s, &floor) && floor.confirmed_counter_floor == 4);
}

static void test_retired_intent_cannot_install_ready_without_new_commit_after_bank_restore(const char *prefix) {
  fake_io_state_t s;
  xiao_ota_command_v2_t previous;
  xiao_ota_wire_descriptor_t next;
  xiao_ota_state_t state;
  xiao_ota_floor_t floor_before, floor_after;
  uint8_t running_before[32], candidate_before[32];
  unsigned boot;

  load_retired_campaign(&s, prefix, &previous, &next);
  /* Negative control: a surviving valid old command really would install
   * the same B bytes, under the retired counter/nonce, after bank restore. */
  memcpy(s.qspi + XIAO_OTA_COMMAND_A, &previous, sizeof(previous));
  assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.transaction_nonce == previous.transaction_nonce && state.candidate_counter == 5);

  load_retired_campaign(&s, prefix, &previous, &next);
  assert(!read_state(&s, &state));
  assert(read_floor(&s, &floor_before));
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, previous.active_image_extent, running_before);
  sha256_of(s.qspi + XIAO_OTA_CANDIDATE_BASE, next.exact_size_bytes, candidate_before);
  for (boot = 0; boot < 3; ++boot) {
    uint8_t digest[32];
    assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
    assert(!read_state(&s, &state));
    assert(read_floor(&s, &floor_after));
    assert(memcmp(&floor_before, &floor_after, sizeof(floor_before)) == 0);
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, previous.active_image_extent, digest);
    assert(memcmp(digest, running_before, sizeof(digest)) == 0);
    sha256_of(s.qspi + XIAO_OTA_CANDIDATE_BASE, next.exact_size_bytes, digest);
    assert(memcmp(digest, candidate_before, sizeof(digest)) == 0);
  }
  printf("exact authorized retirement board=%08x role=%u same B new counter READY/no COMMIT + old bank restore "
         "cannot install; surviving-command negative control reaches retired Trial passed\n",
         (unsigned)XIAO_OTA_BOARD_TARGET, (unsigned)XIAO_OTA_COMPILED_ROLE_ID);
}

int main(int argc, char **argv) {
  crypto_sign_keypair(xiao_ota_test_public_key_ed25519, g_test_secret_key);
  test_valid_usb_reflash_refuses_original_command_without_admission();
  assert(argc == 1 || argc == 2);
  if (argc == 2) {
    test_exact_rf_commit_deferred_reset_handoff_installs_and_confirms(argv[1]);
    test_retired_intent_cannot_install_ready_without_new_commit_after_bank_restore(argv[1]);
  }
  return frozen_boot_process_tests_main();
}

#endif
