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

static void save_remote_fixture(const char *prefix, const char *name, const uint8_t *bytes, size_t size) {
  char path[512];
  int length = snprintf(path, sizeof(path), "%s-%s.bin", prefix, name);
  FILE *output;
  assert(length > 0 && (size_t)length < sizeof(path));
  output = fopen(path, "wb");
  assert(output != NULL);
  assert(fwrite(bytes, 1, size, output) == size);
  assert(fclose(output) == 0);
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

static void test_consumed_failed_command_does_not_install_replacement_after_precommit_abort(const char *prefix) {
  fake_io_state_t s;
  xiao_ota_command_v2_t command;
  xiao_ota_wire_descriptor_t previous, next;
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  uint8_t settings[28], canonical[59], digest[32], running_hash[32];
  uint8_t next_hash[32];
  size_t running_size, candidate_size;
  unsigned attempt;
  fake_io_reset(&s);
  assert(read_remote_fixture(prefix, "rollback-command", (uint8_t *)&command, sizeof(command)) == sizeof(command));
  assert(xiao_ota_command_v2_valid(&command));
  assert(xiao_ota_wire_descriptor_decode(command.wire_descriptor, &previous));
  assert(previous.security_counter == 5);
  assert((((uint32_t)previous.board_family << 16) | previous.board_variant) == XIAO_OTA_BOARD_TARGET);
  assert(previous.role == XIAO_OTA_COMPILED_ROLE_ID);
  memcpy(s.qspi + XIAO_OTA_COMMAND_A, &command, sizeof(command));
  candidate_size = read_remote_fixture(prefix, "rollback-candidate", s.qspi + XIAO_OTA_CANDIDATE_BASE,
                                       XIAO_OTA_CANDIDATE_SIZE);
  running_size = read_remote_fixture(prefix, "rollback-running", s.internal_flash + XIAO_OTA_APP_START,
                                     XIAO_OTA_APP_MAX_SIZE);
  assert(candidate_size == previous.exact_size_bytes && running_size == command.active_image_extent);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, running_size, running_hash);
  assert(read_remote_fixture(prefix, "rollback-sdk", settings, sizeof(settings)) == sizeof(settings));
  fake_io_write_settings_raw(&s, settings);
  assert(read_remote_fixture(prefix, "rollback-floor", s.qspi + XIAO_OTA_FLOOR_A,
                             2 * XIAO_OTA_QSPI_SECTOR_SIZE) == 2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  for (attempt = 0; attempt < XIAO_OTA_MAX_TRIAL_BOOTS; ++attempt)
    assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_FAILED);
  assert(state.transaction_nonce == command.transaction_nonce && state.candidate_counter == 5);
  assert(memcmp(state.candidate_hash_sha256, previous.sha256, 32) == 0);
  assert(state.active_image_extent == running_size && memcmp(state.backup_hash_sha256, running_hash, 32) == 0);
  assert(read_floor(&s, &floor) && floor.confirmed_counter_floor == 4);
  assert(memcmp(s.qspi + XIAO_OTA_COMMAND_A, &command, sizeof(command)) == 0);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, running_size, digest);
  assert(memcmp(digest, running_hash, 32) == 0);

  /* Native production recovery signed-aborted B and admitted different C,
   * READY without COMMIT, without erasing this consumed above-floor command. */
  assert(read_remote_fixture(prefix, "rollback-retained-command-region", s.qspi + XIAO_OTA_COMMAND_A,
                             2 * XIAO_OTA_QSPI_SECTOR_SIZE) == 2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  assert(memcmp(s.qspi + XIAO_OTA_COMMAND_A, &command, sizeof(command)) == 0);
  assert(read_remote_fixture(prefix, "rollback-next-canonical", canonical, sizeof(canonical)) == sizeof(canonical));
  assert(xiao_ota_wire_descriptor_decode(canonical, &next) && next.security_counter == 7);
  assert(memcmp(next.sha256, previous.sha256, 32) != 0);
  assert((((uint32_t)next.board_family << 16) | next.board_variant) == XIAO_OTA_BOARD_TARGET);
  assert(next.role == XIAO_OTA_COMPILED_ROLE_ID);
  candidate_size = read_remote_fixture(prefix, "rollback-next-candidate", s.qspi + XIAO_OTA_CANDIDATE_BASE,
                                       XIAO_OTA_CANDIDATE_SIZE);
  assert(candidate_size == next.exact_size_bytes);
  sha256_of(s.qspi + XIAO_OTA_CANDIDATE_BASE, candidate_size, next_hash);
  assert(memcmp(next_hash, next.sha256, 32) == 0);
  for (attempt = 0; attempt < 3; ++attempt) {
    assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
    assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_FAILED && state.candidate_counter == 5);
    assert(read_floor(&s, &floor) && floor.confirmed_counter_floor == 4);
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, running_size, digest);
    assert(memcmp(digest, running_hash, 32) == 0);
    sha256_of(s.qspi + XIAO_OTA_CANDIDATE_BASE, candidate_size, digest);
    assert(memcmp(digest, next_hash, 32) == 0);
  }
  assert(read_remote_fixture(prefix, "rollback-candidate", s.qspi + XIAO_OTA_CANDIDATE_BASE,
                             XIAO_OTA_CANDIDATE_SIZE) == previous.exact_size_bytes);
  assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_FAILED);
  /* The exact terminal state, not temporary QSPI hash refusal, consumes A. */
  memset(s.qspi + XIAO_OTA_STATE_A, 0xff, 2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.transaction_nonce == command.transaction_nonce && state.candidate_counter == 5);
  printf("real Trial->FailedMax/floor4 board=%08x role=%u retains consumed counter5 command; "
         "native signed ABORT(B)->different C READY/no COMMIT cannot install passed\n",
         (unsigned)XIAO_OTA_BOARD_TARGET, (unsigned)XIAO_OTA_COMPILED_ROLE_ID);
}

static void run_unconfirmed_fixture_rollback(fake_io_state_t *s, const xiao_ota_command_v2_t *command,
                                            uint32_t counter, size_t extent, const uint8_t backup_hash[32]) {
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  uint8_t digest[32];
  unsigned attempt;
  assert(fake_io_run_boot(s) == 0 && s->force_recovery_calls == 0);
  assert(read_state(s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.transaction_nonce == command->transaction_nonce && state.candidate_counter == counter);
  for (attempt = 0; attempt < XIAO_OTA_MAX_TRIAL_BOOTS; ++attempt)
    assert(fake_io_run_boot(s) == 0 && s->force_recovery_calls == 0);
  assert(read_state(s, &state) && state.phase == XIAO_OTA_PHASE_FAILED);
  assert(state.transaction_nonce == command->transaction_nonce && state.candidate_counter == counter);
  assert(state.active_image_extent == extent && memcmp(state.backup_hash_sha256, backup_hash, 32) == 0);
  assert(read_floor(s, &floor) && floor.confirmed_counter_floor == 4);
  sha256_of(s->internal_flash + XIAO_OTA_APP_START, extent, digest);
  assert(memcmp(digest, backup_hash, 32) == 0);
}

static void test_two_real_rollbacks_keep_older_command_safe_only_without_erasing_newest(const char *prefix) {
  fake_io_state_t s;
  xiao_ota_command_v2_t a, b;
  xiao_ota_wire_descriptor_t da, db, next;
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  uint8_t settings[28], canonical[59], digest[32], running_hash[32], next_hash[32];
  uint8_t pair[2 * XIAO_OTA_QSPI_SECTOR_SIZE], closed_state[2 * XIAO_OTA_QSPI_SECTOR_SIZE];
  const uint32_t safe_orders[][2] = {{1, 2}, {UINT32_MAX - 1, UINT32_MAX},
                                     {UINT32_MAX, 0}, {UINT32_C(0x80000002), 1}};
  size_t running_size, size;
  unsigned attempt, order, control;
  fake_io_reset(&s);
  assert(read_remote_fixture(prefix, "multi-rollback-command-a", (uint8_t *)&a, sizeof(a)) == sizeof(a));
  assert(read_remote_fixture(prefix, "multi-rollback-command-b", (uint8_t *)&b, sizeof(b)) == sizeof(b));
  assert(xiao_ota_command_v2_valid(&a) && xiao_ota_command_v2_valid(&b));
  assert(xiao_ota_wire_descriptor_decode(a.wire_descriptor, &da) && da.security_counter == 5);
  assert(xiao_ota_wire_descriptor_decode(b.wire_descriptor, &db) && db.security_counter == 6);
  assert(a.sequence == 1 && b.sequence == 2 && a.transaction_nonce != b.transaction_nonce);
  assert((((uint32_t)db.board_family << 16) | db.board_variant) == XIAO_OTA_BOARD_TARGET);
  assert(db.role == XIAO_OTA_COMPILED_ROLE_ID);
  running_size = read_remote_fixture(prefix, "multi-rollback-running", s.internal_flash + XIAO_OTA_APP_START,
                                     XIAO_OTA_APP_MAX_SIZE);
  assert(running_size == a.active_image_extent && running_size == b.active_image_extent);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, running_size, running_hash);
  assert(read_remote_fixture(prefix, "multi-rollback-sdk", settings, sizeof(settings)) == sizeof(settings));
  fake_io_write_settings_raw(&s, settings);
  assert(read_remote_fixture(prefix, "multi-rollback-floor", s.qspi + XIAO_OTA_FLOOR_A,
                             2 * XIAO_OTA_QSPI_SECTOR_SIZE) == 2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  memcpy(s.qspi + XIAO_OTA_COMMAND_A, &a, sizeof(a));
  assert(read_remote_fixture(prefix, "multi-rollback-candidate-a", s.qspi + XIAO_OTA_CANDIDATE_BASE,
                             XIAO_OTA_CANDIDATE_SIZE) == da.exact_size_bytes);
  run_unconfirmed_fixture_rollback(&s, &a, 5, running_size, running_hash);
  assert(read_remote_fixture(prefix, "multi-rollback-command-region", pair, sizeof(pair)) == sizeof(pair));
  assert(memcmp(pair, &a, sizeof(a)) == 0 &&
         memcmp(pair + XIAO_OTA_QSPI_SECTOR_SIZE, &b, sizeof(b)) == 0);
  memcpy(s.qspi + XIAO_OTA_COMMAND_A, pair, sizeof(pair));
  assert(read_remote_fixture(prefix, "multi-rollback-candidate-b", s.qspi + XIAO_OTA_CANDIDATE_BASE,
                             XIAO_OTA_CANDIDATE_SIZE) == db.exact_size_bytes);
  run_unconfirmed_fixture_rollback(&s, &b, 6, running_size, running_hash);
  assert(memcmp(pair, s.qspi + XIAO_OTA_COMMAND_A, sizeof(pair)) == 0);
  memcpy(closed_state, s.qspi + XIAO_OTA_STATE_A, sizeof(closed_state));

  assert(read_remote_fixture(prefix, "multi-rollback-next-canonical", canonical, sizeof(canonical)) == sizeof(canonical));
  assert(xiao_ota_wire_descriptor_decode(canonical, &next) && next.security_counter == 8);
  assert(next.role == db.role && next.board_family == db.board_family && next.board_variant == db.board_variant);
  size = read_remote_fixture(prefix, "multi-rollback-next-candidate", s.qspi + XIAO_OTA_CANDIDATE_BASE,
                             XIAO_OTA_CANDIDATE_SIZE);
  assert(size == next.exact_size_bytes);
  sha256_of(s.qspi + XIAO_OTA_CANDIDATE_BASE, size, next_hash);
  assert(memcmp(next_hash, next.sha256, 32) == 0);
  for (attempt = 0; attempt < 3; ++attempt) {
    assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
    assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_FAILED);
    assert(state.transaction_nonce == b.transaction_nonce && state.candidate_counter == 6);
    assert(read_floor(&s, &floor) && floor.confirmed_counter_floor == 4);
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, running_size, digest);
    assert(memcmp(digest, running_hash, 32) == 0);
    sha256_of(s.qspi + XIAO_OTA_CANDIDATE_BASE, size, digest);
    assert(memcmp(digest, next_hash, 32) == 0);
    assert(memcmp(pair, s.qspi + XIAO_OTA_COMMAND_A, sizeof(pair)) == 0);
  }

  /* B's exact staged bytes remove temporary hash refusal as an explanation.
   * The frozen loader must still select its consumed nonce, including wrap. */
  for (order = 0; order < sizeof(safe_orders) / sizeof(safe_orders[0]); ++order) {
    a.sequence = safe_orders[order][0]; b.sequence = safe_orders[order][1];
    a.crc32 = xiao_ota_crc32(&a, offsetof(xiao_ota_command_v2_t, crc32));
    b.crc32 = xiao_ota_crc32(&b, offsetof(xiao_ota_command_v2_t, crc32));
    memcpy(s.qspi + XIAO_OTA_COMMAND_A, &a, sizeof(a));
    memcpy(s.qspi + XIAO_OTA_COMMAND_B, &b, sizeof(b));
    assert(read_remote_fixture(prefix, "multi-rollback-candidate-b", s.qspi + XIAO_OTA_CANDIDATE_BASE,
                               XIAO_OTA_CANDIDATE_SIZE) == db.exact_size_bytes);
    assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
    assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_FAILED);
    assert(state.transaction_nonce == b.transaction_nonce && state.candidate_counter == 6);
  }

  /* Erasing the newest, losing the terminal state, or misranking an older,
   * tied or half-range-ambiguous record really can admit an old intent. */
  for (control = 0; control < 5; ++control) {
    memcpy(s.qspi + XIAO_OTA_STATE_A, closed_state, sizeof(closed_state));
    memcpy(s.qspi + XIAO_OTA_COMMAND_A, pair, sizeof(pair));
    assert(read_remote_fixture(prefix, "multi-rollback-running", s.internal_flash + XIAO_OTA_APP_START,
                               XIAO_OTA_APP_MAX_SIZE) == running_size);
    fake_io_write_settings_raw(&s, settings);
    if (control == 0) memset(s.qspi + XIAO_OTA_COMMAND_B, 0xff, XIAO_OTA_QSPI_SECTOR_SIZE);
    if (control == 1) memset(s.qspi + XIAO_OTA_STATE_A, 0xff, sizeof(closed_state));
    if (control >= 2) {
      memcpy(&a, pair, sizeof(a)); memcpy(&b, pair + XIAO_OTA_QSPI_SECTOR_SIZE, sizeof(b));
      a.sequence = control == 2 ? 3 : control == 3 ? 2 : 1;
      b.sequence = control == 4 ? UINT32_C(0x80000001) : 2;
      a.crc32 = xiao_ota_crc32(&a, offsetof(xiao_ota_command_v2_t, crc32));
      b.crc32 = xiao_ota_crc32(&b, offsetof(xiao_ota_command_v2_t, crc32));
      memcpy(s.qspi + XIAO_OTA_COMMAND_A, &a, sizeof(a)); memcpy(s.qspi + XIAO_OTA_COMMAND_B, &b, sizeof(b));
    }
    assert(read_remote_fixture(prefix, control == 1 ? "multi-rollback-candidate-b" : "multi-rollback-candidate-a",
                               s.qspi + XIAO_OTA_CANDIDATE_BASE, XIAO_OTA_CANDIDATE_SIZE) > 0);
    assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
    assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
    assert(state.candidate_counter == (control == 1 ? 6u : 5u));
  }
  printf("two real Trial->FailedMax rollbacks/floor4 board=%08x role=%u: signed precommit ABORT/reupload "
         "preserves both commands safely; production wrap + erase/newer/tie/half-range negative controls passed\n",
         (unsigned)XIAO_OTA_BOARD_TARGET, (unsigned)XIAO_OTA_COMPILED_ROLE_ID);
}

static void load_original_commit_fixture(fake_io_state_t *s, const char *prefix,
                                        xiao_ota_command_v2_t *command,
                                        xiao_ota_wire_descriptor_t *descriptor, uint8_t sdk[28],
                                        bool vendor_crc_unused) {
  xiao_ota_floor_t floor;
  uint8_t digest[32];
  size_t candidate_size, running_size;
  fake_io_reset(s);
  assert(read_remote_fixture(prefix, "original-command", (uint8_t *)command, sizeof(*command)) == sizeof(*command));
  assert(xiao_ota_command_v2_valid(command));
  assert(xiao_ota_wire_descriptor_decode(command->wire_descriptor, descriptor));
  assert((((uint32_t)descriptor->board_family << 16) | descriptor->board_variant) == XIAO_OTA_BOARD_TARGET);
  assert(descriptor->role == XIAO_OTA_COMPILED_ROLE_ID && descriptor->security_counter == 1);
  memcpy(s->qspi + XIAO_OTA_COMMAND_A, command, sizeof(*command));
  candidate_size = read_remote_fixture(prefix, "original-candidate", s->qspi + XIAO_OTA_CANDIDATE_BASE,
                                       XIAO_OTA_CANDIDATE_SIZE);
  running_size = read_remote_fixture(prefix, "original-running", s->internal_flash + XIAO_OTA_APP_START,
                                     XIAO_OTA_APP_MAX_SIZE);
  assert(candidate_size == descriptor->exact_size_bytes && running_size == command->active_image_extent);
  assert(read_remote_fixture(prefix, "original-sdk", sdk, 28) == 28);
  assert(sdk[2] == 0 && sdk[3] == 0);
  assert(running_size == 9004 && crc16_compute(s->internal_flash + XIAO_OTA_APP_START, 9001, NULL) != 0);
  if (!vendor_crc_unused) {
    const uint16_t crc = crc16_compute(s->internal_flash + XIAO_OTA_APP_START, 9001, NULL);
    sdk[2] = (uint8_t)crc; sdk[3] = (uint8_t)(crc >> 8);
  }
  fake_io_write_settings_raw(s, sdk);
  assert(read_remote_fixture(prefix, "original-floor", s->qspi + XIAO_OTA_FLOOR_A,
                             2 * XIAO_OTA_QSPI_SECTOR_SIZE) == 2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  assert(read_remote_fixture(prefix, "original-state-region", s->qspi + XIAO_OTA_STATE_A,
                             2 * XIAO_OTA_QSPI_SECTOR_SIZE) == 2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  assert(read_floor(s, &floor) && floor.sequence == 1 && floor.confirmed_counter_floor == 0);
  assert(floor.active_image_extent == 0);
  sha256_of(s->internal_flash + XIAO_OTA_APP_START, running_size, digest);
  assert(memcmp(digest, command->active_image_hash_sha256, 32) == 0);
}

static void test_exact_original_commit_confirmation_rollback_and_controls(const char *prefix,
                                                                         bool vendor_crc_unused) {
  fake_io_state_t s;
  xiao_ota_command_v2_t command;
  xiao_ota_wire_descriptor_t descriptor;
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  uint8_t sdk[28], current_sdk[28], digest[32], before_hash[32], terminal[2 * XIAO_OTA_QSPI_SECTOR_SIZE];
  unsigned control, attempt;

  for (control = 0; control < 4; ++control) {
    load_original_commit_fixture(&s, prefix, &command, &descriptor, sdk, vendor_crc_unused);
    if (control == 0) s.internal_flash[XIAO_OTA_APP_START + 100] ^= 1;
    if (control == 1) {
      const uint16_t wrong = crc16_compute(s.internal_flash + XIAO_OTA_APP_START, 9001, NULL) ^ 1;
      assert(wrong != 0);
      sdk[2] = (uint8_t)wrong; sdk[3] = (uint8_t)(wrong >> 8);
      fake_io_write_settings_raw(&s, sdk);
    }
    if (control == 2) {
      assert(read_floor(&s, &floor));
      floor.confirmed_counter_floor = 4;
      floor.crc32 = xiao_ota_crc32(&floor, offsetof(xiao_ota_floor_t, crc32));
      memcpy(s.qspi + XIAO_OTA_FLOOR_A, &floor, sizeof(floor));
    }
    if (control == 3) memset(s.qspi + XIAO_OTA_FLOOR_A, 0xff, 2 * XIAO_OTA_QSPI_SECTOR_SIZE);
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, command.active_image_extent, before_hash);
    (void)fake_io_run_boot(&s);
    assert(!read_state(&s, &state));
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, command.active_image_extent, digest);
    assert(memcmp(digest, before_hash, 32) == 0);
    fake_io_read_settings_raw(&s, current_sdk);
    assert(memcmp(current_sdk, sdk, sizeof(sdk)) == 0);
  }

  load_original_commit_fixture(&s, prefix, &command, &descriptor, sdk, vendor_crc_unused);
  assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.transaction_nonce == command.transaction_nonce && state.active_image_extent == 9004);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, descriptor.exact_size_bytes, digest);
  assert(memcmp(digest, descriptor.sha256, 32) == 0);
  write_confirmation(&s, state.transaction_nonce, state.candidate_counter, digest);
  assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor) && floor.confirmed_counter_floor == 1);

  load_original_commit_fixture(&s, prefix, &command, &descriptor, sdk, vendor_crc_unused);
  assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(crc16_compute(s.internal_flash + XIAO_OTA_APP_START, descriptor.exact_size_bytes, NULL) != 0);
  write_confirmation(&s, state.transaction_nonce, state.candidate_counter, descriptor.sha256);
  fake_io_read_settings_raw(&s, current_sdk);
  current_sdk[2] = current_sdk[3] = 0;
  fake_io_write_settings_raw(&s, current_sdk);
  assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_FAILED);
  fake_io_read_settings_raw(&s, current_sdk);
  assert(memcmp(current_sdk, sdk, sizeof(sdk)) == 0);

  load_original_commit_fixture(&s, prefix, &command, &descriptor, sdk, vendor_crc_unused);
  assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  for (attempt = 0; attempt < XIAO_OTA_MAX_TRIAL_BOOTS; ++attempt)
    assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_FAILED);
  assert(state.transaction_nonce == command.transaction_nonce && state.active_image_extent == 9004);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, command.active_image_extent, digest);
  assert(memcmp(digest, command.active_image_hash_sha256, 32) == 0);
  fake_io_read_settings_raw(&s, current_sdk);
  assert(memcmp(current_sdk, sdk, sizeof(sdk)) == 0);
  assert(read_floor(&s, &floor) && floor.confirmed_counter_floor == 0);
  memcpy(terminal, s.qspi + XIAO_OTA_STATE_A, sizeof(terminal));
  for (attempt = 0; attempt < 3; ++attempt) {
    assert(fake_io_run_boot(&s) == 0 && s.force_recovery_calls == 0);
    assert(memcmp(terminal, s.qspi + XIAO_OTA_STATE_A, sizeof(terminal)) == 0);
  }
  char failed_prefix[512];
  const int prefix_bytes = snprintf(failed_prefix, sizeof(failed_prefix), "%s-original-failed%s", prefix,
                                    vendor_crc_unused ? "" : "-nonzero");
  assert(prefix_bytes > 0 && (size_t)prefix_bytes < sizeof(failed_prefix));
  save_remote_fixture(failed_prefix, "state-region", s.qspi + XIAO_OTA_STATE_A,
                      2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  save_remote_fixture(failed_prefix, "command-region", s.qspi + XIAO_OTA_COMMAND_A,
                      2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  save_remote_fixture(failed_prefix, "running", s.internal_flash + XIAO_OTA_APP_START,
                      command.active_image_extent);
  fake_io_read_settings_raw(&s, current_sdk);
  save_remote_fixture(failed_prefix, "sdk", current_sdk, sizeof(current_sdk));
  printf("literal app original COMMIT board=%08x role=%u CRC=%s: genesis floor0, Trial->Confirmed, "
         "Trial->FailedMax exact SDK28/SHA restoration and SHA/CRC/floor/missing-genesis controls passed\n",
         (unsigned)XIAO_OTA_BOARD_TARGET, (unsigned)XIAO_OTA_COMPILED_ROLE_ID,
         vendor_crc_unused ? "vendor-zero" : "matching-nonzero");
}

int main(int argc, char **argv) {
  crypto_sign_keypair(xiao_ota_test_public_key_ed25519, g_test_secret_key);
  test_valid_usb_reflash_refuses_original_command_without_admission();
  assert(argc == 1 || argc == 2);
  if (argc == 2) {
    test_exact_rf_commit_deferred_reset_handoff_installs_and_confirms(argv[1]);
    test_retired_intent_cannot_install_ready_without_new_commit_after_bank_restore(argv[1]);
    test_consumed_failed_command_does_not_install_replacement_after_precommit_abort(argv[1]);
    test_two_real_rollbacks_keep_older_command_safe_only_without_erasing_newest(argv[1]);
    test_exact_original_commit_confirmation_rollback_and_controls(argv[1], true);
    test_exact_original_commit_confirmation_rollback_and_controls(argv[1], false);
  }
  return frozen_boot_process_tests_main();
}

#endif
