/*
 * Literal-execution boot-process integration tests: every scenario here
 * calls fake_io_run_boot() (which invokes the REAL, unmodified
 * xiao_ota_boot_process_io() -- the exact function the production
 * xiao_ota_boot_process() calls against real hardware) against a fake, in-
 * memory-model xiao_ota_io_t (fake_io.c). No OTA transaction decision is
 * reimplemented here: commands are built by calling the same
 * xiao_ota_wire_descriptor_encode()/xiao_ota_crc32() functions production
 * and the host tooling already share, and signed with a genuinely fresh,
 * test-runtime-generated Ed25519 keypair (tweetnacl crypto_sign_keypair()),
 * embedded directly into each built command's own
 * admitted_signer_public_key_ed25519 field -- exactly the same per-command
 * embedded-key verification path xiao_ota_boot_process_io() runs in
 * production, so this never depends on (or needs) any compile-time fixed
 * trust anchor or the real committed lab private key.
 */

#include "xiao_ota_record.h"
#include "xiao_ota_layout.h"
#include "xiao_ota_boot_io.h"
#include "xiao_ota_sha256.h"
#include "fake_io.h"
#include "tweetnacl.h"
#include "crc16.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Required by tweetnacl's crypto_sign_keypair()/crypto_sign(). Test-only,
 * deterministic (not cryptographically secure) -- fine, since this key
 * exists purely to exercise the real command verification path with a
 * genuinely fresh keypair never rooted in any committed secret. */
static uint32_t g_rand_state = 0x9E3779B9u;
void randombytes(unsigned char *buffer, unsigned long long length) {
  unsigned long long i;
  for (i = 0; i < length; ++i) {
    g_rand_state = g_rand_state * 1103515245u + 12345u;
    buffer[i] = (unsigned char)(g_rand_state >> 16);
  }
}

/* This test's own fresh keypair: its public half is copied into every
 * built command's admitted_signer_public_key_ed25519 field below (the
 * same field the real app durably snapshots at COMMIT), never fed to
 * the bootloader through any compile-time override. */
uint8_t xiao_ota_test_public_key_ed25519[32];
static uint8_t g_test_secret_key[64];

static void fill_pattern(uint8_t *buffer, size_t length, uint8_t seed) {
  size_t i;
  for (i = 0; i < length; ++i) buffer[i] = (uint8_t)(seed + i * 7u + i / 251u);
}

static void sha256_of(const uint8_t *data, size_t length, uint8_t out[32]) {
  xiao_ota_sha256_t sha;
  xiao_ota_sha256_init(&sha);
  xiao_ota_sha256_update(&sha, data, length);
  xiao_ota_sha256_final(&sha, out);
}

static void write_floor_direct(fake_io_state_t *s, uint32_t counter_floor,
                               uint32_t extent, const uint8_t hash[32]);

/* Provisions the current ("old") running application directly in fake
 * internal flash plus matching bank-0 settings, then writes the committed
 * floor record that represents the currently installed image. */
static void provision_old_image(fake_io_state_t *s, uint32_t size,
                                uint8_t seed, uint8_t out_hash[32]) {
  uint8_t *region = s->internal_flash + XIAO_OTA_APP_START;
  fill_pattern(region, size, seed);
  sha256_of(region, size, out_hash);
  fake_io_provision_bank0_settings(s, XIAO_OTA_BANK_VALID_APP,
                                  crc16_compute(region, size, NULL), size);
  write_floor_direct(s, 0, size, out_hash);
}

static void write_candidate(fake_io_state_t *s, uint32_t size, uint8_t seed,
                            uint8_t out_hash[32]) {
  uint8_t *buffer = (uint8_t *)&s->qspi[XIAO_OTA_CANDIDATE_BASE];
  assert(size <= XIAO_OTA_CANDIDATE_SIZE);
  fill_pattern(buffer, size, seed);
  sha256_of(buffer, size, out_hash);
}

/*
 * Builds and durably writes a fully real, signed install command -- the
 * SAME xiao_ota_wire_descriptor_encode()/crypto_sign()/xiao_ota_crc32()
 * production path every other build_and_write_command* helper below
 * uses -- but lets the caller supply ANY Ed25519 keypair to sign with
 * and embed as admitted_signer_public_key_ed25519, rather than always
 * the one process-global g_test_secret_key/xiao_ota_test_public_key_
 * ed25519 pair. This is what proves the bootloader genuinely verifies
 * against EACH command's OWN embedded key (the app-admitted-key design),
 * not merely against one fixed key that happens to be test-generated
 * instead of lab-committed.
 */
static void build_and_write_command_signed_by(
    fake_io_state_t *s, uint64_t nonce, uint32_t sequence, uint32_t counter,
    uint32_t image_size, const uint8_t candidate_hash[32],
    uint32_t active_extent, const uint8_t active_hash[32],
    const uint8_t secret_key[64], const uint8_t admitted_public_key[32]) {
  xiao_ota_wire_descriptor_t descriptor;
  uint8_t encoded[XIAO_OTA_WIRE_DESCRIPTOR_SIZE];
  unsigned char signed_message[64 + XIAO_OTA_WIRE_DESCRIPTOR_SIZE];
  unsigned long long signed_length = 0;
  xiao_ota_command_v2_t cmd;

  memset(&descriptor, 0, sizeof(descriptor));
  /* Must match the actual compiled board target (XIAO_OTA_BOARD_TARGET),
   * never a hardcoded XIAO literal -- otherwise every fixture using this
   * helper would build a command for the WRONG device when compiled for
   * any other board profile (e.g. SenseCap), and the real bootloader's
   * board-identity check would legitimately refuse it. */
  descriptor.board_family = (uint16_t)(XIAO_OTA_BOARD_TARGET >> 16);
  descriptor.board_variant = (uint16_t)(XIAO_OTA_BOARD_TARGET & 0xFFFFu);
  descriptor.role = (uint8_t)XIAO_OTA_COMPILED_ROLE_ID;
  descriptor.app_address = XIAO_OTA_APP_START;
  descriptor.exact_size_bytes = image_size;
  memcpy(descriptor.sha256, candidate_hash, 32);
  descriptor.security_counter = counter;
  descriptor.min_boot_capabilities = XIAO_OTA_CAP_QSPI_INSTALL;
  descriptor.format_id = XIAO_OTA_DESCRIPTOR_FORMAT;
  descriptor.key_id = XIAO_OTA_KEY_ID;
  descriptor.algorithm_id = XIAO_OTA_ALGORITHM_ED25519;
  xiao_ota_wire_descriptor_encode(&descriptor, encoded);

  crypto_sign(signed_message, &signed_length, encoded,
             XIAO_OTA_WIRE_DESCRIPTOR_SIZE, secret_key);
  assert(signed_length == 64 + XIAO_OTA_WIRE_DESCRIPTOR_SIZE);

  memset(&cmd, 0, sizeof(cmd));
  cmd.magic = XIAO_OTA_RECORD_MAGIC;
  cmd.record_version = XIAO_OTA_COMMAND_VERSION_CURRENT;
  cmd.record_bytes = sizeof(cmd);
  cmd.sequence = sequence;
  cmd.transaction_nonce = nonce;
  memcpy(cmd.wire_descriptor, encoded, sizeof(encoded));
  memcpy(cmd.admitted_signer_public_key_ed25519, admitted_public_key,
        sizeof(cmd.admitted_signer_public_key_ed25519));
  memcpy(cmd.signature_ed25519, signed_message, 64);
  cmd.active_image_extent = active_extent;
  memcpy(cmd.active_image_hash_sha256, active_hash, 32);
  cmd.crc32 = xiao_ota_crc32(&cmd, offsetof(xiao_ota_command_v2_t, crc32));
  cmd.commit_marker = XIAO_OTA_COMMIT_MARKER;

  memset(s->qspi + XIAO_OTA_COMMAND_A, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memcpy(s->qspi + XIAO_OTA_COMMAND_A, &cmd, sizeof(cmd));
  memset(s->qspi + XIAO_OTA_COMMAND_B, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
}

static void build_and_write_command(fake_io_state_t *s, uint64_t nonce,
                                    uint32_t sequence, uint32_t counter,
                                    uint32_t image_size,
                                    const uint8_t candidate_hash[32],
                                    uint32_t active_extent,
                                    const uint8_t active_hash[32]) {
  build_and_write_command_signed_by(s, nonce, sequence, counter, image_size,
                                    candidate_hash, active_extent, active_hash,
                                    g_test_secret_key,
                                    xiao_ota_test_public_key_ed25519);
}

static void write_confirmation(fake_io_state_t *s, uint64_t nonce,
                               uint32_t counter, const uint8_t hash[32]) {
  xiao_ota_confirmation_t confirmation;
  memset(&confirmation, 0, sizeof(confirmation));
  confirmation.magic = XIAO_OTA_CONFIRM_MAGIC;
  confirmation.record_version = XIAO_OTA_FORMAT_VERSION;
  confirmation.record_bytes = sizeof(confirmation);
  confirmation.sequence = 1;
  confirmation.transaction_nonce = nonce;
  confirmation.confirmed_counter = counter;
  memcpy(confirmation.confirmed_hash_sha256, hash, 32);
  confirmation.crc32 =
      xiao_ota_crc32(&confirmation, offsetof(xiao_ota_confirmation_t, crc32));
  confirmation.commit_marker = XIAO_OTA_COMMIT_MARKER;

  memset(s->qspi + XIAO_OTA_CONFIRM_A, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memcpy(s->qspi + XIAO_OTA_CONFIRM_A, &confirmation, sizeof(confirmation));
  memset(s->qspi + XIAO_OTA_CONFIRM_B, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
}

static void clear_confirmation(fake_io_state_t *s) {
  memset(s->qspi + XIAO_OTA_CONFIRM_A, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memset(s->qspi + XIAO_OTA_CONFIRM_B, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
}

/* Directly fabricates a structurally-valid floor record at slot A, for
 * exercising floor-safety guards (non-regression, idempotent-finish) that
 * the normal command/confirm flow can never itself construct out of
 * sequence, by construction of the production monotonic-counter checks. */
static void write_floor_direct(fake_io_state_t *s, uint32_t counter_floor,
                               uint32_t extent, const uint8_t hash[32]) {
  xiao_ota_floor_t floor;
  uint32_t marker = XIAO_OTA_COMMIT_MARKER;
  memset(&floor, 0, sizeof(floor));
  floor.magic = XIAO_OTA_FLOOR_MAGIC;
  floor.record_version = XIAO_OTA_FORMAT_VERSION;
  floor.record_bytes = sizeof(floor);
  floor.sequence = 1;
  floor.confirmed_counter_floor = counter_floor;
  floor.active_image_extent = extent;
  memcpy(floor.confirmed_hash_sha256, hash, 32);
  floor.crc32 = xiao_ota_crc32(&floor, offsetof(xiao_ota_floor_t, crc32));
  floor.commit_marker = marker;
  memset(s->qspi + XIAO_OTA_FLOOR_A, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memcpy(s->qspi + XIAO_OTA_FLOOR_A, &floor, sizeof(floor));
  memset(s->qspi + XIAO_OTA_FLOOR_B, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
}

/* Directly fabricates a structurally-valid state record at slot A, for
 * exercising confirmation-path guards against combinations (e.g. a
 * lower-counter TRIAL_BOOT than the existing floor) that the normal
 * command-acceptance flow can never itself construct, by construction of
 * the monotonic counter_floor > candidate_counter policy check. */
static void write_state_direct(fake_io_state_t *s, uint32_t phase,
                               uint64_t nonce, uint32_t candidate_counter,
                               uint32_t active_image_extent,
                               const uint8_t candidate_hash[32],
                               const uint8_t installed_hash[32]) {
  xiao_ota_state_t state;
  xiao_ota_settings_sidecar_t sidecar;
  /* The sidecar's frozen 28-byte snapshot is the ACTUAL live settings
   * page at the moment this fixture is called (read via
   * fake_io_read_settings_raw()) -- not arbitrary fabricated bytes.
   * This keeps the fabricated in-flight transaction byte-for-byte
   * consistent with the device state the bootloader would have seen at
   * admission time, while the previous_bank_0/_crc/_size triad mirrored
   * into the state record below is read from those SAME bytes so
   * xiao_ota_boot_process_io()'s bank0_triad_matches check still
   * agrees. */
  uint8_t live_settings_raw[XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE];
  uint16_t previous_bank_0;
  uint16_t previous_bank_0_crc;
  uint32_t previous_bank_0_size;

  fake_io_read_settings_raw(s, live_settings_raw);
  memcpy(&previous_bank_0, live_settings_raw + 0, 2);
  memcpy(&previous_bank_0_crc, live_settings_raw + 2, 2);
  memcpy(&previous_bank_0_size, live_settings_raw + 8, 4);

  memset(&state, 0, sizeof(state));
  state.magic = XIAO_OTA_RECORD_MAGIC;
  state.record_version = XIAO_OTA_FORMAT_VERSION;
  state.record_bytes = sizeof(state);
  state.sequence = 1;
  state.transaction_nonce = nonce;
  state.phase = phase;
  state.active_image_extent = active_image_extent;
  state.candidate_counter = candidate_counter;
  memcpy(state.candidate_hash_sha256, candidate_hash, 32);
  memcpy(state.installed_hash_sha256, installed_hash, 32);
  state.previous_bank_0 = previous_bank_0;
  state.previous_bank_0_crc = previous_bank_0_crc;
  state.previous_bank_0_size = previous_bank_0_size;
  state.crc32 = xiao_ota_crc32(&state, offsetof(xiao_ota_state_t, crc32));
  state.commit_marker = XIAO_OTA_COMMIT_MARKER;
  memset(s->qspi + XIAO_OTA_STATE_A, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memcpy(s->qspi + XIAO_OTA_STATE_A, &state, sizeof(state));
  memset(s->qspi + XIAO_OTA_STATE_B, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);

  /* Every ACTIVE-phase state record must be paired with a matching
   * settings sidecar (xiao_ota_boot_process_io()'s sidecar_matches_state
   * gate) -- fabricate one here bound to the same sequence/nonce, with a
   * frozen-snapshot bank-0 triad matching the state record's own
   * previous_bank_0/_crc/_size above, so tests that directly plant an
   * in-flight TRIAL_BOOT/etc. state record exercise the intended guard,
   * not the unrelated missing-sidecar or wrong-snapshot ones. This
   * helper never fabricates a command record, so the command-digest
   * half of the binding is simply not-applicable here (no command found
   * this boot). */
  memset(&sidecar, 0, sizeof(sidecar));
  sidecar.magic = XIAO_OTA_SIDECAR_MAGIC;
  sidecar.record_version = XIAO_OTA_FORMAT_VERSION;
  sidecar.record_bytes = sizeof(sidecar);
  sidecar.matching_state_sequence = state.sequence;
  sidecar.transaction_nonce = nonce;
  memcpy(sidecar.original_settings_raw, live_settings_raw,
        sizeof(sidecar.original_settings_raw));
  sidecar.crc32 = xiao_ota_crc32(&sidecar, offsetof(xiao_ota_settings_sidecar_t, crc32));
  sidecar.commit_marker = XIAO_OTA_COMMIT_MARKER;
  memcpy(s->qspi + XIAO_OTA_SETTINGS_SIDECAR_A, &sidecar, sizeof(sidecar));
}

static bool read_state(const fake_io_state_t *s, xiao_ota_state_t *out) {
  xiao_ota_state_t a, b;
  const void *newest;
  memcpy(&a, s->qspi + XIAO_OTA_STATE_A, sizeof(a));
  memcpy(&b, s->qspi + XIAO_OTA_STATE_B, sizeof(b));
  newest = xiao_ota_newest_valid(&a, &b, sizeof(a),
                                 (bool (*)(const void *))xiao_ota_state_valid);
  if (newest == NULL) return false;
  memcpy(out, newest, sizeof(*out));
  return true;
}

static bool read_floor(const fake_io_state_t *s, xiao_ota_floor_t *out) {
  xiao_ota_floor_t a, b;
  const void *newest;
  memcpy(&a, s->qspi + XIAO_OTA_FLOOR_A, sizeof(a));
  memcpy(&b, s->qspi + XIAO_OTA_FLOOR_B, sizeof(b));
  newest = xiao_ota_newest_valid(&a, &b, sizeof(a),
                                 (bool (*)(const void *))xiao_ota_floor_valid);
  if (newest == NULL) return false;
  memcpy(out, newest, sizeof(*out));
  return true;
}

static uint32_t read_bank0_size(const fake_io_state_t *s) {
  xiao_ota_bank0_settings_t settings;
  fake_io_read_bank0_settings(s, &settings);
  return settings.bank_0_size;
}

/*
 * Decisive proof of the app-admitted-signer-key design: TWO independently
 * generated Ed25519 keypairs, each signing (and embedding as
 * admitted_signer_public_key_ed25519) its OWN, separate install command,
 * both genuinely install/confirm. This is what actually distinguishes
 * "the bootloader verifies against this command's own embedded key" from
 * a test that would coincidentally still pass against one single fixed/
 * compiled-in anchor -- key B here is NEVER the process-global test key
 * any other fixture in this file uses, and is generated fresh inside this
 * test, so nothing else could make this pass except genuinely reading and
 * using each command's own embedded key.
 */
static void test_two_different_admitted_keys_each_verify_their_own_image(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], hash_a[32], hash_b[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  uint8_t public_key_a[32], secret_key_a[64];
  uint8_t public_key_b[32], secret_key_b[64];
  const uint32_t old_size = 8192;
  const uint32_t size_a = 4096;
  const uint32_t size_b = 12288;

  crypto_sign_keypair(public_key_a, secret_key_a);
  crypto_sign_keypair(public_key_b, secret_key_b);
  assert(memcmp(public_key_a, public_key_b, 32) != 0);

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x61, old_hash);

  /* First transaction: signed and admitted under key A. */
  write_candidate(&s, size_a, 0x62, hash_a);
  build_and_write_command_signed_by(&s, /*nonce=*/301, /*sequence=*/1,
                                    /*counter=*/1, size_a, hash_a, old_size,
                                    old_hash, secret_key_a, public_key_a);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  write_confirmation(&s, 301, 1, hash_a);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 1);

  /* Second, later transaction: signed and admitted under an entirely
   * DIFFERENT key B, rolling the floor forward again -- a real admin
   * key rotation, honoured purely because THIS command carries its own
   * admitted key, never because it happens to match key A. */
  write_candidate(&s, size_b, 0x63, hash_b);
  build_and_write_command_signed_by(&s, /*nonce=*/302, /*sequence=*/1,
                                    /*counter=*/2, size_b, hash_b, size_a,
                                    hash_a, secret_key_b, public_key_b);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  write_confirmation(&s, 302, 2, hash_b);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 2);
  assert(floor.active_image_extent == size_b);
  assert(memcmp(floor.confirmed_hash_sha256, hash_b, 32) == 0);
}

/*
 * A command whose admitted_signer_public_key_ed25519 has been mutated
 * (e.g. torn/corrupted after the app wrote it, or a bit-rot event) no
 * longer matches signature_ed25519 -- xiao_ota_install_command_decode()
 * must reject it on cryptographic grounds before the internal app is
 * ever touched. Proven directly on real internal_flash bytes (not just a
 * phase/return-code enum): the running application's code bytes are
 * byte-for-byte identical after the rejected boot to what they were
 * before it, i.e. no erase/program cycle against the app region ever
 * started. CRC32 is recomputed over the mutated record so this is
 * rejected by signature verification specifically, not merely caught
 * earlier by the cheaper structural CRC check. */
static void test_mutated_admitted_key_rejected_before_any_app_erase(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  xiao_ota_state_t state;
  xiao_ota_command_v2_t cmd;
  uint8_t internal_before[8192];
  const uint32_t old_size = 8192;
  const uint32_t new_size = 4096;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x71, old_hash);
  write_candidate(&s, new_size, 0x72, candidate_hash);
  build_and_write_command(&s, /*nonce=*/401, /*sequence=*/1, /*counter=*/1,
                          new_size, candidate_hash, old_size, old_hash);

  /* Mutate the durable command's embedded admitted key in place (as if a
   * torn/corrupted write landed only partway through this field), then
   * recompute CRC so the record is still STRUCTURALLY valid -- isolating
   * the test to the cryptographic admitted-key check specifically. */
  memcpy(&cmd, s.qspi + XIAO_OTA_COMMAND_A, sizeof(cmd));
  cmd.admitted_signer_public_key_ed25519[0] ^= 0x01u;
  cmd.crc32 = xiao_ota_crc32(&cmd, offsetof(xiao_ota_command_v2_t, crc32));
  memcpy(s.qspi + XIAO_OTA_COMMAND_A, &cmd, sizeof(cmd));
  assert(xiao_ota_command_v2_valid(&cmd)); /* structurally fine, still rejected below */

  memcpy(internal_before, s.internal_flash + XIAO_OTA_APP_START, sizeof(internal_before));

  assert(fake_io_run_boot(&s) == 0);

  /* Rejected: no trial/install state was ever opened. */
  assert(read_state(&s, &state) == false ||
        state.phase != XIAO_OTA_PHASE_TRIAL_BOOT);
  /* The real running app's own code bytes are untouched -- proof no
   * erase/program cycle against the internal app region ever began. */
  assert(memcmp(internal_before, s.internal_flash + XIAO_OTA_APP_START,
                sizeof(internal_before)) == 0);
}

/*
 * A torn/partial overwrite of the durable command record (the app's own
 * write of a NEW command interrupted before completing -- a bad CRC is
 * the direct, observable consequence, modelled here the same way other
 * torn-record fixtures throughout this file do: corrupt bytes, keep the
 * stale CRC) must never strand or regress an already-confirmed install:
 * with no readable/valid command and a healthy current app, boot must
 * behave exactly like the normal no-active-update case (confirmed state
 * intact, no forced recovery, no DFU-only stranding). The prior valid,
 * already-confirmed record (committed state + floor) must survive
 * completely untouched. */
static void test_torn_command_preserves_prior_confirmed_record(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  xiao_ota_state_t before_state, after_state;
  xiao_ota_floor_t before_floor, after_floor;
  const uint32_t old_size = 8192;
  const uint32_t new_size = 4096;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x81, old_hash);
  write_candidate(&s, new_size, 0x82, candidate_hash);
  build_and_write_command(&s, /*nonce=*/501, /*sequence=*/1, /*counter=*/1,
                          new_size, candidate_hash, old_size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  write_confirmation(&s, 501, 1, candidate_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &before_state));
  assert(before_state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &before_floor));

  /* Simulate a torn overwrite of command slot A by a would-be NEXT
   * transaction: a handful of bytes landed, the rest (including a
   * recomputed CRC) never did, leaving the stale/prior CRC in place
   * against now-mismatched body bytes -- i.e. genuinely unreadable, not
   * "erased" (xiao_ota_bytes_erased() must not mistake this for a
   * never-provisioned slot either). */
  memset(s.qspi + XIAO_OTA_COMMAND_A, 0x5A, 17);

  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &after_state));
  assert(after_state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(memcmp(&before_state, &after_state, sizeof(before_state)) == 0);
  assert(read_floor(&s, &after_floor));
  assert(memcmp(&before_floor, &after_floor, sizeof(before_floor)) == 0);
}

/* (a)/(HIGH2 regression): differently-sized old->new update, correct
 * confirmation advances the floor to the NEW (freshly verified) extent,
 * never the old backup extent. Run both directions, per the reviewer's
 * explicit repro sizes. */
static void test_resize_confirm(uint32_t old_size, uint32_t new_size) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t new_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x11, old_hash);
  write_candidate(&s, new_size, 0x55, new_hash);
  build_and_write_command(&s, /*nonce=*/1, /*sequence=*/1, /*counter=*/1,
                          new_size, new_hash, old_size, old_hash);

  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(read_bank0_size(&s) == new_size);

  write_confirmation(&s, /*nonce=*/1, /*counter=*/1, new_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 1);
  assert(floor.active_image_extent == new_size);
  assert(memcmp(floor.confirmed_hash_sha256, new_hash, 32) == 0);
}

/* (b): a byte-identical retry of an already-FAILED transaction must never
 * repeat a backup/install copy or reinstall; a genuinely new authenticated
 * command (full 64-bit nonce difference) must still be honoured. */
static void test_failed_retry_then_new_nonce(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t bad_candidate_hash[32];
  uint8_t good_candidate_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  uint32_t attempt;
  uint8_t internal_snapshot[4096];
  const uint32_t old_size = 65536;
  /* High 32 bits differ only -- regresses the prior uint32_t truncation
   * bug in xiao_ota_command_is_retry_of_failed_transaction() callers. */
  const uint64_t failed_nonce = (UINT64_C(0x00000001) << 32) | 0xAAAAAAAAu;
  const uint64_t new_nonce = (UINT64_C(0xABCDEF01) << 32) | 0xAAAAAAAAu;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x22, old_hash);
  write_candidate(&s, old_size, 0x77, bad_candidate_hash);
  build_and_write_command(&s, failed_nonce, 1, 1, old_size,
                          bad_candidate_hash, old_size, old_hash);

  /* Install succeeds structurally (hashes match at accept/backup/install
   * time -- this is the transport's own candidate, not corrupted), but no
   * confirmation is ever supplied, so the trial exhausts and rolls back. */
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  for (attempt = 0; attempt < XIAO_OTA_MAX_TRIAL_BOOTS; ++attempt) {
    assert(fake_io_run_boot(&s) == 0);
  }
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_FAILED);
  /* This device starts with a committed floor-0 record, so a
   * confirmed_counter_floor==0 floor is legitimately established well
   * before any OTA transaction ever confirms. That is not evidence of a
   * completed install; it simply records the currently running baseline.
   * The floor's own identity must match the OLD image, never the failed
   * candidate. */
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 0);
  assert(floor.active_image_extent == old_size);
  assert(memcmp(floor.confirmed_hash_sha256, old_hash, 32) == 0);
  /* Rollback must have restored the OLD image bytes/extent. */
  {
    uint8_t restored_hash[32];
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, restored_hash);
    assert(memcmp(restored_hash, old_hash, 32) == 0);
  }
  memcpy(internal_snapshot, s.internal_flash + XIAO_OTA_APP_START,
        sizeof(internal_snapshot));

  /* Same failed command, unchanged, still sitting in the command slot:
   * must be refused every subsequent boot with NO repeated copy. */
  for (attempt = 0; attempt < 3; ++attempt) {
    assert(fake_io_run_boot(&s) == 0);
    assert(read_state(&s, &state));
    assert(state.phase == XIAO_OTA_PHASE_FAILED);
    assert(memcmp(s.internal_flash + XIAO_OTA_APP_START, internal_snapshot,
                 sizeof(internal_snapshot)) == 0);
  }
  /* The floor-0 record established above must remain exactly unchanged
   * across every repeated refused-retry boot -- no re-derivation, no
   * drift. */
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 0);
  assert(floor.active_image_extent == old_size);
  assert(memcmp(floor.confirmed_hash_sha256, old_hash, 32) == 0);

  /* A genuinely new, differently-nonced authenticated command (high 32
   * bits differ only) must still be honoured. */
  write_candidate(&s, old_size, 0x99, good_candidate_hash);
  build_and_write_command(&s, new_nonce, 3, 2, old_size, good_candidate_hash,
                          old_size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.transaction_nonce == new_nonce);
  write_confirmation(&s, new_nonce, 2, good_candidate_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 2);
}

/* (d): power loss mid page-write during install is detected fail-closed on
 * the next boot and verifiably restores the OLD image/extent via backup.
 *
 * install copies the candidate IN PLACE over the live app region (the
 * region bank-0 metadata still describes as the OLD image). So an
 * interrupted install always leaves the app region straddling old/new
 * bytes, which means the fresh bank-0 CRC recheck on the very next boot
 * (have_active_extent) can never re-validate against the OLD extent it
 * still records -- by design this makes any resume-after-crash roll back
 * to the QSPI backup rather than blindly continuing the install. That is
 * intentional fail-closed behaviour, not a partial-copy bug: this test
 * exercises exactly that path end to end. */
static void test_crash_mid_install_then_rollback(bool sdk_crc_unused) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  uint8_t original_settings[28], restored_settings[28];
  xiao_ota_state_t state;
  const uint32_t old_size = 32768;
  const uint32_t new_size = 65536;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x33, old_hash);
  if (sdk_crc_unused) {
    assert(crc16_compute(s.internal_flash + XIAO_OTA_APP_START,
                         old_size, NULL) != 0);
    fake_io_provision_bank0_settings(&s, XIAO_OTA_BANK_VALID_APP, 0, old_size);
  }
  fake_io_read_settings_raw(&s, original_settings);
  write_candidate(&s, new_size, 0xCC, candidate_hash);
  build_and_write_command(&s, 7, 1, 1, new_size, candidate_hash, old_size,
                          old_hash);

  /* Crash on the 30th internal_write() call: partway into copy_qspi_to_
   * internal()'s SECOND sector (16 chunks/sector at COPY_CHUNK=256B), so
   * the first sector's completion is already durably checkpointed but the
   * second is not -- exercises a nonzero, sector-aligned progress
   * checkpoint rather than a crash right at the very start. */
  s.crash.op = FAKE_IO_OP_INTERNAL_WRITE;
  s.crash.after = 30;
  assert(fake_io_run_boot(&s) == 1);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_INSTALL_COPYING);
  assert(state.progress_bytes == XIAO_OTA_QSPI_SECTOR_SIZE);
  /* Bank-0 metadata must still show the OLD image -- the crash landed
   * strictly before write_boot_settings() could ever run. */
  assert(read_bank0_size(&s) == old_size);
  fake_io_read_settings_raw(&s, restored_settings);
  assert(memcmp(original_settings, restored_settings,
                sizeof(original_settings)) == 0);

  /* A nonzero SDK CRC rejects the partial candidate by CRC; an unused
   * zero SDK CRC MUST reject it by the fresh whole-original SHA instead.
   * Removing that SHA gate makes the zero-CRC case wrongly reach TRIAL. */
  s.crash.op = FAKE_IO_OP_NONE;
  s.crash.after = -1;
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_FAILED);
  assert(read_bank0_size(&s) == old_size);
  fake_io_read_settings_raw(&s, restored_settings);
  assert(memcmp(original_settings, restored_settings,
                sizeof(original_settings)) == 0);
  {
    uint8_t restored_hash[32];
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, restored_hash);
    assert(memcmp(restored_hash, old_hash, 32) == 0);
  }
}

/* (e): a confirmation that transport-level-matches (same nonce/counter/
 * hash) but no longer reflects what is actually running (USB reflash, or
 * flash damage, during the trial window) must never advance the floor;
 * the boot process must fail safe into rollback instead. */
static void test_stale_confirmation_never_advances_floor(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor, floor_before;
  bool had_floor_before;
  uint32_t attempt;
  const uint32_t old_size = 40960;
  const uint32_t new_size = 40960;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x44, old_hash);
  write_candidate(&s, new_size, 0xEE, candidate_hash);
  build_and_write_command(&s, 42, 1, 1, new_size, candidate_hash, old_size,
                          old_hash);

  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

  /* A transport-valid confirmation for THIS transaction... */
  write_confirmation(&s, 42, 1, candidate_hash);
  /* ...but the content actually running has since changed (simulated USB
   * CDC reflash of a different image during the trial window), and bank-0
   * metadata was never touched by that reflash path. */
  fill_pattern(s.internal_flash + XIAO_OTA_APP_START, new_size, 0x66);

  /* This device is floor-0-provisioned, so the floor-0 record (counter 0,
   * bound to the OLD image) already exists at this point -- capture it
   * so the assertion below can prove it is exactly UNCHANGED, not merely
   * re-check presence/absence. */
  had_floor_before = read_floor(&s, &floor_before);
  assert(had_floor_before);
  assert(floor_before.confirmed_counter_floor == 0);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_floor(&s, &floor) == had_floor_before);
  assert(memcmp(&floor, &floor_before, sizeof(floor)) == 0);
  assert(read_state(&s, &state));
  assert(state.phase != XIAO_OTA_PHASE_CONFIRMED);

  /* Falls through the existing rollback path exactly like an unconfirmed
   * trial; the OLD image is restored, and the floor is still untouched. */
  clear_confirmation(&s);
  for (attempt = 0; attempt < XIAO_OTA_MAX_TRIAL_BOOTS; ++attempt) {
    assert(fake_io_run_boot(&s) == 0);
  }
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_FAILED);
  assert(read_floor(&s, &floor));
  assert(memcmp(&floor, &floor_before, sizeof(floor)) == 0);
  {
    uint8_t restored_hash[32];
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, restored_hash);
    assert(memcmp(restored_hash, old_hash, 32) == 0);
  }
}

/* (f): an explicit upstream DFU/recovery request in progress must bypass
 * ALL OTA transaction work -- not even QSPI is initialised -- regardless
 * of any command/state sitting in QSPI. */
static void test_explicit_dfu_bypasses_ota(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];

  fake_io_reset(&s);
  provision_old_image(&s, 4096, 0x88, old_hash);
  write_candidate(&s, 4096, 0x99, candidate_hash);
  build_and_write_command(&s, 1, 1, 1, 4096, candidate_hash, 4096, old_hash);
  s.dfu_requested = true;

  assert(fake_io_run_boot(&s) == 0);
  assert(s.qspi_init_calls == 0);
  assert(s.force_recovery_calls == 0);
  assert(s.watchdog_start_calls == 0);
  /* Nothing was even read -- the command slot must remain exactly as
   * provisioned (no accept/backup work started). */
  {
    xiao_ota_state_t state;
    assert(!read_state(&s, &state));
  }
}

/* Astra HIGH-2 (idempotent confirmation resume): a crash that lands the
 * floor durably but not yet the state=CONFIRMED write must, on the very
 * next boot, finish CONFIRMED WITHOUT re-deriving or rewriting the floor
 * -- it is already correct for this exact transaction. */
static void test_floor_state_cut_idempotent_resume(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor_before, floor_after;
  const uint32_t size = 28672;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x12, old_hash);
  write_candidate(&s, size, 0x34, candidate_hash);
  build_and_write_command(&s, 55, 1, 1, size, candidate_hash, size,
                          old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  write_confirmation(&s, 55, 1, candidate_hash);

  /* Crash before ANY state-region write this call, i.e. right after the
   * floor was durably committed but before state=CONFIRMED lands. */
  s.crash.op = FAKE_IO_OP_QSPI_WRITE;
  s.crash.addr_lo = XIAO_OTA_STATE_A;
  s.crash.addr_hi = XIAO_OTA_STATE_B + XIAO_OTA_QSPI_SECTOR_SIZE;
  s.crash.after = 1;
  assert(fake_io_run_boot(&s) == 1);
  s.crash.op = FAKE_IO_OP_NONE;
  s.crash.after = -1;

  assert(read_floor(&s, &floor_before));
  assert(floor_before.confirmed_counter_floor == 1);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT); /* unchanged on disk */

  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor_after));
  /* Floor record bytes (including sequence) are untouched -- it was NOT
   * rewritten on the idempotent-finish path. */
  assert(memcmp(&floor_before, &floor_after, sizeof(floor_before)) == 0);
}

/* Astra HIGH-3 (state.sequence preservation): two consecutive full
 * transactions, cutting right after the SECOND transaction's very first
 * (acceptance-time) state commit. Without preserving state.sequence
 * across transactions (i.e. if it were reset to 0), a stale leftover
 * record from the FIRST transaction could still outrank this genuinely
 * newer record in xiao_ota_newest_valid()'s tie-break; asserts the
 * freshly read record is actually the second transaction's. */
static void test_sequence_preserved_across_transactions(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate1_hash[32];
  uint8_t candidate2_hash[32];
  xiao_ota_state_t state;
  uint32_t sequence_after_tx1;
  const uint32_t size1 = 65536;
  const uint32_t size2 = 98304;

  fake_io_reset(&s);
  provision_old_image(&s, size1, 0x41, old_hash);
  write_candidate(&s, size1, 0x51, candidate1_hash);
  build_and_write_command(&s, 100, 1, 1, size1, candidate1_hash, size1,
                          old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  write_confirmation(&s, 100, 1, candidate1_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  sequence_after_tx1 = state.sequence;

  write_candidate(&s, size2, 0x61, candidate2_hash);
  build_and_write_command(&s, 200, 1, 2, size2, candidate2_hash, size1,
                          candidate1_hash);
  s.crash.op = FAKE_IO_OP_QSPI_WRITE;
  s.crash.addr_lo = XIAO_OTA_STATE_A;
  s.crash.addr_hi = XIAO_OTA_STATE_B + XIAO_OTA_QSPI_SECTOR_SIZE;
  /* Acceptance's own persist_state() now durably writes FOUR records
   * (sidecar body+marker, then state body+marker) in the same call --
   * cut before the FIRST write of the NEXT persist_state() call
   * (backup-progress's sidecar body write). */
  s.crash.after = 5;
  assert(fake_io_run_boot(&s) == 1);
  s.crash.op = FAKE_IO_OP_NONE;
  s.crash.after = -1;

  assert(read_state(&s, &state));
  assert(state.candidate_counter == 2);
  assert(state.phase == XIAO_OTA_PHASE_BACKUP_COPYING);
  assert(state.progress_bytes == 0);
  assert(state.sequence == sequence_after_tx1 + 1);
  assert(memcmp(state.candidate_hash_sha256, candidate2_hash, 32) == 0);
}

/* Astra HIGH-3 (backup-authenticate-before-erase): the backup must be
 * hashed/verified BEFORE the first destructive erase of the live
 * (running-trial) app region. A corrupted backup discovered only after
 * an unconfirmed trial exhausts must escalate to recovery and leave the
 * live region completely untouched, never erase-then-discover-nothing-
 * to-restore. */
static void test_backup_authenticated_before_rollback_erase(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  uint8_t running_hash[32];
  uint32_t attempt;
  const uint32_t old_size = 40960;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x71, old_hash);
  write_candidate(&s, old_size, 0x81, candidate_hash);
  build_and_write_command(&s, 99, 1, 1, old_size, candidate_hash, old_size,
                          old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, running_hash);
  assert(memcmp(running_hash, candidate_hash, 32) == 0);

  /* Corrupt the durable QSPI backup after it was already made and
   * verified (e.g. bit rot), with no confirmation ever supplied. */
  s.qspi[XIAO_OTA_BACKUP_BASE] ^= 0xFFu;

  for (attempt = 0; attempt + 1 < XIAO_OTA_MAX_TRIAL_BOOTS; ++attempt) {
    assert(fake_io_run_boot(&s) == 0);
  }
  assert(s.force_recovery_calls == 0);
  /* The final trial boot exhausts the retry budget and transitions to
   * ROLLBACK_COPYING; authenticating the now-corrupt backup must happen
   * BEFORE any erase, escalating to recovery instead. */
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_ROLLBACK_COPYING);
  assert(state.progress_bytes == 0);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, running_hash);
  assert(memcmp(running_hash, candidate_hash, 32) == 0); /* untouched */
}

/* Astra HIGH-1 (pure I/O failure, not a crash): a transient QSPI read
 * failure while re-verifying the signed candidate at acceptance must be
 * treated as "cannot trust this hash" and refuse safely for this boot
 * cycle only -- no crash/reset, nothing ever committed -- while a LATER
 * boot with the fault cleared accepts the exact same still-pending
 * command normally. */
static void test_pure_io_failure_refuses_without_crash(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;

  fake_io_reset(&s);
  provision_old_image(&s, 32768, 0x91, old_hash);
  write_candidate(&s, 32768, 0xA1, candidate_hash);
  build_and_write_command(&s, 5, 1, 1, 32768, candidate_hash, 32768,
                          old_hash);

  s.fail.op = FAKE_IO_OP_QSPI_READ;
  s.fail.addr_lo = XIAO_OTA_CANDIDATE_BASE;
  s.fail.addr_hi = XIAO_OTA_CANDIDATE_BASE + 32768u;
  s.fail.after = 1;
  assert(fake_io_run_boot(&s) == 0); /* no crash -- just a false return */
  assert(!read_state(&s, &state));   /* nothing ever committed */
  assert(s.force_recovery_calls == 0);

  s.fail.op = FAKE_IO_OP_NONE;
  s.fail.after = -1;
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
}

/* Astra HIGH-1 (torn write / readback verify): a write interrupted after
 * only partially landing (device keeps running, not a full power-loss
 * crash) must be caught by write_record()'s own body readback-verify;
 * the FIRST (acceptance-time) persist_state failure must leave nothing
 * committed and refuse safely, with the signed command still available
 * for a clean retry next boot. */
static void test_torn_state_write_refuses_without_commit(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;

  fake_io_reset(&s);
  provision_old_image(&s, 16384, 0xB1, old_hash);
  write_candidate(&s, 16384, 0xC1, candidate_hash);
  build_and_write_command(&s, 9, 1, 1, 16384, candidate_hash, 16384,
                          old_hash);

  s.tear.op = FAKE_IO_OP_QSPI_WRITE;
  s.tear.addr_lo = XIAO_OTA_STATE_A;
  s.tear.addr_hi = XIAO_OTA_STATE_B + XIAO_OTA_QSPI_SECTOR_SIZE;
  s.tear.after = 1; /* the very first STATE body write lands short */
  s.tear_bytes = 8;

  assert(fake_io_run_boot(&s) == 0);
  assert(!read_state(&s, &state));
  assert(s.force_recovery_calls == 0);

  s.tear.op = FAKE_IO_OP_NONE;
  s.tear.after = -1;
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
}

/* Astra HIGH-2 (floor corruption defence): a floor pair that fails
 * structural validation but is NOT genuinely blank (bit rot / leftover
 * unrelated data, not "never provisioned") must refuse ALL new command
 * acceptance rather than silently reopening the anti-rollback counter
 * at 0. */
static void test_corrupt_floor_refuses_new_transaction(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;

  fake_io_reset(&s);
  provision_old_image(&s, 8192, 0xD1, old_hash);
  write_candidate(&s, 8192, 0xE1, candidate_hash);
  build_and_write_command(&s, 3, 1, 1, 8192, candidate_hash, 8192, old_hash);

  /* Leftover non-erased, non-valid garbage in BOTH floor slots -- not a
   * genuinely blank (never-provisioned) pair. */
  memset(s.qspi + XIAO_OTA_FLOOR_A, 0x42, 64);
  memset(s.qspi + XIAO_OTA_FLOOR_B, 0x42, 64);

  assert(fake_io_run_boot(&s) == 0);
  assert(!read_state(&s, &state));
  assert(s.force_recovery_calls == 0);
}

/* Astra HIGH-2 (floor non-regression): a legitimately higher floor
 * (from a LATER completed transaction) must never move backwards --
 * even given a transport-valid confirmation whose OWN state/hash
 * genuinely matches what is currently running -- if that state/
 * confirmation pairing describes an EARLIER (lower-counter) transaction
 * than the floor already durably reflects. */
static void test_floor_non_regression_refuses_stale_confirmation(void) {
  fake_io_state_t s;
  uint8_t running_hash[32];
  xiao_ota_floor_t floor;
  xiao_ota_state_t state;
  const uint32_t size = 20480;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0xF1, running_hash);
  write_floor_direct(&s, 5, size, running_hash);
  write_state_direct(&s, XIAO_OTA_PHASE_TRIAL_BOOT, 11, 1, size,
                     running_hash, running_hash);
  write_confirmation(&s, 11, 1, running_hash);

  assert(fake_io_run_boot(&s) == 0);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 5); /* untouched, not regressed */
  assert(read_state(&s, &state));
  assert(state.phase != XIAO_OTA_PHASE_CONFIRMED);
}

/* Astra HIGH-1 (no CONFIRMED without a durable floor): if persisting the
 * advanced floor fails, force_recovery() must fire and state must NEVER
 * be marked CONFIRMED; a later boot with the fault cleared confirms
 * normally against the exact same still-matching confirmation. */
static void test_no_confirmed_without_durable_floor(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;

  fake_io_reset(&s);
  provision_old_image(&s, 24576, 0xE9, old_hash);
  write_candidate(&s, 24576, 0xF9, candidate_hash);
  build_and_write_command(&s, 21, 1, 1, 24576, candidate_hash, 24576,
                          old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  write_confirmation(&s, 21, 1, candidate_hash);

  s.fail.op = FAKE_IO_OP_QSPI_WRITE;
  s.fail.addr_lo = XIAO_OTA_FLOOR_A;
  s.fail.addr_hi = XIAO_OTA_FLOOR_B + XIAO_OTA_QSPI_SECTOR_SIZE;
  s.fail.after = 1;
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  /* This device is floor-0-provisioned (provision_old_image()), so the
   * pre-existing floor-0 record (counter 0) still durably exists in
   * whichever sibling slot persist_floor() did NOT target -- the failed
   * write only ever erases+fails ITS OWN target sector, never the
   * other. The confirmation must still never be honoured (no ADVANCED
   * floor was durably persisted), so the readable floor must remain
   * exactly the pre-confirmation initial value, not the new counter. */
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

  s.fail.op = FAKE_IO_OP_NONE;
  s.fail.after = -1;
  assert(fake_io_run_boot(&s) == 0);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 1);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
}

/* Typed-pair-read (unreadable metadata) with an EXISTING in-flight
 * transaction present, not merely a first-ever-boot command read: a
 * transient QSPI read failure on the STATE pair mid-transaction must
 * fail closed (force_recovery, no mutation) rather than the failed read
 * being memset to EMPTY and silently treated as "no transaction". */
static void test_state_io_error_mid_transaction_force_recovery(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state_before, state_after;
  uint8_t internal_snapshot[65536];

  fake_io_reset(&s);
  provision_old_image(&s, sizeof(internal_snapshot), 0x15, old_hash);
  write_candidate(&s, sizeof(internal_snapshot), 0x25, candidate_hash);
  build_and_write_command(&s, 61, 1, 1, sizeof(internal_snapshot),
                          candidate_hash, sizeof(internal_snapshot), old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state_before));
  assert(state_before.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  memcpy(internal_snapshot, s.internal_flash + XIAO_OTA_APP_START,
        sizeof(internal_snapshot));

  /* A later, in-transaction boot (not the first-ever command read) hits
   * an unreadable STATE pair -- e.g. slot A. */
  s.fail.op = FAKE_IO_OP_QSPI_READ;
  s.fail.addr_lo = XIAO_OTA_STATE_A;
  s.fail.addr_hi = XIAO_OTA_STATE_A + XIAO_OTA_QSPI_SECTOR_SIZE;
  s.fail.after = 1;
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  /* Never mutated: the on-disk record, live app bytes, and floor (still
   * absent) are exactly as they were before this failed boot. */
  assert(read_state(&s, &state_after));
  assert(memcmp(&state_before, &state_after, sizeof(state_before)) == 0);
  assert(memcmp(s.internal_flash + XIAO_OTA_APP_START, internal_snapshot,
               sizeof(internal_snapshot)) == 0);

  /* Same fault on slot B instead. */
  fake_io_reset(&s);
  provision_old_image(&s, sizeof(internal_snapshot), 0x15, old_hash);
  write_candidate(&s, sizeof(internal_snapshot), 0x25, candidate_hash);
  build_and_write_command(&s, 61, 1, 1, sizeof(internal_snapshot),
                          candidate_hash, sizeof(internal_snapshot), old_hash);
  assert(fake_io_run_boot(&s) == 0);
  s.fail.op = FAKE_IO_OP_QSPI_READ;
  s.fail.addr_lo = XIAO_OTA_STATE_B;
  s.fail.addr_hi = XIAO_OTA_STATE_B + XIAO_OTA_QSPI_SECTOR_SIZE;
  s.fail.after = 1;
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
}

/* Same as above, for the FLOOR pair, with a genuinely EXISTING confirmed
 * floor record present (not the fresh-device MISSING case): an unreadable
 * floor slot mid-history must never be treated as floor==absent, which
 * would silently reopen the anti-rollback counter at 0. */
static void test_floor_io_error_with_existing_record_force_recovery(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_floor_t floor_before, floor_after;
  const uint32_t size = 12288;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x35, old_hash);
  write_candidate(&s, size, 0x45, candidate_hash);
  build_and_write_command(&s, 71, 1, 1, size, candidate_hash, size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  write_confirmation(&s, 71, 1, candidate_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_floor(&s, &floor_before));
  assert(floor_before.confirmed_counter_floor == 1);

  s.fail.op = FAKE_IO_OP_QSPI_READ;
  s.fail.addr_lo = XIAO_OTA_FLOOR_A;
  s.fail.addr_hi = XIAO_OTA_FLOOR_A + XIAO_OTA_QSPI_SECTOR_SIZE;
  s.fail.after = 1;
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  assert(read_floor(&s, &floor_after));
  assert(memcmp(&floor_before, &floor_after, sizeof(floor_before)) == 0);
}

/* Slot-selection-by-actual-physical-location, not sequence parity: a
 * structurally-valid record fabricated directly into slot A with an ODD
 * sequence number must still be recognised as the currently-trusted
 * record living in A, and the next successful persist must target B --
 * never erase A because "next sequence (odd+1=even) belongs in A" under
 * the old parity-based scheme, which would destroy the only trusted
 * record out from under a reader. */
static void test_persist_targets_actual_other_slot_not_parity(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  const uint32_t size = 16384;

  fake_io_reset(&s);
  write_candidate(&s, size, 0x65, candidate_hash);
  provision_old_image(&s, size, 0x65, old_hash);
  memcpy(candidate_hash, old_hash, 32); /* same bytes: currently running == candidate */

  /* Fabricate an odd-sequence TRIAL_BOOT state directly in slot A (the
   * normal command/accept flow can never itself produce an odd starting
   * sequence, since persist_state always writes sequence+1 from a
   * memset-zero start; this exercises the guard against relying on
   * parity as an invariant rather than proving it can't otherwise
   * happen). */
  write_state_direct(&s, XIAO_OTA_PHASE_TRIAL_BOOT, 81, 1, size,
                     candidate_hash, old_hash);
  write_confirmation(&s, 81, 1, candidate_hash);

  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  /* The record fabricated directly in A (sequence 1, odd) must have been
   * superseded by a NEW record in B (sequence 2) -- if the writer had
   * instead computed "sequence 1 -> next is even -> target A" it would
   * have erased slot A (the only place the trusted record ever lived)
   * before writing, which write_record()'s own final valid() readback-
   * gate would still catch as a self-consistency failure, but the
   * intended, actually-safe outcome is landing cleanly in B on the first
   * attempt. */
  assert(state.sequence == 2);
  {
    xiao_ota_state_t a, b;
    memcpy(&a, s.qspi + XIAO_OTA_STATE_A, sizeof(a));
    memcpy(&b, s.qspi + XIAO_OTA_STATE_B, sizeof(b));
    assert(a.sequence == 1 && a.commit_marker == XIAO_OTA_COMMIT_MARKER);
    assert(b.sequence == 2 && b.commit_marker == XIAO_OTA_COMMIT_MARKER);
  }
}

/* Equal-counter/different-hash floor conflict: the durable floor already
 * claims this exact counter for a DIFFERENT image identity than this
 * transaction's own candidate. Neither confirming (does not match the
 * floor) nor rolling back (this transaction's own stashed backup
 * reference may not describe whatever is genuinely running) is safe --
 * must escalate to recovery, touching neither floor nor live flash. */
static void test_floor_equal_counter_different_hash_conflict(void) {
  fake_io_state_t s;
  uint8_t running_hash[32];
  uint8_t other_hash[32];
  xiao_ota_floor_t floor_before, floor_after;
  xiao_ota_state_t state;
  const uint32_t size = 24576;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x95, running_hash);
  {
    uint8_t scratch[64];
    fill_pattern(scratch, sizeof(scratch), 0xA5);
    sha256_of(scratch, sizeof(scratch), other_hash);
  }

  /* Durable floor already claims counter 1 for `other_hash` (some earlier,
   * different image identity than what is running now). */
  write_floor_direct(&s, 1, size, other_hash);
  /* This transaction's own state/confirmation matches what is ACTUALLY
   * running (running_hash) at the SAME counter 1 -- a genuine identity
   * conflict at that counter, not a stale/superseded case. */
  write_state_direct(&s, XIAO_OTA_PHASE_TRIAL_BOOT, 91, 1, size,
                     running_hash, running_hash);
  write_confirmation(&s, 91, 1, running_hash);

  assert(read_floor(&s, &floor_before));
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  assert(read_floor(&s, &floor_after));
  assert(memcmp(&floor_before, &floor_after, sizeof(floor_before)) == 0);
  assert(read_state(&s, &state));
  assert(state.phase != XIAO_OTA_PHASE_CONFIRMED);
  {
    uint8_t live_hash[32];
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, size, live_hash);
    assert(memcmp(live_hash, running_hash, 32) == 0); /* untouched */
  }
}

/* Idempotent-resume floor-identity gap: the durable floor already agrees
 * with THIS transaction on both counter and hash (so the hash-conflict
 * branch above does not fire), the live image genuinely verifies, but the
 * floor's OWN active_image_extent field disagrees with the freshly
 * verified live extent -- an internally inconsistent committed floor
 * record (e.g. a torn/corrupted floor write that landed the right hash
 * bytes but a stale/garbage extent). Counter+hash equality alone must
 * NOT be treated as full floor identity; this must force-recovery rather
 * than finish CONFIRMED or silently trust/rewrite the floor. */
static void test_floor_matching_counter_hash_but_wrong_extent_conflict(void) {
  fake_io_state_t s;
  uint8_t running_hash[32];
  xiao_ota_floor_t floor_before, floor_after;
  xiao_ota_state_t state;
  const uint32_t size = 24576;
  const uint32_t wrong_extent = size + 4096;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x77, running_hash);

  /* Floor agrees on counter (1) and hash (running_hash), but its own
   * active_image_extent field is wrong/inconsistent with what that hash
   * actually describes. */
  write_floor_direct(&s, 1, wrong_extent, running_hash);
  write_state_direct(&s, XIAO_OTA_PHASE_TRIAL_BOOT, 77, 1, size,
                     running_hash, running_hash);
  write_confirmation(&s, 77, 1, running_hash);

  assert(read_floor(&s, &floor_before));
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  assert(read_floor(&s, &floor_after));
  assert(memcmp(&floor_before, &floor_after, sizeof(floor_before)) == 0);
  assert(read_state(&s, &state));
  assert(state.phase != XIAO_OTA_PHASE_CONFIRMED);
  {
    uint8_t live_hash[32];
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, size, live_hash);
    assert(memcmp(live_hash, running_hash, 32) == 0); /* untouched */
  }
}

/* Same signed image AND same counter as an already-FAILED transaction,
 * differing ONLY in the transaction nonce's high 32 bits: must be
 * accepted as a genuinely new, distinct authenticated request (never
 * conflated with the byte-identical retry this policy specifically
 * refuses), and must install/confirm normally. */
static void test_same_image_same_counter_high32_nonce_is_new_request(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  const uint32_t size = 20480;
  const uint64_t failed_nonce = (UINT64_C(0x11111111) << 32) | 0x22222222u;
  const uint64_t new_nonce = (UINT64_C(0x99999999) << 32) | 0x22222222u;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0xB5, old_hash);
  write_candidate(&s, size, 0xC5, candidate_hash);
  build_and_write_command(&s, failed_nonce, 1, 1, size, candidate_hash, size,
                          old_hash);
  assert(fake_io_run_boot(&s) == 0);
  {
    uint32_t attempt;
    for (attempt = 0; attempt < XIAO_OTA_MAX_TRIAL_BOOTS; ++attempt) {
      assert(fake_io_run_boot(&s) == 0);
    }
  }
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_FAILED);

  /* SAME image bytes/hash, SAME counter (1), SAME command sequencing
   * pattern -- only the nonce's high 32 bits differ from the failed
   * transaction above. */
  build_and_write_command(&s, new_nonce, 3, 1, size, candidate_hash, size,
                          old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.transaction_nonce == new_nonce);
  write_confirmation(&s, new_nonce, 1, candidate_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 1);
}

/* Hardware bring-up (Point 5): an unreadable/unresponsive QSPI at
 * qspi_init() must fail closed before anything else is touched -- no
 * command/state/floor read, no mutation. */
static void test_qspi_init_failure_force_recovery(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];

  fake_io_reset(&s);
  provision_old_image(&s, 8192, 0xD5, old_hash);
  write_candidate(&s, 8192, 0xE5, candidate_hash);
  build_and_write_command(&s, 1, 1, 1, 8192, candidate_hash, 8192, old_hash);

  s.fail.op = FAKE_IO_OP_QSPI_INIT;
  s.fail.after = 1;
  assert(fake_io_run_boot(&s) == 0);
  assert(s.qspi_init_calls == 1);
  assert(s.force_recovery_calls == 1);
  {
    xiao_ota_state_t state;
    assert(!read_state(&s, &state));
  }
}

/* Raw bank-0 settings-page torn commit: the settings page is modelled as
 * the real Nordic bootloader_settings_t raw bytes at
 * XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS inside internal flash, written
 * through the SAME production erase/program/verify codec
 * (xiao_ota_settings_set()) every real settings write uses. Tearing that
 * program call after only the VALID_APP flag/CRC bytes land (bank_0_size
 * onward stays at its just-erased 0xFF value) during finalize must be
 * treated exactly like any other finalize failure -- roll back, never
 * silently report installed -- and the ExtraFS region beyond the
 * install/rollback ceiling must survive completely untouched throughout,
 * both across the failed finalize attempt and the subsequent full
 * rollback. */
static void test_torn_settings_commit_during_finalize_forces_rollback(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  const uint32_t old_size = 32768;
  const uint32_t extrafs_offset = XIAO_OTA_APP_START + XIAO_OTA_INSTALL_MAX_SIZE;
  uint8_t extrafs_sentinel[4096];

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x25, old_hash);
  write_candidate(&s, old_size, 0x35, candidate_hash);
  build_and_write_command(&s, 111, 1, 1, old_size, candidate_hash, old_size,
                          old_hash);

  fill_pattern(s.internal_flash + extrafs_offset, sizeof(extrafs_sentinel),
              0x5A);
  memcpy(extrafs_sentinel, s.internal_flash + extrafs_offset,
        sizeof(extrafs_sentinel));

  s.tear.op = FAKE_IO_OP_INTERNAL_WRITE;
  s.tear.after = 1;
  s.tear.addr_lo = XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS;
  s.tear.addr_hi =
      XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE;
  /* Real erase-then-program settings write: the page is fully erased
   * first, then the whole 28-byte raw record is programmed in one call.
   * Tearing that program call after only the first 4 bytes lands the NEW
   * bank_0/bank_0_crc fields but leaves bank_0_size (byte offset 8
   * onward) at its just-erased 0xFF value -- an oversized/implausible
   * size xiao_ota_resolve_active_extent() must refuse, exactly the
   * "flag landed, size/CRC describe something else" torn-page outcome
   * this test exercises. */
  s.tear_bytes = 4;
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  /* finalize_install_and_verify() must treat the torn (failure-returning)
   * settings_set exactly like any other failed finalize step: never
   * TRIAL_BOOT, route to rollback instead. This torn write is a genuine
   * one-shot interruption (like a real single power-loss glitch mid-
   * program), not a persistently broken settings page -- the very next
   * matching write within the SAME boot call (rollback restoring the
   * previous, already-valid bank-0 settings) succeeds normally, so a
   * single boot cycle can carry all the way through to FAILED with the
   * old image and its settings intact. */
  assert(state.phase == XIAO_OTA_PHASE_FAILED);
  assert(memcmp(s.internal_flash + extrafs_offset, extrafs_sentinel,
               sizeof(extrafs_sentinel)) == 0);

  s.tear.after = -1;
  assert(state.phase == XIAO_OTA_PHASE_FAILED);
  {
    uint8_t restored_hash[32];
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, restored_hash);
    assert(memcmp(restored_hash, old_hash, 32) == 0);
  }
  assert(read_bank0_size(&s) == old_size);
  assert(memcmp(s.internal_flash + extrafs_offset, extrafs_sentinel,
               sizeof(extrafs_sentinel)) == 0);
}

/* Full legal-capacity round trip: both the OLD (backup) and NEW
 * (candidate) images are exactly XIAO_OTA_INSTALL_MAX_SIZE (0xAD000),
 * the actual maximum this project will ever sign or install -- not a
 * small 320KiB-500KiB proxy size. A genuine signed install command
 * admits it, backup-copies the old image, installs the new one, then
 * (with no confirmation ever supplied) exhausts every trial boot and
 * genuinely rolls back. Throughout every phase, this asserts ALL bytes
 * of BOTH QSPI physical banks' tail regions past the writable cap --
 * XIAO_OTA_CANDIDATE_BASE+INSTALL_MAX_SIZE..+CANDIDATE_SIZE ("SecA",
 * 0xAD000..0xC6000) and XIAO_OTA_BACKUP_BASE+INSTALL_MAX_SIZE..
 * +BACKUP_SIZE ("SecB", 0x173000..0x18C000), each exactly 100KiB -- and
 * the internal ExtraFS region (XIAO_OTA_APP_START+INSTALL_MAX_SIZE..
 * 0xED000, also 100KiB at this exact cap) remain byte-for-byte
 * untouched, and that the rolled-back image, its bank-0 size, and the
 * FULL 28-byte raw settings page (not just bank_0/bank_0_crc) are
 * restored to their exact pre-install originals. */
static void test_full_capacity_backup_install_rollback_preserves_tail_regions(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32], restored_hash[32];
  uint8_t backup_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  uint8_t original_sdk28[28], restored_sdk28[28];
  static uint8_t secA_sentinel[0x19000], secB_sentinel[0x19000];
  static uint8_t extrafs_sentinel[0x19000];
  uint32_t attempt;
  const uint32_t size = XIAO_OTA_INSTALL_MAX_SIZE; /* 0xAD000: legal max */
  const uint32_t secA_offset = XIAO_OTA_CANDIDATE_BASE + size;
  const uint32_t secB_offset = XIAO_OTA_BACKUP_BASE + size;
  const uint32_t extrafs_offset = XIAO_OTA_APP_START + size;

  _Static_assert(sizeof(secA_sentinel) ==
                    (XIAO_OTA_CANDIDATE_SIZE - XIAO_OTA_INSTALL_MAX_SIZE),
                "SecA/SecB tail sentinel size must match the real "
                "capacity/stride gap (0x19000, 100KiB)");

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x11, old_hash);
  fake_io_read_settings_raw(&s, original_sdk28);

  fill_pattern(extrafs_sentinel, sizeof(extrafs_sentinel), 0x5E);
  memcpy(s.internal_flash + extrafs_offset, extrafs_sentinel,
        sizeof(extrafs_sentinel));

  write_candidate(&s, size, 0x91, candidate_hash);

  fill_pattern(secA_sentinel, sizeof(secA_sentinel), 0xC3);
  memcpy(s.qspi + secA_offset, secA_sentinel, sizeof(secA_sentinel));
  fill_pattern(secB_sentinel, sizeof(secB_sentinel), 0xA7);
  memcpy(s.qspi + secB_offset, secB_sentinel, sizeof(secB_sentinel));

  build_and_write_command(&s, 0x9000000000000001ULL, 1, 1, size,
                          candidate_hash, size, old_hash);

  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, size, restored_hash);
  assert(memcmp(restored_hash, candidate_hash, 32) == 0);
  sha256_of(s.qspi + XIAO_OTA_BACKUP_BASE, size, backup_hash);
  assert(memcmp(backup_hash, old_hash, 32) == 0);
  assert(memcmp(s.qspi + secA_offset, secA_sentinel, sizeof(secA_sentinel)) == 0);
  assert(memcmp(s.qspi + secB_offset, secB_sentinel, sizeof(secB_sentinel)) == 0);
  assert(memcmp(s.internal_flash + extrafs_offset, extrafs_sentinel,
               sizeof(extrafs_sentinel)) == 0);

  for (attempt = 0; attempt < XIAO_OTA_MAX_TRIAL_BOOTS; ++attempt) {
    assert(fake_io_run_boot(&s) == 0);
  }
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_FAILED);
  /* Initial floor-0 device: the pre-existing floor-0 record (counter
   * 0, bound to the OLD image) still exists and is untouched -- never
   * confirmed, so no floor advance ever occurred. */
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 0);

  sha256_of(s.internal_flash + XIAO_OTA_APP_START, size, restored_hash);
  assert(memcmp(restored_hash, old_hash, 32) == 0);
  assert(read_bank0_size(&s) == size);
  fake_io_read_settings_raw(&s, restored_sdk28);
  assert(memcmp(restored_sdk28, original_sdk28, sizeof(original_sdk28)) == 0);
  assert(memcmp(s.qspi + secA_offset, secA_sentinel, sizeof(secA_sentinel)) == 0);
  assert(memcmp(s.qspi + secB_offset, secB_sentinel, sizeof(secB_sentinel)) == 0);
  assert(memcmp(s.internal_flash + extrafs_offset, extrafs_sentinel,
               sizeof(extrafs_sentinel)) == 0);
}

/* A genuine, validly-signed command declaring active_image_extent ==
 * 0xAE000 (one word past XIAO_OTA_INSTALL_MAX_SIZE, still %4==0) must be
 * refused at admission by the absolute capacity bound in
 * xiao_ota_install_command_static_identity_valid() BEFORE any erase,
 * backup copy, or install copy -- not merely because it happens to
 * mismatch some other unrelated field. The device's own recorded
 * (settings-derived) active extent is ALSO set to 0xAE000 here so the
 * ordinary active_image_extent-vs-expected-extent equality check would
 * otherwise agree; only the absolute cap defends this. Full internal
 * flash and QSPI images are snapshotted after all command/candidate
 * setup and compared byte-for-byte after the boot call: not one byte
 * anywhere may change, proving no out-of-cap read, erase, or copy of
 * any kind was ever attempted. */
static void test_active_extent_above_capacity_refused_before_any_mutation(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  uint8_t *internal_snapshot, *qspi_snapshot;
  const uint32_t size = XIAO_OTA_INSTALL_MAX_SIZE + 0x1000u; /* 0xAE000 */

  internal_snapshot = malloc(FAKE_IO_INTERNAL_SIZE);
  qspi_snapshot = malloc(FAKE_IO_QSPI_SIZE);
  assert(internal_snapshot != NULL && qspi_snapshot != NULL);

  fake_io_reset(&s);
  /* Deliberately synthesizes a device whose already-recorded extent is
   * itself above the cap, purely to isolate the absolute-cap refusal
   * from the ordinary extent-equality check -- never a state a real
   * signed install could produce, since that same cap already refuses
   * every prior install this large. */
  provision_old_image(&s, size, 0x63, old_hash);
  write_candidate(&s, size, 0x29, candidate_hash);
  build_and_write_command(&s, 0x9100000000000002ULL, 1, 1, size,
                          candidate_hash, size, old_hash);

  memcpy(internal_snapshot, s.internal_flash, FAKE_IO_INTERNAL_SIZE);
  memcpy(qspi_snapshot, s.qspi, FAKE_IO_QSPI_SIZE);

  assert(fake_io_run_boot(&s) == 0);

  assert(s.force_recovery_calls == 0);
  assert(s.watchdog_start_calls == 0);
  assert(memcmp(s.internal_flash, internal_snapshot, FAKE_IO_INTERNAL_SIZE) == 0);
  assert(memcmp(s.qspi, qspi_snapshot, FAKE_IO_QSPI_SIZE) == 0);

  free(internal_snapshot);
  free(qspi_snapshot);
}

/* Builds a raw 28-byte bootloader_settings_t page with EXPLICIT,
 * distinctive ancillary (non-bank-0) field values -- bank_1/
 * sd_image_size/bl_image_size/app_image_size/sd_image_start -- at their
 * real SDK byte offsets, so a test can prove those fields survive a
 * rollback restore verbatim, not merely "whatever RMW-over-current
 * happened to preserve". */
static void build_settings_raw(uint16_t bank_0, uint16_t bank_0_crc,
                               uint32_t bank_0_size, uint16_t bank_1,
                               uint32_t sd_image_size, uint32_t bl_image_size,
                               uint32_t app_image_size,
                               uint32_t sd_image_start, uint8_t out[28]) {
  uint16_t reserved_pad = 0;
  memset(out, 0, 28);
  memcpy(out + 0, &bank_0, 2);
  memcpy(out + 2, &bank_0_crc, 2);
  memcpy(out + 4, &bank_1, 2);
  memcpy(out + 6, &reserved_pad, 2);
  memcpy(out + 8, &bank_0_size, 4);
  memcpy(out + 12, &sd_image_size, 4);
  memcpy(out + 16, &bl_image_size, 4);
  memcpy(out + 20, &app_image_size, 4);
  memcpy(out + 24, &sd_image_start, 4);
}

/* Sidecar design acceptance (1/4): rollback must restore the settings
 * page to the EXACT 28 bytes frozen once at this transaction's
 * admission, including every ancillary (non-bank-0) field -- never
 * rebuilt from whatever the page currently holds. Corrupting the
 * CURRENT ancillary bytes mid-transaction (after admission, before
 * rollback) and then requiring the post-rollback page match the
 * ORIGINAL, pre-corruption snapshot is what actually distinguishes this
 * from a plain RMW-over-current restore, which would instead durably
 * preserve the corruption. */
static void test_rollback_restores_settings_raw_verbatim(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  uint8_t original_raw[28];
  uint8_t final_raw[28];
  uint8_t custom_raw[28];
  uint32_t attempt;
  const uint32_t old_size = 20480;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x12, old_hash);
  {
    xiao_ota_bank0_settings_t current;
    fake_io_read_bank0_settings(&s, &current);
    build_settings_raw(current.bank_0, current.bank_0_crc,
                       current.bank_0_size, 0xFEu, 0x22222222u,
                       0x33333333u, 0x44444444u, 0x55555555u, custom_raw);
  }
  fake_io_write_settings_raw(&s, custom_raw);
  fake_io_read_settings_raw(&s, original_raw);

  write_candidate(&s, old_size, 0x22, candidate_hash);
  build_and_write_command(&s, 501, 1, 1, old_size, candidate_hash, old_size,
                          old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

  /* Corrupt the CURRENT page's ancillary bytes (bank_1, byte offset 4)
   * directly, simulating page damage/drift after admission -- the
   * frozen sidecar snapshot must be used for the eventual restore
   * instead, never this corrupted "current" value. */
  s.internal_flash[XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + 4] ^= 0xFFu;

  for (attempt = 0; attempt + 1 < XIAO_OTA_MAX_TRIAL_BOOTS; ++attempt) {
    assert(fake_io_run_boot(&s) == 0);
  }
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_FAILED);

  fake_io_read_settings_raw(&s, final_raw);
  assert(memcmp(final_raw, original_raw, 28) == 0);
}

/* Sidecar design acceptance (2/4): an ACTIVE (non-terminal) transaction
 * whose settings sidecar is genuinely MISSING (e.g. a transaction begun
 * before this sidecar existed) must never be silently accepted or
 * reconstructed -- force_recovery(), untouched. */
static void test_active_transaction_missing_sidecar_forces_recovery(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t before, after;

  fake_io_reset(&s);
  provision_old_image(&s, 8192, 0x62, old_hash);
  write_candidate(&s, 8192, 0x72, candidate_hash);
  write_state_direct(&s, XIAO_OTA_PHASE_TRIAL_BOOT, 71, 1, 8192,
                     candidate_hash, old_hash);
  /* write_state_direct() always plants a matching sidecar alongside the
   * state it fabricates (see its own doc-comment) -- explicitly erase it
   * back to blank here to model the genuinely-missing case this test
   * targets. */
  memset(s.qspi + XIAO_OTA_SETTINGS_SIDECAR_A, 0xFF,
        sizeof(xiao_ota_settings_sidecar_t));
  assert(read_state(&s, &before));

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  assert(read_state(&s, &after));
  assert(memcmp(&before, &after, sizeof(before)) == 0);
}

/* Sidecar design acceptance (3/4): a sidecar that reads back structurally
 * valid but whose matching_state_sequence/transaction_nonce disagree with
 * the currently-trusted state record (a torn write between the sidecar
 * and state commits landing a stale-but-valid sidecar in the other slot)
 * must be treated exactly like a missing one for an ACTIVE transaction --
 * force_recovery(), never silently trusted or ignored. */
static void test_active_transaction_mismatched_sidecar_forces_recovery(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t before, after;
  xiao_ota_settings_sidecar_t sidecar;

  fake_io_reset(&s);
  provision_old_image(&s, 8192, 0x63, old_hash);
  write_candidate(&s, 8192, 0x73, candidate_hash);
  write_state_direct(&s, XIAO_OTA_PHASE_TRIAL_BOOT, 71, 1, 8192,
                     candidate_hash, old_hash);
  assert(read_state(&s, &before));

  memcpy(&sidecar, s.qspi + XIAO_OTA_SETTINGS_SIDECAR_A, sizeof(sidecar));
  sidecar.transaction_nonce ^= 0x1u; /* now disagrees with state's nonce */
  sidecar.crc32 =
      xiao_ota_crc32(&sidecar, offsetof(xiao_ota_settings_sidecar_t, crc32));
  memcpy(s.qspi + XIAO_OTA_SETTINGS_SIDECAR_A, &sidecar, sizeof(sidecar));

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  assert(read_state(&s, &after));
  assert(memcmp(&before, &after, sizeof(before)) == 0);
}

/* Regression for the NEW command-digest binding specifically: sequence,
 * nonce and bank0-triad all still agree, but the sidecar's frozen
 * command_digest_sha256 no longer matches the (still-present, unchanged)
 * accepted command record's actual bytes -- e.g. a stray write elsewhere
 * corrupted just that field, or a torn write landed an old sidecar body
 * paired by chance with a state/command sharing the same sequence/nonce.
 * Reached through the REAL admission path (not write_state_direct(), so
 * the command record genuinely exists and command_digest_matches is
 * actually exercised, not vacuously true). */
static void test_active_transaction_command_digest_mismatch_forces_recovery(
    void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  xiao_ota_state_t before, after;
  xiao_ota_settings_sidecar_t sidecar;
  uint32_t sidecar_slot;

  fake_io_reset(&s);
  provision_old_image(&s, 8192, 0x82, old_hash);
  write_candidate(&s, 8192, 0x92, candidate_hash);
  build_and_write_command(&s, 801, 1, 1, 8192, candidate_hash, 8192, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &before));
  assert(before.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

  {
    xiao_ota_state_t a;
    memcpy(&a, s.qspi + XIAO_OTA_STATE_A, sizeof(a));
    sidecar_slot = xiao_ota_state_valid(&a) && a.sequence == before.sequence
                      ? XIAO_OTA_SETTINGS_SIDECAR_A
                      : XIAO_OTA_SETTINGS_SIDECAR_B;
  }
  memcpy(&sidecar, s.qspi + sidecar_slot, sizeof(sidecar));
  sidecar.command_digest_sha256[0] ^= 0xFFu;
  sidecar.crc32 =
      xiao_ota_crc32(&sidecar, offsetof(xiao_ota_settings_sidecar_t, crc32));
  memcpy(s.qspi + sidecar_slot, &sidecar, sizeof(sidecar));

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  assert(read_state(&s, &after));
  assert(memcmp(&before, &after, sizeof(before)) == 0);
}

/* Regression for the NEW bank0-triad binding specifically: sequence,
 * nonce and command digest all still agree, but the sidecar's frozen
 * original_settings_raw describes a DIFFERENT bank_0/bank_0_crc/
 * bank_0_size triad than the durable state's own previous_bank_0/_crc/
 * _size -- a CRC-valid sidecar for the WRONG snapshot, which must never
 * be trusted to drive install/rollback. */
static void test_active_transaction_bank0_triad_mismatch_forces_recovery(
    void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  xiao_ota_state_t before, after;
  xiao_ota_settings_sidecar_t sidecar;
  uint32_t sidecar_slot;
  uint16_t wrong_bank_0;

  fake_io_reset(&s);
  provision_old_image(&s, 8192, 0x83, old_hash);
  write_candidate(&s, 8192, 0x93, candidate_hash);
  build_and_write_command(&s, 802, 1, 1, 8192, candidate_hash, 8192, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &before));
  assert(before.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

  {
    xiao_ota_state_t a;
    memcpy(&a, s.qspi + XIAO_OTA_STATE_A, sizeof(a));
    sidecar_slot = xiao_ota_state_valid(&a) && a.sequence == before.sequence
                      ? XIAO_OTA_SETTINGS_SIDECAR_A
                      : XIAO_OTA_SETTINGS_SIDECAR_B;
  }
  memcpy(&sidecar, s.qspi + sidecar_slot, sizeof(sidecar));
  memcpy(&wrong_bank_0, sidecar.original_settings_raw, 2);
  wrong_bank_0 = (uint16_t)(wrong_bank_0 ^ 0xFFFFu);
  memcpy(sidecar.original_settings_raw, &wrong_bank_0, 2);
  sidecar.crc32 =
      xiao_ota_crc32(&sidecar, offsetof(xiao_ota_settings_sidecar_t, crc32));
  memcpy(s.qspi + sidecar_slot, &sidecar, sizeof(sidecar));

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  assert(read_state(&s, &after));
  assert(memcmp(&before, &after, sizeof(before)) == 0);
}

/* REQUIRED RAW FAULT MATRIX (install path): a genuine power-loss cut
 * partway through the settings page's single 28-byte program word-run
 * (finalize_install_and_verify()'s xiao_ota_settings_apply_bank0() call)
 * aborts the ENTIRE boot call (fake processor resets right there, no
 * further code runs, nothing gets persisted past what already landed
 * durably). By this point the candidate has already been fully copied
 * into the live app region, so whether a genuine separate reboot safely
 * resumes FORWARD (finishing the install) or safely rolls ALL THE WAY
 * BACK (to the old image/settings) depends entirely on how much of the
 * new bank_0/bank_0_crc/bank_0_size triad (the only fields
 * active_extent_from_settings() ever reads) had actually landed before
 * the cut -- exactly the real hardware behaviour this fake_io_crash
 * model exists to prove, not a hand-picked single byte count:
 *   - tear_bytes < 12 (fewer than all of bank_0/crc/size's first 12
 *     bytes landed): fresh bank-0 metadata still describes something
 *     other than the already-copied candidate -- correctly detected and
 *     rolled all the way back to the OLD image/settings, matching
 *     test_crash_mid_install_rollback()'s copy-phase safety property.
 *   - tear_bytes >= 12 (the full triad landed, only ancillary/padding
 *     fields at byte 12+ still erased): bank-0 already legitimately
 *     describes the candidate -- correctly resumes FORWARD, re-runs
 *     finalize with the fault cleared (idempotent), and reaches
 *     TRIAL_BOOT, never stranding a genuinely-finished install. */
static void test_install_settings_write_reboot_resume_matrix(void) {
  size_t tear_bytes;

  /* tear_bytes runs 0..RAW_SIZE inclusive: 0..27 are genuine partial
   * program-word cuts, and RAW_SIZE (28) is the "fully applied before
   * ack" cut -- the physical write completes correctly but the crash
   * still lands before any caller ever observes success, exactly like
   * every other cut here requiring a genuine separate reboot to resume. */
  for (tear_bytes = 0; tear_bytes <= XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE;
      ++tear_bytes) {
    fake_io_state_t s;
    uint8_t old_hash[32];
    uint8_t candidate_hash[32];
    uint8_t running_hash[32];
    xiao_ota_state_t state;
    const uint32_t old_size = 8192;
    const size_t triad_bytes = 12; /* bank_0(2)+bank_0_crc(2)+bank_1(2)+
                                    * reserved_pad(2)+bank_0_size(4) */

    fake_io_reset(&s);
    provision_old_image(&s, old_size, 0xB1, old_hash);
    write_candidate(&s, old_size, 0xC1, candidate_hash);
    build_and_write_command(&s, 900 + (uint64_t)tear_bytes, 1, 1, old_size,
                            candidate_hash, old_size, old_hash);

    s.tear.op = FAKE_IO_OP_INTERNAL_WRITE;
    s.tear.after = 1;
    s.tear.addr_lo = XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS;
    s.tear.addr_hi = XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS +
                    XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE;
    s.tear_bytes = tear_bytes;
    s.tear_crash = true;

    assert(fake_io_run_boot(&s) == 1); /* crashed mid program-word */
    assert(read_state(&s, &state));
    assert(state.phase == XIAO_OTA_PHASE_INSTALL_COPYING);
    assert(state.progress_bytes == old_size);
    assert(s.force_recovery_calls == 0);

    /* Genuine separate reboot: fault cleared, fresh call. */
    s.tear.after = -1;
    s.tear_crash = false;
    assert(fake_io_run_boot(&s) == 0);
    assert(s.force_recovery_calls == 0);
    assert(read_state(&s, &state));
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, running_hash);
    if (tear_bytes < triad_bytes) {
      assert(state.phase == XIAO_OTA_PHASE_FAILED);
      assert(memcmp(running_hash, old_hash, 32) == 0);
      assert(read_bank0_size(&s) == old_size);
    } else {
      assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
      assert(memcmp(running_hash, candidate_hash, 32) == 0);
      assert(read_bank0_size(&s) == old_size); /* candidate reused old_size */
    }
  }
}

/* REQUIRED RAW FAULT MATRIX (rollback path): the same genuine
 * power-loss-cut-then-reboot treatment, but for the ROLLBACK restore's
 * settings write (xiao_ota_settings_restore_raw()) instead of install's.
 * By the time this write runs the backup has already been authenticated
 * and fully copied back into the live app region THIS boot call
 * (progress_bytes==active_image_extent, persisted); the cut must leave
 * that intact and NOT mark FAILED until a later, fault-cleared reboot's
 * settings write actually lands and verifies. */
static void test_rollback_settings_write_reboot_resume_matrix(void) {
  size_t tear_bytes;

  /* Inclusive of RAW_SIZE (28): "fully applied before ack", see the
   * install-path matrix above for the same reasoning. */
  for (tear_bytes = 0; tear_bytes <= XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE;
      ++tear_bytes) {
    fake_io_state_t s;
    uint8_t old_hash[32];
    uint8_t candidate_hash[32];
    uint8_t running_hash[32];
    xiao_ota_state_t state;
    uint32_t attempt;
    const uint32_t old_size = 8192;

    fake_io_reset(&s);
    provision_old_image(&s, old_size, 0xD1, old_hash);
    write_candidate(&s, old_size, 0xE1, candidate_hash);
    /* A candidate hash that will never match the actually-installed
     * image forces every trial boot to keep failing confirmation, so
     * the retry budget exhausts and rollback runs -- reuse the same
     * technique as test_stale_confirmation_never_advances_floor()/
     * test_rollback_restores_settings_raw_verbatim(). */
    build_and_write_command(&s, 950 + (uint64_t)tear_bytes, 1, 1, old_size,
                            candidate_hash, old_size, old_hash);
    assert(fake_io_run_boot(&s) == 0);
    assert(read_state(&s, &state));
    assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

    /* Corrupt the durable QSPI backup's hash expectation is NOT wanted
     * here (that path escalates to force_recovery instead); simply
     * exhaust the trial-boot retry budget without ever confirming. */
    for (attempt = 0; attempt + 1 < XIAO_OTA_MAX_TRIAL_BOOTS; ++attempt) {
      assert(fake_io_run_boot(&s) == 0);
    }

    s.tear.op = FAKE_IO_OP_INTERNAL_WRITE;
    s.tear.after = 1;
    s.tear.addr_lo = XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS;
    s.tear.addr_hi = XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS +
                    XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE;
    s.tear_bytes = tear_bytes;
    s.tear_crash = true;

    /* Final trial boot: exhausts the budget, copies the backup back,
     * then the restore write itself is cut mid-word. */
    assert(fake_io_run_boot(&s) == 1);
    assert(read_state(&s, &state));
    assert(state.phase == XIAO_OTA_PHASE_ROLLBACK_COPYING);
    assert(state.progress_bytes == state.active_image_extent);
    assert(s.force_recovery_calls == 0);
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, running_hash);
    assert(memcmp(running_hash, old_hash, 32) == 0); /* backup already back */

    s.tear.after = -1;
    s.tear_crash = false;
    assert(fake_io_run_boot(&s) == 0);
    assert(s.force_recovery_calls == 0);
    assert(read_state(&s, &state));
    assert(state.phase == XIAO_OTA_PHASE_FAILED);
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, running_hash);
    assert(memcmp(running_hash, old_hash, 32) == 0);
    assert(read_bank0_size(&s) == old_size);
  }
}

/* Sidecar design acceptance (4/4): the settings page's normally-unused
 * tail (beyond the real 28-byte bootloader_settings_t) must read as
 * genuinely blank checked at fresh COMMAND ADMISSION -- before any
 * destructive work (candidate/backup copy, state mutation) starts for
 * this transaction -- not only later, discovered mid-way through
 * finalize/rollback with the transaction already stranded. Poisoning it
 * here must therefore refuse the fresh signed command outright with
 * ZERO state/candidate/backup mutation and no force_recovery (an
 * ordinary admission refusal, exactly like every other admission check),
 * leaving the still-unconsumed command to be retried automatically once
 * the fault clears on a later boot. */
static void test_settings_tail_poisoned_refuses_write(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  uint8_t running_hash[32];
  xiao_ota_state_t state;
  const uint32_t old_size = 8192;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x64, old_hash);
  write_candidate(&s, old_size, 0x74, candidate_hash);
  build_and_write_command(&s, 601, 1, 1, old_size, candidate_hash, old_size,
                          old_hash);
  fake_io_poison_settings_tail(&s, 100, 0x42u);

  /* A poisoned settings-page tail is unexplained device anomaly, not an
   * ordinary "no acceptable command this boot" outcome -- it must
   * force_recovery() (the same observable USB UF2/CDC escalation used
   * for every other fail-closed case), not silently continue as if
   * nothing were wrong. Nothing is mutated either way: no state record,
   * running app untouched. */
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  /* No transaction was ever admitted: no state record exists at all. */
  assert(!read_state(&s, &state));
  /* The running (old) application is completely untouched. */
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, running_hash);
  assert(memcmp(running_hash, old_hash, 32) == 0);

  /* Once the tail is no longer poisoned, the exact same still-pending
   * signed command is retried normally on a later boot and proceeds,
   * with no further force_recovery(). */
  s.internal_flash[XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + 100] = 0xFFu;
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
}

static void test_partial_state_marker_conservatively_burns_possible_retry(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  xiao_ota_state_t before, after, a;
  const uint32_t size = 8192;
  uint32_t target;
  int grants_before_cut;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x81, old_hash);
  write_candidate(&s, size, 0x91, candidate_hash);
  build_and_write_command(&s, 701, 1, 1, size, candidate_hash, size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &before));
  assert(before.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  grants_before_cut = s.watchdog_start_calls;
  memcpy(&a, s.qspi + XIAO_OTA_STATE_A, sizeof(a));
  target = xiao_ota_state_valid(&a) && a.sequence == before.sequence
               ? XIAO_OTA_STATE_B : XIAO_OTA_STATE_A;

  s.tear.op = FAKE_IO_OP_QSPI_WRITE;
  s.tear.after = 2;
  s.tear.addr_lo = target;
  s.tear.addr_hi = target + sizeof(xiao_ota_state_t) - 1;
  s.tear_bytes = 2;
  s.tear_crash = true;
  assert(fake_io_run_boot(&s) == 1);
  assert(s.watchdog_start_calls == grants_before_cut);
  assert(read_state(&s, &after));
  assert(memcmp(&before, &after, sizeof(before)) == 0);

  s.tear.after = -1;
  s.tear_crash = false;
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &after));
  assert(after.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(after.transaction_nonce == before.transaction_nonce);
  /* The complete child body may already have granted retry +1.
   * Reconstruct that fact before publishing and granting retry +2. */
  assert(after.trial_attempts == before.trial_attempts + 2);
  assert(s.watchdog_start_calls == grants_before_cut + 1);
}

static void test_prepared_sidecar_retains_committed_state_pair(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  xiao_ota_state_t before, after;
  const uint32_t size = 8192;
  uint32_t target;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x81, old_hash);
  write_candidate(&s, size, 0x91, candidate_hash);
  build_and_write_command(&s, 701, 1, 1, size, candidate_hash, size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &before));
  assert(before.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  {
    xiao_ota_state_t a;
    memcpy(&a, s.qspi + XIAO_OTA_STATE_A, sizeof(a));
    target = xiao_ota_state_valid(&a) && a.sequence == before.sequence
                 ? XIAO_OTA_STATE_B : XIAO_OTA_STATE_A;
  }
  s.crash.op = FAKE_IO_OP_QSPI_WRITE;
  s.crash.after = 1;
  s.crash.addr_lo = target;
  s.crash.addr_hi = target + sizeof(xiao_ota_state_t);
  assert(fake_io_run_boot(&s) == 1);
  assert(read_state(&s, &after));
  assert(memcmp(&before, &after, sizeof(before)) == 0);

  s.crash.after = -1;
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &after));
  assert(after.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(after.transaction_nonce == before.transaction_nonce);
  assert(after.trial_attempts == before.trial_attempts + 1);
}

/*
 * Astra follow-up regression: exactly one physical slot passing valid()
 * must NOT be enough for read_pair() to return FOUND unconditionally.
 * Slot A here holds an older (sequence 1), fully valid, still-committed
 * TRIAL_BOOT record; slot B holds a NEWER (sequence 2) record that WAS
 * also fully committed (marker programmed) but has since been corrupted
 * (one body byte flipped after its CRC was computed, so valid() now
 * fails while the commit marker itself is untouched/still committed).
 * The pre-fix read_pair() (built on a bare xiao_ota_newest_valid() call)
 * would silently trust slot A as "the" current state, hiding B's
 * corruption entirely and resurrecting stale state as if authoritative.
 * The fixed version must recognize slot B was previously committed
 * (its marker reads committed, its tail is not blank) and refuse instead
 * of falling back to A.
 *
 * `marker_only`, mirroring run_corrupted_committed_newer_floor_refuses_
 * stale_trust() below, exercises the DEEPER variant of this same bug:
 * slot B's CRC-covered body is left FULLY self-consistent (nothing
 * flipped there at all) and only a single marker bit -- in one of the
 * marker's own zero-positions -- is set, exactly the byte pattern real
 * bit rot on an already-committed marker produces, and exactly what a
 * genuinely torn in-flight marker write could ALSO have left behind.
 * With no signed command visible at all this boot (this fixture never
 * calls build_and_write_command()), slot_safe_to_overwrite()'s state-
 * ambiguity binding check has nothing to bind to and must refuse to
 * discard slot B, regardless of how clean slot A looks.
 */
static void run_corrupted_committed_newer_state_refuses_stale_fallback(
    bool marker_only) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  xiao_ota_state_t fabricated;

  fake_io_reset(&s);
  provision_old_image(&s, 8192, 0xC3, old_hash);

  /* Slot A: older, fully valid, committed TRIAL_BOOT record. */
  write_state_direct(&s, XIAO_OTA_PHASE_TRIAL_BOOT, /*nonce=*/1,
                     /*candidate_counter=*/1, 8192, old_hash, old_hash);

  /* Slot B: newer (sequence 2), was fully committed, then corrupted. */
  memset(&fabricated, 0, sizeof(fabricated));
  fabricated.magic = XIAO_OTA_RECORD_MAGIC;
  fabricated.record_version = XIAO_OTA_FORMAT_VERSION;
  fabricated.record_bytes = sizeof(fabricated);
  fabricated.sequence = 2;
  fabricated.transaction_nonce = 2;
  fabricated.phase = XIAO_OTA_PHASE_CONFIRMED;
  fabricated.active_image_extent = 8192;
  fabricated.candidate_counter = 1;
  memcpy(fabricated.candidate_hash_sha256, old_hash, 32);
  memcpy(fabricated.installed_hash_sha256, old_hash, 32);
  fabricated.crc32 = xiao_ota_crc32(&fabricated, offsetof(xiao_ota_state_t, crc32));
  fabricated.commit_marker = XIAO_OTA_COMMIT_MARKER;
  if (marker_only) {
    const uint32_t zero_bits = ~XIAO_OTA_COMMIT_MARKER;
    fabricated.commit_marker |= zero_bits & (~zero_bits + 1u);
  }
  memcpy(s.qspi + XIAO_OTA_STATE_B, &fabricated, sizeof(fabricated));
  if (!marker_only) {
    /* Corrupt AFTER the CRC/marker were committed -- the marker itself
     * stays intact, only the body now disagrees with its own CRC. */
    s.qspi[XIAO_OTA_STATE_B + offsetof(xiao_ota_state_t, candidate_counter)] ^= 0xFF;
  }

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
}

static void test_corrupted_committed_newer_state_refuses_stale_fallback(void) {
  run_corrupted_committed_newer_state_refuses_stale_fallback(false);
}

/*
 * See run_corrupted_committed_newer_state_refuses_stale_fallback()'s
 * doc-comment: the marker-bit-rot variant of the same regression,
 * exercising slot_safe_to_overwrite()'s deeper body-valid-but-marker-
 * ambiguous check for STATE (not just FLOOR).
 */
static void test_committed_state_marker_bit_set_never_reopens_stale_state(void) {
  run_corrupted_committed_newer_state_refuses_stale_fallback(true);
}

/*
 * Main's follow-up regression: nonce agreement ALONE is not sufficient
 * binding evidence for STATE -- see state_ambiguous_binding_ok()'s
 * doc-comment. Slot A holds an older, fully valid, durable TRIAL_BOOT
 * record with trial_attempts=0. Slot B holds a NEWER (sequence 2)
 * record for the SAME transaction (same nonce, same command still
 * visible this boot) that reached trial_attempts=2 -- two full retries
 * beyond slot A's count, more than a single legitimate write starting
 * from slot A could ever produce -- and was then marker-bit-rotted
 * (body/CRC untouched). A binding check that only compared nonces would
 * happily discard slot B and fall back to slot A, silently forgetting
 * two already-spent trial boots and regranting them: with
 * XIAO_OTA_MAX_TRIAL_BOOTS == 3, the device would then get up to 3 MORE
 * retries instead of the 1 it has actually earned. This must instead
 * force recovery.
 */
static void test_committed_state_marker_damage_same_nonce_cannot_regrant_trials(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  xiao_ota_state_t fabricated;
  const uint32_t size = 8192;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x6C, old_hash);
  write_candidate(&s, size, 0x7C, candidate_hash);
  build_and_write_command(&s, /*nonce=*/1, /*sequence=*/1, /*counter=*/1, size,
                          candidate_hash, size, old_hash);

  /* Slot A: older, fully valid, committed TRIAL_BOOT record, trial_attempts=0
   * (write_state_direct()'s fixed fields). */
  write_state_direct(&s, XIAO_OTA_PHASE_TRIAL_BOOT, /*nonce=*/1,
                     /*candidate_counter=*/1, size, candidate_hash, old_hash);

  /* Slot B: newer (sequence 2), SAME nonce/command, trial_attempts=2 --
   * two more than a single legitimate write from slot A could produce
   * (at most trial_attempts=1) -- committed, then its marker corrupted. */
  memset(&fabricated, 0, sizeof(fabricated));
  fabricated.magic = XIAO_OTA_RECORD_MAGIC;
  fabricated.record_version = XIAO_OTA_FORMAT_VERSION;
  fabricated.record_bytes = sizeof(fabricated);
  fabricated.sequence = 2;
  fabricated.transaction_nonce = 1;
  fabricated.phase = XIAO_OTA_PHASE_TRIAL_BOOT;
  fabricated.trial_attempts = 2;
  fabricated.active_image_extent = size;
  fabricated.candidate_counter = 1;
  memcpy(fabricated.candidate_hash_sha256, candidate_hash, 32);
  memcpy(fabricated.installed_hash_sha256, old_hash, 32);
  fabricated.crc32 = xiao_ota_crc32(&fabricated, offsetof(xiao_ota_state_t, crc32));
  fabricated.commit_marker = XIAO_OTA_COMMIT_MARKER;
  {
    const uint32_t zero_bits = ~XIAO_OTA_COMMIT_MARKER;
    fabricated.commit_marker |= zero_bits & (~zero_bits + 1u);
  }
  memcpy(s.qspi + XIAO_OTA_STATE_B, &fabricated, sizeof(fabricated));

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
}

/*
 * Same bug, floor pair: a genuinely newer floor record that was
 * committed then corrupted must make the floor DAMAGED/untrustworthy,
 * never silently resurrect the older (lower, stale) floor value as if
 * it were still authoritative -- that would let a signed command whose
 * counter clears the STALE floor but NOT the genuinely-current one be
 * wrongly admitted.
 */
static void run_corrupted_committed_newer_floor_refuses_stale_trust(
    bool marker_damage, bool body_damage) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t fabricated;

  fake_io_reset(&s);
  provision_old_image(&s, 8192, 0xB7, old_hash);
  write_candidate(&s, 8192, 0xC7, candidate_hash);
  /* Counter 4 clears the older, stale floor=3 below but not the
   * genuinely current, now-corrupted floor=7. */
  build_and_write_command(&s, 4, 1, 4, 8192, candidate_hash, 8192, old_hash);

  write_floor_direct(&s, 3, 8192, old_hash); /* slot A, sequence 1 */

  memset(&fabricated, 0, sizeof(fabricated));
  fabricated.magic = XIAO_OTA_FLOOR_MAGIC;
  fabricated.record_version = XIAO_OTA_FORMAT_VERSION;
  fabricated.record_bytes = sizeof(fabricated);
  fabricated.sequence = 2;
  fabricated.confirmed_counter_floor = 7;
  fabricated.active_image_extent = 8192;
  memcpy(fabricated.confirmed_hash_sha256, old_hash, 32);
  fabricated.crc32 = xiao_ota_crc32(&fabricated, offsetof(xiao_ota_floor_t, crc32));
  fabricated.commit_marker = XIAO_OTA_COMMIT_MARKER;
  if (marker_damage) {
    const uint32_t zero_bits = ~XIAO_OTA_COMMIT_MARKER;
    fabricated.commit_marker |= zero_bits & (~zero_bits + 1u);
  }
  memcpy(s.qspi + XIAO_OTA_FLOOR_B, &fabricated, sizeof(fabricated));
  if (body_damage) {
    s.qspi[XIAO_OTA_FLOOR_B + offsetof(xiao_ota_floor_t, confirmed_counter_floor)] ^= 0xFF;
  }

  assert(fake_io_run_boot(&s) == 0);
  /* Floor is untrustworthy: the signed command must be refused outright,
   * not admitted against the stale, lower floor=3. */
  assert(!read_state(&s, &state));
  assert(s.force_recovery_calls == 0);
}

static void test_corrupted_committed_newer_floor_refuses_stale_trust(void) {
  run_corrupted_committed_newer_floor_refuses_stale_trust(false, true);
}

static void test_floor_corruption_fixture_admits_counter_four_above_healthy_three(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  xiao_ota_state_t state;
  fake_io_reset(&s);
  provision_old_image(&s, 8192, 0xB7, old_hash);
  write_candidate(&s, 8192, 0xC7, candidate_hash);
  build_and_write_command(&s, 4, 1, 4, 8192, candidate_hash, 8192, old_hash);
  write_floor_direct(&s, 3, 8192, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.candidate_counter == 4);
}

static void test_committed_floor_marker_bit_set_never_reopens_stale_counter(void) {
  run_corrupted_committed_newer_floor_refuses_stale_trust(true, false);
}

static void test_committed_floor_marker_and_body_damage_never_reopen_stale_counter(void) {
  run_corrupted_committed_newer_floor_refuses_stale_trust(true, true);
}

/*
 * Astra follow-up regression: with NEITHER physical state slot a winner
 * (genuinely blank device), a sidecar window containing non-blank debris
 * that never validly committed must not be silently ignored just
 * because there is no state record to pair it against.
 */
static void run_real_committed_retry_marker_damage_never_regrants_same_trial(
    uint32_t marker_mask, bool damage_body) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  xiao_ota_state_t state, slot_a;
  uint32_t damaged_address;
  int previously_issued;
  const uint32_t size = 8192;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x24, old_hash);
  write_candidate(&s, size, 0x34, candidate_hash);
  build_and_write_command(&s, 244, 1, 1, size, candidate_hash, size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.trial_attempts == 1);
  previously_issued = s.watchdog_start_calls;
  assert(previously_issued == 2);

  memcpy(&slot_a, s.qspi + XIAO_OTA_STATE_A, sizeof(slot_a));
  damaged_address = xiao_ota_state_valid(&slot_a) && slot_a.sequence == state.sequence
                        ? XIAO_OTA_STATE_A : XIAO_OTA_STATE_B;
  state.commit_marker |= marker_mask;
  if (damage_body) state.candidate_hash_sha256[0] ^= 1u;
  memcpy(s.qspi + damaged_address, &state, sizeof(state));
  assert(fake_io_run_boot(&s) == 0);
  if (damage_body) {
    assert(s.watchdog_start_calls == previously_issued);
  }
  if (s.force_recovery_calls != 0) {
    assert(s.watchdog_start_calls == previously_issued);
  } else {
    assert(read_state(&s, &state));
    assert(state.phase != XIAO_OTA_PHASE_TRIAL_BOOT || state.trial_attempts > 1);
  }
}

static void test_real_committed_retry_marker_damage_never_regrants_same_trial(void) {
  const uint32_t zero_bits = ~XIAO_OTA_COMMIT_MARKER;
  run_real_committed_retry_marker_damage_never_regrants_same_trial(
      zero_bits & (~zero_bits + 1u), false);
}

static void test_real_committed_retry_prefix_shaped_marker_damage_never_regrants_same_trial(void) {
  run_real_committed_retry_marker_damage_never_regrants_same_trial(0xFF000000u, false);
}

static void test_real_committed_retry_erased_marker_never_regrants_same_trial(void) {
  run_real_committed_retry_marker_damage_never_regrants_same_trial(UINT32_MAX, false);
}

static void test_real_committed_retry_erased_marker_and_invalid_body_never_regrants(void) {
  run_real_committed_retry_marker_damage_never_regrants_same_trial(UINT32_MAX, true);
}

static void run_real_retry_bodies_survive_erased_markers_without_losing_backup(
    bool crash_after_parent_erase) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32], backup_hash[32];
  xiao_ota_state_t state;
  const uint32_t size = 8192;
  const uint32_t addresses[] = {XIAO_OTA_STATE_A, XIAO_OTA_STATE_B};
  uint32_t parent_address = 0;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x36, old_hash);
  write_floor_direct(&s, 3, size, old_hash);
  write_candidate(&s, size, 0x76, candidate_hash);
  build_and_write_command(&s, 746, 1, 7, size, candidate_hash, size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(fake_io_run_boot(&s) == 0);
  assert(s.watchdog_start_calls == 2);
  for (size_t i = 0; i < sizeof(addresses) / sizeof(addresses[0]); ++i) {
    memcpy(&state, s.qspi + addresses[i], sizeof(state));
    assert(xiao_ota_state_valid(&state));
    assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
    if (state.trial_attempts == 0) parent_address = addresses[i];
    state.commit_marker = UINT32_MAX;
    memcpy(s.qspi + addresses[i], &state, sizeof(state));
  }

  assert(parent_address != 0);
  if (crash_after_parent_erase) {
    s.crash.op = FAKE_IO_OP_QSPI_WRITE;
    s.crash.after = 1;
    s.crash.addr_lo = parent_address;
    s.crash.addr_hi = parent_address + XIAO_OTA_QSPI_SECTOR_SIZE;
    assert(fake_io_run_boot(&s) == 1);
    assert(s.watchdog_start_calls == 2);
    for (size_t i = 0; i < XIAO_OTA_QSPI_SECTOR_SIZE; ++i) {
      assert(s.qspi[parent_address + i] == 0xFF);
    }
    s.crash.after = -1;
  }
  assert(fake_io_run_boot(&s) == 0);
  sha256_of(s.qspi + XIAO_OTA_BACKUP_BASE, size, backup_hash);
  assert(memcmp(backup_hash, old_hash, sizeof(backup_hash)) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.candidate_counter == 7 && state.trial_attempts == 2);
  assert(s.watchdog_start_calls == 3);
}

static void test_both_real_retry_bodies_survive_erased_markers_without_losing_backup(void) {
  run_real_retry_bodies_survive_erased_markers_without_losing_backup(false);
}

static void test_body_only_retry_source_survives_crash_after_parent_erase(void) {
  run_real_retry_bodies_survive_erased_markers_without_losing_backup(true);
}

static void run_damaged_floor_bound_to_real_confirmed_state_never_reopens_counter(
    uint32_t marker_mask, bool damage_body) {
  fake_io_state_t s;
  uint8_t old_hash[32], confirmed_hash[32], lower_hash[32], next_hash[32], running_hash[32];
  xiao_ota_command_v2_t historical_command;
  xiao_ota_state_t state;
  xiao_ota_floor_t floor, slot_a;
  uint32_t damaged_address;
  const uint32_t size = 8192;
  int previously_issued;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x35, old_hash);
  write_floor_direct(&s, 3, size, old_hash);
  write_candidate(&s, size, 0x75, confirmed_hash);
  build_and_write_command(&s, 707, 1, 7, size, confirmed_hash, size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  write_confirmation(&s, 707, 7, confirmed_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED && state.candidate_counter == 7);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 7);
  memcpy(&historical_command, s.qspi + XIAO_OTA_COMMAND_A,
         sizeof(historical_command));
  previously_issued = s.watchdog_start_calls;

  memcpy(&slot_a, s.qspi + XIAO_OTA_FLOOR_A, sizeof(slot_a));
  damaged_address = xiao_ota_floor_valid(&slot_a) && slot_a.sequence == floor.sequence
                        ? XIAO_OTA_FLOOR_A : XIAO_OTA_FLOOR_B;
  floor.commit_marker |= marker_mask;
  if (damage_body) floor.confirmed_hash_sha256[0] ^= 1u;
  memcpy(s.qspi + damaged_address, &floor, sizeof(floor));
  write_candidate(&s, size, 0x45, lower_hash);
  build_and_write_command(&s, 404, 2, 4, size, lower_hash, size, confirmed_hash);
  memcpy(s.qspi + XIAO_OTA_COMMAND_B, &historical_command,
         sizeof(historical_command));
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.candidate_counter == 7);
  assert(s.watchdog_start_calls == previously_issued);
  if (s.force_recovery_calls == 0) {
    assert(read_floor(&s, &floor));
    assert(floor.confirmed_counter_floor >= 7);
    assert(floor.active_image_extent == size);
    assert(memcmp(floor.confirmed_hash_sha256, confirmed_hash,
                  sizeof(confirmed_hash)) == 0);

    s.fail.op = FAKE_IO_OP_QSPI_ERASE;
    s.fail.after = 1;
    s.fail.count = 0;
    s.fail.addr_lo = XIAO_OTA_FLOOR_A;
    s.fail.addr_hi = XIAO_OTA_FLOOR_B + XIAO_OTA_QSPI_SECTOR_SIZE - 1u;
    for (int cold_boot = 0; cold_boot < 2; ++cold_boot) {
      assert(fake_io_run_boot(&s) == 0);
      assert(s.fail.count == 0);
      assert(s.force_recovery_calls == 0);
      assert(s.watchdog_start_calls == previously_issued);
      assert(read_state(&s, &state));
      assert(state.phase == XIAO_OTA_PHASE_CONFIRMED && state.candidate_counter == 7);
      assert(read_floor(&s, &floor));
      assert(floor.confirmed_counter_floor >= 7);
    }
    s.fail.op = FAKE_IO_OP_NONE;

    write_candidate(&s, size, 0x85, next_hash);
    build_and_write_command(&s, 808, 3, 8, size, next_hash, size, confirmed_hash);
    assert(fake_io_run_boot(&s) == 0);
    assert(s.force_recovery_calls == 0);
    assert(s.watchdog_start_calls == previously_issued + 1);
    assert(read_state(&s, &state));
    assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT && state.candidate_counter == 8);
    write_confirmation(&s, 808, 8, next_hash);
    assert(fake_io_run_boot(&s) == 0);
    assert(s.force_recovery_calls == 0);
    assert(s.watchdog_start_calls == previously_issued + 1);
    assert(read_state(&s, &state));
    assert(state.phase == XIAO_OTA_PHASE_CONFIRMED && state.candidate_counter == 8);
    assert(read_floor(&s, &floor));
    assert(floor.confirmed_counter_floor == 8);
    assert(floor.active_image_extent == size);
    assert(memcmp(floor.confirmed_hash_sha256, next_hash, sizeof(next_hash)) == 0);
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, size, running_hash);
    assert(memcmp(running_hash, next_hash, sizeof(running_hash)) == 0);
    return;
  }
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, size, running_hash);
  assert(memcmp(running_hash, confirmed_hash, sizeof(running_hash)) == 0);
}

static void test_damaged_floor_bound_to_real_confirmed_state_never_reopens_counter(void) {
  const uint32_t zero_bits = ~XIAO_OTA_COMMIT_MARKER;
  run_damaged_floor_bound_to_real_confirmed_state_never_reopens_counter(
      zero_bits & (~zero_bits + 1u), false);
}

static void test_erased_floor_marker_bound_to_real_confirmed_state_never_reopens_counter(void) {
  run_damaged_floor_bound_to_real_confirmed_state_never_reopens_counter(
      UINT32_MAX, false);
}

static void test_erased_floor_marker_and_body_bound_to_real_confirmed_state_never_reopens_counter(void) {
  run_damaged_floor_bound_to_real_confirmed_state_never_reopens_counter(
      UINT32_MAX, true);
}

/*
 * The converse of run_damaged_floor_bound_to_real_confirmed_state_never_
 * reopens_counter() above: there, the CONFIRMED state's own
 * candidate_counter (e.g. 7) genuinely DOMINATES the surviving stale
 * slot (e.g. 3), so repair is legitimate. Here the surviving slot
 * itself is structurally valid and ALREADY at a HIGHER counter (8) than
 * the CONFIRMED state's candidate_counter (7) -- conflicting evidence: the
 * state record is itself stale relative to real, already-durable
 * anti-rollback history sitting on the surviving slot. Repairing the
 * damaged slot from this stale state would silently regress the floor
 * from 8 back down to 7, a genuine anti-rollback violation. Must
 * refuse any mutation and force Recovery instead -- never persist,
 * never erase either slot. Exercised in both physical bank directions
 * (surviving-in-A/damaged-in-B and vice versa) since persist_floor()'s
 * slot selection is address-based, not role-based.
 */
static void run_surviving_floor_above_state_counter_refuses_repair(
    bool survivor_in_slot_a) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  xiao_ota_floor_t survivor, damaged;
  const uint32_t size = 8192;
  uint32_t survivor_address, damaged_address;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0xD3, old_hash);

  memset(&survivor, 0, sizeof(survivor));
  survivor.magic = XIAO_OTA_FLOOR_MAGIC;
  survivor.record_version = XIAO_OTA_FORMAT_VERSION;
  survivor.record_bytes = sizeof(survivor);
  survivor.sequence = 4;
  survivor.confirmed_counter_floor = 8;
  survivor.active_image_extent = size;
  memcpy(survivor.confirmed_hash_sha256, old_hash, 32);
  survivor.crc32 = xiao_ota_crc32(&survivor, offsetof(xiao_ota_floor_t, crc32));
  survivor.commit_marker = XIAO_OTA_COMMIT_MARKER;

  memset(&damaged, 0, sizeof(damaged));
  damaged.magic = XIAO_OTA_FLOOR_MAGIC;
  damaged.record_version = XIAO_OTA_FORMAT_VERSION;
  damaged.record_bytes = sizeof(damaged);
  damaged.sequence = 3;
  damaged.confirmed_counter_floor = 6;
  damaged.active_image_extent = size;
  memcpy(damaged.confirmed_hash_sha256, old_hash, 32);
  damaged.crc32 = xiao_ota_crc32(&damaged, offsetof(xiao_ota_floor_t, crc32));
  damaged.commit_marker = XIAO_OTA_COMMIT_MARKER;
  /* Corrupt a body byte (after CRC computed) so the slot is readable but
   * fails xiao_ota_floor_valid()'s CRC check -- DAMAGED, not MISSING. */
  damaged.confirmed_counter_floor ^= 0xFFu;

  survivor_address = survivor_in_slot_a ? XIAO_OTA_FLOOR_A : XIAO_OTA_FLOOR_B;
  damaged_address = survivor_in_slot_a ? XIAO_OTA_FLOOR_B : XIAO_OTA_FLOOR_A;
  memset(s.qspi + XIAO_OTA_FLOOR_A, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memset(s.qspi + XIAO_OTA_FLOOR_B, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memcpy(s.qspi + survivor_address, &survivor, sizeof(survivor));
  memcpy(s.qspi + damaged_address, &damaged, sizeof(damaged));

  /* A genuinely CONFIRMED state record whose own candidate_counter (7)
   * sits strictly BETWEEN the damaged slot's stale 6 and the surviving
   * slot's real 8 -- enough evidence to repair from if the surviving slot
   * did not already out-rank it, but here it must NOT: the survivor's
   * own already-durable 8 must never be silently discarded. */
  write_state_direct(&s, XIAO_OTA_PHASE_CONFIRMED, /*nonce=*/1, /*candidate_counter=*/7,
                     size, old_hash, old_hash);

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  /* No mutation: both floor slots remain byte-for-byte exactly as
   * fabricated above. */
  assert(memcmp(s.qspi + survivor_address, &survivor, sizeof(survivor)) == 0);
  assert(memcmp(s.qspi + damaged_address, &damaged, sizeof(damaged)) == 0);
  {
    xiao_ota_floor_t reread_survivor;
    memcpy(&reread_survivor, s.qspi + survivor_address, sizeof(reread_survivor));
    assert(xiao_ota_floor_valid(&reread_survivor));
    assert(reread_survivor.confirmed_counter_floor == 8);
  }
}

static void test_surviving_floor_above_state_counter_refuses_repair_survivor_in_a(void) {
  run_surviving_floor_above_state_counter_refuses_repair(true);
}

static void test_surviving_floor_above_state_counter_refuses_repair_survivor_in_b(void) {
  run_surviving_floor_above_state_counter_refuses_repair(false);
}

static void test_orphaned_damaged_sidecar_forces_recovery(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], running_hash[32];
  xiao_ota_state_t state;

  fake_io_reset(&s);
  provision_old_image(&s, 8192, 0xA3, old_hash);

  memset(s.qspi + XIAO_OTA_SETTINGS_SIDECAR_A, 0x77,
        sizeof(xiao_ota_settings_sidecar_t));

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  assert(!read_state(&s, &state));
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, 8192, running_hash);
  assert(memcmp(running_hash, old_hash, 32) == 0);
}

/*
 * A structurally VALID, committed orphan sidecar is NOT automatically
 * harmless just because its own CRC checks out: CRC32 is an integrity
 * check, not an authenticity one. With no command visible at all this
 * boot, there is no way to PROVE the orphan corresponds to any real,
 * currently-live transaction -- it must fail closed (force_recovery),
 * not be waved through as "probably just a torn first-publication
 * prep". (Renamed from the earlier, over-permissive
 * "...is_harmless" test -- see test_first_publication_sidecar_prep_cut_
 * is_harmless() below for the genuine, provably-bound positive case.)
 */
static void test_orphaned_sidecar_with_no_command_forces_recovery(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], running_hash[32];
  xiao_ota_state_t state;
  xiao_ota_settings_sidecar_t sidecar;

  fake_io_reset(&s);
  provision_old_image(&s, 8192, 0x9C, old_hash);

  memset(&sidecar, 0, sizeof(sidecar));
  sidecar.magic = XIAO_OTA_SIDECAR_MAGIC;
  sidecar.record_version = XIAO_OTA_FORMAT_VERSION;
  sidecar.record_bytes = sizeof(sidecar);
  sidecar.matching_state_sequence = 1;
  sidecar.transaction_nonce = 9;
  memset(sidecar.original_settings_raw, 0x5A, sizeof(sidecar.original_settings_raw));
  sidecar.crc32 = xiao_ota_crc32(&sidecar, offsetof(xiao_ota_settings_sidecar_t, crc32));
  sidecar.commit_marker = XIAO_OTA_COMMIT_MARKER;
  memcpy(s.qspi + XIAO_OTA_SETTINGS_SIDECAR_A, &sidecar, sizeof(sidecar));

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  assert(!read_state(&s, &state));
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, 8192, running_hash);
  assert(memcmp(running_hash, old_hash, 32) == 0);
}

/*
 * A REAL signed command IS visible this boot, but the orphan sidecar's
 * recorded binding (transaction_nonce here) does not match it: still
 * unprovable, still force_recovery(). Distinguishes "no command at all"
 * (above) from "a command exists, but this sidecar isn't provably its
 * preparation cut".
 */
static void test_orphaned_sidecar_with_wrong_command_binding_forces_recovery(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32], running_hash[32];
  xiao_ota_state_t state;
  xiao_ota_settings_sidecar_t sidecar;
  const uint32_t size = 8192;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0xB4, old_hash);
  write_candidate(&s, size, 0xC4, candidate_hash);
  build_and_write_command(&s, 777, 1, 1, size, candidate_hash, size, old_hash);

  memset(&sidecar, 0, sizeof(sidecar));
  sidecar.magic = XIAO_OTA_SIDECAR_MAGIC;
  sidecar.record_version = XIAO_OTA_FORMAT_VERSION;
  sidecar.record_bytes = sizeof(sidecar);
  sidecar.matching_state_sequence = 1;
  sidecar.transaction_nonce = 888; /* does NOT match the real command's 777 */
  memset(sidecar.original_settings_raw, 0x5A, sizeof(sidecar.original_settings_raw));
  sidecar.crc32 = xiao_ota_crc32(&sidecar, offsetof(xiao_ota_settings_sidecar_t, crc32));
  sidecar.commit_marker = XIAO_OTA_COMMIT_MARKER;
  memcpy(s.qspi + XIAO_OTA_SETTINGS_SIDECAR_A, &sidecar, sizeof(sidecar));

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
  assert(!read_state(&s, &state));
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, size, running_hash);
  assert(memcmp(running_hash, old_hash, 32) == 0);
}

/*
 * Genuine positive case, using the REAL write path (not a fabricated
 * sidecar): the very FIRST transaction a fresh device ever admits is
 * torn between its (fully-committing) sidecar write and its state
 * write -- a genuine "next transaction's publish was torn before its
 * own state record ever committed" cut. On the next boot the SAME
 * signed command is still visible, the fresh settings-page read is
 * unchanged (the old image never stopped running), and the orphan
 * sidecar's sequence/nonce/digest/snapshot all provably match it --
 * this must resume harmlessly (no force_recovery) and complete the
 * transaction normally.
 */
static void test_first_publication_sidecar_prep_cut_is_harmless(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  xiao_ota_state_t state;
  const uint32_t size = 8192;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x1D, old_hash);
  write_candidate(&s, size, 0x2D, candidate_hash);
  build_and_write_command(&s, 555, 1, 1, size, candidate_hash, size, old_hash);

  s.tear.op = FAKE_IO_OP_QSPI_WRITE;
  s.tear.after = 2; /* the STATE record's marker write (2nd matching call) */
  s.tear.addr_lo = XIAO_OTA_STATE_A;
  s.tear.addr_hi = XIAO_OTA_STATE_A + sizeof(xiao_ota_state_t) - 1;
  s.tear_bytes = 2;
  s.tear_crash = true;

  assert(fake_io_run_boot(&s) == 1); /* crashed mid marker-write */
  assert(s.force_recovery_calls == 0);
  assert(!read_state(&s, &state)); /* state never durably committed */

  s.tear.after = -1;
  s.tear_crash = false;
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.transaction_nonce == 555);
}

/*
 * New coverage for read_paired_sidecar()'s "always unsafe when
 * ambiguous" callback (sidecar_paired_ambiguous_never_safe()): the
 * physically co-located STATE record is fully, exactly committed
 * (winning marker intact), so per write_state_with_sidecar()'s write
 * order (sidecar committed FIRST, then state) the sidecar MUST also
 * have reached its own exact commit at that same time -- there is no
 * legitimate "still in flight" explanation left for it. A single
 * marker bit flipped afterwards (real bit rot, body+CRC otherwise
 * untouched) must therefore force recovery rather than being waved
 * through as a harmless in-flight write, unlike the orphan (no-
 * winning-state) case exercised above and in the sidecar_orphan_*
 * tests.
 */
static void test_committed_sidecar_marker_bit_set_forces_recovery(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  xiao_ota_settings_sidecar_t sidecar;
  const uint32_t size = 8192;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x5E, old_hash);
  /* write_state_direct() plants a fully committed, matching state+
   * sidecar pair together at slot A. */
  write_state_direct(&s, XIAO_OTA_PHASE_TRIAL_BOOT, /*nonce=*/321,
                     /*candidate_counter=*/1, size, old_hash, old_hash);

  memcpy(&sidecar, s.qspi + XIAO_OTA_SETTINGS_SIDECAR_A, sizeof(sidecar));
  assert(sidecar.commit_marker == XIAO_OTA_COMMIT_MARKER);
  {
    const uint32_t zero_bits = ~XIAO_OTA_COMMIT_MARKER;
    sidecar.commit_marker |= zero_bits & (~zero_bits + 1u);
  }
  memcpy(s.qspi + XIAO_OTA_SETTINGS_SIDECAR_A, &sidecar, sizeof(sidecar));

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 1);
}

/*
 * Symmetric/terminal counterpart to test_partial_state_marker_
 * conservatively_burns_possible_retry() and test_first_publication_sidecar_prep_cut_is_
 * harmless(): the PRIOR pair here is a TERMINAL (CONFIRMED) record --
 * not TRIAL_BOOT -- and the torn SECOND transaction's publish targets
 * whichever physical slot is NOT currently holding it (the opposite
 * physical direction from those two tests, whichever that happens to
 * be). A committed CONFIRMED pair must survive a torn next-transaction
 * marker write exactly like a TRIAL_BOOT one does.
 */
static void test_second_transaction_marker_cut_preserves_confirmed_pair(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], first_hash[32], second_hash[32];
  xiao_ota_state_t before, after, a;
  xiao_ota_floor_t floor;
  const uint32_t size = 8192;
  uint32_t target;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0x31, old_hash);
  write_candidate(&s, size, 0x41, first_hash);
  build_and_write_command(&s, 111, 1, 1, size, first_hash, size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &before));
  assert(before.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  write_confirmation(&s, 111, 1, first_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &before));
  assert(before.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 1);

  write_candidate(&s, size, 0x51, second_hash);
  build_and_write_command(&s, 222, 2, 2, size, second_hash, size, first_hash);
  memcpy(&a, s.qspi + XIAO_OTA_STATE_A, sizeof(a));
  target = xiao_ota_state_valid(&a) && a.sequence == before.sequence
               ? XIAO_OTA_STATE_B : XIAO_OTA_STATE_A;

  s.tear.op = FAKE_IO_OP_QSPI_WRITE;
  s.tear.after = 2;
  s.tear.addr_lo = target;
  s.tear.addr_hi = target + sizeof(xiao_ota_state_t) - 1;
  s.tear_bytes = 2;
  s.tear_crash = true;
  assert(fake_io_run_boot(&s) == 1);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &after));
  assert(memcmp(&before, &after, sizeof(before)) == 0);

  s.tear.after = -1;
  s.tear_crash = false;
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &after));
  assert(after.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(after.transaction_nonce == 222);
}

/*
 * REQUIRED RAW FAULT MATRIX addendum (install path): a genuine crash
 * immediately AFTER the settings page erase but BEFORE any byte of the
 * new write ever lands -- the page is left completely blank (all 28
 * bytes erased, not merely a partial program) -- must still recover
 * correctly on a genuine later reboot, exactly like every partial-write
 * cut in the parametrized matrix above but for the physically distinct
 * "fully erased, nothing written yet" state rather than "some bytes
 * landed, some didn't". Uses the plain (non-tear) crash fault, which
 * fires BEFORE internal_write()'s effect -- zero bytes touched. */
static void test_install_settings_erase_then_crash_before_write_resumes(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  uint8_t running_hash[32];
  xiao_ota_state_t state;
  const uint32_t old_size = 8192;
  size_t i;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0xE3, old_hash);
  write_candidate(&s, old_size, 0xF3, candidate_hash);
  build_and_write_command(&s, 990, 1, 1, old_size, candidate_hash, old_size,
                          old_hash);

  s.crash.op = FAKE_IO_OP_INTERNAL_WRITE;
  s.crash.after = 1;
  s.crash.addr_lo = XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS;
  s.crash.addr_hi = XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS +
                    XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE;

  assert(fake_io_run_boot(&s) == 1); /* crashed right after erase */
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_INSTALL_COPYING);
  assert(state.progress_bytes == old_size);
  assert(s.force_recovery_calls == 0);
  /* The settings page is genuinely, completely blank -- not one byte
   * differs from freshly erased. */
  for (i = 0; i < XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE; ++i) {
    assert(s.internal_flash[XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + i] == 0xFFu);
  }

  /* Genuine separate reboot, fault cleared: the fully-blank bank-0 triad
   * can never match the already-installed candidate bytes, so this must
   * safely roll back (same safety property as the sub-triad cuts in the
   * parametrized matrix), never silently continue as TRIAL_BOOT. */
  s.crash.after = -1;
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_FAILED);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, running_hash);
  assert(memcmp(running_hash, old_hash, 32) == 0);
}

/* Same addendum, rollback path: crash immediately after the settings
 * erase, before the restore write's first byte, leaving the page fully
 * blank rather than partially programmed. */
static void test_rollback_settings_erase_then_crash_before_write_resumes(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  uint8_t running_hash[32];
  xiao_ota_state_t state;
  uint32_t attempt;
  const uint32_t old_size = 8192;
  size_t i;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x37, old_hash);
  write_candidate(&s, old_size, 0x47, candidate_hash);
  build_and_write_command(&s, 991, 1, 1, old_size, candidate_hash, old_size,
                          old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

  for (attempt = 0; attempt + 1 < XIAO_OTA_MAX_TRIAL_BOOTS; ++attempt) {
    assert(fake_io_run_boot(&s) == 0);
  }

  s.crash.op = FAKE_IO_OP_INTERNAL_WRITE;
  s.crash.after = 1;
  s.crash.addr_lo = XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS;
  s.crash.addr_hi = XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS +
                    XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE;

  assert(fake_io_run_boot(&s) == 1);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_ROLLBACK_COPYING);
  assert(state.progress_bytes == state.active_image_extent);
  assert(s.force_recovery_calls == 0);
  for (i = 0; i < XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE; ++i) {
    assert(s.internal_flash[XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + i] == 0xFFu);
  }
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, running_hash);
  assert(memcmp(running_hash, old_hash, 32) == 0); /* backup already restored */

  s.crash.after = -1;
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_FAILED);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, running_hash);
  assert(memcmp(running_hash, old_hash, 32) == 0);
  assert(read_bank0_size(&s) == old_size);
}

/*
 * Shared safety assertion for the exhaustive publication cut matrix
 * below: after a genuine tear (or erase-crash) of ANY one of the four
 * physical writes that make up write_state_with_sidecar()'s publish
 * (sidecar body, sidecar marker, state body, state marker) has been
 * cleared and the device rebooted once more, exactly one of the
 * following must hold -- never a mix, never garbage, never a false
 * CONFIRMED, and force_recovery must never have fired for a plain torn
 * write of this kind:
 *
 *   (a) nothing at all durable exists yet (only possible when there was
 *       no prior transaction to fall back to -- the very first-ever
 *       publication) and the running image is exactly the untouched old
 *       image; or
 *   (b) the PRIOR transaction/pair is completely intact and unmoved
 *       (only possible when a prior CONFIRMED pair existed) with the
 *       running image still exactly the prior candidate; or
 *   (c) the NEW transaction fully completed (TRIAL_BOOT, running image
 *       now exactly the new candidate).
 */
static void assert_publication_outcome_safe(fake_io_state_t *s,
                                            bool terminal_prior,
                                            uint64_t prior_nonce,
                                            const uint8_t old_hash[32],
                                            const uint8_t prior_hash[32],
                                            const uint8_t new_hash[32],
                                            uint32_t size) {
  xiao_ota_state_t final_state;
  bool has_state;
  uint8_t running_hash[32];

  assert(s->force_recovery_calls == 0);
  has_state = read_state(s, &final_state);
  sha256_of(s->internal_flash + XIAO_OTA_APP_START, size, running_hash);

  if (!has_state) {
    assert(!terminal_prior);
    assert(memcmp(running_hash, old_hash, 32) == 0);
  } else if (terminal_prior && final_state.transaction_nonce == prior_nonce) {
    assert(final_state.phase == XIAO_OTA_PHASE_CONFIRMED);
    assert(memcmp(running_hash, prior_hash, 32) == 0);
  } else {
    assert(final_state.transaction_nonce == 702);
    assert(final_state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
    assert(memcmp(running_hash, new_hash, 32) == 0);
  }
}

/* Common fixture for both matrix passes below: provisions the running
 * image and, for the terminal-replacement scenario, drives a first
 * transaction (nonce 701) all the way to a genuinely durable CONFIRMED
 * pair before returning the physical sector address ("target") that the
 * SECOND transaction (nonce 702, the one actually being torn) will
 * publish into -- always the sector NOT already holding the first
 * transaction, mirroring persist_state()'s own "actual other slot"
 * placement. For the first-publication scenario there is no prior
 * transaction at all, and the very first-ever publish is already known
 * (and separately regression-tested elsewhere in this file) to always
 * target XIAO_OTA_STATE_A. */
static uint32_t setup_publication_target(fake_io_state_t *s,
                                         bool terminal_prior,
                                         uint8_t old_hash[32],
                                         uint8_t prior_hash[32],
                                         uint8_t new_hash[32], uint32_t size) {
  uint32_t target;

  fake_io_reset(s);
  provision_old_image(s, size, 0x10, old_hash);

  if (terminal_prior) {
    xiao_ota_state_t prior_state, a;

    write_candidate(s, size, 0x20, prior_hash);
    build_and_write_command(s, 701, 1, 1, size, prior_hash, size, old_hash);
    assert(fake_io_run_boot(s) == 0);
    write_confirmation(s, 701, 1, prior_hash);
    assert(fake_io_run_boot(s) == 0);
    assert(read_state(s, &prior_state));
    assert(prior_state.phase == XIAO_OTA_PHASE_CONFIRMED);

    memcpy(&a, s->qspi + XIAO_OTA_STATE_A, sizeof(a));
    target = (xiao_ota_state_valid(&a) && a.sequence == prior_state.sequence)
                ? XIAO_OTA_STATE_B
                : XIAO_OTA_STATE_A;
    write_candidate(s, size, 0x30, new_hash);
    build_and_write_command(s, 702, 2, 2, size, new_hash, size, prior_hash);
  } else {
    target = XIAO_OTA_STATE_A;
    write_candidate(s, size, 0x30, new_hash);
    build_and_write_command(s, 702, 1, 1, size, new_hash, size, old_hash);
  }
  return target;
}

/*
 * REQUIRED EXHAUSTIVE PUBLICATION CUT MATRIX. write_state_with_sidecar()
 * performs, in strict order, FOUR separate physical QSPI writes into the
 * target sector -- sidecar body, sidecar marker, state body, state
 * marker -- each individually torn here at EVERY byte boundary from 0
 * (crash before the first byte lands) through its full length inclusive
 * (the effect fully lands, then a crash fires before the caller ever
 * sees success -- "effect-then-crash"). Run twice: once with no prior
 * transaction at all (the very first-ever publication, onto a genuinely
 * blank sector) and once replacing an already-durable CONFIRMED pair
 * (terminal replacement) -- covering both physical slot directions
 * naturally, since the two scenarios' targets differ, and both the
 * first-publication and active/terminal transaction-history contexts
 * main has repeatedly asked for.
 */
static void run_publication_cut_matrix(bool terminal_prior) {
  const uint32_t size = 8192;
  int which_write;

  for (which_write = 1; which_write <= 4; ++which_write) {
    size_t full_length;
    size_t cut;

    switch (which_write) {
      case 1: full_length = offsetof(xiao_ota_settings_sidecar_t, commit_marker); break;
      case 2: full_length = sizeof(uint32_t); break;
      case 3: full_length = offsetof(xiao_ota_state_t, commit_marker); break;
      default: full_length = sizeof(uint32_t); break;
    }

    for (cut = 0; cut <= full_length; ++cut) {
      fake_io_state_t s;
      uint8_t old_hash[32], prior_hash[32], new_hash[32];
      uint32_t target = setup_publication_target(&s, terminal_prior, old_hash,
                                                 prior_hash, new_hash, size);

      s.tear.op = FAKE_IO_OP_QSPI_WRITE;
      s.tear.after = which_write;
      s.tear.addr_lo = target;
      s.tear.addr_hi = target + XIAO_OTA_QSPI_SECTOR_SIZE;
      s.tear_bytes = cut;
      s.tear_crash = true;

      assert(fake_io_run_boot(&s) == 1);
      assert(s.force_recovery_calls == 0);

      s.tear.after = -1;
      s.tear_crash = false;
      assert(fake_io_run_boot(&s) == 0);
      assert_publication_outcome_safe(&s, terminal_prior, 701, old_hash,
                                      prior_hash, new_hash, size);
    }
  }
}

static void test_state_sidecar_publication_cut_matrix_first_publication(void) {
  run_publication_cut_matrix(false);
}

static void test_state_sidecar_publication_cut_matrix_terminal_replacement(void) {
  run_publication_cut_matrix(true);
}

/*
 * Addendum to the matrix above: a crash during the SECTOR ERASE that
 * write_state_with_sidecar() performs before any of its four writes --
 * fires strictly BEFORE the erase's effect (fake_io's plain crash fault,
 * unlike the tear fault used above), so the target sector is left
 * exactly as it was found (blank for a first publication; blank for a
 * terminal replacement too, since the second transaction always targets
 * the physical slot the first one never touched). Distinct code path
 * from every tear case above (no write ever reaches the sector at all,
 * not even a partial one).
 */
static void run_publication_erase_crash(bool terminal_prior) {
  const uint32_t size = 8192;
  fake_io_state_t s;
  uint8_t old_hash[32], prior_hash[32], new_hash[32];
  uint32_t target = setup_publication_target(&s, terminal_prior, old_hash,
                                             prior_hash, new_hash, size);

  s.crash.op = FAKE_IO_OP_QSPI_ERASE;
  s.crash.after = 1;
  s.crash.addr_lo = target;
  s.crash.addr_hi = target + XIAO_OTA_QSPI_SECTOR_SIZE;

  assert(fake_io_run_boot(&s) == 1);
  assert(s.force_recovery_calls == 0);

  s.crash.after = -1;
  assert(fake_io_run_boot(&s) == 0);
  assert_publication_outcome_safe(&s, terminal_prior, 701, old_hash,
                                  prior_hash, new_hash, size);
}

static void test_publication_erase_crash_first_publication_resumes(void) {
  run_publication_erase_crash(false);
}

static void test_publication_erase_crash_terminal_replacement_resumes(void) {
  run_publication_erase_crash(true);
}

/*
 * Third and final transaction-history context the matrix above was
 * still missing: ACTIVE RETRY, where the "prior" pair and the record
 * being torn are the SAME transaction (a plain trial_attempts++ retry
 * write, not a new command's publish at all). This exercises the
 * OPPOSITE physical direction from the first-publication matrix (that
 * one always targets XIAO_OTA_STATE_A; a retry of it always targets
 * XIAO_OTA_STATE_B, the "other" slot) using the exact same real-writer,
 * every-byte-boundary tear technique, both for the sidecar (re-written
 * verbatim, unchanged content, since it shares STATE's physical erase
 * unit) and the state body/marker.
 */
static uint32_t setup_retry_publication_target(fake_io_state_t *s,
                                               uint8_t old_hash[32],
                                               uint8_t candidate_hash[32],
                                               uint32_t size) {
  xiao_ota_state_t before, a;
  uint32_t target;

  fake_io_reset(s);
  provision_old_image(s, size, 0x50, old_hash);
  write_candidate(s, size, 0x60, candidate_hash);
  build_and_write_command(s, 703, 1, 1, size, candidate_hash, size, old_hash);
  assert(fake_io_run_boot(s) == 0);
  assert(read_state(s, &before));
  assert(before.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(before.trial_attempts == 0);

  memcpy(&a, s->qspi + XIAO_OTA_STATE_A, sizeof(a));
  target = (xiao_ota_state_valid(&a) && a.sequence == before.sequence)
              ? XIAO_OTA_STATE_B
              : XIAO_OTA_STATE_A;
  return target;
}

static void assert_retry_outcome_safe(fake_io_state_t *s,
                                      const uint8_t candidate_hash[32],
                                      uint32_t size) {
  xiao_ota_state_t final_state;
  uint8_t running_hash[32];

  /* A torn retry write that fully landed before the crash (the
   * "cut == full length" case in the loop below) is never ambiguous --
   * both slots decode as EXACT and the newer one (trial_attempts=1)
   * wins outright, so the additional clean boot performs a genuinely
   * NEW, separate retry cycle on top of that already-durable value,
   * legitimately reaching 2 (still under XIAO_OTA_MAX_TRIAL_BOOTS==3);
   * this path never calls force_recovery.
   *
   * A genuinely partial (cut < full_length) tear of the STATE body or
   * marker instead leaves an ambiguous candidate claiming
   * trial_attempts=1 against an EXACT trial_attempts=0 sibling still
   * in TRIAL_BOOT phase -- exactly the delta that durable bytes alone
   * can never safely recredit (see state_ambiguous_binding_ok()'s
   * doc-comment): it is indistinguishable from a bit-rotted record of
   * an ALREADY-armed watchdog cycle. Failing closed to force_recovery
   * here is the required, safe outcome, not a bug -- mirror the same
   * either/or shape main's own retry-damage regressions use instead of
   * asserting resume unconditionally. */
  if (s->force_recovery_calls != 0) {
    return;
  }
  assert(read_state(s, &final_state));
  assert(final_state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(final_state.transaction_nonce == 703);
  assert(final_state.trial_attempts <= 2u);
  sha256_of(s->internal_flash + XIAO_OTA_APP_START, size, running_hash);
  assert(memcmp(running_hash, candidate_hash, 32) == 0);
}

static void run_publication_cut_matrix_active_retry(void) {
  const uint32_t size = 8192;
  int which_write;

  for (which_write = 1; which_write <= 4; ++which_write) {
    size_t full_length;
    size_t cut;

    switch (which_write) {
      case 1: full_length = offsetof(xiao_ota_settings_sidecar_t, commit_marker); break;
      case 2: full_length = sizeof(uint32_t); break;
      case 3: full_length = offsetof(xiao_ota_state_t, commit_marker); break;
      default: full_length = sizeof(uint32_t); break;
    }

    for (cut = 0; cut <= full_length; ++cut) {
      fake_io_state_t s;
      uint8_t old_hash[32], candidate_hash[32];
      uint32_t target =
          setup_retry_publication_target(&s, old_hash, candidate_hash, size);

      s.tear.op = FAKE_IO_OP_QSPI_WRITE;
      s.tear.after = which_write;
      s.tear.addr_lo = target;
      s.tear.addr_hi = target + XIAO_OTA_QSPI_SECTOR_SIZE;
      s.tear_bytes = cut;
      s.tear_crash = true;

      assert(fake_io_run_boot(&s) == 1);
      assert(s.force_recovery_calls == 0);

      s.tear.after = -1;
      s.tear_crash = false;
      assert(fake_io_run_boot(&s) == 0);
      assert_retry_outcome_safe(&s, candidate_hash, size);
    }
  }
}

static void test_state_sidecar_publication_cut_matrix_active_retry(void) {
  run_publication_cut_matrix_active_retry();
}

static void run_publication_erase_crash_active_retry(void) {
  const uint32_t size = 8192;
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  uint32_t target =
      setup_retry_publication_target(&s, old_hash, candidate_hash, size);

  s.crash.op = FAKE_IO_OP_QSPI_ERASE;
  s.crash.after = 1;
  s.crash.addr_lo = target;
  s.crash.addr_hi = target + XIAO_OTA_QSPI_SECTOR_SIZE;

  assert(fake_io_run_boot(&s) == 1);
  assert(s.force_recovery_calls == 0);

  s.crash.after = -1;
  assert(fake_io_run_boot(&s) == 0);
  assert_retry_outcome_safe(&s, candidate_hash, size);
}

static void test_publication_erase_crash_active_retry_resumes(void) {
  run_publication_erase_crash_active_retry();
}

/* Appends 2 fixup bytes at buffer[size-2..size) (overwriting whatever
 * fill_pattern() put there) so crc16_compute(buffer, size, NULL) lands on
 * EXACTLY 0 -- CRC-16 is not a reserved "invalid" sentinel in this
 * project's contract (xiao_ota_resolve_active_extent(), same rationale as
 * test_record.c's CRC==0 unit coverage), so a real signed candidate can
 * legitimately land here. Brute force over all 65536 two-byte values is
 * the simplest correct inversion of this specific bit-oriented algorithm
 * and runs in well under a millisecond for these small candidate sizes;
 * asserts it actually found one rather than silently leaving a nonzero
 * CRC (the algorithm is a bijection in the trailing 2 bytes for a fixed
 * prefix, so this can never fail in practice, but must never be assumed
 * blindly). */
static void force_crc16_zero(uint8_t *buffer, uint32_t size) {
  uint32_t fixup;
  assert(size >= 2);
  for (fixup = 0; fixup <= 0xFFFFu; ++fixup) {
    buffer[size - 2] = (uint8_t)(fixup & 0xFFu);
    buffer[size - 1] = (uint8_t)((fixup >> 8) & 0xFFu);
    if (crc16_compute(buffer, size, NULL) == 0) return;
  }
  assert(0 && "no 2-byte CRC-16 fixup found (algorithm no longer a bijection?)");
}

/*
 * End-to-end CRC-zero outcome (released scope): a REAL signed candidate
 * whose bytes happen to recompute to a bank-0 CRC-16 of exactly 0 must
 * install, confirm/advance the floor, and remain resolvable as the valid
 * active extent across a LATER, independent cold boot -- proving
 * xiao_ota_resolve_active_extent()'s uniform CRC==0 policy (already unit
 * tested in test_record.c) actually holds through the real
 * finalize_install_and_verify() -> active_extent_from_settings() code
 * path the device runs, not just the isolated resolver call. A bug here
 * would show up as an unwarranted force_recovery() on any of the 3 boots
 * below, or bank-0 settings silently reverting to some other extent. */
static void test_signed_zero_crc_candidate_installs_confirms_and_resolves_next_boot(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  const uint32_t old_size = 4096;
  const uint32_t candidate_size = 40960;
  uint8_t *candidate_buffer;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x11, old_hash);

  candidate_buffer = (uint8_t *)&s.qspi[XIAO_OTA_CANDIDATE_BASE];
  fill_pattern(candidate_buffer, candidate_size, 0x77);
  force_crc16_zero(candidate_buffer, candidate_size);
  assert(crc16_compute(candidate_buffer, candidate_size, NULL) == 0);
  sha256_of(candidate_buffer, candidate_size, candidate_hash);

  build_and_write_command(&s, /*nonce=*/1, /*sequence=*/1, /*counter=*/1,
                          candidate_size, candidate_hash, old_size, old_hash);

  /* Boot 1: install the zero-CRC candidate. finalize_install_and_verify()
   * recomputes the CRC-16 over what it just copied into internal flash
   * (byte-identical to the candidate) and writes it verbatim into bank-0
   * -- this must not be treated as "no image installed". */
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(read_bank0_size(&s) == candidate_size);
  {
    xiao_ota_bank0_settings_t settings;
    fake_io_read_bank0_settings(&s, &settings);
    assert(settings.bank_0 == XIAO_OTA_BANK_VALID_APP);
    assert(settings.bank_0_crc == 0);
  }

  /* Boot 2: confirm. active_extent_from_settings() is called again here
   * (TRIAL_BOOT -> CONFIRMED transition) and must accept the stored 0
   * CRC as legitimately matching a fresh recompute of 0, advancing the
   * floor to the new extent/hash rather than force_recovery()-ing. */
  write_confirmation(&s, /*nonce=*/1, /*counter=*/1, candidate_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 1);
  assert(floor.active_image_extent == candidate_size);
  assert(memcmp(floor.confirmed_hash_sha256, candidate_hash, 32) == 0);

  /* Boot 3: a LATER, fully independent cold boot with no pending command
   * at all -- the CONFIRMED-phase floor/state re-derivation still calls
   * active_extent_from_settings() (command_policy_valid()'s
   * expected_active_extent input) against the SAME stored zero CRC. This
   * is the "next boot resolves that zero-CRC image as valid active
   * original" outcome: no crash, no recovery, no silent reversion. */
  clear_confirmation(&s);
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_bank0_size(&s) == candidate_size);
  {
    xiao_ota_bank0_settings_t settings;
    fake_io_read_bank0_settings(&s, &settings);
    assert(settings.bank_0_crc == 0);
  }
}

/*
 * Mismatch-vector companion: a STORED bank-0 CRC of 0 that no longer
 * matches a freshly recomputed nonzero CRC (image bytes changed/damaged
 * out from under a previously-valid zero-CRC install, e.g. a raw flash
 * bit-flip after confirmation) must be refused exactly like any other CRC
 * mismatch -- 0 is a real CRC value, never a wildcard/always-valid
 * sentinel in either direction. */
static void test_stored_zero_crc_no_longer_matches_recomputed_nonzero_refuses(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  const uint32_t old_size = 4096;
  const uint32_t candidate_size = 40960;
  uint8_t *candidate_buffer;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x11, old_hash);

  candidate_buffer = (uint8_t *)&s.qspi[XIAO_OTA_CANDIDATE_BASE];
  fill_pattern(candidate_buffer, candidate_size, 0x77);
  force_crc16_zero(candidate_buffer, candidate_size);
  sha256_of(candidate_buffer, candidate_size, candidate_hash);

  build_and_write_command(&s, /*nonce=*/1, /*sequence=*/1, /*counter=*/1,
                          candidate_size, candidate_hash, old_size, old_hash);

  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

  write_confirmation(&s, /*nonce=*/1, /*counter=*/1, candidate_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);

  /* Flip a single bit in the installed internal-flash image, well after
   * confirmation -- the stored bank-0 CRC is still the OLD, legitimate 0,
   * but a fresh recompute over the now-damaged bytes is no longer 0. */
  s.internal_flash[XIAO_OTA_APP_START] ^= 0x01u;
  clear_confirmation(&s);
  assert(fake_io_run_boot(&s) == 0);
  /* No trustworthy active extent this boot: neither a fresh install nor a
   * rollback is warranted from a single post-confirmation bit-flip with
   * no accompanying signed command -- this must never force_recovery()
   * (that would erase evidence) and must never silently accept the
   * damaged bytes as still matching either. */
  assert(s.force_recovery_calls == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
}

static void provision_vendor_zero_crc_original(fake_io_state_t *s,
                                                uint32_t size,
                                                uint8_t out_hash[32]) {
  uint8_t raw[28];
  provision_old_image(s, size, 0x33, out_hash);
  assert(crc16_compute(s->internal_flash + XIAO_OTA_APP_START, size, NULL) != 0);
  fake_io_provision_bank0_settings(s, XIAO_OTA_BANK_VALID_APP, 0, size);
  fake_io_read_settings_raw(s, raw);
  raw[4] = 0xFF;
  raw[5] = 0;
  fake_io_write_settings_raw(s, raw);
}

static void test_vendor_zero_crc_original_lifecycle(bool confirm) {
  fake_io_state_t s;
  xiao_ota_state_t state;
  xiao_ota_floor_t floor_before, floor_after;
  xiao_ota_bank0_settings_t settings;
  uint8_t old_hash[32], candidate_hash[32], digest[32];
  uint8_t original_settings[28], restored_settings[28];
  const uint32_t old_size = 32768, candidate_size = 40960;

  fake_io_reset(&s);
  provision_vendor_zero_crc_original(&s, old_size, old_hash);
  fake_io_read_settings_raw(&s, original_settings);
  assert(read_floor(&s, &floor_before));
  write_candidate(&s, candidate_size, 0x77, candidate_hash);
  build_and_write_command(&s, 91, 1, 1, candidate_size, candidate_hash,
                          old_size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.previous_bank_0_crc == 0);
  sha256_of(s.qspi + XIAO_OTA_BACKUP_BASE, old_size, digest);
  assert(memcmp(digest, old_hash, 32) == 0);
  sha256_of(s.internal_flash + XIAO_OTA_APP_START, candidate_size, digest);
  assert(memcmp(digest, candidate_hash, 32) == 0);
  fake_io_read_bank0_settings(&s, &settings);
  assert(settings.bank_0_crc != 0);
  assert(settings.bank_0_crc == crc16_compute(
      s.internal_flash + XIAO_OTA_APP_START, candidate_size, NULL));

  if (!confirm) {
    for (uint32_t attempt = 0; attempt < XIAO_OTA_MAX_TRIAL_BOOTS; ++attempt)
      assert(fake_io_run_boot(&s) == 0);
    assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_FAILED);
    fake_io_read_settings_raw(&s, restored_settings);
    assert(memcmp(restored_settings, original_settings, 28) == 0);
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, old_size, digest);
    assert(memcmp(digest, old_hash, 32) == 0);
    assert(read_floor(&s, &floor_after));
    assert(memcmp(&floor_before, &floor_after, sizeof(floor_before)) == 0);
    assert(fake_io_run_boot(&s) == 0);
    assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_FAILED);
    assert(s.watchdog_start_calls == XIAO_OTA_MAX_TRIAL_BOOTS);
    build_and_write_command(&s, 92, 2, 2, candidate_size, candidate_hash,
                            old_size, old_hash);
    assert(fake_io_run_boot(&s) == 0);
    assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
    assert(state.previous_bank_0_crc == 0);
  }
  write_confirmation(&s, confirm ? 91 : 92, confirm ? 1 : 2, candidate_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor_after));
  assert(floor_after.confirmed_counter_floor == (confirm ? 1u : 2u));
  assert(floor_after.active_image_extent == candidate_size);
  assert(memcmp(floor_after.confirmed_hash_sha256, candidate_hash, 32) == 0);
  fake_io_read_bank0_settings(&s, &settings);
  assert(settings.bank_0_crc == crc16_compute(
      s.internal_flash + XIAO_OTA_APP_START, candidate_size, NULL));
  assert(s.force_recovery_calls == 0);
}

static void test_original_baseline_rejections(void) {
  for (unsigned test = 0; test < 13; ++test) {
    fake_io_state_t s;
    xiao_ota_state_t state;
    uint8_t old_hash[32], candidate_hash[32];
    uint8_t *internal_before = malloc(FAKE_IO_INTERNAL_SIZE);
    uint8_t *qspi_before = malloc(FAKE_IO_QSPI_SIZE);
    const uint32_t size = 32768;
    assert(internal_before && qspi_before);
    fake_io_reset(&s);
    provision_vendor_zero_crc_original(&s, size, old_hash);
    write_candidate(&s, size, 0x77, candidate_hash);
    switch (test) {
      case 0: old_hash[0] ^= 1; break;
      case 1: fake_io_provision_bank0_settings(&s, 0xFF, 0, size); break;
      case 2: fake_io_provision_bank0_settings(&s, 1, 0, 0); break;
      case 3:
        fake_io_provision_bank0_settings(&s, 1, 0, XIAO_OTA_INSTALL_MAX_SIZE + 4);
        break;
      case 4:
        s.internal_flash[XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + 4] = 1;
        break;
      case 5:
        memset(s.internal_flash + XIAO_OTA_APP_START, 0xFF, 8);
        sha256_of(s.internal_flash + XIAO_OTA_APP_START, size, old_hash);
        break;
      case 6: {
        uint16_t wrong = crc16_compute(
            s.internal_flash + XIAO_OTA_APP_START, size, NULL) ^ 1u;
        assert(wrong != 0);
        fake_io_provision_bank0_settings(&s, 1, wrong, size);
        break;
      }
      case 7:
      case 8:
      case 9:
      case 10:
        s.fail.op = FAKE_IO_OP_INTERNAL_READ;
        s.fail.after = 1;
        if (test == 7) {
          s.fail.addr_lo = XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS;
          s.fail.addr_hi = s.fail.addr_lo + 28;
          s.fail.after = 2; /* Resolver read, after orphan-sidecar inspection. */
        } else if (test == 8) {
          s.fail.addr_lo = XIAO_OTA_APP_START;
          s.fail.addr_hi = s.fail.addr_lo + 8;
        } else {
          s.fail.addr_lo = XIAO_OTA_APP_START + 256;
          s.fail.addr_hi = s.fail.addr_lo + 256;
          if (test == 10) s.fail.after = 2; /* SHA read after CRC succeeds. */
        }
        break;
      case 11:
        memset(s.qspi + XIAO_OTA_FLOOR_A, 0xFF,
               2 * XIAO_OTA_QSPI_SECTOR_SIZE);
        break;
      case 12:
        s.qspi[XIAO_OTA_FLOOR_A] ^= 1;
        break;
    }
    build_and_write_command(&s, 91, 1, 1, size, candidate_hash, size, old_hash);
    memcpy(internal_before, s.internal_flash, FAKE_IO_INTERNAL_SIZE);
    memcpy(qspi_before, s.qspi, FAKE_IO_QSPI_SIZE);
    assert(fake_io_run_boot(&s) == 0);
    if (read_state(&s, &state))
      fprintf(stderr, "original rejection case %u reached phase %u\n",
              test, state.phase);
    assert(!read_state(&s, &state));
    assert(s.watchdog_start_calls == 0);
    assert(memcmp(internal_before, s.internal_flash, FAKE_IO_INTERNAL_SIZE) == 0);
    assert(memcmp(qspi_before, s.qspi, FAKE_IO_QSPI_SIZE) == 0);
    free(internal_before);
    free(qspi_before);
  }
}

static void test_vendor_zero_crc_original_continuation(bool backup_ready,
                                                       bool read_failure) {
  fake_io_state_t s;
  xiao_ota_state_t state;
  uint8_t old_hash[32], candidate_hash[32], digest[32];
  uint8_t original_settings[28], restored[28];
  const uint32_t size = 32768;
  fake_io_reset(&s);
  provision_vendor_zero_crc_original(&s, size, old_hash);
  fake_io_read_settings_raw(&s, original_settings);
  write_candidate(&s, size, 0x77, candidate_hash);
  build_and_write_command(&s, 91, 1, 1, size, candidate_hash, size, old_hash);
  if (backup_ready) {
    /* Second candidate hash starts after BACKUP_READY is durable. */
    s.crash.op = FAKE_IO_OP_QSPI_READ;
    s.crash.addr_lo = XIAO_OTA_CANDIDATE_BASE;
    s.crash.addr_hi = s.crash.addr_lo + 256;
    s.crash.after = 2;
  } else {
    /* INSTALL_COPYING is durable but no original bytes are erased yet. */
    s.crash.op = FAKE_IO_OP_INTERNAL_ERASE;
    s.crash.addr_lo = XIAO_OTA_APP_START;
    s.crash.addr_hi = s.crash.addr_lo + XIAO_OTA_QSPI_SECTOR_SIZE;
    s.crash.after = 1;
  }
  assert(fake_io_run_boot(&s) == 1);
  assert(read_state(&s, &state));
  assert(state.phase == (backup_ready ? XIAO_OTA_PHASE_BACKUP_READY
                                     : XIAO_OTA_PHASE_INSTALL_COPYING));
  assert(state.progress_bytes == 0);
  s.crash.op = FAKE_IO_OP_NONE;
  if (read_failure) {
    s.fail.op = FAKE_IO_OP_INTERNAL_READ;
    s.fail.addr_lo = XIAO_OTA_APP_START + 256;
    s.fail.addr_hi = s.fail.addr_lo + 256;
    s.fail.after = 1;
  }
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == (read_failure ? XIAO_OTA_PHASE_FAILED
                                     : XIAO_OTA_PHASE_TRIAL_BOOT));
  if (read_failure) {
    fake_io_read_settings_raw(&s, restored);
    assert(memcmp(restored, original_settings, 28) == 0);
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, size, digest);
    assert(memcmp(digest, old_hash, 32) == 0);
  }
  assert(s.force_recovery_calls == 0);
}

static void test_candidate_zero_sdk_crc_mismatch_stays_strict(bool floor_repair) {
  fake_io_state_t s;
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  uint8_t old_hash[32], candidate_hash[32], original_settings[28], restored[28];
  const uint32_t size = 32768;
  fake_io_reset(&s);
  provision_vendor_zero_crc_original(&s, size, old_hash);
  fake_io_read_settings_raw(&s, original_settings);
  write_candidate(&s, size, 0x77, candidate_hash);
  assert(crc16_compute(s.qspi + XIAO_OTA_CANDIDATE_BASE, size, NULL) != 0);
  build_and_write_command(&s, 91, 1, 1, size, candidate_hash, size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  write_confirmation(&s, 91, 1, candidate_hash);
  if (floor_repair) {
    assert(fake_io_run_boot(&s) == 0);
    assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_CONFIRMED);
    memset(s.qspi + XIAO_OTA_FLOOR_A, 0xFF, 2 * XIAO_OTA_QSPI_SECTOR_SIZE);
  }
  /* Keep the exact candidate SHA, but disable the CRC as if SDK stock DFU
   * had written it. Neither qualified confirmation nor floor repair may
   * use the original-image SHA exception to accept this candidate. */
  fake_io_provision_bank0_settings(&s, 1, 0, size);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  if (floor_repair) {
    assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
    assert(!read_floor(&s, &floor));
    for (uint32_t i = 0; i < 2 * XIAO_OTA_QSPI_SECTOR_SIZE; ++i)
      assert(s.qspi[XIAO_OTA_FLOOR_A + i] == 0xFF);
  } else {
    assert(state.phase == XIAO_OTA_PHASE_FAILED);
    assert(read_floor(&s, &floor) && floor.confirmed_counter_floor == 0);
    fake_io_read_settings_raw(&s, restored);
    assert(memcmp(restored, original_settings, 28) == 0);
  }
  assert(s.force_recovery_calls == 0);
}

static void provision_factory_original(fake_io_state_t *s, bool unused_crc,
                                       uint8_t hash[32]) {
  fake_io_reset(s);
  provision_vendor_zero_crc_original(s, 32768, hash);
  if (!unused_crc)
    fake_io_provision_bank0_settings(s, 1, crc16_compute(
        s->internal_flash + XIAO_OTA_APP_START, 32768, NULL), 32768);
  memset(s->qspi + XIAO_OTA_JOURNAL_BASE, 0xFF, XIAO_OTA_JOURNAL_SIZE);
}

static void count_factory_writes(fake_io_state_t *s) {
  s->crash.op = FAKE_IO_OP_QSPI_ERASE;
  s->crash.after = -1;
  s->crash.count = 0;
  s->tear.op = FAKE_IO_OP_QSPI_WRITE;
  s->tear.after = -1;
  s->tear.count = 0;
}

static void assert_factory_no_writes(const fake_io_state_t *s) {
  assert(s->crash.count == 0 && s->tear.count == 0);
}

static void assert_genesis_floor(const fake_io_state_t *s) {
  xiao_ota_floor_t floor;
  assert(read_floor(s, &floor));
  assert(floor.sequence == 1 && floor.confirmed_counter_floor == 0);
  assert(floor.active_image_extent == 0);
  for (unsigned i = 0; i < 32; ++i) assert(floor.confirmed_hash_sha256[i] == 0);
  assert(xiao_ota_floor_valid(
      (const xiao_ota_floor_t *)(s->qspi + XIAO_OTA_FLOOR_A)));
}

static void test_factory_genesis_and_lifecycle(bool unused_crc, bool confirm) {
  fake_io_state_t s;
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  uint8_t old_hash[32], candidate_hash[32], restored_hash[32];
  uint8_t original_sdk[28], restored_sdk[28];
  uint8_t *internal_before = malloc(FAKE_IO_INTERNAL_SIZE);
  uint8_t *qspi_before = malloc(FAKE_IO_QSPI_SIZE);
  assert(internal_before && qspi_before);
  provision_factory_original(&s, unused_crc, old_hash);
  fake_io_read_settings_raw(&s, original_sdk);
  memcpy(internal_before, s.internal_flash, FAKE_IO_INTERNAL_SIZE);
  memcpy(qspi_before, s.qspi, FAKE_IO_QSPI_SIZE);
  assert(fake_io_run_boot(&s) == 0);
  assert_genesis_floor(&s);
  assert(!read_state(&s, &state));
  assert(s.force_recovery_calls == 0 && s.watchdog_start_calls == 0);
  assert(memcmp(internal_before, s.internal_flash, FAKE_IO_INTERNAL_SIZE) == 0);
  memcpy(qspi_before + XIAO_OTA_FLOOR_A, s.qspi + XIAO_OTA_FLOOR_A,
         sizeof(floor));
  assert(memcmp(qspi_before, s.qspi, FAKE_IO_QSPI_SIZE) == 0);
  count_factory_writes(&s);
  assert(fake_io_run_boot(&s) == 0);
  assert_factory_no_writes(&s);
  assert(memcmp(qspi_before, s.qspi, FAKE_IO_QSPI_SIZE) == 0);

  write_candidate(&s, 40960, 0x77, candidate_hash);
  build_and_write_command(&s, 91, 1, 1, 40960, candidate_hash, 32768, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  if (confirm) {
    write_confirmation(&s, 91, 1, candidate_hash);
    assert(fake_io_run_boot(&s) == 0);
    assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_CONFIRMED);
    assert(read_floor(&s, &floor) && floor.confirmed_counter_floor == 1);
    assert(floor.active_image_extent == 40960);
    assert(memcmp(floor.confirmed_hash_sha256, candidate_hash, 32) == 0);
  } else {
    for (unsigned i = 0; i < XIAO_OTA_MAX_TRIAL_BOOTS; ++i)
      assert(fake_io_run_boot(&s) == 0);
    assert(read_state(&s, &state) && state.phase == XIAO_OTA_PHASE_FAILED);
    fake_io_read_settings_raw(&s, restored_sdk);
    assert(memcmp(original_sdk, restored_sdk, 28) == 0);
    sha256_of(s.internal_flash + XIAO_OTA_APP_START, 32768, restored_hash);
    assert(memcmp(old_hash, restored_hash, 32) == 0);
    assert_genesis_floor(&s);
  }
  assert(s.force_recovery_calls == 0);
  free(internal_before);
  free(qspi_before);
}

static void test_factory_journal_denials(void) {
  const uint32_t positions[] = {0, XIAO_OTA_SETTINGS_SIDECAR_OFFSET, 4095};
  for (unsigned sector = 0; sector < 8; ++sector) {
    for (unsigned test = 0; test < 4; ++test) {
      fake_io_state_t s;
      xiao_ota_floor_t floor;
      uint8_t hash[32];
      uint8_t *before = malloc(FAKE_IO_QSPI_SIZE);
      assert(before);
      provision_factory_original(&s, true, hash);
      const uint32_t address = XIAO_OTA_JOURNAL_BASE + sector * 4096;
      if (test < 3) s.qspi[address + positions[test]] = 0;
      else {
        s.fail.op = FAKE_IO_OP_QSPI_READ;
        s.fail.addr_lo = address;
        s.fail.addr_hi = address + 4096;
        s.fail.after = 1;
      }
      memcpy(before, s.qspi, FAKE_IO_QSPI_SIZE);
      count_factory_writes(&s);
      assert(fake_io_run_boot(&s) == 0);
      assert_factory_no_writes(&s);
      assert(!read_floor(&s, &floor));
      assert(memcmp(before, s.qspi, FAKE_IO_QSPI_SIZE) == 0);
      if (test == 3) assert(s.force_recovery_calls == 0);
      free(before);
    }
  }
}

static void test_factory_original_denials(void) {
  for (unsigned test = 0; test < 12; ++test) {
    fake_io_state_t s;
    uint8_t hash[32];
    uint8_t *before = malloc(FAKE_IO_INTERNAL_SIZE);
    assert(before);
    provision_factory_original(&s, true, hash);
    switch (test) {
      case 0: fake_io_provision_bank0_settings(&s, 0xFF, 0, 32768); break;
      case 1: fake_io_provision_bank0_settings(&s, 1, 0, 0); break;
      case 2: fake_io_provision_bank0_settings(&s, 1, 0, 7); break;
      case 3:
        fake_io_provision_bank0_settings(&s, 1, 0, XIAO_OTA_INSTALL_MAX_SIZE + 4);
        break;
      case 4:
        s.internal_flash[XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + 4] = 1;
        break;
      case 5: memset(s.internal_flash + XIAO_OTA_APP_START, 0xFF, 8); break;
      case 6:
        fake_io_provision_bank0_settings(&s, 1, 1, 32768);
        assert(crc16_compute(s.internal_flash + XIAO_OTA_APP_START,
                             32768, NULL) != 1);
        break;
      case 7: fake_io_poison_settings_tail(&s, 4095, 0); break;
      case 8:
      case 9:
      case 10:
        s.fail.op = FAKE_IO_OP_INTERNAL_READ;
        s.fail.after = 1;
        s.fail.addr_lo = test == 8 ? XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS
                                  : XIAO_OTA_APP_START + 256;
        s.fail.addr_hi = s.fail.addr_lo + 4;
        if (test == 9) s.fail.after = 2; /* Actual CRC, after first SHA. */
        break;
      case 11:
        s.fail.op = FAKE_IO_OP_QSPI_READ;
        s.fail.addr_lo = XIAO_OTA_FLOOR_A;
        s.fail.addr_hi = s.fail.addr_lo + 4;
        s.fail.after = 2; /* Independent immediate pre-erase floor check. */
        break;
    }
    memcpy(before, s.internal_flash, FAKE_IO_INTERNAL_SIZE);
    count_factory_writes(&s);
    assert(fake_io_run_boot(&s) == 0);
    assert_factory_no_writes(&s);
    assert(s.force_recovery_calls == 0);
    assert(memcmp(before, s.internal_flash, FAKE_IO_INTERNAL_SIZE) == 0);
    for (uint32_t i = 0; i < XIAO_OTA_JOURNAL_SIZE; ++i)
      assert(s.qspi[XIAO_OTA_JOURNAL_BASE + i] == 0xFF);
    free(before);
  }
}

/* Wrap the existing fake's real read callbacks, preserving its NOR and
 * fault semantics. No parallel processor or flash writer is modelled. */
static xiao_ota_io_t factory_base_io;
static unsigned factory_read_mode, factory_sdk_reads, factory_app_reads;
static bool factory_mask_floor;

static bool factory_qspi_read(void *ctx, uint32_t address, void *out, size_t n) {
  if (!factory_base_io.qspi_read(ctx, address, out, n)) return false;
  if (factory_mask_floor && address >= XIAO_OTA_FLOOR_A &&
      address < XIAO_OTA_FLOOR_B + 4096) {
    memset(out, 0xFF, n);
    if (address + n == XIAO_OTA_FLOOR_B + 4096) factory_mask_floor = false;
  }
  return true;
}

static bool factory_internal_read(void *ctx, uint32_t address, void *out,
                                  size_t n) {
  fake_io_state_t *s = ctx;
  if (address == XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS) {
    factory_sdk_reads++;
    if (factory_read_mode == 1 && factory_sdk_reads == 3)
      s->internal_flash[address + 6] ^= 1; /* Ancillary SDK drift only. */
  }
  if (address == XIAO_OTA_APP_START) {
    factory_app_reads++;
    if (factory_read_mode == 2 && factory_app_reads == 3)
      s->internal_flash[address + 512] ^= 1; /* Drift after the first SHA. */
  }
  return factory_base_io.internal_read(ctx, address, out, n);
}

static void run_factory_read_fault(fake_io_state_t *s, unsigned mode,
                                    bool mask_floor) {
  factory_base_io = fake_io_interface(s);
  xiao_ota_io_t io = factory_base_io;
  factory_read_mode = mode;
  factory_sdk_reads = factory_app_reads = 0;
  factory_mask_floor = mask_floor;
  io.qspi_read = factory_qspi_read;
  io.internal_read = factory_internal_read;
  xiao_ota_boot_process_io(&io);
}

static void test_factory_stability_and_floor_misread(void) {
  for (unsigned mode = 0; mode < 3; ++mode) {
    fake_io_state_t s;
    xiao_ota_floor_t floor;
    uint8_t hash[32];
    uint8_t *before = malloc(FAKE_IO_QSPI_SIZE);
    assert(before);
    provision_factory_original(&s, true, hash);
    if (mode == 0) write_floor_direct(&s, 7, 32768, hash);
    memcpy(before, s.qspi, FAKE_IO_QSPI_SIZE);
    count_factory_writes(&s);
    run_factory_read_fault(&s, mode, mode == 0);
    assert(memcmp(before, s.qspi, FAKE_IO_QSPI_SIZE) == 0);
    assert_factory_no_writes(&s);
    if (mode == 0) {
      assert(!factory_mask_floor);
      assert(read_floor(&s, &floor) && floor.confirmed_counter_floor == 7);
    } else assert(!read_floor(&s, &floor));
    assert(s.force_recovery_calls == 0);
    free(before);
  }
}

static void test_factory_existing_floor_history(void) {
  for (unsigned kind = 0; kind < 4; ++kind) {
    fake_io_state_t s;
    uint8_t hash[32];
    uint8_t *before = malloc(FAKE_IO_QSPI_SIZE);
    assert(before);
    provision_factory_original(&s, true, hash);
    write_floor_direct(&s, kind == 0 ? 0 : 7, 32768, hash);
    if (kind == 2) s.qspi[XIAO_OTA_FLOOR_A] ^= 1;
    if (kind == 3)
      memset(s.qspi + XIAO_OTA_FLOOR_A +
             offsetof(xiao_ota_floor_t, commit_marker), 0xFF, 4);
    memcpy(before, s.qspi, FAKE_IO_QSPI_SIZE);
    count_factory_writes(&s);
    assert(fake_io_run_boot(&s) == 0);
    assert_factory_no_writes(&s);
    assert(memcmp(before, s.qspi, FAKE_IO_QSPI_SIZE) == 0);
    assert(s.force_recovery_calls == 0);
    free(before);
  }
}

static void test_factory_write_cut_matrix(void) {
  for (unsigned test = 0; test < 13; ++test) {
    fake_io_state_t s;
    uint8_t hash[32];
    uint8_t *internal_before = malloc(FAKE_IO_INTERNAL_SIZE);
    uint8_t *qspi_before = malloc(FAKE_IO_QSPI_SIZE);
    assert(internal_before && qspi_before);
    provision_factory_original(&s, true, hash);
    /* Non-journal userdata sentinels, including app filesystem/security. */
    s.qspi[XIAO_OTA_INSTALL_MAX_SIZE] = 0x12;
    s.qspi[XIAO_OTA_BACKUP_BASE + XIAO_OTA_INSTALL_MAX_SIZE] = 0x34;
    s.qspi[XIAO_OTA_FILESYSTEM_BASE] = 0x56;
    s.internal_flash[XIAO_OTA_INSTALL_ALLOWED_END] = 0x78;
    memcpy(internal_before, s.internal_flash, FAKE_IO_INTERNAL_SIZE);
    memcpy(qspi_before, s.qspi, FAKE_IO_QSPI_SIZE);
    fake_io_fault_t *fault = test == 1 || test == 4 || test == 7 ||
                                   test == 9 || test == 11 ? &s.crash
                            : test == 3 || test == 6 ? &s.tear : &s.fail;
    fault->addr_lo = XIAO_OTA_FLOOR_A;
    fault->addr_hi = fault->addr_lo + 4;
    fault->after = 1;
    if (test < 2) fault->op = FAKE_IO_OP_QSPI_ERASE;
    else if (test < 5) {
      fault->op = FAKE_IO_OP_QSPI_WRITE;
      if (test == 3) s.tear_bytes = 20;
      if (test == 4) {
        fault = &s.tear;
        *fault = s.crash;
        s.crash.op = FAKE_IO_OP_NONE;
        fault->op = FAKE_IO_OP_QSPI_WRITE;
        s.tear_bytes = 20;
        s.tear_crash = true;
      }
    } else if (test < 8) {
      fault->op = FAKE_IO_OP_QSPI_WRITE;
      fault->addr_lo += offsetof(xiao_ota_floor_t, commit_marker);
      fault->addr_hi = fault->addr_lo + 4;
      if (test == 6) s.tear_bytes = 2;
    } else if (test < 12) {
      fault->op = FAKE_IO_OP_QSPI_READ;
      fault->after = test < 10 ? 3 : 4; /* Two blank scans, body/final verify. */
    } else {
      fault = &s.tear;
      fault->op = FAKE_IO_OP_QSPI_WRITE;
      fault->addr_lo = XIAO_OTA_FLOOR_A + offsetof(xiao_ota_floor_t, commit_marker);
      fault->addr_hi = fault->addr_lo + 4;
      fault->after = 1;
      s.tear_bytes = 2;
      s.tear_crash = true;
    }
    const bool crash = test == 1 || test == 4 || test == 7 ||
                       test == 9 || test == 11 || test == 12;
    assert(fake_io_run_boot(&s) == (crash ? 1 : 0));
    assert(s.force_recovery_calls == 0);
    assert(memcmp(internal_before, s.internal_flash, FAKE_IO_INTERNAL_SIZE) == 0);
    memcpy(qspi_before + XIAO_OTA_FLOOR_A, s.qspi + XIAO_OTA_FLOOR_A, 4096);
    assert(memcmp(qspi_before, s.qspi, FAKE_IO_QSPI_SIZE) == 0);
    const bool untouched = test < 3;
    s.fail.op = s.crash.op = s.tear.op = FAKE_IO_OP_NONE;
    s.tear_crash = false;
    count_factory_writes(&s);
    s.crash.addr_lo = s.tear.addr_lo = 0;
    s.crash.addr_hi = s.tear.addr_hi = UINT32_MAX;
    assert(fake_io_run_boot(&s) == 0);
    if (untouched) assert_genesis_floor(&s); /* Still wholly blank may retry. */
    else {
      assert_factory_no_writes(&s);
      assert(memcmp(qspi_before, s.qspi, FAKE_IO_QSPI_SIZE) == 0);
    }
    assert(s.force_recovery_calls == 0);
    assert(memcmp(internal_before, s.internal_flash, FAKE_IO_INTERNAL_SIZE) == 0);
    free(internal_before);
    free(qspi_before);
  }
}

int main(void) {
  crypto_sign_keypair(xiao_ota_test_public_key_ed25519, g_test_secret_key);

  test_partial_state_marker_conservatively_burns_possible_retry();
  printf("partial state marker conservatively burns possible retry passed\n");
  test_prepared_sidecar_retains_committed_state_pair();
  printf("prepared sidecar retains committed state pair passed\n");
  test_resize_confirm(320u * 1024u, 500u * 1024u);
  printf("resize confirm 320K->500K passed\n");
  test_resize_confirm(500u * 1024u, 320u * 1024u);
  printf("resize confirm 500K->320K passed\n");
  test_two_different_admitted_keys_each_verify_their_own_image();
  printf("two different admitted signer keys each verify their own image passed\n");
  test_mutated_admitted_key_rejected_before_any_app_erase();
  printf("mutated admitted key rejected before any app erase passed\n");
  test_torn_command_preserves_prior_confirmed_record();
  printf("torn command preserves prior confirmed record passed\n");
  test_failed_retry_then_new_nonce();
  printf("failed-retry / new-nonce passed\n");
  test_crash_mid_install_then_rollback(false);
  test_crash_mid_install_then_rollback(true);
  printf("crash mid install / rollback passed\n");
  test_stale_confirmation_never_advances_floor();
  printf("stale confirmation never advances floor passed\n");
  test_explicit_dfu_bypasses_ota();
  printf("explicit DFU bypass passed\n");
  test_floor_state_cut_idempotent_resume();
  printf("floor/state cut idempotent resume passed\n");
  test_sequence_preserved_across_transactions();
  printf("state.sequence preserved across transactions passed\n");
  test_backup_authenticated_before_rollback_erase();
  printf("backup authenticated before rollback erase passed\n");
  test_pure_io_failure_refuses_without_crash();
  printf("pure I/O failure refuses without crash passed\n");
  test_torn_state_write_refuses_without_commit();
  printf("torn state write refuses without commit passed\n");
  test_corrupt_floor_refuses_new_transaction();
  printf("corrupt floor refuses new transaction passed\n");
  test_floor_non_regression_refuses_stale_confirmation();
  printf("floor non-regression refuses stale confirmation passed\n");
  test_no_confirmed_without_durable_floor();
  printf("no CONFIRMED without durable floor passed\n");
  test_state_io_error_mid_transaction_force_recovery();
  printf("state IO error mid-transaction force-recovery passed\n");
  test_floor_io_error_with_existing_record_force_recovery();
  printf("floor IO error with existing record force-recovery passed\n");
  test_persist_targets_actual_other_slot_not_parity();
  printf("persist targets actual other slot, not parity passed\n");
  test_floor_equal_counter_different_hash_conflict();
  printf("floor equal-counter different-hash conflict passed\n");
  test_floor_matching_counter_hash_but_wrong_extent_conflict();
  printf("floor matching counter/hash but wrong extent conflict passed\n");
  test_same_image_same_counter_high32_nonce_is_new_request();
  printf("same image/counter, high32-only nonce is new request passed\n");
  test_qspi_init_failure_force_recovery();
  printf("qspi_init failure force-recovery passed\n");
  test_torn_settings_commit_during_finalize_forces_rollback();
  printf("torn settings-page commit during finalize forces rollback passed\n");
  test_full_capacity_backup_install_rollback_preserves_tail_regions();
  printf("full capacity backup/install/rollback preserves tail regions passed\n");
  test_active_extent_above_capacity_refused_before_any_mutation();
  printf("active extent above capacity refused before any mutation passed\n");
  test_rollback_restores_settings_raw_verbatim();
  printf("rollback restores settings raw verbatim passed\n");
  test_active_transaction_missing_sidecar_forces_recovery();
  printf("active transaction missing sidecar forces recovery passed\n");
  test_active_transaction_mismatched_sidecar_forces_recovery();
  printf("active transaction mismatched sidecar forces recovery passed\n");
  test_active_transaction_command_digest_mismatch_forces_recovery();
  printf("active transaction command digest mismatch forces recovery passed\n");
  test_active_transaction_bank0_triad_mismatch_forces_recovery();
  printf("active transaction bank0 triad mismatch forces recovery passed\n");
  test_settings_tail_poisoned_refuses_write();
  printf("settings tail poisoned refuses write passed\n");
  test_install_settings_write_reboot_resume_matrix();
  printf("install settings-write reboot resume matrix passed\n");
  test_rollback_settings_write_reboot_resume_matrix();
  printf("rollback settings-write reboot resume matrix passed\n");
  test_corrupted_committed_newer_state_refuses_stale_fallback();
  printf("corrupted committed newer state refuses stale fallback passed\n");
  test_committed_state_marker_bit_set_never_reopens_stale_state();
  printf("committed state marker bit set never reopens stale state passed\n");
  test_committed_state_marker_damage_same_nonce_cannot_regrant_trials();
  printf("committed state marker damage same nonce cannot regrant trials passed\n");
  test_corrupted_committed_newer_floor_refuses_stale_trust();
  printf("corrupted committed newer floor refuses stale trust passed\n");
  test_floor_corruption_fixture_admits_counter_four_above_healthy_three();
  printf("floor corruption fixture admits counter four above healthy three passed\n");
  test_committed_floor_marker_bit_set_never_reopens_stale_counter();
  printf("committed floor marker bit set never reopens stale counter passed\n");
  test_committed_floor_marker_and_body_damage_never_reopen_stale_counter();
  printf("committed floor marker and body damage never reopen stale counter passed\n");
  test_real_committed_retry_marker_damage_never_regrants_same_trial();
  printf("real committed retry marker damage never regrants same trial passed\n");
  test_real_committed_retry_prefix_shaped_marker_damage_never_regrants_same_trial();
  test_real_committed_retry_erased_marker_never_regrants_same_trial();
  test_real_committed_retry_erased_marker_and_invalid_body_never_regrants();
  test_both_real_retry_bodies_survive_erased_markers_without_losing_backup();
  test_body_only_retry_source_survives_crash_after_parent_erase();
  printf("real committed retry prefix-shaped marker damage never regrants same trial passed\n");
  test_damaged_floor_bound_to_real_confirmed_state_never_reopens_counter();
  test_erased_floor_marker_bound_to_real_confirmed_state_never_reopens_counter();
  test_erased_floor_marker_and_body_bound_to_real_confirmed_state_never_reopens_counter();
  printf("damaged floor bound to real confirmed state never reopens counter passed\n");
  test_surviving_floor_above_state_counter_refuses_repair_survivor_in_a();
  test_surviving_floor_above_state_counter_refuses_repair_survivor_in_b();
  printf("surviving floor above stale state counter refuses repair passed\n");
  test_orphaned_damaged_sidecar_forces_recovery();
  printf("orphaned damaged sidecar forces recovery passed\n");
  test_orphaned_sidecar_with_no_command_forces_recovery();
  printf("orphaned sidecar with no command forces recovery passed\n");
  test_orphaned_sidecar_with_wrong_command_binding_forces_recovery();
  printf("orphaned sidecar with wrong command binding forces recovery passed\n");
  test_first_publication_sidecar_prep_cut_is_harmless();
  printf("first publication sidecar prep cut is harmless passed\n");
  test_committed_sidecar_marker_bit_set_forces_recovery();
  printf("committed sidecar marker bit set forces recovery passed\n");
  test_second_transaction_marker_cut_preserves_confirmed_pair();
  printf("second transaction marker cut preserves confirmed pair passed\n");
  test_install_settings_erase_then_crash_before_write_resumes();
  printf("install settings erase-then-crash-before-write resumes passed\n");
  test_rollback_settings_erase_then_crash_before_write_resumes();
  printf("rollback settings erase-then-crash-before-write resumes passed\n");
  test_state_sidecar_publication_cut_matrix_first_publication();
  printf("state/sidecar publication cut matrix (first publication) passed\n");
  test_state_sidecar_publication_cut_matrix_terminal_replacement();
  printf("state/sidecar publication cut matrix (terminal replacement) passed\n");
  test_publication_erase_crash_first_publication_resumes();
  printf("publication erase-crash (first publication) resumes passed\n");
  test_publication_erase_crash_terminal_replacement_resumes();
  printf("publication erase-crash (terminal replacement) resumes passed\n");
  test_state_sidecar_publication_cut_matrix_active_retry();
  printf("state/sidecar publication cut matrix (active retry) passed\n");
  test_publication_erase_crash_active_retry_resumes();
  printf("publication erase-crash (active retry) resumes passed\n");
  test_signed_zero_crc_candidate_installs_confirms_and_resolves_next_boot();
  printf("signed zero-CRC candidate installs/confirms/resolves next boot passed\n");
  test_stored_zero_crc_no_longer_matches_recomputed_nonzero_refuses();
  printf("stored zero CRC no longer matches recomputed nonzero refuses passed\n");
  test_vendor_zero_crc_original_lifecycle(true);
  test_vendor_zero_crc_original_lifecycle(false);
  test_original_baseline_rejections();
  test_vendor_zero_crc_original_continuation(true, false);
  test_vendor_zero_crc_original_continuation(false, false);
  test_vendor_zero_crc_original_continuation(true, true);
  test_vendor_zero_crc_original_continuation(false, true);
  test_candidate_zero_sdk_crc_mismatch_stays_strict(false);
  test_candidate_zero_sdk_crc_mismatch_stays_strict(true);
  printf("vendor CRC-unused original lifecycle and strict candidate/floor guards passed\n");
  test_factory_stability_and_floor_misread();
  test_factory_genesis_and_lifecycle(true, true);
  test_factory_genesis_and_lifecycle(true, false);
  test_factory_genesis_and_lifecycle(false, true);
  test_factory_journal_denials();
  test_factory_original_denials();
  test_factory_existing_floor_history();
  test_factory_write_cut_matrix();
  printf("factory unknown-image floor genesis, history guards and cut matrix passed\n");

  printf("xiao OTA boot process integration tests passed\n");
  return 0;
}
