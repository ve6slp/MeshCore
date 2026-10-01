/*
 * Literal-execution boot-process integration tests: every scenario here
 * calls fake_io_run_boot() (which invokes the REAL, unmodified
 * xiao_ota_boot_process_io() -- the exact function the production
 * xiao_ota_boot_process() calls against real hardware) against a fake, in-
 * memory-model xiao_ota_io_t (fake_io.c). No OTA transaction decision is
 * reimplemented here: commands are built by calling the same
 * xiao_ota_wire_descriptor_encode()/xiao_ota_crc32() functions production
 * and the host tooling already share, and signed with a genuinely fresh,
 * test-runtime-generated Ed25519 keypair (tweetnacl crypto_sign_keypair())
 * fed to xiao_ota_boot_process_io() via -DXIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY,
 * so this never depends on (or needs) the real committed lab private key.
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
#include <sys/stat.h>
#include <errno.h>

/* Production ed25519_verify() (xiao_ota_ed25519_tweetnacl.c) -- no
 * dedicated header declares this symbol (same pattern already used by
 * test_ed25519.c/test_descriptor_contract.c); declared here so
 * test_authority_literal_interop_vector_verifies_and_tamper_rejects()
 * can call it directly against the literal Authority fixture below. */
int ed25519_verify(const unsigned char *signature, const unsigned char *message,
                   size_t message_length, const unsigned char *public_key);

/* Required by tweetnacl's crypto_sign_keypair()/crypto_sign(). Test-only,
 * deterministic (not cryptographically secure) -- fine, since this key
 * exists purely to exercise the real ed25519_verify() call in
 * xiao_ota_boot_io.c with a genuinely fresh keypair never rooted in any
 * committed secret. */
static uint32_t g_rand_state = 0x9E3779B9u;
void randombytes(unsigned char *buffer, unsigned long long length) {
  unsigned long long i;
  for (i = 0; i < length; ++i) {
    g_rand_state = g_rand_state * 1103515245u + 12345u;
    buffer[i] = (unsigned char)(g_rand_state >> 16);
  }
}

/* Definition of the symbol declared in fake_trust_anchor.h and substituted
 * for the production trust anchor via -D on this test build only. */
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

/* Provisions the CURRENT ("old") running application directly in fake
 * internal flash plus real, matching bank-0 settings -- exactly what a
 * fresh, already-installed device looks like from the bootloader's point
 * of view -- AND a matching, genuinely signed genesis
 * BootFloorActivationReceiptV1 (xiao_ota_record.h) bound to this exact,
 * ALREADY-DURABLY-PERSISTED floor body (written via write_floor_direct()
 * before the receipt, mirroring the real provisioning sequence). A
 * genuinely blank floor pair no longer implicitly trusts counter floor
 * 0, nor does a receipt alone without a matching persisted floor body
 * (see xiao_ota_boot_io.c's XIAO_OTA_PAIR_FOUND/XIAO_OTA_PAIR_MISSING
 * handling and floor_genesis_receipt_matches()); this is the single shared place
 * nearly every fixture already establishes its "already-provisioned"
 * starting device, so making its provisioning explicit and signed here
 * converts every existing implicit-factory-floor-0 fixture at once,
 * rather than requiring one-by-one per-test surgery. Fixtures that
 * specifically need a genuinely un-provisioned (no receipt) device use
 * provision_old_image_no_genesis_receipt() instead. */
static void provision_genesis_receipt(fake_io_state_t *s,
                                      uint32_t baseline_extent,
                                      const uint8_t baseline_hash[32]);
static void write_floor_direct(fake_io_state_t *s, uint32_t counter_floor,
                               uint32_t extent, const uint8_t hash[32]);

static void provision_old_image_no_genesis_receipt(fake_io_state_t *s,
                                                    uint32_t size, uint8_t seed,
                                                    uint8_t out_hash[32]) {
  uint8_t *region = s->internal_flash + XIAO_OTA_APP_START;
  fill_pattern(region, size, seed);
  sha256_of(region, size, out_hash);
  fake_io_provision_bank0_settings(s, XIAO_OTA_BANK_VALID_APP,
                                  crc16_compute(region, size, NULL), size);
}

static void provision_old_image(fake_io_state_t *s, uint32_t size,
                                uint8_t seed, uint8_t out_hash[32]) {
  provision_old_image_no_genesis_receipt(s, size, seed, out_hash);
  /* Genesis (floor 0) is trusted only once BOTH an already-durable,
   * fully-committed floor body AND a matching receipt exist -- a
   * receipt is provenance for a PRESENT floor, never a from-nothing
   * reseed instruction (xiao_ota_boot_io.c's XIAO_OTA_PAIR_FOUND/
   * XIAO_OTA_PAIR_MISSING handling). write_floor_direct() performs the
   * EXACT durable body-then-marker write a real factory/provisioning
   * tool would; the receipt is published only afterward, mirroring the
   * real prepare-body -> publish-receipt production sequence. */
  write_floor_direct(s, 0, size, out_hash);
  provision_genesis_receipt(s, size, out_hash);
}

static void write_candidate(fake_io_state_t *s, uint32_t size, uint8_t seed,
                            uint8_t out_hash[32]) {
  uint8_t *buffer = (uint8_t *)&s->qspi[XIAO_OTA_CANDIDATE_BASE];
  assert(size <= XIAO_OTA_CANDIDATE_SIZE);
  fill_pattern(buffer, size, seed);
  sha256_of(buffer, size, out_hash);
}

static void build_and_write_command(fake_io_state_t *s, uint64_t nonce,
                                    uint32_t sequence, uint32_t counter,
                                    uint32_t image_size,
                                    const uint8_t candidate_hash[32],
                                    uint32_t active_extent,
                                    const uint8_t active_hash[32]) {
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
             XIAO_OTA_WIRE_DESCRIPTOR_SIZE, g_test_secret_key);
  assert(signed_length == 64 + XIAO_OTA_WIRE_DESCRIPTOR_SIZE);

  memset(&cmd, 0, sizeof(cmd));
  cmd.magic = XIAO_OTA_RECORD_MAGIC;
  cmd.record_version = XIAO_OTA_COMMAND_VERSION_WIRE_V2;
  cmd.record_bytes = sizeof(cmd);
  cmd.sequence = sequence;
  cmd.transaction_nonce = nonce;
  memcpy(cmd.wire_descriptor, encoded, sizeof(encoded));
  memcpy(cmd.signature_ed25519, signed_message, 64);
  cmd.active_image_extent = active_extent;
  memcpy(cmd.active_image_hash_sha256, active_hash, 32);
  cmd.crc32 = xiao_ota_crc32(&cmd, offsetof(xiao_ota_command_v2_t, crc32));
  cmd.commit_marker = XIAO_OTA_COMMIT_MARKER;

  memset(s->qspi + XIAO_OTA_COMMAND_A, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memcpy(s->qspi + XIAO_OTA_COMMAND_A, &cmd, sizeof(cmd));
  memset(s->qspi + XIAO_OTA_COMMAND_B, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
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

/* Directly fabricates a structurally self-consistent (CRC/magic/bytes
 * all valid) floor record at slot A whose commit_marker is deliberately
 * left at the erased sentinel (0xFFFFFFFF) -- exactly what an
 * un-committed, "prepared" (body written, not yet Spent/finalized)
 * genesis floor body looks like: durably written and CRC-readback-
 * verifiable, but genuinely not yet a trusted, committed fact. Used to
 * build every genesis provisioning-cut fixture below; xiao_ota_boot_io.c
 * must never treat this as trustworthy on its own, with or without an
 * accompanying receipt, and must never attempt to durably repair/
 * finalize it (write its marker) itself -- only an external factory/
 * provisioning tool, alone, ever writes that marker. */
static void write_floor_prepared_direct(fake_io_state_t *s,
                                        uint32_t counter_floor,
                                        uint32_t extent,
                                        const uint8_t hash[32]) {
  xiao_ota_floor_t floor;
  memset(&floor, 0, sizeof(floor));
  floor.magic = XIAO_OTA_FLOOR_MAGIC;
  floor.record_version = XIAO_OTA_FORMAT_VERSION;
  floor.record_bytes = sizeof(floor);
  floor.sequence = 1;
  floor.confirmed_counter_floor = counter_floor;
  floor.active_image_extent = extent;
  memcpy(floor.confirmed_hash_sha256, hash, 32);
  floor.crc32 = xiao_ota_crc32(&floor, offsetof(xiao_ota_floor_t, crc32));
  floor.commit_marker = 0xFFFFFFFFu; /* deliberately NOT committed */
  memset(s->qspi + XIAO_OTA_FLOOR_A, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memcpy(s->qspi + XIAO_OTA_FLOOR_A, &floor, sizeof(floor));
  memset(s->qspi + XIAO_OTA_FLOOR_B, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
}

/*
 * Builds a genuinely signed BootFloorActivationReceiptV1 (see
 * xiao_ota_record.h) declaring genesis (floor 0) for `baseline_extent`/
 * `baseline_hash`, and writes it into floor slot A's activation-receipt
 * window (leaving slot B's window untouched -- xiao_ota_boot_io.c's
 * floor_genesis_receipt_matches() checks both, either verifying
 * suffices). `s->device_address` and the currently-provisioned bank-0
 * settings page are read directly so the receipt genuinely matches
 * whatever this fake device already has configured -- exactly the
 * fresh-hardware-truth proof xiao_ota_boot_io.c independently demands at
 * verification time, never merely a self-consistent but stale claim.
 * Pass a deliberately wrong `corrupt` bit (bad_signature/bad_uid/...) to
 * build the negative-mismatch fixtures without duplicating this whole
 * function per case.
 */
typedef enum {
  RECEIPT_OK = 0,
  RECEIPT_BAD_SIGNATURE,
  RECEIPT_BAD_UID,
  RECEIPT_BAD_DOMAIN,
  RECEIPT_BAD_PROFILE,
  RECEIPT_BAD_TARGET,
  RECEIPT_BAD_ROLE,
  RECEIPT_BAD_BASELINE_HASH,
  RECEIPT_BAD_BASELINE_EXTENT,
  RECEIPT_BAD_SDK28,
  RECEIPT_BAD_ACTIVATION_FLOOR
} receipt_fault_t;

static void build_genesis_receipt_fields(xiao_ota_floor_activation_receipt_t *r,
                                         fake_io_state_t *s,
                                         uint32_t baseline_extent,
                                         const uint8_t baseline_hash[32],
                                         uint32_t host_txn_patch,
                                         receipt_fault_t fault) {
  uint8_t raw_settings[XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE];
  uint8_t sdk28_digest[32];
  uint8_t key_hash[32];

  fake_io_read_settings_raw(s, raw_settings);
  sha256_of(raw_settings, sizeof(raw_settings), sdk28_digest);
  sha256_of(xiao_ota_test_public_key_ed25519, 32, key_hash);

  memset(r, 0, sizeof(*r));
  r->magic = XIAO_OTA_FLOOR_ACTIVATION_MAGIC;
  r->record_version = XIAO_OTA_FLOOR_ACTIVATION_RECORD_VERSION;
  r->record_bytes = sizeof(*r);
  r->boot_counter_domain = (fault == RECEIPT_BAD_DOMAIN)
                             ? XIAO_OTA_BOOT_COUNTER_DOMAIN + 1u
                             : XIAO_OTA_BOOT_COUNTER_DOMAIN;
  r->hw_uid = (fault == RECEIPT_BAD_UID) ? s->device_address + 1u
                                        : s->device_address;
  /* local_public_key / consent_owner_public_key / host_txn_id /
   * authority_txn_digest / manifest_digest / prepared_root_digest: opaque
   * to the bootloader's own verification (host/app responsibility) --
   * arbitrary fixed test bytes, present purely to prove the signature
   * genuinely binds them (tamper-evidence), never interpreted here.
   * host_txn_id's leading 4 bytes carry `host_txn_patch` (default
   * 0x33333333, i.e. byte-identical to the plain 0x33 fill used
   * everywhere else in this struct) -- purely a free, opaque "knob"
   * used by the CRC-collision regression fixture below to construct a
   * SECOND, genuinely differently-signed receipt whose crc32 happens to
   * match a target value, without touching any field that this file's
   * actual verification logic interprets. */
  memset(r->local_public_key, 0x11u, sizeof(r->local_public_key));
  memset(r->consent_owner_public_key, 0x22u, sizeof(r->consent_owner_public_key));
  memset(r->host_txn_id, 0x33u, sizeof(r->host_txn_id));
  r->host_txn_id[0] = (uint8_t)(host_txn_patch);
  r->host_txn_id[1] = (uint8_t)(host_txn_patch >> 8);
  r->host_txn_id[2] = (uint8_t)(host_txn_patch >> 16);
  r->host_txn_id[3] = (uint8_t)(host_txn_patch >> 24);
  r->target = (fault == RECEIPT_BAD_TARGET)
                ? (XIAO_OTA_BOARD_TARGET == XIAO_OTA_TARGET_XIAO_NRF52840
                       ? XIAO_OTA_TARGET_SENSECAP_SOLAR_P1
                       : XIAO_OTA_TARGET_XIAO_NRF52840)
                : XIAO_OTA_BOARD_TARGET;
  r->profile = (fault == RECEIPT_BAD_PROFILE)
                 ? 0u
                 : XIAO_OTA_FLOOR_ACTIVATION_COMPILED_PROFILE;
  r->layout_id = XIAO_OTA_FLOOR_ACTIVATION_LAYOUT_ID;
  /* RECEIPT_BAD_ROLE must always carry a role that is WRONG relative to
   * THIS binary's own compiled role, in both role-0 and role-1 builds --
   * "1 - compiled role" (the other of the only two valid role values)
   * rather than a hardcoded literal 1u, which would silently stop being
   * a fault case at all once compiled for role 1. */
  r->current_role = (fault == RECEIPT_BAD_ROLE) ? (1u - XIAO_OTA_COMPILED_ROLE_ID)
                                                : XIAO_OTA_COMPILED_ROLE_ID;
  r->key_id = XIAO_OTA_KEY_ID;
  memcpy(r->key_fingerprint, key_hash, sizeof(r->key_fingerprint));
  memset(r->authority_txn_digest, 0x44u, sizeof(r->authority_txn_digest));
  memset(r->manifest_digest, 0x55u, sizeof(r->manifest_digest));
  memset(r->prepared_root_digest, 0x66u, sizeof(r->prepared_root_digest));
  r->activation_floor = (fault == RECEIPT_BAD_ACTIVATION_FLOOR) ? 1u : 0u;
  memcpy(r->baseline_hash_sha256, baseline_hash, 32);
  if (fault == RECEIPT_BAD_BASELINE_HASH) r->baseline_hash_sha256[0] ^= 0x01u;
  r->baseline_extent = (fault == RECEIPT_BAD_BASELINE_EXTENT)
                         ? baseline_extent + 4u
                         : baseline_extent;
  /* original_sdk28_digest is now actively bound: genesis_sdk28_baseline_ok()
   * (xiao_ota_boot_io.c) checks it against the live settings page when no
   * transaction is active (always true for the fixtures in this file,
   * which write no state record), or against the admission-time sidecar
   * snapshot while a transaction is active -- never re-derived from a
   * settings page that may have legitimately mutated mid-transaction. See
   * that function's doc-comment for the full phase/provenance rationale. */
  memcpy(r->original_sdk28_digest, sdk28_digest, 32);
  if (fault == RECEIPT_BAD_SDK28) r->original_sdk28_digest[0] ^= 0x01u;
  r->crc32 = xiao_ota_crc32(r, offsetof(xiao_ota_floor_activation_receipt_t, crc32));
}

static void sign_and_write_genesis_receipt_at(fake_io_state_t *s,
                                              uint32_t window_addr,
                                              xiao_ota_floor_activation_receipt_t *r,
                                              receipt_fault_t fault) {
  uint8_t signing_buf[XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN_LEN +
                     offsetof(xiao_ota_floor_activation_receipt_t,
                              signature_ed25519)];
  uint8_t digest[32];
  unsigned char signed_message[64 + 32];
  unsigned long long signed_length = 0;

  memcpy(signing_buf, XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN,
        XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN_LEN);
  memcpy(signing_buf + XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN_LEN, r,
        offsetof(xiao_ota_floor_activation_receipt_t, signature_ed25519));
  sha256_of(signing_buf, sizeof(signing_buf), digest);
  crypto_sign(signed_message, &signed_length, digest, sizeof(digest),
             g_test_secret_key);
  assert(signed_length == 64 + sizeof(digest));
  memcpy(r->signature_ed25519, signed_message, 64);
  if (fault == RECEIPT_BAD_SIGNATURE) r->signature_ed25519[0] ^= 0x01u;

  memset(s->qspi + window_addr, 0xFF,
        XIAO_OTA_FLOOR_ACTIVATION_WINDOW_MAX_SIZE);
  memcpy(s->qspi + window_addr, r, sizeof(*r));
}

static void write_genesis_receipt_variant_at(fake_io_state_t *s,
                                             uint32_t window_addr,
                                             uint32_t baseline_extent,
                                             const uint8_t baseline_hash[32],
                                             receipt_fault_t fault) {
  xiao_ota_floor_activation_receipt_t r;
  build_genesis_receipt_fields(&r, s, baseline_extent, baseline_hash,
                              0x33333333u, fault);
  sign_and_write_genesis_receipt_at(s, window_addr, &r, fault);
}

static void write_genesis_receipt_variant(fake_io_state_t *s,
                                          uint32_t baseline_extent,
                                          const uint8_t baseline_hash[32],
                                          receipt_fault_t fault) {
  write_genesis_receipt_variant_at(s, XIAO_OTA_FLOOR_ACTIVATION_A,
                                   baseline_extent, baseline_hash, fault);
}

static void provision_genesis_receipt(fake_io_state_t *s,
                                      uint32_t baseline_extent,
                                      const uint8_t baseline_hash[32]) {
  write_genesis_receipt_variant(s, baseline_extent, baseline_hash, RECEIPT_OK);
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
   * fake_io_read_settings_raw(), the exact same accessor
   * provision_genesis_receipt()/write_genesis_receipt_variant() use to
   * compute a genesis receipt's original_sdk28_digest) -- not arbitrary
   * fabricated bytes. This keeps the fabricated in-flight transaction
   * genuinely, byte-for-byte consistent with whatever genesis receipt
   * callers of this helper may ALSO have provisioned (see
   * genesis_sdk28_baseline_ok() in xiao_ota_boot_io.c, which now
   * requires the active-transaction sidecar snapshot to hash-match the
   * receipt's signed claim), while the previous_bank_0/_crc/_size triad
   * mirrored into the state record below is read from those SAME bytes,
   * so xiao_ota_boot_process_io()'s bank0_triad_matches check still
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
  /* This device is genesis-provisioned (provision_old_image() writes a
   * genuinely signed BootFloorActivationReceiptV1 -- see
   * xiao_ota_boot_io.c's floor_genesis_receipt_matches()), so a
   * confirmed_counter_floor==0 floor record IS legitimately established
   * the very first boot, well before any OTA transaction ever confirms
   * -- this is the fail-closed genesis contract itself, not evidence of
   * a completed install. The floor's own identity must match the
   * genesis baseline (the OLD image), never the failed candidate. */
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
  /* The genesis floor established above must remain exactly unchanged
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
static void test_crash_mid_install_then_rollback(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  const uint32_t old_size = 32768;
  const uint32_t new_size = 65536;

  fake_io_reset(&s);
  provision_old_image(&s, old_size, 0x33, old_hash);
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

  /* Power restored: disable further injection and resume. The fresh bank-0
   * CRC recheck against the (now partially overwritten) app region fails
   * closed immediately, so this single boot call rolls back to the
   * verified backup and reaches FAILED without ever exposing TRIAL_BOOT. */
  s.crash.op = FAKE_IO_OP_NONE;
  s.crash.after = -1;
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_FAILED);
  assert(read_bank0_size(&s) == old_size);
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

  /* This device is genesis-provisioned, so the genesis floor (counter 0,
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

/*
 * Genesis (floor 0) provisioning-cut/fault battery: a receipt is
 * provenance for an ALREADY-DURABLE, matching, committed floor body,
 * never an instruction to reconstruct a missing body or finalize
 * (write the commit_marker for) an uncommitted one -- this bootloader
 * must never do either, at any of the cut boundaries a real factory/
 * provisioning sequence (prepare body -> publish receipt -> commit
 * marker, each a separate durable step) can be interrupted at. Every
 * case here must refuse ALL fresh command admission (no state record
 * ever created) without ever calling force_recovery -- exactly the
 * same fail-closed-but-otherwise-inert outcome an ordinary DAMAGED
 * floor already produces (see test_corrupt_floor_refuses_new_
 * transaction above).
 */
static void assert_genesis_denies_fresh_admission(fake_io_state_t *s) {
  xiao_ota_state_t state;
  assert(fake_io_run_boot(s) == 0);
  assert(!read_state(s, &state));
  assert(s->force_recovery_calls == 0);
}

/* Pre-body cut: a genuinely fresh device, no floor body and no receipt
 * in either slot at all -- the ordinary XIAO_OTA_PAIR_MISSING case, and
 * (per the fail-closed genesis contract) always untrustworthy, with no
 * exception, even though nothing here is actually damaged. */
static void test_genesis_pre_body_cut_never_admits(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];

  fake_io_reset(&s);
  provision_old_image_no_genesis_receipt(&s, 8192, 0xA1, old_hash);
  write_candidate(&s, 8192, 0xB2, candidate_hash);
  build_and_write_command(&s, 1, 1, 1, 8192, candidate_hash, 8192, old_hash);
  assert_genesis_denies_fresh_admission(&s);
}

/* Post-body cut: the floor body was durably written (CRC-valid,
 * readback-verifiable) but the provisioning process was cut BEFORE the
 * receipt was ever published -- no receipt exists in either window at
 * all. Must deny exactly like a genuinely missing pair; the bootloader
 * must never treat an unauthenticated prepared body as trustworthy on
 * its own, and must never invent/publish a receipt itself. */
static void test_genesis_post_body_pre_receipt_cut_never_admits(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];

  fake_io_reset(&s);
  provision_old_image_no_genesis_receipt(&s, 8192, 0xA2, old_hash);
  write_floor_prepared_direct(&s, 0, 8192, old_hash);
  write_candidate(&s, 8192, 0xB3, candidate_hash);
  build_and_write_command(&s, 1, 1, 1, 8192, candidate_hash, 8192, old_hash);
  assert_genesis_denies_fresh_admission(&s);
}

/* Post-Spent/pre-marker cut: the floor body AND a genuinely verifying,
 * matching receipt are both durably present, but the provisioning
 * process was cut BEFORE the floor's own commit_marker was ever
 * written -- the body is still only "prepared", not committed. A
 * receipt alone (even a fully verifying one) must NEVER reconstruct the
 * missing marker/finalize this record itself; only the ALREADY
 * committed floor (checked at XIAO_OTA_PAIR_FOUND) is ever trusted.
 * Local/factory authority is expected to resume the activation from
 * scratch (a fresh, still-uncommitted candidate body), never this
 * bootloader synthesizing that resume on its own. */
static void test_genesis_post_receipt_pre_marker_cut_never_admits(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];

  fake_io_reset(&s);
  provision_old_image_no_genesis_receipt(&s, 8192, 0xA3, old_hash);
  write_floor_prepared_direct(&s, 0, 8192, old_hash);
  provision_genesis_receipt(&s, 8192, old_hash);
  write_candidate(&s, 8192, 0xB4, candidate_hash);
  build_and_write_command(&s, 1, 1, 1, 8192, candidate_hash, 8192, old_hash);
  assert_genesis_denies_fresh_admission(&s);
}

/* Every individual RECEIPT_BAD_* mismatch -- including RECEIPT_BAD_SDK28,
 * now actively bound by genesis_sdk28_baseline_ok() (xiao_ota_boot_io.c)
 * against the live settings page, since none of these fixtures have any
 * active transaction -- must independently deny fresh admission against
 * an otherwise fully genuine, committed genesis floor body -- a single
 * tampered/wrong field is exactly as untrusted as no receipt at all. */
static void run_genesis_receipt_fault_denies_admission(receipt_fault_t fault) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];

  fake_io_reset(&s);
  provision_old_image_no_genesis_receipt(&s, 8192, 0xA4, old_hash);
  write_floor_direct(&s, 0, 8192, old_hash);
  write_genesis_receipt_variant(&s, 8192, old_hash, fault);
  write_candidate(&s, 8192, 0xB5, candidate_hash);
  build_and_write_command(&s, 1, 1, 1, 8192, candidate_hash, 8192, old_hash);
  assert_genesis_denies_fresh_admission(&s);
}

static void test_genesis_receipt_faults_deny_admission(void) {
  run_genesis_receipt_fault_denies_admission(RECEIPT_BAD_SIGNATURE);
  run_genesis_receipt_fault_denies_admission(RECEIPT_BAD_UID);
  run_genesis_receipt_fault_denies_admission(RECEIPT_BAD_DOMAIN);
  run_genesis_receipt_fault_denies_admission(RECEIPT_BAD_PROFILE);
  run_genesis_receipt_fault_denies_admission(RECEIPT_BAD_TARGET);
  run_genesis_receipt_fault_denies_admission(RECEIPT_BAD_ROLE);
  run_genesis_receipt_fault_denies_admission(RECEIPT_BAD_BASELINE_HASH);
  run_genesis_receipt_fault_denies_admission(RECEIPT_BAD_BASELINE_EXTENT);
  run_genesis_receipt_fault_denies_admission(RECEIPT_BAD_SDK28);
  run_genesis_receipt_fault_denies_admission(RECEIPT_BAD_ACTIVATION_FLOOR);
}

/*
 * Genuine cross-language Ed25519 interop proof against a LITERAL shared
 * fixture (not a re-signed/re-derived roundtrip): this exact 386-byte
 * canonical record and 32-byte publisher public key are byte-identical
 * to Authority's own test/test_lora_ota_authority/test_lora_ota_authority.cpp
 * (BootFloorActivationReceiptCodecTest,
 * RealEd25519CrossLanguageInteropVectorVerifiesWithActualCrypto) and
 * scripts/tests/test_ota_authority_registry.py's mirrored
 * _INTEROP_RECORD_HEX/_INTEROP_PUBLISHER_PUBLIC_KEY_HEX -- independently
 * produced via Python/openssl (ephemeral, discarded test private key;
 * never committed/available here), already proven there to genuinely
 * verify under Authority's own C++ Ed25519 verifier and raw `openssl
 * pkeyutl -verify`. This test proves THIS bootloader's own production
 * digest construction (XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN (no NUL)
 * || body[0..322)) and its production ed25519_verify() independently
 * accept the identical bytes and key -- genuine cross-language/
 * cross-tool interop, no private key or re-signing involved on this
 * side. This is a pure codec/digest/verifier-layer test (not a genesis-
 * admission/boot-state-machine test): the fixture's UID/bindings/
 * fingerprint are Authority's illustrative interop values, not this
 * device's real identity, so it is never staged into fake QSPI floor
 * state and never exercises floor_genesis_receipt_matches()/policy
 * checks -- only the shared record layout + digest + raw signature
 * verification, exactly as requested.
 */
static const uint8_t kAuthorityInteropRecord[386] = {
    0x52, 0x41, 0x46, 0x58, 0x01, 0x00, 0x82, 0x01, 0x54, 0x4F, 0x4F, 0x42, 0xEF, 0xCD, 0xAB, 0x89,
    0x67, 0x45, 0x23, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
    0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
    0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
    0x3D, 0x3E, 0x3F, 0x40, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
    0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
    0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
    0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
    0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
    0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A,
    0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA,
    0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA,
    0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
    0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0x00, 0x00, 0x00, 0x00, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
    0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,
    0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0x00, 0x20, 0x00, 0x00, 0xF1, 0xF2,
    0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x89, 0x42,
    0x30, 0x86, 0xD8, 0xC2, 0xA9, 0x9B, 0x59, 0x25, 0xBC, 0x52, 0x4A, 0x27, 0xB6, 0x9B, 0xFA, 0x71,
    0xD3, 0x02, 0x4F, 0xD9, 0x9B, 0xC7, 0xD5, 0x8D, 0xB9, 0x50, 0x4B, 0x3E, 0xB0, 0x0A, 0xE0, 0x74,
    0xBE, 0x34, 0xB7, 0x5F, 0xD2, 0x44, 0x7C, 0x64, 0xD0, 0x49, 0x81, 0x8A, 0xC2, 0x7E, 0xDA, 0x24,
    0x89, 0x3B, 0x76, 0x21, 0x89, 0x9E, 0x66, 0xB3, 0xCE, 0xCE, 0x7E, 0x0B, 0x13, 0xB3, 0x10, 0x5A,
    0xAA, 0x0E,
};
static const uint8_t kAuthorityInteropPublisherPublicKey[32] = {
    0x10, 0x14, 0xCA, 0xE1, 0xB5, 0xCF, 0x78, 0xA5, 0x26, 0x35, 0x45, 0x25, 0x15, 0x65, 0x8B, 0x73,
    0x0A, 0xF5, 0x97, 0x99, 0xCA, 0x1B, 0x2C, 0x25, 0x0A, 0x63, 0x18, 0x52, 0xC8, 0x24, 0x40, 0x3B,
};

/* Builds SHA256(XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN (no NUL) ||
 * record[0..322)) -- this bootloader's exact production digest
 * construction (matches floor_activation_receipt_binds_floor() in
 * xiao_ota_boot_io.c byte for byte) -- from an arbitrary 386-byte
 * canonical record buffer. */
static void authority_interop_digest(const uint8_t record[386], uint8_t digest[32]) {
  uint8_t signing_buf[XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN_LEN +
                      XIAO_OTA_FLOOR_ACTIVATION_SIGNED_BODY_BYTES];
  memcpy(signing_buf, XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN,
        XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN_LEN);
  memcpy(signing_buf + XIAO_OTA_FLOOR_ACTIVATION_SIGNING_DOMAIN_LEN, record,
        XIAO_OTA_FLOOR_ACTIVATION_SIGNED_BODY_BYTES);
  sha256_of(signing_buf, sizeof(signing_buf), digest);
}

static void test_authority_literal_interop_vector_verifies_and_tamper_rejects(void) {
  uint8_t digest[32];

  /* Genuine positive: this bootloader's own production digest
   * construction + its own production ed25519_verify() accept the
   * literal, independently (Python/openssl)-produced fixture and key --
   * never a mocked/always-true check. (Note: this fixture's
   * key_fingerprint/UID/other body fields are Authority's illustrative
   * filler bytes for exercising the codec, not a real SHA-256(public
   * key) binding -- only the signature/digest/key triple is a genuine
   * cross-language cryptographic claim here.) */
  authority_interop_digest(kAuthorityInteropRecord, digest);
  assert(ed25519_verify(
            kAuthorityInteropRecord + XIAO_OTA_FLOOR_ACTIVATION_OFF_SIGNATURE_ED25519,
            digest, sizeof(digest), kAuthorityInteropPublisherPublicKey) != 0);

  /* Padding-ignored: an arbitrary 388-byte PHYSICAL (word-aligned QSPI
   * read) buffer, with non-0xFF garbage in the 2 trailing bytes that
   * are never part of the canonical/signed contract, must still verify
   * identically -- the digest is built strictly from record[0..322),
   * never the physical padding. */
  {
    uint8_t physical[XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES];
    uint8_t padded_digest[32];
    memcpy(physical, kAuthorityInteropRecord, 386);
    physical[386] = 0x5Au;
    physical[387] = 0xA5u;
    authority_interop_digest(physical, padded_digest);
    assert(memcmp(padded_digest, digest, 32) == 0);
    assert(ed25519_verify(
              physical + XIAO_OTA_FLOOR_ACTIVATION_OFF_SIGNATURE_ED25519,
              padded_digest, sizeof(padded_digest),
              kAuthorityInteropPublisherPublicKey) != 0);
  }

  /* Negative: flip one signed-body byte (offset 100, inside key_id --
   * well before the signature), then recompute the CRC32 field (offset
   * 318) the SAME way a real producer would so the record stays
   * internally CRC-consistent -- the recomputed SHA-256 digest still
   * differs from what was actually signed, so the ORIGINAL, untouched
   * signature must now genuinely fail cryptographic verification (not
   * merely fail a separate CRC check): proves this is a real
   * cryptographic accept/reject, not a CRC-gated stand-in. */
  {
    uint8_t tampered[386];
    uint8_t tampered_digest[32];
    uint32_t crc;
    memcpy(tampered, kAuthorityInteropRecord, sizeof(tampered));
    tampered[100] ^= 0x01u;
    crc = xiao_ota_crc32(tampered, XIAO_OTA_FLOOR_ACTIVATION_OFF_CRC32);
    tampered[318] = (uint8_t)(crc & 0xFFu);
    tampered[319] = (uint8_t)((crc >> 8) & 0xFFu);
    tampered[320] = (uint8_t)((crc >> 16) & 0xFFu);
    tampered[321] = (uint8_t)((crc >> 24) & 0xFFu);
    authority_interop_digest(tampered, tampered_digest);
    assert(memcmp(tampered_digest, digest, 32) != 0);
    assert(ed25519_verify(
              tampered + XIAO_OTA_FLOOR_ACTIVATION_OFF_SIGNATURE_ED25519,
              tampered_digest, sizeof(tampered_digest),
              kAuthorityInteropPublisherPublicKey) == 0);
  }

  /* Negative: signature-only tamper against the ORIGINAL, untouched
   * digest -- a single flipped signature byte must be rejected. */
  {
    uint8_t tampered_sig[64];
    memcpy(tampered_sig, kAuthorityInteropRecord +
                            XIAO_OTA_FLOOR_ACTIVATION_OFF_SIGNATURE_ED25519,
          64);
    tampered_sig[0] ^= 0x01u;
    assert(ed25519_verify(tampered_sig, digest, sizeof(digest),
                          kAuthorityInteropPublisherPublicKey) == 0);
  }

  /* Negative: wrong public key against the ORIGINAL, untouched
   * signature/digest -- a single flipped key byte must be rejected. */
  {
    uint8_t wrong_key[32];
    memcpy(wrong_key, kAuthorityInteropPublisherPublicKey, 32);
    wrong_key[0] ^= 0x01u;
    assert(ed25519_verify(
              kAuthorityInteropRecord + XIAO_OTA_FLOOR_ACTIVATION_OFF_SIGNATURE_ED25519,
              digest, sizeof(digest), wrong_key) == 0);
  }
}

/*
 * genesis_sdk28_baseline_ok()'s ACTIVE-transaction seam
 * (xiao_ota_boot_io.c): while an OTA transaction is actively in-flight
 * (TRIAL_BOOT here, before confirmation), the live settings page may
 * already legitimately differ from the true original baseline, so the
 * admission-time sidecar snapshot must be used instead -- but if THAT
 * snapshot itself does not hash-match the genesis receipt's signed
 * original_sdk28_digest (e.g. a torn/corrupted sidecar write, or one
 * belonging to a different device), the floor-0 genesis claim must be
 * denied exactly like any other tampered receipt field: no confirmation,
 * fail closed via rollback, never silently trusted from the live page
 * instead. Flips a BYTE OUTSIDE the bank-0 triad (app_image_size, offset
 * 20) so xiao_ota_boot_process_io()'s separate, narrower
 * bank0_triad_matches/sidecar_matches_state check still passes -- this
 * exercises the SDK28 digest seam specifically, not that unrelated
 * guard. */
static void test_active_transaction_sdk28_sidecar_mismatch_denies_confirm(void) {
  fake_io_state_t s;
  uint8_t old_hash[32], candidate_hash[32];
  xiao_ota_state_t state, state_a, state_b;
  xiao_ota_settings_sidecar_t sidecar;
  uint32_t sidecar_address;
  const uint32_t size = 8192;
  int attempt;

  fake_io_reset(&s);
  provision_old_image(&s, size, 0xE1, old_hash);
  write_candidate(&s, size, 0xE2, candidate_hash);
  build_and_write_command(&s, 1, 1, 1, size, candidate_hash, size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

  memcpy(&state_a, s.qspi + XIAO_OTA_STATE_A, sizeof(state_a));
  memcpy(&state_b, s.qspi + XIAO_OTA_STATE_B, sizeof(state_b));
  sidecar_address = (xiao_ota_state_valid(&state_a) &&
                    state_a.sequence == state.sequence)
                        ? XIAO_OTA_SETTINGS_SIDECAR_A
                        : XIAO_OTA_SETTINGS_SIDECAR_B;
  memcpy(&sidecar, s.qspi + sidecar_address, sizeof(sidecar));
  sidecar.original_settings_raw[20] ^= 0xFFu;
  sidecar.crc32 = xiao_ota_crc32(&sidecar, offsetof(xiao_ota_settings_sidecar_t, crc32));
  memcpy(s.qspi + sidecar_address, &sidecar, sizeof(sidecar));

  write_confirmation(&s, 1, 1, candidate_hash);
  for (attempt = 0; attempt < 4; ++attempt) {
    assert(fake_io_run_boot(&s) == 0);
    assert(read_state(&s, &state));
    assert(state.phase != XIAO_OTA_PHASE_CONFIRMED);
  }
  /* The original genesis floor must never have been overwritten by this
   * unauthenticated-baseline confirmation attempt. */
  {
    xiao_ota_floor_t floor;
    assert(read_floor(&s, &floor));
    assert(floor.confirmed_counter_floor == 0);
    assert(memcmp(floor.confirmed_hash_sha256, old_hash, 32) == 0);
  }
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
  /* This device is genesis-provisioned (provision_old_image()), so the
   * pre-existing genesis floor (counter 0) still durably exists in
   * whichever sibling slot persist_floor() did NOT target -- the failed
   * write only ever erases+fails ITS OWN target sector, never the
   * other. The confirmation must still never be honoured (no ADVANCED
   * floor was durably persisted), so the readable floor must remain
   * exactly the pre-confirmation genesis value, not the new counter. */
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
  /* Genesis-provisioned device: the pre-existing genesis floor (counter
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
                       current.bank_0_size, 0x1234u, 0x22222222u,
                       0x33333333u, 0x44444444u, 0x55555555u, custom_raw);
  }
  fake_io_write_settings_raw(&s, custom_raw);
  /* The genesis receipt provision_old_image() wrote captured the SDK28
   * digest of the STOCK settings raw, now superseded by custom_raw above
   * (this test's whole point is a custom-but-legitimate starting
   * settings page) -- re-provision so genesis verification binds the
   * settings page this device ACTUALLY has before its first ever boot,
   * exactly as a real factory-provisioning step would capture whatever
   * the device's true starting state is, not a stale earlier snapshot. */
  provision_genesis_receipt(&s, old_size, old_hash);
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
 * binding proof for STATE -- see state_ambiguous_binding_ok()'s
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
  /* write_floor_direct() wipes both physical receipt windows (it fully
   * blanks each slot's whole sector before writing the floor body) --
   * re-provision genesis role/identity evidence afterward, exactly as
   * persist_floor()'s real carry-forward would have kept available on
   * an actual device that genuinely advanced to floor 3 (see
   * floor_role_evidence_ok() in xiao_ota_boot_io.c). */
  provision_genesis_receipt(&s, 8192, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  assert(state.candidate_counter == 4);
}

/*
 * Sol/Astra HIGH finding regression: once a device's floor has genuinely
 * ADVANCED past 0 via the REAL persist_floor() carry-forward path (this
 * test uses the actual install/confirm flow, never write_floor_direct()),
 * the durable role evidence that carry-forward preserved must keep
 * gating EVERY later signed command, not merely genesis -- even a
 * structurally valid, correctly-signed, counter-advancing command for
 * the compiled role actually running, if the retained genesis receipt
 * now belongs to a DIFFERENT role. This is the exact attack described:
 * "replace ONLY the compiled loader binary, keep the same QSPI floor/
 * receipt records" -- role-evidence agreement is symmetric, so forcing
 * BOTH durable receipt windows to attest to the OTHER role (exactly
 * what RECEIPT_BAD_ROLE already always does: "1 - this binary's own
 * compiled role", never a hardcoded literal) is the equivalent, in-
 * process-testable mirror of that swap.
 */
static void test_cross_role_loader_swap_cannot_install_after_real_confirm(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t confirmed_hash[32];
  uint8_t attack_candidate_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  const uint32_t image_size = 65536;

  fake_io_reset(&s);
  provision_old_image(&s, image_size, 0xD1, old_hash);
  write_candidate(&s, image_size, 0xD2, confirmed_hash);
  build_and_write_command(&s, /*nonce=*/1, /*sequence=*/1, /*counter=*/1,
                          image_size, confirmed_hash, image_size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

  write_confirmation(&s, /*nonce=*/1, /*counter=*/1, confirmed_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 1);
  assert(floor.active_image_extent == image_size);
  assert(memcmp(floor.confirmed_hash_sha256, confirmed_hash, 32) == 0);

  /* Durable carry-forward proof: BOTH physical receipt windows must now
   * independently verify for THIS compiled role -- proving
   * persist_floor()'s carry-forward actually ran for real across a
   * genuine ping-pong advance, not merely that one slot happened to
   * still hold its original genesis copy untouched. */
  {
    xiao_ota_floor_activation_receipt_t ra, rb;
    memcpy(&ra, s.qspi + XIAO_OTA_FLOOR_ACTIVATION_A, sizeof(ra));
    memcpy(&rb, s.qspi + XIAO_OTA_FLOOR_ACTIVATION_B, sizeof(rb));
    assert(ra.magic == XIAO_OTA_FLOOR_ACTIVATION_MAGIC);
    assert(rb.magic == XIAO_OTA_FLOOR_ACTIVATION_MAGIC);
    assert(ra.current_role == XIAO_OTA_COMPILED_ROLE_ID);
    assert(rb.current_role == XIAO_OTA_COMPILED_ROLE_ID);
  }

  /* Simulate the loader swap: both durable receipt windows now attest to
   * the OTHER role only. */
  write_genesis_receipt_variant(&s, image_size, confirmed_hash, RECEIPT_BAD_ROLE);
  memcpy(s.qspi + XIAO_OTA_FLOOR_ACTIVATION_B,
        s.qspi + XIAO_OTA_FLOOR_ACTIVATION_A,
        XIAO_OTA_FLOOR_ACTIVATION_WINDOW_MAX_SIZE);

  /* A genuinely new, correctly-signed, counter-advancing command for THIS
   * compiled role must still be refused -- role continuity must hold at
   * every subsequent command, not just once at genesis. */
  write_candidate(&s, image_size, 0xD3, attack_candidate_hash);
  build_and_write_command(&s, /*nonce=*/2, /*sequence=*/2, /*counter=*/2,
                          image_size, attack_candidate_hash, image_size,
                          confirmed_hash);
  assert(fake_io_run_boot(&s) == 0);
  /* No new trial/confirmation must ever be admitted: the existing
   * CONFIRMED state and floor must survive completely untouched. */
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 1);
  assert(floor.active_image_extent == image_size);
  assert(memcmp(floor.confirmed_hash_sha256, confirmed_hash, 32) == 0);
  /* A role-evidence conflict at floor>0 must escalate to a terminal,
   * externally observable Recovery -- not merely a silent "command
   * refused, boot normally" outcome. */
  assert(s.force_recovery_calls == 1);
}

static const char *kColdRoleSwapDir = ".tmp/cold-role-swap-state";

static void cold_role_swap_ensure_dir(void) {
  if (mkdir(kColdRoleSwapDir, 0700) != 0 && errno != EEXIST) {
    fprintf(stderr, "could not create %s: %s\n", kColdRoleSwapDir,
            strerror(errno));
    abort();
  }
}

static void cold_role_swap_path(char *buffer, size_t size, int role) {
  int n = snprintf(buffer, size, "%s/role%d_genuine_floor1.bin",
                   kColdRoleSwapDir, role);
  assert(n > 0 && (size_t)n < size);
}

/*
 * LITERAL cold two-role harness, phase 1 of 2 (producer side).
 *
 * This compiled test binary's OWN role (XIAO_OTA_COMPILED_ROLE_ID, a
 * per-binary compile-time constant -- it cannot be flipped in-process)
 * genuinely commissions genesis and reaches a real CONFIRMED floor1 via
 * the actual install/confirm path (never write_floor_direct()/a hand-
 * built floor), then durably dumps the complete resulting simulated
 * QSPI+internal-flash image and physical device identity to a file
 * named by ITS OWN role. A SEPARATELY, differently-role-compiled test
 * binary (a distinct `make test-xiao-ota-boot-process
 * XIAO_OTA_ROLE_ID=<other>` invocation -- a fresh OS process, fresh
 * RAM, exactly like swapping only the loader binary on real hardware
 * and power-cycling) later reads this same file in
 * test_cold_two_binary_role_swap_refuses_other_role_dump() below. This
 * is what makes the resulting scenario a literal, not simulated, cold
 * two-role test: no single process ever holds two different compiled
 * xiao_ota_boot_io.c role identities at once.
 */
static void test_cold_two_binary_role_swap_produce_genesis_floor1_dump(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t confirmed_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  const uint32_t image_size = 65536;
  char path[256];

  fake_io_reset(&s);
  /* A fixed, shared physical identity both role-compiled binaries use --
   * this is what the real hw_uid-binding check in
   * floor_activation_receipt_identity_role_ok() requires to be IDENTICAL
   * across the swap (same physical device, only the loader changed). */
  s.device_address = UINT64_C(0xC01DC0FFEE0D1D1D);

  provision_old_image(&s, image_size, 0xB1, old_hash);
  write_candidate(&s, image_size, 0xB2, confirmed_hash);
  build_and_write_command(&s, /*nonce=*/1, /*sequence=*/1, /*counter=*/1,
                          image_size, confirmed_hash, image_size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

  write_confirmation(&s, /*nonce=*/1, /*counter=*/1, confirmed_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 1);
  assert(memcmp(floor.confirmed_hash_sha256, confirmed_hash, 32) == 0);

  cold_role_swap_ensure_dir();
  cold_role_swap_path(path, sizeof(path), XIAO_OTA_COMPILED_ROLE_ID);
  assert(fake_io_dump_to_file(&s, path));
}

/*
 * LITERAL cold two-role harness, phase 2 of 2 (consumer side).
 *
 * If a PRIOR, separate invocation of the OTHER role's test binary has
 * already produced its genesis-floor1 dump (see above), this compiled
 * binary -- genuinely built with the OTHER XIAO_OTA_COMPILED_ROLE_ID --
 * loads that exact byte-for-byte QSPI/internal-flash image (same
 * device_address, same floor/receipt history, every byte untouched: the
 * real "swap only the loader, keep the same QSPI chip" scenario) and
 * submits a genuinely signed, counter-advancing command FOR THIS
 * BINARY'S OWN compiled role. The durable floor/receipt history was
 * only ever genesis-certified for the OTHER role, so this must be
 * refused with a terminal Recovery escalation and, critically, must
 * leave every single durable byte (QSPI and internal flash) completely
 * unchanged -- not merely "the right counter/phase fields", the WHOLE
 * image, proving zero mutation occurred on the refusal path.
 *
 * If no such dump exists yet (e.g. this is the very first of the three
 * invocations needed -- role0 then role1 then role0 again, to cover
 * both directions -- in a fresh .tmp), this is reported and skipped
 * rather than failed, since a single `make test-xiao-ota-bootloader`
 * invocation only ever builds/runs ONE compiled role.
 */
static void test_cold_two_binary_role_swap_refuses_other_role_dump(void) {
  const int other_role = 1 - XIAO_OTA_COMPILED_ROLE_ID;
  char path[256];
  fake_io_state_t s;
  uint8_t before_qspi[FAKE_IO_QSPI_SIZE];
  uint8_t before_internal[FAKE_IO_INTERNAL_SIZE];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  uint8_t attack_hash[32];
  FILE *probe;

  cold_role_swap_path(path, sizeof(path), other_role);
  probe = fopen(path, "rb");
  if (!probe) {
    fprintf(stderr,
           "note: no role%d genuine genesis-floor1 dump present yet at "
           "%s -- run `make test-xiao-ota-boot-process "
           "XIAO_OTA_ROLE_ID=%d` (a separately compiled binary) first, "
           "then this role%d binary again, to exercise the literal cold "
           "two-role swap in this direction; skipping for now.\n",
           other_role, path, other_role, XIAO_OTA_COMPILED_ROLE_ID);
    return;
  }
  fclose(probe);

  assert(fake_io_load_from_file(&s, path));

  /* Sanity: the loaded image genuinely shows the OTHER role's own real
   * confirmed floor1, never anything already correct for THIS binary --
   * otherwise this would not be testing a role conflict at all. */
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 1);
  {
    xiao_ota_floor_activation_receipt_t ra, rb;
    memcpy(&ra, s.qspi + XIAO_OTA_FLOOR_ACTIVATION_A, sizeof(ra));
    memcpy(&rb, s.qspi + XIAO_OTA_FLOOR_ACTIVATION_B, sizeof(rb));
    assert(ra.current_role == (uint32_t)other_role);
    assert(rb.current_role == (uint32_t)other_role);
    assert(ra.current_role != (uint32_t)XIAO_OTA_COMPILED_ROLE_ID);
  }

  /* A genuinely signed, counter-advancing command for THIS compiled
   * role -- real production shape, not a tampered/bad-signature attack
   * -- must still be refused. Staging the candidate image + signed
   * command record here mirrors exactly what the real companion
   * firmware legitimately writes to flash BEFORE requesting a reboot
   * into the bootloader -- that write is not itself the thing under
   * test. The zero-mutation proof below is specifically about what
   * fake_io_run_boot() (the bootloader's OWN processing) may or may not
   * additionally touch once it decides to refuse; the snapshot is taken
   * immediately before that call, after staging. */
  write_candidate(&s, 65536, 0xB3, attack_hash);
  build_and_write_command(&s, /*nonce=*/2, /*sequence=*/2, /*counter=*/2,
                          65536, attack_hash, 65536, floor.confirmed_hash_sha256);
  memcpy(before_qspi, s.qspi, sizeof(before_qspi));
  memcpy(before_internal, s.internal_flash, sizeof(before_internal));

  assert(fake_io_run_boot(&s) == 0);

  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED); /* unchanged */
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 1); /* unchanged */
  assert(s.force_recovery_calls >= 1);

  /* Zero-mutation proof: not just the fields checked above, but every
   * durable byte the bootloader's OWN processing of this refused
   * command could have touched. */
  assert(memcmp(before_qspi, s.qspi, sizeof(before_qspi)) == 0);
  assert(memcmp(before_internal, s.internal_flash, sizeof(before_internal)) ==
        0);
}

/*
 * Ordinary same-role continuity must survive an arbitrary NUMBER of real
 * floor advances, not just one -- proving persist_floor()'s carry-forward
 * genuinely re-persists role evidence on every single ping-pong flip (A->
 * B->A->B->...), never merely "once, by accident of which slot happened
 * to still hold the original genesis copy".
 */
static void test_same_role_floor_survives_many_real_advances(void) {
  fake_io_state_t s;
  uint8_t active_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  const uint32_t image_size = 65536;
  const int advances = 6;
  int i;

  fake_io_reset(&s);
  provision_old_image(&s, image_size, 0xE1, active_hash);

  for (i = 0; i < advances; ++i) {
    uint32_t counter = (uint32_t)(i + 1);
    uint64_t nonce = (uint64_t)(i + 1);

    write_candidate(&s, image_size, (uint8_t)(0xF0u + i), candidate_hash);
    build_and_write_command(&s, nonce, /*sequence=*/nonce, counter, image_size,
                            candidate_hash, image_size, active_hash);
    assert(fake_io_run_boot(&s) == 0);
    assert(read_state(&s, &state));
    assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

    write_confirmation(&s, nonce, counter, candidate_hash);
    assert(fake_io_run_boot(&s) == 0);
    assert(read_state(&s, &state));
    assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
    assert(read_floor(&s, &floor));
    assert(floor.confirmed_counter_floor == counter);
    assert(floor.active_image_extent == image_size);
    assert(memcmp(floor.confirmed_hash_sha256, candidate_hash, 32) == 0);

    /* Durable role evidence must still independently verify in BOTH
     * physical windows after every single advance -- not just the
     * first one -- proving the carry-forward re-runs on every ping-
     * pong flip, not only once by accident. */
    {
      xiao_ota_floor_activation_receipt_t ra, rb;
      memcpy(&ra, s.qspi + XIAO_OTA_FLOOR_ACTIVATION_A, sizeof(ra));
      memcpy(&rb, s.qspi + XIAO_OTA_FLOOR_ACTIVATION_B, sizeof(rb));
      assert(ra.magic == XIAO_OTA_FLOOR_ACTIVATION_MAGIC);
      assert(rb.magic == XIAO_OTA_FLOOR_ACTIVATION_MAGIC);
      assert(ra.current_role == XIAO_OTA_COMPILED_ROLE_ID);
      assert(rb.current_role == XIAO_OTA_COMPILED_ROLE_ID);
    }

    memcpy(active_hash, candidate_hash, 32);
  }

  assert(s.force_recovery_calls == 0);
}

/*
 * Builds the LEGACY "sole surviving genesis receipt lives in the NEXT
 * erase target" fixture required by the durable-role HIGH-fix contract:
 * a real, committed floor1 physically resides in slot B (this
 * fixture's chosen "current winner"/persist_floor() SOURCE -- never
 * erased by the following advance), carrying NO valid receipt of its
 * own, while the device's sole surviving signed genesis receipt lives
 * in slot A -- persist_floor()'s next erase TARGET. This is
 * deliberately fabricated directly (never via a real multi-advance
 * install/confirm sequence, which would already carry the receipt into
 * both windows via steady-state carry-forward) to exercise exactly the
 * legacy/transitional case the contract calls out: floor1 reached
 * before this repair logic existed, or a first-ever advance away from
 * genesis whose carry-forward copy never durably landed in the source
 * slot. The app image + matching bank-0 settings are genuinely
 * provisioned (fake_io_run_boot()'s own later install/confirm calls
 * depend on them matching `hash`), but NO state record exists yet --
 * exactly provision_old_image()'s own "idle, no pending transaction"
 * shape, just at floor1 instead of floor0.
 */
static void provision_legacy_floor1_with_sole_receipt_in_next_erase_target(
    fake_io_state_t *s, uint32_t size, const uint8_t hash[32]) {
  xiao_ota_floor_t floor;

  memset(s->qspi + XIAO_OTA_FLOOR_A, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memset(s->qspi + XIAO_OTA_FLOOR_B, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);

  memset(&floor, 0, sizeof(floor));
  floor.magic = XIAO_OTA_FLOOR_MAGIC;
  floor.record_version = XIAO_OTA_FORMAT_VERSION;
  floor.record_bytes = sizeof(floor);
  floor.sequence = 1;
  floor.confirmed_counter_floor = 1;
  floor.active_image_extent = size;
  memcpy(floor.confirmed_hash_sha256, hash, 32);
  floor.crc32 = xiao_ota_crc32(&floor, offsetof(xiao_ota_floor_t, crc32));
  floor.commit_marker = XIAO_OTA_COMMIT_MARKER;
  memcpy(s->qspi + XIAO_OTA_FLOOR_B, &floor, sizeof(floor));

  /* Writes a genuinely signed, identity/role-verifying genesis receipt
   * into slot A's window ONLY (XIAO_OTA_FLOOR_ACTIVATION_A), leaving
   * slot A's own floor BODY area untouched (blank, from the memset
   * above) and slot B's receipt window untouched (blank) -- the exact
   * "sole surviving copy, in the OTHER slot" shape. */
  write_genesis_receipt_variant(s, size, hash, RECEIPT_OK);
}

/*
 * No-fault control case: proves the legacy fixture above genuinely
 * reaches a real, successful same-role advance (floor1 -> floor2) via
 * the actual confirm path, with persist_floor()'s propagate-before-
 * erase durability logic completing cleanly and the ORIGINAL receipt's
 * exact signed bytes (not a re-derived/re-signed copy) ending up
 * present in BOTH physical windows afterward.
 */
static void test_legacy_floor1_sole_receipt_in_next_erase_target_advances_cleanly(void) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  xiao_ota_floor_activation_receipt_t original_receipt, final_a, final_b;
  const uint32_t size = 24576;

  fake_io_reset(&s);
  provision_old_image_no_genesis_receipt(&s, size, 0x9A, old_hash);
  provision_legacy_floor1_with_sole_receipt_in_next_erase_target(&s, size,
                                                                 old_hash);
  memcpy(&original_receipt, s.qspi + XIAO_OTA_FLOOR_ACTIVATION_A,
        sizeof(original_receipt));

  write_candidate(&s, size, 0x9B, candidate_hash);
  build_and_write_command(&s, /*nonce=*/301, /*sequence=*/1, /*counter=*/2,
                          size, candidate_hash, size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);

  write_confirmation(&s, /*nonce=*/301, /*counter=*/2, candidate_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(s.force_recovery_calls == 0);

  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 2);
  assert(memcmp(floor.confirmed_hash_sha256, candidate_hash, 32) == 0);

  memcpy(&final_a, s.qspi + XIAO_OTA_FLOOR_ACTIVATION_A, sizeof(final_a));
  memcpy(&final_b, s.qspi + XIAO_OTA_FLOOR_ACTIVATION_B, sizeof(final_b));
  /* Both windows now hold the IDENTICAL, ORIGINAL signed bytes -- never
   * a re-signed/re-derived receipt (this binary never has a signing
   * key; durability here can only ever mean "copy the exact bytes"). */
  assert(memcmp(&final_a, &original_receipt, sizeof(original_receipt)) == 0);
  assert(memcmp(&final_b, &original_receipt, sizeof(original_receipt)) == 0);
}

typedef enum {
  LEGACY_CUT_PROPAGATE_WRITE_CRASH,
  LEGACY_CUT_PROPAGATE_WRITE_TORN,
  LEGACY_CUT_AFTER_ERASE_BEFORE_RECEIPT,
  LEGACY_CUT_AFTER_RECEIPT_BEFORE_BODY,
} legacy_cut_point_t;

/*
 * The actual physical cut-point matrix the durable-role HIGH-fix
 * contract requires: every one of persist_floor()'s own survivor-copy-
 * before-erase steps, interrupted at the moment right before its
 * durable effect would land, for the EXACT legacy "sole receipt in the
 * next erase target" fixture above (the single most dangerous ordering,
 * since the next erase would otherwise destroy the device's only
 * remaining lifetime-role proof). Every variant asserts: (1) the
 * surviving evidence is never lost regardless of where the cut lands,
 * (2) a subsequent un-faulted retry converges to the IDENTICAL final
 * state as the clean-path test above (same counter, same original
 * signed receipt bytes byte-for-byte in both windows), and (3) no
 * phantom floor/state advance is ever observable from the cut call
 * itself (either the whole confirm visibly didn't happen yet, or it is
 * safely re-attemptable with zero information loss).
 */
static void run_legacy_sole_receipt_advance_cut(legacy_cut_point_t cut) {
  fake_io_state_t s;
  uint8_t old_hash[32];
  uint8_t candidate_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  xiao_ota_floor_activation_receipt_t original_receipt, final_a, final_b;
  const uint32_t size = 20480;

  fake_io_reset(&s);
  provision_old_image_no_genesis_receipt(&s, size, 0xAC, old_hash);
  provision_legacy_floor1_with_sole_receipt_in_next_erase_target(&s, size,
                                                                 old_hash);
  memcpy(&original_receipt, s.qspi + XIAO_OTA_FLOOR_ACTIVATION_A,
        sizeof(original_receipt));

  write_candidate(&s, size, 0xAD, candidate_hash);
  build_and_write_command(&s, /*nonce=*/401, /*sequence=*/1, /*counter=*/2,
                          size, candidate_hash, size, old_hash);
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
  write_confirmation(&s, /*nonce=*/401, /*counter=*/2, candidate_hash);

  switch (cut) {
    case LEGACY_CUT_PROPAGATE_WRITE_CRASH:
      /* The very first write to B's (source's) own window this call --
       * i.e. the propagate write itself -- never takes effect. */
      s.crash.op = FAKE_IO_OP_QSPI_WRITE;
      s.crash.addr_lo = XIAO_OTA_FLOOR_ACTIVATION_B;
      s.crash.addr_hi =
          XIAO_OTA_FLOOR_ACTIVATION_B + XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES;
      s.crash.after = 1;
      assert(fake_io_run_boot(&s) == 1);
      s.crash.op = FAKE_IO_OP_NONE;
      s.crash.after = -1;

      /* Target (A, never touched this call) is untouched; source (B)
       * never received any bytes (crash fired before the write's
       * effect); the confirm transaction visibly never happened. */
      assert(memcmp(s.qspi + XIAO_OTA_FLOOR_ACTIVATION_A, &original_receipt,
                   sizeof(original_receipt)) == 0);
      {
        uint8_t blank_window[sizeof(original_receipt)];
        memset(blank_window, 0xFF, sizeof(blank_window));
        assert(memcmp(s.qspi + XIAO_OTA_FLOOR_ACTIVATION_B, blank_window,
                     sizeof(blank_window)) == 0);
      }
      assert(read_floor(&s, &floor));
      assert(floor.confirmed_counter_floor == 1);
      assert(read_state(&s, &state));
      assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
      break;

    case LEGACY_CUT_PROPAGATE_WRITE_TORN:
      /* The propagate write lands only partially (first 96 of 388
       * bytes) -- a genuine torn/interrupted-but-not-crashed write, the
       * device stays running and observes the failure within this
       * same call. The partially-landed prefix is a true PREFIX of the
       * real target bytes (never garbage), so a later exact-byte retry
       * is NOR-compatible (no bit needs to flip 1, only 0s over
       * already-0s or 0s over still-blank 0xFF). */
      s.tear.op = FAKE_IO_OP_QSPI_WRITE;
      s.tear.addr_lo = XIAO_OTA_FLOOR_ACTIVATION_B;
      s.tear.addr_hi =
          XIAO_OTA_FLOOR_ACTIVATION_B + XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES;
      s.tear.after = 1;
      s.tear_bytes = 96;
      assert(fake_io_run_boot(&s) == 0);
      s.tear.op = FAKE_IO_OP_NONE;
      s.tear.after = -1;
      s.tear_bytes = 0;

      assert(s.force_recovery_calls == 1);
      assert(memcmp(s.qspi + XIAO_OTA_FLOOR_ACTIVATION_A, &original_receipt,
                   sizeof(original_receipt)) == 0);
      /* Source's first 96 bytes already match the real target content
       * (that's what "torn" means here); the call never reached a
       * floor/state advance. */
      assert(memcmp(s.qspi + XIAO_OTA_FLOOR_ACTIVATION_B, &original_receipt,
                   96) == 0);
      assert(read_floor(&s, &floor));
      assert(floor.confirmed_counter_floor == 1);
      assert(read_state(&s, &state));
      assert(state.phase == XIAO_OTA_PHASE_TRIAL_BOOT);
      break;

    case LEGACY_CUT_AFTER_ERASE_BEFORE_RECEIPT:
      /* Propagate+readback into B (source) already durably completed
       * earlier in THIS SAME call (uncrashed); target (A) has already
       * been erased (uncrashed, a different op). The very first write
       * into target's OWN window afterward -- re-publishing its receipt
       * copy -- never takes effect: this is the single most dangerous
       * instant, since A (the device's ORIGINAL copy) is now blank. */
      s.crash.op = FAKE_IO_OP_QSPI_WRITE;
      s.crash.addr_lo = XIAO_OTA_FLOOR_ACTIVATION_A;
      s.crash.addr_hi =
          XIAO_OTA_FLOOR_ACTIVATION_A + XIAO_OTA_FLOOR_ACTIVATION_PHYSICAL_BYTES;
      s.crash.after = 1;
      assert(fake_io_run_boot(&s) == 1);
      s.crash.op = FAKE_IO_OP_NONE;
      s.crash.after = -1;

      /* A is now genuinely blank (erased, receipt write never landed)
       * -- the sole surviving durable copy is in B, already confirmed
       * BEFORE the erase in this same call ever ran. */
      assert(memcmp(s.qspi + XIAO_OTA_FLOOR_ACTIVATION_B, &original_receipt,
                   sizeof(original_receipt)) == 0);
      assert(read_floor(&s, &floor));
      assert(floor.confirmed_counter_floor == 1); /* A not yet committed */
      break;

    case LEGACY_CUT_AFTER_RECEIPT_BEFORE_BODY:
      /* Receipt already durably re-published+read-back into target (A)
       * this call (uncrashed); the floor BODY write into target
       * (distinct address range, offset 0 vs the window's +0x100)
       * never takes effect. */
      s.crash.op = FAKE_IO_OP_QSPI_WRITE;
      s.crash.addr_lo = XIAO_OTA_FLOOR_A;
      s.crash.addr_hi = XIAO_OTA_FLOOR_A + offsetof(xiao_ota_floor_t, commit_marker);
      s.crash.after = 1;
      assert(fake_io_run_boot(&s) == 1);
      s.crash.op = FAKE_IO_OP_NONE;
      s.crash.after = -1;

      /* Both windows already independently hold the receipt (A from
       * this call's own re-publish, B from this call's own earlier
       * propagate) -- no evidence lost either way -- but A's floor BODY
       * never landed, so it is correctly still invalid/blank and B (at
       * counter 1, untouched) remains the sole trusted floor. */
      assert(memcmp(s.qspi + XIAO_OTA_FLOOR_ACTIVATION_A, &original_receipt,
                   sizeof(original_receipt)) == 0);
      assert(memcmp(s.qspi + XIAO_OTA_FLOOR_ACTIVATION_B, &original_receipt,
                   sizeof(original_receipt)) == 0);
      assert(read_floor(&s, &floor));
      assert(floor.confirmed_counter_floor == 1);
      break;
  }

  /* Clean, un-faulted retry must converge to the EXACT same final state
   * as the no-fault control test, regardless of which exact instant was
   * cut: the original signed receipt bytes, byte-for-byte, in BOTH
   * windows, and the floor genuinely advanced to counter 2. */
  assert(fake_io_run_boot(&s) == 0);
  assert(read_state(&s, &state));
  assert(state.phase == XIAO_OTA_PHASE_CONFIRMED);
  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 2);
  assert(memcmp(floor.confirmed_hash_sha256, candidate_hash, 32) == 0);

  memcpy(&final_a, s.qspi + XIAO_OTA_FLOOR_ACTIVATION_A, sizeof(final_a));
  memcpy(&final_b, s.qspi + XIAO_OTA_FLOOR_ACTIVATION_B, sizeof(final_b));
  assert(memcmp(&final_a, &original_receipt, sizeof(original_receipt)) == 0);
  assert(memcmp(&final_b, &original_receipt, sizeof(original_receipt)) == 0);
}

static void test_legacy_sole_receipt_propagate_write_crash_resumes(void) {
  run_legacy_sole_receipt_advance_cut(LEGACY_CUT_PROPAGATE_WRITE_CRASH);
}

static void test_legacy_sole_receipt_propagate_write_torn_resumes(void) {
  run_legacy_sole_receipt_advance_cut(LEGACY_CUT_PROPAGATE_WRITE_TORN);
}

static void test_legacy_sole_receipt_erase_before_receipt_crash_resumes(void) {
  run_legacy_sole_receipt_advance_cut(LEGACY_CUT_AFTER_ERASE_BEFORE_RECEIPT);
}

static void test_legacy_sole_receipt_receipt_before_body_crash_resumes(void) {
  run_legacy_sole_receipt_advance_cut(LEGACY_CUT_AFTER_RECEIPT_BEFORE_BODY);
}

/*
 * TWO INDEPENDENTLY VALID, CONFLICTING GENESIS RECEIPTS, SAME DEVICE/ROLE:
 * fabricates a receipt in window A that is genuinely bound to the
 * currently-committed floor1 (real baseline for THIS device's actual
 * history), and a SECOND, separately and genuinely signed receipt in
 * window B that independently passes every identity/role/signature
 * check (same device hw_uid, same compiled role, same trust-anchor
 * key) but certifies a DIFFERENT baseline (distinct extent/hash) --
 * i.e. a second, distinct, validly-signed genesis authorization for
 * this exact device/role that was never the one actually used for its
 * real history. This is the "two independently valid receipts ... with
 * conflicting lifetime provenance" case the durable-role contract
 * explicitly calls out: identity_role_ok() alone (used by
 * floor_role_evidence_ok() for the ANY-floor gate) does not compare
 * baseline_hash_sha256/baseline_extent across windows, so both A and B
 * currently satisfy it despite disagreeing on which genesis image was
 * ever genuinely activated. This test asserts the REQUIRED behaviour
 * (reject/Recovery on conflicting provenance, never silently pick
 * whichever one happens to verify) and documents a FAIL here as an
 * open contract gap for Root, not a false green.
 */
static void test_two_conflicting_valid_genesis_receipts_same_role(void) {
  fake_io_state_t s;
  uint8_t hash_a[32];
  uint8_t hash_b_unused[32];
  uint8_t candidate_hash[32];
  xiao_ota_floor_t floor;
  const uint32_t size_a = 16384;
  const uint32_t size_b = 24576; /* deliberately different "other genesis" */

  fake_io_reset(&s);
  provision_old_image_no_genesis_receipt(&s, size_a, 0xD1, hash_a);

  /* Real, committed floor1 for THIS device's actual history, matching
   * receipt A below. */
  memset(s.qspi + XIAO_OTA_FLOOR_A, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memset(s.qspi + XIAO_OTA_FLOOR_B, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memset(&floor, 0, sizeof(floor));
  floor.magic = XIAO_OTA_FLOOR_MAGIC;
  floor.record_version = XIAO_OTA_FORMAT_VERSION;
  floor.record_bytes = sizeof(floor);
  floor.sequence = 1;
  floor.confirmed_counter_floor = 1;
  floor.active_image_extent = size_a;
  memcpy(floor.confirmed_hash_sha256, hash_a, 32);
  floor.crc32 = xiao_ota_crc32(&floor, offsetof(xiao_ota_floor_t, crc32));
  floor.commit_marker = XIAO_OTA_COMMIT_MARKER;
  memcpy(s.qspi + XIAO_OTA_FLOOR_A, &floor, sizeof(floor));

  /* Window A: genuinely bound to the real, committed floor above. */
  write_genesis_receipt_variant_at(&s, XIAO_OTA_FLOOR_ACTIVATION_A, size_a,
                                   hash_a, RECEIPT_OK);
  /* Window B: a SECOND, independently valid (same device/role/key,
   * passes identity_role_ok) signed genesis receipt, but for an
   * entirely different baseline image that was never this device's
   * real history. hash_b_unused's content doesn't matter beyond being
   * distinct from hash_a; the sdk28 digest is still computed fresh
   * against the live settings page inside the helper, same as window A,
   * since neither genesis floor's receipt controls that independently. */
  memset(hash_b_unused, 0xEE, sizeof(hash_b_unused));
  write_genesis_receipt_variant_at(&s, XIAO_OTA_FLOOR_ACTIVATION_B, size_b,
                                   hash_b_unused, RECEIPT_OK);

  /* Attempt a genuine same-role advance (floor1 -> floor2). */
  write_candidate(&s, size_a, 0xD2, candidate_hash);
  build_and_write_command(&s, /*nonce=*/501, /*sequence=*/1, /*counter=*/2,
                          size_a, candidate_hash, size_a, hash_a);
  (void)fake_io_run_boot(&s);
  write_confirmation(&s, /*nonce=*/501, /*counter=*/2, candidate_hash);
  (void)fake_io_run_boot(&s);

  assert(read_floor(&s, &floor));
  /* REQUIRED: conflicting provenance must never be silently resolved by
   * picking whichever window happens to verify -- the advance must be
   * refused (floor stays at 1, never reaches 2) and the device must
   * enter Recovery rather than quietly trusting window A over B (or
   * vice versa) with zero cross-window consistency check. */
  assert(floor.confirmed_counter_floor == 1);
  assert(s.force_recovery_calls > 0);
}

/*
 * GF(2) linear-algebra helper: finds a 32-bit `patch` such that XOR-ing
 * together the subset of `elems[i]` selected by patch's set bits equals
 * `target`, via a standard linear-basis reduction (each elems[i] is
 * treated as a vector over GF(2); this is the same technique used to
 * decide "subset xor == target" problems). Used immediately below to
 * construct a genuine CRC32 COLLISION between two otherwise-different
 * signed receipts -- proving the production fix compares actual
 * receipt bytes, not merely the (collidable) 32-bit CRC. Returns false
 * only if target is not in the span of elems (not expected here, since
 * flipping 32 independent bits of a fixed-width CRC32 input reliably
 * yields a full-rank set of deltas).
 */
static bool gf2_find_xor_subset(const uint32_t elems[32], uint32_t target,
                                uint32_t *out_mask) {
  uint32_t basis_vec[32];
  uint32_t basis_mask[32];
  bool basis_used[32] = {0};
  uint32_t cur, cur_mask;
  int i, b;

  for (i = 0; i < 32; ++i) {
    cur = elems[i];
    cur_mask = (1u << i);
    for (b = 31; b >= 0; --b) {
      if (!((cur >> b) & 1u)) continue;
      if (!basis_used[b]) {
        basis_vec[b] = cur;
        basis_mask[b] = cur_mask;
        basis_used[b] = true;
        break;
      }
      cur ^= basis_vec[b];
      cur_mask ^= basis_mask[b];
    }
  }

  cur = target;
  cur_mask = 0;
  for (b = 31; b >= 0; --b) {
    if (!((cur >> b) & 1u)) continue;
    if (!basis_used[b]) return false;
    cur ^= basis_vec[b];
    cur_mask ^= basis_mask[b];
  }
  if (cur != 0u) return false;
  *out_mask = cur_mask;
  return true;
}

/*
 * SAME-CRC, DIFFERENT VALID SIGNED RECEIPTS (deliberate CRC32
 * collision): constructs window A's receipt normally, then uses
 * gf2_find_xor_subset() to find a `host_txn_id` patch value for window
 * B's receipt (a DIFFERENT baseline image -- different extent/hash,
 * i.e. genuinely different signed content) such that B's crc32 field
 * is made to EXACTLY EQUAL A's crc32, by construction -- not by luck.
 * Both receipts are independently, genuinely Ed25519-signed over their
 * own actual (different) content; only their crc32 fields coincide.
 * This proves the earlier CRC32-equality approach would have wrongly
 * treated these as "the same provenance" and let the advance through,
 * while the current byte-exact comparison correctly still refuses it.
 */
static void test_two_valid_receipts_same_crc32_different_content_still_conflicts(void) {
  fake_io_state_t s;
  uint8_t hash_a[32];
  uint8_t hash_b[32];
  uint8_t candidate_hash[32];
  xiao_ota_floor_t floor;
  xiao_ota_floor_activation_receipt_t ra, rb_probe;
  const uint32_t size_a = 12288;
  const uint32_t size_b = 28672;
  uint32_t crc_target;
  uint32_t elems[32];
  uint32_t crc_base;
  uint32_t diff;
  uint32_t patch_mask = 0;
  int i;

  fake_io_reset(&s);
  provision_old_image_no_genesis_receipt(&s, size_a, 0xF1, hash_a);
  memset(hash_b, 0xF2, sizeof(hash_b));

  memset(s.qspi + XIAO_OTA_FLOOR_A, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memset(s.qspi + XIAO_OTA_FLOOR_B, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  memset(&floor, 0, sizeof(floor));
  floor.magic = XIAO_OTA_FLOOR_MAGIC;
  floor.record_version = XIAO_OTA_FORMAT_VERSION;
  floor.record_bytes = sizeof(floor);
  floor.sequence = 1;
  floor.confirmed_counter_floor = 1;
  floor.active_image_extent = size_a;
  memcpy(floor.confirmed_hash_sha256, hash_a, 32);
  floor.crc32 = xiao_ota_crc32(&floor, offsetof(xiao_ota_floor_t, crc32));
  floor.commit_marker = XIAO_OTA_COMMIT_MARKER;
  memcpy(s.qspi + XIAO_OTA_FLOOR_A, &floor, sizeof(floor));

  /* Window A: real receipt, default patch. */
  build_genesis_receipt_fields(&ra, &s, size_a, hash_a, 0x33333333u,
                              RECEIPT_OK);
  crc_target = ra.crc32;
  sign_and_write_genesis_receipt_at(&s, XIAO_OTA_FLOOR_ACTIVATION_A, &ra,
                                    RECEIPT_OK);

  /* Measure the CRC32 delta contributed by each of the 32 bits of the
   * free host_txn_id-based patch, holding window B's OWN (different)
   * baseline fixed, so the solved patch is valid specifically for B's
   * actual content. */
  build_genesis_receipt_fields(&rb_probe, &s, size_b, hash_b, 0u, RECEIPT_OK);
  crc_base = rb_probe.crc32;
  for (i = 0; i < 32; ++i) {
    build_genesis_receipt_fields(&rb_probe, &s, size_b, hash_b,
                                (1u << i), RECEIPT_OK);
    elems[i] = rb_probe.crc32 ^ crc_base;
  }
  diff = crc_base ^ crc_target;
  assert(gf2_find_xor_subset(elems, diff, &patch_mask));

  build_genesis_receipt_fields(&rb_probe, &s, size_b, hash_b, patch_mask,
                              RECEIPT_OK);
  /* Sanity: the collision was genuinely constructed, not coincidental --
   * B's crc32 now exactly equals A's, while B's actual signed content
   * (baseline_extent/baseline_hash_sha256) is still genuinely different
   * from A's. */
  assert(rb_probe.crc32 == crc_target);
  assert(rb_probe.baseline_extent != ra.baseline_extent);
  assert(memcmp(rb_probe.baseline_hash_sha256, ra.baseline_hash_sha256, 32) != 0);
  sign_and_write_genesis_receipt_at(&s, XIAO_OTA_FLOOR_ACTIVATION_B, &rb_probe,
                                    RECEIPT_OK);

  /* Attempt a genuine same-role advance (floor1 -> floor2): must still
   * be refused, exactly like the different-CRC conflict case, even
   * though a CRC32-only comparison would have wrongly accepted this
   * pair as "the same provenance". */
  write_candidate(&s, size_a, 0xF3, candidate_hash);
  build_and_write_command(&s, /*nonce=*/601, /*sequence=*/1, /*counter=*/2,
                          size_a, candidate_hash, size_a, hash_a);
  (void)fake_io_run_boot(&s);
  write_confirmation(&s, /*nonce=*/601, /*counter=*/2, candidate_hash);
  (void)fake_io_run_boot(&s);

  assert(read_floor(&s, &floor));
  assert(floor.confirmed_counter_floor == 1);
  assert(s.force_recovery_calls > 0);
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
  provision_genesis_receipt(&s, size, old_hash); /* carry-forward re-established after write_floor_direct() wipes the window */
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
  provision_genesis_receipt(&s, size, old_hash); /* carry-forward re-established after write_floor_direct() wipes the window */
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
 * the CONFIRMED state's candidate_counter (7) -- conflicting proof: the
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
  provision_old_image_no_genesis_receipt(&s, size, 0xD3, old_hash);

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
   * slot's real 8 -- proof enough to repair from if the surviving slot
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

int main(void) {
  crypto_sign_keypair(xiao_ota_test_public_key_ed25519, g_test_secret_key);

  test_partial_state_marker_conservatively_burns_possible_retry();
  printf("partial state marker conservatively burns possible retry passed\n");
  test_genesis_pre_body_cut_never_admits();
  printf("genesis pre-body cut never admits passed\n");
  test_genesis_post_body_pre_receipt_cut_never_admits();
  printf("genesis post-body/pre-receipt cut never admits passed\n");
  test_genesis_post_receipt_pre_marker_cut_never_admits();
  printf("genesis post-receipt/pre-marker cut never admits passed\n");
  test_genesis_receipt_faults_deny_admission();
  printf("genesis receipt faults deny admission passed\n");
  test_authority_literal_interop_vector_verifies_and_tamper_rejects();
  printf("authority literal interop vector verifies and tamper-rejects passed\n");
  test_active_transaction_sdk28_sidecar_mismatch_denies_confirm();
  printf("active-transaction SDK28 sidecar mismatch denies confirm passed\n");
  test_prepared_sidecar_retains_committed_state_pair();
  printf("prepared sidecar retains committed state pair passed\n");
  test_resize_confirm(320u * 1024u, 500u * 1024u);
  printf("resize confirm 320K->500K passed\n");
  test_resize_confirm(500u * 1024u, 320u * 1024u);
  printf("resize confirm 500K->320K passed\n");
  test_failed_retry_then_new_nonce();
  printf("failed-retry / new-nonce passed\n");
  test_crash_mid_install_then_rollback();
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
  test_cross_role_loader_swap_cannot_install_after_real_confirm();
  printf("cross-role loader swap cannot install after real confirm passed\n");
  test_cold_two_binary_role_swap_produce_genesis_floor1_dump();
  printf("cold two-binary role swap genesis-floor1 dump produced passed\n");
  test_cold_two_binary_role_swap_refuses_other_role_dump();
  printf("cold two-binary role swap refuses other role dump passed\n");
  test_same_role_floor_survives_many_real_advances();
  printf("same-role floor survives many real advances passed\n");
  test_legacy_floor1_sole_receipt_in_next_erase_target_advances_cleanly();
  printf("legacy floor1 sole receipt in next erase target advances cleanly passed\n");
  test_legacy_sole_receipt_propagate_write_crash_resumes();
  printf("legacy sole receipt propagate write crash resumes passed\n");
  test_legacy_sole_receipt_propagate_write_torn_resumes();
  printf("legacy sole receipt propagate write torn resumes passed\n");
  test_legacy_sole_receipt_erase_before_receipt_crash_resumes();
  printf("legacy sole receipt erase before receipt crash resumes passed\n");
  test_legacy_sole_receipt_receipt_before_body_crash_resumes();
  printf("legacy sole receipt receipt before body crash resumes passed\n");
  test_two_conflicting_valid_genesis_receipts_same_role();
  printf("two conflicting valid genesis receipts same role passed\n");
  test_two_valid_receipts_same_crc32_different_content_still_conflicts();
  printf("two valid receipts same crc32 different content still conflicts passed\n");
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

  printf("publication erase-crash (active retry) resumes passed\n");
  test_signed_zero_crc_candidate_installs_confirms_and_resolves_next_boot();
  printf("signed zero-CRC candidate installs/confirms/resolves next boot passed\n");
  test_stored_zero_crc_no_longer_matches_recomputed_nonzero_refuses();
  printf("stored zero CRC no longer matches recomputed nonzero refuses passed\n");

  printf("xiao OTA boot process integration tests passed\n");
  return 0;
}
