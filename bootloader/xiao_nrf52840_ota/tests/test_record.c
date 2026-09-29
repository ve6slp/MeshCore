#include "xiao_ota_record.h"
#include "xiao_ota_sha256.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void commit_state(xiao_ota_state_t *s) {
  s->magic = XIAO_OTA_RECORD_MAGIC;
  s->record_version = XIAO_OTA_FORMAT_VERSION;
  s->record_bytes = sizeof(*s);
  s->crc32 = xiao_ota_crc32(s, offsetof(xiao_ota_state_t, crc32));
  s->commit_marker = XIAO_OTA_COMMIT_MARKER;
}

static void commit_confirmation(xiao_ota_confirmation_t *c) {
  c->magic = XIAO_OTA_CONFIRM_MAGIC;
  c->record_version = XIAO_OTA_FORMAT_VERSION;
  c->record_bytes = sizeof(*c);
  c->crc32 = xiao_ota_crc32(c, offsetof(xiao_ota_confirmation_t, crc32));
  c->commit_marker = XIAO_OTA_COMMIT_MARKER;
}

int main(void) {
  xiao_ota_state_t a;
  xiao_ota_state_t b;
  xiao_ota_confirmation_t confirmation;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));
  memset(&confirmation, 0, sizeof(confirmation));
  assert(sizeof(xiao_ota_canonical_descriptor_t) == 71);
  assert(sizeof(xiao_ota_command_t) == 200);
  assert(sizeof(xiao_ota_state_t) == 152);
  assert((sizeof(xiao_ota_state_t) & 3u) == 0);
  assert(xiao_ota_explicit_dfu_requested(XIAO_OTA_DFU_MAGIC_UF2));
  assert(xiao_ota_explicit_dfu_requested(XIAO_OTA_DFU_MAGIC_SERIAL));
  assert(xiao_ota_explicit_dfu_requested(XIAO_OTA_DFU_MAGIC_OTA_RESET));
  assert(xiao_ota_explicit_dfu_requested(XIAO_OTA_DFU_MAGIC_OTA_APPJUM));
  assert(!xiao_ota_explicit_dfu_requested(0));
  assert(xiao_ota_safe_backup_extent(0, 0xC6000) == 0xC6000);
  assert(xiao_ota_safe_backup_extent(0xC7000, 0xC6000) == 0xC6000);
  assert(xiao_ota_safe_backup_extent(0x12345, 0xC6000) == 0x12348);
  assert(xiao_ota_safe_backup_extent(0xC5FFF, 0xC6000) == 0xC6000);
  {
    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    uint8_t digest[32];
    xiao_ota_sha256_t sha;
    xiao_ota_sha256_init(&sha);
    xiao_ota_sha256_update(&sha, "abc", 3);
    xiao_ota_sha256_final(&sha, digest);
    assert(memcmp(digest, expected, sizeof(digest)) == 0);
  }

  a.sequence = 7;
  a.phase = XIAO_OTA_PHASE_BACKUP_COPYING;
  commit_state(&a);
  assert(xiao_ota_state_valid(&a));
  assert(xiao_ota_recovery_phase(&a, false) == XIAO_OTA_PHASE_BACKUP_COPYING);

  b = a;
  b.sequence = 8;
  b.phase = XIAO_OTA_PHASE_BACKUP_READY;
  commit_state(&b);
  assert(xiao_ota_newest_valid(&a, &b, sizeof(a),
                               (bool (*)(const void *))xiao_ota_state_valid) == &b);
  assert(xiao_ota_recovery_phase(&b, false) == XIAO_OTA_PHASE_INSTALL_COPYING);

  /* Simulate power loss before the final commit word: the older copy wins. */
  b.commit_marker = UINT32_C(0xFFFFFFFF);
  assert(!xiao_ota_state_valid(&b));
  assert(xiao_ota_newest_valid(&a, &b, sizeof(a),
                               (bool (*)(const void *))xiao_ota_state_valid) == &a);

  b = a;
  b.sequence = 9;
  b.phase = XIAO_OTA_PHASE_TRIAL_BOOT;
  b.trial_attempts = XIAO_OTA_MAX_TRIAL_BOOTS - 1;
  b.transaction_nonce = UINT64_C(0x123456789ABCDEF0);
  b.candidate_counter = 42;
  memset(b.candidate_hash_sha256, 0xA5, 32);
  commit_state(&b);
  assert(xiao_ota_recovery_phase(&b, false) == XIAO_OTA_PHASE_TRIAL_BOOT);
  b.trial_attempts = XIAO_OTA_MAX_TRIAL_BOOTS;
  commit_state(&b);
  assert(xiao_ota_recovery_phase(&b, false) == XIAO_OTA_PHASE_ROLLBACK_COPYING);

  confirmation.sequence = 2;
  confirmation.transaction_nonce = b.transaction_nonce;
  confirmation.confirmed_counter = b.candidate_counter;
  memcpy(confirmation.confirmed_hash_sha256, b.candidate_hash_sha256, 32);
  commit_confirmation(&confirmation);
  assert(xiao_ota_confirmation_matches(&b, &confirmation));
  assert(xiao_ota_recovery_phase(&b, true) == XIAO_OTA_PHASE_CONFIRMED);

  confirmation.confirmed_counter++;
  commit_confirmation(&confirmation);
  assert(!xiao_ota_confirmation_matches(&b, &confirmation));

  /* Every interrupted destructive phase resumes; it never falls through to app boot. */
  b.phase = XIAO_OTA_PHASE_INSTALL_COPYING;
  b.progress_bytes = 0x23000;
  b.previous_bank_0 = 1;
  b.previous_bank_0_crc = 0xBEEF;
  b.previous_bank_0_size = 0x45678;
  commit_state(&b);
  assert(xiao_ota_recovery_phase(&b, false) == XIAO_OTA_PHASE_INSTALL_COPYING);
  assert(b.previous_bank_0 == 1);
  assert(b.previous_bank_0_crc == 0xBEEF);
  assert(b.previous_bank_0_size == 0x45678);
  b.phase = XIAO_OTA_PHASE_ROLLBACK_COPYING;
  commit_state(&b);
  assert(xiao_ota_recovery_phase(&b, false) == XIAO_OTA_PHASE_ROLLBACK_COPYING);

  puts("xiao OTA record/state tests passed");
  return 0;
}
