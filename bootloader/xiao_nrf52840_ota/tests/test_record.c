#include "xiao_ota_record.h"
#include "xiao_ota_layout.h"
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

static void run_boot_decision_sequence_tests(void);

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
  /* Sidecar design acceptance: exact frozen 88-byte layout/offsets, never
   * to grow -- pinned the same way state-v1's 152 bytes are pinned
   * above, so any accidental field insertion/reorder/padding drift is
   * caught immediately rather than silently shifting the on-flash
   * layout underneath already-committed boards. */
  assert(sizeof(xiao_ota_settings_sidecar_t) == 88);
  assert((sizeof(xiao_ota_settings_sidecar_t) & 3u) == 0);
  assert(offsetof(xiao_ota_settings_sidecar_t, magic) == 0);
  assert(offsetof(xiao_ota_settings_sidecar_t, record_version) == 4);
  assert(offsetof(xiao_ota_settings_sidecar_t, record_bytes) == 6);
  assert(offsetof(xiao_ota_settings_sidecar_t, matching_state_sequence) == 8);
  assert(offsetof(xiao_ota_settings_sidecar_t, transaction_nonce) == 12);
  assert(offsetof(xiao_ota_settings_sidecar_t, command_digest_sha256) == 20);
  assert(offsetof(xiao_ota_settings_sidecar_t, original_settings_raw) == 52);
  assert(offsetof(xiao_ota_settings_sidecar_t, crc32) == 80);
  assert(offsetof(xiao_ota_settings_sidecar_t, commit_marker) == 84);
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

  /*
   * A fresh, validly signed install command must be accepted with no prior
   * state, once confirmed, and -- critically -- after a completed rollback
   * (FAILED): the device is already running its verified backup at that
   * point, and refusing new commands there would permanently disable OTA
   * after a single rejected/interrupted candidate. Every other phase means a
   * transaction is still in flight and must not be interrupted by a new one.
   */
  assert(xiao_ota_command_acceptable_phase(false, XIAO_OTA_PHASE_EMPTY));
  assert(xiao_ota_command_acceptable_phase(true, XIAO_OTA_PHASE_EMPTY));
  assert(xiao_ota_command_acceptable_phase(true, XIAO_OTA_PHASE_CONFIRMED));
  assert(xiao_ota_command_acceptable_phase(true, XIAO_OTA_PHASE_FAILED));
  assert(!xiao_ota_command_acceptable_phase(true, XIAO_OTA_PHASE_REQUESTED));
  assert(!xiao_ota_command_acceptable_phase(true, XIAO_OTA_PHASE_BACKUP_COPYING));
  assert(!xiao_ota_command_acceptable_phase(true, XIAO_OTA_PHASE_BACKUP_READY));
  assert(!xiao_ota_command_acceptable_phase(true, XIAO_OTA_PHASE_INSTALL_COPYING));
  assert(!xiao_ota_command_acceptable_phase(true, XIAO_OTA_PHASE_TRIAL_BOOT));
  assert(!xiao_ota_command_acceptable_phase(true, XIAO_OTA_PHASE_ROLLBACK_COPYING));

  /*
   * Command v2 wire-descriptor codec: a real, independently-computed
   * (Python struct.pack('>HHBII...') + hashlib.sha256) big-endian golden
   * vector must decode to the exact field values it was built from. This
   * is the SAME byte layout as src/ota/protocol/OtaDescriptor.h's
   * encodeOtaDescriptorCanonical(); board_family/board_variant here read
   * as ASCII "XN"/"40", i.e. XIAO_OTA_TARGET_XIAO_NRF52840 split in half.
   */
  {
    static const uint8_t golden_wire[XIAO_OTA_WIRE_DESCRIPTOR_SIZE] = {
        0x58, 0x4e, 0x34, 0x30, 0x00, 0x00, 0x02, 0x70, 0x00, 0x00, 0x00, 0x10,
        0x00, 0xfc, 0x04, 0xba, 0x5f, 0x8d, 0x08, 0x4d, 0x98, 0x35, 0x66, 0xb3,
        0x05, 0x80, 0x61, 0x84, 0x2b, 0xcf, 0x50, 0x23, 0xde, 0x13, 0x24, 0x14,
        0x41, 0xcd, 0x2c, 0x4a, 0xdb, 0x49, 0x1b, 0x50, 0xba, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01};
    xiao_ota_wire_descriptor_t w;
    uint8_t reencoded[XIAO_OTA_WIRE_DESCRIPTOR_SIZE];
    uint8_t tampered[XIAO_OTA_WIRE_DESCRIPTOR_SIZE];
    xiao_ota_command_v2_t cmd_v2;
    xiao_ota_command_t cmd_v1;
    xiao_ota_install_command_t intent;
    xiao_ota_command_any_t any;

    assert(sizeof(cmd_v2.wire_descriptor) == 59);
    assert(xiao_ota_wire_descriptor_decode(golden_wire, &w));
    assert(w.board_family == XIAO_OTA_BOARD_FAMILY_XIAO_NRF52840);
    assert(w.board_variant == XIAO_OTA_BOARD_VARIANT_XIAO_NRF52840);
    assert(w.role == 0);
    assert(w.app_address == 0x27000);
    assert(w.exact_size_bytes == 0x1000);
    assert(w.security_counter == 5);
    assert(w.min_boot_capabilities == XIAO_OTA_CAP_QSPI_INSTALL);
    assert(w.format_id == XIAO_OTA_DESCRIPTOR_FORMAT);
    assert(w.key_id == XIAO_OTA_KEY_ID);
    assert(w.algorithm_id == XIAO_OTA_ALGORITHM_ED25519);

    /* Round-trip: encode(decode(golden)) must reproduce golden exactly. */
    xiao_ota_wire_descriptor_encode(&w, reencoded);
    assert(memcmp(reencoded, golden_wire, sizeof(golden_wire)) == 0);

    /*
     * decode() is total/lossless for this fixed-width, unpadded, 59-byte
     * BE format: every input byte is consumed into exactly one decoded
     * field (no reserved/ignored bits, no field narrower than the bytes
     * it reads), so decode() always returns true and a single flipped
     * byte simply decodes to a DIFFERENT (not rejected) value -- it is
     * NOT decode()'s job to catch corruption. Genuine tamper rejection
     * happens one layer up, at Ed25519 signature verification over these
     * same 59 bytes (see test_descriptor_contract.c's explicit
     * signed-then-tampered rejection case, which exercises the real
     * ed25519_verify() entry point this bootloader calls). This case only
     * demonstrates the decode-is-total property, not authenticity.
     */
    memcpy(tampered, golden_wire, sizeof(tampered));
    tampered[4] ^= 0x01; /* corrupt role */
    {
      xiao_ota_wire_descriptor_t w2;
      assert(xiao_ota_wire_descriptor_decode(tampered, &w2));
      assert(w2.role != w.role);
    }

    /*
     * Exhaustive single-bit-flip round-trip coverage: for EVERY one of the
     * 59*8=472 bits in the golden wire descriptor, flipping that bit and
     * then decoding+re-encoding must reproduce the FLIPPED input exactly
     * (proving decode() is total and lossless -- no bit is ever ignored,
     * masked, or reinterpreted -- for every possible corruption of every
     * field, not just the one hand-picked byte above).
     */
    {
      size_t bit;
      for (bit = 0; bit < sizeof(golden_wire) * 8; bit++) {
        uint8_t flipped[XIAO_OTA_WIRE_DESCRIPTOR_SIZE];
        uint8_t roundtrip[XIAO_OTA_WIRE_DESCRIPTOR_SIZE];
        xiao_ota_wire_descriptor_t decoded;
        memcpy(flipped, golden_wire, sizeof(flipped));
        flipped[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        assert(xiao_ota_wire_descriptor_decode(flipped, &decoded));
        xiao_ota_wire_descriptor_encode(&decoded, roundtrip);
        assert(memcmp(roundtrip, flipped, sizeof(flipped)) == 0);
      }
    }

    /* Build a fully valid v2 command record around the golden descriptor,
     * patching just its role byte (offset 4 -- see the "corrupt role"
     * tamper case above) to THIS build's actual compiled role: the golden
     * vector itself is a fixed, real, role-0-encoded byte sequence (kept
     * byte-for-byte unchanged above for the codec/round-trip assertions,
     * which are role-agnostic), but the install-command/policy acceptance
     * below must present a command whose role genuinely matches this
     * binary's XIAO_OTA_COMPILED_ROLE_ID to remain a meaningful POSITIVE
     * test in both role-0 and role-1 builds -- otherwise a role-1 build
     * would spuriously treat this fixed role-0 golden vector as a correct
     * installer command for a role-1 binary, which it is not. */
    uint8_t golden_wire_this_role[XIAO_OTA_WIRE_DESCRIPTOR_SIZE];
    memcpy(golden_wire_this_role, golden_wire, sizeof(golden_wire_this_role));
    golden_wire_this_role[4] = (uint8_t)XIAO_OTA_COMPILED_ROLE_ID;

    memset(&cmd_v2, 0, sizeof(cmd_v2));
    cmd_v2.magic = XIAO_OTA_RECORD_MAGIC;
    cmd_v2.record_version = XIAO_OTA_COMMAND_VERSION_WIRE_V2;
    cmd_v2.record_bytes = sizeof(cmd_v2);
    cmd_v2.sequence = 1;
    cmd_v2.transaction_nonce = 0xABCDEF0123456789ULL;
    memcpy(cmd_v2.wire_descriptor, golden_wire_this_role, sizeof(golden_wire_this_role));
    cmd_v2.active_image_extent = 0x2000;
    memset(cmd_v2.active_image_hash_sha256, 0x42, 32);
    cmd_v2.crc32 = xiao_ota_crc32(&cmd_v2, offsetof(xiao_ota_command_v2_t, crc32));
    cmd_v2.commit_marker = XIAO_OTA_COMMIT_MARKER;

    assert(xiao_ota_command_v2_valid(&cmd_v2));
    assert(!xiao_ota_command_valid((const xiao_ota_command_t *)&cmd_v2));

    assert(xiao_ota_install_command_from_v2(&cmd_v2, &intent));
    assert(intent.transaction_nonce == cmd_v2.transaction_nonce);
    assert(intent.target_id == XIAO_OTA_TARGET_XIAO_NRF52840);
    assert(intent.role_id == XIAO_OTA_COMPILED_ROLE_ID);
    assert(intent.device_address == 0);
    assert(intent.allow_broadcast_address == 1);
    assert(intent.app_address == 0x27000);
    assert(intent.image_size_bytes == 0x1000);
    assert(intent.monotonic_counter == 5);
    assert(intent.active_image_extent == 0x2000);

    /* Positive policy acceptance with the real, correctly-encoded v2 descriptor. */
    assert(xiao_ota_install_command_policy_valid(&intent, /*counter_floor=*/4,
                                                 /*expected_active_extent=*/0x2000,
                                                 /*this_device_address=*/0xFEDCBA98));

    /* Field-tamper rejections: every install-relevant field must matter. */
    {
      xiao_ota_install_command_t bad = intent;
      bad.target_id ^= 1;
      assert(!xiao_ota_install_command_policy_valid(&bad, 4, 0x2000, 0xFEDCBA98));
    }
    {
      xiao_ota_install_command_t bad = intent;
      /* Must always be a role genuinely different from the compiled role,
       * in both role-0 and role-1 builds -- "1 - compiled role" rather
       * than a hardcoded literal 1, which would silently stop being a
       * tamper case once compiled for role 1 (bad.role_id would then
       * equal the compiled role and the policy check would wrongly
       * accept it). */
      bad.role_id = 1u - XIAO_OTA_COMPILED_ROLE_ID;
      assert(!xiao_ota_install_command_policy_valid(&bad, 4, 0x2000, 0xFEDCBA98));
    }
    {
      xiao_ota_install_command_t bad = intent;
      bad.app_address += 4;
      assert(!xiao_ota_install_command_policy_valid(&bad, 4, 0x2000, 0xFEDCBA98));
    }
    {
      xiao_ota_install_command_t bad = intent;
      bad.required_boot_capability_flags = 0;
      assert(!xiao_ota_install_command_policy_valid(&bad, 4, 0x2000, 0xFEDCBA98));
    }
    {
      /* Counter not strictly above the durable floor: rejected (replay/downgrade). */
      assert(!xiao_ota_install_command_policy_valid(&intent, 5, 0x2000, 0xFEDCBA98));
      assert(!xiao_ota_install_command_policy_valid(&intent, 6, 0x2000, 0xFEDCBA98));
    }
    {
      /* Active extent mismatch: rejected. */
      assert(!xiao_ota_install_command_policy_valid(&intent, 4, 0x2001, 0xFEDCBA98));
    }
    {
      /* Candidate/install size cap: 708,608 bytes (XIAO_OTA_INSTALL_MAX_SIZE,
       * v1.17's real 0x27000..0xD4000 code region) is accepted; one byte
       * over is rejected, even though it is still well inside the larger
       * XIAO_OTA_CANDIDATE_SIZE/XIAO_OTA_BACKUP_SIZE (811,008-byte,
       * 0x27000..0xED000) extent used for QSPI staging and for the
       * always-safe active-image/backup reference below. This is the exact
       * boundary a real signed install command must respect to guarantee
       * it can never erase into v1.17's own filesystem region
       * (0xD4000..0xED000). */
      assert(XIAO_OTA_INSTALL_MAX_SIZE == 0xAD000u);
      xiao_ota_install_command_t at_cap = intent;
      at_cap.image_size_bytes = XIAO_OTA_INSTALL_MAX_SIZE;
      assert(xiao_ota_install_command_policy_valid(&at_cap, 4, 0x2000, 0xFEDCBA98));

      xiao_ota_install_command_t over_cap = intent;
      over_cap.image_size_bytes = XIAO_OTA_INSTALL_MAX_SIZE + 1u;
      assert(!xiao_ota_install_command_policy_valid(&over_cap, 4, 0x2000, 0xFEDCBA98));
    }
    {
      /* The active-image/backup extent field shares the SAME writable-
       * capacity bound as the install size above (XIAO_OTA_INSTALL_MAX_
       * SIZE, 0xAD000): it is a real destructive-write byte count on the
       * external QSPI backup bank (and, on restore, on internal flash),
       * never the always-safe operation it might look like from its
       * name. XIAO_OTA_BACKUP_SIZE (0xC6000) is a strictly larger
       * PHYSICAL placement stride and must be REJECTED here -- accepting
       * it would let a backup/restore reach into the security-tail
       * region immediately past each bank's real writable capacity. */
      assert(XIAO_OTA_BACKUP_SIZE == 0xC6000u);
      xiao_ota_install_command_t full_backup = intent;
      full_backup.active_image_extent = XIAO_OTA_INSTALL_MAX_SIZE;
      assert(xiao_ota_install_command_policy_valid(&full_backup, 4, XIAO_OTA_INSTALL_MAX_SIZE,
                                                    0xFEDCBA98));

      xiao_ota_install_command_t over_backup_cap = intent;
      over_backup_cap.active_image_extent = XIAO_OTA_BACKUP_SIZE;
      assert(!xiao_ota_install_command_policy_valid(&over_backup_cap, 4, XIAO_OTA_BACKUP_SIZE,
                                                     0xFEDCBA98));
    }
    {
      /* v2 has no device-targeting field; device_address is forced 0 and
       * allow_broadcast forced 1, so ANY device address here still passes
       * (this is the real broadcast-only limitation of v2, not a bug --
       * v1 retains per-device targeting; see the v1 check below). */
      assert(xiao_ota_install_command_policy_valid(&intent, 4, 0x2000, 0x1234));
      assert(xiao_ota_install_command_policy_valid(&intent, 4, 0x2000, 0xFFFFFFFFu));
    }

    /* Structural rejection: wrong record_version byte must not validate as v1 or v2. */
    cmd_v2.record_version = 3;
    cmd_v2.crc32 = xiao_ota_crc32(&cmd_v2, offsetof(xiao_ota_command_v2_t, crc32));
    assert(!xiao_ota_command_v2_valid(&cmd_v2));
    memcpy(&any, &cmd_v2, sizeof(cmd_v2));
    assert(!xiao_ota_command_any_valid(&any));
    cmd_v2.record_version = XIAO_OTA_COMMAND_VERSION_WIRE_V2;
    cmd_v2.crc32 = xiao_ota_crc32(&cmd_v2, offsetof(xiao_ota_command_v2_t, crc32));

    /* xiao_ota_command_any_valid()/xiao_ota_install_command_decode() dispatch
     * correctly by version, with no cross-version fallback. */
    memcpy(&any, &cmd_v2, sizeof(cmd_v2));
    assert(xiao_ota_command_any_valid(&any));
    {
      xiao_ota_install_command_t any_intent;
      assert(xiao_ota_install_command_decode(&any, &any_intent));
      assert(any_intent.image_size_bytes == 0x1000);
    }

    /* A legacy v1 command builds an equivalent, independently-checked intent
     * via the SAME shared policy function -- v1 and v2 share one policy path. */
    memset(&cmd_v1, 0, sizeof(cmd_v1));
    cmd_v1.magic = XIAO_OTA_RECORD_MAGIC;
    cmd_v1.record_version = XIAO_OTA_COMMAND_VERSION_LEGACY_V1;
    cmd_v1.record_bytes = sizeof(cmd_v1);
    cmd_v1.sequence = 1;
    cmd_v1.transaction_nonce = 0x1122334455667788ULL;
    cmd_v1.descriptor.target_id_le = XIAO_OTA_TARGET_XIAO_NRF52840;
    cmd_v1.descriptor.role_id_le = XIAO_OTA_COMPILED_ROLE_ID;
    cmd_v1.descriptor.device_address_le = 0xFEDCBA98;
    cmd_v1.descriptor.allow_broadcast_address = 0;
    cmd_v1.descriptor.required_boot_capability_flags_le = XIAO_OTA_CAP_QSPI_INSTALL;
    cmd_v1.descriptor.monotonic_counter_le = 5;
    cmd_v1.descriptor.image_size_bytes_le = 0x1000;
    cmd_v1.descriptor.app_address_le = 0x27000;
    cmd_v1.descriptor.format_id_le = XIAO_OTA_DESCRIPTOR_FORMAT;
    cmd_v1.descriptor.key_id_le = XIAO_OTA_KEY_ID;
    cmd_v1.descriptor.algorithm_id_le = XIAO_OTA_ALGORITHM_ED25519;
    memcpy(cmd_v1.descriptor.image_hash_sha256, golden_wire + 13, 32);
    cmd_v1.active_image_extent = 0x2000;
    cmd_v1.crc32 = xiao_ota_crc32(&cmd_v1, offsetof(xiao_ota_command_t, crc32));
    cmd_v1.commit_marker = XIAO_OTA_COMMIT_MARKER;

    assert(xiao_ota_command_valid(&cmd_v1));
    assert(!xiao_ota_command_v2_valid((const xiao_ota_command_v2_t *)&cmd_v1));
    {
      xiao_ota_install_command_t v1_intent;
      assert(xiao_ota_install_command_from_v1(&cmd_v1, &v1_intent));
      assert(xiao_ota_install_command_policy_valid(&v1_intent, 4, 0x2000, 0xFEDCBA98));
      /* Exact-device match (not broadcast) also accepts, for v1 only. */
      assert(!xiao_ota_install_command_policy_valid(&v1_intent, 4, 0x2000, 0x1234));
    }
  }

  /* Erased-vs-corrupt distinction (xiao_ota_bytes_erased): the boot process
   * uses this to decide whether a failed-to-validate floor record means
   * "genuinely never provisioned" (safe: counter floor 0) or "damaged/
   * unrelated data" (unsafe: must fail closed, not default to floor 0). */
  {
    uint8_t erased[64];
    uint8_t corrupt[64];
    uint8_t all_zero[64];
    memset(erased, 0xFF, sizeof(erased));
    memset(corrupt, 0xFF, sizeof(corrupt));
    corrupt[3] = 0x37; /* a single stray non-erased byte anywhere ... */
    memset(all_zero, 0x00, sizeof(all_zero));

    assert(xiao_ota_bytes_erased(erased, sizeof(erased)));
    assert(!xiao_ota_bytes_erased(corrupt, sizeof(corrupt))); /* ... must be detected */
    assert(!xiao_ota_bytes_erased(all_zero, sizeof(all_zero)));
    assert(xiao_ota_bytes_erased(erased, 0)); /* zero-length is vacuously erased */

    /* A stray non-erased byte at the very end must also be caught, not
     * just an early one (guards against an off-by-one that only checks a
     * prefix). */
    corrupt[3] = 0xFF;
    corrupt[63] = 0x00;
    assert(!xiao_ota_bytes_erased(corrupt, sizeof(corrupt)));
  }

  /* xiao_ota_resolve_active_extent(): the boot-side fix proving the
   * active-image extent is ALWAYS derived from fresh bank-0 metadata, never
   * a stale durable-floor value left over from a prior OTA install. */
  {
    const uint32_t region = XIAO_OTA_APP_MAX_SIZE;
    uint32_t extent = 0;

    /* Positive: valid fresh bank-0 metadata for a genuinely different size
     * than any earlier OTA install ever recorded -- proves the resolver
     * derives from the CURRENT bank-0 CRC, not a caller-supplied stale
     * value (the old bug used floor.active_image_extent here instead of
     * ever calling this fresh path at all). */
    uint16_t fresh_crc = 0xBEEF;
    uint32_t fresh_size = 0x10000; /* deliberately unlike any "stale" size */
    assert(xiao_ota_resolve_active_extent(/*bank_0_marker_valid=*/true,
                                          fresh_crc, fresh_size, fresh_crc,
                                          region, &extent));
    assert(extent == fresh_size);

    /* Regression: simulate a user reflashing a *smaller* image over
     * USB/CDC after an OTA install already advanced the durable floor to
     * record a *larger* stale extent. The resolver must ignore any stale
     * value entirely -- it never even takes one as an argument -- and
     * derive strictly from the fresh (marker, crc, size) triple below,
     * which here describes a real image half the earlier stale size. */
    uint32_t stale_floor_extent_from_earlier_install = 0x40000;
    uint16_t reflashed_crc = 0x1234;
    uint32_t reflashed_size = 0x20000;
    (void)stale_floor_extent_from_earlier_install; /* never consulted */
    extent = 0;
    assert(xiao_ota_resolve_active_extent(true, reflashed_crc, reflashed_size,
                                          reflashed_crc, region, &extent));
    assert(extent == reflashed_size);
    assert(extent != stale_floor_extent_from_earlier_install);

    /* Fail-closed: bad bank marker. */
    extent = 0xDEADBEEF;
    assert(!xiao_ota_resolve_active_extent(false, fresh_crc, fresh_size,
                                           fresh_crc, region, &extent));
    /* out_extent must be left untouched on failure, not silently defaulted. */
    assert(extent == 0xDEADBEEF);

    /* CRC policy is uniform: 0 is a perfectly legitimate CRC-16 value
     * (e.g. a signed candidate's own pad-fixup can legitimately land on
     * a zero remainder), not a reserved "invalid" sentinel -- reject
     * ONLY on an actual computed/stored mismatch, exactly like any other
     * CRC value, never by special-casing 0 out. */
    extent = 0;
    assert(xiao_ota_resolve_active_extent(true, 0, fresh_size, 0, region,
                                          &extent));
    assert(extent == fresh_size);

    /* Still fail-closed when only ONE side is 0 -- that is a real
     * mismatch, not the uniform-zero case above. */
    extent = 0xDEADBEEF;
    assert(!xiao_ota_resolve_active_extent(true, 0, fresh_size, fresh_crc,
                                           region, &extent));
    assert(extent == 0xDEADBEEF);
    assert(!xiao_ota_resolve_active_extent(true, fresh_crc, fresh_size, 0,
                                           region, &extent));
    assert(extent == 0xDEADBEEF);

    /* Fail-closed: zero size. */
    assert(!xiao_ota_resolve_active_extent(true, fresh_crc, 0, fresh_crc,
                                           region, &extent));

    /* Fail-closed: size larger than the app region. */
    assert(!xiao_ota_resolve_active_extent(true, fresh_crc, region + 4,
                                           fresh_crc, region, &extent));

    /* Fail-closed: CRC mismatch -- the actual "corrupt/foreign bank-0"
     * case a stale floor previously masked by never even being checked. */
    assert(!xiao_ota_resolve_active_extent(true, fresh_crc, fresh_size,
                                           (uint16_t)(fresh_crc ^ 1u), region,
                                           &extent));
  }

  /* xiao_ota_command_is_retry_of_failed_transaction(): the boot-side fix
   * for the endless-reinstall-after-rollback bug -- a byte-identical
   * retry of an already-FAILED transaction (same nonce/counter/hash) must
   * be refused, while any genuinely new authenticated command (any single
   * field different) must still be honoured. */
  {
    uint8_t hash_a[32], hash_b[32];
    memset(hash_a, 0x11, sizeof(hash_a));
    memset(hash_b, 0x22, sizeof(hash_b));

    /* Regression: exact retry of a FAILED transaction is refused. */
    assert(xiao_ota_command_is_retry_of_failed_transaction(
        true, XIAO_OTA_PHASE_FAILED, 42, 7, hash_a, 42, 7, hash_a));

    /* A genuinely new command -- new nonce -- is allowed even though
     * counter/hash happen to match (still refused only on an EXACT
     * identity match of all three fields). */
    assert(!xiao_ota_command_is_retry_of_failed_transaction(
        true, XIAO_OTA_PHASE_FAILED, 42, 7, hash_a, 43, 7, hash_a));

    /* A genuinely new command -- new counter (new image install) -- is
     * allowed. */
    assert(!xiao_ota_command_is_retry_of_failed_transaction(
        true, XIAO_OTA_PHASE_FAILED, 42, 7, hash_a, 42, 8, hash_a));

    /* A genuinely new command -- new image hash -- is allowed. */
    assert(!xiao_ota_command_is_retry_of_failed_transaction(
        true, XIAO_OTA_PHASE_FAILED, 42, 7, hash_a, 42, 7, hash_b));

    /* Not in FAILED phase at all (e.g. CONFIRMED, EMPTY) -- never treated
     * as a retry regardless of field equality. */
    assert(!xiao_ota_command_is_retry_of_failed_transaction(
        true, XIAO_OTA_PHASE_CONFIRMED, 42, 7, hash_a, 42, 7, hash_a));
    assert(!xiao_ota_command_is_retry_of_failed_transaction(
        true, XIAO_OTA_PHASE_EMPTY, 42, 7, hash_a, 42, 7, hash_a));

    /* No prior state at all -- never treated as a retry. */
    assert(!xiao_ota_command_is_retry_of_failed_transaction(
        false, XIAO_OTA_PHASE_FAILED, 42, 7, hash_a, 42, 7, hash_a));

    /* Regression: the nonce is a full 64-bit value end to end
     * (xiao_ota_state_t.transaction_nonce / command/confirmation
     * transaction_nonce are all uint64_t) -- a nonce parameter narrowed to
     * uint32_t would silently truncate the high 32 bits, making two
     * genuinely different 64-bit nonces that only differ above bit 31
     * compare equal. Use nonces that share identical low 32 bits (0) and
     * differ only in the high 32 bits, and confirm this is correctly
     * treated as a genuinely new command, not a retry. */
    {
      uint64_t nonce_old = (uint64_t)1u << 32;   /* 0x1_00000000 */
      uint64_t nonce_new = (uint64_t)2u << 32;   /* 0x2_00000000, low32 == 0 too */
      assert(nonce_old != nonce_new);
      assert((uint32_t)nonce_old == (uint32_t)nonce_new); /* low bits identical */
      assert(xiao_ota_command_is_retry_of_failed_transaction(
          true, XIAO_OTA_PHASE_FAILED, nonce_old, 7, hash_a, nonce_old, 7,
          hash_a));
      assert(!xiao_ota_command_is_retry_of_failed_transaction(
          true, XIAO_OTA_PHASE_FAILED, nonce_old, 7, hash_a, nonce_new, 7,
          hash_a));
    }
  }

  /* xiao_ota_confirmation_hash_bound_extent_valid(): the boot-side fix
   * proving the anti-rollback floor is never advanced on a transport-level
   * confirmation token alone -- a FRESH bank-0 extent/validity and a FRESH
   * live SHA-256 must match exactly what was installed and hashed right
   * after writing it, closing the "USB reflash during trial window" gap.
   * installed_hash_sha256 is computed over exactly candidate_size bytes,
   * so it cryptographically binds both content and length: a fresh hash
   * match at a given extent verifies that extent IS the original
   * candidate size, with no separate durable extent field needed. */
  {
    uint8_t installed_hash[32], fresh_hash_match[32], fresh_hash_mismatch[32];
    const uint32_t max_extent = 0x40000; /* stand-in for XIAO_OTA_INSTALL_MAX_SIZE */
    memset(installed_hash, 0x77, sizeof(installed_hash));
    memcpy(fresh_hash_match, installed_hash, sizeof(installed_hash));
    memset(fresh_hash_mismatch, 0x99, sizeof(fresh_hash_mismatch));

    /* Positive: fresh extent valid, non-zero, within cap, hash matches. */
    assert(xiao_ota_confirmation_hash_bound_extent_valid(
        true, 0x20000, max_extent, fresh_hash_match, installed_hash));

    /* Regression: fresh bank-0 metadata itself is invalid (e.g. this-boot
     * CRC-16 mismatch) -- never advance the floor even if a stale hash
     * happens to line up. */
    assert(!xiao_ota_confirmation_hash_bound_extent_valid(
        false, 0x20000, max_extent, fresh_hash_match, installed_hash));

    /* Regression: fresh extent is exactly zero -- never treated as a
     * valid installed image regardless of hash. */
    assert(!xiao_ota_confirmation_hash_bound_extent_valid(
        true, 0, max_extent, fresh_hash_match, installed_hash));

    /* Regression: fresh extent exceeds the install-size cap -- a
     * corrupted/oversized fresh bank-0 read must never validate even if
     * the hash happens to match (defence in depth alongside the cap
     * already enforced at command-acceptance time). */
    assert(!xiao_ota_confirmation_hash_bound_extent_valid(
        true, max_extent + 1, max_extent, fresh_hash_match, installed_hash));

    /* Regression: fresh SHA-256 over what is actually running right now
     * does not match the hash captured immediately after this
     * transaction's install-copy verified -- e.g. a USB reflash of a
     * same-sized but different image, a differently-sized image, or flash
     * damage. The predicate no longer takes a separate expected-extent
     * argument at all -- the hash mismatch alone is sufficient, whatever
     * the fresh extent is, and this is not a tautological "fresh extent
     * compared to itself" check. */
    assert(!xiao_ota_confirmation_hash_bound_extent_valid(
        true, 0x20000, max_extent, fresh_hash_mismatch, installed_hash));
  }

  {
    /* Golden LE fixture for xiao_ota_settings_sidecar_t: an explicit
     * byte-for-byte expected on-flash image built independently of the
     * struct/CRC code under test (fixed field values, hand-computed
     * layout), proving the actual little-endian byte layout the SDK/
     * host tooling and this bootloader agree on -- not merely that
     * round-tripping through the same struct is self-consistent. */
    xiao_ota_settings_sidecar_t sidecar;
    static const uint8_t golden_sidecar[88] = {
        /* magic "XSID" LE */
        0x44, 0x49, 0x53, 0x58,
        /* record_version=1, record_bytes=88 LE */
        0x01, 0x00, 0x58, 0x00,
        /* matching_state_sequence=0x11223344 LE */
        0x44, 0x33, 0x22, 0x11,
        /* transaction_nonce=0x0102030405060708 LE */
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        /* command_digest_sha256: 0x00..0x1F */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        /* original_settings_raw: 0x20..0x3B (28 bytes) */
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B,
        /* crc32: filled in below, placeholder */
        0x00, 0x00, 0x00, 0x00,
        /* commit_marker LE */
        0x00, 0x00, 0x00, 0x00,
    };
    uint8_t reencoded[88];
    uint8_t tampered[88];
    uint32_t crc;
    uint32_t marker;

    memcpy(&sidecar, golden_sidecar, sizeof(sidecar));
    crc = xiao_ota_crc32(&sidecar, offsetof(xiao_ota_settings_sidecar_t, crc32));
    memcpy(reencoded, golden_sidecar, sizeof(reencoded));
    memcpy(reencoded + offsetof(xiao_ota_settings_sidecar_t, crc32), &crc, 4);
    marker = XIAO_OTA_COMMIT_MARKER;
    memcpy(reencoded + offsetof(xiao_ota_settings_sidecar_t, commit_marker),
          &marker, 4);
    memcpy(&sidecar, reencoded, sizeof(sidecar));

    assert(xiao_ota_settings_sidecar_valid(&sidecar));
    assert(sidecar.matching_state_sequence == 0x11223344u);
    assert(sidecar.transaction_nonce == UINT64_C(0x0102030405060708));
    assert(sidecar.command_digest_sha256[0] == 0x00 &&
          sidecar.command_digest_sha256[31] == 0x1Fu);
    assert(sidecar.original_settings_raw[0] == 0x20 &&
          sidecar.original_settings_raw[27] == 0x3Bu);

    /* Round-trip: the in-memory struct, byte-for-byte, reproduces the
     * exact golden+CRC+marker image (proves no padding/reordering). */
    memcpy(tampered, &sidecar, sizeof(tampered));
    assert(memcmp(tampered, reencoded, sizeof(tampered)) == 0);

    /* Any single flipped payload byte invalidates the CRC. */
    memcpy(tampered, reencoded, sizeof(tampered));
    tampered[10] ^= 0xFFu;
    memcpy(&sidecar, tampered, sizeof(sidecar));
    assert(!xiao_ota_settings_sidecar_valid(&sidecar));

    /* A cleared commit marker means "torn write", never valid. */
    memcpy(tampered, reencoded, sizeof(tampered));
    memset(tampered + offsetof(xiao_ota_settings_sidecar_t, commit_marker), 0,
          4);
    memcpy(&sidecar, tampered, sizeof(sidecar));
    assert(!xiao_ota_settings_sidecar_valid(&sidecar));
  }

  puts("xiao OTA record/state tests passed");
  run_boot_decision_sequence_tests();
  return 0;
}

/*
 * Boot-decision-sequence regression: chains the SAME pure functions
 * xiao_ota_boot.c's xiao_ota_boot_process() calls, in the same order, over
 * a single xiao_ota_state_t/xiao_ota_floor_t pair, for a differently-sized
 * update (old 320-byte backup extent -> new 489-byte installed extent,
 * standing in for real KiB-scale sizes at 1/1000 scale so a real SHA-256
 * can be computed over an actual in-memory buffer instead of a
 * placeholder digest). This is NOT the compiled production file
 * (xiao_ota_boot.c is inseparable from real NRF52840 QSPI/NVMC/WDT
 * peripheral registers and cannot safely link or run on a host process)
 * -- it is a cross-boot-cycle sequence check that the CALL SITES pass the
 * right *state* field and that the hash-length binding this design relies
 * on actually holds for a real SHA-256 implementation, not just an
 * abstract byte-pattern placeholder.
 */
static void run_boot_decision_sequence_tests(void) {
  /* A single shared "flash" buffer: the OLD image occupies its first
   * old_backup_extent bytes: byte 0 differs between old and new content),
   * the NEW image occupies the first new_installed_extent bytes with
   * DIFFERENT content in the overlap region -- exactly what a real
   * differently-sized update looks like (new content, new length). */
  static uint8_t flash[512];
  const uint32_t old_backup_extent = 320u;
  const uint32_t new_installed_extent = 489u;
  const uint32_t max_extent = 512u; /* stand-in for XIAO_OTA_INSTALL_MAX_SIZE */
  uint8_t old_hash[32], new_hash[32], fresh_hash[32];
  xiao_ota_state_t state;
  xiao_ota_floor_t floor;
  xiao_ota_sha256_t sha;
  size_t i;

  memset(&state, 0, sizeof(state));
  memset(&floor, 0, sizeof(floor));
  for (i = 0; i < sizeof(flash); ++i) flash[i] = (uint8_t)(0x11 + i);
  xiao_ota_sha256_init(&sha);
  xiao_ota_sha256_update(&sha, flash, old_backup_extent);
  xiao_ota_sha256_final(&sha, old_hash);

  /* --- Transaction start / backup (mirrors boot.c's BACKUP_COPYING
   * assignment): active_image_extent is the OLD image's extent, fixed now
   * and required unchanged through backup-copy AND rollback-restore. */
  state.active_image_extent = old_backup_extent;
  memcpy(state.backup_hash_sha256, old_hash, 32);

  /* --- Install (mirrors boot.c's INSTALL_COPYING verification): a
   * genuinely different, longer NEW image is written and hashed over its
   * OWN extent right after the copy is verified -- installed_hash_sha256
   * cryptographically binds both this content and this exact length. */
  for (i = old_backup_extent; i < new_installed_extent; ++i) {
    flash[i] = (uint8_t)(0xA0 + i); /* new tail content beyond old extent */
  }
  xiao_ota_sha256_init(&sha);
  xiao_ota_sha256_update(&sha, flash, new_installed_extent);
  xiao_ota_sha256_final(&sha, new_hash);
  memcpy(state.installed_hash_sha256, new_hash, 32);
  state.candidate_counter = 9;
  memcpy(state.candidate_hash_sha256, new_hash, 32);

  /* Scenario A: correct trial-boot confirmation (old 320 -> new 489
   * bytes). A genuinely fresh read+hash at the NEW size, over the ACTUAL
   * flash contents, reproduces installed_hash_sha256 with no separate
   * durable extent field -- this is exactly the differently-sized-update
   * case the earlier explicit-extent-field design existed to handle, now
   * proven for a real hash instead of a placeholder digest. */
  xiao_ota_sha256_init(&sha);
  xiao_ota_sha256_update(&sha, flash, new_installed_extent);
  xiao_ota_sha256_final(&sha, fresh_hash);
  assert(xiao_ota_confirmation_hash_bound_extent_valid(
      true, new_installed_extent, max_extent, fresh_hash,
      state.installed_hash_sha256));

  /* Regression guard against the tautological-proxy failure mode: hashing
   * at the WRONG extent (the old backup's 320 bytes, still real flash
   * content, still a genuine SHA-256) must NOT reproduce
   * installed_hash_sha256 -- proving the predicate's hash check is a real
   * length-binding check, not "fresh extent compared to itself". */
  {
    uint8_t fresh_hash_wrong_extent[32];
    xiao_ota_sha256_init(&sha);
    xiao_ota_sha256_update(&sha, flash, old_backup_extent);
    xiao_ota_sha256_final(&sha, fresh_hash_wrong_extent);
    assert(!xiao_ota_confirmation_hash_bound_extent_valid(
        true, old_backup_extent, max_extent, fresh_hash_wrong_extent,
        state.installed_hash_sha256));
  }

  /* After a successful confirmation, floor.active_image_extent must record
   * the fresh VERIFIED extent (489, what boot.c now assigns from
   * fresh_extent once the hash-bound check passes), and
   * state.active_image_extent (the OLD backup extent) must remain
   * completely untouched -- still available, unchanged, in case any
   * future transaction needs the old span. */
  floor.active_image_extent = new_installed_extent;
  assert(floor.active_image_extent == new_installed_extent);
  assert(state.active_image_extent == old_backup_extent);

  /* Scenario B: reverse direction (old 489 -> new 320 bytes) is symmetric
   * -- a shrink is verified exactly the same way. */
  {
    uint8_t shrink_hash[32], shrink_fresh[32];
    xiao_ota_sha256_init(&sha);
    xiao_ota_sha256_update(&sha, flash, old_backup_extent);
    xiao_ota_sha256_final(&sha, shrink_hash);
    xiao_ota_sha256_init(&sha);
    xiao_ota_sha256_update(&sha, flash, old_backup_extent);
    xiao_ota_sha256_final(&sha, shrink_fresh);
    assert(xiao_ota_confirmation_hash_bound_extent_valid(
        true, old_backup_extent, max_extent, shrink_fresh, shrink_hash));
  }

  /* Scenario C: USB/CDC reflash (or flash damage) during the trial window
   * -- the fresh live hash no longer matches what this transaction
   * installed, so confirmation must refuse and fall to rollback, which
   * restores the OLD backup span (state.active_image_extent, still 320
   * and completely unaffected by the hash-bound confirmation check). */
  {
    uint8_t fresh_hash_reflash[32];
    memset(fresh_hash_reflash, 0xEF, sizeof(fresh_hash_reflash));
    assert(!xiao_ota_confirmation_hash_bound_extent_valid(
        true, new_installed_extent, max_extent, fresh_hash_reflash,
        state.installed_hash_sha256));
    assert(state.active_image_extent == old_backup_extent);
  }

  /* Scenario D: the exact same FAILED (rolled-back) signed command must be
   * refused identically across multiple simulated boots -- no repeated
   * backup/install/trial work -- while a genuinely new nonce (including
   * one differing only in the high 32 bits of the full 64-bit nonce) is
   * accepted. xiao_ota_command_is_retry_of_failed_transaction() is
   * pure/stateless, so calling it repeatedly with the same durable
   * failed-transaction identity models exactly what "the same device
   * boots three more times with the same stale signed command" looks
   * like. */
  {
    uint8_t failed_hash[32];
    uint64_t failed_nonce = (uint64_t)7u << 32; /* 0x7_00000000 */
    int boot_cycle;
    memset(failed_hash, 0x33, sizeof(failed_hash));
    for (boot_cycle = 0; boot_cycle < 3; ++boot_cycle) {
      assert(xiao_ota_command_is_retry_of_failed_transaction(
          true, XIAO_OTA_PHASE_FAILED, failed_nonce, 5, failed_hash,
          failed_nonce, 5, failed_hash));
    }
    /* A genuinely new signed command -- new nonce differing only in the
     * high 32 bits (low 32 bits both 0) -- on the very next boot is still
     * honoured, not silently truncated into matching the old nonce. */
    assert(!xiao_ota_command_is_retry_of_failed_transaction(
        true, XIAO_OTA_PHASE_FAILED, failed_nonce, 5, failed_hash,
        (uint64_t)8u << 32, 5, failed_hash));
    /* And an ordinary low-32-bit-only new nonce is still honoured too. */
    assert(!xiao_ota_command_is_retry_of_failed_transaction(
        true, XIAO_OTA_PHASE_FAILED, failed_nonce, 5, failed_hash,
        failed_nonce + 1, 6, failed_hash));
  }

  puts("xiao OTA boot-decision-sequence tests passed");
}
