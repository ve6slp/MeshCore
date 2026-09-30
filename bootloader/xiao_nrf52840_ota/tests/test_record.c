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
     * Non-canonical rejection: flip a bit that decode() itself would never
     * distinguish from a legitimate field value if it just trusted its
     * input -- decode-then-re-encode-then-compare must still catch a
     * corrupted byte that decode() alone happily parses.
     */
    memcpy(tampered, golden_wire, sizeof(tampered));
    tampered[4] ^= 0x01; /* corrupt role */
    {
      xiao_ota_wire_descriptor_t w2;
      /* decode() itself always "succeeds" at parsing tampered bytes into
       * some struct -- the canonical round-trip is what must reject it if
       * the corruption changes the decoded value (which it does here). */
      xiao_ota_wire_descriptor_decode(tampered, &w2);
      assert(w2.role != w.role);
    }

    /* Build a fully valid v2 command record around the golden descriptor. */
    memset(&cmd_v2, 0, sizeof(cmd_v2));
    cmd_v2.magic = XIAO_OTA_RECORD_MAGIC;
    cmd_v2.record_version = XIAO_OTA_COMMAND_VERSION_WIRE_V2;
    cmd_v2.record_bytes = sizeof(cmd_v2);
    cmd_v2.sequence = 1;
    cmd_v2.transaction_nonce = 0xABCDEF0123456789ULL;
    memcpy(cmd_v2.wire_descriptor, golden_wire, sizeof(golden_wire));
    cmd_v2.active_image_extent = 0x2000;
    memset(cmd_v2.active_image_hash_sha256, 0x42, 32);
    cmd_v2.crc32 = xiao_ota_crc32(&cmd_v2, offsetof(xiao_ota_command_v2_t, crc32));
    cmd_v2.commit_marker = XIAO_OTA_COMMIT_MARKER;

    assert(xiao_ota_command_v2_valid(&cmd_v2));
    assert(!xiao_ota_command_valid((const xiao_ota_command_t *)&cmd_v2));

    assert(xiao_ota_install_command_from_v2(&cmd_v2, &intent));
    assert(intent.transaction_nonce == cmd_v2.transaction_nonce);
    assert(intent.target_id == XIAO_OTA_TARGET_XIAO_NRF52840);
    assert(intent.role_id == XIAO_OTA_ROLE_ANY);
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
      bad.role_id = 1;
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
      /* The active-image/backup extent field is a DIFFERENT bound: the full
       * 811,008-byte (0xC6000) extent is accepted here, because backing up
       * that many bytes is always safe (a protective read+copy, never a
       * flash erase past the candidate/install cap above). */
      assert(XIAO_OTA_BACKUP_SIZE == 0xC6000u);
      xiao_ota_install_command_t full_backup = intent;
      full_backup.active_image_extent = XIAO_OTA_BACKUP_SIZE;
      assert(xiao_ota_install_command_policy_valid(&full_backup, 4, XIAO_OTA_BACKUP_SIZE,
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
    cmd_v1.descriptor.role_id_le = XIAO_OTA_ROLE_ANY;
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

    /* Fail-closed: zero CRC (never a valid stored value). */
    assert(!xiao_ota_resolve_active_extent(true, 0, fresh_size, 0, region,
                                           &extent));

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

  puts("xiao OTA record/state tests passed");
  return 0;
}
