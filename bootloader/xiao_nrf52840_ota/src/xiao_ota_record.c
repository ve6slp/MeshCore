#include "xiao_ota_record.h"

#include <string.h>

#include "xiao_ota_layout.h"

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

bool xiao_ota_resolve_active_extent(bool bank_0_marker_valid,
                                    uint16_t bank_0_crc, uint32_t bank_0_size,
                                    uint16_t recomputed_crc16,
                                    uint32_t app_region_size,
                                    uint32_t *out_extent) {
  /*
   * CRC-16-CCITT (the algorithm crc16_compute()/Nordic's own bank_0_crc
   * use) has no reserved "invalid" codomain value: 0 is a perfectly
   * reachable, legitimate CRC for real image bytes (including after a
   * signed candidate's own pad-fixup step deliberately drives its
   * trailing bytes to land on a zero remainder). Treating stored/
   * recomputed 0 as automatically invalid is not a real integrity check
   * at all -- it is a policy that silently REJECTS a subset of correctly
   * signed, correctly installed images for no cryptographic reason,
   * while doing nothing to catch corruption (a corrupted-to-0 CRC still
   * gets caught below by the equality compare, exactly like any other
   * corrupted value). The only real sentinel here is bank_0_marker_valid
   * itself (whether bank-0 even claims to hold a valid app); once that
   * is true, the ONLY authoritative check is recomputed_crc16 ==
   * bank_0_crc, uniformly, including when both sides are 0.
   */
  if (!bank_0_marker_valid || bank_0_size == 0 ||
      bank_0_size > app_region_size || recomputed_crc16 != bank_0_crc) {
    return false;
  }
  *out_extent = xiao_ota_safe_backup_extent(bank_0_size, app_region_size);
  return true;
}

/*
 * Everything a fully-formed, self-consistent record must satisfy EXCEPT
 * the commit-marker exact match: magic/version/record_bytes/CRC. A
 * record whose body passes this is either (a) durably committed and
 * otherwise intact (only its marker field disagrees, whether because the
 * marker write is still genuinely in flight or because it was corrupted
 * some time after a real commit), or (b) an extraordinarily unlikely
 * coincidental CRC collision on foreign data -- CRC32 makes that
 * negligible in practice, so in effect this predicate answers "is this
 * byte-for-byte a real record of this type, modulo its commit state".
 * See record_body_valid_and_committed() below for why this split matters:
 * a record passing THIS check can NEVER be resolved as safe-to-discard
 * from its own bytes alone (see xiao_ota_boot_io.c's slot_safe_to_
 * overwrite() doc-comment).
 */
static bool record_body_valid(const void *record, size_t size, uint32_t magic,
                              uint16_t expected_version, uint16_t record_bytes,
                              size_t crc_offset) {
  const uint8_t *bytes = (const uint8_t *)record;
  uint32_t stored_crc;
  if (record == NULL || size != record_bytes) {
    return false;
  }
  memcpy(&stored_crc, bytes + crc_offset, sizeof(stored_crc));
  return memcmp(bytes, &magic, sizeof(magic)) == 0 &&
         bytes[4] == (uint8_t)expected_version &&
         bytes[5] == (uint8_t)(expected_version >> 8) &&
         bytes[6] == (uint8_t)record_bytes && bytes[7] == (uint8_t)(record_bytes >> 8) &&
         stored_crc == xiao_ota_crc32(record, crc_offset);
}

static bool record_valid(const void *record, size_t size, uint32_t magic,
                         uint16_t expected_version, uint16_t record_bytes,
                         size_t crc_offset, size_t commit_offset) {
  const uint8_t *bytes = (const uint8_t *)record;
  uint32_t commit;
  if (!record_body_valid(record, size, magic, expected_version, record_bytes,
                         crc_offset)) {
    return false;
  }
  memcpy(&commit, bytes + commit_offset, sizeof(commit));
  return commit == XIAO_OTA_COMMIT_MARKER;
}

bool xiao_ota_command_valid(const xiao_ota_command_t *record) {
  return record_valid(record, sizeof(*record), XIAO_OTA_RECORD_MAGIC,
                      XIAO_OTA_COMMAND_VERSION_LEGACY_V1, sizeof(*record),
                      offsetof(xiao_ota_command_t, crc32),
                      offsetof(xiao_ota_command_t, commit_marker));
}

bool xiao_ota_command_v2_valid(const xiao_ota_command_v2_t *record) {
  return record_valid(record, sizeof(*record), XIAO_OTA_RECORD_MAGIC,
                      XIAO_OTA_COMMAND_VERSION_WIRE_V2, sizeof(*record),
                      offsetof(xiao_ota_command_v2_t, crc32),
                      offsetof(xiao_ota_command_v2_t, commit_marker));
}

/*
 * Dispatches on record_version (offset 4) ONLY -- there is no fallback/OR
 * between versions and no version is ever accepted against the other
 * version's validity/size rule. `record` must point to storage at least
 * sizeof(xiao_ota_command_any_t) bytes (both xiao_ota_command_valid() and
 * xiao_ota_command_v2_valid() read exactly sizeof(their own struct) from
 * it, which xiao_ota_command_any_t guarantees is available).
 */
bool xiao_ota_command_any_valid(const void *record) {
  uint16_t version;
  if (record == NULL) return false;
  memcpy(&version, (const uint8_t *)record + 4, sizeof(version));
  if (version == XIAO_OTA_COMMAND_VERSION_LEGACY_V1) {
    return xiao_ota_command_valid((const xiao_ota_command_t *)record);
  }
  if (version == XIAO_OTA_COMMAND_VERSION_WIRE_V2) {
    return xiao_ota_command_v2_valid((const xiao_ota_command_v2_t *)record);
  }
  return false;
}

bool xiao_ota_state_valid(const xiao_ota_state_t *record) {
  return record_valid(record, sizeof(*record), XIAO_OTA_RECORD_MAGIC,
                      XIAO_OTA_FORMAT_VERSION, sizeof(*record),
                      offsetof(xiao_ota_state_t, crc32),
                      offsetof(xiao_ota_state_t, commit_marker)) &&
         record->phase <= XIAO_OTA_PHASE_FAILED;
}

/*
 * Everything xiao_ota_state_valid() checks EXCEPT the commit-marker
 * exact match -- see record_body_valid()'s doc-comment. Used by
 * slot_safe_to_overwrite() (xiao_ota_boot_io.c) to detect the
 * genuinely-ambiguous case (a fully-formed record whose marker alone
 * disagrees) that NOR-reachability-only reasoning cannot safely resolve.
 */
bool xiao_ota_state_body_valid(const xiao_ota_state_t *record) {
  return record_body_valid(record, sizeof(*record), XIAO_OTA_RECORD_MAGIC,
                           XIAO_OTA_FORMAT_VERSION, sizeof(*record),
                           offsetof(xiao_ota_state_t, crc32)) &&
         record->phase <= XIAO_OTA_PHASE_FAILED;
}

bool xiao_ota_confirmation_valid(const xiao_ota_confirmation_t *record) {
  return record_valid(record, sizeof(*record), XIAO_OTA_CONFIRM_MAGIC,
                      XIAO_OTA_FORMAT_VERSION, sizeof(*record),
                      offsetof(xiao_ota_confirmation_t, crc32),
                      offsetof(xiao_ota_confirmation_t, commit_marker));
}

bool xiao_ota_settings_sidecar_valid(const xiao_ota_settings_sidecar_t *record) {
  return record_valid(record, sizeof(*record), XIAO_OTA_SIDECAR_MAGIC,
                      XIAO_OTA_FORMAT_VERSION, sizeof(*record),
                      offsetof(xiao_ota_settings_sidecar_t, crc32),
                      offsetof(xiao_ota_settings_sidecar_t, commit_marker));
}

/* See xiao_ota_state_body_valid()'s doc-comment; sidecar counterpart. */
bool xiao_ota_settings_sidecar_body_valid(const xiao_ota_settings_sidecar_t *record) {
  return record_body_valid(record, sizeof(*record), XIAO_OTA_SIDECAR_MAGIC,
                           XIAO_OTA_FORMAT_VERSION, sizeof(*record),
                           offsetof(xiao_ota_settings_sidecar_t, crc32));
}

bool xiao_ota_floor_valid(const xiao_ota_floor_t *record) {
  return record_valid(record, sizeof(*record), XIAO_OTA_FLOOR_MAGIC,
                      XIAO_OTA_FORMAT_VERSION, sizeof(*record),
                      offsetof(xiao_ota_floor_t, crc32),
                      offsetof(xiao_ota_floor_t, commit_marker));
}

/* See xiao_ota_state_body_valid()'s doc-comment; floor counterpart. */
bool xiao_ota_floor_body_valid(const xiao_ota_floor_t *record) {
  return record_body_valid(record, sizeof(*record), XIAO_OTA_FLOOR_MAGIC,
                           XIAO_OTA_FORMAT_VERSION, sizeof(*record),
                           offsetof(xiao_ota_floor_t, crc32));
}

bool xiao_ota_floor_activation_receipt_body_valid(
    const xiao_ota_floor_activation_receipt_t *record) {
  return record_body_valid(record, sizeof(*record),
                           XIAO_OTA_FLOOR_ACTIVATION_MAGIC,
                           XIAO_OTA_FLOOR_ACTIVATION_RECORD_VERSION,
                           sizeof(*record),
                           offsetof(xiao_ota_floor_activation_receipt_t, crc32));
}

bool xiao_ota_bytes_erased(const void *data, size_t length) {
  const uint8_t *bytes = (const uint8_t *)data;
  size_t i;
  for (i = 0; i < length; ++i) {
    if (bytes[i] != 0xFFu) return false;
  }
  return true;
}

static void put_be16(uint8_t *dst, uint16_t v) {
  dst[0] = (uint8_t)(v >> 8);
  dst[1] = (uint8_t)v;
}

static uint16_t get_be16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8) | src[1]);
}

static void put_be32(uint8_t *dst, uint32_t v) {
  dst[0] = (uint8_t)(v >> 24);
  dst[1] = (uint8_t)(v >> 16);
  dst[2] = (uint8_t)(v >> 8);
  dst[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *src) {
  return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

void xiao_ota_wire_descriptor_encode(const xiao_ota_wire_descriptor_t *d,
                                     uint8_t out[XIAO_OTA_WIRE_DESCRIPTOR_SIZE]) {
  size_t pos = 0;
  put_be16(out + pos, d->board_family); pos += 2;
  put_be16(out + pos, d->board_variant); pos += 2;
  out[pos] = d->role; pos += 1;
  put_be32(out + pos, d->app_address); pos += 4;
  put_be32(out + pos, d->exact_size_bytes); pos += 4;
  memcpy(out + pos, d->sha256, 32); pos += 32;
  put_be32(out + pos, d->security_counter); pos += 4;
  put_be32(out + pos, d->min_boot_capabilities); pos += 4;
  put_be16(out + pos, d->format_id); pos += 2;
  put_be16(out + pos, d->key_id); pos += 2;
  put_be16(out + pos, d->algorithm_id); pos += 2;
}

bool xiao_ota_wire_descriptor_decode(const uint8_t in[XIAO_OTA_WIRE_DESCRIPTOR_SIZE],
                                     xiao_ota_wire_descriptor_t *out) {
  size_t pos = 0;
  out->board_family = get_be16(in + pos); pos += 2;
  out->board_variant = get_be16(in + pos); pos += 2;
  out->role = in[pos]; pos += 1;
  out->app_address = get_be32(in + pos); pos += 4;
  out->exact_size_bytes = get_be32(in + pos); pos += 4;
  memcpy(out->sha256, in + pos, 32); pos += 32;
  out->security_counter = get_be32(in + pos); pos += 4;
  out->min_boot_capabilities = get_be32(in + pos); pos += 4;
  out->format_id = get_be16(in + pos); pos += 2;
  out->key_id = get_be16(in + pos); pos += 2;
  out->algorithm_id = get_be16(in + pos); pos += 2;
  return true;
}

bool xiao_ota_install_command_from_v1(const xiao_ota_command_t *cmd,
                                      xiao_ota_install_command_t *out) {
  const xiao_ota_canonical_descriptor_t *d = &cmd->descriptor;
  memset(out, 0, sizeof(*out));
  out->transaction_nonce = cmd->transaction_nonce;
  out->target_id = d->target_id_le;
  out->role_id = d->role_id_le;
  out->device_address = d->device_address_le;
  out->allow_broadcast_address = d->allow_broadcast_address;
  out->required_boot_capability_flags = d->required_boot_capability_flags_le;
  out->monotonic_counter = d->monotonic_counter_le;
  out->image_size_bytes = d->image_size_bytes_le;
  out->app_address = d->app_address_le;
  out->format_id = d->format_id_le;
  out->key_id = d->key_id_le;
  out->algorithm_id = d->algorithm_id_le;
  memcpy(out->image_hash_sha256, d->image_hash_sha256, 32);
  out->active_image_extent = cmd->active_image_extent;
  memcpy(out->active_image_hash_sha256, cmd->active_image_hash_sha256, 32);
  return true;
}

bool xiao_ota_install_command_from_v2(const xiao_ota_command_v2_t *cmd,
                                      xiao_ota_install_command_t *out) {
  xiao_ota_wire_descriptor_t w;
  memset(out, 0, sizeof(*out));
  if (!xiao_ota_wire_descriptor_decode(cmd->wire_descriptor, &w)) return false;
  out->transaction_nonce = cmd->transaction_nonce;
  out->target_id = ((uint32_t)w.board_family << 16) | w.board_variant;
  out->role_id = w.role;
  /*
   * The wire descriptor has no per-device targeting field: normalize v2 to
   * always-broadcast. These two fields are NOT part of the signed 59
   * bytes, so this is a fixed, non-attacker-controlled normalization, not
   * a policy relaxation of anything the signature covers.
   */
  out->device_address = 0;
  out->allow_broadcast_address = 1;
  out->required_boot_capability_flags = w.min_boot_capabilities;
  out->monotonic_counter = w.security_counter;
  out->image_size_bytes = w.exact_size_bytes;
  out->app_address = w.app_address;
  out->format_id = w.format_id;
  out->key_id = w.key_id;
  out->algorithm_id = w.algorithm_id;
  memcpy(out->image_hash_sha256, w.sha256, 32);
  out->active_image_extent = cmd->active_image_extent;
  memcpy(out->active_image_hash_sha256, cmd->active_image_hash_sha256, 32);
  return true; /* w.role is uint8_t, so role<=255 always holds by construction. */
}

bool xiao_ota_install_command_decode(const xiao_ota_command_any_t *any,
                                     xiao_ota_install_command_t *out) {
  uint16_t version;
  memcpy(&version, (const uint8_t *)any + 4, sizeof(version));
  if (version == XIAO_OTA_COMMAND_VERSION_LEGACY_V1) {
    return xiao_ota_install_command_from_v1(&any->v1, out);
  }
  if (version == XIAO_OTA_COMMAND_VERSION_WIRE_V2) {
    return xiao_ota_install_command_from_v2(&any->v2, out);
  }
  memset(out, 0, sizeof(*out));
  return false;
}

bool xiao_ota_install_command_static_identity_valid(
    const xiao_ota_install_command_t *cmd, uint64_t this_device_address) {
  if (cmd == NULL) return false;
  /* Checked against this build's compiled-in board profile, never a
   * wildcard/"matches anything" value -- see XIAO_OTA_BOARD_TARGET. */
  if (cmd->target_id != XIAO_OTA_BOARD_TARGET) return false;
  /* Checked against THIS build's compiled role identity
   * (XIAO_OTA_COMPILED_ROLE_ID, 0=companion/1=repeater), never a
   * wildcard -- a role-1 binary refuses a role-0-targeted command and
   * vice versa. XIAO_OTA_ROLE_ANY (0) is simply the companion role's own
   * wire value under this exact-equality check, not a separate
   * "matches anything" case. */
  if (cmd->role_id != XIAO_OTA_COMPILED_ROLE_ID) return false;
  if (cmd->app_address != XIAO_OTA_APP_START) return false;
  if (cmd->format_id != XIAO_OTA_DESCRIPTOR_FORMAT) return false;
  if (cmd->key_id != XIAO_OTA_KEY_ID) return false;
  if (cmd->algorithm_id != XIAO_OTA_ALGORITHM_ED25519) return false;
  if ((cmd->required_boot_capability_flags & XIAO_OTA_CAP_QSPI_INSTALL) == 0) return false;
  /* Candidate/install size capped to XIAO_OTA_INSTALL_MAX_SIZE (708,608
   * bytes, 0x27000..0xD4000), not the full XIAO_OTA_CANDIDATE_SIZE
   * (811,008 bytes, 0x27000..0xED000): 0xD4000..0xED000 is where v1.17's
   * own internal filesystem lives today, and letting an otherwise-valid
   * install erase/overwrite into it would be unsafe. XIAO_OTA_CANDIDATE_
   * SIZE/XIAO_OTA_BACKUP_SIZE remain a separate, larger PHYSICAL
   * placement stride only (see the active/backup extent comment right
   * below) -- never a writable-capacity bound in their own right. */
  if (cmd->image_size_bytes == 0 || cmd->image_size_bytes > XIAO_OTA_INSTALL_MAX_SIZE) return false;
  if ((cmd->image_size_bytes & 3u) != 0) return false;
  /*
   * The active/backup image extent is bounded by the SAME writable
   * image-capacity contract as the install size above
   * (XIAO_OTA_INSTALL_MAX_SIZE, 0xAD000, matching the shared
   * src/ota/platform/Nrf52FlashLayoutContract.h's
   * OTA_NRF52_IMAGE_CAPACITY_BYTES -- see xiao_ota_layout.h's
   * cross-check static assertions), NOT XIAO_OTA_BACKUP_SIZE/
   * XIAO_OTA_CANDIDATE_SIZE (0xC6000): those two describe the fixed
   * PHYSICAL bank-to-bank placement stride only, and the 0xC6000-
   * 0xAD000 = 0x19000 tail past the capacity boundary in each bank is a
   * separate, foreign, global identity/security store this project must
   * never erase or write into. A backup/restore extent this large would
   * do exactly that on the external QSPI backup bank (and, on restore,
   * would also overwrite v1.17's own internal filesystem region) -- so
   * this bound is not "the always-safe read+copy size" it once was
   * assumed to be; it is a real destructive-write bound like the
   * install size above.
   */
  if (cmd->active_image_extent == 0 || cmd->active_image_extent > XIAO_OTA_INSTALL_MAX_SIZE) return false;
  if ((cmd->active_image_extent & 3u) != 0) return false;
  if (cmd->device_address != this_device_address &&
      !(cmd->device_address == 0 && cmd->allow_broadcast_address == 1)) {
    return false;
  }
  return true;
}

bool xiao_ota_install_command_policy_valid(const xiao_ota_install_command_t *cmd,
                                           uint32_t counter_floor,
                                           uint32_t expected_active_extent,
                                           uint64_t this_device_address) {
  if (cmd == NULL) return false;
  if (!xiao_ota_install_command_static_identity_valid(cmd, this_device_address)) {
    return false;
  }
  if (cmd->monotonic_counter <= counter_floor) return false;
  if (cmd->active_image_extent != expected_active_extent) return false;
  return true;
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

/*
 * True when the boot flow may accept a newly written, validly signed install
 * command and start a fresh install transaction. EMPTY/no-state (nothing has
 * ever run) and CONFIRMED (the last install finished cleanly) always accept.
 * FAILED also accepts: it is only reached after a completed rollback whose
 * restored bank_0 settings and image hash were independently verified before
 * FAILED was persisted (see xiao_ota_boot_process()), so the device is
 * already running known-good code -- refusing new commands here would
 * permanently disable OTA after a single rejected/interrupted candidate.
 * Every other phase means a transaction is mid-flight and must run to
 * completion (or force_recovery()) before a new command can be considered.
 */
bool xiao_ota_command_acceptable_phase(bool have_state, xiao_ota_phase_t phase) {
  return !have_state || phase == XIAO_OTA_PHASE_EMPTY ||
         phase == XIAO_OTA_PHASE_CONFIRMED || phase == XIAO_OTA_PHASE_FAILED;
}

bool xiao_ota_command_is_retry_of_failed_transaction(
    bool have_state, xiao_ota_phase_t phase,
    uint64_t state_transaction_nonce, uint32_t state_candidate_counter,
    const uint8_t state_candidate_hash[32], uint64_t intent_transaction_nonce,
    uint32_t intent_monotonic_counter, const uint8_t intent_image_hash[32]) {
  return have_state && phase == XIAO_OTA_PHASE_FAILED &&
         state_transaction_nonce == intent_transaction_nonce &&
         state_candidate_counter == intent_monotonic_counter &&
         memcmp(state_candidate_hash, intent_image_hash, 32) == 0;
}

bool xiao_ota_confirmation_hash_bound_extent_valid(
    bool fresh_active_extent_valid, uint32_t fresh_active_extent,
    uint32_t max_candidate_extent, const uint8_t fresh_hash[32],
    const uint8_t installed_hash[32]) {
  return fresh_active_extent_valid && fresh_active_extent != 0 &&
         fresh_active_extent <= max_candidate_extent &&
         memcmp(fresh_hash, installed_hash, 32) == 0;
}
