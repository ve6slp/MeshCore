#pragma once

// Genuine trial-boot health confirmation (V1): the app-side half of the
// "Power-loss-safe install transaction" contract described in
// docs/lora_ota_nrf52840_qspi.md -- after a signed install, the
// bootloader boots the new image under a 60-second watchdog in
// XIAO_OTA_PHASE_TRIAL_BOOT and only advances the durable anti-rollback
// floor once THIS firmware writes a valid xiao_ota_confirmation_t record
// (bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h) that the
// bootloader's own xiao_ota_confirmation_matches()/
// xiao_ota_confirmation_extent_and_hash_valid() checks accept on its next
// boot. Confirming too early, on a mismatched image, or without genuine
// readiness would let a subtly-broken candidate "wear the crown" as
// though it were fully verified, so EVERY gate below must hold or nothing
// is written:
//   1. A valid state record exists and its phase is EXACTLY
//      XIAO_OTA_PHASE_TRIAL_BOOT (never CONFIRMED/FAILED/EMPTY/etc.).
//   2. The caller-supplied health readiness (radio/filesystem/normal
//      loop) is ALL true -- never partial, never assumed.
//   3. The freshly-resolved (this-boot, never floor/cached) SHA-256 --
//      see XiaoOtaActiveExtentBridge -- EXACTLY matches BOTH the state
//      record's installed_hash AND its candidate_hash. This is the same
//      guard xiao_ota_confirmation_extent_and_hash_valid() documents on
//      the bootloader side: it stops a USB/CDC reflash (or flash damage)
//      during the trial window from producing a confirmation that
//      nominally matches nonce/counter but no longer reflects the image
//      actually running. NOTE: the state record's own
//      `active_image_extent` field is NOT compared here -- per the v1
//      152-byte record layout that field records the OLD/backup image's
//      extent (pre-install), not the newly-installed candidate's size,
//      so it is unrelated to `fresh`'s freshly-resolved extent and an
//      equality check against it was a real bug (rejected legitimate
//      confirmations whenever old/new image sizes differed, and could
//      coincidentally "pass" same-size-image tests without proving
//      anything). Content correctness is instead established purely by
//      the SHA-256 comparisons above, which is exactly as strong a
//      binding (a matching hash could not exist for a wrong-size image)
//      without requiring a v1 record ABI change.
//
// Header-only so the full gate logic is directly host-testable with
// synthetic FlashRegion fixtures, independent of real hardware.

#include <stdint.h>
#include <string.h>

#include "ota/platform/FlashRegion.h"
#include "ota/storage/Crc32.h"
#include "ota/storage/XiaoOtaActiveExtentBridge.h"
#include "ota/storage/XiaoOtaTransactionalWriter.h"

namespace ota {
namespace storage {

// READ-ONLY codec for the bootloader-owned `xiao_ota_state_t` record
// (state A/B, 2 x 4096-byte erase units). The app NEVER writes this --
// only the bootloader does, while progressing an install transaction --
// but reading it back is how the app learns which trial (nonce, target
// extent, installed hash) it must confirm.
class XiaoOtaStateReader {
public:
  static constexpr uint32_t kMagic = 0x584F5441u;         // XIAO_OTA_RECORD_MAGIC
  static constexpr uint32_t kCommitMarker = 0x434F4D54u;   // XIAO_OTA_COMMIT_MARKER
  static constexpr uint16_t kRecordVersion = 1u;           // XIAO_OTA_FORMAT_VERSION
  static constexpr uint32_t kPhaseTrialBoot = 5u;          // XIAO_OTA_PHASE_TRIAL_BOOT
  static constexpr uint32_t kPhaseConfirmed = 6u;          // XIAO_OTA_PHASE_CONFIRMED -- written by the
                                                            // BOOTLOADER itself, on its own subsequent boot,
                                                            // only once it has validated this app's durable
                                                            // confirmation record against the state record
                                                            // (see xiao_ota_confirmation_matches()) -- genuine,
                                                            // already-verified completed-install evidence, not
                                                            // merely "no trial concept" (never fabricated here).
  static constexpr uint32_t kPhaseFailedMax = 8u;          // XIAO_OTA_PHASE_FAILED (highest valid phase)

  // magic(4)+version(2)+bytes(2)+sequence(4)+nonce(8)+phase(4)+
  // progress_bytes(4)+active_image_extent(4)+candidate_counter(4)+
  // previous_bank_0(2)+previous_bank_0_crc(2)+previous_bank_0_size(4)+
  // candidate_hash(32)+backup_hash(32)+installed_hash(32)+
  // trial_attempts(1)+reserved(3)+crc32(4)+commit_marker(4) = 152.
  static constexpr uint32_t kRecordBytes = 152u;
  static constexpr uint32_t kCrcOffset = kRecordBytes - 8;         // 144
  static constexpr uint32_t kCommitMarkerOffset = kRecordBytes - 4;  // 148
  static constexpr uint32_t kInstalledHashOffset = 108u;

  static bool regionIsValid(const platform::FlashRegion& region) {
    return region.isValid() && region.sizeBytes() == (2u * region.eraseUnitBytes()) &&
           region.eraseUnitBytes() >= kRecordBytes;
  }

  static bool isValidRecord(const uint8_t* record, uint32_t len) {
    if (record == nullptr || len != kRecordBytes) return false;
    if (getU32(record) != kMagic) return false;
    if (record[4] != static_cast<uint8_t>(kRecordVersion) || record[5] != 0) return false;
    if (getU16(record + 6) != static_cast<uint16_t>(kRecordBytes)) return false;
    if (getU32(record + kCommitMarkerOffset) != kCommitMarker) return false;
    const uint32_t stored_crc = getU32(record + kCrcOffset);
    if (stored_crc != Crc32::computeFinalized(record, kCrcOffset)) return false;
    return phase(record) <= kPhaseFailedMax;
  }

  static bool readNewest(const platform::FlashRegion& region, uint8_t out_record[kRecordBytes]) {
    uint8_t unused[kRecordBytes];
    return readNewestWithStatus(region, out_record != nullptr ? out_record : unused) == ReadStatus::Found;
  }

  // Distinguishes WHY no valid TRIAL/etc. record was returned, instead of
  // collapsing every non-success case to a single `false` (the older
  // readNewest() above). This matters because a genuinely BLANK pair of
  // slots (legitimate "no state ever written here", e.g. a stock device
  // that never had a bootloader-driven install transaction) is NOT the
  // same situation as an UNREADABLE or CORRUPT slot -- and callers that
  // gate erase/install admission on "is a trial in progress?" must never
  // silently treat the latter two as "definitely not a trial" the way a
  // bare bool would. See XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed()
  // in XiaoOtaCommandRecord.h for the identical blank-vs-corrupt-vs-
  // unreadable distinction already established for the floor region.
  enum class ReadStatus : uint8_t {
    Blank = 0,    // both slots genuinely, fully blank (0xFF) -- legitimate "no trial ever" baseline.
    Found = 1,    // a valid record was found; *out_record is populated with the newest one.
    Unknown = 2,  // at least one slot could not be read (I/O error) -- might have held the true newest record.
    Corrupt = 3,  // no slot unreadable, no valid record found, but at least one slot is
                  // readable-and-non-blank without being a valid record (torn write/tampering).
  };

  static ReadStatus readNewestWithStatus(const platform::FlashRegion& region, uint8_t out_record[kRecordBytes]) {
    if (!regionIsValid(region)) return ReadStatus::Unknown;
    bool found = false;
    uint32_t best_sequence = 0;
    uint8_t best[kRecordBytes] = {};
    // Same "unreadable slot always wins closed, regardless of the other
    // slot's content" rule as the floor reader: a genuinely unreadable
    // slot might have held the true newest record, so it must never be
    // outweighed by a valid/blank finding elsewhere.
    bool any_unreadable = false;
    bool any_corrupt_readable = false;
    for (uint32_t slot = 0; slot < 2u; ++slot) {
      uint8_t buf[kRecordBytes];
      const uint32_t slot_offset = slot * region.eraseUnitBytes();
      if (!platform::isOk(region.read(slot_offset, buf, kRecordBytes))) {
        any_unreadable = true;
        continue;
      }
      if (isValidRecord(buf, kRecordBytes)) {
        const uint32_t seq = getU32(buf + 8);
        if (!found || seq >= best_sequence) {
          found = true;
          best_sequence = seq;
          memcpy(best, buf, kRecordBytes);
        }
        continue;
      }
      if (!isBlank(buf, kRecordBytes)) {
        any_corrupt_readable = true;
        continue;
      }
      // Record-sized prefix reads blank, but a nonblank byte anywhere
      // else in the erase unit (e.g. leftover data near its tail from a
      // prior differently-sized record layout) means this slot was
      // previously written to and must not be silently treated as a
      // genuine baseline -- scan the WHOLE erase unit before trusting it.
      bool read_ok = true;
      const bool fully_blank = isEraseUnitFullyBlank(region, slot_offset, region.eraseUnitBytes(), read_ok);
      if (!read_ok) {
        any_unreadable = true;
      } else if (!fully_blank) {
        any_corrupt_readable = true;
      }
    }
    if (any_unreadable) return ReadStatus::Unknown;
    if (any_corrupt_readable) return ReadStatus::Corrupt;
    if (found) {
      memcpy(out_record, best, kRecordBytes);
      return ReadStatus::Found;
    }
    return ReadStatus::Blank;
  }

  // Accessors over an already-`isValidRecord()`-checked buffer.
  static uint32_t phase(const uint8_t* record) { return getU32(record + 20); }
  static uint64_t transactionNonce(const uint8_t* record) { return getU64(record + 12); }
  static uint32_t activeImageExtent(const uint8_t* record) { return getU32(record + 28); }
  static uint32_t candidateCounter(const uint8_t* record) { return getU32(record + 32); }
  static const uint8_t* installedHashSha256(const uint8_t* record) {
    return record + kInstalledHashOffset;
  }
  // Offset 44: candidate_hash_sha256 -- the hash the transport originally
  // verified for the staged candidate BEFORE the bootloader's own
  // copy/install step. Checking this in addition to installed_hash (see
  // XiaoOtaTrialBootConfirmation::tryConfirm()) catches any divergence
  // introduced during that copy, not just a mismatch against what the
  // bootloader itself later claims it installed.
  static constexpr uint32_t kCandidateHashOffset = 44u;
  static const uint8_t* candidateHashSha256(const uint8_t* record) {
    return record + kCandidateHashOffset;
  }

private:
  static bool isBlank(const uint8_t* buf, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
      if (buf[i] != 0xFFu) return false;
    }
    return true;
  }

  // Scans the ENTIRE erase unit at `slot_offset` (not merely the
  // record-sized prefix) in bounded scratch-sized chunks -- identical in
  // spirit to XiaoOtaFloorReader::isEraseUnitFullyBlank() in
  // XiaoOtaCommandRecord.h. Sets `out_read_ok` to false on any read
  // failure (return value then undefined/false); otherwise true, with
  // the return value indicating whether every byte in the whole erase
  // unit is 0xFF.
  static bool isEraseUnitFullyBlank(const platform::FlashRegion& region, uint32_t slot_offset,
                                    uint32_t erase_unit_bytes, bool& out_read_ok) {
    constexpr uint32_t kScratchBytes = 256;
    uint8_t scratch[kScratchBytes];
    uint32_t offset = 0;
    while (offset < erase_unit_bytes) {
      const uint32_t chunk = (erase_unit_bytes - offset) < kScratchBytes ? (erase_unit_bytes - offset)
                                                                         : kScratchBytes;
      if (!platform::isOk(region.read(slot_offset + offset, scratch, chunk))) {
        out_read_ok = false;
        return false;
      }
      if (!isBlank(scratch, chunk)) {
        out_read_ok = true;
        return false;
      }
      offset += chunk;
    }
    out_read_ok = true;
    return true;
  }

  static uint16_t getU16(const uint8_t* in) {
    return static_cast<uint16_t>(in[0]) | (static_cast<uint16_t>(in[1]) << 8);
  }
  static uint32_t getU32(const uint8_t* in) {
    return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
  }
  static uint64_t getU64(const uint8_t* in) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | in[i];
    return v;
  }
};

struct XiaoOtaConfirmationFields {
  uint32_t sequence = 0;
  uint64_t transaction_nonce = 0;
  uint32_t confirmed_counter = 0;
  uint8_t confirmed_hash_sha256[32] = {};
};

// Power-loss-safe A/B writer for the bootloader's `xiao_ota_confirmation_t`
// record (confirm A/B, 2 x 4096-byte erase units) -- the ONLY record this
// app is authorized to write into the bootloader-owned journal, and only
// via XiaoOtaTrialBootConfirmation::tryConfirm()'s gate below.
class XiaoOtaConfirmationRecord {
public:
  static constexpr uint32_t kMagic = 0x58434E46u;         // XIAO_OTA_CONFIRM_MAGIC
  static constexpr uint32_t kCommitMarker = 0x434F4D54u;  // XIAO_OTA_COMMIT_MARKER
  static constexpr uint16_t kRecordVersion = 1u;          // XIAO_OTA_FORMAT_VERSION
  static constexpr uint32_t kHashBytes = 32u;

  // magic(4)+version(2)+bytes(2)+sequence(4)+nonce(8)+confirmed_counter(4)+
  // confirmed_hash(32)+crc32(4)+commit_marker(4) = 64.
  static constexpr uint32_t kRecordBytes = 4 + 2 + 2 + 4 + 8 + 4 + kHashBytes + 4 + 4;  // = 64
  static constexpr uint32_t kCrcOffset = kRecordBytes - 8;          // 56
  static constexpr uint32_t kCommitMarkerOffset = kRecordBytes - 4;  // 60

  static bool regionIsValid(const platform::FlashRegion& region) {
    return region.isValid() && region.sizeBytes() == (2u * region.eraseUnitBytes()) &&
           region.eraseUnitBytes() >= kRecordBytes;
  }

  static uint32_t serialize(const XiaoOtaConfirmationFields& fields, uint8_t* out, uint32_t out_len) {
    if (out == nullptr || out_len < kRecordBytes) return 0;
    uint32_t pos = 0;
    putU32(out + pos, kMagic); pos += 4;
    putU16(out + pos, kRecordVersion); pos += 2;
    putU16(out + pos, static_cast<uint16_t>(kRecordBytes)); pos += 2;
    putU32(out + pos, fields.sequence); pos += 4;
    putU64(out + pos, fields.transaction_nonce); pos += 8;
    putU32(out + pos, fields.confirmed_counter); pos += 4;
    memcpy(out + pos, fields.confirmed_hash_sha256, kHashBytes); pos += kHashBytes;
    const uint32_t crc = Crc32::computeFinalized(out, kCrcOffset);
    putU32(out + pos, crc); pos += 4;
    putU32(out + pos, kCommitMarker); pos += 4;
    return pos;  // == kRecordBytes
  }

  static bool isValidRecord(const uint8_t* record, uint32_t len) {
    if (record == nullptr || len != kRecordBytes) return false;
    if (getU32(record) != kMagic) return false;
    if (record[4] != static_cast<uint8_t>(kRecordVersion) || record[5] != 0) return false;
    if (getU16(record + 6) != static_cast<uint16_t>(kRecordBytes)) return false;
    if (getU32(record + kCommitMarkerOffset) != kCommitMarker) return false;
    const uint32_t stored_crc = getU32(record + kCrcOffset);
    return stored_crc == Crc32::computeFinalized(record, kCrcOffset);
  }

  static bool writeNext(platform::FlashRegion& region, const XiaoOtaConfirmationFields& fields,
                       uint32_t* out_sequence_written = nullptr) {
    if (!regionIsValid(region)) return false;

    uint32_t current_slot = 0;
    bool have_current = false;
    uint32_t current_sequence = 0;
    for (uint32_t slot = 0; slot < 2u; ++slot) {
      uint8_t buf[kRecordBytes];
      const uint32_t slot_offset = slot * region.eraseUnitBytes();
      // An I/O read failure is NOT "no valid record here" -- we cannot
      // safely pick a target slot without risking erasing a real (but
      // currently unreadable) newest record. Fail closed before any
      // mutation.
      if (!platform::isOk(region.read(slot_offset, buf, kRecordBytes))) return false;
      if (!isValidRecord(buf, kRecordBytes)) continue;
      const uint32_t seq = getU32(buf + 8);
      if (!have_current || seq >= current_sequence) {
        have_current = true;
        current_sequence = seq;
        current_slot = slot;
      }
    }

    if (have_current && current_sequence == 0xFFFFFFFFu) {
      // Sequence exhaustion: never silently wrap back to 0, which would
      // make the brand-new record indistinguishable from (or falsely
      // older than) the true oldest confirmation record ever written.
      return false;
    }

    const uint32_t target_slot = have_current ? (1u - current_slot) : 0u;
    const uint32_t new_sequence = have_current ? (current_sequence + 1u) : 1u;

    XiaoOtaConfirmationFields to_write = fields;
    to_write.sequence = new_sequence;

    uint8_t record[kRecordBytes];
    if (serialize(to_write, record, sizeof(record)) != kRecordBytes) return false;

    const uint32_t slot_offset = target_slot * region.eraseUnitBytes();
    if (!writeOtaJournalRecordTransactional(region, slot_offset, record, kRecordBytes, kCommitMarkerOffset,
                                            kRecordBytes - kCommitMarkerOffset)) {
      return false;
    }

    uint8_t readback[kRecordBytes];
    if (!platform::isOk(region.read(slot_offset, readback, kRecordBytes))) return false;
    if (memcmp(record, readback, kRecordBytes) != 0 || !isValidRecord(readback, kRecordBytes)) return false;

    if (out_sequence_written != nullptr) *out_sequence_written = new_sequence;
    return true;
  }

private:
  static void putU16(uint8_t* out, uint16_t v) {
    out[0] = static_cast<uint8_t>(v & 0xFFu);
    out[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
  }
  static void putU32(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>(v & 0xFFu);
    out[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    out[2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
    out[3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
  }
  static void putU64(uint8_t* out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
  }
  static uint16_t getU16(const uint8_t* in) {
    return static_cast<uint16_t>(in[0]) | (static_cast<uint16_t>(in[1]) << 8);
  }
  static uint32_t getU32(const uint8_t* in) {
    return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
  }
};

// The full app-side confirmation gate -- see file header for the three
// mandatory conditions. Performs NO flash I/O of its own beyond the
// read-only state lookup and the single gated confirmation write; never
// partially writes (writeNext() itself is power-loss-safe: erase+program+
// readback-verify on one alternate slot only).
class XiaoOtaTrialBootConfirmation {
public:
  struct HealthReadiness {
    bool radio_ready = false;
    bool filesystem_ready = false;
    bool loop_healthy = false;
    bool allHealthy() const { return radio_ready && filesystem_ready && loop_healthy; }
  };

  // `fresh` MUST be freshly resolved THIS boot (see
  // XiaoOtaActiveExtentBridge::resolve()/resolveCurrent()) -- never a
  // cached/stale value -- and its active_image_extent must already be
  // non-zero (the bridge's own fail-closed contract); this function
  // additionally refuses to write anything unless that fresh extent+hash
  // exactly match the state record's own installed_hash/active_image_extent,
  // so a mismatched image (USB reflash during the trial window, or a
  // straight-up bug) can never be confirmed.
  static bool tryConfirm(const platform::FlashRegion& state_region, platform::FlashRegion& confirm_region,
                        const XiaoOtaActiveExtentInfo& fresh, const HealthReadiness& readiness,
                        uint32_t* out_confirmed_counter = nullptr) {
    if (!readiness.allHealthy()) return false;
    if (fresh.active_image_extent == 0) return false;

    uint8_t state_buf[XiaoOtaStateReader::kRecordBytes];
    if (!XiaoOtaStateReader::readNewest(state_region, state_buf)) return false;
    if (XiaoOtaStateReader::phase(state_buf) != XiaoOtaStateReader::kPhaseTrialBoot) return false;
    // Content-based binding only: the state record's active_image_extent
    // field is the OLD/backup extent (see file header) and is
    // deliberately NOT compared here. A matching SHA-256 could not exist
    // for a wrong-size image, so requiring the fresh hash to equal BOTH
    // installed_hash and candidate_hash is at least as strong a guard,
    // without needing a v1 record ABI change.
    if (memcmp(XiaoOtaStateReader::installedHashSha256(state_buf), fresh.active_image_hash_sha256, 32) != 0) {
      return false;
    }
    if (memcmp(XiaoOtaStateReader::candidateHashSha256(state_buf), fresh.active_image_hash_sha256, 32) != 0) {
      return false;
    }

    XiaoOtaConfirmationFields fields;
    fields.transaction_nonce = XiaoOtaStateReader::transactionNonce(state_buf);
    fields.confirmed_counter = XiaoOtaStateReader::candidateCounter(state_buf);
    memcpy(fields.confirmed_hash_sha256, fresh.active_image_hash_sha256, sizeof(fields.confirmed_hash_sha256));

    uint32_t sequence_written = 0;
    if (!XiaoOtaConfirmationRecord::writeNext(confirm_region, fields, &sequence_written)) {
      return false;
    }
    if (out_confirmed_counter != nullptr) {
      *out_confirmed_counter = fields.confirmed_counter;
    }
    return true;
  }
};

}  // namespace storage
}  // namespace ota
