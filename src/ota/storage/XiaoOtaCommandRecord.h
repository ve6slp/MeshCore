#pragma once

// Current nRF bootloader install-command ABI and confirmed-floor reader.
// The signed descriptor is the same canonical 59-byte payload used by OTA v4.
// Only record version 3 is encoded or accepted; obsolete command formats
// have no firmware-side compatibility layer.

#include <stdint.h>
#include <string.h>

#include "ota/platform/FlashRegion.h"
#include "ota/storage/Crc32.h"
#include "ota/storage/XiaoOtaTransactionalWriter.h"

namespace ota {
namespace storage {

struct XiaoOtaCommandV3Fields {
  uint32_t sequence = 0;
  uint64_t transaction_nonce = 0;
  uint8_t wire_descriptor[59] = {};
  uint8_t admitted_signer_public_key_ed25519[32] = {};
  uint8_t signature_ed25519[64] = {};
  uint32_t active_image_extent = 0;
  uint8_t active_image_hash_sha256[32] = {};
};

// Current bootloader install-command ABI: record version 3, 220 bytes.
class XiaoOtaCommandRecordV3 {
public:
  static constexpr uint32_t kMagic = 0x584F5441u;
  static constexpr uint32_t kCommitMarker = 0x434F4D54u;
  static constexpr uint16_t kRecordVersion = 3u;  // XIAO_OTA_COMMAND_VERSION_CURRENT
  static constexpr uint32_t kWireDescriptorBytes = 59u;  // XIAO_OTA_WIRE_DESCRIPTOR_SIZE
  static constexpr uint32_t kSignerKeyBytes = 32u;
  static constexpr uint32_t kSignatureBytes = 64u;
  static constexpr uint32_t kHashBytes = 32u;

  // magic(4) + record_version(2) + record_bytes(2) + sequence(4) +
  // nonce(8) + wire_descriptor(59) + admitted_signer_public_key(32) +
  // signature(64) + active_image_extent(4) + active_image_hash(32) +
  // reserved(1) + crc32(4) + commit_marker(4) = 220.
  static constexpr uint32_t kRecordBytes = 4 + 2 + 2 + 4 + 8 + kWireDescriptorBytes + kSignerKeyBytes +
                                            kSignatureBytes + 4 + kHashBytes + 1 + 4 + 4;  // = 220
  static constexpr uint32_t kCrcOffset = kRecordBytes - 8;           // 212
  static constexpr uint32_t kCommitMarkerOffset = kRecordBytes - 4;  // 216

  static bool regionIsValid(const platform::FlashRegion& region) {
    return region.isValid() && region.sizeBytes() == (2u * region.eraseUnitBytes()) &&
           region.eraseUnitBytes() >= kRecordBytes;
  }

  static uint32_t serialize(const XiaoOtaCommandV3Fields& fields, uint8_t* out, uint32_t out_len) {
    if (out == nullptr || out_len < kRecordBytes) {
      return 0;
    }
    uint32_t pos = 0;
    putU32(out + pos, kMagic);
    pos += 4;
    putU16(out + pos, kRecordVersion);
    pos += 2;
    putU16(out + pos, static_cast<uint16_t>(kRecordBytes));
    pos += 2;
    putU32(out + pos, fields.sequence);
    pos += 4;
    putU64(out + pos, fields.transaction_nonce);
    pos += 8;

    memcpy(out + pos, fields.wire_descriptor, kWireDescriptorBytes);
    pos += kWireDescriptorBytes;

    memcpy(out + pos, fields.admitted_signer_public_key_ed25519, kSignerKeyBytes);
    pos += kSignerKeyBytes;

    memcpy(out + pos, fields.signature_ed25519, kSignatureBytes);
    pos += kSignatureBytes;

    putU32(out + pos, fields.active_image_extent);
    pos += 4;
    memcpy(out + pos, fields.active_image_hash_sha256, kHashBytes);
    pos += kHashBytes;

    out[pos] = 0;  // reserved
    pos += 1;

    const uint32_t crc = Crc32::computeFinalized(out, kCrcOffset);
    putU32(out + pos, crc);
    pos += 4;

    putU32(out + pos, kCommitMarker);
    pos += 4;

    return pos;  // == kRecordBytes
  }

  static bool isValidRecord(const uint8_t* record, uint32_t len) {
    if (record == nullptr || len != kRecordBytes) {
      return false;
    }
    if (getU32(record) != kMagic) return false;
    if (record[4] != static_cast<uint8_t>(kRecordVersion) || record[5] != 0) return false;
    if (getU16(record + 6) != static_cast<uint16_t>(kRecordBytes)) return false;
    if (getU32(record + kCommitMarkerOffset) != kCommitMarker) return false;
    const uint32_t stored_crc = getU32(record + kCrcOffset);
    return stored_crc == Crc32::computeFinalized(record, kCrcOffset);
  }

  static bool writeNext(platform::FlashRegion& region, const XiaoOtaCommandV3Fields& fields,
                        uint32_t* out_sequence_written = nullptr);

  // An unreadable slot fails the entire lookup closed.
  static bool readNewest(const platform::FlashRegion& region, uint8_t out_record[kRecordBytes]);

  static constexpr uint32_t kWireDescriptorOffset = 20u;
  // Admitted-signer key immediately follows the 59-byte wire descriptor.
  static constexpr uint32_t kAdmittedSignerKeyOffset = kWireDescriptorOffset + kWireDescriptorBytes;  // = 79

  static uint32_t sequenceOf(const uint8_t* record) { return getU32(record + 8); }
  static uint64_t transactionNonceOf(const uint8_t* record) { return getU64(record + 12); }
  static const uint8_t* wireDescriptorOf(const uint8_t* record) { return record + kWireDescriptorOffset; }
  static const uint8_t* admittedSignerKeyOf(const uint8_t* record) { return record + kAdmittedSignerKeyOffset; }
  static constexpr uint32_t kSignatureOffset = kAdmittedSignerKeyOffset + kSignerKeyBytes;
  static constexpr uint32_t kActiveExtentOffset = kSignatureOffset + kSignatureBytes;
  static const uint8_t* signatureOf(const uint8_t* record) { return record + kSignatureOffset; }
  static uint32_t activeImageExtentOf(const uint8_t* record) { return getU32(record + kActiveExtentOffset); }
  static const uint8_t* activeImageHashOf(const uint8_t* record) { return record + kActiveExtentOffset + 4; }

private:
  static bool readSlot(const platform::FlashRegion& region, uint32_t slot, uint8_t out[kRecordBytes]) {
    const uint32_t slot_offset = slot * region.eraseUnitBytes();
    return platform::isOk(region.read(slot_offset, out, kRecordBytes));
  }

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
    for (int i = 0; i < 8; ++i) {
      out[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    }
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
    for (int i = 7; i >= 0; --i) {
      v = (v << 8) | static_cast<uint64_t>(in[i]);
    }
    return v;
  }
};

inline bool XiaoOtaCommandRecordV3::writeNext(platform::FlashRegion& region, const XiaoOtaCommandV3Fields& fields,
                                              uint32_t* out_sequence_written) {
  if (!regionIsValid(region)) {
    return false;
  }

  uint32_t current_slot = 0;
  bool have_current = false;
  uint32_t current_sequence = 0;
  for (uint32_t slot = 0; slot < 2u; ++slot) {
    uint8_t record[kRecordBytes];
    if (!readSlot(region, slot, record)) return false;
    if (!isValidRecord(record, sizeof(record))) continue;
    const uint32_t sequence = sequenceOf(record);
    if (!have_current || sequence >= current_sequence) {
      have_current = true;
      current_sequence = sequence;
      current_slot = slot;
    }
  }

  if (have_current && current_sequence == 0xFFFFFFFFu) {
    return false;  // sequence exhaustion: refuse rather than wrap to 0.
  }

  const uint32_t target_slot = have_current ? (1u - current_slot) : 0u;
  const uint32_t new_sequence = have_current ? (current_sequence + 1u) : 1u;

  XiaoOtaCommandV3Fields to_write = fields;
  to_write.sequence = new_sequence;

  uint8_t record[kRecordBytes];
  if (serialize(to_write, record, sizeof(record)) != kRecordBytes) {
    return false;
  }

  const uint32_t slot_offset = target_slot * region.eraseUnitBytes();
  if (!writeOtaJournalRecordTransactional(region, slot_offset, record, kRecordBytes, kCommitMarkerOffset,
                                          kRecordBytes - kCommitMarkerOffset)) {
    return false;
  }

  uint8_t readback[kRecordBytes];
  if (!platform::isOk(region.read(slot_offset, readback, kRecordBytes))) {
    return false;
  }
  if (memcmp(record, readback, kRecordBytes) != 0 || !isValidRecord(readback, kRecordBytes)) {
    return false;
  }

  if (out_sequence_written != nullptr) {
    *out_sequence_written = new_sequence;
  }
  return true;
}

inline bool XiaoOtaCommandRecordV3::readNewest(const platform::FlashRegion& region,
                                               uint8_t out_record[kRecordBytes]) {
  if (!regionIsValid(region)) return false;
  bool found = false;
  uint32_t best_sequence = 0;
  uint32_t best_slot = 0;
  for (uint32_t slot = 0; slot < 2u; ++slot) {
    uint8_t record[kRecordBytes];
    if (!readSlot(region, slot, record)) return false;
    if (!isValidRecord(record, sizeof(record))) continue;
    const uint32_t sequence = sequenceOf(record);
    if (!found || sequence >= best_sequence) {
      found = true;
      best_sequence = sequence;
      best_slot = slot;
    }
  }
  if (!found) return false;
  uint8_t buf[kRecordBytes];
  if (!readSlot(region, best_slot, buf)) return false;
  if (!isValidRecord(buf, kRecordBytes)) return false;
  memcpy(out_record, buf, kRecordBytes);
  return true;
}

// Read-only bootloader-owned confirmed counter, hash and extent evidence.
class XiaoOtaFloorReader {
public:
  static constexpr uint32_t kMagic = 0x58464C52u;  // XIAO_OTA_FLOOR_MAGIC
  static constexpr uint32_t kCommitMarker = 0x434F4D54u;
  static constexpr uint16_t kRecordVersion = 1u;
  // magic(4)+version(2)+bytes(2)+sequence(4)+confirmed_counter_floor(4)+
  // active_image_extent(4)+confirmed_hash_sha256(32)+crc32(4)+marker(4) = 60.
  static constexpr uint32_t kRecordBytes = 4 + 2 + 2 + 4 + 4 + 4 + 32 + 4 + 4;
  static constexpr uint32_t kCrcOffset = kRecordBytes - 8;          // 52
  static constexpr uint32_t kCommitMarkerOffset = kRecordBytes - 4;  // 56

  static bool isValidRecord(const uint8_t* record, uint32_t len) {
    if (record == nullptr || len != kRecordBytes) return false;
    if (getU32(record) != kMagic) return false;
    if (record[4] != static_cast<uint8_t>(kRecordVersion) || record[5] != 0) return false;
    if (getU16(record + 6) != static_cast<uint16_t>(kRecordBytes)) return false;
    if (getU32(record + kCommitMarkerOffset) != kCommitMarker) return false;
    return getU32(record + kCrcOffset) == Crc32::computeFinalized(record, kCrcOffset);
  }

  // `region` must be exactly 2 erase units (the floor A/B pair). Returns
  // true and fills `out_confirmed_counter_floor` from the newest valid of
  // the two slots, false if neither slot holds a valid record yet (e.g. a
  // never-updated device) -- callers must treat that as "no known floor",
  // not "floor is 0".
  static bool readNewestConfirmedCounter(const platform::FlashRegion& region,
                                        uint32_t& out_confirmed_counter_floor) {
    if (!region.isValid() || region.sizeBytes() != (2u * region.eraseUnitBytes()) ||
        region.eraseUnitBytes() < kRecordBytes) {
      return false;
    }
    bool found = false;
    uint32_t best_sequence = 0;
    uint32_t best_floor = 0;
    for (uint32_t slot = 0; slot < 2u; ++slot) {
      uint8_t buf[kRecordBytes];
      // An unreadable slot must never be silently skipped: it could have
      // held the true newest record, so this whole lookup must fail
      // closed rather than return a stale/wrong value from the other slot.
      if (!platform::isOk(region.read(slot * region.eraseUnitBytes(), buf, kRecordBytes))) return false;
      if (!isValidRecord(buf, kRecordBytes)) continue;
      const uint32_t seq = getU32(buf + 8);
      if (!found || seq >= best_sequence) {
        found = true;
        best_sequence = seq;
        best_floor = getU32(buf + 12);
      }
    }
    if (!found) return false;
    out_confirmed_counter_floor = best_floor;
    return true;
  }

  // Same slots as readNewestConfirmedCounter(), but distinguishes "no
  // confirmed floor yet" (both slots genuinely blank/erased, i.e. an
  // untouched flash region -- a legitimate first-ever-device baseline of
  // 0) from "a slot holds non-blank data that fails validation" (corrupt
  // -- must fail closed, never silently default to 0). This matters
  // because readNewestConfirmedCounter() above conflates those two cases
  // (both return false), which would let a corrupt/tampered floor slot be
  // silently treated as counter==0 by a naive caller.
  //
  // Returns true (trust `out_confirmed_counter_floor`) when either a
  // valid record was found, OR both slots are entirely 0xFF (blank).
  // Returns false (fail closed -- caller MUST refuse to proceed, never
  // substitute 0) when at least one slot is non-blank but invalid, or a
  // slot could not be read, and no valid record was found.
  static bool readNewestConfirmedCounterFailClosed(const platform::FlashRegion& region,
                                                    uint32_t& out_confirmed_counter_floor) {
    return readNewestConfirmedEvidenceFailClosed(region, out_confirmed_counter_floor, nullptr, nullptr);
  }

  static bool readNewestConfirmedEvidenceFailClosed(const platform::FlashRegion& region,
                                                    uint32_t& out_confirmed_counter_floor,
                                                    uint8_t* out_confirmed_hash,
                                                    uint32_t* out_active_extent) {
    if (out_confirmed_hash) memset(out_confirmed_hash, 0, 32);
    if (out_active_extent) *out_active_extent = 0;
    if (!region.isValid() || region.sizeBytes() != (2u * region.eraseUnitBytes()) ||
        region.eraseUnitBytes() < kRecordBytes) {
      return false;
    }
    bool found_valid = false;
    uint32_t best_sequence = 0;
    uint32_t best_floor = 0;
    uint32_t best_extent = 0;
    uint8_t best_hash[32] = {};
    // A genuinely UNREADABLE slot (I/O error) is categorically worse than
    // a readable-but-corrupt one: it might have held the true newest
    // record, so it ALWAYS fails the whole lookup closed, regardless of
    // whatever the other slot contains. A readable slot whose content is
    // simply invalid/non-blank (corruption of what is very likely an
    // older, already-superseded record) does NOT override a genuinely
    // valid record found in the other slot -- that is the normal,
    // expected steady state of an A/B pair mid-lifecycle.
    bool any_unreadable = false;
    bool any_corrupt_readable = false;
    for (uint32_t slot = 0; slot < 2u; ++slot) {
      const uint32_t slot_offset = slot * region.eraseUnitBytes();
      uint8_t buf[kRecordBytes];
      if (!platform::isOk(region.read(slot_offset, buf, kRecordBytes))) {
        any_unreadable = true;
        continue;
      }
      if (isValidRecord(buf, kRecordBytes)) {
        const uint32_t seq = getU32(buf + 8);
        if (!found_valid || seq >= best_sequence) {
          found_valid = true;
          best_sequence = seq;
          best_floor = getU32(buf + 12);
          best_extent = getU32(buf + 16);
          memcpy(best_hash, buf + 20, 32);
        }
        continue;
      }
      if (!isBlank(buf, kRecordBytes)) {
        any_corrupt_readable = true;
        continue;
      }
      // The record-sized prefix reads as blank, but that alone does not
      // prove this slot is a genuine untouched baseline: a nonblank byte
      // anywhere else in the erase unit (e.g. leftover data near its
      // tail) means this erase unit was previously written to and must
      // not be silently treated as "no record here" -- scan the WHOLE
      // erase unit before trusting the blank-baseline case.
      bool read_ok = true;
      const bool fully_blank = isEraseUnitFullyBlank(region, slot_offset, region.eraseUnitBytes(), read_ok);
      if (!read_ok) {
        any_unreadable = true;
      } else if (!fully_blank) {
        // A nonblank tail with a blank record-prefix header: not a
        // genuine baseline, but also not an I/O failure -- treat the
        // same as any other readable-but-invalid content.
        any_corrupt_readable = true;
      }
    }
    if (any_unreadable) {
      return false;  // fail closed unconditionally: an unreadable slot can never be
                      // outweighed by anything found in the other slot -- it might
                      // have held the true newest floor.
    }
    if (found_valid) {
      out_confirmed_counter_floor = best_floor;
      if (out_confirmed_hash) memcpy(out_confirmed_hash, best_hash, 32);
      if (out_active_extent) *out_active_extent = best_extent;
      return true;
    }
    if (any_corrupt_readable) {
      return false;  // fail closed: readable corruption present, no valid record found.
    }
    out_confirmed_counter_floor = 0;  // both slots genuinely, fully blank: legitimate baseline.
    return true;
  }

  // Same newest-slot search as readNewestConfirmedCounter(), but returns
  // the confirmed `active_image_extent` field (offset 16) instead of the
  // counter floor. NOTE: XiaoOtaActiveExtentBridge::resolve() no longer
  // consults this at all (removed: a confirmed floor can be stale/wrong-
  // sized after a USB reflash) -- it is retained here only as a general-
  // purpose accessor and for its own direct test coverage, not as part of
  // the active-extent-for-install-command resolution path.
  static bool readNewestActiveExtent(const platform::FlashRegion& region, uint32_t& out_active_image_extent) {
    if (!region.isValid() || region.sizeBytes() != (2u * region.eraseUnitBytes()) ||
        region.eraseUnitBytes() < kRecordBytes) {
      return false;
    }
    bool found = false;
    uint32_t best_sequence = 0;
    uint32_t best_extent = 0;
    for (uint32_t slot = 0; slot < 2u; ++slot) {
      uint8_t buf[kRecordBytes];
      // An unreadable slot must never be silently skipped: it could have
      // held the true newest record, so this whole lookup must fail
      // closed rather than return a stale/wrong value from the other slot.
      if (!platform::isOk(region.read(slot * region.eraseUnitBytes(), buf, kRecordBytes))) return false;
      if (!isValidRecord(buf, kRecordBytes)) continue;
      const uint32_t seq = getU32(buf + 8);
      if (!found || seq >= best_sequence) {
        found = true;
        best_sequence = seq;
        best_extent = getU32(buf + 16);
      }
    }
    if (!found) return false;
    out_active_image_extent = best_extent;
    return true;
  }

private:
  static bool isBlank(const uint8_t* buf, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
      if (buf[i] != 0xFFu) return false;
    }
    return true;
  }

  // Scans the ENTIRE erase unit at `slot_offset` (not merely the
  // record-sized prefix) in bounded scratch-sized chunks, so a genuine
  // "blank baseline" determination can never be fooled by nonblank bytes
  // lurking beyond the record itself (e.g. leftover data near the erase
  // unit's tail from a prior, differently-sized record layout). Sets
  // `out_read_ok` to false (return value undefined/false) on any read
  // failure; otherwise sets it true and returns whether every byte in
  // the whole erase unit is 0xFF.
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
};

}  // namespace storage
}  // namespace ota
