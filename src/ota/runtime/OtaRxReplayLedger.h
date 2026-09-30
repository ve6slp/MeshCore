#pragma once

// Durable, bounded, per-direction RX replay admission for the OTA AEAD
// transport. `admit(sequence)` MUST be called -- and must return true --
// BEFORE any dispatch/ACK side effect for a decrypted frame is allowed to
// run (this mirrors, at the transport layer, the same "validate session
// before any side effect" ordering fix already applied to
// OtaFirmwareIntegration's chunk/authorization handling).
//
// Model: a durable "highest accepted sequence" watermark (per direction --
// one instance per peer-direction or per-group-selector the caller is
// tracking) plus a BOUNDED in-RAM bitmap tolerating a limited amount of
// genuine reordering just above the watermark. Sequence 0 is never valid
// (the TX allocator -- OtaTxSequenceLedger.h -- never issues it) and is
// always rejected.
//
// Reboot behavior: the in-RAM reorder bitmap is intentionally NOT
// persisted (persisting every individual accepted sequence would be as
// flash-wear-expensive as persisting every TX). After a reboot, the
// bitmap starts empty and only the durable watermark survives -- so any
// sequence <= the persisted watermark is rejected (conservative: some
// legitimately-reordered-but-already-"seen"-relative-to-a-lost-bitmap
// frames may be rejected as if replayed, which is always SAFE -- a
// genuine sender simply retransmits with a fresh, higher sequence, same
// as any other lost frame), and no already-accepted sequence can ever be
// re-admitted as if new.
//
// Blank records require explicitly authorized virgin commissioning; the
// default refuses missing records on an existing identity. Any uncertain
// write freezes all admissions until a fresh instance resolves durability.
//
// This ledger's FlashRegion is caller-supplied and, like
// OtaTxSequenceLedger.h's, is expected to live OUTSIDE the
// candidate/backup image regions and the bootloader-owned journal --
// exclusively this app's own state, unaffected by (and never affecting)
// any install/rollback/candidate-bank operation.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ota/platform/FlashRegion.h"
#include "ota/runtime/OtaSequenceLedgerIo.h"

namespace meshcore {
namespace ota {
namespace runtime {

// Re-shape of OtaTxSequenceLedgerRecord's record format/logic for a
// distinct durable value (the RX watermark) -- kept as its own type
// (rather than literally reusing OtaTxSequenceLedgerRecord) so the two
// ledgers can never be cross-read/confused, even though their on-flash
// layouts happen to be identical in shape.
class OtaRxReplayLedgerRecord {
public:
  static constexpr uint32_t kMagic = 0x4F544152u;         // "OTAR" (OTA RX watermark).
  static constexpr uint32_t kCommitMarker = 0x52584F4Bu;  // "RXOK"
  static constexpr uint16_t kRecordVersion = 1u;
  static constexpr uint32_t kRecordBytes = 4 + 2 + 2 + 4 + 4 + 4;  // = 20
  static constexpr uint32_t kCrcOffset = kRecordBytes - 8;
  static constexpr uint32_t kCommitMarkerOffset = kRecordBytes - 4;

  static bool regionIsValid(const ::ota::platform::FlashRegion& region) {
    return region.isValid() && region.sizeBytes() == (2u * region.eraseUnitBytes()) &&
           region.eraseUnitBytes() >= kRecordBytes;
  }

  static uint32_t serialize(uint32_t watermark, uint8_t* out, uint32_t out_len) {
    if (out == nullptr || out_len < kRecordBytes) return 0;
    uint32_t pos = 0;
    putU32(out + pos, kMagic); pos += 4;
    putU16(out + pos, kRecordVersion); pos += 2;
    putU16(out + pos, static_cast<uint16_t>(kRecordBytes)); pos += 2;
    putU32(out + pos, watermark); pos += 4;
    const uint32_t crc = ::ota::storage::Crc32::computeFinalized(out, kCrcOffset);
    putU32(out + pos, crc); pos += 4;
    putU32(out + pos, kCommitMarker); pos += 4;
    return pos;
  }

  static bool isValidRecord(const uint8_t* record, uint32_t len) {
    if (record == nullptr || len != kRecordBytes) return false;
    if (getU32(record) != kMagic) return false;
    if (record[4] != static_cast<uint8_t>(kRecordVersion) || record[5] != 0) return false;
    if (getU16(record + 6) != static_cast<uint16_t>(kRecordBytes)) return false;
    if (getU32(record + kCommitMarkerOffset) != kCommitMarker) return false;
    return getU32(record + kCrcOffset) == ::ota::storage::Crc32::computeFinalized(record, kCrcOffset);
  }

  static bool isBlank(const uint8_t* buf, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
      if (buf[i] != 0xFFu) return false;
    }
    return true;
  }

  static uint32_t value(const uint8_t* record) { return getU32(record + 8); }

  static bool readNewestFailClosed(const ::ota::platform::FlashRegion& region, uint32_t& out_watermark) {
    return OtaSequenceLedgerIo<OtaRxReplayLedgerRecord>::readNewest(region, out_watermark);
  }

  static bool advance(::ota::platform::FlashRegion& region, uint32_t new_watermark) {
    return OtaSequenceLedgerIo<OtaRxReplayLedgerRecord>::advance(region, new_watermark);
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
  static uint16_t getU16(const uint8_t* in) {
    return static_cast<uint16_t>(in[0]) | (static_cast<uint16_t>(in[1]) << 8);
  }
  static uint32_t getU32(const uint8_t* in) {
    return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
  }
};

class OtaRxReplayLedger {
public:
  static constexpr uint32_t kWindowBits = 64u;  // bounded reordering tolerance above the watermark.

  explicit OtaRxReplayLedger(
      ::ota::platform::FlashRegion& region,
      OtaSequenceInitialization initialization = OtaSequenceInitialization::RequireExisting)
      : region_(region), initialization_(initialization) {}

  // Must be called (directly, or implicitly via the first admit() call)
  // before any admission decision is trusted. Returns false if the
  // durable watermark record is corrupt/unreadable (fails closed
  // permanently for this instance's lifetime).
  bool load() {
    if (loaded_) return !disabled_;
    loaded_ = true;
    uint32_t watermark = 0;
    if (!OtaRxReplayLedgerRecord::readNewestFailClosed(region_, watermark)) {
      disabled_ = true;
      return false;
    }
    if (watermark == 0 && initialization_ != OtaSequenceInitialization::CommissionVirgin) {
      disabled_ = true;
      return false;
    }
    watermark_ = watermark;
    bitmap_ = 0;
    // Keep this floor for the entire boot, even after advancing the
    // live watermark: lost bitmap history can never become trusted again.
    reboot_floor_ = watermark;
    return true;
  }

  // Returns true iff `sequence` has never been admitted before (replay
  // admission decision) and durably records the outcome BEFORE returning
  // -- i.e. the caller is guaranteed that by the time this returns true,
  // the ledger already durably reflects that `sequence` (and everything
  // <= it) can never be re-admitted, even across an immediate reset. The
  // caller MUST NOT run any dispatch/ACK side effect unless this returns
  // true, and MUST run it only AFTER this call, never before.
  bool admit(uint32_t sequence) {
    if (sequence == 0 || !load() || sequence <= reboot_floor_) return false;

    if (sequence > watermark_) {
      // Advances the watermark: durably persist FIRST, then update
      // in-memory state only on confirmed success.
      if (!OtaRxReplayLedgerRecord::advance(region_, sequence)) {
        disabled_ = true;
        return false;
      }
      const uint32_t advance_by = sequence - watermark_;
      if (advance_by >= kWindowBits) {
        bitmap_ = 0;
      } else {
        bitmap_ <<= advance_by;
      }
      watermark_ = sequence;
      // Mark the new watermark's own bit (bit 0 == watermark_ itself) as
      // seen, so a literal duplicate of this exact frame is still caught.
      bitmap_ |= 1ull;
      return true;
    }

    const uint32_t age = watermark_ - sequence;
    if (age >= kWindowBits) return false;  // too far below the window: reject as replay/too-old.
    const uint64_t bit = 1ull << age;
    if ((bitmap_ & bit) != 0u) return false;  // already admitted: replay.
    bitmap_ |= bit;
    return true;
  }

private:
  ::ota::platform::FlashRegion& region_;
  OtaSequenceInitialization initialization_;
  bool loaded_ = false;
  bool disabled_ = false;
  uint32_t reboot_floor_ = 0;
  uint32_t watermark_ = 0;
  uint64_t bitmap_ = 0;  // bit 0 == watermark_ itself, bit k == (watermark_ - k).
};

}  // namespace runtime
}  // namespace ota
}  // namespace meshcore
