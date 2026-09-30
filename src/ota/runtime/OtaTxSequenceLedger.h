#pragma once

// Durable, power-loss-safe, monotonic TX sequence allocator for the OTA
// AEAD transport (ota/trust/OtaAeadKeySchedule.h's nonce = noncePrefix(8)
// || BE32(sequence)) -- ONE allocator per local node identity, shared
// across every peer/group direction this node ever transmits to/in,
// because a ChaCha20-Poly1305 nonce must NEVER repeat for a given
// (key, nonce) pair, and the per-direction key already encodes
// sender/receiver identity, so only the raw sequence counter itself needs
// this single, global, durable "never issue the same value twice" guard.
//
// Design (block-reservation, not per-value durability): a per-value durable
// write before every single TX would be prohibitively flash-wear-expensive.
// Instead, `allocate()` durably reserves a BLOCK of kBlockSize consecutive
// sequence numbers at a time (one erase+program+readback-verified flash
// write per 64 allocations), then serves individual sequence numbers from
// that block purely from RAM until the block is exhausted. This means a
// reset/power-loss mid-block LOSES the remainder of that block's unused
// sequence numbers -- by design: on restart, the ledger's durable record IS
// the upper bound of the last block ever reserved, so the very first
// allocate() call after a reboot immediately reserves a BRAND NEW block
// starting just past it, skipping the WHOLE previous block (whether or not
// it was fully consumed before the reset) rather than risking any
// possibility of reissuing a sequence value that may already have been
// used to encrypt and transmit a real frame before the reset.
//
// Sequences start at 1 (0 is never issued). A durable record that is
// genuinely absent (both A/B slots blank/erased) is allowed only with
// explicitly authorized virgin commissioning. Absence on an existing
// identity is a fault, not permission to reuse sequence 1. A record that is
// present but corrupt, or a slot that fails to read at all, is NEVER
// treated as "no record" -- the allocator fails closed permanently for
// its lifetime (every subsequent allocate() call also returns false)
// rather than risk reusing a nonce.
//
// A caller whose TX attempt fails or must be retried MUST call allocate()
// again for a fresh sequence number -- this allocator has no notion of
// "the same attempt", and never reissues a previously-returned value.
//
// This ledger's FlashRegion is caller-supplied and is expected to live
// OUTSIDE the candidate/backup image regions and the bootloader-owned
// command/state/confirmation/floor journal -- it is exclusively this
// app's own durable state and must never be touched by, or affect the
// outcome of, any install/rollback/candidate-bank operation. (Concrete
// flash address allocation for this region on real hardware is a
// memory-map decision outside this header's scope -- see the OTA AEAD
// transport handoff notes for the pending coordination item.)
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ota/platform/FlashRegion.h"
#include "ota/runtime/OtaSequenceLedgerIo.h"
#include "ota/storage/Crc32.h"
#include "ota/storage/XiaoOtaTransactionalWriter.h"

namespace meshcore {
namespace ota {
namespace runtime {

// magic(4)+version(2)+bytes(2)+reserved_upper_bound(4)+crc32(4)+marker(4) = 20.
class OtaTxSequenceLedgerRecord {
public:
  static constexpr uint32_t kMagic = 0x4F544153u;         // "OTAS" (OTA sequence).
  static constexpr uint32_t kCommitMarker = 0x53455121u;  // "SEQ!"
  static constexpr uint16_t kRecordVersion = 1u;
  static constexpr uint32_t kRecordBytes = 4 + 2 + 2 + 4 + 4 + 4;  // = 20
  static constexpr uint32_t kCrcOffset = kRecordBytes - 8;          // 12
  static constexpr uint32_t kCommitMarkerOffset = kRecordBytes - 4;  // 16

  static bool regionIsValid(const ::ota::platform::FlashRegion& region) {
    return region.isValid() && region.sizeBytes() == (2u * region.eraseUnitBytes()) &&
           region.eraseUnitBytes() >= kRecordBytes;
  }

  static uint32_t serialize(uint32_t reserved_upper_bound, uint8_t* out, uint32_t out_len) {
    if (out == nullptr || out_len < kRecordBytes) return 0;
    uint32_t pos = 0;
    putU32(out + pos, kMagic); pos += 4;
    putU16(out + pos, kRecordVersion); pos += 2;
    putU16(out + pos, static_cast<uint16_t>(kRecordBytes)); pos += 2;
    putU32(out + pos, reserved_upper_bound); pos += 4;
    const uint32_t crc = ::ota::storage::Crc32::computeFinalized(out, kCrcOffset);
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
    return stored_crc == ::ota::storage::Crc32::computeFinalized(record, kCrcOffset);
  }

  static bool isBlank(const uint8_t* buf, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
      if (buf[i] != 0xFFu) return false;
    }
    return true;
  }

  static uint32_t value(const uint8_t* record) { return getU32(record + 8); }

  // Both blank slots return out=0; the allocator still requires explicit
  // virgin commissioning. Any unreadable, corrupt or zero-valued record
  // refuses the entire lookup, even if the other slot is valid.
  static bool readNewestFailClosed(const ::ota::platform::FlashRegion& region,
                                   uint32_t& out_reserved_upper_bound) {
    return OtaSequenceLedgerIo<OtaTxSequenceLedgerRecord>::readNewest(region, out_reserved_upper_bound);
  }

  // Durably writes a new `reserved_upper_bound` (strictly greater than
  // every prior value) into the other slot, verified by readback.
  // False means uncertain durability, NOT proof that no mutation occurred.
  static bool reserve(::ota::platform::FlashRegion& region, uint32_t new_reserved_upper_bound) {
    return OtaSequenceLedgerIo<OtaTxSequenceLedgerRecord>::advance(region, new_reserved_upper_bound);
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

// The runtime-facing allocator: wraps OtaTxSequenceLedgerRecord with the
// in-RAM fast path (no flash write on every call -- only once per
// kBlockSize allocations).
class OtaTxSequenceAllocator {
public:
  static constexpr uint32_t kBlockSize = 64u;

  explicit OtaTxSequenceAllocator(
      ::ota::platform::FlashRegion& region,
      OtaSequenceInitialization initialization = OtaSequenceInitialization::RequireExisting)
      : region_(region), initialization_(initialization) {}

  // Returns the next never-before-issued sequence number (>= 1) in
  // `out_sequence`, reserving a fresh durable block first if needed.
  // Returns false (nothing allocated) if the ledger is corrupt/unreadable
  // (fails closed permanently for this instance), a reservation write
  // fails, or the sequence space is exhausted (next value would exceed
  // UINT32_MAX -- never silently wraps to 0).
  bool allocate(uint32_t* out_sequence) {
    if (out_sequence == nullptr || disabled_) return false;
    if (!loaded_) {
      loaded_ = true;
      uint32_t reserved_upper_bound = 0;
      if (!OtaTxSequenceLedgerRecord::readNewestFailClosed(region_, reserved_upper_bound)) {
        disabled_ = true;
        return false;
      }
      if ((reserved_upper_bound == 0 && initialization_ != OtaSequenceInitialization::CommissionVirgin) ||
          reserved_upper_bound == UINT32_MAX) {
        disabled_ = true;
        return false;
      }
      reserved_upper_bound_ = reserved_upper_bound;
      next_sequence_ = reserved_upper_bound_ + 1u;  // deliberately skips the whole prior block on reboot.
    }

    if (next_sequence_ > reserved_upper_bound_) {
      // Current block (if any) is exhausted (or this is the very first
      // allocation ever, or the first allocation after a reboot) --
      // durably reserve a fresh block before issuing anything from it.
      if (reserved_upper_bound_ > (0xFFFFFFFFu - kBlockSize)) {
        disabled_ = true;  // sequence space exhausted: fail closed, never wrap.
        return false;
      }
      const uint32_t new_upper_bound = reserved_upper_bound_ + kBlockSize;
      if (!OtaTxSequenceLedgerRecord::reserve(region_, new_upper_bound)) {
        disabled_ = true;  // durability is unknown; only reconstruction may resolve it.
        return false;
      }
      reserved_upper_bound_ = new_upper_bound;
    }

    *out_sequence = next_sequence_;
    if (next_sequence_ == UINT32_MAX) {
      disabled_ = true;
    } else {
      ++next_sequence_;
    }
    return true;
  }

private:
  ::ota::platform::FlashRegion& region_;
  OtaSequenceInitialization initialization_;
  bool loaded_ = false;
  bool disabled_ = false;
  uint32_t reserved_upper_bound_ = 0;
  uint32_t next_sequence_ = 1;
};

}  // namespace runtime
}  // namespace ota
}  // namespace meshcore
