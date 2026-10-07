#pragma once

// Shared power-loss-safe A/B slot writer for every bootloader-owned
// journal record type this app writes (command v1/v2, confirmation).
//
// A naive "erase, then program the WHOLE serialized record (body + CRC +
// trailing commit marker) in one program() call" is unsafe: a reset/power
// loss partway through that single program() can leave the target slot
// with an internally-consistent-looking CRC over garbage, OR (depending
// on exactly which bytes landed) a record whose marker word already reads
// as valid while the body is still partially unwritten. Splitting the
// write into two independently-verified phases -- (1) body+CRC, verified
// by readback, THEN (2) the trailing commit-marker word alone, verified
// by its own readback -- ensures that a genuine RESET/POWER-LOSS at any
// point before phase 2's program() actually lands leaves the target
// slot's commit marker still erased (0xFF...), so `isValidRecord()` on
// that slot fails and the existing valid record in the OTHER (untouched)
// slot keeps winning the newest-sequence comparison in every reader.
//
// IMPORTANT CAVEAT this function's `false` return does NOT guarantee:
// if phase 2's program() genuinely, durably succeeds but the immediately
// following readback() fails for an unrelated transient I/O reason (not
// a reset -- the marker bytes are truly on flash, only this readback
// call failed), this function still returns false, yet the target slot
// may now actually be a valid, complete, readable-on-retry record. A
// caller must NOT treat `false` as proof that the target slot is
// invalid/erased -- only that it cannot durably confirm the write
// succeeded. What IS always guaranteed on any `false` return is that the
// OTHER slot's own pre-existing valid record (if any) was never touched
// and remains exactly as it was. This mirrors storage::Journal's own
// write -> verify -> commit discipline.
#include <cstring>

#include "ota/platform/FlashRegion.h"

namespace ota {
namespace storage {

// Writes `record` (exactly `record_bytes` long) into the erase unit at
// `slot_offset` using the two-phase discipline described above.
// `commit_marker_offset` + `commit_marker_bytes` MUST equal `record_bytes`
// (the marker is always the record's final field). Returns false on any
// I/O failure or readback mismatch at either phase -- see the header
// caveat above: this guarantees the OTHER slot's existing valid record
// remains untouched, but does NOT guarantee this slot is
// itself erased/invalid (a marker-program that durably succeeded, with
// only its own confirming readback failing transiently, can leave a
// genuinely valid record here despite the false return).
inline bool writeOtaJournalRecordTransactional(platform::FlashRegion& region, uint32_t slot_offset,
                                               const uint8_t* record, uint32_t record_bytes,
                                               uint32_t commit_marker_offset,
                                               uint32_t commit_marker_bytes) {
  constexpr uint32_t kMaxRecordBytes = 256u;
  if (record == nullptr || record_bytes == 0 || record_bytes > kMaxRecordBytes ||
      record_bytes > region.eraseUnitBytes() || commit_marker_bytes == 0 ||
      commit_marker_offset > record_bytes || commit_marker_bytes != record_bytes - commit_marker_offset) {
    return false;
  }

  if (!platform::isOk(region.eraseRange(slot_offset, region.eraseUnitBytes()))) {
    return false;
  }

  // Phase 1: body + CRC (everything strictly before the commit marker).
  if (commit_marker_offset > 0) {
    if (!platform::isOk(region.program(slot_offset, record, commit_marker_offset))) {
      return false;
    }
    uint8_t body_readback[kMaxRecordBytes];
    if (!platform::isOk(region.read(slot_offset, body_readback, commit_marker_offset))) {
      return false;
    }
    if (memcmp(record, body_readback, commit_marker_offset) != 0) {
      return false;
    }
  }

  // Phase 2: the commit marker alone, independently verified. Only after
  // THIS readback succeeds does the slot's isValidRecord() check pass.
  if (!platform::isOk(region.program(slot_offset + commit_marker_offset, record + commit_marker_offset,
                                     commit_marker_bytes))) {
    return false;
  }
  uint8_t marker_readback[kMaxRecordBytes];
  if (!platform::isOk(
          region.read(slot_offset + commit_marker_offset, marker_readback, commit_marker_bytes))) {
    return false;
  }
  if (memcmp(record + commit_marker_offset, marker_readback, commit_marker_bytes) != 0) {
    return false;
  }

  return true;
}

}  // namespace storage
}  // namespace ota
