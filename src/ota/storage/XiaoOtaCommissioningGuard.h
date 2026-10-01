#pragma once

// Pure, host-testable "is this device already commissioned" predicate for
// examples/ota_qspi_hardware_test/main.cpp's factory/lab qualification
// harness. That harness deliberately performs destructive raw-flash
// operations (candidateTestRegion() erase/program probes, a signed-image
// stage-and-verify rehearsal) and must refuse to run at all against any
// device that has already gone through real OTA commissioning -- whether
// that's evidenced by (a) a genuinely qualified custom bootloader marker
// (see XiaoOtaBootInfoReader / resolveOtaBoardBootQualification), (b) any
// non-blank content in the 8 xiao_ota_* journal sub-slots (install
// command/state/confirmation/floor A+B -- the bootloader's own durable
// antirollback records), or (c) a valid checkpoint in the generic
// ota::storage::Journal/JournalCheckpoint format used by the separate
// portable ota::boot::BootTransaction self-install path. A prior version
// of this guard only checked (c) via the generic Journal format, which
// per SenseCapQspiLayout.h's own documented contract is NEVER the format
// this specific custom bootloader actually writes to this physical
// partition on real hardware -- so it could not, by itself, detect a
// genuinely-commissioned XIAO device at all. Any ONE of (a)/(b)/(c) being
// true must refuse the harness; this is deliberately OR'd, never AND'd,
// so a partial/ambiguous signal still fails closed (refuses) rather than
// requiring every signal to agree before treating the device as unsafe to
// wipe.

#include <stdint.h>

#include <ota/storage/XiaoOtaLegacyResidue.h>

namespace ota {
namespace storage {

struct XiaoOtaCommissioningInputs {
  // True only when XiaoOtaBootInfoReader's magic/format/CRC validation
  // passes AND board_target_id/role/capability/algorithm all match this
  // build's expectations (see
  // mesh::ota::resolveOtaBoardBootQualification()) -- never board/JEDEC
  // identity or a compiled flag alone.
  bool boot_marker_qualified = false;
  // True only when ota::storage::Journal::recoverLatest() on the real
  // (non-test) journal partition actually returns a valid checkpoint --
  // the separate, generic self-install journal format.
  bool generic_journal_checkpoint_present = false;
  // True when ANY of the 8 raw 4096-byte xiao_ota_* journal sub-slots
  // (command A/B, state A/B, confirmation A/B, floor A/B) contains
  // anything other than entirely-blank (0xFF) bytes.
  bool any_xiao_subslot_nonblank = false;
};

// Returns true (refuse to run the destructive harness) if ANY input
// signal indicates real commissioning has happened or is underway.
inline bool isDeviceAlreadyCommissioned(const XiaoOtaCommissioningInputs& in) {
  return in.boot_marker_qualified || in.generic_journal_checkpoint_present ||
         in.any_xiao_subslot_nonblank;
}

// Convenience helper: computes any_xiao_subslot_nonblank from the 8 raw
// 4096-byte sub-slot buffers (same physical layout/order as
// XiaoOtaLegacyResidue::isSafeToEraseFloorA()'s floor_a/floor_b/tx_sectors
// parameters, but here evaluated generically -- ANY non-blank sub-slot,
// not just the specific known contamination residue pattern -- since this
// guard must refuse on ANY real content, not just one recognized pattern).
inline bool anyXiaoJournalSubSlotNonBlank(const uint8_t* const sub_slots[8], uint32_t sub_slot_bytes) {
  for (int i = 0; i < 8; ++i) {
    if (sub_slots[i] == nullptr) return true;  // unreadable -- fail closed.
    if (!XiaoOtaLegacyResidue::isEntirelyBlank(sub_slots[i], sub_slot_bytes)) return true;
  }
  return false;
}

}  // namespace storage
}  // namespace ota
