#pragma once

// Validated memory map for the SenseCAP Solar 2 MiB external QSPI NOR flash,
// used as the OTA staging device (candidate slot + backup slot + durable
// journal + littlefs filesystem region).
//
// This is an independent, from-scratch layout definition for the new
// storage/trust/boot subsystem (it intentionally does not include or depend
// on src/helpers/LoraOtaPolicy.h, which remains untouched). The numeric
// ranges below were chosen to match the previously agreed partitioning:
//
//   candidate:   0x000000 .. 0x0C6000  (792 KiB)
//   backup:      0x0C6000 .. 0x18C000  (792 KiB)
//   journal:     0x18C000 .. 0x194000  (32 KiB)
//   filesystem:  0x194000 .. 0x200000  (432 KiB)
//
// All bounds/overlap arithmetic is written to avoid unsigned overflow.

#include <stdint.h>
#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashRegion.h"

namespace ota {
namespace platform {

struct SenseCapQspiLayout {
  static constexpr uint32_t kTotalBytes = 2u * 1024u * 1024u;   // 0x200000
  static constexpr uint32_t kEraseUnitBytes = 4096u;            // typical QSPI NOR sector size

  static constexpr uint32_t kCandidateOffset = 0x000000u;
  static constexpr uint32_t kCandidateSize   = 0x0C6000u;       // 792 KiB

  static constexpr uint32_t kBackupOffset = 0x0C6000u;
  static constexpr uint32_t kBackupSize   = 0x0C6000u;          // 792 KiB

  static constexpr uint32_t kJournalOffset = 0x18C000u;
  static constexpr uint32_t kJournalSize   = 0x008000u;         // 32 KiB

  static constexpr uint32_t kFilesystemOffset = 0x194000u;
  static constexpr uint32_t kFilesystemSize   = 0x06C000u;      // 432 KiB

  // Destructive hardware qualification is confined to these explicitly
  // reserved subregions. They are inside OTA-owned partitions and never
  // overlap the partitioned LittleFS range.
  static constexpr uint32_t kCandidateTestOffset = 0x0C2000u;
  static constexpr uint32_t kCandidateTestSize   = 0x004000u;    // 16 KiB
  static constexpr uint32_t kJournalTestOffset   = 0x192000u;
  static constexpr uint32_t kJournalTestSize     = 0x002000u;    // 8 KiB

  // Overflow-safe: returns true if [a_offset, a_offset+a_size) and
  // [b_offset, b_offset+b_size) intersect, without forming offset+size sums
  // that could wrap (all inputs here are static layout constants well below
  // UINT32_MAX, but the check is written generically/defensively).
  static bool rangesOverlap(uint32_t a_offset, uint32_t a_size, uint32_t b_offset, uint32_t b_size) {
    if (a_size == 0 || b_size == 0) {
      return false;
    }
    if (a_offset >= b_offset) {
      // b starts at-or-before a; they overlap unless b ends at-or-before a starts.
      return (b_offset + (b_size - 1u)) >= a_offset;
    } else {
      return (a_offset + (a_size - 1u)) >= b_offset;
    }
  }

  static bool fitsWithin(uint32_t offset, uint32_t size, uint32_t limit) {
    if (offset > limit) {
      return false;
    }
    return size <= (limit - offset);
  }

  static bool isAligned(uint32_t value) {
    return (value % kEraseUnitBytes) == 0;
  }

  // Validates the static layout constants themselves: alignment, no
  // overflow, no overlap, and exact coverage of the 2 MiB device.
  static bool isValid() {
    if (!isAligned(kCandidateOffset) || !isAligned(kCandidateSize)) return false;
    if (!isAligned(kBackupOffset) || !isAligned(kBackupSize)) return false;
    if (!isAligned(kJournalOffset) || !isAligned(kJournalSize)) return false;
    if (!isAligned(kFilesystemOffset) || !isAligned(kFilesystemSize)) return false;

    if (!fitsWithin(kCandidateOffset, kCandidateSize, kTotalBytes)) return false;
    if (!fitsWithin(kBackupOffset, kBackupSize, kTotalBytes)) return false;
    if (!fitsWithin(kJournalOffset, kJournalSize, kTotalBytes)) return false;
    if (!fitsWithin(kFilesystemOffset, kFilesystemSize, kTotalBytes)) return false;

    if (rangesOverlap(kCandidateOffset, kCandidateSize, kBackupOffset, kBackupSize)) return false;
    if (rangesOverlap(kCandidateOffset, kCandidateSize, kJournalOffset, kJournalSize)) return false;
    if (rangesOverlap(kCandidateOffset, kCandidateSize, kFilesystemOffset, kFilesystemSize)) return false;
    if (rangesOverlap(kBackupOffset, kBackupSize, kJournalOffset, kJournalSize)) return false;
    if (rangesOverlap(kBackupOffset, kBackupSize, kFilesystemOffset, kFilesystemSize)) return false;
    if (rangesOverlap(kJournalOffset, kJournalSize, kFilesystemOffset, kFilesystemSize)) return false;

    // The four regions must exactly tile the device with no gaps, given the
    // contiguous ordering candidate, backup, journal, filesystem.
    if (kCandidateOffset + kCandidateSize != kBackupOffset) return false;
    if (kBackupOffset + kBackupSize != kJournalOffset) return false;
    if (kJournalOffset + kJournalSize != kFilesystemOffset) return false;
    if (kFilesystemOffset + kFilesystemSize != kTotalBytes) return false;

    return true;
  }

  static FlashRegion candidateRegion(FlashDevice& device) {
    return FlashRegion(device, kCandidateOffset, kCandidateSize);
  }
  static FlashRegion backupRegion(FlashDevice& device) {
    return FlashRegion(device, kBackupOffset, kBackupSize);
  }
  static FlashRegion journalRegion(FlashDevice& device) {
    return FlashRegion(device, kJournalOffset, kJournalSize);
  }
  static FlashRegion filesystemRegion(FlashDevice& device) {
    return FlashRegion(device, kFilesystemOffset, kFilesystemSize);
  }
  static FlashRegion candidateTestRegion(FlashDevice& device) {
    return FlashRegion(device, kCandidateTestOffset, kCandidateTestSize);
  }
  static FlashRegion journalTestRegion(FlashDevice& device) {
    return FlashRegion(device, kJournalTestOffset, kJournalTestSize);
  }
};

}  // namespace platform
}  // namespace ota
