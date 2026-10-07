#pragma once

// Validated, tail-safe memory map for the SenseCAP Solar 2 MiB external
// QSPI NOR flash (P25Q16H), used as the OTA staging device (candidate slot
// + backup slot + durable journal + littlefs filesystem region).
//
// This is an independent, from-scratch layout definition for the new
// storage/trust/boot subsystem (it intentionally does not include or depend
// on src/helpers/LoraOtaPolicy.h, which remains untouched).
//
// THE NUMERIC VALUES THEMSELVES LIVE IN Nrf52FlashLayoutContract.h (same
// directory) as plain C macros, so a non-C++ consumer (the C bootloader,
// offline signing tooling) can #include that header directly and always
// agree byte-for-byte with this class; every constant below is cross-checked
// against it via static_assert.
//
// Approved tail-safe half-open partitioning (each physical bank is
// PHYSICAL_BANK_STRIDE_BYTES = 0xC6000 apart, but only the first
// IMAGE_CAPACITY_BYTES = 0xAD000 of each bank is writable image capacity):
//
//   candidate (image):  0x000000 .. 0x0AD000  (708608 B, 692 KiB)
//   securityA (tail):   0x0AD000 .. 0x0C6000  (100 KiB)
//   backup (image):     0x0C6000 .. 0x173000  (708608 B, 692 KiB)
//   securityB (tail):   0x173000 .. 0x18C000  (100 KiB)
//   journal:            0x18C000 .. 0x194000  (32 KiB)   -- unchanged
//   filesystem:         0x194000 .. 0x200000  (432 KiB)  -- unchanged
//
// securityA and securityB are NOT per-bank signature/descriptor material:
// together they are the two halves (A/B generations) of ONE global,
// identity-owned append/compaction store, addressed here only as raw
// capability regions -- this header grants no store implementation and no
// identity/provisioning semantics.
//
// FlashRegion bounds reject writes crossing either bank's security tail.
// The candidate metadata A/B sectors occupy 0x0AB000..0x0AD000, above
// the installable APP limit; they are not hardware-test scratch space.
//
// All bounds/overlap arithmetic is written to avoid unsigned overflow.

#include <stdint.h>
#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashRegion.h"
#include "ota/platform/Nrf52FlashLayoutContract.h"

namespace ota {
namespace platform {

struct SenseCapQspiLayout {
  static constexpr uint32_t kTotalBytes = OTA_NRF52_QSPI_TOTAL_BYTES;      // 0x200000
  static constexpr uint32_t kEraseUnitBytes = OTA_NRF52_QSPI_ERASE_UNIT_BYTES; // 4096

  // Physical distance between the start of the candidate bank and the
  // start of the backup bank. This is a PLACEMENT constant only -- it is
  // NOT writable image capacity, and must never be used as an erase/
  // program bound. See kCandidateSize/kBackupSize (the actual writable
  // capacity) and kSecurityTailBytes (the reserved remainder of each
  // bank) below.
  static constexpr uint32_t kPhysicalBankStrideBytes = OTA_NRF52_PHYSICAL_BANK_STRIDE_BYTES; // 0xC6000, fixed
  static constexpr uint32_t kSecurityTailBytes = OTA_NRF52_SECURITY_TAIL_BYTES;               // 0x19000 (100 KiB) per bank

  static constexpr uint32_t kCandidateOffset = OTA_NRF52_CANDIDATE_OFFSET;
  static constexpr uint32_t kCandidateSize   = OTA_NRF52_CANDIDATE_SIZE;      // 0xAD000 (708608 B) -- image capacity only

  // Fixed: kBackupOffset is the physical bank stride and must NEVER move
  // just because kCandidateSize/kBackupSize (writable image capacity)
  // changes -- the backup bank's physical placement is independent of how
  // much of each bank is currently treated as writable image vs. tail.
  static constexpr uint32_t kBackupOffset = OTA_NRF52_BACKUP_OFFSET;          // 0xC6000, fixed
  static constexpr uint32_t kBackupSize   = OTA_NRF52_BACKUP_SIZE;            // 0xAD000 (708608 B) -- image capacity only

  // Dedicated security-tail regions: NOT per-bank signature/descriptor
  // material -- securityA and securityB together are the two halves (A/B
  // generations) of ONE global identity-owned append/compaction store.
  // Exposed as their own explicit capability so image-region code can
  // never reach into them and vice versa. No store implementation here.
  static constexpr uint32_t kSecurityAOffset = OTA_NRF52_SECURITY_A_OFFSET;   // 0xAD000
  static constexpr uint32_t kSecurityASize   = OTA_NRF52_SECURITY_A_SIZE;     // 0x19000
  static constexpr uint32_t kSecurityBOffset = OTA_NRF52_SECURITY_B_OFFSET;   // 0x173000
  static constexpr uint32_t kSecurityBSize   = OTA_NRF52_SECURITY_B_SIZE;     // 0x19000

  static constexpr uint32_t kJournalOffset = OTA_NRF52_JOURNAL_OFFSET;
  static constexpr uint32_t kJournalSize   = OTA_NRF52_JOURNAL_SIZE;          // 32 KiB

  static constexpr uint32_t kFilesystemOffset = OTA_NRF52_FILESYSTEM_OFFSET;
  static constexpr uint32_t kFilesystemSize   = OTA_NRF52_FILESYSTEM_SIZE;    // 432 KiB

  // Last legal (aligned) sector START still entirely inside each bank's
  // writable image capacity -- i.e. exactly one erase unit before the
  // first security-tail byte. Any attempt to erase/program starting at or
  // beyond kSecurityAOffset/kSecurityBOffset via candidateRegion()/
  // backupRegion() is already structurally rejected by FlashRegion's own
  // bounds checking (region size == kCandidateSize/kBackupSize); these
  // constants are exposed additionally so callers/tests can assert the
  // exact boundary explicitly rather than only indirectly.
  static constexpr uint32_t kCandidateLastLegalSectorOffset = OTA_NRF52_CANDIDATE_LAST_LEGAL_SECTOR_OFFSET; // 0xAC000
  static constexpr uint32_t kBackupLastLegalSectorOffset    = OTA_NRF52_BACKUP_LAST_LEGAL_SECTOR_OFFSET;    // 0x172000

  static constexpr uint32_t kCandidateRecordOffset = OTA_NRF52_CANDIDATE_RECORD_OFFSET;
  static constexpr uint32_t kCandidateRecordSize = OTA_NRF52_CANDIDATE_RECORD_SIZE;

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
  // overflow, no overlap, and exact coverage of the 2 MiB device by the
  // six regions (candidate, securityA, backup, securityB, journal,
  // filesystem), plus the fixed physical-stride and candidate-record
  // invariants.
  static bool isValid() {
    if (!isAligned(kCandidateOffset) || !isAligned(kCandidateSize)) return false;
    if (!isAligned(kSecurityAOffset) || !isAligned(kSecurityASize)) return false;
    if (!isAligned(kBackupOffset) || !isAligned(kBackupSize)) return false;
    if (!isAligned(kSecurityBOffset) || !isAligned(kSecurityBSize)) return false;
    if (!isAligned(kJournalOffset) || !isAligned(kJournalSize)) return false;
    if (!isAligned(kFilesystemOffset) || !isAligned(kFilesystemSize)) return false;
    if (!isAligned(kCandidateRecordOffset) || !isAligned(kCandidateRecordSize)) return false;

    if (!fitsWithin(kCandidateOffset, kCandidateSize, kTotalBytes)) return false;
    if (!fitsWithin(kSecurityAOffset, kSecurityASize, kTotalBytes)) return false;
    if (!fitsWithin(kBackupOffset, kBackupSize, kTotalBytes)) return false;
    if (!fitsWithin(kSecurityBOffset, kSecurityBSize, kTotalBytes)) return false;
    if (!fitsWithin(kJournalOffset, kJournalSize, kTotalBytes)) return false;
    if (!fitsWithin(kFilesystemOffset, kFilesystemSize, kTotalBytes)) return false;

    // Physical bank stride is fixed and independent of image-capacity
    // sizing: the backup bank must start exactly one stride after the
    // candidate bank regardless of kCandidateSize.
    if (kBackupOffset != kCandidateOffset + kPhysicalBankStrideBytes) return false;
    // Each bank's image capacity plus its security tail must exactly fill
    // that bank's physical stride (no gap, no overlap, no spare slack).
    if (kCandidateSize + kSecurityTailBytes != kPhysicalBankStrideBytes) return false;
    if (kBackupSize + kSecurityTailBytes != kPhysicalBankStrideBytes) return false;

    // The six regions must exactly tile the device with no gaps, in
    // contiguous order: candidate, securityA, backup, securityB, journal,
    // filesystem.
    if (kCandidateOffset + kCandidateSize != kSecurityAOffset) return false;
    if (kSecurityAOffset + kSecurityASize != kBackupOffset) return false;
    if (kBackupOffset + kBackupSize != kSecurityBOffset) return false;
    if (kSecurityBOffset + kSecurityBSize != kJournalOffset) return false;
    if (kJournalOffset + kJournalSize != kFilesystemOffset) return false;
    if (kFilesystemOffset + kFilesystemSize != kTotalBytes) return false;

    if (!fitsWithin(kCandidateRecordOffset, kCandidateRecordSize,
                    kCandidateOffset + kCandidateSize)) return false;
    if (kCandidateRecordOffset + kCandidateRecordSize != kSecurityAOffset) return false;
    if (kCandidateRecordOffset < OTA_NRF52_INTERNAL_IMAGE_SIZE) return false;

    // Last-legal-sector constants must be exactly one erase unit before
    // each bank's security tail.
    if (kCandidateLastLegalSectorOffset + kEraseUnitBytes != kSecurityAOffset) return false;
    if (kBackupLastLegalSectorOffset + kEraseUnitBytes != kSecurityBOffset) return false;

    return true;
  }

  static FlashRegion candidateRegion(FlashDevice& device) {
    return FlashRegion(device, kCandidateOffset, kCandidateSize);
  }
  static FlashRegion candidatePayloadRegion(FlashDevice& device) {
    return FlashRegion(device, kCandidateOffset, kCandidateRecordOffset - kCandidateOffset);
  }
  static FlashRegion backupRegion(FlashDevice& device) {
    return FlashRegion(device, kBackupOffset, kBackupSize);
  }
  // Dedicated security-tail capabilities, exposed separately from the
  // image regions above so boot/signing code can address exactly the
  // global identity-owned store's A/B halves without ever reaching into
  // that bank's image data (and vice versa).
  static FlashRegion securityARegion(FlashDevice& device) {
    return FlashRegion(device, kSecurityAOffset, kSecurityASize);
  }
  static FlashRegion securityBRegion(FlashDevice& device) {
    return FlashRegion(device, kSecurityBOffset, kSecurityBSize);
  }
  static FlashRegion journalRegion(FlashDevice& device) {
    return FlashRegion(device, kJournalOffset, kJournalSize);
  }
  static FlashRegion filesystemRegion(FlashDevice& device) {
    return FlashRegion(device, kFilesystemOffset, kFilesystemSize);
  }
  static FlashRegion candidateRecordRegion(FlashDevice& device) {
    return FlashRegion(device, kCandidateRecordOffset, kCandidateRecordSize);
  }

  // The XIAO nRF52840 custom bootloader (bootloader/xiao_nrf52840_ota/)
  // subdivides this SAME physical journal partition into fixed 4 KiB
  // sub-slots for its own record types, distinct from (and never written
  // concurrently with, on real hardware) the native tests' generic journal model:
  //   0x18C000 / 0x18D000  -- install command A/B (xiao_ota_command_t)
  //   0x18E000 / 0x18F000  -- install state A/B    (xiao_ota_state_t, boot-owned, app READS ONLY)
  //   0x190000 / 0x191000  -- confirmation A/B      (xiao_ota_confirmation_t)
  //   0x192000 / 0x193000  -- confirmed-counter floor A/B (xiao_ota_floor_t, boot-owned)
  // The install-command A/B pair (ota::storage::XiaoOtaCommandRecord) and
  // the confirmation A/B pair (ota::storage::XiaoOtaConfirmationRecord,
  // ONLY via ota::storage::XiaoOtaTrialHealthMonitor's continuous-window/
  // deadline/incremental-hash gate -- see XiaoOtaTrialHealthMonitor.h)
  // are the only two sub-slots this
  // firmware ever writes. State A/B and the confirmed-counter floor A/B
  // are written exclusively by the bootloader and must never be erased or
  // programmed from application code (state is read-only via
  // ota::storage::XiaoOtaStateReader; the floor via
  // ota::storage::XiaoOtaFloorReader).
  static constexpr uint32_t kXiaoCommandOffset = kJournalOffset;         // 0x18C000
  static constexpr uint32_t kXiaoCommandSize   = 2u * kEraseUnitBytes;   // 8 KiB (A + B)

  static FlashRegion xiaoCommandRegion(FlashDevice& device) {
    return FlashRegion(device, kXiaoCommandOffset, kXiaoCommandSize);
  }

  // Bootloader-owned install state A/B pair (xiao_ota_state_t).
  // Application code must only ever READ this region (see
  // ota::storage::XiaoOtaStateReader) -- never erase or program it; the
  // bootloader alone advances install-transaction phase here.
  static constexpr uint32_t kXiaoStateOffset = kJournalOffset + 2u * kEraseUnitBytes;  // 0x18E000
  static constexpr uint32_t kXiaoStateSize   = 2u * kEraseUnitBytes;                    // 8 KiB (A + B)

  static FlashRegion xiaoStateRegion(FlashDevice& device) {
    return FlashRegion(device, kXiaoStateOffset, kXiaoStateSize);
  }

  // Confirmation A/B pair (xiao_ota_confirmation_t). This is the ONE
  // sub-slot outside install-command A/B that application code is
  // authorized to write -- and only ever via the gated
  // ota::storage::XiaoOtaTrialHealthMonitor path, never
  // a direct/unconditional erase+program.
  static constexpr uint32_t kXiaoConfirmOffset = kJournalOffset + 4u * kEraseUnitBytes;  // 0x190000
  static constexpr uint32_t kXiaoConfirmSize   = 2u * kEraseUnitBytes;                    // 8 KiB (A + B)

  static FlashRegion xiaoConfirmRegion(FlashDevice& device) {
    return FlashRegion(device, kXiaoConfirmOffset, kXiaoConfirmSize);
  }

  // Bootloader-owned confirmed-counter floor A/B pair (xiao_ota_floor_t).
  // Application code must only ever READ this region (see
  // ota::storage::XiaoOtaFloorReader) -- never erase or program it.
  static constexpr uint32_t kXiaoFloorOffset = kJournalOffset + 6u * kEraseUnitBytes;  // 0x192000
  static constexpr uint32_t kXiaoFloorSize   = 2u * kEraseUnitBytes;                    // 8 KiB (A + B)

  static FlashRegion xiaoFloorRegion(FlashDevice& device) {
    return FlashRegion(device, kXiaoFloorOffset, kXiaoFloorSize);
  }

  // Read-only full journal view for validating stock bootstrap admission.
  static FlashRegion xiaoJournalFullRegion(FlashDevice& device) {
    return FlashRegion(device, kJournalOffset, 8u * kEraseUnitBytes);
  }

  // --- Cross-checks against the plain-C shared contract header ---------
  // These guarantee the C++ constants above and Nrf52FlashLayoutContract.h
  // (the header non-C++ consumers such as the bootloader/signer actually
  // #include) can never silently drift apart.
  static_assert(kTotalBytes == OTA_NRF52_QSPI_TOTAL_BYTES, "kTotalBytes must match the shared C contract");
  static_assert(kEraseUnitBytes == OTA_NRF52_QSPI_ERASE_UNIT_BYTES, "kEraseUnitBytes must match the shared C contract");
  static_assert(kPhysicalBankStrideBytes == OTA_NRF52_PHYSICAL_BANK_STRIDE_BYTES, "bank stride must match the shared C contract");
  static_assert(kSecurityTailBytes == OTA_NRF52_SECURITY_TAIL_BYTES, "security tail size must match the shared C contract");
  static_assert(kCandidateOffset == OTA_NRF52_CANDIDATE_OFFSET, "candidate offset must match the shared C contract");
  static_assert(kCandidateSize == OTA_NRF52_CANDIDATE_SIZE, "candidate size must match the shared C contract");
  static_assert(kSecurityAOffset == OTA_NRF52_SECURITY_A_OFFSET, "securityA offset must match the shared C contract");
  static_assert(kSecurityASize == OTA_NRF52_SECURITY_A_SIZE, "securityA size must match the shared C contract");
  static_assert(kBackupOffset == OTA_NRF52_BACKUP_OFFSET, "backup offset must match the shared C contract");
  static_assert(kBackupSize == OTA_NRF52_BACKUP_SIZE, "backup size must match the shared C contract");
  static_assert(kSecurityBOffset == OTA_NRF52_SECURITY_B_OFFSET, "securityB offset must match the shared C contract");
  static_assert(kSecurityBSize == OTA_NRF52_SECURITY_B_SIZE, "securityB size must match the shared C contract");
  static_assert(kJournalOffset == OTA_NRF52_JOURNAL_OFFSET, "journal offset must match the shared C contract");
  static_assert(kJournalSize == OTA_NRF52_JOURNAL_SIZE, "journal size must match the shared C contract");
  static_assert(kFilesystemOffset == OTA_NRF52_FILESYSTEM_OFFSET, "filesystem offset must match the shared C contract");
  static_assert(kFilesystemSize == OTA_NRF52_FILESYSTEM_SIZE, "filesystem size must match the shared C contract");
  static_assert(kCandidateRecordOffset == OTA_NRF52_CANDIDATE_RECORD_OFFSET, "candidate record offset must match the shared C contract");
  static_assert(kCandidateRecordSize == OTA_NRF52_CANDIDATE_RECORD_SIZE, "candidate record size must match the shared C contract");
  static_assert(kCandidateLastLegalSectorOffset == OTA_NRF52_CANDIDATE_LAST_LEGAL_SECTOR_OFFSET, "candidate last legal sector must match the shared C contract");
  static_assert(kBackupLastLegalSectorOffset == OTA_NRF52_BACKUP_LAST_LEGAL_SECTOR_OFFSET, "backup last legal sector must match the shared C contract");
  static_assert(OTA_NRF52_INTERNAL_IMAGE_OFFSET + OTA_NRF52_INTERNAL_IMAGE_SIZE ==
                    OTA_NRF52_INTERNAL_INSTALLER_OFFSET, "application must end at the fixed installer");
  static_assert(OTA_NRF52_INTERNAL_IMAGE_LAST_LEGAL_SECTOR_OFFSET + kEraseUnitBytes ==
                    OTA_NRF52_INTERNAL_INSTALLER_OFFSET, "last application sector must not reach the installer");
  static_assert(OTA_NRF52_INTERNAL_INSTALLER_OFFSET + OTA_NRF52_INTERNAL_INSTALLER_SIZE ==
                    OTA_NRF52_INTERNAL_FS_OFFSET, "installer must end at unchanged InternalExtraFS");
  static_assert(OTA_NRF52_INTERNAL_IMAGE_SIZE <= kCandidateSize &&
                    OTA_NRF52_INTERNAL_IMAGE_SIZE <= kBackupSize, "external banks must fit an installable application");
  static_assert(OTA_NRF52_INTERNAL_IMAGE_OFFSET % kEraseUnitBytes == 0 &&
                    OTA_NRF52_INTERNAL_IMAGE_SIZE % kEraseUnitBytes == 0 &&
                    OTA_NRF52_INTERNAL_INSTALLER_OFFSET % kEraseUnitBytes == 0 &&
                    OTA_NRF52_INTERNAL_INSTALLER_SIZE % kEraseUnitBytes == 0, "internal partitions must be sector aligned");
};

}  // namespace platform
}  // namespace ota
