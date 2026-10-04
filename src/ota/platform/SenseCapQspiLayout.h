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
// This supersedes the earlier full-bank revision of this layout (candidate
// 0x000000..0x0C6000 / backup 0x0C6000..0x18C000, no reserved tail), whose
// lab-only carve-out at 0x0C2000..0x0C6000 consequently overlapped the
// newly introduced securityA region. Eliminated here: candidateRegion()/
// backupRegion() are now sized to EXACTLY IMAGE_CAPACITY_BYTES (never the
// full physical stride), so FlashRegion's own bounds checking structurally
// rejects any program/erase crossing the first tail byte. The
// maintenance/hardware-qualification scratch carve-out is relocated to
// 0x0A9000..0x0AD000, entirely inside the candidate bank's own image
// capacity.
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

  // Destructive hardware qualification (raw erase/program/readback probing,
  // staged signed-image install rehearsal) is confined to this reserved
  // subregion at the END of the candidate bank's own image capacity,
  // immediately before kSecurityAOffset -- never overlapping securityA,
  // the journal, or the filesystem. It is candidate-owned, never shared
  // space: candidate is always erased/rewritten at the start of every real
  // OTA campaign, unlike the journal (see ota::storage::Journal.h), whose
  // slots can transiently hold the durable antirollback "floor" checkpoint
  // and must never be a qualification target.
  //
  // Guard note: ota::storage::XiaoOtaCommissioningGuard's blank-journal /
  // no-boot-marker signals are ABSENCE of evidence, not proof of a virgin
  // device -- a "not detected" result must never be read as "confirmed
  // never commissioned." Any caller of this scratch region must require
  // explicit maintenance authorization AND confirm no live candidate image
  // or backup/recovery state exists; the guard's checks may be retained as
  // one input but never treated as sufficient proof on their own.
  //
  // kCandidateTestOffset/kCandidateTestSize/candidateTestRegion() are kept
  // (values corrected to the new safe range) so existing callers keep
  // compiling; kCandidateMaintenanceScratchOffset/Size/
  // candidateMaintenanceScratchRegion() are the preferred aliases.
  static constexpr uint32_t kCandidateTestOffset = OTA_NRF52_MAINTENANCE_SCRATCH_OFFSET; // 0xA9000
  static constexpr uint32_t kCandidateTestSize   = OTA_NRF52_MAINTENANCE_SCRATCH_SIZE;   // 0x4000 (16 KiB)
  static constexpr uint32_t kCandidateMaintenanceScratchOffset = kCandidateTestOffset;
  static constexpr uint32_t kCandidateMaintenanceScratchSize   = kCandidateTestSize;

  // kJournalTestOffset/kJournalTestSize/journalTestRegion() are kept for
  // source compatibility with existing callers, but RELOCATED: they used
  // to sit inside the real 32 KiB boot journal (0x192000, 8 KiB, next to
  // the bootloader-owned floor slots); that is no longer safe to use as a
  // destructive qualification target, so this legacy name is now an alias
  // for the last two erase sectors (8 KiB) of the candidate-owned
  // maintenance scratch above -- never any part of the real journal, a
  // security tail, or the filesystem. kCandidateRecordScratchOffset/Size/
  // candidateRecordScratchRegion() are the preferred, unambiguously-named
  // aliases for new code.
  static constexpr uint32_t kJournalTestOffset = OTA_NRF52_CANDIDATE_RECORD_SCRATCH_OFFSET; // 0xAB000
  static constexpr uint32_t kJournalTestSize   = OTA_NRF52_CANDIDATE_RECORD_SCRATCH_SIZE;   // 0x2000 (8 KiB)
  static constexpr uint32_t kCandidateRecordScratchOffset = kJournalTestOffset;
  static constexpr uint32_t kCandidateRecordScratchSize   = kJournalTestSize;

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
  // filesystem), plus the fixed physical-stride and maintenance-scratch
  // invariants.
  static bool isValid() {
    if (!isAligned(kCandidateOffset) || !isAligned(kCandidateSize)) return false;
    if (!isAligned(kSecurityAOffset) || !isAligned(kSecurityASize)) return false;
    if (!isAligned(kBackupOffset) || !isAligned(kBackupSize)) return false;
    if (!isAligned(kSecurityBOffset) || !isAligned(kSecurityBSize)) return false;
    if (!isAligned(kJournalOffset) || !isAligned(kJournalSize)) return false;
    if (!isAligned(kFilesystemOffset) || !isAligned(kFilesystemSize)) return false;
    if (!isAligned(kCandidateTestOffset) || !isAligned(kCandidateTestSize)) return false;

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

    // Maintenance scratch must be entirely candidate-owned (never
    // reaching into securityA) and must sit immediately before it.
    if (!fitsWithin(kCandidateTestOffset, kCandidateTestSize, kCandidateOffset + kCandidateSize)) return false;
    if (kCandidateTestOffset + kCandidateTestSize != kSecurityAOffset) return false;
    if (rangesOverlap(kCandidateTestOffset, kCandidateTestSize, kSecurityAOffset, kSecurityASize)) return false;
    if (rangesOverlap(kCandidateTestOffset, kCandidateTestSize, kJournalOffset, kJournalSize)) return false;
    if (rangesOverlap(kCandidateTestOffset, kCandidateTestSize, kFilesystemOffset, kFilesystemSize)) return false;

    // The legacy "journal test" alias must be entirely INSIDE the
    // candidate-owned maintenance scratch above (never any part of the
    // real journal, a security tail, or the filesystem).
    if (!isAligned(kJournalTestOffset) || !isAligned(kJournalTestSize)) return false;
    if (!fitsWithin(kJournalTestOffset, kJournalTestSize, kCandidateTestOffset + kCandidateTestSize)) return false;
    if (kJournalTestOffset < kCandidateTestOffset) return false;
    if (kJournalTestOffset + kJournalTestSize != kCandidateTestOffset + kCandidateTestSize) return false;
    if (rangesOverlap(kJournalTestOffset, kJournalTestSize, kJournalOffset, kJournalSize)) return false;
    if (rangesOverlap(kJournalTestOffset, kJournalTestSize, kSecurityAOffset, kSecurityASize)) return false;
    if (rangesOverlap(kJournalTestOffset, kJournalTestSize, kSecurityBOffset, kSecurityBSize)) return false;
    if (rangesOverlap(kJournalTestOffset, kJournalTestSize, kFilesystemOffset, kFilesystemSize)) return false;

    // Last-legal-sector constants must be exactly one erase unit before
    // each bank's security tail.
    if (kCandidateLastLegalSectorOffset + kEraseUnitBytes != kSecurityAOffset) return false;
    if (kBackupLastLegalSectorOffset + kEraseUnitBytes != kSecurityBOffset) return false;

    return true;
  }

  static FlashRegion candidateRegion(FlashDevice& device) {
    return FlashRegion(device, kCandidateOffset, kCandidateSize);
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
  // Maintenance/lab-only destructive scratch region -- see kCandidateTestOffset
  // above. This accessor performs no gating itself; callers MUST require
  // explicit maintenance authorization and confirm no live candidate image
  // or backup/recovery state exists before using it (absence of a
  // commissioning signal is not proof of that).
  static FlashRegion candidateTestRegion(FlashDevice& device) {
    return FlashRegion(device, kCandidateTestOffset, kCandidateTestSize);
  }
  // Preferred, unambiguously-named alias for candidateTestRegion() -- see
  // the note above kCandidateTestOffset.
  static FlashRegion candidateMaintenanceScratchRegion(FlashDevice& device) {
    return candidateTestRegion(device);
  }
  // Legacy name, RELOCATED -- see kJournalTestOffset above: this no
  // longer touches the real journal at all. It is the last two erase
  // sectors of candidateTestRegion()/candidateMaintenanceScratchRegion(),
  // never the real journal, a security tail, or the filesystem.
  static FlashRegion journalTestRegion(FlashDevice& device) {
    return FlashRegion(device, kJournalTestOffset, kJournalTestSize);
  }
  // Preferred, unambiguously-named alias for journalTestRegion() -- see
  // the note above kJournalTestOffset.
  static FlashRegion candidateRecordScratchRegion(FlashDevice& device) {
    return journalTestRegion(device);
  }

  // The XIAO nRF52840 custom bootloader (bootloader/xiao_nrf52840_ota/)
  // subdivides this SAME physical journal partition into fixed 4 KiB
  // sub-slots for its own record types, distinct from (and never written
  // concurrently with, on real hardware) the generic
  // ota::storage::Journal/JournalCheckpoint format used by the portable
  // ota::boot::BootTransaction self-install path:
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

  // Full 8-sub-slot journal partition (all four A/B pairs above: install
  // command, install state, confirmation, confirmed-counter floor), for
  // LAB-ONLY read-only diagnostics that need to inspect/cross-check
  // multiple sub-slots at fixed indices (see
  // ota::storage::XiaoOtaLegacyResidue and CMD_OTA_LAB's subtype-1 8-index
  // wire contract). Application code must still only ever READ via this
  // accessor except for the one, separately-gated floor-A-only erase.
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
  static_assert(kCandidateTestOffset == OTA_NRF52_MAINTENANCE_SCRATCH_OFFSET, "maintenance scratch offset must match the shared C contract");
  static_assert(kCandidateTestSize == OTA_NRF52_MAINTENANCE_SCRATCH_SIZE, "maintenance scratch size must match the shared C contract");
  static_assert(kJournalTestOffset == OTA_NRF52_CANDIDATE_RECORD_SCRATCH_OFFSET, "relocated legacy journal-test offset must match the shared C contract");
  static_assert(kJournalTestSize == OTA_NRF52_CANDIDATE_RECORD_SCRATCH_SIZE, "relocated legacy journal-test size must match the shared C contract");
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
