#ifndef OTA_PLATFORM_NRF52_FLASH_LAYOUT_CONTRACT_H
#define OTA_PLATFORM_NRF52_FLASH_LAYOUT_CONTRACT_H

/* Pure C, header-only, compile-time layout contract for the nRF52840 OTA
 * targets' flash geometry (external P25Q16H QSPI candidate/backup staging
 * plus the internal nRF52840 application image slot). DELIBERATELY NO C++
 * syntax, so the C bootloader / offline signing tooling can #include this
 * directly and agree byte-for-byte with ota::platform::SenseCapQspiLayout
 * (SenseCapQspiLayout.h, same directory, cross-checks every value here via
 * static_assert -- single source of truth).
 *
 * This header grants no provisioning/identity/key material and wires up
 * nothing itself; it only publishes the numeric partitioning contract. See
 * SenseCapQspiLayout.h for what MAIN needs to wire against these macros.
 */

/* Whole-device size and native NOR erase granularity (4 KiB sectors). */
#define OTA_NRF52_QSPI_TOTAL_BYTES        0x200000u  /* 2 MiB P25Q16H */
#define OTA_NRF52_QSPI_ERASE_UNIT_BYTES   0x1000u    /* 4 KiB */

/* Physical bank stride: the fixed distance from the start of the candidate
 * bank to the start of the backup bank. This is a PHYSICAL placement
 * constant only -- it is NOT writable image capacity. Never treat this
 * value as an erase/program bound; use OTA_NRF52_IMAGE_CAPACITY_BYTES for
 * that instead. Each physical bank is subdivided as:
 *   [bank_start, bank_start + OTA_NRF52_IMAGE_CAPACITY_BYTES)   -- image
 *   [bank_start + OTA_NRF52_IMAGE_CAPACITY_BYTES, bank_start + OTA_NRF52_PHYSICAL_BANK_STRIDE_BYTES)
 *                                                                -- security tail
 */
#define OTA_NRF52_PHYSICAL_BANK_STRIDE_BYTES  0xC6000u   /* 792 KiB, fixed; NOT writable capacity */
#define OTA_NRF52_IMAGE_CAPACITY_BYTES        0xAD000u   /* 708608 bytes, writable image capacity per bank */
#define OTA_NRF52_SECURITY_TAIL_BYTES         0x19000u   /* 100 KiB per bank */

/* Candidate bank: image capacity, then its security-tail half (securityA).
 * securityA/securityB are NOT per-bank signature/descriptor material --
 * together they are the two halves (A/B) of ONE global identity-owned
 * append/compaction store; this header only bounds them as raw capability
 * regions. */
#define OTA_NRF52_CANDIDATE_OFFSET    0x000000u
#define OTA_NRF52_CANDIDATE_SIZE      OTA_NRF52_IMAGE_CAPACITY_BYTES
#define OTA_NRF52_SECURITY_A_OFFSET   0x0AD000u  /* == OTA_NRF52_CANDIDATE_OFFSET + OTA_NRF52_CANDIDATE_SIZE */
#define OTA_NRF52_SECURITY_A_SIZE     OTA_NRF52_SECURITY_TAIL_BYTES

/* Backup bank: physically starts one full stride after candidate (fixed,
 * never move this even if OTA_NRF52_IMAGE_CAPACITY_BYTES changes), then
 * its own image capacity, then its security-tail half (securityB). */
#define OTA_NRF52_BACKUP_OFFSET       OTA_NRF52_PHYSICAL_BANK_STRIDE_BYTES  /* 0x0C6000, fixed */
#define OTA_NRF52_BACKUP_SIZE         OTA_NRF52_IMAGE_CAPACITY_BYTES
#define OTA_NRF52_SECURITY_B_OFFSET   0x173000u  /* == OTA_NRF52_BACKUP_OFFSET + OTA_NRF52_BACKUP_SIZE */
#define OTA_NRF52_SECURITY_B_SIZE     OTA_NRF52_SECURITY_TAIL_BYTES

/* Existing durable boot journal and external LittleFS regions. UNCHANGED
 * by this contract -- no filesystem/journal relocation. */
#define OTA_NRF52_JOURNAL_OFFSET      0x18C000u
#define OTA_NRF52_JOURNAL_SIZE        0x008000u  /* 32 KiB */
#define OTA_NRF52_FILESYSTEM_OFFSET   0x194000u
#define OTA_NRF52_FILESYSTEM_SIZE     0x06C000u  /* 432 KiB */

/* Last legal image-region sector START (inclusive) for each bank: the
 * final whole OTA_NRF52_QSPI_ERASE_UNIT_BYTES-aligned sector that is
 * still entirely inside the writable image capacity, i.e. exactly one
 * erase unit before the first security-tail byte. */
#define OTA_NRF52_CANDIDATE_LAST_LEGAL_SECTOR_OFFSET  0x0AC000u  /* == OTA_NRF52_SECURITY_A_OFFSET - erase unit */
#define OTA_NRF52_BACKUP_LAST_LEGAL_SECTOR_OFFSET     0x172000u  /* == OTA_NRF52_SECURITY_B_OFFSET - erase unit */

/* Durable candidate metadata A/B sectors, owned by OtaCandidateStore.
 * Separate from the boot journal, security tails and userdata. */
#define OTA_NRF52_CANDIDATE_RECORD_SIZE    0x2000u
#define OTA_NRF52_CANDIDATE_RECORD_OFFSET  0x0AB000u

/* Internal nRF52840 installable application slot, on a physically separate
 * flash device. Its target-specific ceiling is smaller than external
 * staging capacity: the fixed installer occupies the following 64 KiB.
 * Generic transport/cache geometry remains 708608 bytes and may stage
 * another target's image; staging capacity is NOT installation authority.
 */
#define OTA_NRF52_INTERNAL_IMAGE_OFFSET   0x027000u
#define OTA_NRF52_INTERNAL_IMAGE_SIZE     0x09D000u  /* 643072 bytes, ends 0x0C4000 */
#define OTA_NRF52_INTERNAL_IMAGE_LAST_LEGAL_SECTOR_OFFSET  0x0C3000u

/* Fixed installer, never application image/backup capacity. */
#define OTA_NRF52_INTERNAL_INSTALLER_OFFSET  0x0C4000u
#define OTA_NRF52_INTERNAL_INSTALLER_SIZE    0x010000u  /* 64 KiB, ends 0x0D4000 */

/* Existing internal-flash extra filesystem region (InternalExtraFS).
 * UNCHANGED / unmoved by this contract. */
#define OTA_NRF52_INTERNAL_FS_OFFSET  0x0D4000u
#define OTA_NRF52_INTERNAL_FS_SIZE    0x019000u  /* ends 0x0ED000, 100 KiB */

#endif /* OTA_PLATFORM_NRF52_FLASH_LAYOUT_CONTRACT_H */
