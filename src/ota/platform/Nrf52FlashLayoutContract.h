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

/* Maintenance destructive scratch: the ONLY sub-range application/lab code
 * may erase/program repeatedly for raw hardware-qualification probing
 * outside of a real signed-image install. Candidate-owned space, entirely
 * inside OTA_NRF52_CANDIDATE's own image capacity, immediately before
 * OTA_NRF52_SECURITY_A_OFFSET -- NEVER shared/spare space.
 *
 * A blank journal / absent boot marker (see
 * ota::storage::XiaoOtaCommissioningGuard) is ABSENCE of evidence, not
 * proof of a virgin device. Callers MUST require explicit maintenance
 * authorization and confirm no live candidate image or backup/recovery
 * state exists before using this range; they must never derive "never
 * commissioned" from the guard's signals alone, and must never grant
 * ordinary/unconditional writes here.
 */
#define OTA_NRF52_MAINTENANCE_SCRATCH_SIZE    0x4000u   /* 16 KiB */
#define OTA_NRF52_MAINTENANCE_SCRATCH_OFFSET  0x0A9000u /* == OTA_NRF52_CANDIDATE_SIZE - scratch size */

/* Legacy "journal test" scratch sub-range, RELOCATED: this used to sit
 * inside the real 32 KiB boot journal (0x192000, 8 KiB, adjacent to the
 * bootloader-owned floor slots) before the tail-safe map existed. It is
 * now the LAST two erase sectors (8 KiB) of the candidate-owned
 * maintenance scratch above -- entirely inside OTA_NRF52_CANDIDATE's own
 * image capacity, and NEVER any part of the real journal, a security
 * tail, or the filesystem. The name is kept only for source
 * compatibility with existing callers; treat
 * OTA_NRF52_CANDIDATE_RECORD_SCRATCH_OFFSET/SIZE as the preferred name
 * for new code. Never use the real journal region itself as a
 * destructive qualification target (see the note above).
 */
#define OTA_NRF52_CANDIDATE_RECORD_SCRATCH_SIZE    0x2000u   /* 8 KiB (2 sectors) */
#define OTA_NRF52_CANDIDATE_RECORD_SCRATCH_OFFSET  0x0AB000u /* == MAINTENANCE_SCRATCH end - 8 KiB */

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
