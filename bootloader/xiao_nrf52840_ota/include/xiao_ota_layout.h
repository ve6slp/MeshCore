#pragma once

#include <stdint.h>

/*
 * Pure-C, header-only shared flash-partitioning contract (owned by MAIN,
 * not this project) that ota::platform::SenseCapQspiLayout.h (C++ side)
 * also cross-checks itself against via static_assert. Included here
 * (never edited here) purely so the constants immediately below can be
 * verified, at compile time, to still agree byte-for-byte with it --
 * this is the single source of truth for the external QSPI candidate/
 * backup bank geometry and the internal application image slot.
 * xiao_ota_platform_layout_contract.h is a thin forwarding stub, not a
 * copy -- see its own doc-comment for why the indirection exists (the
 * upstream ARM build tree gets its own, freshly-copied REAL bytes of
 * the canonical contract at prepare_upstream.py time instead).
 */
#include "xiao_ota_platform_layout_contract.h"
#include "xiao_ota_record.h"

#define XIAO_OTA_APP_START             OTA_NRF52_INTERNAL_IMAGE_OFFSET
#define XIAO_OTA_APP_END               UINT32_C(0x000ED000)
#define XIAO_OTA_APP_MAX_SIZE          (XIAO_OTA_APP_END - XIAO_OTA_APP_START)

/*
 * The paired application slot is 0x27000..0xC4000 (643,072 bytes).
 * The fixed installer occupies 0xC4000..0xD4000; 0xD4000..0xED000 remains
 * the existing internal filesystem (LittleFS/ExtraFS). XIAO_OTA_APP_MAX_SIZE
 * intentionally spans the FULL 0x27000..0xED000 internal-flash extent
 * purely so a fresh bank-0 CRC-16 recompute can read (never write) across
 * whatever is genuinely there without an artificial internal-flash bound
 * getting in the way. It must NEVER be used as a bound on any actual
 * flash write/erase byte count: XIAO_OTA_INSTALL_MAX_SIZE (below) is the
 * one real writable-capacity bound, for BOTH the install/candidate size
 * and the active/backup image extent -- see xiao_ota_record.c's
 * xiao_ota_install_command_policy_valid() and xiao_ota_boot_io.c's
 * active_extent_from_settings() for why a larger bound on either would
 * let a write reach into v1.17's own filesystem region (internal flash)
 * or the external QSPI security-tail regions (candidate/backup banks).
 * XIAO_OTA_INSTALL_MAX_SIZE matches OTA_NRF52_INTERNAL_IMAGE_SIZE, not
 * the larger unchanged physical external-bank image capacity.
 * This is a safety cap, not a wire-format change: no schema,
 * role/target/format field changes.
 */
#define XIAO_OTA_INSTALL_ALLOWED_END   OTA_NRF52_INTERNAL_INSTALLER_OFFSET
#define XIAO_OTA_INSTALL_MAX_SIZE      OTA_NRF52_INTERNAL_IMAGE_SIZE

/*
 * XIAO_OTA_CANDIDATE_SIZE/XIAO_OTA_BACKUP_SIZE are the fixed PHYSICAL
 * bank-to-bank placement stride only (matching the shared contract's
 * OTA_NRF52_PHYSICAL_BANK_STRIDE_BYTES) -- NEVER a writable-capacity
 * bound. Each bank has physical image capacity 0xAD000, but this installer
 * admits only XIAO_OTA_INSTALL_MAX_SIZE (0x9D000). The final 0x19000 bytes
 * of the physical bank remain a separate, foreign, global identity/
 * security store (securityA/securityB in the shared contract) this
 * project must never erase or write into.
 */
#define XIAO_OTA_CANDIDATE_BASE        UINT32_C(0x000000)
#define XIAO_OTA_CANDIDATE_SIZE        UINT32_C(0x0C6000)
#define XIAO_OTA_BACKUP_BASE           UINT32_C(0x0C6000)
#define XIAO_OTA_BACKUP_SIZE           UINT32_C(0x0C6000)
#define XIAO_OTA_JOURNAL_BASE          UINT32_C(0x18C000)
#define XIAO_OTA_JOURNAL_SIZE          UINT32_C(0x008000)
#define XIAO_OTA_FILESYSTEM_BASE       UINT32_C(0x194000)
#define XIAO_OTA_FILESYSTEM_SIZE       UINT32_C(0x06C000)

/*
 * Cross-checks against the shared MAIN-owned contract (included above):
 * if either side ever drifts, this fails the build immediately rather
 * than silently disagreeing about where the security tails/filesystem
 * really start. Kept in the same style as SenseCapQspiLayout.h's own
 * cross-check static_asserts (C++ side) -- this is the C side.
 */
_Static_assert(XIAO_OTA_APP_START == OTA_NRF52_INTERNAL_IMAGE_OFFSET,
              "app start must match the shared C contract");
_Static_assert(XIAO_OTA_INSTALL_MAX_SIZE == OTA_NRF52_INTERNAL_IMAGE_SIZE,
              "install/active-extent writable capacity must match the shared C contract");
_Static_assert(XIAO_OTA_INSTALL_ALLOWED_END ==
                   XIAO_OTA_APP_START + XIAO_OTA_INSTALL_MAX_SIZE,
              "installer must immediately follow the installable APP");
_Static_assert(XIAO_OTA_INSTALL_ALLOWED_END + OTA_NRF52_INTERNAL_INSTALLER_SIZE ==
                   OTA_NRF52_INTERNAL_FS_OFFSET,
              "installer must end at the unchanged extra filesystem");
_Static_assert(XIAO_OTA_APP_END == OTA_NRF52_INTERNAL_FS_OFFSET + OTA_NRF52_INTERNAL_FS_SIZE,
              "internal filesystem end must match the shared C contract");
_Static_assert(XIAO_OTA_CANDIDATE_BASE == OTA_NRF52_CANDIDATE_OFFSET,
              "candidate base must match the shared C contract");
_Static_assert(XIAO_OTA_CANDIDATE_SIZE == OTA_NRF52_PHYSICAL_BANK_STRIDE_BYTES,
              "candidate/backup physical stride must match the shared C contract");
_Static_assert(XIAO_OTA_BACKUP_BASE == OTA_NRF52_BACKUP_OFFSET,
              "backup base must match the shared C contract");
_Static_assert(XIAO_OTA_BACKUP_SIZE == OTA_NRF52_PHYSICAL_BANK_STRIDE_BYTES,
              "backup physical stride must match the shared C contract");
_Static_assert(XIAO_OTA_JOURNAL_BASE == OTA_NRF52_JOURNAL_OFFSET,
              "journal base must match the shared C contract");
_Static_assert(XIAO_OTA_JOURNAL_SIZE == OTA_NRF52_JOURNAL_SIZE,
              "journal size must match the shared C contract");
_Static_assert(XIAO_OTA_FILESYSTEM_BASE == OTA_NRF52_FILESYSTEM_OFFSET,
              "external filesystem base must match the shared C contract");
_Static_assert(XIAO_OTA_FILESYSTEM_SIZE == OTA_NRF52_FILESYSTEM_SIZE,
              "external filesystem size must match the shared C contract");

#define XIAO_OTA_COMMAND_A             UINT32_C(0x18C000)
#define XIAO_OTA_COMMAND_B             UINT32_C(0x18D000)
#define XIAO_OTA_STATE_A               UINT32_C(0x18E000)
#define XIAO_OTA_STATE_B               UINT32_C(0x18F000)
#define XIAO_OTA_CONFIRM_A             UINT32_C(0x190000)
#define XIAO_OTA_CONFIRM_B             UINT32_C(0x191000)
#define XIAO_OTA_FLOOR_A               UINT32_C(0x192000)
#define XIAO_OTA_FLOOR_B               UINT32_C(0x193000)

#define XIAO_OTA_QSPI_SECTOR_SIZE      UINT32_C(0x1000)
#define XIAO_OTA_QSPI_PAGE_SIZE        UINT32_C(0x0100)

/*
 * Internal-flash page holding Nordic SDK11's `bootloader_settings_t`
 * (bank_0/bank_0_crc/bank_0_size plus several fields this project never
 * inspects). Mirrors dfu_types.h's BOOTLOADER_SETTINGS_ADDRESS for the
 * NRF52840_XXAA (1 MiB flash) case exactly -- kept here as a plain
 * constant (instead of including the Nordic SDK header) so the portable
 * transaction processor has no SDK dependency and can link into a native
 * host test build. XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE is the real
 * on-flash struct's size (verified by a compile-time static assertion
 * against the host-safe mirror in xiao_ota_boot_io.c).
 */
#define XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS UINT32_C(0x000FF000)
#define XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE UINT32_C(28)

/*
 * nRF52840 internal code-flash page-erase granularity: this project's own
 * internal_erase_page() callback (xiao_ota_boot.c's
 * hw_internal_erase_page(), NRF_NVMC->ERASEPAGE) always erases a full
 * 4 KiB page. Numerically identical to XIAO_OTA_QSPI_SECTOR_SIZE but
 * given its own name because it describes INTERNAL flash granularity,
 * never the external QSPI part -- copy_qspi_to_internal() already
 * assumed this same 4 KiB internal page size before this constant
 * existed; it is used explicitly here for the settings-page tail-blank
 * check below.
 */
#define XIAO_OTA_INTERNAL_PAGE_SIZE    UINT32_C(0x1000)

/*
 * Boot-private settings sidecar: a SECOND small record living inside
 * EACH existing state sector (offset 0x100, i.e. XIAO_OTA_STATE_A+0x100
 * and XIAO_OTA_STATE_B+0x100 -- never the backup bank, never a new
 * sector of its own), holding the exact original Nordic bootloader
 * settings page (raw28) captured once at transaction admission. This
 * lets rollback restore the pre-install settings page byte-for-byte,
 * rather than reconstructing it from whatever the (possibly torn)
 * CURRENT settings page holds. It shares its physical erase unit with
 * the state record it accompanies -- see xiao_ota_settings_sidecar_t
 * (xiao_ota_record.h) and write_state_with_sidecar() (xiao_ota_boot_io.c)
 * for the one-erase, sidecar-first-then-state write ordering.
 */
#define XIAO_OTA_SETTINGS_SIDECAR_OFFSET UINT32_C(0x100)
#define XIAO_OTA_SETTINGS_SIDECAR_A \
  (XIAO_OTA_STATE_A + XIAO_OTA_SETTINGS_SIDECAR_OFFSET)
#define XIAO_OTA_SETTINGS_SIDECAR_B \
  (XIAO_OTA_STATE_B + XIAO_OTA_SETTINGS_SIDECAR_OFFSET)

/* Physical P25Q16H pins, verified against variants/xiao_nrf52/variant.cpp. */
#define XIAO_OTA_QSPI_SCK_PIN          21u
#define XIAO_OTA_QSPI_CS_PIN           25u
#define XIAO_OTA_QSPI_IO0_PIN          20u
#define XIAO_OTA_QSPI_IO1_PIN          24u
#define XIAO_OTA_QSPI_IO2_PIN          22u
#define XIAO_OTA_QSPI_IO3_PIN          23u
