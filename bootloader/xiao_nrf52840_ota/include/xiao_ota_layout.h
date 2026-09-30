#pragma once

#include <stdint.h>

#define XIAO_OTA_APP_START             UINT32_C(0x00027000)
#define XIAO_OTA_APP_END               UINT32_C(0x000ED000)
#define XIAO_OTA_APP_MAX_SIZE          (XIAO_OTA_APP_END - XIAO_OTA_APP_START)

/*
 * v1.17's actual internal application code region is only
 * 0x27000..0xD4000 (708,608 bytes); 0xD4000..0xED000 is where v1.17's own
 * internal filesystem (LittleFS/ExtraFS) lives today. XIAO_OTA_APP_MAX_SIZE/
 * XIAO_OTA_CANDIDATE_SIZE/XIAO_OTA_BACKUP_SIZE intentionally span the FULL
 * 0x27000..0xED000 extent, because BACKING UP that many bytes -- a
 * protective read+copy of whatever is really there -- is always safe
 * regardless of what lives past 0xD4000. INSTALLING a candidate that large
 * is not safe: nothing else in the wire contract stops it from
 * erasing/overwriting into the filesystem region. XIAO_OTA_INSTALL_MAX_SIZE
 * caps the candidate/install size actually accepted by install-command
 * policy validation to the real v1.17 code region only, until an explicit
 * filesystem-relocation migration proves the FS no longer lives past this
 * boundary -- no such migration-complete signal exists yet, so this is the
 * unconditional default. This is a safety cap, not a wire-format change:
 * no schema, role/target/format field changes.
 */
#define XIAO_OTA_INSTALL_ALLOWED_END   UINT32_C(0x000D4000)
#define XIAO_OTA_INSTALL_MAX_SIZE      \
  (XIAO_OTA_INSTALL_ALLOWED_END - XIAO_OTA_APP_START)

#define XIAO_OTA_CANDIDATE_BASE        UINT32_C(0x000000)
#define XIAO_OTA_CANDIDATE_SIZE        UINT32_C(0x0C6000)
#define XIAO_OTA_BACKUP_BASE           UINT32_C(0x0C6000)
#define XIAO_OTA_BACKUP_SIZE           UINT32_C(0x0C6000)
#define XIAO_OTA_JOURNAL_BASE          UINT32_C(0x18C000)
#define XIAO_OTA_JOURNAL_SIZE          UINT32_C(0x008000)
#define XIAO_OTA_FILESYSTEM_BASE       UINT32_C(0x194000)
#define XIAO_OTA_FILESYSTEM_SIZE       UINT32_C(0x06C000)

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

#define XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS UINT32_C(0x000FF000)
#define XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE UINT32_C(28)

/* Physical P25Q16H pins, verified against variants/xiao_nrf52/variant.cpp. */
#define XIAO_OTA_QSPI_SCK_PIN          21u
#define XIAO_OTA_QSPI_CS_PIN           25u
#define XIAO_OTA_QSPI_IO0_PIN          20u
#define XIAO_OTA_QSPI_IO1_PIN          24u
#define XIAO_OTA_QSPI_IO2_PIN          22u
#define XIAO_OTA_QSPI_IO3_PIN          23u

