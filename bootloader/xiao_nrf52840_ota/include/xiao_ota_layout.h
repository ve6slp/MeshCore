#pragma once

#include <stdint.h>

#define XIAO_OTA_APP_START             UINT32_C(0x00027000)
#define XIAO_OTA_APP_END               UINT32_C(0x000ED000)
#define XIAO_OTA_APP_MAX_SIZE          (XIAO_OTA_APP_END - XIAO_OTA_APP_START)

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

/* Physical P25Q16H pins, verified against variants/xiao_nrf52/variant.cpp. */
#define XIAO_OTA_QSPI_SCK_PIN          21u
#define XIAO_OTA_QSPI_CS_PIN           25u
#define XIAO_OTA_QSPI_IO0_PIN          20u
#define XIAO_OTA_QSPI_IO1_PIN          24u
#define XIAO_OTA_QSPI_IO2_PIN          22u
#define XIAO_OTA_QSPI_IO3_PIN          23u

