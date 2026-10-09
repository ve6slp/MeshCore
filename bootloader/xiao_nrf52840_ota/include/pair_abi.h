#ifndef OTAFIX_PAIR_ABI_H
#define OTAFIX_PAIR_ABI_H
#include <stdbool.h>
#include <stdint.h>
#include "xiao_ota_platform_layout_contract.h"

#define PAIR_MAGIC UINT32_C(0x3253464F)
#define PAIR_ABI_VERSION 1u
#define PAIR_STAGE_START OTA_NRF52_INTERNAL_INSTALLER_OFFSET
#define PAIR_STAGE_END (PAIR_STAGE_START + OTA_NRF52_INTERNAL_INSTALLER_SIZE)
#define PAIR_APP_START OTA_NRF52_INTERNAL_IMAGE_OFFSET
#define PAIR_APP_END PAIR_STAGE_START
#define PAIR_RAM_START UINT32_C(0x20020000)
#define PAIR_RAM_END UINT32_C(0x20030000)

typedef struct {
  uint32_t magic;
  uint32_t abi;
  uint32_t header_bytes;
  uint32_t board;
  uint32_t role;
  uint32_t extent;
  uint32_t entry;
  uint32_t ram_start;
  uint32_t ram_end;
} pair_header_t;

typedef struct {
  uint32_t abi;
  uint32_t bytes;
  uint32_t board;
  uint32_t role;
} pair_request_t;

typedef uint32_t pair_result_t;
enum {
  PAIR_RECOVERY = 0,
  PAIR_APP_INTACT = 1,
  PAIR_BENCH_READY = 2
};
#define PAIR_BENCH_REQUEST UINT32_C(0x42454E43)

typedef pair_result_t (*pair_entry_t)(const pair_request_t *);

typedef struct {
  uint32_t board;
  uint32_t role;
  uint32_t extent;
  uint32_t entry;
  uint32_t crc32;
} pair_expected_t;

bool pair_header_valid(const pair_header_t *, const pair_expected_t *);
bool pair_explicit_escape(uint32_t gpregret, bool pin, uint32_t marker,
                          bool dfu_button);
bool pair_app_gate(bool service_intact, bool bank_valid, bool vendor_valid,
                   bool pending);
bool pair_validate_internal(const pair_expected_t *);
pair_result_t pair_call(const pair_expected_t *);
bool pair_bench_reset(const pair_expected_t *);
bool pair_lock_protection(void);
#endif
