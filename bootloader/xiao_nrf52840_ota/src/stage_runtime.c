#include "pair_abi.h"
#include "stage_recovery.h"
#include "xiao_ota_boot.h"
#include "xiao_ota_boot_io.h"
#include <stddef.h>
#include <stdint.h>

extern uint8_t __data_start__, __data_end__, __data_load__;
extern uint8_t __bss_start__, __bss_end__;
extern pair_result_t stage_entry(const pair_request_t *);
static volatile uint32_t initialized_cookie = UINT32_C(0x3241544F);
static volatile uint32_t zero_cookie;

__attribute__((used, section(".pair_header")))
const pair_header_t stage_header = {
    PAIR_MAGIC, PAIR_ABI_VERSION, sizeof(pair_header_t),
    XIAO_OTA_BOARD_TARGET, XIAO_OTA_COMPILED_ROLE_ID,
    UINT32_MAX, UINT32_MAX, PAIR_RAM_START, PAIR_RAM_END};

/* Called on the primary's existing MSP. This wrapper is deliberately not a
 * reset handler: S140, VTOR, CONTROL, interrupt mask and MSP remain primary-owned. */
pair_result_t stage_run(const pair_request_t *request) {
  if (!request || request->abi != PAIR_ABI_VERSION ||
      (request->bytes != sizeof(*request) && request->bytes != sizeof(*request) + 4) ||
      request->board != XIAO_OTA_BOARD_TARGET ||
      request->role != XIAO_OTA_COMPILED_ROLE_ID) return PAIR_RECOVERY;
  const uint8_t *source = &__data_load__;
  for (uint8_t *dest = &__data_start__; dest < &__data_end__; ++dest)
    *dest = *source++;
  for (uint8_t *dest = &__bss_start__; dest < &__bss_end__; ++dest) *dest = 0;
  if (initialized_cookie != UINT32_C(0x3241544F) || zero_cookie != 0)
    return PAIR_RECOVERY;
  if (request->bytes == sizeof(*request) + 4) {
    const uint32_t *operation = (const uint32_t *)(request + 1);
    return *operation == PAIR_BENCH_REQUEST && xiao_ota_boot_bench_reset() ?
        PAIR_BENCH_READY : PAIR_RECOVERY;
  }
  xiao_ota_boot_process();
  return xiao_ota_stage2_recovery_requested() ? PAIR_RECOVERY : PAIR_APP_INTACT;
}
