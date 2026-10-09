#include "xiao_ota_vendor.h"
#include "xiao_ota_vendor_sdk.h"
#include "xiao_ota_layout.h"
#include "nrf.h"
#include "nrf_sdm.h"
#include "nrf_error.h"
#include "app_timer.h"
#include <string.h>

extern uint32_t proc_soc(void);
extern void xiao_ota_primary_invalidate_app_grant(void);

static uint32_t ticks(void) {
  return app_timer_cnt_get() & UINT32_C(0x00ffffff);
}

static void feed_existing_watchdog(void) {
  if (NRF_WDT->RUNSTATUS) {
    for (unsigned i = 0; i < 8; ++i)
      if (NRF_WDT->RREN & (1u << i)) NRF_WDT->RR[i] = WDT_RR_RR_Reload;
  }
}

uint32_t xiao_ota_primary_init(void) {
  const xiao_ota_vendor_sdk_config_t config = {
      .internal = xiao_ota_boot_internal_io(),
      .app_end = xiao_ota_vendor_usb_bench_mode() ? 0xD4000u : XIAO_OTA_INSTALL_ALLOWED_END,
      .poll_soc = proc_soc,
      .ticks = ticks,
      .timeout_ticks = 5u * 32768u,
      .feed_existing_dfu_watchdog = feed_existing_watchdog,
      .invalidate_app_grant = xiao_ota_primary_invalidate_app_grant,
      .usb_bench = xiao_ota_vendor_usb_bench_mode(),
      .bench_prepare = xiao_ota_primary_bench_prepare,
  };
  return xiao_ota_vendor_sdk_init(&config);
}

bool xiao_ota_vendor_start(uint32_t extent) {
  xiao_ota_primary_invalidate_app_grant();
  return xiao_ota_vendor_sdk_prepare(extent);
}

bool xiao_ota_vendor_finish(uint32_t extent) {
  return xiao_ota_vendor_sdk_publish(extent);
}

bool xiao_ota_vendor_app_ready(void) {
  return xiao_ota_vendor_sdk_intact();
}

static bool direct_app_operation(uint32_t address, size_t bytes) {
  uint8_t enabled = 1;
  const uint32_t end = xiao_ota_vendor_usb_bench_mode() ? 0xD4000u : XIAO_OTA_INSTALL_ALLOWED_END;
  return address >= XIAO_OTA_APP_START && address < end &&
         bytes <= end - address &&
         xiao_ota_vendor_sd_is_enabled(&enabled) == NRF_SUCCESS && !enabled;
}

bool xiao_ota_vendor_erase_page(uint32_t address) {
  const xiao_ota_io_t *io = xiao_ota_boot_internal_io();
  return !(address & 4095u) && direct_app_operation(address, 4096) &&
         io->internal_erase_page(io->ctx, address);
}

bool xiao_ota_vendor_write(uint32_t address, const void *source, size_t bytes) {
  const xiao_ota_io_t *io = xiao_ota_boot_internal_io();
  return !((address | bytes) & 3u) && direct_app_operation(address, bytes) &&
         io->internal_write(io->ctx, address, source, bytes) &&
         memcmp((const void *)(uintptr_t)address, source, bytes) == 0;
}
