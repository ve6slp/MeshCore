#pragma once

#include "xiao_ota_boot_io.h"
#include "bootloader_settings.h"

typedef struct {
  const xiao_ota_io_t *internal;
  uint32_t app_end;
  uint32_t (*poll_soc)(void);
  uint32_t (*ticks)(void);
  uint32_t timeout_ticks;
  void (*feed_existing_dfu_watchdog)(void);
  void (*invalidate_app_grant)(void);
  bool usb_bench;
  bool (*bench_prepare)(void);
} xiao_ota_vendor_sdk_config_t;

uint32_t xiao_ota_vendor_sdk_init(const xiao_ota_vendor_sdk_config_t *config);
bool xiao_ota_vendor_sdk_usb_bench_enter(void);
uint32_t xiao_ota_vendor_sdk_boot_entry(bool routed);
uint32_t xiao_ota_vendor_sdk_sd_init_result(uint32_t error);
uint32_t xiao_ota_vendor_sd_is_enabled(uint8_t *enabled);
uint32_t xiao_ota_vendor_sdk_drain(void);
bool xiao_ota_vendor_sdk_upload_begin(void);
bool xiao_ota_vendor_sdk_prepare(uint32_t extent);
bool xiao_ota_vendor_sdk_publish(uint32_t extent);
bool xiao_ota_vendor_sdk_intact(void);
bool xiao_ota_vendor_sdk_save(const bootloader_settings_t *settings);
bool xiao_ota_vendor_sdk_finalize(const bootloader_settings_t *settings);
uint32_t xiao_ota_vendor_pending_check(void);

bool pstorage_raw_busy(void);
uint32_t pstorage_raw_poll(void);
