#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

bool xiao_ota_vendor_start(uint32_t extent);
bool xiao_ota_vendor_finish(uint32_t extent);
bool xiao_ota_vendor_app_ready(void);
/* Query only after bootloader_dfu_start returns NRF_SUCCESS; not authorization. */
bool xiao_ota_vendor_recovery_complete(void);
bool xiao_ota_vendor_erase_page(uint32_t address);
bool xiao_ota_vendor_write(uint32_t address, const void *source, size_t length);

void xiao_ota_vendor_recovery_begin(void);
/* Admission comes from the configured native-USB serial START dispatcher. */
bool xiao_ota_vendor_usb_bench_mode(void);
bool xiao_ota_vendor_usb_bench_enter(void);
bool xiao_ota_primary_bench_prepare(void);
void xiao_ota_vendor_bench_allow_stage_repair(bool allowed);
#define XIAO_OTA_BENCH_PENDING UINT16_C(0xB34C)
