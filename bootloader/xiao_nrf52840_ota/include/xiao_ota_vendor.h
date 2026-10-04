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
