#pragma once

/*
 * Host-test-only copy of the pinned Nordic SDK's crc16.h prototype
 * (lib/sdk/components/libraries/crc16/crc16.h) so xiao_ota_boot_io.c can be
 * compiled standalone against tests/crc16_host.c without needing the
 * vendored Adafruit bootloader tree's sdk_common.h include chain. See
 * crc16_host.c for the (byte-identical) algorithm.
 */

#include <stdint.h>

uint16_t crc16_compute(uint8_t const *p_data, uint32_t size,
                       uint16_t const *p_crc);
