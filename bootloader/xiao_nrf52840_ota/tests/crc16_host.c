/*
 * Byte-identical copy of the pinned Nordic SDK's crc16_compute() algorithm
 * (lib/sdk/components/libraries/crc16/crc16.c, CRC-16-CCITT/0xFFFF init;
 * "the data can be passed in multiple blocks"), minus the sdk_common.h
 * module-enable wrapper that file requires and which is only available
 * inside the vendored Adafruit bootloader tree. xiao_ota_boot_io.c is
 * built standalone against this on the host so a native test can call the
 * SAME xiao_ota_boot_process_io() that runs on real hardware; this file
 * carries no OTA transaction decision logic of its own.
 */

#include "crc16.h"

#include <stddef.h>

uint16_t crc16_compute(uint8_t const *p_data, uint32_t size,
                       uint16_t const *p_crc) {
  uint16_t crc = (p_crc == NULL) ? 0xFFFF : *p_crc;
  uint32_t i;
  for (i = 0; i < size; i++) {
    crc = (uint8_t)(crc >> 8) | (crc << 8);
    crc ^= p_data[i];
    crc ^= (uint8_t)(crc & 0xFF) >> 4;
    crc ^= (crc << 8) << 4;
    crc ^= ((crc & 0xFF) << 4) << 1;
  }
  return crc;
}
