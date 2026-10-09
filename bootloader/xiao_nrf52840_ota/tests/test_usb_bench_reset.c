#include "fake_io.h"
#include "xiao_ota_layout.h"
#include "xiao_ota_record.h"
#include "xiao_ota_vendor.h"
#include "crc16.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void randombytes(unsigned char *buffer, unsigned long long length) {
  memset(buffer, 0x37, (size_t)length);
}

int main(void) {
  static fake_io_state_t state, before;
  fake_io_reset(&state);
  memset(state.qspi, 0x35, sizeof(state.qspi));
  memset(state.internal_flash, 0x73, sizeof(state.internal_flash));
  before = state;
  xiao_ota_io_t io = fake_io_interface(&state);
  assert(!xiao_ota_usb_bench_reset(&io, false));
  assert(!state.qspi_init_calls && !memcmp(state.qspi, before.qspi, sizeof(state.qspi)));
  assert(!memcmp(state.internal_flash, before.internal_flash, sizeof(state.internal_flash)));
  state.fail.op = FAKE_IO_OP_QSPI_ERASE;
  state.fail.after = 2;
  assert(!xiao_ota_usb_bench_reset(&io, true));
  assert(!memcmp(state.internal_flash, before.internal_flash, sizeof(state.internal_flash)));
  state.fail.op = FAKE_IO_OP_NONE;
  assert(xiao_ota_usb_bench_reset(&io, true));
  for (size_t i = 0; i < sizeof(state.qspi); ++i) assert(state.qspi[i] == 0xff);
  for (size_t i = 0xD4000; i < 0xF4000; ++i) assert(state.internal_flash[i] == 0xff);
  assert(!memcmp(state.internal_flash, before.internal_flash, 0xD4000));
  assert(!memcmp(state.internal_flash + 0xF4000, before.internal_flash + 0xF4000, 0xC000));
  /* Same real USB codecs: field recovery refuses a compound; bench accepts it. */
  memset(state.internal_flash + XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS, 0xff, 4096);
  fake_io_provision_bank0_settings(&state, 1, 1, 8192);
  assert(!xiao_ota_vendor_prepare(&io, 0xAD000));
  assert(xiao_ota_usb_bench_prepare(&io, 0xAD000));
  const uint32_t vectors[] = {0x20040000, 0x27009};
  memset(state.internal_flash + 0x27000, 0x41, 0xAD000);
  memcpy(state.internal_flash + 0x27000, vectors, sizeof(vectors));
  assert(xiao_ota_usb_bench_publish(&io, 0xAD000));
  assert(xiao_ota_usb_bench_intact(&io));
  assert(!xiao_ota_app_is_intact(&io)); /* Cannot be a normal OTA baseline. */
  assert(!xiao_ota_usb_bench_prepare(&io, 0xAD004));
  struct {
    uint16_t bank_0, crc, bank_1, padding;
    uint32_t extent, sd_size, bl_size, app_size, sd_start;
  } pending = {XIAO_OTA_BANK_INVALID_APP, 0, 0xAA, XIAO_OTA_BENCH_PENDING,
               0xA000, 0, 0xA000, 0, 0};
  assert(sizeof(pending) == 28);
  assert(xiao_ota_vendor_settings_write(&io, (const uint8_t *)&pending));
  pending.bank_1 = XIAO_OTA_BANK_INVALID_APP;
  pending.bl_size = 0;
  assert(xiao_ota_vendor_pending_settings_write(&io, (const uint8_t *)&pending));
  assert(!memcmp(state.internal_flash + XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS,
                 &pending, sizeof(pending)));
  pending.bank_1 = 0xAA; pending.bl_size = 0xA000;
  assert(xiao_ota_vendor_settings_write(&io, (const uint8_t *)&pending));
  assert(!xiao_ota_vendor_prepare(&io, 8192));
  state.internal_flash[XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + 32] = 0;
  assert(xiao_ota_usb_bench_prepare(&io, 8192));
  assert(state.internal_flash[XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + 32] == 0xff);
  assert(xiao_ota_usb_bench_publish(&io, 8192));
  assert(xiao_ota_app_is_intact(&io));
  assert(fake_io_run_boot(&state) == 0);
  xiao_ota_floor_t floor;
  memcpy(&floor, state.qspi + XIAO_OTA_FLOOR_A, sizeof(floor));
  assert(xiao_ota_floor_valid(&floor) && floor.confirmed_counter_floor == 0);
  puts("Literal bench reset: unauthorized no-op, fault/retry, bounded userdata wipe, compound/ordinary APP codecs, real cold floor0 PASS");
}
