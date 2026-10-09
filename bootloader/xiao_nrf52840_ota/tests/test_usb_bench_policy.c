/* Execute the actual generated SDK11 packet handler and MBR swap function. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <setjmp.h>
#include "nrf.h"
#include "xiao_ota_vendor.h"
#include "xiao_ota_layout.h"
#include "crc16.h"

#define NRF_SUCCESS 0u
#define NRF_ERROR_INVALID_STATE 1u
#define NRF_ERROR_NOT_SUPPORTED 2u
#define NRF_ERROR_DATA_SIZE 3u
#define NRF_ERROR_INTERNAL 4u
#define NRF_ERROR_INVALID_LENGTH 5u
#define NRF_ERROR_INVALID_ADDR 6u
#define NRF_ERROR_INVALID_DATA 7u
#define APP_ERROR_CHECK(e) do { if ((e) != NRF_SUCCESS) { last_error = (e); longjmp(errors, 1); } } while (0)
#define VERIFY_PARAM_NOT_NULL(p) do { if (!(p)) return NRF_ERROR_INTERNAL; } while (0)
#define VERIFY_SUCCESS(e) do { if ((e)) return (e); } while (0)
#define DFU_UPDATE_APP 4u
#define DFU_UPDATE_SD 1u
#define DFU_UPDATE_BL 2u
#define DFU_STATE_IDLE 0u
#define DFU_STATE_RX_DATA_PKT 1u
#define DFU_STATE_VALIDATE 2u
#define DFU_STATE_WAIT_4_ACTIVATE 3u
#define DFU_UPDATE_BOOT_COMPLETE 1u
#define BOOTLOADER_SETTINGS_SAVING 1u
#define DFU_BL_IMAGE_MAX_SIZE 0xA000u
#define DFU_IMAGE_MAX_SIZE_FULL 0xAD000u
#define DFU_BANK_0_REGION_START 0x27000u
#define BANK_VALID_BOOT 0xAAu
#define BANK_VALID_APP 1u
#define BANK_INVALID_APP 0xFFu
#define BANK_VALID_SD 0xA5u
#define BOOTLOADER_REGION_START 0xF4000u
#define SD_MBR_COMMAND_COPY_BL 1u
#define SD_MBR_COMMAND_COMPARE 2u
typedef struct { uint32_t dfu_update_mode, sd_image_size, bl_image_size, app_image_size; } start_t;
typedef start_t dfu_start_packet_t;
typedef struct {
  uint32_t packet_type;
  union {
    start_t *start_packet;
    struct { uint32_t *p_data_packet; uint32_t packet_length; } data_packet;
  } params;
} dfu_update_packet_t;
typedef struct {
  uint16_t bank_0, bank_0_crc, bank_1;
  uint32_t bank_0_size, sd_image_size, bl_image_size, app_image_size, sd_image_start;
} bootloader_settings_t;
typedef struct {
  uint32_t command;
  union {
    struct { uint32_t *bl_src; uint32_t bl_len; } copy_bl;
    struct { uint32_t *ptr1, *ptr2; uint32_t len; } compare;
  } params;
} sd_mbr_command_t;
#define IS_UPDATING_APP(s) ((s).dfu_update_mode & DFU_UPDATE_APP)
#define IS_UPDATING_SD(s) ((s).dfu_update_mode & DFU_UPDATE_SD)
#define IS_UPDATING_BL(s) ((s).dfu_update_mode & DFU_UPDATE_BL)
#define IS_WORD_SIZED(n) (!((n) & 3u))
static start_t m_start_packet;
static uint32_t m_image_size, m_dfu_state;
static uint32_t m_data_received, m_update_status;
static uint16_t m_extended_packet[1];
static struct { uintptr_t block_id; } active_storage;
static __typeof__(active_storage) *mp_storage_handle_active = &active_storage;
typedef struct {
  uint32_t status_code, app_crc, sd_size, bl_size, app_size;
} dfu_update_status_t;
static struct { void (*prepare)(uint32_t); void (*cleared)(void); uint32_t (*activate)(void); } m_functions;
static bool usb_bench, ble, sd_enabled, mounted, sd_query_error;
#define bench usb_bench
mock_power_t mock_power;
mock_acl_t mock_acl;
static jmp_buf errors;
static uint32_t last_error;
static bool stage_repair_allowed;
static unsigned prepares, swaps;
static bootloader_settings_t settings;
static bool initialized = true, poisoned, io_error, bad_tail, changing_settings;
static unsigned settings_reads;
static bool bench_prepare(void) { return true; }
static struct {
  uint32_t app_end;
  bool usb_bench;
  bool (*bench_prepare)(void);
} config = {0xC4000u, false, bench_prepare};
bool xiao_ota_vendor_sdk_upload_begin(void) { return true; }
uint32_t xiao_ota_vendor_sdk_drain(void) { return 0; }
static uint16_t uint16_decode(const uint8_t *bytes) { return bytes[0] | (uint16_t)bytes[1] << 8; }
static void bootloader_settings_save(const bootloader_settings_t *value) {
  memcpy(&settings, value, sizeof(settings));
}
static uint16_t raw_marker(const bootloader_settings_t *value) {
  uint16_t marker;
  memcpy(&marker, (const uint8_t *)value + 6, sizeof(marker));
  return marker;
}
static void set_marker(uint16_t marker) { memcpy((uint8_t *)&settings + 6, &marker, 2); }
static bool sd_enabled_query(bool *out) {
  if (sd_query_error) return false;
  *out = sd_enabled;
  return true;
}
static bool read_internal(void *ctx, uint32_t address, void *buffer, size_t count) {
  (void)ctx;
  uint8_t *bytes = buffer;
  if (io_error) return false;
  if (address == XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS && count == sizeof(settings)) {
    memcpy(bytes, &settings, count);
    if (changing_settings && settings_reads++) bytes[0] ^= 1;
  } else if (address >= 0x27000 && address + count <= 0x31000) {
    memcpy(bytes, (void *)(uintptr_t)address, count);
  } else {
    memset(bytes, 255, count);
    if (bad_tail) bytes[0] = 0;
  }
  return true;
}
static void dfu_prepare_func_app_erase(uint32_t n) { assert(n == m_image_size); ++prepares; }
static void dfu_cleared_func_app(void) {}
static uint32_t dfu_activate_sd(void) { return 0; }
static uint32_t dfu_activate_bl(void);
static uint32_t dfu_activate_app(void) { return 0; }
static bool is_ota(void) { return ble; }
static bool tud_mounted(void) { return mounted; }
bool xiao_ota_vendor_usb_bench_mode(void) { return bench; }
bool xiao_ota_vendor_sdk_usb_bench_enter(void);
void xiao_ota_vendor_bench_allow_stage_repair(bool allowed) { stage_repair_allowed = allowed; }
uint32_t xiao_ota_vendor_sd_is_enabled(uint8_t *out) { *out = sd_enabled; return 0; }
bool xiao_ota_vendor_start(uint32_t extent) {
  return extent >= 8 && extent <= (bench && !ble ? 0xAD000u : 0x9D000u);
}
static void bootloader_util_settings_get(const bootloader_settings_t **out) { *out = &settings; }
static bool copy_error;
static uint32_t sd_mbr_command(sd_mbr_command_t *command) {
  if (command->command == SD_MBR_COMMAND_COMPARE) {
    assert(command->params.compare.ptr1 == (void *)0xF4000 &&
           command->params.compare.ptr2 == (void *)0x27000);
    return memcmp(command->params.compare.ptr1, command->params.compare.ptr2,
                  command->params.compare.len * 4) ? NRF_ERROR_NOT_SUPPORTED : NRF_SUCCESS;
  }
  assert(command->command == SD_MBR_COMMAND_COPY_BL &&
         command->params.copy_bl.bl_src == (void *)0x27000 &&
         command->params.copy_bl.bl_len == 0xA000 / 4);
  if (copy_error) return NRF_ERROR_INTERNAL;
  memcpy((void *)0xF4000, command->params.copy_bl.bl_src, command->params.copy_bl.bl_len * 4);
  ++swaps; return 0;
}
/* The product helper and this SDK fixture's hardware-state variable share a
 * name; redirect only the extracted helper call. */
#define sd_enabled sd_enabled_query
#include "generated_usb_receipt.inc"
#include "generated_usb_policy.inc"
#undef sd_enabled
#include "generated_usb_enter.inc"

#define NRF_USBD 1
#define MAX_BUFFERS 1
#define INVALID_PACKET 255u
#define START_PACKET 3u
#define DATA_PACKET 4u
#define INIT_PACKET 1u
#define STOP_DATA_PACKET 5u
#define DATA_QUEUE_EMPTY() (!m_data_queue.count)
#define DATA_QUEUE_ELEMENT_GET_PTYPE(i) (m_data_queue.data_packet[i].packet_type)
#define STATE_WRITING_STARTED 0
#define STATE_WRITING_FINISHED 1
static struct {
  unsigned count;
  dfu_update_packet_t data_packet[MAX_BUFFERS];
} m_data_queue;
bool dfu_startup_packet_received;
static uint32_t data_queue_element_free(unsigned index) {
  m_data_queue.data_packet[index].packet_type = INVALID_PACKET;
  m_data_queue.count = 0;
  return 0;
}
static uint32_t dfu_data_pkt_handle(dfu_update_packet_t *packet) { (void)packet; return 0; }
static uint32_t dfu_init_pkt_handle(dfu_update_packet_t *packet) { (void)packet; return 0; }
static uint32_t dfu_init_pkt_complete(void) { return 0; }
static uint32_t dfu_image_activate(void) { return 0; }
static void led_state(unsigned state) { (void)state; }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "generated_usb_dispatch.inc"
#pragma GCC diagnostic pop

static bool usb_start(start_t *start) {
  m_dfu_state = DFU_STATE_IDLE;
  m_data_queue.count = 1;
  m_data_queue.data_packet[0].packet_type = START_PACKET;
  m_data_queue.data_packet[0].params.data_packet.p_data_packet = (uint32_t *)start;
  last_error = 0;
  if (setjmp(errors)) return false;
  process_dfu_packet(NULL, 0);
  return true;
}

int main(void) {
  void *image = mmap((void *)0x27000, 0xA000, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  assert(image == (void *)0x27000);
  void *installed = mmap((void *)0xF4000, 0xA000, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  assert(installed == (void *)0xF4000);
  memset(installed, 0x7B, 0xA000);
  memset(image, 255, 0xA000);
  active_storage.block_id = (uintptr_t)image;
  start_t start = {DFU_UPDATE_BL, 0, 0xA000, 0};
  dfu_update_packet_t packet = {.params.start_packet = &start};
  assert(dfu_start_pkt_handle(&packet) == NRF_ERROR_NOT_SUPPORTED && !prepares);
  bench = true;
  assert(dfu_start_pkt_handle(&packet) == 0 && prepares == 1);
  assert(stage_repair_allowed);
  m_dfu_state = DFU_STATE_RX_DATA_PKT; m_data_received = m_image_size - 4;
  assert(dfu_image_validate() == NRF_ERROR_INVALID_STATE);
  m_data_received = m_image_size;
  m_extended_packet[0] = crc16_compute(image, m_image_size, NULL) ^ 1;
  assert(dfu_image_validate() == NRF_ERROR_INVALID_DATA);
  m_dfu_state = DFU_STATE_RX_DATA_PKT; m_extended_packet[0] ^= 1;
  assert(dfu_image_validate() == NRF_SUCCESS && m_dfu_state == DFU_STATE_WAIT_4_ACTIVATE);
  assert(dfu_activate_bl() == NRF_SUCCESS && settings.bank_1 == BANK_VALID_BOOT);
  assert(settings.bank_0 == BANK_INVALID_APP && settings.bank_0_size == 0xA000 &&
         settings.bank_0_crc == m_extended_packet[0] && raw_marker(&settings) == XIAO_OTA_BENCH_PENDING);
  bootloader_settings_t snapshot;
  memset(&snapshot, 0xD3, sizeof(snapshot));
  legacy_fields_only_get(&snapshot);
  assert(raw_marker(&snapshot) == 0xD3D3);
  bootloader_settings_get(&snapshot);
  assert(raw_marker(&snapshot) == XIAO_OTA_BENCH_PENDING &&
         !memcmp(&snapshot, &settings, sizeof(settings)));
  m_dfu_state = DFU_STATE_IDLE;
  start = (start_t){DFU_UPDATE_APP, 0, 0, 0xAD000};
  assert(dfu_start_pkt_handle(&packet) == 0 && prepares == 2);
  assert(stage_repair_allowed);
  start.app_image_size = 8192;
  assert(dfu_start_pkt_handle(&packet) == 0 && prepares == 3 && !stage_repair_allowed);
  start.app_image_size = 0xAD004;
  assert(dfu_start_pkt_handle(&packet) != 0 && prepares == 3);
  start = (start_t){DFU_UPDATE_BL, 0, 0xA000, 0};
  ble = sd_enabled = true;
  assert(dfu_start_pkt_handle(&packet) == NRF_ERROR_NOT_SUPPORTED && prepares == 3);
  ble = sd_enabled = false; bench = false;
  assert(dfu_start_pkt_handle(&packet) == NRF_ERROR_NOT_SUPPORTED && prepares == 3);
  bench = true; start.sd_image_size = 4; start.dfu_update_mode = DFU_UPDATE_SD | DFU_UPDATE_BL;
  assert(dfu_start_pkt_handle(&packet) == NRF_ERROR_NOT_SUPPORTED && prepares == 3);
  settings.bank_1 = BANK_VALID_BOOT; settings.bl_image_size = 0xA000;
  set_marker(0);
  assert(dfu_bl_image_swap() == NRF_ERROR_NOT_SUPPORTED && !swaps);
  set_marker(XIAO_OTA_BENCH_PENDING);
  bench = false;
  assert(dfu_bl_image_swap() == NRF_ERROR_NOT_SUPPORTED && !swaps);
  bench = true;
  assert(xiao_ota_vendor_pending_check() == NRF_SUCCESS);
  copy_error = true;
  assert(dfu_bl_image_swap() == NRF_ERROR_INTERNAL && !swaps);
  copy_error = false;
  assert(dfu_bl_image_swap() == 0 && swaps == 1);
  bench = false;
  assert(xiao_ota_vendor_pending_check() == NRF_SUCCESS);
  assert(dfu_bl_image_swap() == NRF_SUCCESS && swaps == 1);
  memset(installed, 0x7B, 0xA000); bench = true;
  settings.bl_image_size -= 4;
  assert(dfu_bl_image_swap() == NRF_ERROR_NOT_SUPPORTED && swaps == 1);
  settings.bl_image_size = 0xA000;
  settings.bank_0 = BANK_INVALID_APP;
  settings.bank_0_size = settings.bl_image_size;
  uint8_t chunk[128]; memset(chunk, 255, sizeof(chunk));
  settings.bank_0_crc = 0xFFFF;
  for (uint32_t i = 0; i < settings.bl_image_size; i += sizeof(chunk))
    settings.bank_0_crc = crc16_compute(chunk, sizeof(chunk), &settings.bank_0_crc);
  bench = false;
  assert(xiao_ota_vendor_pending_check() == NRF_ERROR_NOT_SUPPORTED);
  bench = true;
  assert(xiao_ota_vendor_pending_check() == NRF_SUCCESS);
  settings.bank_0_crc ^= 1;
  assert(xiao_ota_vendor_pending_check() == NRF_ERROR_NOT_SUPPORTED);
  settings.bank_0_crc ^= 1;
  settings.bl_image_size -= 4;
  assert(xiao_ota_vendor_pending_check() == NRF_ERROR_NOT_SUPPORTED);
  settings.bl_image_size = 0xA000;
  settings.app_image_size = 4;
  assert(xiao_ota_vendor_pending_check() == NRF_ERROR_NOT_SUPPORTED);
  settings.app_image_size = 0;
  io_error = true;
  assert(xiao_ota_vendor_pending_check() == NRF_ERROR_INTERNAL);
  io_error = false; bad_tail = true;
  assert(xiao_ota_vendor_pending_check() == NRF_ERROR_INVALID_STATE);
  bad_tail = false; changing_settings = true;
  assert(xiao_ota_vendor_pending_check() == NRF_ERROR_INTERNAL);
  changing_settings = false; sd_enabled = true;
  assert(xiao_ota_vendor_pending_check() == NRF_ERROR_INVALID_STATE);
  bench = false; ble = sd_enabled = false;
  config.usb_bench = false; config.app_end = 0xC4000;
  mounted = true; mock_power.USBREGSTATUS = POWER_USBREGSTATUS_VBUSDETECT_Msk;
  start = (start_t){DFU_UPDATE_BL, 0, 0xA000, 0};
  const unsigned before = prepares;
  for (unsigned fault = 0; fault < 10; ++fault) {
    initialized = true; poisoned = false; ble = sd_enabled = false;
    sd_query_error = false;
    mounted = true; config.bench_prepare = bench_prepare;
    mock_power.USBREGSTATUS = POWER_USBREGSTATUS_VBUSDETECT_Msk;
    memset(&mock_acl, 0, sizeof(mock_acl));
    switch (fault) {
      case 0: mounted = false; break;
      case 1: mock_power.USBREGSTATUS = 0; break;
      case 2: mock_acl.ACL[0].SIZE = 0x10000; break;
      case 3: mock_acl.ACL[1].SIZE = 0xA000; break;
      case 4: ble = true; break;
      case 5: sd_enabled = true; break;
      case 6: initialized = false; break;
      case 7: poisoned = true; break;
      case 8: config.bench_prepare = NULL; break;
      case 9: sd_query_error = true; break;
    }
    assert(!usb_start(&start) && last_error == NRF_ERROR_INVALID_STATE);
    assert(!bench && !config.usb_bench && config.app_end == 0xC4000 && prepares == before);
  }
  initialized = true; poisoned = sd_query_error = false;
  ble = sd_enabled = true;
  config.bench_prepare = bench_prepare;
  m_dfu_state = DFU_STATE_IDLE;
  start = (start_t){DFU_UPDATE_APP, 0, 0, 8192};
  assert(dfu_start_pkt_handle(&packet) == NRF_SUCCESS && prepares == before + 1);
  assert(!bench && !config.usb_bench && config.app_end == 0xC4000 && !stage_repair_allowed);
  ble = sd_enabled = false;
  config.bench_prepare = bench_prepare;
  mounted = true; mock_power.USBREGSTATUS = POWER_USBREGSTATUS_VBUSDETECT_Msk;
  memset(&mock_acl, 0, sizeof(mock_acl));
  start = (start_t){DFU_UPDATE_BL, 0, 0xA000, 0};
  assert(usb_start(&start) && bench && config.usb_bench && config.app_end == 0xD4000);
  assert(prepares == before + 2);
  start = (start_t){DFU_UPDATE_APP, 0, 0, 0xAD000};
  assert(usb_start(&start) && prepares == before + 3);
  ble = sd_enabled = true; m_dfu_state = DFU_STATE_IDLE;
  assert(dfu_start_pkt_handle(&packet) != NRF_SUCCESS && prepares == before + 3);
  puts("Actual SDK11 USB START dispatcher + SDK admission: configured USB only; BLE/SD/ACL/init/fault deny; CRC-bound MBR copy PASS");
}
