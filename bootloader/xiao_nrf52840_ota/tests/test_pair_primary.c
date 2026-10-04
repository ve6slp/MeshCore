#include "pair_abi.h"
#include "pair_expected.h"
#include "xiao_ota_boot_io.h"
#include "stage_recovery.h"
#include "nrf.h"
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

typedef struct { uint32_t CC[4]; } mock_timer_t;
typedef struct { uint32_t bank_0; } bootloader_settings_t;
static mock_timer_t timer;
static bootloader_settings_t sdk = {1};
static uint32_t retention;
uint32_t *dbl_reset_mem = &retention;
static bool single_tap, pending;
static unsigned service_calls, dfu_calls, getter_calls, app_calls, pending_calls;
static uint32_t timeout, pending_result;
static jmp_buf route;
bool _ota_dfu, _ota_connected, _sd_inited;
#define NRF_TIMER2 (&timer)
#define BOOTLOADER_VERSION_REGISTER NRF_TIMER2->CC[0]
#define MK_BOOTLOADER_VERSION 0x902u
#define DFU_MAGIC_OTA_APPJUM 0xB1u
#define DFU_MAGIC_OTA_RESET 0xA8u
#define DFU_MAGIC_SERIAL_ONLY_RESET 0x4Eu
#define DFU_MAGIC_UF2_RESET 0x57u
#define DFU_MAGIC_SKIP 0x6Du
#define DFU_DBL_RESET_MAGIC 0x5A1AD5u
#define DFU_DBL_RESET_APP 0x4ee5677eu
#define DFU_DBL_RESET_DELAY 500
#define DFU_SERIAL_STARTUP_INTERVAL 1000
#define BUTTON_DFU 0
#define BUTTON_FRESET 1
#define STATE_BOOTLOADER_STARTED 0
#define STATE_WRITING_STARTED 1
#define STATE_WRITING_FINISHED 2
#define STATE_BLE_DISCONNECTED 3
#define STATE_USB_UNMOUNTED 4
#define BANK_VALID_APP 1u
#define NRF_SUCCESS 0u
#define APP_ASKS_FOR_SINGLE_TAP_RESET() single_tap
#define PRINTF(...) ((void)0)
#define NRFX_DELAY_MS(ms) ((void)(ms))
static void check_dfu_mode(bool);
static uint32_t ble_stack_init(void) { return 0; }
static bool button_pressed(unsigned button) { (void)button; return false; }
static void board_init(void) {}
static void board_teardown(void) {}
static void bootloader_init(void) {}
static void led_state(unsigned state) { (void)state; }
static void usb_teardown(void) {}
static void usb_init(bool serial) { (void)serial; }
static bool is_ota(void) { return _ota_dfu; }
static bool is_sd_existed(void) { return true; }
static void mbr_init_sd(void) {}
static void sd_softdevice_disable(void) {}
static uint32_t xiao_ota_primary_init(void) { return 0; }
static bool bootloader_dfu_sd_in_progress(void) { return pending; }
static uint32_t bootloader_dfu_sd_update_continue(void) {
  assert(mock_acl.ACL[0].SIZE == 0 && mock_acl.ACL[1].SIZE == 0);
  ++pending_calls;
  return pending_result;
}
static uint32_t bootloader_dfu_sd_update_finalize(void) {
  ++pending_calls; pending = false; return pending_result;
}
static bool bootloader_app_is_valid(void) {
  return xiao_ota_app_is_intact(xiao_ota_boot_internal_io());
}
static void bootloader_util_settings_get(const bootloader_settings_t **out) { *out = &sdk; }
#include "primary_grant.inc"
static uint32_t bootloader_dfu_start(bool ble, uint32_t ms, bool startup) {
  (void)ble; (void)startup;
  assert(!pair_intact && "cached preupload grant reached DFU");
  ++dfu_calls; timeout = ms; return NRF_SUCCESS;
}
static bool xiao_ota_vendor_recovery_complete(void) { ++getter_calls; return false; }
static __attribute__((noreturn)) void bootloader_app_start(void) {
  ++app_calls; longjmp(route, 1);
}
__attribute__((noreturn)) void NVIC_SystemReset(void) { longjmp(route, 2); }
extern pair_result_t stage_run(const pair_request_t *);
extern void reset_adapter(void);

pair_result_t pair_call(const pair_expected_t *expected) {
  if (!pair_validate_internal(expected)) return PAIR_RECOVERY;
  ++service_calls;
  const pair_request_t request = {PAIR_ABI_VERSION, sizeof(request), expected->board, expected->role};
  return stage_run(&request);
}

#include "generated_primary.inc"

#ifdef PAIR_LEGACY_NEGATIVE
bool xiao_ota_stage2_recovery_requested(void) { return false; }
#endif

static int boot(void) {
  int value = setjmp(route);
  if (!value) { vendor_main(); assert(!"main returned"); }
  return value;
}

static void fresh_runtime(void) {
  reset_adapter();
  memset(&mock_power, 0, sizeof(mock_power));
  retention = 0;
  service_calls = dfu_calls = getter_calls = app_calls = pending_calls = 0;
  pending_result = 0;
  _ota_dfu = _ota_connected = _sd_inited = single_tap = pending = false;
}

int main(int argc, char **argv) {
  assert(argc == 2);
  void *stage = mmap((void *)PAIR_STAGE_START, 65536, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  void *settings = mmap((void *)0xFF000, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  void *app = mmap((void *)PAIR_APP_START, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  assert(stage == (void *)PAIR_STAGE_START && settings == (void *)0xFF000 &&
         app == (void *)PAIR_APP_START);
  FILE *file = fopen(argv[1], "rb");
  assert(file && fread(stage, 1, paired_stage.extent, file) == paired_stage.extent);
  fclose(file);
  memset(settings, 255, 4096);
  uint8_t before[4096]; memcpy(before, settings, 4096);
  fresh_runtime();
  assert(boot() == 2 && service_calls == 1 && dfu_calls == 1);
  assert(timeout == 0 && mock_power.GPREGRET == 0 && getter_calls == 1);
  assert(xiao_ota_stage2_recovery_requested());
  assert(!memcmp(before, settings, 4096));
  assert(!mock_nvmc.CONFIG && !mock_nvmc.ERASEPAGE && !mock_qspi.TASKS_WRITESTART &&
         !mock_qspi.TASKS_ERASESTART && !mock_wdt.TASKS_START);
  fresh_runtime(); mock_power.GPREGRET = 0x57;
  assert(boot() == 2 && !service_calls && dfu_calls == 1 && timeout == 3000);
  fresh_runtime(); ((uint8_t *)stage)[40] ^= 1;
  assert(boot() == 2 && !service_calls && dfu_calls == 1 && timeout == 0);
  ((uint8_t *)stage)[40] ^= 1;
  fresh_runtime(); pending = true; pending_result = 1;
  assert(boot() == 2 && !service_calls && dfu_calls == 1 && timeout == 0);
  fresh_runtime();
  const uint32_t vectors[2] = {0x2003E000, PAIR_APP_START + 1};
  memcpy(app, vectors, 8);
  const uint8_t valid[28] = {1,0,0,0,0xfe,0,0,0,8};
  memcpy(settings, valid, 28);
  single_tap = true;
  assert(boot() == 2 && service_calls == 1 && dfu_calls == 1 && timeout == 3000);
  assert(retention == DFU_DBL_RESET_APP && mock_power.GPREGRET == 0);
  reset_adapter();
  assert(boot() == 1 && service_calls == 2 && dfu_calls == 1 && app_calls == 1);
  assert(retention == 0);
  puts("Sense selected main + actual adapter/kernel/runtime: R1 recovery, SDK unchanged, "
       "timeout separation, pending-first/error, grant invalidation/fresh stage PASS");
}
