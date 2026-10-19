#include "pair_abi.h"
#include "pair_expected.h"
#include "xiao_ota_boot_io.h"
#include "xiao_ota_record.h"
#include "xiao_ota_layout.h"
#include "xiao_ota_sha256.h"
#include "tweetnacl.h"
#include "crc16.h"
#include "stage_recovery.h"
#include "pair_faults.h"
#include "nrf.h"
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>

typedef struct { uint32_t CC[4]; } mock_timer_t;
#ifdef PAIR_VENDOR_LIFECYCLE
typedef struct {
  uint16_t bank_0, bank_0_crc, bank_1, padding;
  uint32_t bank_0_size, sd_image_size, bl_image_size, app_image_size, sd_image_start;
} bootloader_settings_t;
uint32_t lifecycle_sdk_init(void);
uint32_t lifecycle_dfu_start(bool, uint32_t, bool);
uint32_t lifecycle_init_sd(void);
void lifecycle_ble_enable(void);
uint32_t bootloader_init(void);
bool bootloader_dfu_sd_in_progress(void);
uint32_t bootloader_dfu_sd_update_continue(void);
uint32_t bootloader_dfu_sd_update_finalize(void);
bool bootloader_app_is_valid(void);
void bootloader_util_settings_get(const bootloader_settings_t **);
bool xiao_ota_vendor_recovery_complete(void);
uint32_t xiao_ota_vendor_sdk_boot_entry(bool);
uint32_t xiao_ota_vendor_sdk_sd_init_result(uint32_t);
#else
typedef struct { uint32_t bank_0; } bootloader_settings_t;
static bootloader_settings_t sdk = {1};
#endif
static mock_timer_t timer;
static uint32_t retention;
uint32_t *dbl_reset_mem = &retention;
static bool single_tap, pending, dfu_button, boot_entry_active, in_stage_call;
static bool usb_mounted, usb_sdk_error, complete_boot_upload;
static unsigned service_calls, dfu_calls, getter_calls, app_calls, pending_calls;
static uint32_t timeout, pending_result;
static uint32_t retention_at_dfu;
static unsigned init_sd_calls;
static uint32_t init_sd_error;
static unsigned primary_init_calls, primary_init_failures;
static unsigned automatic_retry_budget, automatic_retries;
static unsigned retry_delays;
static bool fail_trial_app;
static bool campaign, confirm_trial, crash_trial;
static unsigned power_cuts, watchdog_resets, app_resets;
#ifdef PAIR_VENDOR_LIFECYCLE
static void campaign_app(void) {}
#else
static void campaign_app(void);
#endif
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
#define NRF_ERROR_INTERNAL 4u
#define SD_MBR_COMMAND_INIT_SD 2u
#define APP_ERROR_CHECK(error) do { if ((error) != NRF_SUCCESS) longjmp(route, 3); } while (0)
#define APP_ASKS_FOR_SINGLE_TAP_RESET() single_tap
#define PRINTF(...) ((void)0)
#define NRFX_DELAY_MS(ms) do { if ((ms) == 1000u) ++retry_delays; } while (0)
static void check_dfu_mode(bool);
static uint32_t ble_stack_init(void) {
  assert(_sd_inited);
#ifdef PAIR_VENDOR_LIFECYCLE
  lifecycle_ble_enable();
#endif
  return 0;
}
static bool button_pressed(unsigned button) { return button == BUTTON_DFU && dfu_button; }
static void board_init(void) {}
static void board_teardown(void) {}
#ifndef PAIR_VENDOR_LIFECYCLE
static void bootloader_init(void) {}
#endif
static void led_state(unsigned state) { (void)state; }
static void usb_teardown(void) {}
static void usb_init(bool serial) {
  (void)serial;
  usb_mounted = (mock_power.USBREGSTATUS & POWER_USBREGSTATUS_VBUSDETECT_Msk) != 0;
}
static bool tud_mounted(void) { return usb_mounted; }
static bool is_ota(void) { return _ota_dfu; }
static bool is_sd_existed(void) { return true; }
typedef struct { uint32_t command; } sd_mbr_command_t;
static uint32_t sd_mbr_command(sd_mbr_command_t *command) {
  assert(command->command == SD_MBR_COMMAND_INIT_SD && !_sd_inited);
  ++init_sd_calls;
#ifdef PAIR_VENDOR_LIFECYCLE
  return lifecycle_init_sd();
#else
  return init_sd_error;
#endif
}
#ifndef PAIR_VENDOR_LIFECYCLE
static uint32_t xiao_ota_vendor_sdk_boot_entry(bool routed) {
  _sd_inited = routed;
  return NRF_SUCCESS;
}
static uint32_t xiao_ota_vendor_sdk_sd_init_result(uint32_t error) { return error; }
#endif
static void sd_softdevice_disable(void) {}
#ifdef PAIR_VENDOR_LIFECYCLE
static uint32_t xiao_ota_primary_init(void) { return lifecycle_sdk_init(); }
#else
static uint32_t xiao_ota_primary_init(void) {
  ++primary_init_calls;
  if (primary_init_failures) {
    --primary_init_failures;
    return NRF_ERROR_INTERNAL;
  }
  return NRF_SUCCESS;
}
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
#endif
static bool xiao_ota_vendor_sdk_usb_bench_enter(void) {
  return !_ota_dfu && !usb_sdk_error;
}
static uint32_t xiao_ota_vendor_pending_check(void) { return pending_result; }
#include "primary_grant.inc"
static uint32_t bootloader_dfu_start(bool ble, uint32_t ms, bool startup) {
  (void)ble; (void)startup;
  assert(!pair_intact && "cached preupload grant reached DFU");
  if (boot_entry_active && ble) {
    assert(mock_acl.ACL[0].ADDR == PAIR_STAGE_START &&
           mock_acl.ACL[0].SIZE == PAIR_STAGE_END - PAIR_STAGE_START &&
           mock_acl.ACL[0].PERM == ACL_ACL_PERM_WRITE_Msk);
    assert(mock_acl.ACL[1].ADDR == 0xF4000 && mock_acl.ACL[1].SIZE == 0xA000 &&
           mock_acl.ACL[1].PERM == ACL_ACL_PERM_WRITE_Msk);
  }
  if (boot_entry_active && !ble) {
    assert(!xiao_ota_vendor_usb_bench_mode() &&
           !mock_acl.ACL[0].SIZE && !mock_acl.ACL[1].SIZE);
  }
  if (complete_boot_upload) {
    assert(xiao_ota_vendor_usb_bench_enter());
    pending = true;
  }
  ++dfu_calls; timeout = ms;
  retention_at_dfu = retention;
#ifdef PAIR_VENDOR_LIFECYCLE
  return lifecycle_dfu_start(ble, ms, startup);
#else
  return NRF_SUCCESS;
#endif
}
#ifndef PAIR_VENDOR_LIFECYCLE
static bool xiao_ota_vendor_recovery_complete(void) { ++getter_calls; return false; }
#endif
static __attribute__((noreturn)) void bootloader_app_start(void) {
  ++app_calls;
  if (campaign) campaign_app();
  if (fail_trial_app && mock_wdt.TASKS_START) NVIC_SystemReset();
  longjmp(route, 1);
}
__attribute__((noreturn)) void NVIC_SystemReset(void) { longjmp(route, 2); }
void pair_fault_power_cut(void) { longjmp(route, 4); }
extern pair_result_t stage_run(const pair_request_t *);
extern void reset_adapter(void);

pair_result_t pair_call(const pair_expected_t *expected) {
  assert(mock_acl.ACL[0].ADDR == PAIR_STAGE_START &&
         mock_acl.ACL[0].SIZE == PAIR_STAGE_END - PAIR_STAGE_START &&
         mock_acl.ACL[1].ADDR == 0xF4000 && mock_acl.ACL[1].SIZE == 0xA000);
  if (!pair_validate_internal(expected)) return PAIR_RECOVERY;
  ++service_calls;
  const pair_request_t request = {PAIR_ABI_VERSION, sizeof(request), expected->board, expected->role};
  in_stage_call = true;
  pair_result_t result = stage_run(&request);
  in_stage_call = false;
  return result;
}

#include "generated_primary.inc"

#ifdef PAIR_LEGACY_NEGATIVE
bool xiao_ota_stage2_recovery_requested(void) { return false; }
#endif

static int boot(void) {
  volatile unsigned resets = 0;
  for (;;) {
    int value = setjmp(route);
    if (!value) { boot_entry_active = true; vendor_main(); assert(!"main returned"); }
    if (value == 4 || value == 5) {
      assert(campaign && automatic_retries < automatic_retry_budget && !dfu_calls);
      if (value == 4) ++power_cuts;
      else ++watchdog_resets;
      ++automatic_retries;
      retention = 0;
      mock_power.GPREGRET = 0;
      in_stage_call = false;
    } else if (value == 2 && !in_stage_call && !dfu_calls &&
        (mock_power.GPREGRET == DFU_MAGIC_UF2_RESET ||
         (mock_power.GPREGRET == 0 && automatic_retries < automatic_retry_budget))) {
      if (mock_power.GPREGRET == DFU_MAGIC_UF2_RESET) {
        assert(resets++ == 0);
        assert(mock_acl.ACL[0].SIZE && mock_acl.ACL[1].SIZE);
      } else {
        ++automatic_retries;
      }
    } else {
      boot_entry_active = false;
      return value;
    }
    reset_adapter();
    mock_power.RESETREAS = value == 5 ? POWER_RESETREAS_DOG_Msk : value == 4 ? 0 : 4;
    usb_bench = bench_stage_repair = false;
    _ota_dfu = _sd_inited = false;
  }
}

static void fresh_runtime(void) {
  reset_adapter();
  memset(&mock_power, 0, sizeof(mock_power));
  retention = 0;
  service_calls = dfu_calls = getter_calls = app_calls = pending_calls = 0;
  pending_result = 0;
  init_sd_calls = 0; init_sd_error = 0;
  primary_init_calls = primary_init_failures = 0;
  automatic_retry_budget = automatic_retries = 0;
  retry_delays = 0;
  fail_trial_app = false;
  campaign = confirm_trial = crash_trial = false;
  power_cuts = watchdog_resets = app_resets = 0;
  _ota_dfu = _ota_connected = _sd_inited = single_tap = pending = dfu_button = false;
  usb_bench = bench_stage_repair = usb_mounted = usb_sdk_error = false;
  complete_boot_upload = in_stage_call = false;
}

static int boot_result;
static void low_stack_boot(void) { boot_result = boot(); }
static int mapped_boot(void) {
  void *stack = mmap((void *)0x20030000, 65536, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  assert(stack == (void *)0x20030000);
  ucontext_t caller, entry;
  assert(getcontext(&entry) == 0);
  entry.uc_stack.ss_sp = stack; entry.uc_stack.ss_size = 65536;
  entry.uc_link = &caller;
  makecontext(&entry, low_stack_boot, 0);
  assert(swapcontext(&caller, &entry) == 0);
  return boot_result;
}
#ifdef PAIR_VENDOR_LIFECYCLE
int lifecycle_boot(uint32_t marker) {
  fresh_runtime();
  mock_power.GPREGRET = marker;
  return mapped_boot();
}
unsigned lifecycle_init_calls(void) { return init_sd_calls; }
uint32_t lifecycle_timeout(void) { return timeout; }
void lifecycle_initialize_sd(void) { mbr_init_sd(); }
#else
void pair_test_flash(uint8_t *, bool, uint32_t, unsigned);
void pair_test_flash_failure_phase(uint32_t, unsigned);
unsigned pair_test_failed_operations(void);
void randombytes(unsigned char *bytes, unsigned long long size) {
  static uint32_t value = 1;
  while (size--) {
    value = value * 1664525u + 1013904223u;
    *bytes++ = value >> 24;
  }
}

static void provision_transaction(void *app, void *settings, uint8_t *flash,
                                  const void *original, const void *candidate,
                                  uint32_t size) {
  memset(flash, 255, 2u * 1024u * 1024u);
  memset(settings, 255, 4096);
  memcpy(app, original, size);
  const uint16_t crc = crc16_compute(app, size, NULL);
  uint8_t raw[28] = {1, 0, 0, 0, 0xFE};
  memcpy(raw + 2, &crc, sizeof(crc));
  memcpy(raw + 8, &size, sizeof(size));
  memcpy(settings, raw, sizeof(raw));

  xiao_ota_sha256_t sha;
  uint8_t hash[32], candidate_hash[32];
  xiao_ota_sha256_init(&sha);
  xiao_ota_sha256_update(&sha, app, size);
  xiao_ota_sha256_final(&sha, hash);
  memcpy(flash + XIAO_OTA_CANDIDATE_BASE, candidate, size);
  xiao_ota_sha256_init(&sha);
  xiao_ota_sha256_update(&sha, candidate, size);
  xiao_ota_sha256_final(&sha, candidate_hash);

  xiao_ota_floor_t floor = {0};
  floor.magic = XIAO_OTA_FLOOR_MAGIC;
  floor.record_version = XIAO_OTA_FORMAT_VERSION;
  floor.record_bytes = sizeof(floor);
  floor.sequence = 1;
  floor.confirmed_counter_floor = 7;
  floor.active_image_extent = size;
  memcpy(floor.confirmed_hash_sha256, hash, sizeof(hash));
  floor.crc32 = xiao_ota_crc32(&floor, offsetof(xiao_ota_floor_t, crc32));
  floor.commit_marker = XIAO_OTA_COMMIT_MARKER;
  memcpy(flash + XIAO_OTA_FLOOR_A, &floor, sizeof(floor));

  xiao_ota_wire_descriptor_t descriptor = {0};
  descriptor.board_family = XIAO_OTA_BOARD_TARGET >> 16;
  descriptor.board_variant = XIAO_OTA_BOARD_TARGET & 0xFFFFu;
  descriptor.role = XIAO_OTA_COMPILED_ROLE_ID;
  descriptor.app_address = XIAO_OTA_APP_START;
  descriptor.exact_size_bytes = size;
  memcpy(descriptor.sha256, candidate_hash, sizeof(candidate_hash));
  descriptor.security_counter = 8;
  descriptor.min_boot_capabilities = XIAO_OTA_CAP_QSPI_INSTALL;
  descriptor.format_id = XIAO_OTA_DESCRIPTOR_FORMAT;
  descriptor.key_id = XIAO_OTA_KEY_ID;
  descriptor.algorithm_id = XIAO_OTA_ALGORITHM_ED25519;
  xiao_ota_command_v2_t command = {0};
  command.magic = XIAO_OTA_RECORD_MAGIC;
  command.record_version = XIAO_OTA_COMMAND_VERSION_CURRENT;
  command.record_bytes = sizeof(command);
  command.sequence = 1;
  command.transaction_nonce = 123;
  xiao_ota_wire_descriptor_encode(&descriptor, command.wire_descriptor);
  uint8_t secret[64], signed_message[64 + XIAO_OTA_WIRE_DESCRIPTOR_SIZE];
  unsigned long long signed_size;
  crypto_sign_keypair(command.admitted_signer_public_key_ed25519, secret);
  crypto_sign(signed_message, &signed_size, command.wire_descriptor,
              sizeof(command.wire_descriptor), secret);
  assert(signed_size == sizeof(signed_message));
  memcpy(command.signature_ed25519, signed_message, 64);
  command.active_image_extent = size;
  memcpy(command.active_image_hash_sha256, hash, sizeof(hash));
  command.crc32 = xiao_ota_crc32(&command, offsetof(xiao_ota_command_v2_t, crc32));
  command.commit_marker = XIAO_OTA_COMMIT_MARKER;
  memcpy(flash + XIAO_OTA_COMMAND_A, &command, sizeof(command));
}

static void transaction_failure_recovers_without_dfu(void *app, void *settings,
                                                     bool install_read, bool failed_trial) {
  static uint8_t flash[2u * 1024u * 1024u];
  const uint32_t vectors[4] = {0x2003E000, PAIR_APP_START + 1, 0x11223344, 0x55667788};
  uint32_t candidate[4];
  memcpy(candidate, vectors, sizeof(candidate));
  candidate[2] ^= 0xA55AA55A;
  provision_transaction(app, settings, flash, vectors, candidate, sizeof(vectors));
  xiao_ota_floor_t floor;
  memcpy(&floor, flash + XIAO_OTA_FLOOR_A, sizeof(floor));
  fresh_runtime();
  pair_test_flash(flash, install_read,
                  install_read ? XIAO_OTA_CANDIDATE_BASE : XIAO_OTA_BACKUP_BASE,
                  install_read ? 3 : 1);
  fail_trial_app = failed_trial;
  automatic_retry_budget = 1 + (failed_trial ? XIAO_OTA_MAX_TRIAL_BOOTS : 0);
  assert(mapped_boot() == 1);
  assert(pair_test_failed_operations() == 1 && automatic_retries == automatic_retry_budget);
  assert(service_calls == 1 + automatic_retries && !dfu_calls);
  assert(app_calls == 1 + (failed_trial ? XIAO_OTA_MAX_TRIAL_BOOTS : 0));
  assert(!mock_power.GPREGRET && retry_delays == 1);
  assert((bool)mock_wdt.TASKS_START == (!install_read && !failed_trial));
  const xiao_ota_state_t *a = (const void *)(flash + XIAO_OTA_STATE_A);
  const xiao_ota_state_t *b = (const void *)(flash + XIAO_OTA_STATE_B);
  assert(xiao_ota_state_valid(a) && xiao_ota_state_valid(b));
  const xiao_ota_state_t *state = a->sequence > b->sequence ? a : b;
  const bool rolled_back = install_read || failed_trial;
  assert(state->phase == (rolled_back ? XIAO_OTA_PHASE_FAILED : XIAO_OTA_PHASE_TRIAL_BOOT));
  assert(state->transaction_nonce == 123);
  assert(!memcmp(app, rolled_back ? vectors : candidate, sizeof(vectors)));
  assert(!memcmp(flash + XIAO_OTA_FLOOR_A, &floor, sizeof(floor)));
  pair_test_flash(NULL, false, 0, 0);
}

#define CAMPAIGN_IMAGE_SIZE (8192u + 16u)
static uint8_t campaign_flash[2u * 1024u * 1024u], fixture_flash[sizeof(campaign_flash)];
static uint8_t original_image[CAMPAIGN_IMAGE_SIZE], candidate_image[CAMPAIGN_IMAGE_SIZE];
static uint8_t original_settings[4096], protected_stage[65536];
static unsigned rollback_read_failures, trial_startup_failures;

static bool campaign_state_visible(const xiao_ota_state_t *state) {
  return xiao_ota_state_valid(state) ||
      (xiao_ota_state_body_valid(state) &&
       (state->phase == XIAO_OTA_PHASE_FAILED || state->phase == XIAO_OTA_PHASE_CONFIRMED));
}

static const xiao_ota_state_t *campaign_state(void) {
  const xiao_ota_state_t *a = (const void *)(campaign_flash + XIAO_OTA_STATE_A);
  const xiao_ota_state_t *b = (const void *)(campaign_flash + XIAO_OTA_STATE_B);
  if (!campaign_state_visible(a)) return campaign_state_visible(b) ? b : NULL;
  if (!campaign_state_visible(b)) return a;
  return a->sequence > b->sequence ? a : b;
}

static void campaign_app(void) {
  const xiao_ota_state_t *state = campaign_state();
  if (!state || state->phase != XIAO_OTA_PHASE_TRIAL_BOOT) return;
  assert(mock_wdt.TASKS_START && mock_wdt.CRV == 60u * 32768u &&
         mock_wdt.RREN == WDT_RREN_RR0_Msk);
  if (confirm_trial) {
    xiao_ota_confirmation_t confirmation = {0};
    confirmation.magic = XIAO_OTA_CONFIRM_MAGIC;
    confirmation.record_version = XIAO_OTA_FORMAT_VERSION;
    confirmation.record_bytes = sizeof(confirmation);
    confirmation.sequence = 1;
    confirmation.transaction_nonce = state->transaction_nonce;
    confirmation.confirmed_counter = state->candidate_counter;
    memcpy(confirmation.confirmed_hash_sha256, state->installed_hash_sha256, 32);
    confirmation.crc32 = xiao_ota_crc32(&confirmation, offsetof(xiao_ota_confirmation_t, crc32));
    confirmation.commit_marker = XIAO_OTA_COMMIT_MARKER;
    memcpy(campaign_flash + XIAO_OTA_CONFIRM_A, &confirmation, sizeof(confirmation));
    ++app_resets;
    NVIC_SystemReset();
  }
  if (crash_trial) {
    ++app_resets;
    NVIC_SystemReset();
  }
  /* The model advances to the unserviced watchdog's configured expiry.
   * It never supplies a reset to an installer that merely returned an error. */
  longjmp(route, 5);
}

static void assert_pattern(const uint8_t *bytes, size_t length, uint8_t value) {
  for (size_t i = 0; i < length; ++i) assert(bytes[i] == value);
}

static void campaign_run(void *app, void *settings, bool confirm, bool crash,
                         unsigned target, pair_fault_effect_t effect,
                         size_t prefix, unsigned repetitions) {
  memset(app, 255, XIAO_OTA_INSTALL_MAX_SIZE);
  memcpy(app, original_image, sizeof(original_image));
  memcpy(settings, original_settings, sizeof(original_settings));
  memcpy(campaign_flash, fixture_flash, sizeof(campaign_flash));
  fresh_runtime();
  campaign = true;
  confirm_trial = confirm;
  crash_trial = crash;
  automatic_retry_budget = 32;
  pair_test_flash(campaign_flash, false, 0, 0);
  if (rollback_read_failures) {
    pair_test_flash(campaign_flash, true, XIAO_OTA_BACKUP_BASE, 1);
    pair_test_flash_failure_phase(XIAO_OTA_PHASE_ROLLBACK_COPYING, rollback_read_failures);
  }
  if (trial_startup_failures) {
    pair_test_flash(campaign_flash, true, UINT32_MAX, 1);
    pair_test_flash_failure_phase(XIAO_OTA_PHASE_TRIAL_BOOT, trial_startup_failures);
  }
  pair_fault_begin(campaign_flash, target, effect, prefix, repetitions);
  int result = mapped_boot();
  if (result != 1 || dfu_calls || (effect != PAIR_FAULT_NONE && !pair_fault_hits())) {
    fprintf(stderr, "campaign confirm=%u crash=%u target=%u effect=%u prefix=%zu repeat=%u "
            "result=%d hits=%u retries=%u dfu=%u\n", confirm, crash, target, effect,
            prefix, repetitions, result, pair_fault_hits(), automatic_retries, dfu_calls);
    abort();
  }
  const xiao_ota_state_t *state = campaign_state();
  const bool installed = !memcmp(app, candidate_image, sizeof(candidate_image));
  assert(installed || !memcmp(app, original_image, sizeof(original_image)));
  assert(bootloader_app_is_valid() && !mock_power.GPREGRET && !mock_power.USBREGSTATUS);
  if (installed) {
    assert(confirm && state && state->phase == XIAO_OTA_PHASE_CONFIRMED);
  } else if (state) {
    assert(state->phase == XIAO_OTA_PHASE_FAILED);
  }
  if (state) assert(state->transaction_nonce == 123);
  const xiao_ota_floor_t *a = (const void *)(campaign_flash + XIAO_OTA_FLOOR_A);
  const xiao_ota_floor_t *b = (const void *)(campaign_flash + XIAO_OTA_FLOOR_B);
  assert(xiao_ota_floor_valid(a) || xiao_ota_floor_valid(b));
  const xiao_ota_floor_t *floor = !xiao_ota_floor_valid(a) ? b :
      !xiao_ota_floor_valid(b) || a->sequence > b->sequence ? a : b;
  const xiao_ota_floor_t *original_floor = (const void *)(fixture_flash + XIAO_OTA_FLOOR_A);
  assert(floor->confirmed_counter_floor ==
         (installed ? 8u : original_floor->confirmed_counter_floor));
  assert(floor->active_image_extent ==
         (installed ? CAMPAIGN_IMAGE_SIZE : original_floor->active_image_extent) &&
         !memcmp(floor->confirmed_hash_sha256, installed ? state->candidate_hash_sha256
                    : original_floor->confirmed_hash_sha256, 32));
  assert(!memcmp(campaign_flash + XIAO_OTA_FLOOR_A,
                 fixture_flash + XIAO_OTA_FLOOR_A, sizeof(*floor)));
  if (!installed) assert(!memcmp(settings, original_settings, sizeof(original_settings)));
  else {
    assert(!memcmp((uint8_t *)settings + 4, original_settings + 4, 4096 - 4));
  }
  assert(!memcmp(campaign_flash, fixture_flash, XIAO_OTA_CANDIDATE_SIZE));
  assert(!memcmp(campaign_flash + XIAO_OTA_BACKUP_BASE + XIAO_OTA_INSTALL_MAX_SIZE,
                 fixture_flash + XIAO_OTA_BACKUP_BASE + XIAO_OTA_INSTALL_MAX_SIZE,
                 XIAO_OTA_BACKUP_SIZE - XIAO_OTA_INSTALL_MAX_SIZE));
  assert(!memcmp(campaign_flash + XIAO_OTA_FILESYSTEM_BASE,
                 fixture_flash + XIAO_OTA_FILESYSTEM_BASE, XIAO_OTA_FILESYSTEM_SIZE));
  assert(!memcmp((void *)PAIR_STAGE_START, protected_stage, sizeof(protected_stage)));
  assert_pattern((const void *)0xD4000, 0x19000, 0xA6);
  assert_pattern((const void *)0xF4000, 0xA000, 0xA6);
  assert(mock_ficr.DEVICEID[0] == 0x76543210 && mock_ficr.DEVICEID[1] == 0xFEDCBA98);
  if (rollback_read_failures)
    assert(pair_test_failed_operations() == rollback_read_failures);
  if (trial_startup_failures) {
    assert(pair_test_failed_operations() == trial_startup_failures);
    assert(watchdog_resets == XIAO_OTA_MAX_TRIAL_BOOTS + trial_startup_failures);
  }
  pair_fault_end();
  pair_test_flash(NULL, false, 0, 0);
}

static void unattended_fault_campaign(void *app, void *settings) {
  for (unsigned i = 0; i < sizeof(original_image); ++i) {
    original_image[i] = (uint8_t)(i * 17u + 5u);
    candidate_image[i] = (uint8_t)(i * 29u + 11u);
  }
  const uint32_t vectors[] = {0x2003E000, PAIR_APP_START + 1};
  memcpy(original_image, vectors, sizeof(vectors));
  memcpy(candidate_image, vectors, sizeof(vectors));
  provision_transaction(app, settings, fixture_flash, original_image,
                         candidate_image, sizeof(original_image));
  memcpy(original_settings, settings, sizeof(original_settings));
  memset(fixture_flash + XIAO_OTA_CANDIDATE_BASE + XIAO_OTA_INSTALL_MAX_SIZE, 0x59,
         XIAO_OTA_CANDIDATE_SIZE - XIAO_OTA_INSTALL_MAX_SIZE);
  memset(fixture_flash + XIAO_OTA_BACKUP_BASE + XIAO_OTA_INSTALL_MAX_SIZE, 0x6B,
         XIAO_OTA_BACKUP_SIZE - XIAO_OTA_INSTALL_MAX_SIZE);
  memset(fixture_flash + XIAO_OTA_FILESYSTEM_BASE, 0x7D, XIAO_OTA_FILESYSTEM_SIZE);
  memcpy(protected_stage, (void *)PAIR_STAGE_START, sizeof(protected_stage));
  memset((void *)0xD4000, 0xA6, 0x19000);
  memset((void *)0xF4000, 0xA6, 0xA000);
  mock_ficr.DEVICEID[0] = 0x76543210;
  mock_ficr.DEVICEID[1] = 0xFEDCBA98;
  unsigned cases = 0, operations = 0;
  uint16_t stored_crc;
  memcpy(&stored_crc, original_settings + 2, sizeof(stored_crc));
  for (unsigned genesis = 0; genesis < 2; ++genesis) {
    if (genesis) {
      xiao_ota_floor_t *floor = (void *)(fixture_flash + XIAO_OTA_FLOOR_A);
      floor->confirmed_counter_floor = floor->active_image_extent = 0;
      memset(floor->confirmed_hash_sha256, 0, 32);
      floor->crc32 = xiao_ota_crc32(floor, offsetof(xiao_ota_floor_t, crc32));
    }
    for (unsigned unused_crc = 0; unused_crc < 2; ++unused_crc) {
      memcpy(original_settings + 2, &stored_crc, sizeof(stored_crc));
      if (unused_crc) original_settings[2] = original_settings[3] = 0;
      for (unsigned confirm = 0; confirm < 2; ++confirm) {
        campaign_run(app, settings, confirm, false, 0, PAIR_FAULT_NONE, 0, 0);
        assert(confirm ? app_resets == 1 : watchdog_resets == XIAO_OTA_MAX_TRIAL_BOOTS);
        pair_fault_event_t baseline[1024];
        unsigned count = pair_fault_count();
        assert(count && count <= sizeof(baseline) / sizeof(baseline[0]));
        for (unsigned i = 0; i < count; ++i) baseline[i] = pair_fault_event(i);
        operations += count;
        for (unsigned i = 0; i < count; ++i) {
          for (unsigned mode = PAIR_FAULT_ERROR; mode <= PAIR_FAULT_CUT_AFTER; ++mode) {
            bool partial = mode == PAIR_FAULT_PARTIAL_ERROR || mode == PAIR_FAULT_CUT_PARTIAL;
            size_t prefixes[] = {1, baseline[i].length / 2, baseline[i].length - 1, SIZE_MAX};
            for (unsigned p = 0; p < (partial ? 4u : 1u); ++p) {
              campaign_run(app, settings, confirm, false, i, mode, prefixes[p], 1);
              assert(pair_fault_hits() == 1);
              ++cases;
            }
          }
          campaign_run(app, settings, confirm, false, i, PAIR_FAULT_ERROR, 0, 3);
          ++cases;
        }
      }
    }
  }
  campaign_run(app, settings, false, true, 0, PAIR_FAULT_NONE, 0, 0);
  assert(app_resets == XIAO_OTA_MAX_TRIAL_BOOTS && !watchdog_resets);
  rollback_read_failures = 3;
  campaign_run(app, settings, false, false, 0, PAIR_FAULT_NONE, 0, 0);
  rollback_read_failures = 0;
  trial_startup_failures = 3;
  campaign_run(app, settings, false, false, 0, PAIR_FAULT_NONE, 0, 0);
  trial_startup_failures = 0;
  printf("Automatic-reset fault campaign: %u cases at %u install/rollback/confirmation "
         "mutations; first/later OTA, stored/unused SDK CRC, partial writes/erases, repeated errors, "
         "power cuts, trial crash/hang PASS\n",
         cases, operations);
}

int main(int argc, char **argv) {
  assert(argc == 2);
  void *stage = mmap((void *)PAIR_STAGE_START, 65536, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  void *settings = mmap((void *)0xFF000, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  void *app = mmap((void *)PAIR_APP_START, XIAO_OTA_INSTALL_MAX_SIZE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  void *guards = mmap((void *)0xD4000, 0x2A000, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  assert(stage == (void *)PAIR_STAGE_START && settings == (void *)0xFF000 &&
         app == (void *)PAIR_APP_START && guards == (void *)0xD4000);
  FILE *file = fopen(argv[1], "rb");
  assert(file && fread(stage, 1, paired_stage.extent, file) == paired_stage.extent);
  fclose(file);
  memset(settings, 255, 4096);
  uint8_t before[4096]; memcpy(before, settings, 4096);
  fresh_runtime();
  assert(boot() == 2 && service_calls == 1 && dfu_calls == 0);
  assert(mock_power.GPREGRET == 0 && getter_calls == 0 && retention == 0);
  assert(xiao_ota_stage2_recovery_requested());
  assert(!memcmp(before, settings, 4096));
  assert(!mock_nvmc.CONFIG && !mock_nvmc.ERASEPAGE && !mock_qspi.TASKS_WRITESTART &&
         !mock_qspi.TASKS_ERASESTART && !mock_wdt.TASKS_START);
  fresh_runtime(); mock_power.GPREGRET = 0x57;
  assert(boot() == 2 && !service_calls && dfu_calls == 1 && timeout == 0);
  const uint32_t escapes[] = {0xB1, 0xA8, 0x4E, 0x57};
  for (unsigned i = 0; i < sizeof(escapes) / sizeof(escapes[0]); ++i) {
    fresh_runtime(); mock_power.GPREGRET = escapes[i];
    assert(boot() == 2 && !service_calls && dfu_calls == 1);
  }
  fresh_runtime();
  mock_power.RESETREAS = POWER_RESETREAS_RESETPIN_Msk;
  retention = DFU_DBL_RESET_MAGIC;
  assert(boot() == 2 && !service_calls && dfu_calls == 1);
  fresh_runtime(); dfu_button = true;
  assert(boot() == 2 && !service_calls && dfu_calls == 1);
  fresh_runtime(); ((uint8_t *)stage)[40] ^= 1;
  mock_power.RESETREAS = POWER_RESETREAS_RESETPIN_Msk;
  assert(boot() == 2 && !xiao_ota_vendor_usb_bench_mode());
  assert(retention == 0 && !dfu_calls && mock_acl.ACL[0].SIZE);
  fresh_runtime(); mock_power.RESETREAS = POWER_RESETREAS_RESETPIN_Msk;
  retention = DFU_DBL_RESET_MAGIC;
  assert(boot() == 2 && !xiao_ota_vendor_usb_bench_mode() && !mock_acl.ACL[0].SIZE);
  assert(timeout == 0 && !_ota_dfu);
  ((uint8_t *)stage)[40] ^= 1;
  fresh_runtime();
  mock_power.RESETREAS = POWER_RESETREAS_RESETPIN_Msk | 4u; /* Not a pure physical pin reset. */
  retention = DFU_DBL_RESET_MAGIC;
  assert(boot() == 2 && !xiao_ota_vendor_usb_bench_mode());
  for (unsigned marker = 0; marker < 2; ++marker) {
    fresh_runtime();
    mock_power.RESETREAS = POWER_RESETREAS_RESETPIN_Msk | 4u;
    mock_power.USBREGSTATUS = POWER_USBREGSTATUS_VBUSDETECT_Msk;
    retention = marker ? DFU_DBL_RESET_MAGIC : 0;
    assert(boot() == 2 && !service_calls && !_ota_dfu && timeout == 0);
    assert(!xiao_ota_vendor_usb_bench_mode() && !mock_acl.ACL[0].SIZE);
    assert(xiao_ota_vendor_usb_bench_enter());
    assert(xiao_ota_vendor_usb_bench_mode());
  }
  fresh_runtime(); mock_power.GPREGRET = DFU_MAGIC_SERIAL_ONLY_RESET;
  mock_power.USBREGSTATUS = POWER_USBREGSTATUS_VBUSDETECT_Msk;
  complete_boot_upload = true;
  assert(boot() == 2 && pending_calls == 2 && xiao_ota_vendor_usb_bench_mode());
  puts("USB single reset ignores RAM token; USB recovery is not admission; BLE locks and post-upload BOOT copy route PASS");
  fresh_runtime(); ((uint8_t *)stage)[40] ^= 1;
  assert(boot() == 2 && !service_calls && dfu_calls == 0 && mock_power.GPREGRET == 0);
  ((uint8_t *)stage)[40] ^= 1;
  fresh_runtime(); pending = true; pending_result = 1;
  assert(boot() == 2 && !service_calls && dfu_calls == 0 && mock_power.GPREGRET == 0);
  fresh_runtime();
  const uint32_t vectors[2] = {0x2003E000, PAIR_APP_START + 1};
  memcpy(app, vectors, 8);
  const uint8_t valid[28] = {1,0,0,0,0xfe,0,0,0,8};
  memcpy(settings, valid, 28);
  primary_init_failures = 1;
  automatic_retry_budget = 1;
  assert(boot() == 1 && primary_init_calls == 2 && automatic_retries == 1);
  assert(service_calls == 1 && app_calls == 1 && dfu_calls == 0);
  assert(mock_power.GPREGRET == 0 && !retention && retry_delays == 1);
  fresh_runtime();
  primary_init_failures = 3;
  automatic_retry_budget = 2;
  assert(boot() == 2 && primary_init_calls == 3 && automatic_retries == 2);
  assert(!service_calls && !app_calls && !dfu_calls && mock_power.GPREGRET == 0);
  assert(retry_delays == 3);
  fresh_runtime();
  single_tap = true;
  assert(boot() == 2 && service_calls == 1 && dfu_calls == 1 && timeout == 3000);
  assert(retention == DFU_DBL_RESET_APP && mock_power.GPREGRET == 0);
  reset_adapter();
  assert(boot() == 1 && service_calls == 2 && dfu_calls == 1 && app_calls == 1);
  assert(retention == 0);
  fresh_runtime();
  mbr_init_sd();
  assert(_sd_inited && init_sd_calls == 1);
  check_dfu_mode(true);
  assert(_sd_inited && init_sd_calls == 1);
  fresh_runtime(); mock_power.GPREGRET = DFU_MAGIC_OTA_APPJUM;
  assert(boot() == 2 && _sd_inited && !init_sd_calls);
  fresh_runtime(); init_sd_error = 1;
  if (!setjmp(route)) { mbr_init_sd(); assert(!"failed INIT_SD returned"); }
  assert(!_sd_inited && init_sd_calls == 1);
  transaction_failure_recovers_without_dfu(app, settings, false, false);
  transaction_failure_recovers_without_dfu(app, settings, true, false);
  transaction_failure_recovers_without_dfu(app, settings, false, true);
  unattended_fault_campaign(app, settings);
  puts("Sense selected main + actual adapter/kernel/runtime: R1 recovery, SDK unchanged, "
       "timeout separation, pending-first/error, grant invalidation/fresh stage PASS");
  puts("Field failure retries automatically without latching DFU; transient failure returns to APP PASS");
  puts("Signed backup/install I/O failures and failed trial -> automatic resume/rollback, no DFU PASS");
}
#endif
