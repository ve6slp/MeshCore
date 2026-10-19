#include "nrf.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "xiao_ota_layout.h"

NRF_QSPI_Type mock_qspi;
mock_dwt_t mock_dwt;
mock_coredebug_t mock_coredebug;
mock_nvmc_t mock_nvmc;
mock_wdt_t mock_wdt;
mock_ficr_t mock_ficr;
mock_acl_t mock_acl;
mock_power_t mock_power;
uint8_t runtime_window[68];
uint8_t __data_load__[4] = {0x4F, 0x54, 0x41, 0x32};
__asm__(".globl __data_start__\n.set __data_start__, runtime_window + 16\n"
        ".globl __data_end__\n.set __data_end__, runtime_window + 20\n"
        ".globl __bss_start__\n.set __bss_start__, runtime_window + 20\n"
        ".globl __bss_end__\n.set __bss_end__, runtime_window + 52\n");

#ifdef PAIR_VENDOR_LIFECYCLE
extern uint8_t *lifecycle_qspi_flash(void);
#else
static uint8_t *test_flash;
static uint32_t fail_address;
static unsigned fail_after, matching_operations, failed_operations;
static unsigned fail_remaining;
static uint32_t fail_phase;
static bool fail_read;
void pair_test_flash(uint8_t *flash, bool read, uint32_t address, unsigned after) {
  test_flash = flash;
  fail_read = read;
  fail_address = address;
  fail_after = after;
  matching_operations = failed_operations = 0;
  fail_remaining = 1;
  fail_phase = UINT32_MAX;
}
void pair_test_flash_failure_phase(uint32_t phase, unsigned repetitions) {
  fail_phase = phase;
  fail_remaining = repetitions;
}
unsigned pair_test_failed_operations(void) { return failed_operations; }
static bool fail_operation(bool read, uint32_t address) {
  if (read != fail_read || address != fail_address || !fail_remaining) return false;
  if (fail_phase != UINT32_MAX) {
    const xiao_ota_state_t *a = (const void *)(test_flash + XIAO_OTA_STATE_A);
    const xiao_ota_state_t *b = (const void *)(test_flash + XIAO_OTA_STATE_B);
    const xiao_ota_state_t *state = !xiao_ota_state_valid(a) ? b :
        !xiao_ota_state_valid(b) || a->sequence > b->sequence ? a : b;
    if (!xiao_ota_state_valid(state) || state->phase != fail_phase) return false;
  }
  if (++matching_operations < fail_after || !fail_after) return false;
  --fail_remaining;
  ++failed_operations;
  return true;
}
#endif
static unsigned reads;
unsigned lifecycle_qspi_reads(void) { return reads; }
void mock_qspi_poll(void) {
  if (mock_qspi.ENABLE != QSPI_ENABLE_ENABLE_Enabled) return;
#ifdef PAIR_VENDOR_LIFECYCLE
  uint8_t *flash = lifecycle_qspi_flash();
#else
  uint8_t *flash = test_flash;
  if (!flash) return;
#endif
  if (mock_qspi.TASKS_ACTIVATE) {
    mock_qspi.TASKS_ACTIVATE = 0;
#ifndef PAIR_VENDOR_LIFECYCLE
    if (fail_operation(true, UINT32_MAX)) return;
#endif
    mock_qspi.EVENTS_READY = 1;
  }
  if (mock_qspi.TASKS_READSTART) {
#ifndef PAIR_VENDOR_LIFECYCLE
    if (fail_operation(true, mock_qspi.READ.SRC)) {
      mock_qspi.TASKS_READSTART = 0;
      return;
    }
#endif
    assert(mock_qspi.READ.SRC + mock_qspi.READ.CNT <= 2u * 1024u * 1024u);
    memcpy((void *)(uintptr_t)mock_qspi.READ.DST, flash + mock_qspi.READ.SRC,
           mock_qspi.READ.CNT);
    mock_qspi.TASKS_READSTART = 0; mock_qspi.EVENTS_READY = 1; ++reads;
  }
  if (mock_qspi.TASKS_WRITESTART) {
#ifndef PAIR_VENDOR_LIFECYCLE
    if (fail_operation(false, mock_qspi.WRITE.DST)) {
      mock_qspi.TASKS_WRITESTART = 0;
      return;
    }
#endif
    assert(mock_qspi.WRITE.DST + mock_qspi.WRITE.CNT <= 2u * 1024u * 1024u);
    const uint8_t *source = (const void *)(uintptr_t)mock_qspi.WRITE.SRC;
    for (uint32_t n = 0; n < mock_qspi.WRITE.CNT; ++n)
      flash[mock_qspi.WRITE.DST + n] &= source[n];
    mock_qspi.TASKS_WRITESTART = 0; mock_qspi.EVENTS_READY = 1;
  }
  if (mock_qspi.TASKS_ERASESTART) {
    assert(mock_qspi.ERASE.PTR + 4096 <= 2u * 1024u * 1024u);
    memset(flash + mock_qspi.ERASE.PTR, 255, 4096);
    mock_qspi.TASKS_ERASESTART = 0; mock_qspi.EVENTS_READY = 1;
  }
  if (mock_qspi.CINSTRCONF) {
    uint32_t opcode = (mock_qspi.CINSTRCONF >> QSPI_CINSTRCONF_OPCODE_Pos) & 255u;
    switch (opcode) {
      case 0x9f: mock_qspi.CINSTRDAT0 = 0x156085; break;
      case 0x05: mock_qspi.CINSTRDAT0 = 0; break;
      case 0x35: mock_qspi.CINSTRDAT0 = 2; break;
      case 0x06: case 0x31: case 0xab: break;
      default: assert(!"unexpected QSPI opcode");
    }
    mock_qspi.CINSTRCONF = 0; mock_qspi.EVENTS_READY = 1;
  }
}
void mock_clock_tick(void) { mock_dwt.CYCCNT += 64000; }
void mock_nvmc_poll(void) {
#ifndef PAIR_VENDOR_LIFECYCLE
  if (test_flash && mock_nvmc.READY && mock_nvmc.ERASEPAGE) {
    memset((void *)(uintptr_t)mock_nvmc.ERASEPAGE, 255, 4096);
    mock_nvmc.ERASEPAGE = 0;
  }
#endif
}
void mock_barrier(void) {}
void mock_delay_us(uint32_t us) { (void)us; }
void nrf_qspi_disable(NRF_QSPI_Type *qspi) { qspi->ENABLE = 0; }

void reset_adapter(void) {
  memset(&mock_qspi, 0, sizeof(mock_qspi));
  memset(&mock_dwt, 0, sizeof(mock_dwt));
  memset(&mock_coredebug, 0, sizeof(mock_coredebug));
  memset(&mock_nvmc, 0, sizeof(mock_nvmc));
  memset(&mock_wdt, 0, sizeof(mock_wdt));
  memset(&mock_acl, 0, sizeof(mock_acl));
  mock_nvmc.READY = 1;
#ifdef PAIR_VENDOR_LIFECYCLE
  reads = 0;
#endif
}
