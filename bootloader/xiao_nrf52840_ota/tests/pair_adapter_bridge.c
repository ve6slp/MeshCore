#include "nrf.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

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
static unsigned reads;
unsigned lifecycle_qspi_reads(void) { return reads; }
void mock_qspi_poll(void) {
  if (mock_qspi.ENABLE != QSPI_ENABLE_ENABLE_Enabled) return;
  uint8_t *flash = lifecycle_qspi_flash();
  if (mock_qspi.TASKS_ACTIVATE) {
    mock_qspi.TASKS_ACTIVATE = 0;
    mock_qspi.EVENTS_READY = 1;
  }
  if (mock_qspi.TASKS_READSTART) {
    assert(mock_qspi.READ.SRC + mock_qspi.READ.CNT <= 2u * 1024u * 1024u);
    memcpy((void *)(uintptr_t)mock_qspi.READ.DST, flash + mock_qspi.READ.SRC,
           mock_qspi.READ.CNT);
    mock_qspi.TASKS_READSTART = 0; mock_qspi.EVENTS_READY = 1; ++reads;
  }
  if (mock_qspi.TASKS_WRITESTART) {
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
      default: assert(!"unexpected healthy QSPI opcode");
    }
    mock_qspi.CINSTRCONF = 0; mock_qspi.EVENTS_READY = 1;
  }
}
#else
void mock_qspi_poll(void) {}
#endif
void mock_clock_tick(void) { mock_dwt.CYCCNT += 64000; }
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
