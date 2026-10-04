#include "nrf.h"
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

void mock_qspi_poll(void) {}
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
}
