#include "xiao_ota_boot.h"
#include "xiao_ota_boot_io.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "nrf.h"
#include "xiao_ota_layout.h"
#include "xiao_ota_record.h"

/*
 * Real nRF52840 QSPI/NVMC/WDT/FICR/GPREGRET register access. Thin,
 * unchanged register-level adapters implementing the xiao_ota_io_t
 * contract (xiao_ota_boot_io.h) -- all actual OTA transaction decision
 * logic lives in xiao_ota_boot_io.c's xiao_ota_boot_process_io(), which
 * this file only wires up to real hardware and calls unmodified. A
 * native host test builds the exact same xiao_ota_boot_process_io()
 * against a fake, in-memory xiao_ota_io_t instead (tests/fake_io.c) --
 * this file is never part of that build, since it has no SDK-independent
 * host build target of its own.
 */

/*
 * Bounded register-busy-wait timeouts, calibrated per operation class from
 * documented worst-case device timings (not one arbitrary iteration count
 * shared by every operation) -- a wedged/faulty external QSPI chip or NVMC
 * page-erase must never hang the bootloader forever with no watchdog feed
 * during an install; that would defeat the entire trial/rollback safety
 * design. Deadlines are measured against the Cortex-M4's DWT free-running
 * cycle counter (`DWT->CYCCNT`), not an estimated spin-loop iteration
 * count: an *overestimated* cycles-per-iteration guess would silently
 * shrink the real wall-clock timeout instead of only ever padding it
 * generously, so a real hardware clock is used instead of any estimate.
 * `DWT->CYCCNT` requires no interrupts and needs no periodic servicing;
 * elapsed time is computed as `(uint32_t)(DWT->CYCCNT - start)`, which
 * stays correct across a 32-bit wrap by plain unsigned-subtraction
 * arithmetic as long as the actual elapsed time never exceeds the full
 * 32-bit cycle range (over a minute at 64 MHz) -- far beyond any timeout
 * used here. A timeout firing always means "hardware fault", handled by
 * the caller exactly like any other IO failure (never advance phase/
 * floor, trust a hash from it, or continue as if the operation happened).
 */
#define XIAO_OTA_HW_CPU_HZ (64000000u)

static bool g_dwt_cycle_counter_enabled = false;

/* Idempotent: enables the DWT cycle counter once, on first use. Safe to
 * call from every wait function -- a single register read decides
 * whether anything needs to be done. */
static void hw_ensure_cycle_counter_enabled(void) {
  if (g_dwt_cycle_counter_enabled) return;
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
  g_dwt_cycle_counter_enabled = true;
}

static inline uint32_t hw_deadline_cycles(uint32_t timeout_ms) {
  return (uint32_t)(((uint64_t)timeout_ms * XIAO_OTA_HW_CPU_HZ) / 1000u);
}

/* QSPI peripheral bring-up (PSEL/IFCONFIG/ENABLE/ACTIVATE): sub-millisecond
 * in practice; bounded generously at 10 ms. */
#define XIAO_OTA_HW_QSPI_ACTIVATE_TIMEOUT_MS (10u)
/* P25Q16H custom single-byte status-register read/write instructions:
 * bounded generously at 10 ms (far above any real SPI-NOR status-register
 * command turnaround). */
#define XIAO_OTA_HW_QSPI_CINSTR_TIMEOUT_MS (10u)
/* P25Q16H page-program worst case (datasheet tPP, up to a 256-byte page):
 * a few milliseconds typical; bounded at 20 ms. */
#define XIAO_OTA_HW_QSPI_PROGRAM_TIMEOUT_MS (20u)
/* P25Q16H 4 KiB sector-erase worst case (datasheet tSE): hundreds of ms
 * typical; bounded generously at 3000 ms. */
#define XIAO_OTA_HW_QSPI_ERASE_TIMEOUT_MS (3000u)
/* nRF52840 NVMC page-erase worst case (product specification tERASEPAGE):
 * bounded generously at 200 ms. */
#define XIAO_OTA_HW_NVMC_ERASE_TIMEOUT_MS (200u)
/* nRF52840 NVMC single 32-bit word write worst case (product
 * specification tWRITE): bounded generously at 5 ms per word. */
#define XIAO_OTA_HW_NVMC_WRITE_TIMEOUT_MS (5u)

static bool qspi_wait_for(uint32_t timeout_ms) {
  hw_ensure_cycle_counter_enabled();
  const uint32_t start = DWT->CYCCNT;
  const uint32_t deadline_cycles = hw_deadline_cycles(timeout_ms);
  while (NRF_QSPI->EVENTS_READY == 0) {
    if ((uint32_t)(DWT->CYCCNT - start) >= deadline_cycles) return false;
  }
  NRF_QSPI->EVENTS_READY = 0;
  return true;
}

static bool nvmc_wait_for(uint32_t timeout_ms) {
  hw_ensure_cycle_counter_enabled();
  const uint32_t start = DWT->CYCCNT;
  const uint32_t deadline_cycles = hw_deadline_cycles(timeout_ms);
  while (NRF_NVMC->READY == NVMC_READY_READY_Busy) {
    if ((uint32_t)(DWT->CYCCNT - start) >= deadline_cycles) return false;
  }
  return true;
}

/*
 * P25Q16H external QSPI flash custom (single-lane SPI) instructions used
 * only to confirm/set the chip's own Quad Enable bit at bring-up -- the
 * nRF52840 QSPI peripheral's own EVENTS_READY/IFCONFIG quad-mode
 * configuration says nothing about whether the FLASH CHIP ITSELF will
 * actually honour IO2/IO3 as data lines; that is controlled entirely by
 * this status-register bit inside the flash part, which is not
 * guaranteed to still be set after a power loss or an unrelated prior
 * firmware. Opcodes and the Status-Register-2 QE bit position are per the
 * P25Q16H datasheet (Read Status Register-2 0x35, Write Enable 0x06,
 * Write Status Register-2 0x31, QE = SR2 bit 1), corroborated against
 * this repository's own vendored `CustomLFS_QSPIFlash.cpp` flash-chip
 * table and status-register helpers -- reasoned from documented/real
 * in-repo reference behaviour, not re-confirmed against a physical chip
 * by this change.
 *
 * Every CINSTRCONF write below explicitly drives IO2/IO3 HIGH
 * (`QSPI_CINSTRCONF_LIO2_Msk`/`LIO3_Msk`) for the duration of the
 * transfer. In single/dual SPI mode those lines are wired to the flash's
 * WP#/HOLD# pins; leaving them at their register-reset LOW level would
 * assert write-protect/hold on the part during exactly the commands that
 * need to reach it, which can silently block WREN/WRSR2 rather than
 * report any error. This matches `CustomLFS_QSPIFlash.cpp`'s
 * `readStatus()`/`writeStatus()` (`io2_level = true, io3_level = true`)
 * and the same fields set in `nrf_qspi_cinstr_transfer_start()`
 * (`hal/nrf_qspi.h`).
 */
#define XIAO_OTA_P25Q16H_OPCODE_RDSR1 (0x05u)
#define XIAO_OTA_P25Q16H_OPCODE_RDSR2 (0x35u)
#define XIAO_OTA_P25Q16H_OPCODE_WREN (0x06u)
#define XIAO_OTA_P25Q16H_OPCODE_WRSR2 (0x31u)
#define XIAO_OTA_P25Q16H_SR2_QE_BIT (0x02u)
#define XIAO_OTA_P25Q16H_SR1_WIP_BIT (0x01u)
#define XIAO_OTA_HW_QSPI_CINSTR_LEVELS \
  (QSPI_CINSTRCONF_LIO2_Msk | QSPI_CINSTRCONF_LIO3_Msk)

static bool qspi_cinstr_read_byte(uint8_t opcode, uint8_t *out_byte) {
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->CINSTRCONF =
      ((uint32_t)opcode << QSPI_CINSTRCONF_OPCODE_Pos) |
      (QSPI_CINSTRCONF_LENGTH_2B << QSPI_CINSTRCONF_LENGTH_Pos) |
      XIAO_OTA_HW_QSPI_CINSTR_LEVELS;
  if (!qspi_wait_for(XIAO_OTA_HW_QSPI_CINSTR_TIMEOUT_MS)) return false;
  *out_byte = (uint8_t)(NRF_QSPI->CINSTRDAT0 & 0xFFu);
  return true;
}

/* Polls the flash's OWN Write-In-Progress bit (status register 1, bit 0)
 * until it clears. `NRF_QSPI->EVENTS_READY`/CINSTRCONF's WIPWAIT option
 * only prove the *peripheral's* custom-instruction transfer completed, or
 * (per the vendored `nrfx_qspi.c` driver's own comment at the WIPWAIT
 * check) that a *previously issued* write finished before this new
 * instruction started -- neither proves the write this function just
 * issued has itself finished committing inside the flash part. This is
 * the only way to actually confirm that. */
static bool qspi_wait_flash_write_complete(void) {
  hw_ensure_cycle_counter_enabled();
  const uint32_t start = DWT->CYCCNT;
  const uint32_t deadline_cycles =
      hw_deadline_cycles(XIAO_OTA_HW_QSPI_CINSTR_TIMEOUT_MS);
  for (;;) {
    uint8_t status = 0;
    if (!qspi_cinstr_read_byte(XIAO_OTA_P25Q16H_OPCODE_RDSR1, &status)) {
      return false;
    }
    if ((status & XIAO_OTA_P25Q16H_SR1_WIP_BIT) == 0) return true;
    if ((uint32_t)(DWT->CYCCNT - start) >= deadline_cycles) return false;
  }
}

static bool qspi_cinstr_write_enable(void) {
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->CINSTRCONF =
      ((uint32_t)XIAO_OTA_P25Q16H_OPCODE_WREN << QSPI_CINSTRCONF_OPCODE_Pos) |
      (QSPI_CINSTRCONF_LENGTH_1B << QSPI_CINSTRCONF_LENGTH_Pos) |
      XIAO_OTA_HW_QSPI_CINSTR_LEVELS;
  return qspi_wait_for(XIAO_OTA_HW_QSPI_CINSTR_TIMEOUT_MS);
}

static bool qspi_cinstr_write_sr2(uint8_t value) {
  if (!qspi_cinstr_write_enable()) return false;
  NRF_QSPI->CINSTRDAT0 = value;
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->CINSTRCONF =
      ((uint32_t)XIAO_OTA_P25Q16H_OPCODE_WRSR2 << QSPI_CINSTRCONF_OPCODE_Pos) |
      (QSPI_CINSTRCONF_LENGTH_2B << QSPI_CINSTRCONF_LENGTH_Pos) |
      (QSPI_CINSTRCONF_WIPWAIT_Enable << QSPI_CINSTRCONF_WIPWAIT_Pos) |
      XIAO_OTA_HW_QSPI_CINSTR_LEVELS;
  if (!qspi_wait_for(XIAO_OTA_HW_QSPI_CINSTR_TIMEOUT_MS)) return false;
  /* WIPWAIT above only guaranteed the flash was idle BEFORE this WRSR2
   * instruction was issued (see the comment on
   * qspi_wait_flash_write_complete()); explicitly poll WIP now to prove
   * this status-register write itself has actually committed before any
   * caller trusts a subsequent QE readback. */
  return qspi_wait_flash_write_complete();
}

/* Confirms the external flash's Quad Enable bit is set, setting it if
 * necessary, instead of assuming a previous boot (or the factory default)
 * left it that way. Returns false (bring-up must fail closed) if the bit
 * cannot be read, cannot be written, or still reads back unset after an
 * explicit write attempt. */
static bool qspi_confirm_quad_enable(void) {
  uint8_t status = 0;
  if (!qspi_cinstr_read_byte(XIAO_OTA_P25Q16H_OPCODE_RDSR2, &status)) return false;
  if ((status & XIAO_OTA_P25Q16H_SR2_QE_BIT) != 0) return true;
  if (!qspi_cinstr_write_sr2((uint8_t)(status | XIAO_OTA_P25Q16H_SR2_QE_BIT))) {
    return false;
  }
  if (!qspi_cinstr_read_byte(XIAO_OTA_P25Q16H_OPCODE_RDSR2, &status)) return false;
  return (status & XIAO_OTA_P25Q16H_SR2_QE_BIT) != 0;
}

static bool hw_qspi_init(void *ctx) {
  (void)ctx;
  NRF_QSPI->PSEL.SCK = XIAO_OTA_QSPI_SCK_PIN;
  NRF_QSPI->PSEL.CSN = XIAO_OTA_QSPI_CS_PIN;
  NRF_QSPI->PSEL.IO0 = XIAO_OTA_QSPI_IO0_PIN;
  NRF_QSPI->PSEL.IO1 = XIAO_OTA_QSPI_IO1_PIN;
  NRF_QSPI->PSEL.IO2 = XIAO_OTA_QSPI_IO2_PIN;
  NRF_QSPI->PSEL.IO3 = XIAO_OTA_QSPI_IO3_PIN;
  NRF_QSPI->IFCONFIG0 =
      (QSPI_IFCONFIG0_READOC_READ4O << QSPI_IFCONFIG0_READOC_Pos) |
      (QSPI_IFCONFIG0_WRITEOC_PP4O << QSPI_IFCONFIG0_WRITEOC_Pos) |
      (QSPI_IFCONFIG0_ADDRMODE_24BIT << QSPI_IFCONFIG0_ADDRMODE_Pos);
  NRF_QSPI->IFCONFIG1 =
      (3u << QSPI_IFCONFIG1_SCKFREQ_Pos) |
      (QSPI_IFCONFIG1_SPIMODE_MODE0 << QSPI_IFCONFIG1_SPIMODE_Pos);
  NRF_QSPI->ENABLE = QSPI_ENABLE_ENABLE_Enabled;
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->TASKS_ACTIVATE = 1;
  if (!qspi_wait_for(XIAO_OTA_HW_QSPI_ACTIVATE_TIMEOUT_MS)) return false;
  /* IFCONFIG0 above already programs the NRF QSPI PERIPHERAL for quad
   * read/program, but that says nothing about the FLASH CHIP's own Quad
   * Enable bit -- confirm/set it explicitly rather than assuming a prior
   * boot (or the factory default) left it that way. */
  return qspi_confirm_quad_enable();
}

static bool hw_qspi_read(void *ctx, uint32_t address, void *destination,
                         size_t length) {
  (void)ctx;
  NRF_QSPI->READ.SRC = address;
  NRF_QSPI->READ.DST = (uint32_t)destination;
  NRF_QSPI->READ.CNT = length;
  NRF_QSPI->TASKS_READSTART = 1;
  return qspi_wait_for(XIAO_OTA_HW_QSPI_PROGRAM_TIMEOUT_MS);
}

static bool hw_qspi_write(void *ctx, uint32_t address, const void *source,
                          size_t length) {
  (void)ctx;
  NRF_QSPI->WRITE.SRC = (uint32_t)source;
  NRF_QSPI->WRITE.DST = address;
  NRF_QSPI->WRITE.CNT = length;
  NRF_QSPI->TASKS_WRITESTART = 1;
  return qspi_wait_for(XIAO_OTA_HW_QSPI_PROGRAM_TIMEOUT_MS);
}

static bool hw_qspi_erase_sector(void *ctx, uint32_t address) {
  (void)ctx;
  NRF_QSPI->ERASE.PTR = address;
  NRF_QSPI->ERASE.LEN = QSPI_ERASE_LEN_LEN_4KB;
  NRF_QSPI->TASKS_ERASESTART = 1;
  return qspi_wait_for(XIAO_OTA_HW_QSPI_ERASE_TIMEOUT_MS);
}

static bool hw_internal_erase_page(void *ctx, uint32_t address) {
  bool ok;
  (void)ctx;
  NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Een;
  if (!nvmc_wait_for(XIAO_OTA_HW_NVMC_ERASE_TIMEOUT_MS)) {
    NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren;
    return false;
  }
  NRF_NVMC->ERASEPAGE = address;
  ok = nvmc_wait_for(XIAO_OTA_HW_NVMC_ERASE_TIMEOUT_MS);
  NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren;
  return ok;
}

static bool hw_internal_write(void *ctx, uint32_t address, const void *source,
                              size_t length) {
  size_t i;
  bool ok = true;
  (void)ctx;
  NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Wen;
  if (!nvmc_wait_for(XIAO_OTA_HW_NVMC_WRITE_TIMEOUT_MS)) {
    NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren;
    return false;
  }
  for (i = 0; i < length; i += 4) {
    uint32_t word;
    memcpy(&word, (const uint8_t *)source + i, sizeof(word));
    *(volatile uint32_t *)(address + i) = word;
    if (!nvmc_wait_for(XIAO_OTA_HW_NVMC_WRITE_TIMEOUT_MS)) { ok = false; break; }
  }
  NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren;
  return ok;
}

static bool hw_internal_read(void *ctx, uint32_t address, void *destination,
                             size_t length) {
  (void)ctx;
  memcpy(destination, (const void *)address, length);
  return true;
}

static void hw_start_trial_watchdog(void *ctx) {
  (void)ctx;
  NRF_WDT->CONFIG = WDT_CONFIG_SLEEP_Run << WDT_CONFIG_SLEEP_Pos;
  NRF_WDT->CRV = 60u * 32768u;
  NRF_WDT->RREN = WDT_RREN_RR0_Msk;
  NRF_WDT->TASKS_START = 1;
  NRF_WDT->RR[0] = WDT_RR_RR_Reload;
}

static void hw_force_recovery(void *ctx) {
  (void)ctx;
  NRF_POWER->GPREGRET = XIAO_OTA_DFU_MAGIC_UF2;
  NVIC_SystemReset();
  while (true) {}
}

static uint64_t hw_device_address(void *ctx) {
  (void)ctx;
  return ((uint64_t)NRF_FICR->DEVICEID[1] << 32) | NRF_FICR->DEVICEID[0];
}

static bool hw_explicit_dfu_requested(void *ctx) {
  (void)ctx;
  return xiao_ota_explicit_dfu_requested(NRF_POWER->GPREGRET);
}


void xiao_ota_boot_process(void) {
  static const xiao_ota_io_t hardware_io = {
      .ctx = NULL,
      .device_address = hw_device_address,
      .explicit_dfu_requested = hw_explicit_dfu_requested,
      .qspi_init = hw_qspi_init,
      .qspi_read = hw_qspi_read,
      .qspi_write = hw_qspi_write,
      .qspi_erase_sector = hw_qspi_erase_sector,
      .internal_read = hw_internal_read,
      .internal_write = hw_internal_write,
      .internal_erase_page = hw_internal_erase_page,
      .start_trial_watchdog = hw_start_trial_watchdog,
      .force_recovery = hw_force_recovery,
  };
  xiao_ota_boot_process_io(&hardware_io);
}
