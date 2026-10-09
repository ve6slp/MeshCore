#include "xiao_ota_boot.h"
#include "xiao_ota_boot_io.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "nrf.h"
#include "nrfx.h"
#include "nrf_qspi.h"
#include "xiao_ota_layout.h"
#include "xiao_ota_record.h"

static bool bench_reset_active;

static void bench_feed_existing_watchdog(void) {
  if (!bench_reset_active || !NRF_WDT->RUNSTATUS) return;
  for (unsigned i = 0; i < 8; ++i)
    if (NRF_WDT->RREN & (1u << i)) NRF_WDT->RR[i] = 0x6E524635u;
}

#if NRFX_DELAY_DWT_BASED
#error "QSPI wake requires the pinned finite non-DWT nrfx delay"
#endif

/*
 * Real nRF52840 QSPI/NVMC/WDT/FICR/GPREGRET register access. Thin,
 * register-level adapters implementing the xiao_ota_io_t
 * contract (xiao_ota_boot_io.h) -- all actual OTA transaction decision
 * logic lives in xiao_ota_boot_io.c's xiao_ota_boot_process_io(), which
 * this file only wires up to real hardware and calls unmodified. A
 * native host test builds the exact same xiao_ota_boot_process_io()
 * against a fake, in-memory xiao_ota_io_t instead (tests/fake_io.c) --
 * tests/test_qspi_adapter.c also builds this production adapter against
 * a minimal QSPI/DWT register model (not the transaction processor).
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
  /* All private callers use <= 3000 ms; 64 MHz is divisible by 1000.
   * The product fits uint32_t, without a runtime 64-bit division. */
  return timeout_ms * (XIAO_OTA_HW_CPU_HZ / 1000u);
}

/* Activation, wake, and initial flash-idle polling share the erase budget:
 * the MCU may have reset while the external chip was still erasing. */
#define XIAO_OTA_HW_QSPI_STARTUP_TIMEOUT_MS (3000u)
/* P25Q16H custom single-byte status-register read/write instructions:
 * bounded generously at 10 ms (far above any real SPI-NOR status-register
 * command turnaround). */
#define XIAO_OTA_HW_QSPI_CINSTR_TIMEOUT_MS (10u)
/* P25Q16H datasheet July 20, 2020, table 5-4: tPP max 3 ms for
 * up to 256 bytes. Allow 20 ms for transfer plus final WIP completion. */
#define XIAO_OTA_HW_QSPI_PROGRAM_TIMEOUT_MS (20u)
/* Retain the conservative 3000 ms sector-erase budget; it covers both
 * command transfer and flash WIP completion, not just EVENTS_READY. */
#define XIAO_OTA_HW_QSPI_ERASE_TIMEOUT_MS (3000u)
/* nRF52840 NVMC page-erase worst case (product specification tERASEPAGE):
 * bounded generously at 200 ms. */
#define XIAO_OTA_HW_NVMC_ERASE_TIMEOUT_MS (200u)
/* nRF52840 NVMC single 32-bit word write worst case (product
 * specification tWRITE): bounded generously at 5 ms per word. */
#define XIAO_OTA_HW_NVMC_WRITE_TIMEOUT_MS (5u)

/* DWT remains the timebase. Like nrfx's finite-attempt waits, this
 * independent liveness guard also terminates if CYCCNT never starts or
 * stops. It is NOT a wall-clock timeout or a calibrated iteration delay. */
#define XIAO_OTA_HW_DWT_STAGNANT_READ_LIMIT (1024u)

typedef struct {
  uint32_t start;
  uint32_t last;
  uint32_t cycles;
  uint32_t stagnant_reads;
} qspi_deadline_t;

/* Share this initializer in the size-constrained boot image; inlining it
 * duplicates DWT bring-up at every transfer/status-poll call site. */
static __attribute__((noinline)) void qspi_deadline_start(
    qspi_deadline_t *deadline, uint32_t timeout_ms) {
  hw_ensure_cycle_counter_enabled();
  const uint32_t now = DWT->CYCCNT;
  deadline->start = deadline->last = now;
  deadline->cycles = hw_deadline_cycles(timeout_ms);
  deadline->stagnant_reads = 0;
}

static bool qspi_deadline_expired(qspi_deadline_t *deadline) {
  const uint32_t now = DWT->CYCCNT;
  if (now == deadline->last) {
    if (++deadline->stagnant_reads >= XIAO_OTA_HW_DWT_STAGNANT_READ_LIMIT) {
      return true;
    }
  } else {
    deadline->last = now;
    deadline->stagnant_reads = 0;
  }
  return (uint32_t)(now - deadline->start) >= deadline->cycles;
}

static void qspi_quiesce(void) {
  /* Match pinned nrfx_qspi_uninit(): deactivate, then disable using the
   * HAL (including anomaly 122's workaround). Do not wait for READY:
   * it may be the event that never arrives. Disable/readback + DSB
   * precede returning ownership of any EasyDMA buffer to the caller.
   * This cannot undo a command already accepted by the flash chip. */
  NRF_QSPI->INTENCLR = QSPI_INTENCLR_READY_Msk;
  NRF_QSPI->TASKS_DEACTIVATE = 1;
  nrf_qspi_disable(NRF_QSPI);
  (void)NRF_QSPI->ENABLE;
  __DSB();
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->READ.CNT = 0;
  NRF_QSPI->READ.DST = 0;
  NRF_QSPI->WRITE.CNT = 0;
  NRF_QSPI->WRITE.SRC = 0;
}

static bool qspi_wait_ready(qspi_deadline_t *deadline,
                            qspi_deadline_t *operation_deadline) {
  for (;;) {
    bench_feed_existing_watchdog();
    if (qspi_deadline_expired(deadline) ||
        (operation_deadline && qspi_deadline_expired(operation_deadline))) {
      qspi_quiesce();
      return false;
    }
    if (NRF_QSPI->EVENTS_READY != 0) break;
  }
  NRF_QSPI->EVENTS_READY = 0;
  return true;
}

static bool qspi_wait_for(uint32_t timeout_ms) {
  qspi_deadline_t deadline;
  qspi_deadline_start(&deadline, timeout_ms);
  return qspi_wait_ready(&deadline, NULL);
}

static bool nvmc_wait_for(uint32_t timeout_ms) {
  hw_ensure_cycle_counter_enabled();
  const uint32_t start = DWT->CYCCNT;
  const uint32_t deadline_cycles = hw_deadline_cycles(timeout_ms);
  while (NRF_NVMC->READY == NVMC_READY_READY_Busy) {
    bench_feed_existing_watchdog();
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
#define XIAO_OTA_P25Q16H_OPCODE_RELEASE_DPD (0xABu)
#define XIAO_OTA_P25Q16H_SR2_QE_BIT (0x02u)
#define XIAO_OTA_P25Q16H_SR1_WIP_BIT (0x01u)
#define XIAO_OTA_HW_QSPI_CINSTR_LEVELS \
  (QSPI_CINSTRCONF_LIO2_Msk | QSPI_CINSTRCONF_LIO3_Msk)

static __attribute__((noinline)) bool qspi_cinstr_transfer(
    uint32_t configuration, qspi_deadline_t *operation_deadline) {
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->CINSTRCONF = configuration | XIAO_OTA_HW_QSPI_CINSTR_LEVELS;
  qspi_deadline_t transfer;
  qspi_deadline_start(&transfer, XIAO_OTA_HW_QSPI_CINSTR_TIMEOUT_MS);
  return qspi_wait_ready(&transfer, operation_deadline);
}

static bool qspi_cinstr_read_byte_until(uint8_t opcode, uint8_t *out_byte,
                                       qspi_deadline_t *operation_deadline) {
  if (operation_deadline && qspi_deadline_expired(operation_deadline)) {
    qspi_quiesce();
    return false;
  }
  if (!qspi_cinstr_transfer(
          ((uint32_t)opcode << QSPI_CINSTRCONF_OPCODE_Pos) |
          (QSPI_CINSTRCONF_LENGTH_2B << QSPI_CINSTRCONF_LENGTH_Pos),
          operation_deadline)) return false;
  *out_byte = (uint8_t)(NRF_QSPI->CINSTRDAT0 & 0xFFu);
  return true;
}

static bool qspi_cinstr_read_byte(uint8_t opcode, uint8_t *out_byte) {
  return qspi_cinstr_read_byte_until(opcode, out_byte, NULL);
}

/* Polls the flash's OWN Write-In-Progress bit (status register 1, bit 0)
 * until it clears. `NRF_QSPI->EVENTS_READY`/CINSTRCONF's WIPWAIT option
 * only prove the *peripheral's* custom-instruction transfer completed, or
 * (per the vendored `nrfx_qspi.c` driver's own comment at the WIPWAIT
 * check) that a *previously issued* write finished before this new
 * instruction started -- neither proves the write this function just
 * issued has itself finished committing inside the flash part. This is
 * the only way to actually confirm that. */
static bool qspi_wait_flash_write_complete(qspi_deadline_t *deadline) {
  for (;;) {
    uint8_t status = 0;
    if (!qspi_cinstr_read_byte_until(XIAO_OTA_P25Q16H_OPCODE_RDSR1,
                                    &status, deadline)) {
      return false;
    }
    if ((status & XIAO_OTA_P25Q16H_SR1_WIP_BIT) == 0) return true;
  }
}

static bool qspi_cinstr_command(
    uint8_t opcode, qspi_deadline_t *operation_deadline) {
  return qspi_cinstr_transfer(
      ((uint32_t)opcode << QSPI_CINSTRCONF_OPCODE_Pos) |
      (QSPI_CINSTRCONF_LENGTH_1B << QSPI_CINSTRCONF_LENGTH_Pos),
      operation_deadline);
}

static bool qspi_cinstr_write_enable(void) {
  return qspi_cinstr_command(XIAO_OTA_P25Q16H_OPCODE_WREN, NULL);
}

static bool qspi_cinstr_write_sr2(uint8_t value) {
  /* tW max 12 ms (P25Q16H table 5-3); share the conservative 20 ms
   * program budget across WREN, transfer, and WIP polling. */
  qspi_deadline_t deadline;
  qspi_deadline_start(&deadline, XIAO_OTA_HW_QSPI_PROGRAM_TIMEOUT_MS);
  if (!qspi_cinstr_write_enable()) return false;
  NRF_QSPI->CINSTRDAT0 = value;
  if (!qspi_cinstr_transfer(
      ((uint32_t)XIAO_OTA_P25Q16H_OPCODE_WRSR2 << QSPI_CINSTRCONF_OPCODE_Pos) |
      (QSPI_CINSTRCONF_LENGTH_2B << QSPI_CINSTRCONF_LENGTH_Pos) |
      (QSPI_CINSTRCONF_WIPWAIT_Enable << QSPI_CINSTRCONF_WIPWAIT_Pos) |
      XIAO_OTA_HW_QSPI_CINSTR_LEVELS, &deadline)) return false;
  /* WIPWAIT above only guaranteed the flash was idle BEFORE this WRSR2
   * instruction was issued (see the comment on
   * qspi_wait_flash_write_complete()); explicitly poll WIP now to prove
   * this status-register write itself has actually committed before any
   * caller trusts a subsequent QE readback. */
  return qspi_wait_flash_write_complete(&deadline);
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

static bool qspi_wake_and_wait_idle(qspi_deadline_t *deadline) {
  if (!qspi_cinstr_command(XIAO_OTA_P25Q16H_OPCODE_RELEASE_DPD, deadline)) {
    return false;
  }
  /* P25Q16H table 5-3 / section 10.31: tRES1/2 max 8 us.
   * Use the SDK's finite instruction-loop delay, not DWT-dependent wait.
   * No WIPWAIT on AB: a sleeping chip cannot answer status polls. */
  NRFX_DELAY_US(10u);
  return qspi_wait_flash_write_complete(deadline);
}

/* Both supported board profiles use P25Q16H (JEDEC 85:60:15).
 * READY/QE alone can succeed with floating or wrong-part read data. */
static bool qspi_confirm_jedec(void) {
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->CINSTRCONF =
      (0x9Fu << QSPI_CINSTRCONF_OPCODE_Pos) |
      (QSPI_CINSTRCONF_LENGTH_4B << QSPI_CINSTRCONF_LENGTH_Pos) |
      XIAO_OTA_HW_QSPI_CINSTR_LEVELS;
  return qspi_wait_for(XIAO_OTA_HW_QSPI_CINSTR_TIMEOUT_MS) &&
         (NRF_QSPI->CINSTRDAT0 & 0xFFFFFFu) == 0x156085u;
}

static bool hw_qspi_init(void *ctx) {
  (void)ctx;
  qspi_deadline_t deadline;
  qspi_deadline_start(&deadline, XIAO_OTA_HW_QSPI_STARTUP_TIMEOUT_MS);
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
  if (!qspi_wait_ready(&deadline, NULL) ||
      !qspi_wake_and_wait_idle(&deadline)) return false;
  /* IFCONFIG0 above already programs the NRF QSPI PERIPHERAL for quad
   * read/program, but that says nothing about the FLASH CHIP's own Quad
   * Enable bit -- confirm/set it explicitly rather than assuming a prior
   * boot (or the factory default) left it that way. */
  return qspi_confirm_jedec() && qspi_confirm_quad_enable();
}

static bool hw_qspi_read(void *ctx, uint32_t address, void *destination,
                         size_t length) {
  (void)ctx;
  if (NRF_QSPI->ENABLE != QSPI_ENABLE_ENABLE_Enabled) return false;
  qspi_deadline_t deadline;
  qspi_deadline_start(&deadline, XIAO_OTA_HW_QSPI_PROGRAM_TIMEOUT_MS);
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->READ.SRC = address;
  NRF_QSPI->READ.DST = (uint32_t)destination;
  NRF_QSPI->READ.CNT = length;
  NRF_QSPI->TASKS_READSTART = 1;
  return qspi_wait_ready(&deadline, NULL);
}

static bool hw_qspi_write(void *ctx, uint32_t address, const void *source,
                          size_t length) {
  (void)ctx;
  if (NRF_QSPI->ENABLE != QSPI_ENABLE_ENABLE_Enabled) return false;
  qspi_deadline_t deadline;
  qspi_deadline_start(&deadline, XIAO_OTA_HW_QSPI_PROGRAM_TIMEOUT_MS);
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->WRITE.SRC = (uint32_t)source;
  NRF_QSPI->WRITE.DST = address;
  NRF_QSPI->WRITE.CNT = length;
  NRF_QSPI->TASKS_WRITESTART = 1;
  return qspi_wait_ready(&deadline, NULL) &&
         qspi_wait_flash_write_complete(&deadline);
}

static bool hw_qspi_erase_sector(void *ctx, uint32_t address) {
  (void)ctx;
  if (NRF_QSPI->ENABLE != QSPI_ENABLE_ENABLE_Enabled) return false;
  qspi_deadline_t deadline;
  qspi_deadline_start(&deadline, XIAO_OTA_HW_QSPI_ERASE_TIMEOUT_MS);
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->ERASE.PTR = address;
  NRF_QSPI->ERASE.LEN = QSPI_ERASE_LEN_LEN_4KB;
  NRF_QSPI->TASKS_ERASESTART = 1;
  return qspi_wait_ready(&deadline, NULL) &&
         qspi_wait_flash_write_complete(&deadline);
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

#ifdef XIAO_OTA_FIXED_STAGE2_RETURNING
static bool stage_recovery_requested;
bool xiao_ota_stage2_recovery_requested(void) {
  return stage_recovery_requested;
}
#endif

static void hw_force_recovery(void *ctx) {
  (void)ctx;
#ifdef XIAO_OTA_FIXED_STAGE2_RETURNING
  stage_recovery_requested = true;
#else
  NRF_POWER->GPREGRET = XIAO_OTA_DFU_MAGIC_UF2;
  NVIC_SystemReset();
  while (true) {}
#endif
}

static uint64_t hw_device_address(void *ctx) {
  (void)ctx;
  return ((uint64_t)NRF_FICR->DEVICEID[1] << 32) | NRF_FICR->DEVICEID[0];
}

static bool hw_explicit_dfu_requested(void *ctx) {
  (void)ctx;
  return xiao_ota_explicit_dfu_requested(NRF_POWER->GPREGRET);
}


const xiao_ota_io_t *xiao_ota_boot_internal_io(void) {
  static const xiao_ota_io_t internal = {
      .internal_read = hw_internal_read,
      .internal_write = hw_internal_write,
      .internal_erase_page = hw_internal_erase_page,
  };
  return &internal;
}

static const xiao_ota_io_t *complete_io(void) {
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
  return &hardware_io;
}

bool xiao_ota_boot_bench_reset(void) {
  bench_reset_active = true;
  bool ready = xiao_ota_usb_bench_reset(complete_io(), true);
  bench_reset_active = false;
  return ready;
}

void xiao_ota_boot_process(void) {
  const xiao_ota_io_t *hardware_io = complete_io();
#ifdef XIAO_OTA_FIXED_STAGE2_RETURNING
  stage_recovery_requested = false;
#endif
  xiao_ota_boot_process_io(hardware_io);
#ifdef XIAO_OTA_FIXED_STAGE2_RETURNING
  if (!stage_recovery_requested && !xiao_ota_app_is_intact(hardware_io))
    hw_force_recovery(NULL);
#endif
}
