#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nrf.h"
#include "xiao_ota_boot.h"
#include "xiao_ota_boot_io.h"
#include "xiao_ota_layout.h"

NRF_QSPI_Type mock_qspi;
mock_dwt_t mock_dwt;
mock_coredebug_t mock_coredebug;
mock_nvmc_t mock_nvmc;
mock_wdt_t mock_wdt;
mock_power_t mock_power;
mock_ficr_t mock_ficr;

static const xiao_ota_io_t *io;
static uint8_t flash[8192], source[256], destination[256], latched[256];
static uint64_t wall_us, busy_until, transfer_due, custom_due;
static uint32_t erase_us, program_us, transfer_us, status_us;
static uint32_t pending_source, pending_destination, pending_length;
static unsigned pending_task, pending_custom, flash_operation;
static unsigned dma_reads, dma_writes, write_starts, barriers, ticks;
static unsigned status_reads, disable_calls;
static bool frozen_clock, hold_ready, hold_status, suppress_write_ready;
static bool deep_power_down, delay_activation_until_idle, ignore_wake;
static uint64_t wake_ready_at;
static uint32_t clock_tick_us;
static unsigned tick_limit;
static unsigned wake_commands, jedec_reads, early_commands;
static uint8_t sr2;

enum { READ = 1, WRITE, ERASE, PROGRAM, STATUS };

/* Device scheduling only: READY ends command/DMA transmission, while
 * flash busy ends separately. A queued write dereferences its RAM source
 * only when the flash becomes idle, not when WRITESTART is submitted.
 * All timings below are synthetic fault schedules, NOT measurements. */
void mock_qspi_poll(void) {
  if (busy_until && wall_us >= busy_until) {
    if (flash_operation == ERASE) memset(flash, 0xff, 4096);
    if (flash_operation == PROGRAM) {
      for (uint32_t i = 0; i < pending_length; ++i) {
        flash[pending_destination + i] &= latched[i];
      }
    }
    busy_until = 0;
    flash_operation = 0;
  }
  if (mock_qspi.ENABLE != QSPI_ENABLE_ENABLE_Enabled) {
    pending_task = pending_custom = 0;
    mock_qspi.TASKS_ACTIVATE = 0;
    mock_qspi.TASKS_READSTART = mock_qspi.TASKS_WRITESTART = 0;
    mock_qspi.TASKS_ERASESTART = mock_qspi.CINSTRCONF = 0;
    return;
  }
  if (mock_qspi.TASKS_ACTIVATE) {
    if (!hold_ready && (!delay_activation_until_idle || !busy_until)) {
      mock_qspi.TASKS_ACTIVATE = 0;
      mock_qspi.EVENTS_READY = 1;
    }
  }
  if (mock_qspi.TASKS_READSTART || mock_qspi.TASKS_WRITESTART ||
      mock_qspi.TASKS_ERASESTART) {
    assert(!pending_task);
    if (mock_qspi.TASKS_READSTART) {
      pending_task = READ;
      pending_source = mock_qspi.READ.SRC;
      pending_destination = mock_qspi.READ.DST;
      pending_length = mock_qspi.READ.CNT;
    } else if (mock_qspi.TASKS_WRITESTART) {
      pending_task = WRITE;
      ++write_starts;
      pending_source = mock_qspi.WRITE.SRC;
      pending_destination = mock_qspi.WRITE.DST;
      pending_length = mock_qspi.WRITE.CNT;
    } else {
      pending_task = ERASE;
      assert(mock_qspi.ERASE.LEN == QSPI_ERASE_LEN_LEN_4KB);
    }
    mock_qspi.TASKS_READSTART = mock_qspi.TASKS_WRITESTART = 0;
    mock_qspi.TASKS_ERASESTART = 0;
    transfer_due = wall_us + transfer_us;
  }
  if (pending_task && !busy_until && wall_us >= transfer_due && !hold_ready) {
    if (pending_task == READ) {
      assert(pending_source + pending_length <= sizeof(flash));
      memcpy((void *)(uintptr_t)pending_destination,
             flash + pending_source, pending_length);
      ++dma_writes;
    } else if (pending_task == WRITE) {
      assert(pending_length <= sizeof(latched));
      assert(pending_destination + pending_length <= sizeof(flash));
      memcpy(latched, (const void *)(uintptr_t)pending_source, pending_length);
      ++dma_reads;
      busy_until = wall_us + program_us;
      flash_operation = PROGRAM;
    } else {
      busy_until = wall_us + erase_us;
      flash_operation = ERASE;
    }
    if (!(pending_task == WRITE && suppress_write_ready)) {
      mock_qspi.EVENTS_READY = 1;
    }
    pending_task = 0;
  }
  if (mock_qspi.CINSTRCONF) {
    assert(!pending_custom);
    assert((mock_qspi.CINSTRCONF &
            (QSPI_CINSTRCONF_LIO2_Msk | QSPI_CINSTRCONF_LIO3_Msk)) ==
           (QSPI_CINSTRCONF_LIO2_Msk | QSPI_CINSTRCONF_LIO3_Msk));
    pending_custom = (mock_qspi.CINSTRCONF >> QSPI_CINSTRCONF_OPCODE_Pos) & 0xffu;
    if (pending_custom == 0xab) {
      assert((mock_qspi.CINSTRCONF & QSPI_CINSTRCONF_WIPWAIT_Msk) == 0);
      assert(((mock_qspi.CINSTRCONF & QSPI_CINSTRCONF_LENGTH_Msk) >>
              QSPI_CINSTRCONF_LENGTH_Pos) == QSPI_CINSTRCONF_LENGTH_1B);
    }
    mock_qspi.CINSTRCONF = 0;
    custom_due = wall_us + status_us;
  }
  if (pending_custom && wall_us >= custom_due && !hold_status) {
    if (pending_custom == 0x9f) ++jedec_reads;
    if (wall_us < wake_ready_at) ++early_commands;
    if ((deep_power_down && pending_custom != 0xab) || wall_us < wake_ready_at) {
      mock_qspi.CINSTRDAT0 = UINT32_MAX;
    } else switch (pending_custom) {
      case 0x05:
        ++status_reads;
        mock_qspi.CINSTRDAT0 = busy_until ? 1u : 0u;
        break;
      case 0x35: mock_qspi.CINSTRDAT0 = sr2; break;
      case 0x9f: mock_qspi.CINSTRDAT0 = busy_until ? 0xffffffu : 0x156085u; break;
      case 0xab:
        ++wake_commands;
        if (deep_power_down && !ignore_wake) {
          deep_power_down = false;
          wake_ready_at = wall_us + 8u;
        }
        break;
      case 0x06: break;
      case 0x31:
        sr2 = (uint8_t)mock_qspi.CINSTRDAT0;
        busy_until = wall_us + program_us;
        flash_operation = STATUS;
        break;
      default: assert(!"unexpected flash opcode");
    }
    pending_custom = 0;
    mock_qspi.EVENTS_READY = 1;
  }
}

void mock_clock_tick(void) {
  /* Safety bound makes an accidentally unbounded driver an assertion
   * failure rather than an indefinitely hung test process. */
  assert(++ticks < tick_limit && "QSPI wait exceeded finite host observation bound");
  wall_us += clock_tick_us;
  if (!frozen_clock && (mock_dwt.CTRL & DWT_CTRL_CYCCNTENA_Msk)) {
    mock_dwt.CYCCNT += 64u * clock_tick_us;
  }
  mock_qspi_poll();
}

void mock_delay_us(uint32_t number_of_us) {
  wall_us += number_of_us;
  if (!frozen_clock) mock_dwt.CYCCNT += number_of_us * 64u;
  mock_qspi_poll();
}

void nrf_qspi_disable(NRF_QSPI_Type *qspi) {
  assert(qspi == &mock_qspi);
  assert(qspi->TASKS_DEACTIVATE == 1);
  qspi->ENABLE = QSPI_ENABLE_ENABLE_Disabled;
  ++disable_calls;
  mock_qspi_poll();
}

void mock_barrier(void) {
  assert(mock_qspi.ENABLE == QSPI_ENABLE_ENABLE_Disabled);
  ++barriers;
  mock_qspi_poll();
}

void NVIC_SystemReset(void) { assert(!"hardware recovery is outside this test"); }
bool xiao_ota_explicit_dfu_requested(uint32_t value) { (void)value; return false; }
void xiao_ota_boot_process_io(const xiao_ota_io_t *hardware_io) { io = hardware_io; }
bool xiao_ota_usb_bench_reset(const xiao_ota_io_t *hardware_io, bool authorized) {
  assert(authorized);
  return hardware_io->qspi_init(hardware_io->ctx);
}

static void reset_model(void) {
  memset(&mock_qspi, 0, sizeof(mock_qspi));
  memset(&mock_dwt, 0, sizeof(mock_dwt));
  mock_dwt.CTRL = DWT_CTRL_CYCCNTENA_Msk;
  memset(flash, 0x00, sizeof(flash));
  memset(source, 0x3d, sizeof(source));
  memset(destination, 0x77, sizeof(destination));
  wall_us = busy_until = 0;
  pending_task = pending_custom = flash_operation = 0;
  erase_us = 200000u;
  program_us = 3000u;
  transfer_us = status_us = 100u;
  dma_reads = dma_writes = write_starts = barriers = ticks = 0;
  status_reads = disable_calls = 0;
  frozen_clock = hold_ready = hold_status = suppress_write_ready = false;
  deep_power_down = delay_activation_until_idle = ignore_wake = false;
  wake_ready_at = 0;
  clock_tick_us = 100u;
  tick_limit = 100000u;
  wake_commands = jedec_reads = early_commands = 0;
  sr2 = 2;
}

static void initialize(void) {
  reset_model();
  assert(io->qspi_init(NULL));
}

static void assert_quiesced(void) {
  assert(mock_qspi.ENABLE == QSPI_ENABLE_ENABLE_Disabled);
  assert(disable_calls == 1 && barriers == 1);
  assert(!pending_task && !pending_custom);
  assert(mock_qspi.EVENTS_READY == 0);
  assert(mock_qspi.READ.CNT == 0 && mock_qspi.READ.DST == 0);
  assert(mock_qspi.WRITE.CNT == 0 && mock_qspi.WRITE.SRC == 0);
  const unsigned starts = write_starts;
  assert(!io->qspi_write(NULL, 0, source, sizeof(source)));
  assert(!io->qspi_read(NULL, 0, destination, sizeof(destination)));
  assert(!io->qspi_erase_sector(NULL, 0));
  assert(write_starts == starts);
}

static void delayed_erase_then_write(void) {
  initialize();
  const uint64_t start = wall_us;
  assert(io->qspi_erase_sector(NULL, 0));
  assert(!busy_until && "erase returned before flash WIP cleared");
  assert(wall_us - start >= 200000u);
  assert(status_reads > 1);
  assert(io->qspi_write(NULL, 0, source, sizeof(source)));
  assert(!busy_until);
  assert(io->qspi_read(NULL, 0, destination, sizeof(destination)));
  assert(memcmp(source, destination, sizeof(source)) == 0);
}

static void program_busy_and_buffer_reuse(void) {
  initialize();
  memset(flash, 0xff, sizeof(flash));
  program_us = 12000u;
  const uint64_t start = wall_us;
  assert(io->qspi_write(NULL, 0, source, sizeof(source)));
  assert(!busy_until && "program returned before flash WIP cleared");
  assert(wall_us - start >= program_us);
  assert(dma_reads == 1 && status_reads > 1);
  memset(source, 0xa7, sizeof(source));
  wall_us += 200000u;
  mock_qspi_poll();
  for (size_t i = 0; i < sizeof(source); ++i) assert(flash[i] == 0x3d);
  assert(dma_reads == 1);
}

static void pending_buffer_timeout(void) {
  initialize();
  memset(flash, 0xff, sizeof(flash));
  busy_until = wall_us + 100000u;
  flash_operation = STATUS;
  const uint64_t start = wall_us;
  assert(!io->qspi_write(NULL, 0, source, sizeof(source)));
  assert(wall_us - start >= 20000u && wall_us - start < 21000u);
  assert(dma_reads == 0);
  memset(source, 0xa7, sizeof(source)); /* caller reuses its returned buffer */
  wall_us += 200000u;
  mock_qspi_poll();
  assert(dma_reads == 0 && "returned buffer was consumed after timeout");
  for (size_t i = 0; i < sizeof(source); ++i) assert(flash[i] == 0xff);
  assert_quiesced();
}

static void deadline_and_error_propagation(void) {
  initialize();
  erase_us = 3100000u;
  const uint64_t start = wall_us;
  assert(!io->qspi_erase_sector(NULL, 0));
  assert(wall_us - start >= 3000000u && wall_us - start < 3001000u);
  assert(busy_until); /* disabling cannot undo an already accepted erase */
  assert_quiesced();

  initialize();
  memset(flash, 0xff, sizeof(flash));
  program_us = 21000u;
  assert(!io->qspi_write(NULL, 0, source, sizeof(source)));
  assert(dma_reads == 1 && busy_until);
  assert_quiesced();

  initialize();
  memset(flash, 0xff, sizeof(flash));
  transfer_us = 15000u;
  program_us = 12000u; /* transfer + WIP must share ONE 20 ms budget */
  const uint64_t combined_start = wall_us;
  assert(!io->qspi_write(NULL, 0, source, sizeof(source)) &&
         "program restarted its deadline after transfer");
  assert(wall_us - combined_start < 21000u);
  assert_quiesced();

  initialize();
  hold_status = true;
  const uint64_t status_start = wall_us;
  assert(!io->qspi_erase_sector(NULL, 0));
  assert(wall_us - status_start < 12000u); /* CINSTR remains bounded at 10 ms */
  assert_quiesced();
}

static void lost_ready_and_read_timeout(void) {
  initialize();
  memset(flash, 0xff, sizeof(flash));
  suppress_write_ready = true;
  assert(!io->qspi_write(NULL, 0, source, sizeof(source)));
  assert(dma_reads == 1);
  assert_quiesced();

  initialize();
  /* A stale READY must not let a new blocked read return success. */
  mock_qspi.EVENTS_READY = 1;
  busy_until = wall_us + 100000u;
  flash_operation = STATUS;
  assert(!io->qspi_read(NULL, 0, destination, sizeof(destination)));
  wall_us += 200000u;
  mock_qspi_poll();
  assert(dma_writes == 0 && "read DMA touched returned destination");
  for (size_t i = 0; i < sizeof(destination); ++i) assert(destination[i] == 0x77);
  assert_quiesced();
}

static void stopped_clock(void) {
  initialize();
  frozen_clock = true;
  hold_ready = true;
  const unsigned start_ticks = ticks;
  assert(!io->qspi_write(NULL, 0, source, sizeof(source)));
  assert(ticks - start_ticks < 1100u);
  assert_quiesced();

  initialize();
  frozen_clock = true; /* READY still arrives: bound the outer WIP loop too */
  erase_us = 10000000u;
  const unsigned poll_ticks = ticks;
  assert(!io->qspi_erase_sector(NULL, 0));
  assert(ticks - poll_ticks < 3000u);
  assert_quiesced();

  reset_model();
  mock_dwt.CTRL = 0;
  frozen_clock = hold_ready = true; /* counter never starts at activation */
  assert(!io->qspi_init(NULL));
  assert(ticks < 1100u);
  assert_quiesced();
}

static void quick_completion_and_wrap(void) {
  initialize();
  erase_us = program_us = 100u;
  assert(io->qspi_erase_sector(NULL, 0));
  mock_dwt.CYCCNT = UINT32_MAX - 6400u;
  assert(io->qspi_write(NULL, 0, source, 4));
  assert(io->qspi_read(NULL, 0, destination, 4));
  assert(memcmp(source, destination, 4) == 0);
  assert(mock_qspi.ENABLE == QSPI_ENABLE_ENABLE_Enabled);
  assert(!disable_calls);

  reset_model();
  sr2 = 0; /* QE setup also uses the real WIP helper */
  program_us = 12000u;
  assert(io->qspi_init(NULL));
  assert(sr2 == 2 && !busy_until);
}

static void bench_watchdog_scope(void) {
  reset_model();
  memset(&mock_wdt, 0, sizeof(mock_wdt));
  mock_wdt.RUNSTATUS = 1;
  mock_wdt.RREN = 0x81;
  hold_ready = true;
  assert(!xiao_ota_boot_bench_reset());
  assert(!mock_wdt.TASKS_START && mock_wdt.RR[0] == 0x6E524635u &&
         mock_wdt.RR[7] == 0x6E524635u && !mock_wdt.RR[1]);
  mock_wdt.RR[0] = mock_wdt.RR[7] = 0;
  assert(!io->qspi_init(NULL));
  assert(!mock_wdt.RR[0] && !mock_wdt.RR[7]);
  memset(&mock_wdt, 0, sizeof(mock_wdt));
}

int main(int argc, char **argv) {
  /* Non-PIE static buffers fit the nRF's 32-bit DMA registers. This
   * models caller reuse without pretending host stack addresses are RAM. */
  assert((uintptr_t)source <= UINT32_MAX);
  assert((uintptr_t)destination <= UINT32_MAX);
  xiao_ota_boot_process();
  assert(io);
  const struct { const char *name; void (*run)(void); } cases[] = {
    {"bench-watchdog", bench_watchdog_scope},
    {"delayed-erase", delayed_erase_then_write},
    {"program-busy", program_busy_and_buffer_reuse},
    {"pending-buffer", pending_buffer_timeout},
    {"deadline", deadline_and_error_propagation},
    {"lost-ready", lost_ready_and_read_timeout},
    {"stopped-clock", stopped_clock},
    {"quick-wrap", quick_completion_and_wrap},
  };
  unsigned ran = 0;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    if (argc == 1 || strcmp(argv[1], cases[i].name) == 0) {
      printf("RUN %s\n", cases[i].name);
      fflush(stdout);
      cases[i].run();
      printf("PASS %s\n", cases[i].name);
      ++ran;
    }
  }
  assert(ran != 0);
  puts("production QSPI adapter behavioral tests passed");
  return 0;
}
