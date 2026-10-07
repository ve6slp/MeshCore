/* Reuse the device model, not the production wait algorithm. The qualified
 * F1 test/source snapshot remains retained separately on disk. */
#define main qspi_completion_main
#include "test_qspi_adapter.c"
#undef main

static void deep_powerdown_startup(void) {
  reset_model();
  deep_power_down = true;
  clock_tick_us = status_us = 1u;
  tick_limit = 4000000u; /* allow the full 3 s budget at 1 us sampling */
  assert(io->qspi_init(NULL) && "sleeping flash was not woken before identification");
  assert(wake_commands == 1 && !deep_power_down);
  assert(early_commands == 0 && "command issued before tRES elapsed");
  assert(jedec_reads == 1);
  assert(!busy_until);
}

static void mid_erase_startup(void) {
  for (unsigned activation_waits = 0; activation_waits < 2; ++activation_waits) {
    reset_model();
    busy_until = wall_us + 200000u;
    flash_operation = ERASE;
    delay_activation_until_idle = activation_waits != 0;
    assert(io->qspi_init(NULL) && "startup identified flash before its erase completed");
    assert(wall_us >= 200000u && !busy_until);
    assert(wake_commands == 1 && jedec_reads == 1);
    assert(status_reads >= 1);
    assert(mock_qspi.ENABLE == QSPI_ENABLE_ENABLE_Enabled);
  }
}

static void startup_deadline(void) {
  reset_model();
  busy_until = wall_us + 3100000u;
  flash_operation = ERASE;
  assert(!io->qspi_init(NULL));
  assert(jedec_reads == 0 && "identity command reached a still-busy flash");
  assert(wall_us >= 3000000u && wall_us < 3001000u);
  assert_quiesced();

  reset_model();
  deep_power_down = ignore_wake = true;
  assert(!io->qspi_init(NULL));
  assert(jedec_reads == 0 && deep_power_down);
  assert(wall_us >= 3000000u && wall_us < 3001000u);
  assert_quiesced();
}

static void wake_failure_and_clock(void) {
  reset_model();
  deep_power_down = hold_status = true;
  assert(!io->qspi_init(NULL));
  assert(jedec_reads == 0 && wall_us < 12000u);
  assert_quiesced();

  reset_model();
  deep_power_down = hold_status = frozen_clock = true;
  assert(!io->qspi_init(NULL));
  assert(jedec_reads == 0 && ticks < 2200u);
  assert_quiesced();
}

int main(int argc, char **argv) {
  assert((uintptr_t)source <= UINT32_MAX);
  assert((uintptr_t)destination <= UINT32_MAX);
  xiao_ota_boot_process();
  assert(io);
  const struct { const char *name; void (*run)(void); } cases[] = {
    {"deep-powerdown", deep_powerdown_startup},
    {"mid-erase", mid_erase_startup},
    {"startup-deadline", startup_deadline},
    {"wake-error-clock", wake_failure_and_clock},
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
  assert(ran);
  puts("production QSPI startup behavioral tests passed");
  return 0;
}
