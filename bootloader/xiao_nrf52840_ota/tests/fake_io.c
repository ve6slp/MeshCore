#include "fake_io.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "xiao_ota_layout.h"

/* Real NRF_QSPI hardware (hw_qspi_read()/hw_qspi_write() in
 * xiao_ota_boot.c) programs NRF_QSPI->READ.CNT/WRITE.CNT and the
 * SRC/DST address registers directly from the caller's arguments, with
 * no rounding of its own; the peripheral requires both the address and
 * the transfer length to be multiples of 4 bytes. A plain memcpy-backed
 * test double can silently "succeed" on a misaligned transfer that
 * would be hardware-invalid on the real chip -- assert loudly instead,
 * so any production code path that ever issues one (the exact defect
 * class this caught: an auxiliary window read whose canonical wire
 * whose 386-byte canonical wire size is NOT a multiple of 4) fails a
 * native test immediately rather than passing here and only surfacing
 * on real hardware. */
static void assert_qspi_transfer_hardware_aligned(uint32_t address,
                                                  size_t length) {
  assert((address % 4u) == 0u && "QSPI transfer address must be 4-byte aligned");
  assert((length % 4u) == 0u && "QSPI transfer length must be a multiple of 4");
}

static bool fault_matches(fake_io_fault_t *f, fake_io_op_t op,
                          uint32_t address, uint32_t length) {
  if (f->op != op) return false;
  if (address + length <= f->addr_lo || address >= f->addr_hi) return false;
  f->count++;
  return f->after >= 0 && f->count == f->after;
}

/* Fires a crash (longjmp) BEFORE the operation's effect, if configured. */
static void maybe_crash(fake_io_state_t *s, fake_io_op_t op, uint32_t address,
                        uint32_t length) {
  if (fault_matches(&s->crash, op, address, length)) {
    longjmp(s->crash_jump, 1);
  }
}

/* Returns true if a pure I/O failure is configured to fire here (no
 * effect, no crash -- caller must apply nothing and return false). */
static bool maybe_fail(fake_io_state_t *s, fake_io_op_t op, uint32_t address,
                       uint32_t length) {
  return fault_matches(&s->fail, op, address, length);
}

/* Returns true if a torn write is configured to fire here; caller
 * applies only the first s->tear_bytes bytes then returns false. */
static bool maybe_tear(fake_io_state_t *s, fake_io_op_t op, uint32_t address,
                       uint32_t length) {
  return fault_matches(&s->tear, op, address, length);
}

void fake_io_reset(fake_io_state_t *s) {
  memset(s->qspi, 0xFF, sizeof(s->qspi));
  memset(s->internal_flash, 0xFF, sizeof(s->internal_flash));
  s->dfu_requested = false;
  s->device_address = 0;
  s->force_recovery_calls = 0;
  s->watchdog_start_calls = 0;
  s->qspi_init_calls = 0;
  memset(&s->crash, 0, sizeof(s->crash));
  s->crash.after = -1;
  s->crash.addr_lo = 0;
  s->crash.addr_hi = UINT32_MAX;
  memset(&s->fail, 0, sizeof(s->fail));
  s->fail.after = -1;
  s->fail.addr_lo = 0;
  s->fail.addr_hi = UINT32_MAX;
  memset(&s->tear, 0, sizeof(s->tear));
  s->tear.after = -1;
  s->tear.addr_lo = 0;
  s->tear.addr_hi = UINT32_MAX;
  s->tear_bytes = 0;
  s->tear_crash = false;
}

static uint64_t fake_device_address(void *ctx) {
  return ((fake_io_state_t *)ctx)->device_address;
}

static bool fake_explicit_dfu_requested(void *ctx) {
  return ((fake_io_state_t *)ctx)->dfu_requested;
}

static bool fake_qspi_init(void *ctx) {
  fake_io_state_t *s = (fake_io_state_t *)ctx;
  s->qspi_init_calls++;
  if (maybe_fail(s, FAKE_IO_OP_QSPI_INIT, 0, 1)) return false;
  maybe_crash(s, FAKE_IO_OP_QSPI_INIT, 0, 1);
  return true;
}

static bool fake_qspi_read(void *ctx, uint32_t address, void *destination,
                          size_t length) {
  fake_io_state_t *s = (fake_io_state_t *)ctx;
  assert_qspi_transfer_hardware_aligned(address, length);
  if (maybe_fail(s, FAKE_IO_OP_QSPI_READ, address, (uint32_t)length)) {
    return false;
  }
  maybe_crash(s, FAKE_IO_OP_QSPI_READ, address, (uint32_t)length);
  memcpy(destination, s->qspi + address, length);
  return true;
}

static bool fake_qspi_write(void *ctx, uint32_t address, const void *source,
                            size_t length) {
  fake_io_state_t *s = (fake_io_state_t *)ctx;
  size_t i;
  assert_qspi_transfer_hardware_aligned(address, length);
  if (maybe_fail(s, FAKE_IO_OP_QSPI_WRITE, address, (uint32_t)length)) {
    return false;
  }
  maybe_crash(s, FAKE_IO_OP_QSPI_WRITE, address, (uint32_t)length);
  if (maybe_tear(s, FAKE_IO_OP_QSPI_WRITE, address, (uint32_t)length)) {
    size_t applied = s->tear_bytes < length ? s->tear_bytes : length;
    for (i = 0; i < applied; ++i) {
      s->qspi[address + i] &= ((const uint8_t *)source)[i];
    }
    if (s->tear_crash) {
      longjmp(s->crash_jump, 1);
    }
    return false;
  }
  /* Real NOR flash can only clear bits without an erase; AND-in the
   * source so writing over non-erased bytes is faithfully rejected by
   * any subsequent read-back verify, exactly like real hardware. */
  for (i = 0; i < length; ++i) {
    s->qspi[address + i] &= ((const uint8_t *)source)[i];
  }
  return true;
}

static bool fake_qspi_erase_sector(void *ctx, uint32_t address) {
  fake_io_state_t *s = (fake_io_state_t *)ctx;
  if (maybe_fail(s, FAKE_IO_OP_QSPI_ERASE, address, XIAO_OTA_QSPI_SECTOR_SIZE)) {
    return false;
  }
  maybe_crash(s, FAKE_IO_OP_QSPI_ERASE, address, XIAO_OTA_QSPI_SECTOR_SIZE);
  memset(s->qspi + address, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  return true;
}

static bool fake_internal_read(void *ctx, uint32_t address, void *destination,
                               size_t length) {
  fake_io_state_t *s = (fake_io_state_t *)ctx;
  if (maybe_fail(s, FAKE_IO_OP_INTERNAL_READ, address, (uint32_t)length)) {
    return false;
  }
  maybe_crash(s, FAKE_IO_OP_INTERNAL_READ, address, (uint32_t)length);
  memcpy(destination, s->internal_flash + address, length);
  return true;
}

static bool fake_internal_write(void *ctx, uint32_t address,
                                const void *source, size_t length) {
  fake_io_state_t *s = (fake_io_state_t *)ctx;
  size_t i;
  if (maybe_fail(s, FAKE_IO_OP_INTERNAL_WRITE, address, (uint32_t)length)) {
    return false;
  }
  maybe_crash(s, FAKE_IO_OP_INTERNAL_WRITE, address, (uint32_t)length);
  if (maybe_tear(s, FAKE_IO_OP_INTERNAL_WRITE, address, (uint32_t)length)) {
    size_t applied = s->tear_bytes < length ? s->tear_bytes : length;
    for (i = 0; i < applied; ++i) {
      s->internal_flash[address + i] &= ((const uint8_t *)source)[i];
    }
    if (s->tear_crash) {
      longjmp(s->crash_jump, 1);
    }
    return false;
  }
  for (i = 0; i < length; ++i) {
    s->internal_flash[address + i] &= ((const uint8_t *)source)[i];
  }
  return true;
}

static bool fake_internal_erase_page(void *ctx, uint32_t address) {
  fake_io_state_t *s = (fake_io_state_t *)ctx;
  if (maybe_fail(s, FAKE_IO_OP_INTERNAL_ERASE, address,
                XIAO_OTA_QSPI_SECTOR_SIZE)) {
    return false;
  }
  maybe_crash(s, FAKE_IO_OP_INTERNAL_ERASE, address, XIAO_OTA_QSPI_SECTOR_SIZE);
  memset(s->internal_flash + address, 0xFF, XIAO_OTA_QSPI_SECTOR_SIZE);
  return true;
}

/*
 * Plain, fault-free internal-flash accessors used ONLY for test setup/
 * inspection (fake_io_provision_bank0_settings()/
 * fake_io_read_bank0_settings() below) -- never wired into the io_t a
 * boot actually runs against. Mirrors how write_state_direct()/
 * read_state() (test_boot_process.c) already bypass fault injection for
 * QSPI record setup/inspection; this is the same pattern for the
 * settings page.
 */
static bool fake_internal_read_unfaulted(void *ctx, uint32_t address,
                                         void *destination, size_t length) {
  memcpy(destination, ((fake_io_state_t *)ctx)->internal_flash + address,
        length);
  return true;
}

static bool fake_internal_write_unfaulted(void *ctx, uint32_t address,
                                          const void *source, size_t length) {
  fake_io_state_t *s = (fake_io_state_t *)ctx;
  size_t i;
  for (i = 0; i < length; ++i) {
    s->internal_flash[address + i] &= ((const uint8_t *)source)[i];
  }
  return true;
}

static bool fake_internal_erase_page_unfaulted(void *ctx, uint32_t address) {
  memset(((fake_io_state_t *)ctx)->internal_flash + address, 0xFF,
        XIAO_OTA_QSPI_SECTOR_SIZE);
  return true;
}

void fake_io_provision_bank0_settings(fake_io_state_t *s, uint16_t bank_0,
                                      uint16_t bank_0_crc,
                                      uint32_t bank_0_size) {
  xiao_ota_io_t io;
  memset(&io, 0, sizeof(io));
  io.ctx = s;
  io.internal_read = fake_internal_read_unfaulted;
  io.internal_write = fake_internal_write_unfaulted;
  io.internal_erase_page = fake_internal_erase_page_unfaulted;
  /* Setup goes through the SAME production erase/program/verify codec a
   * real settings write uses; only the underlying accessor is unfaulted. */
  (void)xiao_ota_settings_set(&io, bank_0, bank_0_crc, bank_0_size);
}

void fake_io_read_bank0_settings(const fake_io_state_t *s,
                                 xiao_ota_bank0_settings_t *out) {
  xiao_ota_io_t io;
  memset(&io, 0, sizeof(io));
  io.ctx = (void *)s;
  io.internal_read = fake_internal_read_unfaulted;
  memset(out, 0, sizeof(*out));
  (void)xiao_ota_settings_get(&io, out);
}

void fake_io_read_settings_raw(const fake_io_state_t *s, uint8_t out[28]) {
  memcpy(out, s->internal_flash + XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS, 28);
}

void fake_io_write_settings_raw(fake_io_state_t *s, const uint8_t raw[28]) {
  memset(s->internal_flash + XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS, 0xFF,
        XIAO_OTA_QSPI_SECTOR_SIZE);
  memcpy(s->internal_flash + XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS, raw, 28);
}

void fake_io_poison_settings_tail(fake_io_state_t *s, uint32_t offset_in_page,
                                 uint8_t value) {
  s->internal_flash[XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + offset_in_page] =
      value;
}

static void fake_start_trial_watchdog(void *ctx) {
  ((fake_io_state_t *)ctx)->watchdog_start_calls++;
}

static void fake_force_recovery(void *ctx) {
  ((fake_io_state_t *)ctx)->force_recovery_calls++;
}

int fake_io_run_boot(fake_io_state_t *s) {
  xiao_ota_io_t io;
  io.ctx = s;
  io.device_address = fake_device_address;
  io.explicit_dfu_requested = fake_explicit_dfu_requested;
  io.qspi_init = fake_qspi_init;
  io.qspi_read = fake_qspi_read;
  io.qspi_write = fake_qspi_write;
  io.qspi_erase_sector = fake_qspi_erase_sector;
  io.internal_read = fake_internal_read;
  io.internal_write = fake_internal_write;
  io.internal_erase_page = fake_internal_erase_page;
  io.start_trial_watchdog = fake_start_trial_watchdog;
  io.force_recovery = fake_force_recovery;

  if (setjmp(s->crash_jump) != 0) return 1;
  xiao_ota_boot_process_io(&io);
  return 0;
}

/* Plain, fixed-layout dump: qspi[], then internal_flash[], then the
 * 8-byte device_address -- deliberately NOT the whole fake_io_state_t
 * (which also carries fault-injection bookkeeping, counters, and a
 * jmp_buf that have no cross-process/cross-binary meaning and would
 * make the file format depend on this struct's unrelated layout). */
bool fake_io_dump_to_file(const fake_io_state_t *s, const char *path) {
  FILE *f = fopen(path, "wb");
  if (!f) return false;
  bool ok = fwrite(s->qspi, 1, sizeof(s->qspi), f) == sizeof(s->qspi) &&
            fwrite(s->internal_flash, 1, sizeof(s->internal_flash), f) ==
                sizeof(s->internal_flash) &&
            fwrite(&s->device_address, 1, sizeof(s->device_address), f) ==
                sizeof(s->device_address);
  if (fclose(f) != 0) ok = false;
  return ok;
}

bool fake_io_load_from_file(fake_io_state_t *s, const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return false;
  fake_io_reset(s);
  bool ok = fread(s->qspi, 1, sizeof(s->qspi), f) == sizeof(s->qspi) &&
            fread(s->internal_flash, 1, sizeof(s->internal_flash), f) ==
                sizeof(s->internal_flash) &&
            fread(&s->device_address, 1, sizeof(s->device_address), f) ==
                sizeof(s->device_address);
  /* A genuine EOF right here (file has no trailing garbage) must not be
   * mistaken for a short/failed read above. */
  int extra = ok ? fgetc(f) : 0;
  if (ok && extra != EOF) ok = false;
  fclose(f);
  return ok;
}
