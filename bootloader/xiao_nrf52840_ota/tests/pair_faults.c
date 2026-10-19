#include "pair_faults.h"
#include "xiao_ota_boot_io.h"
#include <assert.h>
#include <string.h>

static const xiao_ota_io_t *hardware;
static uint8_t *qspi;
static pair_fault_event_t events[2048], repeated;
static unsigned count, target, hits, remaining;
static size_t prefix;
static pair_fault_effect_t effect;

void pair_fault_begin(uint8_t *flash, unsigned index, pair_fault_effect_t mode,
                      size_t bytes, unsigned repetitions) {
  qspi = flash;
  target = index;
  effect = mode;
  prefix = bytes;
  remaining = repetitions;
  count = hits = 0;
}
void pair_fault_end(void) { qspi = NULL; }
unsigned pair_fault_count(void) { return count; }
unsigned pair_fault_hits(void) { return hits; }
pair_fault_event_t pair_fault_event(unsigned index) {
  assert(index < count && index < sizeof(events) / sizeof(events[0]));
  return events[index];
}

static bool mutation(pair_fault_op_t op, uint32_t address, const void *source,
                     size_t length) {
  pair_fault_event_t event = {op, address, length};
  assert(count < sizeof(events) / sizeof(events[0]));
  events[count] = event;
  bool inject = remaining && effect != PAIR_FAULT_NONE &&
      ((!hits && count == target) ||
       (hits && op == repeated.op && address == repeated.address));
  ++count;
  if (inject) {
    repeated = event;
    ++hits;
    --remaining;
    if (effect == PAIR_FAULT_CUT_BEFORE) pair_fault_power_cut();
    if (effect == PAIR_FAULT_ERROR) return false;
    if (effect == PAIR_FAULT_PARTIAL_ERROR || effect == PAIR_FAULT_CUT_PARTIAL) {
      size_t applied = prefix < length ? prefix : length;
      uint8_t *destination = op == PAIR_QSPI_WRITE || op == PAIR_QSPI_ERASE
          ? qspi + address : (uint8_t *)(uintptr_t)address;
      for (size_t i = 0; i < applied; ++i) {
        if (source) destination[i] &= ((const uint8_t *)source)[i] |
            (prefix == SIZE_MAX ? 0xAA : 0);
        else destination[i] |= prefix == SIZE_MAX ? 0x55 : 255;
      }
      if (effect == PAIR_FAULT_CUT_PARTIAL) pair_fault_power_cut();
      return false;
    }
  }
  bool ok;
  switch (op) {
    case PAIR_QSPI_WRITE:
      ok = hardware->qspi_write(hardware->ctx, address, source, length);
      break;
    case PAIR_QSPI_ERASE:
      ok = hardware->qspi_erase_sector(hardware->ctx, address);
      break;
    case PAIR_INTERNAL_WRITE:
      for (size_t i = 0; i < length; ++i)
        assert((((const uint8_t *)(uintptr_t)address)[i] &
                ((const uint8_t *)source)[i]) == ((const uint8_t *)source)[i]);
      ok = hardware->internal_write(hardware->ctx, address, source, length);
      break;
    case PAIR_INTERNAL_ERASE:
      ok = hardware->internal_erase_page(hardware->ctx, address);
      break;
    default:
      assert(!"unknown mutation");
      return false;
  }
  if (inject && effect == PAIR_FAULT_CUT_AFTER) {
    assert(ok);
    pair_fault_power_cut();
  }
  return ok;
}

static bool qspi_write(void *ctx, uint32_t address, const void *source, size_t length) {
  (void)ctx;
  return mutation(PAIR_QSPI_WRITE, address, source, length);
}
static bool qspi_erase(void *ctx, uint32_t address) {
  (void)ctx;
  return mutation(PAIR_QSPI_ERASE, address, NULL, 4096);
}
static bool internal_write(void *ctx, uint32_t address, const void *source, size_t length) {
  (void)ctx;
  return mutation(PAIR_INTERNAL_WRITE, address, source, length);
}
static bool internal_erase(void *ctx, uint32_t address) {
  (void)ctx;
  return mutation(PAIR_INTERNAL_ERASE, address, NULL, 4096);
}

void __real_xiao_ota_boot_process_io(const xiao_ota_io_t *);
void __wrap_xiao_ota_boot_process_io(const xiao_ota_io_t *io) {
  if (!qspi) {
    __real_xiao_ota_boot_process_io(io);
    return;
  }
  hardware = io;
  xiao_ota_io_t faulted = *io;
  faulted.qspi_write = qspi_write;
  faulted.qspi_erase_sector = qspi_erase;
  faulted.internal_write = internal_write;
  faulted.internal_erase_page = internal_erase;
  __real_xiao_ota_boot_process_io(&faulted);
}
