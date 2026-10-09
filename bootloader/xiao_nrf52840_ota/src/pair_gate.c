#include "pair_abi.h"
#include <stddef.h>

bool pair_header_valid(const pair_header_t *h, const pair_expected_t *e) {
  return h->magic == PAIR_MAGIC && h->abi == PAIR_ABI_VERSION &&
         h->header_bytes == sizeof(*h) && h->board == e->board &&
         h->role == e->role && h->extent == e->extent &&
         h->extent >= sizeof(*h) && h->extent <= PAIR_STAGE_END - PAIR_STAGE_START &&
         h->entry == e->entry && (h->entry & 1u) &&
         (h->entry & ~1u) >= PAIR_STAGE_START + sizeof(*h) &&
         (h->entry & ~1u) < PAIR_STAGE_START + h->extent &&
         h->ram_start == PAIR_RAM_START && h->ram_end == PAIR_RAM_END;
}

bool pair_explicit_escape(uint32_t gpregret, bool pin, uint32_t marker,
                          bool dfu_button) {
  return gpregret == 0xB1 || gpregret == 0xA8 || gpregret == 0x4E ||
         gpregret == 0x57 || (pin && marker == 0x5A1AD5) || dfu_button;
}

bool pair_app_gate(bool service_intact, bool bank_valid, bool vendor_valid,
                   bool pending) {
  return service_intact && bank_valid && vendor_valid && !pending;
}

bool pair_validate_internal(const pair_expected_t *expected) {
  const pair_header_t *header = (const pair_header_t *)(uintptr_t)PAIR_STAGE_START;
  if (!pair_header_valid(header, expected)) return false;
  uint32_t crc = UINT32_MAX;
  const volatile uint8_t *bytes = (const volatile uint8_t *)(uintptr_t)PAIR_STAGE_START;
  for (uint32_t i = 0; i < expected->extent; ++i) {
    crc ^= bytes[i];
    for (unsigned bit = 0; bit < 8; ++bit)
      crc = (crc >> 1) ^ (UINT32_C(0xEDB88320) & (0u - (crc & 1u)));
  }
  return (crc ^ UINT32_MAX) == expected->crc32;
}

pair_result_t pair_call(const pair_expected_t *expected) {
  if (!pair_validate_internal(expected)) return PAIR_RECOVERY;
  const pair_request_t request = {
      PAIR_ABI_VERSION, sizeof(request), expected->board, expected->role};
  const pair_entry_t entry = (pair_entry_t)(uintptr_t)expected->entry;
  pair_result_t result = entry(&request);
  return result == PAIR_APP_INTACT ? result : PAIR_RECOVERY;
}

bool pair_bench_reset(const pair_expected_t *expected) {
  if (!pair_validate_internal(expected)) return false;
  const struct {
    pair_request_t header;
    uint32_t operation;
  } request = {{PAIR_ABI_VERSION, sizeof(request), expected->board, expected->role},
               PAIR_BENCH_REQUEST};
  const pair_entry_t entry = (pair_entry_t)(uintptr_t)expected->entry;
  return entry(&request.header) == PAIR_BENCH_READY;
}
