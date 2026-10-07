#include <stdbool.h>
#include <stdint.h>
#include "nrf.h"
#include "pair_abi.h"

static bool lock_region(unsigned region, uint32_t start, uint32_t size) {
  if (NRF_ACL->ACL[region].SIZE == 0) {
    NRF_ACL->ACL[region].ADDR = start;
    NRF_ACL->ACL[region].SIZE = size;
    NRF_ACL->ACL[region].PERM = ACL_ACL_PERM_WRITE_Msk;
    __DSB();
  }
  return NRF_ACL->ACL[region].ADDR == start &&
         NRF_ACL->ACL[region].SIZE == size &&
         NRF_ACL->ACL[region].PERM == ACL_ACL_PERM_WRITE_Msk;
}

/* ACL regions are reset-locked, not persistent MBR-across-reset protection.
 * SDK settings/MBR params and both filesystem regions remain writable. */
bool pair_lock_protection(void) {
  return lock_region(0, PAIR_STAGE_START, PAIR_STAGE_END - PAIR_STAGE_START) &&
         lock_region(1, 0xF4000u, 0xA000u);
}
