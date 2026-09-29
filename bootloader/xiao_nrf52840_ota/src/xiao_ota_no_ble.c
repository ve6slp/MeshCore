#include <stdint.h>

#include "nrf_error.h"

uint32_t proc_soc(void) {
  return NRF_ERROR_NOT_FOUND;
}

uint32_t dfu_transport_ble_close(void) {
  return NRF_SUCCESS;
}
