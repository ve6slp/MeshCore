#pragma once
#include "nrf.h"

/* The host cannot execute the HAL's physical anomaly-122 register write.
 * It models ENABLE's effect; the ARM build compiles the real pinned HAL. */
void nrf_qspi_disable(NRF_QSPI_Type *qspi);
