#pragma once
#include <stdint.h>

/* Pinned nrfx_glue.h uses the finite instruction-loop delay, not DWT. */
#define NRFX_DELAY_DWT_BASED 0
void mock_delay_us(uint32_t number_of_us);
#define NRFX_DELAY_US(number_of_us) mock_delay_us(number_of_us)
