#pragma once
#include <stdbool.h>
bool xiao_ota_boot_bench_reset(void);

/* Called after board/bootloader initialization and before normal DFU selection. */
void xiao_ota_boot_process(void);
