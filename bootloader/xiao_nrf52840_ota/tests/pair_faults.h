#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  PAIR_QSPI_WRITE, PAIR_QSPI_ERASE, PAIR_INTERNAL_WRITE, PAIR_INTERNAL_ERASE
} pair_fault_op_t;

typedef enum {
  PAIR_FAULT_NONE, PAIR_FAULT_ERROR, PAIR_FAULT_PARTIAL_ERROR,
  PAIR_FAULT_CUT_BEFORE, PAIR_FAULT_CUT_PARTIAL, PAIR_FAULT_CUT_AFTER
} pair_fault_effect_t;

typedef struct {
  pair_fault_op_t op;
  uint32_t address;
  size_t length;
} pair_fault_event_t;

void pair_fault_begin(uint8_t *flash, unsigned target, pair_fault_effect_t effect,
                      size_t prefix, unsigned repetitions);
void pair_fault_end(void);
unsigned pair_fault_count(void);
unsigned pair_fault_hits(void);
pair_fault_event_t pair_fault_event(unsigned index);
void pair_fault_power_cut(void);
