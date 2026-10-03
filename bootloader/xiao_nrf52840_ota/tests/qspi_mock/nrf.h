#pragma once

#include <stdint.h>
#include "nrf52840_bitfields.h"

/* Only QSPI and DWT have behavior. The other adapters are compiled but
 * never invoked. Nordic bitfields come from the pinned SDK, not a copy. */
typedef struct {
  volatile uint32_t TASKS_ACTIVATE, TASKS_READSTART, TASKS_WRITESTART;
  volatile uint32_t TASKS_ERASESTART, TASKS_DEACTIVATE;
  volatile uint32_t EVENTS_READY, INTENCLR, ENABLE;
  struct { volatile uint32_t SCK, CSN, IO0, IO1, IO2, IO3; } PSEL;
  volatile uint32_t IFCONFIG0, IFCONFIG1, CINSTRCONF, CINSTRDAT0;
  struct { volatile uint32_t SRC, DST, CNT; } READ, WRITE;
  struct { volatile uint32_t PTR, LEN; } ERASE;
} NRF_QSPI_Type;

typedef struct { volatile uint32_t CTRL, CYCCNT; } mock_dwt_t;
typedef struct { volatile uint32_t DEMCR; } mock_coredebug_t;
typedef struct { volatile uint32_t READY, CONFIG, ERASEPAGE; } mock_nvmc_t;
typedef struct {
  volatile uint32_t CONFIG, CRV, RREN, TASKS_START, RR[1];
} mock_wdt_t;
typedef struct { volatile uint32_t GPREGRET; } mock_power_t;
typedef struct { volatile uint32_t DEVICEID[2]; } mock_ficr_t;

extern NRF_QSPI_Type mock_qspi;
extern mock_dwt_t mock_dwt;
extern mock_coredebug_t mock_coredebug;
extern mock_nvmc_t mock_nvmc;
extern mock_wdt_t mock_wdt;
extern mock_power_t mock_power;
extern mock_ficr_t mock_ficr;

void mock_qspi_poll(void);
void mock_clock_tick(void);
void mock_barrier(void);
void NVIC_SystemReset(void);

#define NRF_QSPI (mock_qspi_poll(), &mock_qspi)
#define DWT (mock_clock_tick(), &mock_dwt)
#define CoreDebug (&mock_coredebug)
#define NRF_NVMC (&mock_nvmc)
#define NRF_WDT (&mock_wdt)
#define NRF_POWER (&mock_power)
#define NRF_FICR (&mock_ficr)
#define CoreDebug_DEMCR_TRCENA_Msk (1u << 24)
#define DWT_CTRL_CYCCNTENA_Msk (1u << 0)
#define __DSB() mock_barrier()
