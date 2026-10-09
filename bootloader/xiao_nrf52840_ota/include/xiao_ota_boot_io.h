#pragma once

/*
 * Hardware-independent I/O contract for the OTA transaction processor.
 *
 * xiao_ota_boot_process_io() (xiao_ota_boot.c) implements the ENTIRE
 * transaction decision sequence -- command acceptance, backup, install,
 * trial-boot confirmation, rollback, recovery -- purely in terms of the
 * callbacks below. The production entry point xiao_ota_boot_process()
 * builds a real hardware xiao_ota_io_t (QSPI/NVMC/WDT/FICR/GPREGRET thin
 * adapters, unchanged register-level code) and calls
 * xiao_ota_boot_process_io() with it. A native host test builds a FAKE
 * xiao_ota_io_t backed by plain in-memory arrays and calls the exact SAME
 * xiao_ota_boot_process_io() -- so a test failure or pass reflects the
 * real decision sequence, not a parallel reimplementation of it.
 *
 * Every callback takes the same `ctx` pointer the io_t was constructed
 * with (unused/NULL on the real hardware adapter, a fake in-memory-model
 * struct in tests).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct xiao_ota_io;
bool xiao_ota_usb_bench_prepare(const struct xiao_ota_io *io, uint32_t extent);
bool xiao_ota_usb_bench_publish(const struct xiao_ota_io *io, uint32_t extent);
bool xiao_ota_usb_bench_intact(const struct xiao_ota_io *io);
bool xiao_ota_usb_bench_reset(const struct xiao_ota_io *io, bool authorized);

/*
 * Bank-0 (currently-running application) settings this processor reads
 * and writes. Deliberately just these three fields -- everything else in
 * the real bootloader_settings_t (Nordic SDK struct) is preserved as-is
 * by the hardware adapter's read-modify-write and is never inspected by
 * the decision logic.
 */
typedef struct {
  uint16_t bank_0;
  uint16_t bank_0_crc;
  uint32_t bank_0_size;
} xiao_ota_bank0_settings_t;

/*
 * Value of bootloader_settings_t.bank_0 (Nordic SDK bootloader_types.h,
 * enum bootloader_bank_code_t) meaning "bank 0 holds a valid app". Mirrored
 * here as a plain constant (rather than including the SDK header) so this
 * portable processor has no Nordic SDK dependency and can be linked into a
 * native host test build.
 */
#define XIAO_OTA_BANK_VALID_APP 0x01u
#define XIAO_OTA_BANK_INVALID_APP 0x00FFu

typedef struct xiao_ota_io {
  void *ctx;

  /* True if this device's FICR unique ID, packed the same way as
   * command_policy_valid()'s device-address check. */
  uint64_t (*device_address)(void *ctx);

  /* True if a UF2/CDC recovery request is already latched (GPREGRET) --
   * a persistent OTA transaction must never intercept it. */
  bool (*explicit_dfu_requested)(void *ctx);

  /* One-time QSPI peripheral bring-up (pin/interface config, peripheral
   * enable/activate, and confirming the external flash's own Quad Enable
   * status rather than assuming a prior boot left it set). Returns false
   * on any bounded timeout or an unconfirmable/un-settable Quad Enable
   * bit; a no-op returning true for the fake. */
  bool (*qspi_init)(void *ctx);

  /*
   * All QSPI/internal-flash callbacks below return false on any bounded
   * hardware failure (busy-wait timeout, peripheral error status, or a
   * fake-model-injected fault) instead of hanging or silently succeeding.
   * The processor treats false exactly like a verify-mismatch: it must
   * never advance a phase, write a floor, or trust a hash computed from a
   * read that returned false.
   */
  bool (*qspi_read)(void *ctx, uint32_t address, void *destination, size_t length);
  bool (*qspi_write)(void *ctx, uint32_t address, const void *source, size_t length);
  bool (*qspi_erase_sector)(void *ctx, uint32_t address);

  /* Internal code-flash access. Reads may go through a CPU-visible
   * pointer on real hardware; the callback form lets the fake model an
   * arbitrary in-memory buffer instead of a literal process address. */
  bool (*internal_read)(void *ctx, uint32_t address, void *destination, size_t length);
  bool (*internal_write)(void *ctx, uint32_t address, const void *source, size_t length);
  bool (*internal_erase_page)(void *ctx, uint32_t address);

  void (*start_trial_watchdog)(void *ctx);

  /*
   * Trigger an unconditional recovery boot (UF2/CDC DFU). On real
   * hardware this resets the MCU and never returns. The processor still
   * `return`s immediately after invoking it (harmless in production,
   * since the reset already happened; required so a fake can observe the
   * call and let the test driver decide what "next boot" means).
   */
  void (*force_recovery)(void *ctx);
} xiao_ota_io_t;

void xiao_ota_boot_process_io(const xiao_ota_io_t *io);

/* Ordinary APP execution only, never admission, confirmation or floor trust.
 * CRC0 is optional here only under this loader's durable invalid-before-erase
 * and VALID-last contract. Commissioning must exclude legacy active copies. */
bool xiao_ota_app_is_intact(const xiao_ota_io_t *io);

/*
 * Shared, hardware-independent bank-0 settings codec. Both the real
 * hardware adapter (xiao_ota_boot.c) and native host tests (fake_io.c)
 * go through these -- there is exactly one read-modify-write erase/
 * program/verify sequence, expressed purely in terms of the `io_t`
 * internal_read/internal_write/internal_erase_page callbacks above, so a
 * fault injected on those callbacks (crash/fail/tear, address-range
 * gated) exercises the SAME settings-page durability behaviour a real
 * torn/interrupted internal-flash write would produce, instead of a
 * separate hand-maintained settings fault model.
 *
 * xiao_ota_settings_set() preserves every byte of the real Nordic
 * bootloader_settings_t page OTHER than bank_0/bank_0_crc/bank_0_size
 * (bank_1, sd/bl/app image sizes, sd_image_start) by reading the current
 * full raw page first and only overlaying those three fields, exactly
 * like the on-device SDK settings API's own read-modify-write contract.
 */
bool xiao_ota_settings_get(const xiao_ota_io_t *io, xiao_ota_bank0_settings_t *out);
bool xiao_ota_settings_set(const xiao_ota_io_t *io, uint16_t bank_0,
                           uint16_t bank_0_crc, uint32_t bank_0_size);

const xiao_ota_io_t *xiao_ota_boot_internal_io(void);
bool xiao_ota_vendor_prepare(const xiao_ota_io_t *io, uint32_t extent);
bool xiao_ota_vendor_publish(const xiao_ota_io_t *io, uint32_t extent);
bool xiao_ota_vendor_settings_write(const xiao_ota_io_t *io, const uint8_t raw[28]);
bool xiao_ota_vendor_pending_settings_write(const xiao_ota_io_t *io, const uint8_t raw[28]);
bool xiao_ota_stage2_recovery_requested(void);
