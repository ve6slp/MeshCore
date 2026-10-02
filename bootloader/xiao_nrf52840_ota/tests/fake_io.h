#pragma once

/*
 * In-memory fake xiao_ota_io_t backing for native host tests. Models
 * QSPI flash and internal code flash as plain byte arrays (initialised
 * erased/0xFF, exactly like real NOR/internal flash) -- there is no
 * register, DMA, or reset here. Bank-0 settings are NOT modelled as a
 * separate scalar struct: they live at their real internal-flash address
 * (XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS) inside the SAME internal_flash
 * byte array, read/written through the SAME production settings codec
 * (xiao_ota_settings_get()/xiao_ota_settings_set(), xiao_ota_boot_io.h)
 * every real write uses -- so a fault injected on internal_read/
 * internal_write/internal_erase_page at that address exercises a
 * genuine torn/interrupted settings-page write, not a hand-modelled
 * shortcut. Tests call xiao_ota_boot_process_io() (the SAME function the
 * real hardware entry point calls) against this fake, so a test
 * exercises the literal production decision sequence, not a
 * hand-maintained parallel copy.
 *
 * Every record type (command/state/confirm/floor, A and B) lives in its
 * own dedicated 4KiB QSPI sector (see xiao_ota_layout.h), so an
 * address-range-gated fault lets a test target an exact record boundary
 * (e.g. "the floor commit-marker write", or "the state body write")
 * rather than only an N-th call of an operation kind globally. The same
 * addressing applies to the settings page.
 */

#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "xiao_ota_boot_io.h"

#define FAKE_IO_QSPI_SIZE     (2u * 1024u * 1024u)
#define FAKE_IO_INTERNAL_SIZE (1024u * 1024u)

/* Which callback kind a fault-injection point counts against. */
typedef enum {
  FAKE_IO_OP_NONE = 0,
  FAKE_IO_OP_QSPI_INIT,
  FAKE_IO_OP_QSPI_READ,
  FAKE_IO_OP_QSPI_WRITE,
  FAKE_IO_OP_QSPI_ERASE,
  FAKE_IO_OP_INTERNAL_READ,
  FAKE_IO_OP_INTERNAL_WRITE,
  FAKE_IO_OP_INTERNAL_ERASE,
} fake_io_op_t;

/*
 * One fault-injection rule: the `after`'th call of `op` whose target
 * address range overlaps [addr_lo, addr_hi] fires. addr_lo=0,
 * addr_hi=UINT32_MAX (the default after fake_io_reset()) matches any
 * address, i.e. a plain global op-count cut exactly like before.
 */
typedef struct {
  fake_io_op_t op;
  int after;
  int count;
  uint32_t addr_lo;
  uint32_t addr_hi;
} fake_io_fault_t;

typedef struct {
  uint8_t qspi[FAKE_IO_QSPI_SIZE];
  uint8_t internal_flash[FAKE_IO_INTERNAL_SIZE];
  bool dfu_requested;
  uint64_t device_address;
  int force_recovery_calls;
  int watchdog_start_calls;
  int qspi_init_calls;

  /*
   * Power-loss fault injection: the matching call aborts the in-progress
   * xiao_ota_boot_process_io() call via longjmp BEFORE performing that
   * operation (i.e. that write/erase never took effect), simulating
   * power being cut mid-operation while the device itself resets.
   */
  fake_io_fault_t crash;
  jmp_buf crash_jump;

  /*
   * Pure I/O failure injection: the matching call returns false WITHOUT
   * performing the operation and WITHOUT crashing/resetting the "device"
   * -- e.g. a transient QSPI NACK/timeout the firmware must detect and
   * handle in the same boot, not a power loss.
   */
  fake_io_fault_t fail;

  /*
   * Torn-write injection: the matching write call applies only the
   * first `tear_bytes` of the payload (rest of the destination is left
   * exactly as it was), then returns false -- simulating a write that
   * was interrupted after partially landing on the flash page/sector,
   * distinct from both a clean failure (fail, no effect) and a full
   * power-loss crash (aborts before any effect).
   *
   * When `tear_crash` is also set, the partial apply is followed by an
   * actual longjmp abort (like `crash`) instead of a graceful `false`
   * return -- modelling a genuine power-loss cut occurring PARTWAY
   * through a physical program word, not the caller gracefully
   * detecting a write failure and reacting within the same boot call.
   * The very next `fake_io_run_boot()` call after such a cut is a real,
   * separate reboot: it starts with fresh processor RAM (only the
   * persisted qspi[]/internal_flash[] arrays survive), so it exercises
   * genuine cross-reboot resume, not same-call fallback handling.
   */
  fake_io_fault_t tear;
  size_t tear_bytes;
  bool tear_crash;
} fake_io_state_t;

void fake_io_reset(fake_io_state_t *s);

/*
 * Test-only bank-0 settings setup/inspection helpers. Both go through
 * the SAME production settings codec (xiao_ota_settings_set()/
 * xiao_ota_settings_get(), xiao_ota_boot_io.h) every real read/write
 * uses, via a plain unfaulted internal-flash accessor -- so "provision a
 * valid running app" and "what does the durable settings page say now"
 * are never a hand-maintained parallel model of that page, only a
 * deliberately fault-free path to it (fault injection is configured by
 * the test AFTER provisioning, and inspection normally happens AFTER
 * fake_io_run_boot() returns, so bypassing fault-injection bookkeeping
 * here cannot mask a fault that mattered during the boot itself).
 */
void fake_io_provision_bank0_settings(fake_io_state_t *s, uint16_t bank_0,
                                      uint16_t bank_0_crc,
                                      uint32_t bank_0_size);
void fake_io_read_bank0_settings(const fake_io_state_t *s,
                                 xiao_ota_bank0_settings_t *out);

/*
 * Raw whole-page (28-byte) settings accessors -- unlike the bank-0-only
 * helpers above, these expose every field (including bank_1, sd_image_size,
 * bl_image_size and app_image_size, which xiao_ota_bank0_settings_t does not
 * carry) so tests can prove a rollback restore is byte-for-byte
 * identical, not merely bank-0-identical. fake_io_write_settings_raw()
 * bypasses the production codec entirely (a direct memcpy, like
 * write_state_direct() for QSPI records) so a test can plant arbitrary
 * ancillary-field content distinct from anything the codec itself would
 * ever produce.
 */
void fake_io_read_settings_raw(const fake_io_state_t *s, uint8_t out[28]);
void fake_io_write_settings_raw(fake_io_state_t *s, const uint8_t raw[28]);

/*
 * Directly pokes one byte inside the settings page's normally-unused
 * tail (beyond the real 28-byte bootloader_settings_t) to simulate
 * unexpected/foreign data living there -- exercising the settings-page
 * tail-blank safety check that must refuse to erase over it.
 * `offset_in_page` is relative to the settings page base and must be
 * >= 28 (the raw record size) to land in the tail region under test.
 */
void fake_io_poison_settings_tail(fake_io_state_t *s, uint32_t offset_in_page,
                                 uint8_t value);

/*
 * Runs xiao_ota_boot_process_io() once against `s` (one simulated boot).
 * Returns 0 if it ran to normal completion/return, or 1 if the
 * configured crash-injection point fired first (s->qspi/
 * s->internal_flash reflect exactly what was durable at the moment of
 * the simulated power loss).
 */
int fake_io_run_boot(fake_io_state_t *s);

/* Allows literal processor tests to wrap reads without duplicating this
 * flash/fault model or changing any persisted device fields. */
xiao_ota_io_t fake_io_interface(fake_io_state_t *s);

/*
 * Durably serialises/restores exactly the bytes a real device's power-
 * cycle (or loader-only reflash) would retain -- the simulated QSPI and
 * internal-flash images and the device's own physical identity
 * (device_address/hw_uid) -- to/from a plain file. This is the ONLY
 * mechanism by which two genuinely, separately compiled test binaries
 * (one built with -DXIAO_OTA_COMPILED_ROLE_ID=0, the other with =1, each
 * its own `make test-xiao-ota-boot-process XIAO_OTA_ROLE_ID=<n>`
 * invocation and therefore its own fresh OS process/RAM) can hand off a
 * genuinely-reached device state across a real cold restart: the
 * compiled role itself is a per-binary constant and cannot be flipped
 * in-process, so this is what makes the cold two-role swap scenario
 * literal rather than simulated. Returns false on any I/O failure;
 * never partially writes/reads (an incomplete file is a read failure).
 */
bool fake_io_dump_to_file(const fake_io_state_t *s, const char *path);
bool fake_io_load_from_file(fake_io_state_t *s, const char *path);
