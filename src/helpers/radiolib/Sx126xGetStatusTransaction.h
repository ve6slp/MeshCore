#pragma once

#include <stdint.h>

/**
 * \brief  MODULE-TYPE-AGNOSTIC implementation of the scoped "status
 *         width temporarily forced to 0" GET_STATUS transaction trick.
 *
 * RadioLib's own SX126x::getStatus() calls
 * `mod->SPIreadStream(RADIOLIB_SX126X_CMD_GET_STATUS, &data, 0)` --
 * numBytes==0 -- and Module::SPItransferStream() gates BOTH its real-
 * status parsing (`numBytes > 0`) AND its data-copy-out
 * (`memcpy(dataIn, ..., numBytes)`) on that same numBytes, so with
 * numBytes==0 `data` is structurally NEVER written to and the
 * transaction's status is never parsed either -- base getStatus()
 * cannot provide real chip-mode evidence at all in this vendored
 * version.
 *
 * This performs the IDENTICAL physical transaction (same GET_STATUS
 * command byte, same bytes on the wire: `[cmd, NOP]`, buffLen==2) but
 * asks for the status byte as an ordinary 1-byte DATA payload instead:
 * the module's configured STATUS bit-width (index
 * RADIOLIB_MODULE_SPI_WIDTH_STATUS == 2, see Module.h) is temporarily
 * zeroed for the duration of this single, synchronous call only -- so
 * the transfer's automatic status-byte-count contribution drops out and
 * cmdLen(1)+numBytes(1) lines up exactly on the real status byte, at the
 * SAME wire position SX126x::SPIparseStatus()/`statusPos==1` already
 * expect -- then UNCONDITIONALLY restored on every return path,
 * including a genuinely failed transaction, before this function
 * returns. The module/SPI config is shared, single-threaded main-loop
 * state (this firmware never calls into the radio driver from an ISR);
 * the mutation window is bounded to this single call's owning thread:
 * this firmware's radio driver is only ever invoked from the single-
 * threaded main loop, serialized, never re-entered, and never called
 * from an ISR -- so no OTHER caller can begin a SECOND, concurrent
 * SPI transaction while this one is in flight, even though the
 * underlying HAL may internally spin/yield (e.g. busy-pin polling)
 * while waiting for this exact transaction to complete -- so no other
 * SPI caller can ever observe the transiently-zeroed width.
 *
 * Templated purely on the module/bit-width types (rather than depending
 * on RadioLib's `Module`/`Module::BitWidth_t` directly) so this EXACT
 * transaction logic -- not a second, divergent reimplementation of it --
 * can be exercised by a native host unit test against a plain
 * FakeModule double (see test_lora_ota_storage.cpp's
 * Sx126xGetStatusTransactionTest), proving the real 2-byte wire buffer
 * offset and the unconditional width restore, WITHOUT requiring RadioLib
 * or Arduino headers. CustomSX1262::getStatusChecked() is the only
 * thing that instantiates this against the real RadioLib `Module` type
 * (verified by full MCU compilation); this header is what makes the
 * transaction logic itself independently, genuinely host-testable.
 *
 * \tparam ModuleT     the module type (real RadioLib `Module`, or a
 *                     native `FakeModule` double with the same
 *                     `spiConfig.widths[]`/`SPIreadStream()` shape).
 * \tparam BitWidthT   the bit-width enum/type used by `ModuleT::spiConfig.widths[]`.
 * \param  mod              the module instance (real or fake).
 * \param  get_status_cmd   the real GET_STATUS command byte/opcode.
 * \param  out_status       OUT - the real, decoded status byte; ONLY
 *                          meaningful when the returned status indicates
 *                          success (caller-defined "none" sentinel).
 * \param  bits_zero        the module's own "zero-width" enum value
 *                          (e.g. `Module::BITS_0`), passed in rather
 *                          than hard-coded so this template has no
 *                          RadioLib dependency at all.
 * \returns  the real, unmodified SPI transaction status from
 *           `mod->SPIreadStream()`.
*/
template <typename ModuleT, typename BitWidthT>
inline int16_t performSx126xGetStatusTransaction(ModuleT* mod, uint16_t get_status_cmd,
                                                  uint8_t* out_status, BitWidthT bits_zero) {
  static const int kSx126xSpiWidthStatusIndex = 2;  // RADIOLIB_MODULE_SPI_WIDTH_STATUS

  const BitWidthT saved_width = mod->spiConfig.widths[kSx126xSpiWidthStatusIndex];
  mod->spiConfig.widths[kSx126xSpiWidthStatusIndex] = bits_zero;
  uint8_t data = 0xFF;  // poisoned: must not accidentally decode as a plausible mode.
  const int16_t status = mod->SPIreadStream(get_status_cmd, &data, 1);
  // Unconditionally restored on EVERY path, including a genuinely failed
  // transaction -- never left mutated regardless of `status`.
  mod->spiConfig.widths[kSx126xSpiWidthStatusIndex] = saved_width;
  if (out_status != nullptr) *out_status = data;
  return status;
}
