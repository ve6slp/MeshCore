#pragma once

#include <stdint.h>
#include "RadioDriverHealthLatch.h"

/**
 * \brief  Turns THREE real, CHECKED SX1262 SPI register reads -- a
 *         device-errors read, an independent IRQ-flags read, and an
 *         independent GET_STATUS read (each produced by
 *         CustomSX1262::getDeviceErrorsChecked()/getIrqFlagsChecked()/
 *         getStatusChecked()) -- into a single "the driver is genuinely,
 *         actively healthy right now, in the mode software actually
 *         expects" verdict.
 *
 * Deliberately RadioLib/Arduino-INDEPENDENT (plain C++, no radio-library
 * or board headers), mirroring the RadioDriverHealthLatch pattern, so
 * this exact decision logic can be exercised by real native host unit
 * tests: CustomSX1262Wrapper::probeDriverStatus() is the only thing that
 * WIRES the real hardware calls to this logic (verified by full MCU
 * compilation), while this header is what makes the DECISION itself
 * independently, genuinely testable.
 *
 * The root defect this closes: RadioLib's own SX126x::getDeviceErrors()/
 * getIrqFlags() call Module::SPIreadStream() but completely discard its
 * returned int16_t status, then unconditionally decode whatever bytes
 * are left in the buffer -- so a genuinely failed SPI transaction that
 * leaves the buffer at its pre-set value is silently indistinguishable
 * from a real "zero errors" success. SX126x::getStatus() is worse: it
 * calls SPIreadStream(cmd, &data, 0) with numBytes==0, so BOTH its
 * data-copy-out AND its real-status-parsing are structurally skipped --
 * `data` is never written at all. getStatusChecked() (see CustomSX1262.h)
 * performs the identical physical transaction but reads the status byte
 * as an ordinary 1-byte payload instead, so it genuinely works. All
 * THREE checked reads here surface their real status; ANY one reporting
 * non-success is treated as a genuine, unhealthy driver fault -- never a
 * success-shaped fallback.
 *
 * Chip-mode cross-check: the decoded status byte's real chip-mode bits
 * (bits 6:4) are compared against what software currently EXPECTS the
 * chip to be doing (idle/receiving/transmitting). This is an EXACT
 * match requirement -- there is deliberately NO "bounded transitional"
 * exception based on the IRQ flags here: the IRQ register is a LATCHED
 * hardware bit that persists across arbitrarily many subsequent ticks
 * until something explicitly clears it, so treating a stale RX_DONE/
 * TX_DONE/TIMEOUT bit as "fresh completion evidence" would let a chip
 * that is genuinely stuck in STDBY forever keep passing this check
 * indefinitely on nothing but an ancient, never-cleared flag. A real,
 * ordinary transition (chip auto-leaves Rx/Tx to STDBY the instant an
 * operation completes, strictly before software reissues
 * startReceive()/startTransmit()) legitimately fails this ONE probe
 * tick instead -- software must observe a genuinely fresh, actively
 * matching RX or TX mode again within the real trial-health deadline,
 * not rely on this probe inventing unbounded freshness from a latched
 * bit. Any mode byte that does not decode to one of the five real,
 * supported SX126x status modes (STDBY_RC/STDBY_XOSC/FS/RX/TX) is ALSO
 * treated as unhealthy -- an invalid/unsupported mode value is never
 * silently accepted as "close enough" to idle.
*/
struct Sx1262CheckedProbeResult {
  int16_t device_errors_status;  // real SPI transaction status from the device-errors read
  uint16_t device_errors;        // ONLY meaningful when device_errors_status == kRadioLibErrNoneForProbe
  int16_t irq_flags_status;      // real SPI transaction status from the (independent) irq-flags read
  uint32_t irq_flags;            // ONLY meaningful when irq_flags_status == kRadioLibErrNoneForProbe
  int16_t status_read_status;    // real SPI transaction status from the (independent) GET_STATUS read
  uint8_t status_byte;           // ONLY meaningful when status_read_status == kRadioLibErrNoneForProbe
};

// What software currently believes the radio is doing, supplied by the
// caller (CustomSX1262Wrapper::probeDriverStatus(), derived from the
// SAME RadioLibWrapper::isInRecvMode()/isTransmitPending() state the
// ordinary send/receive call sites already maintain) -- never inferred
// from the probe itself.
enum class Sx1262ExpectedChipMode : uint8_t {
  kIdle = 0,
  kReceiving = 1,
  kTransmitting = 2,
};

// Duplicated intentionally rather than pulling in RadioLib.h (whose
// Arduino-global macros conflict with native/g++ builds) -- these are
// the real numeric values of RADIOLIB_ERR_NONE and the SX126x GET_STATUS
// byte's chip-mode/IRQ bit fields (see SX126x_commands.h), not
// redefinitions of those symbols themselves.
static const int16_t kRadioLibErrNoneForProbe = 0;

static const uint8_t kSx1262StatusModeMask      = 0b01110000;
static const uint8_t kSx1262StatusModeStdbyRc   = 0b00100000;
static const uint8_t kSx1262StatusModeStdbyXosc = 0b00110000;
static const uint8_t kSx1262StatusModeFs        = 0b01000000;
static const uint8_t kSx1262StatusModeRx        = 0b01010000;
static const uint8_t kSx1262StatusModeTx        = 0b01100000;

static const uint32_t kSx1262IrqTxDone  = 0x0001;
static const uint32_t kSx1262IrqRxDone  = 0x0002;
static const uint32_t kSx1262IrqTimeout = 0x0200;

// True only for the five real, documented SX126x status-mode encodings
// -- any other value (e.g. the mode field reading back 0b000_0000 or
// 0b111_0000, which are not valid chip modes at all) is a genuine
// driver/SPI-wiring fault, never treated as "harmlessly idle".
inline bool isSupportedSx1262StatusMode(uint8_t mode) {
  return mode == kSx1262StatusModeStdbyRc || mode == kSx1262StatusModeStdbyXosc ||
         mode == kSx1262StatusModeFs || mode == kSx1262StatusModeRx || mode == kSx1262StatusModeTx;
}

inline bool evaluateSx1262CheckedHealth(const Sx1262CheckedProbeResult& r, Sx1262ExpectedChipMode expected) {
  // A genuinely failed SPI transaction on ANY of the three real,
  // independent register reads must fail closed -- never be treated as
  // "healthy by default" just because a (possibly untouched/poisoned)
  // decoded value happens not to look like an error.
  if (r.device_errors_status != kRadioLibErrNoneForProbe) return false;
  if (r.irq_flags_status != kRadioLibErrNoneForProbe) return false;
  if (r.status_read_status != kRadioLibErrNoneForProbe) return false;
  // All three SPI round trips genuinely succeeded: now trust the real,
  // non-discarded device-error bits.
  if (r.device_errors != 0) return false;

  const uint8_t mode = r.status_byte & kSx1262StatusModeMask;
  if (!isSupportedSx1262StatusMode(mode)) return false;

  switch (expected) {
    case Sx1262ExpectedChipMode::kReceiving:
      return mode == kSx1262StatusModeRx;
    case Sx1262ExpectedChipMode::kTransmitting:
      return mode == kSx1262StatusModeTx;
    case Sx1262ExpectedChipMode::kIdle:
    default:
      // Between sends/receives: any real, supported, non-active mode is
      // legitimate; the chip genuinely claiming an ACTIVE Rx or Tx mode
      // while software believes it is idle is a real disagreement.
      return mode != kSx1262StatusModeRx && mode != kSx1262StatusModeTx;
  }

}

enum Sx1262ProbeFailureReason : uint8_t {
  kSx1262DeviceErrorsReadFailed = 0x01,
  kSx1262IrqFlagsReadFailed = 0x02,
  kSx1262StatusReadFailed = 0x04,
  kSx1262DeviceErrorsPresent = 0x08,
  kSx1262UnsupportedMode = 0x10,
  kSx1262ModeMismatch = 0x20,
};

// Attribution only: the health decision above remains the authority. Never
// interpret a decoded field whose checked read failed as independent evidence.
inline uint8_t sx1262ProbeFailureReasons(const Sx1262CheckedProbeResult& r,
                                        Sx1262ExpectedChipMode expected) {
  uint8_t reasons = 0;
  if (r.device_errors_status != 0) reasons |= kSx1262DeviceErrorsReadFailed;
  else if (r.device_errors != 0) reasons |= kSx1262DeviceErrorsPresent;
  if (r.irq_flags_status != 0) reasons |= kSx1262IrqFlagsReadFailed;
  if (r.status_read_status != 0) reasons |= kSx1262StatusReadFailed;
  else {
    const uint8_t mode = r.status_byte & kSx1262StatusModeMask;
    if (!isSupportedSx1262StatusMode(mode)) reasons |= kSx1262UnsupportedMode;
    else if ((expected == Sx1262ExpectedChipMode::kReceiving && mode != kSx1262StatusModeRx) ||
             (expected == Sx1262ExpectedChipMode::kTransmitting && mode != kSx1262StatusModeTx) ||
             (expected != Sx1262ExpectedChipMode::kReceiving &&
              expected != Sx1262ExpectedChipMode::kTransmitting &&
              (mode == kSx1262StatusModeRx || mode == kSx1262StatusModeTx)))
      reasons |= kSx1262ModeMismatch;
  }
  return reasons;
}

inline void recordSx1262CheckedProbeOutcome(RadioDriverHealthLatch& latch,
                                           const Sx1262CheckedProbeResult& r,
                                           Sx1262ExpectedChipMode expected,
                                           uint8_t software_before, uint8_t software_after) {
  if (evaluateSx1262CheckedHealth(r, expected)) {
    latch.recordOutcome(true);
    return;
  }
  mesh::RadioDriverFaultDetails details;
  details.origin = mesh::RadioDriverFaultOrigin::ActiveProbe;
  details.driverStatus = r.device_errors_status != 0 ? r.device_errors_status :
      (r.irq_flags_status != 0 ? r.irq_flags_status : r.status_read_status);
  details.probeReasons = sx1262ProbeFailureReasons(r, expected);
  details.expectedMode = static_cast<uint8_t>(expected);
  details.statusByte = r.status_byte;
  details.deviceErrors = r.device_errors;
  details.irqFlags = r.irq_flags;
  details.deviceErrorsStatus = r.device_errors_status;
  details.irqFlagsStatus = r.irq_flags_status;
  details.statusReadStatus = r.status_read_status;
  details.softwareStateBefore = software_before;
  details.softwareStateAfter = software_after;
  latch.recordOutcome(false, details);
}
