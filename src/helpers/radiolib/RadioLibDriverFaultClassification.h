#pragma once

// Deliberately RadioLib/Arduino-INDEPENDENT (plain C++, no radio-library
// or board headers), like RadioDriverHealthLatch.h, so this exact
// classification decision is directly native-host-testable instead of
// only reachable via full MCU compilation.
namespace radiolib_health {

// RadioLib's RADIOLIB_ERR_NONE / RADIOLIB_ERR_CRC_MISMATCH (see e.g.
// RadioLib/src/TypeDef.h) hardcoded as plain integer literals -- not the
// RadioLib macros themselves -- so this header never needs to include
// any RadioLib/Arduino header.
constexpr int kRadioLibErrNone = 0;
constexpr int kRadioLibErrCrcMismatch = -7;

// True iff `status` (a raw RadioLib driver call return code, e.g. from
// readData()) represents a GENUINE driver/SPI/hardware fault for
// RadioDriverHealthLatch::recordOutcome() purposes -- i.e. every
// non-success status EXCEPT the one expected, ordinary PHY-layer decode
// rejection: RADIOLIB_ERR_CRC_MISMATCH. A packet that fails its CRC was
// still genuinely received over the air and the driver call that read it
// itself completed successfully; only its payload was corrupted on-air,
// which is normal RF environment noise, not evidence that the SPI/driver
// path is unhealthy. Continual ordinary CRC-bad packets must never, on
// their own, force a healthy firmware's OTA trial-boot window to reset.
// The packet itself is still discarded and still counted toward the
// pre-existing n_recv_errors statistic by the caller -- this predicate
// only ever gates the NEWER driverFaultCount()/recordOutcome() signal.
inline bool isGenuineRadioDriverFault(int status) {
  return status != kRadioLibErrNone && status != kRadioLibErrCrcMismatch;
}

}  // namespace radiolib_health
