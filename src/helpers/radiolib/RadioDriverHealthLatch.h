#pragma once

#include <stdint.h>

namespace mesh {

enum class RadioDriverFaultOrigin : uint8_t {
  Unknown = 0,
  StartReceive = 1,
  ReadData = 2,
  ReceiveRearm = 3,
  StartTransmit = 4,
  ActiveProbe = 5,
};

struct RadioDriverFaultDetails {
  RadioDriverFaultOrigin origin = RadioDriverFaultOrigin::Unknown;
  int16_t driverStatus = 0;
  uint8_t probeReasons = 0;
  uint8_t expectedMode = 0;
  uint8_t statusByte = 0;
  uint16_t deviceErrors = 0;
  uint32_t irqFlags = 0;
  int16_t deviceErrorsStatus = 0;
  int16_t irqFlagsStatus = 0;
  int16_t statusReadStatus = 0;
  uint8_t softwareStateBefore = 0;
  uint8_t softwareStateAfter = 0;
};

struct RadioDriverFaultDiagnostic {
  static constexpr uint8_t kOriginCount = 6;
  bool healthy = true;
  bool hasFailure = false;
  uint32_t faultCount = 0;
  uint32_t lastFaultCount = 0;
  uint32_t originCounts[kOriginCount] = {};
  RadioDriverFaultDetails last;
};

// Counts retain the existing unsigned modulo-2^32 semantics. hasFailure
// distinguishes a wrapped lastFaultCount of zero from no recorded failure.
inline void recordRadioDriverOutcome(RadioDriverFaultDiagnostic& diagnostic, bool success,
                                     const RadioDriverFaultDetails& details) {
  diagnostic.healthy = success;
  if (success) return;
  ++diagnostic.faultCount;
  uint8_t origin = static_cast<uint8_t>(details.origin);
  if (origin >= RadioDriverFaultDiagnostic::kOriginCount) origin = 0;
  ++diagnostic.originCounts[origin];
  diagnostic.hasFailure = true;
  diagnostic.lastFaultCount = diagnostic.faultCount;
  diagnostic.last = details;
  diagnostic.last.origin = static_cast<RadioDriverFaultOrigin>(origin);
}

}  // namespace mesh

/**
 * \brief  Turns the raw success/failure return status of the radio
 *         driver's actual startReceive()/readData()/startTransmit() calls
 *         (see RadioLibWrapper, which owns one instance of this and feeds
 *         it from those three real call sites -- never a synthetic extra
 *         probe query) into a single per-tick "is the driver currently
 *         healthy" signal.
 *
 * Deliberately RadioLib/Arduino-INDEPENDENT (plain C++, no radio-library
 * or board headers) so this exact decision logic -- not merely a
 * standalone re-implementation of it -- can be exercised by real native
 * host unit tests. RadioLibWrapper.cpp/.h themselves depend on RadioLib's
 * PhysicalLayer/Module types, which in turn transitively pull in Arduino
 * global macros (`min`/`max`, `random(lo,hi)`) that conflict with
 * <limits>/<algorithm> when compiled in a plain native/g++ environment
 * without extensive additional Arduino-compatibility shimming -- so the
 * WIRING (that RadioLibWrapper actually calls into this class from the
 * right three call sites, in the right order, with the right board/
 * radio types) is verified by full MCU compilation of all real firmware
 * targets instead; this class is what makes the underlying DECISION
 * logic itself independently, genuinely host-testable.
 *
 * This latch preserves the call site's verdict, including the strict
 * active-probe verdict. Retained attribution never changes that decision.
*/
class RadioDriverHealthLatch {
  // The latest outcome alone is NOT sufficient for a trial-health
  // window: it is deliberately overwritten back to healthy by whichever
  // recordOutcome() call happens to run LAST in a given pass -- so a
  // real startReceive()/readData()/startTransmit() failure earlier in
  // the SAME loop iteration would otherwise be silently masked by a
  // later, unrelated, read-only active probe call that happens to
  // succeed (e.g. CustomSX1262Wrapper::probeDriverStatus() itself,
  // called once per tick). Callers that need to detect "did ANY real
  // failure happen since I last checked, even if the very latest result
  // was healthy" (see MyMesh's trial-health accumulation) must compare
  // faultCount() across ticks instead of relying on healthy() alone.
  mesh::RadioDriverFaultDiagnostic _diagnostic;

public:
  /**
   * \brief  called immediately after a real startReceive()/readData()/
   *         startTransmit() driver call returns, with whether THAT call
   *         itself reported success.
  */
  void recordOutcome(bool success, const mesh::RadioDriverFaultDetails& details = {}) {
    mesh::recordRadioDriverOutcome(_diagnostic, success, details);
  }

  void recordFailure(mesh::RadioDriverFaultOrigin origin, int16_t status,
                     uint8_t software_before, uint8_t software_after) {
    mesh::RadioDriverFaultDetails details;
    details.origin = origin;
    details.driverStatus = status;
    details.softwareStateBefore = software_before;
    details.softwareStateAfter = software_after;
    recordOutcome(false, details);
  }

  /**
   * \returns  false only if the most recent real driver call recorded via
   *           recordOutcome() reported failure; true otherwise (including
   *           before any call has ever been recorded). NOTE: this is the
   *           passive/reactive, single-most-recent-call signal only --
   *           see faultCount() for a signal that cannot be masked by a
   *           later, unrelated success.
  */
  bool healthy() const { return _diagnostic.healthy; }

  /**
   * \returns  the total number of genuine failures ever recorded via
   *           recordOutcome(false), incrementing modulo 2^32 for the
   *           lifetime of this object. Comparing two readings of this
   *           value taken at different times tells a caller whether ANY
   *           real failure occurred in between, independent of whatever
   *           the LATEST recordOutcome() call happened to report.
  */
  uint32_t faultCount() const { return _diagnostic.faultCount; }

  void getDiagnostic(mesh::RadioDriverFaultDiagnostic& out) const { out = _diagnostic; }
};
