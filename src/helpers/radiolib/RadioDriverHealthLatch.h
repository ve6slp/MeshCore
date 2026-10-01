#pragma once

#include <stdint.h>

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
 * A momentary, expected state transition (e.g. leaving Rx mode to
 * transmit) is NOT itself a driver failure -- only an explicit
 * non-success return code from an actual driver call is -- so this
 * class has no notion of "Rx state" at all; it purely tracks the
 * most recent real operation's reported outcome.
*/
class RadioDriverHealthLatch {
  bool _failed = false;  // defaults to healthy: no operation has been attempted yet.
  // Monotonic, NEVER-decremented count of every genuine failure ever
  // recorded. `_failed` alone is NOT sufficient for a trial-health
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
  uint32_t _fault_count = 0;

public:
  /**
   * \brief  called immediately after a real startReceive()/readData()/
   *         startTransmit() driver call returns, with whether THAT call
   *         itself reported success.
  */
  void recordOutcome(bool success) {
    _failed = !success;
    if (!success) _fault_count++;
  }

  /**
   * \returns  false only if the most recent real driver call recorded via
   *           recordOutcome() reported failure; true otherwise (including
   *           before any call has ever been recorded). NOTE: this is the
   *           passive/reactive, single-most-recent-call signal only --
   *           see faultCount() for a signal that cannot be masked by a
   *           later, unrelated success.
  */
  bool healthy() const { return !_failed; }

  /**
   * \returns  the total number of genuine failures ever recorded via
   *           recordOutcome(false), monotonically non-decreasing for the
   *           lifetime of this object. Comparing two readings of this
   *           value taken at different times tells a caller whether ANY
   *           real failure occurred in between, independent of whatever
   *           the LATEST recordOutcome() call happened to report.
  */
  uint32_t faultCount() const { return _fault_count; }
};
