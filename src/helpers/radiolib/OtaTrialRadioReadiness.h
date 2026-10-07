#pragma once

#include <stdint.h>

/**
 * \brief  Plain, RadioLib/Arduino-INDEPENDENT decision of whether the
 *         radio genuinely earns "ready" credit for ONE trial-boot-health
 *         tick -- i.e. whether THIS pass should be allowed to CONTRIBUTE
 *         to the continuous health window (XiaoOtaTrialHealthMonitor),
 *         not whether the chip's reported mode is merely self-consistent
 *         with software's own belief (that narrower question is
 *         evaluateSx1262CheckedHealth()'s job, see Sx1262CheckedProbe.h).
 *
 * Two distinct production bugs this closes, both found by external
 * review of the actual wiring (not merely of the unit tests):
 *
 * 1. STICKY MASKING (fixed here by making the caller re-derive this
 *    PER TICK from the two fault-count samples, rather than ever
 *    persisting a "radio fault observed" bool across ticks): a single
 *    transient real-operation failure must fail ONLY the pass it
 *    occurred on -- the continuous-health window is already designed to
 *    simply RESET (not permanently abort the whole boot) on any one
 *    non-ready pass, so a genuinely recovered radio must be able to
 *    start accumulating a fresh continuous window on the very next
 *    pass. Comparing `fault_count_before_probe`/`fault_count_after_probe`
 *    against `last_known_fault_count` (the value as of the END of the
 *    PREVIOUS tick) answers "did ANY real operation fail THIS pass,
 *    including one that happened earlier this same pass and was at risk
 *    of being masked by a later, unrelated, healthy active probe" --
 *    without needing any cross-tick sticky latch at all.
 *
 * 2. INDEFINITE-IDLE ACCEPTANCE: `evaluateSx1262CheckedHealth()`'s
 *    `kIdle` branch legitimately treats ANY real, supported, non-active
 *    chip mode as "not lying" -- that is correct for its own narrower
 *    consistency question, but is NOT proof that the radio is actually
 *    doing its job (continuously receiving, or legitimately
 *    transmitting) during this pass. A radio that cycles
 *    receive-briefly/idle-mostly (e.g. genuinely idle for 7 of every 8
 *    seconds, with one single Rx-mode tick resetting
 *    isRadioStuckOutOfRecv()'s 8-second floor just before it would trip)
 *    would otherwise satisfy EVERY existing check while spending most of
 *    its time NOT actually servicing incoming/outgoing traffic --
 *    `genuinely_servicing` (isInRecvMode() || isSendInProgress(), the
 *    SAME real Dispatcher-tracked state used elsewhere in
 *    tickOtaTrialHealth()) requires this pass to be an ACTIVE Rx or Tx
 *    pass, not merely "idle but internally consistent", to count as
 *    ready. A single legitimate idle tick (e.g. the brief gap between
 *    finishing one receive and the next startReceive() call) simply
 *    fails THIS pass and resets the window exactly like any other
 *    readiness drop already does (see OtaBoardTrialBootHealthConfirmer's
 *    ReadinessDropResetsWindow test) -- it is never treated as an
 *    outright terminal failure, so genuinely-servicing ticks recorded
 *    immediately after still resume accumulating toward confirmation.
 *
 * \param radio_present            false if there is no radio object at all
 *                                 (must never be treated as healthy).
 * \param base_radio_ready         the external once-per-boot readiness gate
 *                                 (setOtaTrialBootHealthSignals()).
 * \param radio_stuck_non_recv     true if isRadioStuckOutOfRecv() fired.
 * \param driver_healthy           the bool result of probeDriverStatus().
 * \param genuinely_servicing      true iff the radio is ACTIVELY
 *                                 receiving OR a send is genuinely in
 *                                 flight this pass (NOT merely idle-but-
 *                                 consistent).
 * \param fault_count_before_probe driverFaultCount() sampled BEFORE
 *                                 calling probeDriverStatus() this tick.
 * \param fault_count_after_probe  driverFaultCount() sampled AFTER
 *                                 calling probeDriverStatus() this tick.
 * \param last_known_fault_count   driverFaultCount() as of the END of
 *                                 the PREVIOUS tick (the caller updates
 *                                 this to fault_count_after_probe every
 *                                 tick, regardless of outcome).
 * \returns  true only if this exact pass is genuine, fresh, fault-free
 *           evidence of a servicing radio.
*/
inline bool evaluateOtaTrialRadioReadyThisPass(bool radio_present, bool base_radio_ready,
                                               bool radio_stuck_non_recv, bool driver_healthy,
                                               bool genuinely_servicing,
                                               uint32_t fault_count_before_probe,
                                               uint32_t fault_count_after_probe,
                                               uint32_t last_known_fault_count) {
  if (!radio_present) return false;
  if (!base_radio_ready) return false;
  if (radio_stuck_non_recv) return false;
  if (!driver_healthy) return false;
  if (!genuinely_servicing) return false;
  // A real operation failure that already happened EARLIER this same
  // tick (before probeDriverStatus() ran) is still observed here, even
  // though probeDriverStatus() itself may separately report healthy.
  if (fault_count_before_probe != last_known_fault_count) return false;
  // The active probe's OWN outcome, recorded via the same counter.
  if (fault_count_after_probe != fault_count_before_probe) return false;
  return true;
}
