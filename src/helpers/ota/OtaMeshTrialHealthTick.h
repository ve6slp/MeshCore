#pragma once

#include <stdint.h>

#include "helpers/ota/OtaBoardBackendCommon.h"
#include "helpers/radiolib/OtaTrialRadioReadiness.h"

// Board-backend-provided (weak default in examples/companion_radio/MyMesh.cpp,
// strong override in variants/*/Ota*Backend.cpp) -- declared here, at
// global scope matching its actual definitions, so this header can call
// it without requiring every TU that includes it to separately forward-
// declare the exact same signature itself.
mesh::ota::OtaBoardTrialHealthOutcome otaBoardTryConfirmHealthyTrialBoot(uint32_t now_ms, bool radio_ready,
                                                                        bool filesystem_ready, bool loop_healthy);

#if defined(ESP32_PLATFORM) && defined(MESHCORE_LORA_OTA) && MESHCORE_LORA_OTA && \
    defined(MESHCORE_ESP32_OTA_STARTUP_NVS_GUARD) && MESHCORE_ESP32_OTA_STARTUP_NVS_GUARD
// Unqualified ESP profiles retain the generic null-query behavior.
bool otaBoardUnknownStartupRecoveryHeld();
#endif

/**
 * \brief  Role-agnostic, board-agnostic trial-boot-health TICK decision,
 *         shared verbatim by every MyMesh that enables MESHCORE_LORA_OTA
 *         (companion_radio role 0 and simple_repeater role 1 alike), so
 *         this orchestration (readiness-this-pass evaluation plus the
 *         terminal-outcome-to-reboot mapping) is never hand-copied a
 *         second time. Each caller still owns its OWN per-tick
 *         evidence-gathering (radio/filesystem probes, which are
 *         genuinely board/member-specific -- a different store class, a
 *         different radio wrapper instance, etc.) and its own latched
 *         state (the `last_radio_fault_count` in/out parameter below),
 *         but the DECISION itself -- is this pass "ready", and does the
 *         resulting outcome warrant a single controlled reboot -- lives
 *         in exactly one place.
 */
namespace mesh {
namespace ota {

struct OtaMeshTrialHealthTickInputs {
  uint32_t now_ms;
  bool radio_present;
  bool base_radio_ready;         // latched once at boot (radio_init() succeeded).
  bool radio_stuck_non_recv;
  bool radio_driver_healthy;
  bool radio_genuinely_servicing;
  uint32_t radio_fault_count_before_probe;
  uint32_t radio_fault_count_after_probe;
  bool filesystem_ready_now;     // already combines boot-mount success + any latched fault.
};

struct OtaMeshTrialHealthTickResult {
  OtaBoardTrialHealthOutcome outcome;
  bool should_reboot;  // Terminal outcomes reboot, except a qualified held StateUnreadable.
};

// `last_radio_fault_count` is read (compared against the two fresh
// per-tick samples) AND updated in place to `radio_fault_count_after_probe`
// -- callers must persist it across ticks themselves (it is genuinely
// per-instance state, not something this stateless function can own).
inline OtaMeshTrialHealthTickResult evaluateOtaMeshTrialHealthTick(const OtaMeshTrialHealthTickInputs& in,
                                                                    uint32_t& last_radio_fault_count,
#if defined(ESP32_PLATFORM) && defined(MESHCORE_LORA_OTA) && MESHCORE_LORA_OTA && \
    defined(MESHCORE_ESP32_OTA_STARTUP_NVS_GUARD) && MESHCORE_ESP32_OTA_STARTUP_NVS_GUARD
                                                                    bool (*unknown_service_held)() = ::otaBoardUnknownStartupRecoveryHeld) {
#else
                                                                    bool (*unknown_service_held)() = nullptr) {
#endif
  const bool radio_ready_now = evaluateOtaTrialRadioReadyThisPass(
      in.radio_present, in.base_radio_ready, in.radio_stuck_non_recv, in.radio_driver_healthy,
      in.radio_genuinely_servicing, in.radio_fault_count_before_probe, in.radio_fault_count_after_probe,
      last_radio_fault_count);
  last_radio_fault_count = in.radio_fault_count_after_probe;

  const auto outcome =
      ::otaBoardTryConfirmHealthyTrialBoot(in.now_ms, radio_ready_now, in.filesystem_ready_now, /*loop_healthy=*/true);

  const bool should_reboot = (outcome == OtaBoardTrialHealthOutcome::Confirmed ||
                              outcome == OtaBoardTrialHealthOutcome::DeadlineExpired ||
                              outcome == OtaBoardTrialHealthOutcome::ConfirmationUncertain ||
                              (outcome == OtaBoardTrialHealthOutcome::StateUnreadable &&
                               !(unknown_service_held && unknown_service_held())));
  return OtaMeshTrialHealthTickResult{outcome, should_reboot};
}

}  // namespace ota
}  // namespace mesh
