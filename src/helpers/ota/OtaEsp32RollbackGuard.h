#pragma once

// initArduino() otherwise confirms PENDING_VERIFY before setup(). The strong
// C override is defined once by variants/xiao_s3_wio/OtaEsp32Backend.cpp; it
// defers confirmation AND arms the independent hardware RTC watchdog there.
// Vendor rollback is NEW -> PENDING_VERIFY -> ABORTED on an unconfirmed reset.

#include <stdint.h>
#include <ota/storage/Esp32PartitionApi.h>
#include <helpers/ota/OtaFirmwareBackend.h>
#include <helpers/ota/OtaRfFrames.h>
#include <ota/runtime/OtaInstallAttemptIdentity.h>

namespace mesh {
namespace ota {

inline bool readEsp32BootCandidate(
    const OtaBootLifecycleEvidence& expected, ::ota::storage::Esp32ImageState state,
    ::ota::storage::OtaCandidateStore& store, const Esp32OtaPolicy& policy,
    const ::ota::trust::SignatureVerifier& signatures, bool floor_known, uint32_t floor,
    ::ota::storage::OtaCandidateStore::Snapshot& out) {
  using State = ::ota::storage::Esp32ImageState;
  using Phase = usb::UsbOtaPhase;
  out = ::ota::storage::OtaCandidateStore::Snapshot();
  const bool failed = expected.phase == Phase::Failed;
  if (expected.transactionNonce == 0 || expected.counter == 0 ||
      (failed && (expected.imageVerified || (state != State::Aborted && state != State::Invalid))) ||
      (!failed && !expected.imageVerified)) return false;
  if (!failed &&
      !((expected.phase == Phase::Trial && state == State::PendingVerify) ||
        (expected.phase == Phase::Installed && state == State::Valid) ||
        (expected.phase == Phase::Unknown && (state == State::Valid || state == State::Undefined))))
    return false;
  ::ota::storage::OtaCandidateStore::Snapshot snapshot;
  meshcore::ota::protocol::OtaDescriptor descriptor;
  if (!verifyEsp32CandidateProvenance(store, policy, signatures, snapshot, descriptor,
                                     failed ? ::ota::storage::OtaCandidateStore::Phase::Failed :
                                              ::ota::storage::OtaCandidateStore::Phase::Committed))
    return false;
  meshcore::ota::runtime::OtaSessionId session;
  session.campaignId = snapshot.campaignId;
  session.sessionId = snapshot.sessionId;
  session.attemptId = snapshot.attemptId;
  if (expected.transactionNonce != meshcore::ota::runtime::otaInstallAttemptNonce(
          snapshot.ownerPublicKey, session, snapshot.canonical) ||
      expected.counter != descriptor.securityCounter ||
      std::memcmp(expected.imageHash, descriptor.sha256, sizeof(expected.imageHash)) != 0 ||
      (expected.phase == Phase::Installed &&
       (!expected.floorKnown || expected.confirmedFloor != expected.counter ||
        !floor_known || floor != expected.counter))) return false;
  out = snapshot;
  return true;
}

inline bool readEsp32BootLifecycle(
    ::ota::storage::Esp32ImageState state, ::ota::storage::OtaCandidateStore& store,
    ::ota::platform::FlashRegion& image, const Esp32OtaPolicy& policy,
    const ::ota::trust::SignatureVerifier& signatures, bool floor_known, uint32_t floor,
    OtaBootLifecycleEvidence& out, bool failed_candidate = false) {
  using State = ::ota::storage::Esp32ImageState;
  using Phase = usb::UsbOtaPhase;
  out = OtaBootLifecycleEvidence();
  if (state != State::Valid && state != State::PendingVerify && state != State::Aborted &&
      state != State::Invalid && state != State::Undefined) return false;
  if (failed_candidate && state != State::Aborted && state != State::Invalid) return false;
  out.floorKnown = floor_known;
  out.confirmedFloor = floor_known ? floor : 0;
  if (state == State::PendingVerify) out.phase = Phase::Trial;
  if (state == State::Aborted || state == State::Invalid) out.phase = Phase::Failed;
  ::ota::storage::OtaCandidateStore::Snapshot snapshot;
  meshcore::ota::protocol::OtaDescriptor descriptor;
  const bool verified = failed_candidate ?
      verifyEsp32CandidateProvenance(store, policy, signatures, snapshot, descriptor,
                                    ::ota::storage::OtaCandidateStore::Phase::Failed) :
      verifyEsp32RunningCandidate(store, image, policy, signatures, snapshot, descriptor);
  if (!verified) return true;
  meshcore::ota::runtime::OtaSessionId session;
  session.campaignId = snapshot.campaignId;
  session.sessionId = snapshot.sessionId;
  session.attemptId = snapshot.attemptId;
  out.transactionNonce = meshcore::ota::runtime::otaInstallAttemptNonce(
      snapshot.ownerPublicKey, session, snapshot.canonical);
  out.counter = descriptor.securityCounter;
  std::memcpy(out.imageHash, descriptor.sha256, sizeof(out.imageHash));
  // An aborted inactive candidate is not proof of the currently running image.
  out.imageVerified = !failed_candidate;
  if (state == State::Valid && out.imageVerified && floor_known && floor == out.counter)
    out.phase = Phase::Installed;
  return true;
}

enum class Esp32TrialHealthOutcome : uint8_t {
  Pending = 0,          // still accumulating health progress, or a non-trial (already-valid) boot.
  Confirmed = 1,         // continuous healthy window satisfied -- caller must call its confirm action exactly once.
  DeadlineExpired = 2,   // kOverallDeadlineMs elapsed without a satisfied healthy window -- caller must
                        // call its forced-rollback-and-reboot action exactly once.
  StateUnreadable = 3,
  ConfirmationUncertain = 4,
};

// Pure decision logic, hardware-free and natively testable: given
// whether this boot is genuinely pending verification (the real caller
// supplies this from esp_ota_get_state_partition()) plus repeated
// readiness ticks, decides exactly once when to confirm or force
// rollback. Never touches esp_ota_* itself -- the caller performs the
// actual confirm/rollback action exactly once, in response to the
// returned terminal outcome.
class Esp32TrialHealthGate {
public:
  static constexpr uint32_t kContinuousHealthyWindowMs = 10000u;
  static constexpr uint32_t kMaxServiceGapMs = 1000u;
  static constexpr uint32_t kOverallDeadlineMs = 45000u;

  // `boot_epoch_ms` must be the genuine application boot origin (in
  // production: the constant 0, since Arduino's millis() already counts
  // from actual power-on/reset) -- see OtaBoardTrialBootHealthConfirmer's
  // identical constructor doc-comment for why reading a fresh clock here
  // instead would silently discount earlier setup() time from the
  // deadline budget. `pending_verify` must reflect a FRESH read of the
  // real OTA state partition (esp_ota_get_state_partition() ==
  // ESP_OTA_IMG_PENDING_VERIFY) at construction time, never cached from
  // an earlier boot.
  Esp32TrialHealthGate(uint32_t boot_epoch_ms, bool pending_verify)
      : deadline_start_ms_(boot_epoch_ms), pending_verify_(pending_verify) {}

  // Call exactly once per main-loop tick with the genuine current
  // wall-clock time and readiness signals. Returns the LATCHED outcome:
  // once Confirmed or DeadlineExpired is reached, every subsequent call
  // returns the same value immediately without further state changes.
  // Callers must react to a terminal outcome with exactly one action
  // (confirm, or forced rollback+reboot) -- this class never calls any
  // esp_ota_* function itself.
  Esp32TrialHealthOutcome tick(uint32_t now_ms, bool radio_ready, bool filesystem_ready, bool loop_healthy) {
    if (outcome_ != Esp32TrialHealthOutcome::Pending) return outcome_;
    if (!pending_verify_) return Esp32TrialHealthOutcome::Pending;  // already-valid boot: nothing to do, ever.

    if (last_tick_valid_ && (now_ms - last_tick_ms_) > kMaxServiceGapMs) {
      window_active_ = false;
    }
    last_tick_ms_ = now_ms;
    last_tick_valid_ = true;

    const bool ready_now = radio_ready && filesystem_ready && loop_healthy;
    if (!ready_now) {
      window_active_ = false;
    } else if (!window_active_) {
      window_active_ = true;
      window_start_ms_ = now_ms;
    }

    // Deadline is enforced before any confirmation decision this tick,
    // exactly like the nRF52 monitor: a tick that simultaneously
    // satisfies the healthy window AND crosses the deadline must still
    // be treated as an expiry, never a late confirm.
    if ((now_ms - deadline_start_ms_) >= kOverallDeadlineMs) {
      outcome_ = Esp32TrialHealthOutcome::DeadlineExpired;
      return outcome_;
    }

    if (window_active_ && (now_ms - window_start_ms_) >= kContinuousHealthyWindowMs) {
      outcome_ = Esp32TrialHealthOutcome::Confirmed;
      return outcome_;
    }

    return Esp32TrialHealthOutcome::Pending;
  }

  Esp32TrialHealthOutcome outcome() const { return outcome_; }
  bool isPendingVerify() const { return pending_verify_; }

private:
  uint32_t deadline_start_ms_;
  bool pending_verify_;
  bool window_active_ = false;
  uint32_t window_start_ms_ = 0;
  bool last_tick_valid_ = false;
  uint32_t last_tick_ms_ = 0;
  Esp32TrialHealthOutcome outcome_ = Esp32TrialHealthOutcome::Pending;
};

class Esp32TrialPlatform {
public:
  virtual ~Esp32TrialPlatform() = default;
  virtual bool runningState(::ota::storage::Esp32ImageState& out) = 0;
  virtual bool armWatchdog(uint32_t remaining_ms) = 0;
  virtual void disarmWatchdog() = 0;
  virtual bool confirmHealthy() = 0;
  virtual void rollbackAndRestart() = 0;
};

// Exercises the actual action boundary as well as the pure health gate.
// Never feeds/extends the watchdog: setup time and stalled loops count.
class Esp32TrialController {
public:
  explicit Esp32TrialController(Esp32TrialPlatform& platform) : platform_(platform), gate_(0, true) {}
  bool begin(uint32_t now_ms) {
    if (begun_) return !unknown_;
    begun_ = true;
    ::ota::storage::Esp32ImageState state;
    unknown_ = !platform_.runningState(state);
    if (!unknown_) {
      trial_ = state == ::ota::storage::Esp32ImageState::PendingVerify;
      unknown_ = state != ::ota::storage::Esp32ImageState::Valid &&
                 state != ::ota::storage::Esp32ImageState::Undefined && !trial_;
    }
    if (trial_ || unknown_) {
      const uint32_t remaining = now_ms < Esp32TrialHealthGate::kOverallDeadlineMs
          ? Esp32TrialHealthGate::kOverallDeadlineMs - now_ms : 1;
      if (!platform_.armWatchdog(remaining)) {
        unknown_ = true;
        outcome_ = Esp32TrialHealthOutcome::StateUnreadable;
        action_taken_ = true;
        platform_.rollbackAndRestart();
      }
    }
    return !unknown_;
  }
  bool activeOrUnknown() const { return !begun_ || unknown_ || trial_; }
  Esp32TrialHealthOutcome tick(uint32_t now_ms, bool radio, bool storage, bool loop) {
    if (!begun_) begin(now_ms);
    if (action_taken_) return outcome_;
    if (unknown_) {
      outcome_ = Esp32TrialHealthOutcome::StateUnreadable;
    } else if (!trial_) {
      return Esp32TrialHealthOutcome::Pending;
    } else {
      outcome_ = gate_.tick(now_ms, radio, storage, loop);
      if (outcome_ == Esp32TrialHealthOutcome::Pending) return outcome_;
      if (outcome_ == Esp32TrialHealthOutcome::Confirmed) {
        ::ota::storage::Esp32ImageState state;
        if (platform_.runningState(state) &&
            state == ::ota::storage::Esp32ImageState::PendingVerify &&
            platform_.confirmHealthy() && platform_.runningState(state) &&
            state == ::ota::storage::Esp32ImageState::Valid) {
          platform_.disarmWatchdog();
          trial_ = false;
          action_taken_ = true;
          return outcome_;
        }
        outcome_ = Esp32TrialHealthOutcome::ConfirmationUncertain;
      }
    }
    action_taken_ = true;
    platform_.rollbackAndRestart();
    return outcome_;
  }
private:
  Esp32TrialPlatform& platform_;
  Esp32TrialHealthGate gate_;
  Esp32TrialHealthOutcome outcome_ = Esp32TrialHealthOutcome::Pending;
  bool begun_ = false, unknown_ = false, trial_ = false, action_taken_ = false;
};

}  // namespace ota
}  // namespace mesh

#if defined(ESP32)
extern "C" bool verifyRollbackLater();
#endif
