#pragma once

#include <cstdint>
#include <ota/storage/Esp32PartitionApi.h>

namespace mesh { namespace ota {

constexpr ::ota::storage::Esp32SdkError kEsp32NvsNoFreePages = 0x110D;
constexpr ::ota::storage::Esp32SdkError kEsp32NvsNewVersionFound = 0x1110;
constexpr ::ota::storage::Esp32SdkError kEsp32InvalidState = 0x103;
inline ::ota::storage::Esp32SdkError esp32NvsStartupInitResult(::ota::storage::Esp32SdkError result) {
  return result == kEsp32NvsNoFreePages || result == kEsp32NvsNewVersionFound ? kEsp32InvalidState : result;
}

inline bool readEsp32EarlyRunningState(::ota::storage::Esp32PartitionApi& sdk,
                                       ::ota::storage::Esp32ImageState& out) {
  using namespace ::ota::storage;
  Esp32PartitionSnapshot context;
  if (sdk.inspect(context) != kEsp32Ok || !Esp32S3PartitionLayout::matches(context)) return false;
  const bool running0 = esp32PartitionEquals(context.running, Esp32S3PartitionLayout::entry(2));
  if ((!running0 && !esp32PartitionEquals(context.running, Esp32S3PartitionLayout::entry(3))) ||
      !esp32PartitionEquals(context.boot, context.running) ||
      !esp32PartitionEquals(context.next, Esp32S3PartitionLayout::entry(running0 ? 3 : 2))) return false;
  const auto inactive = context.appStates[running0 ? 1 : 0];
  if (inactive != Esp32ImageState::Valid && inactive != Esp32ImageState::Undefined &&
      inactive != Esp32ImageState::Aborted && inactive != Esp32ImageState::Invalid) return false;
  out = context.appStates[running0 ? 0 : 1];
  return true;
}

inline bool readEsp32UnknownStartupTopology(::ota::storage::Esp32PartitionApi& sdk) {
  using namespace ::ota::storage;
  Esp32PartitionSnapshot before, after;
  if (sdk.inspect(before) != kEsp32Ok || !Esp32S3PartitionLayout::matches(before)) return false;
  const bool running0 = esp32PartitionEquals(before.running, Esp32S3PartitionLayout::entry(2));
  if ((!running0 && !esp32PartitionEquals(before.running, Esp32S3PartitionLayout::entry(3))) ||
      !esp32PartitionEquals(before.boot, Esp32S3PartitionLayout::entry(running0 ? 3 : 2)) ||
      !esp32PartitionEquals(before.next, before.boot)) return false;
  const auto current = before.appStates[running0 ? 0 : 1];
  if (current != Esp32ImageState::Valid && current != Esp32ImageState::Undefined) return false;
  for (const auto state : before.appStates)
    if (state != Esp32ImageState::New && state != Esp32ImageState::PendingVerify &&
        state != Esp32ImageState::Valid && state != Esp32ImageState::Undefined &&
        state != Esp32ImageState::Aborted && state != Esp32ImageState::Invalid) return false;
  return sdk.inspect(after) == kEsp32Ok && Esp32S3PartitionLayout::matches(after) &&
      esp32PartitionEquals(after.running, before.running) && esp32PartitionEquals(after.boot, before.boot) &&
      esp32PartitionEquals(after.next, before.next) && after.appStates[0] == before.appStates[0] &&
      after.appStates[1] == before.appStates[1];
}

enum class Esp32TrialHealthOutcome : uint8_t {
  Pending, Confirmed, DeadlineExpired, StateUnreadable, ConfirmationUncertain
};

class Esp32TrialHealthGate {
public:
  static constexpr uint32_t kContinuousHealthyWindowMs = 10000;
  static constexpr uint32_t kMaxServiceGapMs = 1000;
  static constexpr uint32_t kOverallDeadlineMs = 45000;
  Esp32TrialHealthGate(uint32_t epoch, bool pending) : epoch_(epoch), pending_(pending) {}
  Esp32TrialHealthOutcome tick(uint32_t now, bool radio, bool filesystem, bool loop) {
    if (!pending_ || outcome_ != Esp32TrialHealthOutcome::Pending) return outcome_;
    if (lastValid_ && uint32_t(now - last_) > kMaxServiceGapMs) window_ = false;
    last_ = now; lastValid_ = true;
    if (!radio || !filesystem || !loop) window_ = false;
    else if (!window_) { window_ = true; windowStart_ = now; }
    if (uint32_t(now - epoch_) >= kOverallDeadlineMs) outcome_ = Esp32TrialHealthOutcome::DeadlineExpired;
    else if (window_ && uint32_t(now - windowStart_) >= kContinuousHealthyWindowMs)
      outcome_ = Esp32TrialHealthOutcome::Confirmed;
    return outcome_;
  }
private:
  uint32_t epoch_, last_ = 0, windowStart_ = 0;
  bool pending_, lastValid_ = false, window_ = false;
  Esp32TrialHealthOutcome outcome_ = Esp32TrialHealthOutcome::Pending;
};

enum class Esp32TrialConfirmation : uint8_t { Unconfirmed, ValidNeedsFloorReconciliation, Confirmed };
template<class Proof, class MarkValid, class SaveFloor>
Esp32TrialConfirmation confirmEsp32TrialImage(Proof proof, MarkValid mark, SaveFloor save) {
  uint32_t counter = 0; bool candidate = false;
  if (!proof(counter, candidate) || !mark()) return Esp32TrialConfirmation::Unconfirmed;
  return candidate && !save(counter) ? Esp32TrialConfirmation::ValidNeedsFloorReconciliation :
      Esp32TrialConfirmation::Confirmed;
}
struct Esp32StartupRestartState { uint32_t magic, attempts; };
constexpr uint32_t kEsp32StartupRestartMagic = 0x45535231;
constexpr uint32_t kEsp32StartupRestartLimit = 2;
inline bool reserveEsp32StartupRestart(Esp32StartupRestartState& state) {
  if (state.magic != kEsp32StartupRestartMagic) { state.attempts = 0; state.magic = kEsp32StartupRestartMagic; }
  if (state.attempts >= kEsp32StartupRestartLimit) return false;
  ++state.attempts;
  return true;
}
class Esp32TrialPlatform {
public:
  virtual ~Esp32TrialPlatform() = default;
  virtual bool runningState(::ota::storage::Esp32ImageState&) = 0;
  virtual bool unknownTopologyHoldAllowed() = 0;
  virtual bool armWatchdog(uint32_t) = 0;
  virtual void disarmWatchdog() = 0;
  virtual Esp32TrialConfirmation confirmHealthy() = 0;
  virtual void reportUnknownService() = 0;
  virtual void restartWithoutRollback() = 0;
  virtual void rollbackAndRestart() = 0;
};
class Esp32TrialController {
public:
  Esp32TrialController(Esp32TrialPlatform& platform, Esp32StartupRestartState* retained = nullptr)
      : platform_(platform), restarts_(retained ? *retained : local_), gate_(0, true) {}
  bool begin(uint32_t now) {
    if (begun_) return !unknown_;
    begun_ = true;
    ::ota::storage::Esp32ImageState state;
    unknown_ = !platform_.runningState(state);
    if (!unknown_) {
      trial_ = state == ::ota::storage::Esp32ImageState::PendingVerify;
      unknown_ = state != ::ota::storage::Esp32ImageState::Valid &&
          state != ::ota::storage::Esp32ImageState::Undefined && !trial_;
    }
    const uint32_t remaining = now < 45000 ? 45000 - now : 1;
    if (unknown_) {
      outcome_ = Esp32TrialHealthOutcome::StateUnreadable;
      acted_ = true;
      if (!platform_.unknownTopologyHoldAllowed() || reserveEsp32StartupRestart(restarts_)) {
        if (!platform_.armWatchdog(remaining)) platform_.reportUnknownService();
        platform_.restartWithoutRollback();
      } else {
        held_ = true;
        platform_.disarmWatchdog();
        platform_.reportUnknownService();
      }
      return false;
    }
    restarts_ = {kEsp32StartupRestartMagic, 0};
    if (trial_ && !platform_.armWatchdog(remaining)) {
      unknown_ = acted_ = true;
      outcome_ = Esp32TrialHealthOutcome::StateUnreadable;
      platform_.restartWithoutRollback();
    }
    return !unknown_;
  }
  bool activeOrUnknown() const { return !begun_ || unknown_ || trial_; }
  bool unknownServiceHeld() const { return held_ && platform_.unknownTopologyHoldAllowed(); }
  Esp32TrialHealthOutcome tick(uint32_t now, bool radio, bool filesystem, bool loop) {
    if (!begun_) begin(now);
    if (acted_ || !trial_) return outcome_;
    outcome_ = gate_.tick(now, radio, filesystem, loop);
    if (outcome_ == Esp32TrialHealthOutcome::Pending) return outcome_;
    if (outcome_ == Esp32TrialHealthOutcome::Confirmed) {
      ::ota::storage::Esp32ImageState state;
      bool forward = true;
      if (platform_.runningState(state) && state == ::ota::storage::Esp32ImageState::PendingVerify) {
        const auto confirmed = platform_.confirmHealthy();
        if (confirmed == Esp32TrialConfirmation::Confirmed && platform_.runningState(state) &&
            state == ::ota::storage::Esp32ImageState::Valid) {
          platform_.disarmWatchdog(); trial_ = false; acted_ = true; return outcome_;
        }
        forward = confirmed != Esp32TrialConfirmation::Unconfirmed;
      }
      outcome_ = Esp32TrialHealthOutcome::ConfirmationUncertain;
      if (forward) { acted_ = true; platform_.restartWithoutRollback(); return outcome_; }
    }
    acted_ = true;
    if (unknown_) platform_.restartWithoutRollback();
    else platform_.rollbackAndRestart();
    return outcome_;
  }
private:
  Esp32TrialPlatform& platform_;
  Esp32StartupRestartState local_ = {0, 0};
  Esp32StartupRestartState& restarts_;
  Esp32TrialHealthGate gate_;
  Esp32TrialHealthOutcome outcome_ = Esp32TrialHealthOutcome::Pending;
  bool begun_ = false, unknown_ = false, trial_ = false, acted_ = false, held_ = false;
};

}}
