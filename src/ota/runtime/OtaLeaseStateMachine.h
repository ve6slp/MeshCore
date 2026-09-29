#pragma once

// Portable direct-mode radio lease state machine.
//
// Guarantees: from every state, on Timeout, Failure, or Reset the state
// machine returns to Normal and invokes the caller-supplied restore
// callback exactly once, so the underlying radio profile is never left in a
// non-default configuration after any failure/timeout/restart path.

#include <cstdint>

namespace meshcore {
namespace ota {
namespace runtime {

enum class OtaLeaseState : uint8_t {
  Normal = 0,
  Requesting,
  Active,
  Releasing,
};

enum class OtaLeaseEvent : uint8_t {
  RequestLease,
  Granted,
  Denied,
  Timeout,
  Failure,
  Release,
  ReleaseAcked,
  Reset,
};

class OtaLeaseStateMachine {
public:
  using RestoreFn = void (*)(void* ctx);

  void setRestoreCallback(RestoreFn fn, void* ctx) {
    restoreFn_ = fn;
    ctx_ = ctx;
  }

  OtaLeaseState state() const { return state_; }
  uint32_t restoreCount() const { return restoreCount_; }

  // Returns false (no state change) for events not legal in the current
  // state. Every legal Timeout/Failure/Reset transition restores Normal;
  // Reset is legal (and idempotent) from every state, including Normal.
  bool handle(OtaLeaseEvent ev) {
    switch (state_) {
      case OtaLeaseState::Normal:
        switch (ev) {
          case OtaLeaseEvent::RequestLease:
            state_ = OtaLeaseState::Requesting;
            return true;
          case OtaLeaseEvent::Reset:
            restore();
            return true;
          default:
            return false;
        }

      case OtaLeaseState::Requesting:
        switch (ev) {
          case OtaLeaseEvent::Granted:
            state_ = OtaLeaseState::Active;
            return true;
          case OtaLeaseEvent::Denied:
          case OtaLeaseEvent::Timeout:
          case OtaLeaseEvent::Failure:
          case OtaLeaseEvent::Reset:
            restore();
            return true;
          default:
            return false;
        }

      case OtaLeaseState::Active:
        switch (ev) {
          case OtaLeaseEvent::Release:
            state_ = OtaLeaseState::Releasing;
            return true;
          case OtaLeaseEvent::Timeout:
          case OtaLeaseEvent::Failure:
          case OtaLeaseEvent::Reset:
            restore();
            return true;
          default:
            return false;
        }

      case OtaLeaseState::Releasing:
        switch (ev) {
          case OtaLeaseEvent::ReleaseAcked:
          case OtaLeaseEvent::Timeout:
          case OtaLeaseEvent::Failure:
          case OtaLeaseEvent::Reset:
            restore();
            return true;
          default:
            return false;
        }

      default:
        return false;
    }
  }

private:
  void restore() {
    state_ = OtaLeaseState::Normal;
    ++restoreCount_;
    if (restoreFn_) restoreFn_(ctx_);
  }

  OtaLeaseState state_ = OtaLeaseState::Normal;
  RestoreFn restoreFn_ = nullptr;
  void* ctx_ = nullptr;
  uint32_t restoreCount_ = 0;
};

} // namespace runtime
} // namespace ota
} // namespace meshcore
