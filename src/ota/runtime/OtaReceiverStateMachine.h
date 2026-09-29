#pragma once

// Receiver-side OTA session state machine.
//
// Explicit, exhaustive legal-transition table: any (state, event) pair not
// listed is illegal and handle() returns false leaving state unchanged.
// Campaign/session/attempt replay isolation is enforced via OtaReplayGuard:
// a new campaign can only begin with a strictly newer (campaignId,
// sessionId, attemptId) tuple than the last one accepted, and events for a
// session other than the currently active one are rejected outright.

#include <cstdint>
#include "OtaSessionIdentity.h"

namespace meshcore {
namespace ota {
namespace runtime {

enum class OtaReceiverState : uint8_t {
  Idle = 0,
  AwaitingDescriptor,
  AwaitingAuthorization,
  Receiving,
  Verifying,
  Committing,
  Complete,
  Failed,
  Aborted,
};

enum class OtaReceiverEvent : uint8_t {
  DescriptorFragmentReceived,
  DescriptorComplete,
  DescriptorRejected,
  AuthorizationGranted,
  AuthorizationDenied,
  ChunkAccepted,
  AllChunksReceived,
  StagingError,
  VerificationOk,
  VerificationFailed,
  CommitOk,
  CommitFailed,
  Abort,
};

class OtaReceiverStateMachine {
public:
  // Starts a new campaign attempt. Only legal while in a non-active state
  // (Idle or any terminal state); rejects (returns false, no state change)
  // a stale/replayed session id. On success moves to AwaitingDescriptor.
  bool beginCampaign(const OtaSessionId& id) {
    if (state_ != OtaReceiverState::Idle && !isTerminal(state_)) return false;
    if (!guard_.acceptIfNewer(id)) return false;
    active_ = id;
    state_ = OtaReceiverState::AwaitingDescriptor;
    return true;
  }

  // Processes an event for session `id`. Rejects events for any session
  // other than the currently active one (stale/foreign/replayed) unless the
  // receiver is Idle, in which case no event is legal (must beginCampaign
  // first).
  bool handle(OtaReceiverEvent ev, const OtaSessionId& id) {
    if (state_ == OtaReceiverState::Idle) return false;
    if (!otaSessionEquals(id, active_)) return false;

    switch (state_) {
      case OtaReceiverState::AwaitingDescriptor:
        switch (ev) {
          case OtaReceiverEvent::DescriptorFragmentReceived:
            return true; // legal no-op, still awaiting completion
          case OtaReceiverEvent::DescriptorComplete:
            state_ = OtaReceiverState::AwaitingAuthorization;
            return true;
          case OtaReceiverEvent::DescriptorRejected:
            state_ = OtaReceiverState::Failed;
            return true;
          case OtaReceiverEvent::Abort:
            state_ = OtaReceiverState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaReceiverState::AwaitingAuthorization:
        switch (ev) {
          case OtaReceiverEvent::AuthorizationGranted:
            state_ = OtaReceiverState::Receiving;
            return true;
          case OtaReceiverEvent::AuthorizationDenied:
            state_ = OtaReceiverState::Failed;
            return true;
          case OtaReceiverEvent::Abort:
            state_ = OtaReceiverState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaReceiverState::Receiving:
        switch (ev) {
          case OtaReceiverEvent::ChunkAccepted:
            return true;
          case OtaReceiverEvent::AllChunksReceived:
            state_ = OtaReceiverState::Verifying;
            return true;
          case OtaReceiverEvent::StagingError:
            state_ = OtaReceiverState::Failed;
            return true;
          case OtaReceiverEvent::Abort:
            state_ = OtaReceiverState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaReceiverState::Verifying:
        switch (ev) {
          case OtaReceiverEvent::VerificationOk:
            state_ = OtaReceiverState::Committing;
            return true;
          case OtaReceiverEvent::VerificationFailed:
            state_ = OtaReceiverState::Failed;
            return true;
          case OtaReceiverEvent::Abort:
            state_ = OtaReceiverState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaReceiverState::Committing:
        switch (ev) {
          case OtaReceiverEvent::CommitOk:
            state_ = OtaReceiverState::Complete;
            return true;
          case OtaReceiverEvent::CommitFailed:
            state_ = OtaReceiverState::Failed;
            return true;
          case OtaReceiverEvent::Abort:
            state_ = OtaReceiverState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaReceiverState::Complete:
      case OtaReceiverState::Failed:
      case OtaReceiverState::Aborted:
      case OtaReceiverState::Idle:
      default:
        return false;
    }
  }

  // Returns the receiver to Idle. Always legal, does not require a matching
  // session id, and never clears the replay guard, so a subsequent
  // beginCampaign() still cannot resurrect a stale attempt.
  void reset() { state_ = OtaReceiverState::Idle; }

  OtaReceiverState state() const { return state_; }
  const OtaSessionId& activeSession() const { return active_; }
  bool hasAcceptedSession() const { return guard_.hasAccepted(); }

private:
  static bool isTerminal(OtaReceiverState s) {
    return s == OtaReceiverState::Complete || s == OtaReceiverState::Failed || s == OtaReceiverState::Aborted;
  }

  OtaReceiverState state_ = OtaReceiverState::Idle;
  OtaSessionId active_{};
  OtaReplayGuard guard_;
};

} // namespace runtime
} // namespace ota
} // namespace meshcore
