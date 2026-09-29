#pragma once

// Coordinator-side OTA session state machine (the sender/driving side of a
// direct or routed-mesh transfer). Mirrors OtaReceiverStateMachine's
// explicit legal-transition table and replay-isolation model.

#include <cstdint>
#include "OtaSessionIdentity.h"

namespace meshcore {
namespace ota {
namespace runtime {

enum class OtaCoordinatorState : uint8_t {
  Idle = 0,
  DescriptorSending,
  AwaitingAuthorization,
  Sending,
  Repairing,
  Committing,
  Complete,
  Failed,
  Aborted,
};

enum class OtaCoordinatorEvent : uint8_t {
  DescriptorDeliveryConfirmed,
  DescriptorRejected,
  AuthorizationGranted,
  AuthorizationDenied,
  ChunkSent,
  ReceiptAllGood,
  ReceiptMissingDetected,
  RepairChunkSent,
  CommitVerified,
  CommitFailed,
  Abort,
};

class OtaCoordinatorStateMachine {
public:
  bool beginCampaign(const OtaSessionId& id) {
    if (state_ != OtaCoordinatorState::Idle && !isTerminal(state_)) return false;
    if (!guard_.acceptIfNewer(id)) return false;
    active_ = id;
    state_ = OtaCoordinatorState::DescriptorSending;
    return true;
  }

  bool handle(OtaCoordinatorEvent ev, const OtaSessionId& id) {
    if (state_ == OtaCoordinatorState::Idle) return false;
    if (!otaSessionEquals(id, active_)) return false;

    switch (state_) {
      case OtaCoordinatorState::DescriptorSending:
        switch (ev) {
          case OtaCoordinatorEvent::DescriptorDeliveryConfirmed:
            state_ = OtaCoordinatorState::AwaitingAuthorization;
            return true;
          case OtaCoordinatorEvent::DescriptorRejected:
            state_ = OtaCoordinatorState::Failed;
            return true;
          case OtaCoordinatorEvent::Abort:
            state_ = OtaCoordinatorState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaCoordinatorState::AwaitingAuthorization:
        switch (ev) {
          case OtaCoordinatorEvent::AuthorizationGranted:
            state_ = OtaCoordinatorState::Sending;
            return true;
          case OtaCoordinatorEvent::AuthorizationDenied:
            state_ = OtaCoordinatorState::Failed;
            return true;
          case OtaCoordinatorEvent::Abort:
            state_ = OtaCoordinatorState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaCoordinatorState::Sending:
        switch (ev) {
          case OtaCoordinatorEvent::ChunkSent:
            return true;
          case OtaCoordinatorEvent::ReceiptAllGood:
            state_ = OtaCoordinatorState::Committing;
            return true;
          case OtaCoordinatorEvent::ReceiptMissingDetected:
            state_ = OtaCoordinatorState::Repairing;
            return true;
          case OtaCoordinatorEvent::Abort:
            state_ = OtaCoordinatorState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaCoordinatorState::Repairing:
        switch (ev) {
          case OtaCoordinatorEvent::RepairChunkSent:
            return true;
          case OtaCoordinatorEvent::ReceiptMissingDetected:
            return true; // still-missing after a repair round: stay, keep repairing
          case OtaCoordinatorEvent::ReceiptAllGood:
            state_ = OtaCoordinatorState::Committing;
            return true;
          case OtaCoordinatorEvent::Abort:
            state_ = OtaCoordinatorState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaCoordinatorState::Committing:
        switch (ev) {
          case OtaCoordinatorEvent::CommitVerified:
            state_ = OtaCoordinatorState::Complete;
            return true;
          case OtaCoordinatorEvent::CommitFailed:
            state_ = OtaCoordinatorState::Failed;
            return true;
          case OtaCoordinatorEvent::Abort:
            state_ = OtaCoordinatorState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaCoordinatorState::Complete:
      case OtaCoordinatorState::Failed:
      case OtaCoordinatorState::Aborted:
      case OtaCoordinatorState::Idle:
      default:
        return false;
    }
  }

  void reset() { state_ = OtaCoordinatorState::Idle; }

  OtaCoordinatorState state() const { return state_; }
  const OtaSessionId& activeSession() const { return active_; }
  bool hasAcceptedSession() const { return guard_.hasAccepted(); }

private:
  static bool isTerminal(OtaCoordinatorState s) {
    return s == OtaCoordinatorState::Complete || s == OtaCoordinatorState::Failed || s == OtaCoordinatorState::Aborted;
  }

  OtaCoordinatorState state_ = OtaCoordinatorState::Idle;
  OtaSessionId active_{};
  OtaReplayGuard guard_;
};

} // namespace runtime
} // namespace ota
} // namespace meshcore
