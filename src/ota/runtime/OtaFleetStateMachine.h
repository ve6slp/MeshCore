#pragma once

// Bounded fleet-update pipeline: Announcement -> Census -> Cohort
// resolution -> Multicast -> Missing census -> directed selective Repair ->
// verified Commit.
//
// The census/repair registry is fixed-capacity (no heap): `MaxFleetSize`
// bounds the number of concurrently tracked fleet members and every output
// (missing-node list, repair targets) is written into caller-owned fixed
// arrays.

#include <cstdint>
#include <cstddef>
#include <array>
#include "OtaSessionIdentity.h"

namespace meshcore {
namespace ota {
namespace runtime {

enum class OtaFleetState : uint8_t {
  Idle = 0,
  Announcing,
  Census,
  CohortResolving,
  Multicasting,
  MissingCensus,
  Repairing,
  Committing,
  Complete,
  Failed,
  Aborted,
};

enum class OtaFleetEvent : uint8_t {
  AnnounceComplete,
  CensusComplete,
  CensusTimeout,
  CohortResolved,
  MulticastComplete,
  NoneMissing,
  SomeMissing,
  RepairRoundComplete,
  CommitVerified,
  CommitFailed,
  Abort,
};

class OtaFleetStateMachine {
public:
  bool beginCampaign(const OtaSessionId& id) {
    if (state_ != OtaFleetState::Idle && !isTerminal(state_)) return false;
    if (!guard_.acceptIfNewer(id)) return false;
    active_ = id;
    state_ = OtaFleetState::Announcing;
    return true;
  }

  bool handle(OtaFleetEvent ev, const OtaSessionId& id) {
    if (state_ == OtaFleetState::Idle) return false;
    if (!otaSessionEquals(id, active_)) return false;

    switch (state_) {
      case OtaFleetState::Announcing:
        switch (ev) {
          case OtaFleetEvent::AnnounceComplete:
            state_ = OtaFleetState::Census;
            return true;
          case OtaFleetEvent::Abort:
            state_ = OtaFleetState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaFleetState::Census:
        switch (ev) {
          case OtaFleetEvent::CensusComplete:
            state_ = OtaFleetState::CohortResolving;
            return true;
          case OtaFleetEvent::CensusTimeout:
            state_ = OtaFleetState::Failed;
            return true;
          case OtaFleetEvent::Abort:
            state_ = OtaFleetState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaFleetState::CohortResolving:
        switch (ev) {
          case OtaFleetEvent::CohortResolved:
            state_ = OtaFleetState::Multicasting;
            return true;
          case OtaFleetEvent::Abort:
            state_ = OtaFleetState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaFleetState::Multicasting:
        switch (ev) {
          case OtaFleetEvent::MulticastComplete:
            state_ = OtaFleetState::MissingCensus;
            return true;
          case OtaFleetEvent::Abort:
            state_ = OtaFleetState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaFleetState::MissingCensus:
        switch (ev) {
          case OtaFleetEvent::NoneMissing:
            state_ = OtaFleetState::Committing;
            return true;
          case OtaFleetEvent::SomeMissing:
            state_ = OtaFleetState::Repairing;
            return true;
          case OtaFleetEvent::Abort:
            state_ = OtaFleetState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaFleetState::Repairing:
        switch (ev) {
          case OtaFleetEvent::RepairRoundComplete:
            state_ = OtaFleetState::MissingCensus; // re-census to check convergence
            return true;
          case OtaFleetEvent::Abort:
            state_ = OtaFleetState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaFleetState::Committing:
        switch (ev) {
          case OtaFleetEvent::CommitVerified:
            state_ = OtaFleetState::Complete;
            return true;
          case OtaFleetEvent::CommitFailed:
            state_ = OtaFleetState::Failed;
            return true;
          case OtaFleetEvent::Abort:
            state_ = OtaFleetState::Aborted;
            return true;
          default:
            return false;
        }

      case OtaFleetState::Complete:
      case OtaFleetState::Failed:
      case OtaFleetState::Aborted:
      case OtaFleetState::Idle:
      default:
        return false;
    }
  }

  void reset() { state_ = OtaFleetState::Idle; }

  OtaFleetState state() const { return state_; }
  const OtaSessionId& activeSession() const { return active_; }
  bool hasAcceptedSession() const { return guard_.hasAccepted(); }

private:
  static bool isTerminal(OtaFleetState s) {
    return s == OtaFleetState::Complete || s == OtaFleetState::Failed || s == OtaFleetState::Aborted;
  }

  OtaFleetState state_ = OtaFleetState::Idle;
  OtaSessionId active_{};
  OtaReplayGuard guard_;
};

// Fixed-capacity (no heap) per-campaign fleet membership/progress registry,
// used to drive directed selective repair and to bound reports to a fleet
// of at most `MaxFleetSize` tracked members.
template <size_t MaxFleetSize>
class OtaFleetCensus {
public:
  static constexpr size_t kMaxMembers = MaxFleetSize;

  void reset() {
    count_ = 0;
    members_.fill(Member{});
  }

  // Inserts a new member or updates an existing one's reported progress.
  // Fails closed (returns false) once kMaxMembers distinct nodes have been
  // registered and `nodeId` is not already one of them -- the fleet report
  // is bounded and never grows without limit.
  bool reportMember(uint32_t nodeId, bool hasFullImage, uint32_t bytesReceived) {
    for (size_t i = 0; i < count_; ++i) {
      if (members_[i].nodeId == nodeId) {
        members_[i].hasFullImage = hasFullImage;
        members_[i].bytesReceived = bytesReceived;
        return true;
      }
    }
    if (count_ >= kMaxMembers) return false;
    members_[count_] = Member{nodeId, hasFullImage, bytesReceived};
    ++count_;
    return true;
  }

  size_t memberCount() const { return count_; }

  bool allComplete() const {
    if (count_ == 0) return false;
    for (size_t i = 0; i < count_; ++i) {
      if (!members_[i].hasFullImage) return false;
    }
    return true;
  }

  // Writes up to maxOut node ids of members still missing the full image
  // (directed selective repair targets) into the caller-owned fixed array.
  // Returns the number written.
  size_t missingMembers(uint32_t* outNodeIds, size_t maxOut) const {
    size_t written = 0;
    for (size_t i = 0; i < count_ && written < maxOut; ++i) {
      if (!members_[i].hasFullImage) outNodeIds[written++] = members_[i].nodeId;
    }
    return written;
  }

private:
  struct Member {
    uint32_t nodeId = 0;
    bool hasFullImage = false;
    uint32_t bytesReceived = 0;
  };

  std::array<Member, kMaxMembers> members_{};
  size_t count_ = 0;
};

inline constexpr size_t kOtaDefaultMaxFleetSize = 64;
using OtaDefaultFleetCensus = OtaFleetCensus<kOtaDefaultMaxFleetSize>;

} // namespace runtime
} // namespace ota
} // namespace meshcore
