#pragma once

// Shared session identity (campaign/session/attempt) and replay-isolation
// guard used by every OTA state machine (receiver, coordinator, fleet).

#include <cstdint>

namespace meshcore {
namespace ota {
namespace runtime {

struct OtaSessionId {
  uint32_t campaignId = 0;
  uint32_t sessionId = 0;
  uint16_t attemptId = 0;
};

// Lexicographic ordering: campaignId, then sessionId, then attemptId.
inline bool otaSessionIsNewer(const OtaSessionId& a, const OtaSessionId& b) {
  if (a.campaignId != b.campaignId) return a.campaignId > b.campaignId;
  if (a.sessionId != b.sessionId) return a.sessionId > b.sessionId;
  return a.attemptId > b.attemptId;
}

inline bool otaSessionEquals(const OtaSessionId& a, const OtaSessionId& b) {
  return a.campaignId == b.campaignId && a.sessionId == b.sessionId && a.attemptId == b.attemptId;
}

// Tracks the most recently accepted session identity across resets/terminal
// transitions so a stale or replayed (campaign, session, attempt) tuple can
// never resurrect (or interleave with) an already-superseded run.
class OtaReplayGuard {
public:
  // Returns true and records `id` as the new "last accepted" iff `id` is
  // strictly newer than whatever was last accepted (or nothing has been
  // accepted yet). Returns false (replay/stale, no state change) otherwise.
  bool acceptIfNewer(const OtaSessionId& id) {
    if (has_ && !otaSessionIsNewer(id, last_)) return false;
    last_ = id;
    has_ = true;
    return true;
  }

  const OtaSessionId& last() const { return last_; }
  bool hasAccepted() const { return has_; }

private:
  OtaSessionId last_{};
  bool has_ = false;
};

} // namespace runtime
} // namespace ota
} // namespace meshcore
