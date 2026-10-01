#pragma once

// Shared bounds, identity and enum types for the campaign/receiver engine
// layer (src/ota/campaign/). This layer is a portable orchestration core
// built ON TOP OF the existing wire/runtime/trust/storage primitives in
// src/ota/{protocol,runtime,trust}; it introduces no cryptography of its
// own and performs no direct flash access -- every side effect (sending a
// frame, persisting state, writing image bytes, changing the radio
// profile, reading the wall clock, confirming a healthy boot) goes through
// an injectable port defined in CampaignPorts.h, so this module can be
// linked into real firmware or a native test with equal fidelity.
//
// Bounded resource ceilings (fixed at compile time, no heap, no dynamic
// growth):
//   - kCampaignMaxInFlightChunks: chunk pipeline depth for both the
//     updater (sender) and the direct/directed transfer paths.
//   - kCampaignMaxFleetMembers: frozen cohort size for a background fleet
//     campaign.
//   - kCampaignMaxMissingRangesPerPage: paginated census/repair page width.
//   - kCampaignMaxRepairRounds: census -> repair -> re-census round cap
//     before remaining members are reported unresolved (not blocked).

#include <cstdint>
#include <cstddef>
#include "../runtime/OtaSessionIdentity.h"

namespace meshcore {
namespace ota {
namespace campaign {

inline constexpr uint32_t kCampaignMaxInFlightChunks = 4;
inline constexpr size_t kCampaignMaxFleetMembers = 32;
inline constexpr size_t kCampaignMaxMissingRangesPerPage = 8;
inline constexpr uint8_t kCampaignMaxRepairRounds = 3;

// Bounded per-connection anti-replay window (directed/target inbound
// frameSeq and fleet/census paging alike): accepts a genuinely-unseen
// sequence number within this many steps BEHIND the highest ever seen
// (legitimate network reordering, not a replay), while still rejecting an
// EXACT duplicate of any sequence already recorded seen. A strict
// monotonic "must be greater than the last accepted" check is NOT
// sufficient: real transport reordering can deliver a later-generated
// higher sequence before an earlier-generated lower one, and naively
// rejecting the lower one as "stale" would silently discard legitimate
// never-before-seen data.
inline constexpr uint32_t kCampaignReplayWindowSize = 4;

// Bounded clock-driven retry timeouts for control/reply traffic whose
// loss must not stall a transfer forever. "Enqueued" (accepted into the
// transport's send queue) is NOT the same event as "actually
// transmitted", and even a genuinely-transmitted frame's reply can still
// be lost -- these bound how long to wait for the expected reply/receipt
// before resending the ORIGINAL already-encoded frame bytes.
inline constexpr uint32_t kCampaignControlRetryTimeoutMs = 2000;
inline constexpr uint8_t kCampaignControlMaxRetries = 5;
inline constexpr uint32_t kCampaignReplyRetryTimeoutMs = 1000;

// Bounded anti-replay window check shared by every per-connection frame
// sequence in this layer (target inbound chunk/control traffic AND the
// updater's inbound receipt traffic): accepts `seq` if it is either newer
// than everything seen so far, or legitimately unseen-but-within-window
// behind the current highest (real network reordering) -- rejects only an
// EXACT duplicate of an already-recorded sequence, or one too far behind
// the window to track. Pure function: never mutates any caller state, so
// callers can compute the candidate's next (lastSeq, mask) and only
// durably commit/apply it once the corresponding side effect (a durable
// persist, or an in-memory ack) has actually happened, mirroring this
// layer's "no ACK without a durable/confirmed effect" discipline.
inline bool campaignReplayWindowCheck(uint32_t currentLastSeq, uint32_t currentMask, uint32_t seq,
                                       uint32_t& outLastSeq, uint32_t& outMask) {
  if (seq > currentLastSeq) {
    uint64_t shift = static_cast<uint64_t>(seq) - currentLastSeq;
    outMask = (shift >= 32u) ? 0u : (currentMask << shift);
    outMask |= 0x1u; // seq itself is the new highest, now seen
    outLastSeq = seq;
    return true;
  }
  uint32_t age = currentLastSeq - seq;
  if (age >= kCampaignReplayWindowSize) { return false; } // beyond tracked window: treat as stale
  uint32_t bit = 1u << age;
  if ((currentMask & bit) != 0) { return false; } // exact duplicate already accepted
  outLastSeq = currentLastSeq;
  outMask = currentMask | bit;
  return true;
}


// Full 32-byte peer/controller identity. This is an opaque, already-
// provisioned public identity handle (e.g. a device's Ed25519 public key
// or a hash thereof) -- this layer never derives, mints or self-signs one.
struct CampaignPeerId {
  uint8_t bytes[32] = {};

  bool operator==(const CampaignPeerId& other) const {
    for (size_t i = 0; i < sizeof(bytes); ++i) {
      if (bytes[i] != other.bytes[i]) return false;
    }
    return true;
  }
  bool operator!=(const CampaignPeerId& other) const { return !(*this == other); }
  bool isZero() const {
    for (uint8_t b : bytes) {
      if (b != 0) return false;
    }
    return true;
  }
};

// Authorization scope for a campaign action. Group membership alone NEVER
// authorizes a pairwise lease/abort/install/control action -- those always
// require a Pairwise-scoped, controller-bound authenticated context.
enum class CampaignAuthScope : uint8_t {
  Pairwise = 0,
  Group = 1,
};

// Explicit reason codes surfaced by refusal/failure/unresolved outcomes.
// Never a silent/default success; every refusal is one of these.
enum class CampaignRefusalReason : uint8_t {
  None = 0,
  UntrustedContext = 1,        // frame lacked verified identity/scope
  ForeignController = 2,       // sender is not the bound controller for this session
  ForeignSession = 3,          // campaign/session/attempt does not match the active one
  StaleReplay = 4,             // session or frame sequence was not strictly newer
  DescriptorInvalid = 5,       // signature/policy verification failed
  GeometryInvalid = 6,
  StagingRejected = 7,
  StagingIoError = 8,
  HashMismatch = 9,
  TransportBackpressure = 10,  // enqueue deferred, not a failure
  TransportRejected = 11,
  BudgetDenied = 12,           // airtime/budget grant denied by dispatcher owner
  Timeout = 13,
  Aborted = 14,
  InvalidRadioProfile = 15,
  BootNotConfirmed = 16,       // image installed but healthy-boot evidence absent
  RoundCapExceeded = 17,       // repair rounds exhausted with members still missing
  GroupNotAuthorizedForPairwise = 18,
  PersistenceFailed = 19,      // durable checkpoint write/readback failed -- no ACK given
  DescriptorConflict = 20,     // same session+controller tuple, DIFFERENT descriptor content
  ConsentPolicyDenied = 21,    // local site/operator consent policy refused
  BootEvidenceMismatch = 22,   // boot evidence did not bind to the exact image/session/counter
  LeaseGrantPolicyDenied = 23, // local site/board policy refused a direct-lease grant
  InvalidLeaseEpoch = 24,      // requested epoch/watchdog duration outside bounded range
  UnresolvedPersistedState = 25, // load() returned Corrupt/IoError; admission blocked until explicit repair
  StaleCensusRound = 26,        // census page's roundIndex does not match the fleet coordinator's current round
  CommissioningProvenanceUnknown = 27, // independent commissioning-provenance backing is Unknown -- default-deny
  RepairAuthorizationRetirementUnconfirmed = 28, // a prior repair-authorization record could not be durably
                                                  // retired before this new admission -- refused before any
                                                  // mutation rather than risk a stale grant later licensing
                                                  // loss of THIS new admission's record.
};

} // namespace campaign
} // namespace ota
} // namespace meshcore
