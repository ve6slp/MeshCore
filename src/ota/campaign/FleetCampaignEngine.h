#pragma once

// Background fleet campaign engine (coordinator/controller side):
// frozen admitted cohort -> multicast bulk -> directed paginated census ->
// cohort/selective gap repair -> re-census (bounded to
// kCampaignMaxRepairRounds rounds) -> per-member PAIRWISE commit.
//
// Bounded, no-heap: at most kCampaignMaxFleetMembers (32) frozen cohort
// members are tracked. Each member's missing ranges are stored PER PAGE
// SLOT (not appended), so up to kCampaignMaxCensusPagesPerMember pages of
// up to kCampaignMaxMissingRangesPerPage entries each accumulate
// correctly regardless of arrival order or duplicate resends: a
// duplicate page idempotently overwrites its own slot, an out-of-order
// page is stored directly into its slot rather than depending on
// sequential arrival, and the true "no ranges missing" determination
// requires EVERY page 0..pageCount-1 to have been received with zero
// total entries across all of them -- a single empty final page can never
// paper over holes reported by an earlier page. Members still missing
// data after the round cap are surfaced explicitly via
// unresolvedMembers(); every other member proceeds to its own
// independent pairwise commit rather than being blocked on the
// unresolved ones.
//
// Group membership authorizes multicast/repair CHUNK DELIVERY only --
// NEVER a Census report's member identity. A Census report always
// requires a genuine authenticated Pairwise frame FROM the member it is
// reporting about (Group frames carry no peer identity at all, so they
// can never be attributed to a specific member's slot); see onFrame()/
// reportCensusPage() below. commitMember() always addresses a single
// peer with CampaignAuthScope::Pairwise, regardless of the campaign's
// group scope -- group membership never authorizes the per-member
// install/commit action either.
//
// onFrame() is the real wire-decoding entry point: it decodes the
// campaign envelope and, for a Census report, the actual
// CampaignCensusPagePayload bytes, validates the frame's authenticated
// context/session/round before ever mutating member state, and dispatches
// internally -- callers hand this raw authenticated frames, not
// pre-decoded structs.

#include <cstdint>
#include <cstddef>
#include <array>

#include "CampaignCommon.h"
#include "CampaignPorts.h"
#include "CampaignWire.h"
#include "../protocol/OtaMessages.h"
#include "../runtime/OtaFleetStateMachine.h"

namespace meshcore {
namespace ota {
namespace campaign {

// Bounded, no-heap per-member "confirmed missing" chunk bitmap sized to
// the worst-case full-image chunk count (kOtaMaxChunkCount = 5536 bits =
// 692 bytes). Bits are ONLY ever set from wire-reported missing-range
// entries -- the census wire format never reports "received" ranges, so
// no clear() is needed: reset() zeroes the bitmap at the start of a
// genuine census round, markMissing() accumulates reported ranges
// (idempotent, order-independent, handles overlapping ranges correctly),
// and countMissing()/extractRanges() give the authoritative current
// missing set once all declared pages for the round have arrived. This
// intentionally does NOT store raw per-page range lists (which would
// require kCampaignMaxCensusPagesPerMember * kCampaignMaxMissingRangesPerPage
// entries per member -- far too much RAM across kCampaignMaxFleetMembers
// members for the ~2768-range worst case of a full 708608-byte image).
class CampaignMemberMissingBitmap {
 public:
  static constexpr size_t kBits = runtime::kOtaMaxChunkCount;
  static constexpr size_t kWords = (kBits + 31) / 32;

  void reset(size_t activeBits) {
    activeBits_ = activeBits > kBits ? kBits : activeBits;
    words_.fill(0);
  }

  void markMissing(uint32_t start, uint32_t count) {
    uint64_t end = static_cast<uint64_t>(start) + count;
    if (end > activeBits_) end = activeBits_;
    for (uint64_t i = start; i < end; ++i) words_[i / 32] |= (1u << (i % 32));
  }

  size_t countMissing() const {
    size_t total = 0;
    for (uint32_t w : words_) {
      uint32_t v = w;
      while (v) {
        total += (v & 1u);
        v >>= 1;
      }
    }
    return total;
  }

  // Extracts contiguous missing-chunk ranges (bounded to maxOut entries,
  // never truncated silently beyond that caller-declared capacity).
  size_t extractRanges(CampaignMissingRangeEntry* out, size_t maxOut) const {
    size_t written = 0;
    size_t i = 0;
    while (i < activeBits_ && written < maxOut) {
      if (!test(i)) {
        ++i;
        continue;
      }
      size_t start = i;
      while (i < activeBits_ && test(i)) ++i;
      out[written].startChunkIndex = static_cast<uint32_t>(start);
      out[written].chunkCount = static_cast<uint32_t>(i - start);
      ++written;
    }
    return written;
  }

 private:
  bool test(size_t i) const { return (words_[i / 32] & (1u << (i % 32))) != 0; }
  std::array<uint32_t, kWords> words_{};
  size_t activeBits_ = 0;
};

// Worst case for a full kOtaMaxImageBytes image at kOtaDefaultChunkPayloadSize
// is ~kOtaMaxChunkCount/2 alternating missing/received chunks == ~2768
// disjoint ranges; at kCampaignMaxMissingRangesPerPage (8) ranges/page that
// is ceil(2768/8) = 346 pages -- bounded here to a byte-aligned 352.
inline constexpr size_t kCampaignMaxCensusPagesPerMember = 352;
inline constexpr size_t kCampaignPagesReceivedBitsetBytes = (kCampaignMaxCensusPagesPerMember + 7) / 8;

class FleetCampaignEngine {
public:
  explicit FleetCampaignEngine(IAuthenticatedTransportPort& transport) : transport_(transport) {}

  // Freezes the admitted cohort for this campaign attempt. Returns false
  // (no state change) if `count` exceeds kCampaignMaxFleetMembers or the
  // session id is stale/replayed. `chunkCount` is the total chunk count
  // of the campaign's geometry (defaults to the max supported image size
  // when the caller doesn't yet track per-campaign geometry) and sizes
  // every member's missing-chunk bitmap.
  bool beginCampaign(const runtime::OtaSessionId& id, uint32_t groupId,
                     const CampaignPeerId* cohort, size_t count,
                     uint32_t chunkCount = static_cast<uint32_t>(runtime::kOtaMaxChunkCount)) {
    if (count > kCampaignMaxFleetMembers) return false;
    if (!fleet_.beginCampaign(id)) return false;
    groupId_ = groupId;
    memberCount_ = count;
    round_ = 0;
    for (size_t i = 0; i < count; ++i) {
      members_[i] = MemberState{};
      members_[i].peerId = cohort[i];
      members_[i].chunkCount = chunkCount;
      members_[i].missingBitmap.reset(chunkCount);
    }
    announcementSent_ = false;
    censusWaitTicks_ = 0;
    roundStarted_ = false;
    repairCursor_ = 0;
    commitTemplateSet_ = false;
    allCommitDispatched_ = false;
    return true;
  }

  bool announceComplete() { return fleet_.handle(runtime::OtaFleetEvent::AnnounceComplete, fleet_.activeSession()); }
  bool multicastComplete() { return fleet_.handle(runtime::OtaFleetEvent::MulticastComplete, fleet_.activeSession()); }

  // Binds the commit template (campaign id/attempt/security counter) used
  // by tick()'s autonomous per-member commit dispatch in the Committing
  // state. Must be set before the engine reaches Committing or tick()
  // will no-op there (explicit gap, not a fabricated commit).
  void setCommitTemplate(const protocol::OtaCommitPayload& commit) {
    commitTemplate_ = commit;
    commitTemplateSet_ = true;
  }

  // Single bounded unit-of-work autonomous driver: performs AT MOST one
  // outbound send or one internal state transition per call, so a
  // caller's tick loop stays non-blocking. Returns true if this call did
  // something, false if there is nothing to do right now (waiting on an
  // external signal -- an inbound Census report via onFrame(), or the
  // externally-owned bulk multicast transport's completion signal in
  // Multicasting, which is a genuine cross-engine boundary since bulk
  // chunk transmission is owned by a Group-scoped UpdaterCampaignEngine
  // instance, not duplicated here).
  bool tick() {
    switch (fleet_.state()) {
      case runtime::OtaFleetState::Announcing:
        return tickAnnouncing();
      case runtime::OtaFleetState::Census:
        return tickCensus();
      case runtime::OtaFleetState::Multicasting:
        return false; // external bulk-transport completion signal (multicastComplete())
      case runtime::OtaFleetState::MissingCensus:
        return resolveMissingCensus();
      case runtime::OtaFleetState::Repairing:
        return tickRepairing();
      case runtime::OtaFleetState::Committing:
        return tickCommitting();
      default:
        return false; // CohortResolving is transient (folded into censusComplete()); terminal states no-op
    }
  }

  // Real wire-decoding dispatch entry point. Decodes the campaign
  // envelope; for a Census report, validates the frame is authenticated
  // and Pairwise-authenticated by the claimed member itself, that the
  // envelope session matches the active campaign, that the engine is
  // currently in a census-accepting state, and that the per-member
  // frame sequence is strictly fresher than the last accepted one --
  // BEFORE any member-state mutation. Returns false (no mutation) on any
  // validation failure.
  bool onFrame(const AuthenticatedInboundFrame& frame) {
    if (!frame.authenticated) { lastRefusal_ = CampaignRefusalReason::UntrustedContext; return false; }
    CampaignEnvelopeHeader hdr;
    const uint8_t* payload = nullptr;
    size_t payloadLen = 0;
    if (decodeCampaignEnvelope(frame.payload, frame.payloadLen, hdr, payload, payloadLen) != CampaignCodecResult::Ok) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }
    if (!runtime::otaSessionEquals(hdr.session, fleet_.activeSession())) {
      lastRefusal_ = CampaignRefusalReason::ForeignSession;
      return false;
    }
    if (hdr.type != CampaignMessageType::Census) {
      // Other campaign message types are handled by other engines
      // (TargetReceiverEngine/UpdaterCampaignEngine/DirectLeaseEngine);
      // this coordinator only consumes Census reports on its inbound path.
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }
    CampaignCensusPagePayload page;
    if (!decodeCampaignCensusPage(payload, payloadLen, page)) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }
    // A Census REPORT must always identify a single specific member --
    // it drives per-member accumulation/repair/commit state -- and a
    // Group-scoped frame carries NO authenticated peer identity at all
    // (see AuthenticatedInboundFrame), so it can NEVER be treated as an
    // identified member's report. Group scope only ever authorizes
    // multicast/repair CHUNK delivery (see class-level comment); it must
    // never be silently upgraded into "this is member X's census reply".
    if (!frame.isPairwise()) {
      lastRefusal_ = CampaignRefusalReason::UntrustedContext;
      return false;
    }
    return reportCensusPage(frame, hdr.frameSeq, frame.pairwise()->peerId, page);
  }

  // Accumulates one paginated census report from `peerId` into its
  // dedicated page slot. See class-level comment for the accumulation
  // contract. Rejects reports from a peer not in the frozen cohort, an
  // unauthenticated/non-pairwise frame (a Census report can only ever be
  // a genuine pairwise reply FROM the member it claims to be about -- see
  // onFrame() above), an inconsistent pageCount for an in-progress
  // multi-page report, or a stale (non-fresher) frame sequence -- all
  // before any mutation.
  bool reportCensusPage(const AuthenticatedInboundFrame& frame, uint32_t envelopeFrameSeq,
                         const CampaignPeerId& peerId, const CampaignCensusPagePayload& page) {
    // Accepted during Census (initial), MissingCensus (evaluating a prior
    // round) AND Repairing: a member may legitimately reply to its own
    // targeted repair request before the coordinator has finished
    // dispatching repair requests to every other still-missing member
    // (real async network delivery), so a re-census report arriving
    // mid-round must not be refused purely on state grounds.
    if (fleet_.state() != runtime::OtaFleetState::Census && fleet_.state() != runtime::OtaFleetState::MissingCensus &&
        fleet_.state() != runtime::OtaFleetState::Repairing) {
      lastRefusal_ = CampaignRefusalReason::ForeignSession;
      return false;
    }
    if (!frame.hasAuthenticatedPeer() || frame.pairwise()->peerId != peerId) {
      lastRefusal_ = CampaignRefusalReason::UntrustedContext;
      return false;
    }
    if (page.pageCount == 0 || page.pageCount > kCampaignMaxCensusPagesPerMember || page.pageIndex >= page.pageCount) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }
    // Binds this page to the coordinator's CURRENT round/generation: a
    // page delayed in flight across a repair-round restart (still
    // carrying the previous round's index) must not be folded into the
    // new round's accumulation, and a page from a round that hasn't
    // started yet is equally invalid.
    if (page.roundIndex != round_) {
      lastRefusal_ = CampaignRefusalReason::StaleCensusRound;
      return false;
    }
    MemberState* m = findMember(peerId);
    if (m == nullptr) { lastRefusal_ = CampaignRefusalReason::ForeignController; return false; }
    if (envelopeFrameSeq <= m->lastFrameSeq) { lastRefusal_ = CampaignRefusalReason::StaleReplay; return false; }

    // First page seen from this member for the (already-current) round:
    // reset whatever was accumulated for a previous round even if this
    // isn't page 0 (out-of-order round entry) -- a stale accumulation
    // must never leak across a repair-round restart.
    if (m->lastRound != page.roundIndex) {
      m->lastRound = page.roundIndex;
      m->pageCount = 0;
      m->pagesReceivedBits.fill(0);
      m->missingBitmap.reset(m->chunkCount);
    }

    // A page 0 (re)declares/restarts the round's pageCount and resets
    // accumulation; a duplicate/retried page 0 carrying the SAME
    // pageCount is idempotent and must not truncate other
    // already-received pages' contributions. Pages may legitimately
    // arrive OUT OF ORDER (page 1 before page 0): the very first page
    // ever seen for a member (pageCount still unestablished, i.e. 0)
    // opportunistically establishes the round's pageCount regardless of
    // its own index, so it is never rejected purely for not being index
    // 0. Once a pageCount has been established, any OTHER declared
    // pageCount from a non-zero-index page is rejected (protects against
    // a corrupt/malicious mid-round pageCount change) -- only page 0 may
    // authoritatively redeclare/restart it.
    if (m->pageCount != page.pageCount) {
      if (m->pageCount == 0 || page.pageIndex == 0) {
        m->pageCount = page.pageCount;
        m->pagesReceivedBits.fill(0);
        m->missingBitmap.reset(m->chunkCount);
      } else {
        lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
        return false;
      }
    }

    for (uint8_t i = 0; i < page.entryCount; ++i) {
      m->missingBitmap.markMissing(page.entries[i].startChunkIndex, page.entries[i].chunkCount);
    }
    m->setPageReceived(page.pageIndex);
    m->bytesReceived = page.bytesReceived;
    m->lastFrameSeq = envelopeFrameSeq;
    m->reported = true;

    m->hasFullImage = m->allPagesReceived() && (m->missingBitmap.countMissing() == 0);

    lastRefusal_ = CampaignRefusalReason::None;
    return true;
  }

  // Flattens one member's currently-accumulated missing ranges (from the
  // bitmap folded across however many pages have been received so far)
  // into a caller-owned fixed array. Returns the number written (bounded
  // to maxOut, never silently truncated beyond that caller-declared
  // capacity in a way that hides remaining ranges from repair targeting
  // -- callers should re-query in subsequent rounds for any remainder).
  size_t memberMissingRanges(const CampaignPeerId& peerId, CampaignMissingRangeEntry* outEntries, size_t maxOut) const {
    const MemberState* m = findMember(peerId);
    if (m == nullptr) return 0;
    return m->missingBitmap.extractRanges(outEntries, maxOut);
  }

  // Transitions Census -> CohortResolving -> Multicasting/Repairing
  // depending on outcome. Members that never reported are conservatively
  // treated as still missing (not silently assumed complete).
  bool censusComplete() {
    if (!fleet_.handle(runtime::OtaFleetEvent::CensusComplete, fleet_.activeSession())) return false;
    return fleet_.handle(runtime::OtaFleetEvent::CohortResolved, fleet_.activeSession());
  }

  bool allMembersComplete() const {
    if (memberCount_ == 0) return false;
    for (size_t i = 0; i < memberCount_; ++i) {
      if (!members_[i].reported || !members_[i].hasFullImage) return false;
    }
    return true;
  }

  // Writes up to `maxOut` peer ids of members still missing data into the
  // caller-owned array (directed selective repair targets).
  size_t missingMembers(CampaignPeerId* outPeers, size_t maxOut) const {
    size_t written = 0;
    for (size_t i = 0; i < memberCount_ && written < maxOut; ++i) {
      if (!members_[i].reported || !members_[i].hasFullImage) outPeers[written++] = members_[i].peerId;
    }
    return written;
  }

  // Decides between committing (nothing missing) and repairing (some
  // missing), matching OtaFleetStateMachine's MissingCensus state.
  bool resolveMissingCensus() {
    if (allMembersComplete()) {
      return fleet_.handle(runtime::OtaFleetEvent::NoneMissing, fleet_.activeSession());
    }
    if (roundCapExceeded()) {
      // Another repair round would just be refused by beginRepairRound():
      // proceed straight to Committing for whichever members ARE
      // resolved. unresolvedMembers() surfaces the rest explicitly rather
      // than blocking the whole campaign forever on an unreachable member.
      return fleet_.handle(runtime::OtaFleetEvent::NoneMissing, fleet_.activeSession());
    }
    return fleet_.handle(runtime::OtaFleetEvent::SomeMissing, fleet_.activeSession());
  }

  // Begins one bounded repair round. Fails (returns false, RoundCapExceeded)
  // once kCampaignMaxRepairRounds rounds have already been spent AND
  // members remain missing -- those members are surfaced via
  // unresolvedMembers(), other resolved members are not blocked.
  bool beginRepairRound() {
    if (round_ >= kCampaignMaxRepairRounds) {
      lastRefusal_ = CampaignRefusalReason::RoundCapExceeded;
      return false;
    }
    ++round_;
    return true;
  }

  bool repairRoundComplete() { return fleet_.handle(runtime::OtaFleetEvent::RepairRoundComplete, fleet_.activeSession()); }

  uint8_t roundsUsed() const { return round_; }
  bool roundCapExceeded() const { return round_ >= kCampaignMaxRepairRounds; }

  size_t unresolvedMembers(CampaignPeerId* outPeers, size_t maxOut) const {
    if (!roundCapExceeded()) return 0;
    return missingMembers(outPeers, maxOut);
  }

  // Per-member pairwise final commit dispatch: ALWAYS Pairwise scope, even
  // though census/repair traffic for this same campaign was Group-scoped.
  CampaignSendResult commitMember(const CampaignPeerId& peerId, const protocol::OtaCommitPayload& commit) {
    MemberState* m = findMember(peerId);
    if (m == nullptr) return CampaignSendResult::Rejected;
    if (!m->hasFullImage) return CampaignSendResult::Rejected; // never commit an unresolved member

    uint8_t payload[protocol::kOtaCommitPayloadSize];
    size_t payloadLen = 0;
    if (!protocol::encodeOtaCommit(commit, payload, sizeof(payload), payloadLen)) return CampaignSendResult::Rejected;

    CampaignEnvelopeHeader hdr;
    hdr.type = CampaignMessageType::Commit;
    hdr.session = fleet_.activeSession();
    hdr.frameSeq = ++frameSeqCounter_;

    uint8_t frame[protocol::kOtaMaxFrameSize];
    size_t frameLen = 0;
    if (encodeCampaignEnvelope(hdr, payload, payloadLen, frame, sizeof(frame), frameLen) != CampaignCodecResult::Ok) {
      return CampaignSendResult::Rejected;
    }

    CampaignDestination dest;
    dest.scope = CampaignAuthScope::Pairwise;
    dest.peerId = peerId;
    CampaignSendResult result = transport_.trySend(dest, protocol::OtaAirtimeCategory::Control, frame, frameLen);
    if (result == CampaignSendResult::Enqueued) {
      m->committed = (commit.verifiedOk != 0);
    }
    return result;
  }

  bool commitAll() { return fleet_.handle(runtime::OtaFleetEvent::CommitVerified, fleet_.activeSession()); }

  runtime::OtaFleetState state() const { return fleet_.state(); }
  size_t memberCount() const { return memberCount_; }
  CampaignRefusalReason lastRefusal() const { return lastRefusal_; }

private:
  bool sendEnvelope(CampaignMessageType type, const CampaignDestination& dest, const uint8_t* payload,
                     size_t payloadLen) {
    CampaignEnvelopeHeader hdr;
    hdr.type = type;
    hdr.session = fleet_.activeSession();
    hdr.frameSeq = ++frameSeqCounter_;
    uint8_t frame[protocol::kOtaMaxFrameSize];
    size_t frameLen = 0;
    if (encodeCampaignEnvelope(hdr, payload, payloadLen, frame, sizeof(frame), frameLen) != CampaignCodecResult::Ok) {
      return false;
    }
    return transport_.trySend(dest, protocol::OtaAirtimeCategory::Control, frame, frameLen) ==
           CampaignSendResult::Enqueued;
  }

  bool tickAnnouncing() {
    if (announcementSent_) return false;
    CampaignDestination dest;
    dest.scope = CampaignAuthScope::Group;
    dest.groupId = groupId_;
    // Announcement carries no ranges (entryCount 0); it exists purely to
    // solicit each cohort member's first census report.
    CampaignCensusPagePayload announce{};
    announce.roundIndex = round_;
    uint8_t payload[kCampaignMaxPayloadSize];
    size_t payloadLen = 0;
    if (!encodeCampaignCensusPage(announce, payload, sizeof(payload), payloadLen)) return false;
    if (!sendEnvelope(CampaignMessageType::Announcement, dest, payload, payloadLen)) return false;
    announcementSent_ = true;
    announceComplete();
    return true;
  }

  bool allMembersReported() const {
    for (size_t i = 0; i < memberCount_; ++i) {
      if (!members_[i].reported) return false;
    }
    return true;
  }

  bool tickCensus() {
    if (allMembersReported()) {
      censusWaitTicks_ = 0;
      return censusComplete();
    }
    if (++censusWaitTicks_ >= kCampaignCensusTimeoutTicks) {
      // Bounded timeout: proceed with whatever reported, remaining
      // silent members stay conservatively "missing" (see reportCensusPage
      // comment / allMembersComplete()) -- never blocks the campaign
      // forever on a single non-responsive member.
      censusWaitTicks_ = 0;
      return censusComplete();
    }
    return false;
  }

  bool tickRepairing() {
    if (!roundStarted_) {
      if (!beginRepairRound()) return false; // round cap: resolveMissingCensus's caller surfaces unresolvedMembers()
      roundStarted_ = true;
      repairCursor_ = 0;
    }
    while (repairCursor_ < memberCount_) {
      MemberState& m = members_[repairCursor_++];
      if (m.hasFullImage) continue; // resolved already; nothing to repair
      CampaignMissingRangeEntry ranges[kCampaignMaxMissingRangesPerPage];
      size_t n = m.missingBitmap.extractRanges(ranges, kCampaignMaxMissingRangesPerPage);
      CampaignCensusPagePayload repairReq{};
      repairReq.pageIndex = 0;
      repairReq.pageCount = 1;
      repairReq.roundIndex = round_;
      repairReq.entryCount = static_cast<uint8_t>(n);
      for (size_t i = 0; i < n; ++i) repairReq.entries[i] = ranges[i];
      uint8_t payload[kCampaignMaxPayloadSize];
      size_t payloadLen = 0;
      if (!encodeCampaignCensusPage(repairReq, payload, sizeof(payload), payloadLen)) continue;
      CampaignDestination dest;
      dest.scope = CampaignAuthScope::Pairwise; // targeted selective repair, always addressed to one member
      dest.peerId = m.peerId;
      sendEnvelope(CampaignMessageType::MissingRange, dest, payload, payloadLen);
      return true; // one bounded unit of work per tick call
    }
    // All missing members have their repair request sent this round;
    // reset each reporting member's "reported"/page state so the next
    // re-census round genuinely re-confirms (rather than trusting stale
    // per-member accumulation from before the repair was even sent).
    for (size_t i = 0; i < memberCount_; ++i) {
      if (!members_[i].hasFullImage) members_[i].reported = false;
    }
    roundStarted_ = false;
    return repairRoundComplete();
  }

  bool tickCommitting() {
    if (!commitTemplateSet_) return false; // explicit adapter gap: caller must setCommitTemplate() first
    for (size_t i = 0; i < memberCount_; ++i) {
      MemberState& m = members_[i];
      if (m.committed || !m.hasFullImage) continue;
      commitMember(m.peerId, commitTemplate_);
      return true; // one bounded unit of work per tick call
    }
    if (!allCommitDispatched_) {
      allCommitDispatched_ = true;
      commitAll();
      return true;
    }
    return false;
  }

  struct MemberState {
    CampaignPeerId peerId{};
    bool reported = false;
    bool hasFullImage = false;
    bool committed = false;
    uint32_t bytesReceived = 0;
    uint32_t lastFrameSeq = 0;
    uint16_t pageCount = 0;
    uint32_t chunkCount = 0;
    uint8_t lastRound = 0; // round/generation this member's accumulated pages belong to
    // Bit i set == page i has been received for the CURRENT round (sized
    // for the real worst-case page count, not the old 8-bit/8-page cap).
    std::array<uint8_t, kCampaignPagesReceivedBitsetBytes> pagesReceivedBits{};
    CampaignMemberMissingBitmap missingBitmap;

    void setPageReceived(uint16_t idx) { pagesReceivedBits[idx / 8] |= static_cast<uint8_t>(1u << (idx % 8)); }
    bool isPageReceived(uint16_t idx) const { return (pagesReceivedBits[idx / 8] & (1u << (idx % 8))) != 0; }
    bool allPagesReceived() const {
      if (pageCount == 0) return false;
      for (uint16_t i = 0; i < pageCount; ++i) {
        if (!isPageReceived(i)) return false;
      }
      return true;
    }
  };

  MemberState* findMember(const CampaignPeerId& peerId) {
    for (size_t i = 0; i < memberCount_; ++i) {
      if (members_[i].peerId == peerId) return &members_[i];
    }
    return nullptr;
  }
  const MemberState* findMember(const CampaignPeerId& peerId) const {
    for (size_t i = 0; i < memberCount_; ++i) {
      if (members_[i].peerId == peerId) return &members_[i];
    }
    return nullptr;
  }

  IAuthenticatedTransportPort& transport_;
  runtime::OtaFleetStateMachine fleet_;
  std::array<MemberState, kCampaignMaxFleetMembers> members_{};
  size_t memberCount_ = 0;
  uint32_t groupId_ = 0;
  uint8_t round_ = 0;
  uint32_t frameSeqCounter_ = 0;
  CampaignRefusalReason lastRefusal_ = CampaignRefusalReason::None;

  bool announcementSent_ = false;
  uint32_t censusWaitTicks_ = 0;
  static constexpr uint32_t kCampaignCensusTimeoutTicks = 64;
  bool roundStarted_ = false;
  size_t repairCursor_ = 0;
  protocol::OtaCommitPayload commitTemplate_{};
  bool commitTemplateSet_ = false;
  bool allCommitDispatched_ = false;
};

} // namespace campaign
} // namespace ota
} // namespace meshcore
