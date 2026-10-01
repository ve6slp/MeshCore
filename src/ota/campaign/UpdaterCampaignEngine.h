#pragma once

// Updater campaign engine (cache-only): begin/write/seal an image into a
// CACHE-ONLY sink, validate exact size/chunk geometry, rehash-seal against
// the signed descriptor, and autonomously retransmit the SEALED cache to a
// bound target after the originating host has disconnected.
//
// This engine owns NO install policy and NEVER mutates any install/boot
// floor: its constructor only accepts IOtaCacheOnlySink (CampaignPorts.h),
// a type that is structurally incapable of installing/committing to boot,
// so it can never be accidentally wired to an install-capable sink.
//
// Two DISTINCT image sources are used deliberately: `hostImageReader_`
// (IImageReaderPort) supplies bytes only while caching from the still-
// connected host in cacheNextChunk(); the SEALED CACHE itself (read back
// via `cache_.readCachedAt()`) is the ONLY source ever used by the
// autonomous post-seal retransmission path in tickTransmit(), so a host
// source that has gone away after disconnect can never be silently
// substituted with stale/wrong bytes.
//
// `outcome() == Complete` requires BOTH a locally sealed cache AND an
// authenticated inbound Receipt reporting TransferComplete from the bound
// destination -- local sealing alone is never reported as campaign
// completion.

#include <cstdint>
#include <cstddef>
#include <array>

#include "CampaignCommon.h"
#include "CampaignPorts.h"
#include "CampaignWire.h"
#include "../protocol/OtaDescriptor.h"
#include "../protocol/OtaMessages.h"
#include "../runtime/OtaGeometry.h"
#include "../runtime/OtaCoordinatorStateMachine.h"
#include "../runtime/OtaTrustInterfaces.h"

namespace meshcore {
namespace ota {
namespace campaign {

enum class UpdaterOutcome : uint8_t {
  InProgress = 0,
  Complete = 1,   // sealed AND remote-confirmed TransferComplete
  Refused = 2,
};

class UpdaterCampaignEngine {
public:
  UpdaterCampaignEngine(runtime::IOtaTrustProvider& trust, IOtaCacheOnlySink& cache,
                         IAuthenticatedTransportPort& transport, IImageReaderPort& hostImageReader,
                         IClockPort& clock)
      : trust_(trust), cache_(cache), transport_(transport), hostImageReader_(hostImageReader), clock_(clock) {}

  // Starts caching a new campaign attempt bound to a single target/cohort
  // destination. Requires the descriptor to pass signature+policy
  // verification BEFORE any staging side effect. Returns false (no state
  // change) for a stale/replayed session id or a descriptor that fails
  // verification. Fully resets every counter/window/flag from any prior
  // attempt -- a stale sealed cache from a completed/aborted PRIOR
  // campaign can never be (re)transmitted as if it were the new image.
  // `selfId` is this controller's own full identity, embedded in the
  // ConsentRequest sent autonomously by tick() (the receiving side binds
  // authorization to the frame's OWN authenticated identity, never to
  // this field alone -- see TargetReceiverEngine::handleConsentRequest).
  bool begin(const runtime::OtaSessionId& id, const protocol::OtaDescriptor& descriptor,
             const uint8_t* signature, size_t signatureLen, const CampaignDestination& dest,
             const CampaignPeerId& selfId = CampaignPeerId{}) {
    if (!trust_.verifyDescriptor(descriptor, signature, signatureLen)) {
      lastRefusal_ = CampaignRefusalReason::DescriptorInvalid;
      return false;
    }
    if (signatureLen > signature_.size()) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }
    runtime::OtaGeometry geometry;
    if (runtime::OtaGeometry::compute(descriptor.exactSizeBytes, runtime::kOtaDefaultChunkPayloadSize,
                                       runtime::kOtaMaxImageBytes, geometry) != runtime::OtaGeometryResult::Ok) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }
    if (!coordinator_.beginCampaign(id)) {
      lastRefusal_ = CampaignRefusalReason::StaleReplay;
      return false;
    }
    if (cache_.beginCache(descriptor) != IOtaCacheOnlySink::Result::Ok) {
      lastRefusal_ = CampaignRefusalReason::StagingRejected;
      coordinator_.handle(runtime::OtaCoordinatorEvent::Abort, id);
      return false;
    }
    descriptor_ = descriptor;
    geometry_ = geometry;
    dest_ = dest;
    selfId_ = selfId;
    std::memcpy(signature_.data(), signature, signatureLen);
    signatureLen_ = signatureLen;
    nextChunkToCache_ = 0;
    cachedComplete_ = false;
    sealed_ = false;
    remoteConfirmed_ = false;
    remoteFailed_ = false;
    frameSeqCounter_ = 0;
    lastReceiptFrameSeq_ = 0;
    receiptReplayMask_ = 0;
    ackedCount_ = 0;
    consentSent_ = false;
    descriptorSent_ = false;
    consentGranted_ = false;
    commitSent_ = false;
    controlPhaseSentAtMs_ = 0;
    consentRetryCount_ = 0;
    commitSentAtMs_ = 0;
    commitRetryCount_ = 0;
    inFlight_.reset();
    lastRefusal_ = CampaignRefusalReason::None;
    coordinator_.handle(runtime::OtaCoordinatorEvent::DescriptorDeliveryConfirmed, id);
    return true;
  }

  // Pulls the next chunk from the HOST image reader and writes it into
  // the cache-only sink (the actual "cache write" side effect). Bounded:
  // caches at most one chunk per call so a caller's tick loop stays
  // non-blocking. Returns false once every chunk has already been cached
  // (idempotent) -- this is the ONLY method that ever touches
  // `hostImageReader_`.
  bool cacheNextChunk() {
    if (cachedComplete_ || nextChunkToCache_ >= geometry_.chunkCount) return false;
    uint32_t len = 0;
    if (!geometry_.chunkLength(nextChunkToCache_, len)) return false;
    uint64_t offset = 0;
    if (!geometry_.chunkOffset(nextChunkToCache_, offset)) return false;

    uint8_t buf[runtime::kOtaDefaultChunkPayloadSize];
    if (!hostImageReader_.readAt(offset, buf, len)) {
      lastRefusal_ = CampaignRefusalReason::StagingIoError;
      return false;
    }
    if (cache_.writeChunk(offset, buf, len) != IOtaCacheOnlySink::Result::Ok) {
      lastRefusal_ = CampaignRefusalReason::StagingIoError;
      return false;
    }
    ++nextChunkToCache_;
    if (nextChunkToCache_ >= geometry_.chunkCount) cachedComplete_ = true;
    return true;
  }

  // Rehashes the sealed cache against the signed descriptor and commits
  // the CACHE (never an install). Only legal once every chunk has been
  // cached; never claims completion otherwise.
  bool sealCache() {
    if (!cachedComplete_) return false;
    IOtaCacheOnlySink::Result r = cache_.sealCache();
    if (r == IOtaCacheOnlySink::Result::Rejected) {
      lastRefusal_ = CampaignRefusalReason::HashMismatch;
      return false;
    }
    if (r != IOtaCacheOnlySink::Result::Ok) {
      lastRefusal_ = CampaignRefusalReason::StagingIoError;
      return false;
    }
    sealed_ = true;
    return true;
  }

  // Autonomous paced retransmission tick: sends at most one chunk per call
  // -- either the next never-yet-sent index (if the in-flight window has a
  // free slot) or, once retryTimeoutMs has elapsed since a slot's last send
  // with no receipt, a fresh-frameSeq retransmission of that same slot's
  // chunk. Bytes are ALWAYS read back from the sealed cache
  // (`cache_.readCachedAt`), never from the host reader. Respects
  // transport backpressure/budget denial rather than busy-looping or
  // fabricating an ACK on a failed send.
  CampaignSendResult tickTransmit(uint32_t retryTimeoutMs = 2000) {
    if (!sealed_) return CampaignSendResult::Rejected;
    uint32_t nextIndex = 0;
    bool isRetry = false;
    if (!inFlight_.nextToSend(geometry_.chunkCount, clock_.nowMs(), retryTimeoutMs, nextIndex, isRetry)) {
      return CampaignSendResult::Rejected;
    }
    if (!isRetry && inFlight_.countInFlight() >= kCampaignMaxInFlightChunks) {
      return CampaignSendResult::Backpressure;
    }

    uint32_t len = 0;
    uint64_t offset = 0;
    if (!geometry_.chunkLength(nextIndex, len) || !geometry_.chunkOffset(nextIndex, offset)) {
      return CampaignSendResult::Rejected;
    }
    uint8_t data[runtime::kOtaDefaultChunkPayloadSize];
    if (!cache_.readCachedAt(offset, data, len)) return CampaignSendResult::Rejected;

    uint8_t chunkBuf[protocol::kOtaChunkHeaderSize + runtime::kOtaDefaultChunkPayloadSize];
    protocol::OtaChunkHeader chdr{nextIndex, static_cast<uint16_t>(len)};
    size_t chunkLen = 0;
    if (!protocol::encodeOtaChunk(chdr, data, len, chunkBuf, sizeof(chunkBuf), chunkLen)) {
      return CampaignSendResult::Rejected;
    }

    CampaignEnvelopeHeader hdr;
    hdr.type = CampaignMessageType::Chunk;
    hdr.session = coordinator_.activeSession();
    hdr.frameSeq = ++frameSeqCounter_;

    uint8_t frame[protocol::kOtaMaxFrameSize];
    size_t frameLen = 0;
    if (encodeCampaignEnvelope(hdr, chunkBuf, chunkLen, frame, sizeof(frame), frameLen) != CampaignCodecResult::Ok) {
      return CampaignSendResult::Rejected;
    }

    CampaignSendResult result = transport_.trySend(dest_, protocol::OtaAirtimeCategory::Relay, frame, frameLen);
    if (result == CampaignSendResult::Enqueued) {
      inFlight_.markSent(nextIndex, clock_.nowMs());
      coordinator_.handle(runtime::OtaCoordinatorEvent::ChunkSent, coordinator_.activeSession());
    }
    return result;
  }

  // Applies an inbound Receipt frame. Requires an authenticated, Pairwise
  // per-member acknowledgement with a strictly fresh per-frame sequence,
  // bound to the EXACT expected destination peer. A Group-destination
  // bulk campaign has NO single expected peer at this layer -- tracking
  // which specific cohort members legitimately report is FLEET's job
  // (FleetCampaignEngine's admitted-cohort/per-member state), never "any
  // authenticated peer" accepted here as if it were the one expected
  // controller. A ChunkAck frees that slot from the in-flight window; a
  // TransferComplete/TransferFailed report is the ONLY thing that can
  // ever move `outcome()` to Complete/Refused.
  bool applyReceipt(const AuthenticatedInboundFrame& frame, uint32_t envelopeFrameSeq,
                     const runtime::OtaSessionId& id, const protocol::OtaReceiptPayload& receipt) {
    if (!frame.hasAuthenticatedPeer()) {
      lastRefusal_ = CampaignRefusalReason::UntrustedContext;
      return false;
    }
    if (dest_.scope != CampaignAuthScope::Pairwise || frame.pairwise()->peerId != dest_.peerId) {
      lastRefusal_ = CampaignRefusalReason::ForeignController;
      return false;
    }
    if (!runtime::otaSessionEquals(id, coordinator_.activeSession())) {
      lastRefusal_ = CampaignRefusalReason::ForeignSession;
      return false;
    }
    // Bounded anti-replay window (same discipline as
    // TargetReceiverEngine's inbound frame handling): a genuinely
    // reordered lower original sequence must still be accepted, not
    // rejected merely because it did not arrive in increasing order --
    // only an exact duplicate or one too far behind the window is stale.
    uint32_t newLastReceiptFrameSeq = 0, newReceiptReplayMask = 0;
    if (!campaignReplayWindowCheck(lastReceiptFrameSeq_, receiptReplayMask_, envelopeFrameSeq,
                                    newLastReceiptFrameSeq, newReceiptReplayMask)) {
      lastRefusal_ = CampaignRefusalReason::StaleReplay;
      return false;
    }
    lastReceiptFrameSeq_ = newLastReceiptFrameSeq;
    receiptReplayMask_ = newReceiptReplayMask;

    switch (receipt.status) {
      case protocol::OtaReceiptStatus::ChunkAck:
        inFlight_.acknowledge(receipt.chunkIndex);
        ++ackedCount_;
        return true;
      case protocol::OtaReceiptStatus::ChunkNack:
        return true; // legal no-op: retry-on-timeout will resend
      case protocol::OtaReceiptStatus::TransferComplete:
        remoteConfirmed_ = true;
        coordinator_.handle(runtime::OtaCoordinatorEvent::CommitVerified, id);
        return true;
      case protocol::OtaReceiptStatus::TransferFailed:
        remoteFailed_ = true;
        lastRefusal_ = CampaignRefusalReason::HashMismatch;
        coordinator_.handle(runtime::OtaCoordinatorEvent::CommitFailed, id);
        return true;
      default:
        return false;
    }
  }

  // Single production inbound entry point: decodes the envelope and
  // routes ConsentGrant/Receipt traffic to the correct internal handler,
  // replacing a driver hand-decoding frames and calling applyReceipt
  // directly with a pre-decoded payload.
  bool onFrame(const AuthenticatedInboundFrame& frame) {
    if (!frame.authenticated) { lastRefusal_ = CampaignRefusalReason::UntrustedContext; return false; }
    CampaignEnvelopeHeader hdr;
    const uint8_t* payload = nullptr;
    size_t payloadLen = 0;
    if (decodeCampaignEnvelope(frame.payload, frame.payloadLen, hdr, payload, payloadLen) != CampaignCodecResult::Ok) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }
    switch (hdr.type) {
      case CampaignMessageType::ConsentGrant: {
        CampaignConsentGrantPayload grant;
        if (!decodeCampaignConsentGrant(payload, payloadLen, grant)) {
          lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
          return false;
        }
        // ConsentGrant is inherently a Pairwise-only control reply bound
        // to the EXACT expected destination peer -- a Group-destination
        // bulk/multicast campaign has no single expected peer at this
        // layer (see applyReceipt() above): it must never accept "any
        // authenticated peer" as if it were the one consenting
        // controller, and it must never accept a Group-scoped frame
        // (which carries no authenticated peer at all) either.
        if (!frame.hasAuthenticatedPeer()) {
          lastRefusal_ = CampaignRefusalReason::UntrustedContext;
          return false;
        }
        if (dest_.scope != CampaignAuthScope::Pairwise || frame.pairwise()->peerId != dest_.peerId) {
          lastRefusal_ = CampaignRefusalReason::ForeignController;
          return false;
        }
        if (!runtime::otaSessionEquals(hdr.session, coordinator_.activeSession())) {
          lastRefusal_ = CampaignRefusalReason::ForeignSession;
          return false;
        }
        if (grant.granted) {
          consentGranted_ = true;
        } else {
          lastRefusal_ = static_cast<CampaignRefusalReason>(grant.refusalReason);
        }
        return grant.granted != 0;
      }
      case CampaignMessageType::Receipt: {
        protocol::OtaReceiptPayload receipt;
        if (!protocol::decodeOtaReceipt(payload, payloadLen, receipt)) {
          lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
          return false;
        }
        return applyReceipt(frame, hdr.frameSeq, hdr.session, receipt);
      }
      default:
        lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
        return false;
    }
  }

  // Autonomous bounded facade: performs AT MOST one unit of outbound-
  // driving work per call (send consent, send descriptor, cache one
  // chunk, seal, transmit one chunk, or send commit) so a caller's tick
  // loop stays non-blocking. Returns true if this call did something,
  // false if there is currently nothing to do (waiting on an inbound
  // event via onFrame, or fully driven to completion/refusal already).
  bool tick() {
    if (outcome() != UpdaterOutcome::InProgress) return false;
    if (!consentSent_) return trySendConsentRequest();
    if (!descriptorSent_) return trySendDescriptorFragment();
    if (!consentGranted_) {
      // Both control frames were enqueued but the target's ConsentGrant
      // reply has not arrived -- it (or one of the two requests) may have
      // been lost on the wire. Resend after a bounded timeout rather than
      // waiting forever; queued != delivered, so a bare Enqueued result
      // earlier never actually proved the peer received anything.
      if (campaignElapsedAtLeast(clock_.nowMs(), controlPhaseSentAtMs_, kCampaignControlRetryTimeoutMs)) {
        if (consentRetryCount_ >= kCampaignControlMaxRetries) {
          lastRefusal_ = CampaignRefusalReason::Timeout;
          return false;
        }
        ++consentRetryCount_;
        consentSent_ = false;
        descriptorSent_ = false; // next tick() calls resend both, fresh frameSeq each
      }
      return false; // waiting for ConsentGrant via onFrame
    }
    if (!cachedComplete_) return cacheNextChunk();
    if (!sealed_) return sealCache();
    if (ackedCount_ < geometry_.chunkCount) return tickTransmit() == CampaignSendResult::Enqueued;
    if (!commitSent_) return trySendCommit();
    if (!remoteConfirmed_ && !remoteFailed_) {
      // Commit was enqueued but neither TransferComplete nor
      // TransferFailed has arrived -- the Commit frame or its receipt may
      // have been lost. Resend after a bounded timeout, same discipline
      // as the consent/descriptor phase above.
      if (campaignElapsedAtLeast(clock_.nowMs(), commitSentAtMs_, kCampaignControlRetryTimeoutMs)) {
        if (commitRetryCount_ >= kCampaignControlMaxRetries) {
          lastRefusal_ = CampaignRefusalReason::Timeout;
          return false;
        }
        ++commitRetryCount_;
        commitSent_ = false; // next tick() call resends, fresh frameSeq
      }
    }
    return false; // fully delivered+committed; waiting for remote TransferComplete/Failed via onFrame
  }

  UpdaterOutcome outcome() const {
    if (remoteFailed_) return UpdaterOutcome::Refused;
    if (sealed_ && remoteConfirmed_) return UpdaterOutcome::Complete;
    if (lastRefusal_ == CampaignRefusalReason::Timeout) return UpdaterOutcome::Refused;
    if (lastRefusal_ != CampaignRefusalReason::None && !sealed_) return UpdaterOutcome::Refused;
    return UpdaterOutcome::InProgress;
  }

  bool isSealed() const { return sealed_; }
  bool isRemoteConfirmed() const { return remoteConfirmed_; }
  bool isConsentGranted() const { return consentGranted_; }
  uint32_t cachedChunkCount() const { return nextChunkToCache_; }
  const runtime::OtaGeometry& geometry() const { return geometry_; }
  CampaignRefusalReason lastRefusal() const { return lastRefusal_; }

private:
  bool trySendConsentRequest() {
    CampaignConsentRequestPayload req;
    std::memcpy(req.controllerId, selfId_.bytes, 32);
    req.scope = static_cast<uint8_t>(dest_.scope);
    req.groupId = dest_.groupId;
    req.descriptorTotalLength = static_cast<uint16_t>(protocol::kOtaDescriptorCanonicalSize + signatureLen_);
    uint8_t payload[kCampaignConsentRequestSize];
    size_t payloadLen = 0;
    if (!encodeCampaignConsentRequest(req, payload, sizeof(payload), payloadLen)) return false;
    if (sendEnvelope(CampaignMessageType::ConsentRequest, payload, payloadLen) != CampaignSendResult::Enqueued) {
      return false;
    }
    consentSent_ = true;
    return true;
  }

  bool trySendDescriptorFragment() {
    uint8_t canonical[protocol::kOtaDescriptorCanonicalSize];
    size_t canonicalLen = 0;
    if (protocol::encodeOtaDescriptorCanonical(descriptor_, canonical, sizeof(canonical), canonicalLen) !=
        protocol::OtaDescriptorCodecResult::Ok) {
      return false;
    }
    std::array<uint8_t, protocol::kOtaDescriptorCanonicalSize + 64> blob{};
    std::memcpy(blob.data(), canonical, canonicalLen);
    std::memcpy(blob.data() + canonicalLen, signature_.data(), signatureLen_);
    const size_t blobLen = canonicalLen + signatureLen_;
    uint8_t payload[kCampaignMaxPayloadSize];
    size_t payloadLen = 0;
    // Single fragment: descriptor(59)+signature(<=64) is proven (see
    // RfBudgetTest.DescriptorPlusSignatureFitsSingleFragment) to always
    // fit in one fragment within the authenticated RF budget.
    if (!encodeCampaignDescriptorFragment(0, 1, static_cast<uint16_t>(blobLen), static_cast<uint16_t>(blobLen),
                                           blob.data(), blobLen, payload, sizeof(payload), payloadLen)) {
      return false;
    }
    if (sendEnvelope(CampaignMessageType::DescriptorFragment, payload, payloadLen) != CampaignSendResult::Enqueued) {
      return false;
    }
    descriptorSent_ = true;
    controlPhaseSentAtMs_ = clock_.nowMs();
    return true;
  }

  bool trySendCommit() {
    protocol::OtaCommitPayload commit{coordinator_.activeSession().campaignId, 1, descriptor_.securityCounter};
    uint8_t payload[protocol::kOtaCommitPayloadSize];
    size_t payloadLen = 0;
    if (!protocol::encodeOtaCommit(commit, payload, sizeof(payload), payloadLen)) return false;
    if (sendEnvelope(CampaignMessageType::Commit, payload, payloadLen) != CampaignSendResult::Enqueued) return false;
    commitSent_ = true;
    commitSentAtMs_ = clock_.nowMs();
    return true;
  }

  CampaignSendResult sendEnvelope(CampaignMessageType type, const uint8_t* payload, size_t payloadLen) {
    CampaignEnvelopeHeader hdr;
    hdr.type = type;
    hdr.session = coordinator_.activeSession();
    hdr.frameSeq = ++frameSeqCounter_;
    uint8_t frame[protocol::kOtaMaxFrameSize];
    size_t frameLen = 0;
    if (encodeCampaignEnvelope(hdr, payload, payloadLen, frame, sizeof(frame), frameLen) != CampaignCodecResult::Ok) {
      return CampaignSendResult::Rejected;
    }
    return transport_.trySend(dest_, protocol::OtaAirtimeCategory::Control, frame, frameLen);
  }

  // Tiny fixed-capacity in-flight tracker: bounds concurrently-unacked
  // chunk indices to kCampaignMaxInFlightChunks slots, no heap. Tracks a
  // per-slot last-sent timestamp so a stalled/dropped chunk (no receipt
  // within retryTimeoutMs) is retransmitted rather than left stuck
  // occupying its slot forever.
  class InFlightWindow {
  public:
    void reset() {
      used_.fill(false);
      slot_.fill(0);
      lastSentMs_.fill(0);
      nextToAssign_ = 0;
    }

    // Selects the next chunk index to (re)send: prefers a timed-out
    // in-flight slot (isRetry=true) over assigning a brand-new index into
    // a free slot (isRetry=false). Returns false when nothing is sendable
    // right now (window full and every slot still within its timeout, or
    // every chunk has been assigned and none remain in flight).
    bool nextToSend(uint32_t totalChunks, uint32_t nowMs, uint32_t retryTimeoutMs,
                    uint32_t& outIndex, bool& isRetry) const {
      for (size_t i = 0; i < kCampaignMaxInFlightChunks; ++i) {
        if (used_[i] && campaignElapsedAtLeast(nowMs, lastSentMs_[i], retryTimeoutMs)) {
          outIndex = slot_[i];
          isRetry = true;
          return true;
        }
      }
      if (nextToAssign_ < totalChunks) {
        for (size_t i = 0; i < kCampaignMaxInFlightChunks; ++i) {
          if (!used_[i]) {
            outIndex = nextToAssign_;
            isRetry = false;
            return true;
          }
        }
      }
      return false;
    }
    uint32_t countInFlight() const {
      uint32_t n = 0;
      for (bool u : used_) if (u) ++n;
      return n;
    }
    // Records that chunkIndex was just (re)sent: assigns a free slot for a
    // brand-new index, or refreshes the timestamp for a retry of an
    // already-occupied slot.
    void markSent(uint32_t chunkIndex, uint32_t nowMs) {
      for (size_t i = 0; i < kCampaignMaxInFlightChunks; ++i) {
        if (used_[i] && slot_[i] == chunkIndex) {
          lastSentMs_[i] = nowMs;
          return;
        }
      }
      for (size_t i = 0; i < kCampaignMaxInFlightChunks; ++i) {
        if (!used_[i]) {
          used_[i] = true;
          slot_[i] = chunkIndex;
          lastSentMs_[i] = nowMs;
          if (chunkIndex >= nextToAssign_) nextToAssign_ = chunkIndex + 1;
          return;
        }
      }
    }
    void acknowledge(uint32_t chunkIndex) {
      for (size_t i = 0; i < kCampaignMaxInFlightChunks; ++i) {
        if (used_[i] && slot_[i] == chunkIndex) {
          used_[i] = false;
          return;
        }
      }
    }

  private:
    std::array<bool, kCampaignMaxInFlightChunks> used_{};
    std::array<uint32_t, kCampaignMaxInFlightChunks> slot_{};
    std::array<uint32_t, kCampaignMaxInFlightChunks> lastSentMs_{};
    uint32_t nextToAssign_ = 0;
  };

  runtime::IOtaTrustProvider& trust_;
  IOtaCacheOnlySink& cache_;
  IAuthenticatedTransportPort& transport_;
  IImageReaderPort& hostImageReader_;
  IClockPort& clock_;

  runtime::OtaCoordinatorStateMachine coordinator_;
  protocol::OtaDescriptor descriptor_{};
  runtime::OtaGeometry geometry_{};
  CampaignDestination dest_{};
  CampaignPeerId selfId_{};
  std::array<uint8_t, 64> signature_{};
  size_t signatureLen_ = 0;
  InFlightWindow inFlight_;
  uint32_t nextChunkToCache_ = 0;
  uint32_t frameSeqCounter_ = 0;
  uint32_t lastReceiptFrameSeq_ = 0;
  uint32_t receiptReplayMask_ = 0;
  uint32_t ackedCount_ = 0;
  bool cachedComplete_ = false;
  bool sealed_ = false;
  bool remoteConfirmed_ = false;
  bool remoteFailed_ = false;
  bool consentSent_ = false;
  bool descriptorSent_ = false;
  bool consentGranted_ = false;
  bool commitSent_ = false;
  // Clock-driven bounded retry state for the control phases (Consent+
  // Descriptor together -- the target's ConsentGrant logically depends on
  // BOTH having arrived; Commit separately). `*RetryCount_` bounds the
  // number of resends so a permanently-lost peer eventually surfaces as
  // an explicit Timeout refusal rather than waiting forever.
  uint32_t controlPhaseSentAtMs_ = 0;
  uint32_t consentRetryCount_ = 0;
  uint32_t commitSentAtMs_ = 0;
  uint32_t commitRetryCount_ = 0;
  CampaignRefusalReason lastRefusal_ = CampaignRefusalReason::None;
};

} // namespace campaign
} // namespace ota
} // namespace meshcore
