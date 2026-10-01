#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>

#include <ota/protocol/OtaDescriptor.h>
#include <ota/protocol/OtaEnvelope.h>
#include <ota/protocol/OtaMessages.h>
#include <ota/protocol/OtaWireTypes.h>
#include <ota/runtime/OtaAirtimeLimiter.h>
#include <ota/runtime/OtaBitmap.h>
#include <ota/runtime/OtaCoordinatorStateMachine.h>
#include <ota/runtime/OtaFleetStateMachine.h>
#include <ota/runtime/OtaGeometry.h>
#include <ota/runtime/OtaLeaseStateMachine.h>
#include <ota/runtime/OtaReceiverStateMachine.h>
#include <ota/runtime/OtaTrustInterfaces.h>

namespace mesh {
namespace ota {

enum class FirmwareOtaMode : uint8_t {
  Direct = 0,
  Routed = 1,
  Fleet = 2,
};

inline const char* firmwareOtaModeName(FirmwareOtaMode mode) {
  switch (mode) {
    case FirmwareOtaMode::Direct: return "direct";
    case FirmwareOtaMode::Routed: return "routed";
    case FirmwareOtaMode::Fleet: return "fleet";
    default: return "unknown";
  }
}

inline bool parseFirmwareOtaMode(const char* value, FirmwareOtaMode& out) {
  if (value == nullptr) return false;
  if (strcmp(value, "direct") == 0) {
    out = FirmwareOtaMode::Direct;
    return true;
  }
  if (strcmp(value, "routed") == 0 || strcmp(value, "mesh") == 0) {
    out = FirmwareOtaMode::Routed;
    return true;
  }
  if (strcmp(value, "fleet") == 0 || strcmp(value, "background") == 0) {
    out = FirmwareOtaMode::Fleet;
    return true;
  }
  return false;
}

inline meshcore::ota::runtime::OtaSessionId otaSessionFromEnvelope(
    const meshcore::ota::protocol::OtaEnvelopeHeader& hdr) {
  meshcore::ota::runtime::OtaSessionId id;
  id.campaignId = hdr.campaignId;
  id.sessionId = hdr.sessionId;
  id.attemptId = hdr.attemptId;
  return id;
}

inline meshcore::ota::protocol::OtaAirtimeCategory otaAirtimeCategoryForMessage(
    meshcore::ota::protocol::OtaMessageType type) {
  using meshcore::ota::protocol::OtaAirtimeCategory;
  using meshcore::ota::protocol::OtaMessageType;

  switch (type) {
    case OtaMessageType::Chunk:
    case OtaMessageType::Announcement:
      return OtaAirtimeCategory::Relay;
    case OtaMessageType::MissingRange:
      return OtaAirtimeCategory::Repair;
    default:
      return OtaAirtimeCategory::Control;
  }
}

struct FirmwareOtaStatus {
  FirmwareOtaMode mode = FirmwareOtaMode::Fleet;
  float dutyCyclePercent = 2.0f;
  uint32_t dutyWindowMs = meshcore::ota::runtime::OtaAirtimeLimiter::kDefaultWindowMs;
  uint32_t dutyBudgetMs = meshcore::ota::runtime::OtaAirtimeLimiter::kDefaultBudgetMs;
  uint32_t dutyUsedMs = 0;
  meshcore::ota::runtime::OtaReceiverState receiverState = meshcore::ota::runtime::OtaReceiverState::Idle;
  meshcore::ota::runtime::OtaCoordinatorState coordinatorState = meshcore::ota::runtime::OtaCoordinatorState::Idle;
  meshcore::ota::runtime::OtaFleetState fleetState = meshcore::ota::runtime::OtaFleetState::Idle;
  meshcore::ota::runtime::OtaLeaseState leaseState = meshcore::ota::runtime::OtaLeaseState::Normal;
  uint32_t rxFrames = 0;
  uint32_t badFrames = 0;
  uint32_t abortedSessions = 0;
  bool rollbackRequested = false;
  bool backendAvailable = false;
  // Real, decoded fleet (background) campaign progress, populated only from
  // validated Census/CohortResolution frames bound to the active campaign
  // (see handleCensus/handleCohortResolution); never advanced on unparsed
  // or foreign-campaign traffic.
  uint32_t fleetCensusReports = 0;
  bool fleetHasCohort = false;
  uint16_t fleetCohortId = 0;
  uint16_t fleetCohortSize = 0;
  uint16_t fleetCohortIndex = 0;
  uint16_t fleetMissingRangeCount = 0;
};

class OtaFirmwareIntegration {
public:
  OtaFirmwareIntegration()
      : airtime_(meshcore::ota::runtime::OtaAirtimeLimiter::kDefaultWindowMs,
                 meshcore::ota::runtime::OtaAirtimeLimiter::kDefaultBudgetMs) {}

  FirmwareOtaMode mode() const { return mode_; }
  void setMode(FirmwareOtaMode mode) { mode_ = mode; }

  float dutyCyclePercent() const { return duty_percent_; }
  uint32_t dutyBudgetMs() const { return budget_ms_; }
  uint32_t dutyWindowMs() const { return window_ms_; }

  bool setDutyCyclePercent(float percent) {
    // Reject non-finite input (NaN, +-Inf) explicitly: NaN fails both
    // `<= 0.0f` and `> 100.0f` (all NaN comparisons are false), so without
    // this guard a NaN would silently pass the bounds check below and then
    // hit undefined behavior in the float->integer budget conversion.
    if (!std::isfinite(percent) || percent <= 0.0f || percent > 100.0f) return false;
    duty_percent_ = percent;
    const uint64_t budget = (static_cast<uint64_t>(window_ms_) * static_cast<uint32_t>(percent * 1000.0f + 0.5f)) / 100000u;
    budget_ms_ = budget > 0 ? static_cast<uint32_t>(budget) : 1;
    airtime_.retune(window_ms_, budget_ms_);
    return true;
  }

  void attachTrustProvider(meshcore::ota::runtime::IOtaTrustProvider* provider) { trust_provider_ = provider; }
  void attachStagingSink(meshcore::ota::runtime::IOtaStagingSink* sink) { staging_sink_ = sink; }
  bool backendAvailable() const { return trust_provider_ != nullptr && staging_sink_ != nullptr; }

  const meshcore::ota::runtime::OtaAirtimeLimiter& airtimeLimiter() const { return airtime_; }
  meshcore::ota::runtime::OtaAirtimeLimiter& airtimeLimiter() { return airtime_; }

  bool canTransmit(uint32_t now_ms,
                   meshcore::ota::protocol::OtaAirtimeCategory category,
                   uint32_t prospective_airtime_ms,
                   bool regulatory_allowed,
                   bool normal_traffic_active) const {
    meshcore::ota::runtime::OtaAirtimeDecisionInput input;
    input.regulatoryAllowed = regulatory_allowed;
    input.normalTrafficActive = normal_traffic_active;
    return airtime_.canAdmit(now_ms, category, prospective_airtime_ms, input);
  }

  bool recordTransmit(uint32_t now_ms,
                      meshcore::ota::protocol::OtaAirtimeCategory category,
                      uint32_t airtime_ms) {
    return airtime_.recordUsage(now_ms, category, airtime_ms);
  }

  bool handleReceivedFrame(const uint8_t* frame, size_t frame_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    OtaEnvelopeHeader hdr;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    OtaCodecResult decoded = decodeOtaEnvelope(frame, frame_len, hdr, payload, payload_len);
    if (decoded != OtaCodecResult::Ok) {
      ++bad_frames_;
      return false;
    }

    ++rx_frames_;
    const OtaSessionId id = otaSessionFromEnvelope(hdr);
    switch (hdr.type) {
      case OtaMessageType::DescriptorFragment:
        return handleDescriptorFragment(id, payload, payload_len);

      case OtaMessageType::Authorization:
        return handleAuthorization(id, payload, payload_len);

      case OtaMessageType::Chunk:
        return handleChunk(id, payload, payload_len);

      case OtaMessageType::Receipt:
        return handleReceipt(id, payload, payload_len);

      case OtaMessageType::Abort:
        if (!receiver_.handle(OtaReceiverEvent::Abort, id)) {
          return false;
        }
        coordinator_.handle(OtaCoordinatorEvent::Abort, id);
        fleet_.handle(OtaFleetEvent::Abort, id);
        lease_.handle(OtaLeaseEvent::Reset);
        resetTransferSession();
        ++aborted_sessions_;
        return true;

      case OtaMessageType::LeaseNegotiation:
        return handleLeaseNegotiation(payload, payload_len);

      case OtaMessageType::Announcement:
        return handleAnnouncement(id, payload, payload_len);

      case OtaMessageType::Census:
        return handleCensus(id, payload, payload_len);

      case OtaMessageType::CohortResolution:
        return handleCohortResolution(id, payload, payload_len);

      case OtaMessageType::MissingRange:
        return handleMissingRange(id, payload, payload_len);

      case OtaMessageType::Commit:
        return handleCommit(id, payload, payload_len);
    }
    return false;
  }

  void abortSession() {
    receiver_.reset();
    coordinator_.reset();
    fleet_.reset();
    lease_.handle(meshcore::ota::runtime::OtaLeaseEvent::Reset);
    resetTransferSession();
    ++aborted_sessions_;
  }

  void requestRollback() {
    rollback_requested_ = true;
    abortSession();
  }

  FirmwareOtaStatus status(uint32_t now_ms) const {
    FirmwareOtaStatus s;
    s.mode = mode_;
    s.dutyCyclePercent = duty_percent_;
    s.dutyWindowMs = window_ms_;
    s.dutyBudgetMs = budget_ms_;
    s.dutyUsedMs = airtime_.storedUsageMs(now_ms);
    s.receiverState = receiver_.state();
    s.coordinatorState = coordinator_.state();
    s.fleetState = fleet_.state();
    s.leaseState = lease_.state();
    s.rxFrames = rx_frames_;
    s.badFrames = bad_frames_;
    s.abortedSessions = aborted_sessions_;
    s.rollbackRequested = rollback_requested_;
    s.backendAvailable = backendAvailable();
    s.fleetCensusReports = fleet_census_reports_;
    s.fleetHasCohort = fleet_has_cohort_;
    s.fleetCohortId = fleet_cohort_.cohortId;
    s.fleetCohortSize = fleet_cohort_.cohortSize;
    s.fleetCohortIndex = fleet_cohort_.cohortIndex;
    s.fleetMissingRangeCount = static_cast<uint16_t>(fleet_last_census_.missingRangeCount);
    return s;
  }

private:
  static constexpr size_t kDescriptorFragmentHeaderSize = 1 + 1 + 2 + 2;

  static bool isReceiverTerminal(meshcore::ota::runtime::OtaReceiverState state) {
    using meshcore::ota::runtime::OtaReceiverState;
    return state == OtaReceiverState::Complete || state == OtaReceiverState::Failed ||
           state == OtaReceiverState::Aborted;
  }

  // True only if a campaign is active AND `id` is exactly that campaign's
  // session identity. Every handler that mutates shared session state
  // (authorization grant, staged bytes, receipt bitmap) MUST check this
  // first and return false without side effects otherwise: this is what
  // stops a foreign, stale, or replayed frame from corrupting the state of
  // a legitimately in-progress transfer, since OtaReceiverStateMachine's own
  // id check only runs (and only fails closed) *after* any code that already
  // ran ahead of it.
  bool isActiveSession(const meshcore::ota::runtime::OtaSessionId& id) const {
    return session_active_ && meshcore::ota::runtime::otaSessionEquals(id, active_session_);
  }

  bool ensureReceiverCampaign(const meshcore::ota::runtime::OtaSessionId& id) {
    using meshcore::ota::runtime::OtaReceiverState;
    if (receiver_.state() == OtaReceiverState::Idle || isReceiverTerminal(receiver_.state())) {
      resetTransferSession();
      if (!receiver_.beginCampaign(id)) return false;
      active_session_ = id;
      session_active_ = true;
      return true;
    }
    return meshcore::ota::runtime::otaSessionEquals(id, receiver_.activeSession());
  }

  bool parseDescriptorFragment(const uint8_t* payload, size_t payload_len,
                               uint8_t& frag_index, uint8_t& frag_count,
                               uint16_t& total_len, uint16_t& fragment_payload_size,
                               const uint8_t*& fragment_data, size_t& fragment_data_len) const {
    if (payload == nullptr || payload_len < kDescriptorFragmentHeaderSize) return false;
    frag_index = payload[0];
    frag_count = payload[1];
    // All OTA wire codecs (OtaWireTypes.h, OtaMessages.h) and the RF lab
    // reference sender use explicit big-endian ("network order") multi-byte
    // fields. This header must match that convention exactly, or a real
    // signed-wire descriptor sent by any conformant peer is silently
    // misparsed (wrong lengths) and rejected.
    total_len = meshcore::ota::protocol::getOtaBE16(payload + 2);
    fragment_payload_size = meshcore::ota::protocol::getOtaBE16(payload + 4);
    fragment_data = payload + kDescriptorFragmentHeaderSize;
    fragment_data_len = payload_len - kDescriptorFragmentHeaderSize;
    return true;
  }

  bool handleDescriptorFragment(const meshcore::ota::runtime::OtaSessionId& id,
                                const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    if (!ensureReceiverCampaign(id)) return false;

    uint8_t frag_index = 0;
    uint8_t frag_count = 0;
    uint16_t total_len = 0;
    uint16_t fragment_payload_size = 0;
    const uint8_t* fragment_data = nullptr;
    size_t fragment_data_len = 0;
    if (!parseDescriptorFragment(payload, payload_len, frag_index, frag_count, total_len,
                                 fragment_payload_size, fragment_data, fragment_data_len) ||
        !descriptor_reassembler_.addFragment(frag_index, frag_count, total_len,
                                             fragment_payload_size, fragment_data, fragment_data_len)) {
      receiver_.handle(OtaReceiverEvent::DescriptorRejected, id);
      stagingAbortFailClosed(staging_sink_);
      return false;
    }

    if (!descriptor_reassembler_.isComplete()) {
      receiver_.handle(OtaReceiverEvent::DescriptorFragmentReceived, id);
      return true;
    }

    const uint8_t* blob = descriptor_reassembler_.blob();
    const size_t blob_len = descriptor_reassembler_.blobLength();
    if (blob_len <= kOtaDescriptorCanonicalSize) {
      receiver_.handle(OtaReceiverEvent::DescriptorRejected, id);
      return false;
    }

    // Idempotency for an exact-duplicate completed descriptor: a lost final
    // ACK legitimately causes a sender to retransmit every fragment of an
    // already-accepted descriptor while the receiver is mid-transfer
    // (Receiving/authorized, chunks already staged). Re-running verify +
    // stagingBeginFailClosed + receipt_map_.reset() below would erase the
    // candidate image and destroy in-flight progress for no protocol
    // reason. Detect this case by comparing the freshly reassembled blob
    // byte-for-byte against the last blob this exact session already
    // verified, and short-circuit to a harmless re-ack that preserves all
    // staged bytes, the receipt bitmap, and authorization state.
    if (descriptor_verified_ && isActiveSession(id) && blob_len == verified_blob_len_ &&
        memcmp(blob, verified_blob_, blob_len) == 0) {
      receiver_.handle(OtaReceiverEvent::DescriptorFragmentReceived, id);
      return true;
    }

    OtaDescriptor descriptor;
    if (decodeOtaDescriptorCanonical(blob, kOtaDescriptorCanonicalSize, descriptor) != OtaDescriptorCodecResult::Ok) {
      receiver_.handle(OtaReceiverEvent::DescriptorRejected, id);
      return false;
    }

    const uint8_t* signature = blob + kOtaDescriptorCanonicalSize;
    const size_t signature_len = blob_len - kOtaDescriptorCanonicalSize;
    OtaGeometry geometry;
    if (!verifyDescriptorFailClosed(trust_provider_, descriptor, signature, signature_len) ||
        OtaGeometry::compute(descriptor.exactSizeBytes, kChunkPayloadSize, kOtaMaxImageBytes, geometry) != OtaGeometryResult::Ok ||
        stagingBeginFailClosed(staging_sink_, descriptor) != IOtaStagingSink::Result::Ok) {
      receiver_.handle(OtaReceiverEvent::DescriptorRejected, id);
      stagingAbortFailClosed(staging_sink_);
      return false;
    }

    descriptor_ = descriptor;
    geometry_ = geometry;
    receipt_map_.reset(geometry_.chunkCount);
    descriptor_verified_ = true;
    authorized_ = false;
    verified_blob_len_ = blob_len;
    memcpy(verified_blob_, blob, blob_len);
    if (staging_sink_ != nullptr) {
      staging_sink_->onVerifiedWireDescriptor(blob, kOtaDescriptorCanonicalSize, signature, signature_len);
    }
    if (coordinator_.state() == OtaCoordinatorState::Idle) coordinator_.beginCampaign(id);
    coordinator_.handle(OtaCoordinatorEvent::DescriptorDeliveryConfirmed, id);
    return receiver_.handle(OtaReceiverEvent::DescriptorComplete, id);
  }

  bool handleAuthorization(const meshcore::ota::runtime::OtaSessionId& id,
                           const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    // Reject foreign/stale/replayed session ids before touching anything:
    // otherwise a spoofed authorization for an unrelated campaign would
    // still flip `authorized_` true and abort the real session's staging
    // sink once the (correctly failing) state-machine check ran below.
    if (!isActiveSession(id)) return false;

    OtaAuthorizationPayload authorization;
    if (!descriptor_verified_ || !decodeOtaAuthorization(payload, payload_len, authorization) ||
        authorization.granted == 0 ||
        !authorizeTransferFailClosed(trust_provider_, descriptor_, authorization)) {
      receiver_.handle(OtaReceiverEvent::AuthorizationDenied, id);
      coordinator_.handle(OtaCoordinatorEvent::AuthorizationDenied, id);
      stagingAbortFailClosed(staging_sink_);
      return false;
    }

    authorized_ = true;
    if (trust_provider_ != nullptr && staging_sink_ != nullptr) {
      uint8_t controller[32];
      if (trust_provider_->controllerIdentity(controller)) {
        staging_sink_->onAuthorizedSession(id, controller);
      }
    }
    bool receiver_ok = receiver_.handle(OtaReceiverEvent::AuthorizationGranted, id);
    bool coordinator_ok = coordinator_.handle(OtaCoordinatorEvent::AuthorizationGranted, id);
    return receiver_ok && coordinator_ok;
  }

  bool handleChunk(const meshcore::ota::runtime::OtaSessionId& id,
                   const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    // Reject foreign/stale/replayed chunks before writing anything to the
    // staging sink or setting bits in the receipt bitmap: without this
    // gate, an interleaved chunk carrying a foreign session id would still
    // be written to the active campaign's staged image and marked received
    // before the state machine's own id check (which only runs afterward,
    // in receiver_.handle()) had a chance to reject it.
    if (!isActiveSession(id)) return false;

    OtaChunkHeader chunk;
    const uint8_t* data = nullptr;
    size_t data_len = 0;
    uint32_t expected_len = 0;
    uint64_t offset = 0;
    if (!descriptor_verified_ || !authorized_ ||
        !decodeOtaChunk(payload, payload_len, chunk, data, data_len) ||
        !geometry_.chunkLength(chunk.chunkIndex, expected_len) ||
        expected_len != data_len ||
        !geometry_.chunkOffset(chunk.chunkIndex, offset) ||
        stagingWriteFailClosed(staging_sink_, offset, data, data_len) != IOtaStagingSink::Result::Ok ||
        !receipt_map_.set(chunk.chunkIndex)) {
      receiver_.handle(OtaReceiverEvent::StagingError, id);
      stagingAbortFailClosed(staging_sink_);
      return false;
    }

    receiver_.handle(OtaReceiverEvent::ChunkAccepted, id);
    coordinator_.handle(OtaCoordinatorEvent::ChunkSent, id);
    return true;
  }

  bool handleReceipt(const meshcore::ota::runtime::OtaSessionId& id,
                     const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;
    OtaReceiptPayload receipt;
    if (!decodeOtaReceipt(payload, payload_len, receipt)) return false;
    if (receipt.status == OtaReceiptStatus::TransferComplete) {
      return coordinator_.handle(OtaCoordinatorEvent::ReceiptAllGood, id);
    }
    if (receipt.status == OtaReceiptStatus::ChunkNack || receipt.status == OtaReceiptStatus::TransferFailed) {
      return coordinator_.handle(OtaCoordinatorEvent::ReceiptMissingDetected, id);
    }
    return true;
  }

  bool handleCommit(const meshcore::ota::runtime::OtaSessionId& id,
                    const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    // Reject foreign/stale/replayed commits before evaluating anything else:
    // commit drives image-hash verification and the final flash commit, so
    // it must be bound to the active session first, defense-in-depth on top
    // of the campaignId check below and receiver_.handle()'s own id check.
    if (!isActiveSession(id)) return false;

    OtaCommitPayload commit;
    if (!descriptor_verified_ || !authorized_ ||
        !decodeOtaCommit(payload, payload_len, commit) ||
        commit.campaignId != id.campaignId ||
        commit.verifiedOk == 0 ||
        commit.finalSecurityCounter != descriptor_.securityCounter ||
        !receipt_map_.allSet()) {
      return false;
    }

    if (!receiver_.handle(OtaReceiverEvent::AllChunksReceived, id)) return false;

    if (!verifyStagedImageHashFailClosed(trust_provider_, descriptor_)) {
      receiver_.handle(OtaReceiverEvent::VerificationFailed, id);
      coordinator_.handle(OtaCoordinatorEvent::CommitFailed, id);
      fleet_.handle(OtaFleetEvent::CommitFailed, id);
      stagingAbortFailClosed(staging_sink_);
      return false;
    }

    if (!receiver_.handle(OtaReceiverEvent::VerificationOk, id) ||
        stagingCommitFailClosed(staging_sink_) != IOtaStagingSink::Result::Ok) {
      receiver_.handle(OtaReceiverEvent::CommitFailed, id);
      coordinator_.handle(OtaCoordinatorEvent::CommitFailed, id);
      fleet_.handle(OtaFleetEvent::CommitFailed, id);
      stagingAbortFailClosed(staging_sink_);
      return false;
    }

    receiver_.handle(OtaReceiverEvent::CommitOk, id);
    coordinator_.handle(OtaCoordinatorEvent::ReceiptAllGood, id);
    coordinator_.handle(OtaCoordinatorEvent::CommitVerified, id);
    fleet_.handle(OtaFleetEvent::CommitVerified, id);
    return true;
  }

  // Real subtype-aware lease negotiation. Every branch requires a legal
  // (state, subtype) combination per OtaLeaseStateMachine's own transition
  // table before advancing, so a malformed frame or a frame that does not
  // fit the current negotiation phase is rejected rather than blindly
  // granting/advancing regardless of content.
  //
  // Note: this only drives the local lease *state machine*. Actually
  // applying the negotiated off-frequency radio profile (frequency,
  // bandwidth, SF, CR) and its automatic expiry/revert is the integrator's
  // responsibility via the same OtaDirectLeaseHandler/OtaDirectLeaseParams
  // path already used for the locally-issued (USB) direct lease command;
  // wiring a remote-negotiated profile table through to that handler is a
  // separate, explicitly tracked follow-up (see status report).
  bool handleLeaseNegotiation(const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    OtaLeaseNegotiationPayload negotiation;
    if (!decodeOtaLeaseNegotiation(payload, payload_len, negotiation)) return false;

    switch (negotiation.subtype) {
      case OtaLeaseSubtype::Request:
        if (lease_.state() != OtaLeaseState::Normal) return false;
        return lease_.handle(OtaLeaseEvent::RequestLease);

      case OtaLeaseSubtype::Grant:
        if (lease_.state() != OtaLeaseState::Requesting) return false;
        return lease_.handle(OtaLeaseEvent::Granted);

      case OtaLeaseSubtype::Deny:
        if (lease_.state() != OtaLeaseState::Requesting) return false;
        return lease_.handle(OtaLeaseEvent::Denied);

      case OtaLeaseSubtype::Renew:
        // Renewal only makes sense while a lease is actually active; it does
        // not itself change state (duration bookkeeping is owned by the
        // transport-layer revert timer).
        return lease_.state() == OtaLeaseState::Active;

      case OtaLeaseSubtype::Release:
        if (lease_.state() == OtaLeaseState::Active) {
          return lease_.handle(OtaLeaseEvent::Release) && lease_.handle(OtaLeaseEvent::ReleaseAcked);
        }
        if (lease_.state() == OtaLeaseState::Releasing) {
          return lease_.handle(OtaLeaseEvent::ReleaseAcked);
        }
        return false;
    }
    return false;
  }

  // Announcement/Census/CohortResolution/MissingRange are real,
  // fully-decoded and campaign-bound below: every one of these rejects
  // (returns false, no state change) frames that fail to decode or that
  // name a campaign other than the one addressed by the envelope. This
  // replaces the previous behavior of advancing the fleet state machine on
  // receipt of any frame of the right *type*, irrespective of its payload.
  bool handleAnnouncement(const meshcore::ota::runtime::OtaSessionId& id,
                          const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    OtaAnnouncementPayload announcement;
    if (!decodeOtaAnnouncement(payload, payload_len, announcement) ||
        announcement.campaignId != id.campaignId) {
      return false;
    }

    if (fleet_.state() == OtaFleetState::Idle) {
      if (!fleet_.beginCampaign(id)) return false;
      fleet_census_reports_ = 0;
      fleet_has_cohort_ = false;
    } else if (!meshcore::ota::runtime::otaSessionEquals(id, fleet_.activeSession())) {
      return false;
    }
    fleet_last_announcement_ = announcement;
    return true;
  }

  bool handleCensus(const meshcore::ota::runtime::OtaSessionId& id,
                    const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    OtaCensusPayload census;
    if (!decodeOtaCensus(payload, payload_len, census) ||
        census.campaignId != id.campaignId ||
        !meshcore::ota::runtime::otaSessionEquals(id, fleet_.activeSession())) {
      return false;
    }
    ++fleet_census_reports_;
    fleet_last_census_ = census;

    switch (fleet_.state()) {
      case OtaFleetState::Announcing:
        if (!fleet_.handle(OtaFleetEvent::AnnounceComplete, id)) return false;
        if (census.haveDescriptor == 0) return true;
        return fleet_.handle(OtaFleetEvent::CensusComplete, id);
      case OtaFleetState::Census:
        // A real census report that shows the reporter still lacks the
        // descriptor is a legal no-op: it does not (falsely) advance the
        // phase, unlike blindly trusting every Census-typed frame.
        if (census.haveDescriptor == 0) return true;
        return fleet_.handle(OtaFleetEvent::CensusComplete, id);
      case OtaFleetState::Multicasting:
        // No dedicated wire message marks "the multicast round is over";
        // the coordinator re-polls with the SAME Census message it used
        // pre-multicast, and its arrival while we're in Multicasting is
        // itself the round-end signal. Fold the MulticastComplete
        // transition and the immediate missing/no-missing evaluation into
        // this one frame rather than requiring a new message type (which
        // would be a wire-format change, not a surgical fix).
        if (!fleet_.handle(OtaFleetEvent::MulticastComplete, id)) return false;
        return fleet_.handle(census.missingRangeCount == 0 ? OtaFleetEvent::NoneMissing
                                                            : OtaFleetEvent::SomeMissing,
                              id);
      case OtaFleetState::MissingCensus:
        return fleet_.handle(census.missingRangeCount == 0 ? OtaFleetEvent::NoneMissing
                                                            : OtaFleetEvent::SomeMissing,
                              id);
      case OtaFleetState::Repairing:
        // Same round-end-via-Census pattern as Multicasting above: a fresh
        // Census poll arriving while we're mid-repair means the coordinator
        // considers this repair round finished, so fold
        // RepairRoundComplete + the next missing/no-missing decision into
        // this one frame (re-census -> either converge to Committing or
        // start another repair round).
        if (!fleet_.handle(OtaFleetEvent::RepairRoundComplete, id)) return false;
        return fleet_.handle(census.missingRangeCount == 0 ? OtaFleetEvent::NoneMissing
                                                            : OtaFleetEvent::SomeMissing,
                              id);
      default:
        return false;
    }
  }

  bool handleCohortResolution(const meshcore::ota::runtime::OtaSessionId& id,
                              const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    OtaCohortResolutionPayload cohort;
    if (!decodeOtaCohortResolution(payload, payload_len, cohort) ||
        cohort.campaignId != id.campaignId ||
        !meshcore::ota::runtime::otaSessionEquals(id, fleet_.activeSession()) ||
        cohort.cohortSize == 0 || cohort.cohortIndex >= cohort.cohortSize) {
      return false;
    }
    if (!fleet_.handle(OtaFleetEvent::CohortResolved, id)) return false;
    fleet_cohort_ = cohort;
    fleet_has_cohort_ = true;
    return true;
  }

  bool handleMissingRange(const meshcore::ota::runtime::OtaSessionId& id,
                          const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    OtaMissingRangePayload missing;
    if (!decodeOtaMissingRange(payload, payload_len, missing) ||
        missing.campaignId != id.campaignId ||
        missing.chunkCount == 0 ||
        !meshcore::ota::runtime::otaSessionEquals(id, fleet_.activeSession())) {
      return false;
    }
    fleet_last_missing_range_ = missing;
    coordinator_.handle(OtaCoordinatorEvent::ReceiptMissingDetected, id);
    // SomeMissing is only a legal fleet-state transition out of
    // MissingCensus (-> Repairing). A directed MissingRange detail frame
    // received WHILE already Repairing is a normal, additional repair
    // target (there can be more than one missing range per round) rather
    // than a new phase transition, so it must not be forced through
    // fleet_.handle() a second time -- that would always fail (Repairing
    // has no SomeMissing case) and reject an otherwise legitimate repair
    // request.
    if (fleet_.state() == OtaFleetState::Repairing) return true;
    return fleet_.handle(OtaFleetEvent::SomeMissing, id);
  }

  void resetTransferSession() {
    descriptor_reassembler_.reset();
    receipt_map_.reset(0);
    geometry_ = meshcore::ota::runtime::OtaGeometry();
    descriptor_ = meshcore::ota::protocol::OtaDescriptor();
    descriptor_verified_ = false;
    authorized_ = false;
    session_active_ = false;
    verified_blob_len_ = 0;
  }


  static constexpr uint32_t kChunkPayloadSize = meshcore::ota::runtime::kOtaDefaultChunkPayloadSize;
  FirmwareOtaMode mode_ = FirmwareOtaMode::Fleet;
  float duty_percent_ = 2.0f;
  uint32_t window_ms_ = meshcore::ota::runtime::OtaAirtimeLimiter::kDefaultWindowMs;
  uint32_t budget_ms_ = meshcore::ota::runtime::OtaAirtimeLimiter::kDefaultBudgetMs;
  meshcore::ota::runtime::IOtaTrustProvider* trust_provider_ = nullptr;
  meshcore::ota::runtime::IOtaStagingSink* staging_sink_ = nullptr;
  meshcore::ota::runtime::OtaAirtimeLimiter airtime_;
  meshcore::ota::runtime::OtaReceiverStateMachine receiver_;
  meshcore::ota::runtime::OtaCoordinatorStateMachine coordinator_;
  meshcore::ota::runtime::OtaFleetStateMachine fleet_;
  meshcore::ota::runtime::OtaLeaseStateMachine lease_;
  meshcore::ota::runtime::OtaSessionId active_session_{};
  bool session_active_ = false;
  meshcore::ota::protocol::OtaDescriptorReassembler descriptor_reassembler_;
  meshcore::ota::protocol::OtaDescriptor descriptor_;
  meshcore::ota::runtime::OtaGeometry geometry_;
  meshcore::ota::runtime::OtaMaxImageBitmap receipt_map_;
  bool descriptor_verified_ = false;
  uint8_t verified_blob_[meshcore::ota::protocol::OtaDescriptorReassembler::kMaxBlobSize] = {};
  size_t verified_blob_len_ = 0;
  bool authorized_ = false;
  uint32_t rx_frames_ = 0;
  uint32_t bad_frames_ = 0;
  uint32_t aborted_sessions_ = 0;
  bool rollback_requested_ = false;
  meshcore::ota::protocol::OtaAnnouncementPayload fleet_last_announcement_{};
  meshcore::ota::protocol::OtaCensusPayload fleet_last_census_{};
  meshcore::ota::protocol::OtaCohortResolutionPayload fleet_cohort_{};
  meshcore::ota::protocol::OtaMissingRangePayload fleet_last_missing_range_{};
  uint32_t fleet_census_reports_ = 0;
  bool fleet_has_cohort_ = false;
};

}  // namespace ota
}  // namespace mesh
