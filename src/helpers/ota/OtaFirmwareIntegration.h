#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>

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
    if (percent <= 0.0f || percent > 100.0f) return false;
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
        if (lease_.state() == OtaLeaseState::Normal) lease_.handle(OtaLeaseEvent::RequestLease);
        lease_.handle(OtaLeaseEvent::Granted);
        return true;

      case OtaMessageType::Announcement:
        if (fleet_.state() == OtaFleetState::Idle) fleet_.beginCampaign(id);
        return true;

      case OtaMessageType::Census:
        fleet_.handle(OtaFleetEvent::AnnounceComplete, id);
        fleet_.handle(OtaFleetEvent::CensusComplete, id);
        return true;

      case OtaMessageType::CohortResolution:
        fleet_.handle(OtaFleetEvent::CohortResolved, id);
        return true;

      case OtaMessageType::MissingRange:
        coordinator_.handle(OtaCoordinatorEvent::ReceiptMissingDetected, id);
        fleet_.handle(OtaFleetEvent::SomeMissing, id);
        return true;

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
    return s;
  }

private:
  static constexpr size_t kDescriptorFragmentHeaderSize = 1 + 1 + 2 + 2;

  static bool isReceiverTerminal(meshcore::ota::runtime::OtaReceiverState state) {
    using meshcore::ota::runtime::OtaReceiverState;
    return state == OtaReceiverState::Complete || state == OtaReceiverState::Failed ||
           state == OtaReceiverState::Aborted;
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
    total_len = static_cast<uint16_t>(payload[2]) | (static_cast<uint16_t>(payload[3]) << 8);
    fragment_payload_size = static_cast<uint16_t>(payload[4]) | (static_cast<uint16_t>(payload[5]) << 8);
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
    if (coordinator_.state() == OtaCoordinatorState::Idle) coordinator_.beginCampaign(id);
    coordinator_.handle(OtaCoordinatorEvent::DescriptorDeliveryConfirmed, id);
    return receiver_.handle(OtaReceiverEvent::DescriptorComplete, id);
  }

  bool handleAuthorization(const meshcore::ota::runtime::OtaSessionId& id,
                           const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

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
    bool receiver_ok = receiver_.handle(OtaReceiverEvent::AuthorizationGranted, id);
    bool coordinator_ok = coordinator_.handle(OtaCoordinatorEvent::AuthorizationGranted, id);
    return receiver_ok && coordinator_ok;
  }

  bool handleChunk(const meshcore::ota::runtime::OtaSessionId& id,
                   const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

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

  void resetTransferSession() {
    descriptor_reassembler_.reset();
    receipt_map_.reset(0);
    geometry_ = meshcore::ota::runtime::OtaGeometry();
    descriptor_ = meshcore::ota::protocol::OtaDescriptor();
    descriptor_verified_ = false;
    authorized_ = false;
    session_active_ = false;
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
  bool authorized_ = false;
  uint32_t rx_frames_ = 0;
  uint32_t bad_frames_ = 0;
  uint32_t aborted_sessions_ = 0;
  bool rollback_requested_ = false;
};

}  // namespace ota
}  // namespace mesh
