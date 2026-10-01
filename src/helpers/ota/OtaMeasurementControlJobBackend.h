#pragma once

// Binds OtaControlSessionRouter's typed IOtaControlJobBackend seam (USB
// commissioning MEASURE/POLL/READ_OBJECT) to the REAL
// OtaBaselineMeasurementCollector -- the collector itself performs no
// flash/hash work inside this adapter's calls: that bounded, resumable
// work is driven independently, once per outer scheduler tick, by
// whatever already owns the collector (see MyMesh::tickOtaTrialHealth(),
// which calls collector.serviceStep() unconditionally whenever a job is
// Pending, entirely independent of USB activity). This adapter therefore
// only ever starts/reads/cancels a job here -- never calls serviceStep()
// itself -- preserving the "MCU never loops to completion inside one USB
// callback" contract documented on IOtaControlJobBackend.
//
// Only OtaControlSubcommand::Measure is handled; Certify/Prepare/Activate
// report an explicit terminal NoCapacity (never a fake Ok/Pending) until
// Authority's/Store's own adapters land -- this backend must never claim
// those operations are available just because Measure is real.

#include <cstring>

#include "helpers/ota/OtaBaselineMeasurementCollector.h"
#include "ota/runtime/OtaControlSessionRouter.h"

namespace meshcore {
namespace ota {
namespace runtime {

class OtaMeasurementControlJobBackend : public IOtaControlJobBackend {
public:
  // Typed reasons reported via the `reason` out-param, disjoint from the
  // router's own 0-108 / dispatch()'s 200-220 ranges (see
  // OtaControlSessionRouter.h's reason-namespace comment) -- this
  // backend's reasons occupy 300+.
  static constexpr uint16_t kReasonUnsupportedOperation = 300;
  static constexpr uint16_t kReasonForeignTicket = 301;
  static constexpr uint16_t kReasonBadObjectKind = 302;
  static constexpr uint16_t kReasonBeginRejected = 303;        // see OtaBaselineMeasurementBeginRejection below.
  static constexpr uint16_t kReasonEncodeFailed = 304;         // evidence present but failed to encode onto the wire.
  static constexpr uint16_t kReasonNoActiveJob = 305;

  explicit OtaMeasurementControlJobBackend(mesh::ota::OtaBaselineMeasurementCollector& collector)
      : collector_(collector) {}

  OtaControlStatus beginJob(OtaControlSubcommand sub, uint32_t jobTicket, OtaControlObjectKind inputKind,
                             const uint8_t* input, size_t inputLen, uint16_t& reason) override {
    (void)inputKind;
    (void)input;
    (void)inputLen; // Measure takes no uploaded object -- nothing to consume here.
    if (sub != OtaControlSubcommand::Measure) {
      reason = kReasonUnsupportedOperation;
      return OtaControlStatus::NoCapacity;
    }
    encoded_valid_ = false;
    uint8_t zeroHostChallenge[16] = {0}; // Measure carries no caller-supplied host challenge on this wire.
    auto outcome = collector_.begin(zeroHostChallenge, kOwnerToken);
    if (!outcome.started) {
      reason = kReasonBeginRejected;
      return OtaControlStatus::NoCapacity;
    }
    active_ticket_ = jobTicket;
    // Real work happens on the next (and subsequent) tick(s) of
    // whatever already drives this collector -- never inline here.
    return OtaControlStatus::Pending;
  }

  OtaControlStatus pollJob(uint32_t jobTicket, uint16_t& reason) override {
    if (jobTicket != active_ticket_) {
      reason = kReasonForeignTicket;
      return OtaControlStatus::Denied;
    }
    return mapCollectorStatus(reason);
  }

  OtaControlStatus readObject(uint32_t jobTicket, OtaControlObjectKind kind, uint32_t offset, uint8_t* dest,
                               uint8_t maxLen, uint8_t& outLen, uint16_t& reason) override {
    outLen = 0;
    if (jobTicket != active_ticket_) {
      reason = kReasonForeignTicket;
      return OtaControlStatus::Denied;
    }
    if (kind != OtaControlObjectKind::Measurement) {
      reason = kReasonBadObjectKind;
      return OtaControlStatus::Denied;
    }
    OtaControlStatus st = mapCollectorStatus(reason);
    if (st != OtaControlStatus::Ok) return st; // Pending/Failure-mapped status -- nothing to copy yet/ever.
    if (!encoded_valid_) {
      reason = kReasonEncodeFailed;
      return OtaControlStatus::Corrupt;
    }
    if (offset >= sizeof(encoded_)) {
      // Unreachable in practice: OtaCommissioningAbi.h's shape validation
      // already bounds offset/total against the fixed Measurement size
      // before dispatch() ever reaches this backend. Kept as explicit
      // defence-in-depth rather than an unchecked pointer add.
      reason = kReasonBadObjectKind;
      return OtaControlStatus::Denied;
    }
    size_t avail = sizeof(encoded_) - offset;
    size_t n = (maxLen < avail) ? maxLen : avail;
    std::memcpy(dest, encoded_ + offset, n);
    outLen = static_cast<uint8_t>(n);
    return OtaControlStatus::Ok;
  }

  void cancelJob(uint32_t jobTicket) override {
    if (jobTicket != active_ticket_) return;
    collector_.cancel(collector_.currentTicketId(), kOwnerToken);
    active_ticket_ = 0;
    encoded_valid_ = false;
  }

private:
  static constexpr mesh::ota::OtaBaselineMeasurementOwnerToken kOwnerToken{0xBADC0FFEE0000001ULL};

  OtaControlStatus mapCollectorStatus(uint16_t& reason) {
    using Status = mesh::ota::OtaBaselineMeasurementStatus;
    switch (collector_.status()) {
      case Status::Idle:
        reason = kReasonNoActiveJob;
        return OtaControlStatus::NoCapacity;
      case Status::Pending:
        return OtaControlStatus::Pending;
      case Status::Present:
        if (!encoded_valid_ && !encodeNow()) {
          reason = kReasonEncodeFailed;
          return OtaControlStatus::Corrupt;
        }
        return OtaControlStatus::Ok;
      case Status::Failure:
      default:
        reason = static_cast<uint16_t>(collector_.failureReason());
        return OtaControlStatus::Corrupt;
    }
  }

  bool encodeNow() {
    mesh::ota::OtaBaselineMeasurementEvidence evidence;
    if (!collector_.readCompletedEvidence(collector_.currentTicketId(), kOwnerToken, evidence)) return false;

    ota::protocol::OtaControlMeasurement m;
    std::memcpy(m.uid8, evidence.device_uid, sizeof(m.uid8));
    std::memcpy(m.fullPublicKey, evidence.full_public_key, sizeof(m.fullPublicKey));
    m.profile = evidence.profile_id;
    m.target = evidence.target_id;
    m.currentRole = evidence.role_id;
    m.layout = evidence.layout_id;
    std::memcpy(m.sdk28Sha256, evidence.current_sdk_sha256, sizeof(m.sdk28Sha256));
    m.imageExtent = evidence.current_image_extent;
    m.imageAddress = evidence.current_image_internal_addr;
    std::memcpy(m.imageSha256, evidence.current_image_sha256, sizeof(m.imageSha256));
    m.imageCrc16 = evidence.current_image_crc16;
    m.loaderStart = evidence.stock_loader_range_start;
    m.loaderLength = evidence.stock_loader_range_length;
    std::memcpy(m.loaderSha256, evidence.stock_loader_hash, sizeof(m.loaderSha256));
    m.bootConfigId = evidence.boot_config_id;
    std::memcpy(m.hostChallenge, evidence.host_challenge, sizeof(m.hostChallenge));
    std::memcpy(m.deviceNonce, evidence.device_nonce, sizeof(m.deviceNonce));
    std::memcpy(m.rawSdk28, evidence.raw_sdk28, sizeof(m.rawSdk28));

    size_t outLen = 0;
    auto result = ota::protocol::encodeOtaControlMeasurement(m, encoded_, sizeof(encoded_), outLen);
    encoded_valid_ = (result == ota::protocol::OtaControlCodecResult::Ok && outLen == sizeof(encoded_));
    return encoded_valid_;
  }

  mesh::ota::OtaBaselineMeasurementCollector& collector_;
  uint32_t active_ticket_ = 0;
  bool encoded_valid_ = false;
  uint8_t encoded_[235] = {0};
};

} // namespace runtime
} // namespace ota
} // namespace meshcore
