#pragma once

// Fake (test-only) implementations of every injectable port consumed by
// src/ota/campaign/**. Each fake fails closed by default and exposes
// explicit knobs (ShouldFail flags, corruption helpers, drop/backpressure
// queues) so tests can drive real negative/failure paths through the
// actual engine code rather than asserting on the fakes themselves.

#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <vector>
#include <deque>

#include "ota/campaign/CampaignCommon.h"
#include "ota/campaign/CampaignPorts.h"
#include "ota/protocol/OtaByteStream.h"
#include "ota/runtime/OtaTrustInterfaces.h"
#include "ota/storage/Crc32.h"

namespace meshcore {
namespace ota {
namespace campaign {
namespace test {

inline CampaignPeerId makePeerId(uint8_t fillByte) {
  CampaignPeerId id;
  std::memset(id.bytes, fillByte, sizeof(id.bytes));
  return id;
}

class FakeClock : public IClockPort {
public:
  uint32_t nowMs() const override { return t_; }
  void advance(uint32_t ms) { t_ += ms; }
  uint32_t t_ = 1000;
};

// Records every send (no automatic routing): tests explicitly relay bytes
// from one node's sentLog into another node's onFrame() so drop/reorder/
// duplicate/foreign-identity scenarios are entirely test-controlled while
// still exercising the engines' real wire-decoding path.
class FakeTransport : public IAuthenticatedTransportPort {
public:
  struct Sent {
    CampaignDestination dest;
    protocol::OtaAirtimeCategory category;
    std::vector<uint8_t> bytes;
  };

  CampaignSendResult trySend(const CampaignDestination& dest, protocol::OtaAirtimeCategory category,
                              const uint8_t* frame, size_t frameLen) override {
    CampaignSendResult r = CampaignSendResult::Enqueued;
    if (!forcedResults.empty()) {
      r = forcedResults.front();
      forcedResults.pop_front();
    }
    if (r == CampaignSendResult::Enqueued) {
      Sent s;
      s.dest = dest;
      s.category = category;
      s.bytes.assign(frame, frame + frameLen);
      sentLog.push_back(std::move(s));
      // By default a fake "send" completes transmission immediately (most
      // tests don't care about TX-completion timing). Setting
      // autoCompleteSends=false models a real radio where enqueued !=
      // transmitted, letting tests exercise engines that gate a profile
      // switch on real TX-completion evidence (see
      // IAuthenticatedTransportPort::txQueueEmpty()).
      if (!autoCompleteSends) ++inFlightCount_;
    }
    return r;
  }

  bool pollInbound(AuthenticatedInboundFrame&) override { return false; }

  bool txQueueEmpty() const override { return inFlightCount_ == 0; }
  void completeOneSend() {
    if (inFlightCount_ > 0) --inFlightCount_;
  }
  void completeAllSends() { inFlightCount_ = 0; }

  std::deque<CampaignSendResult> forcedResults;
  std::vector<Sent> sentLog;
  bool autoCompleteSends = true;
  size_t inFlightCount_ = 0;
};

inline AuthenticatedInboundFrame makeInboundFrame(const std::vector<uint8_t>& bytes, const CampaignPeerId& sender,
                                                   bool authenticated = true) {
  AuthenticatedInboundFrame f;
  f.authenticated = authenticated;
  f.context = PairwiseAuthContext{sender};
  f.payload = bytes.data();
  f.payloadLen = bytes.size();
  return f;
}

// Constructs a genuinely peer-less Group-scoped inbound frame: unlike
// makeInboundFrame() above, there is NO sender/peer identity parameter at
// all here, by design -- a real Group-scoped decrypt structurally cannot
// prove which single member sent it, and this fake must not be able to
// pretend otherwise merely for test convenience.
inline AuthenticatedInboundFrame makeGroupInboundFrame(const std::vector<uint8_t>& bytes, uint32_t groupId,
                                                        bool membershipVerified = true, bool authenticated = true) {
  AuthenticatedInboundFrame f;
  f.authenticated = authenticated;
  f.context = GroupAuthContext{groupId, membershipVerified};
  f.payload = bytes.data();
  f.payloadLen = bytes.size();
  return f;
}

class FakePersistence : public ICampaignPersistencePort {
public:
  CampaignSaveResult save(CampaignPersistRole role, const uint8_t* data, size_t len) override {
    if (saveShouldFail) return CampaignSaveResult::RejectedBeforeMutation;
    if (forceRejectNextSaveForRoleActive && role == forceRejectNextSaveForRole) {
      forceRejectNextSaveForRoleActive = false;
      return CampaignSaveResult::RejectedBeforeMutation;
    }
    if (forceUncertainNextSaveForRoleActive && role == forceUncertainNextSaveForRole) {
      forceUncertainNextSaveForRoleActive = false;
      store[role].assign(data, data + len);
      return CampaignSaveResult::Uncertain;
    }
    if (forceUncertainNextSave) {
      forceUncertainNextSave = false;
      // Simulates a write that physically landed but whose readback/ack
      // step failed (or power was lost immediately after the write): the
      // durable bytes below ARE the new candidate, but the port reports
      // Uncertain rather than Saved.
      store[role].assign(data, data + len);
      return CampaignSaveResult::Uncertain;
    }
    store[role].assign(data, data + len);
    return CampaignSaveResult::Saved;
  }
  CampaignLoadResult load(CampaignPersistRole role, uint8_t* out, size_t cap, size_t& outLen) override {
    if (forceIoError) return CampaignLoadResult::IoError;
    if (forceCorrupt) return CampaignLoadResult::Corrupt;
    auto it = store.find(role);
    if (it == store.end()) return CampaignLoadResult::Missing;
    if (it->second.size() > cap) return CampaignLoadResult::Corrupt;
    std::memcpy(out, it->second.data(), it->second.size());
    outLen = it->second.size();
    return CampaignLoadResult::Ok;
  }
  bool erase(CampaignPersistRole role) override {
    if (forceEraseFailForRoleActive && role == forceEraseFailForRole) {
      forceEraseFailForRoleActive = false;
      if (forceEraseAppliedBeforeFailure) store.erase(role);
      return false; // simulates an erase whose confirming readback failed, scoped to ONE role
    }
    if (forceEraseFail) {
      forceEraseFail = false;
      return false; // simulates an erase whose confirming readback failed
    }
    store.erase(role);
    return true;
  }

  // Test-only corruption helper: flips one byte at `offset` in the
  // durable record for `role` (used to simulate a corrupt/hostile reload
  // record without going through save()).
  void corruptByte(CampaignPersistRole role, size_t offset, uint8_t xorMask = 0xFF) {
    auto it = store.find(role);
    if (it == store.end() || offset >= it->second.size()) return;
    it->second[offset] ^= xorMask;
  }

  bool saveShouldFail = false;
  bool forceUncertainNextSave = false; // one-shot: consumed by the next save() call, ANY role
  // One-shot, but scoped to exactly ONE role -- lets a test force
  // RejectedBeforeMutation on (e.g.) only the main-record write while
  // letting an earlier commission-provenance write for the SAME
  // admission attempt succeed first.
  bool forceRejectNextSaveForRoleActive = false;
  CampaignPersistRole forceRejectNextSaveForRole = CampaignPersistRole::TargetReceiver;
  // One-shot, but scoped to exactly ONE role -- lets a test force
  // Uncertain on (e.g.) only the commission-provenance write, or only
  // the main-record write, without affecting the other save() call that
  // the SAME admission attempt also performs.
  bool forceUncertainNextSaveForRoleActive = false;
  CampaignPersistRole forceUncertainNextSaveForRole = CampaignPersistRole::TargetReceiver;
  bool forceIoError = false;
  bool forceCorrupt = false;
  bool forceEraseFail = false; // one-shot: consumed by the next erase() call, ANY role
  // One-shot, but scoped to exactly ONE role -- lets a test force a
  // specific role's erase() to report unconfirmed without affecting any
  // other role's erase() in the same call sequence.
  bool forceEraseFailForRoleActive = false;
  bool forceEraseAppliedBeforeFailure = false;
  CampaignPersistRole forceEraseFailForRole = CampaignPersistRole::TargetReceiver;
  std::map<CampaignPersistRole, std::vector<uint8_t>> store;
};

// Test-only stand-in for a real factory/security-provisioned backing.
// Models an explicit, independent, VERSIONED, CRC-protected, tri-state
// record in actual persistent bytes (not a RAM sentinel): the record
// binds a Virgin/Used marker to a specific 32-byte device-identity
// fixture, and readCommissioningProvenance() only reports a positive
// Virgin/Used result once it has verified (a) the bytes decode cleanly
// (magic/version/CRC all valid) AND (b) the bound identity in the
// record matches the identity this port instance was configured to
// represent -- a stand-in for "these are genuinely THIS device's own
// factory-burned facts", never some other device's readable-but-foreign
// bytes. Any other outcome (never provisioned, corrupted, wrong
// identity) is Unknown -- the exact same safe default the abstract
// port's own base class returns.
class FakeCommissioningProvenancePort : public ICampaignCommissioningProvenancePort {
public:
  explicit FakeCommissioningProvenancePort(std::array<uint8_t, 32> deviceIdentity = makeAllOnesIdentity())
      : deviceIdentity_(deviceIdentity) {}

  static constexpr uint32_t kMagic = 0x46414354u;  // "FACT"
  static constexpr uint16_t kVersion = 1;
  static constexpr uint8_t kMarkerVirgin = 0x11;
  static constexpr uint8_t kMarkerUsed = 0x22;
  static constexpr size_t kEncodedSize = 4 + 2 + 1 + 32 + 4;  // magic+version+marker+identity+crc32

  // Test-only: simulates genuine factory provisioning writing an
  // explicit, positively-verifiable Virgin record bound to this port's
  // own configured device identity -- models manufacturing, distinct
  // from anything the campaign engine itself ever does.
  void initializeGenuineFactoryVirgin() {
    writeRecordForIdentity(kMarkerVirgin, deviceIdentity_);
    backingPresent_ = true;
  }

  // Test-only: simulates the backing record never having existed, or
  // having been lost (e.g. truly never-provisioned hardware).
  void simulateBackingMissing() { backingPresent_ = false; }

  // Test-only: corrupts the stored bytes so the CRC check fails.
  void corruptBacking() {
    if (!backingPresent_ || bytes_.size() < 9) return;
    bytes_[8] ^= 0xFF;
  }

  // Test-only: simulates a well-formed record that is bound to a
  // DIFFERENT device's identity (e.g. bytes relocated/copied from
  // another unit) -- must read as Unknown, never Used/Virgin, even
  // though the record itself decodes/CRC-checks cleanly.
  void simulateForeignIdentityRecord(uint8_t marker) {
    std::array<uint8_t, 32> foreign{};
    foreign.fill(0xEE);
    writeRecordForIdentity(marker, foreign);
    backingPresent_ = true;
  }

  CampaignCommissioningProvenanceResult readCommissioningProvenance() override {
    if (forceUnknown) return {};
    if (!backingPresent_) return {};  // Unknown: never provisioned / lost
    if (bytes_.size() != kEncodedSize) return {};
    protocol::OtaBoundedReader r(bytes_.data(), bytes_.size());
    uint32_t magic = 0;
    uint16_t version = 0;
    uint8_t marker = 0;
    std::array<uint8_t, 32> identity{};
    if (!(r.getU32(magic) && r.getU16(version) && r.getU8(marker))) return {};
    for (auto& b : identity) {
      uint8_t v = 0;
      if (!r.getU8(v)) return {};
      b = v;
    }
    uint32_t storedCrc = 0;
    if (!r.getU32(storedCrc)) return {};
    const uint32_t expectedCrc = ::ota::storage::Crc32::computeFinalized(bytes_.data(), bytes_.size() - 4);
    if (storedCrc != expectedCrc) return {};
    if (magic != kMagic || version != kVersion) return {};
    if (identity != deviceIdentity_) return {};  // foreign-identity record: Unknown, not proof of anything
    if (marker == kMarkerVirgin) return {CampaignCommissioningState::Virgin};
    if (marker == kMarkerUsed) return {CampaignCommissioningState::Used};
    return {};
  }

  CampaignMarkUsedResult markUsedIfCurrentlyVirgin() override {
    if (forceMarkUsedResult.has_value()) {
      CampaignMarkUsedResult r = *forceMarkUsedResult;
      forceMarkUsedResult.reset();
      return r;
    }
    const CampaignCommissioningProvenanceResult current = readCommissioningProvenance();
    if (current.state == CampaignCommissioningState::Used) return CampaignMarkUsedResult::Confirmed;  // idempotent
    if (current.state != CampaignCommissioningState::Virgin) return CampaignMarkUsedResult::Rejected;  // Unknown: refuse
    writeRecordForIdentity(kMarkerUsed, deviceIdentity_);
    return CampaignMarkUsedResult::Confirmed;
  }

  bool forceUnknown = false;                                   // forces readCommissioningProvenance() to Unknown
  std::optional<CampaignMarkUsedResult> forceMarkUsedResult;    // one-shot override for markUsedIfCurrentlyVirgin()

private:
  static std::array<uint8_t, 32> makeAllOnesIdentity() {
    std::array<uint8_t, 32> id{};
    id.fill(0x01);
    return id;
  }

  void writeRecordForIdentity(uint8_t marker, const std::array<uint8_t, 32>& identity) {
    bytes_.assign(kEncodedSize, 0);
    protocol::OtaBoundedWriter w(bytes_.data(), bytes_.size());
    w.putU32(kMagic);
    w.putU16(kVersion);
    w.putU8(marker);
    for (uint8_t b : identity) w.putU8(b);
    const uint32_t crc = ::ota::storage::Crc32::computeFinalized(bytes_.data(), w.size());
    w.putU32(crc);
  }

  std::array<uint8_t, 32> deviceIdentity_{};
  bool backingPresent_ = false;
  std::vector<uint8_t> bytes_;
};


class FakeTrust : public runtime::IOtaTrustProvider {
public:
  bool verifyDescriptorSignature(const uint8_t*, size_t, const uint8_t*, size_t, uint16_t, uint16_t) override {
    return descriptorValid;
  }
  bool verifyDescriptor(const protocol::OtaDescriptor&, const uint8_t*, size_t) override { return descriptorValid; }
  bool verifyDescriptorPolicy(const protocol::OtaDescriptor&) override { return descriptorValid; }
  bool verifyStagedImageHash(const protocol::OtaDescriptor&) override { return stagedHashValid; }
  bool commitSecurityCounter(uint32_t) override { return true; }

  bool descriptorValid = true;
  bool stagedHashValid = true;
};

class FakeStagingSink : public runtime::IOtaStagingSink {
public:
  Result beginSession(const protocol::OtaDescriptor& d) override {
    if (beginShouldFail) return Result::Rejected;
    // Models a real production sink for which beginSession() ALWAYS means
    // "start brand new": calling it again on an already-in-flight session
    // genuinely discards whatever was previously written. Proves that a
    // reboot-resume path which called beginSession() instead of a real
    // non-destructive resume would silently lose data.
    image.assign(d.exactSizeBytes, 0);
    began = true;
    committed = false;
    aborted = false;
    beginSessionCallCount++;
    return Result::Ok;
  }
  Result writeChunk(uint64_t offset, const uint8_t* data, size_t len) override {
    if (writeShouldFail) return Result::IoError;
    if (offset + len > image.size()) return Result::IoError;
    std::memcpy(image.data() + offset, data, len);
    return Result::Ok;
  }
  Result commit() override {
    if (commitShouldFail) return Result::IoError;
    committed = true;
    return Result::Ok;
  }
  void abort() override { aborted = true; }

  bool beginShouldFail = false, writeShouldFail = false, commitShouldFail = false;
  bool began = false, committed = false, aborted = false;
  uint32_t beginSessionCallCount = 0;
  std::vector<uint8_t> image;
};

// Genuine non-destructive resume adapter for FakeStagingSink: proves the
// campaign layer's reboot-resume path can reattach to an already-begun,
// not-yet-committed/aborted session WITHOUT calling beginSession() (which
// the fake above demonstrably treats as destructive) and WITHOUT
// disturbing any previously-written bytes.
class FakeStagingResume : public IOtaStagingResumePort {
public:
  explicit FakeStagingResume(FakeStagingSink& sink) : sink_(sink) {}

  bool resumeSession(const protocol::OtaDescriptor& descriptor) override {
    if (resumeShouldFail) return false;
    if (!sink_.began || sink_.committed || sink_.aborted) return false;
    if (sink_.image.size() != descriptor.exactSizeBytes) return false;
    resumeCallCount++;
    return true; // reattaches only: image bytes are left exactly as-is
  }

  bool resumeShouldFail = false;
  uint32_t resumeCallCount = 0;

private:
  FakeStagingSink& sink_;
};

class FakeCacheSink : public IOtaCacheOnlySink {
public:
  Result beginCache(const protocol::OtaDescriptor& d) override {
    if (beginShouldFail) return Result::Rejected;
    image.assign(d.exactSizeBytes, 0);
    sealed = false;
    return Result::Ok;
  }
  Result writeChunk(uint64_t offset, const uint8_t* data, size_t len) override {
    if (writeShouldFail) return Result::IoError;
    if (offset + len > image.size()) return Result::IoError;
    std::memcpy(image.data() + offset, data, len);
    return Result::Ok;
  }
  Result sealCache() override {
    if (sealShouldFail) return Result::Rejected;
    sealed = true;
    return Result::Ok;
  }
  bool readCachedAt(uint64_t offset, uint8_t* out, size_t len) override {
    if (!sealed) return false;
    if (offset + len > image.size()) return false;
    std::memcpy(out, image.data() + offset, len);
    return true;
  }
  void abort() override { sealed = false; }

  bool beginShouldFail = false, writeShouldFail = false, sealShouldFail = false;
  bool sealed = false;
  std::vector<uint8_t> image;
};

class FakeHostImageReader : public IImageReaderPort {
public:
  bool readAt(uint64_t offset, uint8_t* out, size_t len) override {
    if (failNext) {
      failNext = false;
      return false;
    }
    if (offset + len > data.size()) return false;
    std::memcpy(out, data.data() + offset, len);
    return true;
  }

  bool failNext = false;
  std::vector<uint8_t> data;
};

class FakeBootEvidence : public IBootEvidencePort {
public:
  CampaignBootEvidence queryBootEvidence() const override { return evidence; }
  CampaignBootEvidence evidence;
};

class FakeConsentPolicy : public IConsentPolicyPort {
public:
  bool isConsentPolicyApproved(const CampaignPeerId&, const protocol::OtaDescriptor&) const override {
    return approve;
  }
  bool approve = true;
};

class FakeLeaseGrantPolicy : public ILeaseGrantPolicyPort {
public:
  bool approveLeaseGrant(const CampaignPeerId&, const CampaignRadioProfileParams&) const override {
    return approve;
  }
  bool approve = true;
};

class FakeRadioProfilePort : public IRadioProfilePort {
public:
  bool applyProfile(const CampaignRadioProfileParams& p) override {
    if (applyShouldFail) return false;
    current = p.profile;
    lastApplied = p;
    return true;
  }
  bool restoreNormalProfile() override {
    if (restoreShouldFail) return false;
    current = CampaignRadioProfile::Normal;
    return true;
  }
  CampaignRadioProfile currentProfile() const override { return current; }
  CampaignRadioProfileParams normalProfileParams() const override { return normal; }
  bool isFrequencyBandApproved(float freqMhz) const override {
    return freqMhz >= approvedMinMhz && freqMhz <= approvedMaxMhz;
  }

  CampaignRadioProfileParams normal{CampaignRadioProfile::Normal, 907.525f, 62.5f, 7, 5};
  CampaignRadioProfile current = CampaignRadioProfile::Normal;
  CampaignRadioProfileParams lastApplied{};
  bool applyShouldFail = false;
  bool restoreShouldFail = false;
  float approvedMinMhz = 902.0f;
  float approvedMaxMhz = 928.0f;
};

} // namespace test
} // namespace campaign
} // namespace ota
} // namespace meshcore
