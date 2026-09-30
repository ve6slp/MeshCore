#pragma once

#include "Esp32DurableBlobStore.h"
#include "ota/platform/Esp32FlashAdapter.h"
#include "ota/protocol/OtaDescriptor.h"
#include "ota/runtime/OtaSessionIdentity.h"

namespace ota {
namespace storage {

enum class Esp32ConsentState : uint8_t { Denied, Granted, Revoked };
enum class Esp32StagingPhase : uint8_t { Admitted, Erasing, Receiving, Staged, Aborted };

struct Esp32AttemptRecord {
  uint8_t signedDescriptor[123] = {};  // canonical descriptor59 + signature64, verbatim
  uint8_t controller[32] = {};
  meshcore::ota::runtime::OtaSessionId session;
  uint8_t attemptDigest[32] = {};  // supplied by the shared authenticated-attempt owner
  Esp32PartitionIdentity partition;
  uint32_t erasedBytes = 0;
  uint32_t verifiedBytes = 0;
  Esp32ConsentState consent = Esp32ConsentState::Denied;
  Esp32StagingPhase phase = Esp32StagingPhase::Admitted;
};

// Security/authorization semantics belong to shared Core/FW, not a second
// ESP protocol. Integrators MUST validate commissioned security contents and
// the authenticated controller + descriptor + fresh local consent here.
class Esp32AttemptPolicy {
public:
  virtual ~Esp32AttemptPolicy() = default;
  virtual bool commissionedSecurityValid(const uint8_t* payload, size_t len) const = 0;
  virtual bool authorizedAttemptValid(const Esp32AttemptRecord& record) const = 0;

  // Explicitly authorize retiring this terminal record for this NEW bound
  // attempt, with fresh authenticated-controller authorization/local consent,
  // not the terminal record's stored grant. For Staged, positively establish
  // that no installer/trial still owns it; unknown state or a stock profile
  // is not qualification. Unsupported retirement fails closed. Authorization
  // and exclusive ownership must remain held through the synchronous save.
  virtual bool authorizeTerminalReplacement(const Esp32AttemptRecord& /*terminal*/,
                                            const Esp32AttemptRecord& /*next*/) const {
    return false;
  }
};

class Esp32AttemptCodec {
public:
  static constexpr size_t kBytes = 236;

  static bool descriptor(const Esp32AttemptRecord& record,
                         meshcore::ota::protocol::OtaDescriptor& out) {
    return meshcore::ota::protocol::decodeOtaDescriptorCanonical(record.signedDescriptor, 59, out) ==
           meshcore::ota::protocol::OtaDescriptorCodecResult::Ok;
  }

  static bool valid(const Esp32AttemptRecord& record) {
    meshcore::ota::protocol::OtaDescriptor image;
    if (!descriptor(record, image) || image.exactSizeBytes == 0 ||
        image.exactSizeBytes > record.partition.size ||
        (!esp32PartitionEquals(record.partition, Esp32S3PartitionLayout::entry(2)) &&
         !esp32PartitionEquals(record.partition, Esp32S3PartitionLayout::entry(3))) ||
        record.verifiedBytes > image.exactSizeBytes || record.erasedBytes % 4096 != 0 ||
        record.erasedBytes > record.partition.size ||
        record.consent > Esp32ConsentState::Revoked || record.phase > Esp32StagingPhase::Aborted)
      return false;
    const uint32_t erase_extent = ((image.exactSizeBytes - 1) / 4096 + 1) * 4096;
    if (record.erasedBytes > erase_extent) return false;
    if (record.phase == Esp32StagingPhase::Admitted &&
        (record.erasedBytes != 0 || record.verifiedBytes != 0)) return false;
    if (record.phase == Esp32StagingPhase::Erasing && record.verifiedBytes != 0) return false;
    if ((record.phase == Esp32StagingPhase::Receiving || record.phase == Esp32StagingPhase::Staged) &&
        record.erasedBytes != erase_extent) return false;
    if (record.phase == Esp32StagingPhase::Staged && record.verifiedBytes != image.exactSizeBytes) return false;
    return true;
  }

  static size_t encode(const Esp32AttemptRecord& record, uint8_t* out, size_t len) {
    if (!valid(record) || out == nullptr || len < kBytes) return 0;
    meshcore::ota::protocol::OtaBoundedWriter writer(out, len);
    const auto& p = record.partition;
    if (!writer.putBytes(record.signedDescriptor, sizeof(record.signedDescriptor)) ||
        !writer.putBytes(record.controller, sizeof(record.controller)) ||
        !writer.putU32(record.session.campaignId) || !writer.putU32(record.session.sessionId) ||
        !writer.putU16(record.session.attemptId) ||
        !writer.putBytes(record.attemptDigest, sizeof(record.attemptDigest)) ||
        !writer.putU32(p.address) || !writer.putU32(p.size) ||
        !writer.putU8(p.type) || !writer.putU8(p.subtype) ||
        !writer.putBytes(reinterpret_cast<const uint8_t*>(p.label), sizeof(p.label)) ||
        !writer.putU8(p.encrypted ? 1 : 0) || !writer.putU8(p.defaultFlash ? 1 : 0) ||
        !writer.putU32(record.erasedBytes) || !writer.putU32(record.verifiedBytes) ||
        !writer.putU8(static_cast<uint8_t>(record.consent)) ||
        !writer.putU8(static_cast<uint8_t>(record.phase))) return 0;
    return writer.size();
  }

  static bool decode(const uint8_t* bytes, size_t len, Esp32AttemptRecord& out) {
    if (bytes == nullptr || len != kBytes) return false;
    Esp32AttemptRecord record;
    meshcore::ota::protocol::OtaBoundedReader reader(bytes, len);
    uint8_t encrypted = 0, default_flash = 0, consent = 0, phase = 0;
    auto& p = record.partition;
    if (!reader.getBytes(record.signedDescriptor, sizeof(record.signedDescriptor)) ||
        !reader.getBytes(record.controller, sizeof(record.controller)) ||
        !reader.getU32(record.session.campaignId) || !reader.getU32(record.session.sessionId) ||
        !reader.getU16(record.session.attemptId) ||
        !reader.getBytes(record.attemptDigest, sizeof(record.attemptDigest)) ||
        !reader.getU32(p.address) || !reader.getU32(p.size) || !reader.getU8(p.type) ||
        !reader.getU8(p.subtype) ||
        !reader.getBytes(reinterpret_cast<uint8_t*>(p.label), sizeof(p.label)) ||
        !reader.getU8(encrypted) || !reader.getU8(default_flash) ||
        !reader.getU32(record.erasedBytes) || !reader.getU32(record.verifiedBytes) ||
        !reader.getU8(consent) || !reader.getU8(phase) || encrypted > 1 || default_flash > 1) return false;
    p.encrypted = encrypted != 0;
    p.defaultFlash = default_flash != 0;
    record.consent = static_cast<Esp32ConsentState>(consent);
    record.phase = static_cast<Esp32StagingPhase>(phase);
    if (!valid(record)) return false;
    out = record;
    return true;
  }

  static bool sameAttempt(const Esp32AttemptRecord& a, const Esp32AttemptRecord& b) {
    return memcmp(a.signedDescriptor, b.signedDescriptor, sizeof(a.signedDescriptor)) == 0 &&
           memcmp(a.controller, b.controller, sizeof(a.controller)) == 0 &&
           meshcore::ota::runtime::otaSessionEquals(a.session, b.session) &&
           memcmp(a.attemptDigest, b.attemptDigest, sizeof(a.attemptDigest)) == 0 &&
           esp32PartitionEquals(a.partition, b.partition);
  }
};

class Esp32AttemptStore {
public:
  Esp32AttemptStore(Esp32DurableBlobStore& blobs, platform::Esp32FlashAdapter& flash,
                    const Esp32AttemptPolicy& policy) : blobs_(blobs), flash_(flash), policy_(policy) {}

  // First admission only. An existing record is never implicitly discarded;
  // subsequent campaigns require the explicit replaceTerminal transition.
  Esp32PersistenceResult admit(const Esp32AttemptRecord& record) {
    flash_.unbind();
    if (!Esp32AttemptCodec::valid(record) || record.phase != Esp32StagingPhase::Admitted ||
        record.consent != Esp32ConsentState::Granted || !policy_.authorizedAttemptValid(record))
      return {Esp32PersistenceStatus::InvalidArgument};
    const auto security = securityReady();
    if (!security.ok()) return security;
    const auto capacity = blobs_.capacity(Esp32AttemptCodec::kBytes);
    if (!capacity.ok()) return capacity;
    Esp32DurableBlob previous;
    const auto loaded = blobs_.load(Esp32BlobKind::Attempt, previous);
    if (loaded.ok()) return {Esp32PersistenceStatus::Conflict};
    if (loaded.status != Esp32PersistenceStatus::Missing) return loaded;
    const auto binding = bind(record);
    if (!binding.ok()) return binding;
    return save(record, Esp32BlobCreation::ExplicitProvision);
  }

  // Retire Aborted, or explicitly policy-qualified Staged, and admit next in
  // ONE journal generation. expected_terminal must match the entire winning
  // checkpoint. next must be Admitted/Granted with zero progress, a strictly
  // newer tuple under OtaReplayGuard's ordering, a new bound attempt digest,
  // and freshly validated policy/SDK ownership/boot selection. A new attempt
  // may retry the SAME signed image; changing only its descriptor/controller
  // cannot resurrect the old tuple. Never delete metadata, reset Security/TX/
  // RX state, erase image bytes, or recover corrupt/uncertain state here.
  Esp32PersistenceResult replaceTerminal(const Esp32AttemptRecord& expected_terminal,
                                        const Esp32AttemptRecord& next_request) {
    flash_.unbind();
    // Policy callbacks may update caller-owned state through other aliases;
    // approval and persistence must refer to the SAME frozen request.
    const Esp32AttemptRecord next = next_request;
    if (!Esp32AttemptCodec::valid(expected_terminal) || !Esp32AttemptCodec::valid(next) ||
        next.phase != Esp32StagingPhase::Admitted || next.consent != Esp32ConsentState::Granted ||
        !policy_.authorizedAttemptValid(next)) return {Esp32PersistenceStatus::InvalidArgument};
    auto security = securityReady();
    if (!security.ok()) return security;
    Esp32DurableBlob stored;
    auto loaded = blobs_.load(Esp32BlobKind::Attempt, stored);
    if (!loaded.ok()) return loaded;
    Esp32AttemptRecord current;
    if (!Esp32AttemptCodec::decode(stored.payload, stored.size, current))
      return {Esp32PersistenceStatus::Corrupt};
    if (!sameCheckpoint(current, expected_terminal) ||
        (current.phase != Esp32StagingPhase::Aborted && current.phase != Esp32StagingPhase::Staged) ||
        !meshcore::ota::runtime::otaSessionIsNewer(next.session, current.session) ||
        memcmp(next.attemptDigest, current.attemptDigest, sizeof(next.attemptDigest)) == 0)
      return {Esp32PersistenceStatus::Conflict};
    const auto capacity = blobs_.capacity(Esp32AttemptCodec::kBytes);
    if (!capacity.ok()) return capacity;
    if (!policy_.authorizeTerminalReplacement(current, next))
      return {Esp32PersistenceStatus::OwnershipDenied};
    // The policy decision must not become a stale retirement proof if its
    // callback changes commissioning or the winning transaction.
    security = securityReady();
    if (!security.ok()) return security;
    Esp32DurableBlob latest;
    loaded = blobs_.load(Esp32BlobKind::Attempt, latest);
    if (!loaded.ok()) return loaded;
    Esp32AttemptRecord latest_record;
    if (!Esp32AttemptCodec::decode(latest.payload, latest.size, latest_record))
      return {Esp32PersistenceStatus::Corrupt};
    if (latest.generation != stored.generation || !sameCheckpoint(current, latest_record))
      return {Esp32PersistenceStatus::Conflict};
    if (!policy_.authorizedAttemptValid(next)) return {Esp32PersistenceStatus::OwnershipDenied};
    const auto binding = bind(next);
    if (!binding.ok()) return binding;
    return save(next);
  }

  // Resume only reads metadata and rebinds a fresh inactive partition.
  // It never erases the slot or resets durable progress/consent.
  Esp32PersistenceResult resume(Esp32AttemptRecord& out) {
    flash_.unbind();
    const auto security = securityReady();
    if (!security.ok()) return security;
    Esp32DurableBlob stored;
    const auto loaded = blobs_.load(Esp32BlobKind::Attempt, stored);
    if (!loaded.ok()) return loaded;
    Esp32AttemptRecord record;
    if (!Esp32AttemptCodec::decode(stored.payload, stored.size, record))
      return {Esp32PersistenceStatus::Corrupt};
    if (record.phase == Esp32StagingPhase::Aborted) return {Esp32PersistenceStatus::Conflict};
    // Authorization may reject revoked/expired consent; it must not mint
    // new consent or treat a signer as an authenticated controller.
    if (record.consent != Esp32ConsentState::Granted || !policy_.authorizedAttemptValid(record))
      return {Esp32PersistenceStatus::OwnershipDenied};
    const auto binding = bind(record);
    if (!binding.ok()) return binding;
    out = record;
    return {};
  }

  Esp32PersistenceResult checkpoint(const Esp32AttemptRecord& next) {
    Esp32AttemptRecord current;
    const auto loaded = resume(current);
    if (!loaded.ok()) return loaded;
    if (!Esp32AttemptCodec::valid(next) || !Esp32AttemptCodec::sameAttempt(current, next) ||
        next.verifiedBytes < current.verifiedBytes || next.erasedBytes < current.erasedBytes ||
        (current.consent != Esp32ConsentState::Granted && next.consent == Esp32ConsentState::Granted) ||
        (current.consent == Esp32ConsentState::Revoked && next.consent != Esp32ConsentState::Revoked) ||
        (next.consent != Esp32ConsentState::Granted &&
         (next.verifiedBytes != current.verifiedBytes || next.erasedBytes != current.erasedBytes ||
          (next.phase != current.phase && next.phase != Esp32StagingPhase::Aborted))) ||
        !phaseTransition(current.phase, next.phase)) return {Esp32PersistenceStatus::Conflict};
    const auto saved = save(next);
    if (!saved.ok() || next.consent != Esp32ConsentState::Granted ||
        next.phase == Esp32StagingPhase::Aborted) flash_.unbind();
    return saved;
  }

private:
  static bool sameCheckpoint(const Esp32AttemptRecord& a, const Esp32AttemptRecord& b) {
    return Esp32AttemptCodec::sameAttempt(a, b) && a.erasedBytes == b.erasedBytes &&
           a.verifiedBytes == b.verifiedBytes && a.consent == b.consent && a.phase == b.phase;
  }

  Esp32PersistenceResult save(const Esp32AttemptRecord& record,
                            Esp32BlobCreation creation = Esp32BlobCreation::ExistingOnly) {
    uint8_t bytes[Esp32AttemptCodec::kBytes];
    const auto len = Esp32AttemptCodec::encode(record, bytes, sizeof(bytes));
    const auto saved = blobs_.save(Esp32BlobKind::Attempt, bytes, len, creation);
    if (!saved.ok()) flash_.unbind();
    return saved;
  }

  static bool phaseTransition(Esp32StagingPhase from, Esp32StagingPhase to) {
    if (from == to) return true;
    if (from == Esp32StagingPhase::Aborted || from == Esp32StagingPhase::Staged) return false;
    if (to == Esp32StagingPhase::Aborted) return true;
    return (from == Esp32StagingPhase::Admitted && to == Esp32StagingPhase::Erasing) ||
           (from == Esp32StagingPhase::Erasing && to == Esp32StagingPhase::Receiving) ||
           (from == Esp32StagingPhase::Receiving && to == Esp32StagingPhase::Staged);
  }

  Esp32PersistenceResult securityReady() {
    Esp32DurableBlob security;
    const auto loaded = blobs_.load(Esp32BlobKind::Security, security);
    if (!loaded.ok()) return loaded;
    if (!policy_.commissionedSecurityValid(security.payload, security.size))
      return {Esp32PersistenceStatus::Corrupt};
    return {};
  }

  Esp32PersistenceResult bind(const Esp32AttemptRecord& record) {
    meshcore::ota::protocol::OtaDescriptor image;
    if (!Esp32AttemptCodec::descriptor(record, image)) return {Esp32PersistenceStatus::Corrupt};
    const auto status = flash_.bind(image.exactSizeBytes, &record.partition);
    if (!platform::isOk(status))
      return {flash_.lastRefusal() == platform::Esp32FlashAdapter::Refusal::Sdk
          ? Esp32PersistenceStatus::IoError : Esp32PersistenceStatus::PartitionMismatch,
          flash_.lastSdkError()};
    return {};
  }

  Esp32DurableBlobStore& blobs_;
  platform::Esp32FlashAdapter& flash_;
  const Esp32AttemptPolicy& policy_;
};

}  // namespace storage
}  // namespace ota
