#include <gtest/gtest.h>
#include <functional>
#include <ota/platform/Esp32FlashAdapter.h>
#include <ota/platform/FlashRegion.h>
#include <ota/storage/Esp32AttemptStore.h>
#include <ota/storage/StorageManager.h>
#include <ota/trust/Ed25519SignatureVerifier.h>
#include <ota/trust/ImageHasher.h>
#include <ota/trust/Sha256.h>
#include "../test_lora_ota_trust/Ed25519TestSigner.h"
#include "Esp32SdkModel.h"

using namespace ota::storage;
using namespace ota::test;
using ota::platform::Esp32FlashAdapter;
using ota::platform::FlashRegion;
using ota::platform::FlashStatus;
using ota::storage::StorageManager;
using Status = Esp32PersistenceStatus;

namespace {

void expectProtected(const Esp32PartitionModel& sdk, const std::vector<uint8_t>& before,
                     const Esp32PartitionIdentity& candidate) {
  EXPECT_EQ(0, memcmp(before.data(), sdk.bytes.data(), candidate.address));
  const size_t tail = candidate.address + candidate.size;
  EXPECT_EQ(0, memcmp(before.data() + tail, sdk.bytes.data() + tail, before.size() - tail));
}

std::vector<uint8_t> encoded(Esp32BlobKind kind, Esp32BlobPhase phase, uint32_t generation,
                             const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> bytes(payload.size() + Esp32BlobCodec::kOverhead);
  EXPECT_EQ(bytes.size(), Esp32BlobCodec::encode(
      kind, phase, generation, payload.data(), payload.size(), bytes.data(), bytes.size()));
  return bytes;
}

void injectRecord(Esp32NvsModel& nvs, Esp32BlobKind kind, Esp32NvsSlot slot,
                  uint32_t generation, const std::vector<uint8_t>& payload,
                  Esp32BlobPhase phase = Esp32BlobPhase::Committed) {
  nvs.namespaceExists = true;
  nvs.durable[{kind, slot}] = encoded(kind, phase, generation, payload);
}

// Test-only commissioning schema; production commissioning/AEAD ledger
// schemas remain owned by Core/FW. The production store treats them as blobs.
class TestAttemptPolicy final : public Esp32AttemptPolicy {
public:
  uint8_t seed[32] = {0x2b, 0x7d, 0x19, 0x53};
  Ed25519TestSigner signer{seed};
  uint8_t controllerSeed[32] = {0x83, 0x6a, 0xef};
  Ed25519TestSigner controllerKey{controllerSeed};
  std::vector<uint8_t> security;
  meshcore::ota::runtime::OtaSessionId authorizedSession{0x12345678, 0x89abcdef, 0x1357};
  uint8_t authorizedController[32] = {};
  bool localConsentValid = true;
  bool revokedAbortAuthorized = false;
  bool replacementAuthorized = false;
  bool stagedRetirementAuthorized = false;
  mutable uint32_t revokedAbortCalls = 0;
  mutable uint32_t replacementCalls = 0;
  std::function<void()> onRevokedAbort;
  std::function<void()> onReplacement;
  std::function<void()> onSecurityValidated;
  TestAttemptPolicy() {
    security.insert(security.end(), signer.publicKey(), signer.publicKey() + 32);
    security.insert(security.end(), controllerKey.publicKey(), controllerKey.publicKey() + 32);
    security.insert(security.end(), {0, 0, 0, 7});  // commissioned, nonzero floor
    memcpy(authorizedController, controllerKey.publicKey(), sizeof(authorizedController));
  }
  bool commissionedSecurityValid(const uint8_t* payload, size_t len) const override {
    const bool valid = len == security.size() && memcmp(payload, security.data(), len) == 0;
    if (valid && onSecurityValidated) onSecurityValidated();
    return valid;
  }
  bool authorizedAttemptValid(const Esp32AttemptRecord& record) const override {
    return localConsentValid && record.consent == Esp32ConsentState::Granted &&
           authenticatedBindingValid(record);
  }
  bool authenticatedBindingValid(const Esp32AttemptRecord& record) const {
    const ota::trust::Ed25519SignatureVerifier verifier;
    uint8_t digest[32];
    attemptDigest(record, digest);
    return memcmp(record.controller, authorizedController, 32) == 0 &&
           meshcore::ota::runtime::otaSessionEquals(record.session, authorizedSession) &&
           memcmp(record.attemptDigest, digest, sizeof(digest)) == 0 &&
           verifier.verify(record.signedDescriptor + 59, 64, record.signedDescriptor, 59,
                           signer.publicKey(), 32);
  }

  bool authorizeRevokedAbort(const Esp32AttemptRecord& revoked) const override {
    ++revokedAbortCalls;
    if (onRevokedAbort) onRevokedAbort();
    return revokedAbortAuthorized && revoked.consent == Esp32ConsentState::Revoked &&
           authenticatedBindingValid(revoked);
  }

  bool authorizeTerminalReplacement(const Esp32AttemptRecord& terminal,
                                    const Esp32AttemptRecord&) const override {
    ++replacementCalls;
    const bool allowed = replacementAuthorized &&
        (terminal.phase != Esp32StagingPhase::Staged || stagedRetirementAuthorized);
    if (onReplacement) onReplacement();
    return allowed;
  }

  // Test-only frozen binding; this does not define a production nonce codec.
  static void attemptDigest(const Esp32AttemptRecord& record, uint8_t out[32]) {
    uint8_t bytes[123 + 32 + 10];
    meshcore::ota::protocol::OtaBoundedWriter writer(bytes, sizeof(bytes));
    EXPECT_TRUE(writer.putBytes(record.signedDescriptor, 123));
    EXPECT_TRUE(writer.putBytes(record.controller, 32));
    EXPECT_TRUE(writer.putU32(record.session.campaignId));
    EXPECT_TRUE(writer.putU32(record.session.sessionId));
    EXPECT_TRUE(writer.putU16(record.session.attemptId));
    ota::trust::Sha256::hash(bytes, writer.size(), out);
  }

  Esp32AttemptRecord attempt(const Esp32PartitionIdentity& partition,
                            const std::vector<uint8_t>& image) const {
    Esp32AttemptRecord record;
    meshcore::ota::protocol::OtaDescriptor descriptor;
    descriptor.boardFamily = 0x4553;
    descriptor.boardVariant = 0x5333;
    descriptor.role = 1;
    descriptor.appAddress = 0x10000;
    descriptor.exactSizeBytes = static_cast<uint32_t>(image.size());
    ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
    descriptor.securityCounter = 8;
    descriptor.formatId = 1;
    descriptor.keyId = 2;
    descriptor.algorithmId = 1;
    size_t written = 0;
    EXPECT_EQ(meshcore::ota::protocol::OtaDescriptorCodecResult::Ok,
              meshcore::ota::protocol::encodeOtaDescriptorCanonical(
                  descriptor, record.signedDescriptor, 59, written));
    EXPECT_EQ(59u, written);
    signer.sign(record.signedDescriptor, 59, record.signedDescriptor + 59);
    memcpy(record.controller, controllerKey.publicKey(), 32);
    record.session = {0x12345678, 0x89abcdef, 0x1357};
    // A fixture token only: production obtains this immutable digest from
    // the shared attempt owner, not an ESP-specific nonce derivation.
    attemptDigest(record, record.attemptDigest);
    record.partition = partition;
    record.consent = Esp32ConsentState::Granted;
    return record;
  }
};

class DefaultReplacementPolicy final : public Esp32AttemptPolicy {
public:
  explicit DefaultReplacementPolicy(const TestAttemptPolicy& policy) : policy_(policy) {}
  bool commissionedSecurityValid(const uint8_t* payload, size_t len) const override {
    return policy_.commissionedSecurityValid(payload, len);
  }
  bool authorizedAttemptValid(const Esp32AttemptRecord& record) const override {
    return policy_.authorizedAttemptValid(record);
  }
private:
  const TestAttemptPolicy& policy_;
};

class AttemptFixture : public ::testing::Test {
protected:
  Esp32PartitionModel partitions;
  Esp32NvsModel nvs;
  Esp32Owners owners;
  Esp32FlashAdapter flash{partitions, owners};
  Esp32DurableBlobStore blobs{nvs, owners};
  TestAttemptPolicy policy;
  Esp32AttemptStore attempts{blobs, flash, policy};
  std::vector<uint8_t> image = std::vector<uint8_t>(1024, 0x37);
  Esp32AttemptRecord record = policy.attempt(partitions.snapshot.next, image);

  void provisionSecurity() {
    ASSERT_TRUE(blobs.save(Esp32BlobKind::Security, policy.security.data(), policy.security.size(),
                           Esp32BlobCreation::ExplicitProvision).ok());
  }
  void admitAndPrepare() {
    provisionSecurity();
    ASSERT_TRUE(attempts.admit(record).ok());
    record.phase = Esp32StagingPhase::Erasing;
    ASSERT_TRUE(attempts.checkpoint(record).ok());
    ASSERT_EQ(FlashStatus::Ok, flash.eraseSector(0));
    record.erasedBytes = 4096;
    ASSERT_TRUE(attempts.checkpoint(record).ok());
    record.phase = Esp32StagingPhase::Receiving;
    ASSERT_TRUE(attempts.checkpoint(record).ok());
  }
  void makeTerminal(Esp32StagingPhase phase = Esp32StagingPhase::Aborted,
                    Esp32ConsentState consent = Esp32ConsentState::Granted) {
    admitAndPrepare();
    ASSERT_FALSE(HasFatalFailure());
    if (phase == Esp32StagingPhase::Staged) {
      FlashRegion candidate(flash, 0, flash.totalSizeBytes());
      ASSERT_TRUE(StorageManager::writeAndVerifyChunk(candidate, 0, 512, image.data(), 512));
      ASSERT_TRUE(StorageManager::writeAndVerifyChunk(candidate, 1, 512, image.data() + 512, 512));
      ota::trust::Sha256 hash;
      uint8_t digest[32];
      ASSERT_TRUE(ota::trust::ImageHasher::hashRegion(hash, candidate, image.size(), digest));
      meshcore::ota::protocol::OtaDescriptor descriptor;
      ASSERT_TRUE(Esp32AttemptCodec::descriptor(record, descriptor));
      ASSERT_EQ(0, memcmp(descriptor.sha256, digest, sizeof(digest)));
      record.verifiedBytes = static_cast<uint32_t>(image.size());
    }
    record.phase = phase;
    record.consent = consent;
    ASSERT_TRUE(attempts.checkpoint(record).ok());
  }
  void revokeReceiving() {
    admitAndPrepare();
    ASSERT_FALSE(HasFatalFailure());
    FlashRegion candidate(flash, 0, flash.totalSizeBytes());
    ASSERT_TRUE(StorageManager::writeAndVerifyChunk(candidate, 0, 512, image.data(), 512));
    record.verifiedBytes = 512;
    ASSERT_TRUE(attempts.checkpoint(record).ok());
    record.consent = Esp32ConsentState::Revoked;
    ASSERT_TRUE(attempts.checkpoint(record).ok());
    policy.localConsentValid = false;
  }
  void seedProtectedBlobs() {
    ASSERT_TRUE(blobs.save(Esp32BlobKind::Security, policy.security.data(), policy.security.size()).ok());
    for (auto kind : {Esp32BlobKind::TxSequence, Esp32BlobKind::RxReplay}) {
      injectRecord(nvs, kind, Esp32NvsSlot::A, 9, {0x01, 0x24, 0x80, 0x18});
      injectRecord(nvs, kind, Esp32NvsSlot::B, 10, {0x01, 0x24, 0x80, 0x19});
    }
  }
  Esp32AttemptRecord nextAttempt() {
    auto next = record;
    ++next.session.attemptId;
    next.phase = Esp32StagingPhase::Admitted;
    next.erasedBytes = next.verifiedBytes = 0;
    next.consent = Esp32ConsentState::Granted;
    TestAttemptPolicy::attemptDigest(next, next.attemptDigest);
    policy.authorizedSession = next.session;
    policy.replacementAuthorized = true;
    return next;
  }
  std::map<Esp32NvsModel::Key, std::vector<uint8_t>> protectedBlobs() const {
    std::map<Esp32NvsModel::Key, std::vector<uint8_t>> out;
    for (const auto& entry : nvs.durable)
      if (entry.first.first != Esp32BlobKind::Attempt) out.insert(entry);
    return out;
  }
  Esp32DurableBlob currentBlob(Esp32DurableBlobStore& store) {
    Esp32DurableBlob stored;
    EXPECT_TRUE(store.load(Esp32BlobKind::Attempt, stored).ok());
    return stored;
  }
  std::vector<uint8_t> attemptPayload(const Esp32AttemptRecord& attempt) {
    std::vector<uint8_t> bytes(Esp32AttemptCodec::kBytes);
    EXPECT_EQ(bytes.size(), Esp32AttemptCodec::encode(attempt, bytes.data(), bytes.size()));
    return bytes;
  }
  struct Snapshot {
    std::map<Esp32NvsModel::Key, std::vector<uint8_t>> durable;
    std::map<std::string, std::vector<uint8_t>> unrelated;
    std::vector<uint8_t> nor;
    std::vector<uint32_t> erased;
    uint32_t sets, commits, programs;
  };
  Snapshot snapshot() const {
    return {nvs.durable, nvs.unrelated, partitions.bytes, partitions.erasedOffsets,
            nvs.setCalls, nvs.commitCalls, partitions.writeCalls};
  }
  void expectProtectedState(const Snapshot& before) const {
    EXPECT_EQ(before.unrelated, nvs.unrelated);
    EXPECT_EQ(before.nor, partitions.bytes);
    EXPECT_EQ(before.erased, partitions.erasedOffsets);
    EXPECT_EQ(before.programs, partitions.writeCalls);
    size_t protected_count = 0;
    for (const auto& entry : before.durable) {
      if (entry.first.first == Esp32BlobKind::Attempt) continue;
      ++protected_count;
      const auto found = nvs.durable.find(entry.first);
      ASSERT_NE(nvs.durable.end(), found);
      EXPECT_EQ(entry.second, found->second);
    }
    EXPECT_EQ(protected_count, protectedBlobs().size());
  }
  void expectUnchanged(const Snapshot& before) const {
    expectProtectedState(before);
    EXPECT_EQ(before.durable, nvs.durable);
    EXPECT_EQ(before.sets, nvs.setCalls);
    EXPECT_EQ(before.commits, nvs.commitCalls);
  }
};

}  // namespace

TEST(Esp32Flash, CompatibilityConstructorRemainsUnsupported) {
  Esp32FlashAdapter flash(0x800000, 4096, 1);
  uint8_t value = 0x42;
  EXPECT_EQ(0x800000u, flash.totalSizeBytes());
  EXPECT_EQ(FlashStatus::Unsupported, flash.read(0, &value, 1));
  EXPECT_EQ(0x42, value);
  EXPECT_EQ(FlashStatus::Unsupported, flash.program(0, &value, 1));
  EXPECT_EQ(FlashStatus::Unsupported, flash.eraseSector(0));
  EXPECT_FALSE(flash.isBound());
  EXPECT_FALSE(Esp32FlashAdapter::installationAvailable());
}

TEST(Esp32Flash, ActualPartitionIoBothSlotDirectionsPreservesEveryOtherByte) {
  for (bool running_app1 : {false, true}) {
    SCOPED_TRACE(running_app1);
    Esp32PartitionModel sdk(running_app1);
    Esp32Owners owners;
    Esp32FlashAdapter flash(sdk, owners);
    const auto before = sdk.bytes;
    ASSERT_EQ(FlashStatus::Ok, flash.bind(4097));
    EXPECT_EQ(0x330000u, flash.totalSizeBytes());
    EXPECT_EQ(4096u, flash.eraseUnitBytes());
    EXPECT_EQ(1u, flash.programUnitBytes());
    EXPECT_TRUE(esp32PartitionEquals(sdk.snapshot.next, flash.partition()));
    FlashRegion candidate(flash, 0, flash.totalSizeBytes());
    ASSERT_TRUE(candidate.isValid());
    ASSERT_EQ(FlashStatus::Ok, candidate.eraseRange(0, 8192));
    std::vector<uint8_t> chunk(512, 0x39), readback(512, 0);
    ASSERT_TRUE(StorageManager::writeAndVerifyChunk(candidate, 1, 512, chunk.data(), chunk.size()));
    ASSERT_EQ(FlashStatus::Ok, candidate.read(512, readback.data(), readback.size()));
    EXPECT_EQ(chunk, readback);
    EXPECT_EQ((std::vector<uint32_t>{0, 4096}), sdk.erasedOffsets);
    EXPECT_EQ(1u, sdk.writeCalls);
    EXPECT_EQ(0, memcmp(chunk.data(), sdk.bytes.data() + sdk.snapshot.next.address + 512, chunk.size()));
    EXPECT_EQ(0, memcmp(before.data() + sdk.snapshot.next.address + 8192,
                        sdk.bytes.data() + sdk.snapshot.next.address + 8192, sdk.snapshot.next.size - 8192));
    expectProtected(sdk, before, sdk.snapshot.next);
  }
}

TEST(Esp32Flash, ReorderedExactTableIsAcceptedButDuplicateOrExtraEntryIsNot) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  std::swap(sdk.snapshot.table[0], sdk.snapshot.table[5]);
  EXPECT_EQ(FlashStatus::Ok, flash.bind(1));
  sdk.snapshot.table[0] = sdk.snapshot.table[1];
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
  EXPECT_EQ(Esp32FlashAdapter::Refusal::Table, flash.lastRefusal());
  sdk.snapshot.count = 7;
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
  EXPECT_EQ(0u, sdk.writeCalls);
  EXPECT_TRUE(sdk.erasedOffsets.empty());
}

TEST(Esp32Flash, EveryAlteredPartitionTableFieldRefusesBeforeMutation) {
  for (size_t entry = 0; entry < 6; ++entry) {
    for (size_t field = 0; field < 7; ++field) {
      SCOPED_TRACE(entry);
      SCOPED_TRACE(field);
      Esp32PartitionModel sdk;
      Esp32Owners owners;
      Esp32FlashAdapter flash(sdk, owners);
      auto& p = sdk.snapshot.table[entry];
      switch (field) {
        case 0: ++p.address; break;
        case 1: p.size -= 4096; break;
        case 2: ++p.type; break;
        case 3: ++p.subtype; break;
        case 4: p.label[0] ^= 1; break;
        case 5: p.encrypted = true; break;
        case 6: p.defaultFlash = false; break;
      }
      EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
      EXPECT_FALSE(flash.isBound());
      EXPECT_EQ(0u, sdk.writeCalls);
      EXPECT_TRUE(sdk.erasedOffsets.empty());
    }
  }
}

TEST(Esp32Flash, RunningFilesystemNvsOtadataCoredumpAndBootAreNeverBindable) {
  for (size_t entry : {size_t(0), size_t(1), size_t(2), size_t(4), size_t(5), size_t(6)}) {
    Esp32PartitionModel sdk;
    Esp32Owners owners;
    Esp32FlashAdapter flash(sdk, owners);
    const auto before = sdk.bytes;
    sdk.snapshot.next = entry == 6 ? Esp32PartitionIdentity{} : Esp32S3PartitionLayout::entry(entry);
    if (entry == 6) {
      sdk.snapshot.next.size = 0x8000;
      memcpy(sdk.snapshot.next.label, "bootloader", 11);
      sdk.snapshot.next.defaultFlash = true;
    }
    EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
    EXPECT_EQ(FlashStatus::Unsupported, flash.eraseSector(0));
    EXPECT_EQ(before, sdk.bytes);
    EXPECT_EQ(0u, sdk.writeCalls);
    EXPECT_TRUE(sdk.erasedOffsets.empty());
  }
}

TEST(Esp32Flash, PersistedPartitionCannotSelectWrongLabelSlotOrGeometry) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  for (size_t i = 0; i < 6; ++i) {
    if (i == 3) continue;
    const auto persisted = Esp32S3PartitionLayout::entry(i);
    EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(4096, &persisted));
  }
  auto persisted = sdk.snapshot.next;
  memcpy(persisted.label, "wrong", 6);
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(4096, &persisted));
  persisted = sdk.snapshot.next;
  ++persisted.size;
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(4096, &persisted));
  EXPECT_EQ(0u, sdk.writeCalls);
}

TEST(Esp32Flash, CapacityAlignmentAndOverflowAreMeasuredBeforeAnySdkIo) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(0));
  EXPECT_EQ(FlashStatus::OutOfRange, flash.bind(0x330001));
  EXPECT_EQ(FlashStatus::OutOfRange, flash.bind(UINT32_MAX));
  ASSERT_EQ(FlashStatus::Ok, flash.bind(0x330000));
  uint8_t byte = 0;
  for (const auto offset : {uint32_t(0x330000), uint32_t(0x330001), UINT32_MAX, UINT32_MAX - 4095}) {
    EXPECT_EQ(FlashStatus::OutOfRange, flash.read(offset, &byte, 1));
    EXPECT_EQ(FlashStatus::OutOfRange, flash.program(offset, &byte, 1));
    EXPECT_EQ(FlashStatus::OutOfRange, flash.eraseSector(offset));
  }
  EXPECT_EQ(FlashStatus::OutOfRange, flash.read(1, &byte, UINT32_MAX));
  EXPECT_EQ(FlashStatus::OutOfRange, flash.program(4096, &byte, UINT32_MAX));
  EXPECT_EQ(FlashStatus::Unaligned, flash.eraseSector(1));
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.read(0, nullptr, 1));
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.program(0, nullptr, 1));
  EXPECT_EQ(FlashStatus::Ok, flash.read(flash.totalSizeBytes(), nullptr, 0));
  EXPECT_EQ(FlashStatus::Ok, flash.program(flash.totalSizeBytes(), nullptr, 0));
  EXPECT_EQ(0u, sdk.readCalls);
  EXPECT_EQ(0u, sdk.writeCalls);
  EXPECT_TRUE(sdk.erasedOffsets.empty());
}

TEST(Esp32Flash, NumericPhysicalAddressesRemainOnlyRelativeInactiveOffsets) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  const auto before = sdk.bytes;
  ASSERT_EQ(FlashStatus::Ok, flash.bind(1));
  const uint8_t value = 0x16;
  for (const uint32_t offset : {0u, 0x9000u, 0xe000u, 0x10000u}) {
    ASSERT_EQ(FlashStatus::Ok, flash.program(offset, &value, 1));
    EXPECT_EQ(value, sdk.bytes[sdk.snapshot.next.address + offset]);
  }
  expectProtected(sdk, before, sdk.snapshot.next);
}

TEST(Esp32Flash, UnknownOtherLeasePendingTrialAndUnresolvedBootSelectionRefuse) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  for (const auto ownership : {Esp32UpdateOwnership::Unknown, Esp32UpdateOwnership::OtherUpdater}) {
    owners.flash = ownership;
    EXPECT_EQ(FlashStatus::IoError, flash.bind(1));
    EXPECT_EQ(Esp32FlashAdapter::Refusal::Ownership, flash.lastRefusal());
  }
  owners.flash = Esp32UpdateOwnership::ExclusiveStorage;
  for (size_t app = 0; app < 2; ++app) {
    for (const auto state : {Esp32ImageState::New, Esp32ImageState::PendingVerify}) {
      sdk.snapshot.appStates[app] = state;
      EXPECT_EQ(FlashStatus::IoError, flash.bind(1));
      EXPECT_EQ(Esp32FlashAdapter::Refusal::Trial, flash.lastRefusal());
    }
    sdk.snapshot.appStates[app] = Esp32ImageState::Valid;
  }
  sdk.snapshot.boot = sdk.snapshot.next;
  EXPECT_EQ(FlashStatus::IoError, flash.bind(1));
  EXPECT_EQ(Esp32FlashAdapter::Refusal::BootSelection, flash.lastRefusal());
  sdk.snapshot.boot = {};
  EXPECT_EQ(FlashStatus::IoError, flash.bind(1));
  EXPECT_EQ(0u, sdk.writeCalls);
  EXPECT_TRUE(sdk.erasedOffsets.empty());
}

TEST(Esp32Flash, RevalidatesSelectionTableAndOwnershipOnEveryOperation) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  ASSERT_EQ(FlashStatus::Ok, flash.bind(1));
  uint8_t byte = 0x52;
  owners.flash = Esp32UpdateOwnership::OtherUpdater;
  EXPECT_EQ(FlashStatus::IoError, flash.read(0, &byte, 1));
  EXPECT_EQ(0x52, byte);
  EXPECT_EQ(FlashStatus::IoError, flash.program(0, &byte, 1));
  EXPECT_EQ(FlashStatus::IoError, flash.eraseSector(0));
  owners.flash = Esp32UpdateOwnership::ExclusiveStorage;
  sdk.snapshot.boot = sdk.snapshot.next;
  EXPECT_EQ(FlashStatus::IoError, flash.eraseSector(0));
  sdk.snapshot.boot = sdk.snapshot.running;
  --sdk.snapshot.table[5].size;
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.program(0, &byte, 1));
  EXPECT_EQ(0u, sdk.readCalls);
  EXPECT_EQ(0u, sdk.writeCalls);
  EXPECT_TRUE(sdk.erasedOffsets.empty());
}

TEST(Esp32Flash, EncryptedPartitionsAndWrongFlashSizeAreExplicitlyRefused) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  sdk.snapshot.next.encrypted = true;
  EXPECT_EQ(FlashStatus::Unsupported, flash.bind(1));
  EXPECT_EQ(Esp32FlashAdapter::Refusal::Encrypted, flash.lastRefusal());
  sdk.snapshot.next.encrypted = false;
  sdk.snapshot.flashSize = 0x400000;
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
  sdk.snapshot.flashSize = 0x800000;
  sdk.snapshot.physicalFlashSize = 0x400000;
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
  sdk.snapshot.physicalFlashSize = 0x1000000;
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
  EXPECT_EQ(0u, sdk.writeCalls);
}

TEST(Esp32Flash, SdkErrorsRetainOriginalErrorAtInspectReadEraseAndWrite) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  sdk.inspectError = 0x108;
  EXPECT_EQ(FlashStatus::IoError, flash.bind(1));
  EXPECT_EQ(0x108, flash.lastSdkError());
  sdk.inspectError = kEsp32Ok;
  ASSERT_EQ(FlashStatus::Ok, flash.bind(1));
  uint8_t byte = 0;
  sdk.readError = 0x107;
  EXPECT_EQ(FlashStatus::IoError, flash.read(0, &byte, 1));
  EXPECT_EQ(0x107, flash.lastSdkError());
  EXPECT_EQ(FlashStatus::IoError, flash.program(0, &byte, 1));
  EXPECT_EQ(0x107, flash.lastSdkError());
  EXPECT_EQ(0u, sdk.writeCalls);
  sdk.readError = kEsp32Ok;
  sdk.eraseError = -1;
  EXPECT_EQ(FlashStatus::IoError, flash.eraseSector(0));
  EXPECT_EQ(-1, flash.lastSdkError());
  sdk.writeFault = FaultTiming::Before;
  sdk.writeError = 0x103;
  EXPECT_EQ(FlashStatus::IoError, flash.program(0, &byte, 1));
  EXPECT_EQ(0x103, flash.lastSdkError());
  EXPECT_EQ(Esp32FlashAdapter::Refusal::Sdk, flash.lastRefusal());
}

TEST(Esp32Flash, NorViolationBeyondFirstReadBlockIsRejectedWithoutPartialMutation) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  ASSERT_EQ(FlashStatus::Ok, flash.bind(512));
  uint8_t zero = 0;
  ASSERT_EQ(FlashStatus::Ok, flash.program(511, &zero, 1));
  const auto before = sdk.bytes;
  std::vector<uint8_t> bytes(512, 0x7f);
  EXPECT_EQ(FlashStatus::PartialProgramViolation, flash.program(0, bytes.data(), bytes.size()));
  EXPECT_EQ(Esp32FlashAdapter::Refusal::NorViolation, flash.lastRefusal());
  EXPECT_EQ(1u, sdk.writeCalls);
  EXPECT_EQ(before, sdk.bytes);
}

TEST(Esp32Persistence, FixedEndianCodecHasExactShapeAndRejectsFutureFormats) {
  const auto bytes = encoded(Esp32BlobKind::Security, Esp32BlobPhase::Committed, 0x01020304, {0xaa, 0xbb});
  const std::vector<uint8_t> prefix{0x45, 0x4f, 0x54, 0x41, 0, 1, 2, 2, 0, 0, 0, 2,
                                    1, 2, 3, 4, 0xaa, 0xbb};
  ASSERT_EQ(22u, bytes.size());
  EXPECT_EQ(0, memcmp(prefix.data(), bytes.data(), prefix.size()));
  Esp32DurableBlob blob;
  Esp32BlobPhase phase = Esp32BlobPhase::Prepared;
  ASSERT_TRUE(Esp32BlobCodec::decode(Esp32BlobKind::Security, bytes.data(), bytes.size(), blob, phase));
  EXPECT_EQ(0x01020304u, blob.generation);
  EXPECT_EQ(2u, blob.size);
  EXPECT_EQ(0xaa, blob.payload[0]);
  EXPECT_EQ(0xbb, blob.payload[1]);
  EXPECT_EQ(Esp32BlobPhase::Committed, phase);
  for (size_t changed : {size_t(5), size_t(6), size_t(7), size_t(11), size_t(17), size_t(21)}) {
    auto bad = bytes;
    bad[changed] ^= 0x40;
    EXPECT_FALSE(Esp32BlobCodec::decode(Esp32BlobKind::Security, bad.data(), bad.size(), blob, phase));
  }
  EXPECT_FALSE(Esp32BlobCodec::decode(Esp32BlobKind::Attempt, bytes.data(), bytes.size(), blob, phase));
  // Retain a valid CRC: these fail on the actual format/length/generation
  // gates rather than merely re-testing CRC detection.
  for (const size_t field : {size_t(5), size_t(6), size_t(7), size_t(11), size_t(12)}) {
    auto bad = bytes;
    if (field == 12) std::fill(bad.begin() + 12, bad.begin() + 16, 0);
    else bad[field] = 0x70;
    meshcore::ota::protocol::putOtaBE32(bad.data() + bad.size() - 4,
        Crc32::computeFinalized(bad.data(), bad.size() - 4));
    EXPECT_FALSE(Esp32BlobCodec::decode(Esp32BlobKind::Security, bad.data(), bad.size(), blob, phase));
  }
}

TEST(Esp32Persistence, MissingSecurityAndLedgerAreNeverAutomaticallyProvisioned) {
  Esp32NvsModel nvs;
  Esp32Owners owners;
  Esp32DurableBlobStore store(nvs, owners);
  Esp32DurableBlob out;
  out.generation = 0x87654321;
  out.payload[0] = 0x7b;
  const uint8_t payload[] = {0x28, 0x37};
  for (const auto kind : {Esp32BlobKind::Security, Esp32BlobKind::TxSequence, Esp32BlobKind::RxReplay}) {
    EXPECT_EQ(Status::Missing, store.load(kind, out).status);
    EXPECT_EQ(Status::Missing, store.save(kind, payload, sizeof(payload)).status);
  }
  EXPECT_EQ(0x87654321u, out.generation);
  EXPECT_EQ(0x7b, out.payload[0]);
  EXPECT_EQ(0u, nvs.setCalls);
  EXPECT_FALSE(nvs.namespaceExists);
}

TEST(Esp32Persistence, SetCommitFreshReadbackEachPhaseAndNewestGenerationBothDirections) {
  for (bool immediate : {false, true}) {
    Esp32NvsModel nvs;
    nvs.immediate = immediate;
    Esp32Owners owners;
    const auto sentinel = nvs.unrelated;
    Esp32DurableBlobStore store(nvs, owners);
    const uint8_t payload[] = {0x19, 0x37, 0x55};
    ASSERT_TRUE(store.save(Esp32BlobKind::Security, payload, sizeof(payload),
                           Esp32BlobCreation::ExplicitProvision).ok());
    const std::vector<std::string> expected{
        "open-ro", "open-rw", "set", "commit", "close", "open-ro", "close",
        "open-rw", "set", "commit", "close", "open-ro", "close"};
    EXPECT_EQ(expected, nvs.trace);
    ASSERT_EQ(2u, nvs.setCalls);
    ASSERT_EQ(2u, nvs.commitCalls);
    for (uint32_t generation = 1; generation <= 3; ++generation) {
      Esp32DurableBlobStore reconstructed(nvs, owners);
      Esp32DurableBlob loaded;
      ASSERT_TRUE(reconstructed.load(Esp32BlobKind::Security, loaded).ok());
      EXPECT_EQ(generation, loaded.generation);
      EXPECT_EQ(generation % 2 == 1 ? Esp32NvsSlot::A : Esp32NvsSlot::B, loaded.slot);
      EXPECT_EQ(sizeof(payload), loaded.size);
      EXPECT_EQ(0, memcmp(payload, loaded.payload, sizeof(payload)));
      if (generation != 3) ASSERT_TRUE(reconstructed.save(Esp32BlobKind::Security, payload, sizeof(payload)).ok());
    }
    EXPECT_EQ(6u, nvs.setCalls);
    EXPECT_EQ(6u, nvs.commitCalls);
    EXPECT_EQ(sentinel, nvs.unrelated);
  }
}

TEST(Esp32Persistence, AdmissionCapacityThresholdAndNamespaceOwnershipAreExact) {
  Esp32NvsModel nvs;
  Esp32Owners owners;
  Esp32DurableBlobStore store(nvs, owners);
  std::vector<uint8_t> payload(Esp32AttemptCodec::kBytes, 0x51);
  EXPECT_EQ(147u, Esp32DurableBlobStore::requiredFreeEntries(payload.size()));
  nvs.free = 146;
  EXPECT_EQ(Status::NoSpace, store.save(Esp32BlobKind::Attempt, payload.data(), payload.size(),
                                      Esp32BlobCreation::ExplicitProvision).status);
  EXPECT_EQ(0u, nvs.setCalls);
  EXPECT_FALSE(nvs.namespaceExists);
  nvs.free = 147;
  owners.metadata = false;
  EXPECT_EQ(Status::OwnershipDenied, store.save(Esp32BlobKind::Attempt, payload.data(), payload.size(),
                                               Esp32BlobCreation::ExplicitProvision).status);
  EXPECT_EQ(0u, nvs.setCalls);
  EXPECT_FALSE(nvs.namespaceExists);
  owners.metadata = true;
  ASSERT_TRUE(store.save(Esp32BlobKind::Attempt, payload.data(), payload.size(),
                         Esp32BlobCreation::ExplicitProvision).ok());
  EXPECT_EQ(2u, nvs.setCalls);
  EXPECT_EQ(2u, nvs.commitCalls);
}

TEST(Esp32Persistence, GenerationExhaustionAndDivergentEqualGenerationsNeverMutate) {
  Esp32NvsModel nvs;
  Esp32Owners owners;
  injectRecord(nvs, Esp32BlobKind::TxSequence, Esp32NvsSlot::B, UINT32_MAX, {0x18});
  Esp32DurableBlobStore store(nvs, owners);
  const uint8_t payload = 0x19;
  EXPECT_EQ(Status::GenerationExhausted, store.save(Esp32BlobKind::TxSequence, &payload, 1).status);
  EXPECT_EQ(0u, nvs.setCalls);
  injectRecord(nvs, Esp32BlobKind::TxSequence, Esp32NvsSlot::A, UINT32_MAX, {0x17});
  Esp32DurableBlob output;
  EXPECT_EQ(Status::Corrupt, store.load(Esp32BlobKind::TxSequence, output).status);
  EXPECT_EQ(Status::Corrupt, store.save(Esp32BlobKind::TxSequence, &payload, 1).status);
  EXPECT_EQ(0u, nvs.setCalls);
}

TEST(Esp32Persistence, CorruptOlderOrNewerSlotNeverFallsBackToGoodSecurity) {
  for (auto corrupt_slot : {Esp32NvsSlot::A, Esp32NvsSlot::B}) {
    Esp32NvsModel nvs;
    Esp32Owners owners;
    injectRecord(nvs, Esp32BlobKind::Security, Esp32NvsSlot::A, 1, {0x51});
    injectRecord(nvs, Esp32BlobKind::Security, Esp32NvsSlot::B, 2, {0x52});
    nvs.durable[{Esp32BlobKind::Security, corrupt_slot}].back() ^= 0x01;
    Esp32DurableBlobStore store(nvs, owners);
    Esp32DurableBlob output;
    output.generation = 77;
    EXPECT_EQ(Status::Corrupt, store.load(Esp32BlobKind::Security, output).status);
    EXPECT_EQ(77u, output.generation);
    uint8_t newer = 0x53;
    EXPECT_EQ(Status::Corrupt, store.save(Esp32BlobKind::Security, &newer, 1).status);
    EXPECT_EQ(0u, nvs.setCalls);
  }
}

TEST(Esp32Persistence, UnreadableSlotPreservesSdkErrorInsteadOfUsingOlderRecord) {
  for (uint32_t failed_read = 1; failed_read <= 4; ++failed_read) {
    Esp32NvsModel nvs;
    Esp32Owners owners;
    injectRecord(nvs, Esp32BlobKind::Security, Esp32NvsSlot::A, 1, {0x51});
    injectRecord(nvs, Esp32BlobKind::Security, Esp32NvsSlot::B, 2, {0x52});
    nvs.failGetAt = failed_read;
    nvs.faultError = 0x110b;
    Esp32DurableBlobStore store(nvs, owners);
    Esp32DurableBlob output;
    const auto result = store.load(Esp32BlobKind::Security, output);
    EXPECT_EQ(Status::IoError, result.status);
    EXPECT_EQ(0x110b, result.sdkError);
    EXPECT_EQ(0u, nvs.setCalls);
  }
}

TEST(Esp32Persistence, SdkNvsTypeAndLengthFailuresAreCorruptNotMissing) {
  for (const auto error : {kEsp32NvsTypeMismatch, kEsp32NvsInvalidLength}) {
    Esp32NvsModel nvs;
    Esp32Owners owners;
    nvs.namespaceExists = true;
    nvs.getError = error;
    Esp32DurableBlobStore store(nvs, owners);
    Esp32DurableBlob output;
    const auto result = store.load(Esp32BlobKind::Security, output);
    EXPECT_EQ(Status::Corrupt, result.status);
    EXPECT_EQ(error, result.sdkError);
    EXPECT_EQ(0u, nvs.setCalls);
  }
}

TEST(Esp32Persistence, SetFailureAtEitherPhaseNeverReportsSuccessAndFreshLoadIsFailClosed) {
  for (uint32_t phase = 1; phase <= 2; ++phase) {
    for (auto timing : {FaultTiming::Before, FaultTiming::Torn, FaultTiming::After}) {
      SCOPED_TRACE(phase);
      SCOPED_TRACE(static_cast<int>(timing));
      Esp32NvsModel nvs;
      Esp32Owners owners;
      nvs.failSetAt = phase;
      nvs.setTiming = timing;
      nvs.tornBytes = 9;
      Esp32DurableBlobStore store(nvs, owners);
      const uint8_t payload[] = {0x81, 0x82};
      const auto result = store.save(Esp32BlobKind::TxSequence, payload, sizeof(payload),
                                     Esp32BlobCreation::ExplicitProvision);
      EXPECT_EQ(Status::DurabilityUncertain, result.status);
      EXPECT_EQ(-1, result.sdkError);
      EXPECT_EQ(Status::IoError, result.uncertaintyCause);
      EXPECT_TRUE(result.mutationMayHaveOccurred);
      EXPECT_EQ(phase, nvs.setCalls);
      nvs.clearFaults();
      Esp32DurableBlob output;
      EXPECT_EQ(Status::DurabilityUncertain, store.load(Esp32BlobKind::TxSequence, output).status);
      Esp32DurableBlobStore fresh(nvs, owners);
      const auto recovered = fresh.load(Esp32BlobKind::TxSequence, output);
      const auto expected = timing == FaultTiming::Torn ? Status::Corrupt :
          phase == 1 && timing == FaultTiming::Before ? Status::Missing :
          phase == 2 && timing == FaultTiming::After ? Status::Ok : Status::DurabilityUncertain;
      EXPECT_EQ(expected, recovered.status);
      if (recovered.ok()) {
        EXPECT_EQ(1u, output.generation);
        EXPECT_EQ(0, memcmp(payload, output.payload, sizeof(payload)));
      }
    }
  }
}

TEST(Esp32Persistence, CommitFailureBeforeOrAfterEitherPhaseSurvivesReconstruction) {
  for (bool immediate : {false, true}) {
    for (uint32_t phase = 1; phase <= 2; ++phase) {
      for (auto timing : {FaultTiming::Before, FaultTiming::After}) {
        SCOPED_TRACE(immediate);
        SCOPED_TRACE(phase);
        SCOPED_TRACE(static_cast<int>(timing));
        Esp32NvsModel nvs;
        nvs.immediate = immediate;
        nvs.failCommitAt = phase;
        nvs.commitTiming = timing;
        Esp32Owners owners;
        Esp32DurableBlobStore store(nvs, owners);
        const uint8_t payload = 0x82;
        const auto result = store.save(Esp32BlobKind::RxReplay, &payload, 1,
                                       Esp32BlobCreation::ExplicitProvision);
        EXPECT_EQ(Status::DurabilityUncertain, result.status);
        EXPECT_EQ(-1, result.sdkError);
        EXPECT_TRUE(result.mutationMayHaveOccurred);
        nvs.clearFaults();
        Esp32DurableBlobStore fresh(nvs, owners);
        Esp32DurableBlob output;
        const auto loaded = fresh.load(Esp32BlobKind::RxReplay, output);
        const bool persisted_this_phase = immediate || timing == FaultTiming::After;
        const auto expected = phase == 1 ? (persisted_this_phase ? Status::DurabilityUncertain : Status::Missing) :
                                          (persisted_this_phase ? Status::Ok : Status::DurabilityUncertain);
        EXPECT_EQ(expected, loaded.status);
        EXPECT_EQ(phase, nvs.commitCalls);
      }
    }
  }
}

TEST(Esp32Persistence, ReadbackFailureOrMismatchNeverReportsDurability) {
  for (uint32_t phase = 1; phase <= 2; ++phase) {
    for (bool mismatch : {false, true}) {
      Esp32NvsModel nvs;
      if (mismatch) nvs.badReadbackAt = phase;
      else nvs.failGetAt = phase;
      Esp32Owners owners;
      Esp32DurableBlobStore store(nvs, owners);
      const uint8_t payload = 0x49;
      const auto result = store.save(Esp32BlobKind::Security, &payload, 1,
                                     Esp32BlobCreation::ExplicitProvision);
      EXPECT_EQ(Status::DurabilityUncertain, result.status);
      EXPECT_EQ(mismatch ? Status::Corrupt : Status::IoError, result.uncertaintyCause);
      EXPECT_EQ(mismatch ? kEsp32Ok : -1, result.sdkError);
      nvs.clearFaults();
      Esp32DurableBlobStore fresh(nvs, owners);
      Esp32DurableBlob output;
      EXPECT_EQ(phase == 1 ? Status::DurabilityUncertain : Status::Ok,
                fresh.load(Esp32BlobKind::Security, output).status);
    }
  }
}

TEST(Esp32Persistence, RuntimeNvsExhaustionIsUncertainAndDoesNotFormatAnything) {
  Esp32NvsModel nvs;
  Esp32Owners owners;
  const auto sentinel = nvs.unrelated;
  nvs.failSetAt = 1;
  nvs.faultError = kEsp32NvsNoSpace;
  Esp32DurableBlobStore store(nvs, owners);
  const uint8_t payload = 0x82;
  const auto result = store.save(Esp32BlobKind::Security, &payload, 1,
                                 Esp32BlobCreation::ExplicitProvision);
  EXPECT_EQ(Status::DurabilityUncertain, result.status);
  EXPECT_EQ(kEsp32NvsNoSpace, result.sdkError);
  EXPECT_EQ(1u, nvs.setCalls);
  EXPECT_EQ(0u, nvs.commitCalls);
  EXPECT_EQ(sentinel, nvs.unrelated);
}

TEST(Esp32Persistence, StatsAndNamespaceOpenErrorsRemainIoErrorsBeforeMutation) {
  Esp32NvsModel nvs;
  Esp32Owners owners;
  Esp32DurableBlobStore store(nvs, owners);
  const uint8_t payload = 0x82;
  nvs.statsError = 0x1101;
  const auto capacity = store.capacity(236);
  EXPECT_EQ(Status::IoError, capacity.status);
  EXPECT_EQ(0x1101, capacity.sdkError);
  nvs.statsError = kEsp32Ok;
  nvs.openError = 0x110f;
  const auto result = store.save(Esp32BlobKind::Security, &payload, 1,
                                 Esp32BlobCreation::ExplicitProvision);
  EXPECT_EQ(Status::IoError, result.status);
  EXPECT_EQ(0x110f, result.sdkError);
  EXPECT_EQ(0u, nvs.setCalls);
}

TEST_F(AttemptFixture, CommissionedMissingCorruptOrSemanticallyInvalidSecurityRefusesAdmission) {
  const auto before = partitions.bytes;
  EXPECT_EQ(Status::Missing, attempts.admit(record).status);
  EXPECT_EQ(0u, nvs.setCalls);
  provisionSecurity();
  const uint32_t writes = nvs.setCalls;
  nvs.durable[{Esp32BlobKind::Security, Esp32NvsSlot::A}].back() ^= 1;
  EXPECT_EQ(Status::Corrupt, attempts.admit(record).status);
  injectRecord(nvs, Esp32BlobKind::Security, Esp32NvsSlot::A, 1, {0x00});
  EXPECT_EQ(Status::Corrupt, attempts.admit(record).status);
  EXPECT_FALSE(flash.isBound());
  EXPECT_EQ(writes, nvs.setCalls);
  EXPECT_EQ(before, partitions.bytes);
  EXPECT_TRUE(partitions.erasedOffsets.empty());
}

TEST_F(AttemptFixture, ExactSignedDescriptorFullControllerSessionDigestAndBindingRoundTrip) {
  provisionSecurity();
  ASSERT_TRUE(attempts.admit(record).ok());
  uint8_t bytes[Esp32AttemptCodec::kBytes] = {};
  ASSERT_EQ(236u, Esp32AttemptCodec::encode(record, bytes, sizeof(bytes)));
  EXPECT_EQ(0, memcmp(record.signedDescriptor, bytes, 123));
  EXPECT_EQ(0, memcmp(record.controller, bytes + 123, 32));
  const uint8_t session[] = {0x12, 0x34, 0x56, 0x78, 0x89, 0xab, 0xcd, 0xef, 0x13, 0x57};
  EXPECT_EQ(0, memcmp(session, bytes + 155, sizeof(session)));
  EXPECT_EQ(0, memcmp(record.attemptDigest, bytes + 165, 32));
  EXPECT_EQ(0x00, bytes[197]); EXPECT_EQ(0x34, bytes[198]);
  EXPECT_EQ(0x00, bytes[199]); EXPECT_EQ(0x00, bytes[200]);
  EXPECT_EQ(static_cast<uint8_t>(Esp32ConsentState::Granted), bytes[234]);
  EXPECT_EQ(static_cast<uint8_t>(Esp32StagingPhase::Admitted), bytes[235]);
  Esp32FlashAdapter reboot_flash(partitions, owners);
  Esp32DurableBlobStore reboot_blobs(nvs, owners);
  Esp32AttemptStore reboot_attempts(reboot_blobs, reboot_flash, policy);
  Esp32AttemptRecord loaded;
  ASSERT_TRUE(reboot_attempts.resume(loaded).ok());
  EXPECT_TRUE(Esp32AttemptCodec::sameAttempt(record, loaded));
  EXPECT_EQ(0u, loaded.erasedBytes);
  EXPECT_EQ(0u, loaded.verifiedBytes);
  EXPECT_TRUE(partitions.erasedOffsets.empty());
  EXPECT_EQ(0u, partitions.writeCalls);
}

TEST_F(AttemptFixture, CapacityWrongPartitionAndUnknownOwnershipFailBeforeAdmissionMutation) {
  provisionSecurity();
  const uint32_t writes = nvs.setCalls;
  const auto before = partitions.bytes;
  nvs.free = 146;
  EXPECT_EQ(Status::NoSpace, attempts.admit(record).status);
  EXPECT_FALSE(flash.isBound());
  nvs.free = 500;
  const auto candidate = record.partition;
  record.partition = partitions.snapshot.running;
  EXPECT_EQ(Status::PartitionMismatch, attempts.admit(record).status);
  record.partition = candidate;
  owners.flash = Esp32UpdateOwnership::Unknown;
  EXPECT_EQ(Status::PartitionMismatch, attempts.admit(record).status);
  EXPECT_FALSE(flash.isBound());
  EXPECT_EQ(writes, nvs.setCalls);
  EXPECT_EQ(before, partitions.bytes);
}

TEST_F(AttemptFixture, ForgedSignatureWrongFullControllerAndMissingLocalConsentAreRefused) {
  provisionSecurity();
  const uint32_t writes = nvs.setCalls;
  const auto original = record;
  record.signedDescriptor[59] ^= 1;
  EXPECT_EQ(Status::InvalidArgument, attempts.admit(record).status);
  record = original;
  record.controller[31] ^= 1;
  EXPECT_EQ(Status::InvalidArgument, attempts.admit(record).status);
  record = original;
  memcpy(record.controller, policy.signer.publicKey(), 32);
  EXPECT_EQ(Status::InvalidArgument, attempts.admit(record).status);
  record = original;
  record.consent = Esp32ConsentState::Denied;
  EXPECT_EQ(Status::InvalidArgument, attempts.admit(record).status);
  EXPECT_EQ(writes, nvs.setCalls);
  EXPECT_FALSE(flash.isBound());
  EXPECT_EQ(0u, partitions.writeCalls);
}

TEST_F(AttemptFixture, ImmutableAttemptAndMonotonicProgressCannotBeReplaced) {
  admitAndPrepare();
  const uint32_t writes = nvs.setCalls;
  const auto original = record;
  for (size_t field = 0; field < 6; ++field) {
    record = original;
    switch (field) {
      case 0: record.signedDescriptor[122] ^= 1; break;
      case 1: record.controller[31] ^= 1; break;
      case 2: ++record.session.attemptId; break;
      case 3: record.attemptDigest[31] ^= 1; break;
      case 4: record.partition = partitions.snapshot.running; break;
      case 5: record.erasedBytes = 0; break;
    }
    EXPECT_EQ(Status::Conflict, attempts.checkpoint(record).status);
  }
  record = original;
  record.phase = Esp32StagingPhase::Admitted;
  EXPECT_EQ(Status::Conflict, attempts.checkpoint(record).status);
  EXPECT_EQ(writes, nvs.setCalls);
}

TEST_F(AttemptFixture, RevokedConsentPersistsAndFreshResumeCannotRestoreIt) {
  admitAndPrepare();
  record.consent = Esp32ConsentState::Revoked;
  ASSERT_TRUE(attempts.checkpoint(record).ok());
  EXPECT_FALSE(flash.isBound());
  const uint32_t writes = nvs.setCalls;
  Esp32FlashAdapter reboot_flash(partitions, owners);
  Esp32DurableBlobStore reboot_blobs(nvs, owners);
  Esp32AttemptStore reboot_attempts(reboot_blobs, reboot_flash, policy);
  Esp32AttemptRecord loaded;
  EXPECT_EQ(Status::OwnershipDenied, reboot_attempts.resume(loaded).status);
  record.consent = Esp32ConsentState::Granted;
  EXPECT_EQ(Status::OwnershipDenied, reboot_attempts.checkpoint(record).status);
  EXPECT_FALSE(reboot_flash.isBound());
  EXPECT_EQ(writes, nvs.setCalls);
  Esp32DurableBlob stored;
  ASSERT_TRUE(reboot_blobs.load(Esp32BlobKind::Attempt, stored).ok());
  ASSERT_TRUE(Esp32AttemptCodec::decode(stored.payload, stored.size, loaded));
  EXPECT_EQ(Esp32ConsentState::Revoked, loaded.consent);
}

TEST_F(AttemptFixture, RevokedReceivingFreshAuthorizedAbortAllowsSeparatelyConsentedNextAttempt) {
  revokeReceiving();
  ASSERT_FALSE(HasFatalFailure());
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  const auto revoked = record;
  const auto old_blob = currentBlob(blobs);
  const auto before = snapshot();
  policy.revokedAbortAuthorized = true;
  Esp32FlashAdapter reboot_flash(partitions, owners);
  Esp32DurableBlobStore reboot_blobs(nvs, owners);
  Esp32AttemptStore reboot_attempts(reboot_blobs, reboot_flash, policy);
  Esp32AttemptRecord restored;
  EXPECT_EQ(Status::OwnershipDenied, reboot_attempts.resume(restored).status);
  auto terminal = revoked;
  terminal.phase = Esp32StagingPhase::Aborted;
  const auto aborted = reboot_attempts.abortRevoked(revoked);
  ASSERT_EQ(Status::Ok, aborted.status);
  EXPECT_TRUE(aborted.mutationMayHaveOccurred);
  EXPECT_FALSE(reboot_flash.isBound());
  const auto aborted_blob = currentBlob(reboot_blobs);
  EXPECT_EQ(old_blob.generation + 1, aborted_blob.generation);
  EXPECT_EQ(attemptPayload(terminal), std::vector<uint8_t>(
      aborted_blob.payload, aborted_blob.payload + aborted_blob.size));
  const auto old_key = Esp32NvsModel::Key{Esp32BlobKind::Attempt, old_blob.slot};
  EXPECT_EQ(before.durable.at(old_key), nvs.durable.at(old_key));
  EXPECT_EQ(before.sets + 2, nvs.setCalls);
  EXPECT_EQ(before.commits + 2, nvs.commitCalls);
  expectProtectedState(before);

  Esp32FlashAdapter fresh_flash(partitions, owners);
  Esp32DurableBlobStore fresh_blobs(nvs, owners);
  Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
  EXPECT_EQ(Status::Conflict, fresh_attempts.resume(restored).status);
  auto next = nextAttempt();
  const auto retired = snapshot();
  EXPECT_EQ(Status::InvalidArgument, fresh_attempts.replaceTerminal(terminal, next).status);
  expectUnchanged(retired);
  policy.localConsentValid = true;
  policy.replacementAuthorized = false;
  EXPECT_EQ(Status::OwnershipDenied, fresh_attempts.replaceTerminal(terminal, next).status);
  expectUnchanged(retired);
  policy.replacementAuthorized = true;
  next.partition = partitions.snapshot.running;
  EXPECT_EQ(Status::PartitionMismatch, fresh_attempts.replaceTerminal(terminal, next).status);
  expectUnchanged(retired);
  next.partition = revoked.partition;
  partitions.snapshot.boot = partitions.snapshot.next;
  EXPECT_EQ(Status::PartitionMismatch, fresh_attempts.replaceTerminal(terminal, next).status);
  expectUnchanged(retired);
  partitions.snapshot.boot = partitions.snapshot.running;
  ASSERT_TRUE(fresh_attempts.replaceTerminal(terminal, next).ok());
  ASSERT_TRUE(fresh_attempts.resume(restored).ok());
  EXPECT_TRUE(Esp32AttemptCodec::sameAttempt(next, restored));
  EXPECT_EQ(Esp32ConsentState::Granted, restored.consent);
  EXPECT_EQ(Esp32StagingPhase::Admitted, restored.phase);
  EXPECT_EQ(0u, restored.erasedBytes);
  EXPECT_EQ(0u, restored.verifiedBytes);
  EXPECT_EQ(old_blob.generation + 2, currentBlob(fresh_blobs).generation);
  EXPECT_EQ(0, memcmp(revoked.signedDescriptor, restored.signedDescriptor, 123));
  expectProtectedState(before);
}

TEST_F(AttemptFixture, RevokedAbortPolicyDefaultsToDenialAndRequiresQualifiedBoundAuthorization) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  const auto before = snapshot();
  DefaultReplacementPolicy default_policy(policy);
  Esp32AttemptStore denied(blobs, flash, default_policy);
  EXPECT_EQ(Status::OwnershipDenied, denied.abortRevoked(record).status);
  EXPECT_EQ(0u, policy.revokedAbortCalls);
  expectUnchanged(before);
  EXPECT_EQ(Status::OwnershipDenied, attempts.abortRevoked(record).status);
  EXPECT_EQ(1u, policy.revokedAbortCalls);
  expectUnchanged(before);
  policy.revokedAbortAuthorized = true;
  policy.authorizedController[31] ^= 1;
  EXPECT_EQ(Status::OwnershipDenied, attempts.abortRevoked(record).status);
  EXPECT_FALSE(flash.isBound());
  expectUnchanged(before);
}

TEST_F(AttemptFixture, RevokedAbortRequiresEveryFieldOfTheExactWinningCheckpoint) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  const auto before = snapshot();
  for (size_t field = 0; field < 12; ++field) {
    SCOPED_TRACE(field);
    auto expected = record;
    switch (field) {
      case 0: expected.phase = Esp32StagingPhase::Aborted; break;
      case 1: expected.phase = Esp32StagingPhase::Aborted; expected.erasedBytes = 0; break;
      case 2: ++expected.verifiedBytes; break;
      case 3: expected.consent = Esp32ConsentState::Granted; break;
      case 4: expected.consent = Esp32ConsentState::Denied; break;
      case 5: ++expected.session.campaignId; break;
      case 6: ++expected.session.sessionId; break;
      case 7: ++expected.session.attemptId; break;
      case 8: expected.controller[31] ^= 1; break;
      case 9: expected.attemptDigest[31] ^= 1; break;
      case 10: expected.signedDescriptor[122] ^= 1; break;
      case 11: expected.partition = partitions.snapshot.running; break;
    }
    ASSERT_TRUE(Esp32AttemptCodec::valid(expected));
    const auto refused = attempts.abortRevoked(expected);
    EXPECT_EQ(Status::Conflict, refused.status);
    EXPECT_FALSE(refused.mutationMayHaveOccurred);
    EXPECT_EQ(0u, policy.revokedAbortCalls);
    EXPECT_FALSE(flash.isBound());
    expectUnchanged(before);
  }
  auto invalid = record;
  invalid.erasedBytes = 1;
  EXPECT_EQ(Status::InvalidArgument, attempts.abortRevoked(invalid).status);
  expectUnchanged(before);
}

TEST_F(AttemptFixture, RevokedAbortNeverRetiresGrantedDeniedStagedOrAlreadyAbortedWinner) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  policy.stagedRetirementAuthorized = true;
  const auto old_blob = currentBlob(blobs);
  for (size_t condition = 0; condition < 5; ++condition) {
    SCOPED_TRACE(condition);
    auto winner = record;
    if (condition == 0) winner.consent = Esp32ConsentState::Granted;
    else if (condition == 1) winner.consent = Esp32ConsentState::Denied;
    else if (condition == 2) winner.phase = Esp32StagingPhase::Aborted;
    else {
      winner.phase = Esp32StagingPhase::Staged;
      winner.verifiedBytes = static_cast<uint32_t>(image.size());
      if (condition == 4) partitions.snapshot.appStates[1] = Esp32ImageState::PendingVerify;
    }
    injectRecord(nvs, Esp32BlobKind::Attempt, old_blob.slot, old_blob.generation, attemptPayload(winner));
    const auto before = snapshot();
    EXPECT_EQ(Status::Conflict, attempts.abortRevoked(winner).status);
    EXPECT_EQ(0u, policy.revokedAbortCalls);
    EXPECT_FALSE(flash.isBound());
    expectUnchanged(before);
  }
}

TEST_F(AttemptFixture, RevokedAdmittedAndErasingAbortPreservesZeroOrPartialEraseProgress) {
  provisionSecurity();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  const auto commissioned = nvs.durable;
  for (size_t condition = 0; condition < 3; ++condition) {
    SCOPED_TRACE(condition);
    nvs.durable = commissioned;
    record = policy.attempt(partitions.snapshot.next, image);
    policy.localConsentValid = true;
    ASSERT_TRUE(attempts.admit(record).ok());
    if (condition != 0) {
      record.phase = Esp32StagingPhase::Erasing;
      ASSERT_TRUE(attempts.checkpoint(record).ok());
      if (condition == 2) {
        ASSERT_EQ(FlashStatus::Ok, flash.eraseSector(0));
        record.erasedBytes = 4096;
        ASSERT_TRUE(attempts.checkpoint(record).ok());
      }
    }
    record.consent = Esp32ConsentState::Revoked;
    ASSERT_TRUE(attempts.checkpoint(record).ok());
    policy.localConsentValid = false;
    policy.revokedAbortAuthorized = true;
    const auto old_blob = currentBlob(blobs);
    const auto before = snapshot();
    ASSERT_TRUE(attempts.abortRevoked(record).ok());
    auto terminal = record;
    terminal.phase = Esp32StagingPhase::Aborted;
    const auto saved = currentBlob(blobs);
    EXPECT_EQ(old_blob.generation + 1, saved.generation);
    EXPECT_EQ(attemptPayload(terminal), std::vector<uint8_t>(saved.payload, saved.payload + saved.size));
    EXPECT_FALSE(flash.isBound());
    expectProtectedState(before);
  }
}

TEST_F(AttemptFixture, RevokedAbortRevalidatesSdkLeaseBootTrialAndPartitionAfterAuthorization) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  const auto original_sdk = partitions.snapshot;
  const auto before = snapshot();
  for (size_t condition = 0; condition < 8; ++condition) {
    SCOPED_TRACE(condition);
    partitions.snapshot = original_sdk;
    owners.flash = Esp32UpdateOwnership::ExclusiveStorage;
    partitions.inspectError = kEsp32Ok;
    policy.onRevokedAbort = [&]() {
      switch (condition) {
        case 0: owners.flash = Esp32UpdateOwnership::Unknown; break;
        case 1: owners.flash = Esp32UpdateOwnership::OtherUpdater; break;
        case 2: partitions.snapshot.boot = partitions.snapshot.next; break;
        case 3: partitions.snapshot.appStates[0] = Esp32ImageState::PendingVerify; break;
        case 4: partitions.snapshot.appStates[1] = Esp32ImageState::New; break;
        case 5: --partitions.snapshot.table[3].size; break;
        case 6: partitions.inspectError = 0x107; break;
        case 7:
          std::swap(partitions.snapshot.running, partitions.snapshot.next);
          partitions.snapshot.boot = partitions.snapshot.running;
          break;
      }
    };
    const auto refused = attempts.abortRevoked(record);
    EXPECT_EQ(condition == 6 ? Status::IoError : Status::PartitionMismatch, refused.status);
    EXPECT_EQ(condition == 6 ? 0x107 : kEsp32Ok, refused.sdkError);
    EXPECT_FALSE(refused.mutationMayHaveOccurred);
    EXPECT_FALSE(flash.isBound());
    expectUnchanged(before);
  }
}

TEST_F(AttemptFixture, RevokedAbortPermissionOwnershipAndCapacityLossCannotMutate) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  const auto before = snapshot();
  for (size_t condition = 0; condition < 5; ++condition) {
    SCOPED_TRACE(condition);
    policy.revokedAbortAuthorized = true;
    owners.metadata = true;
    nvs.free = 500;
    policy.onSecurityValidated = {};
    policy.onRevokedAbort = [&]() {
      if (condition == 0) policy.revokedAbortAuthorized = false;
      else if (condition == 1) owners.metadata = false;
      else if (condition == 2) nvs.free = 146;
    };
    if (condition == 3)
      policy.onSecurityValidated = [&]() { policy.revokedAbortAuthorized = false; };
    if (condition == 4) owners.metadata = false;
    const auto refused = attempts.abortRevoked(record);
    EXPECT_EQ(condition == 2 ? Status::NoSpace : Status::OwnershipDenied, refused.status);
    EXPECT_FALSE(refused.mutationMayHaveOccurred);
    EXPECT_FALSE(flash.isBound());
    expectUnchanged(before);
  }
}

TEST_F(AttemptFixture, RevokedAbortMissingCorruptOrPreparedCommissioningNeverMutates) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  const auto original = nvs.durable;
  for (size_t condition = 0; condition < 5; ++condition) {
    SCOPED_TRACE(condition);
    nvs.durable = original;
    nvs.getError = kEsp32Ok;
    if (condition == 0) {
      nvs.durable.erase({Esp32BlobKind::Security, Esp32NvsSlot::A});
      nvs.durable.erase({Esp32BlobKind::Security, Esp32NvsSlot::B});
    } else if (condition == 1) nvs.durable[{Esp32BlobKind::Security, Esp32NvsSlot::B}].back() ^= 1;
    else if (condition == 2)
      injectRecord(nvs, Esp32BlobKind::Security, Esp32NvsSlot::B, 2, {0x00});
    else if (condition == 3)
      injectRecord(nvs, Esp32BlobKind::Security, Esp32NvsSlot::B, 2,
                   policy.security, Esp32BlobPhase::Prepared);
    else nvs.getError = 0x109;
    const auto before = snapshot();
    Esp32FlashAdapter fresh_flash(partitions, owners);
    Esp32DurableBlobStore fresh_blobs(nvs, owners);
    Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
    const auto refused = fresh_attempts.abortRevoked(record);
    EXPECT_EQ(condition == 0 ? Status::Missing : condition < 3 ? Status::Corrupt :
              condition == 3 ? Status::DurabilityUncertain : Status::IoError, refused.status);
    EXPECT_EQ(condition == 4 ? 0x109 : kEsp32Ok, refused.sdkError);
    EXPECT_EQ(0u, policy.revokedAbortCalls);
    EXPECT_FALSE(fresh_flash.isBound());
    expectUnchanged(before);
  }
}

TEST_F(AttemptFixture, RevokedAbortMissingCorruptOrPreparedAttemptIsNeverDiscarded) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  const auto original = nvs.durable;
  const auto old_blob = currentBlob(blobs);
  for (size_t condition = 0; condition < 5; ++condition) {
    SCOPED_TRACE(condition);
    nvs.durable = original;
    if (condition == 0) {
      nvs.durable.erase({Esp32BlobKind::Attempt, Esp32NvsSlot::A});
      nvs.durable.erase({Esp32BlobKind::Attempt, Esp32NvsSlot::B});
    } else if (condition == 1)
      nvs.durable[{Esp32BlobKind::Attempt, old_blob.slot}].back() ^= 1;
    else if (condition == 2) {
      auto invalid = attemptPayload(record);
      invalid.back() = 0x7f;
      injectRecord(nvs, Esp32BlobKind::Attempt, old_blob.slot, old_blob.generation, invalid);
    } else if (condition == 3)
      injectRecord(nvs, Esp32BlobKind::Attempt, old_blob.slot, old_blob.generation,
                   attemptPayload(record), Esp32BlobPhase::Prepared);
    else {
      const auto older = old_blob.slot == Esp32NvsSlot::A ? Esp32NvsSlot::B : Esp32NvsSlot::A;
      nvs.durable[{Esp32BlobKind::Attempt, older}].back() ^= 1;
    }
    const auto before = snapshot();
    Esp32FlashAdapter fresh_flash(partitions, owners);
    Esp32DurableBlobStore fresh_blobs(nvs, owners);
    Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
    EXPECT_EQ(condition == 0 ? Status::Missing : condition == 3 ?
              Status::DurabilityUncertain : Status::Corrupt, fresh_attempts.abortRevoked(record).status);
    EXPECT_EQ(0u, policy.revokedAbortCalls);
    EXPECT_FALSE(fresh_flash.isBound());
    expectUnchanged(before);
  }
}

TEST_F(AttemptFixture, RevokedAbortCapacityThresholdAndGenerationExhaustionNeverMutate) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  const auto old_blob = currentBlob(blobs);
  nvs.free = 146;
  auto before = snapshot();
  EXPECT_EQ(Status::NoSpace, attempts.abortRevoked(record).status);
  EXPECT_EQ(0u, policy.revokedAbortCalls);
  expectUnchanged(before);
  nvs.free = 147;
  injectRecord(nvs, Esp32BlobKind::Attempt, old_blob.slot, UINT32_MAX, attemptPayload(record));
  before = snapshot();
  EXPECT_EQ(Status::GenerationExhausted, attempts.abortRevoked(record).status);
  EXPECT_EQ(0u, policy.revokedAbortCalls);
  EXPECT_FALSE(flash.isBound());
  expectUnchanged(before);
  injectRecord(nvs, Esp32BlobKind::Attempt, old_blob.slot, old_blob.generation, attemptPayload(record));
  before = snapshot();
  ASSERT_TRUE(attempts.abortRevoked(record).ok());
  EXPECT_EQ(old_blob.generation + 1, currentBlob(blobs).generation);
  EXPECT_FALSE(flash.isBound());
  expectProtectedState(before);
}

TEST_F(AttemptFixture, RevokedAbortCallbackCannotRetireAChangedWinnerOrGeneration) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  const auto original = nvs.durable;
  const auto old_blob = currentBlob(blobs);
  for (size_t condition = 0; condition < 3; ++condition) {
    SCOPED_TRACE(condition);
    nvs.durable = original;
    auto winner = record;
    uint32_t generation = old_blob.generation + 1;
    if (condition == 1) {
      generation = old_blob.generation;
      ++winner.verifiedBytes;
    } else if (condition == 2) {
      ++winner.session.attemptId;
      winner.consent = Esp32ConsentState::Granted;
      winner.phase = Esp32StagingPhase::Admitted;
      winner.erasedBytes = winner.verifiedBytes = 0;
      TestAttemptPolicy::attemptDigest(winner, winner.attemptDigest);
    }
    const auto before = snapshot();
    auto expected = before.durable;
    policy.onRevokedAbort = [&]() {
      injectRecord(nvs, Esp32BlobKind::Attempt, old_blob.slot, generation, attemptPayload(winner));
      expected = nvs.durable;
    };
    const auto refused = attempts.abortRevoked(record);
    EXPECT_EQ(Status::Conflict, refused.status);
    EXPECT_FALSE(refused.mutationMayHaveOccurred);
    EXPECT_FALSE(flash.isBound());
    EXPECT_EQ(expected, nvs.durable);
    EXPECT_EQ(before.sets, nvs.setCalls);
    EXPECT_EQ(before.commits, nvs.commitCalls);
    expectProtectedState(before);
  }
}

TEST_F(AttemptFixture, RevokedAbortPersistsFrozenCheckpointNotCallerAliasedGrantOrProgress) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  const auto revoked = record;
  const auto old_blob = currentBlob(blobs);
  const auto before = snapshot();
  auto expected = revoked;
  policy.onSecurityValidated = [&]() {
    expected.controller[31] ^= 1;
    ++expected.session.attemptId;
    expected.signedDescriptor[122] ^= 1;
    expected.partition = partitions.snapshot.running;
    TestAttemptPolicy::attemptDigest(expected, expected.attemptDigest);
  };
  policy.onRevokedAbort = [&]() {
    expected.consent = Esp32ConsentState::Granted;
    expected.phase = Esp32StagingPhase::Staged;
    expected.verifiedBytes = static_cast<uint32_t>(image.size());
  };
  ASSERT_TRUE(attempts.abortRevoked(expected).ok());
  auto terminal = revoked;
  terminal.phase = Esp32StagingPhase::Aborted;
  const auto saved = currentBlob(blobs);
  EXPECT_EQ(old_blob.generation + 1, saved.generation);
  EXPECT_EQ(attemptPayload(terminal), std::vector<uint8_t>(saved.payload, saved.payload + saved.size));
  EXPECT_FALSE(flash.isBound());
  expectProtectedState(before);
}

TEST_F(AttemptFixture, RevokedAbortCallbackCannotInvalidateOrReplaceValidatedCommissioning) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  const auto original = nvs.durable;
  for (size_t condition = 0; condition < 4; ++condition) {
    SCOPED_TRACE(condition);
    nvs.durable = original;
    const auto before = snapshot();
    auto expected = before.durable;
    policy.onRevokedAbort = [&]() {
      if (condition == 0) nvs.durable[{Esp32BlobKind::Security, Esp32NvsSlot::B}].back() ^= 1;
      else if (condition == 1)
        injectRecord(nvs, Esp32BlobKind::Security, Esp32NvsSlot::B, 3, policy.security);
      else if (condition == 2) {
        auto changed = policy.security;
        changed.back() ^= 1;
        injectRecord(nvs, Esp32BlobKind::Security, Esp32NvsSlot::B, 2, changed);
      } else {
        nvs.durable.erase({Esp32BlobKind::Security, Esp32NvsSlot::A});
        nvs.durable.erase({Esp32BlobKind::Security, Esp32NvsSlot::B});
      }
      expected = nvs.durable;
    };
    const auto refused = attempts.abortRevoked(record);
    EXPECT_EQ(condition == 0 ? Status::Corrupt : condition == 3 ?
              Status::Missing : Status::Conflict, refused.status);
    EXPECT_FALSE(refused.mutationMayHaveOccurred);
    EXPECT_FALSE(flash.isBound());
    EXPECT_EQ(expected, nvs.durable);
    EXPECT_EQ(before.sets, nvs.setCalls);
    EXPECT_EQ(before.commits, nvs.commitCalls);
    EXPECT_EQ(before.nor, partitions.bytes);
    EXPECT_EQ(before.erased, partitions.erasedOffsets);
    EXPECT_EQ(before.programs, partitions.writeCalls);
    EXPECT_EQ(before.unrelated, nvs.unrelated);
  }
}

TEST_F(AttemptFixture, RevokedAbortSaveFailureBeforeMutationRequiresFreshQualifiedRetry) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  const auto old_blob = currentBlob(blobs);
  const auto before = snapshot();
  nvs.failSetAt = nvs.setCalls + 1;
  nvs.setTiming = FaultTiming::Before;
  const auto failed = attempts.abortRevoked(record);
  EXPECT_EQ(Status::DurabilityUncertain, failed.status);
  EXPECT_EQ(Status::IoError, failed.uncertaintyCause);
  EXPECT_EQ(-1, failed.sdkError);
  EXPECT_TRUE(failed.mutationMayHaveOccurred);
  EXPECT_FALSE(flash.isBound());
  EXPECT_EQ(before.durable, nvs.durable);
  EXPECT_EQ(before.sets + 1, nvs.setCalls);
  EXPECT_EQ(before.commits, nvs.commitCalls);
  expectProtectedState(before);
  nvs.clearFaults();
  const auto latched = snapshot();
  EXPECT_EQ(Status::DurabilityUncertain, attempts.abortRevoked(record).status);
  expectUnchanged(latched);
  Esp32FlashAdapter fresh_flash(partitions, owners);
  Esp32DurableBlobStore fresh_blobs(nvs, owners);
  Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
  const auto winner = currentBlob(fresh_blobs);
  EXPECT_EQ(old_blob.generation, winner.generation);
  EXPECT_EQ(attemptPayload(record), std::vector<uint8_t>(winner.payload, winner.payload + winner.size));
  Esp32AttemptRecord restored;
  EXPECT_EQ(Status::OwnershipDenied, fresh_attempts.resume(restored).status);
  policy.revokedAbortAuthorized = false;
  EXPECT_EQ(Status::OwnershipDenied, fresh_attempts.abortRevoked(record).status);
  expectUnchanged(latched);
  policy.revokedAbortAuthorized = true;
  ASSERT_TRUE(fresh_attempts.abortRevoked(record).ok());
  EXPECT_FALSE(fresh_flash.isBound());
  EXPECT_EQ(old_blob.generation + 1, currentBlob(fresh_blobs).generation);
  expectProtectedState(before);
}

TEST_F(AttemptFixture, RevokedAbortCommitFaultsReconstructOnlyOldRevokedPreparedOrDurableAborted) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  const auto original = nvs.durable;
  const auto old_blob = currentBlob(blobs);
  auto terminal = record;
  terminal.phase = Esp32StagingPhase::Aborted;
  for (size_t condition = 0; condition < 8; ++condition) {
    SCOPED_TRACE(condition);
    nvs.durable = original;
    nvs.immediate = condition < 4;
    const uint32_t phase = condition % 4 < 2 ? 1 : 2;
    nvs.commitTiming = condition % 2 == 0 ? FaultTiming::Before : FaultTiming::After;
    nvs.failCommitAt = nvs.commitCalls + phase;
    const auto before = snapshot();
    Esp32FlashAdapter live_flash(partitions, owners);
    Esp32DurableBlobStore live_blobs(nvs, owners);
    Esp32AttemptStore live_attempts(live_blobs, live_flash, policy);
    const auto failed = live_attempts.abortRevoked(record);
    EXPECT_EQ(Status::DurabilityUncertain, failed.status);
    EXPECT_EQ(Status::IoError, failed.uncertaintyCause);
    EXPECT_EQ(-1, failed.sdkError);
    EXPECT_TRUE(failed.mutationMayHaveOccurred);
    EXPECT_FALSE(live_flash.isBound());
    EXPECT_EQ(before.sets + phase, nvs.setCalls);
    EXPECT_EQ(before.commits + phase, nvs.commitCalls);
    const auto old_key = Esp32NvsModel::Key{Esp32BlobKind::Attempt, old_blob.slot};
    EXPECT_EQ(before.durable.at(old_key), nvs.durable.at(old_key));
    expectProtectedState(before);
    nvs.clearFaults();
    const auto after_failure = snapshot();
    EXPECT_EQ(Status::DurabilityUncertain, live_attempts.abortRevoked(record).status);
    expectUnchanged(after_failure);
    Esp32FlashAdapter fresh_flash(partitions, owners);
    Esp32DurableBlobStore fresh_blobs(nvs, owners);
    Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
    const bool old_wins = !nvs.immediate && phase == 1 && nvs.commitTiming == FaultTiming::Before;
    const bool aborted_wins = phase == 2 &&
        (nvs.immediate || nvs.commitTiming == FaultTiming::After);
    Esp32DurableBlob winner;
    EXPECT_EQ(old_wins || aborted_wins ? Status::Ok : Status::DurabilityUncertain,
              fresh_blobs.load(Esp32BlobKind::Attempt, winner).status);
    Esp32AttemptRecord restored;
    EXPECT_EQ(old_wins ? Status::OwnershipDenied : aborted_wins ? Status::Conflict :
              Status::DurabilityUncertain, fresh_attempts.resume(restored).status);
    if (old_wins || aborted_wins) {
      const auto payload = attemptPayload(aborted_wins ? terminal : record);
      EXPECT_EQ(payload, std::vector<uint8_t>(winner.payload, winner.payload + winner.size));
      EXPECT_EQ(old_blob.generation + (aborted_wins ? 1 : 0), winner.generation);
    }
    policy.revokedAbortAuthorized = false;
    EXPECT_EQ(old_wins ? Status::OwnershipDenied : aborted_wins ? Status::Conflict :
              Status::DurabilityUncertain, fresh_attempts.abortRevoked(aborted_wins ? terminal : record).status);
    policy.revokedAbortAuthorized = true;
    EXPECT_FALSE(fresh_flash.isBound());
    expectUnchanged(after_failure);
  }
}

TEST_F(AttemptFixture, RevokedAbortFailedReadbackCannotClaimDurabilityAndFreshWinnerStaysRevoked) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  const auto original = nvs.durable;
  const auto old_blob = currentBlob(blobs);
  auto terminal = record;
  terminal.phase = Esp32StagingPhase::Aborted;
  for (size_t condition = 0; condition < 4; ++condition) {
    SCOPED_TRACE(condition);
    nvs.durable = original;
    const uint32_t phase = condition < 2 ? 1 : 2;
    policy.onRevokedAbort = [&]() {
      // Four reads each: refreshed security, checkpoint, save's predecessor.
      const uint32_t readback = nvs.getCalls + 12 + phase;
      if (condition % 2 == 0) nvs.failGetAt = readback;
      else nvs.badReadbackAt = readback;
    };
    const auto before = snapshot();
    Esp32FlashAdapter live_flash(partitions, owners);
    Esp32DurableBlobStore live_blobs(nvs, owners);
    Esp32AttemptStore live_attempts(live_blobs, live_flash, policy);
    const auto failed = live_attempts.abortRevoked(record);
    EXPECT_EQ(Status::DurabilityUncertain, failed.status);
    EXPECT_EQ(condition % 2 == 0 ? Status::IoError : Status::Corrupt, failed.uncertaintyCause);
    EXPECT_EQ(condition % 2 == 0 ? -1 : kEsp32Ok, failed.sdkError);
    EXPECT_TRUE(failed.mutationMayHaveOccurred);
    EXPECT_FALSE(live_flash.isBound());
    EXPECT_EQ(before.sets + phase, nvs.setCalls);
    EXPECT_EQ(before.commits + phase, nvs.commitCalls);
    const auto old_key = Esp32NvsModel::Key{Esp32BlobKind::Attempt, old_blob.slot};
    EXPECT_EQ(before.durable.at(old_key), nvs.durable.at(old_key));
    expectProtectedState(before);
    nvs.clearFaults();
    policy.onRevokedAbort = {};
    const auto after_failure = snapshot();
    EXPECT_EQ(Status::DurabilityUncertain, live_attempts.abortRevoked(record).status);
    expectUnchanged(after_failure);
    Esp32FlashAdapter fresh_flash(partitions, owners);
    Esp32DurableBlobStore fresh_blobs(nvs, owners);
    Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
    Esp32DurableBlob winner;
    EXPECT_EQ(phase == 1 ? Status::DurabilityUncertain : Status::Ok,
              fresh_blobs.load(Esp32BlobKind::Attempt, winner).status);
    if (phase == 2) {
      EXPECT_EQ(old_blob.generation + 1, winner.generation);
      EXPECT_EQ(attemptPayload(terminal), std::vector<uint8_t>(winner.payload, winner.payload + winner.size));
    }
    EXPECT_EQ(phase == 1 ? Status::DurabilityUncertain : Status::Conflict,
              fresh_attempts.abortRevoked(phase == 1 ? record : terminal).status);
    EXPECT_FALSE(fresh_flash.isBound());
    expectUnchanged(after_failure);
  }
}

TEST_F(AttemptFixture, RevokedAbortTornMetadataRemainsCorruptAfterFreshReconstruction) {
  revokeReceiving();
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  policy.revokedAbortAuthorized = true;
  const auto before = snapshot();
  nvs.failSetAt = nvs.setCalls + 1;
  nvs.setTiming = FaultTiming::Torn;
  nvs.tornBytes = 35;
  const auto failed = attempts.abortRevoked(record);
  EXPECT_EQ(Status::DurabilityUncertain, failed.status);
  EXPECT_TRUE(failed.mutationMayHaveOccurred);
  EXPECT_EQ(-1, failed.sdkError);
  EXPECT_FALSE(flash.isBound());
  expectProtectedState(before);
  nvs.clearFaults();
  const auto after_failure = snapshot();
  Esp32FlashAdapter fresh_flash(partitions, owners);
  Esp32DurableBlobStore fresh_blobs(nvs, owners);
  Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
  EXPECT_EQ(Status::Corrupt, fresh_attempts.abortRevoked(record).status);
  EXPECT_FALSE(fresh_flash.isBound());
  expectUnchanged(after_failure);
}

TEST_F(AttemptFixture, AbortedAttemptCannotBeResurrectedByFreshResumeOrCheckpoint) {
  admitAndPrepare();
  record.phase = Esp32StagingPhase::Aborted;
  ASSERT_TRUE(attempts.checkpoint(record).ok());
  EXPECT_FALSE(flash.isBound());
  const uint32_t writes = nvs.setCalls;
  Esp32FlashAdapter reboot_flash(partitions, owners);
  Esp32DurableBlobStore reboot_blobs(nvs, owners);
  Esp32AttemptStore reboot_attempts(reboot_blobs, reboot_flash, policy);
  Esp32AttemptRecord loaded;
  EXPECT_EQ(Status::Conflict, reboot_attempts.resume(loaded).status);
  record.phase = Esp32StagingPhase::Receiving;
  EXPECT_EQ(Status::Conflict, reboot_attempts.checkpoint(record).status);
  EXPECT_FALSE(reboot_flash.isBound());
  EXPECT_EQ(writes, nvs.setCalls);
  EXPECT_EQ(1u, partitions.erasedOffsets.size());
}

TEST_F(AttemptFixture, CommissionedSecurityLostAfterAdmissionStopsFreshResumeWithoutMutation) {
  admitAndPrepare();
  const auto before = partitions.bytes;
  const auto sentinel = nvs.unrelated;
  const uint32_t writes = nvs.setCalls;
  nvs.durable.erase({Esp32BlobKind::Security, Esp32NvsSlot::A});
  Esp32FlashAdapter reboot_flash(partitions, owners);
  Esp32DurableBlobStore reboot_blobs(nvs, owners);
  Esp32AttemptStore reboot_attempts(reboot_blobs, reboot_flash, policy);
  Esp32AttemptRecord loaded;
  loaded.verifiedBytes = 0xfeed;
  EXPECT_EQ(Status::Missing, reboot_attempts.resume(loaded).status);
  EXPECT_EQ(0xfeedu, loaded.verifiedBytes);
  EXPECT_FALSE(reboot_flash.isBound());
  EXPECT_EQ(writes, nvs.setCalls);
  EXPECT_EQ(before, partitions.bytes);
  EXPECT_EQ(sentinel, nvs.unrelated);
}

TEST_F(AttemptFixture, FreshResumeRevalidatesActualSelectedSlotAndPreservesAllBytes) {
  admitAndPrepare();
  const auto before = partitions.bytes;
  const uint32_t writes = nvs.setCalls;
  std::swap(partitions.snapshot.running, partitions.snapshot.next);
  partitions.snapshot.boot = partitions.snapshot.running;
  Esp32FlashAdapter reboot_flash(partitions, owners);
  Esp32DurableBlobStore reboot_blobs(nvs, owners);
  Esp32AttemptStore reboot_attempts(reboot_blobs, reboot_flash, policy);
  Esp32AttemptRecord loaded;
  loaded.verifiedBytes = 0xfeed;
  EXPECT_EQ(Status::PartitionMismatch, reboot_attempts.resume(loaded).status);
  EXPECT_EQ(0xfeedu, loaded.verifiedBytes);
  EXPECT_FALSE(reboot_flash.isBound());
  EXPECT_EQ(writes, nvs.setCalls);
  EXPECT_EQ(before, partitions.bytes);
  EXPECT_EQ(1u, partitions.erasedOffsets.size());
}

TEST_F(AttemptFixture, TornNorWriteFreshReconstructionResumesWithoutAnyEraseAndHashesExactImage) {
  const uint32_t torn_sizes[] = {0, 1, 127, 128, 511, 512};
  for (size_t scenario = 0; scenario < 12; ++scenario) {
    const bool running_app1 = scenario >= 6;
    const uint32_t torn = torn_sizes[scenario % 6];
    SCOPED_TRACE(running_app1);
    SCOPED_TRACE(torn);
    Esp32PartitionModel sdk(running_app1);
    Esp32NvsModel persistent;
    Esp32FlashAdapter live_flash(sdk, owners);
    Esp32DurableBlobStore live_blobs(persistent, owners);
    Esp32AttemptStore live_attempts(live_blobs, live_flash, policy);
    auto live = policy.attempt(sdk.snapshot.next, image);
    const auto protected_before = sdk.bytes;
    const auto nvs_sentinel = persistent.unrelated;
    ASSERT_TRUE(live_blobs.save(Esp32BlobKind::Security, policy.security.data(), policy.security.size(),
                                Esp32BlobCreation::ExplicitProvision).ok());
    ASSERT_TRUE(live_attempts.admit(live).ok());
    live.phase = Esp32StagingPhase::Erasing;
    ASSERT_TRUE(live_attempts.checkpoint(live).ok());
    ASSERT_EQ(FlashStatus::Ok, live_flash.eraseSector(0));
    live.erasedBytes = 4096;
    ASSERT_TRUE(live_attempts.checkpoint(live).ok());
    live.phase = Esp32StagingPhase::Receiving;
    ASSERT_TRUE(live_attempts.checkpoint(live).ok());
    FlashRegion region(live_flash, 0, live_flash.totalSizeBytes());
    ASSERT_TRUE(StorageManager::writeAndVerifyChunk(region, 0, 512, image.data(), 512));
    live.verifiedBytes = 512;
    ASSERT_TRUE(live_attempts.checkpoint(live).ok());
    sdk.writeFault = FaultTiming::Torn;
    sdk.tornBytes = torn;
    EXPECT_FALSE(StorageManager::writeAndVerifyChunk(region, 1, 512, image.data() + 512, 512));
    EXPECT_EQ(-1, live_flash.lastSdkError());
    EXPECT_EQ(0, memcmp(image.data() + 512, sdk.bytes.data() + sdk.snapshot.next.address + 512, torn));
    for (uint32_t i = torn; i < 512; ++i) EXPECT_EQ(0xff, sdk.bytes[sdk.snapshot.next.address + 512 + i]);
    sdk.writeFault = FaultTiming::None;
    Esp32FlashAdapter fresh_flash(sdk, owners);
    Esp32DurableBlobStore fresh_blobs(persistent, owners);
    Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
    Esp32AttemptRecord restored;
    ASSERT_TRUE(fresh_attempts.resume(restored).ok());
    EXPECT_EQ(512u, restored.verifiedBytes);
    EXPECT_EQ(4096u, restored.erasedBytes);
    ASSERT_EQ(1u, sdk.erasedOffsets.size());
    FlashRegion resumed(fresh_flash, 0, fresh_flash.totalSizeBytes());
    ASSERT_TRUE(StorageManager::writeAndVerifyChunk(resumed, 1, 512, image.data() + 512, 512));
    EXPECT_EQ(1u, sdk.erasedOffsets.size());
    EXPECT_EQ(3u, sdk.writeCalls);
    EXPECT_EQ(0, memcmp(image.data(), sdk.bytes.data() + sdk.snapshot.next.address, image.size()));
    ota::trust::Sha256 hash;
    uint8_t digest[32];
    ASSERT_TRUE(ota::trust::ImageHasher::hashRegion(hash, resumed, image.size(), digest));
    meshcore::ota::protocol::OtaDescriptor descriptor;
    ASSERT_TRUE(Esp32AttemptCodec::descriptor(restored, descriptor));
    EXPECT_EQ(0, memcmp(descriptor.sha256, digest, 32));
    restored.verifiedBytes = 1024;
    ASSERT_TRUE(fresh_attempts.checkpoint(restored).ok());
    restored.phase = Esp32StagingPhase::Staged;
    ASSERT_TRUE(fresh_attempts.checkpoint(restored).ok());
    EXPECT_FALSE(Esp32FlashAdapter::installationAvailable());
    EXPECT_EQ(nvs_sentinel, persistent.unrelated);
    expectProtected(sdk, protected_before, sdk.snapshot.next);
  }
}

TEST_F(AttemptFixture, PreparedMetadataAfterLostCommitBlocksFreshResumeWithoutAppMutation) {
  admitAndPrepare();
  const auto before = partitions.bytes;
  const auto sentinel = nvs.unrelated;
  nvs.failCommitAt = nvs.commitCalls + 1;
  record.verifiedBytes = 512;
  const auto failed = attempts.checkpoint(record);
  EXPECT_EQ(Status::DurabilityUncertain, failed.status);
  EXPECT_EQ(-1, failed.sdkError);
  EXPECT_FALSE(flash.isBound());
  nvs.clearFaults();
  Esp32FlashAdapter reboot_flash(partitions, owners);
  Esp32DurableBlobStore reboot_blobs(nvs, owners);
  Esp32AttemptStore reboot_attempts(reboot_blobs, reboot_flash, policy);
  Esp32AttemptRecord loaded;
  EXPECT_EQ(Status::DurabilityUncertain, reboot_attempts.resume(loaded).status);
  EXPECT_FALSE(reboot_flash.isBound());
  EXPECT_EQ(before, partitions.bytes);
  EXPECT_EQ(sentinel, nvs.unrelated);
  EXPECT_EQ(1u, partitions.erasedOffsets.size());
}

TEST_F(AttemptFixture, AbortedAttemptExplicitlyReplacedByFreshConsentedSameImageAfterReconstruction) {
  makeTerminal();
  ASSERT_FALSE(HasFatalFailure());
  seedProtectedBlobs();
  ASSERT_FALSE(HasFatalFailure());
  const auto terminal = record;
  const auto old_blob = currentBlob(blobs);
  auto next = nextAttempt();
  const auto before = snapshot();
  Esp32FlashAdapter reboot_flash(partitions, owners);
  Esp32DurableBlobStore reboot_blobs(nvs, owners);
  Esp32AttemptStore reboot_attempts(reboot_blobs, reboot_flash, policy);
  const auto result = reboot_attempts.replaceTerminal(terminal, next);
  ASSERT_EQ(Status::Ok, result.status);
  EXPECT_TRUE(result.mutationMayHaveOccurred);
  EXPECT_EQ(1u, policy.replacementCalls);
  EXPECT_EQ(before.sets + 2, nvs.setCalls);
  EXPECT_EQ(before.commits + 2, nvs.commitCalls);
  auto expected = before.durable;
  const auto slot = old_blob.slot == Esp32NvsSlot::A ? Esp32NvsSlot::B : Esp32NvsSlot::A;
  expected[{Esp32BlobKind::Attempt, slot}] = encoded(
      Esp32BlobKind::Attempt, Esp32BlobPhase::Committed, old_blob.generation + 1, attemptPayload(next));
  EXPECT_EQ(expected, nvs.durable);
  expectProtectedState(before);
  EXPECT_EQ(0, memcmp(terminal.signedDescriptor, next.signedDescriptor, 123));
  EXPECT_NE(0, memcmp(terminal.attemptDigest, next.attemptDigest, 32));
  Esp32FlashAdapter fresh_flash(partitions, owners);
  Esp32DurableBlobStore fresh_blobs(nvs, owners);
  Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
  Esp32AttemptRecord restored;
  ASSERT_TRUE(fresh_attempts.resume(restored).ok());
  EXPECT_TRUE(Esp32AttemptCodec::sameAttempt(next, restored));
  EXPECT_EQ(Esp32StagingPhase::Admitted, restored.phase);
  EXPECT_EQ(Esp32ConsentState::Granted, restored.consent);
  EXPECT_EQ(0u, restored.erasedBytes);
  EXPECT_EQ(0u, restored.verifiedBytes);
  EXPECT_EQ(old_blob.generation + 1, currentBlob(fresh_blobs).generation);
  const auto accepted = snapshot();
  EXPECT_EQ(Status::Conflict, fresh_attempts.replaceTerminal(terminal, next).status);
  EXPECT_EQ(Status::Conflict, fresh_attempts.admit(next).status);
  EXPECT_EQ(Status::Conflict, fresh_attempts.checkpoint(terminal).status);
  expectUnchanged(accepted);
}

TEST_F(AttemptFixture, StagedExplicitRetirementRequiresPolicyAndNeverErasesItsImage) {
  makeTerminal(Esp32StagingPhase::Staged);
  ASSERT_FALSE(HasFatalFailure());
  seedProtectedBlobs();
  const auto terminal = record;
  const auto old_blob = currentBlob(blobs);
  auto next = nextAttempt();
  policy.stagedRetirementAuthorized = true;
  const auto before = snapshot();
  Esp32FlashAdapter reboot_flash(partitions, owners);
  Esp32DurableBlobStore reboot_blobs(nvs, owners);
  Esp32AttemptStore reboot_attempts(reboot_blobs, reboot_flash, policy);
  ASSERT_TRUE(reboot_attempts.replaceTerminal(terminal, next).ok());
  expectProtectedState(before);
  const auto old_key = Esp32NvsModel::Key{Esp32BlobKind::Attempt, old_blob.slot};
  EXPECT_EQ(before.durable.at(old_key), nvs.durable.at(old_key));
  Esp32FlashAdapter fresh_flash(partitions, owners);
  Esp32DurableBlobStore fresh_blobs(nvs, owners);
  Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
  Esp32AttemptRecord restored;
  ASSERT_TRUE(fresh_attempts.resume(restored).ok());
  EXPECT_TRUE(Esp32AttemptCodec::sameAttempt(next, restored));
  EXPECT_EQ(Esp32StagingPhase::Admitted, restored.phase);
  EXPECT_EQ(0u, restored.erasedBytes);
  EXPECT_EQ(0u, restored.verifiedBytes);
  EXPECT_EQ(old_blob.generation + 1, currentBlob(fresh_blobs).generation);
  EXPECT_EQ(0, memcmp(image.data(), partitions.bytes.data() + terminal.partition.address, image.size()));
  EXPECT_FALSE(Esp32FlashAdapter::installationAvailable());
}

TEST_F(AttemptFixture, FreshControllerCampaignAndSessionCanReplaceTerminalWithoutResettingSecurity) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  ++next.session.campaignId;
  next.session.sessionId = 0x01020304;
  next.session.attemptId = 1;
  const uint8_t seed[32] = {0x53, 0x29, 0x81, 0x14};
  Ed25519TestSigner another_controller(seed);
  memcpy(next.controller, another_controller.publicKey(), 32);
  TestAttemptPolicy::attemptDigest(next, next.attemptDigest);
  memcpy(policy.authorizedController, next.controller, 32);
  policy.authorizedSession = next.session;
  const auto before = snapshot();
  Esp32FlashAdapter fresh_flash(partitions, owners);
  Esp32DurableBlobStore fresh_blobs(nvs, owners);
  Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
  ASSERT_TRUE(fresh_attempts.replaceTerminal(record, next).ok());
  Esp32AttemptRecord restored;
  ASSERT_TRUE(fresh_attempts.resume(restored).ok());
  EXPECT_TRUE(meshcore::ota::runtime::otaSessionEquals(next.session, restored.session));
  EXPECT_EQ(0, memcmp(next.controller, restored.controller, 32));
  EXPECT_EQ(0, memcmp(next.attemptDigest, restored.attemptDigest, 32));
  EXPECT_EQ(0, memcmp(record.signedDescriptor, restored.signedDescriptor, 123));
  EXPECT_EQ(Esp32StagingPhase::Admitted, restored.phase);
  EXPECT_EQ(before.sets + 2, nvs.setCalls);
  EXPECT_EQ(before.commits + 2, nvs.commitCalls);
  expectProtectedState(before);
}

TEST_F(AttemptFixture, ReplacementPolicyHookDefaultsToRefusalEvenWithValidNewAuthorization) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  DefaultReplacementPolicy default_policy(policy);
  Esp32AttemptStore denied(blobs, flash, default_policy);
  const auto before = snapshot();
  const auto result = denied.replaceTerminal(record, next);
  EXPECT_EQ(Status::OwnershipDenied, result.status);
  EXPECT_FALSE(result.mutationMayHaveOccurred);
  EXPECT_FALSE(flash.isBound());
  expectUnchanged(before);
}

TEST_F(AttemptFixture, ActiveAttemptsCannotBeRetiredEvenWhenReplacementPolicyWouldApprove) {
  provisionSecurity();
  ASSERT_TRUE(attempts.admit(record).ok());
  seedProtectedBlobs();
  const Esp32StagingPhase phases[] = {
      Esp32StagingPhase::Admitted, Esp32StagingPhase::Erasing, Esp32StagingPhase::Receiving};
  for (const auto phase : phases) {
    SCOPED_TRACE(static_cast<int>(phase));
    policy.authorizedSession = record.session;
    if (phase == Esp32StagingPhase::Erasing) {
      record.phase = phase;
      ASSERT_TRUE(attempts.checkpoint(record).ok());
    } else if (phase == Esp32StagingPhase::Receiving) {
      ASSERT_EQ(FlashStatus::Ok, flash.eraseSector(0));
      record.erasedBytes = 4096;
      ASSERT_TRUE(attempts.checkpoint(record).ok());
      record.phase = phase;
      ASSERT_TRUE(attempts.checkpoint(record).ok());
    }
    auto next = nextAttempt();
    const auto before = snapshot();
    EXPECT_EQ(Status::Conflict, attempts.replaceTerminal(record, next).status);
    EXPECT_EQ(0u, policy.replacementCalls);
    EXPECT_FALSE(flash.isBound());
    expectUnchanged(before);
    // Restore only the existing valid capability for preparing the next phase.
    policy.authorizedSession = record.session;
    Esp32AttemptRecord restored;
    ASSERT_TRUE(attempts.resume(restored).ok());
  }
}

TEST_F(AttemptFixture, StagedAwaitingInstallerIsNeverImplicitlyOverwritten) {
  makeTerminal(Esp32StagingPhase::Staged);
  seedProtectedBlobs();
  auto next = nextAttempt();
  const auto before = snapshot();
  EXPECT_EQ(Status::Conflict, attempts.admit(next).status);
  EXPECT_EQ(Status::OwnershipDenied, attempts.replaceTerminal(record, next).status);
  EXPECT_EQ(1u, policy.replacementCalls);
  EXPECT_FALSE(flash.isBound());
  expectUnchanged(before);
}

TEST_F(AttemptFixture, OldTupleCannotBeResurrectedByChangingOnlyImageControllerOrPartition) {
  makeTerminal();
  seedProtectedBlobs();
  const auto before = snapshot();
  for (size_t field = 0; field < 4; ++field) {
    auto next = policy.attempt(record.partition, image);
    if (field == 1) {
      auto different_image = image;
      different_image[0] ^= 1;
      next = policy.attempt(record.partition, different_image);
    } else if (field == 2) {
      const uint8_t seed[] = {0x81, 0x27, 0x39, 0x15, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      Ed25519TestSigner another_controller(seed);
      memcpy(next.controller, another_controller.publicKey(), 32);
    } else if (field == 3) next.partition = partitions.snapshot.running;
    memcpy(policy.authorizedController, next.controller, 32);
    TestAttemptPolicy::attemptDigest(next, next.attemptDigest);
    policy.authorizedSession = next.session;
    policy.replacementAuthorized = true;
    ASSERT_TRUE(policy.authorizedAttemptValid(next));
    EXPECT_EQ(Status::Conflict, attempts.replaceTerminal(record, next).status);
    EXPECT_EQ(0u, policy.replacementCalls);
    EXPECT_FALSE(flash.isBound());
    expectUnchanged(before);
  }
}

TEST_F(AttemptFixture, OlderCampaignSessionAndAttemptReplayRemainRefusedAfterAnotherTerminal) {
  makeTerminal();
  seedProtectedBlobs();
  const auto original_terminal = record;
  auto next = nextAttempt();
  ASSERT_TRUE(attempts.replaceTerminal(record, next).ok());
  next.phase = Esp32StagingPhase::Aborted;
  ASSERT_TRUE(attempts.checkpoint(next).ok());
  const auto before = snapshot();
  Esp32FlashAdapter fresh_flash(partitions, owners);
  Esp32DurableBlobStore fresh_blobs(nvs, owners);
  Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
  for (size_t field = 0; field < 3; ++field) {
    auto replay = original_terminal;
    replay.phase = Esp32StagingPhase::Admitted;
    replay.erasedBytes = replay.verifiedBytes = 0;
    if (field == 1) {
      replay.session = next.session;
      --replay.session.sessionId;
      ++replay.session.attemptId;
    } else if (field == 2) {
      replay.session = next.session;
      --replay.session.campaignId;
      ++replay.session.sessionId;
      ++replay.session.attemptId;
    }
    TestAttemptPolicy::attemptDigest(replay, replay.attemptDigest);
    policy.authorizedSession = replay.session;
    ASSERT_TRUE(policy.authorizedAttemptValid(replay));
    EXPECT_EQ(Status::Conflict, fresh_attempts.replaceTerminal(next, replay).status);
    EXPECT_FALSE(fresh_flash.isBound());
    expectUnchanged(before);
  }
}

TEST_F(AttemptFixture, RevokedTerminalConsentCannotResumeButDistinctFreshGrantCanReplaceIt) {
  makeTerminal(Esp32StagingPhase::Aborted, Esp32ConsentState::Revoked);
  seedProtectedBlobs();
  Esp32AttemptRecord loaded;
  EXPECT_EQ(Status::Conflict, attempts.resume(loaded).status);
  auto next = nextAttempt();
  const auto before = snapshot();
  policy.localConsentValid = false;
  EXPECT_EQ(Status::InvalidArgument, attempts.replaceTerminal(record, next).status);
  expectUnchanged(before);
  policy.localConsentValid = true;
  ASSERT_TRUE(attempts.replaceTerminal(record, next).ok());
  EXPECT_EQ(Esp32ConsentState::Revoked, record.consent);
  ASSERT_TRUE(attempts.resume(loaded).ok());
  EXPECT_EQ(Esp32ConsentState::Granted, loaded.consent);
  EXPECT_TRUE(Esp32AttemptCodec::sameAttempt(next, loaded));
  expectProtectedState(before);
}

TEST_F(AttemptFixture, FreshReplacementRequiresValidSignatureFullControllerDigestAndConsent) {
  makeTerminal();
  seedProtectedBlobs();
  const auto valid_next = nextAttempt();
  const auto before = snapshot();
  for (size_t field = 0; field < 6; ++field) {
    auto next = valid_next;
    switch (field) {
      case 0: next.signedDescriptor[122] ^= 1; break;
      case 1: next.controller[31] ^= 1; break;
      case 2: next.attemptDigest[31] ^= 1; break;
      case 3: next.consent = Esp32ConsentState::Denied; break;
      case 4: next.consent = Esp32ConsentState::Revoked; break;
      case 5: --next.session.attemptId; break;
    }
    EXPECT_EQ(Status::InvalidArgument, attempts.replaceTerminal(record, next).status);
    EXPECT_EQ(0u, policy.replacementCalls);
    expectUnchanged(before);
  }
  policy.replacementAuthorized = false;
  EXPECT_EQ(Status::OwnershipDenied, attempts.replaceTerminal(record, valid_next).status);
  expectUnchanged(before);
}

TEST_F(AttemptFixture, RetirementProofMustMatchTheEntireWinningTerminalCheckpoint) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  const auto before = snapshot();
  for (size_t field = 0; field < 9; ++field) {
    auto expected = record;
    switch (field) {
      case 0: expected.phase = Esp32StagingPhase::Receiving; break;
      case 1: expected.erasedBytes = 0; break;
      case 2: expected.verifiedBytes = 1; break;
      case 3: expected.consent = Esp32ConsentState::Revoked; break;
      case 4: ++expected.session.attemptId; break;
      case 5: expected.controller[31] ^= 1; break;
      case 6: expected.attemptDigest[31] ^= 1; break;
      case 7: expected.signedDescriptor[122] ^= 1; break;
      case 8: expected.partition = partitions.snapshot.running; break;
    }
    ASSERT_TRUE(Esp32AttemptCodec::valid(expected));
    EXPECT_EQ(Status::Conflict, attempts.replaceTerminal(expected, next).status);
    EXPECT_EQ(0u, policy.replacementCalls);
    expectUnchanged(before);
  }
}

TEST_F(AttemptFixture, StagedRetirementRevalidatesSdkLeaseBootTrialAndPartitionAfterPolicyDecision) {
  makeTerminal(Esp32StagingPhase::Staged);
  seedProtectedBlobs();
  auto next = nextAttempt();
  policy.stagedRetirementAuthorized = true;
  const auto original_sdk = partitions.snapshot;
  const auto before = snapshot();
  for (size_t condition = 0; condition < 7; ++condition) {
    SCOPED_TRACE(condition);
    partitions.snapshot = original_sdk;
    owners.flash = Esp32UpdateOwnership::ExclusiveStorage;
    partitions.inspectError = kEsp32Ok;
    policy.onReplacement = [&]() {
      switch (condition) {
        case 0: owners.flash = Esp32UpdateOwnership::Unknown; break;
        case 1: owners.flash = Esp32UpdateOwnership::OtherUpdater; break;
        case 2: partitions.snapshot.boot = partitions.snapshot.next; break;
        case 3: partitions.snapshot.appStates[0] = Esp32ImageState::PendingVerify; break;
        case 4: partitions.snapshot.appStates[1] = Esp32ImageState::New; break;
        case 5: --partitions.snapshot.table[3].size; break;
        case 6: partitions.inspectError = 0x107; break;
      }
    };
    const auto result = attempts.replaceTerminal(record, next);
    EXPECT_EQ(condition == 6 ? Status::IoError : Status::PartitionMismatch, result.status);
    EXPECT_EQ(condition == 6 ? 0x107 : kEsp32Ok, result.sdkError);
    EXPECT_FALSE(result.mutationMayHaveOccurred);
    EXPECT_FALSE(flash.isBound());
    expectUnchanged(before);
  }
}

TEST_F(AttemptFixture, NewPartitionBindingCannotAddressTheRunningOrWrongInactiveSlot) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  next.partition = partitions.snapshot.running;
  const auto before = snapshot();
  EXPECT_EQ(Status::PartitionMismatch, attempts.replaceTerminal(record, next).status);
  expectUnchanged(before);
  next.partition = record.partition;
  std::swap(partitions.snapshot.running, partitions.snapshot.next);
  partitions.snapshot.boot = partitions.snapshot.running;
  EXPECT_EQ(Status::PartitionMismatch, attempts.replaceTerminal(record, next).status);
  EXPECT_FALSE(flash.isBound());
  expectUnchanged(before);
}

TEST_F(AttemptFixture, RevokedConsentOrMetadataOwnershipDuringPolicyDecisionCannotMutate) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  const auto before = snapshot();
  for (size_t condition = 0; condition < 3; ++condition) {
    policy.localConsentValid = true;
    owners.metadata = true;
    nvs.free = 500;
    policy.onReplacement = [&]() {
      if (condition == 0) policy.localConsentValid = false;
      else if (condition == 1) owners.metadata = false;
      else nvs.free = 146;
    };
    EXPECT_EQ(condition == 2 ? Status::NoSpace : Status::OwnershipDenied,
              attempts.replaceTerminal(record, next).status);
    EXPECT_FALSE(flash.isBound());
    expectUnchanged(before);
  }
}

TEST_F(AttemptFixture, MissingCorruptOrPreparedAttemptIsNeverDiscardedByReplacement) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  const auto old_blob = currentBlob(blobs);
  const auto original = nvs.durable;
  for (size_t condition = 0; condition < 4; ++condition) {
    nvs.durable = original;
    const auto key = Esp32NvsModel::Key{Esp32BlobKind::Attempt, old_blob.slot};
    if (condition == 0) nvs.durable[key].back() ^= 1;
    else if (condition == 1) {
      auto invalid = attemptPayload(record);
      invalid.back() = 0x7f;
      injectRecord(nvs, Esp32BlobKind::Attempt, old_blob.slot, old_blob.generation, invalid);
    } else if (condition == 2) {
      injectRecord(nvs, Esp32BlobKind::Attempt, old_blob.slot, old_blob.generation,
                   attemptPayload(record), Esp32BlobPhase::Prepared);
    } else {
      nvs.durable.erase({Esp32BlobKind::Attempt, Esp32NvsSlot::A});
      nvs.durable.erase({Esp32BlobKind::Attempt, Esp32NvsSlot::B});
    }
    const auto before = snapshot();
    Esp32FlashAdapter fresh_flash(partitions, owners);
    Esp32DurableBlobStore fresh_blobs(nvs, owners);
    Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
    EXPECT_EQ(condition < 2 ? Status::Corrupt :
              condition == 2 ? Status::DurabilityUncertain : Status::Missing,
              fresh_attempts.replaceTerminal(record, next).status);
    EXPECT_EQ(0u, policy.replacementCalls);
    EXPECT_FALSE(fresh_flash.isBound());
    expectUnchanged(before);
  }
}

TEST_F(AttemptFixture, ReplacementGenerationExhaustionAndInsufficientCapacityNeverMutate) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  auto old_blob = currentBlob(blobs);
  nvs.free = 146;
  auto before = snapshot();
  EXPECT_EQ(Status::NoSpace, attempts.replaceTerminal(record, next).status);
  EXPECT_EQ(0u, policy.replacementCalls);
  expectUnchanged(before);
  nvs.free = 147;
  injectRecord(nvs, Esp32BlobKind::Attempt, old_blob.slot, UINT32_MAX, attemptPayload(record));
  before = snapshot();
  EXPECT_EQ(Status::GenerationExhausted, attempts.replaceTerminal(record, next).status);
  EXPECT_FALSE(flash.isBound());
  expectUnchanged(before);
}

TEST_F(AttemptFixture, SaveFailureBeforeMutationReloadsOldTerminalInsteadOfInventingNewAttempt) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  const auto old_blob = currentBlob(blobs);
  const auto before = snapshot();
  nvs.failSetAt = nvs.setCalls + 1;
  nvs.setTiming = FaultTiming::Before;
  const auto failed = attempts.replaceTerminal(record, next);
  EXPECT_EQ(Status::DurabilityUncertain, failed.status);
  EXPECT_EQ(-1, failed.sdkError);
  EXPECT_FALSE(flash.isBound());
  EXPECT_EQ(before.durable, nvs.durable);
  EXPECT_EQ(before.sets + 1, nvs.setCalls);
  EXPECT_EQ(before.commits, nvs.commitCalls);
  expectProtectedState(before);
  nvs.clearFaults();
  const auto after_failure = snapshot();
  EXPECT_EQ(Status::DurabilityUncertain, attempts.replaceTerminal(record, next).status);
  expectUnchanged(after_failure);
  Esp32FlashAdapter fresh_flash(partitions, owners);
  Esp32DurableBlobStore fresh_blobs(nvs, owners);
  Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
  const auto persisted = currentBlob(fresh_blobs);
  EXPECT_EQ(old_blob.generation, persisted.generation);
  EXPECT_EQ(old_blob.slot, persisted.slot);
  EXPECT_EQ(0, memcmp(persisted.payload, old_blob.payload, old_blob.size));
  Esp32AttemptRecord restored;
  EXPECT_EQ(Status::Conflict, fresh_attempts.resume(restored).status);
  ASSERT_TRUE(fresh_attempts.replaceTerminal(record, next).ok());
  EXPECT_EQ(old_blob.generation + 1, currentBlob(fresh_blobs).generation);
  expectProtectedState(before);
}

TEST_F(AttemptFixture, DurableNewAttemptBeforeLostAcknowledgementWinsAfterFreshReconstruction) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  const auto old_blob = currentBlob(blobs);
  const auto before = snapshot();
  nvs.failCommitAt = nvs.commitCalls + 2;
  nvs.commitTiming = FaultTiming::After;
  const auto failed = attempts.replaceTerminal(record, next);
  EXPECT_EQ(Status::DurabilityUncertain, failed.status);
  EXPECT_EQ(-1, failed.sdkError);
  EXPECT_TRUE(failed.mutationMayHaveOccurred);
  EXPECT_FALSE(flash.isBound());
  EXPECT_EQ(before.sets + 2, nvs.setCalls);
  EXPECT_EQ(before.commits + 2, nvs.commitCalls);
  expectProtectedState(before);
  const auto old_key = Esp32NvsModel::Key{Esp32BlobKind::Attempt, old_blob.slot};
  EXPECT_EQ(before.durable.at(old_key), nvs.durable.at(old_key));
  nvs.clearFaults();
  Esp32FlashAdapter fresh_flash(partitions, owners);
  Esp32DurableBlobStore fresh_blobs(nvs, owners);
  Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
  Esp32AttemptRecord restored;
  ASSERT_TRUE(fresh_attempts.resume(restored).ok());
  EXPECT_TRUE(Esp32AttemptCodec::sameAttempt(next, restored));
  EXPECT_EQ(Esp32StagingPhase::Admitted, restored.phase);
  EXPECT_EQ(0u, restored.erasedBytes);
  EXPECT_EQ(0u, restored.verifiedBytes);
  EXPECT_EQ(old_blob.generation + 1, currentBlob(fresh_blobs).generation);
  const auto accepted = snapshot();
  EXPECT_EQ(Status::Conflict, fresh_attempts.replaceTerminal(record, next).status);
  expectUnchanged(accepted);
  expectProtectedState(before);
}

TEST_F(AttemptFixture, PreparedReplacementAfterCommitUncertaintyBlocksFreshRetryWithoutErase) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  const auto before = snapshot();
  nvs.failCommitAt = nvs.commitCalls + 1;
  nvs.commitTiming = FaultTiming::After;
  EXPECT_EQ(Status::DurabilityUncertain, attempts.replaceTerminal(record, next).status);
  nvs.clearFaults();
  const auto uncertain = snapshot();
  Esp32FlashAdapter fresh_flash(partitions, owners);
  Esp32DurableBlobStore fresh_blobs(nvs, owners);
  Esp32AttemptStore fresh_attempts(fresh_blobs, fresh_flash, policy);
  EXPECT_EQ(Status::DurabilityUncertain, fresh_attempts.replaceTerminal(record, next).status);
  Esp32AttemptRecord restored;
  EXPECT_EQ(Status::DurabilityUncertain, fresh_attempts.resume(restored).status);
  EXPECT_FALSE(fresh_flash.isBound());
  expectUnchanged(uncertain);
  expectProtectedState(before);
}

TEST_F(AttemptFixture, PolicyCallbackCannotReplaceAChangedWinningActiveCheckpoint) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  const auto old_blob = currentBlob(blobs);
  const auto before = snapshot();
  policy.onReplacement = [&]() {
    injectRecord(nvs, Esp32BlobKind::Attempt, old_blob.slot, old_blob.generation + 1, attemptPayload(next));
  };
  EXPECT_EQ(Status::Conflict, attempts.replaceTerminal(record, next).status);
  EXPECT_EQ(before.sets, nvs.setCalls);
  EXPECT_EQ(before.commits, nvs.commitCalls);
  const auto winner = currentBlob(blobs);
  EXPECT_EQ(old_blob.generation + 1, winner.generation);
  EXPECT_EQ(0, memcmp(winner.payload, attemptPayload(next).data(), winner.size));
  EXPECT_FALSE(flash.isBound());
  expectProtectedState(before);
}

TEST_F(AttemptFixture, ChangedCommissionedSecurityDuringRetirementProofCannotAuthorizeSave) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  const auto before = snapshot();
  policy.onReplacement = [&]() {
    nvs.durable[{Esp32BlobKind::Security, Esp32NvsSlot::B}].back() ^= 1;
  };
  EXPECT_EQ(Status::Corrupt, attempts.replaceTerminal(record, next).status);
  EXPECT_EQ(before.sets, nvs.setCalls);
  EXPECT_EQ(before.commits, nvs.commitCalls);
  EXPECT_EQ(before.nor, partitions.bytes);
  EXPECT_EQ(before.erased, partitions.erasedOffsets);
  EXPECT_EQ(before.programs, partitions.writeCalls);
  for (const auto& entry : before.durable)
    if (entry.first != Esp32NvsModel::Key{Esp32BlobKind::Security, Esp32NvsSlot::B})
      EXPECT_EQ(entry.second, nvs.durable.at(entry.first));
  EXPECT_EQ(before.unrelated, nvs.unrelated);
  EXPECT_FALSE(flash.isBound());
}

TEST_F(AttemptFixture, RefreshedCommissionedPolicyCanRevokeNewConsentBeforeReplacementSave) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  const auto before = snapshot();
  policy.onReplacement = [&]() {
    policy.onSecurityValidated = [&]() { policy.localConsentValid = false; };
  };
  const auto result = attempts.replaceTerminal(record, next);
  EXPECT_EQ(Status::OwnershipDenied, result.status);
  EXPECT_FALSE(result.mutationMayHaveOccurred);
  EXPECT_FALSE(flash.isBound());
  expectUnchanged(before);
}

TEST_F(AttemptFixture, PolicyCallbackCannotRebindTheApprovedProposalToTheRetiredTuple) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  const auto before = snapshot();
  policy.onReplacement = [&]() {
    next.session = record.session;
    TestAttemptPolicy::attemptDigest(next, next.attemptDigest);
    policy.authorizedSession = next.session;
  };
  const auto result = attempts.replaceTerminal(record, next);
  EXPECT_EQ(Status::OwnershipDenied, result.status);
  EXPECT_FALSE(result.mutationMayHaveOccurred);
  EXPECT_FALSE(flash.isBound());
  expectUnchanged(before);
}

TEST_F(AttemptFixture, ReplacementPersistsFrozenAdmittedZeroProgressNotCallerAliasedStagedState) {
  makeTerminal();
  seedProtectedBlobs();
  auto next = nextAttempt();
  const auto approved = next;
  const auto before = snapshot();
  policy.onReplacement = [&]() {
    next.phase = Esp32StagingPhase::Staged;
    next.erasedBytes = 4096;
    next.verifiedBytes = static_cast<uint32_t>(image.size());
  };
  ASSERT_TRUE(attempts.replaceTerminal(record, next).ok());
  Esp32AttemptRecord restored;
  ASSERT_TRUE(attempts.resume(restored).ok());
  EXPECT_TRUE(Esp32AttemptCodec::sameAttempt(approved, restored));
  EXPECT_EQ(Esp32StagingPhase::Admitted, restored.phase);
  EXPECT_EQ(0u, restored.erasedBytes);
  EXPECT_EQ(0u, restored.verifiedBytes);
  expectProtectedState(before);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
