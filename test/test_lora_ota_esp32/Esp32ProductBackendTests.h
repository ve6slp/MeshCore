#pragma once

#include <gtest/gtest.h>
#include <helpers/ota/OtaFirmwareBackend.h>
#include <helpers/ota/OtaFirmwareIntegration.h>
#include <helpers/ota/OtaEsp32RollbackGuard.h>
#include <ota/trust/Ed25519SignatureVerifier.h>
#include "../test_lora_ota_trust/Ed25519TestSigner.h"
#include "Esp32SdkModel.h"

namespace {

using namespace mesh::ota;
using namespace ::ota::storage;
using ::ota::platform::Esp32FlashAdapter;
using ::ota::platform::FlashRegion;
using ::ota::platform::FlashStatus;
using ::ota::test::Esp32PartitionModel;
using ::ota::test::FaultTiming;
using ::ota::test::Ed25519TestSigner;
using Result = OtaLeanReceiver::Result;
using SinkResult = meshcore::ota::runtime::IOtaStagingSink::Result;
using InstallOutcome = Esp32OtaStagingSink::InstallOutcome;

class InstallModel final : public Esp32OtaInstallApi {
public:
  InstallModel(Esp32PartitionModel& sdk, const Esp32OtaPolicy& policy,
               const ::ota::trust::SignatureVerifier& signatures)
      : sdk(sdk), policy(policy), signatures(signatures) {}
  Esp32PartitionModel& sdk;
  const Esp32OtaPolicy& policy;
  const ::ota::trust::SignatureVerifier& signatures;
  uint32_t imageChecks = 0, selections = 0;
  bool imageValid = true, selectionFails = false, selectionTorn = false;
  bool floorKnown = false, floorReadable = true, finalFloorReadable = true;
  uint32_t floor = 0, finalFloor = UINT32_MAX;
  bool confirmedRunningCounter(uint32_t& counter) override;
  bool validateImage(const Esp32PartitionIdentity& partition, uint32_t exact_bytes) override {
    ++imageChecks;
    return imageValid && esp32PartitionEquals(partition, sdk.snapshot.next) &&
           exact_bytes != 0 && exact_bytes <= Esp32OtaPolicy::kCandidateBytes &&
           sdk.bytes[partition.address] == 0xe9;
  }
  bool selectBoot(const Esp32PartitionIdentity& partition) override {
    ++selections;
    if (selectionFails) return false;
    sdk.snapshot.boot = partition;
    sdk.snapshot.appStates[partition.subtype - 0x10] = Esp32ImageState::New;
    return !selectionTorn;
  }
};

class ReadOnlyAppModel final : public ::ota::platform::FlashDevice {
public:
  ReadOnlyAppModel(Esp32PartitionModel& sdk, const Esp32PartitionIdentity& partition)
      : sdk_(sdk), partition_(partition) {}
  uint32_t totalSizeBytes() const override { return partition_.size; }
  uint32_t eraseUnitBytes() const override { return 4096; }
  uint32_t programUnitBytes() const override { return 1; }
  FlashStatus read(uint32_t offset, uint8_t* out, uint32_t len) const override {
    ++sdk_.readCalls;
    if (sdk_.readError != kEsp32Ok || sdk_.readErrorPartition == partition_.address)
      return FlashStatus::IoError;
    if (offset > partition_.size || len > partition_.size - offset || (out == nullptr && len != 0))
      return FlashStatus::OutOfRange;
    if (len != 0) std::memcpy(out, sdk_.bytes.data() + partition_.address + offset, len);
    return FlashStatus::Ok;
  }
  FlashStatus program(uint32_t, const uint8_t*, uint32_t) override { return FlashStatus::Unsupported; }
  FlashStatus eraseSector(uint32_t) override { return FlashStatus::Unsupported; }
private:
  Esp32PartitionModel& sdk_;
  Esp32PartitionIdentity partition_;
};

bool InstallModel::confirmedRunningCounter(uint32_t& counter) {
  counter = 0;
  if (!floorReadable) return false;
  ReadOnlyAppModel reader(sdk, sdk.snapshot.running);
  FlashRegion image(reader, 0, Esp32OtaPolicy::kCandidateBytes);
  FlashRegion metadata(reader, Esp32OtaPolicy::kCandidateBytes, 8192);
  OtaCandidateStore running(metadata);
  uint32_t verified = 0;
  if (!verifyEsp32ConfirmedRunningCounter(sdk, running, image, policy, signatures,
                                         floorKnown, floor, verified)) return false;
  if (!finalFloorReadable || !floorKnown ||
      (finalFloor == UINT32_MAX ? floor : finalFloor) != verified) return false;
  counter = verified;
  return true;
}

class Esp32Product : public ::testing::Test {
protected:
  Esp32PartitionModel sdk;
  Esp32OtaLease lease;
  Esp32FlashAdapter flash{sdk, lease};
  FlashRegion candidate{flash, 0, Esp32OtaPolicy::kCandidateBytes};
  FlashRegion metadata{flash, Esp32OtaPolicy::kCandidateBytes, 8192};
  OtaCandidateStore store{metadata};
  Esp32OtaPolicy policy{0};
  Esp32OtaTrustProvider trust{policy, candidate};
  ::ota::trust::Ed25519SignatureVerifier signatures;
  InstallModel install{sdk, policy, signatures};
  Esp32OtaStagingSink sink{flash, lease, candidate, metadata, store, trust, policy, signatures, install};
  OtaFirmwareIntegration integration;
  uint8_t seed[32] = {0x17, 0x29, 0x53, 0x81};
  Ed25519TestSigner owner{seed};
  uint8_t target[32] = {0x82, 0x94, 0x51};
  std::vector<uint8_t> image = std::vector<uint8_t>(1024, 0x37);
  meshcore::ota::protocol::OtaDescriptor descriptor;
  uint8_t canonical[59] = {}, signature[64] = {};
  bool admin = true;

  void SetUp() override {
    image[0] = 0xe9;
    descriptor.boardFamily = Esp32OtaPolicy::kFamily;
    descriptor.boardVariant = Esp32OtaPolicy::kVariant;
    descriptor.role = policy.role;
    descriptor.appAddress = Esp32OtaPolicy::kAppAddress;
    descriptor.exactSizeBytes = static_cast<uint32_t>(image.size());
    descriptor.securityCounter = 1;
    descriptor.minBootloaderCapabilities = Esp32OtaPolicy::kCapabilities;
    descriptor.formatId = descriptor.keyId = descriptor.algorithmId = 1;
    ::ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
    signDescriptor();
    ASSERT_TRUE(lease.claimStorage());
    ASSERT_EQ(FlashStatus::Ok, flash.bind(Esp32OtaPolicy::kSlotBytes));
    attachTo(integration, sink);
  }
  void attachTo(OtaFirmwareIntegration& flow, Esp32OtaStagingSink& staging) {
    flow.attachTrustProvider(&trust);
    flow.attachLeanSignatureVerifier(&signatures);
    flow.attachStagingSink(&staging);
    flow.attachCandidateStore(&store);
    flow.setLeanTargetPublicKey(target);
    flow.setLeanAdminCheck(this, [](void* ctx, const uint8_t key[32]) {
      const auto* self = static_cast<Esp32Product*>(ctx);
      return self->admin && std::memcmp(key, self->owner.publicKey(), 32) == 0;
    });
  }
  OtaLeanReceiver& receiver() { return integration.leanReceiver(); }
  void signDescriptor() {
    size_t len = 0;
    ASSERT_EQ(meshcore::ota::protocol::OtaDescriptorCodecResult::Ok,
        meshcore::ota::protocol::encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), len));
    ASSERT_EQ(sizeof(canonical), len);
    owner.sign(canonical, sizeof(canonical), signature);
  }
  void begin() {
    ASSERT_EQ(Result::Ok, receiver().begin(owner.publicKey(), canonical, signature, false, false));
  }
  void receive() {
    receive(integration);
  }
  void receive(OtaFirmwareIntegration& flow) {
    for (size_t offset = 0; offset < image.size(); offset += kOtaBlockMaxDataBytes) {
      const size_t take = std::min(kOtaBlockMaxDataBytes, image.size() - offset);
      ASSERT_EQ(Result::Ok, flow.leanReceiver().putBlock(static_cast<uint16_t>(offset / kOtaBlockMaxDataBytes),
                                                       image.data() + offset, take));
    }
  }
  void ready(bool reupload = false) {
    ready(integration, reupload);
  }
  void ready(OtaFirmwareIntegration& flow, bool reupload = false) {
    ASSERT_EQ(Result::Ok, flow.leanReceiver().begin(owner.publicKey(), canonical, signature, reupload, false));
    ASSERT_FALSE(HasFatalFailure());
    receive(flow);
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_EQ(Result::Pending, flow.leanReceiver().requestSeal());
    flow.loop();
    OtaCandidateStore::Snapshot durable;
    ASSERT_TRUE(store.load(durable));
    ASSERT_EQ(OtaCandidateStore::Phase::Ready, durable.phase);
    ASSERT_EQ(OtaCandidateStore::Phase::Ready, flow.leanReceiver().status().phase);
  }
  Result commit() {
    return commit(integration);
  }
  Result commit(OtaFirmwareIntegration& flow) {
    uint8_t hash[32], message[usb::kCommitSignedBytes], commit_signature[64];
    computeOtaManifestHash(canonical, hash);
    const size_t len = usb::buildCommitSignedMessage(target, hash, descriptor.securityCounter, message);
    owner.sign(message, len, commit_signature);
    return flow.leanReceiver().commit(descriptor.securityCounter, commit_signature);
  }
  void successiveInstall(uint32_t counter) {
    image[1] = static_cast<uint8_t>(counter);
    descriptor.securityCounter = counter;
    ::ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
    signDescriptor();
    ASSERT_TRUE(lease.claimStorage());
    ASSERT_EQ(FlashStatus::Ok, flash.bind(Esp32OtaPolicy::kSlotBytes));
    Esp32OtaStagingSink cold_sink(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
    OtaCandidateStore::Snapshot previous;
    if (store.load(previous)) ASSERT_TRUE(cold_sink.recoverUnsuccessfulSelection());
    OtaFirmwareIntegration cold;
    attachTo(cold, cold_sink);
    ready(cold);
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_EQ(Result::Ok, commit(cold));
    ASSERT_EQ(InstallOutcome::Selected, cold_sink.activateDurableCommit());
    rebootIntoCandidate(Esp32ImageState::PendingVerify);
    OtaBootLifecycleEvidence trial_evidence;
    ASSERT_TRUE(lifecycle(false, 0, trial_evidence));
    ASSERT_TRUE(trial_evidence.imageVerified);
    ASSERT_EQ(usb::UsbOtaPhase::Trial, trial_evidence.phase);
    sdk.snapshot.appStates[sdk.snapshot.running.subtype - 0x10] = Esp32ImageState::Valid;
    policy.confirmedCounter = counter;
    install.floorKnown = true;
    install.floor = counter;
    OtaBootLifecycleEvidence installed;
    ASSERT_TRUE(lifecycle(true, counter, installed));
    ASSERT_EQ(usb::UsbOtaPhase::Installed, installed.phase);
    ASSERT_EQ(cold.leanReceiver().status().transactionNonce, installed.transactionNonce);
  }
  void twoSuccessfulInstalls() {
    const uint32_t baseline_metadata = sdk.snapshot.running.address + Esp32OtaPolicy::kCandidateBytes;
    std::fill(sdk.bytes.begin() + baseline_metadata, sdk.bytes.begin() + baseline_metadata + 8192, 0xff);
    successiveInstall(1);
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_EQ(0x340000u, sdk.snapshot.running.address);
    successiveInstall(2);
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_EQ(0x10000u, sdk.snapshot.running.address);
    ASSERT_EQ(FlashStatus::Ok, flash.bind(Esp32OtaPolicy::kSlotBytes));
  }
  void expectRecoveryRefusal(Esp32OtaStagingSink& recovery) {
    const auto before = sdk.bytes;
    const auto writes = sdk.writeCalls;
    const auto erases = sdk.erasedOffsets;
    const auto selections = install.selections;
    EXPECT_FALSE(recovery.recoverUnsuccessfulSelection());
    EXPECT_EQ(before, sdk.bytes);
    EXPECT_EQ(writes, sdk.writeCalls);
    EXPECT_EQ(erases, sdk.erasedOffsets);
    EXPECT_EQ(selections, install.selections);
  }
  void alterStoredProvenance(const Esp32PartitionIdentity& partition, uint32_t byte) {
    const uint32_t base = partition.address + Esp32OtaPolicy::kCandidateBytes;
    for (uint32_t slot = 0; slot < OtaCandidateStore::kRecordSlots; ++slot) {
      auto* record = sdk.bytes.data() + base + slot * OtaCandidateStore::kRecordBytes;
      if (record[0] == 0xff) continue;
      record[byte] ^= 1;
      const uint32_t crc = Crc32::computeFinalized(record, 184);
      for (uint32_t i = 0; i < 4; ++i) record[184 + i] = static_cast<uint8_t>(crc >> (8 * i));
    }
  }
  void expectWriteRevalidationRefusal(Esp32FlashAdapter::Refusal refusal) {
    const auto before = sdk.bytes;
    const auto writes = sdk.writeCalls;
    const auto erases = sdk.erasedOffsets;
    EXPECT_EQ(Result::IoError, receiver().putBlock(0, image.data(), kOtaBlockMaxDataBytes));
    EXPECT_EQ(refusal, flash.lastRefusal());
    EXPECT_EQ(before, sdk.bytes);
    EXPECT_EQ(writes, sdk.writeCalls);
    EXPECT_EQ(erases, sdk.erasedOffsets);
    // Bitmap revalidation may refuse before calling the staging sink.
    EXPECT_EQ(SinkResult::IoError, sink.writeChunk(0, image.data(), kOtaBlockMaxDataBytes));
    EXPECT_EQ(refusal, flash.lastRefusal());
    EXPECT_TRUE(sink.storageIoFaultObserved());
    EXPECT_EQ(before, sdk.bytes);
    EXPECT_EQ(writes, sdk.writeCalls);
    EXPECT_EQ(erases, sdk.erasedOffsets);
    EXPECT_EQ(0u, install.selections);
  }
  void rebootIntoCandidate(Esp32ImageState state) {
    const auto previous = sdk.snapshot.running;
    sdk.snapshot.running = sdk.snapshot.next;
    sdk.snapshot.next = previous;
    sdk.snapshot.boot = sdk.snapshot.running;
    sdk.snapshot.appStates[sdk.snapshot.running.subtype - 0x10] = state;
  }
  bool lifecycle(bool floor_known, uint32_t floor, OtaBootLifecycleEvidence& out,
                 bool failed_candidate = false) {
    const auto partition = failed_candidate ? sdk.snapshot.next : sdk.snapshot.running;
    ReadOnlyAppModel reader(sdk, partition);
    FlashRegion image_view(reader, 0, Esp32OtaPolicy::kCandidateBytes);
    FlashRegion metadata_view(reader, Esp32OtaPolicy::kCandidateBytes, 8192);
    OtaCandidateStore provenance(metadata_view);
    return readEsp32BootLifecycle(sdk.snapshot.appStates[partition.subtype - 0x10], provenance,
                                  image_view, policy, signatures, floor_known, floor, out, failed_candidate);
  }
  bool bootCandidate(const OtaBootLifecycleEvidence& expected, bool floor_known, uint32_t floor,
                     OtaCandidateStore::Snapshot& out) {
    const auto partition = expected.phase == usb::UsbOtaPhase::Failed ?
                           sdk.snapshot.next : sdk.snapshot.running;
    ReadOnlyAppModel reader(sdk, partition);
    FlashRegion metadata_view(reader, Esp32OtaPolicy::kCandidateBytes, 8192);
    OtaCandidateStore provenance(metadata_view);
    return readEsp32BootCandidate(expected, sdk.snapshot.appStates[partition.subtype - 0x10],
                                  provenance, policy, signatures, floor_known, floor, out);
  }
};

TEST_F(Esp32Product, ThreeSuccessiveInstallsReuseConfirmedInactiveSlotWithoutBusy) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  OtaCandidateStore::Snapshot old;
  ASSERT_TRUE(store.load(old));
  ASSERT_EQ(OtaCandidateStore::Phase::Committed, old.phase);
  ASSERT_EQ(1u, usb::getBE32(old.canonical + 45));
  uint8_t marker[4];
  ASSERT_EQ(FlashStatus::Ok, metadata.read(Esp32OtaStagingSink::kSelectionMarkerOffset, marker, sizeof(marker)));
  ASSERT_EQ(0, std::memcmp(marker, Esp32OtaStagingSink::kSelectionMarker, sizeof(marker)));
  successiveInstall(3);
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(3u, install.selections);
  EXPECT_EQ(3u, policy.confirmedCounter);
  EXPECT_EQ(0x340000u, sdk.snapshot.running.address);
}

TEST_F(Esp32Product, RetirementPreservesSignedIdentityAndBitmapWithoutErasingEitherImage) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  OtaCandidateStore::Snapshot original, retired;
  ASSERT_TRUE(store.load(original));
  const auto identity = OtaLeanReceiver::snapshotStatus(original);
  const auto before = sdk.bytes;
  const auto erases = sdk.erasedOffsets;
  Esp32OtaStagingSink recovery(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  ASSERT_TRUE(recovery.recoverUnsuccessfulSelection());
  ASSERT_TRUE(store.load(retired));
  EXPECT_EQ(OtaCandidateStore::Phase::Idle, retired.phase);
  EXPECT_EQ(original.sequence + 1, retired.sequence);
  EXPECT_EQ(0, std::memcmp(original.canonical, retired.canonical, sizeof(original.canonical)));
  EXPECT_EQ(0, std::memcmp(original.signature, retired.signature, sizeof(original.signature)));
  EXPECT_EQ(0, std::memcmp(original.ownerPublicKey, retired.ownerPublicKey, sizeof(original.ownerPublicKey)));
  EXPECT_EQ(identity.transactionNonce, OtaLeanReceiver::snapshotStatus(retired).transactionNonce);
  EXPECT_EQ(original.receivedBlocks, retired.receivedBlocks);
  EXPECT_EQ(erases, sdk.erasedOffsets);
  const uint32_t new_record = sdk.snapshot.next.address + Esp32OtaPolicy::kCandidateBytes +
                             original.sequence * OtaCandidateStore::kRecordBytes;
  EXPECT_TRUE(std::equal(before.begin(), before.begin() + new_record, sdk.bytes.begin()));
  EXPECT_TRUE(std::equal(before.begin() + new_record + OtaCandidateStore::kRecordBytes, before.end(),
                        sdk.bytes.begin() + new_record + OtaCandidateStore::kRecordBytes));
  const auto writes = sdk.writeCalls;
  ASSERT_TRUE(recovery.recoverUnsuccessfulSelection());
  EXPECT_EQ(writes, sdk.writeCalls);
  EXPECT_EQ(2u, install.selections);
}

TEST_F(Esp32Product, RetirementAlsoHandlesPreviouslyMisclassifiedFloorCoveredFailedRecord) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  OtaCandidateStore::Snapshot previous;
  ASSERT_TRUE(store.load(previous));
  previous.phase = OtaCandidateStore::Phase::Failed;
  ASSERT_TRUE(store.append(previous));
  Esp32OtaStagingSink recovery(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  ASSERT_TRUE(recovery.recoverUnsuccessfulSelection());
  ASSERT_TRUE(store.load(previous));
  EXPECT_EQ(OtaCandidateStore::Phase::Idle, previous.phase);
  successiveInstall(3);
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(3u, install.selections);
}

TEST_F(Esp32Product, RetirementRequiresKnownReadableUnchangedExactConfirmedFloor) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  Esp32OtaStagingSink recovery(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  install.floorKnown = false;
  expectRecoveryRefusal(recovery);
  install.floorKnown = true;
  install.floorReadable = false;
  expectRecoveryRefusal(recovery);
  install.floorReadable = true;
  install.finalFloorReadable = false;
  expectRecoveryRefusal(recovery);
  install.finalFloorReadable = true;
  for (const uint32_t floor : {0u, 1u, 3u}) {
    install.floor = floor;
    expectRecoveryRefusal(recovery);
  }
  install.floor = 2;
  install.finalFloor = 3;
  expectRecoveryRefusal(recovery);
  install.finalFloor = UINT32_MAX;
  policy.confirmedCounter = 1;
  expectRecoveryRefusal(recovery);
  policy.confirmedCounter = 2;
  ASSERT_TRUE(recovery.recoverUnsuccessfulSelection());
}

TEST_F(Esp32Product, RetirementRefusesRunningInactiveReadAndSdkInspectionErrors) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  Esp32OtaStagingSink recovery(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  sdk.readError = -1;
  expectRecoveryRefusal(recovery);
  sdk.readError = kEsp32Ok;
  sdk.readErrorPartition = sdk.snapshot.running.address;
  expectRecoveryRefusal(recovery);
  sdk.readErrorPartition = sdk.snapshot.next.address;
  expectRecoveryRefusal(recovery);
  sdk.readErrorPartition = 0;
  sdk.inspectError = -1;
  expectRecoveryRefusal(recovery);
  sdk.inspectError = kEsp32Ok;
  ASSERT_TRUE(recovery.recoverUnsuccessfulSelection());
}

TEST_F(Esp32Product, RetirementRefusesPendingUnknownInvalidRunningAndChangedBootState) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  Esp32OtaStagingSink recovery(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  const auto stable = sdk.snapshot;
  for (size_t slot = 0; slot < 2; ++slot) {
    for (const auto state : {Esp32ImageState::New, Esp32ImageState::PendingVerify,
                             static_cast<Esp32ImageState>(0x7f)}) {
      sdk.snapshot.appStates[slot] = state;
      expectRecoveryRefusal(recovery);
      sdk.snapshot = stable;
    }
  }
  for (const auto state : {Esp32ImageState::Undefined, Esp32ImageState::Invalid, Esp32ImageState::Aborted}) {
    sdk.snapshot.appStates[0] = state;
    expectRecoveryRefusal(recovery);
    sdk.snapshot = stable;
  }
  sdk.snapshot.boot = sdk.snapshot.next;
  expectRecoveryRefusal(recovery);
  sdk.snapshot = stable;
  ASSERT_TRUE(recovery.recoverUnsuccessfulSelection());
}

TEST_F(Esp32Product, ConfirmedRunningProofRechecksSdkAfterHashAndZerosOutputOnFailure) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  ReadOnlyAppModel reader(sdk, sdk.snapshot.running);
  FlashRegion running_image(reader, 0, Esp32OtaPolicy::kCandidateBytes);
  FlashRegion running_metadata(reader, Esp32OtaPolicy::kCandidateBytes, 8192);
  OtaCandidateStore running(running_metadata);
  uint32_t counter = 99;
  sdk.inspectErrorCall = sdk.inspectCalls + 2;
  EXPECT_FALSE(verifyEsp32ConfirmedRunningCounter(sdk, running, running_image, policy, signatures,
                                                true, 2, counter));
  EXPECT_EQ(0u, counter);
  sdk.inspectErrorCall = 0;
  ASSERT_TRUE(verifyEsp32ConfirmedRunningCounter(sdk, running, running_image, policy, signatures,
                                               true, 2, counter));
  EXPECT_EQ(2u, counter);
}

TEST_F(Esp32Product, RetirementRehashesRunningImageAndVerifiesBothOriginalSignatures) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  const auto original = sdk.bytes;
  Esp32OtaStagingSink recovery(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  sdk.bytes[sdk.snapshot.running.address + 7] ^= 1;
  expectRecoveryRefusal(recovery);
  sdk.bytes = original;
  alterStoredProvenance(sdk.snapshot.running, 120);
  expectRecoveryRefusal(recovery);
  sdk.bytes = original;
  alterStoredProvenance(sdk.snapshot.next, 120);
  expectRecoveryRefusal(recovery);
  sdk.bytes = original;
  alterStoredProvenance(sdk.snapshot.next, 88);
  expectRecoveryRefusal(recovery);
  sdk.bytes = original;
  ASSERT_TRUE(recovery.recoverUnsuccessfulSelection());
}

TEST_F(Esp32Product, RetirementNeverRelaxesIncompleteSelectionMarkerActivePhaseOrLocalCache) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  const auto original = sdk.bytes;
  Esp32OtaStagingSink recovery(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  const uint32_t marker = sdk.snapshot.next.address + Esp32OtaPolicy::kCandidateBytes +
                          Esp32OtaStagingSink::kSelectionMarkerOffset;
  std::fill(sdk.bytes.begin() + marker, sdk.bytes.begin() + marker + 4, 0xff);
  expectRecoveryRefusal(recovery);
  sdk.bytes[marker] = Esp32OtaStagingSink::kSelectionMarker[0];
  expectRecoveryRefusal(recovery);
  sdk.bytes = original;
  OtaCandidateStore::Snapshot snapshot;
  ASSERT_TRUE(store.load(snapshot));
  snapshot.localCache = true;
  ASSERT_TRUE(store.append(snapshot));
  expectRecoveryRefusal(recovery);
  snapshot.phase = OtaCandidateStore::Phase::Failed;
  ASSERT_TRUE(store.append(snapshot));
  const auto failed_cache = sdk.bytes;
  const auto cache_writes = sdk.writeCalls;
  ASSERT_TRUE(recovery.recoverUnsuccessfulSelection());
  EXPECT_EQ(failed_cache, sdk.bytes);
  EXPECT_EQ(cache_writes, sdk.writeCalls);
  ASSERT_TRUE(store.load(snapshot));
  EXPECT_TRUE(snapshot.localCache);
  EXPECT_EQ(OtaCandidateStore::Phase::Failed, snapshot.phase);
  for (const auto phase : {OtaCandidateStore::Phase::Receiving, OtaCandidateStore::Phase::Verifying,
                           OtaCandidateStore::Phase::Ready, OtaCandidateStore::Phase::Aborted}) {
    sdk.bytes = original;
    ASSERT_TRUE(store.load(snapshot));
    snapshot.phase = phase;
    ASSERT_TRUE(store.append(snapshot));
    const auto before = sdk.bytes;
    const auto writes = sdk.writeCalls;
    ASSERT_TRUE(recovery.recoverUnsuccessfulSelection());
    EXPECT_EQ(before, sdk.bytes);
    EXPECT_EQ(writes, sdk.writeCalls);
  }
}

TEST_F(Esp32Product, InterruptedRetirementRemainsRecoverableWithoutErasingOrSelecting) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  const auto original = sdk.bytes;
  const auto erases = sdk.erasedOffsets;
  for (const auto timing : {FaultTiming::Before, FaultTiming::Torn, FaultTiming::After}) {
    sdk.bytes = original;
    Esp32OtaStagingSink recovery(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
    sdk.writeFault = timing;
    sdk.tornBytes = 2;
    sdk.writeErrorCall = sdk.writeCalls + 2;  // The appended Idle record's commit marker.
    EXPECT_FALSE(recovery.recoverUnsuccessfulSelection());
    EXPECT_EQ(erases, sdk.erasedOffsets);
    EXPECT_EQ(2u, install.selections);
    sdk.writeFault = FaultTiming::None;
    sdk.writeErrorCall = 0;
    Esp32OtaStagingSink rebooted(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
    ASSERT_TRUE(rebooted.recoverUnsuccessfulSelection());
    OtaCandidateStore::Snapshot retired;
    ASSERT_TRUE(store.load(retired));
    EXPECT_EQ(OtaCandidateStore::Phase::Idle, retired.phase);
    EXPECT_EQ(InstallOutcome::None, rebooted.activateDurableCommit());
    EXPECT_EQ(2u, install.selections);
  }
}

TEST_F(Esp32Product, NewerRolledBackTrialIsNotRetiredAndAuthenticatedRetryCanInstall) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  Esp32OtaStagingSink third(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  ASSERT_TRUE(third.recoverUnsuccessfulSelection());
  image[1] = 3;
  descriptor.securityCounter = 3;
  ::ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
  signDescriptor();
  OtaFirmwareIntegration receiving;
  attachTo(receiving, third);
  ready(receiving);
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit(receiving));
  const auto attempted = receiving.leanReceiver().status();
  ASSERT_EQ(InstallOutcome::Selected, third.activateDurableCommit());
  const auto previous = sdk.snapshot.running;
  rebootIntoCandidate(Esp32ImageState::PendingVerify);
  const auto failed = sdk.snapshot.running;
  sdk.snapshot.running = previous;
  sdk.snapshot.next = failed;
  sdk.snapshot.boot = previous;
  sdk.snapshot.appStates[failed.subtype - 0x10] = Esp32ImageState::Aborted;
  ASSERT_EQ(FlashStatus::Ok, flash.bind(Esp32OtaPolicy::kSlotBytes));
  Esp32OtaStagingSink rollback(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  ASSERT_TRUE(rollback.recoverUnsuccessfulSelection());
  OtaCandidateStore::Snapshot record;
  ASSERT_TRUE(store.load(record));
  ASSERT_EQ(OtaCandidateStore::Phase::Failed, record.phase);
  EXPECT_EQ(attempted.transactionNonce, OtaLeanReceiver::snapshotStatus(record).transactionNonce);
  EXPECT_EQ(0, std::memcmp(signature, record.signature, sizeof(signature)));
  EXPECT_EQ(0, std::memcmp(canonical, record.canonical, sizeof(canonical)));
  EXPECT_EQ(2u, install.floor);
  EXPECT_EQ(InstallOutcome::None, rollback.activateDurableCommit());
  OtaFirmwareIntegration retry;
  attachTo(retry, rollback);
  const auto writes = sdk.writeCalls;
  const auto erases = sdk.erasedOffsets;
  admin = false;
  EXPECT_EQ(Result::Denied, retry.leanReceiver().begin(owner.publicKey(), canonical, signature, true, false));
  admin = true;
  uint8_t bad_signature[64];
  std::memcpy(bad_signature, signature, sizeof(signature));
  bad_signature[0] ^= 1;
  EXPECT_EQ(Result::Denied, retry.leanReceiver().begin(owner.publicKey(), canonical, bad_signature, true, false));
  EXPECT_EQ(writes, sdk.writeCalls);
  EXPECT_EQ(erases, sdk.erasedOffsets);
  ready(retry, true);
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit(retry));
  EXPECT_EQ(InstallOutcome::Selected, rollback.activateDurableCommit());
  EXPECT_EQ(4u, install.selections);
}

TEST_F(Esp32Product, CandidateProjectionReadsRunningRecordWithoutMutatingReceiverOrFlash) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  const auto expected = receiver().status();
  rebootIntoCandidate(Esp32ImageState::PendingVerify);
  const auto before = sdk.bytes;
  const auto writes = sdk.writeCalls;
  const auto erases = sdk.erasedOffsets;
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(false, 0, boot));
  OtaCandidateStore::Snapshot snapshot;
  OtaFirmwareIntegration cold;
  ASSERT_TRUE(bootCandidate(boot, false, 0, snapshot));
  EXPECT_TRUE(snapshot.valid);
  EXPECT_EQ(OtaCandidateStore::Phase::Committed, snapshot.phase);
  EXPECT_EQ(0, std::memcmp(canonical, snapshot.canonical, sizeof(canonical)));
  EXPECT_EQ(0, std::memcmp(signature, snapshot.signature, sizeof(signature)));
  EXPECT_EQ(expected.transactionNonce, boot.transactionNonce);
  EXPECT_FALSE(cold.leanReceiver().status().valid);
  EXPECT_EQ(before, sdk.bytes);
  EXPECT_EQ(writes, sdk.writeCalls);
  EXPECT_EQ(erases, sdk.erasedOffsets);
}

TEST_F(Esp32Product, CandidateProjectionRejectsMismatchedNonceCounterHashAndUnverifiedEvidence) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  rebootIntoCandidate(Esp32ImageState::PendingVerify);
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(false, 0, boot));
  OtaCandidateStore::Snapshot snapshot;
  ASSERT_TRUE(bootCandidate(boot, false, 0, snapshot));
  auto altered = boot;
  altered.transactionNonce ^= 1;
  EXPECT_FALSE(bootCandidate(altered, false, 0, snapshot));
  EXPECT_FALSE(snapshot.valid);
  altered = boot;
  ++altered.counter;
  EXPECT_FALSE(bootCandidate(altered, false, 0, snapshot));
  altered = boot;
  altered.imageHash[0] ^= 1;
  EXPECT_FALSE(bootCandidate(altered, false, 0, snapshot));
  altered = boot;
  altered.imageVerified = false;
  EXPECT_FALSE(bootCandidate(altered, false, 0, snapshot));
}

TEST_F(Esp32Product, CandidateProjectionRechecksSdkStateAndDurableFloorAfterImageProof) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  rebootIntoCandidate(Esp32ImageState::Valid);
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter, boot));
  OtaCandidateStore::Snapshot snapshot;
  ASSERT_TRUE(bootCandidate(boot, true, descriptor.securityCounter, snapshot));
  EXPECT_FALSE(bootCandidate(boot, false, descriptor.securityCounter, snapshot));
  EXPECT_FALSE(snapshot.valid);
  EXPECT_FALSE(bootCandidate(boot, true, descriptor.securityCounter + 1, snapshot));
  sdk.snapshot.appStates[sdk.snapshot.running.subtype - 0x10] = Esp32ImageState::PendingVerify;
  EXPECT_FALSE(bootCandidate(boot, true, descriptor.securityCounter, snapshot));
}

TEST_F(Esp32Product, CandidateProjectionRefusesReadFaultAndChangedProvenance) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  rebootIntoCandidate(Esp32ImageState::Valid);
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter, boot));
  OtaCandidateStore::Snapshot snapshot;
  sdk.readError = -1;
  EXPECT_FALSE(bootCandidate(boot, true, descriptor.securityCounter, snapshot));
  EXPECT_FALSE(snapshot.valid);
  sdk.readError = kEsp32Ok;
  const uint32_t metadata_start = sdk.snapshot.running.address + Esp32OtaPolicy::kCandidateBytes;
  for (uint32_t slot = 0; slot < OtaCandidateStore::kRecordSlots; ++slot)
    sdk.bytes[metadata_start + slot * OtaCandidateStore::kRecordBytes + 120] ^= 1;
  EXPECT_FALSE(bootCandidate(boot, true, descriptor.securityCounter, snapshot));
  EXPECT_FALSE(snapshot.valid);
}

TEST_F(Esp32Product, LifecycleNeverTreatsCommitAcknowledgementAsInstallation) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  EXPECT_FALSE(boot.imageVerified);
  EXPECT_EQ(0u, boot.transactionNonce);
}

TEST_F(Esp32Product, LifecycleReportsSdkTrialWithoutInventingImageOrFloorProof) {
  sdk.snapshot.appStates[sdk.snapshot.running.subtype - 0x10] = Esp32ImageState::PendingVerify;
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(false, 999, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Trial, boot.phase);
  EXPECT_FALSE(boot.imageVerified);
  EXPECT_FALSE(boot.floorKnown);
  EXPECT_EQ(0u, boot.counter);
  EXPECT_EQ(0u, boot.transactionNonce);
}

TEST_F(Esp32Product, LifecycleTrialBindsActualRunningHashCounterAndSessionNonce) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  const auto expected = receiver().status();
  rebootIntoCandidate(Esp32ImageState::PendingVerify);
  const auto before = sdk.bytes;
  const auto writes = sdk.writeCalls;
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(false, 999, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Trial, boot.phase);
  EXPECT_TRUE(boot.imageVerified);
  EXPECT_FALSE(boot.floorKnown);
  EXPECT_EQ(0u, boot.confirmedFloor);
  EXPECT_EQ(expected.counter, boot.counter);
  EXPECT_EQ(expected.transactionNonce, boot.transactionNonce);
  EXPECT_EQ(0, std::memcmp(expected.imageHash, boot.imageHash, 32));
  EXPECT_EQ(before, sdk.bytes);
  EXPECT_EQ(writes, sdk.writeCalls);
}

TEST_F(Esp32Product, LifecycleInstalledRequiresFreshValidStateAndExactDurableFloor) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  rebootIntoCandidate(Esp32ImageState::Valid);
  policy.confirmedCounter = 999;
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(false, 999, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  ASSERT_TRUE(lifecycle(true, 0, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter + 1, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Installed, boot.phase);
  EXPECT_TRUE(boot.imageVerified);
  EXPECT_EQ(descriptor.securityCounter, boot.confirmedFloor);
  sdk.snapshot.appStates[sdk.snapshot.running.subtype - 0x10] = Esp32ImageState::PendingVerify;
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Trial, boot.phase);
  sdk.snapshot.appStates[sdk.snapshot.running.subtype - 0x10] = Esp32ImageState::Valid;
  policy.role = 1;
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  EXPECT_FALSE(boot.imageVerified);
}

TEST_F(Esp32Product, LifecycleRehashesRunningBytesAndDoesNotReusePreviousSuccess) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  rebootIntoCandidate(Esp32ImageState::Valid);
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter, boot));
  ASSERT_EQ(usb::UsbOtaPhase::Installed, boot.phase);
  sdk.bytes[sdk.snapshot.running.address + 500] ^= 1;
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  EXPECT_FALSE(boot.imageVerified);
  EXPECT_EQ(0u, boot.transactionNonce);
}

TEST_F(Esp32Product, LifecycleRejectsUnsignedRunningProvenance) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  OtaCandidateStore::Snapshot snapshot;
  ASSERT_TRUE(store.load(snapshot));
  snapshot.signature[0] ^= 1;
  ASSERT_TRUE(store.append(snapshot));
  rebootIntoCandidate(Esp32ImageState::Valid);
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter, boot));
  EXPECT_FALSE(boot.imageVerified);
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
}

TEST_F(Esp32Product, LifecycleRejectsCacheOnlyRunningProvenance) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  OtaCandidateStore::Snapshot snapshot;
  ASSERT_TRUE(store.load(snapshot));
  snapshot.localCache = true;
  ASSERT_TRUE(store.append(snapshot));
  rebootIntoCandidate(Esp32ImageState::Valid);
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter, boot));
  EXPECT_FALSE(boot.imageVerified);
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  EXPECT_EQ(0u, boot.transactionNonce);
}

TEST_F(Esp32Product, LifecycleRefusesReadErrorsAndUnknownSdkStatesWithoutStaleEvidence) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  rebootIntoCandidate(Esp32ImageState::Valid);
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter, boot));
  sdk.readError = -1;
  ASSERT_TRUE(lifecycle(true, descriptor.securityCounter, boot));
  EXPECT_FALSE(boot.imageVerified);
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  sdk.readError = kEsp32Ok;
  sdk.snapshot.appStates[sdk.snapshot.running.subtype - 0x10] = Esp32ImageState::New;
  EXPECT_FALSE(lifecycle(true, descriptor.securityCounter, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  EXPECT_FALSE(boot.floorKnown);
}

TEST_F(Esp32Product, LifecycleFailedAttemptIsBoundButNeverProofOfRunningImage) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  ASSERT_EQ(InstallOutcome::Selected, sink.activateDurableCommit());
  sdk.snapshot.boot = sdk.snapshot.running;
  sdk.snapshot.appStates[1] = Esp32ImageState::Aborted;
  Esp32OtaStagingSink rollback(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  ASSERT_TRUE(rollback.recoverUnsuccessfulSelection());
  receiver().restore();
  const auto expected = receiver().status();
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(false, 0, boot, true));
  EXPECT_EQ(usb::UsbOtaPhase::Failed, boot.phase);
  EXPECT_EQ(expected.transactionNonce, boot.transactionNonce);
  EXPECT_EQ(expected.counter, boot.counter);
  EXPECT_FALSE(boot.imageVerified);
  sdk.snapshot.appStates[1] = Esp32ImageState::Valid;
  EXPECT_FALSE(lifecycle(false, 0, boot, true));
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
}

TEST_F(Esp32Product, EveryModeStopsAtDurableReadyUntilIndividualCommit) {
  const FirmwareOtaMode modes[] = {FirmwareOtaMode::Direct, FirmwareOtaMode::Routed, FirmwareOtaMode::Fleet};
  bool reupload = false;
  for (const auto mode : modes) {
    integration.setMode(mode);
    ready(reupload);
    reupload = true;
    ASSERT_FALSE(HasFatalFailure());
    EXPECT_EQ(InstallOutcome::None, sink.activateDurableCommit());
    EXPECT_EQ(0u, install.selections);
    EXPECT_TRUE(esp32PartitionEquals(sdk.snapshot.boot, sdk.snapshot.running));
  }
  ASSERT_EQ(Result::Ok, commit());
  EXPECT_EQ(0u, install.selections);
  OtaCandidateStore::Snapshot durable;
  ASSERT_TRUE(store.load(durable));
  ASSERT_EQ(OtaCandidateStore::Phase::Committed, durable.phase);
  EXPECT_EQ(InstallOutcome::Selected, sink.activateDurableCommit());
  EXPECT_EQ(1u, install.selections);
  EXPECT_TRUE(esp32PartitionEquals(sdk.snapshot.boot, sdk.snapshot.next));
  EXPECT_EQ(Esp32ImageState::New, sdk.snapshot.appStates[1]);
  EXPECT_EQ(InstallOutcome::None, sink.activateDurableCommit());
}

TEST_F(Esp32Product, NeverTouchesRunningAppFilesystemNvsOrOtaDataDuringStaging) {
  const auto before = sdk.bytes;
  ready();
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(0, std::memcmp(before.data(), sdk.bytes.data(), sdk.snapshot.next.address));
  const uint32_t after = sdk.snapshot.next.address + sdk.snapshot.next.size;
  EXPECT_EQ(0, std::memcmp(before.data() + after, sdk.bytes.data() + after, before.size() - after));
}

TEST_F(Esp32Product, RequiresLiveExistingAdministratorAtAdmission) {
  admin = false;
  const auto before = sdk.bytes;
  EXPECT_EQ(Result::Denied, receiver().begin(owner.publicKey(), canonical, signature, false, false));
  EXPECT_EQ(before, sdk.bytes);
  EXPECT_EQ(0u, install.selections);
}

TEST_F(Esp32Product, RevokedAdministratorCannotCommitAReadyCandidate) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  admin = false;
  EXPECT_EQ(Result::Denied, commit());
  EXPECT_EQ(InstallOutcome::None, sink.activateDurableCommit());
}

TEST_F(Esp32Product, ForeignRoleCacheCanReachReadyButNeverInstallLocally) {
  descriptor.boardFamily = 0x5849;
  descriptor.boardVariant = 0x414f;
  descriptor.role = 1;
  descriptor.appAddress = 0x27000;
  const uint8_t cortex_vectors[] = {0x00, 0x00, 0x02, 0x20, 0x11, 0x70, 0x02, 0x00};
  std::memcpy(image.data(), cortex_vectors, sizeof(cortex_vectors));
  ::ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
  policy.confirmedCounter = descriptor.securityCounter;
  install.imageValid = false;
  signDescriptor();
  ASSERT_EQ(Result::Ok, receiver().begin(owner.publicKey(), canonical, signature, false, false, true));
  ASSERT_EQ(Result::Ok, receiver().putBlock(0, image.data(), kOtaBlockMaxDataBytes));
  Esp32OtaStagingSink cached(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  OtaFirmwareIntegration rebooted;
  attachTo(rebooted, cached);
  auto& resumed = rebooted.leanReceiver();
  ASSERT_TRUE(resumed.status().localCache);
  ASSERT_EQ(1u, resumed.status().receivedBlocks);
  ASSERT_EQ(Result::Ok, resumed.begin(owner.publicKey(), canonical, signature, false, false, true));
  for (size_t offset = 0; offset < image.size(); offset += kOtaBlockMaxDataBytes) {
    const size_t take = std::min(kOtaBlockMaxDataBytes, image.size() - offset);
    ASSERT_EQ(Result::Ok, resumed.putBlock(static_cast<uint16_t>(offset / kOtaBlockMaxDataBytes),
                                          image.data() + offset, take));
  }
  ASSERT_EQ(Result::Pending, resumed.requestSeal());
  rebooted.loop();
  OtaCandidateStore::Snapshot durable;
  ASSERT_TRUE(store.load(durable));
  ASSERT_TRUE(durable.localCache);
  ASSERT_EQ(OtaCandidateStore::Phase::Ready, durable.phase);
  std::vector<uint8_t> readback(image.size());
  for (size_t offset = 0; offset < image.size(); offset += kOtaBlockMaxDataBytes) {
    const size_t take = std::min(kOtaBlockMaxDataBytes, image.size() - offset);
    ASSERT_EQ(SinkResult::Ok, cached.readChunk(offset, readback.data() + offset, take));
  }
  EXPECT_EQ(image, readback);
  uint8_t hash[32], message[usb::kCommitSignedBytes], sig[64];
  computeOtaManifestHash(canonical, hash);
  const size_t len = usb::buildCommitSignedMessage(target, hash, descriptor.securityCounter, message);
  owner.sign(message, len, sig);
  EXPECT_EQ(Result::Denied, resumed.commit(descriptor.securityCounter, sig));
  cached.onAdmittedOwnerIdentity(owner.publicKey());
  EXPECT_EQ(SinkResult::Rejected, cached.commit());
  EXPECT_EQ(InstallOutcome::None, cached.activateDurableCommit());
  EXPECT_EQ(0u, install.imageChecks);
  EXPECT_EQ(0u, install.selections);
  EXPECT_TRUE(esp32PartitionEquals(sdk.snapshot.boot, sdk.snapshot.running));
}

TEST(Esp32ProductPolicy, SizeAndRoleLimitsAreDerivedFromActualSlotAndBitmap) {
  Esp32OtaPolicy companion{0}, repeater{1};
  EXPECT_EQ(0x32e000u, Esp32OtaPolicy::kCandidateBytes);
  EXPECT_EQ(2749824u, Esp32OtaPolicy::kMaxImageBytes);
  meshcore::ota::protocol::OtaDescriptor d;
  d.boardFamily = Esp32OtaPolicy::kFamily;
  d.boardVariant = Esp32OtaPolicy::kVariant;
  d.appAddress = Esp32OtaPolicy::kAppAddress;
  d.exactSizeBytes = 697248;  // real role-0 target .bin, not just a tiny fixture
  d.securityCounter = 2;
  d.formatId = d.keyId = d.algorithmId = 1;
  d.minBootloaderCapabilities = 1;
  EXPECT_TRUE(companion.accepts(d));
  EXPECT_FALSE(repeater.accepts(d));
  d.role = 1;
  EXPECT_TRUE(repeater.accepts(d));
  repeater.confirmedCounter = 2;
  EXPECT_FALSE(repeater.accepts(d));
  d.securityCounter = 3;
  d.exactSizeBytes = Esp32OtaPolicy::kMaxImageBytes;
  EXPECT_TRUE(repeater.accepts(d));
  ++d.exactSizeBytes;
  EXPECT_FALSE(repeater.accepts(d));
}

TEST_F(Esp32Product, RefusesWrongRoleBoardAddressCapabilitiesAndCounterBeforeErase) {
  const auto original = descriptor;
  for (int field = 0; field < 10; ++field) {
    descriptor = original;
    switch (field) {
      case 0: ++descriptor.role; break;
      case 1: ++descriptor.boardFamily; break;
      case 2: ++descriptor.boardVariant; break;
      case 3: descriptor.appAddress = sdk.snapshot.next.address; break;
      case 4: descriptor.minBootloaderCapabilities = 0; break;
      case 5: descriptor.minBootloaderCapabilities = 3; break;
      case 6: descriptor.securityCounter = 0; break;
      case 7: descriptor.algorithmId = 2; break;
      case 8: descriptor.keyId = 0; break;
      case 9: descriptor.exactSizeBytes = Esp32OtaPolicy::kMaxImageBytes + 1; break;
    }
    signDescriptor();
    const auto before = sdk.bytes;
    EXPECT_EQ(Result::Denied, receiver().begin(owner.publicKey(), canonical, signature, false, false));
    EXPECT_EQ(before, sdk.bytes);
  }
}

TEST_F(Esp32Product, UsesOppositeSdkSlotWhenRunningAppOne) {
  sdk = Esp32PartitionModel(true);
  ASSERT_EQ(FlashStatus::Ok, flash.bind(Esp32OtaPolicy::kSlotBytes));
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  ASSERT_EQ(InstallOutcome::Selected, sink.activateDurableCommit());
  EXPECT_EQ(0x10000u, sdk.snapshot.boot.address);
  EXPECT_EQ(Esp32ImageState::New, sdk.snapshot.appStates[0]);
}

TEST_F(Esp32Product, OrdinaryUpdaterCannotTakeCandidateOrReadyLease) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_FALSE(lease.claimOrdinaryUpdater());
  EXPECT_EQ(SinkResult::Rejected, sink.writeChunk(UINT64_MAX, image.data(), 1));
}

TEST_F(Esp32Product, ExistingOrdinaryUpdaterExcludesLeanErase) {
  lease.releaseStorage();
  ASSERT_TRUE(lease.claimOrdinaryUpdater());
  const auto before = sdk.bytes;
  EXPECT_EQ(Result::Busy, receiver().begin(owner.publicKey(), canonical, signature, false, false));
  EXPECT_EQ(before, sdk.bytes);
  lease.releaseOrdinaryUpdater();
  EXPECT_EQ(Result::Ok, receiver().begin(owner.publicKey(), canonical, signature, false, false));
}

TEST_F(Esp32Product, OrdinaryLeaseHandoffIsAtomicAndCannotStealReadyOwnership) {
  EXPECT_FALSE(lease.claimFreshStorage());
  lease.releaseStorage();
  ASSERT_TRUE(lease.claimFreshStorage());
  ASSERT_TRUE(lease.handoffToOrdinaryUpdater());
  EXPECT_FALSE(lease.claimStorage());
  EXPECT_FALSE(lease.claimFreshStorage());
  EXPECT_FALSE(lease.claimOrdinaryUpdater());
  lease.releaseOrdinaryUpdater();
  EXPECT_TRUE(lease.claimFreshStorage());
}

TEST_F(Esp32Product, RechecksPartitionBootAndTrialStateOnEveryWrite) {
  begin();
  ASSERT_FALSE(HasFatalFailure());
  sdk.snapshot.boot = sdk.snapshot.next;
  expectWriteRevalidationRefusal(Esp32FlashAdapter::Refusal::BootSelection);
}

TEST_F(Esp32Product, ChangedPartitionTableRefusesAlreadyAdmittedWrites) {
  begin();
  ASSERT_FALSE(HasFatalFailure());
  --sdk.snapshot.table[5].size;
  expectWriteRevalidationRefusal(Esp32FlashAdapter::Refusal::Table);
}

TEST_F(Esp32Product, ChangedSdkDestinationRefusesAlreadyAdmittedWrites) {
  begin();
  ASSERT_FALSE(HasFatalFailure());
  const auto inactive = sdk.snapshot.next;
  sdk.snapshot.next = sdk.snapshot.running;
  expectWriteRevalidationRefusal(Esp32FlashAdapter::Refusal::Running);
  sdk.snapshot.next = inactive;
  sdk.snapshot.next.label[0] ^= 1;
  expectWriteRevalidationRefusal(Esp32FlashAdapter::Refusal::Partition);
}

TEST_F(Esp32Product, ChangedTrialStateInEitherSlotRefusesAlreadyAdmittedWrites) {
  begin();
  ASSERT_FALSE(HasFatalFailure());
  for (size_t app = 0; app < 2; ++app) {
    for (const auto state : {Esp32ImageState::New, Esp32ImageState::PendingVerify}) {
      SCOPED_TRACE(app);
      SCOPED_TRACE(static_cast<unsigned>(state));
      sdk.snapshot.appStates[app] = state;
      expectWriteRevalidationRefusal(Esp32FlashAdapter::Refusal::Trial);
    }
    sdk.snapshot.appStates[app] = Esp32ImageState::Valid;
  }
}

TEST_F(Esp32Product, PendingTrialRefusesAdmissionWithoutAnErase) {
  sdk.snapshot.appStates[0] = Esp32ImageState::PendingVerify;
  const auto before = sdk.bytes;
  EXPECT_EQ(Result::IoError, receiver().begin(owner.publicKey(), canonical, signature, false, false));
  EXPECT_EQ(before, sdk.bytes);
}

TEST_F(Esp32Product, RefusesMalformedSdkImageEvenWithMatchingWholeHash) {
  image[0] = 0x12;
  ::ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
  signDescriptor();
  ready();
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(Result::Denied, commit());
  EXPECT_EQ(0u, install.selections);
  EXPECT_TRUE(esp32PartitionEquals(sdk.snapshot.boot, sdk.snapshot.running));
}

TEST_F(Esp32Product, RehashesWholeImageAgainAtCommitAndSelection) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  sdk.bytes[sdk.snapshot.next.address + 500] ^= 1;
  EXPECT_EQ(Result::Denied, commit());
  EXPECT_EQ(0u, install.selections);
}

TEST_F(Esp32Product, RehashesBetweenDurableCommitAndVendorSelection) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  sdk.bytes[sdk.snapshot.next.address + 501] ^= 1;
  EXPECT_EQ(InstallOutcome::Refused, sink.activateDurableCommit());
  EXPECT_EQ(0u, install.selections);
}

TEST_F(Esp32Product, AuthenticatedCommitDoesNotSelectWithoutDurableCommittedRecord) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  sink.onAdmittedOwnerIdentity(owner.publicKey());
  ASSERT_EQ(SinkResult::Ok, sink.commit());
  EXPECT_EQ(InstallOutcome::None, sink.activateDurableCommit());
  EXPECT_EQ(0u, install.selections);
  EXPECT_EQ(SinkResult::Rejected, sink.writeChunk(0, image.data(), 1));
}

TEST_F(Esp32Product, FailedReadyAppendCannotReportReadyAndRetriesDurably) {
  begin();
  receive();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Pending, receiver().requestSeal());
  sdk.writeFault = FaultTiming::Before;
  integration.loop();
  EXPECT_EQ(OtaCandidateStore::Phase::Verifying, receiver().status().phase);
  OtaCandidateStore::Snapshot durable;
  ASSERT_TRUE(store.load(durable));
  EXPECT_EQ(OtaCandidateStore::Phase::Verifying, durable.phase);
  EXPECT_EQ(Result::TooLate, commit());
  EXPECT_EQ(InstallOutcome::None, sink.activateDurableCommit());
  sdk.writeFault = FaultTiming::None;
  integration.loop();
  ASSERT_TRUE(store.load(durable));
  EXPECT_EQ(OtaCandidateStore::Phase::Ready, durable.phase);
}

TEST_F(Esp32Product, FailedCommittedAppendDoesNotSelectAndSignedRetryCanSucceed) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  sdk.writeFault = FaultTiming::Before;
  EXPECT_EQ(Result::IoError, commit());
  OtaCandidateStore::Snapshot durable;
  ASSERT_TRUE(store.load(durable));
  EXPECT_EQ(OtaCandidateStore::Phase::Ready, durable.phase);
  EXPECT_EQ(InstallOutcome::None, sink.activateDurableCommit());
  sdk.writeFault = FaultTiming::None;
  EXPECT_EQ(Result::Ok, commit());
  EXPECT_EQ(InstallOutcome::Selected, sink.activateDurableCommit());
}

TEST_F(Esp32Product, CommitSignatureIsBoundToThisIndividualTarget) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  uint8_t hash[32], message[usb::kCommitSignedBytes], wrong_target[32] = {1}, sig[64];
  computeOtaManifestHash(canonical, hash);
  const size_t len = usb::buildCommitSignedMessage(wrong_target, hash, descriptor.securityCounter, message);
  owner.sign(message, len, sig);
  EXPECT_EQ(Result::Denied, receiver().commit(descriptor.securityCounter, sig));
  EXPECT_EQ(InstallOutcome::None, sink.activateDurableCommit());
}

TEST_F(Esp32Product, CompleteImageAndBitmapMustBeDurableBeforeCommit) {
  begin();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, receiver().putBlock(0, image.data(), kOtaBlockMaxDataBytes));
  EXPECT_EQ(Result::Incomplete, receiver().requestSeal());
  EXPECT_EQ(Result::TooLate, commit());
  EXPECT_EQ(InstallOutcome::None, sink.activateDurableCommit());
}

TEST_F(Esp32Product, TornBlockIsNotMarkedReceivedAndCanBeRetransmitted) {
  begin();
  ASSERT_FALSE(HasFatalFailure());
  sdk.writeFault = FaultTiming::Torn;
  sdk.tornBytes = 17;
  EXPECT_EQ(Result::IoError, receiver().putBlock(0, image.data(), kOtaBlockMaxDataBytes));
  EXPECT_FALSE(store.isReceived(0));
  sdk.writeFault = FaultTiming::None;
  EXPECT_EQ(Result::Ok, receiver().putBlock(0, image.data(), kOtaBlockMaxDataBytes));
  EXPECT_TRUE(store.isReceived(0));
}

TEST_F(Esp32Product, CutDuringSelectionMarkerCannotChangeBootSlot) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  sdk.writeFault = FaultTiming::Torn;
  sdk.tornBytes = 2;
  EXPECT_EQ(InstallOutcome::Refused, sink.activateDurableCommit());
  EXPECT_EQ(0u, install.selections);
  EXPECT_TRUE(esp32PartitionEquals(sdk.snapshot.boot, sdk.snapshot.running));
}

TEST_F(Esp32Product, CutBeforeVendorSelectionLeavesDurableCandidateButNeverAutoRetriesTrial) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  install.selectionFails = true;
  EXPECT_EQ(InstallOutcome::SelectionUncertain, sink.activateDurableCommit());
  EXPECT_TRUE(esp32PartitionEquals(sdk.snapshot.boot, sdk.snapshot.running));
  // Reboot: recreate the production sink, preserving NOR/otadata only.
  Esp32OtaStagingSink rebooted(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  install.selectionFails = false;
  ASSERT_TRUE(rebooted.recoverUnsuccessfulSelection());
  OtaCandidateStore::Snapshot recovered;
  ASSERT_TRUE(store.load(recovered));
  EXPECT_EQ(OtaCandidateStore::Phase::Failed, recovered.phase);
  EXPECT_EQ(InstallOutcome::None, rebooted.activateDurableCommit());
  EXPECT_EQ(1u, install.selections);
}

TEST_F(Esp32Product, ResetAfterDurableCommitBeforeSelectionResumesExactlyOnce) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  Esp32OtaStagingSink rebooted(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  EXPECT_EQ(InstallOutcome::Selected, rebooted.activateDurableCommit());
  EXPECT_EQ(InstallOutcome::None, rebooted.activateDurableCommit());
  EXPECT_EQ(1u, install.selections);
}

TEST_F(Esp32Product, VendorSelectionLostAcknowledgementDoesNotRetireNewTrial) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  install.selectionTorn = true;
  EXPECT_EQ(InstallOutcome::SelectionUncertain, sink.activateDurableCommit());
  EXPECT_EQ(Esp32ImageState::New, sdk.snapshot.appStates[1]);
  Esp32OtaStagingSink rebooted(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  EXPECT_FALSE(rebooted.recoverUnsuccessfulSelection());
  EXPECT_EQ(1u, install.selections);
}

TEST_F(Esp32Product, AbortedTrialCannotBeSilentlyReinstalled) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  ASSERT_EQ(InstallOutcome::Selected, sink.activateDurableCommit());
  sdk.snapshot.boot = sdk.snapshot.running;
  sdk.snapshot.appStates[1] = Esp32ImageState::Aborted;
  Esp32OtaStagingSink rollback(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  ASSERT_TRUE(rollback.recoverUnsuccessfulSelection());
  EXPECT_EQ(InstallOutcome::None, rollback.activateDurableCommit());
  EXPECT_EQ(1u, install.selections);
  // A reboot reconstructs the receiver too; it cannot retain commit_started_.
  OtaFirmwareIntegration rebooted;
  attachTo(rebooted, rollback);
  auto& resumed = rebooted.leanReceiver();
  ASSERT_EQ(Result::Ok, resumed.begin(owner.publicKey(), canonical, signature, true, false));
  for (size_t offset = 0; offset < image.size(); offset += kOtaBlockMaxDataBytes) {
    const size_t take = std::min(kOtaBlockMaxDataBytes, image.size() - offset);
    ASSERT_EQ(Result::Ok, resumed.putBlock(static_cast<uint16_t>(offset / kOtaBlockMaxDataBytes),
                                          image.data() + offset, take));
  }
  ASSERT_EQ(Result::Pending, resumed.requestSeal());
  rebooted.loop();
  ASSERT_EQ(OtaCandidateStore::Phase::Ready, resumed.status().phase);
  uint8_t hash[32], message[usb::kCommitSignedBytes], sig[64];
  computeOtaManifestHash(canonical, hash);
  const size_t len = usb::buildCommitSignedMessage(target, hash, descriptor.securityCounter, message);
  owner.sign(message, len, sig);
  ASSERT_EQ(Result::Ok, resumed.commit(descriptor.securityCounter, sig));
  EXPECT_EQ(InstallOutcome::Selected, rollback.activateDurableCommit());
  EXPECT_EQ(2u, install.selections);
}

class TrialModel final : public Esp32TrialPlatform {
public:
  Esp32ImageState state = Esp32ImageState::PendingVerify;
  bool readable = true, watchdogOk = true, confirmOk = true, persistValid = true;
  uint32_t arms = 0, remaining = 0, disarms = 0, confirmations = 0, resets = 0;
  bool watchdog = false;
  bool runningState(Esp32ImageState& out) override { out = state; return readable; }
  bool armWatchdog(uint32_t ms) override {
    ++arms; remaining = ms; watchdog = watchdogOk; return watchdogOk;
  }
  void disarmWatchdog() override { ++disarms; watchdog = false; }
  bool confirmHealthy() override {
    ++confirmations;
    if (confirmOk && persistValid) state = Esp32ImageState::Valid;
    return confirmOk;
  }
  void rollbackAndRestart() override { ++resets; }
  void hardwareTimeExpires() {
    if (watchdog) {
      ++resets;
      if (state == Esp32ImageState::PendingVerify) state = Esp32ImageState::Aborted;
    }
  }
};

TEST(Esp32TrialActions, DefersConfirmationUntilRealContinuousLateHealth) {
  TrialModel platform;
  Esp32TrialController controller(platform);
  ASSERT_TRUE(controller.begin(5000));
  EXPECT_EQ(40000u, platform.remaining);
  EXPECT_TRUE(controller.activeOrUnknown());
  for (uint32_t t = 5000; t < 15000; t += 500)
    EXPECT_EQ(Esp32TrialHealthOutcome::Pending, controller.tick(t, true, true, true));
  EXPECT_EQ(0u, platform.confirmations);
  EXPECT_EQ(Esp32TrialHealthOutcome::Confirmed, controller.tick(15000, true, true, true));
  EXPECT_EQ(Esp32ImageState::Valid, platform.state);
  EXPECT_EQ(1u, platform.disarms);
  EXPECT_FALSE(controller.activeOrUnknown());
  EXPECT_EQ(Esp32TrialHealthOutcome::Confirmed, controller.tick(15500, true, true, true));
  EXPECT_EQ(1u, platform.confirmations);
}

TEST(Esp32TrialActions, LoopHungBeforeFirstTickStillResetsAndAborts) {
  TrialModel platform;
  Esp32TrialController controller(platform);
  ASSERT_TRUE(controller.begin(100));
  platform.hardwareTimeExpires();
  EXPECT_EQ(1u, platform.resets);
  EXPECT_EQ(Esp32ImageState::Aborted, platform.state);
  EXPECT_EQ(0u, platform.confirmations);
}

TEST(Esp32TrialActions, RadioFailureCannotPreventDeadlineOrHardwareWatchdog) {
  TrialModel platform;
  Esp32TrialController controller(platform);
  ASSERT_TRUE(controller.begin(0));
  for (uint32_t t = 0; t < 45000; t += 500) controller.tick(t, false, true, true);
  EXPECT_EQ(Esp32TrialHealthOutcome::DeadlineExpired, controller.tick(45000, false, true, true));
  EXPECT_EQ(1u, platform.resets);
  EXPECT_EQ(0u, platform.confirmations);
  EXPECT_EQ(0u, platform.disarms);
  controller.tick(46000, true, true, true);
  EXPECT_EQ(1u, platform.resets);
}

TEST(Esp32TrialActions, StorageFaultAndLongServiceGapResetHealthyDwell) {
  TrialModel platform;
  Esp32TrialController controller(platform);
  ASSERT_TRUE(controller.begin(0));
  for (uint32_t t = 0; t <= 9000; t += 500) controller.tick(t, true, true, true);
  controller.tick(9500, true, false, true);
  for (uint32_t t = 10000; t <= 19000; t += 500) controller.tick(t, true, true, true);
  EXPECT_EQ(Esp32TrialHealthOutcome::Pending, controller.tick(21000, true, true, true));
  EXPECT_EQ(0u, platform.confirmations);
  for (uint32_t t = 21500; t < 31000; t += 500) controller.tick(t, true, true, true);
  EXPECT_EQ(Esp32TrialHealthOutcome::Confirmed, controller.tick(31000, true, true, true));
}

TEST(Esp32TrialActions, FailedOrUncertainVendorConfirmNeverDisarmsWatchdog) {
  for (int failure = 0; failure < 3; ++failure) {
    TrialModel platform;
    Esp32TrialController controller(platform);
    ASSERT_TRUE(controller.begin(0));
    for (uint32_t t = 0; t < 10000; t += 500) controller.tick(t, true, true, true);
    if (failure == 0) platform.confirmOk = false;
    if (failure == 1) platform.persistValid = false;
    if (failure == 2) platform.readable = false;
    EXPECT_EQ(Esp32TrialHealthOutcome::ConfirmationUncertain, controller.tick(10000, true, true, true));
    EXPECT_EQ(0u, platform.disarms);
    EXPECT_EQ(1u, platform.resets);
  }
}

TEST(Esp32TrialActions, UnknownStateAndWatchdogFailureAreFailClosed) {
  TrialModel unknown;
  unknown.readable = false;
  Esp32TrialController guard(unknown);
  EXPECT_FALSE(guard.begin(1000));
  EXPECT_TRUE(guard.activeOrUnknown());
  EXPECT_EQ(Esp32TrialHealthOutcome::StateUnreadable, guard.tick(1000, true, true, true));
  EXPECT_EQ(1u, unknown.resets);
  EXPECT_EQ(0u, unknown.confirmations);
  TrialModel no_watchdog;
  no_watchdog.watchdogOk = false;
  Esp32TrialController other(no_watchdog);
  EXPECT_FALSE(other.begin(0));
  EXPECT_EQ(1u, no_watchdog.resets);
}

TEST(Esp32TrialActions, ValidOrFactoryBootDoesNotConfirmOrArmWatchdog) {
  for (auto state : {Esp32ImageState::Valid, Esp32ImageState::Undefined}) {
    TrialModel platform;
    platform.state = state;
    Esp32TrialController controller(platform);
    EXPECT_TRUE(controller.begin(0));
    EXPECT_FALSE(controller.activeOrUnknown());
    EXPECT_EQ(Esp32TrialHealthOutcome::Pending, controller.tick(60000, true, true, true));
    EXPECT_EQ(0u, platform.arms);
    EXPECT_EQ(0u, platform.confirmations);
  }
}

}  // namespace
