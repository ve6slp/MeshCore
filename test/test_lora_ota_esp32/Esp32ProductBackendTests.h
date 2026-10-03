#pragma once

#include <gtest/gtest.h>
#include <helpers/ota/OtaFirmwareBackend.h>
#include <helpers/ota/OtaFirmwareIntegration.h>
#include <helpers/ota/OtaEsp32RollbackGuard.h>
#include <helpers/ota/OtaMeshTrialHealthTick.h>
#include <ota/trust/Ed25519SignatureVerifier.h>
#include "../test_lora_ota_trust/Ed25519TestSigner.h"
#include "Esp32SdkModel.h"

namespace {
mesh::ota::Esp32TrialController* shared_health_controller = nullptr;
mesh::ota::OtaBoardTrialHealthOutcome shared_health_outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
uint32_t shared_health_queries = 0;

bool sharedUnknownServiceHeld() {
  ++shared_health_queries;
  return shared_health_controller == nullptr || shared_health_controller->unknownServiceHeld();
}
bool sharedUnknownServiceNotHeld() { return false; }

class SharedHealthBridge {
public:
  explicit SharedHealthBridge(mesh::ota::Esp32TrialController* controller = nullptr) {
    shared_health_controller = controller;
    shared_health_queries = 0;
  }
  ~SharedHealthBridge() {
    shared_health_controller = nullptr;
    shared_health_outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  }
};
}

mesh::ota::OtaBoardTrialHealthOutcome otaBoardTryConfirmHealthyTrialBoot(
    uint32_t now_ms, bool radio_ready, bool filesystem_ready, bool loop_healthy) {
  if (shared_health_controller == nullptr) return shared_health_outcome;
  switch (shared_health_controller->tick(now_ms, radio_ready, filesystem_ready, loop_healthy)) {
    case mesh::ota::Esp32TrialHealthOutcome::Confirmed: return mesh::ota::OtaBoardTrialHealthOutcome::Confirmed;
    case mesh::ota::Esp32TrialHealthOutcome::DeadlineExpired: return mesh::ota::OtaBoardTrialHealthOutcome::DeadlineExpired;
    case mesh::ota::Esp32TrialHealthOutcome::ConfirmationUncertain: return mesh::ota::OtaBoardTrialHealthOutcome::ConfirmationUncertain;
    case mesh::ota::Esp32TrialHealthOutcome::StateUnreadable: return mesh::ota::OtaBoardTrialHealthOutcome::StateUnreadable;
    default: return mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  }
}

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
  bool floorKnown = false, floorReadable = true, floorWritable = true;
  uint32_t floor = 0, floorReadCalls = 0, floorSaveCalls = 0;
  uint32_t floorErrorCall = 0, floorChangedCall = 0, changedFloor = 0;
  Esp32RunningProof runningProof(uint32_t& counter) override;
  bool readConfirmedFloor(uint32_t& counter, bool& found) override {
    ++floorReadCalls;
    counter = 0;
    found = false;
    if (!floorReadable || floorReadCalls == floorErrorCall) return false;
    found = floorKnown;
    if (found) counter = floorReadCalls == floorChangedCall ? changedFloor : floor;
    return true;
  }
  bool saveConfirmedFloor(uint32_t counter) override {
    ++floorSaveCalls;
    uint32_t previous = 0;
    bool found = false;
    if (!readConfirmedFloor(previous, found) || !floorWritable) return false;
    if (counter > previous) { floor = counter; floorKnown = true; }
    return true;
  }
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
    if (sdk_.readError != kEsp32Ok || sdk_.readErrorPartition == partition_.address ||
        (sdk_.readErrorCall != 0 && sdk_.readCalls == sdk_.readErrorCall))
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

Esp32RunningProof InstallModel::runningProof(uint32_t& counter) {
  ReadOnlyAppModel reader(sdk, sdk.snapshot.running);
  return readEsp32RunningProof(sdk, reader, policy, signatures, counter);
}

class CausalNvsModel {
public:
  explicit CausalNvsModel(Esp32PartitionModel& sdk, uint32_t floor) : sdk(sdk) { storeFloor(floor); }
  Esp32PartitionModel& sdk;
  Esp32SdkError initError = kEsp32Ok;
  bool initialized = true, floorKnown = true, failVerification = false, failNextRead = false, readFault = false;
  uint32_t erases = 0;
  uint32_t storedFloor() const {
    const auto* bytes = sdk.bytes.data() + Esp32S3PartitionLayout::entry(0).address + 64;
    return usb::getBE32(bytes);
  }
  void storeFloor(uint32_t floor) {
    auto* bytes = sdk.bytes.data() + Esp32S3PartitionLayout::entry(0).address + 64;
    for (uint32_t i = 0; i < 4; ++i) bytes[i] = static_cast<uint8_t>(floor >> (24 - 8 * i));
    floorKnown = true;
  }
  bool readFloor(uint32_t& floor, bool& found) {
    floor = 0;
    found = false;
    if (!initialized || failNextRead || readFault) { failNextRead = false; return false; }
    found = floorKnown;
    if (found) floor = storedFloor();
    return true;
  }
  bool saveFloor(uint32_t counter) {
    uint32_t floor;
    bool found;
    if (!readFloor(floor, found)) return false;
    if (counter > floor) storeFloor(counter);
    failNextRead = failVerification;
    return readFloor(floor, found) && found && floor >= counter;
  }
  void eraseExplicitly() {
    const auto partition = Esp32S3PartitionLayout::entry(0);
    std::fill(sdk.bytes.begin() + partition.address, sdk.bytes.begin() + partition.address + partition.size, 0xff);
    ++erases;
    floorKnown = false;
    initError = kEsp32Ok;
  }
  Esp32SdkError initArduinoNvs(bool ota_enabled = true) {
    // The pinned core calls init, formats on these two errors, then retries.
    auto result = ota_enabled ? esp32NvsStartupInitResult(initError) : initError;
    if (result == kEsp32NvsNoFreePages || result == kEsp32NvsNewVersionFound) {
      eraseExplicitly();
      result = ota_enabled ? esp32NvsStartupInitResult(initError) : initError;
    }
    initialized = result == kEsp32Ok;
    return result;
  }
};

class CausalInstallModel final : public Esp32OtaInstallApi {
public:
  CausalInstallModel(InstallModel& install, CausalNvsModel& nvs) : install(install), nvs(nvs) {}
  InstallModel& install;
  CausalNvsModel& nvs;
  bool validateImage(const Esp32PartitionIdentity& p, uint32_t bytes) override {
    return install.validateImage(p, bytes);
  }
  bool selectBoot(const Esp32PartitionIdentity& p) override { return install.selectBoot(p); }
  Esp32RunningProof runningProof(uint32_t& counter) override { return install.runningProof(counter); }
  bool readConfirmedFloor(uint32_t& counter, bool& found) override { return nvs.readFloor(counter, found); }
  bool saveConfirmedFloor(uint32_t counter) override { return nvs.saveFloor(counter); }
};

class CausalTrialModel final : public Esp32TrialPlatform {
public:
  CausalTrialModel(Esp32PartitionModel& sdk, CausalNvsModel& nvs, const Esp32OtaPolicy& policy,
                   const ::ota::trust::SignatureVerifier& signatures)
      : sdk(sdk), nvs(nvs), policy(policy), signatures(signatures) {}
  Esp32PartitionModel& sdk;
  CausalNvsModel& nvs;
  const Esp32OtaPolicy& policy;
  const ::ota::trust::SignatureVerifier& signatures;
  bool markValidFails = false;
  uint32_t arms = 0, disarms = 0, resets = 0, rollbacks = 0, fallbacks = 0, unknownReports = 0;
  bool runningState(Esp32ImageState& out) override { return readEsp32EarlyRunningState(sdk, out); }
  bool unknownTopologyHoldAllowed() override { return readEsp32UnknownStartupTopology(sdk); }
  bool armWatchdog(uint32_t) override { ++arms; return true; }
  void disarmWatchdog() override { ++disarms; }
  void reportUnknownService() override { ++unknownReports; }
  Esp32TrialConfirmation confirmHealthy() override {
    return confirmEsp32TrialImage(
        [&](uint32_t& counter, bool& have_candidate) {
          ReadOnlyAppModel reader(sdk, sdk.snapshot.running);
          FlashRegion image(reader, 0, Esp32OtaPolicy::kCandidateBytes);
          FlashRegion metadata(reader, Esp32OtaPolicy::kCandidateBytes, 8192);
          OtaCandidateStore provenance(metadata);
          OtaCandidateStore::Snapshot snapshot;
          meshcore::ota::protocol::OtaDescriptor descriptor;
          have_candidate = verifyEsp32RunningCandidate(provenance, image, policy, signatures, snapshot, descriptor);
          if (have_candidate) counter = descriptor.securityCounter;
          return have_candidate;
        },
        [&]() {
          if (markValidFails) return false;
          sdk.snapshot.appStates[sdk.snapshot.running.subtype - 0x10] = Esp32ImageState::Valid;
          return true;
        },
        [&](uint32_t counter) { return nvs.saveFloor(counter); });
  }
  void restartWithoutRollback() override {
    ++resets;
    auto& current = sdk.snapshot.appStates[sdk.snapshot.running.subtype - 0x10];
    if (esp32PartitionEquals(sdk.snapshot.boot, sdk.snapshot.running) && current == Esp32ImageState::PendingVerify) {
      current = Esp32ImageState::Aborted;
      sdk.snapshot.boot = sdk.snapshot.next;
    }
    sdk.snapshot.running = sdk.snapshot.boot;
    if (sdk.bytes[sdk.snapshot.boot.address] != 0xe9) {
      sdk.snapshot.running = Esp32S3PartitionLayout::entry(sdk.snapshot.boot.subtype == 0x10 ? 3 : 2);
      ++fallbacks;
    }
    sdk.snapshot.next = Esp32S3PartitionLayout::entry(sdk.snapshot.running.subtype == 0x10 ? 3 : 2);
  }
  void rollbackAndRestart() override {
    Esp32ImageState state;
    if (runningState(state) && state == Esp32ImageState::PendingVerify) {
      ++rollbacks;
      sdk.snapshot.appStates[sdk.snapshot.boot.subtype - 0x10] = Esp32ImageState::Invalid;
      sdk.snapshot.boot = sdk.snapshot.next;
    }
    restartWithoutRollback();
  }
};

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
    setIdentity(flow);
  }
  void setIdentity(OtaFirmwareIntegration& flow) {
    flow.setLeanTargetPublicKey(target);
    flow.setLeanAdminCheck(this, [](void* ctx, const uint8_t key[32]) {
      const auto* self = static_cast<Esp32Product*>(ctx);
      return self->admin && std::memcmp(key, self->owner.publicKey(), 32) == 0;
    });
  }
  Esp32ConfigureOutcome configure(OtaFirmwareIntegration& flow, Esp32OtaStagingSink& staging,
                                  bool trial_or_unknown = false) {
    const char* capability = nullptr;
    const auto outcome = configureEsp32OtaBackend(flow, trial_or_unknown, install, policy, flash, lease,
                                                 store, staging, trust, signatures, capability);
    if (outcome == Esp32ConfigureOutcome::Configured) {
      EXPECT_STREQ("INSTALL_CAPABLE: ESP-IDF A/B rollback", capability);
      setIdentity(flow);
    } else {
      EXPECT_NE(nullptr, std::strstr(capability, "OTA_DISABLED"));
      EXPECT_FALSE(flow.backendAvailable());
      EXPECT_FALSE(flow.leanReceiver().hasStore());
    }
    return outcome;
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
  void thirdTrial() {
    twoSuccessfulInstalls();
    ASSERT_FALSE(HasFatalFailure());
    image[1] = 3;
    descriptor.securityCounter = 3;
    ::ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
    signDescriptor();
    ready();
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_EQ(Result::Ok, commit());
    ASSERT_EQ(InstallOutcome::Selected, sink.activateDurableCommit());
    rebootIntoCandidate(Esp32ImageState::PendingVerify);
  }
  void usbReflash(const Esp32PartitionIdentity& running, bool blank_tail) {
    sdk.snapshot.running = running;
    sdk.snapshot.boot = running;
    sdk.snapshot.next = Esp32S3PartitionLayout::entry(running.subtype == 0x10 ? 3 : 2);
    sdk.snapshot.appStates[0] = sdk.snapshot.appStates[1] = Esp32ImageState::Undefined;
    std::fill(sdk.bytes.begin() + running.address, sdk.bytes.begin() + running.address + image.size(), 0x6b);
    sdk.bytes[running.address] = 0xe9;
    if (blank_tail) {
      const uint32_t base = running.address + Esp32OtaPolicy::kCandidateBytes;
      std::fill(sdk.bytes.begin() + base, sdk.bytes.begin() + base + 8192, 0xff);
    }
  }
  void installConfigured(OtaFirmwareIntegration& flow, Esp32OtaStagingSink& staging, uint32_t counter) {
    image[1] = static_cast<uint8_t>(counter);
    descriptor.securityCounter = counter;
    ::ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
    signDescriptor();
    ready(flow);
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_EQ(Result::Ok, commit(flow));
    ASSERT_EQ(InstallOutcome::Selected, staging.activateDurableCommit());
    rebootIntoCandidate(Esp32ImageState::PendingVerify);
    sdk.snapshot.appStates[sdk.snapshot.running.subtype - 0x10] = Esp32ImageState::Valid;
    ASSERT_TRUE(install.saveConfirmedFloor(counter));
    policy.confirmedCounter = counter;
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
    out = OtaBootLifecycleEvidence();
    Esp32PartitionSnapshot context;
    if (failed_candidate && sdk.inspect(context) != kEsp32Ok) return false;
    const auto partition = failed_candidate ? sdk.snapshot.next : sdk.snapshot.running;
    ReadOnlyAppModel reader(sdk, partition);
    Esp32OtaIoGuard checked(reader);
    FlashRegion image_view(checked, 0, Esp32OtaPolicy::kCandidateBytes);
    FlashRegion metadata_view(checked, Esp32OtaPolicy::kCandidateBytes, 8192);
    OtaCandidateStore provenance(metadata_view);
    const bool verified = readEsp32BootLifecycle(sdk.snapshot.appStates[partition.subtype - 0x10], provenance,
        image_view, metadata_view, policy, signatures, floor_known, floor, out, failed_candidate,
        failed_candidate ? &context : nullptr);
    if (checked.failed()) { out = OtaBootLifecycleEvidence(); return false; }
    if (verified && failed_candidate) {
      Esp32PartitionSnapshot after;
      if (sdk.inspect(after) != kEsp32Ok || !esp32SameClosedFailedSelectionContext(context, after)) {
        out = OtaBootLifecycleEvidence();
        return false;
      }
    }
    return verified;
  }
  bool bootCandidate(const OtaBootLifecycleEvidence& expected, bool floor_known, uint32_t floor,
                     OtaCandidateStore::Snapshot& out) {
    out = OtaCandidateStore::Snapshot();
    const bool failed = expected.phase == usb::UsbOtaPhase::Failed;
    Esp32PartitionSnapshot context;
    if (failed && sdk.inspect(context) != kEsp32Ok) return false;
    const auto partition = expected.phase == usb::UsbOtaPhase::Failed ?
                           sdk.snapshot.next : sdk.snapshot.running;
    ReadOnlyAppModel reader(sdk, partition);
    Esp32OtaIoGuard checked(reader);
    FlashRegion metadata_view(checked, Esp32OtaPolicy::kCandidateBytes, 8192);
    OtaCandidateStore provenance(metadata_view);
    const bool verified = readEsp32BootCandidate(expected, sdk.snapshot.appStates[partition.subtype - 0x10],
        provenance, metadata_view, policy, signatures, floor_known, floor, out, failed ? &context : nullptr);
    if (checked.failed()) { out = OtaCandidateStore::Snapshot(); return false; }
    if (verified && failed) {
      Esp32PartitionSnapshot after;
      if (sdk.inspect(after) != kEsp32Ok || !esp32SameClosedFailedSelectionContext(context, after)) {
        out = OtaCandidateStore::Snapshot();
        return false;
      }
    }
    return verified;
  }
  void attachBootReadback(OtaFirmwareIntegration& flow) {
    flow.setLeanTargetPublicKey(target);
    flow.attachBootLifecycle(this, [](void* ctx, OtaBootLifecycleEvidence& out) {
      auto& self = *static_cast<Esp32Product*>(ctx);
      return self.lifecycle(self.install.floorKnown && self.install.floorReadable, self.install.floor, out);
    }, [](void* ctx, const OtaBootLifecycleEvidence& expected, OtaCandidateStore::Snapshot& out) {
      auto& self = *static_cast<Esp32Product*>(ctx);
      if (!self.install.floorReadable) { out = OtaCandidateStore::Snapshot(); return false; }
      return self.bootCandidate(expected, self.install.floorKnown, self.install.floor, out);
    });
  }
};

class Esp32SharedHealth : public Esp32Product, public ::testing::WithParamInterface<uint8_t> {
protected:
  void SetUp() override {
    policy.role = GetParam();
    Esp32Product::SetUp();
  }
  static OtaMeshTrialHealthTickInputs inputs(uint32_t now) {
    return {now, true, true, false, true, true, 0, 0, true};
  }
};

TEST_P(Esp32SharedHealth, DefaultNullAndFalseGetterPreserveGenericRebootsAndHeldOnlySuppressesUnknown) {
  SharedHealthBridge bridge;
  for (const auto outcome : {OtaBoardTrialHealthOutcome::Pending, OtaBoardTrialHealthOutcome::Confirmed,
                            OtaBoardTrialHealthOutcome::DeadlineExpired,
                            OtaBoardTrialHealthOutcome::ConfirmationUncertain,
                            OtaBoardTrialHealthOutcome::StateUnreadable}) {
    shared_health_outcome = outcome;
    uint32_t faults = 0;
    const auto legacy = evaluateOtaMeshTrialHealthTick(inputs(0), faults);
    const auto explicit_null = evaluateOtaMeshTrialHealthTick(inputs(0), faults, nullptr);
    const auto not_held = evaluateOtaMeshTrialHealthTick(inputs(0), faults, sharedUnknownServiceNotHeld);
    EXPECT_EQ(outcome, legacy.outcome);
    EXPECT_EQ(outcome != OtaBoardTrialHealthOutcome::Pending, legacy.should_reboot);
    EXPECT_EQ(legacy.should_reboot, explicit_null.should_reboot);
    EXPECT_EQ(legacy.should_reboot, not_held.should_reboot);
    shared_health_queries = 0;
    const auto held = evaluateOtaMeshTrialHealthTick(inputs(0), faults, sharedUnknownServiceHeld);
    EXPECT_EQ(outcome, held.outcome);
    EXPECT_EQ(outcome != OtaBoardTrialHealthOutcome::Pending &&
              outcome != OtaBoardTrialHealthOutcome::StateUnreadable, held.should_reboot);
    EXPECT_EQ(outcome == OtaBoardTrialHealthOutcome::StateUnreadable ? 1u : 0u, shared_health_queries);
  }
}

TEST_P(Esp32SharedHealth, GenuineSdkReadFailureNeverBecomesHeldWithExhaustedTopologyBudget) {
  thirdTrial();
  ASSERT_FALSE(HasFatalFailure());
  CausalNvsModel nvs(sdk, 2);
  CausalTrialModel platform(sdk, nvs, policy, signatures);
  Esp32StartupRestartState retained = {kEsp32StartupRestartMagic, kEsp32StartupRestartLimit};
  sdk.inspectError = -1;
  Esp32TrialController controller(platform, &retained);
  EXPECT_FALSE(controller.begin(0));
  EXPECT_FALSE(controller.unknownServiceHeld());
  EXPECT_EQ(1u, platform.resets);
  SharedHealthBridge bridge(&controller);
  uint32_t faults = 0;
  const auto result = evaluateOtaMeshTrialHealthTick(inputs(0), faults, sharedUnknownServiceHeld);
  EXPECT_EQ(OtaBoardTrialHealthOutcome::StateUnreadable, result.outcome);
  EXPECT_TRUE(result.should_reboot);
}

TEST_P(Esp32SharedHealth, HeldQueryRunsAfterBoardTickEstablishesBoundedUnknownService) {
  thirdTrial();
  ASSERT_FALSE(HasFatalFailure());
  sdk.snapshot.appStates[sdk.snapshot.boot.subtype - 0x10] = Esp32ImageState::Valid;
  sdk.snapshot.running = sdk.snapshot.next;
  sdk.snapshot.next = sdk.snapshot.boot;
  CausalNvsModel nvs(sdk, 2);
  CausalTrialModel platform(sdk, nvs, policy, signatures);
  Esp32StartupRestartState retained = {kEsp32StartupRestartMagic, kEsp32StartupRestartLimit};
  Esp32TrialController controller(platform, &retained);
  EXPECT_FALSE(controller.unknownServiceHeld());
  SharedHealthBridge bridge(&controller);
  uint32_t faults = 0;
  const auto result = evaluateOtaMeshTrialHealthTick(inputs(0), faults, sharedUnknownServiceHeld);
  EXPECT_EQ(OtaBoardTrialHealthOutcome::StateUnreadable, result.outcome);
  EXPECT_FALSE(result.should_reboot);
  EXPECT_TRUE(controller.unknownServiceHeld());
  EXPECT_EQ(1u, shared_health_queries);
  EXPECT_EQ(0u, platform.resets);
  EXPECT_EQ(0u, platform.arms);
}

INSTANTIATE_TEST_SUITE_P(BothProductionRoles, Esp32SharedHealth, ::testing::Values(uint8_t{0}, uint8_t{1}),
    [](const ::testing::TestParamInfo<uint8_t>& info) { return info.param == 0 ? "Companion" : "Repeater"; });

TEST_F(Esp32Product, ValidCounterThreeWithDurableFloorAndLostReadbackRestartsForwardAndRecoversAdmission) {
  thirdTrial();
  ASSERT_FALSE(HasFatalFailure());
  const auto candidate_app = sdk.snapshot.running;
  CausalNvsModel nvs(sdk, 2);
  CausalTrialModel platform(sdk, nvs, policy, signatures);
  Esp32TrialController controller(platform);
  ASSERT_TRUE(controller.begin(0));
  for (uint32_t now = 0; now < 10000; now += 500) controller.tick(now, true, true, true);
  nvs.failVerification = true;
  EXPECT_EQ(Esp32TrialHealthOutcome::ConfirmationUncertain, controller.tick(10000, true, true, true));
  EXPECT_EQ(3u, nvs.storedFloor());
  EXPECT_TRUE(esp32PartitionEquals(candidate_app, sdk.snapshot.running));
  EXPECT_EQ(Esp32ImageState::Valid, sdk.snapshot.appStates[candidate_app.subtype - 0x10]);
  EXPECT_EQ(0u, platform.rollbacks);
  EXPECT_EQ(1u, platform.resets);
  EXPECT_EQ(0u, platform.disarms);
  nvs.failVerification = false;
  CausalInstallModel cold_install(install, nvs);
  Esp32OtaStagingSink cold_sink(flash, lease, candidate, metadata, store, trust, policy, signatures, cold_install);
  OtaFirmwareIntegration cold;
  const char* capability = nullptr;
  EXPECT_EQ(Esp32ConfigureOutcome::Configured,
      configureEsp32OtaBackend(cold, false, cold_install, policy, flash, lease, store, cold_sink, trust,
                               signatures, capability));
  EXPECT_EQ(3u, policy.confirmedCounter);
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(true, nvs.storedFloor(), boot));
  EXPECT_EQ(usb::UsbOtaPhase::Installed, boot.phase);
  EXPECT_EQ(3u, boot.counter);
  setIdentity(cold);
  const auto before = sdk.bytes;
  EXPECT_EQ(Result::Denied, cold.leanReceiver().begin(owner.publicKey(), canonical, signature, false, false));
  EXPECT_EQ(before, sdk.bytes);
  image[1] = 4;
  descriptor.securityCounter = 4;
  ::ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
  signDescriptor();
  EXPECT_EQ(Result::Ok, cold.leanReceiver().begin(owner.publicKey(), canonical, signature, false, false));
}

TEST_F(Esp32Product, FailedBeforeValidKeepsFloorAndRollsBackOnlyPendingCandidate) {
  thirdTrial();
  ASSERT_FALSE(HasFatalFailure());
  const auto candidate_app = sdk.snapshot.running;
  const auto previous = sdk.snapshot.next;
  CausalNvsModel nvs(sdk, 2);
  const auto before = sdk.bytes;
  CausalTrialModel platform(sdk, nvs, policy, signatures);
  platform.markValidFails = true;
  Esp32TrialController controller(platform);
  ASSERT_TRUE(controller.begin(0));
  for (uint32_t now = 0; now < 10000; now += 500) controller.tick(now, true, true, true);
  EXPECT_EQ(Esp32TrialHealthOutcome::ConfirmationUncertain, controller.tick(10000, true, true, true));
  EXPECT_EQ(2u, nvs.storedFloor());
  EXPECT_TRUE(esp32PartitionEquals(previous, sdk.snapshot.running));
  EXPECT_EQ(Esp32ImageState::Valid, sdk.snapshot.appStates[previous.subtype - 0x10]);
  EXPECT_EQ(Esp32ImageState::Invalid, sdk.snapshot.appStates[candidate_app.subtype - 0x10]);
  EXPECT_EQ(1u, platform.rollbacks);
  EXPECT_EQ(1u, platform.resets);
  EXPECT_EQ(0u, platform.disarms);
  EXPECT_EQ(before, sdk.bytes);
}

TEST_F(Esp32Product, PersistentConfirmedFloorFaultDisablesOtaWithoutFurtherResetsOrWrites) {
  thirdTrial();
  ASSERT_FALSE(HasFatalFailure());
  CausalNvsModel nvs(sdk, 2);
  CausalTrialModel trial(sdk, nvs, policy, signatures);
  Esp32TrialController confirmation(trial);
  ASSERT_TRUE(confirmation.begin(0));
  for (uint32_t now = 0; now < 10000; now += 500) confirmation.tick(now, true, true, true);
  nvs.failVerification = true;
  ASSERT_EQ(Esp32TrialHealthOutcome::ConfirmationUncertain, confirmation.tick(10000, true, true, true));
  ASSERT_EQ(3u, nvs.storedFloor());
  ASSERT_EQ(1u, trial.resets);
  const auto before = sdk.bytes;
  nvs.failVerification = false;
  nvs.readFault = true;
  Esp32StartupRestartState retained = {0, 0};
  for (uint32_t boot = 0; boot < 6; ++boot) {
    CausalTrialModel service(sdk, nvs, policy, signatures);
    Esp32TrialController controller(service, &retained);
    ASSERT_TRUE(controller.begin(0));
    EXPECT_FALSE(controller.activeOrUnknown());
    nvs.initError = boot % 3 == 0 ? kEsp32NvsNoFreePages :
                    boot % 3 == 1 ? kEsp32NvsNewVersionFound : kEsp32Ok;
    EXPECT_EQ(boot % 3 == 2 ? kEsp32Ok : kEsp32InvalidState, nvs.initArduinoNvs());
    CausalInstallModel cold_install(install, nvs);
    Esp32OtaStagingSink cold_sink(flash, lease, candidate, metadata, store, trust, policy, signatures, cold_install);
    OtaFirmwareIntegration cold;
    const char* capability = nullptr;
    EXPECT_EQ(Esp32ConfigureOutcome::IoError,
        configureEsp32OtaBackend(cold, controller.activeOrUnknown(), cold_install, policy, flash, lease,
                                 store, cold_sink, trust, signatures, capability));
    EXPECT_STREQ("OTA_DISABLED: ESP confirmed floor unreadable", capability);
    for (uint32_t now = 0; now <= 120000; now += 500)
      EXPECT_EQ(Esp32TrialHealthOutcome::Pending, controller.tick(now, true, false, true));
    EXPECT_EQ(0u, service.arms);
    EXPECT_EQ(0u, service.resets);
    EXPECT_EQ(0u, service.rollbacks);
    EXPECT_EQ(Esp32ImageState::Valid, sdk.snapshot.appStates[sdk.snapshot.running.subtype - 0x10]);
    EXPECT_EQ(3u, nvs.storedFloor());
    EXPECT_EQ(0u, nvs.erases);
    EXPECT_EQ(before, sdk.bytes);
  }
}

TEST_F(Esp32Product, RollbackRequiresFreshRunningPendingProofAndNeverInvalidatesValidOrAnotherSelectedApp) {
  thirdTrial();
  ASSERT_FALSE(HasFatalFailure());
  const auto candidate_app = sdk.snapshot.running;
  const auto previous = sdk.snapshot.next;
  CausalNvsModel nvs(sdk, 2);
  CausalTrialModel platform(sdk, nvs, policy, signatures);
  const auto before = sdk.bytes;
  sdk.snapshot.appStates[candidate_app.subtype - 0x10] = Esp32ImageState::Valid;
  platform.rollbackAndRestart();
  EXPECT_EQ(0u, platform.rollbacks);
  EXPECT_EQ(Esp32ImageState::Valid, sdk.snapshot.appStates[candidate_app.subtype - 0x10]);
  EXPECT_TRUE(esp32PartitionEquals(candidate_app, sdk.snapshot.running));
  sdk.snapshot.boot = previous;
  platform.rollbackAndRestart();
  EXPECT_EQ(0u, platform.rollbacks);
  EXPECT_EQ(Esp32ImageState::Valid, sdk.snapshot.appStates[previous.subtype - 0x10]);
  EXPECT_TRUE(esp32PartitionEquals(previous, sdk.snapshot.running));
  sdk.snapshot.running = sdk.snapshot.boot = candidate_app;
  sdk.snapshot.next = previous;
  sdk.snapshot.appStates[candidate_app.subtype - 0x10] = Esp32ImageState::PendingVerify;
  platform.rollbackAndRestart();
  EXPECT_EQ(1u, platform.rollbacks);
  EXPECT_EQ(Esp32ImageState::Invalid, sdk.snapshot.appStates[candidate_app.subtype - 0x10]);
  EXPECT_EQ(Esp32ImageState::Valid, sdk.snapshot.appStates[previous.subtype - 0x10]);
  EXPECT_TRUE(esp32PartitionEquals(previous, sdk.snapshot.running));
  EXPECT_EQ(before, sdk.bytes);
}

TEST_P(Esp32SharedHealth, InvalidSelectedImageRepeatedlyFallsBackButUnknownStartupRestartsAreRetainedAndBounded) {
  thirdTrial();
  ASSERT_FALSE(HasFatalFailure());
  const auto selected = sdk.snapshot.boot;
  const auto fallback = sdk.snapshot.next;
  sdk.snapshot.appStates[selected.subtype - 0x10] = Esp32ImageState::Valid;
  sdk.bytes[selected.address] = 0;  // SDK retains VALID otadata after image validation falls back.
  sdk.snapshot.running = fallback;
  sdk.snapshot.next = selected;
  CausalNvsModel nvs(sdk, 2);
  CausalInstallModel cold_install(install, nvs);
  const auto before = sdk.bytes;
  Esp32StartupRestartState retained = {0, 0};
  uint32_t resets = 0;
  for (uint32_t boot = 0; boot < kEsp32StartupRestartLimit + 3; ++boot) {
    CausalTrialModel platform(sdk, nvs, policy, signatures);
    Esp32TrialController controller(platform, &retained);
    EXPECT_FALSE(controller.begin(0));
    EXPECT_TRUE(controller.activeOrUnknown());
    EXPECT_EQ(boot >= kEsp32StartupRestartLimit, controller.unknownServiceHeld());
    EXPECT_EQ(boot < kEsp32StartupRestartLimit ? 1u : 0u, platform.resets);
    EXPECT_EQ(Esp32TrialHealthOutcome::StateUnreadable, controller.tick(0, false, false, false));
    EXPECT_EQ(0u, platform.rollbacks);
    EXPECT_TRUE(esp32PartitionEquals(fallback, sdk.snapshot.running));
    EXPECT_TRUE(esp32PartitionEquals(selected, sdk.snapshot.boot));
    if (boot >= kEsp32StartupRestartLimit) {
      EXPECT_EQ(0u, platform.arms);
      EXPECT_EQ(1u, platform.unknownReports);
      SharedHealthBridge bridge(&controller);
      uint32_t faults = 0;
      uint32_t radio_service_ticks = 0;
      for (uint32_t now = 500; now <= 120000; now += 500) {
        const auto result = evaluateOtaMeshTrialHealthTick(inputs(now), faults, sharedUnknownServiceHeld);
        EXPECT_EQ(OtaBoardTrialHealthOutcome::StateUnreadable, result.outcome);
        EXPECT_FALSE(result.should_reboot);
        if (result.should_reboot) {
          platform.restartWithoutRollback();
          break;
        }
        ++radio_service_ticks;
      }
      EXPECT_EQ(240u, radio_service_ticks);
      EXPECT_EQ(0u, platform.resets);
      EXPECT_EQ(kEsp32Ok, nvs.initArduinoNvs());
      OtaFirmwareIntegration cold;
      const char* capability = nullptr;
      EXPECT_EQ(Esp32ConfigureOutcome::Refused,
          configureEsp32OtaBackend(cold, controller.activeOrUnknown(), cold_install, policy, flash, lease,
                                   store, sink, trust, signatures, capability));
      EXPECT_STREQ("OTA_DISABLED: ESP trial or unknown", capability);
      EXPECT_FALSE(cold.backendAvailable());
      EXPECT_FALSE(cold.leanReceiver().hasStore());
      sdk.inspectError = -1;
      EXPECT_FALSE(controller.unknownServiceHeld());
      EXPECT_TRUE(evaluateOtaMeshTrialHealthTick(inputs(120500), faults, sharedUnknownServiceHeld).should_reboot);
      sdk.inspectError = kEsp32Ok;
      EXPECT_TRUE(controller.unknownServiceHeld());
      sdk.snapshot.appStates[fallback.subtype - 0x10] = Esp32ImageState::PendingVerify;
      EXPECT_FALSE(controller.unknownServiceHeld());
      sdk.snapshot.appStates[fallback.subtype - 0x10] = Esp32ImageState::Valid;
      EXPECT_TRUE(controller.unknownServiceHeld());
      const auto saved_count = sdk.snapshot.count;
      --sdk.snapshot.count;
      EXPECT_FALSE(controller.unknownServiceHeld());
      sdk.snapshot.count = saved_count;
    }
    resets += platform.resets;
    EXPECT_EQ(before, sdk.bytes);
  }
  EXPECT_EQ(kEsp32StartupRestartLimit, resets);
  EXPECT_EQ(kEsp32StartupRestartLimit, retained.attempts);
  sdk.snapshot.boot = fallback;
  CausalTrialModel recovered(sdk, nvs, policy, signatures);
  Esp32TrialController healthy(recovered, &retained);
  EXPECT_TRUE(healthy.begin(0));
  EXPECT_FALSE(healthy.activeOrUnknown());
  EXPECT_EQ(0u, retained.attempts);
  EXPECT_EQ(0u, recovered.arms);
  EXPECT_EQ(0u, recovered.resets);
  sdk.snapshot.appStates[fallback.subtype - 0x10] = Esp32ImageState::Undefined;
  CausalTrialModel stock(sdk, nvs, policy, signatures);
  Esp32TrialController usb_stock(stock, &retained);
  EXPECT_TRUE(usb_stock.begin(0));
  EXPECT_FALSE(usb_stock.activeOrUnknown());
  EXPECT_EQ(0u, stock.arms);
  EXPECT_EQ(0u, stock.resets);
  EXPECT_EQ(before, sdk.bytes);
}

TEST_F(Esp32Product, ArduinoNvsStartupErrorsPreserveFloorAndBytesInTrialValidAndUsbStockBoots) {
  for (const auto state : {Esp32ImageState::PendingVerify, Esp32ImageState::Valid, Esp32ImageState::Undefined}) {
    sdk.snapshot.appStates[0] = state;
    for (const auto error : {kEsp32NvsNoFreePages, kEsp32NvsNewVersionFound}) {
      CausalNvsModel nvs(sdk, 3);
      nvs.initialized = false;
      nvs.initError = error;
      CausalTrialModel platform(sdk, nvs, policy, signatures);
      Esp32TrialController controller(platform);
      ASSERT_TRUE(controller.begin(0));  // verifyRollbackLater runs before nvs_flash_init.
      const auto before = sdk.bytes;
      EXPECT_EQ(kEsp32InvalidState, nvs.initArduinoNvs());
      EXPECT_FALSE(nvs.initialized);
      EXPECT_EQ(0u, nvs.erases);
      EXPECT_EQ(3u, nvs.storedFloor());
      EXPECT_EQ(before, sdk.bytes);
      EXPECT_EQ(error, nvs.initError);
    }
  }
}

TEST_F(Esp32Product, ExplicitFactoryNvsEraseRemainsSeparateFromStartupErrorProtection) {
  CausalNvsModel nvs(sdk, 3);
  nvs.eraseExplicitly();
  EXPECT_EQ(kEsp32Ok, nvs.initArduinoNvs());
  EXPECT_EQ(1u, nvs.erases);
  uint32_t floor;
  bool found;
  ASSERT_TRUE(nvs.readFloor(floor, found));
  EXPECT_FALSE(found);
  EXPECT_EQ(0u, floor);
  EXPECT_EQ(kEsp32Ok, esp32NvsStartupInitResult(kEsp32Ok));
  EXPECT_EQ(-1, esp32NvsStartupInitResult(-1));
}

TEST_F(Esp32Product, OtaOffWrapperForwardsOriginalNvsResultsAndPreservesArduinoStartupPolicy) {
  for (const auto error : {kEsp32NvsNoFreePages, kEsp32NvsNewVersionFound, kEsp32Ok, -1}) {
    CausalNvsModel nvs(sdk, 3);
    nvs.initError = error;
    const auto before = sdk.bytes;
    const bool formats = error == kEsp32NvsNoFreePages || error == kEsp32NvsNewVersionFound;
    EXPECT_EQ(formats ? kEsp32Ok : error, nvs.initArduinoNvs(false));
    EXPECT_EQ(formats ? 1u : 0u, nvs.erases);
    EXPECT_EQ(!formats, nvs.floorKnown);
    if (formats) {
      const auto partition = Esp32S3PartitionLayout::entry(0);
      EXPECT_TRUE(std::equal(before.begin(), before.begin() + partition.address, sdk.bytes.begin()));
      EXPECT_TRUE(std::equal(before.begin() + partition.address + partition.size, before.end(),
                            sdk.bytes.begin() + partition.address + partition.size));
    } else {
      EXPECT_EQ(before, sdk.bytes);
    }
  }
}

TEST_F(Esp32Product, MissingTrialStateWithDifferentSelectedAppBlocksWritesAndRestartsToExistingAppOnce) {
  thirdTrial();
  ASSERT_FALSE(HasFatalFailure());
  const auto previous = sdk.snapshot.next;
  const auto failed_trial = sdk.snapshot.running;
  sdk.snapshot.boot = previous;
  sdk.snapshot.appStates[failed_trial.subtype - 0x10] = Esp32ImageState::Undefined;
  CausalNvsModel nvs(sdk, 2);
  CausalTrialModel platform(sdk, nvs, policy, signatures);
  const auto before = sdk.bytes;
  Esp32TrialController controller(platform);
  EXPECT_FALSE(controller.begin(0));
  EXPECT_TRUE(controller.activeOrUnknown());
  EXPECT_EQ(Esp32TrialHealthOutcome::StateUnreadable, controller.tick(0, false, false, false));
  EXPECT_EQ(0u, platform.rollbacks);
  EXPECT_EQ(1u, platform.resets);
  EXPECT_TRUE(esp32PartitionEquals(previous, sdk.snapshot.running));
  EXPECT_EQ(Esp32ImageState::Valid, sdk.snapshot.appStates[previous.subtype - 0x10]);
  EXPECT_EQ(before, sdk.bytes);
  CausalTrialModel recovered(sdk, nvs, policy, signatures);
  Esp32TrialController next(recovered);
  EXPECT_TRUE(next.begin(0));
  EXPECT_FALSE(next.activeOrUnknown());
  EXPECT_EQ(Esp32TrialHealthOutcome::Pending, next.tick(60000, true, true, true));
  EXPECT_EQ(0u, recovered.resets);
  sdk.snapshot.appStates[previous.subtype - 0x10] = Esp32ImageState::Undefined;
  CausalTrialModel stock(sdk, nvs, policy, signatures);
  Esp32TrialController usb_stock(stock);
  EXPECT_TRUE(usb_stock.begin(0));
  EXPECT_FALSE(usb_stock.activeOrUnknown());
  EXPECT_EQ(0u, stock.arms);
  EXPECT_EQ(before, sdk.bytes);
}

TEST_F(Esp32Product, UsbBootApp0ReflashWithBlankTailPreservesFloorAndConfiguresNewerAuthenticatedOta) {
  successiveInstall(1);
  ASSERT_FALSE(HasFatalFailure());
  usbReflash(Esp32S3PartitionLayout::entry(2), true);
  const auto floor = install.floor;
  const auto floor_saves = install.floorSaveCalls;
  const auto before = sdk.bytes;
  Esp32OtaStagingSink cold_sink(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  OtaFirmwareIntegration cold;
  ASSERT_EQ(Esp32ConfigureOutcome::Configured, configure(cold, cold_sink));
  EXPECT_TRUE(cold.backendAvailable());
  EXPECT_TRUE(cold.leanReceiver().hasStore());
  EXPECT_EQ(OtaCandidateStore::Phase::Idle, cold.leanReceiver().status().phase);
  EXPECT_EQ(floor, policy.confirmedCounter);
  EXPECT_EQ(floor, install.floor);
  EXPECT_EQ(floor_saves, install.floorSaveCalls);
  EXPECT_FALSE(cold_sink.storageIoFaultObserved());
  EXPECT_EQ(0, std::memcmp(before.data() + sdk.snapshot.running.address,
                           sdk.bytes.data() + sdk.snapshot.running.address, Esp32OtaPolicy::kSlotBytes));
  attachBootReadback(cold);
  EXPECT_NE(usb::UsbOtaPhase::Installed, cold.reportedPhase());
  EXPECT_EQ(Result::Denied, cold.leanReceiver().begin(owner.publicKey(), canonical, signature, true, false));
  descriptor.securityCounter = 2;
  signDescriptor();
  const auto writes = sdk.writeCalls;
  admin = false;
  EXPECT_EQ(Result::Denied, cold.leanReceiver().begin(owner.publicKey(), canonical, signature, false, false));
  admin = true;
  uint8_t other_seed[32] = {0x91};
  Ed25519TestSigner other(other_seed);
  uint8_t other_signature[64];
  other.sign(canonical, sizeof(canonical), other_signature);
  EXPECT_EQ(Result::Denied, cold.leanReceiver().begin(other.publicKey(), canonical, other_signature, false, false));
  EXPECT_EQ(writes, sdk.writeCalls);
  installConfigured(cold, cold_sink, 2);
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(2u, install.floor);
  EXPECT_EQ(2u, install.selections);
}

TEST_F(Esp32Product, UsbDifferentImageWithStaleSignedRunningTailRecoversBothSlotParitiesWithoutFloorErase) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  for (const uint32_t expected_running : {0x10000u, 0x340000u}) {
    ASSERT_EQ(expected_running, sdk.snapshot.running.address);
    const uint32_t floor = install.floor;
    const auto floor_saves = install.floorSaveCalls;
    usbReflash(sdk.snapshot.running, false);
    uint32_t counter = 99;
    EXPECT_EQ(Esp32RunningProof::NotProven, install.runningProof(counter));
    EXPECT_EQ(0u, counter);
    const auto before = sdk.bytes;
    Esp32OtaStagingSink cold_sink(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
    OtaFirmwareIntegration cold;
    ASSERT_EQ(Esp32ConfigureOutcome::Configured, configure(cold, cold_sink));
    EXPECT_EQ(OtaCandidateStore::Phase::Idle, cold.leanReceiver().status().phase);
    EXPECT_EQ(floor, install.floor);
    EXPECT_EQ(floor, policy.confirmedCounter);
    EXPECT_EQ(floor_saves, install.floorSaveCalls);
    EXPECT_FALSE(cold_sink.storageIoFaultObserved());
    EXPECT_EQ(0, std::memcmp(before.data() + expected_running, sdk.bytes.data() + expected_running,
                            Esp32OtaPolicy::kSlotBytes));
    attachBootReadback(cold);
    EXPECT_FALSE(cold.bootLifecycle().imageVerified);
    EXPECT_NE(usb::UsbOtaPhase::Installed, cold.reportedPhase());
    installConfigured(cold, cold_sink, floor + 1);
    ASSERT_FALSE(HasFatalFailure());
    EXPECT_EQ(floor + 1, install.floor);
  }
  EXPECT_EQ(4u, install.selections);
}

TEST_F(Esp32Product, ConfigurationAdvancesFloorOnlyForVerifiedSdkValidRunningImage) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  const auto original = sdk.bytes;
  const auto stable = sdk.snapshot;
  install.floor = 1;
  for (const uint32_t signature_byte : {120u, 88u}) {
    sdk.bytes = original;
    sdk.snapshot = stable;
    alterStoredProvenance(sdk.snapshot.running, signature_byte);
    const auto saves = install.floorSaveCalls;
    Esp32OtaStagingSink cold_sink(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
    OtaFirmwareIntegration cold;
    ASSERT_EQ(Esp32ConfigureOutcome::Configured, configure(cold, cold_sink));
    EXPECT_EQ(1u, install.floor);
    EXPECT_EQ(saves, install.floorSaveCalls);
  }
  sdk.bytes = original;
  sdk.snapshot = stable;
  sdk.snapshot.appStates[0] = Esp32ImageState::Undefined;
  {
    const auto saves = install.floorSaveCalls;
    Esp32OtaStagingSink cold_sink(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
    OtaFirmwareIntegration cold;
    ASSERT_EQ(Esp32ConfigureOutcome::Configured, configure(cold, cold_sink));
    EXPECT_EQ(1u, install.floor);
    EXPECT_EQ(saves, install.floorSaveCalls);
  }
  sdk.bytes = original;
  sdk.snapshot = stable;
  Esp32OtaStagingSink cold_sink(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  OtaFirmwareIntegration cold;
  ASSERT_EQ(Esp32ConfigureOutcome::Configured, configure(cold, cold_sink));
  EXPECT_EQ(2u, install.floor);
  EXPECT_EQ(2u, policy.confirmedCounter);
}

TEST_F(Esp32Product, ConfigurationStillRefusesTrialUnknownIoAndChangedFloorWithoutAttachingBackend) {
  successiveInstall(1);
  ASSERT_FALSE(HasFatalFailure());
  usbReflash(Esp32S3PartitionLayout::entry(2), true);
  const auto stable = sdk.snapshot;
  const auto before = sdk.bytes;
  const auto writes = sdk.writeCalls;
  const auto erases = sdk.erasedOffsets;
  const auto saves = install.floorSaveCalls;
  const auto refused = [&](Esp32ConfigureOutcome expected, bool trial_or_unknown = false) {
    Esp32OtaStagingSink cold_sink(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
    OtaFirmwareIntegration cold;
    EXPECT_EQ(expected, configure(cold, cold_sink, trial_or_unknown));
    EXPECT_EQ(before, sdk.bytes);
    EXPECT_EQ(writes, sdk.writeCalls);
    EXPECT_EQ(erases, sdk.erasedOffsets);
    EXPECT_EQ(1u, install.floor);
    EXPECT_EQ(saves, install.floorSaveCalls);
  };
  refused(Esp32ConfigureOutcome::Refused, true);
  for (size_t slot = 0; slot < 2; ++slot) {
    for (const auto state : {Esp32ImageState::New, Esp32ImageState::PendingVerify,
                             static_cast<Esp32ImageState>(0x7f)}) {
      sdk.snapshot.appStates[slot] = state;
      refused(Esp32ConfigureOutcome::Refused);
      sdk.snapshot = stable;
    }
  }
  sdk.snapshot.boot = sdk.snapshot.next;
  refused(Esp32ConfigureOutcome::Refused);
  sdk.snapshot = stable;
  sdk.inspectError = -1;
  refused(Esp32ConfigureOutcome::IoError);
  sdk.inspectError = kEsp32Ok;
  for (const uint32_t partition : {sdk.snapshot.running.address, sdk.snapshot.next.address}) {
    sdk.readErrorPartition = partition;
    refused(Esp32ConfigureOutcome::IoError);
    sdk.readErrorPartition = 0;
  }
  // A failure in an otherwise unused record must not be mistaken for blank metadata.
  sdk.readErrorCall = sdk.readCalls + 16 + 16;
  refused(Esp32ConfigureOutcome::IoError);
  sdk.readErrorCall = 0;
  install.floorReadable = false;
  refused(Esp32ConfigureOutcome::IoError);
  install.floorReadable = true;
  install.floorErrorCall = install.floorReadCalls + 3;
  refused(Esp32ConfigureOutcome::IoError);
  install.floorErrorCall = 0;
  install.floorChangedCall = install.floorReadCalls + 3;
  install.changedFloor = 2;
  refused(Esp32ConfigureOutcome::Refused);
  install.floorChangedCall = 0;
}

TEST_F(Esp32Product, UsbRecoveryPreservesLiveNewerCandidateAndItsOwnerLock) {
  successiveInstall(1);
  ASSERT_FALSE(HasFatalFailure());
  usbReflash(Esp32S3PartitionLayout::entry(2), true);
  Esp32OtaStagingSink first(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  OtaFirmwareIntegration receiving;
  ASSERT_EQ(Esp32ConfigureOutcome::Configured, configure(receiving, first));
  descriptor.securityCounter = 2;
  signDescriptor();
  ASSERT_EQ(Result::Ok, receiving.leanReceiver().begin(owner.publicKey(), canonical, signature, false, false));
  const auto active = receiving.leanReceiver().status();
  const auto before = sdk.bytes;
  Esp32OtaStagingSink resumed(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  OtaFirmwareIntegration cold;
  ASSERT_EQ(Esp32ConfigureOutcome::Configured, configure(cold, resumed));
  EXPECT_EQ(OtaCandidateStore::Phase::Receiving, cold.leanReceiver().status().phase);
  EXPECT_EQ(active.transactionNonce, cold.leanReceiver().status().transactionNonce);
  EXPECT_EQ(before, sdk.bytes);
  descriptor.securityCounter = 3;
  image[1] = 3;
  ::ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
  signDescriptor();
  const auto writes = sdk.writeCalls;
  const auto erases = sdk.erasedOffsets;
  EXPECT_EQ(Result::Busy, cold.leanReceiver().begin(owner.publicKey(), canonical, signature, false, false));
  EXPECT_EQ(writes, sdk.writeCalls);
  EXPECT_EQ(erases, sdk.erasedOffsets);
  EXPECT_EQ(active.transactionNonce, cold.leanReceiver().status().transactionNonce);
  EXPECT_EQ(1u, install.floor);
}

TEST_F(Esp32Product, UsbRecoveryDoesNotRetireNewerCommitOrUnsuccessfulSelection) {
  successiveInstall(1);
  ASSERT_FALSE(HasFatalFailure());
  usbReflash(Esp32S3PartitionLayout::entry(2), true);
  Esp32OtaStagingSink receiving_sink(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  OtaFirmwareIntegration receiving;
  ASSERT_EQ(Esp32ConfigureOutcome::Configured, configure(receiving, receiving_sink));
  descriptor.securityCounter = 2;
  signDescriptor();
  ready(receiving);
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit(receiving));
  const auto committed = receiving.leanReceiver().status();
  {
    Esp32OtaStagingSink resumed(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
    OtaFirmwareIntegration cold;
    ASSERT_EQ(Esp32ConfigureOutcome::Configured, configure(cold, resumed));
    EXPECT_EQ(OtaCandidateStore::Phase::Committed, cold.leanReceiver().status().phase);
    EXPECT_EQ(committed.transactionNonce, cold.leanReceiver().status().transactionNonce);
    EXPECT_EQ(1u, install.selections);
  }
  ASSERT_EQ(FlashStatus::Ok, metadata.program(Esp32OtaStagingSink::kSelectionMarkerOffset,
                                             Esp32OtaStagingSink::kSelectionMarker, 4));
  Esp32OtaStagingSink failed_sink(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  OtaFirmwareIntegration failed;
  ASSERT_EQ(Esp32ConfigureOutcome::Configured, configure(failed, failed_sink));
  EXPECT_EQ(OtaCandidateStore::Phase::Failed, failed.leanReceiver().status().phase);
  EXPECT_EQ(committed.transactionNonce, failed.leanReceiver().status().transactionNonce);
  EXPECT_EQ(InstallOutcome::None, failed_sink.activateDurableCommit());
  descriptor.securityCounter = 3;
  image[1] = 3;
  ::ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
  signDescriptor();
  const auto before = sdk.bytes;
  EXPECT_EQ(Result::Busy, failed.leanReceiver().begin(owner.publicKey(), canonical, signature, false, false));
  EXPECT_EQ(before, sdk.bytes);
  EXPECT_EQ(1u, install.floor);
  EXPECT_EQ(1u, install.selections);
}

TEST_F(Esp32Product, ConfigurationFloorWriteFailureDoesNotAttachOrRetireCandidate) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  install.floor = 1;
  install.floorWritable = false;
  const auto before = sdk.bytes;
  Esp32OtaStagingSink cold_sink(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  OtaFirmwareIntegration cold;
  EXPECT_EQ(Esp32ConfigureOutcome::IoError, configure(cold, cold_sink));
  EXPECT_EQ(before, sdk.bytes);
  EXPECT_EQ(1u, install.floor);
  EXPECT_FALSE(cold.backendAvailable());
  EXPECT_FALSE(cold.leanReceiver().hasStore());
}

TEST_F(Esp32Product, ColdBootRealProvenanceProjectsTrialAndInstalledIntoUsbAbi2AndRfCensusWithoutWritableBackend) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  const auto original = receiver().status();
  ASSERT_EQ(InstallOutcome::Selected, sink.activateDurableCommit());
  rebootIntoCandidate(Esp32ImageState::PendingVerify);
  OtaFirmwareIntegration cold;
  attachBootReadback(cold);
  const auto before = sdk.bytes;
  const auto writes = sdk.writeCalls;
  const auto erases = sdk.erasedOffsets;
  const auto selections = install.selections;
  for (const auto phase : {usb::UsbOtaPhase::Trial, usb::UsbOtaPhase::Installed}) {
    if (phase == usb::UsbOtaPhase::Installed) {
      sdk.snapshot.appStates[sdk.snapshot.running.subtype - 0x10] = Esp32ImageState::Valid;
      install.floorKnown = true;
      install.floor = descriptor.securityCounter;
    }
    EXPECT_FALSE(cold.backendAvailable());
    EXPECT_FALSE(cold.leanReceiver().hasStore());
    EXPECT_FALSE(cold.leanReceiver().status().valid);
    const auto boot = cold.bootLifecycle();
    ASSERT_TRUE(boot.imageVerified);
    EXPECT_EQ(phase, boot.phase);
    EXPECT_EQ(original.transactionNonce, boot.transactionNonce);
    const auto view = cold.readback();
    ASSERT_TRUE(view.snapshot.valid);
    EXPECT_TRUE(view.bootCandidate);
    EXPECT_EQ(phase, view.phase);
    EXPECT_EQ(original.transactionNonce, view.snapshot.transactionNonce);
    EXPECT_EQ(original.counter, view.snapshot.counter);
    EXPECT_EQ(original.generation, view.snapshot.generation);
    EXPECT_EQ(0, std::memcmp(original.ownerPublicKey, view.snapshot.ownerPublicKey, 32));
    EXPECT_EQ(0, std::memcmp(original.imageHash, view.snapshot.imageHash, 32));
    EXPECT_EQ(0, std::memcmp(original.manifestHash, view.snapshot.manifestHash, 32));

    usb::UsbOtaReply reply;
    reply.setNoSnapshot();
    cold.fillUsbReadback(reply);
    uint8_t encoded[usb::kReplyBytes];
    ASSERT_EQ(90u, usb::encodeUsbOtaReply(reply, encoded));
    EXPECT_NE(0, encoded[5] & usb::kReplyFlagSnapshotValid);
    EXPECT_EQ(static_cast<uint8_t>(phase), encoded[4]);
    EXPECT_EQ(0, std::memcmp(original.manifestHash, encoded + 38, 32));
    EXPECT_EQ(original.totalBlocks, usb::getBE16(encoded + 70));
    EXPECT_EQ(original.totalBlocks, usb::getBE16(encoded + 72));
    EXPECT_EQ(original.counter, usb::getBE32(encoded + 74));
    EXPECT_EQ(0u, usb::getBE32(encoded + 78));
    EXPECT_EQ(original.generation, usb::getBE32(encoded + 86));

    uint8_t poll[kOtaCensusPollBytes], frame[kOtaCensusReportBytes];
    ASSERT_EQ(sizeof(poll), encodeOtaCensusPoll(target, original.manifestHash, 0, poll, sizeof(poll)));
    ASSERT_TRUE(cold.handleReceivedFrame(poll, sizeof(poll), 1000));
    size_t len = 0;
    ASSERT_TRUE(cold.peekOutboundControlFrame(frame, sizeof(frame), len, 1250));
    cold.releaseOutboundControlFrame();
    OtaCensusReport report;
    ASSERT_TRUE(parseOtaCensusReport(frame, len, report));
    ASSERT_TRUE(report.haveLifecycle);
    EXPECT_EQ(0, std::memcmp(target, report.reporter, 32));
    EXPECT_EQ(0, std::memcmp(original.manifestHash, report.manifestHash, 32));
    EXPECT_EQ(phase, report.lifecyclePhase);
    EXPECT_EQ(static_cast<uint8_t>(OtaCandidateStore::Phase::Committed), report.phase);
    EXPECT_EQ(original.counter, report.counter);
    EXPECT_EQ(original.totalBlocks, report.received);
    EXPECT_EQ(original.totalBlocks, report.total);
    EXPECT_EQ(original.generation, report.generation);
    EXPECT_EQ(boot.floorKnown, report.floorKnown);
    EXPECT_EQ(boot.confirmedFloor, report.confirmedFloor);
    for (size_t bit = 0; bit < kOtaCensusWindowBlocks; ++bit)
      EXPECT_EQ(bit < original.totalBlocks, (report.bitmap[bit / 8] & (1u << (bit % 8))) != 0);

    poll[33] ^= 1;
    EXPECT_FALSE(cold.readback(boot, poll + 33).snapshot.valid);
    ASSERT_TRUE(cold.handleReceivedFrame(poll, sizeof(poll), 1500));
    EXPECT_FALSE(cold.peekOutboundControlFrame(frame, sizeof(frame), len, 1750));
    EXPECT_EQ(Result::Unavailable, cold.leanReceiver().begin(owner.publicKey(), canonical, signature, false, false));
    EXPECT_EQ(Result::NotFound, cold.leanReceiver().commit(descriptor.securityCounter, signature));
    EXPECT_FALSE(cold.leanReceiver().status().valid);
  }
  install.floorKnown = false;
  EXPECT_NE(usb::UsbOtaPhase::Installed, cold.readback().phase);
  install.floorKnown = true;
  install.floorReadable = false;
  EXPECT_FALSE(cold.readback().snapshot.valid);
  install.floorReadable = true;
  sdk.readErrorPartition = sdk.snapshot.running.address;
  EXPECT_FALSE(cold.readback().snapshot.valid);
  sdk.readErrorPartition = 0;
  sdk.bytes[sdk.snapshot.running.address + 7] ^= 1;
  EXPECT_FALSE(cold.readback().snapshot.valid);
  sdk.bytes = before;
  alterStoredProvenance(sdk.snapshot.running, 120);
  EXPECT_FALSE(cold.readback().snapshot.valid);
  sdk.bytes = before;
  ASSERT_EQ(usb::UsbOtaPhase::Installed, cold.readback().phase);
  EXPECT_EQ(before, sdk.bytes);
  EXPECT_EQ(writes, sdk.writeCalls);
  EXPECT_EQ(erases, sdk.erasedOffsets);
  EXPECT_EQ(selections, install.selections);
  EXPECT_FALSE(cold.backendAvailable());
  EXPECT_FALSE(cold.leanReceiver().hasStore());
  EXPECT_FALSE(cold.leanReceiver().status().valid);
}

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
  install.floorErrorCall = install.floorReadCalls + 2;
  expectRecoveryRefusal(recovery);
  install.floorErrorCall = 0;
  for (const uint32_t floor : {0u, 1u, 3u}) {
    install.floor = floor;
    expectRecoveryRefusal(recovery);
  }
  install.floor = 2;
  install.floorChangedCall = install.floorReadCalls + 2;
  install.changedFloor = 3;
  expectRecoveryRefusal(recovery);
  install.floorChangedCall = 0;
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
  for (const auto state : {Esp32ImageState::Invalid, Esp32ImageState::Aborted}) {
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
  uint32_t counter = 99;
  sdk.inspectErrorCall = sdk.inspectCalls + 2;
  EXPECT_EQ(Esp32RunningProof::IoError, readEsp32RunningProof(sdk, reader, policy, signatures, counter));
  EXPECT_EQ(0u, counter);
  sdk.inspectErrorCall = 0;
  ASSERT_EQ(Esp32RunningProof::Verified, readEsp32RunningProof(sdk, reader, policy, signatures, counter));
  EXPECT_EQ(2u, counter);
}

TEST_F(Esp32Product, RetirementKeepsInactiveSignatureRequiredButKnownNegativeRunningProofIsNotIo) {
  twoSuccessfulInstalls();
  ASSERT_FALSE(HasFatalFailure());
  const auto original = sdk.bytes;
  Esp32OtaStagingSink recovery(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  sdk.bytes[sdk.snapshot.running.address + 7] ^= 1;
  uint32_t counter = 99;
  EXPECT_EQ(Esp32RunningProof::NotProven, install.runningProof(counter));
  EXPECT_EQ(0u, counter);
  EXPECT_TRUE(recovery.recoverUnsuccessfulSelection());
  EXPECT_FALSE(recovery.storageIoFaultObserved());
  sdk.bytes = original;
  alterStoredProvenance(sdk.snapshot.running, 120);
  EXPECT_EQ(Esp32RunningProof::NotProven, install.runningProof(counter));
  EXPECT_EQ(0u, counter);
  EXPECT_TRUE(recovery.recoverUnsuccessfulSelection());
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
  ASSERT_FALSE(lifecycle(true, descriptor.securityCounter, boot));
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
  for (const auto state : {Esp32ImageState::Aborted, Esp32ImageState::Invalid}) {
    sdk.snapshot.appStates[1] = state;
    ASSERT_TRUE(lifecycle(false, 0, boot, true));
    EXPECT_EQ(usb::UsbOtaPhase::Failed, boot.phase);
    EXPECT_EQ(expected.transactionNonce, boot.transactionNonce);
    EXPECT_EQ(expected.counter, boot.counter);
    EXPECT_EQ(0, std::memcmp(expected.imageHash, boot.imageHash, 32));
    EXPECT_FALSE(boot.imageVerified);
    OtaCandidateStore::Snapshot projected;
    ASSERT_TRUE(bootCandidate(boot, false, 0, projected));
    EXPECT_EQ(0, std::memcmp(signature, projected.signature, sizeof(signature)));
    EXPECT_EQ(0, std::memcmp(canonical, projected.canonical, sizeof(canonical)));
    EXPECT_EQ(0, std::memcmp(owner.publicKey(), projected.ownerPublicKey, 32));
    auto mismatch = boot;
    mismatch.transactionNonce ^= 1;
    EXPECT_FALSE(bootCandidate(mismatch, false, 0, projected));
    mismatch = boot;
    ++mismatch.counter;
    EXPECT_FALSE(bootCandidate(mismatch, false, 0, projected));
    mismatch = boot;
    mismatch.imageHash[0] ^= 1;
    EXPECT_FALSE(bootCandidate(mismatch, false, 0, projected));
  }
  sdk.snapshot.appStates[1] = Esp32ImageState::Valid;
  EXPECT_FALSE(lifecycle(false, 0, boot, true));
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
}

TEST_F(Esp32Product, CompletedFailedProofRequiresClosedNontrialRunningSdkContext) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  ASSERT_EQ(InstallOutcome::Selected, sink.activateDurableCommit());
  sdk.snapshot.boot = sdk.snapshot.running;
  sdk.snapshot.appStates[1] = Esp32ImageState::Aborted;
  Esp32OtaStagingSink recovery(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  ASSERT_TRUE(recovery.recoverUnsuccessfulSelection());
  OtaBootLifecycleEvidence expected;
  ASSERT_TRUE(lifecycle(false, 0, expected, true));
  ASSERT_NE(0u, expected.transactionNonce);
  const auto context = sdk.snapshot;
  const auto before = sdk.bytes;
  OtaCandidateStore::Snapshot projected;
  OtaBootLifecycleEvidence boot;
  for (const auto state : {Esp32ImageState::New, Esp32ImageState::PendingVerify,
                           Esp32ImageState::Aborted, Esp32ImageState::Invalid,
                           static_cast<Esp32ImageState>(9)}) {
    sdk.snapshot.appStates[0] = state;
    EXPECT_FALSE(lifecycle(false, 0, boot, true));
    EXPECT_EQ(0u, boot.transactionNonce);
    EXPECT_FALSE(bootCandidate(expected, false, 0, projected));
    EXPECT_FALSE(projected.valid);
  }
  sdk.snapshot = context;
  sdk.snapshot.boot = sdk.snapshot.next;
  EXPECT_FALSE(lifecycle(false, 0, boot, true));
  EXPECT_FALSE(bootCandidate(expected, false, 0, projected));
  sdk.snapshot = context;
  sdk.snapshot.next = sdk.snapshot.running;
  EXPECT_FALSE(lifecycle(false, 0, boot, true));
  EXPECT_FALSE(bootCandidate(expected, false, 0, projected));
  sdk.snapshot = context;
  sdk.snapshot.appStates[0] = Esp32ImageState::Undefined;
  EXPECT_TRUE(lifecycle(false, 0, boot, true));
  EXPECT_TRUE(bootCandidate(expected, false, 0, projected));
  sdk.snapshot = context;
  for (const uint32_t call : {1u, 2u}) {
    sdk.inspectErrorCall = sdk.inspectCalls + call;
    EXPECT_FALSE(lifecycle(false, 0, boot, true));
    EXPECT_EQ(0u, boot.transactionNonce);
    sdk.inspectErrorCall = sdk.inspectCalls + call;
    EXPECT_FALSE(bootCandidate(expected, false, 0, projected));
    EXPECT_FALSE(projected.valid);
  }
  sdk.inspectErrorCall = 0;
  EXPECT_EQ(before, sdk.bytes);
  EXPECT_EQ(1u, install.selections);
}

TEST_F(Esp32Product, PriorSdkAbortCannotMakeNewFailedStagingACompletedSelection) {
  sdk.snapshot.appStates[1] = Esp32ImageState::Aborted;
  begin();
  image[7] ^= 1;
  receive();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Pending, receiver().requestSeal());
  integration.loop();
  ASSERT_EQ(OtaCandidateStore::Phase::Failed, receiver().status().phase);
  EXPECT_EQ(0u, install.selections);
  uint8_t marker[4];
  ASSERT_EQ(FlashStatus::Ok, metadata.read(Esp32OtaStagingSink::kSelectionMarkerOffset, marker, sizeof(marker)));
  for (const auto byte : marker) ASSERT_EQ(0xff, byte);
  for (const auto state : {Esp32ImageState::Aborted, Esp32ImageState::Invalid}) {
    sdk.snapshot.appStates[1] = state;
    OtaBootLifecycleEvidence boot;
    ASSERT_TRUE(lifecycle(false, 0, boot, true));
    EXPECT_EQ(0u, boot.transactionNonce);
    EXPECT_EQ(0u, boot.counter);
    const auto status = receiver().status();
    OtaBootLifecycleEvidence purported;
    purported.phase = usb::UsbOtaPhase::Failed;
    purported.transactionNonce = status.transactionNonce;
    purported.counter = status.counter;
    std::memcpy(purported.imageHash, status.imageHash, sizeof(purported.imageHash));
    OtaCandidateStore::Snapshot projected;
    EXPECT_FALSE(bootCandidate(purported, false, 0, projected));
    EXPECT_FALSE(projected.valid);
  }
}

TEST_F(Esp32Product, IncompleteSelectionMarkerNeverProvesTerminalFailureWithInheritedSdkAbort) {
  sdk.snapshot.appStates[1] = Esp32ImageState::Aborted;
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  const auto expected = receiver().status();
  sdk.writeFault = FaultTiming::Torn;
  sdk.tornBytes = 2;
  ASSERT_EQ(InstallOutcome::Refused, sink.activateDurableCommit());
  sdk.writeFault = FaultTiming::None;
  Esp32OtaStagingSink recovery(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  ASSERT_TRUE(recovery.recoverUnsuccessfulSelection());
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(false, 0, boot, true));
  EXPECT_EQ(0u, boot.transactionNonce);
  EXPECT_EQ(0u, boot.counter);
  boot.transactionNonce = expected.transactionNonce;
  boot.counter = expected.counter;
  std::memcpy(boot.imageHash, expected.imageHash, 32);
  OtaCandidateStore::Snapshot projected;
  EXPECT_FALSE(bootCandidate(boot, false, 0, projected));
  EXPECT_FALSE(projected.valid);
  EXPECT_EQ(0u, install.selections);
}

TEST_F(Esp32Product, TerminalAccessorRechecksSelectionMarkerAndRefusesMarkerReadIoAfterProof) {
  ready();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(Result::Ok, commit());
  ASSERT_EQ(InstallOutcome::Selected, sink.activateDurableCommit());
  sdk.snapshot.boot = sdk.snapshot.running;
  sdk.snapshot.appStates[1] = Esp32ImageState::Aborted;
  Esp32OtaStagingSink recovery(flash, lease, candidate, metadata, store, trust, policy, signatures, install);
  ASSERT_TRUE(recovery.recoverUnsuccessfulSelection());
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(lifecycle(false, 0, boot, true));
  ASSERT_NE(0u, boot.transactionNonce);
  OtaCandidateStore::Snapshot projected;
  ASSERT_TRUE(bootCandidate(boot, false, 0, projected));
  const uint32_t marker = sdk.snapshot.next.address + Esp32OtaPolicy::kCandidateBytes +
                          Esp32OtaStagingSink::kSelectionMarkerOffset;
  const auto before = sdk.bytes;
  sdk.bytes[marker + 3] = 0xff;
  EXPECT_FALSE(bootCandidate(boot, false, 0, projected));
  EXPECT_FALSE(projected.valid);
  sdk.bytes = before;
  // Sixteen record reads, two bitmap reads, then the selection-marker read.
  sdk.readErrorCall = sdk.readCalls + 19;
  EXPECT_FALSE(bootCandidate(boot, false, 0, projected));
  EXPECT_FALSE(projected.valid);
  sdk.readErrorCall = sdk.readCalls + 19;
  EXPECT_FALSE(lifecycle(false, 0, boot, true));
  EXPECT_EQ(0u, boot.transactionNonce);
  sdk.readErrorCall = 0;
  EXPECT_EQ(before, sdk.bytes);
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
  uint32_t arms = 0, remaining = 0, disarms = 0, confirmations = 0, resets = 0, unknownReports = 0;
  bool watchdog = false;
  bool runningState(Esp32ImageState& out) override { out = state; return readable; }
  bool unknownTopologyHoldAllowed() override { return false; }
  bool armWatchdog(uint32_t ms) override {
    ++arms; remaining = ms; watchdog = watchdogOk; return watchdogOk;
  }
  void disarmWatchdog() override { ++disarms; watchdog = false; }
  void reportUnknownService() override { ++unknownReports; }
  Esp32TrialConfirmation confirmHealthy() override {
    ++confirmations;
    if (confirmOk && persistValid) state = Esp32ImageState::Valid;
    return confirmOk ? Esp32TrialConfirmation::Confirmed : Esp32TrialConfirmation::Unconfirmed;
  }
  void restartWithoutRollback() override { ++resets; }
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
