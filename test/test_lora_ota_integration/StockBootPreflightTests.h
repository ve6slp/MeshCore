#pragma once

#include <helpers/ota/OtaTrialSafeIdentityBoot.h>

#define NRF52_PLATFORM
#define openWrite stockDataStoreOpenWrite
#include "../../examples/companion_radio/DataStore.cpp"
#undef openWrite
namespace stock_acl_test {
#include <helpers/ClientACL.cpp>
}
#undef NRF52_PLATFORM

// Identity operations are outside these ordinary-preference/contacts/cache tests.
bool IdentityStore::load(const char*, mesh::LocalIdentity&) { ADD_FAILURE() << "Unexpected identity load"; return false; }
bool IdentityStore::save(const char*, const mesh::LocalIdentity&) { ADD_FAILURE() << "Unexpected identity save"; return false; }
bool IdentityStore::checkIntegrity(const char*, mesh::LocalIdentity&) const {
  ADD_FAILURE() << "Unexpected identity integrity probe"; return false;
}

namespace {
using StockProof = mesh::ota::OtaBoardStockBootPreflight;
bool stock_cache_blocked = true;

struct StockBootFixture {
  LeanFixture fx;
  LifecycleImageAccessor active;
  RefusalRunningContext running{active.image};
  ::ota::test::FakeNorFlash journal_flash{32768, 4096};
  ::ota::platform::FlashRegion journal{journal_flash, 0, 32768};
  uint8_t seed[32] = {0x67};
  ::ota::test::Ed25519TestSigner owner{seed};
  OtaBoardBootQualification qualification;
  OtaBoardCacheOnlyBackend backend{fx.image_region, fx.candidate_store_region, +[]() { return stock_cache_blocked; }};
  StockBootFixture(uint32_t board = 0x584e3430, uint8_t role = 0) {
    uint8_t marker[60]; std::memset(marker, 0xff, sizeof(marker));
    ::ota::storage::XiaoOtaBootInfoReader::Info info;
    qualification = resolveOtaBoardBootQualificationFromRecordStatus(
        ::ota::storage::XiaoOtaBootInfoReader::classify(marker, sizeof(marker), info), info, board, role, 1);
    fx.admins.add(owner.publicKey());
    stock_cache_blocked = proof() != StockProof::Result::Healthy;
    EXPECT_TRUE(backend.attach(fx.integration, fx.sig_verifier));
  }
  StockProof::Result proof() {
    return StockProof::check(qualification, running, journal, fx.candidate_store_region, fx.sig_verifier);
  }
  void cache(::ota::storage::OtaCandidateStore::Phase phase) {
    const uint8_t image[40] = {0x57};
    uint8_t canonical[59], signature[64], begin[158] = {usb::kCommand, uint8_t(usb::UsbOtaOp::CacheBegin)};
    fx.buildSmallManifest(image, sizeof(image), canonical);
    owner.sign(canonical, sizeof(canonical), signature);
    std::memcpy(begin + 3, owner.publicKey(), 32);
    std::memcpy(begin + 35, canonical, 59); std::memcpy(begin + 94, signature, 64);
    ASSERT_EQ(usb::UsbOtaResult::Ok,
              fx.integration.leanReceiver().handleUsbCacheFrame(begin, sizeof(begin), owner.publicKey()));
    if (phase == ::ota::storage::OtaCandidateStore::Phase::Receiving) return;
    uint8_t put[45] = {usb::kCommand, uint8_t(usb::UsbOtaOp::CachePut), 0, 0, sizeof(image)};
    std::memcpy(put + 5, image, sizeof(image));
    ASSERT_EQ(usb::UsbOtaResult::Ok,
              fx.integration.leanReceiver().handleUsbCacheFrame(put, sizeof(put), owner.publicKey()));
    const uint8_t seal[] = {usb::kCommand, uint8_t(usb::UsbOtaOp::CacheSeal)};
    ASSERT_EQ(usb::UsbOtaResult::Pending,
              fx.integration.leanReceiver().handleUsbCacheFrame(seal, sizeof(seal), owner.publicKey()));
    fx.integration.leanReceiver().loop();
    ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, fx.integration.leanReceiver().status().phase);
    if (phase == ::ota::storage::OtaCandidateStore::Phase::Aborted) {
      const auto status = fx.integration.leanReceiver().status();
      uint8_t message[usb::kAbortSignedBytes];
      usb::buildAbortSignedMessage(fx.target_public_key, status.imageHash, message);
      owner.sign(message, sizeof(message), signature);
      ASSERT_EQ(usb::UsbOtaResult::Ok,
                fx.integration.leanReceiver().abort(owner.publicKey(), signature, status.imageHash));
    }
  }
};

struct StockDataHost : DataStoreHost {
  ContactInfo contact{};
  ChannelDetails channel{};
  bool onContactLoaded(const ContactInfo&) override { return true; }
  bool onChannelLoaded(uint8_t, const ChannelDetails&) override { return true; }
  bool getContactForSave(uint32_t index, ContactInfo& out) override {
    if (index) return false; out = contact; return true;
  }
  bool getChannelForSave(uint8_t index, ChannelDetails& out) override {
    if (index) return false; out = channel; return true;
  }
};
}

TEST(LoraOtaStockBoot, PositiveSdkBlankInstallJournalAndAuthenticatedCacheDriveRealDataStoreBootLatchAndPersistence) {
  using Phase = ::ota::storage::OtaCandidateStore::Phase;
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1}) {
    for (Phase phase : {Phase::Idle, Phase::Receiving, Phase::Ready, Phase::Aborted}) {
      SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role) << '/' << unsigned(phase));
      StockBootFixture f(board, role);
      if (phase != Phase::Idle) f.cache(phase);
      ASSERT_FALSE(HasFatalFailure());
      Adafruit_LittleFS filesystem;
      const std::vector<uint8_t> identity(96, 0x71);
      filesystem.files["/_main.id"] = std::make_shared<std::vector<uint8_t>>(identity);
      const bool early_trial_or_unknown = f.proof() != StockProof::Result::Healthy;
      ASSERT_FALSE(early_trial_or_unknown);
      ASSERT_EQ(0u, filesystem.mounts);
      ASSERT_TRUE(filesystem.begin());
      PacketBoundaryRtc clock;
      DataStore store(filesystem, clock);
      store.begin(!early_trial_or_unknown, false);
      ASSERT_FALSE(store.destructiveWritesDisallowed());
      NodePrefs prefs;
      std::strcpy(prefs.node_name, "OTA-LAB-CLIENT");
      ASSERT_TRUE(store.savePrefs(prefs));
      NodePrefs readback;
      ASSERT_TRUE(store.loadPrefs(readback, !early_trial_or_unknown));
      EXPECT_STREQ("OTA-LAB-CLIENT", readback.node_name);
      StockDataHost host;
      ASSERT_TRUE(store.saveContacts(&host)); ASSERT_TRUE(store.saveChannels(&host));
      EXPECT_TRUE(filesystem.exists("/contacts3")); EXPECT_TRUE(filesystem.exists("/channels2"));
      stock_acl_test::ClientACL acl;
      ASSERT_NE(nullptr, acl.putClient(mesh::Identity(f.owner.publicKey()), PERM_ACL_ADMIN));
      if (!early_trial_or_unknown) acl.save(&filesystem);
      ASSERT_TRUE(filesystem.exists("/s_contacts"));
      EXPECT_EQ(PERM_ACL_ADMIN, filesystem.files.at("/s_contacts")->at(32));
      EXPECT_TRUE(store.formatDisallowed()); EXPECT_FALSE(store.formatFileSystem());
      EXPECT_EQ(0u, filesystem.formats);
      EXPECT_EQ(identity, *filesystem.files.at("/_main.id"));
      EXPECT_FALSE(f.qualification.qualified);
      EXPECT_EQ(OtaBoardQualificationStatus::Unknown, f.qualification.status);
      EXPECT_EQ(0u, f.journal_flash.programOpCount());
      EXPECT_EQ(0u, f.journal_flash.eraseOpCount());
      EXPECT_EQ(StockProof::Result::Healthy, f.proof());
      if (phase == Phase::Ready) {
        const auto status = f.fx.integration.leanReceiver().status();
        uint8_t message[usb::kCommitSignedBytes], signature[64];
        usb::buildCommitSignedMessage(f.fx.target_public_key, status.manifestHash, status.counter, message);
        f.owner.sign(message, sizeof(message), signature);
        EXPECT_EQ(usb::UsbOtaResult::Denied, f.fx.integration.leanReceiver().commit(status.counter, signature));
      }
    }

  }
}

TEST(LoraOtaStockBoot, UnprovenStockCacheAttachmentNeverBecomesReceiverOrInstallAuthorityOrErasesOwnedBytes) {
  for (const uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1}) {
    for (int fault = 0; fault < 3; ++fault) {
      StockBootFixture f(board, role);
      if (fault == 0) f.running.badCrc = true;
      if (fault == 1) f.qualification.reason = OtaBoardQualificationReason::CorruptMarker;
      if (fault == 2) {
        const uint8_t byte = 0;
        ASSERT_TRUE(::ota::platform::isOk(f.journal.program(8192, &byte, 1)));
      }
      OtaFirmwareIntegration integration;
      stock_cache_blocked = f.proof() != StockProof::Result::Healthy;
      ASSERT_TRUE(stock_cache_blocked);
      EXPECT_FALSE(!stock_cache_blocked && f.backend.attach(integration, f.fx.sig_verifier));
      EXPECT_FALSE(integration.backendAvailable());
      const uint8_t image[40] = {0x38};
      uint8_t canonical[59], signature[64];
      f.fx.buildSmallManifest(image, sizeof(image), canonical);
      f.owner.sign(canonical, sizeof(canonical), signature);
      EXPECT_EQ(usb::UsbOtaResult::Unavailable, integration.leanReceiver().begin(
          f.owner.publicKey(), canonical, signature, false, true, true));
      EXPECT_EQ(0u, f.fx.image_flash.eraseOpCount());
      EXPECT_EQ(0u, f.fx.candidate_flash.eraseOpCount());
      EXPECT_EQ(0u, f.journal_flash.eraseOpCount());
    }
  }
}

TEST(LoraOtaStockBoot, MarkerSdkPendingBankAndInstallJournalFailuresBlockBeforeFilesystemAndKeepRealDataStoreReadOnly) {
  using Flash = ::ota::test::FakeNorFlash;
  for (int fault = 0; fault < 16; ++fault) {
    SCOPED_TRACE(fault);
    StockBootFixture f;
    if (fault == 0) f.qualification.reason = OtaBoardQualificationReason::CorruptMarker;
    if (fault == 1) f.qualification.reason = OtaBoardQualificationReason::RoleOrCapabilityMismatch;
    if (fault == 2) { f.qualification.qualified = true; f.qualification.status = OtaBoardQualificationStatus::Qualified; }
    if (fault == 3) f.running.invalid = true;
    if (fault == 4) f.running.badCrc = true;
    if (fault == 5) f.running.bank1 = 1;
    if (fault == 6) f.running.tailErased = false;
    if (fault == 7) f.running.fail = true;
    if (fault == 8) f.running.failAt = f.running.reads + 2;
    if (fault == 9) f.running.changeAt = f.running.reads + 2;
    if (fault >= 10 && fault <= 12) {
      const uint8_t byte = 0;
      ASSERT_TRUE(::ota::platform::isOk(f.journal.program((fault - 10) * 8192, &byte, 1)));
    }
    if (fault == 13) f.journal_flash.armFault({Flash::OpKind::Read, Flash::InjectionTiming::Before,
                                               f.journal_flash.readOpCount() + 1});
    if (fault == 14) f.fx.candidate_flash.armFault({Flash::OpKind::Read, Flash::InjectionTiming::Before,
                                                    f.fx.candidate_flash.readOpCount() + 1});
    if (fault == 15) {
      const uint8_t byte = 0;
      ASSERT_TRUE(::ota::platform::isOk(f.journal.program(3 * 8192, &byte, 1)));
    }
    const bool early_trial_or_unknown = f.proof() != StockProof::Result::Healthy;
    ASSERT_TRUE(early_trial_or_unknown);
    Adafruit_LittleFS filesystem;
    EXPECT_EQ(0u, filesystem.mounts);
    PacketBoundaryRtc clock; DataStore store(filesystem, clock);
    store.begin(!early_trial_or_unknown, false);
    ASSERT_TRUE(store.destructiveWritesDisallowed());
    const auto writes = filesystem.writes, removes = filesystem.removes;
    NodePrefs prefs; std::strcpy(prefs.node_name, "unchanged");
    EXPECT_FALSE(store.savePrefs(prefs));
    StockDataHost host; EXPECT_FALSE(store.saveContacts(&host)); EXPECT_FALSE(store.saveChannels(&host));
    stock_acl_test::ClientACL acl;
    ASSERT_NE(nullptr, acl.putClient(mesh::Identity(f.owner.publicKey()), PERM_ACL_ADMIN));
    if (!early_trial_or_unknown) acl.save(&filesystem);
    EXPECT_FALSE(filesystem.exists("/s_contacts"));
    EXPECT_EQ(writes, filesystem.writes); EXPECT_EQ(removes, filesystem.removes);
    EXPECT_STREQ("unchanged", prefs.node_name);
    EXPECT_EQ(0u, f.journal_flash.eraseOpCount());
  }
}

TEST(LoraOtaStockBoot, TornNoncacheCommittedUnsignedAndOrphanBitmapMetadataNeverGrantOrdinaryWriteProof) {
  using Store = ::ota::storage::OtaCandidateStore;
  for (int fault = 0; fault < 10; ++fault) {
    SCOPED_TRACE(fault);
    StockBootFixture f;
    f.cache(Store::Phase::Ready); ASSERT_FALSE(HasFatalFailure());
    Store::Snapshot snapshot; ASSERT_TRUE(f.fx.candidate_store.load(snapshot));
    if (fault == 0) snapshot.localCache = false;
    if (fault == 1) snapshot.phase = Store::Phase::Committed;
    if (fault == 2) snapshot.signature[0] ^= 1;
    if (fault < 3) ASSERT_TRUE(f.fx.candidate_store.append(snapshot));
    if (fault == 3) {
      const uint8_t byte = 0;
      ASSERT_TRUE(::ota::platform::isOk(f.fx.candidate_store_region.program(2 * Store::kRecordBytes, &byte, 1)));
    }

    if (fault == 4) ASSERT_TRUE(::ota::platform::isOk(f.fx.candidate_store_region.eraseSector(0)));
    if (fault == 5) ASSERT_TRUE(f.fx.candidate_store.clearBitmap());
    if (fault >= 6) {
      OtaDescriptor descriptor;
      ASSERT_EQ(OtaDescriptorCodecResult::Ok, decodeOtaDescriptorCanonical(snapshot.canonical, 59, descriptor));
      if (fault == 6) descriptor.formatId = 2;
      if (fault == 7) descriptor.algorithmId = 2;
      if (fault == 8) descriptor.keyId = 0;
      if (fault == 9) descriptor.appAddress = 0;
      size_t size = 0;
      ASSERT_EQ(OtaDescriptorCodecResult::Ok, encodeOtaDescriptorCanonical(descriptor, snapshot.canonical, 59, size));
      f.owner.sign(snapshot.canonical, 59, snapshot.signature);
      ASSERT_TRUE(f.fx.candidate_store.append(snapshot));
    }
    EXPECT_EQ(StockProof::Result::InvalidCache, f.proof());
  }
}

TEST(LoraOtaStockBoot, GenuineQualifiedTrialRemainsReadOnlyBeforeFilesystemMountAndNeverGeneratesIdentity) {
  LifecycleFixture boot;
  boot.setState(::ota::storage::XiaoOtaStateReader::kPhaseTrialBoot);
  ::ota::test::FakeNorFlash confirm_flash(8192, 4096);
  ::ota::platform::FlashRegion confirm(confirm_flash, 0, 8192);
  OtaBoardTrialBootHealthConfirmer confirmer(boot.state, confirm, boot.accessor, 0);
  const auto decision = resolveOtaBoardStartupDecision(
      true, confirmer.stateReadStatus(), confirmer.statePhase());
  ASSERT_EQ(OtaBoardStartupDecisionStatus::Trial, decision.status);
  const bool early_trial_or_unknown = decision.status != OtaBoardStartupDecisionStatus::Normal;
  Adafruit_LittleFS filesystem;
  ASSERT_EQ(0u, filesystem.mounts);
  PacketBoundaryRtc clock; DataStore store(filesystem, clock);
  store.begin(!early_trial_or_unknown, false);
  NodePrefs prefs; std::strcpy(prefs.node_name, "preserved");
  EXPECT_FALSE(store.savePrefs(prefs));
  EXPECT_TRUE(filesystem.files.empty());
  int generated = 0, saved = 0;
  EXPECT_EQ(ota_identity_boot::Outcome::IdentityUnavailable,
            ota_identity_boot::resolveIdentityTrialSafe(false, []() { return false; },
                [&]() { ++generated; }, [&]() { ++saved; return true; }));
  EXPECT_EQ(0, generated); EXPECT_EQ(0, saved);
  EXPECT_EQ(0u, filesystem.writes); EXPECT_EQ(0u, filesystem.formats);
}
