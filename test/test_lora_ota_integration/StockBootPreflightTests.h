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

struct StockRunningContext : RefusalRunningContext {
  bool vendorCrcDisabled = false;
  uint32_t sizeOverride = UINT32_MAX;
  explicit StockRunningContext(std::vector<uint8_t>& image) : RefusalRunningContext(image) {}
  bool read(OtaNrf52RunningContext& out) const override {
    if (!RefusalRunningContext::read(out)) return false;
    if (vendorCrcDisabled) out.settings[2] = out.settings[3] = 0;
    if (sizeOverride != UINT32_MAX) LifecycleFixture::le32(out.settings + 8, sizeOverride);
    return true;
  }
};

struct StockBootFixture {
  LeanFixture fx;
  LifecycleImageAccessor active;
  StockRunningContext running{active.image};
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
    return StockProof::check(qualification, running, journal);
  }
  StockProof::Result cacheProof() {
    return StockProof::checkCache(fx.candidate_store_region, fx.sig_verifier);
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
      usb::buildAbortSignedMessage(fx.target_public_key, status.imageHash, status.generation, message);
      owner.sign(message, sizeof(message), signature);
      ASSERT_EQ(usb::UsbOtaResult::Ok,
                fx.integration.leanReceiver().abort(owner.publicKey(), signature, status.imageHash, status.generation));
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

void expectOrdinaryStockWrites(StockBootFixture& f) {
  const bool early_trial_or_unknown = f.proof() != StockProof::Result::Healthy;
  ASSERT_FALSE(early_trial_or_unknown);
  Adafruit_LittleFS filesystem;
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
  ASSERT_TRUE(store.saveContacts(&host));
  ASSERT_TRUE(store.saveChannels(&host));
  stock_acl_test::ClientACL acl;
  ASSERT_NE(nullptr, acl.putClient(mesh::Identity(f.owner.publicKey()), PERM_ACL_ADMIN));
  acl.save(&filesystem);
  ASSERT_TRUE(filesystem.exists("/s_contacts"));
  EXPECT_EQ(PERM_ACL_ADMIN, filesystem.files.at("/s_contacts")->at(32));
  EXPECT_TRUE(store.formatDisallowed());
  EXPECT_FALSE(store.formatFileSystem());
  EXPECT_EQ(0u, filesystem.formats);
  EXPECT_FALSE(f.qualification.qualified);
  EXPECT_EQ(OtaBoardQualificationStatus::Unknown, f.qualification.status);
}
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
      EXPECT_EQ(StockProof::Result::Healthy, f.cacheProof());
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

TEST(LoraOtaStockBoot, VendorDisabledCrcAllowsRealEarlyDataStoreAclAndCacheButNeverQualifiedInstallExtent) {
  using Bridge = ::ota::storage::XiaoOtaActiveExtentBridge;
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1}) {
    SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role));
    StockBootFixture f(board, role);
    f.active.image.resize(role ? 527624 : 538484, 0x37);
    LifecycleFixture::le32(f.active.image.data(), 0x20040000);
    LifecycleFixture::le32(f.active.image.data() + 4, 0x27009);
    f.running.vendorCrcDisabled = true;
    const uint16_t fresh_crc = Bridge::crc16Compute(f.active.image.data(), f.active.image.size());
    ASSERT_NE(0, fresh_crc);
    OtaNrf52RunningContext before, after;
    ASSERT_TRUE(f.running.read(before));
    const auto bank = Bridge::decodeBank0FromRaw28Bytes(before.settings);
    ASSERT_EQ(0, bank.bank_0_crc);
    EXPECT_EQ(0u, Bridge::resolve(bank, before.image, before.capacity).active_image_extent);
    StockProof::Diagnostic diagnostic;
    ASSERT_EQ(StockProof::Result::Healthy, StockProof::check(f.qualification, f.running, f.journal, &diagnostic));
    EXPECT_STREQ("healthy", diagnostic.proof);
    EXPECT_TRUE(diagnostic.crcKnown);
    EXPECT_EQ(0, diagnostic.storedCrc);
    EXPECT_EQ(fresh_crc, diagnostic.computedCrc);
    expectOrdinaryStockWrites(f);
    ASSERT_FALSE(HasFatalFailure());
    stock_cache_blocked = f.proof() != StockProof::Result::Healthy;
    ASSERT_FALSE(stock_cache_blocked);
    ASSERT_TRUE(StockProof::cacheAttachAllowed(f.cacheProof()));
    ASSERT_TRUE(f.backend.attach(f.fx.integration, f.fx.sig_verifier));
    f.cache(::ota::storage::OtaCandidateStore::Phase::Ready);
    ASSERT_FALSE(HasFatalFailure());
    ::ota::storage::OtaCandidateStore::Snapshot durable;
    ASSERT_TRUE(f.fx.candidate_store.load(durable));
    EXPECT_TRUE(durable.localCache);
    EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, durable.phase);
    uint8_t message[usb::kCommitSignedBytes], signature[64];
    const auto status = f.fx.integration.leanReceiver().status();
    usb::buildCommitSignedMessage(f.fx.target_public_key, status.manifestHash, status.counter, message);
    f.owner.sign(message, sizeof(message), signature);
    EXPECT_EQ(usb::UsbOtaResult::Denied, f.fx.integration.leanReceiver().commit(status.counter, signature));
    ASSERT_TRUE(f.running.read(after));
    EXPECT_EQ(0, std::memcmp(before.settings, after.settings, sizeof(before.settings)));
    EXPECT_EQ(0u, Bridge::resolve(Bridge::decodeBank0FromRaw28Bytes(after.settings),
                                 after.image, after.capacity).active_image_extent);
    EXPECT_EQ(0u, f.journal_flash.programOpCount());
    EXPECT_EQ(0u, f.journal_flash.eraseOpCount());
  }
}

TEST(LoraOtaStockBoot, VendorDisabledCrcStillRefusesUnprovenSdkMarkerJournalAndReadFaultsBeforeFilesystem) {
  using Flash = ::ota::test::FakeNorFlash;
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1}) {
    for (int fault = 0; fault < 25; ++fault) {
      SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role) << '/' << fault);
      StockBootFixture f(board, role);
      f.running.vendorCrcDisabled = true;
      if (fault == 0) f.qualification.reason = OtaBoardQualificationReason::CorruptMarker;
      if (fault == 1) f.qualification.reason = OtaBoardQualificationReason::RoleOrCapabilityMismatch;
      if (fault == 2) { f.qualification.qualified = true; f.qualification.status = OtaBoardQualificationStatus::Qualified; }
      if (fault == 3) f.running.invalid = true;
      if (fault == 4) { f.running.vendorCrcDisabled = false; f.running.badCrc = true; }
      if (fault == 5) f.running.bank1 = 1;
      if (fault == 6) f.running.tailErased = false;
      if (fault == 7) f.running.fail = true;
      if (fault == 8) f.running.failAt = f.running.reads + 2;
      if (fault == 9) f.running.changeAt = f.running.reads + 2;
      if (fault == 10) f.running.sizeOverride = 0;
      if (fault == 11) f.running.sizeOverride = f.active.image.size() + 1;
      if (fault == 12) std::memset(f.active.image.data(), 0xff, 8);
      if (fault == 13) f.running.sizeOverride = 7;
      if (fault == 14) f.active.image.resize(meshcore::ota::runtime::kOtaMaxImageBytes + 1, 0x37);
      if (fault == 15 || fault == 16) {
        f.journal_flash.armFault({Flash::OpKind::Read, Flash::InjectionTiming::Before,
                                 f.journal_flash.readOpCount() + (fault == 15 ? 1u : 129u)});
      }
      if (fault >= 17) {
        const uint8_t byte = 0;
        ASSERT_TRUE(::ota::platform::isOk(f.journal.program((fault - 17) * 4096 + 13, &byte, 1)));
      }
      StockProof::Diagnostic diagnostic;
      const auto result = StockProof::check(f.qualification, f.running, f.journal, &diagnostic);
      ASSERT_NE(StockProof::Result::Healthy, result);
      if (fault == 4) {
        EXPECT_STREQ("sdk-crc", diagnostic.proof);
        EXPECT_NE(0, diagnostic.storedCrc);
        EXPECT_NE(diagnostic.computedCrc, diagnostic.storedCrc);
      }
      if (fault == 9) EXPECT_EQ(StockProof::Result::Changed, result);
      if (fault == 12) EXPECT_STREQ("sdk-vector", diagnostic.proof);
      if (fault == 15 || fault == 16) EXPECT_EQ(StockProof::Result::IoError, result);
      Adafruit_LittleFS filesystem;
      ASSERT_EQ(0u, filesystem.mounts);
      PacketBoundaryRtc clock;
      DataStore store(filesystem, clock);
      store.begin(result == StockProof::Result::Healthy, false);
      EXPECT_TRUE(store.destructiveWritesDisallowed());
      NodePrefs prefs;
      EXPECT_FALSE(store.savePrefs(prefs));
      StockDataHost host;
      EXPECT_FALSE(store.saveContacts(&host)); EXPECT_FALSE(store.saveChannels(&host));
      stock_acl_test::ClientACL acl;
      ASSERT_NE(nullptr, acl.putClient(mesh::Identity(f.owner.publicKey()), PERM_ACL_ADMIN));
      if (!store.destructiveWritesDisallowed()) acl.save(&filesystem);
      EXPECT_FALSE(filesystem.exists("/s_contacts"));
      EXPECT_EQ(0u, filesystem.writes);
      EXPECT_EQ(0u, f.journal_flash.eraseOpCount());
    }
  }
}

TEST(LoraOtaStockBoot, VendorDisabledCrcRequiresStableWholeImageShaEvenWhenFreshCrcDoesNotChange) {
  using Bridge = ::ota::storage::XiaoOtaActiveExtentBridge;
  struct CollidingContext : StockRunningContext {
    uint32_t collisionAt = 0;
    explicit CollidingContext(std::vector<uint8_t>& image) : StockRunningContext(image) {}
    static void zeroCrc(std::vector<uint8_t>& image) {
      const auto crc = Bridge::crc16Compute(image.data(), image.size() - 2);
      image[image.size() - 2] = crc >> 8;
      image.back() = crc;
    }
    bool read(OtaNrf52RunningContext& out) const override {
      if (reads + 1 == collisionAt) { image[100] ^= 1; zeroCrc(image); }
      return StockRunningContext::read(out);
    }
  };
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1}) {
    StockBootFixture f(board, role);
    CollidingContext::zeroCrc(f.active.image);
    ASSERT_EQ(0, Bridge::crc16Compute(f.active.image.data(), f.active.image.size()));
    CollidingContext running(f.active.image);
    running.vendorCrcDisabled = true;
    running.collisionAt = 2;
    StockProof::Diagnostic diagnostic;
    const auto result = StockProof::check(f.qualification, running, f.journal, &diagnostic);
    EXPECT_EQ(StockProof::Result::Changed, result);
    EXPECT_STREQ("sdk-changed", diagnostic.proof);
    EXPECT_EQ(0, Bridge::crc16Compute(f.active.image.data(), f.active.image.size()));
    Adafruit_LittleFS filesystem;
    PacketBoundaryRtc clock;
    DataStore store(filesystem, clock);
    store.begin(result == StockProof::Result::Healthy, false);
    NodePrefs prefs;
    EXPECT_FALSE(store.savePrefs(prefs));
    EXPECT_EQ(0u, filesystem.mounts);
    EXPECT_EQ(0u, filesystem.writes);
    EXPECT_EQ(0u, f.journal_flash.eraseOpCount());
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
  for (int fault = 0; fault < 15; ++fault) {
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
    if (fault == 14) {
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

TEST(LoraOtaStockBoot, StoreIgnoredCacheDamageAllowsResetButCrcValidPolicyAndBitmapFailuresRefuseAdmission) {
  using Store = ::ota::storage::OtaCandidateStore;
  using Flash = ::ota::test::FakeNorFlash;
  for (int fault = 0; fault < 12; ++fault) for (bool torn : {false, true}) {
    if (fault == 11 && !torn) continue;
    SCOPED_TRACE(::testing::Message() << fault << '/' << torn);
    StockBootFixture f;
    f.cache(Store::Phase::Ready); ASSERT_FALSE(HasFatalFailure());
    Store::Snapshot snapshot; ASSERT_TRUE(f.fx.candidate_store.load(snapshot));
    if (fault == 0) snapshot.localCache = false;
    if (fault == 1) snapshot.phase = Store::Phase::Committed;
    if (fault == 2) snapshot.signature[0] ^= 1;
    auto append = [&]() {
      if (torn) f.fx.candidate_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::Before,
                                             f.fx.candidate_flash.programOpCount() + 2});
      EXPECT_EQ(!torn, f.fx.candidate_store.append(snapshot));
      f.fx.candidate_flash.clearFault();
    };
    if (fault < 3) append();
    if (fault == 3) {
      const uint8_t byte = 0;
      ASSERT_TRUE(::ota::platform::isOk(f.fx.candidate_store_region.program(2 * Store::kRecordBytes, &byte, 1)));
    }

    if (fault == 4) ASSERT_TRUE(::ota::platform::isOk(f.fx.candidate_store_region.eraseSector(0)));
    if (fault == 5) ASSERT_TRUE(f.fx.candidate_store.clearBitmap());
    if (fault >= 6 && fault < 10) {
      OtaDescriptor descriptor;
      ASSERT_EQ(OtaDescriptorCodecResult::Ok, decodeOtaDescriptorCanonical(snapshot.canonical, 59, descriptor));
      if (fault == 6) descriptor.formatId = 2;
      if (fault == 7) descriptor.algorithmId = 2;
      if (fault == 8) descriptor.keyId = 0;
      if (fault == 9) descriptor.appAddress = 0;
      size_t size = 0;
      ASSERT_EQ(OtaDescriptorCodecResult::Ok, encodeOtaDescriptorCanonical(descriptor, snapshot.canonical, 59, size));
      f.owner.sign(snapshot.canonical, 59, snapshot.signature);
      append();
    }
    if (fault == 10) {
      f.fx.candidate_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::Mid,
                                    f.fx.candidate_flash.programOpCount() + 1, 64});
      ASSERT_FALSE(f.fx.candidate_store.append(snapshot));
      f.fx.candidate_flash.clearFault();
    }
    if (fault == 11) {
      uint8_t other_seed[32] = {0xa3};
      ::ota::test::Ed25519TestSigner other(other_seed);
      std::memcpy(snapshot.ownerPublicKey, other.publicKey(), 32);
      other.sign(snapshot.canonical, sizeof(snapshot.canonical), snapshot.signature);
      append();
    }
    const auto cache_result = f.cacheProof();
    const bool store_ignored = fault == 3 || fault == 4 || fault == 10;
    EXPECT_EQ(store_ignored ? StockProof::Result::CacheNeedsReset : StockProof::Result::InvalidCache, cache_result);
    EXPECT_EQ(store_ignored, StockProof::cacheAttachAllowed(cache_result));
    const auto programs = f.fx.candidate_flash.programOpCount(), erases = f.fx.candidate_flash.eraseOpCount();
    expectOrdinaryStockWrites(f);
    ASSERT_FALSE(HasFatalFailure());
    OtaFirmwareIntegration cold;
    stock_cache_blocked = f.proof() != StockProof::Result::Healthy;
    EXPECT_EQ(store_ignored, StockProof::cacheAttachAllowed(cache_result) && f.backend.attach(cold, f.fx.sig_verifier));
    EXPECT_EQ(store_ignored, cold.backendAvailable());
    EXPECT_EQ(programs, f.fx.candidate_flash.programOpCount());
    EXPECT_EQ(erases, f.fx.candidate_flash.eraseOpCount());
  }
}

TEST(LoraOtaStockBoot, CacheReadFaultsRemainUnavailableWithoutBlockingIndependentlyProvenOrdinaryWrites) {
  using Flash = ::ota::test::FakeNorFlash;
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1}) {
    for (uint32_t read : {1u, 32u, 33u, 64u}) {
      SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role) << '/' << read);
      StockBootFixture f(board, role);
      f.fx.candidate_flash.armFault({Flash::OpKind::Read, Flash::InjectionTiming::Before,
                                    f.fx.candidate_flash.readOpCount() + read});
      EXPECT_EQ(StockProof::Result::IoError, f.cacheProof());
      EXPECT_FALSE(StockProof::cacheAttachAllowed(StockProof::Result::IoError));
      expectOrdinaryStockWrites(f);
      ASSERT_FALSE(HasFatalFailure());
      EXPECT_EQ(0u, f.fx.candidate_flash.eraseOpCount());
      EXPECT_EQ(0u, f.fx.candidate_flash.programOpCount());
      EXPECT_EQ(0u, f.journal_flash.eraseOpCount());
    }
  }
}

TEST(LoraOtaStockBoot, RealCacheAppendAndResetCutsColdBootWritableAndRecoverOnlyThroughExplicitOwnerRetry) {
  using Flash = ::ota::test::FakeNorFlash;
  using Store = ::ota::storage::OtaCandidateStore;
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1}) {
    for (bool vendor_zero : {false, true}) for (int cut = 0; cut < 13; ++cut) {
      SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role) << '/' << vendor_zero << '/' << cut);
      StockBootFixture f(board, role);
      f.running.vendorCrcDisabled = vendor_zero;
      const uint8_t image[40] = {0x57};
      uint8_t begin[158] = {usb::kCommand, uint8_t(usb::UsbOtaOp::CacheBegin)};
      std::memcpy(begin + 3, f.owner.publicKey(), 32);
      f.fx.buildSmallManifest(image, sizeof(image), begin + 35);
      f.owner.sign(begin + 35, 59, begin + 94);
      uint8_t put[45] = {usb::kCommand, uint8_t(usb::UsbOtaOp::CachePut), 0, 0, sizeof(image)};
      std::memcpy(put + 5, image, sizeof(image));
      const uint8_t seal[] = {usb::kCommand, uint8_t(usb::UsbOtaOp::CacheSeal)};
      auto& initial = f.fx.integration.leanReceiver();
      const bool reset = cut == 5 || cut == 6 || cut >= 10;
      if (cut >= 3 && cut != 8) {
        f.cache(reset ? Store::Phase::Ready : Store::Phase::Receiving);
        ASSERT_FALSE(HasFatalFailure());
        if (!reset) {
          ASSERT_EQ(usb::UsbOtaResult::Ok, initial.handleUsbCacheFrame(put, sizeof(put), f.owner.publicKey()));
        }
      }
      if (reset) {
        begin[2] = usb::kCacheBeginFlagReupload;
        const uint32_t partial_bytes = cut == 10 ? 96u : cut == 11 ? 512u : 2048u;
        f.fx.candidate_flash.armFault({Flash::OpKind::Erase,
            cut >= 10 ? Flash::InjectionTiming::Mid :
            cut == 5 ? Flash::InjectionTiming::After : Flash::InjectionTiming::Before,
            f.fx.candidate_flash.eraseOpCount() + (cut == 6 ? 2u : 1u), partial_bytes});
        ASSERT_EQ(usb::UsbOtaResult::IoError, initial.handleUsbCacheFrame(begin, sizeof(begin), f.owner.publicKey()));
      } else if (cut == 7) {
        ASSERT_EQ(usb::UsbOtaResult::Pending, initial.handleUsbCacheFrame(seal, sizeof(seal), f.owner.publicKey()));
        f.fx.candidate_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::Before,
                                      f.fx.candidate_flash.programOpCount() + 2});
        f.fx.integration.loop();
        ASSERT_EQ(Store::Phase::Verifying, initial.status().phase);
      } else {
        const bool body_mid = cut == 8 || cut == 9;
        f.fx.candidate_flash.armFault({Flash::OpKind::Program,
            body_mid ? Flash::InjectionTiming::Mid : cut == 2 ? Flash::InjectionTiming::After :
            cut == 1 || cut == 4 ? Flash::InjectionTiming::Mid : Flash::InjectionTiming::Before,
            f.fx.candidate_flash.programOpCount() + (cut == 2 || body_mid ? 1u : 2u), body_mid ? 64u : 2u});
        ASSERT_EQ(usb::UsbOtaResult::IoError, initial.handleUsbCacheFrame(
            cut < 3 || cut == 8 ? begin : seal, cut < 3 || cut == 8 ? sizeof(begin) : sizeof(seal), f.owner.publicKey()));
      }
      f.fx.candidate_flash.clearFault();
      Store::Snapshot durable;
      const bool owned = f.fx.candidate_store.load(durable);
      ASSERT_EQ(cut == 3 || cut == 4 || cut == 7 || cut == 9 || cut == 10 || cut == 11, owned);
      const auto programs = f.fx.candidate_flash.programOpCount(), erases = f.fx.candidate_flash.eraseOpCount();
      const auto image_programs = f.fx.image_flash.programOpCount(), image_erases = f.fx.image_flash.eraseOpCount();
      std::vector<uint8_t> retained(f.fx.candidate_flash.rawBuffer(),
                                  f.fx.candidate_flash.rawBuffer() + f.fx.candidate_flash.rawSize());
      expectOrdinaryStockWrites(f);
      ASSERT_FALSE(HasFatalFailure());
      const auto cache_result = f.cacheProof();
      ASSERT_EQ(StockProof::Result::CacheNeedsReset, cache_result);
      EXPECT_STREQ("cache needs explicit retry/reupload", StockProof::reason(cache_result));
      stock_cache_blocked = f.proof() != StockProof::Result::Healthy;
      OtaFirmwareIntegration cold;
      cold.setLeanAdminCheck(&f.fx.admins, &leanAdminCheckThunk);
      cold.setLeanTargetPublicKey(f.fx.target_public_key);
      OtaBoardCacheOnlyBackend backend(f.fx.image_region, f.fx.candidate_store_region,
                                      +[]() { return stock_cache_blocked; });
      ASSERT_TRUE(StockProof::cacheAttachAllowed(cache_result) && backend.attach(cold, f.fx.sig_verifier));
      auto& cache = cold.leanReceiver();
      ASSERT_EQ(owned, cache.status().valid);
      EXPECT_EQ(programs, f.fx.candidate_flash.programOpCount());
      EXPECT_EQ(erases, f.fx.candidate_flash.eraseOpCount());
      EXPECT_EQ(image_programs, f.fx.image_flash.programOpCount());
      EXPECT_EQ(image_erases, f.fx.image_flash.eraseOpCount());
      EXPECT_EQ(0, std::memcmp(retained.data(), f.fx.candidate_flash.rawBuffer(), retained.size()));
      if (owned) {
        EXPECT_EQ(durable.phase, cache.status().phase);
        EXPECT_EQ(1u, cache.status().receivedBlocks);
        EXPECT_EQ(0, std::memcmp(durable.ownerPublicKey, cache.status().ownerPublicKey, 32));
        uint8_t other_seed[32] = {0x78};
        ::ota::test::Ed25519TestSigner other(other_seed);
        f.fx.admins.add(other.publicKey());
        uint8_t other_begin[158];
        std::memcpy(other_begin, begin, sizeof(begin));
        other_begin[2] = usb::kCacheBeginFlagReupload;
        std::memcpy(other_begin + 3, other.publicKey(), 32);
        other.sign(other_begin + 35, 59, other_begin + 94);
        EXPECT_EQ(usb::UsbOtaResult::Busy,
                  cache.handleUsbCacheFrame(other_begin, sizeof(other_begin), f.owner.publicKey()));
        begin[2] = 0;
        ASSERT_EQ(usb::UsbOtaResult::Ok, cache.handleUsbCacheFrame(begin, sizeof(begin), f.owner.publicKey()));
        EXPECT_EQ(1u, cache.status().receivedBlocks);
        EXPECT_EQ(programs, f.fx.candidate_flash.programOpCount());
        EXPECT_EQ(erases, f.fx.candidate_flash.eraseOpCount());
        if (cut != 7 && !reset) {
          ASSERT_EQ(usb::UsbOtaResult::Pending, cache.handleUsbCacheFrame(seal, sizeof(seal), f.owner.publicKey()));
          cold.loop();
          ASSERT_EQ(Store::Phase::Ready, cache.status().phase);
          EXPECT_EQ(StockProof::Result::CacheNeedsReset, f.cacheProof());
        }
      }
      begin[2] = usb::kCacheBeginFlagReupload;
      ASSERT_EQ(usb::UsbOtaResult::Ok, cache.handleUsbCacheFrame(begin, sizeof(begin), f.owner.publicKey()));
      EXPECT_EQ(0u, cache.status().receivedBlocks);
      EXPECT_EQ(StockProof::Result::Healthy, f.cacheProof());
      ASSERT_EQ(usb::UsbOtaResult::Ok, cache.handleUsbCacheFrame(put, sizeof(put), f.owner.publicKey()));
      ASSERT_EQ(usb::UsbOtaResult::Pending, cache.handleUsbCacheFrame(seal, sizeof(seal), f.owner.publicKey()));
      cold.loop();
      ASSERT_EQ(Store::Phase::Ready, cache.status().phase);
      EXPECT_EQ(StockProof::Result::Healthy, f.cacheProof());
      uint8_t message[usb::kCommitSignedBytes], signature[64];
      const auto status = cache.status();
      usb::buildCommitSignedMessage(f.fx.target_public_key, status.manifestHash, status.counter, message);
      f.owner.sign(message, sizeof(message), signature);
      EXPECT_EQ(usb::UsbOtaResult::Denied, cache.commit(status.counter, signature));
      EXPECT_EQ(0u, f.journal_flash.programOpCount());
      EXPECT_EQ(0u, f.journal_flash.eraseOpCount());
    }
  }
}

TEST(LoraOtaStockBoot, PartialEraseOwnedSuffixKeepsSignedAbortDurableAcrossColdBootUntilExplicitRestart) {
  using Flash = ::ota::test::FakeNorFlash;
  using Store = ::ota::storage::OtaCandidateStore;
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1})
    for (bool vendor_zero : {false, true}) for (bool another_admin : {false, true}) {
      SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role) << '/' << vendor_zero << '/' << another_admin);
      StockBootFixture f(board, role);
      f.running.vendorCrcDisabled = vendor_zero;
      f.cache(Store::Phase::Ready); ASSERT_FALSE(HasFatalFailure());
      Store::Snapshot original;
      ASSERT_TRUE(f.fx.candidate_store.load(original));
      ASSERT_EQ(Store::Phase::Ready, original.phase);
      uint8_t begin[158] = {usb::kCommand, uint8_t(usb::UsbOtaOp::CacheBegin), usb::kCacheBeginFlagReupload};
      std::memcpy(begin + 3, original.ownerPublicKey, 32);
      std::memcpy(begin + 35, original.canonical, 59);
      std::memcpy(begin + 94, original.signature, 64);
      f.fx.candidate_flash.armFault({Flash::OpKind::Erase, Flash::InjectionTiming::Mid,
                                    f.fx.candidate_flash.eraseOpCount() + 1, 512});
      ASSERT_EQ(usb::UsbOtaResult::IoError,
                f.fx.integration.leanReceiver().handleUsbCacheFrame(begin, sizeof(begin), f.owner.publicKey()));
      f.fx.candidate_flash.clearFault();
      ASSERT_EQ(StockProof::Result::CacheNeedsReset, f.cacheProof());
      expectOrdinaryStockWrites(f); ASSERT_FALSE(HasFatalFailure());
      stock_cache_blocked = f.proof() != StockProof::Result::Healthy;
      OtaFirmwareIntegration cold;
      cold.setLeanAdminCheck(&f.fx.admins, &leanAdminCheckThunk);
      cold.setLeanTargetPublicKey(f.fx.target_public_key);
      OtaBoardCacheOnlyBackend backend(f.fx.image_region, f.fx.candidate_store_region,
                                      +[]() { return stock_cache_blocked; });
      ASSERT_TRUE(backend.attach(cold, f.fx.sig_verifier));
      const auto before = cold.leanReceiver().status();
      ASSERT_EQ(Store::Phase::Ready, before.phase);
      EXPECT_EQ(1u, before.receivedBlocks);
      EXPECT_EQ(0, std::memcmp(original.ownerPublicKey, before.ownerPublicKey, 32));
      const uint8_t admin_seed[32] = {0x79};
      ::ota::test::Ed25519TestSigner admin(admin_seed);
      f.fx.admins.add(admin.publicKey());
      const auto& signer = another_admin ? admin : f.owner;
      uint8_t message[usb::kAbortSignedBytes], signature[64];
      usb::buildAbortSignedMessage(f.fx.target_public_key, before.imageHash, before.generation, message);
      signer.sign(message, sizeof(message), signature);
      const auto erases = f.fx.candidate_flash.eraseOpCount();
      ASSERT_EQ(usb::UsbOtaResult::Ok,
                cold.leanReceiver().abort(signer.publicKey(), signature, before.imageHash, before.generation));
      EXPECT_EQ(Store::Phase::Aborted, cold.leanReceiver().status().phase);
      EXPECT_EQ(erases, f.fx.candidate_flash.eraseOpCount());

      OtaFirmwareIntegration rebooted;
      rebooted.setLeanAdminCheck(&f.fx.admins, &leanAdminCheckThunk);
      rebooted.setLeanTargetPublicKey(f.fx.target_public_key);
      OtaBoardCacheOnlyBackend rebooted_backend(f.fx.image_region, f.fx.candidate_store_region,
                                               +[]() { return stock_cache_blocked; });
      ASSERT_TRUE(StockProof::cacheAttachAllowed(f.cacheProof()) && rebooted_backend.attach(rebooted, f.fx.sig_verifier));
      auto& cache = rebooted.leanReceiver();
      ASSERT_EQ(Store::Phase::Aborted, cache.status().phase);
      EXPECT_EQ(1u, cache.status().receivedBlocks);
      Store::Snapshot aborted;
      ASSERT_TRUE(f.fx.candidate_store.load(aborted));
      EXPECT_EQ(original.sessionId + 1, aborted.sessionId);
      EXPECT_GT(aborted.sequence, original.sequence);
      EXPECT_EQ(0, std::memcmp(before.ownerPublicKey, cache.status().ownerPublicKey, 32));
      begin[2] = 0;
      EXPECT_EQ(usb::UsbOtaResult::Denied, cache.handleUsbCacheFrame(begin, sizeof(begin), f.owner.publicKey()));
      for (uint8_t mode : {usb::kStartModeDirect, usb::kStartModeDirected, usb::kStartModeBackground}) {
        OtaRfUploader uploader;
        EXPECT_FALSE(uploader.start(rebooted, mode, f.fx.target_public_key, 1, 908525, 60, 7, false));
      }
      EXPECT_EQ(Store::Phase::Aborted, cache.status().phase);
      EXPECT_EQ(erases, f.fx.candidate_flash.eraseOpCount());
      begin[2] = usb::kCacheBeginFlagReupload;
      ASSERT_EQ(usb::UsbOtaResult::Ok, cache.handleUsbCacheFrame(begin, sizeof(begin), f.owner.publicKey()));
      EXPECT_EQ(Store::Phase::Receiving, cache.status().phase);
      EXPECT_EQ(0u, cache.status().receivedBlocks);
      EXPECT_EQ(StockProof::Result::Healthy, f.cacheProof());
      EXPECT_EQ(0u, f.journal_flash.programOpCount());
      EXPECT_EQ(0u, f.journal_flash.eraseOpCount());
    }
}

TEST(LoraOtaStockBoot, TornReadySealRetryOrDirectSignedAbortKeepsColdSuppressionAndExplicitRestart) {
  using Flash = ::ota::test::FakeNorFlash;
  using Store = ::ota::storage::OtaCandidateStore;
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1})
    for (bool vendor_zero : {false, true}) for (bool heal_ready : {false, true})
      for (bool another_admin : {false, true}) for (bool abort_cut : {false, true}) {
      SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role) << '/' << vendor_zero << '/'
                   << heal_ready << '/' << another_admin << '/' << abort_cut);
      StockBootFixture f(board, role);
      f.running.vendorCrcDisabled = vendor_zero;
      f.cache(Store::Phase::Receiving); ASSERT_FALSE(HasFatalFailure());
      const uint8_t image[40] = {0x57};
      uint8_t put[45] = {usb::kCommand, uint8_t(usb::UsbOtaOp::CachePut), 0, 0, sizeof(image)};
      std::memcpy(put + 5, image, sizeof(image));
      auto& initial = f.fx.integration.leanReceiver();
      ASSERT_EQ(usb::UsbOtaResult::Ok, initial.handleUsbCacheFrame(put, sizeof(put), f.owner.publicKey()));
      const uint8_t seal[] = {usb::kCommand, uint8_t(usb::UsbOtaOp::CacheSeal)};
      ASSERT_EQ(usb::UsbOtaResult::Pending, initial.handleUsbCacheFrame(seal, sizeof(seal), f.owner.publicKey()));
      f.fx.candidate_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::Before,
                                    f.fx.candidate_flash.programOpCount() + 2});
      f.fx.integration.loop();
      ASSERT_EQ(Store::Phase::Verifying, initial.status().phase);
      f.fx.candidate_flash.clearFault();
      ASSERT_EQ(StockProof::Result::CacheNeedsReset, f.cacheProof());
      expectOrdinaryStockWrites(f); ASSERT_FALSE(HasFatalFailure());
      stock_cache_blocked = f.proof() != StockProof::Result::Healthy;
      OtaFirmwareIntegration cold;
      cold.setLeanAdminCheck(&f.fx.admins, &leanAdminCheckThunk);
      cold.setLeanTargetPublicKey(f.fx.target_public_key);
      OtaBoardCacheOnlyBackend backend(f.fx.image_region, f.fx.candidate_store_region,
                                      +[]() { return stock_cache_blocked; });
      ASSERT_TRUE(backend.attach(cold, f.fx.sig_verifier));
      auto& cache = cold.leanReceiver();
      ASSERT_EQ(Store::Phase::Verifying, cache.status().phase);
      if (heal_ready) {
        ASSERT_EQ(usb::UsbOtaResult::Pending, cache.handleUsbCacheFrame(seal, sizeof(seal), f.owner.publicKey()));
        cold.loop();
        ASSERT_EQ(Store::Phase::Ready, cache.status().phase);
        ASSERT_EQ(StockProof::Result::CacheNeedsReset, f.cacheProof());
      }
      Store::Snapshot before;
      ASSERT_TRUE(f.fx.candidate_store.load(before));
      const uint8_t admin_seed[32] = {0x79}, other_seed[32] = {0x78}, outsider_seed[32] = {0x7b};
      ::ota::test::Ed25519TestSigner admin(admin_seed), other(other_seed), outsider(outsider_seed);
      f.fx.admins.add(admin.publicKey());
      f.fx.admins.add(other.publicKey());
      uint8_t begin[158] = {usb::kCommand, uint8_t(usb::UsbOtaOp::CacheBegin), usb::kCacheBeginFlagReupload};
      std::memcpy(begin + 3, before.ownerPublicKey, 32);
      std::memcpy(begin + 35, before.canonical, 59);
      std::memcpy(begin + 94, before.signature, 64);
      uint8_t other_begin[158];
      std::memcpy(other_begin, begin, sizeof(begin));
      std::memcpy(other_begin + 3, other.publicKey(), 32);
      other.sign(other_begin + 35, 59, other_begin + 94);
      EXPECT_EQ(usb::UsbOtaResult::Busy,
                cache.handleUsbCacheFrame(other_begin, sizeof(other_begin), f.owner.publicKey()));
      uint8_t message[usb::kAbortSignedBytes], signature[64];
      const auto status = cache.status();
      usb::buildAbortSignedMessage(f.fx.target_public_key, status.imageHash, status.generation, message);
      outsider.sign(message, sizeof(message), signature);
      EXPECT_EQ(usb::UsbOtaResult::Denied, cache.abort(outsider.publicKey(), signature, status.imageHash, status.generation));
      const auto& signer = another_admin ? admin : f.owner;
      signer.sign(message, sizeof(message), signature);
      const auto erases = f.fx.candidate_flash.eraseOpCount();
      if (abort_cut) f.fx.candidate_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::Before,
                                                  f.fx.candidate_flash.programOpCount() + 2});
      ASSERT_EQ(abort_cut ? usb::UsbOtaResult::IoError : usb::UsbOtaResult::Ok,
                cache.abort(signer.publicKey(), signature, status.imageHash, status.generation));
      f.fx.candidate_flash.clearFault();
      ASSERT_EQ(StockProof::Result::CacheNeedsReset, f.cacheProof());
      if (abort_cut) {
        OtaFirmwareIntegration retry;
        retry.setLeanAdminCheck(&f.fx.admins, &leanAdminCheckThunk);
        retry.setLeanTargetPublicKey(f.fx.target_public_key);
        OtaBoardCacheOnlyBackend retry_backend(f.fx.image_region, f.fx.candidate_store_region,
                                               +[]() { return stock_cache_blocked; });
        ASSERT_TRUE(retry_backend.attach(retry, f.fx.sig_verifier));
        EXPECT_EQ(before.phase, retry.leanReceiver().status().phase);
        ASSERT_EQ(usb::UsbOtaResult::Ok,
                  retry.leanReceiver().abort(signer.publicKey(), signature, status.imageHash, status.generation));
        ASSERT_EQ(StockProof::Result::CacheNeedsReset, f.cacheProof());
      }
      OtaFirmwareIntegration rebooted;
      rebooted.setLeanAdminCheck(&f.fx.admins, &leanAdminCheckThunk);
      rebooted.setLeanTargetPublicKey(f.fx.target_public_key);
      OtaBoardCacheOnlyBackend rebooted_backend(f.fx.image_region, f.fx.candidate_store_region,
                                               +[]() { return stock_cache_blocked; });
      ASSERT_TRUE(StockProof::cacheAttachAllowed(f.cacheProof()) && rebooted_backend.attach(rebooted, f.fx.sig_verifier));
      auto& resumed = rebooted.leanReceiver();
      ASSERT_EQ(Store::Phase::Aborted, resumed.status().phase);
      EXPECT_EQ(1u, resumed.status().receivedBlocks);
      Store::Snapshot aborted;
      ASSERT_TRUE(f.fx.candidate_store.load(aborted));
      EXPECT_EQ(before.sessionId + 1, aborted.sessionId);
      EXPECT_EQ(0, std::memcmp(before.ownerPublicKey, aborted.ownerPublicKey, 32));
      begin[2] = 0;
      EXPECT_EQ(usb::UsbOtaResult::Denied, resumed.handleUsbCacheFrame(begin, sizeof(begin), f.owner.publicKey()));
      other_begin[2] = 0;
      EXPECT_EQ(usb::UsbOtaResult::Busy,
                resumed.handleUsbCacheFrame(other_begin, sizeof(other_begin), f.owner.publicKey()));
      for (uint8_t mode : {usb::kStartModeDirect, usb::kStartModeDirected, usb::kStartModeBackground}) {
        OtaRfUploader uploader;
        EXPECT_FALSE(uploader.start(rebooted, mode, f.fx.target_public_key, 1, 908525, 60, 7, false));
      }
      EXPECT_EQ(erases, f.fx.candidate_flash.eraseOpCount());
      begin[2] = usb::kCacheBeginFlagReupload;
      ASSERT_EQ(usb::UsbOtaResult::Ok, resumed.handleUsbCacheFrame(begin, sizeof(begin), f.owner.publicKey()));
      EXPECT_EQ(Store::Phase::Receiving, resumed.status().phase);
      EXPECT_EQ(0u, resumed.status().receivedBlocks);
      EXPECT_EQ(StockProof::Result::Healthy, f.cacheProof());
      EXPECT_EQ(0u, f.journal_flash.programOpCount());
      EXPECT_EQ(0u, f.journal_flash.eraseOpCount());
    }
}

TEST(LoraOtaStockBoot, TornCacheBindingIgnoresOnlySessionAttemptWhileCompetingOwnerContentAndCampaignStayRefused) {
  using Flash = ::ota::test::FakeNorFlash;
  using Store = ::ota::storage::OtaCandidateStore;
  for (int fault = 0; fault < 4; ++fault) {
    SCOPED_TRACE(fault);
    StockBootFixture f;
    f.cache(Store::Phase::Ready); ASSERT_FALSE(HasFatalFailure());
    Store::Snapshot snapshot;
    ASSERT_TRUE(f.fx.candidate_store.load(snapshot));
    for (int torn = 0; torn < 2; ++torn) {
      ++snapshot.sessionId;
      ++snapshot.attemptId;
      if (torn && fault == 1) ++snapshot.campaignId;
      if (torn && fault == 2) {
        const uint8_t image[40] = {0x59};
        f.fx.buildSmallManifest(image, sizeof(image), snapshot.canonical);
        f.owner.sign(snapshot.canonical, sizeof(snapshot.canonical), snapshot.signature);
      }
      if (torn && fault == 3) {
        const uint8_t seed[32] = {0x7c};
        ::ota::test::Ed25519TestSigner other(seed);
        std::memcpy(snapshot.ownerPublicKey, other.publicKey(), sizeof(snapshot.ownerPublicKey));
        other.sign(snapshot.canonical, sizeof(snapshot.canonical), snapshot.signature);
      }
      f.fx.candidate_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::Before,
                                    f.fx.candidate_flash.programOpCount() + 2});
      ASSERT_FALSE(f.fx.candidate_store.append(snapshot));
      f.fx.candidate_flash.clearFault();
    }
    EXPECT_EQ(fault ? StockProof::Result::InvalidCache : StockProof::Result::CacheNeedsReset, f.cacheProof());
    EXPECT_EQ(!fault, StockProof::cacheAttachAllowed(f.cacheProof()));
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

TEST(LoraOtaStockBoot, CapturedEarlyDiagnosticIdentifiesMarkerSdkJournalAndIoWithoutChangingWriteAuthority) {
  using Flash = ::ota::test::FakeNorFlash;
  const char* expected[] = {"healthy", "marker", "marker", "sdk-tail", "sdk-pending-bank",
                            "sdk-bank0", "sdk-crc", "sdk-read", "sdk-recheck-read", "sdk-changed",
                            "install-journal", "journal-read", "sdk-size", "journal-recheck-read"};
  for (size_t fault = 0; fault < sizeof(expected) / sizeof(expected[0]); ++fault) {
    SCOPED_TRACE(fault);
    StockBootFixture f;
    if (fault == 1) f.qualification.reason = OtaBoardQualificationReason::CorruptMarker;
    if (fault == 2) f.qualification.reason = OtaBoardQualificationReason::RoleOrCapabilityMismatch;
    if (fault == 3) f.running.tailErased = false;
    if (fault == 4) f.running.bank1 = 1;
    if (fault == 5) f.running.invalid = true;
    if (fault == 6) f.running.badCrc = true;
    if (fault == 7) f.running.fail = true;
    if (fault == 8) f.running.failAt = f.running.reads + 2;
    if (fault == 9) f.running.changeAt = f.running.reads + 2;
    if (fault == 10) {
      const uint8_t byte = 0;
      ASSERT_TRUE(::ota::platform::isOk(f.journal.program(16401, &byte, 1)));
    }
    if (fault == 11) f.journal_flash.armFault({Flash::OpKind::Read, Flash::InjectionTiming::Before,
                                              f.journal_flash.readOpCount() + 2});
    if (fault == 12) f.active.image.clear();
    if (fault == 13) f.journal_flash.armFault({Flash::OpKind::Read, Flash::InjectionTiming::Before,
                                              f.journal_flash.readOpCount() + 129});
    const auto programs = f.journal_flash.programOpCount(), erases = f.journal_flash.eraseOpCount();
    StockProof::Diagnostic diagnostic;
    const auto result = StockProof::check(f.qualification, f.running, f.journal, &diagnostic);
    EXPECT_STREQ(expected[fault], diagnostic.proof);
    EXPECT_EQ(fault == 0, result == StockProof::Result::Healthy);
    char detail[128];
    StockProof::formatDiagnostic(detail, sizeof(detail), diagnostic);
    Adafruit_LittleFS filesystem;
    PacketBoundaryRtc clock;
    DataStore store(filesystem, clock);
    store.begin(result == StockProof::Result::Healthy, false);
    uint8_t reply[176];
    const size_t count = encodeOtaOrdinaryWriteDiagnostic(reply, sizeof(reply), 29,
                                                        store.destructiveWritesDisallowed(), detail);
    EXPECT_EQ(29, reply[0]);
    EXPECT_LT(count, sizeof(reply));
    EXPECT_NE(nullptr, std::strstr(reinterpret_cast<char*>(reply + 1), fault == 0 ? "writes=allowed" : "writes=blocked"));
    EXPECT_NE(nullptr, std::strstr(reinterpret_cast<char*>(reply + 1), expected[fault]));
    if (fault == 1 || fault == 2 || fault == 7) EXPECT_NE(nullptr, std::strstr(detail, "sdk=unread"));
    if (fault == 3) EXPECT_NE(nullptr, std::strstr(detail, "tail=0"));
    if (fault == 4) EXPECT_NE(nullptr, std::strstr(detail, "bank1=1"));
    if (fault == 6) {
      EXPECT_TRUE(diagnostic.crcKnown);
      EXPECT_NE(diagnostic.storedCrc, diagnostic.computedCrc);
    }
    if (fault == 10) EXPECT_NE(nullptr, std::strstr(detail, "off=00004011"));
    if (fault == 11) EXPECT_NE(nullptr, std::strstr(detail, "off=00000100"));
    if (fault == 12) EXPECT_NE(nullptr, std::strstr(detail, "size=0"));
    if (fault == 13) EXPECT_NE(nullptr, std::strstr(detail, "off=00000000"));
    NodePrefs prefs;
    std::strcpy(prefs.node_name, "diagnostic-does-not-unlock");
    EXPECT_EQ(fault == 0, store.savePrefs(prefs));
    EXPECT_EQ(programs, f.journal_flash.programOpCount());
    EXPECT_EQ(erases, f.journal_flash.eraseOpCount());
    EXPECT_EQ(0u, f.fx.candidate_flash.eraseOpCount());
    EXPECT_EQ(0u, f.fx.image_flash.eraseOpCount());
  }
}

TEST(LoraOtaStockBoot, DiagnosticReplyUsesRealLatchedPermissionAndEarlySnapshotWithBoundedNoKeyReadbacks) {
  StockBootFixture f;
  f.running.tailErased = false;
  StockProof::Diagnostic early;
  ASSERT_NE(StockProof::Result::Healthy, StockProof::check(f.qualification, f.running, f.journal, &early));
  char captured[128];
  StockProof::formatDiagnostic(captured, sizeof(captured), early);
  Adafruit_LittleFS filesystem;
  PacketBoundaryRtc clock;
  DataStore store(filesystem, clock);
  store.begin(false, false);
  f.running.tailErased = true;
  ASSERT_EQ(StockProof::Result::Healthy, f.proof());
  uint8_t reply[176];
  const auto count = encodeOtaOrdinaryWriteDiagnostic(reply, sizeof(reply), 29,
                                                     store.destructiveWritesDisallowed(), captured);
  EXPECT_EQ(29, reply[0]);
  EXPECT_EQ(1 + std::strlen(reinterpret_cast<char*>(reply + 1)), count);
  EXPECT_NE(nullptr, std::strstr(reinterpret_cast<char*>(reply + 1), "writes=blocked"));
  EXPECT_NE(nullptr, std::strstr(reinterpret_cast<char*>(reply + 1), "proof=sdk-tail"));
  EXPECT_EQ(nullptr, std::strstr(reinterpret_cast<char*>(reply + 1), "CACHE_ONLY"));
  char capability[160];
  formatOtaOrdinaryWriteDiagnostic(capability, sizeof(capability), store.destructiveWritesDisallowed(),
                                  "CACHE_ONLY: verified stock boot");
  EXPECT_STREQ("writes=blocked CACHE_ONLY: verified stock boot", capability);
  uint8_t tiny[12];
  std::memset(tiny, 0x5a, sizeof(tiny));
  EXPECT_EQ(8u, encodeOtaOrdinaryWriteDiagnostic(tiny, 9, 29, true, captured));
  EXPECT_EQ(0, tiny[8]);
  EXPECT_EQ(0x5a, tiny[9]);
  EXPECT_EQ(0x5a, tiny[11]);
  EXPECT_EQ(0u, encodeOtaOrdinaryWriteDiagnostic(nullptr, 0, 29, true, captured));
  EXPECT_EQ(0u, f.journal_flash.eraseOpCount());
  EXPECT_EQ(0u, f.fx.candidate_flash.eraseOpCount());
}
