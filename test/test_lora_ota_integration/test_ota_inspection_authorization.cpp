#include <gtest/gtest.h>

class InspectionCliFilesystem {
public:
  void mkdir(const char*) {}
};
#define FILESYSTEM InspectionCliFilesystem
#include <helpers/CommonCLI.h>
#undef FILESYSTEM

#include <helpers/ota/OtaInspection.h>
#include <helpers/ota/OtaFirmwareBackend.h>
#include "../test_lora_ota_storage/FakeNorFlash.h"
#include <ota/trust/third_party/ed25519/ed25519.h>

TEST(LoraOtaInspection, ProductionRemoteCliAdminGateDoesNotInspectGuestReadOnlyWrongTypeOrShortPayload) {
  using namespace mesh::ota;
  using Store = ::ota::storage::OtaCandidateStore;
  ::ota::test::FakeNorFlash flash(Store::kExpectedRegionBytes, Store::kSectorBytes);
  ::ota::platform::FlashRegion region(flash, 0, Store::kExpectedRegionBytes);
  Store store(region);
  Store::Snapshot candidate;
  candidate.valid = true;
  candidate.phase = Store::Phase::Receiving;
  candidate.totalBlocks = 3;
  candidate.exactSizeBytes = 170;
  candidate.sessionId = 9;
  meshcore::ota::protocol::OtaDescriptor descriptor;
  descriptor.boardFamily = 0x1001;
  descriptor.boardVariant = 2;
  descriptor.role = 7;
  descriptor.exactSizeBytes = candidate.exactSizeBytes;
  descriptor.appAddress = 0x10000;
  descriptor.securityCounter = 5;
  descriptor.keyId = descriptor.algorithmId = descriptor.formatId = 1;
  std::memset(descriptor.sha256, 0xAB, 32);
  size_t len = 0;
  ASSERT_EQ(meshcore::ota::protocol::OtaDescriptorCodecResult::Ok,
      meshcore::ota::protocol::encodeOtaDescriptorCanonical(descriptor, candidate.canonical,
                                                          sizeof(candidate.canonical), len));
  const uint8_t seed[32] = {0xA9};
  uint8_t private_key[64];
  ed25519_create_keypair(candidate.ownerPublicKey, private_key, seed);
  ed25519_sign(candidate.signature, candidate.canonical, sizeof(candidate.canonical),
               candidate.ownerPublicKey, private_key);
  ASSERT_TRUE(store.reset(candidate));
  ASSERT_TRUE(store.markReceived(0));
  OtaFirmwareIntegration integration;
  integration.attachCandidateStore(&store);
  ::ota::test::FakeNorFlash image_flash(4096, 4096);
  ::ota::platform::FlashRegion image_region(image_flash, 0, 4096);
  OtaFirmwareStorageSink sink(image_region);
  integration.attachStagingSink(&sink);
  const uint8_t target[32] = {0xB0};
  integration.setLeanTargetPublicKey(target);
  integration.setLeanAdminCheck(&candidate, [](void* ctx, const uint8_t key[32]) {
    return key && !std::memcmp(key, static_cast<Store::Snapshot*>(ctx)->ownerPublicKey, 32);
  });
  const auto reads = flash.readOpCount(), programs = flash.programOpCount(), erases = flash.eraseOpCount();
  ClientInfo client{};
  unsigned dispatched = 0;
  const auto dispatch = [&](uint8_t type, size_t length) {
    if (!CommonCLI::isAdminTextCommand(type, length, client)) return;
    ++dispatched;
    const auto view = integration.inspectReadback(OtaBootLifecycleEvidence());
    char reply[160];
    formatOtaProgress(reply, sizeof(reply), view);
    EXPECT_STREQ("candidate=receiver phase=receiving received=1 total=3 missing=2 bytes=170 block=84", reply);
    formatOtaCandidate(reply, sizeof(reply), view);
    EXPECT_NE(nullptr, std::strstr(reply, "counter=5 generation=9"));
    formatOtaSettings(reply, sizeof(reply), integration);
    EXPECT_STREQ("mode=fleet duty=2.0%", reply);
  };
  for (const uint8_t permissions : {PERM_ACL_GUEST, PERM_ACL_READ_ONLY, PERM_ACL_READ_WRITE, 0xFD}) {
    client.permissions = permissions;
    dispatch(PAYLOAD_TYPE_TXT_MSG, 20);
  }
  EXPECT_EQ(0u, dispatched);
  EXPECT_EQ(reads, flash.readOpCount());
  client.permissions = PERM_ACL_ADMIN;
  dispatch(PAYLOAD_TYPE_REQ, 20);
  dispatch(PAYLOAD_TYPE_TXT_MSG, 5);
  EXPECT_EQ(0u, dispatched);
  EXPECT_EQ(reads, flash.readOpCount());
  dispatch(PAYLOAD_TYPE_TXT_MSG, 20);
  client.permissions = 0xFF;
  dispatch(PAYLOAD_TYPE_TXT_MSG, 20);
  EXPECT_EQ(2u, dispatched);
  EXPECT_GT(flash.readOpCount(), reads);
  EXPECT_EQ(programs, flash.programOpCount());
  EXPECT_EQ(erases, flash.eraseOpCount());
  std::memcpy(client.id.pub_key, candidate.ownerPublicKey, 32);
  const auto selected = integration.leanReceiver().status();
  const auto abort = [&]() {
    if (!CommonCLI::isAdminTextCommand(PAYLOAD_TYPE_TXT_MSG, 14, client)) return;
    const auto result = integration.abortAuthenticatedAdminCommand(
        client.id.pub_key, selected.generation, selected.counter, selected.imageHash);
    char reply[160];
    formatOtaAdminAbortResult(reply, sizeof(reply), result);
    EXPECT_STREQ("OK - OTA aborted", reply);
  };
  client.permissions = PERM_ACL_READ_ONLY;
  abort();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Receiving, integration.leanReceiver().status().phase);
  EXPECT_EQ(programs, flash.programOpCount());
  client.permissions = PERM_ACL_ADMIN;
  abort();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, integration.leanReceiver().status().phase);
  EXPECT_EQ(10u, integration.leanReceiver().status().generation);
  const auto aborted_programs = flash.programOpCount();
  abort();
  EXPECT_EQ(aborted_programs, flash.programOpCount());
  client.id.pub_key[0] ^= 1;
  EXPECT_EQ(usb::UsbOtaResult::Denied, integration.abortAuthenticatedAdminCommand(
      client.id.pub_key, selected.generation, selected.counter, selected.imageHash));
  EXPECT_EQ(aborted_programs, flash.programOpCount());
}
