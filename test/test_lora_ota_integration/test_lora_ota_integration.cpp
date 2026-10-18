#include <gtest/gtest.h>
#include <Mesh.cpp>
#include <helpers/ota/OtaFirmwareIntegration.h>
#include <helpers/ota/OtaRfFrames.h>
#include <helpers/SimpleMeshTables.h>
#include <helpers/StaticPoolPacketManager.cpp>
#include <vector>

namespace mesh {
Identity::Identity() { memset(pub_key, 0, sizeof(pub_key)); }
LocalIdentity::LocalIdentity() { memset(prv_key, 0, sizeof(prv_key)); }
bool Identity::verify(const uint8_t*, const uint8_t*, int) const { return false; }
void LocalIdentity::sign(uint8_t*, const uint8_t*, int) const { ADD_FAILURE(); }
void LocalIdentity::calcSharedSecret(uint8_t*, const uint8_t*) const { ADD_FAILURE(); }
}

namespace {
using namespace mesh::ota::v4;

class PlatformStub : public Platform {
public:
  unsigned signatures = 0;
  Policy policy() const override { return {}; }
  Result identity(uint8_t out[32]) override { memset(out, 0xA1, 32); return Result::Ok; }
  Result evidence(RunningEvidence& out) override { out = {}; return Result::Ok; }
  Result random(uint8_t* out, size_t size) override { memset(out, 0xB2, size); return Result::Ok; }
  bool isCurrentAdmin(const uint8_t[32]) override { return false; }
  bool verify(const uint8_t[32], const char*, size_t, const uint8_t*, size_t, const uint8_t[64]) override {
    ADD_FAILURE() << "A status query does not authorize an update";
    return false;
  }
  Result sign(const char*, size_t, const uint8_t*, size_t, uint8_t out[64]) override {
    ++signatures; memset(out, 0xC3, 64); return Result::Ok;
  }
  Result recover(Journal&, uint8_t*, size_t, size_t&) override { return Result::State; }
  Result save(const Journal&, const uint8_t*, size_t) override { return Result::Unsupported; }
  Result beginStaging(uint32_t) override { return Result::Unsupported; }
  Result writeStaging(uint32_t, const uint8_t*, size_t) override { return Result::Unsupported; }
  Result readStaging(uint32_t, uint8_t*, size_t) override { return Result::Unsupported; }
  Result clearStaging() override { return Result::Unsupported; }
  Result repair(const Journal&) override { return Result::Unsupported; }
  Result validateInstall(const uint8_t[59], const uint8_t[64], const uint8_t[32]) override { return Result::Unsupported; }
  Result activate(const uint8_t[59], const uint8_t[64], const uint8_t[32], const uint8_t[16], uint32_t) override {
    return Result::Unsupported;
  }
  Result lifecycle(Phase&) override { return Result::State; }
  Result lease(uint32_t, uint32_t, uint8_t, uint8_t, uint32_t) override { return Result::Unsupported; }
};

struct Integration : testing::Test {
  PlatformStub platform;
  Receiver receiver{platform};
  mesh::ota::OtaFirmwareIntegration integration;
  uint8_t query[kMaxFrameBytes] = {};
  size_t query_size = 0;
  void SetUp() override {
    ASSERT_EQ(Result::Ok, integration.attach(&receiver));
    uint8_t body[kQueryBytes] = {}, tag[8] = {};
    memset(body, 0xA1, 32);
    memset(body + 32, 0xD4, 16);
    query_size = encodeFrame(Kind::Query, 7, tag, 123, sizeof(body), 0,
        body, sizeof(body), query, sizeof(query));
    ASSERT_NE(0u, query_size);
  }
  void drain() { size_t size; while (integration.peek(size)) integration.release(); }
};

TEST_F(Integration, SameReceiverRepliesStayOwnedUntilEverySliceHasBeenAccepted) {
  ASSERT_EQ(Result::Ok, integration.onFrame(query, query_size, false, 1000));
  size_t size;
  const auto* pending = integration.peek(size);
  ASSERT_NE(nullptr, pending);
  Frame first;
  ASSERT_TRUE(decodeFrame(pending, size, first));
  EXPECT_EQ(Kind::Status, first.kind);
  EXPECT_EQ(123u, first.object);
  EXPECT_EQ(kStatusBytes, first.total);
  EXPECT_EQ(0u, first.slice);
  EXPECT_EQ(Result::Busy, integration.onFrame(query, query_size, true, 1500));
  EXPECT_FALSE(integration.localReply());
  EXPECT_EQ(pending, integration.peek(size));
  integration.release();
  Frame second;
  pending = integration.peek(size);
  ASSERT_TRUE(decodeFrame(pending, size, second));
  EXPECT_EQ(1u, second.slice);
  integration.release();
  EXPECT_EQ(nullptr, integration.peek(size));
  EXPECT_EQ(1u, platform.signatures);
}

TEST_F(Integration, LocalFeedUsesTheSameReceiverButNeverCreatesRfWork) {
  ASSERT_EQ(Result::Ok, integration.onFrame(query, query_size, true, 1000));
  EXPECT_TRUE(integration.localReply());
  EXPECT_FALSE(integration.hasPendingRfWork());
  EXPECT_EQ(&receiver, integration.receiver());
  drain();
  EXPECT_EQ(Result::Busy, integration.onFrame(query, query_size, false, 1100));
  EXPECT_EQ(1u, platform.signatures);
  EXPECT_EQ(Result::Ok, integration.onFrame(query, query_size, false, 1250));
  EXPECT_TRUE(integration.hasPendingRfWork());
  EXPECT_EQ(2u, platform.signatures);
}

TEST_F(Integration, LeaseExpiryAndFailedRestorationRemainOwnedAndDoNotRewritePreferences) {
  struct Radio { unsigned changes = 0, restores = 0; bool restore_ok = false; } radio;
  integration.attachProfile(&radio, [](void* ctx, uint32_t, uint32_t, uint8_t, uint8_t, bool restore) {
    auto& radio = *static_cast<Radio*>(ctx);
    if (restore) { ++radio.restores; return radio.restore_ok; }
    ++radio.changes; return true;
  });
  ASSERT_EQ(Result::Ok, integration.lease(UINT32_MAX - 20, true, 869000, 250000, 7, 5, 30));
  integration.tick(8, true);
  EXPECT_TRUE(integration.leaseActive());
  integration.tick(10, false);
  EXPECT_EQ(0u, radio.restores);
  integration.tick(10, true);
  EXPECT_TRUE(integration.leaseActive());
  radio.restore_ok = true;
  integration.tick(11, true);
  EXPECT_TRUE(integration.leaseActive());
  integration.tick(1010, true);
  EXPECT_FALSE(integration.leaseActive());
  EXPECT_EQ(2u, radio.restores);
  EXPECT_EQ(1u, radio.changes);
}

TEST_F(Integration, PartiallyFailedProfileApplicationStillSchedulesRestoration) {
  unsigned restores = 0;
  integration.attachProfile(&restores, [](void* ctx, uint32_t, uint32_t, uint8_t, uint8_t, bool restore) {
    if (restore) { ++*static_cast<unsigned*>(ctx); return true; }
    return false;
  });
  EXPECT_EQ(Result::Io, integration.lease(1000, true, 869000, 250000, 7, 5, 60000));
  EXPECT_TRUE(integration.leaseActive());
  integration.tick(1001, false);
  EXPECT_EQ(0u, restores);
  integration.tick(1001, true);
  EXPECT_EQ(1u, restores);
  EXPECT_FALSE(integration.leaseActive());
}

TEST_F(Integration, OrdinaryProfileRequestStopsLeaseOnlyAfterRadioIsIdle) {
  unsigned restores = 0;
  integration.attachProfile(&restores, [](void* ctx, uint32_t, uint32_t, uint8_t, uint8_t, bool restore) {
    if (restore) ++*static_cast<unsigned*>(ctx);
    return true;
  });
  ASSERT_EQ(Result::Ok, integration.lease(1000, true, 869000, 250000, 7, 5, 60000));
  integration.requestLeaseStop(1001);
  EXPECT_EQ(0u, restores);
  integration.tick(1002, false);
  EXPECT_TRUE(integration.leaseActive());
  EXPECT_EQ(0u, restores);
  integration.tick(1003, true);
  EXPECT_EQ(1u, restores);
  EXPECT_FALSE(integration.leaseActive());
}

TEST_F(Integration, AttemptsAreAlreadyPartOfTheGenericFrameAndChangeMeshDuplicateHash) {
  mesh::Packet first, retry;
  first.header = retry.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_LORA_OTA << PH_TYPE_SHIFT);
  first.payload_len = query_size;
  memcpy(first.payload, query, query_size);
  retry = first;
  write32(retry.payload + 2, 8);
  write32(retry.payload + retry.payload_len - 4, crc32(retry.payload, retry.payload_len - 4));
  uint8_t a[MAX_HASH_SIZE], b[MAX_HASH_SIZE];
  first.calculatePacketHash(a); retry.calculatePacketHash(b);
  EXPECT_NE(0, memcmp(a, b, sizeof(a)));
  EXPECT_TRUE(mesh::ota::validOtaPacket(&retry));
}

TEST(Airtime, RetuningDoesNotForgetActualUsageAndBucketsExpireOnlyAfterLastCompletion) {
  mesh::ota::AirtimeBudget budget(1000, 100);
  EXPECT_TRUE(budget.recordUsage(UINT32_MAX - 30, 40));
  EXPECT_TRUE(budget.recordUsage(10, 50));
  EXPECT_FALSE(budget.canAdmit(20, 11, true, false));
  budget.retune(1000, 95);
  EXPECT_FALSE(budget.canAdmit(20, 6, true, false));
  EXPECT_FALSE(budget.canAdmit(20, 1, false, false));
  EXPECT_FALSE(budget.canAdmit(20, 1, true, true));
  EXPECT_EQ(90u, budget.storedUsageMs(1000));
  EXPECT_EQ(0u, budget.storedUsageMs(1011));
}

TEST(Airtime, SustainedShortPacketsCoalesceWithoutAnUnboundedOrOverwrittenAccountingRing) {
  mesh::ota::AirtimeBudget budget(3600000, 3600000);
  for (uint32_t now = 0; now < 3600000; now += 1000) {
    ASSERT_TRUE(budget.canAdmit(now, 10, true, false));
    ASSERT_TRUE(budget.recordUsage(now, 10));
  }
  EXPECT_EQ(36000u, budget.storedUsageMs(3600000));
}

class Clock : public mesh::MillisecondClock {
public:
  unsigned long now = 1;
  unsigned long getMillis() override { return now; }
};
class Random : public mesh::RNG {
public:
  void random(uint8_t* out, size_t size) override { memset(out, 1, size); }
};
class Rtc : public mesh::RTCClock {
public:
  uint32_t getCurrentTime() override { return 1; }
  void setCurrentTime(uint32_t) override {}
};
class Radio : public mesh::Radio {
public:
  bool complete = false, transmitting = false;
  std::vector<std::vector<uint8_t>> sent;
  int recvRaw(uint8_t*, int) override { return 0; }
  uint32_t getEstAirtimeFor(int) override { return 200; }
  float packetScore(float, int) override { return 1; }
  bool startSendRaw(const uint8_t* data, int size) override {
    sent.emplace_back(data, data + size); transmitting = true; complete = false; return true;
  }
  bool isSendComplete() override { return complete; }
  void onSendFinished() override { transmitting = complete = false; }
  bool isInRecvMode() const override { return !transmitting; }
};
class Mesh : public mesh::Mesh {
public:
  Mesh(Radio& radio, Clock& clock, Random& random, Rtc& rtc, StaticPoolPacketManager& manager,
       SimpleMeshTables& tables) : mesh::Mesh(radio, clock, random, rtc, manager, tables) {}
  mesh::DispatcherAction receive(mesh::Packet& packet) { return onRecvPacket(&packet); }
};
struct MeshReceiver : testing::Test {
  PlatformStub platform;
  Receiver receiver{platform};
  Clock clock;
  Radio radio;
  Random random;
  Rtc rtc;
  SimpleMeshTables tables;
  StaticPoolPacketManager manager{12};
  Mesh mesh{radio, clock, random, rtc, manager, tables};
  mesh::Packet query;
  void SetUp() override {
    mesh.begin();
    ASSERT_EQ(Result::Ok, mesh.getOtaIntegration().attach(&receiver));
    uint8_t body[kQueryBytes] = {}, tag[8] = {};
    memset(body, 0xA1, 32);
    memset(body + 32, 0xD4, 16);
    query.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_LORA_OTA << PH_TYPE_SHIFT);
    query.payload_len = encodeFrame(Kind::Query, 7, tag, 123, sizeof(body), 0,
        body, sizeof(body), query.payload, sizeof(query.payload));
  }
};

TEST_F(MeshReceiver, ActualMeshFeedsOneReceiverAndDrainsBothGenericStatusSlicesThroughRadio) {
  mesh.receive(query);
  EXPECT_EQ(1u, platform.signatures);
  clock.now = 2;
  mesh.loop();
  EXPECT_EQ(1, manager.getOutboundTotal());
  clock.now = 3;
  mesh.loop();
  ASSERT_EQ(1u, radio.sent.size());
  radio.complete = true;
  clock.now = 203;
  mesh.loop();
  clock.now = 204;
  mesh.loop();
  ASSERT_EQ(2u, radio.sent.size());
  for (size_t i = 0; i < radio.sent.size(); ++i) {
    Frame frame;
    ASSERT_TRUE(decodeFrame(radio.sent[i].data() + 2, radio.sent[i].size() - 2, frame));
    EXPECT_EQ(Kind::Status, frame.kind);
    EXPECT_EQ(i, frame.slice);
    EXPECT_EQ(123u, frame.object);
  }
  size_t size;
  EXPECT_EQ(nullptr, receiver.peek(size));
  EXPECT_EQ(1u, platform.signatures);
}

TEST_F(MeshReceiver, SameAttemptIsSuppressedButANewV4AttemptReachesTheSameReceiver) {
  mesh.receive(query);
  size_t size;
  while (receiver.peek(size)) receiver.release();
  mesh.receive(query);
  EXPECT_EQ(1u, platform.signatures);
  clock.now = 500;
  write32(query.payload + 2, 8);
  write32(query.payload + query.payload_len - 4, crc32(query.payload, query.payload_len - 4));
  mesh.receive(query);
  EXPECT_EQ(2u, platform.signatures);
}

TEST_F(MeshReceiver, OrdinaryTrafficPrecedesPendingStatusAndLocalRepliesNeverLeakOntoRf) {
  const uint8_t byte = 1;
  auto* normal = mesh.createRawData(&byte, 1);
  ASSERT_NE(nullptr, normal);
  normal->header |= ROUTE_TYPE_DIRECT;
  ASSERT_TRUE(mesh.sendPacket(normal, 0));
  ASSERT_EQ(Result::Ok, mesh.getOtaIntegration().onFrame(query.payload, query.payload_len, true, 1));
  clock.now = 2;
  mesh.loop();
  ASSERT_EQ(1u, radio.sent.size());
  EXPECT_EQ(PAYLOAD_TYPE_RAW_CUSTOM, (radio.sent[0][0] >> PH_TYPE_SHIFT) & PH_TYPE_MASK);
  EXPECT_EQ(0, manager.getOutboundTotal());
  radio.complete = true;
  clock.now = 203;
  mesh.loop();
  clock.now = 204;
  mesh.loop();
  EXPECT_EQ(1u, radio.sent.size());
  EXPECT_EQ(0, manager.getOutboundTotal());
  size_t size;
  EXPECT_NE(nullptr, receiver.peek(size));
}
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
