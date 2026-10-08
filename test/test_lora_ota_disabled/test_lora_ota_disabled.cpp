#include <gtest/gtest.h>
#include <Mesh.h>
#include <helpers/StaticPoolPacketManager.h>
#include "legacy_packet_manager.h"
#include <array>
#include <deque>
#include <vector>

namespace {
class Clock : public mesh::MillisecondClock {
public:
  unsigned long now = 1;
  unsigned long getMillis() override { return now; }
};
class Random : public mesh::RNG {
public:
  void random(uint8_t* dest, size_t size) override { memset(dest, 0, size); }
};
class RealtimeClock : public mesh::RTCClock {
public:
  uint32_t getCurrentTime() override { return 1; }
  void setCurrentTime(uint32_t) override {}
};
class Tables : public mesh::MeshTables {
public:
  int checks = 0;
  int marks = 0;
  bool wasSeen(const mesh::Packet*) override { ++checks; return false; }
  void markSeen(const mesh::Packet*) override { ++marks; }
  void clear(const mesh::Packet*) override {}
};
class Radio : public mesh::Radio {
public:
  std::deque<std::vector<uint8_t>> incoming;
  std::vector<std::vector<uint8_t>> transmitted;
  uint32_t airtime = 200;
  bool sending = false;
  bool completed = false;
  int finishes = 0;

  int recvRaw(uint8_t* bytes, int size) override {
    if (incoming.empty()) return 0;
    auto raw = incoming.front();
    incoming.pop_front();
    if (static_cast<int>(raw.size()) > size) return 0;
    memcpy(bytes, raw.data(), raw.size());
    return raw.size();
  }
  void receive(const mesh::Packet& packet) {
    uint8_t bytes[MAX_TRANS_UNIT];
    auto size = packet.writeTo(bytes);
    incoming.emplace_back(bytes, bytes + size);
  }
  uint32_t getEstAirtimeFor(int) override { return airtime; }
  float packetScore(float, int) override { return 1; }
  bool startSendRaw(const uint8_t* bytes, int size) override {
    transmitted.emplace_back(bytes, bytes + size);
    sending = true;
    completed = false;
    return true;
  }
  bool isSendComplete() override { return completed; }
  void onSendFinished() override { sending = false; completed = false; ++finishes; }
  bool isInRecvMode() const override { return !sending; }
};
class Mesh : public mesh::Mesh {
public:
  unsigned long window = 3600000;
  int rx_delay = 0;
  int ota_received = 0;
  Mesh(Radio& radio, Clock& clock, Random& random, RealtimeClock& rtc,
       mesh::PacketManager& manager, Tables& tables)
      : mesh::Mesh(radio, clock, random, rtc, manager, tables) {
    self_id.pub_key[0] = 0xAB;
  }
  mesh::DispatcherAction receive(mesh::Packet* packet) { return onRecvPacket(packet); }
protected:
  bool allowPacketForward(const mesh::Packet*) override { return true; }
  uint32_t getRetransmitDelay(const mesh::Packet*) override { return 0; }
  int calcRxDelay(float, uint32_t) const override { return rx_delay; }
  unsigned long getDutyCycleWindowMs() const override { return window; }
  void onOtaDataRecv(mesh::Packet*) override { ++ota_received; }
};
struct Fixture : ::testing::Test {
  Clock clock;
  Random random;
  RealtimeClock rtc;
  Radio radio;
  Tables tables;
  LegacyPacketManager manager;
  Mesh mesh{radio, clock, random, rtc, manager, tables};
  mesh::Packet* packet(uint8_t type, uint8_t route = ROUTE_TYPE_FLOOD) {
    auto* p = mesh.obtainNewPacket();
    EXPECT_NE(nullptr, p);
    p->header = (type << PH_TYPE_SHIFT) | route;
    p->payload_len = 1;
    p->payload[0] = 0x55;
    return p;
  }
};

TEST_F(Fixture, LegacyConsumerCompilesAndOrdinarySubmissionConsumesExactlyOnce) {
  auto* p = packet(PAYLOAD_TYPE_RAW_CUSTOM);
  manager.drop_submission = true;
  EXPECT_TRUE(mesh.sendPacket(p, 7, 20));
  EXPECT_EQ(1, manager.submissions);
  EXPECT_EQ(1, manager.releases);
  EXPECT_EQ(8, manager.getFreeCount());
  EXPECT_EQ(7, manager.last_priority);
  EXPECT_EQ(21u, manager.last_schedule);
}

TEST_F(Fixture, UnsupportedOptionalQueueRetainsOwnershipOnFailure) {
  auto* p = packet(PAYLOAD_TYPE_RAW_CUSTOM);
  EXPECT_FALSE(manager.supportsOtaQueue());
  EXPECT_EQ(nullptr, manager.allocOtaPacket());
  EXPECT_FALSE(manager.tryQueueOutbound(p, 7, 0));
  uint8_t priority = 13;
  EXPECT_EQ(nullptr, manager.getNextOutboundWithPriority(1, &priority));
  EXPECT_EQ(13, priority);
  uint32_t scheduled_for = 99;
  EXPECT_FALSE(manager.getOutboundScheduleByIdx(0, scheduled_for));
  EXPECT_EQ(99u, scheduled_for);
  EXPECT_EQ(0, manager.releases);
  EXPECT_EQ(7, manager.getFreeCount());
  mesh.releasePacket(p);
  EXPECT_EQ(8, manager.getFreeCount());
}

TEST_F(Fixture, OrdinaryInvalidFloodRetainsOwnershipButInvalidDispatcherSubmissionConsumes) {
  auto* p = packet(PAYLOAD_TYPE_RAW_CUSTOM);
  EXPECT_FALSE(mesh.sendFlood(p, uint32_t{0}, uint8_t{4}));
  EXPECT_EQ(0, manager.submissions);
  EXPECT_EQ(0, manager.releases);
  EXPECT_EQ(7, manager.getFreeCount());
  mesh.releasePacket(p);
  p = packet(PAYLOAD_TYPE_RAW_CUSTOM);
  p->path_len = 0xC0;
  EXPECT_FALSE(mesh.sendPacket(p, 1));
  EXPECT_EQ(2, manager.releases);
  EXPECT_EQ(8, manager.getFreeCount());
}

TEST_F(Fixture, LocalDirectPathKeepsPriorityOneButZeroHopPathKeepsPriorityZero) {
  auto* p = packet(PAYLOAD_TYPE_PATH);
  const uint8_t path[] = {0x21};
  mesh.sendDirect(p, path, 1, 42);
  EXPECT_EQ(1, manager.last_priority);
  EXPECT_EQ(43u, manager.last_schedule);
  auto* zero_hop = packet(PAYLOAD_TYPE_PATH);
  mesh.sendZeroHop(zero_hop);
  EXPECT_EQ(0, manager.last_priority);
  const uint16_t codes[] = {0x1234, 0x5678};
  auto* scoped = packet(PAYLOAD_TYPE_PATH);
  uint16_t transport_codes[2] = {codes[0], codes[1]};
  mesh.sendZeroHop(scoped, transport_codes);
  EXPECT_EQ(0, manager.last_priority);
}

TEST_F(Fixture, OrdinaryFloodOriginsAndRelaysKeepDifferentPriorities) {
  mesh.sendFlood(packet(PAYLOAD_TYPE_RAW_CUSTOM));
  EXPECT_EQ(1, manager.last_priority);
  mesh.sendFlood(packet(PAYLOAD_TYPE_PATH));
  EXPECT_EQ(2, manager.last_priority);
  mesh.sendFlood(packet(PAYLOAD_TYPE_ADVERT));
  EXPECT_EQ(3, manager.last_priority);
  auto* ack = packet(PAYLOAD_TYPE_ACK);
  ack->payload_len = 4;
  memset(ack->payload, 0, 4);
  ack->setPathHashSizeAndCount(1, 2);
  EXPECT_EQ(ACTION_RETRANSMIT_DELAYED(3, 0), mesh.receive(ack));
  mesh.releasePacket(ack);
}

TEST_F(Fixture, OrdinaryTransmissionUsesDevHalfMtuBudgetWithoutRequeueing) {
  mesh.window = 300;
  mesh.begin();
  EXPECT_EQ(150u, mesh.getRemainingTxBudget());
  auto* p = packet(PAYLOAD_TYPE_RAW_CUSTOM, ROUTE_TYPE_DIRECT);
  ASSERT_TRUE(mesh.sendPacket(p, 7));
  clock.now = 2;
  mesh.loop();
  ASSERT_EQ(1u, radio.transmitted.size());  // 150ms budget admits 200ms estimate on dev.
  EXPECT_EQ(1, manager.submissions);
  EXPECT_EQ(0, manager.getOutboundTotal());
  radio.completed = true;
  clock.now = 102;
  mesh.loop();
  EXPECT_EQ(50u, mesh.getRemainingTxBudget());
  ASSERT_TRUE(mesh.sendPacket(packet(PAYLOAD_TYPE_RAW_CUSTOM, ROUTE_TYPE_DIRECT), 4));
  clock.now = 103;
  mesh.loop();
  EXPECT_EQ(1u, radio.transmitted.size());
  clock.now = 202;
  mesh.loop();
  EXPECT_EQ(1u, radio.transmitted.size());  // dev timestamps use strictly-passed readiness.
  clock.now = 203;
  mesh.loop();
  EXPECT_EQ(1u, radio.transmitted.size());
  clock.now = 204;
  mesh.loop();
  EXPECT_EQ(2u, radio.transmitted.size());
  EXPECT_EQ(2, manager.submissions);
}

#if !MESHCORE_LORA_OTA
TEST_F(Fixture, DisabledUnknownType0CFloodDropsWithoutSeenStateOrForwarding) {
  mesh.begin();
  auto* p = packet(PAYLOAD_TYPE_LORA_OTA);
  radio.receive(*p);
  mesh.releasePacket(p);
  clock.now = 2;
  mesh.loop();
  EXPECT_EQ(0, tables.checks);
  EXPECT_EQ(0, tables.marks);
  EXPECT_EQ(0, mesh.ota_received);
  EXPECT_EQ(0, manager.getOutboundTotal());
  EXPECT_TRUE(radio.transmitted.empty());
  EXPECT_EQ(8, manager.getFreeCount());
}

TEST_F(Fixture, DisabledUnknownType0CDirectForwardingRetainsDevPriorityZero) {
  auto* p = packet(PAYLOAD_TYPE_LORA_OTA, ROUTE_TYPE_DIRECT);
  p->setPathHashSizeAndCount(1, 1);
  p->path[0] = 0xAB;
  EXPECT_EQ(ACTION_RETRANSMIT_DELAYED(0, 0), mesh.receive(p));
  EXPECT_EQ(0, p->getPathHashCount());
  mesh.releasePacket(p);
  auto* origin = packet(PAYLOAD_TYPE_LORA_OTA);
  mesh.sendFlood(origin);
  EXPECT_EQ(1, manager.last_priority);
  EXPECT_EQ(nullptr, mesh.createOtaData(reinterpret_cast<const uint8_t*>("x"), 1));
}
#else
TEST_F(Fixture, EnabledOtaFailsClosedWithLegacyManagerButOrdinaryStillWorks) {
  EXPECT_EQ(nullptr, mesh.createOtaData(reinterpret_cast<const uint8_t*>("x"), 1));
  auto* p = packet(PAYLOAD_TYPE_LORA_OTA);
  EXPECT_FALSE(mesh.sendPacket(p, 0));
  EXPECT_EQ(0, manager.submissions);
  EXPECT_EQ(8, manager.getFreeCount());
  mesh.begin();
  p = packet(PAYLOAD_TYPE_LORA_OTA);
  radio.receive(*p);
  mesh.releasePacket(p);
  clock.now = 2;
  mesh.loop();
  EXPECT_EQ(0, mesh.ota_received);
  EXPECT_EQ(0, tables.marks);
  EXPECT_EQ(8, manager.getFreeCount());
}
#endif

TEST(PacketQueueCompatibility, ExactPriorityAndScheduleAreAvailableWithoutChangingLegacyDequeue) {
  StaticPoolPacketManager manager(3);
  auto* low = manager.allocNew();
  auto* high = manager.allocNew();
  auto* future = manager.allocNew();
  manager.queueOutbound(low, 9, 1);
  manager.queueOutbound(high, 2, 1);
  manager.queueOutbound(future, 0, 50);
  uint32_t scheduled_for = 0;
  ASSERT_TRUE(manager.getOutboundScheduleByIdx(2, scheduled_for));
  EXPECT_EQ(50u, scheduled_for);
  EXPECT_FALSE(manager.getOutboundScheduleByIdx(3, scheduled_for));
  uint8_t priority = 0;
  EXPECT_EQ(high, manager.getNextOutboundWithPriority(1, &priority));
  EXPECT_EQ(2, priority);
  EXPECT_EQ(low, manager.getNextOutbound(1));
  EXPECT_EQ(nullptr, manager.getNextOutbound(49));
  EXPECT_EQ(future, manager.getNextOutbound(50));
  manager.free(low);
  manager.free(high);
  manager.free(future);
  EXPECT_EQ(3, manager.getFreeCount());
}

TEST(PacketQueueCompatibility, FullOptionalQueueLeavesPacketWithCaller) {
  StaticPoolPacketManager manager(1);
  auto* owned = manager.allocNew();
  ASSERT_TRUE(manager.tryQueueOutbound(owned, 1, 0));
  mesh::Packet caller_owned;
  caller_owned.payload_len = 17;
  EXPECT_FALSE(manager.tryQueueOutbound(&caller_owned, 2, 0));
  EXPECT_EQ(17, caller_owned.payload_len);
  EXPECT_EQ(0, manager.getFreeCount());
  EXPECT_EQ(1, manager.getOutboundTotal());
  EXPECT_EQ(owned, manager.getNextOutbound(0));
  manager.free(owned);
  EXPECT_EQ(1, manager.getFreeCount());
}

class RefusingManager : public StaticPoolPacketManager {
public:
  int releases = 0;
  RefusingManager() : StaticPoolPacketManager(8) {}
  bool tryQueueOutbound(mesh::Packet*, uint8_t, uint32_t) override { return false; }
  void free(mesh::Packet* packet) override { ++releases; StaticPoolPacketManager::free(packet); }
};

TEST(PacketQueueCompatibility, LegacyDropAndDispatcherConfirmedFailureEachConsumeExactlyOnce) {
  RefusingManager manager;
  manager.queueOutbound(manager.allocNew(), 1, 0);
  EXPECT_EQ(1, manager.releases);
  EXPECT_EQ(8, manager.getFreeCount());
  Radio radio;
  Clock clock;
  Random random;
  RealtimeClock rtc;
  Tables tables;
  Mesh mesh(radio, clock, random, rtc, manager, tables);
  auto* packet = mesh.obtainNewPacket();
  packet->header = PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT;
  packet->payload_len = 1;
  EXPECT_FALSE(mesh.sendPacket(packet, 1));
  EXPECT_EQ(2, manager.releases);
  EXPECT_EQ(8, manager.getFreeCount());
}

#if MESHCORE_LORA_OTA
struct EnabledFixture : ::testing::Test {
  Clock clock;
  Random random;
  RealtimeClock rtc;
  Radio radio;
  Tables tables;
  StaticPoolPacketManager manager{12};
  Mesh mesh{radio, clock, random, rtc, manager, tables};
  mesh::Packet* ota() {
    const uint8_t data[] = {0x55};
    return mesh.createOtaData(data, sizeof(data));
  }
};

TEST_F(EnabledFixture, ReservedAllocationAndRawAdmissionProtectOrdinaryPool) {
  std::vector<mesh::Packet*> held;
  while (auto* packet = manager.allocOtaPacket()) held.push_back(packet);
  EXPECT_EQ(mesh::PacketManager::kOtaAllocReserve, manager.getFreeCount());
  auto* ordinary = manager.allocNew();
  ASSERT_NE(nullptr, ordinary);  // Ordinary caller still uses the reserve.
  mesh::Packet incoming;
  incoming.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_LORA_OTA << PH_TYPE_SHIFT);
  incoming.payload_len = 1;
  incoming.payload[0] = 0x55;
  mesh.begin();
  radio.receive(incoming);
  clock.now = 2;
  mesh.loop();
  EXPECT_EQ(0, tables.marks);
  EXPECT_EQ(0, mesh.ota_received);
  EXPECT_EQ(3, manager.getFreeCount());
  manager.free(ordinary);
  for (auto* packet : held) manager.free(packet);
}

TEST_F(EnabledFixture, AllOtaRoutesAndRawInjectionStayBehindOrdinaryTraffic) {
  auto* zero_hop = ota();
  ASSERT_NE(nullptr, zero_hop);
  mesh.sendZeroHop(zero_hop);
  auto* scoped = ota();
  ASSERT_NE(nullptr, scoped);
  uint16_t codes[] = {1, 2};
  mesh.sendZeroHop(scoped, codes);
  auto* direct = ota();
  ASSERT_NE(nullptr, direct);
  const uint8_t path[] = {0xAB};
  mesh.sendDirect(direct, path, 1);
  auto* injected = ota();
  ASSERT_NE(nullptr, injected);
  EXPECT_TRUE(mesh.sendPacket(injected, 0));
  auto* normal = mesh.obtainNewPacket();
  normal->header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_PATH << PH_TYPE_SHIFT);
  normal->payload_len = 1;
  mesh.sendZeroHop(normal);
  uint8_t priority = 255;
  EXPECT_EQ(normal, manager.getNextOutboundWithPriority(1, &priority));
  EXPECT_EQ(0, priority);
  manager.free(normal);
  for (int i = 0; i < 4; ++i) {
    auto* packet = manager.getNextOutboundWithPriority(1, &priority);
    ASSERT_NE(nullptr, packet);
    EXPECT_EQ(mesh::ota::kOtaForwardPriority, priority);
    manager.free(packet);
  }
}

TEST_F(EnabledFixture, FullAirtimeDefersOnlyOtaWithoutChangingOrdinaryDevBudget) {
  mesh.window = 300;
  mesh.begin();
  auto* packet = ota();
  ASSERT_NE(nullptr, packet);
  mesh.sendZeroHop(packet);
  clock.now = 2;
  mesh.loop();
  EXPECT_TRUE(radio.transmitted.empty());
  EXPECT_EQ(1, manager.getOutboundTotal());
  uint32_t scheduled_for = 0;
  ASSERT_TRUE(manager.getOutboundScheduleByIdx(0, scheduled_for));
  EXPECT_GT(scheduled_for, clock.now);
  auto* normal = mesh.obtainNewPacket();
  normal->header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT);
  normal->payload_len = 1;
  ASSERT_TRUE(mesh.sendPacket(normal, 0));
  clock.now = 3;
  mesh.loop();
  EXPECT_EQ(1u, radio.transmitted.size());  // Shelving OTA must not globally delay ordinary traffic.
  uint8_t priority = 0;
  EXPECT_EQ(packet, manager.getNextOutboundWithPriority(scheduled_for, &priority));
  EXPECT_EQ(mesh::ota::kOtaForwardPriority, priority);
  manager.free(packet);
}

TEST_F(EnabledFixture, DelayedIngressRelayChecksReserveAgainAfterPoolPressureChanges) {
  mesh.rx_delay = 100;
  mesh.begin();
  mesh::Packet incoming;
  incoming.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_LORA_OTA << PH_TYPE_SHIFT);
  incoming.payload_len = 1;
  incoming.payload[0] = 0x55;
  radio.receive(incoming);
  clock.now = 2;
  mesh.loop();
  EXPECT_EQ(11, manager.getFreeCount());
  EXPECT_EQ(0, mesh.ota_received);
  std::vector<mesh::Packet*> held;
  while (manager.getFreeCount() > mesh::PacketManager::kOtaAllocReserve) held.push_back(manager.allocNew());
  clock.now = 103;
  mesh.loop();
  EXPECT_EQ(1, mesh.ota_received);
  EXPECT_EQ(1, tables.marks);
  EXPECT_EQ(0, manager.getOutboundTotal());
  EXPECT_TRUE(radio.transmitted.empty());
  EXPECT_EQ(5, manager.getFreeCount());
  for (auto* packet : held) manager.free(packet);
  EXPECT_EQ(12, manager.getFreeCount());
}

TEST_F(EnabledFixture, PostParseRawReserveRejectionConsumesOnlyOtaPacket) {
  std::vector<mesh::Packet*> held;
  while (manager.getFreeCount() > 5) held.push_back(manager.allocNew());
  auto* injected = mesh.obtainNewPacket();
  injected->header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_LORA_OTA << PH_TYPE_SHIFT);
  injected->payload_len = 1;
  EXPECT_FALSE(mesh.sendPacket(injected, 0));
  EXPECT_EQ(5, manager.getFreeCount());
  EXPECT_EQ(0, manager.getOutboundTotal());
  auto* normal = mesh.obtainNewPacket();
  normal->header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT);
  normal->payload_len = 1;
  EXPECT_TRUE(mesh.sendPacket(normal, 0));
  EXPECT_EQ(4, manager.getFreeCount());
  EXPECT_EQ(normal, manager.getNextOutbound(1));
  manager.free(normal);
  for (auto* packet : held) manager.free(packet);
}

TEST_F(EnabledFixture, FutureScheduledOrdinaryTrafficDoesNotBlockReadyOta) {
  mesh.begin();
  auto* normal = mesh.obtainNewPacket();
  normal->header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT);
  normal->payload_len = 1;
  ASSERT_TRUE(mesh.sendPacket(normal, 0, 1000));
  auto* packet = ota();
  ASSERT_NE(nullptr, packet);
  mesh.sendZeroHop(packet);
  clock.now = 2;
  EXPECT_FALSE(mesh.hasQueuedNormalTraffic());
  EXPECT_TRUE(mesh.hasQueuedOtaTraffic());
  mesh.loop();
  EXPECT_EQ(1u, radio.transmitted.size());
  EXPECT_EQ(1, manager.getOutboundTotal());
}

TEST(PacketQueueCompatibility, ConfirmedOtaFailureConsumesExactlyOnceInDispatcher) {
  RefusingManager manager;
  Radio radio;
  Clock clock;
  Random random;
  RealtimeClock rtc;
  Tables tables;
  Mesh mesh(radio, clock, random, rtc, manager, tables);
  const uint8_t data[] = {0x55};
  auto* packet = mesh.createOtaData(data, sizeof(data));
  ASSERT_NE(nullptr, packet);
  EXPECT_FALSE(mesh.sendPacket(packet, 0));
  EXPECT_EQ(1, manager.releases);
  EXPECT_EQ(8, manager.getFreeCount());
}
#endif
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
