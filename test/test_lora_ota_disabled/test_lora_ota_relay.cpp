#include <gtest/gtest.h>
#include <Mesh.h>
#include <helpers/SimpleMeshTables.h>
#include <helpers/StaticPoolPacketManager.h>
#include "../../examples/simple_repeater/RepeaterPrefs.h"
#include <array>
#include <deque>
#include <map>
#include <string>
#include <vector>

#if MESHCORE_LORA_OTA_RELAY && !MESHCORE_LORA_OTA
namespace {
class RelayClock : public mesh::MillisecondClock {
public:
  unsigned long now = 1;
  unsigned long getMillis() override { return now; }
};
class RelayRandom : public mesh::RNG {
public:
  void random(uint8_t* dest, size_t size) override { memset(dest, 0, size); }
};
class RelayRtc : public mesh::RTCClock {
public:
  uint32_t getCurrentTime() override { return 1; }
  void setCurrentTime(uint32_t) override {}
};
class RelayRadio : public mesh::Radio {
public:
  std::deque<std::vector<uint8_t>> incoming;
  std::vector<std::vector<uint8_t>> sent;
  uint32_t airtime = 200;
  bool completed = false;
  bool receiving = false;
  int recvRaw(uint8_t* bytes, int size) override {
    if (incoming.empty()) return 0;
    const auto raw = incoming.front();
    incoming.pop_front();
    if (static_cast<int>(raw.size()) > size) return 0;
    memcpy(bytes, raw.data(), raw.size());
    return raw.size();
  }
  void receive(const mesh::Packet& p) {
    uint8_t raw[MAX_TRANS_UNIT];
    const auto len = p.writeTo(raw);
    incoming.emplace_back(raw, raw + len);
  }
  uint32_t getEstAirtimeFor(int) override { return airtime; }
  float packetScore(float, int) override { return 1; }
  bool startSendRaw(const uint8_t* raw, int len) override {
    completed = false;
    sent.emplace_back(raw, raw + len);
    return true;
  }
  bool isSendComplete() override { return completed; }
  void onSendFinished() override { completed = false; }
  bool isInRecvMode() const override { return true; }
  bool isReceiving() override { return receiving; }
};
class RelayMesh : public mesh::Mesh {
public:
  bool forwarding = true;
  bool filtered = false;
  int local_ota = 0;
  int local_raw = 0;
  int local_acks = 0;
  unsigned long window = 3600000;
  float airtime_factor = 1;
  int rx_delay = 0;
  RelayMesh(RelayRadio& radio, RelayClock& clock, RelayRandom& random, RelayRtc& rtc,
            StaticPoolPacketManager& manager, SimpleMeshTables& tables)
      : mesh::Mesh(radio, clock, random, rtc, manager, tables) {
    self_id.pub_key[0] = 0xAB;
    self_id.pub_key[1] = 0xCD;
    self_id.pub_key[2] = 0xEF;
  }
  mesh::DispatcherAction receive(mesh::Packet& packet) { return onRecvPacket(&packet); }
protected:
  bool allowPacketForward(const mesh::Packet*) override { return forwarding; }
  bool filterRecvFloodPacket(mesh::Packet*) override { return filtered; }
  uint32_t getRetransmitDelay(const mesh::Packet*) override { return 0; }
  unsigned long getDutyCycleWindowMs() const override { return window; }
  float getAirtimeBudgetFactor() const override { return airtime_factor; }
  int calcRxDelay(float, uint32_t) const override { return rx_delay; }
  void onOtaDataRecv(mesh::Packet*) override { ++local_ota; }
  void onRawDataRecv(mesh::Packet*) override { ++local_raw; }
  void onAckRecv(mesh::Packet*, uint32_t) override { ++local_acks; }
};
class OpaqueRelay : public ::testing::Test {
public:
  RelayClock clock;
  RelayRandom random;
  RelayRtc rtc;
  RelayRadio radio;
  SimpleMeshTables tables;
  StaticPoolPacketManager manager{16};
  RelayMesh mesh{radio, clock, random, rtc, manager, tables};
  mesh::Packet packet(uint8_t route, uint8_t width = 1, uint8_t count = 0,
                      uint8_t kind = 0x11, uint32_t attempt = 1, uint8_t length = 169) {
    mesh::Packet p;
    p.header = (PAYLOAD_TYPE_LORA_OTA << PH_TYPE_SHIFT) | route;
    p.setPathHashSizeAndCount(width, count);
    memset(p.path, 0x44, sizeof(p.path));
    if (count) mesh.self_id.copyHashTo(p.path, width);
    p.payload_len = length;
    memset(p.payload, 0x5A, length);
    p.payload[0] = kind;
    p.payload[1] = attempt >> 24;
    p.payload[2] = attempt >> 16;
    p.payload[3] = attempt >> 8;
    p.payload[4] = attempt;
    return p;
  }
};

TEST_F(OpaqueRelay, DirectedRequestsConsumeExactlyOneSelectedHopAndPreserveAllPayload) {
  for (uint8_t width = 1; width <= 3; ++width) {
    for (uint8_t kind : {0x11, 0x12}) {
      auto p = packet(ROUTE_TYPE_DIRECT, width, 2, kind, width * 10 + kind);
      const auto before = p;
      EXPECT_EQ(ACTION_RETRANSMIT_DELAYED(250, 0), mesh.receive(p));
      EXPECT_EQ(1, p.getPathHashCount());
      EXPECT_EQ(width, p.getPathHashSize());
      EXPECT_EQ(0, memcmp(p.path, before.path + width, width));
      EXPECT_EQ(0, memcmp(p.payload, before.payload, p.payload_len));
      EXPECT_EQ(0, mesh.local_ota);
      auto duplicate = before;
      EXPECT_EQ(ACTION_RELEASE, mesh.receive(duplicate));
    }
  }
}

TEST_F(OpaqueRelay, CensusReplyFloodAppendsExactlyOneRelayPrefixAtEveryHashWidth) {
  for (uint8_t width = 1; width <= 3; ++width) {
    auto p = packet(ROUTE_TYPE_FLOOD, width, 0, 0x11, width, 128);
    const auto before = p;
    EXPECT_EQ(ACTION_RETRANSMIT_DELAYED(250, 0), mesh.receive(p));
    EXPECT_EQ(1, p.getPathHashCount());
    EXPECT_EQ(width, p.getPathHashSize());
    EXPECT_EQ(0, memcmp(p.path, mesh.self_id.pub_key, width));
    EXPECT_EQ(0, memcmp(p.payload, before.payload, 128));
    auto duplicate = before;
    EXPECT_EQ(ACTION_RELEASE, mesh.receive(duplicate));
    EXPECT_EQ(ACTION_RELEASE, mesh.receive(p));  // Own flood echo is the same packet.
  }
  EXPECT_EQ(0, mesh.local_ota);
}

TEST_F(OpaqueRelay, RealDispatcherTransmitsRequestAndReplyWithCorrectHeadersTrailsAndAttempts) {
  mesh.begin();
  const auto request = packet(ROUTE_TYPE_DIRECT, 3, 1);
  radio.receive(request);
  clock.now = 2;
  mesh.loop();
  ASSERT_EQ(1u, radio.sent.size());
  EXPECT_EQ(0x32, radio.sent[0][0]);
  EXPECT_EQ(0x80, radio.sent[0][1]);
  EXPECT_EQ(0, memcmp(radio.sent[0].data() + 2, request.payload, 169));
  radio.completed = true;
  clock.now = 202;
  mesh.loop();
  const auto reply = packet(ROUTE_TYPE_FLOOD, 1, 0, 0x11, 77, 128);
  radio.receive(reply);
  clock.now = 203;
  mesh.loop();
  ASSERT_EQ(2u, radio.sent.size());
  EXPECT_EQ(0x31, radio.sent[1][0]);
  EXPECT_EQ(1, radio.sent[1][1]);
  EXPECT_EQ(0xAB, radio.sent[1][2]);
  EXPECT_EQ(0, memcmp(radio.sent[1].data() + 3, reply.payload, 128));
  EXPECT_EQ(0, mesh.local_ota);
}

TEST_F(OpaqueRelay, NewAttemptIsDistinctButPathVariationCannotBypassNativeDedup) {
  auto p = packet(ROUTE_TYPE_FLOOD);
  EXPECT_NE(ACTION_RELEASE, mesh.receive(p));
  p = packet(ROUTE_TYPE_FLOOD, 1, 1);
  p.path[0] = 0x34;
  EXPECT_EQ(ACTION_RELEASE, mesh.receive(p));
  p = packet(ROUTE_TYPE_FLOOD, 1, 0, 0x11, 2);
  EXPECT_NE(ACTION_RELEASE, mesh.receive(p));
  EXPECT_EQ(0, mesh.local_ota);
}

TEST_F(OpaqueRelay, WrongHopDisabledTransportFilteredFloodAndDoNotRetransmitStillApply) {
  auto p = packet(ROUTE_TYPE_DIRECT, 1, 1);
  p.path[0] = 0x33;
  EXPECT_EQ(ACTION_RELEASE, mesh.receive(p));
  mesh.forwarding = false;
  p = packet(ROUTE_TYPE_DIRECT, 1, 1);
  EXPECT_EQ(ACTION_RELEASE, mesh.receive(p));
  p = packet(ROUTE_TYPE_FLOOD);
  EXPECT_EQ(ACTION_RELEASE, mesh.receive(p));
  mesh.forwarding = true;
  mesh.filtered = true;
  p = packet(ROUTE_TYPE_FLOOD, 1, 0, 0x11, 2);
  EXPECT_EQ(ACTION_RELEASE, mesh.receive(p));
  mesh.filtered = false;
  EXPECT_NE(ACTION_RELEASE, mesh.receive(p));  // Filtered copy did not poison dedup.
  p = packet(ROUTE_TYPE_FLOOD, 1, 0, 0x11, 3);
  p.markDoNotRetransmit();
  EXPECT_EQ(ACTION_RELEASE, mesh.receive(p));
}

TEST_F(OpaqueRelay, FullPathAndDirectZeroHopCannotCreateFallbackForwardingOrLocalInstallation) {
  auto p = packet(ROUTE_TYPE_FLOOD, 2, MAX_PATH_SIZE / 2);
  EXPECT_EQ(ACTION_RELEASE, mesh.receive(p));
  p = packet(ROUTE_TYPE_DIRECT);
  EXPECT_EQ(ACTION_RELEASE, mesh.receive(p));
  EXPECT_EQ(0, mesh.local_ota);
  EXPECT_FALSE(mesh::ota::kOtaMeshEnabled);
  EXPECT_EQ(nullptr, mesh.createOtaData(p.payload, p.payload_len));
}

TEST_F(OpaqueRelay, OpaqueFutureOrMalformedInstallerPayloadIsNeverInterpretedByRelay) {
  auto p = packet(ROUTE_TYPE_FLOOD, 1, 0, 0xFE);
  p.payload_len = 1;
  EXPECT_NE(ACTION_RELEASE, mesh.receive(p));
  p = packet(ROUTE_TYPE_FLOOD);
  p.payload_len = 1;  // An incomplete attempt envelope is opaque here.
  EXPECT_NE(ACTION_RELEASE, mesh.receive(p));
  EXPECT_EQ(0, mesh.local_ota);
}

TEST_F(OpaqueRelay, QueueReserveRejectsIngressAndRawSubmissionWithoutStarvingOrdinaryBuffers) {
  std::vector<mesh::Packet*> held;
  while (manager.getFreeCount() > 5) held.push_back(manager.allocNew());
  mesh.begin();
  radio.receive(packet(ROUTE_TYPE_FLOOD));
  clock.now = 2;
  mesh.loop();
  EXPECT_EQ(5, manager.getFreeCount());
  EXPECT_EQ(0, manager.getOutboundTotal());
  EXPECT_TRUE(radio.sent.empty());
  auto* ota = mesh.obtainNewPacket();
  *ota = packet(ROUTE_TYPE_DIRECT);
  EXPECT_FALSE(mesh.sendPacket(ota, 0));
  EXPECT_EQ(5, manager.getFreeCount());
  auto* ordinary = mesh.obtainNewPacket();
  ordinary->header = (PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_DIRECT;
  ordinary->payload_len = 1;
  EXPECT_TRUE(mesh.sendPacket(ordinary, 0));
  manager.free(manager.getNextOutbound(clock.now));
  for (auto* p : held) manager.free(p);
  EXPECT_EQ(16, manager.getFreeCount());
}

TEST_F(OpaqueRelay, DelayedIngressRechecksPoolReserveBeforeHoldingOutboundRelay) {
  mesh.rx_delay = 100;
  mesh.begin();
  radio.receive(packet(ROUTE_TYPE_FLOOD));
  clock.now = 2;
  mesh.loop();
  EXPECT_EQ(15, manager.getFreeCount());
  std::vector<mesh::Packet*> held;
  while (manager.getFreeCount() > 4) held.push_back(manager.allocNew());
  clock.now = 103;
  mesh.loop();
  EXPECT_EQ(0, manager.getOutboundTotal());
  EXPECT_EQ(5, manager.getFreeCount());
  EXPECT_TRUE(radio.sent.empty());
  for (auto* p : held) manager.free(p);
}

TEST_F(OpaqueRelay, OrdinaryTrafficWinsEvenWhenOtaWasSubmittedWithHighPriority) {
  mesh.begin();
  auto* ota = mesh.obtainNewPacket();
  *ota = packet(ROUTE_TYPE_DIRECT);
  EXPECT_TRUE(mesh.sendPacket(ota, 0));
  auto* normal = mesh.obtainNewPacket();
  normal->header = (PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_DIRECT;
  normal->payload_len = 1;
  normal->payload[0] = 0x42;
  EXPECT_TRUE(mesh.sendPacket(normal, 3));
  clock.now = 2;
  mesh.loop();
  ASSERT_EQ(1u, radio.sent.size());
  EXPECT_EQ((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_DIRECT, radio.sent[0][0]);
  EXPECT_EQ(1, manager.getOutboundTotal());
  uint8_t priority = 0;
  EXPECT_EQ(ota, manager.getNextOutboundWithPriority(clock.now, &priority));
  EXPECT_EQ(250, priority);
  manager.free(ota);
}

TEST_F(OpaqueRelay, FullMeshAirtimeDefersOnlyOtaAndOrdinaryRoutingRemainsUnchanged) {
  mesh.window = 300;
  mesh.begin();
  auto* ota = mesh.obtainNewPacket();
  *ota = packet(ROUTE_TYPE_DIRECT);
  ASSERT_TRUE(mesh.sendPacket(ota, 0));
  clock.now = 2;
  mesh.loop();
  EXPECT_TRUE(radio.sent.empty());
  EXPECT_EQ(1, manager.getOutboundTotal());
  auto* normal = mesh.obtainNewPacket();
  normal->header = (PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_DIRECT;
  normal->payload_len = 1;
  ASSERT_TRUE(mesh.sendPacket(normal, 0));
  clock.now = 3;
  mesh.loop();
  EXPECT_EQ(1u, radio.sent.size());
  auto ack = packet(ROUTE_TYPE_FLOOD);
  ack.header = (PAYLOAD_TYPE_ACK << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD;
  ack.payload_len = 4;
  ack.setPathHashSizeAndCount(1, 2);
  EXPECT_EQ(ACTION_RETRANSMIT_DELAYED(3, 0), mesh.receive(ack));
  EXPECT_EQ(1, mesh.local_acks);
}

constexpr uint32_t kRelayBudgetMs = 3600000 / 100 * MESHCORE_LORA_OTA_RELAY_DUTY_PERCENT;

TEST_F(OpaqueRelay, AboveConfiguredCapIsDeferredBeforeAnyTransmit) {
  mesh.airtime_factor = 0;  // Isolate the OTA cap from the normal mesh budget.
  radio.airtime = kRelayBudgetMs * 2 / 3 + 2;
  mesh.begin();
  auto* ota = mesh.obtainNewPacket();
  *ota = packet(ROUTE_TYPE_DIRECT);
  ASSERT_TRUE(mesh.sendPacket(ota, 250));
  clock.now = 2;
  mesh.loop();
  EXPECT_TRUE(radio.sent.empty());
  uint32_t schedule = 0;
  ASSERT_TRUE(manager.getOutboundScheduleByIdx(0, schedule));
  EXPECT_EQ(clock.now + 60000, schedule);
}

TEST_F(OpaqueRelay, ConfiguredRollingBudgetShelvesOtaButNotNormalTraffic) {
  mesh.airtime_factor = 0;
  const uint32_t airtime = kRelayBudgetMs * 2 / 3;
  radio.airtime = airtime;  // Timeout envelope exactly fits the configured ceiling.
  mesh.begin();
  auto* ota = mesh.obtainNewPacket();
  *ota = packet(ROUTE_TYPE_DIRECT);
  ASSERT_TRUE(mesh.sendPacket(ota, 250));
  clock.now = 2;
  mesh.loop();
  ASSERT_EQ(1u, radio.sent.size());
  radio.completed = true;
  clock.now = airtime + 2;
  mesh.loop();
  ota = mesh.obtainNewPacket();
  *ota = packet(ROUTE_TYPE_DIRECT, 1, 0, 0x11, 2);
  ASSERT_TRUE(mesh.sendPacket(ota, 250));
  clock.now = airtime * 2 + 3;  // Refill the mesh budget without expiring the OTA charge.
  mesh.loop();
  EXPECT_EQ(1u, radio.sent.size());
  uint32_t schedule = 0;
  ASSERT_TRUE(manager.getOutboundScheduleByIdx(0, schedule));
  EXPECT_EQ(clock.now + 60000, schedule);
  radio.airtime = 200;
  auto* normal = mesh.obtainNewPacket();
  normal->header = (PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_DIRECT;
  normal->payload_len = 1;
  ASSERT_TRUE(mesh.sendPacket(normal, 0));
  clock.now++;
  mesh.loop();
  EXPECT_EQ(2u, radio.sent.size());
  radio.completed = true;
  clock.now += 200;
  mesh.loop();
  radio.airtime = airtime;
  clock.now = airtime + 2 + 3600001;
  mesh.loop();
  EXPECT_EQ(3u, radio.sent.size());  // Fresh hour, same shelved opaque request.
}

TEST_F(OpaqueRelay, TimedOutOtaStillConsumesAirtimeAndCannotEvadeConfiguredBudget) {
  mesh.airtime_factor = 0;
  radio.airtime = kRelayBudgetMs * 2 / 3;
  mesh.begin();
  auto* ota = mesh.obtainNewPacket();
  *ota = packet(ROUTE_TYPE_DIRECT);
  ASSERT_TRUE(mesh.sendPacket(ota, 250));
  clock.now = 2;
  mesh.loop();
  clock.now = kRelayBudgetMs + 3;
  mesh.loop();  // No completion: timeout must still be charged.
  EXPECT_GE(mesh.getTotalAirTime(), kRelayBudgetMs);
  radio.airtime = 200;
  ota = mesh.obtainNewPacket();
  *ota = packet(ROUTE_TYPE_DIRECT, 1, 0, 0x11, 2);
  ASSERT_TRUE(mesh.sendPacket(ota, 250));
  clock.now++;
  mesh.loop();
  EXPECT_EQ(1u, radio.sent.size());
  EXPECT_EQ(1, manager.getOutboundTotal());
}

TEST(RelayProfile, DedicatedPreferencesNeverFallBackToCompanionOrLegacyArtifacts) {
  struct Fs {
    std::map<std::string, std::string> files;
    bool exists(const char* path) const { return files.count(path); }
  } fs;
  fs.files = {{"/prefs.json", "companion"}, {"/new_prefs", "legacy"}, {"/com_prefs", "repeater"},
              {"/contacts", "contacts"}, {"/channels", "channels"}, {"/_main.id", "identity"}};
  const auto before = fs.files;
  EXPECT_STREQ("/relay_prefs.json", kRepeaterPrefsFilename);
  EXPECT_STREQ("/relay_prefs.json", resolveRepeaterPrefsFilename(fs));
  fs.files["/relay_prefs.json"] = "isolated";
  EXPECT_STREQ("/relay_prefs.json", resolveRepeaterPrefsFilename(fs));
  fs.files.erase("/relay_prefs.json");
  EXPECT_EQ(before, fs.files);
}
}  // namespace
#endif
