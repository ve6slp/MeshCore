#pragma once

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include <Mesh.h>
#include <helpers/StaticPoolPacketManager.h>
#include <helpers/ota/OtaRfFrames.h>
#include <ota/protocol/OtaDescriptor.h>
#include <ota/trust/Sha256.h>

#include "../test_lora_ota_trust/Ed25519TestSigner.h"

namespace {

using namespace mesh::ota;

class RelayClock : public mesh::MillisecondClock {
 public:
  uint32_t now = 1000;
  unsigned long getMillis() override { return now; }
};

class RelayRadio : public mesh::Radio {
 public:
  explicit RelayRadio(RelayClock& clock) : clock_(clock) {}
  std::vector<uint8_t> incoming, sent;
  uint32_t estimateMs = 214, completedMs = 320;
  unsigned sends = 0;
  bool finish = true, receiving = false;

  int recvRaw(uint8_t* out, int capacity) override {
    if (incoming.empty()) return 0;
    EXPECT_LE(incoming.size(), static_cast<size_t>(capacity));
    if (incoming.size() > static_cast<size_t>(capacity)) return 0;
    const int size = static_cast<int>(incoming.size());
    std::memcpy(out, incoming.data(), incoming.size());
    incoming.clear();
    return size;
  }
  uint32_t getEstAirtimeFor(int) override { return estimateMs; }
  float packetScore(float, int) override { return 1; }
  bool startSendRaw(const uint8_t* bytes, int size) override {
    sent.assign(bytes, bytes + size);
    started_ = clock_.now;
    pending_ = true;
    ++sends;
    return true;
  }
  bool isSendComplete() override { return pending_ && finish && clock_.now - started_ >= completedMs; }
  void onSendFinished() override { pending_ = false; }
  bool isInRecvMode() const override { return !pending_; }
  bool isReceiving() override { return receiving; }

 private:
  RelayClock& clock_;
  uint32_t started_ = 0;
  bool pending_ = false;
};

class RelayRng : public mesh::RNG {
 public:
  void random(uint8_t* out, size_t size) override { std::memset(out, 0, size); }
};

class RelayRtc : public mesh::RTCClock {
 public:
  uint32_t getCurrentTime() override { return 1; }
  void setCurrentTime(uint32_t) override {}
};

class RelayTables : public mesh::MeshTables {
 public:
  bool wasSeen(const mesh::Packet*) override { return false; }
  void markSeen(const mesh::Packet*) override {}
  void clear(const mesh::Packet*) override {}
};

class ForwardingMesh : public mesh::Mesh {
 public:
  ForwardingMesh(mesh::Radio& radio, mesh::MillisecondClock& clock, mesh::RNG& rng, mesh::RTCClock& rtc,
                 mesh::PacketManager& packets, mesh::MeshTables& tables)
      : Mesh(radio, clock, rng, rtc, packets, tables) {}

 protected:
  bool allowPacketForward(const mesh::Packet*) override { return true; }
  uint32_t getRetransmitDelay(const mesh::Packet*) override { return 0; }
};

struct RelayNode {
  RelayRadio radio;
  RelayRng rng;
  RelayRtc rtc;
  RelayTables tables;
  StaticPoolPacketManager packets{16};
  ForwardingMesh mesh;
  explicit RelayNode(RelayClock& clock, uint8_t hash_base = 0x11)
      : radio(clock), mesh(radio, clock, rng, rtc, packets, tables) {
    const uint8_t hash[] = {hash_base, uint8_t(hash_base + 1), uint8_t(hash_base + 2)};
    std::memcpy(mesh.self_id.pub_key, hash, sizeof(hash));
    mesh.begin();
  }
};

enum class RelayFrame { Authorization, Data, CensusPoll, CensusReport, RepairData, Commit, Abort, Opaque };

std::vector<uint8_t> relayFrame(RelayFrame kind, uint32_t generation = 1) {
  const uint8_t seed[32] = {0xE7}, target[32] = {0x22, 0x23, 0x24};
  ::ota::test::Ed25519TestSigner owner(seed);
  uint8_t image[84] = {0xB7}, canonical[59], hash[32], signature[64];
  meshcore::ota::protocol::OtaDescriptor descriptor;
  descriptor.formatId = descriptor.algorithmId = descriptor.keyId = 1;
  descriptor.boardFamily = 0x584E; descriptor.boardVariant = 0x3430; descriptor.role = 1;
  descriptor.appAddress = 0x27000; descriptor.exactSizeBytes = sizeof(image);
  descriptor.securityCounter = 5; descriptor.minBootloaderCapabilities = 1;
  ::ota::trust::Sha256::hash(image, sizeof(image), descriptor.sha256);
  size_t canonical_size = 0;
  EXPECT_EQ(meshcore::ota::protocol::OtaDescriptorCodecResult::Ok,
            meshcore::ota::protocol::encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), canonical_size));
  computeOtaManifestHash(canonical, hash);
  owner.sign(canonical, sizeof(canonical), signature);
  uint8_t out[kOtaOwnerSignedBlockMaxBytes] = {};
  size_t size = 0;
  switch (kind) {
    case RelayFrame::Authorization:
      size = encodeOtaTargetAuthorization(target, owner.publicKey(), canonical, signature, out, sizeof(out));
      break;
    case RelayFrame::Data:
    case RelayFrame::RepairData: {
      uint8_t message[kOtaBlockSignedMessageMaxBytes];
      const auto len = buildOtaBlockSignedMessage(hash, kOtaOwnerSignedBlockKind, 0, image, sizeof(image), message);
      owner.sign(message, len, signature);
      size = encodeOtaOwnerSignedBlock(owner.publicKey(), 0, image, sizeof(image), signature, out, sizeof(out));
      break;
    }
    case RelayFrame::CensusPoll:
      size = encodeOtaCensusPoll(target, hash, 0, out, sizeof(out));
      break;
    case RelayFrame::CensusReport: {
      OtaCensusReport report;
      std::memcpy(report.reporter, target, 32); std::memcpy(report.manifestHash, hash, 32);
      report.total = 1; report.generation = generation; report.counter = 5;
      report.lifecyclePhase = usb::UsbOtaPhase::Receiving;
      size = encodeOtaCensusReport(report, out, sizeof(out));
      break;
    }
    case RelayFrame::Commit: {
      uint8_t message[usb::kCommitSignedBytes];
      const auto len = usb::buildCommitSignedMessage(target, hash, 5, message);
      owner.sign(message, len, signature);
      size = encodeOtaCommitFrame(target, hash, 5, signature, out, sizeof(out));
      break;
    }
    case RelayFrame::Abort: {
      uint8_t message[usb::kAbortSignedBytes];
      const auto len = usb::buildAbortSignedMessage(target, descriptor.sha256, generation, message);
      owner.sign(message, len, signature);
      size = encodeOtaAbortFrame(owner.publicKey(), target, descriptor.sha256, generation, signature, out, sizeof(out));
      break;
    }
    case RelayFrame::Opaque:
      out[0] = 0xE1; out[1] = 0x4F; out[2] = 0x54;
      size = 3;
      break;
  }
  EXPECT_GT(size, 0u);
  return std::vector<uint8_t>(out, out + size);
}

void queueRouted(RelayNode& node, const std::vector<uint8_t>& frame, uint8_t type = PAYLOAD_TYPE_LORA_OTA) {
  auto* packet = type == PAYLOAD_TYPE_LORA_OTA ? node.mesh.createOtaData(frame.data(), frame.size()) :
                                               node.mesh.obtainNewPacket();
  ASSERT_NE(nullptr, packet);
  if (type != PAYLOAD_TYPE_LORA_OTA) {
    packet->header = type << PH_TYPE_SHIFT;
    packet->payload_len = frame.size();
    std::memcpy(packet->payload, frame.data(), frame.size());
  }
  const uint8_t path[] = {0x11, 0x12, 0x13, 0x22, 0x23, 0x24};
  node.mesh.sendDirect(packet, path, (2u << 6) | 2u);
}

void complete(RelayNode& node, RelayClock& clock) {
  ASSERT_TRUE(node.mesh.isSendInProgress());
  const uint32_t started = clock.now;
  const auto deadline = node.mesh.getCurrentSendDeadlineMs();
  const auto completed_before = node.mesh.getTotalAirTime();
  const auto used_before = node.mesh.getOtaStatus(clock.now).dutyUsedMs;
  const auto timeouts_before = node.mesh.getTxTimeoutCount();
  EXPECT_EQ(node.radio.estimateMs * 3u / 2u, deadline - started);
  for (uint32_t elapsed = 1; elapsed <= node.radio.completedMs; ++elapsed) {
    ++clock.now;
    node.mesh.Dispatcher::loop();
    if (elapsed < node.radio.completedMs) {
      ASSERT_TRUE(node.mesh.isSendInProgress())
          << "terminated at +" << elapsed << "ms; deadline=+" << deadline - started
          << "ms; timeouts=" << node.mesh.getTxTimeoutCount();
      EXPECT_EQ(completed_before, node.mesh.getTotalAirTime());
      EXPECT_EQ(used_before, node.mesh.getOtaStatus(clock.now).dutyUsedMs);
    }
    EXPECT_EQ(timeouts_before, node.mesh.getTxTimeoutCount());
  }
  ASSERT_FALSE(node.mesh.isSendInProgress());
  EXPECT_LT(clock.now, deadline);
  EXPECT_EQ(completed_before + node.radio.completedMs, node.mesh.getTotalAirTime());
}

TEST(OtaRelayAirtime, ActualMeshForwardingChargesEveryModernFrameAtBothTransmittersWithoutLocalAdmission) {
  for (const unsigned route : {0u, 1u, 2u}) {
    for (auto kind : {RelayFrame::Authorization, RelayFrame::Data, RelayFrame::CensusPoll, RelayFrame::CensusReport,
                      RelayFrame::RepairData, RelayFrame::Commit, RelayFrame::Abort, RelayFrame::Opaque}) {
      SCOPED_TRACE(::testing::Message() << route << '/' << static_cast<unsigned>(kind));
      RelayClock clock;
      RelayNode sender(clock), relay(clock), secondRelay(clock, 0x22);
      const auto frame = relayFrame(kind);
      uint16_t transport_codes[] = {0x1234, 0x5678};
      if (route != 0) {
        auto* packet = sender.mesh.createOtaData(frame.data(), frame.size());
        ASSERT_NE(nullptr, packet);
        if (route == 2) {
          ASSERT_TRUE(sender.mesh.sendFlood(packet, transport_codes, 0, 3));
        } else {
          ASSERT_TRUE(sender.mesh.sendFlood(packet, static_cast<uint32_t>(0), 3));
        }
      } else {
        queueRouted(sender, frame);
      }
      ++clock.now; sender.mesh.Dispatcher::loop();
      ASSERT_EQ(1u, sender.radio.sends);
      EXPECT_EQ(0u, sender.mesh.getOtaStatus(clock.now).dutyUsedMs);
      complete(sender, clock);
      ASSERT_FALSE(HasFatalFailure());
      EXPECT_EQ(320u, sender.mesh.getOtaStatus(clock.now).dutyUsedMs);
      relay.radio.incoming = sender.radio.sent;
      relay.mesh.Dispatcher::loop();
      ASSERT_EQ(1u, relay.radio.sends);
      EXPECT_EQ(0u, relay.mesh.getOtaStatus(clock.now).dutyUsedMs);
      complete(relay, clock);
      ASSERT_FALSE(HasFatalFailure());
      const auto status = relay.mesh.getOtaStatus(clock.now);
      EXPECT_EQ(3600000u, status.dutyWindowMs); EXPECT_EQ(72000u, status.dutyBudgetMs);
      EXPECT_EQ(320u, status.dutyUsedMs); EXPECT_EQ(320u, relay.mesh.getTotalAirTime());
      EXPECT_EQ(0u, relay.mesh.getTxTimeoutCount()); EXPECT_EQ(0u, relay.mesh.getOtaAccountingFailureCount());
      EXPECT_FALSE(relay.mesh.getOtaIntegration().leanReceiver().status().valid);
      mesh::Packet forwarded;
      ASSERT_TRUE(forwarded.readFrom(relay.radio.sent.data(), relay.radio.sent.size()));
      EXPECT_EQ(PAYLOAD_TYPE_LORA_OTA, forwarded.getPayloadType());
      EXPECT_EQ(1u, forwarded.getPathHashCount());
      EXPECT_EQ(3u, forwarded.getPathHashSize());
      EXPECT_EQ(route == 0 ? ROUTE_TYPE_DIRECT : route == 1 ? ROUTE_TYPE_FLOOD : ROUTE_TYPE_TRANSPORT_FLOOD,
                forwarded.getRouteType());
      const uint8_t expected_path[] = {uint8_t(route == 0 ? 0x22 : 0x11),
                                      uint8_t(route == 0 ? 0x23 : 0x12),
                                      uint8_t(route == 0 ? 0x24 : 0x13)};
      EXPECT_EQ(0, std::memcmp(expected_path, forwarded.path, sizeof(expected_path)));
      if (route == 2) {
        EXPECT_EQ(transport_codes[0], forwarded.transport_codes[0]);
        EXPECT_EQ(transport_codes[1], forwarded.transport_codes[1]);
      }
      ASSERT_EQ(frame.size(), forwarded.payload_len);
      EXPECT_EQ(0, std::memcmp(frame.data(), forwarded.payload, frame.size()));
      char budget[160];
      ASSERT_TRUE(relay.mesh.getOtaIntegration().formatBudgetMeasurement(budget, sizeof(budget), clock.now,
          relay.mesh.getTotalAirTime(), relay.mesh.getTxTimeoutCount(), relay.mesh.getOtaAccountingFailureCount()));
      EXPECT_NE(nullptr, std::strstr(budget, "w=0036EE80 b=00011940 u=00000140 tx=00000140 to=00000000 af=00000000"));
      if (route == 0) {
        secondRelay.radio.incoming = relay.radio.sent;
        secondRelay.mesh.Dispatcher::loop();
        ASSERT_EQ(1u, secondRelay.radio.sends);
        EXPECT_EQ(0u, secondRelay.mesh.getOtaStatus(clock.now).dutyUsedMs);
        complete(secondRelay, clock); ASSERT_FALSE(HasFatalFailure());
        EXPECT_EQ(320u, secondRelay.mesh.getOtaStatus(clock.now).dutyUsedMs);
        EXPECT_EQ(0u, secondRelay.mesh.getOtaAccountingFailureCount());
        EXPECT_EQ(0u, secondRelay.mesh.getTxTimeoutCount());
        ASSERT_TRUE(forwarded.readFrom(secondRelay.radio.sent.data(), secondRelay.radio.sent.size()));
        EXPECT_EQ(0u, forwarded.getPathHashCount());
        ASSERT_EQ(frame.size(), forwarded.payload_len);
        EXPECT_EQ(0, std::memcmp(frame.data(), forwarded.payload, frame.size()));
        EXPECT_FALSE(secondRelay.mesh.getOtaIntegration().leanReceiver().status().valid);
      }
    }
  }
}

TEST(OtaRelayAirtime, RelayIndependentlyStopsAtActualTwoPercentButStillForwardsOrdinaryAckAndOpaqueGroupData) {
  RelayClock clock;
  RelayNode sender(clock), relay(clock);
  for (uint32_t i = 0; i < 224; ++i) {
    // Distinct signed generations give distinct packet hashes, not duplicate retransmissions.
    queueRouted(sender, relayFrame(RelayFrame::Abort, i + 1));
    ++clock.now; sender.mesh.Dispatcher::loop();
    complete(sender, clock); ASSERT_FALSE(HasFatalFailure());
    relay.radio.incoming = sender.radio.sent;
    relay.mesh.Dispatcher::loop();
    complete(relay, clock); ASSERT_FALSE(HasFatalFailure());
    EXPECT_EQ((i + 1) * 320u, sender.mesh.getOtaStatus(clock.now).dutyUsedMs);
    EXPECT_EQ((i + 1) * 320u, relay.mesh.getOtaStatus(clock.now).dutyUsedMs);
    EXPECT_LE(sender.mesh.getOtaStatus(clock.now).dutyUsedMs, 72000u);
    EXPECT_LE(relay.mesh.getOtaStatus(clock.now).dutyUsedMs, 72000u);
  }
  ASSERT_EQ(71680u, sender.mesh.getOtaStatus(clock.now).dutyUsedMs);
  ASSERT_EQ(71680u, relay.mesh.getOtaStatus(clock.now).dutyUsedMs);
  EXPECT_EQ(71680u, sender.mesh.getTotalAirTime());
  EXPECT_EQ(71680u, relay.mesh.getTotalAirTime());
  // Admission reserves 214*3/2+20 = 341 ms; only 320 ms remain.
  queueRouted(sender, relayFrame(RelayFrame::Abort, 225));
  ++clock.now; sender.mesh.Dispatcher::loop();
  EXPECT_FALSE(sender.mesh.isSendInProgress()); EXPECT_EQ(224u, sender.radio.sends);
  EXPECT_EQ(71680u, sender.mesh.getOtaStatus(clock.now).dutyUsedMs);
  EXPECT_EQ(1, sender.packets.getOutboundTotal());

  RelayNode freshSender(clock);
  queueRouted(freshSender, relayFrame(RelayFrame::Abort, 226));
  ++clock.now; freshSender.mesh.Dispatcher::loop();
  complete(freshSender, clock); ASSERT_FALSE(HasFatalFailure());
  relay.radio.incoming = freshSender.radio.sent;
  relay.mesh.Dispatcher::loop();
  EXPECT_FALSE(relay.mesh.isSendInProgress()); EXPECT_EQ(224u, relay.radio.sends);
  EXPECT_EQ(71680u, relay.mesh.getOtaStatus(clock.now).dutyUsedMs);
  ASSERT_EQ(1, relay.packets.getOutboundTotal());
  EXPECT_EQ(mesh::ota::kOtaForwardPriority, mesh::ota::directPriorityForPayload(
      relay.packets.getOutboundByIdx(0)->getPayloadType()));

  for (const uint8_t type : {uint8_t(PAYLOAD_TYPE_ACK), uint8_t(PAYLOAD_TYPE_GRP_DATA)}) {
    const std::vector<uint8_t> opaque = {0x4F, 0x54, 0x01, 0x09, 0x88, 0x99};
    queueRouted(freshSender, opaque, type);
    ++clock.now; freshSender.mesh.Dispatcher::loop();
    complete(freshSender, clock); ASSERT_FALSE(HasFatalFailure());
    relay.radio.incoming = freshSender.radio.sent;
    relay.mesh.Dispatcher::loop();
    ASSERT_TRUE(relay.mesh.isSendInProgress());
    complete(relay, clock); ASSERT_FALSE(HasFatalFailure());
    mesh::Packet forwarded;
    ASSERT_TRUE(forwarded.readFrom(relay.radio.sent.data(), relay.radio.sent.size()));
    EXPECT_EQ(type, forwarded.getPayloadType());
    EXPECT_EQ(71680u, relay.mesh.getOtaStatus(clock.now).dutyUsedMs);
    EXPECT_EQ(320u, freshSender.mesh.getOtaStatus(clock.now).dutyUsedMs);
    EXPECT_EQ(1, relay.packets.getOutboundTotal());
  }
  EXPECT_EQ(72320u, relay.mesh.getTotalAirTime());
  EXPECT_EQ(0u, relay.mesh.getTxTimeoutCount()); EXPECT_EQ(0u, relay.mesh.getOtaAccountingFailureCount());

  clock.now += 3600001u;
  EXPECT_EQ(0u, relay.mesh.getOtaStatus(clock.now).dutyUsedMs);
  relay.mesh.Dispatcher::loop();
  ASSERT_TRUE(relay.mesh.isSendInProgress());
  complete(relay, clock); ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(320u, relay.mesh.getOtaStatus(clock.now).dutyUsedMs);
  EXPECT_EQ(0, relay.packets.getOutboundTotal());
}

TEST(OtaRelayAirtime, ReadyOrdinaryForwardingPreemptsReadyOtaWithAvailableQuota) {
  RelayClock clock;
  RelayNode sender(clock), relay(clock);
  queueRouted(sender, relayFrame(RelayFrame::Data));
  ++clock.now; sender.mesh.Dispatcher::loop();
  complete(sender, clock); ASSERT_FALSE(HasFatalFailure());
  relay.radio.receiving = true;
  relay.radio.incoming = sender.radio.sent;
  relay.mesh.Dispatcher::loop();
  ASSERT_EQ(1, relay.packets.getOutboundCount(clock.now));
  ASSERT_EQ(0u, relay.radio.sends);

  const std::vector<uint8_t> ack = {0x01, 0x02, 0x03, 0x04};
  queueRouted(sender, ack, PAYLOAD_TYPE_ACK);
  ++clock.now; sender.mesh.Dispatcher::loop();
  complete(sender, clock); ASSERT_FALSE(HasFatalFailure());
  relay.radio.incoming = sender.radio.sent;
  relay.mesh.Dispatcher::loop();
  ASSERT_EQ(2, relay.packets.getOutboundCount(clock.now));
  ASSERT_EQ(0u, relay.radio.sends);
  relay.radio.receiving = false;
  clock.now += 201;
  relay.mesh.Dispatcher::loop();
  ASSERT_TRUE(relay.mesh.isSendInProgress());
  mesh::Packet forwarded;
  ASSERT_TRUE(forwarded.readFrom(relay.radio.sent.data(), relay.radio.sent.size()));
  EXPECT_EQ(PAYLOAD_TYPE_ACK, forwarded.getPayloadType());
  complete(relay, clock); ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(0u, relay.mesh.getOtaStatus(clock.now).dutyUsedMs);
  EXPECT_EQ(320u, relay.mesh.getTotalAirTime());
  ASSERT_EQ(1, relay.packets.getOutboundTotal());
  ++clock.now; relay.mesh.Dispatcher::loop();
  ASSERT_TRUE(relay.mesh.isSendInProgress());
  complete(relay, clock); ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(320u, relay.mesh.getOtaStatus(clock.now).dutyUsedMs);
  EXPECT_EQ(640u, relay.mesh.getTotalAirTime());
  EXPECT_EQ(0, relay.packets.getOutboundTotal());
}

TEST(OtaRelayAirtime, ForwardedTimeoutDoesNotPretendCompletedAccountingAndRemainsObservable) {
  RelayClock clock;
  RelayNode sender(clock), relay(clock);
  queueRouted(sender, relayFrame(RelayFrame::Data));
  ++clock.now; sender.mesh.Dispatcher::loop();
  complete(sender, clock); ASSERT_FALSE(HasFatalFailure());
  relay.radio.finish = false;
  relay.radio.incoming = sender.radio.sent;
  relay.mesh.Dispatcher::loop();
  ASSERT_TRUE(relay.mesh.isSendInProgress());
  const auto started = clock.now;
  EXPECT_EQ(321u, relay.mesh.getCurrentSendDeadlineMs() - started);
  for (uint32_t elapsed = 1; elapsed <= 321; ++elapsed) {
    ++clock.now;
    relay.mesh.Dispatcher::loop();
    ASSERT_TRUE(relay.mesh.isSendInProgress()) << "elapsed=" << elapsed;
    EXPECT_EQ(0u, relay.mesh.getTxTimeoutCount());
  }
  ++clock.now;
  relay.mesh.Dispatcher::loop();
  EXPECT_FALSE(relay.mesh.isSendInProgress());
  EXPECT_EQ(0u, relay.mesh.getOtaStatus(clock.now).dutyUsedMs);
  EXPECT_EQ(0u, relay.mesh.getTotalAirTime());
  EXPECT_EQ(1u, relay.mesh.getTxTimeoutCount());
  relay.mesh.resetStats();
  EXPECT_EQ(1u, relay.mesh.getTxTimeoutCount());
}

}  // namespace
