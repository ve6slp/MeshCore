#include <gtest/gtest.h>

#include <array>
#include <cstring>

#include <Dispatcher.h>
#include <helpers/StaticPoolPacketManager.h>
#include <helpers/ota/OtaMeasurementDiagnostics.h>

namespace {

using mesh::ota::OtaAppliedRadioProfile;
using mesh::ota::OtaRadioMeasurement;
using mesh::ota::OtaFirmwareIntegration;
using meshcore::ota::protocol::OtaAirtimeCategory;

constexpr OtaAppliedRadioProfile normalProfile{907525, 250000, 7, 5};
constexpr OtaAppliedRadioProfile directProfile{908525, 250000, 5, 5};

class MeasurementClock : public mesh::MillisecondClock {
 public:
  uint32_t now = 100;
  unsigned long getMillis() override { return now; }
};

class MeasurementRadio : public mesh::Radio {
 public:
  bool complete = false, transmitting = false;
  int recvRaw(uint8_t*, int) override { return 0; }
  uint32_t getEstAirtimeFor(int) override { return 1000; }
  float packetScore(float, int) override { return 0; }
  bool startSendRaw(const uint8_t*, int) override { transmitting = true; return true; }
  bool isSendComplete() override { return complete; }
  void onSendFinished() override { transmitting = complete = false; }
  bool isInRecvMode() const override { return !transmitting; }
};

class MeasurementDispatcher : public mesh::Dispatcher {
 public:
  MeasurementDispatcher(MeasurementRadio& radio, MeasurementClock& clock, mesh::PacketManager& packets)
      : Dispatcher(radio, clock, packets) {}

  bool queue(bool ota) {
    auto* packet = obtainNewPacket(ota);
    if (packet == nullptr) return false;
    packet->header = (ota ? PAYLOAD_TYPE_LORA_OTA : PAYLOAD_TYPE_ACK) << PH_TYPE_SHIFT | ROUTE_TYPE_DIRECT;
    packet->path_len = 0;
    packet->payload_len = 1;
    packet->payload[0] = 0x55;
    return sendPacket(packet, ota ? mesh::ota::kOtaForwardPriority : 0);
  }

 protected:
  mesh::DispatcherAction onRecvPacket(mesh::Packet*) override { return ACTION_RELEASE; }
};

class MeasurementFlash : public ::ota::platform::FlashDevice {
 public:
  MeasurementFlash() { bytes.fill(0xFF); }
  uint32_t totalSizeBytes() const override { return bytes.size(); }
  uint32_t eraseUnitBytes() const override { return 4096; }
  uint32_t programUnitBytes() const override { return 1; }
  ::ota::platform::FlashStatus read(uint32_t offset, uint8_t* out, uint32_t length) const override {
    if (offset > bytes.size() || length > bytes.size() - offset)
      return ::ota::platform::FlashStatus::OutOfRange;
    std::memcpy(out, bytes.data() + offset, length);
    return ::ota::platform::FlashStatus::Ok;
  }
  ::ota::platform::FlashStatus program(uint32_t offset, const uint8_t* data, uint32_t length) override {
    if (offset > bytes.size() || length > bytes.size() - offset)
      return ::ota::platform::FlashStatus::OutOfRange;
    for (uint32_t i = 0; i < length; ++i)
      if ((bytes[offset + i] & data[i]) != data[i])
        return ::ota::platform::FlashStatus::PartialProgramViolation;
    for (uint32_t i = 0; i < length; ++i) bytes[offset + i] &= data[i];
    return ::ota::platform::FlashStatus::Ok;
  }
  ::ota::platform::FlashStatus eraseSector(uint32_t offset) override {
    if (offset % 4096 || offset > bytes.size() - 4096)
      return ::ota::platform::FlashStatus::OutOfRange;
    std::memset(bytes.data() + offset, 0xFF, 4096);
    return ::ota::platform::FlashStatus::Ok;
  }

 private:
  std::array<uint8_t, 8192> bytes;
};

// Matches the existing native identity mock; these tests exercise radio/accounting, not cryptography.
class MeasurementSignatureVerifier : public ::ota::trust::SignatureVerifier {
 public:
  bool verify(const uint8_t* signature, size_t signatureLen, const uint8_t*, size_t messageLen,
              const uint8_t* publicKey, size_t keyLen) const override {
    if (signatureLen != 64 || !messageLen || keyLen != 32 || publicKey[0] != 0x22) return false;
    for (size_t i = 0; i < signatureLen; ++i) if (signature[i] != 0x5A) return false;
    return true;
  }
};

class OtaMeasurementDirect : public testing::Test {
 protected:
  MeasurementClock clock;
  MeasurementRadio radio;
  StaticPoolPacketManager packets{16};
  MeasurementDispatcher dispatcher{radio, clock, packets};
  MeasurementFlash flash;
  ::ota::platform::FlashRegion region{flash, 0, 8192};
  ::ota::storage::OtaCandidateStore store{region};
  MeasurementSignatureVerifier verifier;
  OtaFirmwareIntegration integration;
  uint8_t owner[32] = {0x11}, target[32] = {0x22};
  bool applySucceeds = true;

  static void sign(void*, const uint8_t*, size_t, uint8_t signature[64]) {
    std::memset(signature, 0x5A, 64);
  }
  static bool change(void* context, uint32_t frequency, bool restore) {
    auto& fixture = *static_cast<OtaMeasurementDirect*>(context);
    auto profile = restore ? normalProfile : directProfile;
    profile.frequencyKhz = frequency;
    fixture.integration.observeRadioApply(fixture.applySucceeds, profile, !restore, fixture.clock.now);
    return fixture.applySucceeds;
  }
  static bool profileChange(void* context, uint32_t frequency, mesh::ota::OtaDirectProfile direct, bool restore) {
    auto& fixture = *static_cast<OtaMeasurementDirect*>(context);
    auto profile = restore ? normalProfile : directProfile;
    profile.frequencyKhz = frequency;
    if (!restore) profile.bandwidthHz = mesh::ota::otaDirectBandwidthHz(direct);
    fixture.integration.observeRadioApply(fixture.applySucceeds, profile, !restore, fixture.clock.now);
    return fixture.applySucceeds;
  }

  void SetUp() override {
    ::ota::storage::OtaCandidateStore::Snapshot snapshot;
    snapshot.valid = snapshot.localCache = true;
    snapshot.phase = ::ota::storage::OtaCandidateStore::Phase::Ready;
    snapshot.totalBlocks = 1;
    snapshot.exactSizeBytes = 164;
    snapshot.sessionId = snapshot.attemptId = 1;
    std::memcpy(snapshot.ownerPublicKey, owner, 32);
    meshcore::ota::protocol::OtaDescriptor descriptor;
    descriptor.exactSizeBytes = 164;
    descriptor.securityCounter = descriptor.formatId = descriptor.algorithmId = descriptor.keyId = 1;
    size_t canonicalLength = 0;
    ASSERT_EQ(meshcore::ota::protocol::OtaDescriptorCodecResult::Ok,
        meshcore::ota::protocol::encodeOtaDescriptorCanonical(descriptor, snapshot.canonical, 59, canonicalLength));
    ASSERT_TRUE(store.reset(snapshot));
    integration.attachCandidateStore(&store);
    ASSERT_TRUE(integration.leanReceiver().status().valid);
    integration.setLeanTargetPublicKey(owner);
    integration.attachLeanSignatureVerifier(&verifier);
    integration.attachRfIdentity(this, sign, change, normalProfile.frequencyKhz);
    integration.observeRadioApply(true, normalProfile, false, clock.now);
    dispatcher.attachOtaIntegration(&integration);
    dispatcher.begin();
  }

  void enterDirect(uint32_t token) {
    uint8_t frame[mesh::ota::kOtaDirectFrameBytes];
    ASSERT_EQ(sizeof(frame), integration.buildDirectRequest(target, directProfile.frequencyKhz, 60000,
                                                           token, frame, sizeof(frame)));
    frame[0] = mesh::ota::kOtaDirectAckKind;
    ASSERT_TRUE(integration.handleReceivedFrame(frame, sizeof(frame), clock.now));
    ASSERT_TRUE(integration.directPending());
    clock.now += 5000;
    integration.tickDirect(clock.now);
    ASSERT_TRUE(integration.directActive());
  }

  void completeTx(bool ota, uint32_t duration) {
    ASSERT_TRUE(dispatcher.queue(ota));
    ++clock.now;
    dispatcher.loop();
    ASSERT_TRUE(dispatcher.isSendInProgress());
    clock.now += duration;
    radio.complete = true;
    dispatcher.loop();
    ASSERT_FALSE(dispatcher.isSendInProgress());
  }
};

}  // namespace

TEST(OtaMeasurementRadio, ReportsOnlySuccessfulAppliedTupleAndInvalidatesPartialFailure) {
  OtaRadioMeasurement measurement;
  char reply[160];
  ASSERT_TRUE(measurement.format(reply, sizeof(reply), false, 0, true, 0, 100));
  EXPECT_NE(nullptr, std::strstr(reply, "v=0"));
  EXPECT_NE(nullptr, std::strstr(reply, "h=0"));
  measurement.observeApply(true, normalProfile, false, 100);
  measurement.observeApply(false, directProfile, true, 200);
  ASSERT_TRUE(measurement.format(reply, sizeof(reply), false, 0, true, 7, 201));
  EXPECT_STREQ("src=driver-applied f=907525 b=250000 s=7 c=5 v=0 a=0 e=00000000 d=00000000"
      " r=00000000 td=00000000 tr=00000000 h=0 x=00000007 af=00000001 n=000000C9", reply);
  measurement.observeApply(true, directProfile, true, 300);
  ASSERT_TRUE(measurement.format(reply, sizeof(reply), true, 60300, false, 8, 301));
  EXPECT_NE(nullptr, std::strstr(reply, "f=908525 b=250000 s=5 c=5 v=1 a=1"));
  EXPECT_NE(nullptr, std::strstr(reply, "d=00000001"));
  EXPECT_NE(nullptr, std::strstr(reply, "h=0 x=00000008 af=00000001"));
}

TEST(OtaMeasurementRadio, BoundedPrefixCapacityAndWrappedTransitionTimes) {
  OtaRadioMeasurement measurement;
  char reply[157];
  measurement.observeApply(true, {2500000, 500000, 12, 8}, true, UINT32_MAX);
  measurement.observeApply(true, normalProfile, false, 0);
  measurement.observeApply(true, {2500000, 500000, 12, 8}, true, 1);
  ASSERT_TRUE(measurement.format(reply, sizeof(reply), true, UINT32_MAX, true, UINT32_MAX, UINT32_MAX));
  EXPECT_NE(nullptr, std::strstr(reply, "d=00000002 r=00000001 td=00000001 tr=00000000"));
  EXPECT_NE(nullptr, std::strstr(reply, "x=FFFFFFFF af=00000000 n=FFFFFFFF"));
  char small[12];
  EXPECT_FALSE(measurement.format(small, sizeof(small), true, 1, true, 0, 1));
  EXPECT_FALSE(measurement.format(nullptr, 0, true, 1, true, 0, 1));
}

TEST(OtaMeasurementBudget, ExactMeasuredTwoPercentThresholdAndWindow) {
  OtaFirmwareIntegration integration;
  char reply[160];
  ASSERT_TRUE(integration.recordTransmit(100, OtaAirtimeCategory::Control, 71000));
  ASSERT_TRUE(integration.recordTransmit(101, OtaAirtimeCategory::Repair, 1000));
  ASSERT_TRUE(integration.formatBudgetMeasurement(reply, sizeof(reply), 101, 73000, 0, 0));
  EXPECT_STREQ("n=00000065 w=0036EE80 b=00011940 u=00011940 tx=00011D28 to=00000000 af=00000000", reply);
  EXPECT_FALSE(integration.canTransmit(101, OtaAirtimeCategory::Control, 0, true, false));
  EXPECT_FALSE(integration.canTransmit(101, OtaAirtimeCategory::Control, 1, true, false));
  EXPECT_FALSE(integration.canTransmit(101, OtaAirtimeCategory::Control, 0, true, true));
  EXPECT_EQ(72000u, integration.status(3600100).dutyUsedMs);
  EXPECT_EQ(1000u, integration.status(3600101).dutyUsedMs);
  EXPECT_EQ(0u, integration.status(3600102).dutyUsedMs);
  EXPECT_FALSE(integration.formatBudgetMeasurement(reply, 12, 101, 73000, 0, 0));
}

TEST_F(OtaMeasurementDirect, TwoRealLeaseIntervalsRestoreAndResumeExcludingDirectTx) {
  completeTx(true, 101);
  EXPECT_EQ(101u, integration.status(clock.now).dutyUsedMs);
  enterDirect(1);
  completeTx(true, 107);
  EXPECT_EQ(101u, integration.status(clock.now).dutyUsedMs);
  clock.now += 60000;
  integration.tickDirect(clock.now);
  ASSERT_FALSE(integration.directActive());
  completeTx(false, 103);
  completeTx(true, 109);
  EXPECT_EQ(210u, integration.status(clock.now).dutyUsedMs);
  enterDirect(2);
  completeTx(true, 113);
  EXPECT_EQ(210u, integration.status(clock.now).dutyUsedMs);
  char reply[160];
  ASSERT_TRUE(integration.formatRadioMeasurement(reply, sizeof(reply), true, 0, clock.now));
  EXPECT_NE(nullptr, std::strstr(reply, "f=908525 b=250000 s=5 c=5 v=1 a=1"));
  EXPECT_NE(nullptr, std::strstr(reply, "d=00000002 r=00000001"));
  integration.stopDirect();
  ASSERT_FALSE(integration.directActive());
  EXPECT_EQ(533u, dispatcher.getTotalAirTime());
  ASSERT_TRUE(integration.formatBudgetMeasurement(reply, sizeof(reply), clock.now,
      dispatcher.getTotalAirTime(), dispatcher.getTxTimeoutCount(), dispatcher.getOtaAccountingFailureCount()));
  EXPECT_NE(nullptr, std::strstr(reply, "u=000000D2 tx=00000215 to=00000000 af=00000000"));
}

TEST_F(OtaMeasurementDirect, Negotiated500ReportsDriverApplied500AndRestoresExactNormalTuple) {
  integration.attachRfProfileIdentity(this, sign, profileChange, normalProfile.frequencyKhz);
  uint8_t frame[mesh::ota::kOtaDirectFrameBytes];
  ASSERT_EQ(sizeof(frame), integration.buildDirectRequest(target, 908525, 60000, 25,
      frame, sizeof(frame), mesh::ota::OtaDirectProfile::Bw500));
  frame[0] = mesh::ota::kOtaDirectProfileAckKind;
  ASSERT_TRUE(integration.handleReceivedFrame(frame, sizeof(frame), clock.now));
  clock.now += 5000; integration.tickDirect(clock.now);
  ASSERT_TRUE(integration.directActive());
  char reply[160];
  ASSERT_TRUE(integration.formatRadioMeasurement(reply, sizeof(reply), true, 0, clock.now));
  EXPECT_NE(nullptr, std::strstr(reply, "f=908525 b=500000 s=5 c=5 v=1 a=1"));
  EXPECT_NE(nullptr, std::strstr(reply, "d=00000001 r=00000000"));
  clock.now += 60000; integration.tickDirect(clock.now);
  ASSERT_FALSE(integration.directActive());
  ASSERT_TRUE(integration.formatRadioMeasurement(reply, sizeof(reply), true, 0, clock.now));
  EXPECT_NE(nullptr, std::strstr(reply, "f=907525 b=250000 s=7 c=5 v=1 a=0"));
  EXPECT_NE(nullptr, std::strstr(reply, "d=00000001 r=00000001"));
}

TEST_F(OtaMeasurementDirect, FailedRestoreDoesNotPublishHealthyOrNormalAppliedTuple) {
  enterDirect(1);
  applySucceeds = false;
  integration.stopDirect();
  ASSERT_TRUE(integration.directActive());
  char reply[160];
  ASSERT_TRUE(integration.formatRadioMeasurement(reply, sizeof(reply), true, 0, clock.now));
  EXPECT_NE(nullptr, std::strstr(reply, "f=908525 b=250000 s=5 c=5 v=0 a=1"));
  EXPECT_NE(nullptr, std::strstr(reply, "r=00000000"));
  EXPECT_NE(nullptr, std::strstr(reply, "h=0 x=00000000 af=00000001"));
  applySucceeds = true;
  integration.stopDirect();
  ASSERT_FALSE(integration.directActive());
  ASSERT_TRUE(integration.formatRadioMeasurement(reply, sizeof(reply), true, 0, clock.now));
  EXPECT_NE(nullptr, std::strstr(reply, "f=907525 b=250000 s=7 c=5 v=1 a=0"));
  EXPECT_NE(nullptr, std::strstr(reply, "r=00000001"));
}

TEST_F(OtaMeasurementDirect, ActualCompletedTimingNotEstimateAndTimeoutsCannotBeResetAway) {
  completeTx(true, 101);
  completeTx(false, 103);
  EXPECT_EQ(204u, dispatcher.getTotalAirTime());
  EXPECT_EQ(101u, integration.status(clock.now).dutyUsedMs);
  for (const bool ota : {true, false}) {
    ASSERT_TRUE(dispatcher.queue(ota));
    ++clock.now;
    dispatcher.loop();
    ASSERT_TRUE(dispatcher.isSendInProgress());
    clock.now += 1501;
    dispatcher.loop();
    ASSERT_FALSE(dispatcher.isSendInProgress());
  }
  EXPECT_EQ(2u, dispatcher.getTxTimeoutCount());
  EXPECT_EQ(0u, dispatcher.getOtaAccountingFailureCount());
  EXPECT_EQ(204u, dispatcher.getTotalAirTime());
  EXPECT_EQ(101u, integration.status(clock.now).dutyUsedMs);
  dispatcher.resetStats();
  EXPECT_EQ(2u, dispatcher.getTxTimeoutCount());
}

TEST_F(OtaMeasurementDirect, RealCompletionAccountingFailureIsObservableAndCannotBeResetAway) {
  ASSERT_TRUE(dispatcher.queue(true));
  ++clock.now;
  dispatcher.loop();
  ASSERT_TRUE(dispatcher.isSendInProgress());
  // Inject saturated accounting storage after admission, before actual completion.
  for (size_t i = 0; i < meshcore::ota::runtime::OtaAirtimeLimiter::kMaxEntries; ++i)
    ASSERT_TRUE(integration.recordTransmit(clock.now, OtaAirtimeCategory::Control, UINT32_MAX));
  clock.now += 101;
  radio.complete = true;
  dispatcher.loop();
  ASSERT_FALSE(dispatcher.isSendInProgress());
  EXPECT_EQ(101u, dispatcher.getTotalAirTime());
  EXPECT_EQ(0u, dispatcher.getTxTimeoutCount());
  EXPECT_EQ(1u, dispatcher.getOtaAccountingFailureCount());
  dispatcher.resetStats();
  EXPECT_EQ(1u, dispatcher.getOtaAccountingFailureCount());
}
