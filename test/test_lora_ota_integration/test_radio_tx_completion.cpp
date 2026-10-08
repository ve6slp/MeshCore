#if defined(MESHCORE_RADIO_TX_COMPLETION_NATIVE)
#include <gtest/gtest.h>

#include <deque>
#include <Dispatcher.h>
#include <helpers/radiolib/CustomSX1262Wrapper.h>

namespace {

class Board : public mesh::MainBoard {
 public:
  unsigned before = 0, after = 0;
  uint16_t getBattMilliVolts() override { return 4200; }
  const char* getManufacturerName() const override { return "native"; }
  uint8_t getStartupReason() const override { return BD_STARTUP_NORMAL; }
  void reboot() override {}
  void onBeforeTransmit() override { ++before; }
  void onAfterTransmit() override { ++after; }
};

class Clock : public mesh::MillisecondClock {
 public:
  unsigned long getMillis() override { return g_mock_millis; }
};

class Manager : public mesh::PacketManager {
 public:
  mesh::Packet packet;
  std::deque<mesh::Packet*> queue;
  unsigned released = 0;
  mesh::Packet* allocNew() override { return &packet; }
  mesh::Packet* allocOtaPacket() override { return &packet; }
  void free(mesh::Packet*) override { ++released; }
  void queueOutbound(mesh::Packet* value, uint8_t, uint32_t) override { queue.push_back(value); }
  bool tryQueueOutbound(mesh::Packet* value, uint8_t, uint32_t) override { queue.push_back(value); return true; }
  bool supportsOtaQueue() const override { return true; }
  mesh::Packet* getNextOutbound(uint32_t now) override { return getNextOutboundWithPriority(now, nullptr); }
  mesh::Packet* getNextOutboundWithPriority(uint32_t, uint8_t* priority) override {
    if (queue.empty()) return nullptr;
    if (priority != nullptr) *priority = 1;
    auto* value = queue.front();
    queue.pop_front();
    return value;
  }
  int getOutboundCount(uint32_t) const override { return queue.size(); }
  int getOutboundTotal() const override { return queue.size(); }
  int getFreeCount() const override { return 8; }
  mesh::Packet* getOutboundByIdx(int index) override { return queue.at(index); }
  bool getOutboundScheduleByIdx(int, uint32_t& out) const override { out = 0; return true; }
  mesh::Packet* removeOutboundByIdx(int index) override {
    auto* value = queue.at(index);
    queue.erase(queue.begin() + index);
    return value;
  }
  void queueInbound(mesh::Packet*, uint32_t) override {}
  mesh::Packet* getNextInbound(uint32_t) override { return nullptr; }
};

class Dispatcher : public mesh::Dispatcher {
 public:
  unsigned logged = 0;
  Dispatcher(mesh::Radio& radio, Clock& clock, Manager& manager) : mesh::Dispatcher(radio, clock, manager) {}
 protected:
  mesh::DispatcherAction onRecvPacket(mesh::Packet*) override { return ACTION_RELEASE; }
  void logTx(mesh::Packet*, int) override { ++logged; }
};

class RadioTxCompletion : public testing::Test {
 protected:
  Module module;
  CustomSX1262 sx{&module};
  Board board;
  CustomSX1262Wrapper radio{sx, board};
  Clock clock;
  Manager manager;
  Dispatcher dispatcher{radio, clock, manager};
  unsigned long budget_at_start = 0;

  void SetUp() override {
    g_mock_millis += 1000;
    dispatcher.begin();
  }
  void start(bool ota = false) {
    auto* packet = dispatcher.obtainNewPacket();
    packet->header = (ota ? PAYLOAD_TYPE_LORA_OTA : PAYLOAD_TYPE_ADVERT) << PH_TYPE_SHIFT | ROUTE_TYPE_FLOOD;
    packet->payload_len = 4;
    packet->payload[0] = 0x4F;
    packet->payload[1] = 0x54;
    packet->payload[2] = 1;
    packet->payload[3] = static_cast<uint8_t>(meshcore::ota::protocol::OtaMessageType::Chunk);
    ASSERT_TRUE(dispatcher.sendPacket(packet, 1));
    dispatcher.loop();
    ASSERT_TRUE(dispatcher.isSendInProgress());
    ASSERT_EQ(1u, module.starts);
    ASSERT_TRUE(radio.isTransmitPending());
    budget_at_start = dispatcher.getRemainingTxBudget();
    g_mock_millis += 20;
  }
  void completedExactlyOnce() {
    EXPECT_FALSE(dispatcher.isSendInProgress());
    EXPECT_TRUE(radio.isInRecvMode());
    EXPECT_EQ(1u, module.finishes);
    EXPECT_EQ(2u, module.receives);
    EXPECT_EQ(1u, board.before);
    EXPECT_EQ(1u, board.after);
    EXPECT_EQ(1u, manager.released);
    EXPECT_EQ(1u, dispatcher.logged);
    EXPECT_EQ(1u, dispatcher.getNumSentFlood());
    EXPECT_EQ(1u, radio.getPacketsSent());
    EXPECT_EQ(20u, dispatcher.getTotalAirTime());
    EXPECT_EQ(budget_at_start - 20, dispatcher.getRemainingTxBudget());
  }
  mesh::RadioDriverFaultDiagnostic diagnostic() {
    mesh::RadioDriverFaultDiagnostic value;
    EXPECT_TRUE(radio.getDriverFaultDiagnostic(value));
    return value;
  }
};

TEST_F(RadioTxCompletion, CompletionBeforeProbeRearmsReceiveWithoutScheduling) {
  start();
  mesh::Packet next{};
  next.header = PAYLOAD_TYPE_ADVERT << PH_TYPE_SHIFT | ROUTE_TYPE_FLOOD;
  next.payload_len = 1;
  ASSERT_TRUE(dispatcher.sendPacket(&next, 1));
  module.complete();
  const unsigned receives = module.receives;
  ASSERT_TRUE(dispatcher.probeRadioDriverStatus());
  completedExactlyOnce();
  EXPECT_EQ(receives + 1, module.receives);
  EXPECT_EQ(3u, module.reads);
  EXPECT_EQ(1u, module.starts);
  EXPECT_EQ(1, manager.getOutboundTotal());
  EXPECT_EQ(0u, radio.driverFaultCount());
}

class CompletionDuringRead : public RadioTxCompletion, public testing::WithParamInterface<unsigned> {};

TEST_P(CompletionDuringRead, ReconcilesOnlyOnce) {
  start();
  module.onRead = [&](unsigned read) { if (read == GetParam()) module.complete(); };
  ASSERT_TRUE(dispatcher.probeRadioDriverStatus());
  completedExactlyOnce();
  EXPECT_EQ(6u, module.reads);
  EXPECT_EQ(0u, radio.driverFaultCount());
}

INSTANTIATE_TEST_SUITE_P(EachCheckedRead, CompletionDuringRead, testing::Values(1u, 2u, 3u));

TEST_F(RadioTxCompletion, IsrAfterStatusPayloadStillUsesOwnedCompletionNotLatchedBit) {
  start();
  module.afterRead = [&](unsigned read) { if (read == 3) module.complete(); };
  ASSERT_TRUE(dispatcher.probeRadioDriverStatus());
  completedExactlyOnce();
  EXPECT_EQ(6u, module.reads);
  EXPECT_EQ(0u, radio.driverFaultCount());
}

TEST_F(RadioTxCompletion, StaleTxDoneNeverMakesPendingStandbyHealthy) {
  start();
  module.mode = 0x20;
  module.irq = kSx1262IrqTxDone;
  for (unsigned attempt = 1; attempt <= 3; ++attempt) {
    EXPECT_FALSE(dispatcher.probeRadioDriverStatus());
    EXPECT_EQ(attempt, radio.driverFaultCount());
  }
  EXPECT_TRUE(dispatcher.isSendInProgress());
  EXPECT_EQ(0u, module.finishes);
  EXPECT_EQ(1u, module.receives);
  EXPECT_EQ(0u, dispatcher.getTotalAirTime());
  EXPECT_EQ(kSx1262ModeMismatch, diagnostic().last.probeReasons);
}

TEST_F(RadioTxCompletion, CompletionWithoutDispatcherOwnershipIsNotReconciled) {
  uint8_t bytes[4]{};
  ASSERT_TRUE(radio.startSendRaw(bytes, sizeof(bytes)));
  module.complete();
  EXPECT_FALSE(dispatcher.probeRadioDriverStatus());
  EXPECT_EQ(0u, module.finishes);
  EXPECT_EQ(1u, radio.driverFaultCount());
}

TEST_F(RadioTxCompletion, ExpiredCurrentCompletionDoesNotAuthorizeStandby) {
  start();
  g_mock_millis = dispatcher.getCurrentSendDeadlineMs() + 1;
  module.complete();
  EXPECT_FALSE(dispatcher.probeRadioDriverStatus());
  EXPECT_TRUE(dispatcher.isSendInProgress());
  EXPECT_EQ(0u, module.finishes);
  EXPECT_EQ(1u, radio.driverFaultCount());
}

TEST_F(RadioTxCompletion, DeadlineExpiringDuringCheckedReadsDoesNotReconcile) {
  start();
  module.onRead = [&](unsigned read) {
    if (read == 3) {
      g_mock_millis = dispatcher.getCurrentSendDeadlineMs() + 1;
      module.complete();
    }
  };
  EXPECT_FALSE(dispatcher.probeRadioDriverStatus());
  EXPECT_TRUE(dispatcher.isSendInProgress());
  EXPECT_EQ(3u, module.reads);
  EXPECT_EQ(0u, module.finishes);
  EXPECT_EQ(1u, radio.driverFaultCount());
}

TEST_F(RadioTxCompletion, DuplicateInterruptDoesNotRepeatCleanupAccountingOrConsumeRx) {
  start(true);
  module.complete();
  ASSERT_TRUE(dispatcher.probeRadioDriverStatus());
  completedExactlyOnce();
  const auto ota_used = dispatcher.getDispatcherOtaIntegration().airtimeLimiter().storedUsageMs(g_mock_millis);
  EXPECT_EQ(20u, ota_used);
  module.interrupt();
  EXPECT_FALSE(radio.isSendComplete());
  ASSERT_TRUE(dispatcher.probeRadioDriverStatus());
  completedExactlyOnce();
  EXPECT_EQ(ota_used, dispatcher.getDispatcherOtaIntegration().airtimeLimiter().storedUsageMs(g_mock_millis));
  EXPECT_EQ(1u, module.starts);
}

class FaultDuringCompletion : public RadioTxCompletion, public testing::WithParamInterface<unsigned> {};

TEST_P(FaultDuringCompletion, RetainsFaultEvenWhenFreshRxProbeSucceeds) {
  const unsigned failure = GetParam();
  if (failure < 3) module.readStatus[failure] = -705;
  if (failure == 3) module.errors = 0x40;
  module.onRead = [&](unsigned read) {
    if (read == 3) {
      module.complete();
      if (failure == 4) module.mode = 0x70;
    }
    if (read == 4) {
      for (auto& status : module.readStatus) status = 0;
      module.errors = 0;
    }
  };
  start();
  EXPECT_FALSE(dispatcher.probeRadioDriverStatus());
  completedExactlyOnce();
  EXPECT_EQ(6u, module.reads);
  EXPECT_EQ(1u, radio.driverFaultCount());
  EXPECT_EQ(mesh::RadioDriverFaultOrigin::ActiveProbe, diagnostic().last.origin);
  EXPECT_NE(0, diagnostic().last.probeReasons);
  EXPECT_EQ(3, diagnostic().last.softwareStateBefore);
  EXPECT_EQ(19, diagnostic().last.softwareStateAfter);
}

INSTANTIATE_TEST_SUITE_P(EveryCheckedFailure, FaultDuringCompletion, testing::Values(0u, 1u, 2u, 3u, 4u));

TEST_F(RadioTxCompletion, RealActiveModeMismatchIsNotDiscardedDuringCompletion) {
  start();
  module.onRead = [&](unsigned read) {
    if (read == 3) { module.complete(); module.mode = 0x50; }
  };
  EXPECT_FALSE(dispatcher.probeRadioDriverStatus());
  completedExactlyOnce();
  EXPECT_EQ(1u, radio.driverFaultCount());
  EXPECT_EQ(kSx1262ModeMismatch, diagnostic().last.probeReasons);
}

TEST_F(RadioTxCompletion, SuccessfulCleanupStillRequiresFreshReceivingMode) {
  start();
  module.onRead = [&](unsigned read) {
    if (read == 3) module.complete();
    if (read == 4) module.mode = 0x20;
  };
  EXPECT_FALSE(dispatcher.probeRadioDriverStatus());
  completedExactlyOnce();
  EXPECT_EQ(6u, module.reads);
  EXPECT_EQ(1u, radio.driverFaultCount());
  EXPECT_EQ(kSx1262ModeMismatch, diagnostic().last.probeReasons);
  EXPECT_FALSE(dispatcher.probeRadioDriverStatus());
  completedExactlyOnce();
  EXPECT_EQ(2u, radio.driverFaultCount());
}

class CleanupFailure : public RadioTxCompletion, public testing::WithParamInterface<bool> {};

TEST_P(CleanupFailure, RemainsVisibleInSamePass) {
  start();
  module.complete();
  if (GetParam()) module.finishStatus = -706;
  else module.receiveStatus = -705;
  EXPECT_FALSE(dispatcher.probeRadioDriverStatus());
  EXPECT_EQ(1u, module.finishes);
  EXPECT_EQ(1u, manager.released);
  EXPECT_EQ(20u, dispatcher.getTotalAirTime());
  EXPECT_FALSE(radio.isInRecvMode());
  EXPECT_GE(radio.driverFaultCount(), 1u);
}

INSTANTIATE_TEST_SUITE_P(FinishOrReceive, CleanupFailure, testing::Values(false, true));

TEST_F(RadioTxCompletion, OrdinaryLoopUsesSameCompletionAccountingAndReceiveRearm) {
  start();
  module.complete();
  dispatcher.loop();
  completedExactlyOnce();
  EXPECT_EQ(0u, radio.driverFaultCount());
}

}  // namespace
#endif
