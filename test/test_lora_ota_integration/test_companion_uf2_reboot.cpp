#include <gtest/gtest.h>

#include <helpers/MultiSerialInterface.h>
#include "../../examples/companion_radio/MyMesh.h"

#include <string>
#include <vector>

namespace {

namespace uf2 = companion_usb_uf2;
using Phase = mesh::ota::usb::UsbOtaPhase;
using Reply = uf2::Reply;

std::vector<uint8_t> command(const std::string& payload) {
  std::vector<uint8_t> frame{19};
  frame.insert(frame.end(), payload.begin(), payload.end());
  return frame;
}

class CompanionUf2 : public testing::Test {
 protected:
  uf2::Pending pending;
  Phase phase = Phase::Idle;
  bool supported = true, local_usb = true, writes_allowed = true;
  bool transport_active = true;
  bool trial_active = false, boot_pending = false, rf_pending = false;
  bool dirty = true, save_ok = true, revoke_after_save = false;
  unsigned permission_queries = 0, clock_queries = 0, saves = 0, entries = 0, resets = 0;
  std::vector<Reply> replies;

  bool allowed() {
    ++permission_queries;
    return transport_active &&
        uf2::permitted(writes_allowed, trial_active, boot_pending, rf_pending, phase);
  }

  bool save() {
    ++saves;
    if (revoke_after_save) boot_pending = true;
    return save_ok;
  }

  bool request(const std::vector<uint8_t>& frame, uint32_t now = 100) {
    return uf2::request(
        frame.data(), frame.size(), supported ? &pending : nullptr, local_usb,
        mesh::ota::OtaFirmwareIntegration::kCommitRebootGraceMs,
        mesh::ota::OtaFirmwareIntegration::kCommitRebootQueueWaitMs,
        [this]() { return allowed(); }, [this, now]() { ++clock_queries; return now; },
        [this](Reply reply) { replies.push_back(reply); });
  }

  void dispatch(const std::vector<uint8_t>& frame) {
    if (!request(frame) && uf2::classify(frame.data(), frame.size()) == uf2::Request::Ordinary) {
      uf2::ordinaryReboot(dirty, writes_allowed, [this]() { save(); }, [this]() { ++resets; });
    }
  }

  void tick(uint32_t now, bool tx = false, bool queued = false, bool interface_busy = false) {
    uf2::tick(
        pending, now, tx, queued, interface_busy, [this]() { return allowed(); },
        [this]() { return !dirty || !writes_allowed || save(); },
        [this](Reply reply) { replies.push_back(reply); }, [this]() { ++entries; });
  }
};

TEST_F(CompanionUf2, ExactRequestAcknowledgesWithoutImmediateWritesOrReset) {
  ASSERT_TRUE(request(command("reboot uf2")));
  ASSERT_TRUE(pending.active);
  EXPECT_EQ(2100u, pending.due_ms);
  EXPECT_EQ(15100u, pending.queue_deadline_ms);
  EXPECT_EQ(std::vector<Reply>{Reply::Ok}, replies);
  EXPECT_EQ(0u, saves);
  EXPECT_EQ(0u, entries);
  EXPECT_EQ(0u, resets);
}

TEST_F(CompanionUf2, DuplicateRequestDoesNotExtendEitherDeadline) {
  ASSERT_TRUE(request(command("reboot uf2")));
  ASSERT_TRUE(request(command("reboot uf2"), 1500));
  EXPECT_EQ(2100u, pending.due_ms);
  EXPECT_EQ(15100u, pending.queue_deadline_ms);
  EXPECT_EQ(1u, clock_queries);
  EXPECT_EQ(2u, replies.size());
}

TEST_F(CompanionUf2, NonUsbRequestIsRejectedBeforeReadinessOrPersistence) {
  local_usb = false;
  dispatch(command("reboot uf2"));
  EXPECT_EQ(std::vector<Reply>{Reply::Unsupported}, replies);
  EXPECT_FALSE(pending.active);
  EXPECT_EQ(0u, permission_queries);
  EXPECT_EQ(0u, clock_queries);
  EXPECT_EQ(0u, saves);
  EXPECT_EQ(0u, resets);
}

TEST_F(CompanionUf2, UnsupportedProfileDoesNotQueryReadinessOrReset) {
  supported = false;
  dispatch(command("reboot uf2"));
  EXPECT_EQ(std::vector<Reply>{Reply::Unsupported}, replies);
  EXPECT_FALSE(pending.active);
  EXPECT_EQ(0u, permission_queries);
  EXPECT_EQ(0u, saves);
  EXPECT_EQ(0u, resets);
}

TEST_F(CompanionUf2, MalformedFormsNeverFallThroughToOrdinaryReset) {
  const std::vector<std::string> malformed{
      "", "r", "reboo", "boot", "reboot ", "reboot u", "reboot uf", "rebootuf2",
      "reboot uf2x", "reboot uf2 ", "reboot uf2\r", "reboot uf2\n",
      std::string("reboot uf2\0", 11), std::string("reboot uf2\0x", 12),
      "reboot uf2 USB", "reboot uf2 local_usb=1"};
  for (const auto& payload : malformed) {
    SCOPED_TRACE(payload);
    const auto before = replies.size();
    dispatch(command(payload));
    ASSERT_EQ(before + 1, replies.size());
    EXPECT_EQ(Reply::IllegalArgument, replies.back());
    EXPECT_FALSE(pending.active);
  }
  EXPECT_EQ(0u, permission_queries);
  EXPECT_EQ(0u, clock_queries);
  EXPECT_EQ(0u, saves);
  EXPECT_EQ(0u, resets);
  EXPECT_EQ(0u, entries);
}

TEST_F(CompanionUf2, EmptyFrameAndNullFrameAreRejectedWithoutAccessingStaleBytes) {
  ASSERT_TRUE(request({}));
  EXPECT_EQ(Reply::IllegalArgument, replies.back());
  EXPECT_EQ(uf2::Request::Malformed, uf2::classify(nullptr, 11));
  EXPECT_EQ(0u, permission_queries);
  EXPECT_EQ(0u, resets);
}

TEST_F(CompanionUf2, MalformedRequestDoesNotChangeAnExistingPendingReboot) {
  ASSERT_TRUE(request(command("reboot uf2")));
  const unsigned queried = permission_queries;
  dispatch(command("reboot uf2x"));
  EXPECT_TRUE(pending.active);
  EXPECT_EQ(2100u, pending.due_ms);
  EXPECT_EQ(15100u, pending.queue_deadline_ms);
  EXPECT_EQ(queried, permission_queries);
  EXPECT_EQ(Reply::IllegalArgument, replies.back());
}

TEST_F(CompanionUf2, OrdinaryRebootPreservesDirtyContactWriteEligibility) {
  for (bool allowed_write : {false, true}) {
    for (bool contacts_dirty : {false, true}) {
      writes_allowed = allowed_write;
      dirty = contacts_dirty;
      const unsigned before = saves;
      dispatch(command("reboot"));
      EXPECT_EQ(before + (allowed_write && contacts_dirty ? 1u : 0u), saves);
    }
  }
  EXPECT_EQ(4u, resets);
  EXPECT_EQ(0u, permission_queries);
  EXPECT_TRUE(replies.empty());
  EXPECT_FALSE(pending.active);
}

TEST_F(CompanionUf2, LegacyNullTerminatorAndFailedSaveStillUseOrdinaryReboot) {
  save_ok = false;
  supported = false;
  local_usb = false;
  dispatch(command(std::string("reboot\0", 7)));
  EXPECT_EQ(1u, saves);
  EXPECT_EQ(1u, resets);
  EXPECT_TRUE(replies.empty());
}

TEST_F(CompanionUf2, OtherOpcodeIsNotClaimedByUf2Parser) {
  auto frame = command("reboot uf2");
  frame[0] = 66;
  EXPECT_FALSE(request(frame));
  EXPECT_TRUE(replies.empty());
  EXPECT_FALSE(pending.active);
  EXPECT_EQ(0u, permission_queries);
}

TEST_F(CompanionUf2, AllTargetForbiddenPhasesRefuseWithoutMutation) {
  for (Phase blocked : {Phase::Erasing, Phase::Receiving, Phase::Verifying, Phase::Ready,
                        Phase::CacheSealed, Phase::CommitPending, Phase::Trial}) {
    phase = blocked;
    ASSERT_TRUE(request(command("reboot uf2")));
    EXPECT_EQ(Reply::BadState, replies.back());
    EXPECT_FALSE(pending.active);
  }
  EXPECT_EQ(0u, clock_queries);
  EXPECT_EQ(0u, saves);
  EXPECT_EQ(0u, entries);
}

TEST_F(CompanionUf2, WriteTrialBootPendingAndRfSafeguardsAllRefuse) {
  writes_allowed = false;
  ASSERT_TRUE(request(command("reboot uf2")));
  writes_allowed = true;
  trial_active = true;
  ASSERT_TRUE(request(command("reboot uf2")));
  trial_active = false;
  boot_pending = true;
  ASSERT_TRUE(request(command("reboot uf2")));
  boot_pending = false;
  rf_pending = true;
  ASSERT_TRUE(request(command("reboot uf2")));
  for (Reply reply : replies) EXPECT_EQ(Reply::BadState, reply);
  EXPECT_FALSE(pending.active);
  EXPECT_EQ(0u, clock_queries);
  EXPECT_EQ(0u, saves);
}

TEST_F(CompanionUf2, AbortedCacheCanScheduleButSealedCacheIsNotSilentlyChanged) {
  phase = Phase::CacheSealed;
  ASSERT_TRUE(request(command("reboot uf2")));
  EXPECT_EQ(Phase::CacheSealed, phase);
  EXPECT_FALSE(pending.active);
  phase = Phase::Aborted;
  ASSERT_TRUE(request(command("reboot uf2")));
  EXPECT_TRUE(pending.active);
  EXPECT_EQ(Phase::Aborted, phase);
}

TEST_F(CompanionUf2, TwoSecondGraceAndExactlyOneEntryAfterDrain) {
  ASSERT_TRUE(request(command("reboot uf2")));
  tick(2099);
  EXPECT_EQ(0u, saves);
  EXPECT_EQ(0u, entries);
  tick(2100);
  EXPECT_EQ(1u, saves);
  EXPECT_EQ(1u, entries);
  EXPECT_FALSE(pending.active);
  const unsigned queried = permission_queries;
  tick(99999);
  EXPECT_EQ(1u, entries);
  EXPECT_EQ(queried, permission_queries);
}

TEST_F(CompanionUf2, TxQueueAndInterfaceMustDrainBeforeTheBound) {
  ASSERT_TRUE(request(command("reboot uf2")));
  tick(2100, true);
  tick(2101, false, true);
  tick(2102, false, false, true);
  EXPECT_EQ(0u, saves);
  EXPECT_EQ(0u, entries);
  tick(2103);
  EXPECT_EQ(1u, entries);
}

TEST_F(CompanionUf2, FifteenSecondBoundCanInterruptOrdinaryQueuedWork) {
  ASSERT_TRUE(request(command("reboot uf2")));
  tick(15099, true, true, true);
  EXPECT_EQ(0u, entries);
  tick(15100, true, true, true);
  EXPECT_EQ(1u, entries);
  EXPECT_FALSE(pending.active);
}

TEST_F(CompanionUf2, DeadlineDoesNotOverrideAnRfOrBootPermissionFailure) {
  ASSERT_TRUE(request(command("reboot uf2")));
  rf_pending = true;
  tick(15100, true, true);
  EXPECT_FALSE(pending.active);
  EXPECT_EQ(Reply::BadState, replies.back());
  EXPECT_EQ(0u, saves);
  EXPECT_EQ(0u, entries);
}

TEST_F(CompanionUf2, PermissionRevocationCancelsWithExplicitFailureEvenDuringGrace) {
  ASSERT_TRUE(request(command("reboot uf2")));
  boot_pending = true;
  tick(101);
  EXPECT_FALSE(pending.active);
  EXPECT_EQ(std::vector<Reply>({Reply::Ok, Reply::BadState}), replies);
  EXPECT_EQ(0u, saves);
  EXPECT_EQ(0u, entries);
}

TEST_F(CompanionUf2, NewlySealedCacheCancelsPendingEntryWithoutChangingTheCache) {
  ASSERT_TRUE(request(command("reboot uf2")));
  phase = Phase::CacheSealed;
  tick(2100);
  EXPECT_EQ(Phase::CacheSealed, phase);
  EXPECT_FALSE(pending.active);
  EXPECT_EQ(Reply::BadState, replies.back());
  EXPECT_EQ(0u, saves);
  EXPECT_EQ(0u, entries);
}

TEST_F(CompanionUf2, EveryRevokedReadinessInputCancelsBeforePersistenceOrEntry) {
  for (unsigned input = 0; input < 5; ++input) {
    SCOPED_TRACE(input);
    writes_allowed = true;
    transport_active = true;
    trial_active = boot_pending = rf_pending = false;
    ASSERT_TRUE(request(command("reboot uf2")));
    switch (input) {
      case 0: writes_allowed = false; break;
      case 1: trial_active = true; break;
      case 2: boot_pending = true; break;
      case 3: rf_pending = true; break;
      case 4: transport_active = false; break;
    }
    tick(2100);
    EXPECT_FALSE(pending.active);
    EXPECT_EQ(Reply::BadState, replies.back());
  }
  EXPECT_EQ(0u, saves);
  EXPECT_EQ(0u, entries);
}

TEST_F(CompanionUf2, ContactPersistenceIsDeferredAndCleanContactsNeedNoWrite) {
  dirty = false;
  ASSERT_TRUE(request(command("reboot uf2")));
  tick(2100);
  EXPECT_EQ(0u, saves);
  EXPECT_EQ(1u, entries);
}

TEST_F(CompanionUf2, FailedContactPersistenceNotifiesAndDoesNotEnterUf2) {
  save_ok = false;
  ASSERT_TRUE(request(command("reboot uf2")));
  tick(2100);
  EXPECT_EQ(1u, saves);
  EXPECT_EQ(Reply::FileIo, replies.back());
  EXPECT_FALSE(pending.active);
  EXPECT_EQ(0u, entries);
}

TEST_F(CompanionUf2, PermissionIsRecheckedAfterTheFinalContactsWrite) {
  revoke_after_save = true;
  ASSERT_TRUE(request(command("reboot uf2")));
  tick(2100);
  EXPECT_EQ(1u, saves);
  EXPECT_EQ(Reply::BadState, replies.back());
  EXPECT_FALSE(pending.active);
  EXPECT_EQ(0u, entries);
}

TEST_F(CompanionUf2, ZeroGraceDeadlineAndQueueDeadlineRemainValidAcrossClockWrap) {
  ASSERT_TRUE(request(command("reboot uf2"), UINT32_MAX - 1999u));
  EXPECT_EQ(0u, pending.due_ms);
  tick(UINT32_MAX);
  EXPECT_EQ(0u, entries);
  tick(0);
  EXPECT_EQ(1u, entries);

  ASSERT_TRUE(request(command("reboot uf2"), UINT32_MAX - 14999u));
  EXPECT_EQ(0u, pending.queue_deadline_ms);
  tick(UINT32_MAX, true, true);
  EXPECT_EQ(1u, entries);
  tick(0, true, true);
  EXPECT_EQ(2u, entries);
}

class FrameInterface : public BaseSerialInterface {
 public:
  bool enabled = true;
  std::vector<uint8_t> received;
  unsigned reads = 0;
  void enable() override { enabled = true; }
  void disable() override { enabled = false; }
  bool isEnabled() const override { return enabled; }
  bool isConnected() const override { return true; }
  bool isWriteBusy() const override { return false; }
  size_t writeFrame(const uint8_t*, size_t len) override { return len; }
  size_t checkRecvFrame(uint8_t* dest) override {
    ++reads;
    const size_t len = received.size();
    if (len) std::memcpy(dest, received.data(), len);
    received.clear();
    return len;
  }
};

TEST_F(CompanionUf2, ActualUsbObjectRatherThanClaimedTransportAuthorizesRequest) {
  MultiSerialInterface manager;
  FrameInterface usb, bluetooth;
  ASSERT_TRUE(manager.addInterface(InterfaceType::USB, &usb));
  manager.enable();
  BaseSerialInterface* serial = &manager;
  usb.received = command("reboot uf2");
  uint8_t frame[MAX_FRAME_SIZE] = {};
  bool from_usb = false;
  const size_t len = uf2::receive(serial, manager, usb, frame, from_usb);
  ASSERT_TRUE(from_usb);
  local_usb = from_usb;
  ASSERT_TRUE(request(std::vector<uint8_t>(frame, frame + len)));
  ASSERT_TRUE(pending.active);

  pending = {};
  bluetooth.received = command("reboot uf2");
  serial = &bluetooth;
  from_usb = true;
  const size_t non_usb_len = uf2::receive(serial, manager, usb, frame, from_usb);
  ASSERT_FALSE(from_usb);
  local_usb = from_usb;
  ASSERT_TRUE(request(std::vector<uint8_t>(frame, frame + non_usb_len)));
  EXPECT_EQ(Reply::Unsupported, replies.back());
  EXPECT_FALSE(pending.active);
}

TEST(CompanionUf2Receive, DisabledOrAbsentReaderCannotLeaveStaleUsbProvenance) {
  MultiSerialInterface manager;
  FrameInterface usb;
  BaseSerialInterface* serial = &manager;
  uint8_t frame[MAX_FRAME_SIZE] = {};
  bool from_usb = true;
  EXPECT_EQ(0u, uf2::receive(serial, manager, usb, frame, from_usb));
  EXPECT_FALSE(from_usb);
  manager.enable();
  usb.disable();
  from_usb = true;
  EXPECT_EQ(0u, uf2::receive(serial, manager, usb, frame, from_usb));
  EXPECT_FALSE(from_usb);
  usb.enable();
  from_usb = true;
  EXPECT_EQ(0u, uf2::receive(serial, manager, usb, frame, from_usb));
  EXPECT_FALSE(from_usb);
  serial = nullptr;
  from_usb = true;
  EXPECT_EQ(0u, uf2::receive(serial, manager, usb, frame, from_usb));
  EXPECT_FALSE(from_usb);
}

}  // namespace
