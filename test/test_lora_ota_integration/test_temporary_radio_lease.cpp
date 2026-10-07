#include <gtest/gtest.h>

#include <helpers/TemporaryRadioLease.h>

namespace {

class TemporaryRadioLeaseRole : public testing::TestWithParam<bool> {
 protected:
  mesh::TemporaryRadioLease lease;
  uint32_t frequency = 907525;
  unsigned applies = 0, restores = 0;
  bool fail = false;

  void apply(uint32_t now) {
    lease.applyIfDue(now, [this]() { ++applies; frequency = 908525; });
  }
  bool restore(uint32_t now, bool idle = true) {
    return lease.restoreIfDue(now, [this]() {
      ++restores;
      if (fail) return false;
      frequency = 907525;
      return true;
    }, idle);
  }
};

TEST_P(TemporaryRadioLeaseRole, FailedRestoreRetainsObligationUntilCheckedSuccess) {
  lease.schedule(0, 1);
  apply(2001);
  ASSERT_EQ(908525u, frequency);
  fail = true;
  EXPECT_FALSE(restore(62001));
  ASSERT_TRUE(lease.pending());
  ASSERT_TRUE(lease.restoreRetryPending());
  EXPECT_EQ(908525u, frequency);
  fail = false;
  EXPECT_FALSE(restore(63001));
  EXPECT_TRUE(restore(63002));
  EXPECT_EQ(907525u, frequency);
  EXPECT_FALSE(lease.pending());
  EXPECT_EQ(2u, restores);
}

TEST_P(TemporaryRadioLeaseRole, ApplyDeadlineZeroIsPresentAndFiresAfterClockWrap) {
  lease.schedule(UINT32_MAX - 1999u, 1);
  apply(UINT32_MAX);
  apply(0);
  EXPECT_EQ(0u, applies);
  apply(1);
  ASSERT_EQ(1u, applies);
  EXPECT_EQ(908525u, frequency);
  EXPECT_TRUE(restore(60001));
  EXPECT_FALSE(lease.pending());
}

TEST_P(TemporaryRadioLeaseRole, RestoreDeadlineZeroIsPresentAndRestoresAfterClockWrap) {
  lease.schedule(0xFFFF0DD0u, 1);
  apply(0xFFFF15A1u);
  ASSERT_EQ(908525u, frequency);
  EXPECT_FALSE(restore(UINT32_MAX));
  EXPECT_FALSE(restore(0));
  EXPECT_TRUE(restore(1));
  EXPECT_EQ(907525u, frequency);
  EXPECT_FALSE(lease.pending());
}

TEST_P(TemporaryRadioLeaseRole, PermanentFailureRetriesAtMostOncePerSecondAndDefersBusyRadio) {
  lease.schedule(0, 1);
  apply(2001);
  fail = true;
  EXPECT_FALSE(restore(62001));
  for (uint32_t now = 62002; now <= 63001; ++now) EXPECT_FALSE(restore(now));
  EXPECT_EQ(1u, restores);
  EXPECT_FALSE(restore(63002, false));
  EXPECT_EQ(1u, restores);
  EXPECT_FALSE(restore(63002));
  EXPECT_EQ(2u, restores);
  EXPECT_TRUE(lease.pending());
  EXPECT_TRUE(lease.restoreRetryPending());
  EXPECT_EQ(908525u, frequency);
}

TEST_P(TemporaryRadioLeaseRole, RetryDeadlineZeroRetainsItsPresence) {
  const uint32_t failureTime = UINT32_MAX - 999u;
  lease.schedule(failureTime - 62001u, 1);
  apply(failureTime - 60000u);
  fail = true;
  EXPECT_FALSE(restore(failureTime));
  ASSERT_TRUE(lease.pending());
  fail = false;
  EXPECT_FALSE(restore(0));
  EXPECT_TRUE(restore(1));
  EXPECT_EQ(907525u, frequency);
}

TEST_P(TemporaryRadioLeaseRole, CancellationRetainsFailedRestoreWithoutApplyingAnExpiredLease) {
  lease.schedule(0, 1);
  lease.cancel(100);
  fail = true;
  EXPECT_FALSE(restore(100));
  ASSERT_TRUE(lease.pending());
  apply(2001);
  EXPECT_EQ(0u, applies);
  fail = false;
  EXPECT_TRUE(restore(2001));
  EXPECT_FALSE(lease.pending());
  EXPECT_EQ(907525u, frequency);
}

TEST_P(TemporaryRadioLeaseRole, ExistingUncheckedApiAndTwoSecondReplyGraceArePreserved) {
  lease.schedule(100, 1);
  apply(2100);
  EXPECT_EQ(0u, applies);
  apply(2101);
  EXPECT_EQ(1u, applies);
  EXPECT_TRUE(lease.applied());
  auto unchecked = [this]() { ++restores; frequency = 907525; };
  EXPECT_FALSE(lease.restoreUncheckedIfDue(62100, unchecked));
  EXPECT_TRUE(lease.restoreUncheckedIfDue(62101, unchecked));
  EXPECT_EQ(1u, restores);
  EXPECT_FALSE(lease.pending());
}

TEST_P(TemporaryRadioLeaseRole, RepeatedCancellationCannotDefeatRestoreBackoff) {
  lease.schedule(0, 1);
  apply(2001);
  fail = true;
  EXPECT_FALSE(restore(62001));
  for (uint32_t now = 62002; now <= 63001; ++now) {
    lease.cancel(now);
    EXPECT_FALSE(restore(now));
  }
  EXPECT_EQ(1u, restores);
  fail = false;
  EXPECT_TRUE(restore(63002));
  EXPECT_EQ(907525u, frequency);
}

TEST_P(TemporaryRadioLeaseRole, RestorationWithoutIdentityGatedApplyPreventsALateExpiredApply) {
  lease.schedule(0, 1);
  EXPECT_TRUE(restore(62001));
  apply(65000);
  EXPECT_EQ(0u, applies);
  EXPECT_EQ(907525u, frequency);
  EXPECT_FALSE(lease.pending());
}

TEST_P(TemporaryRadioLeaseRole, FailedRestoreUsesFreshRetryDeadlineAcrossMultipleClockQuadrants) {
  lease.schedule(0, 1);
  apply(2001);
  fail = true;
  uint32_t now = 62001;
  EXPECT_FALSE(restore(now));
  for (unsigned i = 0; i < 4; ++i) {
    now += 1u << 30;
    EXPECT_FALSE(restore(now));
    EXPECT_EQ(i + 2, restores);
    EXPECT_TRUE(lease.pending());
  }
  fail = false;
  EXPECT_TRUE(restore(now + 1001u));
  EXPECT_EQ(907525u, frequency);
}

INSTANTIATE_TEST_SUITE_P(BothProductionRoles, TemporaryRadioLeaseRole, testing::Bool(),
                        [](const testing::TestParamInfo<bool>& info) {
                          return info.param ? "Companion" : "Repeater";
                        });

}  // namespace
