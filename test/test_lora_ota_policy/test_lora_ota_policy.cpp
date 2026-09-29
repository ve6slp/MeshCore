#include <gtest/gtest.h>

#include "helpers/LoraOtaPolicy.h"

using namespace mesh;

TEST(LoraOtaPolicy, DutyCycleIsClampedTo100Percent) {
    EXPECT_EQ(100U, LoraOtaPolicy::clampDutyCycle(250));
    EXPECT_EQ(2U, LoraOtaPolicy::clampDutyCycle(2));
}

TEST(LoraOtaPolicy, DirectModeBudgetMatchesTheConfiguredDutyCycle) {
    const uint32_t window_ms = 24UL * 60UL * 60UL * 1000UL;
    EXPECT_EQ(864000U, LoraOtaPolicy::computeAirtimeBudgetMs(window_ms, 1));
    EXPECT_EQ(1728000U, LoraOtaPolicy::computeAirtimeBudgetMs(window_ms, 2));
    EXPECT_EQ(8640000U, LoraOtaPolicy::computeAirtimeBudgetMs(window_ms, 10));
}

TEST(LoraOtaPolicy, BackgroundRequiresLowDutyCycleAndLightLoad) {
    EXPECT_TRUE(LoraOtaPolicy::isBackgroundEligible(2, 0.2f));
    EXPECT_FALSE(LoraOtaPolicy::isBackgroundEligible(1, 0.9f));
    EXPECT_FALSE(LoraOtaPolicy::isBackgroundEligible(5, 0.2f));
}

TEST(LoraOtaPolicy, BackgroundPlansReserveTheAirtimeBudgetAcrossLongWindows) {
    const auto plan = LoraOtaPolicy::buildPlan(
        LoraOtaMode::Background,
        LoraOtaPolicy::kMsPer72Hours,
        2,
        0.3f,
        false,
        true,
        true);

    EXPECT_EQ(LoraOtaMode::Background, plan.mode);
    EXPECT_EQ(2U, plan.duty_cycle_percent);
    EXPECT_EQ(5184000U, plan.airtime_budget_ms);
    EXPECT_EQ(2592000U, plan.upload_window_ms);
    EXPECT_TRUE(plan.background_allowed);
}

TEST(LoraOtaPolicy, RoutedPlansDemandAMeshPath) {
    const auto plan = LoraOtaPolicy::buildPlan(
        LoraOtaMode::RoutedMesh,
        LoraOtaPolicy::kMsPerDay,
        10,
        0.5f,
        false,
        false,
        false);

    EXPECT_EQ(LoraOtaMode::RoutedMesh, plan.mode);
    EXPECT_TRUE(plan.mesh_path_required);
    EXPECT_EQ(8640000U, plan.airtime_budget_ms);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
