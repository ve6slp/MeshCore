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

TEST(LoraOtaPolicy, QspiLayoutReservesNonOverlappingFirmwareBanks) {
    EXPECT_TRUE(LoraOtaStorageLayout::isValid());
    EXPECT_EQ(0U, LoraOtaStorageLayout::kCandidateOffset);
    EXPECT_EQ(0x0C6000U, LoraOtaStorageLayout::kBackupOffset);
    EXPECT_EQ(0x18C000U, LoraOtaStorageLayout::kJournalOffset);
    EXPECT_EQ(0x194000U, LoraOtaStorageLayout::kLittleFsOffset);
}

TEST(LoraOtaSession, ManifestValidationRejectsInvalidPolicy) {
    LoraOtaManifest manifest = {};
    manifest.manifest_version = 1;
    manifest.image_size_bytes = 1024;
    manifest.image_crc32 = 0x12345678U;
    manifest.chunk_size_bytes = 128;
    manifest.chunk_count = 8;
    manifest.duty_cycle_percent = 255;
    manifest.required_bootloader_version = 7;
    manifest.security_counter = 42;
    manifest.mode = static_cast<uint8_t>(LoraOtaMode::Direct);
    manifest.update_window_ms = LoraOtaPolicy::kMsPerDay;
    strcpy(manifest.variant, "SenseCap Solar");
    strcpy(manifest.region, "US915");

    LoraOtaSession session;
    EXPECT_FALSE(session.validateManifest(manifest));
}

TEST(LoraOtaSession, ManifestRequiresBootloaderAndSecurityVersion) {
    LoraOtaManifest manifest = {};
    manifest.manifest_version = 1;
    manifest.image_size_bytes = 2048;
    manifest.image_crc32 = 0xABCDEF01U;
    manifest.chunk_size_bytes = 256;
    manifest.chunk_count = 8;
    manifest.update_window_ms = LoraOtaPolicy::kMsPerDay;
    manifest.duty_cycle_percent = 2;
    manifest.required_bootloader_version = 0;
    manifest.security_counter = 0;
    manifest.mode = static_cast<uint8_t>(LoraOtaMode::Direct);
    strcpy(manifest.variant, "SenseCap Solar");
    strcpy(manifest.region, "US915");

    LoraOtaSession session;
    EXPECT_FALSE(session.validateManifest(manifest));
}

TEST(LoraOtaSession, SessionTracksResumableChunkState) {
    LoraOtaSession session;
    LoraOtaManifest manifest = {};
    manifest.manifest_version = 1;
    manifest.firmware_version = 2;
    manifest.image_size_bytes = 2048;
    manifest.image_crc32 = 0xABCDEF01U;
    manifest.chunk_size_bytes = 256;
    manifest.chunk_count = 8;
    manifest.update_window_ms = LoraOtaPolicy::kMsPerDay;
    manifest.required_bootloader_version = 7;
    manifest.security_counter = 42;
    manifest.duty_cycle_percent = 2;
    manifest.mode = static_cast<uint8_t>(LoraOtaMode::RoutedMesh);
    strcpy(manifest.variant, "SenseCap Solar");
    strcpy(manifest.region, "US915");

    EXPECT_TRUE(session.begin(manifest));
    EXPECT_EQ(LoraOtaSessionState::ManifestPending, session.getState());
    EXPECT_TRUE(session.acceptManifest(manifest));
    EXPECT_EQ(LoraOtaSessionState::Ready, session.getState());

    EXPECT_TRUE(session.recordChunk(0, 0x11111111U));
    EXPECT_TRUE(session.recordChunk(3, 0x22222222U));
    EXPECT_FALSE(session.recordChunk(99, 0x33333333U));
    EXPECT_EQ(2U, session.countReceivedChunks());
    EXPECT_EQ(6U, session.countMissingChunks());
    EXPECT_FALSE(session.isComplete());

    EXPECT_TRUE(session.recordChunk(1, 0x44444444U));
    EXPECT_TRUE(session.recordChunk(2, 0x55555555U));
    EXPECT_TRUE(session.recordChunk(4, 0x66666666U));
    EXPECT_TRUE(session.recordChunk(5, 0x77777777U));
    EXPECT_TRUE(session.recordChunk(6, 0x88888888U));
    EXPECT_TRUE(session.recordChunk(7, 0x99999999U));
    EXPECT_TRUE(session.isComplete());
    EXPECT_TRUE(session.setComplete());
    EXPECT_EQ(LoraOtaSessionState::Complete, session.getState());
}

TEST(LoraOtaSession, BackgroundBudgetStaysWithinConfiguredShare) {
    LoraOtaSession session;
    LoraOtaManifest manifest = {};
    manifest.manifest_version = 1;
    manifest.image_size_bytes = 40000;
    manifest.image_crc32 = 0xAABBCCDDU;
    manifest.chunk_size_bytes = 256;
    manifest.chunk_count = 160;
    manifest.update_window_ms = LoraOtaPolicy::kMsPer72Hours;
    manifest.required_bootloader_version = 7;
    manifest.security_counter = 42;
    manifest.duty_cycle_percent = 2;
    manifest.mode = static_cast<uint8_t>(LoraOtaMode::Background);
    strcpy(manifest.variant, "XiaoS3 WioSX1262");
    strcpy(manifest.region, "EU868");

    EXPECT_TRUE(session.begin(manifest));
    EXPECT_EQ(5184000U, session.budgetMs());
    EXPECT_TRUE(session.canTransmitAdditional(1000U));
    EXPECT_FALSE(session.canTransmitAdditional(6000000U));
    EXPECT_EQ(5183000U, session.remainingBudgetMs(1000U));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
