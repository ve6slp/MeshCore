#include <gtest/gtest.h>

#include "ota/storage/XiaoOtaActiveExtentBridge.h"

TEST(XiaoOtaActiveExtentCrcPolicy, GenuineComputedZeroDoesNotPreventExtentResolution) {
  const uint8_t image[] = {0xFF, 0xFF, 0x00, 0x00};
  ota::storage::XiaoOtaBank0Settings bank0;
  bank0.bank_0 = ota::storage::kBankValidApp;
  bank0.bank_0_size = sizeof(image);
  bank0.bank_0_crc = 0;

  ASSERT_EQ(0u, ota::storage::XiaoOtaActiveExtentBridge::crc16Compute(image, sizeof(image)));
  EXPECT_EQ(sizeof(image), ota::storage::XiaoOtaActiveExtentBridge::resolveExtentFromBank0(
                                    bank0, image, sizeof(image)));
}

TEST(XiaoOtaActiveExtentCrcPolicy, ZeroStoredCrcNeverSkipsRealImageVerification) {
  const uint8_t image[] = {0x00, 0x00, 0x00, 0x00};
  ota::storage::XiaoOtaBank0Settings bank0;
  bank0.bank_0 = ota::storage::kBankValidApp;
  bank0.bank_0_size = sizeof(image);
  bank0.bank_0_crc = 0;

  ASSERT_EQ(0x84C0u, ota::storage::XiaoOtaActiveExtentBridge::crc16Compute(image, sizeof(image)));
  EXPECT_EQ(0u, ota::storage::XiaoOtaActiveExtentBridge::resolveExtentFromBank0(
                       bank0, image, sizeof(image)));
}
