#include <gtest/gtest.h>

#include <cstring>

#include <ota/runtime/OtaInstallAttemptIdentity.h>

class InstallAttemptNonceFixture : public ::testing::Test {
protected:
  void SetUp() override {
    for (size_t i = 0; i < sizeof(controller); ++i) controller[i] = static_cast<uint8_t>(i);
    for (size_t i = 0; i < sizeof(descriptor); ++i) descriptor[i] = static_cast<uint8_t>(0x80 + i);
    session.campaignId = 0x01020304;
    session.sessionId = 0x05060708;
    session.attemptId = 0x090a;
  }

  uint8_t controller[32];
  uint8_t descriptor[59];
  meshcore::ota::runtime::OtaSessionId session;
};

TEST_F(InstallAttemptNonceFixture, IndependentDomainSeparatedKnownAnswer) {
  // Independently computed with Python hashlib and struct.pack(">IIH").
  EXPECT_EQ(meshcore::ota::runtime::otaInstallAttemptNonce(controller, session, descriptor),
            UINT64_C(0x8f7bd71d8086d8fb));
  EXPECT_EQ(meshcore::ota::runtime::otaInstallAttemptNonce(controller, session, descriptor),
            UINT64_C(0x8f7bd71d8086d8fb));
}

TEST_F(InstallAttemptNonceFixture, EveryBindingComponentHasIndependentKnownAnswer) {
  controller[0] = 0xff;
  EXPECT_EQ(meshcore::ota::runtime::otaInstallAttemptNonce(controller, session, descriptor),
            UINT64_C(0x341c772653154211));
  controller[0] = 0;
  ++session.campaignId;
  EXPECT_EQ(meshcore::ota::runtime::otaInstallAttemptNonce(controller, session, descriptor),
            UINT64_C(0xd2f379be66f30d90));
  --session.campaignId;
  ++session.sessionId;
  EXPECT_EQ(meshcore::ota::runtime::otaInstallAttemptNonce(controller, session, descriptor),
            UINT64_C(0x6f431dcad161e9d0));
  --session.sessionId;
  ++session.attemptId;
  EXPECT_EQ(meshcore::ota::runtime::otaInstallAttemptNonce(controller, session, descriptor),
            UINT64_C(0xca4354cfe552d47f));
  --session.attemptId;
  descriptor[58] ^= 1;
  EXPECT_EQ(meshcore::ota::runtime::otaInstallAttemptNonce(controller, session, descriptor),
            UINT64_C(0x9ed502395cd64705));
}

TEST_F(InstallAttemptNonceFixture, NullBindingRefuses) {
  EXPECT_EQ(meshcore::ota::runtime::otaInstallAttemptNonce(nullptr, session, descriptor), UINT64_C(0));
  EXPECT_EQ(meshcore::ota::runtime::otaInstallAttemptNonce(controller, session, nullptr), UINT64_C(0));
}
