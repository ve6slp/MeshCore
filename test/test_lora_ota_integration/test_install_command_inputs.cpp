#include <gtest/gtest.h>

#include <cstring>

#include <helpers/ota/OtaBoardBackendCommon.h>

TEST(OtaInstallCommandInputs, NullBindingRefusesWithoutChangingCommand) {
  mesh::ota::OtaBoardInstallCommandProviderV2 provider;
  ::ota::storage::XiaoOtaCommandV2Fields command{};
  command.transaction_nonce = UINT64_C(0x1122334455667788);
  const auto before = command;
  uint8_t descriptor[59] = {}, signature[64] = {}, controller[32] = {};
  meshcore::ota::runtime::OtaSessionId session;
  EXPECT_FALSE(provider.buildInstallCommandV2(nullptr, signature, session, controller, command));
  EXPECT_FALSE(provider.buildInstallCommandV2(descriptor, nullptr, session, controller, command));
  EXPECT_FALSE(provider.buildInstallCommandV2(descriptor, signature, session, nullptr, command));
  EXPECT_EQ(0, memcmp(&before, &command, sizeof(command)));
}
