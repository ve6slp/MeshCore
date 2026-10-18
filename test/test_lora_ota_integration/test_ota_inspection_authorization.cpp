#include <gtest/gtest.h>
class InspectionCliFilesystem { public: void mkdir(const char*) {} };
#define FILESYSTEM InspectionCliFilesystem
#include <helpers/CommonCLI.h>
#undef FILESYSTEM

TEST(LoraOtaInspection, RemoteCliStillRequiresAnActualAdminTextCommand) {
  ClientInfo client{};
  EXPECT_FALSE(CommonCLI::isAdminTextCommand(PAYLOAD_TYPE_TXT_MSG, 6, client));
  client.permissions = PERM_ACL_ADMIN;
  EXPECT_TRUE(CommonCLI::isAdminTextCommand(PAYLOAD_TYPE_TXT_MSG, 6, client));
  EXPECT_FALSE(CommonCLI::isAdminTextCommand(PAYLOAD_TYPE_TXT_MSG, 5, client));
  EXPECT_FALSE(CommonCLI::isAdminTextCommand(PAYLOAD_TYPE_REQ, 6, client));
  client.permissions = PERM_ACL_READ_ONLY;
  EXPECT_FALSE(CommonCLI::isAdminTextCommand(PAYLOAD_TYPE_TXT_MSG, 6, client));
}
