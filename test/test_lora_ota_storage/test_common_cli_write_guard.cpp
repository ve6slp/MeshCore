#include <gtest/gtest.h>
#include <algorithm>
#include <cstdlib>
#include <string>

#define STM32_PLATFORM 1
#include "b_startup_mocks/Adafruit_LittleFS.h"
#define FILESYSTEM Adafruit_LittleFS
using namespace Adafruit_LittleFS_Namespace;
using std::min;
#include "../../src/helpers/CommonCLI.cpp"
#include "../../src/helpers/AdvertDataHelpers.cpp"
#include "../../src/helpers/RegionMap.cpp"
#include "../../src/helpers/TransportKeyStore.cpp"
#undef STM32_PLATFORM

bool mesh::LocalIdentity::validatePrivateKey(const uint8_t*) { return false; }

namespace {

class GuardBoard : public mesh::MainBoard {
public:
  unsigned variant_commands = 0;
  uint16_t getBattMilliVolts() override { return 3700; }
  const char* getManufacturerName() const override { return "fixture"; }
  uint8_t getStartupReason() const override { return 0; }
  void reboot() override {}
  bool handleCommand(const char*, uint32_t, char*) override {
    ++variant_commands;
    return false;
  }
};

class GuardClock : public mesh::RTCClock {
public:
  uint32_t getCurrentTime() override { return 123; }
  void setCurrentTime(uint32_t) override {}
};

class GuardCallbacks : public CommonCLICallbacks {
public:
  bool allowed = false;
  unsigned saves = 0, erases = 0, identity_saves = 0, region_saves = 0;
  mesh::LocalIdentity identity;
  bool allowUserdataWrites() const override { return allowed; }
  void savePrefs() override { ++saves; }
  const char* getFirmwareVer() override { return "fixture"; }
  const char* getBuildDate() override { return "fixture"; }
  const char* getRole() override { return "fixture"; }
  bool formatFileSystem() override { ++erases; return true; }
  void sendSelfAdvertisement(int, bool) override {}
  void updateAdvertTimer() override {}
  void updateFloodAdvertTimer() override {}
  void setLoggingOn(bool) override {}
  void eraseLogFile() override { ++erases; }
  void dumpLogFile() override {}
  void setTxPower(int8_t) override {}
  void formatNeighborsReply(char* reply) override { strcpy(reply, "neighbors"); }
  void formatStatsReply(char* reply) override { strcpy(reply, "stats"); }
  void formatRadioStatsReply(char* reply) override { strcpy(reply, "radio"); }
  void formatPacketStatsReply(char* reply) override { strcpy(reply, "packets"); }
  mesh::LocalIdentity& getSelfId() override { return identity; }
  void saveIdentity(const mesh::LocalIdentity&) override { ++identity_saves; }
  bool saveRegions() override { ++region_saves; return true; }
  void clearStats() override {}
  void applyTempRadioParams(float, float, uint8_t, uint8_t, int) override {}
};

class CommonCliWriteGuard : public testing::Test {
protected:
  Adafruit_LittleFS fs;
  GuardBoard board;
  GuardClock clock;
  SensorManager sensors;
  TransportKeyStore keys;
  RegionMap regions{keys};
  ClientACL acl;
  NodePrefs prefs;
  GuardCallbacks callbacks;
  CommonCLI cli{board, clock, sensors, regions, acl, &prefs, &callbacks};

  void SetUp() override {
    ASSERT_TRUE(fs.begin());
    strcpy(prefs.node_name, "original");
    strcpy(prefs.password, "private");
    strcpy(prefs.guest_password, "guest");
    prefs.owner_info[0] = prefs.bridge_secret[0] = 0;
    prefs.freq = 912.525f;
  }

  std::string command(const char* text) {
    char input[256] = {}, reply[256] = {};
    strcpy(input, text);
    cli.handleCommand(0, input, reply);
    return reply;
  }
};

TEST_F(CommonCliWriteGuard, HeldMutatorsFailBeforeChangingPreferencesRegionsOrCallingVariants) {
  for (const char* text : {
      "set name replaced", "set radio 913.525,250,7,5", "set freq 913.525",
      "set tx 17", "setperm 0011 3", "password replaced",
      "set prv.key 00", "erase", "region default replaced", "region save",
      "region def #new", "region home replaced", "region load", "region put new",
      "log erase", "log start", "sensor set gps 1", "gps on", "gps setloc",
      "gps advert share", "powersaving on", "start ota", "unknown variant"}) {
    SCOPED_TRACE(text);
    EXPECT_EQ("Err - userdata writes held during OTA trial or unresolved boot", command(text));
  }
  EXPECT_STREQ("original", prefs.node_name);
  EXPECT_STREQ("private", prefs.password);
  EXPECT_FLOAT_EQ(912.525f, prefs.freq);
  EXPECT_FALSE(prefs.isDirty());
  EXPECT_EQ(nullptr, regions.getDefaultRegion());
  EXPECT_EQ(0, regions.getCount());
  EXPECT_EQ(0u, callbacks.saves + callbacks.erases + callbacks.identity_saves + callbacks.region_saves);
  EXPECT_EQ(0u, board.variant_commands);
}

TEST_F(CommonCliWriteGuard, HeldReadsRemainAvailableWithoutDispatchingVariantCommands) {
  EXPECT_EQ("> original", command("get name"));
  EXPECT_EQ("neighbors", command("neighbors"));
  EXPECT_EQ("stats", command("stats-core"));
  EXPECT_EQ("fixture (Build: fixture)", command("ver"));
  char reply[160] = {};
  for (const char* text : {"gps", "gps diag", "gps advert", "region home",
                            "region default", "sensor list 3", "ota preflight", "get acl"}) {
    EXPECT_TRUE(cli.checkCommandWritePermission(text, reply)) << text;
  }
  EXPECT_FALSE(cli.checkCommandWritePermission("sensor list 3 set gps 1", reply));
  EXPECT_EQ(0u, board.variant_commands);
}

TEST_F(CommonCliWriteGuard, HeldDirectSaveDoesNotRemoveOrReplaceAnExistingFile) {
  auto bytes = std::make_shared<std::vector<uint8_t>>(std::initializer_list<uint8_t>{1, 2, 3});
  fs._getFS()->files["/prefs.json"] = bytes;
  EXPECT_FALSE(cli.savePrefs(&fs));
  EXPECT_EQ(bytes, fs._getFS()->files.at("/prefs.json"));
  EXPECT_EQ((std::vector<uint8_t>{1, 2, 3}), *bytes);
  EXPECT_EQ(0, fs._getFS()->writes);
  EXPECT_EQ(0, fs._getFS()->removes);
}

TEST_F(CommonCliWriteGuard, HeldLegacyLoadReadsSettingsWithoutMigratingButNormalBootStillMigrates) {
  auto legacy = std::make_shared<std::vector<uint8_t>>(295, 0);
  memcpy(legacy->data() + 4, "legacy name", 12);
  float frequency = 912.525f;
  memcpy(legacy->data() + 72, &frequency, sizeof(frequency));
  fs._getFS()->files["/com_prefs"] = legacy;
  const auto before = *legacy;
  cli.loadPrefs(&fs);
  EXPECT_STREQ("legacy name", prefs.node_name);
  EXPECT_FLOAT_EQ(frequency, prefs.freq);
  EXPECT_FALSE(fs.exists("/prefs.json"));
  EXPECT_EQ(0, fs._getFS()->writes);
  EXPECT_EQ(0, fs._getFS()->removes);
  EXPECT_EQ(before, *legacy);

  callbacks.allowed = true;
  cli.loadPrefs(&fs);
  EXPECT_TRUE(fs.exists("/prefs.json"));
  EXPECT_GT(fs._getFS()->writes, 0);
  EXPECT_EQ(before, *legacy);
}

TEST_F(CommonCliWriteGuard, OrdinaryBootStillRunsSettersAndVariantHooks) {
  callbacks.allowed = true;
  EXPECT_EQ("OK", command("set name updated"));
  EXPECT_STREQ("updated", prefs.node_name);
  EXPECT_EQ(1u, callbacks.saves);
  EXPECT_EQ(1u, board.variant_commands);
  EXPECT_EQ("File system erase: OK", command("erase"));
  EXPECT_EQ(1u, callbacks.erases);
  EXPECT_TRUE(cli.savePrefs(&fs));
}

}  // namespace
