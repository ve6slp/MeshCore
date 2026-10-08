#include <gtest/gtest.h>
#include <algorithm>
#include <cstring>

#define FILESYSTEM Adafruit_LittleFS
#include "b_startup_mocks/Adafruit_LittleFS.h"
using namespace Adafruit_LittleFS_Namespace;
#include "b_startup_mocks/ExampleGlobals.h"
#include <helpers/ota/OtaTrialSafeIdentityBoot.h>
#include <helpers/ota/OtaTrialSafeFilesystemMount.h>

// Execute the actual example setup()/loop() bodies with injected peripherals.
#define MESHCORE_EXAMPLE_STARTUP_NATIVE 1
#define NRF52_PLATFORM 1
#define HAS_EXTERNAL_WATCHDOG 1
#define WIFI_DEBUG_PRINTLN(...) do {} while (0)
#define WIFI_SSID ""
#define WIFI_PWD ""
#define WIFI_RETRY_INTERVAL 0
#define TCP_PORT 5000

#undef MESHCORE_LORA_OTA
#define MESHCORE_LORA_OTA 0
#define ENABLE_WIFI_INTERFACE 1
namespace b_companion_off {
#include "b_startup_mocks/ExampleInstances.h"
#include "../../examples/companion_radio/main.cpp"
}
#undef MESHCORE_LORA_OTA
#define MESHCORE_LORA_OTA 1
namespace b_companion_on {
#include "b_startup_mocks/ExampleInstances.h"
#include "../../examples/companion_radio/main.cpp"
}
#undef ENABLE_WIFI_INTERFACE
#undef MESHCORE_LORA_OTA
#define MESHCORE_LORA_OTA 0
namespace b_repeater_off {
#include "b_startup_mocks/ExampleInstances.h"
#include "../../examples/simple_repeater/main.cpp"
}
#undef MESHCORE_LORA_OTA
#define MESHCORE_LORA_OTA 1
namespace b_repeater_on {
#include "b_startup_mocks/ExampleInstances.h"
#include "../../examples/simple_repeater/main.cpp"
}

TEST(BExampleStartupTest, CompanionOffSleepsExactlyOnceAtOrdinaryLoopPosition) {
  using namespace b_companion_off;
  reset();
  wifi_enabled = wifi_needs_reconnect = true;
  last_wifi_reconnect_attempt = 0;
  g_mock_millis = 10000;
  loop();
  EXPECT_EQ((std::vector<std::string>{"mesh", "interfaces", "sensors", "rtc", "board", "watchdog",
      "sleep", "wifi.disconnect", "wifi.reconnect"}), state.events);
}

TEST(BExampleStartupTest, CompanionOnSleepsExactlyOnceAfterAllServicesAndTrialTick) {
  using namespace b_companion_on;
  reset();
  wifi_enabled = wifi_needs_reconnect = true;
  last_wifi_reconnect_attempt = 0;
  g_mock_millis = 10000;
  loop();
  EXPECT_EQ((std::vector<std::string>{"mesh", "interfaces", "sensors", "rtc", "board", "watchdog",
      "wifi.disconnect", "wifi.reconnect", "trial", "sleep"}), state.events);
}

TEST(BExampleStartupTest, TrialTickCanInhibitSleepInTheSameCompanionPass) {
  using namespace b_companion_on;
  reset();
  wifi_enabled = false;
  state.trial_blocks_sleep = true;
  loop();
  EXPECT_EQ("trial", state.events.back());
  EXPECT_EQ(0, std::count(state.events.begin(), state.events.end(), "sleep"));
}

TEST(BExampleStartupTest, RepeaterOffRadioFailureHaltsBeforeRngStorageIdentityOrBootCompletion) {
  using namespace b_repeater_off;
  reset();
  state.radio_ok = false;
  EXPECT_THROW(setup(), b_example_fixture::Halt);
  EXPECT_FALSE(state.boot_complete);
  EXPECT_EQ(0, state.radio_seeds);
  EXPECT_EQ(0, state.generated);
  EXPECT_EQ(0, InternalFS._getFS()->mounts);
  EXPECT_EQ(0, InternalFS._getFS()->writes);
  EXPECT_FALSE(state.radio_unavailable);
}

TEST(BExampleStartupTest, RepeaterOnFailedRadioStillRunsMaintenanceWithRealFaultSignalsAndNoWrites) {
  using namespace b_repeater_on;
  reset();
  state.radio_ok = false;
  InternalFS._getFS()->mount_error = LFS_ERR_CORRUPT;
  setup();
  EXPECT_TRUE(state.boot_complete);
  EXPECT_TRUE(state.radio_unavailable);
  EXPECT_TRUE(state.identity_unavailable);
  EXPECT_TRUE(state.writes_disallowed);
  EXPECT_FALSE(state.health_radio);
  EXPECT_FALSE(state.health_fs);
  EXPECT_EQ(0, state.radio_seeds);
  EXPECT_EQ(0, state.generated);
  EXPECT_EQ(0, InternalFS._getFS()->formats);
  EXPECT_EQ(0, InternalFS._getFS()->writes);
  loop();
  EXPECT_NE(state.events.end(), std::find(state.events.begin(), state.events.end(), "trial"));
}

TEST(BExampleStartupTest, RepeaterOffAndOnKeepExactlyOneSleepAtTheFinalLoopPosition) {
  b_repeater_off::reset();
  b_repeater_off::loop();
  EXPECT_EQ((std::vector<std::string>{"board", "mesh", "sensors", "rtc", "watchdog", "sleep"}),
      b_repeater_off::state.events);
  b_repeater_on::reset();
  b_repeater_on::loop();
  EXPECT_EQ((std::vector<std::string>{"board", "mesh", "sensors", "rtc", "watchdog", "trial", "sleep"}),
      b_repeater_on::state.events);
}

TEST(BExampleStartupTest, FreshPairedNormalBootActuallyProvisionsCompanionAndRepeaterFromBlankStorage) {
  b_companion_on::reset();
  b_companion_on::InternalFS._getFS()->mount_error = LFS_ERR_CORRUPT;
  b_companion_on::setup();
  EXPECT_EQ(1, b_companion_on::InternalFS._getFS()->formats);
  EXPECT_EQ(1, b_companion_on::state.generated);
  EXPECT_TRUE(b_companion_on::state.generation_permitted);
  EXPECT_TRUE(b_companion_on::state.store_writable);
  EXPECT_FALSE(b_companion_on::state.store_format_permitted);
  EXPECT_TRUE(b_companion_on::state.boot_complete);
  IdentityStore companion_store(b_companion_on::InternalFS, "");
  mesh::LocalIdentity companion_identity;
  EXPECT_EQ(identity_io::LoadStatus::Loaded,
      companion_store.loadWithStatus("_main", companion_identity, true));

  b_repeater_on::reset();
  b_repeater_on::InternalFS._getFS()->mount_error = LFS_ERR_CORRUPT;
  b_repeater_on::setup();
  EXPECT_EQ(1, b_repeater_on::InternalFS._getFS()->formats);
  EXPECT_EQ(1, b_repeater_on::state.generated);
  EXPECT_TRUE(b_repeater_on::state.identity_confirmed);
  EXPECT_TRUE(b_repeater_on::state.boot_complete);
  IdentityStore repeater_store(b_repeater_on::InternalFS, "");
  mesh::LocalIdentity repeater_identity;
  EXPECT_EQ(identity_io::LoadStatus::Loaded,
      repeater_store.loadWithStatus("_main", repeater_identity, true));
}

TEST(BExampleStartupTest, TrialOrUnknownNeverEnablesDestructiveStartupAcrossEitherExample) {
  b_companion_on::reset();
  b_companion_on::state.normal_proven = false;
  b_companion_on::InternalFS._getFS()->mount_error = LFS_ERR_CORRUPT;
  b_companion_on::setup();
  EXPECT_FALSE(b_companion_on::state.generation_permitted);
  EXPECT_FALSE(b_companion_on::state.store_writable);
  EXPECT_EQ(0, b_companion_on::InternalFS._getFS()->formats);
  EXPECT_EQ(0, b_companion_on::InternalFS._getFS()->writes);
  EXPECT_EQ(0, b_companion_on::InternalFS._getFS()->mkdirs);
  EXPECT_EQ(0, b_companion_on::state.generated);

  b_repeater_on::reset();
  b_repeater_on::state.normal_proven = false;
  b_repeater_on::InternalFS._getFS()->mount_error = LFS_ERR_CORRUPT;
  b_repeater_on::setup();
  EXPECT_TRUE(b_repeater_on::state.writes_disallowed);
  EXPECT_EQ(0, b_repeater_on::InternalFS._getFS()->formats);
  EXPECT_EQ(0, b_repeater_on::InternalFS._getFS()->writes);
  EXPECT_EQ(0, b_repeater_on::state.generated);
}

TEST(BExampleStartupTest, IdentityIoFailureBlocksCompanionMigrationAndBothIdentityGenerationPaths) {
  b_companion_on::reset();
  b_companion_on::InternalFS._getFS()->stat_error = LFS_ERR_IO;
  b_companion_on::setup();
  EXPECT_FALSE(b_companion_on::state.store_writable);
  EXPECT_FALSE(b_companion_on::state.generation_permitted);
  EXPECT_EQ(0, b_companion_on::InternalFS._getFS()->mkdirs);
  EXPECT_EQ(0, b_companion_on::InternalFS._getFS()->writes);

  b_repeater_on::reset();
  b_repeater_on::InternalFS._getFS()->stat_error = LFS_ERR_IO;
  b_repeater_on::setup();
  EXPECT_TRUE(b_repeater_on::state.writes_disallowed);
  EXPECT_EQ(0, b_repeater_on::state.generated);
  EXPECT_EQ(0, b_repeater_on::InternalFS._getFS()->writes);
}

TEST(BExampleStartupTest, RadioStatusFaultAfterSuccessfulInitCannotGrantProvisioningOrFormatting) {
  b_companion_on::reset();
  b_companion_on::state.radio_healthy = false;
  b_companion_on::InternalFS._getFS()->mount_error = LFS_ERR_CORRUPT;
  b_companion_on::setup();
  EXPECT_FALSE(b_companion_on::state.health_radio);
  EXPECT_FALSE(b_companion_on::state.store_writable);
  EXPECT_FALSE(b_companion_on::state.generation_permitted);
  EXPECT_EQ(0, b_companion_on::InternalFS._getFS()->formats);
  EXPECT_EQ(0, b_companion_on::state.generated);

  b_repeater_on::reset();
  b_repeater_on::state.radio_healthy = false;
  b_repeater_on::InternalFS._getFS()->mount_error = LFS_ERR_CORRUPT;
  b_repeater_on::setup();
  EXPECT_FALSE(b_repeater_on::state.health_radio);
  EXPECT_TRUE(b_repeater_on::state.radio_unavailable);
  EXPECT_EQ(0, b_repeater_on::InternalFS._getFS()->formats);
  EXPECT_EQ(0, b_repeater_on::state.generated);
}

TEST(BExampleStartupTest, RepeaterFailedIdentitySaveCannotUseRamOnlyKeyOrWriteFurtherUserdata) {
  using namespace b_repeater_on;
  reset();
  InternalFS._getFS()->write_error = true;
  setup();
  EXPECT_EQ(1, state.generated);
  EXPECT_FALSE(state.identity_confirmed);
  EXPECT_TRUE(state.identity_unavailable);
  EXPECT_TRUE(state.writes_disallowed);
  EXPECT_TRUE(mesh::Utils::isZeroes(the_mesh.self_id.pub_key, PUB_KEY_SIZE));
}
