#include <gtest/gtest.h>
#include <cstring>

#define FILESYSTEM Adafruit_LittleFS
#include "b_startup_mocks/Adafruit_LittleFS.h"
using namespace Adafruit_LittleFS_Namespace;
#include "b_startup_mocks/ExampleGlobals.h"
#include <helpers/ota/OtaTrialSafeIdentityBoot.h>
#include <helpers/ota/OtaTrialSafeFilesystemMount.h>

#define MESHCORE_EXAMPLE_STARTUP_NATIVE 1
#define NRF52_PLATFORM 1
#undef MESHCORE_LORA_OTA
#define MESHCORE_LORA_OTA 0
#define MESHCORE_REPEATER_RELAY_PROFILE 1
namespace relay_startup {
#include "b_startup_mocks/ExampleInstances.h"
#include "../../examples/simple_repeater/main.cpp"

mesh::LocalIdentity seedIdentity() {
  InternalFS.Adafruit_LittleFS::begin();
  mesh::LocalIdentity id;
  uint8_t bytes[PRV_KEY_SIZE + PUB_KEY_SIZE];
  memset(bytes, 0x42, sizeof(bytes));
  id.readFrom(bytes, sizeof(bytes));
  IdentityStore persisted(InternalFS, "");
  EXPECT_TRUE(persisted.save("_main", id));
  return id;
}
}  // namespace relay_startup

TEST(RelayStartup, LoadsExistingInternalFsIdentityWithoutFormatGenerationOrAnyBootWrites) {
  using namespace relay_startup;
  reset();
  const auto id = seedIdentity();
  const auto files_before = InternalFS._getFS()->files;
  const int writes_before = InternalFS._getFS()->writes;
  const int removes_before = InternalFS._getFS()->removes;
  setup();
  EXPECT_EQ(0, state.preflights);  // No paired-role qualification or installer backend.
  EXPECT_EQ(0, state.generated);
  EXPECT_EQ(0, InternalFS._getFS()->formats);
  EXPECT_EQ(writes_before, InternalFS._getFS()->writes);
  EXPECT_EQ(removes_before, InternalFS._getFS()->removes);
  EXPECT_EQ(files_before, InternalFS._getFS()->files);
  EXPECT_TRUE(id.matches(the_mesh.self_id));
  EXPECT_FALSE(state.identity_unavailable);
  EXPECT_FALSE(state.writes_disallowed);  // Isolated preferences remain configurable.
  EXPECT_TRUE(state.boot_complete);
}

TEST(RelayStartup, MissingIdentityNeverGeneratesOrWritesAReplacement) {
  using namespace relay_startup;
  reset();
  setup();
  EXPECT_EQ(0, state.generated);
  EXPECT_EQ(0, InternalFS._getFS()->writes);
  EXPECT_EQ(0, InternalFS._getFS()->formats);
  EXPECT_TRUE(state.identity_unavailable);
  EXPECT_TRUE(state.writes_disallowed);
  EXPECT_TRUE(state.boot_complete);
}

TEST(RelayStartup, FailedMountDoesNotFormatOrMutatePersistedIdentity) {
  using namespace relay_startup;
  reset();
  seedIdentity();
  const auto files_before = InternalFS._getFS()->files;
  const int writes_before = InternalFS._getFS()->writes;
  InternalFS._getFS()->mount_error = LFS_ERR_CORRUPT;
  setup();
  EXPECT_EQ(0, state.generated);
  EXPECT_EQ(0, InternalFS._getFS()->formats);
  EXPECT_EQ(writes_before, InternalFS._getFS()->writes);
  EXPECT_EQ(files_before, InternalFS._getFS()->files);
  EXPECT_TRUE(state.identity_unavailable);
  EXPECT_TRUE(state.writes_disallowed);
}

TEST(RelayStartup, UnreadableOrShortIdentityNeverGeneratesOrOverwritesExistingKey) {
  using namespace relay_startup;
  for (bool short_read : {false, true}) {
    reset();
    seedIdentity();
    const auto files_before = InternalFS._getFS()->files;
    const int writes_before = InternalFS._getFS()->writes;
    if (short_read) InternalFS._getFS()->read_limit = 1;
    else InternalFS._getFS()->stat_error = LFS_ERR_IO;
    setup();
    EXPECT_EQ(0, state.generated);
    EXPECT_EQ(0, InternalFS._getFS()->formats);
    EXPECT_EQ(writes_before, InternalFS._getFS()->writes);
    EXPECT_EQ(files_before, InternalFS._getFS()->files);
    EXPECT_TRUE(state.identity_unavailable);
    EXPECT_TRUE(state.writes_disallowed);
  }
}

TEST(RelayStartup, RadioFailureRunsMaintenanceWithoutGeneratingOrWritingIdentity) {
  using namespace relay_startup;
  reset();
  seedIdentity();
  const int writes_before = InternalFS._getFS()->writes;
  state.radio_ok = false;
  setup();
  EXPECT_EQ(0, state.generated);
  EXPECT_EQ(0, state.radio_seeds);
  EXPECT_EQ(writes_before, InternalFS._getFS()->writes);
  EXPECT_TRUE(state.radio_unavailable);
  EXPECT_TRUE(state.writes_disallowed);
  EXPECT_TRUE(state.boot_complete);
}
