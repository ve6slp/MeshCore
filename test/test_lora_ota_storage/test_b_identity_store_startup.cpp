#include <gtest/gtest.h>
#include <cstring>
#include <vector>

#define STM32_PLATFORM 1
#include "b_startup_mocks/Adafruit_LittleFS.h"
#define FILESYSTEM Adafruit_LittleFS
using namespace Adafruit_LittleFS_Namespace;
#include "helpers/IdentityStore.h"
#include "helpers/ContactInfo.h"
#include "helpers/ota/OtaTrialSafeIdentityBoot.h"
#include "helpers/ota/OtaTrialSafeFilesystemMount.h"
#include "../../src/helpers/IdentityStore.cpp"
#undef STM32_PLATFORM

// IdentityStore's filesystem/status decisions are real production code.
// Crypto is outside this fixture; these DTO methods supply its stream dependency.
namespace mesh {
Identity::Identity() { memset(pub_key, 0, sizeof(pub_key)); }
LocalIdentity::LocalIdentity() { memset(prv_key, 0, sizeof(prv_key)); }
bool LocalIdentity::readFrom(Stream& s) {
  return s.readBytes(pub_key, PUB_KEY_SIZE) == PUB_KEY_SIZE &&
         s.readBytes(prv_key, PRV_KEY_SIZE) == PRV_KEY_SIZE;
}
bool LocalIdentity::writeTo(Stream& s) const {
  return s.write(pub_key, PUB_KEY_SIZE) == PUB_KEY_SIZE &&
         s.write(prv_key, PRV_KEY_SIZE) == PRV_KEY_SIZE;
}
size_t LocalIdentity::writeTo(uint8_t* bytes, size_t size) {
  if (size < PUB_KEY_SIZE + PRV_KEY_SIZE) return 0;
  memcpy(bytes, prv_key, PRV_KEY_SIZE);
  memcpy(bytes + PRV_KEY_SIZE, pub_key, PUB_KEY_SIZE);
  return PUB_KEY_SIZE + PRV_KEY_SIZE;
}
void LocalIdentity::readFrom(const uint8_t* bytes, size_t size) {
  if (size != PUB_KEY_SIZE + PRV_KEY_SIZE) return;
  memcpy(prv_key, bytes, PRV_KEY_SIZE);
  memcpy(pub_key, bytes + PRV_KEY_SIZE, PUB_KEY_SIZE);
}
}  // namespace mesh

namespace {

void seedIdentity(Adafruit_LittleFS& fs, uint8_t fill = 0x42) {
  fs._getFS()->files["/_main.id"] =
      std::make_shared<std::vector<uint8_t>>(PUB_KEY_SIZE + PRV_KEY_SIZE, fill);
}

struct StartupResult {
  bool mounted;
  identity_io::LoadStatus status;
  ota_identity_boot::Outcome outcome;
  int generated;
};

StartupResult provision(InternalFileSystem& fs, bool normal_proven, bool radio_ok) {
  const bool mounted = ota_fs_mount::mountTrialSafe(normal_proven && radio_ok,
      [&](){ return fs.Adafruit_LittleFS::begin(); }, [&](){ return fs.begin(); });
  IdentityStore store(fs, "");
  mesh::LocalIdentity identity;
  const auto status = store.loadWithStatus("_main", identity, mounted);
  int generated = 0;
  const auto outcome = ota_identity_boot::resolveIdentityTrialSafe(
      identity_io::canProvisionIdentity(normal_proven, radio_ok, mounted, status),
      [&](){ return status == identity_io::LoadStatus::Loaded; },
      [&](){
        ++generated;
        uint8_t bytes[PUB_KEY_SIZE + PRV_KEY_SIZE];
        memset(bytes, 0x42, sizeof(bytes));
        identity.readFrom(bytes, sizeof(bytes));
      },
      [&](){ return store.save("_main", identity); });
  return {mounted, status, outcome, generated};
}

}  // namespace

TEST(BIdentityStoreStartupTest, FreshNormalMountFailureFormatsThenProvisionsReloadableIdentity) {
  InternalFileSystem fs;
  fs._getFS()->mount_error = LFS_ERR_CORRUPT;
  const auto result = provision(fs, true, true);
  EXPECT_TRUE(result.mounted);
  EXPECT_EQ(identity_io::LoadStatus::Absent, result.status);
  EXPECT_EQ(ota_identity_boot::Outcome::GeneratedAndSaved, result.outcome);
  EXPECT_EQ(1, result.generated);
  EXPECT_EQ(1, fs._getFS()->formats);
  IdentityStore store(fs, "");
  mesh::LocalIdentity reloaded;
  EXPECT_EQ(identity_io::LoadStatus::Loaded, store.loadWithStatus("_main", reloaded, true));
  EXPECT_EQ(0x42, reloaded.pub_key[0]);
  EXPECT_TRUE(store.checkIntegrity("_main", reloaded));
}

TEST(BIdentityStoreStartupTest, ExistingNormalIdentityNeverFormatsOrGenerates) {
  InternalFileSystem fs;
  seedIdentity(fs);
  const auto result = provision(fs, true, true);
  EXPECT_EQ(ota_identity_boot::Outcome::LoadedExisting, result.outcome);
  EXPECT_EQ(0, result.generated);
  EXPECT_EQ(0, fs._getFS()->formats);
  EXPECT_EQ(0, fs._getFS()->writes);
  EXPECT_EQ(0, fs._getFS()->removes);
}

TEST(BIdentityStoreStartupTest, TrialAndUnknownNeverFormatGenerateOrReplaceEvenOnMountFailure) {
  for (int error : {0, LFS_ERR_CORRUPT, LFS_ERR_IO}) {
    InternalFileSystem fs;
    seedIdentity(fs);
    fs._getFS()->mount_error = error;
    const auto before = *fs._getFS()->files.at("/_main.id");
    const auto result = provision(fs, false, true);
    EXPECT_EQ(0, result.generated);
    EXPECT_EQ(0, fs._getFS()->formats);
    EXPECT_EQ(0, fs._getFS()->writes);
    EXPECT_EQ(0, fs._getFS()->removes);
    EXPECT_EQ(before, *fs._getFS()->files.at("/_main.id"));
  }
}

TEST(BIdentityStoreStartupTest, StatIoErrorIsNotAbsenceAndCannotGenerate) {
  InternalFileSystem fs;
  fs._getFS()->stat_error = LFS_ERR_IO;
  const auto result = provision(fs, true, true);
  EXPECT_EQ(identity_io::LoadStatus::Unreadable, result.status);
  EXPECT_EQ(ota_identity_boot::Outcome::IdentityUnavailable, result.outcome);
  EXPECT_EQ(0, result.generated);
  EXPECT_FALSE(identity_io::canWriteUserdata(true, true, result.status));
  EXPECT_EQ(0, fs._getFS()->writes);
  EXPECT_EQ(0, fs._getFS()->removes);
}

TEST(BIdentityStoreStartupTest, OpenFailureAndShortReadNeverReplaceExistingKeyOrPartiallyLoadRam) {
  for (bool open_error : {false, true}) {
    InternalFileSystem fs;
    seedIdentity(fs);
    fs.begin();
    fs._getFS()->open_error = open_error;
    fs._getFS()->read_limit = open_error ? SIZE_MAX : PUB_KEY_SIZE + 3;
    IdentityStore store(fs, "");
    mesh::LocalIdentity identity;
    memset(identity.pub_key, 0x55, sizeof(identity.pub_key));
    const auto status = store.loadWithStatus("_main", identity, true);
    EXPECT_EQ(identity_io::LoadStatus::Unreadable, status);
    EXPECT_EQ(0x55, identity.pub_key[0]);
    EXPECT_FALSE(identity_io::canProvisionIdentity(true, true, true, status));
    EXPECT_EQ(0, fs._getFS()->writes);
    EXPECT_EQ(0, fs._getFS()->removes);
  }
}

TEST(BIdentityStoreStartupTest, FailedRadioCannotProvisionOrFormatBlankNormalFilesystem) {
  InternalFileSystem fs;
  fs._getFS()->mount_error = LFS_ERR_CORRUPT;
  const auto result = provision(fs, true, false);
  EXPECT_EQ(0, result.generated);
  EXPECT_EQ(0, fs._getFS()->formats);
  EXPECT_EQ(0, fs._getFS()->writes);
  EXPECT_EQ(0, fs._getFS()->removes);
}

TEST(BIdentityStoreStartupTest, UnmountedFilesystemNeverEvenStatsAnIdentity) {
  InternalFileSystem fs;
  IdentityStore store(fs, "");
  mesh::LocalIdentity identity;
  EXPECT_EQ(identity_io::LoadStatus::Unavailable, store.loadWithStatus("_main", identity, false));
  EXPECT_EQ(0, fs._getFS()->stats);
}

TEST(BContactPermissionTest, PublicCliAndPrivateOtaGrantsAndRevocationsAreIndependent) {
  ContactInfo contact;
  contact.flags = 0x1F;
  EXPECT_TRUE(contact.isRemoteCLIAllowed());
  EXPECT_FALSE(contact.isOtaAdmin());
  contact.setOtaAdmin(true);
  EXPECT_EQ(0x1F, contact.flags);
  EXPECT_TRUE(contact.isOtaAdmin());
  contact.flags = 0x0F;  // the public app's flags update/revocation
  EXPECT_FALSE(contact.isRemoteCLIAllowed());
  EXPECT_TRUE(contact.isOtaAdmin());
  contact.setOtaAdmin(false);
  EXPECT_EQ(0x0F, contact.flags);
  EXPECT_FALSE(contact.isOtaAdmin());
  contact.setOtaAdmin(true);
  EXPECT_FALSE(contact.isRemoteCLIAllowed());
}

TEST(BIdentityStoreStartupTest, MigrationNeverDeletesOriginalOrReplacesPrimaryAfterStagingFailure) {
  for (int fault : {0, 1, 2}) {
    InternalFileSystem primary, secondary;
    primary.begin();
    secondary.begin();
    seedIdentity(primary, 0x55);
    seedIdentity(secondary, 0x42);
    IdentityStore target(primary, ""), source(secondary, "");
    mesh::LocalIdentity migrating;
    ASSERT_EQ(identity_io::LoadStatus::Loaded, source.loadWithStatus("_main", migrating, true));
    primary._getFS()->write_error = fault == 0;
    primary._getFS()->read_limit = fault == 1 ? PUB_KEY_SIZE : SIZE_MAX;
    primary._getFS()->rename_error = fault == 2;
    EXPECT_FALSE(identity_io::migrateIdentityChecked(
        [&](){ return target.save("_main_migrate", migrating); },
        [&](){ return target.checkIntegrity("_main_migrate", migrating); },
        [&](){ return primary.rename("/_main_migrate.id", "/_main.id"); },
        [&](){ return target.checkIntegrity("_main", migrating); },
        [&](){ return secondary.remove("/_main.id"); }));
    EXPECT_EQ(0x55, primary._getFS()->files.at("/_main.id")->at(0));
    EXPECT_EQ(0x42, secondary._getFS()->files.at("/_main.id")->at(0));
    EXPECT_EQ(0, secondary._getFS()->removes);
  }
}

TEST(BIdentityStoreStartupTest, MigrationOnlyRetiresSecondaryAfterPersistedPrimaryMatchesIt) {
  InternalFileSystem primary, secondary;
  primary.begin();
  secondary.begin();
  seedIdentity(primary, 0x55);
  seedIdentity(secondary, 0x42);
  IdentityStore target(primary, ""), source(secondary, "");
  mesh::LocalIdentity migrating;
  ASSERT_EQ(identity_io::LoadStatus::Loaded, source.loadWithStatus("_main", migrating, true));
  EXPECT_TRUE(identity_io::migrateIdentityChecked(
      [&](){ return target.save("_main_migrate", migrating); },
      [&](){ return target.checkIntegrity("_main_migrate", migrating); },
      [&](){ return primary.rename("/_main_migrate.id", "/_main.id"); },
      [&](){ return target.checkIntegrity("_main", migrating); },
      [&](){ return secondary.remove("/_main.id"); }));
  EXPECT_EQ(0x42, primary._getFS()->files.at("/_main.id")->at(0));
  EXPECT_EQ(0u, secondary._getFS()->files.count("/_main.id"));
  EXPECT_EQ(1, secondary._getFS()->removes);
}
