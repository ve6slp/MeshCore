#include <gtest/gtest.h>
#include <map>
#include <set>
#include <string>

class NativeFileSystem {
public:
  void mkdir(const char*) {}
};

#define FILESYSTEM NativeFileSystem
#include "helpers/CommonCLI.h"
#undef FILESYSTEM

#define XIAO_OTA_COMPILED_ROLE_ID 1
#include "../../examples/simple_repeater/RepeaterPrefs.h"
#undef XIAO_OTA_COMPILED_ROLE_ID

namespace {

class PrefsFilesystem {
public:
  std::map<std::string, std::string> files;
  std::set<std::string> unreadable;
  unsigned writes = 0;

  bool exists(const char* filename) const { return files.count(filename) != 0; }
};

class PrefsStream : public Stream {
  std::string& _bytes;
  size_t _position = 0;

  size_t printSigned(long long value) {
    return Print::print(std::to_string(value).c_str());
  }

  size_t printUnsigned(unsigned long long value) {
    return Print::print(std::to_string(value).c_str());
  }

public:
  explicit PrefsStream(std::string& bytes) : _bytes(bytes) {}
  int available() override { return _bytes.size() - _position; }
  int read() override { return available() ? static_cast<unsigned char>(_bytes[_position++]) : -1; }
  int peek() override { return available() ? static_cast<unsigned char>(_bytes[_position]) : -1; }
  size_t write(uint8_t byte) override { _bytes.push_back(byte); return 1; }
  size_t print(unsigned char value, int) override { return printUnsigned(value); }
  size_t print(int value, int) override { return printSigned(value); }
  size_t print(unsigned int value, int) override { return printUnsigned(value); }
  size_t print(long value, int) override { return printSigned(value); }
  size_t print(unsigned long value, int) override { return printUnsigned(value); }
  size_t print(long long value, int) override { return printSigned(value); }
  size_t print(unsigned long long value, int) override { return printUnsigned(value); }
  size_t print(double value, int precision = 2) override {
    char text[48];
    snprintf(text, sizeof(text), "%.*f", precision, value);
    return Print::print(text);
  }
};

std::string serialize(NodePrefs& prefs) {
  std::string bytes;
  PrefsStream output(bytes);
  EXPECT_TRUE(prefs.saveSerial(output));
  return bytes;
}

bool load(PrefsFilesystem& fs, const char* preferred, NodePrefs& prefs, const char*& selected) {
  selected = resolveRepeaterPrefsFilename(fs, preferred);
  auto file = fs.files.find(selected);
  if (file == fs.files.end() || fs.unreadable.count(selected)) return false;
  PrefsStream input(file->second);
  return prefs.loadSerial(input);
}

void save(PrefsFilesystem& fs, const char* selected, NodePrefs& prefs) {
  fs.files[selected] = serialize(prefs);
  ++fs.writes;
}

void setBenchPrefs(NodePrefs& prefs) {
  strcpy(prefs.node_name, "OTA-LAB-TARGET");
  strcpy(prefs.password, "fixture-admin");
  strcpy(prefs.guest_password, "fixture-guest");
  strcpy(prefs.owner_info, "fixture owner");
  strcpy(prefs.bridge_secret, "fixture-bridge");
  prefs.node_lat = 47.5;
  prefs.node_lon = -122.25;
  prefs.freq = 907.525;
  prefs.bw = 250;
  prefs.sf = 7;
  prefs.cr = 5;
  prefs.path_hash_mode = 2;
  prefs.tx_power_dbm = 17;
  prefs.airtime_factor = 1.5;
  prefs.rx_delay_base = 4;
  prefs.tx_delay_factor = 1.25;
  prefs.direct_tx_delay_factor = 0.5;
  prefs.advert_interval = 5;
  prefs.flood_advert_interval = 8;
  prefs.multi_acks = 1;
  prefs.flood_max = 42;
  prefs.flood_max_unscoped = 8;
  prefs.flood_max_advert = 4;
  prefs.interference_threshold = 10;
  prefs.agc_reset_interval = 2;
  prefs.bridge_enabled = 1;
  prefs.bridge_delay = 750;
  prefs.bridge_pkt_src = 1;
  prefs.bridge_baud = 9600;
  prefs.bridge_channel = 7;
  prefs.powersaving_enabled = 1;
  prefs.gps_enabled = 1;
  prefs.gps_interval = 180;
  prefs.advert_loc_policy = 2;
  prefs.adc_multiplier = 1.1;
  prefs.rx_boosted_gain = 1;
  prefs.radio_fem_rxgain = 1;
  prefs.radio_fem_txgain = 1;
  prefs.loop_detect = 2;
  prefs.cad_enabled = 1;
}

TEST(RepeaterPrefsMigration, OrdinarySerializedDataLoadsInNrfOtaWithoutWrites) {
  NodePrefs ordinary;
  setBenchPrefs(ordinary);
  PrefsFilesystem fs;
  save(fs, "/prefs.json", ordinary);
  fs.files["/_main.id"] = "opaque persisted identity";
  fs.files["/acl"] = "opaque persisted ACL";
  const auto before = fs.files;
  const auto writes_before = fs.writes;

  NodePrefs ota;
  strcpy(ota.node_name, "Xiao_nrf52 Repeater");
  ota.freq = 907.525;
  ota.bw = 62.5;
  ota.sf = 7;
  ota.cr = 5;
  const char* selected = nullptr;
  EXPECT_TRUE(load(fs, kRepeaterPrefsFilename, ota, selected));
  EXPECT_STREQ("/prefs.json", selected);
  EXPECT_STREQ("OTA-LAB-TARGET", ota.node_name);
  EXPECT_FLOAT_EQ(250, ota.bw);
  EXPECT_EQ(2, ota.path_hash_mode);
  EXPECT_FLOAT_EQ(ordinary.freq, ota.freq);
  EXPECT_EQ(7, ota.sf);
  EXPECT_EQ(5, ota.cr);
  EXPECT_EQ(serialize(ordinary), serialize(ota));
  EXPECT_EQ(before, fs.files);
  EXPECT_EQ(writes_before, fs.writes);
}

TEST(RepeaterPrefsMigration, OtaSaveAndRepeatedBootsReuseOrdinaryFile) {
  NodePrefs ordinary;
  setBenchPrefs(ordinary);
  PrefsFilesystem fs;
  save(fs, "/prefs.json", ordinary);
  NodePrefs ota;
  const char* selected = nullptr;
  ASSERT_TRUE(load(fs, kRepeaterPrefsFilename, ota, selected));
  ota.path_hash_mode = 1;
  strcpy(ota.node_name, "updated repeater");
  save(fs, selected, ota);
  EXPECT_EQ(1u, fs.files.size());
  EXPECT_FALSE(fs.exists("/repeater_prefs.json"));

  for (const char* preferred : {"/prefs.json", kRepeaterPrefsFilename}) {
    NodePrefs rebooted;
    ASSERT_TRUE(load(fs, preferred, rebooted, selected));
    EXPECT_STREQ("/prefs.json", selected);
    EXPECT_STREQ("updated repeater", rebooted.node_name);
    EXPECT_EQ(1, rebooted.path_hash_mode);
    EXPECT_EQ(serialize(ota), serialize(rebooted));
  }
}

TEST(RepeaterPrefsMigration, ExistingOtaFileWinsWithoutChangingEitherFile) {
  NodePrefs existing;
  setBenchPrefs(existing);
  PrefsFilesystem fs;
  save(fs, kRepeaterPrefsFilename, existing);
  fs.files["/prefs.json"] = "{name:\"stale ordinary\",radio:{bw:62.5,hash_mode:0}}";
  const auto before = fs.files;
  const auto writes_before = fs.writes;
  NodePrefs loaded;
  const char* selected = nullptr;
  ASSERT_TRUE(load(fs, kRepeaterPrefsFilename, loaded, selected));
  EXPECT_STREQ(kRepeaterPrefsFilename, selected);
  EXPECT_EQ(serialize(existing), serialize(loaded));
  EXPECT_EQ(before, fs.files);
  EXPECT_EQ(writes_before, fs.writes);
}

TEST(RepeaterPrefsMigration, UnreadableOtaFileDoesNotFallBackToStaleOrdinaryFile) {
  PrefsFilesystem fs;
  fs.files[kRepeaterPrefsFilename] = "{name:\"OTA\"}";
  fs.files["/prefs.json"] = "{name:\"stale ordinary\"}";
  fs.unreadable.insert(kRepeaterPrefsFilename);
  NodePrefs loaded;
  const char* selected = nullptr;
  EXPECT_FALSE(load(fs, kRepeaterPrefsFilename, loaded, selected));
  EXPECT_STREQ(kRepeaterPrefsFilename, selected);
  EXPECT_EQ(0u, fs.writes);
}

TEST(RepeaterPrefsMigration, MalformedOtaFileDoesNotFallBackToStaleOrdinaryFile) {
  PrefsFilesystem fs;
  fs.files[kRepeaterPrefsFilename] = "{name:";
  fs.files["/prefs.json"] = "{name:\"stale ordinary\"}";
  const auto before = fs.files;
  NodePrefs loaded;
  const char* selected = nullptr;
  EXPECT_FALSE(load(fs, kRepeaterPrefsFilename, loaded, selected));
  EXPECT_STREQ(kRepeaterPrefsFilename, selected);
  EXPECT_EQ(before, fs.files);
  EXPECT_EQ(0u, fs.writes);
}

TEST(RepeaterPrefsMigration, UnreadableOrdinaryFileRemainsSelectedWithoutWrites) {
  PrefsFilesystem fs;
  fs.files["/prefs.json"] = "{name:\"ordinary\"}";
  fs.unreadable.insert("/prefs.json");
  NodePrefs loaded;
  const char* selected = nullptr;
  EXPECT_FALSE(load(fs, kRepeaterPrefsFilename, loaded, selected));
  EXPECT_STREQ("/prefs.json", selected);
  EXPECT_EQ(1u, fs.files.size());
  EXPECT_EQ(0u, fs.writes);
}

TEST(RepeaterPrefsMigration, FreshFilesystemKeepsEachProfilesDefaultWithoutCreation) {
  PrefsFilesystem fs;
  EXPECT_STREQ("/repeater_prefs.json", resolveRepeaterPrefsFilename(fs));
  EXPECT_STREQ("/prefs.json", resolveRepeaterPrefsFilename(fs, "/prefs.json"));
  EXPECT_TRUE(fs.files.empty());
  EXPECT_EQ(0u, fs.writes);
}

TEST(RepeaterPrefsMigration, OrdinaryEspAndOtherProfilesKeepTheirExistingPath) {
  PrefsFilesystem fs;
  fs.files["/prefs.json"] = "{name:\"ordinary or ESP\",radio:{bw:250,hash_mode:2}}";
  fs.files[kRepeaterPrefsFilename] = "{name:\"unrelated role-specific file\"}";
  const auto before = fs.files;
  NodePrefs loaded;
  const char* selected = nullptr;
  ASSERT_TRUE(load(fs, "/prefs.json", loaded, selected));
  EXPECT_STREQ("/prefs.json", selected);
  EXPECT_STREQ("ordinary or ESP", loaded.node_name);
  EXPECT_FLOAT_EQ(250, loaded.bw);
  EXPECT_EQ(2, loaded.path_hash_mode);
  EXPECT_EQ(before, fs.files);
  EXPECT_EQ(0u, fs.writes);
}

}  // namespace
