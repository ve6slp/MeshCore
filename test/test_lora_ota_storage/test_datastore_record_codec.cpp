// Native, production-code coverage for datastore_io::writeAllContacts()/
// writeAllChannels() (see examples/companion_radio/DataStoreRecordCodec.h)
// -- the EXACT SAME templated write-order/stop-on-first-short-write
// algorithm production DataStore::saveContacts()/saveChannels() call,
// driven here against a plain byte-backed fake File and a POD fake
// record type (never `ContactInfo`/`mesh::Identity`, so no
// Identity.cpp/Ed25519 linkage is needed in the native test build) with
// the identical field layout so the SAME memory offsets/write order are
// genuinely exercised, not a second hand-rolled reimplementation.
#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>
#include <vector>

#include "../../examples/companion_radio/DataStoreRecordCodec.h"

namespace {

// Byte-for-byte layout-compatible stand-in for the real production
// ContactInfo: same field names/sizes/order the codec touches, but with
// a raw `pub_key` array nested the same way `mesh::Identity id` exposes
// its own `pub_key` member (`c.id.pub_key`), so writeAllContacts() needs
// zero special-casing to accept it.
struct FakePubKeyHolder {
  uint8_t pub_key[32];
};

struct FakeContactRecord {
  FakePubKeyHolder id;
  char name[32];
  uint8_t type;
  uint8_t flags;
  uint8_t out_path_len;
  uint8_t out_path[64];
  uint32_t last_advert_timestamp;
  uint32_t lastmod;
  int32_t gps_lat, gps_lon;
  uint32_t sync_since;
};

struct FakeChannelRecord {
  struct {
    uint8_t secret[32];
  } channel;
  char name[32];
};

// A plain byte-backed fake "File": records every write() call and can be
// configured to report a short write after N bytes have been accepted
// across the whole session, to exercise the "stop at first short/failed
// write" behavior without needing any real filesystem.
class FakeCodecFile {
public:
  explicit FakeCodecFile(long fail_after_bytes = -1) : _fail_after_bytes(fail_after_bytes) {}

  size_t write(const uint8_t* data, size_t len) {
    if (_fail_after_bytes >= 0 && _written_total >= (size_t)_fail_after_bytes) {
      return 0;  // simulates a genuine short/failed write.
    }
    size_t actually = len;
    if (_fail_after_bytes >= 0 && _written_total + len > (size_t)_fail_after_bytes) {
      actually = (size_t)_fail_after_bytes - _written_total;  // partial write then fault
    }
    _bytes.insert(_bytes.end(), data, data + actually);
    _written_total += actually;
    return actually;
  }

  const std::vector<uint8_t>& bytes() const { return _bytes; }

private:
  long _fail_after_bytes;
  size_t _written_total = 0;
  std::vector<uint8_t> _bytes;
};

// Fake host yielding a fixed list of contacts/channels, mirroring the
// real DataStoreHost::getContactForSave()/getChannelForSave() contract
// (index-based, returns false once past the end).
class FakeContactHost {
public:
  explicit FakeContactHost(std::vector<FakeContactRecord> contacts) : _contacts(std::move(contacts)) {}

  bool getContactForSave(uint32_t idx, FakeContactRecord& out) {
    if (idx >= _contacts.size()) return false;
    out = _contacts[idx];
    return true;
  }

private:
  std::vector<FakeContactRecord> _contacts;
};

class FakeChannelHost {
public:
  explicit FakeChannelHost(std::vector<FakeChannelRecord> channels) : _channels(std::move(channels)) {}

  bool getChannelForSave(uint8_t idx, FakeChannelRecord& out) {
    if (idx >= _channels.size()) return false;
    out = _channels[idx];
    return true;
  }

private:
  std::vector<FakeChannelRecord> _channels;
};

FakeContactRecord makeContact(uint8_t fill) {
  FakeContactRecord c;
  memset(&c, fill, sizeof(c));
  c.out_path_len = 3;  // arbitrary, distinguishable field value
  return c;
}

FakeChannelRecord makeChannel(uint8_t fill) {
  FakeChannelRecord ch;
  memset(&ch, fill, sizeof(ch));
  return ch;
}

// One real contact record's exact on-disk byte size, per writeAllContacts()'s
// own field-by-field write order: 32(pub_key) + 32(name) + 1(type) +
// 1(flags) + 1(unused) + 4(sync_since) + 1(out_path_len) +
// 4(last_advert_timestamp) + 64(out_path) + 4(lastmod) + 4(gps_lat) + 4(gps_lon)
constexpr size_t kContactRecordBytes = 32 + 32 + 1 + 1 + 1 + 4 + 1 + 4 + 64 + 4 + 4 + 4;
// One real channel record's exact on-disk byte size: 4(unused) + 32(name) + 32(secret)
constexpr size_t kChannelRecordBytes = 4 + 32 + 32;

}  // namespace

TEST(DataStoreRecordCodecTest, WriteAllContactsEmptyHostSucceedsWithNoBytesWritten) {
  FakeContactHost host({});
  FakeCodecFile file;
  bool (*filter)(const FakeContactRecord&) = nullptr;
  EXPECT_TRUE((datastore_io::writeAllContacts<FakeCodecFile, FakeContactHost, decltype(filter), FakeContactRecord>(file, &host, filter)));
  EXPECT_EQ(0u, file.bytes().size());
}

TEST(DataStoreRecordCodecTest, WriteAllContactsWritesEveryRecordInFieldOrder) {
  FakeContactHost host({makeContact(0x11), makeContact(0x22)});
  FakeCodecFile file;
  bool (*filter)(const FakeContactRecord&) = nullptr;
  ASSERT_TRUE((datastore_io::writeAllContacts<FakeCodecFile, FakeContactHost, decltype(filter), FakeContactRecord>(file, &host, filter)));
  EXPECT_EQ(kContactRecordBytes * 2, file.bytes().size());
  // First record's pub_key bytes (first 32 bytes on disk) match the fill value.
  EXPECT_EQ(0x11, file.bytes()[0]);
  EXPECT_EQ(0x22, file.bytes()[kContactRecordBytes]);
}

TEST(DataStoreRecordCodecTest, WriteAllContactsHonorsFilterSkippingRejectedRecords) {
  FakeContactHost host({makeContact(0x11), makeContact(0x22)});
  FakeCodecFile file;
  bool (*filter)(const FakeContactRecord&) = [](const FakeContactRecord& c) { return c.id.pub_key[0] != 0x11; };
  ASSERT_TRUE((datastore_io::writeAllContacts<FakeCodecFile, FakeContactHost, decltype(filter), FakeContactRecord>(file, &host, filter)));
  EXPECT_EQ(kContactRecordBytes, file.bytes().size());  // only the 0x22 record was written
  EXPECT_EQ(0x22, file.bytes()[0]);
}

TEST(DataStoreRecordCodecTest, WriteAllContactsStopsAtFirstShortWrite) {
  FakeContactHost host({makeContact(0x11), makeContact(0x22)});
  // Fail partway through the FIRST record's writes.
  FakeCodecFile file(/*fail_after_bytes=*/10);
  bool (*filter)(const FakeContactRecord&) = nullptr;
  EXPECT_FALSE((datastore_io::writeAllContacts<FakeCodecFile, FakeContactHost, decltype(filter), FakeContactRecord>(file, &host, filter)));
  EXPECT_LT(file.bytes().size(), kContactRecordBytes * 2);  // never reached the second record fully
}

TEST(DataStoreRecordCodecTest, WriteAllChannelsWritesEveryRecordInFieldOrder) {
  FakeChannelHost host({makeChannel(0x33), makeChannel(0x44)});
  FakeCodecFile file;
  ASSERT_TRUE((datastore_io::writeAllChannels<FakeCodecFile, FakeChannelHost, FakeChannelRecord>(file, &host)));
  EXPECT_EQ(kChannelRecordBytes * 2, file.bytes().size());
  // First 4 bytes of each record are the "unused" padding (always zero),
  // then name (index 4) carries the fill value.
  EXPECT_EQ(0, file.bytes()[0]);
  EXPECT_EQ(0x33, file.bytes()[4]);
  EXPECT_EQ(0x44, file.bytes()[kChannelRecordBytes + 4]);
}

TEST(DataStoreRecordCodecTest, WriteAllChannelsStopsAtFirstShortWrite) {
  FakeChannelHost host({makeChannel(0x33), makeChannel(0x44)});
  FakeCodecFile file(/*fail_after_bytes=*/2);
  EXPECT_FALSE((datastore_io::writeAllChannels<FakeCodecFile, FakeChannelHost, FakeChannelRecord>(file, &host)));
  EXPECT_LT(file.bytes().size(), kChannelRecordBytes * 2);
}

namespace {

// A plain byte-backed fake "File" for READS: serves bytes from a fixed
// buffer, and can be configured to return a genuine SHORT read (fewer
// bytes than requested, but not zero) starting at a specific absolute
// byte offset -- simulating a real mid-record truncation/corruption/IO
// fault, distinct from a clean end-of-file (running out of buffered
// bytes entirely, which legitimately returns 0 once the buffer is
// exhausted).
class FakeCodecReadFile {
public:
  explicit FakeCodecReadFile(std::vector<uint8_t> data, long corrupt_at_byte = -1, long force_ioerr_zero_at_byte = -1)
    : _data(std::move(data)), _corrupt_at_byte(corrupt_at_byte), _force_ioerr_zero_at_byte(force_ioerr_zero_at_byte) {}

  size_t read(uint8_t* dest, size_t len) {
    // Simulates a real File implementation's read() genuinely returning
    // 0 due to an I/O error, WITHOUT actually being at the true logical
    // end of the file (position() < size() stays true) -- the exact
    // ambiguity readAllContacts()/readAllChannels() must resolve via
    // position()/size() provenance rather than trusting a bare 0 return.
    if (_force_ioerr_zero_at_byte >= 0 && _pos == (size_t)_force_ioerr_zero_at_byte) {
      return 0;
    }
    size_t remaining = (_pos < _data.size()) ? (_data.size() - _pos) : 0;
    size_t avail = (len < remaining) ? len : remaining;
    if (_corrupt_at_byte >= 0 && _pos < (size_t)_corrupt_at_byte &&
        _pos + avail > (size_t)_corrupt_at_byte) {
      avail = (size_t)_corrupt_at_byte - _pos;  // genuine short read: stop mid-record.
    }
    if (avail > 0) memcpy(dest, _data.data() + _pos, avail);
    _pos += avail;
    return avail;
  }

  uint32_t position() const { return (uint32_t)_pos; }
  uint32_t size() const { return (uint32_t)_data.size(); }

private:
  std::vector<uint8_t> _data;
  size_t _pos = 0;
  long _corrupt_at_byte;
  long _force_ioerr_zero_at_byte;
};

// Fake hosts for the READ direction: record every delivered record, and
// (for the contact host) can be configured to report the in-RAM table
// as "full" after N records, mirroring the real addContact() rejecting
// further records once out of space (NOT a fault).
class FakeContactLoadHost {
public:
  explicit FakeContactLoadHost(int accept_at_most = -1) : _accept_at_most(accept_at_most) {}
  bool onContactLoaded(const FakeContactRecord& c) {
    if (_accept_at_most >= 0 && (int)_loaded.size() >= _accept_at_most) return false;
    _loaded.push_back(c);
    return true;
  }
  const std::vector<FakeContactRecord>& loaded() const { return _loaded; }

private:
  int _accept_at_most;
  std::vector<FakeContactRecord> _loaded;
};

class FakeChannelLoadHost {
public:
  bool onChannelLoaded(uint8_t idx, const FakeChannelRecord& ch) {
    _loaded.push_back(ch);
    return true;
  }
  const std::vector<FakeChannelRecord>& loaded() const { return _loaded; }

private:
  std::vector<FakeChannelRecord> _loaded;
};

// Serializes one contact/channel record using the SAME production write
// order (via writeAllContacts()/writeAllChannels() against a temporary
// FakeCodecFile, single-record host) so the read-side tests exercise
// genuinely production-shaped bytes, not a second hand-rolled encoding.
std::vector<uint8_t> encodeContacts(const std::vector<FakeContactRecord>& contacts) {
  FakeContactHost host(contacts);
  FakeCodecFile file;
  bool (*filter)(const FakeContactRecord&) = nullptr;
  EXPECT_TRUE((datastore_io::writeAllContacts<FakeCodecFile, FakeContactHost, decltype(filter), FakeContactRecord>(file, &host, filter)));
  return file.bytes();
}

std::vector<uint8_t> encodeChannels(const std::vector<FakeChannelRecord>& channels) {
  FakeChannelHost host(channels);
  FakeCodecFile file;
  EXPECT_TRUE((datastore_io::writeAllChannels<FakeCodecFile, FakeChannelHost, FakeChannelRecord>(file, &host)));
  return file.bytes();
}

}  // namespace

TEST(DataStoreRecordCodecTest, ReadAllContactsCleanEmptyFileIsHealthyWithNoRecords) {
  FakeCodecReadFile file({});
  FakeContactLoadHost host;
  EXPECT_TRUE((datastore_io::readAllContacts<FakeCodecReadFile, FakeContactLoadHost, FakeContactRecord>(file, &host)));
  EXPECT_EQ(0u, host.loaded().size());
}

TEST(DataStoreRecordCodecTest, ReadAllContactsCleanEofAfterCompleteRecordsIsHealthy) {
  std::vector<uint8_t> bytes = encodeContacts({makeContact(0x11), makeContact(0x22)});
  FakeCodecReadFile file(bytes);
  FakeContactLoadHost host;
  EXPECT_TRUE((datastore_io::readAllContacts<FakeCodecReadFile, FakeContactLoadHost, FakeContactRecord>(file, &host)));
  ASSERT_EQ(2u, host.loaded().size());
  EXPECT_EQ(0x11, host.loaded()[0].id.pub_key[0]);
  EXPECT_EQ(0x22, host.loaded()[1].id.pub_key[0]);
}

TEST(DataStoreRecordCodecTest, ReadAllContactsPartialFirstFieldIsGenuineFaultNotEof) {
  // Truncated mid-way through the FIRST record's pub_key field (10 of 32
  // bytes) -- this must NOT be silently treated as a clean end-of-file.
  std::vector<uint8_t> bytes = encodeContacts({makeContact(0x11)});
  bytes.resize(10);
  FakeCodecReadFile file(bytes);
  FakeContactLoadHost host;
  EXPECT_FALSE((datastore_io::readAllContacts<FakeCodecReadFile, FakeContactLoadHost, FakeContactRecord>(file, &host)));
  EXPECT_EQ(0u, host.loaded().size());  // no partial record ever delivered to the host
}

TEST(DataStoreRecordCodecTest, ReadAllContactsPartialLaterFieldAfterGoodRecordIsGenuineFault) {
  // First record is completely valid; the SECOND record is truncated
  // partway through a later field (after pub_key+name, before type) --
  // a genuine fault distinct from clean EOF, and the already-good first
  // record must still have been delivered.
  std::vector<uint8_t> bytes = encodeContacts({makeContact(0x11), makeContact(0x22)});
  bytes.resize(kContactRecordBytes + 32 + 32 + 0);  // cut right after 2nd record's name field
  FakeCodecReadFile file(bytes);
  FakeContactLoadHost host;
  EXPECT_FALSE((datastore_io::readAllContacts<FakeCodecReadFile, FakeContactLoadHost, FakeContactRecord>(file, &host)));
  ASSERT_EQ(1u, host.loaded().size());  // first, genuinely complete record was still delivered
  EXPECT_EQ(0x11, host.loaded()[0].id.pub_key[0]);
}

TEST(DataStoreRecordCodecTest, ReadAllContactsStopsCleanlyWhenHostTableIsFull) {
  // The host rejecting a record because its own in-RAM table is full is
  // NOT a fault -- readAllContacts() must report healthy.
  std::vector<uint8_t> bytes = encodeContacts({makeContact(0x11), makeContact(0x22)});
  FakeCodecReadFile file(bytes);
  FakeContactLoadHost host(/*accept_at_most=*/1);
  EXPECT_TRUE((datastore_io::readAllContacts<FakeCodecReadFile, FakeContactLoadHost, FakeContactRecord>(file, &host)));
  EXPECT_EQ(1u, host.loaded().size());
}

TEST(DataStoreRecordCodecTest, ReadAllChannelsCleanEofAfterCompleteRecordsIsHealthy) {
  std::vector<uint8_t> bytes = encodeChannels({makeChannel(0x33), makeChannel(0x44)});
  FakeCodecReadFile file(bytes);
  FakeChannelLoadHost host;
  uint8_t next_idx = 0;
  EXPECT_TRUE((datastore_io::readAllChannels<FakeCodecReadFile, FakeChannelLoadHost, FakeChannelRecord>(file, &host, next_idx)));
  ASSERT_EQ(2u, host.loaded().size());
  EXPECT_EQ(2, next_idx);
  EXPECT_EQ(0x33, host.loaded()[0].name[0]);
  EXPECT_EQ(0x44, host.loaded()[1].name[0]);
}

TEST(DataStoreRecordCodecTest, ReadAllChannelsPartialFirstFieldIsGenuineFaultNotEof) {
  std::vector<uint8_t> bytes = encodeChannels({makeChannel(0x33)});
  bytes.resize(2);  // truncated mid-way through the 4-byte "unused" field
  FakeCodecReadFile file(bytes);
  FakeChannelLoadHost host;
  uint8_t next_idx = 0;
  EXPECT_FALSE((datastore_io::readAllChannels<FakeCodecReadFile, FakeChannelLoadHost, FakeChannelRecord>(file, &host, next_idx)));
  EXPECT_EQ(0u, host.loaded().size());
  EXPECT_EQ(0, next_idx);
}

TEST(DataStoreRecordCodecTest, ReadAllChannelsPartialLaterFieldAfterGoodRecordIsGenuineFault) {
  std::vector<uint8_t> bytes = encodeChannels({makeChannel(0x33), makeChannel(0x44)});
  bytes.resize(kChannelRecordBytes + 4 + 16);  // cut mid-way through 2nd record's name field
  FakeCodecReadFile file(bytes);
  FakeChannelLoadHost host;
  uint8_t next_idx = 0;
  EXPECT_FALSE((datastore_io::readAllChannels<FakeCodecReadFile, FakeChannelLoadHost, FakeChannelRecord>(file, &host, next_idx)));
  ASSERT_EQ(1u, host.loaded().size());
  EXPECT_EQ(1, next_idx);
  EXPECT_EQ(0x33, host.loaded()[0].name[0]);
}

// ---------------------------------------------------------------------
// The EOF-vs-genuine-I/O-error ambiguity: a real File::read() can
// legitimately return 0 bytes for TWO entirely different reasons -- the
// file is genuinely, logically at its end (true EOF), OR an underlying
// I/O error occurred while bytes still genuinely remain. Blindly
// treating every 0-byte read as EOF (the bug MAIN identified) would
// silently discard every remaining on-disk contact/channel while still
// reporting overall success. readAllContacts()/readAllChannels() must
// consult the file's own position()/size() provenance to resolve this,
// never trust the bare 0 return alone.
// ---------------------------------------------------------------------

TEST(DataStoreRecordCodecTest, ReadAllContactsZeroReadWhileDataGenuinelyRemainsOnFirstFieldIsFaultNotEof) {
  // Two genuine on-disk records, but the SECOND record's first field
  // read returns 0 (simulated I/O error) while position() < size() --
  // real bytes for that second record are still genuinely present on
  // disk. Must be reported as a fault, not silently accepted as "no
  // more records", and the first, already-good record must still have
  // been delivered.
  std::vector<uint8_t> bytes = encodeContacts({makeContact(0x11), makeContact(0x22)});
  FakeCodecReadFile file(bytes, /*corrupt_at_byte=*/-1, /*force_ioerr_zero_at_byte=*/(long)kContactRecordBytes);
  FakeContactLoadHost host;
  EXPECT_FALSE((datastore_io::readAllContacts<FakeCodecReadFile, FakeContactLoadHost, FakeContactRecord>(file, &host)));
  ASSERT_EQ(1u, host.loaded().size());
  EXPECT_EQ(0x11, host.loaded()[0].id.pub_key[0]);
}

TEST(DataStoreRecordCodecTest, ReadAllContactsZeroReadAtGenuineEndOfFileIsStillHealthyEof) {
  // The SAME "read() returns 0" outcome, but this time position() ==
  // size() truly holds (no force_ioerr_zero -- the real buffer is
  // genuinely exhausted) -- must still resolve to a clean, healthy EOF,
  // proving the position()/size() check does not spuriously reject
  // ordinary end-of-file.
  std::vector<uint8_t> bytes = encodeContacts({makeContact(0x11)});
  FakeCodecReadFile file(bytes);
  FakeContactLoadHost host;
  EXPECT_TRUE((datastore_io::readAllContacts<FakeCodecReadFile, FakeContactLoadHost, FakeContactRecord>(file, &host)));
  ASSERT_EQ(1u, host.loaded().size());
}

TEST(DataStoreRecordCodecTest, ReadAllChannelsZeroReadWhileDataGenuinelyRemainsOnFirstFieldIsFaultNotEof) {
  std::vector<uint8_t> bytes = encodeChannels({makeChannel(0x33), makeChannel(0x44)});
  FakeCodecReadFile file(bytes, /*corrupt_at_byte=*/-1, /*force_ioerr_zero_at_byte=*/(long)kChannelRecordBytes);
  FakeChannelLoadHost host;
  uint8_t next_idx = 0;
  EXPECT_FALSE((datastore_io::readAllChannels<FakeCodecReadFile, FakeChannelLoadHost, FakeChannelRecord>(file, &host, next_idx)));
  ASSERT_EQ(1u, host.loaded().size());
  EXPECT_EQ(1, next_idx);
}

// ---------------------------------------------------------------------
// datastore_io::readLegacyPrefsFields() -- shared decode for the legacy
// "/new_prefs" binary format (see DataStore::loadPrefsInt()). Exercised
// here against the SAME FakeCodecReadFile used above, proving the exact
// production byte offsets/short-read-abort behavior, not a second
// hand-rolled reimplementation.
// ---------------------------------------------------------------------

namespace {

// Builds one full, well-formed legacy prefs record's on-disk bytes, in
// readLegacyPrefsFields()'s own field order, with distinct, recognizable
// per-field fill values so a decode test can verify true field-by-field
// offsets (not merely "some bytes landed somewhere").
std::vector<uint8_t> encodeLegacyPrefs() {
  std::vector<uint8_t> bytes;
  auto put = [&](const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    bytes.insert(bytes.end(), p, p + len);
  };
  float airtime_factor = 1.5f; put(&airtime_factor, 4);
  char node_name[32]; memset(node_name, 'N', sizeof(node_name)); put(node_name, 32);
  uint8_t pad4[4] = {0,0,0,0}; put(pad4, 4);
  double node_lat = 12.5; put(&node_lat, 8);
  double node_lon = -34.25; put(&node_lon, 8);
  float freq = 910.525f; put(&freq, 4);
  uint8_t sf = 7; put(&sf, 1);
  uint8_t cr = 5; put(&cr, 1);
  uint8_t client_repeat = 1; put(&client_repeat, 1);
  uint8_t manual_add_contacts = 0; put(&manual_add_contacts, 1);
  float bw = 62.5f; put(&bw, 4);
  int8_t tx_power_dbm = 22; put(&tx_power_dbm, 1);
  uint8_t telemetry_mode_base = 1; put(&telemetry_mode_base, 1);
  uint8_t telemetry_mode_loc = 2; put(&telemetry_mode_loc, 1);
  uint8_t telemetry_mode_env = 3; put(&telemetry_mode_env, 1);
  float rx_delay_base = 0.5f; put(&rx_delay_base, 4);
  uint8_t advert_loc_policy = 1; put(&advert_loc_policy, 1);
  uint8_t multi_acks = 1; put(&multi_acks, 1);
  uint8_t path_hash_mode = 2; put(&path_hash_mode, 1);
  uint8_t pad1[1] = {0}; put(pad1, 1);
  uint32_t ble_pin = 123456u; put(&ble_pin, 4);
  uint8_t buzzer_quiet = 1; put(&buzzer_quiet, 1);
  uint8_t gps_enabled = 1; put(&gps_enabled, 1);
  uint32_t gps_interval = 30u; put(&gps_interval, 4);
  uint8_t autoadd_config = 2; put(&autoadd_config, 1);
  uint8_t autoadd_max_hops = 4; put(&autoadd_max_hops, 1);
  uint8_t rx_boosted_gain = 1; put(&rx_boosted_gain, 1);
  char default_scope_name[31]; memset(default_scope_name, 'S', sizeof(default_scope_name)); put(default_scope_name, 31);
  uint8_t default_scope_key[16]; memset(default_scope_key, 0xAB, sizeof(default_scope_key)); put(default_scope_key, 16);
  return bytes;
}

}  // namespace

TEST(DataStoreRecordCodecTest, ReadLegacyPrefsFieldsDecodesEveryFieldAtItsExactOffset) {
  std::vector<uint8_t> bytes = encodeLegacyPrefs();
  FakeCodecReadFile file(bytes);
  datastore_io::LegacyPrefsFields out;
  memset(&out, 0, sizeof(out));
  ASSERT_TRUE(datastore_io::readLegacyPrefsFields(file, out));
  EXPECT_FLOAT_EQ(1.5f, out.airtime_factor);
  EXPECT_EQ('N', out.node_name[0]);
  EXPECT_DOUBLE_EQ(12.5, out.node_lat);
  EXPECT_DOUBLE_EQ(-34.25, out.node_lon);
  EXPECT_EQ(7, out.sf);
  EXPECT_EQ(5, out.cr);
  EXPECT_EQ(123456u, out.ble_pin);
  EXPECT_EQ('S', out.default_scope_name[0]);
  EXPECT_EQ(0xAB, out.default_scope_key[0]);
}

TEST(DataStoreRecordCodecTest, ReadLegacyPrefsFieldsFailsOnGenuineShortReadMidRecord) {
  std::vector<uint8_t> bytes = encodeLegacyPrefs();
  bytes.resize(bytes.size() - 20);  // truncate partway through the last field
  FakeCodecReadFile file(bytes);
  datastore_io::LegacyPrefsFields out;
  EXPECT_FALSE(datastore_io::readLegacyPrefsFields(file, out));
}

// An empty file is a genuine, provenance-backed clean EOF at the very
// first field (position()==0==size()) -- the original hand-written
// loader (plain sequential file.read() calls, return value ignored)
// tolerated this identically to any other legacy file, leaving every
// field at its pre-existing value. This is NOT a fault.
TEST(DataStoreRecordCodecTest, ReadLegacyPrefsFieldsToleratesEmptyFileAsOldestPossibleFormat) {
  FakeCodecReadFile file({});
  datastore_io::LegacyPrefsFields out;
  out.airtime_factor = 9.5f;  // pre-seeded "current prefs" value, as DataStore::loadPrefsInt() does.
  EXPECT_TRUE(datastore_io::readLegacyPrefsFields(file, out));
  EXPECT_FLOAT_EQ(9.5f, out.airtime_factor);  // left untouched: no bytes existed to read.
}

// A genuine I/O error that returns 0 bytes WITHOUT actually being at the
// true end of file (position() < size() still holds) must never be
// misread as a legitimate older-format EOF.
TEST(DataStoreRecordCodecTest, ReadLegacyPrefsFieldsFailsOnZeroReadBeforeTrueEof) {
  std::vector<uint8_t> bytes = encodeLegacyPrefs();
  FakeCodecReadFile file(bytes, -1, /*force_ioerr_zero_at_byte=*/0);
  datastore_io::LegacyPrefsFields out;
  EXPECT_FALSE(datastore_io::readLegacyPrefsFields(file, out));
}

// An older, shorter -- but otherwise perfectly valid -- legacy file that
// simply ends exactly at a field boundary (this format has grown
// field-by-field across many commits, each new pref appended at the
// end) must be tolerated: every field actually present in the file is
// decoded, and every field beyond the truncation point keeps its
// pre-seeded prior value, exactly matching the original loader's
// ignore-the-return-value tolerant behaviour.
TEST(DataStoreRecordCodecTest, ReadLegacyPrefsFieldsToleratesOlderShorterFormatAtFieldBoundary) {
  std::vector<uint8_t> bytes = encodeLegacyPrefs();
  bytes.resize(bytes.size() - 16);  // drop exactly the trailing default_scope_key[16] field.
  FakeCodecReadFile file(bytes);
  datastore_io::LegacyPrefsFields out;
  memset(&out, 0, sizeof(out));
  memset(out.default_scope_key, 0xCD, sizeof(out.default_scope_key));  // pre-seeded prior value.
  ASSERT_TRUE(datastore_io::readLegacyPrefsFields(file, out));
  EXPECT_FLOAT_EQ(1.5f, out.airtime_factor);      // present in the file: decoded.
  EXPECT_EQ('S', out.default_scope_name[0]);      // present in the file: decoded.
  EXPECT_EQ(0xCD, out.default_scope_key[0]);      // absent from this older file: untouched.
}

// ---------------------------------------------------------------------
// datastore_io::scanBlobRecordsForKey()/scanBlobRecordsForWritePosition()
// -- shared scan logic for DataStore::getBlobByKey()/putBlobByKey()'s
// fixed-size-record "/adv_blobs" store, exercised against a small fake
// record type (not the real, much larger production BlobRec) to prove
// the EXACT SAME scan/match/evict/fault-provenance algorithm.
// ---------------------------------------------------------------------

namespace {

struct FakeBlobRecord {
  uint32_t timestamp;
  uint8_t  key[7];
  uint8_t  len;
  uint8_t  data[8];
};

std::vector<uint8_t> encodeBlobRecord(uint32_t timestamp, const uint8_t key[7], uint8_t len, const uint8_t* data) {
  FakeBlobRecord rec;
  memset(&rec, 0, sizeof(rec));
  rec.timestamp = timestamp;
  memcpy(rec.key, key, 7);
  rec.len = len;
  if (data && len > 0) memcpy(rec.data, data, len);
  std::vector<uint8_t> bytes((uint8_t*)&rec, (uint8_t*)&rec + sizeof(rec));
  return bytes;
}

}  // namespace

TEST(DataStoreRecordCodecTest, ScanBlobRecordsForKeyFindsMatchAndCopiesData) {
  uint8_t key_a[7] = {1,2,3,4,5,6,7};
  uint8_t key_b[7] = {9,9,9,9,9,9,9};
  uint8_t payload[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
  std::vector<uint8_t> bytes = encodeBlobRecord(100, key_a, 4, payload);
  std::vector<uint8_t> rec2 = encodeBlobRecord(200, key_b, 0, nullptr);
  bytes.insert(bytes.end(), rec2.begin(), rec2.end());

  FakeCodecReadFile file(bytes);
  bool found = false, fault = false;
  uint8_t out_len = 0;
  uint8_t dest[8] = {0};
  datastore_io::scanBlobRecordsForKey<FakeCodecReadFile, FakeBlobRecord>(file, key_a, 7, found, out_len, dest, fault);
  EXPECT_TRUE(found);
  EXPECT_FALSE(fault);
  EXPECT_EQ(4, out_len);
  EXPECT_EQ(0x11, dest[0]);
  EXPECT_EQ(0x44, dest[3]);
}

TEST(DataStoreRecordCodecTest, ScanBlobRecordsForKeyCleanEofWithNoMatchIsNotAFault) {
  uint8_t key_b[7] = {9,9,9,9,9,9,9};
  std::vector<uint8_t> bytes = encodeBlobRecord(200, key_b, 0, nullptr);
  uint8_t key_missing[7] = {1,1,1,1,1,1,1};

  FakeCodecReadFile file(bytes);
  bool found = false, fault = false;
  uint8_t out_len = 0;
  datastore_io::scanBlobRecordsForKey<FakeCodecReadFile, FakeBlobRecord>(file, key_missing, 7, found, out_len, nullptr, fault);
  EXPECT_FALSE(found);
  EXPECT_FALSE(fault);
}

TEST(DataStoreRecordCodecTest, ScanBlobRecordsForKeyGenuineMidScanFaultIsReportedNotSilentlyNotFound) {
  uint8_t key_a[7] = {1,2,3,4,5,6,7};
  uint8_t key_b[7] = {9,9,9,9,9,9,9};
  std::vector<uint8_t> bytes = encodeBlobRecord(100, key_a, 0, nullptr);
  std::vector<uint8_t> rec2 = encodeBlobRecord(200, key_b, 0, nullptr);
  bytes.insert(bytes.end(), rec2.begin(), rec2.end());
  // Force a 0-byte read() at the start of the SECOND record while data
  // genuinely remains (a real I/O error), not an ordinary clean EOF.
  FakeCodecReadFile file(bytes, /*corrupt_at_byte=*/-1, /*force_ioerr_zero_at_byte=*/(long)sizeof(FakeBlobRecord));
  bool found = false, fault = false;
  uint8_t out_len = 0;
  datastore_io::scanBlobRecordsForKey<FakeCodecReadFile, FakeBlobRecord>(file, key_b, 7, found, out_len, nullptr, fault);
  EXPECT_FALSE(found);
  EXPECT_TRUE(fault);
}

TEST(DataStoreRecordCodecTest, ScanBlobRecordsForWritePositionReturnsExistingKeysOwnOffsetWhenMatched) {
  uint8_t key_a[7] = {1,2,3,4,5,6,7};
  uint8_t key_b[7] = {9,9,9,9,9,9,9};
  std::vector<uint8_t> bytes = encodeBlobRecord(100, key_a, 0, nullptr);
  std::vector<uint8_t> rec2 = encodeBlobRecord(50, key_b, 0, nullptr);
  bytes.insert(bytes.end(), rec2.begin(), rec2.end());

  FakeCodecReadFile file(bytes);
  bool matched = false, fault = false;
  uint32_t out_pos = 0xFFFFFFFF;
  datastore_io::scanBlobRecordsForWritePosition<FakeCodecReadFile, FakeBlobRecord>(file, key_b, 7, matched, out_pos, fault);
  EXPECT_TRUE(matched);
  EXPECT_FALSE(fault);
  EXPECT_EQ(sizeof(FakeBlobRecord), out_pos);  // key_b is the SECOND record
}

TEST(DataStoreRecordCodecTest, ScanBlobRecordsForWritePositionEvictsOldestTimestampWhenNoMatch) {
  uint8_t key_a[7] = {1,2,3,4,5,6,7};
  uint8_t key_b[7] = {9,9,9,9,9,9,9};
  uint8_t key_missing[7] = {5,5,5,5,5,5,5};
  std::vector<uint8_t> bytes = encodeBlobRecord(100, key_a, 0, nullptr);   // newer
  std::vector<uint8_t> rec2 = encodeBlobRecord(50, key_b, 0, nullptr);     // OLDEST -- eviction target
  bytes.insert(bytes.end(), rec2.begin(), rec2.end());

  FakeCodecReadFile file(bytes);
  bool matched = false, fault = false;
  uint32_t out_pos = 0xFFFFFFFF;
  datastore_io::scanBlobRecordsForWritePosition<FakeCodecReadFile, FakeBlobRecord>(file, key_missing, 7, matched, out_pos, fault);
  EXPECT_FALSE(matched);
  EXPECT_FALSE(fault);
  EXPECT_EQ(sizeof(FakeBlobRecord), out_pos);  // key_b (the oldest, at the 2nd slot) was chosen
}

TEST(DataStoreRecordCodecTest, ScanBlobRecordsForWritePositionGenuineMidScanFaultAbortsDecision) {
  uint8_t key_a[7] = {1,2,3,4,5,6,7};
  uint8_t key_b[7] = {9,9,9,9,9,9,9};
  uint8_t key_missing[7] = {5,5,5,5,5,5,5};
  std::vector<uint8_t> bytes = encodeBlobRecord(100, key_a, 0, nullptr);
  std::vector<uint8_t> rec2 = encodeBlobRecord(50, key_b, 0, nullptr);
  bytes.insert(bytes.end(), rec2.begin(), rec2.end());
  FakeCodecReadFile file(bytes, /*corrupt_at_byte=*/-1, /*force_ioerr_zero_at_byte=*/(long)sizeof(FakeBlobRecord));
  bool matched = false, fault = false;
  uint32_t out_pos = 0xFFFFFFFF;
  datastore_io::scanBlobRecordsForWritePosition<FakeCodecReadFile, FakeBlobRecord>(file, key_missing, 7, matched, out_pos, fault);
  EXPECT_TRUE(fault);
}
