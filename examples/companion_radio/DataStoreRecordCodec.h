#pragma once

#include <string.h>

// Forward declarations only (NOT the full <helpers/ContactInfo.h>/
// <helpers/ChannelDetails.h>, which transitively pull in <Arduino.h> and
// so cannot compile in the native/g++ test environment): these two
// names are only ever used here as DEFAULT template arguments below,
// which requires them to be DECLARED, not necessarily complete, as long
// as a translation unit only ever instantiates the templates with the
// default (production always does, via DataStore.cpp, which already
// includes the real, complete definitions through DataStore.h before
// this header is used) or with an explicit, complete alternative type
// (native tests, with a plain POD fake record).
struct ContactInfo;
struct ChannelDetails;

// Generic (Arduino/File-type agnostic) bounded record-writing logic
// shared by DataStore::saveContacts()/saveChannels(). Extracted so
// native host tests can drive the EXACT SAME field-by-field write
// order and "stop at the first short/failed write" decision that
// production DataStore.cpp uses -- against a plain, byte-backed fake
// File and a fake DataStoreHost -- instead of a second, hand-rolled
// reimplementation of this same byte layout that could silently drift
// from the real one. No FILESYSTEM/File/Adafruit_LittleFS/fs::FS type
// is named anywhere in this header: `File` is a template parameter, so
// the identical template instantiates against either the real Arduino
// File type (MCU build) or a native FakeFile (host test) with zero
// source changes to the logic itself.
namespace datastore_io {

// True iff exactly `len` bytes were reported written.
template <typename File>
inline bool writeExact(File& file, const void* data, size_t len) {
  return file.write(reinterpret_cast<const uint8_t*>(data), len) == len;
}

// Writes every contact `host->getContactForSave()` yields (honoring the
// optional `filter`, which may be a null function pointer) to `file` in
// DataStore's existing on-disk field order, stopping at the first
// short/failed write. A host that yields zero contacts (or whose every
// contact is filtered out) legitimately returns true -- an empty
// contact list is not itself a fault; the caller is responsible for
// distinguishing a genuine file-open failure separately (see
// DataStore::saveContacts()).
//
// `Contact` defaults to the real production `ContactInfo` (unchanged
// production behavior/host API); native tests may instantiate this same
// template with a plain POD fake record type instead (matching field
// layout, with e.g. a raw `uint8_t pub_key[32]` in place of
// `mesh::Identity id`) to exercise the EXACT SAME write order/stop-on-
// failure algorithm without needing to link `Identity.cpp`/Ed25519
// crypto into a native test build.
template <typename File, typename Host, typename Filter, typename Contact = ContactInfo>
inline bool writeAllContacts(File& file, Host* host, Filter filter) {
  uint32_t idx = 0;
  Contact c;
  uint8_t unused = 0;

  while (host->getContactForSave(idx, c)) {
    if (filter && !filter(c)) {
      idx++;  // advance to next contact
      continue;
    }
    bool success = writeExact(file, c.id.pub_key, 32);
    success = success && writeExact(file, (uint8_t *)&c.name, 32);
    success = success && writeExact(file, &c.type, 1);
    success = success && writeExact(file, &c.flags, 1);
    success = success && writeExact(file, &unused, 1);
    success = success && writeExact(file, (uint8_t *)&c.sync_since, 4);
    success = success && writeExact(file, (uint8_t *)&c.out_path_len, 1);
    success = success && writeExact(file, (uint8_t *)&c.last_advert_timestamp, 4);
    success = success && writeExact(file, c.out_path, 64);
    success = success && writeExact(file, (uint8_t *)&c.lastmod, 4);
    success = success && writeExact(file, (uint8_t *)&c.gps_lat, 4);
    success = success && writeExact(file, (uint8_t *)&c.gps_lon, 4);

    if (!success) return false;  // write failed
    idx++;  // advance to next contact
  }
  return true;
}

// Writes every channel `host->getChannelForSave()` yields to `file` in
// DataStore's existing on-disk field order, stopping at the first
// short/failed write.
//
// `Channel` defaults to the real production `ChannelDetails` (unchanged
// production behavior/host API); see writeAllContacts() above for the
// native-fake-record rationale.
template <typename File, typename Host, typename Channel = ChannelDetails>
inline bool writeAllChannels(File& file, Host* host) {
  uint8_t channel_idx = 0;
  Channel ch;
  uint8_t unused[4];
  memset(unused, 0, 4);

  while (host->getChannelForSave(channel_idx, ch)) {
    bool success = writeExact(file, unused, 4);
    success = success && writeExact(file, (uint8_t *)ch.name, 32);
    success = success && writeExact(file, (uint8_t *)ch.channel.secret, 32);

    if (!success) return false;  // write failed
    channel_idx++;
  }
  return true;
}

// Reads contact records from `file` in DataStore's existing on-disk
// field order and delivers each to `host->onContactLoaded()`, stopping
// when the host stops accepting records (a full in-RAM contact table is
// NOT a fault).
//
// Return value distinguishes a genuinely CLEAN end-of-file from a real
// read fault, which the original production code (a single
// `if (!success) break; // EOF` after the WHOLE field chain) could not:
// a `read()` of exactly 0 bytes on the very FIRST field of a fresh
// record is ONLY treated as "no more records" when the file's own
// `position()`/`size()` provenance genuinely agrees nothing remains --
// some real File implementations can legitimately return 0 from an
// actual I/O error rather than only "ran past the end", and blindly
// trusting a bare 0-byte return would silently discard every remaining
// on-disk record while still reporting success. ANY other short read --
// including a PARTIAL (neither 0 nor 32) read on that very first field,
// a 0-byte-but-more-data-remains read on the first field, or any short
// read on a LATER field after the first genuinely succeeded -- means a
// record was only partially found on disk, which is a genuine storage
// fault (truncation/corruption/IO error), not an ordinary end-of-file,
// and must be reported as such to the caller rather than silently
// discarding the partial record and reporting success.
//
// `Contact` defaults to the real production `ContactInfo`; see
// writeAllContacts() above for the native-fake-record rationale. Reads
// directly into `c.id.pub_key` (a plain byte array on both the real
// `mesh::Identity` and native fake types), so no `mesh::Identity`
// constructor call is needed here.
template <typename File, typename Host, typename Contact = ContactInfo>
inline bool readAllContacts(File& file, Host* host) {
  bool full = false;
  while (!full) {
    Contact c;
    uint8_t unused;

    // A `read()` returning 0 is only a genuine, clean end-of-file if the
    // file's own position/size provenance agrees there is truly nothing
    // left -- some real File implementations can legitimately return 0
    // from an underlying I/O error (not merely "ran past the end"),
    // which must NOT be silently treated as "no more records" (that
    // would drop every remaining contact and still report success).
    const uint32_t pos_before_record = file.position();
    const uint32_t total_size = file.size();
    const size_t pub_key_read = file.read(c.id.pub_key, 32);
    if (pub_key_read == 0) {
      if (pos_before_record >= total_size) return true;  // genuine, provenance-backed clean EOF.
      return false;  // 0 bytes read but more data genuinely remains: a real I/O fault.
    }
    if (pub_key_read != 32) return false; // genuine fault: partial record.

    bool success = (file.read((uint8_t *)&c.name, 32) == 32);
    success = success && (file.read(&c.type, 1) == 1);
    success = success && (file.read(&c.flags, 1) == 1);
    success = success && (file.read(&unused, 1) == 1);
    success = success && (file.read((uint8_t *)&c.sync_since, 4) == 4);
    success = success && (file.read((uint8_t *)&c.out_path_len, 1) == 1);
    success = success && (file.read((uint8_t *)&c.last_advert_timestamp, 4) == 4);
    success = success && (file.read(c.out_path, 64) == 64);
    success = success && (file.read((uint8_t *)&c.lastmod, 4) == 4);
    success = success && (file.read((uint8_t *)&c.gps_lat, 4) == 4);
    success = success && (file.read((uint8_t *)&c.gps_lon, 4) == 4);

    if (!success) return false;  // genuine fault: partial record after first field.

    if (!host->onContactLoaded(c)) full = true;
  }
  return true;
}

// Reads channel records from `file` in DataStore's existing on-disk
// field order and delivers each to `host->onChannelLoaded()`, stopping
// when the host stops accepting records. Same provenance-backed clean-
// EOF-vs-genuine-fault distinction as readAllContacts() above (a 0-byte
// read on the first field of a fresh record is ONLY EOF when
// position()/size() genuinely agree nothing remains; any other short
// read -- including a 0-byte read while more data remains -- is a
// fault). `next_channel_idx` is advanced in place, mirroring the
// production loop's own running index.
//
// `Channel` defaults to the real production `ChannelDetails`; see
// writeAllChannels() above.
template <typename File, typename Host, typename Channel = ChannelDetails>
inline bool readAllChannels(File& file, Host* host, uint8_t& next_channel_idx) {
  bool full = false;
  while (!full) {
    Channel ch;
    uint8_t unused[4];

    const uint32_t pos_before_record = file.position();
    const uint32_t total_size = file.size();
    const size_t unused_read = file.read(unused, 4);
    if (unused_read == 0) {
      if (pos_before_record >= total_size) return true;  // genuine, provenance-backed clean EOF.
      return false;  // 0 bytes read but more data genuinely remains: a real I/O fault.
    }
    if (unused_read != 4) return false;  // genuine fault: partial record.

    bool success = (file.read((uint8_t *)ch.name, 32) == 32);
    success = success && (file.read((uint8_t *)ch.channel.secret, 32) == 32);

    if (!success) return false;  // genuine fault: partial record after first field.

    if (host->onChannelLoaded(next_channel_idx, ch)) {
      next_channel_idx++;
    } else {
      full = true;
    }
  }
  return true;
}

// Legacy "/new_prefs" binary format's field values, decoded into a
// purely local, Arduino/NodePrefs-independent working copy -- see
// readLegacyPrefsFields() below for why this cannot read directly into
// a real NodePrefs.
struct LegacyPrefsFields {
  float    airtime_factor;
  char     node_name[32];
  double   node_lat, node_lon;
  float    freq;
  uint8_t  sf, cr, client_repeat, manual_add_contacts;
  float    bw;
  int8_t   tx_power_dbm;
  uint8_t  telemetry_mode_base, telemetry_mode_loc, telemetry_mode_env;
  float    rx_delay_base;
  uint8_t  advert_loc_policy, multi_acks, path_hash_mode;
  uint32_t ble_pin;
  uint8_t  buzzer_quiet, gps_enabled;
  uint32_t gps_interval;
  uint8_t  autoadd_config, autoadd_max_hops, rx_boosted_gain;
  char     default_scope_name[31];
  uint8_t  default_scope_key[16];
};

// Reads every legacy "/new_prefs" field from `file`, in DataStore's
// existing on-disk field order/offsets, into `out` -- a purely local
// working copy, never NodePrefs itself (NodePrefs::radio holds a
// private `_parent` back-pointer to its OWNING NodePrefs instance, so a
// whole-struct copy-assignment working-copy pattern would corrupt that
// pointer to dangle at a destroyed temporary).
//
// This format has grown field-by-field across many commits (each new
// pref appended at the end of the on-disk layout), so an older, shorter
// -- but otherwise perfectly valid -- file legitimately runs out of
// bytes exactly at a field boundary; the original hand-written loader
// (plain sequential `file.read()` calls, return value ignored) read
// whatever bytes existed and silently left every field beyond that
// point at its pre-existing in-memory value. To preserve that same
// backward compatibility, the CALLER must pre-seed `out` with the
// current/default values of every field (see DataStore::loadPrefsInt())
// before calling this. A clean stop -- a field read that returns 0
// bytes exactly at end-of-file -- leaves the remaining, not-yet-read
// fields (already seeded by the caller) untouched and returns true
// (older, shorter, still-valid format). A genuine fault -- any other
// short/partial read (mid-field truncation/corruption) -- returns
// false; the caller must not commit ANY of `out` in that case.
template <typename File>
inline bool readLegacyPrefsFields(File& file, LegacyPrefsFields& out) {
  const uint32_t total_size = file.size();
  bool stop_clean = false;  // true once a legitimate older-format EOF is hit.
  bool fault = false;
  auto readField = [&](void* dest, size_t len) {
    if (stop_clean || fault) return;
    const uint32_t pos_before = file.position();
    const int n = file.read((uint8_t*)dest, len);
    if (n == (int)len) return;  // full field read -- keep going.
    if (n == 0 && pos_before >= total_size) {
      stop_clean = true;  // genuine, provenance-backed clean EOF: older/shorter valid format.
      return;
    }
    fault = true;  // partial/short read: real corruption/truncation, never legit EOF.
  };
  uint8_t pad4[4], pad1[1];

  readField(&out.airtime_factor, sizeof(out.airtime_factor));               // 0
  readField(out.node_name, sizeof(out.node_name));                          // 4
  readField(pad4, sizeof(pad4));                                            // 36
  readField(&out.node_lat, sizeof(out.node_lat));                           // 40
  readField(&out.node_lon, sizeof(out.node_lon));                          // 48
  readField(&out.freq, sizeof(out.freq));                                   // 56
  readField(&out.sf, sizeof(out.sf));                                       // 60
  readField(&out.cr, sizeof(out.cr));                                       // 61
  readField(&out.client_repeat, sizeof(out.client_repeat));                // 62
  readField(&out.manual_add_contacts, sizeof(out.manual_add_contacts));    // 63
  readField(&out.bw, sizeof(out.bw));                                       // 64
  readField(&out.tx_power_dbm, sizeof(out.tx_power_dbm));                  // 68
  readField(&out.telemetry_mode_base, sizeof(out.telemetry_mode_base));    // 69
  readField(&out.telemetry_mode_loc, sizeof(out.telemetry_mode_loc));      // 70
  readField(&out.telemetry_mode_env, sizeof(out.telemetry_mode_env));      // 71
  readField(&out.rx_delay_base, sizeof(out.rx_delay_base));                // 72
  readField(&out.advert_loc_policy, sizeof(out.advert_loc_policy));        // 76
  readField(&out.multi_acks, sizeof(out.multi_acks));                      // 77
  readField(&out.path_hash_mode, sizeof(out.path_hash_mode));              // 78
  readField(pad1, sizeof(pad1));                                            // 79
  readField(&out.ble_pin, sizeof(out.ble_pin));                             // 80
  readField(&out.buzzer_quiet, sizeof(out.buzzer_quiet));                  // 84
  readField(&out.gps_enabled, sizeof(out.gps_enabled));                    // 85
  readField(&out.gps_interval, sizeof(out.gps_interval));                  // 86
  readField(&out.autoadd_config, sizeof(out.autoadd_config));              // 87
  readField(&out.autoadd_max_hops, sizeof(out.autoadd_max_hops));          // 88
  readField(&out.rx_boosted_gain, sizeof(out.rx_boosted_gain));            // 89
  readField(out.default_scope_name, sizeof(out.default_scope_name));       // 90
  readField(out.default_scope_key, sizeof(out.default_scope_key));         // 121

  return !fault;  // true for both a fully-read file AND a clean older/shorter-format stop.
}

// Generic (File/Record-type agnostic) linear scan of a fixed-size-record
// blob store (production: DataStore's "/adv_blobs" file of `BlobRec`),
// shared by DataStore::getBlobByKey()/putBlobByKey() so native host
// tests can drive the EXACT SAME clean-EOF-vs-genuine-fault scan
// algorithm against a byte-backed fake File and a plain POD fake record
// type, instead of a second hand-rolled reimplementation.
//
// `Record` must have `key[K]` (K == sizeof(key_prefix) bytes compared
// via memcmp), `uint8_t len`, `uint8_t data[]`, and `uint32_t timestamp`
// members in that relative field order (matching DataStore.cpp's
// on-disk `BlobRec`).
//
// Finds the first record whose key prefix matches `key_prefix`
// (`key_prefix_len` bytes, compared against `Record::key`). On a match,
// copies `tmp.len` bytes from `tmp.data` into `dest_buf` (if non-null)
// and sets `out_len`; `found` reports whether a match was seen at all.
// `fault` is set true (and the scan stops immediately) on a genuine
// mid-scan I/O error -- a short/partial record read, or a 0-byte read
// while `file.position() < file.size()` genuinely still holds -- NEVER
// conflated with an ordinary, provenance-backed clean end-of-file.
template <typename File, typename Record>
inline void scanBlobRecordsForKey(File& file, const uint8_t key_prefix[], size_t key_prefix_len,
                                   bool& found, uint8_t& out_len, uint8_t* dest_buf, bool& fault) {
  found = false;
  fault = false;
  const uint32_t total_size = file.size();
  Record tmp;
  for (;;) {
    const uint32_t pos_before = file.position();
    const int n = file.read((uint8_t *)&tmp, sizeof(tmp));
    if (n == (int)sizeof(tmp)) {
      if (memcmp(key_prefix, tmp.key, key_prefix_len) == 0) {
        found = true;
        out_len = tmp.len;
        if (dest_buf) memcpy(dest_buf, tmp.data, tmp.len);
      }
      continue;
    }
    if (n == 0 && pos_before >= total_size) return;  // genuine, provenance-backed clean EOF.
    fault = true;  // 0 or short bytes read but more data genuinely remains.
    return;
  }
}

// Same scan, but for putBlobByKey()'s "find matching key, else evict
// the oldest (lowest `timestamp`) record" write-position decision.
// `matched` true means `out_pos` is the EXISTING record's own byte
// offset (must be overwritten in place); false means `out_pos` is the
// oldest record's offset (an eviction). `fault` follows the exact same
// provenance rule as scanBlobRecordsForKey() above; the caller MUST NOT
// trust `out_pos`/`matched` and must write nothing when `fault` is true,
// since the scan could not be completed reliably.
template <typename File, typename Record>
inline void scanBlobRecordsForWritePosition(File& file, const uint8_t key_prefix[], size_t key_prefix_len,
                                             bool& matched, uint32_t& out_pos, bool& fault) {
  matched = false;
  fault = false;
  uint32_t pos = 0;
  uint32_t min_timestamp = 0xFFFFFFFF;
  const uint32_t total_size = file.size();
  Record tmp;
  for (;;) {
    const uint32_t pos_before = file.position();
    const int n = file.read((uint8_t *)&tmp, sizeof(tmp));
    if (n == (int)sizeof(tmp)) {
      if (memcmp(key_prefix, tmp.key, key_prefix_len) == 0) {
        matched = true;
        out_pos = pos;
        return;
      }
      if (tmp.timestamp < min_timestamp) {
        min_timestamp = tmp.timestamp;
        out_pos = pos;
      }
      pos += sizeof(tmp);
      continue;
    }
    if (n == 0 && pos_before >= total_size) return;  // genuine, provenance-backed clean EOF.
    fault = true;
    return;
  }
}

}  // namespace datastore_io
