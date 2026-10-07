#include <Arduino.h>
#include "DataStore.h"
#include "DataStoreRecordCodec.h"
#include <helpers/ota/OtaWriteGate.h>

#if defined(EXTRAFS) || defined(QSPIFLASH)
  #define MAX_BLOBRECS 100
#else
  #define MAX_BLOBRECS 20
#endif

DataStore::DataStore(FILESYSTEM& fs, mesh::RTCClock& clock) : _fs(&fs), _fsExtra(nullptr), _clock(&clock),
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
    identity_store(fs, "")
#elif defined(RP2040_PLATFORM)
    identity_store(fs, "/identity")
#else
    identity_store(fs, "/identity")
#endif
{
}

#if defined(EXTRAFS) || defined(QSPIFLASH)
DataStore::DataStore(FILESYSTEM& fs, FILESYSTEM& fsExtra, mesh::RTCClock& clock) : _fs(&fs), _fsExtra(&fsExtra), _clock(&clock),
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
    identity_store(fs, "")
#elif defined(RP2040_PLATFORM)
    identity_store(fs, "/identity")
#else
    identity_store(fs, "/identity")
#endif
{
}
#endif

static File openWrite(FILESYSTEM* fs, const char* filename) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  fs->remove(filename);
  return fs->open(filename, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  return fs->open(filename, "w");
#else
  return fs->open(filename, "w", true);
#endif
}

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  static uint32_t _ContactsChannelsTotalBlocks = 0;
#endif

void DataStore::begin(bool allow_destructive_writes, bool allow_format) {
  _destructive_writes_disallowed_ = !allow_destructive_writes;
  _format_disallowed_ = !allow_format;
#if defined(RP2040_PLATFORM)
  // IdentityStore::begin() unconditionally mkdir()s its identity
  // directory -- an OTA trial/unknown boot must not create it either;
  // loading an EXISTING identity from an already-present directory does
  // not depend on this call having run.
  if (allow_destructive_writes) identity_store.begin();
#endif

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  _ContactsChannelsTotalBlocks = _getContactsChannelsFS()->_getFS()->cfg->block_count;
  checkAdvBlobFile();
  #if defined(EXTRAFS) || defined(QSPIFLASH)
  // migrateToSecondaryFS() unconditionally copies-then-deletes several
  // legacy files; during an OTA trial/unknown boot this destructive
  // migration must not run at all (zero writes/deletes, all original
  // files preserved) -- see DataStore.h's begin() doc comment.
  if (allow_destructive_writes) migrateToSecondaryFS();
  #endif
#else
  // init 'blob store' support
  if (allow_destructive_writes) _fs->mkdir("/bl");
#endif
}

#if defined(ESP32)
  #include <SPIFFS.h>
  #include <nvs_flash.h>
#elif defined(RP2040_PLATFORM)
  #include <LittleFS.h>
#elif defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  #if defined(QSPIFLASH)
    #include <CustomLFS_QSPIFlash.h>
  #elif defined(EXTRAFS)
    #include <CustomLFS.h>
  #else 
    #include <InternalFileSystem.h>
  #endif
#endif

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
int _countLfsBlock(void *p, lfs_block_t block){
      if (block > _ContactsChannelsTotalBlocks) {
        MESH_DEBUG_PRINTLN("ERROR: Block %d exceeds filesystem bounds - CORRUPTION DETECTED!", block);
        return LFS_ERR_CORRUPT;  // return error to abort lfs_traverse() gracefully
    }
  lfs_size_t *size = (lfs_size_t*) p;
  *size += 1;
    return 0;
}

lfs_ssize_t _getLfsUsedBlockCount(FILESYSTEM* fs) {
  lfs_size_t size = 0;
  int err = lfs_traverse(fs->_getFS(), _countLfsBlock, &size);
  if (err) {
    MESH_DEBUG_PRINTLN("ERROR: lfs_traverse() error: %d", err);
    return 0;
  }
  return size;
}
#endif

uint32_t DataStore::getStorageUsedKb() const {
#if defined(ESP32)
  return SPIFFS.usedBytes() / 1024;
#elif defined(RP2040_PLATFORM)
  FSInfo info;
  info.usedBytes = 0;
  _fs->info(info);
  return info.usedBytes / 1024;
#elif defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  const lfs_config* config = _getContactsChannelsFS()->_getFS()->cfg;
  int usedBlockCount = _getLfsUsedBlockCount(_getContactsChannelsFS());
  int usedBytes = config->block_size * usedBlockCount;
  return usedBytes / 1024;
#else
  return 0;
#endif
}

uint32_t DataStore::getStorageTotalKb() const {
#if defined(ESP32)
  return SPIFFS.totalBytes() / 1024;
#elif defined(RP2040_PLATFORM)
  FSInfo info;
  info.totalBytes = 0;
  _fs->info(info);
  return info.totalBytes / 1024;
#elif defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  const lfs_config* config = _getContactsChannelsFS()->_getFS()->cfg;
  int totalBytes = config->block_size * config->block_count;
  return totalBytes / 1024;
#else
  return 0;
#endif
}

File DataStore::openRead(const char* filename) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  return _fs->open(filename, FILE_O_READ);
#elif defined(RP2040_PLATFORM)
  return _fs->open(filename, "r");
#else
  return _fs->open(filename, "r", false);
#endif
}

File DataStore::openRead(FILESYSTEM* fs, const char* filename) const {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  return fs->open(filename, FILE_O_READ);
#elif defined(RP2040_PLATFORM)
  return fs->open(filename, "r");
#else
  return fs->open(filename, "r", false);
#endif
}

bool DataStore::removeFile(const char* filename) {
  if (_destructive_writes_disallowed_) return false;  // OTA trial/unknown boot: zero writes/deletes.
  return _fs->remove(filename);
}

bool DataStore::removeFile(FILESYSTEM* fs, const char* filename) {
  if (_destructive_writes_disallowed_) return false;  // OTA trial/unknown boot: zero writes/deletes.
  return fs->remove(filename);
}

bool DataStore::formatFileSystem() {
  // Deliberately NOT _destructive_writes_disallowed_: format authority is
  // a genuinely separate permit from ordinary userdata read/write -- see
  // DataStore.h's _format_disallowed_ doc comment.
  if (_format_disallowed_) return false;  // No explicit, separately-verified format authority for this boot.
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  if (_fsExtra == nullptr) {
    return _fs->format();
  } else {
    return _fs->format() && _fsExtra->format();
  }
#elif defined(RP2040_PLATFORM)
  return LittleFS.format();
#elif defined(ESP32)
  bool fs_success = ((fs::SPIFFSFS *)_fs)->format();
  esp_err_t nvs_err = nvs_flash_erase(); // no need to reinit, will be done by reboot
  return fs_success && (nvs_err == ESP_OK);
#else
  #error "need to implement format()"
#endif
}

bool DataStore::loadMainIdentity(mesh::LocalIdentity &identity) {
  return identity_store.load("_main", identity);
}

bool DataStore::saveMainIdentity(const mesh::LocalIdentity &identity) {
  // See ota_write_gate::guardedPersist()'s contract: identity_store.save()
  // is never invoked at all during a policy-refused write.
  return ota_write_gate::guardedPersist(_destructive_writes_disallowed_,
                                        [&]() { return identity_store.save("_main", identity); });
}

bool DataStore::loadPrefs(NodePrefs& prefs, bool allow_migration_write) {
  if (_fs->exists("/prefs.json")) {
    File file = openRead(_fs, "/prefs.json");
    if (!file) return false;  // exists() said yes but the open genuinely failed.
    const bool ok = prefs.loadSerial(file);   // new Serial prefs -- real decode outcome, never discarded.
    file.close();
    return ok;
  } else if (_fs->exists("/new_prefs")) {
    // Decode the legacy format into `prefs` (this boot's RAM working
    // state) -- loadPrefsInt() itself never partially commits fields on
    // a genuine read fault, see its own comment. A read failure here is
    // real trial-boot-health evidence either way.
    if (!loadPrefsInt("/new_prefs", prefs)) return false;
    if (!allow_migration_write) {
      // OTA trial/unknown boot: the legacy file is still usable in RAM
      // this boot, but writing the new-format migration file is a
      // persisted-state change that must not happen until this boot is
      // known-Normal -- zero writes, original /new_prefs untouched.
      return true;
    }
    if (savePrefs(prefs)) {                // save to new format
      //_fs->remove("/new_prefs"); // remove old
    }
    return true;  // legacy migration path: unchanged best-effort behavior.
  }
  return true;  // legitimately nothing persisted yet -- fresh device, not a fault.
}

bool DataStore::loadPrefsInt(const char *filename, NodePrefs& prefs) {
  File file = openRead(_fs, filename);
  if (!file) return false;  // genuine open failure.

  // Delegates the actual field-by-field decode to the shared,
  // Arduino/NodePrefs-independent datastore_io::readLegacyPrefsFields()
  // (see DataStoreRecordCodec.h) -- the EXACT SAME logic native host
  // tests exercise against a byte-backed fake File, not a second
  // hand-rolled reimplementation. `fields` is a purely local working
  // copy; NEVER a whole-struct NodePrefs copy (NodePrefs::radio holds a
  // private `_parent` back-pointer to its OWNING NodePrefs instance,
  // which such a copy would corrupt to dangle at a destroyed temporary).
  //
  // Pre-seed `fields` from the CURRENT `prefs` values first: this format
  // has grown field-by-field across many commits, so an older, shorter
  // -- but otherwise valid -- file legitimately ends exactly at a field
  // boundary. readLegacyPrefsFields() leaves every field beyond that
  // point untouched in `fields`, matching the original hand-written
  // loader's tolerant behaviour (plain sequential file.read() calls,
  // return value ignored) of silently keeping prior/default values for
  // fields a legacy file doesn't contain, instead of rejecting the
  // whole read.
  datastore_io::LegacyPrefsFields fields;
  fields.airtime_factor = prefs.airtime_factor;
  memcpy(fields.node_name, prefs.node_name, sizeof(fields.node_name));
  fields.node_lat = prefs.node_lat;
  fields.node_lon = prefs.node_lon;
  fields.freq = prefs.freq;
  fields.sf = prefs.sf;
  fields.cr = prefs.cr;
  fields.client_repeat = prefs._client_repeat;
  fields.manual_add_contacts = prefs.manual_add_contacts;
  fields.bw = prefs.bw;
  fields.tx_power_dbm = prefs.tx_power_dbm;
  fields.telemetry_mode_base = prefs.telemetry_mode_base;
  fields.telemetry_mode_loc = prefs.telemetry_mode_loc;
  fields.telemetry_mode_env = prefs.telemetry_mode_env;
  fields.rx_delay_base = prefs.rx_delay_base;
  fields.advert_loc_policy = prefs.advert_loc_policy;
  fields.multi_acks = prefs.multi_acks;
  fields.path_hash_mode = prefs.path_hash_mode;
  fields.ble_pin = prefs.ble_pin;
  fields.buzzer_quiet = prefs.buzzer_quiet;
  fields.gps_enabled = prefs.gps_enabled;
  fields.gps_interval = prefs.gps_interval;
  fields.autoadd_config = prefs.autoadd_config;
  fields.autoadd_max_hops = prefs.autoadd_max_hops;
  fields.rx_boosted_gain = prefs.rx_boosted_gain;
  memcpy(fields.default_scope_name, prefs.default_scope_name, sizeof(fields.default_scope_name));
  memcpy(fields.default_scope_key, prefs.default_scope_key, sizeof(fields.default_scope_key));

  const bool ok = datastore_io::readLegacyPrefsFields(file, fields);
  file.close();
  if (!ok) return false;  // genuine mid-field short/partial read: prefs left untouched.

  // Commit the working copy into the real `prefs` fields individually
  // (safe: these are scalar/array field assignments, never a
  // whole-struct NodePrefs copy-assignment). Either every field matched
  // the file (full/current format), or the file legitimately ended
  // early (older/shorter format) and the not-read tail above still
  // holds the pre-seeded prior value -- both cases commit cleanly here.
  prefs.airtime_factor = fields.airtime_factor;
  memcpy(prefs.node_name, fields.node_name, sizeof(fields.node_name));
  prefs.node_lat = fields.node_lat;
  prefs.node_lon = fields.node_lon;
  prefs.freq = fields.freq;
  prefs.sf = fields.sf;
  prefs.cr = fields.cr;
  prefs._client_repeat = fields.client_repeat;
  prefs.manual_add_contacts = fields.manual_add_contacts;
  prefs.bw = fields.bw;
  prefs.tx_power_dbm = fields.tx_power_dbm;
  prefs.telemetry_mode_base = fields.telemetry_mode_base;
  prefs.telemetry_mode_loc = fields.telemetry_mode_loc;
  prefs.telemetry_mode_env = fields.telemetry_mode_env;
  prefs.rx_delay_base = fields.rx_delay_base;
  prefs.advert_loc_policy = fields.advert_loc_policy;
  prefs.multi_acks = fields.multi_acks;
  prefs.path_hash_mode = fields.path_hash_mode;
  prefs.ble_pin = fields.ble_pin;
  prefs.buzzer_quiet = fields.buzzer_quiet;
  prefs.gps_enabled = fields.gps_enabled;
  prefs.gps_interval = fields.gps_interval;
  prefs.autoadd_config = fields.autoadd_config;
  prefs.autoadd_max_hops = fields.autoadd_max_hops;
  prefs.rx_boosted_gain = fields.rx_boosted_gain;
  memcpy(prefs.default_scope_name, fields.default_scope_name, sizeof(fields.default_scope_name));
  memcpy(prefs.default_scope_key, fields.default_scope_key, sizeof(fields.default_scope_key));

  // migrate old fields
  prefs.setRepeatEn(prefs._client_repeat != 0);

  return true;
}

bool DataStore::savePrefs(NodePrefs& _prefs) {
  return ota_write_gate::guardedPersist(_destructive_writes_disallowed_, [&]() {
    File file = openWrite(_fs, "/prefs.json");
    if (file) {
      bool success = _prefs.saveSerial(file);
      file.close();
      return success;
    }
    return false;
  });
}

bool DataStore::probeStorageReadiness(mesh::LocalIdentity& current_identity) const {
  // "_main.id" is a MANDATORY artifact, not an optional one:
  // MyMesh::begin() unconditionally creates and saves it (if not already
  // present) strictly BEFORE the trial-health monitor is even
  // constructed, so by the time this probe ever runs during a live
  // trial window its absence, an unreadable/short read, OR a well-
  // formed-but-WRONG persisted identity is unconditionally a genuine
  // storage fault -- never a legitimate "nothing saved yet" case (unlike
  // prefs.json/contacts/channels below, which a freshly-formatted device
  // may legitimately never have saved). identity_store.checkIntegrity()
  // performs its own direct, bounded, single-shot File::read() (never
  // Stream::readBytes(), which can block on a short/stalled file) and
  // compares the persisted key bytes against the identity ACTUALLY
  // currently in RAM -- never merely a read-length check -- and is
  // side-effect-free (a pure read, never a write).
  if (!identity_store.checkIntegrity("_main", current_identity)) return false;

  if (!_fs->exists("/prefs.json")) {
    // Legitimately nothing to check yet (freshly-formatted device that
    // has never saved prefs, or still on the old /new_prefs format) --
    // absence of an optional file is NOT evidence of an IO fault.
    return true;
  }
  File file = openRead(_fs, "/prefs.json");
  if (!file) return false;  // exists() said yes but the open genuinely failed.
  file.close();
  return true;
}

bool DataStore::loadContacts(DataStoreHost* host) {
  FILESYSTEM* fs = _getContactsChannelsFS();
  if (!fs->exists("/contacts3")) return true;  // legitimately nothing persisted yet -- not a fault.
  File file = openRead(fs, "/contacts3");
  if (!file) return false;  // exists() said yes but the open genuinely failed.

  // Delegates to the shared, Arduino-type-agnostic template in
  // DataStoreRecordCodec.h -- the SAME field-read-order/clean-EOF-vs-
  // genuine-fault decision logic native host tests exercise directly
  // against a byte-backed fake File, not a second reimplementation.
  const bool ok = datastore_io::readAllContacts(file, host);
  file.close();
  return ok;
}

bool DataStore::saveContacts(DataStoreHost* host, bool (*filter)(const ContactInfo& c)) {
  return ota_write_gate::guardedPersist(_destructive_writes_disallowed_, [&]() {
    File file = openWrite(_getContactsChannelsFS(), "/contacts3");
    if (!file) return false;  // genuine open failure -- distinct from a legitimately empty contact list.

    // Delegates to the shared, Arduino-type-agnostic template in
    // DataStoreRecordCodec.h -- the SAME field-write-order/stop-on-first-
    // failure decision logic native host tests exercise directly against
    // a byte-backed fake File, not a second reimplementation.
    const bool all_ok = datastore_io::writeAllContacts(file, host, filter);
    file.close();
    return all_ok;
  });
}

bool DataStore::loadChannels(DataStoreHost* host) {
  FILESYSTEM* fs = _getContactsChannelsFS();
  if (!fs->exists("/channels2")) return true;  // legitimately nothing persisted yet -- not a fault.
  File file = openRead(fs, "/channels2");
  if (!file) return false;  // exists() said yes but the open genuinely failed.

  uint8_t channel_idx = 0;
  // Delegates to the shared, Arduino-type-agnostic template in
  // DataStoreRecordCodec.h -- see loadContacts() above.
  const bool ok = datastore_io::readAllChannels(file, host, channel_idx);
  file.close();
  return ok;
}

bool DataStore::saveChannels(DataStoreHost* host) {
  return ota_write_gate::guardedPersist(_destructive_writes_disallowed_, [&]() {
    File file = openWrite(_getContactsChannelsFS(), "/channels2");
    if (!file) return false;  // genuine open failure -- distinct from a legitimately empty channel list.

    // Delegates to the shared, Arduino-type-agnostic template in
    // DataStoreRecordCodec.h -- see saveContacts() above.
    const bool all_ok = datastore_io::writeAllChannels(file, host);
    file.close();
    return all_ok;
  });
}

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)

#define MAX_ADVERT_PKT_LEN   (2 + 32 + PUB_KEY_SIZE + 4 + SIGNATURE_SIZE + MAX_ADVERT_DATA_SIZE)

struct BlobRec {
  uint32_t timestamp;
  uint8_t  key[7];
  uint8_t  len;
  uint8_t  data[MAX_ADVERT_PKT_LEN];
};

#define BLOB_KEY_PREFIX_LEN  7  // sizeof(BlobRec::key)

void DataStore::checkAdvBlobFile() {
  // Defense-in-depth backstop, same discipline as migrateToSecondaryFS():
  // an OTA trial/unknown boot must never create/preallocate this file,
  // even though this method's other call site (putBlobByKey) is already
  // gated by guardedPersist() -- begin() calls this unconditionally, so
  // the check must live here too, not merely at that other call site.
  if (_destructive_writes_disallowed_) return;
  if (!_getContactsChannelsFS()->exists("/adv_blobs")) {
    File file = openWrite(_getContactsChannelsFS(), "/adv_blobs");
    if (file) {
      BlobRec zeroes;
      memset(&zeroes, 0, sizeof(zeroes));
      for (int i = 0; i < MAX_BLOBRECS; i++) {     // pre-allocate to fixed size
        file.write((uint8_t *) &zeroes, sizeof(zeroes));
      }
      file.close();
    }
  }
}

void DataStore::migrateToSecondaryFS() {
  // Defense-in-depth backstop: begin() already gates its one call site
  // on `allow_destructive_writes`, but this guards against ANY future
  // caller too -- an OTA trial/unknown boot must never run this
  // unconditional copy-then-delete migration.
  if (_destructive_writes_disallowed_) return;
  // migrate old adv_blobs, contacts3 and channels2 files to secondary FS if they don't already exist
  if (!_fsExtra->exists("/adv_blobs")) {
    if (_fs->exists("/adv_blobs")) {
    File oldAdvBlobs = openRead(_fs, "/adv_blobs");
    File newAdvBlobs = openWrite(_fsExtra, "/adv_blobs");

    if (oldAdvBlobs && newAdvBlobs) {
      BlobRec rec;
      size_t count = 0;

      // Copy 20 BlobRecs from old to new
      while (count < 20 && oldAdvBlobs.read((uint8_t *)&rec, sizeof(rec)) == sizeof(rec)) {
        newAdvBlobs.seek(count * sizeof(BlobRec));
        newAdvBlobs.write((uint8_t *)&rec, sizeof(rec));
        count++;
      }
    }
    if (oldAdvBlobs) oldAdvBlobs.close();
    if (newAdvBlobs) newAdvBlobs.close();
    _fs->remove("/adv_blobs");
    }
  }
  if (!_fsExtra->exists("/contacts3")) {
    if (_fs->exists("/contacts3")) {
      File oldFile = openRead(_fs, "/contacts3");
      File newFile = openWrite(_fsExtra, "/contacts3");

      if (oldFile && newFile) {
        uint8_t buf[64];
        int n;
        while ((n = oldFile.read(buf, sizeof(buf))) > 0) {
          newFile.write(buf, n);
        }
      }
      if (oldFile) oldFile.close();
      if (newFile) newFile.close();
      _fs->remove("/contacts3");
    }
  }
  if (!_fsExtra->exists("/channels2")) {
    if (_fs->exists("/channels2")) {
      File oldFile = openRead(_fs, "/channels2");
      File newFile = openWrite(_fsExtra, "/channels2");

      if (oldFile && newFile) {
        uint8_t buf[64];
        int n;
        while ((n = oldFile.read(buf, sizeof(buf))) > 0) {
          newFile.write(buf, n);
        }
      }
      if (oldFile) oldFile.close();
      if (newFile) newFile.close();
      _fs->remove("/channels2");
    }
  }
  // cleanup nodes which have been testing the extra fs, copy _main.id and new_prefs back to primary
  if (_fsExtra->exists("/_main.id")) {
      if (_fs->exists("/_main.id")) {_fs->remove("/_main.id");}
      File oldFile = openRead(_fsExtra, "/_main.id");
      File newFile = openWrite(_fs, "/_main.id");

      if (oldFile && newFile) {
        uint8_t buf[64];
        int n;
        while ((n = oldFile.read(buf, sizeof(buf))) > 0) {
          newFile.write(buf, n);
        }
      }
      if (oldFile) oldFile.close();
      if (newFile) newFile.close();
      _fsExtra->remove("/_main.id");
  }
  if (_fsExtra->exists("/new_prefs")) {
    if (_fs->exists("/new_prefs")) {_fs->remove("/new_prefs");}
      File oldFile = openRead(_fsExtra, "/new_prefs");
      File newFile = openWrite(_fs, "/new_prefs");

      if (oldFile && newFile) {
        uint8_t buf[64];
        int n;
        while ((n = oldFile.read(buf, sizeof(buf))) > 0) {
          newFile.write(buf, n);
        }
      }
      if (oldFile) oldFile.close();
      if (newFile) newFile.close();
      _fsExtra->remove("/new_prefs");
  }
  // remove files from where they should not be anymore
  if (_fs->exists("/adv_blobs")) {
    _fs->remove("/adv_blobs");
  }
  if (_fs->exists("/contacts3")) {
    _fs->remove("/contacts3");
  }
  if (_fs->exists("/channels2")) {
    _fs->remove("/channels2");
  }
  if (_fsExtra->exists("/_main.id")) {
    _fsExtra->remove("/_main.id");
  }
  if (_fsExtra->exists("/new_prefs")) {
    _fsExtra->remove("/new_prefs");
  }
}

uint8_t DataStore::getBlobByKey(const uint8_t key[], int key_len, uint8_t dest_buf[]) {
  File file = openRead(_getContactsChannelsFS(), "/adv_blobs");
  uint8_t len = 0;  // 0 = not found
  if (file) {
    // Delegates the scan itself to the shared
    // datastore_io::scanBlobRecordsForKey() (see DataStoreRecordCodec.h)
    // -- the EXACT SAME clean-EOF-vs-genuine-fault provenance logic
    // native host tests exercise against a byte-backed fake File and a
    // plain POD fake record, not a second hand-rolled reimplementation.
    // A fault here means this store's contents could not be fully and
    // reliably scanned for `key`, so it is latched separately via
    // _blob_io_fault_observed rather than silently reported as
    // "not found" through this uint8_t return alone.
    bool found = false, fault = false;
    datastore_io::scanBlobRecordsForKey<File, BlobRec>(file, key, BLOB_KEY_PREFIX_LEN, found, len, dest_buf, fault);
    if (fault) _blob_io_fault_observed = true;
    file.close();
  }
  return len;
}

bool DataStore::putBlobByKey(const uint8_t key[], int key_len, const uint8_t src_buf[], uint8_t len) {
  return ota_write_gate::guardedPersist(_destructive_writes_disallowed_, [&]() {
    if (len < PUB_KEY_SIZE+4+SIGNATURE_SIZE || len > MAX_ADVERT_PKT_LEN) return false;
    checkAdvBlobFile();
    File file = _getContactsChannelsFS()->open("/adv_blobs", FILE_O_WRITE);
    if (file) {
      if (!file.seek(0)) {
        _blob_io_fault_observed = true;
        file.close();
        return false;
      }

      // search for matching key OR evict by oldest timestamp, via the
      // same shared datastore_io::scanBlobRecordsForWritePosition() the
      // native tests exercise -- a scan fault here means the eviction/
      // match decision itself cannot be trusted, so this aborts (writes
      // nothing) rather than risk clobbering the wrong record.
      bool matched = false, fault = false;
      uint32_t found_pos = 0;
      datastore_io::scanBlobRecordsForWritePosition<File, BlobRec>(file, key, BLOB_KEY_PREFIX_LEN, matched, found_pos, fault);
      if (fault) {
        _blob_io_fault_observed = true;
        file.close();
        return false;
      }

      BlobRec tmp;
      memcpy(tmp.key, key, sizeof(tmp.key));  // just record 7 byte prefix of key
      memcpy(tmp.data, src_buf, len);
      tmp.len = len;
      tmp.timestamp = _clock->getCurrentTime();

      bool write_ok = file.seek(found_pos);
      if (write_ok) write_ok = (file.write((uint8_t *) &tmp, sizeof(tmp)) == sizeof(tmp));

      file.close();
      if (!write_ok) {
        _blob_io_fault_observed = true;
        return false;
      }
      return true;
    }
    return false; // error
  });
}
bool DataStore::deleteBlobByKey(const uint8_t key[], int key_len) {
  return ota_write_gate::guardedPersist(_destructive_writes_disallowed_,
                                        [&]() { return true; });  // this is just a stub on NRF52/STM32 platforms
}
#else
inline void makeBlobPath(const uint8_t key[], int key_len, char* path, size_t path_size) {
  char fname[18];
  if (key_len > 8) key_len = 8; // just use first 8 bytes (prefix)
  mesh::Utils::toHex(fname, key, key_len);
  sprintf(path, "/bl/%s", fname);
}

uint8_t DataStore::getBlobByKey(const uint8_t key[], int key_len, uint8_t dest_buf[]) {
  char path[64];
  makeBlobPath(key, key_len, path, sizeof(path));

  if (_fs->exists(path)) {
    File f = openRead(_fs, path);
    if (!f) {
      _blob_io_fault_observed = true;  // exists() said yes but the open genuinely failed.
      return 0;
    }
    int len = f.read(dest_buf, 255); // currently MAX 255 byte blob len supported!!
    f.close();
    if (len < 0) {
      // Genuine read fault (negative status), distinct from a
      // legitimately empty (0-byte) blob.
      _blob_io_fault_observed = true;
      return 0;
    }
    return (uint8_t)len;
  }
  return 0; // not found
}

bool DataStore::putBlobByKey(const uint8_t key[], int key_len, const uint8_t src_buf[], uint8_t len) {
  return ota_write_gate::guardedPersist(_destructive_writes_disallowed_, [&]() {
    char path[64];
    makeBlobPath(key, key_len, path, sizeof(path));

    File f = openWrite(_fs, path);
    if (!f) {
      _blob_io_fault_observed = true;  // genuine open-for-write failure.
      return false;
    }
    int n = f.write(src_buf, len);
    f.close();
    if (n == len) return true; // success!

    _blob_io_fault_observed = true;  // blob was only partially written!
    _fs->remove(path);
    return false; // error
  });
}

bool DataStore::deleteBlobByKey(const uint8_t key[], int key_len) {
  return ota_write_gate::guardedPersist(_destructive_writes_disallowed_, [&]() {
    char path[64];
    makeBlobPath(key, key_len, path, sizeof(path));

    _fs->remove(path);

    return true; // return true even if file did not exist
  });
}
#endif
