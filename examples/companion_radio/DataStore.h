#pragma once

#include <helpers/IdentityStore.h>
#include <helpers/ContactInfo.h>
#include <helpers/ChannelDetails.h>
#include "NodePrefs.h"

class DataStoreHost {
public:
  virtual bool onContactLoaded(const ContactInfo& contact) =0;
  virtual bool getContactForSave(uint32_t idx, ContactInfo& contact) =0;
  virtual bool onChannelLoaded(uint8_t channel_idx, const ChannelDetails& ch) =0;
  virtual bool getChannelForSave(uint8_t channel_idx, ChannelDetails& ch) =0;
};

class DataStore {
  FILESYSTEM* _fs;
  FILESYSTEM* _fsExtra;
  mesh::RTCClock* _clock;
  IdentityStore identity_store;

  // Returns false on a genuine open/read FAULT (failed open, or a
  // short/partial read of any legacy field) -- decodes into a purely
  // local working copy first; NEVER partially commits into `prefs` on
  // failure. See DataStore.cpp's implementation comment for why this
  // cannot use a whole-struct working copy of NodePrefs itself.
  bool loadPrefsInt(const char *filename, NodePrefs& prefs);
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  void checkAdvBlobFile();
#endif

public:
  DataStore(FILESYSTEM& fs, mesh::RTCClock& clock);
  DataStore(FILESYSTEM& fs, FILESYSTEM& fsExtra, mesh::RTCClock& clock);
  // \param allow_destructive_writes -- when false (an OTA trial/unknown
  // boot -- see MyMesh::begin()/otaBoardEarlyBootTrialOrUnknown()),
  // migrateToSecondaryFS()'s unconditional copy-then-delete migration is
  // SKIPPED entirely (zero writes/deletes, all original files preserved)
  // rather than run against potentially-still-being-validated storage.
  // Defaults to true (unchanged legacy behavior) for every existing
  // caller/build that never passes this (e.g. non-OTA examples).
  // \param allow_format -- a GENUINELY SEPARATE permit from
  // allow_destructive_writes: ordinary userdata Normal proof (read/write
  // of existing prefs/contacts/channels/blobs) must NEVER be inferred as
  // format authority. formatFileSystem() checks ONLY this flag, never
  // _destructive_writes_disallowed_ -- a Normal-but-not-factory-verified
  // boot can read/write existing userdata yet still must not be able to
  // wipe it. Defaults to true (unchanged legacy behavior) for every
  // existing caller/build that never passes this.
  void begin(bool allow_destructive_writes = true, bool allow_format = true);
  // Explicit, separately-queryable policy state (distinct from any
  // individual method's genuine I/O success/failure): true for the rest
  // of this boot once begin(false) has been called. Callers that wrap
  // savePrefs()/saveContacts()/saveChannels()/putBlobByKey()/
  // deleteBlobByKey()/saveMainIdentity() and latch a `false` return as
  // trial-boot-health-fault evidence MUST check this FIRST -- those
  // methods themselves now return `false` honestly on a policy-refused
  // write (never claim a policy-skip persisted), so a caller that does
  // not consult this predicate would otherwise misread an intentional,
  // expected refusal as a genuine storage fault.
  bool destructiveWritesDisallowed() const { return _destructive_writes_disallowed_; }
  // Separate from destructiveWritesDisallowed(): true whenever this boot
  // was not granted explicit format authority (see allow_format above),
  // REGARDLESS of whether ordinary userdata writes are permitted. A
  // caller (e.g. CMD_FACTORY_RESET) that wants to refuse BEFORE any
  // side effect (like disabling the serial link) should check this
  // FIRST, not formatFileSystem()'s return value alone.
  bool formatDisallowed() const { return _format_disallowed_; }
  bool formatFileSystem();
  FILESYSTEM* getPrimaryFS() const { return _fs; }
  FILESYSTEM* getSecondaryFS() const { return _fsExtra; }
  bool loadMainIdentity(mesh::LocalIdentity &identity);
  bool saveMainIdentity(const mesh::LocalIdentity &identity);
  // Returns false on a genuine open/read FAULT (an existing, mandatory-
  // format /prefs.json that can't be opened, or whose loadSerial() genuinely
  // fails to decode); true both on a clean, expected "nothing persisted yet"
  // (fresh device) AND on a genuine successful load -- callers that need to
  // distinguish trial-boot-health faults from ordinary first-boot state
  // check this return value (see MyMesh::begin()).
  // \param allow_migration_write -- when false (OTA trial/unknown boot),
  // a legacy /new_prefs file is still READ (decoded into RAM this boot,
  // so an otherwise-healthy node keeps working) but the migration WRITE
  // to the new /prefs.json format -- and therefore any persisted-state
  // change at all -- is skipped; legacy read failure still reports
  // false either way. Defaults to true (unchanged legacy behavior).
  bool loadPrefs(NodePrefs& prefs, bool allow_migration_write = true);
  bool savePrefs(NodePrefs& prefs);
  // Returns false on a genuine mid-record read FAULT (a partial/short
  // read after at least one field -- or the very first field -- of a
  // record was found to be non-empty but incomplete), distinct from a
  // clean end-of-file with zero or more COMPLETE records already
  // delivered to `host`. See datastore_io::readAllContacts().
  bool loadContacts(DataStoreHost* host);
  bool saveContacts(DataStoreHost* host, bool (*filter)(const ContactInfo& c) = NULL);
  // Same clean-EOF-vs-genuine-fault distinction as loadContacts() above.
  // See datastore_io::readAllChannels().
  bool loadChannels(DataStoreHost* host);
  bool saveChannels(DataStoreHost* host);
  void migrateToSecondaryFS();
  uint8_t getBlobByKey(const uint8_t key[], int key_len, uint8_t dest_buf[]);
  bool putBlobByKey(const uint8_t key[], int key_len, const uint8_t src_buf[], uint8_t len);
  bool deleteBlobByKey(const uint8_t key[], int key_len);
  File openRead(const char* filename);
  File openRead(FILESYSTEM* fs, const char* filename) const;
  bool removeFile(const char* filename);
  bool removeFile(FILESYSTEM* fs, const char* filename);
  uint32_t getStorageUsedKb() const;
  uint32_t getStorageTotalKb() const;

  /**
   * \brief  bounded, side-effect-free readiness probe: (1) a genuine
   *         MANDATORY-artifact integrity check of the main identity file
   *         via IdentityStore::checkIntegrity() -- a direct, bounded
   *         File::read() (never Stream::readBytes(), which can block up
   *         to ~1s on a short/stalled file) that compares the persisted
   *         key bytes against the identity actually currently in RAM, so
   *         a well-formed-but-WRONG/stale/foreign persisted identity is
   *         correctly reported as a fault, not merely a length-only
   *         check; then (2) a genuine read-only open (immediately closed,
   *         no content read/written) of the real node-preferences file if
   *         one exists. Returns false on either an actual open/read
   *         failure or an integrity mismatch -- an absent prefs file
   *         (e.g. a freshly-formatted device that has never saved prefs
   *         yet) is a legitimate, non-error condition and is reported as
   *         healthy (true), never fabricated as a fault. Safe to call
   *         repeatedly (e.g. every OTA trial-health tick): it never
   *         writes anything.
   * \param  current_identity IN - the identity actually active in RAM
   *         right now, to compare the persisted mandatory artifact
   *         against (never logged).
  */
  bool probeStorageReadiness(mesh::LocalIdentity& current_identity) const;

  /**
   * \brief  true once getBlobByKey()/putBlobByKey() has observed a
   *         genuine I/O fault (a failed open on an already-established
   *         store, a mid-record/short read or write, or a failed
   *         seek/write) this boot. getBlobByKey()'s uint8_t-length and
   *         putBlobByKey()'s bool return values cannot, by themselves,
   *         distinguish a genuine fault from an ordinary "key not
   *         found"/legitimate outcome without an ABI change -- this is a
   *         separate, out-of-band observable signal for that, mirroring
   *         otaBoardStorageIoFaultObserved()'s pattern. Monotonic for the
   *         lifetime of this object (never cleared): callers needing
   *         trial-boot-health evidence should latch it into their own
   *         cross-tick state exactly like the existing filesystem-fault
   *         signals (see MyMesh::tickOtaTrialHealth()).
  */
  bool blobIoFaultObserved() const { return _blob_io_fault_observed; }

private:
  FILESYSTEM* _getContactsChannelsFS() const { if (_fsExtra) return _fsExtra; return _fs;};
  bool _blob_io_fault_observed = false;
  // Set once in begin() from `allow_destructive_writes` and latched for
  // this object's ENTIRE lifetime (a whole boot -- never cleared until a
  // real reboot creates a new DataStore instance): an OTA trial/unknown
  // boot must not perform ANY normal userdata write, not merely skip the
  // one migration step begin() itself already gated. Every write-capable
  // method below (saveMainIdentity/savePrefs/saveContacts/saveChannels/
  // putBlobByKey/deleteBlobByKey/removeFile) checks this first and
  // performs zero I/O if set, regardless of which later runtime code
  // path (periodic autosave, CLI admin commands, etc.) calls it -- not
  // just the startup save guard. formatFileSystem() does NOT consult
  // this flag (see _format_disallowed_ below) -- userdata-write
  // permission must never imply format authority.
  bool _destructive_writes_disallowed_ = false;
  // Latched for this object's entire lifetime by begin(_, allow_format):
  // true unless explicit, separately-verified format authority was
  // granted. formatFileSystem() checks ONLY this flag -- independent of
  // _destructive_writes_disallowed_, so a userdata-Normal boot with no
  // factory/repair evidence still cannot wipe the filesystem.
  bool _format_disallowed_ = false;
};
