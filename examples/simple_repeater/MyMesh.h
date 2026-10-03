#pragma once

#include <Arduino.h>
#include <Mesh.h>
#include <RTClib.h>
#include <target.h>

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  #include <InternalFileSystem.h>
#elif defined(RP2040_PLATFORM)
  #include <LittleFS.h>
#elif defined(ESP32)
  #include <SPIFFS.h>
  using File = fs::File;
#endif

#ifdef WITH_RS232_BRIDGE
#include "helpers/bridges/RS232Bridge.h"
#define WITH_BRIDGE
#endif

#ifdef WITH_ESPNOW_BRIDGE
#include "helpers/bridges/ESPNowBridge.h"
#define WITH_BRIDGE
#endif

#include <helpers/AdvertDataHelpers.h>
#include <helpers/ArduinoHelpers.h>
#include <helpers/ClientACL.h>
#include <helpers/CommonCLI.h>
#include <helpers/IdentityStore.h>
#include <helpers/SimpleMeshTables.h>
#include <helpers/StaticPoolPacketManager.h>
#include <helpers/TemporaryRadioLease.h>
#include <helpers/StatsFormatHelper.h>
#include <helpers/TxtDataHelpers.h>
#include <helpers/RegionMap.h>
#include <helpers/RoutingPolicy.h>
#include "RateLimiter.h"
#include "RepeaterPrefs.h"

#if MESHCORE_LORA_OTA
#include <helpers/ota/OtaFirmwareService.h>
#include <helpers/ota/OtaMeshTrialHealthTick.h>
#endif

#if MESHCORE_LORA_OTA && MESHCORE_OTA_LAB_BACKEND && defined(NRF52_PLATFORM) && \
    defined(NRF52840_XXAA) && defined(_SEEED_XIAO_NRF52840_H_) && defined(ENABLE_USB_INTERFACE)
#define XIAO_OTA_USB_LAB_CLI 1
#endif

#ifdef WITH_BRIDGE
extern AbstractBridge* bridge;
#endif

struct RepeaterStats {
  uint16_t batt_milli_volts;
  uint16_t curr_tx_queue_len;
  int16_t  noise_floor;
  int16_t  last_rssi;
  uint32_t n_packets_recv;
  uint32_t n_packets_sent;
  uint32_t total_air_time_secs;
  uint32_t total_up_time_secs;
  uint32_t n_sent_flood, n_sent_direct;
  uint32_t n_recv_flood, n_recv_direct;
  uint16_t err_events;                // was 'n_full_events'
  int16_t  last_snr;   // x 4
  uint16_t n_direct_dups, n_flood_dups;
  uint32_t total_rx_air_time_secs;
  uint32_t n_recv_errors;
};

#ifndef MAX_CLIENTS
  #define MAX_CLIENTS           32
#endif

struct NeighbourInfo {
  mesh::Identity id;
  uint32_t advert_timestamp;
  uint32_t heard_timestamp;
  int8_t snr; // multiplied by 4, user should divide to get float value
};

#ifndef FIRMWARE_BUILD_DATE
  #define FIRMWARE_BUILD_DATE   "14 Aug 2026"
#endif

#ifndef FIRMWARE_VERSION
  #define FIRMWARE_VERSION   "v1.17.1"
#endif

#define FIRMWARE_ROLE "repeater"

#define PACKET_LOG_FILE  "/packet_log"

class MyMesh : public mesh::Mesh, public CommonCLICallbacks {
  FILESYSTEM* _fs;
  const char* _prefs_filename = kRepeaterPrefsFilename;
  uint32_t last_millis;
  uint64_t uptime_millis;
  unsigned long next_local_advert, next_flood_advert;
  bool _logging;
  NodePrefs _prefs;
  ClientACL  acl;
  CommonCLI _cli;
  uint8_t reply_data[MAX_PACKET_PAYLOAD];
  uint8_t reply_path[MAX_PATH_SIZE];
  uint8_t reply_path_len;
  TransportKeyStore key_store;
  RegionMap region_map, temp_map;
  RegionEntry* load_stack[8];
  RegionEntry* recv_pkt_region;
  TransportKey default_scope;
  RateLimiter discover_limiter, anon_limiter;
  uint32_t pending_discover_tag;
  unsigned long pending_discover_until;
  bool region_load_active;
  unsigned long dirty_contacts_expiry;
#if MAX_NEIGHBOURS
  NeighbourInfo neighbours[MAX_NEIGHBOURS];
#endif
  CayenneLPP telemetry;
  mesh::TemporaryRadioLease _temporary_radio_lease;
  float pending_freq;
  float pending_bw;
  uint8_t pending_sf;
  uint8_t pending_cr;
  int  matching_peer_indexes[MAX_CLIENTS];
#if defined(WITH_RS232_BRIDGE)
  RS232Bridge bridge;
#elif defined(WITH_ESPNOW_BRIDGE)
  ESPNowBridge bridge;
#endif

  // Mirrors examples/companion_radio/MyMesh.h's `_identity_available_`
  // degraded-dispatch flag byte-for-byte (same default, same meaning):
  // false only when main.cpp's setup() hit a genuine identity-load
  // failure (ota_identity_boot::Outcome::IdentityUnavailable) and chose
  // to perform ZERO generation/writes rather than halt() -- see
  // notifyIdentityUnavailableForDispatch() below. loop() uses this to
  // suppress ordinary mesh dispatch (identity-dependent TX/signing/
  // advert) entirely, keeping only the bounded serial/CLI/maintenance/
  // trial-health path running, rather than operating on an unset
  // identity. Unconditional (not MESHCORE_LORA_OTA-gated), same as
  // companion's, since a non-OTA build's identity-generation permission
  // is always granted and essentially never reaches this state.
  bool _identity_available_ = true;
  // Repeater-specific (companion has no equivalent): false only when
  // this boot's radio_init() genuinely failed. Previously main.cpp
  // halt()ed in that case, stranding the serial/CLI/maintenance path
  // along with RF dispatch; gates the same set of real RF-touching
  // begin()/loop() operations as _identity_available_ so the device can
  // still serve USB maintenance/CLI/OTA-trial-health with radio absent.
  bool _radio_available_ = true;

  // Mirrors companion_radio's DataStore::_destructive_writes_disallowed_
  // (same OtaWriteGate.h contract, same meaning): true only during an
  // OTA trial/unknown boot (ota_allow_destructive_boot_writes computed
  // in main.cpp's setup() via otaBoardEarlyBootTrialOrUnknown()), set
  // once via notifyDestructiveWritesDisallowed() below. Repeater has no
  // DataStore-equivalent wrapper, so loop()'s own acl.save(_fs) call
  // must consult this flag directly (via ota_write_gate::guardedPersist)
  // rather than unconditionally mutating storage and mislabeling a
  // policy-refused write as persisted. Unconditional (not
  // MESHCORE_LORA_OTA-gated) so it compiles identically whether or not
  // OTA is enabled; defaults to false (writes allowed) for ordinary
  // non-OTA builds.
  bool _ota_destructive_writes_disallowed_ = false;

#if MESHCORE_LORA_OTA
  // Mirrors examples/companion_radio/MyMesh.h's identically-named/
  // purposed members byte-for-byte (see that header's doc comments);
  // the DECISION logic both boards drive is the same shared function
  // (helpers/ota/OtaMeshTrialHealthTick.h) -- only this per-instance
  // latched state is necessarily duplicated, since MyMesh here and
  // companion_radio's MyMesh are unrelated C++ classes.
  bool _ota_trial_radio_ready = false;
  bool _ota_trial_filesystem_ready = false;
  bool _ota_trial_reboot_issued = false;
  // Single authoritative owner of the latched filesystem-fault and
  // identity-confirmed-loaded facts previously tracked as two separate
  // role-local bools here (see helpers/ota/OtaFirmwareService.h) -- fed
  // real outcomes via notifyOtaTrialIdentityLoadFault()/
  // notifyOtaIdentityConfirmedLoaded() below (called from main.cpp,
  // which is where this board's identity load/generate/save actually
  // happens) and consumed read-only by tickOtaTrialHealth().
  mesh::ota::OtaFirmwareService _ota_service_;
  uint32_t _ota_trial_last_radio_fault_count_ = 0;

#if XIAO_OTA_USB_LAB_CLI
  bool _uf2_reboot_pending = false;
  uint32_t _uf2_reboot_due_ms = 0, _uf2_reboot_queue_deadline_ms = 0;
  bool uf2RebootAllowed();
#endif

  bool isRadioStuckOutOfRecv(uint32_t now_ms);
  // Astra's correction: boot-mount success + the board-level storage-
  // fault latch alone is stale evidence beyond the exact tick a user
  // happens to trigger a real write -- mirrors companion_radio's
  // DataStore::probeStorageReadiness(), but against repeater's plain
  // IdentityStore (no DataStore-equivalent persistent wrapper here).
  // Bounded, side-effect-free (single IdentityStore::checkIntegrity()
  // read against the identity ACTUALLY in RAM, plus a prefs-file open-
  // then-immediately-close, never a write): see
  // probeIdentityStorageReadiness()'s definition for exactly what each
  // outcome means. Returns false (never true) whenever
  // !_identity_available_ -- a probe against an unbound identity would
  // only ever "pass" vacuously, never real evidence.
  bool probeIdentityStorageReadiness() const;
#endif

  void putNeighbour(const mesh::Identity& id, uint32_t timestamp, float snr);
  uint8_t handleLoginReq(const mesh::Identity& sender, const uint8_t* secret, uint32_t sender_timestamp, const uint8_t* data, bool is_flood);
  uint8_t handleAnonRegionsReq(const mesh::Identity& sender, uint32_t sender_timestamp, const uint8_t* data);
  uint8_t handleAnonOwnerReq(const mesh::Identity& sender, uint32_t sender_timestamp, const uint8_t* data);
  uint8_t handleAnonClockReq(const mesh::Identity& sender, uint32_t sender_timestamp, const uint8_t* data);
  int handleRequest(ClientInfo* sender, uint32_t sender_timestamp, uint8_t* payload, size_t payload_len);
  mesh::Packet* createSelfAdvert();

  File openAppend(const char* fname);
  bool isLooped(const mesh::Packet* packet, const uint8_t max_counters[]);

protected:
  float getAirtimeBudgetFactor() const override {
    return _prefs.airtime_factor;
  }

  bool allowPacketForward(const mesh::Packet* packet) override;
  const char* getLogDateTime() override;
  void logRxRaw(float snr, float rssi, const uint8_t raw[], int len) override;

  void logRx(mesh::Packet* pkt, int len, float score) override;
  void logTx(mesh::Packet* pkt, int len) override;
  void logTxFail(mesh::Packet* pkt, int len) override;
  int calcRxDelay(float score, uint32_t air_time) const override;

  uint32_t getRetransmitDelay(const mesh::Packet* packet) override;
  uint32_t getDirectRetransmitDelay(const mesh::Packet* packet) override;

  int getInterferenceThreshold() const override {
    return _prefs.interference_threshold;
  }
  bool getCADEnabled() const override {
    return _prefs.cad_enabled;
  }
  int getAGCResetInterval() const override {
    return ((int)_prefs.agc_reset_interval) * 4000;   // milliseconds
  }
  uint8_t getExtraAckTransmitCount() const override {
    return _prefs.multi_acks;
  }

#if ENV_INCLUDE_GPS == 1
  void applyGpsPrefs() {
    sensors.setSettingValue("gps", _prefs.gps_enabled?"1":"0");
  }
#endif

  mesh::DispatcherAction onRecvPacket(mesh::Packet* pkt) override;

  void onAnonDataRecv(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender, uint8_t* data, size_t len) override;
  int searchPeersByHash(const uint8_t* hash) override;
  void getPeerSharedSecret(uint8_t* dest_secret, int peer_idx) override;
  void onAdvertRecv(mesh::Packet* packet, const mesh::Identity& id, uint32_t timestamp, const uint8_t* app_data, size_t app_data_len);
  void onPeerDataRecv(mesh::Packet* packet, uint8_t type, int sender_idx, const uint8_t* secret, uint8_t* data, size_t len) override;
  bool onPeerPathRecv(mesh::Packet* packet, int sender_idx, const uint8_t* secret, uint8_t* path, uint8_t path_len, uint8_t extra_type, uint8_t* extra, uint8_t extra_len) override;
  void onControlDataRecv(mesh::Packet* packet) override;

  void sendFloodReply(mesh::Packet* packet, unsigned long delay_millis, uint8_t path_hash_size);

public:
  MyMesh(mesh::MainBoard& board, mesh::Radio& radio, mesh::MillisecondClock& ms, mesh::RNG& rng, mesh::RTCClock& rtc, mesh::MeshTables& tables);

  void begin(FILESYSTEM* fs);
  void sendNodeDiscoverReq();
  const char* getFirmwareVer() override { return FIRMWARE_VERSION; }
  const char* getBuildDate() override { return FIRMWARE_BUILD_DATE; }
  const char* getRole() override { return FIRMWARE_ROLE; }
  const char* getNodeName() { return _prefs.node_name; }
  NodePrefs* getNodePrefs() {
    return &_prefs;
  }

  void savePrefs() override {
    _cli.savePrefs(_fs, _prefs_filename);
  }

  void sendFloodScoped(const TransportKey& scope, mesh::Packet* pkt, uint32_t delay_millis, uint8_t path_hash_size);

  // CommonCLICallbacks
  void applyTempRadioParams(float freq, float bw, uint8_t sf, uint8_t cr, int timeout_mins) override;
  bool formatFileSystem() override;
  void sendSelfAdvertisement(int delay_millis, bool flood) override;
  void updateAdvertTimer() override;
  void updateFloodAdvertTimer() override;

  void setLoggingOn(bool enable) override { _logging = enable; }

  void eraseLogFile() override {
    _fs->remove(PACKET_LOG_FILE);
  }

  void dumpLogFile() override;
  void setTxPower(int8_t power_dbm) override;
  void formatNeighborsReply(char *reply) override;
  void removeNeighbor(const uint8_t* pubkey, int key_len) override;
  void formatStatsReply(char *reply) override;
  void formatRadioStatsReply(char *reply) override;
  void formatPacketStatsReply(char *reply) override;
  void startRegionsLoad() override;
  bool saveRegions() override;
  void onDefaultRegionChanged(const RegionEntry* r) override;

  mesh::LocalIdentity& getSelfId() override { return self_id; }

  void saveIdentity(const mesh::LocalIdentity& new_id) override;
  void clearStats() override;

  void handleCommand(uint32_t sender_timestamp, char* command, char* reply, bool local_usb = false);
  void loop();

#if MESHCORE_LORA_OTA
  // Real admin control surface reusing the SAME getOtaIntegration()/
  // getOtaStatus()/radio-revert machinery as companion_radio's CMD_OTA_
  // CONTROL binary handler -- reached here only via handleCommand()'s
  // existing gates (local serial trusted-owner, or remote client->
  // isAdmin() already checked by the PAYLOAD_TYPE_TXT_MSG caller before
  // handleCommand() is ever invoked). No new admin/auth mechanism.
  bool setFirmwareOtaMode(const char* mode);
  bool setFirmwareOtaDutyCycle(float percent);
  void abortFirmwareOta();
  void rollbackFirmwareOta();
#if MESHCORE_LORA_OTA
  static void otaSignThunk(void* ctx, const uint8_t* message, size_t len, uint8_t signature[64]);
  static bool otaRadioChangeThunk(void* ctx, uint32_t frequency_khz, bool restore);
  static bool otaBootLifecycleThunk(void* ctx, mesh::ota::OtaBootLifecycleEvidence& out);
  static bool otaBootCandidateThunk(void* ctx, const mesh::ota::OtaBootLifecycleEvidence& boot,
                                    ::ota::storage::OtaCandidateStore::Snapshot& out);
#endif
  void formatFirmwareOtaStatus(char* reply, size_t reply_size);
#if MESHCORE_OTA_USB_MEASUREMENTS
  bool applyMeasuredRadioParams(float freq, float bw, uint8_t sf, uint8_t cr, bool direct);
  bool formatFirmwareOtaMeasurement(uint8_t selector, char* reply, size_t reply_size);
#endif
  bool isOtaAdminKey(const uint8_t key[32]) const;
  static bool otaAdminCheckThunk(void* ctx, const uint8_t key[32]);
#endif

  void applyRadioParams(float freq, float bw, uint8_t sf, uint8_t cr);
  void revertTempRadioLeaseIfDue();

#if defined(WITH_BRIDGE)
  void setBridgeState(bool enable) override {
    if (enable == bridge.isRunning()) return;
    if (enable)
    {
      bridge.begin();
    }
    else 
    {
      bridge.end();
    }
  }

  void restartBridge() override {
    if (!bridge.isRunning()) return;
    bridge.end();
    bridge.begin();
  }
#endif

  // To check if there is pending work
  bool hasPendingWork() const;

#if MESHCORE_LORA_OTA
  // Same contract as examples/companion_radio/MyMesh.h's identically-
  // named methods -- see helpers/ota/OtaMeshTrialHealthTick.h for the
  // shared decision logic both boards' loop() glue delegates to.
  void setOtaTrialBootHealthSignals(bool radio_ready, bool filesystem_ready) {
    _ota_trial_radio_ready = radio_ready;
    _ota_trial_filesystem_ready = filesystem_ready;
  }
  // Companion's equivalent latch is set inline inside its own DataStore
  // wrapper/begin() methods (private member access); repeater's identity
  // load instead happens in main.cpp's setup(), outside any MyMesh member
  // function, so a narrow public setter is needed to report the same
  // "a genuine load failure happened this boot" evidence without widening
  // _ota_service_ itself to public access.
  void notifyOtaTrialIdentityLoadFault() {
    _ota_service_.noteIdentityLoadAttempted(/*loaded_ok=*/false);
  }
  // Same reasoning as notifyOtaTrialIdentityLoadFault() above: main.cpp's
  // setup() (not a MyMesh member function) is where repeater's identity
  // load/generate/save actually happens, so it must report the final
  // confirmed-loaded fact through this narrow setter rather than main.cpp
  // reaching into a private member directly.
  void notifyOtaIdentityConfirmedLoaded(bool loaded) {
    if (loaded) {
      _ota_service_.noteIdentityPersisted();
    }
    // `false` here is only ever reached via the already-false default
    // (see main.cpp's call sites) -- nothing further to latch.
  }
  void tickOtaTrialHealth();
#endif

  // Called from main.cpp's setup() in place of the previous halt() on
  // ota_identity_boot::Outcome::IdentityUnavailable -- see
  // _identity_available_'s doc comment above. Unconditional (not
  // MESHCORE_LORA_OTA-gated): main.cpp only ever calls this inside its
  // own #if MESHCORE_LORA_OTA branch today, but the setter itself stays
  // plain so it compiles identically to companion's equivalent path.
  void notifyIdentityUnavailableForDispatch() { _identity_available_ = false; }
  // Called from main.cpp's setup() in place of the previous halt() on a
  // failed radio_init() -- see _radio_available_'s doc comment above.
  void notifyRadioUnavailableForDispatch() { _radio_available_ = false; }
  // Called from main.cpp's setup() with !ota_allow_destructive_boot_writes
  // -- see _ota_destructive_writes_disallowed_'s doc comment above.
  // Unconditional (not MESHCORE_LORA_OTA-gated), same rationale as
  // notifyIdentityUnavailableForDispatch()/notifyRadioUnavailableForDispatch().
  void notifyDestructiveWritesDisallowed() { _ota_destructive_writes_disallowed_ = true; }

  bool setRxBoostedGain(bool enable) override;

  #if defined(USE_LR2021)
  virtual bool configSideDetectors(const uint8_t sideDetSFs[], uint8_t num, float bw) override;
  #endif

};
