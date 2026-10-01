#pragma once

#include <Arduino.h>
#include <Mesh.h>
#include "AbstractUITask.h"

/*------------ Frame Protocol --------------*/
#define FIRMWARE_VER_CODE 13

#ifndef FIRMWARE_BUILD_DATE
#define FIRMWARE_BUILD_DATE "14 Aug 2026"
#endif

#ifndef FIRMWARE_VERSION
#define FIRMWARE_VERSION "v1.17.1"
#endif

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
#include <InternalFileSystem.h>
#elif defined(RP2040_PLATFORM)
#include <LittleFS.h>
#elif defined(ESP32)
#include <SPIFFS.h>
#endif

#include "DataStore.h"
#include "NodePrefs.h"

#include <RTClib.h>
#include <helpers/ArduinoHelpers.h>
#include <helpers/BaseSerialInterface.h>
#include <helpers/IdentityStore.h>
#include <helpers/SimpleMeshTables.h>
#include <helpers/StaticPoolPacketManager.h>
#include <target.h>

/* ---------------------------------- CONFIGURATION ------------------------------------- */

#ifndef LORA_FREQ
#define LORA_FREQ 915.0
#endif
#ifndef LORA_BW
#define LORA_BW 250
#endif
#ifndef LORA_SF
#define LORA_SF 10
#endif
#ifndef LORA_CR
#define LORA_CR 5
#endif
#ifndef LORA_TX_POWER
#define LORA_TX_POWER 20
#endif
#ifndef DEFAULT_PATH_HASH_MODE
#define DEFAULT_PATH_HASH_MODE 0
#endif
#ifndef MAX_LORA_TX_POWER
#define MAX_LORA_TX_POWER LORA_TX_POWER
#endif

#ifndef MAX_CONTACTS
#define MAX_CONTACTS 100
#endif

#ifndef OFFLINE_QUEUE_SIZE
#define OFFLINE_QUEUE_SIZE 16
#endif

#ifndef BLE_NAME_PREFIX
#define BLE_NAME_PREFIX "MeshCore-"
#endif

#include <helpers/BaseChatMesh.h>
#include <helpers/TransportKeyStore.h>
#include "helpers/ota/OtaTrialSafeIdentityBoot.h"
#include "helpers/ota/OtaBoardBaselineMeasurementSource.h"
#include "helpers/ota/OtaFirmwareService.h"
#include "helpers/ota/OtaMeasurementControlJobBackend.h"
#include "ota/runtime/OtaControlSessionRouter.h"

/* -------------------------------------------------------------------------------------- */

#define REQ_TYPE_GET_STATUS             0x01 // same as _GET_STATS
#define REQ_TYPE_KEEP_ALIVE             0x02
#define REQ_TYPE_GET_TELEMETRY_DATA     0x03

struct AdvertPath {
  uint8_t pubkey_prefix[7];
  uint8_t path_len;
  char    name[32];
  uint32_t recv_timestamp;
  uint8_t path[MAX_PATH_SIZE];
};

class MyMesh : public BaseChatMesh, public DataStoreHost {
public:
  MyMesh(mesh::Radio &radio, mesh::RNG &rng, mesh::RTCClock &rtc, SimpleMeshTables &tables, DataStore& store, AbstractUITask* ui=NULL);

  // \param allow_destructive_boot_writes -- when false (an OTA
  // trial/unknown boot -- see otaBoardEarlyBootTrialOrUnknown(), queried
  // by main.cpp strictly BEFORE this call), loadPrefs()'s legacy
  // /new_prefs migration is read-only (no migration write). Defaults to
  // true (unchanged legacy behavior) for any caller that never passes it.
  // \param allow_identity_generation -- DELIBERATELY SEPARATE permit from
  // the above (never derive one from the other): even a future boot
  // classification that permits ordinary existing-userdata behavior
  // (e.g. a positively-certified stock baseline, see
  // OtaBaselineCertificationEvidence.h) must NOT thereby also authorize
  // creating a brand-new identity or persisting it -- that requires its
  // own, still-unwired install/counter authority. When false, a failed
  // loadMainIdentity() does NOT regenerate+persist a new identity (a
  // merely-transiently-unreadable original secret must survive a
  // subsequent trial rollback); self_id is left unset and
  // identity-dependent mesh dispatch is suppressed for the rest of this
  // boot. Defaults to true (unchanged legacy behavior) for any caller
  // that never passes it.
  void begin(bool has_display, bool allow_destructive_boot_writes = true, bool allow_identity_generation = true);
  void startInterface(BaseSerialInterface &serial);

  const char *getNodeName();
  NodePrefs *getNodePrefs();
  uint32_t getBLEPin();

  void loop();
  void handleCmdFrame(size_t len);
  bool advert();
  void enterCLIRescue();

  int  getRecentlyHeard(AdvertPath dest[], int max_num);
  void applyTempRadioParams(float freq, float bw, uint8_t sf, uint8_t cr, int timeout_mins);
  bool setFirmwareOtaMode(const char* mode);
  const char* getFirmwareOtaMode() const;
  bool setFirmwareOtaDutyCycle(float percent);
  float getFirmwareOtaDutyCycle() const;
  void abortFirmwareOta();
  void rollbackFirmwareOta();
  void formatFirmwareOtaStatus(char* reply, size_t reply_size);
#if MESHCORE_LORA_OTA
  bool attachFirmwareOtaBackend(meshcore::ota::runtime::IOtaTrustProvider& trust_provider,
                                meshcore::ota::runtime::IOtaStagingSink& staging_sink);
  // Genuine trial-boot health confirmation: setOtaTrialBootHealthSignals()
  // captures the ONE-TIME boot-init results (radio_init()/filesystem
  // begin() success, captured by main.cpp at startup, since a failed
  // radio_init() halts() before MyMesh is ever reached). tickOtaTrialHealth()
  // below combines these with genuine PER-TICK signals -- a real "stuck
  // out of Rx mode" check bounded by the ACTUAL in-flight send's real
  // airtime+margin deadline when one is genuinely in progress (never a
  // single fixed constant that could misfire on a legitimately long TX),
  // a genuine ACTIVE per-tick driver status probe (Radio::probeDriverStatus(),
  // a real hardware error-flag read on CustomSX1262Wrapper, not merely a
  // passive reaction to whichever ordinary op happened to run last), and
  // either a latched storage IoError from otaBoardStorageIoFaultObserved()
  // (candidate sink) or from an actual ordinary filesystem write this
  // boot (NodePrefs save/identity import, see
  // _ota_service_.trialFilesystemFaultObserved()) -- before calling into the
  // monitor. Neither boot-init result alone is treated as "still ready"
  // forever.
  void setOtaTrialBootHealthSignals(bool radio_ready, bool filesystem_ready);
  // Advances the trial-boot health state machine exactly once. Must be
  // called by the OUTER main.cpp loop() AFTER every other real service
  // for this pass has actually executed (mesh dispatch via loop() above,
  // all interfaces, sensors/UI, RTC, external watchdog, WiFi reconnect)
  // and BEFORE any deep-sleep decision -- confirming health before those
  // services ran this pass would latch a false-healthy outcome even if
  // one of them had silently failed or stalled earlier in the same tick.
  void tickOtaTrialHealth();
  // Baseline measurement collector instance for this board, driven once
  // per tick from tickOtaTrialHealth() below (radio-independent -- see
  // OtaBaselineMeasurementCollector.h). The USB MEASURE/POLL/READ_OBJECT
  // commissioning surface calls begin()/readCompletedEvidence()/cancel()
  // on this SAME instance via _ota_measurement_job_backend_ (bound into
  // _ota_control_backend_slot_ in begin()), rather than a second,
  // un-driven collector.
  mesh::ota::OtaBaselineMeasurementCollector& otaBaselineMeasurementCollector() { return _ota_baseline_collector_; }
#endif

protected:
  float getAirtimeBudgetFactor() const override;
  int getInterferenceThreshold() const override;
  bool getCADEnabled() const override;
  int calcRxDelay(float score, uint32_t air_time) const override;
  uint32_t getRetransmitDelay(const mesh::Packet *packet) override;
  uint32_t getDirectRetransmitDelay(const mesh::Packet *packet) override;
  uint8_t getExtraAckTransmitCount() const override;
  bool filterRecvFloodPacket(mesh::Packet* packet) override;
  bool allowPacketForward(const mesh::Packet* packet) override;

  void sendFloodScoped(const TransportKey& scope, mesh::Packet* pkt, uint32_t delay_millis);
  void sendFloodScoped(const ContactInfo& recipient, mesh::Packet* pkt, uint32_t delay_millis=0) override;
  void sendFloodScoped(const mesh::GroupChannel& channel, mesh::Packet* pkt, uint32_t delay_millis=0) override;

  void logRxRaw(float snr, float rssi, const uint8_t raw[], int len) override;
  bool isAutoAddEnabled() const override;
  bool shouldAutoAddContactType(uint8_t type) const override;
  bool shouldOverwriteWhenFull() const override;
  uint8_t getAutoAddMaxHops() const override;
  void onContactsFull() override;
  void onContactOverwrite(const uint8_t* pub_key) override;
  bool onContactPathRecv(ContactInfo& from, uint8_t* in_path, uint8_t in_path_len, uint8_t* out_path, uint8_t out_path_len, uint8_t extra_type, uint8_t* extra, uint8_t extra_len) override;
  void onDiscoveredContact(ContactInfo &contact, bool is_new, uint8_t path_len, const uint8_t* path) override;
  void onContactPathUpdated(const ContactInfo &contact) override;
  ContactInfo* processAck(const uint8_t *data) override;
  void queueMessage(const ContactInfo &from, uint8_t txt_type, mesh::Packet *pkt, uint32_t sender_timestamp,
                    const uint8_t *extra, int extra_len, const char *text);

  void onMessageRecv(const ContactInfo &from, mesh::Packet *pkt, uint32_t sender_timestamp,
                     const char *text) override;
  void onCommandDataRecv(const ContactInfo &from, mesh::Packet *pkt, uint32_t sender_timestamp,
                         const char *text) override;
  void onSignedMessageRecv(const ContactInfo &from, mesh::Packet *pkt, uint32_t sender_timestamp,
                           const uint8_t *sender_prefix, const char *text) override;
  void onChannelMessageRecv(const mesh::GroupChannel &channel, mesh::Packet *pkt, uint32_t timestamp,
                            const char *text) override;
  void onChannelDataRecv(const mesh::GroupChannel &channel, mesh::Packet *pkt, uint16_t data_type,
                         const uint8_t *data, size_t data_len) override;

  uint8_t onContactRequest(const ContactInfo &contact, uint32_t sender_timestamp, const uint8_t *data,
                           uint8_t len, uint8_t *reply) override;
  void onContactResponse(const ContactInfo &contact, const uint8_t *data, uint8_t len) override;
  void onControlDataRecv(mesh::Packet *packet) override;
  void onRawDataRecv(mesh::Packet *packet) override;
  void onOtaDataRecv(mesh::Packet *packet) override;
  void onTraceRecv(mesh::Packet *packet, uint32_t tag, uint32_t auth_code, uint8_t flags,
                   const uint8_t *path_snrs, const uint8_t *path_hashes, uint8_t path_len) override;

  uint32_t calcFloodTimeoutMillisFor(uint32_t pkt_airtime_millis) const override;
  uint32_t calcDirectTimeoutMillisFor(uint32_t pkt_airtime_millis, uint8_t path_len) const override;
  void onSendTimeout() override;

  // DataStoreHost methods
  bool onContactLoaded(const ContactInfo& contact) override { return addContact(contact); }
  bool getContactForSave(uint32_t idx, ContactInfo& contact) override { return getContactByIdx(idx, contact); }
  bool onChannelLoaded(uint8_t channel_idx, const ChannelDetails& ch) override { return setChannel(channel_idx, ch); }
  bool getChannelForSave(uint8_t channel_idx, ChannelDetails& ch) override { return getChannel(channel_idx, ch); }

  void clearPendingReqs() {
    pending_login = pending_status = pending_telemetry = pending_discovery = pending_req = 0;
  }

public:
  void savePrefs() {
    _prefs.node_lat = sensors.node_lat;
    _prefs.node_lon = sensors.node_lon;
    const bool ok = _store->savePrefs(_prefs);
#if MESHCORE_LORA_OTA
    // Real, already-performed ordinary filesystem write -- its ACTUAL
    // outcome is genuine trial-boot-health evidence (see
    // tickOtaTrialHealth()), never a fabricated probe. Latched: never
    // auto-clears on a later success, matching the same "a genuine
    // storage fault requires a fresh boot before re-trusting filesystem
    // readiness" philosophy already used for otaBoardStorageIoFaultObserved().
    // A policy-refused write (destructiveWritesDisallowed()) is an
    // intentional, expected non-persist -- NOT evidence of a storage
    // fault -- so it must never latch here.
    if (!ok && !_store->destructiveWritesDisallowed()) _ota_service_.noteStorageIoResult(false);
#else
    (void)ok;
#endif
  }

#if ENV_INCLUDE_GPS == 1
  void applyGpsPrefs() {
    sensors.setSettingValue("gps", _prefs.gps_enabled ? "1" : "0");
    if (_prefs.gps_interval > 0) {
      char interval_str[12];  // Max: 24 hours = 86400 seconds (5 digits + null)
      sprintf(interval_str, "%u", _prefs.gps_interval);
      sensors.setSettingValue("gps_interval", interval_str);
    }
  }
#endif

  // To check if there is pending work
  bool hasPendingWork() const;

#if MESHCORE_LORA_OTA
  // Accessor for main.cpp's source-bound USB commissioning adapter (see
  // helpers/ota/OtaUsbCommissioningSerialInterface.h) to construct its
  // OtaUsbControlService around the SAME real router this instance owns
  // and binds its job backend into below -- never a second/duplicate
  // router/session instance.
  meshcore::ota::runtime::OtaControlSessionRouter& getOtaControlRouter() { return _ota_control_router_; }
#endif

private:
  void writeOKFrame();
  void writeErrFrame(uint8_t err_code);
  // Returns true (and has ALREADY replied ERR_CODE_BAD_STATE) iff
  // ordinary persisted-userdata writes are currently policy-disallowed
  // this boot (OTA trial/unknown -- see DataStore::destructiveWritesDisallowed()).
  // Every serial command handler that mutates persisted config/contact/
  // channel/blob/private-key state MUST call this FIRST, before
  // touching any RAM state at all, and return immediately if it returns
  // true -- so a policy refusal is never masked by a fabricated OK reply
  // while real persisted data silently fails to save (or, worse, RAM
  // state itself drifts from disk during a boot that must remain
  // read-only for the whole trial).
  bool refusePersistIfDisallowed();
  // Returns true (and has ALREADY replied ERR_CODE_BAD_STATE) iff a
  // packet about to be handed to sendFlood()/sendDirect()/sendZeroHop()/
  // sendPacket() cannot actually be dispatched onto the radio this boot.
  // MyMesh::loop() entirely skips BaseChatMesh::loop() (which calls
  // Mesh::loop(), the ONLY thing that drains the outbound packet queue)
  // whenever identity is unavailable -- so a packet enqueued in that
  // state would sit forever and never transmit, even though it doesn't
  // itself need self_id for crypto. Every serial command handler that
  // enqueues mesh TX work (whether or not it also derives secrets from
  // self_id) MUST call this FIRST, before packet allocation/enqueue, and
  // return immediately if it returns true -- so SENT/OK is never a lie
  // for work that can never be serviced.
  bool refuseSendIfDispatchUnavailable();
  void writeDisabledFrame();
  void writeContactRespFrame(uint8_t code, const ContactInfo &contact);
  void updateContactFromFrame(ContactInfo &contact, uint32_t& last_mod, const uint8_t *frame, int len);
  void addToOfflineQueue(const uint8_t frame[], int len);
  int getFromOfflineQueue(uint8_t frame[]);
  int getBlobByKey(const uint8_t key[], int key_len, uint8_t dest_buf[]) override { 
    return _store->getBlobByKey(key, key_len, dest_buf);
  }
  bool putBlobByKey(const uint8_t key[], int key_len, const uint8_t src_buf[], int len) override {
    const bool ok = _store->putBlobByKey(key, key_len, src_buf, len);
#if MESHCORE_LORA_OTA
    // Same latch/rationale as savePrefs()/saveChannels() below -- a real,
    // already-performed ordinary filesystem write (used for e.g.
    // per-contact/channel extra-blob data), never a fabricated probe. A
    // policy-refused write must never be misread as a storage fault.
    if (!ok && !_store->destructiveWritesDisallowed()) _ota_service_.noteStorageIoResult(false);
#endif
    return ok;
  }

  void checkCLIRescueCmd();
  void checkSerialInterface();
  bool isValidClientRepeatFreq(uint32_t f) const;
  void checkTempRadioLease();
  void revertTempRadioLeaseIfDue();

  // helpers, short-cuts
  void saveChannels() {
    const bool ok = _store->saveChannels(this);
#if MESHCORE_LORA_OTA
    // Same latch/rationale as savePrefs() above -- a real, already-
    // performed ordinary filesystem write, never a fabricated probe. A
    // policy-refused write must never be misread as a storage fault.
    if (!ok && !_store->destructiveWritesDisallowed()) _ota_service_.noteStorageIoResult(false);
#else
    (void)ok;
#endif
  }
  void saveContacts();

  DataStore* _store;
  NodePrefs _prefs;
  uint32_t pending_login;
  uint32_t pending_status;
  uint32_t pending_telemetry, pending_discovery;   // pending _TELEMETRY_REQ
  uint32_t pending_req;   // pending _BINARY_REQ
  BaseSerialInterface *_serial;
  AbstractUITask* _ui;

  ContactsIterator _iter;
  uint32_t _iter_filter_since;
  uint32_t _most_recent_lastmod;
  uint32_t _active_ble_pin;
  bool _iter_started;
  bool _cli_rescue;
  bool send_unscoped;   // force un-scoped flood (instead of using send_scope)
  char cli_command[80];
  uint8_t app_target_ver;
  uint8_t *sign_data;
  uint32_t sign_data_len;
  unsigned long dirty_contacts_expiry;
  unsigned long set_radio_at;
  unsigned long revert_radio_at;
  float pending_freq;
  float pending_bw;
  uint8_t pending_sf;
  uint8_t pending_cr;

  // False only when begin() hit a genuine identity-load failure during an
  // OTA trial/unknown boot (allow_destructive_boot_writes == false) --
  // per Astra's explicit contract, no identity (not even a RAM-only
  // temporary one) is ever synthesized in that case, so self_id is left
  // at its default/unset value. loop() uses this to suppress ordinary
  // mesh dispatch (identity-dependent TX/signing) entirely, keeping only
  // the bounded serial/diagnostic/trial-health maintenance path running,
  // rather than operating on an unregistered temporary identity.
  bool _identity_available_ = true;

#if MESHCORE_LORA_OTA
  bool _ota_trial_radio_ready = false;
  bool _ota_trial_filesystem_ready = false;
  bool _ota_trial_reboot_issued = false;
  // Single authoritative owner of the latched filesystem-fault and
  // identity-confirmed-loaded facts previously tracked as two separate
  // role-local bools here (see helpers/ota/OtaFirmwareService.h) --
  // fed real outcomes below and by every ordinary persisted-write call
  // site in this file; consumed read-only by _ota_baseline_source_ and
  // tickOtaTrialHealth().
  mesh::ota::OtaFirmwareService _ota_service_;
  // The driverFaultCount() value as of the end of the previous
  // tickOtaTrialHealth() call. Used ONLY as a per-tick comparison
  // baseline (see evaluateOtaTrialRadioReadyThisPass() in
  // OtaTrialRadioReadiness.h) -- deliberately NOT a sticky/latched
  // "fault observed" bool: a single transient real-operation failure
  // must fail only the ONE pass it occurred on, not the whole boot,
  // since the continuous-health window already resets (rather than
  // aborts) on any one non-ready pass, and a genuinely recovered radio
  // must be free to start accumulating a fresh window on the very next
  // pass.
  uint32_t _ota_trial_last_radio_fault_count_ = 0;
  // Real per-board source adapter + collector instance (see
  // helpers/ota/OtaBoardBaselineMeasurementSource.h), constructed once
  // with a pointer to self_id.pub_key (already-loaded, never generated
  // here). Driven once per tick from tickOtaTrialHealth(), independent of
  // any USB activity -- the backend below never calls serviceStep()
  // itself (see OtaMeasurementControlJobBackend.h), only begin()/poll()/
  // readObject() wired through to this same collector from begin().
  mesh::ota::OtaBoardBaselineMeasurementSource _ota_baseline_source_;
  mesh::ota::OtaBaselineMeasurementCollector _ota_baseline_collector_;
  // The real MEASURE/POLL/READ_OBJECT IOtaControlJobBackend, bound into
  // _ota_control_backend_slot_ in begin() below. Certify/Prepare/Activate
  // remain an explicit terminal NoCapacity from this same backend until
  // Authority's/Store's own adapters land -- never a fake Ok/Pending.
  meshcore::ota::runtime::OtaMeasurementControlJobBackend _ota_measurement_job_backend_;

  // Device-side entropy bridge for OtaControlSessionRouter's minted
  // session ids / CHALLENGE bytes. IMPORTANT: this intentionally does
  // NOT read from `_rng` (== `fast_rng`, a `StdRNG` wrapping
  // `::random(0,256)` seeded once at boot -- see
  // src/helpers/ArduinoHelpers.h) or any other millis()/counter-based
  // source; that is exactly the deterministic-PRNG fallback the
  // commissioning contract disallows ("device-generated", never a
  // predictable/host-chosen source). The genuine real-radio-noise
  // equivalent already exists (`RadioNoiseListener`, see
  // src/helpers/radiolib/RadioLibWrappers.h, and the ready
  // `mesh::ota::helpers::OtaControlRadioEntropy` adapter in
  // src/helpers/ota/OtaDeviceAuthorityBoardAdapters.h) but needs a
  // `PhysicalLayer&`, which is NOT reachable from here: MyMesh only
  // holds the abstract `mesh::Radio&` (src/Dispatcher.h), which exposes
  // no entropy seam, and the concrete `RadioLibWrapper`
  // (src/helpers/radiolib/RadioLibWrappers.h) keeps its `PhysicalLayer*`
  // private -- both files are outside this scope's owned edit surface.
  // Until one of those (owner-approved) exposes real radio entropy to
  // MyMesh, this bridge fails closed: every call reports failure, so
  // OPEN/CHALLENGE correctly report NoCapacity/entropy-unavailable
  // rather than ever minting a session id or challenge from StdRNG.
  class OtaControlRngEntropy : public meshcore::ota::runtime::IOtaControlEntropySource {
  public:
    bool fillRandom(uint8_t*, size_t) override { return false; }
  };
  OtaControlRngEntropy _ota_control_entropy_;

  // Fail-closed by default (see OtaControlNullJobBackend); Authority's/
  // Store's eventual physical-writer adapter binds here via
  // _ota_control_backend_slot_.bind(...) once their own coordinator APIs
  // stabilize -- no job-bearing USB command can fabricate progress until
  // then.
  meshcore::ota::runtime::OtaControlJobBackendSlot _ota_control_backend_slot_;
  meshcore::ota::runtime::OtaControlSessionRouter _ota_control_router_;

  // True iff the radio has been continuously out of Rx mode for longer
  // than is legitimate right now -- bounded by the real in-flight send's
  // airtime+margin deadline when one is genuinely in progress, or a
  // fixed conservative floor when neither receiving nor sending. See
  // tickOtaTrialHealth()'s comment for why neither signal alone suffices.
  bool isRadioStuckOutOfRecv(uint32_t now_ms);
#endif

  TransportKey send_scope;

  uint8_t cmd_frame[MAX_FRAME_SIZE + 1];
  uint8_t out_frame[MAX_FRAME_SIZE + 1];
  CayenneLPP telemetry;

  struct Frame {
    uint8_t len;
    uint8_t buf[MAX_FRAME_SIZE];

    bool isChannelMsg() const;
  };
  int offline_queue_len;
  Frame offline_queue[OFFLINE_QUEUE_SIZE];

  struct AckTableEntry {
    unsigned long msg_sent;
    uint32_t ack;
    ContactInfo* contact;
  };
  #define EXPECTED_ACK_TABLE_SIZE 8
  AckTableEntry expected_ack_table[EXPECTED_ACK_TABLE_SIZE]; // circular table
  int next_ack_idx;

  #define ADVERT_PATH_TABLE_SIZE   16
  AdvertPath advert_paths[ADVERT_PATH_TABLE_SIZE]; // circular table
};

extern MyMesh the_mesh;
