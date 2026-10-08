#include "MyMesh.h"

#include <Arduino.h> // needed for PlatformIO
#ifdef ENABLE_WIFI_INTERFACE
#include <WiFi.h>
#endif
#include <algorithm>
#include <cmath>
#include <Mesh.h>
#include <helpers/ota/OtaMeshHooks.h>
#if MESHCORE_LORA_OTA
#include <helpers/ota/OtaBoardBackendCommon.h>
#include <helpers/ota/OtaBlockSigning.h>
#include <helpers/ota/OtaDirectLease.h>
#include <helpers/ota/OtaMeshTrialHealthTick.h>
#endif
#if XIAO_OTA_COMPANION_USB_UF2
#include <helpers/ArduinoSerialInterface.h>
#include <helpers/MultiSerialInterface.h>
extern MultiSerialInterface interface_manager;
extern ArduinoSerialInterface usb_serial_interface;
#endif
#if MESHCORE_LORA_OTA
__attribute__((weak)) bool otaBoardGetBootLifecycle(mesh::ota::OtaBootLifecycleEvidence& out) {
  out = mesh::ota::OtaBootLifecycleEvidence();
  return false;
}
__attribute__((weak)) bool otaBoardBootLifecycleVerificationPending() { return false; }
__attribute__((weak)) bool otaBoardReadBootCandidate(const mesh::ota::OtaBootLifecycleEvidence&,
                                                    ::ota::storage::OtaCandidateStore::Snapshot&) { return false; }
#include <helpers/ota/OtaRfFrames.h>
#include <helpers/ota/OtaRfUploader.h>
#include <helpers/radiolib/OtaTrialRadioReadiness.h>
#endif

#if MESHCORE_LORA_OTA
__attribute__((weak)) bool otaBoardApplyRfProfile(float, float, uint8_t, uint8_t) { return false; }
__attribute__((weak)) bool configureCompanionFirmwareOtaBackend(mesh::ota::OtaFirmwareIntegration&) {
  return false;
}
// Compact install-capability+reason string, provided by whichever backend
// is linked in (see variants/xiao_nrf52/OtaProductionBackend.cpp /
// variants/sensecap_solar/OtaProductionBackend.cpp); weak default covers
// any build with no OTA backend compiled in at all.
__attribute__((weak)) const char* otaBoardInstallCapabilityStatus() {
  return "backend not configured";
}
__attribute__((weak)) const char* otaBoardEarlyWriteDiagnostic() {
  return "proof=backend-unavailable";
}
// Genuine trial-boot health confirmation entry point (see
// src/ota/storage/XiaoOtaTrialHealthMonitor.h for the full continuous-
// window/deadline/incremental-hash gate); weak default covers any build
// with no OTA backend compiled in at all (always Pending, since there is
// no state/confirm region to consult).
__attribute__((weak)) mesh::ota::OtaBoardTrialHealthOutcome otaBoardTryConfirmHealthyTrialBoot(
    uint32_t, bool, bool, bool) {
  return mesh::ota::OtaBoardTrialHealthOutcome::Pending;
}
// True only while a genuine trial-boot health window is in progress (see
// variants/*/Ota*Backend.cpp); weak default covers any build with no OTA
// backend compiled in at all.
__attribute__((weak)) bool otaBoardTrialHealthWindowActive() {
  return false;
}

// Genuine EARLIEST-boot-phase preflight, called from main.cpp strictly
// A missing backend is unknown, never positive Normal authority.
// Startup asks NormalProven before any destructive userdata operation.
__attribute__((weak)) bool otaBoardEarlyBootTrialOrUnknown() {
  return true;
}
__attribute__((weak)) bool otaBoardEarlyBootNormalProven() {
  return false;
}

// True once the wrapped staging sink has observed a genuine IoError on
// any writeChunk()/commit() this boot (see OtaBoardTrialGuardedStagingSink
// in OtaBoardBackendCommon.h); weak default covers any build with no OTA
// backend compiled in at all (no storage to ever fault).
__attribute__((weak)) bool otaBoardStorageIoFaultObserved() {
  return false;
}
#endif

#define CMD_APP_START                 1
#define CMD_SEND_TXT_MSG              2
#define CMD_SEND_CHANNEL_TXT_MSG      3
#define CMD_GET_CONTACTS              4 // with optional 'since' (for efficient sync)
#define CMD_GET_DEVICE_TIME           5
#define CMD_SET_DEVICE_TIME           6
#define CMD_SEND_SELF_ADVERT          7
#define CMD_SET_ADVERT_NAME           8
#define CMD_ADD_UPDATE_CONTACT        9
#define CMD_SYNC_NEXT_MESSAGE         10
#define CMD_SET_RADIO_PARAMS          11
#define CMD_SET_RADIO_TX_POWER        12
#define CMD_RESET_PATH                13
#define CMD_SET_ADVERT_LATLON         14
#define CMD_REMOVE_CONTACT            15
#define CMD_SHARE_CONTACT             16
#define CMD_EXPORT_CONTACT            17
#define CMD_IMPORT_CONTACT            18
#define CMD_REBOOT                    19
#define CMD_GET_BATT_AND_STORAGE      20   // was CMD_GET_BATTERY_VOLTAGE
#define CMD_SET_TUNING_PARAMS         21
#define CMD_DEVICE_QUERY              22
#define CMD_EXPORT_PRIVATE_KEY        23
#define CMD_IMPORT_PRIVATE_KEY        24
#define CMD_SEND_RAW_DATA             25
#define CMD_SEND_LOGIN                26
#define CMD_SEND_STATUS_REQ           27
#define CMD_HAS_CONNECTION            28
#define CMD_LOGOUT                    29 // 'Disconnect'
#define CMD_GET_CONTACT_BY_KEY        30
#define CMD_GET_CHANNEL               31
#define CMD_SET_CHANNEL               32
#define CMD_SIGN_START                33
#define CMD_SIGN_DATA                 34
#define CMD_SIGN_FINISH               35
#define CMD_SEND_TRACE_PATH           36
#define CMD_SET_DEVICE_PIN            37
#define CMD_SET_OTHER_PARAMS          38
#define CMD_SEND_TELEMETRY_REQ        39  // can deprecate this
#define CMD_GET_CUSTOM_VARS           40
#define CMD_SET_CUSTOM_VAR            41
#define CMD_GET_ADVERT_PATH           42
#define CMD_GET_TUNING_PARAMS         43
// NOTE: CMD range 44..49 parked, potentially for WiFi operations
#define CMD_SEND_BINARY_REQ           50
#define CMD_FACTORY_RESET             51
#define CMD_SEND_PATH_DISCOVERY_REQ   52
#define CMD_SET_FLOOD_SCOPE_KEY       54   // v8+
#define CMD_SEND_CONTROL_DATA         55   // v8+
#define CMD_GET_STATS                 56   // v8+, second byte is stats type
#define CMD_SEND_ANON_REQ             57
#define CMD_SET_AUTOADD_CONFIG        58
#define CMD_GET_AUTOADD_CONFIG        59
#define CMD_GET_ALLOWED_REPEAT_FREQ   60
#define CMD_SET_PATH_HASH_MODE        61
#define CMD_SEND_CHANNEL_DATA         62
#define CMD_SET_DEFAULT_FLOOD_SCOPE   63
#define CMD_GET_DEFAULT_FLOOD_SCOPE   64
#define CMD_SEND_RAW_PACKET           65
#define CMD_RUN_CLI_COMMAND           66  // v14+
#if MESHCORE_LORA_OTA
#define CMD_OTA_CONTROL               67
#endif

// Stats sub-types for CMD_GET_STATS
#define STATS_TYPE_CORE               0
#define STATS_TYPE_RADIO              1
#define STATS_TYPE_PACKETS             2

#define RESP_CODE_OK                  0
#define RESP_CODE_ERR                 1
#define RESP_CODE_CONTACTS_START      2  // first reply to CMD_GET_CONTACTS
#define RESP_CODE_CONTACT             3  // multiple of these (after CMD_GET_CONTACTS)
#define RESP_CODE_END_OF_CONTACTS     4  // last reply to CMD_GET_CONTACTS
#define RESP_CODE_SELF_INFO           5  // reply to CMD_APP_START
#define RESP_CODE_SENT                6  // reply to CMD_SEND_TXT_MSG
#define RESP_CODE_CONTACT_MSG_RECV    7  // a reply to CMD_SYNC_NEXT_MESSAGE (ver < 3)
#define RESP_CODE_CHANNEL_MSG_RECV    8  // a reply to CMD_SYNC_NEXT_MESSAGE (ver < 3)
#define RESP_CODE_CURR_TIME           9  // a reply to CMD_GET_DEVICE_TIME
#define RESP_CODE_NO_MORE_MESSAGES    10 // a reply to CMD_SYNC_NEXT_MESSAGE
#define RESP_CODE_EXPORT_CONTACT      11
#define RESP_CODE_BATT_AND_STORAGE    12 // a reply to a CMD_GET_BATT_AND_STORAGE
#define RESP_CODE_DEVICE_INFO         13 // a reply to CMD_DEVICE_QUERY
#define RESP_CODE_PRIVATE_KEY         14 // a reply to CMD_EXPORT_PRIVATE_KEY
#define RESP_CODE_DISABLED            15
#define RESP_CODE_CONTACT_MSG_RECV_V3 16 // a reply to CMD_SYNC_NEXT_MESSAGE (ver >= 3)
#define RESP_CODE_CHANNEL_MSG_RECV_V3 17 // a reply to CMD_SYNC_NEXT_MESSAGE (ver >= 3)
#define RESP_CODE_CHANNEL_INFO        18 // a reply to CMD_GET_CHANNEL
#define RESP_CODE_SIGN_START          19
#define RESP_CODE_SIGNATURE           20
#define RESP_CODE_CUSTOM_VARS         21
#define RESP_CODE_ADVERT_PATH         22
#define RESP_CODE_TUNING_PARAMS       23
#define RESP_CODE_STATS               24   // v8+, second byte is stats type
#define RESP_CODE_AUTOADD_CONFIG      25
#define RESP_ALLOWED_REPEAT_FREQ      26
#define RESP_CODE_CHANNEL_DATA_RECV   27
#define RESP_CODE_DEFAULT_FLOOD_SCOPE 28
#define RESP_CODE_CLI_REPLY           29  // v14+, a reply to CMD_RUN_CLI_COMMAND
#if MESHCORE_LORA_OTA
#define RESP_CODE_OTA_STATUS          30

#define OTA_CTRL_GET_STATUS           0
#define OTA_CTRL_SET_MODE             1
#define OTA_CTRL_SET_DUTY             2
#define OTA_CTRL_ABORT                3
#define OTA_CTRL_ROLLBACK             4
#define OTA_CTRL_DIRECT_LEASE         5

#endif

#define MAX_CHANNEL_DATA_LENGTH       (MAX_FRAME_SIZE - 9)

#define SEND_TIMEOUT_BASE_MILLIS        500
#define FLOOD_SEND_TIMEOUT_FACTOR       16.0f
#define DIRECT_SEND_PERHOP_FACTOR       6.0f
#define DIRECT_SEND_PERHOP_EXTRA_MILLIS 250
#define LAZY_CONTACTS_WRITE_DELAY       5000

#define PUBLIC_GROUP_PSK                "izOH6cXN6mrJ5e26oRXNcg=="

// these are _pushed_ to client app at any time
#define PUSH_CODE_ADVERT                0x80
#define PUSH_CODE_PATH_UPDATED          0x81
#define PUSH_CODE_SEND_CONFIRMED        0x82
#define PUSH_CODE_MSG_WAITING           0x83
#define PUSH_CODE_RAW_DATA              0x84
#define PUSH_CODE_LOGIN_SUCCESS         0x85
#define PUSH_CODE_LOGIN_FAIL            0x86
#define PUSH_CODE_STATUS_RESPONSE       0x87
#define PUSH_CODE_LOG_RX_DATA           0x88
#define PUSH_CODE_TRACE_DATA            0x89
#define PUSH_CODE_NEW_ADVERT            0x8A
#define PUSH_CODE_TELEMETRY_RESPONSE    0x8B
#define PUSH_CODE_BINARY_RESPONSE       0x8C
#define PUSH_CODE_PATH_DISCOVERY_RESPONSE 0x8D
#define PUSH_CODE_CONTROL_DATA          0x8E   // v8+
#define PUSH_CODE_CONTACT_DELETED       0x8F // used to notify client app of deleted contact when overwriting oldest
#define PUSH_CODE_CONTACTS_FULL         0x90 // used to notify client app that contacts storage is full

#define ERR_CODE_UNSUPPORTED_CMD        1
#define ERR_CODE_NOT_FOUND              2
#define ERR_CODE_TABLE_FULL             3
#define ERR_CODE_BAD_STATE              4
#define ERR_CODE_FILE_IO_ERROR          5
#define ERR_CODE_ILLEGAL_ARG            6

#define MAX_SIGN_DATA_LEN               (8 * 1024) // 8K

// Auto-add config bitmask
// Bit 0: If set, overwrite oldest non-favourite contact when contacts file is full
// Bits 1-4: these indicate which contact types to auto-add when manual_contact_mode = 0x01
#define AUTO_ADD_OVERWRITE_OLDEST (1 << 0)  // 0x01 - overwrite oldest non-favourite when full
#define AUTO_ADD_CHAT             (1 << 1)  // 0x02 - auto-add Chat (Companion) (ADV_TYPE_CHAT)
#define AUTO_ADD_REPEATER         (1 << 2)  // 0x04 - auto-add Repeater (ADV_TYPE_REPEATER)
#define AUTO_ADD_ROOM_SERVER      (1 << 3)  // 0x08 - auto-add Room Server (ADV_TYPE_ROOM)
#define AUTO_ADD_SENSOR           (1 << 4)  // 0x10 - auto-add Sensor (ADV_TYPE_SENSOR)

void MyMesh::writeOKFrame() {
  uint8_t buf[1];
  buf[0] = RESP_CODE_OK;
  _serial->writeFrame(buf, 1);
}
void MyMesh::writeErrFrame(uint8_t err_code) {
  uint8_t buf[2];
  buf[0] = RESP_CODE_ERR;
  buf[1] = err_code;
  _serial->writeFrame(buf, 2);
}

void MyMesh::writeDisabledFrame() {
  uint8_t buf[1];
  buf[0] = RESP_CODE_DISABLED;
  _serial->writeFrame(buf, 1);
}

bool MyMesh::refusePersistIfDisallowed() {
  if (_store->destructiveWritesDisallowed()) {
    // OTA trial/unknown boot: reject BEFORE the caller mutates any RAM
    // state, so a policy refusal is never masked by a later fabricated
    // OK reply (or by RAM/disk drift) -- see doc comment in MyMesh.h.
    writeErrFrame(ERR_CODE_BAD_STATE);
    return true;
  }
  return false;
}

bool MyMesh::refuseSendIfDispatchUnavailable() {
  if (!_identity_available_) {
    // Mesh::loop() (invoked only via BaseChatMesh::loop(), see loop()
    // below) is what actually drains the outbound packet queue over the
    // radio. MyMesh::loop() skips BaseChatMesh::loop() entirely whenever
    // identity is unavailable, so any packet already handed to
    // sendFlood()/sendDirect()/sendZeroHop()/sendPacket() in that state
    // would sit queued and never transmit -- refuse BEFORE packet
    // allocation/enqueue rather than reply SENT/OK for work that can
    // never be serviced. This single flag/guard also covers the subset
    // of sends that separately need self_id for crypto (e.g.
    // getSharedSecret(self_id)): that failure mode is a strict subset of
    // "dispatch unavailable", so one shared guard suffices for both.
    writeErrFrame(ERR_CODE_BAD_STATE);
    return true;
  }
  return false;
}

void MyMesh::writeContactRespFrame(uint8_t code, const ContactInfo &contact) {
  int i = 0;
  out_frame[i++] = code;
  memcpy(&out_frame[i], contact.id.pub_key, PUB_KEY_SIZE);
  i += PUB_KEY_SIZE;
  out_frame[i++] = contact.type;
  out_frame[i++] = contact.flags;
  out_frame[i++] = contact.out_path_len;
  memcpy(&out_frame[i], contact.out_path, MAX_PATH_SIZE);
  i += MAX_PATH_SIZE;
  StrHelper::strzcpy((char *)&out_frame[i], contact.name, 32);
  i += 32;
  memcpy(&out_frame[i], &contact.last_advert_timestamp, 4);
  i += 4;
  memcpy(&out_frame[i], &contact.gps_lat, 4);
  i += 4;
  memcpy(&out_frame[i], &contact.gps_lon, 4);
  i += 4;
  memcpy(&out_frame[i], &contact.lastmod, 4);
  i += 4;
  _serial->writeFrame(out_frame, i);
}

void MyMesh::updateContactFromFrame(ContactInfo &contact, uint32_t& last_mod, const uint8_t *frame, int len) {
  int i = 0;
  uint8_t code = frame[i++]; // eg. CMD_ADD_UPDATE_CONTACT
  memcpy(contact.id.pub_key, &frame[i], PUB_KEY_SIZE);
  i += PUB_KEY_SIZE;
  contact.type = frame[i++];
  contact.flags = frame[i++];
  contact.out_path_len = frame[i++];
  memcpy(contact.out_path, &frame[i], MAX_PATH_SIZE);
  i += MAX_PATH_SIZE;
  memcpy(contact.name, &frame[i], 32);
  i += 32;
  memcpy(&contact.last_advert_timestamp, &frame[i], 4);
  i += 4;
  if (len >= i + 8) { // optional fields
    memcpy(&contact.gps_lat, &frame[i], 4);
    i += 4;
    memcpy(&contact.gps_lon, &frame[i], 4);
    i += 4;
    if (len >= i + 4) {
      memcpy(&last_mod, &frame[i], 4);
    }
  }
}

bool MyMesh::Frame::isChannelMsg() const {
  return buf[0] == RESP_CODE_CHANNEL_MSG_RECV || buf[0] == RESP_CODE_CHANNEL_MSG_RECV_V3 ||
         buf[0] == RESP_CODE_CHANNEL_DATA_RECV;
}

void MyMesh::addToOfflineQueue(const uint8_t frame[], int len) {
  if (offline_queue_len >= OFFLINE_QUEUE_SIZE) {
    MESH_DEBUG_PRINTLN("WARN: offline_queue is full!");
    int pos = 0;
    while (pos < offline_queue_len) {
      if (offline_queue[pos].isChannelMsg()) {
        for (int i = pos; i < offline_queue_len - 1; i++) { // delete oldest channel msg from queue
          offline_queue[i] = offline_queue[i + 1];
        }
        MESH_DEBUG_PRINTLN("INFO: removed oldest channel message from queue.");
        offline_queue[offline_queue_len - 1].len = len;
        memcpy(offline_queue[offline_queue_len - 1].buf, frame, len);
        return;
      }
      pos++;
    }
    MESH_DEBUG_PRINTLN("INFO: no channel messages to remove from queue.");
  } else {
    offline_queue[offline_queue_len].len = len;
    memcpy(offline_queue[offline_queue_len].buf, frame, len);
    offline_queue_len++;
  }
}

int MyMesh::getFromOfflineQueue(uint8_t frame[]) {
  if (offline_queue_len > 0) {         // check offline queue
    size_t len = offline_queue[0].len; // take from top of queue
    memcpy(frame, offline_queue[0].buf, len);

    offline_queue_len--;
    for (int i = 0; i < offline_queue_len; i++) { // delete top item from queue
      offline_queue[i] = offline_queue[i + 1];
    }
    return len;
  }
  return 0; // queue is empty
}

float MyMesh::getAirtimeBudgetFactor() const {
  return _prefs.airtime_factor;
}

int MyMesh::getInterferenceThreshold() const {
  return _prefs.interference_threshold;
}
bool MyMesh::getCADEnabled() const {
  return _prefs.cad_enabled;
}

int MyMesh::calcRxDelay(float score, uint32_t air_time) const {
  if (_prefs.rx_delay_base <= 0.0f) return 0;
  return (int)((pow(_prefs.rx_delay_base, 0.85f - score) - 1.0) * air_time);
}

uint32_t MyMesh::getRetransmitDelay(const mesh::Packet *packet) {
  uint32_t t = (_radio->getEstAirtimeFor(packet->getPathByteLen() + packet->payload_len + 2) * _prefs.tx_delay_factor);
  return getRNG()->nextInt(0, 5*t + 1);
}
uint32_t MyMesh::getDirectRetransmitDelay(const mesh::Packet *packet) {
  uint32_t t = (_radio->getEstAirtimeFor(packet->getPathByteLen() + packet->payload_len + 2) * _prefs.direct_tx_delay_factor);
  return getRNG()->nextInt(0, 5*t + 1);
}

uint8_t MyMesh::getExtraAckTransmitCount() const {
  return _prefs.multi_acks;
}

void MyMesh::logRxRaw(float snr, float rssi, const uint8_t raw[], int len) {
  if (_serial->isConnected() && len + 3 <= MAX_FRAME_SIZE) {
    int i = 0;
    out_frame[i++] = PUSH_CODE_LOG_RX_DATA;
    out_frame[i++] = (int8_t)(snr * 4);
    out_frame[i++] = (int8_t)(rssi);
    memcpy(&out_frame[i], raw, len);
    i += len;

#if MESHCORE_LORA_OTA
    _serial->tryWriteFrame(out_frame, i);
#else
    _serial->writeFrame(out_frame, i);
#endif
  }
}

bool MyMesh::isAutoAddEnabled() const {
  return (_prefs.manual_add_contacts & 1) == 0;
}

bool MyMesh::shouldAutoAddContactType(uint8_t contact_type) const {
  if ((_prefs.manual_add_contacts & 1) == 0) {
    return true;
  }

  uint8_t type_bit = 0;
  switch (contact_type) {
    case ADV_TYPE_CHAT:
      type_bit = AUTO_ADD_CHAT;
      break;
    case ADV_TYPE_REPEATER:
      type_bit = AUTO_ADD_REPEATER;
      break;
    case ADV_TYPE_ROOM:
      type_bit = AUTO_ADD_ROOM_SERVER;
      break;
    case ADV_TYPE_SENSOR:
      type_bit = AUTO_ADD_SENSOR;
      break;
    default:
      return false;  // Unknown type, don't auto-add
  }

  return (_prefs.autoadd_config & type_bit) != 0;
}

bool MyMesh::shouldOverwriteWhenFull() const {
  return (_prefs.autoadd_config & AUTO_ADD_OVERWRITE_OLDEST) != 0;
}

uint8_t MyMesh::getAutoAddMaxHops() const {
  return _prefs.autoadd_max_hops;
}

void MyMesh::onContactOverwrite(const uint8_t* pub_key) {
    _store->deleteBlobByKey(pub_key, PUB_KEY_SIZE); // delete from storage
  if (_serial->isConnected()) {
    out_frame[0] = PUSH_CODE_CONTACT_DELETED;
    memcpy(&out_frame[1], pub_key, PUB_KEY_SIZE);
    _serial->writeFrame(out_frame, 1 + PUB_KEY_SIZE);
  }
}

void MyMesh::onContactsFull() {
  if (_serial->isConnected()) {
    out_frame[0] = PUSH_CODE_CONTACTS_FULL;
    _serial->writeFrame(out_frame, 1);
  }
}

void MyMesh::onDiscoveredContact(ContactInfo &contact, bool is_new, uint8_t path_len, const uint8_t* path) {
  if (_serial->isConnected()) {
    if (is_new) {
      writeContactRespFrame(PUSH_CODE_NEW_ADVERT, contact);
    } else {
      out_frame[0] = PUSH_CODE_ADVERT;
      memcpy(&out_frame[1], contact.id.pub_key, PUB_KEY_SIZE);
      _serial->writeFrame(out_frame, 1 + PUB_KEY_SIZE);
    }
  }

  // add inbound-path to mem cache
  if (path && mesh::Packet::isValidPathLen(path_len)) {  // check path is valid
    AdvertPath* p = advert_paths;
    uint32_t oldest = 0xFFFFFFFF;
    for (int i = 0; i < ADVERT_PATH_TABLE_SIZE; i++) {   // check if already in table, otherwise evict oldest
      if (memcmp(advert_paths[i].pubkey_prefix, contact.id.pub_key, sizeof(AdvertPath::pubkey_prefix)) == 0) {
        p = &advert_paths[i];   // found
        break;
      }
      if (advert_paths[i].recv_timestamp < oldest) {
        oldest = advert_paths[i].recv_timestamp;
        p = &advert_paths[i];
      }
    }

    memcpy(p->pubkey_prefix, contact.id.pub_key, sizeof(p->pubkey_prefix));
    strcpy(p->name, contact.name);
    p->recv_timestamp = getRTCClock()->getCurrentTime();
    p->path_len = mesh::Packet::copyPath(p->path, path, path_len);
  }

  if (_listener) _listener->onDiscoveredContact(contact, is_new, path_len, path);

  if (!is_new) dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY); // only schedule lazy write for contacts that are in contacts[]
}

static int sort_by_recent(const void *a, const void *b) {
  return ((AdvertPath *) b)->recv_timestamp - ((AdvertPath *) a)->recv_timestamp;
}

int MyMesh::getRecentlyHeard(AdvertPath dest[], int max_num) {
  if (max_num > ADVERT_PATH_TABLE_SIZE) max_num = ADVERT_PATH_TABLE_SIZE;
  qsort(advert_paths, ADVERT_PATH_TABLE_SIZE, sizeof(advert_paths[0]), sort_by_recent);

  for (int i = 0; i < max_num; i++) {
    dest[i] = advert_paths[i];
  }
  return max_num;
}

void MyMesh::onContactPathUpdated(const ContactInfo &contact) {
  out_frame[0] = PUSH_CODE_PATH_UPDATED;
  memcpy(&out_frame[1], contact.id.pub_key, PUB_KEY_SIZE);
  _serial->writeFrame(out_frame, 1 + PUB_KEY_SIZE); // NOTE: app may not be connected

  dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
}

ContactInfo*  MyMesh::processAck(const uint8_t *data) {
  if (_listener) {
    uint32_t ack_crc;
    memcpy(&ack_crc, data, 4);
    _listener->onACKRecv(ack_crc);
  }
  // see if matches any in a table
  for (int i = 0; i < EXPECTED_ACK_TABLE_SIZE; i++) {
    if (memcmp(data, &expected_ack_table[i].ack, 4) == 0) { // got an ACK from recipient
      out_frame[0] = PUSH_CODE_SEND_CONFIRMED;
      memcpy(&out_frame[1], data, 4);
      uint32_t trip_time = _ms->getMillis() - expected_ack_table[i].msg_sent;
      memcpy(&out_frame[5], &trip_time, 4);
      _serial->writeFrame(out_frame, 9);

      // NOTE: the same ACK can be received multiple times!
      expected_ack_table[i].ack = 0; // clear expected hash, now that we have received ACK
      return expected_ack_table[i].contact;
    }
  }
  return checkConnectionsAck(data);
}

void MyMesh::queueMessage(const ContactInfo &from, uint8_t txt_type, mesh::Packet *pkt,
                          uint32_t sender_timestamp, const uint8_t *extra, int extra_len, const char *text) {
  int i = 0;
  if (app_target_ver >= 3) {
    out_frame[i++] = RESP_CODE_CONTACT_MSG_RECV_V3;
    out_frame[i++] = (int8_t)(pkt->getSNR() * 4);
    out_frame[i++] = 0; // reserved1
    out_frame[i++] = 0; // reserved2
  } else {
    out_frame[i++] = RESP_CODE_CONTACT_MSG_RECV;
  }
  memcpy(&out_frame[i], from.id.pub_key, 6);
  i += 6; // just 6-byte prefix
  uint8_t path_len = out_frame[i++] = pkt->isRouteFlood() ? pkt->path_len : 0xFF;
  out_frame[i++] = txt_type;
  memcpy(&out_frame[i], &sender_timestamp, 4);
  i += 4;
  if (extra_len > 0) {
    memcpy(&out_frame[i], extra, extra_len);
    i += extra_len;
  }
  int tlen = strlen(text); // TODO: UTF-8 ??
  if (i + tlen > MAX_FRAME_SIZE) {
    tlen = MAX_FRAME_SIZE - i;
  }
  memcpy(&out_frame[i], text, tlen);
  i += tlen;
  addToOfflineQueue(out_frame, i);

  if (_serial->isConnected()) {
    uint8_t frame[1];
    frame[0] = PUSH_CODE_MSG_WAITING; // send push 'tickle'
    _serial->writeFrame(frame, 1);
  }

  if (_listener) {
    _listener->onMessageRecv(pkt, from, txt_type, sender_timestamp, text);
    _listener->onQueueSizeChanged(offline_queue_len);
  }
}

bool MyMesh::filterRecvFloodPacket(mesh::Packet* packet) {
  // REVISIT: try to determine which Region (from transport_codes[1]) that Sender is indicating for replies/responses
  //    if unknown, fallback to finding Region from transport_codes[0], the 'scope' used by Sender
  return false;
}

bool MyMesh::allowPacketForward(const mesh::Packet* packet) {
  return _prefs.isRepeatEn();
}

void MyMesh::sendFloodScoped(const TransportKey& scope, mesh::Packet* pkt, uint32_t delay_millis) {
  if (scope.isNull()) {
    sendFlood(pkt, delay_millis, _prefs.path_hash_mode + 1);
  } else {
    uint16_t codes[2];
    codes[0] = scope.calcTransportCode(pkt);
    codes[1] = 0;  // REVISIT: set to 'home' Region, for sender/return region?
    sendFlood(pkt, codes, delay_millis, _prefs.path_hash_mode + 1);
  }
}

void MyMesh::sendFloodScoped(const ContactInfo& recipient, mesh::Packet* pkt, uint32_t delay_millis) {
  // TODO: dynamic send_scope, depending on recipient and current 'home' Region
  if (send_unscoped) {
    sendFlood(pkt, delay_millis, _prefs.path_hash_mode + 1);  // app has explicitly requested un-scoped
  } else {
    TransportKey default_scope;
    memcpy(&default_scope.key, _prefs.default_scope_key, sizeof(default_scope.key));

    auto scope = send_scope.isNull() ? &default_scope : &send_scope;
    sendFloodScoped(*scope, pkt, delay_millis);
  }
}
void MyMesh::sendFloodScoped(const mesh::GroupChannel& channel, mesh::Packet* pkt, uint32_t delay_millis) {
  // TODO: have per-channel send_scope
  if (send_unscoped) {
    sendFlood(pkt, delay_millis, _prefs.path_hash_mode + 1);  // app has explicitly requested un-scoped
  } else {
    TransportKey default_scope;
    memcpy(&default_scope.key, _prefs.default_scope_key, sizeof(default_scope.key));

    auto scope = send_scope.isNull() ? &default_scope : &send_scope;
    sendFloodScoped(*scope, pkt, delay_millis);
  }
}

void MyMesh::onMessageRecv(const ContactInfo &from, mesh::Packet *pkt, uint32_t sender_timestamp,
                           const char *text) {
  markConnectionActive(from); // in case this is from a server, and we have a connection
  queueMessage(from, TXT_TYPE_PLAIN, pkt, sender_timestamp, NULL, 0, text);
}

void MyMesh::onCommandDataRecv(const ContactInfo &from, mesh::Packet *pkt, uint32_t sender_timestamp, const char *text) {
  markConnectionActive(from); // in case this is from a server, and we have a connection
  queueMessage(from, TXT_TYPE_CLI_DATA, pkt, sender_timestamp, NULL, 0, text);
}

void MyMesh::onCLICommandRecv(const ContactInfo &from, mesh::Packet *pkt, uint32_t sender_timestamp,
                               const char *text, char* reply) {
  markConnectionActive(from); // in case this is from a server, and we have a connection
  if (from.isRemoteCLIAllowed()) {
    if (!handleCommand(text, sender_timestamp, reply)) {
      strcat(reply, "Unknown command");   // reply may have cmd prefix from 'text'
    }
  } else {
    queueMessage(from, TXT_TYPE_CLI_COMMAND, pkt, sender_timestamp, NULL, 0, text);
  }
}

void MyMesh::onSignedMessageRecv(const ContactInfo &from, mesh::Packet *pkt, uint32_t sender_timestamp,
                                 const uint8_t *sender_prefix, const char *text) {
  markConnectionActive(from);
  // from.sync_since change needs to be persisted
  dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
  queueMessage(from, TXT_TYPE_SIGNED_PLAIN, pkt, sender_timestamp, sender_prefix, 4, text);
}

void MyMesh::onChannelMessageRecv(const mesh::GroupChannel &channel, mesh::Packet *pkt, uint32_t timestamp,
                                  const char *text) {
  int i = 0;
  if (app_target_ver >= 3) {
    out_frame[i++] = RESP_CODE_CHANNEL_MSG_RECV_V3;
    out_frame[i++] = (int8_t)(pkt->getSNR() * 4);
    out_frame[i++] = 0; // reserved1
    out_frame[i++] = 0; // reserved2
  } else {
    out_frame[i++] = RESP_CODE_CHANNEL_MSG_RECV;
  }

  uint8_t channel_idx = findChannelIdx(channel);
  out_frame[i++] = channel_idx;
  uint8_t path_len = out_frame[i++] = pkt->isRouteFlood() ? pkt->path_len : 0xFF;

  out_frame[i++] = TXT_TYPE_PLAIN;
  memcpy(&out_frame[i], &timestamp, 4);
  i += 4;
  int tlen = strlen(text); // TODO: UTF-8 ??
  if (i + tlen > MAX_FRAME_SIZE) {
    tlen = MAX_FRAME_SIZE - i;
  }
  memcpy(&out_frame[i], text, tlen);
  i += tlen;
  addToOfflineQueue(out_frame, i);

  if (_serial->isConnected()) {
    uint8_t frame[1];
    frame[0] = PUSH_CODE_MSG_WAITING; // send push 'tickle'
    _serial->writeFrame(frame, 1);
  }
  if (_listener) {
    // Get the channel name from the channel index
    ChannelDetails channel_details;
    if (!getChannel(channel_idx, channel_details)) {
      strcpy(channel_details.name, "Unknown");
    }
    _listener->onChannelMessageRecv(pkt, channel_details, text);
    _listener->onQueueSizeChanged(offline_queue_len);
  }
}

void MyMesh::onChannelDataRecv(const mesh::GroupChannel &channel, mesh::Packet *pkt, uint16_t data_type,
                               const uint8_t *data, size_t data_len) {
  if (data_len > MAX_CHANNEL_DATA_LENGTH) {
    MESH_DEBUG_PRINTLN("onChannelDataRecv: dropping payload_len=%d exceeds frame limit=%d",
                       (uint32_t)data_len, (uint32_t)MAX_CHANNEL_DATA_LENGTH);
    return;
  }

  int i = 0;
  out_frame[i++] = RESP_CODE_CHANNEL_DATA_RECV;
  out_frame[i++] = (int8_t)(pkt->getSNR() * 4);
  out_frame[i++] = 0; // reserved1
  out_frame[i++] = 0; // reserved2

  uint8_t channel_idx = findChannelIdx(channel);
  out_frame[i++] = channel_idx;
  out_frame[i++] = pkt->isRouteFlood() ? pkt->path_len : 0xFF;
  out_frame[i++] = (uint8_t)(data_type & 0xFF);
  out_frame[i++] = (uint8_t)(data_type >> 8);
  out_frame[i++] = (uint8_t)data_len;

  int copy_len = (int)data_len;
  if (copy_len > 0) {
    memcpy(&out_frame[i], data, copy_len);
    i += copy_len;
  }
  addToOfflineQueue(out_frame, i);

  if (_serial->isConnected()) {
    uint8_t frame[1];
    frame[0] = PUSH_CODE_MSG_WAITING; // send push 'tickle'
    _serial->writeFrame(frame, 1);
  }
  if (_listener) {
    _listener->onChannelDataRecv(pkt, channel, data_type, data, data_len);
  }
}

uint8_t MyMesh::onContactRequest(const ContactInfo &contact, uint32_t sender_timestamp, const uint8_t *data,
                                 uint8_t len, uint8_t *reply) {
  if (data[0] == REQ_TYPE_GET_TELEMETRY_DATA) {
    uint8_t permissions = 0;
    uint8_t cp = contact.flags >> 1; // LSB used as 'favourite' bit (so only use upper bits)

    if (_prefs.telemetry_mode_base == TELEM_MODE_ALLOW_ALL) {
      permissions = TELEM_PERM_BASE;
    } else if (_prefs.telemetry_mode_base == TELEM_MODE_ALLOW_FLAGS) {
      permissions = cp & TELEM_PERM_BASE;
    }

    if (_prefs.telemetry_mode_loc == TELEM_MODE_ALLOW_ALL) {
      permissions |= TELEM_PERM_LOCATION;
    } else if (_prefs.telemetry_mode_loc == TELEM_MODE_ALLOW_FLAGS) {
      permissions |= cp & TELEM_PERM_LOCATION;
    }

    if (_prefs.telemetry_mode_env == TELEM_MODE_ALLOW_ALL) {
      permissions |= TELEM_PERM_ENVIRONMENT;
    } else if (_prefs.telemetry_mode_env == TELEM_MODE_ALLOW_FLAGS) {
      permissions |= cp & TELEM_PERM_ENVIRONMENT;
    }

    uint8_t perm_mask = ~(data[1]);    // NEW: first reserved byte (of 4), is now inverse mask to apply to permissions
    permissions &= perm_mask;

    if (permissions & TELEM_PERM_BASE) { // only respond if base permission bit is set
      telemetry.reset();
      telemetry.addVoltage(TELEM_CHANNEL_SELF, (float)board.getBattMilliVolts() / 1000.0f);
      // query other sensors -- target specific
      sensors.querySensors(permissions, telemetry);

      float temperature = board.getMCUTemperature();
      if(!isnan(temperature)) { // Supported boards with built-in temperature sensor. ESP32-C3 may return NAN
        telemetry.addTemperature(TELEM_CHANNEL_SELF, temperature); // Built-in MCU Temperature
      }

      memcpy(reply, &sender_timestamp,
             4); // reflect sender_timestamp back in response packet (kind of like a 'tag')

      uint8_t tlen = telemetry.getSize();
      memcpy(&reply[4], telemetry.getBuffer(), tlen);
      return 4 + tlen;
    }
  } else if (_listener) {
    return _listener->onUnhandledRequest(contact, sender_timestamp, data, len, reply);
  }
  return 0; // unknown
}

void MyMesh::onContactResponse(const ContactInfo &contact, const uint8_t *data, uint8_t len) {
  uint32_t tag;
  memcpy(&tag, data, 4);

  if (pending_login && memcmp(&pending_login, contact.id.pub_key, 4) == 0) { // check for login response
    // yes, is response to pending sendLogin()
    pending_login = 0;

    int i = 0;
    if (memcmp(&data[4], "OK", 2) == 0) { // legacy Repeater login OK response
      out_frame[i++] = PUSH_CODE_LOGIN_SUCCESS;
      out_frame[i++] = 0; // legacy: is_admin = false
      memcpy(&out_frame[i], contact.id.pub_key, 6);
      i += 6;                                     // pub_key_prefix
    } else if (data[4] == RESP_SERVER_LOGIN_OK) { // new login response
      uint16_t keep_alive_secs = ((uint16_t)data[5]) * 16;
      if (keep_alive_secs > 0) {
        startConnection(contact, keep_alive_secs);
      }
      out_frame[i++] = PUSH_CODE_LOGIN_SUCCESS;
      out_frame[i++] = data[6]; // permissions (eg. is_admin)
      memcpy(&out_frame[i], contact.id.pub_key, 6);
      i += 6; // pub_key_prefix
      memcpy(&out_frame[i], &tag, 4);
      i += 4; // NEW: include server timestamp
      out_frame[i++] = data[7]; // NEW (v7): ACL permissions
      out_frame[i++] = data[12]; // FIRMWARE_VER_LEVEL
    } else {
      out_frame[i++] = PUSH_CODE_LOGIN_FAIL;
      out_frame[i++] = 0; // reserved
      memcpy(&out_frame[i], contact.id.pub_key, 6);
      i += 6; // pub_key_prefix
    }
    _serial->writeFrame(out_frame, i);
  } else if (len > 4 && // check for status response
             pending_status &&
             memcmp(&pending_status, contact.id.pub_key, 4) == 0 // legacy matching scheme
                                                                 // FUTURE: tag == pending_status
  ) {
    pending_status = 0;

    int i = 0;
    out_frame[i++] = PUSH_CODE_STATUS_RESPONSE;
    out_frame[i++] = 0; // reserved
    memcpy(&out_frame[i], contact.id.pub_key, 6);
    i += 6; // pub_key_prefix
    memcpy(&out_frame[i], &data[4], len - 4);
    i += (len - 4);
    _serial->writeFrame(out_frame, i);
  } else if (len > 4 && tag == pending_telemetry) {  // check for matching response tag
    pending_telemetry = 0;

    int i = 0;
    out_frame[i++] = PUSH_CODE_TELEMETRY_RESPONSE;
    out_frame[i++] = 0; // reserved
    memcpy(&out_frame[i], contact.id.pub_key, 6);
    i += 6; // pub_key_prefix
    memcpy(&out_frame[i], &data[4], len - 4);
    i += (len - 4);
    _serial->writeFrame(out_frame, i);
  } else if (len > 4 && tag == pending_req) {  // check for matching response tag
    pending_req = 0;

    int i = 0;
    out_frame[i++] = PUSH_CODE_BINARY_RESPONSE;
    out_frame[i++] = 0; // reserved
    memcpy(&out_frame[i], &tag, 4);   // app needs to match this to RESP_CODE_SENT.tag
    i += 4;
    memcpy(&out_frame[i], &data[4], len - 4);
    i += (len - 4);
    _serial->writeFrame(out_frame, i);
  } else {
    bool handled;
    if (_listener && len > 4) {
      handled = _listener->onUnhandledResponse(contact, tag, &data[4], len - 4);
    } else {
      handled = false;
    }
    if (!handled) {   // let the app know about unknown/unhandled responses (eg. push telemetry packets)
      int i = 0;
      out_frame[i++] = PUSH_CODE_BINARY_RESPONSE;
      out_frame[i++] = 0; // reserved
      memcpy(&out_frame[i], data, len);
      i += len;
      _serial->writeFrame(out_frame, i);
    }
  }
}

bool MyMesh::onContactPathRecv(ContactInfo& contact, uint8_t* in_path, uint8_t in_path_len, uint8_t* out_path, uint8_t out_path_len, uint8_t extra_type, uint8_t* extra, uint8_t extra_len) {
  if (extra_type == PAYLOAD_TYPE_RESPONSE && extra_len > 4) {
    uint32_t tag;
    memcpy(&tag, extra, 4);

    if (tag == pending_discovery) {  // check for matching response tag)
      pending_discovery = 0;

      if (!mesh::Packet::isValidPathLen(in_path_len) || !mesh::Packet::isValidPathLen(out_path_len)) {
        MESH_DEBUG_PRINTLN("onContactPathRecv, invalid path sizes: %d, %d", in_path_len, out_path_len);
      } else {
        int i = 0;
        out_frame[i++] = PUSH_CODE_PATH_DISCOVERY_RESPONSE;
        out_frame[i++] = 0; // reserved
        memcpy(&out_frame[i], contact.id.pub_key, 6);
        i += 6; // pub_key_prefix
        out_frame[i++] = out_path_len;
        i += mesh::Packet::writePath(&out_frame[i], out_path, out_path_len);
        out_frame[i++] = in_path_len;
        i += mesh::Packet::writePath(&out_frame[i], in_path, in_path_len);
        // NOTE: telemetry data in 'extra' is discarded at present

        _serial->writeFrame(out_frame, i);
      }
      return false;  // DON'T send reciprocal path!
    }
  }
  // let base class handle received path and data
  return BaseChatMesh::onContactPathRecv(contact, in_path, in_path_len, out_path, out_path_len, extra_type, extra, extra_len);
}

void MyMesh::onControlDataRecv(mesh::Packet *packet) {
  if (packet->payload_len + 4 > sizeof(out_frame)) {
    MESH_DEBUG_PRINTLN("onControlDataRecv(), payload_len too long: %d", packet->payload_len);
    return;
  }
  int i = 0;
  out_frame[i++] = PUSH_CODE_CONTROL_DATA;
  out_frame[i++] = (int8_t)(_radio->getLastSNR() * 4);
  out_frame[i++] = (int8_t)(_radio->getLastRSSI());
  out_frame[i++] = packet->path_len;
  memcpy(&out_frame[i], packet->payload, packet->payload_len);
  i += packet->payload_len;

  if (_serial->isConnected()) {
    _serial->writeFrame(out_frame, i);
  } else {
    MESH_DEBUG_PRINTLN("onControlDataRecv(), data received while app offline");
  }

  if (_listener) _listener->onControlDataRecv(packet);
}

void MyMesh::onRawDataRecv(mesh::Packet *packet) {
  if (packet->payload_len + 4 > sizeof(out_frame)) {
    MESH_DEBUG_PRINTLN("onRawDataRecv(), payload_len too long: %d", packet->payload_len);
    return;
  }
  int i = 0;
  out_frame[i++] = PUSH_CODE_RAW_DATA;
  out_frame[i++] = (int8_t)(_radio->getLastSNR() * 4);
  out_frame[i++] = (int8_t)(_radio->getLastRSSI());
  out_frame[i++] = 0xFF; // reserved (possibly path_len in future)
  memcpy(&out_frame[i], packet->payload, packet->payload_len);
  i += packet->payload_len;

  if (_serial->isConnected()) {
    _serial->writeFrame(out_frame, i);
  } else {
    MESH_DEBUG_PRINTLN("onRawDataRecv(), data received while app offline");
  }
  if (_listener) {
    _listener->onRawDataRecv(packet);
  }
}

void MyMesh::onTraceRecv(mesh::Packet *packet, uint32_t tag, uint32_t auth_code, uint8_t flags,
                         const uint8_t *path_snrs, const uint8_t *path_hashes, uint8_t path_len) {
  uint8_t path_sz = flags & 0x03;  // NEW v1.11+
  if (12 + path_len + (path_len >> path_sz) + 1 > sizeof(out_frame)) {
    MESH_DEBUG_PRINTLN("onTraceRecv(), path_len is too long: %d", (uint32_t)path_len);
    return;
  }
  int i = 0;
  out_frame[i++] = PUSH_CODE_TRACE_DATA;
  out_frame[i++] = 0; // reserved
  out_frame[i++] = path_len;
  out_frame[i++] = flags;
  memcpy(&out_frame[i], &tag, 4);
  i += 4;
  memcpy(&out_frame[i], &auth_code, 4);
  i += 4;
  memcpy(&out_frame[i], path_hashes, path_len);
  i += path_len;

  memcpy(&out_frame[i], path_snrs, path_len >> path_sz);
  i += path_len >> path_sz;
  out_frame[i++] = (int8_t)(packet->getSNR() * 4); // extra/final SNR (to this node)

  if (_serial->isConnected()) {
    _serial->writeFrame(out_frame, i);
  } else {
    MESH_DEBUG_PRINTLN("onTraceRecv(), data received while app offline");
  }
  if (_listener) {
    _listener->onTraceRecv(packet, tag, auth_code, flags, path_snrs, path_hashes, path_len);
  }
}

uint32_t MyMesh::calcFloodTimeoutMillisFor(uint32_t pkt_airtime_millis) const {
  return SEND_TIMEOUT_BASE_MILLIS + (FLOOD_SEND_TIMEOUT_FACTOR * pkt_airtime_millis);
}
uint32_t MyMesh::calcDirectTimeoutMillisFor(uint32_t pkt_airtime_millis, uint8_t path_len) const {
  uint8_t path_hash_count = path_len & 63;
  return SEND_TIMEOUT_BASE_MILLIS +
         ((pkt_airtime_millis * DIRECT_SEND_PERHOP_FACTOR + DIRECT_SEND_PERHOP_EXTRA_MILLIS) *
          (path_hash_count + 1));
}

void MyMesh::onSendTimeout() {}

MyMesh::MyMesh(mesh::Radio &radio, mesh::RNG &rng, mesh::RTCClock &rtc, SimpleMeshTables &tables, DataStore& store)
    : BaseChatMesh(radio, *new ArduinoMillis(), rng, rtc, *new StaticPoolPacketManager(16), tables),
      _serial(NULL), telemetry(MAX_PACKET_PAYLOAD - 4), _store(&store), _listener(NULL), _iter(0) {
  _iter_started = false;
  _cli_rescue = false;
  cli_command[0] = 0;
  offline_queue_len = 0;
  app_target_ver = 0;
  clearPendingReqs();
  next_ack_idx = 0;
  sign_data = NULL;
  dirty_contacts_expiry = 0;
  _temporary_radio_lease.reset();
  pending_freq = 0.0f;
  pending_bw = 0.0f;
  pending_sf = 0;
  pending_cr = 0;
  memset(advert_paths, 0, sizeof(advert_paths));
  memset(send_scope.key, 0, sizeof(send_scope.key));
  send_unscoped = false;

  // defaults
  _prefs.airtime_factor = 1.0;
  _prefs.tx_delay_factor = 0.5f;
  _prefs.direct_tx_delay_factor = 0.2f;
  strcpy(_prefs.node_name, "NONAME");
  _prefs.freq = LORA_FREQ;
  _prefs.sf = LORA_SF;
  _prefs.bw = LORA_BW;
  _prefs.cr = LORA_CR;
  _prefs.tx_power_dbm = LORA_TX_POWER;
  _prefs.gps_enabled = 0;       // GPS disabled by default
  _prefs.gps_interval = 0;      // No automatic GPS updates by default
  _prefs.radio_fem_rxgain = 1;
#ifdef RADIO_FEM_TXGAIN
  _prefs.radio_fem_txgain = RADIO_FEM_TXGAIN;   // board-specific default for PA
#else
  _prefs.radio_fem_txgain = 0;
#endif
  //_prefs.rx_delay_base = 10.0f;  enable once new algo fixed
  _prefs.setRepeatEn(false);
#if defined(USE_SX1262) || defined(USE_SX1268)
#ifdef SX126X_RX_BOOSTED_GAIN
  _prefs.rx_boosted_gain = SX126X_RX_BOOSTED_GAIN;
#else
  _prefs.rx_boosted_gain = 1; // enabled by default
#endif
#endif
}

void MyMesh::begin(bool allow_destructive_boot_writes, bool allow_identity_generation,
                   identity_io::LoadStatus identity_status) {
  BaseChatMesh::begin();

#if MESHCORE_LORA_OTA
  const bool normal_proven = otaBoardEarlyBootNormalProven();
  const bool radio_ready = _ota_trial_radio_ready && _radio != nullptr && _radio->probeDriverStatus();
  _ota_trial_radio_ready = radio_ready;
  if (identity_status == identity_io::LoadStatus::Unchecked) {
    identity_status = _store->loadMainIdentityStatus(self_id, _ota_trial_filesystem_ready);
  }
  allow_destructive_boot_writes = allow_destructive_boot_writes && radio_ready &&
      identity_io::canWriteUserdata(normal_proven, _ota_trial_filesystem_ready, identity_status);
  if (!allow_destructive_boot_writes) _store->disallowDestructiveWrites();
  allow_identity_generation = allow_identity_generation &&
      allow_destructive_boot_writes && identity_io::canProvisionIdentity(
          normal_proven, radio_ready, _ota_trial_filesystem_ready, identity_status);
  const bool identity_initially_loaded = identity_status == identity_io::LoadStatus::Loaded;
#else
  const bool identity_initially_loaded = identity_status == identity_io::LoadStatus::Unchecked
      ? _store->loadMainIdentity(self_id) : identity_status == identity_io::LoadStatus::Loaded;
#endif
#if MESHCORE_LORA_OTA
  // Hoisted so the fallback branch below can also update it from the
  // actual resolveIdentityTrialSafe() outcome (see after the branch).
  // Also latches fault evidence unconditionally on a genuine load
  // failure -- see OtaFirmwareService::noteIdentityLoadAttempted()'s doc
  // comment (even a legitimately blank/never-configured device reaches
  // this: a failed read cannot be distinguished from storage corruption
  // caused by an in-progress OTA candidate).
  _ota_service_.noteIdentityLoadAttempted(identity_initially_loaded);
#endif
  if (!identity_initially_loaded) {
    bool save_ok = false;
    const ota_identity_boot::Outcome outcome = ota_identity_boot::resolveIdentityTrialSafe(
        allow_identity_generation,
        [this]() { return false; },  // load_fn: already known-failed above, never re-invoked.
        [this]() {
          self_id = radio_new_identity();  // create new random identity (RAM-only, until persisted below)
          int count = 0;
          while (count < 10 && (self_id.pub_key[0] == 0x00 || self_id.pub_key[0] == 0xFF)) {  // reserved id hashes
            self_id = radio_new_identity();
            count++;
          }
        },
        [this, &save_ok]() {
          save_ok = _store->saveMainIdentity(self_id);
          return save_ok;
        });
    if (outcome == ota_identity_boot::Outcome::IdentityUnavailable) {
#if MESHCORE_LORA_OTA
      // OTA trial/unknown boot (see otaBoardEarlyBootTrialOrUnknown(),
      // queried by main.cpp BEFORE this call): the ORIGINAL persisted
      // identity might merely be transiently unreadable, not genuinely
      // corrupt/absent -- generating ANY identity now (even RAM-only)
      // and using it for mesh TX/crypto would violate the trial's
      // read-only contract and could itself destroy the real secret's
      // only chance of recovery if this trial later fails and rolls
      // back. Perform ZERO generation and ZERO writes: self_id is left
      // at its default/unset value, and loop() suppresses all ordinary
      // (identity-dependent) mesh dispatch for the rest of this boot,
      // leaving only the bounded serial/diagnostic/trial-health path
      // running until a genuine future reboot.
      _identity_available_ = false;
#endif
    } else if (outcome == ota_identity_boot::Outcome::GeneratedAndSaved ||
               outcome == ota_identity_boot::Outcome::GeneratedRamOnlyNoWrites) {
#if MESHCORE_LORA_OTA
      const bool identity_write_disallowed = _store->destructiveWritesDisallowed();
      if (outcome == ota_identity_boot::Outcome::GeneratedRamOnlyNoWrites) {
        _identity_available_ = false;
        self_id = mesh::LocalIdentity();
        _store->disallowDestructiveWrites();
        allow_destructive_boot_writes = false;
      }
      // Real, already-performed ordinary filesystem write at boot -- its
      // ACTUAL outcome is genuine trial-boot-health evidence (see
      // tickOtaTrialHealth()); this runs before configureCompanionFirmware
      // OtaBackend() below constructs the confirmer, so the service is
      // already correctly updated for that confirmer's very first tick.
      // (This branch is only reachable when identity generation WAS
      // permitted, so a failed save here is always a genuine I/O fault,
      // never a policy refusal -- the destructiveWritesDisallowed()
      // check inside noteIdentityResolution() is defensive/future-
      // proofing only, kept consistent with every other save-site below.)
      _ota_service_.noteIdentityResolution(outcome, identity_write_disallowed);
#else
      (void)save_ok;
#endif
    }
  }

// if name is provided as a build flag, use that as default node name instead
#ifdef ADVERT_NAME
  strcpy(_prefs.node_name, ADVERT_NAME);
#else
  // use hex of first 4 bytes of identity public key as default node name
  char pub_key_hex[10];
  mesh::Utils::toHex(pub_key_hex, self_id.pub_key, 4);
  strcpy(_prefs.node_name, pub_key_hex);
#endif

  // if build provides default-scope, init with that
#ifdef DEFAULT_FLOOD_SCOPE_NAME
  strcpy(_prefs.default_scope_name, DEFAULT_FLOOD_SCOPE_NAME);
  {
    TransportKeyStore temp;
    TransportKey key;
    temp.getAutoKeyFor(0, "#" DEFAULT_FLOOD_SCOPE_NAME, key);
    memcpy(_prefs.default_scope_key, key.key, sizeof(key.key));
  }
#endif

  // load persisted prefs
  {
    const bool prefs_ok = _store->loadPrefs(_prefs, allow_destructive_boot_writes);
#if MESHCORE_LORA_OTA
    if (!prefs_ok) _ota_service_.noteStorageIoResult(false);
#else
    (void)prefs_ok;
#endif
  }
  sensors.node_lat = _prefs.node_lat;
  sensors.node_lon = _prefs.node_lon;

  // sanitise bad pref values
  _prefs.rx_delay_base = constrain(_prefs.rx_delay_base, 0, 20.0f);
  _prefs.tx_delay_factor = constrain(_prefs.tx_delay_factor, 0, 2.0f);
  _prefs.direct_tx_delay_factor = constrain(_prefs.direct_tx_delay_factor, 0, 2.0f);
  _prefs.airtime_factor = constrain(_prefs.airtime_factor, 0, 9.0f);
  _prefs.freq = constrain(_prefs.freq, 150.0f, 2500.0f);
  _prefs.bw = constrain(_prefs.bw, 7.8f, 500.0f);
  _prefs.sf = constrain(_prefs.sf, 5, 12);
  _prefs.cr = constrain(_prefs.cr, 5, 8);
  _prefs.tx_power_dbm = constrain(_prefs.tx_power_dbm, -9, MAX_LORA_TX_POWER);
  _prefs.gps_enabled = constrain(_prefs.gps_enabled, 0, 1);  // Ensure boolean 0 or 1
  _prefs.gps_interval = constrain(_prefs.gps_interval, 0, 86400);  // Max 24 hours
#if MESHCORE_LORA_OTA
  _prefs.ota_mode = constrain(_prefs.ota_mode, 0, 2);
  // Migrate any non-finite (NaN/Inf, e.g. from erased-flash 0xFF bytes
  // reinterpreted as float) or non-positive persisted value to the default
  // 2% before constrain(), since NaN silently passes a `<= 0.0f` check
  // (all NaN comparisons are false) and would otherwise reach constrain()
  // and the airtime-budget float->integer conversion undefined.
  if (!std::isfinite(_prefs.ota_duty_percent) || _prefs.ota_duty_percent < 0.0f) {
    _prefs.ota_duty_percent = 2.0f;
  }
  _prefs.ota_duty_percent = constrain(_prefs.ota_duty_percent, 0.0f, 100.0f);
  getOtaIntegration().setMode(static_cast<mesh::ota::FirmwareOtaMode>(_prefs.ota_mode));
  getOtaIntegration().setDutyCyclePercent(_prefs.ota_duty_percent);
  setOtaAirtimeDutyCyclePercent(_prefs.ota_duty_percent);
  getOtaIntegration().setLeanAdminCheck(this, &MyMesh::otaAdminCheckThunk);
  if (_identity_available_) getOtaIntegration().setLeanTargetPublicKey(self_id.pub_key);
  getOtaIntegration().attachRfProfileIdentity(this, &MyMesh::otaSelfIdSignThunk, &MyMesh::otaRadioChangeThunk,
                                       static_cast<uint32_t>(_prefs.freq * 1000.0f + 0.5f));
  getOtaIntegration().attachBootLifecycle(this, &MyMesh::otaBootLifecycleThunk, &MyMesh::otaBootCandidateThunk);
  configureCompanionFirmwareOtaBackend(getOtaIntegration());
#if defined(NRF52840_XXAA)
  getOtaIntegration().attachCommitReboot(nullptr, [](void*) { board.reboot(); });
#endif
#endif

  _active_ble_pin = _prefs.ble_pin;

  resetContacts();
  {
    const bool contacts_ok = _store->loadContacts(this);
#if MESHCORE_LORA_OTA
    if (!contacts_ok) _ota_service_.noteStorageIoResult(false);
#else
    (void)contacts_ok;
#endif
  }
  bootstrapRTCfromContacts();
  addChannel("Public", PUBLIC_GROUP_PSK); // pre-configure public channel
  {
    const bool channels_ok = _store->loadChannels(this);
#if MESHCORE_LORA_OTA
    if (!channels_ok) _ota_service_.noteStorageIoResult(false);
#else
    (void)channels_ok;
#endif
  }

  applyRadioParams(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
  radio_driver.setTxPower(_prefs.tx_power_dbm);
  radio_driver.setRxBoostedGainMode(_prefs.rx_boosted_gain);

  board.attachDynamicPrefs(_prefs.getCustom());

  MESH_DEBUG_PRINTLN("RX Boosted Gain Mode: %s",
                     radio_driver.getRxBoostedGainMode() ? "Enabled" : "Disabled");
}

const char *MyMesh::getNodeName() {
  return _prefs.node_name;
}
NodePrefs *MyMesh::getNodePrefs() {
  return &_prefs;
}
uint32_t MyMesh::getBLEPin() {
  return _active_ble_pin;
}
void MyMesh::setBLEPin(uint32_t active_pin) {
  _active_ble_pin = active_pin;
}

struct FreqRange {
  uint32_t lower_freq, upper_freq;
};

static FreqRange repeat_freq_ranges[] = {
  #ifdef ALLOWED_REPEAT_FREQ_RANGE
  ALLOWED_REPEAT_FREQ_RANGE
  #else
  { 433000, 433000 },
  { 869495, 869495 },
  { 918000, 918000 }
  #endif
};

bool MyMesh::isValidClientRepeatFreq(uint32_t f) const {
  for (int i = 0; i < sizeof(repeat_freq_ranges)/sizeof(repeat_freq_ranges[0]); i++) {
    auto r = &repeat_freq_ranges[i];
    if (f >= r->lower_freq && f <= r->upper_freq) return true;
  }
  return false;
}

void MyMesh::startInterface(BaseSerialInterface &serial) {
  _serial = &serial;
  serial.enable();
}

void MyMesh::applyTempRadioParams(float freq, float bw, uint8_t sf, uint8_t cr, int timeout_mins) {
#if MESHCORE_LORA_OTA
  _ota_rf_uploader.stop(getOtaIntegration());
#endif
  pending_freq = freq;
  pending_bw = bw;
  pending_sf = sf;
  pending_cr = cr;

  _temporary_radio_lease.schedule(_ms->getMillis(), timeout_mins);
}

bool MyMesh::setFirmwareOtaMode(const char* mode) {
#if MESHCORE_LORA_OTA
  mesh::ota::FirmwareOtaMode parsed;
  if (!mesh::ota::parseFirmwareOtaMode(mode, parsed)) return false;
  _prefs.ota_mode = static_cast<uint8_t>(parsed);
  getOtaIntegration().setMode(parsed);
  savePrefs();
  return true;
#else
  (void)mode;
  return false;
#endif
}

const char* MyMesh::getFirmwareOtaMode() const {
#if MESHCORE_LORA_OTA
  return mesh::ota::firmwareOtaModeName(static_cast<mesh::ota::FirmwareOtaMode>(_prefs.ota_mode));
#else
  return "unsupported";
#endif
}

bool MyMesh::setFirmwareOtaDutyCycle(float percent) {
#if MESHCORE_LORA_OTA
  if (!std::isfinite(percent) || percent <= 0.0f || percent > 100.0f) return false;
  if (!getOtaIntegration().setDutyCyclePercent(percent)) return false;
  if (!setOtaAirtimeDutyCyclePercent(percent)) return false;
  _prefs.ota_duty_percent = percent;
  savePrefs();
  return true;
#else
  (void)percent;
  return false;
#endif
}

float MyMesh::getFirmwareOtaDutyCycle() const {
#if MESHCORE_LORA_OTA
  return _prefs.ota_duty_percent;
#else
  return 0.0f;
#endif
}

#if MESHCORE_LORA_OTA
bool MyMesh::attachFirmwareOtaBackend(meshcore::ota::runtime::IOtaTrustProvider& trust_provider,
                                      meshcore::ota::runtime::IOtaStagingSink& staging_sink) {
  getOtaIntegration().attachTrustProvider(&trust_provider);
  getOtaIntegration().attachStagingSink(&staging_sink);
  return true;
}
#endif

void MyMesh::abortFirmwareOta() {
#if MESHCORE_LORA_OTA
  _ota_rf_uploader.stop(getOtaIntegration());
  _ota_upload_active = false;
  getOtaIntegration().abortSession();
#endif
  if (_temporary_radio_lease.pending()) {
    _temporary_radio_lease.cancel(_ms->getMillis());
    revertTempRadioLeaseIfDue();
  }
}

void MyMesh::rollbackFirmwareOta() {
#if MESHCORE_LORA_OTA
  getOtaIntegration().requestRollback();
#endif
  abortFirmwareOta();
}

void MyMesh::formatFirmwareOtaStatus(char* reply, size_t reply_size) {
#if MESHCORE_LORA_OTA
  auto& integration = getOtaIntegration();
  const auto boot = integration.bootLifecycle();
  const auto view = integration.readback(boot);
  mesh::ota::formatOtaBootLifecycleStatus(reply, reply_size, boot,
                                         view.phase, view.snapshot.counter);
#else
  snprintf(reply, reply_size, "OTA unsupported");
#endif
}

void MyMesh::applyRadioParams(float freq, float bw, uint8_t sf, uint8_t cr) {
  radio_driver.setParams(freq, bw, sf, cr);
}

bool MyMesh::isOtaAdminKey(const uint8_t key[32]) const {
#if MESHCORE_LORA_OTA
  if (key == nullptr) return false;
  if (_identity_available_ && std::memcmp(key, self_id.pub_key, PUB_KEY_SIZE) == 0) return true;
  ContactInfo* contact = const_cast<MyMesh*>(this)->lookupContactByPubKey(key, PUB_KEY_SIZE);
  return contact != nullptr && contact->isOtaAdmin();
#else
  (void)key;
  return false;
#endif
}

bool MyMesh::otaAdminCheckThunk(void* ctx, const uint8_t key[32]) {
  return ctx != nullptr && static_cast<MyMesh*>(ctx)->isOtaAdminKey(key);
}

#if MESHCORE_LORA_OTA
void MyMesh::otaSelfIdSignThunk(void* ctx, const uint8_t* message, size_t message_len, uint8_t signature_out[64]) {
  static_cast<MyMesh*>(ctx)->self_id.sign(signature_out, message, static_cast<int>(message_len));
}

bool MyMesh::floodOtaFrame(const uint8_t* frame, size_t frame_len, meshcore::ota::protocol::OtaAirtimeCategory category) {
  if (_radio == nullptr || frame == nullptr || frame_len == 0) return false;
  const uint32_t now_ms = _ms->getMillis();
  if (isSendInProgress() || _mgr->getOutboundTotal() != 0) return false;
  const uint32_t est_airtime_ms = _radio->getEstAirtimeFor(static_cast<int>(frame_len + 4));
  if (!getOtaIntegration().canTransmit(now_ms, category, est_airtime_ms, /*regulatory_allowed=*/true,
                                      /*normal_traffic_active=*/isSendInProgress())) {
    return false;
  }
  auto* pkt = createOtaData(frame, frame_len);
  if (pkt == nullptr) return false;
  if (!sendFlood(pkt, static_cast<uint32_t>(0), _prefs.path_hash_mode + 1)) return false;
  return true;
}

bool MyMesh::sendOtaControlFrameToTarget(const uint8_t target[32], const uint8_t* frame, size_t frame_len,
                                        meshcore::ota::protocol::OtaAirtimeCategory category) {
  if (_radio == nullptr || frame == nullptr || frame_len == 0) return false;
  uint8_t wire[MAX_PACKET_PAYLOAD];
  const bool new_attempt = getOtaIntegration().retryAttemptsEnabled() &&
                           !mesh::ota::isOtaRetryAttempt(frame[0]);
  frame_len = getOtaIntegration().prepareRfTransmit(frame, frame_len, wire, sizeof(wire));
  if (!frame_len) return false;
  frame = wire;
  ContactInfo* contact = lookupContactByPubKey(target, PUB_KEY_SIZE);
  const uint8_t path = !getOtaIntegration().directActive() && contact &&
      contact->out_path_len != OUT_PATH_UNKNOWN ? contact->out_path_len : 0;
  if (!mesh::ota::otaRfPathFits(frame_len, path)) return false;
  const uint32_t now_ms = _ms->getMillis();
  if (isSendInProgress() || _mgr->getOutboundTotal() != 0) return false;
  const uint32_t est_airtime_ms = _radio->getEstAirtimeFor(static_cast<int>(
      mesh::ota::isOtaRetryAttempt(frame[0]) ?
          frame_len + 2 + ((path >> 6) + 1) * (path & 63) : frame_len + 4));
  if (!getOtaIntegration().canTransmit(now_ms, category, est_airtime_ms, /*regulatory_allowed=*/true,
                                      /*normal_traffic_active=*/isSendInProgress())) {
    return false;
  }
  auto* pkt = createOtaData(frame, frame_len);
  if (pkt == nullptr) return false;
  // The frame's own embedded target field is what actually matters (the
  // remote receiver re-derives its signed message using ITS OWN real
  // identity, never a wire-routing hint -- see OtaLeanReceiver::commit()/
  // abort()'s doc comment), so a known direct path is purely an airtime
  // optimization, never a correctness requirement.
  if (getOtaIntegration().directActive()) {
    sendZeroHop(pkt);
  } else if (contact != nullptr && contact->out_path_len != OUT_PATH_UNKNOWN) {
    sendDirect(pkt, contact->out_path, contact->out_path_len);
  } else if (!sendFlood(pkt, static_cast<uint32_t>(0), _prefs.path_hash_mode + 1)) {
    return false;
  }
  if (_mgr->getOutboundTotal() == 0) return false;
  return !new_attempt || getOtaIntegration().acceptRfTransmit(frame, frame_len);
}

bool MyMesh::otaRadioChangeThunk(void* ctx, uint32_t frequency_khz, mesh::ota::OtaDirectProfile profile, bool restore) {
  auto* mesh = static_cast<MyMesh*>(ctx);
  return otaBoardApplyRfProfile(restore ? mesh->_prefs.freq : frequency_khz / 1000.0f,
                         restore ? mesh->_prefs.bw : mesh::ota::otaDirectBandwidthHz(profile) / 1000.0f,
                         restore ? mesh->_prefs.sf : 5, restore ? mesh->_prefs.cr : 5);
}
bool MyMesh::otaBootLifecycleThunk(void*, mesh::ota::OtaBootLifecycleEvidence& out) {
  return otaBoardGetBootLifecycle(out);
}
bool MyMesh::otaBootCandidateThunk(void*, const mesh::ota::OtaBootLifecycleEvidence& boot,
                                  ::ota::storage::OtaCandidateStore::Snapshot& out) {
  return otaBoardReadBootCandidate(boot, out);
}

bool MyMesh::otaSendThunk(void* ctx, mesh::ota::OtaRfRoute route, const uint8_t target[32],
                          const uint8_t* frame, size_t len, meshcore::ota::protocol::OtaAirtimeCategory category) {
  auto* mesh = static_cast<MyMesh*>(ctx);
  if (route == mesh::ota::OtaRfRoute::Directed) {
    auto* contact = mesh->lookupContactByPubKey(target, PUB_KEY_SIZE);
    if (!contact || contact->out_path_len == OUT_PATH_UNKNOWN) return false;
    return mesh->sendOtaControlFrameToTarget(target, frame, len, category);
  }
  if (route == mesh::ota::OtaRfRoute::Multicast) {
    if (mesh->_ota_upload_channel == 0xFF) return mesh->floodOtaFrame(frame, len, category);
    ChannelDetails channel;
    if (!mesh->getChannel(mesh->_ota_upload_channel, channel) || !mesh->_radio ||
        mesh->isSendInProgress() || mesh->_mgr->getOutboundTotal() != 0) return false;
    if (!mesh->getOtaIntegration().canTransmit(mesh->_ms->getMillis(), category,
          mesh->_radio->getEstAirtimeFor(len + 8), true, false)) return false;
    auto* packet = mesh->createOtaData(frame, len);
    if (!packet) return false;
    // Same region/scoping rules as ordinary multicast for this channel;
    // OTA authority remains the original full-key block signature.
    mesh->sendFloodScoped(channel.channel, packet);
    return true;
  }
  if (!mesh->_radio || mesh->isSendInProgress() || mesh->_mgr->getOutboundTotal() != 0) return false;
  const uint32_t now = mesh->_ms->getMillis();
  if (!mesh->getOtaIntegration().canTransmit(now, category, mesh->_radio->getEstAirtimeFor(len + 4), true, false)) return false;
  auto* packet = mesh->createOtaData(frame, len);
  if (!packet) return false;
  mesh->sendZeroHop(packet);
  return true;
}

void MyMesh::pumpOtaRfUpload() {
  if (!_identity_available_) { _ota_rf_uploader.stop(getOtaIntegration()); return; }
  if (isSendInProgress() || _mgr->getOutboundTotal() != 0) return;
  if (_ota_stop_upload_when_idle) {
    _ota_stop_upload_when_idle = false;
    _ota_rf_uploader.stop(getOtaIntegration());
  }
  _ota_rf_uploader.pump(getOtaIntegration(), _ms->getMillis(), this, &MyMesh::otaSelfIdSignThunk, &MyMesh::otaSendThunk);
  _ota_upload_active = _ota_rf_uploader.active();
}
#endif

void MyMesh::handleUsbOtaProtocolOp(uint8_t op, const uint8_t* cmd_frame, int len) {
  using namespace mesh::ota::usb;

  UsbOtaReply reply;
  reply.requestOp = op;
  reply.setNoSnapshot();

#if MESHCORE_LORA_OTA
  auto& lean = getOtaIntegration().leanReceiver();
  auto mapPhase = [](const ::ota::storage::OtaCandidateStore::Phase phase) -> UsbOtaPhase {
    switch (phase) {
      case ::ota::storage::OtaCandidateStore::Phase::Receiving: return UsbOtaPhase::Receiving;
      case ::ota::storage::OtaCandidateStore::Phase::Verifying: return UsbOtaPhase::Verifying;
      case ::ota::storage::OtaCandidateStore::Phase::Ready: return UsbOtaPhase::Ready;
      case ::ota::storage::OtaCandidateStore::Phase::Committed: return UsbOtaPhase::CommitPending;
      case ::ota::storage::OtaCandidateStore::Phase::Aborted: return UsbOtaPhase::Aborted;
      case ::ota::storage::OtaCandidateStore::Phase::Failed: return UsbOtaPhase::Failed;
      default: return UsbOtaPhase::Idle;
    }
  };
  auto fillLocalSnapshot = [&]() {
    getOtaIntegration().fillUsbReadback(reply);
  };
  const auto sendRemoteControl = [](void* ctx, const uint8_t target[32], const uint8_t* frame, size_t frame_len) {
    return static_cast<MyMesh*>(ctx)->sendOtaControlFrameToTarget(
        target, frame, frame_len, meshcore::ota::protocol::OtaAirtimeCategory::Control);
  };

  switch (static_cast<UsbOtaOp>(op)) {
    case UsbOtaOp::SetContactAdmin: {
      if ((size_t)len != kSetContactAdminTotalBytes || cmd_frame[34] > 1) {
        reply.result = UsbOtaResult::BadRequest;
        break;
      }
      const uint8_t* pub_key = &cmd_frame[2];
      const bool enable = cmd_frame[2 + kPubKeyBytes] != 0;
      std::memcpy(reply.target, pub_key, kPubKeyBytes);
      if (_store->destructiveWritesDisallowed()) {
        reply.result = UsbOtaResult::Denied;
        break;
      }
      ContactInfo* recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
      if (!recipient) {
        reply.result = UsbOtaResult::NotFound;
        break;
      }
      const uint8_t prev_permissions = recipient->ota_permissions;
      const uint32_t prev_lastmod = recipient->lastmod;
      recipient->setOtaAdmin(enable);
      recipient->lastmod = getRTCClock()->getCurrentTime();
      if (saveContacts()) reply.result = UsbOtaResult::Ok;
      else {
        recipient->ota_permissions = prev_permissions;
        recipient->lastmod = prev_lastmod;
        reply.result = UsbOtaResult::IoError;
      }
      break;
    }
    case UsbOtaOp::CacheBegin: {
      reply = getOtaIntegration().handleUsbLocalControl(cmd_frame, static_cast<size_t>(len),
                                                       _identity_available_ ? self_id.pub_key : nullptr);
      if (reply.result == UsbOtaResult::Ok) {
        _ota_rf_uploader.stop(getOtaIntegration());
        _ota_cache_reupload = (cmd_frame[2] & kCacheBeginFlagReupload) != 0;
        _ota_selected_target_count = 0;
      }
      break;
    }
    case UsbOtaOp::CachePut:
    case UsbOtaOp::CacheSeal: {
      reply = getOtaIntegration().handleUsbLocalControl(cmd_frame, static_cast<size_t>(len),
                                                       _identity_available_ ? self_id.pub_key : nullptr);
      break;
    }
    case UsbOtaOp::AddTarget: {
      if ((size_t)len != kAddTargetTotalBytes) {
        reply.result = UsbOtaResult::BadRequest;
        break;
      }
      const uint8_t* target = &cmd_frame[2];
      std::memcpy(reply.target, target, kPubKeyBytes);
      if (std::all_of(target, target + 32, [](uint8_t b) { return b == 0; }) ||
          (_identity_available_ && !std::memcmp(target, self_id.pub_key, 32))) {
        reply.result = UsbOtaResult::BadRequest; break;
      }
      bool exists = false;
      for (uint8_t i = 0; i < _ota_selected_target_count; ++i) {
        if (std::memcmp(_ota_selected_targets[i], target, kPubKeyBytes) == 0) { exists = true; break; }
      }
      if (!exists) {
        if (_ota_selected_target_count >= kMaxSelectedTargets) reply.result = UsbOtaResult::Busy;
        else {
          std::memcpy(_ota_selected_targets[_ota_selected_target_count++], target, kPubKeyBytes);
          reply.result = UsbOtaResult::Ok;
        }
      } else {
        reply.result = UsbOtaResult::Ok;
      }
      fillLocalSnapshot();
      break;
    }
    case UsbOtaOp::Start: {
      mesh::ota::OtaDirectProfile profile;
      bool retry_attempts;
      if (!parseStartOptions(cmd_frame, len, profile, retry_attempts)) {
        reply.result = UsbOtaResult::BadRequest;
        break;
      }
      const uint8_t mode = cmd_frame[2];
      const uint8_t channel = cmd_frame[3];
      const uint32_t frequency_khz = getBE32(cmd_frame + 4);
      const uint32_t lease_ms = getBE16(&cmd_frame[8]);
      const uint32_t duty_milli_percent = getBE32(&cmd_frame[10]);
      if (mode != kStartModeDirect && mode != kStartModeDirected && mode != kStartModeBackground) {
        reply.result = UsbOtaResult::BadRequest;
        break;
      }
      if ((mode != kStartModeBackground && channel != kStartChannelDirectedOrDirect) ||
          (mode != kStartModeDirect && (frequency_khz != 0 || lease_ms != 0)) ||
          (mode == kStartModeDirect && (frequency_khz < 150000 || frequency_khz > 2500000 ||
            frequency_khz == static_cast<uint32_t>(_prefs.freq * 1000.0f + 0.5f) ||
            lease_ms < kDirectLeaseMsMin || lease_ms > kDirectLeaseMsMax))) {
        reply.result = UsbOtaResult::BadRequest; break;
      }
      if ((mode == kStartModeDirect || mode == kStartModeDirected) && _ota_selected_target_count != 1) {
        reply.result = UsbOtaResult::BadRequest;
        break;
      }
      if (_ota_selected_target_count == 0) {
        reply.result = UsbOtaResult::BadRequest;
        break;
      }
      if (duty_milli_percent > kDutyMilliPercentMax) {
        reply.result = UsbOtaResult::BadRequest;
        break;
      }
      const auto snap = lean.status();
      if (!snap.valid || snap.phase != ::ota::storage::OtaCandidateStore::Phase::Ready) {
        reply.result = UsbOtaResult::NotFound;
        break;
      }
      if (!_identity_available_) {
        reply.result = UsbOtaResult::Unavailable;
        break;
      }
      if (!snap.localCache || std::memcmp(snap.ownerPublicKey, self_id.pub_key, 32)) {
        reply.result = UsbOtaResult::Denied; break;
      }
      if (mode != kStartModeDirect) {
        bool routable = true;
        for (uint8_t i = 0; i < _ota_selected_target_count; ++i) {
          const auto* contact = lookupContactByPubKey(_ota_selected_targets[i], PUB_KEY_SIZE);
          if (!contact || contact->out_path_len == OUT_PATH_UNKNOWN) routable = false;
          else if (!mesh::ota::otaRfPathFits(retry_attempts ? 170 : 183, contact->out_path_len)) {
            reply.result = UsbOtaResult::BadRequest;
            break;
          }
        }
        if (reply.result == UsbOtaResult::BadRequest) break;
        if (!routable) { reply.result = UsbOtaResult::Busy; break; }
      }
      if (mode == kStartModeBackground && channel != 0xFF) {
        ChannelDetails selected;
        if (!getChannel(channel, selected)) { reply.result = UsbOtaResult::BadRequest; break; }
      }
      // Duty is a real caller-configured share, never pinned to the
      // 2% default -- setDutyCyclePercent() enforces/propagates the
      // existing airtime-limiter bounds (0..100%), including a genuine
      // explicit pause at 0%.
      if (!getOtaIntegration().setDutyCyclePercent(duty_milli_percent / 1000.0f)) {
        reply.result = UsbOtaResult::BadRequest;
        break;
      }
      setOtaAirtimeDutyCyclePercent(duty_milli_percent / 1000.0f);
      getOtaIntegration().setMode(static_cast<mesh::ota::FirmwareOtaMode>(mode));
      for (uint8_t i = 0; i < _ota_selected_target_count; ++i) {
        getOtaIntegration().trackOtaTarget(_ota_selected_targets[i]);
      }
      _ota_upload_channel = channel;
      _ota_upload_active = _ota_rf_uploader.start(getOtaIntegration(), mode, &_ota_selected_targets[0][0],
                                                  _ota_selected_target_count, frequency_khz, lease_ms,
                                                  getRNG()->nextInt(1, 0x7FFFFFFF), _ota_cache_reupload, profile, retry_attempts);
      reply.result = _ota_upload_active ? UsbOtaResult::Ok : UsbOtaResult::BadRequest;
      fillLocalSnapshot();
      break;
    }
    case UsbOtaOp::Commit: {
      if ((size_t)len != kCommitTotalBytes) {
        reply.result = UsbOtaResult::BadRequest;
        break;
      }
      const uint8_t* target = &cmd_frame[2];
      std::memcpy(reply.target, target, kPubKeyBytes);
      const bool local_target = _identity_available_ && std::memcmp(target, self_id.pub_key, kPubKeyBytes) == 0;
      if (!local_target) reply.flags |= kReplyFlagRemote;
      if (!_identity_available_) {
        reply.result = UsbOtaResult::Unavailable;
        break;
      }
      if (local_target) {
        reply.result = getOtaIntegration().handleUsbLocalCommit(
            cmd_frame, static_cast<size_t>(len), this, &MyMesh::otaSelfIdSignThunk, _ms->getMillis());
        fillLocalSnapshot();
        break;
      }
      reply = getOtaIntegration().handleUsbRemoteControl(cmd_frame, static_cast<size_t>(len), this, sendRemoteControl);
      if (reply.result == UsbOtaResult::Ok) {
        _ota_stop_upload_when_idle = _ota_rf_uploader.mode() == kStartModeDirect || _ota_selected_target_count == 1;
      }
      break;
    }
    case UsbOtaOp::Abort: {
      if ((size_t)len != kAbortTotalBytes) {
        reply.result = UsbOtaResult::BadRequest;
        break;
      }
      const uint8_t* target = &cmd_frame[2];
      std::memcpy(reply.target, target, kPubKeyBytes);
      const bool zero_target = std::all_of(target, target + kPubKeyBytes, [](uint8_t b) { return b == 0; });
      const bool local_target = zero_target || (_identity_available_ && std::memcmp(target, self_id.pub_key, kPubKeyBytes) == 0);
      if (!local_target) reply.flags |= kReplyFlagRemote;
      if (local_target) {
        reply = getOtaIntegration().handleUsbLocalControl(cmd_frame, static_cast<size_t>(len),
                                                         _identity_available_ ? self_id.pub_key : nullptr);
        if (reply.result == UsbOtaResult::Ok) {
          _ota_rf_uploader.stop(getOtaIntegration()); _ota_upload_active = false;
        }
        break;
      }
      if (!_identity_available_) {
        reply.result = UsbOtaResult::Unavailable;
        break;
      }
      reply = getOtaIntegration().handleUsbRemoteControl(cmd_frame, static_cast<size_t>(len), this, sendRemoteControl);
      if (reply.result == UsbOtaResult::Ok) {
        // Keep the direct profile until the signed ABORT actually leaves
        // the TX queue; restoring at enqueue would strand the receiver.
        _ota_stop_upload_when_idle = _ota_rf_uploader.mode() == kStartModeDirect || _ota_selected_target_count == 1;
      }
      break;
    }
    case UsbOtaOp::Status: {
      if ((size_t)len != kStatusTotalBytes) {
        reply.result = UsbOtaResult::BadRequest;
        break;
      }
      const uint8_t* target = &cmd_frame[2];
      std::memcpy(reply.target, target, kPubKeyBytes);
      const bool zero_target = std::all_of(target, target + kPubKeyBytes, [](uint8_t b) { return b == 0; });
      const bool local_target = zero_target || (_identity_available_ && std::memcmp(target, self_id.pub_key, kPubKeyBytes) == 0);
      if (local_target) {
        reply.result = UsbOtaResult::Ok;
        fillLocalSnapshot();
        break;
      }
      // Remote target: actively solicit a FRESH observation every call
      // -- never answer purely from whatever was last cached, which is
      // exactly the stale-READY-authorizes-COMMIT hazard MAIN flagged.
      // A poll is sent (airtime permitting) before reporting the cache,
      // so a caller that waits for `statusAgeMs` to drop below its own
      // poll-start timestamp can tell a genuinely fresh reply from an
      // old one; "no report ever observed" always stays distinguishable
      // via setNoSnapshot()'s kStatusAgeUnknown sentinel.
      reply.flags |= kReplyFlagRemote;
      if (!_identity_available_) {
        reply.result = UsbOtaResult::Unavailable;
        break;
      }
      getOtaIntegration().trackOtaTarget(target);
      const auto local_snap = lean.status();
      if (local_snap.valid) {
        uint8_t poll_frame[mesh::ota::kOtaCensusPollBytes] = {};
        const size_t poll_len = mesh::ota::encodeOtaCensusPoll(target, local_snap.manifestHash, 0, poll_frame, sizeof(poll_frame));
        if (poll_len != 0) {
          sendOtaControlFrameToTarget(target, poll_frame, poll_len, meshcore::ota::protocol::OtaAirtimeCategory::Control);
        }
      }
      mesh::ota::OtaFirmwareIntegration::TargetObservation obs;
      const bool tracked = getOtaIntegration().targetObservation(target, _ms->getMillis(), obs);
      if (!tracked || !obs.haveReport || !obs.haveBitmap || !local_snap.valid ||
          std::memcmp(obs.manifestHash, local_snap.manifestHash, 32)) {
        reply.result = UsbOtaResult::Ok; // tracked-but-never-observed is a valid, truthful "Unknown" answer, not an error.
        break;
      }
      reply.result = UsbOtaResult::Ok;
      reply.flags |= kReplyFlagSnapshotValid;
      std::memcpy(reply.manifestHash, obs.manifestHash, 32);
      reply.phase = obs.haveLifecycle ? obs.lifecyclePhase :
                      mapPhase(static_cast<::ota::storage::OtaCandidateStore::Phase>(obs.phase));
      reply.durableReceivedBlocks = obs.receivedBlocks;
      reply.totalBlocks = obs.totalBlocks;
      reply.statusAgeMs = obs.ageMs;
      reply.counter = obs.haveLifecycle ? obs.counter : local_snap.counter;
      reply.generation = obs.generation;
      std::memcpy(reply.beginNonce, obs.beginNonce, sizeof(reply.beginNonce));
      reply.wireVersion = obs.wireVersion;
      break;
    }
    default:
      reply.result = UsbOtaResult::Unsupported;
      break;
  }

#else
  (void)cmd_frame;
  (void)len;
  reply.result = UsbOtaResult::Unsupported;
#endif
  uint8_t out[kReplyBytes];
  encodeUsbOtaReply(reply, out);
  _serial->writeFrame(out, kReplyBytes);
}

void MyMesh::replyUf2Reboot(companion_usb_uf2::Reply reply) {
  using Reply = companion_usb_uf2::Reply;
  switch (reply) {
    case Reply::Ok: writeOKFrame(); break;
    case Reply::Unsupported: writeErrFrame(ERR_CODE_UNSUPPORTED_CMD); break;
    case Reply::BadState: writeErrFrame(ERR_CODE_BAD_STATE); break;
    case Reply::IllegalArgument: writeErrFrame(ERR_CODE_ILLEGAL_ARG); break;
    case Reply::FileIo: writeErrFrame(ERR_CODE_FILE_IO_ERROR); break;
  }
}

#if XIAO_OTA_COMPANION_USB_UF2
bool MyMesh::uf2RebootAllowed() {
  if (_serial != &interface_manager || !_serial->isEnabled() || !usb_serial_interface.isEnabled()) {
    return false;
  }
  return companion_usb_uf2::permitted(
      !_store->destructiveWritesDisallowed(), otaBoardTrialHealthWindowActive(),
      otaBoardBootLifecycleVerificationPending(), getOtaIntegration().hasPendingRfWork(),
      getOtaIntegration().readback().phase);
}
#endif

void MyMesh::handleCmdFrame(size_t len) {
#if MESHCORE_LORA_OTA
  if (len >= 2 && cmd_frame[0] == CMD_OTA_CONTROL && cmd_frame[1] >= 0x10 && cmd_frame[1] <= 0x18) {
    handleUsbOtaProtocolOp(cmd_frame[1], cmd_frame, len);
    return;
  }
#endif
  handleOrdinaryCmdFrame(len);
}

void MyMesh::handleOrdinaryCmdFrame(size_t len) {
#if XIAO_OTA_COMPANION_USB_UF2
  auto* uf2_pending = &_uf2_reboot;
  const bool local_usb = _command_from_local_usb;
#else
  companion_usb_uf2::Pending* uf2_pending = nullptr;
  const bool local_usb = false;
#endif
  if (companion_usb_uf2::request(
          cmd_frame, len, uf2_pending, local_usb,
#if XIAO_OTA_COMPANION_USB_UF2
          mesh::ota::OtaFirmwareIntegration::kCommitRebootGraceMs,
          mesh::ota::OtaFirmwareIntegration::kCommitRebootQueueWaitMs,
#else
          0, 0,  // Unsupported profiles reject before consulting either deadline.
#endif
          [this]() {
#if XIAO_OTA_COMPANION_USB_UF2
            return uf2RebootAllowed();
#else
            return false;
#endif
          },
          [this]() { return _ms->getMillis(); },
          [this](companion_usb_uf2::Reply reply) { replyUf2Reboot(reply); })) {
    return;
  }
  if (cmd_frame[0] == CMD_DEVICE_QUERY && len >= 2) { // sent when app establishes connection
    app_target_ver = cmd_frame[1];                    // which version of protocol does app understand

    int i = 0;
    out_frame[i++] = RESP_CODE_DEVICE_INFO;
    out_frame[i++] = FIRMWARE_VER_CODE;
    out_frame[i++] = MAX_CONTACTS / 2;   // v3+
    out_frame[i++] = MAX_GROUP_CHANNELS; // v3+
    memcpy(&out_frame[i], &_prefs.ble_pin, 4);
    i += 4;
    memset(&out_frame[i], 0, 12);
    strcpy((char *)&out_frame[i], FIRMWARE_BUILD_DATE);
    i += 12;
    StrHelper::strzcpy((char *)&out_frame[i], board.getManufacturerName(), 40);
    i += 40;
    StrHelper::strzcpy((char *)&out_frame[i], FIRMWARE_VERSION, 20);
    i += 20;
    out_frame[i++] = _prefs.isRepeatEn() ? 1 : 0;   // v9+
    out_frame[i++] = _prefs.path_hash_mode;  // v10+
    _serial->writeFrame(out_frame, i);
  } else if (cmd_frame[0] == CMD_APP_START &&
             len >= 8) { // sent when app establishes connection, respond with node ID
    //  cmd_frame[1..7]  reserved future
    char *app_name = (char *)&cmd_frame[8];
    cmd_frame[len] = 0; // make app_name null terminated
    MESH_DEBUG_PRINTLN("App %s connected", app_name);

    _iter_started = false; // stop any left-over ContactsIterator
    int i = 0;
    out_frame[i++] = RESP_CODE_SELF_INFO;
    out_frame[i++] = ADV_TYPE_CHAT; // what this node Advert identifies as (maybe node's pronouns too?? :-)
    out_frame[i++] = _prefs.tx_power_dbm;
    out_frame[i++] = MAX_LORA_TX_POWER;
    memcpy(&out_frame[i], self_id.pub_key, PUB_KEY_SIZE);
    i += PUB_KEY_SIZE;

    int32_t lat, lon;
    lat = (sensors.node_lat * 1000000.0);
    lon = (sensors.node_lon * 1000000.0);
    memcpy(&out_frame[i], &lat, 4);
    i += 4;
    memcpy(&out_frame[i], &lon, 4);
    i += 4;
    out_frame[i++] = _prefs.multi_acks; // new v7+
    out_frame[i++] = _prefs.advert_loc_policy;
    out_frame[i++] = (_prefs.telemetry_mode_env << 4) | (_prefs.telemetry_mode_loc << 2) |
                     (_prefs.telemetry_mode_base); // v5+
    out_frame[i++] = _prefs.manual_add_contacts;

    const bool temp_radio_active = _temporary_radio_lease.applied();
    const float active_freq = temp_radio_active ? pending_freq : _prefs.freq;
    const float active_bw = temp_radio_active ? pending_bw : _prefs.bw;
    const uint8_t active_sf = temp_radio_active ? pending_sf : _prefs.sf;
    const uint8_t active_cr = temp_radio_active ? pending_cr : _prefs.cr;
    uint32_t freq = active_freq * 1000;
    memcpy(&out_frame[i], &freq, 4);
    i += 4;
    uint32_t bw = active_bw * 1000;
    memcpy(&out_frame[i], &bw, 4);
    i += 4;
    out_frame[i++] = active_sf;
    out_frame[i++] = active_cr;

    int tlen = strlen(_prefs.node_name); // revisit: UTF_8 ??
    memcpy(&out_frame[i], _prefs.node_name, tlen);
    i += tlen;
    _serial->writeFrame(out_frame, i);
  } else if (cmd_frame[0] == CMD_RUN_CLI_COMMAND && len >= 3) { // V14+
    int i = 1;
    char *text = (char *)&cmd_frame[i];
    int tlen = len - i;
    text[tlen] = 0; // ensure null

    reply_buf[0] = 0;
    if (!handleCommand(text, 0, reply_buf)) {
      strcat(reply_buf, "Unknown command");   // reply_buf may have cmd prefix from 'text'
    }
    out_frame[0] = RESP_CODE_CLI_REPLY;
    int rlen = strlen(reply_buf);
    memcpy(&out_frame[1], reply_buf, rlen);
    _serial->writeFrame(out_frame, 1 + rlen);
  } else if (cmd_frame[0] == CMD_SEND_TXT_MSG && len >= 14) {
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE. sendMessage()/sendCommandData()
      // also derive the per-contact shared secret from self_id, but the
      // shared guard covers dispatch-unavailability regardless.
    } else {
    int i = 1;
    uint8_t txt_type = cmd_frame[i++];
    uint8_t attempt = cmd_frame[i++];
    uint32_t msg_timestamp;
    memcpy(&msg_timestamp, &cmd_frame[i], 4);
    i += 4;
    uint8_t *pub_key_prefix = &cmd_frame[i];
    i += 6;
    ContactInfo *recipient = lookupContactByPubKey(pub_key_prefix, 6);
    if (recipient && (txt_type == TXT_TYPE_PLAIN || txt_type == TXT_TYPE_CLI_DATA || txt_type == TXT_TYPE_CLI_COMMAND)) {
      char *text = (char *)&cmd_frame[i];
      int tlen = len - i;
      uint32_t est_timeout;
      text[tlen] = 0; // ensure null
      int result;
      uint32_t expected_ack;
      if (txt_type == TXT_TYPE_CLI_DATA || txt_type == TXT_TYPE_CLI_COMMAND) {
        msg_timestamp = getRTCClock()->getCurrentTimeUnique(); // Use node's RTC instead of app timestamp to avoid tripping replay protection
        result = sendCommandData(*recipient, msg_timestamp, attempt, txt_type, text, est_timeout);
        expected_ack = 0; // no Ack expected
      } else {
        result = sendMessage(*recipient, msg_timestamp, attempt, text, expected_ack, est_timeout);
      }
      // TODO: add expected ACK to table
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        if (expected_ack) {
          expected_ack_table[next_ack_idx].msg_sent = _ms->getMillis(); // add to circular table
          expected_ack_table[next_ack_idx].ack = expected_ack;
          expected_ack_table[next_ack_idx].contact = recipient;
          next_ack_idx = (next_ack_idx + 1) % EXPECTED_ACK_TABLE_SIZE;
        }

        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &expected_ack, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(recipient == NULL
                        ? ERR_CODE_NOT_FOUND
                        : ERR_CODE_UNSUPPORTED_CMD); // unknown recipient, or unsupported TXT_TYPE_*
    }
    }
  } else if (cmd_frame[0] == CMD_SEND_CHANNEL_TXT_MSG) { // send GroupChannel text msg
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE. sendGroupMessage() does not
      // itself need self_id (channel pre-shared secret only), but the
      // packet it enqueues via sendFlood() would never be drained by
      // Mesh::loop() while dispatch is unavailable -- refuse BEFORE
      // enqueue rather than reply OK for work that can never be sent.
    } else {
    int i = 1;
    uint8_t txt_type = cmd_frame[i++]; // should be TXT_TYPE_PLAIN
    uint8_t channel_idx = cmd_frame[i++];
    uint32_t msg_timestamp;
    memcpy(&msg_timestamp, &cmd_frame[i], 4);
    i += 4;
    const char *text = (char *)&cmd_frame[i];

    if (txt_type != TXT_TYPE_PLAIN) {
      writeErrFrame(ERR_CODE_UNSUPPORTED_CMD);
    } else {
      ChannelDetails channel;
      bool success = getChannel(channel_idx, channel);
      if (success && sendGroupMessage(msg_timestamp, channel.channel, _prefs.node_name, text, len - i)) {
        writeOKFrame();
      } else {
        writeErrFrame(ERR_CODE_NOT_FOUND); // bad channel_idx
      }
    }
    }
  } else if (cmd_frame[0] == CMD_SEND_CHANNEL_DATA) { // send GroupChannel datagram
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE. sendGroupData() does not
      // itself need self_id, but the enqueued packet would never be
      // drained by Mesh::loop() while dispatch is unavailable.
    } else {
    if (len < 4) {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      return;
    }
    int i = 1;
    uint8_t channel_idx = cmd_frame[i++];
    uint8_t path_len = cmd_frame[i++];

    // validate path len, allowing 0xFF for flood
    if (!mesh::Packet::isValidPathLen(path_len) && path_len != OUT_PATH_UNKNOWN) {
      MESH_DEBUG_PRINTLN("CMD_SEND_CHANNEL_DATA invalid path size: %d", path_len);
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      return;
    }

    // parse provided path if not flood
    uint8_t path[MAX_PATH_SIZE];
    if (path_len != OUT_PATH_UNKNOWN) {
      i += mesh::Packet::writePath(path, &cmd_frame[i], path_len);
    }

    uint16_t data_type = ((uint16_t)cmd_frame[i]) | (((uint16_t)cmd_frame[i + 1]) << 8);
    i += 2;
    const uint8_t *payload = &cmd_frame[i];
    int payload_len = (len > (size_t)i) ? (int)(len - i) : 0;

    ChannelDetails channel;
    if (!getChannel(channel_idx, channel)) {
      writeErrFrame(ERR_CODE_NOT_FOUND); // bad channel_idx
    } else if (data_type == DATA_TYPE_RESERVED) {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    } else if (payload_len > MAX_GROUP_DATA_LENGTH) {
      MESH_DEBUG_PRINTLN("CMD_SEND_CHANNEL_DATA payload too long: %d > %d", payload_len, MAX_GROUP_DATA_LENGTH);
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    } else if (sendGroupData(channel.channel, path, path_len, data_type, payload, payload_len)) {
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_TABLE_FULL);
    }
    }
  } else if (cmd_frame[0] == CMD_GET_CONTACTS) { // get Contact list
    if (_iter_started) {
      writeErrFrame(ERR_CODE_BAD_STATE); // iterator is currently busy
    } else {
      if (len >= 5) { // has optional 'since' param
        memcpy(&_iter_filter_since, &cmd_frame[1], 4);
      } else {
        _iter_filter_since = 0;
      }

      uint8_t reply[5];
      reply[0] = RESP_CODE_CONTACTS_START;
      uint32_t count = getNumContacts(); // total, NOT filtered count
      memcpy(&reply[1], &count, 4);
      _serial->writeFrame(reply, 5);

      // start iterator
      _iter = startContactsIterator();
      _iter_started = true;
      _most_recent_lastmod = 0;
    }
  } else if (cmd_frame[0] == CMD_SET_ADVERT_NAME && len >= 2) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate _prefs.node_name.
    } else {
    int nlen = len - 1;
    if (nlen > sizeof(_prefs.node_name) - 1) nlen = sizeof(_prefs.node_name) - 1; // max len
    memcpy(_prefs.node_name, &cmd_frame[1], nlen);
    _prefs.node_name[nlen] = 0; // null terminator
    savePrefs();
    writeOKFrame();
    }
  } else if (cmd_frame[0] == CMD_SET_ADVERT_LATLON && len >= 9) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate sensors.node_lat/lon.
    } else {
    int32_t lat, lon, alt = 0;
    memcpy(&lat, &cmd_frame[1], 4);
    memcpy(&lon, &cmd_frame[5], 4);
    if (len >= 13) {
      memcpy(&alt, &cmd_frame[9], 4); // for FUTURE support
    }
    if (lat <= 90 * 1E6 && lat >= -90 * 1E6 && lon <= 180 * 1E6 && lon >= -180 * 1E6) {
      sensors.node_lat = ((double)lat) / 1000000.0;
      sensors.node_lon = ((double)lon) / 1000000.0;
      savePrefs();
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG); // invalid geo coordinate
    }
    }
  } else if (cmd_frame[0] == CMD_GET_DEVICE_TIME) {
    uint8_t reply[5];
    reply[0] = RESP_CODE_CURR_TIME;
    uint32_t now = getRTCClock()->getCurrentTime();
    memcpy(&reply[1], &now, 4);
    _serial->writeFrame(reply, 5);
  } else if (cmd_frame[0] == CMD_SET_DEVICE_TIME && len >= 5) {
    uint32_t secs;
    memcpy(&secs, &cmd_frame[1], 4);
    uint32_t curr = getRTCClock()->getCurrentTime();
    if (secs >= curr) {
      getRTCClock()->setCurrentTime(secs);
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    }
  } else if (cmd_frame[0] == CMD_SEND_SELF_ADVERT) {
    if (!_identity_available_) {
      // No real identity was established this boot (trial/unknown, see
      // begin()) -- signing and sending an advert from the default/unset
      // self_id would broadcast a bogus identity as if it were genuine.
      writeErrFrame(ERR_CODE_BAD_STATE);
    } else {
    mesh::Packet* pkt;
    if (_prefs.advert_loc_policy == ADVERT_LOC_NONE) {
      pkt = createSelfAdvert(_prefs.node_name);
    } else {
      pkt = createSelfAdvert(_prefs.node_name, sensors.node_lat, sensors.node_lon);
    }
    if (pkt) {
      if (len >= 2 && cmd_frame[1] == 1) { // optional param (1 = flood, 0 = zero hop)
        unsigned long delay_millis = 0;
        TransportKey default_scope;
        memcpy(&default_scope.key, _prefs.default_scope_key, sizeof(default_scope.key));
        sendFloodScoped(default_scope, pkt, delay_millis);
      } else {
        sendZeroHop(pkt);
      }
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_TABLE_FULL);
    }
    }
  } else if (cmd_frame[0] == CMD_RESET_PATH && len >= 1 + 32) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate the contact table.
    } else {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient) {
      recipient->out_path_len = OUT_PATH_UNKNOWN;
      // recipient->lastmod = ??   shouldn't be needed, app already has this version of contact
      dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // unknown contact
    }
    }
  } else if (cmd_frame[0] == CMD_ADD_UPDATE_CONTACT && len >= 1 + 32 + 2 + 1) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate the contact table.
    } else {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    uint32_t last_mod = getRTCClock()->getCurrentTime();  // fallback value if not present in cmd_frame
    if (recipient) {
      updateContactFromFrame(*recipient, last_mod, cmd_frame, len);
      recipient->lastmod = last_mod;
      dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
      writeOKFrame();
    } else {
      ContactInfo contact;
      updateContactFromFrame(contact, last_mod, cmd_frame, len);
      contact.lastmod = last_mod;
      contact.sync_since = 0;
      if (addContact(contact)) {
        dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
        writeOKFrame();
      } else {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      }
    }
    }
  } else if (cmd_frame[0] == CMD_REMOVE_CONTACT) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate the contact table.
    } else {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient && removeContact(*recipient)) {
      _store->deleteBlobByKey(pub_key, PUB_KEY_SIZE);
      dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // not found, or unable to remove
    }
    }
  } else if (cmd_frame[0] == CMD_SHARE_CONTACT) {
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE. shareContactZeroHop() does not
      // need self_id, but it enqueues via sendZeroHop() -> sendPacket(),
      // which Mesh::loop() would never drain while dispatch is unavailable.
    } else {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient) {
      if (shareContactZeroHop(*recipient)) {
        writeOKFrame();
      } else {
        writeErrFrame(ERR_CODE_TABLE_FULL); // unable to send
      }
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND);
    }
    }
  } else if (cmd_frame[0] == CMD_GET_CONTACT_BY_KEY) {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *contact = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (contact) {
      writeContactRespFrame(RESP_CODE_CONTACT, *contact);
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // not found
    }
  } else if (cmd_frame[0] == CMD_EXPORT_CONTACT) {
    if (len < 1 + PUB_KEY_SIZE) {
      // export SELF
      if (!_identity_available_) {
        // No real identity this boot -- exporting/signing a card for the
        // default/unset self_id would hand the caller a bogus identity.
        writeErrFrame(ERR_CODE_BAD_STATE);
      } else {
      mesh::Packet* pkt;
      if (_prefs.advert_loc_policy == ADVERT_LOC_NONE) {
        pkt = createSelfAdvert(_prefs.node_name);
      } else {
        pkt = createSelfAdvert(_prefs.node_name, sensors.node_lat, sensors.node_lon);
      }
      if (pkt) {
        pkt->header |= ROUTE_TYPE_FLOOD; // would normally be sent in this mode

        out_frame[0] = RESP_CODE_EXPORT_CONTACT;
        uint8_t out_len = pkt->writeTo(&out_frame[1]);
        releasePacket(pkt); // undo the obtainNewPacket()
        _serial->writeFrame(out_frame, out_len + 1);
      } else {
        writeErrFrame(ERR_CODE_TABLE_FULL); // Error
      }
      }
    } else {
      uint8_t *pub_key = &cmd_frame[1];
      ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
      uint8_t out_len;
      if (recipient && (out_len = exportContact(*recipient, &out_frame[1])) > 0) {
        out_frame[0] = RESP_CODE_EXPORT_CONTACT;
        _serial->writeFrame(out_frame, out_len + 1);
      } else {
        writeErrFrame(ERR_CODE_NOT_FOUND); // not found
      }
    }
  } else if (cmd_frame[0] == CMD_IMPORT_CONTACT && len > 2 + 32 + 64) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate the contact table.
    } else if (importContact(&cmd_frame[1], len - 1)) {
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    }
  } else if (cmd_frame[0] == CMD_SYNC_NEXT_MESSAGE) {
    int out_len;
    if ((out_len = getFromOfflineQueue(out_frame)) > 0) {
      _serial->writeFrame(out_frame, out_len);
      if (_listener) _listener->onQueueSizeChanged(offline_queue_len);
    } else {
      out_frame[0] = RESP_CODE_NO_MORE_MESSAGES;
      _serial->writeFrame(out_frame, 1);
    }
  } else if (cmd_frame[0] == CMD_SET_RADIO_PARAMS) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate _prefs/radio params.
    } else {
    int i = 1;
    uint32_t freq;
    memcpy(&freq, &cmd_frame[i], 4);
    i += 4;
    uint32_t bw;
    memcpy(&bw, &cmd_frame[i], 4);
    i += 4;
    uint8_t sf = cmd_frame[i++];
    uint8_t cr = cmd_frame[i++];
    uint8_t repeat = 0;  // default - false
    if (len > i) {
      repeat = cmd_frame[i++];   // FIRMWARE_VER_CODE  9+
    }

    if (repeat && !isValidClientRepeatFreq(freq)) {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    } else if (freq >= 150000 && freq <= 2500000 && sf >= 5 && sf <= 12 && cr >= 5 && cr <= 8 && bw >= 7000 &&
        bw <= 500000) {
      _prefs.sf = sf;
      _prefs.cr = cr;
      _prefs.freq = (float)freq / 1000.0;
      _prefs.bw = (float)bw / 1000.0;
      _prefs.setRepeatEn(repeat != 0);
      savePrefs();

      applyRadioParams(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
      MESH_DEBUG_PRINTLN("OK: CMD_SET_RADIO_PARAMS: f=%d, bw=%d, sf=%d, cr=%d", freq, bw, (uint32_t)sf,
                         (uint32_t)cr);

      writeOKFrame();
    } else {
      MESH_DEBUG_PRINTLN("Error: CMD_SET_RADIO_PARAMS: f=%d, bw=%d, sf=%d, cr=%d", freq, bw, (uint32_t)sf,
                         (uint32_t)cr);
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    }
    }
  } else if (cmd_frame[0] == CMD_SET_RADIO_TX_POWER) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate _prefs.tx_power_dbm.
    } else {
    int8_t power = (int8_t)cmd_frame[1];
    if (power < -9 || power > MAX_LORA_TX_POWER) {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    } else {
      _prefs.tx_power_dbm = power;
      savePrefs();
      radio_driver.setTxPower(_prefs.tx_power_dbm);
      writeOKFrame();
    }
    }
  } else if (cmd_frame[0] == CMD_SET_TUNING_PARAMS) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate _prefs tuning params.
    } else {
    int i = 1;
    uint32_t rx, af;
    memcpy(&rx, &cmd_frame[i], 4);
    i += 4;
    memcpy(&af, &cmd_frame[i], 4);
    i += 4;
    _prefs.rx_delay_base = ((float)rx) / 1000.0f;
    _prefs.airtime_factor = ((float)af) / 1000.0f;
    savePrefs();
    writeOKFrame();
    }
  } else if (cmd_frame[0] == CMD_GET_TUNING_PARAMS) {
    uint32_t rx = _prefs.rx_delay_base * 1000, af = _prefs.airtime_factor * 1000;
    int i = 0;
    out_frame[i++] = RESP_CODE_TUNING_PARAMS;
    memcpy(&out_frame[i], &rx, 4); i += 4;
    memcpy(&out_frame[i], &af, 4); i += 4;
    _serial->writeFrame(out_frame, i);
  } else if (cmd_frame[0] == CMD_SET_OTHER_PARAMS) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate _prefs other params.
    } else {
    _prefs.manual_add_contacts = cmd_frame[1];
    if (len >= 3) {
      _prefs.telemetry_mode_base = cmd_frame[2] & 0x03; // v5+
      _prefs.telemetry_mode_loc = (cmd_frame[2] >> 2) & 0x03;
      _prefs.telemetry_mode_env = (cmd_frame[2] >> 4) & 0x03;

      if (len >= 4) {
        _prefs.advert_loc_policy = cmd_frame[3];
        if (len >= 5) {
          _prefs.multi_acks = cmd_frame[4];
        }
      }
    }
    savePrefs();
    writeOKFrame();
    }
  } else if (cmd_frame[0] == CMD_SET_PATH_HASH_MODE && cmd_frame[1] == 0 && len >= 3) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate _prefs.path_hash_mode.
    } else if (cmd_frame[2] >= 3) {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    } else {
      _prefs.path_hash_mode = cmd_frame[2];
      savePrefs();
      writeOKFrame();
    }
  } else if (cmd_frame[0] == CMD_REBOOT && memcmp(&cmd_frame[1], "reboot", 6) == 0) {
    // Read-only trial/unknown: skip the pending lazy contacts write (no
    // IO fault, no fake-persisted claim) rather than attempting a
    // disallowed save right before rebooting; permitted boots keep the
    // existing real-IO-fault behavior of saveContacts() unchanged.
    companion_usb_uf2::ordinaryReboot(
        dirty_contacts_expiry != 0, !_store->destructiveWritesDisallowed(),
        [this]() { saveContacts(); }, []() { board.reboot(); });
  } else if (cmd_frame[0] == CMD_GET_BATT_AND_STORAGE) {
    uint8_t reply[11];
    int i = 0;
    reply[i++] = RESP_CODE_BATT_AND_STORAGE;
    uint16_t battery_millivolts = board.getBattMilliVolts();
    uint32_t used = _store->getStorageUsedKb();
    uint32_t total = _store->getStorageTotalKb();
    memcpy(&reply[i], &battery_millivolts, 2); i += 2;
    memcpy(&reply[i], &used, 4); i += 4;
    memcpy(&reply[i], &total, 4); i += 4;
    _serial->writeFrame(reply, i);
  } else if (cmd_frame[0] == CMD_EXPORT_PRIVATE_KEY) {
#if ENABLE_PRIVATE_KEY_EXPORT
    if (!_identity_available_) {
      // No real identity this boot -- self_id is default/unset; exporting
      // it would hand the caller a bogus, non-recoverable key.
      writeErrFrame(ERR_CODE_BAD_STATE);
    } else {
    uint8_t reply[65];
    reply[0] = RESP_CODE_PRIVATE_KEY;
    self_id.writeTo(&reply[1], 64);
    _serial->writeFrame(reply, 65);
    }
#else
    writeDisabledFrame();
#endif
  } else if (cmd_frame[0] == CMD_IMPORT_PRIVATE_KEY && len >= 65) {
#if ENABLE_PRIVATE_KEY_IMPORT
    if (!_identity_available_ || _store->destructiveWritesDisallowed()) {
      // Importing/replacing the identity in RAM during a trial/unknown
      // boot is exactly the temporary-identity substitution the trial's
      // read-only contract forbids -- reject BEFORE touching self_id or
      // `identity` at all. `_identity_available_` alone is insufficient:
      // it only reflects whether THIS device's own identity failed to
      // load, not the broader "destructive writes are disallowed this
      // boot" policy (e.g. a qualified-but-no-install-history board can
      // load its existing identity fine yet still be Unknown/read-only).
      writeErrFrame(ERR_CODE_BAD_STATE);
    } else if (!mesh::LocalIdentity::validatePrivateKey(&cmd_frame[1])) {
        writeErrFrame(ERR_CODE_ILLEGAL_ARG); // invalid key
    } else {
        mesh::LocalIdentity identity;
        identity.readFrom(&cmd_frame[1], 64);
        if (_store->saveMainIdentity(identity)) {
          self_id = identity;
          writeOKFrame();
#if MESHCORE_LORA_OTA
          // A real, durable identity write just succeeded -- the exact
          // same category of evidence as begin()'s GeneratedAndSaved
          // outcome, so this is genuine "confirmed loaded" evidence too
          // (not merely leaving the previous, possibly now-stale,
          // boot-time answer in place).
          _ota_service_.noteIdentityPersisted();
#endif
          // re-load contacts, to invalidate ecdh shared_secrets
          resetContacts();
          {
            const bool reload_ok = _store->loadContacts(this);
#if MESHCORE_LORA_OTA
            if (!reload_ok) _ota_service_.noteStorageIoResult(false);
#else
            (void)reload_ok;
#endif
          }
        } else {
          // Already excluded the policy-refusal case above (rejected
          // with BAD_STATE before reaching here), so a `false` here is
          // always a genuine I/O fault.
          writeErrFrame(ERR_CODE_FILE_IO_ERROR);
#if MESHCORE_LORA_OTA
          // Real, already-performed ordinary filesystem write genuinely
          // failed -- same latch as savePrefs(); see tickOtaTrialHealth().
          _ota_service_.noteStorageIoResult(false);
#endif
        }
    }
#else
    writeDisabledFrame();
#endif
  } else if (cmd_frame[0] == CMD_SEND_RAW_DATA && len >= 6) {
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE. createRawData()/sendDirect()
      // need no self_id, but the enqueued packet would never be drained
      // by Mesh::loop() while dispatch is unavailable.
    } else {
    int i = 1;
    uint8_t path_len = cmd_frame[i++];
    if (path_len >= 0 && mesh::Packet::isValidPathLen(path_len)) {
      uint8_t path[MAX_PATH_SIZE];
      i += mesh::Packet::writePath(path, &cmd_frame[i], path_len);
      if (i + 4 > len) {  // min payload 4 bytes
        writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      } else {
        auto pkt = createRawData(&cmd_frame[i], len - i);
        if (pkt) {
          sendDirect(pkt, path, path_len);
          writeOKFrame();
        } else {
          writeErrFrame(ERR_CODE_TABLE_FULL);
        }
      }
    } else {
      writeErrFrame(ERR_CODE_UNSUPPORTED_CMD); // flood, not supported (yet)
    }
    }
  } else if (cmd_frame[0] == CMD_SEND_LOGIN && len >= 1 + PUB_KEY_SIZE) {
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE; sendLogin() also derives the
      // shared secret from self_id.
    } else {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    char *password = (char *)&cmd_frame[1 + PUB_KEY_SIZE];
    cmd_frame[len] = 0; // ensure null terminator in password
    if (recipient) {
      uint32_t est_timeout;
      int result = sendLogin(*recipient, password, est_timeout);
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        clearPendingReqs();
        memcpy(&pending_login, recipient->id.pub_key, 4); // match this to onContactResponse()
        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &pending_login, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // contact not found
    }
    }
  } else if (cmd_frame[0] == CMD_SEND_ANON_REQ && len > 1 + PUB_KEY_SIZE) {
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE; sendAnonReq() also derives
      // the shared secret from self_id.
    } else {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    ContactInfo anon;
    if (recipient == NULL) { // FIRMWARE_VER_CODE 13+,  allow non-contact requests
      memset(&anon, 0, sizeof(anon));
      memcpy(anon.id.pub_key, pub_key, PUB_KEY_SIZE);
      anon.out_path_len = 0;   // default to zero-hop direct
      anon.type = ADV_TYPE_NONE;  // unknown
      anon.lastmod = getRTCClock()->getCurrentTime();

      if (addContact(anon)) recipient = &anon;
    }
    uint8_t *data = &cmd_frame[1 + PUB_KEY_SIZE];
    if (recipient) {
      uint32_t tag, est_timeout;
      int result = sendAnonReq(*recipient, data, len - (1 + PUB_KEY_SIZE), tag, est_timeout);
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        clearPendingReqs();
        pending_req = tag; // match this to onContactResponse()
        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &tag, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(ERR_CODE_TABLE_FULL); // contacts full
    }
    }
  } else if (cmd_frame[0] == CMD_SEND_STATUS_REQ && len >= 1 + PUB_KEY_SIZE) {
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE; sendRequest() also derives
      // the shared secret from self_id.
    } else {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient) {
      uint32_t tag, est_timeout;
      int result = sendRequest(*recipient, REQ_TYPE_GET_STATUS, tag, est_timeout);
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        clearPendingReqs();
        // FUTURE:  pending_status = tag;  // match this in onContactResponse()
        memcpy(&pending_status, recipient->id.pub_key, 4); // legacy matching scheme
        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &tag, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // contact not found
    }
    }
  } else if (cmd_frame[0] == CMD_SEND_PATH_DISCOVERY_REQ && cmd_frame[1] == 0 && len >= 2 + PUB_KEY_SIZE) {
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE; sendRequest() also derives
      // the shared secret from self_id.
    } else {
    uint8_t *pub_key = &cmd_frame[2];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient) {
      uint32_t tag, est_timeout;
      // 'Path Discovery' is just a special case of flood + Telemetry req
      uint8_t req_data[9];
      req_data[0] = REQ_TYPE_GET_TELEMETRY_DATA;
      req_data[1] = ~(TELEM_PERM_BASE);  // NEW: inverse permissions mask (ie. we only want BASE telemetry)
      memset(&req_data[2], 0, 3);  // reserved
      getRNG()->random(&req_data[5], 4);   // random blob to help make packet-hash unique
      auto save = recipient->out_path_len;    // temporarily force sendRequest() to flood
      recipient->out_path_len = OUT_PATH_UNKNOWN;
      int result = sendRequest(*recipient, req_data, sizeof(req_data), tag, est_timeout);
      recipient->out_path_len = save;
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        clearPendingReqs();
        pending_discovery = tag; // match this in onContactResponse()
        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &tag, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // contact not found
    }
    }
  } else if (cmd_frame[0] == CMD_SEND_TELEMETRY_REQ && len >= 4 + PUB_KEY_SIZE) {  // can deprecate, in favour of CMD_SEND_BINARY_REQ
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE; sendRequest() also derives
      // the shared secret from self_id.
    } else {
    uint8_t *pub_key = &cmd_frame[4];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient) {
      uint32_t tag, est_timeout;
      int result = sendRequest(*recipient, REQ_TYPE_GET_TELEMETRY_DATA, tag, est_timeout);
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        clearPendingReqs();
        pending_telemetry = tag; // match this in onContactResponse()
        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &tag, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // contact not found
    }
    }
  } else if (cmd_frame[0] == CMD_SEND_TELEMETRY_REQ && len == 4) {  // 'self' telemetry request
    telemetry.reset();
    telemetry.addVoltage(TELEM_CHANNEL_SELF, (float)board.getBattMilliVolts() / 1000.0f);
    float temperature = board.getMCUTemperature();
    if(!isnan(temperature)) { // Supported boards with built-in temperature sensor. ESP32-C3 may return NAN
      telemetry.addTemperature(TELEM_CHANNEL_SELF, temperature); // Built-in MCU Temperature
    }

    // query other sensors -- target specific
    sensors.querySensors(0xFF, telemetry);

    int i = 0;
    out_frame[i++] = PUSH_CODE_TELEMETRY_RESPONSE;
    out_frame[i++] = 0; // reserved
    memcpy(&out_frame[i], self_id.pub_key, 6);
    i += 6; // pub_key_prefix
    uint8_t tlen = telemetry.getSize();
    memcpy(&out_frame[i], telemetry.getBuffer(), tlen);
    i += tlen;
    _serial->writeFrame(out_frame, i);
  } else if (cmd_frame[0] == CMD_SEND_BINARY_REQ && len >= 2 + PUB_KEY_SIZE) {
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE; sendRequest() also derives
      // the shared secret from self_id.
    } else {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient) {
      uint8_t *req_data = &cmd_frame[1 + PUB_KEY_SIZE];
      uint32_t tag, est_timeout;
      int result = sendRequest(*recipient, req_data, len - (1 + PUB_KEY_SIZE), tag, est_timeout);
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        clearPendingReqs();
        pending_req = tag; // match this in onContactResponse()
        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &tag, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // contact not found
    }
    }
  } else if (cmd_frame[0] == CMD_HAS_CONNECTION && len >= 1 + PUB_KEY_SIZE) {
    uint8_t *pub_key = &cmd_frame[1];
    if (hasConnectionTo(pub_key)) {
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND);
    }
  } else if (cmd_frame[0] == CMD_LOGOUT && len >= 1 + PUB_KEY_SIZE) {
    uint8_t *pub_key = &cmd_frame[1];
    stopConnection(pub_key);
    writeOKFrame();
  } else if (cmd_frame[0] == CMD_GET_CHANNEL && len >= 2) {
    uint8_t channel_idx = cmd_frame[1];
    ChannelDetails channel;
    if (getChannel(channel_idx, channel)) {
      int i = 0;
      out_frame[i++] = RESP_CODE_CHANNEL_INFO;
      out_frame[i++] = channel_idx;
      strcpy((char *)&out_frame[i], channel.name);
      i += 32;
      memcpy(&out_frame[i], channel.channel.secret, 16);
      i += 16; // NOTE: only 128-bit supported
      _serial->writeFrame(out_frame, i);
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND);
    }
  } else if (cmd_frame[0] == CMD_SET_CHANNEL && len >= 2 + 32 + 32) {
    writeErrFrame(ERR_CODE_UNSUPPORTED_CMD); // not supported (yet)
  } else if (cmd_frame[0] == CMD_SET_CHANNEL && len >= 2 + 32 + 16) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate the channel table.
    } else {
    uint8_t channel_idx = cmd_frame[1];
    ChannelDetails channel;
    StrHelper::strncpy(channel.name, (char *)&cmd_frame[2], 32);
    memset(channel.channel.secret, 0, sizeof(channel.channel.secret));
    memcpy(channel.channel.secret, &cmd_frame[2 + 32], 16); // NOTE: only 128-bit supported
    if (setChannel(channel_idx, channel)) {
      saveChannels();
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // bad channel_idx
    }
    }
  } else if (cmd_frame[0] == CMD_SIGN_START) {
    out_frame[0] = RESP_CODE_SIGN_START;
    out_frame[1] = 0; // reserved
    uint32_t len = MAX_SIGN_DATA_LEN;
    memcpy(&out_frame[2], &len, 4);
    _serial->writeFrame(out_frame, 6);

    if (sign_data) {
      free(sign_data);
    }
    sign_data = (uint8_t *)malloc(MAX_SIGN_DATA_LEN);
    sign_data_len = 0;
  } else if (cmd_frame[0] == CMD_SIGN_DATA && len > 1) {
    if (sign_data == NULL || sign_data_len + (len - 1) > MAX_SIGN_DATA_LEN) {
      writeErrFrame(sign_data == NULL ? ERR_CODE_BAD_STATE : ERR_CODE_TABLE_FULL); // error: too long
    } else {
      memcpy(&sign_data[sign_data_len], &cmd_frame[1], len - 1);
      sign_data_len += (len - 1);
      writeOKFrame();
    }
  } else if (cmd_frame[0] == CMD_SIGN_FINISH) {
    if (!_identity_available_) {
      // No real identity this boot -- signing with the default/unset
      // self_id would return a meaningless signature as if genuine.
      if (sign_data) { free(sign_data); sign_data = NULL; }
      writeErrFrame(ERR_CODE_BAD_STATE);
    } else if (sign_data) {
      self_id.sign(&out_frame[1], sign_data, sign_data_len);

      free(sign_data); // don't need sign_data now
      sign_data = NULL;

      out_frame[0] = RESP_CODE_SIGNATURE;
      _serial->writeFrame(out_frame, 1 + SIGNATURE_SIZE);
    } else {
      writeErrFrame(ERR_CODE_BAD_STATE);
    }
  } else if (cmd_frame[0] == CMD_SEND_TRACE_PATH && len > 10 && len - 10 < MAX_PACKET_PAYLOAD-5) {
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE. createTrace()/sendDirect()
      // need no self_id, but the enqueued packet would never be drained
      // by Mesh::loop() while dispatch is unavailable.
    } else {
    uint8_t path_len = len - 10;
    uint8_t flags = cmd_frame[9];
    uint8_t path_sz = flags & 0x03;  // NEW v1.11+
    if ((path_len >> path_sz) > MAX_PATH_SIZE || (path_len % (1 << path_sz)) != 0) { // make sure is multiple of path_sz
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    } else {
      uint32_t tag, auth;
      memcpy(&tag, &cmd_frame[1], 4);
      memcpy(&auth, &cmd_frame[5], 4);
      auto pkt = createTrace(tag, auth, flags);
      if (pkt) {
        sendDirect(pkt, &cmd_frame[10], path_len);

        uint32_t t = _radio->getEstAirtimeFor(pkt->payload_len + pkt->path_len + 2);
        uint32_t est_timeout = calcDirectTimeoutMillisFor(t, path_len >> path_sz);

        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = 0;
        memcpy(&out_frame[2], &tag, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      } else {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      }
    }
    }
  } else if (cmd_frame[0] == CMD_SET_DEVICE_PIN && len >= 5) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate _prefs.ble_pin.
    } else {

    // get pin from command frame
    uint32_t pin;
    memcpy(&pin, &cmd_frame[1], 4);

    // ensure pin is zero, or a valid 6 digit pin
    if (pin == 0 || (pin >= 100000 && pin <= 999999)) {
      _prefs.ble_pin = pin;
      savePrefs();
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    }
    }
  } else if (cmd_frame[0] == CMD_GET_CUSTOM_VARS) {
    out_frame[0] = RESP_CODE_CUSTOM_VARS;
    char *dp = (char *)&out_frame[1];
    for (int i = 0; i < sensors.getNumSettings() && dp - (char *)&out_frame[1] < 140; i++) {
      if (i > 0) {
        *dp++ = ',';
      }
      strcpy(dp, sensors.getSettingName(i));
      dp = strchr(dp, 0);
      *dp++ = ':';
      strcpy(dp, sensors.getSettingValue(i));
      dp = strchr(dp, 0);
    }
    _serial->writeFrame(out_frame, dp - (char *)out_frame);
  } else if (cmd_frame[0] == CMD_SET_CUSTOM_VAR && len >= 4) {
    cmd_frame[len] = 0;
    char *sp = (char *)&cmd_frame[1];
    char *np = strchr(sp, ':'); // look for separator char
    if (np) {
      *np++ = 0; // modify 'cmd_frame', replace ':' with null
      bool success = sensors.setSettingValue(sp, np);
      bool persist_refused = false;
      if (success) {
        #if ENV_INCLUDE_GPS == 1
        // Update node preferences for GPS settings
        if (strcmp(sp, "gps") == 0) {
          if (refusePersistIfDisallowed()) {
            // already replied ERR_CODE_BAD_STATE; do not mutate _prefs.gps_enabled.
            persist_refused = true;
          } else {
            _prefs.gps_enabled = (np[0] == '1') ? 1 : 0;
            savePrefs();
          }
        } else if (strcmp(sp, "gps_interval") == 0) {
          if (refusePersistIfDisallowed()) {
            // already replied ERR_CODE_BAD_STATE; do not mutate _prefs.gps_interval.
            persist_refused = true;
          } else {
            uint32_t interval_seconds = atoi(np);
            _prefs.gps_interval = constrain(interval_seconds, 0, 86400);
            savePrefs();
          }
        }
        #endif
        if (!persist_refused) {
          writeOKFrame();
        }
      } else {
        writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      }
    } else {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    }
  } else if (cmd_frame[0] == CMD_GET_ADVERT_PATH && len >= PUB_KEY_SIZE+2) {
    // FUTURE use:  uint8_t reserved = cmd_frame[1];
    uint8_t *pub_key = &cmd_frame[2];
    AdvertPath* found = NULL;
    for (int i = 0; i < ADVERT_PATH_TABLE_SIZE; i++) {
      auto p = &advert_paths[i];
      if (memcmp(p->pubkey_prefix, pub_key, sizeof(p->pubkey_prefix)) == 0) {
        found = p;
        break;
      }
    }
    if (found) {
      int i = 0;
      out_frame[i++] = RESP_CODE_ADVERT_PATH;
      memcpy(&out_frame[i], &found->recv_timestamp, 4); i += 4;
      out_frame[i++] = found->path_len;
      i += mesh::Packet::writePath(&out_frame[i], found->path, found->path_len);
      _serial->writeFrame(out_frame, i);
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND);
    }
  } else if (cmd_frame[0] == CMD_GET_STATS && len >= 2) {
    uint8_t stats_type = cmd_frame[1];
    if (stats_type == STATS_TYPE_CORE) {
      int i = 0;
      out_frame[i++] = RESP_CODE_STATS;
      out_frame[i++] = STATS_TYPE_CORE;
      uint16_t battery_mv = board.getBattMilliVolts();
      uint32_t uptime_secs = _ms->getMillis() / 1000;
      uint8_t queue_len = (uint8_t)_mgr->getOutboundTotal();
      memcpy(&out_frame[i], &battery_mv, 2); i += 2;
      memcpy(&out_frame[i], &uptime_secs, 4); i += 4;
      memcpy(&out_frame[i], &_err_flags, 2); i += 2;
      out_frame[i++] = queue_len;
      _serial->writeFrame(out_frame, i);
    } else if (stats_type == STATS_TYPE_RADIO) {
      int i = 0;
      out_frame[i++] = RESP_CODE_STATS;
      out_frame[i++] = STATS_TYPE_RADIO;
      int16_t noise_floor = (int16_t)_radio->getNoiseFloor();
      int8_t last_rssi = (int8_t)radio_driver.getLastRSSI();
      int8_t last_snr = (int8_t)(radio_driver.getLastSNR() * 4); // scaled by 4 for 0.25 dB precision
      uint32_t tx_air_secs = getTotalAirTime() / 1000;
      uint32_t rx_air_secs = getReceiveAirTime() / 1000;
      memcpy(&out_frame[i], &noise_floor, 2); i += 2;
      out_frame[i++] = last_rssi;
      out_frame[i++] = last_snr;
      memcpy(&out_frame[i], &tx_air_secs, 4); i += 4;
      memcpy(&out_frame[i], &rx_air_secs, 4); i += 4;
      _serial->writeFrame(out_frame, i);
    } else if (stats_type == STATS_TYPE_PACKETS) {
      int i = 0;
      out_frame[i++] = RESP_CODE_STATS;
      out_frame[i++] = STATS_TYPE_PACKETS;
      uint32_t recv = radio_driver.getPacketsRecv();
      uint32_t sent = radio_driver.getPacketsSent();
      uint32_t n_sent_flood = getNumSentFlood();
      uint32_t n_sent_direct = getNumSentDirect();
      uint32_t n_recv_flood = getNumRecvFlood();
      uint32_t n_recv_direct = getNumRecvDirect();
      uint32_t n_recv_errors = radio_driver.getPacketsRecvErrors();
      memcpy(&out_frame[i], &recv, 4); i += 4;
      memcpy(&out_frame[i], &sent, 4); i += 4;
      memcpy(&out_frame[i], &n_sent_flood, 4); i += 4;
      memcpy(&out_frame[i], &n_sent_direct, 4); i += 4;
      memcpy(&out_frame[i], &n_recv_flood, 4); i += 4;
      memcpy(&out_frame[i], &n_recv_direct, 4); i += 4;
      memcpy(&out_frame[i], &n_recv_errors, 4); i += 4;
      _serial->writeFrame(out_frame, i);
    } else {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG); // invalid stats sub-type
    }
  } else if (cmd_frame[0] == CMD_FACTORY_RESET && memcmp(&cmd_frame[1], "reset", 5) == 0) {
    if (_store->formatDisallowed()) {
      // No explicit, separately-verified format authority for this boot
      // -- refuse BEFORE disabling serial, so the reply is actually
      // reachable (a disabled serial link cannot be un-disabled without
      // a genuine reboot, which we must not trigger for a denied reset).
      writeErrFrame(ERR_CODE_BAD_STATE);
    } else {
    if (_serial) {
      MESH_DEBUG_PRINTLN("Factory reset: disabling serial interface to prevent reconnects (BLE/WiFi)");
      _serial->disable(); // Phone app disconnects before we can send OK frame so it's safe here
    }
    bool success = _store->formatFileSystem();
    if (success) {
      writeOKFrame();
      delay(1000);
      board.reboot();  // doesn't return
    } else {
      writeErrFrame(ERR_CODE_FILE_IO_ERROR);
    }
    }
  } else if (cmd_frame[0] == CMD_SET_FLOOD_SCOPE_KEY && len >= 2 && cmd_frame[1] == 0) {
    if (len >= 2 + 16) {
      memcpy(send_scope.key, &cmd_frame[2], sizeof(send_scope.key));  // set scope override TransportKey
    } else {
      memset(send_scope.key, 0, sizeof(send_scope.key));  // reset scope override
    }
    send_unscoped = false;
    writeOKFrame();
  } else if (cmd_frame[0] == CMD_SET_FLOOD_SCOPE_KEY && len >= 2 && cmd_frame[1] == 1) {  // ver 12+
    send_unscoped = true;
    writeOKFrame();
  } else if (cmd_frame[0] == CMD_SET_DEFAULT_FLOOD_SCOPE && len >= 1) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate _prefs default flood scope.
    } else if (len >= 1+31+16) {
      int n = strlen((char *) &cmd_frame[1]);
      if (n > 0 && n < 31) {
        strcpy(_prefs.default_scope_name, (char *) &cmd_frame[1]);
        memcpy(_prefs.default_scope_key, &cmd_frame[1+31], 16);
        savePrefs();
        writeOKFrame();
      } else {
        writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      }
    } else {
      memset(_prefs.default_scope_name, 0, sizeof(_prefs.default_scope_name));  // set default scope to null
      memset(_prefs.default_scope_key, 0, sizeof(_prefs.default_scope_key));
      savePrefs();
      writeOKFrame();
    }
  } else if (cmd_frame[0] == CMD_GET_DEFAULT_FLOOD_SCOPE) {
    out_frame[0] = RESP_CODE_DEFAULT_FLOOD_SCOPE;
    if (strlen(_prefs.default_scope_name) > 0) {
      memcpy(&out_frame[1], _prefs.default_scope_name, 31);
      memcpy(&out_frame[1+31], _prefs.default_scope_key, 16);
      _serial->writeFrame(out_frame, 1+31+16);
    } else {
      _serial->writeFrame(out_frame, 1);   // no name or key means null
    }
  } else if (cmd_frame[0] == CMD_SEND_CONTROL_DATA && len >= 2 && (cmd_frame[1] & 0x80) != 0) {
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE. createControlData()/
      // sendZeroHop() need no self_id, but the enqueued packet would
      // never be drained by Mesh::loop() while dispatch is unavailable.
    } else {
    auto resp = createControlData(&cmd_frame[1], len - 1);
    if (resp) {
      sendZeroHop(resp);
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_TABLE_FULL);
    }
    }
  } else if (cmd_frame[0] == CMD_SET_AUTOADD_CONFIG) {
    if (refusePersistIfDisallowed()) {
      // already replied ERR_CODE_BAD_STATE; do not mutate _prefs.autoadd_config.
    } else {
    _prefs.autoadd_config = cmd_frame[1];
    if (len >= 3) {
      _prefs.autoadd_max_hops = min(cmd_frame[2], (uint8_t)64);
    }
    savePrefs();
    writeOKFrame();
    }
  } else if (cmd_frame[0] == CMD_GET_AUTOADD_CONFIG) {
    int i = 0;
    out_frame[i++] = RESP_CODE_AUTOADD_CONFIG;
    out_frame[i++] = _prefs.autoadd_config;
    out_frame[i++] = _prefs.autoadd_max_hops;
    _serial->writeFrame(out_frame, i);
  } else if (cmd_frame[0] == CMD_GET_ALLOWED_REPEAT_FREQ) {
    int i = 0;
    out_frame[i++] = RESP_ALLOWED_REPEAT_FREQ;
    for (int k = 0; k < sizeof(repeat_freq_ranges)/sizeof(repeat_freq_ranges[0]) && i + 8 < sizeof(out_frame); k++) {
      auto r = &repeat_freq_ranges[k];
      memcpy(&out_frame[i], &r->lower_freq, 4); i += 4;
      memcpy(&out_frame[i], &r->upper_freq, 4); i += 4;
    }
    _serial->writeFrame(out_frame, i);
  } else if (cmd_frame[0] == CMD_SEND_RAW_PACKET && len >= 4) {
    if (refuseSendIfDispatchUnavailable()) {
      // already replied ERR_CODE_BAD_STATE. A raw parsed packet needs no
      // self_id, but sendPacket() enqueues it and Mesh::loop() would
      // never drain it while dispatch is unavailable.
    } else {
    // Payload type isn't known until after allocation+parse, exactly like
    // raw radio ingress (Dispatcher::checkRecv()) -- so a raw packet that
    // turns out to be OTA traffic must be re-checked against the same
    // ordinary-traffic reserve post-parse and released (not queued) if
    // accepting it would leave the pool at/below the reserve. Without
    // this, OTA traffic injected via this command bypasses the reserve
    // entirely and can exhaust the whole pool. See PacketManager::
    // kOtaAllocReserve.
    auto pkt = obtainNewPacket();
    if (pkt) {
      uint8_t priority = cmd_frame[1];
      if (tryParsePacket(pkt, &cmd_frame[2], len - 2)) {
        if (mesh::ota::exceedsOtaAllocReserveAfterParse(pkt, _mgr->getFreeCount(), mesh::PacketManager::kOtaAllocReserve)) {
          releasePacket(pkt);
          writeErrFrame(ERR_CODE_TABLE_FULL);
        } else {
          sendPacket(pkt, priority, 0);
          writeOKFrame();
        }
      } else {
        releasePacket(pkt);
        writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      }
    } else {
      writeErrFrame(ERR_CODE_TABLE_FULL);
    }
    }
#if MESHCORE_LORA_OTA
  } else if (cmd_frame[0] == CMD_OTA_CONTROL && len >= 2) {
    uint8_t op = cmd_frame[1];
    if (op == OTA_CTRL_GET_STATUS) {
      if (len == 3 && (cmd_frame[2] == 1 || cmd_frame[2] == 2)) {
        const char* detail = cmd_frame[2] == 1 ? otaBoardEarlyWriteDiagnostic() : otaBoardInstallCapabilityStatus();
        const size_t count = mesh::ota::encodeOtaOrdinaryWriteDiagnostic(
            out_frame, sizeof(out_frame), RESP_CODE_OTA_STATUS, _store->destructiveWritesDisallowed(), detail);
        _serial->writeFrame(out_frame, count);
      } else if (len == 2) {
        int i = 0;
        out_frame[i++] = RESP_CODE_OTA_STATUS;
        formatFirmwareOtaStatus((char*)&out_frame[i], sizeof(out_frame) - i);
        i += strlen((char*)&out_frame[i]);
        _serial->writeFrame(out_frame, i);
      } else {
        writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      }
    } else if (op == OTA_CTRL_SET_MODE && len >= 3) {
      if (refusePersistIfDisallowed()) {
        // already replied ERR_CODE_BAD_STATE; do not mutate _prefs.ota_mode.
      } else {
        const char* mode = cmd_frame[2] == 0 ? "direct" : (cmd_frame[2] == 1 ? "routed" : (cmd_frame[2] == 2 ? "fleet" : ""));
        if (setFirmwareOtaMode(mode)) writeOKFrame(); else writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      }
    } else if (op == OTA_CTRL_SET_DUTY && len >= 6) {
      if (refusePersistIfDisallowed()) {
        // already replied ERR_CODE_BAD_STATE; do not mutate _prefs.ota_duty_percent.
      } else {
        uint32_t milli_percent;
        memcpy(&milli_percent, &cmd_frame[2], 4);
        if (setFirmwareOtaDutyCycle(((float)milli_percent) / 1000.0f)) writeOKFrame(); else writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      }
    } else if (op == OTA_CTRL_ABORT) {
      abortFirmwareOta();
      writeOKFrame();
    } else if (op == OTA_CTRL_ROLLBACK) {
      rollbackFirmwareOta();
      writeOKFrame();
    } else if (op == OTA_CTRL_DIRECT_LEASE && len >= 14) {
      if (refusePersistIfDisallowed()) {
        // already replied ERR_CODE_BAD_STATE; do not mutate _prefs.ota_mode
        // or the live radio engine. DIRECT_LEASE currently reuses
        // setFirmwareOtaMode("direct"), which persists _prefs.ota_mode via
        // savePrefs() -- refuse BEFORE any mutation rather than silently
        // applying the lease and replying OK while the persisted mode is
        // left stale/rolled back.
      } else {
      int i = 2;
      uint32_t freq;
      uint32_t bw;
      memcpy(&freq, &cmd_frame[i], 4); i += 4;
      memcpy(&bw, &cmd_frame[i], 4); i += 4;
      uint8_t sf = cmd_frame[i++];
      uint8_t cr = cmd_frame[i++];
      uint16_t timeout_mins;
      memcpy(&timeout_mins, &cmd_frame[i], 2);
      mesh::ota::OtaDirectLeaseParams lease{((float)freq) / 1000.0f, ((float)bw) / 1000.0f, sf, cr, timeout_mins};
      if (mesh::ota::isValidOtaDirectLease(lease)) {
        class BinaryLeaseHandler : public mesh::ota::OtaDirectLeaseHandler {
        public:
          explicit BinaryLeaseHandler(MyMesh* mesh) : mesh_(mesh) {}
          bool setOtaDirectMode() override { return mesh_->setFirmwareOtaMode("direct"); }
          void applyOtaDirectLease(const mesh::ota::OtaDirectLeaseParams& params) override {
            mesh_->applyTempRadioParams(params.freqMhz, params.bandwidthKhz,
                                        params.spreadingFactor, params.codingRate,
                                        params.timeoutMinutes);
          }
        private:
          MyMesh* mesh_;
        } handler(this);
        if (mesh::ota::requestOtaDirectLease(handler, lease)) {
          writeOKFrame();
        } else {
          writeErrFrame(ERR_CODE_ILLEGAL_ARG);
        }
      } else {
        writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      }
      }
    } else if (op >= 0x10 && op <= 0x18) {
      // Lean local-USB uploader/status wire contract (see
      // helpers/ota/OtaUsbProtocol.h) -- fixed 107-byte ABI3 reply shape, NOT
      // writeOKFrame()/writeErrFrame().
      handleUsbOtaProtocolOp(op, cmd_frame, len);
    } else {
      // The USB commissioning/session-router subcommand range
      // (OPEN..CLOSE) that used to be handled here depended on the
      // now-removed USB control-session-router/measurement-collector
      // subsystem (see docs/lora_ota_development.md for the cleanup
      // rationale). Report it as unsupported rather than wiring a
      // fabricated/placeholder reply; a real minimal uploader API is a
      // separate, coordinated follow-up.
      writeErrFrame(ERR_CODE_UNSUPPORTED_CMD);
    }
#endif
  } else {
    writeErrFrame(ERR_CODE_UNSUPPORTED_CMD);
    MESH_DEBUG_PRINTLN("ERROR: unknown command: %02X", cmd_frame[0]);
  }
}

static bool save_filter(const ContactInfo& c) {
  return c.type != ADV_TYPE_NONE;   // don't save the transient/anon entries
}

bool MyMesh::saveContacts() {
  const bool ok = _store->saveContacts(this, save_filter);
#if MESHCORE_LORA_OTA
  // Same latch/rationale as savePrefs() -- a real, already-performed
  // ordinary filesystem write, never a fabricated probe. A policy-
  // refused write must never be misread as a storage fault.
  if (!ok && !_store->destructiveWritesDisallowed()) _ota_service_.noteStorageIoResult(false);
#endif
  return ok;
}

void MyMesh::enterCLIRescue() {
  _cli_rescue = true;
  cli_command[0] = 0;
  Serial.println("========= CLI Rescue =========");
}

bool MyMesh::handleCommand(const char* command, uint32_t sender_timestamp, char* reply) {
  while (*command == ' ') command++; // skip leading spaces

  if (strlen(command) > 4 && command[2] == '|') { // optional prefix (for companion radio CLI)
    memcpy(reply, command, 3);                    // reflect the prefix back
    reply += 3;
    *reply = 0;
    command += 3;
  }

  if (_prefs.getRadioPrefs()->handleCommand(command, sender_timestamp, reply)) {  // is radio CLI command?
    if (_prefs.getRadioPrefs()->isDirty()) { savePrefs(); }
    return true;
  }

  // hook for variant-specific CLI processing
  if (board.handleCommand(command, sender_timestamp, reply)) {
    if (_prefs.isDirty()) { savePrefs(); }
    return true;
  }

  if (strcmp(command, "reboot") == 0) {
    board.reboot(); // doesn't return
    return true;
  }

  if (strcmp(command, "poweroff") == 0 || strcmp(command, "shutdown") == 0) {
    board.powerOff(); // doesn't return
    return true;
  }

  if (memcmp(command, "set name ", 9) == 0) {
    if (AdvertDataParser::isValidName(&command[9])) {
      StrHelper::strncpy(_prefs.node_name, &command[9], sizeof(_prefs.node_name));
      savePrefs();
      strcpy(reply, "OK");
    } else {
      strcpy(reply, "Error, bad chars");
    }
    return true;
  }
  if (strcmp(command, "get name") == 0) {
    sprintf(reply, "> %s", _prefs.node_name);
    return true;
  }

  if (memcmp(command, "set pin ", 8) == 0) {
    _prefs.ble_pin = atoi(&command[8]);
    savePrefs();
    sprintf(reply, "> pin is now %06d", _prefs.ble_pin);
    return true;
  }

#ifdef ENABLE_WIFI_INTERFACE
  if (memcmp(command, "set wifi.ssid ", 14) == 0) {
    StrHelper::strncpy(_prefs.wifi_ssid, &command[14], sizeof(_prefs.wifi_ssid));
    savePrefs();
    sprintf(reply, "> wifi.ssid is now %s (set wifi.pwd too, then reboot)", _prefs.wifi_ssid);
    return true;
  }
  if (memcmp(command, "set wifi.pwd ", 13) == 0) {
    StrHelper::strncpy(_prefs.wifi_pwd, &command[13], sizeof(_prefs.wifi_pwd));
    savePrefs();
    strcpy(reply, "> wifi.pwd updated (reboot to apply)");
    return true;
  }
  if (strcmp(command, "get wifi.pwd") == 0) {
    sprintf(reply, "> %s", _prefs.wifi_pwd);
    return true;
  }
  if (strcmp(command, "set wifi.clear") == 0) {
    _prefs.wifi_ssid[0] = 0;
    _prefs.wifi_pwd[0] = 0;
    savePrefs();
    strcpy(reply, "> wifi config cleared (reboot to apply)");
    return true;
  }
  if (strcmp(command, "get wifi.ssid") == 0) {
    sprintf(reply, "> %s", _prefs.getWifiSSID()[0] ? _prefs.getWifiSSID() : "(not set)");
    return true;
  }
  if (memcmp(command, "set wifi.enabled ", 17) == 0) {
    _prefs.wifi_enabled = atoi(&command[17]) ? 1 : 0;
    savePrefs();
    sprintf(reply, "> wifi.enabled is now %d (reboot to apply)", _prefs.wifi_enabled);
    return true;
  }
  if (strcmp(command, "get wifi.enabled") == 0) {
    sprintf(reply, "> %d", _prefs.wifi_enabled);
    return true;
  }
  if (strcmp(command, "get wifi.status") == 0) {
    strcpy(reply, WiFi.status() == WL_CONNECTED ? "> connected" : "> disconnected");
    return true;
  }
  if (strcmp(command, "get wifi.ip") == 0) {
    if (WiFi.status() == WL_CONNECTED) {
      sprintf(reply, "> %s", WiFi.localIP().toString().c_str());
    } else {
      strcpy(reply, "> (not connected)");
    }
    return true;
  }
#endif

  if (strcmp(command, "board") == 0) {
    strcpy(reply, board.getManufacturerName());
    return true;
  }

  if (strcmp(command, "ver") == 0) {
    sprintf(reply, "%s (Build: %s)", FIRMWARE_VERSION, FIRMWARE_BUILD_DATE);
    return true;
  }

  if (strcmp(command, "get tz.offset") == 0) {
    sprintf(reply, "> %d", _prefs.tz_offset);
    return true;
  }
  if (memcmp(command, "set tz.offset ", 14) == 0) {
    int8_t tz = atof(&command[14]);
    if (tz < -12 || tz > 14) {
      strcpy(reply, "Error, must be from -12 to +14");
    } else {
      _prefs.tz_offset = tz;
      savePrefs();
      strcpy(reply, "OK");
    }
    return true;
  }

  return false;  // not handled
}

void MyMesh::checkCLIRescueCmd() {
  int len = strlen(cli_command);
  // `cli_command` must stay NUL-terminated within its bounds. If it ever isn't,
  // strlen() above can return >= sizeof(cli_command) and the loop below would
  // then index past the buffer, so clamp defensively.
  if (len >= (int)sizeof(cli_command)) {
    cli_command[0] = 0;
    len = 0;
  }
  while (Serial.available() && len < sizeof(cli_command)-1) {
    char c = Serial.read();
    if (c != '\n') {
      cli_command[len++] = c;
      cli_command[len] = 0;
    }
    Serial.print(c);  // echo
  }
  if (len == sizeof(cli_command)-1) {  // buffer full: treat as a completed line
    cli_command[sizeof(cli_command)-2] = '\r';  // place end-of-line marker inside the buffer
    cli_command[sizeof(cli_command)-1] = 0;     // keep the buffer NUL-terminated
  }

  if (len > 0 && cli_command[len - 1] == '\r') {  // received complete line
    cli_command[len - 1] = 0;  // replace newline with C string null terminator

    reply_buf[0] = 0;
    if (handleCommand(cli_command, 0, reply_buf)) {
      // command was handled, print reply output
      Serial.print("  "); Serial.print(reply_buf); Serial.println();
    } else if (strcmp(cli_command, "rebuild") == 0) {
      bool success = _store->formatFileSystem();
      if (success) {
        const bool id_ok = _store->saveMainIdentity(self_id);
#if MESHCORE_LORA_OTA
        if (id_ok) {
          // Re-persists the SAME already-held identity after an
          // erase+rebuild -- a real, durable write just succeeded, the
          // same category of evidence as begin()'s GeneratedAndSaved.
          _ota_service_.noteIdentityPersisted();
        } else {
          _ota_service_.noteStorageIoResult(false);
        }
#else
        (void)id_ok;
#endif
        savePrefs();
        saveContacts();
        saveChannels();
        Serial.println("  > erase and rebuild done");
      } else {
        Serial.println("  Error: erase failed");
      }
    } else if (strcmp(cli_command, "erase") == 0) {
      bool success = _store->formatFileSystem();
      if (success) {
        Serial.println("  > erase done");
      } else {
        Serial.println("  Error: erase failed");
      }
    } else if (memcmp(cli_command, "ls", 2) == 0) {

      // get path from command e.g: "ls /adafruit"
      const char *path = &cli_command[3];

      bool is_fs2 = false;
      if (memcmp(path, "UserData/", 9) == 0) {
        path += 8; // skip "UserData"
      } else if (memcmp(path, "ExtraFS/", 8) == 0) {
        path += 7; // skip "ExtraFS"
        is_fs2 = true;
      }
      Serial.printf("Listing files in %s\n", path);

      // log each file and directory
      File root = _store->openRead(path);
      if (is_fs2 == false) {
        if (root) {
          File file = root.openNextFile();
          while (file) {
            if (file.isDirectory()) {
              Serial.printf("[dir]  UserData%s/%s\n", path, file.name());
            } else {
              Serial.printf("[file] UserData%s/%s (%d bytes)\n", path, file.name(), file.size());
            }
            // move to next file
            file = root.openNextFile();
          }
          root.close();
        }
      }

      if (is_fs2 == true || strlen(path) == 0 || strcmp(path, "/") == 0) {
        if (_store->getSecondaryFS() != nullptr) {
          File root2 = _store->openRead(_store->getSecondaryFS(), path);
          File file = root2.openNextFile();
          while (file) {
            if (file.isDirectory()) {
              Serial.printf("[dir]  ExtraFS%s/%s\n", path, file.name());
            } else {
              Serial.printf("[file] ExtraFS%s/%s (%d bytes)\n", path, file.name(), file.size());
            }
            // move to next file
            file = root2.openNextFile();
          }
          root2.close();
        }
      }
    } else if (memcmp(cli_command, "cat", 3) == 0) {

      // get path from command e.g: "cat /contacts3"
      const char *path = &cli_command[4];

      bool is_fs2 = false;
      if (memcmp(path, "UserData/", 9) == 0) {
        path += 8; // skip "UserData"
      } else if (memcmp(path, "ExtraFS/", 8) == 0) {
        path += 7; // skip "ExtraFS"
        is_fs2 = true;
      } else {
        Serial.println("Invalid path provided, must start with UserData/ or ExtraFS/");
        cli_command[0] = 0;
        return;
      }

      // log file content as hex
      File file = _store->openRead(path);
      if (is_fs2 == true) {
        file = _store->openRead(_store->getSecondaryFS(), path);
      }
      if(file){

        // get file content
        int file_size = file.available();
        uint8_t buffer[file_size];
        file.read(buffer, file_size);

        // print hex
        mesh::Utils::printHex(Serial, buffer, file_size);
        Serial.print("\n");

        file.close();

      }

    } else if (memcmp(cli_command, "rm ", 3) == 0) {
      // get path from command e.g: "rm /adv_blobs"
      const char *path = &cli_command[3];
      MESH_DEBUG_PRINTLN("Removing file: %s", path);
      // ensure path is not empty, or root dir
      if(!path || strlen(path) == 0 || strcmp(path, "/") == 0){
        Serial.println("Invalid path provided");
      } else {
      bool is_fs2 = false;
      if (memcmp(path, "UserData/", 9) == 0) {
        path += 8; // skip "UserData"
      } else if (memcmp(path, "ExtraFS/", 8) == 0) {
        path += 7; // skip "ExtraFS"
        is_fs2 = true;
      }

        // remove file
        bool removed;
        if (is_fs2) {
          MESH_DEBUG_PRINTLN("Removing file from ExtraFS: %s", path);
          removed = _store->removeFile(_store->getSecondaryFS(), path);
        } else {
          MESH_DEBUG_PRINTLN("Removing file from UserData: %s", path);
          removed = _store->removeFile(path);
        }
        if(removed){
          Serial.println("File removed");
        } else {
          Serial.println("Failed to remove file");
        }

      }

    } else if (strcmp(cli_command, "reboot") == 0) {
      board.reboot();  // doesn't return
    } else {
      Serial.println("  Error: unknown command");
    }

    cli_command[0] = 0;  // reset command buffer
  }
}

void MyMesh::checkSerialInterface() {
#if XIAO_OTA_COMPANION_USB_UF2
  bool local_usb = false;
  size_t len = companion_usb_uf2::receive(
      _serial, interface_manager, usb_serial_interface, cmd_frame, local_usb);
#else
  size_t len = _serial->checkRecvFrame(cmd_frame);
#endif
  if (len > 0) {
#if XIAO_OTA_COMPANION_USB_UF2
    _command_from_local_usb = local_usb;
#endif
    handleCmdFrame(len);
#if XIAO_OTA_COMPANION_USB_UF2
    _command_from_local_usb = false;
#endif
  } else if (_iter_started              // check if our ContactsIterator is 'running'
             && !_serial->isWriteBusy() // don't spam the Serial Interface too quickly!
  ) {
    sendNextContact();
  //} else if (!_serial->isWriteBusy()) {
  //  checkConnections();    // TODO - deprecate the 'Connections' stuff
  }
}

__attribute__((noinline)) void MyMesh::sendNextContact() {
    ContactInfo contact;
    if (_iter.hasNext(this, contact)) {
      if (contact.lastmod > _iter_filter_since) { // apply the 'since' filter
        writeContactRespFrame(RESP_CODE_CONTACT, contact);
        if (contact.lastmod > _most_recent_lastmod) {
          _most_recent_lastmod = contact.lastmod; // save for the RESP_CODE_END_OF_CONTACTS frame
        }
      }
    } else { // EOF
      out_frame[0] = RESP_CODE_END_OF_CONTACTS;
      memcpy(&out_frame[1], &_most_recent_lastmod,
             4); // include the most recent lastmod, so app can update their 'since'
      _serial->writeFrame(out_frame, 5);
      _iter_started = false;
    }
}

void MyMesh::loop() {
#if MESHCORE_LORA_OTA
  if (!_identity_available_) _ota_rf_uploader.stop(getOtaIntegration());
  getOtaIntegration().tickDirect(_ms->getMillis(), !isSendInProgress() && _mgr->getOutboundTotal() == 0);
#endif
  if (_identity_available_) {
    // Ordinary mesh dispatch (packet TX/RX scheduling, advertising,
    // signing) is entirely identity-dependent -- suppressed whenever
    // begin() could not establish a real identity during a trial/
    // unknown boot (see the ota_identity_boot::Outcome::IdentityUnavailable
    // branch above). The bounded serial/diagnostic/trial-health
    // maintenance path below still runs either way.
    BaseChatMesh::loop();
    checkTempRadioLease();
#if MESHCORE_LORA_OTA
    pumpOtaRfUpload();
#endif
  }
  // Lease restoration must not be identity-gated -- see
  // revertTempRadioLeaseIfDue()'s doc comment.
  revertTempRadioLeaseIfDue();

  if (_cli_rescue) {
    checkCLIRescueCmd();
  } else {
    checkSerialInterface();
#if defined(ENABLE_WIFI_INTERFACE) && defined(RP2040_PLATFORM) && !defined(ENABLE_USB_INTERFACE)
    // RP2040 WiFi builds are headless and have no way into the rescue CLI (that needs a
    // display + long-press), so serve config commands on the otherwise unused USB serial
    checkCLIRescueCmd();
#endif
  }

  // is there are pending dirty contacts write needed? A denied/failed
  // write must never be silently labeled "saved" -- gate BEFORE mutation
  // (mirrors the CMD_REBOOT handler's existing identical guard above)
  // rather than calling saveContacts() unconditionally and only
  // propagating its fault afterward. Astra's correction: the previous
  // version cleared dirty_contacts_expiry unconditionally even when the
  // gate denied the write, permanently discarding the pending save
  // instead of retrying once writes are allowed again -- only clear the
  // flag on the branch that actually performed the write.
  if (dirty_contacts_expiry && millisHasNowPassed(dirty_contacts_expiry)) {
    if (!_store->destructiveWritesDisallowed()) {
      saveContacts();
      dirty_contacts_expiry = 0;
    }
  }
#if MESHCORE_LORA_OTA && defined(NRF52840_XXAA)
  getOtaIntegration().tickCommitReboot(_ms->getMillis(), isSendInProgress(),
                                      _mgr->getOutboundTotal() != 0, _serial->isWriteBusy());
#endif
#if XIAO_OTA_COMPANION_USB_UF2
  companion_usb_uf2::tick(
      _uf2_reboot, _ms->getMillis(), isSendInProgress(), _mgr->getOutboundTotal() != 0,
      _serial->isWriteBusy(), [this]() { return uf2RebootAllowed(); },
      [this]() {
        return !dirty_contacts_expiry || _store->destructiveWritesDisallowed() || saveContacts();
      },
      [this](companion_usb_uf2::Reply reply) { replyUf2Reboot(reply); },
      []() { Serial.flush(); enterUf2Dfu(); });
#endif
}

#if MESHCORE_LORA_OTA
void MyMesh::setOtaTrialBootHealthSignals(bool radio_ready, bool filesystem_ready) {
  _ota_trial_radio_ready = radio_ready;
  _ota_trial_filesystem_ready = filesystem_ready;
}

bool MyMesh::isRadioStuckOutOfRecv(uint32_t now_ms) {
  if (_radio != nullptr && _radio->isInRecvMode()) return false;
  if (isSendInProgress()) {
    // Genuinely transmitting right now: bound by the real per-packet
    // airtime+margin deadline Dispatcher already computed for this send
    // (see checkSend()), so a legitimately long TX (e.g. SF12) is never
    // mistaken for "stuck", instead of a single fixed constant.
    return millisHasNowPassed(getCurrentSendDeadlineMs());
  }
  // Neither receiving nor sending: fall back to the same conservative
  // floor Dispatcher's own generic watchdog uses (see Dispatcher.cpp
  // loop()'s ERR_EVENT_STARTRX_TIMEOUT), computed independently here
  // from the Dispatcher-tracked Rx-mode-transition timestamp, rather
  // than depending on that sticky/global `_err_flags` bit (shared with
  // unrelated error reporting and never proactively re-cleared).
  return (now_ms - getRadioNonRecvSinceMs()) > 8000;
}

void MyMesh::tickOtaTrialHealth() {
  // Reaching this call at all, on every outer-loop pass, IS the
  // "loop_healthy" liveness proof (a crashed/hung/watchdog-reset
  // firmware never gets here again) -- AND, because main.cpp's loop()
  // now calls this only AFTER mesh dispatch, every interface, sensors/
  // UI, RTC, the external watchdog, and WiFi reconnect have already run
  // to completion THIS SAME PASS, it is a genuinely complete "this whole
  // outer service loop finished" signal, not merely "some earlier code
  // in this tick ran." The genuinely CONTINUOUS 10-second window and the
  // 45-second overall deadline are both tracked, tick-to-tick-gap-aware,
  // inside XiaoOtaTrialHealthMonitor itself (see that header), driven
  // purely by the wall-clock `now_ms` passed in below; this call site
  // only reacts to the LATCHED terminal outcome.
  const uint32_t now_ms = _ms->getMillis();
  // Real, per-tick (not just cached-at-boot) grounded signals:
  //
  // Radio: `_radio->isInRecvMode()` ALONE would incorrectly disqualify a
  // perfectly healthy node the instant it transmits an ordinary packet
  // (TX briefly leaves Rx mode -- see RadioLibWrapper's STATE_TX_WAIT/
  // STATE_TX_DONE/brief STATE_IDLE window before the next startReceive()),
  // resetting the continuous window on completely normal traffic. A
  // SINGLE fixed "stuck out of Rx" constant is ALSO insufficient on its
  // own: a genuinely healthy transmission at a supported SF (e.g. SF12)
  // can legitimately take longer than any one fixed constant, so the
  // stuck check below is bounded by the ACTUAL per-packet airtime+margin
  // deadline Dispatcher already computes for the send currently in
  // flight (`getCurrentSendDeadlineMs()`, see checkSend()) whenever one
  // is genuinely in progress (`isSendInProgress()`), falling back to the
  // same conservative floor as Dispatcher's own generic watchdog only
  // when neither receiving nor sending. Driver health itself is now a
  // genuine, ACTIVE, per-tick probe (`Radio::probeDriverStatus()`) --
  // for CustomSX1262Wrapper this is a real bounded hardware error-flag
  // read taken THIS tick (see CustomSX1262Wrapper::probeDriverStatus()),
  // not merely a passively-latched reaction to whichever ordinary op
  // happened to run last, and not merely an "unobserved default" during
  // a quiet period with no ordinary traffic at all. A null radio is
  // never treated as healthy.
  //
  // Filesystem: the boot-time mount flag never re-validates itself, and
  // the OTA candidate-sink IoError latch (`otaBoardStorageIoFaultObserved()`)
  // is never actually exercised WHILE a trial is active -- the guarded
  // staging sink deliberately refuses to even begin a session (let alone
  // reach writeChunk()/commit()) whenever a trial-boot health window is
  // active/unknown (see OtaBoardTrialGuardedStagingSink), so it can never
  // observe an ordinary filesystem fault during exactly the window that
  // matters. Instead, reuse the ACTUAL outcome of genuine, already-
  // performed ordinary filesystem writes/reads this boot -- NodePrefs
  // saves (`savePrefs()`), contact/channel saves (`saveContacts()`/
  // `saveChannels()`), identity-import saves (`CMD_IMPORT_PRIVATE_KEY`)
  // and identity load at startup (`_store->saveMainIdentity()`/loadMain
  // paths) all already call bool-returning DataStore methods and now
  // report into `_ota_service_` (see helpers/ota/OtaFirmwareService.h)
  // on a genuine failure
  // (see MyMesh.h/DataStore.h/checkSerialInterface()/main.cpp) -- never a
  // fabricated dummy probe write, and never assumed to stay "ready"
  // forever just because the mount once succeeded. Those writes only
  // happen when the USER actually triggers one, though, so a window with
  // no user activity would otherwise see stale (boot-time-only)
  // evidence; `DataStore::probeStorageReadiness()` closes that gap with
  // a genuinely bounded, side-effect-free (single File::read(), never a
  // write) fresh MANDATORY-identity-integrity check (persisted key bytes
  // compared against `self_id`, actually in RAM, not just a read-length
  // check) plus a real prefs.json open-then-immediately-close, performed
  // on EVERY tick during the window, so a real mid-trial storage failure
  // is still observed even if the user never happens to save anything.
  if (_store != nullptr && !_store->probeStorageReadiness(self_id)) {
    _ota_service_.noteStorageIoResult(false);
  }
  // Sampled fresh THIS tick only -- never persisted across ticks (see
  // OtaTrialRadioReadiness.h for why a sticky "fault observed" bool
  // would wrongly abort the whole boot on one transient failure).
  const uint32_t radio_fault_count_before_probe = (_radio != nullptr) ? _radio->driverFaultCount() : _ota_trial_last_radio_fault_count_;
  const bool radio_driver_healthy = probeRadioDriverStatus();
  const uint32_t radio_fault_count_after_probe = (_radio != nullptr) ? _radio->driverFaultCount() : radio_fault_count_before_probe;
  const bool radio_stuck_non_recv = isRadioStuckOutOfRecv(now_ms);
  // Genuine ACTIVE service proof for this pass: an internally-consistent
  // "idle" chip status is NOT proof the radio is actually doing its job
  // -- only an active Rx or a genuinely in-flight Tx counts (see
  // OtaTrialRadioReadiness.h's "INDEFINITE-IDLE ACCEPTANCE" note). A
  // lone idle pass simply fails this pass (resetting the window like
  // any other readiness drop), it is never a terminal failure.
  const bool radio_genuinely_servicing = (_radio != nullptr) && (_radio->isInRecvMode() || isSendInProgress());
  const bool filesystem_ready_now = _ota_trial_filesystem_ready && !otaBoardStorageIoFaultObserved() &&
                                    !_ota_service_.trialFilesystemFaultObserved() &&
                                    !(_store != nullptr && _store->blobIoFaultObserved());
  // Shared with every other MESHCORE_LORA_OTA MyMesh (e.g.
  // examples/simple_repeater/MyMesh.cpp's role-1 build) -- see
  // helpers/ota/OtaMeshTrialHealthTick.h: this call is the single place
  // the readiness-this-pass evaluation and the terminal-outcome-to-
  // reboot mapping live, never hand-copied a second time.
  const mesh::ota::OtaMeshTrialHealthTickInputs tick_in{
      now_ms, _radio != nullptr, _ota_trial_radio_ready, radio_stuck_non_recv, radio_driver_healthy,
      radio_genuinely_servicing, radio_fault_count_before_probe, radio_fault_count_after_probe,
      filesystem_ready_now};
  const auto tick_result =
      mesh::ota::evaluateOtaMeshTrialHealthTick(tick_in, _ota_trial_last_radio_fault_count_);
  // Exactly one deliberate, controlled reboot on any of the three
  // terminal outcomes -- Confirmed (durable confirmation already
  // written+read back), DeadlineExpired (never touch/rely on the
  // bootloader's own watchdog reload; issue our own reboot instead so
  // its unconfirmed-trial rollback path runs cleanly on the next boot),
  // ConfirmationUncertain (a confirmation write attempt itself failed --
  // never retried; the next boot re-reads the actual durable token from
  // flash rather than this process attempting a second flash
  // transaction), or StateUnreadable (the eager at-construction state-
  // record read itself came back ambiguous -- an unreadable or corrupt
  // slot -- so whether a trial is genuinely in progress could not be
  // determined at all; fails closed rather than running indefinitely).
  // Latched via _ota_trial_reboot_issued so this can never fire twice.
  if (!_ota_trial_reboot_issued && tick_result.should_reboot) {
    _ota_trial_reboot_issued = true;
    board.reboot();
  }
}
#endif

void MyMesh::checkTempRadioLease() {
  _temporary_radio_lease.applyIfDue(_ms->getMillis(), [this]() {
    applyRadioParams(pending_freq, pending_bw, pending_sf, pending_cr);
  });
}

// Restoring normal parameters must remain independent of identity availability.
void MyMesh::revertTempRadioLeaseIfDue() {
  const uint32_t now = _ms->getMillis();
#if MESHCORE_LORA_OTA && defined(NRF52_PLATFORM)
  _temporary_radio_lease.restoreIfDue(now, [this]() {
    const bool restored = otaBoardApplyRfProfile(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
    if (!restored) MESH_DEBUG_PRINTLN("Temporary radio lease: normal profile restore failed");
    return restored;
  }, !isSendInProgress() && !_radio->isReceiving());
#else
  // Preserve the existing unchecked radio API on other platforms/builds.
  _temporary_radio_lease.restoreUncheckedIfDue(now, [this]() {
    applyRadioParams(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
  });
#endif
}

bool MyMesh::advert() {
  if (!_identity_available_) {
    // No real identity this boot (trial/unknown) -- called from UI
    // button-press handlers outside loop()'s identity gate; behave like
    // any other "couldn't advertise" failure rather than signing with
    // the default/unset self_id.
    return false;
  }
  mesh::Packet* pkt;
  if (_prefs.advert_loc_policy == ADVERT_LOC_NONE) {
    pkt = createSelfAdvert(_prefs.node_name);
  } else {
    pkt = createSelfAdvert(_prefs.node_name, sensors.node_lat, sensors.node_lon);
  }
  if (pkt) {
    sendZeroHop(pkt);
    return true;
  } else {
    return false;
  }
}

// To check if there is pending work
bool MyMesh::hasPendingWork() const {
#if XIAO_OTA_COMPANION_USB_UF2
  if (_uf2_reboot.active) return true;
#endif
  bool trial_active = false;
#if MESHCORE_LORA_OTA
  // Never let this device deep-sleep while a trial-boot health window is
  // genuinely in progress -- sleeping would starve the continuous
  // radio/filesystem/loop readiness this window requires, and could
  // stall the whole confirmation past the 45-second deadline for no
  // reason other than an otherwise-idle radio queue.
  trial_active = otaBoardTrialHealthWindowActive() || otaBoardBootLifecycleVerificationPending() ||
                   _ota_rf_uploader.active() || getOtaIntegration().hasPendingRfWork();
#endif
  return _mgr->getOutboundTotal() > 0 || dirty_contacts_expiry != 0 || trial_active;
}
