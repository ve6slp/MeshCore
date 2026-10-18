#pragma once

// SDK-only doubles: the test compiles the unmodified production backend and
// partition boundary. Flash, partition identity/state and NVS remain observable.
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

using esp_err_t = int32_t;
constexpr esp_err_t ESP_OK = 0, ESP_ERR_INVALID_ARG = 0x102, ESP_ERR_INVALID_SIZE = 0x104;
constexpr esp_err_t ESP_ERR_NOT_FOUND = 0x105, ESP_ERR_NVS_NOT_FOUND = 0x1102;
constexpr esp_err_t ESP_ERR_WIFI_NOT_INIT = 0x3001;
enum esp_partition_type_t { ESP_PARTITION_TYPE_APP = 0, ESP_PARTITION_TYPE_DATA = 1,
                            ESP_PARTITION_TYPE_ANY = 0xff };
enum esp_partition_subtype_t { ESP_PARTITION_SUBTYPE_ANY = 0xff };
enum esp_ota_img_states_t { ESP_OTA_IMG_NEW, ESP_OTA_IMG_PENDING_VERIFY, ESP_OTA_IMG_VALID,
                          ESP_OTA_IMG_INVALID, ESP_OTA_IMG_ABORTED, ESP_OTA_IMG_UNDEFINED = -1 };
struct esp_flash_t {};
inline esp_flash_t nativeChip;
inline esp_flash_t* esp_flash_default_chip = &nativeChip;
struct esp_partition_t {
  esp_flash_t* flash_chip;
  esp_partition_type_t type;
  esp_partition_subtype_t subtype;
  uint32_t address, size;
  char label[17];
  bool encrypted;
};
struct NativeEspState {
  std::vector<uint8_t> flash;
  esp_partition_t partitions[6] = {};
  esp_ota_img_states_t states[2] = {ESP_OTA_IMG_VALID, ESP_OTA_IMG_UNDEFINED};
  unsigned running = 0, boot = 0, restarts = 0, markValidCalls = 0;
  uint32_t entropy = 0, physicalSize = 0x800000;
  size_t partitionCount = 6, reads = 0, writes = 0, erases = 0;
  std::map<std::string, std::map<std::string, std::vector<uint8_t>>> nvs;
  std::vector<std::string> handles;
  void reset(unsigned slot) {
    flash.assign(0x800000, 0x5a);
    const char* labels[] = {"nvs", "otadata", "app0", "app1", "spiffs", "coredump"};
    const uint32_t addresses[] = {0x9000, 0xe000, 0x10000, 0x340000, 0x670000, 0x7f0000};
    const uint32_t sizes[] = {0x5000, 0x2000, 0x330000, 0x330000, 0x180000, 0x10000};
    const unsigned subtypes[] = {2, 0, 0x10, 0x11, 0x82, 3};
    for (unsigned i = 0; i < 6; ++i) {
      partitions[i] = {esp_flash_default_chip, i == 2 || i == 3 ?
          ESP_PARTITION_TYPE_APP : ESP_PARTITION_TYPE_DATA,
          static_cast<esp_partition_subtype_t>(subtypes[i]), addresses[i], sizes[i], {}, false};
      std::strcpy(partitions[i].label, labels[i]);
    }
    std::fill(flash.begin() + 0x33c000, flash.begin() + 0x340000, 0xff);
    states[0] = states[1] = ESP_OTA_IMG_VALID;
    running = boot = slot; restarts = markValidCalls = 0;
    physicalSize = 0x800000; partitionCount = 6; reads = writes = erases = 0;
    nvs.clear(); handles.clear();
    nvs["personality"]["identity"] = {0x21, 0x33, 0x87};
    nvs["personality"]["radio"] = {0x44, 0x57, 0x18};
  }
  void bootSelected() { running = boot; states[running] = ESP_OTA_IMG_PENDING_VERIFY; }
  void rollback(esp_ota_img_states_t state) {
    assert(state == ESP_OTA_IMG_ABORTED || state == ESP_OTA_IMG_INVALID);
    states[running] = state; running = boot = 1 - running;
  }
};
inline NativeEspState nativeEsp;

inline esp_err_t esp_flash_get_size(esp_flash_t*, uint32_t* size) {
  *size = nativeEsp.flash.size(); return ESP_OK;
}
inline esp_err_t esp_flash_get_physical_size(esp_flash_t*, uint32_t* size) {
  *size = nativeEsp.physicalSize; return ESP_OK;
}
using esp_partition_iterator_t = const esp_partition_t*;
inline esp_partition_iterator_t esp_partition_find(esp_partition_type_t, esp_partition_subtype_t,
                                                   const char*) {
  return nativeEsp.partitionCount ? nativeEsp.partitions : nullptr;
}
inline const esp_partition_t* esp_partition_get(esp_partition_iterator_t it) { return it; }
inline esp_partition_iterator_t esp_partition_next(esp_partition_iterator_t it) {
  return size_t(it - nativeEsp.partitions + 1) < nativeEsp.partitionCount ? it + 1 : nullptr;
}
inline void esp_partition_iterator_release(esp_partition_iterator_t) {}
inline const esp_partition_t* esp_partition_find_first(esp_partition_type_t type,
                                                       esp_partition_subtype_t subtype,
                                                       const char* label) {
  for (size_t i = 0; i < nativeEsp.partitionCount; ++i) {
    const auto& p = nativeEsp.partitions[i];
    if (p.type == type && (subtype == ESP_PARTITION_SUBTYPE_ANY || p.subtype == subtype) &&
        (!label || !std::strcmp(label, p.label))) return &p;
  }
  return nullptr;
}
inline const esp_partition_t* esp_ota_get_running_partition() {
  return &nativeEsp.partitions[2 + nativeEsp.running];
}
inline const esp_partition_t* esp_ota_get_boot_partition() {
  return &nativeEsp.partitions[2 + nativeEsp.boot];
}
inline const esp_partition_t* esp_ota_get_next_update_partition(const esp_partition_t* running) {
  return &nativeEsp.partitions[running == &nativeEsp.partitions[2] ? 3 : 2];
}
inline esp_err_t esp_ota_get_state_partition(const esp_partition_t* p, esp_ota_img_states_t* out) {
  if (p != &nativeEsp.partitions[2] && p != &nativeEsp.partitions[3]) return ESP_ERR_INVALID_ARG;
  *out = nativeEsp.states[p - nativeEsp.partitions - 2]; return ESP_OK;
}
inline esp_err_t esp_ota_set_boot_partition(const esp_partition_t* p) {
  if (p != &nativeEsp.partitions[2] && p != &nativeEsp.partitions[3]) return ESP_ERR_INVALID_ARG;
  nativeEsp.boot = p - nativeEsp.partitions - 2;
  nativeEsp.states[nativeEsp.boot] = ESP_OTA_IMG_NEW; return ESP_OK;
}
inline esp_err_t esp_ota_mark_app_valid_cancel_rollback() {
  ++nativeEsp.markValidCalls; nativeEsp.states[nativeEsp.running] = ESP_OTA_IMG_VALID; return ESP_OK;
}
inline esp_err_t esp_ota_mark_app_invalid_rollback_and_reboot() {
  nativeEsp.rollback(ESP_OTA_IMG_INVALID); ++nativeEsp.restarts; return ESP_OK;
}
inline bool nativeRange(const esp_partition_t* p, uint32_t offset, size_t size) {
  return p && offset <= p->size && size <= p->size - offset;
}
inline esp_err_t esp_partition_read(const esp_partition_t* p, uint32_t offset, void* out, size_t size) {
  if (!nativeRange(p, offset, size) || (!out && size)) return ESP_ERR_INVALID_ARG;
  if (size) std::memcpy(out, nativeEsp.flash.data() + p->address + offset, size);
  ++nativeEsp.reads; return ESP_OK;
}
inline esp_err_t esp_partition_write(const esp_partition_t* p, uint32_t offset,
                                    const void* data, size_t size) {
  if (!nativeRange(p, offset, size) || (!data && size)) return ESP_ERR_INVALID_ARG;
  const auto* in = static_cast<const uint8_t*>(data);
  for (size_t i = 0; i < size; ++i) nativeEsp.flash[p->address + offset + i] &= in[i];
  ++nativeEsp.writes; return ESP_OK;
}
inline esp_err_t esp_partition_erase_range(const esp_partition_t* p, uint32_t offset, size_t size) {
  if (!nativeRange(p, offset, size) || offset % 4096 || size % 4096) return ESP_ERR_INVALID_ARG;
  std::fill(nativeEsp.flash.begin() + p->address + offset,
            nativeEsp.flash.begin() + p->address + offset + size, 0xff);
  ++nativeEsp.erases; return ESP_OK;
}
struct esp_partition_pos_t { uint32_t offset, size; };
struct esp_image_metadata_t { uint32_t image_len = 0; };
constexpr int ESP_IMAGE_VERIFY = 0;
inline uint32_t nativeLe32(const uint8_t* p) {
  return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
inline esp_err_t esp_image_verify(int, const esp_partition_pos_t* pos, esp_image_metadata_t* out) {
  // The fixture uses one genuine ESP image segment and the ESP XOR checksum.
  if (!pos || pos->size < 48 || pos->offset > nativeEsp.flash.size() ||
      pos->size > nativeEsp.flash.size() - pos->offset) return ESP_ERR_INVALID_ARG;
  const uint8_t* p = nativeEsp.flash.data() + pos->offset;
  if (p[0] != 0xe9 || p[1] != 1 || p[23] != 0) return ESP_ERR_INVALID_ARG;
  const uint32_t dataSize = nativeLe32(p + 28);
  if (dataSize > pos->size - 48) return ESP_ERR_INVALID_SIZE;
  const uint32_t size = (32 + dataSize + 16) & ~uint32_t(15);
  if (size > pos->size) return ESP_ERR_INVALID_SIZE;
  uint8_t checksum = 0xef;
  for (uint32_t i = 0; i < dataSize; ++i) checksum ^= p[32 + i];
  if (p[size - 1] != checksum) return ESP_ERR_INVALID_ARG;
  out->image_len = size; return ESP_OK;
}

using nvs_handle_t = unsigned;
constexpr int NVS_READONLY = 0, NVS_READWRITE = 1;
inline esp_err_t nvs_open(const char* name, int mode, nvs_handle_t* handle) {
  if (!nativeEsp.nvs.count(name) && mode == NVS_READONLY) return ESP_ERR_NVS_NOT_FOUND;
  nativeEsp.nvs[name]; nativeEsp.handles.emplace_back(name);
  *handle = nativeEsp.handles.size() - 1; return ESP_OK;
}
inline void nvs_close(nvs_handle_t) {}
inline esp_err_t nvs_get_blob(nvs_handle_t h, const char* key, void* data, size_t* size) {
  const auto& ns = nativeEsp.nvs.at(nativeEsp.handles.at(h));
  const auto it = ns.find(key);
  if (it == ns.end()) return ESP_ERR_NVS_NOT_FOUND;
  if (*size < it->second.size()) return ESP_ERR_INVALID_SIZE;
  *size = it->second.size(); std::memcpy(data, it->second.data(), *size); return ESP_OK;
}
inline esp_err_t nvs_get_u32(nvs_handle_t h, const char* key, uint32_t* value) {
  uint8_t bytes[4]; size_t size = sizeof(bytes);
  const auto result = nvs_get_blob(h, key, bytes, &size);
  if (result != ESP_OK) return result;
  if (size != 4) return ESP_ERR_INVALID_SIZE;
  *value = nativeLe32(bytes); return ESP_OK;
}
inline esp_err_t nvs_set_blob(nvs_handle_t h, const char* key, const void* bytes, size_t size) {
  const auto* p = static_cast<const uint8_t*>(bytes);
  nativeEsp.nvs.at(nativeEsp.handles.at(h))[key] = std::vector<uint8_t>(p, p + size); return ESP_OK;
}
inline esp_err_t nvs_erase_key(nvs_handle_t h, const char* key) {
  return nativeEsp.nvs.at(nativeEsp.handles.at(h)).erase(key) ? ESP_OK : ESP_ERR_NVS_NOT_FOUND;
}
inline esp_err_t nvs_commit(nvs_handle_t) { return ESP_OK; }

struct Ed25519 {
  static bool verify(const uint8_t* signature, const uint8_t* key, const uint8_t* message, size_t size);
};
#define RTC_NOINIT_ATTR
#define ESP_ARDUINO_VERSION_VAL(a,b,c) ((a)*10000+(b)*100+(c))
#define ESP_ARDUINO_VERSION ESP_ARDUINO_VERSION_VAL(2,0,17)
#define ESP_IDF_VERSION_VAL(a,b,c) ESP_ARDUINO_VERSION_VAL(a,b,c)
#define ESP_IDF_VERSION ESP_IDF_VERSION_VAL(4,4,7)
#define ESP_LOGE(...) ((void)0)
inline uint32_t millis() { return 0; }
inline void esp_restart() { ++nativeEsp.restarts; }
using wifi_mode_t = int;
constexpr wifi_mode_t WIFI_MODE_NULL = 0;
inline esp_err_t esp_wifi_get_mode(wifi_mode_t*) { return ESP_ERR_WIFI_NOT_INIT; }
constexpr int ESP_BT_CONTROLLER_STATUS_IDLE = 0, ESP_BT_CONTROLLER_STATUS_ENABLED = 2;
inline int esp_bt_controller_get_status() { return ESP_BT_CONTROLLER_STATUS_IDLE; }
inline uint32_t esp_random() { return ++nativeEsp.entropy * 2654435761u; }
inline void esp_fill_random(void* out, size_t size) {
  auto* p = static_cast<uint8_t*>(out);
  for (size_t i = 0; i < size; ++i) p[i] = esp_random() >> 24;
}
inline void bootloader_random_enable() {}
inline void bootloader_random_disable() {}
inline void esp_rom_delay_us(unsigned) {}
constexpr unsigned RTC_CLK_CAL_FRACT = 19;
inline uint32_t esp_clk_slowclk_cal_get() { return 1u << RTC_CLK_CAL_FRACT; }
inline int RTCCNTL = 0;
constexpr int WDT_RWDT = 0, WDT_STAGE0 = 0, WDT_STAGE1 = 1, WDT_STAGE2 = 2, WDT_STAGE3 = 3;
constexpr int WDT_STAGE_ACTION_RESET_SYSTEM = 1, WDT_STAGE_ACTION_OFF = 0;
struct wdt_hal_context_t { int inst = 0; int* rwdt_dev = nullptr; bool enabled = false; };
inline void wdt_hal_write_protect_disable(wdt_hal_context_t*) {}
inline void wdt_hal_write_protect_enable(wdt_hal_context_t*) {}
inline void wdt_hal_init(wdt_hal_context_t*, int, int, bool) {}
inline void wdt_hal_set_flashboot_en(wdt_hal_context_t*, bool) {}
inline void wdt_hal_config_stage(wdt_hal_context_t*, int, uint32_t, int) {}
inline void wdt_hal_enable(wdt_hal_context_t* w) { w->enabled = true; }
inline void wdt_hal_disable(wdt_hal_context_t* w) { w->enabled = false; }
inline bool wdt_hal_is_enabled(wdt_hal_context_t* w) { return w->enabled; }
struct NativeRadio {
  int standby() { return 0; }
  int setFrequency(float) { return 0; }
  int setSpreadingFactor(uint8_t) { return 0; }
  int setBandwidth(float) { return 0; }
  int setCodingRate(uint8_t) { return 0; }
  int setPreambleLength(unsigned) { return 0; }
  void setPreambleMillis(unsigned) {}
  void setMaxPayloadMillis(unsigned) {}
};
struct NativeRadioDriver {
  struct Timing { unsigned preambleMillis = 0, payloadMillis = 0; };
  void begin() {}
  static unsigned preambleLengthForSF(uint8_t) { return 8; }
  Timing calcMaxPacketMillis(uint8_t, float, uint8_t, unsigned) { return {}; }
  int recvRaw(uint8_t*, unsigned) { return 0; }
  bool isInRecvMode() const { return true; }
  bool probeDriverStatus() const { return true; }
};
#define RADIO_CLASS NativeRadio
extern NativeRadioDriver radio_driver;
