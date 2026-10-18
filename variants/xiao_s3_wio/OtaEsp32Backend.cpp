#if defined(ESP32_PLATFORM) && defined(MESHCORE_LORA_OTA) && MESHCORE_LORA_OTA

#include <Arduino.h>
#include <Ed25519.h>
#include <esp_attr.h>
#include <esp_bt.h>
#include <esp_flash.h>
#include <esp_image_format.h>
#include <esp_log.h>
#include <esp_ota_ops.h>
#include <esp_random.h>
#include <esp_rom_sys.h>
#include <esp_wifi.h>
#include <bootloader_random.h>
#include <esp_arduino_version.h>
#include <esp_idf_version.h>
#include <esp_private/esp_clk.h>
#include <hal/wdt_hal.h>
#include <soc/rtc.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <helpers/ota/OtaBoardBackendCommon.h>
#include <helpers/ota/OtaBoardEsp32Trial.h>
#include <helpers/ota/OtaV4Receiver.h>
#include <ota/platform/Esp32FlashAdapter.h>
#include <ota/platform/Esp32OtaMetadataAdapter.h>
#include <target.h>

#if !defined(XIAO_S3_OTA_COMPILED_ROLE_ID)
#error "OTA v4 requires an explicitly bound companion/repeater role"
#endif
#if !CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE || !CONFIG_APP_ROLLBACK_ENABLE
#error "ESP OTA requires vendor bootloader and application rollback"
#endif
#if !defined(MESHCORE_ESP32_OTA_STARTUP_NVS_GUARD) || !MESHCORE_ESP32_OTA_STARTUP_NVS_GUARD
#error "ESP OTA requires its startup NVS no-erase guard"
#endif
#if ESP_ARDUINO_VERSION != ESP_ARDUINO_VERSION_VAL(2, 0, 17) || \
    ESP_IDF_VERSION != ESP_IDF_VERSION_VAL(4, 4, 7)
#error "ESP OTA startup hooks require a qualified Arduino/IDF version"
#endif
#if defined(ADMIN_PASSWORD) && !defined(DISABLE_WIFI_OTA) && !defined(MESHCORE_ESP32_OTA_UPDATER_LEASE)
#error "The ordinary updater must participate in the shared OTA lease"
#endif

extern RADIO_CLASS radio;
bool otaBoardApplyRfProfile(float frequency, float bandwidth, uint8_t sf, uint8_t cr) {
  return mesh::ota::applyCheckedOtaRadioProfile(radio, radio_driver, frequency, bandwidth, sf, cr);
}

namespace {
using namespace mesh::ota;
using namespace mesh::ota::v4;
using namespace ::ota::storage;
constexpr uint32_t kImageBytes = kChunkBytes * kMaxChunks;
::ota::storage::Esp32IdfPartitionApi v4Sdk;
bool storageFault = false, resetPending = false, resetWaiting = false;
uint32_t resetAt = 0;
RTC_NOINIT_ATTR Esp32StartupRestartState retainedRestarts;

class EspSignatures final : public ::ota::trust::SignatureVerifier {
public:
  bool verify(const uint8_t* signature, size_t signatureSize, const uint8_t* message,
      size_t messageSize, const uint8_t* key, size_t keySize) const override {
    return signature && signatureSize == 64 && key && keySize == 32 && (message || !messageSize) &&
        Ed25519::verify(signature, key, message, messageSize);
  }
} signatures;

class UpdateOwner final : public Esp32UpdateOwner {
public:
  Esp32UpdateOwnership ownership(const Esp32PartitionIdentity&) const override {
    return held ? Esp32UpdateOwnership::ExclusiveStorage : Esp32UpdateOwnership::OtherUpdater;
  }
  bool held = false, ordinary = false;
} owner;
::ota::platform::Esp32FlashAdapter payloadDevice(v4Sdk, owner);
::ota::platform::FlashRegion payload(payloadDevice, 0, kImageBytes);
::ota::platform::Esp32OtaMetadataAdapter metadataDevice(v4Sdk);
::ota::platform::FlashRegion metadata(metadataDevice, 0, metadataDevice.kBytes);

const esp_partition_t* resolveApp(const Esp32PartitionIdentity& identity) {
  const auto* app = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
      static_cast<esp_partition_subtype_t>(identity.subtype), identity.label);
  return app && app->flash_chip == esp_flash_default_chip && !app->encrypted &&
      app->address == identity.address && app->size == identity.size &&
      app->type == identity.type && app->subtype == identity.subtype ? app : nullptr;
}
bool contextNormal() {
  Esp32ImageState state;
  return readEsp32EarlyRunningState(v4Sdk, state) &&
      (state == Esp32ImageState::Valid || state == Esp32ImageState::Undefined);
}

bool hashApp(const esp_partition_t* app, uint32_t size, uint8_t out[32]) {
  if (!app || !size || size > kImageBytes) return false;
  uint8_t bytes[256];
  ::ota::trust::Sha256 hash;
  for (uint32_t offset = 0; offset < size;) {
    const uint32_t count = size - offset < sizeof(bytes) ? size - offset : sizeof(bytes);
    if (esp_partition_read(app, offset, bytes, count) != ESP_OK) return false;
    hash.update(bytes, count);
    offset += count;
  }
  hash.finish(out);
  return true;
}
bool runningImage(uint32_t& size, uint8_t hash[32]) {
  Esp32PartitionSnapshot context;
  if (v4Sdk.inspect(context) != kEsp32Ok || !Esp32S3PartitionLayout::matches(context)) return false;
  const auto* app = resolveApp(context.running);
  if (!app || app != esp_ota_get_running_partition()) return false;
  const esp_partition_pos_t position = {app->address, kImageBytes};
  esp_image_metadata_t image = {};
  if (esp_image_verify(ESP_IMAGE_VERIFY, &position, &image) != ESP_OK ||
      !image.image_len || image.image_len > kImageBytes) return false;
  size = image.image_len;
  return hashApp(app, size, hash);
}

bool readFloor(uint32_t& counter, uint32_t& size, uint8_t hash[32], bool& bound) {
  counter = size = 0; bound = false; std::memset(hash, 0, 32);
  nvs_handle_t handle;
  const esp_err_t opened = nvs_open("meshota", NVS_READONLY, &handle);
  if (opened == ESP_ERR_NVS_NOT_FOUND) return true;
  if (opened != ESP_OK) return false;
  uint32_t previous = 0;
  const esp_err_t legacy = nvs_get_u32(handle, "floor", &previous);
  uint8_t record[48]; size_t bytes = sizeof(record);
  const esp_err_t loaded = nvs_get_blob(handle, "floor4", record, &bytes);
  nvs_close(handle);
  if (legacy != ESP_OK && legacy != ESP_ERR_NVS_NOT_FOUND) return false;
  if (loaded == ESP_ERR_NVS_NOT_FOUND) { counter = previous; return true; }
  if (loaded != ESP_OK || bytes != sizeof(record) || read32(record) != 0x4D434634 ||
      read32(record + 44) != crc32(record, 44) || read32(record + 4) < previous ||
      !read32(record + 8) || read32(record + 8) > kImageBytes) return false;
  counter = read32(record + 4); size = read32(record + 8);
  std::memcpy(hash, record + 12, 32); bound = true;
  return true;
}
bool saveFloor(uint32_t counter, uint32_t size, const uint8_t hash[32]) {
  uint32_t previous, previousSize; uint8_t previousHash[32]; bool previousBound;
  if (!readFloor(previous, previousSize, previousHash, previousBound) || counter < previous) return false;
  if (counter == previous && previousBound)
    return size == previousSize && !std::memcmp(hash, previousHash, 32);
  uint8_t record[48] = {};
  write32(record, 0x4D434634); write32(record + 4, counter); write32(record + 8, size);
  std::memcpy(record + 12, hash, 32); write32(record + 44, crc32(record, 44));
  nvs_handle_t handle;
  if (nvs_open("meshota", NVS_READWRITE, &handle) != ESP_OK) return false;
  const bool saved = nvs_set_blob(handle, "floor4", record, sizeof(record)) == ESP_OK &&
      nvs_commit(handle) == ESP_OK;
  nvs_close(handle);
  return saved && readFloor(previous, previousSize, previousHash, previousBound) && previousBound &&
      previous == counter && previousSize == size && !std::memcmp(previousHash, hash, 32);
}
Result receiptMatches(const char* key, const Journal& journal, uint32_t address) {
  uint8_t receipt[60]; size_t size = sizeof(receipt); nvs_handle_t handle;
  const esp_err_t opened = nvs_open("meshota", NVS_READONLY, &handle);
  if (opened == ESP_ERR_NVS_NOT_FOUND) return Result::State;
  if (opened != ESP_OK) return Result::Io;
  const esp_err_t loaded = nvs_get_blob(handle, key, receipt, &size);
  nvs_close(handle);
  if (loaded == ESP_ERR_NVS_NOT_FOUND) return Result::State;
  if (loaded != ESP_OK) return Result::Io;
  if (size != sizeof(receipt) || read32(receipt + 56) != crc32(receipt, 56)) return Result::Integrity;
  return !std::memcmp(receipt, journal.packageHash, 32) &&
      !std::memcmp(receipt + 32, journal.transaction, 16) &&
      read32(receipt + 48) == journal.generation && read32(receipt + 52) == address ?
      Result::Ok : Result::State;
}
bool saveReceipt(const char* key, const Journal& journal, uint32_t address) {
  uint8_t receipt[60] = {};
  std::memcpy(receipt, journal.packageHash, 32); std::memcpy(receipt + 32, journal.transaction, 16);
  write32(receipt + 48, journal.generation); write32(receipt + 52, address);
  write32(receipt + 56, crc32(receipt, 56));
  nvs_handle_t handle;
  if (nvs_open("meshota", NVS_READWRITE, &handle) != ESP_OK) return false;
  const bool saved = nvs_set_blob(handle, key, receipt, sizeof(receipt)) == ESP_OK &&
      nvs_commit(handle) == ESP_OK;
  nvs_close(handle);
  return saved && receiptMatches(key, journal, address) == Result::Ok;
}
bool runningReceiptMatches(const Journal& journal) {
  const auto* app = esp_ota_get_running_partition();
  return app && (receiptMatches("select4", journal, app->address) == Result::Ok ||
      receiptMatches("intent4", journal, app->address) == Result::Ok);
}

bool readBootPackage(Journal& journal, uint8_t canonical[59], uint8_t signer[32], uint8_t signature[64]) {
  static uint8_t bytes[kMaxManifestBytes];
  size_t size = 0;
  OtaV4Journal store(metadata);
  if (store.recover(journal, bytes, sizeof(bytes), size) != Result::Ok) return false;
  Manifest manifest;
  if (manifest.parse(bytes, size) != Result::Ok || std::memcmp(manifest.hash(), journal.packageHash, 32) ||
      !signatures.verify(manifest.bootSignature(), 64, manifest.canonical(), 59, manifest.signer(), 32))
    return false;
  if (!runningReceiptMatches(journal)) return false;
  std::memcpy(canonical, manifest.canonical(), 59);
  std::memcpy(signer, manifest.signer(), 32);
  std::memcpy(signature, manifest.bootSignature(), 64);
  return journal.phase == Phase::ActivationPending || journal.phase == Phase::Trial ||
      journal.phase == Phase::Confirmed;
}
bool reconcileFloor() {
  Esp32ImageState state;
  if (!readEsp32EarlyRunningState(v4Sdk, state) || state != Esp32ImageState::Valid) return true;
  Journal journal; uint8_t canonical[59], signer[32], signature[64], hash[32]; uint32_t size;
  if (!readBootPackage(journal, canonical, signer, signature)) return true;
  return runningImage(size, hash) && size == read32(canonical + 9) &&
      !std::memcmp(hash, canonical + 13, 32) && saveFloor(read32(canonical + 45), size, hash);
}

class TrialPlatform final : public Esp32TrialPlatform {
public:
  bool runningState(Esp32ImageState& state) override { return readEsp32EarlyRunningState(v4Sdk, state); }
  bool unknownTopologyHoldAllowed() override { return readEsp32UnknownStartupTopology(v4Sdk); }
  bool armWatchdog(uint32_t remaining) override {
    const uint32_t period = esp_clk_slowclk_cal_get();
    if (!period || !remaining) return false;
    const uint64_t ticks = (uint64_t(remaining) * 1000u << RTC_CLK_CAL_FRACT) / period;
    if (ticks < 16 || ticks > UINT32_MAX) return false;
    watchdog_.inst = WDT_RWDT; watchdog_.rwdt_dev = &RTCCNTL;
    wdt_hal_write_protect_disable(&watchdog_);
    wdt_hal_init(&watchdog_, WDT_RWDT, 0, false);
    wdt_hal_write_protect_disable(&watchdog_);
    wdt_hal_set_flashboot_en(&watchdog_, false);
    wdt_hal_config_stage(&watchdog_, WDT_STAGE0, uint32_t(ticks) & ~15u, WDT_STAGE_ACTION_RESET_SYSTEM);
    wdt_hal_config_stage(&watchdog_, WDT_STAGE1, 0, WDT_STAGE_ACTION_OFF);
    wdt_hal_config_stage(&watchdog_, WDT_STAGE2, 0, WDT_STAGE_ACTION_OFF);
    wdt_hal_config_stage(&watchdog_, WDT_STAGE3, 0, WDT_STAGE_ACTION_OFF);
    wdt_hal_enable(&watchdog_); wdt_hal_write_protect_enable(&watchdog_);
    armed_ = wdt_hal_is_enabled(&watchdog_);
    return armed_;
  }
  void disarmWatchdog() override {
    if (!armed_) return;
    wdt_hal_write_protect_disable(&watchdog_); wdt_hal_disable(&watchdog_);
    wdt_hal_write_protect_enable(&watchdog_); armed_ = false;
  }
  Esp32TrialConfirmation confirmHealthy() override {
    Journal journal; uint8_t canonical[59], signer[32], signature[64], actual[32]; uint32_t size;
    if (!readBootPackage(journal, canonical, signer, signature) || !runningImage(size, actual) ||
        size != read32(canonical + 9) || std::memcmp(actual, canonical + 13, 32))
      return Esp32TrialConfirmation::Unconfirmed;
    if (esp_ota_mark_app_valid_cancel_rollback() != ESP_OK) return Esp32TrialConfirmation::Unconfirmed;
    if (!saveFloor(read32(canonical + 45), size, actual)) {
      storageFault = true;
      return Esp32TrialConfirmation::ValidNeedsFloorReconciliation;
    }
    return Esp32TrialConfirmation::Confirmed;
  }
  void reportUnknownService() override {
    ESP_LOGE("meshota", "Unknown startup topology: OTA and destructive writes disabled");
  }
  void restartWithoutRollback() override { esp_restart(); }
  void rollbackAndRestart() override {
    Esp32ImageState state;
    if (runningState(state) && state == Esp32ImageState::PendingVerify)
      esp_ota_mark_app_invalid_rollback_and_reboot();
    esp_restart();
  }
private:
  wdt_hal_context_t watchdog_ = {};
  bool armed_ = false;
} trialPlatform;
Esp32TrialController trial(trialPlatform, &retainedRestarts);

bool espEntropy(uint8_t* out, size_t size) {
  if (!out || !size || size > 64) return false;
  wifi_mode_t mode = WIFI_MODE_NULL;
  if (esp_wifi_get_mode(&mode) != ESP_ERR_WIFI_NOT_INIT) return false;
  const auto bt = esp_bt_controller_get_status();
  if (bt == ESP_BT_CONTROLLER_STATUS_ENABLED) { esp_fill_random(out, size); return true; }
  if (bt != ESP_BT_CONTROLLER_STATUS_IDLE) return false;
  bootloader_random_enable();
  esp_rom_delay_us(200);
  for (size_t i = 0; i < size; i += 4) {
    esp_rom_delay_us(128);
    const uint32_t word = esp_random();
    std::memcpy(out + i, &word, size - i < 4 ? size - i : 4);
  }
  bootloader_random_disable();
  return true;
}
Policy espPolicy() {
  Policy policy;
  policy.boardFamily = 0x4553; policy.boardVariant = 0x5333;
  policy.role = XIAO_S3_OTA_COMPILED_ROLE_ID;
  policy.appAddress = 0x10000; policy.maxImageBytes = kImageBytes; policy.bootloaderCapabilities = 1;
  return policy;
}
class EspFirmwarePlatform final : public FirmwarePlatform {
public:
  EspFirmwarePlatform() : FirmwarePlatform(espPolicy(), payload, metadata, signatures) {}
  Result random(uint8_t* out, size_t size) override { return espEntropy(out, size) ? Result::Ok : Result::Io; }
  Result beginStaging(uint32_t size) override {
    if (mutationAllowed() != Result::Ok || !::ota::platform::isOk(payloadDevice.bind(kImageBytes)))
      return Result::Busy;
    if (!saveReceipt("stage4", latest_, payloadDevice.partition().address)) return Result::Io;
    stagingBound_ = true;
    return FirmwarePlatform::beginStaging(size);
  }
  Result writeStaging(uint32_t offset, const uint8_t* data, size_t size) override {
    if (!stagingBound_) {
      if (mutationAllowed() != Result::Ok || offset != 0) return Result::Busy;
      if (!saveReceipt("stage4", latest_, payloadDevice.partition().address)) {
        storageFault = true;
        return Result::Io;
      }
      stagingBound_ = true;
    }
    return FirmwarePlatform::writeStaging(offset, data, size);
  }
  Result save(const Journal& journal, const uint8_t* bytes, size_t size) override {
    if (owner.ordinary || !owner.held) return Result::Busy;
    return FirmwarePlatform::save(journal, bytes, size);
  }
  Result repair(const Journal& idle) override {
    const Result repaired = FirmwarePlatform::repair(idle);
    if (repaired != Result::Ok) return repaired;
    nvs_handle_t handle;
    if (nvs_open("meshota", NVS_READWRITE, &handle) != ESP_OK) return Result::Io;
    bool erased = true;
    const char* const keys[] = {"stage4", "intent4", "select4"};
    for (const auto* key : keys) {
      const esp_err_t result = nvs_erase_key(handle, key);
      erased = erased && (result == ESP_OK || result == ESP_ERR_NVS_NOT_FOUND);
    }
    erased = erased && nvs_commit(handle) == ESP_OK;
    nvs_close(handle);
    stagingBound_ = false;
    if (!erased) { storageFault = true; return Result::Io; }
    uint32_t floor, size; uint8_t hash[32]; bool bound;
    storageFault = !readFloor(floor, size, hash, bound);
    return storageFault ? Result::Io : Result::Ok;
  }
  bool ordinaryAllowed() const {
    return !resetPending && !storageFaultObserved() && (!haveCandidate_ ||
        latest_.phase == Phase::Confirmed || latest_.phase == Phase::Failed ||
        latest_.phase == Phase::Aborted || latest_.phase == Phase::Idle);
  }
  Result evidence(RunningEvidence& out) override {
    out = RunningEvidence();
    if (!reconcileFloor()) { storageFault = true; return Result::Io; }
    uint32_t floorSize; uint8_t floorHash[32]; bool floorBound;
    if (!readFloor(out.floor, floorSize, floorHash, floorBound)) { storageFault = true; return Result::Io; }
    out.flags = FloorKnown;
    uint32_t size;
    if (runningImage(size, out.hash)) {
      out.flags |= RunningHashKnown;
      Esp32ImageState state;
      if (readEsp32EarlyRunningState(v4Sdk, state) && state == Esp32ImageState::Valid &&
          floorBound && floorSize == size && !std::memcmp(out.hash, floorHash, 32) &&
          (!haveCandidate_ || runningReceiptMatches(latest_)))
        out.flags |= RunningConfirmed;
    }
    return Result::Ok;
  }
  Result validateInstall(const uint8_t canonical[59], const uint8_t signature[64],
                          const uint8_t signer[32]) override {
    if (resetPending && haveCandidate_ && canonical && signature && signer &&
        !std::memcmp(canonical, canonical_, 59) && !std::memcmp(signer, signer_, 32) &&
        isCurrentAdmin(signer) && verify(signer, nullptr, 0, canonical, 59, signature))
      return Result::Ok;
    if (mutationAllowed() != Result::Ok) return Result::Busy;
    const Result valid = verifyRawImage(canonical, signature, signer);
    if (valid != Result::Ok) return valid;
    const auto* app = resolveApp(payloadDevice.partition());
    if (!app || app == esp_ota_get_running_partition() || app == esp_ota_get_boot_partition())
      return Result::Denied;
    const esp_partition_pos_t position = {app->address, kImageBytes};
    esp_image_metadata_t image = {};
    return esp_image_verify(ESP_IMAGE_VERIFY, &position, &image) == ESP_OK &&
        image.image_len == read32(canonical + 9) ? Result::Ok : Result::Integrity;
  }
  Result activate(const uint8_t canonical[59], const uint8_t signature[64], const uint8_t signer[32],
                  const uint8_t transaction[16], uint32_t generation) override {
    if (!canonical || !signature || !signer || !transaction || !generation) return Result::Invalid;
    if (!haveCandidate_ || generation != latest_.generation ||
        std::memcmp(transaction, latest_.transaction, 16) || std::memcmp(canonical, canonical_, 59) ||
        std::memcmp(signer, signer_, 32) || !isCurrentAdmin(signer)) return Result::Denied;
    if (resetPending) return Result::Ok;
    const Result checked = validateInstall(canonical, signature, signer);
    if (checked != Result::Ok) return checked;
    const auto* app = resolveApp(payloadDevice.partition());
    if (!app) return Result::Denied;
    resetPending = true;
    // Bind the trial before SDK selection; its completion receipt may be torn.
    if (!saveReceipt("intent4", latest_, app->address)) return Result::Io;
    const esp_err_t selected = esp_ota_set_boot_partition(app);
    esp_ota_img_states_t state;
    if (selected != ESP_OK || esp_ota_get_boot_partition() != app ||
        esp_ota_get_state_partition(app, &state) != ESP_OK || state != ESP_OTA_IMG_NEW)
      return Result::Io;
    return saveReceipt("select4", latest_, app->address) ? Result::Ok : Result::Io;
  }
  Result lifecycle(Phase& phase) override {
    if (!haveCandidate_) return Result::State;
    Esp32ImageState state;
    if (!readEsp32EarlyRunningState(v4Sdk, state)) return Result::State;
    uint32_t bytes; uint8_t hash[32];
    if (!runningImage(bytes, hash)) return Result::Io;
    const bool matches = bytes == read32(canonical_ + 9) && !std::memcmp(hash, canonical_ + 13, 32);
    const bool bound = matches && runningReceiptMatches(latest_);
    if (state == Esp32ImageState::PendingVerify && bound) { phase = Phase::Trial; return Result::Ok; }
    if (state == Esp32ImageState::Valid && bound) {
      RunningEvidence running;
      if (evidence(running) == Result::Ok && (running.flags & RunningConfirmed) &&
          running.floor >= read32(canonical_ + 45)) { phase = Phase::Confirmed; return Result::Ok; }
    }
    // Rollback is transaction/slot evidence, not a difference in image bytes:
    // a higher-counter package may legitimately contain the same firmware.
    if (!bound && contextNormal()) {
      Esp32PartitionSnapshot context;
      if (v4Sdk.inspect(context) != kEsp32Ok || !Esp32S3PartitionLayout::matches(context)) return Result::Io;
      const auto inactive = context.appStates[context.next.subtype - 0x10];
      if (inactive != Esp32ImageState::Aborted && inactive != Esp32ImageState::Invalid) return Result::State;
      if (receiptMatches("select4", latest_, context.next.address) == Result::Ok) {
        phase = Phase::Failed;
        return Result::Ok;
      }
    }
    return Result::State;
  }
protected:
  Result prepareRecoveredStaging(uint32_t rawSize) override {
    stagingBound_ = false;
    if (latest_.phase == Phase::Aborted || latest_.phase == Phase::Confirmed ||
        latest_.phase == Phase::Failed) { staging_.invalidate(); return Result::Ok; }
    Phase boot;
    if (lifecycle(boot) == Result::Ok) { staging_.invalidate(); return Result::Ok; }
    if (!contextNormal()) { staging_.invalidate(); return Result::Ok; }
    if (!::ota::platform::isOk(payloadDevice.bind(kImageBytes))) return Result::Io;
    // A closed SDK state with uncertain publication must not re-arm a failed
    // trial from a replayed Activate. Fresh signed staging repair revokes it.
    if (latest_.phase == Phase::ActivationPending || latest_.phase == Phase::Trial) {
      const Result intent = receiptMatches("intent4", latest_, payloadDevice.partition().address);
      const Result selected = receiptMatches("select4", latest_, payloadDevice.partition().address);
      if (intent == Result::Io || selected == Result::Io) return Result::Io;
      if (intent == Result::Integrity || selected == Result::Integrity ||
          (intent == Result::Ok && selected != Result::Ok)) return Result::Integrity;
    }
    const Result receipt = receiptMatches("stage4", latest_, payloadDevice.partition().address);
    if (latest_.nextChunk && latest_.phase != Phase::Confirmed && latest_.phase != Phase::Failed &&
        latest_.phase != Phase::Trial && receipt != Result::Ok)
      return receipt == Result::Io ? receipt : Result::Integrity;
    stagingBound_ = receipt == Result::Ok;
    return staging_.begin(rawSize);
  }
  Result mutationAllowed() override {
    return owner.held && !owner.ordinary && !resetPending && !trial.activeOrUnknown() &&
        contextNormal() ? Result::Ok : Result::Busy;
  }
private:
  bool stagingBound_ = false;
} platform;

void earlyTrial() { trial.begin(millis()); }
}

extern "C" bool verifyRollbackLater() { earlyTrial(); return true; }
bool otaBoardEarlyBootTrialOrUnknown() { earlyTrial(); return trial.activeOrUnknown(); }
bool otaBoardEarlyBootNormalProven() { return !otaBoardEarlyBootTrialOrUnknown(); }
bool otaBoardTrialHealthWindowActive() { return trial.activeOrUnknown(); }
bool otaBoardUnknownStartupRecoveryHeld() { return trial.unknownServiceHeld(); }
bool otaBoardStorageIoFaultObserved() { return storageFault || platform.storageFaultObserved(); }
const char* otaBoardInstallCapabilityStatus() {
  return trial.activeOrUnknown() ? "STAGING_ONLY: trial or unknown" : "INSTALL_CAPABLE: OTA v4 ESP-IDF rollback";
}
bool otaBoardClaimOrdinaryFirmwareUpdate() {
  earlyTrial();
  if (trial.activeOrUnknown() || owner.ordinary || !platform.ordinaryAllowed()) return false;
  owner.held = false;
  owner.ordinary = true;
  payloadDevice.unbind();
  return true;
}
void otaBoardReleaseOrdinaryFirmwareUpdate() {
  owner.ordinary = false;
  owner.held = contextNormal();
  if (owner.held && !::ota::platform::isOk(payloadDevice.bind(kImageBytes))) {
    owner.held = false;
    storageFault = true;
  }
}
mesh::ota::v4::Receiver* otaBoardConfigureV4Backend(const mesh::ota::v4::RuntimeHooks& hooks) {
  earlyTrial();
  if (owner.ordinary) return nullptr;
  owner.held = true;
  platform.attach(hooks);
  if (!trial.activeOrUnknown() && !::ota::platform::isOk(payloadDevice.bind(kImageBytes))) {
    storageFault = true;
    return nullptr;
  }
  static mesh::ota::v4::Receiver receiver(platform);
  return &receiver;
}
mesh::ota::OtaBoardTrialHealthOutcome otaBoardTryConfirmHealthyTrialBoot(
    uint32_t now, bool radioReady, bool filesystemReady, bool loopHealthy) {
  if (resetPending) {
    if (!resetWaiting) { resetWaiting = true; resetAt = now; }
    if (uint32_t(now - resetAt) >= 500) esp_restart();
  }
  switch (trial.tick(now, radioReady, filesystemReady && !otaBoardStorageIoFaultObserved(), loopHealthy)) {
    case Esp32TrialHealthOutcome::Confirmed: return OtaBoardTrialHealthOutcome::Confirmed;
    case Esp32TrialHealthOutcome::DeadlineExpired: return OtaBoardTrialHealthOutcome::DeadlineExpired;
    case Esp32TrialHealthOutcome::StateUnreadable: return OtaBoardTrialHealthOutcome::StateUnreadable;
    case Esp32TrialHealthOutcome::ConfirmationUncertain: return OtaBoardTrialHealthOutcome::ConfirmationUncertain;
    default: return OtaBoardTrialHealthOutcome::Pending;
  }
}

extern "C" esp_err_t __real_nvs_flash_init();
extern "C" esp_err_t __wrap_nvs_flash_init() {
  const esp_err_t result = __real_nvs_flash_init();
  if (result != ESP_OK) storageFault = true;
  return mesh::ota::esp32NvsStartupInitResult(result);
}
#endif
