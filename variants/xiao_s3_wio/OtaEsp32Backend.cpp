#if defined(ESP32_PLATFORM) && defined(MESHCORE_LORA_OTA) && MESHCORE_LORA_OTA

#include <Arduino.h>
#include <Ed25519.h>
#include <esp_flash.h>
#include <esp_image_format.h>
#include <esp_ota_ops.h>
#include <esp_attr.h>
#include <esp_random.h>
#include <bootloader_random.h>
#include <esp_bt.h>
#include <esp_rom_sys.h>
#include <esp_wifi.h>
#include <cstring>
#include <esp_partition.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <esp_log.h>
#include <esp_arduino_version.h>
#include <esp_idf_version.h>
#include <esp_private/esp_clk.h>
#include <hal/wdt_hal.h>
#include <soc/rtc.h>
#include <helpers/ota/OtaBoardBackendCommon.h>
#include <helpers/ota/OtaEsp32RollbackGuard.h>
#include <helpers/ota/OtaFirmwareIntegration.h>
#include <target.h>

#if !defined(XIAO_S3_OTA_COMPILED_ROLE_ID)
#error "ESP LoRa OTA requires an explicitly bound companion/repeater role"
#endif
#if !CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE || !CONFIG_APP_ROLLBACK_ENABLE
#error "ESP LoRa OTA requires vendor bootloader and app rollback support"
#endif
#if !defined(MESHCORE_ESP32_OTA_STARTUP_NVS_GUARD) || !MESHCORE_ESP32_OTA_STARTUP_NVS_GUARD
#error "ESP LoRa OTA requires the build-local nvs_flash_init startup wrapper"
#endif
#if ESP_ARDUINO_VERSION != ESP_ARDUINO_VERSION_VAL(2, 0, 17) || \
    ESP_IDF_VERSION != ESP_IDF_VERSION_VAL(4, 4, 7)
#error "ESP LoRa OTA startup interception must be qualified for this Arduino/IDF version"
#endif
#if defined(ADMIN_PASSWORD) && !defined(DISABLE_WIFI_OTA) && !defined(MESHCORE_ESP32_OTA_UPDATER_LEASE)
#error "ESP LoRa OTA must exclude the ordinary updater or wire its shared lease before server startup"
#endif

extern RADIO_CLASS radio;

bool otaBoardApplyRfProfile(float frequency, float bandwidth, uint8_t sf, uint8_t cr) {
  return mesh::ota::applyCheckedOtaRadioProfile(radio, radio_driver, frequency, bandwidth, sf, cr);
}

namespace {

// BEGIN nonce entropy. IDF 4.4 esp_random() is only a true RNG while WiFi/BT
// RF runs or the SAR ADC entropy source is enabled; these OTA builds keep RF
// off, so without this the post-cold-boot nonce would rest on unspecified
// pseudo-random state. Guarantee, with no pseudo-random fallback:
//  - WiFi not initialised (esp_wifi_get_mode: NOT_INIT) and BT controller
//    IDLE, as in the USB OTA images: enable the documented SAR ADC/8 MHz
//    source (bootloader_random_enable), wait 128 us before every 32-bit word
//    (8x the IDF bootloader's 1 bit per 40 APB cycles at 80 MHz), then
//    disable it again within this same synchronous loop-task call (~1.3 ms
//    for the 32-byte BEGIN draw). Disable restores the
//    bootloader hand-off state (ADC1 back on RTC control, SAR power off,
//    APB SARADC gated), which Arduino's per-read ADC/tsens setup expects.
//    The SX1262 is on SPI and is untouched.
//  - BT controller enabled: RF is on, so esp_fill_random() is the
//    documented true RNG; the ADC source must not be enabled with RF on.
//  - WiFi initialised or BT controller in a transitional state: indeterminate,
//    so return false and BEGIN reports Unavailable.

bool otaEspEntropy(void*, uint8_t* out, size_t len) {
  static constexpr size_t kMaxEntropyBytes = 64;
  static constexpr uint32_t kSourceWarmupUs = 200;
  static constexpr uint32_t kWordRefillUs = 128;
  if (out == nullptr || len == 0 || len > kMaxEntropyBytes) return false;
  wifi_mode_t mode = WIFI_MODE_NULL;
  if (esp_wifi_get_mode(&mode) != ESP_ERR_WIFI_NOT_INIT) return false;
  const auto bt = esp_bt_controller_get_status();
  if (bt == ESP_BT_CONTROLLER_STATUS_ENABLED) {
    esp_fill_random(out, len);
    return true;
  }
  if (bt != ESP_BT_CONTROLLER_STATUS_IDLE) return false;
  bootloader_random_enable();
  esp_rom_delay_us(kSourceWarmupUs);
  for (size_t i = 0; i < len; i += 4) {
    esp_rom_delay_us(kWordRefillUs);
    const uint32_t word = esp_random();
    const size_t n = len - i < 4 ? len - i : 4;
    std::memcpy(out + i, &word, n);
  }
  bootloader_random_disable();
  return true;
}

using namespace mesh::ota;
using ::ota::storage::Esp32ImageState;
using ::ota::storage::OtaCandidateStore;
constexpr uint8_t kRole = XIAO_S3_OTA_COMPILED_ROLE_ID;
static_assert(kRole <= 1, "unsupported ESP LoRa OTA role");

class OwnerSignatureVerifier final : public ::ota::trust::SignatureVerifier {
public:
  bool verify(const uint8_t* signature, size_t signature_len, const uint8_t* message,
              size_t message_len, const uint8_t* public_key, size_t public_key_len) const override {
    return signature != nullptr && signature_len == 64 && message != nullptr &&
           public_key != nullptr && public_key_len == 32 &&
           Ed25519::verify(signature, public_key, message, message_len);
  }
};

const esp_partition_t* resolveApp(const ::ota::storage::Esp32PartitionIdentity& p) {
  const auto* app = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
      static_cast<esp_partition_subtype_t>(p.subtype), p.label);
  if (app == nullptr || app->flash_chip != esp_flash_default_chip ||
      app->address != p.address || app->size != p.size || app->encrypted ||
      app->type != p.type || app->subtype != p.subtype) return nullptr;
  return app;
}

class VendorInstallApi final : public Esp32OtaInstallApi {
public:
  bool validateImage(const ::ota::storage::Esp32PartitionIdentity& p, uint32_t exact_bytes) override {
    const auto* app = resolveApp(p);
    if (app == nullptr || app == esp_ota_get_running_partition() ||
        app == esp_ota_get_boot_partition()) return false;
    const esp_partition_pos_t pos = {app->address, Esp32OtaPolicy::kCandidateBytes};
    esp_image_metadata_t image = {};
    // IDF verifies headers/segments, target chip/revision, checksum and the
    // appended image digest (and secure-boot signature when configured).
    return esp_image_verify(ESP_IMAGE_VERIFY, &pos, &image) == ESP_OK &&
           image.image_len == exact_bytes;
  }
  bool selectBoot(const ::ota::storage::Esp32PartitionIdentity& p) override {
    const auto* app = resolveApp(p);
    if (app == nullptr || app == esp_ota_get_running_partition() ||
        app == esp_ota_get_boot_partition()) return false;
    if (esp_ota_set_boot_partition(app) != ESP_OK) return false;
    esp_ota_img_states_t state;
    return esp_ota_get_boot_partition() == app &&
           esp_ota_get_state_partition(app, &state) == ESP_OK && state == ESP_OTA_IMG_NEW;
  }
  Esp32RunningProof runningProof(uint32_t& counter) override;
  bool readConfirmedFloor(uint32_t& counter, bool& found) override;
  bool saveConfirmedFloor(uint32_t counter) override;
};

// Read-only proof from the RUNNING slot, including its candidate provenance.
// Esp32FlashAdapter itself remains strictly incapable of writing active apps.
class ReadOnlyAppReader final : public ::ota::platform::FlashDevice {
public:
  explicit ReadOnlyAppReader(bool running = true) : running_(running) {}
  uint32_t totalSizeBytes() const override { return Esp32OtaPolicy::kSlotBytes; }
  uint32_t eraseUnitBytes() const override { return 4096; }
  uint32_t programUnitBytes() const override { return 1; }
  ::ota::platform::FlashStatus read(uint32_t offset, uint8_t* data, uint32_t len) const override {
    const auto* app = running_ ? esp_ota_get_running_partition() : esp_ota_get_next_update_partition(nullptr);
    if (app == nullptr || app->flash_chip != esp_flash_default_chip || app->encrypted ||
        app->size != totalSizeBytes() ||
        (app->address != 0x10000 && app->address != 0x340000) ||
        offset > app->size || len > app->size - offset || (data == nullptr && len != 0))
      return ::ota::platform::FlashStatus::OutOfRange;
    const auto expected = ::ota::storage::Esp32S3PartitionLayout::entry(app->address == 0x10000 ? 2 : 3);
    if (resolveApp(expected) != app) return ::ota::platform::FlashStatus::InvalidArgument;
    return esp_partition_read(app, offset, data, len) == ESP_OK
        ? ::ota::platform::FlashStatus::Ok : ::ota::platform::FlashStatus::IoError;
  }
  ::ota::platform::FlashStatus program(uint32_t, const uint8_t*, uint32_t) override {
    return ::ota::platform::FlashStatus::Unsupported;
  }
  ::ota::platform::FlashStatus eraseSector(uint32_t) override {
    return ::ota::platform::FlashStatus::Unsupported;
  }
private:
  bool running_;
};

OwnerSignatureVerifier signatures;
Esp32OtaLease lease;
Esp32OtaPolicy policy{kRole};
::ota::platform::Esp32FlashAdapter flash(lease);
::ota::platform::FlashRegion candidate(flash, 0, Esp32OtaPolicy::kCandidateBytes);
::ota::platform::FlashRegion metadata(flash, Esp32OtaPolicy::kCandidateBytes, 8192);
OtaCandidateStore store(metadata);
Esp32OtaTrustProvider trust(policy, candidate);
VendorInstallApi vendor_install;
Esp32OtaStagingSink sink(flash, lease, candidate, metadata, store, trust, policy, signatures, vendor_install);
OtaFirmwareIntegration* integration = nullptr;
const char* capability = "OTA_DISABLED: not configured";
bool storage_fault = false;
bool commit_waiting = false;
uint32_t commit_observed_ms = 0;
// Image-check fallback can leave boot != running across every warm reset.
RTC_NOINIT_ATTR Esp32StartupRestartState startup_restarts;

bool readFloor(uint32_t& out, bool* found = nullptr) {
  out = 0;
  if (found != nullptr) *found = false;
  nvs_handle_t handle;
  esp_err_t err = nvs_open("meshota", NVS_READONLY, &handle);
  if (err == ESP_ERR_NVS_NOT_FOUND) return true;
  if (err != ESP_OK) return false;
  err = nvs_get_u32(handle, "floor", &out);
  nvs_close(handle);
  if (found != nullptr) *found = err == ESP_OK;
  return err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND;
}

Esp32RunningProof VendorInstallApi::runningProof(uint32_t& counter) {
  ReadOnlyAppReader reader;
  ::ota::storage::Esp32IdfPartitionApi sdk;
  return readEsp32RunningProof(sdk, reader, policy, signatures, counter);
}

bool VendorInstallApi::readConfirmedFloor(uint32_t& counter, bool& found) {
  return readFloor(counter, &found);
}

bool saveFloor(uint32_t counter) {
  uint32_t floor;
  if (!readFloor(floor)) return false;
  if (counter <= floor) return true;
  nvs_handle_t handle;
  if (nvs_open("meshota", NVS_READWRITE, &handle) != ESP_OK) return false;
  const bool ok = nvs_set_u32(handle, "floor", counter) == ESP_OK && nvs_commit(handle) == ESP_OK;
  nvs_close(handle);
  return ok && readFloor(floor) && floor >= counter;
}

bool VendorInstallApi::saveConfirmedFloor(uint32_t counter) { return saveFloor(counter); }

bool runningCandidateCounter(uint32_t& counter, bool& have_candidate) {
  have_candidate = false;
  ReadOnlyAppReader reader;
  ::ota::platform::FlashRegion running_metadata(reader, Esp32OtaPolicy::kCandidateBytes, 8192);
  OtaCandidateStore running_store(running_metadata);
  ::ota::platform::FlashRegion running_image(reader, 0, Esp32OtaPolicy::kCandidateBytes);
  OtaCandidateStore::Snapshot s;
  meshcore::ota::protocol::OtaDescriptor d;
  if (!verifyEsp32RunningCandidate(running_store, running_image, policy, signatures, s, d)) {
    if (s.valid) return false;
    // Stock/ordinary firmware has no lean provenance. An unreadable region
    // is NOT silently treated as a stock baseline.
    uint8_t first[4];
    return ::ota::platform::isOk(running_metadata.read(0, first, sizeof(first))) &&
           first[0] == 0xff && first[1] == 0xff && first[2] == 0xff && first[3] == 0xff;
  }
  counter = d.securityCounter;
  have_candidate = true;
  return true;
}

class VendorTrialPlatform final : public Esp32TrialPlatform {
public:
  bool runningState(Esp32ImageState& out) override {
    ::ota::storage::Esp32IdfPartitionApi sdk;
    return readEsp32EarlyRunningState(sdk, out);
  }
  bool unknownTopologyHoldAllowed() override {
    ::ota::storage::Esp32IdfPartitionApi sdk;
    return readEsp32UnknownStartupTopology(sdk);
  }
  bool armWatchdog(uint32_t remaining_ms) override {
    // The pinned IDF4.4 S3 SDK's legacy soc/rtc_wdt.h is ESP32-only.
    // Use its actual S3 HAL, including LL's stage-0 timeout scaling.
    const uint32_t period = esp_clk_slowclk_cal_get();
    if (period == 0 || remaining_ms == 0) return false;
    const uint64_t ticks = (static_cast<uint64_t>(remaining_ms) * 1000u << RTC_CLK_CAL_FRACT) / period;
    if (ticks < 16 || ticks > UINT32_MAX) return false;
    watchdog_.inst = WDT_RWDT;
    watchdog_.rwdt_dev = &RTCCNTL;
    wdt_hal_write_protect_disable(&watchdog_);
    wdt_hal_init(&watchdog_, WDT_RWDT, 0, false);
    wdt_hal_write_protect_disable(&watchdog_);
    wdt_hal_set_flashboot_en(&watchdog_, false);
    wdt_hal_config_stage(&watchdog_, WDT_STAGE0, static_cast<uint32_t>(ticks) & ~15u,
                         WDT_STAGE_ACTION_RESET_SYSTEM);
    wdt_hal_config_stage(&watchdog_, WDT_STAGE1, 0, WDT_STAGE_ACTION_OFF);
    wdt_hal_config_stage(&watchdog_, WDT_STAGE2, 0, WDT_STAGE_ACTION_OFF);
    wdt_hal_config_stage(&watchdog_, WDT_STAGE3, 0, WDT_STAGE_ACTION_OFF);
    wdt_hal_enable(&watchdog_);
    wdt_hal_write_protect_enable(&watchdog_);
    armed_ = wdt_hal_is_enabled(&watchdog_);
    return armed_;
  }
  void disarmWatchdog() override {
    if (!armed_) return;
    wdt_hal_write_protect_disable(&watchdog_);
    wdt_hal_disable(&watchdog_);
    wdt_hal_write_protect_enable(&watchdog_);
    armed_ = false;
  }
  Esp32TrialConfirmation confirmHealthy() override {
    // Never advance the numeric floor during a failed trial. If reset cuts
    // the valid->floor window, next startup reconciles the signed RUNNING
    // candidate before permitting another transfer.
    return confirmEsp32TrialImage(
        [](uint32_t& counter, bool& have_candidate) {
          const bool ok = runningCandidateCounter(counter, have_candidate);
          if (!ok) storage_fault = true;
          return ok;
        },
        []() { return esp_ota_mark_app_valid_cancel_rollback() == ESP_OK; },
        [](uint32_t counter) {
          const bool ok = saveFloor(counter);
          if (!ok) storage_fault = true;
          return ok;
        });
  }
  void restartWithoutRollback() override { esp_restart(); }
  void reportUnknownService() override {
    ESP_LOGE("meshota", "ESP startup context unknown; restart attempts=%u; OTA and destructive writes disabled",
             static_cast<unsigned>(startup_restarts.attempts));
  }
  void rollbackAndRestart() override {
    // An uncertain VALID publication must reconcile forward; a different
    // selected app must never be invalidated on behalf of this running app.
    Esp32ImageState state;
    if (runningState(state) && state == Esp32ImageState::PendingVerify)
      esp_ota_mark_app_invalid_rollback_and_reboot();
    esp_restart();
  }
private:
  wdt_hal_context_t watchdog_ = {};
  bool armed_ = false;
};

VendorTrialPlatform trial_platform;
Esp32TrialController trial(trial_platform, &startup_restarts);

void earlyTrialGuard() {
  trial.begin(static_cast<uint32_t>(millis()));
}

}  // namespace

static_assert(ESP_ERR_NVS_NO_FREE_PAGES == mesh::ota::kEsp32NvsNoFreePages, "NVS error ABI changed");
static_assert(ESP_ERR_NVS_NEW_VERSION_FOUND == mesh::ota::kEsp32NvsNewVersionFound, "NVS error ABI changed");
static_assert(ESP_ERR_INVALID_STATE == mesh::ota::kEsp32InvalidState, "NVS error ABI changed");

// This strong symbol must appear as T (not W) in BOTH linked firmware ELFs.
extern "C" bool verifyRollbackLater() {
  earlyTrialGuard();
  return true;
}

bool otaBoardEarlyBootTrialOrUnknown() {
  earlyTrialGuard();
  return trial.activeOrUnknown();
}

// Positive Normal proof for provisioning/format decisions: every false
// return of otaBoardEarlyBootTrialOrUnknown() is a positive proof path;
// IO, layout, identity and unknown-state paths all answer false here.
bool otaBoardEarlyBootNormalProven() { return !otaBoardEarlyBootTrialOrUnknown(); }

bool otaBoardTrialHealthWindowActive() { return trial.activeOrUnknown(); }
bool otaBoardUnknownStartupRecoveryHeld() { return trial.unknownServiceHeld(); }
bool otaBoardStorageIoFaultObserved() { return storage_fault || sink.storageIoFaultObserved(); }
const char* otaBoardInstallCapabilityStatus() { return capability; }

bool otaBoardGetBootLifecycle(mesh::ota::OtaBootLifecycleEvidence& out) {
  out = OtaBootLifecycleEvidence();
  Esp32ImageState state;
  if (!trial_platform.runningState(state)) return false;
  uint32_t floor = 0;
  bool floor_known = false;
  if (!readFloor(floor, &floor_known)) {
    storage_fault = true;
    floor_known = false;
  }
  ReadOnlyAppReader running;
  Esp32OtaIoGuard checked_running(running);
  ::ota::platform::FlashRegion running_image(checked_running, 0, Esp32OtaPolicy::kCandidateBytes);
  ::ota::platform::FlashRegion running_metadata(checked_running, Esp32OtaPolicy::kCandidateBytes, 8192);
  OtaCandidateStore running_store(running_metadata);
  if (!readEsp32BootLifecycle(state, running_store, running_image, running_metadata, policy, signatures,
                             floor_known, floor, out) || checked_running.failed()) {
    if (checked_running.failed()) storage_fault = true;
    out = OtaBootLifecycleEvidence();
    return false;
  }
  Esp32ImageState latest;
  if (!trial_platform.runningState(latest) || latest != state) {
    out = OtaBootLifecycleEvidence();
    return false;
  }
  const auto* next = esp_ota_get_next_update_partition(nullptr);
  if (next == nullptr || next == esp_ota_get_running_partition()) {
    out = OtaBootLifecycleEvidence();
    return false;
  }
  esp_ota_img_states_t next_state;
  const auto next_result = esp_ota_get_state_partition(next, &next_state);
  if (next_result != ESP_OK && next_result != ESP_ERR_NOT_FOUND) {
    storage_fault = true;
    out = OtaBootLifecycleEvidence();
    return false;
  }
  if ((state == Esp32ImageState::Valid || state == Esp32ImageState::Undefined) && next_result == ESP_OK &&
      (next_state == ESP_OTA_IMG_ABORTED || next_state == ESP_OTA_IMG_INVALID)) {
    ::ota::storage::Esp32IdfPartitionApi sdk;
    ::ota::storage::Esp32PartitionSnapshot context;
    if (sdk.inspect(context) != ::ota::storage::kEsp32Ok) {
      storage_fault = true;
      out = OtaBootLifecycleEvidence();
      return false;
    }
    if (!esp32ClosedFailedSelectionContext(context) || resolveApp(context.next) != next) {
      out = OtaBootLifecycleEvidence();
      return false;
    }
    ReadOnlyAppReader failed(false);
    Esp32OtaIoGuard checked_failed(failed);
    ::ota::platform::FlashRegion failed_image(checked_failed, 0, Esp32OtaPolicy::kCandidateBytes);
    ::ota::platform::FlashRegion failed_metadata(checked_failed, Esp32OtaPolicy::kCandidateBytes, 8192);
    OtaCandidateStore failed_store(failed_metadata);
    OtaBootLifecycleEvidence failure;
    const bool verified = readEsp32BootLifecycle(static_cast<Esp32ImageState>(next_state), failed_store,
        failed_image, failed_metadata, policy, signatures, floor_known, floor, failure, true, &context);
    if (checked_failed.failed()) {
      storage_fault = true;
      out = OtaBootLifecycleEvidence();
      return false;
    }
    if (verified && failure.transactionNonce != 0) {
      ::ota::storage::Esp32PartitionSnapshot after;
      if (sdk.inspect(after) != ::ota::storage::kEsp32Ok) {
        storage_fault = true;
        out = OtaBootLifecycleEvidence();
        return false;
      }
      if (!esp32SameClosedFailedSelectionContext(context, after)) {
        out = OtaBootLifecycleEvidence();
        return false;
      }
      esp_ota_img_states_t latest_state;
      const auto latest_result = esp_ota_get_state_partition(next, &latest_state);
      if (latest_result != ESP_OK || latest_state != next_state ||
          next != esp_ota_get_next_update_partition(nullptr)) {
        if (latest_result != ESP_OK && latest_result != ESP_ERR_NOT_FOUND) storage_fault = true;
        out = OtaBootLifecycleEvidence();
        return false;
      }
      out = failure;
    }
  }
  return true;
}

bool otaBoardReadBootCandidate(const mesh::ota::OtaBootLifecycleEvidence& expected,
                              ::ota::storage::OtaCandidateStore::Snapshot& out) {
  out = OtaCandidateStore::Snapshot();
  const bool failed = expected.phase == usb::UsbOtaPhase::Failed;
  const auto* app = failed ? esp_ota_get_next_update_partition(nullptr) : esp_ota_get_running_partition();
  esp_ota_img_states_t state;
  if (app == nullptr) return false;
  const esp_err_t state_result = esp_ota_get_state_partition(app, &state);
  if (state_result == ESP_ERR_NOT_FOUND && !failed) state = ESP_OTA_IMG_UNDEFINED;
  else if (state_result != ESP_OK) return false;
  ::ota::storage::Esp32IdfPartitionApi sdk;
  ::ota::storage::Esp32PartitionSnapshot context;
  if (failed) {
    if (sdk.inspect(context) != ::ota::storage::kEsp32Ok) {
      storage_fault = true;
      return false;
    }
    if (!esp32ClosedFailedSelectionContext(context) || resolveApp(context.next) != app) return false;
  }
  uint32_t floor = 0;
  bool floor_known = false;
  if (!readFloor(floor, &floor_known)) {
    storage_fault = true;
    return false;
  }
  ReadOnlyAppReader reader(!failed);
  Esp32OtaIoGuard checked(reader);
  ::ota::platform::FlashRegion provenance(checked, Esp32OtaPolicy::kCandidateBytes, 8192);
  OtaCandidateStore boot_store(provenance);
  OtaCandidateStore::Snapshot candidate;
  if (!readEsp32BootCandidate(expected, static_cast<Esp32ImageState>(state), boot_store, provenance,
                             policy, signatures, floor_known, floor, candidate, failed ? &context : nullptr) ||
      checked.failed()) {
    if (checked.failed()) storage_fault = true;
    return false;
  }
  esp_ota_img_states_t latest;
  const esp_err_t latest_result = esp_ota_get_state_partition(app, &latest);
  if (latest_result == ESP_ERR_NOT_FOUND && !failed) latest = ESP_OTA_IMG_UNDEFINED;
  else if (latest_result != ESP_OK) return false;
  if (latest != state ||
      app != (failed ? esp_ota_get_next_update_partition(nullptr) : esp_ota_get_running_partition()))
    return false;
  if (failed) {
    ::ota::storage::Esp32PartitionSnapshot after;
    if (sdk.inspect(after) != ::ota::storage::kEsp32Ok) {
      storage_fault = true;
      return false;
    }
    if (!esp32SameClosedFailedSelectionContext(context, after)) return false;
  }
  out = candidate;
  return true;
}

// The ordinary updater must take this same lease BEFORE it exposes any
// FirmwareUpdate/AsyncElegantOTA write path, and retain it until reboot.
bool otaBoardClaimOrdinaryFirmwareUpdate() {
  earlyTrialGuard();
  if (trial.activeOrUnknown() || !lease.claimFreshStorage()) return false;
  if (!::ota::platform::isOk(flash.bind(Esp32OtaPolicy::kSlotBytes)) ||
      !::ota::platform::isOk(metadata.eraseRange(0, metadata.sizeBytes()))) {
    storage_fault = true;
    return false;
  }
  // Retire stale FAILED/ABORTED provenance before the ordinary updater
  // writes this slot. Keep continuous ownership while changing the owner.
  return lease.handoffToOrdinaryUpdater();
}
void otaBoardReleaseOrdinaryFirmwareUpdate() { lease.releaseOrdinaryUpdater(); }

bool configureCompanionFirmwareOtaBackend(OtaFirmwareIntegration& target) {
  earlyTrialGuard();
  const auto outcome = configureEsp32OtaBackend(target, trial.activeOrUnknown(), vendor_install, policy,
                                               flash, lease, store, sink, trust, signatures, capability);
  if (outcome == Esp32ConfigureOutcome::IoError) storage_fault = true;
  if (outcome != Esp32ConfigureOutcome::Configured) return false;
  target.attachEntropy(nullptr, &otaEspEntropy);
  integration = &target;
  return true;
}

OtaBoardTrialHealthOutcome otaBoardTryConfirmHealthyTrialBoot(
    uint32_t now_ms, bool radio_ready, bool filesystem_ready, bool loop_healthy) {
  if (!trial.activeOrUnknown() && integration != nullptr) {
    // Give the USB/RF response time to leave before selecting/restarting.
    // READY alone never enters this branch, in any transport mode.
    const auto status = integration->leanReceiver().status();
    if (status.valid && status.phase == OtaCandidateStore::Phase::Committed) {
      if (!commit_waiting) { commit_waiting = true; commit_observed_ms = now_ms; }
      if ((now_ms - commit_observed_ms) >= 500) {
        const auto result = sink.activateDurableCommit();
        if (result == Esp32OtaStagingSink::InstallOutcome::Selected ||
            result == Esp32OtaStagingSink::InstallOutcome::SelectionUncertain) esp_restart();
        if (result == Esp32OtaStagingSink::InstallOutcome::Refused)
          capability = "OTA_DISABLED: ESP install uncertain; reupload";
      }
    } else if (status.valid && (status.phase == OtaCandidateStore::Phase::Aborted ||
                               status.phase == OtaCandidateStore::Phase::Failed)) {
      lease.releaseStorage();
    }
  }
  switch (trial.tick(now_ms, radio_ready, filesystem_ready && !otaBoardStorageIoFaultObserved(), loop_healthy)) {
    case Esp32TrialHealthOutcome::Confirmed: return OtaBoardTrialHealthOutcome::Confirmed;
    case Esp32TrialHealthOutcome::DeadlineExpired: return OtaBoardTrialHealthOutcome::DeadlineExpired;
    case Esp32TrialHealthOutcome::StateUnreadable: return OtaBoardTrialHealthOutcome::StateUnreadable;
    case Esp32TrialHealthOutcome::ConfirmationUncertain: return OtaBoardTrialHealthOutcome::ConfirmationUncertain;
    default: return OtaBoardTrialHealthOutcome::Pending;
  }
}

#endif

#if defined(ESP32_PLATFORM) && MESHCORE_LORA_OTA && MESHCORE_ESP32_OTA_STARTUP_NVS_GUARD
#include <nvs_flash.h>

extern "C" esp_err_t __real_nvs_flash_init();
extern "C" esp_err_t __wrap_nvs_flash_init() {
  const esp_err_t result = __real_nvs_flash_init();
  const esp_err_t guarded = mesh::ota::esp32NvsStartupInitResult(result);
  if (result != ESP_OK) {
    storage_fault = true;
    ESP_LOGE("meshota", "NVS initialization failed (0x%x); startup erase is not authorized",
             static_cast<unsigned>(result));
  }
  return guarded;
}
#endif
