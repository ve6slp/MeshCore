#if defined(ESP32_PLATFORM) && defined(MESHCORE_LORA_OTA) && MESHCORE_LORA_OTA

#include <Arduino.h>
#include <Ed25519.h>
#include <esp_flash.h>
#include <esp_image_format.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <nvs.h>
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
#if defined(ADMIN_PASSWORD) && !defined(DISABLE_WIFI_OTA) && !defined(MESHCORE_ESP32_OTA_UPDATER_LEASE)
#error "ESP LoRa OTA must exclude the ordinary updater or wire its shared lease before server startup"
#endif

extern RADIO_CLASS radio;

bool otaBoardApplyRfProfile(float frequency, float bandwidth, uint8_t sf, uint8_t cr) {
  return mesh::ota::applyCheckedOtaRadioProfile(radio, radio_driver, frequency, bandwidth, sf, cr);
}

namespace {

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

bool reconcileRunningFloor() {
  uint32_t counter = 0;
  bool have_candidate = false;
  return runningCandidateCounter(counter, have_candidate) && (!have_candidate || saveFloor(counter));
}

class VendorTrialPlatform final : public Esp32TrialPlatform {
public:
  bool runningState(Esp32ImageState& out) override {
    const auto* running = esp_ota_get_running_partition();
    if (running == nullptr) return false;
    esp_ota_img_states_t state;
    const esp_err_t err = esp_ota_get_state_partition(running, &state);
    if (err == ESP_ERR_NOT_FOUND) { out = Esp32ImageState::Undefined; return true; }
    if (err != ESP_OK) return false;
    out = static_cast<Esp32ImageState>(state);
    return true;
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
  bool confirmHealthy() override {
    // Never advance the numeric floor during a failed trial. If reset cuts
    // the valid->floor window, next startup reconciles the signed RUNNING
    // candidate before permitting another transfer.
    uint32_t counter = 0;
    bool have_candidate = false;
    if (!runningCandidateCounter(counter, have_candidate)) { storage_fault = true; return false; }
    if (esp_ota_mark_app_valid_cancel_rollback() != ESP_OK) return false;
    if (have_candidate && !saveFloor(counter)) { storage_fault = true; return false; }
    return true;
  }
  void rollbackAndRestart() override {
    // IDF refuses rollback if no previous valid app exists. Still RESET:
    // an unconfirmed PENDING_VERIFY image must not run indefinitely.
    esp_ota_mark_app_invalid_rollback_and_reboot();
    esp_restart();
  }
private:
  wdt_hal_context_t watchdog_ = {};
  bool armed_ = false;
};

VendorTrialPlatform trial_platform;
Esp32TrialController trial(trial_platform);

void earlyTrialGuard() {
  trial.begin(static_cast<uint32_t>(millis()));
}

}  // namespace

// This strong symbol must appear as T (not W) in BOTH linked firmware ELFs.
extern "C" bool verifyRollbackLater() {
  earlyTrialGuard();
  return true;
}

bool otaBoardEarlyBootTrialOrUnknown() {
  earlyTrialGuard();
  return trial.activeOrUnknown();
}

bool otaBoardTrialHealthWindowActive() { return trial.activeOrUnknown(); }
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
  ::ota::platform::FlashRegion running_image(running, 0, Esp32OtaPolicy::kCandidateBytes);
  ::ota::platform::FlashRegion running_metadata(running, Esp32OtaPolicy::kCandidateBytes, 8192);
  OtaCandidateStore running_store(running_metadata);
  if (!readEsp32BootLifecycle(state, running_store, running_image, policy, signatures,
                             floor_known, floor, out)) return false;
  Esp32ImageState latest;
  if (!trial_platform.runningState(latest) || latest != state) {
    out = OtaBootLifecycleEvidence();
    return false;
  }
  const auto* next = esp_ota_get_next_update_partition(nullptr);
  esp_ota_img_states_t next_state;
  if (next != nullptr && next != esp_ota_get_running_partition() &&
      esp_ota_get_state_partition(next, &next_state) == ESP_OK &&
      (next_state == ESP_OTA_IMG_ABORTED || next_state == ESP_OTA_IMG_INVALID)) {
    ReadOnlyAppReader failed(false);
    ::ota::platform::FlashRegion failed_image(failed, 0, Esp32OtaPolicy::kCandidateBytes);
    ::ota::platform::FlashRegion failed_metadata(failed, Esp32OtaPolicy::kCandidateBytes, 8192);
    OtaCandidateStore failed_store(failed_metadata);
    OtaBootLifecycleEvidence failure;
    if (readEsp32BootLifecycle(static_cast<Esp32ImageState>(next_state), failed_store, failed_image,
                              policy, signatures, floor_known, floor, failure, true) &&
        failure.transactionNonce != 0) out = failure;
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
  uint32_t floor = 0;
  bool floor_known = false;
  if (!readFloor(floor, &floor_known)) {
    storage_fault = true;
    return false;
  }
  ReadOnlyAppReader reader(!failed);
  ::ota::platform::FlashRegion provenance(reader, Esp32OtaPolicy::kCandidateBytes, 8192);
  OtaCandidateStore boot_store(provenance);
  OtaCandidateStore::Snapshot candidate;
  if (!readEsp32BootCandidate(expected, static_cast<Esp32ImageState>(state), boot_store,
                             policy, signatures, floor_known, floor, candidate)) return false;
  esp_ota_img_states_t latest;
  const esp_err_t latest_result = esp_ota_get_state_partition(app, &latest);
  if (latest_result == ESP_ERR_NOT_FOUND && !failed) latest = ESP_OTA_IMG_UNDEFINED;
  else if (latest_result != ESP_OK) return false;
  if (latest != state ||
      app != (failed ? esp_ota_get_next_update_partition(nullptr) : esp_ota_get_running_partition()))
    return false;
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
  if (trial.activeOrUnknown()) {
    capability = "OTA_DISABLED: ESP trial or unknown";
    return false;
  }
  if (!reconcileRunningFloor() || !readFloor(policy.confirmedCounter)) {
    storage_fault = true;
    capability = "OTA_DISABLED: ESP confirmed floor unreadable";
    return false;
  }
  if (!lease.claimStorage() || !::ota::platform::isOk(flash.bind(Esp32OtaPolicy::kSlotBytes))) {
    capability = "OTA_DISABLED: ESP partition or updater ownership";
    return false;
  }
  OtaCandidateStore::Snapshot s;
  bool existing = store.load(s);
  if (!existing) {
    uint8_t first[4];
    if (!::ota::platform::isOk(metadata.read(0, first, sizeof(first))) ||
        first[0] != 0xff || first[1] != 0xff || first[2] != 0xff || first[3] != 0xff) {
      storage_fault = true;
      capability = "OTA_DISABLED: ESP candidate metadata damaged";
      return false;
    }
  }
  if (existing && s.phase == OtaCandidateStore::Phase::Committed) {
    if (!sink.recoverUnsuccessfulSelection() || !store.load(s)) {
      storage_fault = true;
      capability = "OTA_DISABLED: ESP install recovery unreadable";
      return false;
    }
  }
  target.attachTrustProvider(&trust);
  target.attachLeanSignatureVerifier(&signatures);
  target.attachStagingSink(&sink);
  target.attachCandidateStore(&store);
  integration = &target;
  capability = "INSTALL_CAPABLE: ESP-IDF A/B rollback";
  if (!existing || s.phase == OtaCandidateStore::Phase::Aborted || s.phase == OtaCandidateStore::Phase::Failed)
    lease.releaseStorage();
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
