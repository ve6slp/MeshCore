#pragma once

#include <Arduino.h>
#include <Ed25519.h>
#include <nrf_soc.h>
#include <helpers/ota/OtaBoardBackendCommon.h>
#include <helpers/ota/OtaV4Receiver.h>
#include <ota/platform/Nrf52FlashAdapter.h>
#include <ota/platform/SenseCapQspiLayout.h>
#include <target.h>

#if !defined(XIAO_OTA_COMPILED_ROLE_ID) || !defined(MESHCORE_V4_NRF_TARGET)
#error "OTA v4 requires an explicitly bound board and companion/repeater role"
#endif
static_assert(XIAO_OTA_COMPILED_ROLE_ID == 0 || XIAO_OTA_COMPILED_ROLE_ID == 1,
              "unsupported OTA role");

extern RADIO_CLASS radio;
bool otaBoardApplyRfProfile(float frequency, float bandwidth, uint8_t sf, uint8_t cr) {
  return mesh::ota::applyCheckedOtaRadioProfile(radio, radio_driver, frequency, bandwidth, sf, cr);
}

namespace {
using namespace mesh::ota::v4;
using Layout = ota::platform::SenseCapQspiLayout;
ota::platform::Nrf52FlashAdapter v4Flash;
ota::platform::FlashRegion v4Payload = Layout::candidatePayloadRegion(v4Flash);
ota::platform::FlashRegion v4Metadata = Layout::candidateRecordRegion(v4Flash);
ota::platform::FlashRegion v4Commands = Layout::xiaoCommandRegion(v4Flash);
ota::platform::FlashRegion v4State = Layout::xiaoStateRegion(v4Flash);
ota::platform::FlashRegion v4Floor = Layout::xiaoFloorRegion(v4Flash);
ota::platform::FlashRegion v4Confirm = Layout::xiaoConfirmRegion(v4Flash);
NrfRunningReader v4Running;
NrfFirmwarePlatform* v4Backend = nullptr;
bool v4FlashReady = false, v4Normal = false;
bool v4ResetWaiting = false;
uint32_t v4ResetAt = 0;
const char* v4Capability = "OTA_DISABLED: not configured";

class NrfSignatureVerifier final : public ota::trust::SignatureVerifier {
public:
  bool verify(const uint8_t* signature, size_t signatureSize, const uint8_t* message,
      size_t messageSize, const uint8_t* key, size_t keySize) const override {
    return signature && signatureSize == 64 && key && keySize == 32 &&
        (message || !messageSize) && Ed25519::verify(signature, key, message, messageSize);
  }
};
NrfSignatureVerifier v4Signatures;

bool nrfV4Entropy(uint8_t* out, size_t size) {
  if (!out || !size || size > 64) return false;
  uint8_t softdevice = 0;
  if (sd_softdevice_is_enabled(&softdevice) != NRF_SUCCESS) return false;
  const uint32_t start = millis();
  size_t done = 0;
  if (softdevice) {
    while (done < size) {
      uint8_t available = 0;
      if (sd_rand_application_bytes_available_get(&available) != NRF_SUCCESS) return false;
      if (!available) {
        if (millis() - start >= 250) return false;
        delay(1);
        continue;
      }
      const uint8_t count = size - done < available ? size - done : available;
      if (sd_rand_application_vector_get(out + done, count) != NRF_SUCCESS) return false;
      done += count;
    }
    return true;
  }
  NRF_RNG->CONFIG = RNG_CONFIG_DERCEN_Msk;
  NRF_RNG->EVENTS_VALRDY = 0;
  NRF_RNG->TASKS_START = 1;
  while (done < size) {
    if (!NRF_RNG->EVENTS_VALRDY) {
      if (millis() - start >= 250) { NRF_RNG->TASKS_STOP = 1; return false; }
      continue;
    }
    NRF_RNG->EVENTS_VALRDY = 0;
    out[done++] = static_cast<uint8_t>(NRF_RNG->VALUE);
  }
  NRF_RNG->TASKS_STOP = 1;
  return true;
}

Policy nrfV4Policy() {
  Policy policy;
  policy.boardFamily = uint32_t(MESHCORE_V4_NRF_TARGET) >> 16;
  policy.boardVariant = uint32_t(MESHCORE_V4_NRF_TARGET) & 0xFFFF;
  policy.role = XIAO_OTA_COMPILED_ROLE_ID;
  policy.appAddress = OTA_NRF52_INTERNAL_IMAGE_OFFSET;
  policy.maxImageBytes = OTA_NRF52_INTERNAL_IMAGE_SIZE;
  policy.bootloaderCapabilities = 1;
  return policy;
}

bool initializeNrfV4() {
  if (!v4FlashReady) {
    if (!Layout::isValid() || !ota::platform::isOk(v4Flash.begin())) return false;
    const uint8_t* jedec = v4Flash.jedecId();
    if (jedec[0] != 0x85 || jedec[1] != 0x60 || jedec[2] != 0x15) return false;
    v4FlashReady = true;
  }
  if (!v4Backend) {
    static NrfFirmwarePlatform backend(nrfV4Policy(), v4Payload, v4Metadata, v4Commands,
        v4State, v4Floor, v4Confirm, v4Signatures, v4Running, nrfV4Entropy);
    v4Backend = &backend;
  }
  return true;
}
}

bool otaBoardEarlyBootTrialOrUnknown() {
  v4Normal = initializeNrfV4() && v4Backend->normalProven();
  return !v4Normal;
}
bool otaBoardEarlyBootNormalProven() { return !otaBoardEarlyBootTrialOrUnknown(); }
bool otaBoardTrialHealthWindowActive() {
  return !v4Backend || !v4Normal || v4Backend->trialActive();
}
bool otaBoardStorageIoFaultObserved() {
  return !v4FlashReady || (v4Backend && v4Backend->storageFaultObserved());
}
const char* otaBoardInstallCapabilityStatus() { return v4Capability; }
const char* otaBoardEarlyWriteDiagnostic() { return v4Normal ? "proof=verified-running" : "proof=unknown"; }
mesh::ota::OtaBoardTrialHealthOutcome otaBoardTryConfirmHealthyTrialBoot(
    uint32_t now, bool radioReady, bool filesystemReady, bool loopHealthy) {
  if (!v4Backend) return mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  if (v4Backend->activationPending()) {
    if (!v4ResetWaiting) { v4ResetWaiting = true; v4ResetAt = now; }
    if (uint32_t(now - v4ResetAt) >= 500) NVIC_SystemReset();
  }
  return v4Backend->health(now, radioReady, filesystemReady, loopHealthy);
}
mesh::ota::v4::Receiver* otaBoardConfigureV4Backend(const mesh::ota::v4::RuntimeHooks& hooks) {
  if (!initializeNrfV4()) {
    v4Capability = "OTA_DISABLED: QSPI unavailable";
    return nullptr;
  }
  v4Backend->attach(hooks);
  v4Capability = v4Backend->installationReady() ? "INSTALL_CAPABLE: OTA v4" :
      "STAGING_ONLY: installer or running proof unavailable";
  static mesh::ota::v4::Receiver receiver(*v4Backend);
  return &receiver;
}
