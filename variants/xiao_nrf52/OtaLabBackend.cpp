#include <Arduino.h>

#if defined(MESHCORE_OTA_LAB_BACKEND) && MESHCORE_OTA_LAB_BACKEND

#include <cstring>
#include <Ed25519.h>

#include <helpers/ota/OtaFirmwareBackend.h>
#include <helpers/ota/OtaFirmwareIntegration.h>
#include <ota/platform/Nrf52FlashAdapter.h>
#include <ota/platform/SenseCapQspiLayout.h>
#include <ota/trust/DescriptorVerifier.h>
#include <ota/trust/MonotonicCounter.h>
#include <ota/trust/Sha256.h>

namespace {

class LabMonotonicCounter : public ota::trust::MonotonicCounter {
public:
  bool currentValue(uint32_t& out) const override {
    out = value_;
    return true;
  }

  bool commitNewValue(uint32_t value) override {
    if (value <= value_) return false;
    value_ = value;
    return true;
  }

private:
  uint32_t value_ = 0;
};

class LabSignatureVerifier : public ota::trust::SignatureVerifier {
public:
  bool verify(const uint8_t* signature, size_t signature_len,
              const uint8_t* message, size_t message_len,
              const uint8_t* public_key, size_t public_key_len) const override {
    if (signature == nullptr || public_key == nullptr ||
        (message == nullptr && message_len != 0) ||
        signature_len != 64 || public_key_len != 32) {
      return false;
    }
    return Ed25519::verify(signature, public_key, message, message_len);
  }
};

constexpr uint8_t kLabPublicKey[32] = {
    0x79, 0xB5, 0x56, 0x2E, 0x8F, 0xE6, 0x54, 0xF9,
    0x40, 0x78, 0xB1, 0x12, 0xE8, 0xA9, 0x8B, 0xA7,
    0x90, 0x1F, 0x85, 0x3A, 0xE6, 0x95, 0xBE, 0xD7,
    0xE0, 0xE3, 0x91, 0x0B, 0xAD, 0x04, 0x96, 0x64,
};

ota::platform::Nrf52FlashAdapter flash;
ota::platform::FlashRegion candidate =
    ota::platform::SenseCapQspiLayout::candidateTestRegion(flash);
LabMonotonicCounter counter;
ota::trust::Sha256 hasher;
LabSignatureVerifier signature_verifier;
ota::trust::DeviceTrustAnchor anchor;
ota::trust::DescriptorVerifier* verifier = nullptr;
mesh::ota::OtaFirmwareTrustProvider* trust = nullptr;
mesh::ota::OtaFirmwareStorageSink* staging = nullptr;

}  // namespace

bool configureCompanionFirmwareOtaBackend(mesh::ota::OtaFirmwareIntegration& integration) {
  if (!ota::platform::SenseCapQspiLayout::isValid() ||
      !ota::platform::isOk(flash.begin())) {
    return false;
  }
  const uint8_t* jedec_id = flash.jedecId();
  if (jedec_id[0] != 0x85 || jedec_id[1] != 0x60 || jedec_id[2] != 0x15) {
    return false;
  }

  std::memcpy(anchor.trusted_signer_public_key_ed25519, kLabPublicKey,
              sizeof(kLabPublicKey));
  anchor.expected_target_id = 0x52840001u;
  anchor.expected_role_id = 1u;
  anchor.supported_boot_capability_flags = 0u;

  static ota::trust::DescriptorVerifier lab_verifier(
      hasher, signature_verifier, counter, anchor);
  static mesh::ota::OtaFirmwareTrustProvider lab_trust(
      lab_verifier, candidate, signature_verifier, kLabPublicKey);
  static mesh::ota::OtaFirmwareStorageSink lab_staging(candidate);
  verifier = &lab_verifier;
  trust = &lab_trust;
  staging = &lab_staging;

  integration.attachTrustProvider(trust);
  integration.attachStagingSink(staging);
  return integration.backendAvailable();
}

#endif
