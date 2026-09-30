#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <ota/platform/FlashRegion.h>
#include <ota/storage/StorageManager.h>
#include <ota/trust/DescriptorVerifier.h>
#include <ota/trust/TrustTypes.h>
#include <ota/runtime/OtaGeometry.h>
#include <ota/runtime/OtaTrustInterfaces.h>

namespace mesh {
namespace ota {

inline uint32_t otaTrustTargetId(const meshcore::ota::protocol::OtaDescriptor& descriptor) {
  return (static_cast<uint32_t>(descriptor.boardFamily) << 16) | descriptor.boardVariant;
}

inline ::ota::trust::ImageDescriptor otaTrustImageDescriptorFromWire(
    const meshcore::ota::protocol::OtaDescriptor& descriptor,
    const uint8_t* signature,
    size_t signature_len) {
  ::ota::trust::ImageDescriptor out;
  std::memcpy(out.image_hash_sha256, descriptor.sha256, sizeof(out.image_hash_sha256));
  if (signature != nullptr) {
    const size_t copy_len = signature_len < sizeof(out.signature_ed25519)
        ? signature_len
        : sizeof(out.signature_ed25519);
    std::memcpy(out.signature_ed25519, signature, copy_len);
  }
  out.target_id = otaTrustTargetId(descriptor);
  out.role_id = descriptor.role;
  out.device_address = 0;
  out.allow_broadcast_address = true;
  out.required_boot_capability_flags = descriptor.minBootloaderCapabilities;
  out.monotonic_counter = descriptor.securityCounter;
  out.image_size_bytes = descriptor.exactSizeBytes;
  out.app_address = descriptor.appAddress;
  out.format_id = descriptor.formatId;
  out.key_id = descriptor.keyId;
  out.algorithm_id = descriptor.algorithmId;
  return out;
}

class OtaFirmwareTrustProvider : public meshcore::ota::runtime::IOtaTrustProvider {
public:
  OtaFirmwareTrustProvider(::ota::trust::DescriptorVerifier& verifier,
                           ::ota::platform::FlashRegion& candidate_region)
      : verifier_(verifier), candidate_region_(candidate_region) {}

  OtaFirmwareTrustProvider(::ota::trust::DescriptorVerifier& verifier,
                           ::ota::platform::FlashRegion& candidate_region,
                           const ::ota::trust::SignatureVerifier& wire_signature_verifier,
                           const uint8_t trusted_wire_public_key[32])
      : verifier_(verifier),
        candidate_region_(candidate_region),
        wire_signature_verifier_(&wire_signature_verifier) {
    if (trusted_wire_public_key != nullptr) {
      std::memcpy(trusted_wire_public_key_, trusted_wire_public_key,
                  sizeof(trusted_wire_public_key_));
    }
  }

  bool verifyDescriptorSignature(const uint8_t* canonical_descriptor, size_t descriptor_len,
                                 const uint8_t* signature, size_t signature_len,
                                 uint16_t, uint16_t) override {
    return wire_signature_verifier_ != nullptr &&
           canonical_descriptor != nullptr &&
           signature != nullptr &&
           signature_len == sizeof(descriptor_.signature_ed25519) &&
           wire_signature_verifier_->verify(
               signature, signature_len, canonical_descriptor, descriptor_len,
               trusted_wire_public_key_, sizeof(trusted_wire_public_key_));
  }

  bool verifyDescriptor(const meshcore::ota::protocol::OtaDescriptor& descriptor,
                        const uint8_t* signature,
                        size_t signature_len) override {
    if (signature == nullptr || signature_len != sizeof(descriptor_.signature_ed25519)) {
      return false;
    }
    descriptor_ = otaTrustImageDescriptorFromWire(descriptor, signature, signature_len);
    ::ota::trust::VerificationResult result;
    if (wire_signature_verifier_ != nullptr) {
      uint8_t canonical[meshcore::ota::protocol::kOtaDescriptorCanonicalSize] = {};
      size_t canonical_len = 0;
      if (meshcore::ota::protocol::encodeOtaDescriptorCanonical(
              descriptor, canonical, sizeof(canonical), canonical_len) !=
              meshcore::ota::protocol::OtaDescriptorCodecResult::Ok ||
          !verifyDescriptorSignature(canonical, canonical_len, signature, signature_len,
                                     descriptor.keyId, descriptor.algorithmId)) {
        descriptor_verified_ = false;
        return false;
      }
      result = verifier_.verifyPolicy(descriptor_);
    } else {
      result = verifier_.verifyDescriptor(descriptor_);
    }
    descriptor_verified_ = result.ok;
    return result.ok;
  }

  bool verifyDescriptorPolicy(const meshcore::ota::protocol::OtaDescriptor&) override {
    return descriptor_verified_;
  }

  bool authorizeTransfer(const meshcore::ota::protocol::OtaDescriptor& descriptor,
                         const meshcore::ota::protocol::OtaAuthorizationPayload& authorization) override {
    return descriptor_verified_ &&
           descriptor.securityCounter == descriptor_.monotonic_counter &&
           authorization.granted != 0 &&
           authorization.maxInFlightChunks > 0;
  }

  bool verifyStagedImageHash(const meshcore::ota::protocol::OtaDescriptor& descriptor) override {
    if (!descriptor_verified_ || descriptor.securityCounter != descriptor_.monotonic_counter) {
      return false;
    }
    const ::ota::trust::VerificationResult result = verifier_.verifyImageBytes(descriptor_, candidate_region_);
    return result.ok;
  }

  bool commitSecurityCounter(uint32_t counter) override {
    (void)counter;
    return false;
  }

private:
  ::ota::trust::DescriptorVerifier& verifier_;
  ::ota::platform::FlashRegion& candidate_region_;
  ::ota::trust::ImageDescriptor descriptor_;
  bool descriptor_verified_ = false;
  const ::ota::trust::SignatureVerifier* wire_signature_verifier_ = nullptr;
  uint8_t trusted_wire_public_key_[32] = {};
};

class OtaFirmwareStorageSink : public meshcore::ota::runtime::IOtaStagingSink {
public:
  explicit OtaFirmwareStorageSink(::ota::platform::FlashRegion& candidate_region)
      : candidate_region_(candidate_region) {}

  Result beginSession(const meshcore::ota::protocol::OtaDescriptor& descriptor) override {
    descriptor_ = descriptor;
    active_ = false;
    if (descriptor.exactSizeBytes == 0 || descriptor.exactSizeBytes > candidate_region_.sizeBytes()) {
      return Result::Rejected;
    }
    if (!::ota::storage::StorageManager::erasePartition(candidate_region_)) {
      return Result::IoError;
    }
    active_ = true;
    return Result::Ok;
  }

  Result writeChunk(uint64_t offset, const uint8_t* data, size_t len) override {
    if (!active_ || data == nullptr || len == 0 || offset > 0xFFFFFFFFu) {
      return Result::Rejected;
    }
    if ((offset % meshcore::ota::runtime::kOtaDefaultChunkPayloadSize) != 0) {
      return Result::Rejected;
    }
    const uint32_t chunk_index = static_cast<uint32_t>(offset / meshcore::ota::runtime::kOtaDefaultChunkPayloadSize);
    if (!::ota::storage::StorageManager::writeAndVerifyChunk(
            candidate_region_, chunk_index, meshcore::ota::runtime::kOtaDefaultChunkPayloadSize,
            data, static_cast<uint32_t>(len))) {
      return Result::IoError;
    }
    return Result::Ok;
  }

  Result commit() override {
    if (!active_) return Result::Rejected;
    active_ = false;
    return Result::Ok;
  }

  void abort() override { active_ = false; }

private:
  ::ota::platform::FlashRegion& candidate_region_;
  meshcore::ota::protocol::OtaDescriptor descriptor_;
  bool active_ = false;
};

}  // namespace ota
}  // namespace mesh
