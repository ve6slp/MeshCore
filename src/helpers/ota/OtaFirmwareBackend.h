#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <ota/platform/FlashRegion.h>
#include <ota/storage/StorageManager.h>
#include <ota/storage/XiaoOtaCommandRecord.h>
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

  // Preferred constructor: also binds the exact (keyId, algorithmId) this
  // device's boot policy trusts, so `verifyDescriptorSignature()` itself
  // rejects a descriptor tagged with any other key/algorithm identity
  // BEFORE checking the Ed25519 signature bytes -- not merely relying on
  // `DescriptorVerifier::verifyPolicy()` to catch it downstream, since
  // `verifyDescriptorSignature()` is a directly callable interface entry
  // point (see `verifyDescriptorSignatureFailClosed()`) that could be
  // invoked on its own.
  OtaFirmwareTrustProvider(::ota::trust::DescriptorVerifier& verifier,
                           ::ota::platform::FlashRegion& candidate_region,
                           const ::ota::trust::SignatureVerifier& wire_signature_verifier,
                           const uint8_t trusted_wire_public_key[32],
                           uint16_t trusted_key_id,
                           uint16_t trusted_algorithm_id)
      : OtaFirmwareTrustProvider(verifier, candidate_region, wire_signature_verifier,
                                 trusted_wire_public_key) {
    trusted_key_id_ = trusted_key_id;
    trusted_algorithm_id_ = trusted_algorithm_id;
    key_id_check_enabled_ = true;
  }

  bool verifyDescriptorSignature(const uint8_t* canonical_descriptor, size_t descriptor_len,
                                 const uint8_t* signature, size_t signature_len,
                                 uint16_t key_id, uint16_t algorithm_id) override {
    if (key_id_check_enabled_ &&
        (key_id != trusted_key_id_ || algorithm_id != trusted_algorithm_id_)) {
      return false;
    }
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
    if (!descriptor_verified_ || counter != descriptor_.monotonic_counter) {
      return false;
    }
    return verifier_.commitCounter(descriptor_);
  }

  bool controllerIdentity(uint8_t out[32]) override {
    if (!descriptor_verified_ || out == nullptr) return false;
    std::memcpy(out, trusted_wire_public_key_, 32);
    return true;
  }

private:
  ::ota::trust::DescriptorVerifier& verifier_;
  ::ota::platform::FlashRegion& candidate_region_;
  ::ota::trust::ImageDescriptor descriptor_;
  bool descriptor_verified_ = false;
  const ::ota::trust::SignatureVerifier* wire_signature_verifier_ = nullptr;
  uint8_t trusted_wire_public_key_[32] = {};
  uint16_t trusted_key_id_ = 0;
  uint16_t trusted_algorithm_id_ = 0;
  bool key_id_check_enabled_ = false;
};

// Supplies the bootloader-form (71-byte, little-endian) signed install
// command for the image currently staged and verified in the candidate
// region, so OtaFirmwareStorageSink::commit() can durably hand it off to a
// custom bootloader (e.g. XIAO's, via ota::storage::XiaoOtaCommandRecord).
//
// This is deliberately NOT satisfiable by re-signing or re-encoding the
// already-verified 59-byte transport descriptor/signature: the 71-byte
// bootloader descriptor has its own independent Ed25519 signature that
// only an offline holder of the bootloader's private key
// (bootloader/xiao_nrf52840_ota/tools/sign_image.py) can produce, and
// `active_image_extent`/`active_image_hash_sha256` describe the CURRENTLY
// RUNNING application image on internal flash, which this OTA subsystem
// (built entirely on external QSPI FlashRegion/FlashDevice) has no
// mechanism to read. A real implementation therefore needs both (a) a way
// to receive the offline-signed 71-byte command+signature alongside/after
// the image transfer, and (b) an internal-flash reader for the running
// image. Platforms without both simply never construct a provider (or
// return false from buildInstallCommand()), and commit() then correctly
// refuses to complete a durable bootloader handoff rather than writing a
// record with fabricated signature/hash data -- see the fail-closed
// comment on commit() below.
class IOtaInstallCommandProvider {
public:
  virtual ~IOtaInstallCommandProvider() = default;

  // Returns true and fills `out` iff a genuine, offline-signed install
  // command is available for the image just verified against `descriptor`.
  // MUST return false (never fabricate placeholder signature/hash/extent
  // data) when any required input -- signature, running-image hash, or
  // running-image extent -- is not genuinely available.
  virtual bool buildInstallCommand(const meshcore::ota::protocol::OtaDescriptor& descriptor,
                                   ::ota::storage::XiaoOtaCommandFields& out) = 0;
};

// Command v2's counterpart of IOtaInstallCommandProvider: no offline
// signing tool/private key is needed here, because the bootloader's v2
// install command authenticates the SAME 59-byte canonical wire descriptor
// and 64-byte Ed25519 signature the transport already verified --
// `wireDescriptor59`/`signature64` are those exact bytes, copied verbatim,
// never re-derived or re-signed. Implementations still MUST return false
// (never fabricate placeholder extent/hash data) when the currently-
// running image's extent/hash cannot be genuinely determined (e.g. see
// ::ota::storage::XiaoOtaActiveExtentBridge for the only sanctioned
// source of those two fields).
class IOtaInstallCommandProviderV2 {
public:
  virtual ~IOtaInstallCommandProviderV2() = default;

  // `session`/`controller` bind this specific authenticated, locally-
  // authorized attempt (see IOtaStagingSink::onAuthorizedSession()) --
  // implementations use these, together with wireDescriptor59, to derive
  // a deterministic transaction identity that changes across genuinely
  // new authorized attempts but stays stable across a retried commit of
  // the SAME attempt (see OtaBoardBackendCommon.h's
  // computeOtaTransactionNonce()).
  virtual bool buildInstallCommandV2(const uint8_t wireDescriptor59[::ota::storage::XiaoOtaCommandRecordV2::kWireDescriptorBytes],
                                     const uint8_t signature64[::ota::storage::XiaoOtaCommandRecordV2::kSignatureBytes],
                                     const meshcore::ota::runtime::OtaSessionId& session,
                                     const uint8_t controller[32],
                                     ::ota::storage::XiaoOtaCommandV2Fields& out) = 0;
};

class OtaFirmwareStorageSink : public meshcore::ota::runtime::IOtaStagingSink {
public:
  explicit OtaFirmwareStorageSink(::ota::platform::FlashRegion& candidate_region)
      : candidate_region_(candidate_region) {}

  // Overload that additionally durably hands the staged+verified image off
  // to a custom bootloader via `command_region` (must be exactly 2 erase
  // units, e.g. SenseCapQspiLayout::xiaoCommandRegion()) once `provider`
  // supplies a genuine signed command. `command_region`/`provider` may be
  // null, in which case commit() behaves exactly like the single-argument
  // constructor above (staging-only, no bootloader handoff).
  OtaFirmwareStorageSink(::ota::platform::FlashRegion& candidate_region,
                        ::ota::platform::FlashRegion* command_region,
                        IOtaInstallCommandProvider* command_provider)
      : candidate_region_(candidate_region),
        command_region_(command_region),
        command_provider_(command_provider) {}

  // v2 counterpart: `command_region_v2` holds xiao_ota_command_v2_t
  // records (188 bytes/slot) instead of v1's 200-byte records; typically
  // the SAME physical A/B sectors as v1 (the bootloader dispatches by the
  // record_version byte at a fixed offset, so either version's record can
  // occupy either slot), but a distinct FlashRegion*/provider pair is
  // taken here so a backend can choose v1, v2, or (temporarily) both.
  OtaFirmwareStorageSink(::ota::platform::FlashRegion& candidate_region,
                        ::ota::platform::FlashRegion* command_region_v2,
                        IOtaInstallCommandProviderV2* command_provider_v2)
      : candidate_region_(candidate_region),
        command_region_v2_(command_region_v2),
        command_provider_v2_(command_provider_v2) {}

  Result beginSession(const meshcore::ota::protocol::OtaDescriptor& descriptor) override {
    abort();
    if (!canAttach(descriptor)) {
      return Result::Rejected;
    }
    if (!::ota::storage::StorageManager::erasePartition(candidate_region_)) {
      return Result::IoError;
    }
    descriptor_ = descriptor;
    active_ = true;
    return Result::Ok;
  }

  // The caller must re-verify durable metadata before attaching, then
  // restore the verified descriptor and local authorization hooks.
  Result resumeSession(const meshcore::ota::protocol::OtaDescriptor& descriptor) {
    abort();
    if (!canAttach(descriptor)) return Result::Rejected;
    descriptor_ = descriptor;
    active_ = true;
    return Result::Ok;
  }

  Result writeChunk(uint64_t offset, const uint8_t* data, size_t len) override {
    if (!active_ || data == nullptr || len == 0 ||
        len > meshcore::ota::runtime::kOtaDefaultChunkPayloadSize ||
        offset >= descriptor_.exactSizeBytes ||
        len > descriptor_.exactSizeBytes - offset) {
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

  // Captures the transport's own verified 59-byte wire descriptor +
  // 64-byte signature verbatim, so commit() can hand them to
  // command_provider_v2_ unchanged -- no re-derivation, no re-signing.
  void onVerifiedWireDescriptor(const uint8_t* wireDescriptor59, size_t wireDescriptorLen,
                                const uint8_t* signature64, size_t signatureLen) override {
    if (wireDescriptor59 == nullptr || signature64 == nullptr ||
        wireDescriptorLen != sizeof(verified_wire_descriptor_) ||
        signatureLen != sizeof(verified_signature_)) {
      have_verified_wire_ = false;
      return;
    }
    std::memcpy(verified_wire_descriptor_, wireDescriptor59, sizeof(verified_wire_descriptor_));
    std::memcpy(verified_signature_, signature64, sizeof(verified_signature_));
    have_verified_wire_ = true;
  }

  // Captures the session identity + controller pubkey of the specific
  // authenticated, locally-authorized attempt that granted access, so
  // commit() can bind the install command's transaction identity to THIS
  // attempt rather than the descriptor alone (Sol finding: descriptor-only
  // binding made an explicit new authorized retry of the same image
  // indistinguishable from a failed transaction's own retry).
  void onAuthorizedSession(const meshcore::ota::runtime::OtaSessionId& session,
                           const uint8_t controller[32]) override {
    authorized_session_ = session;
    if (controller != nullptr) {
      std::memcpy(authorized_controller_, controller, sizeof(authorized_controller_));
      have_authorized_session_ = true;
    } else {
      have_authorized_session_ = false;
    }
  }

  // Fail-closed: when a custom-bootloader handoff is configured (either
  // v1's command_region_/command_provider_ or v2's
  // command_region_v2_/command_provider_v2_), commit() only ever succeeds
  // once a genuine signed install command has been durably written -- it
  // never falls back to "staged only" success in that configuration,
  // since a stock/no-handoff commit() result would otherwise be
  // indistinguishable from "installed", which it is not.
  Result commit() override {
    if (!active_) return Result::Rejected;
    if ((command_region_v2_ == nullptr) != (command_provider_v2_ == nullptr) ||
        (command_region_ == nullptr) != (command_provider_ == nullptr)) {
      return Result::Rejected;
    }
    if (command_region_v2_ != nullptr && command_provider_v2_ != nullptr) {
      if (!have_verified_wire_) return Result::Rejected;
      // Fail closed: a v2 handoff MUST be bound to a specific
      // authenticated, locally-authorized attempt (onAuthorizedSession())
      // before commit() ever calls the provider -- never fabricate a
      // transaction identity from the descriptor alone.
      if (!have_authorized_session_) return Result::Rejected;
      ::ota::storage::XiaoOtaCommandV2Fields fields;
      if (!command_provider_v2_->buildInstallCommandV2(verified_wire_descriptor_, verified_signature_,
                                                        authorized_session_, authorized_controller_, fields)) {
        return Result::Rejected;
      }
      if (!::ota::storage::XiaoOtaCommandRecordV2::writeNext(*command_region_v2_, fields)) {
        return Result::IoError;
      }
    } else if (command_region_ != nullptr && command_provider_ != nullptr) {
      ::ota::storage::XiaoOtaCommandFields fields;
      if (!command_provider_->buildInstallCommand(descriptor_, fields)) {
        return Result::Rejected;
      }
      if (!::ota::storage::XiaoOtaCommandRecord::writeNext(*command_region_, fields)) {
        return Result::IoError;
      }
    }
    active_ = false;
    committed_ = true;
    return Result::Ok;
  }

  void abort() override {
    active_ = false;
    committed_ = false;
    have_verified_wire_ = false;
    have_authorized_session_ = false;
  }

  bool isActive() const { return active_; }
  bool isCommitted() const { return committed_; }
  bool haveVerifiedWireDescriptor() const { return have_verified_wire_; }
  bool haveAuthorizedSession() const { return have_authorized_session_; }
  const uint8_t* verifiedWireDescriptor() const { return verified_wire_descriptor_; }
  const uint8_t* authorizedController() const { return authorized_controller_; }

private:
  bool canAttach(const meshcore::ota::protocol::OtaDescriptor& descriptor) const {
    return candidate_region_.isValid() && descriptor.exactSizeBytes != 0 &&
           descriptor.exactSizeBytes <= candidate_region_.sizeBytes();
  }

  ::ota::platform::FlashRegion& candidate_region_;
  ::ota::platform::FlashRegion* command_region_ = nullptr;
  IOtaInstallCommandProvider* command_provider_ = nullptr;
  ::ota::platform::FlashRegion* command_region_v2_ = nullptr;
  IOtaInstallCommandProviderV2* command_provider_v2_ = nullptr;
  uint8_t verified_wire_descriptor_[::ota::storage::XiaoOtaCommandRecordV2::kWireDescriptorBytes] = {};
  uint8_t verified_signature_[::ota::storage::XiaoOtaCommandRecordV2::kSignatureBytes] = {};
  meshcore::ota::runtime::OtaSessionId authorized_session_{};
  uint8_t authorized_controller_[32] = {};
  bool have_authorized_session_ = false;
  bool have_verified_wire_ = false;
  meshcore::ota::protocol::OtaDescriptor descriptor_;
  bool active_ = false;
  bool committed_ = false;
};

}  // namespace ota
}  // namespace mesh
