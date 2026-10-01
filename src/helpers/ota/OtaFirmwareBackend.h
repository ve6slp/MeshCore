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
#include <atomic>
#include <ota/platform/Esp32FlashAdapter.h>
#include <ota/storage/OtaCandidateStore.h>
#include <ota/trust/ImageHasher.h>
#include <ota/trust/Sha256.h>

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

  bool verifyDescriptorPolicyOnly(const meshcore::ota::protocol::OtaDescriptor& descriptor) override {
    return verifier_.verifyPolicy(otaTrustImageDescriptorFromWire(descriptor, nullptr, 0)).ok;
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

  // Lean path: the owner's signature over the manifest (not this
  // compiled anchor) is what authenticated the candidate at begin() time
  // (see OtaLeanReceiver::begin()/verifyOwnerSignature()) -- there is no
  // legacy descriptor_verified_ to require here. Still re-derive the
  // ImageDescriptor fresh from the wire bytes and re-check the staged
  // bytes' actual sha256 against it, never trusting a cached result.
  bool verifyStagedImageHashPolicyOnly(const meshcore::ota::protocol::OtaDescriptor& descriptor) override {
    const ::ota::trust::ImageDescriptor lean_descriptor = otaTrustImageDescriptorFromWire(descriptor, nullptr, 0);
    const ::ota::trust::VerificationResult result = verifier_.verifyImageBytes(lean_descriptor, candidate_region_);
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

// Command v3's counterpart of IOtaInstallCommandProviderV2 -- same
// verbatim-copy rationale (no offline signing tool/private key needed;
// `wireDescriptor59`/`signature64` are the exact transport-verified
// bytes), but additionally supplies `admittedSignerPublicKey32`: the
// Ed25519 public key the running app already verified the manifest
// signer against via its own existing admin-identity trust mechanism
// (see OtaFirmwareStorageSink::onAuthorizedSession()'s `controller`
// parameter -- the sole sanctioned source of this field; never a
// wire-supplied or fabricated key). Implementations still MUST return
// false (never fabricate placeholder extent/hash data) when the
// currently-running image's extent/hash cannot be genuinely determined.
class IOtaInstallCommandProviderV3 {
public:
  virtual ~IOtaInstallCommandProviderV3() = default;

  virtual bool buildInstallCommandV3(const uint8_t wireDescriptor59[::ota::storage::XiaoOtaCommandRecordV3::kWireDescriptorBytes],
                                     const uint8_t signature64[::ota::storage::XiaoOtaCommandRecordV3::kSignatureBytes],
                                     const uint8_t admittedSignerPublicKey32[::ota::storage::XiaoOtaCommandRecordV3::kSignerKeyBytes],
                                     const meshcore::ota::runtime::OtaSessionId& session,
                                     const uint8_t controller[32],
                                     ::ota::storage::XiaoOtaCommandV3Fields& out) = 0;
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

  // v3 counterpart: `command_region_v3` holds xiao_ota_command_v2_t
  // records AT record_version 3 (220 bytes/slot, the bootloader's
  // current/sole accepted format -- see XiaoOtaCommandRecordV3's
  // doc-comment). Same physical A/B sectors as v1/v2 (union-aware
  // classification, see XiaoOtaCommandSlotClassifier); a distinct
  // FlashRegion*/provider pair lets a backend choose exactly one of
  // v1/v2/v3 (v3 is the only one any current real bootloader build
  // accepts).
  OtaFirmwareStorageSink(::ota::platform::FlashRegion& candidate_region,
                        ::ota::platform::FlashRegion* command_region_v3,
                        IOtaInstallCommandProviderV3* command_provider_v3)
      : candidate_region_(candidate_region),
        command_region_v3_(command_region_v3),
        command_provider_v3_(command_provider_v3) {}

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
  Result resumeSession(const meshcore::ota::protocol::OtaDescriptor& descriptor) override {
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
        len > descriptor_.exactSizeBytes - offset ||
        offset > 0xFFFFFFFFull) {
      return Result::Rejected;
    }
    // Writes directly at the raw byte offset: the caller (legacy chunk
    // protocol at 128-byte pitch, or the lean path's 84-byte block index *
    // kOtaBlockMaxDataBytes) owns its own chunking convention, and no
    // single fixed modulus here can be correct for both -- see
    // writeAndVerifyAtOffset()'s doc comment in StorageManager.h.
    if (!::ota::storage::StorageManager::writeAndVerifyAtOffset(
            candidate_region_, static_cast<uint32_t>(offset), data, static_cast<uint32_t>(len))) {
      return Result::IoError;
    }
    return Result::Ok;
  }

  // Real read-back of previously staged bytes, for an autonomous RF
  // uploader re-transmitting blocks it already owns (see
  // IOtaStagingSink::readChunk doc comment). Uses the exact same raw-
  // offset addressing as writeChunk() above so a round-trip write-then-
  // read always addresses identical flash bytes.
  Result readChunk(uint64_t offset, uint8_t* out, size_t len) override {
    if (!active_ || out == nullptr || len == 0 ||
        len > meshcore::ota::runtime::kOtaDefaultChunkPayloadSize ||
        offset >= descriptor_.exactSizeBytes ||
        len > descriptor_.exactSizeBytes - offset ||
        offset > 0xFFFFFFFFull) {
      return Result::Rejected;
    }
    if (!::ota::storage::StorageManager::readAtOffset(candidate_region_, static_cast<uint32_t>(offset), out,
                                                       static_cast<uint32_t>(len))) {
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
  //
  // NOTE: `controller` here is ONLY ever used for the v1/v2 transaction-
  // nonce derivation (a narrow, non-trust-bearing purpose: "did this
  // exact authorized attempt change"). It must NEVER be reused as v3's
  // admitted_signer_public_key_ed25519 -- see onAdmittedOwnerIdentity()
  // below for that distinct, stricter concept.
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

  // Command v3's admitted_signer_public_key_ed25519 MUST be the real
  // cryptographic OWNER identity -- the actual Ed25519 public key that
  // genuinely signed this candidate's manifest/COMMIT, resolved through
  // the device's own existing admin-authorization mechanism (ClientACL
  // entry / local trusted owner self_id) -- NEVER the compiled/
  // qualification-time trust anchor used elsewhere purely to verify the
  // manifest signature bytes (OtaFirmwareTrustProvider::controllerIdentity()),
  // and NEVER an image/descriptor tag standing in for a key. Per MAIN's
  // explicit correction: "your C++ writer must consume final record
  // incl original owner's actual public key at explicit COMMIT, not
  // compile key or image tag." Until a real caller supplies this via a
  // genuinely verified owner lookup (pending coordination with the Boot
  // owner on the exact admission mechanism), it is intentionally left
  // unset so commit() fails closed below rather than fabricate a value.
  void onAdmittedOwnerIdentity(const uint8_t owner_public_key[32]) override {
    if (owner_public_key == nullptr) {
      have_admitted_owner_public_key_ = false;
      return;
    }
    std::memcpy(admitted_owner_public_key_, owner_public_key, sizeof(admitted_owner_public_key_));
    have_admitted_owner_public_key_ = true;
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
        (command_region_v3_ == nullptr) != (command_provider_v3_ == nullptr) ||
        (command_region_ == nullptr) != (command_provider_ == nullptr)) {
      return Result::Rejected;
    }
    if (command_region_v3_ != nullptr && command_provider_v3_ != nullptr) {
      if (!have_verified_wire_) return Result::Rejected;
      // Same fail-closed rationale as v2: a v3 handoff MUST be bound to a
      // specific authenticated, locally-authorized attempt before commit()
      // ever calls the provider.
      if (!have_authorized_session_) return Result::Rejected;
      // Additionally (v3-only): the durable record's admitted signer key
      // MUST be a genuinely resolved owner identity -- never the compiled
      // trust anchor or authorized_controller_ (see onAdmittedOwnerIdentity()
      // doc-comment). Until a real caller supplies this, fail closed.
      if (!have_admitted_owner_public_key_) return Result::Rejected;
      ::ota::storage::XiaoOtaCommandV3Fields fields;
      if (!command_provider_v3_->buildInstallCommandV3(verified_wire_descriptor_, verified_signature_,
                                                        admitted_owner_public_key_, authorized_session_,
                                                        authorized_controller_, fields)) {
        return Result::Rejected;
      }
      if (!::ota::storage::XiaoOtaCommandRecordV3::writeNext(*command_region_v3_, fields)) {
        return Result::IoError;
      }
    } else if (command_region_v2_ != nullptr && command_provider_v2_ != nullptr) {
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
    have_admitted_owner_public_key_ = false;
  }

  bool isActive() const { return active_; }
  bool isCommitted() const { return committed_; }
  bool haveVerifiedWireDescriptor() const { return have_verified_wire_; }
  bool haveAuthorizedSession() const { return have_authorized_session_; }
  bool haveAdmittedOwnerIdentity() const { return have_admitted_owner_public_key_; }
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
  ::ota::platform::FlashRegion* command_region_v3_ = nullptr;
  IOtaInstallCommandProviderV3* command_provider_v3_ = nullptr;
  uint8_t verified_wire_descriptor_[::ota::storage::XiaoOtaCommandRecordV2::kWireDescriptorBytes] = {};
  uint8_t verified_signature_[::ota::storage::XiaoOtaCommandRecordV2::kSignatureBytes] = {};
  meshcore::ota::runtime::OtaSessionId authorized_session_{};
  uint8_t authorized_controller_[32] = {};
  uint8_t admitted_owner_public_key_[32] = {};
  bool have_authorized_session_ = false;
  bool have_admitted_owner_public_key_ = false;
  bool have_verified_wire_ = false;
  meshcore::ota::protocol::OtaDescriptor descriptor_;
  bool active_ = false;
  bool committed_ = false;
};

// ESP32 uses vendor A/B boot selection, not the Nordic command journal.
// The final two sectors of the inactive application hold the ONE lean
// candidate record/bitmap; neither the active app nor SPIFFS/NVS is erased.
struct Esp32OtaPolicy {
  static constexpr uint16_t kFamily = 0x4553;
  static constexpr uint16_t kVariant = 0x5333;
  static constexpr uint32_t kAppAddress = 0x10000;
  static constexpr uint32_t kSlotBytes = 0x330000;
  static constexpr uint32_t kCandidateBytes = kSlotBytes - 8192;
  static constexpr uint32_t kMaxImageBytes = (4096u - 4u) * 8u * kOtaBlockMaxDataBytes;
  static constexpr uint32_t kCapabilities = 1;
  uint8_t role;
  uint32_t confirmedCounter = 0;

  bool accepts(const meshcore::ota::protocol::OtaDescriptor& d) const {
    return role <= 1 && d.boardFamily == kFamily && d.boardVariant == kVariant &&
           d.role == role && d.appAddress == kAppAddress &&
           d.exactSizeBytes != 0 && d.exactSizeBytes <= kCandidateBytes &&
           d.exactSizeBytes <= kMaxImageBytes &&
           d.minBootloaderCapabilities == kCapabilities &&
           d.formatId == 1 && d.keyId != 0 && d.algorithmId == 1 &&
           d.securityCounter > confirmedCounter;
  }
};

inline bool verifyEsp32CandidateProvenance(
    ::ota::storage::OtaCandidateStore& store, const Esp32OtaPolicy& policy,
    const ::ota::trust::SignatureVerifier& signatures,
    ::ota::storage::OtaCandidateStore::Snapshot& snapshot,
    meshcore::ota::protocol::OtaDescriptor& descriptor,
    ::ota::storage::OtaCandidateStore::Phase phase = ::ota::storage::OtaCandidateStore::Phase::Committed) {
  snapshot = ::ota::storage::OtaCandidateStore::Snapshot();
  descriptor = meshcore::ota::protocol::OtaDescriptor();
  const Esp32OtaPolicy image_policy{policy.role};
  return store.load(snapshot) && snapshot.phase == phase && !snapshot.localCache &&
         meshcore::ota::protocol::decodeOtaDescriptorCanonical(
             snapshot.canonical, sizeof(snapshot.canonical), descriptor) ==
             meshcore::ota::protocol::OtaDescriptorCodecResult::Ok &&
         image_policy.accepts(descriptor) && descriptor.exactSizeBytes == snapshot.exactSizeBytes &&
         snapshot.totalBlocks == (descriptor.exactSizeBytes + kOtaBlockMaxDataBytes - 1) / kOtaBlockMaxDataBytes &&
         snapshot.receivedBlocks == snapshot.totalBlocks &&
         signatures.verify(snapshot.signature, sizeof(snapshot.signature), snapshot.canonical,
                           sizeof(snapshot.canonical), snapshot.ownerPublicKey, sizeof(snapshot.ownerPublicKey));
}

inline bool verifyEsp32RunningCandidate(
    ::ota::storage::OtaCandidateStore& store, ::ota::platform::FlashRegion& image,
    const Esp32OtaPolicy& policy, const ::ota::trust::SignatureVerifier& signatures,
    ::ota::storage::OtaCandidateStore::Snapshot& snapshot,
    meshcore::ota::protocol::OtaDescriptor& descriptor) {
  if (!verifyEsp32CandidateProvenance(store, policy, signatures, snapshot, descriptor)) return false;
  ::ota::trust::Sha256 sha;
  uint8_t actual[32];
  return ::ota::trust::ImageHasher::hashRegion(sha, image, descriptor.exactSizeBytes, actual) &&
         std::memcmp(actual, descriptor.sha256, sizeof(actual)) == 0;
}

class Esp32OtaLease final : public ::ota::storage::Esp32UpdateOwner {
public:
  bool claimStorage() {
    uint8_t expected = kNone;
    return owner_.compare_exchange_strong(expected, kStorage) || expected == kStorage;
  }
  bool claimFreshStorage() {
    uint8_t expected = kNone;
    return owner_.compare_exchange_strong(expected, kStorage);
  }
  bool handoffToOrdinaryUpdater() {
    uint8_t expected = kStorage;
    return owner_.compare_exchange_strong(expected, kOrdinary);
  }
  bool claimOrdinaryUpdater() {
    uint8_t expected = kNone;
    return owner_.compare_exchange_strong(expected, kOrdinary);
  }
  void releaseStorage() { release(kStorage); }
  void releaseOrdinaryUpdater() { release(kOrdinary); }
  bool storageHeld() const { return owner_.load() == kStorage; }
  ::ota::storage::Esp32UpdateOwnership ownership(
      const ::ota::storage::Esp32PartitionIdentity&) const override {
    return storageHeld() ? ::ota::storage::Esp32UpdateOwnership::ExclusiveStorage
                        : ::ota::storage::Esp32UpdateOwnership::OtherUpdater;
  }
private:
  void release(uint8_t from) { owner_.compare_exchange_strong(from, kNone); }
  static constexpr uint8_t kNone = 0, kStorage = 1, kOrdinary = 2;
  std::atomic<uint8_t> owner_{kNone};
};

class Esp32OtaInstallApi {
public:
  virtual ~Esp32OtaInstallApi() = default;
  virtual bool validateImage(const ::ota::storage::Esp32PartitionIdentity& partition,
                             uint32_t exact_bytes) = 0;
  // The implementation MUST use esp_ota_set_boot_partition(), which validates
  // the app and writes redundant CRC-protected otadata with state NEW.
  virtual bool selectBoot(const ::ota::storage::Esp32PartitionIdentity& partition) = 0;
};

class Esp32OtaTrustProvider final : public meshcore::ota::runtime::IOtaTrustProvider {
public:
  Esp32OtaTrustProvider(const Esp32OtaPolicy& policy, ::ota::platform::FlashRegion& candidate)
      : policy_(policy), candidate_(candidate) {}
  bool verifyDescriptorSignature(const uint8_t*, size_t, const uint8_t*, size_t,
                                 uint16_t, uint16_t) override { return false; }
  bool verifyDescriptorPolicyOnly(const meshcore::ota::protocol::OtaDescriptor& d) override {
    return policy_.accepts(d);
  }
  bool verifyStagedImageHashPolicyOnly(const meshcore::ota::protocol::OtaDescriptor& d) override {
    // A USB uploader may cache another board/role's manifest; hash checking
    // must still cover those bytes. Installation separately requires policy.
    if (d.exactSizeBytes == 0 || d.exactSizeBytes > Esp32OtaPolicy::kMaxImageBytes ||
        !candidate_.isValid()) return false;
    ::ota::trust::Sha256 sha;
    uint8_t actual[32];
    return ::ota::trust::ImageHasher::hashRegion(sha, candidate_, d.exactSizeBytes, actual) &&
           std::memcmp(actual, d.sha256, sizeof(actual)) == 0;
  }
private:
  const Esp32OtaPolicy& policy_;
  ::ota::platform::FlashRegion& candidate_;
};

class Esp32OtaStagingSink final : public meshcore::ota::runtime::IOtaStagingSink {
public:
  using Store = ::ota::storage::OtaCandidateStore;
  enum class InstallOutcome : uint8_t { None, Selected, Refused, SelectionUncertain };
  // Outside the candidate bitmap's maximum accepted image coverage.
  static constexpr uint32_t kSelectionMarkerOffset = Store::kExpectedRegionBytes - 4;
  static constexpr uint8_t kSelectionMarker[4] = {0x53, 0x45, 0x4c, 0x31};

  Esp32OtaStagingSink(::ota::platform::Esp32FlashAdapter& flash, Esp32OtaLease& lease,
                      ::ota::platform::FlashRegion& candidate,
                      ::ota::platform::FlashRegion& metadata, Store& store,
                      Esp32OtaTrustProvider& trust, const Esp32OtaPolicy& policy,
                      const ::ota::trust::SignatureVerifier& signatures, Esp32OtaInstallApi& install)
      : flash_(flash), lease_(lease), candidate_(candidate), metadata_(metadata),
        store_(store), trust_(trust), policy_(policy), signatures_(signatures), install_(install) {}

  Result beginSession(const meshcore::ota::protocol::OtaDescriptor& d) override {
    if (!canStore(d) || installation_attempted_) return Result::Rejected;
    if (!lease_.claimStorage()) return Result::Rejected;
    if (!::ota::platform::isOk(flash_.bind(Esp32OtaPolicy::kSlotBytes))) return fault();
    const uint32_t erase = flash_.eraseUnitBytes();
    const uint32_t erase_bytes = ((d.exactSizeBytes + erase - 1) / erase) * erase;
    if (!::ota::platform::isOk(candidate_.eraseRange(0, erase_bytes))) return fault();
    descriptor_ = d;
    active_ = true;
    admitted_ = false;
    commit_requested_ = false;
    return Result::Ok;
  }
  Result resumeSession(const meshcore::ota::protocol::OtaDescriptor& d) override {
    if (!canStore(d) || installation_attempted_ || !lease_.claimStorage())
      return Result::Rejected;
    if (!::ota::platform::isOk(flash_.bind(Esp32OtaPolicy::kSlotBytes))) return fault();
    descriptor_ = d;
    active_ = true;
    admitted_ = false;
    commit_requested_ = false;
    return Result::Ok;
  }
  Result writeChunk(uint64_t offset, const uint8_t* bytes, size_t len) override {
    if (!active_ || commit_requested_ || installation_attempted_ || bytes == nullptr || len == 0 ||
        offset > descriptor_.exactSizeBytes || len > descriptor_.exactSizeBytes - offset)
      return Result::Rejected;
    if (!::ota::platform::isOk(candidate_.program(static_cast<uint32_t>(offset), bytes,
                                                static_cast<uint32_t>(len)))) return fault();
    uint8_t check[128];
    for (size_t done = 0; done < len;) {
      const size_t take = len - done < sizeof(check) ? len - done : sizeof(check);
      if (!::ota::platform::isOk(candidate_.read(static_cast<uint32_t>(offset + done),
                                                check, static_cast<uint32_t>(take))) ||
          std::memcmp(check, bytes + done, take) != 0) return fault();
      done += take;
    }
    return Result::Ok;
  }
  Result readChunk(uint64_t offset, uint8_t* out, size_t len) override {
    if (!active_ || out == nullptr || offset > descriptor_.exactSizeBytes ||
        len > descriptor_.exactSizeBytes - offset) return Result::Rejected;
    return ::ota::platform::isOk(candidate_.read(static_cast<uint32_t>(offset), out,
                                                static_cast<uint32_t>(len))) ? Result::Ok : fault();
  }
  void onAdmittedOwnerIdentity(const uint8_t owner[32]) override {
    admitted_ = owner != nullptr;
    if (admitted_) std::memcpy(admitted_owner_, owner, sizeof(admitted_owner_));
  }
  Result commit() override {
    Store::Snapshot durable;
    if (!active_ || installation_attempted_ || !admitted_ || !loadVerified(durable, Store::Phase::Ready) ||
        std::memcmp(admitted_owner_, durable.ownerPublicKey, sizeof(admitted_owner_)) != 0)
      return Result::Rejected;
    // Selection is deferred until the caller has durably appended Committed.
    // This is a recoverable handoff, not permission to install at READY.
    commit_requested_ = true;
    return Result::Ok;
  }
  void abort() override {
    active_ = false;
    admitted_ = false;
    commit_requested_ = false;
    // Keep the lease until the caller durably appends Aborted/clears bitmap.
  }
  InstallOutcome activateDurableCommit() {
    if (installation_attempted_ || !lease_.storageHeld()) return InstallOutcome::None;
    Store::Snapshot durable;
    if (!store_.load(durable) || durable.phase != Store::Phase::Committed) return InstallOutcome::None;
    uint8_t marker[4];
    if (!::ota::platform::isOk(metadata_.read(kSelectionMarkerOffset, marker, sizeof(marker))))
      return refused();
    // A cut AFTER recording this marker but BEFORE/during vendor selection
    // leaves the previous app bootable. Never auto-retry a rolled-back trial.
    // A new signed reupload/COMMIT is required for an uncertain attempt.
    for (uint8_t byte : marker) if (byte != 0xff) return refused();
    if (!loadVerified(durable, Store::Phase::Committed)) return refused();
    if (!::ota::platform::isOk(metadata_.program(kSelectionMarkerOffset, kSelectionMarker, 4)) ||
        !::ota::platform::isOk(metadata_.read(kSelectionMarkerOffset, marker, sizeof(marker))) ||
        std::memcmp(marker, kSelectionMarker, 4) != 0) return refused();
    installation_attempted_ = true;
    // No further flash/metadata access after the boot slot changes.
    return install_.selectBoot(flash_.partition()) ? InstallOutcome::Selected
                                                   : InstallOutcome::SelectionUncertain;
  }
  bool recoverUnsuccessfulSelection() {
    Store::Snapshot s;
    if (!store_.load(s)) return false;
    if (s.phase != Store::Phase::Committed) return true;
    uint8_t marker[4];
    // This read revalidates boot==running and absence of NEW/PENDING_VERIFY:
    // only the safe previous application can retire a failed trial.
    if (!::ota::platform::isOk(metadata_.read(kSelectionMarkerOffset, marker, 4))) return false;
    bool attempted = false;
    for (uint8_t byte : marker) attempted |= byte != 0xff;
    if (!attempted) return true;
    s.phase = Store::Phase::Failed;
    return store_.append(s);
  }
  bool storageIoFaultObserved() const { return io_fault_; }

private:
  static bool canStore(const meshcore::ota::protocol::OtaDescriptor& d) {
    return d.exactSizeBytes != 0 && d.exactSizeBytes <= Esp32OtaPolicy::kCandidateBytes &&
           d.exactSizeBytes <= Esp32OtaPolicy::kMaxImageBytes;
  }
  bool loadVerified(Store::Snapshot& s, Store::Phase phase) {
    if (!store_.load(s) || !s.valid || s.localCache || s.phase != phase) return false;
    meshcore::ota::protocol::OtaDescriptor d;
    if (meshcore::ota::protocol::decodeOtaDescriptorCanonical(s.canonical, sizeof(s.canonical), d) !=
        meshcore::ota::protocol::OtaDescriptorCodecResult::Ok || !policy_.accepts(d) ||
        s.exactSizeBytes != d.exactSizeBytes ||
        s.totalBlocks != (d.exactSizeBytes + kOtaBlockMaxDataBytes - 1) / kOtaBlockMaxDataBytes ||
        s.receivedBlocks != s.totalBlocks ||
        !signatures_.verify(s.signature, sizeof(s.signature), s.canonical, sizeof(s.canonical),
                            s.ownerPublicKey, sizeof(s.ownerPublicKey)) ||
        !trust_.verifyStagedImageHashPolicyOnly(d)) return false;
    return install_.validateImage(flash_.partition(), d.exactSizeBytes);
  }
  Result fault() { io_fault_ = true; return Result::IoError; }
  InstallOutcome refused() { installation_attempted_ = true; return InstallOutcome::Refused; }
  ::ota::platform::Esp32FlashAdapter& flash_;
  Esp32OtaLease& lease_;
  ::ota::platform::FlashRegion& candidate_;
  ::ota::platform::FlashRegion& metadata_;
  Store& store_;
  Esp32OtaTrustProvider& trust_;
  const Esp32OtaPolicy& policy_;
  const ::ota::trust::SignatureVerifier& signatures_;
  Esp32OtaInstallApi& install_;
  meshcore::ota::protocol::OtaDescriptor descriptor_;
  uint8_t admitted_owner_[32] = {};
  bool active_ = false, admitted_ = false, commit_requested_ = false;
  bool io_fault_ = false, installation_attempted_ = false;
};

}  // namespace ota
}  // namespace mesh
