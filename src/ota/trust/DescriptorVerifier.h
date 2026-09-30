#pragma once

// Canonical descriptor verification pipeline: SHA-256 image hash, Ed25519
// signature, target/role/address match, boot capability, and monotonic
// (anti-rollback) counter -- all fail-closed, with no permissive default.
//
// Every check in `verifyDescriptor` and `verifyImageBytes` is a positive
// assertion that must explicitly succeed; there is no code path that
// returns VerificationResult::pass() without every relevant check having
// run and matched. If any dependency (hasher, signature verifier, region
// read) reports an error, the result is a failure, never a pass.

#include <stdint.h>
#include <cstring>

#include "ota/platform/FlashRegion.h"
#include "ota/trust/TrustTypes.h"
#include "ota/trust/HashAlgorithm.h"
#include "ota/trust/SignatureVerifier.h"
#include "ota/trust/MonotonicCounter.h"
#include "ota/trust/CanonicalDescriptor.h"
#include "ota/trust/ImageHasher.h"

namespace ota {
namespace trust {

class DescriptorVerifier {
public:
  DescriptorVerifier(HashAlgorithm& hasher, SignatureVerifier& signature_verifier,
                      MonotonicCounter& counter, const DeviceTrustAnchor& anchor)
      : hasher_(hasher), signature_verifier_(signature_verifier), counter_(counter), anchor_(anchor) {}

  // Verifies everything about the descriptor EXCEPT the actual image bytes
  // (signature over the canonical fields, target/role/address, boot
  // capability, anti-rollback counter). Call `verifyImageBytes` separately
  // once the candidate image is fully staged, since recomputing a SHA-256
  // over up to ~800 KiB of flash is comparatively expensive and callers may
  // want to reject an obviously-wrong descriptor before touching flash at
  // all.
  VerificationResult verifyDescriptor(const ImageDescriptor& descriptor) const {
    if (descriptor.image_size_bytes == 0) {
      return VerificationResult::fail(TrustFailureReason::MalformedDescriptor);
    }

    uint8_t message[CanonicalDescriptor::kMessageBytes];
    const size_t written = CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
    if (written != CanonicalDescriptor::kMessageBytes) {
      return VerificationResult::fail(TrustFailureReason::MalformedDescriptor);
    }

    // Signature check uses ONLY the anchor's trusted key -- the descriptor
    // never supplies its own signer key (see TrustTypes.h).
    const bool signature_ok = signature_verifier_.verify(
        descriptor.signature_ed25519, sizeof(descriptor.signature_ed25519), message, written,
        anchor_.trusted_signer_public_key_ed25519, sizeof(anchor_.trusted_signer_public_key_ed25519));
    if (!signature_ok) {
      return VerificationResult::fail(TrustFailureReason::SignatureInvalid);
    }

    return verifyPolicy(descriptor);
  }

  // Verifies all receiver-local descriptor policy after an external caller
  // has authenticated a different canonical representation of the same
  // fields (for example, the OTA protocol's canonical wire descriptor).
  VerificationResult verifyPolicy(const ImageDescriptor& descriptor) const {
    if (descriptor.image_size_bytes == 0) {
      return VerificationResult::fail(TrustFailureReason::MalformedDescriptor);
    }

    if (descriptor.target_id != anchor_.expected_target_id) {
      return VerificationResult::fail(TrustFailureReason::TargetMismatch);
    }
    if (descriptor.role_id != anchor_.expected_role_id) {
      return VerificationResult::fail(TrustFailureReason::RoleMismatch);
    }

    // Address binding: the descriptor must either name this exact device,
    // or explicitly opt into broadcast -- there is no implicit wildcard.
    if (!descriptor.allow_broadcast_address && descriptor.device_address != anchor_.device_address) {
      return VerificationResult::fail(TrustFailureReason::AddressMismatch);
    }

    // Boot capability: every capability the image requires must be present
    // in what this device's bootloader actually supports.
    if ((descriptor.required_boot_capability_flags & ~anchor_.supported_boot_capability_flags) != 0u) {
      return VerificationResult::fail(TrustFailureReason::BootCapabilityMissing);
    }

    // Anti-rollback: the new counter must be STRICTLY greater than the
    // currently committed value. A counter read failure fails closed.
    uint32_t current_counter = 0;
    if (!counter_.currentValue(current_counter)) {
      return VerificationResult::fail(TrustFailureReason::Unsupported);
    }
    if (descriptor.monotonic_counter <= current_counter) {
      return VerificationResult::fail(TrustFailureReason::CounterNotStrictlyIncreasing);
    }

    return VerificationResult::pass();
  }

  // Recomputes SHA-256 over `descriptor.image_size_bytes` bytes of
  // `candidate_region` and compares it against the descriptor's claimed
  // hash. This is intentionally independent of the descriptor's own
  // `image_size_bytes` bookkeeping being trustworthy: a mismatched region
  // size is itself a failure.
  VerificationResult verifyImageBytes(const ImageDescriptor& descriptor, const platform::FlashRegion& candidate_region) const {
    if (descriptor.image_size_bytes > candidate_region.sizeBytes()) {
      return VerificationResult::fail(TrustFailureReason::ImageSizeMismatch);
    }

    uint8_t computed_hash[32];
    if (!ImageHasher::hashRegion(hasher_, candidate_region, descriptor.image_size_bytes, computed_hash)) {
      return VerificationResult::fail(TrustFailureReason::Unsupported);
    }

    if (std::memcmp(computed_hash, descriptor.image_hash_sha256, 32) != 0) {
      return VerificationResult::fail(TrustFailureReason::ImageHashMismatch);
    }

    return VerificationResult::pass();
  }

  // Convenience: runs both stages, only advancing to the (more expensive)
  // image-byte hash if the metadata/signature stage passed.
  VerificationResult verifyAll(const ImageDescriptor& descriptor, const platform::FlashRegion& candidate_region) const {
    VerificationResult metadata_result = verifyDescriptor(descriptor);
    if (!metadata_result.ok) {
      return metadata_result;
    }
    return verifyImageBytes(descriptor, candidate_region);
  }

  // Commits the descriptor's monotonic counter as the new floor. Callers
  // must only invoke this AFTER the corresponding image has been fully
  // installed and confirmed (see BootTransaction), never merely after
  // `verifyAll` passes, so that a device that never actually boots the new
  // image cannot be locked out of retrying the same or an older-but-still-
  // valid campaign.
  bool commitCounter(const ImageDescriptor& descriptor) {
    return counter_.commitNewValue(descriptor.monotonic_counter);
  }

  bool counterAtLeast(uint32_t value) const {
    uint32_t current_counter = 0;
    return counter_.currentValue(current_counter) && current_counter >= value;
  }

  bool currentCounterValue(uint32_t& out) const {
    return counter_.currentValue(out);
  }

private:
  HashAlgorithm& hasher_;
  SignatureVerifier& signature_verifier_;
  MonotonicCounter& counter_;
  DeviceTrustAnchor anchor_;
};

}  // namespace trust
}  // namespace ota
