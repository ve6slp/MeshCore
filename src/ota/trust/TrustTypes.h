#pragma once

// Canonical, platform-independent trust data types for the OTA image
// descriptor pipeline. An `ImageDescriptor` is the signed metadata record
// that accompanies a candidate firmware image; a `DeviceTrustAnchor` is the
// set of values a specific device is willing to trust when checking one.

#include <stdint.h>
#include <cstring>

namespace ota {
namespace trust {

// The set of checks the canonical verification pipeline performs, and the
// specific reason a verification failed. `None` is only ever used to mean
// "no failure" alongside `ok == true`; it must never be treated as an
// implicit pass on its own.
enum class TrustFailureReason : uint8_t {
  None = 0,
  MalformedDescriptor = 1,
  ImageHashMismatch = 2,
  SignatureInvalid = 3,
  TargetMismatch = 4,
  RoleMismatch = 5,
  AddressMismatch = 6,
  BootCapabilityMissing = 7,
  CounterNotStrictlyIncreasing = 8,
  ImageSizeMismatch = 9,
  Unsupported = 10,
  FormatIdMismatch = 11,
  KeyIdMismatch = 12,
  AlgorithmIdMismatch = 13,
};

struct VerificationResult {
  bool ok = false;
  TrustFailureReason reason = TrustFailureReason::Unsupported;

  static VerificationResult pass() { return VerificationResult{true, TrustFailureReason::None}; }
  static VerificationResult fail(TrustFailureReason r) { return VerificationResult{false, r}; }
};

// The signed, canonical descriptor for a candidate image. This struct's
// layout is NOT used directly as the wire/signing format (see
// CanonicalDescriptor.h for the explicit, fixed-width serialization); it is
// the in-memory representation the verification pipeline operates on.
//
// Deliberately absent: an embedded "signer public key" field. Trusting a
// key the descriptor itself supplies would let an attacker simply embed
// their own key and self-sign; the only key ever used to verify a
// descriptor's signature is the one baked into this device's
// `DeviceTrustAnchor`.
struct ImageDescriptor {
  uint8_t image_hash_sha256[32] = {0};
  uint8_t signature_ed25519[64] = {0};

  uint32_t target_id = 0;
  uint32_t role_id = 0;
  uint64_t device_address = 0;         // 0 means "no specific device", only valid if anchor explicitly allows broadcast
  bool allow_broadcast_address = false;

  uint32_t required_boot_capability_flags = 0;
  uint32_t monotonic_counter = 0;
  uint32_t image_size_bytes = 0;
  uint32_t app_address = 0;
  uint16_t format_id = 0;
  uint16_t key_id = 0;
  uint16_t algorithm_id = 0;
};

// What THIS device is willing to accept. Populated once at boot from
// provisioned/immutable device identity; never derived from the descriptor
// being checked.
struct DeviceTrustAnchor {
  uint8_t trusted_signer_public_key_ed25519[32] = {0};
  uint32_t expected_target_id = 0;
  uint32_t expected_role_id = 0;
  uint64_t device_address = 0;
  uint32_t supported_boot_capability_flags = 0;  // bitmask of capabilities this device's bootloader actually has

  // The exact (formatId, keyId, algorithmId) triple this device's boot
  // policy trusts. A descriptor claiming any other value must be
  // rejected BEFORE any flash write, even if its signature verifies
  // against `trusted_signer_public_key_ed25519` -- otherwise a
  // differently-keyed/algorithm-tagged-but-still-verifiable descriptor
  // could slip past intent-level policy (e.g. a lab STAGING_ONLY key
  // being accepted on a qualified-production device, or vice versa).
  // 0 in any of these fields is a valid, explicit configured value (not
  // "unset"/"don't care") -- callers MUST populate all three from the
  // device's actual boot-marker-qualified or lab STAGING_ONLY identity.
  uint16_t expected_format_id = 0;
  uint16_t expected_key_id = 0;
  uint16_t expected_algorithm_id = 0;
};

}  // namespace trust
}  // namespace ota
