#pragma once

#include <stdint.h>
#include <string.h>

// Typed evidence interfaces for the two authority concepts Astra's
// startup decision introduces, neither of which is wired to any call
// site in THIS firmware yet -- populating/verifying a REAL instance of
// either (a genuine out-of-band commissioning/manufacturing signature,
// or a genuine host-tool challenge/response) is a SEPARATE OWNER's
// responsibility. Both evaluator functions below are deliberately
// default-deny: with no real verifier wired in, they always report
// insufficient evidence, so this firmware never fabricates a positive
// result while that authority doesn't exist yet -- "honestly stay
// Unknown, no fake permissive provider."
namespace mesh {
namespace ota {

// "CertifyExistingBaseline" evidence: the ONLY thing that can ever turn
// a blank/uncertified stock board's classification from Unknown into a
// positive Normal (see OtaBoardQualificationStatus in
// OtaBoardBackendCommon.h) -- a separately signed record binding the
// full device UID, the full (not merely prefix) public key, role,
// layout, the CURRENT image's SHA-256 + extent + SDK, and a positively
// identified stock-loader executable range/hash + boot config. A blank
// BOOTINFO record alone is explicitly NOT this evidence.
//
// `device_uid` is the nRF52840's FULL FICR DEVICEID, canonical
// big-endian 8 bytes: UID = (DEVICEID[1] << 32) | DEVICEID[0], encoded
// BE so device_uid[0..3] = DEVICEID[1] (BE32) and device_uid[4..7] =
// DEVICEID[0] (BE32). This MUST be the cross-owner-agreed exact 8-byte
// value the authority side's AuthorityBinding::hardwareUid also carries
// -- never truncated, hashed, or derived from a differently-sized value,
// and never zero-padded to "match" a mismatched width. ESP32 and any
// future mixed/multi-chip UID encodings are explicitly a separately
// typed future profile, out of scope for this first nRF52840 profile.
struct OtaBaselineCertificationEvidence {
  static constexpr size_t kDeviceUidBytes = 8;
  uint8_t device_uid[kDeviceUidBytes] = {0};
  uint8_t full_public_key[32] = {0};
  uint32_t role_id = 0;
  uint32_t layout_id = 0;
  uint8_t current_image_sha256[32] = {0};
  uint32_t current_image_extent = 0;
  // Exact SHA-256 digest (32 bytes) of the device's actual CURRENT SDK
  // build/config SETTINGS -- NOT a bare version integer, and NOT a hash
  // of compiler/toolchain binary bytes. A u32 "version" can't prove
  // which exact SDK settings produced the approved image, and hashing
  // the compiler itself doesn't tell you what the *device* was actually
  // configured/built with. This is a genuine LOCAL measurement, taken
  // fresh each baseline job via
  // IOtaBaselineMeasurementSource::readCurrentSdkDigest() (see
  // OtaBaselineMeasurementCollector.h's local measured adapter) -- never
  // a copied/precomputed constant. The authority side's manifest must
  // bind against this same full digest if it is ever compared here.
  uint8_t original_sdk_sha256[32] = {0};
  uint8_t stock_loader_hash[32] = {0};
  uint32_t stock_loader_range_start = 0;
  uint32_t stock_loader_range_length = 0;
  uint32_t boot_config_id = 0;
  // Signature (e.g. Ed25519) over the canonical encoding of every field
  // above, from the (not-yet-implemented) baseline-certification
  // authority. `signature_present` is false by default/absent evidence.
  uint8_t signature[64] = {0};
  bool signature_present = false;
};

enum class OtaBaselineCertificationOutcome { InsufficientEvidence, Certified };

// A future owner's REAL verifier: must perform genuine signature
// verification over the canonical byte encoding of `evidence`'s fields
// -- never trusted based on the struct's mere presence/shape alone.
using BaselineSignatureVerifier = bool (*)(const OtaBaselineCertificationEvidence& evidence);

// Default-deny: with `verifier == nullptr` (the only case reachable
// today -- no call site constructs/passes a real one) or an absent
// signature, always reports InsufficientEvidence.
inline OtaBaselineCertificationOutcome evaluateBaselineCertification(
    const OtaBaselineCertificationEvidence& evidence,
    BaselineSignatureVerifier verifier = nullptr) {
  if (!evidence.signature_present || verifier == nullptr) {
    return OtaBaselineCertificationOutcome::InsufficientEvidence;
  }
  if (!verifier(evidence)) return OtaBaselineCertificationOutcome::InsufficientEvidence;
  return OtaBaselineCertificationOutcome::Certified;
}

// Host challenge-bound per-boot USB certificate evidence: a FRESH,
// per-boot proof (never a static/replayable token) from a legitimate
// host tool. If ever genuinely verified, this can unlock ORDINARY
// EXISTING-USERDATA behaviour (continuing to use an already-persisted
// identity/prefs/contacts, read-only, for this boot) while the board
// remains otherwise Unknown/uncertified. It must NEVER seed a counter,
// generate/replace an identity, or grant install authority -- those
// stay exclusively gated by the OTA trust chain regardless of this
// outcome.
struct OtaHostBootCertificateEvidence {
  uint8_t challenge_nonce[16] = {0};
  uint8_t host_signature[64] = {0};
  bool signature_present = false;
};

enum class OtaHostBootCertificateOutcome { InsufficientEvidence, Unlocked };

using HostBootCertificateVerifier = bool (*)(const OtaHostBootCertificateEvidence& evidence);

// Default-deny, same rationale as evaluateBaselineCertification() above.
inline OtaHostBootCertificateOutcome evaluateHostBootCertificate(
    const OtaHostBootCertificateEvidence& evidence,
    HostBootCertificateVerifier verifier = nullptr) {
  if (!evidence.signature_present || verifier == nullptr) {
    return OtaHostBootCertificateOutcome::InsufficientEvidence;
  }
  if (!verifier(evidence)) return OtaHostBootCertificateOutcome::InsufficientEvidence;
  return OtaHostBootCertificateOutcome::Unlocked;
}

}  // namespace ota
}  // namespace mesh
