#pragma once

// Closes the real, confirmed gap flagged in review: embedding the
// original issuer-signed AuthorityTransaction inside ActivationPermit
// (see AuthorityDeviceSession.h) re-verifies that a genuine issuer
// produced the GRANT, but that signature covers only the 174-byte
// AuthorityCodec signed message -- it says NOTHING about activation
// purpose, freshness, or whether the host's own two-copy
// ActivationSpent gate was ever actually reached. A grant's signed
// bytes (transactionId, manifestDigestSha256, etc.) are already visible
// in cleartext from the earlier prepare() exchange; without something
// MORE, an attacker able to reach a device's activation path could
// replay the SAME authentic grant as "proof of activation" at a moment
// when the host registries are still only Issued/ConsumedPrepared, not
// ActivationSpent.
//
// ActivationAuthorizationV1 is a SEPARATE, purpose-bound signed object,
// produced by the HOST ONLY at the moment BOTH registry copies have been
// independently confirmed ActivationSpent (see
// AuthorityCoordinator::activateExistingRoot), and verified by the
// device under a DISTINCT domain-separated message. Domain separation
// (a different literal domain string, hashed as part of what is
// signed) is what makes a grant-only signature cryptographically
// impossible to present as valid activation-authorization proof -- not
// merely a semantic/type distinction a caller could bypass by tagging
// the wrong struct.
//
// Signed using the SAME EXISTING issuer key identified by
// AuthorityTransaction::issuerKeyId -- this file creates NO new
// production key. AuthorityActivationSigningTrust below is an explicit,
// separately-wired abstract seam (default-deny: AuthorityCoordinator
// denies activateExistingRoot outright if none is wired) that a real
// integrator (MAIN/Store) wires to whatever mechanism holds/uses that
// issuer key online (e.g. an HSM-backed signer used by the live
// commissioning tool) -- necessarily distinct from the OFFLINE
// grant-signing tool (scripts/ota_authority_registry.py) that produces
// AuthorityTransaction itself, since that tool need not be online at
// activation time.

#include <stdint.h>
#include <stddef.h>
#include <cstring>
#include "ota/authority/AuthorityTypes.h"
#include "ota/authority/AuthorityCodec.h"
#include "ota/protocol/OtaByteStream.h"

namespace ota {
namespace authority {

// Bound to the EXACT moment the host observed both copies durably
// ActivationSpent for `transactionId` / `expectedBinding` /
// `preparedRootDigestSha256`. `hostNonce` is independent, freshly
// generated host entropy -- distinct from `deviceFreshChallenge` (the
// same per-session challenge also carried in
// ActivationPermit::hostChallenge) -- specifically so this signature
// can never be precomputed/cached ahead of the Spent gate being reached:
// a host that tried to sign this before both copies were durably Spent
// would have to guess a `hostNonce` value it has not chosen yet.
struct ActivationAuthorizationV1 {
  uint8_t transactionId[kTransactionIdBytes] = {0};
  uint8_t grantDigestSha256[kDigestBytes] = {0};           // Astra29 fix: == A == SHA256(the EXACT
                                                            // AuthorityCodec::kRecordBytes signed grant RECORD,
                                                            // INCLUDING the issuer signature) -- see
                                                            // AuthorityCodec::computeRecordDigestSha256. NOT
                                                            // txn.manifestDigestSha256 (M, the manifest's OWN policy
                                                            // digest) -- binding to M was a confirmed bug that let
                                                            // ANY grant whose manifest happened to match satisfy
                                                            // this check regardless of transaction identity.
  uint8_t preparedRootDigestSha256[kDigestBytes] = {0};    // R: the registry's ACTUALLY-recorded ActivationSpent root,
                                                            // genuinely produced by the device's own stageRoot() during
                                                            // the prepare handshake -- never assumed equal to
                                                            // grantDigestSha256 (A) or manifestDigestSha256 (M); see
                                                            // PreparedRootCommitment.h and AuthorityTypes.h.
  uint32_t spentAuthorizedRevision = 0;                    // txn.revision, AT the moment both copies reached ActivationSpent.
  AuthorityBinding expectedBinding;                        // Full binding this authorization is scoped to; substituting
                                                            // any single field invalidates the signature (see
                                                            // AuthorityCodec::writeBindingFields, reused verbatim here).
  uint8_t deviceFreshChallenge[kChallengeBytes] = {0};     // Same value as this attempt's ActivationPermit::hostChallenge.
  uint8_t hostNonce[kChallengeBytes] = {0};                // Independent fresh host entropy; see freshness note above.
  uint8_t issuerSignatureEd25519[kSignatureBytes] = {0};
};

enum class ActivationAuthorizationDecodeError : uint8_t {
  None = 0,
  TooShort = 1,
  TooLong = 2,
  InvalidCryptoForm = 3,
  InvalidGroupSelectorForPairwise = 4,
};

class ActivationAuthorizationCodec {
public:
  // txnId(16) + grantDigest(32) + preparedRoot(32) + revision(4) +
  // AuthorityCodec::kBindingBytes(87) + deviceFreshChallenge(16) +
  // hostNonce(16) = 203 bytes.
  static constexpr size_t kBodyBytes = 203;
  static constexpr size_t kRecordBytes = kBodyBytes + kSignatureBytes;  // 267.

  static const char* signedDomain() { return "MeshCore/OTA/activate-existing-root/v1"; }
  static constexpr size_t kSignedDomainBytes = 38;  // strlen(signedDomain()), NUL excluded -- verified via Python len().
  static constexpr size_t kSignedMessageBytes = kSignedDomainBytes + kBodyBytes;  // 241.

  static size_t serializeBody(const ActivationAuthorizationV1& a, uint8_t* out, size_t out_len) {
    meshcore::ota::protocol::OtaBoundedWriter w(out, out_len);
    if (!w.putBytes(a.transactionId, kTransactionIdBytes)) return 0;
    if (!w.putBytes(a.grantDigestSha256, kDigestBytes)) return 0;
    if (!w.putBytes(a.preparedRootDigestSha256, kDigestBytes)) return 0;
    if (!w.putU32(a.spentAuthorizedRevision)) return 0;
    if (!AuthorityCodec::writeBindingFields(w, a.expectedBinding)) return 0;
    if (!w.putBytes(a.deviceFreshChallenge, kChallengeBytes)) return 0;
    if (!w.putBytes(a.hostNonce, kChallengeBytes)) return 0;
    return w.size();
  }

  static size_t serializeRecord(const ActivationAuthorizationV1& a, uint8_t* out, size_t out_len) {
    meshcore::ota::protocol::OtaBoundedWriter w(out, out_len);
    uint8_t body[kBodyBytes];
    if (serializeBody(a, body, sizeof(body)) != kBodyBytes) return 0;
    if (!w.putBytes(body, kBodyBytes)) return 0;
    if (!w.putBytes(a.issuerSignatureEd25519, kSignatureBytes)) return 0;
    return w.size();
  }

  // Builds the exact domain-separated message the signature covers:
  // signedDomain() || canonical body. Never includes the signature
  // itself.
  static size_t serializeSignedMessage(const ActivationAuthorizationV1& a, uint8_t* out, size_t out_len) {
    meshcore::ota::protocol::OtaBoundedWriter w(out, out_len);
    if (!w.putBytes(reinterpret_cast<const uint8_t*>(signedDomain()), kSignedDomainBytes)) return 0;
    uint8_t body[kBodyBytes];
    if (serializeBody(a, body, sizeof(body)) != kBodyBytes) return 0;
    if (!w.putBytes(body, kBodyBytes)) return 0;
    return w.size();
  }

  // Fails closed on any malformed/truncated/wrong-length input, never
  // partially populating `out`.
  static ActivationAuthorizationDecodeError parseRecord(const uint8_t* in, size_t in_len, ActivationAuthorizationV1& out) {
    if (in_len < kRecordBytes) return ActivationAuthorizationDecodeError::TooShort;
    if (in_len > kRecordBytes) return ActivationAuthorizationDecodeError::TooLong;

    ActivationAuthorizationV1 parsed;
    meshcore::ota::protocol::OtaBoundedReader reader(in, kRecordBytes);

    if (!reader.getBytes(parsed.transactionId, kTransactionIdBytes)) return ActivationAuthorizationDecodeError::TooShort;
    if (!reader.getBytes(parsed.grantDigestSha256, kDigestBytes)) return ActivationAuthorizationDecodeError::TooShort;
    if (!reader.getBytes(parsed.preparedRootDigestSha256, kDigestBytes)) return ActivationAuthorizationDecodeError::TooShort;

    uint32_t revision = 0;
    if (!reader.getU32(revision)) return ActivationAuthorizationDecodeError::TooShort;
    parsed.spentAuthorizedRevision = revision;

    const AuthorityDecodeError binding_error = AuthorityCodec::readBindingFields(reader, parsed.expectedBinding);
    if (binding_error == AuthorityDecodeError::InvalidCryptoForm) return ActivationAuthorizationDecodeError::InvalidCryptoForm;
    if (binding_error == AuthorityDecodeError::InvalidGroupSelectorForPairwise) {
      return ActivationAuthorizationDecodeError::InvalidGroupSelectorForPairwise;
    }
    if (binding_error != AuthorityDecodeError::None) return ActivationAuthorizationDecodeError::TooShort;

    if (!reader.getBytes(parsed.deviceFreshChallenge, kChallengeBytes)) return ActivationAuthorizationDecodeError::TooShort;
    if (!reader.getBytes(parsed.hostNonce, kChallengeBytes)) return ActivationAuthorizationDecodeError::TooShort;
    if (!reader.getBytes(parsed.issuerSignatureEd25519, kSignatureBytes)) return ActivationAuthorizationDecodeError::TooShort;

    out = parsed;
    return ActivationAuthorizationDecodeError::None;
  }
};

// Abstract, explicit signing seam for producing an
// ActivationAuthorizationV1 signature using the EXISTING issuer key
// identified by `issuerKeyId` -- NOT a new production key. Default-deny:
// AuthorityCoordinator::activateExistingRoot returns
// AuthorityOutcome::Denied outright if none is wired, rather than ever
// falling back to reusing/re-exporting the original grant signature.
class AuthorityActivationSigningTrust {
public:
  virtual ~AuthorityActivationSigningTrust() = default;
  virtual bool signActivationAuthorization(uint16_t issuerKeyId, const uint8_t* message, size_t message_len,
                                            uint8_t out_signature[kSignatureBytes]) = 0;
};

}  // namespace authority
}  // namespace ota
