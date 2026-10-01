#pragma once

// Wire-shaped permit/response types exchanged between the host
// AuthorityCoordinator and a real device commissioning session, plus the
// abstract session interface itself. There is deliberately no production
// implementation of DeviceAuthoritySession here: wiring this to an actual
// USB/serial commissioning transport is MAIN's later integration step.
// Keeping it abstract and unimplemented is the explicit intent, not an
// oversight -- see the top-level task scope.

#include <stdint.h>
#include <cstring>
#include "ota/authority/AuthorityTypes.h"
#include "ota/authority/ActivationAuthorizationCodec.h"
#include "ota/authority/PrepareAuthorizationCodec.h"

namespace ota {
namespace authority {

// Which in-flight operation a device-minted challenge was drawn for.
// Astra Sol fix: a single device-side outstanding-challenge slot is
// shared across Prepare/Activate requests for the same session, so the
// purpose must be bound into both the mint and the consume check --
// otherwise a challenge minted for one purpose could be presented back
// to authorize the other.
enum class AuthorityChallengePurpose : uint8_t { Prepare = 0, Activate = 1 };

// Sent to the device to authorize STAGING exactly one permitted root.
// `auth` is a separate, purpose-bound, issuer-signed
// PrepareAuthorizationV1 (see PrepareAuthorizationCodec.h) bound to a
// challenge the DEVICE ITSELF minted for this exact
// (session, Prepare-purpose, A, inputDigest) tuple -- never a bare
// host-chosen value the host could predict/replay. The device must NOT
// enable encryption/sequence issuance/RX dispatch in response to this
// alone.
struct PreparePermit {
  AuthorityTransaction txn;
  PrepareAuthorizationV1 auth;
};

// The device's genuine, freshly-signed acknowledgement that it staged
// EXACTLY the permitted root. `deviceNonce` is the device's OWN
// contributed entropy (never supplied by the host), so freshness does not
// depend solely on the host's challenge being unpredictable.
struct PreparedRootResponse {
  uint8_t deviceNonce[kChallengeBytes] = {0};
  uint8_t rootDigestSha256[kDigestBytes] = {0};
  uint8_t deviceSignatureEd25519[kSignatureBytes] = {0};
};

// Sent to the device to authorize activating an ALREADY-staged root --
// never a fresh seed. Carries the FULL issuer-signed grant transaction
// (not just a bare transactionId/digest pair) AND a separate,
// domain-separated `activationAuth` proof (see
// ActivationAuthorizationCodec.h).
//
// IMPORTANT, CORRECTED STATUS (do not overclaim): embedding `txn` alone
// re-verifies that a genuine issuer produced the ORIGINAL GRANT, but
// that grant signature covers only the 174-byte AuthorityCodec message
// and says nothing about activation purpose/freshness/Spent-state --
// its bytes are already visible in cleartext from the earlier prepare()
// exchange, so a captured, perfectly authentic grant signature alone
// would previously have been replayable as "activation proof" before the
// host's own two-copy ActivationSpent gate was genuinely reached. The
// REAL closure of that gap is `activationAuth`: a separate signature,
// produced by the host ONLY at the moment both copies are confirmed
// ActivationSpent, under a domain string exclusive to this purpose, over
// a message that binds transactionId/grantDigest/preparedRootDigest/
// expectedBinding/deviceFreshChallenge/a fresh hostNonce. Domain
// separation makes a grant-only (or prepare-purpose) signature
// cryptographically unusable here, not merely a type/semantic check a
// caller could bypass by mislabeling a struct.
//
// `preparedRootDigestSha256` is the exact root the HOST registry
// recorded as ActivationSpent (R, genuinely produced by the device's own
// stageRoot() during the earlier prepare handshake -- AuthorityTransaction
// no longer carries any issuer-precommitted root field, see
// AuthorityTypes.h); the device checks it equals its own locally staged
// root (DeviceAuthorityState::stagedRootDigestSha256) and the
// independently verified `activationAuth.preparedRootDigestSha256`.
// `activationAuth.deviceFreshChallenge` IS the device-minted challenge
// for this activation (no separate bare `hostChallenge` field any more
// -- that was the caller-echo gap: a device could not previously
// distinguish a genuinely device-issued challenge from one the host
// simply copied back to itself).
struct ActivationPermit {
  AuthorityTransaction txn;
  uint8_t preparedRootDigestSha256[kDigestBytes] = {0};
  ActivationAuthorizationV1 activationAuth;
};

struct ActivationResponse {
  uint8_t deviceNonce[kChallengeBytes] = {0};
  uint8_t deviceSignatureEd25519[kSignatureBytes] = {0};
};

// Canonical messages the device's Ed25519 signature actually covers, so
// both the host coordinator and any device-side implementation build the
// identical bytes. `tag` disambiguates a prepare-ack from an activation-
// ack so one can never be replayed as the other.
class AuthorityAckCodec {
public:
  static constexpr uint8_t kTagPrepare = 0xA1;
  static constexpr uint8_t kTagActivate = 0xA2;
  static constexpr size_t kMessageBytes = kChallengeBytes + kChallengeBytes + kTransactionIdBytes + kDigestBytes + 1;

  static size_t serializePrepareAck(const uint8_t hostChallenge[kChallengeBytes], const uint8_t deviceNonce[kChallengeBytes],
                                     const uint8_t transactionId[kTransactionIdBytes], const uint8_t rootDigest[kDigestBytes],
                                     uint8_t* out, size_t out_len) {
    return serialize(hostChallenge, deviceNonce, transactionId, rootDigest, kTagPrepare, out, out_len);
  }

  static size_t serializeActivateAck(const uint8_t hostChallenge[kChallengeBytes], const uint8_t deviceNonce[kChallengeBytes],
                                      const uint8_t transactionId[kTransactionIdBytes], const uint8_t rootDigest[kDigestBytes],
                                      uint8_t* out, size_t out_len) {
    return serialize(hostChallenge, deviceNonce, transactionId, rootDigest, kTagActivate, out, out_len);
  }

private:
  static size_t serialize(const uint8_t hostChallenge[kChallengeBytes], const uint8_t deviceNonce[kChallengeBytes],
                           const uint8_t transactionId[kTransactionIdBytes], const uint8_t rootDigest[kDigestBytes],
                           uint8_t tag, uint8_t* out, size_t out_len) {
    if (out == nullptr || out_len < kMessageBytes) return 0;
    size_t pos = 0;
    std::memcpy(out + pos, hostChallenge, kChallengeBytes); pos += kChallengeBytes;
    std::memcpy(out + pos, deviceNonce, kChallengeBytes); pos += kChallengeBytes;
    std::memcpy(out + pos, transactionId, kTransactionIdBytes); pos += kTransactionIdBytes;
    std::memcpy(out + pos, rootDigest, kDigestBytes); pos += kDigestBytes;
    out[pos++] = tag;
    return pos;
  }
};

// Abstract transport for a single live commissioning conversation.
// Implementations MUST NOT fabricate a response: any I/O failure,
// timeout, or malformed device reply must return false, never a
// zero-filled/default response object.
class DeviceAuthoritySession {
public:
  virtual ~DeviceAuthoritySession() = default;
  // Round-trips to the real device and returns a FRESH, DEVICE-MINTED,
  // single-use challenge for the exact (purpose, transactionId) pair --
  // never a host-fabricated value. The host must call this immediately
  // before building the corresponding PrepareAuthorizationV1/
  // ActivationAuthorizationV1 (whose `deviceFreshChallenge` field must
  // equal exactly what this returns) and must not cache/reuse the
  // result across a different transactionId or purpose. Returns false
  // on any I/O failure/timeout -- never a zero-filled fallback.
  virtual bool requestDeviceChallenge(AuthorityChallengePurpose purpose, const uint8_t transactionId[kTransactionIdBytes],
                                       uint8_t out_challenge[kChallengeBytes]) = 0;
  virtual bool sendPreparePermit(const PreparePermit& permit, PreparedRootResponse& out_response) = 0;
  virtual bool sendActivationPermit(const ActivationPermit& permit, ActivationResponse& out_response) = 0;
};

}  // namespace authority
}  // namespace ota
