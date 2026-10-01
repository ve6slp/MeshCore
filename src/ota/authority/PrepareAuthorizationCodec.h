#pragma once

// Astra production-contract (section D) fix: the interfaces inspected
// before this file existed (PreparePermit = G + a HOST-chosen
// hostChallenge) do NOT prove a fresh DEVICE-minted challenge was ever
// involved -- a host could reuse/predict/replay the same bytes it
// itself generated. PrepareAuthorizationV1 is a SEPARATE, purpose-bound,
// domain-separated signed object -- the exact structural sibling of
// ActivationAuthorizationCodec.h's ActivationAuthorizationV1, built the
// same way, for the same reason, but for the PREPARE step instead of
// ACTIVATE:
//
//   - Signed using the SAME EXISTING issuer key identified by
//     AuthorityTransaction::issuerKeyId. No new production key.
//   - Produced by the host ONLY after BOTH registry copies are already
//     durably ConsumedPrepared(rootBound=false) for this transaction
//     (see AuthorityCoordinator::prepare) -- never before.
//   - Bound to `deviceFreshChallenge`, a challenge the DEVICE itself
//     minted for this exact (USB session, purpose=Prepare, A, inputDigest)
//     tuple -- single-use, invalidated on reset/reconnect/timeout. This
//     file defines the wire shape and the host-side verification
//     contract; the actual device-side challenge-minting/single-use
//     bookkeeping is a device/session concern (DeviceAuthorityGuard /
//     the USB transport), not duplicated here.
//   - `inputDigest` = SHA256(G238 || C238 || B117 || rxContextKind(1) ||
//     peerFullPublicKey(32)) -- exactly 626 input bytes, see
//     computeInputDigestSha256() below. This is what binds the Prepare
//     authorization to the EXACT grant, baseline certificate, baseline
//     manifest, and peer-pairwise RX context the device is about to
//     prepare against -- substituting any one of those invalidates the
//     signature, just as substituting any AuthorityBinding field
//     invalidates ActivationAuthorizationV1.
//
// This file is a CODEC + explicit signing/verification seam only. It
// does not implement the typed bounded guard continuation state machine
// (AuthorityCoordinator::prepare / DeviceAuthorityMaintenance) that will
// eventually produce/consume it, nor the device-minted-challenge
// transport itself -- those remain separate, already-tracked follow-on
// work. No existing 238/117/386 record format is altered.

#include <stdint.h>
#include <stddef.h>
#include <cstring>
#include "ota/authority/AuthorityTypes.h"
#include "ota/authority/AuthorityCodec.h"
#include "ota/authority/BaselineCertificationManifest.h"
#include "ota/protocol/OtaByteStream.h"
#include "ota/trust/Sha256.h"

namespace ota {
namespace authority {

// Matches the "RX context kind: u8 = Peer" wire field from the Astra
// production contract's fixed first-pair P683 layout -- kept as its own
// tiny enum here (rather than reusing some unrelated existing one) since
// nothing else in this module currently names this exact concept.
enum class PrepareRxContextKind : uint8_t {
  None = 0,
  Peer = 1,
};

struct PrepareAuthorizationV1 {
  uint8_t transactionId[kTransactionIdBytes] = {0};
  uint8_t grantDigestSha256[kDigestBytes] = {0};   // A == AuthorityCodec::computeRecordDigestSha256(G). Same
                                                    // meaning/derivation as ActivationAuthorizationV1::grantDigestSha256
                                                    // -- NEVER txn.manifestDigestSha256 (M).
  uint8_t inputDigestSha256[kDigestBytes] = {0};   // SHA256(G238||C238||B117||rxContextKind(1)||peerFullPublicKey(32)).
                                                    // See computeInputDigestSha256().
  uint32_t authorizedRevision = 0;                 // txn.revision at the moment both copies reached ConsumedPrepared.
  AuthorityBinding expectedBinding;                // Full binding this authorization is scoped to.
  uint8_t deviceFreshChallenge[kChallengeBytes] = {0};  // Device-MINTED challenge for (session, Prepare-purpose, A,
                                                         // inputDigest) -- never host-chosen/predicted.
  uint8_t hostNonce[kChallengeBytes] = {0};        // Independent fresh host entropy, same freshness rationale as
                                                    // ActivationAuthorizationV1::hostNonce.
  uint8_t issuerSignatureEd25519[kSignatureBytes] = {0};
};

enum class PrepareAuthorizationDecodeError : uint8_t {
  None = 0,
  TooShort = 1,
  TooLong = 2,
  InvalidCryptoForm = 3,
  InvalidGroupSelectorForPairwise = 4,
};

class PrepareAuthorizationCodec {
public:
  // txnId(16) + grantDigest(32) + inputDigest(32) + revision(4) +
  // AuthorityCodec::kBindingBytes(87) + deviceFreshChallenge(16) +
  // hostNonce(16) = 203 bytes.
  static constexpr size_t kBodyBytes = 203;
  static constexpr size_t kRecordBytes = kBodyBytes + kSignatureBytes;  // 267.

  static const char* signedDomain() { return "MeshCore/OTA/prepare-store-root/v1"; }
  static constexpr size_t kSignedDomainBytes = 34;  // strlen(signedDomain()), NUL excluded.
  static constexpr size_t kSignedMessageBytes = kSignedDomainBytes + kBodyBytes;  // 237.

  // Exactly 238 (G) + 238 (C) + 117 (B) + 1 (rxContextKind) + 32
  // (peerFullPublicKey) = 626 input bytes -- never includes this
  // wrapper's own body or any transport/signature bytes.
  static constexpr size_t kInputDigestSourceBytes =
      AuthorityCodec::kRecordBytes + AuthorityCodec::kRecordBytes + BaselineCertificationManifestCodec::kManifestBytes +
      1 + kPublicKeyBytes;

  static bool computeInputDigestSha256(const AuthorityTransaction& grant, const AuthorityTransaction& certify,
                                        const BaselineCertificationManifest& manifest, PrepareRxContextKind rxKind,
                                        const uint8_t peerFullPublicKey[kPublicKeyBytes],
                                        uint8_t out_digest[kDigestBytes]) {
    uint8_t buf[kInputDigestSourceBytes];
    size_t off = 0;
    if (AuthorityCodec::serializeRecord(grant, buf + off, AuthorityCodec::kRecordBytes) != AuthorityCodec::kRecordBytes) {
      return false;
    }
    off += AuthorityCodec::kRecordBytes;
    if (AuthorityCodec::serializeRecord(certify, buf + off, AuthorityCodec::kRecordBytes) != AuthorityCodec::kRecordBytes) {
      return false;
    }
    off += AuthorityCodec::kRecordBytes;
    if (BaselineCertificationManifestCodec::serialize(manifest, buf + off,
                                                        BaselineCertificationManifestCodec::kManifestBytes) !=
        BaselineCertificationManifestCodec::kManifestBytes) {
      return false;
    }
    off += BaselineCertificationManifestCodec::kManifestBytes;
    buf[off] = static_cast<uint8_t>(rxKind);
    off += 1;
    std::memcpy(buf + off, peerFullPublicKey, kPublicKeyBytes);
    off += kPublicKeyBytes;
    if (off != kInputDigestSourceBytes) return false;
    ota::trust::Sha256::hash(buf, sizeof(buf), out_digest);
    return true;
  }

  static size_t serializeBody(const PrepareAuthorizationV1& p, uint8_t* out, size_t out_len) {
    meshcore::ota::protocol::OtaBoundedWriter w(out, out_len);
    if (!w.putBytes(p.transactionId, kTransactionIdBytes)) return 0;
    if (!w.putBytes(p.grantDigestSha256, kDigestBytes)) return 0;
    if (!w.putBytes(p.inputDigestSha256, kDigestBytes)) return 0;
    if (!w.putU32(p.authorizedRevision)) return 0;
    if (!AuthorityCodec::writeBindingFields(w, p.expectedBinding)) return 0;
    if (!w.putBytes(p.deviceFreshChallenge, kChallengeBytes)) return 0;
    if (!w.putBytes(p.hostNonce, kChallengeBytes)) return 0;
    return w.size();
  }

  static size_t serializeRecord(const PrepareAuthorizationV1& p, uint8_t* out, size_t out_len) {
    meshcore::ota::protocol::OtaBoundedWriter w(out, out_len);
    uint8_t body[kBodyBytes];
    if (serializeBody(p, body, sizeof(body)) != kBodyBytes) return 0;
    if (!w.putBytes(body, kBodyBytes)) return 0;
    if (!w.putBytes(p.issuerSignatureEd25519, kSignatureBytes)) return 0;
    return w.size();
  }

  // Builds the exact domain-separated message the signature covers:
  // signedDomain() || canonical body. Never includes the signature
  // itself.
  static size_t serializeSignedMessage(const PrepareAuthorizationV1& p, uint8_t* out, size_t out_len) {
    meshcore::ota::protocol::OtaBoundedWriter w(out, out_len);
    if (!w.putBytes(reinterpret_cast<const uint8_t*>(signedDomain()), kSignedDomainBytes)) return 0;
    uint8_t body[kBodyBytes];
    if (serializeBody(p, body, sizeof(body)) != kBodyBytes) return 0;
    if (!w.putBytes(body, kBodyBytes)) return 0;
    return w.size();
  }

  // Fails closed on any malformed/truncated/wrong-length input, never
  // partially populating `out`.
  static PrepareAuthorizationDecodeError parseRecord(const uint8_t* in, size_t in_len, PrepareAuthorizationV1& out) {
    if (in_len < kRecordBytes) return PrepareAuthorizationDecodeError::TooShort;
    if (in_len > kRecordBytes) return PrepareAuthorizationDecodeError::TooLong;

    PrepareAuthorizationV1 parsed;
    meshcore::ota::protocol::OtaBoundedReader reader(in, kRecordBytes);

    if (!reader.getBytes(parsed.transactionId, kTransactionIdBytes)) return PrepareAuthorizationDecodeError::TooShort;
    if (!reader.getBytes(parsed.grantDigestSha256, kDigestBytes)) return PrepareAuthorizationDecodeError::TooShort;
    if (!reader.getBytes(parsed.inputDigestSha256, kDigestBytes)) return PrepareAuthorizationDecodeError::TooShort;

    uint32_t revision = 0;
    if (!reader.getU32(revision)) return PrepareAuthorizationDecodeError::TooShort;
    parsed.authorizedRevision = revision;

    const AuthorityDecodeError binding_error = AuthorityCodec::readBindingFields(reader, parsed.expectedBinding);
    if (binding_error == AuthorityDecodeError::InvalidCryptoForm) {
      return PrepareAuthorizationDecodeError::InvalidCryptoForm;
    }
    if (binding_error == AuthorityDecodeError::InvalidGroupSelectorForPairwise) {
      return PrepareAuthorizationDecodeError::InvalidGroupSelectorForPairwise;
    }
    if (binding_error != AuthorityDecodeError::None) return PrepareAuthorizationDecodeError::TooShort;

    if (!reader.getBytes(parsed.deviceFreshChallenge, kChallengeBytes)) return PrepareAuthorizationDecodeError::TooShort;
    if (!reader.getBytes(parsed.hostNonce, kChallengeBytes)) return PrepareAuthorizationDecodeError::TooShort;
    if (!reader.getBytes(parsed.issuerSignatureEd25519, kSignatureBytes)) return PrepareAuthorizationDecodeError::TooShort;

    out = parsed;
    return PrepareAuthorizationDecodeError::None;
  }
};

// Abstract, explicit signing seam for producing a PrepareAuthorizationV1
// signature using the EXISTING issuer key identified by `issuerKeyId`
// -- NOT a new production key. Mirrors AuthorityActivationSigningTrust
// exactly; kept as a separate interface (rather than reusing that one)
// so a real integrator can wire -- or deliberately NOT wire, leaving
// Prepare authorization default-deny -- independently of Activate
// authorization. Default-deny: any coordinator entrypoint that will
// eventually produce PrepareAuthorizationV1 must deny outright if none
// is wired, exactly like AuthorityActivationSigningTrust's existing
// contract, never falling back to reusing/re-exporting the original
// grant signature.
class AuthorityPrepareSigningTrust {
public:
  virtual ~AuthorityPrepareSigningTrust() = default;
  virtual bool signPrepareAuthorization(uint16_t issuerKeyId, const uint8_t* message, size_t message_len,
                                         uint8_t out_signature[kSignatureBytes]) = 0;
};

}  // namespace authority
}  // namespace ota
