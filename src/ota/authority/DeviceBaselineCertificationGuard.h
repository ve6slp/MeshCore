#pragma once

// Portable, default-denying DEVICE-side verifier for the
// CertifyExistingBaseline authority operation (AuthorityTypes.h /
// BaselineCertificationManifest.h) -- the narrow "turn an existing stock
// OTA=1 USB image into a positively certified Normal baseline" check,
// kept entirely separate from DeviceAuthorityGuard's Commission/Repair/
// Rekey staged/activated lifecycle: this guard NEVER touches
// DeviceAuthorityStore/DeviceAuthorityMaintenance, seeds no TX/RX
// counter, generates no identity, and grants no installation authority.
// It returns exactly the two-valued typed outcome the Firmware owner's
// src/helpers/ota/OtaBaselineCertificationEvidence.h already uses the
// same contract for (Unknown by default; PositiveNormal only on a
// genuine, freshly-reverified positive result) -- "honestly stay
// Unknown, no fake permissive provider" applies here identically.
//
// Every dependency (signature verifier, issuer trust, entropy, and the
// LOCAL evidence capture hook) is abstract with NO production-shaped
// default: a guard missing any one of them, or a local-evidence capture
// that fails/returns a non-matching digest, or a verification against
// this exact device's own binding that fails, all resolve to Unknown --
// never a silent PositiveNormal fallback.
//
// This guard performs NO real image/loader/USB inspection itself --
// `DeviceBaselineLocalEvidence` is the abstract seam a real integrator
// (Firmware/MAIN) wires to the device's actual current image hash/
// extent/stock-loader artifact/boot config; wiring that, and whatever
// transport delivers the signed CertifyExistingBaseline transaction to
// the device in the first place (USB session, or a read-only record
// already resident on the device), are both explicitly left
// unimplemented here -- see the top-level task scope.
//
// `evaluate()` performs zero caching: every call re-verifies the
// signature, re-checks the binding, draws a genuinely fresh device
// nonce, and re-captures local evidence from scratch. There is
// deliberately no "stay PositiveNormal until told otherwise" state --
// this is what makes "renewed proof each boot" (rather than a persisted
// activated receipt) an enforced property of this guard, not a
// documentation-only intention.

#include <stdint.h>
#include <cstring>
#include "ota/authority/AuthorityTypes.h"
#include "ota/authority/AuthorityCodec.h"
#include "ota/authority/AuthorityHostInterfaces.h"
#include "ota/authority/BaselineCertificationManifest.h"
#include "ota/authority/DeviceAuthorityGuard.h"  // reuses DeviceAuthorityEntropy -- the same real-CSPRNG seam,
                                                    // never a second parallel entropy abstraction.
#include "ota/trust/SignatureVerifier.h"

namespace ota {
namespace authority {

// Same two-valued shape as the Firmware owner's
// OtaBaselineCertificationOutcome{InsufficientEvidence, Certified} /
// OtaBoardQualificationStatus{..., Unknown} -- named to match this task's
// explicit "typed Unknown/positiveNormal contract" wording exactly.
enum class BaselineCertificationOutcome : uint8_t {
  Unknown = 0,         // Default. Any missing dependency, mismatch, or failed re-verification lands here.
  PositiveNormal = 1,  // Genuine, freshly-reverified certification for this exact device/boot.
};

// The ONLY thing that may ever produce a genuine local manifest here is
// a real, per-call, freshly-taken measurement of this device's CURRENT
// image/loader/boot-config -- never a cached/remembered value from a
// previous boot or a previous call. Returning true with a stale or
// fabricated manifest would defeat the entire "renewed proof each boot"
// property; there is no way for this guard to detect that misuse from
// the outside, so a real implementation carries that obligation.
//
// Astra30/31 fix: this seam used to return only a bare digest, which
// made it structurally impossible for the guard to ever see (and
// therefore enforce) `allowOrdinaryUserdata` -- a byte-perfect digest
// match against an `allowOrdinaryUserdata == false` manifest would
// previously have been accepted as PositiveNormal, even though "false"
// means this exact baseline explicitly does NOT permit ordinary
// userdata use. The seam now returns the COMPLETE freshly-measured
// manifest (the already-bounded, fixed-width 117-byte structured
// result a real collector -- e.g. the Firmware owner's read-only bounded
// collector -- produces), so the guard can both recompute the digest
// AND explicitly require the positive-permission flag itself. This
// guard still performs NO raw image/loader byte scanning of its own: it
// only ever hashes/compares the already-captured structured fields.
//
// Coordination note (FW owner question, answered here rather than by
// editing FW's own files; CORRECTED per a later Astra finding --
// superseding what this comment used to say): `allowOrdinaryUserdata`
// is INTENTIONALLY absent from OtaBaselineMeasurementEvidence and must
// stay that way, but it must NEVER be sourced from the device's own
// CURRENTLY-ACTIVE write-gate state (e.g. a live
// ota_allow_ordinary_userdata_writes-equivalent flag). Doing so would be
// circular: the very first certification attempt is, by definition, the
// thing that is supposed to be able to ENABLE ordinary-userdata use on a
// baseline that has never had it before -- if the adapter mirrored the
// CURRENT (still-disabled) gate state into the local manifest, the
// digest of a genuinely correct issuer-signed request (which signs
// allowOrdinaryUserdata == true, the POLICY BEING REQUESTED) would never
// match, and no first-ever grant could ever succeed. The eventual real
// `captureFreshManifest()` adapter (not implemented here, and not
// implemented by FW's collector) must instead source this ONE field
// from the AUTHENTICATED REQUESTED POLICY itself -- i.e. the exact
// allowOrdinaryUserdata value the pending CertifyExistingBaseline
// request/manifest is asking to certify (surfaced to the adapter by
// whatever transport delivers the pending request, entirely separate
// from and prior to this guard's own digest re-verification) -- never
// derived/computed from measurement bytes, and never read back from a
// state this very certification is meant to establish. This guard's own
// digest-then-flag check below is what makes that requested bit
// cryptographically binding: the local_manifest it hashes must be
// byte-identical to what the issuer signed, and `allowOrdinaryUserdata`
// is simply one more field of that same signed manifest, not a separate
// side-channel fact pulled from device state at evaluation time.
// Measurement fields (image/extent/SDK28/loader/boot-config/UID/PK/
// profile/target/role/layout) flow from the collector unchanged, merged
// with this ONE authenticated-policy field before this guard ever sees
// the composed manifest.
class DeviceBaselineLocalEvidence {
public:
  virtual ~DeviceBaselineLocalEvidence() = default;
  virtual bool captureFreshManifest(BaselineCertificationManifest& out_manifest) = 0;
};

class DeviceBaselineCertificationGuard {
public:
  DeviceBaselineCertificationGuard(const AuthorityBinding& ownIdentity, ota::trust::SignatureVerifier* verifier,
                                    AuthorityIssuerTrust* issuerTrust, DeviceAuthorityEntropy* entropy,
                                    DeviceBaselineLocalEvidence* localEvidence)
      : ownIdentity_(ownIdentity),
        verifier_(verifier),
        issuerTrust_(issuerTrust),
        entropy_(entropy),
        localEvidence_(localEvidence) {}
  // Zero I/O in the constructor.

  bool dependenciesWired() const {
    return verifier_ != nullptr && issuerTrust_ != nullptr && entropy_ != nullptr && localEvidence_ != nullptr;
  }

  // `out_freshNonce`, if non-null, receives the fresh per-call device
  // nonce drawn during this evaluation -- exposed so a future reporting/
  // ack transport (not implemented here) can bind a signed receipt to
  // this exact, non-replayable evaluation, without this guard having to
  // invent that wire message itself.
  BaselineCertificationOutcome evaluate(const AuthorityTransaction& txn,
                                        uint8_t* out_freshNonce = nullptr) const {
    if (!dependenciesWired()) return BaselineCertificationOutcome::Unknown;
    if (txn.operation != AuthorityOperation::CertifyExistingBaseline) {
      return BaselineCertificationOutcome::Unknown;  // Reject cross-use of any other operation kind.
    }
    // Astra30/31: direct device-side re-evaluation of the same
    // zero-floor/zero-chain invariants AuthorityCoordinator::
    // submitCertifyExistingBaseline enforces on the host/CLI side --
    // never relying solely on the issuer CLI/host to have gotten this
    // right. This operation never chains off prior history and never
    // seeds a counter, ever; a transaction claiming otherwise is
    // rejected here directly, not merely by convention elsewhere.
    if (txn.revision != 0) return BaselineCertificationOutcome::Unknown;
    static const uint8_t kZeroTransactionId[kTransactionIdBytes] = {0};
    if (std::memcmp(txn.predecessorTransactionId, kZeroTransactionId, kTransactionIdBytes) != 0) {
      return BaselineCertificationOutcome::Unknown;
    }
    if (txn.initialTxSequenceFloor != 0 || txn.initialRxReplayFloor != 0) {
      return BaselineCertificationOutcome::Unknown;
    }
    if (!exactlyThisDevice(txn.binding)) return BaselineCertificationOutcome::Unknown;

    uint8_t issuer_public_key[kPublicKeyBytes];
    if (!issuerTrust_->lookupIssuerPublicKey(txn.issuerKeyId, issuer_public_key)) {
      return BaselineCertificationOutcome::Unknown;
    }
    uint8_t message[AuthorityCodec::kSignedMessageBytes];
    const size_t written = AuthorityCodec::serializeSignedMessage(txn, message, sizeof(message));
    if (written != AuthorityCodec::kSignedMessageBytes) return BaselineCertificationOutcome::Unknown;
    if (!verifier_->verify(txn.issuerSignatureEd25519, kSignatureBytes, message, written, issuer_public_key,
                            kPublicKeyBytes)) {
      return BaselineCertificationOutcome::Unknown;
    }

    // Fresh per-boot/per-call device challenge: drawn unconditionally on
    // every evaluation, never reused/cached -- a provider that cannot
    // supply genuine entropy denies the whole evaluation rather than
    // proceeding without it.
    uint8_t device_nonce[kChallengeBytes];
    if (!entropy_->freshNonce(device_nonce)) return BaselineCertificationOutcome::Unknown;

    // The actual positive evidence: a REAL, freshly-taken, COMPLETE
    // local measurement (image SHA/extent/stock-loader hash+range/boot
    // config/allow-userdata flag), never a bare digest -- see
    // DeviceBaselineLocalEvidence's rationale above for why a bare
    // digest previously hid whether `allowOrdinaryUserdata` was false.
    BaselineCertificationManifest local_manifest;
    if (!localEvidence_->captureFreshManifest(local_manifest)) {
      return BaselineCertificationOutcome::Unknown;
    }
    uint8_t local_digest[32];
    if (!BaselineCertificationManifestCodec::computeDigestSha256(local_manifest, local_digest)) {
      return BaselineCertificationOutcome::Unknown;
    }
    if (std::memcmp(local_digest, txn.manifestDigestSha256, kDigestBytes) != 0) {
      return BaselineCertificationOutcome::Unknown;
    }
    // A digest match alone is not enough: an `allowOrdinaryUserdata ==
    // false` manifest means this exact, faithfully-matched baseline
    // explicitly does NOT permit ordinary userdata use, and must never
    // be treated as a positive "Normal" certification regardless of how
    // exactly it matches what the issuer signed.
    if (!local_manifest.allowOrdinaryUserdata) return BaselineCertificationOutcome::Unknown;

    if (out_freshNonce != nullptr) std::memcpy(out_freshNonce, device_nonce, kChallengeBytes);
    return BaselineCertificationOutcome::PositiveNormal;
  }

private:
  bool exactlyThisDevice(const AuthorityBinding& claimed) const {
    // Astra30/31 fix: for CertifyExistingBaseline, `historicalInitialRoleId`
    // is reused to mean the ROLE BEING CERTIFIED right now -- NOT the
    // historical factory/commission-time role recorded for audit
    // elsewhere. `ownIdentity_` must therefore be constructed by the
    // caller holding this device's CURRENT actual role in that same
    // field; comparing it directly here is what prevents a signed
    // baseline certificate issued for one role from being silently
    // accepted while the device is actually configured/operating under
    // a genuinely different role. Every other field is likewise matched
    // against this guard's OWN configured identity -- never copied
    // trust from the incoming (attacker-influenced) claimed binding.
    return std::memcmp(claimed.hardwareUid, ownIdentity_.hardwareUid, kHardwareUidBytes) == 0 &&
           std::memcmp(claimed.meshFullPublicKey, ownIdentity_.meshFullPublicKey, kPublicKeyBytes) == 0 &&
           claimed.cryptoDomain == ownIdentity_.cryptoDomain && claimed.profileId == ownIdentity_.profileId &&
           claimed.layoutId == ownIdentity_.layoutId &&
           claimed.historicalInitialRoleId == ownIdentity_.historicalInitialRoleId &&
           std::memcmp(claimed.consentOwnerPublicKey, ownIdentity_.consentOwnerPublicKey, kPublicKeyBytes) == 0;
  }

  AuthorityBinding ownIdentity_;
  ota::trust::SignatureVerifier* verifier_;
  AuthorityIssuerTrust* issuerTrust_;
  DeviceAuthorityEntropy* entropy_;
  DeviceBaselineLocalEvidence* localEvidence_;
};

}  // namespace authority
}  // namespace ota
