#pragma once

// Canonical, platform-independent types for the OTA commissioning
// authority: the operator-owned registry that gates commission/repair/
// rekey of a device's OTA identity, kept fully independent of the
// device's own (offline, ordinary-operation) OTA storage.
//
// A device's normal OTA counters/keys live entirely on-device (see
// src/ota/security, owned separately). This module only concerns the
// narrow, high-stakes moment where an operator with physical custody of
// the device grants it a NEW commissioning/repair/rekey transaction --
// every field here exists to make that grant unambiguous and non-
// substitutable (see AuthorityCodec.h for the exact signed byte layout).

#include <stdint.h>
#include <cstring>
#include "ota/runtime/OtaAeadFrame.h"

namespace ota {
namespace authority {

constexpr size_t kHardwareUidBytes = 8;    // nRF52840 FICR DEVICEID[0..1], full 64 bits.
constexpr size_t kPublicKeyBytes = 32;     // Ed25519 public key (Mesh identity or consent-owner).
constexpr size_t kDigestBytes = 32;        // SHA-256.
constexpr size_t kTransactionIdBytes = 16; // Random, operator/tool-generated, never reused.
constexpr size_t kSignatureBytes = 64;     // Ed25519 signature.
constexpr size_t kChallengeBytes = 16;     // Fresh per-session device challenge.

// What kind of authority grant a transaction represents. A label/role
// change alone is never one of these -- see AuthorityBinding::role_id.
enum class AuthorityOperation : uint8_t {
  Commission = 1,  // First legitimate root for this (uid, fullPK, domain, layout).
  Repair = 2,      // Re-establish an already-commissioned root; never fabricates floors.
  Rekey = 3,       // Genuine pairwise/group key-material change with explicit consent.

  // A distinct, narrower grant: certifies that an EXISTING stock OTA=1
  // USB image/loader on this exact device is a legitimate Normal
  // baseline -- see BaselineCertificationManifest.h. Deliberately NEVER
  // enters the Commission/Repair/Rekey Issued->ConsumedPrepared->
  // ActivationSpent lifecycle (AuthorityCoordinator::prepare/
  // resumePrepared/activateExistingRoot explicitly refuse this
  // operation with AuthorityOutcome::OperationMismatch): it grants no
  // counter seed, no identity generation, and no installation/
  // commissioning authority. revision/predecessor/both sequence floors
  // MUST be zero for this operation -- see AuthorityCodec::
  // validateOperationConstraints.
  CertifyExistingBaseline = 4,
};

inline bool isValidAuthorityOperation(uint8_t raw) {
  return raw == static_cast<uint8_t>(AuthorityOperation::Commission) ||
         raw == static_cast<uint8_t>(AuthorityOperation::Repair) ||
         raw == static_cast<uint8_t>(AuthorityOperation::Rekey) ||
         raw == static_cast<uint8_t>(AuthorityOperation::CertifyExistingBaseline);
}

// The monotone lifecycle every transaction moves through. Never
// regresses: a registry copy observed at ConsumedPrepared or
// ActivationSpent must never be treated as merely Issued again (see
// AuthorityRegistryPort.h's reconciliation rules).
enum class TransactionState : uint8_t {
  Issued = 1,
  ConsumedPrepared = 2,
  ActivationSpent = 3,
};

// The exact crypto-domain a transaction is bound to: which AEAD form
// (pairwise vs group) and, for group, which selector. Reuses the real
// wire-level form enum from the runtime transport rather than inventing a
// parallel one, so "domain" here can never silently drift out of sync
// with what the transport actually authenticates against.
struct CryptoDomainBinding {
  meshcore::ota::runtime::OtaAeadForm form = meshcore::ota::runtime::OtaAeadForm::Pairwise;
  uint16_t groupSelector = 0;  // Must be 0 for Pairwise; meaningful only for Group.

  bool operator==(const CryptoDomainBinding& other) const {
    return form == other.form && groupSelector == other.groupSelector;
  }
  bool operator!=(const CryptoDomainBinding& other) const { return !(*this == other); }
};

// Everything that identifies WHICH physical device and WHICH key/consent
// context a transaction is bound to. Every field participates in the
// signed message (AuthorityCodec.h) -- substituting any single one
// invalidates the signature, so there is no way to "reuse" a valid
// transaction against a different device/domain/consent owner.
struct AuthorityBinding {
  uint8_t hardwareUid[kHardwareUidBytes] = {0};       // Full nRF FICR DEVICEID, never a shortened hash.
  uint8_t meshFullPublicKey[kPublicKeyBytes] = {0};   // Full local Mesh identity public key.
  CryptoDomainBinding cryptoDomain;
  uint32_t profileId = 0;                             // Board/profile id (matches sign_image.py BOARD_TARGETS).
  uint32_t layoutId = 0;                              // Flash/partition layout id.
  uint32_t historicalInitialRoleId = 0;                // Recorded for audit; role changes alone never affect dominance.
  uint8_t consentOwnerPublicKey[kPublicKeyBytes] = {0}; // Operator/custody key that authorized this grant.

  bool sameOwnership(const AuthorityBinding& other) const {
    // Store/device ownership identity per the approved contract: UID +
    // fullPK + cryptoDomain + layout. Role and consent owner are
    // deliberately excluded -- they may legitimately change without that
    // being a different "owner" for dominance/repair purposes.
    return std::memcmp(hardwareUid, other.hardwareUid, kHardwareUidBytes) == 0 &&
           std::memcmp(meshFullPublicKey, other.meshFullPublicKey, kPublicKeyBytes) == 0 &&
           cryptoDomain == other.cryptoDomain &&
           layoutId == other.layoutId;
  }

  // Same PHYSICAL device/domain/layout, deliberately WITHOUT comparing
  // fullPK -- used only to find the prior history a genuine rekey (which
  // changes fullPK on purpose) is allowed to supersede.
  bool sameDeviceIdentity(const AuthorityBinding& other) const {
    return std::memcmp(hardwareUid, other.hardwareUid, kHardwareUidBytes) == 0 &&
           cryptoDomain == other.cryptoDomain &&
           layoutId == other.layoutId;
  }

  // Sol43 HIGH fix (supersedes the previous samePhysicalLifetime key):
  // keeping cryptoDomain in this comparison was ITSELF the same kind of
  // "transport/label" escape this fence exists to close -- cryptoDomain
  // (AEAD form + group selector) is a negotiable/selectable transport
  // choice, not an immutable physical fact about the chip, so a second
  // genuinely-signed Commission for the SAME hardwareUid but a DIFFERENT
  // cryptoDomain (or layoutId) was still invisible to both
  // reconcileLatestActivationForOwner/reconcileOwnershipLineage (scoped
  // to sameOwnership, which requires cryptoDomain+layout to match) AND
  // the physical-lineage scan itself (previously also comparing
  // cryptoDomain) -- letting a fresh, duplicate "genesis" Issued record
  // through for a device that already has real history. The LIFETIME
  // first-use/fork-fence key is the full PHYSICAL UID alone: the ONE
  // field that is an immutable fact about the chip (nRF FICR DEVICEID),
  // independent of changing meshFullPublicKey (rekey),
  // historicalInitialRoleId (role), profileId, layoutId, or cryptoDomain
  // (crypto-form/group-selector) -- all of which remain legitimately
  // changeable "labels" for the SAME physical lifetime. Those other
  // binding fields remain necessary for OTHER comparisons (self-
  // consistency checks like rekeyExplicitly's own rekeyTxn-vs-prior
  // check, and the narrower "ownership" scan), but must never be allowed
  // to act as an escape hatch FROM the lifetime fence itself. No new
  // field/domain-string/key/registry is introduced here -- this uses
  // only the existing hardwareUid.
  bool samePhysicalLifetime(const AuthorityBinding& other) const {
    return std::memcmp(hardwareUid, other.hardwareUid, kHardwareUidBytes) == 0;
  }
};

// The full, signed commissioning/repair/rekey transaction. `issuerKeyId`
// identifies (out of band, via the verifier's own trust anchor) which
// issuer key must have produced `issuerSignatureEd25519` -- the issuer's
// actual public key is never carried inside the signed message itself
// (an attacker embedding their own key would otherwise be able to self-
// sign; see ota/trust/TrustTypes.h for the same principle applied to
// image descriptors).
struct AuthorityTransaction {
  AuthorityBinding binding;
  AuthorityOperation operation = AuthorityOperation::Commission;
  uint8_t transactionId[kTransactionIdBytes] = {0};
  uint32_t revision = 0;
  uint8_t predecessorTransactionId[kTransactionIdBytes] = {0};  // All-zero iff revision == 0 (no predecessor).
  uint8_t manifestDigestSha256[kDigestBytes] = {0};             // Digest of the canonical init/repair/rekey MANIFEST
                                                                 // document itself (initial seeds / repair scope /
                                                                 // expected-root POLICY) -- NOT the root digest.
                                                                 //
                                                                 // Astra29 correction: this transaction deliberately
                                                                 // carries NO issuer-precommitted "expected root"
                                                                 // field anymore. The issuer cannot know the exact
                                                                 // prepared-store-root digest (R) ahead of time --
                                                                 // only the device/store, after actually applying the
                                                                 // manifest, can produce R (see
                                                                 // PreparedRootCommitment.h). A prior revision of this
                                                                 // struct carried an `expectedRootDigestSha256` field
                                                                 // that DeviceAuthorityGuard::verifyAndPrepare simply
                                                                 // echoed back as if it were a real device-attested
                                                                 // root -- a confirmed "fake ACK R" defect. Removing
                                                                 // the field entirely (rather than just changing how
                                                                 // it is used) makes that shortcut structurally
                                                                 // impossible: R now only ever comes from
                                                                 // DeviceAuthorityMaintenance::stageRoot's real,
                                                                 // store-backed output.
  uint32_t initialTxSequenceFloor = 0;                          // Exact permitted TX floor (or repair/rekey scope bound).
  uint32_t initialRxReplayFloor = 0;                            // Exact permitted RX floor (or repair/rekey scope bound).
  uint16_t issuerKeyId = 0;
  uint64_t issuedAtUnixSeconds = 0;                             // Audit trail only -- never treated as first-use proof alone.
  uint8_t issuerSignatureEd25519[kSignatureBytes] = {0};

  bool hasPredecessor() const { return revision != 0; }
};

// Narrow outcome codes returned by every authority operation. There is no
// generic "ok" boolean anywhere in this API: every failure is typed so a
// caller (or test) can distinguish "your binding is wrong" from "the
// registry copies disagree" from "a dependency was never wired".
enum class AuthorityOutcome : uint8_t {
  Ok = 0,
  Denied = 1,                 // A required dependency (verifier/entropy/store/maintenance) was missing.
  BindingMismatch = 2,        // UID/fullPK/domain/profile/layout/consent/role did not match exactly.
  SignatureInvalid = 3,
  TransactionNotFound = 4,
  WrongState = 5,             // e.g. resumePrepared on an Issued-only transaction.
  RegistryDisagreement = 6,   // The two copies disagree in a way that is NOT a clean dominance case (Uncertain).
  StaleRevision = 7,          // A repair/rekey attempted to move backwards or skip history.
  ChallengeMismatch = 8,
  DeviceResponseMismatch = 9, // Device's signed root/ack did not match what was permitted.
  MissingHistory = 10,        // Repair/rekey requested but no prior ActivationSpent exists for this owner.
  CorruptRecord = 11,
  OperationMismatch = 12,     // e.g. a CertifyExistingBaseline transaction fed into prepare()/activateExistingRoot(),
                               // or a non-CertifyExistingBaseline transaction fed into submitCertifyExistingBaseline().
  Pending = 13,                // A device-side I/O boundary (stageRoot/commitStaged/activateStagedRoot/commitActivated/
                               // readCurrent) genuinely cannot complete synchronously right now -- retry the SAME
                               // in-flight call later (driven by service/main ticks, never a synchronous spin).
                               // Never serialized to wire bytes; purely an in-process guard/coordinator status.
};

inline bool authorityOutcomeIsSuccess(AuthorityOutcome outcome) {
  return outcome == AuthorityOutcome::Ok;
}

}  // namespace authority
}  // namespace ota
