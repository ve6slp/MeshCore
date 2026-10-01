#pragma once

// Host-side operator/registry coordinator: the explicit API
// (describeBinding / prepare / resumePrepared / activateExistingRoot /
// repairExisting / rekeyExplicitly) required by the approved contract,
// implemented against a real two-copy AuthorityRegistryPair and genuine
// Ed25519 verification. Every dependency is deny-by-default: a missing
// verifier, issuer trust map, or challenge provider makes every operation
// return AuthorityOutcome::Denied, never a silent success.
//
// This class performs the REGISTRY-side half of commissioning. It never
// holds an issuer PRIVATE key (transactions arrive already signed --
// signing is an offline operator action, see scripts/ota_authority_registry.py)
// and it never talks to real hardware directly (DeviceAuthoritySession is
// abstract; wiring an actual USB/serial transport is MAIN's later step).

#include <stdint.h>
#include <cstring>
#include "ota/authority/AuthorityTypes.h"
#include "ota/authority/AuthorityCodec.h"
#include "ota/authority/ActivationAuthorizationCodec.h"
#include "ota/authority/PrepareAuthorizationCodec.h"
#include "ota/authority/BaselineCertificationManifest.h"
#include "ota/authority/AuthorityRegistryPort.h"
#include "ota/authority/AuthorityHostInterfaces.h"
#include "ota/authority/AuthorityDeviceSession.h"
#include "ota/authority/AuthorityCrossProcessLock.h"
#include "ota/trust/SignatureVerifier.h"

namespace ota {
namespace authority {

// The additional real inputs a genuine PrepareAuthorizationV1's
// `inputDigestSha256` binds (see PrepareAuthorizationCodec.h's
// computeInputDigestSha256): the baseline-certify transaction (C), the
// baseline manifest (B) it certifies, and the peer-pairwise RX context
// the device is about to prepare against. AuthorityCoordinator does not
// otherwise retain these (they are not part of the registry record
// itself) -- the caller driving an actual prepare()/resumePrepared()
// handshake (e.g. scripts/ota_authority_registry.py, or a future C++
// host tool) supplies them explicitly for the exact operation in
// progress, never a cached/implicit default.
struct PrepareAuthorizationInputs {
  AuthorityTransaction certifyTxn;
  BaselineCertificationManifest manifest;
  PrepareRxContextKind rxContextKind = PrepareRxContextKind::None;
  uint8_t peerFullPublicKey[kPublicKeyBytes] = {0};
};

class AuthorityCoordinator {
public:
  // `activationSigningTrust` is OPTIONAL at the type level (defaults to
  // nullptr) purely so existing callers that never invoke
  // activateExistingRoot are not forced to change -- but
  // activateExistingRoot itself unconditionally denies if it is not
  // wired (see below): there is no success-shaped fallback that skips
  // producing a genuine ActivationAuthorizationV1.
  // `crossProcessLock` defaults to nullptr at the TYPE level only so the
  // constructor signature does not need two separately-defaulted
  // trailing parameters -- Sol c577a77f (H2): a missing lock is now a
  // REQUIRED dependency exactly like verifier/issuerTrust/
  // challengeProvider (see dependenciesWired() below): every entrypoint
  // denies outright rather than silently proceeding unlocked. Callers
  // that genuinely only run single-process must pass an EXPLICIT
  // InProcessOnlyAuthorityCrossProcessLock, never rely on the default.
  // When wired, every mutating entrypoint below (submitCommission,
  // submitCertifyExistingBaseline, repairExisting, rekeyExplicitly,
  // prepare, resumePrepared, activateExistingRoot) holds it for the
  // entrypoint's ENTIRE duration (Sol fe862c8 H2; Sol39 H1 fix extended
  // this to repairExisting/rekeyExplicitly, which previously held NO
  // lease at all) -- never just around the initial lookup, which
  // would reopen the exact same check-then-act race one step later.
  AuthorityCoordinator(AuthorityRegistryPair& registry, ota::trust::SignatureVerifier* verifier,
                        AuthorityIssuerTrust* issuerTrust, AuthorityChallengeProvider* challengeProvider,
                        AuthorityActivationSigningTrust* activationSigningTrust = nullptr,
                        AuthorityCrossProcessLock* crossProcessLock = nullptr,
                        AuthorityPrepareSigningTrust* prepareSigningTrust = nullptr)
      : registry_(registry),
        verifier_(verifier),
        issuerTrust_(issuerTrust),
        challengeProvider_(challengeProvider),
        activationSigningTrust_(activationSigningTrust),
        crossProcessLock_(crossProcessLock),
        prepareSigningTrust_(prepareSigningTrust) {}
  // Zero I/O here: no file/socket touched until an operation is actually invoked.

  // Sol c577a77f (H2): crossProcessLock_ is now a REQUIRED dependency,
  // not an optional nicety -- a missing lock preserves the exact
  // production ownership-fork race this whole file exists to close, so
  // it must deny exactly like a missing verifier/issuerTrust/
  // challengeProvider would. Callers that genuinely only run
  // single-process must supply an EXPLICIT
  // InProcessOnlyAuthorityCrossProcessLock (see AuthorityCrossProcessLock.h)
  // rather than relying on an implicit nullptr fallback.
  bool dependenciesWired() const {
    return verifier_ != nullptr && issuerTrust_ != nullptr && challengeProvider_ != nullptr && crossProcessLock_ != nullptr;
  }

  // Submits a brand-new, already issuer-signed Commission transaction.
  // Rejects (Denied) if the signature does not verify, or if a
  // transaction with this id already exists (never overwritten).
  AuthorityOutcome submitCommission(const AuthorityTransaction& txn) {
    if (!dependenciesWired()) return AuthorityOutcome::Denied;
    AuthorityCrossProcessLockGuard lock_guard(crossProcessLock_);
    if (!lock_guard.acquired()) return AuthorityOutcome::Denied;
    if (txn.operation != AuthorityOperation::Commission) return AuthorityOutcome::BindingMismatch;
    if (txn.revision != 0) return AuthorityOutcome::StaleRevision;
    // CORRECTED per review: a fresh, revision-0 "first use" Commission
    // was previously accepted purely on txnId/op/rev/signature, with NO
    // check of whether this exact domain+fullPK ownership already has
    // surviving ActivationSpent history. That let a relabel (new UID,
    // profile, layout, or role) of an already-commissioned owner be
    // smuggled through as a brand-new "genesis" Commission instead of
    // going through repairExisting/rekeyExplicitly -- exactly the "label
    // isn't cryptographic rekey" / "role changes do not make unchanged
    // key material unused" violation the contract forbids. Any surviving
    // history for this owner (Agreed or RecoveredFromSingleCopy) now
    // rejects a fresh Commission outright; Uncertain history must not be
    // resolved toward permission either.
    ReconciliationResult owner_history = registry_.reconcileLatestActivationForOwner(txn.binding);
    if (owner_history.outcome == ReconciliationOutcome::Uncertain) return AuthorityOutcome::RegistryDisagreement;
    if (owner_history.outcome == ReconciliationOutcome::Agreed ||
        owner_history.outcome == ReconciliationOutcome::RecoveredFromSingleCopy) {
      return AuthorityOutcome::StaleRevision;
    }
    // H3 fix: reconcileLatestActivationForOwner above is structurally
    // blind to a sibling revision-0 Commission for this SAME owner that
    // has reached Issued or even ConsumedPrepared but has not yet been
    // ActivationSpent -- it only ever looks at ActivationSpent history.
    // That let two distinct revision-0 "genesis" transactions for the
    // same exact owner both be accepted, race to Issued, and potentially
    // both later reach ActivationSpent (a genuine ownership fork). Any
    // existing record for this owner in ANY state must block a fresh
    // genesis Commission, not just an already-spent one.
    ReconciliationResult owner_lineage = registry_.reconcileOwnershipLineage(txn.binding);
    if (owner_lineage.outcome == ReconciliationOutcome::Uncertain) return AuthorityOutcome::RegistryDisagreement;
    if (owner_lineage.outcome == ReconciliationOutcome::Agreed ||
        owner_lineage.outcome == ReconciliationOutcome::RecoveredFromSingleCopy) {
      return AuthorityOutcome::StaleRevision;
    }
    // MAIN's binding clarification (and Sol43 HIGH fix): the two checks
    // above are both scoped to sameOwnership (UID+fullPK+cryptoDomain+
    // layout), so despite the H3 comment's stated intent, they do NOT
    // actually catch a relabeled profileId/layoutId/cryptoDomain (or a
    // changed fullPK) for the SAME physical chip -- that is a genuinely
    // different "owner" by those checks' definition, so a fresh genesis
    // Commission claiming a different profile/layout/crypto-domain label
    // (or key) would previously have been accepted even though real
    // history already exists for this exact physical device. The
    // lifetime fork-fence (samePhysicalLifetime: full PHYSICAL UID
    // ONLY, independent of fullPK/profile/layout/role/cryptoDomain
    // labels) must ALSO be checked here, not just in repairExisting/
    // rekeyExplicitly, so NO relabel of any kind -- including a
    // different AEAD crypto-form/group-selector -- can smuggle a fresh
    // "genesis" Commission in over an already-commissioned physical
    // device -- only repairExisting/rekeyExplicitly may extend that
    // device's real history.
    ReconciliationResult physical_lineage = registry_.reconcilePhysicalLineage(txn.binding);
    if (physical_lineage.outcome == ReconciliationOutcome::Uncertain) return AuthorityOutcome::RegistryDisagreement;
    if (physical_lineage.outcome == ReconciliationOutcome::Agreed ||
        physical_lineage.outcome == ReconciliationOutcome::RecoveredFromSingleCopy) {
      return AuthorityOutcome::StaleRevision;
    }
    const AuthorityOutcome verify_outcome = verifyIssuerSignature(txn);
    if (verify_outcome != AuthorityOutcome::Ok) return verify_outcome;
    if (!registry_.commitIssued(txn)) return AuthorityOutcome::Denied;
    return AuthorityOutcome::Ok;
  }

  // Submits a brand-new, already issuer-signed CertifyExistingBaseline
  // transaction: a narrower grant than Commission that certifies an
  // EXISTING stock OTA=1 image/loader as a legitimate Normal baseline --
  // see BaselineCertificationManifest.h for what `txn.manifestDigestSha256`
  // must be the digest of. Never advances past Issued: this operation
  // deliberately never enters the Commission/Repair/Rekey lifecycle (see
  // the OperationMismatch guards in prepare/resumePrepared/
  // activateExistingRoot below), so it grants no counter seed, no
  // identity generation, and no installation/commissioning authority.
  AuthorityOutcome submitCertifyExistingBaseline(const AuthorityTransaction& txn) {
    if (!dependenciesWired()) return AuthorityOutcome::Denied;
    AuthorityCrossProcessLockGuard lock_guard(crossProcessLock_);
    if (!lock_guard.acquired()) return AuthorityOutcome::Denied;
    if (txn.operation != AuthorityOperation::CertifyExistingBaseline) return AuthorityOutcome::OperationMismatch;
    // Defense in depth beyond the device-side guard: this operation can
    // never carry a predecessor/non-zero revision (it does not chain
    // off, or supersede, any prior Issued/ActivationSpent history) and
    // can never carry a non-zero TX/RX floor (it seeds no counters,
    // ever).
    if (txn.revision != 0) return AuthorityOutcome::StaleRevision;
    static const uint8_t kZeroTransactionId[kTransactionIdBytes] = {0};
    if (std::memcmp(txn.predecessorTransactionId, kZeroTransactionId, kTransactionIdBytes) != 0) {
      return AuthorityOutcome::StaleRevision;
    }
    if (txn.initialTxSequenceFloor != 0 || txn.initialRxReplayFloor != 0) return AuthorityOutcome::BindingMismatch;

    const AuthorityOutcome verify_outcome = verifyIssuerSignature(txn);
    if (verify_outcome != AuthorityOutcome::Ok) return verify_outcome;
    if (!registry_.commitIssued(txn)) return AuthorityOutcome::Denied;
    return AuthorityOutcome::Ok;
  }

  // Returns Ok only if `claimed` matches, field-for-field, the binding the
  // registry has on record for `transactionId` -- any single substituted
  // field (UID, fullPK, domain, profile, layout, consent owner, role) is a
  // BindingMismatch, even though the underlying signature is unaffected.
  AuthorityOutcome describeBinding(const uint8_t transactionId[kTransactionIdBytes], const AuthorityBinding& claimed,
                                    StoredTransactionRecord& out_record) {
    if (!dependenciesWired()) return AuthorityOutcome::Denied;
    ReconciliationResult rec = registry_.reconcile(transactionId);
    if (rec.outcome == ReconciliationOutcome::NotFound) return AuthorityOutcome::TransactionNotFound;
    if (rec.outcome == ReconciliationOutcome::Uncertain) return AuthorityOutcome::RegistryDisagreement;
    if (!bindingsExactlyEqual(rec.resolved.txn.binding, claimed)) return AuthorityOutcome::BindingMismatch;
    out_record = rec.resolved;
    return AuthorityOutcome::Ok;
  }

  // Issued -> ConsumedPrepared (both copies, read back) THEN the device
  // handshake THEN ConsumedPrepared -> ActivationSpent (both copies, read
  // back) -- exactly the ordering rule 5 requires. Never returns Ok
  // without every one of those steps having genuinely happened.
  AuthorityOutcome prepare(const uint8_t transactionId[kTransactionIdBytes], DeviceAuthoritySession& session,
                            const PrepareAuthorizationInputs& prepInputs, StoredTransactionRecord& out_record) {
    if (!dependenciesWired()) return AuthorityOutcome::Denied;
    AuthorityCrossProcessLockGuard lock_guard(crossProcessLock_);
    if (!lock_guard.acquired()) return AuthorityOutcome::Denied;
    ReconciliationResult rec = registry_.reconcile(transactionId);
    if (rec.outcome == ReconciliationOutcome::NotFound) return AuthorityOutcome::TransactionNotFound;
    if (rec.outcome == ReconciliationOutcome::Uncertain) return AuthorityOutcome::RegistryDisagreement;
    if (!eligibleForActivationLifecycle(rec.resolved.txn.operation)) return AuthorityOutcome::OperationMismatch;
    if (rec.resolved.state != TransactionState::Issued) return AuthorityOutcome::WrongState;

    const AuthorityOutcome verify_outcome = verifyIssuerSignature(rec.resolved.txn);
    if (verify_outcome != AuthorityOutcome::Ok) return verify_outcome;

    // Sol c577a77f (H2 residual): re-validate physical ownership lineage
    // NOW, immediately before consuming Issued into ConsumedPrepared --
    // not only at submitCommission/rekeyExplicitly time. A competing
    // transaction for this exact physical device could have been issued
    // and even reached ActivationSpent in the window since this one was
    // first issued.
    const AuthorityOutcome lineage_outcome = revalidatePhysicalOwnershipLineage(rec.resolved.txn);
    if (lineage_outcome != AuthorityOutcome::Ok) return lineage_outcome;

    if (rec.needsReplicaRepair) repairReplicaIssued(rec.resolved.txn);

    // Astra29: there is no issuer-precommitted root to record here
    // anymore -- the real R can only come from the device's own
    // stageRoot() during the handshake below. Commit ConsumedPrepared as
    // explicitly ROOT-UNBOUND (a zero placeholder digest that is NEVER
    // treated as a real, comparable root -- see the `rootBound` flag in
    // AuthorityRegistryPort.h), not a copied "success" value.
    uint8_t zero_root[kDigestBytes] = {0};
    uint8_t zero_challenge[kChallengeBytes] = {0};
    if (!registry_.commitStateTransition(transactionId, TransactionState::ConsumedPrepared, zero_root,
                                          /*rootBound=*/false, zero_challenge)) {
      return AuthorityOutcome::Denied;
    }

    return runPrepareHandshake(transactionId, session, prepInputs, out_record);
  }

  // Resumes an already-ConsumedPrepared transaction (no fresh registry
  // consumption -- the Issued credential was already spent) with a brand
  // new fresh challenge. Safe to call repeatedly after an interrupted or
  // rejected handshake.
  //
  // CORRECTED per review: this must be restricted to EXACTLY
  // ConsumedPrepared, never ActivationSpent. Before this fix, calling
  // resumePrepared on an already-ActivationSpent transaction still fell
  // through to runPrepareHandshake(), which unconditionally re-sends a
  // fresh PreparePermit -- causing the device to re-stage/commitStaged
  // (DeviceAuthorityGuard::verifyAndPrepare), which can clear the
  // device's own `activated` flag, BEFORE the host's own
  // commitStateTransition ever re-checks legality. That is a genuine
  // "accept a side effect, then maybe reject the second spend" ordering
  // bug: the device-side downgrade already happened by the time any
  // rejection could occur. An already-ActivationSpent transaction may
  // only be resumed via activateExistingRoot() (re-delivers the EXISTING
  // recorded permit, never re-stages).
  AuthorityOutcome resumePrepared(const uint8_t transactionId[kTransactionIdBytes], DeviceAuthoritySession& session,
                                    const PrepareAuthorizationInputs& prepInputs, StoredTransactionRecord& out_record) {
    if (!dependenciesWired()) return AuthorityOutcome::Denied;
    AuthorityCrossProcessLockGuard lock_guard(crossProcessLock_);
    if (!lock_guard.acquired()) return AuthorityOutcome::Denied;
    ReconciliationResult rec = registry_.reconcile(transactionId);
    if (rec.outcome == ReconciliationOutcome::NotFound) return AuthorityOutcome::TransactionNotFound;
    if (rec.outcome == ReconciliationOutcome::Uncertain) return AuthorityOutcome::RegistryDisagreement;
    if (!eligibleForActivationLifecycle(rec.resolved.txn.operation)) return AuthorityOutcome::OperationMismatch;
    // Only ConsumedPrepared may resume the PREPARE handshake -- Issued
    // must go through prepare() first, and ActivationSpent must go
    // through activateExistingRoot() instead (never re-stage an existing
    // activation).
    if (rec.resolved.state != TransactionState::ConsumedPrepared) return AuthorityOutcome::WrongState;
    return runPrepareHandshake(transactionId, session, prepInputs, out_record);
  }

  // Delivers the ALREADY-recorded ActivationSpent permit to the device and
  // verifies its signed activation acknowledgement. No registry write
  // happens here -- the spend already happened inside prepare(); this call
  // only ever hands off an existing grant and is safe to retry.
  AuthorityOutcome activateExistingRoot(const uint8_t transactionId[kTransactionIdBytes], DeviceAuthoritySession& session,
                                         StoredTransactionRecord& out_record) {
    if (!dependenciesWired()) return AuthorityOutcome::Denied;
    // The real close of the "replay a valid grant signature as
    // activation proof before both-copy Spent" gap requires actually
    // producing a fresh, domain-separated ActivationAuthorizationV1
    // signature below -- if no signing seam is wired, deny outright
    // rather than falling back to sending the permit without one.
    if (activationSigningTrust_ == nullptr) return AuthorityOutcome::Denied;
    AuthorityCrossProcessLockGuard lock_guard(crossProcessLock_);
    if (!lock_guard.acquired()) return AuthorityOutcome::Denied;
    ReconciliationResult rec = registry_.reconcile(transactionId);
    if (rec.outcome == ReconciliationOutcome::NotFound) return AuthorityOutcome::TransactionNotFound;
    if (rec.outcome == ReconciliationOutcome::Uncertain) return AuthorityOutcome::RegistryDisagreement;
    if (!eligibleForActivationLifecycle(rec.resolved.txn.operation)) return AuthorityOutcome::OperationMismatch;
    if (rec.resolved.state != TransactionState::ActivationSpent) return AuthorityOutcome::WrongState;

    if (rec.needsReplicaRepair) {
      // CORRECTED per review (M: "missing Spent replica repair only
      // transitions, empty copy lacks Issued forever"): this block used
      // to call ONLY commitStateTransition for ConsumedPrepared/
      // ActivationSpent -- if the lagging copy was not merely behind but
      // genuinely EMPTY for this transactionId (never received the
      // original Issued record at all, e.g. the very first commitIssued
      // write to it failed), appendStateTransition has no preceding
      // Issued row to advance from, so repair could NEVER actually
      // succeed: every future call would hit the exact same gap and
      // permanently deny, rather than genuinely self-healing. Rebuilding
      // via repairReplicaToResolved below always writes the resolved
      // Issued record FIRST (a harmless no-op if it is already present),
      // then the intermediate ConsumedPrepared/ActivationSpent
      // transitions in order, using ONLY the resolved record's own exact
      // digest/rootBound/challenge -- never a new grant, new root, or
      // reseed. Both commitStateTransition return values were also
      // previously discarded outright -- if either write failed (e.g.
      // one copy unwritable/missing), this fell through and still
      // signed/released an ActivationAuthorizationV1 backed by only ONE
      // copy genuinely reflecting ActivationSpent, violating rule 5's
      // "durably mark ActivationSpent in BOTH copies BEFORE returning
      // activation permission" and rule 7's "return authority only after
      // both independently persisted/read-back states agree". Now:
      // repair is attempted best-effort, AND a fresh re-reconciliation
      // afterwards must independently confirm BOTH copies agree at
      // ActivationSpent -- never trust the pre-repair snapshot, and
      // never treat an individual repair step's own return value as
      // success (see repairReplicaToResolved's own comment: one side
      // routinely, correctly, "fails" a redundant write).
      repairReplicaToResolved(rec.resolved);

      ReconciliationResult after_repair = registry_.reconcile(transactionId);
      if (after_repair.outcome != ReconciliationOutcome::Agreed) return AuthorityOutcome::RegistryDisagreement;
      if (after_repair.resolved.state != TransactionState::ActivationSpent) return AuthorityOutcome::RegistryDisagreement;
      rec = after_repair;  // Use the freshly confirmed, both-copy-agreed record from here on, not the stale pre-repair one.
    }

    // Sol fe862c8 residual (H5): the one positive storage barrier this
    // method MUST pass before signing and releasing an
    // ActivationAuthorization -- an Agreed reconcile() above (whether
    // from the fast path or post-repair) only proves both copies'
    // CONTENT currently matches; it does not prove either copy's
    // underlying write-time fsync genuinely reached stable storage.
    // Re-confirm both copies right now, immediately before signing.
    if (!registry_.confirmBothCopiesDurable()) return AuthorityOutcome::RegistryDisagreement;

    // Astra Sol fix (root cause): `deviceFreshChallenge` is no longer a
    // host-fabricated value -- round-trip to the REAL device and obtain
    // a genuinely device-minted, single-use challenge for exactly this
    // (Activate, transactionId) pair before building the authorization
    // that will bind it.
    uint8_t device_challenge[kChallengeBytes];
    if (!session.requestDeviceChallenge(AuthorityChallengePurpose::Activate, transactionId, device_challenge)) {
      return AuthorityOutcome::Denied;
    }
    // Independent fresh entropy from `device_challenge` above -- see
    // ActivationAuthorizationV1::hostNonce's freshness note: this value
    // cannot be chosen ahead of reaching this point, so the signature
    // below cannot be precomputed/cached before both copies were
    // confirmed ActivationSpent (the `rec.reconcile()` call just above).
    uint8_t host_nonce[kChallengeBytes];
    if (!challengeProvider_->freshChallenge(host_nonce)) return AuthorityOutcome::Denied;

    ActivationAuthorizationV1 auth;
    std::memcpy(auth.transactionId, rec.resolved.txn.transactionId, kTransactionIdBytes);
    // Astra29 fix: grantDigestSha256 MUST be A = SHA256(the exact
    // kRecordBytes signed grant record, INCLUDING the issuer signature)
    // -- NOT manifestDigestSha256 (M, the manifest's own policy digest).
    // Binding to M let this authorization be satisfied by ANY grant
    // whose manifest happened to match, regardless of transaction
    // identity/binding/revision -- a confirmed bug.
    if (!AuthorityCodec::computeRecordDigestSha256(rec.resolved.txn, auth.grantDigestSha256)) {
      return AuthorityOutcome::CorruptRecord;
    }
    // The ACTUAL registry-recorded ActivationSpent root -- re-read from
    // `rec.resolved`, not merely copied from the issuer's
    // expectedRootDigestSha256, so this authorization proves what the
    // durable record genuinely says, not just what was originally
    // expected.
    std::memcpy(auth.preparedRootDigestSha256, rec.resolved.preparedRootDigestSha256, kDigestBytes);
    auth.spentAuthorizedRevision = rec.resolved.txn.revision;
    auth.expectedBinding = rec.resolved.txn.binding;
    std::memcpy(auth.deviceFreshChallenge, device_challenge, kChallengeBytes);
    std::memcpy(auth.hostNonce, host_nonce, kChallengeBytes);

    uint8_t auth_message[ActivationAuthorizationCodec::kSignedMessageBytes];
    if (ActivationAuthorizationCodec::serializeSignedMessage(auth, auth_message, sizeof(auth_message)) !=
        ActivationAuthorizationCodec::kSignedMessageBytes) {
      return AuthorityOutcome::CorruptRecord;
    }
    if (!activationSigningTrust_->signActivationAuthorization(rec.resolved.txn.issuerKeyId, auth_message,
                                                                sizeof(auth_message), auth.issuerSignatureEd25519)) {
      return AuthorityOutcome::Denied;
    }

    ActivationPermit permit;
    permit.txn = rec.resolved.txn;
    std::memcpy(permit.preparedRootDigestSha256, rec.resolved.preparedRootDigestSha256, kDigestBytes);
    permit.activationAuth = auth;

    ActivationResponse response;
    if (!session.sendActivationPermit(permit, response)) return AuthorityOutcome::Denied;

    uint8_t message[AuthorityAckCodec::kMessageBytes];
    AuthorityAckCodec::serializeActivateAck(device_challenge, response.deviceNonce, transactionId,
                                             rec.resolved.preparedRootDigestSha256, message, sizeof(message));
    if (!verifier_->verify(response.deviceSignatureEd25519, kSignatureBytes, message, sizeof(message),
                            rec.resolved.txn.binding.meshFullPublicKey, kPublicKeyBytes)) {
      return AuthorityOutcome::SignatureInvalid;
    }

    out_record = rec.resolved;
    return AuthorityOutcome::Ok;
  }

  // Accepts an already-issuer-signed Repair transaction only if genuine
  // surviving ActivationSpent history exists for the SAME owner (UID +
  // fullPK + cryptoDomain + layout) and the new transaction's floors do
  // not regress below that history -- repair never fabricates a lower
  // watermark, and a missing history is a disabled state, not a reset.
  AuthorityOutcome repairExisting(const AuthorityTransaction& repairTxn) {
    if (!dependenciesWired()) return AuthorityOutcome::Denied;
    // Sol39 H1 fix: this entrypoint previously held NO cross-process
    // lease at all -- "repairExisting checks latest ACTIVATED old
    // owner, not pending physical tip" was only half the bug; the other
    // half is that without a lease, two independent repair/rekey
    // issuers racing the exact same owner could each perform their own
    // check-then-act window entirely unserialized against each other,
    // exactly the fork this lease exists to close everywhere else.
    AuthorityCrossProcessLockGuard lock_guard(crossProcessLock_);
    if (!lock_guard.acquired()) return AuthorityOutcome::Denied;
    if (repairTxn.operation != AuthorityOperation::Repair) return AuthorityOutcome::BindingMismatch;

    const AuthorityOutcome verify_outcome = verifyIssuerSignature(repairTxn);
    if (verify_outcome != AuthorityOutcome::Ok) return verify_outcome;

    ReconciliationResult prior = registry_.reconcileLatestActivationForOwner(repairTxn.binding);
    if (prior.outcome == ReconciliationOutcome::NotFound) return AuthorityOutcome::MissingHistory;
    if (prior.outcome == ReconciliationOutcome::Uncertain) return AuthorityOutcome::RegistryDisagreement;

    if (!chainsFromPredecessor(repairTxn, prior.resolved.txn)) return AuthorityOutcome::StaleRevision;
    if (repairTxn.initialTxSequenceFloor < prior.resolved.txn.initialTxSequenceFloor) return AuthorityOutcome::StaleRevision;
    if (repairTxn.initialRxReplayFloor < prior.resolved.txn.initialRxReplayFloor) return AuthorityOutcome::StaleRevision;

    // Sol39 H1 fix: `prior` above (readLatestActivationForOwner) is
    // STRUCTURALLY BLIND to a pending (Issued/ConsumedPrepared, not yet
    // ActivationSpent) successor already claimed under a DIFFERENT
    // fullPK for this SAME physical device -- e.g. ActivationSpent A,
    // then a Rekey A->B reaches Issued (not yet activated), then a
    // Repair for the OLD owner A at the SAME revision/predecessor as
    // the (still-pending) B would previously have been accepted here,
    // forking the physical lineage the moment B later activates.
    // reconcilePhysicalLineage scans by physical device identity
    // (UID+cryptoDomain+layout only, deliberately ignoring fullPK)
    // across ANY state (purpose-filtered to exclude
    // CertifyExistingBaseline, which is never lineage history) -- the
    // SAME fence rekeyExplicitly already applies at its own issuance
    // point, applied here too so a sequential pending-rekey-then-repair
    // is denied exactly like a genuinely concurrent one.
    ReconciliationResult lineage = registry_.reconcilePhysicalLineage(repairTxn.binding);
    if (lineage.outcome == ReconciliationOutcome::Uncertain) return AuthorityOutcome::RegistryDisagreement;
    if (lineage.outcome == ReconciliationOutcome::Agreed || lineage.outcome == ReconciliationOutcome::RecoveredFromSingleCopy) {
      const bool tip_is_prior = std::memcmp(lineage.resolved.txn.transactionId, prior.resolved.txn.transactionId,
                                             kTransactionIdBytes) == 0;
      const bool tip_is_this_candidate =
          std::memcmp(lineage.resolved.txn.transactionId, repairTxn.transactionId, kTransactionIdBytes) == 0;
      if (!tip_is_prior && !tip_is_this_candidate) return AuthorityOutcome::StaleRevision;
    }

    if (!registry_.commitIssued(repairTxn)) return AuthorityOutcome::Denied;
    return AuthorityOutcome::Ok;
  }

  // Accepts an already-issuer-signed Rekey transaction: same physical
  // device/domain/layout as `priorBinding`, but a GENUINELY different Mesh
  // full public key (a role/label change alone is never accepted here --
  // see AuthorityBinding::sameDeviceIdentity).
  AuthorityOutcome rekeyExplicitly(const AuthorityTransaction& rekeyTxn, const AuthorityBinding& priorBinding) {
    if (!dependenciesWired()) return AuthorityOutcome::Denied;
    // Sol39 H1 fix: same missing-lease defect as repairExisting above --
    // this entrypoint previously held NO cross-process lease either.
    AuthorityCrossProcessLockGuard lock_guard(crossProcessLock_);
    if (!lock_guard.acquired()) return AuthorityOutcome::Denied;
    if (rekeyTxn.operation != AuthorityOperation::Rekey) return AuthorityOutcome::BindingMismatch;
    if (!rekeyTxn.binding.sameDeviceIdentity(priorBinding)) return AuthorityOutcome::BindingMismatch;
    if (std::memcmp(rekeyTxn.binding.meshFullPublicKey, priorBinding.meshFullPublicKey, kPublicKeyBytes) == 0) {
      // A label/role/UID relabel is NOT a rekey: the key material must
      // actually change, or this is rejected outright.
      return AuthorityOutcome::BindingMismatch;
    }

    const AuthorityOutcome verify_outcome = verifyIssuerSignature(rekeyTxn);
    if (verify_outcome != AuthorityOutcome::Ok) return verify_outcome;

    ReconciliationResult prior = registry_.reconcileLatestActivationForOwner(priorBinding);
    if (prior.outcome == ReconciliationOutcome::NotFound) return AuthorityOutcome::MissingHistory;
    if (prior.outcome == ReconciliationOutcome::Uncertain) return AuthorityOutcome::RegistryDisagreement;
    if (!chainsFromPredecessor(rekeyTxn, prior.resolved.txn)) return AuthorityOutcome::StaleRevision;

    // H-finding fix ("rekey A->B reaches Issued/ConsumedPrepared but not
    // yet ActivationSpent, then a competing rekey A->C for the SAME
    // predecessor+revision is ALSO accepted"): `prior` above is scoped
    // to readLatestActivationForOwner, which ONLY ever sees the OLD
    // key's ActivationSpent record -- it is structurally blind to a
    // PENDING (not yet activated) successor already claimed under a
    // DIFFERENT new fullPK, because that successor's Issued/
    // ConsumedPrepared rows are filed under ITS OWN fullPK, not the old
    // one. reconcilePhysicalLineage scans by physical device identity
    // (UID+cryptoDomain+layout only, deliberately ignoring fullPK) across
    // ANY state, so it sees exactly that pending successor. If the
    // lineage tip is neither the OLD key's own record (no successor
    // pending yet) nor THIS candidate itself, some OTHER transaction
    // already claimed this predecessor+revision -- block the fork here
    // rather than silently letting both succeed. (Note: `tip_is_this_
    // candidate` guards against this SAME lineage tip being the
    // candidate under evaluation -- it does not, by itself, make a
    // byte-identical resubmission of an already-committed transactionId
    // succeed below; commitIssued/appendIssued independently and
    // unconditionally refuse ANY duplicate transactionId, by design,
    // regardless of this fork fence.)
    ReconciliationResult lineage = registry_.reconcilePhysicalLineage(priorBinding);
    if (lineage.outcome == ReconciliationOutcome::Uncertain) return AuthorityOutcome::RegistryDisagreement;
    if (lineage.outcome == ReconciliationOutcome::Agreed || lineage.outcome == ReconciliationOutcome::RecoveredFromSingleCopy) {
      const bool tip_is_prior = std::memcmp(lineage.resolved.txn.transactionId, prior.resolved.txn.transactionId,
                                             kTransactionIdBytes) == 0;
      const bool tip_is_this_candidate =
          std::memcmp(lineage.resolved.txn.transactionId, rekeyTxn.transactionId, kTransactionIdBytes) == 0;
      if (!tip_is_prior && !tip_is_this_candidate) return AuthorityOutcome::StaleRevision;
    }

    if (!registry_.commitIssued(rekeyTxn)) return AuthorityOutcome::Denied;
    return AuthorityOutcome::Ok;
  }

  AuthorityRegistryPair& registry() { return registry_; }

private:
  // Only these three operations ever move through Issued->
  // ConsumedPrepared->ActivationSpent. CertifyExistingBaseline (and any
  // future non-lifecycle operation) is refused here explicitly -- this
  // is the "reject cross-use" guard the approved contract requires,
  // rather than relying on state alone (a CertifyExistingBaseline
  // transaction never reaches ConsumedPrepared/ActivationSpent in the
  // first place, but this guard makes that an enforced invariant, not
  // an incidental one).
  static bool eligibleForActivationLifecycle(AuthorityOperation operation) {
    return operation == AuthorityOperation::Commission || operation == AuthorityOperation::Repair ||
           operation == AuthorityOperation::Rekey;
  }

  static bool bindingsExactlyEqual(const AuthorityBinding& a, const AuthorityBinding& b) {
    return std::memcmp(a.hardwareUid, b.hardwareUid, kHardwareUidBytes) == 0 &&
           std::memcmp(a.meshFullPublicKey, b.meshFullPublicKey, kPublicKeyBytes) == 0 &&
           a.cryptoDomain == b.cryptoDomain && a.profileId == b.profileId && a.layoutId == b.layoutId &&
           a.historicalInitialRoleId == b.historicalInitialRoleId &&
           std::memcmp(a.consentOwnerPublicKey, b.consentOwnerPublicKey, kPublicKeyBytes) == 0;
  }

  static bool chainsFromPredecessor(const AuthorityTransaction& candidate, const AuthorityTransaction& predecessor) {
    if (candidate.revision != predecessor.revision + 1) return false;
    return std::memcmp(candidate.predecessorTransactionId, predecessor.transactionId, kTransactionIdBytes) == 0;
  }

  // Sol c577a77f (H2 residual): "revalidate physical UID/full owner/
  // predecessor BEFORE Prepare AND Spent, not just issue". A
  // Commission/Repair/Rekey transaction's own existence at Issued/
  // ConsumedPrepared is NOT, by itself, still proof that it remains the
  // dominant surviving record for its physical device identity at the
  // LATER moment prepare()/the final Spent-transition actually runs --
  // e.g. a competing Rekey to a different fullPK for the SAME physical
  // UID could have been submitted and itself reached ActivationSpent in
  // the window between this transaction's Issue and its Prepare/Spend.
  // Re-run the SAME physical-lineage dominance check rekeyExplicitly()
  // already performs at issue time, but against `txn` (the EXACT
  // transaction about to be prepared/spent) as the candidate: if some
  // OTHER transactionId is now the lineage tip, this one has been
  // superseded and must be refused here, never silently allowed to
  // proceed and consume/activate stale ownership.
  AuthorityOutcome revalidatePhysicalOwnershipLineage(const AuthorityTransaction& txn) const {
    ReconciliationResult lineage = registry_.reconcilePhysicalLineage(txn.binding);
    if (lineage.outcome == ReconciliationOutcome::Uncertain) return AuthorityOutcome::RegistryDisagreement;
    if (lineage.outcome == ReconciliationOutcome::NotFound) {
      // This transaction is already known to exist in the registry (the
      // caller fetched it via reconcile() moments ago) -- a physical-
      // lineage scan over the SAME physical UID+domain+layout finding
      // nothing at all is an internal inconsistency, never a green
      // light.
      return AuthorityOutcome::RegistryDisagreement;
    }
    if (lineage.outcome == ReconciliationOutcome::Agreed || lineage.outcome == ReconciliationOutcome::RecoveredFromSingleCopy) {
      const bool tip_is_this_txn =
          std::memcmp(lineage.resolved.txn.transactionId, txn.transactionId, kTransactionIdBytes) == 0;
      if (!tip_is_this_txn) return AuthorityOutcome::StaleRevision;
    }
    return AuthorityOutcome::Ok;
  }

  AuthorityOutcome verifyIssuerSignature(const AuthorityTransaction& txn) const {
    uint8_t issuer_public_key[kPublicKeyBytes];
    if (!issuerTrust_->lookupIssuerPublicKey(txn.issuerKeyId, issuer_public_key)) return AuthorityOutcome::Denied;
    uint8_t message[AuthorityCodec::kSignedMessageBytes];
    const size_t written = AuthorityCodec::serializeSignedMessage(txn, message, sizeof(message));
    if (written != AuthorityCodec::kSignedMessageBytes) return AuthorityOutcome::CorruptRecord;
    if (!verifier_->verify(txn.issuerSignatureEd25519, kSignatureBytes, message, written, issuer_public_key, kPublicKeyBytes)) {
      return AuthorityOutcome::SignatureInvalid;
    }
    return AuthorityOutcome::Ok;
  }

  void repairReplicaIssued(const AuthorityTransaction& txn) {
    // Best-effort: bring a missing/lagging copy back up to an already-
    // agreed Issued record. Never used to manufacture a NEW decision --
    // reconcile() already determined `txn` is the dominant truth.
    registry_.copyA().appendIssued(txn);
    registry_.copyB().appendIssued(txn);
  }

  // General-purpose, ORDER-preserving, idempotent replica repair: brings
  // BOTH copies up to `resolved`'s exact lineage (Issued -> optionally
  // ConsumedPrepared -> optionally ActivationSpent), never a fresh grant,
  // never a different/invented root, never skipping ahead. Best-effort
  // and intentionally void: each underlying commitStateTransition is
  // itself a two-copy "both must accept" call, but during a REPAIR one
  // side routinely already holds the target state and legitimately
  // rejects the (redundant) write as a non-monotonic advance -- so the
  // pair-level "a_ok && b_ok" result of an individual repair step is
  // NOT a meaningful success signal here (it would read as "failed"
  // even when the one side that actually needed the write succeeded).
  // The only thing that may ever be trusted as "repair worked" is a
  // FRESH, independent reconcile() call the CALLER performs afterwards
  // and requires to report Agreed at exactly `resolved.state` -- every
  // call site below does exactly that.
  void repairReplicaToResolved(const StoredTransactionRecord& resolved) {
    repairReplicaIssued(resolved.txn);
    if (resolved.state == TransactionState::Issued) return;

    // ConsumedPrepared is ALWAYS committed root-UNBOUND with this fixed,
    // never-a-real-value placeholder (see prepare()) -- reconstructing
    // it here uses the exact same constant, never `resolved`'s OWN
    // (possibly ActivationSpent, rootBound=true) digest, which would
    // wrongly claim a root was already bound at the ConsumedPrepared
    // step.
    static const uint8_t kZeroRoot[kDigestBytes] = {0};
    static const uint8_t kZeroChallenge[kChallengeBytes] = {0};
    registry_.commitStateTransition(resolved.txn.transactionId, TransactionState::ConsumedPrepared, kZeroRoot,
                                      /*rootBound=*/false, kZeroChallenge);
    if (resolved.state == TransactionState::ConsumedPrepared) return;

    registry_.commitStateTransition(resolved.txn.transactionId, TransactionState::ActivationSpent,
                                      resolved.preparedRootDigestSha256, /*rootBound=*/true, resolved.challenge);
  }

  AuthorityOutcome runPrepareHandshake(const uint8_t transactionId[kTransactionIdBytes], DeviceAuthoritySession& session,
                                        const PrepareAuthorizationInputs& prepInputs, StoredTransactionRecord& out_record) {
    // Astra Sol fix: a genuine PrepareAuthorizationV1 requires the SAME
    // explicit signing seam as ActivationAuthorizationV1 -- deny outright
    // if it is not wired, rather than sending a bare, unsigned permit
    // (the exact "no fresh device challenge ever verified" root cause).
    if (prepareSigningTrust_ == nullptr) return AuthorityOutcome::Denied;

    ReconciliationResult rec = registry_.reconcile(transactionId);
    if (rec.outcome == ReconciliationOutcome::RecoveredFromSingleCopy) {
      // CORRECTED per review (M: "prepare returns Ok-Spent after a fresh
      // RecoveredFromSingleCopy readback"): entering the device
      // handshake on a KNOWN single-copy (not durably two-copy-agreed)
      // starting state, and only fixing the replica gap retroactively
      // after the handshake already ran, let a "completed two-copy
      // prepare" be reported even though the STARTING state was never
      // actually confirmed durable on both copies. Repair the gap FIRST
      // (never fabricating a new decision -- `rec.resolved` is already
      // the dominant truth reconcile() determined) and REQUIRE a fresh
      // Agreed confirmation before ever running the device handshake;
      // if repair still cannot produce Agreed, fail explicitly rather
      // than silently proceeding on a single-copy basis.
      repairReplicaToResolved(rec.resolved);
      ReconciliationResult after_repair = registry_.reconcile(transactionId);
      if (after_repair.outcome != ReconciliationOutcome::Agreed) return AuthorityOutcome::RegistryDisagreement;
      rec = after_repair;
    } else if (rec.outcome != ReconciliationOutcome::Agreed) {
      return AuthorityOutcome::RegistryDisagreement;
    }

    // Sol fe862c8 residual (H5): a plain Agreed reconcile() above is not
    // enough to justify sending a PreparePermit -- it can observe bytes
    // that reached the page cache despite an earlier fsync failure that
    // was never actually confirmed durable. Positively re-confirm BOTH
    // copies right now, immediately before this permission release.
    if (!registry_.confirmBothCopiesDurable()) return AuthorityOutcome::RegistryDisagreement;

    // Astra Sol fix (root cause): `deviceFreshChallenge` is no longer a
    // host-fabricated value -- round-trip to the REAL device and obtain
    // a genuinely device-minted, single-use challenge for exactly this
    // (Prepare, transactionId) pair before building the authorization
    // that will bind it.
    uint8_t device_challenge[kChallengeBytes];
    if (!session.requestDeviceChallenge(AuthorityChallengePurpose::Prepare, transactionId, device_challenge)) {
      return AuthorityOutcome::Denied;
    }
    // Independent fresh HOST entropy for `hostNonce` -- distinct from
    // `device_challenge` above, same freshness rationale as
    // ActivationAuthorizationV1::hostNonce.
    uint8_t host_nonce[kChallengeBytes];
    if (!challengeProvider_->freshChallenge(host_nonce)) return AuthorityOutcome::Denied;

    PrepareAuthorizationV1 auth;
    std::memcpy(auth.transactionId, rec.resolved.txn.transactionId, kTransactionIdBytes);
    if (!AuthorityCodec::computeRecordDigestSha256(rec.resolved.txn, auth.grantDigestSha256)) {
      return AuthorityOutcome::CorruptRecord;
    }
    if (!PrepareAuthorizationCodec::computeInputDigestSha256(rec.resolved.txn, prepInputs.certifyTxn, prepInputs.manifest,
                                                              prepInputs.rxContextKind, prepInputs.peerFullPublicKey,
                                                              auth.inputDigestSha256)) {
      return AuthorityOutcome::CorruptRecord;
    }
    auth.authorizedRevision = rec.resolved.txn.revision;
    auth.expectedBinding = rec.resolved.txn.binding;
    std::memcpy(auth.deviceFreshChallenge, device_challenge, kChallengeBytes);
    std::memcpy(auth.hostNonce, host_nonce, kChallengeBytes);

    uint8_t auth_message[PrepareAuthorizationCodec::kSignedMessageBytes];
    if (PrepareAuthorizationCodec::serializeSignedMessage(auth, auth_message, sizeof(auth_message)) !=
        PrepareAuthorizationCodec::kSignedMessageBytes) {
      return AuthorityOutcome::CorruptRecord;
    }
    if (!prepareSigningTrust_->signPrepareAuthorization(rec.resolved.txn.issuerKeyId, auth_message, sizeof(auth_message),
                                                          auth.issuerSignatureEd25519)) {
      return AuthorityOutcome::Denied;
    }

    PreparePermit permit;
    permit.txn = rec.resolved.txn;
    permit.auth = auth;

    PreparedRootResponse response;
    if (!session.sendPreparePermit(permit, response)) return AuthorityOutcome::Denied;

    uint8_t message[AuthorityAckCodec::kMessageBytes];
    AuthorityAckCodec::serializePrepareAck(device_challenge, response.deviceNonce, transactionId, response.rootDigestSha256,
                                            message, sizeof(message));
    if (!verifier_->verify(response.deviceSignatureEd25519, kSignatureBytes, message, sizeof(message),
                            rec.resolved.txn.binding.meshFullPublicKey, kPublicKeyBytes)) {
      return AuthorityOutcome::SignatureInvalid;
    }

    // Sol c577a77f (H2 residual): re-validate physical ownership lineage
    // ONE MORE TIME, immediately before the final ActivationSpent commit
    // -- not only at submitCommission/prepare's own entry. The device
    // handshake above can take real wall-clock time (a human swaps a USB
    // cable, a radio/serial round trip), during which a competing
    // transaction for this exact physical device could have reached
    // ActivationSpent via a different, concurrently-running coordinator
    // call.
    const AuthorityOutcome final_lineage_outcome = revalidatePhysicalOwnershipLineage(rec.resolved.txn);
    if (final_lineage_outcome != AuthorityOutcome::Ok) return final_lineage_outcome;

    // Astra29: there is no issuer-precommitted expectedRootDigestSha256
    // left to compare against -- R is genuinely unknown until the device
    // reports it here. The device's signature (just verified above) over
    // `response.rootDigestSha256` IS the proof that it actually staged
    // exactly this value; this is the FIRST moment R becomes known and
    // bound, which is exactly why ConsumedPrepared was committed as
    // root-UNBOUND a moment ago in prepare()/held unbound across any
    // resumePrepared() retries.
    if (!registry_.commitStateTransition(transactionId, TransactionState::ActivationSpent, response.rootDigestSha256,
                                          /*rootBound=*/true, device_challenge)) {
      return AuthorityOutcome::Denied;
    }

    ReconciliationResult after = registry_.reconcile(transactionId);
    if (after.outcome == ReconciliationOutcome::RecoveredFromSingleCopy) {
      // M4 fix ("prepare's final Spent-commit path still accepts a
      // RecoveredFromSingleCopy reconciliation result as a completed,
      // durable two-copy Spent"): the repair-then-require-Agreed
      // discipline applied to the STARTING state above must also apply
      // here, to the FINAL state, after BOTH ActivationSpent appends
      // were just attempted. A fresh read-back failure on either copy
      // immediately after both appends "succeeded" (e.g. one copy's
      // write landed but a later independent read of it faults, or the
      // two copies never actually agreed because only one accepted the
      // transition) must never be reported as a completed two-copy
      // Spent -- attempt one genuine repair-to-Agreed pass, and if that
      // still cannot produce Agreed, fail explicitly rather than
      // silently returning Ok on unconfirmed single-copy evidence.
      repairReplicaToResolved(after.resolved);
      after = registry_.reconcile(transactionId);
    }
    if (after.outcome != ReconciliationOutcome::Agreed) {
      return AuthorityOutcome::RegistryDisagreement;
    }
    if (after.resolved.state != TransactionState::ActivationSpent) return AuthorityOutcome::RegistryDisagreement;

    // Sol fe862c8 residual (H5): same positive barrier requirement
    // applies to the FINAL ActivationSpent confirmation -- an Agreed
    // reconcile() alone is not proof either copy's marker fsync actually
    // reached stable storage. Re-confirm both copies right now, BEFORE
    // reporting this handshake as a completed two-copy Spent (which is
    // what ultimately permits activateExistingRoot() to sign and release
    // an ActivationAuthorization later).
    if (!registry_.confirmBothCopiesDurable()) return AuthorityOutcome::RegistryDisagreement;

    out_record = after.resolved;
    return AuthorityOutcome::Ok;
  }

  AuthorityRegistryPair& registry_;
  ota::trust::SignatureVerifier* verifier_;
  AuthorityIssuerTrust* issuerTrust_;
  AuthorityChallengeProvider* challengeProvider_;
  AuthorityActivationSigningTrust* activationSigningTrust_;
  AuthorityCrossProcessLock* crossProcessLock_;
  AuthorityPrepareSigningTrust* prepareSigningTrust_;
};

}  // namespace authority
}  // namespace ota
