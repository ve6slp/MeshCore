#pragma once

// Portable, default-denying DEVICE-side authority guard: the firmware-
// facing half of the commissioning lifecycle. Every dependency
// (signature verifier, issuer trust, entropy, durable local history,
// maintenance/staging hook, identity signer) is an abstract interface
// with NO production-shaped default anywhere in this header -- a guard
// missing any one of them denies every operation. Wiring the real NVS/
// flash-backed DeviceAuthorityStore, the real device identity signer
// (IdentityStore), and the real staging/activation side effects is
// Firmware/Store's integration step, coordinated by MAIN; this header
// only defines the narrow, safe interfaces and the fail-closed logic that
// consumes them.
//
// This guard never reseeds an activation from nothing: verifyAndActivate
// requires a LOCALLY, DURABLY staged root that matches exactly -- losing
// the local staged record (flash wipe, corruption) makes activation
// impossible again until a genuine new prepare() round trip, never an
// automatic "assume factory/first use" fallback.

#include <stdint.h>
#include <cstring>
#include "ota/authority/AuthorityTypes.h"
#include "ota/authority/AuthorityCodec.h"
#include "ota/authority/AuthorityHostInterfaces.h"
#include "ota/authority/AuthorityDeviceSession.h"
#include "ota/authority/PrepareAuthorizationCodec.h"
#include "ota/trust/SignatureVerifier.h"

namespace ota {
namespace authority {

// The device's own durable record of what it has staged/activated. There
// is deliberately no in-memory-only production implementation: a device
// that cannot durably persist this must deny rather than behave as if it
// were blank (which would look exactly like a fabricated "first use").
struct DeviceAuthorityState {
  bool staged = false;
  bool activated = false;
  uint8_t transactionId[kTransactionIdBytes] = {0};
  uint8_t stagedRootDigestSha256[kDigestBytes] = {0};
  uint32_t txSequenceFloor = 0;
  uint32_t rxReplayFloor = 0;
};

// H2 fix: a read of the device's local authority state can end in
// exactly one of three distinguishable ways, and callers must never
// conflate them. `PositivelyEmpty` is the ONLY status that may ever be
// treated as "genuinely never staged, blank device" -- reported strictly
// when the underlying store positively confirms nothing has ever been
// written. Any read/IO FAILURE (flash read error, corrupted record,
// unavailable storage) is `Error` and must deny before ANY
// prepare/stage/activate/counter mutation, never silently treated the
// same as a blank device -- a failure that LOOKS blank would be
// indistinguishable from fabricated first-use proof.
// H2 fix extended: `Pending` means the underlying store genuinely cannot
// answer synchronously RIGHT NOW (e.g. a real flash/Store backend
// reports WouldBlock) -- distinct from both `Present` and
// `PositivelyEmpty`. Callers must never fold `Pending` into either of
// those; it means "retry this same read later", not "confirmed blank"
// nor "confirmed content".
enum class DeviceAuthorityReadStatus : uint8_t { Present = 0, PositivelyEmpty = 1, Error = 2, Pending = 3 };

// Tri-state result for the device-local mutating I/O boundary
// (commitStaged/commitActivated/stageRoot/activateStagedRoot). A real
// backend (flash/Store) may need more than one tick to durably complete
// a write -- `Pending` lets the guard's verifyAndPrepare/verifyAndActivate
// resume the SAME in-flight operation on a later call (same owning
// transactionId) WITHOUT re-verifying the signature or re-consuming the
// already-spent device challenge a second time. There is no success-
// shaped fallback: a backend that cannot distinguish "still working" from
// "done" must report `Denied`, never silently coerce `Pending` into `Ok`.
enum class DeviceAuthorityIoStatus : uint8_t { Ok = 0, Pending = 1, Denied = 2 };

class DeviceAuthorityStore {
public:
  virtual ~DeviceAuthorityStore() = default;
  // Returns `PositivelyEmpty` iff nothing has ever been staged (a
  // genuinely blank device); `Present` iff `out` was filled in with a
  // real prior record; `Error` iff the store itself could not be read at
  // all (flash fault, corrupt record, unavailable storage) -- callers
  // must deny immediately on `Error`, before any further mutation, never
  // treating it the same as `PositivelyEmpty`. `Pending` means retry
  // later; never fold it into either terminal status.
  virtual DeviceAuthorityReadStatus readCurrent(DeviceAuthorityState& out) const = 0;
  virtual DeviceAuthorityIoStatus commitStaged(const uint8_t transactionId[kTransactionIdBytes],
                                                const uint8_t rootDigestSha256[kDigestBytes], uint32_t txSequenceFloor,
                                                uint32_t rxReplayFloor) = 0;
  virtual DeviceAuthorityIoStatus commitActivated(const uint8_t transactionId[kTransactionIdBytes],
                                                   const uint8_t rootDigestSha256[kDigestBytes]) = 0;
};


class DeviceAuthorityEntropy {
public:
  virtual ~DeviceAuthorityEntropy() = default;
  virtual bool freshNonce(uint8_t out_nonce[kChallengeBytes]) = 0;
};

// The actual on-device side effects of staging/activating a root. This
// guard contains NO flash/counter access itself -- it only decides
// whether those side effects are authorized, and durably records that
// decision via DeviceAuthorityStore before ever reporting success.
class DeviceAuthorityMaintenance {
public:
  virtual ~DeviceAuthorityMaintenance() = default;
  // Astra29: stageRoot no longer merely returns a bool -- there is no
  // issuer-precommitted root left to fall back to (AuthorityTransaction
  // carries no expectedRootDigestSha256 field anymore). A real
  // implementation must actually apply the manifest to real per-device
  // storage, durably persist the versioned prepared-facts artifact P,
  // and write the genuine R = PreparedRootCommitment::computeDigestSha256(P)
  // into `out_rootDigestSha256` BEFORE returning `Ok`. Returning `Ok`
  // without writing a real digest here would silently resurrect the
  // exact "fake ACK R" defect this change exists to close -- there is no
  // default production implementation in this module, only this
  // abstract, default-denying seam. `Pending` means this exact call must
  // be retried later (bounded by service/main ticks, not a synchronous
  // spin) with NO side effects yet committed.
  virtual DeviceAuthorityIoStatus stageRoot(const AuthorityTransaction& txn, uint8_t out_rootDigestSha256[kDigestBytes]) = 0;
  virtual DeviceAuthorityIoStatus activateStagedRoot(const uint8_t transactionId[kTransactionIdBytes],
                                                      const uint8_t rootDigestSha256[kDigestBytes]) = 0;
};

// The device's own Ed25519 identity signing hook (the private-key half of
// `AuthorityBinding::meshFullPublicKey`). A real implementation delegates
// to the device's existing identity/signing infrastructure; this guard
// never holds or derives a private key itself.
class DeviceIdentitySigner {
public:
  virtual ~DeviceIdentitySigner() = default;
  virtual bool signWithDeviceIdentity(const uint8_t* message, size_t message_len, uint8_t out_signature[kSignatureBytes]) = 0;
};

// Narrow, non-boolean grant handed to TX/RX adapters once activation
// succeeds -- never a generic "factory = true" flag. A future integrator
// seeds the real OtaTxSequenceLedger / OtaRxReplayLedger from exactly
// these fields, never from anything computed independently of this guard.
struct TxRxActivationGrant {
  uint8_t transactionId[kTransactionIdBytes] = {0};
  uint32_t txSequenceFloor = 0;
  uint32_t rxReplayFloor = 0;
};

class DeviceAuthorityGuard {
public:
  DeviceAuthorityGuard(const AuthorityBinding& ownIdentity, ota::trust::SignatureVerifier* verifier,
                        AuthorityIssuerTrust* issuerTrust, DeviceAuthorityEntropy* entropy, DeviceAuthorityStore* store,
                        DeviceAuthorityMaintenance* maintenance, DeviceIdentitySigner* signer)
      : ownIdentity_(ownIdentity),
        verifier_(verifier),
        issuerTrust_(issuerTrust),
        entropy_(entropy),
        store_(store),
        maintenance_(maintenance),
        signer_(signer) {}
  // Zero I/O in the constructor.

  bool dependenciesWired() const {
    return verifier_ != nullptr && issuerTrust_ != nullptr && entropy_ != nullptr && store_ != nullptr &&
           maintenance_ != nullptr && signer_ != nullptr;
  }

  const AuthorityBinding& ownIdentity() const { return ownIdentity_; }

  // Mints a fresh, single-use, device-owned challenge for exactly this
  // (purpose, transactionId) pair, overwriting any previous outstanding
  // challenge (e.g. a cancelled/superseded prior attempt). The host's
  // DeviceAuthoritySession::requestDeviceChallenge seam calls this on the
  // real device; LoopbackDeviceSession calls it in-process for tests.
  // Only an EXACT (purpose, transactionId, bytes) match later consumes
  // it -- a foreign/mismatched presentation never invalidates it (the
  // real owner can still retry).
  bool beginChallenge(AuthorityChallengePurpose purpose, const uint8_t transactionId[kTransactionIdBytes],
                       uint8_t out_challenge[kChallengeBytes]) {
    if (!dependenciesWired()) return false;
    uint8_t fresh[kChallengeBytes];
    if (!entropy_->freshNonce(fresh)) return false;
    outstandingChallenge_.active = true;
    outstandingChallenge_.purpose = purpose;
    std::memcpy(outstandingChallenge_.transactionId, transactionId, kTransactionIdBytes);
    std::memcpy(outstandingChallenge_.challenge, fresh, kChallengeBytes);
    std::memcpy(out_challenge, fresh, kChallengeBytes);
    return true;
  }

  // Invalidates any outstanding challenge (disconnect/reset/timeout/valid
  // owner cancel) -- a foreign request must never be able to call this to
  // invalidate another session's unused challenge; only the owning
  // session/job does.
  void cancelChallenge() { outstandingChallenge_.active = false; }

  AuthorityOutcome verifyAndPrepare(const PreparePermit& permit, PreparedRootResponse& out_response) {
    if (!dependenciesWired()) return AuthorityOutcome::Denied;
    const bool resuming = preparePhase_ != PrepareContinuationPhase::None &&
                           std::memcmp(preparedTxnId_, permit.txn.transactionId, kTransactionIdBytes) == 0;

    if (resuming) {
      // Sol review HIGH fix: a Pending stageRoot()/commitStaged()
      // continuation used to match ONLY the bare transactionId, then
      // fall straight through to the staging/committing phases below
      // using THIS call's `permit.txn`/`permit.auth` directly -- a
      // same-transaction-id retry carrying CHANGED fields (e.g. a
      // different initialTxSequenceFloor/initialRxReplayFloor, a
      // different binding, or any other field) would reach
      // stageRoot()/commitStaged() entirely unverified, since neither
      // the issuer signature nor the PrepareAuthorizationV1 signature
      // nor the challenge is re-checked on a resuming call. Guard against
      // this by requiring the CURRENT permit's txn/auth to be byte-for-
      // byte identical (via their own canonical signed-record encoding,
      // which covers every field INCLUDING the issuer signature) to what
      // was retained from the ORIGINAL verified call. A changed/foreign
      // retry is rejected here with NO mutation and the in-flight
      // continuation left completely untouched, so the genuine owner can
      // still resume later with an EXACT retry.
      uint8_t current_txn_record[AuthorityCodec::kRecordBytes];
      uint8_t current_auth_record[PrepareAuthorizationCodec::kRecordBytes];
      if (AuthorityCodec::serializeRecord(permit.txn, current_txn_record, sizeof(current_txn_record)) !=
              AuthorityCodec::kRecordBytes ||
          PrepareAuthorizationCodec::serializeRecord(permit.auth, current_auth_record, sizeof(current_auth_record)) !=
              PrepareAuthorizationCodec::kRecordBytes) {
        return AuthorityOutcome::CorruptRecord;
      }
      uint8_t retained_txn_record[AuthorityCodec::kRecordBytes];
      uint8_t retained_auth_record[PrepareAuthorizationCodec::kRecordBytes];
      AuthorityCodec::serializeRecord(preparedTxn_, retained_txn_record, sizeof(retained_txn_record));
      PrepareAuthorizationCodec::serializeRecord(preparedAuth_, retained_auth_record, sizeof(retained_auth_record));
      if (std::memcmp(current_txn_record, retained_txn_record, sizeof(current_txn_record)) != 0 ||
          std::memcmp(current_auth_record, retained_auth_record, sizeof(current_auth_record)) != 0) {
        return AuthorityOutcome::BindingMismatch;
      }
    }

    if (!resuming) {
      if (!exactlyThisDevice(permit.txn.binding)) return AuthorityOutcome::BindingMismatch;
      // CORRECTED per review: this guard never restricted operation type
      // -- a signed CertifyExistingBaseline transaction (a read-only
      // "Normal" certification that must NEVER stage/commit any root)
      // could otherwise reach stageRoot()/commitStaged() below unchanged.
      // Reject before any mutation.
      if (!eligibleForActivationLifecycle(permit.txn.operation)) return AuthorityOutcome::OperationMismatch;

      const AuthorityOutcome issuer_outcome = verifyIssuer(permit.txn);
      if (issuer_outcome != AuthorityOutcome::Ok) return issuer_outcome;

      DeviceAuthorityState current;
      const DeviceAuthorityReadStatus read_status = store_->readCurrent(current);
      if (read_status == DeviceAuthorityReadStatus::Error) return AuthorityOutcome::Denied;
      if (read_status == DeviceAuthorityReadStatus::Pending) return AuthorityOutcome::Pending;
      const bool has_current = read_status == DeviceAuthorityReadStatus::Present;
      if (has_current && current.activated) {
        // H1 fix: the SAME transactionId already being activated is NOT a
        // "different lineage supersedes it" case -- falling through here
        // used to re-run stageRoot()/commitStaged() against an already-
        // activated device, potentially clearing/downgrading its own
        // activation state via a replayed, otherwise-still-validly-signed
        // Prepare permit. Refuse ALL Prepare once this exact transaction
        // is activated; only a genuinely DIFFERENT chaining transaction
        // (Repair/Rekey below) may ever proceed past this point.
        if (std::memcmp(current.transactionId, permit.txn.transactionId, kTransactionIdBytes) == 0) {
          return AuthorityOutcome::WrongState;
        }
        // Something else is already genuinely commissioned. Only a
        // Repair/Rekey that explicitly chains from what is currently
        // activated may supersede it -- a bare re-Commission over an
        // active root is exactly the "relabel pretending to be first
        // use" case rule 4/8 forbid.
        if (permit.txn.operation == AuthorityOperation::Commission) return AuthorityOutcome::BindingMismatch;
        if (std::memcmp(permit.txn.predecessorTransactionId, current.transactionId, kTransactionIdBytes) != 0) {
          return AuthorityOutcome::StaleRevision;
        }
      }

      // Astra Sol fix (root cause): verifyAndPrepare used to accept any
      // caller-echoed `hostChallenge` -- it never actually consumed a
      // device-minted challenge nor verified a real PrepareAuthorizationV1
      // at all. Independently verify the SEPARATE, purpose-bound,
      // issuer-signed PrepareAuthorizationV1 under its own domain-
      // separated message; a captured grant/activation-purpose signature
      // cannot satisfy this (different domain string, different field
      // set), closing the "no fresh device challenge ever verified" gap
      // for real.
      uint8_t issuer_public_key[kPublicKeyBytes];
      if (!issuerTrust_->lookupIssuerPublicKey(permit.txn.issuerKeyId, issuer_public_key)) return AuthorityOutcome::Denied;
      uint8_t auth_message[PrepareAuthorizationCodec::kSignedMessageBytes];
      if (PrepareAuthorizationCodec::serializeSignedMessage(permit.auth, auth_message, sizeof(auth_message)) !=
          PrepareAuthorizationCodec::kSignedMessageBytes) {
        return AuthorityOutcome::CorruptRecord;
      }
      if (!verifier_->verify(permit.auth.issuerSignatureEd25519, kSignatureBytes, auth_message, sizeof(auth_message),
                              issuer_public_key, kPublicKeyBytes)) {
        return AuthorityOutcome::SignatureInvalid;
      }
      if (std::memcmp(permit.auth.transactionId, permit.txn.transactionId, kTransactionIdBytes) != 0) {
        return AuthorityOutcome::BindingMismatch;
      }
      uint8_t expected_grant_digest[kDigestBytes];
      if (!AuthorityCodec::computeRecordDigestSha256(permit.txn, expected_grant_digest)) return AuthorityOutcome::CorruptRecord;
      if (std::memcmp(permit.auth.grantDigestSha256, expected_grant_digest, kDigestBytes) != 0) {
        return AuthorityOutcome::BindingMismatch;
      }
      if (permit.auth.authorizedRevision != permit.txn.revision) return AuthorityOutcome::BindingMismatch;
      if (!bindingsExactlyEqual(permit.auth.expectedBinding, permit.txn.binding)) return AuthorityOutcome::BindingMismatch;
      // The real fix: consume THIS guard's own tracked outstanding
      // challenge (minted earlier via beginChallenge/
      // requestDeviceChallenge) -- never a bare field the host could
      // have echoed back to itself. Single-use: a replay of the exact
      // same auth a second time finds no outstanding challenge left and
      // is denied.
      if (!consumeChallenge(AuthorityChallengePurpose::Prepare, permit.txn.transactionId, permit.auth.deviceFreshChallenge)) {
        return AuthorityOutcome::ChallengeMismatch;
      }

      uint8_t device_nonce[kChallengeBytes];
      if (!entropy_->freshNonce(device_nonce)) return AuthorityOutcome::Denied;

      // Retain the EXACT authenticated txn/auth values now, before
      // entering the resumable continuation -- every I/O boundary call
      // below (and any later Pending resume) consumes ONLY these
      // retained copies, never `permit.txn`/`permit.auth` directly, so a
      // changed field on a later resuming call can never reach
      // stageRoot()/commitStaged() even if the match check above were
      // ever bypassed.
      preparedTxn_ = permit.txn;
      preparedAuth_ = permit.auth;
      preparePhase_ = PrepareContinuationPhase::Staging;
      std::memcpy(preparedTxnId_, permit.txn.transactionId, kTransactionIdBytes);
      std::memcpy(preparedDeviceNonce_, device_nonce, kChallengeBytes);
    }

    // Astra29: R is no longer an issuer-precommitted value echoed back --
    // it comes ONLY from a real stageRoot() call that actually applies
    // the manifest to per-device storage and reports what it genuinely
    // persisted. A maintenance seam that is missing/unwired (or that
    // itself fails) denies outright; there is no success-shaped fallback
    // that invents a digest here. `Pending` resumes this SAME in-flight
    // operation on a later call without re-verifying the signature or
    // re-consuming the already-spent challenge above.
    if (preparePhase_ == PrepareContinuationPhase::Staging) {
      uint8_t staged_root[kDigestBytes];
      const DeviceAuthorityIoStatus stage_status = maintenance_->stageRoot(preparedTxn_, staged_root);
      if (stage_status == DeviceAuthorityIoStatus::Pending) return AuthorityOutcome::Pending;
      if (stage_status == DeviceAuthorityIoStatus::Denied) {
        preparePhase_ = PrepareContinuationPhase::None;
        return AuthorityOutcome::Denied;
      }
      std::memcpy(preparedRoot_, staged_root, kDigestBytes);
      preparePhase_ = PrepareContinuationPhase::Committing;
    }

    if (preparePhase_ == PrepareContinuationPhase::Committing) {
      const DeviceAuthorityIoStatus commit_status = store_->commitStaged(
          preparedTxn_.transactionId, preparedRoot_, preparedTxn_.initialTxSequenceFloor, preparedTxn_.initialRxReplayFloor);
      if (commit_status == DeviceAuthorityIoStatus::Pending) return AuthorityOutcome::Pending;
      if (commit_status == DeviceAuthorityIoStatus::Denied) {
        preparePhase_ = PrepareContinuationPhase::None;
        return AuthorityOutcome::Denied;
      }
    }

    uint8_t message[AuthorityAckCodec::kMessageBytes];
    AuthorityAckCodec::serializePrepareAck(preparedAuth_.deviceFreshChallenge, preparedDeviceNonce_, preparedTxn_.transactionId,
                                            preparedRoot_, message, sizeof(message));
    uint8_t signature[kSignatureBytes];
    if (!signer_->signWithDeviceIdentity(message, sizeof(message), signature)) return AuthorityOutcome::Denied;

    std::memcpy(out_response.deviceNonce, preparedDeviceNonce_, kChallengeBytes);
    std::memcpy(out_response.rootDigestSha256, preparedRoot_, kDigestBytes);
    std::memcpy(out_response.deviceSignatureEd25519, signature, kSignatureBytes);
    preparePhase_ = PrepareContinuationPhase::None;
    return AuthorityOutcome::Ok;
  }

  AuthorityOutcome verifyAndActivate(const ActivationPermit& permit, ActivationResponse& out_response,
                                      TxRxActivationGrant& out_grant) {
    if (!dependenciesWired()) return AuthorityOutcome::Denied;
    const bool resuming = activatePhase_ != ActivateContinuationPhase::None &&
                           std::memcmp(activatedTxnId_, permit.txn.transactionId, kTransactionIdBytes) == 0;

    if (resuming) {
      // Sol review HIGH fix: same rationale as verifyAndPrepare above --
      // a resuming call (ReadingCurrent/Activating/Committing) must use
      // ONLY the exact authenticated txn/activationAuth/
      // preparedRootDigest retained from the ORIGINAL verified call,
      // never this call's (potentially changed/foreign) fields. Reject
      // any divergence with NO mutation, leaving the in-flight
      // continuation intact for a genuine exact retry.
      uint8_t current_txn_record[AuthorityCodec::kRecordBytes];
      uint8_t current_auth_record[ActivationAuthorizationCodec::kRecordBytes];
      if (AuthorityCodec::serializeRecord(permit.txn, current_txn_record, sizeof(current_txn_record)) !=
              AuthorityCodec::kRecordBytes ||
          ActivationAuthorizationCodec::serializeRecord(permit.activationAuth, current_auth_record,
                                                         sizeof(current_auth_record)) !=
              ActivationAuthorizationCodec::kRecordBytes) {
        return AuthorityOutcome::CorruptRecord;
      }
      uint8_t retained_txn_record[AuthorityCodec::kRecordBytes];
      uint8_t retained_auth_record[ActivationAuthorizationCodec::kRecordBytes];
      AuthorityCodec::serializeRecord(activatedTxn_, retained_txn_record, sizeof(retained_txn_record));
      ActivationAuthorizationCodec::serializeRecord(activatedAuth_, retained_auth_record, sizeof(retained_auth_record));
      if (std::memcmp(current_txn_record, retained_txn_record, sizeof(current_txn_record)) != 0 ||
          std::memcmp(current_auth_record, retained_auth_record, sizeof(current_auth_record)) != 0 ||
          std::memcmp(permit.preparedRootDigestSha256, activatedPreparedRootDigest_, kDigestBytes) != 0) {
        return AuthorityOutcome::BindingMismatch;
      }
    }

    if (!resuming) {
      if (!exactlyThisDevice(permit.txn.binding)) return AuthorityOutcome::BindingMismatch;
      // Same restriction as verifyAndPrepare -- checked before any of the
      // signature/binding verification below reaches activateStagedRoot().
      if (!eligibleForActivationLifecycle(permit.txn.operation)) return AuthorityOutcome::OperationMismatch;

      // Independently re-verify the issuer signature on the FULL grant
      // transaction carried by this permit. IMPORTANT, CORRECTED STATUS:
      // this alone only proves a genuine issuer produced the ORIGINAL
      // GRANT -- that signature covers only the 174-byte AuthorityCodec
      // message and says nothing about activation purpose, freshness, or
      // whether the host's own two-copy ActivationSpent gate was ever
      // reached; its bytes are already visible in cleartext from the
      // earlier prepare() exchange. The REAL closure of that gap is the
      // separate `permit.activationAuth` check below, under its own
      // domain-separated signature (see ActivationAuthorizationCodec.h).
      const AuthorityOutcome issuer_outcome = verifyIssuer(permit.txn);
      if (issuer_outcome != AuthorityOutcome::Ok) return issuer_outcome;
      // Astra29: there is no more issuer-precommitted expectedRootDigestSha256
      // to compare against here -- the ONLY roots that matter are (a) what
      // the device itself durably staged (current.stagedRootDigestSha256,
      // checked below) and (b) what the host's ActivationAuthorizationV1
      // independently attests as preparedRootDigestSha256 (checked next).

      // Independently verify the SEPARATE, purpose-bound
      // ActivationAuthorizationV1 under its own domain-separated message.
      // A captured, genuinely valid GRANT signature (or a Prepare-purpose
      // ack signature) cannot satisfy this check: the signed bytes differ
      // (different domain string, different field set) so no cross-
      // purpose signature reuse is cryptographically possible here, closing
      // the "replay before both-copy Spent" gap for real.
      uint8_t issuer_public_key[kPublicKeyBytes];
      if (!issuerTrust_->lookupIssuerPublicKey(permit.txn.issuerKeyId, issuer_public_key)) return AuthorityOutcome::Denied;
      uint8_t auth_message[ActivationAuthorizationCodec::kSignedMessageBytes];
      if (ActivationAuthorizationCodec::serializeSignedMessage(permit.activationAuth, auth_message, sizeof(auth_message)) !=
          ActivationAuthorizationCodec::kSignedMessageBytes) {
        return AuthorityOutcome::CorruptRecord;
      }
      if (!verifier_->verify(permit.activationAuth.issuerSignatureEd25519, kSignatureBytes, auth_message, sizeof(auth_message),
                              issuer_public_key, kPublicKeyBytes)) {
        return AuthorityOutcome::SignatureInvalid;
      }
      // Cross-bind the authorization to THIS exact grant/session -- never
      // accept an authorization minted for a different transaction,
      // revision, binding, root, or challenge.
      if (std::memcmp(permit.activationAuth.transactionId, permit.txn.transactionId, kTransactionIdBytes) != 0) {
        return AuthorityOutcome::BindingMismatch;
      }
      // Astra29 fix: `grantDigestSha256` MUST be A = SHA256(the exact
      // kRecordBytes signed grant record, INCLUDING the issuer signature),
      // never manifestDigestSha256 (M, policy content only) -- comparing
      // against M was a confirmed bug that let ANY correctly-signed grant
      // for a different transaction satisfy this check as long as its
      // manifest happened to match. Recompute A fresh from `permit.txn`
      // (already issuer-signature-verified above) rather than trusting any
      // caller-supplied digest.
      uint8_t expected_grant_digest[kDigestBytes];
      if (!AuthorityCodec::computeRecordDigestSha256(permit.txn, expected_grant_digest)) return AuthorityOutcome::CorruptRecord;
      if (std::memcmp(permit.activationAuth.grantDigestSha256, expected_grant_digest, kDigestBytes) != 0) {
        return AuthorityOutcome::BindingMismatch;
      }
      if (std::memcmp(permit.activationAuth.preparedRootDigestSha256, permit.preparedRootDigestSha256, kDigestBytes) != 0) {
        return AuthorityOutcome::BindingMismatch;
      }
      if (permit.activationAuth.spentAuthorizedRevision != permit.txn.revision) return AuthorityOutcome::BindingMismatch;
      if (!bindingsExactlyEqual(permit.activationAuth.expectedBinding, permit.txn.binding)) return AuthorityOutcome::BindingMismatch;
      // Astra Sol fix (root cause): this used to compare
      // `activationAuth.deviceFreshChallenge` against a bare
      // caller-echoed `permit.hostChallenge` field -- a host could set
      // both to the SAME value it invented itself, so this never proved
      // a real device-minted challenge was involved. Consume THIS
      // guard's own tracked outstanding challenge instead (minted via
      // beginChallenge/requestDeviceChallenge) -- single-use, and a
      // mismatched presentation never invalidates a still-outstanding
      // genuine one.
      if (!consumeChallenge(AuthorityChallengePurpose::Activate, permit.txn.transactionId,
                             permit.activationAuth.deviceFreshChallenge)) {
        return AuthorityOutcome::ChallengeMismatch;
      }

      // Sol review MEDIUM fix: the challenge above is single-use and is
      // now ALREADY consumed -- a retry can never present it again. The
      // OLD code called store_->readCurrent() here still inside the
      // `!resuming` block, and on `Pending` returned immediately WITHOUT
      // ever setting `activatePhase_` away from `None`. That left
      // `resuming` false on the caller's retry, so the retry fell back
      // into this exact `!resuming` branch a second time, hit
      // `consumeChallenge()` again, and was wrongly denied
      // ChallengeMismatch (the one-use challenge was already gone) --
      // an exact, legitimate retry could never complete. Fix: retain the
      // exact authenticated values and establish the continuation
      // (`ReadingCurrent`) BEFORE calling readCurrent(), so a `Pending`
      // result resumes via `resuming` above without re-verifying the
      // signature or attempting to re-consume the challenge again.
      activatedTxn_ = permit.txn;
      activatedAuth_ = permit.activationAuth;
      std::memcpy(activatedPreparedRootDigest_, permit.preparedRootDigestSha256, kDigestBytes);
      activatePhase_ = ActivateContinuationPhase::ReadingCurrent;
      std::memcpy(activatedTxnId_, permit.txn.transactionId, kTransactionIdBytes);
    }

    if (activatePhase_ == ActivateContinuationPhase::ReadingCurrent) {
      // H2 fix: `Error` (read/IO failure) must deny immediately, exactly
      // like a missing staged root -- never fall through treating it the
      // same as a confirmed-empty store that merely lacks `staged`.
      DeviceAuthorityState current;
      const DeviceAuthorityReadStatus read_status = store_->readCurrent(current);
      if (read_status == DeviceAuthorityReadStatus::Pending) return AuthorityOutcome::Pending;
      if (read_status != DeviceAuthorityReadStatus::Present || !current.staged) {
        // No existing local staged root (or the read itself failed):
        // never reseed/fabricate one here.
        activatePhase_ = ActivateContinuationPhase::None;
        return AuthorityOutcome::Denied;
      }
      if (std::memcmp(current.transactionId, activatedTxn_.transactionId, kTransactionIdBytes) != 0) {
        activatePhase_ = ActivateContinuationPhase::None;
        return AuthorityOutcome::TransactionNotFound;
      }
      if (std::memcmp(current.stagedRootDigestSha256, activatedPreparedRootDigest_, kDigestBytes) != 0) {
        activatePhase_ = ActivateContinuationPhase::None;
        return AuthorityOutcome::DeviceResponseMismatch;
      }

      uint8_t device_nonce[kChallengeBytes];
      if (!entropy_->freshNonce(device_nonce)) return AuthorityOutcome::Denied;

      activatePhase_ = ActivateContinuationPhase::Activating;
      std::memcpy(activatedDeviceNonce_, device_nonce, kChallengeBytes);
      activatedTxSequenceFloor_ = current.txSequenceFloor;
      activatedRxReplayFloor_ = current.rxReplayFloor;
    }

    // `Pending` resumes this SAME in-flight activation on a later call
    // without re-verifying the signature or re-consuming the
    // already-spent challenge above.
    if (activatePhase_ == ActivateContinuationPhase::Activating) {
      const DeviceAuthorityIoStatus activate_status =
          maintenance_->activateStagedRoot(activatedTxn_.transactionId, activatedPreparedRootDigest_);
      if (activate_status == DeviceAuthorityIoStatus::Pending) return AuthorityOutcome::Pending;
      if (activate_status == DeviceAuthorityIoStatus::Denied) {
        activatePhase_ = ActivateContinuationPhase::None;
        return AuthorityOutcome::Denied;
      }
      activatePhase_ = ActivateContinuationPhase::Committing;
    }

    if (activatePhase_ == ActivateContinuationPhase::Committing) {
      const DeviceAuthorityIoStatus commit_status =
          store_->commitActivated(activatedTxn_.transactionId, activatedPreparedRootDigest_);
      if (commit_status == DeviceAuthorityIoStatus::Pending) return AuthorityOutcome::Pending;
      if (commit_status == DeviceAuthorityIoStatus::Denied) {
        activatePhase_ = ActivateContinuationPhase::None;
        return AuthorityOutcome::Denied;
      }
    }

    uint8_t message[AuthorityAckCodec::kMessageBytes];
    AuthorityAckCodec::serializeActivateAck(activatedAuth_.deviceFreshChallenge, activatedDeviceNonce_,
                                             activatedTxn_.transactionId, activatedPreparedRootDigest_, message,
                                             sizeof(message));
    uint8_t signature[kSignatureBytes];
    if (!signer_->signWithDeviceIdentity(message, sizeof(message), signature)) return AuthorityOutcome::Denied;

    std::memcpy(out_response.deviceNonce, activatedDeviceNonce_, kChallengeBytes);
    std::memcpy(out_response.deviceSignatureEd25519, signature, kSignatureBytes);

    std::memcpy(out_grant.transactionId, activatedTxn_.transactionId, kTransactionIdBytes);
    out_grant.txSequenceFloor = activatedTxSequenceFloor_;
    out_grant.rxReplayFloor = activatedRxReplayFloor_;
    activatePhase_ = ActivateContinuationPhase::None;
    return AuthorityOutcome::Ok;
  }

  // Narrow query for "what am I currently authorized to run counters
  // against", usable independently of a live handshake (e.g. at boot).
  AuthorityOutcome currentActivationGrant(TxRxActivationGrant& out_grant) const {
    if (store_ == nullptr) return AuthorityOutcome::Denied;
    DeviceAuthorityState current;
    // H2 fix: `Error` must deny distinctly from "no activation exists
    // yet" -- both currently return early, but never by silently
    // equating a read failure with a clean absence.
    const DeviceAuthorityReadStatus read_status = store_->readCurrent(current);
    if (read_status == DeviceAuthorityReadStatus::Error) return AuthorityOutcome::Denied;
    if (read_status == DeviceAuthorityReadStatus::Pending) return AuthorityOutcome::Pending;
    if (read_status != DeviceAuthorityReadStatus::Present || !current.activated) return AuthorityOutcome::TransactionNotFound;
    std::memcpy(out_grant.transactionId, current.transactionId, kTransactionIdBytes);
    out_grant.txSequenceFloor = current.txSequenceFloor;
    out_grant.rxReplayFloor = current.rxReplayFloor;
    return AuthorityOutcome::Ok;
  }

private:
  bool exactlyThisDevice(const AuthorityBinding& claimed) const {
    return std::memcmp(claimed.hardwareUid, ownIdentity_.hardwareUid, kHardwareUidBytes) == 0 &&
           std::memcmp(claimed.meshFullPublicKey, ownIdentity_.meshFullPublicKey, kPublicKeyBytes) == 0 &&
           claimed.cryptoDomain == ownIdentity_.cryptoDomain && claimed.profileId == ownIdentity_.profileId &&
           claimed.layoutId == ownIdentity_.layoutId &&
           std::memcmp(claimed.consentOwnerPublicKey, ownIdentity_.consentOwnerPublicKey, kPublicKeyBytes) == 0;
  }

  // Full field-for-field binding equality (including role and
  // consentOwnerPublicKey, unlike exactlyThisDevice above which only
  // checks what identifies THIS device) -- used to verify an
  // ActivationAuthorizationV1::expectedBinding was minted for the EXACT
  // same binding the grant itself was signed for, substituting nothing.
  static bool bindingsExactlyEqual(const AuthorityBinding& a, const AuthorityBinding& b) {
    return std::memcmp(a.hardwareUid, b.hardwareUid, kHardwareUidBytes) == 0 &&
           std::memcmp(a.meshFullPublicKey, b.meshFullPublicKey, kPublicKeyBytes) == 0 &&
           a.cryptoDomain == b.cryptoDomain && a.profileId == b.profileId && a.layoutId == b.layoutId &&
           a.historicalInitialRoleId == b.historicalInitialRoleId &&
           std::memcmp(a.consentOwnerPublicKey, b.consentOwnerPublicKey, kPublicKeyBytes) == 0;
  }

  // Mirrors AuthorityCoordinator::eligibleForActivationLifecycle exactly
  // -- CertifyExistingBaseline (and any other non-lifecycle operation)
  // must NEVER reach the Commission/Repair/Rekey Prepare/Activate
  // mutation path, even if it somehow carries a genuinely valid issuer
  // signature. Checked first, before ANY device-side mutation (stageRoot/
  // commitStaged/activateStagedRoot/commitActivated), per review.
  static bool eligibleForActivationLifecycle(AuthorityOperation operation) {
    return operation == AuthorityOperation::Commission || operation == AuthorityOperation::Repair ||
           operation == AuthorityOperation::Rekey;
  }

  AuthorityOutcome verifyIssuer(const AuthorityTransaction& txn) const {
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

  // Single-use: consumes the outstanding challenge ONLY on an exact
  // (purpose, transactionId, bytes) match, clearing it so a replay of
  // the same authorization a second time finds nothing outstanding. A
  // mismatched/foreign presentation leaves a still-valid outstanding
  // challenge untouched -- the genuine owner can still retry.
  bool consumeChallenge(AuthorityChallengePurpose purpose, const uint8_t transactionId[kTransactionIdBytes],
                         const uint8_t presented[kChallengeBytes]) {
    if (!outstandingChallenge_.active) return false;
    if (outstandingChallenge_.purpose != purpose) return false;
    if (std::memcmp(outstandingChallenge_.transactionId, transactionId, kTransactionIdBytes) != 0) return false;
    if (std::memcmp(outstandingChallenge_.challenge, presented, kChallengeBytes) != 0) return false;
    outstandingChallenge_.active = false;
    return true;
  }

  AuthorityBinding ownIdentity_;
  ota::trust::SignatureVerifier* verifier_;
  AuthorityIssuerTrust* issuerTrust_;
  DeviceAuthorityEntropy* entropy_;
  DeviceAuthorityStore* store_;
  DeviceAuthorityMaintenance* maintenance_;
  DeviceIdentitySigner* signer_;

  struct OutstandingChallenge {
    bool active = false;
    AuthorityChallengePurpose purpose = AuthorityChallengePurpose::Prepare;
    uint8_t transactionId[kTransactionIdBytes] = {0};
    uint8_t challenge[kChallengeBytes] = {0};
  };
  OutstandingChallenge outstandingChallenge_;

  // Resumable Prepare continuation: a Pending stageRoot()/commitStaged()
  // resumes via the SAME transactionId without re-verifying the
  // PrepareAuthorizationV1 signature or re-consuming the already-spent
  // challenge above. `preparedTxn_`/`preparedAuth_` are the EXACT
  // authenticated values from the original verified call -- every
  // resuming call is checked against these (see the match-check at the
  // top of verifyAndPrepare) and every I/O boundary call below consumes
  // ONLY these retained copies, never a later call's possibly-changed
  // `permit.txn`/`permit.auth` fields directly (Sol review HIGH fix).
  enum class PrepareContinuationPhase : uint8_t { None, Staging, Committing };
  PrepareContinuationPhase preparePhase_ = PrepareContinuationPhase::None;
  uint8_t preparedTxnId_[kTransactionIdBytes] = {0};
  AuthorityTransaction preparedTxn_;
  PrepareAuthorizationV1 preparedAuth_;
  uint8_t preparedRoot_[kDigestBytes] = {0};
  uint8_t preparedDeviceNonce_[kChallengeBytes] = {0};

  // Resumable Activate continuation: same rationale as Prepare above,
  // plus an extra `ReadingCurrent` phase (Sol review MEDIUM fix) so a
  // Pending result from store_->readCurrent() -- which happens AFTER the
  // single-use challenge has already been consumed -- can resume without
  // ever needing to re-consume that challenge a second time.
  // `activatedTxn_`/`activatedAuth_`/`activatedPreparedRootDigest_` are
  // the EXACT authenticated values retained from the original verified
  // call; every resuming call (in ANY of ReadingCurrent/Activating/
  // Committing) is checked against these, and every I/O boundary call
  // below consumes ONLY these retained copies, never a later call's
  // possibly-changed `permit` fields directly.
  enum class ActivateContinuationPhase : uint8_t { None, ReadingCurrent, Activating, Committing };
  ActivateContinuationPhase activatePhase_ = ActivateContinuationPhase::None;
  uint8_t activatedTxnId_[kTransactionIdBytes] = {0};
  AuthorityTransaction activatedTxn_;
  ActivationAuthorizationV1 activatedAuth_;
  uint8_t activatedPreparedRootDigest_[kDigestBytes] = {0};
  uint8_t activatedDeviceNonce_[kChallengeBytes] = {0};
  uint32_t activatedTxSequenceFloor_ = 0;
  uint32_t activatedRxReplayFloor_ = 0;
};

}  // namespace authority
}  // namespace ota
