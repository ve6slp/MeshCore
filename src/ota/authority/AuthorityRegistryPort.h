#pragma once

// Two-copy durable registry abstraction for OTA commissioning authority
// transactions, and the cold-reconciliation rules the approved contract
// requires: a valid later (more-advanced) state for the exact same bound
// transaction dominates a stale earlier one; a single missing/corrupt copy
// never manufactures unused permission out of thin air; disagreement that
// is not a clean "one copy is simply lagging" case is always Uncertain,
// never silently resolved toward permission.
//
// `AuthorityRegistryCopy` is a single persisted copy. Concrete backends
// (see FileAuthorityRegistryCopy.h for the real file-backed one used by
// both the native tests and the host CLI's embedded record format) commit
// every write with a full readback verification before reporting success.
// `AuthorityRegistryPair` never releases an outcome without having
// independently read back BOTH copies.

#include <stdint.h>
#include <cstring>
#include "ota/authority/AuthorityTypes.h"
#include "ota/authority/AuthorityCodec.h"

namespace ota {
namespace authority {

// One durably-persisted snapshot of a transaction's lifecycle. `state`
// starts at Issued and only ever advances; `preparedRootDigestSha256` and
// `challenge` are populated once state reaches ConsumedPrepared and never
// change afterward (ActivationSpent must reference the SAME prepared
// root, never a different one).
struct StoredTransactionRecord {
  AuthorityTransaction txn;
  TransactionState state = TransactionState::Issued;
  uint8_t preparedRootDigestSha256[kDigestBytes] = {0};
  // Astra29: ConsumedPrepared is explicitly "root UNBOUND" until the
  // device has actually staged/ACKed a real root -- `rootBound` is the
  // durable flag distinguishing that from a genuinely-known (possibly
  // legitimately zero-valued, though that can never actually occur with
  // a real SHA-256) digest. ActivationSpent MUST always have
  // rootBound == true (enforced by appendStateTransition); a stored
  // ActivationSpent with rootBound == false is a contradiction and is
  // always treated as corrupt/Uncertain by reconcileCopies, never as
  // usable permission.
  bool rootBound = false;
  uint8_t challenge[kChallengeBytes] = {0};

  bool sameTransactionIdentity(const StoredTransactionRecord& other) const {
    return std::memcmp(txn.transactionId, other.txn.transactionId, kTransactionIdBytes) == 0;
  }

  // Byte-identical signed content (catches a copy whose transaction
  // record was tampered with even though its transactionId matches).
  bool sameSignedContent(const StoredTransactionRecord& other) const {
    uint8_t a[AuthorityCodec::kSignedMessageBytes];
    uint8_t b[AuthorityCodec::kSignedMessageBytes];
    if (AuthorityCodec::serializeSignedMessage(txn, a, sizeof(a)) != AuthorityCodec::kSignedMessageBytes) return false;
    if (AuthorityCodec::serializeSignedMessage(other.txn, b, sizeof(b)) != AuthorityCodec::kSignedMessageBytes) return false;
    return std::memcmp(a, b, sizeof(a)) == 0;
  }
};

inline uint8_t stateRank(TransactionState s) { return static_cast<uint8_t>(s); }

class AuthorityRegistryCopy {
public:
  virtual ~AuthorityRegistryCopy() = default;

  // Durably appends a brand-new Issued transaction. Must fail (return
  // false) if `transactionId` already exists in this copy -- transactions
  // are never overwritten in place, only advanced via appendStateTransition.
  virtual bool appendIssued(const AuthorityTransaction& txn) = 0;

  // Durably appends a state advance for an existing transaction. Callers
  // (AuthorityRegistryPair / AuthorityCoordinator) are responsible for
  // only ever calling this with a strictly-advancing `newState`; backends
  // MUST still reject (return false) any non-advancing state as defense
  // in depth.
  virtual bool appendStateTransition(const uint8_t transactionId[kTransactionIdBytes], TransactionState newState,
                                      const uint8_t preparedRootDigestSha256[kDigestBytes], bool rootBound,
                                      const uint8_t challenge[kChallengeBytes]) = 0;

  // Scans all durable records and returns the latest valid (CRC/commit-
  // marker verified) state for `transactionId`. Returns false if nothing
  // valid is found (distinct from `out.corruptButPresent`, which a caller
  // can use to distinguish "never existed" from "existed but unreadable").
  virtual bool readLatest(const uint8_t transactionId[kTransactionIdBytes], StoredTransactionRecord& out,
                           bool& out_corrupt_but_present) const = 0;

  // Scans for the latest ActivationSpent transaction whose binding has the
  // same ownership identity (UID + fullPK + cryptoDomain + layout) as
  // `owner`, regardless of transactionId -- used by repairExisting /
  // rekeyExplicitly to find surviving history. Returns false if none.
  // `out_corrupt_but_present` mirrors readLatest's meaning: true if ANY
  // unreadable/unexplained slot was seen anywhere in the backing store
  // while scanning, so a caller never mistakes "some history was
  // unreadable" for "no further history exists" (a later, higher-revision
  // ActivationSpent record hidden behind corruption must never be
  // silently skipped -- see FileAuthorityRegistryCopy's "owner Scanner"
  // fix).
  virtual bool readLatestActivationForOwner(const AuthorityBinding& owner, StoredTransactionRecord& out,
                                             bool& out_corrupt_but_present) const = 0;

  // Scans for the latest-revision record for this PHYSICAL device
  // (hardwareUid ONLY -- deliberately WITHOUT comparing fullPK,
  // profileId, layoutId, OR cryptoDomain -- see
  // AuthorityBinding::samePhysicalLifetime; Sol43 HIGH fix: cryptoDomain
  // was previously (wrongly) kept in this key, which let a second signed
  // Commission for the SAME hardwareUid but a different crypto-form/
  // group-selector escape this fence entirely as a "different device").
  // MAIN's binding clarification requires this fence be independent of
  // changing PK/role/profile/layout/crypto-domain labels, never just the
  // broader sameDeviceIdentity scope, in ANY state
  // (Issued/ConsumedPrepared/ActivationSpent), not just ActivationSpent.
  // This is the fence a genuine rekey must check in
  // addition to readLatestActivationForOwner: a pending-but-not-yet-
  // activated successor (a different fullPK already Issued/prepared
  // against the SAME predecessor) still dominates the old key for
  // fork-prevention purposes -- two different fullPKs must never both
  // be accepted as "the" successor of the same predecessor. If more
  // than one DISTINCT transactionId is found at the same highest
  // revision for this physical device, that is an unresolved fork at
  // this copy and must be surfaced as `out_corrupt_but_present`, never
  // silently resolved by picking one.
  virtual bool readLatestPhysicalLineage(const AuthorityBinding& physicalDevice, StoredTransactionRecord& out,
                                          bool& out_corrupt_but_present) const = 0;

  // H3 fix: scans for the latest-revision record for this EXACT ownership
  // identity (AuthorityBinding::sameOwnership -- UID + fullPK +
  // cryptoDomain + layout) in ANY state (Issued/ConsumedPrepared/
  // ActivationSpent), not just ActivationSpent. This closes the gap
  // readLatestActivationForOwner leaves open: two distinct revision-0
  // Commission transactions for the SAME owner can both reach Issued (or
  // even ConsumedPrepared) before either is ever ActivationSpent, since
  // readLatestActivationForOwner is structurally blind to anything that
  // has not yet been spent. Same fork-surfacing contract as
  // readLatestPhysicalLineage: two DISTINCT transactionIds at the same
  // highest revision for this owner must be surfaced as
  // `out_corrupt_but_present`, never silently resolved by picking one.
  virtual bool readLatestOwnershipLineage(const AuthorityBinding& owner, StoredTransactionRecord& out,
                                           bool& out_corrupt_but_present) const = 0;

  // Sol fe862c8 residual (H5): a prior write's own fsync() call failing
  // is NOT provably undone by this class's best-effort "poison the
  // marker" correction -- that corrective write/fsync can itself fail,
  // or the process can die between the original failure and the
  // correction, leaving byte-perfect-but-never-durably-confirmed bytes
  // readable by a later, entirely separate caller. The only invariant
  // that actually closes this gap is a POSITIVE storage barrier
  // performed IMMEDIATELY BEFORE any authority-permission release
  // (never only at write time): re-open this copy's backing file fresh
  // (no cached fd/state) and actually call fsync() on it again right
  // now, plus fsync the parent directory again -- a LATER fsync success
  // genuinely confirms whatever is currently in the page cache for this
  // file reaches stable storage, even if an EARLIER fsync attempt during
  // the original write failed. If this fresh confirmation fails, the
  // caller MUST deny the permission release outright, regardless of what
  // a plain readLatest()/reconcile() reported. Returns false if the
  // backing file does not exist (nothing to confirm) OR either fsync
  // fails.
  virtual bool confirmDurable() const = 0;
};

enum class ReconciliationOutcome : uint8_t {
  Agreed = 0,              // Both copies independently confirm the same state.
  RecoveredFromSingleCopy = 1,  // Exactly one copy had a valid record; replica repair is owed, not permission.
  Uncertain = 2,            // Disagreement that is not a clean "one copy is lagging" case.
  NotFound = 3,
};

struct ReconciliationResult {
  ReconciliationOutcome outcome = ReconciliationOutcome::NotFound;
  StoredTransactionRecord resolved;
  bool needsReplicaRepair = false;  // A lagging or missing copy should be brought up to `resolved`.
};

// Pure reconciliation logic, independent of storage backend, so it can be
// exercised directly against hand-built StoredTransactionRecord fixtures
// (deletion/corruption/rollback/conflict) without needing real files for
// every case.
inline ReconciliationResult reconcileCopies(bool a_present, bool a_corrupt, const StoredTransactionRecord& a,
                                             bool b_present, bool b_corrupt, const StoredTransactionRecord& b) {
  ReconciliationResult result;

  const bool a_valid = a_present && !a_corrupt;
  const bool b_valid = b_present && !b_corrupt;

  if (!a_valid && !b_valid) {
    // Neither copy has anything trustworthy. A corrupt-but-present record
    // is a documented boundary (rule 8), never silently treated as absent
    // permission -- surface Uncertain rather than NotFound if either side
    // had SOMETHING, so callers know this is not simply "never issued".
    result.outcome = (a_corrupt || b_corrupt) ? ReconciliationOutcome::Uncertain : ReconciliationOutcome::NotFound;
    return result;
  }

  if (a_valid && !b_valid) {
    result.outcome = ReconciliationOutcome::RecoveredFromSingleCopy;
    result.resolved = a;
    result.needsReplicaRepair = true;
    return result;
  }
  if (b_valid && !a_valid) {
    result.outcome = ReconciliationOutcome::RecoveredFromSingleCopy;
    result.resolved = b;
    result.needsReplicaRepair = true;
    return result;
  }

  // Both valid. Must be the exact same bound transaction to compare at all.
  if (!a.sameTransactionIdentity(b) || !a.sameSignedContent(b)) {
    result.outcome = ReconciliationOutcome::Uncertain;
    return result;
  }

  // ActivationSpent MUST always be rootBound by construction (see
  // appendStateTransition). A stored ActivationSpent claiming
  // rootBound == false is a contradiction -- never trusted as permission.
  if ((a.state == TransactionState::ActivationSpent && !a.rootBound) ||
      (b.state == TransactionState::ActivationSpent && !b.rootBound)) {
    result.outcome = ReconciliationOutcome::Uncertain;
    return result;
  }

  if (a.state == b.state) {
    // Equal-revision (equal-state) agreement -- but if a ConsumedPrepared
    // pair disagrees on WHETHER a root is bound, or on WHICH root was
    // prepared when both claim one is bound, that is exactly the
    // "equal-revision conflict" the contract calls out. If NEITHER side
    // has bound a root yet (the normal fresh-ConsumedPrepared case),
    // there is nothing to compare and no conflict is possible.
    if (a.state != TransactionState::Issued) {
      if (a.rootBound != b.rootBound) {
        result.outcome = ReconciliationOutcome::Uncertain;
        return result;
      }
      if (a.rootBound && std::memcmp(a.preparedRootDigestSha256, b.preparedRootDigestSha256, kDigestBytes) != 0) {
        result.outcome = ReconciliationOutcome::Uncertain;
        return result;
      }
    }
    result.outcome = ReconciliationOutcome::Agreed;
    result.resolved = a;
    return result;
  }

  // Different states for the identical transaction: the more-advanced one
  // dominates (never regress), but only because it is a strict, lawful
  // advance -- if the LOWER (lagging) copy has already bound a root, it
  // must agree with the higher copy's root. A lower copy that has NOT
  // yet bound a root (e.g. it is still a fresh, not-yet-handshaken
  // ConsumedPrepared while the other copy already reached
  // ActivationSpent) has nothing to conflict about -- the higher copy
  // genuinely moved further ahead and the lower copy simply needs
  // replica repair, never Uncertain.
  const StoredTransactionRecord& higher = stateRank(a.state) > stateRank(b.state) ? a : b;
  const StoredTransactionRecord& lower = stateRank(a.state) > stateRank(b.state) ? b : a;
  if (lower.state != TransactionState::Issued && lower.rootBound &&
      std::memcmp(lower.preparedRootDigestSha256, higher.preparedRootDigestSha256, kDigestBytes) != 0) {
    result.outcome = ReconciliationOutcome::Uncertain;
    return result;
  }

  result.outcome = ReconciliationOutcome::RecoveredFromSingleCopy;  // Lagging copy, same treatment: repair, don't regress.
  result.resolved = higher;
  result.needsReplicaRepair = true;
  return result;
}

// Orchestrates two real AuthorityRegistryCopy backends: every write goes
// to both, each with its own readback, and reconciliation always runs
// through `reconcileCopies` above -- there is no code path that returns an
// outcome derived from only one copy's write succeeding.
class AuthorityRegistryPair {
public:
  AuthorityRegistryPair(AuthorityRegistryCopy& copyA, AuthorityRegistryCopy& copyB)
      : copyA_(copyA), copyB_(copyB) {}

  // Commits a brand-new Issued transaction to BOTH copies. Returns false
  // (and leaves neither copy claiming success to the caller) if either
  // copy's durable write fails -- a caller observing `false` here must
  // not treat the transaction as issued even if one copy happened to
  // accept it; a later reconcile() will report RecoveredFromSingleCopy
  // for that copy, which is a repair case, not a fresh grant.
  bool commitIssued(const AuthorityTransaction& txn) {
    const bool a_ok = copyA_.appendIssued(txn);
    const bool b_ok = copyB_.appendIssued(txn);
    return a_ok && b_ok;
  }

  bool commitStateTransition(const uint8_t transactionId[kTransactionIdBytes], TransactionState newState,
                              const uint8_t preparedRootDigestSha256[kDigestBytes], bool rootBound,
                              const uint8_t challenge[kChallengeBytes]) {
    // Defense in depth: ActivationSpent must always be rootBound, even if
    // a caller mistakenly passes false -- refuse outright rather than
    // durably persist a self-contradictory record to either copy.
    if (newState == TransactionState::ActivationSpent && !rootBound) return false;
    const bool a_ok = copyA_.appendStateTransition(transactionId, newState, preparedRootDigestSha256, rootBound, challenge);
    const bool b_ok = copyB_.appendStateTransition(transactionId, newState, preparedRootDigestSha256, rootBound, challenge);
    return a_ok && b_ok;
  }

  // Sol fe862c8 residual (H5): the one positive storage barrier that may
  // ever justify releasing authority permission. Callers (
  // AuthorityCoordinator) must call this IMMEDIATELY before every
  // permission release (a PreparePermit, a re-sent prepared-state
  // response, or a signed ActivationAuthorization) -- never trust a plain
  // reconcile() alone, since a reconcile() read can observe bytes that
  // reached the page cache despite a PRIOR fsync failure during the
  // write that produced them. Requires BOTH copies to independently
  // reconfirm durability right now.
  bool confirmBothCopiesDurable() const { return copyA_.confirmDurable() && copyB_.confirmDurable(); }

  ReconciliationResult reconcile(const uint8_t transactionId[kTransactionIdBytes]) const {
    StoredTransactionRecord a, b;
    bool a_corrupt = false, b_corrupt = false;
    const bool a_present = copyA_.readLatest(transactionId, a, a_corrupt);
    const bool b_present = copyB_.readLatest(transactionId, b, b_corrupt);
    return reconcileCopies(a_present, a_corrupt, a, b_present, b_corrupt, b);
  }

  // Same dominance treatment as reconcile(), but for "the latest
  // ActivationSpent transaction for this owner" lookups used by
  // repairExisting / rekeyExplicitly. A found record is always
  // ActivationSpent by construction (see AuthorityRegistryCopy::
  // readLatestActivationForOwner), so state-based dominance collapses to
  // "higher revision wins, equal revision must be the identical
  // transaction".
  ReconciliationResult reconcileLatestActivationForOwner(const AuthorityBinding& owner) const {
    StoredTransactionRecord a, b;
    bool a_corrupt = false, b_corrupt = false;
    const bool a_present = copyA_.readLatestActivationForOwner(owner, a, a_corrupt);
    const bool b_present = copyB_.readLatestActivationForOwner(owner, b, b_corrupt);

    // Same treatment as reconcile(): a copy that saw ANY unreadable slot
    // is untrusted regardless of whether it also happened to find an
    // earlier, stale record -- unknown later history must never be
    // silently treated as "no further history exists".
    const bool a_valid = a_present && !a_corrupt;
    const bool b_valid = b_present && !b_corrupt;

    ReconciliationResult result;
    if (!a_valid && !b_valid) {
      result.outcome = (a_corrupt || b_corrupt) ? ReconciliationOutcome::Uncertain : ReconciliationOutcome::NotFound;
      return result;
    }
    if (a_valid && !b_valid) {
      result.outcome = ReconciliationOutcome::RecoveredFromSingleCopy;
      result.resolved = a;
      result.needsReplicaRepair = true;
      return result;
    }
    if (b_valid && !a_valid) {
      result.outcome = ReconciliationOutcome::RecoveredFromSingleCopy;
      result.resolved = b;
      result.needsReplicaRepair = true;
      return result;
    }

    if (a.txn.revision == b.txn.revision) {
      if (!a.sameTransactionIdentity(b) || !a.sameSignedContent(b)) {
        result.outcome = ReconciliationOutcome::Uncertain;
        return result;
      }
      result.outcome = ReconciliationOutcome::Agreed;
      result.resolved = a;
      return result;
    }

    result.outcome = ReconciliationOutcome::RecoveredFromSingleCopy;
    result.resolved = a.txn.revision > b.txn.revision ? a : b;
    result.needsReplicaRepair = true;
    return result;
  }

  // Fork-prevention fence for rekeyExplicitly: combines both copies'
  // readLatestPhysicalLineage scans with the SAME revision-dominance
  // treatment as reconcileLatestActivationForOwner above, but across ANY
  // state and ANY fullPK for this physical device. Equal-revision
  // disagreement (including a genuine fork -- two DIFFERENT
  // transactionIds at the same revision, whether within one copy via
  // `out_corrupt_but_present` or across the two copies here) is always
  // Uncertain, never silently resolved toward one candidate.
  ReconciliationResult reconcilePhysicalLineage(const AuthorityBinding& physicalDevice) const {
    StoredTransactionRecord a, b;
    bool a_corrupt = false, b_corrupt = false;
    const bool a_present = copyA_.readLatestPhysicalLineage(physicalDevice, a, a_corrupt);
    const bool b_present = copyB_.readLatestPhysicalLineage(physicalDevice, b, b_corrupt);

    const bool a_valid = a_present && !a_corrupt;
    const bool b_valid = b_present && !b_corrupt;

    ReconciliationResult result;
    if (!a_valid && !b_valid) {
      result.outcome = (a_corrupt || b_corrupt) ? ReconciliationOutcome::Uncertain : ReconciliationOutcome::NotFound;
      return result;
    }
    if (a_valid && !b_valid) {
      result.outcome = ReconciliationOutcome::RecoveredFromSingleCopy;
      result.resolved = a;
      result.needsReplicaRepair = true;
      return result;
    }
    if (b_valid && !a_valid) {
      result.outcome = ReconciliationOutcome::RecoveredFromSingleCopy;
      result.resolved = b;
      result.needsReplicaRepair = true;
      return result;
    }

    if (a.txn.revision == b.txn.revision) {
      if (!a.sameTransactionIdentity(b) || !a.sameSignedContent(b)) {
        result.outcome = ReconciliationOutcome::Uncertain;
        return result;
      }
      result.outcome = ReconciliationOutcome::Agreed;
      result.resolved = a;
      return result;
    }

    result.outcome = ReconciliationOutcome::RecoveredFromSingleCopy;
    result.resolved = a.txn.revision > b.txn.revision ? a : b;
    result.needsReplicaRepair = true;
    return result;
  }

  // H3 fork-prevention fence for submitCommission (and any other
  // recheck immediately before consuming Issued into ConsumedPrepared/
  // ActivationSpent): combines both copies' readLatestOwnershipLineage
  // scans with the SAME dominance treatment as reconcilePhysicalLineage
  // above, but keyed on the EXACT owner (UID+fullPK+domain+layout)
  // rather than physical device identity, and across ANY state
  // (Issued/ConsumedPrepared/ActivationSpent). This is what lets a
  // SECOND revision-0 Commission for an owner that already has an
  // Issued-but-not-yet-spent record be rejected, not just one that is
  // already ActivationSpent.
  ReconciliationResult reconcileOwnershipLineage(const AuthorityBinding& owner) const {
    StoredTransactionRecord a, b;
    bool a_corrupt = false, b_corrupt = false;
    const bool a_present = copyA_.readLatestOwnershipLineage(owner, a, a_corrupt);
    const bool b_present = copyB_.readLatestOwnershipLineage(owner, b, b_corrupt);

    const bool a_valid = a_present && !a_corrupt;
    const bool b_valid = b_present && !b_corrupt;

    ReconciliationResult result;
    if (!a_valid && !b_valid) {
      result.outcome = (a_corrupt || b_corrupt) ? ReconciliationOutcome::Uncertain : ReconciliationOutcome::NotFound;
      return result;
    }
    if (a_valid && !b_valid) {
      result.outcome = ReconciliationOutcome::RecoveredFromSingleCopy;
      result.resolved = a;
      result.needsReplicaRepair = true;
      return result;
    }
    if (b_valid && !a_valid) {
      result.outcome = ReconciliationOutcome::RecoveredFromSingleCopy;
      result.resolved = b;
      result.needsReplicaRepair = true;
      return result;
    }

    if (a.txn.revision == b.txn.revision) {
      if (!a.sameTransactionIdentity(b) || !a.sameSignedContent(b)) {
        result.outcome = ReconciliationOutcome::Uncertain;
        return result;
      }
      result.outcome = ReconciliationOutcome::Agreed;
      result.resolved = a;
      return result;
    }

    result.outcome = ReconciliationOutcome::RecoveredFromSingleCopy;
    result.resolved = a.txn.revision > b.txn.revision ? a : b;
    result.needsReplicaRepair = true;
    return result;
  }

  AuthorityRegistryCopy& copyA() { return copyA_; }
  AuthorityRegistryCopy& copyB() { return copyB_; }

private:
  AuthorityRegistryCopy& copyA_;
  AuthorityRegistryCopy& copyB_;
};

}  // namespace authority
}  // namespace ota
