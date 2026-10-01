#pragma once

// Top-level, flash-serialized, amortized security store: two 100 KiB
// generation tails (A/B, see OtaSecurityGeometry.h), each holding a 64 KiB
// snapshot checkpoint + 32 KiB append-only data log witnessed by the
// OPPOSITE bank's 4 KiB head-witness sector. Conforms to (implements
// adapters over, see OtaSecurityTxRxAdapters.h) the existing, UNCHANGED
// ITxSequenceBackingStore / IRxSequenceBackingStore / commissioning-
// authority interfaces in ota/runtime/OtaSequenceBackingPort.h.
//
// This class performs NO I/O in its constructor -- only FlashRegion/engine
// references and plain arithmetic are set up. Every fact (active
// bank/generation, TX upper bound, RX watermarks, table occupancy) is
// derived by an explicit reconstruct() call that reads and classifies
// EVERY relevant byte on both tails; it never trusts residual RAM state.
//
// Cold-evidence combination rule (see OtaSecurityEvidence.h for the raw
// per-record taxonomy): a record at the highest evidenced position for a
// given counter/context is only ever treated as a durable, usable fact
// when BOTH its data cell AND its opposite-bank witness independently
// classify Committed with matching identity/generation/slot/lsn binding.
// Anything else (BodyOnly either side, Unprovable, mismatched binding, a
// witness attesting to a position whose data cell is unreadable, or a
// data cell claiming completion with no matching witness) freezes that
// fact as Uncertain rather than silently adopting an older/lower head or
// discarding the possible commitment. When an ambiguous position's
// record type/identity cannot even be determined (e.g. the data cell
// itself is gone and only a witness LSN survives), the WHOLE store
// freezes conservatively, since the ambiguity cannot be attributed to one
// specific counter/context.

#include <stdint.h>
#include <algorithm>
#include <cstring>
#include <map>
#include <vector>

#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashRegion.h"
#include "ota/runtime/OtaSequenceBackingPort.h"
#include "ota/security/OtaSecurityAppendEngine.h"
#include "ota/security/OtaSecurityByteCodec.h"
#include "ota/security/OtaSecurityDataCell.h"
#include "ota/security/OtaSecurityEvidence.h"
#include "ota/security/OtaSecurityGeometry.h"
#include "ota/security/OtaSecurityPhysicalPartitionArbiter.h"
#include "ota/security/OtaSecuritySnapshot.h"
#include "ota/security/OtaSecurityWitnessSector.h"
#include "ota/storage/Crc32.h"
#include "ota/trust/Sha256.h"

// Forward declaration only: a test-only accessor (defined in this
// suite's own .cpp, at global scope) that the production class grants
// friend access to below, so the phased reconstruct() helper
// (resolveActivePhysicalState) can be invoked/measured in isolation by
// the test suite without widening the real production API surface.
struct OtaSecurityStorePhaseATestAccess;

namespace ota {
namespace security {

using meshcore::ota::runtime::OtaRxLedgerContext;
using meshcore::ota::runtime::OtaSequenceBackingResult;

// Opaque per-caller identity for the owner-bound ordinary-mutation engine.
// Two DIFFERENT callers driving the SAME Store instance (e.g. two adapter
// objects wrapping one OtaSecurityStore&) must never be able to "resume"
// -- let alone silently collect the durable result of -- each other's
// in-flight operation merely because their call arguments happen to be
// byte-identical; only the SAME owner token may resume a matching
// in-flight op. The default (nullptr) owner represents the common
// single-driver-per-instance case (almost every existing direct
// store.reserveTx(...)-style test call): all such callers share the one
// default identity, so their own resume semantics are completely
// unchanged. A caller that legitimately wants independent ownership
// (chiefly the port-conforming adapters in OtaSecurityTxRxAdapters.h,
// each of which passes its own `this`) supplies a distinct, stable
// pointer of its own.
using OtaSecurityOperationOwner = const void*;

// Opaque owner+ticket handle for the async, resumable ordinary-mutation
// engine. A ticket is minted ONLY by a fresh start (see startOrdinaryOp())
// and is the SOLE resumption credential from that point on: unlike the
// superseded (owner, argsFingerprint) resume check, presenting the exact
// SAME owner and byte-identical arguments is deliberately NOT sufficient
// to resume or collect an in-flight op -- the caller MUST have retained
// the actual `OtaSecurityOperationTicket` value handed back by the start
// call (or a prior WouldBlock-returning poll) and pass it back verbatim.
// This closes two real gaps the old fingerprint-based resume had: (1) two
// distinct logical requests from the SAME owner that happen to carry
// identical argument bytes could otherwise be confused with each other
// (a 64-bit args hash is not an identity proof); (2) an owner token whose
// underlying object was destroyed and a NEW, unrelated object happens to
// be allocated at the exact same address (ABA) could otherwise silently
// "resume" a stale op it never started -- the previous op's `id` (a
// monotonically-increasing, never-reused counter) genuinely differs from
// any ticket a fresh caller could present, so the match always fails.
// `id == 0` is the canonical "no ticket" / "not currently holding
// anything" sentinel and can never match a real in-flight op (ticket ids
// are minted starting at 1 and never reused).
//
// `issuerInstanceEpoch`: binds this ticket to the exact RAM Store OBJECT
// (not merely the logical physical identity -- see `storeIdentity_`,
// which two DIFFERENT Store objects legitimately wrapping the SAME
// physical media intentionally share) that minted it. Each
// OtaSecurityStore instance draws a fresh value from a process-wide
// monotonic, never-reused counter at construction (see
// OtaSecurityStore::nextInstanceEpoch()). Without this, a ticket
// {owner, id} minted by Store object A could be mistakenly presented to
// a DIFFERENT Store object B (e.g. a stale caller reference, or B
// reusing A's now-freed RAM address) whose OWN, unrelated pendingOp_
// happens to have independently reached the identical (owner, id) pair
// (each Store's `nextOpTicketSeed_` starts at 1, so id collisions across
// distinct objects are the expected common case, not a rare fluke) --
// silently resuming/cancelling/collecting the WRONG object's operation.
// Comparing the issuing instance's epoch closes this cross-object ABA
// gap; a ticket is honored ONLY by the exact Store object that minted
// it.
struct OtaSecurityOperationTicket {
  OtaSecurityOperationOwner owner = nullptr;
  uint64_t id = 0;
  uint64_t issuerInstanceEpoch = 0;
  bool valid() const { return id != 0 && owner != nullptr && issuerInstanceEpoch != 0; }
};


// Bounded, real (not simulated) flash-serialized security store. See the
// file header comment above for the overall protocol.
class OtaSecurityStore {
public:
  // Retains references only; carves the six FlashRegions (two tails x
  // {snapshot, dataLog, witness}) via plain arithmetic. NO I/O happens
  // here -- callers MUST call reconstruct() before any other method.
  //
  // `physicalToken`: MANDATORY, board-supplied `PhysicalPartitionToken`
  // identifying the ONE real physical NOR chip this Store's carved
  // partition lives on. Root correction: a FlashDevice&'s own object
  // address is only an OBJECT identity, NOT a hardware identity -- two
  // separately constructed FlashDevice/IFlashIO WRAPPER OBJECTS that both
  // address the SAME physical chip are different objects, so deriving
  // identity from `&device` would silently fail to unify them. The
  // caller (production: the board's platform layer; native tests:
  // whatever fixture represents "this is chip N") MUST supply the SAME
  // token for every wrapper addressing one physical chip, and a
  // DIFFERENT token for every genuinely distinct chip -- this is never
  // inferred here. Passing `physicalToken == 0` ("unknown/unbound") is
  // treated as a permanent misconfiguration: this instance refuses
  // BEFORE any I/O or mutation (partitionMisconfigured() becomes true
  // immediately, arbiter_ stays nullptr, reconstruct() returns without
  // touching flash) rather than ever inferring "distinct object address
  // == distinct chip". The registry's actual arbitration key is the
  // FULL, EXACT (token, bankAOffset, bankBOffset) tuple (see
  // PhysicalPartitionKey in OtaSecurityPhysicalPartitionArbiter.h) --
  // compared field-by-field, never collapsed through a hash/XOR that
  // could theoretically collide two distinct tuples onto one identity.
  //
  // `sharedArbiter`: OPTIONAL, but there is NO "unshared/private" mode
  // regardless of whether it is supplied. Pass nullptr (the "default"
  // path) and this Store automatically joins the SINGLE,
  // registry-owned arbiter for its (token, bankAOffset, bankBOffset)
  // identity, created on first use -- so two "default" Store wrappers
  // sharing one token genuinely arbitrate against each other, never
  // silently race. Pass an explicit, externally-owned arbiter (which
  // MUST outlive this Store) when a caller wants to inject a SPECIFIC
  // shared instance across multiple wrappers it constructs -- every such
  // wrapper MUST be given the SAME arbiter object; see
  // OtaSecurityPhysicalPartitionArbiter.h. Passing a DIFFERENT explicit
  // arbiter than one already bound (by a still-alive Store, default OR
  // explicit) to this same physical identity is refused: this instance
  // becomes permanently misconfigured and every subsequent operation
  // fails closed (Uncertain/false/WouldBlock), never silently proceeding
  // unshared.
  OtaSecurityStore(::ota::platform::FlashDevice& device, uint32_t bankAOffset, uint32_t bankBOffset,
                    uint64_t storeIdentity, PhysicalPartitionToken physicalToken,
                    OtaSecurityPhysicalPartitionArbiter* sharedArbiter = nullptr)
      : carveA_(device, bankAOffset), carveB_(device, bankBOffset), storeIdentity_(storeIdentity),
        instanceEpoch_(nextInstanceEpoch()) {
    if (physicalToken == 0) {
      // Unknown/unbound physical identity: refuse before ANY I/O or
      // mutation. arbiter_ stays nullptr; misconfigured_ latches
      // permanently (matches the existing mismatched-explicit-arbiter
      // refusal path everywhere else in this class).
      misconfigured_ = true;
      return;
    }
    physicalPartitionKey_ = PhysicalPartitionKey{physicalToken, bankAOffset, bankBOffset};
    arbiter_ = OtaSecurityPartitionArbiterRegistry::acquire(physicalPartitionKey_, sharedArbiter);
    misconfigured_ = (arbiter_ == nullptr);
  }

  ~OtaSecurityStore() {
    if (arbiter_ == nullptr) return;  // misconfigured: never bound, nothing to release.
    arbiter_->release(this);
    OtaSecurityPartitionArbiterRegistry::release(physicalPartitionKey_, arbiter_);
  }

  OtaSecurityStore(const OtaSecurityStore&) = delete;
  OtaSecurityStore& operator=(const OtaSecurityStore&) = delete;
  // Move is intentionally NOT supported: arbiter ownership tickets are
  // bound to a stable `this` address (OwnerToken); a moved-from/to pair
  // would silently invalidate that binding.
  OtaSecurityStore(OtaSecurityStore&&) = delete;
  OtaSecurityStore& operator=(OtaSecurityStore&&) = delete;

  bool regionsValid() const { return carveA_.isValid() && carveB_.isValid(); }
  bool partitionMisconfigured() const { return misconfigured_; }

  // Narrow, already-safe, ZERO-I/O exclusive-lease primitive for an
  // EXTERNAL caller (e.g. a cooperative FW-side media-access job) that
  // needs to hold real exclusive ownership of this store's physical
  // partition for the duration of its OWN bounded sequence of QSPI/
  // flash-adjacent operations, WITHOUT going through any of this Store's
  // read/reconstruct/mutation entry points (those remain separately
  // scoped/hardened elsewhere and must not be called synchronously from
  // an unrelated caller). Returns the SAME shared, registry-unified
  // OtaSecurityPhysicalPartitionArbiter instance every sibling Store
  // wrapper over this exact physical identity already arbitrates
  // through (see OtaSecurityPhysicalPartitionArbiter.h) -- acquiring
  // here via the arbiter's own `acquire(OwnerToken)`/`release(OwnerToken)`
  // with a caller-supplied, stable, non-null OwnerToken (NEVER this
  // Store's own `this`, which is reserved for the Store's internal
  // acquisitions) genuinely excludes this Store's own internal
  // acquirePartitionOwnership() (and every sibling Store) for as long as
  // the external caller holds it, and vice versa. Returns nullptr ONLY
  // when this instance is permanently misconfigured (partitionMisconfigured()
  // is true -- an unbound/zero physicalToken, or a refused explicit-
  // arbiter mismatch): a real, permanent configuration error, distinct
  // from ordinary contention, checked ONCE at setup since the RAM
  // arbiter itself has no transient I/O-fault mode of its own. Ordinary
  // contention (a different owner -- Store-internal or another external
  // caller -- currently holds it) is reported by `acquire()` returning
  // false on an otherwise-valid (non-null) arbiter, and must be treated
  // as "retry later", never escalated.
  OtaSecurityPhysicalPartitionArbiter* physicalPartitionArbiter() const {
    return misconfigured_ ? nullptr : arbiter_;
  }

  // --- Cold reconstruction -------------------------------------------------
  // SLICE5: reconstruct() is a TEST/offline-tool convenience ONLY -- it
  // loops the bounded stepReconstruct() engine to completion (see its
  // definition's kMaxReconstructDrainSteps cap) in one call, and must
  // never be invoked from a production, time-budgeted, or RX-dispatch-
  // adjacent call path. Every actual production entry point
  // (openExistingTx/Rx, reserveTx/advanceRx/etc, refreshIfPhysicallyStale())
  // already drives the SAME bounded cursor one unit at a time via its own
  // retained ticket and returns typed WouldBlock while rebuilding -- it
  // never calls this synchronous wrapper. A real cold-startup/service
  // caller must do likewise: drive stepReconstruct() directly under its
  // own owner+ticket+step cadence, never call reconstruct().
  void reconstruct();

  uint32_t activeGeneration() const { return activeGeneration_; }
  OtaSecurityBankId activeBank() const { return activeBank_; }
  bool storeWideFrozen() const { return storeFrozen_; }
  uint32_t ordinaryAppendsUsed() const { return nextFreeSlot_; }
  uint32_t compactionCount() const { return compactionCount_; }

  // --- TX: single global identity, block-reservation counter --------------
  OtaSequenceBackingResult openExistingTx();
  OtaSequenceBackingResult readTxCounter(uint32_t& outReservedUpperBound);
  // `ticket` is an in/out owner+ticket handle: on a FRESH start (ticket
  // with id==0 and no op currently pending for a matching credential)
  // this call mints a fresh ticket into it if the op cannot complete
  // within this bounded step; the caller MUST pass that exact ticket
  // back on every subsequent call until this op reaches a terminal
  // result, at which point `ticket` is reset to {} (burned -- can never
  // be replayed). See OtaSecurityOperationTicket's doc comment for why
  // (owner, argsFingerprint) alone is no longer sufficient.
  OtaSequenceBackingResult reserveTx(uint32_t expectedCurrentUpperBound, uint32_t blockSize,
                                     uint32_t& outNewUpperBound, OtaSecurityOperationOwner owner,
                                     OtaSecurityOperationTicket& ticket);
  // `factoryGrantAuthorized` stands in for an INDEPENDENT, positive,
  // one-use factory/full-identity commissioning proof supplied from
  // outside this counter API (see OtaSequenceBackingPort.h's doc comment);
  // this store never treats a blank/Missing record as permission by
  // itself -- both this flag AND txUpperBound_==0 are required.
  //
  // Typed result (NOT a bare bool -- MAIN/Root correction): a legacy
  // bool return conflated "still pending, call again" with "genuinely,
  // permanently denied," and gave a resuming caller presenting CHANGED
  // arguments no way to distinguish "your original op finished" from
  // "a DIFFERENT request was silently accepted on your behalf." This
  // returns Committed (the ORIGINAL fresh-start request is now durable),
  // WouldBlock (genuinely still in flight -- call again with the SAME
  // ticket and the SAME original arguments), Conflict (a ticket IS
  // in-flight, but THIS call's arguments do not match the ones captured
  // at the fresh start -- no physical step was taken, the original
  // ticket/op is untouched and still resumable by a caller presenting
  // the correct original arguments), NoCapacity, or OwnershipDenied
  // (owner==nullptr, not authorized, or an already-commissioned source).
  OtaSequenceBackingResult commissionVirginTx(uint32_t initialUpperBound, bool factoryGrantAuthorized,
                                              OtaSecurityOperationOwner owner, OtaSecurityOperationTicket& ticket);

  // --- RX: full peer32 / group92 watermark ---------------------------------
  OtaSequenceBackingResult openExistingRx(const OtaRxLedgerContext& ctx);
  OtaSequenceBackingResult readRxCounter(const OtaRxLedgerContext& ctx, uint32_t& outWatermark);
  OtaSequenceBackingResult advanceRx(const OtaRxLedgerContext& ctx, uint32_t expectedHead, uint32_t newHead,
                                    OtaSecurityOperationOwner owner, OtaSecurityOperationTicket& ticket);
  // Same typed-result contract as commissionVirginTx() above.
  OtaSequenceBackingResult commissionVirginRx(const OtaRxLedgerContext& ctx, uint32_t initialWatermark,
                                              bool factoryGrantAuthorized, OtaSecurityOperationOwner owner,
                                              OtaSecurityOperationTicket& ticket);

  // --- Terminal attempts: 384 capacity, one-use, never evicted -------------
  // Returns Committed (newly admitted), Committed with `outDuplicate=true`
  // (byte-identical re-submission, idempotent no-op, no new slot
  // consumed), Conflict (tuple/nonce collision against a DIFFERENT
  // manifest -- refused), or NoCapacity (all 384 slots already used).
  OtaSequenceBackingResult admitTerminalAttempt(const OtaSecurityTerminalEntry& entry, bool& outDuplicate,
                                                OtaSecurityOperationOwner owner, OtaSecurityOperationTicket& ticket);
  uint32_t terminalAttemptCount() const { return terminalCount_; }
  uint32_t peerCount() const { return peerTableCount_; }
  uint32_t cohortCount() const { return cohortTableCount_; }

  // Resident-footprint observability (STOREPLAN Priority 3): the actual
  // per-row size of the resident terminal INDEX (location16+flags16+
  // tupleFingerprint32 = 8B), exposed as a plain constant rather than the
  // private nested index-entry type itself, purely so the resource-gate
  // test can assert the real measured number without needing friend
  // access into the Store's internal representation.
  static constexpr size_t kTerminalIndexEntryBytes = 8u;

  static void computeTerminalNoncePreimage(const uint8_t controller[32], uint32_t campaign, uint32_t session,
                                            uint16_t attempt, const uint8_t canonicalDescriptorDigest[32],
                                            uint64_t& outNonce);

  // --- FactoryGrant: independent, durable, ONE-USE, default-deny --------
  // commissioning grant (device UID + full local PK + format/profile/
  // layout/role/initial-role + local consent owner + transaction). A
  // fresh/never-granted store answers factoryGrantConsumed()==false,
  // never true -- this is never inferred from a blank/Missing backing.
  // Returns OwnershipDenied if already consumed (one-use).
  OtaSequenceBackingResult commissionFactoryGrant(const OtaSecurityFactoryGrant& grant,
                                                  OtaSecurityOperationOwner owner,
                                                  OtaSecurityOperationTicket& ticket);
  bool factoryGrantConsumed() const { return factoryGrantConsumed_; }
  const OtaSecurityFactoryGrant& factoryGrant() const { return factoryGrant_; }

  // --- LiveBinding: real typed 4096-byte-budget blob (signed material / --
  // consent / frozen SDK28 / original SHA / extent+bitmap / bounded
  // 350-roster by stable peer-table index). Durable via a bounded,
  // fixed-count multi-cell transaction in the ordinary log; ALL chunks
  // must individually commit before the whole binding is treated as
  // committed -- see OtaSecuritySnapshot.h's OtaSecurityLiveBindingCodec.
  OtaSequenceBackingResult writeLiveBinding(const OtaSecurityLiveBinding& binding, OtaSecurityOperationOwner owner,
                                            OtaSecurityOperationTicket& ticket);
  bool liveBindingCommitted() const { return liveBindingPresent_; }
  const OtaSecurityLiveBinding& liveBinding() const { return liveBinding_; }

  // --- Owner-bound ordinary-op ticket: real public handoff + cancel ------
  // 0 means no ordinary mutation is currently in flight on this instance.
  // A nonzero value identifies the SINGLE in-flight op; it is cleared the
  // instant that op reaches a terminal result, OR is explicitly cancelled
  // below. Unlike the prior (owner, argsFingerprint)-only resume scheme,
  // every one of the 7 ordinary-mutation methods above now hands this
  // EXACT value back to the caller via its `OtaSecurityOperationTicket&`
  // out-parameter the moment a fresh op is started -- this accessor
  // remains for observability/tests, but is no longer the only way the
  // real ticket reaches a caller.
  uint64_t pendingOrdinaryOperationTicket() const { return pendingOp_.ticket; }
  bool hasPendingOrdinaryOperation() const { return pendingOp_.kind != OrdinaryOpKind::None; }

  // Explicitly invalidates (cancels) THIS instance's RAM-only resumption
  // cursor for its in-flight ordinary op, but ONLY if `owner` is exactly
  // the owner that started it (a null owner, or any owner other than the
  // one that started the op, never matches and changes nothing). This is
  // a RAM-lifetime operation, not an undo: any bytes already made durable
  // by prior steps of the op (a committed data-cell body+marker, a
  // committed witness, or a committed seal/switch record) remain exactly
  // as durable as they were -- cancelling only means THIS instance will
  // no longer try to resume/continue that specific physical cell/chunk
  // sequence itself. A subsequent fresh owner (including a NEW instance
  // after a cold RAM reset, or the SAME owner starting a genuinely new
  // op) must refresh from flash and reconcile/resume the pending durable
  // state on its own, exactly like any other cold-start caller -- the
  // durable generation/seal/witness facts on flash are what govern
  // recovery, never this RAM ticket. Intended primarily for adapter
  // destructors (RAII "drain"): an adapter object going out of scope must
  // never leave a phantom RAM ticket that nothing can ever resume or
  // cancel again, which would otherwise permanently wedge this Store
  // instance's ordinary-mutation engine behind a caller that no longer
  // exists. Requires the EXACT (issuer instance, owner, id) ticket -- not
  // merely a matching owner -- so a stale/ABA'd ticket from a previous op
  // (or a previous Store OBJECT reused at the same address, or even a
  // DIFFERENT still-alive Store object whose own (owner,id) pair happens
  // to collide) can never cancel a DIFFERENT, unrelated op. Returns true
  // if a matching pending op was actually cancelled, false if there was
  // nothing pending for this exact ticket.
  bool cancelPendingOrdinaryOperation(const OtaSecurityOperationTicket& ticket) {
    if (!ticket.valid()) return false;
    if (pendingOp_.kind == OrdinaryOpKind::None || ticket.issuerInstanceEpoch != instanceEpoch_ ||
        pendingOp_.owner != ticket.owner || pendingOp_.ticket != ticket.id) {
      return false;
    }
    clearPendingOrdinaryOp();
    // The RAM-only resumption cursor is gone; if no other reason holds
    // the shared physical-partition ownership (this WAS the only reason
    // this instance held it while the op was in flight), release it so a
    // sibling instance is not blocked behind a caller that no longer
    // intends to resume anything.
    if (!hasPendingOrdinaryOperation() && !compactionInProgress_) releasePartitionOwnership();
    return true;
  }

  // --- Compaction -----------------------------------------------------------
  // A(gen G) <-> B(gen G+1), reversed exactly the other direction next
  // time. See the class/file doc comments for the exact ordered protocol.
  // compact() is a synchronous convenience wrapper that loops compactStep()
  // to completion (preserves the original single-call contract for all
  // existing callers/tests).
  OtaSequenceBackingResult compact();

  // Bounded, resumable, single-step compaction primitive: performs exactly
  // ONE physical unit of work (one sector erase, or one bounded program/
  // verify/switch/activate step) per call and returns WouldBlock until the
  // whole compaction finishes (Committed) or fails terminally. Intended
  // for a per-tick service-step integration (never inlined directly into
  // e.g. radio RX dispatch); freezes ordinary mutations for the duration
  // (see CompactionPhase's doc comment). Idempotent to call when idle: a
  // fresh call with no compaction already in progress simply starts one.
  OtaSequenceBackingResult compactStep();
  bool compactionInProgress() const { return compactionInProgress_; }

  // Diagnostics for wear-accounting tests: total erase operations observed
  // by the underlying FlashDevice(s) is available via the test's own
  // FakeNorFlash handle; this exposes only what the store itself knows it
  // asked for (each compact() erases exactly 24 destination sectors + 1
  // source-witness sector; every append performs zero erases).
  static constexpr uint32_t kSectorsErasedPerCompaction = 24u + 1u;

private:
  // Test-only accessor letting the test suite invoke/measure the phased
  // reconstruct() helpers (resolveActivePhysicalState, etc.) in isolation
  // without widening the real production API surface -- see the
  // ReconstructPhaseAResult comment above for why this phase is defined
  // as its own independently testable unit.
  friend struct ::OtaSecurityStorePhaseATestAccess;

  // Process-wide, never-reused, never-reset monotonic counter: the SOLE
  // source of each Store object's `instanceEpoch_` (see ticket doc
  // comment above). A plain function-local static avoids any global
  // static-init-order concern; not thread-safe (this engine is single-
  // threaded/cooperative throughout, matching every other piece of
  // mutable Store state).
  static uint64_t nextInstanceEpoch() {
    static uint64_t counter = 0;
    return ++counter;
  }

  OtaSecurityTailCarve carveA_;
  OtaSecurityTailCarve carveB_;
  uint64_t storeIdentity_;
  // Uniquely identifies THIS RAM OBJECT (never the logical physical
  // store -- see storeIdentity_, which siblings over the same media
  // legitimately share). Stamped into every ticket this instance mints;
  // see OtaSecurityOperationTicket::issuerInstanceEpoch.
  uint64_t instanceEpoch_;

  // Physical partition arbitration (see OtaSecurityPhysicalPartitionArbiter.h
  // for the full contract). arbiter_ is ALWAYS the registry-owned (or
  // explicitly-injected) shared arbiter for this Store's physical
  // identity -- there is no private/unshared fallback; nullptr occurs
  // for a permanently-misconfigured instance (refused explicit-arbiter
  // mismatch, OR an unbound/zero physicalToken), whose destructor and
  // every mutation entry point check for it via misconfigured_.
  OtaSecurityPhysicalPartitionArbiter* arbiter_ = nullptr;
  PhysicalPartitionKey physicalPartitionKey_{};
  bool misconfigured_ = false;  // true for a refused explicit-arbiter mismatch OR an unbound (zero) physicalToken; permanent, RAM-only.

  // Acquires this instance's ownership ticket for the shared physical
  // partition BEFORE any fresh-view refresh/CAS/source-freeze/seal work,
  // per the STOREPLAN contract. Returns false (caller must return
  // WouldBlock without touching flash) when a FOREIGN owner (another
  // Store wrapper sharing this same arbiter, e.g. mid-compaction) already
  // holds it, or when this instance is permanently misconfigured.
  bool acquirePartitionOwnership() {
    if (misconfigured_) return false;
    return arbiter_->acquire(this);
  }
  void releasePartitionOwnership() { arbiter_->release(this); }

  OtaSecurityBankId activeBank_ = OtaSecurityBankId::A;
  uint32_t activeGeneration_ = 1;
  bool storeFrozen_ = false;
  bool txFrozen_ = false;
  bool txOpened_ = false;
  uint32_t txUpperBound_ = 0;

  uint32_t nextFreeSlot_ = 0;  // next unused ordinary physical position (0..253) in the active bank.
  uint64_t nextLsn_ = 1;       // next global monotonic LSN to assign.
  uint32_t compactionCount_ = 0;
  bool activeSnapshotValid_ = false;  // true only once a witness-verified snapshot exists (post-first-compaction).

  // --- Bounded/resumable compaction state (see compactStep()) -------------
  // A compaction in progress FREEZES all ordinary mutation entry points
  // (reserveTx/advanceRx/commissionVirginTx/commissionVirginRx/
  // admitTerminalAttempt/commissionFactoryGrant/writeLiveBinding), which
  // return WouldBlock/false while compactionInProgress_ is true -- exactly
  // the "freeze mutations" requirement for A(G)->B(G+1). Each call to
  // compactStep() performs exactly ONE bounded unit of physical work (one
  // sector erase, or one bounded program/verify/switch/activate step) and
  // returns WouldBlock until the whole compaction is done, at which point
  // it returns Committed (or a terminal error, freezing the store exactly
  // like the prior monolithic compact() did). compact() itself is now a
  // thin convenience wrapper that loops compactStep() to completion, so
  // existing single-call callers/tests are unaffected.
  enum class CompactionPhase : uint8_t {
    Idle = 0,
    SealSource,
    EraseDestSnapshotSector,
    EraseDestLogSector,
    WriteDestSnapshot,
    ReadbackVerifyDestSnapshot,
    PrepareSourceWitness,
    CommitSwitch,
    Activate,
  };
  bool compactionInProgress_ = false;
  CompactionPhase compactionPhase_ = CompactionPhase::Idle;
  OtaSecurityBankId compactionSource_ = OtaSecurityBankId::A;
  OtaSecurityBankId compactionDest_ = OtaSecurityBankId::A;
  uint32_t compactionNewGeneration_ = 0;
  uint32_t compactionEraseCursor_ = 0;  // sector index within the CURRENT erase phase only.
  // Byte offset already durably programmed WITHIN the current
  // WriteDestSnapshot unit's row (see programRowSliceAndAdvance()):
  // nonzero only while a single table row (peer48B/cohort160B/
  // terminal96B) straddles a 256B physical NOR page and needed more
  // than one compactStep() call to finish -- a row's physical start
  // address is `tableBase + index*entryBytes`, which is NOT generally
  // 256-aligned, so e.g. a cohort row at absolute offset mod256==160
  // with len160 crosses into the next page and MUST NOT be programmed
  // in a single physical page operation.
  uint32_t compactionRowByteOffset_ = 0;

  // Bounded/resumable sub-state for CompactionPhase::PrepareSourceWitness
  // -- the ONE step that, unlike ordinary per-append witness prep (always
  // a cache hit after the first reference to a generation), is
  // genuinely computing a (bank, generation) digest for the VERY FIRST
  // time (dest's freshly-written snapshot has never been hashed before).
  // A naive single-call ensureWitnessPrepared() here would read+hash all
  // kSnapshotSizeBytes (64 KiB) in one synchronous burst -- exactly the
  // per-step budget violation this sub-state machine exists to prevent:
  // one 1024-byte chunk is hashed per compactStep() call, then the
  // witness sector erase/body-program/marker-program are ALSO each their
  // own call (mirroring the <=1 program-or-erase-call-per-step rule
  // already applied to SealSource/CommitSwitch below).
  enum class WitnessPrepSubPhase : uint8_t { StreamDigest = 0, EraseWitnessSector, ProgramBody, ProgramMarker };
  enum class WitnessPrepStepOutcome : uint8_t { InProgress, Done, Failed };
  WitnessPrepSubPhase witnessPrepSubPhase_ = WitnessPrepSubPhase::StreamDigest;
  ::ota::trust::Sha256 compactionWitnessSha_;
  uint64_t compactionPreparedDigestValue_ = 0;
  WitnessPrepStepOutcome prepareSourceWitnessStep(OtaSecurityBankId protectedBank, uint32_t generation);

  // Bounded/resumable sub-state for the reserved seal/switch cell writes
  // (CompactionPhase::SealSource / CommitSwitch): a physical cell is
  // committed via a two-phase body-then-marker program, and the approved
  // per-step budget allows at most ONE program-or-erase call per
  // compactStep() invocation -- so body and marker are split into two
  // separate calls instead of the ordinary synchronous writeCellOnly().
  enum class ReservedCellSubPhase : uint8_t { CheckAndBody = 0, Marker };
  enum class ReservedCellStepOutcome : uint8_t { InProgress, Committed, Failed };
  ReservedCellSubPhase sealSubPhase_ = ReservedCellSubPhase::CheckAndBody;
  ReservedCellSubPhase switchSubPhase_ = ReservedCellSubPhase::CheckAndBody;
  ReservedCellStepOutcome appendReservedRecordStep(OtaSecurityBankId bank, uint32_t physicalIndex,
                                                   OtaSecurityRecordType type, uint32_t generation,
                                                   const uint8_t* payload, uint16_t payloadLen,
                                                   ReservedCellSubPhase& subPhase);

  // --- Owner-bound resumable ordinary-mutation engine ---------------------
  // Every ordinary public mutation (reserveTx/advanceRx/commissionVirginTx/
  // commissionVirginRx/admitTerminalAttempt/commissionFactoryGrant/
  // writeLiveBinding) drives through this SINGLE piece of per-instance
  // state instead of a one-shot synchronous body+marker write, mirroring
  // the bounded/resumable pattern already proven correct for
  // appendReservedRecordStep()/compactStep(). At most ONE ordinary op may
  // be in flight on a given Store instance at a time; a genuinely
  // DIFFERENT request (different kind, different argument bytes, OR a
  // DIFFERENT caller-supplied owner token) made while one is in flight is
  // refused with WouldBlock rather than stomping -- or being silently
  // "collected" by -- the in-flight one. A matching request (same kind,
  // same argument bytes, same owner) is treated as a legitimate RESUME and
  // continues the SAME physical cell(s) from wherever they left off.
  //
  // Physical cross-INSTANCE exclusion (a second Store OBJECT sharing this
  // one's physical-partition arbiter) is enforced separately, at
  // acquirePartitionOwnership(): it cannot even reach this state while a
  // sibling instance holds ownership mid-flight. But two DIFFERENT
  // CALLERS can also legitimately share ONE Store instance -- e.g. two
  // independent OtaSecurityTxBackingStore adapter objects both wrapping
  // the same OtaSecurityStore& (a valid shape per the port interfaces,
  // which say nothing about one-driver-per-backing-store) -- and, without
  // an explicit per-caller owner token, a second such caller supplying
  // BYTE-IDENTICAL arguments would satisfy the (kind, argsFingerprint)
  // resume check above and silently "collect"/observe the FIRST caller's
  // still-in-flight reservation as if it were its own. `owner` (an opaque
  // OtaSecurityOperationOwner, e.g. an adapter's own `this`) closes this
  // gap: only the exact owner that started an op may resume it; any other
  // owner -- matching args or not -- is simply "busy" and gets WouldBlock
  // without touching any state, exactly like a genuinely different
  // request would.
  enum class OrdinaryOpKind : uint8_t {
    None = 0,
    ReserveTx,
    CommissionVirginTx,
    AdvanceRx,
    CommissionVirginRx,
    AdmitTerminal,
    CommissionFactoryGrant,
    WriteLiveBinding,
  };
  enum class OrdinaryOpStepOutcome : uint8_t { InProgress, Committed, Failed };

  // Splits an ordinary append's exact four physical program calls
  // (data body, data marker, witness body, witness marker) one per
  // step so every public ordinary-mutation call performs at most ONE
  // program call, per the approved per-step budget. EnsureWitness runs
  // FIRST, before CheckAndBody: on every ordinary append after the
  // witness sector's first reference to this (bank, generation) it is a
  // pure cache-hit read (zero writes), so it safely falls through into
  // CheckAndBody within the SAME step; the very first (genesis) append
  // of a store's lifetime instead needs its own erase+body+marker
  // sequence, bounded to its own separate steps below (see
  // stepEnsureWitnessPrepared()) so that case never bundles more than
  // one program-or-erase call into a single public step either.
  enum class OrdinaryCellSubPhase : uint8_t { EnsureWitness = 0, CheckAndBody, Marker, WitnessBody, WitnessMarker };

  // Bounded/resumable counterpart of the old single-call
  // ensureWitnessPrepared(): CheckCache performs only a read (plus a
  // cache-hit-only digest lookup) and, on a genuine cold miss, the ONE
  // erase call needed -- never more. ProgramBody/ProgramMarker each
  // perform exactly one program call. DoneNoWrite (a pure cache hit,
  // zero writes) is the only outcome the caller may fold into the same
  // step as subsequent work; DoneAfterWrite/InProgress both mean this
  // step already spent its one program-or-erase call and the rest of
  // the cell op must wait for the NEXT call.
  enum class OrdinaryWitnessPrepSubPhase : uint8_t { CheckCache = 0, ProgramBody, ProgramMarker };
  enum class OrdinaryWitnessPrepOutcome : uint8_t { InProgress, DoneNoWrite, DoneAfterWrite, Failed };
  OrdinaryWitnessPrepSubPhase ordinaryWitnessPrepSubPhase_ = OrdinaryWitnessPrepSubPhase::CheckCache;
  OtaSecurityWitnessSectorHeader ordinaryWitnessPrepHeader_;
  OrdinaryWitnessPrepOutcome stepEnsureWitnessPrepared(OtaSecurityBankId protectedBank, uint32_t generation);

  struct PendingOrdinaryOp {
    OrdinaryOpKind kind = OrdinaryOpKind::None;
    uint64_t ticket = 0;            // opaque, unique per started op; 0 == none in flight.
    OtaSecurityOperationOwner owner = nullptr;  // exact caller that started this op; only a matching TICKET may resume.
    uint32_t physicalIndex = 0;     // ordinary-log cell claimed for the CURRENT chunk.
    OrdinaryCellSubPhase cellSubPhase = OrdinaryCellSubPhase::EnsureWitness;
    OtaSecurityRecordType recordType = OtaSecurityRecordType::TxReservation;
    uint16_t logicalSlot = 0;
    uint8_t payload[kCellPayloadBytes] = {0};
    uint16_t payloadLen = 0;
    uint32_t chunkIndex = 0;   // 0-based index of the chunk currently being (re)written.
    uint32_t chunkCount = 1;   // total chunks in this op; 1 for every op except WriteLiveBinding.
    uint64_t transactionLsn = 0;  // fixed at chunk 0, reused verbatim in every later chunk's header.
  };
  PendingOrdinaryOp pendingOp_;
  uint64_t nextOpTicketSeed_ = 1;
  // The FULL encoded live-binding area bytes captured ONCE, at the fresh
  // start call of a WriteLiveBinding op (see writeLiveBinding()) -- the
  // Store OWNS this immutable copy for the lifetime of the op so every
  // later chunk (and the final committed RAM publish) is driven from
  // EXACTLY the bytes the FIRST chunk's witness already committed to,
  // never from whatever `binding` argument a later resume call happens
  // to pass (which may legitimately differ, by caller bug or otherwise,
  // from the original request -- see OtaSecurityOperationTicket's doc
  // comment: a matching ticket proves WHICH operation is being resumed,
  // never that the resumed call's other arguments are trustworthy).
  // Only meaningful while pendingOp_.kind == WriteLiveBinding.
  uint8_t pendingLiveBindingFullBytes_[kLiveBindingAreaBytes] = {0};

  // True iff `t` is the EXACT (issuer-instance, owner, id) ticket
  // currently holding the pending op of `kind` -- the sole resumption
  // credential (see OtaSecurityOperationTicket's doc comment:
  // byte-identical arguments and/or a matching owner are deliberately
  // NOT sufficient on their own). The issuerInstanceEpoch check rejects
  // a ticket minted by a DIFFERENT Store RAM object outright, even if
  // that object's (owner, id) pair happens to collide with this
  // instance's current pendingOp_ (expected, not rare, since every
  // Store's nextOpTicketSeed_ independently starts at 1).
  // `callerOwner`: the CURRENT call's own `owner` argument. Root
  // correction (Sol's "wrongpassedowner withcopiedvalidticket accepted"
  // finding): a ticket's OWN embedded `t.owner` field is information the
  // Store handed back to whoever started the op -- if that ticket value
  // is copied/leaked/misrouted to a DIFFERENT caller, comparing only
  // `pendingOp_.owner == t.owner` (ignoring what THIS call's actual
  // caller claims to be) would accept it regardless of which owner
  // object is actually presenting it. This match therefore requires
  // THREE independent facts to agree: the ticket is well-formed and
  // issued by this exact Store instance, this call's own `callerOwner`
  // argument equals the op's recorded owner, AND the ticket's embedded
  // `t.owner` ALSO equals it -- so a correct ticket presented by the
  // wrong owner (even copied byte-for-byte) is refused exactly like a
  // wrong ticket would be.
  bool ordinaryOpTicketMatches(OrdinaryOpKind kind, OtaSecurityOperationOwner callerOwner,
                               const OtaSecurityOperationTicket& t) const {
    return t.valid() && t.issuerInstanceEpoch == instanceEpoch_ && pendingOp_.kind == kind &&
           pendingOp_.owner == callerOwner && t.owner == callerOwner && pendingOp_.ticket == t.id;
  }
  // True if no op is in flight (free to start a fresh one) or `t` is the
  // exact ticket already holding the in-flight op of `kind` -- a
  // legitimate resume. False means "busy with something else": a
  // genuinely different op, OR ANY caller (even the op's own owner)
  // that does not present the exact matching ticket -- caller must
  // return WouldBlock without touching any state.
  bool ordinaryOpFreeOrResuming(OrdinaryOpKind kind, OtaSecurityOperationOwner callerOwner,
                                const OtaSecurityOperationTicket& t) const {
    if (pendingOp_.kind == OrdinaryOpKind::None) return true;
    return ordinaryOpTicketMatches(kind, callerOwner, t);
  }
  void clearPendingOrdinaryOp() { pendingOp_ = PendingOrdinaryOp{}; }

  // Starts a FRESH pending ordinary op for chunk 0 and mints a brand-new
  // ticket into `outTicket` (never 0, never reused -- ABA-proof against a
  // stale ticket from any earlier op). Pre-mutation capacity check covers
  // the WHOLE op (all chunkCount chunks) before any physical write -- a
  // multi-chunk transaction must never consume capacity it cannot finish
  // using. Returns false (NoCapacity, no state touched, no I/O performed,
  // `outTicket` left untouched) if there is not room for every chunk.
  bool startOrdinaryOp(OrdinaryOpKind kind, OtaSecurityOperationOwner owner, OtaSecurityRecordType type,
                       uint16_t logicalSlot, const uint8_t* payload, uint16_t payloadLen, uint32_t chunkCount,
                       uint64_t transactionLsn, OtaSecurityOperationTicket& outTicket) {
    if (nextFreeSlot_ + chunkCount > kOrdinaryCellCount) return false;
    pendingOp_.kind = kind;
    pendingOp_.ticket = nextOpTicketSeed_++;
    pendingOp_.owner = owner;
    pendingOp_.physicalIndex = nextFreeSlot_;
    pendingOp_.cellSubPhase = OrdinaryCellSubPhase::EnsureWitness;
    pendingOp_.recordType = type;
    pendingOp_.logicalSlot = logicalSlot;
    std::memcpy(pendingOp_.payload, payload, payloadLen);
    pendingOp_.payloadLen = payloadLen;
    pendingOp_.chunkIndex = 0;
    pendingOp_.chunkCount = chunkCount;
    pendingOp_.transactionLsn = transactionLsn;
    outTicket.owner = owner;
    outTicket.id = pendingOp_.ticket;
    outTicket.issuerInstanceEpoch = instanceEpoch_;
    return true;
  }

  // Drives exactly ONE bounded physical step (witness-prepare sub-step,
  // data body, data marker, witness body, or witness marker -- the same
  // exact physical calls an ordinary append has always required) of the
  // CURRENT chunk of pendingOp_, never more than one program-or-erase
  // call per invocation. On the witness marker landing durably, advances
  // nextFreeSlot_/nextLsn_ exactly once and reports Committed for THIS
  // CHUNK ONLY -- multi-chunk advancement is the caller's
  // (stepPendingOrdinaryOp's) job.
  OrdinaryOpStepOutcome stepPendingOrdinaryCell() {
    OtaSecurityAppendEngine eng = engineFor(activeBank_);
    if (pendingOp_.cellSubPhase == OrdinaryCellSubPhase::EnsureWitness) {
      OrdinaryWitnessPrepOutcome wo = stepEnsureWitnessPrepared(activeBank_, activeGeneration_);
      if (wo == OrdinaryWitnessPrepOutcome::Failed) return OrdinaryOpStepOutcome::Failed;
      if (wo == OrdinaryWitnessPrepOutcome::DoneAfterWrite) {
        // A program/erase call already happened this step (priming a
        // genuinely NEW witness sector) -- CheckAndBody's own work must
        // wait for the next call, never bundled into the same one.
        pendingOp_.cellSubPhase = OrdinaryCellSubPhase::CheckAndBody;
        return OrdinaryOpStepOutcome::InProgress;
      }
      if (wo == OrdinaryWitnessPrepOutcome::InProgress) return OrdinaryOpStepOutcome::InProgress;
      // DoneNoWrite: a pure cache-hit read, zero writes spent this step
      // -- safe to fall straight through into CheckAndBody below.
      pendingOp_.cellSubPhase = OrdinaryCellSubPhase::CheckAndBody;
    }
    if (pendingOp_.cellSubPhase == OrdinaryCellSubPhase::CheckAndBody) {
      OtaSecurityCellHeader existing;
      uint8_t existingPayload[kCellPayloadBytes];
      bool ioErr = false;
      OtaSecurityEvidence ev = eng.readCell(pendingOp_.physicalIndex, existing, existingPayload, ioErr);
      if (ev == OtaSecurityEvidence::Committed && existing.recordType == pendingOp_.recordType &&
          existing.generation == activeGeneration_ && existing.slotIndex == pendingOp_.logicalSlot) {
        // Idempotent resume: the data cell already landed in a prior
        // call. Still must (re)confirm the cross-bank witness below --
        // do NOT report Committed yet.
        pendingOp_.cellSubPhase = OrdinaryCellSubPhase::WitnessBody;
        return OrdinaryOpStepOutcome::InProgress;
      }
      OtaSecurityCellHeader header;
      header.version = 1;
      header.recordType = pendingOp_.recordType;
      header.slotIndex = pendingOp_.logicalSlot;
      header.generation = activeGeneration_;
      header.lsn = nextLsn_;
      header.payloadLength = pendingOp_.payloadLen;
      if (eng.writeCellBody(pendingOp_.physicalIndex, header, pendingOp_.payload, pendingOp_.payloadLen) !=
          OtaSecurityIoOutcome::Ok) {
        return OrdinaryOpStepOutcome::Failed;
      }
      pendingOp_.cellSubPhase = OrdinaryCellSubPhase::Marker;
      return OrdinaryOpStepOutcome::InProgress;
    }
    if (pendingOp_.cellSubPhase == OrdinaryCellSubPhase::Marker) {
      if (eng.writeCellMarker(pendingOp_.physicalIndex) != OtaSecurityIoOutcome::Ok) {
        return OrdinaryOpStepOutcome::Failed;
      }
      pendingOp_.cellSubPhase = OrdinaryCellSubPhase::WitnessBody;
      return OrdinaryOpStepOutcome::InProgress;
    }
    if (pendingOp_.cellSubPhase == OrdinaryCellSubPhase::WitnessBody) {
      uint64_t digest = 0;
      if (!cachedSnapshotDigest(activeBank_, activeGeneration_, digest)) return OrdinaryOpStepOutcome::Failed;
      uint32_t crc = eng.computeWitnessContextualCrc(storeIdentity_, digest, activeGeneration_,
                                                     (uint16_t)otherBank(activeBank_), pendingOp_.physicalIndex,
                                                     nextLsn_);
      uint64_t existingLsn = 0;
      bool witnessIoErr = false;
      OtaSecurityEvidence wev = eng.readWitnessRecord(pendingOp_.physicalIndex, crc, existingLsn, witnessIoErr);
      if (wev == OtaSecurityEvidence::Committed && existingLsn == nextLsn_) {
        // Idempotent resume: this chunk's witness already landed too.
        pendingOp_.cellSubPhase = OrdinaryCellSubPhase::EnsureWitness;
        ++nextLsn_;
        ++nextFreeSlot_;
        return OrdinaryOpStepOutcome::Committed;
      }
      if (eng.writeWitnessRecordBody(pendingOp_.physicalIndex, nextLsn_, crc) != OtaSecurityIoOutcome::Ok) {
        return OrdinaryOpStepOutcome::Failed;
      }
      pendingOp_.cellSubPhase = OrdinaryCellSubPhase::WitnessMarker;
      return OrdinaryOpStepOutcome::InProgress;
    }
    // WitnessMarker.
    if (eng.writeWitnessRecordMarker(pendingOp_.physicalIndex) != OtaSecurityIoOutcome::Ok) {
      return OrdinaryOpStepOutcome::Failed;
    }
    ++nextLsn_;
    ++nextFreeSlot_;
    pendingOp_.cellSubPhase = OrdinaryCellSubPhase::EnsureWitness;
    return OrdinaryOpStepOutcome::Committed;
  }

  // Top-level ordinary-op driver: advances the CURRENT chunk one bounded
  // step, and once it lands durably, advances to the NEXT chunk (if any
  // remain) by rebuilding that chunk's payload -- ONLY WriteLiveBinding
  // has more than one chunk; `liveBindingFullBytes` is null for every
  // other op kind. Reports the WHOLE op's outcome: InProgress/Failed as
  // reported by the current chunk, or Committed only once the LAST
  // chunk's marker has landed. On Committed or Failed the pending op is
  // cleared (and physical ownership released by the caller's guard);
  // on InProgress it is left in place for the next call to resume.
  OrdinaryOpStepOutcome stepPendingOrdinaryOp(const uint8_t* liveBindingFullBytes) {
    OrdinaryOpStepOutcome chunkOutcome = stepPendingOrdinaryCell();
    if (chunkOutcome != OrdinaryOpStepOutcome::Committed) {
      if (chunkOutcome == OrdinaryOpStepOutcome::Failed) clearPendingOrdinaryOp();
      return chunkOutcome;
    }
    if (pendingOp_.chunkIndex + 1 < pendingOp_.chunkCount) {
      ++pendingOp_.chunkIndex;
      pendingOp_.physicalIndex = nextFreeSlot_;
      uint32_t part = pendingOp_.chunkIndex;
      uint32_t off = part * kLiveBindingChunkDataBytes;
      uint32_t len = std::min<uint32_t>(kLiveBindingChunkDataBytes, kLiveBindingFixedBytes - off);
      uint8_t payload[kCellPayloadBytes] = {0};
      putU64(payload, sizeof(payload), 0, pendingOp_.transactionLsn);
      putU8(payload, sizeof(payload), 8, (uint8_t)part);
      putU8(payload, sizeof(payload), 9, (uint8_t)pendingOp_.chunkCount);
      putU16(payload, sizeof(payload), 10, (uint16_t)kLiveBindingFixedBytes);
      putBytes(payload, sizeof(payload), kLiveBindingChunkPrefixBytes, liveBindingFullBytes + off, len);
      std::memcpy(pendingOp_.payload, payload, sizeof(payload));
      pendingOp_.payloadLen = (uint16_t)(kLiveBindingChunkPrefixBytes + len);
      pendingOp_.logicalSlot = (uint16_t)part;
      pendingOp_.cellSubPhase = OrdinaryCellSubPhase::EnsureWitness;
      return OrdinaryOpStepOutcome::InProgress;  // whole op not yet complete.
    }
    clearPendingOrdinaryOp();
    return OrdinaryOpStepOutcome::Committed;
  }

  bool factoryGrantConsumed_ = false;
  OtaSecurityFactoryGrant factoryGrant_;
  bool liveBindingPresent_ = false;
  OtaSecurityLiveBinding liveBinding_;

  // Per-bank cache of the VALIDATED digest of that bank's snapshot bytes
  // for one specific generation. Sound because a (bank, generation) pair's
  // snapshot bytes are written EXACTLY ONCE, ever, by compact() (when that
  // bank becomes the destination for that generation) and never mutated
  // again until a LATER compact() re-erases+rewrites the same bank for a
  // strictly-greater generation -- at which point `generation` no longer
  // matches and the cache entry is naturally treated as a miss and
  // recomputed. This is NOT the forbidden pattern of caching MUTABLE
  // per-append TX/RX counters/LSN (that remains governed exclusively by
  // refreshIfPhysicallyStale()'s physical re-read before every CAS); the
  // snapshot bytes underlying this cache are provably immutable within a
  // generation regardless of how many Store instances are open over them.
  struct DigestCacheEntry {
    bool valid = false;
    uint32_t generation = 0;
    uint64_t digest = 0;
  };
  DigestCacheEntry digestCacheA_;
  DigestCacheEntry digestCacheB_;
  DigestCacheEntry& digestCacheFor(OtaSecurityBankId b) {
    return b == OtaSecurityBankId::A ? digestCacheA_ : digestCacheB_;
  }
  // Returns the validated digest of `bank`'s snapshot at exactly
  // `generation`, computing it (streaming, bounded-chunk) only on a cache
  // miss (first reference to this exact (bank, generation) pair since this
  // Store instance opened). Returns false on I/O failure (cache is only
  // EVER populated with a successfully-computed digest -- Sol finding #4:
  // a failed read must never be cached as if a numerically-valid digest
  // of 0 were a real, successful result).
  bool cachedSnapshotDigest(OtaSecurityBankId bank, uint32_t generation, uint64_t& outDigest);

  // Fixed-capacity, heap-free resident RX tables. Each entry retains the
  // FULL exact key (32-byte peer id / 92-byte group context -- never a
  // hash/selector, see OtaRxLedgerContext::equals()): this is required
  // both for exact-byte identity comparison (no collision aliasing) and
  // because compact() re-programs a fresh destination snapshot directly
  // from these RAM facts. A plain fixed array (vs. std::map<vector<...>>)
  // removes ALL per-entry heap/red-black-tree node overhead (~100+B/entry
  // down to the exact struct size below), a real, measured reduction
  // toward the constrained embedded RAM budget -- see the
  // ResidentFootprint tests for exact sizeof()/byte accounting. Linear
  // scan is used for lookup (bounded N<=350/4/384, not a hot loop at
  // LoRa packet rates).
  struct PeerTableEntry {
    uint8_t key[32] = {0};
    uint32_t index = 0;
    uint32_t head = 0;
    bool frozen = false;
  };
  struct CohortTableEntry {
    uint8_t key[92] = {0};
    uint32_t index = 0;
    uint32_t head = 0;
    bool frozen = false;
  };
  PeerTableEntry peerTable_[kPeerTableCapacity];
  uint32_t peerTableCount_ = 0;
  CohortTableEntry cohortTable_[kCohortTableCapacity];
  uint32_t cohortTableCount_ = 0;

  // --- STOREPLAN Priority 3: terminal-table RESIDENT footprint reduction.
  // Unlike peer/cohort (kept fully resident -- Astra's plan explicitly
  // retains full 48*350/160*4), the 384-slot terminal table is the
  // largest RAM consumer (384*96 = 36864B full rows) for data that is
  // WRITE-ONCE/append-only and never needs a hot-path full-row RAM copy:
  // every consumer (duplicate/conflict detection, compaction re-encode)
  // can re-read the authoritative bytes on demand from wherever they
  // durably live. Replace the full 96B-per-row cache with an 8B index
  // entry (384*8 = 3072B): WHERE the canonical row currently lives
  // (still-uncompacted ordinary log cell, or a fixed canonical snapshot
  // slot after a compaction has folded it in) plus a cheap 32-bit
  // fingerprint used ONLY to skip full-row re-reads for tuples that
  // provably cannot match -- never trusted alone as duplicate/conflict/
  // identity proof (a fingerprint MATCH always triggers a full on-flash
  // re-read and exact field comparison before any Committed/Conflict
  // decision is returned; ties resolve conservatively as if fingerprints
  // always collide).
  static constexpr uint16_t kTerminalLocSourceBit = 0x8000u;  // 0=snapshot-table slot, 1=ordinary-log cell.
  static constexpr uint16_t kTerminalLocIndexMask = 0x7FFFu;
  struct OtaSecurityTerminalIndexEntry {
    uint16_t location = 0;          // see kTerminalLocSourceBit/kTerminalLocIndexMask above.
    uint16_t flags = 0;             // bit0 = occupied (defensive; always true for i<terminalCount_).
    uint32_t tupleFingerprint = 0;  // CRC32(controller||campaign||session||attempt) -- AID ONLY, see above.
  };
  static_assert(sizeof(OtaSecurityTerminalIndexEntry) == kTerminalIndexEntryBytes,
                "public kTerminalIndexEntryBytes must track this private struct's real size exactly");
  OtaSecurityTerminalIndexEntry terminalIndex_[kTerminalTableCapacity];
  uint32_t terminalCount_ = 0;

  // --- Bounded terminal fingerprint-collision scan (see admitTerminalAttempt) ---
  // The RAM-only fingerprint prefilter below costs zero flash bytes per
  // candidate it REJECTS (kTerminalTableCapacity=384 cheap uint32 compares
  // is not a physical-I/O budget concern); the only physical reads it can
  // ever issue are the ones in readTerminalRow() below, one per actual
  // fingerprint MATCH. A real match should resolve the request (duplicate
  // or Conflict) on the SAME call almost always. To keep a worst-case
  // adversarial run of colliding fingerprints (fingerprint is a truncated
  // CRC32 AID, not a proof, so engineered collisions are possible) from
  // issuing more than kTerminalCollisionReadsPerCall physical row reads
  // within one public call, the scan retains its index and resumes on the
  // next call instead of draining further matches inline.
  static constexpr uint32_t kTerminalCollisionReadsPerCall = 1;
  uint32_t terminalScanResumeIndex_ = 0;  // RAM-only; next table index to resume the collision scan from.
  OtaSecurityOperationTicket terminalScanTicket_;  // owns an in-progress (unresolved) collision scan, if any.
  uint8_t terminalScanPayload_[kTerminalEntryBytes] = {0};  // encoded candidate the in-progress scan belongs to.

  static uint32_t computeTerminalTupleFingerprint(const uint8_t controller[32], uint32_t campaign,
                                                   uint32_t session, uint16_t attempt) {
    uint8_t buf[32 + 4 + 4 + 2];
    std::memcpy(buf, controller, 32);
    buf[32] = (uint8_t)(campaign >> 24);
    buf[33] = (uint8_t)(campaign >> 16);
    buf[34] = (uint8_t)(campaign >> 8);
    buf[35] = (uint8_t)(campaign);
    buf[36] = (uint8_t)(session >> 24);
    buf[37] = (uint8_t)(session >> 16);
    buf[38] = (uint8_t)(session >> 8);
    buf[39] = (uint8_t)(session);
    buf[40] = (uint8_t)(attempt >> 8);
    buf[41] = (uint8_t)(attempt);
    return ::ota::storage::Crc32::computeFinalized(buf, sizeof(buf));
  }

  // Re-reads the FULL 96-byte canonical row this index entry currently
  // points at, from wherever it durably lives (still-uncompacted ordinary
  // log cell on the active bank, or the active bank's canonical snapshot
  // table slot). Returns false (and the caller must freeze/Uncertain,
  // never silently drop/skip -- same "occupied row read failure" policy
  // as the peer/cohort/terminal snapshot-replay loops) on ANY I/O or
  // decode failure.
  bool readTerminalRow(const OtaSecurityTerminalIndexEntry& idx, OtaSecurityTerminalEntry& out) {
    uint32_t physIndex = (uint32_t)(idx.location & kTerminalLocIndexMask);
    if ((idx.location & kTerminalLocSourceBit) == 0) {
      uint8_t raw[kTerminalEntryBytes];
      if (!::ota::platform::isOk(
              carve(activeBank_).snapshot().read(kTerminalTableOffset + physIndex * kTerminalEntryBytes, raw,
                                                 sizeof(raw)))) {
        return false;
      }
      return OtaSecurityTerminalEntryCodec::decode(raw, sizeof(raw), out);
    }
    OtaSecurityAppendEngine eng = engineFor(activeBank_);
    OtaSecurityCellHeader header;
    uint8_t payload[kCellPayloadBytes];
    bool ioErr = false;
    OtaSecurityEvidence ev = eng.readCell(physIndex, header, payload, ioErr);
    if (ioErr || ev != OtaSecurityEvidence::Committed) return false;
    return OtaSecurityTerminalEntryCodec::decode(payload, sizeof(payload), out);
  }

  PeerTableEntry* findPeer(const uint8_t key[32]) {
    for (uint32_t i = 0; i < peerTableCount_; ++i) {
      if (std::memcmp(peerTable_[i].key, key, 32) == 0) return &peerTable_[i];
    }
    return nullptr;
  }
  CohortTableEntry* findCohort(const uint8_t key[92]) {
    for (uint32_t i = 0; i < cohortTableCount_; ++i) {
      if (std::memcmp(cohortTable_[i].key, key, 92) == 0) return &cohortTable_[i];
    }
    return nullptr;
  }

  OtaSecurityTailCarve& carve(OtaSecurityBankId b) { return b == OtaSecurityBankId::A ? carveA_ : carveB_; }
  OtaSecurityAppendEngine engineFor(OtaSecurityBankId b) {
    OtaSecurityTailCarve& own = carve(b);
    OtaSecurityTailCarve& opp = carve(otherBank(b));
    return OtaSecurityAppendEngine(own.dataLog(), opp.witness(), b);
  }

  // Writes the reserved seal (254) or switch (255) cell for `bank` at its
  // current active generation. NOTE: unlike an ordinary-log append, this is
  // NOT cross-bank witnessed -- the witness sector has exactly
  // kOrdinaryCellCount (254) slots, one per ordinary index, with no slot
  // for either reserved index. Durability here rests on the same-bank
  // two-phase body+marker commit (each phase individually program+readback
  // verified) plus, for the switch record specifically, cross-validation
  // against the destination bank's own already-verified snapshot digest
  // baked into its payload. This is a deliberate, narrower fault-coverage
  // boundary than ordinary records and is called out explicitly in the
  // final report.
  OtaSequenceBackingResult appendReservedRecord(OtaSecurityBankId bank, uint32_t physicalIndex,
                                               OtaSecurityRecordType type, uint32_t generation, const uint8_t* payload,
                                               uint16_t payloadLen);

  void resetReconstructedState();
  bool decodeSnapshotHeader(OtaSecurityBankId bank, OtaSecuritySnapshotHeader& out);

  // Phase A of reconstruct()'s eventual resumable migration (per the
  // phased-migration contract): header-decode + witness-claim + bank/
  // generation selection + final-digest-verify. NOT <=1024B/O(1) bounded:
  // checkWitnessAttestsBank -> cachedSnapshotDigest -> computeSnapshotDigest
  // performs a full kSnapshotSizeBytes (64 KiB) re-hash per candidate bank
  // whose digest cache is cold, up to 128 KiB total for both banks -- this
  // is the exact pre-existing cost the old inline reconstruct() code always
  // paid (this extraction, below, is a byte-for-byte behavior-preserving
  // move, not a reduction). It IS independent of table/log row count
  // (peer/cohort/terminal/log population never changes this cost), but
  // that is a narrower property than per-step boundedness. The genuinely
  // bounded, resumable re-implementation is stepResolveActivePhysicalState()
  // + BankEvidenceCursor below; this synchronous version remains a
  // TEST-REFERENCE-ONLY equivalence oracle (still reconstruct()'s actual
  // production path today) until a later slice replaces its call site, per
  // the phased-migration contract's explicit "temporary legacy gate, not a
  // production acceptance" allowance. `out` carries the phase's otherwise-
  // local results (the chosen bank's re-decoded header, its verified
  // digest, and whether its witness attestation passed) that the next
  // phase (snapshot-fold) needs.
  struct ReconstructPhaseAResult {
    OtaSecuritySnapshotHeader activeHdr{};
    uint64_t activeDigest = 0;
    bool witnessHeaderValid = false;
  };
  void resolveActivePhysicalState(ReconstructPhaseAResult& out);

  // --- Bounded/resumable re-implementation of Phase A ---------------------
  // See the phased-migration contract: Idle -> ObserveHeadersAndClaims ->
  // DigestA -> DigestB -> Select -> Recheck -> Done/Failed. Every step
  // performs at most one min(remaining,1024)-byte read (Observe/Recheck:
  // exactly 2*kHeaderEncodedBytes + 2*kWitnessHeaderBytes = 576 bytes in
  // one call; DigestA/DigestB: exactly one <=1024B snapshot chunk read per
  // call, 64 calls per 65536-byte bank; Select: zero I/O, a pure decision
  // over already-captured evidence). NOT YET wired into reconstruct() or
  // any production call path -- this slice is new, independently testable
  // infrastructure only (see stepResolveActivePhysicalState()'s own doc
  // comment and the test suite's friend-accessor drive helper).
  enum class BankEvidencePhase : uint8_t {
    Idle, ObserveHeadersAndClaims, DigestA, DigestB, Select, Recheck, Done, Failed
  };
  // Explicit classification of a captured raw header buffer -- decode()
  // returning false alone cannot tell a genuinely-never-written (blank,
  // all-0xFF) header apart from a corrupted one; collapsing both into a
  // single "false" (as the legacy decodeSnapshotHeader()/magicX booleans
  // still do) would let a truly-damaged header be silently treated as
  // ordinary, not-yet-written virgin state.
  enum class HeaderReadStatus : uint8_t { Erased, Decoded, Malformed, IoError };
  enum class BankEvidenceStepOutcome : uint8_t { Pending, Ready, Failed, OwnershipDenied };

  struct BankEvidenceCursor {
    BankEvidencePhase phase = BankEvidencePhase::Idle;
    OtaSecurityOperationOwner owner = nullptr;
    uint64_t ticketId = 0;
    uint64_t issuerInstanceEpoch = 0;

    // Observe phase's captured raw bytes -- exactly the 576 bytes read in
    // that one call, reused (never re-hashed) by Select/Recheck.
    uint8_t rawHeaderA[kHeaderEncodedBytes] = {0};
    uint8_t rawHeaderB[kHeaderEncodedBytes] = {0};
    bool headerIoErrorA = false;
    bool headerIoErrorB = false;
    uint8_t rawWitnessForA[kWitnessHeaderBytes] = {0};  // lives physically in bank B, attests bank A.
    uint8_t rawWitnessForB[kWitnessHeaderBytes] = {0};  // lives physically in bank A, attests bank B.
    bool witnessIoErrorForA = false;
    bool witnessIoErrorForB = false;

    // DigestA/DigestB's resumable scan state -- ONE reusable hasher, never
    // two concurrently, a read scratch no larger than one chunk, and a
    // plain byte offset cursor; no per-chunk history retained.
    ::ota::trust::Sha256 sha{};
    uint32_t digestOffset = 0;
    bool digestIoError = false;
    uint64_t digestA = 0;
    uint64_t digestB = 0;

    // Select's provisional (not-yet-durable-to-members) decision, applied
    // to the real activeBank_/activeGeneration_/activeSnapshotValid_/
    // storeFrozen_ members only once Recheck confirms the evidence it was
    // computed from is still exactly byte-identical.
    OtaSecurityBankId provisionalActiveBank = OtaSecurityBankId::A;
    uint32_t provisionalActiveGeneration = 1;
    bool provisionalActiveSnapshotValid = false;
    bool provisionalStoreFrozen = false;
    bool provisionalWitnessHeaderValid = false;
    ReconstructPhaseAResult provisional{};
  };
  BankEvidenceCursor bankEvidenceCursor_;

  // Drives exactly one bounded step. `owner`/`ticket` follow the same
  // ABA-proof resume contract as the ordinary-mutation ops (see
  // OtaSecurityOperationTicket's doc comment): a fresh cycle is started
  // with a default-constructed (invalid) ticket while the cursor is Idle;
  // every subsequent call MUST present the EXACT ticket minted on that
  // first call, or it is refused (OwnershipDenied) without touching any
  // state -- never a silent restart, never a foreign caller's progress.
  // Never disturbs an already in-flight ordinary mutation or compaction
  // (both must independently finish or be cancelled first). `out` is
  // populated ONLY when this call returns Ready; it is left untouched on
  // Pending/Failed/OwnershipDenied (never a stale/partial value that could
  // be mistaken for a real result).
  BankEvidenceStepOutcome stepResolveActivePhysicalState(OtaSecurityOperationOwner owner,
                                                        OtaSecurityOperationTicket& ticket,
                                                        ReconstructPhaseAResult& out);
  // Releases the cursor/lease only -- never touches flash, never alters
  // activeBank_/activeGeneration_/activeSnapshotValid_/storeFrozen_ (those
  // are only ever written at Done, which this never reaches). A foreign/
  // stale ticket is a silent no-op (nothing of that caller's was ever
  // actually held).
  void cancelBankEvidenceCursor(const OtaSecurityOperationTicket& ticket);

  // --- SLICE2: bounded/resumable snapshot-fold cursor ---------------------
  // ROOT's staged-conversion contract (SLICE2, "snapshot fold cursor
  // only"): an OUTER cursor that drives Phase A (the SAME bounded
  // BankEvidenceCursor above, via its own internal ticket -- one external
  // caller's ReconstructCursor keeps continuous logical ownership from
  // PhaseA through every fold phase; Phase A completing is NOT "store
  // ready") and then folds the chosen bank's validated snapshot into the
  // EXISTING fixed-size tables (peerTable_/cohortTable_/terminalIndex_/
  // liveBinding_) IN PLACE -- no second shadow table -- one occupied row
  // per call (peer 48B, cohort 160B, terminal INDEX 96B source row, live-
  // binding 4*1024B chunks of the 4096B area), PLUS (SLICE3) the reserved
  // seal(254)/switch(255) LSN-safety cells and the 254-slot ordinary log
  // replay, one physical pair (128B data + 16B witness = 144B) per call.
  // Still NOT wired into reconstruct() or any production call path
  // (SLICE4) -- new, independently testable infrastructure only, exactly
  // like stepResolveActivePhysicalState() before it.
  enum class ReconstructPhase : uint8_t {
    Idle, PhaseA, HeaderFields, Peers, Cohorts, Terminals, LiveBinding, ReservedCells, OrdinaryLog, Finalize, Done,
    Failed
  };
  // Reuses BankEvidenceStepOutcome's exact 4-value shape (Pending/Ready/
  // Failed/OwnershipDenied) -- a separate alias purely for call-site
  // clarity, not a different contract.
  using ReconstructStepOutcome = BankEvidenceStepOutcome;

  // Bounded, fixed-size (NOT std::map<uint64_t, ...>) accumulator for the
  // ordinary log's bounded, fixed-count LiveBinding multi-cell
  // transaction: only the HIGHEST touched transaction LSN is ever
  // consulted (a strictly-higher txLsn discards never-to-be-read older
  // partial evidence; an equal txLsn accumulates; a strictly-lower txLsn
  // is ignored), so one resident instance is the exact bounded
  // replacement for a per-transaction history map. Shared by name
  // between the legacy reconstruct()'s own local variable and SLICE3's
  // retained ReconstructCursor field, both folded via the SAME
  // foldConfirmedOrdinaryCellRecord() helper below -- never two
  // divergent copies of this same assembly logic.
  struct OtaSecurityLiveBindingLogEvidence {
    bool have[kLiveBindingChunkCount] = {false};
    uint8_t bytes[kLiveBindingChunkCount][kLiveBindingChunkDataBytes] = {{0}};
    uint16_t totalLength = 0;
  };

  // Pure fold of one CONFIRMED (witness-corroborated) ordinary-log
  // record's counter/table/live-binding-evidence effects, taking an
  // already-classified header+payload+physical position. Shared, by
  // direct call, between legacy reconstruct()'s full cold replay and
  // SLICE3's bounded OrdinaryLog cursor phase below -- SLICE3's explicit
  // "extract one pure fold function... avoid divergent semantic copies"
  // requirement. Touches shared Store members (txUpperBound_/peerTable_/
  // cohortTable_/terminalIndex_/factoryGrant_/*Count_/storeFrozen_)
  // directly (both call sites operate on the SAME single Store instance
  // mid-reconstruction); `txAmbiguous`/`liveEv`/`highestLiveTxLsn`/
  // `haveLiveTx` are passed by reference since the two call sites retain
  // them in different places (legacy: local scan variables; cursor:
  // ReconstructCursor fields) but must observe identical semantics.
  void foldConfirmedOrdinaryCellRecord(const OtaSecurityCellHeader& header, const uint8_t* payload, uint32_t pos,
                                       bool& txAmbiguous, OtaSecurityLiveBindingLogEvidence& liveEv,
                                       uint64_t& highestLiveTxLsn, bool& haveLiveTx);
  // Pure fold of one ATTRIBUTABLE-BUT-UNCONFIRMED (BodyOnly/mismatched-
  // witness) ordinary-log record: marks the specific context it names as
  // frozen (never evicted/aliased), or -- for whole-store-scoped kinds --
  // freezes storeFrozen_ directly. Same sharing rationale as
  // foldConfirmedOrdinaryCellRecord() above.
  void foldAmbiguousOrdinaryCellRecord(const OtaSecurityCellHeader& header, const uint8_t* payload,
                                       bool& txAmbiguous, bool& liveBindingTxAmbiguous);

  struct ReconstructCursor {
    ReconstructPhase phase = ReconstructPhase::Idle;
    OtaSecurityOperationOwner owner = nullptr;
    uint64_t ticketId = 0;
    uint64_t issuerInstanceEpoch = 0;

    // Internal ticket this SAME cursor uses to drive the shared, single
    // bankEvidenceCursor_ through its own Idle->...->Done cycle. Opaque to
    // callers of stepReconstruct(); never exposed, never substitutable.
    OtaSecurityOperationTicket phaseATicket{};
    ReconstructPhaseAResult phaseAResult{};
    // Pure-memory fold baseline captured once, at HeaderFields, from the
    // Phase-A-validated snapshot header -- zero I/O, gated on
    // witnessHeaderValid exactly like the legacy reconstruct().
    uint32_t txBaseline = 0;

    // One-row-per-call indices into the chosen bank's snapshot tables.
    uint32_t peerIndex = 0;
    uint32_t cohortIndex = 0;
    uint32_t terminalIndex = 0;
    // LiveBinding's 4*1024B retained scratch -- satisfies
    // OtaSecurityLiveBindingCodec::decode()'s `rawLen>=kLiveBindingAreaBytes`
    // requirement (it needs a full 4096B buffer even though it only
    // interprets a ~916B prefix) without ever reading more than 1024B of
    // NEW flash bytes in any single call.
    uint32_t liveBindingChunkIndex = 0;
    uint8_t liveBindingScratch[kLiveBindingAreaBytes] = {0};

    // --- SLICE3: reserved seal(254)/switch(255) + 254-slot ordinary log
    // replay, folded one physical unit per call on this SAME retained
    // owner/lease. -----------------------------------------------------
    // 0 = seal cell step pending, 1 = switch cell step pending, 2 = both done.
    uint32_t reservedIdx = 0;
    // The seal cell's own evidence/header, captured once during the
    // ReservedCells phase and reused (zero extra I/O) by Finalize's
    // pending-seal-resume detection below -- mirrors the legacy
    // reconstruct()'s separate re-read of the SAME cell exactly, but only
    // reads it once total across this whole cursor cycle.
    OtaSecurityCellHeader sealHeader{};
    OtaSecurityEvidence sealEvidence = OtaSecurityEvidence::AbsentBytes;
    // One physical log position (0..kOrdinaryCellCount-1) folded per call.
    uint32_t logPos = 0;
    bool txAmbiguous = false;
    // Highest physical position carrying ANY attributable (confirmed OR
    // ambiguous/BodyOnly) record -- nextFreeSlot_ must never reuse this
    // physical slot even when the record there is ambiguous, exactly
    // like a confirmed one; tracking only CONFIRMED positions would let
    // a confirmed-but-lower slot "hide" a higher ambiguous slot's
    // physical occupancy and silently reuse/overwrite its LSN.
    bool anyAttributable = false;
    uint32_t highestAttributablePosition = 0;
    // Bounded, fixed-size (NOT std::map<uint64_t, ...>) accumulator for
    // the log's bounded, fixed-count LiveBinding transaction chunks --
    // only the highest touched transaction LSN is ever consulted, so one
    // resident slot (reset whenever a strictly-higher txLsn is first
    // seen) is the exact bounded replacement; see foldConfirmedOrdinaryCellRecord().
    OtaSecurityLiveBindingLogEvidence logLiveEvidence{};
    uint64_t highestLiveBindingTxLsn = 0;
    bool haveLiveBindingTx = false;
    bool liveBindingTxAmbiguous = false;
  };
  ReconstructCursor reconstructCursor_;
  // SLICE4: persistent ticket for the INTERNAL, self-owned (owner == this)
  // bounded rebuild driven one step per refreshIfPhysicallyStale() call --
  // replaces the old unbounded synchronous reconstruct() fallback on the
  // foreign-change path. Valid only while that internal rebuild is
  // mid-flight; reset to a fresh (invalid) ticket once it reaches a
  // terminal outcome.
  OtaSecurityOperationTicket rebuildTicket_;
  // Readiness gate: stays false for the ENTIRE fold (even though
  // peerTable_/cohortTable_/terminalIndex_/liveBinding_ are being written
  // in place as each row completes) until Finalize/Done -- "keep counts
  // unpublished... until Finalize" per the SLICE2 contract. Not yet
  // consulted by any public accessor (that wiring is SLICE4); maintained
  // now so SLICE4 has a real, already-correct flag to gate on.
  bool reconstructFoldReady_ = false;

  // Drives exactly one bounded step of the whole cold-reconstruction fold
  // (Phase A + header/peer/cohort/terminal/live-binding fold). Same ABA-
  // proof ticket-resume contract as stepResolveActivePhysicalState(): a
  // fresh cycle starts from an invalid ticket while Idle; every resuming
  // call must present the EXACT minted ticket or is refused
  // (OwnershipDenied) without touching any state. Refuses to start while
  // an ordinary mutation/compaction is in flight, OR while the shared
  // bankEvidenceCursor_ is already held by an independent, directly-
  // driven Phase-A-only caller (a real, serialized shared-resource
  // conflict, not a silent steal).
  ReconstructStepOutcome stepReconstruct(OtaSecurityOperationOwner owner, OtaSecurityOperationTicket& ticket);
  // Releases the cursor/lease only -- never touches flash, never
  // alters peerTable_/cohortTable_/terminalIndex_/liveBinding_/
  // reconstructFoldReady_ beyond whatever rows were already folded in
  // place (those remain, but reconstructFoldReady_ stays false, so they
  // are not yet published as readable facts). A foreign/stale ticket is a
  // silent no-op.
  void cancelReconstructCursor(const OtaSecurityOperationTicket& ticket);

  // Returns false on ANY flash I/O failure (never a fabricated 0 digest
  // treated as success -- Sol finding #4: a read failure must propagate
  // as an explicit failure, never as a numerically-valid-looking digest
  // that a caller could go on to cache/compare as if it were real).
  bool computeSnapshotDigest(OtaSecurityBankId bank, uint64_t& outDigest);
  // Returns true only if the witness sector OPPOSITE `bank` attests
  // `bank`'s CURRENT, exact, byte-for-byte snapshot digest at `generation`
  // -- i.e. a fully proven (not merely magic-valid) snapshot. Used both to
  // select which bank is active on cold reconstruct() (Sol finding #3)
  // and to gate the ordinary-log confirmation loop (shared with finding
  // #2's snapshot-baseline integrity gate).
  bool checkWitnessAttestsBank(OtaSecurityBankId bank, uint32_t generation, uint64_t& outDigest);
  bool witnessPreparedForGeneration(OtaSecurityBankId bank, uint32_t generation);
  // Returns the witness sector OPPOSITE `bank`'s claim about `bank`'s
  // protection generation, as a TYPED tri-state -- never collapsing
  // "genuinely never written" and "cannot currently be read" into the
  // same boolean, which would let an ambiguous read be silently treated
  // as "no claim" (Sol H2): Present (and the REAL claimed generation, via
  // `outGeneration`) if the witness sector is Committed and structurally
  // bound to this exact store/bank; Absent if it is genuinely blank
  // (AbsentBytes) or Committed but bound to a DIFFERENT store/bank (a
  // real, unambiguous "not a claim for this bank" fact, not a read
  // failure); Error for every other evidence class (BodyOnly/Unprovable/
  // IoError) -- a genuinely UNKNOWN claim that must never be treated as
  // "no claim exists" by any caller, per Sol finding #2/H2.
  enum class WitnessGenerationClaim : uint8_t { Present, Absent, Error };
  WitnessGenerationClaim witnessClaimedGeneration(OtaSecurityBankId bank, uint32_t& outGeneration);
  // Zero-I/O counterparts of witnessClaimedGeneration()/witnessPreparedForGeneration()/
  // checkWitnessAttestsBank() operating on an already-captured raw witness
  // buffer (see BankEvidenceCursor's Select phase) instead of performing
  // their own flash read.
  WitnessGenerationClaim pureWitnessClaimedGeneration(OtaSecurityBankId protectedBank, const uint8_t* rawWitness,
                                                      bool witnessIoError, OtaSecurityWitnessSectorHeader& outHeader,
                                                      uint32_t& outGeneration) const;
  bool pureWitnessPreparedForGeneration(OtaSecurityBankId protectedBank, uint32_t generation,
                                       const OtaSecurityWitnessSectorHeader& header, WitnessGenerationClaim claim) const;
  bool pureCheckWitnessAttestsBank(OtaSecurityBankId protectedBank, uint32_t generation, uint64_t freshDigest,
                                  const OtaSecurityWitnessSectorHeader& header, WitnessGenerationClaim claim) const;
  // Cheap, physical re-verification used immediately before every CAS
  // mutation (reserveTx / advanceRx / commissionVirginTx / commissionVirginRx
  // / commissionFactoryGrant / writeLiveBinding / admitTerminalAttempt) AND
  // before every plain counter read (readTxCounter / readRxCounter):
  // closes the cross-instance race where two independently-opened Store
  // instances over the SAME physical bytes could otherwise both believe
  // they won an identical CAS, or a reader could otherwise return a
  // stale cached value after a foreign writer's commit (Sol finding #1).
  //
  // Per-call cost is BOUNDED: a genuine foreign write is first tried via
  // tryApplyForeignOrdinaryCellIncrementally() (one cell + one witness
  // read, well under the approved per-step byte/op budget); only the two
  // genuinely rare, harder cases -- a real bank/generation compaction
  // switch, or an ordinary record type that single-cell helper
  // deliberately does not cover (see its own doc comment) -- fall back to
  // the full, unbounded reconstruct(). Returning `CaughtUpOneStep` tells
  // every caller "state moved by exactly one bounded step just now; return
  // WouldBlock and let the caller retry" rather than proceeding to compare
  // against not-yet-fully-fresh state. Returning `Uncertain` (Sol H2) means
  // the opposite bank's witness generation claim could not be determined
  // at all (a genuine read fault, distinct from a genuinely-blank claim) --
  // this is deliberately NOT escalated to a full reconstruct() (which would
  // blow the per-step byte/op budget hiding an expensive retry behind a
  // transient fault); the caller must fail closed (Uncertain/false) for
  // THIS step and may retry fresh on a later call.
  enum class RefreshOutcome : uint8_t { AlreadyFresh, CaughtUpOneStep, Uncertain };
  RefreshOutcome refreshIfPhysicallyStale();

  // Tries to fold EXACTLY ONE foreign-written, witness-confirmed ordinary
  // cell at `pos` directly into the live RAM structures (txUpperBound_/
  // peerTable_/cohortTable_/terminalIndex_/factoryGrant_) without the
  // full reconstruct()'s from-scratch re-derivation -- bounded to one
  // ~128B cell read + one ~32B witness-record read (well under the
  // approved per-step budget), zero program/erase calls.
  //
  // Deliberately, honestly scoped to only the "simple", single-cell,
  // non-chunked record types (TxReservation/RxPeerAdvance/RxGroupAdvance/
  // TerminalAttempt/FactoryGrantRecord) that ALREADY confirm cleanly
  // against the witness on the first try; LiveBindingChunk (needs
  // cross-chunk assembly state this single-cell helper does not carry),
  // any non-Committed/unconfirmed evidence, and any genuine table-
  // capacity overflow instead return NeedsFullReconstruct so the caller
  // falls back to the existing, unbounded reconstruct() path -- this
  // remaining gap is explicit, not silently hidden.
  enum class OrdinaryCellCatchupOutcome : uint8_t { NoForeignCell, Applied, NeedsFullReconstruct };
  OrdinaryCellCatchupOutcome tryApplyForeignOrdinaryCellIncrementally(uint32_t pos);

  // Bounded, read-only refresh used by every plain counter/state read
  // (readTxCounter/readRxCounter/openExistingTx/openExistingRx): acquires
  // physical partition ownership for exactly ONE step, refreshes if
  // physically stale, then releases ownership immediately -- a read
  // never needs to hold the lease across multiple steps since nothing of
  // its own is "in flight" (the "physical bus released between steps"
  // principle applies to reads too). Returns `Retry` when the caller
  // must return WouldBlock right now without reading the cached value:
  // either a FOREIGN owner currently holds the partition, or a bounded
  // single-cell catch-up step was just performed and the view may still
  // not be fully fresh (more foreign cells may remain). Returns
  // `Unknown` (Sol H2) when the opposite bank's witness generation claim
  // genuinely could not be determined (a real read fault, not mere
  // absence) -- the caller must return Uncertain, never silently proceed
  // to read a cached value that might already be stale relative to an
  // undetectable foreign compaction. Returns `ProceedFresh` when it is
  // safe to proceed to read the now-verified-fresh cached value. An own
  // in-flight ordinary op is left completely undisturbed (matches
  // refreshIfPhysicallyStale()'s own resume-skip rule).
  enum class BoundedReadRefreshOutcome : uint8_t { ProceedFresh, Retry, Unknown };
  BoundedReadRefreshOutcome refreshForBoundedReadNeedsRetry() {
    if (hasPendingOrdinaryOperation()) return BoundedReadRefreshOutcome::ProceedFresh;
    if (!acquirePartitionOwnership()) return BoundedReadRefreshOutcome::Retry;
    RefreshOutcome outcome = refreshIfPhysicallyStale();
    releasePartitionOwnership();
    if (outcome == RefreshOutcome::Uncertain) return BoundedReadRefreshOutcome::Unknown;
    if (outcome == RefreshOutcome::CaughtUpOneStep) return BoundedReadRefreshOutcome::Retry;
    return BoundedReadRefreshOutcome::ProceedFresh;
  }

  // Programs exactly ONE physical-NOR-page-bounded slice of a small
  // (<=256B) row at `rowAddr`, resuming from compactionRowByteOffset_
  // across calls so a row whose absolute address range straddles a 256B
  // physical page (peer/cohort/terminal entry bases are NOT generally
  // page-aligned) never costs more than one physical page program per
  // compactStep() call. Readback/verify for the row happens separately
  // in ReadbackVerifyDestSnapshot (unaffected by this slicing -- NOR
  // reads are not page-constrained). Returns true once the row is fully
  // programmed (resets the offset back to 0 for the next row); false
  // means more slices remain and the caller MUST return WouldBlock
  // WITHOUT advancing its unit cursor. `ok` is set false on any program
  // I/O failure (caller must freeze exactly like the old single-call path).
  bool programRowSliceAndAdvance(::ota::platform::FlashRegion& dest, uint32_t rowAddr, const uint8_t* rowBytes,
                                 uint32_t rowLen, bool& ok) {
    uint32_t addr = rowAddr + compactionRowByteOffset_;
    uint32_t remaining = rowLen - compactionRowByteOffset_;
    uint32_t n = std::min<uint32_t>(remaining, 256u - (addr % 256u));
    if (!::ota::platform::isOk(dest.program(addr, rowBytes + compactionRowByteOffset_, n))) {
      ok = false;
      return false;
    }
    ok = true;
    compactionRowByteOffset_ += n;
    if (compactionRowByteOffset_ >= rowLen) {
      compactionRowByteOffset_ = 0;
      return true;
    }
    return false;
  }

  // Bounded per-service-step snapshot write/readback-verify layout: maps
  // a single flat "unit" cursor (0 = header; then one unit per occupied
  // peer/cohort/terminal table entry; then one unit per bounded
  // live-binding-area chunk) so compactStep() can process EXACTLY ONE
  // unit per call during WriteDestSnapshot/ReadbackVerifyDestSnapshot,
  // instead of programming/reading the entire populated snapshot in one
  // service step.
  struct SnapshotUnitLayout {
    uint32_t peerBase;
    uint32_t cohortBase;
    uint32_t terminalBase;
    uint32_t liveBase;
    uint32_t totalUnits;
  };
  SnapshotUnitLayout computeSnapshotUnitLayout() const {
    SnapshotUnitLayout layout;
    layout.peerBase = 1;  // unit 0 is always the header.
    layout.cohortBase = layout.peerBase + peerTableCount_;
    layout.terminalBase = layout.cohortBase + cohortTableCount_;
    layout.liveBase = layout.terminalBase + terminalCount_;
    layout.totalUnits = layout.liveBase + (liveBindingPresent_ ? kLiveBindingAreaWriteChunkCount : 0u);
    return layout;
  }

  // Same-bank-only two-phase commit (no opposite-bank witness step) used
  // exclusively for the reserved seal/switch cells -- see
  // appendReservedRecord()'s comment above.
  OtaSequenceBackingResult writeCellOnly(OtaSecurityBankId bank, uint32_t physicalIndex, OtaSecurityCellHeader header,
                                        const uint8_t* payload, uint16_t payloadLen);
};


inline void OtaSecurityStore::resetReconstructedState() {
  storeFrozen_ = false;
  txFrozen_ = false;
  txOpened_ = false;
  txUpperBound_ = 0;
  nextFreeSlot_ = 0;
  nextLsn_ = 1;
  activeSnapshotValid_ = false;
  factoryGrantConsumed_ = false;
  factoryGrant_ = OtaSecurityFactoryGrant();
  liveBindingPresent_ = false;
  liveBinding_ = OtaSecurityLiveBinding();
  peerTableCount_ = 0;
  cohortTableCount_ = 0;
  terminalCount_ = 0;
  // A cold reconstruct invalidates ANY in-progress terminal
  // collision-scan's premise (the very table it was scanning is being
  // rebuilt from physical truth): burn it, same as every other RAM-only
  // provisional fact discarded here.
  terminalScanTicket_ = OtaSecurityOperationTicket{};
  terminalScanResumeIndex_ = 0;
  // Invalidate the per-bank validated-digest cache on every reconstruct():
  // reconstruct()'s entire purpose is to trust NOTHING residual in RAM,
  // and a stale cache entry is exactly such residual state -- without
  // this, a same-instance reconstruct() called after externally-injected
  // flash corruption (e.g. a fault-injection test byte-flipping an
  // already-committed snapshot) would keep reporting the OLD, pre-
  // corruption digest as if it were freshly, successfully re-verified
  // (Sol finding #4).
  digestCacheA_ = DigestCacheEntry();
  digestCacheB_ = DigestCacheEntry();
}

inline bool OtaSecurityStore::decodeSnapshotHeader(OtaSecurityBankId bank, OtaSecuritySnapshotHeader& out) {
  uint8_t raw[kHeaderEncodedBytes];
  ::ota::platform::FlashStatus st = carve(bank).snapshot().read(kHeaderAreaOffset, raw, sizeof(raw));
  if (!::ota::platform::isOk(st)) return false;
  return OtaSecuritySnapshotHeaderCodec::decode(raw, sizeof(raw), out);
}

// Truncated (8-byte) SHA-256 digest over the bank's entire currently-
// programmed snapshot bytes -- used purely to bind witness sectors/switch
// records to "this exact snapshot", never as a substitute for the CRCs
// already protecting each individual record.
//
// Streams the 64 KiB snapshot region through a small, bounded, ON-STACK
// chunk buffer (kDigestChunkBytes) into ota::trust::Sha256's incremental
// update(), rather than materializing the entire region in one 64 KiB
// heap vector -- Sha256 is already a streaming/blockwise hasher, so no
// correctness is lost by feeding it in pieces. This is the ONLY place raw
// snapshot bytes are re-read+hashed from flash; callers on the hot
// per-append path must go through cachedSnapshotDigest() instead so this
// (relatively expensive, whole-region) computation happens at most once
// per (bank, generation) pair for the lifetime of this Store instance.
inline bool OtaSecurityStore::computeSnapshotDigest(OtaSecurityBankId bank, uint64_t& outDigest) {
  constexpr uint32_t kDigestChunkBytes = 1024u;
  uint8_t chunk[kDigestChunkBytes];
  ::ota::platform::FlashRegion& region = carve(bank).snapshot();
  ::ota::trust::Sha256 sha;
  sha.reset();
  for (uint32_t off = 0; off < kSnapshotSizeBytes; off += kDigestChunkBytes) {
    uint32_t len = kSnapshotSizeBytes - off < kDigestChunkBytes ? (kSnapshotSizeBytes - off) : kDigestChunkBytes;
    if (!::ota::platform::isOk(region.read(off, chunk, len))) return false;
    sha.update(chunk, len);
  }
  uint8_t digest[32];
  sha.finish(digest);
  uint64_t out = 0;
  for (int i = 0; i < 8; ++i) out = (out << 8) | digest[i];
  outDigest = out;
  return true;
}

inline bool OtaSecurityStore::cachedSnapshotDigest(OtaSecurityBankId bank, uint32_t generation, uint64_t& outDigest) {
  DigestCacheEntry& cache = digestCacheFor(bank);
  if (cache.valid && cache.generation == generation) {
    outDigest = cache.digest;
    return true;
  }
  uint64_t digest = 0;
  if (!computeSnapshotDigest(bank, digest)) return false;  // I/O failure: never cached, never treated as success.
  cache.valid = true;
  cache.generation = generation;
  cache.digest = digest;
  outDigest = digest;
  return true;
}

// Returns true only if the witness sector OPPOSITE `bank` has actually
// been PREPARED (two-phase committed) for `bank` at exactly `generation`
// -- i.e. compact()'s final witness-prepare step for this generation ran
// to completion -- WITHOUT regard to whether the digest it recorded still
// matches `bank`'s current bytes. This is the fine-grained signal needed
// to tell apart "this candidate generation was never confirmed at all"
// (safe to ignore entirely and resume on whatever else still verifies)
// from "this candidate generation WAS once confirmed, and has since been
// damaged" (must never be silently discarded -- see checkWitnessAttestsBank
// and reconstruct()'s bank-selection use of both signals together).
inline bool OtaSecurityStore::witnessPreparedForGeneration(OtaSecurityBankId bank, uint32_t generation) {
  OtaSecurityAppendEngine engine = engineFor(bank);  // witness lives in otherBank(bank), protects `bank`.
  OtaSecurityWitnessSectorHeader witnessHeader;
  bool ioErr = false;
  OtaSecurityEvidence ev = engine.readWitnessHeader(witnessHeader, ioErr);
  return ev == OtaSecurityEvidence::Committed && witnessHeader.protectedGeneration == generation &&
         witnessHeader.ownerBankSlot == (uint16_t)otherBank(bank) && witnessHeader.storeIdentity == storeIdentity_;
}

inline OtaSecurityStore::WitnessGenerationClaim OtaSecurityStore::witnessClaimedGeneration(OtaSecurityBankId bank,
                                                                                          uint32_t& outGeneration) {
  OtaSecurityAppendEngine engine = engineFor(bank);  // witness lives in otherBank(bank), protects `bank`.
  OtaSecurityWitnessSectorHeader witnessHeader;
  bool ioErr = false;
  OtaSecurityEvidence ev = engine.readWitnessHeader(witnessHeader, ioErr);
  if (ev == OtaSecurityEvidence::AbsentBytes) return WitnessGenerationClaim::Absent;
  if (ev != OtaSecurityEvidence::Committed) return WitnessGenerationClaim::Error;  // BodyOnly/Unprovable/IoError.
  if (witnessHeader.ownerBankSlot != (uint16_t)otherBank(bank) || witnessHeader.storeIdentity != storeIdentity_) {
    // Committed, but structurally bound to a DIFFERENT bank/store -- a
    // real, unambiguous "not a claim for this bank" fact, not a read
    // failure of any kind.
    return WitnessGenerationClaim::Absent;
  }
  outGeneration = witnessHeader.protectedGeneration;
  return WitnessGenerationClaim::Present;
}

// Returns true only if the witness sector OPPOSITE `bank` is Committed and
// attests `bank`'s CURRENT, exact, byte-for-byte snapshot digest at
// `generation` -- the one authoritative "this bank's snapshot is fully,
// provenly intact" check shared by cold bank-selection (finding #3) and
// the ordinary-log confirmation gate (finding #2). `outDigest` is always
// set to `bank`'s freshly-computed current digest when readable, 0 on an
// I/O failure (never treated as a match either way -- Sol finding #4).
inline bool OtaSecurityStore::checkWitnessAttestsBank(OtaSecurityBankId bank, uint32_t generation,
                                                      uint64_t& outDigest) {
  outDigest = 0;
  uint64_t digest = 0;
  if (!cachedSnapshotDigest(bank, generation, digest)) return false;  // I/O failure: never a match.
  outDigest = digest;
  if (!witnessPreparedForGeneration(bank, generation)) return false;
  OtaSecurityAppendEngine engine = engineFor(bank);
  OtaSecurityWitnessSectorHeader witnessHeader;
  bool ioErr = false;
  engine.readWitnessHeader(witnessHeader, ioErr);
  return witnessHeader.destSnapshotDigest == outDigest;
}

// Bounded/resumable counterpart of the old single-call
// ensureWitnessPrepared(): prepares (erasing if necessary) the witness
// sector OPPOSITE `protectedBank` so that it correctly attests
// `protectedBank` at `generation`, one program-or-erase call per
// invocation. The erase-then-reprogram path is only ever taken (a) at
// genesis bootstrap (sector is still blank, nothing to lose) or (b)
// immediately after compact() has already built+validated the new
// destination snapshot, at which point the erased sector's old contents
// (from two generations back) are provably dominated by the
// just-validated snapshot chain and safe to discard.
inline OtaSecurityStore::OrdinaryWitnessPrepOutcome OtaSecurityStore::stepEnsureWitnessPrepared(
    OtaSecurityBankId protectedBank, uint32_t generation) {
  OtaSecurityBankId witnessBank = otherBank(protectedBank);
  if (ordinaryWitnessPrepSubPhase_ == OrdinaryWitnessPrepSubPhase::CheckCache) {
    OtaSecurityAppendEngine probe = engineFor(protectedBank);
    OtaSecurityWitnessSectorHeader existing;
    bool ioErr = false;
    OtaSecurityEvidence existingEv = probe.readWitnessHeader(existing, ioErr);
    uint64_t digest = 0;
    if (!cachedSnapshotDigest(protectedBank, generation, digest)) {
      return OrdinaryWitnessPrepOutcome::Failed;  // I/O failure: never proceed.
    }
    if (existingEv == OtaSecurityEvidence::Committed && existing.protectedGeneration == generation &&
        existing.ownerBankSlot == (uint16_t)witnessBank && existing.destSnapshotDigest == digest &&
        existing.storeIdentity == storeIdentity_) {
      return OrdinaryWitnessPrepOutcome::DoneNoWrite;  // zero writes performed this call.
    }
    ordinaryWitnessPrepHeader_.storeIdentity = storeIdentity_;
    ordinaryWitnessPrepHeader_.destSnapshotDigest = digest;
    ordinaryWitnessPrepHeader_.protectedGeneration = generation;
    ordinaryWitnessPrepHeader_.ownerBankSlot = (uint16_t)witnessBank;
    ::ota::platform::FlashRegion& witnessRegion = carve(witnessBank).witness();
    if (!::ota::platform::isOk(witnessRegion.eraseSector(0))) return OrdinaryWitnessPrepOutcome::Failed;
    ordinaryWitnessPrepSubPhase_ = OrdinaryWitnessPrepSubPhase::ProgramBody;
    return OrdinaryWitnessPrepOutcome::InProgress;  // one erase call spent this step.
  }
  if (ordinaryWitnessPrepSubPhase_ == OrdinaryWitnessPrepSubPhase::ProgramBody) {
    OtaSecurityAppendEngine eng = engineFor(protectedBank);
    if (eng.writeWitnessHeaderBody(ordinaryWitnessPrepHeader_) != OtaSecurityIoOutcome::Ok) {
      return OrdinaryWitnessPrepOutcome::Failed;
    }
    ordinaryWitnessPrepSubPhase_ = OrdinaryWitnessPrepSubPhase::ProgramMarker;
    return OrdinaryWitnessPrepOutcome::InProgress;  // one program call spent this step.
  }
  // ProgramMarker.
  OtaSecurityAppendEngine eng = engineFor(protectedBank);
  if (eng.writeWitnessHeaderMarker() != OtaSecurityIoOutcome::Ok) return OrdinaryWitnessPrepOutcome::Failed;
  ordinaryWitnessPrepSubPhase_ = OrdinaryWitnessPrepSubPhase::CheckCache;  // reset for any FUTURE use.
  return OrdinaryWitnessPrepOutcome::DoneAfterWrite;  // one program call spent this step.
}

inline OtaSequenceBackingResult OtaSecurityStore::appendReservedRecord(OtaSecurityBankId bank, uint32_t physicalIndex,
                                                                       OtaSecurityRecordType type, uint32_t generation,
                                                                       const uint8_t* payload, uint16_t payloadLen) {
  OtaSecurityCellHeader header;
  header.version = 1;
  header.recordType = type;
  header.slotIndex = kTxGlobalSlot;
  header.generation = generation;
  header.lsn = nextLsn_;
  header.payloadLength = payloadLen;
  OtaSequenceBackingResult result = writeCellOnly(bank, physicalIndex, header, payload, payloadLen);
  if (result == OtaSequenceBackingResult::Committed) ++nextLsn_;
  return result;
}

inline OtaSequenceBackingResult OtaSecurityStore::writeCellOnly(OtaSecurityBankId bank, uint32_t physicalIndex,
                                                                OtaSecurityCellHeader header, const uint8_t* payload,
                                                                uint16_t payloadLen) {
  OtaSecurityAppendEngine eng = engineFor(bank);
  if (eng.writeCellBody(physicalIndex, header, payload, payloadLen) != OtaSecurityIoOutcome::Ok) {
    return OtaSequenceBackingResult::Uncertain;
  }
  if (eng.writeCellMarker(physicalIndex) != OtaSecurityIoOutcome::Ok) {
    return OtaSequenceBackingResult::Uncertain;
  }
  return OtaSequenceBackingResult::Committed;
}

// Bounded, one-program-call-per-invocation counterpart of
// appendReservedRecord()/writeCellOnly(), used ONLY by the compaction
// SealSource/CommitSwitch phases (see compactStep()). `subPhase` is
// caller-owned resumable state: CheckAndBody first reads the cell to
// detect an already-committed resume (idempotent retry after a cold
// restart mid-compaction -- a physical cell can only be programmed once
// between erases, so a prior successful body+marker must be recognized
// and skipped, never re-attempted), otherwise programs ONLY the body and
// advances to Marker; a second call then programs ONLY the marker and
// reports Committed. Exactly mirrors the original writeCellOnly() body
// bytes/ordering -- only the NUMBER of calls needed to reach Committed
// changes (one physical program per call instead of two per call).
inline OtaSecurityStore::ReservedCellStepOutcome OtaSecurityStore::appendReservedRecordStep(
    OtaSecurityBankId bank, uint32_t physicalIndex, OtaSecurityRecordType type, uint32_t generation,
    const uint8_t* payload, uint16_t payloadLen, ReservedCellSubPhase& subPhase) {
  OtaSecurityAppendEngine eng = engineFor(bank);
  if (subPhase == ReservedCellSubPhase::CheckAndBody) {
    OtaSecurityCellHeader existing;
    uint8_t existingPayload[kCellPayloadBytes];
    bool ioErr = false;
    OtaSecurityEvidence ev = eng.readCell(physicalIndex, existing, existingPayload, ioErr);
    if (ev == OtaSecurityEvidence::Committed && existing.recordType == type && existing.generation == generation) {
      subPhase = ReservedCellSubPhase::CheckAndBody;  // reset for any FUTURE use of this same sub-phase slot.
      return ReservedCellStepOutcome::Committed;
    }
    OtaSecurityCellHeader header;
    header.version = 1;
    header.recordType = type;
    header.slotIndex = kTxGlobalSlot;
    header.generation = generation;
    header.lsn = nextLsn_;
    header.payloadLength = payloadLen;
    if (eng.writeCellBody(physicalIndex, header, payload, payloadLen) != OtaSecurityIoOutcome::Ok) {
      return ReservedCellStepOutcome::Failed;
    }
    subPhase = ReservedCellSubPhase::Marker;
    return ReservedCellStepOutcome::InProgress;
  }
  if (eng.writeCellMarker(physicalIndex) != OtaSecurityIoOutcome::Ok) {
    return ReservedCellStepOutcome::Failed;
  }
  ++nextLsn_;
  subPhase = ReservedCellSubPhase::CheckAndBody;  // reset for any FUTURE use of this same sub-phase slot.
  return ReservedCellStepOutcome::Committed;
}

// Bounded, resumable counterpart of ensureWitnessPrepared() used ONLY by
// CompactionPhase::PrepareSourceWitness (see the class comment on
// witnessPrepSubPhase_/compactionWitnessSha_): streams `protectedBank`'s
// freshly-written snapshot ONE kSnapshotWriteStepByteBudget-sized chunk
// per call into an incremental SHA-256, then erases/programs the
// opposite bank's witness sector across three further single-call steps
// (erase, body program, marker program) -- never more than one physical
// erase-or-program call, and never more than kSnapshotWriteStepByteBudget
// bytes transferred, in any single invocation.
inline OtaSecurityStore::WitnessPrepStepOutcome OtaSecurityStore::prepareSourceWitnessStep(
    OtaSecurityBankId protectedBank, uint32_t generation) {
  switch (witnessPrepSubPhase_) {
    case WitnessPrepSubPhase::StreamDigest: {
      if (compactionEraseCursor_ == 0) compactionWitnessSha_.reset();
      uint8_t chunk[kSnapshotWriteStepByteBudget];
      uint32_t off = compactionEraseCursor_;
      uint32_t len = kSnapshotSizeBytes - off < kSnapshotWriteStepByteBudget ? (kSnapshotSizeBytes - off)
                                                                             : kSnapshotWriteStepByteBudget;
      ::ota::platform::FlashRegion& region = carve(protectedBank).snapshot();
      if (!::ota::platform::isOk(region.read(off, chunk, len))) return WitnessPrepStepOutcome::Failed;
      compactionWitnessSha_.update(chunk, len);
      compactionEraseCursor_ += len;
      if (compactionEraseCursor_ < kSnapshotSizeBytes) return WitnessPrepStepOutcome::InProgress;

      uint8_t digestBytes[32];
      compactionWitnessSha_.finish(digestBytes);
      uint64_t out = 0;
      for (int i = 0; i < 8; ++i) out = (out << 8) | digestBytes[i];
      compactionPreparedDigestValue_ = out;
      // Populate the ordinary per-append digest cache too, so any LATER
      // ordinary-append witness confirmation on this (bank, generation)
      // is a pure cache hit like every other generation's digest,
      // exactly as if computeSnapshotDigest() had been called normally.
      DigestCacheEntry& cache = digestCacheFor(protectedBank);
      cache.valid = true;
      cache.generation = generation;
      cache.digest = out;
      witnessPrepSubPhase_ = WitnessPrepSubPhase::EraseWitnessSector;
      return WitnessPrepStepOutcome::InProgress;
    }
    case WitnessPrepSubPhase::EraseWitnessSector: {
      OtaSecurityBankId witnessBank = otherBank(protectedBank);
      ::ota::platform::FlashRegion& witnessRegion = carve(witnessBank).witness();
      if (!::ota::platform::isOk(witnessRegion.eraseSector(0))) return WitnessPrepStepOutcome::Failed;
      witnessPrepSubPhase_ = WitnessPrepSubPhase::ProgramBody;
      return WitnessPrepStepOutcome::InProgress;
    }
    case WitnessPrepSubPhase::ProgramBody: {
      OtaSecurityWitnessSectorHeader hdr;
      hdr.storeIdentity = storeIdentity_;
      hdr.destSnapshotDigest = compactionPreparedDigestValue_;
      hdr.protectedGeneration = generation;
      hdr.ownerBankSlot = (uint16_t)otherBank(protectedBank);
      OtaSecurityAppendEngine eng = engineFor(protectedBank);
      if (eng.writeWitnessHeaderBody(hdr) != OtaSecurityIoOutcome::Ok) return WitnessPrepStepOutcome::Failed;
      witnessPrepSubPhase_ = WitnessPrepSubPhase::ProgramMarker;
      return WitnessPrepStepOutcome::InProgress;
    }
    case WitnessPrepSubPhase::ProgramMarker: {
      OtaSecurityAppendEngine eng = engineFor(protectedBank);
      if (eng.writeWitnessHeaderMarker() != OtaSecurityIoOutcome::Ok) return WitnessPrepStepOutcome::Failed;
      witnessPrepSubPhase_ = WitnessPrepSubPhase::StreamDigest;  // reset for any FUTURE compaction.
      compactionEraseCursor_ = 0;
      return WitnessPrepStepOutcome::Done;
    }
  }
  return WitnessPrepStepOutcome::Failed;
}

inline void OtaSecurityStore::resolveActivePhysicalState(ReconstructPhaseAResult& out) {
  OtaSecuritySnapshotHeader hdrA, hdrB;
  bool magicA = decodeSnapshotHeader(OtaSecurityBankId::A, hdrA);
  bool magicB = decodeSnapshotHeader(OtaSecurityBankId::B, hdrB);
  uint64_t digestA = 0, digestB = 0;

  // Independent, header-decode-AGNOSTIC proof that a bank was CONFIRMED as
  // a real compaction destination at some generation at least once -- read
  // directly from the OPPOSITE bank's witness sector, which is entirely
  // unaffected by whether THIS bank's own header copy happens to be
  // readable right now (Sol finding #2: a header read I/O error, or a
  // single-bit/byte corruption that merely breaks the magic check, must
  // never be silently conflated with "genuinely never written" -- doing
  // so would let a truly-blank-looking-but-actually-damaged header
  // resurrect stale genesis state and discard a real, witness-proven
  // newer generation).
  uint32_t witnessGenClaimA = 0;
  WitnessGenerationClaim claimA = witnessClaimedGeneration(OtaSecurityBankId::A, witnessGenClaimA);
  bool witnessClaimsA = claimA == WitnessGenerationClaim::Present;
  uint32_t witnessGenClaimB = 0;
  WitnessGenerationClaim claimB = witnessClaimedGeneration(OtaSecurityBankId::B, witnessGenClaimB);
  bool witnessClaimsB = claimB == WitnessGenerationClaim::Present;
  // A genuinely UNKNOWN (not merely absent) witness claim on EITHER side
  // means we cannot safely tell "never written" from "was written, but
  // cannot currently be proven" -- per Sol H2, this must never be
  // silently folded into "no claim" and risk resurrecting stale genesis
  // state or discarding a real newer generation. Freeze immediately;
  // storeFrozen_ is what actually governs every caller regardless of
  // whatever best-effort bank/generation bookkeeping runs below.
  if (claimA == WitnessGenerationClaim::Error || claimB == WitnessGenerationClaim::Error) {
    storeFrozen_ = true;
  }

  // Bank A is the hard-wired genesis-active bank: before it is EVER the
  // destination of a compaction it legitimately has no on-flash snapshot
  // header at all (magicA == false), yet it is still the correct, fully
  // intact active bank at the implicit generation 1. Gating verification
  // on "magicA == true" would incorrectly treat that normal, never-yet-
  // compacted state as unverifiable. Use the REAL claimed generation when
  // a header decodes, else the witness's OWN claim if one exists, else the
  // one generation a genuinely-never-written A could ever legitimately be
  // at (1); the opposite bank's witness check below still independently
  // proves (or disproves) this against the physical bytes, so a genuinely
  // corrupted/lost A can never be spuriously accepted this way (a
  // mismatched real generation simply fails to verify).
  uint32_t effectiveGenA = magicA ? hdrA.generation : (witnessClaimsA ? witnessGenClaimA : 1);
  // B, by construction, can NEVER acquire a witness claim until it has
  // actually been a real compaction destination at least once -- so ANY
  // witness claim for B proves real compacted state exists, even while
  // B's own header copy is currently unreadable.
  uint32_t effectiveGenB = magicB ? hdrB.generation : (witnessClaimsB ? witnessGenClaimB : 0);
  // A candidate bank is only trustworthy if the OPPOSITE bank's witness
  // independently attests its CURRENT exact bytes at its own claimed
  // generation -- a magic-valid-but-unwitnessed header (e.g. torn after a
  // header-only write, or corrupted by a single bit flip) must never be
  // silently folded in as fact (Sol finding #2/#3).
  bool verifiedA = checkWitnessAttestsBank(OtaSecurityBankId::A, effectiveGenA, digestA);
  bool verifiedB =
      (magicB || witnessClaimsB) && checkWitnessAttestsBank(OtaSecurityBankId::B, effectiveGenB, digestB);
  // Fine-grained "was this candidate generation ever CONFIRMED at all"
  // signal, independent of whether its digest still matches now -- lets
  // bank selection distinguish "dest never got far enough to represent a
  // real newer state" (safe to ignore) from "dest WAS once fully
  // confirmed, and has since been damaged" (must never be silently
  // discarded, per "no silent old-generation fallback").
  bool witnessReadyA = witnessPreparedForGeneration(OtaSecurityBankId::A, effectiveGenA);
  bool witnessReadyB =
      (magicB || witnessClaimsB) && witnessPreparedForGeneration(OtaSecurityBankId::B, effectiveGenB);

  // True pristine genesis requires that B has NEVER been confirmed as a
  // real compaction destination AT ALL -- checked via the independent
  // witness claim, not merely "B's header happens to be unreadable right
  // now" -- so a genuinely-corrupted-but-once-real B generation is never
  // silently discarded in favor of resurrecting stale bank-A genesis.
  if (!magicA && !magicB && !witnessClaimsB) {
    // True pristine genesis: NEITHER bank has ever had anything written to
    // its snapshot header (checked first, before any witness probing, so a
    // brand-new never-commissioned store -- whose opposite-bank witness is
    // itself still blank, hence verifiedA would otherwise read false too --
    // is never confused with a real corruption/freeze case below). Bank A
    // at generation 1 is the legitimate pre-commissioning default -- NOT an
    // error; commissioning itself is independently gated by the factory-
    // grant proof in commissionVirginTx / commissionVirginRx regardless of
    // this state.
    activeBank_ = OtaSecurityBankId::A;
    activeGeneration_ = 1;
    activeSnapshotValid_ = false;
  } else {
    // General two-candidate comparison, symmetric in EITHER compaction
    // direction: whichever bank claims the (strictly) HIGHER generation is
    // the only one that could ever represent a real successor state, so it
    // is examined first.
    uint32_t genA = effectiveGenA;
    uint32_t genB = effectiveGenB;
    bool aIsHigher = genA >= genB;
    OtaSecurityBankId higherBank = aIsHigher ? OtaSecurityBankId::A : OtaSecurityBankId::B;
    OtaSecurityBankId lowerBank = aIsHigher ? OtaSecurityBankId::B : OtaSecurityBankId::A;
    uint32_t higherGen = aIsHigher ? genA : genB;
    uint32_t lowerGen = aIsHigher ? genB : genA;
    bool higherVerified = aIsHigher ? verifiedA : verifiedB;
    bool higherWitnessReady = aIsHigher ? witnessReadyA : witnessReadyB;
    bool lowerVerified = aIsHigher ? verifiedB : verifiedA;

    if (higherVerified) {
      // The higher-generation candidate is fully, independently proven --
      // by construction (compact() only ever binds a witness to a
      // generation strictly greater than its source's) this can never be a
      // regression, so it is always safe to prefer outright.
      activeBank_ = higherBank;
      activeGeneration_ = higherGen;
      activeSnapshotValid_ = true;
    } else if (!higherWitnessReady && lowerVerified) {
      // The higher-generation candidate's own claimed generation was NEVER
      // confirmed by its protecting witness at all (header written, or
      // even nothing written yet, but the two-phase witness-prepare step
      // never landed) -- it never got far enough to represent a real
      // alternate state, so it carries zero risk of silently discarding
      // anything real. Safe to ignore it entirely and resume on the
      // still-intact lower/older candidate.
      activeBank_ = lowerBank;
      activeGeneration_ = lowerGen;
      activeSnapshotValid_ = (lowerBank == OtaSecurityBankId::A) ? magicA : true;
    } else {
      // Either the higher candidate WAS once fully confirmed and has since
      // been damaged (witness ready but digest mismatch), or neither
      // candidate verifies at all: an aborted/incomplete compaction (or a
      // corrupted snapshot) with no provable-complete successor and no
      // provable-intact predecessor either. Never select the incomplete/
      // unproven one and never silently fall back to an older generation
      // that might be missing real facts the damaged newer one once held --
      // freeze the whole store. Best-effort bookkeeping only (all
      // operations below return Uncertain regardless, since storeFrozen_
      // will be true).
      activeBank_ = higherBank;
      activeGeneration_ = higherGen;
      activeSnapshotValid_ = false;
      storeFrozen_ = true;
    }
  }
  // Re-decode the CHOSEN active bank's header fresh, right before folding
  // its fields forward, rather than reusing the (possibly stale/failed)
  // hdrA/hdrB read from the top of this function. This both gives a
  // single transient read glitch a second chance to clear (a one-off I/O
  // error must not itself cost real, witness-proven facts) and, if the
  // header genuinely still cannot be decoded, catches the case where the
  // witness claims a generation whose actual field CONTENT cannot be
  // recovered at all: such facts are Unprovable and must freeze the store
  // rather than silently exposing zero-valued defaults as if they were
  // real (Sol finding #2).
  bool activeHeaderReadable = decodeSnapshotHeader(activeBank_, out.activeHdr);
  if (activeSnapshotValid_ && !activeHeaderReadable) {
    storeFrozen_ = true;
    activeSnapshotValid_ = false;
  }

  // Single authoritative witness check for the FINAL chosen (bank,
  // generation) pair -- correctly covers genesis too (a blank/never-
  // decoded header still needs this to see whether an earlier append
  // session already prepared the opposite witness for generation 1).
  out.witnessHeaderValid = checkWitnessAttestsBank(activeBank_, activeGeneration_, out.activeDigest);
}

// --- stepResolveActivePhysicalState()'s helpers -----------------------------
// Pure (zero-I/O) counterparts of decodeSnapshotHeader()/witnessClaimedGeneration()/
// witnessPreparedForGeneration()/checkWitnessAttestsBank() that operate on
// already-captured raw bytes (a BankEvidenceCursor's rawHeaderX/rawWitnessForX)
// instead of performing their own flash reads -- used exclusively by the
// Select phase below, so Select is genuinely zero-I/O per the phased-
// migration contract, yet reaches the EXACT same verdicts the synchronous
// resolveActivePhysicalState() above would reach from the same physical
// bytes.
inline OtaSecurityStore::WitnessGenerationClaim OtaSecurityStore::pureWitnessClaimedGeneration(
    OtaSecurityBankId protectedBank, const uint8_t* rawWitness, bool witnessIoError,
    OtaSecurityWitnessSectorHeader& outHeader, uint32_t& outGeneration) const {
  if (witnessIoError) return WitnessGenerationClaim::Error;
  OtaSecurityEvidence ev = OtaSecurityWitnessHeaderCodec::classify(rawWitness, kWitnessHeaderBytes, outHeader);
  if (ev == OtaSecurityEvidence::AbsentBytes) return WitnessGenerationClaim::Absent;
  if (ev != OtaSecurityEvidence::Committed) return WitnessGenerationClaim::Error;  // BodyOnly/Unprovable/IoError.
  if (outHeader.ownerBankSlot != (uint16_t)otherBank(protectedBank) || outHeader.storeIdentity != storeIdentity_) {
    return WitnessGenerationClaim::Absent;  // Committed, but bound to a DIFFERENT bank/store.
  }
  outGeneration = outHeader.protectedGeneration;
  return WitnessGenerationClaim::Present;
}

inline bool OtaSecurityStore::pureWitnessPreparedForGeneration(OtaSecurityBankId protectedBank, uint32_t generation,
                                                              const OtaSecurityWitnessSectorHeader& header,
                                                              OtaSecurityStore::WitnessGenerationClaim claim) const {
  return claim == WitnessGenerationClaim::Present && header.protectedGeneration == generation &&
         header.ownerBankSlot == (uint16_t)otherBank(protectedBank) && header.storeIdentity == storeIdentity_;
}

inline bool OtaSecurityStore::pureCheckWitnessAttestsBank(OtaSecurityBankId protectedBank, uint32_t generation,
                                                         uint64_t freshDigest,
                                                         const OtaSecurityWitnessSectorHeader& header,
                                                         OtaSecurityStore::WitnessGenerationClaim claim) const {
  if (!pureWitnessPreparedForGeneration(protectedBank, generation, header, claim)) return false;
  return header.destSnapshotDigest == freshDigest;
}

// --- Bounded/resumable re-implementation of Phase A -------------------------
// See BankEvidenceCursor's doc comment for the phase sequence and exact
// per-call byte budgets. NOT wired into reconstruct()/refreshIfPhysicallyStale()
// in this slice -- new, independently testable infrastructure only.
inline OtaSecurityStore::BankEvidenceStepOutcome OtaSecurityStore::stepResolveActivePhysicalState(
    OtaSecurityOperationOwner owner, OtaSecurityOperationTicket& ticket, ReconstructPhaseAResult& out) {
  BankEvidenceCursor& c = bankEvidenceCursor_;

  if (c.phase == BankEvidencePhase::Idle) {
    // A fresh cycle always starts from an explicitly-invalid ticket --
    // never silently "adopt" a caller-supplied-but-stale ticket value as
    // if it already belonged to a cursor that no longer exists.
    if (ticket.valid()) return BankEvidenceStepOutcome::OwnershipDenied;
    // Never disturb an already in-flight ordinary mutation or compaction;
    // both must independently finish or be cancelled first.
    if (hasPendingOrdinaryOperation() || compactionInProgress_) return BankEvidenceStepOutcome::OwnershipDenied;
    if (!acquirePartitionOwnership()) return BankEvidenceStepOutcome::Pending;  // physical bus busy; try again later.
    c = BankEvidenceCursor{};
    c.owner = owner;
    c.ticketId = nextOpTicketSeed_++;
    c.issuerInstanceEpoch = instanceEpoch_;
    c.phase = BankEvidencePhase::ObserveHeadersAndClaims;
    ticket.owner = owner;
    ticket.id = c.ticketId;
    ticket.issuerInstanceEpoch = instanceEpoch_;
    releasePartitionOwnership();  // physical bus released between calls; logical ownership lives in the cursor/ticket.
    return BankEvidenceStepOutcome::Pending;
  }

  // Every resuming call (any phase other than Idle) must present the
  // EXACT ticket minted on the first call -- a foreign/stale/mismatched
  // ticket is refused without touching any state (ABA-proof, same
  // contract as ordinaryOpTicketMatches()).
  if (!ticket.valid() || ticket.issuerInstanceEpoch != c.issuerInstanceEpoch || ticket.owner != c.owner ||
      ticket.id != c.ticketId || owner != c.owner) {
    return BankEvidenceStepOutcome::OwnershipDenied;
  }

  if (c.phase == BankEvidencePhase::Done) {
    out = c.provisional;
    return BankEvidenceStepOutcome::Ready;  // idempotent until cancelled.
  }
  if (c.phase == BankEvidencePhase::Failed) {
    return BankEvidenceStepOutcome::Failed;  // terminal for this cursor cycle until cancelled/restarted.
  }

  if (!acquirePartitionOwnership()) return BankEvidenceStepOutcome::Pending;  // physical bus busy this call.
  BankEvidenceStepOutcome outcome = BankEvidenceStepOutcome::Pending;

  if (c.phase == BankEvidencePhase::ObserveHeadersAndClaims) {
    // Exactly 2*kHeaderEncodedBytes + 2*kWitnessHeaderBytes = 576 bytes,
    // one call, zero hashing/classification here.
    ::ota::platform::FlashStatus stHA = carve(OtaSecurityBankId::A).snapshot().read(kHeaderAreaOffset, c.rawHeaderA,
                                                                                    sizeof(c.rawHeaderA));
    c.headerIoErrorA = !::ota::platform::isOk(stHA);
    ::ota::platform::FlashStatus stHB = carve(OtaSecurityBankId::B).snapshot().read(kHeaderAreaOffset, c.rawHeaderB,
                                                                                    sizeof(c.rawHeaderB));
    c.headerIoErrorB = !::ota::platform::isOk(stHB);
    // Witness for A lives physically in bank B, and vice versa.
    ::ota::platform::FlashStatus stWA =
        carve(otherBank(OtaSecurityBankId::A)).witness().read(0, c.rawWitnessForA, sizeof(c.rawWitnessForA));
    c.witnessIoErrorForA = !::ota::platform::isOk(stWA);
    ::ota::platform::FlashStatus stWB =
        carve(otherBank(OtaSecurityBankId::B)).witness().read(0, c.rawWitnessForB, sizeof(c.rawWitnessForB));
    c.witnessIoErrorForB = !::ota::platform::isOk(stWB);
    c.sha.reset();
    c.digestOffset = 0;
    c.digestIoError = false;
    c.phase = BankEvidencePhase::DigestA;
  } else if (c.phase == BankEvidencePhase::DigestA || c.phase == BankEvidencePhase::DigestB) {
    OtaSecurityBankId digestBank = (c.phase == BankEvidencePhase::DigestA) ? OtaSecurityBankId::A : OtaSecurityBankId::B;
    constexpr uint32_t kDigestChunkBytes = 1024u;
    uint8_t chunk[kDigestChunkBytes];
    uint32_t len =
        kSnapshotSizeBytes - c.digestOffset < kDigestChunkBytes ? (kSnapshotSizeBytes - c.digestOffset) : kDigestChunkBytes;
    ::ota::platform::FlashStatus st = carve(digestBank).snapshot().read(c.digestOffset, chunk, len);
    if (!::ota::platform::isOk(st)) c.digestIoError = true;
    else c.sha.update(chunk, len);
    c.digestOffset += len;
    if (c.digestOffset >= kSnapshotSizeBytes) {
      uint8_t digestBytes[32];
      c.sha.finish(digestBytes);
      uint64_t digestValue = 0;
      for (int i = 0; i < 8; ++i) digestValue = (digestValue << 8) | digestBytes[i];
      if (c.phase == BankEvidencePhase::DigestA) {
        if (!c.digestIoError) c.digestA = digestValue;
        c.sha.reset();
        c.digestOffset = 0;
        bool thisDigestFailed = c.digestIoError;
        c.digestIoError = false;
        if (thisDigestFailed) {
          c.phase = BankEvidencePhase::Failed;  // I/O error mid-scan: typed failure, never a silent zero-digest.
        } else {
          c.phase = BankEvidencePhase::DigestB;
        }
      } else {
        if (c.digestIoError) {
          c.phase = BankEvidencePhase::Failed;
        } else {
          c.digestB = digestValue;
          c.phase = BankEvidencePhase::Select;
        }
      }
    }
  } else if (c.phase == BankEvidencePhase::Select) {
    // Zero I/O: pure decision over the already-captured Observe-phase
    // bytes and the already-computed digestA/digestB, porting EXACTLY
    // resolveActivePhysicalState()'s algorithm (see that function's doc
    // comment for the full rationale of every branch below).
    OtaSecuritySnapshotHeader hdrA{}, hdrB{};
    bool magicA = !c.headerIoErrorA && OtaSecuritySnapshotHeaderCodec::decode(c.rawHeaderA, kHeaderEncodedBytes, hdrA);
    bool magicB = !c.headerIoErrorB && OtaSecuritySnapshotHeaderCodec::decode(c.rawHeaderB, kHeaderEncodedBytes, hdrB);

    OtaSecurityWitnessSectorHeader witHeaderA{}, witHeaderB{};
    uint32_t witnessGenClaimA = 0, witnessGenClaimB = 0;
    WitnessGenerationClaim claimA = pureWitnessClaimedGeneration(OtaSecurityBankId::A, c.rawWitnessForA,
                                                                 c.witnessIoErrorForA, witHeaderA, witnessGenClaimA);
    WitnessGenerationClaim claimB = pureWitnessClaimedGeneration(OtaSecurityBankId::B, c.rawWitnessForB,
                                                                 c.witnessIoErrorForB, witHeaderB, witnessGenClaimB);
    bool witnessClaimsA = claimA == WitnessGenerationClaim::Present;
    bool witnessClaimsB = claimB == WitnessGenerationClaim::Present;

    bool provisionalFrozen = false;
    if (claimA == WitnessGenerationClaim::Error || claimB == WitnessGenerationClaim::Error) provisionalFrozen = true;

    uint32_t effectiveGenA = magicA ? hdrA.generation : (witnessClaimsA ? witnessGenClaimA : 1);
    uint32_t effectiveGenB = magicB ? hdrB.generation : (witnessClaimsB ? witnessGenClaimB : 0);

    bool verifiedA = pureCheckWitnessAttestsBank(OtaSecurityBankId::A, effectiveGenA, c.digestA, witHeaderA, claimA);
    bool verifiedB = (magicB || witnessClaimsB) &&
                     pureCheckWitnessAttestsBank(OtaSecurityBankId::B, effectiveGenB, c.digestB, witHeaderB, claimB);
    bool witnessReadyA = pureWitnessPreparedForGeneration(OtaSecurityBankId::A, effectiveGenA, witHeaderA, claimA);
    bool witnessReadyB = (magicB || witnessClaimsB) &&
                        pureWitnessPreparedForGeneration(OtaSecurityBankId::B, effectiveGenB, witHeaderB, claimB);

    OtaSecurityBankId provBank;
    uint32_t provGen;
    bool provValid;

    if (!magicA && !magicB && !witnessClaimsB) {
      provBank = OtaSecurityBankId::A;
      provGen = 1;
      provValid = false;
    } else {
      uint32_t genA = effectiveGenA;
      uint32_t genB = effectiveGenB;
      bool aIsHigher = genA >= genB;
      OtaSecurityBankId higherBank = aIsHigher ? OtaSecurityBankId::A : OtaSecurityBankId::B;
      OtaSecurityBankId lowerBank = aIsHigher ? OtaSecurityBankId::B : OtaSecurityBankId::A;
      uint32_t higherGen = aIsHigher ? genA : genB;
      uint32_t lowerGen = aIsHigher ? genB : genA;
      bool higherVerified = aIsHigher ? verifiedA : verifiedB;
      bool higherWitnessReady = aIsHigher ? witnessReadyA : witnessReadyB;
      bool lowerVerified = aIsHigher ? verifiedB : verifiedA;

      if (higherVerified) {
        provBank = higherBank;
        provGen = higherGen;
        provValid = true;
      } else if (!higherWitnessReady && lowerVerified) {
        provBank = lowerBank;
        provGen = lowerGen;
        provValid = (lowerBank == OtaSecurityBankId::A) ? magicA : true;
      } else {
        provBank = higherBank;
        provGen = higherGen;
        provValid = false;
        provisionalFrozen = true;
      }
    }

    // Re-decode (purely, from already-captured bytes) the CHOSEN bank's
    // header, exactly mirroring resolveActivePhysicalState()'s "second
    // chance" re-decode step -- here it is the SAME Observe-phase bytes
    // (Recheck re-reads and compares them fresh before this decision is
    // trusted), not a second physical read.
    OtaSecuritySnapshotHeader chosenHdr{};
    bool chosenHeaderReadable =
        (provBank == OtaSecurityBankId::A) ? magicA : magicB;
    if (chosenHeaderReadable) chosenHdr = (provBank == OtaSecurityBankId::A) ? hdrA : hdrB;
    if (provValid && !chosenHeaderReadable) {
      provisionalFrozen = true;
      provValid = false;
    }

    uint64_t chosenDigest = (provBank == OtaSecurityBankId::A) ? c.digestA : c.digestB;
    bool chosenWitnessValid = (provBank == OtaSecurityBankId::A)
                                 ? pureCheckWitnessAttestsBank(OtaSecurityBankId::A, provGen, c.digestA, witHeaderA, claimA)
                                 : pureCheckWitnessAttestsBank(OtaSecurityBankId::B, provGen, c.digestB, witHeaderB, claimB);

    c.provisionalActiveBank = provBank;
    c.provisionalActiveGeneration = provGen;
    c.provisionalActiveSnapshotValid = provValid;
    c.provisionalStoreFrozen = provisionalFrozen;
    c.provisionalWitnessHeaderValid = chosenWitnessValid;
    c.provisional.activeHdr = chosenHdr;
    c.provisional.activeDigest = chosenDigest;
    c.provisional.witnessHeaderValid = chosenWitnessValid;
    c.phase = BankEvidencePhase::Recheck;
  } else if (c.phase == BankEvidencePhase::Recheck) {
    // Reread the SAME 576 bytes under the same held lease and compare
    // exact header/witness facts against the Observe-phase captures --
    // any mismatch (including a flipped I/O-error state) means the
    // physical evidence changed mid-scan, relative to which digestA/
    // digestB/Select's decision were computed: a typed failure, never a
    // partial/empty Ready.
    // Zero-initialized (not just declared) so that a read() which fails
    // WITHOUT writing `data` (a genuine I/O error) still produces
    // deterministic, comparably-identical bytes against the Observe-phase
    // capture (itself zero-initialized at cursor reset) -- never an
    // accidental mismatch against uninitialized stack garbage.
    uint8_t rawHeaderA2[kHeaderEncodedBytes] = {0}, rawHeaderB2[kHeaderEncodedBytes] = {0};
    uint8_t rawWitnessForA2[kWitnessHeaderBytes] = {0}, rawWitnessForB2[kWitnessHeaderBytes] = {0};
    ::ota::platform::FlashStatus stHA =
        carve(OtaSecurityBankId::A).snapshot().read(kHeaderAreaOffset, rawHeaderA2, sizeof(rawHeaderA2));
    bool headerIoErrorA2 = !::ota::platform::isOk(stHA);
    ::ota::platform::FlashStatus stHB =
        carve(OtaSecurityBankId::B).snapshot().read(kHeaderAreaOffset, rawHeaderB2, sizeof(rawHeaderB2));
    bool headerIoErrorB2 = !::ota::platform::isOk(stHB);
    ::ota::platform::FlashStatus stWA =
        carve(otherBank(OtaSecurityBankId::A)).witness().read(0, rawWitnessForA2, sizeof(rawWitnessForA2));
    bool witnessIoErrorForA2 = !::ota::platform::isOk(stWA);
    ::ota::platform::FlashStatus stWB =
        carve(otherBank(OtaSecurityBankId::B)).witness().read(0, rawWitnessForB2, sizeof(rawWitnessForB2));
    bool witnessIoErrorForB2 = !::ota::platform::isOk(stWB);

    bool unchanged = headerIoErrorA2 == c.headerIoErrorA && headerIoErrorB2 == c.headerIoErrorB &&
                     witnessIoErrorForA2 == c.witnessIoErrorForA && witnessIoErrorForB2 == c.witnessIoErrorForB &&
                     std::memcmp(rawHeaderA2, c.rawHeaderA, kHeaderEncodedBytes) == 0 &&
                     std::memcmp(rawHeaderB2, c.rawHeaderB, kHeaderEncodedBytes) == 0 &&
                     std::memcmp(rawWitnessForA2, c.rawWitnessForA, kWitnessHeaderBytes) == 0 &&
                     std::memcmp(rawWitnessForB2, c.rawWitnessForB, kWitnessHeaderBytes) == 0;

    if (!unchanged) {
      c.phase = BankEvidencePhase::Failed;
    } else {
      // Apply the confirmed decision to the real store members ONLY now --
      // never speculatively mid-flight, unlike the synchronous legacy
      // version, which mutates these directly throughout.
      activeBank_ = c.provisionalActiveBank;
      activeGeneration_ = c.provisionalActiveGeneration;
      activeSnapshotValid_ = c.provisionalActiveSnapshotValid;
      if (c.provisionalStoreFrozen) storeFrozen_ = true;
      // Publish fresh digest caches only under their exact new evidence/
      // generation binding -- cold reconstruction invalidates any old
      // cached entries, so these replace them wholesale, never merge.
      DigestCacheEntry& cacheA = digestCacheFor(OtaSecurityBankId::A);
      cacheA.valid = true;
      cacheA.generation = (c.provisionalActiveBank == OtaSecurityBankId::A) ? c.provisionalActiveGeneration
                                                                           : cacheA.generation;
      cacheA.digest = c.digestA;
      DigestCacheEntry& cacheB = digestCacheFor(OtaSecurityBankId::B);
      cacheB.valid = true;
      cacheB.generation = (c.provisionalActiveBank == OtaSecurityBankId::B) ? c.provisionalActiveGeneration
                                                                           : cacheB.generation;
      cacheB.digest = c.digestB;
      out = c.provisional;
      c.phase = BankEvidencePhase::Done;
      outcome = BankEvidenceStepOutcome::Ready;
    }
  }

  releasePartitionOwnership();  // physical bus released each call; logical ownership stays in the cursor/ticket.
  if (c.phase == BankEvidencePhase::Failed) return BankEvidenceStepOutcome::Failed;
  if (c.phase == BankEvidencePhase::Done) return BankEvidenceStepOutcome::Ready;
  return outcome;
}

inline void OtaSecurityStore::cancelBankEvidenceCursor(const OtaSecurityOperationTicket& ticket) {
  BankEvidenceCursor& c = bankEvidenceCursor_;
  if (c.phase == BankEvidencePhase::Idle) return;  // nothing held; silent no-op.
  if (!ticket.valid() || ticket.issuerInstanceEpoch != c.issuerInstanceEpoch || ticket.owner != c.owner ||
      ticket.id != c.ticketId) {
    return;  // foreign/stale ticket: nothing of THIS caller's was ever actually held.
  }
  c = BankEvidenceCursor{};
}

// --- SLICE3: pure per-record ordinary-log fold, shared by legacy
// reconstruct()'s full cold replay and stepReconstruct()'s bounded
// OrdinaryLog phase below (see each helper's declaration-site comment). ---
inline void OtaSecurityStore::foldConfirmedOrdinaryCellRecord(const OtaSecurityCellHeader& header,
                                                              const uint8_t* payload, uint32_t pos,
                                                              bool& txAmbiguous,
                                                              OtaSecurityLiveBindingLogEvidence& liveEv,
                                                              uint64_t& highestLiveTxLsn, bool& haveLiveTx) {
  switch (header.recordType) {
    case OtaSecurityRecordType::TxReservation: {
      uint32_t value = 0;
      getU32(payload, kCellPayloadBytes, 0, value);
      if (value > txUpperBound_) txUpperBound_ = value;
      txAmbiguous = false;
      break;
    }
    case OtaSecurityRecordType::RxPeerAdvance: {
      uint8_t key[32];
      getBytes(payload, kCellPayloadBytes, 0, key, 32);
      uint32_t head = 0;
      getU32(payload, kCellPayloadBytes, 32, head);
      PeerTableEntry* existing = findPeer(key);
      if (existing == nullptr) {
        if (peerTableCount_ >= kPeerTableCapacity) {
          storeFrozen_ = true;
        } else {
          PeerTableEntry& te = peerTable_[peerTableCount_];
          std::memcpy(te.key, key, 32);
          te.index = peerTableCount_;
          te.head = head;
          ++peerTableCount_;
          existing = &te;
        }
      } else if (head > existing->head) {
        existing->head = head;
      }
      // Bounded replacement for ambiguousPeer.erase(key): a later
      // CONFIRMED record for this exact key un-freezes it.
      if (existing != nullptr) existing->frozen = false;
      break;
    }
    case OtaSecurityRecordType::RxGroupAdvance: {
      uint8_t key[92];
      getBytes(payload, kCellPayloadBytes, 0, key, 92);
      uint32_t head = 0;
      getU32(payload, kCellPayloadBytes, 92, head);
      CohortTableEntry* existing = findCohort(key);
      if (existing == nullptr) {
        if (cohortTableCount_ >= kCohortTableCapacity) {
          storeFrozen_ = true;
        } else {
          CohortTableEntry& te = cohortTable_[cohortTableCount_];
          std::memcpy(te.key, key, 92);
          te.index = cohortTableCount_;
          te.head = head;
          ++cohortTableCount_;
          existing = &te;
        }
      } else if (head > existing->head) {
        existing->head = head;
      }
      if (existing != nullptr) existing->frozen = false;
      break;
    }
    case OtaSecurityRecordType::TerminalAttempt: {
      OtaSecurityTerminalEntry e;
      if (OtaSecurityTerminalEntryCodec::decode(payload, kCellPayloadBytes, e)) {
        if (terminalCount_ >= kTerminalTableCapacity) {
          storeFrozen_ = true;
        } else {
          OtaSecurityTerminalIndexEntry& te = terminalIndex_[terminalCount_++];
          te.location = (uint16_t)(pos & kTerminalLocIndexMask) | kTerminalLocSourceBit;  // ordinary-log cell.
          te.flags = 0x1u;
          te.tupleFingerprint = computeTerminalTupleFingerprint(e.controller, e.campaign, e.session, e.attempt);
        }
      }
      break;
    }
    case OtaSecurityRecordType::FactoryGrantRecord: {
      OtaSecurityFactoryGrant g;
      getU64(payload, kCellPayloadBytes, 0, g.deviceUid);
      getBytes(payload, kCellPayloadBytes, 8, g.fullLocalPublicKey, 32);
      getU32(payload, kCellPayloadBytes, 40, g.profile);
      getU32(payload, kCellPayloadBytes, 44, g.layout);
      getU32(payload, kCellPayloadBytes, 48, g.role);
      getU32(payload, kCellPayloadBytes, 52, g.initialRole);
      getBytes(payload, kCellPayloadBytes, 56, g.consentOwner, 32);
      getU64(payload, kCellPayloadBytes, 88, g.transaction);
      factoryGrant_ = g;
      factoryGrantConsumed_ = true;
      break;
    }
    case OtaSecurityRecordType::LiveBindingChunk: {
      uint64_t txLsn = 0;
      uint8_t partIndex = 0, partCount = 0;
      uint16_t totalLength = 0;
      getU64(payload, kCellPayloadBytes, 0, txLsn);
      getU8(payload, kCellPayloadBytes, 8, partIndex);
      getU8(payload, kCellPayloadBytes, 9, partCount);
      getU16(payload, kCellPayloadBytes, 10, totalLength);
      if (partCount == kLiveBindingChunkCount && partIndex < kLiveBindingChunkCount &&
          totalLength == kLiveBindingFixedBytes) {
        // Bounded replacement for liveBindingTxs[txLsn]: see
        // OtaSecurityLiveBindingLogEvidence's doc comment.
        if (!haveLiveTx || txLsn > highestLiveTxLsn) {
          liveEv = OtaSecurityLiveBindingLogEvidence{};
          highestLiveTxLsn = txLsn;
          haveLiveTx = true;
        }
        if (txLsn == highestLiveTxLsn) {
          liveEv.have[partIndex] = true;
          liveEv.totalLength = totalLength;
          std::memcpy(liveEv.bytes[partIndex], payload + kLiveBindingChunkPrefixBytes, kLiveBindingChunkDataBytes);
        }
      }
      break;
    }
    default:
      break;  // SealRecord / SwitchRecord are structural markers, not counter facts.
  }
}

inline void OtaSecurityStore::foldAmbiguousOrdinaryCellRecord(const OtaSecurityCellHeader& header,
                                                              const uint8_t* payload, bool& txAmbiguous,
                                                              bool& liveBindingTxAmbiguous) {
  // Attributable ambiguity: freeze only the specific context this header
  // identifies, unless a LATER confirmed record for the same context
  // dominates it (handled by foldConfirmedOrdinaryCellRecord()'s
  // un-freeze lines above, applied in position order since both call
  // sites scan sequentially).
  switch (header.recordType) {
    case OtaSecurityRecordType::TxReservation:
      txAmbiguous = true;
      break;
    case OtaSecurityRecordType::RxPeerAdvance: {
      uint8_t key[32];
      getBytes(payload, kCellPayloadBytes, 0, key, 32);
      // If this key has already been confirmed into peerTable_, mark its
      // own `frozen` field directly. If it was NEVER confirmed at all,
      // there is no table entry to freeze -- matching the original
      // sequential-scan semantics exactly.
      PeerTableEntry* entry = findPeer(key);
      if (entry != nullptr) entry->frozen = true;
      break;
    }
    case OtaSecurityRecordType::RxGroupAdvance: {
      uint8_t key[92];
      getBytes(payload, kCellPayloadBytes, 0, key, 92);
      CohortTableEntry* entry = findCohort(key);
      if (entry != nullptr) entry->frozen = true;
      break;
    }
    case OtaSecurityRecordType::FactoryGrantRecord:
      // A one-use, whole-store identity fact -- an ambiguity here cannot
      // be attributed to any narrower context, so it freezes the whole
      // store (mirrors the seal/switch structural-record handling).
      storeFrozen_ = true;
      break;
    case OtaSecurityRecordType::LiveBindingChunk:
      // A specific chunk exists but didn't independently confirm: the
      // WHOLE transaction it belongs to can no longer be safely
      // assembled or ruled out -- resolved once the highest touched
      // transaction LSN is known (Finalize/legacy's post-loop step).
      liveBindingTxAmbiguous = true;
      break;
    default:
      break;
  }
}

// --- SLICE2/3: stepReconstruct() -- bounded/resumable snapshot-fold +
// reserved-cell + ordinary-log-replay cursor -------------------------------
inline OtaSecurityStore::ReconstructStepOutcome OtaSecurityStore::stepReconstruct(
    OtaSecurityOperationOwner owner, OtaSecurityOperationTicket& ticket) {
  ReconstructCursor& c = reconstructCursor_;

  if (c.phase == ReconstructPhase::Idle) {
    if (ticket.valid()) return ReconstructStepOutcome::OwnershipDenied;
    if (hasPendingOrdinaryOperation() || compactionInProgress_) return ReconstructStepOutcome::OwnershipDenied;
    // The shared bankEvidenceCursor_ must not already be held by an
    // independent, directly-driven caller of stepResolveActivePhysicalState
    // -- a real serialized shared-resource conflict, refused as Pending
    // (try again later), never a silent steal of someone else's evidence.
    if (bankEvidenceCursor_.phase != BankEvidencePhase::Idle) return ReconstructStepOutcome::Pending;
    if (misconfigured_) return ReconstructStepOutcome::Failed;
    // Same ordering as the legacy synchronous reconstruct(): reset ALL
    // reconstructed state (tables/counts/freeze/caches) BEFORE Phase A
    // runs, since Phase A's Recheck step is the one that writes the real
    // activeBank_/activeGeneration_/activeSnapshotValid_/storeFrozen_
    // members -- resetting afterwards would destroy that result.
    resetReconstructedState();
    c = ReconstructCursor{};
    c.owner = owner;
    c.ticketId = nextOpTicketSeed_++;
    c.issuerInstanceEpoch = instanceEpoch_;
    c.phase = ReconstructPhase::PhaseA;
    ticket.owner = owner;
    ticket.id = c.ticketId;
    ticket.issuerInstanceEpoch = instanceEpoch_;
    return ReconstructStepOutcome::Pending;
  }

  if (!ticket.valid() || ticket.issuerInstanceEpoch != c.issuerInstanceEpoch || ticket.owner != c.owner ||
      ticket.id != c.ticketId || owner != c.owner) {
    return ReconstructStepOutcome::OwnershipDenied;
  }

  if (c.phase == ReconstructPhase::Done) return ReconstructStepOutcome::Ready;  // idempotent until cancelled.
  if (c.phase == ReconstructPhase::Failed) return ReconstructStepOutcome::Failed;

  if (c.phase == ReconstructPhase::PhaseA) {
    BankEvidenceStepOutcome inner = stepResolveActivePhysicalState(owner, c.phaseATicket, c.phaseAResult);
    if (inner == BankEvidenceStepOutcome::Failed || inner == BankEvidenceStepOutcome::OwnershipDenied) {
      // OwnershipDenied here would mean something foreign stole/stepped
      // bankEvidenceCursor_ out from under this SAME owner's internal
      // ticket -- impossible under the Idle-time exclusivity check above
      // short of a bug; treat defensively as a typed failure, never a
      // silent retry loop. Either way the child Phase-A session is OVER
      // from this parent's perspective -- release the SHARED
      // bankEvidenceCursor_ promptly (RAM-only, never touches flash) so
      // an independent, standalone Phase-A-only caller is never left
      // stuck behind a parked, already-finished child session; the
      // PARENT's own (outer, ReconstructCursor) ticket/lease is entirely
      // separate and is NOT released here.
      if (c.phaseATicket.valid()) cancelBankEvidenceCursor(c.phaseATicket);
      c.phase = ReconstructPhase::Failed;
      return ReconstructStepOutcome::Failed;
    }
    if (inner == BankEvidenceStepOutcome::Ready) {
      // c.phaseAResult already holds the Ready value; release the child
      // session now (same reasoning as the Failed branch above) rather
      // than leaving bankEvidenceCursor_ parked in Done, which would
      // otherwise deny a fresh standalone Phase-A caller forever.
      if (c.phaseATicket.valid()) cancelBankEvidenceCursor(c.phaseATicket);
      c.phase = ReconstructPhase::HeaderFields;
    }
    return ReconstructStepOutcome::Pending;
  }

  if (c.phase == ReconstructPhase::HeaderFields) {
    // Zero I/O: pure fold of the Phase-A-validated header's own fields,
    // gated EXACTLY like the legacy reconstruct() -- only a witness-
    // attested snapshot's fields are ever exposed as durable facts.
    const OtaSecuritySnapshotHeader& activeHdr = c.phaseAResult.activeHdr;
    if (activeSnapshotValid_ && c.phaseAResult.witnessHeaderValid) {
      // A committed, witness-attested header claiming MORE occupied rows
      // than physically fit is itself an impossible/corrupt fact, never
      // silently clamped to `capacity` and folded as if the excess rows
      // simply didn't exist -- that would let a real, committed claim
      // for an out-of-range index later read back as Missing instead of
      // the genuinely-ambiguous/corrupt state it actually is. Freeze and
      // fold nothing from this generation's tables/live-binding.
      if (activeHdr.peerCount > kPeerTableCapacity || activeHdr.cohortCount > kCohortTableCapacity ||
          activeHdr.terminalCount > kTerminalTableCapacity) {
        storeFrozen_ = true;
        txUpperBound_ = c.txBaseline;
        // Still proceed to the reserved-cell/ordinary-log fold (SLICE3)
        // unconditionally -- exactly like legacy reconstruct(), whose
        // LSN-safety/log-replay step runs regardless of snapshot/freeze
        // state, so a resumed store never reuses an LSN the aborted
        // attempt already consumed.
        c.phase = ReconstructPhase::ReservedCells;
        return ReconstructStepOutcome::Pending;
      }
      c.txBaseline = activeHdr.txGlobalUpperBoundCheckpoint;
      // Must be set here (not left to the OrdinaryLog phase's `if (value
      // > txUpperBound_)` fold alone): when NO newer TxReservation record
      // exists in the log, the snapshot checkpoint IS the durable value,
      // and the fold-forward comparison would otherwise never run,
      // silently leaving txUpperBound_ at its post-reset 0 -- i.e. a
      // witness-attested, committed counter read back as Missing.
      txUpperBound_ = c.txBaseline;
      factoryGrantConsumed_ = activeHdr.factoryGrantConsumed;
      factoryGrant_ = activeHdr.factoryGrant;
      c.phase = ReconstructPhase::Peers;
    } else if (activeSnapshotValid_ && !c.phaseAResult.witnessHeaderValid) {
      // Magic-valid but not independently corroborated right now: cannot
      // trust ANY individual field -- freeze, skip straight to the
      // reserved-cell/ordinary-log fold (nothing further to fold from
      // this generation's snapshot bytes).
      storeFrozen_ = true;
      txUpperBound_ = c.txBaseline;
      c.phase = ReconstructPhase::ReservedCells;
    } else {
      // Genesis / no valid snapshot: txBaseline stays 0, nothing to fold.
      txUpperBound_ = c.txBaseline;
      c.phase = ReconstructPhase::ReservedCells;
    }
    return ReconstructStepOutcome::Pending;
  }

  if (c.phase == ReconstructPhase::Peers) {
    const OtaSecuritySnapshotHeader& activeHdr = c.phaseAResult.activeHdr;
    if (c.peerIndex >= activeHdr.peerCount || c.peerIndex >= kPeerTableCapacity) {
      c.phase = ReconstructPhase::Cohorts;
      return ReconstructStepOutcome::Pending;
    }
    ::ota::platform::FlashRegion& snap = carve(activeBank_).snapshot();
    uint8_t raw[kPeerEntryBytes];
    // Same digest-already-verified reasoning as the legacy reconstruct():
    // this row lies within a snapshot whose entire 64 KiB was just
    // successfully read while computing the Phase-A-verified digest. A
    // read/decode failure here on a header-claimed-occupied entry is
    // therefore a real anomaly -- freeze, but keep scanning (never drop a
    // possibly-real later entry just because an earlier one faulted).
    if (!::ota::platform::isOk(snap.read(kPeerTableOffset + c.peerIndex * kPeerEntryBytes, raw, sizeof(raw)))) {
      storeFrozen_ = true;
      ++c.peerIndex;
      return ReconstructStepOutcome::Pending;
    }
    OtaSecurityPeerEntry e;
    if (!OtaSecurityPeerEntryCodec::decode(raw, sizeof(raw), e)) {
      storeFrozen_ = true;
      ++c.peerIndex;
      return ReconstructStepOutcome::Pending;
    }
    if ((e.flags & 0x1u) != 0) {  // occupied
      if (peerTableCount_ >= kPeerTableCapacity) {
        storeFrozen_ = true;
      } else {
        PeerTableEntry& te = peerTable_[peerTableCount_++];
        std::memcpy(te.key, e.fullPeerPublicKey, 32);
        te.index = c.peerIndex;
        te.head = e.rxHead;
      }
    }
    ++c.peerIndex;
    return ReconstructStepOutcome::Pending;
  }

  if (c.phase == ReconstructPhase::Cohorts) {
    const OtaSecuritySnapshotHeader& activeHdr = c.phaseAResult.activeHdr;
    if (c.cohortIndex >= activeHdr.cohortCount || c.cohortIndex >= kCohortTableCapacity) {
      c.phase = ReconstructPhase::Terminals;
      return ReconstructStepOutcome::Pending;
    }
    ::ota::platform::FlashRegion& snap = carve(activeBank_).snapshot();
    uint8_t raw[kCohortEntryBytes];
    if (!::ota::platform::isOk(snap.read(kCohortTableOffset + c.cohortIndex * kCohortEntryBytes, raw, sizeof(raw)))) {
      storeFrozen_ = true;
      ++c.cohortIndex;
      return ReconstructStepOutcome::Pending;
    }
    OtaSecurityCohortEntry e;
    if (!OtaSecurityCohortEntryCodec::decode(raw, sizeof(raw), e)) {
      storeFrozen_ = true;
      ++c.cohortIndex;
      return ReconstructStepOutcome::Pending;
    }
    if (cohortTableCount_ >= kCohortTableCapacity) {
      storeFrozen_ = true;
    } else {
      CohortTableEntry& te = cohortTable_[cohortTableCount_++];
      std::memcpy(te.key, e.groupContext, 92);
      te.index = c.cohortIndex;
      te.head = e.rxHead;
    }
    ++c.cohortIndex;
    return ReconstructStepOutcome::Pending;
  }

  if (c.phase == ReconstructPhase::Terminals) {
    const OtaSecuritySnapshotHeader& activeHdr = c.phaseAResult.activeHdr;
    if (c.terminalIndex >= activeHdr.terminalCount || c.terminalIndex >= kTerminalTableCapacity) {
      c.phase = ReconstructPhase::LiveBinding;
      return ReconstructStepOutcome::Pending;
    }
    ::ota::platform::FlashRegion& snap = carve(activeBank_).snapshot();
    uint8_t raw[kTerminalEntryBytes];
    if (!::ota::platform::isOk(snap.read(kTerminalTableOffset + c.terminalIndex * kTerminalEntryBytes, raw,
                                        sizeof(raw)))) {
      storeFrozen_ = true;
      ++c.terminalIndex;
      return ReconstructStepOutcome::Pending;
    }
    OtaSecurityTerminalEntry e;
    if (!OtaSecurityTerminalEntryCodec::decode(raw, sizeof(raw), e)) {
      storeFrozen_ = true;
      ++c.terminalIndex;
      return ReconstructStepOutcome::Pending;
    }
    if (terminalCount_ >= kTerminalTableCapacity) {
      storeFrozen_ = true;
    } else {
      OtaSecurityTerminalIndexEntry& te = terminalIndex_[terminalCount_++];
      te.location = (uint16_t)c.terminalIndex;  // snapshot-table slot -- source bit stays 0.
      te.flags = 0x1u;
      te.tupleFingerprint = computeTerminalTupleFingerprint(e.controller, e.campaign, e.session, e.attempt);
    }
    ++c.terminalIndex;
    return ReconstructStepOutcome::Pending;
  }

  if (c.phase == ReconstructPhase::LiveBinding) {
    constexpr uint32_t kLiveChunkBytes = 1024u;
    static_assert(kLiveBindingAreaBytes % kLiveChunkBytes == 0, "live-binding area must divide evenly into chunks");
    ::ota::platform::FlashRegion& snap = carve(activeBank_).snapshot();
    ::ota::platform::FlashStatus st =
        snap.read(kLiveBindingOffset + c.liveBindingChunkIndex * kLiveChunkBytes,
                 c.liveBindingScratch + c.liveBindingChunkIndex * kLiveChunkBytes, kLiveChunkBytes);
    if (!::ota::platform::isOk(st)) {
      // Same digest-already-verified reasoning: a liveBinding read
      // failure here cannot be silently treated as "no binding" -- freeze
      // rather than guess, but still finish the scheduled chunk count
      // (no partial-chunk retry loop) before moving to Finalize.
      storeFrozen_ = true;
    }
    ++c.liveBindingChunkIndex;
    if (c.liveBindingChunkIndex >= kLiveBindingAreaBytes / kLiveChunkBytes) {
      if (!storeFrozen_) {
        OtaSecurityLiveBinding lb;
        if (OtaSecurityLiveBindingCodec::decode(c.liveBindingScratch, sizeof(c.liveBindingScratch), lb)) {
          liveBinding_ = lb;
          liveBindingPresent_ = lb.present;
        } else {
          // decode() returning false collapses two very different real
          // outcomes that must NOT be treated alike: a genuinely never-
          // written area (every byte 0xFF -- the ordinary, expected
          // genesis/no-binding-yet case) versus a format-unsupported or
          // corrupted area (wrong magic/bad roster count on NON-blank
          // bytes) -- the latter is a real, committed-looking fact this
          // store cannot currently trust and must never silently expose
          // as "no live binding" by leaving liveBindingPresent_ at its
          // already-false default.
          bool allFf = true;
          for (uint32_t i = 0; i < kLiveBindingAreaBytes && allFf; ++i) {
            if (c.liveBindingScratch[i] != 0xFFu) allFf = false;
          }
          if (!allFf) storeFrozen_ = true;
        }
      }
      c.phase = ReconstructPhase::ReservedCells;
    }
    return ReconstructStepOutcome::Pending;
  }

  if (c.phase == ReconstructPhase::ReservedCells) {
    // One reserved cell (seal=254, then switch=255) folded per call: pure
    // LSN-safety advance, so a resumed store never reuses an LSN an
    // aborted compaction attempt already consumed. Runs regardless of
    // freeze/snapshot state, exactly like legacy reconstruct()'s
    // identical unconditional fold. ~128B read per call.
    OtaSecurityAppendEngine engine = engineFor(activeBank_);
    const uint32_t reservedCellIndex = (c.reservedIdx == 0) ? kSealCellIndex : kSwitchCellIndex;
    OtaSecurityCellHeader rHeader;
    uint8_t rPayload[kCellPayloadBytes];
    bool rIoErr = false;
    OtaSecurityEvidence rEv = engine.readCell(reservedCellIndex, rHeader, rPayload, rIoErr);
    if (rEv == OtaSecurityEvidence::Committed && rHeader.lsn + 1 > nextLsn_) {
      nextLsn_ = rHeader.lsn + 1;
    }
    if (c.reservedIdx == 0) {
      // Remember the seal cell's own evidence/header for Finalize's
      // pending-seal-resume detection below -- zero EXTRA I/O there
      // (one physical read total for this cell across the whole cycle,
      // not two).
      c.sealHeader = rHeader;
      c.sealEvidence = rEv;
    }
    ++c.reservedIdx;
    if (c.reservedIdx >= 2) {
      c.phase = ReconstructPhase::OrdinaryLog;
    }
    return ReconstructStepOutcome::Pending;
  }

  if (c.phase == ReconstructPhase::OrdinaryLog) {
    // One physical ordinary-log position folded per call: 128B data cell
    // + 16B witness record = 144B, well under the approved per-step
    // budget. Mirrors legacy reconstruct()'s identical per-position scan
    // exactly, via the SAME foldConfirmedOrdinaryCellRecord()/
    // foldAmbiguousOrdinaryCellRecord() pure helpers (no divergent copy).
    if (c.logPos >= kOrdinaryCellCount) {
      c.phase = ReconstructPhase::Finalize;
      return ReconstructStepOutcome::Pending;
    }
    OtaSecurityAppendEngine engine = engineFor(activeBank_);
    const uint32_t pos = c.logPos;
    OtaSecurityCellHeader header;
    uint8_t payload[kCellPayloadBytes];
    bool dataIoErr = false;
    OtaSecurityEvidence dataEv = engine.readCell(pos, header, payload, dataIoErr);

    if (dataEv == OtaSecurityEvidence::AbsentBytes) {
      uint64_t witLsn = 0;
      bool witIoErr = false;
      OtaSecurityEvidence wEv = engine.readWitnessRecord(pos, 0u, witLsn, witIoErr);
      if (wEv != OtaSecurityEvidence::AbsentBytes) {
        // Data gone, witness non-blank: cannot attribute to any context.
        storeFrozen_ = true;
      }
      ++c.logPos;
      return ReconstructStepOutcome::Pending;
    }

    const bool headerAttributable =
        (dataEv == OtaSecurityEvidence::Committed || dataEv == OtaSecurityEvidence::BodyOnly);
    if (!headerAttributable) {
      // Unprovable / IoError: header itself can't be trusted.
      uint64_t witLsn = 0;
      bool witIoErr = false;
      OtaSecurityEvidence wEv = engine.readWitnessRecord(pos, 0u, witLsn, witIoErr);
      if (wEv != OtaSecurityEvidence::AbsentBytes) {
        storeFrozen_ = true;
      }
      ++c.logPos;
      return ReconstructStepOutcome::Pending;
    }

    if (header.lsn + 1 > nextLsn_) nextLsn_ = header.lsn + 1;
    c.anyAttributable = true;
    c.highestAttributablePosition = pos;

    bool confirmed = false;
    if (dataEv == OtaSecurityEvidence::Committed && c.phaseAResult.witnessHeaderValid) {
      uint32_t expectedCrc =
          engine.computeWitnessContextualCrc(storeIdentity_, c.phaseAResult.activeDigest, activeGeneration_,
                                             (uint16_t)otherBank(activeBank_), pos, header.lsn);
      uint64_t confirmedLsn = 0;
      bool confirmIoErr = false;
      OtaSecurityEvidence wEv = engine.readWitnessRecord(pos, expectedCrc, confirmedLsn, confirmIoErr);
      confirmed = (wEv == OtaSecurityEvidence::Committed && confirmedLsn == header.lsn);
    }

    if (confirmed) {
      foldConfirmedOrdinaryCellRecord(header, payload, pos, c.txAmbiguous, c.logLiveEvidence,
                                      c.highestLiveBindingTxLsn, c.haveLiveBindingTx);
    } else {
      foldAmbiguousOrdinaryCellRecord(header, payload, c.txAmbiguous, c.liveBindingTxAmbiguous);
    }
    ++c.logPos;
    return ReconstructStepOutcome::Pending;
  }

  if (c.phase == ReconstructPhase::Finalize) {
    // Resolve the bounded, fixed-size ambiguity/position/LSN facts the
    // ReservedCells+OrdinaryLog phases just folded -- SLICE3's extension
    // of this SAME cursor (txUpperBound_ was already published at
    // HeaderFields; every branch sets it).
    nextFreeSlot_ = c.anyAttributable ? c.highestAttributablePosition + 1 : 0;
    txFrozen_ = c.txAmbiguous;
    // peerTable_[i].frozen / cohortTable_[i].frozen were already
    // maintained in real time by the fold helpers above (no separate
    // post-loop resolution needed).

    // Resolve the LiveBinding multi-cell transaction log: a log-
    // confirmed transaction DOMINATES the snapshot baseline exactly like
    // TX/peer/cohort facts do. Only the transaction at the HIGHEST
    // touched LSN matters -- requiring a contiguous, consistent history
    // through the highest evidenced LSN, never a silent fallback to an
    // older complete transaction when a newer one was attempted but left
    // incomplete.
    if (c.haveLiveBindingTx) {
      const OtaSecurityLiveBindingLogEvidence& ev = c.logLiveEvidence;
      bool complete = true;
      for (uint32_t i = 0; i < kLiveBindingChunkCount; ++i) {
        if (!ev.have[i]) {
          complete = false;
          break;
        }
      }
      if (complete) {
        uint8_t full[kLiveBindingAreaBytes] = {0};
        uint32_t off = 0;
        for (uint32_t i = 0; i < kLiveBindingChunkCount && off < kLiveBindingFixedBytes; ++i) {
          uint32_t len = std::min<uint32_t>(kLiveBindingChunkDataBytes, kLiveBindingFixedBytes - off);
          std::memcpy(full + off, ev.bytes[i], len);
          off += len;
        }
        OtaSecurityLiveBinding lb;
        if (OtaSecurityLiveBindingCodec::decode(full, sizeof(full), lb)) {
          liveBinding_ = lb;
          liveBindingPresent_ = lb.present;
        } else {
          storeFrozen_ = true;  // fully-confirmed chunks that still fail to decode: real damage, not missing.
        }
      } else {
        // The highest-LSN transaction attempted is incomplete: a
        // possible commitment that cannot be assembled and must not be
        // silently discarded in favor of an older, complete one.
        storeFrozen_ = true;
      }
    } else if (c.liveBindingTxAmbiguous) {
      storeFrozen_ = true;
    }

    // Detect a durably-committed-but-never-activated compaction seal in
    // the ACTIVE bank (matching its OWN current generation) -- see
    // legacy reconstruct()'s identical check for the full rationale.
    // Reuses c.sealHeader/c.sealEvidence captured once during
    // ReservedCells (zero EXTRA I/O here).
    if (!storeFrozen_ && !compactionInProgress_) {
      if (c.sealEvidence == OtaSecurityEvidence::Committed &&
          c.sealHeader.recordType == OtaSecurityRecordType::SealRecord &&
          c.sealHeader.generation == activeGeneration_) {
        compactionInProgress_ = true;
        compactionSource_ = activeBank_;
        compactionDest_ = otherBank(activeBank_);
        compactionNewGeneration_ = activeGeneration_ + 1;
        compactionPhase_ = CompactionPhase::SealSource;
        compactionEraseCursor_ = 0;
      }
    }

    reconstructFoldReady_ = true;
    c.phase = ReconstructPhase::Done;
    return ReconstructStepOutcome::Ready;
  }

  return ReconstructStepOutcome::Failed;  // unreachable for a well-formed cursor; never a silent Pending loop.
}

inline void OtaSecurityStore::cancelReconstructCursor(const OtaSecurityOperationTicket& ticket) {
  ReconstructCursor& c = reconstructCursor_;
  if (c.phase == ReconstructPhase::Idle) return;  // nothing held; silent no-op.
  if (!ticket.valid() || ticket.issuerInstanceEpoch != c.issuerInstanceEpoch || ticket.owner != c.owner ||
      ticket.id != c.ticketId) {
    return;  // foreign/stale ticket: nothing of THIS caller's was ever actually held.
  }
  // If Phase A's inner cursor is still mid-flight, release it too -- its
  // ticket is private to this (now-cancelled) ReconstructCursor and would
  // otherwise be unreachably stuck holding bankEvidenceCursor_ forever.
  if (c.phaseATicket.valid()) cancelBankEvidenceCursor(c.phaseATicket);
  reconstructFoldReady_ = false;
  c = ReconstructCursor{};
}

// --- Cold reconstruction ----------------------------------------------------
inline void OtaSecurityStore::reconstruct() {
  // SLICE4: this is the deliberate one-time, synchronous cold-open
  // entrypoint (constructor-adjacent setup / explicit caller-driven
  // re-derivation), NOT a mid-operation fallback -- unlike the old
  // inline duplicate algorithm this used to run, it now drains the SAME
  // typed, bounded stepReconstruct() engine that refreshIfPhysicallyStale()
  // steps incrementally. This eliminates the divergent-copy risk entirely:
  // there is only ONE reconstruction algorithm now, exercised either one
  // full synchronous drain at a time (here) or one bounded step at a time
  // (refreshIfPhysicallyStale()/stepReconstruct() callers).
  //
  // Unbound/unknown physical identity (zero physicalToken) OR a refused
  // explicit-arbiter mismatch: refuse BEFORE any I/O, never infer a
  // physical identity from anything else.
  if (misconfigured_) return;

  // `this` is used as the internal owner sentinel for this self-driven
  // drain -- distinct from any real external caller's OtaSecurityOperationOwner
  // (adapters/tests always pass their OWN object identity, never the Store
  // itself), so this can never collide with or be stolen by a foreign
  // caller's ticket.
  OtaSecurityOperationTicket ticket;
  // Budget, one-step-per-call throughout (never an unbounded while
  // (Pending) loop): ~160 PhaseA bank-evidence steps (two 64 KiB digests
  // at <=1024 B/step) + up to kPeerTableCapacity (350) + kCohortTableCapacity
  // (4) + kTerminalTableCapacity (384) one-row-per-call snapshot-fold
  // steps + up to 4 LiveBinding 1024B-chunk steps + 2 ReservedCells steps
  // + kOrdinaryCellCount (254) OrdinaryLog steps (one physical log
  // position per step) + a small fixed number of orchestration-only
  // steps (Idle/ObserveHeadersAndClaims/Select/Recheck/.../Finalize
  // transitions): ~160+350+4+384+4+2+254+~10 =~ 1168 worst case. 1536
  // covers this with headroom; documented bound, never an unbounded
  // while(Pending) loop.
  constexpr int kMaxReconstructDrainSteps = 1536;
  for (int step = 0; step < kMaxReconstructDrainSteps; ++step) {
    ReconstructStepOutcome outcome = stepReconstruct(static_cast<OtaSecurityOperationOwner>(this), ticket);
    if (outcome == ReconstructStepOutcome::Ready) {
      // Release the shared reconstructCursor_ back to Idle now that this
      // self-contained synchronous drain is complete -- otherwise it
      // stays parked at Done, forever refusing any LATER bounded rebuild
      // (e.g. refreshIfPhysicallyStale()'s foreign-change path) a fresh
      // ticket, since a parked cursor's exact-ticket-match check would
      // reject that new, different ticket as OwnershipDenied. The already
      // resolved facts (tables/counters/activeBank_/etc.) live in their
      // OWN Store members, not in the cursor, so this never discards them.
      cancelReconstructCursor(ticket);
      return;
    }
    if (outcome == ReconstructStepOutcome::Failed || outcome == ReconstructStepOutcome::OwnershipDenied) {
      // A structural failure (or a defensive ownership conflict that
      // should be impossible for this self-owned ticket) leaves
      // reconstructed state partial/unknown -- fail closed rather than
      // silently return with some fields folded and others not.
      storeFrozen_ = true;
      cancelReconstructCursor(ticket);
      return;
    }
    // Pending: keep stepping this SAME retained ticket/cursor.
  }
  // Exceeded the documented bound -- fail closed; never silently return
  // with a partial fold or loop unbounded.
  storeFrozen_ = true;
  cancelReconstructCursor(ticket);
}

inline OtaSecurityStore::RefreshOutcome OtaSecurityStore::refreshIfPhysicallyStale() {
  if (storeFrozen_) return RefreshOutcome::AlreadyFresh;
  // Resuming our OWN in-flight ordinary op: physical partition ownership
  // has been held continuously (across every prior WouldBlock) since the
  // op started, so NO foreign instance could have changed anything here
  // -- and the exact slot check below (#2) would otherwise misclassify
  // our own not-yet-witnessed in-progress body/marker write as a
  // foreign writer's collision, destructively reconstruct()-ing mid-op
  // and silently discarding this instance's still-ambiguous RAM counts
  // (e.g. cohortTableCount_/peerTableCount_) before they are genuinely
  // durable. Skip the whole staleness re-derivation while resuming.
  if (hasPendingOrdinaryOperation()) return RefreshOutcome::AlreadyFresh;

  // SLICE4: a bounded internal rebuild from a PRIOR foreign-change
  // detection (below) is already mid-flight under rebuildTicket_ -- step
  // it exactly once more under the SAME retained ticket rather than
  // re-deriving staleness from scratch (which would add redundant reads
  // on top of the cursor's own already-bounded per-step budget).
  if (rebuildTicket_.valid()) {
    ReconstructStepOutcome stepOutcome = stepReconstruct(static_cast<OtaSecurityOperationOwner>(this), rebuildTicket_);
    if (stepOutcome == ReconstructStepOutcome::Ready) {
      // Release the shared reconstructCursor_ back to Idle -- otherwise
      // it stays parked at Done and refuses any LATER rebuild attempt (a
      // fresh ticket) as OwnershipDenied. The resolved facts already live
      // in their own Store members, not in the cursor.
      cancelReconstructCursor(rebuildTicket_);
      rebuildTicket_ = OtaSecurityOperationTicket{};
      return RefreshOutcome::AlreadyFresh;
    }
    if (stepOutcome == ReconstructStepOutcome::Pending) return RefreshOutcome::CaughtUpOneStep;
    // Failed or OwnershipDenied: fail closed, never silently fall back to
    // a synchronous full reconstruct() or stale cached state.
    cancelReconstructCursor(rebuildTicket_);
    rebuildTicket_ = OtaSecurityOperationTicket{};
    return RefreshOutcome::Uncertain;
  }

  OtaSecuritySnapshotHeader hdrA, hdrB;
  bool magicA = decodeSnapshotHeader(OtaSecurityBankId::A, hdrA);
  bool magicB = decodeSnapshotHeader(OtaSecurityBankId::B, hdrB);
  bool activeIsA = (activeBank_ == OtaSecurityBankId::A);
  bool activeMagicNow = activeIsA ? magicA : magicB;
  uint32_t activeGenNow = activeIsA ? hdrA.generation : hdrB.generation;

  // Cheap check #0: has the OPPOSITE bank now been witness-confirmed (by
  // a FOREIGN instance's completed compaction) as a real destination at a
  // generation strictly higher than what we believe is current? A
  // completed compaction seals/switches our cached active (now-SOURCE)
  // bank WITHOUT touching its own snapshot header at all, and its next
  // free ordinary slot can remain genuinely blank (the source's log is
  // never erased) -- so neither check #1 nor check #2 below would catch
  // this on their own, letting a stale instance keep appending to an
  // already-superseded bank whose new records would be silently dropped
  // on a future cold reconstruct() (Sol finding #1). The opposite bank's
  // witness (physically stored in OUR OWN cached active bank's tail) is
  // exactly the independent, foreign-write-proof signal needed here.
  uint32_t oppositeWitnessGen = 0;
  WitnessGenerationClaim oppositeClaim = witnessClaimedGeneration(otherBank(activeBank_), oppositeWitnessGen);
  if (oppositeClaim == WitnessGenerationClaim::Error) {
    // Genuinely UNKNOWN whether a foreign compaction completed -- per
    // Sol H2, this must NEVER silently fall through as "no claim" (which
    // would let a stale cached counter be returned/CAS'd against an
    // already-superseded bank). Fail closed for exactly this bounded
    // step without doing any MORE I/O to try to disambiguate (that would
    // hide an expensive retry behind what may be a transient fault and
    // blow the per-step budget); the caller retries fresh next call.
    return RefreshOutcome::Uncertain;
  }
  bool oppositeClaims = oppositeClaim == WitnessGenerationClaim::Present;
  bool foreignCompactionCompleted = oppositeClaims && oppositeWitnessGen > activeGeneration_;

  // Cheap check #1: did a foreign compaction flip the active bank/
  // generation out from under us since our last reconstruct()/refresh?
  bool foreignChange = foreignCompactionCompleted || (activeMagicNow != activeSnapshotValid_) ||
                        (activeMagicNow && activeGenNow != activeGeneration_);

  // Cheap check #2: is the exact physical slot our next ordinary append
  // would target still genuinely blank? A foreign writer (a second,
  // independently-opened Store instance over the SAME physical bytes)
  // landing here first is exactly the race Sol's review flagged. Try a
  // BOUNDED single-cell catch-up first (see
  // tryApplyForeignOrdinaryCellIncrementally's doc comment); only the
  // genuinely-harder remaining cases escalate to the full reconstruct()
  // below.
  if (!foreignChange && nextFreeSlot_ < kOrdinaryCellCount) {
    OrdinaryCellCatchupOutcome catchup = tryApplyForeignOrdinaryCellIncrementally(nextFreeSlot_);
    if (catchup == OrdinaryCellCatchupOutcome::Applied) return RefreshOutcome::CaughtUpOneStep;
    if (catchup == OrdinaryCellCatchupOutcome::NeedsFullReconstruct) foreignChange = true;
    // NoForeignCell: genuinely nothing new; leave foreignChange false.
  }

  if (foreignChange) {
    // SLICE4: rare path (a real bank/generation compaction switch, or an
    // ordinary record this bounded single-cell helper deliberately does
    // not cover -- see its doc comment). Re-derive ALL state from
    // scratch, but via the SAME bounded, resumable stepReconstruct()
    // engine -- never the old unbounded synchronous reconstruct() full
    // drain. This call only KICKS OFF the internal rebuild (first step is
    // always Pending, by construction -- see stepReconstruct()'s Idle
    // branch); subsequent refreshIfPhysicallyStale() calls continue it
    // above via rebuildTicket_. CaughtUpOneStep already maps to
    // OtaSequenceBackingResult::WouldBlock at every call site, so a
    // caller's CAS/read naturally gets WouldBlock-then-fresh-retry
    // instead of this call ever blocking synchronously.
    ReconstructStepOutcome stepOutcome = stepReconstruct(static_cast<OtaSecurityOperationOwner>(this), rebuildTicket_);
    if (stepOutcome == ReconstructStepOutcome::Ready) {
      cancelReconstructCursor(rebuildTicket_);
      rebuildTicket_ = OtaSecurityOperationTicket{};
      return RefreshOutcome::AlreadyFresh;
    }
    if (stepOutcome == ReconstructStepOutcome::Pending) return RefreshOutcome::CaughtUpOneStep;
    cancelReconstructCursor(rebuildTicket_);
    rebuildTicket_ = OtaSecurityOperationTicket{};
    return RefreshOutcome::Uncertain;
  }
  return RefreshOutcome::AlreadyFresh;
}

// Deliberately scoped, bounded (one ~128B cell read + one ~32B witness
// read, zero program/erase calls) attempt to fold EXACTLY ONE foreign-
// written ordinary cell at `pos` into the live RAM structures without
// the full reconstruct()'s from-scratch re-derivation. See the class
// declaration's doc comment for the exact, honestly-reported set of
// cases this covers vs. falls back on.
inline OtaSecurityStore::OrdinaryCellCatchupOutcome OtaSecurityStore::tryApplyForeignOrdinaryCellIncrementally(
    uint32_t pos) {
  if (pos >= kOrdinaryCellCount) return OrdinaryCellCatchupOutcome::NoForeignCell;
  OtaSecurityAppendEngine engine = engineFor(activeBank_);
  OtaSecurityCellHeader header;
  uint8_t payload[kCellPayloadBytes];
  bool dataIoErr = false;
  OtaSecurityEvidence dataEv = engine.readCell(pos, header, payload, dataIoErr);
  if (dataEv == OtaSecurityEvidence::AbsentBytes) {
    // Blank data bytes ALONE never prove "genuinely never written" --
    // they describe the storage, not the authority (per the class doc
    // comments' cold-evidence rules). Mirror reconstruct()'s identical
    // Absent-data handling: independently check the corresponding
    // opposite-bank witness slot for THIS exact physical position before
    // concluding nothing foreign happened here. A non-blank witness at a
    // blank data slot means a real commitment may have existed and only
    // the data cell was lost (e.g. a partial/failed erase-adjacent
    // disturb) -- this specific paired/unattributable case is explicitly
    // outside this bounded helper's single-cell-fold guarantee and must
    // escalate to the full reconstruct() path, which freezes the store
    // rather than silently treating the slot as free and reusable (never
    // resurrecting it as "nothing here" and never letting a subsequent
    // caller re-issue/overwrite the same counter range). This adds
    // exactly one bounded (~32B) witness read, not a fresh full scan.
    uint64_t witLsn = 0;
    bool witIoErr = false;
    OtaSecurityEvidence wEv = engine.readWitnessRecord(pos, 0u, witLsn, witIoErr);
    if (wEv != OtaSecurityEvidence::AbsentBytes) return OrdinaryCellCatchupOutcome::NeedsFullReconstruct;
    return OrdinaryCellCatchupOutcome::NoForeignCell;
  }
  if (dataEv != OtaSecurityEvidence::Committed) {
    // BodyOnly/Unprovable/IoError: cannot be safely folded by this
    // bounded single-cell helper -- the full reconstruct() path already
    // correctly handles every one of these evidence classes (freezing
    // the specific attributable context, never discarding a possible
    // commitment).
    return OrdinaryCellCatchupOutcome::NeedsFullReconstruct;
  }

  // Deliberately scoped to single-cell, non-chunked, non-structural
  // record types; see this method's declaration-site doc comment.
  switch (header.recordType) {
    case OtaSecurityRecordType::TxReservation:
    case OtaSecurityRecordType::RxPeerAdvance:
    case OtaSecurityRecordType::RxGroupAdvance:
    case OtaSecurityRecordType::TerminalAttempt:
    case OtaSecurityRecordType::FactoryGrantRecord:
      break;
    default:
      return OrdinaryCellCatchupOutcome::NeedsFullReconstruct;
  }

  // checkWitnessAttestsBank()'s snapshot digest is a warm cache hit here
  // (ordinary-log appends never touch the peer/cohort/terminal snapshot
  // region, so the cache populated by the last reconstruct()/compaction
  // at this exact generation remains valid) -- bounded, not a fresh
  // 64KiB stream.
  uint64_t activeDigest = 0;
  if (!checkWitnessAttestsBank(activeBank_, activeGeneration_, activeDigest)) {
    return OrdinaryCellCatchupOutcome::NeedsFullReconstruct;
  }
  uint32_t expectedCrc = engine.computeWitnessContextualCrc(storeIdentity_, activeDigest, activeGeneration_,
                                                            (uint16_t)otherBank(activeBank_), pos, header.lsn);
  uint64_t confirmedLsn = 0;
  bool confirmIoErr = false;
  OtaSecurityEvidence wEv = engine.readWitnessRecord(pos, expectedCrc, confirmedLsn, confirmIoErr);
  if (wEv != OtaSecurityEvidence::Committed || confirmedLsn != header.lsn) {
    return OrdinaryCellCatchupOutcome::NeedsFullReconstruct;  // not (yet) witness-confirmed: fall back.
  }

  // Fold exactly like reconstruct()'s "confirmed" branch, for this ONE
  // record only.
  switch (header.recordType) {
    case OtaSecurityRecordType::TxReservation: {
      uint32_t value = 0;
      getU32(payload, sizeof(payload), 0, value);
      if (value > txUpperBound_) txUpperBound_ = value;
      txFrozen_ = false;
      break;
    }
    case OtaSecurityRecordType::RxPeerAdvance: {
      uint8_t key[32];
      getBytes(payload, sizeof(payload), 0, key, 32);
      uint32_t head = 0;
      getU32(payload, sizeof(payload), 32, head);
      PeerTableEntry* existing = findPeer(key);
      if (existing == nullptr) {
        if (peerTableCount_ >= kPeerTableCapacity) return OrdinaryCellCatchupOutcome::NeedsFullReconstruct;
        PeerTableEntry& te = peerTable_[peerTableCount_];
        std::memcpy(te.key, key, 32);
        te.index = peerTableCount_;
        te.head = head;
        te.frozen = false;
        ++peerTableCount_;
      } else {
        if (head > existing->head) existing->head = head;
        existing->frozen = false;
      }
      break;
    }
    case OtaSecurityRecordType::RxGroupAdvance: {
      uint8_t key[92];
      getBytes(payload, sizeof(payload), 0, key, 92);
      uint32_t head = 0;
      getU32(payload, sizeof(payload), 92, head);
      CohortTableEntry* existing = findCohort(key);
      if (existing == nullptr) {
        if (cohortTableCount_ >= kCohortTableCapacity) return OrdinaryCellCatchupOutcome::NeedsFullReconstruct;
        CohortTableEntry& te = cohortTable_[cohortTableCount_];
        std::memcpy(te.key, key, 92);
        te.index = cohortTableCount_;
        te.head = head;
        te.frozen = false;
        ++cohortTableCount_;
      } else {
        if (head > existing->head) existing->head = head;
        existing->frozen = false;
      }
      break;
    }
    case OtaSecurityRecordType::TerminalAttempt: {
      OtaSecurityTerminalEntry e;
      if (!OtaSecurityTerminalEntryCodec::decode(payload, sizeof(payload), e)) {
        return OrdinaryCellCatchupOutcome::NeedsFullReconstruct;
      }
      if (terminalCount_ >= kTerminalTableCapacity) return OrdinaryCellCatchupOutcome::NeedsFullReconstruct;
      OtaSecurityTerminalIndexEntry& te = terminalIndex_[terminalCount_++];
      te.location = (uint16_t)(pos & kTerminalLocIndexMask) | kTerminalLocSourceBit;
      te.flags = 0x1u;
      te.tupleFingerprint = computeTerminalTupleFingerprint(e.controller, e.campaign, e.session, e.attempt);
      break;
    }
    case OtaSecurityRecordType::FactoryGrantRecord: {
      OtaSecurityFactoryGrant g;
      getU64(payload, sizeof(payload), 0, g.deviceUid);
      getBytes(payload, sizeof(payload), 8, g.fullLocalPublicKey, 32);
      getU32(payload, sizeof(payload), 40, g.profile);
      getU32(payload, sizeof(payload), 44, g.layout);
      getU32(payload, sizeof(payload), 48, g.role);
      getU32(payload, sizeof(payload), 52, g.initialRole);
      getBytes(payload, sizeof(payload), 56, g.consentOwner, 32);
      getU64(payload, sizeof(payload), 88, g.transaction);
      factoryGrant_ = g;
      factoryGrantConsumed_ = true;
      break;
    }
    default:
      return OrdinaryCellCatchupOutcome::NeedsFullReconstruct;  // unreachable given the switch above.
  }

  if (header.lsn + 1 > nextLsn_) nextLsn_ = header.lsn + 1;
  nextFreeSlot_ = pos + 1;
  return OrdinaryCellCatchupOutcome::Applied;
}

// --- TX ----------------------------------------------------------------
inline OtaSequenceBackingResult OtaSecurityStore::openExistingTx() {
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  {
    BoundedReadRefreshOutcome refreshOutcome = refreshForBoundedReadNeedsRetry();
    if (refreshOutcome == BoundedReadRefreshOutcome::Unknown) return OtaSequenceBackingResult::Uncertain;
    if (refreshOutcome == BoundedReadRefreshOutcome::Retry) return OtaSequenceBackingResult::WouldBlock;
  }
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  if (txFrozen_) return OtaSequenceBackingResult::Uncertain;
  if (txUpperBound_ == 0) return OtaSequenceBackingResult::Missing;
  txOpened_ = true;
  return OtaSequenceBackingResult::Committed;
}

inline OtaSequenceBackingResult OtaSecurityStore::readTxCounter(uint32_t& outReservedUpperBound) {
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  // Reads participate in the same bounded staleness check as mutations:
  // a foreign writer's already-durable commit must never be masked by a
  // stale RAM cache, and the catch-up itself must stay within the
  // approved per-step byte/op budget (never a hidden full reconstruct()).
  {
    BoundedReadRefreshOutcome refreshOutcome = refreshForBoundedReadNeedsRetry();
    if (refreshOutcome == BoundedReadRefreshOutcome::Unknown) return OtaSequenceBackingResult::Uncertain;
    if (refreshOutcome == BoundedReadRefreshOutcome::Retry) return OtaSequenceBackingResult::WouldBlock;
  }
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  if (txFrozen_) return OtaSequenceBackingResult::Uncertain;
  if (txUpperBound_ == 0) return OtaSequenceBackingResult::Missing;
  outReservedUpperBound = txUpperBound_;
  return OtaSequenceBackingResult::Committed;
}

inline OtaSequenceBackingResult OtaSecurityStore::reserveTx(uint32_t expectedCurrentUpperBound, uint32_t blockSize,
                                                            uint32_t& outNewUpperBound,
                                                            OtaSecurityOperationOwner owner,
                                                            OtaSecurityOperationTicket& ticket) {
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  if (txFrozen_) return OtaSequenceBackingResult::Uncertain;
  // A null owner can never legitimately hold or resume an in-flight op
  // (see ordinaryOpFreeOrResuming/startOrdinaryOp): explicitly refuse
  // rather than silently treating an absent caller identity as a
  // trusted "any" that could be mistaken for, or collide with, a real
  // owner's ticket.
  if (owner == nullptr) return OtaSequenceBackingResult::OwnershipDenied;
  // A DIFFERENT request -- OR ANY caller (even the legitimate owner)
  // that does not present the EXACT ticket already holding an in-flight
  // op -- is refused (busy) rather than stomping it, or being silently
  // collected just because the caller's owner/args happen to match; see
  // OtaSecurityOperationTicket's doc comment on why (owner, args) alone
  // is no longer a sufficient resume credential.
  if (!ordinaryOpFreeOrResuming(OrdinaryOpKind::ReserveTx, owner, ticket)) return OtaSequenceBackingResult::WouldBlock;
  bool resuming = ordinaryOpTicketMatches(OrdinaryOpKind::ReserveTx, owner, ticket);
  if (!resuming && compactionInProgress_) return OtaSequenceBackingResult::WouldBlock;
  // Physical partition ownership MUST be acquired on a fresh start and
  // remains held across every resumed step of this op (released only
  // once the op reaches Committed/Failed) -- STOREPLAN cross-instance
  // arbitration contract: a foreign owner (a sibling Store wrapper
  // sharing this same arbiter) means WouldBlock, never proceeding with
  // this instance's possibly-stale view.
  if (!acquirePartitionOwnership()) return OtaSequenceBackingResult::WouldBlock;
  struct ReleaseGuard {
    OtaSecurityStore* s;
    ~ReleaseGuard() {
      if (!s->hasPendingOrdinaryOperation()) s->releasePartitionOwnership();
    }
  } releaseGuard{this};
  if (!resuming) {
    RefreshOutcome freshness = refreshIfPhysicallyStale();
    if (freshness == RefreshOutcome::Uncertain) {
      // Opposite bank's witness generation claim could not be determined
      // (Sol H2): fail closed for this step rather than compare against
      // a view that might already be stale relative to an undetectable
      // foreign compaction.
      return OtaSequenceBackingResult::Uncertain;
    }
    if (freshness == RefreshOutcome::CaughtUpOneStep) {
      // A bounded single-cell catch-up step was just performed; this
      // instance's counter is not YET guaranteed fully fresh (there may
      // be more foreign cells beyond this one) -- return WouldBlock now
      // rather than comparing against a still-possibly-stale value, per
      // the per-step budget (no hidden extra I/O this same call).
      return OtaSequenceBackingResult::WouldBlock;
    }
    if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
    if (txFrozen_) return OtaSequenceBackingResult::Uncertain;
    if (txUpperBound_ == 0) return OtaSequenceBackingResult::Missing;
    if (expectedCurrentUpperBound != txUpperBound_) return OtaSequenceBackingResult::Conflict;
    if (blockSize == 0 || txUpperBound_ > UINT32_MAX - blockSize) return OtaSequenceBackingResult::Uncertain;
    uint32_t candidate = txUpperBound_ + blockSize;
    // Persist the original CAS predecessor/blockSize too (not just the
    // computed candidate): MAIN's correction -- a resuming call
    // presenting a DIFFERENT expectedCurrentUpperBound/blockSize is a
    // genuinely different request, not merely a different result, and
    // must be caught by the exact-request-match check below, not only
    // by comparing the final published value. `candidate` STAYS at
    // offset 0 -- reconstruct()'s and tryApplyForeignOrdinaryCellIncrementally()'s
    // TxReservation decode both read the committed value from offset 0
    // and must not be touched; the new CAS fields are appended AFTER it.
    uint8_t payload[kCellPayloadBytes] = {0};
    putU32(payload, sizeof(payload), 0, candidate);
    putU32(payload, sizeof(payload), 4, expectedCurrentUpperBound);
    putU32(payload, sizeof(payload), 8, blockSize);
    if (!startOrdinaryOp(OrdinaryOpKind::ReserveTx, owner, OtaSecurityRecordType::TxReservation, 0, payload, 12, 1, 0,
                        ticket)) {
      return OtaSequenceBackingResult::NoCapacity;  // pre-mutation check failed: state unchanged.
    }
    // Defer the first physical step to the NEXT (resuming) call: a fresh
    // start's refresh/validation reads above already consume a
    // meaningful share of the per-step byte budget, and bundling the
    // first program call into the SAME call would exceed it -- see the
    // per-step I/O budget test. `ticket` now holds the fresh handle the
    // caller MUST present on its next call.
    return OtaSequenceBackingResult::WouldBlock;
  }
  // Resuming completion: the CAS predecessor/blockSize/candidate actually
  // being driven to completion are whatever startOrdinaryOp captured at
  // the FRESH start call -- NEVER this call's arguments. MAIN's
  // correction: it is NOT enough to silently ignore changed
  // expectedCurrentUpperBound/blockSize and keep publishing the original
  // candidate -- a caller presenting DIFFERENT CAS arguments here must be
  // told its request does not match the one in flight (Conflict),
  // WITHOUT taking any physical step and WITHOUT disturbing the original
  // ticket/op, so it never mistakes Committed for its OWN changed
  // request having landed.
  uint32_t candidate = 0;
  uint32_t originalExpectedCurrentUpperBound = 0;
  uint32_t originalBlockSize = 0;
  getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 0, candidate);
  getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 4, originalExpectedCurrentUpperBound);
  getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 8, originalBlockSize);
  if (expectedCurrentUpperBound != originalExpectedCurrentUpperBound || blockSize != originalBlockSize) {
    return OtaSequenceBackingResult::Conflict;
  }
  OrdinaryOpStepOutcome outcome = stepPendingOrdinaryOp(nullptr);
  if (outcome == OrdinaryOpStepOutcome::InProgress) return OtaSequenceBackingResult::WouldBlock;
  if (outcome == OrdinaryOpStepOutcome::Failed) {
    txFrozen_ = true;  // any post-mutation ambiguity permanently freezes TX until a fresh reconstruct().
    ticket = OtaSecurityOperationTicket{};  // terminal result: burn the ticket, never replayable.
    return OtaSequenceBackingResult::Uncertain;
  }
  txUpperBound_ = candidate;
  outNewUpperBound = candidate;
  ticket = OtaSecurityOperationTicket{};  // terminal result: burn the ticket, never replayable.
  return OtaSequenceBackingResult::Committed;
}

inline OtaSequenceBackingResult OtaSecurityStore::commissionVirginTx(uint32_t initialUpperBound,
                                                                     bool factoryGrantAuthorized,
                                                                     OtaSecurityOperationOwner owner,
                                                                     OtaSecurityOperationTicket& ticket) {
  if (storeFrozen_ || txFrozen_) return OtaSequenceBackingResult::Uncertain;
  if (!factoryGrantAuthorized) return OtaSequenceBackingResult::OwnershipDenied;
  if (owner == nullptr) return OtaSequenceBackingResult::OwnershipDenied;  // see reserveTx's nullptr-owner doc comment.
  if (!ordinaryOpFreeOrResuming(OrdinaryOpKind::CommissionVirginTx, owner, ticket))
    return OtaSequenceBackingResult::WouldBlock;
  bool resuming = ordinaryOpTicketMatches(OrdinaryOpKind::CommissionVirginTx, owner, ticket);
  if (!resuming && compactionInProgress_) return OtaSequenceBackingResult::WouldBlock;
  if (!acquirePartitionOwnership()) return OtaSequenceBackingResult::WouldBlock;
  struct ReleaseGuard {
    OtaSecurityStore* s;
    ~ReleaseGuard() {
      if (!s->hasPendingOrdinaryOperation()) s->releasePartitionOwnership();
    }
  } releaseGuard{this};
  if (!resuming) {
    RefreshOutcome freshness = refreshIfPhysicallyStale();
    if (freshness == RefreshOutcome::Uncertain) return OtaSequenceBackingResult::Uncertain;  // Sol H2: fail closed.
    if (freshness == RefreshOutcome::CaughtUpOneStep) return OtaSequenceBackingResult::WouldBlock;
    if (storeFrozen_ || txFrozen_) return OtaSequenceBackingResult::Uncertain;
    if (txUpperBound_ != 0) return OtaSequenceBackingResult::OwnershipDenied;  // already-used: never relabeled.
    if (initialUpperBound == 0) return OtaSequenceBackingResult::OwnershipDenied;
    uint8_t payload[kCellPayloadBytes] = {0};
    putU32(payload, sizeof(payload), 0, initialUpperBound);
    if (!startOrdinaryOp(OrdinaryOpKind::CommissionVirginTx, owner, OtaSecurityRecordType::TxReservation, 0, payload,
                         4, 1, 0, ticket)) {
      return OtaSequenceBackingResult::NoCapacity;
    }
    // Defer the first physical step to the next (resuming) call -- see
    // reserveTx()'s identical comment on the per-step I/O budget. `ticket`
    // now holds the fresh handle the caller MUST present next call.
    return OtaSequenceBackingResult::WouldBlock;
  }
  // Resuming completion: the durable fact being driven to completion is
  // whatever was captured into pendingOp_.payload at the FRESH start
  // call -- NOT this call's `initialUpperBound` argument. MAIN's
  // correction: it is NOT enough to simply ignore a changed argument and
  // silently keep publishing the original fact -- a caller presenting a
  // CHANGED `initialUpperBound` here must be told its request does not
  // match the one actually in flight (Conflict), WITHOUT taking any
  // physical step and WITHOUT disturbing the original ticket/op, so (a)
  // it never mistakes Committed/success for ITS OWN changed value having
  // landed, and (b) the legitimate original caller can still present the
  // correct original arguments later and finish the real op.
  uint32_t originalInitialUpperBound = 0;
  getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 0, originalInitialUpperBound);
  if (initialUpperBound != originalInitialUpperBound) return OtaSequenceBackingResult::Conflict;
  OrdinaryOpStepOutcome outcome = stepPendingOrdinaryOp(nullptr);
  if (outcome != OrdinaryOpStepOutcome::Committed) {
    if (outcome == OrdinaryOpStepOutcome::Failed) {
      txFrozen_ = true;
      ticket = OtaSecurityOperationTicket{};  // terminal: burn ticket.
      return OtaSequenceBackingResult::Uncertain;
    }
    return OtaSequenceBackingResult::WouldBlock;  // InProgress: ticket stays valid, pendingOp_ still in flight.
  }
  txUpperBound_ = originalInitialUpperBound;
  ticket = OtaSecurityOperationTicket{};  // terminal result: burn the ticket, never replayable.
  return OtaSequenceBackingResult::Committed;
}

// --- RX ------------------------------------------------------------------
inline OtaSequenceBackingResult OtaSecurityStore::openExistingRx(const OtaRxLedgerContext& ctx) {
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  {
    BoundedReadRefreshOutcome refreshOutcome = refreshForBoundedReadNeedsRetry();
    if (refreshOutcome == BoundedReadRefreshOutcome::Unknown) return OtaSequenceBackingResult::Uncertain;
    if (refreshOutcome == BoundedReadRefreshOutcome::Retry) return OtaSequenceBackingResult::WouldBlock;
  }
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  bool isPeer = ctx.kind() == OtaRxLedgerContext::Kind::Peer;
  bool frozen = false;
  bool found = false;
  if (isPeer) {
    PeerTableEntry* it = findPeer(ctx.peerId().data());
    found = it != nullptr;
    if (found) frozen = it->frozen;
  } else {
    CohortTableEntry* it = findCohort(ctx.groupContext().data());
    found = it != nullptr;
    if (found) frozen = it->frozen;
  }
  if (!found) return OtaSequenceBackingResult::Missing;
  if (frozen) return OtaSequenceBackingResult::Uncertain;
  return OtaSequenceBackingResult::Committed;
}

inline OtaSequenceBackingResult OtaSecurityStore::readRxCounter(const OtaRxLedgerContext& ctx, uint32_t& outWatermark) {
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  {
    BoundedReadRefreshOutcome refreshOutcome = refreshForBoundedReadNeedsRetry();
    if (refreshOutcome == BoundedReadRefreshOutcome::Unknown) return OtaSequenceBackingResult::Uncertain;
    if (refreshOutcome == BoundedReadRefreshOutcome::Retry) return OtaSequenceBackingResult::WouldBlock;
  }
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  bool isPeer = ctx.kind() == OtaRxLedgerContext::Kind::Peer;
  bool found = false;
  bool frozen = false;
  uint32_t head = 0;
  if (isPeer) {
    PeerTableEntry* it = findPeer(ctx.peerId().data());
    found = it != nullptr;
    if (found) { frozen = it->frozen; head = it->head; }
  } else {
    CohortTableEntry* it = findCohort(ctx.groupContext().data());
    found = it != nullptr;
    if (found) { frozen = it->frozen; head = it->head; }
  }
  if (!found) return OtaSequenceBackingResult::Missing;
  if (frozen) return OtaSequenceBackingResult::Uncertain;
  outWatermark = head;
  return OtaSequenceBackingResult::Committed;
}

inline OtaSequenceBackingResult OtaSecurityStore::advanceRx(const OtaRxLedgerContext& ctx, uint32_t expectedHead,
                                                            uint32_t newHead, OtaSecurityOperationOwner owner,
                                                            OtaSecurityOperationTicket& ticket) {
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  if (owner == nullptr) return OtaSequenceBackingResult::OwnershipDenied;  // see reserveTx's doc comment.
  bool isPeer = ctx.kind() == OtaRxLedgerContext::Kind::Peer;
  if (!ordinaryOpFreeOrResuming(OrdinaryOpKind::AdvanceRx, owner, ticket)) return OtaSequenceBackingResult::WouldBlock;
  bool resuming = ordinaryOpTicketMatches(OrdinaryOpKind::AdvanceRx, owner, ticket);
  if (!resuming && compactionInProgress_) return OtaSequenceBackingResult::WouldBlock;
  if (!acquirePartitionOwnership()) return OtaSequenceBackingResult::WouldBlock;
  struct ReleaseGuard {
    OtaSecurityStore* s;
    ~ReleaseGuard() {
      if (!s->hasPendingOrdinaryOperation()) s->releasePartitionOwnership();
    }
  } releaseGuard{this};
  OtaSecurityRecordType type = isPeer ? OtaSecurityRecordType::RxPeerAdvance : OtaSecurityRecordType::RxGroupAdvance;
  if (!resuming) {
    // must run BEFORE any table lookup: may fully rebuild the tables.
    {
      RefreshOutcome freshness = refreshIfPhysicallyStale();
      if (freshness == RefreshOutcome::Uncertain) return OtaSequenceBackingResult::Uncertain;  // Sol H2: fail closed, never proceed on undeterminable freshness.
      if (freshness == RefreshOutcome::CaughtUpOneStep) return OtaSequenceBackingResult::WouldBlock;
    }
    if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
    PeerTableEntry* peerEntry = isPeer ? findPeer(ctx.peerId().data()) : nullptr;
    CohortTableEntry* cohortEntry = isPeer ? nullptr : findCohort(ctx.groupContext().data());
    bool found = isPeer ? (peerEntry != nullptr) : (cohortEntry != nullptr);
    if (!found) return OtaSequenceBackingResult::Missing;
    bool frozen = isPeer ? peerEntry->frozen : cohortEntry->frozen;
    uint32_t currentHead = isPeer ? peerEntry->head : cohortEntry->head;
    if (frozen) return OtaSequenceBackingResult::Uncertain;
    if (currentHead != expectedHead) return OtaSequenceBackingResult::Conflict;
    if (newHead < expectedHead) return OtaSequenceBackingResult::Conflict;  // known facts never regress.
    // Persist expectedHead too (not just newHead): MAIN's correction --
    // a resuming call presenting a DIFFERENT CAS predecessor proof is a
    // genuinely different request, not merely a different result, and
    // must be caught by the exact-request-match check below, not only
    // the final published value. `newHead` STAYS at its original offset
    // (32 for peer / 92 for group) -- reconstruct()'s and
    // tryApplyForeignOrdinaryCellIncrementally()'s RxPeerAdvance/
    // RxGroupAdvance decode both read the committed head from that exact
    // offset and must not be touched; expectedHead is appended AFTER it.
    uint8_t payload[kCellPayloadBytes] = {0};
    uint16_t payloadLen = isPeer ? 40 : 100;
    if (isPeer) {
      putBytes(payload, sizeof(payload), 0, ctx.peerId().data(), 32);
      putU32(payload, sizeof(payload), 32, newHead);
      putU32(payload, sizeof(payload), 36, expectedHead);
    } else {
      putBytes(payload, sizeof(payload), 0, ctx.groupContext().data(), 92);
      putU32(payload, sizeof(payload), 92, newHead);
      putU32(payload, sizeof(payload), 96, expectedHead);
    }
    if (!startOrdinaryOp(OrdinaryOpKind::AdvanceRx, owner, type, 0, payload, payloadLen, 1, 0, ticket)) {
      return OtaSequenceBackingResult::NoCapacity;  // pre-mutation check failed: state unchanged.
    }
    // Defer the first physical step to the next (resuming) call -- see
    // reserveTx()'s identical comment on the per-step I/O budget.
    return OtaSequenceBackingResult::WouldBlock;
  }
  // Resuming completion: the context key, CAS predecessor, and new head
  // actually being driven to completion are whatever startOrdinaryOp
  // captured into pendingOp_.payload/pendingOp_.recordType at the FRESH
  // start call -- NEVER this call's `ctx`/`expectedHead`/`newHead`
  // arguments. MAIN's correction: it is NOT enough to silently ignore a
  // changed argument and keep publishing the original fact -- a caller
  // presenting a DIFFERENT ctx/expectedHead/newHead here must be told
  // its request does not match the one in flight (Conflict), WITHOUT
  // taking any physical step and WITHOUT disturbing the original
  // ticket/op, so it never mistakes Committed for its OWN changed
  // request having landed, and the real original caller can still
  // finish the real op later.
  bool originalIsPeer = pendingOp_.recordType == OtaSecurityRecordType::RxPeerAdvance;
  uint8_t originalKey[92] = {0};
  uint32_t originalNewHead = 0;
  uint32_t originalExpectedHead = 0;
  if (originalIsPeer) {
    getBytes(pendingOp_.payload, sizeof(pendingOp_.payload), 0, originalKey, 32);
    getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 32, originalNewHead);
    getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 36, originalExpectedHead);
  } else {
    getBytes(pendingOp_.payload, sizeof(pendingOp_.payload), 0, originalKey, 92);
    getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 92, originalNewHead);
    getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 96, originalExpectedHead);
  }
  bool ctxMatches = isPeer == originalIsPeer &&
                    std::memcmp(originalKey, isPeer ? ctx.peerId().data() : ctx.groupContext().data(),
                                isPeer ? 32 : 92) == 0;
  if (!ctxMatches || expectedHead != originalExpectedHead || newHead != originalNewHead) {
    return OtaSequenceBackingResult::Conflict;
  }
  OrdinaryOpStepOutcome outcome = stepPendingOrdinaryOp(nullptr);
  if (outcome == OrdinaryOpStepOutcome::InProgress) return OtaSequenceBackingResult::WouldBlock;
  if (outcome == OrdinaryOpStepOutcome::Failed) {
    // Any post-mutation ambiguity permanently freezes this specific
    // context until a fresh reconstruct() -- mirrors the old behavior.
    if (originalIsPeer) {
      PeerTableEntry* after = findPeer(originalKey);
      if (after != nullptr) after->frozen = true;
    } else {
      CohortTableEntry* after = findCohort(originalKey);
      if (after != nullptr) after->frozen = true;
    }
    ticket = OtaSecurityOperationTicket{};  // terminal result: burn the ticket, never replayable.
    return OtaSequenceBackingResult::Uncertain;
  }
  // Committed: re-find rather than reuse any pointer captured before the
  // physical I/O above, defensively.
  if (originalIsPeer) {
    PeerTableEntry* after = findPeer(originalKey);
    if (after != nullptr) after->head = originalNewHead;
  } else {
    CohortTableEntry* after = findCohort(originalKey);
    if (after != nullptr) after->head = originalNewHead;
  }
  ticket = OtaSecurityOperationTicket{};  // terminal result: burn the ticket, never replayable.
  return OtaSequenceBackingResult::Committed;
}

inline OtaSequenceBackingResult OtaSecurityStore::commissionVirginRx(const OtaRxLedgerContext& ctx,
                                                                     uint32_t initialWatermark,
                                                                     bool factoryGrantAuthorized,
                                                                     OtaSecurityOperationOwner owner,
                                                                     OtaSecurityOperationTicket& ticket) {
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  if (!factoryGrantAuthorized) return OtaSequenceBackingResult::OwnershipDenied;
  if (initialWatermark == 0) return OtaSequenceBackingResult::OwnershipDenied;  // same contract as TX: never 0.
  if (owner == nullptr) return OtaSequenceBackingResult::OwnershipDenied;  // see reserveTx's nullptr-owner doc comment.
  bool isPeer = ctx.kind() == OtaRxLedgerContext::Kind::Peer;
  if (!ordinaryOpFreeOrResuming(OrdinaryOpKind::CommissionVirginRx, owner, ticket))
    return OtaSequenceBackingResult::WouldBlock;
  bool resuming = ordinaryOpTicketMatches(OrdinaryOpKind::CommissionVirginRx, owner, ticket);
  if (!resuming && compactionInProgress_) return OtaSequenceBackingResult::WouldBlock;  // mutations frozen during compaction.
  if (!acquirePartitionOwnership()) return OtaSequenceBackingResult::WouldBlock;
  struct ReleaseGuard {
    OtaSecurityStore* s;
    ~ReleaseGuard() {
      if (!s->hasPendingOrdinaryOperation()) s->releasePartitionOwnership();
    }
  } releaseGuard{this};
  {
    RefreshOutcome freshness = refreshIfPhysicallyStale();
    if (freshness == RefreshOutcome::Uncertain) return OtaSequenceBackingResult::Uncertain;  // Sol H2: fail closed.
    if (freshness == RefreshOutcome::CaughtUpOneStep) return OtaSequenceBackingResult::WouldBlock;
  }
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  OtaSecurityRecordType type = isPeer ? OtaSecurityRecordType::RxPeerAdvance : OtaSecurityRecordType::RxGroupAdvance;
  if (!resuming) {
    if (isPeer) {
      if (findPeer(ctx.peerId().data()) != nullptr) return OtaSequenceBackingResult::OwnershipDenied;  // already enrolled: not this method's job.
      if (peerTableCount_ >= kPeerTableCapacity) return OtaSequenceBackingResult::NoCapacity;
    } else {
      if (findCohort(ctx.groupContext().data()) != nullptr) return OtaSequenceBackingResult::OwnershipDenied;
      if (cohortTableCount_ >= kCohortTableCapacity) return OtaSequenceBackingResult::NoCapacity;
    }
    uint8_t payload[kCellPayloadBytes] = {0};
    uint16_t payloadLen = isPeer ? 36 : 96;
    if (isPeer) {
      putBytes(payload, sizeof(payload), 0, ctx.peerId().data(), 32);
      putU32(payload, sizeof(payload), 32, initialWatermark);
    } else {
      putBytes(payload, sizeof(payload), 0, ctx.groupContext().data(), 92);
      putU32(payload, sizeof(payload), 92, initialWatermark);
    }
    if (!startOrdinaryOp(OrdinaryOpKind::CommissionVirginRx, owner, type, 0, payload, payloadLen, 1, 0, ticket))
      return OtaSequenceBackingResult::NoCapacity;
    // Defer the first physical step to the next (resuming) call -- see
    // reserveTx()'s identical comment on the per-step I/O budget.
    return OtaSequenceBackingResult::WouldBlock;
  }
  // Resuming completion: publish the key/watermark actually captured at
  // the FRESH start call (pendingOp_.payload/pendingOp_.recordType),
  // NEVER this call's `ctx`/`initialWatermark` arguments. MAIN's
  // correction: a resuming call presenting a DIFFERENT ctx/watermark
  // must be told its request does not match the one in flight
  // (Conflict), WITHOUT taking any physical step and WITHOUT disturbing
  // the original ticket/op -- see advanceRx's identical fix. MUST decode
  // BEFORE stepPendingOrdinaryOp(), which clears pendingOp_ the instant
  // it reports Committed.
  bool originalIsPeer = pendingOp_.recordType == OtaSecurityRecordType::RxPeerAdvance;
  uint8_t originalKey[92] = {0};
  uint32_t originalInitialWatermark = 0;
  if (originalIsPeer) {
    getBytes(pendingOp_.payload, sizeof(pendingOp_.payload), 0, originalKey, 32);
    getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 32, originalInitialWatermark);
  } else {
    getBytes(pendingOp_.payload, sizeof(pendingOp_.payload), 0, originalKey, 92);
    getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 92, originalInitialWatermark);
  }
  bool ctxMatches = isPeer == originalIsPeer &&
                    std::memcmp(originalKey, isPeer ? ctx.peerId().data() : ctx.groupContext().data(),
                                isPeer ? 32 : 92) == 0;
  if (!ctxMatches || initialWatermark != originalInitialWatermark) {
    return OtaSequenceBackingResult::Conflict;
  }
  OrdinaryOpStepOutcome outcome = stepPendingOrdinaryOp(nullptr);
  if (outcome != OrdinaryOpStepOutcome::Committed) {
    if (outcome == OrdinaryOpStepOutcome::Failed) {
      ticket = OtaSecurityOperationTicket{};  // terminal: burn ticket.
      return OtaSequenceBackingResult::Uncertain;
    }
    return OtaSequenceBackingResult::WouldBlock;  // InProgress: ticket stays valid, pendingOp_ still in flight.
  }
  if (originalIsPeer) {
    PeerTableEntry& te = peerTable_[peerTableCount_];
    std::memcpy(te.key, originalKey, 32);
    te.index = peerTableCount_;
    te.head = originalInitialWatermark;
    te.frozen = false;
    ++peerTableCount_;
  } else {
    CohortTableEntry& te = cohortTable_[cohortTableCount_];
    std::memcpy(te.key, originalKey, 92);
    te.index = cohortTableCount_;
    te.head = originalInitialWatermark;
    te.frozen = false;
    ++cohortTableCount_;
  }
  ticket = OtaSecurityOperationTicket{};  // terminal result: burn the ticket, never replayable.
  return OtaSequenceBackingResult::Committed;
}


// --- Terminal attempts -----------------------------------------------------
inline void OtaSecurityStore::computeTerminalNoncePreimage(const uint8_t controller[32], uint32_t campaign,
                                                           uint32_t session, uint16_t attempt,
                                                           const uint8_t canonicalDescriptorDigest[32],
                                                           uint64_t& outNonce) {
  static const char kDomain[] = "MeshCore/OTA/install-attempt/v1";
  uint8_t buf[32 + 32 + 4 + 4 + 2 + 32];
  size_t off = 0;
  std::memcpy(buf + off, kDomain, sizeof(kDomain) - 1);
  off += sizeof(kDomain) - 1;
  std::memcpy(buf + off, controller, 32);
  off += 32;
  buf[off++] = (uint8_t)(campaign >> 24);
  buf[off++] = (uint8_t)(campaign >> 16);
  buf[off++] = (uint8_t)(campaign >> 8);
  buf[off++] = (uint8_t)(campaign);
  buf[off++] = (uint8_t)(session >> 24);
  buf[off++] = (uint8_t)(session >> 16);
  buf[off++] = (uint8_t)(session >> 8);
  buf[off++] = (uint8_t)(session);
  buf[off++] = (uint8_t)(attempt >> 8);
  buf[off++] = (uint8_t)(attempt);
  std::memcpy(buf + off, canonicalDescriptorDigest, 32);
  off += 32;
  ::ota::trust::Sha256 sha;
  sha.reset();
  sha.update(buf, off);
  uint8_t digest[32];
  sha.finish(digest);
  outNonce = 0;
  for (int i = 0; i < 8; ++i) outNonce = (outNonce << 8) | digest[i];
}

inline OtaSequenceBackingResult OtaSecurityStore::admitTerminalAttempt(const OtaSecurityTerminalEntry& entry,
                                                                       bool& outDuplicate,
                                                                       OtaSecurityOperationOwner owner,
                                                                       OtaSecurityOperationTicket& ticket) {
  outDuplicate = false;
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  if (owner == nullptr) return OtaSequenceBackingResult::OwnershipDenied;  // see reserveTx's doc comment.
  uint8_t payload[kCellPayloadBytes] = {0};
  if (!OtaSecurityTerminalEntryCodec::encode(entry, payload, kTerminalEntryBytes)) {
    return OtaSequenceBackingResult::Uncertain;
  }
  if (!ordinaryOpFreeOrResuming(OrdinaryOpKind::AdmitTerminal, owner, ticket)) return OtaSequenceBackingResult::WouldBlock;
  bool resuming = ordinaryOpTicketMatches(OrdinaryOpKind::AdmitTerminal, owner, ticket);
  if (!resuming && compactionInProgress_) return OtaSequenceBackingResult::WouldBlock;
  if (!acquirePartitionOwnership()) return OtaSequenceBackingResult::WouldBlock;
  struct ReleaseGuard {
    OtaSecurityStore* s;
    ~ReleaseGuard() {
      if (!s->hasPendingOrdinaryOperation()) s->releasePartitionOwnership();
    }
  } releaseGuard{this};
  if (!resuming) {
    {
      RefreshOutcome freshness = refreshIfPhysicallyStale();
      if (freshness == RefreshOutcome::Uncertain) return OtaSequenceBackingResult::Uncertain;  // Sol H2: fail closed, never proceed on undeterminable freshness.
      if (freshness == RefreshOutcome::CaughtUpOneStep) return OtaSequenceBackingResult::WouldBlock;
    }
    if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
    uint64_t expectedNonce = 0;
    computeTerminalNoncePreimage(entry.controller, entry.campaign, entry.session, entry.attempt,
                                 entry.canonicalDescriptorDigest, expectedNonce);
    if (expectedNonce != entry.nonce) return OtaSequenceBackingResult::Conflict;

    // Bounded fingerprint-collision scan (SLICE5): resume from where a
    // prior call left off if this IS that in-progress scan's own
    // owner+ticket+request, otherwise start fresh at index 0. See
    // kTerminalCollisionReadsPerCall's declaration comment: an engineered
    // run of colliding fingerprints (the index stores a truncated AID,
    // never proof) must never cost more than that many physical row
    // reads within a single call -- the RAM-only prefilter below is free.
    uint32_t scanStart = 0;
    if (terminalScanTicket_.valid()) {
      bool sameOwnerTicket = ticket.valid() && ticket.id == terminalScanTicket_.id &&
                             ticket.issuerInstanceEpoch == instanceEpoch_ && ticket.owner == owner &&
                             terminalScanTicket_.owner == owner;
      if (!sameOwnerTicket) return OtaSequenceBackingResult::WouldBlock;  // foreign/stale ticket, scan busy.
      if (std::memcmp(payload, terminalScanPayload_, kTerminalEntryBytes) != 0) {
        // Same ticket, changed request: zero I/O, original scan intact.
        return OtaSequenceBackingResult::Conflict;
      }
      scanStart = terminalScanResumeIndex_;
    }
    uint32_t candidateFp =
        computeTerminalTupleFingerprint(entry.controller, entry.campaign, entry.session, entry.attempt);
    uint32_t reads = 0;
    uint32_t i = scanStart;
    for (; i < terminalCount_; ++i) {
      if (terminalIndex_[i].tupleFingerprint != candidateFp) continue;  // cheap reject, no flash I/O.
      if (reads >= kTerminalCollisionReadsPerCall) {
        // Budget exhausted for this call: retain the scan and resume
        // from this exact (not-yet-read) index next call -- never skip it.
        terminalScanResumeIndex_ = i;
        if (!terminalScanTicket_.valid()) {
          terminalScanTicket_.owner = owner;
          terminalScanTicket_.id = nextOpTicketSeed_++;
          terminalScanTicket_.issuerInstanceEpoch = instanceEpoch_;
          std::memcpy(terminalScanPayload_, payload, kTerminalEntryBytes);
        }
        ticket = terminalScanTicket_;
        return OtaSequenceBackingResult::WouldBlock;
      }
      ++reads;
      // Fingerprint matched -- this is only an AID, never proof: re-read
      // the actual row and compare real fields before any decision.
      OtaSecurityTerminalEntry existing;
      if (!readTerminalRow(terminalIndex_[i], existing)) {
        terminalScanTicket_ = OtaSecurityOperationTicket{};  // terminal outcome: scan fully resolved (frozen).
        return OtaSequenceBackingResult::Uncertain;  // occupied row read failure -> freeze, never drop the fact.
      }
      bool sameNonce = existing.nonce == entry.nonce;
      bool sameTuple = std::memcmp(existing.controller, entry.controller, 32) == 0 &&
                        existing.campaign == entry.campaign && existing.session == entry.session &&
                        existing.attempt == entry.attempt;
      bool sameDigest = std::memcmp(existing.canonicalDescriptorDigest, entry.canonicalDescriptorDigest, 32) == 0;
      if (sameTuple && sameDigest) {
        outDuplicate = true;
        terminalScanTicket_ = OtaSecurityOperationTicket{};
        return OtaSequenceBackingResult::Committed;  // idempotent re-submission, no new slot consumed.
      }
      if (sameNonce && !(sameTuple && sameDigest)) {
        terminalScanTicket_ = OtaSecurityOperationTicket{};
        return OtaSequenceBackingResult::Conflict;  // nonce collision.
      }
      if (sameTuple && !sameDigest) {
        terminalScanTicket_ = OtaSecurityOperationTicket{};
        return OtaSequenceBackingResult::Conflict;  // differing manifest.
      }
    }
    // Reached the end with no unresolved collision: scan fully done,
    // release any held scan ticket/resume state before proceeding.
    terminalScanTicket_ = OtaSecurityOperationTicket{};
    terminalScanResumeIndex_ = 0;

    if (terminalCount_ >= kTerminalTableCapacity) return OtaSequenceBackingResult::NoCapacity;
    if (!startOrdinaryOp(OrdinaryOpKind::AdmitTerminal, owner, OtaSecurityRecordType::TerminalAttempt, 0, payload,
                         kTerminalEntryBytes, 1, 0, ticket)) {
      return OtaSequenceBackingResult::NoCapacity;
    }
    // Defer the first physical step to the next (resuming) call -- see
    // reserveTx()'s identical comment on the per-step I/O budget.
    return OtaSequenceBackingResult::WouldBlock;
  }
  // Resuming completion: the fingerprint must be derived from the ORIGINAL
  // entry captured into pendingOp_.payload at the fresh start call --
  // NEVER this call's `entry` argument -- so the index entry always
  // points at the tuple that actually landed on flash (see advanceRx's
  // identical fix above). MUST decode BEFORE stepPendingOrdinaryOp(),
  // which clears pendingOp_ the instant it reports Committed.
  OtaSecurityTerminalEntry originalEntry;
  if (!OtaSecurityTerminalEntryCodec::decode(pendingOp_.payload, sizeof(pendingOp_.payload), originalEntry)) {
    // Must never happen (we encoded it ourselves at start); fail closed
    // rather than fabricate an index entry from untrusted current args.
    ticket = OtaSecurityOperationTicket{};
    return OtaSequenceBackingResult::Uncertain;
  }
  // MAIN's correction: a resuming call presenting a DIFFERENT entry (any
  // byte of it) than the one captured at the fresh start must be told
  // its request does not match the in-flight one (Conflict), WITHOUT
  // taking any physical step and WITHOUT disturbing the original
  // ticket/op -- byte-exact compare of the encoded forms is simplest and
  // cannot miss a field a future struct edit might otherwise forget.
  if (std::memcmp(payload, pendingOp_.payload, kTerminalEntryBytes) != 0) {
    return OtaSequenceBackingResult::Conflict;
  }
  OrdinaryOpStepOutcome outcome = stepPendingOrdinaryOp(nullptr);
  if (outcome == OrdinaryOpStepOutcome::InProgress) return OtaSequenceBackingResult::WouldBlock;
  if (outcome == OrdinaryOpStepOutcome::Failed) {
    ticket = OtaSecurityOperationTicket{};  // terminal result: burn the ticket, never replayable.
    return OtaSequenceBackingResult::Uncertain;
  }
  OtaSecurityTerminalIndexEntry& te = terminalIndex_[terminalCount_++];
  te.location = (uint16_t)((nextFreeSlot_ - 1) & kTerminalLocIndexMask) | kTerminalLocSourceBit;
  te.flags = 0x1u;
  te.tupleFingerprint = computeTerminalTupleFingerprint(originalEntry.controller, originalEntry.campaign,
                                                        originalEntry.session, originalEntry.attempt);
  ticket = OtaSecurityOperationTicket{};  // terminal result: burn the ticket, never replayable.
  return OtaSequenceBackingResult::Committed;
}

// --- FactoryGrant ----------------------------------------------------------
inline OtaSequenceBackingResult OtaSecurityStore::commissionFactoryGrant(const OtaSecurityFactoryGrant& grant,
                                                                         OtaSecurityOperationOwner owner,
                                                                         OtaSecurityOperationTicket& ticket) {
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  if (owner == nullptr) return OtaSequenceBackingResult::OwnershipDenied;  // see reserveTx's doc comment.
  uint8_t payload[kCellPayloadBytes] = {0};
  putU64(payload, sizeof(payload), 0, grant.deviceUid);
  putBytes(payload, sizeof(payload), 8, grant.fullLocalPublicKey, 32);
  putU32(payload, sizeof(payload), 40, grant.profile);
  putU32(payload, sizeof(payload), 44, grant.layout);
  putU32(payload, sizeof(payload), 48, grant.role);
  putU32(payload, sizeof(payload), 52, grant.initialRole);
  putBytes(payload, sizeof(payload), 56, grant.consentOwner, 32);
  putU64(payload, sizeof(payload), 88, grant.transaction);
  if (!ordinaryOpFreeOrResuming(OrdinaryOpKind::CommissionFactoryGrant, owner, ticket)) {
    return OtaSequenceBackingResult::WouldBlock;
  }
  bool resuming = ordinaryOpTicketMatches(OrdinaryOpKind::CommissionFactoryGrant, owner, ticket);
  if (!resuming && compactionInProgress_) return OtaSequenceBackingResult::WouldBlock;
  if (!acquirePartitionOwnership()) return OtaSequenceBackingResult::WouldBlock;
  struct ReleaseGuard {
    OtaSecurityStore* s;
    ~ReleaseGuard() {
      if (!s->hasPendingOrdinaryOperation()) s->releasePartitionOwnership();
    }
  } releaseGuard{this};
  {
    RefreshOutcome freshness = refreshIfPhysicallyStale();
    if (freshness == RefreshOutcome::Uncertain) return OtaSequenceBackingResult::Uncertain;  // Sol H2: fail closed, never proceed on undeterminable freshness.
    if (freshness == RefreshOutcome::CaughtUpOneStep) return OtaSequenceBackingResult::WouldBlock;
  }
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  if (!resuming) {
    // Default-deny, one-use: a store that has already consumed its grant
    // must never accept another, regardless of label/role relabeling.
    if (factoryGrantConsumed_) return OtaSequenceBackingResult::OwnershipDenied;
    if (!startOrdinaryOp(OrdinaryOpKind::CommissionFactoryGrant, owner, OtaSecurityRecordType::FactoryGrantRecord,
                         kFactoryGrantSlot, payload, 96, 1, 0, ticket)) {
      return OtaSequenceBackingResult::NoCapacity;
    }
    // Defer the first physical step to the next (resuming) call -- see
    // reserveTx()'s identical comment on the per-step I/O budget.
    return OtaSequenceBackingResult::WouldBlock;
  }
  // Resuming completion: publish the grant actually captured into
  // pendingOp_.payload at the FRESH start call -- NEVER this call's
  // `grant` argument -- mirrors reconstruct()'s identical
  // FactoryGrantRecord decode and advanceRx's/admitTerminalAttempt's
  // identical fix above. MUST decode BEFORE stepPendingOrdinaryOp(),
  // which clears pendingOp_ the instant it reports Committed.
  //
  // MAIN's correction: a resuming call presenting a DIFFERENT grant (any
  // byte of it) than the one captured at the fresh start must be told
  // its request does not match the in-flight one (Conflict), WITHOUT
  // taking any physical step and WITHOUT disturbing the original
  // ticket/op -- byte-exact compare of the encoded forms, same pattern
  // as admitTerminalAttempt above.
  if (std::memcmp(payload, pendingOp_.payload, 96) != 0) {
    return OtaSequenceBackingResult::Conflict;
  }
  OtaSecurityFactoryGrant originalGrant;
  getU64(pendingOp_.payload, sizeof(pendingOp_.payload), 0, originalGrant.deviceUid);
  getBytes(pendingOp_.payload, sizeof(pendingOp_.payload), 8, originalGrant.fullLocalPublicKey, 32);
  getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 40, originalGrant.profile);
  getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 44, originalGrant.layout);
  getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 48, originalGrant.role);
  getU32(pendingOp_.payload, sizeof(pendingOp_.payload), 52, originalGrant.initialRole);
  getBytes(pendingOp_.payload, sizeof(pendingOp_.payload), 56, originalGrant.consentOwner, 32);
  getU64(pendingOp_.payload, sizeof(pendingOp_.payload), 88, originalGrant.transaction);
  OrdinaryOpStepOutcome outcome = stepPendingOrdinaryOp(nullptr);
  if (outcome == OrdinaryOpStepOutcome::InProgress) return OtaSequenceBackingResult::WouldBlock;
  if (outcome == OrdinaryOpStepOutcome::Failed) {
    ticket = OtaSecurityOperationTicket{};  // terminal result: burn the ticket, never replayable.
    return OtaSequenceBackingResult::Uncertain;
  }
  factoryGrantConsumed_ = true;
  factoryGrant_ = originalGrant;
  ticket = OtaSecurityOperationTicket{};  // terminal result: burn the ticket, never replayable.
  return OtaSequenceBackingResult::Committed;
}

// --- LiveBinding -------------------------------------------------------------
inline OtaSequenceBackingResult OtaSecurityStore::writeLiveBinding(const OtaSecurityLiveBinding& binding,
                                                                   OtaSecurityOperationOwner owner,
                                                                   OtaSecurityOperationTicket& ticket) {
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  if (owner == nullptr) return OtaSequenceBackingResult::OwnershipDenied;  // see reserveTx's doc comment.
  uint8_t full[kLiveBindingAreaBytes];
  if (!OtaSecurityLiveBindingCodec::encode(binding, full, sizeof(full))) return OtaSequenceBackingResult::Uncertain;
  if (!ordinaryOpFreeOrResuming(OrdinaryOpKind::WriteLiveBinding, owner, ticket)) {
    return OtaSequenceBackingResult::WouldBlock;
  }
  bool resuming = ordinaryOpTicketMatches(OrdinaryOpKind::WriteLiveBinding, owner, ticket);
  if (!resuming && compactionInProgress_) return OtaSequenceBackingResult::WouldBlock;
  if (!acquirePartitionOwnership()) return OtaSequenceBackingResult::WouldBlock;
  struct ReleaseGuard {
    OtaSecurityStore* s;
    ~ReleaseGuard() {
      if (!s->hasPendingOrdinaryOperation()) s->releasePartitionOwnership();
    }
  } releaseGuard{this};
  if (!resuming) {
    {
      RefreshOutcome freshness = refreshIfPhysicallyStale();
      if (freshness == RefreshOutcome::Uncertain) return OtaSequenceBackingResult::Uncertain;  // Sol H2: fail closed, never proceed on undeterminable freshness.
      if (freshness == RefreshOutcome::CaughtUpOneStep) return OtaSequenceBackingResult::WouldBlock;
    }
    if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
    // Pre-mutation capacity check: ALL chunks must fit before writing ANY
    // of them -- a partial transaction must never consume capacity it
    // cannot finish using.
    if (nextFreeSlot_ + kLiveBindingChunkCount > kOrdinaryCellCount) return OtaSequenceBackingResult::NoCapacity;
    const uint64_t transactionLsn = nextLsn_;
    uint32_t len0 = std::min<uint32_t>(kLiveBindingChunkDataBytes, kLiveBindingFixedBytes);
    uint8_t payload0[kCellPayloadBytes] = {0};
    putU64(payload0, sizeof(payload0), 0, transactionLsn);
    putU8(payload0, sizeof(payload0), 8, 0);
    putU8(payload0, sizeof(payload0), 9, (uint8_t)kLiveBindingChunkCount);
    putU16(payload0, sizeof(payload0), 10, (uint16_t)kLiveBindingFixedBytes);
    putBytes(payload0, sizeof(payload0), kLiveBindingChunkPrefixBytes, full, len0);
    if (!startOrdinaryOp(OrdinaryOpKind::WriteLiveBinding, owner, OtaSecurityRecordType::LiveBindingChunk, 0,
                         payload0, (uint16_t)(kLiveBindingChunkPrefixBytes + len0), kLiveBindingChunkCount,
                         transactionLsn, ticket)) {
      return OtaSequenceBackingResult::NoCapacity;
    }
    // Store OWNS an immutable copy of the full encoded area from this
    // point on -- every later resumed chunk/final publish is driven from
    // THIS copy, never from whatever `binding` a later call happens to
    // pass (see pendingLiveBindingFullBytes_'s doc comment).
    std::memcpy(pendingLiveBindingFullBytes_, full, kLiveBindingAreaBytes);
    // Defer the first physical step to the next (resuming) call -- see
    // reserveTx()'s identical comment on the per-step I/O budget.
    return OtaSequenceBackingResult::WouldBlock;
  }
  // Every resumed step is driven from pendingLiveBindingFullBytes_ -- the
  // immutable copy captured at the fresh-start call -- NEVER from `full`
  // (re-derived above from THIS call's possibly-different `binding`
  // argument). The ticket alone proves WHICH operation is being resumed,
  // never that this call's other arguments agree with the original
  // request (see OtaSecurityOperationTicket's doc comment).
  //
  // MAIN's correction: a resuming call presenting a DIFFERENT binding
  // (any byte of its encoded form) than the one captured at the fresh
  // start must be told its request does not match the in-flight one
  // (Conflict), WITHOUT taking any physical step, WITHOUT consuming any
  // more of the multi-chunk transaction, and WITHOUT disturbing the
  // original ticket/op -- same byte-exact-compare pattern as
  // commissionFactoryGrant/admitTerminalAttempt above. No chunk may be
  // mixed between the original and a mismatched resume's bytes.
  if (std::memcmp(full, pendingLiveBindingFullBytes_, kLiveBindingAreaBytes) != 0) {
    return OtaSequenceBackingResult::Conflict;
  }
  OrdinaryOpStepOutcome outcome = stepPendingOrdinaryOp(pendingLiveBindingFullBytes_);
  if (outcome == OrdinaryOpStepOutcome::InProgress) return OtaSequenceBackingResult::WouldBlock;
  if (outcome == OrdinaryOpStepOutcome::Failed) {
    // Partial transaction: whatever landed stays on flash as evidence for
    // a future cold reconstruct() to classify -- NEVER treated as
    // committed here, and the in-RAM liveBinding_/liveBindingPresent_
    // stay at their prior (possibly-absent) value.
    ticket = OtaSecurityOperationTicket{};  // terminal result: burn the ticket, never replayable.
    return OtaSequenceBackingResult::Uncertain;
  }
  // Publish exactly what was durably written -- decode from the SAME
  // owned immutable bytes just committed, never from the (possibly
  // divergent) current-call `binding` argument.
  OtaSecurityLiveBinding originalBinding;
  if (!OtaSecurityLiveBindingCodec::decode(pendingLiveBindingFullBytes_, kLiveBindingAreaBytes, originalBinding)) {
    // Must never happen (we encoded it ourselves at start); fail closed.
    ticket = OtaSecurityOperationTicket{};
    return OtaSequenceBackingResult::Uncertain;
  }
  liveBinding_ = originalBinding;
  liveBindingPresent_ = originalBinding.present;
  ticket = OtaSecurityOperationTicket{};  // terminal result: burn the ticket, never replayable.
  return OtaSequenceBackingResult::Committed;
}

// --- Compaction --------------------------------------------------------
// SLICE5: compact() is a TEST/offline-tool convenience ONLY -- it loops
// compactStep() to an UNBOUNDED completion and must never be called from
// any production, time-budgeted, or interrupt/RX-dispatch-adjacent call
// path (nothing in src/ota/security/** does; the TX/RX adapters and
// refreshIfPhysicallyStale() only ever drive compactStep()/
// stepReconstruct() one bounded unit at a time). A real cold-startup or
// per-tick service caller MUST drive compactStep() directly under its
// own retained ticket/step cadence, exactly like stepReconstruct().
inline OtaSequenceBackingResult OtaSecurityStore::compact() {
  OtaSequenceBackingResult r;
  while ((r = compactStep()) == OtaSequenceBackingResult::WouldBlock) {
    // Convenience synchronous wrapper: loop the bounded step primitive to
    // completion. Real per-tick integration should call compactStep()
    // directly instead of this loop.
  }
  return r;
}

// Bounded, resumable compaction primitive -- see CompactionPhase's class
// doc comment. Each call performs exactly ONE physical erase or ONE
// bounded program/verify/switch/activate step; the exact ordered protocol
// (seal source -> erase dest -> build+verify dest snapshot -> prepare
// source witness -> commit switch -> activate dest) is UNCHANGED from the
// original monolithic compact(), just sliced across phases/calls instead
// of one synchronous burst of 25 erases + ~739 program calls.
inline OtaSequenceBackingResult OtaSecurityStore::compactStep() {
  if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
  // A pending ordinary mutation (reserveTx/advanceRx/etc, mid-flight via
  // the owner-bound resumable engine) must finish or fail before
  // compaction may start on THIS instance -- never stomp it.
  if (!compactionInProgress_ && hasPendingOrdinaryOperation()) return OtaSequenceBackingResult::WouldBlock;

  bool alreadyInProgressAtEntry = compactionInProgress_;
  if (!alreadyInProgressAtEntry) {
    // Physical partition ownership MUST be acquired BEFORE any fresh-view
    // refresh/seal/source-freeze (STOREPLAN cross-instance arbitration
    // contract). A foreign owner (a sibling Store wrapper sharing this
    // same arbiter, already mid-compaction or mid-mutation) means
    // WouldBlock here, without touching any compaction state.
    if (!acquirePartitionOwnership()) return OtaSequenceBackingResult::WouldBlock;
  }
  // Ownership is now held (freshly acquired just above on a fresh start,
  // or already held from an earlier compactStep() call on this same
  // in-progress compaction). Release it the instant compactionInProgress_
  // transitions back to false -- this single guard covers every one of
  // this function's many internal completion/abort return paths without
  // needing to touch each individually, and correctly keeps ownership
  // HELD across every WouldBlock return between phases.
  struct ReleaseGuardOnFinish {
    OtaSecurityStore* s;
    ~ReleaseGuardOnFinish() {
      if (!s->compactionInProgress_) s->releasePartitionOwnership();
    }
  } releaseGuardOnFinish{this};

  if (!compactionInProgress_) {
    // Re-derive physical truth BEFORE snapshotting any state a fresh
    // compaction will bake into the destination bank (active bank/
    // generation, txUpperBound_, peer/cohort/terminal tables,
    // FactoryGrant/LiveBinding). Without this, a Store instance whose RAM
    // still reflects an earlier, now-stale view (e.g. a sibling instance
    // reserved TX up to 164 while this one still caches 100) would seal
    // and publish a destination snapshot checkpointing the STALE facts,
    // permanently losing everything a genuinely-committed foreign write
    // already established -- Sol finding #1. Only runs once, at the
    // START of a fresh compaction (never mid-compaction: ordinary
    // mutation entry points already freeze/return WouldBlock while
    // compactionInProgress_ is true, so there is no concurrent foreign
    // mutation to race against once this instance is itself mid-phase).
    //
    // A bounded single-cell catch-up step leaves the view only PARTIALLY
    // fresh (there may be MORE foreign cells beyond the one just
    // applied) -- compaction's baseline snapshot must never be sealed
    // from a partially-caught-up view, so stay in the bootstrap branch
    // (compactionInProgress_ left false) and return WouldBlock again,
    // letting the caller re-drive compactStep() until the view is
    // genuinely, fully fresh (AlreadyFresh) before committing to
    // SealSource.
    {
      RefreshOutcome freshness = refreshIfPhysicallyStale();
      if (freshness == RefreshOutcome::Uncertain) return OtaSequenceBackingResult::Uncertain;  // Sol H2: fail closed, never proceed on undeterminable freshness.
      if (freshness == RefreshOutcome::CaughtUpOneStep) return OtaSequenceBackingResult::WouldBlock;
    }
    if (storeFrozen_) return OtaSequenceBackingResult::Uncertain;
    compactionSource_ = activeBank_;
    compactionDest_ = otherBank(compactionSource_);
    compactionNewGeneration_ = activeGeneration_ + 1;
    if (compactionNewGeneration_ == 0) return OtaSequenceBackingResult::Uncertain;  // non-wrapping exhaustion.
    compactionInProgress_ = true;
    compactionPhase_ = CompactionPhase::SealSource;
    compactionEraseCursor_ = 0;
    compactionRowByteOffset_ = 0;  // fresh compaction: no row-slice carried over from any prior attempt.
    sealSubPhase_ = ReservedCellSubPhase::CheckAndBody;
    // Bounded-step budget: refreshIfPhysicallyStale()'s own reads (small,
    // but non-zero) must not be bundled into the SAME compactStep() call
    // as SealSource's first program call -- return WouldBlock here so the
    // bootstrap's I/O and SealSource's own <=1-program-call budget are
    // counted in two genuinely separate steps, never combined into one
    // step whose total could exceed the approved per-step byte budget.
    return OtaSequenceBackingResult::WouldBlock;
  }

  OtaSecurityBankId source = compactionSource_;
  OtaSecurityBankId dest = compactionDest_;
  uint32_t newGeneration = compactionNewGeneration_;

  switch (compactionPhase_) {
    case CompactionPhase::Idle:
      // Unreachable: compactionInProgress_ guarantees a non-Idle phase here.
      compactionInProgress_ = false;
      return OtaSequenceBackingResult::Uncertain;

    case CompactionPhase::SealSource: {
      // Seal source (reserved cell 254), witnessed in dest -- dest is
      // untouched so far, nothing destructive has happened yet. Bounded
      // to <=1 program-or-erase call per compactStep() invocation via
      // appendReservedRecordStep()'s body/marker sub-phase split; its
      // CheckAndBody sub-phase's own idempotent-resume check (detecting
      // an already-committed seal from a prior, interrupted compaction
      // attempt at this exact generation) is unchanged from before.
      static const uint8_t kSealPayload[kCellPayloadBytes] = {0};
      ReservedCellStepOutcome sealOutcome = appendReservedRecordStep(
          source, kSealCellIndex, OtaSecurityRecordType::SealRecord, activeGeneration_, kSealPayload, 0, sealSubPhase_);
      if (sealOutcome == ReservedCellStepOutcome::Failed) {
        compactionInProgress_ = false;
        storeFrozen_ = true;
        return OtaSequenceBackingResult::Uncertain;
      }
      if (sealOutcome == ReservedCellStepOutcome::InProgress) {
        return OtaSequenceBackingResult::WouldBlock;
      }
      compactionPhase_ = CompactionPhase::EraseDestSnapshotSector;
      compactionEraseCursor_ = 0;
      return OtaSequenceBackingResult::WouldBlock;
    }

    case CompactionPhase::EraseDestSnapshotSector: {
      // Erase dest's snapshot ONE 4 KiB sector per call (16 sectors total
      // = kSnapshotSizeBytes); dest's witness sector is explicitly
      // preserved (it still protects source's now-sealed log).
      ::ota::platform::FlashRegion& destSnap = carve(dest).snapshot();
      if (!::ota::platform::isOk(destSnap.eraseSector(compactionEraseCursor_ * kSecurityEraseUnitBytes))) {
        compactionInProgress_ = false;
        storeFrozen_ = true;
        return OtaSequenceBackingResult::Uncertain;
      }
      ++compactionEraseCursor_;
      if (compactionEraseCursor_ >= kSnapshotEraseSectorCount) {
        compactionPhase_ = CompactionPhase::EraseDestLogSector;
        compactionEraseCursor_ = 0;
      }
      return OtaSequenceBackingResult::WouldBlock;
    }

    case CompactionPhase::EraseDestLogSector: {
      // Erase dest's dataLog ONE 4 KiB sector per call (8 sectors total =
      // kDataLogSizeBytes).
      ::ota::platform::FlashRegion& destLog = carve(dest).dataLog();
      if (!::ota::platform::isOk(destLog.eraseSector(compactionEraseCursor_ * kSecurityEraseUnitBytes))) {
        compactionInProgress_ = false;
        storeFrozen_ = true;
        return OtaSequenceBackingResult::Uncertain;
      }
      ++compactionEraseCursor_;
      if (compactionEraseCursor_ >= kDataLogEraseSectorCount) {
        compactionPhase_ = CompactionPhase::WriteDestSnapshot;
        compactionEraseCursor_ = 0;  // repurposed below as the bounded write-unit cursor.
      }
      return OtaSequenceBackingResult::WouldBlock;
    }

    case CompactionPhase::WriteDestSnapshot: {
      // Bounded per-service-step snapshot write (STOREPLAN Priority 2):
      // compactionEraseCursor_ is repurposed as a flat "unit" cursor
      // (see computeSnapshotUnitLayout()) -- EXACTLY ONE header/table-
      // entry/live-binding-area chunk is built per compactStep() call,
      // but a peer/cohort/terminal row that straddles a 256B physical
      // NOR page (see programRowSliceAndAdvance()) is itself sliced
      // across additional calls so AT MOST ONE physical page program
      // ever happens per call -- the unit cursor only advances once the
      // WHOLE row has been durably programmed.
      ::ota::platform::FlashRegion& destSnap = carve(dest).snapshot();
      SnapshotUnitLayout layout = computeSnapshotUnitLayout();
      uint32_t unit = compactionEraseCursor_;
      bool ok = false;

      if (unit == 0) {
        // Carry forward the FactoryGrant (whole-store, singleton) and
        // the LiveBinding length marker (the blob body itself is
        // programmed in its own later units) -- these must survive
        // compaction exactly like txUpperBound_/peer/cohort/terminal
        // facts do; dropping them here would silently un-commission the
        // store across a generation boundary.
        OtaSecuritySnapshotHeader newHeader;
        newHeader.storeIdentity = storeIdentity_;
        newHeader.generation = newGeneration;
        newHeader.txGlobalUpperBoundCheckpoint = txUpperBound_;
        newHeader.peerCount = (uint16_t)peerTableCount_;
        newHeader.cohortCount = (uint16_t)cohortTableCount_;
        newHeader.terminalCount = (uint16_t)terminalCount_;
        newHeader.factoryGrantConsumed = factoryGrantConsumed_;
        newHeader.factoryGrant = factoryGrant_;
        newHeader.liveBindingLength = liveBindingPresent_ ? (uint16_t)kLiveBindingFixedBytes : 0u;
        uint8_t headerBuf[kHeaderEncodedBytes];
        ok = OtaSecuritySnapshotHeaderCodec::encode(newHeader, headerBuf, sizeof(headerBuf)) &&
             ::ota::platform::isOk(destSnap.program(kHeaderAreaOffset, headerBuf, sizeof(headerBuf)));
      } else if (unit < layout.cohortBase) {
        const PeerTableEntry& kv = peerTable_[unit - layout.peerBase];
        OtaSecurityPeerEntry e;
        std::memcpy(e.fullPeerPublicKey, kv.key, 32);
        e.rxHead = kv.head;
        e.stableIndex = (uint16_t)kv.index;
        e.flags = 0x1u;
        uint8_t raw[kPeerEntryBytes];
        if (!OtaSecurityPeerEntryCodec::encode(e, raw, sizeof(raw))) {
          ok = false;
        } else if (!programRowSliceAndAdvance(destSnap, kPeerTableOffset + kv.index * kPeerEntryBytes, raw,
                                              sizeof(raw), ok)) {
          // Row straddled a 256B physical page: this call programmed
          // only the first slice -- resume the SAME unit next call
          // instead of advancing the cursor, so at most ONE physical
          // page program happens per compactStep() call.
          return ok ? OtaSequenceBackingResult::WouldBlock : (compactionInProgress_ = false, storeFrozen_ = true,
                                                               OtaSequenceBackingResult::Uncertain);
        }
      } else if (unit < layout.terminalBase) {
        const CohortTableEntry& kv = cohortTable_[unit - layout.cohortBase];
        OtaSecurityCohortEntry e;
        std::memcpy(e.groupContext, kv.key, 92);
        e.rxHead = kv.head;
        uint8_t raw[kCohortEntryBytes];
        if (!OtaSecurityCohortEntryCodec::encode(e, raw, sizeof(raw))) {
          ok = false;
        } else if (!programRowSliceAndAdvance(destSnap, kCohortTableOffset + kv.index * kCohortEntryBytes, raw,
                                              sizeof(raw), ok)) {
          return ok ? OtaSequenceBackingResult::WouldBlock : (compactionInProgress_ = false, storeFrozen_ = true,
                                                               OtaSequenceBackingResult::Uncertain);
        }
      } else if (unit < layout.liveBase) {
        uint32_t i = unit - layout.terminalBase;
        OtaSecurityTerminalEntry entry;
        uint8_t raw[kTerminalEntryBytes];
        if (!readTerminalRow(terminalIndex_[i], entry) || !OtaSecurityTerminalEntryCodec::encode(entry, raw, sizeof(raw))) {
          ok = false;
        } else if (!programRowSliceAndAdvance(destSnap, kTerminalTableOffset + i * kTerminalEntryBytes, raw,
                                              sizeof(raw), ok)) {
          return ok ? OtaSequenceBackingResult::WouldBlock : (compactionInProgress_ = false, storeFrozen_ = true,
                                                               OtaSequenceBackingResult::Uncertain);
        }
      } else {
        // Live-binding-area chunk: the codec only ever encodes the WHOLE
        // struct atomically (a transient, on-stack 4 KiB scratch buffer,
        // discarded at the end of this case -- never retained across
        // calls), but only kLiveBindingAreaWriteChunkBytes of it are
        // actually PROGRAMMED to flash this step.
        uint32_t chunk = unit - layout.liveBase;
        uint8_t lbBuf[kLiveBindingAreaBytes];
        if (OtaSecurityLiveBindingCodec::encode(liveBinding_, lbBuf, sizeof(lbBuf))) {
          uint32_t off = chunk * kLiveBindingAreaWriteChunkBytes;
          uint32_t len = std::min<uint32_t>(kLiveBindingAreaWriteChunkBytes, kLiveBindingAreaBytes - off);
          ok = ::ota::platform::isOk(destSnap.program(kLiveBindingOffset + off, lbBuf + off, len));
        }
      }

      if (!ok) {
        compactionInProgress_ = false;
        storeFrozen_ = true;
        return OtaSequenceBackingResult::Uncertain;
      }
      ++compactionEraseCursor_;
      if (compactionEraseCursor_ >= layout.totalUnits) {
        compactionPhase_ = CompactionPhase::ReadbackVerifyDestSnapshot;
        compactionEraseCursor_ = 0;
      }
      return OtaSequenceBackingResult::WouldBlock;
    }

    case CompactionPhase::ReadbackVerifyDestSnapshot: {
      // Bounded per-service-step EXACT-BYTE readback verification
      // (STOREPLAN Priority 2), mirroring WriteDestSnapshot's unit
      // cursor exactly: re-encode the SAME deterministic expected bytes
      // for ONE unit (a pure function of the RAM-authoritative facts,
      // so no extra state needs to be retained across steps), read back
      // ONLY that unit's bytes, and memcmp -- covering every single byte
      // of header/peer/cohort/terminal/live-binding content (Sol finding
      // #5: a program succeeding but landing the WRONG byte elsewhere
      // must never be silently certified), while never reading back more
      // than kSnapshotWriteStepByteBudget bytes in one compactStep()
      // call.
      ::ota::platform::FlashRegion& destSnap = carve(dest).snapshot();
      SnapshotUnitLayout layout = computeSnapshotUnitLayout();
      uint32_t unit = compactionEraseCursor_;
      bool ok = false;

      if (unit == 0) {
        OtaSecuritySnapshotHeader newHeader;
        newHeader.storeIdentity = storeIdentity_;
        newHeader.generation = newGeneration;
        newHeader.txGlobalUpperBoundCheckpoint = txUpperBound_;
        newHeader.peerCount = (uint16_t)peerTableCount_;
        newHeader.cohortCount = (uint16_t)cohortTableCount_;
        newHeader.terminalCount = (uint16_t)terminalCount_;
        newHeader.factoryGrantConsumed = factoryGrantConsumed_;
        newHeader.factoryGrant = factoryGrant_;
        newHeader.liveBindingLength = liveBindingPresent_ ? (uint16_t)kLiveBindingFixedBytes : 0u;
        uint8_t expectedRaw[kHeaderEncodedBytes];
        uint8_t readBackRaw[kHeaderEncodedBytes];
        ok = OtaSecuritySnapshotHeaderCodec::encode(newHeader, expectedRaw, sizeof(expectedRaw)) &&
             ::ota::platform::isOk(destSnap.read(kHeaderAreaOffset, readBackRaw, sizeof(readBackRaw))) &&
             std::memcmp(expectedRaw, readBackRaw, kHeaderEncodedBytes) == 0;
      } else if (unit < layout.cohortBase) {
        const PeerTableEntry& kv = peerTable_[unit - layout.peerBase];
        OtaSecurityPeerEntry e;
        std::memcpy(e.fullPeerPublicKey, kv.key, 32);
        e.rxHead = kv.head;
        e.stableIndex = (uint16_t)kv.index;
        e.flags = 0x1u;
        uint8_t expectedRaw[kPeerEntryBytes];
        uint8_t readBackRaw[kPeerEntryBytes];
        ok = OtaSecurityPeerEntryCodec::encode(e, expectedRaw, sizeof(expectedRaw)) &&
             ::ota::platform::isOk(
                 destSnap.read(kPeerTableOffset + kv.index * kPeerEntryBytes, readBackRaw, sizeof(readBackRaw))) &&
             std::memcmp(expectedRaw, readBackRaw, kPeerEntryBytes) == 0;
      } else if (unit < layout.terminalBase) {
        const CohortTableEntry& kv = cohortTable_[unit - layout.cohortBase];
        OtaSecurityCohortEntry e;
        std::memcpy(e.groupContext, kv.key, 92);
        e.rxHead = kv.head;
        uint8_t expectedRaw[kCohortEntryBytes];
        uint8_t readBackRaw[kCohortEntryBytes];
        ok = OtaSecurityCohortEntryCodec::encode(e, expectedRaw, sizeof(expectedRaw)) &&
             ::ota::platform::isOk(
                 destSnap.read(kCohortTableOffset + kv.index * kCohortEntryBytes, readBackRaw, sizeof(readBackRaw))) &&
             std::memcmp(expectedRaw, readBackRaw, kCohortEntryBytes) == 0;
      } else if (unit < layout.liveBase) {
        uint32_t i = unit - layout.terminalBase;
        OtaSecurityTerminalEntry entry;
        uint8_t expectedRaw[kTerminalEntryBytes];
        uint8_t readBackRaw[kTerminalEntryBytes];
        ok = readTerminalRow(terminalIndex_[i], entry) &&
             OtaSecurityTerminalEntryCodec::encode(entry, expectedRaw, sizeof(expectedRaw)) &&
             ::ota::platform::isOk(
                 destSnap.read(kTerminalTableOffset + i * kTerminalEntryBytes, readBackRaw, sizeof(readBackRaw))) &&
             std::memcmp(expectedRaw, readBackRaw, kTerminalEntryBytes) == 0;
      } else {
        uint32_t chunk = unit - layout.liveBase;
        uint8_t expectedFull[kLiveBindingAreaBytes];
        if (OtaSecurityLiveBindingCodec::encode(liveBinding_, expectedFull, sizeof(expectedFull))) {
          uint32_t off = chunk * kLiveBindingAreaWriteChunkBytes;
          uint32_t len = std::min<uint32_t>(kLiveBindingAreaWriteChunkBytes, kLiveBindingAreaBytes - off);
          uint8_t readBackRaw[kLiveBindingAreaWriteChunkBytes];
          ok = ::ota::platform::isOk(destSnap.read(kLiveBindingOffset + off, readBackRaw, len)) &&
               std::memcmp(expectedFull + off, readBackRaw, len) == 0;
        }
      }

      if (!ok) {
        compactionInProgress_ = false;
        storeFrozen_ = true;
        return OtaSequenceBackingResult::Uncertain;
      }
      ++compactionEraseCursor_;
      if (compactionEraseCursor_ >= layout.totalUnits) {
        compactionPhase_ = CompactionPhase::PrepareSourceWitness;
        compactionEraseCursor_ = 0;
        witnessPrepSubPhase_ = WitnessPrepSubPhase::StreamDigest;
      }
      return OtaSequenceBackingResult::WouldBlock;
    }

    case CompactionPhase::PrepareSourceWitness: {
      // Prepare SOURCE's own witness sector (erase+rebuild) so it can
      // protect dest at generation+1 going forward; its old contents
      // (from two generations back) are dominated by the just-validated
      // dest snapshot. Bounded to <=1 program-or-erase call (and
      // <=kSnapshotWriteStepByteBudget bytes transferred) per
      // compactStep() invocation via prepareSourceWitnessStep()'s
      // digest-streaming/erase/body/marker sub-phases.
      WitnessPrepStepOutcome witnessOutcome = prepareSourceWitnessStep(dest, newGeneration);
      if (witnessOutcome == WitnessPrepStepOutcome::Failed) {
        compactionInProgress_ = false;
        storeFrozen_ = true;
        return OtaSequenceBackingResult::Uncertain;
      }
      if (witnessOutcome == WitnessPrepStepOutcome::InProgress) {
        return OtaSequenceBackingResult::WouldBlock;
      }
      compactionPhase_ = CompactionPhase::CommitSwitch;
      return OtaSequenceBackingResult::WouldBlock;
    }

    case CompactionPhase::CommitSwitch: {
      // Commit the switch record in SOURCE's log (reserved cell 255),
      // witnessed in dest (dest's witness sector is untouched and still
      // valid for source's current generation). Bounded to <=1
      // program-or-erase call per compactStep() invocation via
      // appendReservedRecordStep()'s body/marker sub-phase split.
      static const uint8_t kSwitchPayloadTemplate[kCellPayloadBytes] = {0};
      uint8_t switchPayload[kCellPayloadBytes];
      std::memcpy(switchPayload, kSwitchPayloadTemplate, sizeof(switchPayload));
      putU32(switchPayload, sizeof(switchPayload), 0, newGeneration);
      ReservedCellStepOutcome switchOutcome =
          appendReservedRecordStep(source, kSwitchCellIndex, OtaSecurityRecordType::SwitchRecord, activeGeneration_,
                                   switchPayload, 4, switchSubPhase_);
      if (switchOutcome == ReservedCellStepOutcome::Failed) {
        compactionInProgress_ = false;
        storeFrozen_ = true;
        return OtaSequenceBackingResult::Uncertain;
      }
      if (switchOutcome == ReservedCellStepOutcome::InProgress) {
        return OtaSequenceBackingResult::WouldBlock;
      }
      compactionPhase_ = CompactionPhase::Activate;
      return OtaSequenceBackingResult::WouldBlock;
    }

    case CompactionPhase::Activate: {
      // Activate dest. Every terminal row now canonically lives at its
      // fixed snapshot-table slot i on the (about to become active) dest
      // bank -- re-point every index entry there in one pass (cheap: RAM
      // only, no flash I/O, so it stays within THIS step's zero-I/O
      // budget) so subsequent reads resolve against the NEW active bank
      // correctly, never a stale ordinary-log physical index that no
      // longer means anything once activeBank_ flips below.
      for (uint32_t i = 0; i < terminalCount_; ++i) {
        terminalIndex_[i].location = (uint16_t)i;  // snapshot-table slot i, source bit 0.
        terminalIndex_[i].flags = 0x1u;
        // tupleFingerprint is content-derived and unchanged by relocation.
      }
      activeBank_ = dest;
      activeGeneration_ = newGeneration;
      // Compaction just built, verified, and activated a fresh, genuinely
      // witness-verified snapshot header on `dest` -- this MUST be
      // reflected here, or the very next refreshIfPhysicallyStale() call
      // (e.g. from a subsequent read/mutation on THIS SAME instance)
      // would see activeMagicNow (freshly decoded as true for `dest`)
      // diverge from a stale cached activeSnapshotValid_ and misclassify
      // its own just-completed compaction as an undetected FOREIGN
      // change, kicking off a wholly unnecessary bounded rebuild.
      activeSnapshotValid_ = true;
      nextFreeSlot_ = 0;
      ++compactionCount_;
      compactionInProgress_ = false;
      compactionPhase_ = CompactionPhase::Idle;
      return OtaSequenceBackingResult::Committed;
    }
  }
  // Unreachable (switch is exhaustive over a closed enum); satisfies
  // -Wreturn-type without adding a "default:" case that would silently
  // swallow a future unhandled phase.
  compactionInProgress_ = false;
  return OtaSequenceBackingResult::Uncertain;
}

}  // namespace security
}  // namespace ota
