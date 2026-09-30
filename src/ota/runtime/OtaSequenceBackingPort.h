#pragma once

// Store-agnostic backing-port abstraction for the OTA TX sequence
// allocator and RX replay ledger (see OtaTxSequenceLedger.h /
// OtaRxReplayLedger.h). Those two headers' FlashRegion-backed classes
// remain UNCHANGED and are retained as the reference implementation --
// this header instead defines the seam a FUTURE shared append-store
// (Astra's reserved bank tail; not yet released) can be adapted behind,
// without this runtime layer ever hardcoding a physical store, sector
// count, or wear-leveling scheme.
//
// Astra contract encoded here:
//  - TX sequence allocation is keyed by exactly ONE identity: this
//    node's own local identity, shared globally across every
//    peer/group direction it ever transmits to/in (a ChaCha20-Poly1305
//    nonce must never repeat for a given key, and only the raw
//    sequence itself needs this single global "never issue twice"
//    guard -- see OtaTxSequenceLedger.h's header comment).
//  - RX replay admission is keyed by either a FULL 32-byte peer
//    identity, or a FULL 92-byte group context -- NEVER a hash or a
//    short selector. Two different real identities must never be
//    conflated into the same durable record, even under an adversarial
//    or accidentally-colliding indexing scheme in a real shared store.
//  - A backing store's constructor retains references only and
//    performs NO flash/store I/O; every fact is obtained via an
//    explicit method call.
//  - openExisting()/readCounter()/reserveTx()/advanceRx() ALL require
//    an already-positively-bound, existing durable record. None of
//    them may silently commission/create one -- that would reintroduce
//    exactly the "blank heuristic" this whole engine has been
//    corrected away from elsewhere. The ONLY sanctioned way to
//    transition an identity/context from genuinely-never-commissioned
//    to a real starting counter is the separate, one-use
//    ITxSequenceCommissioningAuthority / IRxSequenceCommissioningAuthority
//    interfaces below -- deliberately NOT reachable through the regular
//    allocate()/admit() runtime API, and never exposed via a
//    "CommissionVirgin" constructor flag on a production backing.
//    CRITICAL: `Missing`/a genuinely-blank record is NEVER, by itself,
//    proof that an identity/context is safe to commission -- absence
//    can equally mean a PREVIOUSLY-commissioned record was lost
//    (corruption, erasure, a swapped/lost backing). A real production
//    authority implementation must derive its one-use permission from
//    a POSITIVE, INDEPENDENT, one-use factory/full-identity commissioning
//    proof (bound to the actual identity being commissioned) supplied
//    by a source OUTSIDE this counter API entirely -- never from the
//    blank/Missing state of the counter record alone. The concrete
//    safe-default base implementations below correctly always refuse
//    (`commissionVirginTx()`/`commissionVirginRx()` return false) when
//    left unwired for exactly this reason: an unwired/default authority
//    must deny, not "helpfully" treat absence as permission.
//  - advanceRx() takes an `expectedHead` (compare-and-swap style): a
//    real shared store may have its physical write head advanced by
//    OTHER contexts' unrelated mutations; a per-context record must
//    never be perturbed by that, and a caller whose cached head has
//    simply gone stale (Conflict) must refresh and retry -- it must
//    NEVER be treated as durability-uncertain and must NEVER
//    permanently disable the ledger, unlike genuine Missing/Corrupt/
//    Uncertain/OwnershipDenied/NoCapacity outcomes. A refresh reporting
//    a LOWER head than the caller already durably knows must never be
//    trusted either -- that would silently reopen already-closed
//    history, so callers fail closed on that instead.
//  - reserveTx() is likewise CAS-style via `expectedCurrentUpperBound`.
//    A block's reserved upper bound is an EXCLUSIVE OWNER CLAIM by
//    whoever reserved it -- a Conflict means ANOTHER writer already
//    legitimately owns every value up to the store's actual current
//    bound. Callers must never treat any of those values as their own
//    to emit (that would reissue a nonce another writer already owns);
//    they must skip the entire foreign range and reserve a brand-new
//    block of their own past it.
#include <array>
#include <cstdint>
#include <cstring>

namespace meshcore {
namespace ota {
namespace runtime {

// Every backing operation resolves to exactly one of these. Callers
// must treat Missing/Corrupt/Uncertain/OwnershipDenied/NoCapacity as
// fail-closed (permanently disable the ledger instance for its
// lifetime); WouldBlock/Conflict are transient/expected and must NOT
// disable anything -- only refuse THIS call.
enum class OtaSequenceBackingResult : uint8_t {
  Committed = 0,        // durably confirmed; the requested value now IS the durable truth.
  WouldBlock = 1,        // transient backpressure from the underlying store; retry later.
  Missing = 2,           // no existing bound record for this identity/context. This is NOT proof of
                         // first use: an absent/blank record may equally mean a previously-commissioned
                         // record was LOST (corruption/erasure/reconstruction gap). Never, by itself,
                         // license fresh/virgin commissioning -- see ITxSequenceCommissioningAuthority /
                         // IRxSequenceCommissioningAuthority below.
  Corrupt = 3,           // a record exists but failed structural/CRC validation.
  Uncertain = 4,         // the mutation's durability could not be confirmed (may or may not have landed).
  Conflict = 5,          // expectedHead did not match the store's actual current head (CAS mismatch).
  NoCapacity = 6,        // the store has a bounded number of distinct contexts and is full.
  OwnershipDenied = 7,   // not opened, or opened against a different identity/context than requested.
};

inline bool otaSequenceBackingResultIsPermanentFault(OtaSequenceBackingResult r) {
  switch (r) {
    case OtaSequenceBackingResult::Missing:
    case OtaSequenceBackingResult::Corrupt:
    case OtaSequenceBackingResult::Uncertain:
    case OtaSequenceBackingResult::OwnershipDenied:
    case OtaSequenceBackingResult::NoCapacity:
      return true;
    default:
      return false;  // Committed, WouldBlock, Conflict: never a permanent fault by themselves.
  }
}

// Full-byte RX admission context -- a discriminated union of a full
// 32-byte peer identity or a full 92-byte group context. Deliberately
// NOT a hash/selector: equality compares the ENTIRE bound array, so two
// genuinely-different identities can never be conflated even if some
// underlying index (e.g. a hash map in a real shared store) would
// otherwise collide them.
class OtaRxLedgerContext {
public:
  enum class Kind : uint8_t { Peer = 0, Group = 1 };

  static OtaRxLedgerContext forPeer(const uint8_t peerId[32]) {
    OtaRxLedgerContext c;
    c.kind_ = Kind::Peer;
    std::memcpy(c.peerId_.data(), peerId, 32);
    return c;
  }

  static OtaRxLedgerContext forGroup(const uint8_t groupContext[92]) {
    OtaRxLedgerContext c;
    c.kind_ = Kind::Group;
    std::memcpy(c.groupContext_.data(), groupContext, 92);
    return c;
  }

  Kind kind() const { return kind_; }
  const std::array<uint8_t, 32>& peerId() const { return peerId_; }
  const std::array<uint8_t, 92>& groupContext() const { return groupContext_; }

  // Full-byte comparison only -- never a truncated/hashed comparison.
  bool equals(const OtaRxLedgerContext& other) const {
    if (kind_ != other.kind_) return false;
    if (kind_ == Kind::Peer) return peerId_ == other.peerId_;
    return groupContext_ == other.groupContext_;
  }

private:
  Kind kind_ = Kind::Peer;
  std::array<uint8_t, 32> peerId_{};
  std::array<uint8_t, 92> groupContext_{};
};

// ---------------------------------------------------------------------
// TX: single global identity, block-reservation counter.
// ---------------------------------------------------------------------
class ITxSequenceBackingStore {
public:
  virtual ~ITxSequenceBackingStore() = default;

  // Binds this instance to its (single, implicit) identity's existing
  // durable record. Safe concrete default: no real backing wired ->
  // Missing (never silently treated as commissioned).
  virtual OtaSequenceBackingResult openExisting() { return OtaSequenceBackingResult::Missing; }

  // Requires a prior successful openExisting() that itself resolved
  // Committed (a genuinely existing, positively-commissioned record).
  virtual OtaSequenceBackingResult readCounter(uint32_t& outReservedUpperBound) {
    (void)outReservedUpperBound;
    return OtaSequenceBackingResult::OwnershipDenied;
  }

  // Durably reserves a fresh block of `blockSize` additional sequence
  // numbers (new upper bound = current + blockSize), returned in
  // `outNewUpperBound` on Committed. CAS-style: `expectedCurrentUpperBound`
  // must match the store's actual current upper bound, else Conflict
  // (transient -- e.g. another writer, or this caller's own previous
  // Uncertain reserve that had actually landed durably, advanced it
  // since the caller's last readCounter()/reserveTx()). This prevents a
  // stale allocator from ever reserving into a range another writer has
  // already claimed.
  virtual OtaSequenceBackingResult reserveTx(uint32_t expectedCurrentUpperBound, uint32_t blockSize,
                                              uint32_t& outNewUpperBound) {
    (void)expectedCurrentUpperBound;
    (void)blockSize;
    (void)outNewUpperBound;
    return OtaSequenceBackingResult::OwnershipDenied;
  }
};

// One-use, independent-of-the-regular-API commissioning authority. A
// production TX backing NEVER exposes a "CommissionVirgin" constructor
// flag; the only way a genuinely-never-commissioned identity gets a
// real starting counter is through this separate interface, which a
// deployment can choose to wire up (or not) entirely independently of
// the regular runtime allocator.
class ITxSequenceCommissioningAuthority {
public:
  virtual ~ITxSequenceCommissioningAuthority() = default;

  // A real implementation MUST refuse unless BOTH (a) the backing
  // genuinely has no existing counter record yet (Missing -- never
  // silently overwrites/relaxes an already-commissioned or corrupt
  // identity), AND (b) an INDEPENDENT, positive, one-use factory/full-
  // identity commissioning proof for THIS SPECIFIC identity has been
  // supplied from outside this counter API. Condition (a) alone is
  // NEVER sufficient: a genuinely-blank record can equally mean a
  // previously-commissioned record was lost, not that the identity is
  // safe to (re)commission. `initialUpperBound` must be >= 1 (0 is
  // never a valid durable value -- see OtaTxSequenceLedger.h).
  // Safe concrete default: always refuses (no real authority wired) --
  // an unwired default MUST deny, never treat blank/Missing as implicit
  // permission.
  virtual bool commissionVirginTx(uint32_t initialUpperBound) {
    (void)initialUpperBound;
    return false;
  }
};

// ---------------------------------------------------------------------
// RX: multi-context (full peer/group identity), watermark-CAS counter.
// ---------------------------------------------------------------------
class IRxSequenceBackingStore {
public:
  virtual ~IRxSequenceBackingStore() = default;

  virtual OtaSequenceBackingResult openExisting(const OtaRxLedgerContext& context) {
    (void)context;
    return OtaSequenceBackingResult::Missing;
  }

  virtual OtaSequenceBackingResult readCounter(const OtaRxLedgerContext& context, uint32_t& outWatermark) {
    (void)context;
    (void)outWatermark;
    return OtaSequenceBackingResult::OwnershipDenied;
  }

  // Compare-and-swap: `expectedHead` must match the store's actual
  // current watermark for `context`, else Conflict (transient, NOT a
  // permanent fault -- another context's mutation may simply have
  // moved a shared physical head; the caller should refresh via
  // readCounter() and retry, never disable itself over this alone).
  virtual OtaSequenceBackingResult advanceRx(const OtaRxLedgerContext& context, uint32_t expectedHead,
                                              uint32_t newHead) {
    (void)context;
    (void)expectedHead;
    (void)newHead;
    return OtaSequenceBackingResult::OwnershipDenied;
  }
};

class IRxSequenceCommissioningAuthority {
public:
  virtual ~IRxSequenceCommissioningAuthority() = default;

  // Same "blank alone is never sufficient" contract as
  // ITxSequenceCommissioningAuthority::commissionVirginTx() above: a
  // real implementation MUST require both a genuinely-Missing record
  // for `context` AND an independent, positive, one-use factory/full-
  // identity commissioning proof bound to that SAME context, supplied
  // from outside this counter API. `initialWatermark` must be >= 1
  // (see OtaRxReplayLedger.h -- sequence 0 is never valid; the
  // smallest safe commissioning act marks sequence 1 as already-seen
  // so genuine traffic starts at 2). Safe concrete default: always
  // refuses (no real authority wired) -- deny, never infer permission
  // from absence.
  virtual bool commissionVirginRx(const OtaRxLedgerContext& context, uint32_t initialWatermark) {
    (void)context;
    (void)initialWatermark;
    return false;
  }
};

}  // namespace runtime
}  // namespace ota
}  // namespace meshcore
