#pragma once

// Thin adapters implementing the UNCHANGED, existing
// ITxSequenceBackingStore / IRxSequenceBackingStore /
// ITxSequenceCommissioningAuthority / IRxSequenceCommissioningAuthority
// interfaces (ota/runtime/OtaSequenceBackingPort.h) by delegating to a real
// flash-serialized OtaSecurityStore (OtaSecurityStore.h). No new I/O or
// policy lives here -- every method is a direct pass-through plus the
// identity-binding/ownership checks the port's doc comments require.
//
// Mirrors the EXISTING-ONLY split already established by
// ota/runtime/OtaFlashSequenceBackingAdapters.h: the regular backing-store
// adapters never silently commission anything, and the commissioning
// authorities are SEPARATE classes, each requiring an explicit
// `factoryGrantAuthorized` flag supplied by the caller/test from OUTSIDE
// this counter API (standing in for an independent, positive, one-use
// factory/full-identity proof) -- never inferred from a blank/Missing
// counter record alone.

#include <cstdint>

#include "ota/runtime/OtaSequenceBackingPort.h"
#include "ota/security/OtaSecurityStore.h"

namespace ota {
namespace security {

using ::meshcore::ota::runtime::IRxSequenceBackingStore;
using ::meshcore::ota::runtime::IRxSequenceCommissioningAuthority;
using ::meshcore::ota::runtime::ITxSequenceBackingStore;
using ::meshcore::ota::runtime::ITxSequenceCommissioningAuthority;
using ::meshcore::ota::runtime::OtaRxLedgerContext;
using ::meshcore::ota::runtime::OtaSequenceBackingResult;

// Single global TX identity, backed by `store`. The store reference must
// outlive this adapter; no I/O happens in this constructor (matches the
// port's "no I/O in constructors" contract -- OtaSecurityStore itself
// requires an explicit reconstruct() call before use, performed by the
// caller/test, not here).
class OtaSecurityTxBackingStore : public ITxSequenceBackingStore {
public:
  explicit OtaSecurityTxBackingStore(OtaSecurityStore& store) : store_(store) {}

  // RAII drain: if this adapter object is destroyed while it still holds
  // an in-flight ordinary op's RAM ticket (e.g. a caller drops it mid
  // WouldBlock-retry loop), release that RAM-only resumption cursor so
  // the underlying Store is never permanently wedged behind an owner
  // pointer that can no longer ever call back in to resume/cancel it.
  // This never undoes anything already durable -- see
  // cancelPendingOrdinaryOperation()'s doc comment. Passing the actual
  // ticket_ (not just `this`) is required now: a bare owner match is no
  // longer sufficient to cancel -- see OtaSecurityOperationTicket's doc
  // comment on ABA protection.
  ~OtaSecurityTxBackingStore() override { store_.cancelPendingOrdinaryOperation(ticket_); }


  OtaSequenceBackingResult openExisting() override { return store_.openExistingTx(); }

  OtaSequenceBackingResult readCounter(uint32_t& outReservedUpperBound) override {
    return store_.readTxCounter(outReservedUpperBound);
  }

  OtaSequenceBackingResult reserveTx(uint32_t expectedCurrentUpperBound, uint32_t blockSize,
                                     uint32_t& outNewUpperBound) override {
    // Passing `this` as the owner gives THIS adapter object a distinct
    // identity from any sibling OtaSecurityTxBackingStore wrapping the
    // SAME underlying store; `ticket_` is this adapter's own private,
    // in/out resumption handle -- the fixed port signature has no room
    // for a caller-supplied ticket, so the adapter itself is the ticket's
    // sole keeper across resumed WouldBlock calls.
    return store_.reserveTx(expectedCurrentUpperBound, blockSize, outNewUpperBound, this, ticket_);
  }

  // Test/diagnostic-only: exposes the underlying store's owner-bound
  // resumable-op observability (pendingOrdinaryOperationTicket() /
  // hasPendingOrdinaryOperation()) through this thin pass-through adapter
  // without adding anything to the fixed port interface itself.
  OtaSecurityStore& underlyingStoreForTest() { return store_; }

private:
  OtaSecurityStore& store_;
  OtaSecurityOperationTicket ticket_{};
};

// One bound RX context (full peer32 or full group92), backed by `store`.
// Like the reference FlashRxSequenceBackingStore, the bound context is
// fixed at construction and any call using a DIFFERENT context is refused
// OwnershipDenied.
class OtaSecurityRxBackingStore : public IRxSequenceBackingStore {
public:
  OtaSecurityRxBackingStore(OtaSecurityStore& store, OtaRxLedgerContext boundContext)
      : store_(store), boundContext_(boundContext) {}

  // See OtaSecurityTxBackingStore's identical destructor note.
  ~OtaSecurityRxBackingStore() override { store_.cancelPendingOrdinaryOperation(ticket_); }


  OtaSequenceBackingResult openExisting(const OtaRxLedgerContext& context) override {
    if (!context.equals(boundContext_)) return OtaSequenceBackingResult::OwnershipDenied;
    return store_.openExistingRx(context);
  }

  OtaSequenceBackingResult readCounter(const OtaRxLedgerContext& context, uint32_t& outWatermark) override {
    if (!context.equals(boundContext_)) return OtaSequenceBackingResult::OwnershipDenied;
    return store_.readRxCounter(context, outWatermark);
  }

  OtaSequenceBackingResult advanceRx(const OtaRxLedgerContext& context, uint32_t expectedHead,
                                    uint32_t newHead) override {
    if (!context.equals(boundContext_)) return OtaSequenceBackingResult::OwnershipDenied;
    // See OtaSecurityTxBackingStore::reserveTx's identical `this`-as-owner
    // / private-ticket note.
    return store_.advanceRx(context, expectedHead, newHead, this, ticket_);
  }

  // Test/diagnostic-only: see OtaSecurityTxBackingStore's identical note.
  OtaSecurityStore& underlyingStoreForTest() { return store_; }

private:
  OtaSecurityStore& store_;
  OtaRxLedgerContext boundContext_;
  OtaSecurityOperationTicket ticket_{};
};

// Separate, one-use TX commissioning authority. `factoryGrantAuthorized`
// stands in for an independent, positive, one-use factory/full-identity
// proof supplied from outside this counter API (see the file/class doc
// comments above and OtaSequenceBackingPort.h); this adapter itself does
// NOT derive permission from the counter's Missing/blank state.
class OtaSecurityTxCommissioningAuthority : public ITxSequenceCommissioningAuthority {
public:
  OtaSecurityTxCommissioningAuthority(OtaSecurityStore& store, bool factoryGrantAuthorized)
      : store_(store), factoryGrantAuthorized_(factoryGrantAuthorized) {}

  // See OtaSecurityTxBackingStore's identical destructor note.
  ~OtaSecurityTxCommissioningAuthority() override { store_.cancelPendingOrdinaryOperation(ticket_); }


  // The fixed port interface's bool-returning signature cannot express
  // WouldBlock/Conflict/etc. distinctly; map ONLY the typed Committed
  // result to true, everything else (still pending, request mismatch on
  // a resume, or a genuine denial) to false -- the caller of this
  // bool-only port API must retry with the SAME original arguments on
  // any false, exactly as it always had to.
  bool commissionVirginTx(uint32_t initialUpperBound) override {
    return store_.commissionVirginTx(initialUpperBound, factoryGrantAuthorized_, this, ticket_) ==
           OtaSequenceBackingResult::Committed;
  }

  // Test/diagnostic-only: see OtaSecurityTxBackingStore's identical note.
  OtaSecurityStore& underlyingStoreForTest() { return store_; }

private:
  OtaSecurityStore& store_;
  bool factoryGrantAuthorized_;
  OtaSecurityOperationTicket ticket_{};
};

// Separate, one-use RX commissioning authority (per-call context, not
// bound at construction, since a single factory grant source may
// legitimately authorize enrollment of more than one context -- the
// store itself still independently enforces one-use-per-context and
// capacity bounds regardless of how many times this authority is asked).
class OtaSecurityRxCommissioningAuthority : public IRxSequenceCommissioningAuthority {
public:
  OtaSecurityRxCommissioningAuthority(OtaSecurityStore& store, bool factoryGrantAuthorized)
      : store_(store), factoryGrantAuthorized_(factoryGrantAuthorized) {}

  // See OtaSecurityTxBackingStore's identical destructor note.
  ~OtaSecurityRxCommissioningAuthority() override { store_.cancelPendingOrdinaryOperation(ticket_); }


  // Same bool-mapping contract as commissionVirginTx() above.
  bool commissionVirginRx(const OtaRxLedgerContext& context, uint32_t initialWatermark) override {
    return store_.commissionVirginRx(context, initialWatermark, factoryGrantAuthorized_, this, ticket_) ==
           OtaSequenceBackingResult::Committed;
  }

  // Test/diagnostic-only: see OtaSecurityTxBackingStore's identical note.
  OtaSecurityStore& underlyingStoreForTest() { return store_; }

private:
  OtaSecurityStore& store_;
  bool factoryGrantAuthorized_;
  OtaSecurityOperationTicket ticket_{};
};

}  // namespace security
}  // namespace ota
