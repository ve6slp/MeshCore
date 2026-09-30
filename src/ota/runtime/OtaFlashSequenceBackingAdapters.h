#pragma once

// Reference IOtaSequenceBackingStore implementations bridging the
// UNCHANGED, already-proven FlashRegion+2-sector journal classes in
// OtaTxSequenceLedger.h / OtaRxReplayLedger.h behind the store-agnostic
// port defined in OtaSequenceBackingPort.h. These adapters are NOT a
// production flash-wear solution for the future shared append store --
// that real store (two non-contiguous 100KiB tails, 64KiB snapshot +
// 36KiB log, 128 cells, 286 ordinary capacity, sealed source/switch
// witness, no fallback) is owned by FW and lands after its health gate.
// This header exists purely so the abstraction in OtaSequenceBackingPort.h
// is proven against the CURRENT, already fully-tested 2-sector journal
// (see test_lora_ota_runtime.cpp's OtaTxSequenceLedger/OtaRxReplayLedger
// suites) rather than only ever being exercised by an in-memory test
// double.
#include <cstdint>

#include "ota/platform/FlashRegion.h"
#include "ota/runtime/OtaRxReplayLedger.h"
#include "ota/runtime/OtaSequenceBackingPort.h"
#include "ota/runtime/OtaTxSequenceLedger.h"

namespace meshcore {
namespace ota {
namespace runtime {

// Single global TX identity backed by one dedicated FlashRegion (exactly
// the same physical layout OtaTxSequenceAllocator already uses). The
// constructor retains only a reference -- no I/O happens until
// openExisting() is explicitly called.
//
// EXISTING-ONLY: this reference adapter deliberately does NOT implement
// ITxSequenceCommissioningAuthority. A bare "genuinely blank flash
// region" check is NOT independent, durable, one-use commissioning
// proof -- a lost/erased record would let this same identity silently
// rebootstrap. A real production authority must derive its one-use
// permission from an INDEPENDENT commissioning/provenance fact outside
// this adapter (see the campaign-scope ICampaignCommissioningProvenancePort
// precedent); wiring such an authority is deliberately left to that
// separate, independently-authorized mechanism, never bundled into this
// existing-record-only adapter. Tests that need a genuinely-commissioned
// starting record for this reference adapter must preseed it directly
// via the already-existing, already-proven OtaTxSequenceLedgerRecord::reserve()
// primitive (i.e. as an explicitly independently-authorized test setup
// step), never via a fake "authority" method on this class.
class FlashTxSequenceBackingStore : public ITxSequenceBackingStore {
public:
  explicit FlashTxSequenceBackingStore(::ota::platform::FlashRegion& region) : region_(region) {}

  // `openExisting()` must never let this SAME instance's known-durable
  // floor (`cachedUpperBound_`) regress. A structurally-valid-looking
  // read that is LOWER than a value this instance already positively
  // observed is real corruption/rollback (or the record having gone
  // blank/regressed out from under it), never a legitimate reopen --
  // reissuing/re-admitting anything below a known head risks reusing an
  // already-used nonce or re-opening an already-closed replay window.
  // A genuinely fresh instance that has never observed a positive value
  // (`cachedUpperBound_ == 0`) still reports Missing for a blank record,
  // per the existing "blank alone is never virgin-commissioning proof"
  // contract. NOTE: this only protects a SAME reference-adapter
  // instance's own in-process memory of what it already saw -- a
  // brand-new instance after a genuine reboot has no way to detect a
  // durable full-record replacement/rollback from outside this
  // reference adapter's physical-provenance claim; that is explicitly
  // out of scope here.
  OtaSequenceBackingResult openExisting() override {
    uint32_t value = 0;
    if (!OtaTxSequenceLedgerRecord::readNewestFailClosed(region_, value)) {
      opened_ = false;
      return OtaSequenceBackingResult::Corrupt;
    }
    if (value < cachedUpperBound_) {
      // Regression below a floor this instance already positively knew
      // -- never trust it, and never lower the retained known floor.
      opened_ = false;
      return OtaSequenceBackingResult::Corrupt;
    }
    if (value == 0) {
      opened_ = false;
      // Absent record: NOT proof of first use. A previously-commissioned
      // record may have been LOST (corruption/erasure) rather than this
      // identity being genuinely virgin -- see ITxSequenceCommissioningAuthority.
      return OtaSequenceBackingResult::Missing;
    }
    opened_ = true;
    cachedUpperBound_ = value;
    return OtaSequenceBackingResult::Committed;
  }

  // `readCounter()` ALWAYS re-reads the ACTUAL durable journal -- never
  // just echoes a cached value -- because the abstract port promises a
  // comparison against the real current durable head, not one
  // particular adapter instance's private RAM copy. This matters even
  // for a single dedicated FlashRegion: nothing prevents a SECOND
  // FlashTxSequenceBackingStore instance (a distinct writer, e.g. after
  // a reboot, or a genuinely separate allocator sharing the same
  // region in-process) from having durably advanced the journal past
  // what THIS instance last cached.
  OtaSequenceBackingResult readCounter(uint32_t& outReservedUpperBound) override {
    if (!opened_) return OtaSequenceBackingResult::OwnershipDenied;
    uint32_t actual = 0;
    if (!OtaTxSequenceLedgerRecord::readNewestFailClosed(region_, actual) || actual == 0) {
      // A genuine read/CRC failure, or the record having gone blank
      // AFTER this instance successfully opened it, is real journal
      // corruption/loss -- never a success-shaped cached answer.
      return OtaSequenceBackingResult::Corrupt;
    }
    if (actual < cachedUpperBound_) {
      // The durable head can never legitimately regress below a value
      // this instance already durably observed -- a lower-but-otherwise
      // -valid-looking record is real corruption/rollback, not a fresh
      // legitimate state. `cachedUpperBound_` is the known-floor guard
      // this comparison needs, not a trusted answer by itself.
      return OtaSequenceBackingResult::Corrupt;
    }
    cachedUpperBound_ = actual;
    outReservedUpperBound = actual;
    return OtaSequenceBackingResult::Committed;
  }

  // CAS-style: `expectedCurrentUpperBound` is compared against the
  // ACTUAL current durable head (freshly re-read here, never the stale
  // private cache) -- a mismatch means EITHER another writer durably
  // advanced the journal past this instance's last-known value, OR
  // this instance's own prior Uncertain reserve had actually landed;
  // either way it is a transient Conflict, never a permanent fault.
  // NOTE: this reference adapter's underlying 2-sector journal
  // (OtaTxSequenceLedgerRecord) is NOT thread-atomic -- concurrent
  // callers racing the SAME physical erase/program cycle from separate
  // threads/cores is out of scope here; this only fixes the port's
  // promised actual-head comparison for genuinely sequential/in-process
  // multi-writer use (e.g. two allocator instances taking turns, or
  // reconstruction after reboot), not a true concurrent-hardware CAS.
  OtaSequenceBackingResult reserveTx(uint32_t expectedCurrentUpperBound, uint32_t blockSize,
                                      uint32_t& outNewUpperBound) override {
    if (!opened_) return OtaSequenceBackingResult::OwnershipDenied;
    uint32_t actual = 0;
    if (!OtaTxSequenceLedgerRecord::readNewestFailClosed(region_, actual) || actual == 0) {
      return OtaSequenceBackingResult::Corrupt;  // genuine journal loss/corruption, not a cache miss.
    }
    if (actual < cachedUpperBound_) {
      return OtaSequenceBackingResult::Corrupt;  // regression below a known-durable floor -- real fault.
    }
    cachedUpperBound_ = actual;
    if (expectedCurrentUpperBound != actual) {
      return OtaSequenceBackingResult::Conflict;
    }
    if (blockSize == 0 || actual > (0xFFFFFFFFu - blockSize)) {
      return OtaSequenceBackingResult::NoCapacity;  // sequence space exhausted -- never wrap.
    }
    const uint32_t target = actual + blockSize;
    if (!OtaTxSequenceLedgerRecord::reserve(region_, target)) {
      return OtaSequenceBackingResult::Uncertain;  // durability unknown -- caller must fail closed.
    }
    cachedUpperBound_ = target;
    outNewUpperBound = target;
    return OtaSequenceBackingResult::Committed;
  }

 private:
  ::ota::platform::FlashRegion& region_;
  bool opened_ = false;
  uint32_t cachedUpperBound_ = 0;
};

// A single bound RX context backed by one dedicated FlashRegion (mirrors
// OtaRxReplayLedger's existing one-region-per-direction model). The
// bound `context` is fixed at construction (identity binding), and any
// call using a DIFFERENT context is refused OwnershipDenied -- this
// models, for the reference/flash path, the identity-binding guarantee
// a real multi-context shared store must also enforce internally. This
// RAM-only `boundContext_` is a reference-adapter convenience, NOT
// durable identity proof -- a real production adapter must derive its
// binding from the SAME durable record it reads/writes, not a
// constructor argument alone.
//
// EXISTING-ONLY: like FlashTxSequenceBackingStore, this class does NOT
// implement IRxSequenceCommissioningAuthority -- a blank-region check
// is not independent commissioning proof. Tests must preseed a
// genuinely-commissioned starting watermark directly via the existing
// OtaRxReplayLedgerRecord::advance() primitive.
class FlashRxSequenceBackingStore : public IRxSequenceBackingStore {
public:
  FlashRxSequenceBackingStore(::ota::platform::FlashRegion& region, OtaRxLedgerContext boundContext)
      : region_(region), boundContext_(boundContext) {}

  // Same known-durable-floor never-regresses contract as
  // FlashTxSequenceBackingStore::openExisting() -- see that method's
  // doc comment for the full rationale and its explicit same-instance-
  // only / no-cross-reboot-detection scope limitation.
  OtaSequenceBackingResult openExisting(const OtaRxLedgerContext& context) override {
    if (!context.equals(boundContext_)) return OtaSequenceBackingResult::OwnershipDenied;
    uint32_t watermark = 0;
    if (!OtaRxReplayLedgerRecord::readNewestFailClosed(region_, watermark)) {
      opened_ = false;
      return OtaSequenceBackingResult::Corrupt;
    }
    if (watermark < cachedWatermark_) {
      // Regression below a floor this instance already positively knew
      // -- never trust it, and never lower the retained known floor.
      opened_ = false;
      return OtaSequenceBackingResult::Corrupt;
    }
    if (watermark == 0) {
      opened_ = false;
      // Absent record: NOT proof of first use for this context. A
      // previously-commissioned watermark may have been LOST rather
      // than this context being genuinely virgin -- see
      // IRxSequenceCommissioningAuthority.
      return OtaSequenceBackingResult::Missing;
    }
    opened_ = true;
    cachedWatermark_ = watermark;
    return OtaSequenceBackingResult::Committed;
  }

  // `readCounter()` ALWAYS re-reads the ACTUAL durable journal for this
  // bound context -- never just echoes a cached value -- for the same
  // reason as FlashTxSequenceBackingStore::readCounter(): the port
  // promises comparison against the real current durable head, not one
  // adapter instance's private RAM copy (e.g. a second
  // FlashRxSequenceBackingStore bound to the SAME context/region may
  // have durably advanced it since this instance last cached it).
  OtaSequenceBackingResult readCounter(const OtaRxLedgerContext& context, uint32_t& outWatermark) override {
    if (!context.equals(boundContext_)) return OtaSequenceBackingResult::OwnershipDenied;
    if (!opened_) return OtaSequenceBackingResult::OwnershipDenied;
    uint32_t actual = 0;
    if (!OtaRxReplayLedgerRecord::readNewestFailClosed(region_, actual) || actual == 0) {
      // Genuine read/CRC failure, or the record having gone blank AFTER
      // this instance successfully opened it: real journal corruption
      // or loss, never a success-shaped cached answer.
      return OtaSequenceBackingResult::Corrupt;
    }
    if (actual < cachedWatermark_) {
      // The durable watermark can never legitimately regress below a
      // value this instance already durably observed -- a lower-but-
      // valid-looking record is real corruption/rollback, never a
      // fresh legitimate state. `cachedWatermark_` is the known-floor
      // guard this comparison needs, not a trusted answer by itself.
      return OtaSequenceBackingResult::Corrupt;
    }
    cachedWatermark_ = actual;
    outWatermark = actual;
    return OtaSequenceBackingResult::Committed;
  }

  // CAS-style, compared against the ACTUAL current durable watermark
  // (freshly re-read here, never the stale private cache). NOTE: like
  // the TX adapter, this reference journal is NOT thread-atomic --
  // this only fixes the promised actual-head comparison for genuinely
  // sequential/in-process multi-writer use, never a true concurrent-
  // hardware CAS.
  OtaSequenceBackingResult advanceRx(const OtaRxLedgerContext& context, uint32_t expectedHead,
                                     uint32_t newHead) override {
    if (!context.equals(boundContext_)) return OtaSequenceBackingResult::OwnershipDenied;
    if (!opened_) return OtaSequenceBackingResult::OwnershipDenied;
    uint32_t actual = 0;
    if (!OtaRxReplayLedgerRecord::readNewestFailClosed(region_, actual) || actual == 0) {
      return OtaSequenceBackingResult::Corrupt;  // genuine journal loss/corruption, not a cache miss.
    }
    if (actual < cachedWatermark_) {
      return OtaSequenceBackingResult::Corrupt;  // regression below a known-durable floor -- real fault.
    }
    cachedWatermark_ = actual;
    if (expectedHead != actual) {
      // A mismatch against the ACTUAL durable head means either another
      // writer bound to this same context durably advanced it, or this
      // instance's own prior Uncertain advance had actually landed --
      // still surfaced as a transient Conflict, never a permanent fault.
      return OtaSequenceBackingResult::Conflict;
    }
    if (!OtaRxReplayLedgerRecord::advance(region_, newHead)) {
      return OtaSequenceBackingResult::Uncertain;
    }
    cachedWatermark_ = newHead;
    return OtaSequenceBackingResult::Committed;
  }

private:
  ::ota::platform::FlashRegion& region_;
  OtaRxLedgerContext boundContext_;
  bool opened_ = false;
  uint32_t cachedWatermark_ = 0;
};

}  // namespace runtime
}  // namespace ota
}  // namespace meshcore
