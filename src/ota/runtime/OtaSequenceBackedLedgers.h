#pragma once

// Store-agnostic runtime-facing TX sequence allocator / RX replay
// ledger built purely against the abstract ITxSequenceBackingStore /
// IRxSequenceBackingStore interfaces (OtaSequenceBackingPort.h). These
// are prerequisites for a future real shared append store (Astra's
// reserved bank tail; FW not yet released) -- they implement IDENTICAL
// block-reservation / watermark-bitmap semantics to the existing
// FlashRegion-specific OtaTxSequenceAllocator / OtaRxReplayLedger
// (which remain the unmodified reference implementation), but never
// hardcode a physical store: any conforming backing (the flash adapter
// in OtaFlashSequenceBackingAdapters.h, an in-memory test double, or a
// future shared-store adapter) can be plugged in without touching this
// header.
//
// Fault handling contract:
//  - Missing/Corrupt/Uncertain/OwnershipDenied/NoCapacity from the
//    backing permanently disable this instance for its lifetime (fail
//    closed) -- only a freshly reconstructed instance re-querying the
//    backing can ever resolve/re-open.
//  - WouldBlock/Conflict are transient and NEVER permanently disable
//    anything: WouldBlock simply fails this one call (retry later);
//    Conflict (expectedHead stale relative to the backing's actual
//    current head -- e.g. after a prior call's durability was reported
//    Uncertain but had actually landed, or a genuinely shared store
//    saw another writer advance the head) triggers exactly one
//    bounded in-call refresh+retry before giving up on this call
//    (never a busy loop).
#include <cstdint>

#include "ota/runtime/OtaSequenceBackingPort.h"

namespace meshcore {
namespace ota {
namespace runtime {

class OtaBackedTxSequenceAllocator {
public:
  static constexpr uint32_t kDefaultBlockSize = 64u;

  explicit OtaBackedTxSequenceAllocator(ITxSequenceBackingStore& backing, uint32_t blockSize = kDefaultBlockSize)
      : backing_(backing), blockSize_(blockSize == 0 ? kDefaultBlockSize : blockSize) {}

  // Returns the next never-before-issued sequence number (>= 1). See
  // OtaTxSequenceAllocator::allocate() for the identical semantics this
  // mirrors (block reservation, whole-block skip on reconstruction,
  // never wraps).
  bool allocate(uint32_t* outSequence) {
    if (outSequence == nullptr || disabled_) return false;
    if (!opened_) {
      const OtaSequenceBackingResult openResult = backing_.openExisting();
      if (openResult != OtaSequenceBackingResult::Committed) {
        if (!otaSequenceBackingResultIsPermanentFault(openResult)) return false;  // WouldBlock/Conflict: transient, retry later.
        disabled_ = true;  // Missing/Corrupt/Uncertain/OwnershipDenied/NoCapacity: fail closed permanently.
        return false;
      }
      uint32_t existingUpperBound = 0;
      const OtaSequenceBackingResult readResult = backing_.readCounter(existingUpperBound);
      if (readResult != OtaSequenceBackingResult::Committed) {
        if (!otaSequenceBackingResultIsPermanentFault(readResult)) return false;  // WouldBlock/Conflict: not opened yet, transient, retry.
        disabled_ = true;
        return false;
      }
      if (existingUpperBound == UINT32_MAX) {
        disabled_ = true;  // sequence space already fully exhausted: never wrap nextSequence_ to 0.
        return false;
      }
      if (existingUpperBound == 0) {
        // A genuinely-commissioned durable value is NEVER 0 (see the
        // commissioning-authority contract: initialUpperBound must be
        // >= 1). A "Committed" result reporting 0 is self-contradictory
        // -- an honestly never-commissioned identity must answer
        // Missing, not a successful-looking 0 -- so this can only be a
        // corrupt/invalid backing masquerading as success. Never treat
        // it as "nothing reserved yet, safe to start from 1"; fail
        // closed instead of silently authorizing a first reservation
        // the backing never actually attested to.
        disabled_ = true;
        return false;
      }
      opened_ = true;
      reservedUpperBound_ = existingUpperBound;
      nextSequence_ = reservedUpperBound_ + 1u;  // deliberately skips any abandoned partial block.
    }

    if (nextSequence_ > reservedUpperBound_) {
      if (reservedUpperBound_ > (0xFFFFFFFFu - blockSize_)) {
        disabled_ = true;  // sequence space exhausted: fail closed, never wrap.
        return false;
      }
      uint32_t expectedForThisCall = reservedUpperBound_;
      uint32_t newUpperBound = 0;
      OtaSequenceBackingResult reserveResult = backing_.reserveTx(expectedForThisCall, blockSize_, newUpperBound);
      if (reserveResult == OtaSequenceBackingResult::Conflict) {
        // Bounded, single refresh+retry: our cached reservedUpperBound_
        // is stale relative to the store's actual current upper bound
        // (e.g. another writer genuinely reserved a block ahead of us).
        // CRITICAL: a reservation's upper bound is an EXCLUSIVE OWNER
        // CLAIM, never permission for anyone else to consume it -- we
        // must NEVER treat any value <= the refreshed bound as ours to
        // emit (that would reissue a nonce the other writer already
        // legitimately owns). Instead we burn/skip the ENTIRE foreign
        // range and reserve a brand-new block of our own past it,
        // exactly like the existing "skip the whole abandoned/foreign
        // block" reboot discipline.
        uint32_t freshUpperBound = 0;
        const OtaSequenceBackingResult refreshResult = backing_.readCounter(freshUpperBound);
        if (refreshResult != OtaSequenceBackingResult::Committed) {
          if (!otaSequenceBackingResultIsPermanentFault(refreshResult)) {
            return false;  // WouldBlock/Conflict: transient, state untouched, caller retries this same allocate() later.
          }
          disabled_ = true;
          return false;
        }
        if (freshUpperBound < reservedUpperBound_) {
          // A "Committed" refresh reporting a LOWER bound than what we
          // already know is durably claimed would silently reopen
          // already-owned range -- never trust it; fail closed instead.
          disabled_ = true;
          return false;
        }
        reservedUpperBound_ = freshUpperBound;
        if (freshUpperBound == UINT32_MAX || reservedUpperBound_ > (0xFFFFFFFFu - blockSize_)) {
          disabled_ = true;  // sequence space exhausted: fail closed, never wrap.
          return false;
        }
        nextSequence_ = freshUpperBound + 1u;  // exclusive: none of [.., freshUpperBound] is ever ours.
        expectedForThisCall = reservedUpperBound_;
        reserveResult = backing_.reserveTx(expectedForThisCall, blockSize_, newUpperBound);
      }
      if (reserveResult == OtaSequenceBackingResult::WouldBlock ||
          reserveResult == OtaSequenceBackingResult::Conflict) {
        return false;  // transient: caller may retry this same allocate() later.
      }
      if (reserveResult != OtaSequenceBackingResult::Committed) {
        disabled_ = true;  // Uncertain/NoCapacity/OwnershipDenied/etc: durability unknown, fail closed.
        return false;
      }
      if (newUpperBound != expectedForThisCall + blockSize_) {
        // A CAS reservation's ENTIRE contract is that a successful
        // (Committed) result grants EXACTLY the claimed block --
        // [expectedForThisCall+1 .. expectedForThisCall+blockSize_] --
        // never more, never less. A backing reporting any other value
        // alongside Committed is not honoring the CAS it was asked to
        // perform (a silent overclaim, or a truncated/corrupt grant)
        // and must never be trusted enough to emit from -- fail closed
        // rather than accept a success-shaped but invalid payload.
        disabled_ = true;
        return false;
      }
      reservedUpperBound_ = newUpperBound;
    }

    *outSequence = nextSequence_;
    if (nextSequence_ == UINT32_MAX) {
      disabled_ = true;
    } else {
      ++nextSequence_;
    }
    return true;
  }

  bool isDisabled() const { return disabled_; }

private:
  ITxSequenceBackingStore& backing_;
  uint32_t blockSize_;
  bool opened_ = false;
  bool disabled_ = false;
  uint32_t reservedUpperBound_ = 0;
  uint32_t nextSequence_ = 1;
};

class OtaBackedRxReplayLedger {
public:
  static constexpr uint32_t kWindowBits = 64u;

  OtaBackedRxReplayLedger(IRxSequenceBackingStore& backing, OtaRxLedgerContext context)
      : backing_(backing), context_(context) {}

  bool load() {
    if (loaded_) return !disabled_;
    const OtaSequenceBackingResult openResult = backing_.openExisting(context_);
    if (openResult != OtaSequenceBackingResult::Committed) {
      if (!otaSequenceBackingResultIsPermanentFault(openResult)) return false;  // WouldBlock/Conflict: not loaded yet, transient, retry.
      disabled_ = true;
      loaded_ = true;
      return false;
    }
    uint32_t watermark = 0;
    const OtaSequenceBackingResult readResult = backing_.readCounter(context_, watermark);
    if (readResult != OtaSequenceBackingResult::Committed) {
      if (!otaSequenceBackingResultIsPermanentFault(readResult)) return false;  // WouldBlock/Conflict: not loaded yet, transient, retry.
      disabled_ = true;
      loaded_ = true;
      return false;
    }
    if (watermark == 0) {
      // Same contract as the TX side: a genuinely-commissioned durable
      // watermark is NEVER 0 (commissioning marks sequence 1 as
      // already-seen so real traffic starts at 2). A "Committed" result
      // reporting 0 is self-contradictory -- an honestly never-
      // commissioned context must answer Missing, not a successful-
      // looking 0 -- so this can only be a corrupt/invalid backing.
      // Never treat it as "nothing admitted yet, safe to start fresh";
      // fail closed instead of silently authorizing first use the
      // backing never actually attested to.
      disabled_ = true;
      loaded_ = true;
      return false;
    }
    loaded_ = true;
    watermark_ = watermark;
    bitmap_ = 0;
    // Kept for the entire lifetime of this instance, even as the live
    // watermark advances: a lost in-RAM bitmap can never become trusted
    // again once reconstructed.
    rebootFloor_ = watermark;
    return true;
  }

  // Same contract as OtaRxReplayLedger::admit(): must be called (and
  // return true) BEFORE any dispatch/ACK side effect for `sequence`.
  bool admit(uint32_t sequence) {
    if (sequence == 0 || disabled_) return false;
    if (!load()) return false;
    if (sequence <= rebootFloor_) return false;

    if (sequence > watermark_) {
      OtaSequenceBackingResult advanceResult = backing_.advanceRx(context_, watermark_, sequence);
      if (advanceResult == OtaSequenceBackingResult::Conflict) {
        // Bounded, single refresh+retry: our cached watermark_ is stale
        // relative to the backing's actual current head (e.g. a prior
        // call's Uncertain result had actually landed, or a genuinely
        // shared store saw another writer advance it) -- never treated
        // as corruption/uncertainty by itself.
        uint32_t freshWatermark = 0;
        const OtaSequenceBackingResult refreshResult = backing_.readCounter(context_, freshWatermark);
        if (refreshResult != OtaSequenceBackingResult::Committed) {
          if (!otaSequenceBackingResultIsPermanentFault(refreshResult)) {
            return false;  // WouldBlock/Conflict: transient, state untouched, caller retries this same admit() later.
          }
          disabled_ = true;
          return false;
        }
        if (freshWatermark < watermark_) {
          // A "Committed" refresh reporting a LOWER head than what we
          // already know is durably closed would silently reopen
          // already-closed history -- never trust it; fail closed.
          disabled_ = true;
          return false;
        }
        if (freshWatermark != watermark_) {
          // The head genuinely moved by UNKNOWN/EXTERNAL means (not our
          // own tracked advanceRx() call landing) -- our bitmap's bit
          // positions were only ever aligned relative to the OLD
          // watermark, so we can no longer trust ANY of them across
          // this unexplained gap. Conservatively treat the WHOLE
          // now-visible window as already-closed (never invent
          // knowledge that any of those frames are still "unseen");
          // if the head is unchanged, preserve the known bitmap as-is.
          watermark_ = freshWatermark;
          bitmap_ = ~0ull;
        }
        if (sequence <= watermark_) {
          // The refreshed head already covers this sequence: re-run the
          // ordinary (non-advancing) admission path below against the
          // now-current watermark/bitmap.
          return admitWithinOrBelowWatermark(sequence);
        }
        advanceResult = backing_.advanceRx(context_, watermark_, sequence);
      }
      if (advanceResult == OtaSequenceBackingResult::WouldBlock ||
          advanceResult == OtaSequenceBackingResult::Conflict) {
        return false;  // transient: caller may retry this same admit() later.
      }
      if (advanceResult != OtaSequenceBackingResult::Committed) {
        disabled_ = true;  // Uncertain/Missing/Corrupt/OwnershipDenied/NoCapacity: fail closed.
        return false;
      }
      const uint32_t advanceBy = sequence - watermark_;
      bitmap_ = (advanceBy >= kWindowBits) ? 0ull : (bitmap_ << advanceBy);
      watermark_ = sequence;
      bitmap_ |= 1ull;  // bit 0 == watermark_ itself: catches a literal duplicate of this exact frame.
      return true;
    }
    return admitWithinOrBelowWatermark(sequence);
  }

  bool isDisabled() const { return disabled_; }

private:
  bool admitWithinOrBelowWatermark(uint32_t sequence) {
    if (sequence <= rebootFloor_) return false;
    const uint32_t age = watermark_ - sequence;
    if (age >= kWindowBits) return false;
    const uint64_t bit = 1ull << age;
    if ((bitmap_ & bit) != 0u) return false;
    bitmap_ |= bit;
    return true;
  }

  IRxSequenceBackingStore& backing_;
  OtaRxLedgerContext context_;
  bool loaded_ = false;
  bool disabled_ = false;
  uint32_t rebootFloor_ = 0;
  uint32_t watermark_ = 0;
  uint64_t bitmap_ = 0;
};

}  // namespace runtime
}  // namespace ota
}  // namespace meshcore
