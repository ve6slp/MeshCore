#pragma once

// Shared, RAM-only physical-partition arbitration for OtaSecurityStore.
//
// A "physical partition" here means the pair of NOR tails (bank A + bank
// B) backing ONE logical store's physical media. When more than one
// OtaSecurityStore WRAPPER OBJECT addresses the SAME physical media (e.g.
// one board-owned root cooperative engine constructing separate TX-side
// and RX-side Store wrappers over the same QSPI device/offsets, or a
// native test exercising two independently-opened Store instances), every
// such wrapper MUST arbitrate through the SAME
// OtaSecurityPhysicalPartitionArbiter instance -- there is NO safe
// "unshared/private" mode. Root correction: this is enforced by
// OtaSecurityPartitionArbiterRegistry itself, keyed by the STABLE
// PHYSICAL media identity (FlashDevice address + bank offsets), NOT by
// which wrapper object happens to ask -- so even a Store constructed
// WITHOUT an explicit external arbiter never gets a private, unshared
// one; it automatically joins the single registry-owned arbiter for its
// physical identity (created on first use), genuinely racing-safe
// against every other Store (default OR explicit) over the SAME media.
// Passing an explicit external arbiter remains supported (and is still
// how a production caller injects a specific shared instance across
// multiple wrappers it constructs); the registry unifies both paths onto
// exactly one arbiter per physical identity and refuses (misconfigures)
// a Store that explicitly injects a DIFFERENT arbiter than one already
// bound and still referenced for that identity.
//
// Ownership tickets (OwnerToken, an opaque caller-supplied stable
// identity -- in practice `this` of the acquiring OtaSecurityStore) are
// RAM-only and NEVER persisted to flash. A ticket, once acquired, is held
// across however many bounded WouldBlock-returning service steps the
// caller's logical operation needs (e.g. every phase of one compaction)
// until that operation completes, is explicitly cancelled, or the owning
// Store object is destroyed -- NOT until any timer/expiry (none exists;
// ownership is a plain compare-and-hold, not a lease with a wall-clock
// timeout). Destruction/cancellation releases ONLY the RAM ticket; it
// NEVER undoes an already-durable reservation/seal/publication -- the
// next owner refreshes the real physical medium under its own fresh
// ticket and must resume/reconcile any durably-sealed-but-unactivated
// compaction before any ordinary append, per
// OtaSecurityStore::reconstruct()'s pending-seal detection. Because the
// arbiter itself is pure RAM, a fresh process restart naturally starts
// with a brand-new, unowned registry entry once every prior Store for
// that identity has been destroyed: durable recovery correctness rests
// entirely on the flash-resident seal/witness/generation facts
// reconstruct() re-derives under this fresh ownership, never on any RAM
// ticket surviving the restart.
//
// This is a SEPARATE concern from any physical flash-bus mutual-exclusion
// lock: the arbiter governs WHICH LOGICAL OPERATION currently owns the
// partition (so a sibling wrapper's CAS/refresh/compaction never races
// this one's), while the underlying flash bus itself is naturally
// released back to other bus users between every bounded step simply
// because each Store method call performs ONE bounded unit of work and
// returns control to the caller -- no bus lock is held across calls. A
// genuinely synchronous physical program/erase/read call must actually
// finish before that release happens (no speculative early release while
// a transfer may still be touching a scratch/DMA buffer); this module is
// pure RAM/ownership bookkeeping and holds no opinion on any given
// IFlashIO call's own internal completion semantics, which remain that
// driver's responsibility.

#include <cstddef>
#include <cstdint>
#include <map>

namespace ota {
namespace security {

// Root correction: a FlashDevice& object's OWN address is only an OBJECT
// identity, not a physical-hardware identity -- it is safe to use as a
// physical key ONLY when every alias for one physical chip is guaranteed
// to be literally the same C++ object. Two distinct backend FlashDevice
// WRAPPER OBJECTS (e.g. separately constructed by TX-side and RX-side
// code, or by two different driver instances) that both address the SAME
// physical NOR chip are DIFFERENT objects with different addresses, so
// address-based keying would silently fail to unify them and let two
// Stores race on one real chip. The only safe fix is an EXPLICIT, board-
// supplied `PhysicalPartitionToken` that the caller guarantees is the
// SAME numeric value for every wrapper addressing one physical chip
// (e.g. a QSPI chip-select/bus-id constant baked into the board's
// platform layer), NEVER inferred from any object's address.
//
// `PhysicalPartitionKey` is the FULL, EXACT (token, bankAOffset,
// bankBOffset) tuple -- compared field-by-field via `operator<`, not
// collapsed through any hash/XOR (a XOR- or multiply-combined single
// integer can theoretically collide across different tuples; an exact
// tuple comparison cannot).
using PhysicalPartitionToken = uint64_t;

struct PhysicalPartitionKey {
  PhysicalPartitionToken token = 0;
  uint32_t bankAOffset = 0;
  uint32_t bankBOffset = 0;

  bool operator<(const PhysicalPartitionKey& other) const {
    if (token != other.token) return token < other.token;
    if (bankAOffset != other.bankAOffset) return bankAOffset < other.bankAOffset;
    return bankBOffset < other.bankBOffset;
  }
};

class OtaSecurityPhysicalPartitionArbiter {
public:
  using OwnerToken = const void*;

  // Grants (or re-enters, if `owner` already holds it) exclusive
  // ownership of this physical partition. Returns false if a DIFFERENT
  // owner currently holds it -- the caller must treat this as
  // WouldBlock, never proceed to refresh/CAS/seal with its own
  // possibly-divergent RAM facts.
  bool acquire(OwnerToken owner) {
    if (owner_ == nullptr || owner_ == owner) {
      owner_ = owner;
      return true;
    }
    return false;
  }

  // Releases ownership -- a no-op if `owner` does not currently hold it
  // (so a destructor/cancel path can call this unconditionally and
  // safely).
  void release(OwnerToken owner) {
    if (owner_ == owner) owner_ = nullptr;
  }

  bool isFree() const { return owner_ == nullptr; }
  bool isOwnedBy(OwnerToken owner) const { return owner_ == owner; }

private:
  OwnerToken owner_ = nullptr;
};

// Enforces "distinct Store wrappers over the SAME physical media MUST
// use one shared arbiter" -- for BOTH usage modes. There is NO silent
// "private, unshared" bypass: a Store constructed WITHOUT an explicit
// external arbiter does not get a private one of its own -- it instead
// automatically joins the SINGLE, registry-owned, implicit arbiter for
// its physical identity (creating it on first use). This means two
// "default" Store wrappers over the SAME physical media (same physical
// identity -- device + bank offsets, NOT the wrapper object's own
// address) genuinely share real ownership arbitration, closing the gap
// where "optional/default" could otherwise be mistaken for "exempt from
// arbitration". An explicit external arbiter (when the caller DOES
// inject one) still works exactly as before and still wins outright:
// once bound for a physical identity, every subsequent Store for that
// SAME identity (explicit-matching or default) joins that SAME object;
// a DIFFERENT explicit arbiter for an already-bound identity is refused
// outright (misconfiguration), never silently accepted as "different
// media" or silently downgraded to a private unshared one.
//
// Ref-counted per physical-identity tag so a later, genuinely fresh
// Store (e.g. simulating a cold process restart, constructed only AFTER
// every earlier Store instance for that same physical identity has been
// destroyed) may legitimately (re)bind -- implicit or explicit -- for
// the same media once the refcount reaches zero.
class OtaSecurityPartitionArbiterRegistry {
public:
  // Returns the arbiter this physical identity must use, or nullptr on
  // refusal (an explicit `externalArbiter` that conflicts with a
  // DIFFERENT arbiter -- implicit or explicit -- already registered and
  // still referenced for this identity). Pass `externalArbiter == nullptr`
  // for the "default" path: it always joins whatever is already
  // registered for this identity (implicit or explicit), or creates and
  // registers the shared implicit arbiter on first use. Never refused.
  static OtaSecurityPhysicalPartitionArbiter* acquire(const PhysicalPartitionKey& physicalIdentity,
                                                      OtaSecurityPhysicalPartitionArbiter* externalArbiter) {
    Entries& entries = registry();
    auto it = entries.find(physicalIdentity);
    if (it == entries.end()) {
      it = entries.emplace(physicalIdentity, Entry{}).first;
      if (externalArbiter != nullptr) {
        it->second.arbiter = externalArbiter;
        it->second.implicit = false;
      } else {
        it->second.arbiter = &it->second.storage;  // registry-owned; address stable while refCount > 0.
        it->second.implicit = true;
      }
    } else if (externalArbiter != nullptr && it->second.arbiter != externalArbiter) {
      return nullptr;  // explicit refusal: foreign arbiter, same media, still referenced.
    }
    ++it->second.refCount;
    return it->second.arbiter;
  }

  static void release(const PhysicalPartitionKey& physicalIdentity, OtaSecurityPhysicalPartitionArbiter* arbiter) {
    Entries& entries = registry();
    auto it = entries.find(physicalIdentity);
    if (it == entries.end() || it->second.arbiter != arbiter) return;
    if (--it->second.refCount == 0) entries.erase(it);
  }

private:
  struct Entry {
    OtaSecurityPhysicalPartitionArbiter storage;  // used only when implicit == true.
    OtaSecurityPhysicalPartitionArbiter* arbiter = nullptr;
    bool implicit = true;
    int refCount = 0;
  };
  using Entries = std::map<PhysicalPartitionKey, Entry>;
  static Entries& registry() {
    static Entries entries;
    return entries;
  }
};

}  // namespace security
}  // namespace ota
