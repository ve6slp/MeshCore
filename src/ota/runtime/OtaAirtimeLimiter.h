#pragma once

// OTA rolling/sliding-window airtime limiter.
//
// - Uses a fixed-capacity (no heap) ring buffer of individual usage entries;
//   each entry ages out of the window on its own as time advances, so the
//   allowance *expires* rather than being an ever-growing/never-reset
//   campaign bucket.
// - admits stored (still-valid) usage plus the prospective full duration of
//   a new transmission before allowing it, never counting a transmission
//   until it has actually happened (two-step canAdmit()/recordUsage()).
// - tracks Control/Repair/Relay categories.
// - clock arithmetic is wrap-safe: all elapsed-time comparisons use unsigned
//   subtraction, which is correct modulo 2^32 as long as elapsed time
//   itself never exceeds ~24 days (window sizes here are on the order of an
//   hour, far below that bound).
// - regulatory admissibility and mesh normal-traffic precedence are both
//   supplied as explicit inputs to canAdmit(), not baked into internal
//   state, so this module stays agnostic to *why* either gate fired.

#include <cstdint>
#include <cstddef>
#include <array>
#include "../protocol/OtaWireTypes.h"

namespace meshcore {
namespace ota {
namespace runtime {

struct OtaAirtimeDecisionInput {
  // Independent regulatory-compliance verdict (e.g. duty-cycle/LBT rules
  // for the operating region). false unconditionally denies admission
  // regardless of remaining budget.
  bool regulatoryAllowed = true;
  // True while real (non-OTA) mesh traffic should take precedence. When
  // true, only Control-category OTA traffic (small lease/negotiation
  // frames) may still be admitted; Repair/Relay traffic yields entirely.
  bool normalTrafficActive = false;
};

class OtaAirtimeLimiter {
public:
  static constexpr size_t kMaxEntries = 256;
  static constexpr uint32_t kDefaultWindowMs = 3600000;  // 1 hour
  static constexpr uint32_t kDefaultBudgetMs = 72000;    // 2% of 1 hour

  explicit OtaAirtimeLimiter(uint32_t windowMs = kDefaultWindowMs, uint32_t budgetMs = kDefaultBudgetMs)
      : windowMs_(windowMs), budgetMs_(budgetMs) {}

  uint32_t windowMs() const { return windowMs_; }
  uint32_t budgetMs() const { return budgetMs_; }

  void retune(uint32_t windowMs, uint32_t budgetMs) {
    windowMs_ = windowMs;
    budgetMs_ = budgetMs;
  }

  // Sum of still-valid (non-expired as of nowMs) recorded usage, across all
  // categories.
  uint32_t storedUsageMs(uint32_t nowMs) const { return storedUsageMsFiltered(nowMs, false, protocol::OtaAirtimeCategory::Control); }

  // Sum of still-valid recorded usage restricted to one category.
  uint32_t storedUsageMs(uint32_t nowMs, protocol::OtaAirtimeCategory category) const {
    return storedUsageMsFiltered(nowMs, true, category);
  }

  // True iff admitting `prospectiveDurationMs` more of `category` traffic
  // right now would keep (still-valid stored usage + prospective) within
  // budget, AND the regulatory input allows it, AND normal mesh traffic
  // precedence (if asserted) does not block this category.
  bool canAdmit(uint32_t nowMs, protocol::OtaAirtimeCategory /*category*/, uint32_t prospectiveDurationMs,
                const OtaAirtimeDecisionInput& decision) const {
    if (!decision.regulatoryAllowed) return false;
    // Ready normal (non-OTA) mesh traffic takes absolute precedence over
    // ALL OTA airtime categories, Control included. An earlier version
    // exempted Control here so that OTA session-control frames (auth,
    // receipts, lease negotiation, census, etc.) could preempt ready
    // normal traffic; that violates the "normal traffic is never starved
    // by OTA" guarantee this limiter exists to enforce.
    if (decision.normalTrafficActive) return false;
    if (!hasAccountingCapacity(nowMs)) return false;

    const uint32_t used = storedUsageMs(nowMs);
    const uint64_t prospective = static_cast<uint64_t>(used) + static_cast<uint64_t>(prospectiveDurationMs);
    return prospective <= static_cast<uint64_t>(budgetMs_);
  }

  // Records actual usage after a transmission has happened. Callers should
  // only invoke this after a prior canAdmit() returned true for a duration
  // covering `durationMs`. Fails closed (returns false, no state mutated)
  // if the fixed-capacity ring is full of still-valid entries and none can
  // be reclaimed -- this deliberately under-admits rather than
  // silently losing accounted usage.
  bool recordUsage(uint32_t nowMs, protocol::OtaAirtimeCategory category, uint32_t durationMs) {
    if (count_ < kMaxEntries) {
      size_t idx = (head_ + count_) % kMaxEntries;
      entries_[idx] = Entry{nowMs, durationMs, category, true};
      ++count_;
      return true;
    }
    // Ring is full: only reclaim the oldest slot if it has actually expired.
    Entry& oldest = entries_[head_];
    if (!oldest.valid || isExpired(oldest, nowMs)) {
      oldest = Entry{nowMs, durationMs, category, true};
      head_ = (head_ + 1) % kMaxEntries;
      return true;
    }
    return false;
  }

private:
  struct Entry {
    uint32_t timestampMs = 0;
    uint32_t durationMs = 0;
    protocol::OtaAirtimeCategory category = protocol::OtaAirtimeCategory::Control;
    bool valid = false;
  };

  bool isExpired(const Entry& e, uint32_t nowMs) const {
    // Wrap-safe: relies on unsigned modulo-2^32 subtraction.
    const uint32_t elapsed = nowMs - e.timestampMs;
    return elapsed > windowMs_;
  }

  bool hasAccountingCapacity(uint32_t nowMs) const {
    if (count_ < kMaxEntries) return true;
    const Entry& oldest = entries_[head_];
    return !oldest.valid || isExpired(oldest, nowMs);
  }

  uint32_t storedUsageMsFiltered(uint32_t nowMs, bool filterByCategory, protocol::OtaAirtimeCategory category) const {
    uint32_t total = 0;
    for (size_t i = 0; i < count_; ++i) {
      const Entry& e = entries_[(head_ + i) % kMaxEntries];
      if (!e.valid) continue;
      if (isExpired(e, nowMs)) continue;
      if (filterByCategory && e.category != category) continue;
      total += e.durationMs;
    }
    return total;
  }

  std::array<Entry, kMaxEntries> entries_{};
  size_t head_ = 0;
  size_t count_ = 0;
  uint32_t windowMs_;
  uint32_t budgetMs_;
};

} // namespace runtime
} // namespace ota
} // namespace meshcore
