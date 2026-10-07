#pragma once

#include <stdint.h>

namespace mesh {

class TemporaryRadioLease {
 public:
  void reset() {
    apply_at_ = restore_at_ = retry_at_ = 0;
    apply_pending_ = restore_pending_ = retry_pending_ = false;
  }

  void schedule(uint32_t now, int timeout_minutes) {
    int64_t duration = timeout_minutes > 0 ? static_cast<int64_t>(timeout_minutes) * 60000 : 0;
    const int64_t maximum = INT32_MAX - 2000;
    if (duration > maximum) duration = maximum;
    apply_at_ = now + 2000u;
    restore_at_ = now + static_cast<uint32_t>(2000 + duration);
    apply_pending_ = restore_pending_ = true;
    retry_pending_ = false;
  }

  bool pending() const { return apply_pending_ || restore_pending_; }
  bool applied() const { return restore_pending_ && !apply_pending_; }
  bool restoreRetryPending() const { return retry_pending_; }

  void cancel(uint32_t now) {
    if (!pending()) return;
    apply_pending_ = false;
    if (!retry_pending_) restore_at_ = now - 1u;
  }

  template<typename Apply>
  bool applyIfDue(uint32_t now, Apply apply) {
    if (!apply_pending_ || !passed(now, apply_at_)) return false;
    apply();
    apply_pending_ = false;
    return true;
  }

  template<typename Restore>
  bool restoreIfDue(uint32_t now, Restore restore, bool radio_idle = true) {
    if (!restore_pending_) return false;
    // Retry a failed restore only when idle, without reconfiguring every loop.
    if (retry_pending_) {
      if (!radio_idle || !passed(now, retry_at_)) return false;
    } else if (!passed(now, restore_at_)) {
      return false;
    }
    apply_pending_ = false;
    if (restore()) {
      restore_pending_ = retry_pending_ = false;
      return true;
    }
    retry_pending_ = true;
    retry_at_ = now + 1000u;
    return false;
  }

  template<typename Restore>
  bool restoreUncheckedIfDue(uint32_t now, Restore restore) {
    return restoreIfDue(now, [&restore]() { restore(); return true; });
  }

 private:
  static bool passed(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) > 0;
  }
  uint32_t apply_at_ = 0, restore_at_ = 0, retry_at_ = 0;
  bool apply_pending_ = false, restore_pending_ = false, retry_pending_ = false;
};

}  // namespace mesh
