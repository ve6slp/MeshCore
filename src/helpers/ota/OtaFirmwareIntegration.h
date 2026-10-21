#pragma once

#include <cmath>
#include <helpers/ota/OtaV4Receiver.h>

namespace mesh { namespace ota {

class AirtimeBudget {
public:
  static constexpr uint32_t kDefaultWindowMs = 3600000, kDefaultBudgetMs = 72000;
  explicit AirtimeBudget(uint32_t window = kDefaultWindowMs, uint32_t budget = kDefaultBudgetMs)
      : window_(window), budget_(budget) {}
  uint32_t windowMs() const { return window_; }
  uint32_t budgetMs() const { return budget_; }
  void retune(uint32_t window, uint32_t budget) { window_ = window; budget_ = budget; }
  uint32_t storedUsageMs(uint32_t now) const {
    uint64_t used = 0;
    for (size_t i = 0; i < count_; ++i)
      if (!expired(entries_[i], now)) used += entries_[i].duration;
    return used > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(used);
  }
  bool canAdmit(uint32_t now, uint32_t duration, bool regulatory, bool normal_traffic) const {
    if (!regulatory || normal_traffic ||
        static_cast<uint64_t>(storedUsageMs(now)) + duration > budget_) return false;
    return count_ < kCapacity || reusable(now) != kCapacity || coalescing(now, duration, duration) != kCapacity;
  }
  bool recordUsage(uint32_t now, uint32_t duration) {
    size_t index = coalescing(now, duration, 0);
    if (index != kCapacity) {
      entries_[index].last = now;
      entries_[index].duration += duration;
      return true;
    }
    index = count_ < kCapacity ? count_++ : reusable(now);
    if (index == kCapacity) return false;
    entries_[index] = {now, now, duration};
    return true;
  }

private:
  // Coalesce completions into bounded 15-second buckets. A bucket expires
  // after its last completion, conservatively retaining every charged send.
  struct Entry { uint32_t first = 0, last = 0, duration = 0; };
  static constexpr size_t kCapacity = 256;
  bool expired(const Entry& entry, uint32_t now) const { return now - entry.last > window_; }
  size_t reusable(uint32_t now) const {
    for (size_t i = 0; i < count_; ++i) if (expired(entries_[i], now)) return i;
    return kCapacity;
  }
  size_t coalescing(uint32_t now, uint32_t duration, uint32_t completion_delay) const {
    for (size_t i = count_; i > 0; --i) {
      const auto& entry = entries_[i - 1];
      if (!expired(entry, now) && static_cast<uint64_t>(static_cast<uint32_t>(now - entry.first)) +
          completion_delay <= 15000 && static_cast<uint64_t>(entry.duration) + duration <= UINT32_MAX)
        return i - 1;
    }
    return kCapacity;
  }
  Entry entries_[kCapacity]{};
  size_t count_ = 0;
  uint32_t window_, budget_;
};

// This adapter borrows the board's single receiver. It never owns image,
// manifest, cache, uploader or competing transaction state.
class OtaFirmwareIntegration {
public:
  using Result = v4::Result;
  using ProfileFn = bool (*)(void*, uint32_t, uint32_t, uint8_t, uint8_t, bool);
  static constexpr uint32_t kCommitRebootGraceMs = 2000;
  static constexpr uint32_t kCommitRebootQueueWaitMs = 15000;

  Result attach(v4::Receiver* receiver) {
    receiver_ = receiver;
    return receiver_ ? receiver_->begin() : Result::Unsupported;
  }
  v4::Receiver* receiver() const { return receiver_; }
  Result onFrame(const uint8_t* bytes, size_t size, bool local = false, uint32_t now = 0,
                 const uint8_t* flood_path = nullptr, uint8_t flood_path_len = 0) {
    if (!receiver_) return Result::Unsupported;
    v4::Frame frame;
    if (!v4::decodeFrame(bytes, size, frame)) return Result::Invalid;
    size_t pending = 0;
    if (receiver_->peek(pending)) return Result::Busy;
    const bool query = frame.kind == v4::Kind::Query || frame.kind == v4::Kind::ProgressQuery;
    const uint8_t* reply_path = nullptr;
    uint8_t reply_path_len = 0;
    if (query) {
      if (!v4::decodeQueryReplyPath(frame, reply_path, reply_path_len)) return Result::Invalid;
      const size_t width = (flood_path_len >> 6) + 1;
      if (flood_path && (width > 3 || (flood_path_len & 63) * width > v4::kMaxReplyPathBytes))
        return Result::Invalid;
    }
    if (frame.kind == v4::Kind::Query) {
      if (queried_ && static_cast<uint32_t>(now - last_query_) < 250) return Result::Busy;
      last_query_ = now;
      queried_ = true;
    }
    local_reply_ = local;
    const Result result = receiver_->onFrame(bytes, size);
    if (result == Result::Ok && query && receiver_->peek(pending)) {
      reply_path_len_ = reply_path_len;
      if (reply_path) {
        std::memcpy(reply_path_, reply_path, (reply_path_len & 63) * ((reply_path_len >> 6) + 1));
      } else if (flood_path) {
        reply_path_len_ = flood_path_len;
        const size_t width = (flood_path_len >> 6) + 1, count = flood_path_len & 63;
        for (size_t i = 0; i < count; ++i)
          std::memcpy(reply_path_ + i * width, flood_path + (count - i - 1) * width, width);
      }
    }
    if (result == Result::Ok && lease_active_ &&
        ((frame.kind == v4::Kind::Abort && phase() == v4::Phase::Aborted) ||
         (frame.kind == v4::Kind::Repair && phase() == v4::Phase::Idle))) {
      lease_expiry_ = now;
      restore_retry_ = false;
    }
    return result;
  }
  void tick(uint32_t now, bool radio_idle) {
    if (lease_active_ && static_cast<int32_t>(now - lease_expiry_) >= 0 && radio_idle &&
        (!restore_retry_ || static_cast<int32_t>(now - restore_after_) >= 0)) {
      if (!stopLease()) {
        restore_retry_ = true;
        restore_after_ = now + 1000;
      }
    }
    if (receiver_) receiver_->tick();
  }
  const uint8_t* peek(size_t& size) const {
    size = 0;
    return receiver_ ? receiver_->peek(size) : nullptr;
  }
  void release() { if (receiver_) receiver_->release(); }
  bool localReply() const { return local_reply_; }
  const uint8_t* replyPath() const { return reply_path_; }
  uint8_t replyPathLen() const { return reply_path_len_; }
  bool hasPendingRfWork() const {
    size_t size = 0;
    return !local_reply_ && peek(size) != nullptr;
  }
  v4::Phase phase() const {
    return receiver_ ? receiver_->journal().phase : v4::Phase::Idle;
  }
  bool busy() const {
    const auto p = phase();
    return lease_active_ || hasPendingRfWork() || p == v4::Phase::Receiving ||
        p == v4::Phase::Verifying || p == v4::Phase::Ready ||
        p == v4::Phase::ActivationPending || p == v4::Phase::Trial;
  }
  void attachProfile(void* context, ProfileFn fn) { context_ = context; profile_ = fn; }
  Result lease(uint32_t now, bool idle, uint32_t frequency, uint32_t bandwidth,
               uint8_t sf, uint8_t cr, uint32_t duration) {
    if (!idle) return Result::Busy;
    if (!profile_) return Result::Unsupported;
    if (!duration) return stopLease() ? Result::Ok : Result::Io;
    if (duration > 60000 || frequency < 150000 || frequency > 2500000 ||
        bandwidth < 7800 || bandwidth > 500000 || sf < 5 || sf > 12 || cr < 5 || cr > 8)
      return Result::Invalid;
    lease_active_ = true;
    restore_retry_ = false;
    lease_expiry_ = now;
    // Checked radio configuration can fail after changing only some registers.
    // Retain restoration ownership even when applying the override fails.
    if (!profile_(context_, frequency, bandwidth, sf, cr, false)) return Result::Io;
    lease_expiry_ = now + duration;
    return Result::Ok;
  }
  bool stopLease() {
    if (!lease_active_) return true;
    if (!profile_ || !profile_(context_, 0, 0, 0, 0, true)) return false;
    lease_active_ = false;
    restore_retry_ = false;
    return true;
  }
  void requestLeaseStop(uint32_t now) {
    if (lease_active_) {
      lease_expiry_ = now;
      restore_retry_ = false;
    }
  }
  bool leaseActive() const { return lease_active_; }

  bool setDutyCyclePercent(float percent) {
    if (!std::isfinite(percent) || percent < 0 || percent > 100) return false;
    duty_percent_ = percent;
    airtime_.retune(airtime_.windowMs(),
        static_cast<uint32_t>(static_cast<double>(airtime_.windowMs()) * percent / 100.0));
    return true;
  }
  float dutyCyclePercent() const { return duty_percent_; }
  uint32_t dutyBudgetMs() const { return airtime_.budgetMs(); }
  const AirtimeBudget& airtimeLimiter() const { return airtime_; }
  bool canTransmit(uint32_t now, uint32_t duration, bool regulatory_allowed, bool normal_traffic) const {
    return !accounting_fault_ && airtime_.canAdmit(now, duration, regulatory_allowed, normal_traffic);
  }
  bool recordTransmit(uint32_t now, uint32_t duration) {
    if (!airtime_.recordUsage(now, duration)) accounting_fault_ = true;
    return !accounting_fault_;
  }

private:
  v4::Receiver* receiver_ = nullptr;
  AirtimeBudget airtime_;
  void* context_ = nullptr;
  ProfileFn profile_ = nullptr;
  uint32_t lease_expiry_ = 0, last_query_ = 0, restore_after_ = 0;
  uint8_t reply_path_[v4::kMaxReplyPathBytes]{}, reply_path_len_ = 0;
  float duty_percent_ = 2;
  bool lease_active_ = false, local_reply_ = false, accounting_fault_ = false, queried_ = false;
  bool restore_retry_ = false;
};

}}
