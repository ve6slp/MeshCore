#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cerrno>

// Keep SDK's generic Byte/UInt names out of Arduino sensor headers' scope.
namespace mesh { namespace ota { namespace lzma_sdk {
#include <helpers/ota/third_party/lzma/LzmaDec.h>
#include <helpers/ota/third_party/lzma/Bra.h>
}}}

namespace mesh { namespace ota {

// SDK26.04 persistent dictionary API. The caller's output is the history;
// probabilities and CLzmaDec are instance-owned, never allocated or on stack.
class OtaLzma {
public:
  static constexpr size_t kMaxOutput = 8192;
  static constexpr size_t kSliceBytes = 128;
  static constexpr size_t kProbabilityCount = 1984 + 768 * 2;
  static constexpr unsigned kMaxSlices = 2 * ((kMaxOutput + kSliceBytes - 1) / kSliceBytes) + 4;
  enum class Result { Ok, Pending, Bounds, Truncated, Invalid, OutputLength, Trailing, WorkLimit };

  Result begin(const uint8_t* input, size_t size, uint8_t* output, size_t expected) {
    if (!input || !output || !size || size > kMaxOutput || !expected || expected > kMaxOutput)
      return result_ = Result::Bounds;
    input_ = input; size_ = size; expected_ = expected; consumed_ = slices_ = 0;
    state_ = lzma_sdk::CLzmaDec{};
    state_.prop.lc = 0; state_.prop.lp = 1; state_.prop.pb = 1; state_.prop.dicSize = 8192;
    state_.probs = probabilities_; state_.probs_1664 = probabilities_ + 1664;
    state_.numProbs = kProbabilityCount;
    state_.dic = output; state_.dicBufSize = expected;
    lzma_sdk::LzmaDec_Init(&state_);
    return result_ = Result::Pending;
  }

  __attribute__((noinline)) Result step() {
    if (!input_) return result_ = Result::Bounds;
    if (result_ != Result::Pending) return result_;
    if (++slices_ > kMaxSlices) return result_ = Result::WorkLimit;
    const size_t before = state_.dicPos;
    const size_t limit = expected_ - before > kSliceBytes ? before + kSliceBytes : expected_;
    lzma_sdk::SizeT available = size_ - consumed_ > kSliceBytes ? kSliceBytes : size_ - consumed_;
    lzma_sdk::ELzmaStatus status = lzma_sdk::LZMA_STATUS_NOT_SPECIFIED;
    const auto result = lzma_sdk::LzmaDec_DecodeToDic(&state_, limit, input_ + consumed_, &available,
        limit == expected_ ? lzma_sdk::LZMA_FINISH_END : lzma_sdk::LZMA_FINISH_ANY, &status);
    consumed_ += available;
    if (result != SZ_OK) return result_ = Result::Invalid;
    if (state_.dicPos > expected_) return result_ = Result::OutputLength;
    if (status == lzma_sdk::LZMA_STATUS_FINISHED_WITH_MARK) {
      if (state_.dicPos != expected_) return result_ = Result::OutputLength;
      return result_ = consumed_ == size_ ? Result::Ok : Result::Trailing;
    }
    if (!available && state_.dicPos == before)
      return result_ = consumed_ == size_ ? Result::Truncated : Result::Invalid;
    if (consumed_ == size_ && status == lzma_sdk::LZMA_STATUS_NEEDS_MORE_INPUT)
      return result_ = Result::Truncated;
    return result_;
  }

  unsigned slices() const { return slices_; }
  size_t produced() const { return state_.dicPos; }
  size_t consumed() const { return consumed_; }

private:
  lzma_sdk::CLzmaProb probabilities_[kProbabilityCount] = {};
  lzma_sdk::CLzmaDec state_{};
  const uint8_t* input_ = nullptr;
  size_t size_ = 0, expected_ = 0, consumed_ = 0;
  unsigned slices_ = 0;
  Result result_ = Result::Ok;
};

static_assert(sizeof(lzma_sdk::CLzmaProb) == 2, "Only the fixed 7040-byte LZMA probability profile is supported");

}}
