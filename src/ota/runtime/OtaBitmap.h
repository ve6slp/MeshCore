#pragma once

// Fixed-capacity, no-heap chunk-received bitmap.

#include <cstdint>
#include <cstddef>
#include <array>
#include "OtaGeometry.h"

namespace meshcore {
namespace ota {
namespace runtime {

template <size_t MaxBits>
class OtaBitmap {
public:
  static constexpr size_t kWordBits = 32;
  static constexpr size_t kWordCount = (MaxBits + kWordBits - 1) / kWordBits;

  // Activates the first `activeBits` bits (clamped to MaxBits) and clears
  // all of them to "not received". Must be called before use so a stale
  // bitmap from a previous campaign/attempt can never be misread as
  // belonging to a new, differently-sized image.
  void reset(size_t activeBits) {
    activeBits_ = activeBits > MaxBits ? MaxBits : activeBits;
    words_.fill(0);
  }

  bool set(size_t index) {
    if (index >= activeBits_) return false;
    words_[index / kWordBits] |= (1u << (index % kWordBits));
    return true;
  }

  bool test(size_t index) const {
    if (index >= activeBits_) return false;
    return (words_[index / kWordBits] & (1u << (index % kWordBits))) != 0;
  }

  size_t countSet() const {
    size_t total = 0;
    for (size_t i = 0; i < kWordCount; ++i) {
      uint32_t w = words_[i];
      while (w) {
        total += (w & 1u);
        w >>= 1;
      }
    }
    return total;
  }

  bool allSet() const { return activeBits_ > 0 && countSet() == activeBits_; }

  bool firstMissing(size_t& outIndex) const {
    for (size_t i = 0; i < activeBits_; ++i) {
      if (!test(i)) {
        outIndex = i;
        return true;
      }
    }
    return false;
  }

  // Writes up to maxRanges contiguous [start, start+count) missing ranges
  // into caller-owned fixed arrays (no heap). Returns the number written.
  size_t missingRanges(uint32_t* outStart, uint32_t* outCount, size_t maxRanges) const {
    size_t written = 0;
    size_t i = 0;
    while (i < activeBits_ && written < maxRanges) {
      if (test(i)) {
        ++i;
        continue;
      }
      size_t start = i;
      while (i < activeBits_ && !test(i)) ++i;
      outStart[written] = static_cast<uint32_t>(start);
      outCount[written] = static_cast<uint32_t>(i - start);
      ++written;
    }
    return written;
  }

  size_t activeBits() const { return activeBits_; }

private:
  std::array<uint32_t, kWordCount> words_{};
  size_t activeBits_ = 0;
};

// Statically sized to represent the largest supported image
// (kOtaMaxImageBytes at kOtaDefaultChunkPayloadSize) with no heap use.
using OtaMaxImageBitmap = OtaBitmap<kOtaMaxChunkCount>;

} // namespace runtime
} // namespace ota
} // namespace meshcore
