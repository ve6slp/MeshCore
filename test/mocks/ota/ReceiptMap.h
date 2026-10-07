#pragma once

// Native journal model's fixed bit-per-chunk receipt map. Capacity matches its
// 1024-byte payload; unsupported geometries fail closed without heap use.

#include <stdint.h>
#include <array>
#include <cstring>

namespace ota {
namespace storage {

class ReceiptMap {
public:
  static constexpr uint32_t kMaxBytes = 1024;
  static constexpr uint32_t kMaxChunks = kMaxBytes * 8;
  ReceiptMap() : chunk_count_(0) {}

  explicit ReceiptMap(uint32_t chunk_count) : chunk_count_(0) { reset(chunk_count); }

  static uint32_t byteCountFor(uint32_t chunk_count) {
    return chunk_count / 8u + (chunk_count % 8u != 0);
  }

  bool reset(uint32_t chunk_count) {
    if (chunk_count > kMaxChunks) {
      chunk_count_ = 0;
      bytes_.fill(0);
      return false;
    }
    chunk_count_ = chunk_count;
    bytes_.fill(0);
    return true;
  }

  uint32_t chunkCount() const { return chunk_count_; }
  uint32_t byteCount() const { return byteCountFor(chunk_count_); }
  const uint8_t* data() const { return chunk_count_ == 0 ? nullptr : bytes_.data(); }

  bool markReceived(uint32_t chunk_index) {
    if (chunk_index >= chunk_count_) {
      return false;
    }
    bytes_[chunk_index / 8u] |= (uint8_t)(1u << (chunk_index % 8u));
    return true;
  }

  void clearReceived(uint32_t chunk_index) {
    if (chunk_index >= chunk_count_) {
      return;
    }
    bytes_[chunk_index / 8u] &= (uint8_t)~(1u << (chunk_index % 8u));
  }

  bool isReceived(uint32_t chunk_index) const {
    if (chunk_index >= chunk_count_) {
      return false;
    }
    return (bytes_[chunk_index / 8u] & (uint8_t)(1u << (chunk_index % 8u))) != 0u;
  }

  uint32_t countReceived() const {
    uint32_t total = 0;
    for (uint32_t i = 0; i < chunk_count_; ++i) {
      if (isReceived(i)) {
        ++total;
      }
    }
    return total;
  }

  bool allReceived() const {
    return chunk_count_ > 0 && countReceived() == chunk_count_;
  }

  // Loads the bitmap from a raw byte buffer (e.g. as read back from the
  // journal). `chunk_count` establishes the logical size; `buf_len` must be
  // at least byteCountFor(chunk_count).
  bool loadFrom(uint32_t chunk_count, const uint8_t* buf, uint32_t buf_len) {
    const uint32_t needed = byteCountFor(chunk_count);
    if (chunk_count > kMaxChunks || buf == nullptr || buf_len < needed) {
      return false;
    }
    chunk_count_ = chunk_count;
    bytes_.fill(0);
    std::memcpy(bytes_.data(), buf, needed);
    return true;
  }

private:
  uint32_t chunk_count_;
  std::array<uint8_t, kMaxBytes> bytes_{};
};

}  // namespace storage
}  // namespace ota
