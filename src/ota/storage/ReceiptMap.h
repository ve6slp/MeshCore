#pragma once

// Dynamic bit-per-chunk receipt map, tracking which OTA chunks have been
// durably received/verified for the current campaign. Sized at runtime from
// the manifest's chunk_count, so it is not artificially capped the way a
// fixed 256-byte bitmap would be (this module is required to support at
// least 5069 chunks; a 792 KiB candidate image with e.g. 160-byte chunks
// needs ~5069 chunks, and this map supports arbitrarily more, bounded only
// by available RAM/journal slot capacity).

#include <stdint.h>
#include <vector>
#include <algorithm>

namespace ota {
namespace storage {

class ReceiptMap {
public:
  ReceiptMap() : chunk_count_(0) {}

  explicit ReceiptMap(uint32_t chunk_count) : chunk_count_(chunk_count) {
    bytes_.assign(byteCountFor(chunk_count), 0u);
  }

  static uint32_t byteCountFor(uint32_t chunk_count) {
    return (chunk_count + 7u) / 8u;
  }

  void reset(uint32_t chunk_count) {
    chunk_count_ = chunk_count;
    bytes_.assign(byteCountFor(chunk_count), 0u);
  }

  uint32_t chunkCount() const { return chunk_count_; }
  uint32_t byteCount() const { return (uint32_t)bytes_.size(); }
  const uint8_t* data() const { return bytes_.empty() ? nullptr : bytes_.data(); }

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
    if (buf == nullptr || buf_len < needed) {
      return false;
    }
    chunk_count_ = chunk_count;
    bytes_.assign(buf, buf + needed);
    return true;
  }

private:
  uint32_t chunk_count_;
  std::vector<uint8_t> bytes_;
};

}  // namespace storage
}  // namespace ota
