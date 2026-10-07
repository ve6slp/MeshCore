#pragma once

// Bounds-checked, non-throwing byte cursors used by every OTA wire codec.
// Never allocate; every put/get returns false (leaving the buffer state
// unchanged) instead of overrunning the caller-owned buffer, so callers can
// safely feed untrusted/truncated/oversized wire data without heap use.

#include "OtaWireTypes.h"

namespace meshcore {
namespace ota {
namespace protocol {

class OtaBoundedWriter {
public:
  OtaBoundedWriter(uint8_t* buf, size_t capacity) : buf_(buf), capacity_(capacity), pos_(0) {}

  size_t size() const { return pos_; }
  size_t remaining() const { return capacity_ - pos_; }

  bool putU8(uint8_t v) {
    if (remaining() < 1) return false;
    buf_[pos_++] = v;
    return true;
  }

  bool putU16(uint16_t v) {
    if (remaining() < 2) return false;
    putOtaBE16(buf_ + pos_, v);
    pos_ += 2;
    return true;
  }

  bool putU32(uint32_t v) {
    if (remaining() < 4) return false;
    putOtaBE32(buf_ + pos_, v);
    pos_ += 4;
    return true;
  }

  bool putBytes(const uint8_t* src, size_t len) {
    if (len == 0) return true;
    if (remaining() < len) return false;
    for (size_t i = 0; i < len; ++i) buf_[pos_ + i] = src[i];
    pos_ += len;
    return true;
  }

private:
  uint8_t* buf_;
  size_t capacity_;
  size_t pos_;
};

class OtaBoundedReader {
public:
  OtaBoundedReader(const uint8_t* buf, size_t capacity) : buf_(buf), capacity_(capacity), pos_(0) {}

  size_t remaining() const { return capacity_ - pos_; }
  size_t position() const { return pos_; }

  bool getU8(uint8_t& out) {
    if (remaining() < 1) return false;
    out = buf_[pos_++];
    return true;
  }

  bool getU16(uint16_t& out) {
    if (remaining() < 2) return false;
    out = getOtaBE16(buf_ + pos_);
    pos_ += 2;
    return true;
  }

  bool getU32(uint32_t& out) {
    if (remaining() < 4) return false;
    out = getOtaBE32(buf_ + pos_);
    pos_ += 4;
    return true;
  }

  bool getBytes(uint8_t* dst, size_t len) {
    if (len == 0) return true;
    if (remaining() < len) return false;
    for (size_t i = 0; i < len; ++i) dst[i] = buf_[pos_ + i];
    pos_ += len;
    return true;
  }

  // Pointer to the unread tail, for zero-copy variable-length payloads.
  const uint8_t* cursor() const { return buf_ + pos_; }

  bool skip(size_t len) {
    if (remaining() < len) return false;
    pos_ += len;
    return true;
  }

private:
  const uint8_t* buf_;
  size_t capacity_;
  size_t pos_;
};

} // namespace protocol
} // namespace ota
} // namespace meshcore
