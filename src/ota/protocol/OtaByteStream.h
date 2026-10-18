#pragma once

// Bounds-checked byte cursors for the canonical boot-safety descriptor.
// Never allocate; every put/get returns false (leaving the buffer state
// unchanged) instead of overrunning the caller-owned buffer, so callers can
// safely feed untrusted/truncated/oversized wire data without heap use.

#include <cstddef>
#include <cstdint>

namespace meshcore {
namespace ota {
namespace protocol {

inline void putOtaBE16(uint8_t* dst, uint16_t v) {
  dst[0] = static_cast<uint8_t>(v >> 8);
  dst[1] = static_cast<uint8_t>(v);
}

inline uint16_t getOtaBE16(const uint8_t* src) {
  return static_cast<uint16_t>((static_cast<uint16_t>(src[0]) << 8) | src[1]);
}

inline void putOtaBE32(uint8_t* dst, uint32_t v) {
  dst[0] = static_cast<uint8_t>(v >> 24);
  dst[1] = static_cast<uint8_t>(v >> 16);
  dst[2] = static_cast<uint8_t>(v >> 8);
  dst[3] = static_cast<uint8_t>(v);
}

inline uint32_t getOtaBE32(const uint8_t* src) {
  return (static_cast<uint32_t>(src[0]) << 24) |
         (static_cast<uint32_t>(src[1]) << 16) |
         (static_cast<uint32_t>(src[2]) << 8) | src[3];
}

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

private:
  const uint8_t* buf_;
  size_t capacity_;
  size_t pos_;
};

} // namespace protocol
} // namespace ota
} // namespace meshcore
