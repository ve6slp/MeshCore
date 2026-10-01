#pragma once

// Small, explicit, bounds-checked little-endian byte codec used across the
// security store's fixed on-flash record layouts (data cells, witness
// records/headers, snapshot tables). Deliberately NOT a packed struct
// reinterpret_cast: every field is read/written at an explicit byte offset
// so the on-flash layout is independent of compiler struct-packing/
// endianness/alignment behavior, and so a short/truncated buffer is
// detected (returns false) rather than read out of bounds.

#include <stdint.h>
#include <stddef.h>

namespace ota {
namespace security {

// Returns false (and writes nothing) if `offset + 1/2/4/8` would exceed
// `bufLen` -- callers must check the return value.
inline bool putU8(uint8_t* buf, size_t bufLen, size_t offset, uint8_t v) {
  if (offset + 1 > bufLen) return false;
  buf[offset] = v;
  return true;
}

inline bool getU8(const uint8_t* buf, size_t bufLen, size_t offset, uint8_t& out) {
  if (offset + 1 > bufLen) return false;
  out = buf[offset];
  return true;
}

inline bool putU16(uint8_t* buf, size_t bufLen, size_t offset, uint16_t v) {
  if (offset + 2 > bufLen) return false;
  buf[offset + 0] = (uint8_t)(v & 0xFFu);
  buf[offset + 1] = (uint8_t)((v >> 8) & 0xFFu);
  return true;
}

inline bool getU16(const uint8_t* buf, size_t bufLen, size_t offset, uint16_t& out) {
  if (offset + 2 > bufLen) return false;
  out = (uint16_t)((uint16_t)buf[offset + 0] | ((uint16_t)buf[offset + 1] << 8));
  return true;
}

inline bool putU32(uint8_t* buf, size_t bufLen, size_t offset, uint32_t v) {
  if (offset + 4 > bufLen) return false;
  buf[offset + 0] = (uint8_t)(v & 0xFFu);
  buf[offset + 1] = (uint8_t)((v >> 8) & 0xFFu);
  buf[offset + 2] = (uint8_t)((v >> 16) & 0xFFu);
  buf[offset + 3] = (uint8_t)((v >> 24) & 0xFFu);
  return true;
}

inline bool getU32(const uint8_t* buf, size_t bufLen, size_t offset, uint32_t& out) {
  if (offset + 4 > bufLen) return false;
  out = (uint32_t)buf[offset + 0] | ((uint32_t)buf[offset + 1] << 8) | ((uint32_t)buf[offset + 2] << 16) |
        ((uint32_t)buf[offset + 3] << 24);
  return true;
}

inline bool putU64(uint8_t* buf, size_t bufLen, size_t offset, uint64_t v) {
  if (offset + 8 > bufLen) return false;
  for (int i = 0; i < 8; ++i) {
    buf[offset + i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
  }
  return true;
}

inline bool getU64(const uint8_t* buf, size_t bufLen, size_t offset, uint64_t& out) {
  if (offset + 8 > bufLen) return false;
  out = 0;
  for (int i = 0; i < 8; ++i) {
    out |= ((uint64_t)buf[offset + i]) << (8 * i);
  }
  return true;
}

// Bytewise copy in/out with an explicit bounds check (used for fixed-size
// opaque fields: peer public keys, group contexts, digests, ...).
inline bool putBytes(uint8_t* buf, size_t bufLen, size_t offset, const uint8_t* src, size_t n) {
  if (offset + n > bufLen) return false;
  for (size_t i = 0; i < n; ++i) buf[offset + i] = src[i];
  return true;
}

inline bool getBytes(const uint8_t* buf, size_t bufLen, size_t offset, uint8_t* dst, size_t n) {
  if (offset + n > bufLen) return false;
  for (size_t i = 0; i < n; ++i) dst[i] = buf[offset + i];
  return true;
}

// True iff buf[offset .. offset+n) are all the NOR-erased value (0xFF) --
// used to distinguish "never programmed" (AbsentBytes) from a genuinely
// programmed-but-corrupt record.
inline bool isAllFF(const uint8_t* buf, size_t bufLen, size_t offset, size_t n) {
  if (offset + n > bufLen) return false;
  for (size_t i = 0; i < n; ++i) {
    if (buf[offset + i] != 0xFFu) return false;
  }
  return true;
}

}  // namespace security
}  // namespace ota
