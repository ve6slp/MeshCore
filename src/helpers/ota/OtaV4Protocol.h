#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace mesh { namespace ota { namespace v4 {

inline constexpr uint8_t kVersion = 4;
inline constexpr uint8_t kMagic = 0xD4;
inline constexpr size_t kChunkBytes = 8192;
inline constexpr size_t kSliceBytes = 128;
inline constexpr size_t kMaxChunks = 128;
inline constexpr size_t kMaxManifestBytes = 8192;
inline constexpr size_t kMaxControlBytes = 512;
inline constexpr size_t kHashBytes = 32;
inline constexpr size_t kTagBytes = 8;
inline constexpr size_t kNonceBytes = 16;
inline constexpr size_t kSignatureBytes = 64;
inline constexpr size_t kFrameHeaderBytes = 19;
inline constexpr size_t kFrameTrailerBytes = 4;
inline constexpr size_t kMaxFrameBytes = kFrameHeaderBytes + kSliceBytes + kFrameTrailerBytes;
inline constexpr size_t kManifestPrefixBytes = 4 + 1 + 1 + 2 + 32 + 59 + 64;
inline constexpr size_t kManifestEntryBytes = 1 + 2 + 32;
inline constexpr size_t kSignedCommandBytes = 32 + 32 + 32 + 16 + 4;
inline constexpr size_t kCommandBytes = kSignedCommandBytes + kSignatureBytes;
inline constexpr size_t kQueryBytes = 32 + 16;
inline constexpr size_t kSignedStatusBytes = 169;
inline constexpr size_t kStatusBytes = kSignedStatusBytes + kSignatureBytes;
inline constexpr size_t kProgressQueryBytes = 32;
inline constexpr size_t kProgressBytes = 32 + 4 + 2 + 8 + 1 + 1;
inline constexpr size_t kLeaseParametersBytes = 4 + 4 + 1 + 1 + 4;
inline constexpr size_t kLeaseCommandBytes = kCommandBytes + kLeaseParametersBytes;

inline constexpr char kManifestDomain[] = "MeshCore OTA package v4";
inline constexpr char kStatusDomain[] = "MeshCore OTA status v4";
inline constexpr char kAdmitDomain[] = "MeshCore OTA admit v4";
inline constexpr char kActivateDomain[] = "MeshCore OTA activate v4";
inline constexpr char kAbortDomain[] = "MeshCore OTA abort v4";
inline constexpr char kLeaseDomain[] = "MeshCore OTA lease v4";
inline constexpr char kRepairDomain[] = "MeshCore OTA repair v4";

enum Evidence : uint8_t {
  FloorKnown = 1,
  RunningHashKnown = 2,
  RunningConfirmed = 4,
};

enum class Kind : uint8_t {
  Query = 1,
  Status = 2,
  Manifest = 3,
  Admit = 4,
  Data = 5,
  ProgressQuery = 6,
  Progress = 7,
  Activate = 8,
  Abort = 9,
  Lease = 10,
  Repair = 11,
};

enum class Codec : uint8_t { Raw = 0, Lzma = 1, LzmaThumb = 2 };

enum class Phase : uint8_t {
  Idle = 0,
  Receiving = 1,
  Verifying = 2,
  Ready = 3,
  ActivationPending = 4,
  Trial = 5,
  Confirmed = 6,
  Aborted = 7,
  Failed = 8,
  MetadataFault = 9,
};

enum class Result : uint8_t {
  Ok = 0,
  Invalid = 1,
  Denied = 2,
  Busy = 3,
  State = 4,
  Integrity = 5,
  Io = 6,
  Unsupported = 7,
  Replay = 8,
};

inline uint16_t read16(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline uint32_t read32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

inline void write16(uint8_t* p, uint16_t n) {
  p[0] = static_cast<uint8_t>(n >> 8);
  p[1] = static_cast<uint8_t>(n);
}

inline void write32(uint8_t* p, uint32_t n) {
  p[0] = static_cast<uint8_t>(n >> 24);
  p[1] = static_cast<uint8_t>(n >> 16);
  p[2] = static_cast<uint8_t>(n >> 8);
  p[3] = static_cast<uint8_t>(n);
}

inline uint64_t read64(const uint8_t* p) {
  return (static_cast<uint64_t>(read32(p)) << 32) | read32(p + 4);
}

inline void write64(uint8_t* p, uint64_t n) {
  write32(p, static_cast<uint32_t>(n >> 32));
  write32(p + 4, static_cast<uint32_t>(n));
}

inline uint32_t crc32(const uint8_t* p, size_t size) {
  uint32_t crc = UINT32_MAX;
  for (size_t i = 0; i < size; ++i) {
    crc ^= p[i];
    for (unsigned bit = 0; bit < 8; ++bit)
      crc = (crc >> 1) ^ ((crc & 1u) ? 0xEDB88320u : 0u);
  }
  return ~crc;
}

inline bool validKind(uint8_t kind) {
  return kind >= static_cast<uint8_t>(Kind::Query) && kind <= static_cast<uint8_t>(Kind::Repair);
}

struct Frame {
  Kind kind = Kind::Query;
  uint32_t attempt = 0;
  const uint8_t* tag = nullptr;
  uint16_t object = 0;
  uint16_t total = 0;
  uint8_t slice = 0;
  const uint8_t* data = nullptr;
  size_t size = 0;
};

inline size_t sliceSize(size_t total, size_t slice) {
  const size_t offset = slice * kSliceBytes;
  if (!total || total > kChunkBytes || offset >= total) return 0;
  const size_t remaining = total - offset;
  return remaining < kSliceBytes ? remaining : kSliceBytes;
}

inline bool decodeFrame(const uint8_t* bytes, size_t size, Frame& out) {
  if (!bytes || size <= kFrameHeaderBytes + kFrameTrailerBytes || size > kMaxFrameBytes ||
      bytes[0] != kMagic || !validKind(bytes[1]) || !read32(bytes + 2)) return false;
  const uint16_t total = read16(bytes + 16);
  const size_t payload = size - kFrameHeaderBytes - kFrameTrailerBytes;
  if (sliceSize(total, bytes[18]) != payload ||
      crc32(bytes, size - kFrameTrailerBytes) != read32(bytes + size - kFrameTrailerBytes))
    return false;
  out.kind = static_cast<Kind>(bytes[1]);
  out.attempt = read32(bytes + 2);
  out.tag = bytes + 6;
  out.object = read16(bytes + 14);
  out.total = total;
  out.slice = bytes[18];
  out.data = bytes + kFrameHeaderBytes;
  out.size = payload;
  return true;
}

inline size_t encodeFrame(Kind kind, uint32_t attempt, const uint8_t tag[kTagBytes],
                          uint16_t object, uint16_t total, uint8_t slice,
                          const uint8_t* data, size_t size, uint8_t* out, size_t capacity) {
  const size_t bytes = kFrameHeaderBytes + size + kFrameTrailerBytes;
  if (!validKind(static_cast<uint8_t>(kind)) || !attempt || !tag || !data || !out ||
      !size || sliceSize(total, slice) != size || bytes > capacity || bytes > kMaxFrameBytes)
    return 0;
  out[0] = kMagic;
  out[1] = static_cast<uint8_t>(kind);
  write32(out + 2, attempt);
  std::memcpy(out + 6, tag, kTagBytes);
  write16(out + 14, object);
  write16(out + 16, total);
  out[18] = slice;
  std::memcpy(out + kFrameHeaderBytes, data, size);
  write32(out + kFrameHeaderBytes + size, crc32(out, kFrameHeaderBytes + size));
  return bytes;
}

inline uint64_t sliceMask(size_t total) {
  const size_t count = (total + kSliceBytes - 1) / kSliceBytes;
  return count == 64 ? UINT64_MAX : count && count < 64 ? (UINT64_C(1) << count) - 1 : 0;
}

}}}
