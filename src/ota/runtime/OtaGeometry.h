#pragma once

// Strict geometry math for OTA image transfer, using checked (overflow
// aware) arithmetic. No heap use.

#include <cstdint>
#include <cstddef>
#include <limits>

namespace meshcore {
namespace ota {
namespace runtime {

inline constexpr uint32_t kOtaMaxImageBytes = 811008;
inline constexpr uint32_t kOtaDefaultChunkPayloadSize = 160;
// ceil(811008 / 160)
inline constexpr size_t kOtaMaxChunkCount = 5069;

enum class OtaGeometryResult : uint8_t {
  Ok = 0,
  ZeroImageSize,
  ZeroChunkSize,
  ImageTooLarge,
  ArithmeticOverflow,
};

// Exact chunk geometry for a single image transfer: total chunk count and
// the exact length of the final (possibly short) chunk. All internal
// arithmetic is performed in 64-bit and checked against uint32_t bounds
// before being accepted, so a malicious/corrupt (imageSize, chunkSize) pair
// can never silently overflow into an inconsistent bitmap size.
struct OtaGeometry {
  uint32_t imageSizeBytes = 0;
  uint32_t chunkPayloadSize = 0;
  uint32_t chunkCount = 0;
  uint32_t finalChunkLength = 0;

  static OtaGeometryResult compute(uint32_t imageSizeBytes, uint32_t chunkPayloadSize,
                                    uint32_t maxImageSizeBytes, OtaGeometry& out) {
    if (imageSizeBytes == 0) return OtaGeometryResult::ZeroImageSize;
    if (chunkPayloadSize == 0) return OtaGeometryResult::ZeroChunkSize;
    if (imageSizeBytes > maxImageSizeBytes) return OtaGeometryResult::ImageTooLarge;

    const uint64_t size64 = imageSizeBytes;
    const uint64_t chunk64 = chunkPayloadSize;
    const uint64_t count64 = (size64 + chunk64 - 1) / chunk64; // ceil-div; no overflow since size64 <= UINT32_MAX
    if (count64 == 0 || count64 > std::numeric_limits<uint32_t>::max()) {
      return OtaGeometryResult::ArithmeticOverflow;
    }
    if (count64 > kOtaMaxChunkCount) return OtaGeometryResult::ImageTooLarge;

    const uint64_t fullChunks = count64 - 1;
    const uint64_t consumedByFull = fullChunks * chunk64;
    if (consumedByFull > size64) return OtaGeometryResult::ArithmeticOverflow; // defensive, should be unreachable
    const uint64_t finalLen = size64 - consumedByFull;
    if (finalLen == 0 || finalLen > chunk64) return OtaGeometryResult::ArithmeticOverflow;

    out.imageSizeBytes = imageSizeBytes;
    out.chunkPayloadSize = chunkPayloadSize;
    out.chunkCount = static_cast<uint32_t>(count64);
    out.finalChunkLength = static_cast<uint32_t>(finalLen);
    return OtaGeometryResult::Ok;
  }

  // Exact byte length of chunk `index` (chunkPayloadSize for all but the
  // last chunk, finalChunkLength for the last one). Fails closed for any
  // out-of-range index, including on a default-constructed (uncomputed)
  // geometry.
  bool chunkLength(uint32_t index, uint32_t& outLen) const {
    if (chunkCount == 0 || index >= chunkCount) return false;
    outLen = (index == chunkCount - 1) ? finalChunkLength : chunkPayloadSize;
    return true;
  }

  bool chunkOffset(uint32_t index, uint64_t& outOffset) const {
    if (chunkCount == 0 || index >= chunkCount) return false;
    outOffset = static_cast<uint64_t>(index) * static_cast<uint64_t>(chunkPayloadSize);
    return true;
  }
};

} // namespace runtime
} // namespace ota
} // namespace meshcore
