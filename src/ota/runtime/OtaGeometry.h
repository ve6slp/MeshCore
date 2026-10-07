#pragma once

// Strict geometry math for OTA image transfer, using checked (overflow
// aware) arithmetic. No heap use.

#include <cstdint>
#include <cstddef>
#include <limits>

namespace meshcore {
namespace ota {
namespace runtime {

// Generic transfer/cache ceiling and maximum ordinary nRF APP extent.
// Installation has a stricter per-target policy: paired nRF firmware
// must fit 643072 bytes below the immutable installer at 0xC4000.
// Cache capacity never grants authority to overwrite that installer or
// userdata; the board trust provider and bootloader enforce the install cap.
inline constexpr uint32_t kOtaMaxImageBytes = 708608;
// Chunk payload size is bounded by the *host<->companion USB serial* link,
// not the LoRa air interface: a host tool
// injects/observes OTA chunk traffic by wrapping a raw mesh packet inside a
// CMD_SEND_RAW_PACKET serial command, and BaseSerialInterface.h enforces a
// hard, shared, non-OTA-specific MAX_FRAME_SIZE of 176 bytes on that link
// (not increased here: additive compatibility with all existing serial
// consumers takes priority over a larger OTA chunk). Zero-hop overhead for
// a single chunk frame on that path is:
//   2  command header   (CMD_SEND_RAW_PACKET + priority)
//   2  raw packet header (header byte + path_len byte, 0 hops)
//   17 kOtaHeaderSize (OTA envelope header)
//   6  kOtaChunkHeaderSize (chunk index + length)
//   -----------------------------------------------
//   27 fixed overhead -> 176 - 27 = 149 bytes max at zero hops.
// Routed/directed-mode packets add getPathHashSize() bytes (up to 3, per
// Packet::getPathHashSize()) PER HOP to the path field, shrinking the
// budget further. 128 is chosen so up to 7 hops of 3-byte path hashes
// still fit (128 + 7*3 = 149 <= 149), it divides kOtaMaxImageBytes evenly
// (keeping the final chunk full-size), and it leaves 21 bytes of slack at
// zero/low hop counts for other optional header fields (e.g. transport
// codes) without ever exceeding the shared serial frame limit.
inline constexpr uint32_t kOtaDefaultChunkPayloadSize = 128;
// exact: 708608 / 128
inline constexpr size_t kOtaMaxChunkCount = 5536;

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
