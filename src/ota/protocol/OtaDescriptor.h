#pragma once

// Canonical signed OTA image descriptor.
//
// This is the trust-anchor payload that binds a firmware image to a specific
// board family/variant/role, its exact flash address and size, its SHA-256
// digest, an anti-rollback security counter, the minimum bootloader
// capabilities required to install it, and the format/key/algorithm ids that
// tell an external trust provider how to verify the accompanying signature.
//
// This module performs NO cryptography: it only produces/parses a
// deterministic canonical byte sequence. The actual signature bytes are
// opaque to this module and must be verified by an IOtaTrustProvider
// implementation supplied by the integrator (see
// src/ota/runtime/OtaTrustInterfaces.h).

#include "OtaWireTypes.h"
#include "OtaByteStream.h"
#include <cstring>

namespace meshcore {
namespace ota {
namespace protocol {

inline constexpr size_t kOtaSha256Size = 32;

struct OtaDescriptor {
  uint16_t boardFamily = 0;
  uint16_t boardVariant = 0;
  uint8_t role = 0;
  uint32_t appAddress = 0;
  uint32_t exactSizeBytes = 0;
  uint8_t sha256[kOtaSha256Size] = {};
  uint32_t securityCounter = 0;
  // Bitmask of bootloader capabilities the receiver's bootloader must
  // possess (e.g. staged-verify, external-flash, rollback) for this image to
  // be installable. Semantics of individual bits are owned by the
  // integrator.
  uint32_t minBootloaderCapabilities = 0;
  uint16_t formatId = 0;
  uint16_t keyId = 0;
  uint16_t algorithmId = 0;
};

// Fixed canonical wire size: 2+2+1+4+4+32+4+4+2+2+2.
inline constexpr size_t kOtaDescriptorCanonicalSize = 59;

enum class OtaDescriptorCodecResult : uint8_t {
  Ok = 0,
  TooShort,
  TooLong,
};

// Serializes the descriptor into a deterministic, field-order canonical byte
// sequence suitable for hashing/signing externally. Field-by-field encoding
// (not memcpy of the struct) avoids any compiler padding/alignment
// dependency.
inline OtaDescriptorCodecResult encodeOtaDescriptorCanonical(const OtaDescriptor& d,
                                                              uint8_t* dst, size_t dstCapacity,
                                                              size_t& outLen) {
  if (dstCapacity < kOtaDescriptorCanonicalSize) return OtaDescriptorCodecResult::TooShort;
  OtaBoundedWriter w(dst, dstCapacity);
  bool ok = w.putU16(d.boardFamily) && w.putU16(d.boardVariant) && w.putU8(d.role) &&
            w.putU32(d.appAddress) && w.putU32(d.exactSizeBytes) &&
            w.putBytes(d.sha256, kOtaSha256Size) &&
            w.putU32(d.securityCounter) && w.putU32(d.minBootloaderCapabilities) &&
            w.putU16(d.formatId) && w.putU16(d.keyId) && w.putU16(d.algorithmId);
  if (!ok) return OtaDescriptorCodecResult::TooShort;
  outLen = w.size();
  return OtaDescriptorCodecResult::Ok;
}

inline OtaDescriptorCodecResult decodeOtaDescriptorCanonical(const uint8_t* src, size_t srcLen,
                                                              OtaDescriptor& out) {
  if (srcLen < kOtaDescriptorCanonicalSize) return OtaDescriptorCodecResult::TooShort;
  if (srcLen > kOtaDescriptorCanonicalSize) return OtaDescriptorCodecResult::TooLong;
  OtaBoundedReader r(src, srcLen);
  bool ok = r.getU16(out.boardFamily) && r.getU16(out.boardVariant) && r.getU8(out.role) &&
            r.getU32(out.appAddress) && r.getU32(out.exactSizeBytes) &&
            r.getBytes(out.sha256, kOtaSha256Size) &&
            r.getU32(out.securityCounter) && r.getU32(out.minBootloaderCapabilities) &&
            r.getU16(out.formatId) && r.getU16(out.keyId) && r.getU16(out.algorithmId);
  if (!ok) return OtaDescriptorCodecResult::TooShort;
  return OtaDescriptorCodecResult::Ok;
}

// Bounded, no-heap reassembler for the DescriptorFragment message type,
// which carries the canonical descriptor bytes plus an opaque signature
// blob split across one or more fragments (e.g. for larger post-quantum
// signatures that don't fit a single frame's payload budget).
//
// Fragment geometry mirrors the chunk transfer model: every fragment but the
// last is exactly `fragmentPayloadSize` bytes; the last is whatever remains.
class OtaDescriptorReassembler {
public:
  static constexpr size_t kMaxBlobSize = 256;
  static constexpr uint8_t kMaxFragments = 8;

  void reset() {
    totalLength_ = 0;
    fragCount_ = 0;
    fragmentPayloadSize_ = 0;
    receivedMask_ = 0;
    started_ = false;
  }

  // Returns true if the fragment was accepted (including an exact-duplicate
  // resend). Returns false and leaves state unchanged for: invalid geometry
  // (zero/oversized fragCount, out-of-range fragIndex, totalLength exceeding
  // kMaxBlobSize, a length that doesn't match the expected size for that
  // fragment index), or a fragment whose fragCount/totalLength/
  // fragmentPayloadSize conflicts with an already-started reassembly (this
  // is treated as a distinct, non-replay-isolated concern here -- callers
  // must reset() between campaign attempts).
  bool addFragment(uint8_t fragIndex, uint8_t fragCount, uint16_t totalLength,
                    uint16_t fragmentPayloadSize, const uint8_t* data, size_t len) {
    if (fragCount == 0 || fragCount > kMaxFragments) return false;
    if (fragIndex >= fragCount) return false;
    if (totalLength == 0 || totalLength > kMaxBlobSize) return false;
    if (fragmentPayloadSize == 0 || fragmentPayloadSize > totalLength) return false;

    if (started_) {
      if (fragCount != fragCount_ || totalLength != totalLength_ ||
          fragmentPayloadSize != fragmentPayloadSize_) {
        return false;
      }
    }

    bool isLast = (fragIndex == static_cast<uint8_t>(fragCount - 1));
    size_t offset = static_cast<size_t>(fragIndex) * static_cast<size_t>(fragmentPayloadSize);
    size_t expectedLen = isLast ? (static_cast<size_t>(totalLength) - offset)
                                 : static_cast<size_t>(fragmentPayloadSize);
    if (len != expectedLen) return false;
    if (offset + expectedLen > kMaxBlobSize) return false;

    for (size_t i = 0; i < len; ++i) blob_[offset + i] = data[i];

    started_ = true;
    fragCount_ = fragCount;
    totalLength_ = totalLength;
    fragmentPayloadSize_ = fragmentPayloadSize;
    receivedMask_ |= (1u << fragIndex);
    return true;
  }

  bool isComplete() const {
    if (!started_) return false;
    uint32_t need = (fragCount_ >= 32) ? 0xFFFFFFFFu : ((1u << fragCount_) - 1u);
    return (receivedMask_ & need) == need;
  }

  const uint8_t* blob() const { return blob_; }
  size_t blobLength() const { return totalLength_; }

private:
  uint8_t blob_[kMaxBlobSize] = {};
  uint16_t totalLength_ = 0;
  uint8_t fragCount_ = 0;
  uint16_t fragmentPayloadSize_ = 0;
  uint32_t receivedMask_ = 0;
  bool started_ = false;
};

} // namespace protocol
} // namespace ota
} // namespace meshcore
