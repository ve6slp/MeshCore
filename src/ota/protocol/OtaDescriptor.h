#pragma once

// Canonical signed OTA image descriptor.
//
// This is the trust-anchor payload that binds a firmware image to a specific
// board family/variant/role, its exact flash address and size, its SHA-256
// digest, an anti-rollback security counter, the minimum bootloader
// capabilities required to install it, and the format/key/algorithm ids that
// identify the accompanying signature.
//
// This module performs NO cryptography: it only produces/parses a
// deterministic 59-byte big-endian sequence shared by OTA v4 packages and
// the bootloader's signed installation command. Signature verification is
// performed by the package and boot-safety layers, not by this codec.

#include "OtaByteStream.h"

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

} // namespace protocol
} // namespace ota
} // namespace meshcore
