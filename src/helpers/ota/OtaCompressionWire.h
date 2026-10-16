#pragma once
#include <helpers/ota/OtaBlockSigning.h>
#include <helpers/ota/OtaUsbProtocol.h>

namespace mesh { namespace ota {
static constexpr uint8_t kOtaCompressionPollKind = 0x13;
static constexpr uint8_t kOtaCompressionReportKind = 0x14;
static constexpr uint8_t kOtaCompressedFragmentKind = 0x15;
static constexpr uint8_t kOtaCodecCapabilityRequestKind = 0x16;
static constexpr uint8_t kOtaCodecCapabilityReportKind = 0x17;
static constexpr size_t kOtaCodecCapabilityRequestBytes = 83;
static constexpr size_t kOtaCodecCapabilityPrefixBytes = 87;
static constexpr size_t kOtaCodecCapabilityReportBytes = kOtaCodecCapabilityPrefixBytes + 64;
static constexpr uint8_t kOtaCodecCapabilityVersion = 1;
static constexpr uint8_t kOtaLzmaProfile = 0xa0;
static constexpr uint8_t kOtaLzmaThumbProfile = 0xa1;
static constexpr uint8_t kOtaCompressionRawProfile = 0;
static constexpr size_t kOtaCompressionGroupBytes = 8064;
static constexpr size_t kOtaCompressionGroupBlocks = kOtaCompressionGroupBytes / kOtaBlockMaxDataBytes;
static constexpr size_t kOtaCompressionPollBytes = 87;
static constexpr size_t kOtaCompressionReportBytes = 95;
static constexpr size_t kOtaCompressionHeaderBytes = 18;
static constexpr size_t kOtaCompressionFragmentOverhead = kOtaCompressionHeaderBytes + 64;
static constexpr size_t kOtaCompressionMaxDataBytes = 89;
static constexpr size_t kOtaCompressionMaxFrameBytes = kOtaCompressionFragmentOverhead + kOtaCompressionMaxDataBytes;

inline size_t buildOtaCodecCapabilityMessage(const uint8_t* prefix, uint8_t* out, size_t capacity) {
  static constexpr char domain[] = "MeshCore/OTA/codec-capability/v1";
  const size_t size = sizeof(domain) - 1 + kOtaCodecCapabilityPrefixBytes;
  if (!prefix || !out || capacity < size || prefix[0] != kOtaCodecCapabilityReportKind) return 0;
  std::memcpy(out, domain, sizeof(domain) - 1);
  std::memcpy(out + sizeof(domain) - 1, prefix, kOtaCodecCapabilityPrefixBytes);
  return size;
}

// CMD65 + priority, LOG_RX_DATA + SNR/RSSI, Mesh header/path-size. Account
// for maximum path growth, not just the path on the first transmission.
inline size_t otaCompressedFragmentCapacity(uint8_t hash_width, uint8_t max_hops,
                                             bool retry, bool transport_codes = false) {
  const size_t path = static_cast<size_t>(hash_width) * max_hops;
  if (!hash_width || hash_width > 3 || max_hops > 63 || path > 64) return 0;
  const size_t framing = 3u + 2u + path + (transport_codes ? 4u : 0u) +
                         (retry ? 5u : 0u) + kOtaCompressionFragmentOverhead;
  return framing < 176 ? 176 - framing : 0;
}

inline size_t buildOtaCompressedMessage(const uint8_t target[32], const uint8_t hash[32],
    uint32_t generation, const uint8_t nonce[usb::kBeginNonceBytes],
    const uint8_t* frame, size_t prefix_len, uint8_t* message, size_t capacity) {
  static constexpr char domain[] = "MeshCore/OTA/lzma1/v1";
  const size_t context = sizeof(domain) - 1 + 32 + 32 + 4 + usb::kBeginNonceBytes;
  if (!target || !hash || !nonce || !frame || !message ||
      prefix_len <= kOtaCompressionHeaderBytes ||
      prefix_len > kOtaCompressionHeaderBytes + kOtaCompressionMaxDataBytes ||
      capacity < context + prefix_len) return 0;
  size_t at = 0;
  std::memcpy(message, domain, sizeof(domain) - 1); at += sizeof(domain) - 1;
  std::memcpy(message + at, target, 32); at += 32;
  std::memcpy(message + at, hash, 32); at += 32;
  usb::putBE32(message + at, generation); at += 4;
  std::memcpy(message + at, nonce, usb::kBeginNonceBytes); at += usb::kBeginNonceBytes;
  std::memcpy(message + at, frame, prefix_len);
  return at + prefix_len;
}

inline bool validOtaCompressedFragment(const uint8_t* frame, size_t len) {
  return frame && frame[0] == kOtaCompressedFragmentKind &&
         len > kOtaCompressionFragmentOverhead && len <= kOtaCompressionMaxFrameBytes;
}
}}
