#pragma once

// Strict, bounded, endian-explicit OTA envelope codec.
//
// Wire layout (all multi-byte fields big-endian):
//   [0:2)   namespace id       (must equal kOtaNamespaceId)
//   [2:3)   protocol version   (must equal kOtaProtocolVersion)
//   [3:4)   message type       (must be a known OtaMessageType)
//   [4:8)   campaign id
//   [8:12)  session id
//   [12:14) attempt id
//   [14:15) flags
//   [15:17) payload length
//   [17:17+payloadLength) payload
//
// Decoding is strict: truncated frames, frames with declared payload length
// that does not exactly match the remaining bytes (whether short or padded
// with trailing garbage), oversized frames, unknown namespace, unknown
// version and unknown message type are all rejected explicitly and
// distinguishably via OtaCodecResult.

#include "OtaWireTypes.h"
#include "OtaByteStream.h"

namespace meshcore {
namespace ota {
namespace protocol {

inline constexpr size_t kOtaHeaderSize = 2 + 1 + 1 + 4 + 4 + 2 + 1 + 2; // 17 bytes
inline constexpr size_t kOtaMaxPayloadSize = kOtaMaxFrameSize - kOtaHeaderSize;

enum class OtaCodecResult : uint8_t {
  Ok = 0,
  TooShort,
  TooLong,
  BadNamespace,
  BadVersion,
  BadMessageType,
  PayloadLengthMismatch,
  PayloadTooLarge,
};

struct OtaEnvelopeHeader {
  uint16_t ns = kOtaNamespaceId;
  uint8_t version = kOtaProtocolVersion;
  OtaMessageType type = OtaMessageType::DescriptorFragment;
  uint32_t campaignId = 0;
  uint32_t sessionId = 0;
  uint16_t attemptId = 0;
  uint8_t flags = 0;
  uint16_t payloadLength = 0;
};

// Encodes header + payload into dst. Fails closed (returns a non-Ok result,
// leaves dst untouched beyond whatever partial writes already checked out)
// if dst is too small or the payload exceeds the maximum bounded size.
inline OtaCodecResult encodeOtaEnvelope(const OtaEnvelopeHeader& hdr,
                                         const uint8_t* payload, size_t payloadLen,
                                         uint8_t* dst, size_t dstCapacity, size_t& outLen) {
  if (payloadLen > kOtaMaxPayloadSize || payloadLen > 0xFFFFu) return OtaCodecResult::PayloadTooLarge;
  if (dstCapacity < kOtaHeaderSize + payloadLen) return OtaCodecResult::TooShort;
  if (!isKnownOtaMessageType(static_cast<uint8_t>(hdr.type))) return OtaCodecResult::BadMessageType;

  OtaBoundedWriter w(dst, dstCapacity);
  bool ok = w.putU16(hdr.ns) && w.putU8(hdr.version) &&
            w.putU8(static_cast<uint8_t>(hdr.type)) &&
            w.putU32(hdr.campaignId) && w.putU32(hdr.sessionId) &&
            w.putU16(hdr.attemptId) && w.putU8(hdr.flags) &&
            w.putU16(static_cast<uint16_t>(payloadLen)) &&
            w.putBytes(payload, payloadLen);
  if (!ok) return OtaCodecResult::TooShort;
  outLen = w.size();
  return OtaCodecResult::Ok;
}

// Strictly validates and decodes a frame. On success, outPayload/outPayloadLen
// point directly into src (zero-copy, no heap).
inline OtaCodecResult decodeOtaEnvelope(const uint8_t* src, size_t srcLen,
                                         OtaEnvelopeHeader& hdr,
                                         const uint8_t*& outPayload, size_t& outPayloadLen) {
  if (srcLen < kOtaHeaderSize) return OtaCodecResult::TooShort;
  if (srcLen > kOtaMaxFrameSize) return OtaCodecResult::TooLong;

  OtaBoundedReader r(src, srcLen);
  uint16_t ns = 0;
  uint8_t version = 0;
  uint8_t type = 0;
  uint32_t campaignId = 0;
  uint32_t sessionId = 0;
  uint16_t attemptId = 0;
  uint8_t flags = 0;
  uint16_t payloadLength = 0;

  if (!(r.getU16(ns) && r.getU8(version) && r.getU8(type) &&
        r.getU32(campaignId) && r.getU32(sessionId) && r.getU16(attemptId) &&
        r.getU8(flags) && r.getU16(payloadLength))) {
    return OtaCodecResult::TooShort;
  }

  if (ns != kOtaNamespaceId) return OtaCodecResult::BadNamespace;
  if (version != kOtaProtocolVersion) return OtaCodecResult::BadVersion;
  if (!isKnownOtaMessageType(type)) return OtaCodecResult::BadMessageType;
  if (payloadLength > kOtaMaxPayloadSize) return OtaCodecResult::PayloadTooLarge;
  // Exact-match requirement: rejects both truncated payloads (remaining()
  // less than declared) and oversized/padded frames (remaining() greater
  // than declared, e.g. trailing garbage bytes).
  if (r.remaining() != payloadLength) return OtaCodecResult::PayloadLengthMismatch;

  hdr.ns = ns;
  hdr.version = version;
  hdr.type = static_cast<OtaMessageType>(type);
  hdr.campaignId = campaignId;
  hdr.sessionId = sessionId;
  hdr.attemptId = attemptId;
  hdr.flags = flags;
  hdr.payloadLength = payloadLength;
  outPayload = r.cursor();
  outPayloadLen = payloadLength;
  return OtaCodecResult::Ok;
}

} // namespace protocol
} // namespace ota
} // namespace meshcore
