#pragma once

// Fixed-layout payload structs and bounded encode/decode helpers for every
// OTA message type other than DescriptorFragment (see OtaDescriptor.h) and
// the envelope header itself (see OtaEnvelope.h).
//
// Every codec is strict: it fails (returns false) rather than reading past
// the supplied buffer, and decode requires an exact-length match for any
// fixed-size trailer. Variable-length trailing data (e.g. chunk payload
// bytes) is returned as a bounded (pointer, length) pair into the caller's
// buffer -- never copied to a heap-allocated container.

#include "OtaWireTypes.h"
#include "OtaByteStream.h"

namespace meshcore {
namespace ota {
namespace protocol {

// ---------------------------------------------------------------------
// Authorization: coordinator -> receiver grant/deny of a transfer attempt.
// ---------------------------------------------------------------------
struct OtaAuthorizationPayload {
  uint8_t granted = 0;
  uint32_t leaseId = 0;
  uint32_t expiresAtMs = 0;
  uint16_t maxInFlightChunks = 0;
};

inline constexpr size_t kOtaAuthorizationPayloadSize = 1 + 4 + 4 + 2;

inline bool encodeOtaAuthorization(const OtaAuthorizationPayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kOtaAuthorizationPayloadSize) return false;
  OtaBoundedWriter w(dst, cap);
  bool ok = w.putU8(p.granted) && w.putU32(p.leaseId) && w.putU32(p.expiresAtMs) && w.putU16(p.maxInFlightChunks);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeOtaAuthorization(const uint8_t* src, size_t len, OtaAuthorizationPayload& out) {
  if (len != kOtaAuthorizationPayloadSize) return false;
  OtaBoundedReader r(src, len);
  return r.getU8(out.granted) && r.getU32(out.leaseId) && r.getU32(out.expiresAtMs) && r.getU16(out.maxInFlightChunks);
}

// ---------------------------------------------------------------------
// Chunk: coordinator -> receiver image data. Data trailer is variable
// length (bounded by kOtaMaxPayloadSize - fixed header, see OtaEnvelope.h).
// ---------------------------------------------------------------------
struct OtaChunkHeader {
  uint32_t chunkIndex = 0;
  uint16_t dataLength = 0;
};

inline constexpr size_t kOtaChunkHeaderSize = 4 + 2;

inline bool encodeOtaChunk(const OtaChunkHeader& hdr, const uint8_t* data, size_t dataLen,
                            uint8_t* dst, size_t cap, size_t& outLen) {
  if (dataLen > 0xFFFFu || dataLen != hdr.dataLength) return false;
  if (cap < kOtaChunkHeaderSize + dataLen) return false;
  OtaBoundedWriter w(dst, cap);
  bool ok = w.putU32(hdr.chunkIndex) && w.putU16(hdr.dataLength) && w.putBytes(data, dataLen);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeOtaChunk(const uint8_t* src, size_t len, OtaChunkHeader& hdr,
                            const uint8_t*& outData, size_t& outDataLen) {
  if (len < kOtaChunkHeaderSize) return false;
  OtaBoundedReader r(src, len);
  if (!(r.getU32(hdr.chunkIndex) && r.getU16(hdr.dataLength))) return false;
  if (r.remaining() != hdr.dataLength) return false;
  outData = r.cursor();
  outDataLen = hdr.dataLength;
  return true;
}

// ---------------------------------------------------------------------
// Receipt: receiver -> coordinator durable receipt/status report.
// ---------------------------------------------------------------------
enum class OtaReceiptStatus : uint8_t {
  ChunkAck = 0,
  ChunkNack = 1,
  TransferComplete = 2,
  TransferFailed = 3,
};

struct OtaReceiptPayload {
  OtaReceiptStatus status = OtaReceiptStatus::ChunkAck;
  uint32_t chunkIndex = 0;
  uint32_t bytesReceived = 0;
  uint32_t lastGoodOffset = 0;
};

inline constexpr size_t kOtaReceiptPayloadSize = 1 + 4 + 4 + 4;

inline bool encodeOtaReceipt(const OtaReceiptPayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kOtaReceiptPayloadSize) return false;
  OtaBoundedWriter w(dst, cap);
  bool ok = w.putU8(static_cast<uint8_t>(p.status)) && w.putU32(p.chunkIndex) &&
            w.putU32(p.bytesReceived) && w.putU32(p.lastGoodOffset);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeOtaReceipt(const uint8_t* src, size_t len, OtaReceiptPayload& out) {
  if (len != kOtaReceiptPayloadSize) return false;
  OtaBoundedReader r(src, len);
  uint8_t status = 0;
  bool ok = r.getU8(status) && r.getU32(out.chunkIndex) && r.getU32(out.bytesReceived) && r.getU32(out.lastGoodOffset);
  if (!ok || status > static_cast<uint8_t>(OtaReceiptStatus::TransferFailed)) return false;
  out.status = static_cast<OtaReceiptStatus>(status);
  return true;
}

// ---------------------------------------------------------------------
// Abort: either party terminating a session.
// ---------------------------------------------------------------------
struct OtaAbortPayload {
  uint8_t reasonCode = 0;
  uint32_t atChunkIndex = 0;
};

inline constexpr size_t kOtaAbortPayloadSize = 1 + 4;

inline bool encodeOtaAbort(const OtaAbortPayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kOtaAbortPayloadSize) return false;
  OtaBoundedWriter w(dst, cap);
  bool ok = w.putU8(p.reasonCode) && w.putU32(p.atChunkIndex);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeOtaAbort(const uint8_t* src, size_t len, OtaAbortPayload& out) {
  if (len != kOtaAbortPayloadSize) return false;
  OtaBoundedReader r(src, len);
  return r.getU8(out.reasonCode) && r.getU32(out.atChunkIndex);
}

// ---------------------------------------------------------------------
// LeaseNegotiation: direct-mode radio profile lease request/grant/deny/
// renew/release.
// ---------------------------------------------------------------------
struct OtaLeaseNegotiationPayload {
  OtaLeaseSubtype subtype = OtaLeaseSubtype::Request;
  uint32_t leaseId = 0;
  uint32_t durationMs = 0;
  uint8_t radioProfileId = 0;
};

inline constexpr size_t kOtaLeaseNegotiationPayloadSize = 1 + 4 + 4 + 1;

inline bool encodeOtaLeaseNegotiation(const OtaLeaseNegotiationPayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kOtaLeaseNegotiationPayloadSize) return false;
  OtaBoundedWriter w(dst, cap);
  bool ok = w.putU8(static_cast<uint8_t>(p.subtype)) && w.putU32(p.leaseId) &&
            w.putU32(p.durationMs) && w.putU8(p.radioProfileId);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeOtaLeaseNegotiation(const uint8_t* src, size_t len, OtaLeaseNegotiationPayload& out) {
  if (len != kOtaLeaseNegotiationPayloadSize) return false;
  OtaBoundedReader r(src, len);
  uint8_t subtype = 0;
  bool ok = r.getU8(subtype) && r.getU32(out.leaseId) && r.getU32(out.durationMs) && r.getU8(out.radioProfileId);
  if (!ok || subtype < static_cast<uint8_t>(OtaLeaseSubtype::Request) ||
      subtype > static_cast<uint8_t>(OtaLeaseSubtype::Release)) {
    return false;
  }
  out.subtype = static_cast<OtaLeaseSubtype>(subtype);
  return true;
}

// ---------------------------------------------------------------------
// Announcement: bounded-fleet campaign advertisement.
// ---------------------------------------------------------------------
struct OtaAnnouncementPayload {
  uint32_t campaignId = 0;
  uint16_t descriptorTotalLength = 0;
  uint8_t priority = 0;
  uint32_t expiresAtMs = 0;
};

inline constexpr size_t kOtaAnnouncementPayloadSize = 4 + 2 + 1 + 4;

inline bool encodeOtaAnnouncement(const OtaAnnouncementPayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kOtaAnnouncementPayloadSize) return false;
  OtaBoundedWriter w(dst, cap);
  bool ok = w.putU32(p.campaignId) && w.putU16(p.descriptorTotalLength) && w.putU8(p.priority) && w.putU32(p.expiresAtMs);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeOtaAnnouncement(const uint8_t* src, size_t len, OtaAnnouncementPayload& out) {
  if (len != kOtaAnnouncementPayloadSize) return false;
  OtaBoundedReader r(src, len);
  return r.getU32(out.campaignId) && r.getU16(out.descriptorTotalLength) && r.getU8(out.priority) && r.getU32(out.expiresAtMs);
}

// ---------------------------------------------------------------------
// Census: fleet member -> coordinator progress report.
// ---------------------------------------------------------------------
struct OtaCensusPayload {
  uint32_t campaignId = 0;
  uint8_t haveDescriptor = 0;
  uint32_t bytesReceived = 0;
  uint16_t missingRangeCount = 0;
};

inline constexpr size_t kOtaCensusPayloadSize = 4 + 1 + 4 + 2;

inline bool encodeOtaCensus(const OtaCensusPayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kOtaCensusPayloadSize) return false;
  OtaBoundedWriter w(dst, cap);
  bool ok = w.putU32(p.campaignId) && w.putU8(p.haveDescriptor) && w.putU32(p.bytesReceived) && w.putU16(p.missingRangeCount);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeOtaCensus(const uint8_t* src, size_t len, OtaCensusPayload& out) {
  if (len != kOtaCensusPayloadSize) return false;
  OtaBoundedReader r(src, len);
  return r.getU32(out.campaignId) && r.getU8(out.haveDescriptor) && r.getU32(out.bytesReceived) && r.getU16(out.missingRangeCount);
}

// ---------------------------------------------------------------------
// CohortResolution: coordinator -> fleet member cohort/multicast group
// assignment.
// ---------------------------------------------------------------------
struct OtaCohortResolutionPayload {
  uint32_t campaignId = 0;
  uint16_t cohortId = 0;
  uint16_t cohortSize = 0;
  uint16_t cohortIndex = 0;
};

inline constexpr size_t kOtaCohortResolutionPayloadSize = 4 + 2 + 2 + 2;

inline bool encodeOtaCohortResolution(const OtaCohortResolutionPayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kOtaCohortResolutionPayloadSize) return false;
  OtaBoundedWriter w(dst, cap);
  bool ok = w.putU32(p.campaignId) && w.putU16(p.cohortId) && w.putU16(p.cohortSize) && w.putU16(p.cohortIndex);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeOtaCohortResolution(const uint8_t* src, size_t len, OtaCohortResolutionPayload& out) {
  if (len != kOtaCohortResolutionPayloadSize) return false;
  OtaBoundedReader r(src, len);
  return r.getU32(out.campaignId) && r.getU16(out.cohortId) && r.getU16(out.cohortSize) && r.getU16(out.cohortIndex);
}

// ---------------------------------------------------------------------
// MissingRange: fleet member -> coordinator directed selective-repair
// request.
// ---------------------------------------------------------------------
struct OtaMissingRangePayload {
  uint32_t campaignId = 0;
  uint32_t startChunkIndex = 0;
  uint32_t chunkCount = 0;
};

inline constexpr size_t kOtaMissingRangePayloadSize = 4 + 4 + 4;

inline bool encodeOtaMissingRange(const OtaMissingRangePayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kOtaMissingRangePayloadSize) return false;
  OtaBoundedWriter w(dst, cap);
  bool ok = w.putU32(p.campaignId) && w.putU32(p.startChunkIndex) && w.putU32(p.chunkCount);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeOtaMissingRange(const uint8_t* src, size_t len, OtaMissingRangePayload& out) {
  if (len != kOtaMissingRangePayloadSize) return false;
  OtaBoundedReader r(src, len);
  return r.getU32(out.campaignId) && r.getU32(out.startChunkIndex) && r.getU32(out.chunkCount);
}

// ---------------------------------------------------------------------
// Commit: coordinator -> receiver final verified-install instruction.
// ---------------------------------------------------------------------
struct OtaCommitPayload {
  uint32_t campaignId = 0;
  uint8_t verifiedOk = 0;
  uint32_t finalSecurityCounter = 0;
};

inline constexpr size_t kOtaCommitPayloadSize = 4 + 1 + 4;

inline bool encodeOtaCommit(const OtaCommitPayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kOtaCommitPayloadSize) return false;
  OtaBoundedWriter w(dst, cap);
  bool ok = w.putU32(p.campaignId) && w.putU8(p.verifiedOk) && w.putU32(p.finalSecurityCounter);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeOtaCommit(const uint8_t* src, size_t len, OtaCommitPayload& out) {
  if (len != kOtaCommitPayloadSize) return false;
  OtaBoundedReader r(src, len);
  return r.getU32(out.campaignId) && r.getU8(out.verifiedOk) && r.getU32(out.finalSecurityCounter);
}

} // namespace protocol
} // namespace ota
} // namespace meshcore
