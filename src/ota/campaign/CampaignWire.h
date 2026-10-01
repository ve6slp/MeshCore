#pragma once

// Versioned campaign datagram wire codec (protocol version 2).
//
// This is an EXPLICITLY NEW, versioned wire format distinct from the
// legacy raw lab envelope in src/ota/protocol/OtaEnvelope.h (version 1,
// kOtaProtocolVersion == 1). Both coexist: decodeOtaEnvelope() (v1) still
// rejects anything whose version byte isn't 1, and decodeCampaignEnvelope
// (this file, v2) only ever accepts version byte 2. Neither file's
// behavior is silently changed by the other's existence.
//
// The plaintext header carried here is deliberately compact: peer/
// controller identity and authorization scope are NOT repeated on every
// wire frame, because that identity is already established out-of-band by
// the authenticated transport port (see CampaignPorts.h,
// AuthenticatedInboundFrame::pairwise()->peerId) before this layer ever
// sees the frame -- duplicating a 32-byte identity into every chunk frame would
// eat directly into the real remaining authenticated-RF budget for no
// additional trust benefit. Full 32-byte controller identity IS carried
// explicitly inside the ConsentRequest/ConsentGrant payload bodies below,
// because that identity is the actual content being bound/consented to,
// not merely the transport-level sender.
//
// Header layout (21 bytes, all multi-byte fields big-endian):
//   [0:2)   namespace id        (reuses protocol::kOtaNamespaceId)
//   [2:3)   protocol version    (must equal kCampaignProtocolVersion == 2)
//   [3:4)   message type        (CampaignMessageType)
//   [4:8)   campaign id
//   [8:12)  session id
//   [12:14) attempt id
//   [14:18) frame sequence      (fresh authenticated per-frame retry
//                                 sequence, independent of the transfer
//                                 session/attempt tuple above -- used for
//                                 per-frame dedup/retry, never to gate
//                                 session-level replay)
//   [18:19) flags
//   [19:21) payload length
//   [21:21+payloadLength) payload

#include <cstdint>
#include <cstddef>
#include "../protocol/OtaWireTypes.h"
#include "../protocol/OtaByteStream.h"
#include "../protocol/OtaMessages.h"
#include "../runtime/OtaSessionIdentity.h"
#include "../runtime/OtaGeometry.h"

namespace meshcore {
namespace ota {
namespace campaign {

inline constexpr uint8_t kCampaignProtocolVersion = 2;

// Radio/authenticated-transport bounds this module is modeled against
// (see src/MeshCore.h / src/Packet.h for the authoritative firmware
// values; restated here as independent constants -- deliberately not
// included -- so this module stays free of any firmware/Mesh coupling):
//   MAX_PACKET_PAYLOAD = 184  (protocol::kOtaMaxFrameSize, above)
//   MAX_PATH_SIZE      = 64   (a SEPARATE field from payload; not part of
//                              this budget)
//   MAX_TRANS_UNIT     = 255  (path + header + payload on the air)
//
// A real authenticated send does NOT merely truncate 2 bytes of MAC off
// the 184-byte payload: it AEAD-encrypts a plaintext body consisting of a
// 4-byte sequence/nonce field followed by this campaign envelope, pads
// that combined body up to a 16-byte cipher block boundary, appends a
// full 16-byte authentication TAG (not a weak 2-byte MAC), and the
// resulting ciphertext sits behind 3 bytes of fixed outer framing
// (message-type/flags) still inside the 184-byte payload field. I.e.:
//
//   184 >= 3 + 16(tag) + roundUp16(4(seq) + campaignFrameLen)
//
// Solving for the largest campaignFrameLen that satisfies this for every
// possible padding remainder gives the conservative worst-case ceiling
// below (evaluated at compile time, not hand-computed/hardcoded, so it
// automatically tracks these parameters if they ever change):
inline constexpr size_t kCampaignCryptoFixedOverheadBytes = 3;
inline constexpr size_t kCampaignCryptoTagBytes = 16; // strong AEAD tag, NOT a 2-byte MAC
inline constexpr size_t kCampaignCryptoSequenceBytes = 4;
inline constexpr size_t kCampaignCryptoPadBlockBytes = 16;

inline constexpr size_t campaignRoundUpToBlock(size_t n, size_t block) {
  return ((n + block - 1) / block) * block;
}

// Largest campaignFrameLen (envelope header + payload) such that
// 3 + 16 + roundUp16(4 + campaignFrameLen) <= kOtaMaxFrameSize, found by
// evaluating the worst case directly rather than an approximation.
inline constexpr size_t campaignComputeMaxAuthenticatedFrameLen() {
  // The largest padded-body budget that still fits: kOtaMaxFrameSize minus
  // the fixed 3-byte outer framing and the 16-byte tag, rounded DOWN to a
  // block boundary (a padded ciphertext body is always an exact multiple
  // of the block size).
  size_t rawBudget = protocol::kOtaMaxFrameSize - kCampaignCryptoFixedOverheadBytes - kCampaignCryptoTagBytes;
  size_t paddedBodyBudget = (rawBudget / kCampaignCryptoPadBlockBytes) * kCampaignCryptoPadBlockBytes;
  return paddedBodyBudget - kCampaignCryptoSequenceBytes;
}

inline constexpr size_t kCampaignAuthenticatedFrameBudget = campaignComputeMaxAuthenticatedFrameLen(); // 156 bytes

inline constexpr size_t kCampaignHeaderSize = 2 + 1 + 1 + 4 + 4 + 2 + 4 + 1 + 2; // 21 bytes
inline constexpr size_t kCampaignMaxPayloadSize = kCampaignAuthenticatedFrameBudget - kCampaignHeaderSize; // 135 bytes

static_assert(kCampaignAuthenticatedFrameBudget == 156, "RF budget formula drifted from the accepted derivation");
static_assert(kCampaignMaxPayloadSize >= runtime::kOtaDefaultChunkPayloadSize + protocol::kOtaChunkHeaderSize,
              "Chunk payload (header+128B) must fit under the real authenticated remaining budget");

enum class CampaignMessageType : uint8_t {
  ConsentRequest = 1,   // controller -> target: descriptor admission ask + consent binding
  ConsentGrant = 2,     // target -> controller: accept/deny with reason
  Chunk = 3,
  Receipt = 4,
  Abort = 5,
  LeaseNegotiation = 6, // direct-mode radio profile lease
  Announcement = 7,     // background fleet campaign advertisement
  Census = 8,           // paginated fleet progress report
  CohortResolution = 9,
  MissingRange = 10,    // paginated selective repair request
  Commit = 11,          // pairwise final verified-install instruction
  Hello = 12,           // direct-mode rendezvous ON the alternate frequency
  DescriptorFragment = 13, // one fragment of the signed descriptor+signature blob
};

inline constexpr uint8_t kCampaignMessageTypeMin = static_cast<uint8_t>(CampaignMessageType::ConsentRequest);
inline constexpr uint8_t kCampaignMessageTypeMax = static_cast<uint8_t>(CampaignMessageType::DescriptorFragment);

inline constexpr bool isKnownCampaignMessageType(uint8_t raw) {
  return raw >= kCampaignMessageTypeMin && raw <= kCampaignMessageTypeMax;
}

struct CampaignEnvelopeHeader {
  uint16_t ns = protocol::kOtaNamespaceId;
  uint8_t version = kCampaignProtocolVersion;
  CampaignMessageType type = CampaignMessageType::ConsentRequest;
  runtime::OtaSessionId session{};
  uint32_t frameSeq = 0;
  uint8_t flags = 0;
  uint16_t payloadLength = 0;
};

enum class CampaignCodecResult : uint8_t {
  Ok = 0,
  TooShort,
  TooLong,
  BadNamespace,
  BadVersion,
  BadMessageType,
  PayloadLengthMismatch,
  PayloadTooLarge,
};

inline CampaignCodecResult encodeCampaignEnvelope(const CampaignEnvelopeHeader& hdr,
                                                   const uint8_t* payload, size_t payloadLen,
                                                   uint8_t* dst, size_t dstCapacity, size_t& outLen) {
  if (payloadLen > kCampaignMaxPayloadSize || payloadLen > 0xFFFFu) return CampaignCodecResult::PayloadTooLarge;
  if (dstCapacity < kCampaignHeaderSize + payloadLen) return CampaignCodecResult::TooShort;
  if (!isKnownCampaignMessageType(static_cast<uint8_t>(hdr.type))) return CampaignCodecResult::BadMessageType;

  protocol::OtaBoundedWriter w(dst, dstCapacity);
  bool ok = w.putU16(hdr.ns) && w.putU8(hdr.version) && w.putU8(static_cast<uint8_t>(hdr.type)) &&
            w.putU32(hdr.session.campaignId) && w.putU32(hdr.session.sessionId) &&
            w.putU16(hdr.session.attemptId) && w.putU32(hdr.frameSeq) && w.putU8(hdr.flags) &&
            w.putU16(static_cast<uint16_t>(payloadLen)) && w.putBytes(payload, payloadLen);
  if (!ok) return CampaignCodecResult::TooShort;
  outLen = w.size();
  return CampaignCodecResult::Ok;
}

inline CampaignCodecResult decodeCampaignEnvelope(const uint8_t* src, size_t srcLen,
                                                   CampaignEnvelopeHeader& hdr,
                                                   const uint8_t*& outPayload, size_t& outPayloadLen) {
  if (srcLen < kCampaignHeaderSize) return CampaignCodecResult::TooShort;
  if (srcLen > kCampaignAuthenticatedFrameBudget) return CampaignCodecResult::TooLong;

  protocol::OtaBoundedReader r(src, srcLen);
  uint16_t ns = 0;
  uint8_t version = 0;
  uint8_t type = 0;
  uint32_t campaignId = 0;
  uint32_t sessionId = 0;
  uint16_t attemptId = 0;
  uint32_t frameSeq = 0;
  uint8_t flags = 0;
  uint16_t payloadLength = 0;

  if (!(r.getU16(ns) && r.getU8(version) && r.getU8(type) && r.getU32(campaignId) &&
        r.getU32(sessionId) && r.getU16(attemptId) && r.getU32(frameSeq) && r.getU8(flags) &&
        r.getU16(payloadLength))) {
    return CampaignCodecResult::TooShort;
  }

  if (ns != protocol::kOtaNamespaceId) return CampaignCodecResult::BadNamespace;
  if (version != kCampaignProtocolVersion) return CampaignCodecResult::BadVersion;
  if (!isKnownCampaignMessageType(type)) return CampaignCodecResult::BadMessageType;
  if (payloadLength > kCampaignMaxPayloadSize) return CampaignCodecResult::PayloadTooLarge;
  if (r.remaining() != payloadLength) return CampaignCodecResult::PayloadLengthMismatch;

  hdr.ns = ns;
  hdr.version = version;
  hdr.type = static_cast<CampaignMessageType>(type);
  hdr.session.campaignId = campaignId;
  hdr.session.sessionId = sessionId;
  hdr.session.attemptId = attemptId;
  hdr.frameSeq = frameSeq;
  hdr.flags = flags;
  hdr.payloadLength = payloadLength;
  outPayload = r.cursor();
  outPayloadLen = payloadLength;
  return CampaignCodecResult::Ok;
}

// ---------------------------------------------------------------------
// ConsentRequest / ConsentGrant: explicit descriptor-admission consent
// binding. Carries the FULL 32-byte controller identity and the
// authorization scope (pairwise vs group) as actual content, distinct
// from (and in addition to) the transport-level authenticated sender.
// ---------------------------------------------------------------------
struct CampaignConsentRequestPayload {
  uint8_t controllerId[32] = {};
  uint8_t scope = 0; // CampaignAuthScope
  uint32_t groupId = 0;
  uint16_t descriptorTotalLength = 0;
};

inline constexpr size_t kCampaignConsentRequestSize = 32 + 1 + 4 + 2;

inline bool encodeCampaignConsentRequest(const CampaignConsentRequestPayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kCampaignConsentRequestSize) return false;
  protocol::OtaBoundedWriter w(dst, cap);
  bool ok = w.putBytes(p.controllerId, sizeof(p.controllerId)) && w.putU8(p.scope) &&
            w.putU32(p.groupId) && w.putU16(p.descriptorTotalLength);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeCampaignConsentRequest(const uint8_t* src, size_t len, CampaignConsentRequestPayload& out) {
  if (len != kCampaignConsentRequestSize) return false;
  protocol::OtaBoundedReader r(src, len);
  return r.getBytes(out.controllerId, sizeof(out.controllerId)) && r.getU8(out.scope) &&
         r.getU32(out.groupId) && r.getU16(out.descriptorTotalLength);
}

struct CampaignConsentGrantPayload {
  uint8_t granted = 0;
  uint8_t refusalReason = 0; // CampaignRefusalReason
  uint16_t maxInFlightChunks = 0;
};

inline constexpr size_t kCampaignConsentGrantSize = 1 + 1 + 2;

inline bool encodeCampaignConsentGrant(const CampaignConsentGrantPayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kCampaignConsentGrantSize) return false;
  protocol::OtaBoundedWriter w(dst, cap);
  bool ok = w.putU8(p.granted) && w.putU8(p.refusalReason) && w.putU16(p.maxInFlightChunks);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeCampaignConsentGrant(const uint8_t* src, size_t len, CampaignConsentGrantPayload& out) {
  if (len != kCampaignConsentGrantSize) return false;
  protocol::OtaBoundedReader r(src, len);
  return r.getU8(out.granted) && r.getU8(out.refusalReason) && r.getU16(out.maxInFlightChunks);
}

// ---------------------------------------------------------------------
// Paginated Census / MissingRange: bounds each page to
// kCampaignMaxMissingRangesPerPage entries so a fleet member with many
// scattered holes never produces an unbounded single frame.
// ---------------------------------------------------------------------
struct CampaignMissingRangeEntry {
  uint32_t startChunkIndex = 0;
  uint32_t chunkCount = 0;
};

inline constexpr size_t kCampaignMissingRangeEntrySize = 4 + 4;

struct CampaignCensusPagePayload {
  uint32_t bytesReceived = 0;
  uint16_t pageIndex = 0;
  uint16_t pageCount = 0;
  uint8_t entryCount = 0; // <= kCampaignMaxMissingRangesPerPage
  // Binds this page to a specific repair round/generation so a stale page
  // from a previous round (e.g. delayed in flight across a repair-round
  // restart) cannot be folded into the current round's accumulation.
  uint8_t roundIndex = 0;
  CampaignMissingRangeEntry entries[8] = {};
};

inline constexpr size_t kCampaignCensusPageFixedSize = 4 + 2 + 2 + 1 + 1;

inline bool encodeCampaignCensusPage(const CampaignCensusPagePayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (p.entryCount > 8) return false;
  const size_t needed = kCampaignCensusPageFixedSize + static_cast<size_t>(p.entryCount) * kCampaignMissingRangeEntrySize;
  if (cap < needed) return false;
  protocol::OtaBoundedWriter w(dst, cap);
  bool ok = w.putU32(p.bytesReceived) && w.putU16(p.pageIndex) && w.putU16(p.pageCount) && w.putU8(p.entryCount) &&
            w.putU8(p.roundIndex);
  for (uint8_t i = 0; ok && i < p.entryCount; ++i) {
    ok = w.putU32(p.entries[i].startChunkIndex) && w.putU32(p.entries[i].chunkCount);
  }
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeCampaignCensusPage(const uint8_t* src, size_t len, CampaignCensusPagePayload& out) {
  if (len < kCampaignCensusPageFixedSize) return false;
  protocol::OtaBoundedReader r(src, len);
  if (!(r.getU32(out.bytesReceived) && r.getU16(out.pageIndex) && r.getU16(out.pageCount) && r.getU8(out.entryCount) &&
        r.getU8(out.roundIndex))) {
    return false;
  }
  if (out.entryCount > 8) return false;
  const size_t expected = kCampaignCensusPageFixedSize + static_cast<size_t>(out.entryCount) * kCampaignMissingRangeEntrySize;
  if (len != expected) return false;
  for (uint8_t i = 0; i < out.entryCount; ++i) {
    if (!(r.getU32(out.entries[i].startChunkIndex) && r.getU32(out.entries[i].chunkCount))) return false;
  }
  return true;
}

// ---------------------------------------------------------------------
// DescriptorFragment: bounded, no-heap delivery of the signed descriptor
// (59 bytes canonical) + opaque signature blob, reusing
// protocol::OtaDescriptorReassembler's fragment geometry contract
// verbatim (fragIndex/fragCount/totalLength/fragmentPayloadSize). A
// descriptor+typical signature normally fits in ONE fragment under the
// real authenticated budget; multi-fragment delivery exists so a larger
// signature/blob is genuinely paginated rather than ever packed into an
// oversized frame.
// ---------------------------------------------------------------------
inline constexpr size_t kCampaignDescriptorFragmentFixedSize = 1 + 1 + 2 + 2;

inline bool encodeCampaignDescriptorFragment(uint8_t fragIndex, uint8_t fragCount, uint16_t totalLength,
                                              uint16_t fragmentPayloadSize, const uint8_t* data, size_t dataLen,
                                              uint8_t* dst, size_t cap, size_t& outLen) {
  const size_t needed = kCampaignDescriptorFragmentFixedSize + dataLen;
  if (cap < needed || needed > kCampaignMaxPayloadSize) return false;
  protocol::OtaBoundedWriter w(dst, cap);
  bool ok = w.putU8(fragIndex) && w.putU8(fragCount) && w.putU16(totalLength) &&
            w.putU16(fragmentPayloadSize) && w.putBytes(data, dataLen);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeCampaignDescriptorFragment(const uint8_t* src, size_t len, uint8_t& fragIndex, uint8_t& fragCount,
                                              uint16_t& totalLength, uint16_t& fragmentPayloadSize,
                                              const uint8_t*& outData, size_t& outDataLen) {
  if (len < kCampaignDescriptorFragmentFixedSize) return false;
  protocol::OtaBoundedReader r(src, len);
  if (!(r.getU8(fragIndex) && r.getU8(fragCount) && r.getU16(totalLength) && r.getU16(fragmentPayloadSize))) {
    return false;
  }
  outData = r.cursor();
  outDataLen = r.remaining();
  return true;
}

// ---------------------------------------------------------------------
// Lease (CampaignMessageType::LeaseNegotiation): full bilateral
// request/grant/deny/activate/ack/release/releaseAck handshake on the
// NORMAL channel, carrying the actual requested/granted profile
// parameters explicitly (never a bare profile-id lookup) plus a fresh
// per-exchange nonce for authenticated binding. Frequencies are encoded
// as fixed-point (kHz-of-a-milli-MHz) integers rather than IEEE floats so
// the wire format is unambiguous across toolchains.
//
// Hello (CampaignMessageType::Hello) is the SEPARATE rendezvous message
// actually sent on the alternate (post-hop) frequency once both sides
// have Activated -- kept as its own message type since it necessarily
// travels over a different physical channel than the negotiation above.
// ---------------------------------------------------------------------
enum class CampaignLeaseSubtype : uint8_t {
  Request = 1,
  Grant = 2,
  Deny = 3,
  Activate = 4,
  Ack = 5,
  Release = 6,
  ReleaseAck = 7,
};

inline constexpr uint8_t kCampaignLeaseSubtypeMin = static_cast<uint8_t>(CampaignLeaseSubtype::Request);
inline constexpr uint8_t kCampaignLeaseSubtypeMax = static_cast<uint8_t>(CampaignLeaseSubtype::ReleaseAck);

struct CampaignLeasePayload {
  CampaignLeaseSubtype subtype = CampaignLeaseSubtype::Request;
  uint32_t leaseId = 0;
  uint32_t nonce = 0;
  uint32_t epochMs = 0;         // bounded watchdog duration for this phase
  uint32_t freqMhzMilli = 0;    // freqMhz * 1000, fixed-point
  uint16_t bandwidthKhzX10 = 0; // bandwidthKhz * 10, fixed-point
  uint8_t spreadingFactor = 0;
  uint8_t codingRate = 0;
  uint8_t reason = 0;           // CampaignRefusalReason, meaningful for Deny
};

inline constexpr size_t kCampaignLeasePayloadSize = 1 + 4 + 4 + 4 + 4 + 2 + 1 + 1 + 1; // 22

inline bool encodeCampaignLease(const CampaignLeasePayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kCampaignLeasePayloadSize) return false;
  if (static_cast<uint8_t>(p.subtype) < kCampaignLeaseSubtypeMin ||
      static_cast<uint8_t>(p.subtype) > kCampaignLeaseSubtypeMax) {
    return false;
  }
  protocol::OtaBoundedWriter w(dst, cap);
  bool ok = w.putU8(static_cast<uint8_t>(p.subtype)) && w.putU32(p.leaseId) && w.putU32(p.nonce) &&
            w.putU32(p.epochMs) && w.putU32(p.freqMhzMilli) && w.putU16(p.bandwidthKhzX10) &&
            w.putU8(p.spreadingFactor) && w.putU8(p.codingRate) && w.putU8(p.reason);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeCampaignLease(const uint8_t* src, size_t len, CampaignLeasePayload& out) {
  if (len != kCampaignLeasePayloadSize) return false;
  protocol::OtaBoundedReader r(src, len);
  uint8_t subtype = 0;
  bool ok = r.getU8(subtype) && r.getU32(out.leaseId) && r.getU32(out.nonce) && r.getU32(out.epochMs) &&
            r.getU32(out.freqMhzMilli) && r.getU16(out.bandwidthKhzX10) && r.getU8(out.spreadingFactor) &&
            r.getU8(out.codingRate) && r.getU8(out.reason);
  if (!ok || subtype < kCampaignLeaseSubtypeMin || subtype > kCampaignLeaseSubtypeMax) return false;
  out.subtype = static_cast<CampaignLeaseSubtype>(subtype);
  return true;
}

// Hello: sent ON the alternate frequency after both sides Activate, to
// confirm the rendezvous actually succeeded before any ordinary chunk
// traffic begins on the temporary profile.
struct CampaignHelloPayload {
  uint32_t leaseId = 0;
  uint32_t nonce = 0;
};

inline constexpr size_t kCampaignHelloPayloadSize = 4 + 4;

inline bool encodeCampaignHello(const CampaignHelloPayload& p, uint8_t* dst, size_t cap, size_t& outLen) {
  if (cap < kCampaignHelloPayloadSize) return false;
  protocol::OtaBoundedWriter w(dst, cap);
  bool ok = w.putU32(p.leaseId) && w.putU32(p.nonce);
  if (!ok) return false;
  outLen = w.size();
  return true;
}

inline bool decodeCampaignHello(const uint8_t* src, size_t len, CampaignHelloPayload& out) {
  if (len != kCampaignHelloPayloadSize) return false;
  protocol::OtaBoundedReader r(src, len);
  return r.getU32(out.leaseId) && r.getU32(out.nonce);
}

} // namespace campaign
} // namespace ota
} // namespace meshcore
