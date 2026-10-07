#include <gtest/gtest.h>

#include <cstring>

#include "ota/protocol/OtaWireTypes.h"
#include "ota/protocol/OtaByteStream.h"
#include "ota/protocol/OtaEnvelope.h"
#include "ota/protocol/OtaDescriptor.h"
#include "ota/protocol/OtaMessages.h"

using namespace meshcore::ota::protocol;

namespace {

OtaEnvelopeHeader makeHeader(OtaMessageType type, uint32_t campaign = 1, uint32_t session = 2, uint16_t attempt = 3) {
  OtaEnvelopeHeader hdr;
  hdr.type = type;
  hdr.campaignId = campaign;
  hdr.sessionId = session;
  hdr.attemptId = attempt;
  hdr.flags = 0;
  return hdr;
}

} // namespace

// ---------------------------------------------------------------------
// Envelope codec
// ---------------------------------------------------------------------

TEST(OtaEnvelope, RoundTripsWithPayload) {
  const uint8_t payload[3] = {0xAA, 0xBB, 0xCC};
  uint8_t frame[kOtaMaxFrameSize];
  size_t outLen = 0;
  auto hdr = makeHeader(OtaMessageType::Chunk);

  ASSERT_EQ(OtaCodecResult::Ok, encodeOtaEnvelope(hdr, payload, sizeof(payload), frame, sizeof(frame), outLen));
  EXPECT_EQ(kOtaHeaderSize + sizeof(payload), outLen);

  OtaEnvelopeHeader decoded;
  const uint8_t* outPayload = nullptr;
  size_t outPayloadLen = 0;
  ASSERT_EQ(OtaCodecResult::Ok, decodeOtaEnvelope(frame, outLen, decoded, outPayload, outPayloadLen));
  EXPECT_EQ(kOtaNamespaceId, decoded.ns);
  EXPECT_EQ(kOtaProtocolVersion, decoded.version);
  EXPECT_EQ(OtaMessageType::Chunk, decoded.type);
  EXPECT_EQ(1u, decoded.campaignId);
  EXPECT_EQ(2u, decoded.sessionId);
  EXPECT_EQ(3u, decoded.attemptId);
  ASSERT_EQ(sizeof(payload), outPayloadLen);
  EXPECT_EQ(0, std::memcmp(payload, outPayload, sizeof(payload)));
}

TEST(OtaEnvelope, RoundTripsWithZeroLengthPayload) {
  uint8_t frame[kOtaMaxFrameSize];
  size_t outLen = 0;
  auto hdr = makeHeader(OtaMessageType::Abort);

  ASSERT_EQ(OtaCodecResult::Ok, encodeOtaEnvelope(hdr, nullptr, 0, frame, sizeof(frame), outLen));
  EXPECT_EQ(kOtaHeaderSize, outLen);

  OtaEnvelopeHeader decoded;
  const uint8_t* outPayload = nullptr;
  size_t outPayloadLen = 123;
  ASSERT_EQ(OtaCodecResult::Ok, decodeOtaEnvelope(frame, outLen, decoded, outPayload, outPayloadLen));
  EXPECT_EQ(0u, outPayloadLen);
}

TEST(OtaEnvelope, RejectsTruncatedHeader) {
  uint8_t frame[kOtaHeaderSize - 1] = {0};
  OtaEnvelopeHeader decoded;
  const uint8_t* outPayload = nullptr;
  size_t outPayloadLen = 0;
  EXPECT_EQ(OtaCodecResult::TooShort, decodeOtaEnvelope(frame, sizeof(frame), decoded, outPayload, outPayloadLen));
}

TEST(OtaEnvelope, RejectsTruncatedPayload) {
  const uint8_t payload[5] = {1, 2, 3, 4, 5};
  uint8_t frame[kOtaMaxFrameSize];
  size_t outLen = 0;
  auto hdr = makeHeader(OtaMessageType::Chunk);
  ASSERT_EQ(OtaCodecResult::Ok, encodeOtaEnvelope(hdr, payload, sizeof(payload), frame, sizeof(frame), outLen));

  OtaEnvelopeHeader decoded;
  const uint8_t* outPayload = nullptr;
  size_t outPayloadLen = 0;
  // Truncate the last payload byte off the wire.
  EXPECT_EQ(OtaCodecResult::PayloadLengthMismatch,
            decodeOtaEnvelope(frame, outLen - 1, decoded, outPayload, outPayloadLen));
}

TEST(OtaEnvelope, RejectsOversizedFrameWithTrailingGarbage) {
  const uint8_t payload[5] = {1, 2, 3, 4, 5};
  uint8_t frame[kOtaMaxFrameSize];
  size_t outLen = 0;
  auto hdr = makeHeader(OtaMessageType::Chunk);
  ASSERT_EQ(OtaCodecResult::Ok, encodeOtaEnvelope(hdr, payload, sizeof(payload), frame, sizeof(frame), outLen));

  frame[outLen] = 0xFF; // trailing garbage byte, not accounted for by payloadLength
  OtaEnvelopeHeader decoded;
  const uint8_t* outPayload = nullptr;
  size_t outPayloadLen = 0;
  EXPECT_EQ(OtaCodecResult::PayloadLengthMismatch,
            decodeOtaEnvelope(frame, outLen + 1, decoded, outPayload, outPayloadLen));
}

TEST(OtaEnvelope, RejectsFrameLargerThanMaxFrameSize) {
  uint8_t frame[kOtaMaxFrameSize + 1] = {0};
  OtaEnvelopeHeader decoded;
  const uint8_t* outPayload = nullptr;
  size_t outPayloadLen = 0;
  EXPECT_EQ(OtaCodecResult::TooLong, decodeOtaEnvelope(frame, sizeof(frame), decoded, outPayload, outPayloadLen));
}

TEST(OtaEnvelope, RejectsWrongNamespace) {
  uint8_t frame[kOtaMaxFrameSize];
  size_t outLen = 0;
  auto hdr = makeHeader(OtaMessageType::Abort);
  ASSERT_EQ(OtaCodecResult::Ok, encodeOtaEnvelope(hdr, nullptr, 0, frame, sizeof(frame), outLen));
  frame[0] = 0x00;
  frame[1] = 0x00;

  OtaEnvelopeHeader decoded;
  const uint8_t* outPayload = nullptr;
  size_t outPayloadLen = 0;
  EXPECT_EQ(OtaCodecResult::BadNamespace, decodeOtaEnvelope(frame, outLen, decoded, outPayload, outPayloadLen));
}

TEST(OtaEnvelope, RejectsWrongVersion) {
  uint8_t frame[kOtaMaxFrameSize];
  size_t outLen = 0;
  auto hdr = makeHeader(OtaMessageType::Abort);
  ASSERT_EQ(OtaCodecResult::Ok, encodeOtaEnvelope(hdr, nullptr, 0, frame, sizeof(frame), outLen));
  frame[2] = kOtaProtocolVersion + 1;

  OtaEnvelopeHeader decoded;
  const uint8_t* outPayload = nullptr;
  size_t outPayloadLen = 0;
  EXPECT_EQ(OtaCodecResult::BadVersion, decodeOtaEnvelope(frame, outLen, decoded, outPayload, outPayloadLen));
}

TEST(OtaEnvelope, RejectsUnknownMessageType) {
  uint8_t frame[kOtaMaxFrameSize];
  size_t outLen = 0;
  auto hdr = makeHeader(OtaMessageType::Abort);
  ASSERT_EQ(OtaCodecResult::Ok, encodeOtaEnvelope(hdr, nullptr, 0, frame, sizeof(frame), outLen));
  frame[3] = 0; // message type 0 is not assigned
  OtaEnvelopeHeader decoded;
  const uint8_t* outPayload = nullptr;
  size_t outPayloadLen = 0;
  EXPECT_EQ(OtaCodecResult::BadMessageType, decodeOtaEnvelope(frame, outLen, decoded, outPayload, outPayloadLen));

  frame[3] = kOtaMessageTypeMax + 1; // one past the last assigned type
  EXPECT_EQ(OtaCodecResult::BadMessageType, decodeOtaEnvelope(frame, outLen, decoded, outPayload, outPayloadLen));
}

TEST(OtaEnvelope, RejectsUnknownMessageTypeOnEncode) {
  uint8_t frame[kOtaMaxFrameSize];
  size_t outLen = 0;
  OtaEnvelopeHeader hdr;
  hdr.type = static_cast<OtaMessageType>(0); // unassigned
  EXPECT_EQ(OtaCodecResult::BadMessageType, encodeOtaEnvelope(hdr, nullptr, 0, frame, sizeof(frame), outLen));
}

TEST(OtaEnvelope, RejectsPayloadLargerThanMax) {
  uint8_t oversized[kOtaMaxPayloadSize + 1] = {0};
  uint8_t frame[kOtaMaxFrameSize + 64];
  size_t outLen = 0;
  auto hdr = makeHeader(OtaMessageType::Chunk);
  EXPECT_EQ(OtaCodecResult::PayloadTooLarge,
            encodeOtaEnvelope(hdr, oversized, sizeof(oversized), frame, sizeof(frame), outLen));
}

TEST(OtaEnvelope, RejectsUndersizedDestinationBuffer) {
  const uint8_t payload[10] = {0};
  uint8_t frame[kOtaHeaderSize]; // too small to hold header + payload
  size_t outLen = 0;
  auto hdr = makeHeader(OtaMessageType::Chunk);
  EXPECT_EQ(OtaCodecResult::TooShort, encodeOtaEnvelope(hdr, payload, sizeof(payload), frame, sizeof(frame), outLen));
}

TEST(OtaEnvelope, MaxPayloadSizeFitsWithinMaxFrameSize) {
  EXPECT_EQ(kOtaMaxFrameSize, kOtaHeaderSize + kOtaMaxPayloadSize);
}

// ---------------------------------------------------------------------
// Descriptor canonical codec
// ---------------------------------------------------------------------

TEST(OtaDescriptor, CanonicalRoundTrip) {
  OtaDescriptor d;
  d.boardFamily = 0x1234;
  d.boardVariant = 0x5678;
  d.role = 7;
  d.appAddress = 0x08000000;
  d.exactSizeBytes = 811008;
  for (int i = 0; i < 32; ++i) d.sha256[i] = static_cast<uint8_t>(i);
  d.securityCounter = 42;
  d.minBootloaderCapabilities = 0x0000000F;
  d.formatId = 1;
  d.keyId = 2;
  d.algorithmId = 3;

  uint8_t buf[kOtaDescriptorCanonicalSize];
  size_t outLen = 0;
  ASSERT_EQ(OtaDescriptorCodecResult::Ok, encodeOtaDescriptorCanonical(d, buf, sizeof(buf), outLen));
  EXPECT_EQ(kOtaDescriptorCanonicalSize, outLen);

  OtaDescriptor decoded;
  ASSERT_EQ(OtaDescriptorCodecResult::Ok, decodeOtaDescriptorCanonical(buf, outLen, decoded));
  EXPECT_EQ(d.boardFamily, decoded.boardFamily);
  EXPECT_EQ(d.boardVariant, decoded.boardVariant);
  EXPECT_EQ(d.role, decoded.role);
  EXPECT_EQ(d.appAddress, decoded.appAddress);
  EXPECT_EQ(d.exactSizeBytes, decoded.exactSizeBytes);
  EXPECT_EQ(0, std::memcmp(d.sha256, decoded.sha256, 32));
  EXPECT_EQ(d.securityCounter, decoded.securityCounter);
  EXPECT_EQ(d.minBootloaderCapabilities, decoded.minBootloaderCapabilities);
  EXPECT_EQ(d.formatId, decoded.formatId);
  EXPECT_EQ(d.keyId, decoded.keyId);
  EXPECT_EQ(d.algorithmId, decoded.algorithmId);
}

TEST(OtaDescriptor, RejectsTruncatedCanonicalBytes) {
  uint8_t buf[kOtaDescriptorCanonicalSize - 1] = {0};
  OtaDescriptor decoded;
  EXPECT_EQ(OtaDescriptorCodecResult::TooShort, decodeOtaDescriptorCanonical(buf, sizeof(buf), decoded));
}

TEST(OtaDescriptor, RejectsOversizedCanonicalBytes) {
  uint8_t buf[kOtaDescriptorCanonicalSize + 1] = {0};
  OtaDescriptor decoded;
  EXPECT_EQ(OtaDescriptorCodecResult::TooLong, decodeOtaDescriptorCanonical(buf, sizeof(buf), decoded));
}

TEST(OtaDescriptor, RejectsUndersizedEncodeDestination) {
  OtaDescriptor d;
  uint8_t buf[kOtaDescriptorCanonicalSize - 1];
  size_t outLen = 0;
  EXPECT_EQ(OtaDescriptorCodecResult::TooShort, encodeOtaDescriptorCanonical(d, buf, sizeof(buf), outLen));
}

// ---------------------------------------------------------------------
// Descriptor fragment reassembly
// ---------------------------------------------------------------------

TEST(OtaDescriptorReassembler, SingleFragmentCompletes) {
  OtaDescriptorReassembler r;
  uint8_t blob[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  EXPECT_TRUE(r.addFragment(0, 1, 10, 10, blob, 10));
  ASSERT_TRUE(r.isComplete());
  EXPECT_EQ(10u, r.blobLength());
  EXPECT_EQ(0, std::memcmp(blob, r.blob(), 10));
}

TEST(OtaDescriptorReassembler, MultiFragmentInOrder) {
  OtaDescriptorReassembler r;
  uint8_t f0[4] = {1, 2, 3, 4};
  uint8_t f1[4] = {5, 6, 7, 8};
  uint8_t f2[2] = {9, 10};
  EXPECT_FALSE(r.isComplete());
  EXPECT_TRUE(r.addFragment(0, 3, 10, 4, f0, 4));
  EXPECT_FALSE(r.isComplete());
  EXPECT_TRUE(r.addFragment(1, 3, 10, 4, f1, 4));
  EXPECT_FALSE(r.isComplete());
  EXPECT_TRUE(r.addFragment(2, 3, 10, 4, f2, 2));
  ASSERT_TRUE(r.isComplete());
  EXPECT_EQ(10u, r.blobLength());
  uint8_t expect[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  EXPECT_EQ(0, std::memcmp(expect, r.blob(), 10));
}

TEST(OtaDescriptorReassembler, MultiFragmentOutOfOrderAndDuplicate) {
  OtaDescriptorReassembler r;
  uint8_t f0[4] = {1, 2, 3, 4};
  uint8_t f1[4] = {5, 6, 7, 8};
  uint8_t f2[2] = {9, 10};
  EXPECT_TRUE(r.addFragment(2, 3, 10, 4, f2, 2));
  EXPECT_TRUE(r.addFragment(0, 3, 10, 4, f0, 4));
  EXPECT_FALSE(r.isComplete());
  EXPECT_TRUE(r.addFragment(0, 3, 10, 4, f0, 4)); // exact duplicate resend accepted
  EXPECT_TRUE(r.addFragment(1, 3, 10, 4, f1, 4));
  ASSERT_TRUE(r.isComplete());
  uint8_t expect[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  EXPECT_EQ(0, std::memcmp(expect, r.blob(), 10));
}

TEST(OtaDescriptorReassembler, RejectsZeroFragCount) {
  OtaDescriptorReassembler r;
  uint8_t data[1] = {0};
  EXPECT_FALSE(r.addFragment(0, 0, 1, 1, data, 1));
}

TEST(OtaDescriptorReassembler, RejectsFragCountAboveMax) {
  OtaDescriptorReassembler r;
  uint8_t data[1] = {0};
  EXPECT_FALSE(r.addFragment(0, OtaDescriptorReassembler::kMaxFragments + 1, 1, 1, data, 1));
}

TEST(OtaDescriptorReassembler, RejectsOutOfRangeFragIndex) {
  OtaDescriptorReassembler r;
  uint8_t data[1] = {0};
  EXPECT_FALSE(r.addFragment(3, 3, 3, 1, data, 1));
}

TEST(OtaDescriptorReassembler, RejectsTotalLengthAboveMaxBlobSize) {
  OtaDescriptorReassembler r;
  uint8_t data[1] = {0};
  EXPECT_FALSE(r.addFragment(0, 1, OtaDescriptorReassembler::kMaxBlobSize + 1, OtaDescriptorReassembler::kMaxBlobSize + 1, data, 1));
}

TEST(OtaDescriptorReassembler, RejectsWrongLengthForFragment) {
  OtaDescriptorReassembler r;
  uint8_t data[4] = {1, 2, 3, 4};
  // fragIndex 0 of 3, fragmentPayloadSize 4 expects exactly 4 bytes.
  EXPECT_FALSE(r.addFragment(0, 3, 10, 4, data, 3));
  // Last fragment expects exactly (totalLength - offset) bytes = 2, not 4.
  EXPECT_FALSE(r.addFragment(2, 3, 10, 4, data, 4));
}

TEST(OtaDescriptorReassembler, RejectsConflictingGeometryMidReassembly) {
  OtaDescriptorReassembler r;
  uint8_t f0[4] = {1, 2, 3, 4};
  EXPECT_TRUE(r.addFragment(0, 3, 10, 4, f0, 4));
  // Same fragIndex but a different totalLength/fragCount than already
  // established: rejected rather than silently overwriting geometry.
  EXPECT_FALSE(r.addFragment(0, 4, 12, 3, f0, 3));
}

TEST(OtaDescriptorReassembler, ResetAllowsFreshGeometry) {
  OtaDescriptorReassembler r;
  uint8_t f0[4] = {1, 2, 3, 4};
  EXPECT_TRUE(r.addFragment(0, 3, 10, 4, f0, 4));
  r.reset();
  EXPECT_FALSE(r.isComplete());
  uint8_t g0[5] = {9, 9, 9, 9, 9};
  EXPECT_TRUE(r.addFragment(0, 1, 5, 5, g0, 5));
  ASSERT_TRUE(r.isComplete());
  EXPECT_EQ(5u, r.blobLength());
}

// ---------------------------------------------------------------------
// Per-message-type codec round trips + malformed input
// ---------------------------------------------------------------------

TEST(OtaMessages, AuthorizationRoundTrip) {
  OtaAuthorizationPayload p;
  p.granted = 1;
  p.leaseId = 99;
  p.expiresAtMs = 123456;
  p.maxInFlightChunks = 8;
  uint8_t buf[kOtaAuthorizationPayloadSize];
  size_t outLen = 0;
  ASSERT_TRUE(encodeOtaAuthorization(p, buf, sizeof(buf), outLen));
  OtaAuthorizationPayload decoded;
  ASSERT_TRUE(decodeOtaAuthorization(buf, outLen, decoded));
  EXPECT_EQ(p.granted, decoded.granted);
  EXPECT_EQ(p.leaseId, decoded.leaseId);
  EXPECT_EQ(p.expiresAtMs, decoded.expiresAtMs);
  EXPECT_EQ(p.maxInFlightChunks, decoded.maxInFlightChunks);
}

TEST(OtaMessages, AuthorizationRejectsWrongLength) {
  OtaAuthorizationPayload decoded;
  uint8_t buf[kOtaAuthorizationPayloadSize - 1] = {0};
  EXPECT_FALSE(decodeOtaAuthorization(buf, sizeof(buf), decoded));
  uint8_t big[kOtaAuthorizationPayloadSize + 1] = {0};
  EXPECT_FALSE(decodeOtaAuthorization(big, sizeof(big), decoded));
}

TEST(OtaMessages, ChunkRoundTrip) {
  OtaChunkHeader hdr;
  hdr.chunkIndex = 5069 - 1;
  hdr.dataLength = 128;
  uint8_t data[128];
  for (int i = 0; i < 128; ++i) data[i] = static_cast<uint8_t>(i);
  uint8_t buf[kOtaChunkHeaderSize + 128];
  size_t outLen = 0;
  ASSERT_TRUE(encodeOtaChunk(hdr, data, sizeof(data), buf, sizeof(buf), outLen));

  OtaChunkHeader decodedHdr;
  const uint8_t* outData = nullptr;
  size_t outDataLen = 0;
  ASSERT_TRUE(decodeOtaChunk(buf, outLen, decodedHdr, outData, outDataLen));
  EXPECT_EQ(hdr.chunkIndex, decodedHdr.chunkIndex);
  EXPECT_EQ(hdr.dataLength, decodedHdr.dataLength);
  ASSERT_EQ(128u, outDataLen);
  EXPECT_EQ(0, std::memcmp(data, outData, 128));
}

TEST(OtaMessages, ChunkRejectsDataLengthMismatchOnEncode) {
  OtaChunkHeader hdr;
  hdr.chunkIndex = 0;
  hdr.dataLength = 10; // does not match actual dataLen passed below
  uint8_t data[5] = {0};
  uint8_t buf[64];
  size_t outLen = 0;
  EXPECT_FALSE(encodeOtaChunk(hdr, data, sizeof(data), buf, sizeof(buf), outLen));
}

TEST(OtaMessages, ChunkRejectsTruncatedTrailer) {
  OtaChunkHeader hdr;
  hdr.chunkIndex = 0;
  hdr.dataLength = 10;
  uint8_t data[10] = {0};
  uint8_t buf[64];
  size_t outLen = 0;
  ASSERT_TRUE(encodeOtaChunk(hdr, data, sizeof(data), buf, sizeof(buf), outLen));

  OtaChunkHeader decodedHdr;
  const uint8_t* outData = nullptr;
  size_t outDataLen = 0;
  EXPECT_FALSE(decodeOtaChunk(buf, outLen - 1, decodedHdr, outData, outDataLen));
}

TEST(OtaMessages, ReceiptRoundTrip) {
  OtaReceiptPayload p;
  p.status = OtaReceiptStatus::TransferComplete;
  p.chunkIndex = 10;
  p.bytesReceived = 811008;
  p.lastGoodOffset = 810880;
  uint8_t buf[kOtaReceiptPayloadSize];
  size_t outLen = 0;
  ASSERT_TRUE(encodeOtaReceipt(p, buf, sizeof(buf), outLen));
  OtaReceiptPayload decoded;
  ASSERT_TRUE(decodeOtaReceipt(buf, outLen, decoded));
  EXPECT_EQ(p.status, decoded.status);
  EXPECT_EQ(p.chunkIndex, decoded.chunkIndex);
  EXPECT_EQ(p.bytesReceived, decoded.bytesReceived);
  EXPECT_EQ(p.lastGoodOffset, decoded.lastGoodOffset);
}

TEST(OtaMessages, ReceiptRejectsInvalidStatusEnum) {
  uint8_t buf[kOtaReceiptPayloadSize] = {0};
  buf[0] = 99; // not a valid OtaReceiptStatus
  OtaReceiptPayload decoded;
  EXPECT_FALSE(decodeOtaReceipt(buf, sizeof(buf), decoded));
}

TEST(OtaMessages, AbortRoundTrip) {
  OtaAbortPayload p;
  p.reasonCode = 3;
  p.atChunkIndex = 42;
  uint8_t buf[kOtaAbortPayloadSize];
  size_t outLen = 0;
  ASSERT_TRUE(encodeOtaAbort(p, buf, sizeof(buf), outLen));
  OtaAbortPayload decoded;
  ASSERT_TRUE(decodeOtaAbort(buf, outLen, decoded));
  EXPECT_EQ(p.reasonCode, decoded.reasonCode);
  EXPECT_EQ(p.atChunkIndex, decoded.atChunkIndex);
}

TEST(OtaMessages, LeaseNegotiationRoundTrip) {
  OtaLeaseNegotiationPayload p;
  p.subtype = OtaLeaseSubtype::Grant;
  p.leaseId = 7;
  p.durationMs = 5000;
  p.radioProfileId = 2;
  uint8_t buf[kOtaLeaseNegotiationPayloadSize];
  size_t outLen = 0;
  ASSERT_TRUE(encodeOtaLeaseNegotiation(p, buf, sizeof(buf), outLen));
  OtaLeaseNegotiationPayload decoded;
  ASSERT_TRUE(decodeOtaLeaseNegotiation(buf, outLen, decoded));
  EXPECT_EQ(p.subtype, decoded.subtype);
  EXPECT_EQ(p.leaseId, decoded.leaseId);
  EXPECT_EQ(p.durationMs, decoded.durationMs);
  EXPECT_EQ(p.radioProfileId, decoded.radioProfileId);
}

TEST(OtaMessages, LeaseNegotiationRejectsInvalidSubtype) {
  uint8_t buf[kOtaLeaseNegotiationPayloadSize] = {0};
  buf[0] = 0; // subtype 0 is not assigned (Request starts at 1)
  OtaLeaseNegotiationPayload decoded;
  EXPECT_FALSE(decodeOtaLeaseNegotiation(buf, sizeof(buf), decoded));
}

TEST(OtaMessages, AnnouncementRoundTrip) {
  OtaAnnouncementPayload p;
  p.campaignId = 100;
  p.descriptorTotalLength = 59;
  p.priority = 5;
  p.expiresAtMs = 999999;
  uint8_t buf[kOtaAnnouncementPayloadSize];
  size_t outLen = 0;
  ASSERT_TRUE(encodeOtaAnnouncement(p, buf, sizeof(buf), outLen));
  OtaAnnouncementPayload decoded;
  ASSERT_TRUE(decodeOtaAnnouncement(buf, outLen, decoded));
  EXPECT_EQ(p.campaignId, decoded.campaignId);
  EXPECT_EQ(p.descriptorTotalLength, decoded.descriptorTotalLength);
  EXPECT_EQ(p.priority, decoded.priority);
  EXPECT_EQ(p.expiresAtMs, decoded.expiresAtMs);
}

TEST(OtaMessages, CensusRoundTrip) {
  OtaCensusPayload p;
  p.campaignId = 100;
  p.haveDescriptor = 1;
  p.bytesReceived = 500;
  p.missingRangeCount = 3;
  uint8_t buf[kOtaCensusPayloadSize];
  size_t outLen = 0;
  ASSERT_TRUE(encodeOtaCensus(p, buf, sizeof(buf), outLen));
  OtaCensusPayload decoded;
  ASSERT_TRUE(decodeOtaCensus(buf, outLen, decoded));
  EXPECT_EQ(p.campaignId, decoded.campaignId);
  EXPECT_EQ(p.haveDescriptor, decoded.haveDescriptor);
  EXPECT_EQ(p.bytesReceived, decoded.bytesReceived);
  EXPECT_EQ(p.missingRangeCount, decoded.missingRangeCount);
}

TEST(OtaMessages, CohortResolutionRoundTrip) {
  OtaCohortResolutionPayload p;
  p.campaignId = 1;
  p.cohortId = 2;
  p.cohortSize = 16;
  p.cohortIndex = 4;
  uint8_t buf[kOtaCohortResolutionPayloadSize];
  size_t outLen = 0;
  ASSERT_TRUE(encodeOtaCohortResolution(p, buf, sizeof(buf), outLen));
  OtaCohortResolutionPayload decoded;
  ASSERT_TRUE(decodeOtaCohortResolution(buf, outLen, decoded));
  EXPECT_EQ(p.campaignId, decoded.campaignId);
  EXPECT_EQ(p.cohortId, decoded.cohortId);
  EXPECT_EQ(p.cohortSize, decoded.cohortSize);
  EXPECT_EQ(p.cohortIndex, decoded.cohortIndex);
}

TEST(OtaMessages, MissingRangeRoundTrip) {
  OtaMissingRangePayload p;
  p.campaignId = 1;
  p.startChunkIndex = 100;
  p.chunkCount = 25;
  uint8_t buf[kOtaMissingRangePayloadSize];
  size_t outLen = 0;
  ASSERT_TRUE(encodeOtaMissingRange(p, buf, sizeof(buf), outLen));
  OtaMissingRangePayload decoded;
  ASSERT_TRUE(decodeOtaMissingRange(buf, outLen, decoded));
  EXPECT_EQ(p.campaignId, decoded.campaignId);
  EXPECT_EQ(p.startChunkIndex, decoded.startChunkIndex);
  EXPECT_EQ(p.chunkCount, decoded.chunkCount);
}

TEST(OtaMessages, CommitRoundTrip) {
  OtaCommitPayload p;
  p.campaignId = 1;
  p.verifiedOk = 1;
  p.finalSecurityCounter = 43;
  uint8_t buf[kOtaCommitPayloadSize];
  size_t outLen = 0;
  ASSERT_TRUE(encodeOtaCommit(p, buf, sizeof(buf), outLen));
  OtaCommitPayload decoded;
  ASSERT_TRUE(decodeOtaCommit(buf, outLen, decoded));
  EXPECT_EQ(p.campaignId, decoded.campaignId);
  EXPECT_EQ(p.verifiedOk, decoded.verifiedOk);
  EXPECT_EQ(p.finalSecurityCounter, decoded.finalSecurityCounter);
}

// ---------------------------------------------------------------------
// Bounded byte-stream primitive: exhaustive truncation/overflow behavior
// ---------------------------------------------------------------------

TEST(OtaBoundedWriter, FailsWithoutMutatingOnOverflow) {
  uint8_t buf[1] = {0xAB};
  OtaBoundedWriter w(buf, sizeof(buf));
  EXPECT_FALSE(w.putU16(1234));
  EXPECT_EQ(0u, w.size());
  EXPECT_EQ(0xAB, buf[0]); // untouched
}

TEST(OtaBoundedReader, FailsWithoutAdvancingOnUnderflow) {
  uint8_t buf[1] = {0x01};
  OtaBoundedReader r(buf, sizeof(buf));
  uint16_t v = 0;
  EXPECT_FALSE(r.getU16(v));
  EXPECT_EQ(0u, r.position());
}

TEST(OtaWireTypes, KnownMessageTypeBoundsAreExact) {
  EXPECT_FALSE(isKnownOtaMessageType(0));
  EXPECT_TRUE(isKnownOtaMessageType(kOtaMessageTypeMin));
  EXPECT_TRUE(isKnownOtaMessageType(kOtaMessageTypeMax));
  EXPECT_FALSE(isKnownOtaMessageType(kOtaMessageTypeMax + 1));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
