#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "helpers/ota/OtaUsbControlFramer.h"

using meshcore::ota::helpers::OtaUsbControlFramer;

namespace {

std::vector<OtaUsbControlFramer::FeedResult> feedAll(OtaUsbControlFramer& f, const std::vector<uint8_t>& bytes,
                                                      uint32_t nowMs = 0) {
  std::vector<OtaUsbControlFramer::FeedResult> results;
  for (uint8_t b : bytes) results.push_back(f.feedByte(b, nowMs));
  return results;
}

std::vector<uint8_t> lenPrefixed(uint8_t dir, uint16_t len, const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> out = {dir, static_cast<uint8_t>(len & 0xFF), static_cast<uint8_t>((len >> 8) & 0xFF)};
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

TEST(OtaUsbControlFramer, WellFormedFrameIsAssembledByteByByte) {
  OtaUsbControlFramer f('<');
  std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04};
  auto wire = lenPrefixed('<', 4, payload);
  auto results = feedAll(f, wire);
  for (size_t i = 0; i + 1 < results.size(); i++) EXPECT_EQ(OtaUsbControlFramer::FeedResult::Idle, results[i]);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::FrameReady, results.back());
  ASSERT_EQ(4u, f.frameLen());
  EXPECT_EQ(0, std::memcmp(f.frameData(), payload.data(), 4));
}

TEST(OtaUsbControlFramer, StrayBytesBeforeStartAreIgnoredNeverMisparsedAsHeader) {
  OtaUsbControlFramer f('<');
  std::vector<uint8_t> payload = {0xAA};
  auto wire = lenPrefixed('<', 1, payload);
  std::vector<uint8_t> noisy = {0x00, 0xFF, '>', 0x7F};
  noisy.insert(noisy.end(), wire.begin(), wire.end());
  auto results = feedAll(f, noisy);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::FrameReady, results.back());
  ASSERT_EQ(1u, f.frameLen());
  EXPECT_EQ(0xAAu, f.frameData()[0]);
}

TEST(OtaUsbControlFramer, ZeroDeclaredLengthIsDiscardedNeverDispatchedAsEmptyFrame) {
  OtaUsbControlFramer f('<');
  auto wire = lenPrefixed('<', 0, {});
  auto results = feedAll(f, wire);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::Discarded, results.back());
}

TEST(OtaUsbControlFramer, OversizedDeclaredLengthIsDiscardedWithoutConsumingAnyPayloadBytes) {
  OtaUsbControlFramer f('<');
  // Declare a length larger than kMaxPayload (168); the parser must
  // reject at the header and resync rather than try to read 9000 bytes.
  std::vector<uint8_t> wire = {'<', 0x28, 0x23}; // 0x2328 = 9000
  auto results = feedAll(f, wire);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::Discarded, results.back());

  // A genuine well-formed frame fed right afterwards must parse cleanly
  // -- proving the parser actually resynced rather than entering a
  // wedged state.
  auto nextWire = lenPrefixed('<', 2, {0x11, 0x22});
  auto results2 = feedAll(f, nextWire);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::FrameReady, results2.back());
  ASSERT_EQ(2u, f.frameLen());
  EXPECT_EQ(0x11, f.frameData()[0]);
  EXPECT_EQ(0x22, f.frameData()[1]);
}

TEST(OtaUsbControlFramer, MaxPayloadExactlyAtCapacityParsesCleanly) {
  OtaUsbControlFramer f('<');
  std::vector<uint8_t> payload(OtaUsbControlFramer::kMaxPayload, 0x5A);
  auto wire = lenPrefixed('<', static_cast<uint16_t>(payload.size()), payload);
  auto results = feedAll(f, wire);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::FrameReady, results.back());
  EXPECT_EQ(OtaUsbControlFramer::kMaxPayload, f.frameLen());
}

TEST(OtaUsbControlFramer, OneByteOverCapacityIsDiscardedNotTruncated) {
  OtaUsbControlFramer f('<');
  std::vector<uint8_t> payload(OtaUsbControlFramer::kMaxPayload + 1, 0x5A);
  auto wire = lenPrefixed('<', static_cast<uint16_t>(payload.size()), payload);
  auto results = feedAll(f, wire);
  // Rejected at the header (byte 3, once the 16-bit length is known) --
  // never gets to FrameReady even though well-formed-looking payload
  // bytes follow.
  bool sawDiscarded = false;
  for (auto r : results)
    if (r == OtaUsbControlFramer::FeedResult::Discarded) sawDiscarded = true;
  EXPECT_TRUE(sawDiscarded);
  for (auto r : results) EXPECT_NE(OtaUsbControlFramer::FeedResult::FrameReady, r);
}

TEST(OtaUsbControlFramer, StalledPartialFrameIsDiscardedByTickAfterTimeoutNotBefore) {
  OtaUsbControlFramer f('<', /*frameTimeoutMs=*/100);
  // Start a frame declaring 4 bytes, but only ever deliver 1.
  f.feedByte('<', 0);
  f.feedByte(4, 0);
  f.feedByte(0, 0);
  f.feedByte(0xAA, 0);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::Idle, f.tick(50)); // not yet timed out
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::TimedOut, f.tick(150));

  // Parser must be usable again afterwards (not permanently wedged).
  auto wire = lenPrefixed('<', 2, {0x01, 0x02});
  auto results = feedAll(f, wire, 150);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::FrameReady, results.back());
}

TEST(OtaUsbControlFramer, TickIsNoOpWhileIdleAtWaitStart) {
  OtaUsbControlFramer f('<', 100);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::Idle, f.tick(1000000));
}

TEST(OtaUsbControlFramer, ResetDiscardsAnyInFlightFrameImmediately) {
  OtaUsbControlFramer f('<');
  f.feedByte('<', 0);
  f.feedByte(4, 0);
  f.feedByte(0, 0);
  f.feedByte(0xAA, 0);
  f.reset();
  auto wire = lenPrefixed('<', 2, {0x01, 0x02});
  auto results = feedAll(f, wire);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::FrameReady, results.back());
  ASSERT_EQ(2u, f.frameLen());
  EXPECT_EQ(0x01, f.frameData()[0]);
}

TEST(OtaUsbControlFramer, BackToBackFramesParseIndependentlyWithoutCrossContamination) {
  OtaUsbControlFramer f('<');
  auto wireA = lenPrefixed('<', 2, {0x11, 0x22});
  auto wireB = lenPrefixed('<', 3, {0xAA, 0xBB, 0xCC});
  auto resultsA = feedAll(f, wireA);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::FrameReady, resultsA.back());
  ASSERT_EQ(2u, f.frameLen());
  auto resultsB = feedAll(f, wireB);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::FrameReady, resultsB.back());
  ASSERT_EQ(3u, f.frameLen());
  EXPECT_EQ(0xAA, f.frameData()[0]);
  EXPECT_EQ(0xBB, f.frameData()[1]);
  EXPECT_EQ(0xCC, f.frameData()[2]);
}

TEST(OtaUsbControlFramer, BuildFrameProducesExactDirectionLengthPayloadBytes) {
  uint8_t payload[4] = {0x01, 0x02, 0x03, 0x04};
  uint8_t out[16] = {};
  size_t n = OtaUsbControlFramer::buildFrame('>', payload, sizeof(payload), out, sizeof(out));
  ASSERT_EQ(7u, n);
  EXPECT_EQ('>', out[0]);
  EXPECT_EQ(0x04, out[1]);
  EXPECT_EQ(0x00, out[2]);
  EXPECT_EQ(0, std::memcmp(out + 3, payload, 4));
}

TEST(OtaUsbControlFramer, BuildFrameRefusesZeroLength) {
  uint8_t out[16];
  EXPECT_EQ(0u, OtaUsbControlFramer::buildFrame('>', nullptr, 0, out, sizeof(out)));
}

TEST(OtaUsbControlFramer, BuildFrameRefusesOversizedPayload) {
  std::vector<uint8_t> payload(OtaUsbControlFramer::kMaxPayload + 1, 0);
  uint8_t out[8 + OtaUsbControlFramer::kMaxPayload] = {};
  EXPECT_EQ(0u, OtaUsbControlFramer::buildFrame('>', payload.data(), payload.size(), out, sizeof(out)));
}

TEST(OtaUsbControlFramer, BuildFrameRefusesWhenDestinationCapacityTooSmall) {
  uint8_t payload[4] = {1, 2, 3, 4};
  uint8_t out[6]; // needs 7 (3 header + 4 payload)
  EXPECT_EQ(0u, OtaUsbControlFramer::buildFrame('>', payload, sizeof(payload), out, sizeof(out)));
}

TEST(OtaUsbControlFramer, RoundTripBuildThenParseRecoversOriginalPayload) {
  uint8_t payload[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01};
  uint8_t wire[16] = {};
  size_t wireLen = OtaUsbControlFramer::buildFrame('<', payload, sizeof(payload), wire, sizeof(wire));
  ASSERT_GT(wireLen, 0u);
  OtaUsbControlFramer f('<');
  OtaUsbControlFramer::FeedResult last = OtaUsbControlFramer::FeedResult::Idle;
  for (size_t i = 0; i < wireLen; i++) last = f.feedByte(wire[i], 0);
  EXPECT_EQ(OtaUsbControlFramer::FeedResult::FrameReady, last);
  ASSERT_EQ(sizeof(payload), f.frameLen());
  EXPECT_EQ(0, std::memcmp(f.frameData(), payload, sizeof(payload)));
}

} // namespace
