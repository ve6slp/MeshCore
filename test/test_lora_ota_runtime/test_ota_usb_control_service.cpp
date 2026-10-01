#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "helpers/ota/OtaUsbControlFramer.h"
#include "helpers/ota/OtaUsbControlService.h"
#include "ota/runtime/OtaControlSessionRouter.h"

using meshcore::ota::helpers::OtaUsbControlFramer;
using meshcore::ota::helpers::OtaUsbControlService;
using namespace meshcore::ota::runtime;
using namespace meshcore::ota::protocol;

namespace {

// Deterministic, test-controllable entropy -- see the equivalent fixture
// in test_ota_control_session_router.cpp.
class FakeEntropy : public IOtaControlEntropySource {
public:
  bool fillRandom(uint8_t* dest, size_t len) override {
    for (size_t i = 0; i < len; i++) dest[i] = static_cast<uint8_t>(counter_ + i);
    counter_ += 1;
    return true;
  }
  uint8_t counter_ = 1;
};

class NullBackend : public IOtaControlJobBackend {
public:
  OtaControlStatus beginJob(OtaControlSubcommand, uint32_t, OtaControlObjectKind, const uint8_t*, size_t,
                            uint16_t&) override {
    return OtaControlStatus::Ok;
  }
  OtaControlStatus pollJob(uint32_t, uint16_t&) override { return OtaControlStatus::Ok; }
  OtaControlStatus readObject(uint32_t, OtaControlObjectKind, uint32_t, uint8_t*, uint8_t, uint8_t& outLen,
                              uint16_t&) override {
    outLen = 0;
    return OtaControlStatus::Ok;
  }
  void cancelJob(uint32_t) override {}
};

// Builds a wire-ready OUTER '<'+LE16+payload byte stream for an OPEN
// request.
std::vector<uint8_t> outerOpenFrame(uint32_t requestId) {
  OtaControlRequestHeader h;
  h.sub = OtaControlSubcommand::Open;
  h.requestId = requestId;
  uint8_t inner[kOtaControlRequestHeaderSize];
  EXPECT_TRUE(encodeOtaControlRequestHeader(h, inner, sizeof(inner)));
  uint8_t outer[3 + kOtaControlRequestHeaderSize];
  size_t n = OtaUsbControlFramer::buildFrame('<', inner, sizeof(inner), outer, sizeof(outer));
  return std::vector<uint8_t>(outer, outer + n);
}

std::vector<uint8_t> outerPollFrame(const uint8_t session[kOtaControlSessionIdBytes], uint32_t requestId,
                                    uint32_t jobTicket) {
  OtaControlRequestHeader h;
  h.sub = OtaControlSubcommand::Poll;
  h.requestId = requestId;
  h.jobTicket = jobTicket;
  std::memcpy(h.session, session, kOtaControlSessionIdBytes);
  uint8_t inner[kOtaControlRequestHeaderSize];
  EXPECT_TRUE(encodeOtaControlRequestHeader(h, inner, sizeof(inner)));
  uint8_t outer[3 + kOtaControlRequestHeaderSize];
  size_t n = OtaUsbControlFramer::buildFrame('<', inner, sizeof(inner), outer, sizeof(outer));
  return std::vector<uint8_t>(outer, outer + n);
}

OtaControlReplyHeader decodePendingReply(const OtaUsbControlService& svc) {
  // Strip the 3-byte outer framing ('>' + LE16 len) to get at the inner
  // control reply header for assertions.
  const uint8_t* wire = svc.pendingReplyData();
  size_t wireLen = svc.pendingReplyLen();
  EXPECT_GE(wireLen, 3u);
  const uint8_t* inner = wire + 3;
  size_t innerLen = wireLen - 3;
  OtaControlReplyHeader out;
  EXPECT_TRUE(decodeOtaControlReplyHeader(inner, innerLen, out));
  return out;
}

TEST(OtaUsbControlService, WellFormedOpenProducesSessionMintingReply) {
  FakeEntropy entropy;
  NullBackend backend;
  OtaControlSessionRouter router{entropy, backend};
  OtaUsbControlService svc(router);

  auto frame = outerOpenFrame(1);
  bool replied = false;
  for (uint8_t b : frame) replied = svc.onByte(b, 0) || replied;
  ASSERT_TRUE(replied);
  ASSERT_TRUE(svc.hasPendingReply());
  auto reply = decodePendingReply(svc);
  EXPECT_EQ(OtaControlStatus::Ok, reply.status);
  EXPECT_TRUE(router.isSessionOpen());
}

TEST(OtaUsbControlService, GarbageBytesBeforeAWellFormedFrameNeverProduceASpuriousReply) {
  FakeEntropy entropy;
  NullBackend backend;
  OtaControlSessionRouter router{entropy, backend};
  OtaUsbControlService svc(router);

  // Noise that could look like a stray header byte (including a stray
  // leading '<') must never cause a short/garbled dispatch.
  const uint8_t noise[] = {0x00, 0xFF, '<', 0x05, 0x7F};
  bool repliedDuringNoise = false;
  for (uint8_t b : noise) repliedDuringNoise = svc.onByte(b, 0) || repliedDuringNoise;
  EXPECT_FALSE(repliedDuringNoise);

  auto frame = outerOpenFrame(2);
  bool replied = false;
  for (uint8_t b : frame) replied = svc.onByte(b, 1000) || replied;
  ASSERT_TRUE(replied);
  auto reply = decodePendingReply(svc);
  EXPECT_EQ(OtaControlStatus::Ok, reply.status);
}

TEST(OtaUsbControlService, PartialStreamInterruptedThenResumedWithFreshFrameRecoversCleanly) {
  FakeEntropy entropy;
  NullBackend backend;
  OtaControlSessionRouter router{entropy, backend};
  OtaUsbControlService svc(router);

  auto frame = outerOpenFrame(3);
  // Feed only the outer header + 1 payload byte, then stop (simulating a
  // dropped USB connection mid-frame) and let it time out.
  for (size_t i = 0; i < 4; i++) EXPECT_FALSE(svc.onByte(frame[i], 0));
  svc.tick(10000); // well past the default 2000ms timeout -- discards the stall

  // A genuine subsequent OPEN must parse cleanly, not be corrupted by the
  // abandoned partial bytes.
  auto freshFrame = outerOpenFrame(4);
  bool replied = false;
  for (uint8_t b : freshFrame) replied = svc.onByte(b, 10001) || replied;
  ASSERT_TRUE(replied);
  auto reply = decodePendingReply(svc);
  EXPECT_EQ(OtaControlStatus::Ok, reply.status);
}

TEST(OtaUsbControlService, ReplayOfAnIdenticalOpenFrameAfterSessionAlreadyOpenIsBusyNotASecondSession) {
  FakeEntropy entropy;
  NullBackend backend;
  OtaControlSessionRouter router{entropy, backend};
  OtaUsbControlService svc(router);

  auto frame = outerOpenFrame(5);
  for (uint8_t b : frame) svc.onByte(b, 0);
  ASSERT_TRUE(svc.hasPendingReply());
  auto firstReply = decodePendingReply(svc);
  ASSERT_EQ(OtaControlStatus::Ok, firstReply.status);
  uint8_t session[kOtaControlSessionIdBytes];
  std::memcpy(session, firstReply.session, kOtaControlSessionIdBytes);
  svc.consumeReply();

  // Replaying the exact same byte-for-byte OPEN frame while already open
  // must be refused as Busy, never silently re-minting/overwriting the
  // live session.
  for (uint8_t b : frame) svc.onByte(b, 1);
  ASSERT_TRUE(svc.hasPendingReply());
  auto secondReply = decodePendingReply(svc);
  EXPECT_EQ(OtaControlStatus::Busy, secondReply.status);
  // The original session must remain intact/usable afterwards -- CLOSE
  // with the ORIGINAL session should succeed (Ok), proving the replay
  // attempt didn't invalidate or replace the live session.
  svc.consumeReply();
  OtaControlRequestHeader closeReq;
  closeReq.sub = OtaControlSubcommand::Close;
  closeReq.requestId = 6;
  std::memcpy(closeReq.session, session, kOtaControlSessionIdBytes);
  uint8_t closeInner[kOtaControlRequestHeaderSize];
  ASSERT_TRUE(encodeOtaControlRequestHeader(closeReq, closeInner, sizeof(closeInner)));
  uint8_t closeOuter[3 + kOtaControlRequestHeaderSize];
  size_t closeOuterLen =
      OtaUsbControlFramer::buildFrame('<', closeInner, sizeof(closeInner), closeOuter, sizeof(closeOuter));
  for (size_t i = 0; i < closeOuterLen; i++) svc.onByte(closeOuter[i], 2);
  ASSERT_TRUE(svc.hasPendingReply());
  auto closeReply = decodePendingReply(svc);
  EXPECT_EQ(OtaControlStatus::Ok, closeReply.status);
}

TEST(OtaUsbControlService, ConnectionEpochChangeRevokesSessionAndDiscardsInFlightFrameAndStaleReply) {
  FakeEntropy entropy;
  NullBackend backend;
  OtaControlSessionRouter router{entropy, backend};
  OtaUsbControlService svc(router);

  auto frame = outerOpenFrame(7);
  for (uint8_t b : frame) svc.onByte(b, 0);
  ASSERT_TRUE(svc.hasPendingReply());
  ASSERT_TRUE(router.isSessionOpen());

  // A genuine disconnect/reconnect must drop the unread reply (a new
  // physical source must never receive a reply addressed to the old
  // one) and revoke the session so a changed/foreign ticket can never
  // resume it.
  svc.onConnectionEpochChanged();
  EXPECT_FALSE(svc.hasPendingReply());
  EXPECT_FALSE(router.isSessionOpen());

  // A request against the now-revoked session must be denied, not quietly
  // honoured as if the old source were still trusted.
  uint8_t staleSession[kOtaControlSessionIdBytes];
  std::memset(staleSession, 0xAB, sizeof(staleSession));
  auto pollFrame = outerPollFrame(staleSession, 8, 0);
  bool replied = false;
  for (uint8_t b : pollFrame) replied = svc.onByte(b, 0) || replied;
  ASSERT_TRUE(replied);
  auto reply = decodePendingReply(svc);
  EXPECT_EQ(OtaControlStatus::Denied, reply.status);
}

TEST(OtaUsbControlService, OversizedDeclaredOuterLengthIsDiscardedAndNeverDispatchedToTheRouter) {
  FakeEntropy entropy;
  NullBackend backend;
  OtaControlSessionRouter router{entropy, backend};
  OtaUsbControlService svc(router);

  const uint8_t malformed[] = {'<', 0xFF, 0xFF}; // declares a 65535-byte payload, far over kMaxPayload
  bool replied = false;
  for (uint8_t b : malformed) replied = svc.onByte(b, 0) || replied;
  EXPECT_FALSE(replied);
  EXPECT_FALSE(router.isSessionOpen()); // router was never even invoked

  // Parser must resync and accept a genuine frame right after.
  auto frame = outerOpenFrame(9);
  bool repliedAfter = false;
  for (uint8_t b : frame) repliedAfter = svc.onByte(b, 0) || repliedAfter;
  EXPECT_TRUE(repliedAfter);
}

} // namespace
