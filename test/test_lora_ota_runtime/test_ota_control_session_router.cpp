#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "ota/runtime/OtaControlSessionRouter.h"

using namespace meshcore::ota::runtime;
using meshcore::ota::protocol::OtaControlObjectKind;
using meshcore::ota::protocol::OtaControlReplyHeader;
using meshcore::ota::protocol::OtaControlRequestHeader;
using meshcore::ota::protocol::OtaControlStatus;
using meshcore::ota::protocol::OtaControlSubcommand;
using meshcore::ota::protocol::kOtaControlMaxDataLen;
using meshcore::ota::protocol::kOtaControlReplyHeaderSize;
using meshcore::ota::protocol::kOtaControlRequestHeaderSize;
using meshcore::ota::protocol::kOtaControlSessionIdBytes;

namespace {

// Deterministic, test-controllable "entropy": fills with an incrementing
// byte pattern seeded by a counter, so distinct OPEN/CHALLENGE calls get
// distinguishably different (not just reproducible) bytes without pulling
// in any real RNG.
class FakeEntropy : public IOtaControlEntropySource {
public:
  bool fillRandom(uint8_t* dest, size_t len) override {
    if (fail_) return false;
    for (size_t i = 0; i < len; i++) dest[i] = static_cast<uint8_t>(counter_ + i);
    counter_ += 1;
    return true;
  }
  uint8_t counter_ = 1;
  bool fail_ = false;
};

// Scriptable backend recording every call so tests can assert exactly
// which (and how many) backend methods actually ran.
class RecordingBackend : public IOtaControlJobBackend {
public:
  OtaControlStatus beginJob(OtaControlSubcommand sub, uint32_t jobTicket, OtaControlObjectKind inputKind,
                             const uint8_t* input, size_t inputLen, uint16_t& reason) override {
    beginCalls++;
    lastBeginSub = sub;
    lastBeginTicket = jobTicket;
    lastBeginKind = inputKind;
    lastBeginInput.assign(input, input + inputLen);
    reason = beginReason;
    return beginStatus;
  }
  OtaControlStatus pollJob(uint32_t jobTicket, uint16_t& reason) override {
    pollCalls++;
    lastPollTicket = jobTicket;
    reason = pollReason;
    return pollStatus;
  }
  OtaControlStatus readObject(uint32_t jobTicket, OtaControlObjectKind kind, uint32_t offset,
                               uint8_t* dest, uint8_t maxLen, uint8_t& outLen, uint16_t& reason) override {
    readCalls++;
    lastReadTicket = jobTicket;
    lastReadKind = kind;
    lastReadOffset = offset;
    reason = readReason;
    if (readStatus == OtaControlStatus::Ok) {
      uint8_t n = std::min<uint8_t>(maxLen, static_cast<uint8_t>(readPayload.size()));
      std::memcpy(dest, readPayload.data(), n);
      outLen = n;
    }
    return readStatus;
  }
  void cancelJob(uint32_t jobTicket) override {
    cancelCalls++;
    lastCancelTicket = jobTicket;
  }

  int beginCalls = 0, pollCalls = 0, readCalls = 0, cancelCalls = 0;
  OtaControlSubcommand lastBeginSub = OtaControlSubcommand::Open;
  uint32_t lastBeginTicket = 0, lastPollTicket = 0, lastReadTicket = 0, lastCancelTicket = 0;
  OtaControlObjectKind lastBeginKind = OtaControlObjectKind::None;
  OtaControlObjectKind lastReadKind = OtaControlObjectKind::None;
  uint32_t lastReadOffset = 0;
  std::vector<uint8_t> lastBeginInput;
  std::vector<uint8_t> readPayload;
  uint16_t beginReason = 0, pollReason = 0, readReason = 0;
  OtaControlStatus beginStatus = OtaControlStatus::Ok;
  OtaControlStatus pollStatus = OtaControlStatus::Pending;
  OtaControlStatus readStatus = OtaControlStatus::Ok;
};

size_t buildRequest(OtaControlRequestHeader hdr, const uint8_t* data, size_t dataLen,
                     uint8_t* out, size_t cap) {
  // ReadObject's wire contract is special: header.dataLen is the
  // REQUESTED READ COUNT (1..128), not a transferred-payload length --
  // the actual payload bytes after the header are always 0 for a
  // request. So only force-overwrite hdr.dataLen from the actual
  // transferred `dataLen` when there IS a transferred payload; otherwise
  // trust whatever the caller already set on `hdr.dataLen` (defaulting to
  // 0 for every ordinary header-only/zero-payload call site).
  if (dataLen > 0) hdr.dataLen = static_cast<uint8_t>(dataLen);
  // A real host client always sets a non-zero requestId; most fixtures in
  // this file predate the router calling the shared shape validator
  // (which rejects requestId==0), so default one in rather than touch
  // every call site.
  if (hdr.requestId == 0) hdr.requestId = 1;
  if (!meshcore::ota::protocol::encodeOtaControlRequestHeader(hdr, out, cap)) return 0;
  if (dataLen > 0) {
    if (kOtaControlRequestHeaderSize + dataLen > cap) return 0;
    std::memcpy(out + kOtaControlRequestHeaderSize, data, dataLen);
  }
  return kOtaControlRequestHeaderSize + dataLen;
}

OtaControlReplyHeader decodeReply(const uint8_t* buf, size_t len) {
  OtaControlReplyHeader out;
  EXPECT_TRUE(meshcore::ota::protocol::decodeOtaControlReplyHeader(buf, len, out));
  return out;
}

struct RouterFixture : public ::testing::Test {
  FakeEntropy entropy;
  RecordingBackend backend;
  OtaControlSessionRouter router{entropy, backend};

  // Opens a session and returns the session id bytes the device minted.
  // OPEN carries NO payload (no host challenge) -- just the identity
  // header.
  void openSession(uint8_t sessionOut[kOtaControlSessionIdBytes]) {
    OtaControlRequestHeader req;
    req.sub = OtaControlSubcommand::Open;
    req.requestId = 1;
    uint8_t reqBuf[64], replyBuf[64];
    size_t reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
    size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
    OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
    EXPECT_EQ(OtaControlStatus::Ok, reply.status);
    std::memcpy(sessionOut, reply.session, kOtaControlSessionIdBytes);
  }
};

TEST_F(RouterFixture, OpenRejectsNonZeroPayload) {
  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Open;
  uint8_t bogusPayload[4] = {1, 2, 3, 4};
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, bogusPayload, sizeof(bogusPayload), reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Denied, reply.status);
  EXPECT_FALSE(router.isSessionOpen());
}

TEST_F(RouterFixture, OpenSucceedsAndMintsFreshSession) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);
  EXPECT_TRUE(router.isSessionOpen());
}

TEST_F(RouterFixture, SecondOpenWhileOccupiedIsBusy) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);

  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Open;
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Busy, reply.status);
}

TEST_F(RouterFixture, RequestWithNoOpenSessionIsDenied) {
  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Poll;
  req.jobTicket = 7;
  // Deliberately non-zero so the codec-level shape check (which rejects
  // an all-zero session on any non-OPEN request) doesn't mask this test's
  // actual target: the router's own "no session is open at all" check.
  std::memset(req.session, 0xAB, kOtaControlSessionIdBytes);
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Denied, reply.status);
  EXPECT_EQ(OtaControlSessionRouter::kReasonNoSession, reply.reason);
}

TEST_F(RouterFixture, RequestWithMismatchedSessionIsDenied) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);

  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Poll;
  req.jobTicket = 7;
  std::memset(req.session, 0xFF, kOtaControlSessionIdBytes); // definitely wrong
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Denied, reply.status);
  EXPECT_EQ(OtaControlSessionRouter::kReasonSessionMismatch, reply.reason);
}

TEST_F(RouterFixture, JobRequestWithZeroTicketIsDeniedWhenIdle) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);

  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Measure;
  req.jobTicket = 0;
  std::memcpy(req.session, session, kOtaControlSessionIdBytes);
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Denied, reply.status);
  EXPECT_EQ(0, backend.beginCalls);
}

TEST_F(RouterFixture, MeasureJobBeginsThenSameRequestPollsInstead) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);
  backend.beginStatus = OtaControlStatus::Pending;
  backend.pollStatus = OtaControlStatus::Pending;

  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Measure;
  req.jobTicket = 42;
  std::memcpy(req.session, session, kOtaControlSessionIdBytes);
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));

  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Pending, reply.status);
  EXPECT_EQ(1, backend.beginCalls);
  EXPECT_EQ(0, backend.pollCalls);

  // Identical resubmission (same ticket, same sub, same args): must poll,
  // not re-invoke beginJob.
  replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Pending, reply.status);
  EXPECT_EQ(1, backend.beginCalls);
  EXPECT_EQ(1, backend.pollCalls);
  EXPECT_EQ(42u, router.activeJobTicket());
}

TEST_F(RouterFixture, SameTicketChangedArgumentsIsRejectedNotReprocessed) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);
  backend.beginStatus = OtaControlStatus::Pending;

  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Measure;
  req.jobTicket = 42;
  std::memcpy(req.session, session, kOtaControlSessionIdBytes);
  uint8_t inlineData[4] = {1, 2, 3, 4};
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, inlineData, sizeof(inlineData), reqBuf, sizeof(reqBuf));
  router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  ASSERT_EQ(1, backend.beginCalls);

  // Same ticket, different inline data bytes => changed request (shape
  // stays legal: objectKind=None, dataLen=payloadLen>0; only the content
  // differs).
  inlineData[0] = 0xFF;
  reqLen = buildRequest(req, inlineData, sizeof(inlineData), reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::RejectedChangedRequest, reply.status);
  EXPECT_EQ(1, backend.beginCalls); // no second beginJob call
  EXPECT_EQ(0, backend.pollCalls);
}

TEST_F(RouterFixture, ForeignTicketWhileOccupiedIsDenied) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);
  backend.beginStatus = OtaControlStatus::Pending;

  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Measure;
  req.jobTicket = 42;
  std::memcpy(req.session, session, kOtaControlSessionIdBytes);
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));

  req.jobTicket = 99; // different, nonzero
  reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Denied, reply.status);
  EXPECT_EQ(1, backend.beginCalls); // untouched
}

TEST_F(RouterFixture, ZeroTicketWhileOccupiedIsBusy) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);
  backend.beginStatus = OtaControlStatus::Pending;

  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Measure;
  req.jobTicket = 42;
  std::memcpy(req.session, session, kOtaControlSessionIdBytes);
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));

  req.jobTicket = 0;
  reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Busy, reply.status);
}

TEST_F(RouterFixture, OkKeepsTicketActiveForSubsequentReadObjectThenCancelReleasesIt) {
  // Ok (like Pending) is one of the two statuses the ABI header's own
  // comment documents as "permit continued use of the same job ticket" --
  // a host must still be able to READ_OBJECT (e.g. fetch a freshly
  // Prepared P683) after the job itself reports Ok, so the router must
  // NOT drop the ticket purely because the backend finished.
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);
  backend.beginStatus = OtaControlStatus::Ok;

  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Measure;
  req.jobTicket = 42;
  std::memcpy(req.session, session, kOtaControlSessionIdBytes);
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  EXPECT_EQ(42u, router.activeJobTicket());

  // A different ticket is still foreign/occupied while 42 remains active.
  req.jobTicket = 43;
  reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Denied, reply.status);
  EXPECT_EQ(1, backend.beginCalls);

  // Only an explicit CANCEL releases the RAM lease/ticket.
  OtaControlRequestHeader cancelReq;
  cancelReq.sub = OtaControlSubcommand::Cancel;
  cancelReq.jobTicket = 42;
  std::memcpy(cancelReq.session, session, kOtaControlSessionIdBytes);
  reqLen = buildRequest(cancelReq, nullptr, 0, reqBuf, sizeof(reqBuf));
  router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  EXPECT_EQ(0u, router.activeJobTicket());

  // A fresh ticket can now start a new job without Denied/Busy.
  req.jobTicket = 43;
  reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Ok, reply.status);
  EXPECT_EQ(2, backend.beginCalls);
}

TEST_F(RouterFixture, GenuineFailureStatusReleasesTicketImmediately) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);
  backend.beginStatus = OtaControlStatus::Corrupt;

  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Measure;
  req.jobTicket = 42;
  std::memcpy(req.session, session, kOtaControlSessionIdBytes);
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Corrupt, reply.status);
  EXPECT_EQ(0u, router.activeJobTicket());

  // A fresh ticket can now start a new job immediately.
  req.jobTicket = 43;
  reqLen = buildRequest(req, nullptr, 0, reqBuf, sizeof(reqBuf));
  backend.beginStatus = OtaControlStatus::Ok;
  replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Ok, reply.status);
  EXPECT_EQ(2, backend.beginCalls);
}

TEST_F(RouterFixture, PutFragmentAssemblesObjectAcrossTwoFragmentsThenJobSeesWholeObject) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);

  // BaselineManifestB117 (fixed 117 bytes): two fragments, 64 + 53.
  std::vector<uint8_t> object(117);
  for (size_t i = 0; i < object.size(); i++) object[i] = static_cast<uint8_t>(i);

  uint8_t reqBuf[256], replyBuf[64];
  for (int frag = 0; frag < 2; frag++) {
    uint32_t offset = frag == 0 ? 0 : 64;
    uint8_t len = frag == 0 ? 64 : 53;
    OtaControlRequestHeader req;
    req.sub = OtaControlSubcommand::PutFragment;
    req.jobTicket = 7;
    req.objectKind = OtaControlObjectKind::BaselineManifestB117;
    req.total = 117;
    req.offset = offset;
    req.dataLen = len;
    std::memcpy(req.session, session, kOtaControlSessionIdBytes);
    size_t reqLen = buildRequest(req, object.data() + offset, len, reqBuf, sizeof(reqBuf));
    size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
    OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
    EXPECT_EQ(OtaControlStatus::Ok, reply.status);
  }

  backend.beginStatus = OtaControlStatus::Ok;
  OtaControlRequestHeader certifyReq;
  certifyReq.sub = OtaControlSubcommand::Certify;
  certifyReq.jobTicket = 7;
  certifyReq.objectKind = OtaControlObjectKind::BaselineManifestB117;
  certifyReq.total = 117; // echoes the referenced object kind's fixed size
  std::memcpy(certifyReq.session, session, kOtaControlSessionIdBytes);
  size_t reqLen = buildRequest(certifyReq, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Ok, reply.status);
  ASSERT_EQ(1, backend.beginCalls);
  EXPECT_EQ(OtaControlSubcommand::Certify, backend.lastBeginSub);
  EXPECT_EQ(OtaControlObjectKind::BaselineManifestB117, backend.lastBeginKind);
  ASSERT_EQ(object.size(), backend.lastBeginInput.size());
  EXPECT_EQ(0, std::memcmp(object.data(), backend.lastBeginInput.data(), object.size()));
}

TEST_F(RouterFixture, PutFragmentRejectsTotalMismatchingFixedSize) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);

  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::PutFragment;
  req.jobTicket = 7;
  req.objectKind = OtaControlObjectKind::BaselineManifestB117; // fixed 117
  req.total = 100; // wrong
  req.offset = 0;
  req.dataLen = 10;
  std::memcpy(req.session, session, kOtaControlSessionIdBytes);
  uint8_t data[10] = {0};
  uint8_t reqBuf[256], replyBuf[64];
  size_t reqLen = buildRequest(req, data, sizeof(data), reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Denied, reply.status);
}

TEST_F(RouterFixture, JobRequestReferencingIncompleteUploadIsMissing) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);

  // Put only the first half of a 117-byte object, never finish it.
  OtaControlRequestHeader putReq;
  putReq.sub = OtaControlSubcommand::PutFragment;
  putReq.jobTicket = 7;
  putReq.objectKind = OtaControlObjectKind::BaselineManifestB117;
  putReq.total = 117;
  putReq.offset = 0;
  putReq.dataLen = 60;
  std::memcpy(putReq.session, session, kOtaControlSessionIdBytes);
  uint8_t data[60] = {0};
  uint8_t reqBuf[256], replyBuf[64];
  size_t reqLen = buildRequest(putReq, data, sizeof(data), reqBuf, sizeof(reqBuf));
  router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));

  OtaControlRequestHeader certifyReq;
  certifyReq.sub = OtaControlSubcommand::Certify;
  certifyReq.jobTicket = 7;
  certifyReq.objectKind = OtaControlObjectKind::BaselineManifestB117;
  certifyReq.total = 117; // echoes the referenced object kind's fixed size
  std::memcpy(certifyReq.session, session, kOtaControlSessionIdBytes);
  reqLen = buildRequest(certifyReq, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Missing, reply.status);
  EXPECT_EQ(0, backend.beginCalls);
}

TEST_F(RouterFixture, ReadObjectReturnsBackendSlice) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);
  backend.beginStatus = OtaControlStatus::Pending;

  OtaControlRequestHeader jobReq;
  jobReq.sub = OtaControlSubcommand::Prepare;
  jobReq.jobTicket = 5;
  std::memcpy(jobReq.session, session, kOtaControlSessionIdBytes);
  uint8_t reqBuf[256], replyBuf[256];
  size_t reqLen = buildRequest(jobReq, nullptr, 0, reqBuf, sizeof(reqBuf));
  router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));

  backend.readPayload = {0xAA, 0xBB, 0xCC, 0xDD};
  OtaControlRequestHeader readReq;
  readReq.sub = OtaControlSubcommand::ReadObject;
  readReq.jobTicket = 5;
  readReq.objectKind = OtaControlObjectKind::PreparedRootP683;
  readReq.total = 683; // the object kind's fixed size, per ReadObject's shape contract
  readReq.offset = 10;
  readReq.dataLen = 4; // requested read count, no transferred payload bytes
  std::memcpy(readReq.session, session, kOtaControlSessionIdBytes);
  reqLen = buildRequest(readReq, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Ok, reply.status);
  EXPECT_EQ(4, reply.dataLen);
  EXPECT_EQ(10u, reply.offset);
  ASSERT_EQ(1, backend.readCalls);
  EXPECT_EQ(5u, backend.lastReadTicket);
  EXPECT_EQ(OtaControlObjectKind::PreparedRootP683, backend.lastReadKind);
  EXPECT_EQ(10u, backend.lastReadOffset);
  EXPECT_EQ(0, std::memcmp(replyBuf + kOtaControlReplyHeaderSize, backend.readPayload.data(), 4));
}

TEST_F(RouterFixture, CancelReleasesTicketAndCallsBackend) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);
  backend.beginStatus = OtaControlStatus::Pending;

  OtaControlRequestHeader jobReq;
  jobReq.sub = OtaControlSubcommand::Prepare;
  jobReq.jobTicket = 9;
  std::memcpy(jobReq.session, session, kOtaControlSessionIdBytes);
  uint8_t reqBuf[256], replyBuf[256];
  size_t reqLen = buildRequest(jobReq, nullptr, 0, reqBuf, sizeof(reqBuf));
  router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  ASSERT_EQ(9u, router.activeJobTicket());

  OtaControlRequestHeader cancelReq;
  cancelReq.sub = OtaControlSubcommand::Cancel;
  cancelReq.jobTicket = 9;
  std::memcpy(cancelReq.session, session, kOtaControlSessionIdBytes);
  reqLen = buildRequest(cancelReq, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Ok, reply.status);
  EXPECT_EQ(0u, router.activeJobTicket());
  EXPECT_EQ(1, backend.cancelCalls);
  EXPECT_EQ(9u, backend.lastCancelTicket);
}

TEST_F(RouterFixture, CloseEndsSessionAndSubsequentRequestsAreDenied) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);

  OtaControlRequestHeader closeReq;
  closeReq.sub = OtaControlSubcommand::Close;
  std::memcpy(closeReq.session, session, kOtaControlSessionIdBytes);
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(closeReq, nullptr, 0, reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Ok, reply.status);
  EXPECT_FALSE(router.isSessionOpen());

  OtaControlRequestHeader pollReq;
  pollReq.sub = OtaControlSubcommand::Poll;
  pollReq.jobTicket = 1;
  std::memcpy(pollReq.session, session, kOtaControlSessionIdBytes);
  reqLen = buildRequest(pollReq, nullptr, 0, reqBuf, sizeof(reqBuf));
  replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Denied, reply.status);
}

TEST_F(RouterFixture, ChallengeReturnsFreshBytesEachCall) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);

  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Challenge;
  req.total = 1;
  req.offset = 0;
  std::memcpy(req.session, session, kOtaControlSessionIdBytes);
  uint8_t purposeByte[1] = {static_cast<uint8_t>(OtaControlSubcommand::Prepare)};
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, purposeByte, sizeof(purposeByte), reqBuf, sizeof(reqBuf));

  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply1 = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Ok, reply1.status);
  EXPECT_EQ(kOtaControlSessionIdBytes, reply1.dataLen);
  EXPECT_EQ(kOtaControlSessionIdBytes, reply1.total);
  std::vector<uint8_t> c1(replyBuf + kOtaControlReplyHeaderSize, replyBuf + replyLen);

  replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply2 = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Ok, reply2.status);
  std::vector<uint8_t> c2(replyBuf + kOtaControlReplyHeaderSize, replyBuf + replyLen);
  EXPECT_NE(c1, c2);
}

TEST_F(RouterFixture, ChallengeRejectsInvalidPurposeByte) {
  uint8_t session[kOtaControlSessionIdBytes];
  openSession(session);

  OtaControlRequestHeader req;
  req.sub = OtaControlSubcommand::Challenge;
  req.total = 1;
  std::memcpy(req.session, session, kOtaControlSessionIdBytes);
  uint8_t badPurposeByte[1] = {static_cast<uint8_t>(OtaControlSubcommand::Measure)};
  uint8_t reqBuf[64], replyBuf[64];
  size_t reqLen = buildRequest(req, badPurposeByte, sizeof(badPurposeByte), reqBuf, sizeof(reqBuf));
  size_t replyLen = router.dispatch(reqBuf, reqLen, replyBuf, sizeof(replyBuf));
  OtaControlReplyHeader reply = decodeReply(replyBuf, replyLen);
  EXPECT_EQ(OtaControlStatus::Denied, reply.status);
  EXPECT_EQ(OtaControlSessionRouter::kReasonBadChallengePurpose, reply.reason);
}

TEST(OtaControlJobBackendSlot, DefaultsToNullBackendAndForwardsAfterBind) {
  OtaControlJobBackendSlot slot;
  uint16_t reason = 0;
  EXPECT_EQ(OtaControlStatus::NoCapacity, slot.beginJob(OtaControlSubcommand::Measure, 1,
                                                          OtaControlObjectKind::None, nullptr, 0, reason));

  RecordingBackend real;
  real.beginStatus = OtaControlStatus::Ok;
  slot.bind(&real);
  EXPECT_EQ(OtaControlStatus::Ok, slot.beginJob(OtaControlSubcommand::Measure, 1,
                                                 OtaControlObjectKind::None, nullptr, 0, reason));
  EXPECT_EQ(1, real.beginCalls);

  slot.bind(nullptr); // revert to fail-closed default
  EXPECT_EQ(OtaControlStatus::NoCapacity, slot.beginJob(OtaControlSubcommand::Measure, 1,
                                                          OtaControlObjectKind::None, nullptr, 0, reason));
  EXPECT_EQ(1, real.beginCalls); // untouched after revert
}

} // namespace
