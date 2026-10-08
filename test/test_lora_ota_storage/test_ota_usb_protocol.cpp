// Native, production-code coverage for the fixed-layout lean USB OTA
// uploader/status wire contract (see src/helpers/ota/OtaUsbProtocol.h).
// Pure codec: exercises the exact byte offsets/big-endian encoding of
// the 90-byte ABI2 reply and the signed-message shapes, with no
// hardware/flash dependency.
#include <gtest/gtest.h>
#include <algorithm>
#include <cstdint>
#include <cstring>

#include "helpers/ota/OtaUsbProtocol.h"

using namespace mesh::ota::usb;
using mesh::ota::OtaDirectProfile;

TEST(OtaUsbProtocolTest, RetryStartIsExplicitAndCannotReplaceLegacyOr500ProfileShape) {
  uint8_t command[kStartRetryTotalBytes] = {kCommand, static_cast<uint8_t>(UsbOtaOp::Start),
      kStartModeDirected, 255};
  OtaDirectProfile profile;
  bool retry;
  ASSERT_TRUE(parseStartOptions(command, kStartTotalBytes, profile, retry));
  EXPECT_EQ(OtaDirectProfile::Legacy250, profile);
  EXPECT_FALSE(retry);
  command[15] = kStartFlagRetryAttempts;
  ASSERT_TRUE(parseStartOptions(command, sizeof(command), profile, retry));
  EXPECT_TRUE(retry);
  EXPECT_FALSE(parseStartProfile(command, sizeof(command), profile));
  command[2] = kStartModeBackground;
  EXPECT_TRUE(parseStartOptions(command, sizeof(command), profile, retry));
  for (uint8_t flags : {uint8_t(0), uint8_t(2), uint8_t(3), uint8_t(255)}) {
    command[15] = flags;
    EXPECT_FALSE(parseStartOptions(command, sizeof(command), profile, retry));
  }
  command[15] = 1; command[14] = 2;
  EXPECT_FALSE(parseStartOptions(command, sizeof(command), profile, retry));
  command[2] = kStartModeDirect;
  EXPECT_TRUE(parseStartOptions(command, kStartProfileTotalBytes, profile, retry));
  EXPECT_EQ(OtaDirectProfile::Bw500, profile);
  EXPECT_FALSE(retry);
  EXPECT_FALSE(parseStartOptions(command, sizeof(command), profile, retry));
  for (size_t len : {size_t(0), size_t(13), size_t(17)})
    EXPECT_FALSE(parseStartOptions(command, len, profile, retry));
}

TEST(OtaUsbProtocolTest, ReplyLayoutMatchesFixed107ByteAbi3Contract) {
  UsbOtaReply reply;
  reply.requestOp = static_cast<uint8_t>(UsbOtaOp::Status);
  reply.result = UsbOtaResult::Ok;
  reply.phase = UsbOtaPhase::Ready;
  reply.flags = kReplyFlagSnapshotValid;
  for (int i = 0; i < 32; i++) reply.target[i] = (uint8_t)(0xA0 + i);
  for (int i = 0; i < 32; i++) reply.manifestHash[i] = (uint8_t)(0xB0 + i);
  reply.durableReceivedBlocks = 1234;
  reply.totalBlocks = 5678;
  reply.counter = 0x01020304;
  reply.statusAgeMs = 42;
  reply.retryAfterMs = 0;
  reply.generation = 0xA1B2C3D4;
  for (int i = 0; i < 16; i++) reply.beginNonce[i] = (uint8_t)(0xC0 + i);
  reply.wireVersion = kOtaWireVersion;

  uint8_t out[kReplyBytes];
  ASSERT_EQ(kReplyBytes, encodeUsbOtaReply(reply, out));

  EXPECT_EQ(30, out[0]);           // upstream RESP29 remains the CLI reply
  EXPECT_EQ(kAbiVersion, out[1]);
  EXPECT_EQ(static_cast<uint8_t>(UsbOtaOp::Status), out[2]);
  EXPECT_EQ(static_cast<uint8_t>(UsbOtaResult::Ok), out[3]);
  EXPECT_EQ(static_cast<uint8_t>(UsbOtaPhase::Ready), out[4]);
  EXPECT_EQ(kReplyFlagSnapshotValid, out[5]);
  EXPECT_EQ(0xA0, out[6]);         // target[0]
  EXPECT_EQ(0xA0 + 31, out[6 + 31]); // target[31]
  EXPECT_EQ(0xB0, out[38]);        // manifestHash[0]
  EXPECT_EQ(0xB0 + 31, out[38 + 31]);
  EXPECT_EQ(getBE16(&out[70]), 1234);
  EXPECT_EQ(getBE16(&out[72]), 5678);
  EXPECT_EQ(getBE32(&out[74]), 0x01020304u);
  EXPECT_EQ(getBE32(&out[78]), 42u);
  EXPECT_EQ(getBE32(&out[82]), 0u);
  EXPECT_EQ(3u, out[1]);
  EXPECT_EQ(0xA1B2C3D4u, getBE32(&out[86]));
  EXPECT_EQ(0xC0, out[90]);
  EXPECT_EQ(0xC0 + 15, out[105]);
  EXPECT_EQ(3u, out[106]);
}

TEST(OtaUsbProtocolTest, NoSnapshotShapeIsCanonical) {
  UsbOtaReply reply;
  reply.flags = kReplyFlagSnapshotValid; // pre-set, must be cleared by setNoSnapshot()
  reply.phase = UsbOtaPhase::Ready;
  reply.manifestHash[0] = 0xFF;
  reply.durableReceivedBlocks = 7;
  reply.totalBlocks = 9;
  reply.counter = 55;
  reply.statusAgeMs = 3;
  reply.generation = 99;
  reply.beginNonce[0] = 0x44;

  reply.setNoSnapshot();

  EXPECT_EQ(0, reply.flags & kReplyFlagSnapshotValid);
  EXPECT_EQ(UsbOtaPhase::Unknown, reply.phase);
  for (int i = 0; i < 32; i++) EXPECT_EQ(0, reply.manifestHash[i]);
  EXPECT_EQ(0, reply.durableReceivedBlocks);
  EXPECT_EQ(0, reply.totalBlocks);
  EXPECT_EQ(0u, reply.counter);
  EXPECT_EQ(kStatusAgeUnknown, reply.statusAgeMs);
  EXPECT_EQ(0u, reply.generation);
  EXPECT_FALSE(beginNonceBound(reply.beginNonce));
}

TEST(OtaUsbProtocolTest, BigEndianRoundTrip) {
  uint8_t buf[4];
  putBE16(buf, 0xBEEF);
  EXPECT_EQ(0xBE, buf[0]);
  EXPECT_EQ(0xEF, buf[1]);
  EXPECT_EQ(0xBEEF, getBE16(buf));

  putBE32(buf, 0xDEADBEEF);
  EXPECT_EQ(0xDE, buf[0]);
  EXPECT_EQ(0xAD, buf[1]);
  EXPECT_EQ(0xBE, buf[2]);
  EXPECT_EQ(0xEF, buf[3]);
  EXPECT_EQ(0xDEADBEEFu, getBE32(buf));
}

TEST(OtaUsbProtocolTest, EverySubopResultEncodesNoSnapshotWithoutEchoAndPreservesRealViews) {
  for (uint8_t op = 0x10; op <= 0x18; ++op) {
    for (uint8_t result = 0; result <= static_cast<uint8_t>(UsbOtaResult::Unsupported); ++result) {
      for (const uint8_t scope : {uint8_t(0), kReplyFlagRemote}) {
        UsbOtaReply reply;
        reply.requestOp = op;
        reply.result = static_cast<UsbOtaResult>(result);
        reply.flags = scope;
        reply.phase = UsbOtaPhase::Ready;
        std::memset(reply.target, 0xA7, sizeof(reply.target));
        std::memset(reply.manifestHash, 0x5A, sizeof(reply.manifestHash));
        reply.durableReceivedBlocks = 5;
        reply.totalBlocks = 9;
        reply.counter = 33;
        reply.statusAgeMs = 4;
        reply.retryAfterMs = 442;
        reply.generation = 0x01020304;
        std::memset(reply.beginNonce, 0x6B, sizeof(reply.beginNonce));
        uint8_t encoded[kReplyBytes];
        ASSERT_EQ(kReplyBytes, encodeUsbOtaReply(reply, encoded));
        EXPECT_EQ(op, encoded[2]);
        EXPECT_EQ(result, encoded[3]);
        EXPECT_EQ(static_cast<uint8_t>(UsbOtaPhase::Unknown), encoded[4]);
        EXPECT_EQ(scope, encoded[5]);
        EXPECT_EQ(0, std::memcmp(reply.target, encoded + 6, sizeof(reply.target)));
        const uint8_t empty[40] = {};
        EXPECT_EQ(0, std::memcmp(empty, encoded + 38, sizeof(empty)));
        EXPECT_EQ(kStatusAgeUnknown, getBE32(encoded + 78));
        EXPECT_EQ(442u, getBE32(encoded + 82));
        EXPECT_EQ(0u, getBE32(encoded + 86));
        const uint8_t no_nonce[16] = {};
        EXPECT_EQ(0, std::memcmp(no_nonce, encoded + 90, sizeof(no_nonce)));
        EXPECT_EQ(UsbOtaPhase::Ready, reply.phase);
        EXPECT_EQ(0x5A, reply.manifestHash[0]);  // Encoding does not mutate the working reply.
        reply.flags |= kReplyFlagSnapshotValid;
        ASSERT_EQ(kReplyBytes, encodeUsbOtaReply(reply, encoded));
        EXPECT_EQ(static_cast<uint8_t>(UsbOtaPhase::Ready), encoded[4]);
        EXPECT_EQ(scope | kReplyFlagSnapshotValid, encoded[5]);
        EXPECT_EQ(0, std::memcmp(reply.manifestHash, encoded + 38, sizeof(reply.manifestHash)));
        EXPECT_EQ(5u, getBE16(encoded + 70));
        EXPECT_EQ(9u, getBE16(encoded + 72));
        EXPECT_EQ(33u, getBE32(encoded + 74));
        EXPECT_EQ(4u, getBE32(encoded + 78));
        EXPECT_EQ(442u, getBE32(encoded + 82));
        EXPECT_EQ(0x01020304u, getBE32(encoded + 86));
        EXPECT_EQ(0, std::memcmp(reply.beginNonce, encoded + 90, sizeof(reply.beginNonce)));
      }
    }
  }
}

TEST(OtaUsbProtocolTest, CommitSignedMessageBindsDomainTargetHashCounterGenerationAndNonce) {
  uint8_t target[kPubKeyBytes];
  uint8_t hash[kHashBytes];
  uint8_t nonce[kBeginNonceBytes];
  for (int i = 0; i < 32; i++) { target[i] = (uint8_t)i; hash[i] = (uint8_t)(100 + i); }
  for (int i = 0; i < 16; i++) nonce[i] = (uint8_t)(200 + i);

  uint8_t msg[kCommitSignedBytes];
  size_t n = buildCommitSignedMessage(target, hash, 0x11223344, 0x55667788, nonce, msg);
  ASSERT_EQ(110u, n);
  ASSERT_EQ(kCommitSignedBytes, n);
  EXPECT_STREQ("MeshCore/OTA/commit/v2", kCommitDomain);

  // domain prefix, no NUL terminator included.
  EXPECT_EQ(0, std::memcmp(msg, kCommitDomain, kCommitDomainLen));
  // target immediately follows domain.
  EXPECT_EQ(0, std::memcmp(msg + kCommitDomainLen, target, kPubKeyBytes));
  // hash immediately follows target.
  EXPECT_EQ(0, std::memcmp(msg + kCommitDomainLen + kPubKeyBytes, hash, kHashBytes));
  // counter (big-endian) is the final 4 bytes.
  EXPECT_EQ(getBE32(msg + kCommitDomainLen + kPubKeyBytes + kHashBytes), 0x11223344u);
  EXPECT_EQ(getBE32(msg + kCommitDomainLen + kPubKeyBytes + kHashBytes + 4), 0x55667788u);
  EXPECT_EQ(0, std::memcmp(msg + kCommitDomainLen + kPubKeyBytes + kHashBytes + 8, nonce, sizeof(nonce)));

  // A new BEGIN nonce for the identical image yields a different message.
  uint8_t other[kCommitSignedBytes];
  nonce[15] ^= 1;
  buildCommitSignedMessage(target, hash, 0x11223344, 0x55667788, nonce, other);
  EXPECT_NE(0, std::memcmp(msg, other, sizeof(msg)));
}

TEST(OtaUsbProtocolTest, CommitRequestParsesOnlyExact90ByteNonceBoundForm) {
  uint8_t command[kCommitTotalBytes] = {kCommand, static_cast<uint8_t>(UsbOtaOp::Commit)};
  for (int i = 0; i < 32; i++) { command[2 + i] = 0x10; command[34 + i] = 0x20; }
  putBE32(command + 66, 9);
  putBE32(command + 70, 0x0A0B0C0D);
  for (int i = 0; i < 16; i++) command[74 + i] = (uint8_t)(0x30 + i);
  UsbCommitRequest request;
  ASSERT_TRUE(parseCommitRequest(command, sizeof(command), request));
  EXPECT_EQ(command + 2, request.target);
  EXPECT_EQ(command + 34, request.manifestHash);
  EXPECT_EQ(9u, request.counter);
  EXPECT_EQ(0x0A0B0C0Du, request.generation);
  EXPECT_EQ(command + 74, request.beginNonce);
  EXPECT_FALSE(parseCommitRequest(command, 70, request));
  EXPECT_FALSE(parseCommitRequest(command, sizeof(command) - 1, request));
  command[1] = static_cast<uint8_t>(UsbOtaOp::Abort);
  EXPECT_FALSE(parseCommitRequest(command, sizeof(command), request));
}

TEST(OtaUsbProtocolTest, DifferentTargetProducesDifferentSignedMessage) {
  // Captured-for-A-cannot-commit-B: changing only the target byte range
  // must change the signed message (and therefore invalidate any
  // signature computed over the other target's message).
  uint8_t targetA[kPubKeyBytes]; std::memset(targetA, 0xAA, sizeof(targetA));
  uint8_t targetB[kPubKeyBytes]; std::memset(targetB, 0xBB, sizeof(targetB));
  uint8_t hash[kHashBytes]; std::memset(hash, 0x55, sizeof(hash));
  uint8_t nonce[kBeginNonceBytes]; std::memset(nonce, 0x77, sizeof(nonce));

  uint8_t msgA[kCommitSignedBytes];
  uint8_t msgB[kCommitSignedBytes];
  buildCommitSignedMessage(targetA, hash, 7, 1, nonce, msgA);
  buildCommitSignedMessage(targetB, hash, 7, 1, nonce, msgB);

  EXPECT_NE(0, std::memcmp(msgA, msgB, kCommitSignedBytes));
}

TEST(OtaUsbProtocolTest, FixedWireSizesMatchContract) {
  EXPECT_EQ(158u, kCacheBeginTotalBytes);
  EXPECT_EQ(89u, kCachePutMaxTotalBytes);
  EXPECT_EQ(2u, kCacheSealTotalBytes);
  EXPECT_EQ(34u, kAddTargetTotalBytes);
  EXPECT_EQ(14u, kStartTotalBytes);
  EXPECT_EQ(90u, kCommitTotalBytes);
  EXPECT_EQ(70u, kAbortTotalBytes);
  EXPECT_EQ(34u, kStatusTotalBytes);
  EXPECT_EQ(35u, kSetContactAdminTotalBytes);
  EXPECT_EQ(107u, kReplyBytes);
  EXPECT_EQ(3u, kAbiVersion);
  EXPECT_EQ(3u, kOtaWireVersion);
}

TEST(OtaUsbProtocolTest, AbortSignedMessageBindsV2DomainTargetImageHashAndGeneration) {
  uint8_t target[kPubKeyBytes];
  uint8_t imageHash[kHashBytes];
  for (int i = 0; i < 32; i++) { target[i] = (uint8_t)(200 + i); imageHash[i] = (uint8_t)(50 + i); }

  uint8_t msg[kAbortSignedBytes];
  size_t n = buildAbortSignedMessage(target, imageHash, 0x12345678, msg);
  ASSERT_EQ(kAbortSignedBytes, n);

  EXPECT_EQ(0, std::memcmp(msg, kAbortDomain, kAbortDomainLen));
  EXPECT_EQ(0, std::memcmp(msg + kAbortDomainLen, target, kPubKeyBytes));
  EXPECT_EQ(0, std::memcmp(msg + kAbortDomainLen + kPubKeyBytes, imageHash, kHashBytes));
  EXPECT_STREQ("MeshCore/OTA/abort/v2", kAbortDomain);
  EXPECT_EQ(0x12345678u, getBE32(msg + kAbortDomainLen + kPubKeyBytes + kHashBytes));
  uint8_t other[kAbortSignedBytes];
  buildAbortSignedMessage(target, imageHash, 0x12345679, other);
  EXPECT_NE(0, std::memcmp(msg, other, sizeof(msg)));

  // ABORT's domain must differ from COMMIT's: a COMMIT signature can
  // never double as a valid ABORT signature or vice versa, even when
  // the target/hash bytes happen to coincide.
  EXPECT_NE(0, std::memcmp(kAbortDomain, kCommitDomain,
                           std::min(kAbortDomainLen, kCommitDomainLen)));
}

TEST(OtaUsbProtocolTest, DutyShareBoundsAreConfigurableRangeNotFixedConstant) {
  // The on-mesh airtime/duty SHARE is a caller-configured value within
  // the existing supported bounds for ALL modes; 2.000% is only a
  // default/test convenience value, never the sole permitted one.
  EXPECT_EQ(0u, kDutyMilliPercentMin);
  EXPECT_EQ(100000u, kDutyMilliPercentMax);
  EXPECT_EQ(2000u, kDefaultDutyMilliPercent);
  EXPECT_GT(kDutyMilliPercentMax, kDefaultDutyMilliPercent);
}
