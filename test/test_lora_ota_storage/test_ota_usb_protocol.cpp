// Native, production-code coverage for the fixed-layout lean USB OTA
// uploader/status wire contract (see src/helpers/ota/OtaUsbProtocol.h).
// Pure codec: exercises the exact byte offsets/big-endian encoding of
// the 86-byte reply and the commit-signature message shape, with no
// hardware/flash dependency.
#include <gtest/gtest.h>
#include <algorithm>
#include <cstdint>
#include <cstring>

#include "helpers/ota/OtaUsbProtocol.h"

using namespace mesh::ota::usb;

TEST(OtaUsbProtocolTest, ReplyLayoutMatchesFixed86ByteContract) {
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

  uint8_t out[kReplyBytes];
  ASSERT_EQ(kReplyBytes, encodeUsbOtaReply(reply, out));

  EXPECT_EQ(31, out[0]);           // kReplyCode
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

  reply.setNoSnapshot();

  EXPECT_EQ(0, reply.flags & kReplyFlagSnapshotValid);
  EXPECT_EQ(UsbOtaPhase::Unknown, reply.phase);
  for (int i = 0; i < 32; i++) EXPECT_EQ(0, reply.manifestHash[i]);
  EXPECT_EQ(0, reply.durableReceivedBlocks);
  EXPECT_EQ(0, reply.totalBlocks);
  EXPECT_EQ(0u, reply.counter);
  EXPECT_EQ(kStatusAgeUnknown, reply.statusAgeMs);
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

TEST(OtaUsbProtocolTest, CommitSignedMessageBindsDomainTargetHashAndCounter) {
  uint8_t target[kPubKeyBytes];
  uint8_t hash[kHashBytes];
  for (int i = 0; i < 32; i++) { target[i] = (uint8_t)i; hash[i] = (uint8_t)(100 + i); }

  uint8_t msg[kCommitSignedBytes];
  size_t n = buildCommitSignedMessage(target, hash, 0x11223344, msg);
  ASSERT_EQ(kCommitSignedBytes, n);

  // domain prefix, no NUL terminator included.
  EXPECT_EQ(0, std::memcmp(msg, kCommitDomain, kCommitDomainLen));
  // target immediately follows domain.
  EXPECT_EQ(0, std::memcmp(msg + kCommitDomainLen, target, kPubKeyBytes));
  // hash immediately follows target.
  EXPECT_EQ(0, std::memcmp(msg + kCommitDomainLen + kPubKeyBytes, hash, kHashBytes));
  // counter (big-endian) is the final 4 bytes.
  EXPECT_EQ(getBE32(msg + kCommitDomainLen + kPubKeyBytes + kHashBytes), 0x11223344u);
}

TEST(OtaUsbProtocolTest, DifferentTargetProducesDifferentSignedMessage) {
  // Captured-for-A-cannot-commit-B: changing only the target byte range
  // must change the signed message (and therefore invalidate any
  // signature computed over the other target's message).
  uint8_t targetA[kPubKeyBytes]; std::memset(targetA, 0xAA, sizeof(targetA));
  uint8_t targetB[kPubKeyBytes]; std::memset(targetB, 0xBB, sizeof(targetB));
  uint8_t hash[kHashBytes]; std::memset(hash, 0x55, sizeof(hash));

  uint8_t msgA[kCommitSignedBytes];
  uint8_t msgB[kCommitSignedBytes];
  buildCommitSignedMessage(targetA, hash, 7, msgA);
  buildCommitSignedMessage(targetB, hash, 7, msgB);

  EXPECT_NE(0, std::memcmp(msgA, msgB, kCommitSignedBytes));
}

TEST(OtaUsbProtocolTest, FixedWireSizesMatchContract) {
  EXPECT_EQ(158u, kCacheBeginTotalBytes);
  EXPECT_EQ(89u, kCachePutMaxTotalBytes);
  EXPECT_EQ(2u, kCacheSealTotalBytes);
  EXPECT_EQ(34u, kAddTargetTotalBytes);
  EXPECT_EQ(14u, kStartTotalBytes);
  EXPECT_EQ(70u, kCommitTotalBytes);
  EXPECT_EQ(66u, kAbortTotalBytes);
  EXPECT_EQ(34u, kStatusTotalBytes);
  EXPECT_EQ(35u, kSetContactAdminTotalBytes);
  EXPECT_EQ(86u, kReplyBytes);
}

TEST(OtaUsbProtocolTest, AbortSignedMessageBindsOwnDomainTargetAndImageHash) {
  uint8_t target[kPubKeyBytes];
  uint8_t imageHash[kHashBytes];
  for (int i = 0; i < 32; i++) { target[i] = (uint8_t)(200 + i); imageHash[i] = (uint8_t)(50 + i); }

  uint8_t msg[kAbortSignedBytes];
  size_t n = buildAbortSignedMessage(target, imageHash, msg);
  ASSERT_EQ(kAbortSignedBytes, n);

  EXPECT_EQ(0, std::memcmp(msg, kAbortDomain, kAbortDomainLen));
  EXPECT_EQ(0, std::memcmp(msg + kAbortDomainLen, target, kPubKeyBytes));
  EXPECT_EQ(0, std::memcmp(msg + kAbortDomainLen + kPubKeyBytes, imageHash, kHashBytes));

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
