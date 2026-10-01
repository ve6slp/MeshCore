#include "ota/protocol/OtaCommissioningAbi.h"

#include <cstring>
#include <gtest/gtest.h>
#include <vector>

using namespace meshcore::ota::protocol;
namespace {
std::vector<uint8_t> fromHex(const char *text) {
  std::vector<uint8_t> out;
  for (size_t i = 0; text[i];) {
    while (text[i] == ' ' || text[i] == '\n')
      ++i;
    if (!text[i]) break;
    auto digit = [](char c) -> uint8_t { return c <= '9' ? uint8_t(c - '0') : uint8_t((c | 32) - 'a' + 10); };
    out.push_back(uint8_t((digit(text[i]) << 4) | digit(text[i + 1])));
    i += 2;
  }
  return out;
}
bool makeFrame(const OtaControlRequestHeader &h, const uint8_t *payload, size_t payloadLen, uint8_t *out,
               size_t capacity, size_t &outLen) {
  if (capacity < kOtaControlRequestHeaderSize + payloadLen ||
      !encodeOtaControlRequestHeader(h, out, kOtaControlRequestHeaderSize))
    return false;
  for (size_t i = 0; i < payloadLen; ++i)
    out[kOtaControlRequestHeaderSize + i] = payload[i];
  outLen = kOtaControlRequestHeaderSize + payloadLen;
  return true;
}
const char kOpenRequestHex[] =
    "42 20 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 02 03 04 "
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00";
const char kChallengeRequestHex[] = "42 29 01 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f "
                                    "01 02 03 04 11 22 33 44 00 00 00 00 01 00 00 00 00 01 24";
const char kActivationChallengeRequestHex[] = "42 29 01 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f "
                                              "01 02 03 04 11 22 33 44 00 00 00 00 01 00 00 00 00 01 25";
const char kReadReplyHex[] = "1f 27 01 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f "
                             "01 02 03 04 11 22 33 44 01 00 00 00 eb 00 00 00 05 03 aa bb cc";
const char kChallengeReplyHex[] = "1f 29 01 00 00 01 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f "
                                  "01 02 03 04 11 22 33 44 00 00 00 00 00 00 00 00 00 10 "
                                  "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f";
const char kMeasurementHex[] =
    "01 01 02 03 04 05 06 07 08 "
    "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f "
    "01 02 03 04 11 12 13 14 00 00 00 01 a1 a2 a3 a4 "
    "30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f "
    "00 00 12 34 00 02 70 00 "
    "50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f "
    "be ef 00 00 10 00 00 00 20 00 "
    "70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f "
    "00 01 00 02 "
    "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f "
    "a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af "
    "d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb";

TEST(OtaMaintenanceWire, SharedOpenRequestLiteralAndRoundTrip) {
  const auto expected = fromHex(kOpenRequestHex);
  ASSERT_EQ(37u, expected.size());
  OtaControlRequestFrameView view;
  ASSERT_EQ(OtaControlCodecResult::Ok, decodeOtaControlRequestFrame(expected.data(), expected.size(), view));
  EXPECT_EQ(OtaControlSubcommand::Open, view.header.sub);
  EXPECT_EQ(0x01020304u, view.header.requestId);
  // OPEN carries NO payload: no host challenge, no purpose byte -- the
  // device mints and returns the session in its reply.
  EXPECT_EQ(0u, view.payloadLen);
  uint8_t encoded[kOtaControlRequestHeaderSize + kOtaControlMaxDataLen];
  size_t len = 0;
  ASSERT_EQ(OtaControlCodecResult::Ok, encodeOtaControlRequestFrame(view.header, view.data, view.payloadLen,
                                                                    encoded, sizeof(encoded), len));
  EXPECT_EQ(expected, std::vector<uint8_t>(encoded, encoded + len));
}
TEST(OtaMaintenanceWire, ReadObjectUsesDataLenAsRequestedCount) {
  OtaControlRequestHeader h;
  h.sub = OtaControlSubcommand::ReadObject;
  h.session[0] = 1;
  h.requestId = 0x01020304;
  h.objectKind = OtaControlObjectKind::Measurement;
  h.total = 235;
  h.offset = 232;
  h.dataLen = 3;
  uint8_t request[kOtaControlRequestHeaderSize];
  ASSERT_TRUE(encodeOtaControlRequestHeader(h, request, sizeof(request)));
  OtaControlRequestFrameView view;
  ASSERT_EQ(OtaControlCodecResult::Ok, decodeOtaControlRequestFrame(request, sizeof(request), view));
  EXPECT_EQ(0u, view.payloadLen);
  EXPECT_EQ(3u, view.header.dataLen);
  h.offset = 0xfffffffeu;
  EXPECT_EQ(OtaControlCodecResult::RangeOverflow, commissioning_detail::validateRequest(h, 0));
  h.offset = 233;
  EXPECT_EQ(OtaControlCodecResult::RangeOutOfBounds, commissioning_detail::validateRequest(h, 0));
}
TEST(OtaMaintenanceWire, SharedReplyLiteralRoundTripsAndMatchesReadCount) {
  const auto expected = fromHex(kReadReplyHex);
  ASSERT_EQ(43u, expected.size());
  OtaControlReplyHeader h;
  ASSERT_EQ(OtaControlCodecResult::Ok, validateOtaControlReplyFrame(expected.data(), expected.size(), h));
  EXPECT_EQ(OtaControlStatus::Ok, h.status);
  EXPECT_EQ(0x01020304u, h.requestId);
  EXPECT_EQ(3u, h.dataLen);
  uint8_t encoded[kOtaControlMaxReplyWireSize];
  size_t encodedLen = 0;
  ASSERT_EQ(OtaControlCodecResult::Ok,
            encodeOtaControlReplyFrame(h, expected.data() + kOtaControlReplyHeaderSize, h.dataLen, encoded,
                                       sizeof(encoded), encodedLen));
  EXPECT_EQ(expected, std::vector<uint8_t>(encoded, encoded + encodedLen));
  auto unknownReason = expected;
  unknownReason[4] = 0xca;
  unknownReason[5] = 0xfe;
  ASSERT_EQ(OtaControlCodecResult::Ok,
            validateOtaControlReplyFrame(unknownReason.data(), unknownReason.size(), h));
  ASSERT_EQ(OtaControlCodecResult::Ok,
            encodeOtaControlReplyFrame(h, unknownReason.data() + kOtaControlReplyHeaderSize, h.dataLen,
                                       encoded, sizeof(encoded), encodedLen));
  EXPECT_EQ(unknownReason, std::vector<uint8_t>(encoded, encoded + encodedLen));
}
TEST(OtaMaintenanceWire, SharedMeasurementLiteralRoundTripsWithRawSdkBytes) {
  const auto expected = fromHex(kMeasurementHex);
  ASSERT_EQ(235u, expected.size());
  OtaControlMeasurement m;
  ASSERT_EQ(OtaControlCodecResult::Ok, decodeOtaControlMeasurement(expected.data(), expected.size(), m));
  EXPECT_EQ(1u, m.currentRole);
  EXPECT_EQ(0x00010002u, m.bootConfigId);
  EXPECT_EQ(0xd0u, m.rawSdk28[0]);
  EXPECT_EQ(0xebu, m.rawSdk28[27]);
  uint8_t encoded[235];
  size_t n = 0;
  ASSERT_EQ(OtaControlCodecResult::Ok, encodeOtaControlMeasurement(m, encoded, sizeof(encoded), n));
  EXPECT_EQ(expected, std::vector<uint8_t>(encoded, encoded + n));
}
TEST(OtaMaintenanceWire, StrictAdmissionRejectsTamperingWithoutChangingOutput) {
  auto frame = fromHex(kOpenRequestHex);
  OtaControlRequestFrameView out;
  out.header.requestId = 0xfeedbeef;
  out.payloadLen = 9;
  frame[2] = 2;
  EXPECT_EQ(OtaControlCodecResult::UnsupportedVersion,
            decodeOtaControlRequestFrame(frame.data(), frame.size(), out));
  EXPECT_EQ(0xfeedbeefu, out.header.requestId);
  EXPECT_EQ(9u, out.payloadLen);
  frame = fromHex(kOpenRequestHex);
  frame.push_back(0);
  EXPECT_EQ(OtaControlCodecResult::DataLengthMismatch,
            decodeOtaControlRequestFrame(frame.data(), frame.size(), out));
  frame = fromHex(kOpenRequestHex);
  frame[1] = 0x2b;
  EXPECT_EQ(OtaControlCodecResult::UnsupportedSubcommand,
            decodeOtaControlRequestFrame(frame.data(), frame.size(), out));
  frame = fromHex(kOpenRequestHex);
  frame[27] = 11;
  EXPECT_EQ(OtaControlCodecResult::UnsupportedObjectKind,
            decodeOtaControlRequestFrame(frame.data(), frame.size(), out));
  auto m = fromHex(kMeasurementHex);
  m.push_back(0);
  OtaControlMeasurement measurement;
  measurement.profile = 0xabcdef01;
  EXPECT_EQ(OtaControlCodecResult::ExtraFrameBytes,
            decodeOtaControlMeasurement(m.data(), m.size(), measurement));
  EXPECT_EQ(0xabcdef01u, measurement.profile);
  m = fromHex(kMeasurementHex);
  m[0] = 2;
  EXPECT_EQ(OtaControlCodecResult::InvalidMeasurementVersion,
            decodeOtaControlMeasurement(m.data(), m.size(), measurement));
}
TEST(OtaMaintenanceWire, EnforcesSliceAndChallengeReplyBoundaries) {
  OtaControlRequestHeader h;
  h.sub = OtaControlSubcommand::PutFragment;
  h.session[0] = 1;
  h.requestId = 1;
  h.objectKind = OtaControlObjectKind::PreparedRootP683;
  h.total = 683;
  h.dataLen = 128;
  uint8_t payload[128] = {};
  uint8_t bytes[kOtaControlMaxRequestWireSize] = {};
  size_t n = 0;
  ASSERT_EQ(OtaControlCodecResult::Ok,
            encodeOtaControlRequestFrame(h, payload, sizeof(payload), bytes, sizeof(bytes), n));
  OtaControlRequestFrameView view;
  EXPECT_EQ(OtaControlCodecResult::Ok, decodeOtaControlRequestFrame(bytes, n, view));
  h.dataLen = 129;
  EXPECT_EQ(OtaControlCodecResult::DataTooLarge, commissioning_detail::validateRequest(h, 129));
  uint8_t challengeBytes[16] = {};
  uint8_t challengeReply[kOtaControlReplyHeaderSize + kOtaControlChallengeBytes] = {};
  OtaControlReplyHeader reply;
  reply.sub = OtaControlSubcommand::Challenge;
  reply.status = OtaControlStatus::Ok;
  reply.requestId = 5;
  reply.dataLen = 16;
  size_t challengeReplyLen = 0;
  EXPECT_EQ(OtaControlCodecResult::Ok,
            encodeOtaControlReplyFrame(reply, challengeBytes, sizeof(challengeBytes), challengeReply,
                                       sizeof(challengeReply), challengeReplyLen));
  EXPECT_EQ(OtaControlCodecResult::Ok,
            validateOtaControlReplyFrame(challengeReply, challengeReplyLen, reply));
}
TEST(OtaMaintenanceWire, EverySubcommandStatusAndObjectKindIsCovered) {
  const OtaControlSubcommand commands[] = { OtaControlSubcommand::Measure, OtaControlSubcommand::Certify,
                                            OtaControlSubcommand::Prepare, OtaControlSubcommand::Activate,
                                            OtaControlSubcommand::Poll,    OtaControlSubcommand::Cancel,
                                            OtaControlSubcommand::Close };
  for (const auto sub : commands) {
    OtaControlRequestHeader request;
    request.sub = sub;
    request.session[0] = 1;
    request.requestId = static_cast<uint32_t>(sub);
    uint8_t frame[kOtaControlRequestHeaderSize];
    size_t frameLen = 0;
    ASSERT_EQ(OtaControlCodecResult::Ok,
              encodeOtaControlRequestFrame(request, nullptr, 0, frame, sizeof(frame), frameLen))
        << static_cast<unsigned>(sub);
    OtaControlRequestFrameView parsed;
    ASSERT_EQ(OtaControlCodecResult::Ok, decodeOtaControlRequestFrame(frame, frameLen, parsed));
    EXPECT_EQ(sub, parsed.header.sub);
  }

  for (uint8_t kind = static_cast<uint8_t>(OtaControlObjectKind::Measurement);
       kind <= static_cast<uint8_t>(OtaControlObjectKind::PrepareInput626); ++kind) {
    OtaControlRequestHeader request;
    request.sub = OtaControlSubcommand::PutFragment;
    request.session[0] = 1;
    request.requestId = kind;
    request.objectKind = static_cast<OtaControlObjectKind>(kind);
    request.total = otaControlObjectKindFixedSize(request.objectKind);
    request.dataLen = 1;
    const uint8_t payload = kind;
    uint8_t frame[kOtaControlRequestHeaderSize + 1];
    size_t frameLen = 0;
    ASSERT_EQ(OtaControlCodecResult::Ok,
              encodeOtaControlRequestFrame(request, &payload, 1, frame, sizeof(frame), frameLen))
        << unsigned(kind);
    OtaControlRequestFrameView parsed;
    ASSERT_EQ(OtaControlCodecResult::Ok, decodeOtaControlRequestFrame(frame, frameLen, parsed));
    EXPECT_EQ(request.objectKind, parsed.header.objectKind);
  }

  for (uint8_t status = 0; status <= static_cast<uint8_t>(OtaControlStatus::NoCapacity); ++status) {
    OtaControlReplyHeader reply;
    reply.sub = OtaControlSubcommand::Poll;
    reply.status = static_cast<OtaControlStatus>(status);
    reply.requestId = 1;
    uint8_t frame[kOtaControlReplyHeaderSize];
    size_t frameLen = 0;
    ASSERT_EQ(OtaControlCodecResult::Ok,
              encodeOtaControlReplyFrame(reply, nullptr, 0, frame, sizeof(frame), frameLen))
        << unsigned(status);
    OtaControlReplyHeader parsed;
    ASSERT_EQ(OtaControlCodecResult::Ok, validateOtaControlReplyFrame(frame, frameLen, parsed));
    EXPECT_EQ(status, static_cast<uint8_t>(parsed.status));
  }
}

TEST(OtaMaintenanceWire, ChallengeRequestGoldenVectorBindsAuthorizationPurpose) {
  // CHALLENGE is an inline CONTROL payload, not a transferred object:
  // Kind=None, total=dataLen=1, offset=0; the single payload byte is the
  // literal target subcommand value (Prepare=0x24 or Activate=0x25).
  const auto expected = fromHex(kChallengeRequestHex);
  ASSERT_EQ(kOtaControlRequestHeaderSize + 1u, expected.size());
  OtaControlRequestFrameView parsed;
  ASSERT_EQ(OtaControlCodecResult::Ok,
            decodeOtaControlRequestFrame(expected.data(), expected.size(), parsed));
  EXPECT_EQ(OtaControlSubcommand::Challenge, parsed.header.sub);
  EXPECT_EQ(0x11223344u, parsed.header.jobTicket);
  EXPECT_EQ(OtaControlObjectKind::None, parsed.header.objectKind);
  ASSERT_EQ(1u, parsed.payloadLen);
  EXPECT_EQ(static_cast<uint8_t>(OtaControlSubcommand::Prepare), parsed.data[0]);
  EXPECT_TRUE(otaControlIsValidChallengePurposeByte(parsed.data[0]));

  uint8_t encoded[kOtaControlRequestHeaderSize + 1];
  size_t encodedLen = 0;
  ASSERT_EQ(OtaControlCodecResult::Ok,
            encodeOtaControlRequestFrame(parsed.header, parsed.data, parsed.payloadLen, encoded,
                                         sizeof(encoded), encodedLen));
  EXPECT_EQ(expected, std::vector<uint8_t>(encoded, encoded + encodedLen));

  // A purpose byte that isn't Prepare/Activate is a shape violation at the
  // header-decode layer only in the sense that the BYTE value itself is a
  // router-level semantic check (validateRequest only enforces the
  // structural 1-byte-inline shape); confirm the byte-value helper
  // correctly rejects an unrelated subcommand value like Measure (0x21).
  EXPECT_FALSE(otaControlIsValidChallengePurposeByte(static_cast<uint8_t>(OtaControlSubcommand::Measure)));

  // objectKind must stay None for Challenge -- any other kind is now an
  // invalid shape (Challenge no longer encodes purpose via objectKind).
  OtaControlRequestHeader invalid = parsed.header;
  invalid.objectKind = OtaControlObjectKind::PrepareAuth267;
  OtaControlRequestFrameView unchanged;
  unchanged.header.requestId = 0xabcdef01;
  std::vector<uint8_t> invalidFrame = expected;
  invalidFrame[27] = static_cast<uint8_t>(OtaControlObjectKind::PrepareAuth267);
  EXPECT_EQ(OtaControlCodecResult::InvalidOperationShape,
            decodeOtaControlRequestFrame(invalidFrame.data(), invalidFrame.size(), unchanged));
  EXPECT_EQ(0xabcdef01u, unchanged.header.requestId);
  EXPECT_EQ(OtaControlCodecResult::InvalidOperationShape, commissioning_detail::validateRequest(invalid, 1));

  invalid = parsed.header;
  const auto activationLiteral = fromHex(kActivationChallengeRequestHex);
  ASSERT_EQ(OtaControlCodecResult::Ok,
            decodeOtaControlRequestFrame(activationLiteral.data(), activationLiteral.size(), parsed));
  ASSERT_EQ(1u, parsed.payloadLen);
  EXPECT_EQ(static_cast<uint8_t>(OtaControlSubcommand::Activate), parsed.data[0]);
  EXPECT_TRUE(otaControlIsValidChallengePurposeByte(parsed.data[0]));
  uint8_t activationEncoded[kOtaControlRequestHeaderSize + 1];
  size_t activationEncodedLen = 0;
  ASSERT_EQ(OtaControlCodecResult::Ok,
            encodeOtaControlRequestFrame(parsed.header, parsed.data, parsed.payloadLen, activationEncoded,
                                         sizeof(activationEncoded), activationEncodedLen));
  EXPECT_EQ(activationLiteral,
            std::vector<uint8_t>(activationEncoded, activationEncoded + activationEncodedLen));

  EXPECT_EQ(OtaControlCodecResult::Ok, commissioning_detail::validateRequest(invalid, 1));
  invalid.jobTicket = 0; // Challenge no longer requires a nonzero jobTicket -- only shape + open
                         // session are checked at the codec layer; a zero jobTicket is harmless here.
  std::memset(invalid.session, 0, sizeof(invalid.session));
  EXPECT_EQ(OtaControlCodecResult::InvalidSession, commissioning_detail::validateRequest(invalid, 1));
}

TEST(OtaMaintenanceWire, ChallengeSuccessAndRefusalHaveDistinctCompleteShapes) {
  const auto expected = fromHex(kChallengeReplyHex);
  ASSERT_EQ(kOtaControlReplyHeaderSize + kOtaControlChallengeBytes, expected.size());
  OtaControlReplyHeader reply;
  ASSERT_EQ(OtaControlCodecResult::Ok, validateOtaControlReplyFrame(expected.data(), expected.size(), reply));
  EXPECT_EQ(OtaControlSubcommand::Challenge, reply.sub);
  EXPECT_EQ(0x01020304u, reply.requestId);
  EXPECT_EQ(0x11223344u, reply.jobTicket);
  EXPECT_EQ(16u, reply.dataLen);
  uint8_t encoded[kOtaControlMaxReplyWireSize];
  size_t encodedLen = 0;
  ASSERT_EQ(OtaControlCodecResult::Ok,
            encodeOtaControlReplyFrame(reply, expected.data() + kOtaControlReplyHeaderSize,
                                       kOtaControlChallengeBytes, encoded, sizeof(encoded), encodedLen));
  EXPECT_EQ(expected, std::vector<uint8_t>(encoded, encoded + encodedLen));

  reply.status = OtaControlStatus::Denied;
  reply.dataLen = 0;
  reply.reason = static_cast<uint16_t>(OtaControlReason::NoSession);
  ASSERT_EQ(OtaControlCodecResult::Ok,
            encodeOtaControlReplyFrame(reply, nullptr, 0, encoded, sizeof(encoded), encodedLen));
  EXPECT_EQ(OtaControlCodecResult::Ok, validateOtaControlReplyFrame(encoded, encodedLen, reply));
}

} // namespace
int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
