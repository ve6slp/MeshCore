#include <gtest/gtest.h>
#include <cstring>
#include "ota/protocol/OtaDescriptor.h"

using namespace meshcore::ota::protocol;

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
  const uint8_t expected[] = {
      0x12, 0x34, 0x56, 0x78, 7,
      0x08, 0, 0, 0, 0, 0x0c, 0x60, 0,
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
      16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
      0, 0, 0, 42, 0, 0, 0, 15, 0, 1, 0, 2, 0, 3};
  ASSERT_EQ(sizeof(expected), outLen);
  EXPECT_EQ(0, std::memcmp(expected, buf, sizeof(expected)));

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

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
