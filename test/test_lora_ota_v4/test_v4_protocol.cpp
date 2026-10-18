#include <gtest/gtest.h>
#include <helpers/ota/OtaV4Protocol.h>

using namespace mesh::ota::v4;

TEST(OtaV4Protocol, TransfersFullAndFinalSlicesWithoutSignatures) {
  uint8_t tag[kTagBytes] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint8_t data[kSliceBytes];
  for (size_t i = 0; i < sizeof(data); ++i) data[i] = static_cast<uint8_t>(i);
  uint8_t wire[kMaxFrameBytes];
  const auto size = encodeFrame(Kind::Data, 0x12345678, tag, 63, 8192, 63,
                                data, sizeof(data), wire, sizeof(wire));
  ASSERT_EQ(151u, size);
  Frame frame;
  ASSERT_TRUE(decodeFrame(wire, size, frame));
  EXPECT_EQ(Kind::Data, frame.kind);
  EXPECT_EQ(0x12345678u, frame.attempt);
  EXPECT_EQ(63u, frame.object);
  EXPECT_EQ(8192u, frame.total);
  EXPECT_EQ(63u, frame.slice);
  EXPECT_EQ(0, std::memcmp(tag, frame.tag, sizeof(tag)));
  EXPECT_EQ(0, std::memcmp(data, frame.data, sizeof(data)));

  const auto last = encodeFrame(Kind::Data, 0x12345679, tag, 0, 129, 1,
                                data, 1, wire, sizeof(wire));
  ASSERT_EQ(24u, last);
  ASSERT_TRUE(decodeFrame(wire, last, frame));
  EXPECT_EQ(1u, frame.size);
  EXPECT_EQ(3u, sliceMask(frame.total));
}

TEST(OtaV4Protocol, RejectsCorruptionAndImpossibleGeometry) {
  uint8_t tag[kTagBytes] = {};
  uint8_t data[kSliceBytes] = {};
  uint8_t wire[kMaxFrameBytes];
  const auto size = encodeFrame(Kind::Manifest, 1, tag, 0, 128, 0,
                                data, sizeof(data), wire, sizeof(wire));
  ASSERT_NE(0u, size);
  Frame frame;
  wire[kFrameHeaderBytes] ^= 1;
  EXPECT_FALSE(decodeFrame(wire, size, frame));
  wire[kFrameHeaderBytes] ^= 1;
  EXPECT_FALSE(decodeFrame(wire, size - 1, frame));
  wire[18] = 1;
  write32(wire + size - kFrameTrailerBytes, crc32(wire, size - kFrameTrailerBytes));
  EXPECT_FALSE(decodeFrame(wire, size, frame));
  EXPECT_EQ(0u, encodeFrame(Kind::Data, 1, tag, 0, 8193, 0,
                            data, sizeof(data), wire, sizeof(wire)));
  EXPECT_EQ(0u, encodeFrame(Kind::Data, 0, tag, 0, 128, 0,
                            data, sizeof(data), wire, sizeof(wire)));
  EXPECT_EQ(0u, encodeFrame(Kind::Data, 1, tag, 0, 128, 0,
                            data, sizeof(data), wire, sizeof(wire) - 1));
}

TEST(OtaV4Protocol, DistinguishesMeshRetriesAndRejectsEarlierProtocol) {
  uint8_t tag[kTagBytes] = {};
  uint8_t data[1] = {42};
  uint8_t first[kMaxFrameBytes], retry[kMaxFrameBytes];
  const auto size = encodeFrame(Kind::Data, 7, tag, 0, 1, 0, data, 1, first, sizeof(first));
  ASSERT_NE(0u, size);
  ASSERT_EQ(size, encodeFrame(Kind::Data, 8, tag, 0, 1, 0, data, 1, retry, sizeof(retry)));
  EXPECT_NE(0, std::memcmp(first, retry, size));
  Frame frame;
  ASSERT_TRUE(decodeFrame(first, size, frame));
  ASSERT_TRUE(decodeFrame(retry, size, frame));
  EXPECT_EQ(8u, frame.attempt);
  first[0] = 3;
  write32(first + size - kFrameTrailerBytes, crc32(first, size - kFrameTrailerBytes));
  EXPECT_FALSE(decodeFrame(first, size, frame));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
