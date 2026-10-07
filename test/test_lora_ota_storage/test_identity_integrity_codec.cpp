// Native, production-code coverage for identity_io::checkIdentityIntegrity()
// (see src/helpers/IdentityIntegrityCodec.h), the shared bounded-read +
// content-comparison decision IdentityStore::checkIntegrity() uses to
// validate the MANDATORY on-disk identity artifact during OTA trial-
// health checks. Driven here against a plain byte-backed fake file so a
// genuine regression in the "short read", "corrupted/mismatched
// content", or "exact-length success" decision is caught natively, not
// merely by full MCU compilation.
#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>
#include <vector>

#include "helpers/IdentityIntegrityCodec.h"

namespace {

constexpr size_t kPub = 32;
constexpr size_t kPrv = 64;

// Byte-backed fake file: `read()` returns however many bytes are
// actually available (never blocks/waits), matching the real
// Adafruit_LittleFS::File::read()/fs::File::read() "return what's there
// right now" bounded semantics -- unlike Stream::readBytes(), which
// this codec deliberately avoids.
class FakeIdentityFile {
public:
  explicit FakeIdentityFile(std::vector<uint8_t> content) : _content(std::move(content)) {}

  int read(uint8_t* buf, size_t len) {
    size_t avail = _content.size() - _pos;
    size_t n = (len < avail) ? len : avail;
    memcpy(buf, _content.data() + _pos, n);
    _pos += n;
    return (int)n;
  }

private:
  std::vector<uint8_t> _content;
  size_t _pos = 0;
};

std::vector<uint8_t> makeIdentityBytes(uint8_t pub_fill, uint8_t prv_fill) {
  std::vector<uint8_t> v(kPub + kPrv);
  memset(v.data(), pub_fill, kPub);
  memset(v.data() + kPub, prv_fill, kPrv);
  return v;
}

}  // namespace

TEST(IdentityIntegrityCodecTest, ExactMatchingContentReportsHealthy) {
  auto bytes = makeIdentityBytes(0xAA, 0xBB);
  FakeIdentityFile file(bytes);
  uint8_t expected_pub[kPub]; memset(expected_pub, 0xAA, kPub);
  uint8_t expected_prv[kPrv]; memset(expected_prv, 0xBB, kPrv);
  uint8_t scratch[kPub + kPrv];
  EXPECT_TRUE(identity_io::checkIdentityIntegrity(file, kPub, kPrv, expected_pub, expected_prv, scratch, sizeof(scratch)));
}

TEST(IdentityIntegrityCodecTest, MismatchedPubKeyContentIsRejectedNotJustLength) {
  // Well-formed, exact-length, but a DIFFERENT (foreign/stale) identity --
  // this is the exact case a length-only check would wrongly accept.
  auto bytes = makeIdentityBytes(0xAA, 0xBB);
  FakeIdentityFile file(bytes);
  uint8_t expected_pub[kPub]; memset(expected_pub, 0xCC, kPub);  // different pub_key
  uint8_t expected_prv[kPrv]; memset(expected_prv, 0xBB, kPrv);
  uint8_t scratch[kPub + kPrv];
  EXPECT_FALSE(identity_io::checkIdentityIntegrity(file, kPub, kPrv, expected_pub, expected_prv, scratch, sizeof(scratch)));
}

TEST(IdentityIntegrityCodecTest, MismatchedPrvKeyContentIsRejected) {
  auto bytes = makeIdentityBytes(0xAA, 0xBB);
  FakeIdentityFile file(bytes);
  uint8_t expected_pub[kPub]; memset(expected_pub, 0xAA, kPub);
  uint8_t expected_prv[kPrv]; memset(expected_prv, 0xDD, kPrv);  // different prv_key
  uint8_t scratch[kPub + kPrv];
  EXPECT_FALSE(identity_io::checkIdentityIntegrity(file, kPub, kPrv, expected_pub, expected_prv, scratch, sizeof(scratch)));
}

TEST(IdentityIntegrityCodecTest, ShortReadIsRejectedNotTreatedAsPartialSuccess) {
  std::vector<uint8_t> truncated(kPub + kPrv - 10, 0xAA);  // genuinely short/corrupt file
  FakeIdentityFile file(truncated);
  uint8_t expected_pub[kPub]; memset(expected_pub, 0xAA, kPub);
  uint8_t expected_prv[kPrv]; memset(expected_prv, 0xAA, kPrv);
  uint8_t scratch[kPub + kPrv];
  EXPECT_FALSE(identity_io::checkIdentityIntegrity(file, kPub, kPrv, expected_pub, expected_prv, scratch, sizeof(scratch)));
}

TEST(IdentityIntegrityCodecTest, EmptyFileIsRejected) {
  FakeIdentityFile file({});
  uint8_t expected_pub[kPub]; memset(expected_pub, 0xAA, kPub);
  uint8_t expected_prv[kPrv]; memset(expected_prv, 0xAA, kPrv);
  uint8_t scratch[kPub + kPrv];
  EXPECT_FALSE(identity_io::checkIdentityIntegrity(file, kPub, kPrv, expected_pub, expected_prv, scratch, sizeof(scratch)));
}

TEST(IdentityIntegrityCodecTest, UndersizedScratchBufferIsRefusedNeverOverrun) {
  auto bytes = makeIdentityBytes(0xAA, 0xBB);
  FakeIdentityFile file(bytes);
  uint8_t expected_pub[kPub]; memset(expected_pub, 0xAA, kPub);
  uint8_t expected_prv[kPrv]; memset(expected_prv, 0xBB, kPrv);
  uint8_t scratch[4];  // deliberately too small
  EXPECT_FALSE(identity_io::checkIdentityIntegrity(file, kPub, kPrv, expected_pub, expected_prv, scratch, sizeof(scratch)));
}
