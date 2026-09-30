#if defined(MESHCORE_OTA_CRYPTO_NATIVE)

#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include <ota/trust/OtaAeadCipher.h>
#include <ota/trust/Sha256.h>

using ota::trust::OtaAeadCipher;
using meshcore::ota::runtime::OtaAeadFrame;

namespace {

size_t checks = 0;

std::vector<uint8_t> fromHex(const char* hex) {
  const size_t len = std::strlen(hex);
  assert((len % 2) == 0);
  std::vector<uint8_t> bytes(len / 2);
  for (size_t i = 0; i < bytes.size(); ++i) {
    unsigned value = 0;
    assert(std::sscanf(hex + 2 * i, "%2x", &value) == 1);
    bytes[i] = static_cast<uint8_t>(value);
  }
  return bytes;
}

struct RfcVector {
  std::array<uint8_t, 32> key{};
  std::vector<uint8_t> nonce = fromHex("070000004041424344454647");
  std::vector<uint8_t> ad = fromHex("50515253c0c1c2c3c4c5c6c7");
  std::vector<uint8_t> ciphertext = fromHex(
      "d31a8d34648e60db7b86afbc53ef7ec2"
      "a4aded51296e08fea9e2b5a736ee62d6"
      "3dbea45e8ca9671282fafb69da92728b"
      "1a71de0a9e060b2905d6a5b67ecd3b36"
      "92ddbd7f2d778b8c9803aee328091b58"
      "fab324e4fad675945585808b4831d7bc"
      "3ff4def08e4b7a9de576d26586cec64b"
      "6116");
  std::vector<uint8_t> tag = fromHex("1ae10b594f09e26a7e902ecbd0600691");

  RfcVector() {
    for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(0x80 + i);
  }
};

void knownAnswer() {
  // RFC 8439 section 2.8.2; plaintext hash independently checked with
  // Python cryptography, not derived by the C++ implementation under test.
  const RfcVector v;
  OtaAeadCipher cipher;
  std::vector<uint8_t> plaintext(v.ciphertext.size());
  assert(cipher.open(v.key.data(), v.nonce.data(), v.ad.data(), v.ad.size(),
                     v.ciphertext.data(), v.ciphertext.size(), v.tag.data(), plaintext.data()));
  uint8_t digest[32];
  ota::trust::Sha256::hash(plaintext.data(), plaintext.size(), digest);
  const auto expectedHash = fromHex("34dbfcbbe73c59195a7ac563b41b82f334845053c707b83d8179d7b165778b19");
  assert(std::memcmp(digest, expectedHash.data(), sizeof(digest)) == 0);
  std::vector<uint8_t> sealed(plaintext.size());
  std::array<uint8_t, 16> tag{};
  assert(OtaAeadCipher::seal(v.key.data(), v.nonce.data(), v.ad.data(), v.ad.size(),
                           plaintext.data(), plaintext.size(), sealed.data(), tag.data()));
  assert(sealed == v.ciphertext);
  assert(std::memcmp(tag.data(), v.tag.data(), tag.size()) == 0);
  ++checks;
}

void rejectsTamperingWithoutPlaintextRelease() {
  const RfcVector original;
  OtaAeadCipher cipher;
  for (unsigned field = 0; field < 5; ++field) {
    const size_t count = field == 0 ? original.tag.size() :
                         field == 1 ? original.ciphertext.size() :
                         field == 2 ? original.ad.size() :
                         field == 3 ? original.nonce.size() : original.key.size();
    const unsigned bits = field == 0 ? 8 : 1;
    for (size_t byte = 0; byte < count; ++byte) {
      for (unsigned bit = 0; bit < bits; ++bit) {
        RfcVector v;
        uint8_t* changed = field == 0 ? v.tag.data() :
                           field == 1 ? v.ciphertext.data() :
                           field == 2 ? v.ad.data() :
                           field == 3 ? v.nonce.data() : v.key.data();
        changed[byte] ^= static_cast<uint8_t>(1u << bit);
        std::array<uint8_t, OtaAeadCipher::kMaxPlaintextBytes> output;
        output.fill(0xA5);
        const auto before = output;
        assert(!cipher.open(v.key.data(), v.nonce.data(), v.ad.data(), v.ad.size(),
                            v.ciphertext.data(), v.ciphertext.size(), v.tag.data(), output.data()));
        assert(output == before);
        ++checks;
      }
    }
  }
  std::vector<uint8_t> output(original.ciphertext.size());
  assert(cipher.open(original.key.data(), original.nonce.data(), original.ad.data(), original.ad.size(),
                     original.ciphertext.data(), original.ciphertext.size(), original.tag.data(), output.data()));
  ++checks;
}

void everyAllowedLengthAndRejectedBoundary() {
  const RfcVector v;
  std::array<uint8_t, OtaAeadCipher::kMaxPlaintextBytes> plaintext{}, encrypted{}, output{};
  std::array<uint8_t, 16> tag{};
  OtaAeadCipher cipher;
  for (size_t i = 0; i < plaintext.size(); ++i) plaintext[i] = static_cast<uint8_t>(i);
  for (size_t len = OtaAeadCipher::kMinPlaintextBytes; len <= plaintext.size(); ++len) {
    assert(OtaAeadCipher::seal(v.key.data(), v.nonce.data(), nullptr, 0,
                             plaintext.data(), len, encrypted.data(), tag.data()));
    output.fill(0xA5);
    assert(cipher.open(v.key.data(), v.nonce.data(), nullptr, 0,
                       encrypted.data(), len, tag.data(), output.data()));
    assert(std::memcmp(output.data(), plaintext.data(), len) == 0);
    for (size_t i = len; i < output.size(); ++i) assert(output[i] == 0xA5);
    ++checks;
  }
  for (const size_t len : {size_t{0}, size_t{20}, size_t{157}, SIZE_MAX}) {
    encrypted.fill(0xA5);
    output.fill(0xA5);
    tag.fill(0xA5);
    const auto beforeCiphertext = encrypted;
    const auto beforePlaintext = output;
    const auto beforeTag = tag;
    assert(!OtaAeadCipher::seal(v.key.data(), v.nonce.data(), v.ad.data(), v.ad.size(),
                              plaintext.data(), len, encrypted.data(), tag.data()));
    assert(!cipher.open(v.key.data(), v.nonce.data(), v.ad.data(), v.ad.size(),
                        encrypted.data(), len, tag.data(), output.data()));
    assert(encrypted == beforeCiphertext && output == beforePlaintext && tag == beforeTag);
    ++checks;
  }
}

void invalidPointers() {
  const RfcVector v;
  OtaAeadCipher cipher;
  std::array<uint8_t, 156> output;
  std::array<uint8_t, 16> tag;
  for (unsigned field = 0; field < 6; ++field) {
    output.fill(0xA5);
    tag.fill(0xA5);
    const auto beforeOutput = output;
    const auto beforeTag = tag;
    assert(!OtaAeadCipher::seal(field == 0 ? nullptr : v.key.data(),
                              field == 1 ? nullptr : v.nonce.data(),
                              field == 2 ? nullptr : v.ad.data(), v.ad.size(),
                              field == 3 ? nullptr : v.ciphertext.data(), v.ciphertext.size(),
                              field == 4 ? nullptr : output.data(), field == 5 ? nullptr : tag.data()));
    assert(output == beforeOutput && tag == beforeTag);
    assert(!cipher.open(field == 0 ? nullptr : v.key.data(),
                        field == 1 ? nullptr : v.nonce.data(),
                        field == 2 ? nullptr : v.ad.data(), v.ad.size(),
                        field == 3 ? nullptr : v.ciphertext.data(), v.ciphertext.size(),
                        field == 4 ? nullptr : v.tag.data(), field == 5 ? nullptr : output.data()));
    assert(output == beforeOutput);
    ++checks;
  }
}

void otaFramingAndAssociatedData() {
  const RfcVector v;
  OtaAeadCipher cipher;
  const uint8_t header[3] = {0xA1, 0x11, 0x22};
  std::array<uint8_t, 28> ad{};
  size_t adLen = 0;
  assert(OtaAeadFrame::associatedDataBytes() == ad.size());
  assert(OtaAeadFrame::buildAssociatedData(header, 0x01020304, 156, ad.data(), ad.size(), &adLen));
  const auto golden = fromHex("4d657368436f72652f4f54412f41454144310ca1112201020304009c");
  assert(adLen == golden.size() && std::memcmp(ad.data(), golden.data(), adLen) == 0);
  const auto before = ad;
  assert(!OtaAeadFrame::buildAssociatedData(nullptr, 1, 156, ad.data(), ad.size(), &adLen));
  assert(ad == before);
  ++checks;

  for (const uint8_t form : {uint8_t{0xA1}, uint8_t{0xA2}}) {
    for (const size_t len : {size_t{21}, size_t{155}, size_t{156}}) {
      std::vector<uint8_t> plaintext(len, 0x71);
      std::vector<uint8_t> frame(len + 23);
      frame[0] = form;
      frame[1] = 0x11;
      frame[2] = 0x22;
      OtaAeadFrame::encodeSequence(0x01020304, frame.data() + 3);
      assert(OtaAeadFrame::buildAssociatedData(frame.data(), 0x01020304, len,
                                              ad.data(), ad.size(), &adLen));
      assert(OtaAeadCipher::seal(v.key.data(), v.nonce.data(), ad.data(), adLen,
                                plaintext.data(), len, frame.data() + 7, frame.data() + 7 + len));
      auto parsed = OtaAeadFrame::parse(frame.data(), frame.size());
      assert(parsed.ok && parsed.sequence == 0x01020304 && parsed.ciphertext_len == len);
      std::vector<uint8_t> opened(len);
      assert(cipher.open(v.key.data(), v.nonce.data(), ad.data(), adLen,
                         parsed.ciphertext, parsed.ciphertext_len, parsed.tag, opened.data()));
      assert(opened == plaintext);
      for (size_t byte = 0; byte < 7; ++byte) {
        frame[byte] ^= 1;
        parsed = OtaAeadFrame::parse(frame.data(), frame.size());
        if (parsed.ok) {
          assert(OtaAeadFrame::buildAssociatedData(frame.data(), parsed.sequence, parsed.ciphertext_len,
                                                  ad.data(), ad.size(), &adLen));
          opened.assign(len, 0xA5);
          const auto untouched = opened;
          assert(!cipher.open(v.key.data(), v.nonce.data(), ad.data(), adLen,
                              parsed.ciphertext, parsed.ciphertext_len, parsed.tag, opened.data()));
          assert(opened == untouched);
        }
        frame[byte] ^= 1;
        ++checks;
      }
      frame.pop_back();
      parsed = OtaAeadFrame::parse(frame.data(), frame.size());
      if (parsed.ok) {
        assert(OtaAeadFrame::buildAssociatedData(frame.data(), parsed.sequence, parsed.ciphertext_len,
                                                ad.data(), ad.size(), &adLen));
        opened.assign(len, 0xA5);
        const auto untouched = opened;
        assert(!cipher.open(v.key.data(), v.nonce.data(), ad.data(), adLen,
                            parsed.ciphertext, parsed.ciphertext_len, parsed.tag, opened.data()));
        assert(opened == untouched);
      }
      ++checks;
    }
  }
  std::array<uint8_t, 180> oversized{};
  oversized[0] = 0xA1;
  assert(!OtaAeadFrame::parse(oversized.data(), oversized.size()).ok);
  ++checks;
}

} // namespace

int main() {
  knownAnswer();
  rejectsTamperingWithoutPlaintextRelease();
  everyAllowedLengthAndRejectedBoundary();
  invalidPointers();
  otaFramingAndAssociatedData();
  std::printf("OTA real ChaCha20-Poly1305: %zu checks passed\n", checks);
}

#endif
