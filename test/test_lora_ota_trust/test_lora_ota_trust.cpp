// gtest suite for the OTA trust layer: SHA-256 known-answer vectors,
// Ed25519 known-answer vectors (RFC 8032), and the fail-closed
// DescriptorVerifier pipeline built on genuine sign/verify round trips.

#include <gtest/gtest.h>
#include <stdint.h>
#include <cstring>
#include <vector>
#include <string>
#include <memory>

#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashRegion.h"
#include "ota/trust/Sha256.h"
#include "ota/trust/Ed25519SignatureVerifier.h"
#include "ota/trust/TrustTypes.h"
#include "ota/trust/CanonicalDescriptor.h"
#include "ota/trust/DescriptorVerifier.h"

#include "FakeMonotonicCounter.h"
#include "Ed25519TestSigner.h"
#include "../test_lora_ota_storage/FakeNorFlash.h"

namespace {

// -----------------------------------------------------------------------
// Hex helpers (test-only, not part of the production trust pipeline).
// -----------------------------------------------------------------------

int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::vector<uint8_t> hexToBytes(const char* hex) {
  std::vector<uint8_t> out;
  size_t len = std::strlen(hex);
  for (size_t i = 0; i + 1 < len; i += 2) {
    int hi = hexNibble(hex[i]);
    int lo = hexNibble(hex[i + 1]);
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

// -----------------------------------------------------------------------
// SHA-256 known-answer tests (FIPS 180-4 / NIST CAVP short/long vectors).
// -----------------------------------------------------------------------

std::string toHex(const uint8_t* data, size_t len) {
  static const char* kDigits = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(kDigits[data[i] >> 4]);
    out.push_back(kDigits[data[i] & 0x0F]);
  }
  return out;
}

}  // namespace

TEST(Sha256KnownAnswer, EmptyString) {
  uint8_t digest[32];
  ota::trust::Sha256::hash(reinterpret_cast<const uint8_t*>(""), 0, digest);
  EXPECT_EQ(toHex(digest, 32), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Sha256KnownAnswer, Abc) {
  const char* msg = "abc";
  uint8_t digest[32];
  ota::trust::Sha256::hash(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg), digest);
  EXPECT_EQ(toHex(digest, 32), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256KnownAnswer, TwoBlockMessage) {
  // NIST/FIPS 180-2 multi-block known-answer vector.
  const char* msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  uint8_t digest[32];
  ota::trust::Sha256::hash(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg), digest);
  EXPECT_EQ(toHex(digest, 32), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Sha256KnownAnswer, StreamingMatchesOneShot) {
  const char* msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  size_t len = std::strlen(msg);

  uint8_t one_shot[32];
  ota::trust::Sha256::hash(reinterpret_cast<const uint8_t*>(msg), len, one_shot);

  ota::trust::Sha256 streamed;
  streamed.update(reinterpret_cast<const uint8_t*>(msg), 3);
  streamed.update(reinterpret_cast<const uint8_t*>(msg) + 3, len - 3);
  uint8_t streamed_digest[32];
  streamed.finish(streamed_digest);

  EXPECT_EQ(0, std::memcmp(one_shot, streamed_digest, 32));
}

// -----------------------------------------------------------------------
// Ed25519 known-answer tests (RFC 8032 section 7.1 test vectors, retrieved
// verbatim from https://www.rfc-editor.org/rfc/rfc8032.txt).
// -----------------------------------------------------------------------

TEST(Ed25519KnownAnswer, Rfc8032Test1EmptyMessage) {
  std::vector<uint8_t> pub =
      hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  std::vector<uint8_t> sig = hexToBytes(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61"
      "e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

  ota::trust::Ed25519SignatureVerifier verifier;
  EXPECT_TRUE(verifier.verify(sig.data(), sig.size(), nullptr, 0, pub.data(), pub.size()));

  // Tamper with one byte of the signature: must fail closed.
  std::vector<uint8_t> tampered_sig = sig;
  tampered_sig[0] ^= 0x01;
  EXPECT_FALSE(verifier.verify(tampered_sig.data(), tampered_sig.size(), nullptr, 0, pub.data(), pub.size()));
}

TEST(Ed25519KnownAnswer, Rfc8032Test2OneByteMessage) {
  std::vector<uint8_t> pub =
      hexToBytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
  std::vector<uint8_t> msg = hexToBytes("72");
  std::vector<uint8_t> sig = hexToBytes(
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458"
      "f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

  ota::trust::Ed25519SignatureVerifier verifier;
  EXPECT_TRUE(verifier.verify(sig.data(), sig.size(), msg.data(), msg.size(), pub.data(), pub.size()));

  std::vector<uint8_t> wrong_msg = hexToBytes("73");
  EXPECT_FALSE(verifier.verify(sig.data(), sig.size(), wrong_msg.data(), wrong_msg.size(), pub.data(), pub.size()));
}

TEST(Ed25519KnownAnswer, Rfc8032Test3TwoByteMessage) {
  std::vector<uint8_t> pub =
      hexToBytes("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
  std::vector<uint8_t> msg = hexToBytes("af82");
  std::vector<uint8_t> sig = hexToBytes(
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae6"
      "7f760984dc6594a7c15e9716ed28dc027beceea1ec40a");

  ota::trust::Ed25519SignatureVerifier verifier;
  EXPECT_TRUE(verifier.verify(sig.data(), sig.size(), msg.data(), msg.size(), pub.data(), pub.size()));
}

TEST(Ed25519KnownAnswer, Rfc8032TestShaAbc) {
  std::vector<uint8_t> pub =
      hexToBytes("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
  std::vector<uint8_t> msg = hexToBytes(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836b"
      "a3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  std::vector<uint8_t> sig = hexToBytes(
      "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdf"
      "bc7c66431e0303dca179c138ac17ad9bef1177331a704");

  ota::trust::Ed25519SignatureVerifier verifier;
  EXPECT_TRUE(verifier.verify(sig.data(), sig.size(), msg.data(), msg.size(), pub.data(), pub.size()));
}

TEST(Ed25519KnownAnswer, RejectsMalformedLengths) {
  std::vector<uint8_t> pub =
      hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  std::vector<uint8_t> sig = hexToBytes(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61"
      "e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

  ota::trust::Ed25519SignatureVerifier verifier;
  // Truncated signature and truncated public key must both fail closed
  // rather than being silently zero-padded/accepted.
  EXPECT_FALSE(verifier.verify(sig.data(), sig.size() - 1, nullptr, 0, pub.data(), pub.size()));
  EXPECT_FALSE(verifier.verify(sig.data(), sig.size(), nullptr, 0, pub.data(), pub.size() - 1));
  EXPECT_FALSE(verifier.verify(nullptr, sig.size(), nullptr, 0, pub.data(), pub.size()));
}

// -----------------------------------------------------------------------
// Test-only sign helper self-check: round-trips through the SAME verifier
// used by production code, proving the test signer and Ed25519Verifier
// agree with each other before relying on that pairing for
// DescriptorVerifier integration tests below.
// -----------------------------------------------------------------------

TEST(Ed25519TestSignerSelfCheck, SignThenVerifyRoundTrips) {
  uint8_t seed[32];
  for (int i = 0; i < 32; ++i) seed[i] = static_cast<uint8_t>(i + 1);
  ota::test::Ed25519TestSigner signer(seed);

  const uint8_t message[] = {0x01, 0x02, 0x03, 0x04, 0x05};
  uint8_t signature[64];
  signer.sign(message, sizeof(message), signature);

  ota::trust::Ed25519SignatureVerifier verifier;
  EXPECT_TRUE(verifier.verify(signature, sizeof(signature), message, sizeof(message), signer.publicKey(), 32));

  uint8_t tampered[sizeof(message)];
  std::memcpy(tampered, message, sizeof(message));
  tampered[0] ^= 0x01;
  EXPECT_FALSE(verifier.verify(signature, sizeof(signature), tampered, sizeof(tampered), signer.publicKey(), 32));
}

// -----------------------------------------------------------------------
// DescriptorVerifier pipeline integration tests.
// -----------------------------------------------------------------------

namespace {

class DescriptorVerifierFixture : public ::testing::Test {
protected:
  void SetUp() override {
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = static_cast<uint8_t>(0x40 + i);
    signer_.reset(new ota::test::Ed25519TestSigner(seed));

    std::memcpy(anchor_.trusted_signer_public_key_ed25519, signer_->publicKey(), 32);
    anchor_.expected_target_id = 0x1001;
    anchor_.expected_role_id = 7;
    anchor_.device_address = 0xAABBCCDDu;
    anchor_.supported_boot_capability_flags = 0x0000000Fu;  // bits 0-3 supported

    flash_.reset(new ota::test::FakeNorFlash(64 * 1024, 4096));
    region_.reset(new ota::platform::FlashRegion(*flash_, 0, 64 * 1024));

    counter_.reset(new ota::test::FakeMonotonicCounter(10));
    hasher_.reset(new ota::trust::Sha256());
    sig_verifier_.reset(new ota::trust::Ed25519SignatureVerifier());
    verifier_.reset(new ota::trust::DescriptorVerifier(*hasher_, *sig_verifier_, *counter_, anchor_));
  }

  // Writes `image_bytes` into the candidate region and returns a validly
  // signed descriptor describing it (hash matches, signature genuine).
  ota::trust::ImageDescriptor buildValidDescriptor(const std::vector<uint8_t>& image_bytes, uint32_t counter_value) {
    // Program in erase-unit-aligned chunks starting from an erased region.
    uint32_t offset = 0;
    while (offset < image_bytes.size()) {
      uint32_t chunk = image_bytes.size() - offset;
      if (chunk > 256) chunk = 256;
      EXPECT_TRUE(ota::platform::isOk(region_->program(offset, image_bytes.data() + offset, chunk)));
      offset += chunk;
    }

    ota::trust::ImageDescriptor descriptor;
    ota::trust::Sha256::hash(image_bytes.data(), image_bytes.size(), descriptor.image_hash_sha256);
    descriptor.target_id = anchor_.expected_target_id;
    descriptor.role_id = anchor_.expected_role_id;
    descriptor.device_address = anchor_.device_address;
    descriptor.allow_broadcast_address = false;
    descriptor.required_boot_capability_flags = 0x00000003u;  // subset of supported
    descriptor.monotonic_counter = counter_value;
    descriptor.image_size_bytes = static_cast<uint32_t>(image_bytes.size());

    uint8_t message[ota::trust::CanonicalDescriptor::kMessageBytes];
    size_t written = ota::trust::CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
    EXPECT_EQ(written, ota::trust::CanonicalDescriptor::kMessageBytes);
    signer_->sign(message, written, descriptor.signature_ed25519);

    return descriptor;
  }

  std::unique_ptr<ota::test::Ed25519TestSigner> signer_;
  ota::trust::DeviceTrustAnchor anchor_;
  std::unique_ptr<ota::test::FakeNorFlash> flash_;
  std::unique_ptr<ota::platform::FlashRegion> region_;
  std::unique_ptr<ota::test::FakeMonotonicCounter> counter_;
  std::unique_ptr<ota::trust::Sha256> hasher_;
  std::unique_ptr<ota::trust::Ed25519SignatureVerifier> sig_verifier_;
  std::unique_ptr<ota::trust::DescriptorVerifier> verifier_;
};

}  // namespace

TEST_F(DescriptorVerifierFixture, ValidDescriptorAndImagePasses) {
  std::vector<uint8_t> image(4096, 0);
  for (size_t i = 0; i < image.size(); ++i) image[i] = static_cast<uint8_t>(i);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 11);

  ota::trust::VerificationResult meta_result = verifier_->verifyDescriptor(descriptor);
  EXPECT_TRUE(meta_result.ok);
  EXPECT_EQ(meta_result.reason, ota::trust::TrustFailureReason::None);

  ota::trust::VerificationResult image_result = verifier_->verifyImageBytes(descriptor, *region_);
  EXPECT_TRUE(image_result.ok);

  ota::trust::VerificationResult all_result = verifier_->verifyAll(descriptor, *region_);
  EXPECT_TRUE(all_result.ok);
}

TEST_F(DescriptorVerifierFixture, TamperedImageBytesFailHash) {
  std::vector<uint8_t> image(2048, 0xAB);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 11);

  // Corrupt one programmed byte directly via the fake's raw buffer path is
  // not possible (program() enforces 1->0 only and there's no public
  // "poke" API) -- instead corrupt the descriptor's claimed hash itself,
  // which exercises the same mismatch-detection code path.
  descriptor.image_hash_sha256[0] ^= 0xFF;

  ota::trust::VerificationResult result = verifier_->verifyImageBytes(descriptor, *region_);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::ImageHashMismatch);
}

TEST_F(DescriptorVerifierFixture, InvalidSignatureFailsClosed) {
  std::vector<uint8_t> image(512, 0x11);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 11);
  descriptor.signature_ed25519[0] ^= 0x01;

  ota::trust::VerificationResult result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::SignatureInvalid);
}

TEST_F(DescriptorVerifierFixture, WrongTargetIdFailsClosed) {
  std::vector<uint8_t> image(512, 0x22);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 11);
  descriptor.target_id = anchor_.expected_target_id + 1;

  // Signature was computed over the ORIGINAL target_id; mutating the field
  // after signing also breaks the signature, but the field-specific check
  // must be reachable in principle -- verify the signature check itself
  // rejects the mutated message first (still a correct fail-closed
  // outcome), then verify a properly re-signed-but-wrong-target descriptor
  // is rejected for the right reason.
  ota::trust::VerificationResult mutated_result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(mutated_result.ok);

  // Re-sign with the wrong target so ONLY the target check can fail.
  uint8_t message[ota::trust::CanonicalDescriptor::kMessageBytes];
  size_t written = ota::trust::CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
  signer_->sign(message, written, descriptor.signature_ed25519);

  ota::trust::VerificationResult result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::TargetMismatch);
}

TEST_F(DescriptorVerifierFixture, WrongRoleIdFailsClosed) {
  std::vector<uint8_t> image(512, 0x33);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 11);
  descriptor.role_id = anchor_.expected_role_id + 1;
  uint8_t message[ota::trust::CanonicalDescriptor::kMessageBytes];
  size_t written = ota::trust::CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
  signer_->sign(message, written, descriptor.signature_ed25519);

  ota::trust::VerificationResult result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::RoleMismatch);
}

TEST_F(DescriptorVerifierFixture, WrongKeyIdFailsClosedEvenWithGenuineSignature) {
  anchor_.expected_key_id = 5;
  anchor_.expected_algorithm_id = 1;
  verifier_.reset(new ota::trust::DescriptorVerifier(*hasher_, *sig_verifier_, *counter_, anchor_));

  std::vector<uint8_t> image(512, 0x55);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 11);
  descriptor.key_id = 6;  // wrong -- signed with the genuine key, but tagged with the wrong key id.
  descriptor.algorithm_id = 1;
  uint8_t message[ota::trust::CanonicalDescriptor::kMessageBytes];
  size_t written = ota::trust::CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
  signer_->sign(message, written, descriptor.signature_ed25519);

  ota::trust::VerificationResult result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::KeyIdMismatch);
}

TEST_F(DescriptorVerifierFixture, WrongAlgorithmIdFailsClosedEvenWithGenuineSignature) {
  anchor_.expected_key_id = 1;
  anchor_.expected_algorithm_id = 1;
  verifier_.reset(new ota::trust::DescriptorVerifier(*hasher_, *sig_verifier_, *counter_, anchor_));

  std::vector<uint8_t> image(512, 0x66);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 11);
  descriptor.key_id = 1;
  descriptor.algorithm_id = 2;  // wrong algorithm -- e.g. claims a non-Ed25519 scheme.
  uint8_t message[ota::trust::CanonicalDescriptor::kMessageBytes];
  size_t written = ota::trust::CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
  signer_->sign(message, written, descriptor.signature_ed25519);

  ota::trust::VerificationResult result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::AlgorithmIdMismatch);
}

TEST_F(DescriptorVerifierFixture, WrongFormatIdFailsClosedEvenWithGenuineSignature) {
  anchor_.expected_format_id = 1;
  verifier_.reset(new ota::trust::DescriptorVerifier(*hasher_, *sig_verifier_, *counter_, anchor_));

  std::vector<uint8_t> image(512, 0x77);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 11);
  descriptor.format_id = 2;  // wrong format.
  uint8_t message[ota::trust::CanonicalDescriptor::kMessageBytes];
  size_t written = ota::trust::CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
  signer_->sign(message, written, descriptor.signature_ed25519);

  ota::trust::VerificationResult result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::FormatIdMismatch);
}

TEST_F(DescriptorVerifierFixture, WrongDeviceAddressFailsClosedUnlessBroadcast) {
  std::vector<uint8_t> image(512, 0x44);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 11);
  descriptor.device_address = anchor_.device_address + 1;
  descriptor.allow_broadcast_address = false;
  uint8_t message[ota::trust::CanonicalDescriptor::kMessageBytes];
  size_t written = ota::trust::CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
  signer_->sign(message, written, descriptor.signature_ed25519);

  ota::trust::VerificationResult result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::AddressMismatch);

  // Same wrong address, but explicit broadcast opt-in must pass this check.
  descriptor.allow_broadcast_address = true;
  written = ota::trust::CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
  signer_->sign(message, written, descriptor.signature_ed25519);
  ota::trust::VerificationResult broadcast_result = verifier_->verifyDescriptor(descriptor);
  EXPECT_TRUE(broadcast_result.ok);
}

TEST_F(DescriptorVerifierFixture, MissingBootCapabilityFailsClosed) {
  std::vector<uint8_t> image(512, 0x55);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 11);
  descriptor.required_boot_capability_flags = 0x00000010u;  // bit 4, NOT in anchor's supported set
  uint8_t message[ota::trust::CanonicalDescriptor::kMessageBytes];
  size_t written = ota::trust::CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
  signer_->sign(message, written, descriptor.signature_ed25519);

  ota::trust::VerificationResult result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::BootCapabilityMissing);
}

TEST_F(DescriptorVerifierFixture, DowngradeCounterFailsClosed) {
  std::vector<uint8_t> image(512, 0x66);
  // counter_ starts at 10 (see SetUp); descriptor claims 5, which is <=
  // current -- must be rejected as a downgrade/replay attempt.
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 5);

  ota::trust::VerificationResult result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::CounterNotStrictlyIncreasing);
}

TEST_F(DescriptorVerifierFixture, EqualCounterFailsClosed) {
  std::vector<uint8_t> image(512, 0x77);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 10);  // == current, not strictly greater

  ota::trust::VerificationResult result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::CounterNotStrictlyIncreasing);
}

TEST_F(DescriptorVerifierFixture, UnavailableCounterFailsClosed) {
  std::vector<uint8_t> image(512, 0x88);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 11);
  counter_->setAvailable(false);

  ota::trust::VerificationResult result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::Unsupported);
}

TEST_F(DescriptorVerifierFixture, ImageSizeMismatchFailsClosed) {
  std::vector<uint8_t> image(512, 0x99);
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(image, 11);
  descriptor.image_size_bytes = region_->sizeBytes() + 1;  // larger than the whole region

  ota::trust::VerificationResult result = verifier_->verifyImageBytes(descriptor, *region_);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::ImageSizeMismatch);
}

TEST_F(DescriptorVerifierFixture, ZeroSizedDescriptorIsMalformed) {
  ota::trust::ImageDescriptor descriptor;  // never populated -- image_size_bytes stays 0
  ota::trust::VerificationResult result = verifier_->verifyDescriptor(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ota::trust::TrustFailureReason::MalformedDescriptor);
}

TEST_F(DescriptorVerifierFixture, CommitCounterRejectsNonIncreasingValue) {
  ota::trust::ImageDescriptor descriptor = buildValidDescriptor(std::vector<uint8_t>(64, 0), 11);
  EXPECT_TRUE(verifier_->commitCounter(descriptor));

  uint32_t current = 0;
  ASSERT_TRUE(counter_->currentValue(current));
  EXPECT_EQ(current, 11u);

  // Attempting to commit the same value again must fail (not strictly
  // increasing), not silently no-op-succeed.
  EXPECT_FALSE(verifier_->commitCounter(descriptor));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
