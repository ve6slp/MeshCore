// SHA-256 and Ed25519 known-answer and identity-crypto invariants.

#include <gtest/gtest.h>
#include <stdint.h>
#include <cstring>
#include <vector>
#include <string>

#define ED25519_NO_SEED 1
#include <ed_25519.h>

#include "ota/trust/Sha256.h"
#include "ota/trust/Ed25519SignatureVerifier.h"

#include "Ed25519TestSigner.h"

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

TEST(LegacyIdentityCrypto, OriginalKeypairAndSignatureMatchRfc8032) {
  const auto seed = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  uint8_t public_key[32], private_key[64], signature[64];
  ed25519_create_keypair(public_key, private_key, seed.data());
  EXPECT_EQ(toHex(public_key, sizeof(public_key)),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  ed25519_sign(signature, nullptr, 0, public_key, private_key);
  EXPECT_EQ(toHex(signature, sizeof(signature)),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
            "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
}

TEST(LegacyIdentityCrypto, ExpandedPrivateKeyDerivesOriginalPublicKeyAndSigns) {
  const auto seed = hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
  uint8_t public_key[32], private_key[64], restored_private_key[64], derived_public_key[32];
  ed25519_create_keypair(public_key, private_key, seed.data());
  std::memcpy(restored_private_key, private_key, sizeof(private_key));
  ed25519_derive_pub(derived_public_key, restored_private_key);
  EXPECT_EQ(0, std::memcmp(public_key, derived_public_key, sizeof(public_key)));
  EXPECT_EQ(toHex(derived_public_key, sizeof(derived_public_key)),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
  const uint8_t message[] = {0x72};
  uint8_t signature[64];
  ed25519_sign(signature, message, sizeof(message), derived_public_key, restored_private_key);
  EXPECT_EQ(toHex(signature, sizeof(signature)),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085"
            "ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
  ota::trust::Ed25519SignatureVerifier verifier;
  EXPECT_TRUE(verifier.verify(signature, sizeof(signature), message, sizeof(message),
                              derived_public_key, sizeof(derived_public_key)));
  const uint8_t tampered[] = {0x73};
  EXPECT_FALSE(verifier.verify(signature, sizeof(signature), tampered, sizeof(tampered),
                               derived_public_key, sizeof(derived_public_key)));
}

TEST(LegacyIdentityCrypto, OriginalKeyExchangeRemainsBilateralAndNonzero) {
  const auto alice_seed = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  const auto bob_seed = hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
  uint8_t alice_public[32], alice_private[64], bob_public[32], bob_private[64];
  ed25519_create_keypair(alice_public, alice_private, alice_seed.data());
  ed25519_create_keypair(bob_public, bob_private, bob_seed.data());
  uint8_t alice_secret[32], bob_secret[32], zero[32] = {};
  ed25519_key_exchange(alice_secret, bob_public, alice_private);
  ed25519_key_exchange(bob_secret, alice_public, bob_private);
  EXPECT_EQ(0, std::memcmp(alice_secret, bob_secret, sizeof(alice_secret)));
  EXPECT_NE(0, std::memcmp(alice_secret, zero, sizeof(alice_secret)));
}

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
// agree with each other before relying on that pairing for package tests.
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

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
