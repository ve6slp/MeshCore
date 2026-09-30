#pragma once

// Direction-aware pairwise and group key/nonce derivation for the OTA AEAD
// transport (ChaCha20-Poly1305 over the existing per-contact Mesh ECDH
// shared secret, or a separately-provisioned 32-byte group secret), per the
// coordinator-approved "MeshCore/OTA/AEAD1" scheme:
//
//   salt   = SHA256("MeshCore/OTA/AEAD1")
//   pairwise context(sender -> receiver) = sender.fullPubKey32 || receiver.fullPubKey32
//   key    = HKDF-SHA256(IKM=existing Mesh ECDH shared secret, salt, info="peer/key"  || context, 32)
//   noncePrefix = HKDF-SHA256(IKM=shared secret,                salt, info="peer/nonce"|| context, 8)
//   nonce  = noncePrefix(8) || BE32(sequence)                                          -- 12 bytes total.
//
// Every derivation is direction-separated by construction: the context for
// A -> B (sender A, receiver B) is the byte-reverse of B -> A's context, so
// the two directions of the same pair get independent key/nonce material
// from the same underlying shared secret, even though both sides compute
// the SAME 32-byte ECDH secret. Both correspondents derive an IDENTICAL
// per-direction key/nonce-prefix because both know which side is the
// sender for a given frame (already inherent in the destHash/srcHash the
// outer frame carries) -- there is no ambiguity about "who is A"; A is
// simply whichever side sent this particular frame.
//
// Group frames use a SEPARATELY, PAIRWISE-PROVISIONED 32-byte group secret
// (proves cohort MEMBERSHIP only, never sender/controller identity -- see
// OtaAeadFrame.h's scope note) with its own context/derivation, entirely
// independent of any pairwise shared secret.
//
// A zero (all-0x00) shared/group secret is never a legitimate ECDH output
// or a legitimate provisioned secret -- every derive*() call here refuses
// (returns false, no key material produced) rather than silently deriving
// from an all-zero IKM.
//
// Header-only, no dependency on the Arduino Crypto library (see
// OtaHkdfSha256.h's own header comment for why HKDF is a portable
// reimplementation of RFC 5869 here rather than a call into
// Crypto/HKDF.h): usable identically on every build target.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ota/trust/OtaHkdfSha256.h"
#include "ota/trust/Sha256.h"

namespace ota {
namespace trust {

namespace ota_aead_detail {

inline bool isAllZero(const uint8_t* p, size_t len) {
  uint8_t acc = 0;
  for (size_t i = 0; i < len; ++i) acc |= p[i];
  return acc == 0;
}

inline void appendBE32(uint8_t* out, size_t& off, uint32_t v) {
  out[off++] = static_cast<uint8_t>(v >> 24);
  out[off++] = static_cast<uint8_t>(v >> 16);
  out[off++] = static_cast<uint8_t>(v >> 8);
  out[off++] = static_cast<uint8_t>(v);
}

inline void appendBE16(uint8_t* out, size_t& off, uint16_t v) {
  out[off++] = static_cast<uint8_t>(v >> 8);
  out[off++] = static_cast<uint8_t>(v);
}

}  // namespace ota_aead_detail

class OtaAeadKeySchedule {
public:
  static constexpr size_t kKeyBytes = 32;
  static constexpr size_t kNoncePrefixBytes = 8;
  static constexpr size_t kNonceBytes = 12;
  static constexpr size_t kFullPubKeyBytes = 32;
  static constexpr size_t kPairwiseContextBytes = kFullPubKeyBytes * 2;  // 64
  static constexpr size_t kGroupContextBytes = 32 + 4 + 4 + 2 + 32 + 2 + 16;  // 92

  // Salt is fixed and public: SHA256("MeshCore/OTA/AEAD1"). Computed once
  // and cached -- every derivation (pairwise or group) uses this same salt.
  static const uint8_t* salt() {
    static uint8_t cached[32];
    static bool computed = false;
    if (!computed) {
      static const char kLabel[] = "MeshCore/OTA/AEAD1";  // no NUL included, per spec.
      Sha256::hash(reinterpret_cast<const uint8_t*>(kLabel), sizeof(kLabel) - 1, cached);
      computed = true;
    }
    return cached;
  }

  // Pairwise key material for the direction sender -> receiver. `out_key`
  // receives 32 bytes, `out_nonce_prefix` receives 8 bytes. Returns false
  // (no output written) if `shared_secret` is all-zero.
  static bool derivePairwise(const uint8_t shared_secret[32], const uint8_t sender_full_pub_key[32],
                            const uint8_t receiver_full_pub_key[32], uint8_t out_key[kKeyBytes],
                            uint8_t out_nonce_prefix[kNoncePrefixBytes]) {
    if (ota_aead_detail::isAllZero(shared_secret, 32)) return false;

    uint8_t context[kPairwiseContextBytes];
    memcpy(context, sender_full_pub_key, 32);
    memcpy(context + 32, receiver_full_pub_key, 32);

    return deriveKeyAndNonce("peer/key", 8, "peer/nonce", 10, shared_secret, 32, context,
                             kPairwiseContextBytes, out_key, out_nonce_prefix);
  }

  // Group key material. `group_secret` is the pairwise-provisioned 32-byte
  // cohort secret (proves membership only). Context is
  // publisher.fullPubKey32 || campaignBE32 || sessionBE32 || attemptBE16 ||
  // descriptorDigest32 || cohortBE16 || epoch16.
  static bool deriveGroup(const uint8_t group_secret[32], const uint8_t publisher_full_pub_key[32],
                         uint32_t campaign_id, uint32_t session_id, uint16_t attempt_id,
                         const uint8_t descriptor_digest32[32], uint16_t cohort_id, const uint8_t epoch16[16],
                         uint8_t out_key[kKeyBytes], uint8_t out_nonce_prefix[kNoncePrefixBytes]) {
    if (ota_aead_detail::isAllZero(group_secret, 32)) return false;

    uint8_t context[kGroupContextBytes];
    size_t off = 0;
    memcpy(context + off, publisher_full_pub_key, 32);
    off += 32;
    ota_aead_detail::appendBE32(context, off, campaign_id);
    ota_aead_detail::appendBE32(context, off, session_id);
    ota_aead_detail::appendBE16(context, off, attempt_id);
    memcpy(context + off, descriptor_digest32, 32);
    off += 32;
    ota_aead_detail::appendBE16(context, off, cohort_id);
    memcpy(context + off, epoch16, 16);
    off += 16;
    // (off must equal kGroupContextBytes; enforced by the buffer size above.)

    return deriveKeyAndNonce("group/key", 9, "group/nonce", 11, group_secret, 32, context,
                             kGroupContextBytes, out_key, out_nonce_prefix);
  }

  // selector2 = first 2 bytes of SHA256("group/selector" || context), the
  // SAME 92-byte context construction as deriveGroup() above (not an
  // HKDF output -- a plain truncated hash, used only as a non-secret
  // lookup tag for which group key a receiver should try, never as key
  // material itself).
  static uint16_t deriveGroupSelector(const uint8_t publisher_full_pub_key[32], uint32_t campaign_id,
                                     uint32_t session_id, uint16_t attempt_id,
                                     const uint8_t descriptor_digest32[32], uint16_t cohort_id,
                                     const uint8_t epoch16[16]) {
    uint8_t context[kGroupContextBytes];
    size_t off = 0;
    memcpy(context + off, publisher_full_pub_key, 32);
    off += 32;
    ota_aead_detail::appendBE32(context, off, campaign_id);
    ota_aead_detail::appendBE32(context, off, session_id);
    ota_aead_detail::appendBE16(context, off, attempt_id);
    memcpy(context + off, descriptor_digest32, 32);
    off += 32;
    ota_aead_detail::appendBE16(context, off, cohort_id);
    memcpy(context + off, epoch16, 16);
    off += 16;

    static const char kSelectorLabel[] = "group/selector";
    uint8_t message[sizeof(kSelectorLabel) - 1 + kGroupContextBytes];
    memcpy(message, kSelectorLabel, sizeof(kSelectorLabel) - 1);
    memcpy(message + sizeof(kSelectorLabel) - 1, context, kGroupContextBytes);
    uint8_t digest[32];
    Sha256::hash(message, sizeof(message), digest);
    return static_cast<uint16_t>((static_cast<uint16_t>(digest[0]) << 8) | digest[1]);
  }

  // Assembles the full 12-byte IV: noncePrefix(8) || BE32(sequence).
  static void buildNonce(const uint8_t nonce_prefix[kNoncePrefixBytes], uint32_t sequence,
                        uint8_t out_nonce[kNonceBytes]) {
    memcpy(out_nonce, nonce_prefix, kNoncePrefixBytes);
    size_t off = kNoncePrefixBytes;
    ota_aead_detail::appendBE32(out_nonce, off, sequence);
  }

private:
  static bool deriveKeyAndNonce(const char* key_label, size_t key_label_len, const char* nonce_label,
                               size_t nonce_label_len, const uint8_t* ikm, size_t ikm_len,
                               const uint8_t* context, size_t context_len, uint8_t out_key[kKeyBytes],
                               uint8_t out_nonce_prefix[kNoncePrefixBytes]) {
    uint8_t info_key[16 + kPairwiseContextBytes > 16 + kGroupContextBytes ? 16 + kPairwiseContextBytes
                                                                          : 16 + kGroupContextBytes];
    memcpy(info_key, key_label, key_label_len);
    memcpy(info_key + key_label_len, context, context_len);
    if (!HkdfSha256::deriveKey(salt(), 32, ikm, ikm_len, info_key, key_label_len + context_len, out_key,
                              kKeyBytes)) {
      return false;
    }

    uint8_t info_nonce[16 + kPairwiseContextBytes > 16 + kGroupContextBytes ? 16 + kPairwiseContextBytes
                                                                            : 16 + kGroupContextBytes];
    memcpy(info_nonce, nonce_label, nonce_label_len);
    memcpy(info_nonce + nonce_label_len, context, context_len);
    return HkdfSha256::deriveKey(salt(), 32, ikm, ikm_len, info_nonce, nonce_label_len + context_len,
                                out_nonce_prefix, kNoncePrefixBytes);
  }
};

}  // namespace trust
}  // namespace ota
