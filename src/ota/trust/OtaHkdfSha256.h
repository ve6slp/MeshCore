#pragma once

// Portable HMAC-SHA256 (RFC 2104) + HKDF-SHA256 (RFC 5869 Extract/Expand),
// built directly on the existing dependency-free ota::trust::Sha256, with
// no dependency on any Arduino/vendor crypto library -- so it is directly
// exercisable by native unit tests (including RFC 5869's own published
// fixed test vectors) without any native build-configuration change.
//
// This computes byte-for-byte the same HKDF-SHA256 output as the
// Arduino Crypto library's `HKDF<SHA256>` class (both implement RFC 5869
// exactly) -- it exists as a portable, always-available reimplementation
// of the SAME standard so the OTA AEAD transport's key/nonce derivation
// (ota/trust/OtaAeadKeySchedule.h) can be pinned against RFC 5869's known
// -answer vectors on every build target, not only ones with the Crypto
// library's native lib_deps entry present. This is NOT a new/bespoke KDF
// design -- it is RFC 5869 HKDF-SHA256, nothing else.
//
// Header-only, all methods inline/static.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ota/trust/Sha256.h"

namespace ota {
namespace trust {

class HmacSha256 {
public:
  static constexpr size_t kBlockBytes = 64;
  static constexpr size_t kDigestBytes = 32;

  static void compute(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len,
                      uint8_t out_mac[kDigestBytes]) {
    uint8_t key_block[kBlockBytes] = {0};
    if (key_len > kBlockBytes) {
      Sha256::hash(key, key_len, key_block);  // RFC 2104: oversized keys are hashed down first.
    } else if (key_len > 0) {
      memcpy(key_block, key, key_len);
    }

    uint8_t ipad[kBlockBytes];
    uint8_t opad[kBlockBytes];
    for (size_t i = 0; i < kBlockBytes; ++i) {
      ipad[i] = static_cast<uint8_t>(key_block[i] ^ 0x36u);
      opad[i] = static_cast<uint8_t>(key_block[i] ^ 0x5cu);
    }

    Sha256 inner;
    inner.update(ipad, kBlockBytes);
    inner.update(data, data_len);
    uint8_t inner_digest[kDigestBytes];
    inner.finish(inner_digest);

    Sha256 outer;
    outer.update(opad, kBlockBytes);
    outer.update(inner_digest, kDigestBytes);
    outer.finish(out_mac);
  }
};

// RFC 5869 HKDF-SHA256. `extract()` and `expand()` are exposed separately
// (per RFC 5869 section 2) as well as via the combined `deriveKey()`
// convenience wrapper most callers want.
class HkdfSha256 {
public:
  static constexpr size_t kDigestBytes = 32;
  static constexpr size_t kMaxOutputBytes = 255 * kDigestBytes;  // RFC 5869 hard limit for SHA-256.

  // RFC 5869 section 2.2: PRK = HMAC-Hash(salt, IKM). An empty salt is
  // replaced by a string of HashLen zero bytes, per spec.
  static void extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len,
                     uint8_t out_prk[kDigestBytes]) {
    if (salt_len == 0) {
      uint8_t zero_salt[kDigestBytes] = {0};
      HmacSha256::compute(zero_salt, kDigestBytes, ikm, ikm_len, out_prk);
    } else {
      HmacSha256::compute(salt, salt_len, ikm, ikm_len, out_prk);
    }
  }

  // RFC 5869 section 2.3: OKM = T(1) || T(2) || ... truncated to L bytes,
  // where T(0) = empty, T(i) = HMAC-Hash(PRK, T(i-1) || info || i).
  static bool expand(const uint8_t prk[kDigestBytes], const uint8_t* info, size_t info_len, uint8_t* out,
                     size_t out_len) {
    if (out_len > kMaxOutputBytes) return false;  // RFC 5869 hard limit (255 * HashLen); fail closed.
    uint8_t t_prev[kDigestBytes];
    size_t t_prev_len = 0;
    size_t produced = 0;
    uint8_t counter = 1;
    while (produced < out_len) {
      uint8_t buf[kDigestBytes + 512 + 1];  // t_prev(<=32) + info + 1-byte counter; info bounded by caller.
      if (info_len > sizeof(buf) - kDigestBytes - 1) return false;  // defensive bound, not an RFC limit.
      size_t off = 0;
      memcpy(buf + off, t_prev, t_prev_len);
      off += t_prev_len;
      if (info_len > 0) {
        memcpy(buf + off, info, info_len);
        off += info_len;
      }
      buf[off++] = counter;
      uint8_t t_cur[kDigestBytes];
      HmacSha256::compute(prk, kDigestBytes, buf, off, t_cur);
      const size_t take = (out_len - produced) < kDigestBytes ? (out_len - produced) : kDigestBytes;
      memcpy(out + produced, t_cur, take);
      produced += take;
      memcpy(t_prev, t_cur, kDigestBytes);
      t_prev_len = kDigestBytes;
      ++counter;
    }
    return true;
  }

  // Convenience: extract-then-expand in one call.
  static bool deriveKey(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len,
                       const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len) {
    uint8_t prk[kDigestBytes];
    extract(salt, salt_len, ikm, ikm_len, prk);
    return expand(prk, info, info_len, out, out_len);
  }
};

}  // namespace trust
}  // namespace ota
