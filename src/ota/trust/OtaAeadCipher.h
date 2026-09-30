#pragma once

// ChaCha20-Poly1305 (RFC 8439) seal/open wrapper for the OTA AEAD
// transport, built on the Arduino Crypto library's `ChaChaPoly` class
// (rweather/Crypto, already a project lib_dep for every Arduino build
// target) -- per the coordinator's explicit instruction to use the
// already-available library rather than a new/bespoke cipher design.
//
// make test-ota-aead-cipher links the same Crypto sources used on hardware,
// without the deterministic SHA256 mock used by other native Mesh tests.
//
// Quarantine discipline: `open()` NEVER writes to the caller's
// `out_plaintext` buffer until AFTER its own `checkTag()` call has
// succeeded. `decrypt()` on the underlying cipher is a streaming
// operation that produces plaintext bytes before the tag is verified;
// those bytes are written ONLY into this class's own private `quarantine_`
// scratch buffer, never into caller-visible storage, and are zeroed
// before returning failure -- no parsing/storage/callback may observe
// unauthenticated plaintext at any point.
#include <ChaChaPoly.h>
#include <Crypto.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ota/runtime/OtaAeadFrame.h"

namespace ota {
namespace trust {

class OtaAeadCipher {
public:
  static constexpr size_t kKeyBytes = 32;
  static constexpr size_t kNonceBytes = 12;
  static constexpr size_t kTagBytes = 16;
  static constexpr size_t kMaxPlaintextBytes = ::meshcore::ota::runtime::kOtaAeadMaxPlaintextBytes;
  static constexpr size_t kMinPlaintextBytes = ::meshcore::ota::runtime::kOtaAeadMinPlaintextBytes;

  // Seals `plaintext` (len in [kMinPlaintextBytes, kMaxPlaintextBytes]),
  // writing exactly `len` ciphertext bytes to `out_ciphertext` and 16 tag
  // bytes to `out_tag`. Returns false (nothing written) on an out-of-
  // bounds length or a key/IV the cipher itself rejects.
  static bool seal(const uint8_t key[kKeyBytes], const uint8_t nonce[kNonceBytes], const uint8_t* ad,
                  size_t ad_len, const uint8_t* plaintext, size_t len, uint8_t* out_ciphertext,
                  uint8_t out_tag[kTagBytes]) {
    if (key == nullptr || nonce == nullptr || plaintext == nullptr ||
        out_ciphertext == nullptr || out_tag == nullptr ||
        (ad == nullptr && ad_len != 0) ||
        len < kMinPlaintextBytes || len > kMaxPlaintextBytes) return false;
    ChaChaPoly cipher;
    if (!cipher.setKey(key, kKeyBytes)) return false;
    if (!cipher.setIV(nonce, kNonceBytes)) return false;
    cipher.addAuthData(ad, ad_len);
    cipher.encrypt(out_ciphertext, plaintext, len);
    cipher.computeTag(out_tag, kTagBytes);
    cipher.clear();
    return true;
  }

  // Opens `ciphertext`+`tag` (both `len`/kTagBytes long) into a PRIVATE
  // quarantine scratch buffer first; only a full, successful 16-byte tag
  // check causes `out_plaintext` (caller-owned, >= len bytes) to receive
  // the plaintext. Any failure -- bad length, bad key/IV, or a failed tag
  // check (corrupted/forged/truncated ciphertext or tag) -- leaves
  // `out_plaintext` completely untouched and the internal quarantine
  // buffer zeroed, and returns false.
  bool open(const uint8_t key[kKeyBytes], const uint8_t nonce[kNonceBytes], const uint8_t* ad, size_t ad_len,
           const uint8_t* ciphertext, size_t len, const uint8_t tag[kTagBytes], uint8_t* out_plaintext) {
    if (key == nullptr || nonce == nullptr || ciphertext == nullptr ||
        tag == nullptr || out_plaintext == nullptr ||
        (ad == nullptr && ad_len != 0) ||
        len < kMinPlaintextBytes || len > kMaxPlaintextBytes) return false;
    ChaChaPoly cipher;
    if (!cipher.setKey(key, kKeyBytes)) return false;
    if (!cipher.setIV(nonce, kNonceBytes)) return false;
    cipher.addAuthData(ad, ad_len);
    cipher.decrypt(quarantine_, ciphertext, len);  // private scratch only -- not caller-visible yet.
    const bool tag_ok = cipher.checkTag(tag, kTagBytes);
    cipher.clear();
    if (!tag_ok) {
      clean(quarantine_, sizeof(quarantine_));
      return false;
    }
    memcpy(out_plaintext, quarantine_, len);
    clean(quarantine_, sizeof(quarantine_));
    return true;
  }

private:
  uint8_t quarantine_[kMaxPlaintextBytes] = {0};
};

}  // namespace trust
}  // namespace ota
