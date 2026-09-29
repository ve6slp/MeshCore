#pragma once

// Real Ed25519 signature verification, backed by the vendored, public-
// domain ed25519 (ed25519-donna derived) implementation under
// third_party/ed25519/. This is genuine asymmetric cryptography validated
// against the RFC 8032 known-answer test vectors in
// test/test_lora_ota_trust -- it is not a test double.

#include <stdint.h>
#include <stddef.h>
#include "ota/trust/SignatureVerifier.h"
#include "ota/trust/third_party/ed25519/Ed25519Impl.h"

namespace ota {
namespace trust {

class Ed25519SignatureVerifier : public SignatureVerifier {
public:
  static constexpr size_t kSignatureBytes = 64;
  static constexpr size_t kPublicKeyBytes = 32;

  bool verify(const uint8_t* signature, size_t signature_len,
              const uint8_t* message, size_t message_len,
              const uint8_t* public_key, size_t public_key_len) const override {
    // Fail closed on any malformed input rather than delegating to the
    // library with an out-of-bounds/short buffer.
    if (signature == nullptr || public_key == nullptr) {
      return false;
    }
    if (signature_len != kSignatureBytes || public_key_len != kPublicKeyBytes) {
      return false;
    }
    if (message == nullptr && message_len != 0) {
      return false;
    }

    return ed25519_impl::ed25519_verify(signature, message, message_len, public_key) != 0;
  }
};

}  // namespace trust
}  // namespace ota
