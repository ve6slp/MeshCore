#pragma once

// Test-only helper that performs a genuine Ed25519 keypair-generation +
// signing round trip so tests can construct real, validly-signed
// ImageDescriptors. It calls straight into the same vendored
// ed25519_create_keypair / ed25519_sign routines that ship in
// third_party/ed25519 (see NOTICE.txt) -- production firmware code never
// calls these two functions, only ed25519_verify.

#include <stdint.h>
#include <cstring>
#include "ota/trust/third_party/ed25519/Ed25519Impl.h"

namespace ota {
namespace test {

class Ed25519TestSigner {
public:
  // Deterministically derives a keypair from a fixed 32-byte seed (no OS
  // randomness involved, so tests are fully reproducible).
  explicit Ed25519TestSigner(const uint8_t seed[32]) {
    ota::trust::ed25519_impl::ed25519_create_keypair(public_key_, private_key_, seed);
  }

  const uint8_t* publicKey() const { return public_key_; }

  void sign(const uint8_t* message, size_t message_len, uint8_t out_signature[64]) const {
    ota::trust::ed25519_impl::ed25519_sign(out_signature, message, message_len, public_key_, private_key_);
  }

private:
  uint8_t public_key_[32] = {0};
  uint8_t private_key_[64] = {0};
};

}  // namespace test
}  // namespace ota
