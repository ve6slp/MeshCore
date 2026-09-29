#pragma once

// Abstract signature verification interface used by the descriptor
// verification pipeline. There is deliberately NO default/"always true"
// implementation anywhere in this header or its production callers: a
// missing/unwired verifier must be a compile-time or explicit
// construction-time choice, never a silent fallback.

#include <stdint.h>
#include <stddef.h>

namespace ota {
namespace trust {

class SignatureVerifier {
public:
  virtual ~SignatureVerifier() = default;

  // Returns true only if `signature` is a valid signature over `message` by
  // the holder of `public_key`. Implementations MUST fail closed: any
  // malformed input (wrong lengths, null pointers, algorithm-specific
  // malleability checks) returns false, never true.
  virtual bool verify(const uint8_t* signature, size_t signature_len,
                       const uint8_t* message, size_t message_len,
                       const uint8_t* public_key, size_t public_key_len) const = 0;
};

}  // namespace trust
}  // namespace ota
