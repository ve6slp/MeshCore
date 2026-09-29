#pragma once

// Deterministic, fixed-width serialization of the fields of an
// ImageDescriptor that are covered by its Ed25519 signature. This is the
// exact byte sequence that must have been signed by the trusted key; using
// a single canonical function for both signing (offline, not part of this
// firmware-side module) and verification (here) eliminates any ambiguity
// about field order, width, or padding that could otherwise let two
// different descriptors serialize to signatures that "look" compatible.
//
// The signature itself, and any signer-supplied public key, are
// deliberately NOT part of the signed message (a signature cannot cover
// itself, and the signer key is never taken from the descriptor -- see
// TrustTypes.h).

#include <stdint.h>
#include <stddef.h>
#include <cstring>
#include "ota/trust/TrustTypes.h"

namespace ota {
namespace trust {

class CanonicalDescriptor {
public:
  static constexpr size_t kMessageBytes = 32 + 4 + 4 + 8 + 1 + 4 + 4 + 4 + 4 + 2 + 2 + 2;  // = 71

  // Serializes the signed fields of `descriptor` into `out`, which must be
  // at least kMessageBytes long. Returns the number of bytes written
  // (always kMessageBytes on success), or 0 if `out_len` is too small.
  static size_t serialize(const ImageDescriptor& descriptor, uint8_t* out, size_t out_len) {
    if (out == nullptr || out_len < kMessageBytes) {
      return 0;
    }

    size_t pos = 0;
    memcpy(out + pos, descriptor.image_hash_sha256, 32);
    pos += 32;

    putU32(out + pos, descriptor.target_id);
    pos += 4;
    putU32(out + pos, descriptor.role_id);
    pos += 4;
    putU64(out + pos, descriptor.device_address);
    pos += 8;
    out[pos] = descriptor.allow_broadcast_address ? 1u : 0u;
    pos += 1;
    putU32(out + pos, descriptor.required_boot_capability_flags);
    pos += 4;
    putU32(out + pos, descriptor.monotonic_counter);
    pos += 4;
    putU32(out + pos, descriptor.image_size_bytes);
    pos += 4;
    putU32(out + pos, descriptor.app_address);
    pos += 4;
    putU16(out + pos, descriptor.format_id);
    pos += 2;
    putU16(out + pos, descriptor.key_id);
    pos += 2;
    putU16(out + pos, descriptor.algorithm_id);
    pos += 2;

    return pos;
  }

private:
  static void putU16(uint8_t* out, uint16_t v) {
    out[0] = (uint8_t)(v & 0xFFu);
    out[1] = (uint8_t)((v >> 8) & 0xFFu);
  }

  static void putU32(uint8_t* out, uint32_t v) {
    out[0] = (uint8_t)(v & 0xFFu);
    out[1] = (uint8_t)((v >> 8) & 0xFFu);
    out[2] = (uint8_t)((v >> 16) & 0xFFu);
    out[3] = (uint8_t)((v >> 24) & 0xFFu);
  }

  static void putU64(uint8_t* out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
      out[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
    }
  }
};

}  // namespace trust
}  // namespace ota
