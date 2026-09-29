#pragma once

// Self-contained, portable SHA-256 (FIPS 180-4) implementation with no
// dependency on any Arduino/vendor crypto library, so the image-hash half of
// the trust pipeline performs genuine cryptographic hashing rather than a
// placeholder. Correctness is pinned by NIST/RFC known-answer vectors in
// test/test_lora_ota_trust.
//
// Header-only (all methods inline) so it can be consumed directly by
// PlatformIO's native unit tests without any build-configuration change.

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "ota/trust/HashAlgorithm.h"

namespace ota {
namespace trust {

namespace sha256_detail {

inline const uint32_t* roundConstants() {
  static const uint32_t k[64] = {
      0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
      0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
      0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
      0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
      0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
      0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
      0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
      0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
  };
  return k;
}

inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32u - n)); }

inline uint32_t loadBigEndian32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline void storeBigEndian32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v >> 24);
  p[1] = static_cast<uint8_t>(v >> 16);
  p[2] = static_cast<uint8_t>(v >> 8);
  p[3] = static_cast<uint8_t>(v);
}

}  // namespace sha256_detail

class Sha256 : public HashAlgorithm {
public:
  Sha256() { reset(); }

  void reset() override {
    state_[0] = 0x6a09e667u;
    state_[1] = 0xbb67ae85u;
    state_[2] = 0x3c6ef372u;
    state_[3] = 0xa54ff53au;
    state_[4] = 0x510e527fu;
    state_[5] = 0x9b05688cu;
    state_[6] = 0x1f83d9abu;
    state_[7] = 0x5be0cd19u;
    total_len_bytes_ = 0;
    buffer_len_ = 0;
    memset(buffer_, 0, sizeof(buffer_));
  }

  void update(const uint8_t* data, size_t len) override {
    total_len_bytes_ += static_cast<uint64_t>(len);

    size_t offset = 0;
    if (buffer_len_ > 0) {
      const size_t needed = 64 - buffer_len_;
      const size_t take = len < needed ? len : needed;
      memcpy(buffer_ + buffer_len_, data, take);
      buffer_len_ += take;
      offset += take;
      if (buffer_len_ == 64) {
        processBlock(buffer_);
        buffer_len_ = 0;
      }
    }

    while (offset + 64 <= len) {
      processBlock(data + offset);
      offset += 64;
    }

    const size_t remaining = len - offset;
    if (remaining > 0) {
      memcpy(buffer_ + buffer_len_, data + offset, remaining);
      buffer_len_ += remaining;
    }
  }

  void finish(uint8_t out_digest[32]) override {
    const uint64_t bit_len = total_len_bytes_ * 8u;

    const uint8_t pad_start = 0x80u;
    update(&pad_start, 1);

    const uint8_t zero = 0x00u;
    // buffer_len_ cycles mod 64; pad with zero bytes until it reaches 56,
    // leaving exactly 8 bytes for the 64-bit big-endian length field. This
    // naturally wraps through 64 -> 0 via update()'s own block-flush logic
    // if the pad byte above already pushed buffer_len_ past 56.
    while (buffer_len_ != 56) {
      update(&zero, 1);
    }

    uint8_t len_bytes[8];
    for (int i = 0; i < 8; ++i) {
      len_bytes[i] = static_cast<uint8_t>(bit_len >> (56 - 8 * i));
    }
    memcpy(buffer_ + buffer_len_, len_bytes, 8);
    processBlock(buffer_);
    buffer_len_ = 0;

    for (int i = 0; i < 8; ++i) {
      sha256_detail::storeBigEndian32(out_digest + (i * 4), state_[i]);
    }
  }

  // One-shot convenience wrapper.
  static void hash(const uint8_t* data, size_t len, uint8_t out_digest[32]) {
    Sha256 sha;
    sha.update(data, len);
    sha.finish(out_digest);
  }

private:
  void processBlock(const uint8_t block[64]) {
    using namespace sha256_detail;
    const uint32_t* k = roundConstants();

    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
      w[i] = loadBigEndian32(block + (i * 4));
    }
    for (int i = 16; i < 64; ++i) {
      const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

    for (int i = 0; i < 64; ++i) {
      const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const uint32_t ch = (e & f) ^ ((~e) & g);
      const uint32_t temp1 = h + S1 + ch + k[i] + w[i];
      const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temp2 = S0 + maj;

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  uint32_t state_[8];
  uint64_t total_len_bytes_;
  uint8_t buffer_[64];
  size_t buffer_len_;
};

}  // namespace trust
}  // namespace ota
