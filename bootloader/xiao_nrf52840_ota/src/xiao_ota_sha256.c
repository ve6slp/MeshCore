#include "xiao_ota_sha256.h"

#include <string.h>

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t ror(uint32_t x, unsigned n) { return (x >> n) | (x << (32u - n)); }
static uint32_t load_be(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void store_be(uint8_t *p, uint32_t x) {
  p[0] = (uint8_t)(x >> 24); p[1] = (uint8_t)(x >> 16);
  p[2] = (uint8_t)(x >> 8); p[3] = (uint8_t)x;
}

static void transform(xiao_ota_sha256_t *c, const uint8_t block[64]) {
  uint32_t w[64], a, b, cc, d, e, f, g, h;
  unsigned i;
  for (i = 0; i < 16; ++i) w[i] = load_be(block + i * 4);
  for (; i < 64; ++i) {
    uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
  e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];
  for (i = 0; i < 64; ++i) {
    uint32_t s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
    uint32_t t1 = h + s1 + ((e & f) ^ (~e & g)) + k[i] + w[i];
    uint32_t s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
    uint32_t t2 = s0 + ((a & b) ^ (a & cc) ^ (b & cc));
    h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
  }
  c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
  c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

void xiao_ota_sha256_init(xiao_ota_sha256_t *c) {
  static const uint32_t initial[8] = {
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  memcpy(c->state, initial, sizeof(initial));
  c->total = 0;
  c->used = 0;
}

void xiao_ota_sha256_update(xiao_ota_sha256_t *c, const void *data, size_t length) {
  const uint8_t *p = (const uint8_t *)data;
  c->total += length;
  while (length != 0) {
    size_t n = sizeof(c->block) - c->used;
    if (n > length) n = length;
    memcpy(c->block + c->used, p, n);
    c->used += n; p += n; length -= n;
    if (c->used == sizeof(c->block)) {
      transform(c, c->block);
      c->used = 0;
    }
  }
}

void xiao_ota_sha256_final(xiao_ota_sha256_t *c, uint8_t digest[32]) {
  uint64_t bits = c->total * 8u;
  uint8_t one = 0x80, zero = 0;
  uint8_t length[8];
  unsigned i;
  xiao_ota_sha256_update(c, &one, 1);
  while (c->used != 56) xiao_ota_sha256_update(c, &zero, 1);
  for (i = 0; i < 8; ++i) length[i] = (uint8_t)(bits >> (56 - i * 8));
  xiao_ota_sha256_update(c, length, sizeof(length));
  for (i = 0; i < 8; ++i) store_be(digest + i * 4, c->state[i]);
}
