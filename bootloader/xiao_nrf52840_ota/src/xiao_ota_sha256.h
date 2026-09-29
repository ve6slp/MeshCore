#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t state[8];
  uint64_t total;
  uint8_t block[64];
  size_t used;
} xiao_ota_sha256_t;

void xiao_ota_sha256_init(xiao_ota_sha256_t *ctx);
void xiao_ota_sha256_update(xiao_ota_sha256_t *ctx, const void *data, size_t length);
void xiao_ota_sha256_final(xiao_ota_sha256_t *ctx, uint8_t digest[32]);

