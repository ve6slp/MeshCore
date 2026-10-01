#pragma once

/*
 * Force-included (GCC -include) into xiao_ota_boot_io.c ONLY for the native
 * fake-IO test build, declaring the test-only trust anchor symbol that
 * -DXIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY=xiao_ota_test_public_key_ed25519
 * substitutes at both ed25519_verify() call sites. Never used by a
 * production build (which keeps the default xiao_ota_lab_public_key_ed25519
 * anchor from xiao_ota_public_key.h and never defines the override).
 */

#include <stdint.h>

extern uint8_t xiao_ota_test_public_key_ed25519[32];
