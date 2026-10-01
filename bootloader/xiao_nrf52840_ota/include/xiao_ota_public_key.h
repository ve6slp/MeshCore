#pragma once

#include <stdint.h>

/*
 * Fixed, non-secret placeholder value committed directly in source
 * control -- NOT generated, provisioned, or rotated by any tool. It exists
 * only to give two build-time-only consumers a stable arbitrary 32-byte
 * value: (1) the boot-info marker's build-provenance field
 * (xiao_ota_boot_info_t.reference_signer_public_key_ed25519, see
 * xiao_ota_boot_info.h) and (2) tools/prepare_upstream.py's CRC-patch
 * input. There is no corresponding private key retained anywhere in this
 * repo, and this value is NEVER a runtime install-command trust anchor:
 * that is always read per-command from a command's own
 * admitted_signer_public_key_ed25519 (xiao_ota_record.h; see "App-admitted
 * signer key" in README.md). tools/provision_lab_key.py generates an
 * UNRELATED, purely local/offline private-key fixture (under .tmp, never
 * committed) for use with sign_image.py's --private-key in manual/lab
 * signing workflows; it does not read or write this header.
 */
#define XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES \
    0x5a, 0x48, 0xad, 0xfc, 0x09, 0x9a, 0xe3, 0xac, \
    0x07, 0x67, 0xb3, 0xf8, 0x76, 0xd8, 0x1c, 0x59, \
    0xad, 0x48, 0x75, 0xab, 0xa8, 0xcf, 0x7a, 0x0c, \
    0x3c, 0xb5, 0xa9, 0x62, 0xf9, 0xac, 0x57, 0x2a

static const uint8_t xiao_ota_lab_public_key_ed25519[32] = {
    XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES,
};
