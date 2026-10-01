#include "xiao_ota_boot_info.h"

#include "xiao_ota_public_key.h"

void xiao_ota_boot_info_build(xiao_ota_boot_info_t *out, uint32_t board_target_id,
                              uint32_t role_id, uint32_t capability_flags,
                              uint16_t key_id, uint16_t algorithm_id,
                              const uint8_t reference_signer_public_key[32]) {
  size_t i;
  out->magic = XIAO_OTA_BOOT_INFO_MAGIC;
  out->format_version = XIAO_OTA_BOOT_INFO_FORMAT_VERSION;
  out->struct_bytes = XIAO_OTA_BOOT_INFO_STRUCT_BYTES;
  out->board_target_id = board_target_id;
  out->role_id = role_id;
  out->capability_flags = capability_flags;
  out->key_id = key_id;
  out->algorithm_id = algorithm_id;
  for (i = 0; i < sizeof(out->reference_signer_public_key_ed25519); ++i) {
    out->reference_signer_public_key_ed25519[i] = reference_signer_public_key[i];
  }
  out->crc32 = xiao_ota_crc32(out, offsetof(xiao_ota_boot_info_t, crc32));
}

bool xiao_ota_boot_info_valid(const xiao_ota_boot_info_t *info) {
  if (info == NULL) return false;
  if (info->magic != XIAO_OTA_BOOT_INFO_MAGIC) return false;
  if (info->format_version != XIAO_OTA_BOOT_INFO_FORMAT_VERSION) return false;
  if (info->struct_bytes != XIAO_OTA_BOOT_INFO_STRUCT_BYTES) return false;
  return info->crc32 == xiao_ota_crc32(info, offsetof(xiao_ota_boot_info_t, crc32));
}

/*
 * The actual immutable marker baked into this bootloader binary: a real
 * `const` object, fully initialized at compile time from this build's real
 * board profile, capability, and reference signer key, placed by the
 * linker script's dedicated .xiao_ota_boot_info section at the fixed
 * XIAO_OTA_BOOT_INFO_ADDRESS (see linker/nrf52840_xiao_ota*.ld). There is no
 * runtime write path to this object anywhere in this bootloader -- it is
 * `const`, lives in true flash ROM, and a Cortex-M plain store instruction
 * to it would fault rather than silently succeed even if something tried.
 *
 * Every field except crc32 is a real compile-time constant expression. The
 * CRC-32 (the same IEEE/reflected algorithm as xiao_ota_crc32(), verified
 * identical in tests/test_record.c) cannot itself be written as a C
 * constant expression by hand without risking silent drift from the real
 * field values, so its literal below is a documented placeholder that
 * tools/prepare_upstream.py computes for real (by independently replicating
 * xiao_ota_crc32() in Python over the exact same packed 56-byte layout
 * preceding this field) and substitutes textually into the copied build
 * tree before compilation -- exactly the same "compute a real value, patch
 * it into vendored source" approach prepare_upstream.py already uses
 * elsewhere (see its main.c patching). A CRC-32 is a 32-bit value, so
 * 0xFFFFFFFF is not mathematically excluded as a real result over some
 * input -- it is astronomically unlikely over these specific 56 bytes, and
 * more importantly this exact placeholder is what prepare_upstream.py's
 * patch step matches on textually (see XIAO_OTA_BOOT_INFO_CRC32_PLACEHOLDER
 * below). Anyone who forgets to run it through prepare_upstream.py gets a
 * marker whose CRC field still reads this placeholder text/value and, in
 * the overwhelming majority of cases, an immediately-failing
 * xiao_ota_boot_info_valid(); prepare_upstream.py itself is the actual
 * enforcement point (it raises SystemExit if the placeholder text or the
 * expected 56-byte pre-CRC layout aren't found), not a probabilistic
 * argument about CRC-32 collisions.
 */
__attribute__((section(".xiao_ota_boot_info"), used))
const xiao_ota_boot_info_t g_xiao_ota_boot_info = {
    .magic = XIAO_OTA_BOOT_INFO_MAGIC,
    .format_version = XIAO_OTA_BOOT_INFO_FORMAT_VERSION,
    .struct_bytes = XIAO_OTA_BOOT_INFO_STRUCT_BYTES,
    .board_target_id = XIAO_OTA_BOARD_TARGET,
    .role_id = XIAO_OTA_COMPILED_ROLE_ID,
    .capability_flags = XIAO_OTA_CAP_QSPI_INSTALL,
    .key_id = XIAO_OTA_KEY_ID,
    .algorithm_id = XIAO_OTA_ALGORITHM_ED25519,
    .reference_signer_public_key_ed25519 = {XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES},
    .crc32 = 0xFFFFFFFFu, /* XIAO_OTA_BOOT_INFO_CRC32_PLACEHOLDER: patched by prepare_upstream.py */
};
