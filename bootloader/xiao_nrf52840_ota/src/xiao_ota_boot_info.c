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

/* Immutable flash marker at XIAO_OTA_BOOT_INFO_ADDRESS. build_pair.py
 * computes its CRC over the packed fields before compilation. The reserved
 * reference key field never authorizes installation. */
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
    .reference_signer_public_key_ed25519 = {XIAO_OTA_REFERENCE_PUBLIC_KEY_ED25519_BYTES},
    .crc32 = 0xFFFFFFFFu, /* XIAO_OTA_BOOT_INFO_CRC32_PLACEHOLDER: patched by build_pair.py */
};
