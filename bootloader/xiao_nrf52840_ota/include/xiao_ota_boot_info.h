#pragma once

/*
 * Immutable boot-info/capability marker.
 *
 * This is a small, fixed-layout, fixed-address record baked into the
 * flashed bootloader binary itself (not the running application, not the
 * OTA journal) so the application can, at any time, read a well-known
 * flash address and fail closed if it is not talking to a qualified
 * MeshCore custom bootloader. This bootloader never writes this address at
 * any point in a stock/unmodified image's build (no such object exists in
 * upstream Adafruit_nRF52_Bootloader source), so an unmodified stock image
 * is expected to leave it at whatever an erased/never-programmed nRF52840
 * flash cell reads back as (conventionally all 0xFF for NOR flash) --
 * but this expectation has not been independently confirmed by dumping a
 * real stock-flashed board's 0xFDC00 bytes in this project; treat "reads as
 * erased" as the anticipated common case, not a verified fact. Regardless
 * of what a stock image's bytes at this address actually are,
 * xiao_ota_boot_info_valid() enforces bad-magic/bad-format-version/bad-CRC
 * rejection unconditionally on whatever is read -- detection does not
 * depend on, or assume, any particular stock-image byte pattern.
 *
 * Placement: a dedicated linker section (.xiao_ota_boot_info) inside the
 * existing 2 KiB BOOTLOADER_CONFIG flash region (0xFD800..0xFE000), at a
 * fixed offset chosen with wide margin from the stock Adafruit
 * `.bootloaderConfig` UF2/CF2 config-key table that also lives in that
 * region (that table uses roughly the first 56 bytes; this marker starts
 * 1024 bytes in and is well clear of it in both directions before the
 * region ends at 0xFE000). See linker/nrf52840_xiao_ota*.ld.
 */

#include <stdbool.h>
#include <stdint.h>

#include "xiao_ota_record.h"

#define XIAO_OTA_BOOT_INFO_MAGIC UINT32_C(0x584F4249) /* "XOBI" */
#define XIAO_OTA_BOOT_INFO_FORMAT_VERSION 1u

/* Fixed address the application reads directly (flash is memory-mapped on
 * nRF52840); also enforced by the linker script placing this exact section
 * there, and cross-checked at link time (see the ASSERT in the linker
 * scripts). */
#define XIAO_OTA_BOOT_INFO_ADDRESS UINT32_C(0xFDC00)

typedef struct XIAO_OTA_PACKED {
  uint32_t magic;             /* XIAO_OTA_BOOT_INFO_MAGIC */
  uint16_t format_version;    /* XIAO_OTA_BOOT_INFO_FORMAT_VERSION */
  uint16_t struct_bytes;      /* sizeof(xiao_ota_boot_info_t), for forward compat */
  uint32_t board_target_id;   /* XIAO_OTA_BOARD_TARGET this binary enforces */
  uint32_t role_id;           /* XIAO_OTA_COMPILED_ROLE_ID (0 or 1) */
  uint32_t capability_flags;  /* e.g. XIAO_OTA_CAP_QSPI_INSTALL */
  uint16_t key_id;            /* XIAO_OTA_KEY_ID */
  uint16_t algorithm_id;      /* XIAO_OTA_ALGORITHM_ED25519 */
  /*
   * NOT a trust anchor and NOT what this bootloader verifies install
   * commands against: verification is dynamic, per-command, against
   * EACH command's own embedded admitted_signer_public_key_ed25519 (see
   * xiao_ota_command_v2_t, xiao_ota_record.h). This field is purely an
   * informational record of the public half of whatever key
   * tools/sign_image.py's --private-key convenience default happened to
   * use for THIS build/board/role at prepare_upstream.py time -- i.e.
   * "which lab/test key this artifact's own default signing tool would
   * sign with," not "the one key this bootloader will accept." Treat it
   * the same as board_target_id/role_id/capability_flags above: a
   * qualified-build identity/provenance fact for tooling and app-side
   * sanity checks, never an install-time authorization input.
   */
  uint8_t reference_signer_public_key_ed25519[32];
  uint32_t crc32;             /* IEEE CRC-32 over every byte above (xiao_ota_crc32) */
} xiao_ota_boot_info_t;

#define XIAO_OTA_BOOT_INFO_STRUCT_BYTES ((uint16_t)sizeof(xiao_ota_boot_info_t))

/*
 * Pure, host-testable helpers. Building the actual immutable ROM instance
 * (xiao_ota_boot_info.c) uses these; the application/app-bridge should use
 * xiao_ota_boot_info_valid() on whatever it reads back from
 * XIAO_OTA_BOOT_INFO_ADDRESS, and MUST treat any false result -- whatever
 * the actual byte pattern turns out to be on an unqualified/stock image,
 * erased or not -- as "cannot confirm a qualified custom boot" and fail
 * closed rather than assume install capability. Confirming a qualified
 * custom boot this way is NOT itself an install-command trust decision:
 * actual install-command signature verification always reads the
 * admitted key from that specific command (xiao_ota_command_v2_t), never
 * from reference_signer_public_key_ed25519 below.
 */
void xiao_ota_boot_info_build(xiao_ota_boot_info_t *out, uint32_t board_target_id,
                              uint32_t role_id, uint32_t capability_flags,
                              uint16_t key_id, uint16_t algorithm_id,
                              const uint8_t reference_signer_public_key[32]);
bool xiao_ota_boot_info_valid(const xiao_ota_boot_info_t *info);
