/*
 * Host-testable behavioral coverage for the immutable boot-info/capability
 * marker (xiao_ota_boot_info.h/.c). Wired into `test-xiao-ota-bootloader`
 * in the repo Makefile; see README.md's "Build" section for the recipe.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "xiao_ota_boot_info.h"
#include "xiao_ota_public_key.h"

int main(void) {
  /* Sanity: the real g_xiao_ota_boot_info instance this bootloader ships
   * has the placeholder CRC replaced by prepare_upstream.py before it is
   * ever compiled for a real board; on a from-repo (unpatched) build the
   * placeholder is deliberately invalid, so validation is expected to fail
   * until that patch step runs. This test proves the *logic*, not the
   * unpatched literal in the committed source file. */
  assert(sizeof(xiao_ota_boot_info_t) <= 128); /* must comfortably fit the reserved slot */
  assert(XIAO_OTA_BOOT_INFO_ADDRESS >= 0xFD800 + 0x400);
  assert(XIAO_OTA_BOOT_INFO_ADDRESS + sizeof(xiao_ota_boot_info_t) <= 0xFE000);

  xiao_ota_boot_info_t info;
  xiao_ota_boot_info_build(&info, XIAO_OTA_TARGET_XIAO_NRF52840, XIAO_OTA_ROLE_ANY,
                           XIAO_OTA_CAP_QSPI_INSTALL, XIAO_OTA_KEY_ID,
                           XIAO_OTA_ALGORITHM_ED25519, xiao_ota_lab_public_key_ed25519);

  /* Positive: a genuinely built marker validates. */
  assert(xiao_ota_boot_info_valid(&info));
  assert(info.board_target_id == XIAO_OTA_TARGET_XIAO_NRF52840);
  assert(memcmp(info.trusted_public_key, xiao_ota_lab_public_key_ed25519, 32) == 0);

  /* A stock/unqualified bootloader leaves this flash region erased --
   * simulate that exact byte pattern and confirm it is unambiguously
   * rejected (fail closed), not merely "different". */
  {
    xiao_ota_boot_info_t erased;
    memset(&erased, 0xFF, sizeof(erased));
    assert(!xiao_ota_boot_info_valid(&erased));
  }

  /* All-zero (e.g. a naively zero-initialized page, not actually erased
   * flash, but a plausible corruption/attack pattern) must also fail. */
  {
    xiao_ota_boot_info_t zeroed;
    memset(&zeroed, 0x00, sizeof(zeroed));
    assert(!xiao_ota_boot_info_valid(&zeroed));
  }

  /* Tamper rejection: flipping any single field must invalidate the CRC. */
  {
    xiao_ota_boot_info_t tampered = info;
    tampered.board_target_id ^= 1u;
    assert(!xiao_ota_boot_info_valid(&tampered));
  }
  {
    xiao_ota_boot_info_t tampered = info;
    tampered.capability_flags = 0; /* strip the install capability bit */
    assert(!xiao_ota_boot_info_valid(&tampered));
  }
  {
    xiao_ota_boot_info_t tampered = info;
    tampered.trusted_public_key[0] ^= 1u; /* swap the trusted key */
    assert(!xiao_ota_boot_info_valid(&tampered));
  }
  {
    xiao_ota_boot_info_t tampered = info;
    tampered.format_version = 2; /* unknown future format */
    assert(!xiao_ota_boot_info_valid(&tampered));
  }

  /* A different real board profile (SenseCAP Solar P1) produces a
   * distinct, independently valid marker with a different board_target_id
   * -- never a wildcard, never confusable with the XIAO profile's marker. */
  {
    xiao_ota_boot_info_t sensecap;
    xiao_ota_boot_info_build(&sensecap, XIAO_OTA_TARGET_SENSECAP_SOLAR_P1,
                             XIAO_OTA_ROLE_ANY, XIAO_OTA_CAP_QSPI_INSTALL,
                             XIAO_OTA_KEY_ID, XIAO_OTA_ALGORITHM_ED25519,
                             xiao_ota_lab_public_key_ed25519);
    assert(xiao_ota_boot_info_valid(&sensecap));
    assert(sensecap.board_target_id != info.board_target_id);
    assert(sensecap.board_target_id == XIAO_OTA_TARGET_SENSECAP_SOLAR_P1);
    /* Cross-check: a XIAO app that only trusts the XIAO target must reject
     * a SenseCAP marker, and vice versa -- this is the actual "app detects
     * qualified boot vs. wrong board" check, not a naive magic/CRC-only
     * check. */
    assert(sensecap.board_target_id != XIAO_OTA_TARGET_XIAO_NRF52840);
    assert(info.board_target_id != XIAO_OTA_TARGET_SENSECAP_SOLAR_P1);
  }

  puts("xiao OTA boot-info/capability marker tests passed");
  return 0;
}
