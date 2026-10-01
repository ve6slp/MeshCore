#pragma once

/*
 * Force-included (GCC -include) into xiao_ota_boot_io.c by the Makefile's
 * test-xiao-ota-boot-process recipe, which also still passes
 * -DXIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY=xiao_ota_test_public_key_ed25519. As
 * of the app-admitted-signer-key design (xiao_ota_command_v2_t's
 * admitted_signer_public_key_ed25519 field), xiao_ota_boot_io.c no longer
 * has any XIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY-gated code path to substitute
 * into -- verification now always reads the key from the command record
 * itself, never from a compiled-in/overridable macro. Both the -D and
 * this -include are therefore harmless, unused build inputs (an unused
 * command-line macro definition and an unused extern declaration; neither
 * triggers a diagnostic under this build's warning flags), kept only
 * because the Makefile recipe that passes them is owned outside this
 * directory. test_boot_process.c defines (and uses) the symbol below
 * directly: its public half is copied into every test-built command's
 * own admitted_signer_public_key_ed25519 field, exactly mirroring how the
 * real running app durably snapshots an admitted key at COMMIT.
 */

#include <stdint.h>

extern uint8_t xiao_ota_test_public_key_ed25519[32];
