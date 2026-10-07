/*
 * Behavioral proof of the bootloader/transport descriptor contract.
 *
 * The bootloader verifies an Ed25519 signature over the LoRa OTA
 * transport's own 59-byte big-endian canonical wire descriptor
 * (meshcore::ota::protocol::encodeOtaDescriptorCanonical(), see
 * src/ota/protocol/OtaDescriptor.h) -- the SAME bytes and the SAME
 * signature the transport already verified (src/helpers/ota/
 * OtaFirmwareBackend.h / DescriptorVerifier::verifyPolicy()), not a
 * re-derived or re-signed form. This is exactly what xiao_ota_command_v2_t
 * + command_policy_valid() in xiao_ota_boot.c authenticate:
 * ed25519_verify(sig, wire_descriptor, 59, pubkey).
 */

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "xiao_ota_record.h"

int ed25519_verify(const unsigned char *signature, const unsigned char *message,
                   size_t message_length, const unsigned char *public_key);

/*
 * Fixture regeneration (disposable test key, not the lab key):
 *   openssl genpkey -algorithm ED25519 -out priv.pem
 *   openssl pkey -in priv.pem -pubout -out pub.pem
 *   openssl pkey -pubin -in pub.pem -outform DER | tail -c 32   # PUBLIC_KEY
 * MESSAGE_59 is a real big-endian protocol OtaDescriptor canonical wire
 * encoding (board family/variant = target split in half, role, app
 * address, size, sha256, security counter, capabilities, format/key/
 * algorithm ids) -- generated with Python struct.pack('>HHBII', ...) +
 * hashlib.sha256(...), independently of this bootloader's own
 * xiao_ota_wire_descriptor_encode(), so the round-trip assertion below is
 * a genuine cross-check, not a tautology.
 * SIGNATURE_WIRE_59 is `openssl pkeyutl -sign -rawin -inkey priv.pem` over
 * MESSAGE_59.
 */
static const unsigned char PUBLIC_KEY[32] = {
    0x69, 0x43, 0x42, 0x4f, 0x22, 0x6a, 0xee, 0x23, 0xf5, 0x75, 0x35, 0x95,
    0x02, 0xc7, 0xdf, 0x64, 0x53, 0xe7, 0x81, 0x48, 0x4a, 0xfd, 0x5d, 0x4b,
    0x15, 0x71, 0xc5, 0x46, 0x65, 0x17, 0x38, 0x79};

/* Same logical fields as the former legacy descriptor fixture, encoded as
 * the real big-endian protocol wire descriptor: boardFamily=0x584E,
 * boardVariant=0x3430, role=0, appAddress=0x27000, exactSizeBytes=0x2000,
 * sha256, counter=7, capabilities=1, formatId=keyId=algorithmId=1. */
static const unsigned char MESSAGE_59[59] = {
    0x58, 0x4e, 0x34, 0x30, 0x00, 0x00, 0x02, 0x70, 0x00, 0x00, 0x00, 0x20,
    0x00, 0xae, 0x61, 0x16, 0x9f, 0x79, 0xd2, 0x24, 0x90, 0xe6, 0xb1, 0xdb,
    0x91, 0x03, 0xc0, 0x5f, 0x9a, 0x73, 0xd7, 0x20, 0xe2, 0x3e, 0xf0, 0x06,
    0x68, 0x32, 0x0d, 0x41, 0x40, 0x98, 0x3a, 0xcc, 0x5e, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01};

/* Signature over MESSAGE_59 (i.e. what the LoRa transport verifies, and
 * what the install command's ed25519_verify() call verifies). */
static const unsigned char SIGNATURE_WIRE_59[64] = {
    0xaa, 0x10, 0xe7, 0xd2, 0xfc, 0x6e, 0xd1, 0xe6, 0xcd, 0x95, 0xdc, 0x02,
    0x24, 0xf5, 0xa2, 0x88, 0x3a, 0x3b, 0xb6, 0xc3, 0x05, 0xa0, 0x12, 0xf6,
    0x7b, 0xf8, 0x8c, 0x92, 0xe3, 0x63, 0xb7, 0x2c, 0x3b, 0xef, 0xef, 0xe5,
    0xbe, 0xdd, 0xa0, 0x0b, 0xd7, 0xf3, 0xa4, 0xf1, 0x35, 0xfd, 0x38, 0xd2,
    0x6e, 0x04, 0x74, 0xb3, 0x8f, 0x9e, 0xbe, 0x59, 0x92, 0xda, 0x4f, 0x24,
    0x6e, 0x3f, 0x1a, 0x0f};

/*
 * The "full command v2 acceptance" positive test below needs a genuinely
 * signed descriptor whose role field equals THIS build's compiled role --
 * MESSAGE_59/SIGNATURE_WIRE_59 above are fixed, real, role=0-signed
 * fixtures (kept byte-for-byte unchanged; everything above this point only
 * exercises role-agnostic decode/cross-version-mismatch behavior, never
 * xiao_ota_install_command_policy_valid()). For a role-1 build we need a
 * SEPARATE, independently real-signed role=1 fixture instead -- generated
 * the same way (disposable test key, not the lab key):
 *   openssl genpkey -algorithm ED25519 -out priv.pem
 *   openssl pkey -in priv.pem -pubout -out pub.pem
 *   openssl pkey -pubin -in pub.pem -outform DER | tail -c 32   # PUBLIC_KEY
 *   openssl pkeyutl -sign -rawin -inkey priv.pem -in msg59_role1.bin -out sig.bin
 * MESSAGE_59_ROLE1 is the exact same logical fields as MESSAGE_59 above
 * with only role patched to 1 (board family/variant, appAddress=0x27000,
 * exactSizeBytes=0x2000, sha256, counter=7, capabilities=1, format/key/
 * algorithm ids=1). Compiled unconditionally (not just for role-1 builds)
 * so the crossed-role test below can use it as the "other role" fixture
 * in BOTH role builds.
 */
static const unsigned char PUBLIC_KEY_ROLE1[32] = {
    0xd9, 0x94, 0x28, 0x61, 0x2f, 0x4c, 0xac, 0xe1, 0x39, 0x7b, 0xa6, 0xbc,
    0x87, 0xa6, 0x90, 0x26, 0xb0, 0x7f, 0x89, 0xda, 0x16, 0x0b, 0x27, 0x85,
    0x97, 0xd8, 0xf1, 0x2f, 0x6b, 0x8e, 0x9a, 0x56};

static const unsigned char MESSAGE_59_ROLE1[59] = {
    0x58, 0x4e, 0x34, 0x30, 0x01, 0x00, 0x02, 0x70, 0x00, 0x00, 0x00, 0x20,
    0x00, 0xae, 0x61, 0x16, 0x9f, 0x79, 0xd2, 0x24, 0x90, 0xe6, 0xb1, 0xdb,
    0x91, 0x03, 0xc0, 0x5f, 0x9a, 0x73, 0xd7, 0x20, 0xe2, 0x3e, 0xf0, 0x06,
    0x68, 0x32, 0x0d, 0x41, 0x40, 0x98, 0x3a, 0xcc, 0x5e, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01};

static const unsigned char SIGNATURE_WIRE_59_ROLE1[64] = {
    0x75, 0x4f, 0xdc, 0xdc, 0xb2, 0x87, 0x4b, 0x43, 0x76, 0xec, 0x3c, 0xb7,
    0x3f, 0x56, 0x4e, 0xa5, 0xac, 0xf9, 0xc6, 0xd3, 0x3c, 0x0d, 0xe5, 0xa0,
    0x83, 0xdf, 0x2f, 0xda, 0xaf, 0x55, 0x5e, 0x57, 0x57, 0xca, 0x54, 0xf2,
    0xed, 0x13, 0x91, 0xfd, 0xef, 0x83, 0x5f, 0xea, 0x9d, 0xa3, 0x41, 0x41,
    0x63, 0xf6, 0x49, 0xbf, 0x0c, 0xd5, 0xb6, 0x31, 0xf0, 0xb1, 0x73, 0x8d,
    0xf2, 0x53, 0x83, 0x0e};

/* ROLE_TEST_* always names the fixture whose embedded role matches THIS
 * build's compiled role (used by the positive acceptance test).
 * OTHER_ROLE_* always names the fixture for the OTHER role (used by the
 * crossed-role test: it must still verify cryptographically -- it is a
 * real, correctly-signed descriptor -- but be rejected at admission
 * because its role does not match this build's compiled role). */
#if XIAO_OTA_COMPILED_ROLE_ID == 1
#define ROLE_TEST_PUBLIC_KEY PUBLIC_KEY_ROLE1
#define ROLE_TEST_MESSAGE_59 MESSAGE_59_ROLE1
#define ROLE_TEST_SIGNATURE_WIRE_59 SIGNATURE_WIRE_59_ROLE1
#define OTHER_ROLE_PUBLIC_KEY PUBLIC_KEY
#define OTHER_ROLE_MESSAGE_59 MESSAGE_59
#define OTHER_ROLE_SIGNATURE_WIRE_59 SIGNATURE_WIRE_59
#else
#define ROLE_TEST_PUBLIC_KEY PUBLIC_KEY
#define ROLE_TEST_MESSAGE_59 MESSAGE_59
#define ROLE_TEST_SIGNATURE_WIRE_59 SIGNATURE_WIRE_59
#define OTHER_ROLE_PUBLIC_KEY PUBLIC_KEY_ROLE1
#define OTHER_ROLE_MESSAGE_59 MESSAGE_59_ROLE1
#define OTHER_ROLE_SIGNATURE_WIRE_59 SIGNATURE_WIRE_59_ROLE1
#endif

int main(void) {
  /* Sanity: the bootloader's own wire descriptor form is the exact
   * expected size. */
  assert(XIAO_OTA_WIRE_DESCRIPTOR_SIZE == sizeof(MESSAGE_59));

  /*
   * MESSAGE_59 was built independently (Python struct.pack, not this
   * bootloader's own encoder). Cross-check: decoding it with THIS
   * bootloader's xiao_ota_wire_descriptor_decode() must (a) succeed
   * (canonical bytes) and (b) recover the exact same field values, proving
   * this bootloader's codec agrees with the real protocol's byte layout.
   */
  {
    xiao_ota_wire_descriptor_t w;
    assert(xiao_ota_wire_descriptor_decode(MESSAGE_59, &w));
    assert(w.board_family == XIAO_OTA_BOARD_FAMILY_XIAO_NRF52840);
    assert(w.board_variant == XIAO_OTA_BOARD_VARIANT_XIAO_NRF52840);
    assert(w.role == 0);
    assert(w.app_address == 0x27000);
    assert(w.exact_size_bytes == 0x2000);
    assert(w.security_counter == 7);
    assert(w.min_boot_capabilities == XIAO_OTA_CAP_QSPI_INSTALL);
    assert(memcmp(w.sha256, MESSAGE_59 + 13, 32) == 0);
  }

  /* The signature verifies only against the exact bytes it was made for. */
  assert(ed25519_verify(SIGNATURE_WIRE_59, MESSAGE_59, sizeof(MESSAGE_59),
                        PUBLIC_KEY) == 1);
  {
    /* A single flipped message byte must be rejected (fail-closed, no
     * partial/fuzzy match). */
    unsigned char bad_msg[59];
    memcpy(bad_msg, MESSAGE_59, sizeof(bad_msg));
    bad_msg[10] ^= 0x01; /* corrupt exactSizeBytes */
    assert(ed25519_verify(SIGNATURE_WIRE_59, bad_msg, sizeof(bad_msg),
                          PUBLIC_KEY) == 0);
  }

  /*
   * Full command v2 acceptance: build a real xiao_ota_command_v2_t around
   * MESSAGE_59/SIGNATURE_WIRE_59, decode+authorize it exactly as
   * command_policy_valid() in xiao_ota_boot.c does (structural validity ->
   * xiao_ota_install_command_from_v2() -> ed25519_verify() over the wire
   * descriptor bytes with this same public key ->
   * xiao_ota_install_command_policy_valid()), and confirm it is accepted.
   * This is the positive proof that a correctly BE-encoded, genuinely
   * signed v2 descriptor is accepted by the real verification pipeline --
   * not just that mismatched forms are rejected.
   */
  {
    xiao_ota_command_v2_t cmd;
    xiao_ota_install_command_t intent;
    memset(&cmd, 0, sizeof(cmd));
    cmd.magic = XIAO_OTA_RECORD_MAGIC;
    cmd.record_version = XIAO_OTA_COMMAND_VERSION_CURRENT;
    cmd.record_bytes = sizeof(cmd);
    cmd.sequence = 1;
    cmd.transaction_nonce = 0x0102030405060708ULL;
    memcpy(cmd.wire_descriptor, ROLE_TEST_MESSAGE_59, sizeof(ROLE_TEST_MESSAGE_59));
    memcpy(cmd.admitted_signer_public_key_ed25519, ROLE_TEST_PUBLIC_KEY,
           sizeof(cmd.admitted_signer_public_key_ed25519));
    memcpy(cmd.signature_ed25519, ROLE_TEST_SIGNATURE_WIRE_59,
           sizeof(ROLE_TEST_SIGNATURE_WIRE_59));
    cmd.active_image_extent = 0x1000;
    memset(cmd.active_image_hash_sha256, 0x11, 32);
    cmd.crc32 = xiao_ota_crc32(&cmd, offsetof(xiao_ota_command_v2_t, crc32));
    cmd.commit_marker = XIAO_OTA_COMMIT_MARKER;

    assert(xiao_ota_command_v2_valid(&cmd));
    assert(xiao_ota_install_command_from_v2(&cmd, &intent));
    assert(ed25519_verify(cmd.signature_ed25519, cmd.wire_descriptor,
                          XIAO_OTA_WIRE_DESCRIPTOR_SIZE, ROLE_TEST_PUBLIC_KEY) == 1);
    assert(xiao_ota_install_command_policy_valid(
        &intent, /*counter_floor=*/6, /*expected_active_extent=*/0x1000,
        /*this_device_address=*/0xDEADBEEF));

    /* A single flipped signature byte must be rejected. */
    {
      unsigned char bad_sig[64];
      memcpy(bad_sig, ROLE_TEST_SIGNATURE_WIRE_59, 64);
      bad_sig[0] ^= 0x01;
      assert(ed25519_verify(bad_sig, cmd.wire_descriptor,
                            XIAO_OTA_WIRE_DESCRIPTOR_SIZE, ROLE_TEST_PUBLIC_KEY) == 0);
    }
    /* A single flipped message byte (any signed field) must be rejected. */
    {
      unsigned char bad_msg[XIAO_OTA_WIRE_DESCRIPTOR_SIZE];
      memcpy(bad_msg, ROLE_TEST_MESSAGE_59, sizeof(bad_msg));
      bad_msg[10] ^= 0x01; /* corrupt exactSizeBytes */
      assert(ed25519_verify(ROLE_TEST_SIGNATURE_WIRE_59, bad_msg, sizeof(bad_msg),
                            ROLE_TEST_PUBLIC_KEY) == 0);
    }
  }

  /*
   * Crossed-role rejection: OTHER_ROLE_MESSAGE_59/OTHER_ROLE_SIGNATURE_WIRE_59
   * is a REAL, independently and correctly Ed25519-signed descriptor for
   * the role this binary was NOT compiled for. Authenticity (signature
   * verification) must still succeed -- it is a genuine signature over
   * genuine bytes, role mismatch is not a corruption -- but admission via
   * xiao_ota_install_command_policy_valid() must reject it, because its
   * role field does not equal this build's XIAO_OTA_COMPILED_ROLE_ID. This
   * proves role is enforced at the admission/policy layer, not smuggled
   * into (or silently accepted by) signature verification itself.
   */
  {
    xiao_ota_command_v2_t cmd;
    xiao_ota_install_command_t intent;
    memset(&cmd, 0, sizeof(cmd));
    cmd.magic = XIAO_OTA_RECORD_MAGIC;
    cmd.record_version = XIAO_OTA_COMMAND_VERSION_CURRENT;
    cmd.record_bytes = sizeof(cmd);
    cmd.sequence = 1;
    cmd.transaction_nonce = 0x0102030405060708ULL;
    memcpy(cmd.wire_descriptor, OTHER_ROLE_MESSAGE_59, sizeof(OTHER_ROLE_MESSAGE_59));
    memcpy(cmd.admitted_signer_public_key_ed25519, OTHER_ROLE_PUBLIC_KEY,
           sizeof(cmd.admitted_signer_public_key_ed25519));
    memcpy(cmd.signature_ed25519, OTHER_ROLE_SIGNATURE_WIRE_59,
           sizeof(OTHER_ROLE_SIGNATURE_WIRE_59));
    cmd.active_image_extent = 0x1000;
    memset(cmd.active_image_hash_sha256, 0x11, 32);
    cmd.crc32 = xiao_ota_crc32(&cmd, offsetof(xiao_ota_command_v2_t, crc32));
    cmd.commit_marker = XIAO_OTA_COMMIT_MARKER;

    assert(xiao_ota_command_v2_valid(&cmd));
    /* Cryptographic authenticity still holds for the other role's genuine
     * signature over its genuine bytes. */
    assert(ed25519_verify(cmd.signature_ed25519, cmd.wire_descriptor,
                          XIAO_OTA_WIRE_DESCRIPTOR_SIZE, OTHER_ROLE_PUBLIC_KEY) == 1);
    assert(xiao_ota_install_command_from_v2(&cmd, &intent));
    assert(intent.role_id != XIAO_OTA_COMPILED_ROLE_ID);
    /* Admission must reject it solely on role mismatch. */
    assert(!xiao_ota_install_command_policy_valid(
        &intent, /*counter_floor=*/6, /*expected_active_extent=*/0x1000,
        /*this_device_address=*/0xDEADBEEF));
  }

  puts("xiao OTA bootloader/transport descriptor contract test passed");
  return 0;
}
