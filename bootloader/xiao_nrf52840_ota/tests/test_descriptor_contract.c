/*
 * Behavioral proof of the bootloader/transport descriptor contract, for
 * BOTH command versions this bootloader accepts.
 *
 * Command v1 (legacy): the bootloader verifies an Ed25519 signature over
 * its own 71-byte little-endian xiao_ota_canonical_descriptor_t (byte-for-
 * byte equal to ota::trust::CanonicalDescriptor::serialize(), produced
 * offline by tools/sign_image.py --legacy-v1).
 *
 * Command v2 (current): the bootloader verifies an Ed25519 signature over
 * the LoRa OTA transport's own 59-byte big-endian canonical wire descriptor
 * (meshcore::ota::protocol::encodeOtaDescriptorCanonical(), see
 * src/ota/protocol/OtaDescriptor.h) -- the SAME bytes and the SAME
 * signature the transport already verified (src/helpers/ota/
 * OtaFirmwareBackend.h / DescriptorVerifier::verifyPolicy()), not a
 * re-derived or re-signed form. This is exactly what
 * xiao_ota_command_v2_t + command_policy_valid() in xiao_ota_boot.c
 * authenticate: ed25519_verify(sig, wire_descriptor, 59, pubkey).
 *
 * These two message forms carry overlapping logical fields (target/role/
 * address, size, hash, counter, capability, format/key/algo ids) but are
 * NOT the same byte sequence: different field widths (role is 1 byte on
 * the wire vs. 4 bytes in v1), different field order (the image hash is
 * not first on the wire), different endianness (wire is big-endian, v1 is
 * little-endian), and fields present in only one form (device_address/
 * allow_broadcast_address only exist in v1; boardFamily/boardVariant only
 * exist on the wire). A signature produced over one form can never verify
 * against the other -- this test proves that fail-closed cross-version
 * property AND that each version's own real, correctly-encoded signed
 * message is genuinely accepted, using the exact codec
 * (xiao_ota_wire_descriptor_encode/decode) and the exact ed25519_verify()
 * entry point the real boot flow calls.
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
 * MESSAGE_71 is a little-endian xiao_ota_canonical_descriptor_t and
 * MESSAGE_59 is a real big-endian protocol OtaDescriptor canonical wire
 * encoding for the same logical field values (board family/variant =
 * target split in half, role, app address, size, sha256, security counter,
 * capabilities, format/key/algorithm ids) -- generated with Python
 * struct.pack('>HHBII', ...) + hashlib.sha256(...), independently of this
 * bootloader's own xiao_ota_wire_descriptor_encode(), so the round-trip
 * assertion below is a genuine cross-check, not a tautology.
 * Each SIGNATURE_* is `openssl pkeyutl -sign -rawin -inkey priv.pem` over
 * the matching MESSAGE_* file.
 */
static const unsigned char PUBLIC_KEY[32] = {
    0x69, 0x43, 0x42, 0x4f, 0x22, 0x6a, 0xee, 0x23, 0xf5, 0x75, 0x35, 0x95,
    0x02, 0xc7, 0xdf, 0x64, 0x53, 0xe7, 0x81, 0x48, 0x4a, 0xfd, 0x5d, 0x4b,
    0x15, 0x71, 0xc5, 0x46, 0x65, 0x17, 0x38, 0x79};

static const unsigned char MESSAGE_71[71] = {
    0xae, 0x61, 0x16, 0x9f, 0x79, 0xd2, 0x24, 0x90, 0xe6, 0xb1, 0xdb, 0x91,
    0x03, 0xc0, 0x5f, 0x9a, 0x73, 0xd7, 0x20, 0xe2, 0x3e, 0xf0, 0x06, 0x68,
    0x32, 0x0d, 0x41, 0x40, 0x98, 0x3a, 0xcc, 0x5e, 0x30, 0x34, 0x4e, 0x58,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
    0x00, 0x00, 0x70, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00};

/* Same logical fields as MESSAGE_71, encoded as the real big-endian
 * protocol wire descriptor: boardFamily=0x584E, boardVariant=0x3430,
 * role=0, appAddress=0x27000, exactSizeBytes=0x2000, sha256, counter=7,
 * capabilities=1, formatId=keyId=algorithmId=1. */
static const unsigned char MESSAGE_59[59] = {
    0x58, 0x4e, 0x34, 0x30, 0x00, 0x00, 0x02, 0x70, 0x00, 0x00, 0x00, 0x20,
    0x00, 0xae, 0x61, 0x16, 0x9f, 0x79, 0xd2, 0x24, 0x90, 0xe6, 0xb1, 0xdb,
    0x91, 0x03, 0xc0, 0x5f, 0x9a, 0x73, 0xd7, 0x20, 0xe2, 0x3e, 0xf0, 0x06,
    0x68, 0x32, 0x0d, 0x41, 0x40, 0x98, 0x3a, 0xcc, 0x5e, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01};

/* Signature over MESSAGE_59 (i.e. what the LoRa transport verifies, and
 * what command v2's ed25519_verify() call verifies). */
static const unsigned char SIGNATURE_WIRE_59[64] = {
    0xaa, 0x10, 0xe7, 0xd2, 0xfc, 0x6e, 0xd1, 0xe6, 0xcd, 0x95, 0xdc, 0x02,
    0x24, 0xf5, 0xa2, 0x88, 0x3a, 0x3b, 0xb6, 0xc3, 0x05, 0xa0, 0x12, 0xf6,
    0x7b, 0xf8, 0x8c, 0x92, 0xe3, 0x63, 0xb7, 0x2c, 0x3b, 0xef, 0xef, 0xe5,
    0xbe, 0xdd, 0xa0, 0x0b, 0xd7, 0xf3, 0xa4, 0xf1, 0x35, 0xfd, 0x38, 0xd2,
    0x6e, 0x04, 0x74, 0xb3, 0x8f, 0x9e, 0xbe, 0x59, 0x92, 0xda, 0x4f, 0x24,
    0x6e, 0x3f, 0x1a, 0x0f};

/* Signature over MESSAGE_71 (i.e. what command v1's ed25519_verify() call
 * verifies). */
static const unsigned char SIGNATURE_BOOTLOADER_71[64] = {
    0xeb, 0x5d, 0x85, 0x43, 0x47, 0x9d, 0x85, 0xa2, 0x0c, 0x76, 0x96, 0xfe,
    0x47, 0x33, 0x4f, 0x31, 0xfa, 0x5c, 0x0f, 0x5e, 0xec, 0x24, 0x82, 0xd0,
    0x0b, 0x6f, 0x0b, 0x6a, 0xcd, 0x96, 0x77, 0xa0, 0xf5, 0x16, 0xf7, 0x17,
    0x31, 0x93, 0x68, 0x96, 0x72, 0x38, 0xfb, 0x07, 0x4d, 0xc7, 0xde, 0x91,
    0xb6, 0x0d, 0x71, 0x27, 0xfd, 0x8a, 0x58, 0xf0, 0x05, 0x12, 0xbc, 0xfe,
    0x38, 0x9e, 0x4a, 0x02};

int main(void) {
  /* Sanity: the bootloader's own descriptor forms are the exact expected
   * sizes. */
  assert(sizeof(xiao_ota_canonical_descriptor_t) == sizeof(MESSAGE_71));
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
    assert(memcmp(w.sha256, MESSAGE_71, 32) == 0); /* MESSAGE_71 starts with the same sha256 */
  }

  /* Each signature verifies only against the exact bytes it was made for. */
  assert(ed25519_verify(SIGNATURE_WIRE_59, MESSAGE_59, sizeof(MESSAGE_59),
                        PUBLIC_KEY) == 1);
  assert(ed25519_verify(SIGNATURE_BOOTLOADER_71, MESSAGE_71,
                        sizeof(MESSAGE_71), PUBLIC_KEY) == 1);

  /*
   * The core cross-version contract: a transport-verified wire signature
   * over the 59-byte protocol descriptor MUST NOT be accepted as a v1
   * 71-byte signature, and vice versa, even though every logical field
   * value matches. Command v1 and v2 authenticate strictly against their
   * own message form; there is no "bridge" or reinterpretation.
   */
  assert(ed25519_verify(SIGNATURE_WIRE_59, MESSAGE_71, sizeof(MESSAGE_71),
                        PUBLIC_KEY) == 0);
  assert(ed25519_verify(SIGNATURE_BOOTLOADER_71, MESSAGE_59,
                        sizeof(MESSAGE_59), PUBLIC_KEY) == 0);

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
    cmd.record_version = XIAO_OTA_COMMAND_VERSION_WIRE_V2;
    cmd.record_bytes = sizeof(cmd);
    cmd.sequence = 1;
    cmd.transaction_nonce = 0x0102030405060708ULL;
    memcpy(cmd.wire_descriptor, MESSAGE_59, sizeof(MESSAGE_59));
    memcpy(cmd.signature_ed25519, SIGNATURE_WIRE_59, sizeof(SIGNATURE_WIRE_59));
    cmd.active_image_extent = 0x1000;
    memset(cmd.active_image_hash_sha256, 0x11, 32);
    cmd.crc32 = xiao_ota_crc32(&cmd, offsetof(xiao_ota_command_v2_t, crc32));
    cmd.commit_marker = XIAO_OTA_COMMIT_MARKER;

    assert(xiao_ota_command_v2_valid(&cmd));
    assert(xiao_ota_install_command_from_v2(&cmd, &intent));
    assert(ed25519_verify(cmd.signature_ed25519, cmd.wire_descriptor,
                          XIAO_OTA_WIRE_DESCRIPTOR_SIZE, PUBLIC_KEY) == 1);
    assert(xiao_ota_install_command_policy_valid(
        &intent, /*counter_floor=*/6, /*expected_active_extent=*/0x1000,
        /*this_device_address=*/0xDEADBEEF));

    /* A single flipped signature byte must be rejected. */
    {
      unsigned char bad_sig[64];
      memcpy(bad_sig, SIGNATURE_WIRE_59, 64);
      bad_sig[0] ^= 0x01;
      assert(ed25519_verify(bad_sig, cmd.wire_descriptor,
                            XIAO_OTA_WIRE_DESCRIPTOR_SIZE, PUBLIC_KEY) == 0);
    }
    /* A single flipped message byte (any signed field) must be rejected. */
    {
      unsigned char bad_msg[XIAO_OTA_WIRE_DESCRIPTOR_SIZE];
      memcpy(bad_msg, MESSAGE_59, sizeof(bad_msg));
      bad_msg[10] ^= 0x01; /* corrupt exactSizeBytes */
      assert(ed25519_verify(SIGNATURE_WIRE_59, bad_msg, sizeof(bad_msg),
                            PUBLIC_KEY) == 0);
    }
  }

  puts("xiao OTA bootloader/transport descriptor contract test passed");
  return 0;
}
