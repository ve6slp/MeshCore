#include <stddef.h>
#include <string.h>

#include "tweetnacl.h"

int ed25519_verify(const unsigned char *signature, const unsigned char *message,
                   size_t message_length, const unsigned char *public_key) {
  /*
   * tweetnacl's crypto_sign_open(m, mlen, sm, n, pk) copies the FULL
   * signed message (all `n` == 64 + message_length bytes: signature plus
   * message) into `m` before validating and truncating it, so `m` must be
   * sized for the concatenated signature+message, not just the message.
   * Sizing `opened_message` to only `message_length` bytes here silently
   * overflowed the stack by up to 64 bytes for every real, full-size
   * (71-byte) install-command descriptor verification -- exactly the
   * signature check that gates a candidate install
   * (xiao_ota_boot.c:command_policy_valid()). The prior empty-message unit
   * test never exercised message_length > 7, so it could not catch this.
   */
  unsigned char signed_message[64 + 71];
  unsigned char opened_message[64 + 71];
  unsigned long long opened_length = 0;

  if (message_length > 71u || (signature[63] & 0xe0u) != 0) {
    return 0;
  }
  memcpy(signed_message, signature, 64);
  memcpy(signed_message + 64, message, message_length);
  return crypto_sign_open(opened_message, &opened_length, signed_message,
                          64 + message_length, public_key) == 0 &&
         opened_length == message_length &&
         memcmp(opened_message, message, message_length) == 0;
}
