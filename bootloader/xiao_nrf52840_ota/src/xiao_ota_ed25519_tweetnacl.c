#include <stddef.h>
#include <string.h>

#include "tweetnacl.h"

int ed25519_verify(const unsigned char *signature, const unsigned char *message,
                   size_t message_length, const unsigned char *public_key) {
  unsigned char signed_message[64 + 71];
  unsigned char opened_message[71];
  unsigned long long opened_length = 0;

  if (message_length > sizeof(opened_message) || (signature[63] & 0xe0u) != 0) {
    return 0;
  }
  memcpy(signed_message, signature, 64);
  memcpy(signed_message + 64, message, message_length);
  return crypto_sign_open(opened_message, &opened_length, signed_message,
                          64 + message_length, public_key) == 0 &&
         opened_length == message_length &&
         memcmp(opened_message, message, message_length) == 0;
}
