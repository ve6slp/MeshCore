#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Generic (File-type agnostic) bounded MANDATORY-identity-artifact
// integrity check shared by IdentityStore::checkIntegrity(). `File` is a
// template parameter so the identical read+compare logic instantiates
// against either the real Arduino/Adafruit_LittleFS/fs::FS File type
// (MCU build) or a native byte-backed fake file (host test) with zero
// source changes -- so a genuine regression in the bounded-read/content-
// comparison decision itself would be caught natively, not merely by
// full MCU compilation.
//
// Deliberately takes a DIRECT `File::read(void*, size)` call (never
// Stream::readBytes(), which can internally loop/block up to its
// default ~1s timeout waiting for more bytes on a short/stalled file --
// an unacceptable risk inside a per-tick health probe), and always
// compares the persisted bytes against the CALLER-supplied "currently
// active" key bytes -- never trusting read-LENGTH alone, so a well-
// formed-but-WRONG/stale/foreign persisted identity is correctly
// reported as a fault rather than silently accepted as healthy.
namespace identity_io {

template <typename File>
inline bool checkIdentityIntegrity(File& file, size_t pub_key_size, size_t prv_key_size,
                                    const uint8_t* expected_pub_key, const uint8_t* expected_prv_key,
                                    uint8_t* scratch_buf, size_t scratch_buf_len) {
  const size_t total = pub_key_size + prv_key_size;
  if (scratch_buf_len < total) return false;  // caller-supplied scratch buffer too small: refuse, never overrun.

  int n = file.read(scratch_buf, total);
  if (n != (int)total) return false;  // short/failed read -> genuine fault, never a legitimate absence here.

  bool pub_ok = memcmp(scratch_buf, expected_pub_key, pub_key_size) == 0;
  bool prv_ok = memcmp(scratch_buf + pub_key_size, expected_prv_key, prv_key_size) == 0;
  return pub_ok && prv_ok;
}

}  // namespace identity_io
