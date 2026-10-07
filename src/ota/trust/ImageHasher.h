#pragma once

// Streams bytes out of a bounded FlashRegion through a HashAlgorithm so the
// image-hash step of the trust pipeline never needs to load an entire (up
// to 792 KiB) candidate image into RAM at once.

#include <stdint.h>
#include "ota/platform/FlashRegion.h"
#include "ota/platform/FlashTypes.h"
#include "ota/trust/HashAlgorithm.h"

namespace ota {
namespace trust {

class ImageHasher {
public:
  static constexpr uint32_t kStreamBufferBytes = 256;

  // Hashes exactly `length` bytes starting at offset 0 of `region` into
  // `out_digest`. Returns false (leaving `out_digest` untouched) if any
  // read fails or `length` exceeds the region's bounds -- callers must
  // treat a false return as "hash pipeline error", never as a passing
  // comparison against a zeroed digest.
  static bool hashRegion(HashAlgorithm& hasher, const platform::FlashRegion& region, uint32_t length, uint8_t out_digest[32]) {
    if (!region.isValid() || length > region.sizeBytes()) {
      return false;
    }

    hasher.reset();
    uint8_t buf[kStreamBufferBytes];
    uint32_t offset = 0;
    while (offset < length) {
      const uint32_t remaining = length - offset;
      const uint32_t step = remaining > kStreamBufferBytes ? kStreamBufferBytes : remaining;
      if (!platform::isOk(region.read(offset, buf, step))) {
        return false;
      }
      hasher.update(buf, step);
      offset += step;
    }
    hasher.finish(out_digest);
    return true;
  }
};

}  // namespace trust
}  // namespace ota
