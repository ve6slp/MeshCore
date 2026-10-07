#pragma once

// Self-contained CRC-32 (IEEE 802.3 / zlib polynomial 0xEDB88320) used to
// protect journal records and receipt-map payloads against corruption and
// torn writes. Deliberately independent of any other CRC implementation in
// the tree.

#include <stdint.h>
#include <stddef.h>

namespace ota {
namespace storage {

class Crc32 {
public:
  static uint32_t compute(const uint8_t* data, size_t len, uint32_t seed = 0xFFFFFFFFu) {
    uint32_t crc = seed;
    for (size_t i = 0; i < len; ++i) {
      crc ^= data[i];
      for (int bit = 0; bit < 8; ++bit) {
        const uint32_t mask = (uint32_t)(-(int32_t)(crc & 1u));
        crc = (crc >> 1) ^ (0xEDB88320u & mask);
      }
    }
    return crc;
  }

  // Convenience wrapper returning the finalized (inverted) CRC, matching the
  // conventional CRC-32 output used by zlib/Ethernet.
  static uint32_t computeFinalized(const uint8_t* data, size_t len) {
    return compute(data, len, 0xFFFFFFFFu) ^ 0xFFFFFFFFu;
  }
};

}  // namespace storage
}  // namespace ota
