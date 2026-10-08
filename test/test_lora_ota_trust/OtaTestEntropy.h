#pragma once

#include <cstddef>
#include <cstdint>

// Native stand-in for board hardware entropy: every call yields new bytes,
// like the nRF/ESP RNG, so each BEGIN draws a distinct nonce. Tests that
// need entropy failure attach their own function.
inline uint64_t& otaTestEntropyState() {
  static uint64_t state = 0x9E3779B97F4A7C15ull;
  return state;
}

inline bool otaTestEntropy(void*, uint8_t* out, size_t len) {
  auto& state = otaTestEntropyState();
  for (size_t i = 0; i < len; ++i) {
    if ((i & 7u) == 0) {
      state += 0x9E3779B97F4A7C15ull;
    }
    uint64_t z = state + i;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    z ^= z >> 31;
    out[i] = static_cast<uint8_t>(z >> (8 * (i & 7u)));
  }
  return true;
}

template <typename Integration>
inline bool attachOtaTestEntropy(Integration& integration) {
  integration.attachEntropy(nullptr, &otaTestEntropy);
  return true;
}
