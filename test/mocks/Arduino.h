#pragma once

#include <cstdint>
#include <cmath>
#include <cstdio>
#include "Stream.h"

inline uint32_t g_mock_millis = 0;

using std::isnan;

template <typename T, typename L, typename H>
inline T constrain(T value, L low, H high) {
  return value < low ? static_cast<T>(low) : value > high ? static_cast<T>(high) : value;
}

inline char* ltoa(long value, char* out, int base) {
  if (base != 10) return nullptr;
  std::sprintf(out, "%ld", value);
  return out;
}

inline uint32_t millis() {
  return g_mock_millis;
}

inline void delay(uint32_t ms) {
  g_mock_millis += ms;
}
