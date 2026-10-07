#pragma once
#include <cstdint>
#include <Arduino.h>

// Native preference serialization tests have no physical radio.
struct NativeRadioDriver {
  bool setRxBoostedGainMode(bool) { return true; }
  void setTxPower(int8_t) {}
};

inline NativeRadioDriver radio_driver;
