#pragma once

#include <Arduino.h>

#define MAX_FRAME_SIZE  176   // +4 for transport codes (region scoping)

class BaseSerialInterface {
protected:
  BaseSerialInterface() { }

public:
  virtual void enable() = 0;
  virtual void disable() = 0;
  virtual bool isEnabled() const = 0;

  virtual bool isConnected() const = 0;
  virtual void loop() {};

  virtual bool isWriteBusy() const = 0;
  virtual size_t writeFrame(const uint8_t src[], size_t len) = 0;
#if MESHCORE_LORA_OTA
  // Optional diagnostics: never wait for a reader; zero means skipped or incomplete.
  virtual size_t tryWriteFrame(const uint8_t[], size_t) { return 0; }
#endif
  virtual size_t checkRecvFrame(uint8_t dest[]) = 0;
};
