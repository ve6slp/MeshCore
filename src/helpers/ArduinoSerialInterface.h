#pragma once

#include "BaseSerialInterface.h"
#include <Arduino.h>

class ArduinoSerialInterface : public BaseSerialInterface {
  bool _isEnabled;
  uint8_t _state;
  uint16_t _frame_len;
  uint16_t rx_len;
  Stream* _serial;
  uint8_t rx_buf[MAX_FRAME_SIZE];
#if MESHCORE_LORA_OTA
  uint8_t tx_buf[MAX_FRAME_SIZE + 3];
  uint16_t tx_len = 0, tx_offset = 0;
#if defined(ESP32_PLATFORM) && ARDUINO_USB_CDC_ON_BOOT
  uint32_t tx_session = 0;
#endif

  bool isUsbSerial() const;
  bool diagnosticConnected() const;
  bool refreshDiagnosticSession();
  bool flushDiagnosticFrame();
#endif

public:
  ArduinoSerialInterface() { _isEnabled = false; _state = 0; _serial = nullptr; }

  void begin(Stream& serial);

  // BaseSerialInterface methods
  void enable() override;
  void disable() override;
  bool isEnabled() const override { return _isEnabled; }

  bool isConnected() const override;

  bool isWriteBusy() const override;
#if MESHCORE_LORA_OTA
  void loop() override;
#endif
  size_t writeFrame(const uint8_t src[], size_t len) override;
#if MESHCORE_LORA_OTA
  size_t tryWriteFrame(const uint8_t src[], size_t len) override;
#endif
  size_t checkRecvFrame(uint8_t dest[]) override;
};
