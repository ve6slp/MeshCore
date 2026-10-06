#pragma once

#include <Arduino.h>
#include <algorithm>
#include <cstdint>
#include <functional>

using std::max;
using std::min;
class SPIClass {};
inline long random(long lower, long) { return lower; }
struct MockRadioSerial {
  template <typename T> void print(T) {}
  template <typename T> void println(T) {}
};
inline MockRadioSerial Serial;

#define RADIOLIB_ERR_NONE 0
#define RADIOLIB_ERR_SPI_CMD_FAILED -707
#define RADIOLIB_ERR_SPI_CMD_INVALID -706
#define RADIOLIB_CHANNEL_FREE 0
#define RADIOLIB_SX126X_SYNC_WORD_PRIVATE 0x12
#define RADIOLIB_SX126X_RX_TIMEOUT_INF 0xFFFFFF
#define RADIOLIB_IRQ_RX_DEFAULT_FLAGS 2
#define RADIOLIB_IRQ_RX_DEFAULT_MASK 2
#define RADIOLIB_IRQ_PREAMBLE_DETECTED 2
#define RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED 4
#define RADIOLIB_SX126X_IRQ_HEADER_VALID 16
#define RADIOLIB_SX126X_IRQ_HEADER_ERR 32
#define RADIOLIB_SX126X_IRQ_SYNC_WORD_VALID 8
#define RADIOLIB_SX126X_STANDBY_RC 0
#define RADIOLIB_SX126X_CALIBRATE_ALL 0x7F
#define RADIOLIB_SX126X_CMD_CALIBRATE 0x89
#define RADIOLIB_SX126X_CMD_GET_DEVICE_ERRORS 0x17
#define RADIOLIB_SX126X_CMD_GET_IRQ_STATUS 0x12
#define RADIOLIB_SX126X_CMD_GET_STATUS 0xC0
#define RADIOLIB_SX126X_REG_RX_GAIN 0x8AC
#define RADIOLIB_SX126X_RX_GAIN_BOOSTED 0x96

struct MockRadioHal {
  void delay(uint32_t ms) { ::delay(ms); }
  void yield() {}
  int digitalRead(int) { return 0; }
};

class Module {
 public:
  static constexpr uint8_t BITS_0 = 0;
  struct { uint8_t widths[4] = {8, 8, 8, 8}; } spiConfig;
  MockRadioHal storage;
  MockRadioHal* hal = &storage;
  void (*interrupt)() = nullptr;
  std::function<void(unsigned)> onRead;
  std::function<void(unsigned)> afterRead;
  uint8_t mode = 0x20;
  uint16_t errors = 0;
  uint16_t irq = 0;
  int16_t readStatus[3]{};
  int16_t receiveStatus = 0, finishStatus = 0, transmitStatus = 0;
  unsigned reads = 0, starts = 0, finishes = 0, receives = 0;

  void complete() {
    mode = 0x20;
    irq = 1;
    if (interrupt != nullptr) interrupt();
  }
  int getGpio() const { return 0; }
  int16_t SPIreadStream(uint16_t command, uint8_t* data, size_t size) {
    ++reads;
    if (onRead) onRead(reads);
    const unsigned slot = command == RADIOLIB_SX126X_CMD_GET_DEVICE_ERRORS ? 0 :
                          command == RADIOLIB_SX126X_CMD_GET_IRQ_STATUS ? 1 : 2;
    if (readStatus[slot] != 0) return readStatus[slot];
    if (size == 1) {
      data[0] = mode | 0x0C;
    } else {
      const uint16_t value = slot == 0 ? errors : irq;
      data[0] = value >> 8;
      data[1] = value;
    }
    if (afterRead) afterRead(reads);
    return 0;
  }
  int16_t SPIwriteStream(uint16_t, uint8_t*, size_t, bool, bool) { return 0; }
};

class PhysicalLayer {
 public:
  Module* mod;
  explicit PhysicalLayer(Module* module) : mod(module) {}
  virtual ~PhysicalLayer() = default;
  void setPacketReceivedAction(void (*callback)()) { mod->interrupt = callback; }
  int16_t setPreambleLength(uint16_t) { return 0; }
  int16_t setOutputPower(int8_t) { return 0; }
  int16_t sleep(bool = true) { return 0; }
  int16_t standby(uint8_t = 0, bool = false) { mod->mode = 0x20; return 0; }
  int32_t random(int32_t) { return 1; }
  uint8_t randomByte() { return 0; }
  virtual int16_t startReceive() {
    ++mod->receives;
    if (mod->receiveStatus == 0) { mod->mode = 0x50; mod->irq = 0; }
    return mod->receiveStatus;
  }
  int getPacketLength() { return 0; }
  int16_t readData(uint8_t*, int) { return 0; }
  uint32_t getTimeOnAir(int) { return 100000; }
  int16_t startTransmit(uint8_t*, int) {
    ++mod->starts;
    if (mod->transmitStatus == 0) { mod->mode = 0x60; mod->irq = 0; }
    return mod->transmitStatus;
  }
  int16_t finishTransmit() {
    ++mod->finishes;
    if (mod->finishStatus == 0) { mod->irq = 0; mod->mode = 0x20; }
    return mod->finishStatus;
  }
  int16_t scanChannel() { return RADIOLIB_CHANNEL_FREE; }
  float getRSSI(bool = true) { return -110; }
  float getSNR() { return 10; }
};

class SX126x : public PhysicalLayer {
 public:
  using PhysicalLayer::PhysicalLayer;
  float freqMHz = 907.525;
  uint8_t spreadingFactor = 7;
  int16_t startReceive(uint32_t, uint32_t, uint32_t, uint8_t) { return PhysicalLayer::startReceive(); }
  template <typename... T> int16_t begin(T...) { return 0; }
  template <typename... T> int16_t setCRC(T...) { return 0; }
  template <typename... T> int16_t setFrequency(T...) { return 0; }
  template <typename... T> int16_t setSpreadingFactor(T...) { return 0; }
  template <typename... T> int16_t setBandwidth(T...) { return 0; }
  template <typename... T> int16_t setCodingRate(T...) { return 0; }
  template <typename... T> int16_t setRxBoostedGainMode(T...) { return 0; }
  template <typename... T> int16_t calibrateImage(T...) { return 0; }
  template <typename... T> int16_t readRegister(T...) { return 0; }
  template <typename... T> int16_t writeRegister(T...) { return 0; }
  int16_t clearIrqFlags(uint32_t mask) { mod->irq &= ~mask; return 0; }
  uint32_t getIrqFlags() { return mod->irq; }
  uint16_t getDeviceErrors() { return mod->errors; }
  uint8_t getStatus() { return mod->mode | 0x0C; }
};

using SX1262 = SX126x;
