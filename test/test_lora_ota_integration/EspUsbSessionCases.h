#pragma once

#include <gtest/gtest.h>
#include <Arduino.h>
#include <algorithm>
#include <cstring>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace {
using esp_event_base_t = const char*;
using esp_event_handler_t = void (*)(void*, esp_event_base_t, int32_t, void*);
enum {
  ARDUINO_HW_CDC_BUS_RESET_EVENT = 1,
  ARDUINO_HW_CDC_RX_EVENT = 2,
  ARDUINO_HW_CDC_TX_EVENT = 3,
  ARDUINO_USB_CDC_CONNECTED_EVENT = 0,
  ARDUINO_USB_CDC_DISCONNECTED_EVENT = 1,
  ARDUINO_USB_CDC_LINE_STATE_EVENT = 2,
  ARDUINO_USB_CDC_RX_EVENT = 4,
  ARDUINO_USB_CDC_TX_EVENT = 5,
  ARDUINO_USB_STOPPED_EVENT = 1
};
union arduino_usb_cdc_event_data_t {
  struct { bool dtr, rts; } line_state;
};
struct portMUX_TYPE { std::mutex lock; };

class EspDiagnosticStream : public Stream {
public:
  bool connected = true, dtr = true, rts = true;
  int room = 256;
  size_t max_chunk = SIZE_MAX;
  unsigned writes = 0, would_block = 0, disconnected_writes = 0, registrations = 0;
  esp_event_handler_t callback = nullptr;
  std::vector<uint8_t> bytes;
  std::vector<size_t> requested_sizes;
  std::function<void()> on_capacity, on_write;

  void reset() {
    connected = true;
    dtr = rts = true;
    room = 256;
    max_chunk = SIZE_MAX;
    writes = would_block = disconnected_writes = 0;
    bytes.clear();
    requested_sizes.clear();
    on_capacity = on_write = {};
  }
  void onEvent(esp_event_handler_t handler) { ++registrations; callback = handler; }
  explicit operator bool() const {
#if ESP_USB_TEST_MODE
    return connected;
#else
    return connected && dtr && rts;
#endif
  }
  int availableForWrite() override {
    auto hook = std::move(on_capacity);
    if (hook) hook();
    return room;
  }
  size_t write(const uint8_t* src, size_t len) override {
    ++writes;
    requested_sizes.push_back(len);
    if (!connected) ++disconnected_writes;
    if (len > static_cast<size_t>(room)) { ++would_block; return 0; }
    const size_t written = std::min(len, max_chunk);
    bytes.insert(bytes.end(), src, src + written);
    room -= written;
    auto hook = std::move(on_write);
    if (hook) hook();
    return written;
  }
  void event(int32_t id) { if (callback) callback(this, "cdc", id, nullptr); }
  void lineState(bool next_dtr, bool next_rts) {
    dtr = next_dtr; rts = next_rts;
    arduino_usb_cdc_event_data_t data{};
    data.line_state.dtr = dtr;
    data.line_state.rts = rts;
    if (callback) callback(this, "cdc", ARDUINO_USB_CDC_LINE_STATE_EVENT, &data);
  }
  void boundary(bool reconnect) {
    connected = false;
    bytes.clear();
#if ESP_USB_TEST_MODE
    event(ARDUINO_HW_CDC_BUS_RESET_EVENT);
#else
    event(ARDUINO_USB_CDC_DISCONNECTED_EVENT);
#endif
    if (reconnect) {
      connected = true;
      room = 256;
      max_chunk = SIZE_MAX;
#if !ESP_USB_TEST_MODE
      event(ARDUINO_USB_CDC_CONNECTED_EVENT);
#endif
    }
  }
};

EspDiagnosticStream esp_test_serial;
bool tud_cdc_n_connected(uint8_t itf) {
  return itf == 0 && esp_test_serial.connected && esp_test_serial.dtr;
}
class EspDiagnosticUsbBus {
public:
  esp_event_handler_t callback = nullptr;
  unsigned registrations = 0;
  void onEvent(int32_t id, esp_event_handler_t handler) {
    EXPECT_EQ(ARDUINO_USB_STOPPED_EVENT, id);
    ++registrations; callback = handler;
  }
  void stop() { if (callback) callback(this, "usb", ARDUINO_USB_STOPPED_EVENT, nullptr); }
} esp_test_usb_bus;
}

#define portMUX_INITIALIZER_UNLOCKED {}
#define portENTER_CRITICAL(mux) (mux)->lock.lock()
#define portEXIT_CRITICAL(mux) (mux)->lock.unlock()
#define ESP32_PLATFORM
#define ARDUINO_USB_CDC_ON_BOOT 1
#define ARDUINO_USB_MODE ESP_USB_TEST_MODE
#define Serial esp_test_serial
#define USB esp_test_usb_bus
#if ESP_USB_TEST_MODE
#define ArduinoSerialInterface EspHwArduinoSerialInterface
#define ESP_USB_TEST_SUITE LoraOtaEspHwUsbSession
#else
#define ArduinoSerialInterface EspTinyArduinoSerialInterface
#define ESP_USB_TEST_SUITE LoraOtaEspTinyUsbSession
#endif
#include <helpers/ArduinoSerialInterface.cpp>

namespace {
using SessionAdapter = ArduinoSerialInterface;
std::vector<uint8_t> sessionWireFrame(const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> frame{'>', static_cast<uint8_t>(payload.size()),
                           static_cast<uint8_t>(payload.size() >> 8)};
  frame.insert(frame.end(), payload.begin(), payload.end());
  return frame;
}
}

#undef ArduinoSerialInterface
#undef Serial
#undef USB
#undef portMUX_INITIALIZER_UNLOCKED
#undef portENTER_CRITICAL
#undef portEXIT_CRITICAL
#undef ARDUINO_USB_MODE
#undef ARDUINO_USB_CDC_ON_BOOT
#undef ESP32_PLATFORM

TEST(ESP_USB_TEST_SUITE, ConnectedBeforeBeginLogsImmediatelyAndRegistersOnlyOnceAcrossInstancesAndBegins) {
  esp_test_serial.reset();
  SessionAdapter first;
  first.begin(esp_test_serial); first.enable();
  ASSERT_EQ(1u, esp_test_serial.registrations);
  const std::vector<uint8_t> event(14, 0x91);
  EXPECT_EQ(event.size(), first.tryWriteFrame(event.data(), event.size()));
  EXPECT_EQ(sessionWireFrame(event), esp_test_serial.bytes);
  for (int i = 0; i < 5; ++i) {
    SessionAdapter next;
    next.begin(esp_test_serial); next.enable();
    next.begin(esp_test_serial);
    esp_test_serial.bytes.clear(); esp_test_serial.room = 256;
    EXPECT_EQ(event.size(), next.tryWriteFrame(event.data(), event.size()));
    EXPECT_EQ(sessionWireFrame(event), esp_test_serial.bytes);
  }
  EXPECT_EQ(1u, esp_test_serial.registrations);
  EXPECT_EQ(0u, esp_test_serial.would_block);
}

TEST(ESP_USB_TEST_SUITE, DisconnectedWithFreeFifoNeverWritesOrBuffersAnOptionalSuffix) {
  esp_test_serial.reset();
  esp_test_serial.connected = false;
  SessionAdapter usb;
  usb.begin(esp_test_serial); usb.enable();
  const std::vector<uint8_t> event(14, 0x91);
  for (int i = 0; i < 20; ++i) {
    EXPECT_EQ(0u, usb.tryWriteFrame(event.data(), event.size()));
    usb.loop();
  }
  EXPECT_EQ(0u, esp_test_serial.writes);
  esp_test_serial.boundary(true);
  EXPECT_EQ(event.size(), usb.tryWriteFrame(event.data(), event.size()));
  EXPECT_EQ(sessionWireFrame(event), esp_test_serial.bytes);
  EXPECT_EQ(0u, esp_test_serial.disconnected_writes);
}

TEST(ESP_USB_TEST_SUITE, RootEightByteFifoCounterexampleDoesNotCreateACrossSessionPrefix) {
  esp_test_serial.reset();
  esp_test_serial.room = 8;
  SessionAdapter usb;
  usb.begin(esp_test_serial); usb.enable();
  const std::vector<uint8_t> event(14, 0x91), response{5, 1, 2};
  EXPECT_EQ(0u, usb.tryWriteFrame(event.data(), event.size()));
  EXPECT_EQ(0u, esp_test_serial.writes);
  esp_test_serial.boundary(false);
  usb.loop();
  EXPECT_EQ(0u, esp_test_serial.writes);
  esp_test_serial.boundary(true);
  EXPECT_EQ(response.size(), usb.writeFrame(response.data(), response.size()));
  EXPECT_EQ(sessionWireFrame(response), esp_test_serial.bytes);
  EXPECT_EQ(0u, esp_test_serial.disconnected_writes);
}

TEST(ESP_USB_TEST_SUITE, PartialTailResetAndReconnectBetweenLoopsCannotPrependOldSuffixToResponse) {
  const std::vector<uint8_t> event(14, 0x91), response{5, 1, 2};
  for (const bool loop_first : {false, true}) {
    esp_test_serial.reset();
    esp_test_serial.max_chunk = 8;
    SessionAdapter usb;
    usb.begin(esp_test_serial); usb.enable();
    EXPECT_EQ(0u, usb.tryWriteFrame(event.data(), event.size()));
    ASSERT_EQ(8u, esp_test_serial.bytes.size());
    const auto writes = esp_test_serial.writes;
    esp_test_serial.boundary(true);
    if (loop_first) {
      usb.loop();
      EXPECT_EQ(writes, esp_test_serial.writes);
    }
    EXPECT_EQ(response.size(), usb.writeFrame(response.data(), response.size()));
    EXPECT_EQ(sessionWireFrame(response), esp_test_serial.bytes);
    EXPECT_EQ(0u, esp_test_serial.disconnected_writes);
    EXPECT_EQ(0u, esp_test_serial.would_block);
  }
}

TEST(ESP_USB_TEST_SUITE, ResetDuringCapacityOrWriteDoesNotClaimCompleteOrLeakTailIntoNextResponse) {
  const std::vector<uint8_t> event(14, 0x91), response{5, 1, 2};
  for (const bool during_write : {false, true}) {
    esp_test_serial.reset();
    SessionAdapter usb;
    usb.begin(esp_test_serial); usb.enable();
    if (during_write) {
      esp_test_serial.max_chunk = 8;
      esp_test_serial.on_write = [] { esp_test_serial.boundary(true); };
    } else {
      esp_test_serial.on_capacity = [] { esp_test_serial.boundary(true); };
    }
    EXPECT_EQ(0u, usb.tryWriteFrame(event.data(), event.size()));
    EXPECT_TRUE(esp_test_serial.bytes.empty());
    EXPECT_EQ(during_write ? 1u : 0u, esp_test_serial.writes);
    EXPECT_EQ(response.size(), usb.writeFrame(response.data(), response.size()));
    EXPECT_EQ(sessionWireFrame(response), esp_test_serial.bytes);
    EXPECT_EQ(0u, esp_test_serial.would_block);
  }
}

TEST(ESP_USB_TEST_SUITE, SameSessionShortTailCompletesBeforeResponseAndRxTxNotificationsDoNotDiscardIt) {
  esp_test_serial.reset();
  esp_test_serial.max_chunk = 8;
  SessionAdapter usb;
  usb.begin(esp_test_serial); usb.enable();
  const std::vector<uint8_t> event(14, 0x91), response{5, 1, 2};
  EXPECT_EQ(0u, usb.tryWriteFrame(event.data(), event.size()));
#if ESP_USB_TEST_MODE
  esp_test_serial.event(ARDUINO_HW_CDC_RX_EVENT);
  esp_test_serial.event(ARDUINO_HW_CDC_TX_EVENT);
#else
  esp_test_serial.event(ARDUINO_USB_CDC_RX_EVENT);
  esp_test_serial.event(ARDUINO_USB_CDC_TX_EVENT);
#endif
  esp_test_serial.max_chunk = SIZE_MAX;
  EXPECT_EQ(response.size(), usb.writeFrame(response.data(), response.size()));
  auto expected = sessionWireFrame(event);
  const auto reply = sessionWireFrame(response);
  expected.insert(expected.end(), reply.begin(), reply.end());
  EXPECT_EQ(expected, esp_test_serial.bytes);
  EXPECT_EQ(0u, esp_test_serial.would_block);
}

TEST(ESP_USB_TEST_SUITE, RepeatedBeginInActiveSessionPreservesPartialFrameWithoutAnotherRegistration) {
  esp_test_serial.reset();
  esp_test_serial.max_chunk = 8;
  SessionAdapter usb;
  usb.begin(esp_test_serial); usb.enable();
  const std::vector<uint8_t> event(14, 0x91), response{5, 1, 2};
  EXPECT_EQ(0u, usb.tryWriteFrame(event.data(), event.size()));
  usb.begin(esp_test_serial);
  esp_test_serial.max_chunk = SIZE_MAX;
  EXPECT_EQ(response.size(), usb.writeFrame(response.data(), response.size()));
  auto expected = sessionWireFrame(event);
  const auto reply = sessionWireFrame(response);
  expected.insert(expected.end(), reply.begin(), reply.end());
  EXPECT_EQ(expected, esp_test_serial.bytes);
  EXPECT_EQ(1u, esp_test_serial.registrations);
}

TEST(ESP_USB_TEST_SUITE, EventWorkerOnlyPublishesEpochAndDisabledAdapterDiscardsOnResume) {
  esp_test_serial.reset();
  esp_test_serial.max_chunk = 8;
  SessionAdapter usb;
  usb.begin(esp_test_serial); usb.enable();
  const std::vector<uint8_t> event(14, 0x91), response{5, 1, 2};
  EXPECT_EQ(0u, usb.tryWriteFrame(event.data(), event.size()));
  const auto old_prefix = esp_test_serial.bytes;
  usb.disable();
  std::thread worker([] {
#if ESP_USB_TEST_MODE
    esp_test_serial.event(ARDUINO_HW_CDC_BUS_RESET_EVENT);
#else
    esp_test_serial.event(ARDUINO_USB_CDC_DISCONNECTED_EVENT);
    esp_test_serial.event(ARDUINO_USB_CDC_CONNECTED_EVENT);
#endif
  });
  worker.join();
  EXPECT_EQ(old_prefix, esp_test_serial.bytes);
  usb.loop();
  EXPECT_EQ(1u, esp_test_serial.writes);
  esp_test_serial.bytes.clear(); esp_test_serial.room = 256; esp_test_serial.max_chunk = SIZE_MAX;
  usb.enable();
  EXPECT_EQ(response.size(), usb.writeFrame(response.data(), response.size()));
  EXPECT_EQ(sessionWireFrame(response), esp_test_serial.bytes);
  EXPECT_EQ(1u, esp_test_serial.registrations);
}

TEST(ESP_USB_TEST_SUITE, BeginAfterBoundaryDropsOldTailAndGlobalUsbEpochDoesNotAffectUartChunking) {
  esp_test_serial.reset();
  esp_test_serial.max_chunk = 8;
  SessionAdapter usb;
  usb.begin(esp_test_serial); usb.enable();
  const std::vector<uint8_t> event(14, 0x91), response{5, 1, 2};
  EXPECT_EQ(0u, usb.tryWriteFrame(event.data(), event.size()));
  esp_test_serial.boundary(true);
  usb.begin(esp_test_serial);
  EXPECT_EQ(response.size(), usb.writeFrame(response.data(), response.size()));
  EXPECT_EQ(sessionWireFrame(response), esp_test_serial.bytes);

  EspDiagnosticStream uart;
  uart.room = 64;
  usb.begin(uart);
  const std::vector<uint8_t> raw(MAX_FRAME_SIZE, 0x88);
  EXPECT_EQ(0u, usb.tryWriteFrame(raw.data(), raw.size()));
  EXPECT_EQ(64u, uart.bytes.size());
  esp_test_serial.boundary(true);
  for (int i = 0; i < 2; ++i) { uart.room = 64; usb.loop(); }
  EXPECT_EQ(sessionWireFrame(raw), uart.bytes);
  EXPECT_EQ((std::vector<size_t>{64, 64, 51}), uart.requested_sizes);
  EXPECT_EQ(0u, uart.would_block);
  EXPECT_EQ(1u, esp_test_serial.registrations);
}

#if !ESP_USB_TEST_MODE
TEST(ESP_USB_TEST_SUITE, InitialDtrOnlySessionUsesPublicCdcReadinessDespiteFalseArduinoBool) {
  esp_test_serial.reset();
  esp_test_serial.rts = false;
  EXPECT_FALSE(static_cast<bool>(esp_test_serial));
  EXPECT_TRUE(tud_cdc_n_connected(0));
  SessionAdapter usb;
  usb.begin(esp_test_serial); usb.enable();
  const std::vector<uint8_t> event(14, 0x91), raw(MAX_FRAME_SIZE, 0x88);
  for (const auto& payload : {event, raw}) {
    esp_test_serial.bytes.clear(); esp_test_serial.room = 256;
    EXPECT_EQ(payload.size(), usb.tryWriteFrame(payload.data(), payload.size()));
    EXPECT_EQ(sessionWireFrame(payload), esp_test_serial.bytes);
  }
  EXPECT_EQ(1u, esp_test_serial.registrations);
  EXPECT_EQ(1u, esp_test_usb_bus.registrations);
  EXPECT_EQ(0u, esp_test_serial.would_block);
}

TEST(ESP_USB_TEST_SUITE, DtrOnlyLineStateCloseAndReopenBetweenPollsRetiresPartialTail) {
  esp_test_serial.reset();
  esp_test_serial.rts = false; esp_test_serial.max_chunk = 8;
  SessionAdapter usb;
  usb.begin(esp_test_serial); usb.enable();
  const std::vector<uint8_t> event(14, 0x91), response{5, 1, 2};
  EXPECT_EQ(0u, usb.tryWriteFrame(event.data(), event.size()));
  ASSERT_EQ(8u, esp_test_serial.bytes.size());
  esp_test_serial.lineState(false, false);
  esp_test_serial.bytes.clear();
  esp_test_serial.lineState(true, false);
  EXPECT_FALSE(static_cast<bool>(esp_test_serial));
  esp_test_serial.max_chunk = SIZE_MAX; esp_test_serial.room = 256;
  EXPECT_EQ(response.size(), usb.writeFrame(response.data(), response.size()));
  EXPECT_EQ(sessionWireFrame(response), esp_test_serial.bytes);
  EXPECT_EQ(event.size(), usb.tryWriteFrame(event.data(), event.size()));
  EXPECT_EQ(0u, esp_test_serial.would_block);
}

TEST(ESP_USB_TEST_SUITE, RtsChangeWithDtrStillActiveDoesNotDiscardPartialFrame) {
  esp_test_serial.reset();
  esp_test_serial.rts = false; esp_test_serial.max_chunk = 8;
  SessionAdapter usb;
  usb.begin(esp_test_serial); usb.enable();
  const std::vector<uint8_t> event(14, 0x91), response{5, 1, 2};
  EXPECT_EQ(0u, usb.tryWriteFrame(event.data(), event.size()));
  esp_test_serial.lineState(true, true);
  esp_test_serial.lineState(true, false);
  esp_test_serial.max_chunk = SIZE_MAX;
  EXPECT_EQ(response.size(), usb.writeFrame(response.data(), response.size()));
  auto expected = sessionWireFrame(event);
  const auto reply = sessionWireFrame(response);
  expected.insert(expected.end(), reply.begin(), reply.end());
  EXPECT_EQ(expected, esp_test_serial.bytes);
}

TEST(ESP_USB_TEST_SUITE, PublicUsbStoppedBoundaryCoversResetWithoutStrictCdcDisconnectedEvent) {
  esp_test_serial.reset();
  esp_test_serial.rts = false; esp_test_serial.max_chunk = 8;
  SessionAdapter usb;
  usb.begin(esp_test_serial); usb.enable();
  const std::vector<uint8_t> event(14, 0x91), response{5, 1, 2};
  EXPECT_EQ(0u, usb.tryWriteFrame(event.data(), event.size()));
  EXPECT_FALSE(static_cast<bool>(esp_test_serial));
  esp_test_serial.connected = false;
  esp_test_usb_bus.stop();
  esp_test_serial.bytes.clear();
  usb.loop();
  EXPECT_EQ(1u, esp_test_serial.writes);
  esp_test_serial.connected = true; esp_test_serial.max_chunk = SIZE_MAX;
  esp_test_serial.room = 256;
  EXPECT_EQ(response.size(), usb.writeFrame(response.data(), response.size()));
  EXPECT_EQ(sessionWireFrame(response), esp_test_serial.bytes);
  usb.begin(esp_test_serial);
  EXPECT_EQ(event.size(), usb.tryWriteFrame(event.data(), event.size()));
  EXPECT_EQ(1u, esp_test_usb_bus.registrations);
}
#endif

#undef ESP_USB_TEST_SUITE
