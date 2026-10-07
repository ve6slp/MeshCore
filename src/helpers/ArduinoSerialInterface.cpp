#include "ArduinoSerialInterface.h"

#if MESHCORE_LORA_OTA && defined(ESP32_PLATFORM) && ARDUINO_USB_CDC_ON_BOOT
#if !ARDUINO_USB_MODE && CONFIG_TINYUSB_ENABLED
#include "esp32-hal-tinyusb.h"
#include "USB.h"
#endif

namespace {
portMUX_TYPE usb_session_mux = portMUX_INITIALIZER_UNLOCKED;
uint32_t usb_session = 0;

uint32_t diagnosticUsbSession() {
  portENTER_CRITICAL(&usb_session_mux);
  const uint32_t session = usb_session;
  portEXIT_CRITICAL(&usb_session_mux);
  return session;
}

void advanceDiagnosticUsbSession() {
  // CDC callbacks run on the SDK event task, not the USB ISR.
  portENTER_CRITICAL(&usb_session_mux);
  ++usb_session;
  portEXIT_CRITICAL(&usb_session_mux);
}

void onDiagnosticUsbEvent(void*, esp_event_base_t, int32_t event_id, void* event_data) {
#if ARDUINO_USB_MODE
  const bool boundary = event_id == ARDUINO_HW_CDC_BUS_RESET_EVENT;
#else
  bool boundary = event_id == ARDUINO_USB_CDC_CONNECTED_EVENT ||
                  event_id == ARDUINO_USB_CDC_DISCONNECTED_EVENT;
  if (event_id == ARDUINO_USB_CDC_LINE_STATE_EVENT && event_data) {
    const auto* data = static_cast<const arduino_usb_cdc_event_data_t*>(event_data);
    if (!data->line_state.dtr) boundary = true;
  }
#endif
  // The event worker publishes only an epoch; frame storage stays on the main loop.
  if (boundary) advanceDiagnosticUsbSession();
}

#if !ARDUINO_USB_MODE
void onDiagnosticUsbStopped(void*, esp_event_base_t, int32_t event_id, void*) {
  if (event_id == ARDUINO_USB_STOPPED_EVENT) advanceDiagnosticUsbSession();
}
#endif

void observeDiagnosticUsbSessions() {
  static const bool registered = []() {
    Serial.onEvent(onDiagnosticUsbEvent);
#if !ARDUINO_USB_MODE
    USB.onEvent(ARDUINO_USB_STOPPED_EVENT, onDiagnosticUsbStopped);
#endif
    return true;
  }();
  (void)registered;
}
}
#endif

#define RECV_STATE_IDLE        0
#define RECV_STATE_HDR_FOUND   1
#define RECV_STATE_LEN1_FOUND  2
#define RECV_STATE_LEN2_FOUND  3

void ArduinoSerialInterface::begin(Stream& serial) {
#if MESHCORE_LORA_OTA && defined(ESP32_PLATFORM) && ARDUINO_USB_CDC_ON_BOOT
  const bool same_usb = _serial == &serial && &serial == &Serial;
#endif
  _serial = &serial;
#if MESHCORE_LORA_OTA
#if defined(ESP32_PLATFORM) && ARDUINO_USB_CDC_ON_BOOT
  if (!same_usb) tx_len = tx_offset = 0;
  if (isUsbSerial()) observeDiagnosticUsbSessions();
  if (same_usb) refreshDiagnosticSession();
  else tx_session = diagnosticUsbSession();
#else
  tx_len = tx_offset = 0;
#endif
#endif
#ifdef RAK_4631
  pinMode(WB_IO2, OUTPUT);
#endif
}

void ArduinoSerialInterface::enable() { 
  _isEnabled = true;
  _state = RECV_STATE_IDLE;
}
void ArduinoSerialInterface::disable() {
  _isEnabled = false;
}

bool ArduinoSerialInterface::isConnected() const { 
  return true;   // no way of knowing, so assume yes
}

bool ArduinoSerialInterface::isWriteBusy() const {
  return false;
}

#if MESHCORE_LORA_OTA
bool ArduinoSerialInterface::isUsbSerial() const {
#if defined(NRF52_PLATFORM) && defined(USE_TINYUSB)
  return _serial == &Serial;
#elif defined(ESP32_PLATFORM) && ARDUINO_USB_CDC_ON_BOOT
  return _serial == &Serial;
#else
  return false;
#endif
}

bool ArduinoSerialInterface::diagnosticConnected() const {
  if (!_serial) return false;
#if defined(NRF52_PLATFORM) && defined(USE_TINYUSB)
  if (isUsbSerial()) return Serial.dtr() != 0;
#elif defined(ESP32_PLATFORM) && ARDUINO_USB_CDC_ON_BOOT
  if (isUsbSerial()) {
#if ARDUINO_USB_MODE
    return static_cast<bool>(Serial);
#else
    // SDK Serial is CDC interface 0; this public API requires DTR, not RTS.
    return tud_cdc_n_connected(0);
#endif
  }
#endif
  return true;
}

bool ArduinoSerialInterface::refreshDiagnosticSession() {
  bool current = diagnosticConnected();
#if defined(ESP32_PLATFORM) && ARDUINO_USB_CDC_ON_BOOT
  if (isUsbSerial()) {
    const uint32_t session = diagnosticUsbSession();
    if (tx_session != session) current = false;
    tx_session = session;
  }
#endif
  if (!current) tx_len = tx_offset = 0;
  return current;
}

bool ArduinoSerialInterface::flushDiagnosticFrame() {
  if (!refreshDiagnosticSession()) return false;
  if (tx_offset == tx_len) return true;
  const size_t remaining = tx_len - tx_offset;
  const int capacity = _serial->availableForWrite();
  if (capacity <= 0 || (isUsbSerial() && capacity < static_cast<int>(remaining))) return false;
  if (!refreshDiagnosticSession()) return false;
  const size_t chunk = remaining < static_cast<size_t>(capacity) ? remaining : static_cast<size_t>(capacity);
  const size_t written = _serial->write(tx_buf + tx_offset, chunk);
  tx_offset += written;
  if (!refreshDiagnosticSession()) return false;
  const bool complete = tx_offset == tx_len;
  if (complete || (isUsbSerial() && !tx_offset) || !diagnosticConnected()) tx_len = tx_offset = 0;
  return complete;
}

void ArduinoSerialInterface::loop() {
  if (_isEnabled) flushDiagnosticFrame();
}

size_t ArduinoSerialInterface::tryWriteFrame(const uint8_t src[], size_t len) {
  if (!_isEnabled || !src || !len || len > MAX_FRAME_SIZE) return 0;
  loop();
  if (tx_len || !diagnosticConnected()) return 0;
  // USB needs whole-frame FIFO room; UART retains its frame across bounded chunks.
  // All framed writers run on the main loop, with accurate availableForWrite capacity.
  if (isUsbSerial() && _serial->availableForWrite() < static_cast<int>(len + 3)) return 0;
  if (!refreshDiagnosticSession()) return 0;
  tx_buf[0] = '>';
  tx_buf[1] = len & 0xFF;
  tx_buf[2] = len >> 8;
  memcpy(tx_buf + 3, src, len);
  tx_len = len + 3;
  tx_offset = 0;
  return flushDiagnosticFrame() ? len : 0;
}
#endif

size_t ArduinoSerialInterface::writeFrame(const uint8_t src[], size_t len) {
  if (len > MAX_FRAME_SIZE) {
    // frame is too big!
    return 0;
  }

#if MESHCORE_LORA_OTA
  // A short diagnostic write must finish before a reliable response shares its stream.
  while (tx_offset < tx_len) {
    if (!refreshDiagnosticSession()) break;
    const size_t written = _serial->write(tx_buf + tx_offset, tx_len - tx_offset);
    if (!written) {
      if (!diagnosticConnected()) tx_len = tx_offset = 0;
      return 0;
    }
    tx_offset += written;
    if (!refreshDiagnosticSession()) break;
  }
  tx_len = tx_offset = 0;
#endif

  uint8_t hdr[3];
  hdr[0] = '>';
  hdr[1] = (len & 0xFF);  // LSB
  hdr[2] = (len >> 8);    // MSB

  _serial->write(hdr, 3);
  return _serial->write(src, len);
}

size_t ArduinoSerialInterface::checkRecvFrame(uint8_t dest[]) {
  while (_serial->available()) {
    int c = _serial->read();
    if (c < 0) break;

    switch (_state) {
      case RECV_STATE_IDLE:
        if (c == '<') {
          _state = RECV_STATE_HDR_FOUND;
        }
        break;
      case RECV_STATE_HDR_FOUND:
        _frame_len = (uint8_t)c;   // LSB
        _state = RECV_STATE_LEN1_FOUND;
        break;
      case RECV_STATE_LEN1_FOUND:
        _frame_len |= ((uint16_t)c) << 8;   // MSB
        rx_len = 0;
        _state = _frame_len > 0 ? RECV_STATE_LEN2_FOUND : RECV_STATE_IDLE;
        break;
      default:
        if (rx_len < MAX_FRAME_SIZE) {
          rx_buf[rx_len] = (uint8_t)c;   // rest of frame will be discarded if > MAX
        }
        rx_len++;
        if (rx_len >= _frame_len) {  // received a complete frame?
          if (_frame_len > MAX_FRAME_SIZE) _frame_len = MAX_FRAME_SIZE;    // truncate
          memcpy(dest, rx_buf, _frame_len);
          _state = RECV_STATE_IDLE;  // reset state, for next frame
          return _frame_len;
        }
    }
  }
  return 0;
}
