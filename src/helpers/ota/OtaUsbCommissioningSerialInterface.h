#pragma once

// Source-bound USB port/framer+router adapter: the ONE owner/parser for
// the physical USB serial stream under MESHCORE_LORA_OTA. Implements the
// EXISTING BaseSerialInterface contract (registered as InterfaceType::USB
// in place of ArduinoSerialInterface) so no edit to
// ArduinoSerialInterface.cpp/MultiSerialInterface.h is required.
//
// Demultiplexes a single incoming byte stream sharing the SAME outer
// transport framing used by both paths -- one leading direction byte
// ('<' host->device / '>' device->host) + LE16 payload length + payload
// bytes, no trailing delimiter -- between:
//  - Legacy companion CLI frames: passed through unmodified via this
//    class's own checkRecvFrame()/writeFrame(), exactly like
//    ArduinoSerialInterface's existing wire behavior (so handleCmdFrame
//    keeps working unchanged).
//  - OTA commissioning control frames: identified once at least 2
//    payload bytes have arrived (payload[0] == kOtaControlCommand (66)
//    and payload[1] within the OtaControlSubcommand range 0x20..0x2A),
//    intercepted here and routed directly into a live
//    OtaUsbControlService. Replies are written straight back to the
//    owned Serial stream in flushPendingOtaReply(), NEVER through
//    MultiSerialInterface::writeFrame() (which broadcasts to every
//    registered interface) -- a maintenance reply must only ever reach
//    the exact physical source that opened the session.
//
// Why a new parser instead of wrapping ArduinoSerialInterface's output:
// that class (a) silently clamps an oversized declared length down to
// MAX_FRAME_SIZE and STILL dispatches the truncated prefix rather than
// rejecting the frame outright, and (b) drains available() bytes with no
// per-call work cap, and (c) isConnected() is hardcoded `true` ("no way
// of knowing"). A source-bound adapter built on top of that output could
// not reconstruct a truthful ingress/frame boundary or connection state.
// This class instead rejects (discards whole-frame, never truncates-and-
// dispatches) any frame whose declared length exceeds the shared buffer
// capacity, bounds the number of bytes it drains per checkRecvFrame()
// call, and requires a REAL connection probe (see isPhysicallyConnectedFn
// below) rather than assuming true.
//
// NOT natively host-testable: requires Arduino.h and a concrete Stream/
// Serial object. Its OTA-routing path delegates every byte, unchanged,
// to the already natively-tested OtaUsbControlFramer/OtaUsbControlService
// /OtaControlSessionRouter; this class itself contributes only the
// demux/framing glue and must be verified against the real Arduino
// toolchain by whoever owns the MCU build.

#include "helpers/BaseSerialInterface.h"
#include "helpers/ota/OtaUsbControlService.h"
#include "ota/protocol/OtaCommissioningAbi.h"

#include <cstring>

namespace meshcore {
namespace ota {
namespace helpers {

class OtaUsbCommissioningSerialInterface : public BaseSerialInterface {
public:
  // Large enough for either path: the legacy companion CLI's existing
  // MAX_FRAME_SIZE (176) and the OTA control channel's own
  // OtaUsbControlFramer::kMaxPayload (168) share one buffer.
  static constexpr size_t kBufCapacity =
      (MAX_FRAME_SIZE > OtaUsbControlFramer::kMaxPayload) ? MAX_FRAME_SIZE
                                                           : OtaUsbControlFramer::kMaxPayload;
  // Bounded per-call work cap: a saturated/wedged USB link can never
  // stall the rest of the firmware's loop() indefinitely.
  static constexpr size_t kMaxBytesPerPoll = 256;

  // `otaService` must outlive this adapter (owned by whatever longer-
  // lived service/MyMesh holds the real OtaControlSessionRouter).
  // `isPhysicallyConnectedFn` must be a REAL probe of USB connection
  // state (e.g. `[](){ return (bool)Serial; }` on the TinyUSB/Adafruit
  // nRF52 cores this is wired for, where the concrete Serial object's
  // operator bool() reflects whether the host actually has the CDC port
  // open) -- never a stub returning a literal true/false.
  OtaUsbCommissioningSerialInterface(OtaUsbControlService &otaService,
                                      bool (*isPhysicallyConnectedFn)())
      : ota_service_(otaService), is_physically_connected_fn_(isPhysicallyConnectedFn) {}

  void begin(Stream &serial) { _serial = &serial; }

  void enable() override {
    _enabled = true;
    resetParse();
  }
  void disable() override { _enabled = false; }
  bool isEnabled() const override { return _enabled; }

  bool isConnected() const override {
    return is_physically_connected_fn_ != nullptr && is_physically_connected_fn_();
  }

  void loop() override {
    const bool connected = isConnected();
    if (connected != last_connected_) {
      last_connected_ = connected;
      // A genuine connection-epoch change (new physical attach, or a
      // disconnect) -- never ordinary idle polling -- revokes any open
      // session/job and discards any in-flight/unsent frame so a newly
      // attached, distinct source must re-authenticate via a fresh OPEN.
      ota_service_.onConnectionEpochChanged();
      resetParse();
    }
    ota_service_.tick(millis());
    flushPendingOtaReply();
  }

  bool isWriteBusy() const override { return false; }

  // Legacy reply path, byte-for-byte identical to ArduinoSerialInterface's
  // existing wire behavior -- unaffected by the OTA interception above.
  size_t writeFrame(const uint8_t src[], size_t len) override {
    if (_serial == nullptr || len == 0 || len > MAX_FRAME_SIZE) return 0;
    uint8_t hdr[3];
    hdr[0] = '>';
    hdr[1] = static_cast<uint8_t>(len & 0xFF);
    hdr[2] = static_cast<uint8_t>(len >> 8);
    _serial->write(hdr, 3);
    return _serial->write(src, len);
  }

  size_t checkRecvFrame(uint8_t dest[]) override {
    if (_serial == nullptr) return 0;
    flushPendingOtaReply();

    size_t consumed = 0;
    while (consumed < kMaxBytesPerPoll && _serial->available()) {
      const int c = _serial->read();
      if (c < 0) break;
      ++consumed;
      const uint8_t b = static_cast<uint8_t>(c);

      switch (state_) {
        case State::WaitStart:
          if (b == '<') state_ = State::Len1;
          break;
        case State::Len1:
          declared_len_ = b;
          state_ = State::Len2;
          break;
        case State::Len2: {
          declared_len_ |= static_cast<uint16_t>(b) << 8;
          if (declared_len_ == 0 || declared_len_ > kBufCapacity) {
            // Malformed: reject outright (never dispatch a truncated
            // prefix); resync to look for the next '<'.
            resetParse();
            break;
          }
          fill_ = 0;
          route_ = Route::Undecided;
          state_ = State::Payload;
          break;
        }
        case State::Payload: {
          buf_[fill_++] = b;
          if (route_ == Route::Undecided && fill_ >= 2) {
            const uint8_t subByte = buf_[1];
            const bool isOta =
                buf_[0] == ::meshcore::ota::protocol::kOtaControlCommand &&
                subByte >= static_cast<uint8_t>(::meshcore::ota::protocol::OtaControlSubcommand::Open) &&
                subByte <= static_cast<uint8_t>(::meshcore::ota::protocol::OtaControlSubcommand::Close);
            route_ = isOta ? Route::Ota : Route::Legacy;
            if (route_ == Route::Ota) {
              // Replay the outer header + the payload bytes buffered so
              // far (exactly `fill_` of them) into the OTA service's own
              // byte-at-a-time framer -- the ONLY place these bytes are
              // fed to it.
              const uint32_t now = millis();
              ota_service_.onByte('<', now);
              ota_service_.onByte(static_cast<uint8_t>(declared_len_ & 0xFF), now);
              ota_service_.onByte(static_cast<uint8_t>(declared_len_ >> 8), now);
              for (size_t i = 0; i < fill_; ++i) ota_service_.onByte(buf_[i], now);
            }
          } else if (route_ == Route::Ota) {
            // Route already decided on a prior byte -- feed this one live.
            ota_service_.onByte(b, millis());
          }
          if (fill_ >= declared_len_) {
            // A 1-byte payload can never satisfy the 2-byte OTA command/
            // subcommand prefix check above; treat it as legacy so the
            // frame isn't silently dropped.
            if (route_ == Route::Undecided) route_ = Route::Legacy;
            const bool wasLegacy = (route_ == Route::Legacy);
            const size_t frameLen = declared_len_;
            if (wasLegacy) {
              std::memcpy(dest, buf_, frameLen);
              resetParse();
              flushPendingOtaReply();
              return frameLen;
            }
            resetParse();
            flushPendingOtaReply();
          }
          break;
        }
      }
    }
    flushPendingOtaReply();
    return 0;
  }

private:
  enum class State : uint8_t { WaitStart, Len1, Len2, Payload };
  enum class Route : uint8_t { Undecided, Legacy, Ota };

  void resetParse() {
    state_ = State::WaitStart;
    declared_len_ = 0;
    fill_ = 0;
    route_ = Route::Undecided;
  }

  void flushPendingOtaReply() {
    if (_serial == nullptr || !ota_service_.hasPendingReply()) return;
    _serial->write(ota_service_.pendingReplyData(), ota_service_.pendingReplyLen());
    ota_service_.consumeReply();
  }

  OtaUsbControlService &ota_service_;
  bool (*is_physically_connected_fn_)();
  Stream *_serial = nullptr;
  bool _enabled = false;
  bool last_connected_ = false;

  State state_ = State::WaitStart;
  Route route_ = Route::Undecided;
  uint16_t declared_len_ = 0;
  size_t fill_ = 0;
  uint8_t buf_[kBufCapacity];
};

} // namespace helpers
} // namespace ota
} // namespace meshcore
