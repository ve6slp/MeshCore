#pragma once

// For boards (e.g. examples/simple_repeater) whose existing USB CLI is a
// plain idle-at-newline TEXT line reader with no BaseSerialInterface/
// binary framing at all: demultiplexes that SAME raw byte stream between
// the existing text-line CLI (left entirely unchanged) and OTA
// commissioning control frames, using the EXACT SAME outer '<' + LE16
// length + payload framing as the companion_radio USB adapter (see
// OtaUsbCommissioningSerialInterface.h's doc comment for why a fresh,
// bounded parser is used rather than any existing one).
//
// A '<' can only begin a binary OTA frame while the text CLI is
// genuinely IDLE (no partially-typed command line pending) -- the demux
// decision is made the instant '<' arrives at idle. Once committed to
// binary framing, every subsequent byte (including ones that would
// otherwise look like CR/LF) is consumed here and NEVER reaches the
// text CLI, until the declared-length frame completes, is discarded as
// malformed, or stalls past the shared frame timeout.
//
// NOT natively host-testable (requires the Arduino-facing
// OtaUsbControlService, which itself wraps the native-testable
// OtaUsbControlFramer/OtaControlSessionRouter unchanged); this class
// contributes only the idle-byte text/binary routing decision and must
// be verified against the real Arduino toolchain by whoever owns the
// MCU build.

#include "helpers/ota/OtaUsbControlService.h"

#include <cstddef>
#include <cstdint>

namespace meshcore {
namespace ota {
namespace helpers {

class OtaUsbTextCliBinaryDemux {
public:
  explicit OtaUsbTextCliBinaryDemux(OtaUsbControlService &service) : service_(service) {}

  // Call for every incoming raw byte. `atIdle` must be true only when
  // the caller's text command buffer is currently empty (no partial
  // line pending) -- a '<' arriving mid-line is NOT a binary frame
  // start; an in-progress text line already owns this byte stream.
  // Returns true iff this byte was consumed as part of ongoing/just-
  // started binary OTA framing and MUST NOT be handed to the text CLI.
  bool consumeByte(uint8_t b, uint32_t nowMs, bool atIdle) {
    if (in_binary_ && (nowMs - frame_start_ms_) >= OtaUsbControlFramer::kDefaultFrameTimeoutMs) {
      // Mirrors the underlying framer's own stall timeout (same
      // constant, same clock) so both layers revert to idle in
      // lockstep: this byte is re-evaluated as a FRESH potential frame
      // start, never swallowed as stale payload of an already-discarded
      // frame.
      in_binary_ = false;
    }

    if (!in_binary_) {
      if (!(atIdle && b == '<')) return false;
      in_binary_ = true;
      state_ = State::Len1;
      frame_start_ms_ = nowMs;
      service_.onByte(b, nowMs);
      return true;
    }

    switch (state_) {
      case State::Len1:
        declared_len_ = b;
        state_ = State::Len2;
        break;
      case State::Len2: {
        declared_len_ |= static_cast<uint16_t>(b) << 8;
        fill_ = 0;
        if (declared_len_ == 0 || declared_len_ > OtaUsbControlFramer::kMaxPayload) {
          // The underlying framer independently discards this exact
          // condition from the identical two length bytes -- just
          // resync our own idle/binary latch here, in lockstep.
          in_binary_ = false;
        } else {
          state_ = State::Payload;
        }
        break;
      }
      case State::Payload:
        ++fill_;
        if (fill_ >= declared_len_) {
          in_binary_ = false; // frame complete; next byte resumes text-idle
        }
        break;
    }

    service_.onByte(b, nowMs);
    return true;
  }

  // Must be called every loop() pass (independent of incoming bytes) so
  // a stalled partial binary frame can never wedge text CLI input
  // forever, even if no further bytes ever arrive to trigger the
  // lockstep check in consumeByte() above.
  void tick(uint32_t nowMs) {
    service_.tick(nowMs);
    if (in_binary_ && (nowMs - frame_start_ms_) >= OtaUsbControlFramer::kDefaultFrameTimeoutMs) {
      in_binary_ = false;
    }
  }

  // Call on a genuine USB connection-epoch change (new physical attach,
  // or a disconnect) -- discards any in-flight binary-mode latch here
  // (the caller must separately call the wrapped OtaUsbControlService's
  // own onConnectionEpochChanged()).
  void reset() {
    in_binary_ = false;
    state_ = State::Len1;
    declared_len_ = 0;
    fill_ = 0;
  }

private:
  enum class State : uint8_t { Len1, Len2, Payload };

  OtaUsbControlService &service_;
  bool in_binary_ = false;
  State state_ = State::Len1;
  uint16_t declared_len_ = 0;
  size_t fill_ = 0;
  uint32_t frame_start_ms_ = 0;
};

} // namespace helpers
} // namespace ota
} // namespace meshcore
