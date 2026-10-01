#pragma once

// Bounded, fixed-size, incremental byte framer for the OTA USB control
// channel's OUTER transport framing: ONE leading direction byte ('<' for
// host->device, '>' for device->host) + LE16 payload length + payload
// bytes. There is NO trailing delimiter -- the declared length is the
// only end-of-frame signal.
//
// This is deliberately host-buildable (no Arduino/Serial dependency) so
// it can be exercised by native tests; the Arduino-facing adapter that
// actually owns a `Serial`/`BaseSerialInterface` wraps this class and
// supplies the raw bytes.
//
// Design constraints (see OtaUsbControlFramer tests for the behaviors
// this enforces):
//  - Fixed-size internal buffer, no dynamic growth; payload capped at
//    kMaxPayload (168 bytes: the larger of the inner control request/
//    reply wire sizes, which top out at 37+128=165 and 40+128=168
//    respectively).
//  - A declared length of 0 or > kMaxPayload is a malformed header: it
//    is rejected and the parser resyncs to look for the next leading
//    direction byte, WITHOUT ever surfacing a truncated/partial frame
//    to the caller.
//  - A partial frame that stalls (no forward progress within the
//    timeout window) is discarded on the next `tick()`, so a dropped
//    byte or wedged host can never permanently block future frames.
//  - Exactly one frame is buffered/parsed at a time; the caller must
//    consume (copy out) a ready frame before feeding further bytes, or
//    subsequent bytes simply begin assembling the next frame once the
//    ready one is explicitly cleared via `resetAfterConsume()`.

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace meshcore {
namespace ota {
namespace helpers {

class OtaUsbControlFramer {
public:
  // Larger of the inner request (37+128=165) and reply (40+128=168) wire
  // sizes; kept as a literal here (rather than including the protocol
  // header) so this framer has zero dependency on the control ABI and
  // can be reused for any <=168-byte inner payload.
  static constexpr size_t kMaxPayload = 168;
  static constexpr uint32_t kDefaultFrameTimeoutMs = 2000;

  enum class FeedResult : uint8_t {
    Idle,        // Byte consumed, no frame boundary reached yet.
    FrameReady,  // A complete, validly-shaped frame is now available.
    Discarded,   // A malformed header (bad direction byte while not
                 // resyncing, or zero/oversized declared length) was
                 // rejected; the parser has resynced to WaitStart.
    TimedOut,    // A stalled partial frame was discarded by tick().
  };

  explicit OtaUsbControlFramer(uint8_t expectedDirectionByte,
                                uint32_t frameTimeoutMs = kDefaultFrameTimeoutMs)
      : expected_direction_(expectedDirectionByte), timeout_ms_(frameTimeoutMs) {}

  // Resets all parse state; any partially-assembled or ready frame is
  // discarded. Used on a connection-epoch change (new USB attach).
  void reset() {
    state_ = State::WaitStart;
    filled_ = 0;
    need_ = 0;
    len_ = 0;
  }

  // Feed one incoming byte. `nowMs` is a monotonic millisecond clock
  // used only for stall timeout accounting.
  FeedResult feedByte(uint8_t b, uint32_t nowMs) {
    switch (state_) {
      case State::WaitStart:
        if (b != expected_direction_) return FeedResult::Idle; // ignore stray bytes
        frame_start_ms_ = nowMs;
        state_ = State::LenLow;
        return FeedResult::Idle;
      case State::LenLow:
        len_lo_ = b;
        state_ = State::LenHigh;
        return FeedResult::Idle;
      case State::LenHigh: {
        const size_t declared = static_cast<size_t>(len_lo_) | (static_cast<size_t>(b) << 8);
        if (declared == 0 || declared > kMaxPayload) {
          // Malformed header: never dispatch a truncated/guessed prefix.
          // Resync immediately rather than trying to skip `declared`
          // unknown bytes (which could itself be wrong for a corrupt
          // length field).
          state_ = State::WaitStart;
          return FeedResult::Discarded;
        }
        need_ = declared;
        filled_ = 0;
        state_ = State::Payload;
        return FeedResult::Idle;
      }
      case State::Payload:
        payload_[filled_++] = b;
        if (filled_ < need_) return FeedResult::Idle;
        len_ = need_;
        state_ = State::WaitStart;
        return FeedResult::FrameReady;
      default:
        return FeedResult::Idle;
    }
  }

  // Call periodically (independent of feedByte) so a partial frame that
  // stops arriving mid-stream doesn't wedge the parser forever.
  FeedResult tick(uint32_t nowMs) {
    if (state_ == State::WaitStart) return FeedResult::Idle;
    if (nowMs - frame_start_ms_ >= timeout_ms_) {
      state_ = State::WaitStart;
      filled_ = 0;
      need_ = 0;
      return FeedResult::TimedOut;
    }
    return FeedResult::Idle;
  }

  // Valid only immediately after feedByte() returns FrameReady, and only
  // until the next feedByte() call (which begins assembling the next
  // frame into the same buffer).
  const uint8_t* frameData() const { return payload_; }
  size_t frameLen() const { return len_; }

  // Builds an outer frame (direction byte + LE16 length + payload) into
  // `out`. Returns 0 (and writes nothing) if payload is zero/oversized
  // or doesn't fit `cap` -- callers must never transmit a truncated
  // length-prefixed frame.
  static size_t buildFrame(uint8_t directionByte, const uint8_t* payload, size_t len, uint8_t* out,
                           size_t cap) {
    if (len == 0 || len > kMaxPayload) return 0;
    if (cap < len + 3) return 0;
    out[0] = directionByte;
    out[1] = static_cast<uint8_t>(len & 0xFF);
    out[2] = static_cast<uint8_t>((len >> 8) & 0xFF);
    std::memcpy(out + 3, payload, len);
    return len + 3;
  }

private:
  enum class State : uint8_t { WaitStart, LenLow, LenHigh, Payload };

  uint8_t expected_direction_;
  uint32_t timeout_ms_;
  State state_ = State::WaitStart;
  uint8_t len_lo_ = 0;
  uint8_t payload_[kMaxPayload] = {};
  size_t filled_ = 0;
  size_t need_ = 0;
  size_t len_ = 0;
  uint32_t frame_start_ms_ = 0;
};

} // namespace helpers
} // namespace ota
} // namespace meshcore
