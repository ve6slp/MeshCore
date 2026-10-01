#pragma once

// Source-bound USB control-channel service: wires the bounded
// OtaUsbControlFramer transport framing to a live OtaControlSessionRouter,
// so a single demultiplexed byte stream (owned by whatever Arduino-facing
// adapter actually reads/writes `Serial`) can be fed in one byte at a
// time and produces ready-to-transmit reply frames.
//
// Deliberately host-buildable: no Arduino/Serial dependency. The
// Arduino-facing wrapper that implements BaseSerialInterface (not yet
// built) owns a `Serial`/physical USB source, reads raw bytes, feeds
// them here via onByte(), and writes out pendingReplyData()/pendingReplyLen()
// once hasPendingReply() is true, then calls consumeReply().
//
// Connection-epoch handling: a genuine USB disconnect/reconnect (a real
// transport event, never the legacy always-true isConnected() proxy)
// must revoke any open session/job -- a new physical connection is a
// new, unauthenticated source and must start from OPEN again. Call
// onConnectionEpochChanged() exactly when the adapter observes that.

#include <cstddef>
#include <cstdint>

#include "helpers/ota/OtaUsbControlFramer.h"
#include "ota/protocol/OtaCommissioningAbi.h"
#include "ota/runtime/OtaControlSessionRouter.h"

namespace meshcore {
namespace ota {
namespace helpers {

class OtaUsbControlService {
public:
  // `router` must outlive this service; it is NOT owned here (per the
  // intended design where a single, longer-lived OtaFirmwareService owns
  // the router/job, and this class is purely the transport glue).
  explicit OtaUsbControlService(runtime::OtaControlSessionRouter& router)
      : router_(router), rx_('<'), reply_len_(0) {}

  // Feed one raw incoming byte from the physical USB source. Returns true
  // if a reply frame is now pending (hasPendingReply()).
  bool onByte(uint8_t b, uint32_t nowMs) {
    const auto result = rx_.feedByte(b, nowMs);
    if (result != OtaUsbControlFramer::FeedResult::FrameReady) return false;
    return dispatchReadyFrame();
  }

  // Call periodically (independent of onByte) so a stalled partial frame
  // (dropped bytes mid-transfer) can never wedge the parser.
  void tick(uint32_t nowMs) { rx_.tick(nowMs); }

  bool hasPendingReply() const { return reply_len_ > 0; }
  const uint8_t* pendingReplyData() const { return reply_wire_; }
  size_t pendingReplyLen() const { return reply_len_; }
  void consumeReply() { reply_len_ = 0; }

  // Must be called on every genuine USB connection epoch change (new
  // physical attach, or a disconnect) -- NEVER on ordinary idle polling.
  // Discards any in-flight partial frame, drops any not-yet-sent reply
  // (a stale reply must never be delivered to a newly-attached, distinct
  // source), and forcibly revokes any open session/job so the new
  // physical connection must re-authenticate via a fresh OPEN.
  void onConnectionEpochChanged() {
    rx_.reset();
    reply_len_ = 0;
    router_.forceCloseSession();
  }

private:
  bool dispatchReadyFrame() {
    uint8_t replyFrame[ota::protocol::kOtaControlMaxReplyWireSize];
    const size_t replyFrameLen =
        router_.dispatch(rx_.frameData(), rx_.frameLen(), replyFrame, sizeof(replyFrame));
    if (replyFrameLen == 0) return false; // malformed beyond recovery; nothing to send back
    const size_t wireLen =
        OtaUsbControlFramer::buildFrame('>', replyFrame, replyFrameLen, reply_wire_, sizeof(reply_wire_));
    if (wireLen == 0) return false; // reply somehow exceeds the outer framing capacity; drop rather than truncate
    reply_len_ = wireLen;
    return true;
  }

  runtime::OtaControlSessionRouter& router_;
  OtaUsbControlFramer rx_;
  uint8_t reply_wire_[3 + OtaUsbControlFramer::kMaxPayload];
  size_t reply_len_;
};

} // namespace helpers
} // namespace ota
} // namespace meshcore
