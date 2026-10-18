#pragma once

#include <helpers/ota/OtaV4Protocol.h>

namespace mesh { namespace ota { namespace usb {

// Requests: [67, 4, op, body]. Probe has no body. Send carries an actual
// serialized Mesh packet, LocalFeed an unchanged generic v4 frame, and
// SetAdmin a current contact's full key plus a boolean.
// Replies: [30, 4, op, v4::Result]. Send appends actual airtime_us BE32;
// Ok is issued only by physical TX completion, never queue admission.
// Local receiver output is [30, 4, 3, v4frame]; RF input is [0x91, Mesh packet].
inline constexpr uint8_t kCommand = 67, kReplyCode = 30, kAbiVersion = 4;
inline constexpr uint8_t kRawPacketPush = 0x91;
enum class Op : uint8_t { Probe = 0, Send = 1, LocalFeed = 2, LocalFrame = 3, SetAdmin = 4 };
inline constexpr size_t kReplyBytes = 4;
inline constexpr size_t kSendReplyBytes = 8;

}}}
