#pragma once

#include <Packet.h>
#include <helpers/ota/OtaV4Protocol.h>

namespace mesh { namespace ota {

// path_len encodes both hash width and hop count. Budget the complete path,
// including any flood growth chosen by the host; never shrink v4 slices.
inline bool otaRfPathFits(size_t frame_size, uint8_t path_len, bool transport_codes = false) {
  return mesh::Packet::isValidPathLen(path_len) && frame_size <= v4::kMaxFrameBytes &&
      2 + (path_len & 63) * ((path_len >> 6) + 1) + frame_size +
          (transport_codes ? 4 : 0) <= MAX_TRANS_UNIT;
}

inline bool validOtaPacket(const mesh::Packet* packet) {
  v4::Frame frame;
  return packet && otaRfPathFits(packet->payload_len, packet->path_len, packet->hasTransportCodes()) &&
      v4::decodeFrame(packet->payload, packet->payload_len, frame);
}

}}
