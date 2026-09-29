#pragma once

#include <cstdint>
#include <Packet.h>

namespace mesh {
namespace ota {

static constexpr uint8_t kOtaForwardPriority = 250;

inline bool isOtaPayloadType(uint8_t payload_type) {
  return payload_type == PAYLOAD_TYPE_LORA_OTA;
}

inline bool isOtaPacket(const Packet* packet) {
  return packet != nullptr && isOtaPayloadType(packet->getPayloadType());
}

inline uint8_t floodPriorityForPayload(uint8_t payload_type, uint8_t path_hash_count) {
  (void)path_hash_count;
  if (payload_type == PAYLOAD_TYPE_LORA_OTA) return kOtaForwardPriority;
  if (payload_type == PAYLOAD_TYPE_PATH) return 2;
  if (payload_type == PAYLOAD_TYPE_ADVERT) return 3;
  return 1;
}

inline uint8_t directPriorityForPayload(uint8_t payload_type) {
  if (payload_type == PAYLOAD_TYPE_LORA_OTA) return kOtaForwardPriority;
  if (payload_type == PAYLOAD_TYPE_PATH) return 1;
  return 0;
}

}  // namespace ota
}  // namespace mesh
