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

// Locally-originated raw packet injection (e.g. CMD_SEND_RAW_PACKET) can't
// know its payload type until after allocation+parse, exactly like raw
// radio ingress (Dispatcher::checkRecv()). This mirrors the identical
// post-parse reserve check already enforced there and at
// Dispatcher::processRecvPacket() (see PacketManager::kOtaAllocReserve):
// once a parsed packet turns out to be OTA traffic, and accepting it would
// leave the pool at/below the shared ordinary-traffic reserve, the caller
// must release it (not queue it for send) instead of relying on
// allocNew()'s is_ota_bulk reserve check, which only fires when the
// caller already knew at allocation time that the packet was OTA traffic.
inline bool exceedsOtaAllocReserveAfterParse(const Packet* packet, int free_count_after_alloc, int reserve) {
  return isOtaPacket(packet) && free_count_after_alloc <= reserve;
}

}  // namespace ota
}  // namespace mesh
