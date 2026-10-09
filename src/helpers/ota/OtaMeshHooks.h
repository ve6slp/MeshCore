#pragma once

#include <cstdint>
#include <Packet.h>

#ifndef MESHCORE_LORA_OTA_RELAY
#define MESHCORE_LORA_OTA_RELAY 0
#endif

namespace mesh {
namespace ota {

static constexpr uint8_t kOtaForwardPriority = 250;

#if defined(MESHCORE_LORA_OTA) && MESHCORE_LORA_OTA
static constexpr bool kOtaMeshEnabled = true;
#else
static constexpr bool kOtaMeshEnabled = false;
#endif

// Relay-only builds classify opaque OTA traffic without enabling an installer.
inline bool isOtaPayloadType(uint8_t payload_type) {
  return (kOtaMeshEnabled || MESHCORE_LORA_OTA_RELAY) && payload_type == PAYLOAD_TYPE_LORA_OTA;
}

inline bool isOtaPacket(const Packet* packet) {
  return packet != nullptr && isOtaPayloadType(packet->getPayloadType());
}

// Local-origin flood priority (legacy: PATH 2, ADVERT 3, others 1). Relayed
// ordinary floods keep Mesh's hop-count priority and never use this helper.
inline uint8_t floodPriorityForPayload(uint8_t payload_type, uint8_t path_hash_count) {
  (void)path_hash_count;
  if (isOtaPayloadType(payload_type)) return kOtaForwardPriority;
  if (payload_type == PAYLOAD_TYPE_PATH) return 2;
  if (payload_type == PAYLOAD_TYPE_ADVERT) return 3;
  return 1;
}

// sendDirect priority (legacy: PATH 1, others 0). sendZeroHop is always 0
// in Mesh and must not use this helper.
inline uint8_t directPriorityForPayload(uint8_t payload_type) {
  if (isOtaPayloadType(payload_type)) return kOtaForwardPriority;
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
