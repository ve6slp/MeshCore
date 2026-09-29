#pragma once

// LoRa OTA wire protocol - shared primitive types, constants and explicit
// endian codecs.
//
// This header (and the rest of src/ota/protocol/) has no dependency on the
// shared MeshCore firmware headers so it can be wired into any transport by
// an integrator later. It performs no cryptography and no flash/storage
// access.

#include <cstdint>
#include <cstddef>

namespace meshcore {
namespace ota {
namespace protocol {

// Frozen dedicated logical message namespace for OTA envelopes. Any receiver
// MUST reject frames whose namespace does not match this value. This value
// and the protocol version below are a stable wire contract: they must never
// be reused for a different meaning, only superseded by a new version.
inline constexpr uint16_t kOtaNamespaceId = 0x4F54; // ASCII "OT"
inline constexpr uint8_t kOtaProtocolVersion = 1;

// Matches MeshCore's MAX_PACKET_PAYLOAD (see src/MeshCore.h, currently 184)
// at the time this protocol was designed. Kept as an independent, explicit
// constant so this module has no compile-time dependency on shared firmware
// headers; the integrator may adjust this when wiring the real transport.
inline constexpr size_t kOtaMaxFrameSize = 184;

// Frozen logical message type namespace for OTA envelopes.
enum class OtaMessageType : uint8_t {
  DescriptorFragment = 1,
  Authorization = 2,
  Chunk = 3,
  Receipt = 4,
  Abort = 5,
  LeaseNegotiation = 6,
  Announcement = 7,
  Census = 8,
  CohortResolution = 9,
  MissingRange = 10,
  Commit = 11,
};

inline constexpr uint8_t kOtaMessageTypeMin = static_cast<uint8_t>(OtaMessageType::DescriptorFragment);
inline constexpr uint8_t kOtaMessageTypeMax = static_cast<uint8_t>(OtaMessageType::Commit);

constexpr bool isKnownOtaMessageType(uint8_t raw) {
  return raw >= kOtaMessageTypeMin && raw <= kOtaMessageTypeMax;
}

// Sub-operations carried inside a LeaseNegotiation message.
enum class OtaLeaseSubtype : uint8_t {
  Request = 1,
  Grant = 2,
  Deny = 3,
  Renew = 4,
  Release = 5,
};

// Airtime accounting categories understood by the OTA runtime limiter.
enum class OtaAirtimeCategory : uint8_t {
  Control = 0,
  Repair = 1,
  Relay = 2,
};

inline constexpr int kOtaAirtimeCategoryCount = 3;

// ---- Explicit big-endian ("network order") codecs. Byte-wise, no aliasing
// or undefined behavior from reinterpret_cast/memcpy of multi-byte types. ----

inline void putOtaBE16(uint8_t* dst, uint16_t v) {
  dst[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
  dst[1] = static_cast<uint8_t>(v & 0xFF);
}

inline uint16_t getOtaBE16(const uint8_t* src) {
  return static_cast<uint16_t>((static_cast<uint16_t>(src[0]) << 8) | static_cast<uint16_t>(src[1]));
}

inline void putOtaBE32(uint8_t* dst, uint32_t v) {
  dst[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
  dst[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
  dst[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
  dst[3] = static_cast<uint8_t>(v & 0xFF);
}

inline uint32_t getOtaBE32(const uint8_t* src) {
  return (static_cast<uint32_t>(src[0]) << 24) |
         (static_cast<uint32_t>(src[1]) << 16) |
         (static_cast<uint32_t>(src[2]) << 8) |
         static_cast<uint32_t>(src[3]);
}

} // namespace protocol
} // namespace ota
} // namespace meshcore
