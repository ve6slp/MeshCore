#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "OtaSessionIdentity.h"
#include "ota/trust/Sha256.h"

namespace meshcore {
namespace ota {
namespace runtime {

// BE64(first8(SHA256(domain || controller32 || campaignBE32 ||
// sessionBE32 || attemptBE16 || SHA256(canonical59)))), without domain NUL.
// Derivation is not authorization: the durable owner must preserve the
// complete binding and refuse zero/colliding nonces before command publication.
inline uint64_t otaInstallAttemptNonce(const uint8_t controller[32], const OtaSessionId& session,
                                      const uint8_t canonical_descriptor[59]) {
  if (controller == nullptr || canonical_descriptor == nullptr) return 0;
  static const char domain[] = "MeshCore/OTA/install-attempt/v1";
  uint8_t descriptor_hash[32];
  ::ota::trust::Sha256::hash(canonical_descriptor, 59, descriptor_hash);
  uint8_t message[sizeof(domain) - 1 + 32 + 4 + 4 + 2 + sizeof(descriptor_hash)];
  size_t off = 0;
  memcpy(message + off, domain, sizeof(domain) - 1);
  off += sizeof(domain) - 1;
  memcpy(message + off, controller, 32);
  off += 32;
  message[off++] = static_cast<uint8_t>(session.campaignId >> 24);
  message[off++] = static_cast<uint8_t>(session.campaignId >> 16);
  message[off++] = static_cast<uint8_t>(session.campaignId >> 8);
  message[off++] = static_cast<uint8_t>(session.campaignId);
  message[off++] = static_cast<uint8_t>(session.sessionId >> 24);
  message[off++] = static_cast<uint8_t>(session.sessionId >> 16);
  message[off++] = static_cast<uint8_t>(session.sessionId >> 8);
  message[off++] = static_cast<uint8_t>(session.sessionId);
  message[off++] = static_cast<uint8_t>(session.attemptId >> 8);
  message[off++] = static_cast<uint8_t>(session.attemptId);
  memcpy(message + off, descriptor_hash, sizeof(descriptor_hash));
  off += sizeof(descriptor_hash);
  uint8_t hash[32];
  ::ota::trust::Sha256::hash(message, off, hash);
  uint64_t nonce = 0;
  for (size_t i = 0; i < 8; ++i) nonce = (nonce << 8) | hash[i];
  return nonce;
}

}  // namespace runtime
}  // namespace ota
}  // namespace meshcore
