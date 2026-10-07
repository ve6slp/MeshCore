#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <ota/trust/Sha256.h>

namespace mesh {
namespace ota {

static constexpr uint8_t kOtaSignedBlockKind = 0x01u;
static constexpr uint8_t kOtaOwnerSignedBlockKind = 0x09u;
// 183 bytes at the USB ABI's unchanged 84-byte block size, fitting a
// MeshCore payload. The full manifest hash is signed, not repeated.
static constexpr size_t kOtaOwnerSignedBlockMaxBytes = 1u + 32u + 2u + 84u + 64u;
static constexpr size_t kOtaManifestTagBytes = 4u;
static constexpr size_t kOtaBlockIndexBytes = 2u;
static constexpr size_t kOtaBlockSignatureBytes = 64u;
static constexpr size_t kOtaBlockMaxDataBytes = 84u;
static constexpr size_t kOtaManifestHashBytes = 32u;
static constexpr size_t kOtaCanonicalManifestBytes = 59u;
static constexpr size_t kOtaBlockSignedMessageMaxBytes =
    kOtaManifestHashBytes + 1u + kOtaBlockIndexBytes + 1u + kOtaBlockMaxDataBytes;
static constexpr size_t kOtaSignedBlockMinBytes =
    1u + kOtaManifestTagBytes + kOtaBlockIndexBytes + 1u + kOtaBlockSignatureBytes;
static constexpr size_t kOtaSignedBlockMaxBytes =
    1u + kOtaManifestTagBytes + kOtaBlockIndexBytes + kOtaBlockMaxDataBytes + kOtaBlockSignatureBytes;

struct OtaSignedBlockFrame {
  uint8_t kind = 0;
  uint8_t manifestTag[kOtaManifestTagBytes] = {0};
  uint16_t index = 0;
  const uint8_t* data = nullptr;
  size_t dataLen = 0;
  const uint8_t* signature = nullptr;
};

inline size_t encodeOtaOwnerSignedBlock(const uint8_t owner[32], uint16_t index,
                                        const uint8_t* data, size_t len, const uint8_t signature[64],
                                        uint8_t* out, size_t capacity) {
  const size_t size = 99u + len;
  if (!owner || !data || !signature || !out || len == 0 || len > 84 || capacity < size) return 0;
  out[0] = kOtaOwnerSignedBlockKind;
  std::memcpy(out + 1, owner, 32);
  out[33] = static_cast<uint8_t>(index >> 8);
  out[34] = static_cast<uint8_t>(index);
  std::memcpy(out + 35, data, len);
  std::memcpy(out + 35 + len, signature, 64);
  return size;
}

inline uint16_t getOtaBlockIndexBe(const uint8_t in[2]) {
  return static_cast<uint16_t>((static_cast<uint16_t>(in[0]) << 8) | in[1]);
}

inline void putOtaBlockIndexBe(uint8_t out[2], uint16_t value) {
  out[0] = static_cast<uint8_t>((value >> 8) & 0xFFu);
  out[1] = static_cast<uint8_t>(value & 0xFFu);
}

inline void computeOtaManifestHash(const uint8_t canonical[kOtaCanonicalManifestBytes],
                                   uint8_t out[kOtaManifestHashBytes]) {
  ::ota::trust::Sha256::hash(canonical, kOtaCanonicalManifestBytes, out);
}

inline void manifestTagFromHash(const uint8_t manifest_hash[kOtaManifestHashBytes],
                                uint8_t out[kOtaManifestTagBytes]) {
  std::memcpy(out, manifest_hash, kOtaManifestTagBytes);
}

inline size_t buildOtaBlockSignedMessage(const uint8_t manifest_hash[kOtaManifestHashBytes],
                                         uint8_t kind, uint16_t index,
                                         const uint8_t* data, size_t data_len,
                                         uint8_t out[kOtaBlockSignedMessageMaxBytes]) {
  size_t i = 0;
  std::memcpy(&out[i], manifest_hash, kOtaManifestHashBytes); i += kOtaManifestHashBytes;
  out[i++] = kind;
  putOtaBlockIndexBe(&out[i], index); i += kOtaBlockIndexBytes;
  out[i++] = static_cast<uint8_t>(data_len);
  if (data_len != 0 && data != nullptr) {
    std::memcpy(&out[i], data, data_len);
    i += data_len;
  }
  return i;
}

inline bool parseOtaSignedBlockFrame(const uint8_t* frame, size_t frame_len, OtaSignedBlockFrame& out) {
  if (frame == nullptr || frame_len < kOtaSignedBlockMinBytes || frame_len > kOtaSignedBlockMaxBytes) {
    return false;
  }
  const size_t data_len = frame_len - (1u + kOtaManifestTagBytes + kOtaBlockIndexBytes + kOtaBlockSignatureBytes);
  if (data_len == 0 || data_len > kOtaBlockMaxDataBytes) return false;
  out.kind = frame[0];
  std::memcpy(out.manifestTag, &frame[1], kOtaManifestTagBytes);
  out.index = getOtaBlockIndexBe(&frame[1 + kOtaManifestTagBytes]);
  out.data = &frame[1 + kOtaManifestTagBytes + kOtaBlockIndexBytes];
  out.dataLen = data_len;
  out.signature = out.data + data_len;
  return true;
}

inline bool encodeOtaSignedBlockFrame(uint8_t kind, const uint8_t manifest_hash[kOtaManifestHashBytes],
                                      uint16_t index, const uint8_t* data, size_t data_len,
                                      const uint8_t signature[kOtaBlockSignatureBytes],
                                      uint8_t* out, size_t out_capacity, size_t& out_len) {
  if (out == nullptr || signature == nullptr || data == nullptr || data_len == 0 ||
      data_len > kOtaBlockMaxDataBytes) {
    return false;
  }
  out_len = 1u + kOtaManifestTagBytes + kOtaBlockIndexBytes + data_len + kOtaBlockSignatureBytes;
  if (out_capacity < out_len) return false;
  out[0] = kind;
  manifestTagFromHash(manifest_hash, &out[1]);
  putOtaBlockIndexBe(&out[1 + kOtaManifestTagBytes], index);
  std::memcpy(&out[1 + kOtaManifestTagBytes + kOtaBlockIndexBytes], data, data_len);
  std::memcpy(&out[1 + kOtaManifestTagBytes + kOtaBlockIndexBytes + data_len], signature,
              kOtaBlockSignatureBytes);
  return true;
}

}  // namespace ota
}  // namespace mesh
