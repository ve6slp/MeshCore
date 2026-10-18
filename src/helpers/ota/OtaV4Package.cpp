#include "OtaV4Package.h"
#include <ota/trust/Sha256.h>

namespace mesh { namespace ota { namespace v4 {

Result Manifest::parse(const uint8_t* bytes, size_t size) {
  bytes_ = nullptr; size_ = 0; count_ = 0;
  descriptor_ = Descriptor{};
  std::memset(hash_, 0, sizeof(hash_));
  if (!bytes || size < kManifestPrefixBytes + kManifestEntryBytes + kSignatureBytes ||
      size > kMaxManifestBytes || std::memcmp(bytes, "MCO4", 4) ||
      bytes[4] != kVersion || bytes[5] != 13) return Result::Invalid;
  const uint16_t count = read16(bytes + 6);
  if (!count || count > kMaxChunks ||
      size != kManifestPrefixBytes + count * kManifestEntryBytes + kSignatureBytes)
    return Result::Invalid;
  if (meshcore::ota::protocol::decodeOtaDescriptorCanonical(bytes + 40, 59, descriptor_) !=
      meshcore::ota::protocol::OtaDescriptorCodecResult::Ok) return Result::Invalid;
  if (!descriptor_.exactSizeBytes || descriptor_.exactSizeBytes > kChunkBytes * kMaxChunks ||
      (descriptor_.exactSizeBytes + kChunkBytes - 1) / kChunkBytes != count)
    return Result::Invalid;
  for (uint16_t i = 0; i < count; ++i) {
    const uint8_t* entry = bytes + kManifestPrefixBytes + i * kManifestEntryBytes;
    if (entry[0] > static_cast<uint8_t>(Codec::LzmaThumb)) return Result::Unsupported;
    const size_t stored = read16(entry + 1);
    const size_t raw = i + 1 == count ?
        descriptor_.exactSizeBytes - static_cast<size_t>(i) * kChunkBytes : kChunkBytes;
    if (!stored || stored > kChunkBytes ||
        (entry[0] == static_cast<uint8_t>(Codec::Raw) && stored != raw))
      return Result::Invalid;
  }
  bytes_ = bytes; size_ = size; count_ = count;
  ::ota::trust::Sha256::hash(bytes, size, hash_);
  return Result::Ok;
}

Result Manifest::authorize(Platform& platform) const {
  if (!bytes_) return Result::State;
  const Policy p = platform.policy();
  const auto& d = descriptor_;
  if (d.boardFamily != p.boardFamily || d.boardVariant != p.boardVariant || d.role != p.role ||
      d.appAddress != p.appAddress || !p.maxImageBytes || d.exactSizeBytes > p.maxImageBytes ||
      d.exactSizeBytes > UINT32_MAX - d.appAddress)
    return Result::Invalid;
  if (d.formatId != p.formatId || d.keyId != p.keyId || d.algorithmId != p.algorithmId ||
      (d.minBootloaderCapabilities & ~p.bootloaderCapabilities))
    return Result::Unsupported;
  RunningEvidence evidence;
  const Result result = platform.evidence(evidence);
  if (result != Result::Ok) return result;
  if (!(evidence.flags & FloorKnown)) return Result::Denied;
  if (d.securityCounter <= evidence.floor) return Result::Replay;
  if (!platform.isCurrentAdmin(signer()) ||
      !platform.verify(signer(), nullptr, 0, canonical(), 59, bootSignature()) ||
      !platform.verify(signer(), kManifestDomain, sizeof(kManifestDomain), bytes_,
                       size_ - kSignatureBytes, bytes_ + size_ - kSignatureBytes))
    return Result::Denied;
  return Result::Ok;
}

Chunk Manifest::chunk(uint16_t index) const {
  if (!bytes_ || index >= count_) return Chunk{};
  const uint8_t* entry = bytes_ + kManifestPrefixBytes + index * kManifestEntryBytes;
  return Chunk{static_cast<Codec>(entry[0]), read16(entry + 1), entry + 3};
}

size_t Manifest::rawSize(uint16_t index) const {
  if (!bytes_ || index >= count_) return 0;
  return index + 1 == count_ ?
      descriptor_.exactSizeBytes - static_cast<size_t>(index) * kChunkBytes : kChunkBytes;
}

}}}
