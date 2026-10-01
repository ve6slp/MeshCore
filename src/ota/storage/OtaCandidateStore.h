#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <ota/platform/FlashRegion.h>
#include <ota/storage/Crc32.h>
#include <ota/protocol/OtaDescriptor.h>
#include <helpers/ota/OtaBlockSigning.h>

namespace ota {
namespace storage {

class OtaCandidateStore {
public:
  enum class Phase : uint8_t {
    Idle = 0,
    Receiving = 1,
    Verifying = 2,
    Ready = 3,
    Committed = 4,
    Aborted = 5,
    Failed = 6,
  };

  struct Snapshot {
    bool valid = false;
    bool localCache = false;
    Phase phase = Phase::Idle;
    uint32_t sequence = 0;
    uint32_t campaignId = 0;
    uint32_t sessionId = 0;
    uint16_t attemptId = 0;
    uint16_t totalBlocks = 0;
    uint32_t exactSizeBytes = 0;
    uint8_t canonical[mesh::ota::kOtaCanonicalManifestBytes] = {0};
    uint8_t ownerPublicKey[32] = {0};
    uint8_t signature[64] = {0};
    uint16_t receivedBlocks = 0;
  };

  static constexpr uint32_t kMagic = 0x4F544341u;  // OTCA
  static constexpr uint16_t kVersion = 1u;
  static constexpr uint32_t kCommitMarker = 0x43414E44u;  // CAND
  static constexpr uint32_t kSectorBytes = 4096u;
  static constexpr uint32_t kExpectedRegionBytes = 8192u;
  static constexpr uint32_t kMetadataSectorOffset = 0u;
  static constexpr uint32_t kBitmapSectorOffset = kSectorBytes;
  static constexpr uint32_t kRecordBytes = 256u;
  static constexpr uint32_t kRecordSlots = kSectorBytes / kRecordBytes;
  static constexpr uint32_t kMaxBlocks = kSectorBytes * 8u;

  explicit OtaCandidateStore(platform::FlashRegion& region) : region_(region) {}

  bool isValid() const {
    return region_.isValid() && region_.eraseUnitBytes() == kSectorBytes &&
           region_.sizeBytes() == kExpectedRegionBytes;
  }

  bool reset(const Snapshot& snapshot) {
    if (!isValid() || !snapshot.valid || snapshot.totalBlocks == 0 || snapshot.totalBlocks > kMaxBlocks) return false;
    if (!eraseMetadataSector() || !eraseBitmapSector()) return false;
    return append(snapshot);
  }

  bool append(const Snapshot& snapshot) {
    if (!isValid() || !snapshot.valid || snapshot.totalBlocks == 0 || snapshot.totalBlocks > kMaxBlocks) return false;
    uint32_t slot = 0;
    uint32_t previous_sequence = 0;
    if (!findNextSlot(slot, previous_sequence)) return false;

    uint8_t record[kRecordBytes];
    std::memset(record, 0xFF, sizeof(record));
    putU32(record + 0, kMagic);
    putU16(record + 4, kVersion);
    putU16(record + 6, static_cast<uint16_t>(kRecordBytes));
    putU32(record + 8, previous_sequence + 1u);
    record[12] = static_cast<uint8_t>(snapshot.phase) | (snapshot.localCache ? 0x80u : 0u);
    putU16(record + 13, snapshot.totalBlocks);
    putU32(record + 15, snapshot.exactSizeBytes);
    putU32(record + 19, snapshot.campaignId);
    putU32(record + 23, snapshot.sessionId);
    putU16(record + 27, snapshot.attemptId);
    std::memcpy(record + 29, snapshot.canonical, sizeof(snapshot.canonical));
    std::memcpy(record + 88, snapshot.ownerPublicKey, sizeof(snapshot.ownerPublicKey));
    std::memcpy(record + 120, snapshot.signature, sizeof(snapshot.signature));
    putU32(record + 184, Crc32::computeFinalized(record, 184));
    putU32(record + 188, kCommitMarker);

    const uint32_t slot_offset = kMetadataSectorOffset + slot * kRecordBytes;
    if (!platform::isOk(region_.program(slot_offset, record, 188))) return false;
    uint8_t verify[188];
    if (!platform::isOk(region_.read(slot_offset, verify, 188))) return false;
    if (std::memcmp(record, verify, 188) != 0) return false;
    if (!platform::isOk(region_.program(slot_offset + 188, record + 188, 4))) return false;
    uint8_t marker[4];
    if (!platform::isOk(region_.read(slot_offset + 188, marker, 4))) return false;
    if (getU32(marker) != kCommitMarker) return false;
    return true;
  }

  bool load(Snapshot& out) const {
    out = Snapshot();
    if (!isValid()) return false;
    bool found = false;
    uint32_t best_sequence = 0;
    Snapshot best;
    for (uint32_t slot = 0; slot < kRecordSlots; ++slot) {
      Snapshot current;
      if (!readSlot(slot, current)) continue;
      if (!found || current.sequence >= best_sequence) {
        found = true;
        best_sequence = current.sequence;
        best = current;
      }
    }
    if (!found) return false;
    best.receivedBlocks = countReceived(best.totalBlocks);
    out = best;
    return true;
  }

  bool clearBitmap() {
    return eraseBitmapSector();
  }

  bool markReceived(uint16_t block_index) {
    if (!isValid()) return false;
    const uint32_t byte_index = block_index / 8u;
    const uint8_t bit = static_cast<uint8_t>(1u << (block_index % 8u));
    if (byte_index >= kSectorBytes) return false;
    const uint32_t offset = kBitmapSectorOffset + byte_index;
    uint8_t current = 0xFFu;
    if (!platform::isOk(region_.read(offset, &current, 1))) return false;
    if ((current & bit) == 0u) return true;
    const uint8_t programmed = static_cast<uint8_t>(current & static_cast<uint8_t>(~bit));
    if (!platform::isOk(region_.program(offset, &programmed, 1))) return false;
    uint8_t verify = 0xFFu;
    if (!platform::isOk(region_.read(offset, &verify, 1))) return false;
    return verify == programmed;
  }

  bool isReceived(uint16_t block_index) const {
    bool received = false;
    return readReceived(block_index, received) && received;
  }

  bool readReceived(uint16_t block_index, bool& received) const {
    received = false;
    if (!isValid()) return false;
    const uint32_t byte_index = block_index / 8u;
    const uint8_t bit = static_cast<uint8_t>(1u << (block_index % 8u));
    if (byte_index >= kSectorBytes) return false;
    uint8_t current = 0xFFu;
    if (!platform::isOk(region_.read(kBitmapSectorOffset + byte_index, &current, 1))) return false;
    received = (current & bit) == 0u;
    return true;
  }

  uint16_t countReceived(uint16_t total_blocks) const {
    if (!isValid() || total_blocks == 0) return 0;
    uint16_t total = 0;
    const uint32_t bytes = (static_cast<uint32_t>(total_blocks) + 7u) / 8u;
    for (uint32_t i = 0; i < bytes; ++i) {
      uint8_t current = 0xFFu;
      if (!platform::isOk(region_.read(kBitmapSectorOffset + i, &current, 1))) return 0;
      for (uint8_t bit = 0; bit < 8u; ++bit) {
        const uint32_t block = i * 8u + bit;
        if (block >= total_blocks) break;
        if ((current & static_cast<uint8_t>(1u << bit)) == 0u) ++total;
      }
    }
    return total;
  }

private:
  static void putU16(uint8_t* out, uint16_t value) {
    out[0] = static_cast<uint8_t>(value & 0xFFu);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
  }

  static void putU32(uint8_t* out, uint32_t value) {
    out[0] = static_cast<uint8_t>(value & 0xFFu);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
    out[2] = static_cast<uint8_t>((value >> 16) & 0xFFu);
    out[3] = static_cast<uint8_t>((value >> 24) & 0xFFu);
  }

  static uint16_t getU16(const uint8_t* in) {
    return static_cast<uint16_t>(static_cast<uint16_t>(in[0]) |
                                 (static_cast<uint16_t>(in[1]) << 8));
  }

  static uint32_t getU32(const uint8_t* in) {
    return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
  }

  bool eraseMetadataSector() {
    return platform::isOk(region_.eraseSector(kMetadataSectorOffset));
  }

  bool eraseBitmapSector() {
    return platform::isOk(region_.eraseSector(kBitmapSectorOffset));
  }

  bool findNextSlot(uint32_t& out_slot, uint32_t& out_previous_sequence) const {
    out_slot = 0;
    out_previous_sequence = 0;
    bool found_any = false;
    uint32_t first_free = kRecordSlots;
    for (uint32_t slot = 0; slot < kRecordSlots; ++slot) {
      Snapshot current;
      if (readSlot(slot, current)) {
        found_any = true;
        if (current.sequence >= out_previous_sequence) out_previous_sequence = current.sequence;
        continue;
      }
      uint8_t first4[4] = {0, 0, 0, 0};
      if (!platform::isOk(region_.read(kMetadataSectorOffset + slot * kRecordBytes, first4, 4))) return false;
      if (first4[0] == 0xFFu && first4[1] == 0xFFu && first4[2] == 0xFFu && first4[3] == 0xFFu) {
        first_free = slot;
        break;
      }
    }
    if (first_free >= kRecordSlots) return false;
    (void)found_any;
    out_slot = first_free;
    return true;
  }

  bool readSlot(uint32_t slot, Snapshot& out) const {
    if (slot >= kRecordSlots) return false;
    uint8_t record[192];
    const uint32_t offset = kMetadataSectorOffset + slot * kRecordBytes;
    if (!platform::isOk(region_.read(offset, record, sizeof(record)))) return false;
    if (getU32(record + 0) != kMagic) return false;
    if (getU16(record + 4) != kVersion) return false;
    if (getU16(record + 6) != kRecordBytes) return false;
    if (getU32(record + 188) != kCommitMarker) return false;
    if (Crc32::computeFinalized(record, 184) != getU32(record + 184)) return false;
    out = Snapshot();
    out.valid = true;
    out.sequence = getU32(record + 8);
    out.phase = static_cast<Phase>(record[12] & 0x7Fu);
    out.localCache = (record[12] & 0x80u) != 0;
    out.totalBlocks = getU16(record + 13);
    out.exactSizeBytes = getU32(record + 15);
    out.campaignId = getU32(record + 19);
    out.sessionId = getU32(record + 23);
    out.attemptId = getU16(record + 27);
    std::memcpy(out.canonical, record + 29, sizeof(out.canonical));
    std::memcpy(out.ownerPublicKey, record + 88, sizeof(out.ownerPublicKey));
    std::memcpy(out.signature, record + 120, sizeof(out.signature));
    return true;
  }

  platform::FlashRegion& region_;
};

}  // namespace storage
}  // namespace ota
