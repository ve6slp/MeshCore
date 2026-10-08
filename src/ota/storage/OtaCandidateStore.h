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
    // Fresh per-BEGIN attempt nonce (record v2). All-zero means a legacy
    // v1 record: still authoritative state, but never COMMIT-authorizable.
    uint8_t beginNonce[16] = {0};
    uint16_t receivedBlocks = 0;
  };

  // Found: newest committed slot decoded and its bitmap counted. A
  // CRC-valid body whose marker is incomplete (a torn marker program, or an
  // interrupted erase that moved only marker bits toward erased) counts only
  // when it revokes (Idle/Aborted/Failed): either reading then leaves less
  // authority, so a revoked READY/nonce can never be resurrected.
  // Empty: every slot is blank or a CRC-valid unmarked non-revoking body,
  // or reset() began (any exact tombstone; all other slots are superseded).
  // IoError: some slot/bitmap could not be read, or (without a tombstone) a
  // non-blank slot is not a CRC-valid supported body (see classifyRecord);
  // never fall back to an older slot.
  enum class LoadResult : uint8_t { Found = 0, Empty = 1, IoError = 2 };

  static constexpr uint32_t kMagic = 0x4F544341u;  // OTCA
  static constexpr uint16_t kVersion = 2u;
  static constexpr uint16_t kLegacyVersion = 1u;
  // v2 layout: 0..183 as v1, 184..199 beginNonce16, 200 CRC32(0..199),
  // 204 commit marker, 208..255 erased. v1: 184 CRC32(0..183), 188 marker.
  static constexpr uint32_t kNonceOffset = 184u;
  static constexpr uint32_t kCrcOffset = 200u;
  static constexpr uint32_t kMarkerOffset = 204u;
  static constexpr uint32_t kLegacyCrcOffset = 184u;
  static constexpr uint32_t kLegacyMarkerOffset = 188u;
  static constexpr uint32_t kDecodedBytes = kMarkerOffset + 4u;
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
    if (!tombstoneRecords() || !eraseMetadataSector() || !eraseBitmapSector()) return false;
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
    std::memcpy(record + kNonceOffset, snapshot.beginNonce, sizeof(snapshot.beginNonce));
    putU32(record + kCrcOffset, Crc32::computeFinalized(record, kCrcOffset));
    putU32(record + kMarkerOffset, kCommitMarker);

    const uint32_t slot_offset = kMetadataSectorOffset + slot * kRecordBytes;
    if (!platform::isOk(region_.program(slot_offset, record, kMarkerOffset))) return false;
    uint8_t verify[kMarkerOffset];
    if (!platform::isOk(region_.read(slot_offset, verify, kMarkerOffset))) return false;
    if (std::memcmp(record, verify, kMarkerOffset) != 0) return false;
    if (!platform::isOk(region_.program(slot_offset + kMarkerOffset, record + kMarkerOffset, 4))) return false;
    uint8_t marker[4];
    if (!platform::isOk(region_.read(slot_offset + kMarkerOffset, marker, 4))) return false;
    if (getU32(marker) != kCommitMarker) return false;
    return true;
  }

  LoadResult load(Snapshot& out) const {
    out = Snapshot();
    if (!isValid()) return LoadResult::IoError;
    bool found = false, best_marked = false, tombstone = false, unexplained = false;
    uint32_t best_sequence = 0;
    Snapshot best;
    for (uint32_t slot = 0; slot < kRecordSlots; ++slot) {
      Snapshot current;
      const auto state = readSlot(slot, current);
      if (state == SlotState::Unreadable) return LoadResult::IoError;
      if (state == SlotState::Unexplained) unexplained = true;
      if (state == SlotState::Tombstone) tombstone = true;
      if (state != SlotState::Valid && state != SlotState::TornRevocation) continue;
      const bool marked = state == SlotState::Valid;
      if (!found || current.sequence > best_sequence || (current.sequence == best_sequence && (marked || !best_marked))) {
        found = true;
        best_marked = marked;
        best_sequence = current.sequence;
        best = current;
      }
    }
    // Our own reset began: everything older is superseded, and other slots
    // are its partly tombstoned or partly erased bytes.
    if (tombstone) return LoadResult::Empty;
    if (unexplained) return LoadResult::IoError;
    if (!found) return LoadResult::Empty;
    if (!readReceivedCount(best.totalBlocks, best.receivedBlocks)) return LoadResult::IoError;
    out = best;
    return LoadResult::Found;
  }

  // Exact SYN-06 residue: the append wrote and verified a complete v2 body
  // (magic, version, CRC) but power failed before the commit marker, which
  // is still fully erased. Its manifest is returned only for caller-side
  // authentication; it never becomes candidate state.
  bool readPremarkerResidue(uint32_t slot, Snapshot& out) const {
    out = Snapshot();
    if (!isValid() || slot >= kRecordSlots) return false;
    uint8_t record[kDecodedBytes];
    if (!platform::isOk(region_.read(kMetadataSectorOffset + slot * kRecordBytes, record, sizeof(record)))) return false;
    if (getU32(record) != kMagic || getU16(record + 4) != kVersion || getU16(record + 6) != kRecordBytes ||
        getU32(record + kMarkerOffset) != 0xFFFFFFFFu ||
        Crc32::computeFinalized(record, kCrcOffset) != getU32(record + kCrcOffset)) return false;
    decode(record, out);
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
    uint16_t total = 0;
    return readReceivedCount(total_blocks, total) ? total : 0;
  }

  bool readReceivedCount(uint16_t total_blocks, uint16_t& total) const {
    total = 0;
    if (!isValid()) return false;
    if (total_blocks == 0) return true;
    const uint32_t bytes = (static_cast<uint32_t>(total_blocks) + 7u) / 8u;
    for (uint32_t i = 0; i < bytes; ++i) {
      uint8_t current = 0xFFu;
      if (!platform::isOk(region_.read(kBitmapSectorOffset + i, &current, 1))) { total = 0; return false; }
      for (uint8_t bit = 0; bit < 8u; ++bit) {
        const uint32_t block = i * 8u + bit;
        if (block >= total_blocks) break;
        if ((current & static_cast<uint8_t>(1u << bit)) == 0u) ++total;
      }
    }
    return true;
  }

  enum class RecordClass : uint8_t { Valid, Residue, Tombstone, Unexplained };

  // Classifies one slot's first kDecodedBytes. Residue is only a blank slot
  // or a supported, CRC-valid body whose marker is incomplete (a torn marker
  // program or marker-only erase damage; see load()). Any other non-blank
  // content (a bad CRC/header with any marker, including an erased one, a
  // marker with bits outside CAND, or an unsupported version) cannot be told
  // apart from damage to newer, possibly revoking state: callers must block,
  // never skip it and fall back to an older slot. A torn body program is
  // therefore unavailable until an authenticated USB recovery. Tombstone is
  // an exact all-zero slot written only by reset() (see tombstoneRecords()).
  static RecordClass classifyRecord(const uint8_t* record) {
    bool blank = true, zero = true;
    for (uint32_t i = 0; i < kDecodedBytes; ++i) {
      blank = blank && record[i] == 0xFFu;
      zero = zero && record[i] == 0u;
    }
    if (blank) return RecordClass::Residue;
    if (zero) return RecordClass::Tombstone;
    const uint16_t version = getU16(record + 4);
    const bool supported = getU32(record) == kMagic && getU16(record + 6) == kRecordBytes &&
                           (version == kVersion || version == kLegacyVersion);
    if (!supported) return RecordClass::Unexplained;
    const uint32_t marker_at = version == kLegacyVersion ? kLegacyMarkerOffset : kMarkerOffset;
    const uint32_t crc_at = version == kLegacyVersion ? kLegacyCrcOffset : kCrcOffset;
    const uint32_t marker = getU32(record + marker_at);
    if (Crc32::computeFinalized(record, crc_at) != getU32(record + crc_at)) return RecordClass::Unexplained;
    if (marker == kCommitMarker) return RecordClass::Valid;
    if ((marker & kCommitMarker) == kCommitMarker) return RecordClass::Residue;
    return RecordClass::Unexplained;
  }

private:
  enum class SlotState : uint8_t { Valid, TornRevocation, Ignored, Tombstone, Unexplained, Unreadable };

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

  // A NOR sector erase interrupted by power loss is unordered: it may blank
  // only the newest (e.g. ABORTED) slot while older READY slots survive. So
  // before erasing, reset() overwrites every non-blank slot with zeros and
  // verifies it (program only clears bits). An interrupted reset can then
  // leave only exact tombstones, blank slots, untouched records (a cut while
  // tombstoning) or partly programmed/erased bytes, never a revived older
  // record once the reset began: any exact tombstone makes load() report
  // Empty (the authenticated BEGIN that started the reset superseded every
  // slot). Without a tombstone, unexplained bytes stay IoError.
  bool tombstoneRecords() {
    static const uint8_t kZero[kDecodedBytes] = {};
    for (uint32_t slot = 0; slot < kRecordSlots; ++slot) {
      const uint32_t offset = kMetadataSectorOffset + slot * kRecordBytes;
      uint8_t record[kDecodedBytes];
      if (!platform::isOk(region_.read(offset, record, sizeof(record)))) return false;
      const auto kind = classifyRecord(record);
      if (kind == RecordClass::Tombstone) continue;
      if (kind == RecordClass::Residue && getU32(record) != kMagic) continue;  // blank
      if (!platform::isOk(region_.program(offset, kZero, sizeof(kZero))) ||
          !platform::isOk(region_.read(offset, record, sizeof(record))) ||
          std::memcmp(record, kZero, sizeof(kZero)) != 0) return false;
    }
    return true;
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
    uint32_t first_free = kRecordSlots;
    for (uint32_t slot = 0; slot < kRecordSlots; ++slot) {
      Snapshot current;
      const auto state = readSlot(slot, current);
      if (state == SlotState::Valid || state == SlotState::TornRevocation) {
        if (current.sequence >= out_previous_sequence) out_previous_sequence = current.sequence;
        continue;
      }
      if (state == SlotState::Unreadable || state == SlotState::Unexplained || state == SlotState::Tombstone)
        return false;
      uint8_t first4[4] = {0, 0, 0, 0};
      if (!platform::isOk(region_.read(kMetadataSectorOffset + slot * kRecordBytes, first4, 4))) return false;
      if (first_free == kRecordSlots &&
          first4[0] == 0xFFu && first4[1] == 0xFFu && first4[2] == 0xFFu && first4[3] == 0xFFu) {
        first_free = slot;
      }
    }
    if (first_free >= kRecordSlots) return false;
    out_slot = first_free;
    return true;
  }

  SlotState readSlot(uint32_t slot, Snapshot& out) const {
    if (slot >= kRecordSlots) return SlotState::Unreadable;
    uint8_t record[kDecodedBytes];
    const uint32_t offset = kMetadataSectorOffset + slot * kRecordBytes;
    if (!platform::isOk(region_.read(offset, record, sizeof(record)))) return SlotState::Unreadable;
    const auto kind = classifyRecord(record);
    if (kind == RecordClass::Unexplained) return SlotState::Unexplained;
    if (kind == RecordClass::Tombstone) return SlotState::Tombstone;
    const bool legacy = getU16(record + 4) == kLegacyVersion;
    if (kind == RecordClass::Residue) {
      // Blank, or a CRC-valid unmarked body: only a revocation phase counts.
      const uint8_t phase = record[12] & 0x7Fu;
      if (getU32(record) != kMagic ||
          (phase != static_cast<uint8_t>(Phase::Idle) && phase != static_cast<uint8_t>(Phase::Aborted) &&
           phase != static_cast<uint8_t>(Phase::Failed))) return SlotState::Ignored;
    }
    decode(record, out);
    if (legacy) std::memset(out.beginNonce, 0, sizeof(out.beginNonce));
    return kind == RecordClass::Valid ? SlotState::Valid : SlotState::TornRevocation;
  }

  static void decode(const uint8_t* record, Snapshot& out) {
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
    std::memcpy(out.beginNonce, record + kNonceOffset, sizeof(out.beginNonce));
  }

  platform::FlashRegion& region_;
};

}  // namespace storage
}  // namespace ota
