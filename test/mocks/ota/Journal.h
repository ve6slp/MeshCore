#pragma once

// Native model of a redundant journal for OTA campaign checkpoints (receipt map +
// install/backup progress + phase), stored in the small journal partition.
//
// Design summary:
//  - The journal region is divided into fixed-size slots, one per erase
//    sector, used as a round-robin append log. Each write targets the slot
//    after the current highest-valid one, erasing only that single slot.
//  - Every write follows write -> readback verify -> commit-marker ordering:
//    the header + zero-padded receipt payload are programmed first and
//    read back byte-for-byte to confirm they landed correctly, and only
//    then is a small, distinct 4-byte commit marker programmed as the very
//    last step. A record with a missing/incorrect marker is never treated
//    as valid, regardless of what its header/CRC say.
//  - Every record is bound to a `campaign_id` so a checkpoint from a
//    previous, unrelated update attempt can never be misapplied to a new
//    one.
//  - Recovery scans every slot, validates magic/CRCs/commit marker/campaign
//    independently per slot, and selects the valid record with the highest
//    monotonically increasing sequence number. Round-robin slot reuse means
//    older (superseded) records are naturally reclaimed over time -- this
//    doubles as the journal's "compaction" strategy, with no separate
//    compaction pass required.
//  - Because the previously-committed slot(s) are left completely
//    untouched until a NEW write has been fully verified, at least one
//    valid historical checkpoint always survives a torn write, an
//    interrupted erase, or arbitrary corruption of the slot currently being
//    written.
//
// This class is intentionally header-only (all methods defined inline)
// so it can be consumed directly by PlatformIO's native unit tests without
// requiring any change to the top-level build configuration.

#include <stdint.h>
#include <string.h>
#include "ota/platform/FlashRegion.h"
#include "ReceiptMap.h"
#include "ota/storage/Crc32.h"

namespace ota {
namespace storage {

struct JournalCheckpoint {
  uint32_t campaign_id = 0;
  uint32_t sequence = 0;
  uint8_t phase = 0;
  uint32_t chunk_count = 0;
  uint32_t backup_progress_bytes = 0;
  uint32_t install_progress_bytes = 0;
  uint32_t descriptor_monotonic_counter = 0;
  uint32_t target_image_intact = 0;
  uint32_t counter_commit_started = 0;
  ReceiptMap receipts;
};

class Journal {
public:
  static constexpr uint32_t kMagic = 0x4A4F5452u;         // "JOTR"
  static constexpr uint32_t kCommitMarker = 0xC011DA7Eu;
  static constexpr uint32_t kMaxReceiptBytes = ReceiptMap::kMaxBytes;
  static constexpr uint32_t kMaxChunkCount = ReceiptMap::kMaxChunks;
  // magic(4) + campaign_id(4) + sequence(4) + phase(1) + chunk_count(4) +
  // backup_progress_bytes(4) + install_progress_bytes(4) +
  // descriptor_monotonic_counter(4) + target_image_intact(4) +
  // counter_commit_started(4) + receipt_bytes_len(4) +
  // header_crc32(4) + payload_crc32(4) = 49 bytes.
  static constexpr uint32_t kHeaderBytes = 49u;
  static constexpr uint32_t kMarkerBytes = 4u;
  static constexpr uint32_t kSlotBytes = 4096u;             // must equal the journal region's erase unit
  static constexpr uint32_t kSlotUsedBytes = kHeaderBytes + kMaxReceiptBytes + kMarkerBytes;

  explicit Journal(platform::FlashRegion& region) : region_(region) {}

  // Validates that the supplied region is geometrically compatible with
  // this journal's fixed slot layout.
  bool isValid() const {
    if (!region_.isValid()) return false;
    if (region_.eraseUnitBytes() != kSlotBytes) return false;
    if (region_.sizeBytes() < (kSlotBytes * 2u)) return false;
    if ((region_.sizeBytes() % kSlotBytes) != 0) return false;
    if (kSlotUsedBytes > kSlotBytes) return false;
    return true;
  }

  uint32_t slotCount() const { return region_.sizeBytes() / kSlotBytes; }

  // Scans all slots and returns the newest valid, fully committed
  // checkpoint (optionally restricted to a specific campaign_id when
  // `filter_campaign_id` is non-null). Returns false if none is found.
  bool recoverLatest(JournalCheckpoint& out, const uint32_t* filter_campaign_id = nullptr) const {
    bool found_any = false;
    uint32_t best_sequence = 0;
    JournalCheckpoint best_checkpoint;

    const uint32_t slots = slotCount();
    for (uint32_t i = 0; i < slots; ++i) {
      ParsedSlot parsed;
      if (!readSlot(i, parsed) || !parsed.valid) {
        continue;
      }
      if (filter_campaign_id != nullptr && parsed.checkpoint.campaign_id != *filter_campaign_id) {
        continue;
      }
      if (!found_any || parsed.checkpoint.sequence >= best_sequence) {
        found_any = true;
        best_sequence = parsed.checkpoint.sequence;
        best_checkpoint = parsed.checkpoint;
      }
    }

    if (!found_any) {
      return false;
    }
    out = best_checkpoint;
    return true;
  }

  // Writes a new checkpoint, choosing the slot after the current
  // highest-valid one (round robin). Returns false (without corrupting any
  // previously valid slot) if any step -- erase, program, or readback
  // verification -- fails.
  bool writeCheckpoint(const JournalCheckpoint& checkpoint) {
    if (!isValid()) return false;
    if (checkpoint.chunk_count > kMaxChunkCount) return false;
    if (checkpoint.receipts.chunkCount() != checkpoint.chunk_count) return false;

    uint32_t current_slot = 0;
    JournalCheckpoint current_checkpoint;
    const bool has_current = findHighestValidSlot(current_slot, current_checkpoint);

    const uint32_t slots = slotCount();
    const uint32_t target_slot = has_current ? ((current_slot + 1u) % slots) : 0u;
    const uint32_t new_sequence = has_current ? (current_checkpoint.sequence + 1u) : 1u;

    JournalCheckpoint to_write = checkpoint;
    to_write.sequence = new_sequence;

    const uint32_t receipt_len = to_write.receipts.byteCount();
    if (receipt_len > kMaxReceiptBytes) return false;

    uint8_t buf[kSlotUsedBytes];
    memset(buf, 0, sizeof(buf));

    uint8_t payload[kMaxReceiptBytes];
    memset(payload, 0, sizeof(payload));
    if (to_write.receipts.data() != nullptr && receipt_len > 0) {
      memcpy(payload, to_write.receipts.data(), receipt_len);
    }
    const uint32_t payload_crc = Crc32::computeFinalized(payload, receipt_len);

    serializeHeader(buf, to_write, 0, payload_crc);
    const uint32_t real_header_crc = Crc32::computeFinalized(buf, kOffHeaderCrc);
    serializeHeader(buf, to_write, real_header_crc, payload_crc);

    memcpy(buf + kHeaderBytes, payload, kMaxReceiptBytes);
    // Marker area intentionally left as zero bytes (NOT the commit marker
    // value) for the initial program pass; it is programmed last,
    // separately, only after the header+payload readback verifies
    // successfully.
    memset(buf + kHeaderBytes + kMaxReceiptBytes, 0x00, kMarkerBytes);

    const uint32_t slot_offset = target_slot * kSlotBytes;

    if (!platform::isOk(region_.eraseSector(slot_offset))) return false;

    const uint32_t header_and_payload_len = kHeaderBytes + kMaxReceiptBytes;
    if (!platform::isOk(region_.program(slot_offset, buf, header_and_payload_len))) return false;

    // Readback verify before commit.
    uint8_t readback[kHeaderBytes + kMaxReceiptBytes];
    if (!platform::isOk(region_.read(slot_offset, readback, header_and_payload_len))) return false;
    if (memcmp(readback, buf, header_and_payload_len) != 0) return false;

    // Commit: program the marker as the final, distinct step.
    uint8_t marker_bytes[kMarkerBytes];
    putU32(marker_bytes, kCommitMarker);
    const uint32_t marker_offset = slot_offset + kHeaderBytes + kMaxReceiptBytes;
    if (!platform::isOk(region_.program(marker_offset, marker_bytes, kMarkerBytes))) return false;

    uint8_t marker_readback[kMarkerBytes];
    if (!platform::isOk(region_.read(marker_offset, marker_readback, kMarkerBytes))) return false;
    if (getU32(marker_readback) != kCommitMarker) return false;

    return true;
  }

  // Erases every slot, discarding all history. Used only for deliberate
  // "start a brand-new campaign" resets, never implicitly.
  bool eraseAll() {
    if (!isValid()) return false;
    const uint32_t slots = slotCount();
    for (uint32_t i = 0; i < slots; ++i) {
      if (!platform::isOk(region_.eraseSector(i * kSlotBytes))) return false;
    }
    return true;
  }

private:
  struct ParsedSlot {
    bool valid = false;
    JournalCheckpoint checkpoint;
  };

  static constexpr uint32_t kOffMagic = 0;
  static constexpr uint32_t kOffCampaign = 4;
  static constexpr uint32_t kOffSequence = 8;
  static constexpr uint32_t kOffPhase = 12;
  static constexpr uint32_t kOffChunkCount = 13;
  static constexpr uint32_t kOffBackupProgress = 17;
  static constexpr uint32_t kOffInstallProgress = 21;
  static constexpr uint32_t kOffDescriptorCounter = 25;
  static constexpr uint32_t kOffTargetImageIntact = 29;
  static constexpr uint32_t kOffCounterCommitStarted = 33;
  static constexpr uint32_t kOffReceiptLen = 37;
  static constexpr uint32_t kOffHeaderCrc = 41;
  static constexpr uint32_t kOffPayloadCrc = 45;

  static void putU32(uint8_t* out, uint32_t v) {
    out[0] = (uint8_t)(v & 0xFFu);
    out[1] = (uint8_t)((v >> 8) & 0xFFu);
    out[2] = (uint8_t)((v >> 16) & 0xFFu);
    out[3] = (uint8_t)((v >> 24) & 0xFFu);
  }

  static uint32_t getU32(const uint8_t* in) {
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
  }

  static void serializeHeader(uint8_t* out, const JournalCheckpoint& checkpoint, uint32_t header_crc32, uint32_t payload_crc32) {
    putU32(out + kOffMagic, kMagic);
    putU32(out + kOffCampaign, checkpoint.campaign_id);
    putU32(out + kOffSequence, checkpoint.sequence);
    out[kOffPhase] = checkpoint.phase;
    putU32(out + kOffChunkCount, checkpoint.chunk_count);
    putU32(out + kOffBackupProgress, checkpoint.backup_progress_bytes);
    putU32(out + kOffInstallProgress, checkpoint.install_progress_bytes);
    putU32(out + kOffDescriptorCounter, checkpoint.descriptor_monotonic_counter);
    putU32(out + kOffTargetImageIntact, checkpoint.target_image_intact);
    putU32(out + kOffCounterCommitStarted, checkpoint.counter_commit_started);
    putU32(out + kOffReceiptLen, checkpoint.receipts.byteCount());
    putU32(out + kOffHeaderCrc, header_crc32);
    putU32(out + kOffPayloadCrc, payload_crc32);
  }

  static bool parseHeader(const uint8_t* in, JournalCheckpoint& out, uint32_t& header_crc32_field, uint32_t& payload_crc32_field) {
    const uint32_t magic = getU32(in + kOffMagic);
    if (magic != kMagic) return false;

    out.campaign_id = getU32(in + kOffCampaign);
    out.sequence = getU32(in + kOffSequence);
    out.phase = in[kOffPhase];
    out.chunk_count = getU32(in + kOffChunkCount);
    out.backup_progress_bytes = getU32(in + kOffBackupProgress);
    out.install_progress_bytes = getU32(in + kOffInstallProgress);
    out.descriptor_monotonic_counter = getU32(in + kOffDescriptorCounter);
    out.target_image_intact = getU32(in + kOffTargetImageIntact);
    out.counter_commit_started = getU32(in + kOffCounterCommitStarted);
    const uint32_t receipt_len = getU32(in + kOffReceiptLen);
    header_crc32_field = getU32(in + kOffHeaderCrc);
    payload_crc32_field = getU32(in + kOffPayloadCrc);

    if (out.chunk_count > kMaxChunkCount) return false;
    if (receipt_len != ReceiptMap::byteCountFor(out.chunk_count) || receipt_len > kMaxReceiptBytes) return false;
    return true;
  }

  bool readSlot(uint32_t slot_index, ParsedSlot& out) const {
    out.valid = false;

    uint8_t buf[kSlotUsedBytes];
    const uint32_t slot_offset = slot_index * kSlotBytes;
    if (!platform::isOk(region_.read(slot_offset, buf, kSlotUsedBytes))) {
      return false;
    }

    uint32_t header_crc_field = 0;
    uint32_t payload_crc_field = 0;
    JournalCheckpoint parsed;
    if (!parseHeader(buf, parsed, header_crc_field, payload_crc_field)) {
      return false;
    }

    // header_crc32 covers everything in the header EXCEPT the two CRC
    // fields themselves (they cannot cover their own bytes).
    const uint32_t computed_header_crc = Crc32::computeFinalized(buf, kOffHeaderCrc);
    if (computed_header_crc != header_crc_field) {
      return false;
    }

    const uint8_t* payload = buf + kHeaderBytes;
    const uint32_t receipt_len = ReceiptMap::byteCountFor(parsed.chunk_count);
    const uint32_t computed_payload_crc = Crc32::computeFinalized(payload, receipt_len);
    if (computed_payload_crc != payload_crc_field) {
      return false;
    }

    const uint8_t* marker_bytes = buf + kHeaderBytes + kMaxReceiptBytes;
    const uint32_t marker = getU32(marker_bytes);
    if (marker != kCommitMarker) {
      return false;
    }

    if (!parsed.receipts.loadFrom(parsed.chunk_count, payload, receipt_len)) {
      return false;
    }

    out.checkpoint = parsed;
    out.valid = true;
    return true;
  }

  bool findHighestValidSlot(uint32_t& slot_index_out, JournalCheckpoint& checkpoint_out) const {
    bool found_any = false;
    uint32_t best_slot = 0;
    uint32_t best_sequence = 0;
    JournalCheckpoint best_checkpoint;

    const uint32_t slots = slotCount();
    for (uint32_t i = 0; i < slots; ++i) {
      ParsedSlot parsed;
      if (!readSlot(i, parsed) || !parsed.valid) {
        continue;
      }
      if (!found_any || parsed.checkpoint.sequence >= best_sequence) {
        found_any = true;
        best_sequence = parsed.checkpoint.sequence;
        best_slot = i;
        best_checkpoint = parsed.checkpoint;
      }
    }

    if (!found_any) {
      return false;
    }
    slot_index_out = best_slot;
    checkpoint_out = best_checkpoint;
    return true;
  }

  platform::FlashRegion& region_;
};

}  // namespace storage
}  // namespace ota
