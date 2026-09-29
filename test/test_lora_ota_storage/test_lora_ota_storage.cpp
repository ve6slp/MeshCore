// gtest suite for the OTA storage layer: SenseCAP QSPI layout validation,
// FlashRegion overflow-safety, the durable redundant Journal (including
// fault-injected torn writes/interrupted erase/corruption/round-robin
// "compaction"), ReceiptMap chunk-count exactness (>=5069 chunks), and
// StorageManager's verified chunked write/copy operations.

#include <gtest/gtest.h>
#include <stdint.h>
#include <vector>
#include <memory>
#include <cstring>

#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashRegion.h"
#include "ota/platform/FlashTypes.h"
#include "ota/platform/SenseCapQspiLayout.h"
#include "ota/storage/Crc32.h"
#include "ota/storage/ReceiptMap.h"
#include "ota/storage/Journal.h"
#include "ota/storage/StorageManager.h"

#include "FakeNorFlash.h"

using ota::platform::FlashRegion;
using ota::platform::FlashStatus;
using ota::platform::SenseCapQspiLayout;
using ota::storage::Crc32;
using ota::storage::Journal;
using ota::storage::JournalCheckpoint;
using ota::storage::ReceiptMap;
using ota::storage::StorageManager;
using ota::test::FakeNorFlash;

// -----------------------------------------------------------------------
// SenseCAP QSPI layout.
// -----------------------------------------------------------------------

TEST(SenseCapQspiLayoutTest, StaticLayoutIsValid) {
  EXPECT_TRUE(SenseCapQspiLayout::isValid());
}

TEST(SenseCapQspiLayoutTest, ExactRequiredRanges) {
  EXPECT_EQ(SenseCapQspiLayout::kCandidateOffset, 0x000000u);
  EXPECT_EQ(SenseCapQspiLayout::kCandidateOffset + SenseCapQspiLayout::kCandidateSize, 0x0C6000u);
  EXPECT_EQ(SenseCapQspiLayout::kBackupOffset, 0x0C6000u);
  EXPECT_EQ(SenseCapQspiLayout::kBackupOffset + SenseCapQspiLayout::kBackupSize, 0x18C000u);
  EXPECT_EQ(SenseCapQspiLayout::kJournalOffset, 0x18C000u);
  EXPECT_EQ(SenseCapQspiLayout::kJournalOffset + SenseCapQspiLayout::kJournalSize, 0x194000u);
  EXPECT_EQ(SenseCapQspiLayout::kFilesystemOffset, 0x194000u);
  EXPECT_EQ(SenseCapQspiLayout::kFilesystemOffset + SenseCapQspiLayout::kFilesystemSize, 0x200000u);
}

TEST(SenseCapQspiLayoutTest, RegionsAreValidOnRealSizedFakeDevice) {
  FakeNorFlash flash(SenseCapQspiLayout::kTotalBytes, SenseCapQspiLayout::kEraseUnitBytes);
  FlashRegion candidate = SenseCapQspiLayout::candidateRegion(flash);
  FlashRegion backup = SenseCapQspiLayout::backupRegion(flash);
  FlashRegion journal = SenseCapQspiLayout::journalRegion(flash);
  FlashRegion filesystem = SenseCapQspiLayout::filesystemRegion(flash);
  EXPECT_TRUE(candidate.isValid());
  EXPECT_TRUE(backup.isValid());
  EXPECT_TRUE(journal.isValid());
  EXPECT_TRUE(filesystem.isValid());
}

TEST(SenseCapQspiLayoutTest, OverlapDetectionCatchesIntroducedOverlap) {
  // Deliberately probe the overlap-detection helper itself (not the fixed
  // static layout) with a synthetic overlapping pair, to make sure it
  // actually catches real overlaps rather than trivially returning false.
  EXPECT_TRUE(SenseCapQspiLayout::rangesOverlap(0x1000, 0x2000, 0x2000, 0x1000));
  EXPECT_TRUE(SenseCapQspiLayout::rangesOverlap(0x1000, 0x2000, 0x0000, 0x1500));
  EXPECT_FALSE(SenseCapQspiLayout::rangesOverlap(0x1000, 0x1000, 0x2000, 0x1000));
  EXPECT_FALSE(SenseCapQspiLayout::rangesOverlap(0x1000, 0, 0x1000, 0x1000));
}

TEST(SenseCapQspiLayoutTest, FitsWithinRejectsOffsetPastLimitWithoutOverflow) {
  // offset > limit must be rejected without computing (limit - offset),
  // which would underflow/wrap for unsigned arithmetic.
  EXPECT_FALSE(SenseCapQspiLayout::fitsWithin(0xFFFFFFFFu, 1, 0x1000u));
  EXPECT_TRUE(SenseCapQspiLayout::fitsWithin(0x1000u, 0, 0x1000u));
}

// -----------------------------------------------------------------------
// FlashRegion overflow-safe bounds checking.
// -----------------------------------------------------------------------

TEST(FlashRegionTest, RejectsOutOfRangeReadNearUint32Max) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  ASSERT_TRUE(region.isValid());

  uint8_t buf[16];
  // region_offset itself is enormous; must be rejected via the
  // "region_offset > size_bytes_" check before any offset+len addition is
  // ever formed, so this can never wrap around to a small, in-bounds value.
  FlashStatus status = region.read(0xFFFFFFF0u, buf, 32);
  EXPECT_EQ(status, FlashStatus::OutOfRange);
}

TEST(FlashRegionTest, RejectsLenThatWouldOverflowIfAddedNaively) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  ASSERT_TRUE(region.isValid());

  uint8_t buf[16];
  // offset=100, len=0xFFFFFFFF -- offset+len overflows uint32_t if computed
  // directly; the region must still reject this as out of range rather than
  // wrapping into something that looks in-bounds.
  FlashStatus status = region.read(100, buf, 0xFFFFFFFFu);
  EXPECT_EQ(status, FlashStatus::OutOfRange);
}

TEST(FlashRegionTest, InvalidWhenBaseOffsetExceedsDevice) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0xFFFFF000u, 4096);
  EXPECT_FALSE(region.isValid());
}

TEST(FlashRegionTest, InvalidWhenUnaligned) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion misaligned_offset(flash, 100, 4096);
  EXPECT_FALSE(misaligned_offset.isValid());
  FlashRegion misaligned_size(flash, 0, 100);
  EXPECT_FALSE(misaligned_size.isValid());
}

TEST(FlashRegionTest, ProgramEnforcesOneToZeroOnlyViaUnderlyingDevice) {
  FakeNorFlash flash(4096, 4096);
  FlashRegion region(flash, 0, 4096);
  ASSERT_TRUE(region.isValid());

  uint8_t first[4] = {0xF0, 0xF0, 0xF0, 0xF0};
  ASSERT_TRUE(ota::platform::isOk(region.program(0, first, 4)));

  uint8_t second[4] = {0xFF, 0xFF, 0xFF, 0xFF};  // would require 0->1 on some bits
  FlashStatus status = region.program(0, second, 4);
  EXPECT_EQ(status, FlashStatus::PartialProgramViolation);
}

// -----------------------------------------------------------------------
// ReceiptMap exactness, including the required >=5069 chunk count.
// -----------------------------------------------------------------------

TEST(ReceiptMapTest, SupportsAtLeast5069Chunks) {
  const uint32_t kChunks = 5069;
  ReceiptMap map(kChunks);
  EXPECT_EQ(map.chunkCount(), kChunks);
  EXPECT_EQ(map.byteCount(), (kChunks + 7u) / 8u);

  EXPECT_FALSE(map.allReceived());
  for (uint32_t i = 0; i < kChunks; ++i) {
    EXPECT_TRUE(map.markReceived(i));
  }
  EXPECT_TRUE(map.allReceived());
  EXPECT_EQ(map.countReceived(), kChunks);

  // Out-of-range index must be rejected, not silently wrap into a valid one.
  EXPECT_FALSE(map.markReceived(kChunks));
  EXPECT_FALSE(map.isReceived(kChunks));
}

TEST(ReceiptMapTest, PartialReceiptIsNotAllReceived) {
  const uint32_t kChunks = 5069;
  ReceiptMap map(kChunks);
  for (uint32_t i = 0; i < kChunks - 1; ++i) {
    map.markReceived(i);
  }
  EXPECT_FALSE(map.allReceived());
  EXPECT_EQ(map.countReceived(), kChunks - 1);
  map.markReceived(kChunks - 1);
  EXPECT_TRUE(map.allReceived());
}

TEST(ReceiptMapTest, ClearReceivedUnmarksBit) {
  ReceiptMap map(16);
  map.markReceived(3);
  EXPECT_TRUE(map.isReceived(3));
  map.clearReceived(3);
  EXPECT_FALSE(map.isReceived(3));
}

TEST(ReceiptMapTest, LoadFromRoundTrips) {
  ReceiptMap original(5069);
  for (uint32_t i = 0; i < 5069; i += 3) {
    original.markReceived(i);
  }
  ReceiptMap loaded;
  ASSERT_TRUE(loaded.loadFrom(5069, original.data(), original.byteCount()));
  for (uint32_t i = 0; i < 5069; ++i) {
    EXPECT_EQ(loaded.isReceived(i), original.isReceived(i)) << "chunk " << i;
  }
}

// -----------------------------------------------------------------------
// Journal: normal recovery, torn writes, interrupted erase, corruption,
// round-robin "compaction", and campaign binding.
// -----------------------------------------------------------------------

namespace {

JournalCheckpoint makeCheckpoint(uint32_t campaign_id, uint8_t phase, uint32_t chunk_count, uint32_t marked_up_to) {
  JournalCheckpoint cp;
  cp.campaign_id = campaign_id;
  cp.phase = phase;
  cp.chunk_count = chunk_count;
  cp.backup_progress_bytes = 1000;
  cp.install_progress_bytes = 0;
  cp.receipts = ReceiptMap(chunk_count);
  for (uint32_t i = 0; i < marked_up_to && i < chunk_count; ++i) {
    cp.receipts.markReceived(i);
  }
  return cp;
}

class JournalFixture : public ::testing::Test {
protected:
  void SetUp() override {
    flash_.reset(new FakeNorFlash(Journal::kSlotBytes * 4, Journal::kSlotBytes));
    region_.reset(new FlashRegion(*flash_, 0, Journal::kSlotBytes * 4));
    journal_.reset(new Journal(*region_));
    ASSERT_TRUE(journal_->isValid());
  }

  std::unique_ptr<FakeNorFlash> flash_;
  std::unique_ptr<FlashRegion> region_;
  std::unique_ptr<Journal> journal_;
};

}  // namespace

TEST_F(JournalFixture, RecoverLatestFailsOnEmptyJournal) {
  JournalCheckpoint out;
  EXPECT_FALSE(journal_->recoverLatest(out));
}

TEST(JournalTest, RejectsSingleSlotJournalBecauseItCannotSurviveTornReplacement) {
  FakeNorFlash flash(Journal::kSlotBytes, Journal::kSlotBytes);
  FlashRegion region(flash, 0, Journal::kSlotBytes);
  Journal journal(region);
  EXPECT_FALSE(journal.isValid());
  EXPECT_FALSE(journal.writeCheckpoint(makeCheckpoint(1, 1, 0, 0)));
}

TEST_F(JournalFixture, WriteThenRecoverRoundTrips) {
  JournalCheckpoint cp = makeCheckpoint(/*campaign_id=*/42, /*phase=*/3, /*chunk_count=*/100, /*marked_up_to=*/57);
  ASSERT_TRUE(journal_->writeCheckpoint(cp));

  JournalCheckpoint recovered;
  ASSERT_TRUE(journal_->recoverLatest(recovered));
  EXPECT_EQ(recovered.campaign_id, 42u);
  EXPECT_EQ(recovered.phase, 3);
  EXPECT_EQ(recovered.chunk_count, 100u);
  EXPECT_EQ(recovered.sequence, 1u);
  EXPECT_EQ(recovered.receipts.countReceived(), 57u);
  for (uint32_t i = 0; i < 100; ++i) {
    EXPECT_EQ(recovered.receipts.isReceived(i), i < 57);
  }
}

TEST_F(JournalFixture, SequentialWritesRoundRobinAcrossSlots) {
  const uint32_t slots = journal_->slotCount();
  ASSERT_EQ(slots, 4u);

  for (uint32_t n = 0; n < 10; ++n) {
    JournalCheckpoint cp = makeCheckpoint(7, (uint8_t)n, 64, n);
    ASSERT_TRUE(journal_->writeCheckpoint(cp));
    JournalCheckpoint recovered;
    ASSERT_TRUE(journal_->recoverLatest(recovered));
    EXPECT_EQ(recovered.sequence, n + 1);
    EXPECT_EQ(recovered.phase, n);
  }
}

TEST_F(JournalFixture, CampaignFilterExcludesOtherCampaigns) {
  ASSERT_TRUE(journal_->writeCheckpoint(makeCheckpoint(1, 0, 32, 10)));
  ASSERT_TRUE(journal_->writeCheckpoint(makeCheckpoint(2, 0, 32, 20)));

  JournalCheckpoint recovered;
  uint32_t campaign_one = 1;
  ASSERT_TRUE(journal_->recoverLatest(recovered, &campaign_one));
  EXPECT_EQ(recovered.campaign_id, 1u);
  EXPECT_EQ(recovered.receipts.countReceived(), 10u);

  uint32_t campaign_three = 3;
  EXPECT_FALSE(journal_->recoverLatest(recovered, &campaign_three));
}

TEST_F(JournalFixture, InterruptedEraseLeavesPreviousCheckpointRecoverable) {
  ASSERT_TRUE(journal_->writeCheckpoint(makeCheckpoint(9, 1, 64, 5)));  // slot 0

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Erase;
  fault.timing = FakeNorFlash::InjectionTiming::Mid;
  fault.trigger_op_count = flash_->eraseOpCount() + 1;  // the NEXT erase (slot 1)
  fault.partial_bytes = 100;
  flash_->armFault(fault);

  // The second write's erase is interrupted -- writeCheckpoint must report
  // failure, not silently succeed with a half-erased slot.
  EXPECT_FALSE(journal_->writeCheckpoint(makeCheckpoint(9, 2, 64, 6)));

  // The FIRST checkpoint must still be the one recovered.
  JournalCheckpoint recovered;
  ASSERT_TRUE(journal_->recoverLatest(recovered));
  EXPECT_EQ(recovered.phase, 1);
  EXPECT_EQ(recovered.receipts.countReceived(), 5u);
}

TEST_F(JournalFixture, TornWriteMidProgramLeavesPreviousCheckpointRecoverable) {
  ASSERT_TRUE(journal_->writeCheckpoint(makeCheckpoint(9, 1, 64, 5)));  // slot 0, sequence 1

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Program;
  fault.timing = FakeNorFlash::InjectionTiming::Mid;
  fault.trigger_op_count = flash_->programOpCount() + 1;  // the next program() call (header+payload of slot 1)
  fault.partial_bytes = 10;                               // only 10 bytes of the header actually land
  flash_->armFault(fault);

  EXPECT_FALSE(journal_->writeCheckpoint(makeCheckpoint(9, 2, 64, 6)));

  JournalCheckpoint recovered;
  ASSERT_TRUE(journal_->recoverLatest(recovered));
  EXPECT_EQ(recovered.sequence, 1u);
  EXPECT_EQ(recovered.phase, 1);
}

TEST_F(JournalFixture, TornWriteAtCommitMarkerLeavesPreviousCheckpointRecoverable) {
  ASSERT_TRUE(journal_->writeCheckpoint(makeCheckpoint(9, 1, 64, 5)));  // slot 0, sequence 1

  // Fault the SECOND program() call of the second writeCheckpoint (the
  // marker program), after the header+payload program already succeeded.
  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Program;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash_->programOpCount() + 2;  // 1st program = header+payload, 2nd = marker
  flash_->armFault(fault);

  EXPECT_FALSE(journal_->writeCheckpoint(makeCheckpoint(9, 2, 64, 6)));

  // Slot 1 has valid header+payload+CRC but NO commit marker -- it must be
  // treated as entirely invalid, and slot 0 (sequence 1) must still win.
  JournalCheckpoint recovered;
  ASSERT_TRUE(journal_->recoverLatest(recovered));
  EXPECT_EQ(recovered.sequence, 1u);
}

TEST_F(JournalFixture, CorruptedSlotBytesAreRejectedByCrc) {
  ASSERT_TRUE(journal_->writeCheckpoint(makeCheckpoint(9, 1, 64, 5)));   // slot 0
  ASSERT_TRUE(journal_->writeCheckpoint(makeCheckpoint(9, 2, 64, 6)));   // slot 1, newest

  // Directly corrupt a payload byte in slot 1 on the underlying medium,
  // bypassing the Journal API entirely (simulates e.g. a bit-flip from a
  // radiation event or a partially-failed erase/program cycle that the
  // fake's own fault injection didn't already model).
  std::vector<uint8_t> raw(flash_->rawBuffer(), flash_->rawBuffer() + flash_->rawSize());
  const uint32_t slot1_offset = Journal::kSlotBytes;
  const uint32_t payload_byte_offset = slot1_offset + Journal::kHeaderBytes + 4;
  // Flip a bit directly via a fresh erase+program cycle so the physical
  // 1->0-only constraint is respected: erase the sector, then reprogram it
  // with everything the same except the flipped payload byte.
  std::vector<uint8_t> sector(raw.begin() + slot1_offset, raw.begin() + slot1_offset + Journal::kSlotBytes);
  sector[Journal::kHeaderBytes + 4] ^= 0xFFu;  // guaranteed to differ, whatever the original bit pattern
  ASSERT_TRUE(ota::platform::isOk(flash_->eraseSector(slot1_offset)));
  ASSERT_TRUE(ota::platform::isOk(flash_->program(slot1_offset, sector.data(), (uint32_t)sector.size())));

  // Slot 1 is now corrupt (payload CRC mismatch) -- recovery must fall back
  // to slot 0.
  JournalCheckpoint recovered;
  ASSERT_TRUE(journal_->recoverLatest(recovered));
  EXPECT_EQ(recovered.phase, 1);
  EXPECT_EQ(recovered.sequence, 1u);
}

TEST_F(JournalFixture, RoundRobinReclaimsOldestSlotActingAsCompaction) {
  const uint32_t slots = journal_->slotCount();
  // Write more checkpoints than there are slots; the oldest slots get
  // reused (this doubles as the journal's compaction strategy).
  for (uint32_t n = 0; n < slots * 3; ++n) {
    ASSERT_TRUE(journal_->writeCheckpoint(makeCheckpoint(5, (uint8_t)(n % 250), 64, n % 64)));
  }
  JournalCheckpoint recovered;
  ASSERT_TRUE(journal_->recoverLatest(recovered));
  EXPECT_EQ(recovered.sequence, slots * 3);
  // Round-robin reuse means only the most recent `slots` sequence numbers
  // can possibly still be present; the oldest ones were physically erased
  // and reprogrammed over multiple full cycles, which is what makes this
  // journal never need a separate compaction pass.
  EXPECT_EQ(recovered.phase, (uint8_t)((slots * 3 - 1) % 250));
}

TEST_F(JournalFixture, RejectsChunkCountAboveCapacity) {
  JournalCheckpoint cp = makeCheckpoint(1, 0, Journal::kMaxChunkCount + 1, 0);
  EXPECT_FALSE(journal_->writeCheckpoint(cp));
}

TEST_F(JournalFixture, SupportsAtLeast5069ChunksEndToEnd) {
  JournalCheckpoint cp = makeCheckpoint(1, 5, 5069, 5069);
  ASSERT_TRUE(journal_->writeCheckpoint(cp));

  JournalCheckpoint recovered;
  ASSERT_TRUE(journal_->recoverLatest(recovered));
  EXPECT_EQ(recovered.chunk_count, 5069u);
  EXPECT_TRUE(recovered.receipts.allReceived());
}

TEST_F(JournalFixture, EraseAllDiscardsAllHistory) {
  ASSERT_TRUE(journal_->writeCheckpoint(makeCheckpoint(1, 0, 32, 32)));
  ASSERT_TRUE(journal_->eraseAll());
  JournalCheckpoint recovered;
  EXPECT_FALSE(journal_->recoverLatest(recovered));
}

// -----------------------------------------------------------------------
// StorageManager: chunked write/verify, resumable copy, fault injection.
// -----------------------------------------------------------------------

TEST(StorageManagerTest, WriteAndVerifyChunkRoundTrips) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  ASSERT_TRUE(StorageManager::erasePartition(region));

  uint8_t data[64];
  for (int i = 0; i < 64; ++i) data[i] = (uint8_t)i;
  ASSERT_TRUE(StorageManager::writeAndVerifyChunk(region, 3, 64, data, 64));

  uint8_t readback[64];
  ASSERT_TRUE(StorageManager::readChunk(region, 3, 64, readback, 64));
  EXPECT_EQ(0, std::memcmp(data, readback, 64));
}

TEST(StorageManagerTest, WriteAndVerifyChunkDetectsTornProgram) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  ASSERT_TRUE(StorageManager::erasePartition(region));

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Program;
  fault.timing = FakeNorFlash::InjectionTiming::Mid;
  fault.trigger_op_count = 1;
  fault.partial_bytes = 10;
  flash.armFault(fault);

  uint8_t data[64];
  for (int i = 0; i < 64; ++i) data[i] = (uint8_t)(0xA0 + i);
  EXPECT_FALSE(StorageManager::writeAndVerifyChunk(region, 0, 64, data, 64));
}

TEST(StorageManagerTest, ChunkIndexOverflowIsRejected) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  uint8_t data[4] = {1, 2, 3, 4};
  // chunk_index * chunk_size_bytes would overflow uint32_t here.
  EXPECT_FALSE(StorageManager::writeAndVerifyChunk(region, 0xFFFFFFFFu, 64, data, 4));
}

TEST(StorageManagerTest, CopyRangeVerifiedRoundTrips) {
  FakeNorFlash src_flash(8192, 4096);
  FakeNorFlash dst_flash(8192, 4096);
  FlashRegion src(src_flash, 0, 8192);
  FlashRegion dst(dst_flash, 0, 8192);
  ASSERT_TRUE(StorageManager::erasePartition(src));
  ASSERT_TRUE(StorageManager::erasePartition(dst));

  std::vector<uint8_t> pattern(4000);
  for (size_t i = 0; i < pattern.size(); ++i) pattern[i] = (uint8_t)(i * 7);
  ASSERT_TRUE(ota::platform::isOk(src.program(0, pattern.data(), (uint32_t)pattern.size())));

  uint32_t progress = 0;
  ASSERT_TRUE(StorageManager::copyRangeVerified(src, dst, (uint32_t)pattern.size(), 0, progress));
  EXPECT_EQ(progress, pattern.size());
  EXPECT_TRUE(StorageManager::regionsEqual(src, dst, (uint32_t)pattern.size()));
}

TEST(StorageManagerTest, CopyRangeVerifiedStopsAtFirstFailureAndIsResumable) {
  FakeNorFlash src_flash(8192, 4096);
  FakeNorFlash dst_flash(8192, 4096);
  FlashRegion src(src_flash, 0, 8192);
  FlashRegion dst(dst_flash, 0, 8192);
  ASSERT_TRUE(StorageManager::erasePartition(src));
  ASSERT_TRUE(StorageManager::erasePartition(dst));

  std::vector<uint8_t> pattern(2000);
  for (size_t i = 0; i < pattern.size(); ++i) pattern[i] = (uint8_t)(i + 3);
  ASSERT_TRUE(ota::platform::isOk(src.program(0, pattern.data(), (uint32_t)pattern.size())));

  // Interrupt the destination's first program() call.
  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Program;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = 1;
  dst_flash.armFault(fault);

  uint32_t progress = 0;
  EXPECT_FALSE(StorageManager::copyRangeVerified(src, dst, (uint32_t)pattern.size(), 0, progress));

  // Clear the fault and resume from wherever progress stopped (0, since the
  // very first chunk failed) -- must complete successfully now.
  dst_flash.clearFault();
  uint32_t resumed_progress = 0;
  EXPECT_TRUE(StorageManager::copyRangeVerified(src, dst, (uint32_t)pattern.size(), 0, resumed_progress));
  EXPECT_EQ(resumed_progress, pattern.size());
  EXPECT_TRUE(StorageManager::regionsEqual(src, dst, (uint32_t)pattern.size()));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
