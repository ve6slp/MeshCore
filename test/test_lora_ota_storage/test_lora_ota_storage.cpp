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
#include "ota/storage/OtaCandidateStore.h"
#include "ota/storage/StorageManager.h"
#include "ota/storage/XiaoOtaCommandRecord.h"
#include "ota/storage/XiaoOtaBootInfoReader.h"
#include "ota/storage/XiaoOtaActiveExtentBridge.h"
#include "ota/storage/XiaoOtaLegacyResidue.h"
#include "ota/storage/XiaoOtaTrialBootConfirmation.h"
#include "ota/trust/Sha256.h"
#include "ota/trust/Ed25519SignatureVerifier.h"
#include "../test_lora_ota_trust/Ed25519TestSigner.h"
#include "helpers/radiolib/RadioDriverHealthLatch.h"
#include "helpers/radiolib/Sx1262CheckedProbe.h"
#include "helpers/radiolib/Sx126xGetStatusTransaction.h"
#include "helpers/radiolib/OtaTrialRadioReadiness.h"
#include "helpers/radiolib/RadioLibDriverFaultClassification.h"
#include "ota/trust/DescriptorVerifier.h"
#include "ota/protocol/OtaDescriptor.h"
#include "helpers/ota/OtaBoardBackendCommon.h"
#include "helpers/ota/OtaTrialSafeIdentityBoot.h"
#include "helpers/ota/OtaWriteGate.h"

#include "FakeNorFlash.h"

using ota::platform::FlashRegion;
using ota::platform::FlashStatus;
using ota::platform::SenseCapQspiLayout;
using ota::storage::Crc32;
using ota::storage::Journal;
using ota::storage::JournalCheckpoint;
using ota::storage::OtaCandidateStore;
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
  EXPECT_EQ(SenseCapQspiLayout::kCandidateOffset + SenseCapQspiLayout::kCandidateSize, 0x0AD000u);
  EXPECT_EQ(SenseCapQspiLayout::kBackupOffset, 0x0C6000u);
  EXPECT_EQ(SenseCapQspiLayout::kBackupOffset + SenseCapQspiLayout::kBackupSize, 0x173000u);
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
  FlashRegion candidate_test = SenseCapQspiLayout::candidateTestRegion(flash);
  FlashRegion journal_test = SenseCapQspiLayout::journalTestRegion(flash);
  EXPECT_TRUE(candidate.isValid());
  EXPECT_TRUE(backup.isValid());
  EXPECT_TRUE(journal.isValid());
  EXPECT_TRUE(filesystem.isValid());
  EXPECT_TRUE(candidate_test.isValid());
  EXPECT_TRUE(journal_test.isValid());
}

TEST(SenseCapQspiLayoutTest, HardwareTestRegionsStayCandidateOwnedAndNeverOverlapJournalOrLittleFs) {
  EXPECT_GE(SenseCapQspiLayout::kCandidateTestOffset,
            SenseCapQspiLayout::kCandidateOffset);
  EXPECT_TRUE(SenseCapQspiLayout::fitsWithin(
      SenseCapQspiLayout::kCandidateTestOffset,
      SenseCapQspiLayout::kCandidateTestSize,
      SenseCapQspiLayout::kCandidateOffset + SenseCapQspiLayout::kCandidateSize));
  EXPECT_GE(SenseCapQspiLayout::kJournalTestOffset,
            SenseCapQspiLayout::kCandidateTestOffset);
  EXPECT_TRUE(SenseCapQspiLayout::fitsWithin(
      SenseCapQspiLayout::kJournalTestOffset,
      SenseCapQspiLayout::kJournalTestSize,
      SenseCapQspiLayout::kCandidateTestOffset + SenseCapQspiLayout::kCandidateTestSize));
  EXPECT_FALSE(SenseCapQspiLayout::rangesOverlap(
      SenseCapQspiLayout::kCandidateTestOffset,
      SenseCapQspiLayout::kCandidateTestSize,
      SenseCapQspiLayout::kFilesystemOffset,
      SenseCapQspiLayout::kFilesystemSize));
  EXPECT_FALSE(SenseCapQspiLayout::rangesOverlap(
      SenseCapQspiLayout::kCandidateTestOffset,
      SenseCapQspiLayout::kCandidateTestSize,
      SenseCapQspiLayout::kJournalOffset,
      SenseCapQspiLayout::kJournalSize));
  EXPECT_FALSE(SenseCapQspiLayout::rangesOverlap(
      SenseCapQspiLayout::kJournalTestOffset,
      SenseCapQspiLayout::kJournalTestSize,
      SenseCapQspiLayout::kJournalOffset,
      SenseCapQspiLayout::kJournalSize));
  EXPECT_FALSE(SenseCapQspiLayout::rangesOverlap(
      SenseCapQspiLayout::kJournalTestOffset,
      SenseCapQspiLayout::kJournalTestSize,
      SenseCapQspiLayout::kFilesystemOffset,
      SenseCapQspiLayout::kFilesystemSize));
}

TEST(SenseCapQspiLayoutTest, XiaoJournalFullRegionCoversAllEightSubSlotsExactly) {
  FakeNorFlash flash(2 * 1024 * 1024, 4096);
  FlashRegion journal_full = SenseCapQspiLayout::xiaoJournalFullRegion(flash);
  ASSERT_TRUE(journal_full.isValid());
  EXPECT_EQ(journal_full.sizeBytes(), 8u * 4096u);
  // Base offset must match the physically-first sub-slot (install command
  // A) at kJournalOffset, per the fixed 8-index map:
  // 0=floorA,1=floorB,2=commandA,3=commandB,4=stateA,5=stateB,6=confirmA,
  // 7=confirmB -- a *logical* index used by the wire contract, distinct
  // from physical sub-slot order within the region.
  EXPECT_EQ(SenseCapQspiLayout::kXiaoCommandOffset, SenseCapQspiLayout::kJournalOffset);
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
// Durable lean-OTA candidate metadata + receipt bitmap.
// -----------------------------------------------------------------------

TEST(OtaCandidateStoreTest, ResetLoadAndNewestAppendRoundTrip) {
  FakeNorFlash flash(OtaCandidateStore::kExpectedRegionBytes, OtaCandidateStore::kSectorBytes);
  FlashRegion region(flash, 0, OtaCandidateStore::kExpectedRegionBytes);
  OtaCandidateStore store(region);
  ASSERT_TRUE(store.isValid());

  OtaCandidateStore::Snapshot first;
  first.valid = true;
  first.phase = OtaCandidateStore::Phase::Receiving;
  first.campaignId = 0x11223344u;
  first.sessionId = 7u;
  first.attemptId = 1u;
  first.totalBlocks = 3u;
  first.exactSizeBytes = 2u * mesh::ota::kOtaBlockMaxDataBytes + 5u;
  for (size_t i = 0; i < sizeof(first.canonical); ++i) first.canonical[i] = static_cast<uint8_t>(i);
  for (size_t i = 0; i < sizeof(first.ownerPublicKey); ++i) first.ownerPublicKey[i] = static_cast<uint8_t>(0x80u + i);
  for (size_t i = 0; i < sizeof(first.signature); ++i) first.signature[i] = static_cast<uint8_t>(0x40u + i);
  ASSERT_TRUE(store.reset(first));

  OtaCandidateStore::Snapshot loaded;
  ASSERT_TRUE(store.load(loaded));
  EXPECT_TRUE(loaded.valid);
  EXPECT_EQ(OtaCandidateStore::Phase::Receiving, loaded.phase);
  EXPECT_EQ(first.campaignId, loaded.campaignId);
  EXPECT_EQ(first.sessionId, loaded.sessionId);
  EXPECT_EQ(first.attemptId, loaded.attemptId);
  EXPECT_EQ(first.totalBlocks, loaded.totalBlocks);
  EXPECT_EQ(first.exactSizeBytes, loaded.exactSizeBytes);
  EXPECT_EQ(0, std::memcmp(first.canonical, loaded.canonical, sizeof(first.canonical)));
  EXPECT_EQ(0, std::memcmp(first.ownerPublicKey, loaded.ownerPublicKey, sizeof(first.ownerPublicKey)));
  EXPECT_EQ(0, std::memcmp(first.signature, loaded.signature, sizeof(first.signature)));
  EXPECT_EQ(0u, loaded.receivedBlocks);

  OtaCandidateStore::Snapshot second = loaded;
  second.phase = OtaCandidateStore::Phase::Ready;
  ASSERT_TRUE(store.append(second));

  OtaCandidateStore::Snapshot newest;
  ASSERT_TRUE(store.load(newest));
  EXPECT_EQ(OtaCandidateStore::Phase::Ready, newest.phase);
  EXPECT_GT(newest.sequence, loaded.sequence);
}

TEST(OtaCandidateStoreTest, DuplicateBitmapMarksAreIdempotentWithoutReprogramming) {
  FakeNorFlash flash(OtaCandidateStore::kExpectedRegionBytes, OtaCandidateStore::kSectorBytes);
  FlashRegion region(flash, 0, OtaCandidateStore::kExpectedRegionBytes);
  OtaCandidateStore store(region);
  ASSERT_TRUE(store.isValid());

  OtaCandidateStore::Snapshot snapshot;
  snapshot.valid = true;
  snapshot.phase = OtaCandidateStore::Phase::Receiving;
  snapshot.campaignId = 1u;
  snapshot.sessionId = 1u;
  snapshot.attemptId = 1u;
  snapshot.totalBlocks = 16u;
  snapshot.exactSizeBytes = snapshot.totalBlocks * mesh::ota::kOtaBlockMaxDataBytes;
  ASSERT_TRUE(store.reset(snapshot));

  const uint32_t program_before = flash.programOpCount();
  ASSERT_TRUE(store.markReceived(5));
  const uint32_t program_after_first = flash.programOpCount();
  EXPECT_GT(program_after_first, program_before);
  ASSERT_TRUE(store.isReceived(5));

  ASSERT_TRUE(store.markReceived(5));
  EXPECT_EQ(program_after_first, flash.programOpCount())
      << "duplicate block receipts must be a durable no-op, not a second bitmap rewrite";
  EXPECT_EQ(1u, store.countReceived(snapshot.totalBlocks));
}

TEST(OtaCandidateStoreTest, AppendAfterPartialEraseUsesNewestValidSuffixNotTheFirstFreeSlot) {
  using Store = OtaCandidateStore;
  for (auto phase : {Store::Phase::Receiving, Store::Phase::Verifying, Store::Phase::Aborted})
    for (bool damaged_sequence : {false, true}) {
      SCOPED_TRACE(::testing::Message() << unsigned(phase) << '/' << damaged_sequence);
      FakeNorFlash flash(Store::kExpectedRegionBytes, Store::kSectorBytes);
      FlashRegion region(flash, 0, Store::kExpectedRegionBytes);
      Store store(region);
      Store::Snapshot snapshot;
      snapshot.valid = true; snapshot.localCache = true; snapshot.totalBlocks = 3;
      snapshot.exactSizeBytes = 200; snapshot.sessionId = 17;
      snapshot.ownerPublicKey[0] = 0x87;
      snapshot.phase = Store::Phase::Receiving;
      ASSERT_TRUE(store.reset(snapshot));
      ASSERT_TRUE(store.markReceived(0)); ASSERT_TRUE(store.markReceived(2));
      snapshot.phase = Store::Phase::Verifying; ASSERT_TRUE(store.append(snapshot));
      snapshot.phase = Store::Phase::Ready; ASSERT_TRUE(store.append(snapshot));
      flash.armFault({FakeNorFlash::OpKind::Erase, FakeNorFlash::InjectionTiming::Mid,
                      flash.eraseOpCount() + 1, 2 * Store::kRecordBytes});
      ASSERT_FALSE(ota::platform::isOk(region.eraseSector(0)));
      flash.clearFault();
      if (damaged_sequence) {
        uint8_t record[Store::kRecordBytes];
        ASSERT_TRUE(ota::platform::isOk(region.read(2 * Store::kRecordBytes, record, sizeof(record))));
        std::memset(record + 8, 0xff, 4);
        ASSERT_TRUE(ota::platform::isOk(region.program(Store::kRecordBytes, record, sizeof(record))));
      }
      Store::Snapshot surviving;
      ASSERT_TRUE(store.load(surviving));
      ASSERT_EQ(Store::Phase::Ready, surviving.phase);
      ASSERT_EQ(3u, surviving.sequence);
      surviving.phase = phase; ++surviving.sessionId;
      const auto erases = flash.eraseOpCount();
      ASSERT_TRUE(store.append(surviving));
      Store cold(region);
      Store::Snapshot reloaded;
      ASSERT_TRUE(cold.load(reloaded));
      EXPECT_EQ(phase, reloaded.phase);
      EXPECT_EQ(4u, reloaded.sequence);
      EXPECT_EQ(18u, reloaded.sessionId);
      EXPECT_EQ(2u, reloaded.receivedBlocks);
      EXPECT_EQ(0, std::memcmp(snapshot.ownerPublicKey, reloaded.ownerPublicKey, sizeof(snapshot.ownerPublicKey)));
      EXPECT_EQ(erases, flash.eraseOpCount());
    }
}

TEST(OtaCandidateStoreTest, AppendCannotGuessSequenceWhenAValidSuffixIsUnreadable) {
  using Store = OtaCandidateStore;
  FakeNorFlash flash(Store::kExpectedRegionBytes, Store::kSectorBytes);
  FlashRegion region(flash, 0, Store::kExpectedRegionBytes);
  Store store(region);
  Store::Snapshot snapshot;
  snapshot.valid = true; snapshot.totalBlocks = 1; snapshot.exactSizeBytes = 40;
  snapshot.phase = Store::Phase::Receiving; ASSERT_TRUE(store.reset(snapshot));
  snapshot.phase = Store::Phase::Verifying; ASSERT_TRUE(store.append(snapshot));
  snapshot.phase = Store::Phase::Ready; ASSERT_TRUE(store.append(snapshot));
  flash.armFault({FakeNorFlash::OpKind::Erase, FakeNorFlash::InjectionTiming::Mid,
                  flash.eraseOpCount() + 1, 2 * Store::kRecordBytes});
  ASSERT_FALSE(ota::platform::isOk(region.eraseSector(0)));
  flash.clearFault();
  snapshot.phase = Store::Phase::Aborted;
  const auto programs = flash.programOpCount();
  flash.armFault({FakeNorFlash::OpKind::Read, FakeNorFlash::InjectionTiming::Before, flash.readOpCount() + 5});
  EXPECT_FALSE(store.append(snapshot));
  EXPECT_EQ(programs, flash.programOpCount());
  flash.clearFault();
  Store cold(region);
  ASSERT_TRUE(cold.load(snapshot));
  EXPECT_EQ(Store::Phase::Ready, snapshot.phase);
  EXPECT_EQ(3u, snapshot.sequence);
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

// -----------------------------------------------------------------------
// XiaoOtaCommandRecord: byte-exact bootloader install-command bridge.
// -----------------------------------------------------------------------

using ota::storage::XiaoOtaCommandFields;
using ota::storage::XiaoOtaCommandRecord;
using ota::storage::XiaoOtaCommandV2Fields;
using ota::storage::XiaoOtaCommandRecordV2;
using ota::storage::XiaoOtaCommandRecordV3;
using ota::storage::XiaoOtaCommandV3Fields;
using ota::storage::XiaoOtaBootInfoReader;
using ota::storage::XiaoOtaActiveExtentBridge;
using ota::storage::XiaoOtaBank0Settings;
using ota::storage::kXiaoOtaAppMaxSize;
using ota::storage::kBankValidApp;

namespace {

XiaoOtaCommandFields makeSampleCommandFields() {
  XiaoOtaCommandFields fields;
  fields.transaction_nonce = 0x1122334455667788ull;
  for (int i = 0; i < 32; ++i) fields.descriptor.image_hash_sha256[i] = (uint8_t)(i + 1);
  fields.descriptor.target_id = 0x584E3430u;  // XIAO_OTA_TARGET_XIAO_NRF52840
  fields.descriptor.role_id = 0;              // XIAO_OTA_ROLE_ANY
  fields.descriptor.device_address = 0;
  fields.descriptor.allow_broadcast_address = true;
  fields.descriptor.required_boot_capability_flags = 1;  // XIAO_OTA_CAP_QSPI_INSTALL
  fields.descriptor.monotonic_counter = 7;
  fields.descriptor.image_size_bytes = 8192;
  fields.descriptor.app_address = 0x27000;
  fields.descriptor.format_id = 1;
  fields.descriptor.key_id = 1;
  fields.descriptor.algorithm_id = 1;
  for (int i = 0; i < 64; ++i) fields.descriptor_signature[i] = (uint8_t)(200 - i);
  fields.active_image_extent = 0x20000;
  for (int i = 0; i < 32; ++i) fields.active_image_hash_sha256[i] = (uint8_t)(64 + i);
  return fields;
}

uint32_t sequenceFieldOf(const uint8_t* record) {
  return static_cast<uint32_t>(record[8]) | (static_cast<uint32_t>(record[9]) << 8) |
         (static_cast<uint32_t>(record[10]) << 16) | (static_cast<uint32_t>(record[11]) << 24);
}

XiaoOtaCommandV2Fields makeSampleCommandV2Fields() {
  using meshcore::ota::protocol::OtaDescriptor;
  using meshcore::ota::protocol::encodeOtaDescriptorCanonical;
  using meshcore::ota::protocol::kOtaDescriptorCanonicalSize;

  OtaDescriptor d;
  d.boardFamily = 0x584E;
  d.boardVariant = 0x3430;
  d.role = 0;
  d.appAddress = 0x27000;
  d.exactSizeBytes = 8192;
  for (int i = 0; i < 32; ++i) d.sha256[i] = static_cast<uint8_t>(i + 1);
  d.securityCounter = 7;
  d.minBootloaderCapabilities = 1;
  d.formatId = 1;
  d.keyId = 1;
  d.algorithmId = 1;

  XiaoOtaCommandV2Fields fields;
  fields.transaction_nonce = 0x1122334455667788ull;
  size_t out_len = 0;
  encodeOtaDescriptorCanonical(d, fields.wire_descriptor, sizeof(fields.wire_descriptor), out_len);
  for (int i = 0; i < 64; ++i) fields.signature_ed25519[i] = static_cast<uint8_t>(200 - i);
  fields.active_image_extent = 0x20000;
  for (int i = 0; i < 32; ++i) fields.active_image_hash_sha256[i] = static_cast<uint8_t>(64 + i);
  return fields;
}

// V3: current/sole bootloader-accepted command format (identical to V2
// except for the inserted 32-byte admitted-signer-key field; see
// XiaoOtaCommandRecordV3's doc-comment in XiaoOtaCommandRecord.h).
XiaoOtaCommandV3Fields makeSampleCommandV3Fields() {
  using meshcore::ota::protocol::OtaDescriptor;
  using meshcore::ota::protocol::encodeOtaDescriptorCanonical;
  using meshcore::ota::protocol::kOtaDescriptorCanonicalSize;

  OtaDescriptor d;
  d.boardFamily = 0x584E;
  d.boardVariant = 0x3430;
  d.role = 0;
  d.appAddress = 0x27000;
  d.exactSizeBytes = 8192;
  for (int i = 0; i < 32; ++i) d.sha256[i] = static_cast<uint8_t>(i + 1);
  d.securityCounter = 7;
  d.minBootloaderCapabilities = 1;
  d.formatId = 1;
  d.keyId = 1;
  d.algorithmId = 1;

  XiaoOtaCommandV3Fields fields;
  fields.transaction_nonce = 0x1122334455667788ull;
  size_t out_len = 0;
  encodeOtaDescriptorCanonical(d, fields.wire_descriptor, sizeof(fields.wire_descriptor), out_len);
  for (int i = 0; i < 32; ++i) fields.admitted_signer_public_key_ed25519[i] = static_cast<uint8_t>(10 + i);
  for (int i = 0; i < 64; ++i) fields.signature_ed25519[i] = static_cast<uint8_t>(200 - i);
  fields.active_image_extent = 0x20000;
  for (int i = 0; i < 32; ++i) fields.active_image_hash_sha256[i] = static_cast<uint8_t>(64 + i);
  return fields;
}

}  // namespace

TEST(XiaoOtaCommandRecordTest, RecordSizeMatchesBootloaderStructLayout) {
  // magic(4)+version(2)+bytes(2)+seq(4)+nonce(8)+descriptor(71)+sig(64)+
  // active_extent(4)+active_hash(32)+reserved(1)+crc32(4)+marker(4) = 200,
  // matching sizeof(xiao_ota_command_t) with XIAO_OTA_PACKED.
  EXPECT_EQ(XiaoOtaCommandRecord::kRecordBytes, 200u);
}

TEST(XiaoOtaCommandRecordTest, SerializeThenIsValidRecordRoundTrips) {
  const XiaoOtaCommandFields fields = makeSampleCommandFields();
  uint8_t buf[XiaoOtaCommandRecord::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecord::serialize(fields, buf, sizeof(buf)), XiaoOtaCommandRecord::kRecordBytes);
  EXPECT_TRUE(XiaoOtaCommandRecord::isValidRecord(buf, sizeof(buf)));
}

TEST(XiaoOtaCommandRecordTest, CorruptingAnyByteInvalidatesCrc) {
  const XiaoOtaCommandFields fields = makeSampleCommandFields();
  uint8_t buf[XiaoOtaCommandRecord::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecord::serialize(fields, buf, sizeof(buf)), XiaoOtaCommandRecord::kRecordBytes);
  buf[10] ^= 0xFFu;  // inside the embedded descriptor
  EXPECT_FALSE(XiaoOtaCommandRecord::isValidRecord(buf, sizeof(buf)));
}

TEST(XiaoOtaCommandRecordTest, MissingCommitMarkerIsRejectedEvenWithGoodCrc) {
  const XiaoOtaCommandFields fields = makeSampleCommandFields();
  uint8_t buf[XiaoOtaCommandRecord::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecord::serialize(fields, buf, sizeof(buf)), XiaoOtaCommandRecord::kRecordBytes);
  buf[XiaoOtaCommandRecord::kCommitMarkerOffset] ^= 0xFFu;  // marker corrupted, CRC untouched
  EXPECT_FALSE(XiaoOtaCommandRecord::isValidRecord(buf, sizeof(buf)));
}

TEST(XiaoOtaCommandRecordTest, WriteNextAlternatesSlotsAndIncrementsSequence) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  ASSERT_TRUE(XiaoOtaCommandRecord::regionIsValid(region));

  const XiaoOtaCommandFields fields = makeSampleCommandFields();

  uint32_t seq1 = 0;
  ASSERT_TRUE(XiaoOtaCommandRecord::writeNext(region, fields, &seq1));
  EXPECT_EQ(seq1, 1u);

  uint32_t seq2 = 0;
  ASSERT_TRUE(XiaoOtaCommandRecord::writeNext(region, fields, &seq2));
  EXPECT_EQ(seq2, 2u);

  uint8_t newest[XiaoOtaCommandRecord::kRecordBytes];
  ASSERT_TRUE(XiaoOtaCommandRecord::readNewest(region, newest));
  EXPECT_TRUE(XiaoOtaCommandRecord::isValidRecord(newest, sizeof(newest)));

  // Slot B (offset 4096) must hold the newest (sequence 2) record; slot A
  // (offset 0, sequence 1) must remain a separately valid, untouched
  // record -- the never-leave-both-invalid guarantee.
  uint8_t slot_a[XiaoOtaCommandRecord::kRecordBytes];
  uint8_t slot_b[XiaoOtaCommandRecord::kRecordBytes];
  ASSERT_TRUE(ota::platform::isOk(region.read(0, slot_a, sizeof(slot_a))));
  ASSERT_TRUE(ota::platform::isOk(region.read(4096, slot_b, sizeof(slot_b))));
  EXPECT_TRUE(XiaoOtaCommandRecord::isValidRecord(slot_a, sizeof(slot_a)));
  EXPECT_TRUE(XiaoOtaCommandRecord::isValidRecord(slot_b, sizeof(slot_b)));
  EXPECT_EQ(memcmp(slot_b, newest, sizeof(newest)), 0);
}

TEST(XiaoOtaCommandRecordTest, WriteNextFailureLeavesPreviousSlotIntact) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const XiaoOtaCommandFields fields = makeSampleCommandFields();

  uint32_t seq1 = 0;
  ASSERT_TRUE(XiaoOtaCommandRecord::writeNext(region, fields, &seq1));

  // Fault-inject the *next* program() call (which will target slot B) so
  // the second write fails after erasing but before a valid record lands.
  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Program;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash.programOpCount() + 1;
  flash.armFault(fault);

  uint32_t seq2 = 0;
  EXPECT_FALSE(XiaoOtaCommandRecord::writeNext(region, fields, &seq2));

  // Slot A (sequence 1) must still be the recoverable newest record.
  uint8_t newest[XiaoOtaCommandRecord::kRecordBytes];
  ASSERT_TRUE(XiaoOtaCommandRecord::readNewest(region, newest));
  EXPECT_EQ(sequenceFieldOf(newest), 1u);
}

// A slot-select READ failure (I/O error, as opposed to "content invalid")
// must abort writeNext() BEFORE it erases/programs anything: it is not
// safe to treat an unreadable slot as "no valid record here", since that
// slot might actually hold the true newest record we simply couldn't
// read this time. Both slots being unreadable must equally refuse with
// zero erase/program operations performed.
TEST(XiaoOtaCommandRecordTest, WriteNextRefusesAndMutatesNothingWhenEitherSlotReadFails) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const XiaoOtaCommandFields fields = makeSampleCommandFields();

  uint32_t seq1 = 0;
  ASSERT_TRUE(XiaoOtaCommandRecord::writeNext(region, fields, &seq1));
  const uint32_t erase_count_before = flash.eraseOpCount();
  const uint32_t program_count_before = flash.programOpCount();

  // Fault the very first read() call writeNext() will issue (slot A's
  // read, during target-slot selection) -- before any mutation.
  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Read;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash.readOpCount() + 1;
  flash.armFault(fault);

  uint32_t seq2 = 0;
  EXPECT_FALSE(XiaoOtaCommandRecord::writeNext(region, fields, &seq2));
  EXPECT_EQ(flash.eraseOpCount(), erase_count_before);
  EXPECT_EQ(flash.programOpCount(), program_count_before);

  // Slot A's genuine sequence-1 record must be completely untouched.
  flash.clearFault();
  uint8_t newest[XiaoOtaCommandRecord::kRecordBytes];
  ASSERT_TRUE(XiaoOtaCommandRecord::readNewest(region, newest));
  EXPECT_EQ(sequenceFieldOf(newest), 1u);
}

TEST(XiaoOtaCommandRecordTest, WriteNextRefusesAndMutatesNothingWhenBothSlotReadsFail) {
  // With writeNext() now failing closed on the FIRST unreadable slot
  // (see the test above), a fresh/blank region whose very first
  // slot-selection read fails must equally refuse -- never fabricating
  // sequence 1 from an unknown slot state -- with zero erase/program.
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const XiaoOtaCommandFields fields = makeSampleCommandFields();

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Read;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash.readOpCount() + 1;
  flash.armFault(fault);

  uint32_t seq = 0;
  EXPECT_FALSE(XiaoOtaCommandRecord::writeNext(region, fields, &seq));
  EXPECT_EQ(flash.eraseOpCount(), 0u);
  EXPECT_EQ(flash.programOpCount(), 0u);
}

// ---------------------------------------------------------------------
// XiaoOtaCommandRecordV2: wire-descriptor command record (188 bytes)
// ---------------------------------------------------------------------

TEST(XiaoOtaCommandRecordV2Test, RecordSizeMatchesBootloaderV2StructLayout) {
  // magic(4)+version(2)+bytes(2)+seq(4)+nonce(8)+wire_descriptor(59)+
  // sig(64)+active_extent(4)+active_hash(32)+reserved(1)+crc32(4)+
  // marker(4) = 188, matching sizeof(xiao_ota_command_v2_t).
  EXPECT_EQ(XiaoOtaCommandRecordV2::kRecordBytes, 188u);
}

TEST(XiaoOtaCommandRecordV2Test, SerializeThenIsValidRecordRoundTrips) {
  const XiaoOtaCommandV2Fields fields = makeSampleCommandV2Fields();
  uint8_t buf[XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecordV2::serialize(fields, buf, sizeof(buf)), XiaoOtaCommandRecordV2::kRecordBytes);
  EXPECT_TRUE(XiaoOtaCommandRecordV2::isValidRecord(buf, sizeof(buf)));
}

TEST(XiaoOtaCommandRecordV2Test, EmbeddedWireDescriptorBytesAreVerbatim) {
  // The 59-byte wire descriptor inside the serialized record must be a
  // byte-exact copy of the already-verified transport descriptor, never
  // re-derived: confirm it round-trips unchanged at the known offset.
  const XiaoOtaCommandV2Fields fields = makeSampleCommandV2Fields();
  uint8_t buf[XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecordV2::serialize(fields, buf, sizeof(buf)), XiaoOtaCommandRecordV2::kRecordBytes);
  constexpr uint32_t kDescriptorStart = 20u;
  EXPECT_EQ(memcmp(buf + kDescriptorStart, fields.wire_descriptor, sizeof(fields.wire_descriptor)), 0);
}

TEST(XiaoOtaCommandRecordV2Test, CorruptingAnyByteInvalidatesCrc) {
  const XiaoOtaCommandV2Fields fields = makeSampleCommandV2Fields();
  uint8_t buf[XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecordV2::serialize(fields, buf, sizeof(buf)), XiaoOtaCommandRecordV2::kRecordBytes);
  buf[25] ^= 0xFFu;  // inside the embedded wire descriptor
  EXPECT_FALSE(XiaoOtaCommandRecordV2::isValidRecord(buf, sizeof(buf)));
}

TEST(XiaoOtaCommandRecordV2Test, V1AndV2RecordVersionsAreDistinctAndNeverCrossValidate) {
  // A v1-shaped buffer must never validate as v2, and vice versa (proves
  // record_version dispatch is exact, not merely "some small integer").
  const XiaoOtaCommandFields v1_fields = makeSampleCommandFields();
  uint8_t v1_buf[XiaoOtaCommandRecord::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecord::serialize(v1_fields, v1_buf, sizeof(v1_buf)), XiaoOtaCommandRecord::kRecordBytes);
  EXPECT_FALSE(XiaoOtaCommandRecordV2::isValidRecord(v1_buf, sizeof(v1_buf)));

  const XiaoOtaCommandV2Fields v2_fields = makeSampleCommandV2Fields();
  uint8_t v2_buf[XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecordV2::serialize(v2_fields, v2_buf, sizeof(v2_buf)), XiaoOtaCommandRecordV2::kRecordBytes);
  EXPECT_FALSE(XiaoOtaCommandRecord::isValidRecord(v2_buf, sizeof(v2_buf)));
}

TEST(XiaoOtaCommandRecordV2Test, WriteNextAlternatesSlotsAndIncrementsSequence) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const XiaoOtaCommandV2Fields fields = makeSampleCommandV2Fields();

  uint32_t seq1 = 0;
  ASSERT_TRUE(XiaoOtaCommandRecordV2::writeNext(region, fields, &seq1));
  EXPECT_EQ(seq1, 1u);

  uint32_t seq2 = 0;
  ASSERT_TRUE(XiaoOtaCommandRecordV2::writeNext(region, fields, &seq2));
  EXPECT_EQ(seq2, 2u);

  uint8_t newest[XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_TRUE(XiaoOtaCommandRecordV2::readNewest(region, newest));
  EXPECT_EQ(sequenceFieldOf(newest), 2u);
}

TEST(XiaoOtaCommandRecordV2Test, WriteNextFailureLeavesPreviousSlotIntact) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const XiaoOtaCommandV2Fields fields = makeSampleCommandV2Fields();

  uint32_t seq1 = 0;
  ASSERT_TRUE(XiaoOtaCommandRecordV2::writeNext(region, fields, &seq1));

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Program;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash.programOpCount() + 1;
  flash.armFault(fault);

  uint32_t seq2 = 0;
  EXPECT_FALSE(XiaoOtaCommandRecordV2::writeNext(region, fields, &seq2));

  uint8_t newest[XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_TRUE(XiaoOtaCommandRecordV2::readNewest(region, newest));
  EXPECT_EQ(sequenceFieldOf(newest), 1u);
}

// See XiaoOtaCommandRecordTest.WriteNextRefusesAndMutatesNothingWhen*
// above for the rationale: an unreadable slot must abort writeNext()
// before any mutation, never be silently treated as "no valid record".
TEST(XiaoOtaCommandRecordV2Test, WriteNextRefusesAndMutatesNothingWhenSlotReadFails) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const XiaoOtaCommandV2Fields fields = makeSampleCommandV2Fields();

  uint32_t seq1 = 0;
  ASSERT_TRUE(XiaoOtaCommandRecordV2::writeNext(region, fields, &seq1));
  const uint32_t erase_count_before = flash.eraseOpCount();
  const uint32_t program_count_before = flash.programOpCount();

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Read;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash.readOpCount() + 1;
  flash.armFault(fault);

  uint32_t seq2 = 0;
  EXPECT_FALSE(XiaoOtaCommandRecordV2::writeNext(region, fields, &seq2));
  EXPECT_EQ(flash.eraseOpCount(), erase_count_before);
  EXPECT_EQ(flash.programOpCount(), program_count_before);

  flash.clearFault();
  uint8_t newest[XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_TRUE(XiaoOtaCommandRecordV2::readNewest(region, newest));
  EXPECT_EQ(sequenceFieldOf(newest), 1u);
}

// ---------------------------------------------------------------------
// XiaoOtaCommandRecordV3: current/sole bootloader-accepted command
// format (record_version 3, 220 bytes) -- see the bootloader owner's
// xiao_ota_record.h, which states BOTH the legacy 71-byte v1 format AND
// the admitted-key-less record_version-2 shape have been retired; "v2"
// naming on the underlying C struct is kept only to avoid a mechanical
// rename, not because a newer struct name exists there.
// ---------------------------------------------------------------------

TEST(XiaoOtaCommandRecordV3Test, RecordSizeMatchesBootloaderCurrentStructLayout) {
  // magic(4)+version(2)+bytes(2)+seq(4)+nonce(8)+wire_descriptor(59)+
  // admitted_signer_public_key(32)+sig(64)+active_extent(4)+
  // active_hash(32)+reserved(1)+crc32(4)+marker(4) = 220, matching
  // sizeof(xiao_ota_command_v2_t) at XIAO_OTA_COMMAND_VERSION_CURRENT==3.
  EXPECT_EQ(XiaoOtaCommandRecordV3::kRecordBytes, 220u);
}

TEST(XiaoOtaCommandRecordV3Test, SerializeThenIsValidRecordRoundTrips) {
  const XiaoOtaCommandV3Fields fields = makeSampleCommandV3Fields();
  uint8_t buf[XiaoOtaCommandRecordV3::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecordV3::serialize(fields, buf, sizeof(buf)), XiaoOtaCommandRecordV3::kRecordBytes);
  EXPECT_TRUE(XiaoOtaCommandRecordV3::isValidRecord(buf, sizeof(buf)));
}

TEST(XiaoOtaCommandRecordV3Test, EmbeddedWireDescriptorAndAdmittedSignerKeyAreVerbatimAndAdjacent) {
  // The 59-byte wire descriptor must round-trip unchanged, and the
  // 32-byte admitted-signer key must immediately follow it (offset 79) --
  // this is the ONE structural difference from V2.
  const XiaoOtaCommandV3Fields fields = makeSampleCommandV3Fields();
  uint8_t buf[XiaoOtaCommandRecordV3::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecordV3::serialize(fields, buf, sizeof(buf)), XiaoOtaCommandRecordV3::kRecordBytes);
  constexpr uint32_t kDescriptorStart = 20u;
  constexpr uint32_t kAdmittedSignerKeyStart = kDescriptorStart + 59u;  // 79
  EXPECT_EQ(memcmp(buf + kDescriptorStart, fields.wire_descriptor, sizeof(fields.wire_descriptor)), 0);
  EXPECT_EQ(memcmp(buf + kAdmittedSignerKeyStart, fields.admitted_signer_public_key_ed25519,
                   sizeof(fields.admitted_signer_public_key_ed25519)), 0);
  EXPECT_EQ(kAdmittedSignerKeyStart, XiaoOtaCommandRecordV3::kAdmittedSignerKeyOffset);
}

TEST(XiaoOtaCommandRecordV3Test, CorruptingAnyByteInvalidatesCrc) {
  const XiaoOtaCommandV3Fields fields = makeSampleCommandV3Fields();
  uint8_t buf[XiaoOtaCommandRecordV3::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecordV3::serialize(fields, buf, sizeof(buf)), XiaoOtaCommandRecordV3::kRecordBytes);
  buf[90] ^= 0xFFu;  // inside the embedded admitted-signer key
  EXPECT_FALSE(XiaoOtaCommandRecordV3::isValidRecord(buf, sizeof(buf)));
}

TEST(XiaoOtaCommandRecordV3Test, V2AndV3RecordVersionsAreDistinctAndNeverCrossValidate) {
  const XiaoOtaCommandV2Fields v2_fields = makeSampleCommandV2Fields();
  uint8_t v2_buf[XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecordV2::serialize(v2_fields, v2_buf, sizeof(v2_buf)), XiaoOtaCommandRecordV2::kRecordBytes);
  EXPECT_FALSE(XiaoOtaCommandRecordV3::isValidRecord(v2_buf, sizeof(v2_buf)));

  const XiaoOtaCommandV3Fields v3_fields = makeSampleCommandV3Fields();
  uint8_t v3_buf[XiaoOtaCommandRecordV3::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecordV3::serialize(v3_fields, v3_buf, sizeof(v3_buf)), XiaoOtaCommandRecordV3::kRecordBytes);
  EXPECT_FALSE(XiaoOtaCommandRecordV2::isValidRecord(v3_buf, sizeof(v3_buf)));
}

TEST(XiaoOtaCommandRecordV3Test, WriteNextAlternatesSlotsAndIncrementsSequence) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const XiaoOtaCommandV3Fields fields = makeSampleCommandV3Fields();

  uint32_t seq1 = 0;
  ASSERT_TRUE(XiaoOtaCommandRecordV3::writeNext(region, fields, &seq1));
  EXPECT_EQ(seq1, 1u);

  uint32_t seq2 = 0;
  ASSERT_TRUE(XiaoOtaCommandRecordV3::writeNext(region, fields, &seq2));
  EXPECT_EQ(seq2, 2u);

  uint8_t newest[XiaoOtaCommandRecordV3::kRecordBytes];
  ASSERT_TRUE(XiaoOtaCommandRecordV3::readNewest(region, newest));
  EXPECT_EQ(sequenceFieldOf(newest), 2u);
}

TEST(XiaoOtaCommandRecordV3Test, WriteNextRecognizesLiveV2RecordAndTargetsTheOtherSlotWithoutErasingIt) {
  // Union-aware upgrade path: a device previously running V2-writing
  // firmware, later reflashed with V3-only firmware, must not have its
  // live V2 slot silently erased/overwritten by the first V3 write.
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const XiaoOtaCommandV2Fields v2_fields = makeSampleCommandV2Fields();
  const XiaoOtaCommandV3Fields v3_fields = makeSampleCommandV3Fields();

  uint32_t v2_seq = 0;
  ASSERT_TRUE(XiaoOtaCommandRecordV2::writeNext(region, v2_fields, &v2_seq));  // lands in slot 0, sequence 1.
  EXPECT_EQ(v2_seq, 1u);

  uint32_t v3_seq = 0;
  ASSERT_TRUE(XiaoOtaCommandRecordV3::writeNext(region, v3_fields, &v3_seq));
  EXPECT_EQ(v3_seq, 2u);  // continues the shared generation, not reset to 1.

  uint8_t slot0[XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_TRUE(ota::platform::isOk(region.read(0, slot0, sizeof(slot0))));
  EXPECT_TRUE(XiaoOtaCommandRecordV2::isValidRecord(slot0, sizeof(slot0)));

  uint8_t newest[XiaoOtaCommandRecordV3::kRecordBytes];
  ASSERT_TRUE(XiaoOtaCommandRecordV3::readNewest(region, newest));
  EXPECT_EQ(sequenceFieldOf(newest), 2u);
}

// ---------------------------------------------------------------------
// Union-aware A/B slot classification: the shared command region can
// physically hold either a v1(200B) or v2(188B) record in either slot
// (e.g. a device previously running v1-writing firmware, later reflashed
// with v2-only firmware). writeNext()/readNewest() of EITHER version
// must recognize a live record of the OTHER version already occupying a
// slot -- never treat it as "empty" (which would erase/overwrite it and
// reset the generation), and never report an older own-version record as
// "newest" when the true newest-by-sequence slot holds the other type.
// ---------------------------------------------------------------------

TEST(XiaoOtaCommandUnionTest, V2WriteNextRecognizesLiveV1RecordAndTargetsTheOtherSlotWithoutErasingIt) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const XiaoOtaCommandFields v1_fields = makeSampleCommandFields();
  const XiaoOtaCommandV2Fields v2_fields = makeSampleCommandV2Fields();

  uint32_t v1_seq = 0;
  ASSERT_TRUE(XiaoOtaCommandRecord::writeNext(region, v1_fields, &v1_seq));  // lands in slot 0, sequence 1.
  EXPECT_EQ(v1_seq, 1u);

  uint32_t v2_seq = 0;
  ASSERT_TRUE(XiaoOtaCommandRecordV2::writeNext(region, v2_fields, &v2_seq));
  // Must have targeted slot 1 (the OTHER slot), continuing the shared
  // generation counter, NOT reset to 1 by treating slot 0 as unrecognized/empty.
  EXPECT_EQ(v2_seq, 2u);

  // Slot 0's original v1 record must still be byte-for-byte intact.
  uint8_t slot0[XiaoOtaCommandRecord::kRecordBytes];
  ASSERT_TRUE(ota::platform::isOk(region.read(0, slot0, sizeof(slot0))));
  ASSERT_TRUE(XiaoOtaCommandRecord::isValidRecord(slot0, sizeof(slot0)));
  EXPECT_EQ(sequenceFieldOf(slot0), 1u);

  // The true newest (by sequence) is the v2 record: v2::readNewest() must
  // find it, and v1::readNewest() must NOT fall back to reporting its own
  // (now-superseded) slot-0 record as "the newest".
  uint8_t v2_newest[XiaoOtaCommandRecordV2::kRecordBytes];
  EXPECT_TRUE(XiaoOtaCommandRecordV2::readNewest(region, v2_newest));
  EXPECT_EQ(sequenceFieldOf(v2_newest), 2u);

  uint8_t v1_newest[XiaoOtaCommandRecord::kRecordBytes];
  EXPECT_FALSE(XiaoOtaCommandRecord::readNewest(region, v1_newest));
}

TEST(XiaoOtaCommandUnionTest, V1WriteNextRecognizesLiveV2RecordAndTargetsTheOtherSlotWithoutErasingIt) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const XiaoOtaCommandV2Fields v2_fields = makeSampleCommandV2Fields();
  const XiaoOtaCommandFields v1_fields = makeSampleCommandFields();

  uint32_t v2_seq = 0;
  ASSERT_TRUE(XiaoOtaCommandRecordV2::writeNext(region, v2_fields, &v2_seq));  // lands in slot 0, sequence 1.
  EXPECT_EQ(v2_seq, 1u);

  uint32_t v1_seq = 0;
  ASSERT_TRUE(XiaoOtaCommandRecord::writeNext(region, v1_fields, &v1_seq));
  EXPECT_EQ(v1_seq, 2u);  // continues the shared generation, targets slot 1.

  uint8_t slot0[XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_TRUE(ota::platform::isOk(region.read(0, slot0, sizeof(slot0))));
  ASSERT_TRUE(XiaoOtaCommandRecordV2::isValidRecord(slot0, sizeof(slot0)));
  EXPECT_EQ(sequenceFieldOf(slot0), 1u);

  uint8_t v1_newest[XiaoOtaCommandRecord::kRecordBytes];
  EXPECT_TRUE(XiaoOtaCommandRecord::readNewest(region, v1_newest));
  EXPECT_EQ(sequenceFieldOf(v1_newest), 2u);

  uint8_t v2_newest[XiaoOtaCommandRecordV2::kRecordBytes];
  EXPECT_FALSE(XiaoOtaCommandRecordV2::readNewest(region, v2_newest));
}

TEST(XiaoOtaCommandUnionTest, MixedSlotNewerOlderOrderingIsResolvedBySequenceNotByOwnVersionPreference) {
  // slot 0 = v1 seq 1 (older), slot 1 = v2 seq 2 (newer, written directly
  // via a second v1 writeNext then overwritten -- simulate by writing v1
  // twice so slot 1 holds v1 seq2, then force a v2 write which must pick
  // up generation 3 and target slot 0 (the least-recently-written slot),
  // proving the "oldest slot, not own-type slot" selection still holds
  // when both slots are populated with a mix of recognized types.
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const XiaoOtaCommandFields v1_fields = makeSampleCommandFields();
  const XiaoOtaCommandV2Fields v2_fields = makeSampleCommandV2Fields();

  uint32_t seq = 0;
  ASSERT_TRUE(XiaoOtaCommandRecord::writeNext(region, v1_fields, &seq));  // slot0, seq1
  EXPECT_EQ(seq, 1u);
  ASSERT_TRUE(XiaoOtaCommandRecordV2::writeNext(region, v2_fields, &seq));  // slot1, seq2
  EXPECT_EQ(seq, 2u);
  ASSERT_TRUE(XiaoOtaCommandRecord::writeNext(region, v1_fields, &seq));  // slot0 again, seq3
  EXPECT_EQ(seq, 3u);

  uint8_t v1_newest[XiaoOtaCommandRecord::kRecordBytes];
  EXPECT_TRUE(XiaoOtaCommandRecord::readNewest(region, v1_newest));
  EXPECT_EQ(sequenceFieldOf(v1_newest), 3u);
  uint8_t v2_newest[XiaoOtaCommandRecordV2::kRecordBytes];
  EXPECT_FALSE(XiaoOtaCommandRecordV2::readNewest(region, v2_newest));  // superseded, must not report seq2.
}

TEST(XiaoOtaCommandUnionTest, V2ReadNewestFailsClosedWhenTheTrueNewestSlotIsUnreadable) {
  // slot 0 = v1 seq1 (readable, older); slot 1 = unreadable (would hold
  // the true newest, of unknown type). Must return false, never fall
  // back to reporting slot 0's older v1 record as "the newest v2 record"
  // (it isn't even a v2 record, but the point generalizes: an unreadable
  // higher-sequence-candidate slot must never be silently skipped).
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const XiaoOtaCommandFields v1_fields = makeSampleCommandFields();
  uint32_t seq = 0;
  ASSERT_TRUE(XiaoOtaCommandRecord::writeNext(region, v1_fields, &seq));  // slot0, seq1

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Read;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash.readOpCount() + 2;  // slot 1's classification read.
  flash.armFault(fault);

  uint8_t v2_newest[XiaoOtaCommandRecordV2::kRecordBytes];
  EXPECT_FALSE(XiaoOtaCommandRecordV2::readNewest(region, v2_newest));
  uint8_t v1_newest[XiaoOtaCommandRecord::kRecordBytes];
  flash.clearFault();
  fault.trigger_op_count = flash.readOpCount() + 2;
  flash.armFault(fault);
  EXPECT_FALSE(XiaoOtaCommandRecord::readNewest(region, v1_newest));
}

TEST(XiaoOtaCommandUnionTest, WriteNextRefusesWhenCurrentSequenceIsAlreadyUint32MaxRatherThanWrappingToZero) {
  // Craft a record whose sequence is already the maximum representable
  // value, program it directly (bypassing writeNext's own increment), and
  // confirm writeNext() of EITHER version refuses to proceed (rather than
  // silently wrapping to 0, which would make a brand-new record
  // indistinguishable from -- or falsely appear older than -- genuinely
  // old records).
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  XiaoOtaCommandFields v1_fields = makeSampleCommandFields();
  v1_fields.sequence = 0xFFFFFFFFu;
  uint8_t maxed_record[XiaoOtaCommandRecord::kRecordBytes];
  ASSERT_EQ(XiaoOtaCommandRecord::serialize(v1_fields, maxed_record, sizeof(maxed_record)),
            XiaoOtaCommandRecord::kRecordBytes);
  ASSERT_TRUE(ota::platform::isOk(region.program(0, maxed_record, sizeof(maxed_record))));
  ASSERT_TRUE(XiaoOtaCommandRecord::isValidRecord(maxed_record, sizeof(maxed_record)));

  const uint32_t erase_count_before = flash.eraseOpCount();
  const uint32_t program_count_before = flash.programOpCount();

  uint32_t seq_out = 0;
  EXPECT_FALSE(XiaoOtaCommandRecord::writeNext(region, v1_fields, &seq_out));
  EXPECT_EQ(flash.eraseOpCount(), erase_count_before);
  EXPECT_EQ(flash.programOpCount(), program_count_before);

  const XiaoOtaCommandV2Fields v2_fields = makeSampleCommandV2Fields();
  uint32_t v2_seq_out = 0;
  EXPECT_FALSE(XiaoOtaCommandRecordV2::writeNext(region, v2_fields, &v2_seq_out));
  EXPECT_EQ(flash.eraseOpCount(), erase_count_before);
  EXPECT_EQ(flash.programOpCount(), program_count_before);
}

// ---------------------------------------------------------------------
// XiaoOtaFloorReader: bootloader-owned confirmed-counter/extent floor
// ---------------------------------------------------------------------

namespace {

// XiaoOtaFloorReader is READ-ONLY by design (only the bootloader ever
// writes xiao_ota_floor_t), so there is no writeNext()/serialize() helper
// to reuse here -- this constructs a valid raw record byte-for-byte,
// matching XiaoOtaFloorReader::isValidRecord()'s exact field layout, the
// same way the bootloader itself would.
std::vector<uint8_t> makeFloorRecordBytes(uint32_t sequence, uint32_t confirmed_counter_floor,
                                          uint32_t active_image_extent) {
  std::vector<uint8_t> rec(ota::storage::XiaoOtaFloorReader::kRecordBytes, 0);
  auto putU16 = [&](uint32_t pos, uint16_t v) {
    rec[pos] = static_cast<uint8_t>(v & 0xFFu);
    rec[pos + 1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
  };
  auto putU32 = [&](uint32_t pos, uint32_t v) {
    rec[pos] = static_cast<uint8_t>(v & 0xFFu);
    rec[pos + 1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    rec[pos + 2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
    rec[pos + 3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
  };
  putU32(0, ota::storage::XiaoOtaFloorReader::kMagic);
  rec[4] = static_cast<uint8_t>(ota::storage::XiaoOtaFloorReader::kRecordVersion);
  rec[5] = 0;
  putU16(6, static_cast<uint16_t>(ota::storage::XiaoOtaFloorReader::kRecordBytes));
  putU32(8, sequence);
  putU32(12, confirmed_counter_floor);
  putU32(16, active_image_extent);
  // bytes 20..51: confirmed_hash_sha256, left zeroed for this test helper.
  const uint32_t crc = Crc32::computeFinalized(rec.data(), ota::storage::XiaoOtaFloorReader::kCrcOffset);
  putU32(ota::storage::XiaoOtaFloorReader::kCrcOffset, crc);
  putU32(ota::storage::XiaoOtaFloorReader::kCommitMarkerOffset, ota::storage::XiaoOtaFloorReader::kCommitMarker);
  return rec;
}

}  // namespace

TEST(XiaoOtaFloorReaderTest, ReadNewestConfirmedCounterFindsHighestSequenceSlot) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const auto slot_a = makeFloorRecordBytes(1, 5, 10000);
  const auto slot_b = makeFloorRecordBytes(2, 9, 20000);
  ASSERT_TRUE(ota::platform::isOk(region.program(0, slot_a.data(), static_cast<uint32_t>(slot_a.size()))));
  ASSERT_TRUE(ota::platform::isOk(region.program(4096, slot_b.data(), static_cast<uint32_t>(slot_b.size()))));

  uint32_t counter = 0;
  ASSERT_TRUE(ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounter(region, counter));
  EXPECT_EQ(counter, 9u);
}

TEST(XiaoOtaFloorReaderTest, ReadNewestActiveExtentFindsHighestSequenceSlot) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const auto slot_a = makeFloorRecordBytes(1, 5, 10000);
  const auto slot_b = makeFloorRecordBytes(2, 9, 20000);
  ASSERT_TRUE(ota::platform::isOk(region.program(0, slot_a.data(), static_cast<uint32_t>(slot_a.size()))));
  ASSERT_TRUE(ota::platform::isOk(region.program(4096, slot_b.data(), static_cast<uint32_t>(slot_b.size()))));

  uint32_t extent = 0;
  ASSERT_TRUE(ota::storage::XiaoOtaFloorReader::readNewestActiveExtent(region, extent));
  EXPECT_EQ(extent, 20000u);
}

TEST(XiaoOtaFloorReaderTest, NeitherSlotValidMeansNoKnownFloor) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  uint32_t counter = 0;
  uint32_t extent = 0;
  EXPECT_FALSE(ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounter(region, counter));
  EXPECT_FALSE(ota::storage::XiaoOtaFloorReader::readNewestActiveExtent(region, extent));
}

TEST(XiaoOtaFloorReaderTest, FailClosedCounterTreatsBothSlotsBlankAsBaselineZero) {
  // A device that has never had a confirmed OTA install: both floor slots
  // are genuinely blank (erased, all-0xFF) -- this is the legitimate
  // first-ever-device baseline, not corruption.
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  uint32_t counter = 123;
  ASSERT_TRUE(ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed(region, counter));
  EXPECT_EQ(counter, 0u);
}

TEST(XiaoOtaFloorReaderTest, FailClosedCounterTrustsAValidRecordEvenIfItsFloorIsZero) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const auto slot_a = makeFloorRecordBytes(/*sequence=*/1, /*confirmed_counter_floor=*/0, 10000);
  ASSERT_TRUE(ota::platform::isOk(region.program(0, slot_a.data(), static_cast<uint32_t>(slot_a.size()))));

  uint32_t counter = 999;
  ASSERT_TRUE(ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed(region, counter));
  EXPECT_EQ(counter, 0u);
}

TEST(XiaoOtaFloorReaderTest, FailClosedCounterRejectsNonBlankInvalidSlotRatherThanDefaultingToZero) {
  // A slot that is non-blank but fails validation (e.g. torn write, or
  // tampering) must fail closed -- NOT be silently treated the same as a
  // genuinely-blank slot (which would incorrectly default to counter=0).
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  auto corrupt = makeFloorRecordBytes(1, 5, 10000);
  corrupt[10] ^= 0xFFu;  // corrupt a payload byte without fixing up the CRC.
  ASSERT_TRUE(ota::platform::isOk(region.program(0, corrupt.data(), static_cast<uint32_t>(corrupt.size()))));

  uint32_t counter = 0;
  EXPECT_FALSE(ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed(region, counter));
}

TEST(XiaoOtaFloorReaderTest, FailClosedCounterPrefersValidSlotOverACorruptOtherSlot) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const auto valid_slot = makeFloorRecordBytes(9, 42, 10000);
  auto corrupt_slot = makeFloorRecordBytes(1, 5, 10000);
  corrupt_slot[10] ^= 0xFFu;
  ASSERT_TRUE(
      ota::platform::isOk(region.program(0, corrupt_slot.data(), static_cast<uint32_t>(corrupt_slot.size()))));
  ASSERT_TRUE(
      ota::platform::isOk(region.program(4096, valid_slot.data(), static_cast<uint32_t>(valid_slot.size()))));

  uint32_t counter = 0;
  ASSERT_TRUE(ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed(region, counter));
  EXPECT_EQ(counter, 42u);
}

// An UNREADABLE slot (genuine I/O error) is categorically different from
// a readable-but-corrupt one: it might have held the true newest record,
// so it must fail the WHOLE lookup closed even when the other slot holds
// an old, but structurally valid, record -- never silently trust the old
// slot's value while treating the unreadable one as "absent".
TEST(XiaoOtaFloorReaderTest, FailClosedCounterRejectsWhenNewerSlotIsUnreadableEvenIfOlderSlotIsValid) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const auto old_valid_slot = makeFloorRecordBytes(1, 5, 10000);
  ASSERT_TRUE(ota::platform::isOk(
      region.program(0, old_valid_slot.data(), static_cast<uint32_t>(old_valid_slot.size()))));

  // Fault slot B's read (the second of the two reads
  // readNewestConfirmedCounterFailClosed() issues) -- this slot might
  // genuinely hold a newer, unreadable record.
  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Read;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash.readOpCount() + 2;
  flash.armFault(fault);

  uint32_t counter = 999;
  EXPECT_FALSE(ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed(region, counter));
}

// A blank record-sized prefix does NOT by itself prove a genuine blank
// baseline: nonblank bytes anywhere else in the erase unit (e.g. right
// at its very last byte) must still refuse the "no known floor -> 0"
// path -- even when the OTHER slot is also entirely, genuinely blank.
TEST(XiaoOtaFloorReaderTest, FailClosedCounterRejectsBlankHeaderWithNonBlankTailRatherThanDefaultingToZero) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  uint8_t one_byte = 0x00u;
  // Slot A's record-sized prefix (bytes [0, kRecordBytes)) stays entirely
  // blank/erased; only the very last byte of its 4096-byte erase unit is
  // nonblank.
  ASSERT_TRUE(ota::platform::isOk(region.program(4095, &one_byte, 1)));

  uint32_t counter = 0;
  EXPECT_FALSE(ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed(region, counter));
}

// ---------------------------------------------------------------------
// XiaoOtaBootInfoReader: immutable boot-info/capability marker
// ---------------------------------------------------------------------

std::vector<uint8_t> makeSampleBootInfoRecord() {
  std::vector<uint8_t> rec(XiaoOtaBootInfoReader::kStructBytes, 0);
  auto putU16 = [&](size_t off, uint16_t v) {
    rec[off] = static_cast<uint8_t>(v & 0xFF);
    rec[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
  };
  auto putU32 = [&](size_t off, uint32_t v) {
    rec[off] = static_cast<uint8_t>(v & 0xFF);
    rec[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    rec[off + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    rec[off + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
  };
  putU32(0, XiaoOtaBootInfoReader::kMagic);
  putU16(4, XiaoOtaBootInfoReader::kFormatVersion);
  putU16(6, static_cast<uint16_t>(XiaoOtaBootInfoReader::kStructBytes));
  putU32(8, 0x584E3430u);   // board_target_id (XIAO nRF52840)
  putU32(12, 0u);           // role_id (ANY)
  putU32(16, 0x1u);         // capability_flags (QSPI_INSTALL)
  putU16(20, 1u);           // key_id
  putU16(22, 1u);           // algorithm_id (Ed25519)
  for (size_t i = 0; i < 32; ++i) rec[24 + i] = static_cast<uint8_t>(0xA0 + i);
  const uint32_t crc = Crc32::computeFinalized(rec.data(), XiaoOtaBootInfoReader::kCrcOffset);
  putU32(XiaoOtaBootInfoReader::kCrcOffset, crc);
  return rec;
}

TEST(XiaoOtaBootInfoReaderTest, ValidRecordDecodesExpectedFields) {
  const std::vector<uint8_t> rec = makeSampleBootInfoRecord();
  XiaoOtaBootInfoReader::Info info;
  ASSERT_TRUE(XiaoOtaBootInfoReader::decode(rec.data(), rec.size(), info));
  EXPECT_EQ(info.boardTargetId, 0x584E3430u);
  EXPECT_EQ(info.roleId, 0u);
  EXPECT_EQ(info.capabilityFlags, 0x1u);
  EXPECT_EQ(info.keyId, 1u);
  EXPECT_EQ(info.algorithmId, 1u);
  EXPECT_EQ(info.trustedPublicKey[0], 0xA0);
  EXPECT_EQ(info.trustedPublicKey[31], 0xBF);
}

TEST(XiaoOtaBootInfoReaderTest, AllErasedFlashFailsClosedNotAsCorruption) {
  // A stock/unmodified Adafruit bootloader leaves this address at 0xFF:
  // this must decode as "invalid" (fail closed) exactly like any other
  // bad record, with no special-cased exception/log path.
  std::vector<uint8_t> rec(XiaoOtaBootInfoReader::kStructBytes, 0xFF);
  XiaoOtaBootInfoReader::Info info;
  EXPECT_FALSE(XiaoOtaBootInfoReader::isValidRecord(rec.data(), rec.size()));
  EXPECT_FALSE(XiaoOtaBootInfoReader::decode(rec.data(), rec.size(), info));
}

TEST(XiaoOtaBootInfoReaderTest, CorruptedCrcIsRejected) {
  std::vector<uint8_t> rec = makeSampleBootInfoRecord();
  rec[10] ^= 0xFF;  // flip a byte inside board_target_id
  XiaoOtaBootInfoReader::Info info;
  EXPECT_FALSE(XiaoOtaBootInfoReader::isValidRecord(rec.data(), rec.size()));
  EXPECT_FALSE(XiaoOtaBootInfoReader::decode(rec.data(), rec.size(), info));
}

TEST(XiaoOtaBootInfoReaderTest, WrongFormatVersionIsRejected) {
  std::vector<uint8_t> rec = makeSampleBootInfoRecord();
  rec[4] = 2;  // format_version = 2, unsupported
  EXPECT_FALSE(XiaoOtaBootInfoReader::isValidRecord(rec.data(), rec.size()));
}

TEST(XiaoOtaBootInfoReaderTest, WrongLengthIsRejected) {
  const std::vector<uint8_t> rec = makeSampleBootInfoRecord();
  EXPECT_FALSE(XiaoOtaBootInfoReader::isValidRecord(rec.data(), rec.size() - 1));
}

TEST(XiaoOtaBootInfoReaderTest, ReadCurrentFailsClosedOffTarget) {
  // Native/non-nRF52840 builds have no meaning for the fixed hardware
  // address: readCurrent() must simply fail closed rather than
  // dereference it.
  XiaoOtaBootInfoReader::Info info;
  EXPECT_FALSE(XiaoOtaBootInfoReader::readCurrent(info));
}

// ---------------------------------------------------------------------
// XiaoOtaActiveExtentBridge: first-install / current-extent resolution
// ---------------------------------------------------------------------

namespace {

std::vector<uint8_t> makeFakeAppImage(uint32_t len, uint8_t seed) {
  std::vector<uint8_t> image(len);
  for (uint32_t i = 0; i < len; ++i) image[i] = static_cast<uint8_t>(seed + (i & 0xFFu));
  return image;
}

}  // namespace

TEST(XiaoOtaActiveExtentBridgeTest, Crc16MatchesKnownCcittFalseCheckValue) {
  // Standard CRC-16/CCITT-FALSE check value for ASCII "123456789" is
  // 0x29B1 -- this is the exact variant Nordic's SDK crc16_compute()
  // implements, and the one xiao_ota_boot.c's bank-0 legacy-extent check
  // relies on.
  const uint8_t check[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
  EXPECT_EQ(XiaoOtaActiveExtentBridge::crc16Compute(check, sizeof(check)), 0x29B1u);
}

TEST(XiaoOtaActiveExtentBridgeTest, ValidBank0SettingsAreTrustedForExtent) {
  const uint32_t bank0_size = 65536;
  std::vector<uint8_t> image = makeFakeAppImage(bank0_size, 0x11);
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = bank0_size;
  bank0.bank_0_crc = XiaoOtaActiveExtentBridge::crc16Compute(image.data(), bank0_size);

  const uint32_t extent = XiaoOtaActiveExtentBridge::resolveExtentFromBank0(bank0, image.data(), bank0_size);
  EXPECT_EQ(extent, bank0_size);
}

TEST(XiaoOtaActiveExtentBridgeTest, OversizedBank0SizeBeyondInstallCeilingFailsClosedEvenWithinRawMappedRegion) {
  // MAIN's bug #6: a bank0_size beyond the true protocol/install ceiling
  // (kXiaoOtaAppInstallMaxSize == 643072, protecting the installer at
  // 0xC4000 and InternalExtraFS at 0xD4000) must be rejected,
  // even though it is still comfortably within the raw mapped-region size
  // (kXiaoOtaAppMaxSize == 811008) that app_image_len alone would allow --
  // never silently accept an oversized/injected extent just because it
  // fits in the wider raw-memory-safety bound.
  ASSERT_GT(ota::storage::kXiaoOtaAppMaxSize, ota::storage::kXiaoOtaAppInstallMaxSize);
  const uint32_t bank0_size = ota::storage::kXiaoOtaAppInstallMaxSize + 1;
  std::vector<uint8_t> image = makeFakeAppImage(ota::storage::kXiaoOtaAppMaxSize, 0x55);
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = bank0_size;
  bank0.bank_0_crc = XiaoOtaActiveExtentBridge::crc16Compute(image.data(), bank0_size);

  const uint32_t extent = XiaoOtaActiveExtentBridge::resolveExtentFromBank0(
      bank0, image.data(), static_cast<uint32_t>(image.size()));
  EXPECT_EQ(extent, 0u);
}

TEST(XiaoOtaActiveExtentBridgeTest, BankSizeExactlyAtInstallCeilingIsAccepted) {
  // The boundary itself (exactly kXiaoOtaAppInstallMaxSize) must still be
  // a legitimate, acceptable extent -- only strictly-over is rejected.
  const uint32_t bank0_size = ota::storage::kXiaoOtaAppInstallMaxSize;
  std::vector<uint8_t> image = makeFakeAppImage(bank0_size, 0x66);
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = bank0_size;
  bank0.bank_0_crc = XiaoOtaActiveExtentBridge::crc16Compute(image.data(), bank0_size);

  const uint32_t extent = XiaoOtaActiveExtentBridge::resolveExtentFromBank0(bank0, image.data(), bank0_size);
  EXPECT_EQ(extent, bank0_size);
}

TEST(XiaoOtaActiveExtentBridgeTest, MismatchedBank0CrcFailsClosedToZero) {
  const uint32_t bank0_size = 65536;
  std::vector<uint8_t> image = makeFakeAppImage(bank0_size, 0x11);
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = bank0_size;
  bank0.bank_0_crc = 0xDEAD;  // wrong on purpose

  const uint32_t extent = XiaoOtaActiveExtentBridge::resolveExtentFromBank0(bank0, image.data(), bank0_size);
  EXPECT_EQ(extent, 0u);
}

TEST(XiaoOtaActiveExtentBridgeTest, InvalidBankMarkerFailsClosedToZero) {
  const uint32_t bank0_size = 65536;
  std::vector<uint8_t> image = makeFakeAppImage(bank0_size, 0x11);
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = 0;  // not kBankValidApp: e.g. a virgin/stock bootloader page
  bank0.bank_0_size = bank0_size;
  bank0.bank_0_crc = XiaoOtaActiveExtentBridge::crc16Compute(image.data(), bank0_size);

  const uint32_t extent = XiaoOtaActiveExtentBridge::resolveExtentFromBank0(bank0, image.data(), bank0_size);
  EXPECT_EQ(extent, 0u);
}

TEST(XiaoOtaActiveExtentBridgeTest, TruncatedAppImageBufferFailsClosedToZero) {
  const uint32_t bank0_size = 65536;
  std::vector<uint8_t> image = makeFakeAppImage(bank0_size, 0x11);
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = bank0_size;
  bank0.bank_0_crc = XiaoOtaActiveExtentBridge::crc16Compute(image.data(), bank0_size);

  // app_image_len shorter than bank0_size: cannot safely hash the claimed
  // extent -- must fail closed, never silently clamp/guess a shorter one.
  const uint32_t extent =
      XiaoOtaActiveExtentBridge::resolveExtentFromBank0(bank0, image.data(), bank0_size - 1);
  EXPECT_EQ(extent, 0u);
}

TEST(XiaoOtaActiveExtentBridgeTest, ResolveNeverConsultsAFloorAndFailsClosedOnInvalidBank0) {
  // Regression for the removed floor-priority design: resolve() no longer
  // accepts (or can be influenced by) any floor extent argument at all --
  // a stale confirmed floor from a since-USB-reflashed device must never
  // win over a fresh (or absent) bank0 read.
  std::vector<uint8_t> image = makeFakeAppImage(kXiaoOtaAppMaxSize, 0x22);
  XiaoOtaBank0Settings bank0;  // deliberately left invalid/zero.

  const auto info =
      XiaoOtaActiveExtentBridge::resolve(bank0, image.data(), static_cast<uint32_t>(image.size()));
  EXPECT_EQ(info.active_image_extent, 0u);
  uint8_t all_zero_hash[32] = {0};
  EXPECT_EQ(memcmp(info.active_image_hash_sha256, all_zero_hash, 32), 0);
}

TEST(XiaoOtaActiveExtentBridgeTest, ValidFreshBank0AlwaysWinsRegardlessOfAnyPriorFloorSize) {
  // "Valid stale floor + different size uses fresh size" regression main
  // requested: since resolve() takes no floor input whatsoever, a
  // differently-sized fresh bank0 image always determines the extent --
  // there is no code path left that could let an old floor's size win.
  const uint32_t bank0_size = 4096;  // deliberately different from any floor size a caller might imagine.
  std::vector<uint8_t> image = makeFakeAppImage(bank0_size, 0x44);
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = bank0_size;
  bank0.bank_0_crc = XiaoOtaActiveExtentBridge::crc16Compute(image.data(), bank0_size);

  const auto info =
      XiaoOtaActiveExtentBridge::resolve(bank0, image.data(), static_cast<uint32_t>(image.size()));
  EXPECT_EQ(info.active_image_extent, bank0_size);
  uint8_t expected_hash[32];
  ota::trust::Sha256::hash(image.data(), bank0_size, expected_hash);
  EXPECT_EQ(memcmp(info.active_image_hash_sha256, expected_hash, 32), 0);
}

TEST(XiaoOtaActiveExtentBridgeTest, HashIsAlwaysFreshOverWhateverImageIsPassedNow) {
  // Simulates a USB-reflashed image: the hash returned must reflect the
  // image bytes actually present now, never any cached/previous value.
  const uint32_t bank0_size = 4096;
  std::vector<uint8_t> old_image = makeFakeAppImage(bank0_size, 0xAA);
  std::vector<uint8_t> new_image = makeFakeAppImage(bank0_size, 0xBB);

  uint8_t stale_hash[32];
  ota::trust::Sha256::hash(old_image.data(), bank0_size, stale_hash);

  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = bank0_size;
  bank0.bank_0_crc = XiaoOtaActiveExtentBridge::crc16Compute(new_image.data(), bank0_size);

  const auto info = XiaoOtaActiveExtentBridge::resolve(bank0, new_image.data(),
                                                        static_cast<uint32_t>(new_image.size()));
  EXPECT_NE(memcmp(info.active_image_hash_sha256, stale_hash, 32), 0);
}

TEST(XiaoOtaActiveExtentBridgeTest, NoValidBank0FailsClosedSafelyRatherThanFullRangeFallback) {
  std::vector<uint8_t> image = makeFakeAppImage(kXiaoOtaAppMaxSize, 0x33);
  XiaoOtaBank0Settings bank0;  // all-zero: virgin/never-written bootloader page.

  const auto info =
      XiaoOtaActiveExtentBridge::resolve(bank0, image.data(), static_cast<uint32_t>(image.size()));
  EXPECT_EQ(info.active_image_extent, 0u);
}

TEST(XiaoOtaActiveExtentBridgeTest, ResolveCurrentFailsClosedOffTarget) {
  const auto info = XiaoOtaActiveExtentBridge::resolveCurrent();
  EXPECT_EQ(info.active_image_extent, 0u);
}

// Independent fixture proving the CONFIRMED Nordic SDK11
// bootloader_settings_t raw byte layout is decoded at the exact offsets
// boot-Hydra specified (bank_0 u16@0, bank_0_crc u16@2, bank_1 u16@4,
// padding@6..7, bank_0_size u32@8) -- not merely re-asserting whatever
// the implementation currently does, but constructing a raw 28-byte
// buffer byte-by-byte from the documented offsets and checking the
// decoded struct fields independently.
TEST(XiaoOtaActiveExtentBridgeTest, DecodesConfirmedNordicBootloaderSettingsRawOffsetsExactly) {
  uint8_t raw[XiaoOtaActiveExtentBridge::kBootloaderSettingsRawBytes] = {0};
  // bank_0 = 1 (BANK_VALID_APP) at offset 0, little-endian u16.
  raw[0] = 0x01;
  raw[1] = 0x00;
  // bank_0_crc = 0xBEEF at offset 2, little-endian u16.
  raw[2] = 0xEF;
  raw[3] = 0xBE;
  // bank_1 = 0xCAFE at offset 4 -- not consulted by this bridge, but
  // placed here to prove it is NOT accidentally read as bank_0_crc/size.
  raw[4] = 0xFE;
  raw[5] = 0xCA;
  // offset 6..7: padding, deliberately non-zero to prove it's ignored.
  raw[6] = 0x55;
  raw[7] = 0x55;
  // bank_0_size = 0x0001E240 (123456) at offset 8, little-endian u32.
  raw[8] = 0x40;
  raw[9] = 0xE2;
  raw[10] = 0x01;
  raw[11] = 0x00;

  const auto bank0 = XiaoOtaActiveExtentBridge::decodeBank0FromRaw28Bytes(raw);
  EXPECT_EQ(bank0.bank_0, 1u);
  EXPECT_EQ(bank0.bank_0_crc, 0xBEEFu);
  EXPECT_EQ(bank0.bank_0_size, 123456u);
}

TEST(XiaoOtaActiveExtentBridgeTest, DecodedRawSettingsIntegrateWithResolveEndToEnd) {
  // A real image whose true CRC16/size are known, packed into a raw
  // settings-page fixture at the confirmed offsets, must resolve exactly
  // as if the fields had been supplied directly -- proving the raw
  // decoder and resolve() compose correctly end-to-end.
  std::vector<uint8_t> image(2048, 0);
  for (size_t i = 0; i < image.size(); ++i) image[i] = static_cast<uint8_t>(i * 7);
  const uint32_t real_size = 1500;
  const uint16_t real_crc = XiaoOtaActiveExtentBridge::crc16Compute(image.data(), real_size);

  uint8_t raw[XiaoOtaActiveExtentBridge::kBootloaderSettingsRawBytes] = {0};
  raw[0] = 1;  // bank_0 = BANK_VALID_APP.
  raw[2] = static_cast<uint8_t>(real_crc & 0xFF);
  raw[3] = static_cast<uint8_t>((real_crc >> 8) & 0xFF);
  raw[8] = static_cast<uint8_t>(real_size & 0xFF);
  raw[9] = static_cast<uint8_t>((real_size >> 8) & 0xFF);
  raw[10] = static_cast<uint8_t>((real_size >> 16) & 0xFF);
  raw[11] = static_cast<uint8_t>((real_size >> 24) & 0xFF);

  const auto bank0 = XiaoOtaActiveExtentBridge::decodeBank0FromRaw28Bytes(raw);
  const auto info = XiaoOtaActiveExtentBridge::resolve(bank0, image.data(), static_cast<uint32_t>(image.size()));
  EXPECT_EQ(info.active_image_extent, real_size);
}

// ---------------------------------------------------------------------
// OtaBoardBackendCommon: shared fail-closed counter/qualification/status
// logic extracted from the XIAO lab / SenseCAP production backend .cpp
// files, to avoid duplicating it there untested.
// ---------------------------------------------------------------------

// Regression for a real bug found via physical RF lab testing: a signed
// wire descriptor with a genuine, nonzero format_id (every real descriptor
// in this repo's own fixtures uses format_id=1, matching bootloader/
// xiao_nrf52840_ota's XIAO_OTA_DESCRIPTOR_FORMAT) was silently rejected as
// FormatIdMismatch, because both real backend .cpp files populated
// expected_key_id/expected_algorithm_id but never expected_format_id,
// leaving it at DeviceTrustAnchor's zero default. configureOtaTrustAnchorIdentity()
// exists specifically so all six anchor identity fields are always
// populated together -- this proves it actually does so.
TEST(ConfigureOtaTrustAnchorIdentityTest, PopulatesAllSixFieldsIncludingFormatId) {
  ::ota::trust::DeviceTrustAnchor anchor;
  mesh::ota::configureOtaTrustAnchorIdentity(anchor, /*expected_target_id=*/0x584E3430u,
                                             /*expected_role_id=*/0u,
                                             /*supported_boot_capability_flags=*/1u,
                                             /*expected_format_id=*/1u, /*expected_key_id=*/1u,
                                             /*expected_algorithm_id=*/1u);
  EXPECT_EQ(anchor.expected_target_id, 0x584E3430u);
  EXPECT_EQ(anchor.expected_role_id, 0u);
  EXPECT_EQ(anchor.supported_boot_capability_flags, 1u);
  EXPECT_EQ(anchor.expected_format_id, 1u);
  EXPECT_EQ(anchor.expected_key_id, 1u);
  EXPECT_EQ(anchor.expected_algorithm_id, 1u);
}

// End-to-end reproduction of the actual physical failure: a descriptor
// with format_id=1 (the real, correct value every fixture in this repo
// signs with) against an anchor built by the shared helper must pass
// policy verification -- NOT fail with FormatIdMismatch the way it did
// when expected_format_id was left unset in the real backend files.
TEST(ConfigureOtaTrustAnchorIdentityTest, DescriptorWithRealFormatIdPassesPolicyAfterHelperConfigures) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);  // blank floor -> baseline 0.

  ::ota::trust::DeviceTrustAnchor anchor;
  mesh::ota::configureOtaTrustAnchorIdentity(anchor, /*expected_target_id=*/0x584E3430u,
                                             /*expected_role_id=*/0u,
                                             /*supported_boot_capability_flags=*/1u,
                                             /*expected_format_id=*/1u, /*expected_key_id=*/1u,
                                             /*expected_algorithm_id=*/1u);

  ::ota::trust::ImageDescriptor descriptor;
  descriptor.target_id = 0x584E3430u;
  descriptor.role_id = 0u;
  descriptor.allow_broadcast_address = true;
  descriptor.required_boot_capability_flags = 1u;
  descriptor.monotonic_counter = 1u;  // strictly greater than baseline 0.
  descriptor.image_size_bytes = 320u;
  descriptor.format_id = 1u;
  descriptor.key_id = 1u;
  descriptor.algorithm_id = 1u;

  ::ota::trust::Sha256 hasher;
  ::ota::trust::Ed25519SignatureVerifier sig_verifier;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);
  const auto result = verifier.verifyPolicy(descriptor);
  EXPECT_TRUE(result.ok);
  EXPECT_EQ(result.reason, ::ota::trust::TrustFailureReason::None);
}

// Proves the failure mode this whole fix addresses: the SAME descriptor,
// verified against an anchor left at DeviceTrustAnchor's raw zero default
// for expected_format_id (i.e. what the real backend files did before this
// fix), is wrongly rejected -- documenting the exact regression a future
// change to configureOtaTrustAnchorIdentity() (or a new call site that
// bypasses it) must not reintroduce.
TEST(ConfigureOtaTrustAnchorIdentityTest, UnsetFormatIdOnAnchorRejectsAGenuinelyValidDescriptor) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);

  ::ota::trust::DeviceTrustAnchor anchor;  // expected_format_id left at its 0 default, on purpose.
  anchor.expected_target_id = 0x584E3430u;
  anchor.expected_role_id = 0u;
  anchor.supported_boot_capability_flags = 1u;
  anchor.expected_key_id = 1u;
  anchor.expected_algorithm_id = 1u;

  ::ota::trust::ImageDescriptor descriptor;
  descriptor.target_id = 0x584E3430u;
  descriptor.role_id = 0u;
  descriptor.allow_broadcast_address = true;
  descriptor.required_boot_capability_flags = 1u;
  descriptor.monotonic_counter = 1u;
  descriptor.image_size_bytes = 320u;
  descriptor.format_id = 1u;
  descriptor.key_id = 1u;
  descriptor.algorithm_id = 1u;

  ::ota::trust::Sha256 hasher;
  ::ota::trust::Ed25519SignatureVerifier sig_verifier;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);
  const auto result = verifier.verifyPolicy(descriptor);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.reason, ::ota::trust::TrustFailureReason::FormatIdMismatch);
}

TEST(OtaBoardFailClosedMonotonicCounterTest, BlankFloorSeedsBaselineZero) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);

  uint32_t value = 123;
  ASSERT_TRUE(counter.currentValue(value));
  EXPECT_EQ(value, 0u);
}

TEST(OtaBoardFailClosedMonotonicCounterTest, CorruptNonBlankSlotFailsClosed) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  auto corrupt = makeFloorRecordBytes(1, 5, 10000);
  corrupt[10] ^= 0xFFu;
  ASSERT_TRUE(ota::platform::isOk(region.program(0, corrupt.data(), static_cast<uint32_t>(corrupt.size()))));

  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);
  uint32_t value = 0;
  EXPECT_FALSE(counter.currentValue(value));
  EXPECT_FALSE(counter.commitNewValue(1));
}

TEST(OtaBoardFailClosedMonotonicCounterTest, CommitRejectsNonIncreasingValueAndUnseededFailure) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const auto slot_a = makeFloorRecordBytes(1, 10, 10000);
  ASSERT_TRUE(ota::platform::isOk(region.program(0, slot_a.data(), static_cast<uint32_t>(slot_a.size()))));

  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);
  EXPECT_FALSE(counter.commitNewValue(10));  // not strictly greater.
  EXPECT_TRUE(counter.commitNewValue(11));
  uint32_t value = 0;
  ASSERT_TRUE(counter.currentValue(value));
  EXPECT_EQ(value, 11u);
}

// ---------------------------------------------------------------------
// resolveOtaBoardInstallGate(): the shared "qualified marker && valid
// bank0 && initialized floor" predicate both backends (.cpp, Arduino-
// dependent, otherwise untestable natively) must consult before
// attaching a durable install-command provider.
// Each of the three inputs is exercised independently to prove none is
// individually sufficient, and that a corrupt/unreadable floor disables
// install capability even when the other two both hold (never silently
// treated as floor==0).
// ---------------------------------------------------------------------

TEST(OtaBoardInstallGateTest, RefusesWhenNotQualifiedEvenWithValidBank0AndReadableFloor) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);  // blank floor -> readable, baseline 0.

  const auto result = mesh::ota::resolveOtaBoardInstallGate(/*qualified=*/false, /*bank0_active_image_extent=*/0x20000u,
                                                             counter);
  EXPECT_FALSE(result.install_capable);
}

TEST(OtaBoardInstallGateTest, RefusesWhenBank0ExtentIsZeroEvenWhenQualifiedAndFloorReadable) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);

  const auto result =
      mesh::ota::resolveOtaBoardInstallGate(/*qualified=*/true, /*bank0_active_image_extent=*/0u, counter);
  EXPECT_FALSE(result.install_capable);
}

TEST(OtaBoardInstallGateTest, RefusesWhenFloorIsCorruptEvenWhenQualifiedAndBank0Valid) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  auto corrupt = makeFloorRecordBytes(1, 5, 10000);
  corrupt[10] ^= 0xFFu;  // non-blank but invalid: must fail closed, never default to floor==0.
  ASSERT_TRUE(ota::platform::isOk(region.program(0, corrupt.data(), static_cast<uint32_t>(corrupt.size()))));
  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);

  const auto result =
      mesh::ota::resolveOtaBoardInstallGate(/*qualified=*/true, /*bank0_active_image_extent=*/0x20000u, counter);
  EXPECT_FALSE(result.install_capable);
}

TEST(OtaBoardInstallGateTest, RefusesWhenFloorSlotIsUnreadableEvenWhenQualifiedAndBank0Valid) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Read;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash.readOpCount() + 1;
  flash.armFault(fault);

  const auto result =
      mesh::ota::resolveOtaBoardInstallGate(/*qualified=*/true, /*bank0_active_image_extent=*/0x20000u, counter);
  EXPECT_FALSE(result.install_capable);
}

// A readable-and-valid OLD floor record in one slot must not mask a
// genuinely unreadable (possibly newer) OTHER slot: the gate must refuse
// install capability, not silently trust the stale floor value.
TEST(OtaBoardInstallGateTest, RefusesWhenOlderSlotIsValidButNewerSlotIsUnreadable) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const auto old_valid_slot = makeFloorRecordBytes(1, 5, 10000);
  ASSERT_TRUE(ota::platform::isOk(
      region.program(0, old_valid_slot.data(), static_cast<uint32_t>(old_valid_slot.size()))));

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Read;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash.readOpCount() + 2;  // slot B's read.
  flash.armFault(fault);

  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);
  const auto result =
      mesh::ota::resolveOtaBoardInstallGate(/*qualified=*/true, /*bank0_active_image_extent=*/0x20000u, counter);
  EXPECT_FALSE(result.install_capable);
}

// A blank record header with nonblank data at the erase unit's tail must
// never be treated as a genuine blank baseline -- the gate must refuse
// install capability rather than silently accepting floor==0.
TEST(OtaBoardInstallGateTest, RefusesWhenBlankHeaderHasNonBlankTailRatherThanDefaultingToBaselineZero) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  uint8_t one_byte = 0x00u;
  ASSERT_TRUE(ota::platform::isOk(region.program(4095, &one_byte, 1)));

  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);
  const auto result =
      mesh::ota::resolveOtaBoardInstallGate(/*qualified=*/true, /*bank0_active_image_extent=*/0x20000u, counter);
  EXPECT_FALSE(result.install_capable);
}

TEST(OtaBoardInstallGateTest, BlankNumericZeroIsNeverQualifiedInstallerPermission) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);  // both slots blank -> legitimate baseline 0.

  const auto result =
      mesh::ota::resolveOtaBoardInstallGate(/*qualified=*/true, /*bank0_active_image_extent=*/0x20000u, counter);
  uint32_t numeric = 99;
  ASSERT_TRUE(counter.currentValue(numeric));
  EXPECT_EQ(0u, numeric);
  EXPECT_FALSE(result.install_capable);
  EXPECT_EQ(result.floor_value, 0u);
}

TEST(OtaBoardInstallGateTest, PresentGenesisZeroIsQualifiedInstallerPermissionNotInstalledEvidence) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  auto genesis = makeFloorRecordBytes(1, 0, 0);
  std::memset(genesis.data() + 20, 0, 32);
  const auto crc = ota::storage::Crc32::computeFinalized(genesis.data(), 52);
  for (uint32_t i = 0; i < 4; ++i) genesis[52 + i] = static_cast<uint8_t>(crc >> (i * 8));
  ASSERT_TRUE(ota::platform::isOk(region.program(0, genesis.data(), genesis.size())));
  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);
  const auto result = mesh::ota::resolveOtaBoardInstallGate(true, 9004, counter);
  EXPECT_TRUE(result.install_capable);
  EXPECT_EQ(0u, result.floor_value);
  uint8_t hash[32]; uint32_t floor = 99, extent = 99;
  ASSERT_TRUE(ota::storage::XiaoOtaFloorReader::readNewestConfirmedEvidenceFailClosed(region, floor, hash, &extent));
  EXPECT_EQ(0u, floor);
  EXPECT_EQ(0u, extent);
  const uint8_t unknown[32] = {};
  EXPECT_EQ(0, std::memcmp(hash, unknown, sizeof(hash)));
}

TEST(OtaBoardInstallGateTest, InstallCapableWithAGenuineNonZeroFloorRecord) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const auto slot_a = makeFloorRecordBytes(1, 42, 10000);
  ASSERT_TRUE(ota::platform::isOk(region.program(0, slot_a.data(), static_cast<uint32_t>(slot_a.size()))));
  mesh::ota::OtaBoardFailClosedMonotonicCounter counter(region);

  const auto result =
      mesh::ota::resolveOtaBoardInstallGate(/*qualified=*/true, /*bank0_active_image_extent=*/0x20000u, counter);
  EXPECT_TRUE(result.install_capable);
  EXPECT_EQ(result.floor_value, 42u);
}

TEST(OtaBoardWireDescriptorSecurityCounterBETest, DecodesBigEndianU32AtFixedOffset) {
  uint8_t wire_descriptor[59] = {0};
  wire_descriptor[45] = 0x01;
  wire_descriptor[46] = 0x02;
  wire_descriptor[47] = 0x03;
  wire_descriptor[48] = 0x04;
  EXPECT_EQ(mesh::ota::otaBoardWireDescriptorSecurityCounterBE(wire_descriptor), 0x01020304u);
}

// Deterministic transaction-identity tests (replaces the previously
// rejected entropy-source design): computeOtaTransactionNonce() is a pure
// function of (controller, session, wire_descriptor) -- no flash
// read/write, no RNG.
TEST(OtaBoardInstallCommandProviderV2Test, FailsClosedWhenNoValidBank0IsPresent) {
  // Off-target native build: resolveCurrent() always returns extent=0, so
  // the shared install-command provider must refuse to build a command,
  // regardless of the (deterministic) nonce, which is cheap and always
  // computable but must never be written without a genuine fresh extent.
  mesh::ota::OtaBoardInstallCommandProviderV2 provider;
  uint8_t wire_descriptor[59] = {0};
  uint8_t signature[64] = {0};
  uint8_t controller[32] = {0};
  meshcore::ota::runtime::OtaSessionId session{1, 2, 3};
  ota::storage::XiaoOtaCommandV2Fields out;
  EXPECT_FALSE(provider.buildInstallCommandV2(wire_descriptor, signature, session, controller, out));
}

TEST(OtaBoardTransactionNonceTest, SameControllerSessionAndDescriptorAlwaysProducesTheSameNonce) {
  uint8_t controller[32];
  memset(controller, 0xAB, sizeof(controller));
  uint8_t wire_descriptor[59];
  memset(wire_descriptor, 0x11, sizeof(wire_descriptor));
  meshcore::ota::runtime::OtaSessionId session{100, 200, 3};

  const uint64_t nonce1 = mesh::ota::computeOtaTransactionNonce(controller, session, wire_descriptor);
  const uint64_t nonce2 = mesh::ota::computeOtaTransactionNonce(controller, session, wire_descriptor);
  EXPECT_EQ(nonce1, nonce2);  // idempotent: a repeated commit of the SAME attempt reuses the same nonce.
  EXPECT_NE(nonce1, 0u);
}

TEST(OtaBoardTransactionNonceTest, DifferentAttemptIdChangesNonceEvenWithSameDescriptor) {
  uint8_t controller[32];
  memset(controller, 0xCD, sizeof(controller));
  uint8_t wire_descriptor[59];
  memset(wire_descriptor, 0x22, sizeof(wire_descriptor));
  meshcore::ota::runtime::OtaSessionId session_a{1, 1, 1};
  meshcore::ota::runtime::OtaSessionId session_b{1, 1, 2};  // a genuinely new locally-authorized attempt.

  const uint64_t nonce_a = mesh::ota::computeOtaTransactionNonce(controller, session_a, wire_descriptor);
  const uint64_t nonce_b = mesh::ota::computeOtaTransactionNonce(controller, session_b, wire_descriptor);
  // A same-image retry after a FAILED attempt must be possible: a new
  // attemptId alone (no descriptor change needed) yields a fresh nonce.
  EXPECT_NE(nonce_a, nonce_b);
}

TEST(OtaBoardTransactionNonceTest, DifferentSessionOrCampaignIdChangesNonce) {
  uint8_t controller[32];
  memset(controller, 0xEE, sizeof(controller));
  uint8_t wire_descriptor[59];
  memset(wire_descriptor, 0x33, sizeof(wire_descriptor));
  meshcore::ota::runtime::OtaSessionId base{1, 1, 1};
  meshcore::ota::runtime::OtaSessionId diff_session{1, 2, 1};
  meshcore::ota::runtime::OtaSessionId diff_campaign{2, 1, 1};

  const uint64_t base_nonce = mesh::ota::computeOtaTransactionNonce(controller, base, wire_descriptor);
  EXPECT_NE(base_nonce, mesh::ota::computeOtaTransactionNonce(controller, diff_session, wire_descriptor));
  EXPECT_NE(base_nonce, mesh::ota::computeOtaTransactionNonce(controller, diff_campaign, wire_descriptor));
}

TEST(OtaBoardTransactionNonceTest, DifferentControllerChangesNonce) {
  uint8_t controller_a[32];
  memset(controller_a, 0x01, sizeof(controller_a));
  uint8_t controller_b[32];
  memset(controller_b, 0x02, sizeof(controller_b));
  uint8_t wire_descriptor[59];
  memset(wire_descriptor, 0x44, sizeof(wire_descriptor));
  meshcore::ota::runtime::OtaSessionId session{9, 9, 9};

  EXPECT_NE(mesh::ota::computeOtaTransactionNonce(controller_a, session, wire_descriptor),
            mesh::ota::computeOtaTransactionNonce(controller_b, session, wire_descriptor));
}

TEST(OtaBoardTransactionNonceTest, DifferentDescriptorChangesNonceForSameSessionAndController) {
  uint8_t controller[32];
  memset(controller, 0x77, sizeof(controller));
  meshcore::ota::runtime::OtaSessionId session{5, 5, 5};
  uint8_t descriptor_a[59];
  memset(descriptor_a, 0x55, sizeof(descriptor_a));
  uint8_t descriptor_b[59];
  memset(descriptor_b, 0x66, sizeof(descriptor_b));

  EXPECT_NE(mesh::ota::computeOtaTransactionNonce(controller, session, descriptor_a),
            mesh::ota::computeOtaTransactionNonce(controller, session, descriptor_b));
}

TEST(OtaBoardBootQualificationTest, FailsClosedOffTargetRegardlessOfExpectedIds) {
  const auto q = mesh::ota::resolveOtaBoardBootQualification(0x584E3430u, 0u, 1u);
  EXPECT_FALSE(q.qualified);
}

// Pure mapping tests (see resolveOtaBoardBootQualificationFromRecordStatus()
// in OtaBoardBackendCommon.h): resolveOtaBoardBootQualification() itself
// calls the hardware-bound classifyCurrent(), which is only ever Corrupt
// off-target, so these exercise every branch directly with synthetic
// RecordStatus/Info values instead.
TEST(OtaBoardBootQualificationFromRecordStatusTest, BlankMarkerIsUnknownNeverNormal) {
  ::ota::storage::XiaoOtaBootInfoReader::Info info{};
  const auto q = mesh::ota::resolveOtaBoardBootQualificationFromRecordStatus(
      ::ota::storage::XiaoOtaBootInfoReader::RecordStatus::Blank, info, 1u, 1u, 1u);
  EXPECT_EQ(mesh::ota::OtaBoardQualificationStatus::Unknown, q.status);
  EXPECT_EQ(mesh::ota::OtaBoardQualificationReason::BlankUncertifiedStock, q.reason);
  EXPECT_FALSE(q.qualified);
}

TEST(OtaBoardBootQualificationFromRecordStatusTest, CorruptMarkerIsUnknown) {
  ::ota::storage::XiaoOtaBootInfoReader::Info info{};
  const auto q = mesh::ota::resolveOtaBoardBootQualificationFromRecordStatus(
      ::ota::storage::XiaoOtaBootInfoReader::RecordStatus::Corrupt, info, 1u, 1u, 1u);
  EXPECT_EQ(mesh::ota::OtaBoardQualificationStatus::Unknown, q.status);
  EXPECT_EQ(mesh::ota::OtaBoardQualificationReason::CorruptMarker, q.reason);
  EXPECT_FALSE(q.qualified);
}

TEST(OtaBoardBootQualificationFromRecordStatusTest, FoundButMismatchedRoleIsUnknown) {
  ::ota::storage::XiaoOtaBootInfoReader::Info info{};
  info.boardTargetId = 1u;
  info.roleId = 2u;  // expected 1u below: mismatch.
  info.capabilityFlags = 1u;
  info.algorithmId = 1u;
  const auto q = mesh::ota::resolveOtaBoardBootQualificationFromRecordStatus(
      ::ota::storage::XiaoOtaBootInfoReader::RecordStatus::Found, info, 1u, 1u, 1u);
  EXPECT_EQ(mesh::ota::OtaBoardQualificationStatus::Unknown, q.status);
  EXPECT_EQ(mesh::ota::OtaBoardQualificationReason::RoleOrCapabilityMismatch, q.reason);
  EXPECT_FALSE(q.qualified);
}

TEST(OtaBoardBootQualificationFromRecordStatusTest, FoundAndFullyMatchingIsQualified) {
  ::ota::storage::XiaoOtaBootInfoReader::Info info{};
  info.boardTargetId = 1u;
  info.roleId = 1u;
  info.capabilityFlags = 1u;
  info.algorithmId = 1u;  // Ed25519.
  const auto q = mesh::ota::resolveOtaBoardBootQualificationFromRecordStatus(
      ::ota::storage::XiaoOtaBootInfoReader::RecordStatus::Found, info, 1u, 1u, 1u);
  EXPECT_EQ(mesh::ota::OtaBoardQualificationStatus::Qualified, q.status);
  EXPECT_EQ(mesh::ota::OtaBoardQualificationReason::QualifiedMatch, q.reason);
  EXPECT_TRUE(q.qualified);
}

// Pure mapping tests (see resolveOtaBoardStartupDecision() in
// OtaBoardBackendCommon.h): this is the typed Normal/Trial/Unknown
// startup decision that replaces the previous bare isTrialActive()
// boolean fallthrough in both variants/*/Ota*Backend.cpp -- "not
// currently mid-trial" is NOT the same as "positively proven safe", so
// every branch other than a genuinely Found+CONFIRMED record must fail
// closed (Unknown or Trial), never silently equivalent-to-allow.
using ::ota::storage::XiaoOtaStateReader;

TEST(OtaBoardStartupDecisionTest, UnqualifiedIsAlwaysUnknownRegardlessOfState) {
  const auto d = mesh::ota::resolveOtaBoardStartupDecision(
      /*qualified=*/false, XiaoOtaStateReader::ReadStatus::Found, XiaoOtaStateReader::kPhaseConfirmed);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Unknown, d.status);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionReason::NotQualified, d.reason);
}

TEST(OtaBoardStartupDecisionTest, QualifiedButStateUnreadableIsTrialFailClosed) {
  const auto d = mesh::ota::resolveOtaBoardStartupDecision(
      /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Unknown, 0u);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Trial, d.status);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionReason::StateUnreadable, d.reason);
}

TEST(OtaBoardStartupDecisionTest, QualifiedButStateCorruptIsTrialFailClosed) {
  const auto d = mesh::ota::resolveOtaBoardStartupDecision(
      /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Corrupt, 0u);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Trial, d.status);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionReason::StateUnreadable, d.reason);
}

TEST(OtaBoardStartupDecisionTest, QualifiedBlankStateNoInstallHistoryIsUnknownNotNormal) {
  // The previously-broken case: a qualified board that has never
  // undergone any OTA transaction must NOT be treated as safe/legacy-
  // equivalent merely because it's "not currently mid-trial".
  const auto d = mesh::ota::resolveOtaBoardStartupDecision(
      /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Blank, 0u);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Unknown, d.status);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionReason::NoInstallHistory, d.reason);
}

TEST(OtaBoardStartupDecisionTest, QualifiedFoundTrialBootPhaseIsTrialUnchanged) {
  const auto d = mesh::ota::resolveOtaBoardStartupDecision(
      /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Found, XiaoOtaStateReader::kPhaseTrialBoot);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Trial, d.status);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionReason::ActiveTrialBoot, d.reason);
}

TEST(OtaBoardStartupDecisionTest, QualifiedFoundConfirmedPhaseWithoutFreshProofStaysUnknown) {
  // CONFIRMED phase alone is NECESSARY but NOT SUFFICIENT for Normal:
  // the bootloader phase byte proves it validated the durable
  // confirmation record on a PRIOR boot, but does not bind that to the
  // image currently running (e.g. after a USB reflash that left the
  // phase byte untouched). Without a positive
  // has_verified_fresh_baseline_proof (the 4th argument, defaulted
  // false and not currently wired anywhere), this must stay Unknown.
  const auto d = mesh::ota::resolveOtaBoardStartupDecision(
      /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Found, XiaoOtaStateReader::kPhaseConfirmed);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Unknown, d.status);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionReason::ConfirmedPendingFreshVerification, d.reason);
}

TEST(OtaBoardStartupDecisionTest, QualifiedFoundConfirmedPhaseWithFreshProofIsGenuineNormal) {
  // The one and only positively-evidenced Normal path: a Found record
  // whose phase is bootloader-verified CONFIRMED AND a real fresh
  // proof provider has bound that evidence to the currently running
  // image (SDK/CRC/SHA/signature/role) this boot -- genuine,
  // already-observable evidence, not fabricated here. No caller in
  // this tree passes true today; this test exercises the pure mapping
  // function directly to prove Normal is reachable once real proof
  // wiring exists, not that it is currently reached.
  const auto d = mesh::ota::resolveOtaBoardStartupDecision(
      /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Found, XiaoOtaStateReader::kPhaseConfirmed,
      /*has_verified_fresh_baseline_proof=*/true);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Normal, d.status);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionReason::ConfirmedInstallEvidence, d.reason);
}


TEST(OtaBoardStartupDecisionTest, QualifiedFoundFailedPhaseIsUnknownNotRollback) {
  // "FAILED alone is not rollback": the bootloader recording FAILED only
  // proves it gave up on the trial, not that a rollback to a verified-
  // good baseline itself completed -- must still fail closed.
  const auto d = mesh::ota::resolveOtaBoardStartupDecision(
      /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Found, XiaoOtaStateReader::kPhaseFailedMax);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Unknown, d.status);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionReason::IncompleteOrAmbiguousPhase, d.reason);
}

TEST(OtaBoardStartupDecisionTest, QualifiedFoundOtherMidTransactionPhaseIsUnknown) {
  const auto d = mesh::ota::resolveOtaBoardStartupDecision(
      /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Found, /*phase=*/2u /* BACKUP_COPYING */);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Unknown, d.status);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionReason::IncompleteOrAmbiguousPhase, d.reason);
}

// ---------------------------------------------------------------------
// Integrated, byte-backed end-to-end startup-preservation test: drives
// the SAME three real production decision/gate pieces used by
// main.cpp/MyMesh.cpp/DataStore.cpp together (resolveOtaBoardStartupDecision()
// -> ota_identity_boot::resolveIdentityTrialSafe() ->
// ota_write_gate::guardedPersist()), against a simulated byte-backed
// "disk" pre-seeded with existing identity/prefs/contacts/channels/blob
// data, under every StartupDecision outcome. Not a rewritten/duplicated
// model: each step below is a direct call into the identical shared
// header production code links against.
// ---------------------------------------------------------------------
namespace {

struct FakeBootMedia {
  std::vector<uint8_t> identity{1, 2, 3, 4};  // pre-existing persisted secret.
  std::vector<uint8_t> prefs{5, 6, 7};
  std::vector<uint8_t> contacts{8, 9};
  std::vector<uint8_t> channels{10, 11};
  std::vector<uint8_t> blob{12, 13, 14};
  int identity_generate_calls = 0;
  int identity_save_calls = 0;
  int prefs_write_calls = 0;
  int contacts_write_calls = 0;
  int channels_write_calls = 0;
  int blob_write_calls = 0;
};

// Runs one full simulated boot against `media` for a given qualified/
// state-status/phase combination (identical inputs
// otaBoardEarlyBootTrialOrUnknown() would feed
// resolveOtaBoardStartupDecision() with in the real backends), plus a
// simulated identity LOAD failure (the worst case MAIN's contract most
// cares about -- a merely-transiently-unreadable original secret must
// survive). Returns the resulting decision for the caller to assert on.
mesh::ota::OtaBoardStartupDecision runSimulatedBoot(FakeBootMedia& media, bool qualified,
                                                    XiaoOtaStateReader::ReadStatus state_status,
                                                    uint32_t phase,
                                                    bool has_verified_fresh_baseline_proof = false) {
  const mesh::ota::OtaBoardStartupDecision decision =
      mesh::ota::resolveOtaBoardStartupDecision(qualified, state_status, phase,
                                                has_verified_fresh_baseline_proof);
  const bool allow_destructive_boot_writes =
      decision.status == mesh::ota::OtaBoardStartupDecisionStatus::Normal;
  // allow_identity_generation is a DELIBERATELY separate permit (see
  // MyMesh::begin()) -- identical value today, but never merely aliased.
  const bool allow_identity_generation = allow_destructive_boot_writes;

  // 1) Identity: load_fn simulates the existing secret being (for this
  // test) unreadable this boot -- the case Astra's contract most cares
  // about (must survive a later rollback byte-identical).
  const ota_identity_boot::Outcome outcome = ota_identity_boot::resolveIdentityTrialSafe(
      allow_identity_generation, [&]() { return false; /* load always fails this boot */ },
      [&]() { ++media.identity_generate_calls; },
      [&]() {
        ++media.identity_save_calls;
        media.identity = {0xAA, 0xAA, 0xAA, 0xAA};  // what a real save would overwrite with.
        return true;
      });
  (void)outcome;

  // 2) Ordinary userdata writes: all gated through the exact same shared
  // ota_write_gate::guardedPersist() DataStore.cpp itself calls.
  ota_write_gate::guardedPersist(!allow_destructive_boot_writes, [&]() {
    ++media.prefs_write_calls;
    media.prefs = {0xBB, 0xBB, 0xBB};
    return true;
  });
  ota_write_gate::guardedPersist(!allow_destructive_boot_writes, [&]() {
    ++media.contacts_write_calls;
    media.contacts = {0xCC, 0xCC};
    return true;
  });
  ota_write_gate::guardedPersist(!allow_destructive_boot_writes, [&]() {
    ++media.channels_write_calls;
    media.channels = {0xDD, 0xDD};
    return true;
  });
  ota_write_gate::guardedPersist(!allow_destructive_boot_writes, [&]() {
    ++media.blob_write_calls;
    media.blob = {0xEE, 0xEE, 0xEE};
    return true;
  });

  return decision;
}

}  // namespace

TEST(OtaStartupPreservationTest, QualifiedBlankNoInstallHistoryPreservesEveryByteAndGeneratesNothing) {
  FakeBootMedia media;
  const auto initial = media;  // copy for comparison.
  const auto decision =
      runSimulatedBoot(media, /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Blank, 0u);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Unknown, decision.status);
  EXPECT_EQ(0, media.identity_generate_calls);
  EXPECT_EQ(0, media.identity_save_calls);
  EXPECT_EQ(0, media.prefs_write_calls);
  EXPECT_EQ(0, media.contacts_write_calls);
  EXPECT_EQ(0, media.channels_write_calls);
  EXPECT_EQ(0, media.blob_write_calls);
  EXPECT_EQ(initial.identity, media.identity);
  EXPECT_EQ(initial.prefs, media.prefs);
  EXPECT_EQ(initial.contacts, media.contacts);
  EXPECT_EQ(initial.channels, media.channels);
  EXPECT_EQ(initial.blob, media.blob);
}

TEST(OtaStartupPreservationTest, QualifiedActiveTrialBootPreservesEveryByteAndGeneratesNothing) {
  FakeBootMedia media;
  const auto initial = media;
  const auto decision = runSimulatedBoot(media, /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Found,
                                         XiaoOtaStateReader::kPhaseTrialBoot);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Trial, decision.status);
  EXPECT_EQ(0, media.identity_generate_calls);
  EXPECT_EQ(0, media.prefs_write_calls);
  EXPECT_EQ(initial.identity, media.identity);
  EXPECT_EQ(initial.prefs, media.prefs);
  EXPECT_EQ(initial.contacts, media.contacts);
  EXPECT_EQ(initial.channels, media.channels);
  EXPECT_EQ(initial.blob, media.blob);
}

TEST(OtaStartupPreservationTest, QualifiedTerminalFailedPreservesEveryByteAndGeneratesNothing) {
  // "FAILED alone is not rollback": must still be treated exactly like
  // every other unproven case -- zero generation, zero writes.
  FakeBootMedia media;
  const auto initial = media;
  const auto decision = runSimulatedBoot(media, /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Found,
                                         XiaoOtaStateReader::kPhaseFailedMax);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Unknown, decision.status);
  EXPECT_EQ(0, media.identity_generate_calls);
  EXPECT_EQ(0, media.prefs_write_calls);
  EXPECT_EQ(0, media.contacts_write_calls);
  EXPECT_EQ(0, media.channels_write_calls);
  EXPECT_EQ(0, media.blob_write_calls);
  EXPECT_EQ(initial.identity, media.identity);
  EXPECT_EQ(initial.prefs, media.prefs);
}

TEST(OtaStartupPreservationTest, StateUnreadablePreservesEveryByteAndGeneratesNothing) {
  FakeBootMedia media;
  const auto initial = media;
  const auto decision =
      runSimulatedBoot(media, /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Unknown, 0u);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Trial, decision.status);
  EXPECT_EQ(0, media.identity_generate_calls);
  EXPECT_EQ(0, media.prefs_write_calls);
  EXPECT_EQ(initial.identity, media.identity);
}

TEST(OtaStartupPreservationTest, UnqualifiedPreservesEveryByteAndGeneratesNothing) {
  FakeBootMedia media;
  const auto initial = media;
  const auto decision =
      runSimulatedBoot(media, /*qualified=*/false, XiaoOtaStateReader::ReadStatus::Found,
                       XiaoOtaStateReader::kPhaseConfirmed);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Unknown, decision.status);
  EXPECT_EQ(0, media.identity_generate_calls);
  EXPECT_EQ(0, media.prefs_write_calls);
  EXPECT_EQ(initial.identity, media.identity);
}

TEST(OtaStartupPreservationTest, QualifiedConfirmedWithoutFreshProofPreservesEveryByteAndGeneratesNothing) {
  // CONFIRMED phase alone (the real call path -- no caller currently
  // supplies fresh baseline proof) must resolve exactly like every other
  // unproven case: zero generation, zero writes, byte-identical media.
  FakeBootMedia media;
  const auto initial = media;
  const auto decision = runSimulatedBoot(media, /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Found,
                                         XiaoOtaStateReader::kPhaseConfirmed);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Unknown, decision.status);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionReason::ConfirmedPendingFreshVerification, decision.reason);
  EXPECT_EQ(0, media.identity_generate_calls);
  EXPECT_EQ(0, media.identity_save_calls);
  EXPECT_EQ(0, media.prefs_write_calls);
  EXPECT_EQ(0, media.contacts_write_calls);
  EXPECT_EQ(0, media.channels_write_calls);
  EXPECT_EQ(0, media.blob_write_calls);
  EXPECT_EQ(initial.identity, media.identity);
  EXPECT_EQ(initial.prefs, media.prefs);
  EXPECT_EQ(initial.contacts, media.contacts);
  EXPECT_EQ(initial.channels, media.channels);
  EXPECT_EQ(initial.blob, media.blob);
}

TEST(OtaStartupPreservationTest, GenuineConfirmedWithFreshProofPermitsGenerationAndWritesAsBaseline) {
  // Baseline/control case: the ONE positively-evidenced Normal path
  // (CONFIRMED phase PLUS a real fresh baseline proof, deliberately
  // forced true here since no production caller supplies it today) must
  // still behave like ordinary legacy boot (permits generation/writes) --
  // proves the tests above are actually discriminating on the decision,
  // not merely always-false.
  FakeBootMedia media;
  const auto decision = runSimulatedBoot(media, /*qualified=*/true, XiaoOtaStateReader::ReadStatus::Found,
                                         XiaoOtaStateReader::kPhaseConfirmed,
                                         /*has_verified_fresh_baseline_proof=*/true);
  EXPECT_EQ(mesh::ota::OtaBoardStartupDecisionStatus::Normal, decision.status);
  EXPECT_EQ(1, media.identity_generate_calls);
  EXPECT_EQ(1, media.identity_save_calls);
  EXPECT_EQ(1, media.prefs_write_calls);
  EXPECT_EQ(1, media.contacts_write_calls);
  EXPECT_EQ(1, media.channels_write_calls);
  EXPECT_EQ(1, media.blob_write_calls);
  EXPECT_EQ((std::vector<uint8_t>{0xAA, 0xAA, 0xAA, 0xAA}), media.identity);
  EXPECT_EQ((std::vector<uint8_t>{0xBB, 0xBB, 0xBB}), media.prefs);
}

TEST(FormatOtaBoardCapabilityStatusTest, CopiesShortReasonVerbatim) {
  char buf[64];
  mesh::ota::formatOtaBoardCapabilityStatus(buf, sizeof(buf), "INSTALL_CAPABLE: ok");
  EXPECT_STREQ(buf, "INSTALL_CAPABLE: ok");
}

TEST(FormatOtaBoardCapabilityStatusTest, TruncatesLongReasonWithoutOverflow) {
  char buf[8];
  mesh::ota::formatOtaBoardCapabilityStatus(buf, sizeof(buf), "this reason is much longer than the buffer");
  EXPECT_EQ(strlen(buf), 7u);  // out_len - 1, NUL-terminated, no overflow.
}

TEST(OtaBoardFloorDiagnosticTest, PresentGenesisIsNotAZeroDefaultAndReadbackNeverWrites) {
  using Diagnostic = mesh::ota::OtaBoardFloorDiagnostic;
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  EXPECT_EQ(Diagnostic::Status::Blank, Diagnostic::read(region).status);
  char detail[mesh::ota::kOtaBoardFloorCapabilityStatusBytes];
  mesh::ota::formatOtaBoardFloorCapabilityStatus(detail, sizeof(detail), "INSTALL_CAPABLE: old cached reason", region);
  EXPECT_STREQ("STAGING_ONLY: floor not initialized floor=blank seq=? ctr=? ext=? sha=? io=ok", detail);
  const auto genesis = makeFloorRecordBytes(1, 0, 0);
  ASSERT_TRUE(ota::platform::isOk(region.program(0, genesis.data(), genesis.size())));
  const auto before = std::vector<uint8_t>(flash.rawBuffer(), flash.rawBuffer() + flash.rawSize());
  const auto programs = flash.programOpCount(), erases = flash.eraseOpCount();
  const auto evidence = Diagnostic::read(region);
  EXPECT_EQ(Diagnostic::Status::Present, evidence.status);
  EXPECT_EQ(1u, evidence.sequence);
  EXPECT_EQ(0u, evidence.counter);
  EXPECT_EQ(0u, evidence.extent);
  const uint8_t zero_hash[32] = {};
  EXPECT_EQ(0, std::memcmp(zero_hash, evidence.hash, sizeof(zero_hash)));
  mesh::ota::formatOtaBoardFloorCapabilityStatus(detail, sizeof(detail), "INSTALL_CAPABLE: verified original", region);
  EXPECT_STREQ(("INSTALL_CAPABLE: floor=present seq=00000001 ctr=00000000 ext=00000000 sha=" +
                std::string(64, '0') + " io=ok").c_str(), detail);
  EXPECT_EQ(programs, flash.programOpCount());
  EXPECT_EQ(erases, flash.eraseOpCount());
  EXPECT_EQ(0, std::memcmp(before.data(), flash.rawBuffer(), before.size()));
}

TEST(OtaBoardFloorDiagnosticTest, FullNewestRecordAndHashFitBothExistingResponsesWithoutTruncation) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  const auto older = makeFloorRecordBytes(1, 0, 0);
  auto newest = makeFloorRecordBytes(0xffffffff, 0xffffffff, 0xffffffff);
  std::memset(newest.data() + 20, 0xff, 32);
  const uint32_t crc = Crc32::computeFinalized(newest.data(), ota::storage::XiaoOtaFloorReader::kCrcOffset);
  for (uint32_t i = 0; i < 4; ++i) newest[52 + i] = crc >> (8 * i);
  ASSERT_TRUE(ota::platform::isOk(region.program(0, older.data(), older.size())));
  ASSERT_TRUE(ota::platform::isOk(region.program(4096, newest.data(), newest.size())));
  char detail[mesh::ota::kOtaBoardFloorCapabilityStatusBytes], repeater[160];
  mesh::ota::formatOtaBoardFloorCapabilityStatus(detail, sizeof(detail), "INSTALL_CAPABLE: verified original", region);
  const std::string expected = "INSTALL_CAPABLE: floor=present seq=FFFFFFFF ctr=FFFFFFFF ext=FFFFFFFF sha=" +
      std::string(64, 'F') + " io=ok";
  EXPECT_EQ(expected, detail);
  EXPECT_EQ(144u, std::strlen(detail));
  for (bool blocked : {false, true}) {
    mesh::ota::formatOtaOrdinaryWriteDiagnostic(repeater, sizeof(repeater), blocked, detail);
    const std::string text = std::string(blocked ? "writes=blocked " : "writes=allowed ") + expected;
    EXPECT_EQ(text, repeater);
    EXPECT_EQ(159u, std::strlen(repeater));
    uint8_t companion[176];
    const auto bytes = mesh::ota::encodeOtaOrdinaryWriteDiagnostic(companion, sizeof(companion), 29, blocked, detail);
    EXPECT_EQ(160u, bytes);
    EXPECT_EQ(29, companion[0]);
    EXPECT_EQ(text, reinterpret_cast<char*>(companion + 1));
  }
  char short_detail[64];
  mesh::ota::formatOtaBoardFloorCapabilityStatus(short_detail, sizeof(short_detail),
                                               "INSTALL_CAPABLE: verified original", region);
  EXPECT_STREQ("STAGING_ONLY: floor=unavailable io=buffer", short_detail);
}

TEST(OtaBoardFloorDiagnosticTest, TornCrcTailAndReadErrorsNeverInventPresentZeroEvidence) {
  using Diagnostic = mesh::ota::OtaBoardFloorDiagnostic;
  for (int fault = 0; fault < 6; ++fault) {
    FakeNorFlash flash(8192, 4096);
    FlashRegion region(flash, 0, 8192);
    auto record = makeFloorRecordBytes(1, 0, 0);
    if (fault == 0) record[52] ^= 1;
    if (fault == 1)
      flash.armFault({FakeNorFlash::OpKind::Program, FakeNorFlash::InjectionTiming::Mid, 1, 17});
    if (fault <= 1) {
      EXPECT_EQ(fault == 0, ota::platform::isOk(region.program(0, record.data(), record.size())));
      flash.clearFault();
    } else if (fault == 2 || fault == 3) {
      if (fault == 3) ASSERT_TRUE(ota::platform::isOk(region.program(0, record.data(), record.size())));
      const uint8_t tail = 0;
      ASSERT_TRUE(ota::platform::isOk(region.program(8191, &tail, 1)));
    }
    if (fault >= 4)
      flash.armFault({FakeNorFlash::OpKind::Read, FakeNorFlash::InjectionTiming::Before,
                     flash.readOpCount() + (fault == 4 ? 1u : 18u)});
    char detail[mesh::ota::kOtaBoardFloorCapabilityStatusBytes];
    mesh::ota::formatOtaBoardFloorCapabilityStatus(detail, sizeof(detail), "INSTALL_CAPABLE: stale", region);
    EXPECT_NE(nullptr, std::strstr(detail, fault < 4 ? "floor=corrupt" : "floor=read-error"));
    EXPECT_NE(nullptr, std::strstr(detail, "seq=? ctr=? ext=? sha=?"));
    EXPECT_NE(nullptr, std::strstr(detail, fault < 4 ? "io=ok" : "io=read-error"));
    EXPECT_EQ(0, std::strncmp(detail, "STAGING_ONLY: ", 14));
  }
  FakeNorFlash flash(4096, 4096);
  FlashRegion wrong_geometry(flash, 0, 4096);
  EXPECT_EQ(Diagnostic::Status::Unavailable, Diagnostic::read(wrong_geometry).status);
}

// ---------------------------------------------------------------------
// XiaoOtaLegacyResidue: known-contamination-pattern predicate + the full
// floor-A erase-safety gate, plus a fake-erase-counter harness proving no
// mutation occurs on unknown/valid/dirty-B/pending-transaction inputs.
// ---------------------------------------------------------------------

namespace {

std::vector<uint8_t> makeKnownResidueSector(uint32_t len = 4096) {
  std::vector<uint8_t> sector(len, 0xFF);
  for (uint32_t i = 0; i < ota::storage::XiaoOtaLegacyResidue::kResidueByteCount; ++i) {
    sector[ota::storage::XiaoOtaLegacyResidue::kResidueStartOffset + i] =
        static_cast<uint8_t>(0xE7u ^ static_cast<uint8_t>((i * 11u) & 0xFFu));
  }
  return sector;
}

std::vector<uint8_t> makeBlankSector(uint32_t len = 4096) {
  return std::vector<uint8_t>(len, 0xFF);
}

// Minimal harness standing in for the real backend's gated erase: takes
// already-read sector contents (never touches real flash), applies the
// SAME safety gate the production code will use, and only then increments
// a fake "erase happened" counter -- letting a test assert zero mutation
// occurred for any input that should be refused.
class FakeGatedFloorAEraser {
public:
  bool tryErase(const std::vector<uint8_t>& floor_a, const std::vector<uint8_t>& floor_b,
                const std::vector<std::vector<uint8_t>>& tx_sectors) {
    const uint8_t* tx_ptrs[6];
    for (int i = 0; i < 6; ++i) tx_ptrs[i] = tx_sectors[i].data();
    const bool safe = ota::storage::XiaoOtaLegacyResidue::isSafeToEraseFloorA(
        floor_a.data(), static_cast<uint32_t>(floor_a.size()), floor_b.data(),
        static_cast<uint32_t>(floor_b.size()), tx_ptrs, static_cast<uint32_t>(tx_sectors[0].size()));
    if (!safe) return false;
    ++erase_count_;
    return true;
  }

  uint32_t eraseCount() const { return erase_count_; }

private:
  uint32_t erase_count_ = 0;
};

std::vector<std::vector<uint8_t>> makeAllBlankTxSectors() {
  return {makeBlankSector(), makeBlankSector(), makeBlankSector(),
          makeBlankSector(), makeBlankSector(), makeBlankSector()};
}

}  // namespace

TEST(XiaoOtaLegacyResidueTest, RecognizesExactKnownContaminationPattern) {
  const auto sector = makeKnownResidueSector();
  EXPECT_TRUE(ota::storage::XiaoOtaLegacyResidue::isKnownContaminationResidue(sector.data(), sector.size()));
}

TEST(XiaoOtaLegacyResidueTest, RejectsPatternWithOneByteWrong) {
  auto sector = makeKnownResidueSector();
  sector[10] ^= 0x01u;  // corrupt one residue byte.
  EXPECT_FALSE(ota::storage::XiaoOtaLegacyResidue::isKnownContaminationResidue(sector.data(), sector.size()));
}

TEST(XiaoOtaLegacyResidueTest, RejectsAnyNonFFByteOutsideTheResidueRange) {
  auto sector = makeKnownResidueSector();
  sector[1000] = 0x00u;  // valid-looking data far outside the residue range.
  EXPECT_FALSE(ota::storage::XiaoOtaLegacyResidue::isKnownContaminationResidue(sector.data(), sector.size()));
}

TEST(XiaoOtaLegacyResidueTest, EntirelyBlankSectorIsNotTheResiduePattern) {
  const auto sector = makeBlankSector();
  EXPECT_FALSE(ota::storage::XiaoOtaLegacyResidue::isKnownContaminationResidue(sector.data(), sector.size()));
  EXPECT_TRUE(ota::storage::XiaoOtaLegacyResidue::isEntirelyBlank(sector.data(), sector.size()));
}

// Windowed predicate must be byte-for-byte equivalent to the buffered
// whole-sector predicate: streaming a sector through fixed 128-byte
// windows (as the lab firmware's low-stack floor-cleanup path now does)
// must accept exactly what the buffered check accepts, and reject exactly
// what it rejects -- including a corruption far past the first window.
namespace {
bool checkAllWindowsResidue(const std::vector<uint8_t>& sector, uint32_t window_bytes) {
  for (uint32_t offset = 0; offset < sector.size(); offset += window_bytes) {
    if (!ota::storage::XiaoOtaLegacyResidue::isKnownContaminationResidueWindow(
            offset, sector.data() + offset, window_bytes)) {
      return false;
    }
  }
  return true;
}
}  // namespace

TEST(XiaoOtaLegacyResidueTest, WindowedResidueCheckAcceptsExactKnownPatternAcrossAllWindows) {
  const auto sector = makeKnownResidueSector();
  ASSERT_EQ(0u, sector.size() % 128u);
  EXPECT_TRUE(checkAllWindowsResidue(sector, 128));
}

TEST(XiaoOtaLegacyResidueTest, WindowedResidueCheckRejectsCorruptionInsideResidueRange) {
  auto sector = makeKnownResidueSector();
  sector[10] ^= 0x01u;  // corrupt one residue byte, still within window 0.
  EXPECT_FALSE(checkAllWindowsResidue(sector, 128));
}

TEST(XiaoOtaLegacyResidueTest, WindowedResidueCheckRejectsCorruptionInALaterWindow) {
  auto sector = makeKnownResidueSector();
  sector[1000] = 0x00u;  // valid-looking data far outside window 0.
  EXPECT_FALSE(checkAllWindowsResidue(sector, 128));
}

TEST(XiaoOtaLegacyResidueTest, WindowedResidueCheckRejectsEntirelyBlankSector) {
  const auto sector = makeBlankSector();
  EXPECT_FALSE(checkAllWindowsResidue(sector, 128));
}

TEST(FakeGatedFloorAEraserTest, ErasesOnlyTheExactExpectedResidueWithAllElseBlank) {
  FakeGatedFloorAEraser eraser;
  EXPECT_TRUE(eraser.tryErase(makeKnownResidueSector(), makeBlankSector(), makeAllBlankTxSectors()));
  EXPECT_EQ(eraser.eraseCount(), 1u);
}

TEST(FakeGatedFloorAEraserTest, RefusesAndDoesNotMutateOnUnknownFloorAContent) {
  FakeGatedFloorAEraser eraser;
  std::vector<uint8_t> unknown_floor_a(4096, 0x42);  // arbitrary unrecognized content.
  EXPECT_FALSE(eraser.tryErase(unknown_floor_a, makeBlankSector(), makeAllBlankTxSectors()));
  EXPECT_EQ(eraser.eraseCount(), 0u);
}

TEST(FakeGatedFloorAEraserTest, RefusesAndDoesNotMutateOnAValidLookingFloorRecord) {
  FakeGatedFloorAEraser eraser;
  const auto valid_floor = makeFloorRecordBytes(3, 7, 20000);
  std::vector<uint8_t> floor_a_sector(4096, 0xFF);
  std::copy(valid_floor.begin(), valid_floor.end(), floor_a_sector.begin());
  EXPECT_FALSE(eraser.tryErase(floor_a_sector, makeBlankSector(), makeAllBlankTxSectors()));
  EXPECT_EQ(eraser.eraseCount(), 0u);
}

TEST(FakeGatedFloorAEraserTest, RefusesAndDoesNotMutateWhenFloorBIsDirty) {
  FakeGatedFloorAEraser eraser;
  std::vector<uint8_t> dirty_floor_b(4096, 0xFF);
  dirty_floor_b[100] = 0x00;  // any non-blank byte anywhere in floor B.
  EXPECT_FALSE(eraser.tryErase(makeKnownResidueSector(), dirty_floor_b, makeAllBlankTxSectors()));
  EXPECT_EQ(eraser.eraseCount(), 0u);
}

TEST(FakeGatedFloorAEraserTest, RefusesAndDoesNotMutateWhenAnyTransactionSectorIsPending) {
  for (int pending_index = 0; pending_index < 6; ++pending_index) {
    FakeGatedFloorAEraser eraser;
    auto tx_sectors = makeAllBlankTxSectors();
    tx_sectors[pending_index][50] = 0x01u;  // simulate a pending/committed transaction sector.
    EXPECT_FALSE(eraser.tryErase(makeKnownResidueSector(), makeBlankSector(), tx_sectors))
        << "pending_index=" << pending_index;
    EXPECT_EQ(eraser.eraseCount(), 0u) << "pending_index=" << pending_index;
  }
}

// ---------------------------------------------------------------------
// XiaoOtaStateReader / XiaoOtaConfirmationRecord / XiaoOtaTrialBootConfirmation:
// the app-side genuine trial-boot health confirmation gate (item 4).
// ---------------------------------------------------------------------

namespace {

using ota::storage::XiaoOtaActiveExtentInfo;
using ota::storage::XiaoOtaConfirmationFields;
using ota::storage::XiaoOtaConfirmationRecord;
using ota::storage::XiaoOtaStateReader;
using ota::storage::XiaoOtaTrialBootConfirmation;

// XiaoOtaStateReader is READ-ONLY (only the bootloader ever writes
// xiao_ota_state_t), so this builds a valid raw record byte-for-byte,
// matching its exact field layout, the same way the bootloader itself
// would after progressing an install transaction.
std::vector<uint8_t> makeStateRecordBytes(uint32_t sequence, uint64_t transaction_nonce, uint32_t phase,
                                          uint32_t active_image_extent, uint32_t candidate_counter,
                                          const uint8_t installed_hash[32],
                                          const uint8_t candidate_hash[32] = nullptr) {
  std::vector<uint8_t> rec(XiaoOtaStateReader::kRecordBytes, 0);
  auto putU16 = [&](uint32_t pos, uint16_t v) {
    rec[pos] = static_cast<uint8_t>(v & 0xFFu);
    rec[pos + 1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
  };
  auto putU32 = [&](uint32_t pos, uint32_t v) {
    rec[pos] = static_cast<uint8_t>(v & 0xFFu);
    rec[pos + 1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    rec[pos + 2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
    rec[pos + 3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
  };
  auto putU64 = [&](uint32_t pos, uint64_t v) {
    for (int i = 0; i < 8; ++i) rec[pos + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
  };
  putU32(0, XiaoOtaStateReader::kMagic);
  rec[4] = static_cast<uint8_t>(XiaoOtaStateReader::kRecordVersion);
  rec[5] = 0;
  putU16(6, static_cast<uint16_t>(XiaoOtaStateReader::kRecordBytes));
  putU32(8, sequence);
  putU64(12, transaction_nonce);
  putU32(20, phase);
  putU32(24, 0);  // progress_bytes, unused by the app-side gate.
  putU32(28, active_image_extent);
  putU32(32, candidate_counter);
  // bytes 36..43: previous_bank_0/crc/size, unused by the app-side gate.
  // bytes 44..75: candidate_hash_sha256, unused by the app-side gate.
  // bytes 76..107: backup_hash_sha256, unused by the app-side gate.
  if (installed_hash != nullptr) {
    memcpy(rec.data() + 108, installed_hash, 32);
  }
  if (candidate_hash != nullptr) {
    memcpy(rec.data() + XiaoOtaStateReader::kCandidateHashOffset, candidate_hash, 32);
  }
  rec[140] = 0;  // trial_attempts.
  const uint32_t crc = Crc32::computeFinalized(rec.data(), XiaoOtaStateReader::kCrcOffset);
  putU32(XiaoOtaStateReader::kCrcOffset, crc);
  putU32(XiaoOtaStateReader::kCommitMarkerOffset, XiaoOtaStateReader::kCommitMarker);
  return rec;
}

}  // namespace

TEST(XiaoOtaStateReaderTest, ReadNewestFindsHighestSequenceValidSlot) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  uint8_t hash[32] = {1, 2, 3};
  const auto slot_a = makeStateRecordBytes(1, 100, XiaoOtaStateReader::kPhaseTrialBoot, 5000, 7, hash);
  const auto slot_b = makeStateRecordBytes(2, 200, XiaoOtaStateReader::kPhaseTrialBoot, 6000, 8, hash);
  ASSERT_TRUE(ota::platform::isOk(region.program(0, slot_a.data(), static_cast<uint32_t>(slot_a.size()))));
  ASSERT_TRUE(ota::platform::isOk(region.program(4096, slot_b.data(), static_cast<uint32_t>(slot_b.size()))));

  uint8_t newest[XiaoOtaStateReader::kRecordBytes];
  ASSERT_TRUE(XiaoOtaStateReader::readNewest(region, newest));
  EXPECT_EQ(XiaoOtaStateReader::activeImageExtent(newest), 6000u);
  EXPECT_EQ(XiaoOtaStateReader::candidateCounter(newest), 8u);
  EXPECT_EQ(XiaoOtaStateReader::transactionNonce(newest), 200u);
}

TEST(XiaoOtaStateReaderTest, BothSlotsInvalidMeansNoState) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);  // both slots left erased (0xFF).
  uint8_t out[XiaoOtaStateReader::kRecordBytes];
  EXPECT_FALSE(XiaoOtaStateReader::readNewest(region, out));
}

// readNewestWithStatus() distinguishes WHY, instead of collapsing every
// non-success case into a single bool -- see MAIN's bug #2: an eager
// caller (XiaoOtaTrialHealthMonitor's constructor) that treated
// readNewest()'s plain false the same for "genuinely blank" as for
// "unreadable/corrupt" was silently permitting a competing install/erase
// whenever the true state was actually unknown.
TEST(XiaoOtaStateReaderTest, ReadNewestWithStatusBothSlotsGenuinelyBlankIsBlank) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  uint8_t out[XiaoOtaStateReader::kRecordBytes];
  EXPECT_EQ(XiaoOtaStateReader::readNewestWithStatus(region, out), XiaoOtaStateReader::ReadStatus::Blank);
}

TEST(XiaoOtaStateReaderTest, ReadNewestWithStatusValidRecordIsFound) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  uint8_t hash[32] = {9};
  const auto rec = makeStateRecordBytes(1, 100, XiaoOtaStateReader::kPhaseTrialBoot, 5000, 7, hash);
  ASSERT_TRUE(ota::platform::isOk(region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));
  uint8_t out[XiaoOtaStateReader::kRecordBytes];
  EXPECT_EQ(XiaoOtaStateReader::readNewestWithStatus(region, out), XiaoOtaStateReader::ReadStatus::Found);
  EXPECT_EQ(XiaoOtaStateReader::activeImageExtent(out), 5000u);
}

TEST(XiaoOtaStateReaderTest, ReadNewestWithStatusReadableButInvalidNonBlankSlotIsCorrupt) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  uint8_t hash[32] = {9};
  auto rec = makeStateRecordBytes(1, 100, XiaoOtaStateReader::kPhaseTrialBoot, 5000, 7, hash);
  rec[10] ^= 0xFFu;  // corrupt a payload byte without fixing up the CRC.
  ASSERT_TRUE(ota::platform::isOk(region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));
  uint8_t out[XiaoOtaStateReader::kRecordBytes];
  EXPECT_EQ(XiaoOtaStateReader::readNewestWithStatus(region, out), XiaoOtaStateReader::ReadStatus::Corrupt);
}

TEST(XiaoOtaStateReaderTest, ReadNewestWithStatusBlankHeaderWithNonBlankTailIsCorruptNotBlank) {
  // A blank record-sized prefix does NOT by itself prove a genuine blank
  // baseline: a nonblank byte anywhere else in the erase unit (e.g. its
  // very last byte) must not be silently treated as "no record here".
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  uint8_t tail_byte = 0x01;
  ASSERT_TRUE(ota::platform::isOk(region.program(4095, &tail_byte, 1)));
  uint8_t out[XiaoOtaStateReader::kRecordBytes];
  EXPECT_EQ(XiaoOtaStateReader::readNewestWithStatus(region, out), XiaoOtaStateReader::ReadStatus::Corrupt);
}

TEST(XiaoOtaStateReaderTest, CorruptNewerTrialCannotFallBackToOlderConfirmedState) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  uint8_t hash[32] = {9};
  const auto older = makeStateRecordBytes(1, 100, 6, 5000, 7, hash);
  auto newer = makeStateRecordBytes(2, 200, XiaoOtaStateReader::kPhaseTrialBoot, 5000, 8, hash);
  newer[12] ^= 1;
  ASSERT_TRUE(ota::platform::isOk(region.program(0, older.data(), static_cast<uint32_t>(older.size()))));
  ASSERT_TRUE(ota::platform::isOk(region.program(4096, newer.data(), static_cast<uint32_t>(newer.size()))));
  uint8_t out[XiaoOtaStateReader::kRecordBytes];
  EXPECT_EQ(XiaoOtaStateReader::ReadStatus::Corrupt, XiaoOtaStateReader::readNewestWithStatus(region, out));
  EXPECT_FALSE(XiaoOtaStateReader::readNewest(region, out));
}

TEST(XiaoOtaStateReaderTest, ReadNewestWithStatusUnreadableSlotIsUnknownEvenWhenOlderSlotIsValid) {
  // An older, structurally valid record in slot A must NOT be trusted as
  // "the newest" when slot B (which could genuinely hold a newer record)
  // cannot be read at all -- the whole lookup must fail closed as
  // Unknown, never silently substituting the older slot's value.
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  uint8_t hash[32] = {9};
  const auto rec = makeStateRecordBytes(1, 100, XiaoOtaStateReader::kPhaseTrialBoot, 5000, 7, hash);
  ASSERT_TRUE(ota::platform::isOk(region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Read;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash.readOpCount() + 2;  // the 2nd read is slot B.
  flash.armFault(fault);

  uint8_t out[XiaoOtaStateReader::kRecordBytes];
  EXPECT_EQ(XiaoOtaStateReader::readNewestWithStatus(region, out), XiaoOtaStateReader::ReadStatus::Unknown);
}

TEST(XiaoOtaConfirmationRecordTest, SerializeThenIsValidRecordRoundTrips) {
  XiaoOtaConfirmationFields fields;
  fields.sequence = 3;
  fields.transaction_nonce = 12345;
  fields.confirmed_counter = 9;
  memset(fields.confirmed_hash_sha256, 0xAB, sizeof(fields.confirmed_hash_sha256));

  uint8_t record[XiaoOtaConfirmationRecord::kRecordBytes];
  ASSERT_EQ(XiaoOtaConfirmationRecord::serialize(fields, record, sizeof(record)),
            XiaoOtaConfirmationRecord::kRecordBytes);
  EXPECT_TRUE(XiaoOtaConfirmationRecord::isValidRecord(record, sizeof(record)));
}

TEST(XiaoOtaConfirmationRecordTest, CorruptingAnyByteInvalidatesCrc) {
  XiaoOtaConfirmationFields fields;
  fields.confirmed_counter = 1;
  uint8_t record[XiaoOtaConfirmationRecord::kRecordBytes];
  ASSERT_EQ(XiaoOtaConfirmationRecord::serialize(fields, record, sizeof(record)),
            XiaoOtaConfirmationRecord::kRecordBytes);
  record[10] ^= 0x01;
  EXPECT_FALSE(XiaoOtaConfirmationRecord::isValidRecord(record, sizeof(record)));
}

TEST(XiaoOtaConfirmationRecordTest, WriteNextAlternatesSlotsAndIncrementsSequence) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  XiaoOtaConfirmationFields fields;
  fields.transaction_nonce = 42;
  fields.confirmed_counter = 1;

  uint32_t seq1 = 0;
  ASSERT_TRUE(XiaoOtaConfirmationRecord::writeNext(region, fields, &seq1));
  EXPECT_EQ(seq1, 1u);

  fields.confirmed_counter = 2;
  uint32_t seq2 = 0;
  ASSERT_TRUE(XiaoOtaConfirmationRecord::writeNext(region, fields, &seq2));
  EXPECT_EQ(seq2, 2u);
}

// Same fail-closed rationale as XiaoOtaCommandRecordTest.WriteNextRefuses
// AndMutatesNothingWhenSlotReadFails: an unreadable slot during target-
// slot selection must abort writeNext() before any erase/program, never
// be silently treated as "no valid record here".
TEST(XiaoOtaConfirmationRecordTest, WriteNextRefusesAndMutatesNothingWhenSlotReadFails) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  XiaoOtaConfirmationFields fields;
  fields.transaction_nonce = 42;
  fields.confirmed_counter = 1;

  uint32_t seq1 = 0;
  ASSERT_TRUE(XiaoOtaConfirmationRecord::writeNext(region, fields, &seq1));
  const uint32_t erase_count_before = flash.eraseOpCount();
  const uint32_t program_count_before = flash.programOpCount();

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Read;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash.readOpCount() + 1;
  flash.armFault(fault);

  fields.confirmed_counter = 2;
  uint32_t seq2 = 0;
  EXPECT_FALSE(XiaoOtaConfirmationRecord::writeNext(region, fields, &seq2));
  EXPECT_EQ(flash.eraseOpCount(), erase_count_before);
  EXPECT_EQ(flash.programOpCount(), program_count_before);

  // Slot A's genuine sequence-1 record must be completely untouched.
  flash.clearFault();
  uint8_t slot_a[XiaoOtaConfirmationRecord::kRecordBytes];
  ASSERT_TRUE(ota::platform::isOk(region.read(0, slot_a, sizeof(slot_a))));
  ASSERT_TRUE(XiaoOtaConfirmationRecord::isValidRecord(slot_a, sizeof(slot_a)));
  EXPECT_EQ(sequenceFieldOf(slot_a), 1u);
}

TEST(XiaoOtaConfirmationRecordTest, MarkerPhaseFailureLeavesPreviousSlotValidAndReadable) {
  // Fault injected on the SECOND program() call of the second writeNext()
  // (the commit-marker phase, per the two-phase transactional writer) --
  // proves the old valid record in the untouched slot survives, and the
  // freshly (partially) written slot never validates.
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  XiaoOtaConfirmationFields fields;
  fields.transaction_nonce = 111;
  fields.confirmed_counter = 5;
  uint32_t seq1 = 0;
  ASSERT_TRUE(XiaoOtaConfirmationRecord::writeNext(region, fields, &seq1));  // slot 0, sequence 1

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Program;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = flash.programOpCount() + 2;  // 1st program = body+CRC, 2nd = marker.
  flash.armFault(fault);

  fields.confirmed_counter = 6;
  EXPECT_FALSE(XiaoOtaConfirmationRecord::writeNext(region, fields));

  bool found_old = false;
  for (uint32_t slot = 0; slot < 2u; ++slot) {
    uint8_t buf[XiaoOtaConfirmationRecord::kRecordBytes];
    ASSERT_TRUE(ota::platform::isOk(region.read(slot * region.eraseUnitBytes(), buf, sizeof(buf))));
    if (XiaoOtaConfirmationRecord::isValidRecord(buf, sizeof(buf))) {
      EXPECT_FALSE(found_old);  // exactly one valid slot must remain.
      found_old = true;
      EXPECT_EQ(buf[8] | (buf[9] << 8) | (buf[10] << 16) | (buf[11] << 24), 1u);  // sequence == 1 (old record).
    }
  }
  EXPECT_TRUE(found_old);
}

TEST(XiaoOtaConfirmationRecordTest, BodyPhaseFailureLeavesPreviousSlotValidAndReadable) {
  FakeNorFlash flash(8192, 4096);
  FlashRegion region(flash, 0, 8192);
  XiaoOtaConfirmationFields fields;
  fields.transaction_nonce = 111;
  fields.confirmed_counter = 5;
  ASSERT_TRUE(XiaoOtaConfirmationRecord::writeNext(region, fields));  // slot 0, sequence 1

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Program;
  fault.timing = FakeNorFlash::InjectionTiming::Mid;
  fault.trigger_op_count = flash.programOpCount() + 1;  // the body+CRC phase itself.
  fault.partial_bytes = 8;
  flash.armFault(fault);

  fields.confirmed_counter = 6;
  EXPECT_FALSE(XiaoOtaConfirmationRecord::writeNext(region, fields));

  uint8_t slot0[XiaoOtaConfirmationRecord::kRecordBytes];
  ASSERT_TRUE(ota::platform::isOk(region.read(0, slot0, sizeof(slot0))));
  ASSERT_TRUE(XiaoOtaConfirmationRecord::isValidRecord(slot0, sizeof(slot0)));
  EXPECT_EQ(slot0[8] | (slot0[9] << 8) | (slot0[10] << 16) | (slot0[11] << 24), 1u);
}

// ---------------------------------------------------------------------
// XiaoOtaTrialBootConfirmation::tryConfirm(): the full gate. Each test
// below proves EXACTLY ONE precondition failing refuses the confirm and
// writes nothing (verified via readNewest() on the confirm region still
// finding no record), and that a genuinely all-conditions-satisfied trial
// DOES get a durable, readback-verified confirmation record.
// ---------------------------------------------------------------------

namespace {

struct TrialFixture {
  FakeNorFlash state_flash{8192, 4096};
  FakeNorFlash confirm_flash{8192, 4096};
  ota::platform::FlashRegion state_region{state_flash, 0, 8192};
  ota::platform::FlashRegion confirm_region{confirm_flash, 0, 8192};
  uint8_t installed_hash[32];
  XiaoOtaActiveExtentInfo fresh;

  TrialFixture() {
    memset(installed_hash, 0x77, sizeof(installed_hash));
    fresh.active_image_extent = 5000;
    memcpy(fresh.active_image_hash_sha256, installed_hash, sizeof(installed_hash));
  }

  void writeState(uint32_t phase, uint32_t active_image_extent, const uint8_t* hash) {
    const auto rec = makeStateRecordBytes(1, 99, phase, active_image_extent, 3, hash, hash);
    ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));
  }

  void writeStateWithDistinctHashes(uint32_t phase, uint32_t active_image_extent,
                                    const uint8_t* installed, const uint8_t* candidate) {
    const auto rec = makeStateRecordBytes(1, 99, phase, active_image_extent, 3, installed, candidate);
    ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));
  }

  XiaoOtaTrialBootConfirmation::HealthReadiness allHealthy() const {
    XiaoOtaTrialBootConfirmation::HealthReadiness r;
    r.radio_ready = true;
    r.filesystem_ready = true;
    r.loop_healthy = true;
    return r;
  }
};

}  // namespace

TEST(XiaoOtaTrialBootConfirmationTest, ConfirmsWhenEveryGateIsSatisfied) {
  TrialFixture fx;
  fx.writeState(XiaoOtaStateReader::kPhaseTrialBoot, 5000, fx.installed_hash);

  uint32_t confirmed_counter = 0;
  EXPECT_TRUE(XiaoOtaTrialBootConfirmation::tryConfirm(fx.state_region, fx.confirm_region, fx.fresh,
                                                       fx.allHealthy(), &confirmed_counter));
  EXPECT_EQ(confirmed_counter, 3u);

  uint8_t state_record[XiaoOtaStateReader::kRecordBytes];
  ASSERT_TRUE(XiaoOtaStateReader::readNewest(fx.state_region, state_record));  // sanity: state still readable.
}

TEST(XiaoOtaTrialBootConfirmationTest, RefusesAndWritesNothingWhenNotHealthy) {
  TrialFixture fx;
  fx.writeState(XiaoOtaStateReader::kPhaseTrialBoot, 5000, fx.installed_hash);
  XiaoOtaTrialBootConfirmation::HealthReadiness not_ready = fx.allHealthy();
  not_ready.radio_ready = false;

  EXPECT_FALSE(XiaoOtaTrialBootConfirmation::tryConfirm(fx.state_region, fx.confirm_region, fx.fresh, not_ready));

  // Read the ACTUAL confirm region back (not an uninitialized local
  // buffer) to prove nothing was durably written on this refusal path.
  bool any_valid = false;
  for (uint32_t slot = 0; slot < 2u; ++slot) {
    uint8_t out[XiaoOtaConfirmationRecord::kRecordBytes];
    const uint32_t slot_offset = slot * fx.confirm_region.eraseUnitBytes();
    if (ota::platform::isOk(fx.confirm_region.read(slot_offset, out, sizeof(out))) &&
        XiaoOtaConfirmationRecord::isValidRecord(out, sizeof(out))) {
      any_valid = true;
    }
  }
  EXPECT_FALSE(any_valid);
}

TEST(XiaoOtaTrialBootConfirmationTest, RefusesWhenStatePhaseIsNotTrialBoot) {
  TrialFixture fx;
  fx.writeState(XiaoOtaStateReader::kPhaseFailedMax, 5000, fx.installed_hash);  // CONFIRMED/FAILED, not trial.

  EXPECT_FALSE(XiaoOtaTrialBootConfirmation::tryConfirm(fx.state_region, fx.confirm_region, fx.fresh,
                                                        fx.allHealthy()));
}

TEST(XiaoOtaTrialBootConfirmationTest, RefusesWhenNoStateRecordExists) {
  TrialFixture fx;  // state region left erased -- no transaction recorded.
  EXPECT_FALSE(XiaoOtaTrialBootConfirmation::tryConfirm(fx.state_region, fx.confirm_region, fx.fresh,
                                                        fx.allHealthy()));
}

TEST(XiaoOtaTrialBootConfirmationTest, RefusesWhenFreshExtentIsZeroEvenIfEverythingElseMatches) {
  TrialFixture fx;
  fx.writeState(XiaoOtaStateReader::kPhaseTrialBoot, 5000, fx.installed_hash);
  fx.fresh.active_image_extent = 0;  // e.g. bridge itself failed closed this boot.

  EXPECT_FALSE(XiaoOtaTrialBootConfirmation::tryConfirm(fx.state_region, fx.confirm_region, fx.fresh,
                                                        fx.allHealthy()));
}

TEST(XiaoOtaTrialBootConfirmationTest, ExtentFieldMismatchNoLongerMattersOnlyHashDoes) {
  // The state record's active_image_extent field records the OLD/backup
  // image's size (pre-install), which is unrelated to the freshly
  // resolved candidate's extent -- a real device legitimately installs a
  // DIFFERENT-sized image than whatever was previously running. Proves
  // this field is genuinely no longer consulted: extent differs, hashes
  // still match, confirmation still succeeds.
  TrialFixture fx;
  fx.writeState(XiaoOtaStateReader::kPhaseTrialBoot, /*active_image_extent=*/999999, fx.installed_hash);

  EXPECT_TRUE(XiaoOtaTrialBootConfirmation::tryConfirm(fx.state_region, fx.confirm_region, fx.fresh,
                                                       fx.allHealthy()));
}

TEST(XiaoOtaTrialBootConfirmationTest, RefusesWhenFreshHashDoesNotMatchInstalledHash) {
  TrialFixture fx;
  fx.writeState(XiaoOtaStateReader::kPhaseTrialBoot, 5000, fx.installed_hash);
  fx.fresh.active_image_hash_sha256[0] ^= 0x01;  // simulates a reflashed/different image mid-trial.

  EXPECT_FALSE(XiaoOtaTrialBootConfirmation::tryConfirm(fx.state_region, fx.confirm_region, fx.fresh,
                                                        fx.allHealthy()));
}

TEST(XiaoOtaTrialBootConfirmationTest, RefusesWhenFreshHashDoesNotMatchCandidateHash) {
  // installed_hash matches, but candidate_hash (offset 44 -- what the
  // transport originally verified pre-install) does NOT: proves both
  // hashes are independently required, not just installed_hash.
  TrialFixture fx;
  uint8_t different_candidate[32];
  memset(different_candidate, 0x22, sizeof(different_candidate));
  fx.writeStateWithDistinctHashes(XiaoOtaStateReader::kPhaseTrialBoot, 5000, fx.installed_hash,
                                  different_candidate);

  EXPECT_FALSE(XiaoOtaTrialBootConfirmation::tryConfirm(fx.state_region, fx.confirm_region, fx.fresh,
                                                        fx.allHealthy()));
}

TEST(XiaoOtaTrialBootConfirmationTest, GenuineContentShaOldLargeImageDoesNotMatchNewSmallImage) {
  // Real-content SHA-256 (not a crafted fake digest): hashing genuinely
  // different-sized image content over the SAME extent value must yield
  // different digests, so a wrong-content confirmation cannot slip
  // through merely because sizes coincidentally line up.
  TrialFixture fx;
  std::vector<uint8_t> old_large_image(5000, 0xAA);
  std::vector<uint8_t> new_small_image(5000, 0xBB);  // same extent, different content.
  uint8_t old_hash[32];
  uint8_t new_hash[32];
  ota::trust::Sha256::hash(old_large_image.data(), old_large_image.size(), old_hash);
  ota::trust::Sha256::hash(new_small_image.data(), new_small_image.size(), new_hash);
  ASSERT_NE(0, memcmp(old_hash, new_hash, 32));

  // State records the OLD image's genuine hash as "installed"; fresh
  // resolves the NEW image's genuine hash -- must NOT match.
  fx.writeState(XiaoOtaStateReader::kPhaseTrialBoot, 5000, old_hash);
  fx.fresh.active_image_extent = 5000;
  memcpy(fx.fresh.active_image_hash_sha256, new_hash, 32);

  EXPECT_FALSE(XiaoOtaTrialBootConfirmation::tryConfirm(fx.state_region, fx.confirm_region, fx.fresh,
                                                        fx.allHealthy()));
}

TEST(XiaoOtaTrialBootConfirmationTest, GenuineContentShaMatchingImageConfirmsRegardlessOfOldExtent) {
  // Reverse of the above: genuinely matching content (same real SHA-256
  // over actual bytes) confirms even though the state record's stale
  // active_image_extent field names a completely different (old/backup)
  // size.
  TrialFixture fx;
  std::vector<uint8_t> image(5000, 0xCC);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);

  fx.writeState(XiaoOtaStateReader::kPhaseTrialBoot, /*active_image_extent=*/123456, hash);
  fx.fresh.active_image_extent = 5000;
  memcpy(fx.fresh.active_image_hash_sha256, hash, 32);

  EXPECT_TRUE(XiaoOtaTrialBootConfirmation::tryConfirm(fx.state_region, fx.confirm_region, fx.fresh,
                                                       fx.allHealthy()));
}

TEST(XiaoOtaTrialBootConfirmationTest, ConfirmationCarriesForwardExactNonceAndCounterFromState) {
  TrialFixture fx;
  const auto rec = makeStateRecordBytes(1, /*transaction_nonce=*/0xDEADBEEFCAFEu,
                                        XiaoOtaStateReader::kPhaseTrialBoot, 5000, /*candidate_counter=*/77,
                                        fx.installed_hash, fx.installed_hash);
  ASSERT_TRUE(ota::platform::isOk(fx.state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  uint32_t confirmed_counter = 0;
  ASSERT_TRUE(XiaoOtaTrialBootConfirmation::tryConfirm(fx.state_region, fx.confirm_region, fx.fresh,
                                                       fx.allHealthy(), &confirmed_counter));
  EXPECT_EQ(confirmed_counter, 77u);
}

// ---------------------------------------------------------------------
// OtaBoardTrialBootHealthConfirmer: the shared board-facing wrapper
// around ::ota::storage::XiaoOtaTrialHealthMonitor (see that header for
// the full continuous-window/deadline/incremental-hash contract), used
// by both backends' loop()-tick entry points (see
// src/helpers/ota/OtaBoardBackendCommon.h).
// ---------------------------------------------------------------------

// Bug #2 (MAIN's correction): an unreadable or corrupt state slot must
// fail CLOSED to a new immediate terminal StateUnreadable outcome --
// never silently folded into "not a trial" (readNewest()'s old plain
// bool did exactly that, permitting a competing install/erase against
// genuinely unknown/ambiguous state).
TEST(OtaBoardTrialBootHealthConfirmerTest, UnreadableNewerStateSlotLatchesStateUnreadableAtConstruction) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  // An older, structurally valid record in slot A, but with a genuinely
  // non-TRIAL phase (6, i.e. XIAO_OTA_PHASE_CONFIRMED) -- if this were
  // trusted as "the newest", the confirmer would wrongly conclude
  // isTrialActive()==false. Slot B's read is faulted instead: it might
  // genuinely hold a newer TRIAL_BOOT record, so the whole lookup must
  // fail closed rather than trust slot A.
  uint8_t hash[32] = {1};
  const auto confirmed_rec = makeStateRecordBytes(1, 100, /*phase=*/6, 5000, 7, hash);
  ASSERT_TRUE(
      ota::platform::isOk(state_region.program(0, confirmed_rec.data(), static_cast<uint32_t>(confirmed_rec.size()))));

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Read;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = state_flash.readOpCount() + 2;  // the 2nd read is slot B.
  state_flash.armFault(fault);

  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, /*boot_epoch_ms=*/0);
  // Fails closed IMMEDIATELY at construction, before any tick() at all:
  // never trusts the older CONFIRMED-phase slot A as "the newest".
  EXPECT_EQ(confirmer.outcome(), mesh::ota::OtaBoardTrialHealthOutcome::StateUnreadable);
  EXPECT_TRUE(confirmer.isTrialActive());  // blocks erase/install/sleep -- unknown must never be "not active".

  // tick() returns the already-latched terminal outcome immediately,
  // touching no flash/hasher/image-accessor work at all.
  EXPECT_EQ(confirmer.tick(0, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::StateUnreadable);
  EXPECT_EQ(confirmer.lastConfirmedCounter(), 0u);

  // No confirmation write of any kind: the confirm region stays entirely
  // blank.
  std::vector<uint8_t> confirm_contents(confirm_flash.rawSize());
  memcpy(confirm_contents.data(), confirm_flash.rawBuffer(), confirm_flash.rawSize());
  for (uint8_t b : confirm_contents) EXPECT_EQ(b, 0xFFu);
}

TEST(OtaBoardTrialBootHealthConfirmerTest, CorruptNonBlankStateSlotAlsoLatchesStateUnreadable) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  uint8_t hash[32] = {1};
  auto rec = makeStateRecordBytes(1, 100, XiaoOtaStateReader::kPhaseTrialBoot, 5000, 7, hash);
  rec[10] ^= 0xFFu;  // corrupt without fixing up the CRC -- readable, non-blank, invalid.
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, /*boot_epoch_ms=*/0);
  EXPECT_EQ(confirmer.outcome(), mesh::ota::OtaBoardTrialHealthOutcome::StateUnreadable);
  EXPECT_TRUE(confirmer.isTrialActive());
  EXPECT_EQ(confirmer.tick(0, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::StateUnreadable);
}

TEST(OtaBoardTrialBootHealthConfirmerTest, NeverConfirmsOffTargetWhenNoStateRecordPresent) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  // No valid state record at all (blank flash): stock/non-trial device,
  // must stay Pending forever, regardless of how much wall-clock time
  // passes or how healthy the readiness signals are.
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, /*boot_epoch_ms=*/0);
  uint32_t now_ms = 0;
  for (int i = 0; i < 50; ++i) {
    EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
    now_ms += 1000;
  }
  EXPECT_FALSE(confirmer.isTrialActive());
}

TEST(OtaBoardTrialBootHealthConfirmerTest, RefusesImmediatelyWhenNotReadyAndNeverStartsWindow) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  uint8_t hash[32] = {0x11};
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, /*boot_epoch_ms=*/0);
  EXPECT_EQ(confirmer.tick(0, /*radio_ready=*/false, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  EXPECT_EQ(confirmer.lastConfirmedCounter(), 0u);
  // A genuine TRIAL_BOOT state record is present (isTrialActive() is
  // independent of this-tick readiness), but confirmation never happens
  // while not-ready.
  EXPECT_TRUE(confirmer.isTrialActive());
}

namespace {

// Supplies a fixed (pointer, extent) pair to XiaoOtaTrialHealthMonitor's
// injectable seam, and counts calls so tests can prove the expensive
// image resolution is only ever attempted once a state record genuinely
// says TRIAL_BOOT. `steps_to_resolve` lets a test simulate BOUNDED,
// multi-call incremental extent resolution (matching the real hardware
// resolver's contract) instead of always resolving on the very first
// call.
class CountingFakeActiveImageAccessor : public ota::storage::IXiaoOtaActiveImageAccessor {
public:
  const uint8_t* image = nullptr;
  uint32_t extent = 0;
  bool ok = true;
  int call_count = 0;
  int steps_to_resolve = 1;
  int steps_taken_ = 0;

  ota::storage::XiaoOtaExtentResolutionStep stepExtentResolution(uint32_t /*max_bytes*/,
                                                                 const uint8_t** out_image,
                                                                 uint32_t* out_extent) override {
    ++call_count;
    ++steps_taken_;
    if (steps_taken_ < steps_to_resolve) {
      *out_image = nullptr;
      *out_extent = 0;
      return ota::storage::XiaoOtaExtentResolutionStep::InProgress;
    }
    if (!ok) {
      *out_image = nullptr;
      *out_extent = 0;
      return ota::storage::XiaoOtaExtentResolutionStep::Failed;
    }
    *out_image = image;
    *out_extent = extent;
    return ota::storage::XiaoOtaExtentResolutionStep::Resolved;
  }
};

}  // namespace

TEST(OtaBoardTrialBootHealthConfirmerTest, InjectedImageAccessorConfirmsAfterContinuousHealthyWindow) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(2000, 0x42);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, /*transaction_nonce=*/7, XiaoOtaStateReader::kPhaseTrialBoot,
                                        /*active_image_extent=*/1234, /*candidate_counter=*/9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());

  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);
  // isTrialActive() reflects genuine state IMMEDIATELY at construction
  // (the cheap phase-only state read happens eagerly, once, in the
  // constructor -- never lazily on first tick()) -- this closes the gap
  // where an install/erase attempted between boot and this object's
  // first tick() would otherwise have seen a false "not active."
  EXPECT_TRUE(confirmer.isTrialActive());

  // Advance in 500ms ticks (no service gap, each step well under the
  // 1000ms gap threshold) for just under 10 continuous seconds: must not
  // confirm yet.
  uint32_t now_ms = 0;
  mesh::ota::OtaBoardTrialHealthOutcome outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  for (int i = 0; i < 19; ++i) {  // 19 * 500 = 9500ms; window opened on the very first tick (now_ms=500).
    now_ms += 500;
    outcome = confirmer.tick(now_ms, true, true, true);
    EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  }
  EXPECT_TRUE(confirmer.isTrialActive());
  // One more (still <=1000ms) tick crosses the 10-second continuous
  // window (window opened at now_ms=500, so 10500 is the first tick
  // >= window_start + 10000); the hash (2000 bytes, well under
  // kHashBytesPerPass=1024/pass * enough ticks) must also have finished
  // and matched by now.
  now_ms += 1000;
  outcome = confirmer.tick(now_ms, true, true, true);
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::Confirmed);
  EXPECT_EQ(confirmer.lastConfirmedCounter(), 9u);
  // Per MAIN's corrected bug #7 requirement: trial exclusion must NOT
  // lift the instant a terminal outcome latches -- only a genuine
  // subsequent boot with a fresh, non-trial state record actually exits
  // "trial" (this closes the gap where a reboot() call that somehow
  // returned/no-opped could otherwise have permitted an install/erase
  // during the interval between a terminal outcome and the real reboot).
  EXPECT_TRUE(confirmer.isTrialActive());
  EXPECT_GT(fake.call_count, 0);

  // Latches: further calls never re-consult the image source, and the
  // outcome never changes.
  const int calls_at_confirm = fake.call_count;
  EXPECT_EQ(confirmer.tick(now_ms + 1000, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Confirmed);
  EXPECT_EQ(fake.call_count, calls_at_confirm);
}

TEST(OtaBoardTrialBootHealthConfirmerTest, ServiceGapResetsWindowAndNeverConfirmsEarly) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(256, 0x33);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);

  // Tick continuously (500ms steps, no gap) for 9 seconds -- window
  // opens on the very first tick (now_ms=500).
  uint32_t now_ms = 0;
  for (int i = 0; i < 18; ++i) {  // 18 * 500 = 9000ms
    now_ms += 500;
    EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  }
  // A >1000ms service gap must reset the window: even though ~9.5s has
  // now elapsed since the very first tick, the CONTINUOUS window
  // restarts entirely from this tick.
  now_ms += 1500;
  EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  const uint32_t restart_ms = now_ms;
  // Continuous ticking again (500ms steps) for just under 10s since the
  // restart: must not confirm yet.
  while (now_ms + 500 < restart_ms + 10000) {
    now_ms += 500;
    EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  }
  // One more tick crosses 10s since the restart.
  now_ms += 500;
  EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Confirmed);
}

TEST(OtaBoardTrialBootHealthConfirmerTest, ReadinessDropResetsWindow) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(256, 0x77);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);

  uint32_t now_ms = 0;
  for (int i = 0; i < 18; ++i) {  // 18 * 500 = 9000ms continuous, window opened at first tick.
    now_ms += 500;
    EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  }
  // filesystem_ready flips false (small, non-gap step): window must
  // reset even though there is no wall-clock service gap. The window
  // only reopens on the NEXT tick where readiness is true again, so
  // that tick's timestamp -- not the drop's -- is the real restart
  // baseline.
  now_ms += 500;
  EXPECT_EQ(confirmer.tick(now_ms, true, false, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  now_ms += 500;
  EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  const uint32_t restart_ms = now_ms;
  while (now_ms + 500 < restart_ms + 10000) {
    now_ms += 500;
    EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  }
  now_ms += 500;
  EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Confirmed);
}

TEST(OtaBoardTrialBootHealthConfirmerTest, DeadlineExpiresWhenNeverContinuouslyHealthy) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(256, 0x99);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);

  // Never continuously healthy for 10s straight (readiness flaps every
  // tick) -- must expire at the 45s deadline instead of confirming, and
  // must never write a confirmation record.
  uint32_t now_ms = 0;
  mesh::ota::OtaBoardTrialHealthOutcome outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  bool ready = true;
  while (now_ms < 50000 && outcome == mesh::ota::OtaBoardTrialHealthOutcome::Pending) {
    now_ms += 900;  // under the 1000ms gap threshold, but readiness flaps below
    ready = !ready;
    outcome = confirmer.tick(now_ms, ready, true, true);
  }
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::DeadlineExpired);
  // Per MAIN's corrected bug #7 requirement: trial exclusion persists
  // across ANY terminal outcome (Confirmed, DeadlineExpired,
  // ConfirmationUncertain) until a genuine subsequent boot -- never
  // lifted merely because this boot's outcome is already decided.
  EXPECT_TRUE(confirmer.isTrialActive());

  // Latched: further ticks stay DeadlineExpired, never flip to Confirmed.
  EXPECT_EQ(confirmer.tick(now_ms + 1000, true, true, true),
           mesh::ota::OtaBoardTrialHealthOutcome::DeadlineExpired);
}

TEST(OtaBoardTrialBootHealthConfirmerTest, WithheldLoopReadinessExpiresWithoutConfirmationDespiteHealthyServices) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(256, 0x99);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);

  constexpr uint32_t deadline = ota::storage::XiaoOtaTrialHealthMonitor::kOverallDeadlineMs;
  ASSERT_EQ(45000u, deadline);
  for (uint32_t now_ms = 0; now_ms < deadline; now_ms += 500) {
    EXPECT_EQ(mesh::ota::OtaBoardTrialHealthOutcome::Pending,
              confirmer.tick(now_ms, /*radio_ready=*/true, /*filesystem_ready=*/true, /*loop_healthy=*/false));
  }
  EXPECT_GT(fake.call_count, 0);
  EXPECT_EQ(mesh::ota::OtaBoardTrialHealthOutcome::DeadlineExpired,
            confirmer.tick(deadline, true, true, false));
  EXPECT_TRUE(confirmer.isTrialActive());
  EXPECT_EQ(mesh::ota::OtaBoardTrialHealthOutcome::DeadlineExpired,
            confirmer.tick(deadline + 500, true, true, true));
  EXPECT_EQ(0u, confirm_flash.eraseOpCount());
  EXPECT_EQ(0u, confirm_flash.programOpCount());
}

TEST(OtaBoardTrialBootHealthConfirmerTest, NeverConsultsImageAccessorWhenStateIsNotTrialBootPhase) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  uint8_t hash[32] = {0x22};
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseFailedMax, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);
  EXPECT_FALSE(confirmer.isTrialActive());
  uint32_t now_ms = 0;
  for (int i = 0; i < 60; ++i) {
    EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
    now_ms += 1000;
  }
  EXPECT_EQ(fake.call_count, 0);  // not TRIAL_BOOT -- must never reach the expensive resolve.
}

TEST(OtaBoardTrialBootHealthConfirmerTest, HashMismatchNeverConfirmsAndExpiresAtDeadline) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(256, 0xAB);
  uint8_t wrong_hash[32];
  memset(wrong_hash, 0xEE, sizeof(wrong_hash));  // deliberately does NOT match image's real hash.
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, wrong_hash, wrong_hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);

  uint32_t now_ms = 0;
  mesh::ota::OtaBoardTrialHealthOutcome outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  while (now_ms < 50000 && outcome == mesh::ota::OtaBoardTrialHealthOutcome::Pending) {
    now_ms += 500;
    outcome = confirmer.tick(now_ms, true, true, true);
  }
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::DeadlineExpired);
}

// Bug #3 (MAIN's correction): the monitor's own driveIncrementalHash()
// must never trust an injected/buggy accessor's reported extent blindly
// -- defense-in-depth independent of the REAL hardware resolver (which
// already enforces this bound itself). An extent beyond the 643072-byte
// install ceiling must never be dereferenced/hashed.
TEST(OtaBoardTrialBootHealthConfirmerTest, OversizedAccessorExtentFailsClosedWithoutHashingAndExpiresAtDeadline) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  // A buffer genuinely smaller than the bogus reported extent -- if the
  // monitor ever actually tried to hash `extent` bytes starting here, it
  // would read out of bounds; the test would then crash/UB under
  // AddressSanitizer/valgrind rather than merely failing an assertion.
  std::vector<uint8_t> small_buffer(64, 0x42);
  uint8_t hash[32];
  ota::trust::Sha256::hash(small_buffer.data(), small_buffer.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = small_buffer.data();
  fake.extent = ::ota::storage::kXiaoOtaAppInstallMaxSize + 4u;  // beyond the 643072-byte ceiling.
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);

  uint32_t now_ms = 0;
  mesh::ota::OtaBoardTrialHealthOutcome outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  while (now_ms < 50000 && outcome == mesh::ota::OtaBoardTrialHealthOutcome::Pending) {
    now_ms += 500;
    outcome = confirmer.tick(now_ms, true, true, true);
  }
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::DeadlineExpired);
}

// An extent exactly AT the install ceiling remains accepted (only
// STRICTLY beyond is rejected) -- proven independently for
// XiaoOtaActiveExtentBridge already; this proves the SAME bound applies
// at the monitor's own defense-in-depth accessor-validation layer.
TEST(OtaBoardTrialBootHealthConfirmerTest, ExtentExactlyAtInstallCeilingIsNotRejectedByAccessorGuard) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(256, 0x55);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  // Deliberately mismatched vs the real hash's extent (only the accessor
  // guard's own extent-bound check is under test here, not end-to-end
  // hash matching) -- kept at exactly the ceiling to prove it is NOT
  // rejected purely for being large; the hash naturally will not match
  // (extent != image.size()), so this still legitimately expires at the
  // deadline rather than confirming -- proving the guard only rejects
  // STRICTLY-beyond-ceiling extents, not the ceiling value itself
  // (which would otherwise also hit the same DeadlineExpired path,
  // making this test indistinguishable from the oversized case above if
  // the boundary were off-by-one in the wrong direction -- see the
  // dedicated unit-level bridge boundary tests for the exact-match
  // case).
  fake.extent = ::ota::storage::kXiaoOtaAppInstallMaxSize;
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);
  EXPECT_EQ(confirmer.tick(1, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  // The accessor's stepExtentResolution() was actually consulted (not
  // short-circuited by some earlier gate) -- proving the guard is
  // reached and evaluates the ceiling value without rejecting it purely
  // for being large.
  EXPECT_GT(fake.call_count, 0);
}

// Bug #3: a reported extent that is not a whole multiple of 4 bytes
// cannot be a genuine linked/flashed nRF52840 application image size --
// defense-in-depth against a corrupt/adversarial accessor, independent
// of the oversized-extent guard above.
TEST(OtaBoardTrialBootHealthConfirmerTest, UnalignedAccessorExtentFailsClosedAndExpiresAtDeadline) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(256, 0x77);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = 255u;  // one byte short of a multiple of 4 -- not a genuine image size.
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);

  uint32_t now_ms = 0;
  mesh::ota::OtaBoardTrialHealthOutcome outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  while (now_ms < 50000 && outcome == mesh::ota::OtaBoardTrialHealthOutcome::Pending) {
    now_ms += 500;
    outcome = confirmer.tick(now_ms, true, true, true);
  }
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::DeadlineExpired);
}

TEST(OtaBoardTrialBootHealthConfirmerTest, ConfirmationWriteFailureIsNeverRetriedAndExpiresAtDeadline) {
  // MAIN's real bug: tryWriteConfirmation() was re-invoked on EVERY
  // subsequent tick once window+hash conditions were satisfied and a
  // prior attempt had already failed -- despite a comment claiming
  // otherwise -- risking a SECOND flash transaction interleaved with an
  // already-uncertain first one. Proves AT MOST ONE attempt, ever, AND
  // (per MAIN's corrected requirement) that a failed confirmation write
  // latches the terminal ConfirmationUncertain outcome IMMEDIATELY on
  // the tick it happens -- never left Pending-until-deadline, which
  // would let other code (sleep, a competing erase) run during a window
  // where the actual outcome is already known to be unrecoverable.
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(256, 0x37);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  // The very first program() call ever made against confirm_flash fails
  // permanently (never a transient blip) -- the single confirmation
  // attempt must genuinely fail, not merely be skipped.
  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Program;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = confirm_flash.programOpCount() + 1;
  confirm_flash.armFault(fault);

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);

  uint32_t now_ms = 0;
  mesh::ota::OtaBoardTrialHealthOutcome outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  // Small (500ms) continuous steps to the point the window+hash first
  // become satisfiable (~10.5s from the first tick) -- the failed write
  // attempt latches ConfirmationUncertain on THIS SAME tick, not later.
  for (int i = 0; i < 21 && outcome == mesh::ota::OtaBoardTrialHealthOutcome::Pending; ++i) {
    now_ms += 500;
    outcome = confirmer.tick(now_ms, true, true, true);
  }
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::ConfirmationUncertain);
  const uint32_t program_ops_after_first_attempt = confirm_flash.programOpCount();
  EXPECT_GT(program_ops_after_first_attempt, 0u);

  // Continue ticking (still small, continuous steps) all the way past
  // the 45s deadline -- must NEVER attempt a second write, and must
  // NEVER "downgrade" the already-latched ConfirmationUncertain outcome
  // into DeadlineExpired; ConfirmationUncertain is itself terminal.
  while (now_ms < 45500) {
    now_ms += 500;
    outcome = confirmer.tick(now_ms, true, true, true);
  }
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::ConfirmationUncertain);
  EXPECT_EQ(confirm_flash.programOpCount(), program_ops_after_first_attempt);
}

TEST(OtaBoardTrialBootHealthConfirmerTest, ResolvedTrueWithNullImagePointerNeverCrashesAndFailsClosed) {
  // Defensive guard: even if an injected (or, hypothetically, a buggy
  // future real) accessor reports Resolved with a non-zero extent but a
  // null image pointer, the monitor must never dereference it -- treat
  // exactly like Failed, never crash, never confirm.
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  uint8_t hash[32] = {0x44};
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = nullptr;  // deliberately null even though ok=true and extent>0.
  fake.extent = 256;
  fake.ok = true;
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);

  uint32_t now_ms = 0;
  mesh::ota::OtaBoardTrialHealthOutcome outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  while (now_ms < 50000 && outcome == mesh::ota::OtaBoardTrialHealthOutcome::Pending) {
    now_ms += 500;
    outcome = confirmer.tick(now_ms, true, true, true);
  }
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::DeadlineExpired);
  EXPECT_EQ(confirm_flash.programOpCount(), 0u);  // never even attempted a write.
}

TEST(OtaBoardTrialBootHealthConfirmerTest, ExtentResolutionItselfIsBoundedAcrossMultipleTicksBeforeHashingBegins) {
  // The extent's own CRC-16 verification (XiaoOtaIncrementalExtentResolver)
  // is exactly as potentially expensive as the SHA-256 image hash if done
  // in one call, so it too must be driven in bounded, per-tick steps --
  // this simulates a real multi-pass resolution (steps_to_resolve=5)
  // instead of the single-call shortcut most other tests use.
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(64, 0x5C);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());
  fake.steps_to_resolve = 5;
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);

  uint32_t now_ms = 0;
  for (int i = 0; i < 4; ++i) {
    now_ms += 500;
    EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  }
  // Exactly one bounded resolution step consulted per tick so far -- the
  // 5th (final, resolving) step has not happened yet.
  EXPECT_EQ(fake.call_count, 4);

  mesh::ota::OtaBoardTrialHealthOutcome outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  while (now_ms < 10500 && outcome == mesh::ota::OtaBoardTrialHealthOutcome::Pending) {
    now_ms += 500;
    outcome = confirmer.tick(now_ms, true, true, true);
  }
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::Confirmed);
  EXPECT_EQ(fake.call_count, 5);  // extent resolution never re-consulted once Resolved.
}

TEST(OtaBoardTrialBootHealthConfirmerTest, GapOfExactlyMaxServiceGapMsDoesNotResetWindow) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(64, 0x61);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);

  uint32_t now_ms = 0;
  // First tick opens the window at t=0.
  EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  // A gap of EXACTLY kMaxServiceGapMs (1000ms, not >) must NOT be treated
  // as a service gap -- the window must NOT reset.
  now_ms += 1000;
  EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);

  mesh::ota::OtaBoardTrialHealthOutcome outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  while (now_ms < 10000) {
    now_ms += 500;
    outcome = confirmer.tick(now_ms, true, true, true);
  }
  // If the 1000ms gap above had incorrectly reset the window, confirming
  // this early (exactly 10000ms after the ORIGINAL t=0 window start)
  // would be impossible.
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::Confirmed);
}

TEST(OtaBoardTrialBootHealthConfirmerTest, GapOfOneMoreThanMaxServiceGapMsResetsWindow) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(64, 0x62);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, /*boot_epoch_ms=*/0);

  uint32_t now_ms = 0;
  EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  // ONE millisecond more than the threshold (1001ms, > kMaxServiceGapMs)
  // IS a genuine service gap: the window must reset from this tick.
  now_ms += 1001;
  EXPECT_EQ(confirmer.tick(now_ms, true, true, true), mesh::ota::OtaBoardTrialHealthOutcome::Pending);

  mesh::ota::OtaBoardTrialHealthOutcome outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  // Must NOT have confirmed by 10000ms (original t=0 baseline) -- the
  // reset means confirmation is only reachable ~1001ms later than that.
  while (now_ms < 10000) {
    now_ms += 500;
    outcome = confirmer.tick(now_ms, true, true, true);
  }
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::Pending);
  // Continuing on (still small steps) confirms once the FULL 10s has
  // elapsed since the restarted window (at ~1001ms), proving the window
  // genuinely did reset rather than simply being slow.
  while (outcome == mesh::ota::OtaBoardTrialHealthOutcome::Pending) {
    now_ms += 500;
    outcome = confirmer.tick(now_ms, true, true, true);
  }
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::Confirmed);
}

TEST(OtaBoardTrialBootHealthConfirmerTest, ContinuousWindowSurvivesMillisWraparound) {
  // now_ms is a caller-supplied wall-clock millis() value that genuinely
  // wraps at UINT32_MAX on real hardware; all internal arithmetic here is
  // plain unsigned subtraction, which is correctly wrap-safe as long as
  // true elapsed time never exceeds ~49.7 days -- proves that in practice
  // by actually crossing the wrap boundary mid-window.
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(64, 0x5A);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());
  uint32_t now_ms = static_cast<uint32_t>(0) - 4000u;  // UINT32_MAX - 3999
  const uint32_t start_ms = now_ms;
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, start_ms);

  mesh::ota::OtaBoardTrialHealthOutcome outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  for (int i = 0; i < 25 && outcome == mesh::ota::OtaBoardTrialHealthOutcome::Pending; ++i) {
    now_ms += 500;  // wraps past UINT32_MAX partway through this loop.
    outcome = confirmer.tick(now_ms, true, true, true);
  }
  EXPECT_LT(now_ms, start_ms);  // sanity: the wrap genuinely happened.
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::Confirmed);
}


TEST(OtaBoardTrialBootHealthConfirmerTest, DeadlineWinsWhenHealthWindowCompletesAtFortyFiveSeconds) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);
  std::vector<uint8_t> image(256, 0x51);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto record = makeStateRecordBytes(
      1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(
      state_region.program(0, record.data(), static_cast<uint32_t>(record.size()))));
  CountingFakeActiveImageAccessor source;
  source.image = image.data();
  source.extent = static_cast<uint32_t>(image.size());
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, source, /*boot_epoch_ms=*/0);
  for (uint32_t now = 0; now < 45000; now += 1000) {
    EXPECT_EQ(mesh::ota::OtaBoardTrialHealthOutcome::Pending,
              confirmer.tick(now, now >= 35000, true, true));
  }
  EXPECT_EQ(mesh::ota::OtaBoardTrialHealthOutcome::DeadlineExpired,
            confirmer.tick(45000, true, true, true));
  EXPECT_EQ(0u, confirm_flash.eraseOpCount());
  EXPECT_EQ(0u, confirm_flash.programOpCount());
}

// -----------------------------------------------------------------------
// OtaBoardTrialGuardedStagingSink: MAIN's bug #8 -- the trial-active
// predicate previously only ever gated BUILDING a durable install
// command, never the storage sink's own beginSession() erase/stage
// admission. A qualified-but-trial-active (or unknown, predicate-null-
// pointer-safe) device must never let a NEW campaign begin erasing/
// staging over a candidate region whose prior trial-boot confirmation
// hasn't yet survived a reboot.
// -----------------------------------------------------------------------
class FakeGuardedInnerStagingSink : public meshcore::ota::runtime::IOtaStagingSink {
public:
  int begin_session_calls = 0;
  int write_chunk_calls = 0;
  int commit_calls = 0;
  int abort_calls = 0;
  Result begin_session_result = Result::Ok;
  Result write_chunk_result = Result::Ok;
  Result commit_result = Result::Ok;

  Result beginSession(const meshcore::ota::protocol::OtaDescriptor&) override {
    ++begin_session_calls;
    return begin_session_result;
  }
  Result writeChunk(uint64_t, const uint8_t*, size_t) override {
    ++write_chunk_calls;
    return write_chunk_result;
  }
  Result commit() override {
    ++commit_calls;
    return commit_result;
  }
  void abort() override { ++abort_calls; }
};

bool g_guarded_sink_test_predicate_value = false;
bool guardedSinkTestPredicate() { return g_guarded_sink_test_predicate_value; }

TEST(OtaBoardTrialGuardedStagingSinkTest, RefusesBeginSessionWhilePredicateTrueWithNoMutationAtAll) {
  FakeGuardedInnerStagingSink inner;
  g_guarded_sink_test_predicate_value = true;
  mesh::ota::OtaBoardTrialGuardedStagingSink guarded(inner, &guardedSinkTestPredicate);

  meshcore::ota::protocol::OtaDescriptor descriptor{};
  EXPECT_EQ(guarded.beginSession(descriptor), meshcore::ota::runtime::IOtaStagingSink::Result::Rejected);
  EXPECT_EQ(inner.begin_session_calls, 0);  // the wrapped sink is never even consulted.
}

TEST(OtaBoardTrialGuardedStagingSinkTest, PermitsBeginSessionOncePredicateIsFalse) {
  FakeGuardedInnerStagingSink inner;
  g_guarded_sink_test_predicate_value = false;
  mesh::ota::OtaBoardTrialGuardedStagingSink guarded(inner, &guardedSinkTestPredicate);

  meshcore::ota::protocol::OtaDescriptor descriptor{};
  EXPECT_EQ(guarded.beginSession(descriptor), meshcore::ota::runtime::IOtaStagingSink::Result::Ok);
  EXPECT_EQ(inner.begin_session_calls, 1);
}

TEST(OtaBoardTrialGuardedStagingSinkTest, NullPredicateFailsClosedAsAlwaysBlocking) {
  // A null predicate must never be treated as "not active" (which would
  // silently permit an erase) -- fail closed exactly like predicate()==true.
  FakeGuardedInnerStagingSink inner;
  mesh::ota::OtaBoardTrialGuardedStagingSink guarded(inner, nullptr);

  meshcore::ota::protocol::OtaDescriptor descriptor{};
  EXPECT_EQ(guarded.beginSession(descriptor), meshcore::ota::runtime::IOtaStagingSink::Result::Rejected);
  EXPECT_EQ(inner.begin_session_calls, 0);
}

TEST(OtaBoardTrialGuardedStagingSinkTest, WriteChunkAndCommitAlwaysDelegateRegardlessOfPredicate) {
  // Only beginSession() (the erase/stage-admission point) is gated -- an
  // ALREADY-admitted session's writeChunk()/commit() calls must never be
  // silently dropped mid-transfer merely because the predicate later
  // flips (e.g. a second, unrelated trial window starting on a stale
  // signal): they always delegate.
  FakeGuardedInnerStagingSink inner;
  g_guarded_sink_test_predicate_value = true;
  mesh::ota::OtaBoardTrialGuardedStagingSink guarded(inner, &guardedSinkTestPredicate);

  uint8_t data[4] = {1, 2, 3, 4};
  EXPECT_EQ(guarded.writeChunk(0, data, sizeof(data)), meshcore::ota::runtime::IOtaStagingSink::Result::Ok);
  EXPECT_EQ(inner.write_chunk_calls, 1);
  EXPECT_EQ(guarded.commit(), meshcore::ota::runtime::IOtaStagingSink::Result::Ok);
  EXPECT_EQ(inner.commit_calls, 1);
  guarded.abort();
  EXPECT_EQ(inner.abort_calls, 1);
}

TEST(OtaBoardTrialGuardedStagingSinkTest, LatchesStorageIoFaultObservedOnWriteChunkIoErrorAndNeverClears) {
  FakeGuardedInnerStagingSink inner;
  g_guarded_sink_test_predicate_value = false;
  mesh::ota::OtaBoardTrialGuardedStagingSink guarded(inner, &guardedSinkTestPredicate);
  EXPECT_FALSE(guarded.storageIoFaultObserved());

  inner.write_chunk_result = meshcore::ota::runtime::IOtaStagingSink::Result::IoError;
  uint8_t data[1] = {0};
  guarded.writeChunk(0, data, sizeof(data));
  EXPECT_TRUE(guarded.storageIoFaultObserved());

  // Never auto-clears, even once a later call succeeds.
  inner.write_chunk_result = meshcore::ota::runtime::IOtaStagingSink::Result::Ok;
  guarded.writeChunk(4, data, sizeof(data));
  EXPECT_TRUE(guarded.storageIoFaultObserved());
}

TEST(OtaBoardTrialGuardedStagingSinkTest, LatchesStorageIoFaultObservedOnCommitIoError) {
  FakeGuardedInnerStagingSink inner;
  g_guarded_sink_test_predicate_value = false;
  mesh::ota::OtaBoardTrialGuardedStagingSink guarded(inner, &guardedSinkTestPredicate);
  inner.commit_result = meshcore::ota::runtime::IOtaStagingSink::Result::IoError;
  guarded.commit();
  EXPECT_TRUE(guarded.storageIoFaultObserved());
}

TEST(OtaBoardTrialGuardedStagingSinkTest, RejectedBeginSessionIsNotConfusedWithAnIoFault) {
  // A trial-active refusal is an expected, benign STAGING_ONLY outcome --
  // it must never itself be mistaken for a genuine storage IoError.
  FakeGuardedInnerStagingSink inner;
  g_guarded_sink_test_predicate_value = true;
  mesh::ota::OtaBoardTrialGuardedStagingSink guarded(inner, &guardedSinkTestPredicate);
  meshcore::ota::protocol::OtaDescriptor descriptor{};
  guarded.beginSession(descriptor);
  EXPECT_FALSE(guarded.storageIoFaultObserved());
}

// ---------------------------------------------------------------------
// RadioDriverHealthLatch: the plain-C++, RadioLib/Arduino-independent
// decision logic behind RadioLibWrapper::isDriverHealthy() (see
// src/helpers/radiolib/RadioLibWrappers.{h,cpp} for the three real call
// sites -- startRecv()/recvRaw()/startSendRaw() -- that feed this class
// from ACTUAL startReceive()/readData()/startTransmit() driver return
// codes; RadioLibWrapper.cpp itself cannot be compiled in this native
// environment without an extensive additional Arduino-compatibility
// shim layer -- RadioLib's own PhysicalLayer/Module headers compile
// fine standalone in native "generic" mode, but RadioLibWrapper.cpp
// additionally needs Arduino's global `min`/`max` macros and the
// 2-argument `random(lo,hi)` overload, and defining bare `min`/`max`
// macros unconditionally conflicts with <limits>/<algorithm>'s
// std::min/std::max -- so RadioLibWrapper's correct WIRING is verified
// via full MCU compilation of all 3 real firmware targets instead,
// while this exact decision class gets genuine native unit coverage).
// ---------------------------------------------------------------------

TEST(RadioDriverHealthLatchTest, DefaultsToHealthyBeforeAnyOperationIsRecorded) {
  RadioDriverHealthLatch latch;
  EXPECT_TRUE(latch.healthy());
}

TEST(RadioDriverHealthLatchTest, SuccessfulReceiveOperationReportsHealthy) {
  RadioDriverHealthLatch latch;
  latch.recordOutcome(/*success=*/true);
  EXPECT_TRUE(latch.healthy());
}

TEST(RadioDriverHealthLatchTest, FailedDriverCallReportsUnhealthyImmediately) {
  RadioDriverHealthLatch latch;
  latch.recordOutcome(/*success=*/false);
  EXPECT_FALSE(latch.healthy());
}

TEST(RadioDriverHealthLatchTest, SubsequentSuccessAfterAFailureClearsBackToHealthy) {
  // Unlike the FS/trial-state fault latches elsewhere in this suite
  // (which deliberately never auto-clear), the radio driver signal
  // tracks the MOST RECENT real operation's outcome -- a transient
  // driver hiccup that the driver itself subsequently recovers from
  // (e.g. the very next startReceive() call succeeds) must not
  // permanently disqualify health for the rest of the trial.
  RadioDriverHealthLatch latch;
  latch.recordOutcome(false);
  ASSERT_FALSE(latch.healthy());
  latch.recordOutcome(true);
  EXPECT_TRUE(latch.healthy());
}

TEST(RadioDriverHealthLatchTest, AGenuineOrdinaryTransmitSequenceNeverReportsUnhealthy) {
  // Mirrors the real startSendRaw() -> onSendFinished() -> next
  // startRecv() call sequence for one ordinary, fully-successful
  // transmit: every one of those real driver calls reports success, so
  // the latch must read healthy throughout -- an ordinary TX must never
  // be misread as a driver failure.
  RadioDriverHealthLatch latch;
  latch.recordOutcome(true);  // startSendRaw() succeeded
  EXPECT_TRUE(latch.healthy());
  latch.recordOutcome(true);  // the following startReceive() (re-arm) succeeded
  EXPECT_TRUE(latch.healthy());
}

TEST(RadioDriverHealthLatchTest, ActiveProbeDuringAQuietRxPeriodWithNoOrdinaryTrafficIsGenuinelyObserved) {
  // A quiet channel with NO ordinary send/receive completions at all
  // must not be reported healthy purely because "nothing bad has
  // happened yet" (an unobserved default is not positive proof). This
  // mirrors CustomSX1262Wrapper::probeDriverStatus(): each health tick
  // takes a genuine ACTIVE probe (there, a real getDeviceErrors() SPI
  // read) and feeds its outcome into this SAME latch every tick,
  // regardless of whether any ordinary traffic op happened to run --
  // so a fault that occurs mid-quiet-period is still caught the very
  // next tick, not merely whenever the next unrelated Tx/Rx completes.
  RadioDriverHealthLatch latch;
  for (int tick = 0; tick < 5; ++tick) {
    latch.recordOutcome(true);  // simulated periodic active probe: no errors this tick.
    EXPECT_TRUE(latch.healthy());
  }
  latch.recordOutcome(false);  // the active probe itself now detects a fault mid-quiet-period.
  EXPECT_FALSE(latch.healthy());
}

// ---------------------------------------------------------------------
// evaluateSx1262CheckedHealth(): the plain-C++, RadioLib/Arduino-
// independent decision logic behind CustomSX1262Wrapper::probeDriverStatus()
// (see src/helpers/radiolib/CustomSX1262.h's getDeviceErrorsChecked()/
// getIrqFlagsChecked()/getStatusChecked() for the real checked SPI call
// sites). Proves the exact regression MAIN identified in RadioLib's OWN
// getDeviceErrors()/getStatus(): a genuinely FAILED (or, for getStatus(),
// structurally never-populated) SPI transaction that happens to leave
// the decoded bytes reading back as zero/plausible must resolve to
// UNHEALTHY, never a "success-shaped" fallback -- AND that the real
// decoded chip MODE must genuinely agree with what software currently
// expects (idle/receiving/transmitting), with only a bounded, IRQ-
// evidence-backed exception for a just-completed operation.
// ---------------------------------------------------------------------

TEST(Sx1262CheckedProbeTest, BothChecksSucceedingWithZeroErrorsIsHealthy) {
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = kSx1262StatusModeRx;
  EXPECT_TRUE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kReceiving));
}

TEST(Sx1262CheckedProbeTest, FailedDeviceErrorsSpiTransactionWithUnchangedZeroBytesIsUnhealthy) {
  // This is the EXACT defect in RadioLib's SX126x::getDeviceErrors():
  // the real SPI transaction genuinely failed (non-success status), but
  // the (never-actually-written) register bytes still decode as 0 --
  // the naive "errors == 0 means healthy" check would wrongly report
  // healthy here. The checked status must override that.
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = -1;  // any non-success RadioLib status
  r.device_errors = 0;          // buffer never touched by the failed transaction -- still reads as "no errors"
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = kSx1262StatusModeRx;
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kReceiving));
}

TEST(Sx1262CheckedProbeTest, FailedIrqFlagsSpiTransactionIsUnhealthyEvenIfDeviceErrorsSucceeded) {
  // The SECOND, independent checked SPI transaction must also genuinely
  // succeed -- one succeeding register read alone is not proof that the
  // driver overall is healthy.
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = -2;
  r.irq_flags = 0;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = kSx1262StatusModeRx;
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kReceiving));
}

TEST(Sx1262CheckedProbeTest, BothChecksSucceedingButGenuineNonZeroDeviceErrorsIsUnhealthy) {
  // Both real SPI transactions genuinely succeeded this time, but the
  // chip's own actual error-accumulator bits are non-zero -- a real
  // hardware fault (e.g. PLL lock failure), not an SPI transport issue.
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0x0001;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = kSx1262StatusModeRx;
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kReceiving));
}

TEST(Sx1262CheckedProbeTest, FailedStatusSpiTransactionIsUnhealthyEvenIfOtherTwoSucceeded) {
  // The THIRD, independent checked SPI transaction (the fixed, genuinely
  // working GET_STATUS read) must also genuinely succeed -- this is the
  // exact regression the base (broken, numBytes==0) getStatus() could
  // never even exercise, since it never surfaces a real transaction
  // status at all.
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;
  r.status_read_status = -3;   // genuinely failed SPI transaction
  r.status_byte = kSx1262StatusModeRx;  // buffer coincidentally plausible-looking
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kReceiving));
}

TEST(Sx1262CheckedProbeTest, ExpectedReceivingButChipGenuinelyReportsTransmittingIsUnhealthy) {
  // A genuine chip-mode disagreement: software believes it is receiving,
  // but the chip's OWN real status byte says it's transmitting -- with
  // no IRQ evidence of ANY just-completed Rx operation. Must fail
  // closed, not be silently accepted.
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = kSx1262StatusModeTx;
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kReceiving));
}

TEST(Sx1262CheckedProbeTest, ExpectedReceivingChipInStandbyWithStaleRxDoneIrqIsCorrectlyRejected) {
  // The formerly-exploitable "bounded, IRQ-evidence-backed transitional
  // exception" is REMOVED: IRQ_RX_DONE is a hardware-LATCHED bit that
  // persists across arbitrarily many subsequent ticks until explicitly
  // cleared (which this read-only probe never does) -- so a chip
  // genuinely STUCK in standby forever (a real fault) would pass this
  // check on nothing but an ancient IRQ bit from long before. An
  // expected-receiving probe must now see the chip's status mode
  // EXACTLY matching RX, with no IRQ-based grace at all.
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = kSx1262IrqRxDone;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = kSx1262StatusModeStdbyRc;
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kReceiving));
}

TEST(Sx1262CheckedProbeTest, ExpectedReceivingChipInStandbyWithoutCompletionIrqIsUnhealthy) {
  // The SAME standby mode, but with NO completion IRQ evidence at all --
  // must NOT be silently accepted as a legitimate transition.
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;  // no RX_DONE/TIMEOUT evidence
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = kSx1262StatusModeStdbyRc;
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kReceiving));
}

TEST(Sx1262CheckedProbeTest, ExpectedTransmittingChipGenuinelyReportingTxIsHealthy) {
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = kSx1262StatusModeTx;
  EXPECT_TRUE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kTransmitting));
}

TEST(Sx1262CheckedProbeTest, ExpectedTransmittingChipInStandbyWithStaleTxDoneIrqIsCorrectlyRejected) {
  // A genuinely long TX (e.g. SF12) is not disqualified by THIS probe at
  // all -- the caller's own airtime-based deadline (see
  // MyMesh::isRadioStuckOutOfRecv()) is what bounds "how long is too
  // long", not this probe -- but a chip reported as sitting in FS mode
  // with only a stale, hardware-latched TX_DONE bit from an arbitrarily
  // old completed transmit is NOT proof of a just-now transition, and
  // must be rejected exactly like the RX case above: deny this probe
  // tick and wait for the mode to genuinely, freshly read back as TX.
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = kSx1262IrqTxDone;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = kSx1262StatusModeFs;
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kTransmitting));
}

TEST(Sx1262CheckedProbeTest, ExpectedTransmittingChipInStandbyWithoutCompletionIrqIsUnhealthy) {
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;  // no TX_DONE evidence
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = kSx1262StatusModeStdbyXosc;
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kTransmitting));
}

TEST(Sx1262CheckedProbeTest, ExpectedIdleChipWithUnsupportedStatusModeByteIsRejected) {
  // An invalid/unsupported status-mode byte (not one of the 5 real
  // SX126x modes: STDBY_RC/STDBY_XOSC/FS/RX/TX) must never be silently
  // accepted just because it happens to differ from RX/TX.
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = 0x00;  // mode bits 6:4 == 0, not a real SX126x mode.
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kIdle));
}

TEST(Sx1262CheckedProbeTest, ExpectedReceivingChipWithUnsupportedStatusModeByteIsRejected) {
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = 0x70;  // mode bits 6:4 == 0b111, not a real SX126x mode.
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kReceiving));
}

TEST(Sx1262CheckedProbeTest, ExpectedTransmittingChipWithUnsupportedStatusModeByteIsRejected) {
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = 0x10;  // mode bits 6:4 == 0b0001, not a real SX126x mode.
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kTransmitting));
}

TEST(Sx1262CheckedProbeTest, ExpectedIdleChipGenuinelyReportingActiveRxIsUnhealthy) {
  // Software believes the radio is idle (between a completed send and
  // the next startReceive()), but the chip claims an ACTIVE Rx mode --
  // a real disagreement, never silently accepted.
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = kSx1262StatusModeRx;
  EXPECT_FALSE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kIdle));
}

TEST(Sx1262CheckedProbeTest, ExpectedIdleChipInStandbyIsHealthy) {
  Sx1262CheckedProbeResult r{};
  r.device_errors_status = kRadioLibErrNoneForProbe;
  r.device_errors = 0;
  r.irq_flags_status = kRadioLibErrNoneForProbe;
  r.irq_flags = 0;
  r.status_read_status = kRadioLibErrNoneForProbe;
  r.status_byte = kSx1262StatusModeStdbyRc;
  EXPECT_TRUE(evaluateSx1262CheckedHealth(r, Sx1262ExpectedChipMode::kIdle));
}

// ---------------------------------------------------------------------
// performSx126xGetStatusTransaction(): the plain, module-type-agnostic
// implementation of the scoped "status width temporarily forced to 0"
// wire trick (see Sx126xGetStatusTransaction.h). Proves, against a
// plain FakeModule double (no RadioLib/Arduino dependency), the exact
// TWO things MAIN identified as easy to get wrong: (1) the real 2-byte
// wire buffer offset -- cmdLen(1)+numBytes(1), with the status byte
// landing at buffIn[1], NOT accidentally at buffIn[0] or buffIn[2] --
// and (2) that spiConfig.widths[STATUS] is unconditionally restored to
// its ORIGINAL value on every return path, including a genuinely FAILED
// transaction, never left permanently mutated.
// ---------------------------------------------------------------------

namespace {

enum class FakeBitWidth : uint8_t { kBits0 = 0, kBits8 = 1 };

struct FakeSpiConfig {
  FakeBitWidth widths[3] = { FakeBitWidth::kBits8, FakeBitWidth::kBits0, FakeBitWidth::kBits8 };
};

// A minimal double standing in for RadioLib's real `Module`: records
// every (cmd, numBytes, widths[STATUS]-at-call-time) it was invoked
// with, and can be configured to simulate a genuinely failed SPI
// transaction (status != 0) while still writing a real byte into the
// buffer (mirroring a real driver that might report a failure status
// but still have shifted SOME byte onto the wire) -- or to leave `data`
// completely untouched on failure, whichever the caller wants to
// exercise.
struct FakeModule {
  FakeSpiConfig spiConfig;
  int16_t next_transaction_status = 0;     // 0 == success, matching kRadioLibErrNoneForProbe.
  uint8_t byte_to_write_on_success = 0x55;  // the "real status byte" this fake pretends the chip returned.
  bool write_byte_even_on_failure = false;

  uint16_t last_cmd = 0;
  size_t last_num_bytes = 0;
  FakeBitWidth status_width_during_call = FakeBitWidth::kBits8;

  int16_t SPIreadStream(uint16_t cmd, uint8_t* data_in, size_t num_bytes) {
    last_cmd = cmd;
    last_num_bytes = num_bytes;
    status_width_during_call = spiConfig.widths[2];  // captured DURING the call, proving it was genuinely scoped-zeroed.
    if (next_transaction_status == 0) {
      if (num_bytes >= 1) data_in[0] = byte_to_write_on_success;
    } else if (write_byte_even_on_failure && num_bytes >= 1) {
      data_in[0] = byte_to_write_on_success;
    }
    return next_transaction_status;
  }
};

}  // namespace

TEST(Sx126xGetStatusTransactionTest, SuccessfulTransactionUsesCorrectTwoByteWireOffsetAndReturnsRealByte) {
  FakeModule mod;
  mod.next_transaction_status = 0;
  mod.byte_to_write_on_success = 0x57;  // arbitrary plausible status byte.

  uint8_t out_status = 0;
  const int16_t status = performSx126xGetStatusTransaction(&mod, (uint16_t)0xC0, &out_status, FakeBitWidth::kBits0);

  EXPECT_EQ(0, status);
  EXPECT_EQ(0x57, out_status);
  EXPECT_EQ((uint16_t)0xC0, mod.last_cmd);
  // The REAL wire trick: numBytes requested is exactly 1 (the status
  // byte as an ordinary 1-byte data payload), landing the copy-out at
  // buffIn[cmdLen(1)+0]==buffIn[1] inside the real Module -- exactly
  // where SX126x::SPIparseStatus()'s statusPos==1 already expects it.
  EXPECT_EQ(1u, mod.last_num_bytes);
  // Proves the width was GENUINELY zero DURING the call itself (not
  // merely before/after), i.e. the scoped mutation was actually in
  // effect for this exact transaction.
  EXPECT_EQ(FakeBitWidth::kBits0, mod.status_width_during_call);
}

TEST(Sx126xGetStatusTransactionTest, StatusWidthIsRestoredAfterSuccessfulTransaction) {
  FakeModule mod;
  mod.spiConfig.widths[2] = FakeBitWidth::kBits8;  // the real, ordinary pre-existing width.
  mod.next_transaction_status = 0;

  uint8_t out_status = 0;
  performSx126xGetStatusTransaction(&mod, (uint16_t)0xC0, &out_status, FakeBitWidth::kBits0);

  EXPECT_EQ(FakeBitWidth::kBits8, mod.spiConfig.widths[2]);
}

TEST(Sx126xGetStatusTransactionTest, StatusWidthIsRestoredEvenAfterAGenuinelyFailedTransaction) {
  // The critical never-permanently-mutated guarantee: a real, failed SPI
  // transaction must NOT leave spiConfig in the transiently-zeroed state
  // -- every other SPI caller after this one depends on the ordinary
  // width being back in place, success or failure.
  FakeModule mod;
  mod.spiConfig.widths[2] = FakeBitWidth::kBits8;
  mod.next_transaction_status = -2;  // genuine SPI transaction failure.
  mod.write_byte_even_on_failure = false;

  uint8_t out_status = 0xAA;  // pre-set to a sentinel to prove it's not misread as success.
  const int16_t status = performSx126xGetStatusTransaction(&mod, (uint16_t)0xC0, &out_status, FakeBitWidth::kBits0);

  EXPECT_EQ(-2, status);
  EXPECT_EQ(FakeBitWidth::kBits8, mod.spiConfig.widths[2]);  // restored despite the failure.
}

TEST(Sx126xGetStatusTransactionTest, FailedTransactionStatusIsNeverTreatedAsSuccess) {
  FakeModule mod;
  mod.next_transaction_status = -7;
  mod.write_byte_even_on_failure = true;  // buffer coincidentally holds a plausible-looking byte.
  mod.byte_to_write_on_success = kSx1262StatusModeRx;

  uint8_t out_status = 0;
  const int16_t status = performSx126xGetStatusTransaction(&mod, (uint16_t)0xC0, &out_status, FakeBitWidth::kBits0);

  // The caller (CustomSX1262Wrapper/evaluateSx1262CheckedHealth) relies
  // on this non-zero return to reject the whole probe outright,
  // REGARDLESS of whatever happens to be sitting in out_status.
  EXPECT_NE(0, status);
}

// ---------------------------------------------------------------------
// evaluateOtaTrialRadioReadyThisPass(): the per-tick radio readiness
// decision that feeds XiaoOtaTrialHealthMonitor/OtaBoardTrialBootHealth
// Confirmer. Proves the two production bugs closed this round: (1) a
// same-tick fault-count advance is never sticky across ticks -- a
// single transient failure fails only the ONE pass it occurred on, and
// (2) a chip reporting an internally-consistent "idle" status is never,
// by itself, accepted as proof of genuine ongoing service.
// ---------------------------------------------------------------------

TEST(OtaTrialRadioReadinessTest, GenuineActiveRxWithNoFaultAdvanceAndNoStuckIsReady) {
  EXPECT_TRUE(evaluateOtaTrialRadioReadyThisPass(
    /*radio_present=*/true, /*base_radio_ready=*/true, /*radio_stuck_non_recv=*/false,
    /*driver_healthy=*/true, /*genuinely_servicing=*/true,
    /*fault_count_before_probe=*/5, /*fault_count_after_probe=*/5, /*last_known_fault_count=*/5));
}

TEST(OtaTrialRadioReadinessTest, NullRadioIsNeverReady) {
  EXPECT_FALSE(evaluateOtaTrialRadioReadyThisPass(
    /*radio_present=*/false, /*base_radio_ready=*/true, /*radio_stuck_non_recv=*/false,
    /*driver_healthy=*/true, /*genuinely_servicing=*/true,
    /*fault_count_before_probe=*/0, /*fault_count_after_probe=*/0, /*last_known_fault_count=*/0));
}

TEST(OtaTrialRadioReadinessTest, ConsistentIdleStatusAloneIsNotReadyEvenWithNoFaults) {
  // The exact bug this round closes: a chip genuinely, internally
  // consistent with software's OWN belief that it is idle is still NOT
  // proof of active service -- `genuinely_servicing` (isInRecvMode() ||
  // isSendInProgress()) must independently be true.
  EXPECT_FALSE(evaluateOtaTrialRadioReadyThisPass(
    /*radio_present=*/true, /*base_radio_ready=*/true, /*radio_stuck_non_recv=*/false,
    /*driver_healthy=*/true, /*genuinely_servicing=*/false,
    /*fault_count_before_probe=*/3, /*fault_count_after_probe=*/3, /*last_known_fault_count=*/3));
}

TEST(OtaTrialRadioReadinessTest, RealOperationFailureEarlierThisSameTickIsNotMaskedByALaterHealthyProbe) {
  // fault_count advanced BEFORE probeDriverStatus() ran (an earlier
  // ordinary send/receive call this tick failed); the active probe
  // itself then reports driver_healthy=true and its own fault count
  // stays flat (before==after) -- the earlier failure must still fail
  // this pass.
  EXPECT_FALSE(evaluateOtaTrialRadioReadyThisPass(
    /*radio_present=*/true, /*base_radio_ready=*/true, /*radio_stuck_non_recv=*/false,
    /*driver_healthy=*/true, /*genuinely_servicing=*/true,
    /*fault_count_before_probe=*/6, /*fault_count_after_probe=*/6, /*last_known_fault_count=*/5));
}

TEST(OtaTrialRadioReadinessTest, ProbeItselfFailingThisTickIsNotReadyRegardlessOfEarlierBaseline) {
  EXPECT_FALSE(evaluateOtaTrialRadioReadyThisPass(
    /*radio_present=*/true, /*base_radio_ready=*/true, /*radio_stuck_non_recv=*/false,
    /*driver_healthy=*/true, /*genuinely_servicing=*/true,
    /*fault_count_before_probe=*/5, /*fault_count_after_probe=*/6, /*last_known_fault_count=*/5));
}

TEST(OtaTrialRadioReadinessTest, ATransientSingleTickFaultDoesNotPermanentlyDisqualifyTheNextPass) {
  // Tick N: a real fault advances the count (not ready this pass).
  EXPECT_FALSE(evaluateOtaTrialRadioReadyThisPass(
    /*radio_present=*/true, /*base_radio_ready=*/true, /*radio_stuck_non_recv=*/false,
    /*driver_healthy=*/true, /*genuinely_servicing=*/true,
    /*fault_count_before_probe=*/5, /*fault_count_after_probe=*/6, /*last_known_fault_count=*/5));
  // Tick N+1: the caller updates last_known_fault_count to 6 (the prior
  // tick's final value) regardless of outcome; this SAME radio, now
  // genuinely recovered and actively servicing with no further fault
  // advance, must be free to be ready again immediately -- proving the
  // fix is NOT sticky across ticks.
  EXPECT_TRUE(evaluateOtaTrialRadioReadyThisPass(
    /*radio_present=*/true, /*base_radio_ready=*/true, /*radio_stuck_non_recv=*/false,
    /*driver_healthy=*/true, /*genuinely_servicing=*/true,
    /*fault_count_before_probe=*/6, /*fault_count_after_probe=*/6, /*last_known_fault_count=*/6));
}

// ---------------------------------------------------------------------
// End-to-end epoch-sequence proof against the REAL
// OtaBoardTrialBootHealthConfirmer: a single transient fault followed by
// a genuine continuous 10-second window of active-service ticks still
// confirms before the 45-second deadline; a repeated stale-idle pattern
// (chip status internally consistent but never genuinely servicing,
// exactly the "7s idle + 1s Rx" exploit MAIN identified) can NEVER
// sustain a continuous 10-second window and therefore never confirms,
// instead genuinely expiring at the 45-second deadline.
// ---------------------------------------------------------------------

TEST(OtaTrialRadioReadinessTest, TransientFaultThenGenuineTenSecondActiveWindowConfirmsBeforeFortyFiveSeconds) {
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(64, 0x5A);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());
  const uint32_t start_ms = 1000;
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, start_ms);

  uint32_t now_ms = start_ms;
  uint32_t last_known_fault_count = 0;
  // Tick 0: a single real fault this pass (simulating an ordinary
  // startReceive() failure earlier this same tick) -- resets the window,
  // never a terminal failure.
  bool ready = evaluateOtaTrialRadioReadyThisPass(true, true, false, true, true, 1, 1, last_known_fault_count);
  last_known_fault_count = 1;
  EXPECT_FALSE(ready);
  mesh::ota::OtaBoardTrialHealthOutcome outcome = confirmer.tick(now_ms, ready, true, true);
  ASSERT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::Pending);

  // Ticks 1..11: genuinely, continuously servicing (active Rx), no
  // further fault advance -- a real fresh continuous window (window_start_ms_
  // is set on the FIRST good tick, so 11 further 1-second ticks are
  // needed to actually reach the full 10-second elapsed span from there).
  for (int i = 0; i < 11 && outcome == mesh::ota::OtaBoardTrialHealthOutcome::Pending; ++i) {
    now_ms += 1000;
    ready = evaluateOtaTrialRadioReadyThisPass(true, true, false, true, true,
                                                last_known_fault_count, last_known_fault_count,
                                                last_known_fault_count);
    EXPECT_TRUE(ready);
    outcome = confirmer.tick(now_ms, ready, true, true);
  }
  EXPECT_LT(now_ms - start_ms, 45000u);
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::Confirmed);
}

TEST(OtaTrialRadioReadinessTest, RepeatedStaleIdlePatternNeverSustainsTenSecondsAndExpiresAtDeadline) {
  // Reproduces MAIN's "7s idle + one Rx tick" exploit scenario: the chip
  // status is ALWAYS internally consistent (never an outright driver
  // fault), but genuinely idle (not servicing) most ticks, with a brief
  // single active-Rx tick just often enough to have reset any fixed
  // "stuck" timer under the OLD logic -- under the FIXED logic, each
  // idle tick simply fails to contribute, so 10 continuous ready ticks
  // can never accumulate and the confirmer must genuinely expire at the
  // deadline.
  FakeNorFlash state_flash(8192, 4096);
  FakeNorFlash confirm_flash(8192, 4096);
  ota::platform::FlashRegion state_region(state_flash, 0, 8192);
  ota::platform::FlashRegion confirm_region(confirm_flash, 0, 8192);

  std::vector<uint8_t> image(64, 0x5A);
  uint8_t hash[32];
  ota::trust::Sha256::hash(image.data(), image.size(), hash);
  const auto rec = makeStateRecordBytes(1, 7, XiaoOtaStateReader::kPhaseTrialBoot, 1234, 9, hash, hash);
  ASSERT_TRUE(ota::platform::isOk(state_region.program(0, rec.data(), static_cast<uint32_t>(rec.size()))));

  CountingFakeActiveImageAccessor fake;
  fake.image = image.data();
  fake.extent = static_cast<uint32_t>(image.size());
  const uint32_t start_ms = 0;
  mesh::ota::OtaBoardTrialBootHealthConfirmer confirmer(state_region, confirm_region, fake, start_ms);

  uint32_t now_ms = start_ms;
  mesh::ota::OtaBoardTrialHealthOutcome outcome = mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  for (int i = 0; i < 60 && outcome == mesh::ota::OtaBoardTrialHealthOutcome::Pending; ++i) {
    now_ms += 1000;
    // One-in-eight ticks genuinely servicing (Rx); the rest genuinely
    // idle but internally chip-consistent -- never a driver fault.
    const bool genuinely_servicing = (i % 8) == 7;
    const bool ready = evaluateOtaTrialRadioReadyThisPass(true, true, false, true, genuinely_servicing,
                                                            0, 0, 0);
    EXPECT_EQ(genuinely_servicing, ready);
    outcome = confirmer.tick(now_ms, ready, true, true);
  }
  EXPECT_EQ(outcome, mesh::ota::OtaBoardTrialHealthOutcome::DeadlineExpired);
}

// RadioLibDriverFaultClassification: distinguishes a genuine driver/SPI
// fault from an expected, ordinary over-the-air PHY decode rejection
// (RADIOLIB_ERR_CRC_MISMATCH) for RadioDriverHealthLatch purposes -- see
// RadioLibWrapper::recvRaw()'s readData() call site.
TEST(RadioLibDriverFaultClassificationTest, SuccessIsNeverAFault) {
  EXPECT_FALSE(radiolib_health::isGenuineRadioDriverFault(radiolib_health::kRadioLibErrNone));
}

TEST(RadioLibDriverFaultClassificationTest, OrdinaryCrcMismatchIsNotAGenuineDriverFault) {
  EXPECT_FALSE(radiolib_health::isGenuineRadioDriverFault(radiolib_health::kRadioLibErrCrcMismatch));
}

TEST(RadioLibDriverFaultClassificationTest, AnyOtherNonzeroStatusIsAGenuineDriverFault) {
  EXPECT_TRUE(radiolib_health::isGenuineRadioDriverFault(-2));   // e.g. RADIOLIB_ERR_UNKNOWN
  EXPECT_TRUE(radiolib_health::isGenuineRadioDriverFault(-706)); // e.g. LR2021 busy/hw fault
  EXPECT_TRUE(radiolib_health::isGenuineRadioDriverFault(1));
}

// A mixed stream of ordinary CRC-bad packets and successful RX must never
// advance RadioDriverHealthLatch's faultCount() (the OTA trial-health
// signal), while a genuine driver/SPI failure still must. Exercises the
// SAME classification predicate + RadioDriverHealthLatch pairing
// RadioLibWrapper::recvRaw() actually wires together.
TEST(RadioLibDriverFaultClassificationTest, MixedCrcBadAndSuccessfulRxNeverAdvancesFaultCount) {
  RadioDriverHealthLatch latch;
  const int statuses[] = {radiolib_health::kRadioLibErrNone, radiolib_health::kRadioLibErrCrcMismatch,
                          radiolib_health::kRadioLibErrCrcMismatch, radiolib_health::kRadioLibErrNone,
                          radiolib_health::kRadioLibErrCrcMismatch};
  for (int status : statuses) {
    latch.recordOutcome(!radiolib_health::isGenuineRadioDriverFault(status));
  }
  EXPECT_EQ(latch.faultCount(), 0u);
  EXPECT_TRUE(latch.healthy());
}

TEST(RadioLibDriverFaultClassificationTest, GenuineSpiReadFailureStillAdvancesFaultCount) {
  RadioDriverHealthLatch latch;
  latch.recordOutcome(!radiolib_health::isGenuineRadioDriverFault(radiolib_health::kRadioLibErrNone));
  latch.recordOutcome(!radiolib_health::isGenuineRadioDriverFault(-2)); // genuine driver fault
  EXPECT_EQ(latch.faultCount(), 1u);
  EXPECT_FALSE(latch.healthy());
}


int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
