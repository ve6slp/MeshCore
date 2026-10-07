// Exercises nRF flash-region boundaries against a real-sized FakeNorFlash:
// image banks, security tails, candidate metadata and the fixed installer.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashRegion.h"
#include "ota/platform/FlashTypes.h"
#include "ota/platform/SenseCapQspiLayout.h"
#include "ota/platform/Nrf52FlashLayoutContract.h"
#include "ota/runtime/OtaGeometry.h"
#include "ota/storage/XiaoOtaActiveExtentBridge.h"

#include "../test_lora_ota_storage/FakeNorFlash.h"

using ota::platform::FlashRegion;
using ota::platform::FlashStatus;
using ota::platform::SenseCapQspiLayout;
using ota::test::FakeNorFlash;

namespace {

FakeNorFlash makeRealSizedDevice() {
  return FakeNorFlash(SenseCapQspiLayout::kTotalBytes, SenseCapQspiLayout::kEraseUnitBytes);
}

// Erases and programs `region` fully with `byte_pattern` (which must have
// at least one 0 bit so it applies cleanly onto freshly-erased 0xFF), then
// reads it back and asserts the seed actually took effect -- so later
// "preserved" assertions cannot be satisfied by the region simply still
// being at its erased default.
void seedNonFf(FlashRegion& region, uint8_t byte_pattern) {
  ASSERT_NE(byte_pattern, 0xFFu);
  ASSERT_EQ(region.eraseRange(0, region.sizeBytes()), FlashStatus::Ok);
  std::vector<uint8_t> pattern(region.sizeBytes(), byte_pattern);
  ASSERT_EQ(region.program(0, pattern.data(), pattern.size()), FlashStatus::Ok);
  std::vector<uint8_t> readback(region.sizeBytes(), 0);
  ASSERT_EQ(region.read(0, readback.data(), readback.size()), FlashStatus::Ok);
  ASSERT_EQ(0, std::memcmp(pattern.data(), readback.data(), pattern.size()))
      << "seed did not take effect -- preservation assertions below would be meaningless";
}

void expectRegionStillReads(FlashRegion& region, uint8_t expected_byte_pattern) {
  std::vector<uint8_t> readback(region.sizeBytes(), 0);
  ASSERT_EQ(region.read(0, readback.data(), readback.size()), FlashStatus::Ok);
  std::vector<uint8_t> expected(region.sizeBytes(), expected_byte_pattern);
  EXPECT_EQ(0, std::memcmp(expected.data(), readback.data(), expected.size()));
}

}  // namespace

// -----------------------------------------------------------------------
// Static layout validity and the new tail-safe boundary contract.
// -----------------------------------------------------------------------

TEST(NrfLayoutBoundaries, StaticLayoutIsValid) {
  EXPECT_TRUE(SenseCapQspiLayout::isValid());
}

TEST(NrfLayoutBoundaries, ApprovedHalfOpenMapExactly) {
  EXPECT_EQ(SenseCapQspiLayout::kCandidateOffset, 0x000000u);
  EXPECT_EQ(SenseCapQspiLayout::kCandidateSize, 0x0AD000u);
  EXPECT_EQ(SenseCapQspiLayout::kSecurityAOffset, 0x0AD000u);
  EXPECT_EQ(SenseCapQspiLayout::kSecurityASize, 0x019000u);
  EXPECT_EQ(SenseCapQspiLayout::kBackupOffset, 0x0C6000u);
  EXPECT_EQ(SenseCapQspiLayout::kBackupSize, 0x0AD000u);
  EXPECT_EQ(SenseCapQspiLayout::kSecurityBOffset, 0x173000u);
  EXPECT_EQ(SenseCapQspiLayout::kSecurityBSize, 0x019000u);
  EXPECT_EQ(SenseCapQspiLayout::kJournalOffset, 0x18C000u);
  EXPECT_EQ(SenseCapQspiLayout::kJournalSize, 0x008000u);
  EXPECT_EQ(SenseCapQspiLayout::kFilesystemOffset, 0x194000u);
  EXPECT_EQ(SenseCapQspiLayout::kFilesystemSize, 0x06C000u);
  // Six regions exactly tile the 2 MiB device with no gaps.
  EXPECT_EQ(SenseCapQspiLayout::kFilesystemOffset + SenseCapQspiLayout::kFilesystemSize,
            SenseCapQspiLayout::kTotalBytes);
}

TEST(NrfLayoutBoundaries, PhysicalBankStrideFixedRegardlessOfImageCapacity) {
  // Backup offset must remain exactly one physical stride after candidate
  // -- 0xC6000, fixed -- independent of kCandidateSize/kBackupSize.
  EXPECT_EQ(SenseCapQspiLayout::kPhysicalBankStrideBytes, 0x0C6000u);
  EXPECT_EQ(SenseCapQspiLayout::kBackupOffset,
            SenseCapQspiLayout::kCandidateOffset + SenseCapQspiLayout::kPhysicalBankStrideBytes);
  // Physical stride is NOT writable capacity: it strictly exceeds the
  // actual image capacity by exactly one security tail.
  EXPECT_EQ(SenseCapQspiLayout::kCandidateSize + SenseCapQspiLayout::kSecurityTailBytes,
            SenseCapQspiLayout::kPhysicalBankStrideBytes);
  EXPECT_EQ(SenseCapQspiLayout::kBackupSize + SenseCapQspiLayout::kSecurityTailBytes,
            SenseCapQspiLayout::kPhysicalBankStrideBytes);
}

TEST(NrfLayoutBoundaries, SecurityTailsAreWholeHundredKibEachAndBackToBackWithImageCapacity) {
  EXPECT_EQ(SenseCapQspiLayout::kSecurityTailBytes, 100u * 1024u);
  EXPECT_EQ(SenseCapQspiLayout::kSecurityASize, SenseCapQspiLayout::kSecurityTailBytes);
  EXPECT_EQ(SenseCapQspiLayout::kSecurityBSize, SenseCapQspiLayout::kSecurityTailBytes);
  EXPECT_EQ(SenseCapQspiLayout::kCandidateOffset + SenseCapQspiLayout::kCandidateSize,
            SenseCapQspiLayout::kSecurityAOffset);
  EXPECT_EQ(SenseCapQspiLayout::kBackupOffset + SenseCapQspiLayout::kBackupSize,
            SenseCapQspiLayout::kSecurityBOffset);
}

TEST(NrfLayoutBoundaries, LastLegalImageSectorOffsetsMatchApprovedBoundaries) {
  EXPECT_EQ(SenseCapQspiLayout::kCandidateLastLegalSectorOffset, 0x0AC000u);
  EXPECT_EQ(SenseCapQspiLayout::kBackupLastLegalSectorOffset, 0x172000u);
  EXPECT_EQ(OTA_NRF52_INTERNAL_IMAGE_LAST_LEGAL_SECTOR_OFFSET, 0x0C3000u);
  // Exactly one erase unit before the corresponding security tail start.
  EXPECT_EQ(SenseCapQspiLayout::kCandidateLastLegalSectorOffset + SenseCapQspiLayout::kEraseUnitBytes,
            SenseCapQspiLayout::kSecurityAOffset);
  EXPECT_EQ(SenseCapQspiLayout::kBackupLastLegalSectorOffset + SenseCapQspiLayout::kEraseUnitBytes,
            SenseCapQspiLayout::kSecurityBOffset);
}

// -----------------------------------------------------------------------
// Real FlashRegion/FakeNorFlash bounds enforcement: candidate/backup image
// regions must actually be sized to image capacity only, and must reject
// any program/erase that reaches into (or across) the first tail byte.
// -----------------------------------------------------------------------

TEST(NrfLayoutBoundaries, CandidateAndBackupRegionsAreExactlyImageCapacitySized) {
  FakeNorFlash flash = makeRealSizedDevice();
  FlashRegion candidate = SenseCapQspiLayout::candidateRegion(flash);
  FlashRegion backup = SenseCapQspiLayout::backupRegion(flash);
  ASSERT_TRUE(candidate.isValid());
  ASSERT_TRUE(backup.isValid());
  EXPECT_EQ(candidate.sizeBytes(), SenseCapQspiLayout::kCandidateSize);
  EXPECT_EQ(candidate.baseOffset(), SenseCapQspiLayout::kCandidateOffset);
  EXPECT_EQ(backup.sizeBytes(), SenseCapQspiLayout::kBackupSize);
  EXPECT_EQ(backup.baseOffset(), SenseCapQspiLayout::kBackupOffset);
}

TEST(NrfLayoutBoundaries, CandidateRegionRejectsEraseAtFirstTailByte) {
  FakeNorFlash flash = makeRealSizedDevice();
  FlashRegion candidate = SenseCapQspiLayout::candidateRegion(flash);
  // region_offset == kCandidateSize is exactly the first byte of
  // securityA, relative to the candidate region's own base -- must be
  // rejected as out of range, never silently permitted.
  EXPECT_EQ(candidate.eraseSector(SenseCapQspiLayout::kCandidateSize), FlashStatus::OutOfRange);
  // One sector further in is rejected too.
  EXPECT_EQ(candidate.eraseSector(SenseCapQspiLayout::kCandidateSize + SenseCapQspiLayout::kEraseUnitBytes),
            FlashStatus::OutOfRange);
  // The direct absolute-address probe: erasing device offset kSecurityAOffset
  // through the securityA accessor (not candidateRegion) must still work --
  // proving the tail is real, separate, addressable capability space, not
  // simply unreachable/broken.
  FlashRegion security_a = SenseCapQspiLayout::securityARegion(flash);
  ASSERT_TRUE(security_a.isValid());
  EXPECT_EQ(security_a.eraseSector(0), FlashStatus::Ok);
}

TEST(NrfLayoutBoundaries, CandidateRegionRejectsProgramCrossingIntoSecurityTail) {
  FakeNorFlash flash = makeRealSizedDevice();
  FlashRegion candidate = SenseCapQspiLayout::candidateRegion(flash);
  uint8_t data[16];
  std::memset(data, 0xAB, sizeof(data));
  // A program call starting inside the last legal sector but whose length
  // would extend past kCandidateSize (into securityA) must be rejected.
  const uint32_t start_near_end = SenseCapQspiLayout::kCandidateSize - 8u;
  EXPECT_EQ(candidate.program(start_near_end, data, sizeof(data)), FlashStatus::OutOfRange);
  // Reading across the same boundary is likewise rejected.
  uint8_t readback[16];
  EXPECT_EQ(candidate.read(start_near_end, readback, sizeof(readback)), FlashStatus::OutOfRange);
}

TEST(NrfLayoutBoundaries, BackupRegionRejectsEraseAtFirstTailByte) {
  FakeNorFlash flash = makeRealSizedDevice();
  FlashRegion backup = SenseCapQspiLayout::backupRegion(flash);
  EXPECT_EQ(backup.eraseSector(SenseCapQspiLayout::kBackupSize), FlashStatus::OutOfRange);
  FlashRegion security_b = SenseCapQspiLayout::securityBRegion(flash);
  ASSERT_TRUE(security_b.isValid());
  EXPECT_EQ(security_b.eraseSector(0), FlashStatus::Ok);
}

TEST(NrfLayoutBoundaries, BackupRegionRejectsProgramCrossingIntoSecurityTail) {
  FakeNorFlash flash = makeRealSizedDevice();
  FlashRegion backup = SenseCapQspiLayout::backupRegion(flash);
  uint8_t data[16];
  std::memset(data, 0xAB, sizeof(data));
  // Mirrors CandidateRegionRejectsProgramCrossingIntoSecurityTail above,
  // but for the backup/securityB boundary -- both banks must reject a
  // program call that would cross into their tail identically.
  const uint32_t start_near_end = SenseCapQspiLayout::kBackupSize - 8u;
  EXPECT_EQ(backup.program(start_near_end, data, sizeof(data)), FlashStatus::OutOfRange);
  uint8_t readback[16];
  EXPECT_EQ(backup.read(start_near_end, readback, sizeof(readback)), FlashStatus::OutOfRange);
}

TEST(NrfLayoutBoundaries, LastLegalSectorEraseAndProgramSucceedOnBothBanks) {
  FakeNorFlash flash = makeRealSizedDevice();
  FlashRegion candidate = SenseCapQspiLayout::candidateRegion(flash);
  FlashRegion backup = SenseCapQspiLayout::backupRegion(flash);

  const uint32_t candidate_last_region_relative =
      SenseCapQspiLayout::kCandidateLastLegalSectorOffset - SenseCapQspiLayout::kCandidateOffset;
  const uint32_t backup_last_region_relative =
      SenseCapQspiLayout::kBackupLastLegalSectorOffset - SenseCapQspiLayout::kBackupOffset;

  ASSERT_EQ(candidate.eraseSector(candidate_last_region_relative), FlashStatus::Ok);
  ASSERT_EQ(backup.eraseSector(backup_last_region_relative), FlashStatus::Ok);

  uint8_t pattern[8];
  std::memset(pattern, 0x5A, sizeof(pattern));
  EXPECT_EQ(candidate.program(candidate_last_region_relative, pattern, sizeof(pattern)), FlashStatus::Ok);
  EXPECT_EQ(backup.program(backup_last_region_relative, pattern, sizeof(pattern)), FlashStatus::Ok);

  uint8_t readback[8] = {0};
  EXPECT_EQ(candidate.read(candidate_last_region_relative, readback, sizeof(readback)), FlashStatus::Ok);
  EXPECT_EQ(0, std::memcmp(pattern, readback, sizeof(pattern)));
  std::memset(readback, 0, sizeof(readback));
  EXPECT_EQ(backup.read(backup_last_region_relative, readback, sizeof(readback)), FlashStatus::Ok);
  EXPECT_EQ(0, std::memcmp(pattern, readback, sizeof(pattern)));

  // But one sector further (the first tail sector) must be rejected on
  // both banks -- the boundary is exact, not off-by-one.
  const uint32_t candidate_first_tail_relative = candidate_last_region_relative + SenseCapQspiLayout::kEraseUnitBytes;
  const uint32_t backup_first_tail_relative = backup_last_region_relative + SenseCapQspiLayout::kEraseUnitBytes;
  EXPECT_EQ(candidate.eraseSector(candidate_first_tail_relative), FlashStatus::OutOfRange);
  EXPECT_EQ(backup.eraseSector(backup_first_tail_relative), FlashStatus::OutOfRange);
}

TEST(NrfLayoutBoundaries, SecurityRegionsAreValidAndDoNotOverlapImageRegions) {
  FakeNorFlash flash = makeRealSizedDevice();
  FlashRegion candidate = SenseCapQspiLayout::candidateRegion(flash);
  FlashRegion backup = SenseCapQspiLayout::backupRegion(flash);
  FlashRegion security_a = SenseCapQspiLayout::securityARegion(flash);
  FlashRegion security_b = SenseCapQspiLayout::securityBRegion(flash);
  ASSERT_TRUE(security_a.isValid());
  ASSERT_TRUE(security_b.isValid());
  EXPECT_EQ(security_a.sizeBytes(), SenseCapQspiLayout::kSecurityTailBytes);
  EXPECT_EQ(security_b.sizeBytes(), SenseCapQspiLayout::kSecurityTailBytes);

  EXPECT_FALSE(SenseCapQspiLayout::rangesOverlap(candidate.baseOffset(), candidate.sizeBytes(),
                                                  security_a.baseOffset(), security_a.sizeBytes()));
  EXPECT_FALSE(SenseCapQspiLayout::rangesOverlap(backup.baseOffset(), backup.sizeBytes(),
                                                  security_b.baseOffset(), security_b.sizeBytes()));
  EXPECT_FALSE(SenseCapQspiLayout::rangesOverlap(security_a.baseOffset(), security_a.sizeBytes(),
                                                  backup.baseOffset(), backup.sizeBytes()));
}

TEST(NrfLayoutBoundaries, JournalAndFilesystemRegionsRemainUnchangedAndValid) {
  FakeNorFlash flash = makeRealSizedDevice();
  FlashRegion journal = SenseCapQspiLayout::journalRegion(flash);
  FlashRegion filesystem = SenseCapQspiLayout::filesystemRegion(flash);
  ASSERT_TRUE(journal.isValid());
  ASSERT_TRUE(filesystem.isValid());
  EXPECT_EQ(journal.baseOffset(), 0x18C000u);
  EXPECT_EQ(journal.sizeBytes(), 0x008000u);
  EXPECT_EQ(filesystem.baseOffset(), 0x194000u);
  EXPECT_EQ(filesystem.sizeBytes(), 0x06C000u);
}

TEST(NrfLayoutBoundaries, CandidateRecordsNeverTouchJournalSecurityTailsOrFilesystem) {
  FakeNorFlash flash = makeRealSizedDevice();
  FlashRegion records = SenseCapQspiLayout::candidateRecordRegion(flash);
  ASSERT_TRUE(records.isValid());
  EXPECT_EQ(records.baseOffset(), SenseCapQspiLayout::kCandidateRecordOffset);
  EXPECT_EQ(records.sizeBytes(), SenseCapQspiLayout::kCandidateRecordSize);
  EXPECT_GE(records.baseOffset(), OTA_NRF52_INTERNAL_IMAGE_SIZE);

  // Positive mutation proof: preseed all four protected neighbors non-FF...
  FlashRegion real_journal = SenseCapQspiLayout::journalRegion(flash);
  FlashRegion security_a = SenseCapQspiLayout::securityARegion(flash);
  FlashRegion security_b = SenseCapQspiLayout::securityBRegion(flash);
  FlashRegion filesystem = SenseCapQspiLayout::filesystemRegion(flash);
  seedNonFf(real_journal, 0x91u);
  seedNonFf(security_a, 0x92u);
  seedNonFf(security_b, 0x93u);
  seedNonFf(filesystem, 0x94u);

  ASSERT_EQ(records.eraseRange(0, records.sizeBytes()), FlashStatus::Ok);
  std::vector<uint8_t> record_pattern(records.sizeBytes(), 0xE5u);
  ASSERT_EQ(records.program(0, record_pattern.data(), record_pattern.size()), FlashStatus::Ok);
  EXPECT_EQ(records.eraseSector(records.sizeBytes()), FlashStatus::OutOfRange);

  // The real journal, both tails, and the filesystem must be unchanged.
  expectRegionStillReads(real_journal, 0x91u);
  expectRegionStillReads(security_a, 0x92u);
  expectRegionStillReads(security_b, 0x93u);
  expectRegionStillReads(filesystem, 0x94u);
}

TEST(NrfLayoutBoundaries, CandidatePayloadCannotEraseOrProgramItsDurableMetadata) {
  FakeNorFlash flash = makeRealSizedDevice();
  FlashRegion payload = SenseCapQspiLayout::candidatePayloadRegion(flash);
  FlashRegion records = SenseCapQspiLayout::candidateRecordRegion(flash);
  ASSERT_TRUE(payload.isValid());
  seedNonFf(records, 0x93);
  EXPECT_EQ(payload.baseOffset() + payload.sizeBytes(), records.baseOffset());
  EXPECT_EQ(payload.sizeBytes(), 700416u);
  EXPECT_GE(payload.sizeBytes(), OTA_NRF52_INTERNAL_IMAGE_SIZE);
  const uint8_t crossing[2] = {0x35, 0x37};
  EXPECT_EQ(payload.eraseSector(payload.sizeBytes()), FlashStatus::OutOfRange);
  EXPECT_EQ(payload.eraseRange(payload.sizeBytes() - payload.eraseUnitBytes(),
                              2u * payload.eraseUnitBytes()), FlashStatus::OutOfRange);
  EXPECT_EQ(payload.program(payload.sizeBytes() - 1, crossing, sizeof(crossing)),
            FlashStatus::OutOfRange);
  expectRegionStillReads(records, 0x93);
}

// -----------------------------------------------------------------------
// Internal install capacity is target-specific, not generic staging capacity.
// -----------------------------------------------------------------------

TEST(NrfLayoutBoundaries, InternalImageReservesFixedInstallerWithoutShrinkingExternalCapacity) {
  EXPECT_EQ(OTA_NRF52_INTERNAL_IMAGE_OFFSET, 0x027000u);
  EXPECT_EQ(OTA_NRF52_INTERNAL_IMAGE_SIZE, 643072u);
  EXPECT_EQ(ota::storage::kXiaoOtaAppInstallMaxSize, OTA_NRF52_INTERNAL_IMAGE_SIZE);
  EXPECT_EQ(ota::storage::kXiaoOtaAppStart, OTA_NRF52_INTERNAL_IMAGE_OFFSET);
  EXPECT_EQ(OTA_NRF52_INTERNAL_IMAGE_OFFSET + OTA_NRF52_INTERNAL_IMAGE_SIZE, 0x0C4000u);
  EXPECT_EQ(OTA_NRF52_INTERNAL_INSTALLER_OFFSET, 0x0C4000u);
  EXPECT_EQ(OTA_NRF52_INTERNAL_INSTALLER_SIZE, 64u * 1024u);
  EXPECT_EQ(OTA_NRF52_INTERNAL_IMAGE_LAST_LEGAL_SECTOR_OFFSET + SenseCapQspiLayout::kEraseUnitBytes,
            OTA_NRF52_INTERNAL_INSTALLER_OFFSET);
  EXPECT_EQ(OTA_NRF52_INTERNAL_INSTALLER_OFFSET + OTA_NRF52_INTERNAL_INSTALLER_SIZE,
            OTA_NRF52_INTERNAL_FS_OFFSET);
  EXPECT_LT(OTA_NRF52_INTERNAL_IMAGE_SIZE, SenseCapQspiLayout::kCandidateSize);
  EXPECT_EQ(meshcore::ota::runtime::kOtaMaxImageBytes, 708608u);
  EXPECT_EQ(meshcore::ota::runtime::kOtaMaxChunkCount, 5536u);
  EXPECT_EQ(SenseCapQspiLayout::kCandidateSize, meshcore::ota::runtime::kOtaMaxImageBytes);
  EXPECT_EQ(OTA_NRF52_INTERNAL_FS_OFFSET, 0x0D4000u);
  EXPECT_EQ(OTA_NRF52_INTERNAL_FS_SIZE, 0x019000u);
  // 100 KiB, unmoved.
  EXPECT_EQ(OTA_NRF52_INTERNAL_FS_OFFSET + OTA_NRF52_INTERNAL_FS_SIZE, 0x0ED000u);
}

// -----------------------------------------------------------------------
// Real, full-capacity tail/journal/filesystem preservation. All of these
// neighbor regions are first preseeded with a distinct NON-FF pattern
// (seedNonFf asserts the seed actually took) so a later readback that
// merely still shows the erased 0xFF default can never be mistaken for
// "preserved". Only then is a real full-image-capacity erase+program
// cycle driven across the ENTIRE candidate/backup regions, and the
// neighbors re-read to confirm byte-for-byte survival.
// -----------------------------------------------------------------------

TEST(NrfLayoutBoundaries, CandidateFullCapacityOperationsPreserveBothTailsJournalAndFilesystem) {
  FakeNorFlash flash = makeRealSizedDevice();
  FlashRegion security_a = SenseCapQspiLayout::securityARegion(flash);
  FlashRegion security_b = SenseCapQspiLayout::securityBRegion(flash);
  FlashRegion journal = SenseCapQspiLayout::journalRegion(flash);
  FlashRegion filesystem = SenseCapQspiLayout::filesystemRegion(flash);

  seedNonFf(security_a, 0x11u);
  seedNonFf(security_b, 0x22u);
  seedNonFf(journal, 0x33u);
  seedNonFf(filesystem, 0x44u);

  // A real, full-image-capacity erase+program cycle across the entire
  // candidate region -- not a single sector, the whole kCandidateSize.
  FlashRegion candidate = SenseCapQspiLayout::candidateRegion(flash);
  ASSERT_EQ(candidate.eraseRange(0, candidate.sizeBytes()), FlashStatus::Ok);
  std::vector<uint8_t> image_pattern(candidate.sizeBytes(), 0xC3u);
  ASSERT_EQ(candidate.program(0, image_pattern.data(), image_pattern.size()), FlashStatus::Ok);

  expectRegionStillReads(security_a, 0x11u);
  expectRegionStillReads(security_b, 0x22u);
  expectRegionStillReads(journal, 0x33u);
  expectRegionStillReads(filesystem, 0x44u);
}

TEST(NrfLayoutBoundaries, BackupFullCapacityOperationsPreserveBothTailsJournalAndFilesystem) {
  FakeNorFlash flash = makeRealSizedDevice();
  FlashRegion security_a = SenseCapQspiLayout::securityARegion(flash);
  FlashRegion security_b = SenseCapQspiLayout::securityBRegion(flash);
  FlashRegion journal = SenseCapQspiLayout::journalRegion(flash);
  FlashRegion filesystem = SenseCapQspiLayout::filesystemRegion(flash);

  seedNonFf(security_a, 0x55u);
  seedNonFf(security_b, 0x66u);
  seedNonFf(journal, 0x77u);
  seedNonFf(filesystem, 0x88u);

  // Same full-image-capacity erase+program cycle, but across the ENTIRE
  // backup region this time, to prove both banks -- not just candidate --
  // can never reach their own or the other bank's tail, nor the journal/
  // filesystem, during a real full-size operation.
  FlashRegion backup = SenseCapQspiLayout::backupRegion(flash);
  ASSERT_EQ(backup.eraseRange(0, backup.sizeBytes()), FlashStatus::Ok);
  std::vector<uint8_t> image_pattern(backup.sizeBytes(), 0xD4u);
  ASSERT_EQ(backup.program(0, image_pattern.data(), image_pattern.size()), FlashStatus::Ok);

  expectRegionStillReads(security_a, 0x55u);
  expectRegionStillReads(security_b, 0x66u);
  expectRegionStillReads(journal, 0x77u);
  expectRegionStillReads(filesystem, 0x88u);
}
