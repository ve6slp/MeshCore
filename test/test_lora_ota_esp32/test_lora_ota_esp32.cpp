#include <gtest/gtest.h>
#include <ota/platform/Esp32FlashAdapter.h>
#include <ota/platform/FlashRegion.h>
#include <ota/storage/StorageManager.h>
#include <helpers/ota/OtaEsp32RollbackGuard.h>
#include "Esp32SdkModel.h"
#include "Esp32ProductBackendTests.h"

using namespace ota::storage;
using namespace ota::test;
using ota::platform::Esp32FlashAdapter;
using ota::platform::FlashRegion;
using ota::platform::FlashStatus;
using ota::storage::StorageManager;

namespace {

void expectProtected(const Esp32PartitionModel& sdk, const std::vector<uint8_t>& before,
                     const Esp32PartitionIdentity& candidate) {
  EXPECT_EQ(0, memcmp(before.data(), sdk.bytes.data(), candidate.address));
  const size_t tail = candidate.address + candidate.size;
  EXPECT_EQ(0, memcmp(before.data() + tail, sdk.bytes.data() + tail, before.size() - tail));
}

}  // namespace

TEST(Esp32Flash, CompatibilityConstructorRemainsUnsupported) {
  Esp32FlashAdapter flash(0x800000, 4096, 1);
  uint8_t value = 0x42;
  EXPECT_EQ(0x800000u, flash.totalSizeBytes());
  EXPECT_EQ(FlashStatus::Unsupported, flash.read(0, &value, 1));
  EXPECT_EQ(0x42, value);
  EXPECT_EQ(FlashStatus::Unsupported, flash.program(0, &value, 1));
  EXPECT_EQ(FlashStatus::Unsupported, flash.eraseSector(0));
  EXPECT_FALSE(flash.isBound());
  EXPECT_FALSE(Esp32FlashAdapter::installationAvailable());
}

TEST(Esp32Flash, ActualPartitionIoBothSlotDirectionsPreservesEveryOtherByte) {
  for (bool running_app1 : {false, true}) {
    SCOPED_TRACE(running_app1);
    Esp32PartitionModel sdk(running_app1);
    Esp32Owners owners;
    Esp32FlashAdapter flash(sdk, owners);
    const auto before = sdk.bytes;
    ASSERT_EQ(FlashStatus::Ok, flash.bind(4097));
    EXPECT_EQ(0x330000u, flash.totalSizeBytes());
    EXPECT_EQ(4096u, flash.eraseUnitBytes());
    EXPECT_EQ(1u, flash.programUnitBytes());
    EXPECT_TRUE(esp32PartitionEquals(sdk.snapshot.next, flash.partition()));
    FlashRegion candidate(flash, 0, flash.totalSizeBytes());
    ASSERT_TRUE(candidate.isValid());
    ASSERT_EQ(FlashStatus::Ok, candidate.eraseRange(0, 8192));
    std::vector<uint8_t> chunk(512, 0x39), readback(512, 0);
    ASSERT_TRUE(StorageManager::writeAndVerifyChunk(candidate, 1, 512, chunk.data(), chunk.size()));
    ASSERT_EQ(FlashStatus::Ok, candidate.read(512, readback.data(), readback.size()));
    EXPECT_EQ(chunk, readback);
    EXPECT_EQ((std::vector<uint32_t>{0, 4096}), sdk.erasedOffsets);
    EXPECT_EQ(1u, sdk.writeCalls);
    EXPECT_EQ(0, memcmp(chunk.data(), sdk.bytes.data() + sdk.snapshot.next.address + 512, chunk.size()));
    EXPECT_EQ(0, memcmp(before.data() + sdk.snapshot.next.address + 8192,
                        sdk.bytes.data() + sdk.snapshot.next.address + 8192, sdk.snapshot.next.size - 8192));
    expectProtected(sdk, before, sdk.snapshot.next);
  }
}

TEST(Esp32Flash, ReorderedExactTableIsAcceptedButDuplicateOrExtraEntryIsNot) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  std::swap(sdk.snapshot.table[0], sdk.snapshot.table[5]);
  EXPECT_EQ(FlashStatus::Ok, flash.bind(1));
  sdk.snapshot.table[0] = sdk.snapshot.table[1];
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
  EXPECT_EQ(Esp32FlashAdapter::Refusal::Table, flash.lastRefusal());
  sdk.snapshot.count = 7;
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
  EXPECT_EQ(0u, sdk.writeCalls);
  EXPECT_TRUE(sdk.erasedOffsets.empty());
}

TEST(Esp32Flash, EveryAlteredPartitionTableFieldRefusesBeforeMutation) {
  for (size_t entry = 0; entry < 6; ++entry) {
    for (size_t field = 0; field < 7; ++field) {
      SCOPED_TRACE(entry);
      SCOPED_TRACE(field);
      Esp32PartitionModel sdk;
      Esp32Owners owners;
      Esp32FlashAdapter flash(sdk, owners);
      auto& p = sdk.snapshot.table[entry];
      switch (field) {
        case 0: ++p.address; break;
        case 1: p.size -= 4096; break;
        case 2: ++p.type; break;
        case 3: ++p.subtype; break;
        case 4: p.label[0] ^= 1; break;
        case 5: p.encrypted = true; break;
        case 6: p.defaultFlash = false; break;
      }
      EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
      EXPECT_FALSE(flash.isBound());
      EXPECT_EQ(0u, sdk.writeCalls);
      EXPECT_TRUE(sdk.erasedOffsets.empty());
    }
  }
}

TEST(Esp32Flash, RunningFilesystemNvsOtadataCoredumpAndBootAreNeverBindable) {
  for (size_t entry : {size_t(0), size_t(1), size_t(2), size_t(4), size_t(5), size_t(6)}) {
    Esp32PartitionModel sdk;
    Esp32Owners owners;
    Esp32FlashAdapter flash(sdk, owners);
    const auto before = sdk.bytes;
    sdk.snapshot.next = entry == 6 ? Esp32PartitionIdentity{} : Esp32S3PartitionLayout::entry(entry);
    if (entry == 6) {
      sdk.snapshot.next.size = 0x8000;
      memcpy(sdk.snapshot.next.label, "bootloader", 11);
      sdk.snapshot.next.defaultFlash = true;
    }
    EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
    EXPECT_EQ(FlashStatus::Unsupported, flash.eraseSector(0));
    EXPECT_EQ(before, sdk.bytes);
    EXPECT_EQ(0u, sdk.writeCalls);
    EXPECT_TRUE(sdk.erasedOffsets.empty());
  }
}

TEST(Esp32Flash, PersistedPartitionCannotSelectWrongLabelSlotOrGeometry) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  for (size_t i = 0; i < 6; ++i) {
    if (i == 3) continue;
    const auto persisted = Esp32S3PartitionLayout::entry(i);
    EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(4096, &persisted));
  }
  auto persisted = sdk.snapshot.next;
  memcpy(persisted.label, "wrong", 6);
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(4096, &persisted));
  persisted = sdk.snapshot.next;
  ++persisted.size;
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(4096, &persisted));
  EXPECT_EQ(0u, sdk.writeCalls);
}

TEST(Esp32Flash, CapacityAlignmentAndOverflowAreMeasuredBeforeAnySdkIo) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(0));
  EXPECT_EQ(FlashStatus::OutOfRange, flash.bind(0x330001));
  EXPECT_EQ(FlashStatus::OutOfRange, flash.bind(UINT32_MAX));
  ASSERT_EQ(FlashStatus::Ok, flash.bind(0x330000));
  uint8_t byte = 0;
  for (const auto offset : {uint32_t(0x330000), uint32_t(0x330001), UINT32_MAX, UINT32_MAX - 4095}) {
    EXPECT_EQ(FlashStatus::OutOfRange, flash.read(offset, &byte, 1));
    EXPECT_EQ(FlashStatus::OutOfRange, flash.program(offset, &byte, 1));
    EXPECT_EQ(FlashStatus::OutOfRange, flash.eraseSector(offset));
  }
  EXPECT_EQ(FlashStatus::OutOfRange, flash.read(1, &byte, UINT32_MAX));
  EXPECT_EQ(FlashStatus::OutOfRange, flash.program(4096, &byte, UINT32_MAX));
  EXPECT_EQ(FlashStatus::Unaligned, flash.eraseSector(1));
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.read(0, nullptr, 1));
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.program(0, nullptr, 1));
  EXPECT_EQ(FlashStatus::Ok, flash.read(flash.totalSizeBytes(), nullptr, 0));
  EXPECT_EQ(FlashStatus::Ok, flash.program(flash.totalSizeBytes(), nullptr, 0));
  EXPECT_EQ(0u, sdk.readCalls);
  EXPECT_EQ(0u, sdk.writeCalls);
  EXPECT_TRUE(sdk.erasedOffsets.empty());
}

TEST(Esp32Flash, NumericPhysicalAddressesRemainOnlyRelativeInactiveOffsets) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  const auto before = sdk.bytes;
  ASSERT_EQ(FlashStatus::Ok, flash.bind(1));
  const uint8_t value = 0x16;
  for (const uint32_t offset : {0u, 0x9000u, 0xe000u, 0x10000u}) {
    ASSERT_EQ(FlashStatus::Ok, flash.program(offset, &value, 1));
    EXPECT_EQ(value, sdk.bytes[sdk.snapshot.next.address + offset]);
  }
  expectProtected(sdk, before, sdk.snapshot.next);
}

TEST(Esp32Flash, UnknownOtherLeasePendingTrialAndUnresolvedBootSelectionRefuse) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  for (const auto ownership : {Esp32UpdateOwnership::Unknown, Esp32UpdateOwnership::OtherUpdater}) {
    owners.flash = ownership;
    EXPECT_EQ(FlashStatus::IoError, flash.bind(1));
    EXPECT_EQ(Esp32FlashAdapter::Refusal::Ownership, flash.lastRefusal());
  }
  owners.flash = Esp32UpdateOwnership::ExclusiveStorage;
  for (size_t app = 0; app < 2; ++app) {
    for (const auto state : {Esp32ImageState::New, Esp32ImageState::PendingVerify}) {
      sdk.snapshot.appStates[app] = state;
      EXPECT_EQ(FlashStatus::IoError, flash.bind(1));
      EXPECT_EQ(Esp32FlashAdapter::Refusal::Trial, flash.lastRefusal());
    }
    sdk.snapshot.appStates[app] = Esp32ImageState::Valid;
  }
  sdk.snapshot.boot = sdk.snapshot.next;
  EXPECT_EQ(FlashStatus::IoError, flash.bind(1));
  EXPECT_EQ(Esp32FlashAdapter::Refusal::BootSelection, flash.lastRefusal());
  sdk.snapshot.boot = {};
  EXPECT_EQ(FlashStatus::IoError, flash.bind(1));
  EXPECT_EQ(0u, sdk.writeCalls);
  EXPECT_TRUE(sdk.erasedOffsets.empty());
}

TEST(Esp32Flash, RevalidatesSelectionTableAndOwnershipOnEveryOperation) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  ASSERT_EQ(FlashStatus::Ok, flash.bind(1));
  uint8_t byte = 0x52;
  owners.flash = Esp32UpdateOwnership::OtherUpdater;
  EXPECT_EQ(FlashStatus::IoError, flash.read(0, &byte, 1));
  EXPECT_EQ(0x52, byte);
  EXPECT_EQ(FlashStatus::IoError, flash.program(0, &byte, 1));
  EXPECT_EQ(FlashStatus::IoError, flash.eraseSector(0));
  owners.flash = Esp32UpdateOwnership::ExclusiveStorage;
  sdk.snapshot.boot = sdk.snapshot.next;
  EXPECT_EQ(FlashStatus::IoError, flash.eraseSector(0));
  sdk.snapshot.boot = sdk.snapshot.running;
  --sdk.snapshot.table[5].size;
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.program(0, &byte, 1));
  EXPECT_EQ(0u, sdk.readCalls);
  EXPECT_EQ(0u, sdk.writeCalls);
  EXPECT_TRUE(sdk.erasedOffsets.empty());
}

TEST(Esp32Flash, EncryptedPartitionsAndWrongFlashSizeAreExplicitlyRefused) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  sdk.snapshot.next.encrypted = true;
  EXPECT_EQ(FlashStatus::Unsupported, flash.bind(1));
  EXPECT_EQ(Esp32FlashAdapter::Refusal::Encrypted, flash.lastRefusal());
  sdk.snapshot.next.encrypted = false;
  sdk.snapshot.flashSize = 0x400000;
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
  sdk.snapshot.flashSize = 0x800000;
  sdk.snapshot.physicalFlashSize = 0x400000;
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
  sdk.snapshot.physicalFlashSize = 0x1000000;
  EXPECT_EQ(FlashStatus::InvalidArgument, flash.bind(1));
  EXPECT_EQ(0u, sdk.writeCalls);
}

TEST(Esp32Flash, SdkErrorsRetainOriginalErrorAtInspectReadEraseAndWrite) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  sdk.inspectError = 0x108;
  EXPECT_EQ(FlashStatus::IoError, flash.bind(1));
  EXPECT_EQ(0x108, flash.lastSdkError());
  sdk.inspectError = kEsp32Ok;
  ASSERT_EQ(FlashStatus::Ok, flash.bind(1));
  uint8_t byte = 0;
  sdk.readError = 0x107;
  EXPECT_EQ(FlashStatus::IoError, flash.read(0, &byte, 1));
  EXPECT_EQ(0x107, flash.lastSdkError());
  EXPECT_EQ(FlashStatus::IoError, flash.program(0, &byte, 1));
  EXPECT_EQ(0x107, flash.lastSdkError());
  EXPECT_EQ(0u, sdk.writeCalls);
  sdk.readError = kEsp32Ok;
  sdk.eraseError = -1;
  EXPECT_EQ(FlashStatus::IoError, flash.eraseSector(0));
  EXPECT_EQ(-1, flash.lastSdkError());
  sdk.writeFault = FaultTiming::Before;
  sdk.writeError = 0x103;
  EXPECT_EQ(FlashStatus::IoError, flash.program(0, &byte, 1));
  EXPECT_EQ(0x103, flash.lastSdkError());
  EXPECT_EQ(Esp32FlashAdapter::Refusal::Sdk, flash.lastRefusal());
}

TEST(Esp32Flash, NorViolationBeyondFirstReadBlockIsRejectedWithoutPartialMutation) {
  Esp32PartitionModel sdk;
  Esp32Owners owners;
  Esp32FlashAdapter flash(sdk, owners);
  ASSERT_EQ(FlashStatus::Ok, flash.bind(512));
  uint8_t zero = 0;
  ASSERT_EQ(FlashStatus::Ok, flash.program(511, &zero, 1));
  const auto before = sdk.bytes;
  std::vector<uint8_t> bytes(512, 0x7f);
  EXPECT_EQ(FlashStatus::PartialProgramViolation, flash.program(0, bytes.data(), bytes.size()));
  EXPECT_EQ(Esp32FlashAdapter::Refusal::NorViolation, flash.lastRefusal());
  EXPECT_EQ(1u, sdk.writeCalls);
  EXPECT_EQ(before, sdk.bytes);
}

TEST(Esp32TrialHealthGate, NonTrialBootStaysPendingForeverAndNeverActs) {
  mesh::ota::Esp32TrialHealthGate gate(0, false);
  EXPECT_FALSE(gate.isPendingVerify());
  for (uint32_t t = 0; t <= 60000; t += 5000) {
    EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Pending, gate.tick(t, true, true, true));
  }
}

TEST(Esp32TrialHealthGate, ContinuousHealthyWindowConfirmsExactlyOnce) {
  mesh::ota::Esp32TrialHealthGate gate(0, true);
  EXPECT_TRUE(gate.isPendingVerify());
  for (uint32_t t = 0; t < 10000; t += 1000) {
    EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Pending, gate.tick(t, true, true, true));
  }
  EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Confirmed, gate.tick(10000, true, true, true));
  EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Confirmed, gate.tick(20000, false, false, false));
}

TEST(Esp32TrialHealthGate, UnhealthyTickResetsWindowBeforeMaturity) {
  mesh::ota::Esp32TrialHealthGate gate(0, true);
  for (uint32_t t = 0; t < 19500; t += 500) {
    const bool healthy = (t != 9000);
    EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Pending, gate.tick(t, healthy, healthy, healthy));
  }
  EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Confirmed, gate.tick(19500, true, true, true));
}

TEST(Esp32TrialHealthGate, WideServiceGapInvalidatesInProgressWindowEvenIfReadinessNeverDropped) {
  mesh::ota::Esp32TrialHealthGate gate(0, true);
  for (uint32_t t = 0; t <= 5000; t += 500) {
    EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Pending, gate.tick(t, true, true, true));
  }
  EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Pending, gate.tick(7500, true, true, true));
  for (uint32_t t = 8000; t < 17500; t += 500) {
    EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Pending, gate.tick(t, true, true, true));
  }
  EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Confirmed, gate.tick(17500, true, true, true));
}

TEST(Esp32TrialHealthGate, NeverHealthyExpiresAtDeadlineRatherThanHangingForever) {
  mesh::ota::Esp32TrialHealthGate gate(0, true);
  for (uint32_t t = 0; t < 48000; t += 4000) {
    EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Pending, gate.tick(t, false, false, false));
  }
  EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::DeadlineExpired, gate.tick(48000, false, false, false));
  EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::DeadlineExpired, gate.tick(60000, true, true, true));
}

TEST(Esp32TrialHealthGate, DeadlineTakesPriorityOverASimultaneouslyMaturingWindow) {
  mesh::ota::Esp32TrialHealthGate gate(0, true);
  for (uint32_t t = 0; t < 35500; t += 500) {
    EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Pending, gate.tick(t, false, false, false));
  }
  for (uint32_t t = 35500; t < 45000; t += 500) {
    EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::Pending, gate.tick(t, true, true, true));
  }
  EXPECT_EQ(mesh::ota::Esp32TrialHealthOutcome::DeadlineExpired, gate.tick(45000, true, true, true));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
