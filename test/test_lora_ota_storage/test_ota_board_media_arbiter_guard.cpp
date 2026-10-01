// Native tests for OtaBoardMediaArbiterGuard (OtaBoardBackendCommon.h),
// the shared wiring both nRF USB backends now use to back the baseline-
// measurement job's media-arbiter seam with the REAL, RAM-only
// ota::security::OtaSecurityPartitionArbiterRegistry -- the SAME shared
// mechanism OtaSecurityStore itself uses -- rather than a private/
// unshared token of the collector's own. Exercises genuine cross-
// instance contention/release over the registry, AND genuine
// cross-class contention against a real OtaSecurityStore constructed
// over the SAME canonical (physicalToken, kSecurityAOffset,
// kSecurityBOffset) tuple -- not a manual call-count substitute, and
// not two guards merely sharing a private made-up key with each other.
#include <gtest/gtest.h>
#include <helpers/ota/OtaBoardBackendCommon.h>
#include <ota/platform/Nrf52QspiPhysicalIdentity.h>
#include <ota/platform/SenseCapQspiLayout.h>
#include <ota/security/OtaSecurityStore.h>

#include "FakeNorFlash.h"

using mesh::ota::OtaBaselineMeasurementArbiterResult;
using mesh::ota::OtaBoardMediaArbiterGuard;
using ota::platform::SenseCapQspiLayout;
using ota::security::OtaSecurityStore;
using ota::test::FakeNorFlash;

TEST(OtaBoardMediaArbiterGuardTest, SingleGuardAcquiresThenReleasesCleanly) {
  OtaBoardMediaArbiterGuard guard(/*physical_token=*/0x11u, /*bank_a_offset=*/0x1000u, /*bank_b_offset=*/0x2000u);
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, guard.acquire());
  guard.release();
  // Re-acquiring after a clean release must succeed again (registry
  // refcount genuinely returned to zero, no stale ownership left over).
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, guard.acquire());
  guard.release();
}

TEST(OtaBoardMediaArbiterGuardTest, ZeroTokenIsRefusedImmediatelyAsUnavailable) {
  // Matches OtaSecurityStore's own "physicalToken == 0 means
  // unknown/unbound, refuse before any I/O" convention -- never silently
  // treated as a valid identity.
  OtaBoardMediaArbiterGuard guard(/*physical_token=*/0u, /*bank_a_offset=*/0x1000u, /*bank_b_offset=*/0x2000u);
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Unavailable, guard.acquire());
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Unavailable, guard.acquire());
}

TEST(OtaBoardMediaArbiterGuardTest, ReentrantAcquireBySameGuardNeverContends) {
  OtaBoardMediaArbiterGuard guard(/*physical_token=*/0x12u, /*bank_a_offset=*/0x3000u, /*bank_b_offset=*/0x4000u);
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, guard.acquire());
  // The collector itself may call acquireMediaArbiter() repeatedly while
  // phase_ == AcquireArbiter before observing Acquired the first time;
  // once genuinely held, further calls from the SAME guard must keep
  // succeeding, never regress to Contended against its own ownership.
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, guard.acquire());
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, guard.acquire());
  guard.release();
}

TEST(OtaBoardMediaArbiterGuardTest, SecondGuardOnSamePhysicalIdentityIsContendedWhileFirstHolds) {
  OtaBoardMediaArbiterGuard first(/*physical_token=*/0x13u, /*bank_a_offset=*/0x5000u, /*bank_b_offset=*/0x6000u);
  OtaBoardMediaArbiterGuard second(/*physical_token=*/0x13u, /*bank_a_offset=*/0x5000u, /*bank_b_offset=*/0x6000u);
  ASSERT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, first.acquire());
  // Same (token, bankA, bankB) tuple as `first` -- a genuinely DIFFERENT
  // owner (the `second` guard's own `this`) must be refused, never
  // silently granted a private/unshared copy.
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Contended, second.acquire());
  first.release();
  // Once `first` releases, `second` (a distinct owner) must now be able
  // to genuinely acquire the same physical identity.
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, second.acquire());
  second.release();
}

TEST(OtaBoardMediaArbiterGuardTest, DifferentPhysicalIdentitiesNeverContendWithEachOther) {
  OtaBoardMediaArbiterGuard xiao(/*physical_token=*/0x584E3430u, /*bank_a_offset=*/0x7000u,
                                 /*bank_b_offset=*/0x8000u);
  OtaBoardMediaArbiterGuard sensecap(/*physical_token=*/0x53435031u, /*bank_a_offset=*/0x7000u,
                                     /*bank_b_offset=*/0x8000u);
  // Same bank offsets, but a genuinely DIFFERENT board-species token:
  // PhysicalPartitionKey's exact-tuple comparison must treat these as
  // distinct physical chips, never unify them.
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, xiao.acquire());
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, sensecap.acquire());
  xiao.release();
  sensecap.release();
}

TEST(OtaBoardMediaArbiterGuardTest, DestructorReleasesOwnershipWithoutExplicitReleaseCall) {
  OtaBoardMediaArbiterGuard second(/*physical_token=*/0x14u, /*bank_a_offset=*/0x9000u, /*bank_b_offset=*/0xA000u);
  {
    OtaBoardMediaArbiterGuard first(/*physical_token=*/0x14u, /*bank_a_offset=*/0x9000u, /*bank_b_offset=*/0xA000u);
    ASSERT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, first.acquire());
    EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Contended, second.acquire());
  }  // `first` destroyed here -- its held ticket AND registry reference must both be released.
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, second.acquire());
  second.release();
}

// --- Cross-class tests: a REAL OtaSecurityStore on the SAME declared
// physical identity as the guard (SenseCapQspiLayout's own canonical
// security-tail offsets), not two guards sharing a made-up key. ---

namespace {
constexpr uint64_t kCrossTestToken = 0xC0FFEEu;  // nonzero; a shared per-test-case chip identity.

FakeNorFlash makeFlash() {
  return FakeNorFlash(SenseCapQspiLayout::kTotalBytes, SenseCapQspiLayout::kEraseUnitBytes, 1);
}
}  // namespace

TEST(OtaBoardMediaArbiterGuardTest, PendingStoreMutationBlocksCollectorGuardOnSamePhysicalIdentity) {
  FakeNorFlash flash = makeFlash();
  OtaSecurityStore store(flash, SenseCapQspiLayout::kSecurityAOffset, SenseCapQspiLayout::kSecurityBOffset,
                         /*storeIdentity=*/1u, kCrossTestToken);
  ASSERT_FALSE(store.partitionMisconfigured());
  store.reconstruct();
  ASSERT_FALSE(store.hasPendingOrdinaryOperation());

  int owner_tag = 0;
  const void* owner = &owner_tag;
  ota::security::OtaSecurityOperationTicket ticket;
  // Fresh (non-resuming) commissionVirginTx() start: per its own
  // documented contract, the FIRST call deliberately defers the actual
  // physical program step to the next (resuming) call, returning false
  // while leaving hasPendingOrdinaryOperation()==true -- which means
  // physical partition ownership is genuinely HELD across this window,
  // not released, per the STOREPLAN cross-instance arbitration contract.
  const auto first_call = store.commissionVirginTx(/*initialUpperBound=*/100u, /*factoryGrantAuthorized=*/true,
                                                    owner, ticket);
  EXPECT_EQ(meshcore::ota::runtime::OtaSequenceBackingResult::WouldBlock, first_call);
  ASSERT_TRUE(store.hasPendingOrdinaryOperation());

  // A guard over the SAME EXACT (token, bankA, bankB) tuple must observe
  // genuine contention from Store's real in-flight ownership -- not a
  // private/unshared token of its own.
  OtaBoardMediaArbiterGuard guard(kCrossTestToken, SenseCapQspiLayout::kSecurityAOffset,
                                  SenseCapQspiLayout::kSecurityBOffset);
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Contended, guard.acquire());

  // Drive Store's resumable op to completion (bounded loop; a real
  // FakeNorFlash single-cell program should commit within a handful of
  // steps).
  bool committed = false;
  for (int i = 0; i < 16 && !committed; ++i) {
    committed = store.commissionVirginTx(/*initialUpperBound=*/100u, /*factoryGrantAuthorized=*/true, owner, ticket) ==
                meshcore::ota::runtime::OtaSequenceBackingResult::Committed;
  }
  ASSERT_TRUE(committed);
  ASSERT_FALSE(store.hasPendingOrdinaryOperation());

  // Ownership must now be genuinely released: the guard can acquire it.
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, guard.acquire());
  guard.release();
}

TEST(OtaBoardMediaArbiterGuardTest, CollectorHoldingLeaseBlocksStoreOnSamePhysicalIdentity) {
  FakeNorFlash flash = makeFlash();
  OtaSecurityStore store(flash, SenseCapQspiLayout::kSecurityAOffset, SenseCapQspiLayout::kSecurityBOffset,
                         /*storeIdentity=*/2u, kCrossTestToken);
  ASSERT_FALSE(store.partitionMisconfigured());
  store.reconstruct();  // cold-start, uncontended.

  OtaBoardMediaArbiterGuard guard(kCrossTestToken, SenseCapQspiLayout::kSecurityAOffset,
                                  SenseCapQspiLayout::kSecurityBOffset);
  ASSERT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, guard.acquire());

  // Store's own bounded read path (readTxCounter -> refreshForBoundedReadNeedsRetry
  // -> acquirePartitionOwnership()) must now observe the foreign
  // (guard's) ownership and return WouldBlock -- never silently proceed
  // with a possibly-stale view while the guard genuinely holds the same
  // physical partition.
  uint32_t upper_bound = 0;
  const auto result = store.readTxCounter(upper_bound);
  EXPECT_EQ(meshcore::ota::runtime::OtaSequenceBackingResult::WouldBlock, result);

  // Once the guard releases, Store must be able to proceed again (a
  // virgin store reports Missing, not WouldBlock, proving ownership was
  // genuinely released rather than merely re-reporting the same block).
  guard.release();
  const auto result_after = store.readTxCounter(upper_bound);
  EXPECT_EQ(meshcore::ota::runtime::OtaSequenceBackingResult::Missing, result_after);
}

TEST(OtaBoardMediaArbiterGuardTest, DifferentChipsNeverOverBlockEvenWithSameBankOffsets) {
  FakeNorFlash flash_a = makeFlash();
  OtaSecurityStore store_a(flash_a, SenseCapQspiLayout::kSecurityAOffset, SenseCapQspiLayout::kSecurityBOffset,
                           /*storeIdentity=*/3u, /*physicalToken=*/0x1001u);
  ASSERT_FALSE(store_a.partitionMisconfigured());
  store_a.reconstruct();

  int owner_tag = 0;
  const void* owner = &owner_tag;
  ota::security::OtaSecurityOperationTicket ticket;
  ASSERT_EQ(meshcore::ota::runtime::OtaSequenceBackingResult::WouldBlock,
            store_a.commissionVirginTx(100u, true, owner, ticket));
  ASSERT_TRUE(store_a.hasPendingOrdinaryOperation());

  // A guard for a DIFFERENT chip token (same bank offsets) must never be
  // blocked by store_a's in-flight operation.
  OtaBoardMediaArbiterGuard other_chip_guard(/*physical_token=*/0x1002u, SenseCapQspiLayout::kSecurityAOffset,
                                             SenseCapQspiLayout::kSecurityBOffset);
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, other_chip_guard.acquire());
  other_chip_guard.release();
}

// --- Alias-wrapper test: a SECOND OtaSecurityStore wrapper object (a
// different C++ instance) over the SAME physical identity must still be
// unified with the FIRST via the registry (never "different object ==
// different chip"), matching OtaSecurityStore's own doc comment. ---
TEST(OtaBoardMediaArbiterGuardTest, AliasStoreWrapperSharingSamePhysicalIdentityStillUnified) {
  FakeNorFlash flash = makeFlash();
  OtaSecurityStore store_one(flash, SenseCapQspiLayout::kSecurityAOffset, SenseCapQspiLayout::kSecurityBOffset,
                             /*storeIdentity=*/4u, kCrossTestToken + 1u);
  store_one.reconstruct();
  int owner_tag = 0;
  const void* owner = &owner_tag;
  ota::security::OtaSecurityOperationTicket ticket;
  ASSERT_EQ(meshcore::ota::runtime::OtaSequenceBackingResult::WouldBlock,
            store_one.commissionVirginTx(100u, true, owner, ticket));
  ASSERT_TRUE(store_one.hasPendingOrdinaryOperation());

  // A SECOND, independently-constructed Store wrapper object for the
  // SAME (token, bankA, bankB) physical identity must be genuinely
  // blocked by store_one's in-flight op -- proving the registry unifies
  // by physical identity, not by wrapper object address.
  OtaSecurityStore store_alias(flash, SenseCapQspiLayout::kSecurityAOffset, SenseCapQspiLayout::kSecurityBOffset,
                               /*storeIdentity=*/4u, kCrossTestToken + 1u);
  uint32_t upper_bound = 0;
  EXPECT_EQ(meshcore::ota::runtime::OtaSequenceBackingResult::WouldBlock, store_alias.readTxCounter(upper_bound));

  bool committed = false;
  for (int i = 0; i < 16 && !committed; ++i) {
    committed = store_one.commissionVirginTx(100u, true, owner, ticket) ==
                meshcore::ota::runtime::OtaSequenceBackingResult::Committed;
  }
  ASSERT_TRUE(committed);
  auto result = store_alias.readTxCounter(upper_bound);
  for (size_t i = 0; i < 1536 && result == meshcore::ota::runtime::OtaSequenceBackingResult::WouldBlock; ++i) {
    result = store_alias.readTxCounter(upper_bound);
  }
  ASSERT_EQ(meshcore::ota::runtime::OtaSequenceBackingResult::Committed, result);
  EXPECT_EQ(100u, upper_bound);
}

// --- ota::platform::tokenForChipSelectPin canonical-helper tests: the
// REAL physical identity a board backend's `flash.physicalResourceToken()`
// (Nrf52FlashAdapter.h / Nrf52QspiPhysicalIdentity.h) actually derives
// from the real nRF52840 QSPI peripheral + chip-select GPIO pairing --
// not a board-model literal. Xiao's real PIN_QSPI_CS is 25 (see
// variant.h); pin 26 stands in for "a genuinely different CS line" (a
// distinct, independent physical part), and 48 is the first value
// outside the real nRF52840 absolute-GPIO-pin range [0,47]. ---

TEST(OtaBoardMediaArbiterGuardTest, TokenForChipSelectPinRejectsOutOfRangePinAsUnavailable) {
  EXPECT_EQ(0u, ota::platform::tokenForChipSelectPin(48u));
  EXPECT_EQ(0u, ota::platform::tokenForChipSelectPin(0xFFFFFFFFu));
  // In-range boundary must NOT be rejected.
  EXPECT_NE(0u, ota::platform::tokenForChipSelectPin(47u));
  EXPECT_NE(0u, ota::platform::tokenForChipSelectPin(0u));

  OtaBoardMediaArbiterGuard guard(ota::platform::tokenForChipSelectPin(48u), SenseCapQspiLayout::kSecurityAOffset,
                                  SenseCapQspiLayout::kSecurityBOffset);
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Unavailable, guard.acquire());
}

TEST(OtaBoardMediaArbiterGuardTest, RealStoreOnCanonicalChipSelectTokenGenuinelyContendsAgainstGuardOnSamePin) {
  // Same real CS pin (25) on both sides of the arbitration, via the
  // EXACT canonical helper a real board backend would use -- proving
  // the guard and a real OtaSecurityStore genuinely share a lease over
  // "this one real QSPI controller + this one real CS line," not merely
  // two guards agreeing on a private literal.
  const uint64_t pin25_token = ota::platform::tokenForChipSelectPin(25u);
  ASSERT_NE(0u, pin25_token);

  FakeNorFlash flash = makeFlash();
  OtaSecurityStore store(flash, SenseCapQspiLayout::kSecurityAOffset, SenseCapQspiLayout::kSecurityBOffset,
                         /*storeIdentity=*/6u, pin25_token);
  ASSERT_FALSE(store.partitionMisconfigured());
  store.reconstruct();
  ASSERT_FALSE(store.hasPendingOrdinaryOperation());

  int owner_tag = 0;
  const void* owner = &owner_tag;
  ota::security::OtaSecurityOperationTicket ticket;
  ASSERT_EQ(meshcore::ota::runtime::OtaSequenceBackingResult::WouldBlock,
            store.commissionVirginTx(/*initialUpperBound=*/100u, /*factoryGrantAuthorized=*/true, owner, ticket));
  ASSERT_TRUE(store.hasPendingOrdinaryOperation());

  OtaBoardMediaArbiterGuard guard_same_pin(pin25_token, SenseCapQspiLayout::kSecurityAOffset,
                                           SenseCapQspiLayout::kSecurityBOffset);
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Contended, guard_same_pin.acquire());
}

TEST(OtaBoardMediaArbiterGuardTest, RealStoreOnOnePinNeverContendsWithGuardOnADistinctChipSelectPin) {
  // A genuinely DIFFERENT chip-select line (26) must never be blocked by
  // an in-flight Store operation on pin 25's physical identity -- distinct
  // real hardware, distinct token, no over-blocking.
  const uint64_t pin25_token = ota::platform::tokenForChipSelectPin(25u);
  const uint64_t pin26_token = ota::platform::tokenForChipSelectPin(26u);
  ASSERT_NE(0u, pin25_token);
  ASSERT_NE(0u, pin26_token);
  ASSERT_NE(pin25_token, pin26_token);

  FakeNorFlash flash = makeFlash();
  OtaSecurityStore store(flash, SenseCapQspiLayout::kSecurityAOffset, SenseCapQspiLayout::kSecurityBOffset,
                         /*storeIdentity=*/7u, pin25_token);
  ASSERT_FALSE(store.partitionMisconfigured());
  store.reconstruct();

  int owner_tag = 0;
  const void* owner = &owner_tag;
  ota::security::OtaSecurityOperationTicket ticket;
  ASSERT_EQ(meshcore::ota::runtime::OtaSequenceBackingResult::WouldBlock,
            store.commissionVirginTx(100u, true, owner, ticket));
  ASSERT_TRUE(store.hasPendingOrdinaryOperation());

  OtaBoardMediaArbiterGuard guard_other_pin(pin26_token, SenseCapQspiLayout::kSecurityAOffset,
                                            SenseCapQspiLayout::kSecurityBOffset);
  EXPECT_EQ(OtaBaselineMeasurementArbiterResult::Acquired, guard_other_pin.acquire());
  guard_other_pin.release();
}
