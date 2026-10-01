// Native, production-code coverage for OtaBaselineMeasurementCollector
// V2 (see helpers/ota/OtaBaselineMeasurementCollector.h). Exercises the
// REAL Idle/Pending/Present/Failure state machine, ownership/contention
// semantics, the genuinely SHARED per-call I/O budget across the
// image-resolve+hash phases, the collector's own independent bounds
// re-check, the end-of-job Recheck consistency requirement, and the
// local SDK-settings codec -- not a source-only stub with opaque
// precomputed digests.
#include <gtest/gtest.h>
#include <vector>
#include <cstring>

#include "helpers/ota/OtaBaselineMeasurementCollector.h"
#include "helpers/ota/OtaSdkSettingsCodec.h"

using mesh::ota::IOtaBaselineMeasurementSource;
using mesh::ota::OtaBaselineMeasurementArbiterResult;
using mesh::ota::OtaBaselineMeasurementBeginRejection;
using mesh::ota::OtaBaselineMeasurementCollector;
using mesh::ota::OtaBaselineMeasurementEvidence;
using mesh::ota::OtaBaselineMeasurementFailureReason;
using mesh::ota::OtaBaselineMeasurementOwnerToken;
using mesh::ota::OtaBaselineMeasurementStatus;
using mesh::ota::OtaBaselineMeasurementStepOutcome;
using mesh::ota::OtaBaselineMeasurementSubStep;
using mesh::ota::kOtaCurrentSdkSettingsRecordBytes;
using ExtentMax = std::integral_constant<uint32_t, ::ota::storage::kXiaoOtaAppInstallMaxSize>;

namespace {

uint16_t realCrc16(const uint8_t* data, uint32_t len) {
  return ::ota::storage::XiaoOtaActiveExtentBridge::crc16Compute(data, len);
}

// A fully-controllable fixture source: every phase can be individually
// forced to fail, made resumable across multiple calls with a
// configurable "cost", or mutated mid-job (to exercise Recheck) -- all
// without touching any real hardware.
class FakeMeasurementSource : public IOtaBaselineMeasurementSource {
public:
  OtaBaselineMeasurementArbiterResult arbiter_result = OtaBaselineMeasurementArbiterResult::Acquired;
  int arbiter_contend_calls_remaining = 0;  // returns Contended this many times before Acquired.
  bool arbiter_acquired = false;
  bool arbiter_released = false;

  bool identity_ok = true;
  bool profile_ok = true;
  bool sdk_ok = true;
  bool extent_ok = true;
  bool stock_loader_ok = true;
  bool boot_config_ok = true;
  bool boot_config_catalogue_unavailable = false;
  bool boot_config_mismatch = false;
  bool qspi_ok = true;
  bool entropy_ok = true;

  uint32_t profile_id = 1, target_id = 10, role_id = 2, layout_id = 3;
  uint8_t sdk_raw[kOtaCurrentSdkSettingsRecordBytes] = {0x11};
  bool mutate_sdk_on_reread = false;  // simulates a genuine mid-job SDK change.
  int sdk_read_count = 0;

  uint32_t extent_value = 0;
  uint32_t internal_addr_value = OtaBaselineMeasurementCollector::kAppWindowStartAddr;
  uint16_t stored_crc16 = 0xFFFFu;  // overwritten to the real CRC by tests that care.

  std::vector<uint8_t> image;
  uint32_t image_resolve_cost = 8;  // bytes the (fake) resolver itself "consumes" before Resolved.
  uint32_t image_resolve_progress = 0;
  bool image_access_failed = false;
  bool image_resolved_once = false;
  bool report_null_image = false;
  bool report_wrong_extent = false;

  uint32_t stock_loader_cost = 8;
  uint32_t stock_loader_progress = 0;
  bool stock_loader_resolved_once = false;
  uint32_t qspi_cost = 8;
  uint32_t qspi_progress = 0;
  bool qspi_resolved_once = false;

  OtaBaselineMeasurementArbiterResult acquireMediaArbiter() override {
    if (arbiter_contend_calls_remaining > 0) {
      --arbiter_contend_calls_remaining;
      return OtaBaselineMeasurementArbiterResult::Contended;
    }
    if (arbiter_result == OtaBaselineMeasurementArbiterResult::Acquired) arbiter_acquired = true;
    return arbiter_result;
  }
  void releaseMediaArbiter() override { arbiter_released = true; }

  bool readDeviceIdentity(uint8_t out_uid8[8], uint8_t out_pubkey32[32]) override {
    if (!identity_ok) return false;
    for (int i = 0; i < 8; ++i) out_uid8[i] = static_cast<uint8_t>(0xA0 + i);
    for (int i = 0; i < 32; ++i) out_pubkey32[i] = static_cast<uint8_t>(0xB0 + i);
    return true;
  }

  bool readCompiledProfile(uint32_t& out_profile_id, uint32_t& out_target_id, uint32_t& out_role_id,
                           uint32_t& out_layout_id) override {
    if (!profile_ok) return false;
    out_profile_id = profile_id;
    out_target_id = target_id;
    out_role_id = role_id;
    out_layout_id = layout_id;
    return true;
  }

  bool readRawCurrentSdkSettings(uint8_t out_raw28[kOtaCurrentSdkSettingsRecordBytes]) override {
    if (!sdk_ok) return false;
    ++sdk_read_count;
    if (mutate_sdk_on_reread && sdk_read_count > 1) {
      uint8_t mutated[kOtaCurrentSdkSettingsRecordBytes];
      memcpy(mutated, sdk_raw, sizeof(mutated));
      mutated[0] ^= 0xFF;  // genuine change, still perfectly readable.
      memcpy(out_raw28, mutated, sizeof(mutated));
    } else {
      memcpy(out_raw28, sdk_raw, kOtaCurrentSdkSettingsRecordBytes);
    }
    return true;
  }

  bool readValidatedBank0Extent(uint32_t& out_extent, uint32_t& out_internal_addr,
                                uint16_t& out_stored_crc16) override {
    if (!extent_ok) return false;
    out_extent = extent_value;
    out_internal_addr = internal_addr_value;
    out_stored_crc16 = stored_crc16;
    return true;
  }

  OtaBaselineMeasurementSubStep stepAppImageAccess(uint32_t max_bytes, uint32_t* out_bytes_consumed,
                                                   const uint8_t** out_image, uint32_t* out_extent) override {
    if (image_access_failed) return OtaBaselineMeasurementSubStep::Failed;
    if (!image_resolved_once) {
      const uint32_t remaining_needed = image_resolve_cost - image_resolve_progress;
      const uint32_t take = remaining_needed < max_bytes ? remaining_needed : max_bytes;
      *out_bytes_consumed = take;
      image_resolve_progress += take;
      if (image_resolve_progress < image_resolve_cost) return OtaBaselineMeasurementSubStep::InProgress;
      image_resolved_once = true;
      if (report_null_image) {
        *out_image = nullptr;
        *out_extent = static_cast<uint32_t>(image.size());
        return OtaBaselineMeasurementSubStep::Resolved;
      }
      *out_image = image.data();
      *out_extent = report_wrong_extent ? static_cast<uint32_t>(image.size()) + 1
                                        : static_cast<uint32_t>(image.size());
      return OtaBaselineMeasurementSubStep::Resolved;
    }
    *out_bytes_consumed = 0;
    *out_image = image.data();
    *out_extent = static_cast<uint32_t>(image.size());
    return OtaBaselineMeasurementSubStep::Resolved;
  }

  OtaBaselineMeasurementSubStep stepStockLoaderRangeHash(uint32_t max_bytes, uint32_t* out_bytes_consumed,
                                                         uint32_t& out_start, uint32_t& out_length,
                                                         uint8_t out_hash32[32]) override {
    if (!stock_loader_ok) return OtaBaselineMeasurementSubStep::Failed;
    if (!stock_loader_resolved_once) {
      const uint32_t remaining_needed = stock_loader_cost - stock_loader_progress;
      const uint32_t take = remaining_needed < max_bytes ? remaining_needed : max_bytes;
      *out_bytes_consumed = take;
      stock_loader_progress += take;
      if (stock_loader_progress < stock_loader_cost) return OtaBaselineMeasurementSubStep::InProgress;
      stock_loader_resolved_once = true;
    } else {
      *out_bytes_consumed = 0;
    }
    out_start = 0x1000;
    out_length = 0x2000;
    memset(out_hash32, 0x7A, 32);
    return OtaBaselineMeasurementSubStep::Resolved;
  }

  OtaBaselineMeasurementSubStep stepBootConfigSelection(uint32_t /*max_bytes*/, uint32_t* out_bytes_consumed,
                                                        uint32_t& out_boot_config_id,
                                                        bool& out_catalogue_unavailable,
                                                        bool& out_mismatch) override {
    *out_bytes_consumed = 0;
    out_catalogue_unavailable = boot_config_catalogue_unavailable;
    out_mismatch = boot_config_mismatch;
    if (!boot_config_ok) return OtaBaselineMeasurementSubStep::Failed;
    out_boot_config_id = 42;
    return OtaBaselineMeasurementSubStep::Resolved;
  }

  OtaBaselineMeasurementSubStep stepQspiStateInspection(uint32_t max_bytes, uint32_t* out_bytes_consumed) override {
    if (!qspi_ok) return OtaBaselineMeasurementSubStep::Failed;
    if (!qspi_resolved_once) {
      const uint32_t remaining_needed = qspi_cost - qspi_progress;
      const uint32_t take = remaining_needed < max_bytes ? remaining_needed : max_bytes;
      *out_bytes_consumed = take;
      qspi_progress += take;
      if (qspi_progress < qspi_cost) return OtaBaselineMeasurementSubStep::InProgress;
      qspi_resolved_once = true;
    } else {
      *out_bytes_consumed = 0;
    }
    return OtaBaselineMeasurementSubStep::Resolved;
  }

  bool getPlatformEntropy16(uint8_t out[16]) override {
    if (!entropy_ok) return false;
    for (int i = 0; i < 16; ++i) out[i] = static_cast<uint8_t>(0xC0 + i);
    return true;
  }

  void setImage(std::vector<uint8_t> img, uint16_t crc) {
    image = std::move(img);
    extent_value = static_cast<uint32_t>(image.size());
    stored_crc16 = crc;
  }
};

const uint8_t kChallenge[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
const OtaBaselineMeasurementOwnerToken kOwnerA{0xAAAAAAAAAAAAAAAAull};
const OtaBaselineMeasurementOwnerToken kOwnerB{0xBBBBBBBBBBBBBBBBull};

// Bounded: a genuine production stall is a test FAILURE, never a hang.
// Returns the total number of serviceStep() calls actually made.
int runToCompletion(OtaBaselineMeasurementCollector& collector, uint32_t ticket_id,
                    OtaBaselineMeasurementOwnerToken owner) {
  int calls = 0;
  while (collector.status() == OtaBaselineMeasurementStatus::Pending && calls < 10000) {
    collector.serviceStep(ticket_id, owner);
    ++calls;
  }
  EXPECT_LT(calls, 10000) << "collector never reached a terminal state";
  return calls;
}

}  // namespace

TEST(OtaBaselineMeasurementCollectorTest, DefaultIdleNeverCoastsToPresentWithoutBegin) {
  FakeMeasurementSource src;
  OtaBaselineMeasurementCollector collector(src);
  EXPECT_EQ(OtaBaselineMeasurementStatus::Idle, collector.status());

  // Ticket 0 / a zero-value owner token must never be servicable.
  EXPECT_EQ(OtaBaselineMeasurementStepOutcome::NotRunning,
            collector.serviceStep(0, OtaBaselineMeasurementOwnerToken{0}));
  EXPECT_EQ(OtaBaselineMeasurementStepOutcome::NotRunning, collector.serviceStep(0, kOwnerA));
  EXPECT_EQ(OtaBaselineMeasurementStatus::Idle, collector.status());

  OtaBaselineMeasurementEvidence evidence;
  EXPECT_FALSE(collector.readCompletedEvidence(0, kOwnerA, evidence));
}

TEST(OtaBaselineMeasurementCollectorTest, GenuinelyAvailableBoardReachesPresentWithRealFieldsIncludingProfileId) {
  FakeMeasurementSource src;
  src.setImage({0x01, 0x02, 0x03, 0x04, 0x05}, realCrc16((const uint8_t[]){0x01, 0x02, 0x03, 0x04, 0x05}, 5));

  OtaBaselineMeasurementCollector collector(src);
  const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
  ASSERT_TRUE(begin_outcome.started);
  ASSERT_EQ(OtaBaselineMeasurementStatus::Pending, collector.status());

  runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
  ASSERT_EQ(OtaBaselineMeasurementStatus::Present, collector.status());
  EXPECT_TRUE(src.arbiter_acquired);
  EXPECT_TRUE(src.arbiter_released);

  OtaBaselineMeasurementEvidence evidence;
  ASSERT_TRUE(collector.readCompletedEvidence(begin_outcome.ticket.ticket_id, kOwnerA, evidence));
  EXPECT_EQ(1u, evidence.profile_id);
  EXPECT_EQ(10u, evidence.target_id);
  EXPECT_EQ(0, memcmp(kChallenge, evidence.host_challenge, 16));
  EXPECT_EQ(0, memcmp(begin_outcome.ticket.device_nonce, evidence.device_nonce, 16));
}

TEST(OtaBaselineMeasurementCollectorTest, DifferentOwnerCannotBeginOrReadWhileAJobIsGenuinelyPending) {
  FakeMeasurementSource src;
  src.setImage({0xAA, 0xBB}, realCrc16((const uint8_t[]){0xAA, 0xBB}, 2));

  OtaBaselineMeasurementCollector collector(src);
  const auto a = collector.begin(kChallenge, kOwnerA);
  ASSERT_TRUE(a.started);
  collector.serviceStep(a.ticket.ticket_id, kOwnerA);  // AcquireArbiter -- job now genuinely in flight.

  const auto b = collector.begin(kChallenge, kOwnerB);
  EXPECT_FALSE(b.started);
  EXPECT_EQ(OtaBaselineMeasurementBeginRejection::AnotherOwnerActive, b.rejection);

  EXPECT_EQ(OtaBaselineMeasurementStepOutcome::RejectedWrongOwner,
            collector.serviceStep(a.ticket.ticket_id, kOwnerB));

  runToCompletion(collector, a.ticket.ticket_id, kOwnerA);
  ASSERT_EQ(OtaBaselineMeasurementStatus::Present, collector.status());

  OtaBaselineMeasurementEvidence evidence;
  EXPECT_FALSE(collector.readCompletedEvidence(a.ticket.ticket_id, kOwnerB, evidence));
  EXPECT_TRUE(collector.readCompletedEvidence(a.ticket.ticket_id, kOwnerA, evidence));

  // Now that it's terminal (Present, not Pending), a different owner MAY start a new job.
  const auto c = collector.begin(kChallenge, kOwnerB);
  EXPECT_TRUE(c.started);
}

TEST(OtaBaselineMeasurementCollectorTest, SameOwnerRestartSupersedesItsOwnInFlightJobCleanly) {
  FakeMeasurementSource src;
  OtaBaselineMeasurementCollector collector(src);
  const auto first = collector.begin(kChallenge, kOwnerA);
  ASSERT_TRUE(first.started);
  collector.serviceStep(first.ticket.ticket_id, kOwnerA);  // holds the arbiter now.
  EXPECT_TRUE(src.arbiter_acquired);

  const auto second = collector.begin(kChallenge, kOwnerA);
  EXPECT_TRUE(second.started);
  EXPECT_NE(first.ticket.ticket_id, second.ticket.ticket_id);
  EXPECT_TRUE(src.arbiter_released);  // old lease released before the new job began.

  // The old ticket is now fully stale.
  EXPECT_EQ(OtaBaselineMeasurementStepOutcome::RejectedStaleTicket,
            collector.serviceStep(first.ticket.ticket_id, kOwnerA));
}

TEST(OtaBaselineMeasurementCollectorTest, InvalidOwnerTokenAndTicketExhaustionAreRejectedWithoutMutatingState) {
  FakeMeasurementSource src;
  {
    OtaBaselineMeasurementCollector collector(src);
    const auto outcome = collector.begin(kChallenge, OtaBaselineMeasurementOwnerToken{0});
    EXPECT_FALSE(outcome.started);
    EXPECT_EQ(OtaBaselineMeasurementBeginRejection::InvalidOwnerToken, outcome.rejection);
    EXPECT_EQ(OtaBaselineMeasurementStatus::Idle, collector.status());
  }
  {
    // Test-only constructor seeds the ticket counter at its ceiling.
    OtaBaselineMeasurementCollector collector(src, 0xFFFFFFFFu);
    const auto outcome = collector.begin(kChallenge, kOwnerA);
    EXPECT_FALSE(outcome.started);
    EXPECT_EQ(OtaBaselineMeasurementBeginRejection::TicketsExhausted, outcome.rejection);
    EXPECT_EQ(0u, outcome.ticket.ticket_id);
    EXPECT_EQ(OtaBaselineMeasurementStatus::Idle, collector.status());
  }
}

TEST(OtaBaselineMeasurementCollectorTest, EntropyUnavailableRejectsBeginWithoutMutatingAnyState) {
  FakeMeasurementSource src;
  src.entropy_ok = false;
  OtaBaselineMeasurementCollector collector(src);
  const auto outcome = collector.begin(kChallenge, kOwnerA);
  EXPECT_FALSE(outcome.started);
  EXPECT_EQ(OtaBaselineMeasurementBeginRejection::EntropyUnavailable, outcome.rejection);
  EXPECT_EQ(OtaBaselineMeasurementStatus::Idle, collector.status());
  EXPECT_EQ(0u, collector.currentTicketId());
}

TEST(OtaBaselineMeasurementCollectorTest, ExplicitCancelByOwnerReleasesLeaseAndReturnsToIdle) {
  FakeMeasurementSource src;
  OtaBaselineMeasurementCollector collector(src);
  const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
  collector.serviceStep(begin_outcome.ticket.ticket_id, kOwnerA);  // acquires the arbiter.
  ASSERT_TRUE(src.arbiter_acquired);

  // Wrong owner cannot cancel.
  EXPECT_FALSE(collector.cancel(begin_outcome.ticket.ticket_id, kOwnerB));
  EXPECT_EQ(OtaBaselineMeasurementStatus::Pending, collector.status());

  EXPECT_TRUE(collector.cancel(begin_outcome.ticket.ticket_id, kOwnerA));
  EXPECT_EQ(OtaBaselineMeasurementStatus::Idle, collector.status());
  EXPECT_TRUE(src.arbiter_released);
}

TEST(OtaBaselineMeasurementCollectorTest, ArbiterContentionStaysPendingNeverFailureUntilGenuineErrorOrSuccess) {
  FakeMeasurementSource src;
  src.arbiter_contend_calls_remaining = 3;
  OtaBaselineMeasurementCollector collector(src);
  const auto begin_outcome = collector.begin(kChallenge, kOwnerA);

  for (int i = 0; i < 3; ++i) {
    collector.serviceStep(begin_outcome.ticket.ticket_id, kOwnerA);
    EXPECT_EQ(OtaBaselineMeasurementStatus::Pending, collector.status());
  }
  EXPECT_FALSE(src.arbiter_acquired);
  collector.serviceStep(begin_outcome.ticket.ticket_id, kOwnerA);  // now genuinely acquires.
  EXPECT_TRUE(src.arbiter_acquired);
  EXPECT_EQ(OtaBaselineMeasurementStatus::Pending, collector.status());
}

TEST(OtaBaselineMeasurementCollectorTest, ArbiterGenuineErrorIsFailureNotContention) {
  FakeMeasurementSource src;
  src.arbiter_result = OtaBaselineMeasurementArbiterResult::Unavailable;
  OtaBaselineMeasurementCollector collector(src);
  const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
  runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
  EXPECT_EQ(OtaBaselineMeasurementStatus::Failure, collector.status());
  EXPECT_EQ(OtaBaselineMeasurementFailureReason::MediaArbiterUnavailable, collector.failureReason());
  EXPECT_FALSE(src.arbiter_acquired);
}

TEST(OtaBaselineMeasurementCollectorTest, StorageCutsOnEachPhaseEachFailClosedAndReleaseTheArbiter) {
  struct Case {
    const char* name;
    void (*apply)(FakeMeasurementSource&);
    OtaBaselineMeasurementFailureReason expected;
  };
  static const Case cases[] = {
      {"identity", [](FakeMeasurementSource& s) { s.identity_ok = false; },
       OtaBaselineMeasurementFailureReason::IdentityUnreadable},
      {"profile", [](FakeMeasurementSource& s) { s.profile_ok = false; },
       OtaBaselineMeasurementFailureReason::ProfileUnreadable},
      {"sdk", [](FakeMeasurementSource& s) { s.sdk_ok = false; },
       OtaBaselineMeasurementFailureReason::SdkSettingsUnreadable},
      {"extent", [](FakeMeasurementSource& s) { s.extent_ok = false; },
       OtaBaselineMeasurementFailureReason::ExtentOutOfBounds},
      {"image", [](FakeMeasurementSource& s) { s.image_access_failed = true; },
       OtaBaselineMeasurementFailureReason::ImageHashFailed},
      {"stock_loader", [](FakeMeasurementSource& s) { s.stock_loader_ok = false; },
       OtaBaselineMeasurementFailureReason::StockLoaderRangeUnreadable},
      {"boot_config", [](FakeMeasurementSource& s) { s.boot_config_ok = false; },
       OtaBaselineMeasurementFailureReason::BootConfigUnreadable},
      {"boot_config_catalogue_unavailable",
       [](FakeMeasurementSource& s) {
         s.boot_config_ok = false;
         s.boot_config_catalogue_unavailable = true;
       },
       OtaBaselineMeasurementFailureReason::BootConfigCatalogueUnavailable},
      {"boot_config_mismatch",
       [](FakeMeasurementSource& s) {
         s.boot_config_ok = false;
         s.boot_config_mismatch = true;
       },
       OtaBaselineMeasurementFailureReason::BootConfigMismatch},
      {"qspi", [](FakeMeasurementSource& s) { s.qspi_ok = false; },
       OtaBaselineMeasurementFailureReason::QspiStateConflict},
  };
  for (const auto& c : cases) {
    FakeMeasurementSource src;
    src.setImage({1, 2, 3}, realCrc16((const uint8_t[]){1, 2, 3}, 3));
    c.apply(src);
    OtaBaselineMeasurementCollector collector(src);
    const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
    runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
    EXPECT_EQ(OtaBaselineMeasurementStatus::Failure, collector.status()) << c.name;
    EXPECT_EQ(c.expected, collector.failureReason()) << c.name;
    EXPECT_TRUE(src.arbiter_released) << c.name;
  }
}

TEST(OtaBaselineMeasurementCollectorTest, ExtentExactlyAtInstallCeilingIsAcceptedOneByteOverIsRejected) {
  {
    FakeMeasurementSource src;
    src.image.assign(ExtentMax::value, 0);
    src.extent_value = ExtentMax::value;
    src.stored_crc16 = realCrc16(src.image.data(), static_cast<uint32_t>(src.image.size()));
    OtaBaselineMeasurementCollector collector(src);
    const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
    runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
    EXPECT_EQ(OtaBaselineMeasurementStatus::Present, collector.status());
  }
  {
    FakeMeasurementSource src;
    src.extent_value = ExtentMax::value + 1;  // over the real ceiling.
    OtaBaselineMeasurementCollector collector(src);
    const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
    runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
    EXPECT_EQ(OtaBaselineMeasurementStatus::Failure, collector.status());
    EXPECT_EQ(OtaBaselineMeasurementFailureReason::ExtentOutOfBounds, collector.failureReason());
  }
  {
    FakeMeasurementSource src;
    src.extent_value = 4;
    src.internal_addr_value = OtaBaselineMeasurementCollector::kAppWindowStartAddr + 1;  // wrong window.
    OtaBaselineMeasurementCollector collector(src);
    const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
    runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
    EXPECT_EQ(OtaBaselineMeasurementStatus::Failure, collector.status());
    EXPECT_EQ(OtaBaselineMeasurementFailureReason::ExtentOutOfBounds, collector.failureReason());
  }
  {
    FakeMeasurementSource src;
    src.extent_value = 0;  // zero extent rejected before access.
    OtaBaselineMeasurementCollector collector(src);
    const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
    runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
    EXPECT_EQ(OtaBaselineMeasurementStatus::Failure, collector.status());
    EXPECT_EQ(OtaBaselineMeasurementFailureReason::ExtentOutOfBounds, collector.failureReason());
  }
}

TEST(OtaBaselineMeasurementCollectorTest, NullResolvedImageAndInconsistentExtentAreEachRejected) {
  {
    FakeMeasurementSource src;
    src.setImage({1, 2, 3, 4}, 0);
    src.report_null_image = true;
    OtaBaselineMeasurementCollector collector(src);
    const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
    runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
    EXPECT_EQ(OtaBaselineMeasurementStatus::Failure, collector.status());
    EXPECT_EQ(OtaBaselineMeasurementFailureReason::ImageNullOrInconsistent, collector.failureReason());
  }
  {
    FakeMeasurementSource src;
    src.setImage({1, 2, 3, 4}, 0);
    src.report_wrong_extent = true;  // resolver disagrees with the frozen bank-0 extent.
    OtaBaselineMeasurementCollector collector(src);
    const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
    runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
    EXPECT_EQ(OtaBaselineMeasurementStatus::Failure, collector.status());
    EXPECT_EQ(OtaBaselineMeasurementFailureReason::ImageNullOrInconsistent, collector.failureReason());
  }
}

TEST(OtaBaselineMeasurementCollectorTest, GenuinelyComputedZeroCrc16MatchingStoredZeroIsValidNotAbsent) {
  FakeMeasurementSource src;
  static const uint8_t img[] = {0xFF, 0xFF, 0x00, 0x00};  // well-known genuine CRC-16 == 0 fixture.
  ASSERT_EQ(0u, realCrc16(img, sizeof(img)));
  src.setImage(std::vector<uint8_t>(img, img + sizeof(img)), /*crc=*/0);

  OtaBaselineMeasurementCollector collector(src);
  const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
  runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
  ASSERT_EQ(OtaBaselineMeasurementStatus::Present, collector.status());

  OtaBaselineMeasurementEvidence evidence;
  ASSERT_TRUE(collector.readCompletedEvidence(begin_outcome.ticket.ticket_id, kOwnerA, evidence));
  EXPECT_EQ(0u, evidence.current_image_crc16);
}

TEST(OtaBaselineMeasurementCollectorTest, ComputedCrcMismatchAgainstSdkStoredCrcIsFailureNotJustEmitted) {
  FakeMeasurementSource src;
  static const uint8_t img[] = {0x11, 0x22, 0x33, 0x44};
  const uint16_t genuine = realCrc16(img, sizeof(img));
  src.setImage(std::vector<uint8_t>(img, img + sizeof(img)), static_cast<uint16_t>(genuine ^ 0xFFFFu));

  OtaBaselineMeasurementCollector collector(src);
  const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
  runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
  EXPECT_EQ(OtaBaselineMeasurementStatus::Failure, collector.status());
  EXPECT_EQ(OtaBaselineMeasurementFailureReason::ImageCrcMismatch, collector.failureReason());
}

TEST(OtaBaselineMeasurementCollectorTest, SdkSettingsGenuinelyChangingMidJobFailsClosedAtRecheckNotSilentlyAccepted) {
  FakeMeasurementSource src;
  src.setImage({1, 2, 3}, realCrc16((const uint8_t[]){1, 2, 3}, 3));
  src.mutate_sdk_on_reread = true;  // the SECOND readRawCurrentSdkSettings() call (Recheck) differs.

  OtaBaselineMeasurementCollector collector(src);
  const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
  runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
  EXPECT_EQ(OtaBaselineMeasurementStatus::Failure, collector.status());
  EXPECT_EQ(OtaBaselineMeasurementFailureReason::InconsistentReread, collector.failureReason());
  EXPECT_GT(src.sdk_read_count, 1);  // proves the Recheck phase genuinely re-read it.
}

TEST(OtaBaselineMeasurementCollectorTest, SharedBudgetCombinesResolveAndHashInOneCallWhenTheyFitTogether) {
  // resolve cost (900) + hash of a 50-byte image (50) == 950 <= 1024 --
  // must complete the WHOLE ImageHash phase (resolve+hash) in exactly
  // ONE serviceStep() call, proving the two sub-steps genuinely share
  // one combined budget rather than each independently spending 1024.
  FakeMeasurementSource src;
  std::vector<uint8_t> img(50);
  for (size_t i = 0; i < img.size(); ++i) img[i] = static_cast<uint8_t>(i);
  src.setImage(img, realCrc16(img.data(), static_cast<uint32_t>(img.size())));
  src.image_resolve_cost = 900;

  OtaBaselineMeasurementCollector collector(src);
  const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
  // Phases before ImageHash: AcquireArbiter, Identity, Profile, SdkSettings, Extent == 5 calls.
  for (int i = 0; i < 5; ++i) collector.serviceStep(begin_outcome.ticket.ticket_id, kOwnerA);
  ASSERT_EQ(OtaBaselineMeasurementStatus::Pending, collector.status());

  collector.serviceStep(begin_outcome.ticket.ticket_id, kOwnerA);  // the ImageHash call itself.
  // StockLoader/BootConfig/QspiState/Recheck haven't run yet, but the
  // image hash+CRC must already be fully computed after this ONE call.
  OtaBaselineMeasurementEvidence evidence_probe;
  // (Can't read evidence until Present, but we CAN prove completion
  // indirectly: finish the remaining trivial phases and confirm no
  // SECOND ImageHash-phase call was ever needed by counting total calls.)
  int remaining_calls = 0;
  while (collector.status() == OtaBaselineMeasurementStatus::Pending && remaining_calls < 100) {
    collector.serviceStep(begin_outcome.ticket.ticket_id, kOwnerA);
    ++remaining_calls;
  }
  ASSERT_EQ(OtaBaselineMeasurementStatus::Present, collector.status());
  // StockLoader(1) + BootConfig(1) + QspiState(1) + Recheck(1) == 4 more calls, no extra ImageHash call.
  EXPECT_EQ(4, remaining_calls);
  ASSERT_TRUE(collector.readCompletedEvidence(begin_outcome.ticket.ticket_id, kOwnerA, evidence_probe));
}

TEST(OtaBaselineMeasurementCollectorTest, SharedBudgetSpillsHashIntoASecondCallWhenCombinedExceedsTheBudget) {
  // resolve cost (900) + hash of a 200-byte image would be 1100 > 1024
  // -- the hash portion must genuinely spill into a SECOND ImageHash
  // call (124 bytes this call, 76 bytes next), never silently exceeding
  // the shared 1024-byte cap in one call.
  FakeMeasurementSource src;
  std::vector<uint8_t> img(200);
  for (size_t i = 0; i < img.size(); ++i) img[i] = static_cast<uint8_t>(i * 3);
  src.setImage(img, realCrc16(img.data(), static_cast<uint32_t>(img.size())));
  src.image_resolve_cost = 900;

  OtaBaselineMeasurementCollector collector(src);
  const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
  for (int i = 0; i < 5; ++i) collector.serviceStep(begin_outcome.ticket.ticket_id, kOwnerA);  // through Extent.
  collector.serviceStep(begin_outcome.ticket.ticket_id, kOwnerA);  // ImageHash call #1: resolves + hashes 124.
  ASSERT_EQ(OtaBaselineMeasurementStatus::Pending, collector.status());  // NOT yet StockLoader/Present.

  const int calls_before = 6;
  int total_calls = calls_before;
  while (collector.status() == OtaBaselineMeasurementStatus::Pending && total_calls < 10000) {
    collector.serviceStep(begin_outcome.ticket.ticket_id, kOwnerA);
    ++total_calls;
  }
  ASSERT_EQ(OtaBaselineMeasurementStatus::Present, collector.status());
  // One extra ImageHash call (#2) was genuinely required beyond the single-call case above.
  EXPECT_EQ(calls_before + 1 /*ImageHash#2*/ + 4 /*StockLoader/BootConfig/QspiState/Recheck*/, total_calls);
}

TEST(OtaBaselineMeasurementCollectorTest, StockLoaderAndQspiPhasesAreGenuinelyResumableAcrossMultipleCalls) {
  FakeMeasurementSource src;
  src.setImage({9, 9}, realCrc16((const uint8_t[]){9, 9}, 2));
  src.stock_loader_cost = 2000;  // forces >1 call (each call capped at kMaxBytesPerPublicStep).
  src.qspi_cost = 2000;

  OtaBaselineMeasurementCollector collector(src);
  const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
  const int calls = runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
  EXPECT_EQ(OtaBaselineMeasurementStatus::Present, collector.status());
  // Both StockLoader and QspiState now genuinely need 2 calls each
  // (2000 bytes / 1024-byte cap), on top of the other single-call phases.
  EXPECT_GT(calls, 10);
}

TEST(OtaBaselineMeasurementCollectorTest, RadioFailedButCollectorAvailableCase) {
  // This collector has NO radio dependency whatsoever (no such field or
  // method exists on the source seam at all) -- it must reach Present
  // purely off storage/identity/profile facts.
  FakeMeasurementSource src;
  src.setImage({0x10, 0x20, 0x30}, realCrc16((const uint8_t[]){0x10, 0x20, 0x30}, 3));
  OtaBaselineMeasurementCollector collector(src);
  const auto begin_outcome = collector.begin(kChallenge, kOwnerA);
  runToCompletion(collector, begin_outcome.ticket.ticket_id, kOwnerA);
  EXPECT_EQ(OtaBaselineMeasurementStatus::Present, collector.status());
}

TEST(OtaSdkSettingsCodecTest, HashesTheExactRawBytesHandedToIt) {
  // No record layout/schema is defined by this header any more (see its
  // rewritten header comment): it only hashes whatever exact 28 raw
  // bytes the caller supplies (the real bootloader-settings page in
  // production).
  uint8_t raw[kOtaCurrentSdkSettingsRecordBytes];
  for (uint32_t i = 0; i < kOtaCurrentSdkSettingsRecordBytes; ++i) raw[i] = static_cast<uint8_t>(i * 7 + 3);

  uint8_t digest[32];
  mesh::ota::hashOtaCurrentSdkSettingsRecordRaw(raw, digest);
  uint8_t expected[32];
  ::ota::trust::Sha256::hash(raw, kOtaCurrentSdkSettingsRecordBytes, expected);
  EXPECT_EQ(0, memcmp(digest, expected, 32));
}

TEST(OtaSdkSettingsCodecTest, AnySingleChangedByteAcrossAll28ProducesADifferentHash) {
  // Root-contract requirement: a genuine change to ANY of the real 28
  // bytes (not just a subset a fabricated schema happened to interpret)
  // must be observable via a changed hash.
  for (uint32_t changed_index = 0; changed_index < kOtaCurrentSdkSettingsRecordBytes; ++changed_index) {
    uint8_t raw[kOtaCurrentSdkSettingsRecordBytes] = {0};
    uint8_t digest_before[32];
    mesh::ota::hashOtaCurrentSdkSettingsRecordRaw(raw, digest_before);

    raw[changed_index] ^= 0xFF;
    uint8_t digest_after[32];
    mesh::ota::hashOtaCurrentSdkSettingsRecordRaw(raw, digest_after);

    EXPECT_NE(0, memcmp(digest_before, digest_after, 32)) << "byte index " << changed_index;
  }
}
