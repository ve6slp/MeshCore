// Native tests for OtaMeasurementControlJobBackend: binds
// OtaControlSessionRouter's typed IOtaControlJobBackend seam to a REAL
// OtaBaselineMeasurementCollector, verifying MEASURE/POLL/READ_OBJECT
// deliver the genuine 235-byte OtaControlMeasurement wire object end to
// end -- never a fabricated Ok/Pending.
#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "helpers/ota/OtaBaselineMeasurementCollector.h"
#include "helpers/ota/OtaMeasurementControlJobBackend.h"

using mesh::ota::IOtaBaselineMeasurementSource;
using mesh::ota::OtaBaselineMeasurementArbiterResult;
using mesh::ota::OtaBaselineMeasurementCollector;
using mesh::ota::OtaBaselineMeasurementStatus;
using mesh::ota::OtaBaselineMeasurementSubStep;
using mesh::ota::kOtaCurrentSdkSettingsRecordBytes;
using meshcore::ota::runtime::OtaMeasurementControlJobBackend;
using namespace meshcore::ota::protocol;

namespace {

// Minimal always-succeeds-eventually fixture: every bounded phase
// resolves on its first call (cost 0) so tests don't need to iterate the
// shared-budget mechanics already covered by
// test_lora_ota_storage/test_baseline_measurement_collector.cpp -- this
// file is about the CONTROL-ABI adapter, not the collector's own state
// machine.
class HappyPathSource : public IOtaBaselineMeasurementSource {
public:
  bool entropy_ok = true;
  std::vector<uint8_t> image = std::vector<uint8_t>(16, 0x42);
  // Must be the REAL CRC-16 over `image` -- the collector independently
  // computes it and fails closed (ImageCrcMismatch) on any disagreement.
  uint16_t stored_crc16 = ::ota::storage::XiaoOtaActiveExtentBridge::crc16Compute(
      std::vector<uint8_t>(16, 0x42).data(), 16);

  OtaBaselineMeasurementArbiterResult acquireMediaArbiter() override {
    return OtaBaselineMeasurementArbiterResult::Acquired;
  }
  void releaseMediaArbiter() override {}

  bool readDeviceIdentity(uint8_t out_uid8[8], uint8_t out_pubkey32[32]) override {
    for (int i = 0; i < 8; ++i) out_uid8[i] = static_cast<uint8_t>(0xA0 + i);
    for (int i = 0; i < 32; ++i) out_pubkey32[i] = static_cast<uint8_t>(0xB0 + i);
    return true;
  }
  bool readCompiledProfile(uint32_t& p, uint32_t& t, uint32_t& r, uint32_t& l) override {
    p = 1; t = 10; r = 0; l = 3;
    return true;
  }
  bool readRawCurrentSdkSettings(uint8_t out_raw28[kOtaCurrentSdkSettingsRecordBytes]) override {
    memset(out_raw28, 0x11, kOtaCurrentSdkSettingsRecordBytes);
    return true;
  }
  bool readValidatedBank0Extent(uint32_t& out_extent, uint32_t& out_internal_addr,
                                uint16_t& out_stored_crc16) override {
    out_extent = static_cast<uint32_t>(image.size());
    out_internal_addr = OtaBaselineMeasurementCollector::kAppWindowStartAddr;
    out_stored_crc16 = stored_crc16;
    return true;
  }
  OtaBaselineMeasurementSubStep stepAppImageAccess(uint32_t, uint32_t* out_bytes_consumed,
                                                   const uint8_t** out_image, uint32_t* out_extent) override {
    *out_bytes_consumed = 0;
    *out_image = image.data();
    *out_extent = static_cast<uint32_t>(image.size());
    return OtaBaselineMeasurementSubStep::Resolved;
  }
  OtaBaselineMeasurementSubStep stepStockLoaderRangeHash(uint32_t, uint32_t* out_bytes_consumed,
                                                         uint32_t& out_start, uint32_t& out_length,
                                                         uint8_t out_hash32[32]) override {
    *out_bytes_consumed = 0;
    out_start = 0x1000;
    out_length = 0x2000;
    memset(out_hash32, 0x7A, 32);
    return OtaBaselineMeasurementSubStep::Resolved;
  }
  OtaBaselineMeasurementSubStep stepBootConfigSelection(uint32_t, uint32_t* out_bytes_consumed,
                                                        uint32_t& out_boot_config_id,
                                                        bool& out_catalogue_unavailable,
                                                        bool& out_mismatch) override {
    *out_bytes_consumed = 0;
    out_boot_config_id = 0x00010001u;
    out_catalogue_unavailable = false;
    out_mismatch = false;
    return OtaBaselineMeasurementSubStep::Resolved;
  }
  OtaBaselineMeasurementSubStep stepQspiStateInspection(uint32_t, uint32_t* out_bytes_consumed) override {
    *out_bytes_consumed = 0;
    return OtaBaselineMeasurementSubStep::Resolved;
  }
  bool getPlatformEntropy16(uint8_t out[16]) override {
    if (!entropy_ok) return false;
    for (int i = 0; i < 16; ++i) out[i] = static_cast<uint8_t>(0xC0 + i);
    return true;
  }
};

// Drives the collector exactly like MyMesh::tickOtaTrialHealth() does --
// one serviceStep() per "tick", entirely independent of the backend
// under test, so these tests prove the adapter never has to (and must
// not) advance the collector itself.
void tickCollector(OtaBaselineMeasurementCollector& collector) {
  if (collector.status() == OtaBaselineMeasurementStatus::Pending) {
    collector.serviceStep(collector.currentTicketId(), collector.currentOwnerToken());
  }
}

TEST(OtaMeasurementControlJobBackend, UnsupportedSubcommandIsExplicitNoCapacityNeverFakeOk) {
  HappyPathSource source;
  OtaBaselineMeasurementCollector collector(source);
  OtaMeasurementControlJobBackend backend(collector);
  uint16_t reason = 0;
  auto st = backend.beginJob(OtaControlSubcommand::Prepare, 1, OtaControlObjectKind::None, nullptr, 0, reason);
  EXPECT_EQ(OtaControlStatus::NoCapacity, st);
  EXPECT_EQ(OtaMeasurementControlJobBackend::kReasonUnsupportedOperation, reason);
}

TEST(OtaMeasurementControlJobBackend, MeasureBeginIsPendingNeverAdvancesInline) {
  HappyPathSource source;
  OtaBaselineMeasurementCollector collector(source);
  OtaMeasurementControlJobBackend backend(collector);
  uint16_t reason = 0;
  auto st = backend.beginJob(OtaControlSubcommand::Measure, 7, OtaControlObjectKind::None, nullptr, 0, reason);
  EXPECT_EQ(OtaControlStatus::Pending, st);
  // Backend must not have advanced the collector itself.
  EXPECT_EQ(OtaBaselineMeasurementStatus::Pending, collector.status());

  // pollJob is status-only: repeated polling with no external tick must
  // never progress the job.
  uint16_t pollReason = 0;
  EXPECT_EQ(OtaControlStatus::Pending, backend.pollJob(7, pollReason));
  EXPECT_EQ(OtaControlStatus::Pending, backend.pollJob(7, pollReason));
  EXPECT_EQ(OtaBaselineMeasurementStatus::Pending, collector.status());
}

TEST(OtaMeasurementControlJobBackend, FullRoundTripThroughExternalTicksProducesRealMeasurement) {
  HappyPathSource source;
  OtaBaselineMeasurementCollector collector(source);
  OtaMeasurementControlJobBackend backend(collector);
  uint16_t reason = 0;
  ASSERT_EQ(OtaControlStatus::Pending,
            backend.beginJob(OtaControlSubcommand::Measure, 11, OtaControlObjectKind::None, nullptr, 0, reason));

  int ticks = 0;
  while (collector.status() == OtaBaselineMeasurementStatus::Pending && ticks < 1000) {
    tickCollector(collector);
    ++ticks;
  }
  ASSERT_EQ(OtaBaselineMeasurementStatus::Present, collector.status());

  uint16_t pollReason = 0;
  EXPECT_EQ(OtaControlStatus::Ok, backend.pollJob(11, pollReason));

  // Read the full 235-byte object in two chunks (>128 requires two
  // ReadObject calls on the real wire, exactly like a genuine USB host).
  uint8_t chunk1[128] = {0};
  uint8_t outLen1 = 0;
  uint16_t readReason = 0;
  ASSERT_EQ(OtaControlStatus::Ok,
            backend.readObject(11, OtaControlObjectKind::Measurement, 0, chunk1, 128, outLen1, readReason));
  EXPECT_EQ(128, outLen1);

  uint8_t chunk2[107] = {0};
  uint8_t outLen2 = 0;
  ASSERT_EQ(OtaControlStatus::Ok,
            backend.readObject(11, OtaControlObjectKind::Measurement, 128, chunk2, 107, outLen2, readReason));
  EXPECT_EQ(107, outLen2);

  uint8_t full[235];
  std::memcpy(full, chunk1, 128);
  std::memcpy(full + 128, chunk2, 107);

  OtaControlMeasurement decoded;
  ASSERT_EQ(OtaControlCodecResult::Ok, decodeOtaControlMeasurement(full, sizeof(full), decoded));
  EXPECT_EQ(0xA0, decoded.uid8[0]);
  EXPECT_EQ(1u, decoded.profile);
  EXPECT_EQ(10u, decoded.target);
  EXPECT_EQ(3u, decoded.layout);
  EXPECT_EQ(0x00010001u, decoded.bootConfigId);
  EXPECT_EQ(0x11, decoded.rawSdk28[0]);
}

TEST(OtaMeasurementControlJobBackend, ForeignTicketIsDeniedNeverLeaksAnotherJobsData) {
  HappyPathSource source;
  OtaBaselineMeasurementCollector collector(source);
  OtaMeasurementControlJobBackend backend(collector);
  uint16_t reason = 0;
  ASSERT_EQ(OtaControlStatus::Pending,
            backend.beginJob(OtaControlSubcommand::Measure, 5, OtaControlObjectKind::None, nullptr, 0, reason));

  uint16_t pollReason = 0;
  EXPECT_EQ(OtaControlStatus::Denied, backend.pollJob(999, pollReason));
  EXPECT_EQ(OtaMeasurementControlJobBackend::kReasonForeignTicket, pollReason);

  uint8_t dest[128];
  uint8_t outLen = 0;
  EXPECT_EQ(OtaControlStatus::Denied,
            backend.readObject(999, OtaControlObjectKind::Measurement, 0, dest, 128, outLen, pollReason));
  EXPECT_EQ(0, outLen);
}

TEST(OtaMeasurementControlJobBackend, CancelReleasesJobAndSubsequentPollIsDenied) {
  HappyPathSource source;
  OtaBaselineMeasurementCollector collector(source);
  OtaMeasurementControlJobBackend backend(collector);
  uint16_t reason = 0;
  ASSERT_EQ(OtaControlStatus::Pending,
            backend.beginJob(OtaControlSubcommand::Measure, 3, OtaControlObjectKind::None, nullptr, 0, reason));
  backend.cancelJob(3);
  EXPECT_EQ(OtaBaselineMeasurementStatus::Idle, collector.status());

  uint16_t pollReason = 0;
  EXPECT_EQ(OtaControlStatus::Denied, backend.pollJob(3, pollReason));
}

TEST(OtaMeasurementControlJobBackend, EntropyUnavailableAtBeginIsExplicitNoCapacityNeverFabricatedProgress) {
  HappyPathSource source;
  source.entropy_ok = false;
  OtaBaselineMeasurementCollector collector(source);
  OtaMeasurementControlJobBackend backend(collector);
  uint16_t reason = 0;
  auto st = backend.beginJob(OtaControlSubcommand::Measure, 2, OtaControlObjectKind::None, nullptr, 0, reason);
  EXPECT_EQ(OtaControlStatus::NoCapacity, st);
  EXPECT_EQ(OtaMeasurementControlJobBackend::kReasonBeginRejected, reason);
  EXPECT_EQ(OtaBaselineMeasurementStatus::Idle, collector.status());
}

TEST(OtaMeasurementControlJobBackend, WrongObjectKindOnReadObjectIsDeniedEvenWithValidTicket) {
  HappyPathSource source;
  OtaBaselineMeasurementCollector collector(source);
  OtaMeasurementControlJobBackend backend(collector);
  uint16_t reason = 0;
  ASSERT_EQ(OtaControlStatus::Pending,
            backend.beginJob(OtaControlSubcommand::Measure, 9, OtaControlObjectKind::None, nullptr, 0, reason));
  int ticks = 0;
  while (collector.status() == OtaBaselineMeasurementStatus::Pending && ticks < 1000) {
    tickCollector(collector);
    ++ticks;
  }
  ASSERT_EQ(OtaBaselineMeasurementStatus::Present, collector.status());

  uint8_t dest[16];
  uint8_t outLen = 0xFF;
  uint16_t readReason = 0;
  EXPECT_EQ(OtaControlStatus::Denied,
            backend.readObject(9, OtaControlObjectKind::BootReceipt386, 0, dest, 16, outLen, readReason));
  EXPECT_EQ(0, outLen);
}

} // namespace
