#include <gtest/gtest.h>
#include <array>
#include <helpers/radiolib/RadioLibDriverFaultClassification.h>
#include <helpers/radiolib/Sx1262CheckedProbe.h>

namespace {
using mesh::RadioDriverFaultDiagnostic;
using mesh::RadioDriverFaultDetails;
using mesh::RadioDriverFaultOrigin;

RadioDriverFaultDiagnostic snapshot(const RadioDriverHealthLatch& latch) {
  RadioDriverFaultDiagnostic diagnostic;
  latch.getDiagnostic(diagnostic);
  return diagnostic;
}
}

TEST(OtaRadioFaultAttribution, DefaultsAndUnattributedLegacyCallsPreserveHealthAndCount) {
  RadioDriverHealthLatch latch;
  const auto initial = snapshot(latch);
  EXPECT_TRUE(initial.healthy);
  EXPECT_FALSE(initial.hasFailure);
  EXPECT_EQ(0u, initial.faultCount);
  for (auto count : initial.originCounts) EXPECT_EQ(0u, count);
  latch.recordOutcome(false);
  EXPECT_FALSE(latch.healthy());
  EXPECT_EQ(1u, latch.faultCount());
  EXPECT_EQ(1u, snapshot(latch).originCounts[0]);
  latch.recordOutcome(true);
  EXPECT_TRUE(latch.healthy());
  EXPECT_EQ(1u, latch.faultCount());
  EXPECT_TRUE(snapshot(latch).hasFailure);
}

TEST(OtaRadioFaultAttribution, EachOperationOriginRetainsStatusAcrossSuccessfulRecovery) {
  RadioDriverHealthLatch latch;
  const std::array<RadioDriverFaultOrigin, 4> origins{
      RadioDriverFaultOrigin::StartReceive, RadioDriverFaultOrigin::ReadData,
      RadioDriverFaultOrigin::ReceiveRearm, RadioDriverFaultOrigin::StartTransmit};
  const std::array<int16_t, 4> statuses{-705, -6, -706, -707};
  for (size_t i = 0; i < origins.size(); ++i) {
    latch.recordFailure(origins[i], statuses[i], 0x01, 0x11);
    const auto failed = snapshot(latch);
    EXPECT_FALSE(failed.healthy);
    EXPECT_EQ(i + 1, failed.faultCount);
    EXPECT_EQ(failed.faultCount, failed.lastFaultCount);
    EXPECT_EQ(origins[i], failed.last.origin);
    EXPECT_EQ(statuses[i], failed.last.driverStatus);
    EXPECT_EQ(0x01, failed.last.softwareStateBefore);
    EXPECT_EQ(0x11, failed.last.softwareStateAfter);
    EXPECT_EQ(1u, failed.originCounts[static_cast<uint8_t>(origins[i])]);
    latch.recordOutcome(true);
    const auto recovered = snapshot(latch);
    EXPECT_TRUE(recovered.healthy);
    EXPECT_EQ(failed.faultCount, recovered.faultCount);
    EXPECT_EQ(failed.lastFaultCount, recovered.lastFaultCount);
    EXPECT_EQ(failed.last.origin, recovered.last.origin);
    EXPECT_EQ(failed.last.driverStatus, recovered.last.driverStatus);
  }
}

TEST(OtaRadioFaultAttribution, CrcRejectionRemainsHealthyAndDoesNotOverwriteFailure) {
  RadioDriverHealthLatch latch;
  latch.recordFailure(RadioDriverFaultOrigin::StartTransmit, -707, 1, 1);
  for (const int status : {0, -7, -7, 0}) {
    EXPECT_FALSE(radiolib_health::isGenuineRadioDriverFault(status));
    latch.recordOutcome(!radiolib_health::isGenuineRadioDriverFault(status));
    EXPECT_TRUE(latch.healthy());
    EXPECT_EQ(1u, latch.faultCount());
    EXPECT_EQ(-707, snapshot(latch).last.driverStatus);
  }
  for (const int status : {-6, -2, -705, -706, -707, 1})
    EXPECT_TRUE(radiolib_health::isGenuineRadioDriverFault(status));
}

TEST(OtaRadioFaultAttribution, CompletedTxModeMismatchIsStillUnhealthyButNowAttributed) {
  RadioDriverHealthLatch latch;
  Sx1262CheckedProbeResult probe{};
  probe.status_byte = kSx1262StatusModeStdbyRc;
  probe.irq_flags = kSx1262IrqTxDone;
  recordSx1262CheckedProbeOutcome(latch, probe, Sx1262ExpectedChipMode::kTransmitting, 0x03, 0x13);
  const auto failed = snapshot(latch);
  EXPECT_FALSE(failed.healthy);
  EXPECT_EQ(1u, failed.faultCount);
  EXPECT_EQ(RadioDriverFaultOrigin::ActiveProbe, failed.last.origin);
  EXPECT_EQ(kSx1262ModeMismatch, failed.last.probeReasons);
  EXPECT_EQ(kSx1262IrqTxDone, failed.last.irqFlags);
  EXPECT_EQ(0x03, failed.last.softwareStateBefore);
  EXPECT_EQ(0x13, failed.last.softwareStateAfter);
  probe.status_byte = kSx1262StatusModeRx;
  recordSx1262CheckedProbeOutcome(latch, probe, Sx1262ExpectedChipMode::kReceiving, 1, 1);
  const auto recovered = snapshot(latch);
  EXPECT_TRUE(recovered.healthy);
  EXPECT_EQ(1u, recovered.faultCount);
  EXPECT_EQ(kSx1262ModeMismatch, recovered.last.probeReasons);
  EXPECT_EQ(kSx1262StatusModeStdbyRc, recovered.last.statusByte);
}

TEST(OtaRadioFaultAttribution, CheckedFailuresRetainEveryStatusButDoNotTrustPoisonedValues) {
  RadioDriverHealthLatch latch;
  Sx1262CheckedProbeResult probe{-705, 0xFFFF, -706, 0xFFFFFFFF, -707, 0xFF};
  recordSx1262CheckedProbeOutcome(latch, probe, Sx1262ExpectedChipMode::kReceiving, 1, 0x11);
  const auto diagnostic = snapshot(latch);
  EXPECT_FALSE(diagnostic.healthy);
  EXPECT_EQ(0x07, diagnostic.last.probeReasons);
  EXPECT_EQ(-705, diagnostic.last.driverStatus);
  EXPECT_EQ(-705, diagnostic.last.deviceErrorsStatus);
  EXPECT_EQ(-706, diagnostic.last.irqFlagsStatus);
  EXPECT_EQ(-707, diagnostic.last.statusReadStatus);
  EXPECT_EQ(0xFFFF, diagnostic.last.deviceErrors);
  EXPECT_EQ(0xFFFFFFFF, diagnostic.last.irqFlags);
  EXPECT_EQ(0xFF, diagnostic.last.statusByte);
  probe = {0, 0x0040, 0, 0, 0, 0};
  recordSx1262CheckedProbeOutcome(latch, probe, Sx1262ExpectedChipMode::kReceiving, 1, 1);
  EXPECT_EQ(kSx1262DeviceErrorsPresent | kSx1262UnsupportedMode, snapshot(latch).last.probeReasons);
  EXPECT_EQ(0, snapshot(latch).last.driverStatus);
}

TEST(OtaRadioFaultAttribution, ReasonsAndRecordedVerdictsAgreeWithStrictProbeDecision) {
  RadioDriverHealthLatch latch;
  uint32_t failures = 0;
  for (unsigned mask = 0; mask < 8; ++mask) {
    for (uint16_t errors : {0, 1, 0xFFFF}) {
      for (unsigned byte = 0; byte < 256; ++byte) {
        for (unsigned expected = 0; expected < 4; ++expected) {
          Sx1262CheckedProbeResult probe{
              static_cast<int16_t>(mask & 1 ? -705 : 0), errors,
              static_cast<int16_t>(mask & 2 ? -706 : 0), kSx1262IrqTxDone | kSx1262IrqRxDone,
              static_cast<int16_t>(mask & 4 ? -707 : 0), static_cast<uint8_t>(byte)};
          const auto mode = static_cast<Sx1262ExpectedChipMode>(expected);
          const bool healthy = evaluateSx1262CheckedHealth(probe, mode);
          EXPECT_EQ(healthy, sx1262ProbeFailureReasons(probe, mode) == 0);
          recordSx1262CheckedProbeOutcome(latch, probe, mode, 3, 0x13);
          if (!healthy) ++failures;
          EXPECT_EQ(healthy, latch.healthy());
          EXPECT_EQ(failures, latch.faultCount());
        }
      }
    }
  }
}

TEST(OtaRadioFaultAttribution, CountWrapKeepsValidLastFailureAndPerOriginModuloSemantics) {
  RadioDriverFaultDiagnostic diagnostic;
  diagnostic.faultCount = UINT32_MAX;
  diagnostic.originCounts[4] = UINT32_MAX;
  RadioDriverFaultDetails details;
  details.origin = RadioDriverFaultOrigin::StartTransmit;
  details.driverStatus = -707;
  mesh::recordRadioDriverOutcome(diagnostic, false, details);
  EXPECT_EQ(0u, diagnostic.faultCount);
  EXPECT_EQ(0u, diagnostic.lastFaultCount);
  EXPECT_EQ(0u, diagnostic.originCounts[4]);
  EXPECT_TRUE(diagnostic.hasFailure);
  mesh::recordRadioDriverOutcome(diagnostic, true, {});
  EXPECT_TRUE(diagnostic.healthy);
  EXPECT_EQ(-707, diagnostic.last.driverStatus);
  details.origin = static_cast<RadioDriverFaultOrigin>(255);
  mesh::recordRadioDriverOutcome(diagnostic, false, details);
  EXPECT_EQ(RadioDriverFaultOrigin::Unknown, diagnostic.last.origin);
  EXPECT_EQ(1u, diagnostic.originCounts[0]);
}
