#include <gtest/gtest.h>
#include <array>
#include <cstring>
#include <limits>
#include <string>
#include <helpers/radiolib/RadioLibDriverFaultClassification.h>
#include <helpers/radiolib/Sx1262CheckedProbe.h>

namespace {
using mesh::RadioDriverFaultDiagnostic;
using mesh::RadioDriverFaultDetails;
using mesh::RadioDriverFaultOrigin;
using mesh::RadioServiceDiagnostic;

RadioDriverFaultDiagnostic snapshot(const RadioDriverHealthLatch& latch) {
  RadioDriverFaultDiagnostic diagnostic;
  latch.getDiagnostic(diagnostic);
  return diagnostic;
}

void expectSameDiagnostic(const RadioDriverFaultDiagnostic& expected,
                          const RadioDriverFaultDiagnostic& actual) {
  EXPECT_EQ(expected.healthy, actual.healthy);
  EXPECT_EQ(expected.hasFailure, actual.hasFailure);
  EXPECT_EQ(expected.faultCount, actual.faultCount);
  EXPECT_EQ(expected.lastFaultCount, actual.lastFaultCount);
  for (size_t i = 0; i < RadioDriverFaultDiagnostic::kOriginCount; ++i)
    EXPECT_EQ(expected.originCounts[i], actual.originCounts[i]);
  EXPECT_EQ(expected.last.origin, actual.last.origin);
  EXPECT_EQ(expected.last.driverStatus, actual.last.driverStatus);
  EXPECT_EQ(expected.last.probeReasons, actual.last.probeReasons);
  EXPECT_EQ(expected.last.expectedMode, actual.last.expectedMode);
  EXPECT_EQ(expected.last.statusByte, actual.last.statusByte);
  EXPECT_EQ(expected.last.deviceErrors, actual.last.deviceErrors);
  EXPECT_EQ(expected.last.irqFlags, actual.last.irqFlags);
  EXPECT_EQ(expected.last.deviceErrorsStatus, actual.last.deviceErrorsStatus);
  EXPECT_EQ(expected.last.irqFlagsStatus, actual.last.irqFlagsStatus);
  EXPECT_EQ(expected.last.statusReadStatus, actual.last.statusReadStatus);
  EXPECT_EQ(expected.last.softwareStateBefore, actual.last.softwareStateBefore);
  EXPECT_EQ(expected.last.softwareStateAfter, actual.last.softwareStateAfter);
}

void expectSameServiceDiagnostic(const RadioServiceDiagnostic& expected,
                                 const RadioServiceDiagnostic& actual) {
  EXPECT_EQ(expected.freeCount, actual.freeCount);
  EXPECT_EQ(expected.outboundTotal, actual.outboundTotal);
  EXPECT_EQ(expected.txTimeoutCount, actual.txTimeoutCount);
  EXPECT_EQ(expected.otaAccountingFailureCount, actual.otaAccountingFailureCount);
  EXPECT_EQ(expected.remainingTxBudget, actual.remainingTxBudget);
  EXPECT_EQ(expected.remainingOtaAirtimeBudget, actual.remainingOtaAirtimeBudget);
  EXPECT_EQ(expected.normalTrafficQueued, actual.normalTrafficQueued);
  EXPECT_EQ(expected.directActive, actual.directActive);
  EXPECT_EQ(expected.directPending, actual.directPending);
  EXPECT_EQ(expected.controlDue, actual.controlDue);
  EXPECT_EQ(expected.controlLength, actual.controlLength);
  EXPECT_EQ(expected.controlKind, actual.controlKind);
}
}

TEST(OtaRadioFaultAttribution, ServiceFormatterDefaultsAndDueControlSnapshotArePassive) {
  RadioServiceDiagnostic diagnostic;
  const auto initial = diagnostic;
  std::array<char, 161> out;
  out.fill('!');
  ASSERT_TRUE(mesh::formatRadioServiceDiagnostic(out.data(), 160, diagnostic));
  EXPECT_STREQ("ram free=0 q=0 to=0 af=0 tx=0 ota=0 n=0 d=0 p=0 c=0 len=0 kind=00", out.data());
  EXPECT_EQ('!', out[160]);
  expectSameServiceDiagnostic(initial, diagnostic);
  diagnostic = {32, 2, 4, 1, 1000, 72000, true, false, true, true, 123, 0x0B};
  const auto before = diagnostic;
  ASSERT_TRUE(mesh::formatRadioServiceDiagnostic(out.data(), 160, diagnostic));
  EXPECT_STREQ("ram free=32 q=2 to=4 af=1 tx=3E8 ota=11940 n=1 d=0 p=1 c=1 len=123 kind=0B", out.data());
  EXPECT_LT(std::strlen(out.data()) + 3, 160u);
  EXPECT_EQ('!', out[160]);
  expectSameServiceDiagnostic(before, diagnostic);
}

TEST(OtaRadioFaultAttribution, ServiceFormatterMaximalFieldsFitReplyAndExactCapacity) {
  RadioServiceDiagnostic diagnostic{
      std::numeric_limits<int>::min(), std::numeric_limits<int>::min(),
      UINT32_MAX, UINT32_MAX, std::numeric_limits<unsigned long>::max(),
      std::numeric_limits<unsigned long>::max(), true, true, true, true, UINT16_MAX, UINT8_MAX};
  const auto before = diagnostic;
  const std::string budget_max = sizeof(unsigned long) == 8 ? "FFFFFFFFFFFFFFFF" : "FFFFFFFF";
  const std::string expected =
      "ram free=" + std::to_string(diagnostic.freeCount) +
      " q=" + std::to_string(diagnostic.outboundTotal) +
      " to=FFFFFFFF af=FFFFFFFF tx=" + budget_max + " ota=" + budget_max +
      " n=1 d=1 p=1 c=1 len=65535 kind=FF";
  std::array<char, 161> out;
  out.fill('!');
  ASSERT_TRUE(mesh::formatRadioServiceDiagnostic(out.data(), 160, diagnostic));
  EXPECT_STREQ(expected.c_str(), out.data());
  const size_t length = std::strlen(out.data());
  EXPECT_EQ(sizeof(unsigned long) == 8 ? 133u : 117u, length);
  EXPECT_LE(length + 3, 159u);
  EXPECT_EQ('\0', out[length]);
  EXPECT_EQ('!', out[length + 1]);
  EXPECT_EQ('!', out[160]);
  out.fill('!');
  ASSERT_TRUE(mesh::formatRadioServiceDiagnostic(out.data(), length + 1, diagnostic));
  EXPECT_STREQ(expected.c_str(), out.data());
  EXPECT_EQ('!', out[length + 1]);
  expectSameServiceDiagnostic(before, diagnostic);
}

TEST(OtaRadioFaultAttribution, ServiceFormatterRejectsNullAndSmallBuffersWithoutMutation) {
  RadioServiceDiagnostic diagnostic{32, 2, 4, 1, 1000, 72000, true, false, true, true, 123, 0x0B};
  const auto before = diagnostic;
  EXPECT_FALSE(mesh::formatRadioServiceDiagnostic(nullptr, 160, diagnostic));
  EXPECT_FALSE(mesh::formatRadioServiceDiagnostic(nullptr, 0, diagnostic));
  std::array<char, 161> out;
  out.fill('!');
  EXPECT_FALSE(mesh::formatRadioServiceDiagnostic(out.data(), 0, diagnostic));
  EXPECT_EQ('!', out[0]);
  for (size_t capacity : {size_t{1}, size_t{4}}) {
    out.fill('!');
    EXPECT_FALSE(mesh::formatRadioServiceDiagnostic(out.data(), capacity, diagnostic));
    EXPECT_EQ('\0', out[0]);
    for (size_t i = capacity; i < out.size(); ++i) EXPECT_EQ('!', out[i]);
  }
  ASSERT_TRUE(mesh::formatRadioServiceDiagnostic(out.data(), 160, diagnostic));
  const size_t missing_nul_capacity = std::strlen(out.data());
  out.fill('!');
  EXPECT_FALSE(mesh::formatRadioServiceDiagnostic(out.data(), missing_nul_capacity, diagnostic));
  EXPECT_EQ('\0', out[0]);
  EXPECT_EQ('\0', out[missing_nul_capacity - 1]);
  for (size_t i = missing_nul_capacity; i < out.size(); ++i) EXPECT_EQ('!', out[i]);
  expectSameServiceDiagnostic(before, diagnostic);
}

TEST(OtaRadioFaultAttribution, PassiveFormatterDefaultsHaveNoFaultAndTerminateWithinBounds) {
  RadioDriverFaultDiagnostic diagnostic;
  const auto before = diagnostic;
  std::array<char, 161> out;
  out.fill('!');
  ASSERT_TRUE(mesh::formatRadioDriverFaultDiagnostic(out.data(), 160, diagnostic,
                                                   false, false, false, false));
  EXPECT_STREQ("retained h=1 f=0 n=0 l=0 o=0 ds=0 pr=0 em=0 sb=0 de=0 irq=0 "
               "es=0 is=0 ss=0 sw=0/0 r=0 t=0 d=0 p=0", out.data());
  EXPECT_LT(std::strlen(out.data()), 160u);
  EXPECT_EQ('!', out[160]);
  expectSameDiagnostic(before, diagnostic);
}

TEST(OtaRadioFaultAttribution, PassiveFormatterMaximalFieldsFitReplyIncludingOptionalPrefix) {
  RadioDriverFaultDiagnostic diagnostic;
  diagnostic.healthy = false;
  diagnostic.hasFailure = true;
  diagnostic.faultCount = UINT32_MAX;
  diagnostic.lastFaultCount = UINT32_MAX;
  for (auto& count : diagnostic.originCounts) count = UINT32_MAX;
  diagnostic.last = {static_cast<RadioDriverFaultOrigin>(UINT8_MAX), INT16_MIN,
                     UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT16_MAX, UINT32_MAX,
                     INT16_MIN, INT16_MIN, INT16_MIN, UINT8_MAX, UINT8_MAX};
  const auto before = diagnostic;
  const char* expected =
      "retained h=0 f=1 n=FFFFFFFF l=FFFFFFFF o=255 ds=-32768 pr=FF em=FF sb=FF "
      "de=FFFF irq=FFFFFFFF es=-32768 is=-32768 ss=-32768 sw=FF/FF r=1 t=1 d=1 p=1";
  std::array<char, 161> out;
  out.fill('!');
  ASSERT_TRUE(mesh::formatRadioDriverFaultDiagnostic(out.data(), 160, diagnostic,
                                                   true, true, true, true));
  EXPECT_STREQ(expected, out.data());
  EXPECT_EQ(148u, std::strlen(out.data()));
  EXPECT_LE(std::strlen(out.data()) + 3, 159u);
  EXPECT_EQ('\0', out[148]);
  EXPECT_EQ('!', out[149]);
  EXPECT_EQ('!', out[160]);
  out.fill('!');
  ASSERT_TRUE(mesh::formatRadioDriverFaultDiagnostic(out.data(), 149, diagnostic,
                                                   true, true, true, true));
  EXPECT_STREQ(expected, out.data());
  EXPECT_EQ('!', out[149]);
  expectSameDiagnostic(before, diagnostic);
}

TEST(OtaRadioFaultAttribution, PassiveFormatterRetainsLastFailureAfterSuccessfulRecovery) {
  RadioDriverHealthLatch latch;
  Sx1262CheckedProbeResult probe{-705, 0xFFFF, -706, 0xFFFFFFFF, -707, 0xFF};
  recordSx1262CheckedProbeOutcome(latch, probe, Sx1262ExpectedChipMode::kReceiving, 1, 0x11);
  latch.recordOutcome(true);
  auto diagnostic = snapshot(latch);
  const auto before = diagnostic;
  char out[160];
  ASSERT_TRUE(mesh::formatRadioDriverFaultDiagnostic(out, sizeof(out), diagnostic,
                                                   true, false, true, false));
  EXPECT_STREQ("retained h=1 f=1 n=1 l=1 o=5 ds=-705 pr=7 em=1 sb=FF de=FFFF "
               "irq=FFFFFFFF es=-705 is=-706 ss=-707 sw=1/11 r=1 t=0 d=1 p=0", out);
  expectSameDiagnostic(before, diagnostic);
  expectSameDiagnostic(before, snapshot(latch));
}

TEST(OtaRadioFaultAttribution, PassiveFormatterRejectsNullAndSmallBuffersWithoutOverrun) {
  RadioDriverFaultDiagnostic diagnostic;
  const auto before = diagnostic;
  EXPECT_FALSE(mesh::formatRadioDriverFaultDiagnostic(nullptr, 160, diagnostic,
                                                    false, false, false, false));
  EXPECT_FALSE(mesh::formatRadioDriverFaultDiagnostic(nullptr, 0, diagnostic,
                                                    false, false, false, false));
  std::array<char, 161> out;
  out.fill('!');
  EXPECT_FALSE(mesh::formatRadioDriverFaultDiagnostic(out.data(), 0, diagnostic,
                                                    false, false, false, false));
  EXPECT_EQ('!', out[0]);
  for (size_t capacity : {size_t{1}, size_t{4}}) {
    out.fill('!');
    EXPECT_FALSE(mesh::formatRadioDriverFaultDiagnostic(out.data(), capacity, diagnostic,
                                                      false, false, false, false));
    EXPECT_EQ('\0', out[0]);
    for (size_t i = capacity; i < out.size(); ++i) EXPECT_EQ('!', out[i]);
  }
  ASSERT_TRUE(mesh::formatRadioDriverFaultDiagnostic(out.data(), 160, diagnostic,
                                                   false, false, false, false));
  const size_t missing_nul_capacity = std::strlen(out.data());
  out.fill('!');
  EXPECT_FALSE(mesh::formatRadioDriverFaultDiagnostic(out.data(), missing_nul_capacity, diagnostic,
                                                    false, false, false, false));
  EXPECT_EQ('\0', out[0]);
  EXPECT_EQ('\0', out[missing_nul_capacity - 1]);
  for (size_t i = missing_nul_capacity; i < out.size(); ++i) EXPECT_EQ('!', out[i]);
  expectSameDiagnostic(before, diagnostic);
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
