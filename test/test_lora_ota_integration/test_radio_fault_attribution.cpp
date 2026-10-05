#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>

#include <Dispatcher.h>
#include <helpers/BaseSerialInterface.h>
#include <helpers/ota/OtaMeasurementDiagnostics.h>
#include <helpers/radiolib/RadioLibDriverFaultClassification.h>
#include <helpers/radiolib/Sx1262CheckedProbe.h>

namespace {

using mesh::RadioDriverFaultDiagnostic;
using mesh::RadioDriverFaultDetails;
using mesh::RadioDriverFaultOrigin;
namespace usb = mesh::ota::usb;

RadioDriverFaultDiagnostic snapshot(const RadioDriverHealthLatch& latch) {
  RadioDriverFaultDiagnostic diagnostic;
  latch.getDiagnostic(diagnostic);
  return diagnostic;
}

class UnsupportedRadio : public mesh::Radio {
 public:
  int recvRaw(uint8_t*, int) override { return 0; }
  uint32_t getEstAirtimeFor(int) override { return 1; }
  float packetScore(float, int) override { return 0; }
  bool startSendRaw(const uint8_t*, int) override { return true; }
  bool isSendComplete() override { return false; }
  void onSendFinished() override {}
  bool isInRecvMode() const override { return true; }
};

class DiagnosticRadio : public UnsupportedRadio {
 public:
  RadioDriverHealthLatch latch;
  mutable unsigned getters = 0;
  unsigned probes = 0;
  bool probeDriverStatus() override { ++probes; return latch.healthy(); }
  bool getDriverFaultDiagnostic(RadioDriverFaultDiagnostic& out) const override {
    ++getters;
    latch.getDiagnostic(out);
    return true;
  }
};

std::string source(const char* path) {
  std::ifstream file(path);
  EXPECT_TRUE(file.good()) << path;
  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

size_t occurrences(const std::string& text, const std::string& needle) {
  size_t count = 0, position = 0;
  while ((position = text.find(needle, position)) != std::string::npos) {
    ++count;
    position += needle.size();
  }
  return count;
}

}  // namespace

TEST(OtaRadioFaultAttribution, DefaultsAndUnattributedLegacyCallsPreserveHealthAndCount) {
  RadioDriverHealthLatch latch;
  const auto initial = snapshot(latch);
  EXPECT_TRUE(initial.healthy);
  EXPECT_FALSE(initial.hasFailure);
  EXPECT_EQ(0u, initial.faultCount);
  EXPECT_EQ(0u, initial.lastFaultCount);
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
    EXPECT_EQ(0, failed.last.probeReasons);
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
  EXPECT_EQ(1u, failed.originCounts[5]);
  EXPECT_EQ(RadioDriverFaultOrigin::ActiveProbe, failed.last.origin);
  EXPECT_EQ(0, failed.last.driverStatus);
  EXPECT_EQ(kSx1262ModeMismatch, failed.last.probeReasons);
  EXPECT_EQ(2, failed.last.expectedMode);
  EXPECT_EQ(kSx1262StatusModeStdbyRc, failed.last.statusByte);
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
  EXPECT_EQ(1u, diagnostic.faultCount);
  EXPECT_EQ(1u, diagnostic.originCounts[5]);
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
  EXPECT_EQ(0x0040, snapshot(latch).last.deviceErrors);
}

TEST(OtaRadioFaultAttribution, ReasonsAndRecordedVerdictsAgreeWithUnchangedStrictProbeDecision) {
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
  EXPECT_FALSE(diagnostic.healthy);
  mesh::recordRadioDriverOutcome(diagnostic, true, {});
  EXPECT_TRUE(diagnostic.healthy);
  EXPECT_TRUE(diagnostic.hasFailure);
  EXPECT_EQ(-707, diagnostic.last.driverStatus);
  details.origin = static_cast<RadioDriverFaultOrigin>(255);
  mesh::recordRadioDriverOutcome(diagnostic, false, details);
  EXPECT_EQ(RadioDriverFaultOrigin::Unknown, diagnostic.last.origin);
  EXPECT_EQ(1u, diagnostic.originCounts[0]);
}

TEST(OtaRadioFaultAttribution, SelectorFiveLeavesEveryExistingSelectorAndRequestUnchanged) {
  uint8_t command[] = {66, 0, 0, 0};
  for (uint8_t selector = 0; selector <= 4; ++selector) {
    command[2] = selector;
    EXPECT_EQ(usb::RadioFaultStatusRequest::Other, usb::classifyRadioFaultStatusRequest(command, 3));
    EXPECT_EQ(usb::RadioFaultStatusRequest::Other, usb::classifyRadioFaultStatusRequest(command, 4));
  }
  EXPECT_EQ(usb::RadioFaultStatusRequest::Other, usb::classifyRadioFaultStatusRequest(command, 2));
  command[2] = 5;
  EXPECT_EQ(usb::RadioFaultStatusRequest::Valid, usb::classifyRadioFaultStatusRequest(command, 3));
  EXPECT_EQ(usb::RadioFaultStatusRequest::InvalidLength, usb::classifyRadioFaultStatusRequest(command, 4));
  EXPECT_EQ(usb::RadioFaultStatusRequest::Other, usb::classifyRadioFaultStatusRequest(nullptr, 3));
  command[0] = 65;
  EXPECT_EQ(usb::RadioFaultStatusRequest::Other, usb::classifyRadioFaultStatusRequest(command, 3));
  command[0] = 66; command[1] = 1;
  EXPECT_EQ(usb::RadioFaultStatusRequest::Other, usb::classifyRadioFaultStatusRequest(command, 3));
}

TEST(OtaRadioFaultAttribution, Exact57ByteReplyIsBoundedPublicAndBigEndianIncludingSignedStatuses) {
  RadioDriverFaultDiagnostic diagnostic;
  diagnostic.healthy = diagnostic.hasFailure = true;
  diagnostic.faultCount = 0x12345678;
  diagnostic.lastFaultCount = 0x90ABCDEF;
  auto& last = diagnostic.last;
  last.origin = RadioDriverFaultOrigin::ActiveProbe;
  last.driverStatus = INT16_MIN;
  last.probeReasons = 0x07;
  last.expectedMode = 2;
  last.statusByte = 0xFF;
  last.deviceErrors = 0x1234;
  last.irqFlags = 0xFEDCBA98;
  last.deviceErrorsStatus = -705;
  last.irqFlagsStatus = INT16_MAX;
  last.statusReadStatus = -1;
  last.softwareStateBefore = 0x03;
  last.softwareStateAfter = 0x13;
  for (uint8_t i = 0; i < diagnostic.kOriginCount; ++i) diagnostic.originCounts[i] = UINT32_MAX - i;
  std::array<uint8_t, MAX_FRAME_SIZE> out;
  out.fill(0xA5);
  ASSERT_EQ(57u, mesh::ota::encodeOtaRadioFaultDiagnostic(out.data(), out.size(), diagnostic));
  const std::array<uint8_t, 57> expected{
      29, 1, 5, 1, 1, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
      5, 0x80, 0, 7, 2, 0xFF, 0x12, 0x34, 0xFE, 0xDC, 0xBA, 0x98,
      0xFD, 0x3F, 0x7F, 0xFF, 0xFF, 0xFF, 3, 0x13,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
      0xFF, 0xFF, 0xFF, 0xFD, 0xFF, 0xFF, 0xFF, 0xFC,
      0xFF, 0xFF, 0xFF, 0xFB, 0xFF, 0xFF, 0xFF, 0xFA};
  EXPECT_TRUE(std::equal(expected.begin(), expected.end(), out.begin()));
  for (size_t i = expected.size(); i < out.size(); ++i) EXPECT_EQ(0xA5, out[i]);
  EXPECT_LE(usb::kRadioFaultStatusReplyBytes, MAX_FRAME_SIZE);
  out.fill(0xA5);
  EXPECT_EQ(0u, mesh::ota::encodeOtaRadioFaultDiagnostic(out.data(), 56, diagnostic));
  for (auto byte : out) EXPECT_EQ(0xA5, byte);
  EXPECT_EQ(0u, mesh::ota::encodeOtaRadioFaultDiagnostic(nullptr, 57, diagnostic));
  EXPECT_EQ(57u, mesh::ota::encodeOtaRadioFaultDiagnostic(out.data(), 57, diagnostic));
}

TEST(OtaRadioFaultAttribution, OptionalGetterIsPassiveAndUnsupportedDoesNotFabricateSuccess) {
  DiagnosticRadio radio;
  radio.latch.recordFailure(RadioDriverFaultOrigin::ReceiveRearm, -706, 0, 0);
  radio.latch.recordOutcome(true);
  uint8_t reply[57];
  size_t length = 999;
  const mesh::Radio* base = &radio;
  EXPECT_EQ(mesh::ota::OtaRadioFaultReplyResult::Ok,
            mesh::ota::readOtaRadioFaultDiagnostic(base, reply, sizeof(reply), length));
  EXPECT_EQ(57u, length);
  EXPECT_EQ(1u, radio.getters);
  EXPECT_EQ(0u, radio.probes);
  EXPECT_EQ(1, reply[3]);
  EXPECT_EQ(1, reply[4]);
  EXPECT_EQ(3, reply[13]);
  EXPECT_EQ(1u, radio.latch.faultCount());
  EXPECT_EQ(-706, snapshot(radio.latch).last.driverStatus);
  UnsupportedRadio unsupported;
  base = &unsupported;
  EXPECT_EQ(mesh::ota::OtaRadioFaultReplyResult::Unsupported,
            mesh::ota::readOtaRadioFaultDiagnostic(base, reply, sizeof(reply), length));
  EXPECT_EQ(0u, length);
  base = nullptr;
  EXPECT_EQ(mesh::ota::OtaRadioFaultReplyResult::Unsupported,
            mesh::ota::readOtaRadioFaultDiagnostic(base, reply, sizeof(reply), length));
  EXPECT_EQ(0u, length);
  base = &radio;
  EXPECT_EQ(mesh::ota::OtaRadioFaultReplyResult::BadState,
            mesh::ota::readOtaRadioFaultDiagnostic(base, reply, 56, length));
  EXPECT_EQ(0u, length);
  EXPECT_EQ(0u, radio.probes);
}

TEST(OtaRadioFaultAttribution, ExistingAsciiRadioAndBudgetResponsesStayByteCompatible) {
  mesh::ota::OtaRadioMeasurement measurement;
  measurement.observeApply(true, {907525, 250000, 7, 5}, false, 100);
  char reply[176];
  ASSERT_TRUE(measurement.format(reply, sizeof(reply), false, 0, true, 53, 100));
  EXPECT_STREQ("src=driver-applied f=907525 b=250000 s=7 c=5 v=1 a=0 e=00000000 d=00000000"
      " r=00000000 td=00000000 tr=00000000 h=1 x=00000035 af=00000000 n=00000064", reply);
  ASSERT_TRUE(mesh::ota::formatOtaBudgetMeasurement(reply, sizeof(reply), 101, 3600000, 72000,
                                                  72000, 73000, 0, 0));
  EXPECT_STREQ("n=00000065 w=0036EE80 b=00011940 u=00011940 tx=00011D28 to=00000000 af=00000000", reply);
}

TEST(OtaRadioFaultAttribution, ProductWiringKeepsThreeExistingReadsAndAllFourOperationSites) {
  const auto probe = source("src/helpers/radiolib/CustomSX1262Wrapper.h");
  EXPECT_EQ(1u, occurrences(probe, "r.device_errors_status = sx->getDeviceErrorsChecked(&r.device_errors);"));
  EXPECT_EQ(1u, occurrences(probe, "r.irq_flags_status = sx->getIrqFlagsChecked(&r.irq_flags);"));
  EXPECT_EQ(1u, occurrences(probe, "r.status_read_status = sx->getStatusChecked(&r.status_byte);"));
  EXPECT_EQ(3u, occurrences(probe, "= sx->"));
  EXPECT_EQ(1u, occurrences(probe, "recordSx1262CheckedProbeOutcome(_driver_health, r, expected, software_before, driverSoftwareState());"));
  const auto wrapper = source("src/helpers/radiolib/RadioLibWrappers.cpp");
  for (const char* origin : {"StartReceive", "ReadData", "ReceiveRearm", "StartTransmit"})
    EXPECT_EQ(1u, occurrences(wrapper, std::string("_driver_health.recordFailure(mesh::RadioDriverFaultOrigin::") +
        origin + ", err, software_before, state);"));
  EXPECT_EQ(2u, occurrences(wrapper, "int err = _radio->startReceive();"));
  EXPECT_EQ(1u, occurrences(wrapper, "int err = _radio->readData(bytes, len);"));
  EXPECT_EQ(1u, occurrences(wrapper, "int err = _radio->startTransmit((uint8_t *) bytes, len);"));
  EXPECT_EQ(1u, occurrences(wrapper, "radiolib_health::isGenuineRadioDriverFault(err)"));
  const auto usb_handler = source("examples/companion_radio/MyMesh.cpp");
  EXPECT_EQ(1u, occurrences(usb_handler, "mesh::ota::usb::classifyRadioFaultStatusRequest(cmd_frame, len)"));
  EXPECT_NE(std::string::npos, usb_handler.find("OtaRadioFaultReplyResult::Unsupported)\n            writeErrFrame(ERR_CODE_UNSUPPORTED_CMD);"));
  EXPECT_NE(std::string::npos, usb_handler.find("OtaRadioFaultReplyResult::BadState)\n            writeErrFrame(ERR_CODE_BAD_STATE);"));
  EXPECT_NE(std::string::npos, usb_handler.find("if (len == 3 && (cmd_frame[2] == 3 || cmd_frame[2] == 4))"));
  EXPECT_NE(std::string::npos, usb_handler.find("if (len == 3 && (cmd_frame[2] == 1 || cmd_frame[2] == 2))"));
  EXPECT_NE(std::string::npos, usb_handler.find("formatFirmwareOtaStatus((char*)&out_frame[i], sizeof(out_frame) - i);"));
}
