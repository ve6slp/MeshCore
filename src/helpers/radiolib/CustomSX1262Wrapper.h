#pragma once

#include "CustomSX1262.h"
#include "RadioLibWrappers.h"
#include "SX126xReset.h"
#include "Sx1262CheckedProbe.h"

#ifndef USE_SX1262
#define USE_SX1262
#endif

class CustomSX1262Wrapper : public RadioLibWrapper {
public:
  CustomSX1262Wrapper(CustomSX1262& radio, mesh::MainBoard& board) : RadioLibWrapper(radio, board) { }

  void setParams(float freq, float bw, uint8_t sf, uint8_t cr) override {
    ((CustomSX1262 *)_radio)->setFrequency(freq);
    ((CustomSX1262 *)_radio)->setSpreadingFactor(sf);
    ((CustomSX1262 *)_radio)->setBandwidth(bw);
    ((CustomSX1262 *)_radio)->setCodingRate(cr);
    updatePreamble(sf);
    PacketMillis pm = calcMaxPacketMillis(sf, bw, cr, preambleLengthForSF(sf));
    ((CustomSX1262 *)_radio)->setPreambleMillis(pm.preambleMillis);
    ((CustomSX1262 *)_radio)->setMaxPayloadMillis(pm.payloadMillis);
  }

  bool isReceivingPacket() override { 
    return ((CustomSX1262 *)_radio)->isReceiving();
  }
  float getCurrentRSSI() override {
    return ((CustomSX1262 *)_radio)->getRSSI(false);
  }
  float getLastRSSI() const override { return ((CustomSX1262 *)_radio)->getRSSI(); }
  float getLastSNR() const override { return ((CustomSX1262 *)_radio)->getSNR(); }

  float packetScore(float snr, int packet_len) override {
    int sf = ((CustomSX1262 *)_radio)->spreadingFactor;
    return packetScoreInt(snr, sf, packet_len);
  }
  uint8_t getSpreadingFactor() const override { return ((CustomSX1262 *)_radio)->spreadingFactor; }
  virtual void powerOff() override {
    ((CustomSX1262 *)_radio)->sleep(false);
  }

  bool setRxBoostedGainMode(bool en) override {
    return ((CustomSX1262 *)_radio)->setRxBoostedGainMode(en) == RADIOLIB_ERR_NONE;
  }
  bool getRxBoostedGainMode() const override {
    return ((CustomSX1262 *)_radio)->getRxBoostedGainMode();
  }

  void doResetAGC() override { sx126xResetAGC((SX126x *)_radio, getRxBoostedGainMode()); }

  // Genuine, ACTIVE, bounded hardware status probe: performs THREE real,
  // independent, CHECKED SPI register reads right now (device-errors,
  // irq-flags, AND a genuinely-working GET_STATUS read -- see
  // CustomSX1262::getDeviceErrorsChecked()/getIrqFlagsChecked()/
  // getStatusChecked()), instead of only reacting to whichever ordinary
  // send/receive call happens to run next, and instead of trusting
  // RadioLib's own getDeviceErrors()/getStatus(), which either discard
  // the real SPI transaction status or (for getStatus() in this
  // vendored version) never populate their output at all. The decision
  // itself (evaluateSx1262CheckedHealth()) is plain, RadioLib/Arduino-
  // independent C++ specifically so it is natively testable -- see
  // Sx1262CheckedProbe.h. Feeds the verdict into the SAME shared
  // RadioDriverHealthLatch as ordinary op outcomes so this call and
  // ordinary send/receive results cannot disagree about what "healthy"
  // means. Deliberately does NOT call clearDeviceErrors(): that is a
  // separate write/SPI round-trip with a real side effect (resets the
  // chip's hardware error-accumulator), and a read-only probe must not
  // mutate hardware state merely to observe it -- the latch already
  // self-clears back to healthy on the next real successful op, so a
  // single historical error bit cannot wedge this signal permanently.
  //
  // The real chip-mode bits decoded from getStatusChecked() are cross-
  // checked against what software currently expects (isInRecvMode()/
  // isTransmitPending(), the SAME real state ordinary send/receive call
  // sites already maintain) via evaluateSx1262CheckedHealth() -- a
  // genuine disagreement (e.g. the chip reporting neither Rx nor Tx
  // while software believes it is actively receiving, with no IRQ
  // evidence of a just-completed operation) is a real, unhealthy fault,
  // not merely "one error-accumulator register happened to read back as
  // zero".
  bool probeDriverStatus() override {
    auto* sx = (CustomSX1262 *)_radio;
    const uint8_t software_before = driverSoftwareState();
    Sx1262CheckedProbeResult r;
    r.device_errors_status = sx->getDeviceErrorsChecked(&r.device_errors);
    r.irq_flags_status = sx->getIrqFlagsChecked(&r.irq_flags);
    r.status_read_status = sx->getStatusChecked(&r.status_byte);

    Sx1262ExpectedChipMode expected = Sx1262ExpectedChipMode::kIdle;
    if (isInRecvMode()) expected = Sx1262ExpectedChipMode::kReceiving;
    else if (isTransmitPending()) expected = Sx1262ExpectedChipMode::kTransmitting;

    recordSx1262CheckedProbeOutcome(_driver_health, r, expected, software_before, driverSoftwareState());
    return _driver_health.healthy();
  }
};
