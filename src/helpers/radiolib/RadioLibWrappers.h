#pragma once

#include <Mesh.h>
#include <RadioLib.h>
#include <helpers/radiolib/RadioDriverHealthLatch.h>

#ifdef USE_CC310_HW_CRYPTO
#include <Adafruit_nRFCrypto.h>
#endif
struct PacketMillis {
  uint32_t preambleMillis;  // preamble-detect -> header-valid deadline
  uint32_t payloadMillis;   // header-valid   -> rx-done deadline
};

class RadioLibWrapper : public mesh::Radio {
protected:
  PhysicalLayer* _radio;
  mesh::MainBoard* _board;
  uint32_t n_recv, n_sent, n_recv_errors;
  int16_t _noise_floor, _threshold;
  bool _cad_enabled;
  uint16_t _num_floor_samples;
  int32_t _floor_sample_sum;
  uint8_t _preamble_sf;

  // Latched by the actual return status of a real startReceive()/
  // readData()/startTransmit() driver call (see .cpp) -- true means the
  // driver just reported a genuine failure on ordinary traffic, not a
  // fabricated probe. Cleared back to false the next time one of those
  // same real operations succeeds. Defaults to healthy so a device that
  // has not yet performed any radio operation is not reported unhealthy.
  // The decision logic itself lives in RadioDriverHealthLatch (plain
  // C++, no RadioLib/Arduino dependency) specifically so it can be
  // exercised by real native host unit tests -- see that header.
  RadioDriverHealthLatch _driver_health;

  void idle();
  void startRecv();
  uint8_t driverSoftwareState() const;
  bool transmitCompletionPending() const;
  float packetScoreInt(float snr, int sf, int packet_len);
  virtual bool isReceivingPacket() =0;
  virtual void doResetAGC();

public:
  RadioLibWrapper(PhysicalLayer& radio, mesh::MainBoard& board) : _radio(&radio), _board(&board), _preamble_sf(0) { n_recv = n_sent = 0; }

  void begin() override;
  virtual void powerOff() { _radio->sleep(); }
  int recvRaw(uint8_t* bytes, int sz) override;
  uint32_t getEstAirtimeFor(int len_bytes) override;
  bool startSendRaw(const uint8_t* bytes, int len) override;
  bool isSendComplete() override;
  void onSendFinished() override;
  bool isInRecvMode() const override;
  // True iff the driver's own internal state currently reflects an
  // in-flight, not-yet-complete transmit (STATE_TX_WAIT, set by
  // startSendRaw() and cleared by isSendComplete()/onSendFinished()) --
  // the SAME real state isInRecvMode() already exposes, just for the
  // complementary Tx case. Used by CustomSX1262Wrapper::probeDriverStatus()
  // to tell the checked chip-mode probe what software currently expects
  // the radio to be doing, without any extra/duplicate state tracking.
  bool isTransmitPending() const;
  bool isChannelActive();

  /**
   * \brief  true unless the most recent genuine startReceive()/readData()/
   *         startTransmit() driver call actually returned a non-success
   *         status. Latched by real, already-happening radio operations
   *         (never a synthetic extra query); cleared back to healthy by
   *         the next one of those operations that succeeds. See
   *         `_driver_op_failed`.
  */
  bool isDriverHealthy() const override { return _driver_health.healthy(); }

  uint32_t driverFaultCount() const override { return _driver_health.faultCount(); }

  bool getDriverFaultDiagnostic(mesh::RadioDriverFaultDiagnostic& out) const override {
    _driver_health.getDiagnostic(out);
    return true;
  }

  // No chip-agnostic active probe exists at this generic RadioLib-wrapper
  // level (only the concrete chip-specific subclass, e.g.
  // CustomSX1262Wrapper, knows a real hardware status/error-flag read) --
  // pass through to the existing passive/reactive signal unchanged.
  bool probeDriverStatus() override { return isDriverHealthy(); }

  bool isReceiving() override {
    if (isReceivingPacket()) return true;

    return isChannelActive();
  }

  virtual void setParams(float freq, float bw, uint8_t sf, uint8_t cr) = 0;
  uint32_t getRngSeed();
  void setTxPower(int8_t dbm);

  virtual float getCurrentRSSI() =0;
  virtual uint8_t getSpreadingFactor() const { return LORA_SF; }
  static uint16_t preambleLengthForSF(uint8_t sf) { return sf <= 8 ? 32 : 16; }
  void updatePreamble(uint8_t sf) { _preamble_sf = sf; _radio->setPreambleLength(preambleLengthForSF(sf)); }
  PacketMillis calcMaxPacketMillis(uint8_t sf, float bw, uint8_t cr, uint8_t preambleSymbols);
  virtual int16_t performChannelScan();

  int getNoiseFloor() const override { return _noise_floor; }
  void triggerNoiseFloorCalibrate(int threshold) override;
  void setCADEnabled(bool enable) override { _cad_enabled = enable; }
  void resetAGC() override;

  void loop() override;

  uint32_t getPacketsRecv() const { return n_recv; }
  uint32_t getPacketsRecvErrors() const { return n_recv_errors; }
  uint32_t getPacketsSent() const { return n_sent; }
  void resetStats() { n_recv = n_sent = n_recv_errors = 0; }

  virtual float getLastRSSI() const override;
  virtual float getLastSNR() const override;

  float packetScore(float snr, int packet_len) override { return packetScoreInt(snr, 10, packet_len); }  // assume sf=10

  virtual bool setRxBoostedGainMode(bool) { return false; }
  virtual bool getRxBoostedGainMode() const { return false; }
  
  virtual bool configSideDetectors(const uint8_t sideDetSFs[], uint8_t num, float bw) { return false; }
};

/**
 * \brief  an RNG impl using the noise from the LoRa radio as entropy.
 *         NOTE: this is VERY SLOW!  Use only for things like creating new LocalIdentity
*/
class RadioNoiseListener : public mesh::RNG {
  PhysicalLayer* _radio;
public:
  RadioNoiseListener(PhysicalLayer& radio): _radio(&radio) { }

  void random(uint8_t* dest, size_t sz) override {
#ifdef USE_CC310_HW_CRYPTO
    nRFCrypto.Random.generate(dest, (uint16_t)sz);
    for (int i = 0; i < sz; i++) {
      dest[i] ^= _radio->randomByte() ^ (::random(0, 256) & 0xFF); // combine with Radio's entropy
    }
#else
    for (int i = 0; i < sz; i++) {
      dest[i] = _radio->randomByte() ^ (::random(0, 256) & 0xFF);
    }
#endif
  }
};
