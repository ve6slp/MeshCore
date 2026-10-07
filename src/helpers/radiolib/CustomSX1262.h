#pragma once

#include <RadioLib.h>
#include "MeshCore.h"
#if MESHCORE_LORA_OTA
#include <helpers/radiolib/Sx126xGetStatusTransaction.h>
#endif

class CustomSX1262 : public SX1262 {
  uint32_t _preambleMillis = 66;
  uint32_t _maxPayloadMillis = 3934;
  uint32_t _activityAt = 0;
  bool _headerSeen = false;

  public:
    CustomSX1262(Module *mod) : SX1262(mod) { }

  #ifdef RP2040_PLATFORM
    bool std_init(SPIClassRP2040* spi = NULL)
  #else
    bool std_init(SPIClass* spi = NULL)
  #endif
    {
  #ifdef SX126X_DIO3_TCXO_VOLTAGE
      float tcxo = SX126X_DIO3_TCXO_VOLTAGE;
  #else
      float tcxo = 1.6f;
  #endif

  #ifdef LORA_CR
      uint8_t cr = LORA_CR;
  #else
      uint8_t cr = 5;
  #endif

  #ifdef SX126X_USE_REGULATOR_LDO
      constexpr bool useRegulatorLDO = SX126X_USE_REGULATOR_LDO;
  #else
      constexpr bool useRegulatorLDO = false;
  #endif

      MESH_DEBUG_PRINTLN("SX1262 regulator requested: %s", useRegulatorLDO ? "LDO" : "DC-DC");

  #if defined(P_LORA_SCLK)
    #ifdef NRF52_PLATFORM
      if (spi) { spi->setPins(P_LORA_MISO, P_LORA_SCLK, P_LORA_MOSI); spi->begin(); }
    #elif defined(RP2040_PLATFORM)
      if (spi) {
        spi->setMISO(P_LORA_MISO);
        //spi->setCS(P_LORA_NSS); // Setting CS results in freeze
        spi->setSCK(P_LORA_SCLK);
        spi->setMOSI(P_LORA_MOSI);
        spi->begin();
      }
    #else
      if (spi) spi->begin(P_LORA_SCLK, P_LORA_MISO, P_LORA_MOSI);
    #endif
  #endif
      int status = begin(LORA_FREQ, LORA_BW, LORA_SF, cr, RADIOLIB_SX126X_SYNC_WORD_PRIVATE, LORA_TX_POWER, 16, tcxo, useRegulatorLDO);
      // if radio init fails with -707/-706, try again with tcxo voltage set to 0.0f
      if (status == RADIOLIB_ERR_SPI_CMD_FAILED || status == RADIOLIB_ERR_SPI_CMD_INVALID) {
        MESH_DEBUG_PRINTLN("SX1262 init failed with error %d, retrying with TCXO at 0.0V", status);
        tcxo = 0.0f;
        status = begin(LORA_FREQ, LORA_BW, LORA_SF, cr, RADIOLIB_SX126X_SYNC_WORD_PRIVATE, LORA_TX_POWER, 16, tcxo, useRegulatorLDO);
      }
      if (status != RADIOLIB_ERR_NONE) {
        Serial.print("ERROR: radio init failed: ");
        Serial.println(status);
        return false;  // fail
      }
    
      setCRC(1);
  
  #ifdef SX126X_CURRENT_LIMIT
      setCurrentLimit(SX126X_CURRENT_LIMIT);
  #endif
  #ifdef SX126X_DIO2_AS_RF_SWITCH
      setDio2AsRfSwitch(SX126X_DIO2_AS_RF_SWITCH);
  #endif
  #ifdef SX126X_RX_BOOSTED_GAIN
      setRxBoostedGainMode(SX126X_RX_BOOSTED_GAIN);
  #endif
  #if defined(SX126X_RXEN) || defined(SX126X_TXEN)
    #ifndef SX126X_RXEN
      #define SX126X_RXEN RADIOLIB_NC
    #endif
    #ifndef SX126X_TXEN
      #define SX126X_TXEN RADIOLIB_NC
    #endif
      setRfSwitchPins(SX126X_RXEN, SX126X_TXEN);
  #endif 

  // for improved RX with Heltec v4
  #ifdef SX126X_REGISTER_PATCH
    uint8_t r_data = 0;
    readRegister(0x8B5, &r_data, 1);
    r_data |= 0x01;
    writeRegister(0x8B5, &r_data, 1);
  #endif

      MESH_DEBUG_PRINTLN("SX1262 status=0x%02X device_errors=0x%04X", getStatus(), getDeviceErrors());

      return true;  // success
    }

    int16_t startReceive() override {
      // include the PREAMBLE_DETECTED irq bit in reported flags
      return SX1262::startReceive(RADIOLIB_SX126X_RX_TIMEOUT_INF, RADIOLIB_IRQ_RX_DEFAULT_FLAGS | (1UL << RADIOLIB_IRQ_PREAMBLE_DETECTED), RADIOLIB_IRQ_RX_DEFAULT_MASK, 0);
    }

    bool isReceiving() {
      uint32_t irq = getIrqFlags();
      bool preamble = irq & RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED; // bit 2
      bool header   = irq & RADIOLIB_SX126X_IRQ_HEADER_VALID;      // bit 4
      bool hdrErr   = irq & RADIOLIB_SX126X_IRQ_HEADER_ERR;        // bit 5
      uint32_t now  = millis();
      if (hdrErr) {
        clearIrqFlags(RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED | RADIOLIB_SX126X_IRQ_HEADER_VALID | RADIOLIB_SX126X_IRQ_HEADER_ERR | RADIOLIB_SX126X_IRQ_SYNC_WORD_VALID);
        _activityAt = 0;
        _headerSeen = false;
        return false;
      }
      if (!header && _headerSeen) {
        // something cleared the header flag, reset our state.
        _activityAt = 0; _headerSeen = false;
        return false;
      }

      if (header) {
        if (!_headerSeen) { _headerSeen = true; _activityAt = now; };
        if (now - _activityAt > _maxPayloadMillis) {
          MESH_DEBUG_PRINTLN("Clearing header IRQ after %ums", _maxPayloadMillis);
          clearIrqFlags(RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED | RADIOLIB_SX126X_IRQ_HEADER_VALID | RADIOLIB_SX126X_IRQ_HEADER_ERR | RADIOLIB_SX126X_IRQ_SYNC_WORD_VALID);
          _activityAt = 0; _headerSeen = false;
          return false;
        }
        return true;
      }
      if (preamble) {
        if (_activityAt == 0) _activityAt = now;
        if (now - _activityAt > _preambleMillis) {
          clearIrqFlags(RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED);
          _activityAt = 0;
          MESH_DEBUG_PRINTLN("Clearing preamble IRQ after %ums", _preambleMillis);

          return false;
        }
        return true;
      }
      _activityAt = 0; _headerSeen = false;
      return false;
    }

    void setPreambleMillis(uint32_t preambleMillis) {
      _preambleMillis = preambleMillis;
      MESH_DEBUG_PRINTLN("Set _preambleMillis=%u", _preambleMillis);
    }
    void setMaxPayloadMillis(uint32_t payloadMillis) {
      _maxPayloadMillis = payloadMillis;
      MESH_DEBUG_PRINTLN("Set _maxPayloadMillis=%u", _maxPayloadMillis);
    }

    bool getRxBoostedGainMode() {
      uint8_t rxGain = 0;
      readRegister(RADIOLIB_SX126X_REG_RX_GAIN, &rxGain, 1);
      return (rxGain == RADIOLIB_SX126X_RX_GAIN_BOOSTED);
    }

#if MESHCORE_LORA_OTA
    /**
     * \brief  Genuine, CHECKED replica of SX126x::getDeviceErrors(): unlike
     *         the base RadioLib implementation (which calls
     *         `mod->SPIreadStream()` but completely discards its returned
     *         int16_t status, then unconditionally decodes whatever bytes
     *         are left in the buffer), this surfaces the REAL underlying
     *         SPI transaction status so a genuinely failed transfer (bus
     *         fault, GPIO/busy timeout, ...) is never silently mistaken
     *         for "zero errors" success just because the untouched buffer
     *         still reads back as zero.
     * \param  out_errors OUT - decoded device-error bits; ONLY meaningful
     *                    when the returned status == RADIOLIB_ERR_NONE.
     * \returns  the real RadioLib SPI transaction status.
    */
    int16_t getDeviceErrorsChecked(uint16_t* out_errors) {
      // Poisoned (non-zero, NOT the success-shaped {0,0}) default: if the
      // SPI transaction genuinely fails before ever touching the buffer,
      // the decoded value must not accidentally look like "zero errors".
      uint8_t data[2] = { 0xFF, 0xFF };
      int16_t status = mod->SPIreadStream(RADIOLIB_SX126X_CMD_GET_DEVICE_ERRORS, data, 2);
      *out_errors = (((uint16_t)data[0] & 0xFF) << 8) | (uint16_t)data[1];
      return status;
    }

    /**
     * \brief  Genuine, CHECKED replica of SX126x::getIrqFlags(): a SECOND,
     *         independent real SPI register read (distinct command/
     *         register from getDeviceErrorsChecked() above) that also
     *         surfaces its actual transaction status instead of
     *         discarding it -- so a driver-health probe can require TWO
     *         genuinely-successful, independent hardware SPI round trips
     *         before reporting healthy, not merely "one error-accumulator
     *         register happened to read back as zero".
     * \param  out_flags OUT - decoded IRQ status bits; ONLY meaningful
     *                   when the returned status == RADIOLIB_ERR_NONE.
     * \returns  the real RadioLib SPI transaction status.
    */
    int16_t getIrqFlagsChecked(uint32_t* out_flags) {
      uint8_t data[2] = { 0xFF, 0xFF };  // poisoned, same rationale as above.
      int16_t status = mod->SPIreadStream(RADIOLIB_SX126X_CMD_GET_IRQ_STATUS, data, 2);
      *out_flags = (((uint32_t)data[0]) << 8) | (uint32_t)data[1];
      return status;
    }

    /**
     * \brief  Genuine, CHECKED replica of SX126x::getStatus(): the base
     *         RadioLib implementation calls
     *         `mod->SPIreadStream(RADIOLIB_SX126X_CMD_GET_STATUS, &data, 0)`
     *         -- numBytes==0 -- and Module::SPItransferStream() gates
     *         BOTH its real-status parsing (`numBytes > 0`) AND its
     *         data-copy-out (`memcpy(dataIn, ..., numBytes)`) on that
     *         same numBytes, so with numBytes==0 `data` is structurally
     *         NEVER written to and the transaction's status is never
     *         parsed either -- base getStatus() cannot provide real
     *         chip-mode evidence at all in this vendored version.
     *
     *         This performs the IDENTICAL physical transaction (same
     *         GET_STATUS command byte, same bytes on the wire) but asks
     *         for the status byte as an ordinary 1-byte DATA payload
     *         instead: `mod->spiConfig`'s configured STATUS bit-width is
     *         temporarily zeroed for the duration of this single,
     *         synchronous call only -- so the transfer's automatic
     *         status-byte-count contribution drops out and
     *         cmdLen(1)+numBytes(1) lines up exactly on the real status
     *         byte, at the SAME wire position SX126x::SPIparseStatus()/
     *         `statusPos==1` already expect -- then immediately restored,
     *         even if the transfer itself failed, before returning.
     *         `mod->spiConfig` is shared, single-threaded main-loop
     *         state (this firmware never calls into the radio driver
     *         from an ISR, and never re-enters it); the mutation window
     *         is bounded to this one call's owning thread -- no OTHER
     *         caller can begin a second, concurrent SPI transaction
     *         while this one is in flight, even though the underlying
     *         HAL may internally spin/yield while waiting for it to
     *         complete -- so no other SPI caller can ever observe the
     *         transiently-zeroed width.
     * \param  out_status OUT - the real, decoded status byte (chip mode
     *                    in bits 6:4, command status in bits 3:1); ONLY
     *                    meaningful when the returned status ==
     *                    RADIOLIB_ERR_NONE.
     * \returns  the real RadioLib SPI transaction status, as genuinely
     *           parsed by SX126x::SPIparseStatus() from that same byte
     *           (so a 0x00/0xFF "chip not found" byte, or a byte
     *           indicating a timed-out/invalid/failed SPI command, is
     *           already reported as a non-success status here, not left
     *           for the caller to separately decode).
     *
     *         The actual scoped-width-trick transaction is implemented
     *         ONCE, module-type-agnostically, in
     *         Sx126xGetStatusTransaction.h's
     *         performSx126xGetStatusTransaction() -- this method is a
     *         thin, real-RadioLib-Module-typed instantiation of it, so
     *         the SAME transaction logic (not a second reimplementation)
     *         is exercised by native host unit tests against a plain
     *         FakeModule double.
    */
    int16_t getStatusChecked(uint8_t* out_status) {
      return performSx126xGetStatusTransaction(mod, (uint16_t)RADIOLIB_SX126X_CMD_GET_STATUS,
                                                out_status, Module::BITS_0);
    }
#endif
};
