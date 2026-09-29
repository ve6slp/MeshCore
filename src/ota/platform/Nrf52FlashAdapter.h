#pragma once

#include <stdint.h>
#include <string.h>

#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashTypes.h"

#if defined(NRF52840_XXAA)
#include <Arduino.h>
#include <nrfx_qspi.h>
#include <nrf_qspi.h>
#include <variant.h>
#endif

namespace ota {
namespace platform {

class Nrf52FlashAdapter : public FlashDevice {
public:
  static constexpr uint32_t kDefaultTotalBytes = 2u * 1024u * 1024u;
  static constexpr uint32_t kDefaultEraseBytes = 4096u;
  static constexpr uint32_t kDefaultPageBytes = 256u;

  Nrf52FlashAdapter(uint32_t total_size_bytes = kDefaultTotalBytes,
                    uint32_t erase_unit_bytes = kDefaultEraseBytes,
                    uint32_t program_unit_bytes = 1u)
      : total_size_bytes_(total_size_bytes),
        erase_unit_bytes_(erase_unit_bytes),
        program_unit_bytes_(program_unit_bytes) {}

  FlashStatus begin() {
#if defined(NRF52840_XXAA)
    if (initialized_) {
      return FlashStatus::Ok;
    }
    if (total_size_bytes_ == 0 || erase_unit_bytes_ == 0 || program_unit_bytes_ == 0) {
      return FlashStatus::InvalidArgument;
    }

    nrfx_qspi_config_t config;
    memset(&config, 0, sizeof(config));
    config.xip_offset = 0;
    config.pins.sck_pin = g_ADigitalPinMap[PIN_QSPI_SCK];
    config.pins.csn_pin = g_ADigitalPinMap[PIN_QSPI_CS];
    config.pins.io0_pin = g_ADigitalPinMap[PIN_QSPI_IO0];
    config.pins.io1_pin = g_ADigitalPinMap[PIN_QSPI_IO1];
    config.pins.io2_pin = g_ADigitalPinMap[PIN_QSPI_IO2];
    config.pins.io3_pin = g_ADigitalPinMap[PIN_QSPI_IO3];
    config.prot_if.readoc = NRF_QSPI_READOC_FASTREAD;
    config.prot_if.writeoc = NRF_QSPI_WRITEOC_PP;
    config.prot_if.addrmode = NRF_QSPI_ADDRMODE_24BIT;
    config.phy_if.sck_freq = NRF_QSPI_FREQ_32MDIV2;
    config.phy_if.spi_mode = NRF_QSPI_MODE_0;
    config.phy_if.dpmen = false;
    config.prot_if.dpmconfig = false;
    config.irq_priority = 2;

    const nrfx_err_t init_result = nrfx_qspi_init(&config, qspiEventHandler, this);
    if (init_result != NRFX_SUCCESS) {
      return FlashStatus::IoError;
    }
    initialized_ = true;

    uint8_t id[3] = {0, 0, 0};
    const FlashStatus id_status = readJedecId(id);
    if (!isOk(id_status) || id[0] == 0x00 || id[0] == 0xFF ||
        id[1] == 0x00 || id[1] == 0xFF || id[2] == 0x00 || id[2] == 0xFF) {
      nrfx_qspi_uninit();
      initialized_ = false;
      return isOk(id_status) ? FlashStatus::IoError : id_status;
    }
    memcpy(jedec_id_, id, sizeof(jedec_id_));
    return FlashStatus::Ok;
#else
    return FlashStatus::Unsupported;
#endif
  }

  bool isInitialized() const { return initialized_; }

  FlashStatus readJedecId(uint8_t out[3]) const {
    if (out == nullptr) {
      return FlashStatus::InvalidArgument;
    }
#if defined(NRF52840_XXAA)
    if (!initialized_) {
      return FlashStatus::Unsupported;
    }
    nrf_qspi_cinstr_conf_t instruction =
        NRFX_QSPI_DEFAULT_CINSTR(0x9Fu, NRF_QSPI_CINSTR_LEN_4B);
    instruction.io2_level = true;
    instruction.io3_level = true;
    const nrfx_err_t result = nrfx_qspi_cinstr_xfer(&instruction, nullptr, out);
    return result == NRFX_SUCCESS ? FlashStatus::Ok : FlashStatus::IoError;
#else
    (void)out;
    return FlashStatus::Unsupported;
#endif
  }

  const uint8_t* jedecId() const { return jedec_id_; }

  FlashStatus readStatusRegister(uint8_t opcode, uint8_t& value) const {
#if defined(NRF52840_XXAA)
    if (!initialized_) {
      return FlashStatus::Unsupported;
    }
    nrf_qspi_cinstr_conf_t instruction =
        NRFX_QSPI_DEFAULT_CINSTR(opcode, NRF_QSPI_CINSTR_LEN_2B);
    instruction.io2_level = true;
    instruction.io3_level = true;
    return nrfx_qspi_cinstr_xfer(&instruction, nullptr, &value) == NRFX_SUCCESS
        ? FlashStatus::Ok
        : FlashStatus::IoError;
#else
    (void)opcode;
    (void)value;
    return FlashStatus::Unsupported;
#endif
  }

  uint32_t totalSizeBytes() const override { return total_size_bytes_; }
  uint32_t eraseUnitBytes() const override { return erase_unit_bytes_; }
  uint32_t programUnitBytes() const override { return program_unit_bytes_; }

  FlashStatus eraseSector(uint32_t offset) override {
#if defined(NRF52840_XXAA)
    if (!initialized_) {
      return FlashStatus::Unsupported;
    }
    if ((offset % erase_unit_bytes_) != 0) {
      return FlashStatus::Unaligned;
    }
    if (!rangeFits(offset, erase_unit_bytes_)) {
      return FlashStatus::OutOfRange;
    }
    operation_complete_ = false;
    const nrfx_err_t result = nrfx_qspi_erase(NRF_QSPI_ERASE_LEN_4KB, offset);
    if (result != NRFX_SUCCESS) {
      return FlashStatus::IoError;
    }
    return waitForOperation(30000u);
#else
    (void)offset;
    return FlashStatus::Unsupported;
#endif
  }

  FlashStatus program(uint32_t offset, const uint8_t* data, uint32_t len) override {
    if (len == 0) {
      return FlashStatus::Ok;
    }
    if (data == nullptr) {
      return FlashStatus::InvalidArgument;
    }
    if ((offset % program_unit_bytes_) != 0 || (len % program_unit_bytes_) != 0) {
      return FlashStatus::Unaligned;
    }
    if (!rangeFits(offset, len)) {
      return FlashStatus::OutOfRange;
    }
#if defined(NRF52840_XXAA)
    if (!initialized_) {
      return FlashStatus::Unsupported;
    }

    uint32_t done = 0;
    while (done < len) {
      const uint32_t absolute = offset + done;
      const uint32_t page_remaining = kDefaultPageBytes - (absolute % kDefaultPageBytes);
      const uint32_t aligned_start = absolute & ~3u;
      const uint32_t leading = absolute - aligned_start;
      uint32_t step = len - done;
      if (step > page_remaining) step = page_remaining;
      if (step > (sizeof(scratch_) - leading)) step = sizeof(scratch_) - leading;
      const uint32_t aligned_len = (leading + step + 3u) & ~3u;

      if (!isOk(readRaw(aligned_start, scratch_, aligned_len))) {
        return FlashStatus::IoError;
      }
      for (uint32_t i = 0; i < step; ++i) {
        if ((scratch_[leading + i] & data[done + i]) != data[done + i]) {
          return FlashStatus::PartialProgramViolation;
        }
      }

      memcpy(scratch_ + leading, data + done, step);
      operation_complete_ = false;
      if (nrfx_qspi_write(scratch_, aligned_len, aligned_start) != NRFX_SUCCESS) {
        return FlashStatus::IoError;
      }
      if (!isOk(waitForOperation(5000u))) {
        return FlashStatus::IoError;
      }
      done += step;
    }
    return FlashStatus::Ok;
#else
    (void)offset;
    (void)data;
    (void)len;
    return FlashStatus::Unsupported;
#endif
  }

  FlashStatus read(uint32_t offset, uint8_t* data, uint32_t len) const override {
    if (len == 0) {
      return FlashStatus::Ok;
    }
    if (data == nullptr) {
      return FlashStatus::InvalidArgument;
    }
    if (!rangeFits(offset, len)) {
      return FlashStatus::OutOfRange;
    }
#if defined(NRF52840_XXAA)
    if (!initialized_) {
      return FlashStatus::Unsupported;
    }

    uint32_t done = 0;
    while (done < len) {
      const uint32_t absolute = offset + done;
      const uint32_t aligned_start = absolute & ~3u;
      const uint32_t leading = absolute - aligned_start;
      uint32_t step = len - done;
      if (step > (sizeof(scratch_) - leading)) step = sizeof(scratch_) - leading;
      const uint32_t aligned_len = (leading + step + 3u) & ~3u;
      const FlashStatus status = readRaw(aligned_start, scratch_, aligned_len);
      if (!isOk(status)) {
        return status;
      }
      memcpy(data + done, scratch_ + leading, step);
      done += step;
    }
    return FlashStatus::Ok;
#else
    (void)offset;
    (void)data;
    (void)len;
    return FlashStatus::Unsupported;
#endif
  }

  static constexpr bool hasHardwareBackend() {
#if defined(NRF52840_XXAA)
    return true;
#else
    return false;
#endif
  }

  static constexpr bool hasCustomBootloader() { return false; }

private:
  bool rangeFits(uint32_t offset, uint32_t len) const {
    return offset <= total_size_bytes_ && len <= (total_size_bytes_ - offset);
  }

#if defined(NRF52840_XXAA)
  FlashStatus readRaw(uint32_t offset, uint8_t* data, uint32_t len) const {
    operation_complete_ = false;
    if (nrfx_qspi_read(data, len, offset) != NRFX_SUCCESS) {
      return FlashStatus::IoError;
    }
    return waitForOperation(5000u);
  }

  static void qspiEventHandler(nrfx_qspi_evt_t event, void* context) {
    if (event == NRFX_QSPI_EVENT_DONE && context != nullptr) {
      static_cast<Nrf52FlashAdapter*>(context)->operation_complete_ = true;
    }
  }

  FlashStatus waitForOperation(uint32_t timeout_ms) const {
    const uint32_t started = millis();
    while (millis() - started < timeout_ms) {
      if (operation_complete_) {
        return FlashStatus::Ok;
      }
      delay(1);
    }
    return FlashStatus::IoError;
  }
#endif

  uint32_t total_size_bytes_;
  uint32_t erase_unit_bytes_;
  uint32_t program_unit_bytes_;
  bool initialized_ = false;
  uint8_t jedec_id_[3] = {0, 0, 0};
  mutable volatile bool operation_complete_ = false;
  alignas(4) mutable uint8_t scratch_[kDefaultPageBytes];
};

}  // namespace platform
}  // namespace ota
