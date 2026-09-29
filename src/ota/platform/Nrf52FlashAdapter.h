#pragma once

// nRF52 external QSPI flash adapter for the portable OTA storage stack.
//
// GAP (documented, not papered over): the stock/Adafruit nRF52 bootloader
// does not support booting from or staging through external QSPI flash, so
// even a working nrfx_qspi driver binding here would not be sufficient on
// its own -- a CUSTOM bootloader (with its own trust anchor and copy/verify
// logic mirroring src/ota/boot/BootTransaction) is required to actually
// consume what this adapter would stage. Neither the nrfx_qspi driver glue
// nor the custom bootloader exist in this repository yet. Every I/O
// operation below therefore deterministically reports
// FlashStatus::Unsupported rather than a success-shaped fallback.

#include <stdint.h>
#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashTypes.h"

namespace ota {
namespace platform {

class Nrf52FlashAdapter : public FlashDevice {
public:
  Nrf52FlashAdapter(uint32_t total_size_bytes, uint32_t erase_unit_bytes, uint32_t program_unit_bytes)
      : total_size_bytes_(total_size_bytes),
        erase_unit_bytes_(erase_unit_bytes),
        program_unit_bytes_(program_unit_bytes) {}

  uint32_t totalSizeBytes() const override { return total_size_bytes_; }
  uint32_t eraseUnitBytes() const override { return erase_unit_bytes_; }
  uint32_t programUnitBytes() const override { return program_unit_bytes_; }

  FlashStatus eraseSector(uint32_t /*offset*/) override {
    return FlashStatus::Unsupported;
  }

  FlashStatus program(uint32_t /*offset*/, const uint8_t* /*data*/, uint32_t /*len*/) override {
    return FlashStatus::Unsupported;
  }

  FlashStatus read(uint32_t /*offset*/, uint8_t* /*data*/, uint32_t /*len*/) const override {
    return FlashStatus::Unsupported;
  }

  // True once a real nrfx_qspi backend AND a custom bootloader capable of
  // consuming the staged image both exist. Always false in this portable
  // module.
  static constexpr bool hasHardwareBackend() { return false; }
  static constexpr bool hasCustomBootloader() { return false; }

private:
  uint32_t total_size_bytes_;
  uint32_t erase_unit_bytes_;
  uint32_t program_unit_bytes_;
};

}  // namespace platform
}  // namespace ota
