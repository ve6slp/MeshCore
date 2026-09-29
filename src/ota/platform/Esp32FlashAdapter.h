#pragma once

// ESP32 QSPI/internal-flash adapter for the portable OTA storage stack.
//
// GAP (documented, not papered over): a real binding requires ESP-IDF's
// esp_flash/esp_partition (or a raw spi_flash) driver plus a partition table
// entry describing the candidate/backup/journal regions, none of which are
// wired into this portable module. Until that platform glue is added, every
// I/O operation below deterministically reports FlashStatus::Unsupported.
// This is intentional: we do not provide a success-shaped fallback that
// would silently pretend to write/read flash it never touched.

#include <stdint.h>
#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashTypes.h"

namespace ota {
namespace platform {

class Esp32FlashAdapter : public FlashDevice {
public:
  // `total_size_bytes`/`erase_unit_bytes`/`program_unit_bytes` describe the
  // physical part this adapter is *intended* to drive (e.g. the values from
  // SenseCapQspiLayout, or an ESP32-S3 external QSPI part). Reporting these
  // geometry constants does not require a hardware binding; they are only
  // used by higher layers to size regions/journal slots ahead of a real
  // backend being attached.
  Esp32FlashAdapter(uint32_t total_size_bytes, uint32_t erase_unit_bytes, uint32_t program_unit_bytes)
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

  // True once a real ESP-IDF backend has been compiled in and attached.
  // Always false in this portable module.
  static constexpr bool hasHardwareBackend() { return false; }

private:
  uint32_t total_size_bytes_;
  uint32_t erase_unit_bytes_;
  uint32_t program_unit_bytes_;
};

}  // namespace platform
}  // namespace ota
