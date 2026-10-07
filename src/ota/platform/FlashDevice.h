#pragma once

// Abstract raw NOR-flash-style device interface. A `FlashDevice` represents
// the ENTIRE addressable device (e.g. the whole 2 MiB SenseCAP QSPI part or
// the whole ESP32 internal flash); bounded views into it are obtained via
// `FlashRegion` (see FlashRegion.h) so that higher layers can never address
// outside of their assigned partition.
//
// Implementations MUST honor real NOR flash semantics:
//  - `eraseSector()` sets an entire, aligned `eraseUnitBytes()`-sized sector
//    to the erased value (0xFF per byte).
//  - `program()` may only ever clear bits (1 -> 0); attempting to set a bit
//    from 0 back to 1 without an intervening erase is a programming
//    violation and must be rejected (see FlashStatus::PartialProgramViolation).
//  - `read()` never has side effects on the underlying medium.

#include <stdint.h>
#include "ota/platform/FlashTypes.h"

namespace ota {
namespace platform {

class FlashDevice {
public:
  virtual ~FlashDevice() = default;

  // Total addressable size of the device, in bytes.
  virtual uint32_t totalSizeBytes() const = 0;

  // Minimum erase granularity, in bytes. Erase operations MUST be aligned to
  // this value in both offset and (implicitly) size.
  virtual uint32_t eraseUnitBytes() const = 0;

  // Minimum program granularity, in bytes. 1 means byte-programmable.
  virtual uint32_t programUnitBytes() const = 0;

  // Erases exactly one `eraseUnitBytes()`-aligned sector starting at
  // `offset`. `offset` must be a multiple of `eraseUnitBytes()`.
  virtual FlashStatus eraseSector(uint32_t offset) = 0;

  // Programs `len` bytes at `offset`. `offset` and `len` must be multiples
  // of `programUnitBytes()` for adapters that require it (the portable
  // fake used in tests allows byte granularity).
  virtual FlashStatus program(uint32_t offset, const uint8_t* data, uint32_t len) = 0;

  // Reads `len` bytes starting at `offset` into `data`.
  virtual FlashStatus read(uint32_t offset, uint8_t* data, uint32_t len) const = 0;
};

}  // namespace platform
}  // namespace ota
