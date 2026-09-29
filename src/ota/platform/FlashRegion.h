#pragma once

// A `FlashRegion` is a bounds-checked, overflow-safe view onto a slice of a
// `FlashDevice`. All higher-level OTA storage/boot code operates only through
// regions, never against a raw device+offset pair, so that a defect in one
// layer cannot address memory belonging to another partition (candidate vs.
// backup vs. journal vs. filesystem).
//
// Every arithmetic bounds check here is written to avoid unsigned overflow:
// we never compute `offset + len` and then compare against a limit, because
// that addition can itself wrap on 32-bit hardware. Instead we always check
// `len <= (limit - offset)` after first confirming `offset <= limit`.

#include <stdint.h>
#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashTypes.h"

namespace ota {
namespace platform {

class FlashRegion {
public:
  // `device` must outlive this FlashRegion.
  FlashRegion(FlashDevice& device, uint32_t base_offset, uint32_t size_bytes)
      : device_(device), base_offset_(base_offset), size_bytes_(size_bytes) {}

  // Validates that this region is well formed against the underlying
  // device: the base offset does not overflow when added to the size, the
  // region fits entirely within the device, and both base offset and size
  // are aligned to the device's erase unit (required so that callers can
  // always erase whole sectors without touching neighboring partitions).
  bool isValid() const {
    const uint32_t device_total = device_.totalSizeBytes();
    const uint32_t erase_unit = device_.eraseUnitBytes();

    if (erase_unit == 0) {
      return false;
    }
    if (base_offset_ > device_total) {
      return false;
    }
    // Overflow-safe: size_bytes_ must fit in the remaining space after
    // base_offset_, computed as (device_total - base_offset_), which cannot
    // underflow because we just confirmed base_offset_ <= device_total.
    if (size_bytes_ > (device_total - base_offset_)) {
      return false;
    }
    if ((base_offset_ % erase_unit) != 0) {
      return false;
    }
    if ((size_bytes_ % erase_unit) != 0) {
      return false;
    }
    return true;
  }

  uint32_t sizeBytes() const { return size_bytes_; }
  uint32_t baseOffset() const { return base_offset_; }
  uint32_t eraseUnitBytes() const { return device_.eraseUnitBytes(); }
  uint32_t programUnitBytes() const { return device_.programUnitBytes(); }

  FlashStatus read(uint32_t region_offset, uint8_t* data, uint32_t len) const {
    uint32_t absolute = 0;
    FlashStatus bounds = computeAbsolute(region_offset, len, absolute);
    if (!isOk(bounds)) {
      return bounds;
    }
    return device_.read(absolute, data, len);
  }

  FlashStatus program(uint32_t region_offset, const uint8_t* data, uint32_t len) {
    uint32_t absolute = 0;
    FlashStatus bounds = computeAbsolute(region_offset, len, absolute);
    if (!isOk(bounds)) {
      return bounds;
    }
    const uint32_t program_unit = device_.programUnitBytes();
    if (program_unit > 1 && ((region_offset % program_unit) != 0 || (len % program_unit) != 0)) {
      return FlashStatus::Unaligned;
    }
    return device_.program(absolute, data, len);
  }

  // Erases exactly one erase-unit-sized sector at `region_offset` (which
  // must be sector-aligned relative to this region's base, and the base
  // itself is guaranteed sector-aligned by isValid()).
  FlashStatus eraseSector(uint32_t region_offset) {
    const uint32_t erase_unit = device_.eraseUnitBytes();
    if (erase_unit == 0) {
      return FlashStatus::InvalidArgument;
    }
    if ((region_offset % erase_unit) != 0) {
      return FlashStatus::Unaligned;
    }
    uint32_t absolute = 0;
    FlashStatus bounds = computeAbsolute(region_offset, erase_unit, absolute);
    if (!isOk(bounds)) {
      return bounds;
    }
    return device_.eraseSector(absolute);
  }

  // Erases every sector covering [region_offset, region_offset+len). `len`
  // must be a multiple of the erase unit.
  FlashStatus eraseRange(uint32_t region_offset, uint32_t len) {
    const uint32_t erase_unit = device_.eraseUnitBytes();
    if (erase_unit == 0 || (len % erase_unit) != 0 || (region_offset % erase_unit) != 0) {
      return FlashStatus::Unaligned;
    }
    uint32_t absolute_check = 0;
    FlashStatus bounds = computeAbsolute(region_offset, len, absolute_check);
    if (!isOk(bounds)) {
      return bounds;
    }
    for (uint32_t done = 0; done < len; done += erase_unit) {
      FlashStatus status = eraseSector(region_offset + done);
      if (!isOk(status)) {
        return status;
      }
    }
    return FlashStatus::Ok;
  }

private:
  // Overflow-safe absolute-address computation: validates
  // `region_offset + len <= size_bytes_` without ever forming the
  // (possibly overflowing) sum `region_offset + len`, then adds the
  // (already overflow-checked) base offset.
  FlashStatus computeAbsolute(uint32_t region_offset, uint32_t len, uint32_t& absolute_out) const {
    if (region_offset > size_bytes_) {
      return FlashStatus::OutOfRange;
    }
    if (len > (size_bytes_ - region_offset)) {
      return FlashStatus::OutOfRange;
    }
    // base_offset_ + region_offset cannot overflow uint32_t here because
    // isValid() guarantees base_offset_ + size_bytes_ <= device_total, and
    // region_offset <= size_bytes_ was just checked above, so the sum is
    // bounded by device_total which itself fits in uint32_t.
    absolute_out = base_offset_ + region_offset;
    return FlashStatus::Ok;
  }

  FlashDevice& device_;
  uint32_t base_offset_;
  uint32_t size_bytes_;
};

}  // namespace platform
}  // namespace ota
