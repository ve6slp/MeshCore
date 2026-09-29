#pragma once

// Deterministic in-memory fake NOR flash used across the OTA storage/trust/
// boot test suites. It faithfully models the physical constraints that make
// power-loss-safe flash storage hard:
//
//  - Erased bytes read as 0xFF; only eraseSector() can set bits 0 -> 1, and
//    only for a whole, aligned erase-unit-sized sector.
//  - program() can only clear bits (1 -> 0). Attempting to set an already-
//    programmed bit back to 1 without an intervening erase is rejected as
//    FlashStatus::PartialProgramViolation and the buffer is left untouched.
//  - Fault injection lets a test simulate a reset/power-loss at any of the
//    following boundaries, for the Nth operation of a given kind:
//      * before an erase/program/read is applied at all (op has no effect)
//      * mid-way through an erase or program (only part of the sector/bytes
//        actually changes -- a torn write/interrupted erase)
//      * after an erase/program/read fully completes, but the fake still
//        reports IoError to the caller (models the case where the physical
//        write succeeded but the MCU lost power/reset before recording
//        success -- callers must not trust a report of success OR failure
//        without readback verification).

#include <stdint.h>
#include <vector>
#include <cstring>

#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashTypes.h"

namespace ota {
namespace test {

class FakeNorFlash : public ota::platform::FlashDevice {
public:
  enum class OpKind : uint8_t { Erase, Program, Read };
  enum class InjectionTiming : uint8_t {
    None,
    Before,   // operation has no effect at all, returns IoError
    Mid,      // operation partially applies (partial_bytes), returns IoError
    After,    // operation fully applies, but still returns IoError
  };

  struct FaultSpec {
    OpKind kind = OpKind::Program;
    InjectionTiming timing = InjectionTiming::None;
    uint32_t trigger_op_count = 1;  // 1-based: fires on the Nth operation of `kind`
    uint32_t partial_bytes = 0;     // only meaningful for InjectionTiming::Mid
  };

  FakeNorFlash(uint32_t total_size_bytes, uint32_t erase_unit_bytes, uint32_t program_unit_bytes = 1)
      : total_size_bytes_(total_size_bytes),
        erase_unit_bytes_(erase_unit_bytes),
        program_unit_bytes_(program_unit_bytes),
        buffer_(total_size_bytes, 0xFFu) {}

  uint32_t totalSizeBytes() const override { return total_size_bytes_; }
  uint32_t eraseUnitBytes() const override { return erase_unit_bytes_; }
  uint32_t programUnitBytes() const override { return program_unit_bytes_; }

  // --- Fault injection controls -------------------------------------------

  void armFault(const FaultSpec& spec) {
    fault_ = spec;
    fault_armed_ = true;
  }

  void clearFault() {
    fault_armed_ = false;
    fault_ = FaultSpec();
  }

  uint32_t eraseOpCount() const { return erase_op_count_; }
  uint32_t programOpCount() const { return program_op_count_; }
  uint32_t readOpCount() const { return read_op_count_; }

  // Direct, no-fault-injected inspection of the underlying medium, for test
  // assertions about exactly what bytes ended up on "flash" after a
  // simulated crash.
  const uint8_t* rawBuffer() const { return buffer_.data(); }
  uint32_t rawSize() const { return (uint32_t)buffer_.size(); }

  // --- FlashDevice ----------------------------------------------------------

  ota::platform::FlashStatus eraseSector(uint32_t offset) override {
    ++erase_op_count_;
    if (erase_unit_bytes_ == 0 || (offset % erase_unit_bytes_) != 0) {
      return ota::platform::FlashStatus::Unaligned;
    }
    if (offset >= total_size_bytes_ || erase_unit_bytes_ > (total_size_bytes_ - offset)) {
      return ota::platform::FlashStatus::OutOfRange;
    }

    if (matchesFault(OpKind::Erase, erase_op_count_)) {
      if (fault_.timing == InjectionTiming::Before) {
        return ota::platform::FlashStatus::IoError;
      }
      if (fault_.timing == InjectionTiming::Mid) {
        const uint32_t n = fault_.partial_bytes > erase_unit_bytes_ ? erase_unit_bytes_ : fault_.partial_bytes;
        for (uint32_t i = 0; i < n; ++i) {
          buffer_[offset + i] = 0xFFu;
        }
        return ota::platform::FlashStatus::IoError;
      }
      // After: falls through to a full, real erase, then reports IoError below.
    }

    for (uint32_t i = 0; i < erase_unit_bytes_; ++i) {
      buffer_[offset + i] = 0xFFu;
    }

    if (matchesFault(OpKind::Erase, erase_op_count_) && fault_.timing == InjectionTiming::After) {
      return ota::platform::FlashStatus::IoError;
    }
    return ota::platform::FlashStatus::Ok;
  }

  ota::platform::FlashStatus program(uint32_t offset, const uint8_t* data, uint32_t len) override {
    ++program_op_count_;
    if (data == nullptr && len > 0) {
      return ota::platform::FlashStatus::InvalidArgument;
    }
    if (offset > total_size_bytes_ || len > (total_size_bytes_ - offset)) {
      return ota::platform::FlashStatus::OutOfRange;
    }
    if (program_unit_bytes_ > 1 && ((offset % program_unit_bytes_) != 0 || (len % program_unit_bytes_) != 0)) {
      return ota::platform::FlashStatus::Unaligned;
    }

    // Enforce the physical 1->0-only programming constraint before making
    // any change: real NOR flash simply ANDs the new value in (it cannot
    // set a bit back to 1), so if the caller's intended bytes require a
    // bit to go 0->1 without an erase, that is a caller bug we surface
    // rather than silently mask.
    for (uint32_t i = 0; i < len; ++i) {
      const uint8_t existing = buffer_[offset + i];
      const uint8_t incoming = data[i];
      if ((existing & incoming) != incoming) {
        return ota::platform::FlashStatus::PartialProgramViolation;
      }
    }

    if (matchesFault(OpKind::Program, program_op_count_)) {
      if (fault_.timing == InjectionTiming::Before) {
        return ota::platform::FlashStatus::IoError;
      }
      if (fault_.timing == InjectionTiming::Mid) {
        const uint32_t n = fault_.partial_bytes > len ? len : fault_.partial_bytes;
        for (uint32_t i = 0; i < n; ++i) {
          buffer_[offset + i] &= data[i];
        }
        return ota::platform::FlashStatus::IoError;
      }
    }

    for (uint32_t i = 0; i < len; ++i) {
      buffer_[offset + i] &= data[i];
    }

    if (matchesFault(OpKind::Program, program_op_count_) && fault_.timing == InjectionTiming::After) {
      return ota::platform::FlashStatus::IoError;
    }
    return ota::platform::FlashStatus::Ok;
  }

  ota::platform::FlashStatus read(uint32_t offset, uint8_t* data, uint32_t len) const override {
    ++read_op_count_;
    if (data == nullptr && len > 0) {
      return ota::platform::FlashStatus::InvalidArgument;
    }
    if (offset > total_size_bytes_ || len > (total_size_bytes_ - offset)) {
      return ota::platform::FlashStatus::OutOfRange;
    }

    if (matchesFault(OpKind::Read, read_op_count_) && fault_.timing == InjectionTiming::Before) {
      return ota::platform::FlashStatus::IoError;
    }

    std::memcpy(data, buffer_.data() + offset, len);

    if (matchesFault(OpKind::Read, read_op_count_) && fault_.timing == InjectionTiming::After) {
      return ota::platform::FlashStatus::IoError;
    }
    return ota::platform::FlashStatus::Ok;
  }

private:
  bool matchesFault(OpKind kind, uint32_t op_count) const {
    return fault_armed_ && fault_.kind == kind && fault_.timing != InjectionTiming::None &&
           fault_.trigger_op_count == op_count;
  }

  uint32_t total_size_bytes_;
  uint32_t erase_unit_bytes_;
  uint32_t program_unit_bytes_;
  std::vector<uint8_t> buffer_;

  bool fault_armed_ = false;
  FaultSpec fault_;

  uint32_t erase_op_count_ = 0;
  uint32_t program_op_count_ = 0;
  mutable uint32_t read_op_count_ = 0;
};

}  // namespace test
}  // namespace ota
