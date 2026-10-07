#pragma once

// Portable, platform-independent flash storage primitives used by the LoRa OTA
// storage/trust/boot subsystem. Nothing in this header depends on any vendor
// SDK; concrete adapters (see Esp32FlashAdapter.h / Nrf52FlashAdapter.h) bind
// these interfaces to real hardware.

#include <stdint.h>

namespace ota {
namespace platform {

// Result of any flash operation. Callers MUST treat anything other than
// `Ok` as "the operation may or may not have taken effect" (see FakeNorFlash
// for the fault-injection semantics this is designed around) and re-validate
// via readback rather than trusting the return code alone.
enum class FlashStatus : uint8_t {
  Ok = 0,
  InvalidArgument = 1,   // bad offset/length/alignment supplied by the caller
  OutOfRange = 2,        // access falls outside the addressable/region bounds
  Unaligned = 3,         // offset/length not aligned to the required unit
  IoError = 4,           // underlying operation failed (torn write, fault injected, hardware NACK, etc.)
  Unsupported = 5,       // platform adapter has no backend wired up
  PartialProgramViolation = 6, // attempted to set a bit 0->1 without an intervening erase
};

inline bool isOk(FlashStatus status) {
  return status == FlashStatus::Ok;
}

}  // namespace platform
}  // namespace ota
