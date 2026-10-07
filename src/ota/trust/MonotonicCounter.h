#pragma once

// Abstract interface to a persistent, monotonically increasing (anti-
// rollback) counter. Production backends must survive power loss: nRF52
// reads the bootloader-owned QSPI floor and ESP32 uses durable NVS state.
// No permissive default implementation is provided.

#include <stdint.h>

namespace ota {
namespace trust {

class MonotonicCounter {
public:
  virtual ~MonotonicCounter() = default;

  // Reads the current committed counter value into `out`. Returns false if
  // the counter storage is unavailable (callers MUST treat that as "cannot
  // verify anti-rollback" and fail closed, not as "counter is 0").
  virtual bool currentValue(uint32_t& out) const = 0;

  // Durably commits `new_value` as the new counter floor. Implementations
  // MUST reject (return false, and MUST NOT partially persist) any
  // `new_value` that is not strictly greater than the current committed
  // value.
  virtual bool commitNewValue(uint32_t new_value) = 0;
};

}  // namespace trust
}  // namespace ota
