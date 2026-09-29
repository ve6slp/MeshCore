#pragma once

// Abstract interface to a persistent, monotonically increasing (anti-
// rollback) counter. This is a hard security-relevant primitive: production
// backends must survive power loss/reflash cycles (nRF52 UICR/one-time
// write regions, ESP32 eFuse or NVS-backed anti-rollback counters). No
// production-shaped default implementation is provided here or anywhere in
// this module; see the platform adapters for the concrete (currently
// unsupported/stubbed) hardware bindings and their documented gaps.

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
