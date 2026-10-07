#pragma once

// Simple in-memory MonotonicCounter test double. This is explicitly NOT a
// production implementation (it has no persistence, so it does not actually
// provide anti-rollback protection across a reboot) -- it exists purely so
// DescriptorVerifier tests can exercise the counter-check logic without a
// real platform backend. It performs no cryptographic operation and does
// not claim to.

#include <stdint.h>
#include "ota/trust/MonotonicCounter.h"

namespace ota {
namespace test {

class FakeMonotonicCounter : public trust::MonotonicCounter {
public:
  explicit FakeMonotonicCounter(uint32_t initial_value = 0) : value_(initial_value) {}

  bool currentValue(uint32_t& out) const override {
    if (!available_) {
      return false;
    }
    out = value_;
    return true;
  }

  bool commitNewValue(uint32_t new_value) override {
    if (!available_) {
      return false;
    }
    if (new_value <= value_) {
      return false;
    }
    value_ = new_value;
    return true;
  }

  // Simulates the counter storage becoming unavailable (e.g. hardware
  // fault), forcing callers to fail closed rather than assume 0.
  void setAvailable(bool available) { available_ = available; }

private:
  uint32_t value_;
  bool available_ = true;
};

}  // namespace test
}  // namespace ota
