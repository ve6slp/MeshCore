#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>

#if MESHCORE_LORA_OTA && MESHCORE_OTA_LAB_BACKEND && defined(NRF52_PLATFORM) && defined(ENABLE_USB_INTERFACE)
#define MESHCORE_OTA_USB_MEASUREMENTS 1
#else
#define MESHCORE_OTA_USB_MEASUREMENTS 0
#endif

namespace mesh {
namespace ota {

struct OtaAppliedRadioProfile {
  uint32_t frequencyKhz = 0;
  uint32_t bandwidthHz = 0;
  uint8_t spreadingFactor = 0;
  uint8_t codingRate = 0;
};

class OtaRadioMeasurement {
 public:
  void observeApply(bool succeeded, const OtaAppliedRadioProfile& profile,
                    bool direct, uint32_t nowMs) {
    if (!succeeded) {
      valid_ = false;
      ++applyFailures_;
      return;
    }
    profile_ = profile;
    valid_ = true;
    if (direct) {
      ++directApplies_;
      lastDirectMs_ = nowMs;
    } else if (directApplied_) {
      ++restorations_;
      lastRestoreMs_ = nowMs;
    }
    directApplied_ = direct;
  }

  bool format(char* out, size_t capacity, bool active, uint32_t expiryMs,
              bool driverHealthy, uint32_t driverFaults, uint32_t nowMs) const {
    if (out == nullptr || capacity == 0) return false;
    const int written = std::snprintf(out, capacity,
        "src=driver-applied f=%lu b=%lu s=%u c=%u v=%u a=%u e=%08lX d=%08lX r=%08lX"
        " td=%08lX tr=%08lX h=%u x=%08lX af=%08lX n=%08lX",
        static_cast<unsigned long>(profile_.frequencyKhz),
        static_cast<unsigned long>(profile_.bandwidthHz),
        static_cast<unsigned>(profile_.spreadingFactor), static_cast<unsigned>(profile_.codingRate),
        static_cast<unsigned>(valid_), static_cast<unsigned>(active),
        static_cast<unsigned long>(expiryMs), static_cast<unsigned long>(directApplies_),
        static_cast<unsigned long>(restorations_), static_cast<unsigned long>(lastDirectMs_),
        static_cast<unsigned long>(lastRestoreMs_), static_cast<unsigned>(valid_ && driverHealthy),
        static_cast<unsigned long>(driverFaults), static_cast<unsigned long>(applyFailures_),
        static_cast<unsigned long>(nowMs));
    return written >= 0 && static_cast<size_t>(written) < capacity;
  }

 private:
  OtaAppliedRadioProfile profile_;
  bool valid_ = false, directApplied_ = false;
  uint32_t directApplies_ = 0, restorations_ = 0, applyFailures_ = 0;
  uint32_t lastDirectMs_ = 0, lastRestoreMs_ = 0;
};

inline bool formatOtaBudgetMeasurement(char* out, size_t capacity, uint32_t nowMs,
                                      uint32_t windowMs, uint32_t budgetMs, uint32_t usedMs,
                                      uint32_t completedTxMs, uint32_t timeouts,
                                      uint32_t accountingFailures) {
  if (out == nullptr || capacity == 0) return false;
  const int written = std::snprintf(out, capacity,
      "n=%08lX w=%08lX b=%08lX u=%08lX tx=%08lX to=%08lX af=%08lX",
      static_cast<unsigned long>(nowMs), static_cast<unsigned long>(windowMs),
      static_cast<unsigned long>(budgetMs), static_cast<unsigned long>(usedMs),
      static_cast<unsigned long>(completedTxMs), static_cast<unsigned long>(timeouts),
      static_cast<unsigned long>(accountingFailures));
  return written >= 0 && static_cast<size_t>(written) < capacity;
}

}  // namespace ota
}  // namespace mesh
