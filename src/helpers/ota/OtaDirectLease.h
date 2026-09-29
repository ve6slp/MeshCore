#pragma once

#include <cstdint>

namespace mesh {
namespace ota {

struct OtaDirectLeaseParams {
  float freqMhz = 0.0f;
  float bandwidthKhz = 0.0f;
  uint8_t spreadingFactor = 0;
  uint8_t codingRate = 0;
  int timeoutMinutes = 0;
};

class OtaDirectLeaseHandler {
public:
  virtual ~OtaDirectLeaseHandler() = default;
  virtual bool setOtaDirectMode() = 0;
  virtual void applyOtaDirectLease(const OtaDirectLeaseParams& params) = 0;
};

inline bool isValidOtaDirectLease(const OtaDirectLeaseParams& params) {
  return params.freqMhz >= 150.0f && params.freqMhz <= 2500.0f &&
         params.spreadingFactor >= 5 && params.spreadingFactor <= 12 &&
         params.codingRate >= 5 && params.codingRate <= 8 &&
         params.bandwidthKhz >= 7.0f && params.bandwidthKhz <= 500.0f &&
         params.timeoutMinutes > 0;
}

inline bool requestOtaDirectLease(OtaDirectLeaseHandler& handler, const OtaDirectLeaseParams& params) {
  if (!isValidOtaDirectLease(params)) return false;
  if (!handler.setOtaDirectMode()) return false;
  handler.applyOtaDirectLease(params);
  return true;
}

}  // namespace ota
}  // namespace mesh
