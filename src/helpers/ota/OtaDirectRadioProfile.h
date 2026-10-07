#pragma once

#include <cstdint>

namespace mesh {
namespace ota {

enum class OtaDirectProfile : uint8_t {
  Legacy250 = 0,
  Bw250 = 1,
  Bw500 = 2,
};

inline bool isOtaDirectProfile(OtaDirectProfile profile) {
  return profile == OtaDirectProfile::Legacy250 || profile == OtaDirectProfile::Bw250 ||
         profile == OtaDirectProfile::Bw500;
}

inline uint32_t otaDirectBandwidthHz(OtaDirectProfile profile) {
  return profile == OtaDirectProfile::Bw500 ? 500000u : 250000u;
}

}  // namespace ota
}  // namespace mesh
