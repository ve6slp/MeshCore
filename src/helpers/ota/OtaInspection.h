#pragma once

#include <cstdio>
#include <helpers/ota/OtaFirmwareIntegration.h>

namespace mesh { namespace ota {

inline const char* otaPhaseName(v4::Phase phase) {
  switch (phase) {
    case v4::Phase::Idle: return "idle";
    case v4::Phase::Receiving: return "receiving";
    case v4::Phase::Verifying: return "verifying";
    case v4::Phase::Ready: return "ready";
    case v4::Phase::ActivationPending: return "activation-pending";
    case v4::Phase::Trial: return "trial";
    case v4::Phase::Confirmed: return "confirmed";
    case v4::Phase::Aborted: return "aborted";
    case v4::Phase::Failed: return "failed";
    case v4::Phase::MetadataFault: return "metadata-fault";
  }
  return "unknown";
}

inline void formatOtaStatus(char* out, size_t size, const OtaFirmwareIntegration& integration) {
  const auto* receiver = integration.receiver();
  if (!receiver) {
    snprintf(out, size, "OTA v4 unavailable");
    return;
  }
  const auto& state = receiver->journal();
  snprintf(out, size, "OTA v4 phase=%s generation=%lu next=%u result=%u lease=%u",
      otaPhaseName(state.phase), static_cast<unsigned long>(state.generation),
      state.nextChunk, static_cast<unsigned>(state.lastResult), integration.leaseActive());
}

}}
