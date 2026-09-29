#pragma once

#include <stdint.h>

namespace mesh {

enum class LoraOtaMode : uint8_t {
  Direct = 0,
  RoutedMesh = 1,
  Background = 2,
};

struct LoraOtaPlan {
  LoraOtaMode mode;
  uint8_t duty_cycle_percent;
  uint32_t airtime_budget_ms;
  uint32_t upload_window_ms;
  uint32_t cadence_ms;
  bool background_allowed;
  bool mesh_path_required;
};

class LoraOtaPolicy {
public:
  static constexpr uint32_t kMsPerHour = 60UL * 60UL * 1000UL;
  static constexpr uint32_t kMsPerDay = 24UL * kMsPerHour;
  static constexpr uint32_t kMsPer72Hours = 3UL * kMsPerDay;

  static uint8_t clampDutyCycle(uint8_t duty_cycle_percent) {
    if (duty_cycle_percent > 100) {
      return 100;
    }
    return duty_cycle_percent;
  }

  static uint32_t computeAirtimeBudgetMs(uint32_t update_window_ms, uint8_t duty_cycle_percent) {
    uint8_t safe_percent = clampDutyCycle(duty_cycle_percent);
    if (update_window_ms == 0) {
      return 0;
    }

    uint64_t budget = static_cast<uint64_t>(update_window_ms) * safe_percent;
    return static_cast<uint32_t>(budget / 100ULL);
  }

  static uint32_t computeUploadWindowMs(uint32_t update_window_ms, uint8_t duty_cycle_percent) {
    return computeAirtimeBudgetMs(update_window_ms, duty_cycle_percent);
  }

  static uint32_t computeCadenceMs(uint32_t update_window_ms, uint8_t duty_cycle_percent) {
    uint32_t budget = computeAirtimeBudgetMs(update_window_ms, duty_cycle_percent);
    if (budget == 0) {
      return update_window_ms;
    }
    return update_window_ms / (budget > 0 ? (budget / 1000U + 1U) : 1U);
  }

  static bool isBackgroundEligible(uint8_t duty_cycle_percent, float network_load_fraction) {
    if (duty_cycle_percent == 0) {
      return false;
    }

    const float load = network_load_fraction < 0.0f ? 0.0f : network_load_fraction;
    const float safe_load = load > 1.0f ? 1.0f : load;

    return duty_cycle_percent <= 2U && safe_load < 0.8f;
  }

  static bool requiresMeshPath(LoraOtaMode mode) {
    return mode == LoraOtaMode::RoutedMesh || mode == LoraOtaMode::Background;
  }

  static LoraOtaPlan buildPlan(
      LoraOtaMode mode,
      uint32_t update_window_ms,
      uint8_t duty_cycle_percent,
      float network_load_fraction,
      bool direct_radio_available,
      bool mesh_path_available,
      bool multicast_enabled) {
    const uint8_t safe_percent = clampDutyCycle(duty_cycle_percent);
    const uint32_t airtime_budget_ms = computeAirtimeBudgetMs(update_window_ms, safe_percent);
    const uint32_t upload_window_ms = direct_radio_available ? airtime_budget_ms : (airtime_budget_ms / 2U);
    const uint32_t cadence_ms = computeCadenceMs(update_window_ms, safe_percent);
    const bool background_allowed = (mode == LoraOtaMode::Background) && isBackgroundEligible(safe_percent, network_load_fraction);
    const bool mesh_path_required = requiresMeshPath(mode);

    LoraOtaPlan plan = {
      mode,
      safe_percent,
      airtime_budget_ms,
      upload_window_ms,
      cadence_ms,
      background_allowed,
      mesh_path_required && !mesh_path_available,
    };

    if (mode == LoraOtaMode::Direct) {
      plan.background_allowed = false;
      plan.mesh_path_required = false;
      return plan;
    }

    if (mode == LoraOtaMode::RoutedMesh) {
      plan.background_allowed = false;
      plan.mesh_path_required = !mesh_path_available;
      return plan;
    }

    if (mode == LoraOtaMode::Background) {
      plan.background_allowed = multicast_enabled && isBackgroundEligible(safe_percent, network_load_fraction);
      plan.mesh_path_required = !multicast_enabled && !mesh_path_available;
      return plan;
    }

    return plan;
  }
};

}  // namespace mesh
