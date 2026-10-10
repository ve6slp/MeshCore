#pragma once

#include <cstdio>
#include <helpers/ota/OtaFirmwareIntegration.h>

namespace mesh {
namespace ota {

struct OtaAdminAbortGuard {
  uint32_t generation = 0;
  uint32_t counter = 0;
  uint8_t imageHash[32] = {};
};

inline bool parseOtaAdminAbortGuard(const char* command, OtaAdminAbortGuard& out) {
  if (!command || std::strncmp(command, "abort ", 6)) return false;
  command += 6;
  OtaAdminAbortGuard parsed;
  const auto decimal = [](const char*& text, uint32_t& value) {
    if (*text < '0' || *text > '9' || (*text == '0' && text[1] != ' ')) return false;
    value = 0;
    unsigned digits = 0;
    while (*text >= '0' && *text <= '9') {
      const uint32_t digit = static_cast<uint32_t>(*text++ - '0');
      if (++digits > 10 || value > (UINT32_MAX - digit) / 10u) return false;
      value = value * 10u + digit;
    }
    if (*text != ' ') return false;
    ++text;
    return true;
  };
  if (!decimal(command, parsed.generation) || !parsed.generation || !decimal(command, parsed.counter)) return false;
  const auto hex = [](char value) {
    return value >= '0' && value <= '9' ? value - '0' :
           value >= 'a' && value <= 'f' ? value - 'a' + 10 : -1;
  };
  for (size_t i = 0; i < 32; ++i) {
    const int high = hex(*command);
    if (high < 0) return false;
    ++command;
    const int low = hex(*command);
    if (low < 0) return false;
    ++command;
    parsed.imageHash[i] = static_cast<uint8_t>((high << 4) | low);
  }
  if (*command) return false;
  out = parsed;
  return true;
}

inline usb::UsbOtaResult handleOtaAdminAbortCommand(OtaFirmwareIntegration& integration,
    const uint8_t admin_public_key[32], const char* command) {
  OtaAdminAbortGuard guard;
  if (!parseOtaAdminAbortGuard(command, guard)) return usb::UsbOtaResult::BadRequest;
  return integration.abortAuthenticatedAdminCommand(admin_public_key, guard.generation, guard.counter, guard.imageHash);
}

inline const char* otaInspectionSource(const OtaFirmwareIntegration::Readback& view) {
  return view.bootCandidate ? "boot" : view.snapshot.localCache ? "cache" : "receiver";
}

inline bool formatOtaInspectionUnavailable(char* out, size_t size,
                                           const OtaFirmwareIntegration::Readback& view) {
  if (view.snapshot.storageUnavailable) {
    snprintf(out, size, "Err - candidate storage unavailable");
  } else if (!view.snapshot.valid) {
    snprintf(out, size, "%s", view.emptyStore ? "candidate=none phase=idle" : "Err - candidate state unavailable");
  } else {
    const auto& st = view.snapshot;
    if (st.blockBytes != kOtaBlockMaxDataBytes || !st.imageBytes ||
        st.imageBytes > ::ota::storage::OtaCandidateStore::kMaxBlocks * kOtaBlockMaxDataBytes ||
        st.totalBlocks != (st.imageBytes + kOtaBlockMaxDataBytes - 1u) / kOtaBlockMaxDataBytes ||
        st.receivedBlocks > st.totalBlocks) {
      snprintf(out, size, "Err - candidate geometry invalid");
    } else {
      return false;
    }
  }
  return true;
}

inline void formatOtaProgress(char* out, size_t size, const OtaFirmwareIntegration::Readback& view) {
  if (formatOtaInspectionUnavailable(out, size, view)) return;
  const auto& st = view.snapshot;
  const int written = snprintf(out, size,
      "candidate=%s phase=%s received=%u total=%u missing=%u bytes=%lu block=%u",
      otaInspectionSource(view), otaLifecyclePhaseName(view.phase), st.receivedBlocks, st.totalBlocks,
      st.totalBlocks - st.receivedBlocks, (unsigned long)st.imageBytes, st.blockBytes);
  if (written < 0 || static_cast<size_t>(written) >= size)
    snprintf(out, size, "Err - progress reply too long");
}

inline void formatOtaCandidate(char* out, size_t size, const OtaFirmwareIntegration::Readback& view) {
  if (formatOtaInspectionUnavailable(out, size, view)) return;
  char image[65];
  static constexpr char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < 32; ++i) {
    image[2 * i] = hex[view.snapshot.imageHash[i] >> 4];
    image[2 * i + 1] = hex[view.snapshot.imageHash[i] & 15];
  }
  image[64] = 0;
  const int written = snprintf(out, size, "candidate=%s phase=%s counter=%lu generation=%lu image=%s",
      otaInspectionSource(view), otaLifecyclePhaseName(view.phase), (unsigned long)view.snapshot.counter,
      (unsigned long)view.snapshot.generation, image);
  if (written < 0 || static_cast<size_t>(written) >= size)
    snprintf(out, size, "Err - candidate reply too long");
}

inline void formatOtaSettings(char* out, size_t size, const OtaFirmwareIntegration& integration) {
  const unsigned tenths = static_cast<unsigned>(integration.dutyCyclePercent() * 10.0f + 0.5f);
  const int written = snprintf(out, size, "mode=%s duty=%u.%u%%",
      firmwareOtaModeName(integration.mode()), tenths / 10, tenths % 10);
  if (written < 0 || static_cast<size_t>(written) >= size)
    snprintf(out, size, "Err - settings reply too long");
}

inline void formatOtaAdminAbortResult(char* out, size_t size, usb::UsbOtaResult result) {
  using Result = usb::UsbOtaResult;
  if (result == Result::BadRequest) {
    snprintf(out, size, "Err - usage: ota abort <generation> <counter> <image>");
    return;
  }
  if (result == Result::Ok) {
    snprintf(out, size, "OK - OTA aborted");
    return;
  }
  const char* reason = result == Result::Unavailable ? "unavailable" :
                       result == Result::Denied ? "denied" :
                       result == Result::TooLate ? "too late" :
                       result == Result::IoError ? "I/O error" :
                       result == Result::Mismatch ? "mismatch" :
                       result == Result::Busy ? "busy" : "not found";
  snprintf(out, size, "Err - OTA abort %s", reason);
}

}  // namespace ota
}  // namespace mesh
