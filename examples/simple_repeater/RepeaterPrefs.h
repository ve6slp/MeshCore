#pragma once

#ifndef MESHCORE_REPEATER_RELAY_PROFILE
#define MESHCORE_REPEATER_RELAY_PROFILE 0
#endif

#if MESHCORE_REPEATER_RELAY_PROFILE
static constexpr const char* kRepeaterPrefsFilename = "/relay_prefs.json";
#elif defined(XIAO_OTA_COMPILED_ROLE_ID) && XIAO_OTA_COMPILED_ROLE_ID == 1
static constexpr const char* kRepeaterPrefsFilename = "/repeater_prefs.json";
#else
static constexpr const char* kRepeaterPrefsFilename = "/prefs.json";
#endif

template <typename Filesystem>
const char* resolveRepeaterPrefsFilename(Filesystem& fs, const char* preferred = kRepeaterPrefsFilename) {
#if !MESHCORE_REPEATER_RELAY_PROFILE
  // Keep existing OTA data authoritative; reuse ordinary storage without
  // copying or renaming it during an unconfirmed upgrade.
  if (!fs.exists(preferred) && fs.exists("/prefs.json")) return "/prefs.json";
#endif
  return preferred;
}
