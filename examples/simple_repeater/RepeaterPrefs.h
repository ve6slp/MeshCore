#pragma once

#if defined(XIAO_OTA_COMPILED_ROLE_ID) && XIAO_OTA_COMPILED_ROLE_ID == 1
static constexpr const char* kRepeaterPrefsFilename = "/repeater_prefs.json";
#else
static constexpr const char* kRepeaterPrefsFilename = "/prefs.json";
#endif

template <typename Filesystem>
const char* resolveRepeaterPrefsFilename(Filesystem& fs, const char* preferred = kRepeaterPrefsFilename) {
  // Keep existing OTA data authoritative; reuse ordinary storage without
  // copying or renaming it during an unconfirmed upgrade.
  if (!fs.exists(preferred) && fs.exists("/prefs.json")) return "/prefs.json";
  return preferred;
}
