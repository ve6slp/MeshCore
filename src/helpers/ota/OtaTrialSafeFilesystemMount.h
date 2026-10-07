// Arduino-independent, testable filesystem-mount-decision helpers for the
// OTA trial/unknown-boot safety gate.
//
// Several of the filesystem backends used across supported boards
// (Adafruit's InternalFileSystem, this repo's CustomLFS wrapper, and the
// pinned third-party CustomLFS_QSPIFlash library) implement their `begin()`
// as "mount, and if that fails, erase/format the backing flash region and
// remount" -- all inside one call, with no public API to request a
// mount-only attempt. During an OTA trial/unknown boot we must NEVER risk
// that destructive erase/format running, because a failed trial has to be
// able to roll back to the previous firmware with userdata intact.
//
// These templates capture the two decision shapes we actually need at the
// real mount call sites (see examples/companion_radio/main.cpp), so that
// native tests can prove the destructive path is invoked exactly zero times
// when writes are disallowed, using plain lambdas/counters instead of real
// Arduino filesystem objects.
#pragma once

namespace ota_fs_mount {

// Case 1: the backend exposes a genuine non-destructive mount-only path
// (e.g. calling the non-virtual `Adafruit_LittleFS::begin()` base method
// directly, bypassing a derived class's format-on-fail override) in
// addition to its legacy format-on-fail `begin()`. When destructive boot
// writes are disallowed, ALWAYS use the mount-only path and NEVER invoke
// `legacy_format_on_fail_mount_fn`, regardless of the mount-only outcome.
// When allowed, preserve prior behaviour exactly by calling the legacy
// path (which itself still performs the mount-only attempt internally).
template <typename MountOnlyFn, typename LegacyFormatOnFailMountFn>
bool mountTrialSafe(bool allow_destructive_boot_writes,
                     MountOnlyFn&& mount_only_fn,
                     LegacyFormatOnFailMountFn&& legacy_format_on_fail_mount_fn) {
  if (!allow_destructive_boot_writes) {
    return mount_only_fn();
  }
  return legacy_format_on_fail_mount_fn();
}

// Case 2: the backend's ONLY public entry point performs peripheral
// initialization, mount, AND format-on-fail atomically with no separable
// mount-only step (e.g. CustomLFS_QSPIFlash::begin()). There is nothing
// safe to call at all when destructive writes are disallowed -- even the
// very first mount attempt inside `begin_fn` may format on failure -- so
// `begin_fn` must not be invoked; the filesystem is reported as
// unavailable/degraded for the remainder of this boot instead.
template <typename BeginFn>
bool mountOrDegradeIfDestructiveWritesDisallowed(bool allow_destructive_boot_writes,
                                                  BeginFn&& begin_fn) {
  if (!allow_destructive_boot_writes) {
    return false;
  }
  return begin_fn();
}

}  // namespace ota_fs_mount
