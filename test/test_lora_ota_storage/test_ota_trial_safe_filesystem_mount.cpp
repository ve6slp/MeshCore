// gtest suite for ota_fs_mount's Arduino-independent mount-decision
// helpers (src/helpers/ota/OtaTrialSafeFilesystemMount.h). These prove,
// via plain call-counting lambdas rather than real Arduino filesystem
// objects, that a trial/unknown boot can NEVER reach a destructive
// format-on-fail code path -- matching the real call sites wired in
// examples/companion_radio/main.cpp for InternalFS, this repo's CustomLFS
// (EXTRAFS), and CustomLFS_QSPIFlash.

#include <gtest/gtest.h>

#include <functional>

#include "helpers/ota/OtaTrialSafeFilesystemMount.h"

namespace {

struct CallCounter {
  int count = 0;
  bool result;
  explicit CallCounter(bool r) : result(r) {}
  bool operator()() {
    ++count;
    return result;
  }
};

}  // namespace

// --- mountTrialSafe (InternalFS/ExtraFS shape: separable mount-only vs
//     legacy format-on-fail paths) ---

TEST(OtaTrialSafeFilesystemMountTest, TrialDisallowedUsesMountOnlyNeverLegacy) {
  CallCounter mount_only(true);
  CallCounter legacy(true);

  bool ok = ota_fs_mount::mountTrialSafe(/*allow_destructive_boot_writes=*/false,
                                          std::ref(mount_only), std::ref(legacy));

  EXPECT_TRUE(ok);
  EXPECT_EQ(mount_only.count, 1);
  EXPECT_EQ(legacy.count, 0);
}

TEST(OtaTrialSafeFilesystemMountTest, TrialDisallowedMountOnlyFailurePropagatesWithoutFormatting) {
  CallCounter mount_only(false);
  CallCounter legacy(true);

  bool ok = ota_fs_mount::mountTrialSafe(/*allow_destructive_boot_writes=*/false,
                                          std::ref(mount_only), std::ref(legacy));

  // A failed mount-only attempt during trial must be reported as failed --
  // NOT silently retried via the formatting path, no matter what.
  EXPECT_FALSE(ok);
  EXPECT_EQ(mount_only.count, 1);
  EXPECT_EQ(legacy.count, 0);
}

TEST(OtaTrialSafeFilesystemMountTest, NormalBootUsesLegacyFormatOnFailPathUnchanged) {
  CallCounter mount_only(true);
  CallCounter legacy(true);

  bool ok = ota_fs_mount::mountTrialSafe(/*allow_destructive_boot_writes=*/true,
                                          std::ref(mount_only), std::ref(legacy));

  // Normal/non-trial boot must preserve the exact prior behaviour: only the
  // legacy (format-on-fail-capable) path is invoked, matching the original
  // unconditional `InternalFS.begin()` / `ExtraFS.begin()` call.
  EXPECT_TRUE(ok);
  EXPECT_EQ(mount_only.count, 0);
  EXPECT_EQ(legacy.count, 1);
}

TEST(OtaTrialSafeFilesystemMountTest, NormalBootLegacyFailurePropagates) {
  CallCounter mount_only(true);
  CallCounter legacy(false);

  bool ok = ota_fs_mount::mountTrialSafe(/*allow_destructive_boot_writes=*/true,
                                          std::ref(mount_only), std::ref(legacy));

  EXPECT_FALSE(ok);
  EXPECT_EQ(mount_only.count, 0);
  EXPECT_EQ(legacy.count, 1);
}

// --- mountOrDegradeIfDestructiveWritesDisallowed (QSPIFlash shape: one
//     atomic begin() with no separable mount-only step) ---

TEST(OtaTrialSafeFilesystemMountTest, TrialDisallowedNeverCallsAtomicBegin) {
  CallCounter begin_fn(true);

  bool ok = ota_fs_mount::mountOrDegradeIfDestructiveWritesDisallowed(
      /*allow_destructive_boot_writes=*/false, std::ref(begin_fn));

  // Even though begin_fn "would have" succeeded, it must never be invoked
  // at all during trial/unknown boot -- the filesystem is reported
  // unavailable/degraded instead, since merely calling begin() risks its
  // internal format-on-fail retry.
  EXPECT_FALSE(ok);
  EXPECT_EQ(begin_fn.count, 0);
}

TEST(OtaTrialSafeFilesystemMountTest, NormalBootCallsAtomicBeginExactlyOnce) {
  CallCounter begin_fn(true);

  bool ok = ota_fs_mount::mountOrDegradeIfDestructiveWritesDisallowed(
      /*allow_destructive_boot_writes=*/true, std::ref(begin_fn));

  EXPECT_TRUE(ok);
  EXPECT_EQ(begin_fn.count, 1);
}

TEST(OtaTrialSafeFilesystemMountTest, NormalBootAtomicBeginFailurePropagates) {
  CallCounter begin_fn(false);

  bool ok = ota_fs_mount::mountOrDegradeIfDestructiveWritesDisallowed(
      /*allow_destructive_boot_writes=*/true, std::ref(begin_fn));

  EXPECT_FALSE(ok);
  EXPECT_EQ(begin_fn.count, 1);
}
