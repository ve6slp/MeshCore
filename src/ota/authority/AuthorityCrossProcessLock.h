#pragma once

// Cross-process mutual exclusion for the two-copy authority registry
// (Sol fe862c8/c577a77f review, H2): two independent OS processes (e.g.
// two concurrent `ota_authority_registry.py issue` invocations, or a CLI
// issuer racing a live C++ host) can each perform their OWN "does this
// owner already have surviving history?" lookup and then their OWN
// append, entirely in-process. Without a serialization point that spans
// BOTH processes, the check-then-act window between those two steps lets
// two genuinely distinct revision-0 grants for the exact same physical
// owner both observe "no existing record" and both succeed -- an actual
// ownership fork, not a theoretical race.
//
// Sol c577a77f REJECTED the first version of this file on two counts,
// both fixed here:
//
//   (1) AuthorityCrossProcessLockGuard previously treated a nullptr lock
//       as "acquired": that is NOT a safety-compatible default -- it
//       preserves the exact production race this header exists to
//       close, for any caller that simply forgets (or never gets around
//       to) wiring a real lock. A MISSING lock must always DENY. A
//       caller that genuinely only ever runs single-process (e.g. a
//       narrow unit test that never launches a second real OS process)
//       must supply an EXPLICIT lock object with that contract --
//       InProcessOnlyAuthorityCrossProcessLock below exists for exactly
//       that -- rather than relying on an implicit "nullptr means fine"
//       fallback.
//
//   (2) The original FileAuthorityCrossProcessLock derived ONE lock file
//       per PAIR, from the lexicographically-smaller of the two copy
//       paths. That does NOT correctly serialize two DIFFERENT pairs
//       that share ONE common copy (e.g. pair (A,B) and pair (B,C) both
//       legitimately mutate copy B's ownership history): pair (A,B)
//       derives min(A,B), pair (B,C) derives min(B,C) -- two DIFFERENT
//       lock files, so the two pairs never actually serialize against
//       each other despite both touching B. Relative/absolute path
//       spelling, and symlink/hardlink aliases of the identical
//       underlying file, likewise were never recognized as "the same
//       lock". This version instead locks PER-COPY, keyed by the copy's
//       true physical identity (device+inode once the file exists --
//       the one thing that genuinely survives symlink AND hardlink
//       aliasing -- or a realpath'd parent-directory+basename for a
//       copy that does not exist yet, since no hardlink alias is
//       possible for a file that doesn't exist), and acquires BOTH
//       copies' per-copy locks in a single GLOBALLY STABLE sorted order
//       (by the derived lock-file path) for every call, regardless of
//       which copy a given process happens to call "A" or "B" -- this
//       is what actually prevents an AB/BA deadlock when two pairs
//       overlap on one shared copy.

#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <algorithm>
#include <string>
#include <vector>

namespace ota {
namespace authority {

// Abstract port. acquire() blocks until the lock is held or returns
// false on a genuine failure -- never a silent "proceed unlocked"
// fallback. Not re-entrant: a caller must not nest acquire() calls on
// the same instance from the same process/thread.
class AuthorityCrossProcessLock {
 public:
  virtual ~AuthorityCrossProcessLock() = default;
  virtual bool acquire() = 0;
  virtual void release() = 0;
};

// RAII guard used at every coordinator entrypoint. Sol c577a77f: a
// MISSING (nullptr) lock is ALWAYS treated as not-acquired (deny) --
// there is no implicit "unwired means proceed unlocked" fallback
// anymore. A non-null lock that fails to acquire likewise reports
// acquired()==false; callers MUST treat either case as Denied, never
// proceed.
class AuthorityCrossProcessLockGuard {
 public:
  explicit AuthorityCrossProcessLockGuard(AuthorityCrossProcessLock* lock) : lock_(lock), acquired_(false) {
    acquired_ = (lock_ != nullptr) && lock_->acquire();
  }
  ~AuthorityCrossProcessLockGuard() {
    if (lock_ != nullptr && acquired_) lock_->release();
  }

  bool acquired() const { return acquired_; }

  AuthorityCrossProcessLockGuard(const AuthorityCrossProcessLockGuard&) = delete;
  AuthorityCrossProcessLockGuard& operator=(const AuthorityCrossProcessLockGuard&) = delete;

 private:
  AuthorityCrossProcessLock* lock_;
  bool acquired_;
};

// FOR TESTS ONLY: real production code must never construct this.
// Provides the EXPLICIT "I genuinely only run single-process, no real
// OS-process serialization is needed" contract Root's review allows --
// trivially succeeds every time, never touches the filesystem. This is
// deliberately the ONLY way to get that old permissive behavior back:
// it must be opted into by name, never implied by a missing lock.
class InProcessOnlyAuthorityCrossProcessLock : public AuthorityCrossProcessLock {
 public:
  bool acquire() override { return true; }
  void release() override {}
};

// Sol39 H2: this design was REJECTED again on code inspection even
// though it compiled and passed tests -- the derived-sidecar-lock-file
// approach above has two root-cause defects:
//
//   (1) Lock IDENTITY CHANGES between "copy file absent" and "copy file
//       present": canonicalCopyLockPath() branches on stat() success,
//       so two FileAuthorityCrossProcessLock instances constructed
//       before vs. after the SAME logical copy is first created can
//       derive genuinely DIFFERENT lock paths for what is supposed to
//       be the same serialization point.
//   (2) When the file exists, the derived path is
//       `real_dir + dev + ino` -- but dev+ino ALONE already uniquely
//       identifies the underlying file regardless of which directory
//       path reached it. Including real_dir means two HARDLINKS of the
//       exact same inode reachable via DIFFERENT directories compute
//       DIFFERENT lock paths and never actually contend.
//
// The fix: stop deriving a SEPARATE sidecar lock file at all. Instead,
// `open(O_CREAT|O_RDWR)` the REAL registry copy file directly (NEVER
// O_TRUNC, NEVER rename/unlink it as part of lock management -- a
// crash safely drops the OS-held flock automatically, and the copy's
// actual content is never touched by lock bookkeeping), then fstat()
// the resulting descriptor to get (st_dev, st_ino) for a GLOBALLY
// STABLE ORDER (never a path string) across independently-constructed
// instances that might reference overlapping or aliased copies. This
// is correct because (a) POSIX guarantees concurrent O_CREAT opens of
// the SAME path by different processes converge on the SAME underlying
// inode -- no TOCTOU race in identity -- and (b) Linux flock()
// conflict detection happens at the inode level, so two different open
// file descriptions reached via DIFFERENT hardlink paths to the SAME
// inode correctly contend for the same lock. Both fds are opened
// BEFORE any ordering/locking decision is made, so there is no window
// between "determine identity" and "open" in which the two could
// diverge.
// Real filesystem-backed implementation: flocks the ACTUAL registry
// copy files directly (never a derived sidecar path), ordered by the
// opened descriptors' true (dev, ino) identity -- the one thing that is
// genuinely invariant across relative/absolute spelling, symlink
// aliasing, AND hardlink aliasing across different directories -- so
// two independently-constructed instances that reference overlapping
// or aliased copies always acquire in the SAME globally-stable order
// and can never deadlock (AB vs BA) against each other.
class FileAuthorityCrossProcessLock : public AuthorityCrossProcessLock {
 public:
  FileAuthorityCrossProcessLock(const std::string& copyAPath, const std::string& copyBPath)
      : copyPaths_{copyAPath, copyBPath} {}

  ~FileAuthorityCrossProcessLock() override { releaseAll(); }

  bool acquire() override {
    // Open BOTH real copy files up front -- O_CREAT|O_RDWR, NEVER
    // O_TRUNC -- before any ordering decision, so identity resolution
    // (fstat below) always reflects the SAME descriptors we are about
    // to lock; there is no separate "derive path, then open" window
    // for the two to diverge.
    std::vector<int> opened_fds(copyPaths_.size(), -1);
    std::vector<OpenedCopy> opened;
    bool ok = true;
    for (size_t i = 0; i < copyPaths_.size() && ok; ++i) {
      const int fd = open(copyPaths_[i].c_str(), O_CREAT | O_RDWR, 0600);
      if (fd < 0) {
        ok = false;
        break;
      }
      struct stat st;
      if (fstat(fd, &st) != 0) {
        close(fd);
        ok = false;
        break;
      }
      opened_fds[i] = fd;
      opened.push_back(OpenedCopy{fd, st.st_dev, st.st_ino});
    }
    if (!ok) {
      for (int fd : opened_fds) {
        if (fd >= 0) close(fd);
      }
      return false;
    }

    // Dedupe aliases (same copy reached via two different path spellings,
    // or a genuine hardlink of the same inode in a different directory)
    // by (dev, ino) BEFORE locking -- flock()'ing the same inode twice
    // through two different fds from the SAME process would otherwise
    // self-deadlock on some platforms and is pointless regardless, since
    // one exclusive hold already covers the physical file.
    std::vector<OpenedCopy> unique;
    for (const auto& c : opened) {
      bool is_dup = false;
      for (const auto& u : unique) {
        if (u.dev == c.dev && u.ino == c.ino) {
          is_dup = true;
          break;
        }
      }
      if (is_dup) {
        close(c.fd);  // Redundant fd for an already-represented physical file.
      } else {
        unique.push_back(c);
      }
    }

    // Globally stable order by true (dev, ino) identity -- never by
    // path string -- so overlapping/aliased pairs constructed by
    // different callers always lock in the SAME order.
    std::sort(unique.begin(), unique.end(), [](const OpenedCopy& a, const OpenedCopy& b) {
      if (a.dev != b.dev) return a.dev < b.dev;
      return a.ino < b.ino;
    });

    fds_.clear();
    for (size_t i = 0; i < unique.size(); ++i) {
      if (flock(unique[i].fd, LOCK_EX) != 0) {
        for (size_t j = 0; j < i; ++j) {
          flock(fds_[j], LOCK_UN);
          close(fds_[j]);
        }
        for (size_t j = i; j < unique.size(); ++j) close(unique[j].fd);
        fds_.clear();
        return false;
      }
      fds_.push_back(unique[i].fd);
    }
    return true;
  }

  void release() override { releaseAll(); }

 private:
  struct OpenedCopy {
    int fd;
    dev_t dev;
    ino_t ino;
  };

  void releaseAll() {
    for (int fd : fds_) {
      flock(fd, LOCK_UN);
      close(fd);
    }
    fds_.clear();
  }

  std::vector<std::string> copyPaths_;
  std::vector<int> fds_;
};

}  // namespace authority
}  // namespace ota

