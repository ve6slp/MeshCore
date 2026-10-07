#pragma once

#include <atomic>

namespace mesh {
namespace ota {

// Product callers run in setup/the mesh loop, not USB/QSPI interrupt callbacks.
// Each buffered call level owns distinct storage and rejects reentry before using it.
class OtaBoardProofScratchLease {
public:
  explicit OtaBoardProofScratchLease(std::atomic_flag& busy)
      : busy_(busy), acquired_(!busy.test_and_set(std::memory_order_acquire)) {}
  ~OtaBoardProofScratchLease() {
    if (acquired_) busy_.clear(std::memory_order_release);
  }
  explicit operator bool() const { return acquired_; }
  OtaBoardProofScratchLease(const OtaBoardProofScratchLease&) = delete;
  OtaBoardProofScratchLease& operator=(const OtaBoardProofScratchLease&) = delete;
private:
  std::atomic_flag& busy_;
  bool acquired_;
};

}  // namespace ota
}  // namespace mesh
