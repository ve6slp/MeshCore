#pragma once

// Abstract hashing interface used by the descriptor verification pipeline.
// Kept separate from any concrete algorithm so the trust pipeline is not
// hard-wired to a single implementation (and so tests can substitute a
// deterministic-but-clearly-fake double without it masquerading as the
// production SHA-256 implementation).

#include <stdint.h>
#include <stddef.h>

namespace ota {
namespace trust {

class HashAlgorithm {
public:
  virtual ~HashAlgorithm() = default;
  virtual void reset() = 0;
  virtual void update(const uint8_t* data, size_t len) = 0;
  virtual void finish(uint8_t out_digest[32]) = 0;
  virtual size_t digestSizeBytes() const { return 32; }
};

}  // namespace trust
}  // namespace ota
