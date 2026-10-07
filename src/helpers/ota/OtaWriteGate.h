// Single shared write-gate mechanism used directly by DataStore's
// destructive-write methods (savePrefs/saveContacts/saveChannels/
// putBlobByKey/deleteBlobByKey/saveMainIdentity -- see DataStore.cpp) --
// NOT a duplicated/parallel model: production calls this exact template,
// and native tests drive the exact same template with a byte-backed
// fake `perform_fn` to prove the mutation-suppression behavior directly,
// not merely via call-count-only substitutes.
//
// Contract: when `disallowed` is true (an OTA trial/unknown boot, see
// DataStore::destructiveWritesDisallowed()), `perform_fn` -- the real,
// already-implemented open/seek/write/close logic for that call site --
// is NEVER invoked at all (zero underlying I/O, zero RAM mutation of
// whatever it would have touched), and this returns `false` honestly (a
// policy-refused write is not a persisted success). When `disallowed` is
// false, `perform_fn` is invoked exactly once and its real result is
// forwarded unchanged (ordinary legacy behavior, byte-for-byte
// unmodified).
#pragma once

namespace ota_write_gate {

template <typename PerformFn>
bool guardedPersist(bool disallowed, PerformFn&& perform_fn) {
  if (disallowed) return false;
  return perform_fn();
}

}  // namespace ota_write_gate
