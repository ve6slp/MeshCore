// Arduino-independent, testable trial-safe identity-boot decision helper.
//
// Astra's explicit contract: during an OTA trial/unknown boot, a failed
// identity load must result in ZERO identity generation AND zero writes --
// not merely "generate in RAM but don't save". Even a temporary,
// unregistered, RAM-only identity must never be synthesized or used for
// mesh TX / the counter-or-consent domain during an unresolved trial,
// because the original persisted secret might merely be transiently
// unreadable (not genuinely corrupt/absent), and a failed trial has to be
// able to roll back with that original secret completely untouched.
//
// This header captures only the DECISION sequencing (does generate_fn get
// invoked at all, does save_fn get invoked at all) so native tests can
// prove it with plain call-counting lambdas/byte-backed fakes, independent
// of any real Arduino identity/filesystem object. See
// examples/companion_radio/MyMesh.cpp's begin() for the real call site.
#pragma once

namespace ota_identity_boot {

enum class Outcome {
  // load_fn() succeeded: nothing else was invoked.
  LoadedExisting,
  // load_fn() failed, destructive writes were allowed: a fresh identity
  // was generated AND successfully persisted (ordinary legacy behaviour).
  GeneratedAndSaved,
  // load_fn() failed, destructive writes were allowed, but save_fn()
  // itself failed: the freshly generated identity is still used in RAM
  // for this boot only (pre-existing legacy behaviour, unrelated to the
  // trial/unknown restriction below) -- no further writes are retried.
  GeneratedRamOnlyNoWrites,
  // load_fn() failed AND destructive writes were disallowed (trial/
  // unknown boot): generate_fn/save_fn were NEVER invoked. The caller
  // must treat identity as unavailable this boot -- suppress identity-
  // dependent mesh TX/crypto and keep only a bounded trial/reboot/
  // maintenance path -- rather than silently operating on an ad-hoc
  // temporary identity.
  IdentityUnavailable,
};

template <typename LoadFn, typename GenerateFn, typename SaveFn>
Outcome resolveIdentityTrialSafe(bool allow_destructive_boot_writes, LoadFn&& load_fn,
                                  GenerateFn&& generate_fn, SaveFn&& save_fn) {
  if (load_fn()) {
    return Outcome::LoadedExisting;
  }
  if (!allow_destructive_boot_writes) {
    return Outcome::IdentityUnavailable;
  }
  generate_fn();
  if (save_fn()) {
    return Outcome::GeneratedAndSaved;
  }
  return Outcome::GeneratedRamOnlyNoWrites;
}

}  // namespace ota_identity_boot
