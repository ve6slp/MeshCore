#pragma once

// Single authoritative owner, per board, of this firmware's OTA-relevant
// boot/runtime lifecycle evidence -- previously duplicated as two
// independent role-local bools in examples/companion_radio/MyMesh.h and
// examples/simple_repeater/MyMesh.h (`_ota_trial_filesystem_fault_observed_`,
// `_ota_identity_confirmed_loaded_`). Exactly ONE instance per MyMesh,
// constructed once, fed REAL outcomes from begin()'s/main.cpp's identity
// resolution and every ordinary persisted-write/read call site; consumed
// read-only by tickOtaTrialHealth().
//
// Arduino-independent, plain C++ -- natively testable (see
// test/test_lora_ota_storage/test_ota_firmware_service.cpp).
//
// Astra's correction: a non-null `self_id.pub_key` address and a
// once-true "identity confirmed loaded" bool are both merely interim
// lifecycle assertions, not fresh, ongoing integrity proof -- a LATER
// genuine storage/identity fault must invalidate previously-confirmed
// identity evidence (see noteStorageIoResult() below), rather than
// leaving stale "still durable" evidence in place forever once latched.

#include "helpers/ota/OtaTrialSafeIdentityBoot.h"

namespace mesh {
namespace ota {

class OtaFirmwareService {
 public:
  // Call exactly once, immediately after DataStore::loadMainIdentity()'s
  // (or the repeater-equivalent IdentityStore::load()'s) raw bool
  // result, before ota_identity_boot::resolveIdentityTrialSafe() ever
  // runs. A genuine load failure is latched as fault evidence
  // UNCONDITIONALLY, even on a legitimately blank/never-configured
  // device -- see examples/companion_radio/MyMesh.cpp's begin() for the
  // full rationale (a load failure here can't be distinguished from
  // storage corruption caused by an in-progress OTA candidate).
  void noteIdentityLoadAttempted(bool loaded_ok) {
    identity_confirmed_loaded_ = loaded_ok;
    if (!loaded_ok) trial_filesystem_fault_observed_ = true;
  }

  // Call with the real ota_identity_boot::Outcome once
  // resolveIdentityTrialSafe() returns (only reached when the initial
  // load above failed) and whether destructive boot writes were
  // disallowed this boot. LoadedExisting is never passed here (handled
  // entirely by noteIdentityLoadAttempted() above); IdentityUnavailable
  // needs no further action (identity_confirmed_loaded_ is already false
  // from noteIdentityLoadAttempted()).
  void noteIdentityResolution(ota_identity_boot::Outcome outcome, bool destructive_writes_disallowed) {
    if (outcome == ota_identity_boot::Outcome::GeneratedAndSaved) {
      identity_confirmed_loaded_ = true;
    } else if (outcome == ota_identity_boot::Outcome::GeneratedRamOnlyNoWrites) {
      // Never "confirmed loaded" -- a RAM-only identity was never read
      // back from durable storage and is not guaranteed to survive this
      // boot. Only a genuine I/O fault (writes were actually permitted
      // but the save itself failed) counts as fault evidence here -- a
      // policy refusal is an intentional, expected non-persist.
      if (!destructive_writes_disallowed) trial_filesystem_fault_observed_ = true;
    }
    // LoadedExisting: never reached via this path (see doc comment).
    // IdentityUnavailable: nothing further to latch (already false).
  }

  // Call when a real, already-performed, durable identity write (NOT a
  // boot-time generate+save -- see noteIdentityResolution() for that
  // case) succeeds elsewhere at runtime, e.g. a CLI/USB identity import
  // or an explicit erase+rebuild -- the exact same category of evidence
  // as ota_identity_boot::Outcome::GeneratedAndSaved.
  void noteIdentityPersisted() { identity_confirmed_loaded_ = true; }

  // Call at EVERY ordinary persisted read/write call site (savePrefs/
  // saveChannels/saveContacts/putBlobByKey/loadPrefs/loadContacts/
  // loadChannels/probeStorageReadiness/etc.) with that operation's REAL,
  // already-performed I/O result -- never call this for an operation
  // that was policy-refused before being attempted
  // (destructiveWritesDisallowed()), matching every existing call site's
  // own gating. A genuine fault invalidates previously-confirmed
  // identity evidence: identity durability evidence captured before a
  // subsequent storage fault is stale, not still-current proof.
  void noteStorageIoResult(bool ok) {
    if (!ok) {
      trial_filesystem_fault_observed_ = true;
      identity_confirmed_loaded_ = false;
    }
  }

  bool identityConfirmedLoaded() const { return identity_confirmed_loaded_; }
  bool trialFilesystemFaultObserved() const { return trial_filesystem_fault_observed_; }

 private:
  bool identity_confirmed_loaded_ = false;
  bool trial_filesystem_fault_observed_ = false;
};

}  // namespace ota
}  // namespace mesh
