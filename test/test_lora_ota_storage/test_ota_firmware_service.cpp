// Native coverage for mesh::ota::OtaFirmwareService (see
// helpers/ota/OtaFirmwareService.h) -- the single authoritative per-board
// owner of OTA-relevant identity/filesystem lifecycle evidence, replacing
// the two previously-duplicated role-local bools in
// examples/companion_radio/MyMesh.h and examples/simple_repeater/MyMesh.h.

#include <gtest/gtest.h>

#include "helpers/ota/OtaFirmwareService.h"

using mesh::ota::OtaFirmwareService;

namespace {

TEST(OtaFirmwareServiceTest, FreshInstanceStartsWithNoEvidenceAndNoFault) {
  OtaFirmwareService service;
  EXPECT_FALSE(service.identityConfirmedLoaded());
  EXPECT_FALSE(service.trialFilesystemFaultObserved());
}

TEST(OtaFirmwareServiceTest, NoteIdentityLoadAttemptedTrueConfirmsLoadedWithoutFault) {
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(true);
  EXPECT_TRUE(service.identityConfirmedLoaded());
  EXPECT_FALSE(service.trialFilesystemFaultObserved());
}

TEST(OtaFirmwareServiceTest, NoteIdentityLoadAttemptedFalseLatchesFaultAndLeavesUnconfirmed) {
  // A genuine load failure can't be distinguished from storage
  // corruption caused by an in-progress OTA candidate -- latch it
  // unconditionally, even on a legitimately blank/never-configured
  // device.
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(false);
  EXPECT_FALSE(service.identityConfirmedLoaded());
  EXPECT_TRUE(service.trialFilesystemFaultObserved());
}

TEST(OtaFirmwareServiceTest, NoteIdentityResolutionGeneratedAndSavedConfirmsLoadedWithoutFault) {
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(false);  // Only reached after an initial load failure.
  service.noteIdentityResolution(ota_identity_boot::Outcome::GeneratedAndSaved,
                                  /*destructive_writes_disallowed=*/false);
  EXPECT_TRUE(service.identityConfirmedLoaded());
  // The initial load failure already latched fault evidence; a
  // subsequent successful generate+save does not retroactively clear it
  // -- the storage subsystem genuinely misbehaved earlier this boot.
  EXPECT_TRUE(service.trialFilesystemFaultObserved());
}

TEST(OtaFirmwareServiceTest,
     NoteIdentityResolutionGeneratedRamOnlyWithGenuineIoFaultLatchesFaultAndStaysUnconfirmed) {
  // destructive_writes_disallowed=false means writes were permitted but
  // the save itself genuinely failed -- real fault evidence.
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(false);
  service.noteIdentityResolution(ota_identity_boot::Outcome::GeneratedRamOnlyNoWrites,
                                  /*destructive_writes_disallowed=*/false);
  EXPECT_FALSE(service.identityConfirmedLoaded());
  EXPECT_TRUE(service.trialFilesystemFaultObserved());
}

TEST(OtaFirmwareServiceTest,
     NoteIdentityResolutionGeneratedRamOnlyWithPolicyRefusalIsNotFaultEvidence) {
  // destructive_writes_disallowed=true is an intentional, expected
  // non-persist (policy refusal), never fault evidence by itself.
  // Exercise this branch directly on a fresh instance to isolate its
  // own behaviour (real callers always precede this with a failed
  // noteIdentityLoadAttempted(); the class itself does not enforce that
  // ordering) -- a policy refusal alone must never set the fault flag.
  OtaFirmwareService service;
  service.noteIdentityResolution(ota_identity_boot::Outcome::GeneratedRamOnlyNoWrites,
                                  /*destructive_writes_disallowed=*/true);
  EXPECT_FALSE(service.identityConfirmedLoaded());
  EXPECT_FALSE(service.trialFilesystemFaultObserved());
}

TEST(OtaFirmwareServiceTest, NoteIdentityPersistedConfirmsLoadedEvenAfterAnEarlierLoadFailure) {
  // Equivalent evidence category to GeneratedAndSaved -- e.g. a serial
  // identity import or explicit erase+rebuild succeeding at runtime.
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(false);
  service.noteIdentityPersisted();
  EXPECT_TRUE(service.identityConfirmedLoaded());
}

TEST(OtaFirmwareServiceTest, NoteStorageIoResultOkLeavesExistingStateUnchanged) {
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(true);
  service.noteStorageIoResult(/*ok=*/true);
  EXPECT_TRUE(service.identityConfirmedLoaded());
  EXPECT_FALSE(service.trialFilesystemFaultObserved());
}

TEST(OtaFirmwareServiceTest, NoteStorageIoResultFailureInvalidatesPreviouslyConfirmedIdentity) {
  // The core new-behaviour requirement: a LATER genuine storage fault
  // must invalidate previously-confirmed identity evidence, not merely
  // be mechanically migrated -- stale "was durable" evidence is not
  // proof the identity is still durable right now.
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(true);
  ASSERT_TRUE(service.identityConfirmedLoaded());
  service.noteStorageIoResult(/*ok=*/false);
  EXPECT_FALSE(service.identityConfirmedLoaded());
  EXPECT_TRUE(service.trialFilesystemFaultObserved());
}

TEST(OtaFirmwareServiceTest, FaultLatchNeverAutoClearsExceptViaExplicitReconfirmation) {
  // Once latched, the fault flag must stay latched through further
  // successful I/O -- only an explicit fresh identity re-confirmation
  // event (noteIdentityLoadAttempted(true)/noteIdentityPersisted()) can
  // change identityConfirmedLoaded(); trialFilesystemFaultObserved()
  // itself never auto-clears at all once set, by design.
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(false);
  ASSERT_TRUE(service.trialFilesystemFaultObserved());

  service.noteStorageIoResult(/*ok=*/true);
  EXPECT_TRUE(service.trialFilesystemFaultObserved());

  service.noteIdentityPersisted();
  EXPECT_TRUE(service.identityConfirmedLoaded());
  EXPECT_TRUE(service.trialFilesystemFaultObserved());
}

}  // namespace
