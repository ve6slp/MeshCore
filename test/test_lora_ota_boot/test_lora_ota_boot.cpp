// gtest suite for the OTA boot transaction state machine: the core
// erase-gating invariant (no target erase before authentication + verified
// backup), the full backup/install/trial/confirm/rollback lifecycle, and
// crash-consistent recovery from interruption at each destructive step.

#include <gtest/gtest.h>
#include <stdint.h>
#include <memory>
#include <vector>
#include <cstring>
#include <type_traits>

#include "ota/platform/FlashRegion.h"
#include "ota/platform/FlashTypes.h"
#include "ota/storage/Journal.h"
#include "ota/trust/Sha256.h"
#include "ota/trust/Ed25519SignatureVerifier.h"
#include "ota/trust/TrustTypes.h"
#include "ota/trust/CanonicalDescriptor.h"
#include "ota/trust/DescriptorVerifier.h"
#include "ota/boot/BootTransaction.h"

#include "../test_lora_ota_storage/FakeNorFlash.h"
#include "../test_lora_ota_trust/FakeMonotonicCounter.h"
#include "../test_lora_ota_trust/Ed25519TestSigner.h"

using ota::boot::BootTransaction;
using ota::platform::FlashRegion;
using ota::storage::Journal;
using ota::storage::JournalCheckpoint;
using ota::test::FakeNorFlash;

// Helper macro standing in for ASSERT_TRUE inside a non-void helper method
// (gtest's ASSERT_* can only be used directly in a function returning
// void); mirrors that restriction for the one call site below.
#define ASSERT_TRUE_OR_RETURN(cond)                       \
  do {                                                    \
    if (!(cond)) return ota::trust::ImageDescriptor();    \
  } while (0)

namespace {

constexpr uint32_t kCandidateSize = 8192;
constexpr uint32_t kBackupSize = 8192;
constexpr uint32_t kTargetSize = 8192;
constexpr uint32_t kJournalSlotBytes = Journal::kSlotBytes;
constexpr uint32_t kJournalSlots = 4;

class BootTransactionFixture : public ::testing::Test {
protected:
  void SetUp() override {
    candidate_flash_.reset(new FakeNorFlash(kCandidateSize, 4096));
    backup_flash_.reset(new FakeNorFlash(kBackupSize, 4096));
    target_flash_.reset(new FakeNorFlash(kTargetSize, 4096));
    journal_flash_.reset(new FakeNorFlash(kJournalSlotBytes * kJournalSlots, kJournalSlotBytes));

    candidate_region_.reset(new FlashRegion(*candidate_flash_, 0, kCandidateSize));
    backup_region_.reset(new FlashRegion(*backup_flash_, 0, kBackupSize));
    target_region_.reset(new FlashRegion(*target_flash_, 0, kTargetSize));
    journal_region_.reset(new FlashRegion(*journal_flash_, 0, kJournalSlotBytes * kJournalSlots));

    journal_.reset(new Journal(*journal_region_));
    ASSERT_TRUE(journal_->isValid());

    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = static_cast<uint8_t>(0x10 + i);
    signer_.reset(new ota::test::Ed25519TestSigner(seed));

    anchor_.expected_target_id = 0x2002;
    anchor_.expected_role_id = 3;
    anchor_.device_address = 0x1234567890ABCDEFull;
    anchor_.supported_boot_capability_flags = 0xFFFFFFFFu;
    std::memcpy(anchor_.trusted_signer_public_key_ed25519, signer_->publicKey(), 32);

    counter_.reset(new ota::test::FakeMonotonicCounter(0));
    hasher_.reset(new ota::trust::Sha256());
    sig_verifier_.reset(new ota::trust::Ed25519SignatureVerifier());
    verifier_.reset(new ota::trust::DescriptorVerifier(*hasher_, *sig_verifier_, *counter_, anchor_));

    // Seed the "current" target image with a known pattern so backup can be
    // meaningfully verified.
    target_image_.assign(kTargetSize, 0);
    for (size_t i = 0; i < target_image_.size(); ++i) target_image_[i] = static_cast<uint8_t>(i * 3 + 1);
    ASSERT_TRUE(ota::platform::isOk(target_region_->program(0, target_image_.data(), (uint32_t)target_image_.size())));

    candidate_image_.assign(kCandidateSize, 0);
    for (size_t i = 0; i < candidate_image_.size(); ++i) candidate_image_[i] = static_cast<uint8_t>(i * 5 + 2);
  }

  // Programs `candidate_image_` into the candidate region and returns a
  // validly signed descriptor for it, bound to the fixture's trust anchor.
  ota::trust::ImageDescriptor buildAndProgramValidDescriptor(uint32_t counter_value) {
    ASSERT_TRUE_OR_RETURN(ota::platform::isOk(
        candidate_region_->program(0, candidate_image_.data(), (uint32_t)candidate_image_.size())));

    ota::trust::ImageDescriptor descriptor;
    ota::trust::Sha256::hash(candidate_image_.data(), candidate_image_.size(), descriptor.image_hash_sha256);
    descriptor.target_id = anchor_.expected_target_id;
    descriptor.role_id = anchor_.expected_role_id;
    descriptor.device_address = anchor_.device_address;
    descriptor.allow_broadcast_address = false;
    descriptor.required_boot_capability_flags = 0;
    descriptor.monotonic_counter = counter_value;
    descriptor.image_size_bytes = (uint32_t)candidate_image_.size();

    uint8_t message[ota::trust::CanonicalDescriptor::kMessageBytes];
    size_t written = ota::trust::CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
    signer_->sign(message, written, descriptor.signature_ed25519);
    return descriptor;
  }

  std::unique_ptr<FakeNorFlash> candidate_flash_, backup_flash_, target_flash_, journal_flash_;
  std::unique_ptr<FlashRegion> candidate_region_, backup_region_, target_region_, journal_region_;
  std::unique_ptr<Journal> journal_;
  std::unique_ptr<ota::test::Ed25519TestSigner> signer_;
  ota::trust::DeviceTrustAnchor anchor_;
  std::unique_ptr<ota::test::FakeMonotonicCounter> counter_;
  std::unique_ptr<ota::trust::Sha256> hasher_;
  std::unique_ptr<ota::trust::Ed25519SignatureVerifier> sig_verifier_;
  std::unique_ptr<ota::trust::DescriptorVerifier> verifier_;
  std::vector<uint8_t> target_image_;
  std::vector<uint8_t> candidate_image_;
};

}  // namespace

// -----------------------------------------------------------------------
// Core erase-gating invariant.
// -----------------------------------------------------------------------

TEST(BootTransactionApiTest, BackupApiTakesNoCallerSuppliedLength) {
  bool (BootTransaction::*backup_method)() = &BootTransaction::backupTarget;
  EXPECT_TRUE((std::is_same<decltype(backup_method), bool (BootTransaction::*)()>::value));
}

TEST(BootTransactionApiTest, InstallApiRequiresVerifierRatherThanCallerSuppliedLength) {
  bool (BootTransaction::*install_method)(ota::trust::DescriptorVerifier&) =
      &BootTransaction::installCandidateToTarget;
  EXPECT_TRUE((std::is_same<decltype(install_method),
                            bool (BootTransaction::*)(ota::trust::DescriptorVerifier&)>::value));
}

TEST(BootTransactionApiTest, ConstructorDoesNotAcceptCallerSuppliedRunningImageLength) {
  EXPECT_TRUE((std::is_constructible<BootTransaction, Journal&, uint32_t, FlashRegion&, FlashRegion&,
                                     FlashRegion&>::value));
  EXPECT_FALSE((std::is_constructible<BootTransaction, Journal&, uint32_t, FlashRegion&, FlashRegion&,
                                      FlashRegion&, uint32_t>::value));
}

TEST_F(BootTransactionFixture, InstallRejectedWithoutAuthenticationOrBackupTouchesNoFlash) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);

  const uint32_t erase_count_before = target_flash_->eraseOpCount();
  EXPECT_FALSE(txn.installCandidateToTarget(*verifier_));
  EXPECT_EQ(target_flash_->eraseOpCount(), erase_count_before) << "target must not be touched without auth+backup";
  EXPECT_EQ(txn.phase(), BootTransaction::Phase::Idle);
}

TEST_F(BootTransactionFixture, InstallRejectedWithBackupButNoAuthentication) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(txn.backupTarget());
  ASSERT_TRUE(txn.backupVerified());

  const uint32_t erase_count_before = target_flash_->eraseOpCount();
  EXPECT_FALSE(txn.installCandidateToTarget(*verifier_));
  EXPECT_EQ(target_flash_->eraseOpCount(), erase_count_before);
}

TEST_F(BootTransactionFixture, InstallRejectedWithAuthenticationButNoBackup) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);
  ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
  ASSERT_TRUE(txn.candidateAuthenticated());

  const uint32_t erase_count_before = target_flash_->eraseOpCount();
  EXPECT_FALSE(txn.installCandidateToTarget(*verifier_));
  EXPECT_EQ(target_flash_->eraseOpCount(), erase_count_before);
}

TEST_F(BootTransactionFixture, InstallSucceedsOnlyAfterBothAuthenticationAndBackup) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);

  ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
  ASSERT_TRUE(txn.backupTarget());
  EXPECT_TRUE(txn.installCandidateToTarget(*verifier_));
  EXPECT_EQ(txn.phase(), BootTransaction::Phase::InstallVerified);

  std::vector<uint8_t> readback(kTargetSize);
  ASSERT_TRUE(ota::platform::isOk(target_region_->read(0, readback.data(), kTargetSize)));
  EXPECT_EQ(0, std::memcmp(readback.data(), candidate_image_.data(), kTargetSize));
}

TEST_F(BootTransactionFixture, RecoveryRejectsBackupTargetToPreserveVerifiedBackup) {
  const uint32_t campaign_id = 21;
  BootTransaction txn(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);
  ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
  ASSERT_TRUE(txn.backupTarget());

  std::vector<uint8_t> backup_before(kTargetSize);
  ASSERT_TRUE(ota::platform::isOk(backup_region_->read(0, backup_before.data(), kTargetSize)));

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Program;
  fault.timing = FakeNorFlash::InjectionTiming::Mid;
  fault.trigger_op_count = target_flash_->programOpCount() + 1;
  fault.partial_bytes = 17;
  target_flash_->armFault(fault);
  ASSERT_FALSE(txn.installCandidateToTarget(*verifier_));
  ASSERT_EQ(txn.phase(), BootTransaction::Phase::Recovery);
  target_flash_->clearFault();

  EXPECT_FALSE(txn.backupTarget());
  std::vector<uint8_t> backup_after(kTargetSize);
  ASSERT_TRUE(ota::platform::isOk(backup_region_->read(0, backup_after.data(), kTargetSize)));
  EXPECT_EQ(0, std::memcmp(backup_before.data(), backup_after.data(), kTargetSize));
}

TEST_F(BootTransactionFixture, RecoveryAuthenticateThenBackupStillRejectedAndPersistsAfterReboot) {
  const uint32_t campaign_id = 22;
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);
  std::vector<uint8_t> backup_before(kTargetSize);

  {
    BootTransaction txn(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
    ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
    ASSERT_TRUE(txn.backupTarget());
    ASSERT_TRUE(ota::platform::isOk(backup_region_->read(0, backup_before.data(), kTargetSize)));

    FakeNorFlash::FaultSpec fault;
    fault.kind = FakeNorFlash::OpKind::Program;
    fault.timing = FakeNorFlash::InjectionTiming::Mid;
    fault.trigger_op_count = target_flash_->programOpCount() + 1;
    fault.partial_bytes = 23;
    target_flash_->armFault(fault);
    ASSERT_FALSE(txn.installCandidateToTarget(*verifier_));
    ASSERT_EQ(txn.phase(), BootTransaction::Phase::Recovery);
    target_flash_->clearFault();

    ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
    EXPECT_EQ(txn.phase(), BootTransaction::Phase::CandidateAuthenticated);
    EXPECT_FALSE(txn.backupTarget());
  }

  BootTransaction recovered(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(recovered.recoverFromJournal());
  EXPECT_EQ(recovered.phase(), BootTransaction::Phase::CandidateAuthenticated);
  EXPECT_FALSE(recovered.backupTarget());

  std::vector<uint8_t> backup_after(kTargetSize);
  ASSERT_TRUE(ota::platform::isOk(backup_region_->read(0, backup_after.data(), kTargetSize)));
  EXPECT_EQ(0, std::memcmp(backup_before.data(), backup_after.data(), kTargetSize));
}

TEST_F(BootTransactionFixture, InstallRejectsRecoveredUndersizedBackupProgressBeforeTargetErase) {
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);

  JournalCheckpoint cp;
  cp.campaign_id = 23;
  cp.phase = static_cast<uint8_t>(BootTransaction::Phase::BackupVerified);
  cp.backup_progress_bytes = 1;
  cp.descriptor_monotonic_counter = descriptor.monotonic_counter;
  ASSERT_TRUE(journal_->writeCheckpoint(cp));

  BootTransaction recovered(*journal_, 23, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(recovered.recoverFromJournal());
  ASSERT_TRUE(recovered.backupVerified());
  ASSERT_TRUE(recovered.authenticateCandidate(*verifier_, descriptor));

  const uint32_t erase_count_before = target_flash_->eraseOpCount();
  EXPECT_FALSE(recovered.installCandidateToTarget(*verifier_));
  EXPECT_EQ(target_flash_->eraseOpCount(), erase_count_before);
}

TEST_F(BootTransactionFixture, RollbackRejectsRecoveredUndersizedBackupBeforeTargetErase) {
  JournalCheckpoint cp;
  cp.campaign_id = 26;
  cp.phase = static_cast<uint8_t>(BootTransaction::Phase::Recovery);
  cp.backup_progress_bytes = 1;
  cp.target_image_intact = 0;
  ASSERT_TRUE(journal_->writeCheckpoint(cp));

  BootTransaction recovered(*journal_, 26, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(recovered.recoverFromJournal());
  ASSERT_EQ(recovered.phase(), BootTransaction::Phase::Recovery);
  ASSERT_TRUE(recovered.backupVerified());

  const uint32_t erase_count_before = target_flash_->eraseOpCount();
  EXPECT_FALSE(recovered.rollbackToBackup());
  EXPECT_EQ(target_flash_->eraseOpCount(), erase_count_before);
}

TEST_F(BootTransactionFixture, InstallRehashesCandidateImmediatelyBeforeTargetErase) {
  BootTransaction txn(*journal_, 24, *candidate_region_, *backup_region_, *target_region_);
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);
  ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
  ASSERT_TRUE(txn.backupTarget());

  std::vector<uint8_t> first_sector(candidate_image_.begin(), candidate_image_.begin() + 4096);
  first_sector[0] ^= 0xFFu;
  ASSERT_TRUE(ota::platform::isOk(candidate_region_->eraseRange(0, 4096)));
  ASSERT_TRUE(ota::platform::isOk(candidate_region_->program(0, first_sector.data(), 4096)));

  const uint32_t erase_count_before = target_flash_->eraseOpCount();
  EXPECT_FALSE(txn.installCandidateToTarget(*verifier_));
  EXPECT_EQ(target_flash_->eraseOpCount(), erase_count_before);
  EXPECT_FALSE(txn.candidateAuthenticated());
}

TEST_F(BootTransactionFixture, InstallUsesSignedDescriptorLengthRatherThanCallerLength) {
  BootTransaction txn(*journal_, 25, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(ota::platform::isOk(
      candidate_region_->program(0, candidate_image_.data(), (uint32_t)candidate_image_.size())));

  ota::trust::ImageDescriptor descriptor;
  const uint32_t signed_size = kCandidateSize / 2;
  ota::trust::Sha256::hash(candidate_image_.data(), signed_size, descriptor.image_hash_sha256);
  descriptor.target_id = anchor_.expected_target_id;
  descriptor.role_id = anchor_.expected_role_id;
  descriptor.device_address = anchor_.device_address;
  descriptor.allow_broadcast_address = false;
  descriptor.required_boot_capability_flags = 0;
  descriptor.monotonic_counter = 1;
  descriptor.image_size_bytes = signed_size;

  uint8_t message[ota::trust::CanonicalDescriptor::kMessageBytes];
  size_t written = ota::trust::CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
  signer_->sign(message, written, descriptor.signature_ed25519);

  ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
  ASSERT_TRUE(txn.backupTarget());
  ASSERT_TRUE(txn.installCandidateToTarget(*verifier_));
  EXPECT_EQ(txn.installProgressBytes(), signed_size);
  EXPECT_EQ(txn.phase(), BootTransaction::Phase::InstallVerified);
}

// -----------------------------------------------------------------------
// Trust-pipeline rejection scenarios (via the boot transaction).
// -----------------------------------------------------------------------

TEST_F(BootTransactionFixture, CandidateCorruptionFailsAuthentication) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);

  // Corrupt one candidate byte AFTER the descriptor was computed over the
  // original bytes.
  uint8_t one_byte = candidate_image_[0] ^ 0xFF;
  ASSERT_TRUE(ota::platform::isOk(candidate_region_->eraseRange(0, 4096)));
  candidate_image_[0] = one_byte;  // keep the in-memory model consistent for re-reads below (unused otherwise)
  ASSERT_TRUE(ota::platform::isOk(candidate_region_->program(0, &one_byte, 1)));
  // Restore remaining bytes since we erased a whole sector.
  ASSERT_TRUE(ota::platform::isOk(
      candidate_region_->program(1, candidate_image_.data() + 1, 4095)));

  EXPECT_FALSE(txn.authenticateCandidate(*verifier_, descriptor));
  EXPECT_FALSE(txn.candidateAuthenticated());
  EXPECT_EQ(txn.phase(), BootTransaction::Phase::Idle);
}

TEST_F(BootTransactionFixture, WrongTargetIdFailsAuthentication) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);
  descriptor.target_id = anchor_.expected_target_id + 1;
  // Re-sign so only the target-id check can fail (mutating after signing
  // would otherwise just fail on signature).
  uint8_t message[ota::trust::CanonicalDescriptor::kMessageBytes];
  size_t written = ota::trust::CanonicalDescriptor::serialize(descriptor, message, sizeof(message));
  signer_->sign(message, written, descriptor.signature_ed25519);

  EXPECT_FALSE(txn.authenticateCandidate(*verifier_, descriptor));
  EXPECT_FALSE(txn.candidateAuthenticated());
}

TEST_F(BootTransactionFixture, DowngradeCounterFailsAuthentication) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(counter_->commitNewValue(5));
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(3);  // < current committed value

  EXPECT_FALSE(txn.authenticateCandidate(*verifier_, descriptor));
}

TEST_F(BootTransactionFixture, BackupCorruptionIsDetectedByVerification) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(txn.backupTarget());
  ASSERT_TRUE(txn.backupVerified());

  // Directly corrupt the backup medium underneath the transaction (models
  // e.g. a bit-flip in the backup partition discovered by a later
  // integrity re-check), and confirm the corruption is detectable via a
  // plain region compare -- StorageManager::regionsEqual is the same
  // primitive backupTarget() itself uses to certify `backup_verified_`.
  std::vector<uint8_t> raw(backup_flash_->rawBuffer(), backup_flash_->rawBuffer() + backup_flash_->rawSize());
  raw[0] ^= 0xFF;
  ASSERT_TRUE(ota::platform::isOk(backup_region_->eraseRange(0, 4096)));
  ASSERT_TRUE(ota::platform::isOk(backup_region_->program(0, raw.data(), 4096)));

  EXPECT_FALSE(ota::storage::StorageManager::regionsEqual(*target_region_, *backup_region_, kTargetSize));
}

// -----------------------------------------------------------------------
// Full lifecycle: backup -> install -> trial -> confirm.
// -----------------------------------------------------------------------

TEST_F(BootTransactionFixture, FullLifecycleConfirmsSuccessfully) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);

  ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
  ASSERT_TRUE(txn.backupTarget());
  ASSERT_TRUE(txn.installCandidateToTarget(*verifier_));
  ASSERT_TRUE(txn.enterTrial());
  EXPECT_EQ(txn.phase(), BootTransaction::Phase::Trial);

  ASSERT_TRUE(txn.confirmTrial(*verifier_));
  EXPECT_EQ(txn.phase(), BootTransaction::Phase::Confirmed);

  uint32_t committed = 0;
  ASSERT_TRUE(counter_->currentValue(committed));
  EXPECT_EQ(committed, 1u);
}

TEST_F(BootTransactionFixture, RecoveredTrialConfirmsUsingPersistedDescriptorCounter) {
  const uint32_t campaign_id = 31;
  {
    BootTransaction txn(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
    ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(7);
    ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
    ASSERT_TRUE(txn.backupTarget());
    ASSERT_TRUE(txn.installCandidateToTarget(*verifier_));
    ASSERT_TRUE(txn.enterTrial());
  }

  BootTransaction recovered(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(recovered.recoverFromJournal());
  ASSERT_EQ(recovered.phase(), BootTransaction::Phase::Trial);
  ASSERT_TRUE(recovered.confirmTrial(*verifier_));
  EXPECT_EQ(recovered.phase(), BootTransaction::Phase::Confirmed);

  uint32_t committed = 0;
  ASSERT_TRUE(counter_->currentValue(committed));
  EXPECT_EQ(committed, 7u);
}

TEST_F(BootTransactionFixture, ConfirmTrialDoesNotCommitCounterIfPendingCheckpointFails) {
  BootTransaction txn(*journal_, 32, *candidate_region_, *backup_region_, *target_region_);
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);
  ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
  ASSERT_TRUE(txn.backupTarget());
  ASSERT_TRUE(txn.installCandidateToTarget(*verifier_));
  ASSERT_TRUE(txn.enterTrial());

  FakeNorFlash::FaultSpec fault;
  fault.kind = FakeNorFlash::OpKind::Program;
  fault.timing = FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = journal_flash_->programOpCount() + 1;
  journal_flash_->armFault(fault);

  EXPECT_FALSE(txn.confirmTrial(*verifier_));
  EXPECT_EQ(txn.phase(), BootTransaction::Phase::Trial);
  uint32_t committed = 99;
  ASSERT_TRUE(counter_->currentValue(committed));
  EXPECT_EQ(committed, 0u);
}

TEST_F(BootTransactionFixture, ConfirmTrialPendingBeforeCommitStartCanRecoverAndRollback) {
  const uint32_t campaign_id = 33;
  {
    BootTransaction txn(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
    ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(2);
    ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
    ASSERT_TRUE(txn.backupTarget());
    ASSERT_TRUE(txn.installCandidateToTarget(*verifier_));
    ASSERT_TRUE(txn.enterTrial());

    FakeNorFlash::FaultSpec fault;
    fault.kind = FakeNorFlash::OpKind::Program;
    fault.timing = FakeNorFlash::InjectionTiming::Before;
    fault.trigger_op_count = journal_flash_->programOpCount() + 3;
    journal_flash_->armFault(fault);

    EXPECT_FALSE(txn.confirmTrial(*verifier_));
    EXPECT_EQ(txn.phase(), BootTransaction::Phase::CounterCommitPending);
  }

  journal_flash_->clearFault();
  counter_->setAvailable(false);
  BootTransaction recovered(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(recovered.recoverFromJournal());
  EXPECT_EQ(recovered.phase(), BootTransaction::Phase::CounterCommitPending);
  ASSERT_TRUE(recovered.rollbackToBackup());
  EXPECT_EQ(recovered.phase(), BootTransaction::Phase::RolledBack);

  std::vector<uint8_t> readback(kTargetSize);
  ASSERT_TRUE(ota::platform::isOk(target_region_->read(0, readback.data(), kTargetSize)));
  EXPECT_EQ(0, std::memcmp(readback.data(), target_image_.data(), kTargetSize));
  counter_->setAvailable(true);
  uint32_t committed = 0;
  ASSERT_TRUE(counter_->currentValue(committed));
  EXPECT_EQ(committed, 0u);
}

TEST_F(BootTransactionFixture, ConfirmTrialCommitFailureRevertsToTrialAndCanRetryWhenHealthy) {
  const uint32_t campaign_id = 35;
  BootTransaction txn(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(4);
  ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
  ASSERT_TRUE(txn.backupTarget());
  ASSERT_TRUE(txn.installCandidateToTarget(*verifier_));
  ASSERT_TRUE(txn.enterTrial());

  counter_->setAvailable(false);
  EXPECT_FALSE(txn.confirmTrial(*verifier_));
  EXPECT_EQ(txn.phase(), BootTransaction::Phase::Trial);

  counter_->setAvailable(true);
  ASSERT_TRUE(txn.confirmTrial(*verifier_));
  uint32_t committed = 0;
  ASSERT_TRUE(counter_->currentValue(committed));
  EXPECT_EQ(committed, 4u);
}

TEST_F(BootTransactionFixture, ConfirmTrialRecoversWhenCounterCommittedButConfirmedCheckpointFails) {
  const uint32_t campaign_id = 34;
  {
    BootTransaction txn(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
    ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(3);
    ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
    ASSERT_TRUE(txn.backupTarget());
    ASSERT_TRUE(txn.installCandidateToTarget(*verifier_));
    ASSERT_TRUE(txn.enterTrial());

    FakeNorFlash::FaultSpec fault;
    fault.kind = FakeNorFlash::OpKind::Program;
    fault.timing = FakeNorFlash::InjectionTiming::Before;
    fault.trigger_op_count = journal_flash_->programOpCount() + 5;
    journal_flash_->armFault(fault);

    EXPECT_FALSE(txn.confirmTrial(*verifier_));
    EXPECT_EQ(txn.phase(), BootTransaction::Phase::CounterCommitPending);
  }

  journal_flash_->clearFault();
  uint32_t committed = 0;
  ASSERT_TRUE(counter_->currentValue(committed));
  EXPECT_EQ(committed, 3u);

  BootTransaction recovered(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(recovered.recoverFromJournal());
  EXPECT_EQ(recovered.phase(), BootTransaction::Phase::CounterCommitPending);
  EXPECT_FALSE(recovered.rollbackToBackup(verifier_.get()));
  ASSERT_TRUE(recovered.confirmTrial(*verifier_));
  EXPECT_EQ(recovered.phase(), BootTransaction::Phase::Confirmed);
}

TEST_F(BootTransactionFixture, EnterTrialRejectedBeforeInstallVerified) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);
  EXPECT_FALSE(txn.enterTrial());
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);
  ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
  EXPECT_FALSE(txn.enterTrial());
  ASSERT_TRUE(txn.backupTarget());
  EXPECT_FALSE(txn.enterTrial());
}

TEST_F(BootTransactionFixture, ConfirmTrialRejectedWithoutTrial) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);
  EXPECT_FALSE(txn.confirmTrial(*verifier_));
}

// -----------------------------------------------------------------------
// Unconfirmed-trial rollback.
// -----------------------------------------------------------------------

TEST_F(BootTransactionFixture, UnconfirmedTrialRollsBackToOriginalImage) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);
  ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);

  ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
  ASSERT_TRUE(txn.backupTarget());
  ASSERT_TRUE(txn.installCandidateToTarget(*verifier_));
  ASSERT_TRUE(txn.enterTrial());

  // Trial never confirmed (e.g. new image failed to boot cleanly) --
  // caller invokes rollback instead.
  ASSERT_TRUE(txn.rollbackToBackup());
  EXPECT_EQ(txn.phase(), BootTransaction::Phase::RolledBack);

  std::vector<uint8_t> readback(kTargetSize);
  ASSERT_TRUE(ota::platform::isOk(target_region_->read(0, readback.data(), kTargetSize)));
  EXPECT_EQ(0, std::memcmp(readback.data(), target_image_.data(), kTargetSize));

  // The counter must NOT have been committed -- an unconfirmed trial must
  // never advance the anti-rollback floor.
  uint32_t committed = 0;
  ASSERT_TRUE(counter_->currentValue(committed));
  EXPECT_EQ(committed, 0u);
}

TEST_F(BootTransactionFixture, RollbackRejectedOutsideTrialOrRecovery) {
  BootTransaction txn(*journal_, 1, *candidate_region_, *backup_region_, *target_region_);
  EXPECT_FALSE(txn.rollbackToBackup());  // Idle
  ASSERT_TRUE(txn.backupTarget());
  EXPECT_FALSE(txn.rollbackToBackup());  // BackupVerified, not Trial/Recovery
}

// -----------------------------------------------------------------------
// Crash-consistent recovery around each destructive-step cut point.
// -----------------------------------------------------------------------

TEST_F(BootTransactionFixture, CrashMidBackupRecoversAsRetryableBackupInProgress) {
  {
    BootTransaction txn(*journal_, 7, *candidate_region_, *backup_region_, *target_region_);
    FakeNorFlash::FaultSpec fault;
    fault.kind = FakeNorFlash::OpKind::Program;
    fault.timing = FakeNorFlash::InjectionTiming::Mid;
    fault.trigger_op_count = backup_flash_->programOpCount() + 1;
    fault.partial_bytes = 50;
    backup_flash_->armFault(fault);

    EXPECT_FALSE(txn.backupTarget());
    EXPECT_EQ(txn.phase(), BootTransaction::Phase::BackupInProgress);
    EXPECT_FALSE(txn.backupVerified());
  }

  // Simulate a reset: fresh transaction object, recover state from journal.
  backup_flash_->clearFault();
  BootTransaction recovered(*journal_, 7, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(recovered.recoverFromJournal());
  EXPECT_EQ(recovered.phase(), BootTransaction::Phase::BackupInProgress);
  EXPECT_FALSE(recovered.backupVerified());

  // Target must be completely untouched by the interrupted backup attempt.
  std::vector<uint8_t> readback(kTargetSize);
  ASSERT_TRUE(ota::platform::isOk(target_region_->read(0, readback.data(), kTargetSize)));
  EXPECT_EQ(0, std::memcmp(readback.data(), target_image_.data(), kTargetSize));

  // Retry succeeds cleanly.
  ASSERT_TRUE(recovered.backupTarget());
  EXPECT_TRUE(recovered.backupVerified());
}

TEST_F(BootTransactionFixture, CrashMidInstallRecoversIntoRecoveryAndRollbackSucceeds) {
  uint32_t campaign_id = 11;
  {
    BootTransaction txn(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
    ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);
    ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
    ASSERT_TRUE(txn.backupTarget());

    FakeNorFlash::FaultSpec fault;
    fault.kind = FakeNorFlash::OpKind::Program;
    fault.timing = FakeNorFlash::InjectionTiming::Mid;
    fault.trigger_op_count = target_flash_->programOpCount() + 1;
    fault.partial_bytes = 37;
    target_flash_->armFault(fault);

    EXPECT_FALSE(txn.installCandidateToTarget(*verifier_));
    EXPECT_EQ(txn.phase(), BootTransaction::Phase::Recovery);
  }

  target_flash_->clearFault();
  BootTransaction recovered(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(recovered.recoverFromJournal());
  EXPECT_EQ(recovered.phase(), BootTransaction::Phase::Recovery);
  EXPECT_TRUE(recovered.backupVerified());
  EXPECT_FALSE(recovered.candidateAuthenticated());  // must require live re-authentication

  // Never silently "confirmed" or left bricked -- rollback is available
  // and restores the original image.
  ASSERT_TRUE(recovered.rollbackToBackup());
  EXPECT_EQ(recovered.phase(), BootTransaction::Phase::RolledBack);

  std::vector<uint8_t> readback(kTargetSize);
  ASSERT_TRUE(ota::platform::isOk(target_region_->read(0, readback.data(), kTargetSize)));
  EXPECT_EQ(0, std::memcmp(readback.data(), target_image_.data(), kTargetSize));
}

TEST_F(BootTransactionFixture, CrashAfterInstallVerifiedButBeforeTrialRecoversCleanly) {
  uint32_t campaign_id = 13;
  {
    BootTransaction txn(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
    ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);
    ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
    ASSERT_TRUE(txn.backupTarget());
    ASSERT_TRUE(txn.installCandidateToTarget(*verifier_));
    EXPECT_EQ(txn.phase(), BootTransaction::Phase::InstallVerified);
    // (simulated reset here, before enterTrial() was ever called)
  }

  BootTransaction recovered(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(recovered.recoverFromJournal());
  EXPECT_EQ(recovered.phase(), BootTransaction::Phase::InstallVerified);
  EXPECT_TRUE(recovered.backupVerified());

  // The install was fully verified before the crash -- proceeding to trial
  // is safe and must not be blocked by recovery.
  EXPECT_TRUE(recovered.enterTrial());
}

TEST_F(BootTransactionFixture, CrashMidRollbackRecoversIntoRecoveryAndCanRetry) {
  uint32_t campaign_id = 17;
  {
    BootTransaction txn(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
    ota::trust::ImageDescriptor descriptor = buildAndProgramValidDescriptor(1);
    ASSERT_TRUE(txn.authenticateCandidate(*verifier_, descriptor));
    ASSERT_TRUE(txn.backupTarget());
    ASSERT_TRUE(txn.installCandidateToTarget(*verifier_));
    ASSERT_TRUE(txn.enterTrial());

    FakeNorFlash::FaultSpec fault;
    fault.kind = FakeNorFlash::OpKind::Program;
    fault.timing = FakeNorFlash::InjectionTiming::Mid;
    fault.trigger_op_count = target_flash_->programOpCount() + 1;
    fault.partial_bytes = 20;
    target_flash_->armFault(fault);

    EXPECT_FALSE(txn.rollbackToBackup());
  }

  target_flash_->clearFault();
  BootTransaction recovered(*journal_, campaign_id, *candidate_region_, *backup_region_, *target_region_);
  ASSERT_TRUE(recovered.recoverFromJournal());
  EXPECT_EQ(recovered.phase(), BootTransaction::Phase::Recovery);
  EXPECT_TRUE(recovered.backupVerified());

  ASSERT_TRUE(recovered.rollbackToBackup());
  EXPECT_EQ(recovered.phase(), BootTransaction::Phase::RolledBack);
  std::vector<uint8_t> readback(kTargetSize);
  ASSERT_TRUE(ota::platform::isOk(target_region_->read(0, readback.data(), kTargetSize)));
  EXPECT_EQ(0, std::memcmp(readback.data(), target_image_.data(), kTargetSize));
}

TEST_F(BootTransactionFixture, RecoverFromJournalFailsWithNoPriorCheckpoint) {
  BootTransaction txn(*journal_, 999, *candidate_region_, *backup_region_, *target_region_);
  EXPECT_FALSE(txn.recoverFromJournal());
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
