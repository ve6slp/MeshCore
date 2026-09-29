#pragma once

// Portable boot transaction state machine enforcing the core OTA security
// floor: the internal application ("target") partition can NEVER be erased
// until (a) the candidate image has been authenticated via the trust
// pipeline AND (b) a complete, byte-verified backup of the current target
// image exists. This invariant is enforced by a single guard at the top of
// `installCandidateToTarget()` -- the only method in this class that ever
// erases `target_region_` -- and is checked before any flash access is
// even attempted, so a rejected call leaves the target partition
// completely untouched.
//
// States: Idle -> CandidateAuthenticated / BackupInProgress -> BackupVerified
//         -> InstallInProgress -> InstallVerified -> Trial -> Confirmed
//                                                  \-> RollingBack -> RolledBack
//         (any destructive step interrupted by a crash recovers into
//          Recovery, from which only a safe rollback or a fresh,
//          fully re-authenticated re-install is possible -- never a blind
//          resume of a partially-completed erase/copy).
//
// Crash consistency: every phase transition is durably checkpointed via
// `storage::Journal` (write -> readback-verify -> commit-marker ordering)
// BEFORE the corresponding flash-destructive step begins, so a reset at
// any point can always be classified into one of: "destructive step never
// started" (safe to retry), "destructive step interrupted" (forced into
// Recovery, backup is still known-intact), or "destructive step completed
// and verified" (safe to proceed). Header-only so it can be consumed
// directly by PlatformIO's native unit tests without any build-config
// change.

#include <stdint.h>

#include "ota/platform/FlashRegion.h"
#include "ota/platform/FlashTypes.h"
#include "ota/storage/Journal.h"
#include "ota/storage/StorageManager.h"
#include "ota/trust/DescriptorVerifier.h"
#include "ota/trust/TrustTypes.h"

namespace ota {
namespace boot {

class BootTransaction {
public:
  enum class Phase : uint8_t {
    Idle = 0,
    CandidateAuthenticated = 1,
    BackupInProgress = 2,
    BackupVerified = 3,
    InstallInProgress = 4,
    InstallVerified = 5,
    Trial = 6,
    Confirmed = 7,
    RollingBack = 8,
    RolledBack = 9,
    Recovery = 10,
    CounterCommitPending = 11,
  };

  // `journal` provides durable, crash-consistent checkpointing for this
  // transaction; it may be a dedicated journal instance/region or shared
  // with the storage layer's chunk-receipt journal on real hardware, as
  // long as `campaign_id` uniquely scopes this transaction's records.
  BootTransaction(storage::Journal& journal, uint32_t campaign_id,
                  platform::FlashRegion& candidate_region, platform::FlashRegion& backup_region,
                  platform::FlashRegion& target_region)
      : journal_(journal),
        campaign_id_(campaign_id),
        candidate_region_(candidate_region),
        backup_region_(backup_region),
        target_region_(target_region),
        running_image_size_bytes_(target_region.sizeBytes()) {}

  Phase phase() const { return phase_; }
  bool candidateAuthenticated() const { return candidate_authenticated_; }
  bool backupVerified() const { return backup_verified_; }
  uint32_t backupProgressBytes() const { return backup_progress_; }
  uint32_t installProgressBytes() const { return install_progress_; }

  // Step 1: runs the full trust pipeline (signature, target/role/address,
  // boot capability, anti-rollback counter, and image hash) against the
  // candidate partition. Only on a full pass does this durably record
  // that authentication occurred, which is one of the two preconditions
  // `installCandidateToTarget()` checks.
  bool authenticateCandidate(trust::DescriptorVerifier& verifier, const trust::ImageDescriptor& descriptor) {
    if (!canAuthenticateFromCurrentPhase()) {
      return false;
    }
    trust::VerificationResult result = verifier.verifyAll(descriptor, candidate_region_);
    if (!result.ok) {
      candidate_authenticated_ = false;
      return false;
    }
    candidate_authenticated_ = true;
    descriptor_ = descriptor;
    phase_ = Phase::CandidateAuthenticated;
    if (!checkpoint()) {
      candidate_authenticated_ = false;
      phase_ = target_known_intact_ ? Phase::Idle : Phase::Recovery;
      descriptor_ = trust::ImageDescriptor();
      return false;
    }
    return true;
  }

  // Step 2: durable, verified backup of the CURRENT target image into the
  // backup partition. This step never touches `target_region_` -- only
  // `backup_region_` is erased/written -- so it can safely be retried
  // after any interruption without any risk to the running firmware.
  bool backupTarget() {
    if (!trustedRunningImageExtentIsValid() || !target_known_intact_ || !canBackupFromCurrentPhase()) {
      return false;
    }

    backup_verified_ = false;
    backup_progress_ = 0;
    phase_ = Phase::BackupInProgress;
    if (!checkpoint()) {
      return false;
    }

    if (!platform::isOk(backup_region_.eraseRange(0, backup_region_.sizeBytes()))) {
      checkpoint();  // stay in BackupInProgress -- target untouched, safe to retry
      return false;
    }

    uint32_t progress = 0;
    if (!storage::StorageManager::copyRangeVerified(target_region_, backup_region_, running_image_size_bytes_, 0,
                                                      progress)) {
      backup_progress_ = progress;
      checkpoint();
      return false;
    }
    if (!storage::StorageManager::regionsEqual(target_region_, backup_region_, running_image_size_bytes_)) {
      return false;
    }

    backup_progress_ = running_image_size_bytes_;
    backup_verified_ = true;
    phase_ = Phase::BackupVerified;
    if (!checkpoint()) {
      backup_verified_ = false;
      phase_ = Phase::BackupInProgress;
      return false;
    }
    return true;
  }

  // Step 3: THE gated destructive operation, and the only method in this
  // class that ever erases `target_region_`. Returns false, without
  // performing any flash access whatsoever, unless BOTH
  // `candidate_authenticated_` and `backup_verified_` are already true.
  bool installCandidateToTarget(trust::DescriptorVerifier& verifier) {
    if (!candidate_authenticated_ || !backup_verified_ || backup_progress_ != running_image_size_bytes_) {
      return false;  // GUARD: no erase, program, or read is issued.
    }
    if (!trustedRunningImageExtentIsValid()) {
      return false;
    }
    if (descriptor_.image_size_bytes == 0 || descriptor_.image_size_bytes > target_region_.sizeBytes() ||
        descriptor_.image_size_bytes > candidate_region_.sizeBytes()) {
      return false;
    }
    trust::VerificationResult live_result = verifier.verifyAll(descriptor_, candidate_region_);
    if (!live_result.ok) {
      candidate_authenticated_ = false;
      return false;
    }

    const Phase phase_before_install_checkpoint = phase_;
    const bool target_known_intact_before_install_checkpoint = target_known_intact_;
    target_known_intact_ = false;
    phase_ = Phase::InstallInProgress;
    if (!checkpoint()) {
      target_known_intact_ = target_known_intact_before_install_checkpoint;
      phase_ = phase_before_install_checkpoint;
      return false;
    }

    if (!platform::isOk(target_region_.eraseRange(0, target_region_.sizeBytes()))) {
      // Target partition may now be partially erased. Backup is already
      // known-verified (the guard above required it), so this is always
      // recoverable via rollback, never a silent brick.
      phase_ = Phase::Recovery;
      checkpoint();
      return false;
    }

    uint32_t progress = 0;
    if (!storage::StorageManager::copyRangeVerified(candidate_region_, target_region_, descriptor_.image_size_bytes, 0,
                                                      progress)) {
      install_progress_ = progress;
      phase_ = Phase::Recovery;
      checkpoint();
      return false;
    }
    if (!storage::StorageManager::regionsEqual(candidate_region_, target_region_, descriptor_.image_size_bytes)) {
      phase_ = Phase::Recovery;
      checkpoint();
      return false;
    }

    install_progress_ = descriptor_.image_size_bytes;
    phase_ = Phase::InstallVerified;
    return checkpoint();
  }

  // Step 4: transition into the trial phase. In real firmware this
  // precedes an actual reboot into the newly installed image; here it is
  // a durable state transition only reachable from a verified install.
  bool enterTrial() {
    if (phase_ != Phase::InstallVerified) {
      return false;
    }
    phase_ = Phase::Trial;
    return checkpoint();
  }

  // Step 5: the trial image self-reported healthy. Commits the
  // descriptor's monotonic (anti-rollback) counter as the new floor --
  // deliberately only reachable from Trial, never merely after
  // authentication/verification, so a device that never actually boots
  // the new image cannot be locked out of retrying an older-but-still-
  // valid campaign.
  bool confirmTrial(trust::DescriptorVerifier& verifier) {
    if (phase_ != Phase::Trial && phase_ != Phase::CounterCommitPending) {
      return false;
    }
    if (descriptor_.monotonic_counter == 0) {
      return false;
    }
    if (phase_ == Phase::Trial) {
      counter_commit_started_ = false;
      phase_ = Phase::CounterCommitPending;
      if (!checkpoint()) {
        phase_ = Phase::Trial;
        return false;
      }
    }
    if (!verifier.counterAtLeast(descriptor_.monotonic_counter)) {
      if (!counter_commit_started_) {
        counter_commit_started_ = true;
        if (!checkpoint()) {
          counter_commit_started_ = false;
          return false;
        }
      }
      if (!verifier.commitCounter(descriptor_)) {
        counter_commit_started_ = false;
        phase_ = Phase::Trial;
        checkpoint();
        return false;
      }
    }
    counter_commit_started_ = true;
    phase_ = Phase::Confirmed;
    if (!checkpoint()) {
      phase_ = Phase::CounterCommitPending;
      return false;
    }
    return true;
  }

  // Step 6: restore the backed-up image into the target partition. Valid
  // from Trial (an unconfirmed trial that must not be left running) or
  // Recovery (an install interrupted after the destructive erase step).
  // In both cases `backup_verified_` is guaranteed true, because
  // `installCandidateToTarget()` never runs without it, and rollback never
  // modifies `backup_region_` itself, only reads from it -- so this
  // operation is always safe to retry after yet another interruption.
  bool rollbackToBackup(trust::DescriptorVerifier* verifier = nullptr) {
    if (phase_ != Phase::Trial && phase_ != Phase::Recovery && phase_ != Phase::CounterCommitPending) {
      return false;
    }
    if (!backup_verified_ || backup_progress_ != running_image_size_bytes_) {
      return false;  // defensive fail-closed; should be unreachable
    }
    if (phase_ == Phase::CounterCommitPending) {
      if (counter_commit_started_) {
        if (verifier == nullptr || descriptor_.monotonic_counter == 0) {
          return false;
        }
        uint32_t current_counter = 0;
        if (!verifier->currentCounterValue(current_counter)) {
          return false;
        }
        if (current_counter >= descriptor_.monotonic_counter) {
          return false;
        }
      }
    }

    const Phase phase_before_rollback_checkpoint = phase_;
    const bool target_known_intact_before_rollback_checkpoint = target_known_intact_;
    target_known_intact_ = false;
    phase_ = Phase::RollingBack;
    if (!checkpoint()) {
      target_known_intact_ = target_known_intact_before_rollback_checkpoint;
      phase_ = phase_before_rollback_checkpoint;
      return false;
    }

    if (!platform::isOk(target_region_.eraseRange(0, target_region_.sizeBytes()))) {
      return false;  // remains RollingBack/reclassified to Recovery on next recoverFromJournal()
    }
    uint32_t progress = 0;
    if (!storage::StorageManager::copyRangeVerified(backup_region_, target_region_, running_image_size_bytes_, 0, progress)) {
      return false;
    }
    if (!storage::StorageManager::regionsEqual(backup_region_, target_region_, running_image_size_bytes_)) {
      return false;
    }

    target_known_intact_ = true;
    phase_ = Phase::RolledBack;
    return checkpoint();
  }

  // Reconstructs in-memory state from the journal after a reset/reboot.
  // Does NOT itself re-verify the candidate's signature/hash or re-diff
  // the backup's bytes -- it restores exactly enough state to know
  // whether a rollback is safe (it always is, whenever backup_verified_
  // ends up true here, because that flag can only be reconstructed as
  // true from phases that are only reachable once a real, verified backup
  // completed). A destructive step (install, rollback) that was
  // interrupted is NEVER resumed blindly: it is reclassified into
  // `Recovery`, and `candidate_authenticated_` is always reset to false,
  // requiring a fresh, live re-authentication against the current
  // candidate partition contents before any further install attempt.
  bool recoverFromJournal() {
    storage::JournalCheckpoint cp;
    if (!journal_.recoverLatest(cp, &campaign_id_)) {
      return false;
    }

    const Phase recovered_phase = static_cast<Phase>(cp.phase);
    backup_progress_ = cp.backup_progress_bytes;
    install_progress_ = cp.install_progress_bytes;
    descriptor_ = trust::ImageDescriptor();
    descriptor_.monotonic_counter = cp.descriptor_monotonic_counter;
    target_known_intact_ = cp.target_image_intact != 0;
    counter_commit_started_ = cp.counter_commit_started != 0;

    backup_verified_ = (recovered_phase == Phase::BackupVerified || recovered_phase == Phase::InstallInProgress ||
                         recovered_phase == Phase::InstallVerified || recovered_phase == Phase::Trial ||
                         recovered_phase == Phase::Confirmed || recovered_phase == Phase::RollingBack ||
                         recovered_phase == Phase::RolledBack || recovered_phase == Phase::Recovery ||
                         recovered_phase == Phase::CounterCommitPending);

    if (recovered_phase == Phase::InstallInProgress || recovered_phase == Phase::RollingBack) {
      phase_ = Phase::Recovery;
    } else {
      phase_ = recovered_phase;
    }

    candidate_authenticated_ = false;
    return true;
  }

private:
  bool canAuthenticateFromCurrentPhase() const {
    switch (phase_) {
      case Phase::Idle:
      case Phase::CandidateAuthenticated:
      case Phase::BackupInProgress:
      case Phase::BackupVerified:
      case Phase::Recovery:
        return true;
      default:
        return false;  // Trial/Confirmed/InstallInProgress/RollingBack/RolledBack must not silently re-authenticate
    }
  }

  bool canBackupFromCurrentPhase() const {
    switch (phase_) {
      case Phase::Idle:
      case Phase::CandidateAuthenticated:
      case Phase::BackupInProgress:
      case Phase::BackupVerified:
        return true;
      default:
        return false;
    }
  }

  bool trustedRunningImageExtentIsValid() const {
    return running_image_size_bytes_ > 0 && running_image_size_bytes_ <= target_region_.sizeBytes() &&
           running_image_size_bytes_ <= backup_region_.sizeBytes();
  }

  bool checkpoint() {
    storage::JournalCheckpoint cp;
    cp.campaign_id = campaign_id_;
    cp.phase = static_cast<uint8_t>(phase_);
    cp.chunk_count = 0;
    cp.backup_progress_bytes = backup_progress_;
    cp.install_progress_bytes = install_progress_;
    cp.descriptor_monotonic_counter = descriptor_.monotonic_counter;
    cp.target_image_intact = target_known_intact_ ? 1u : 0u;
    cp.counter_commit_started = counter_commit_started_ ? 1u : 0u;
    return journal_.writeCheckpoint(cp);
  }

  storage::Journal& journal_;
  uint32_t campaign_id_;
  platform::FlashRegion& candidate_region_;
  platform::FlashRegion& backup_region_;
  platform::FlashRegion& target_region_;
  uint32_t running_image_size_bytes_;
  bool target_known_intact_ = true;

  Phase phase_ = Phase::Idle;
  bool candidate_authenticated_ = false;
  bool backup_verified_ = false;
  bool counter_commit_started_ = false;
  uint32_t backup_progress_ = 0;
  uint32_t install_progress_ = 0;
  trust::ImageDescriptor descriptor_;
};

}  // namespace boot
}  // namespace ota
