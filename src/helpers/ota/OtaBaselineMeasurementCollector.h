#pragma once

// Astra30/31 (V2 -- tightened contract after Turn102 rejection): a REAL,
// shared, bounded, read-only baseline-measurement job with an explicit
// ownership/contention model and a genuinely shared per-call I/O budget
// -- not a source-only stub with opaque precomputed digests.
//
// This job NEVER grants Normal/identity-generation/format/commission/
// write authority by itself. Its only output (Present) is a measured
// OtaBaselineMeasurementEvidence snapshot; certifying that snapshot into
// a positive classification remains a SEPARATE, not-yet-implemented real
// signature verifier's job (see OtaBaselineCertificationEvidence.h).
// `has_verified_fresh_baseline_proof` stays false/unwired everywhere in
// this tree.
//
// V2 design constraints (all enforced HERE, not left to callers or the
// source seam):
//  - Idle/Pending/Present/Failure are all distinct: a default-constructed
//    (or post-cancel/post-terminal) collector is Idle, and serviceStep()
//    on an Idle collector is a no-op typed rejection -- it can never
//    "coast" to Present without a genuine begin().
//  - Ownership: begin() takes an explicit caller-supplied
//    OtaBaselineMeasurementOwnerToken (a sequence number alone is
//    observable/guessable, not an identity). A second begin() from a
//    DIFFERENT owner while a job is genuinely in flight is REJECTED
//    (typed AnotherOwnerActive) -- it can never silently steal/cancel
//    another owner's job. Only the SAME owner (or an explicit cancel()
//    by that same owner) may restart. Ticket ids never wrap (exhaustion
//    is a typed rejection, avoiding ABA); ticket 0 is reserved/invalid.
//  - Each serviceStep() call shares ONE combined kMaxBytesPerPublicStep
//    (1024) budget across whatever sub-work it performs THIS call -- the
//    image-extent-resolution step and the incremental hash/CRC step
//    explicitly SHARE that one budget rather than each independently
//    consuming a full 1024. Stock-loader hashing and QSPI inspection are
//    themselves resumable bounded phases with real consumed-byte
//    out-params, not opaque all-or-nothing bool calls.
//  - Contention (the media arbiter is busy/leased elsewhere right now)
//    stays Pending (WouldBlock semantics, retry later) and is NEVER
//    conflated with Failure; only a genuine configuration/IO error
//    escalates to Failure(MediaArbiterUnavailable).
//  - The collector re-validates bounds itself (never trusts the seam
//    alone): extent must be nonzero, <= kXiaoOtaAppInstallMaxSize, the
//    internal address range must be exactly the real nRF52 app window,
//    and hash_progress_ is guarded against ever exceeding the frozen
//    extent (no unsigned underflow when computing "remaining").
//    Resolved-but-null image pointers, and a resolved extent that
//    disagrees with the earlier frozen bank-0 extent, are both explicit
//    Failure cases -- not silently trusted.
//  - The computed application CRC-16 is compared against the SDK's own
//    STORED CRC (a genuine zero stored value is a valid, checkable
//    comparison target, never treated as "absent"); a mismatch is
//    Failure, not a silently-emitted-only computed value.
//  - Exactly one bank-0 extent and one SDK-settings snapshot is frozen
//    for the whole job; a final Recheck phase re-reads identity/profile/
//    SDK-settings/extent and requires an EXACT byte-for-byte match to
//    what was frozen earlier -- a legitimately-still-readable but now
//    DIFFERENT SDK/extent/identity is Failure (InconsistentReread), never
//    silently accepted as if nothing changed mid-job.
//  - The host_challenge itself (not just the device nonce) is frozen
//    into the evidence at begin() and returned verbatim by
//    readCompletedEvidence() -- no caller can substitute a different
//    challenge after the fact; only the SAME owner token may read it.
//  - This collector never touches QSPI/flash directly -- only via the
//    injectable media-arbiter seam, and denies/stays-Pending if that
//    arbiter reports contention, or Fails if it reports a genuine error.
//  - No RAM-fabricated identity, no radio dependency whatsoever (a
//    caller integrating this must never gate it on radio health).

#include <stdint.h>
#include <string.h>

#include "helpers/ota/OtaSdkSettingsCodec.h"
#include "ota/storage/XiaoOtaActiveExtentBridge.h"  // kXiaoOtaAppInstallMaxSize, crc16Step
#include "ota/trust/Sha256.h"

namespace mesh {
namespace ota {

enum class OtaBaselineMeasurementStatus : uint8_t { Idle, Pending, Present, Failure };

enum class OtaBaselineMeasurementFailureReason : uint8_t {
  None,
  MediaArbiterUnavailable,     // genuine config/IO error from the arbiter seam (NOT mere contention).
  IdentityUnreadable,
  ProfileUnreadable,
  SdkSettingsUnreadable,
  ExtentOutOfBounds,           // zero/oversized/out-of-window extent, or inconsistent address.
  ImageNullOrInconsistent,     // Resolved-but-null image pointer, or extent disagreeing with the frozen one.
  ImageHashFailed,             // bounded app-image access itself reported Failed.
  ImageCrcMismatch,            // computed CRC-16 disagrees with the SDK's own stored CRC (incl. a genuine 0).
  StockLoaderRangeUnreadable,
  BootConfigUnreadable,         // genuine selector-read/MBR-params-blank-scan anomaly (not merely an absent catalogue).
  BootConfigCatalogueUnavailable, // selector evidence read fine, but no approved catalogue row exists yet -- never a generic IO error.
  BootConfigMismatch,           // a catalogue row for this target EXISTS but genuinely differs from live measurement.
  QspiStateConflict,           // unresolved trial/history conflict observed during inspection.
  InconsistentReread,          // end-of-job reread of identity/profile/SDK/extent no longer matches the frozen snapshot.
};

// Rejections from begin() itself -- distinct from a job's own
// FailureReason, because these happen BEFORE any ticket/ownership state
// is ever mutated.
enum class OtaBaselineMeasurementBeginRejection : uint8_t {
  None,
  InvalidOwnerToken,      // owner_token.value == 0 is reserved/invalid.
  AnotherOwnerActive,     // a genuinely different owner's job is still Pending.
  TicketsExhausted,       // the ticket sequence has reached its ceiling; never wraps (no ABA).
  EntropyUnavailable,     // couldn't draw a fresh device_nonce16 -- never proceeds with a fabricated one.
};

// serviceStep()'s own typed outcome -- silent no-ops are never allowed
// to look identical to genuine progress.
enum class OtaBaselineMeasurementStepOutcome : uint8_t {
  Progressed,           // did some bounded work (or made a no-progress contention retry) on the live job.
  RejectedStaleTicket,
  RejectedWrongOwner,
  NotRunning,           // collector is Idle/Present/Failure -- no live job to service.
};

enum class OtaBaselineMeasurementArbiterResult : uint8_t { Acquired, Contended, Unavailable };

// Multi-call bounded sub-step result, shared by the app-image, stock-
// loader and QSPI-inspection phases.
enum class OtaBaselineMeasurementSubStep : uint8_t { InProgress, Resolved, Failed };

struct OtaBaselineMeasurementOwnerToken {
  uint64_t value = 0;
};

// Injectable hardware seam. Every method must perform AT MOST the
// bounded read/compute work documented per call; multi-byte phases are
// resumable (return InProgress + consumed-byte out-param) rather than
// silently doing a full scan behind an opaque bool. A real hardware
// adapter is constructed per-backend (OtaLabBackend.cpp /
// OtaProductionBackend.cpp); native tests inject a synthetic fixture.
class IOtaBaselineMeasurementSource {
public:
  virtual ~IOtaBaselineMeasurementSource() = default;

  virtual OtaBaselineMeasurementArbiterResult acquireMediaArbiter() = 0;
  virtual void releaseMediaArbiter() = 0;

  // Already-loaded (never generated) full nRF52 FICR UID (canonical
  // BE8) and already-loaded full public key.
  virtual bool readDeviceIdentity(uint8_t out_uid8[8], uint8_t out_pubkey32[32]) = 0;

  // profile_id (1 == Xiao lab, 2 == SenseCAP production, etc.) is a
  // distinct field from target/role/layout -- callers must supply the
  // real compiled-in profile identifier, not fold it into target_id.
  virtual bool readCompiledProfile(uint32_t& out_profile_id, uint32_t& out_target_id, uint32_t& out_role_id,
                                    uint32_t& out_layout_id) = 0;

  // Exact 28 RAW bytes of the device's current SDK/build-settings record
  // (see OtaSdkSettingsCodec.h) -- the collector decodes/hashes these
  // itself; this seam must never hand back a precomputed digest.
  virtual bool readRawCurrentSdkSettings(uint8_t out_raw28[kOtaCurrentSdkSettingsRecordBytes]) = 0;

  // Validated bank-0 extent/current image's internal flash address PLUS
  // the SDK's own recorded application CRC-16 (a genuine 0 is a valid
  // value here, not "absent"). The seam itself must enforce extent != 0,
  // extent <= kXiaoOtaAppInstallMaxSize and the internal address window,
  // returning false on violation -- the collector re-checks these same
  // bounds independently below (defence in depth, never trust-only).
  virtual bool readValidatedBank0Extent(uint32_t& out_extent, uint32_t& out_internal_addr,
                                        uint16_t& out_stored_crc16) = 0;

  // Bounded per-call app-image extent resolution + access: `max_bytes`
  // is this call's REMAINING shared budget; `out_bytes_consumed` must
  // report exactly how much of it this call actually used, so the
  // collector can subtract it before deciding how much budget is left
  // for incremental hashing in the SAME public serviceStep() call.
  virtual OtaBaselineMeasurementSubStep stepAppImageAccess(uint32_t max_bytes, uint32_t* out_bytes_consumed,
                                                           const uint8_t** out_image, uint32_t* out_extent) = 0;

  // Allowlisted stock-loader executable-range SHA + range, read from an
  // actual live flash hash catalogue coordinated with the Boot owner
  // (never archived/captured media) -- itself resumable/bounded.
  virtual OtaBaselineMeasurementSubStep stepStockLoaderRangeHash(uint32_t max_bytes, uint32_t* out_bytes_consumed,
                                                                 uint32_t& out_start, uint32_t& out_length,
                                                                 uint8_t out_hash32[32]) = 0;

  // Bounded/resumable boot-config-selection evidence phase: reads the
  // real MBR forward-pointer words + UICR NRFFW mirror words + performs
  // an incremental blank-scan of the MBR-parameter page, classifying
  // the selector tuple against Root/Astra-pinned POLICY shapes -- but
  // NEVER emits an authorized `out_boot_config_id` by itself (Resolved
  // is intentionally unreachable until Root supplies the real stock-
  // loader-hash catalogue row; see each backend's doc comment). `Failed`
  // here is the expected, non-authorising outcome today. `out_catalogue_
  // unavailable` distinguishes the two genuinely different `Failed`
  // causes so the collector can report a typed `BootConfigCatalogue
  // Unavailable` (evidence gathered fine, no approved catalogue row
  // exists yet -- expected/normal) instead of the generic `BootConfig
  // Unreadable` IO-style failure (a real selector-read or blank-scan
  // anomaly), rather than ever conflating "unknown" with "corrupt".
  virtual OtaBaselineMeasurementSubStep stepBootConfigSelection(uint32_t max_bytes, uint32_t* out_bytes_consumed,
                                                                uint32_t& out_boot_config_id,
                                                                bool& out_catalogue_unavailable,
                                                                bool& out_mismatch) = 0;

  // Positive QSPI + state-region inspection, itself resumable/bounded;
  // Failed means a genuine unresolved trial/history conflict was found.
  virtual OtaBaselineMeasurementSubStep stepQspiStateInspection(uint32_t max_bytes, uint32_t* out_bytes_consumed) = 0;

  // Real entropy independent of the radio, from an existing platform
  // seam (e.g. hardware RNG).
  virtual bool getPlatformEntropy16(uint8_t out[16]) = 0;
};

struct OtaBaselineMeasurementTicket {
  uint8_t host_challenge[16] = {0};
  uint8_t device_nonce[16] = {0};
  uint32_t ticket_id = 0;  // 0 == invalid/not-started.
};

struct OtaBaselineMeasurementBeginOutcome {
  bool started = false;
  OtaBaselineMeasurementTicket ticket;
  OtaBaselineMeasurementBeginRejection rejection = OtaBaselineMeasurementBeginRejection::None;
};

// Evidence produced ONLY on Present -- mirrors
// OtaBaselineCertificationEvidence's measured fields (minus the
// authority signature, which this collector never attaches).
struct OtaBaselineMeasurementEvidence {
  uint8_t device_uid[8] = {0};
  uint8_t full_public_key[32] = {0};
  uint32_t profile_id = 0;
  uint32_t target_id = 0;
  uint32_t role_id = 0;
  uint32_t layout_id = 0;
  uint8_t current_sdk_sha256[32] = {0};
  uint32_t current_image_extent = 0;
  uint32_t current_image_internal_addr = 0;
  uint8_t current_image_sha256[32] = {0};
  uint16_t current_image_crc16 = 0;  // computed; zero IS a valid result, not "absent".
  uint32_t stock_loader_range_start = 0;
  uint32_t stock_loader_range_length = 0;
  uint8_t stock_loader_hash[32] = {0};
  uint32_t boot_config_id = 0;
  uint8_t host_challenge[16] = {0};  // frozen verbatim at begin() -- never substitutable after the fact.
  uint8_t device_nonce[16] = {0};
  // Opaque original 28 raw SDK/build-settings bytes (NOT host-endian
  // words) -- mirrors OtaControlMeasurement::rawSdk28 on the wire so a
  // control-ABI adapter can forward this evidence verbatim without
  // re-deriving it from current_sdk_sha256 (a hash cannot be inverted
  // back into these bytes).
  uint8_t raw_sdk28[kOtaCurrentSdkSettingsRecordBytes] = {0};
};

class OtaBaselineMeasurementCollector {
public:
  static constexpr uint32_t kMaxBytesPerPublicStep = 1024;
  // Real internal nRF52 app-install window this codebase already
  // establishes elsewhere (OtaGeometry.h/XiaoOtaActiveExtentBridge.h):
  // 0x27000 .. 0x27000 + kXiaoOtaAppInstallMaxSize (== 0xD4000 exactly).
  static constexpr uint32_t kAppWindowStartAddr = 0x27000u;
  static constexpr uint32_t kAppWindowEndAddr =
      kAppWindowStartAddr + ::ota::storage::kXiaoOtaAppInstallMaxSize;

  explicit OtaBaselineMeasurementCollector(IOtaBaselineMeasurementSource& source) : source_(source) {}

  // Test-only: seeds the internal ticket counter so unit tests can
  // exercise the TicketsExhausted rejection path without actually
  // issuing ~4 billion real tickets first. Production callers must
  // always use the single-argument constructor (which starts at 0).
  OtaBaselineMeasurementCollector(IOtaBaselineMeasurementSource& source, uint32_t test_only_initial_ticket_id)
      : source_(source), current_ticket_id_(test_only_initial_ticket_id) {}

  ~OtaBaselineMeasurementCollector() {
    if (arbiter_held_) source_.releaseMediaArbiter();
  }

  OtaBaselineMeasurementCollector(const OtaBaselineMeasurementCollector&) = delete;
  OtaBaselineMeasurementCollector& operator=(const OtaBaselineMeasurementCollector&) = delete;

  // Starts a job bound to `host_challenge`, owned by `owner_token`.
  // Rejects (no state mutated at all) if: owner_token is invalid (0), a
  // DIFFERENT owner's job is genuinely still Pending, the ticket
  // sequence is exhausted, or fresh entropy can't be drawn. Restarting
  // one's OWN in-flight job is allowed (supersedes it cleanly, including
  // releasing any held arbiter first).
  OtaBaselineMeasurementBeginOutcome begin(const uint8_t host_challenge[16],
                                           OtaBaselineMeasurementOwnerToken owner_token) {
    OtaBaselineMeasurementBeginOutcome outcome;
    if (owner_token.value == 0) {
      outcome.rejection = OtaBaselineMeasurementBeginRejection::InvalidOwnerToken;
      return outcome;
    }
    if (status_ == OtaBaselineMeasurementStatus::Pending && owner_token.value != current_owner_.value) {
      outcome.rejection = OtaBaselineMeasurementBeginRejection::AnotherOwnerActive;
      return outcome;
    }
    if (current_ticket_id_ == 0xFFFFFFFFu) {
      outcome.rejection = OtaBaselineMeasurementBeginRejection::TicketsExhausted;
      return outcome;
    }
    uint8_t nonce[16];
    if (!source_.getPlatformEntropy16(nonce)) {
      outcome.rejection = OtaBaselineMeasurementBeginRejection::EntropyUnavailable;
      return outcome;
    }

    if (arbiter_held_) {
      source_.releaseMediaArbiter();
      arbiter_held_ = false;
    }
    ++current_ticket_id_;
    current_owner_ = owner_token;
    ticket_ = OtaBaselineMeasurementTicket{};
    memcpy(ticket_.host_challenge, host_challenge, sizeof(ticket_.host_challenge));
    memcpy(ticket_.device_nonce, nonce, sizeof(nonce));
    ticket_.ticket_id = current_ticket_id_;

    status_ = OtaBaselineMeasurementStatus::Pending;
    failure_reason_ = OtaBaselineMeasurementFailureReason::None;
    phase_ = Phase::AcquireArbiter;
    hash_progress_ = 0;
    crc16_ = 0xFFFFu;
    image_resolved_ = false;
    image_ptr_ = nullptr;
    frozen_extent_ = 0;
    hasher_.reset();
    evidence_ = OtaBaselineMeasurementEvidence{};
    memcpy(evidence_.host_challenge, host_challenge, sizeof(evidence_.host_challenge));
    memcpy(evidence_.device_nonce, nonce, sizeof(nonce));

    outcome.started = true;
    outcome.ticket = ticket_;
    return outcome;
  }

  // Explicit cancel by the OWNING caller only -- releases any held
  // arbiter lease immediately and returns to Idle. A stale ticket_id or
  // a different owner's cancel attempt is rejected (false, no mutation).
  bool cancel(uint32_t ticket_id, OtaBaselineMeasurementOwnerToken owner_token) {
    if (status_ != OtaBaselineMeasurementStatus::Pending) return false;
    if (ticket_id != current_ticket_id_ || owner_token.value != current_owner_.value) return false;
    if (arbiter_held_) {
      source_.releaseMediaArbiter();
      arbiter_held_ = false;
    }
    status_ = OtaBaselineMeasurementStatus::Idle;
    phase_ = Phase::AcquireArbiter;
    return true;
  }

  // Performs at most kMaxBytesPerPublicStep bytes of combined work this
  // call. Must be invoked repeatedly (once per scheduler tick) until
  // status() is no longer Pending.
  OtaBaselineMeasurementStepOutcome serviceStep(uint32_t ticket_id, OtaBaselineMeasurementOwnerToken owner_token) {
    if (status_ != OtaBaselineMeasurementStatus::Pending) return OtaBaselineMeasurementStepOutcome::NotRunning;
    if (ticket_id != current_ticket_id_) return OtaBaselineMeasurementStepOutcome::RejectedStaleTicket;
    if (owner_token.value != current_owner_.value) return OtaBaselineMeasurementStepOutcome::RejectedWrongOwner;

    switch (phase_) {
      case Phase::AcquireArbiter: {
        if (!arbiter_held_) {
          const auto r = source_.acquireMediaArbiter();
          if (r == OtaBaselineMeasurementArbiterResult::Unavailable) {
            fail(OtaBaselineMeasurementFailureReason::MediaArbiterUnavailable);
            break;
          }
          if (r == OtaBaselineMeasurementArbiterResult::Contended) break;  // stays Pending; caller retries.
          arbiter_held_ = true;
        }
        phase_ = Phase::Identity;
        break;
      }
      case Phase::Identity: {
        if (!source_.readDeviceIdentity(frozen_uid_, frozen_pubkey_)) {
          fail(OtaBaselineMeasurementFailureReason::IdentityUnreadable);
          break;
        }
        memcpy(evidence_.device_uid, frozen_uid_, sizeof(frozen_uid_));
        memcpy(evidence_.full_public_key, frozen_pubkey_, sizeof(frozen_pubkey_));
        phase_ = Phase::Profile;
        break;
      }
      case Phase::Profile: {
        if (!source_.readCompiledProfile(frozen_profile_id_, frozen_target_id_, frozen_role_id_,
                                         frozen_layout_id_)) {
          fail(OtaBaselineMeasurementFailureReason::ProfileUnreadable);
          break;
        }
        evidence_.profile_id = frozen_profile_id_;
        evidence_.target_id = frozen_target_id_;
        evidence_.role_id = frozen_role_id_;
        evidence_.layout_id = frozen_layout_id_;
        phase_ = Phase::SdkSettings;
        break;
      }
      case Phase::SdkSettings: {
        uint8_t raw[kOtaCurrentSdkSettingsRecordBytes];
        if (!source_.readRawCurrentSdkSettings(raw)) {
          fail(OtaBaselineMeasurementFailureReason::SdkSettingsUnreadable);
          break;
        }
        memcpy(frozen_sdk_raw_, raw, sizeof(frozen_sdk_raw_));
        memcpy(evidence_.raw_sdk28, raw, sizeof(evidence_.raw_sdk28));
        hashOtaCurrentSdkSettingsRecordRaw(raw, evidence_.current_sdk_sha256);
        phase_ = Phase::Extent;
        break;
      }
      case Phase::Extent: {
        uint32_t extent = 0, internal_addr = 0;
        uint16_t stored_crc = 0;
        if (!source_.readValidatedBank0Extent(extent, internal_addr, stored_crc)) {
          fail(OtaBaselineMeasurementFailureReason::ExtentOutOfBounds);
          break;
        }
        // Defence-in-depth: re-validate independently of the seam.
        if (extent == 0 || extent > ::ota::storage::kXiaoOtaAppInstallMaxSize || internal_addr != kAppWindowStartAddr ||
            internal_addr > kAppWindowEndAddr - extent) {
          fail(OtaBaselineMeasurementFailureReason::ExtentOutOfBounds);
          break;
        }
        frozen_extent_ = extent;
        frozen_internal_addr_ = internal_addr;
        frozen_stored_crc16_ = stored_crc;
        evidence_.current_image_extent = extent;
        evidence_.current_image_internal_addr = internal_addr;
        phase_ = Phase::ImageHash;
        break;
      }
      case Phase::ImageHash: {
        uint32_t budget_left = kMaxBytesPerPublicStep;
        if (!image_resolved_) {
          uint32_t consumed = 0;
          const uint8_t* image = nullptr;
          uint32_t resolved_extent = 0;
          const auto step = source_.stepAppImageAccess(budget_left, &consumed, &image, &resolved_extent);
          // Never trust an out-of-range consumed report from the seam.
          if (consumed > budget_left) consumed = budget_left;
          budget_left -= consumed;
          if (step == OtaBaselineMeasurementSubStep::Failed) {
            fail(OtaBaselineMeasurementFailureReason::ImageHashFailed);
            break;
          }
          if (step == OtaBaselineMeasurementSubStep::InProgress) break;  // more resolution work next call.
          if (image == nullptr || resolved_extent != frozen_extent_) {
            fail(OtaBaselineMeasurementFailureReason::ImageNullOrInconsistent);
            break;
          }
          image_ptr_ = image;
          image_resolved_ = true;
        }
        if (image_resolved_ && budget_left > 0) {
          if (hash_progress_ > frozen_extent_) {
            // Underflow guard: this should never legitimately happen.
            fail(OtaBaselineMeasurementFailureReason::ImageNullOrInconsistent);
            break;
          }
          const uint32_t remaining_to_hash = frozen_extent_ - hash_progress_;
          const uint32_t take = remaining_to_hash < budget_left ? remaining_to_hash : budget_left;
          if (take > 0) {
            hasher_.update(image_ptr_ + hash_progress_, take);
            crc16_ = crc16Bytes(crc16_, image_ptr_ + hash_progress_, take);
            hash_progress_ += take;
          }
          if (hash_progress_ >= frozen_extent_) {
            hasher_.finish(evidence_.current_image_sha256);
            evidence_.current_image_crc16 = crc16_;  // zero is a valid computed result, not "absent".
            if (crc16_ != frozen_stored_crc16_) {
              fail(OtaBaselineMeasurementFailureReason::ImageCrcMismatch);
              break;
            }
            phase_ = Phase::StockLoader;
          }
        }
        break;
      }
      case Phase::StockLoader: {
        uint32_t consumed = 0;
        const auto step = source_.stepStockLoaderRangeHash(kMaxBytesPerPublicStep, &consumed,
                                                            evidence_.stock_loader_range_start,
                                                            evidence_.stock_loader_range_length,
                                                            evidence_.stock_loader_hash);
        if (step == OtaBaselineMeasurementSubStep::Failed) {
          fail(OtaBaselineMeasurementFailureReason::StockLoaderRangeUnreadable);
          break;
        }
        if (step == OtaBaselineMeasurementSubStep::InProgress) break;
        phase_ = Phase::BootConfig;
        break;
      }
      case Phase::BootConfig: {
        uint32_t consumed = 0;
        bool catalogue_unavailable = false;
        bool mismatch = false;
        const auto step = source_.stepBootConfigSelection(kMaxBytesPerPublicStep, &consumed,
                                                           evidence_.boot_config_id, catalogue_unavailable,
                                                           mismatch);
        if (step == OtaBaselineMeasurementSubStep::Failed) {
          fail(mismatch ? OtaBaselineMeasurementFailureReason::BootConfigMismatch
               : catalogue_unavailable ? OtaBaselineMeasurementFailureReason::BootConfigCatalogueUnavailable
                                     : OtaBaselineMeasurementFailureReason::BootConfigUnreadable);
          break;
        }
        if (step == OtaBaselineMeasurementSubStep::InProgress) break;
        phase_ = Phase::QspiState;
        break;
      }
      case Phase::QspiState: {
        uint32_t consumed = 0;
        const auto step = source_.stepQspiStateInspection(kMaxBytesPerPublicStep, &consumed);
        if (step == OtaBaselineMeasurementSubStep::Failed) {
          fail(OtaBaselineMeasurementFailureReason::QspiStateConflict);
          break;
        }
        if (step == OtaBaselineMeasurementSubStep::InProgress) break;
        phase_ = Phase::Recheck;
        break;
      }
      case Phase::Recheck: {
        // Fresh re-read of identity/profile/SDK-settings/extent; ANY
        // byte-for-byte divergence from the frozen snapshot above --
        // even if still perfectly readable -- invalidates the job.
        uint8_t uid[8], pubkey[32];
        uint32_t profile_id = 0, target_id = 0, role_id = 0, layout_id = 0;
        uint8_t raw[kOtaCurrentSdkSettingsRecordBytes];
        uint32_t extent = 0, internal_addr = 0;
        uint16_t stored_crc = 0;
        if (!source_.readDeviceIdentity(uid, pubkey) ||
            !source_.readCompiledProfile(profile_id, target_id, role_id, layout_id) ||
            !source_.readRawCurrentSdkSettings(raw) ||
            !source_.readValidatedBank0Extent(extent, internal_addr, stored_crc)) {
          fail(OtaBaselineMeasurementFailureReason::InconsistentReread);
          break;
        }
        if (memcmp(uid, frozen_uid_, sizeof(uid)) != 0 || memcmp(pubkey, frozen_pubkey_, sizeof(pubkey)) != 0 ||
            profile_id != frozen_profile_id_ || target_id != frozen_target_id_ ||
            role_id != frozen_role_id_ || layout_id != frozen_layout_id_ ||
            memcmp(raw, frozen_sdk_raw_, sizeof(raw)) != 0 || extent != frozen_extent_ ||
            internal_addr != frozen_internal_addr_ || stored_crc != frozen_stored_crc16_) {
          fail(OtaBaselineMeasurementFailureReason::InconsistentReread);
          break;
        }
        source_.releaseMediaArbiter();
        arbiter_held_ = false;
        status_ = OtaBaselineMeasurementStatus::Present;
        phase_ = Phase::Done;
        break;
      }
      case Phase::Done:
        break;
    }
    return OtaBaselineMeasurementStepOutcome::Progressed;
  }

  OtaBaselineMeasurementStatus status() const { return status_; }
  OtaBaselineMeasurementFailureReason failureReason() const { return failure_reason_; }
  uint32_t currentTicketId() const { return current_ticket_id_; }
  // Read-only: the owner of whichever job is currently Pending/Present
  // (zero value / meaningless when Idle). Exists ONLY so a same-process
  // scheduler (e.g. MyMesh's per-tick driver, which starts no jobs of
  // its own) can advance whichever job is genuinely in flight without
  // needing to separately track the external caller's owner_token --
  // this is NOT a bypass of the begin()/cancel()/readCompletedEvidence()
  // ownership checks above, which still require an exact owner_token
  // match from any EXTERNAL caller.
  OtaBaselineMeasurementOwnerToken currentOwnerToken() const { return current_owner_; }

  // Only ever populated (and only ever returned true) when status() ==
  // Present AND both `ticket_id` and `owner_token` still match the job
  // that completed -- a different owner, or a stale ticket, can never
  // read this job's evidence, and Pending/Idle/Failure never yield one.
  bool readCompletedEvidence(uint32_t ticket_id, OtaBaselineMeasurementOwnerToken owner_token,
                             OtaBaselineMeasurementEvidence& out) const {
    if (status_ != OtaBaselineMeasurementStatus::Present) return false;
    if (ticket_id != current_ticket_id_ || owner_token.value != current_owner_.value) return false;
    out = evidence_;
    return true;
  }

private:
  enum class Phase : uint8_t {
    AcquireArbiter,
    Identity,
    Profile,
    SdkSettings,
    Extent,
    ImageHash,
    StockLoader,
    BootConfig,
    QspiState,
    Recheck,
    Done,
  };

  void fail(OtaBaselineMeasurementFailureReason reason) {
    if (arbiter_held_) {
      source_.releaseMediaArbiter();
      arbiter_held_ = false;
    }
    status_ = OtaBaselineMeasurementStatus::Failure;
    failure_reason_ = reason;
    phase_ = Phase::Done;
  }

  static uint16_t crc16Bytes(uint16_t crc, const uint8_t* data, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
      crc = ::ota::storage::XiaoOtaActiveExtentBridge::crc16Step(crc, data[i]);
    }
    return crc;
  }

  IOtaBaselineMeasurementSource& source_;
  OtaBaselineMeasurementTicket ticket_;
  OtaBaselineMeasurementOwnerToken current_owner_;
  uint32_t current_ticket_id_ = 0;
  OtaBaselineMeasurementStatus status_ = OtaBaselineMeasurementStatus::Idle;
  OtaBaselineMeasurementFailureReason failure_reason_ = OtaBaselineMeasurementFailureReason::None;
  Phase phase_ = Phase::AcquireArbiter;
  bool arbiter_held_ = false;

  // Frozen-once-per-job snapshot, re-verified verbatim in Phase::Recheck.
  uint8_t frozen_uid_[8] = {0};
  uint8_t frozen_pubkey_[32] = {0};
  uint32_t frozen_profile_id_ = 0;
  uint32_t frozen_target_id_ = 0;
  uint32_t frozen_role_id_ = 0;
  uint32_t frozen_layout_id_ = 0;
  uint8_t frozen_sdk_raw_[kOtaCurrentSdkSettingsRecordBytes] = {0};
  uint32_t frozen_extent_ = 0;
  uint32_t frozen_internal_addr_ = 0;
  uint16_t frozen_stored_crc16_ = 0;

  uint32_t hash_progress_ = 0;
  uint16_t crc16_ = 0xFFFFu;
  bool image_resolved_ = false;
  const uint8_t* image_ptr_ = nullptr;
  ::ota::trust::Sha256 hasher_;
  OtaBaselineMeasurementEvidence evidence_;
};

}  // namespace ota
}  // namespace mesh
