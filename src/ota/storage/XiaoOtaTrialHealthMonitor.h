#pragma once

// Genuine trial-boot HEALTH-WINDOW state machine (V1 tightened contract).
//
// Replaces the earlier "5 seconds elapsed since this code first ran,
// then hash the whole image synchronously in one call" approach (which
// (a) was not a CONTINUOUS health signal at all -- once the 5s flag
// latched true it stayed true even if readiness later dropped or the
// main loop stalled for multiple seconds, and (b) blocked for as long as
// it takes to SHA-256 up to ~811008 bytes in a single call, on every
// tick, until confirmed) with:
//
//  1. A genuinely CONTINUOUS health window: radio_ready, filesystem_ready
//     and loop_healthy must ALL hold for kContinuousHealthyWindowMs of
//     real wall-clock time with no interruption. Either a readiness flag
//     going false, OR a tick-to-tick service gap wider than
//     kMaxServiceGapMs (the main loop stalled long enough that
//     "continuously healthy" can no longer be claimed truthfully),
//     restarts the window from zero.
//  2. A bounded kOverallDeadlineMs from this boot's first tick: if the
//     window is never satisfied (and the image hash verified) within
//     this deadline, the outcome latches to DeadlineExpired. This
//     monitor NEVER touches any hardware watchdog reload register --
//     that remains the bootloader's own 60-second trial-boot watchdog,
//     entirely out of scope here -- callers must react to
//     DeadlineExpired with their OWN single deliberate reboot so the
//     bootloader's unconfirmed-trial rollback path runs on its next
//     boot, rather than silently retrying forever on this boot.
//  3. An INCREMENTAL image-hash AND an INCREMENTAL extent resolution:
//     at most kHashBytesPerPass bytes of EITHER are processed per
//     tick() call (via the already-incremental ota::trust::Sha256::
//     update(), and via IXiaoOtaActiveImageAccessor::
//     stepExtentResolution()'s bounded CRC-16 steps), so a real ~700 KiB
//     image is never hashed OR extent-CRC-verified synchronously in one
//     blocking call. Both are computed and compared AT MOST ONCE per
//     boot (latched via hash_finished_), never redone on subsequent
//     ticks.
//  4. Exactly one durable confirmation write (+ readback) attempt, ever,
//     per boot (latched via confirmation_attempted_), then exactly one
//     terminal outcome: Confirmed on success, or an IMMEDIATELY latched
//     ConfirmationUncertain on write/readback FAILURE -- never left
//     dangling as Pending-until-deadline, which would let a caller keep
//     sleeping/erasing/looping while an already-uncertain durable write
//     transaction is outstanding. Never retried -- retrying could
//     interleave a second flash transaction with an already-uncertain
//     first one. This monitor never reboots itself -- rebooting is a
//     board/main-loop concern (see otaBoardTryConfirmHealthyTrialBoot()
//     callers), not a storage concern -- callers must perform exactly
//     one deliberate reboot in reaction to ANY of the three terminal
//     transitions (Confirmed, DeadlineExpired, ConfirmationUncertain).
//     The deadline is always checked BEFORE any hash/extent/confirmation
//     work in a given tick, so it always wins a tie against a same-tick
//     confirmation. isTrialActive() stays true across all three terminal
//     outcomes too -- trial exclusion only actually lifts on a genuine
//     subsequent boot with a fresh, non-trial state record.
//  5. A cheap phase-only state-record read happens EAGERLY, once, at
//     CONSTRUCTION (not lazily on first tick()), together with a
//     caller-supplied genuine `boot_epoch_ms` (also NOT the first
//     tick()'s timestamp) that arms the 45s deadline immediately: a
//     stock/confirmed/non-trial device's ordinary tick() never touches
//     the image accessor, the hasher, or the confirmation region at all,
//     and its outcome() stays Pending forever -- exactly the required
//     "stock/unqualified path stays inert" behaviour -- and
//     isTrialActive() answers correctly from the moment the object
//     exists, closing the otherwise-possible gap where an install/erase
//     attempted between boot and this object's first tick() would have
//     seen a false
//     "not active."
//
// Header-only so the full state machine is directly host-testable with
// synthetic FlashRegion + image fixtures and an explicit fake clock
// (`now_ms` is always caller-supplied, never read from a real clock
// here), independent of real hardware or any actual elapsed wall-clock
// time.

#include <stdint.h>
#include <string.h>

#include "ota/platform/FlashRegion.h"
#include "ota/storage/XiaoOtaActiveExtentBridge.h"
#include "ota/storage/XiaoOtaTrialBootConfirmation.h"
#include "ota/trust/Sha256.h"

namespace ota {
namespace storage {

enum class XiaoOtaTrialHealthOutcome : uint8_t {
  Pending = 0,               // still accumulating health/hash progress, not yet decided (or stock/non-trial).
  Confirmed = 1,             // durable confirmation written + read back (latched, terminal).
  DeadlineExpired = 2,       // kOverallDeadlineMs elapsed without confirming (latched, terminal).
  ConfirmationUncertain = 3, // the single confirmation write/readback attempt FAILED (latched,
                             // terminal, immediately -- never left dangling as Pending-until-
                             // deadline, which would let a caller keep sleeping/erasing/looping
                             // during an already-uncertain durable write). The caller's single
                             // deliberate reboot is the only recovery; the bootloader re-reads
                             // whatever durable token genuinely landed.
  StateUnreadable = 4,       // the eager, at-construction state-record read came back Unknown
                             // (a slot was genuinely unreadable -- I/O error) or Corrupt (a
                             // readable slot was non-blank but failed validation), so whether a
                             // trial is genuinely in progress cannot be determined at all. Fails
                             // CLOSED immediately (latched, terminal, this boot): never silently
                             // treated as "not a trial" (which would permit a competing
                             // install/erase or deep sleep), and never left dangling forever
                             // either -- the caller's single deliberate reboot is the only
                             // recovery, exactly like the other three terminal outcomes.
};

// Result of one bounded step of extent resolution (see
// stepExtentResolution() below): resolving the extent itself (a fresh
// CRC-16 over up to the whole ~811 KiB image, per
// XiaoOtaActiveExtentBridge::resolveExtentFromBank0()) is exactly the
// same kind of potentially-large synchronous cost as the SHA-256 image
// hash, so it MUST be driven incrementally, bounded to at most
// kHashBytesPerPass bytes per call, exactly like the hash itself -- never
// a single blocking whole-image call during a trial tick. (The
// XiaoOtaExtentResolutionStep enum itself lives in
// XiaoOtaActiveExtentBridge.h, included below, alongside the real
// hardware XiaoOtaIncrementalExtentResolver implementation.)
//
// Test/production seam: supplies the raw (pointer, extent) of the
// currently-running image WITHOUT hashing it -- see
// XiaoOtaActiveExtentBridge::XiaoOtaIncrementalExtentResolver for the
// real hardware implementation. Deliberately separate from the (now
// unused by this monitor) all-at-once XiaoOtaActiveExtentBridge::resolve()/
// computeFreshHash() synchronous path.
class IXiaoOtaActiveImageAccessor {
public:
  virtual ~IXiaoOtaActiveImageAccessor() = default;
  // Drives at most `max_bytes` of bounded extent-resolution work per
  // call; must be called repeatedly (from successive tick()s) until it
  // returns something other than InProgress. On Resolved, *out_image is
  // guaranteed non-null and *out_extent > 0; on Failed, both are left
  // untouched by contract (callers must not depend on them).
  virtual XiaoOtaExtentResolutionStep stepExtentResolution(uint32_t max_bytes, const uint8_t** out_image,
                                                           uint32_t* out_extent) = 0;
};

class XiaoOtaTrialHealthMonitor {
public:
  static constexpr uint32_t kContinuousHealthyWindowMs = 10000u;
  static constexpr uint32_t kMaxServiceGapMs = 1000u;
  static constexpr uint32_t kOverallDeadlineMs = 45000u;
  static constexpr uint32_t kHashBytesPerPass = 1024u;

  // `boot_epoch_ms` MUST be the genuine application boot origin (in
  // production: the Arduino millis() epoch itself, i.e. the constant 0
  // -- millis() already counts from actual power-on/reset, so nothing
  // needs to be "captured" at all; a fresh millis() reading taken here,
  // at this object's (already-lazy, post-flash-ready) construction time,
  // would silently discount whatever earlier setup() work (Serial/
  // board/radio/filesystem begin()) already consumed from the 45s
  // budget -- NOT the timestamp of this monitor's first tick() call).
  // Arming the deadline lazily on first tick() (the previous behaviour)
  // let a slow/delayed first tick (e.g. due to other setup() work)
  // silently grant extra deadline budget beyond the genuine 45s-from-
  // boot contract; arming it here, at construction, with the true
  // origin epoch, closes that gap.
  XiaoOtaTrialHealthMonitor(platform::FlashRegion& state_region, platform::FlashRegion& confirm_region,
                           IXiaoOtaActiveImageAccessor& image_accessor, uint32_t boot_epoch_ms)
      : state_region_(state_region), confirm_region_(confirm_region), image_accessor_(&image_accessor),
        deadline_start_ms_(boot_epoch_ms) {
    // Read the phase-only state record EAGERLY, right here at
    // construction (still exactly once, ever) -- NOT lazily on the first
    // tick(). isTrialActive() must answer correctly the instant this
    // object exists, before any tick() has necessarily run, so callers
    // (install-command gating, deep-sleep suppression) can never observe
    // a false "not active" during the brief window between construction
    // and a first tick -- e.g. an install/erase attempted between boot
    // and the very first main-loop iteration.
    //
    // Uses the TYPED ReadStatus (Blank/Found/Unknown/Corrupt), not the
    // plain bool readNewest(): a genuinely blank pair of slots (no trial
    // ever) is the only case that may safely conclude "not a trial".
    // Unknown (an unreadable slot -- might have held the true newest
    // record) and Corrupt (readable but invalid, non-blank content) must
    // NEVER be silently folded into "not a trial" -- that would have
    // permitted a competing install/erase against unknown/ambiguous
    // state. Both instead fail closed immediately: state_is_trial_ is
    // set true (blocks erase/sleep, see isTrialActive()) and the outcome
    // latches straight to StateUnreadable so the caller performs its one
    // required reboot rather than running indefinitely in an ambiguous
    // state.
    uint8_t state_buf[XiaoOtaStateReader::kRecordBytes];
    const XiaoOtaStateReader::ReadStatus state_status =
        XiaoOtaStateReader::readNewestWithStatus(state_region_, state_buf);
    // Retained for callers (see stateReadStatus()/statePhase() below)
    // that need the RAW eager read outcome/phase to build a typed
    // startup decision (Normal/Trial/Unknown) independent of the
    // narrower isTrialActive() bool -- e.g. distinguishing a genuinely
    // blank state region (no install history at all -- NOT positive
    // evidence of a safe baseline) from a Found record whose phase is
    // CONFIRMED (genuine, bootloader-verified completed-install
    // evidence) from every other found phase (ambiguous/incomplete
    // lifecycle, must fail closed). state_phase_ is only meaningful
    // when state_read_status_ == Found.
    state_read_status_ = state_status;
    if (state_status == XiaoOtaStateReader::ReadStatus::Found) {
      state_phase_ = XiaoOtaStateReader::phase(state_buf);
    }
    if (state_status == XiaoOtaStateReader::ReadStatus::Found &&
        XiaoOtaStateReader::phase(state_buf) == XiaoOtaStateReader::kPhaseTrialBoot) {
      state_is_trial_ = true;
      transaction_nonce_ = XiaoOtaStateReader::transactionNonce(state_buf);
      candidate_counter_ = XiaoOtaStateReader::candidateCounter(state_buf);
      memcpy(expected_installed_hash_, XiaoOtaStateReader::installedHashSha256(state_buf), 32);
      memcpy(expected_candidate_hash_, XiaoOtaStateReader::candidateHashSha256(state_buf), 32);
    } else if (state_status == XiaoOtaStateReader::ReadStatus::Unknown ||
              state_status == XiaoOtaStateReader::ReadStatus::Corrupt) {
      state_is_trial_ = true;
      outcome_ = XiaoOtaTrialHealthOutcome::StateUnreadable;
    }
  }

  // Raw eager-read outcome of the bootloader-owned state record, as
  // observed once at construction -- see the constructor's doc comment
  // above. Used to build a typed startup decision distinct from the
  // narrower isTrialActive() bool (which only distinguishes "is a
  // TRIAL_BOOT phase, or ambiguous state, currently unresolved").
  XiaoOtaStateReader::ReadStatus stateReadStatus() const { return state_read_status_; }

  // Only meaningful when stateReadStatus() == Found; 0 (XIAO_OTA_PHASE_
  // EMPTY) otherwise.
  uint32_t statePhase() const { return state_phase_; }


  // Call exactly once per main-loop tick with the genuine current
  // wall-clock time (caller's own monotonic millis clock) and readiness
  // signals. Returns the LATCHED outcome: once Confirmed or
  // DeadlineExpired is reached, every subsequent call returns the same
  // value immediately without touching flash, the hasher, or the image
  // accessor again.
  XiaoOtaTrialHealthOutcome tick(uint32_t now_ms, bool radio_ready, bool filesystem_ready, bool loop_healthy) {
    if (outcome_ != XiaoOtaTrialHealthOutcome::Pending) return outcome_;

    // Service-gap detection: any tick-to-tick wall-clock gap wider than
    // kMaxServiceGapMs invalidates the in-progress continuous window.
    if (last_tick_valid_ && (now_ms - last_tick_ms_) > kMaxServiceGapMs) {
      window_active_ = false;
    }
    last_tick_ms_ = now_ms;
    last_tick_valid_ = true;

    const bool ready_now = radio_ready && filesystem_ready && loop_healthy;
    if (!ready_now) {
      window_active_ = false;
    } else if (!window_active_) {
      window_active_ = true;
      window_start_ms_ = now_ms;
    }

    if (!state_is_trial_) {
      // Stock/confirmed/non-trial device: stays Pending forever, no
      // further work is ever performed.
      return XiaoOtaTrialHealthOutcome::Pending;
    }

    // The 45-second deadline is enforced BEFORE any hash progress or
    // confirmation-write attempt this tick -- not after. Checking it only
    // at the very end (as the previous revision did) meant a tick that
    // simultaneously satisfied the window+hash AND crossed the deadline
    // would confirm first and never reach the deadline check at all,
    // silently accepting a boot that only barely (or not genuinely)
    // stayed within budget. The deadline must always win a tie.
    if ((now_ms - deadline_start_ms_) >= kOverallDeadlineMs) {
      outcome_ = XiaoOtaTrialHealthOutcome::DeadlineExpired;
      return outcome_;
    }

    driveIncrementalHash();

    // Confirmation happens only once the continuous window itself is
    // satisfied AND the (independently, incrementally verified) hash
    // matches -- checked AFTER this tick's incremental progress, so a
    // tick that itself completes the hash and the window can confirm in
    // the same call. `confirmation_attempted_` guarantees AT MOST ONE
    // durable write/readback transaction ever, this boot: a failed
    // attempt is a terminal UNCERTAIN outcome for this boot -- never
    // retried on a tight loop (that could interleave a second flash
    // transaction with an uncertain first one) -- the boot's own single
    // deliberate reboot (on the subsequent DeadlineExpired fallthrough)
    // is the only safe recovery path, letting the bootloader re-read
    // whatever durable token genuinely landed.
    if (!confirmation_attempted_ && hash_finished_ && hash_matched_ && window_active_ &&
        (now_ms - window_start_ms_) >= kContinuousHealthyWindowMs) {
      confirmation_attempted_ = true;
      // Either a durable Confirmed outcome, or an immediately-latched
      // ConfirmationUncertain terminal outcome on write/readback FAILURE
      // -- never left dangling as Pending-until-deadline (which would
      // let a caller keep sleeping/erasing/looping while an already-
      // uncertain durable write transaction is outstanding). No second
      // attempt is ever made either way; isTrialActive() stays true for
      // BOTH terminal outcomes until the caller's single deliberate
      // reboot actually happens on a subsequent boot.
      outcome_ = tryWriteConfirmation() ? XiaoOtaTrialHealthOutcome::Confirmed
                                       : XiaoOtaTrialHealthOutcome::ConfirmationUncertain;
      return outcome_;
    }

    if ((now_ms - deadline_start_ms_) >= kOverallDeadlineMs) {
      outcome_ = XiaoOtaTrialHealthOutcome::DeadlineExpired;
      return outcome_;
    }

    return XiaoOtaTrialHealthOutcome::Pending;
  }

  XiaoOtaTrialHealthOutcome outcome() const { return outcome_; }
  uint32_t confirmedCounter() const { return confirmed_counter_; }

  // True while a genuine TRIAL_BOOT state record is in progress --
  // INCLUDING after a same-boot terminal outcome (Confirmed,
  // DeadlineExpired, or ConfirmationUncertain) has latched. Trial
  // exclusion (deep-sleep suppression, erase/install admission gating)
  // must NOT lift the instant a terminal outcome is decided: the actual
  // exit from "trial" only happens via a genuine subsequent boot with a
  // fresh (non-trial) state record. If this boot's own reboot() call
  // somehow returned/no-opped instead of actually resetting the board,
  // treating a terminal-but-not-yet-rebooted outcome as "no longer
  // active" would incorrectly permit installs/erases before that fresh
  // boot state actually exists.
  bool isTrialActive() const { return state_is_trial_; }

private:
  void driveIncrementalHash() {
    if (hash_finished_) return;
    if (!extent_resolved_) {
      // Extent resolution itself involves a fresh CRC-16 over up to the
      // whole running image -- exactly as expensive/blocking as the
      // SHA-256 hash below if done in one call -- so it MUST be driven
      // in the same bounded kHashBytesPerPass-per-tick steps, never in a
      // single synchronous call during a trial tick.
      const uint8_t* image = nullptr;
      uint32_t extent = 0;
      const XiaoOtaExtentResolutionStep step =
          image_accessor_->stepExtentResolution(kHashBytesPerPass, &image, &extent);
      if (step == XiaoOtaExtentResolutionStep::InProgress) {
        return;  // more bounded resolution work remains; try again next tick.
      }
      extent_resolved_ = true;
      // Fail closed on ANY of: outright Failed, a reported zero extent,
      // (defensively) a null image pointer even if the accessor claims
      // Resolved, an extent beyond kXiaoOtaAppInstallMaxSize (the same
      // 708608-byte install ceiling enforced elsewhere -- an injected/
      // buggy accessor reporting an oversized extent must never be
      // trusted to dereference/hash that many bytes, even though the
      // REAL hardware resolver already enforces this bound itself; this
      // is defense-in-depth against the injectable accessor seam, not
      // reliance on the real implementation alone), or an extent that is
      // not a whole multiple of 4 bytes (every legitimately linked/
      // flashed nRF52840 application image is word-aligned in size; a
      // non-multiple-of-4 value cannot be a genuine image extent and is
      // itself evidence of a corrupt/adversarial accessor) -- never
      // guess/fall back; this boot correctly falls through to
      // DeadlineExpired (the state record genuinely says TRIAL_BOOT, so
      // this is a real fault, not silently treated as confirmed).
      if (step != XiaoOtaExtentResolutionStep::Resolved || extent == 0 || image == nullptr ||
          extent > kXiaoOtaAppInstallMaxSize || (extent % 4u) != 0u) {
        image_ = nullptr;
        extent_ = 0;
        hash_finished_ = true;
        hash_matched_ = false;
        return;
      }
      image_ = image;
      extent_ = extent;
      hash_progress_ = 0;
      // Return WITHOUT starting the hash this same tick: extent
      // resolution just consumed up to kHashBytesPerPass bytes of work
      // (a fresh CRC-16 step) this call, and beginning the SHA-256 pass
      // in the SAME tick would push total bytes-of-work for this tick
      // to up to 2x kHashBytesPerPass -- violating the "at most
      // kHashBytesPerPass bytes of EITHER per tick" bound. The first
      // hash pass begins on the NEXT tick() call instead.
      return;
    }

    const uint32_t remaining = extent_ - hash_progress_;
    const uint32_t take = remaining < kHashBytesPerPass ? remaining : kHashBytesPerPass;
    if (take > 0) {
      hasher_.update(image_ + hash_progress_, take);
      hash_progress_ += take;
    }
    if (hash_progress_ >= extent_) {
      uint8_t digest[32];
      hasher_.finish(digest);
      hash_finished_ = true;
      hash_matched_ = (memcmp(digest, expected_installed_hash_, 32) == 0) &&
                     (memcmp(digest, expected_candidate_hash_, 32) == 0);
    }
  }

  bool tryWriteConfirmation() {
    XiaoOtaConfirmationFields fields;
    fields.transaction_nonce = transaction_nonce_;
    fields.confirmed_counter = candidate_counter_;
    memcpy(fields.confirmed_hash_sha256, expected_installed_hash_, 32);
    uint32_t sequence_written = 0;
    if (!XiaoOtaConfirmationRecord::writeNext(confirm_region_, fields, &sequence_written)) {
      return false;
    }
    confirmed_counter_ = candidate_counter_;
    return true;
  }

  platform::FlashRegion& state_region_;
  platform::FlashRegion& confirm_region_;
  IXiaoOtaActiveImageAccessor* image_accessor_;

  XiaoOtaTrialHealthOutcome outcome_ = XiaoOtaTrialHealthOutcome::Pending;

  uint32_t deadline_start_ms_ = 0;  // armed at construction (see constructor init list), not lazily on first tick.
  bool last_tick_valid_ = false;
  uint32_t last_tick_ms_ = 0;

  bool window_active_ = false;
  uint32_t window_start_ms_ = 0;

  bool confirmation_attempted_ = false;  // at most ONE durable write/readback transaction, ever, per boot.

  bool state_is_trial_ = false;
  // Raw eager-read state (see stateReadStatus()/statePhase() accessors
  // above): state_read_status_ defaults to Blank (matches "no record at
  // all" until the constructor's actual read runs); state_phase_ is only
  // meaningful when state_read_status_ == Found.
  XiaoOtaStateReader::ReadStatus state_read_status_ = XiaoOtaStateReader::ReadStatus::Blank;
  uint32_t state_phase_ = 0;
  uint64_t transaction_nonce_ = 0;
  uint32_t candidate_counter_ = 0;
  uint8_t expected_installed_hash_[32] = {};
  uint8_t expected_candidate_hash_[32] = {};

  bool extent_resolved_ = false;
  const uint8_t* image_ = nullptr;
  uint32_t extent_ = 0;
  uint32_t hash_progress_ = 0;
  bool hash_finished_ = false;
  bool hash_matched_ = false;
  trust::Sha256 hasher_;

  uint32_t confirmed_counter_ = 0;
};

}  // namespace storage
}  // namespace ota
