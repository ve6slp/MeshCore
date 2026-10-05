#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>

#include <ota/protocol/OtaDescriptor.h>
#include <ota/protocol/OtaEnvelope.h>
#include <ota/protocol/OtaMessages.h>
#include <ota/protocol/OtaWireTypes.h>
#include <ota/runtime/OtaAirtimeLimiter.h>
#include <ota/runtime/OtaBitmap.h>
#include <ota/runtime/OtaCoordinatorStateMachine.h>
#include <ota/runtime/OtaFleetStateMachine.h>
#include <ota/runtime/OtaGeometry.h>
#include <ota/runtime/OtaLeaseStateMachine.h>
#include <ota/runtime/OtaReceiverStateMachine.h>
#include <ota/runtime/OtaTrustInterfaces.h>
#include <ota/storage/OtaCandidateStore.h>
#include <helpers/ota/OtaLeanReceiver.h>
#include <helpers/ota/OtaMeasurementDiagnostics.h>
#include <helpers/ota/OtaRfFrames.h>

namespace mesh {
namespace ota {

enum class FirmwareOtaMode : uint8_t {
  Direct = 0,
  Routed = 1,
  Fleet = 2,
};

inline const char* firmwareOtaModeName(FirmwareOtaMode mode) {
  switch (mode) {
    case FirmwareOtaMode::Direct: return "direct";
    case FirmwareOtaMode::Routed: return "routed";
    case FirmwareOtaMode::Fleet: return "fleet";
    default: return "unknown";
  }
}

inline bool parseFirmwareOtaMode(const char* value, FirmwareOtaMode& out) {
  if (value == nullptr) return false;
  if (strcmp(value, "direct") == 0) {
    out = FirmwareOtaMode::Direct;
    return true;
  }
  if (strcmp(value, "routed") == 0 || strcmp(value, "mesh") == 0) {
    out = FirmwareOtaMode::Routed;
    return true;
  }
  if (strcmp(value, "fleet") == 0 || strcmp(value, "background") == 0) {
    out = FirmwareOtaMode::Fleet;
    return true;
  }
  return false;
}

inline meshcore::ota::runtime::OtaSessionId otaSessionFromEnvelope(
    const meshcore::ota::protocol::OtaEnvelopeHeader& hdr) {
  meshcore::ota::runtime::OtaSessionId id;
  id.campaignId = hdr.campaignId;
  id.sessionId = hdr.sessionId;
  id.attemptId = hdr.attemptId;
  return id;
}

inline meshcore::ota::protocol::OtaAirtimeCategory otaAirtimeCategoryForMessage(
    meshcore::ota::protocol::OtaMessageType type) {
  using meshcore::ota::protocol::OtaAirtimeCategory;
  using meshcore::ota::protocol::OtaMessageType;

  switch (type) {
    case OtaMessageType::Chunk:
    case OtaMessageType::Announcement:
      return OtaAirtimeCategory::Relay;
    case OtaMessageType::MissingRange:
      return OtaAirtimeCategory::Repair;
    default:
      return OtaAirtimeCategory::Control;
  }
}

struct FirmwareOtaStatus {
  FirmwareOtaMode mode = FirmwareOtaMode::Fleet;
  float dutyCyclePercent = 2.0f;
  uint32_t dutyWindowMs = meshcore::ota::runtime::OtaAirtimeLimiter::kDefaultWindowMs;
  uint32_t dutyBudgetMs = meshcore::ota::runtime::OtaAirtimeLimiter::kDefaultBudgetMs;
  uint32_t dutyUsedMs = 0;
  meshcore::ota::runtime::OtaReceiverState receiverState = meshcore::ota::runtime::OtaReceiverState::Idle;
  meshcore::ota::runtime::OtaCoordinatorState coordinatorState = meshcore::ota::runtime::OtaCoordinatorState::Idle;
  meshcore::ota::runtime::OtaFleetState fleetState = meshcore::ota::runtime::OtaFleetState::Idle;
  meshcore::ota::runtime::OtaLeaseState leaseState = meshcore::ota::runtime::OtaLeaseState::Normal;
  uint32_t rxFrames = 0;
  uint32_t badFrames = 0;
  uint32_t abortedSessions = 0;
  bool rollbackRequested = false;
  bool backendAvailable = false;
  // Real, decoded fleet (background) campaign progress, populated only from
  // validated Census/CohortResolution frames bound to the active campaign
  // (see handleCensus/handleCohortResolution); never advanced on unparsed
  // or foreign-campaign traffic.
  uint32_t fleetCensusReports = 0;
  bool fleetHasCohort = false;
  uint16_t fleetCohortId = 0;
  uint16_t fleetCohortSize = 0;
  uint16_t fleetCohortIndex = 0;
  uint16_t fleetMissingRangeCount = 0;
};

class OtaFirmwareIntegration {
public:
  OtaFirmwareIntegration()
      : airtime_(meshcore::ota::runtime::OtaAirtimeLimiter::kDefaultWindowMs,
                 meshcore::ota::runtime::OtaAirtimeLimiter::kDefaultBudgetMs) {}

  bool retryAttemptsEnabled() const { return retry_attempts_enabled_; }
  bool retryAttemptsExhausted() const { return retry_attempts_exhausted_; }
  bool setRetryAttempts(bool enabled, uint32_t first_attempt = 1) {
    if (enabled && !first_attempt) return false;
    retry_attempts_enabled_ = enabled;
    // Never reset a live sequence on START/stop. A fresh boot uses a random seed.
    if (enabled && retry_next_attempt_ == 0 && !retry_attempts_exhausted_)
      retry_next_attempt_ = first_attempt;
    return !enabled || !retry_attempts_exhausted_;
  }
  size_t prepareRfTransmit(const uint8_t* frame, size_t len, uint8_t* out, size_t capacity,
                           meshcore::ota::protocol::OtaAirtimeCategory category =
                               meshcore::ota::protocol::OtaAirtimeCategory::Control) const {
    if (!frame || !len || !out) return 0;
    if (isOtaRetryAttempt(frame[0])) {
      uint32_t attempt; const uint8_t* inner; size_t inner_len;
      if (!parseOtaRetryAttempt(frame, len, attempt, inner, inner_len)) return 0;
    } else if (retry_attempts_enabled_) {
      if (retry_attempts_exhausted_ || !retry_next_attempt_) return 0;
      return encodeOtaRetryAttempt(retry_next_attempt_, frame, len, out, capacity,
          category == meshcore::ota::protocol::OtaAirtimeCategory::Repair);
    }
    if (len > capacity) return 0;
    std::memmove(out, frame, len);
    return len;
  }
  // Only the boundary that prepared a new local attempt acknowledges admission.
  // Passing an already-wrapped frame through another boundary must not count twice.
  bool acceptRfTransmit(const uint8_t* frame, size_t len) {
    uint32_t attempt; const uint8_t* inner; size_t inner_len;
    if (!retry_attempts_enabled_ || retry_attempts_exhausted_ ||
        !parseOtaRetryAttempt(frame, len, attempt, inner, inner_len) ||
        attempt != retry_next_attempt_) return false;
    if (retry_next_attempt_ == UINT32_MAX) retry_attempts_exhausted_ = true;
    else ++retry_next_attempt_;
    return true;
  }

  FirmwareOtaMode mode() const { return mode_; }
  void setMode(FirmwareOtaMode mode) { mode_ = mode; }

  float dutyCyclePercent() const { return duty_percent_; }
  uint32_t dutyBudgetMs() const { return budget_ms_; }
  uint32_t dutyWindowMs() const { return window_ms_; }

  bool setDutyCyclePercent(float percent) {
    // Reject non-finite input (NaN, +-Inf) explicitly: NaN fails both
    // `< 0.0f` and `> 100.0f` (all NaN comparisons are false), so without
    // this guard a NaN would silently pass the bounds check below and then
    // hit undefined behavior in the float->integer budget conversion.
    if (!std::isfinite(percent) || percent < 0.0f || percent > 100.0f) return false;
    duty_percent_ = percent;
    const uint64_t budget = (static_cast<uint64_t>(window_ms_) * static_cast<uint32_t>(percent * 1000.0f + 0.5f)) / 100000u;
    budget_ms_ = static_cast<uint32_t>(budget);
    airtime_.retune(window_ms_, budget_ms_);
    return true;
  }

  void attachTrustProvider(meshcore::ota::runtime::IOtaTrustProvider* provider) {
    trust_provider_ = provider;
    lean_.attachTrustProvider(provider);
  }
  void attachStagingSink(meshcore::ota::runtime::IOtaStagingSink* sink) {
    staging_sink_ = sink;
    lean_.attachStagingSink(sink);
  }
  void attachCandidateStore(::ota::storage::OtaCandidateStore* store) { lean_.attachCandidateStore(store); }
  void attachLeanSignatureVerifier(const ::ota::trust::SignatureVerifier* verifier) { lean_.attachOwnerSignatureVerifier(verifier); }
  void setLeanAdminCheck(void* ctx, OtaLeanReceiver::AdminCheckFn fn) { lean_.setAdminCheck(ctx, fn); }
  void setLeanTargetPublicKey(const uint8_t key[32]) { lean_.setTargetPublicKey(key); }
  OtaLeanReceiver& leanReceiver() { return lean_; }
  const OtaLeanReceiver& leanReceiver() const { return lean_; }
  __attribute__((noinline)) void loop() { lean_.loop(); }
  static constexpr uint32_t kCommitRebootGraceMs = 2000;
  static constexpr uint32_t kCommitRebootQueueWaitMs = 15000;
  using CommitRebootFn = void (*)(void*);
  void attachCommitReboot(void* ctx, CommitRebootFn fn) { commit_reboot_ctx_ = ctx; commit_reboot_ = fn; }
  __attribute__((noinline)) usb::UsbOtaResult commitAndDeferReboot(
      uint32_t counter, const uint8_t signature[64], uint32_t now_ms) {
    static std::atomic_flag busy = ATOMIC_FLAG_INIT;
    OtaBoardProofScratchLease lease(busy);
    if (!lease) return usb::UsbOtaResult::Busy;
    static OtaLeanReceiver::Status before;
    captureLeanStatus(before);
    const auto result = lean_.commit(counter, signature);
    if (result != usb::UsbOtaResult::Ok) return result;
    stopDirect();
    // A retry after boot must not reboot an already-running trial or installed image.
    if (commit_reboot_ && before.phase == ::ota::storage::OtaCandidateStore::Phase::Ready &&
        (!commit_reboot_pending_ || commit_reboot_nonce_ != before.transactionNonce)) {
      commit_reboot_pending_ = true;
      commit_reboot_nonce_ = currentTransactionNonce();
      commit_reboot_due_ms_ = now_ms + kCommitRebootGraceMs;
      commit_reboot_queue_deadline_ms_ = now_ms + kCommitRebootQueueWaitMs;
    }
    return result;
  }
  bool takeCommitReboot(uint32_t now_ms, bool tx_active, bool outbound_queued, bool interface_busy = false) {
    if (!commit_reboot_pending_) return false;
    const auto st = lean_.status();
    if (!st.valid || st.phase != ::ota::storage::OtaCandidateStore::Phase::Committed ||
        st.transactionNonce != commit_reboot_nonce_) {
      commit_reboot_pending_ = false;
      return false;
    }
    if (static_cast<int32_t>(now_ms - commit_reboot_due_ms_) < 0) return false;
    const bool queue_deadline = static_cast<int32_t>(now_ms - commit_reboot_queue_deadline_ms_) >= 0;
    if (tx_active && (!queue_deadline || direct_active_ || direct_pending_)) return false;
    stopDirect();
    if (direct_active_ || direct_pending_) return false;
    // At the deadline a controlled reset may interrupt normal TX, never an unrestored direct profile.
    if (!queue_deadline &&
        (pending_control_frame_valid_ || outbound_queued || interface_busy)) return false;
    commit_reboot_pending_ = false;
    return true;
  }
  __attribute__((noinline)) bool tickCommitReboot(
      uint32_t now_ms, bool tx_active, bool outbound_queued, bool interface_busy = false) {
    if (!commit_reboot_ || !takeCommitReboot(now_ms, tx_active, outbound_queued, interface_busy)) return false;
    commit_reboot_(commit_reboot_ctx_);
    return true;
  }
  using SignFn = void (*)(void*, const uint8_t*, size_t, uint8_t[64]);
  using RadioChangeFn = bool (*)(void*, uint32_t, bool);
  using ProfileRadioChangeFn = bool (*)(void*, uint32_t, OtaDirectProfile, bool);
  void attachRfIdentity(void* ctx, SignFn sign, RadioChangeFn change, uint32_t normal_freq_khz) {
    rf_ctx_ = ctx; rf_sign_ = sign; rf_radio_change_ = change; rf_profile_radio_change_ = nullptr;
    normal_freq_khz_ = normal_freq_khz;
  }
  void attachRfProfileIdentity(void* ctx, SignFn sign, ProfileRadioChangeFn change, uint32_t normal_freq_khz) {
    rf_ctx_ = ctx; rf_sign_ = sign; rf_profile_radio_change_ = change; rf_radio_change_ = nullptr;
    normal_freq_khz_ = normal_freq_khz;
  }
  bool supportsDirectProfile(OtaDirectProfile profile) const {
    return isOtaDirectProfile(profile) &&
           (rf_profile_radio_change_ || (profile != OtaDirectProfile::Bw500 && rf_radio_change_));
  }
  bool applyDirectRadio(uint32_t frequency, OtaDirectProfile profile, bool restore) {
    if (rf_profile_radio_change_) return rf_profile_radio_change_(rf_ctx_, frequency, profile, restore);
    return profile != OtaDirectProfile::Bw500 && rf_radio_change_ &&
           rf_radio_change_(rf_ctx_, frequency, restore);
  }
  usb::UsbOtaReply handleUsbLocalControl(const uint8_t* command, size_t len, const uint8_t local_owner[32]) {
    usb::UsbOtaReply reply;
    reply.setNoSnapshot();
    reply.result = usb::UsbOtaResult::BadRequest;
    if (!command || len < 2 || command[0] != usb::kCommand) return reply;
    reply.requestOp = command[1];
    switch (static_cast<usb::UsbOtaOp>(command[1])) {
      case usb::UsbOtaOp::CacheBegin:
        if (len != usb::kCacheBeginTotalBytes || (command[2] & ~usb::kCacheBeginFlagReupload)) return reply;
        reply.result = lean_.handleUsbCacheFrame(command, len, local_owner);
        fillUsbReadback(reply);
        break;
      case usb::UsbOtaOp::CachePut:
      case usb::UsbOtaOp::CacheSeal:
        reply.result = lean_.handleUsbCacheFrame(command, len, local_owner);
        if (reply.result != usb::UsbOtaResult::BadRequest) fillUsbReadback(reply);
        break;
      case usb::UsbOtaOp::Abort: {
        if (len != usb::kAbortTotalBytes) return reply;
        std::memcpy(reply.target, command + 2, sizeof(reply.target));
        if (!local_owner || !rf_sign_) {
          reply.result = usb::UsbOtaResult::Unavailable;
          return reply;
        }
        bool zero_target = true;
        for (const auto byte : reply.target) if (byte) zero_target = false;
        if (!zero_target && std::memcmp(reply.target, local_owner, sizeof(reply.target))) return reply;
        uint8_t message[usb::kAbortSignedBytes], signature[64];
        const auto generation = usb::getBE32(command + 66);
        const auto message_len = usb::buildAbortSignedMessage(local_owner, command + 34, generation, message);
        rf_sign_(rf_ctx_, message, message_len, signature);
        reply.result = lean_.abort(local_owner, signature, command + 34, generation, true);
        fillUsbReadback(reply);
        break;
      }
      default:
        reply.result = usb::UsbOtaResult::Unsupported;
        break;
    }
    return reply;
  }
  using UsbRemoteControlSendFn = bool (*)(void*, const uint8_t[32], const uint8_t*, size_t);
  // A queued remote command is not evidence of the target's durable state.
  usb::UsbOtaReply handleUsbRemoteControl(const uint8_t* command, size_t len,
                                        void* send_ctx, UsbRemoteControlSendFn send) {
    usb::UsbOtaReply reply;
    reply.setNoSnapshot();
    reply.flags |= usb::kReplyFlagRemote;
    reply.result = usb::UsbOtaResult::BadRequest;
    if (!command || len < 2 || command[0] != usb::kCommand) return reply;
    reply.requestOp = command[1];
    const auto op = static_cast<usb::UsbOtaOp>(command[1]);
    if ((op != usb::UsbOtaOp::Commit && op != usb::UsbOtaOp::Abort) ||
        len != (op == usb::UsbOtaOp::Commit ? usb::kCommitTotalBytes : usb::kAbortTotalBytes)) return reply;
    const auto* target = command + 2;
    const auto* hash = target + usb::kPubKeyBytes;
    std::memcpy(reply.target, target, sizeof(reply.target));
    if (!rf_sign_ || !lean_.haveTargetPublicKey() || !send) {
      reply.result = usb::UsbOtaResult::Unavailable;
      return reply;
    }
    uint8_t message[usb::kCommitSignedBytes > usb::kAbortSignedBytes ?
                    usb::kCommitSignedBytes : usb::kAbortSignedBytes], signature[64], frame[kOtaAbortFrameBytes];
    size_t message_len, frame_len;
    if (op == usb::UsbOtaOp::Commit) {
      const auto st = lean_.status();
      if (!st.valid || std::memcmp(st.manifestHash, hash, usb::kHashBytes)) {
        reply.result = usb::UsbOtaResult::Mismatch;
        return reply;
      }
      const auto counter = usb::getBE32(hash + usb::kHashBytes);
      message_len = usb::buildCommitSignedMessage(target, hash, counter, message);
      rf_sign_(rf_ctx_, message, message_len, signature);
      frame_len = encodeOtaCommitFrame(target, hash, counter, signature, frame, sizeof(frame));
    } else {
      const auto generation = usb::getBE32(command + 66);
      message_len = usb::buildAbortSignedMessage(target, hash, generation, message);
      rf_sign_(rf_ctx_, message, message_len, signature);
      frame_len = encodeOtaAbortFrame(lean_.targetPublicKey(), target, hash, generation, signature, frame, sizeof(frame));
    }
    reply.result = frame_len && send(send_ctx, target, frame, frame_len) ?
        usb::UsbOtaResult::Ok : usb::UsbOtaResult::Busy;
    return reply;
  }
  using BootLifecycleFn = bool (*)(void*, OtaBootLifecycleEvidence&);
  // The board verifies signed provenance and live boot/slot identity before returning a read-only snapshot.
  using BootCandidateFn = bool (*)(void*, const OtaBootLifecycleEvidence&,
                                  ::ota::storage::OtaCandidateStore::Snapshot&);
  void attachBootLifecycle(void* ctx, BootLifecycleFn fn, BootCandidateFn candidate_fn = nullptr) {
    boot_ctx_ = ctx; boot_lifecycle_ = fn; boot_candidate_ = candidate_fn;
    lean_.attachTerminalCheck(this, &terminalCandidateThunk);
  }
  void attachUnadmittedAbort(void* ctx, OtaLeanReceiver::UnadmittedAbortFn fn) {
    lean_.attachUnadmittedAbort(ctx, fn);
  }
  OtaBootLifecycleEvidence bootLifecycle() const {
    OtaBootLifecycleEvidence out;
    if (boot_lifecycle_ && !boot_lifecycle_(boot_ctx_, out)) out = OtaBootLifecycleEvidence();
    return out;
  }
  static usb::UsbOtaPhase candidatePhase(::ota::storage::OtaCandidateStore::Phase phase) {
    using Phase = ::ota::storage::OtaCandidateStore::Phase;
    switch (phase) {
      case Phase::Receiving: return usb::UsbOtaPhase::Receiving;
      case Phase::Verifying: return usb::UsbOtaPhase::Verifying;
      case Phase::Ready: return usb::UsbOtaPhase::Ready;
      case Phase::Committed: return usb::UsbOtaPhase::CommitPending;
      case Phase::Aborted: return usb::UsbOtaPhase::Aborted;
      case Phase::Failed: return usb::UsbOtaPhase::Failed;
      default: return usb::UsbOtaPhase::Idle;
    }
  }
  usb::UsbOtaPhase reportedPhase() const {
    return readback().phase;
  }
  struct Readback {
    OtaLeanReceiver::Status snapshot;
    usb::UsbOtaPhase phase = usb::UsbOtaPhase::Unknown;
    bool bootCandidate = false;
  };

  Readback readback() const {
    return readback(lean_.status().localCache ? OtaBootLifecycleEvidence() : bootLifecycle());
  }

  Readback readback(const OtaBootLifecycleEvidence& boot, const uint8_t* manifest_hash = nullptr) const {
    using Phase = ::ota::storage::OtaCandidateStore::Phase;
    Readback out;
    const auto st = lean_.status();
    if (st.valid && (!manifest_hash || !std::memcmp(manifest_hash, st.manifestHash, 32))) {
      out.snapshot = st;
      out.phase = phaseForCandidate(st, boot);
      const bool superseded = boot.phase == usb::UsbOtaPhase::Installed && boot.imageVerified &&
                              boot.floorKnown && boot.confirmedFloor >= st.counter;
      if (st.localCache || st.counter > boot.counter ||
          ((st.phase == Phase::Receiving || st.phase == Phase::Verifying || st.phase == Phase::Ready) &&
           !superseded) ||
          (boot.transactionNonce && boot.transactionNonce == st.transactionNonce &&
           boot.counter == st.counter && !std::memcmp(boot.imageHash, st.imageHash, 32) &&
           out.phase == boot.phase)) return out;
    }
    ::ota::storage::OtaCandidateStore::Snapshot candidate;
    if (boot_candidate_ && boot_candidate_(boot_ctx_, boot, candidate) &&
        validBootCandidate(boot, candidate)) {
      const auto snapshot = OtaLeanReceiver::snapshotStatus(candidate);
      if (!manifest_hash || !std::memcmp(manifest_hash, snapshot.manifestHash, 32)) {
        out.snapshot = snapshot;
        out.phase = boot.phase == usb::UsbOtaPhase::Unknown ? usb::UsbOtaPhase::CommitPending : boot.phase;
        out.bootCandidate = true;
      }
    }
    return out;
  }
  void fillUsbReadback(usb::UsbOtaReply& reply) const {
    const auto view = readback();
    const auto& st = view.snapshot;
    if (!st.valid) return;
    reply.flags |= usb::kReplyFlagSnapshotValid;
    reply.phase = view.phase;
    std::memcpy(reply.manifestHash, st.manifestHash, sizeof(reply.manifestHash));
    reply.durableReceivedBlocks = st.receivedBlocks;
    reply.totalBlocks = st.totalBlocks;
    reply.counter = st.counter;
    reply.generation = st.generation;
    reply.statusAgeMs = 0;
  }
  usb::UsbOtaPhase reportedPhase(const OtaBootLifecycleEvidence& boot) const {
    return readback(boot).phase;
  }
  bool directActive() const { return direct_active_; }
  bool directPending() const { return direct_pending_; }
  void observeRadioApply(bool succeeded, const OtaAppliedRadioProfile& profile,
                         bool direct, uint32_t now_ms) {
    radio_measurement_.observeApply(succeeded, profile, direct, now_ms);
  }
  bool formatRadioMeasurement(char* out, size_t capacity, bool driver_healthy,
                             uint32_t driver_faults, uint32_t now_ms) const {
    return radio_measurement_.format(out, capacity, direct_active_, direct_expiry_ms_,
                                     driver_healthy, driver_faults, now_ms);
  }
  bool formatBudgetMeasurement(char* out, size_t capacity, uint32_t now_ms,
                              uint32_t completed_tx_ms, uint32_t timeouts,
                              uint32_t accounting_failures) const {
    const auto measured = status(now_ms);
    return formatOtaBudgetMeasurement(out, capacity, now_ms, measured.dutyWindowMs,
        measured.dutyBudgetMs, measured.dutyUsedMs, completed_tx_ms, timeouts, accounting_failures);
  }
  bool hasPendingRfWork() const {
    return commit_reboot_pending_ || direct_active_ || direct_pending_ || pending_control_frame_valid_ ||
           lean_.status().phase == ::ota::storage::OtaCandidateStore::Phase::Verifying;
  }
  void stopDirect() {
    direct_pending_ = false;
    direct_waiting_ack_ = false;
    if (pending_control_frame_valid_ && (pending_control_frame_[0] == kOtaDirectAckKind ||
        pending_control_frame_[0] == kOtaDirectProfileAckKind)) pending_control_frame_valid_ = false;
    if (direct_active_ && applyDirectRadio(normal_freq_khz_, OtaDirectProfile::Legacy250, true)) direct_active_ = false;
  }
  __attribute__((noinline)) void tickDirect(uint32_t now_ms, bool radio_idle = true) {
    if (direct_active_ && static_cast<int32_t>(now_ms - direct_expiry_ms_) >= 0) stopDirect();
    if (direct_pending_ && static_cast<int32_t>(now_ms - direct_transition_deadline_) >= 0) stopDirect();
    if (direct_pending_ && direct_ack_tx_wait_ && !pending_control_frame_valid_ && radio_idle) {
      // Begin the receiver's transition delay after ACK TX drained, not
      // when its request arrived (a queued/duty-delayed ACK is not sent).
      direct_ack_tx_wait_ = false;
      direct_apply_ms_ = now_ms + 5000u;
    }
    if (direct_pending_ && !direct_ack_tx_wait_ && !pending_control_frame_valid_ &&
        static_cast<int32_t>(now_ms - direct_apply_ms_) >= 0 && radio_idle) {
      direct_pending_ = false;
      if (applyDirectRadio(direct_freq_khz_, direct_profile_, false)) {
        direct_active_ = true;
        direct_expiry_ms_ = now_ms + direct_lease_ms_;
      } else if (!applyDirectRadio(normal_freq_khz_, OtaDirectProfile::Legacy250, true)) {
        direct_active_ = true;
        direct_expiry_ms_ = now_ms;
      }
    }
    const auto st = lean_.status();
    if (direct_active_ && (st.phase == ::ota::storage::OtaCandidateStore::Phase::Aborted ||
                          st.phase == ::ota::storage::OtaCandidateStore::Phase::Committed ||
                          !st.valid || (!st.localCache && !lean_.currentAdmin(st.ownerPublicKey)))) stopDirect();
  }
  size_t buildDirectRequest(const uint8_t target[32], uint32_t freq_khz, uint16_t lease_ms,
                            uint32_t token, uint8_t* out, size_t capacity,
                            OtaDirectProfile profile = OtaDirectProfile::Legacy250) {
    const auto st = lean_.status();
    if (!st.valid || !rf_sign_ || !lean_.haveTargetPublicKey() || freq_khz == normal_freq_khz_ ||
        freq_khz < 150000 || freq_khz > 2500000 || lease_ms < usb::kDirectLeaseMsMin ||
        lease_ms > usb::kDirectLeaseMsMax || direct_active_ || direct_pending_ || !isOtaDirectProfile(profile) ||
        (profile == OtaDirectProfile::Bw500 && !supportsDirectProfile(profile))) return 0;
    const auto len = profile == OtaDirectProfile::Legacy250 ?
        encodeOtaDirectFrame(kOtaDirectRequestKind, lean_.targetPublicKey(), target, st.manifestHash,
                            freq_khz, lease_ms, token, out, capacity) :
        encodeOtaDirectProfileFrame(kOtaDirectProfileRequestKind, profile, lean_.targetPublicKey(), target,
                                   st.manifestHash, freq_khz, lease_ms, token, out, capacity);
    if (!len) return 0;
    uint8_t message[160];
    const auto mlen = buildOtaDirectMessage(out, message);
    rf_sign_(rf_ctx_, message, mlen, out + 107);
    std::memcpy(direct_request_, out, 107);
    direct_waiting_ack_ = true;
    return len;
  }
  bool backendAvailable() const { return trust_provider_ != nullptr && staging_sink_ != nullptr; }

  // --- Real-mesh (RF-only) remote-target observation tracking ---------
  // Used by an uploader (e.g. the companion USB-driven uploader) to learn
  // whether a remote target it added actually has the candidate in Ready
  // phase, WITHOUT ever trusting a stale/cached belief: `trackOtaTarget`
  // registers interest, `requestStatusPoll` builds an (unsigned,
  // authority-free) solicitation frame to provoke a fresh reply, and
  // `targetObservation` reports the age of the last reply actually seen
  // from that exact reporter key so a caller can tell a genuinely fresh
  // remote observation from a stale/nonexistent one (age ==
  // kNoObservationAgeMs means "never observed").
  static constexpr size_t kMaxTrackedOtaTargets = usb::kMaxSelectedTargets;
  static constexpr uint32_t kNoObservationAgeMs = 0xFFFFFFFFu;

  struct TargetObservation {
    bool tracked = false;
    bool haveReport = false;
    uint32_t ageMs = kNoObservationAgeMs;
    uint16_t receivedBlocks = 0;
    uint16_t totalBlocks = 0;
    uint8_t phase = 0;
    uint8_t manifestHash[32] = {};
    uint16_t first = 0;
    uint8_t bitmap[kOtaCensusBitmapBytes] = {};
    bool haveBitmap = false;
    uint32_t generation = 0;
    usb::UsbOtaPhase lifecyclePhase = usb::UsbOtaPhase::Unknown;
    bool haveLifecycle = false, floorKnown = false;
    uint32_t confirmedFloor = 0, counter = 0;
  };

  void trackOtaTarget(const uint8_t target_pk[32]) {
    if (target_pk == nullptr) return;
    int free_slot = -1;
    uint32_t oldest_seen = 0xFFFFFFFFu;
    int oldest_slot = 0;
    for (size_t i = 0; i < kMaxTrackedOtaTargets; ++i) {
      if (targets_[i].tracked && std::memcmp(targets_[i].publicKey, target_pk, 32) == 0) return;
      if (!targets_[i].tracked && free_slot < 0) free_slot = static_cast<int>(i);
      if (targets_[i].lastSeenMs <= oldest_seen) { oldest_seen = targets_[i].lastSeenMs; oldest_slot = static_cast<int>(i); }
    }
    const int slot = (free_slot >= 0) ? free_slot : oldest_slot;
    targets_[slot] = TrackedTarget();
    targets_[slot].tracked = true;
    std::memcpy(targets_[slot].publicKey, target_pk, 32);
  }
  void clearTargetObservation(const uint8_t key[32]) {
    for (auto& t : targets_) {
      if (!t.tracked || std::memcmp(t.publicKey, key, 32)) continue;
      t.haveReport = false; t.haveBitmap = false;
    }
  }

  bool targetObservation(const uint8_t target_pk[32], uint32_t now_ms, TargetObservation& out) const {
    out = TargetObservation();
    if (target_pk == nullptr) return false;
    for (size_t i = 0; i < kMaxTrackedOtaTargets; ++i) {
      if (!targets_[i].tracked || std::memcmp(targets_[i].publicKey, target_pk, 32) != 0) continue;
      out.tracked = true;
      if (targets_[i].haveReport) {
        out.haveReport = true;
        out.ageMs = now_ms - targets_[i].lastSeenMs;
        out.receivedBlocks = targets_[i].receivedBlocks;
        out.totalBlocks = targets_[i].totalBlocks;
        out.phase = targets_[i].phase;
        std::memcpy(out.manifestHash, targets_[i].manifestHash, 32);
        std::memcpy(out.bitmap, targets_[i].bitmap, kOtaCensusBitmapBytes);
        out.first = targets_[i].first;
        out.haveBitmap = targets_[i].haveBitmap;
        out.generation = targets_[i].generation;
        out.lifecyclePhase = targets_[i].lifecyclePhase;
        out.haveLifecycle = targets_[i].haveLifecycle;
        out.floorKnown = targets_[i].floorKnown;
        out.confirmedFloor = targets_[i].confirmedFloor;
        out.counter = targets_[i].counter;
      }
      return true;
    }
    return false;
  }

  // Builds the (unsigned, informational-only) poll frame that a caller
  // should transmit to provoke a fresh StatusReport from a tracked
  // target -- a forged poll can only cause an extra harmless broadcast,
  // never an authority decision, so it deliberately carries no signature.
  size_t buildStatusPollFrame(const uint8_t manifest_tag[kOtaManifestTagBytes],
                             uint8_t* out, size_t out_capacity) const {
    return encodeOtaStatusPollFrame(manifest_tag, out, out_capacity);
  }

  // Drains at most one queued outbound StatusReport reply this node owes
  // (in response to a received StatusPoll for its own admitted
  // candidate). The caller (board/Mesh loop) is responsible for actually
  // transmitting the bytes; this object only ever stages one at a time.
  bool pollOutboundControlFrame(uint8_t* out, size_t out_capacity, size_t& out_len) {
    if (!pending_control_frame_valid_) return false;
    if (out == nullptr || out_capacity < pending_control_frame_len_) return false;
    std::memcpy(out, pending_control_frame_, pending_control_frame_len_);
    out_len = pending_control_frame_len_;
    pending_control_frame_valid_ = false;
    return true;
  }
  bool peekOutboundControlFrame(uint8_t* out, size_t capacity, size_t& len, uint32_t now_ms) const {
    if (!pending_control_frame_valid_ || static_cast<int32_t>(now_ms - pending_control_due_ms_) < 0 ||
        !out || capacity < pending_control_frame_len_) return false;
    std::memcpy(out, pending_control_frame_, pending_control_frame_len_);
    len = pending_control_frame_len_;
    return true;
  }
  void releaseOutboundControlFrame() { pending_control_frame_valid_ = false; }

  const meshcore::ota::runtime::OtaAirtimeLimiter& airtimeLimiter() const { return airtime_; }
  meshcore::ota::runtime::OtaAirtimeLimiter& airtimeLimiter() { return airtime_; }

  bool canTransmit(uint32_t now_ms,
                   meshcore::ota::protocol::OtaAirtimeCategory category,
                   uint32_t prospective_airtime_ms,
                   bool regulatory_allowed,
                   bool normal_traffic_active) const {
    // The configured share applies on-mesh, not to the negotiated
    // off-frequency SF5 window. Bound every off-mesh TX by the remaining
    // lease instead (including TX completion margin), and retain normal
    // queue precedence and regulatory gating.
    if (direct_active_) {
      const int32_t remaining = static_cast<int32_t>(direct_expiry_ms_ - now_ms);
      return budget_ms_ != 0 && regulatory_allowed && !normal_traffic_active && remaining > 0 &&
             static_cast<uint64_t>(prospective_airtime_ms) * 3u / 2u + 20u < static_cast<uint32_t>(remaining);
    }
    const uint64_t completion_bound_ms = static_cast<uint64_t>(prospective_airtime_ms) * 3u / 2u + 20u;
    if (completion_bound_ms > UINT32_MAX) return false;
    meshcore::ota::runtime::OtaAirtimeDecisionInput input;
    input.regulatoryAllowed = regulatory_allowed;
    input.normalTrafficActive = normal_traffic_active;
    return airtime_.canAdmit(now_ms, category, static_cast<uint32_t>(completion_bound_ms), input);
  }

  bool recordTransmit(uint32_t now_ms,
                      meshcore::ota::protocol::OtaAirtimeCategory category,
                      uint32_t airtime_ms) {
    if (direct_active_) return true;
    return airtime_.recordUsage(now_ms, category, airtime_ms);
  }

  __attribute__((noinline)) bool handleReceivedFrame(
      const uint8_t* frame, size_t frame_len, uint32_t now_ms = 0) {
    uint32_t attempt = 0;
    if (frame && frame_len && isOtaRetryAttempt(frame[0])) {
      const uint8_t* inner; size_t inner_len;
      if (!parseOtaRetryAttempt(frame, frame_len, attempt, inner, inner_len)) {
        ++bad_frames_;
        return false;
      }
      frame = inner; frame_len = inner_len;
    }
    const bool was_pending = pending_control_frame_valid_;
    const bool accepted = handleReceivedInnerFrame(frame, frame_len, now_ms);
    if (accepted && attempt && (!was_pending || frame[0] == kOtaCommitKind) &&
        pending_control_frame_valid_) {
      pending_control_frame_len_ = encodeOtaRetryAttempt(attempt, pending_control_frame_,
          pending_control_frame_len_, pending_control_frame_, sizeof(pending_control_frame_));
      pending_control_frame_valid_ = pending_control_frame_len_ != 0;
    }
    return accepted;
  }

private:
  __attribute__((noinline)) bool handleReceivedInnerFrame(
      const uint8_t* frame, size_t frame_len, uint32_t now_ms) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    OtaEnvelopeHeader hdr;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    OtaCodecResult decoded = decodeOtaEnvelope(frame, frame_len, hdr, payload, payload_len);
    if (decoded != OtaCodecResult::Ok) {
      const LeanControlResult control = handleLeanControlFrame(frame, frame_len, now_ms);
      if (control == LeanControlResult::Handled) {
        ++rx_frames_;
        return true;
      }
      if (control == LeanControlResult::Rejected) {
        ++bad_frames_;
        return false;
      }
      const auto lean_result = lean_.handleSignedBlockFrame(frame, frame_len);
      if (lean_result == usb::UsbOtaResult::Ok) {
        ++rx_frames_;
        return true;
      }
      ++bad_frames_;
      return false;
    }

    // A configured lean product must not allow the obsolete envelope
    // session to write the same candidate bank around its durable owner.
    if (lean_.hasStore()) { ++bad_frames_; return false; }
    ++rx_frames_;
    return handleDecodedEnvelope(hdr, payload, payload_len);
  }

private:
  bool retry_attempts_enabled_ = false, retry_attempts_exhausted_ = false;
  uint32_t retry_next_attempt_ = 0;
  __attribute__((noinline)) bool handleDecodedEnvelope(
      const meshcore::ota::protocol::OtaEnvelopeHeader& hdr, const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;
    const OtaSessionId id = otaSessionFromEnvelope(hdr);
    switch (hdr.type) {
      case OtaMessageType::DescriptorFragment:
        return handleDescriptorFragment(id, payload, payload_len);

      case OtaMessageType::Authorization:
        return handleAuthorization(id, payload, payload_len);

      case OtaMessageType::Chunk:
        return handleChunk(id, payload, payload_len);

      case OtaMessageType::Receipt:
        return handleReceipt(id, payload, payload_len);

      case OtaMessageType::Abort:
        if (!receiver_.handle(OtaReceiverEvent::Abort, id)) {
          return false;
        }
        coordinator_.handle(OtaCoordinatorEvent::Abort, id);
        fleet_.handle(OtaFleetEvent::Abort, id);
        lease_.handle(OtaLeaseEvent::Reset);
        resetTransferSession();
        ++aborted_sessions_;
        return true;

      case OtaMessageType::LeaseNegotiation:
        return handleLeaseNegotiation(payload, payload_len);

      case OtaMessageType::Announcement:
        return handleAnnouncement(id, payload, payload_len);

      case OtaMessageType::Census:
        return handleCensus(id, payload, payload_len);

      case OtaMessageType::CohortResolution:
        return handleCohortResolution(id, payload, payload_len);

      case OtaMessageType::MissingRange:
        return handleMissingRange(id, payload, payload_len);

      case OtaMessageType::Commit:
        return handleCommit(id, payload, payload_len);
    }
    return false;
  }

public:
  void abortSession() {
    stopDirect();
    if (lean_.hasStore()) {
      // This legacy transport-stop command has no signed image hash.
      // It must not abort the lean sink behind a durable READY/cache
      // snapshot, nor discard the candidate's original owner/progress.
      ++aborted_sessions_;
      return;
    }
    receiver_.reset();
    coordinator_.reset();
    fleet_.reset();
    lease_.handle(meshcore::ota::runtime::OtaLeaseEvent::Reset);
    resetTransferSession();
    ++aborted_sessions_;
  }

  void requestRollback() {
    rollback_requested_ = true;
    abortSession();
  }

  FirmwareOtaStatus status(uint32_t now_ms) const {
    FirmwareOtaStatus s;
    s.mode = mode_;
    s.dutyCyclePercent = duty_percent_;
    s.dutyWindowMs = window_ms_;
    s.dutyBudgetMs = budget_ms_;
    s.dutyUsedMs = airtime_.storedUsageMs(now_ms);
    s.receiverState = receiver_.state();
    s.coordinatorState = coordinator_.state();
    s.fleetState = fleet_.state();
    s.leaseState = lease_.state();
    s.rxFrames = rx_frames_;
    s.badFrames = bad_frames_;
    s.abortedSessions = aborted_sessions_;
    s.rollbackRequested = rollback_requested_;
    s.backendAvailable = backendAvailable();
    s.fleetCensusReports = fleet_census_reports_;
    s.fleetHasCohort = fleet_has_cohort_;
    s.fleetCohortId = fleet_cohort_.cohortId;
    s.fleetCohortSize = fleet_cohort_.cohortSize;
    s.fleetCohortIndex = fleet_cohort_.cohortIndex;
    s.fleetMissingRangeCount = static_cast<uint16_t>(fleet_last_census_.missingRangeCount);
    return s;
  }

private:
  static bool terminalCandidateThunk(void* ctx, const ::ota::storage::OtaCandidateStore::Snapshot& candidate) {
    return static_cast<OtaFirmwareIntegration*>(ctx)->terminalCandidate(candidate);
  }
  bool terminalCandidate(const ::ota::storage::OtaCandidateStore::Snapshot& candidate) const {
    using Phase = ::ota::storage::OtaCandidateStore::Phase;
    if (!candidate.valid || candidate.localCache ||
        (candidate.phase != Phase::Committed && candidate.phase != Phase::Ready && candidate.phase != Phase::Failed) ||
        !validCandidateGeometry(candidate, candidate.phase != Phase::Failed) ||
        !lean_.verifySignature(candidate.ownerPublicKey, candidate.canonical, sizeof(candidate.canonical),
                               candidate.signature)) return false;
    const auto boot = bootLifecycle();
    if (boot.phase != usb::UsbOtaPhase::Installed && boot.phase != usb::UsbOtaPhase::Failed) return false;
    return validBootCandidate(boot, candidate, true);
  }
  static bool validBootCandidate(const OtaBootLifecycleEvidence& boot,
                                 const ::ota::storage::OtaCandidateStore::Snapshot& candidate,
                                 bool retiring = false) {
    using Phase = ::ota::storage::OtaCandidateStore::Phase;
    const bool failed = boot.phase == usb::UsbOtaPhase::Failed;
    if (!candidate.valid || candidate.localCache ||
        (candidate.phase != (failed ? Phase::Failed : Phase::Committed) &&
         !(retiring && (candidate.phase == Phase::Ready || (failed && candidate.phase == Phase::Committed)))) ||
        !boot.transactionNonce ||
        (failed ? boot.imageVerified : !boot.imageVerified) ||
        (!failed && boot.phase != usb::UsbOtaPhase::Trial && boot.phase != usb::UsbOtaPhase::Installed &&
         boot.phase != usb::UsbOtaPhase::Unknown)) return false;
    if (!validCandidateGeometry(candidate, !failed || (retiring && candidate.phase != Phase::Failed))) return false;
    const auto st = OtaLeanReceiver::snapshotStatus(candidate);
    return st.counter != 0 && st.counter == boot.counter && st.transactionNonce == boot.transactionNonce &&
           !std::memcmp(st.imageHash, boot.imageHash, 32) &&
           (boot.phase != usb::UsbOtaPhase::Installed ||
            (boot.floorKnown && boot.confirmedFloor == st.counter));
  }
  static bool validCandidateGeometry(const ::ota::storage::OtaCandidateStore::Snapshot& candidate, bool complete) {
    meshcore::ota::protocol::OtaDescriptor descriptor;
    if (meshcore::ota::protocol::decodeOtaDescriptorCanonical(candidate.canonical, sizeof(candidate.canonical),
          descriptor) != meshcore::ota::protocol::OtaDescriptorCodecResult::Ok ||
        descriptor.formatId != 1 || descriptor.algorithmId != 1 || descriptor.keyId == 0 ||
        descriptor.appAddress == 0 || descriptor.exactSizeBytes == 0 ||
        descriptor.exactSizeBytes > ::ota::storage::OtaCandidateStore::kMaxBlocks * kOtaBlockMaxDataBytes ||
        candidate.exactSizeBytes != descriptor.exactSizeBytes ||
        candidate.totalBlocks != (descriptor.exactSizeBytes + kOtaBlockMaxDataBytes - 1u) / kOtaBlockMaxDataBytes ||
        candidate.receivedBlocks > candidate.totalBlocks ||
        (complete && candidate.receivedBlocks != candidate.totalBlocks)) return false;
    return true;
  }
  usb::UsbOtaPhase phaseForCandidate(const OtaLeanReceiver::Status& st,
                                    const OtaBootLifecycleEvidence& boot) const {
    if (!st.valid) return usb::UsbOtaPhase::Unknown;
    if (st.localCache) return st.phase == ::ota::storage::OtaCandidateStore::Phase::Ready ?
                                usb::UsbOtaPhase::CacheSealed : candidatePhase(st.phase);
    if (boot.transactionNonce == st.transactionNonce && boot.transactionNonce && boot.counter == st.counter) {
      if (boot.phase == usb::UsbOtaPhase::Failed) return usb::UsbOtaPhase::Failed;
      if ((boot.phase == usb::UsbOtaPhase::Trial || boot.phase == usb::UsbOtaPhase::Installed) &&
          !std::memcmp(boot.imageHash, st.imageHash, 32)) {
        uint8_t canonical[59], signature[64];
        if (lean_.exportCandidateForUpload(canonical, signature) &&
            lean_.verifySignature(st.ownerPublicKey, canonical, sizeof(canonical), signature) &&
            (boot.phase == usb::UsbOtaPhase::Trial ||
             (boot.imageVerified && boot.floorKnown && boot.confirmedFloor == st.counter))) return boot.phase;
      }
    }
    return candidatePhase(st.phase);
  }
  static constexpr size_t kDescriptorFragmentHeaderSize = 1 + 1 + 2 + 2;

  enum class LeanControlResult { NotControlFrame, Handled, Rejected };

  struct TrackedTarget {
    bool tracked = false;
    uint8_t publicKey[32] = {0};
    bool haveReport = false;
    uint32_t lastSeenMs = 0;
    uint16_t receivedBlocks = 0;
    uint16_t totalBlocks = 0;
    uint8_t phase = 0;
    uint8_t manifestHash[32] = {};
    uint16_t first = 0;
    uint8_t bitmap[kOtaCensusBitmapBytes] = {};
    bool haveBitmap = false;
    uint32_t generation = 0;
    usb::UsbOtaPhase lifecyclePhase = usb::UsbOtaPhase::Unknown;
    bool haveLifecycle = false, floorKnown = false;
    uint32_t confirmedFloor = 0, counter = 0;
  };

  // Dispatches the 4 real-mesh lean control-frame kinds (Authorization /
  // Commit / Abort / StatusReport / StatusPoll, see OtaRfFrames.h) that
  // are NOT the per-block SignedBlock frame. Any frame whose first byte
  // doesn't match one of these kinds is NotControlFrame (falls through to
  // the SignedBlock path unchanged); a recognized kind that fails to
  // parse or is denied by lean_ is Rejected (counted as a bad frame, no
  // fallback attempted -- these kind bytes can never also be a valid
  // SignedBlock frame, see OtaBlockSigning.h kOtaSignedBlockKind=0x01).
  __attribute__((noinline)) LeanControlResult handleLeanControlFrame(
      const uint8_t* frame, size_t frame_len, uint32_t now_ms) {
    if (frame == nullptr || frame_len == 0) return LeanControlResult::NotControlFrame;
    switch (frame[0]) {
      case kOtaTargetAuthorizationKind:
      case kOtaAuthorizationKind: return handleAuthorizationControl(frame, frame_len);
      case kOtaCommitKind: return handleCommitControl(frame, frame_len, now_ms);
      case kOtaAbortKind: return handleAbortControl(frame, frame_len);
      case kOtaReuploadKind: return handleReuploadControl(frame, frame_len);
      default: return handleInformationalControlFrame(frame, frame_len, now_ms);
    }
  }

  __attribute__((noinline)) LeanControlResult handleAuthorizationControl(const uint8_t* frame, size_t frame_len) {
    static std::atomic_flag busy = ATOMIC_FLAG_INIT;
    OtaBoardProofScratchLease lease(busy);
    if (!lease) return LeanControlResult::Rejected;
    if (frame[0] == kOtaTargetAuthorizationKind) {
      if (frame_len != 164 || !lean_.haveTargetPublicKey()) return LeanControlResult::Rejected;
      uint8_t tag[8]; otaTargetTag(lean_.targetPublicKey(), tag);
      if (std::memcmp(tag, frame + 1, 8)) return LeanControlResult::Rejected;
      const auto r = lean_.begin(frame + 9, frame + 41, frame + 100, false, false);
      return r == usb::UsbOtaResult::Ok || lean_.prepareReupload(frame + 9, frame + 41, frame + 100) ?
                LeanControlResult::Handled : LeanControlResult::Rejected;
    }
    static OtaAuthorizationFrame parsed;
    if (!parseOtaAuthorizationFrame(frame, frame_len, parsed)) return LeanControlResult::Rejected;
    const auto r = lean_.begin(parsed.ownerPublicKey, parsed.canonical, parsed.signature, false, false);
    return r == usb::UsbOtaResult::Ok ? LeanControlResult::Handled : LeanControlResult::Rejected;
  }

  __attribute__((noinline)) LeanControlResult handleCommitControl(
      const uint8_t* frame, size_t frame_len, uint32_t now_ms) {
    static std::atomic_flag busy = ATOMIC_FLAG_INIT;
    OtaBoardProofScratchLease lease(busy);
    if (!lease) return LeanControlResult::Rejected;
    static OtaCommitFrame parsed;
    if (!parseOtaCommitFrame(frame, frame_len, parsed)) return LeanControlResult::Rejected;
    static OtaLeanReceiver::Status st;
    captureLeanStatus(st);
    if (!lean_.haveTargetPublicKey() || std::memcmp(parsed.target, lean_.targetPublicKey(), 32) ||
        !st.valid || std::memcmp(parsed.manifestHash, st.manifestHash, 32)) return LeanControlResult::Rejected;
    const auto r = commitAndDeferReboot(parsed.counter, parsed.signature, now_ms);
    if (r == usb::UsbOtaResult::Ok) {
      uint8_t tag[kOtaManifestTagBytes];
      manifestTagFromHash(st.manifestHash, tag);
      pending_control_frame_valid_ = false;
      queueStatusReportReply(tag);
      pending_control_due_ms_ = now_ms;
    }
    return r == usb::UsbOtaResult::Ok ? LeanControlResult::Handled : LeanControlResult::Rejected;
  }

  __attribute__((noinline)) LeanControlResult handleAbortControl(const uint8_t* frame, size_t frame_len) {
    static std::atomic_flag busy = ATOMIC_FLAG_INIT;
    OtaBoardProofScratchLease lease(busy);
    if (!lease) return LeanControlResult::Rejected;
    static OtaAbortFrame parsed;
    if (!parseOtaAbortFrame(frame, frame_len, parsed)) return LeanControlResult::Rejected;
    if (!lean_.haveTargetPublicKey() || std::memcmp(parsed.target, lean_.targetPublicKey(), 32))
      return LeanControlResult::Rejected;
    const auto r = lean_.abort(parsed.signerPublicKey, parsed.signature, parsed.imageHash, parsed.generation);
    if (r == usb::UsbOtaResult::Ok) stopDirect();
    return r == usb::UsbOtaResult::Ok ? LeanControlResult::Handled : LeanControlResult::Rejected;
  }

  __attribute__((noinline)) LeanControlResult handleReuploadControl(const uint8_t* frame, size_t frame_len) {
    static std::atomic_flag busy = ATOMIC_FLAG_INIT;
    OtaBoardProofScratchLease lease(busy);
    if (!lease) return LeanControlResult::Rejected;
    if (frame_len != kOtaReuploadFrameBytes) return LeanControlResult::Rejected;
    static OtaLeanReceiver::Status st;
    captureLeanStatus(st);
    if (!st.valid || st.phase != ::ota::storage::OtaCandidateStore::Phase::Aborted ||
        !lean_.haveTargetPublicKey() || std::memcmp(frame + 33, lean_.targetPublicKey(), 32) ||
        usb::getBE32(frame + 97) != st.generation || !lean_.currentAdmin(frame + 1))
      return LeanControlResult::Rejected;
    static uint8_t message[160], canonical[59], sig[64];
    auto len = buildOtaReuploadMessage(frame, message);
    if (!lean_.verifySignature(frame + 1, message, len, frame + 101)) return LeanControlResult::Rejected;
    usb::UsbOtaResult result;
    // A local cache always needs fresh receiver authorization, even for identical content.
    if (!st.localCache && std::memcmp(frame + 65, st.manifestHash, 32) == 0 && std::memcmp(frame + 1, st.ownerPublicKey, 32) == 0) {
      if (!lean_.exportCandidateForUpload(canonical, sig)) return LeanControlResult::Rejected;
      result = lean_.begin(st.ownerPublicKey, canonical, sig, true, false);
    } else {
      result = lean_.activatePreparedReupload(frame + 1, frame + 65);
    }
    return result == usb::UsbOtaResult::Ok ? LeanControlResult::Handled : LeanControlResult::Rejected;
  }

  __attribute__((noinline)) void captureLeanStatus(OtaLeanReceiver::Status& out) const {
    out = lean_.status();
  }
  __attribute__((noinline)) uint64_t currentTransactionNonce() const {
    return lean_.status().transactionNonce;
  }

  __attribute__((noinline)) LeanControlResult handleInformationalControlFrame(
      const uint8_t* frame, size_t frame_len, uint32_t now_ms) {
    if (frame == nullptr || frame_len == 0) return LeanControlResult::NotControlFrame;
    switch (frame[0]) {
      case kOtaStatusReportKind: {
        OtaStatusReportFrame parsed;
        if (!parseOtaStatusReportFrame(frame, frame_len, parsed)) return LeanControlResult::Rejected;
        recordTargetObservation(parsed, now_ms);
        return LeanControlResult::Handled;
      }
      case kOtaCensusPollKind: {
        if (frame_len != kOtaCensusPollBytes || !lean_.haveTargetPublicKey()) return LeanControlResult::Rejected;
        if (std::memcmp(frame + 1, lean_.targetPublicKey(), 32)) return LeanControlResult::Handled;
        const auto boot = bootLifecycle();
        const auto view = readback(boot, frame + 33);
        auto st = view.snapshot;
        const bool pending = !st.valid;
        if (pending && !lean_.pendingReuploadStatus(frame + 33, st)) return LeanControlResult::Handled;
        if (st.localCache) return LeanControlResult::Handled;
        if (pending_control_frame_valid_) return LeanControlResult::Handled;
        OtaCensusReport r;
        std::memcpy(r.reporter, lean_.targetPublicKey(), 32);
        std::memcpy(r.manifestHash, st.manifestHash, 32);
        r.first = usb::getBE16(frame + 65);
        if (r.first >= st.totalBlocks) return LeanControlResult::Rejected;
        for (size_t bit = 0; bit < kOtaCensusWindowBlocks; ++bit) {
          const uint32_t index = static_cast<uint32_t>(r.first) + bit;
          if (!pending && index < st.totalBlocks &&
              (view.bootCandidate ? st.receivedBlocks == st.totalBlocks : lean_.isBlockReceived(index)))
            r.bitmap[bit / 8] |= 1u << (bit % 8);
        }
        r.received = st.receivedBlocks; r.total = st.totalBlocks;
        r.phase = static_cast<uint8_t>(st.phase); r.generation = st.generation;
        r.lifecyclePhase = pending ? usb::UsbOtaPhase::Aborted : view.phase;
        r.floorKnown = boot.floorKnown; r.confirmedFloor = boot.confirmedFloor;
        r.counter = st.counter;
        pending_control_frame_len_ = encodeOtaCensusReport(r, pending_control_frame_, sizeof(pending_control_frame_));
        pending_control_frame_valid_ = pending_control_frame_len_ != 0;
        pending_control_due_ms_ = now_ms + ((r.reporter[0] * 17u + r.reporter[31]) % 250u);
        return LeanControlResult::Handled;
      }
      case kOtaCensusReportKind: {
        OtaCensusReport r;
        if (!parseOtaCensusReport(frame, frame_len, r) || r.received > r.total) return LeanControlResult::Rejected;
        const auto st = lean_.status();
        if (!st.valid || std::memcmp(st.manifestHash, r.manifestHash, 32) || r.total != st.totalBlocks ||
            r.first >= st.totalBlocks || (r.haveLifecycle && r.counter != st.counter)) return LeanControlResult::Rejected;
        for (auto& t : targets_) {
          if (!t.tracked || std::memcmp(t.publicKey, r.reporter, 32)) continue;
          t.haveReport = true; t.lastSeenMs = now_ms;
          t.receivedBlocks = r.received; t.totalBlocks = r.total; t.phase = r.phase;
          std::memcpy(t.manifestHash, r.manifestHash, 32);
          t.first = r.first; std::memcpy(t.bitmap, r.bitmap, kOtaCensusBitmapBytes); t.haveBitmap = true;
          t.generation = r.generation;
          t.lifecyclePhase = r.lifecyclePhase; t.haveLifecycle = r.haveLifecycle;
          t.floorKnown = r.floorKnown; t.confirmedFloor = r.confirmedFloor; t.counter = r.counter;
        }
        return LeanControlResult::Handled;
      }
      case kOtaDirectRequestKind:
      case kOtaDirectAckKind:
      case kOtaDirectProfileRequestKind:
      case kOtaDirectProfileAckKind:
        return handleDirectFrame(frame, frame_len, now_ms);
      case kOtaStatusPollKind: {
        OtaStatusPollFrame parsed;
        if (!parseOtaStatusPollFrame(frame, frame_len, parsed)) return LeanControlResult::Rejected;
        queueStatusReportReply(parsed.manifestTag);
        return LeanControlResult::Handled;
      }

      default:
        return LeanControlResult::NotControlFrame;
    }
  }

  LeanControlResult handleDirectFrame(const uint8_t* frame, size_t len, uint32_t now) {
        if (len != kOtaDirectFrameBytes || !rf_sign_ || (!rf_radio_change_ && !rf_profile_radio_change_) ||
            !lean_.haveTargetPublicKey()) return LeanControlResult::Rejected;
        const auto st = lean_.status();
        if (!st.valid || std::memcmp(frame + 65, st.manifestHash, 32)) return LeanControlResult::Rejected;
        uint32_t freq = 0;
        OtaDirectProfile profile;
        if (!parseOtaDirectProfile(frame, len, profile, freq) ||
            (profile == OtaDirectProfile::Bw500 && !rf_profile_radio_change_)) return LeanControlResult::Rejected;
        const uint16_t lease = usb::getBE16(frame + 101);
        if (freq == normal_freq_khz_ || freq < 150000 || freq > 2500000 ||
            lease < usb::kDirectLeaseMsMin || lease > usb::kDirectLeaseMsMax) return LeanControlResult::Rejected;
        uint8_t message[160];
        const auto mlen = buildOtaDirectMessage(frame, message);
        if (frame[0] == kOtaDirectAckKind || frame[0] == kOtaDirectProfileAckKind) {
          const uint8_t expected_ack = direct_request_[0] == kOtaDirectRequestKind ?
              kOtaDirectAckKind : kOtaDirectProfileAckKind;
          if (!direct_waiting_ack_ || frame[0] != expected_ack || std::memcmp(frame + 1, direct_request_ + 1, 106) ||
              !lean_.verifySignature(frame + 33, message, mlen, frame + 107)) return LeanControlResult::Rejected;
          direct_waiting_ack_ = false;
          direct_ack_tx_wait_ = false;
        } else {
          if (st.localCache || std::memcmp(frame + 33, lean_.targetPublicKey(), 32) ||
              std::memcmp(frame + 1, st.ownerPublicKey, 32) || !lean_.currentAdmin(frame + 1) ||
              (st.phase != ::ota::storage::OtaCandidateStore::Phase::Receiving &&
               st.phase != ::ota::storage::OtaCandidateStore::Phase::Ready) ||
              !lean_.verifySignature(frame + 1, message, mlen, frame + 107)) return LeanControlResult::Rejected;
          if (direct_active_ || direct_pending_ || pending_control_frame_valid_) return LeanControlResult::Handled;
          // A repeated signed request must not renew a lease after a timeout.
          const uint32_t token = usb::getBE32(frame + 103);
          if (direct_have_token_ && token == direct_last_token_) return LeanControlResult::Rejected;
          direct_have_token_ = true; direct_last_token_ = token;
          std::memcpy(pending_control_frame_, frame, len);
          pending_control_frame_[0] = frame[0] == kOtaDirectRequestKind ? kOtaDirectAckKind : kOtaDirectProfileAckKind;
          const auto ack_len = buildOtaDirectMessage(pending_control_frame_, message);
          rf_sign_(rf_ctx_, message, ack_len, pending_control_frame_ + 107);
          pending_control_frame_len_ = len; pending_control_frame_valid_ = true; pending_control_due_ms_ = now;
          direct_ack_tx_wait_ = true;
        }
        direct_freq_khz_ = freq; direct_lease_ms_ = lease; direct_profile_ = profile;
        direct_apply_ms_ = now + 5000u; direct_pending_ = true;
        direct_transition_deadline_ = now + 20000u;
        return LeanControlResult::Handled;
  }

  // Unsigned/informational by design (see OtaRfFrames.h header comment):
  // only ever updates bookkeeping for a target this node itself chose to
  // track via trackOtaTarget(), never an authority decision.
  void recordTargetObservation(const OtaStatusReportFrame& report, uint32_t now_ms) {
    const auto st = lean_.status();
    if (st.valid && std::memcmp(report.manifestTag, st.manifestHash, kOtaManifestTagBytes)) return;
    for (size_t i = 0; i < kMaxTrackedOtaTargets; ++i) {
      if (!targets_[i].tracked || std::memcmp(targets_[i].publicKey, report.reporterPublicKey, 32) != 0) continue;
      targets_[i].haveReport = true;
      targets_[i].lastSeenMs = now_ms;
      targets_[i].receivedBlocks = report.receivedBlocks;
      targets_[i].totalBlocks = report.totalBlocks;
      targets_[i].phase = report.phase;
      return;
    }
  }

  // Stages (at most one pending) an outbound StatusReport reply to a
  // StatusPoll, only if this node itself currently holds a valid admitted
  // candidate matching the polled manifest tag -- a poll for any other
  // tag, or arriving while idle, is silently ignored (never an error:
  // StatusPoll carries no authority, so there is nothing to fail closed).
  __attribute__((noinline)) void queueStatusReportReply(const uint8_t manifest_tag[kOtaManifestTagBytes]) {
    const auto st = lean_.status();
    if (!st.valid || st.localCache || !lean_.haveTargetPublicKey() || pending_control_frame_valid_) return;
    uint8_t my_tag[kOtaManifestTagBytes];
    manifestTagFromHash(st.manifestHash, my_tag);
    if (std::memcmp(my_tag, manifest_tag, kOtaManifestTagBytes) != 0) return;
    const uint8_t phase = static_cast<uint8_t>(st.phase);
    const size_t len = encodeOtaStatusReportFrame(lean_.targetPublicKey(), my_tag, st.receivedBlocks,
                                                  st.totalBlocks, phase, pending_control_frame_,
                                                  sizeof(pending_control_frame_));
    if (len == 0) return;
    pending_control_frame_len_ = len;
    pending_control_frame_valid_ = true;
  }

  static bool isReceiverTerminal(meshcore::ota::runtime::OtaReceiverState state) {
    using meshcore::ota::runtime::OtaReceiverState;
    return state == OtaReceiverState::Complete || state == OtaReceiverState::Failed ||
           state == OtaReceiverState::Aborted;
  }

  // True only if a campaign is active AND `id` is exactly that campaign's
  // session identity. Every handler that mutates shared session state
  // (authorization grant, staged bytes, receipt bitmap) MUST check this
  // first and return false without side effects otherwise: this is what
  // stops a foreign, stale, or replayed frame from corrupting the state of
  // a legitimately in-progress transfer, since OtaReceiverStateMachine's own
  // id check only runs (and only fails closed) *after* any code that already
  // ran ahead of it.
  bool isActiveSession(const meshcore::ota::runtime::OtaSessionId& id) const {
    return session_active_ && meshcore::ota::runtime::otaSessionEquals(id, active_session_);
  }

  bool ensureReceiverCampaign(const meshcore::ota::runtime::OtaSessionId& id) {
    using meshcore::ota::runtime::OtaReceiverState;
    if (receiver_.state() == OtaReceiverState::Idle || isReceiverTerminal(receiver_.state())) {
      resetTransferSession();
      if (!receiver_.beginCampaign(id)) return false;
      active_session_ = id;
      session_active_ = true;
      return true;
    }
    return meshcore::ota::runtime::otaSessionEquals(id, receiver_.activeSession());
  }

  bool parseDescriptorFragment(const uint8_t* payload, size_t payload_len,
                               uint8_t& frag_index, uint8_t& frag_count,
                               uint16_t& total_len, uint16_t& fragment_payload_size,
                               const uint8_t*& fragment_data, size_t& fragment_data_len) const {
    if (payload == nullptr || payload_len < kDescriptorFragmentHeaderSize) return false;
    frag_index = payload[0];
    frag_count = payload[1];
    // All OTA wire codecs (OtaWireTypes.h, OtaMessages.h) and the RF lab
    // reference sender use explicit big-endian ("network order") multi-byte
    // fields. This header must match that convention exactly, or a real
    // signed-wire descriptor sent by any conformant peer is silently
    // misparsed (wrong lengths) and rejected.
    total_len = meshcore::ota::protocol::getOtaBE16(payload + 2);
    fragment_payload_size = meshcore::ota::protocol::getOtaBE16(payload + 4);
    fragment_data = payload + kDescriptorFragmentHeaderSize;
    fragment_data_len = payload_len - kDescriptorFragmentHeaderSize;
    return true;
  }

  bool handleDescriptorFragment(const meshcore::ota::runtime::OtaSessionId& id,
                                const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    if (!ensureReceiverCampaign(id)) return false;

    uint8_t frag_index = 0;
    uint8_t frag_count = 0;
    uint16_t total_len = 0;
    uint16_t fragment_payload_size = 0;
    const uint8_t* fragment_data = nullptr;
    size_t fragment_data_len = 0;
    if (!parseDescriptorFragment(payload, payload_len, frag_index, frag_count, total_len,
                                 fragment_payload_size, fragment_data, fragment_data_len) ||
        !descriptor_reassembler_.addFragment(frag_index, frag_count, total_len,
                                             fragment_payload_size, fragment_data, fragment_data_len)) {
      receiver_.handle(OtaReceiverEvent::DescriptorRejected, id);
      stagingAbortFailClosed(staging_sink_);
      return false;
    }

    if (!descriptor_reassembler_.isComplete()) {
      receiver_.handle(OtaReceiverEvent::DescriptorFragmentReceived, id);
      return true;
    }

    const uint8_t* blob = descriptor_reassembler_.blob();
    const size_t blob_len = descriptor_reassembler_.blobLength();
    if (blob_len <= kOtaDescriptorCanonicalSize) {
      receiver_.handle(OtaReceiverEvent::DescriptorRejected, id);
      return false;
    }

    // Idempotency for an exact-duplicate completed descriptor: a lost final
    // ACK legitimately causes a sender to retransmit every fragment of an
    // already-accepted descriptor while the receiver is mid-transfer
    // (Receiving/authorized, chunks already staged). Re-running verify +
    // stagingBeginFailClosed + receipt_map_.reset() below would erase the
    // candidate image and destroy in-flight progress for no protocol
    // reason. Detect this case by comparing the freshly reassembled blob
    // byte-for-byte against the last blob this exact session already
    // verified, and short-circuit to a harmless re-ack that preserves all
    // staged bytes, the receipt bitmap, and authorization state.
    if (descriptor_verified_ && isActiveSession(id) && blob_len == verified_blob_len_ &&
        memcmp(blob, verified_blob_, blob_len) == 0) {
      receiver_.handle(OtaReceiverEvent::DescriptorFragmentReceived, id);
      return true;
    }

    OtaDescriptor descriptor;
    if (decodeOtaDescriptorCanonical(blob, kOtaDescriptorCanonicalSize, descriptor) != OtaDescriptorCodecResult::Ok) {
      receiver_.handle(OtaReceiverEvent::DescriptorRejected, id);
      return false;
    }

    const uint8_t* signature = blob + kOtaDescriptorCanonicalSize;
    const size_t signature_len = blob_len - kOtaDescriptorCanonicalSize;
    OtaGeometry geometry;
    if (!verifyDescriptorFailClosed(trust_provider_, descriptor, signature, signature_len) ||
        OtaGeometry::compute(descriptor.exactSizeBytes, kChunkPayloadSize, kOtaMaxImageBytes, geometry) != OtaGeometryResult::Ok ||
        stagingBeginFailClosed(staging_sink_, descriptor) != IOtaStagingSink::Result::Ok) {
      receiver_.handle(OtaReceiverEvent::DescriptorRejected, id);
      stagingAbortFailClosed(staging_sink_);
      return false;
    }

    descriptor_ = descriptor;
    geometry_ = geometry;
    receipt_map_.reset(geometry_.chunkCount);
    descriptor_verified_ = true;
    authorized_ = false;
    verified_blob_len_ = blob_len;
    memcpy(verified_blob_, blob, blob_len);
    if (staging_sink_ != nullptr) {
      staging_sink_->onVerifiedWireDescriptor(blob, kOtaDescriptorCanonicalSize, signature, signature_len);
    }
    if (coordinator_.state() == OtaCoordinatorState::Idle) coordinator_.beginCampaign(id);
    coordinator_.handle(OtaCoordinatorEvent::DescriptorDeliveryConfirmed, id);
    return receiver_.handle(OtaReceiverEvent::DescriptorComplete, id);
  }

  bool handleAuthorization(const meshcore::ota::runtime::OtaSessionId& id,
                           const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    // Reject foreign/stale/replayed session ids before touching anything:
    // otherwise a spoofed authorization for an unrelated campaign would
    // still flip `authorized_` true and abort the real session's staging
    // sink once the (correctly failing) state-machine check ran below.
    if (!isActiveSession(id)) return false;

    OtaAuthorizationPayload authorization;
    if (!descriptor_verified_ || !decodeOtaAuthorization(payload, payload_len, authorization) ||
        authorization.granted == 0 ||
        !authorizeTransferFailClosed(trust_provider_, descriptor_, authorization)) {
      receiver_.handle(OtaReceiverEvent::AuthorizationDenied, id);
      coordinator_.handle(OtaCoordinatorEvent::AuthorizationDenied, id);
      stagingAbortFailClosed(staging_sink_);
      return false;
    }

    authorized_ = true;
    if (trust_provider_ != nullptr && staging_sink_ != nullptr) {
      uint8_t controller[32];
      if (trust_provider_->controllerIdentity(controller)) {
        staging_sink_->onAuthorizedSession(id, controller);
      }
    }
    bool receiver_ok = receiver_.handle(OtaReceiverEvent::AuthorizationGranted, id);
    bool coordinator_ok = coordinator_.handle(OtaCoordinatorEvent::AuthorizationGranted, id);
    return receiver_ok && coordinator_ok;
  }

  bool handleChunk(const meshcore::ota::runtime::OtaSessionId& id,
                   const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    // Reject foreign/stale/replayed chunks before writing anything to the
    // staging sink or setting bits in the receipt bitmap: without this
    // gate, an interleaved chunk carrying a foreign session id would still
    // be written to the active campaign's staged image and marked received
    // before the state machine's own id check (which only runs afterward,
    // in receiver_.handle()) had a chance to reject it.
    if (!isActiveSession(id)) return false;

    OtaChunkHeader chunk;
    const uint8_t* data = nullptr;
    size_t data_len = 0;
    uint32_t expected_len = 0;
    uint64_t offset = 0;
    if (!descriptor_verified_ || !authorized_ ||
        !decodeOtaChunk(payload, payload_len, chunk, data, data_len) ||
        !geometry_.chunkLength(chunk.chunkIndex, expected_len) ||
        expected_len != data_len ||
        !geometry_.chunkOffset(chunk.chunkIndex, offset) ||
        stagingWriteFailClosed(staging_sink_, offset, data, data_len) != IOtaStagingSink::Result::Ok ||
        !receipt_map_.set(chunk.chunkIndex)) {
      receiver_.handle(OtaReceiverEvent::StagingError, id);
      stagingAbortFailClosed(staging_sink_);
      return false;
    }

    receiver_.handle(OtaReceiverEvent::ChunkAccepted, id);
    coordinator_.handle(OtaCoordinatorEvent::ChunkSent, id);
    return true;
  }

  bool handleReceipt(const meshcore::ota::runtime::OtaSessionId& id,
                     const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;
    OtaReceiptPayload receipt;
    if (!decodeOtaReceipt(payload, payload_len, receipt)) return false;
    if (receipt.status == OtaReceiptStatus::TransferComplete) {
      return coordinator_.handle(OtaCoordinatorEvent::ReceiptAllGood, id);
    }
    if (receipt.status == OtaReceiptStatus::ChunkNack || receipt.status == OtaReceiptStatus::TransferFailed) {
      return coordinator_.handle(OtaCoordinatorEvent::ReceiptMissingDetected, id);
    }
    return true;
  }

  bool handleCommit(const meshcore::ota::runtime::OtaSessionId& id,
                    const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    // Reject foreign/stale/replayed commits before evaluating anything else:
    // commit drives image-hash verification and the final flash commit, so
    // it must be bound to the active session first, defense-in-depth on top
    // of the campaignId check below and receiver_.handle()'s own id check.
    if (!isActiveSession(id)) return false;

    OtaCommitPayload commit;
    if (!descriptor_verified_ || !authorized_ ||
        !decodeOtaCommit(payload, payload_len, commit) ||
        commit.campaignId != id.campaignId ||
        commit.verifiedOk == 0 ||
        commit.finalSecurityCounter != descriptor_.securityCounter ||
        !receipt_map_.allSet()) {
      return false;
    }

    if (!receiver_.handle(OtaReceiverEvent::AllChunksReceived, id)) return false;

    if (!verifyStagedImageHashFailClosed(trust_provider_, descriptor_)) {
      receiver_.handle(OtaReceiverEvent::VerificationFailed, id);
      coordinator_.handle(OtaCoordinatorEvent::CommitFailed, id);
      fleet_.handle(OtaFleetEvent::CommitFailed, id);
      stagingAbortFailClosed(staging_sink_);
      return false;
    }

    if (!receiver_.handle(OtaReceiverEvent::VerificationOk, id) ||
        stagingCommitFailClosed(staging_sink_) != IOtaStagingSink::Result::Ok) {
      receiver_.handle(OtaReceiverEvent::CommitFailed, id);
      coordinator_.handle(OtaCoordinatorEvent::CommitFailed, id);
      fleet_.handle(OtaFleetEvent::CommitFailed, id);
      stagingAbortFailClosed(staging_sink_);
      return false;
    }

    receiver_.handle(OtaReceiverEvent::CommitOk, id);
    coordinator_.handle(OtaCoordinatorEvent::ReceiptAllGood, id);
    coordinator_.handle(OtaCoordinatorEvent::CommitVerified, id);
    fleet_.handle(OtaFleetEvent::CommitVerified, id);
    return true;
  }

  // Real subtype-aware lease negotiation. Every branch requires a legal
  // (state, subtype) combination per OtaLeaseStateMachine's own transition
  // table before advancing, so a malformed frame or a frame that does not
  // fit the current negotiation phase is rejected rather than blindly
  // granting/advancing regardless of content.
  //
  // Note: this only drives the local lease *state machine*. Actually
  // applying the negotiated off-frequency radio profile (frequency,
  // bandwidth, SF, CR) and its automatic expiry/revert is the integrator's
  // responsibility via the same OtaDirectLeaseHandler/OtaDirectLeaseParams
  // path already used for the locally-issued (USB) direct lease command;
  // wiring a remote-negotiated profile table through to that handler is a
  // separate, explicitly tracked follow-up (see status report).
  bool handleLeaseNegotiation(const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    OtaLeaseNegotiationPayload negotiation;
    if (!decodeOtaLeaseNegotiation(payload, payload_len, negotiation)) return false;

    switch (negotiation.subtype) {
      case OtaLeaseSubtype::Request:
        if (lease_.state() != OtaLeaseState::Normal) return false;
        return lease_.handle(OtaLeaseEvent::RequestLease);

      case OtaLeaseSubtype::Grant:
        if (lease_.state() != OtaLeaseState::Requesting) return false;
        return lease_.handle(OtaLeaseEvent::Granted);

      case OtaLeaseSubtype::Deny:
        if (lease_.state() != OtaLeaseState::Requesting) return false;
        return lease_.handle(OtaLeaseEvent::Denied);

      case OtaLeaseSubtype::Renew:
        // Renewal only makes sense while a lease is actually active; it does
        // not itself change state (duration bookkeeping is owned by the
        // transport-layer revert timer).
        return lease_.state() == OtaLeaseState::Active;

      case OtaLeaseSubtype::Release:
        if (lease_.state() == OtaLeaseState::Active) {
          return lease_.handle(OtaLeaseEvent::Release) && lease_.handle(OtaLeaseEvent::ReleaseAcked);
        }
        if (lease_.state() == OtaLeaseState::Releasing) {
          return lease_.handle(OtaLeaseEvent::ReleaseAcked);
        }
        return false;
    }
    return false;
  }

  // Announcement/Census/CohortResolution/MissingRange are real,
  // fully-decoded and campaign-bound below: every one of these rejects
  // (returns false, no state change) frames that fail to decode or that
  // name a campaign other than the one addressed by the envelope. This
  // replaces the previous behavior of advancing the fleet state machine on
  // receipt of any frame of the right *type*, irrespective of its payload.
  bool handleAnnouncement(const meshcore::ota::runtime::OtaSessionId& id,
                          const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    OtaAnnouncementPayload announcement;
    if (!decodeOtaAnnouncement(payload, payload_len, announcement) ||
        announcement.campaignId != id.campaignId) {
      return false;
    }

    if (fleet_.state() == OtaFleetState::Idle) {
      if (!fleet_.beginCampaign(id)) return false;
      fleet_census_reports_ = 0;
      fleet_has_cohort_ = false;
    } else if (!meshcore::ota::runtime::otaSessionEquals(id, fleet_.activeSession())) {
      return false;
    }
    fleet_last_announcement_ = announcement;
    return true;
  }

  bool handleCensus(const meshcore::ota::runtime::OtaSessionId& id,
                    const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    OtaCensusPayload census;
    if (!decodeOtaCensus(payload, payload_len, census) ||
        census.campaignId != id.campaignId ||
        !meshcore::ota::runtime::otaSessionEquals(id, fleet_.activeSession())) {
      return false;
    }
    ++fleet_census_reports_;
    fleet_last_census_ = census;

    switch (fleet_.state()) {
      case OtaFleetState::Announcing:
        if (!fleet_.handle(OtaFleetEvent::AnnounceComplete, id)) return false;
        if (census.haveDescriptor == 0) return true;
        return fleet_.handle(OtaFleetEvent::CensusComplete, id);
      case OtaFleetState::Census:
        // A real census report that shows the reporter still lacks the
        // descriptor is a legal no-op: it does not (falsely) advance the
        // phase, unlike blindly trusting every Census-typed frame.
        if (census.haveDescriptor == 0) return true;
        return fleet_.handle(OtaFleetEvent::CensusComplete, id);
      case OtaFleetState::Multicasting:
        // No dedicated wire message marks "the multicast round is over";
        // the coordinator re-polls with the SAME Census message it used
        // pre-multicast, and its arrival while we're in Multicasting is
        // itself the round-end signal. Fold the MulticastComplete
        // transition and the immediate missing/no-missing evaluation into
        // this one frame rather than requiring a new message type (which
        // would be a wire-format change, not a surgical fix).
        if (!fleet_.handle(OtaFleetEvent::MulticastComplete, id)) return false;
        return fleet_.handle(census.missingRangeCount == 0 ? OtaFleetEvent::NoneMissing
                                                            : OtaFleetEvent::SomeMissing,
                              id);
      case OtaFleetState::MissingCensus:
        return fleet_.handle(census.missingRangeCount == 0 ? OtaFleetEvent::NoneMissing
                                                            : OtaFleetEvent::SomeMissing,
                              id);
      case OtaFleetState::Repairing:
        // Same round-end-via-Census pattern as Multicasting above: a fresh
        // Census poll arriving while we're mid-repair means the coordinator
        // considers this repair round finished, so fold
        // RepairRoundComplete + the next missing/no-missing decision into
        // this one frame (re-census -> either converge to Committing or
        // start another repair round).
        if (!fleet_.handle(OtaFleetEvent::RepairRoundComplete, id)) return false;
        return fleet_.handle(census.missingRangeCount == 0 ? OtaFleetEvent::NoneMissing
                                                            : OtaFleetEvent::SomeMissing,
                              id);
      default:
        return false;
    }
  }

  bool handleCohortResolution(const meshcore::ota::runtime::OtaSessionId& id,
                              const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    OtaCohortResolutionPayload cohort;
    if (!decodeOtaCohortResolution(payload, payload_len, cohort) ||
        cohort.campaignId != id.campaignId ||
        !meshcore::ota::runtime::otaSessionEquals(id, fleet_.activeSession()) ||
        cohort.cohortSize == 0 || cohort.cohortIndex >= cohort.cohortSize) {
      return false;
    }
    if (!fleet_.handle(OtaFleetEvent::CohortResolved, id)) return false;
    fleet_cohort_ = cohort;
    fleet_has_cohort_ = true;
    return true;
  }

  bool handleMissingRange(const meshcore::ota::runtime::OtaSessionId& id,
                          const uint8_t* payload, size_t payload_len) {
    using namespace meshcore::ota::protocol;
    using namespace meshcore::ota::runtime;

    OtaMissingRangePayload missing;
    if (!decodeOtaMissingRange(payload, payload_len, missing) ||
        missing.campaignId != id.campaignId ||
        missing.chunkCount == 0 ||
        !meshcore::ota::runtime::otaSessionEquals(id, fleet_.activeSession())) {
      return false;
    }
    fleet_last_missing_range_ = missing;
    coordinator_.handle(OtaCoordinatorEvent::ReceiptMissingDetected, id);
    // SomeMissing is only a legal fleet-state transition out of
    // MissingCensus (-> Repairing). A directed MissingRange detail frame
    // received WHILE already Repairing is a normal, additional repair
    // target (there can be more than one missing range per round) rather
    // than a new phase transition, so it must not be forced through
    // fleet_.handle() a second time -- that would always fail (Repairing
    // has no SomeMissing case) and reject an otherwise legitimate repair
    // request.
    if (fleet_.state() == OtaFleetState::Repairing) return true;
    return fleet_.handle(OtaFleetEvent::SomeMissing, id);
  }

  void resetTransferSession() {
    descriptor_reassembler_.reset();
    receipt_map_.reset(0);
    geometry_ = meshcore::ota::runtime::OtaGeometry();
    descriptor_ = meshcore::ota::protocol::OtaDescriptor();
    descriptor_verified_ = false;
    authorized_ = false;
    session_active_ = false;
    verified_blob_len_ = 0;
  }


  static constexpr uint32_t kChunkPayloadSize = meshcore::ota::runtime::kOtaDefaultChunkPayloadSize;
  FirmwareOtaMode mode_ = FirmwareOtaMode::Fleet;
  float duty_percent_ = 2.0f;
  uint32_t window_ms_ = meshcore::ota::runtime::OtaAirtimeLimiter::kDefaultWindowMs;
  uint32_t budget_ms_ = meshcore::ota::runtime::OtaAirtimeLimiter::kDefaultBudgetMs;
  meshcore::ota::runtime::IOtaTrustProvider* trust_provider_ = nullptr;
  meshcore::ota::runtime::IOtaStagingSink* staging_sink_ = nullptr;
  OtaLeanReceiver lean_;
  TrackedTarget targets_[kMaxTrackedOtaTargets];
  bool pending_control_frame_valid_ = false;
  bool commit_reboot_pending_ = false;
  void* commit_reboot_ctx_ = nullptr;
  CommitRebootFn commit_reboot_ = nullptr;
  uint64_t commit_reboot_nonce_ = 0;
  uint32_t commit_reboot_due_ms_ = 0, commit_reboot_queue_deadline_ms_ = 0;
  uint8_t pending_control_frame_[kOtaDirectFrameBytes] = {0};
  size_t pending_control_frame_len_ = 0;
  uint32_t pending_control_due_ms_ = 0;
  void* rf_ctx_ = nullptr;
  void* boot_ctx_ = nullptr;
  BootLifecycleFn boot_lifecycle_ = nullptr;
  BootCandidateFn boot_candidate_ = nullptr;
  SignFn rf_sign_ = nullptr;
  RadioChangeFn rf_radio_change_ = nullptr;
  ProfileRadioChangeFn rf_profile_radio_change_ = nullptr;
  OtaDirectProfile direct_profile_ = OtaDirectProfile::Legacy250;
  uint32_t normal_freq_khz_ = 0, direct_freq_khz_ = 0;
  uint16_t direct_lease_ms_ = 0;
  uint32_t direct_apply_ms_ = 0, direct_expiry_ms_ = 0, direct_last_token_ = 0;
  uint32_t direct_transition_deadline_ = 0;
  bool direct_active_ = false, direct_pending_ = false, direct_waiting_ack_ = false, direct_have_token_ = false;
  bool direct_ack_tx_wait_ = false;
  uint8_t direct_request_[107] = {};
  OtaRadioMeasurement radio_measurement_;
  meshcore::ota::runtime::OtaAirtimeLimiter airtime_;
  meshcore::ota::runtime::OtaReceiverStateMachine receiver_;
  meshcore::ota::runtime::OtaCoordinatorStateMachine coordinator_;
  meshcore::ota::runtime::OtaFleetStateMachine fleet_;
  meshcore::ota::runtime::OtaLeaseStateMachine lease_;
  meshcore::ota::runtime::OtaSessionId active_session_{};
  bool session_active_ = false;
  meshcore::ota::protocol::OtaDescriptorReassembler descriptor_reassembler_;
  meshcore::ota::protocol::OtaDescriptor descriptor_;
  meshcore::ota::runtime::OtaGeometry geometry_;
  meshcore::ota::runtime::OtaMaxImageBitmap receipt_map_;
  bool descriptor_verified_ = false;
  uint8_t verified_blob_[meshcore::ota::protocol::OtaDescriptorReassembler::kMaxBlobSize] = {};
  size_t verified_blob_len_ = 0;
  bool authorized_ = false;
  uint32_t rx_frames_ = 0;
  uint32_t bad_frames_ = 0;
  uint32_t aborted_sessions_ = 0;
  bool rollback_requested_ = false;
  meshcore::ota::protocol::OtaAnnouncementPayload fleet_last_announcement_{};
  meshcore::ota::protocol::OtaCensusPayload fleet_last_census_{};
  meshcore::ota::protocol::OtaCohortResolutionPayload fleet_cohort_{};
  meshcore::ota::protocol::OtaMissingRangePayload fleet_last_missing_range_{};
  uint32_t fleet_census_reports_ = 0;
  bool fleet_has_cohort_ = false;
};

}  // namespace ota
}  // namespace mesh
