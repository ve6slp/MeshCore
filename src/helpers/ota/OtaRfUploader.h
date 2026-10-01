#pragma once

// Small, Mesh-independent building blocks for the autonomous RF uploader
// (see examples/companion_radio/MyMesh.cpp's pumpOtaRfUpload()): signing
// one block frame fresh at TX time (never a cached/reused per-block
// signature -- the block bytes themselves are already durable, read back
// from local flash via OtaLeanReceiver::readBlock()) and a minimal
// round-robin repair-sweep cursor. Kept free of any Mesh/Packet/Identity
// dependency so both pieces are unit-testable in isolation at the native
// level; the actual transport (direct/routed/multicast send) and signing
// identity are supplied by the caller.

#include <cstddef>
#include <cstdint>

#include <helpers/ota/OtaBlockSigning.h>
#include <helpers/ota/OtaFirmwareIntegration.h>

namespace mesh {
namespace ota {

// Signing callback: writes a 64-byte Ed25519 signature over `message`
// (message_len bytes) into `signature_out`. Bound by the caller to
// whatever identity object is authoritative for signing (this header
// never holds, derives, or sees a private key itself).
using OtaBlockSignFn = void (*)(void* ctx, const uint8_t* message, size_t message_len, uint8_t signature_out[64]);

// Builds ONE fresh-signed signed-block RF frame for `index` out of
// `data`/`data_len` (already read back from local flash by the caller).
// Signing happens HERE, fresh, on every call -- no per-block signature is
// ever cached or reused, matching the agreed "re-sign fresh at TX time"
// design (the only thing persisted durably is the plain block bytes).
// Returns the encoded frame length, or 0 on any invalid input.
inline size_t signAndEncodeOtaBlock(const uint8_t manifest_hash[32], uint16_t index,
                                    const uint8_t* data, size_t data_len,
                                    void* sign_ctx, OtaBlockSignFn sign_fn,
                                    uint8_t* out, size_t out_capacity, const uint8_t* owner = nullptr) {
  if (sign_fn == nullptr || manifest_hash == nullptr || data == nullptr || data_len == 0 ||
      data_len > kOtaBlockMaxDataBytes) {
    return 0;
  }
  uint8_t message[kOtaBlockSignedMessageMaxBytes] = {};
  const size_t message_len =
      buildOtaBlockSignedMessage(manifest_hash, owner ? kOtaOwnerSignedBlockKind : kOtaSignedBlockKind,
                                index, data, data_len, message);
  uint8_t signature[64] = {};
  sign_fn(sign_ctx, message, message_len, signature);
  if (owner) return encodeOtaOwnerSignedBlock(owner, index, data, data_len, signature, out, out_capacity);
  size_t out_len = 0;
  if (!encodeOtaSignedBlockFrame(kOtaSignedBlockKind, manifest_hash, index, data, data_len, signature, out,
                                out_capacity, out_len)) {
    return 0;
  }
  return out_len;
}

// Minimal round-robin repair-sweep cursor for the block stream: offers
// every index in turn, wrapping back to 0 forever. The caller is expected
// to SKIP a peeked index without calling advance()'s side effects beyond
// moving on (see advance()) when every currently-tracked target already
// has fresher evidence than that index -- re-polled StatusReport
// observations make that particular retransmission genuinely wasted
// airtime; a continuous sweep (rather than a one-shot pass) means a
// target that joins late, drops out, or never reports back at all is
// still repaired/served on the next lap without any separate per-target
// bitmap on the uploader side.
class OtaRfUploadCursor {
public:
  void reset() { next_index_ = 0; }
  uint16_t peek() const { return next_index_; }
  void advance(uint16_t total_blocks) {
    if (total_blocks == 0) { next_index_ = 0; return; }
    next_index_ = static_cast<uint16_t>((next_index_ + 1) % total_blocks);
  }

private:
  uint16_t next_index_ = 0;
};

enum class OtaRfRoute { Directed, Multicast, ZeroHop };

// The production companion uses this same bounded pump as native tests.
// Counts are telemetry only: repairs consult the durable bitmap window.
class OtaRfUploader {
public:
  using SendFn = bool (*)(void*, OtaRfRoute, const uint8_t[32], const uint8_t*, size_t,
                          meshcore::ota::protocol::OtaAirtimeCategory);
  bool start(OtaFirmwareIntegration& integration, uint8_t mode, const uint8_t* targets, uint8_t count,
              uint32_t frequency, uint16_t lease, uint32_t token, bool reupload) {
    const auto st = integration.leanReceiver().status();
    if (!st.valid || st.phase != ::ota::storage::OtaCandidateStore::Phase::Ready ||
        !targets || count == 0 || count > usb::kMaxSelectedTargets || mode > usb::kStartModeBackground ||
        (mode != usb::kStartModeBackground && count != 1)) return false;
    stop(integration);
    mode_ = mode; targets_ = targets; count_ = count; frequency_ = frequency; lease_ = lease; token_ = token;
    reupload_ = reupload; active_ = true; stage_ = Stage::Admission;
    target_ = 0; index_ = 0; first_ = 0; last_poll_ = 0; waiting_poll_ = false; last_direct_request_ = 0;
    reupload_spent_ = 0; reupload_pending_ = 0;
    normal_stage_ = 0; normal_poll_ms_ = 0;
    for (uint8_t i = 0; i < count; ++i) {
      integration.trackOtaTarget(targets + 32u * i);
      integration.clearTargetObservation(targets + 32u * i);
    }
    return true;
  }
  void stop(OtaFirmwareIntegration& integration) { active_ = false; integration.stopDirect(); }
  bool active() const { return active_; }
  uint8_t mode() const { return mode_; }

  void pump(OtaFirmwareIntegration& integration, uint32_t now, void* ctx, OtaBlockSignFn sign, SendFn send) {
    if (!active_ || !sign || !send) return;
    auto& lean = integration.leanReceiver();
    const auto st = lean.status();
    if (!st.valid || st.phase != ::ota::storage::OtaCandidateStore::Phase::Ready ||
        std::memcmp(st.ownerPublicKey, lean.targetPublicKey(), 32)) { stop(integration); return; }
    using Category = meshcore::ota::protocol::OtaAirtimeCategory;
    uint8_t frame[kOtaOwnerSignedBlockMaxBytes];
    const auto selected = [&]() { return targets_ + 32u * target_; };
    const auto route = [&]() { return mode_ == usb::kStartModeDirect ? OtaRfRoute::ZeroHop : OtaRfRoute::Directed; };

    if (stage_ == Stage::Admission) {
      uint8_t canonical[59], signature[64];
      if (!lean.exportCandidateForUpload(canonical, signature)) return;
      const auto len = encodeOtaTargetAuthorization(selected(), st.ownerPublicKey, canonical, signature, frame, sizeof(frame));
      if (send(ctx, route(), selected(), frame, len, Category::Control)) {
        if (++target_ == count_) { target_ = 0; stage_ = Stage::Initial; }
      }
      return;
    }
    bool all_terminal = true;
    for (uint8_t i = 0; i < count_; ++i) {
      OtaFirmwareIntegration::TargetObservation observation;
      integration.targetObservation(targets_ + 32u * i, now, observation);
      if (observation.haveBitmap && !std::memcmp(observation.manifestHash, st.manifestHash, 32) &&
          (reupload_pending_ & (1u << i)) && observation.generation != reupload_generation_[i]) {
        reupload_spent_ |= 1u << i;
        reupload_pending_ &= ~(1u << i);
      }
      const auto phase = static_cast<::ota::storage::OtaCandidateStore::Phase>(observation.phase);
      if (!observation.haveBitmap || observation.ageMs >= 120000u ||
          std::memcmp(observation.manifestHash, st.manifestHash, 32) ||
          (phase != ::ota::storage::OtaCandidateStore::Phase::Ready &&
           phase != ::ota::storage::OtaCandidateStore::Phase::Committed &&
           phase != ::ota::storage::OtaCandidateStore::Phase::Aborted) ||
          (phase == ::ota::storage::OtaCandidateStore::Phase::Aborted &&
           reupload_ && !(reupload_spent_ & (1u << i)))) { all_terminal = false; break; }
    }
    if (all_terminal) { active_ = false; return; }

    if (mode_ == usb::kStartModeDirect && !integration.directActive()) {
      if (integration.directPending()) return;
      // Every bounded lease returns both radios to normal service. A
      // fresh handshake resumes the existing candidate/bitmap, including
      // after receiver reboot or a lost ACK; no lease lasts indefinitely.
      if (last_direct_request_ && now - last_direct_request_ < static_cast<uint32_t>(lease_) + 15000u) return;
      // Repair admission on the normal profile before every handshake.
      // A lost START or an ABORTed target must not leave the sender
      // blindly requesting an off-frequency lease forever.
      if (normal_stage_ == 0) {
        uint8_t canonical[59], signature[64];
        lean.exportCandidateForUpload(canonical, signature);
        const auto len = encodeOtaTargetAuthorization(targets_, st.ownerPublicKey, canonical, signature, frame, sizeof(frame));
        if (send(ctx, OtaRfRoute::ZeroHop, targets_, frame, len, Category::Control)) normal_stage_ = 1;
        return;
      }
      if (normal_stage_ == 1) {
        const auto len = encodeOtaCensusPoll(targets_, st.manifestHash, 0, frame, sizeof(frame));
        if (send(ctx, OtaRfRoute::ZeroHop, targets_, frame, len, Category::Control)) {
          normal_stage_ = 2; normal_poll_ms_ = now;
        }
        return;
      }
      OtaFirmwareIntegration::TargetObservation observation;
      integration.targetObservation(targets_, now, observation);
      const bool response = observation.haveBitmap && observation.ageMs <= now - normal_poll_ms_ &&
                            !std::memcmp(observation.manifestHash, st.manifestHash, 32);
      if (!response) {
        if (now - normal_poll_ms_ >= 15000u) normal_stage_ = 0;
        return;
      }
      if (observation.phase == static_cast<uint8_t>(::ota::storage::OtaCandidateStore::Phase::Aborted)) {
        if (!reupload_ || (reupload_spent_ & 1u)) { active_ = false; return; }
        if (sendApprovedReupload(st, 0, observation.generation, frame, ctx, sign, send, OtaRfRoute::ZeroHop)) {
          integration.clearTargetObservation(targets_);
          normal_stage_ = 0;
        }
        return;
      }
      const auto len = integration.buildDirectRequest(targets_, frequency_, lease_, ++token_, frame, sizeof(frame));
      if (len && send(ctx, OtaRfRoute::ZeroHop, targets_, frame, len, Category::Control)) {
        last_direct_request_ = now; normal_stage_ = 0;
      }
      return;
    }

    if (stage_ == Stage::Initial) {
      if (index_ < st.totalBlocks) {
        if (sendBlock(lean, st, index_, ctx, sign, send,
                      mode_ == usb::kStartModeBackground ? OtaRfRoute::Multicast : route(), targets_, Category::Relay)) ++index_;
        return;
      }
      stage_ = Stage::Census; target_ = 0; first_ = 0; waiting_poll_ = false;
    }
    OtaFirmwareIntegration::TargetObservation obs;
    integration.targetObservation(selected(), now, obs);
    const bool fresh = obs.haveBitmap && obs.first == first_ && obs.ageMs < 120000u &&
        obs.totalBlocks == st.totalBlocks && !std::memcmp(obs.manifestHash, st.manifestHash, 32);
    if (stage_ == Stage::Census) {
      // One target poll at a time, with a jittered receiver response:
      // avoids a multicast census response implosion.
      if (waiting_poll_ && fresh && obs.ageMs <= now - last_poll_) {
        waiting_poll_ = false;
        if (obs.phase == static_cast<uint8_t>(::ota::storage::OtaCandidateStore::Phase::Aborted)) {
          if (reupload_ && !(reupload_spent_ & (1u << target_))) {
            if (!sendApprovedReupload(st, target_, obs.generation, frame, ctx, sign, send, route())) { waiting_poll_ = true; return; }
            integration.clearTargetObservation(selected());
          }
          nextTarget(st.totalBlocks);
          return;
        }
        if (obs.phase == static_cast<uint8_t>(::ota::storage::OtaCandidateStore::Phase::Ready) ||
            obs.phase == static_cast<uint8_t>(::ota::storage::OtaCandidateStore::Phase::Committed)) {
          nextTarget(st.totalBlocks);
          return;
        }
        stage_ = Stage::Repair; index_ = first_;
      } else {
        if (waiting_poll_ && now - last_poll_ < 15000u) return;
        if (waiting_poll_) {
          // Missing admission/reboot/loss: re-offer the signed manifest,
          // then repair this window conservatively until it reports.
          uint8_t canonical[59], sig[64];
          lean.exportCandidateForUpload(canonical, sig);
          const auto len = encodeOtaTargetAuthorization(selected(), st.ownerPublicKey, canonical, sig, frame, sizeof(frame));
          if (!send(ctx, route(), selected(), frame, len, Category::Control)) return;
          stage_ = Stage::Repair; index_ = first_; waiting_poll_ = false; repair_unknown_ = true;
          return;
        }
        const auto len = encodeOtaCensusPoll(selected(), st.manifestHash, first_, frame, sizeof(frame));
        if (send(ctx, route(), selected(), frame, len, Category::Control)) {
          waiting_poll_ = true; last_poll_ = now; repair_unknown_ = false;
        }
        return;
      }
    }
    if (stage_ == Stage::Repair) {
      const uint32_t end = static_cast<uint32_t>(first_) + kOtaCensusWindowBlocks;
      while (index_ < st.totalBlocks && index_ < end) {
        const uint16_t bit = index_ - first_;
        if (!repair_unknown_ && fresh && (obs.bitmap[bit / 8] & (1u << (bit % 8)))) { ++index_; continue; }
        if (sendBlock(lean, st, index_, ctx, sign, send, route(), selected(), Category::Repair)) ++index_;
        return;
      }
      nextTarget(st.totalBlocks);
    }
  }

private:
  enum class Stage { Admission, Initial, Census, Repair };
  bool sendApprovedReupload(const OtaLeanReceiver::Status& st, uint8_t target, uint32_t generation,
                              uint8_t* frame, void* ctx, OtaBlockSignFn sign, SendFn send, OtaRfRoute route) {
    const uint32_t bit = 1u << target;
    if ((reupload_pending_ & bit) && reupload_generation_[target] != generation) return false;
    if (!sendReupload(st, targets_ + 32u * target, generation, frame, ctx, sign, send, route)) return false;
    // Queue admission is not delivery. Retry only this approved generation
    // until census observes advancement; never override a later ABORT.
    reupload_pending_ |= bit;
    reupload_generation_[target] = generation;
    return true;
  }
  static bool sendReupload(const OtaLeanReceiver::Status& st, const uint8_t target[32], uint32_t generation,
                             uint8_t* frame, void* ctx, OtaBlockSignFn sign, SendFn send, OtaRfRoute route) {
    frame[0] = kOtaReuploadKind;
    std::memcpy(frame + 1, st.ownerPublicKey, 32); std::memcpy(frame + 33, target, 32);
    std::memcpy(frame + 65, st.manifestHash, 32); usb::putBE32(frame + 97, generation);
    uint8_t message[160]; const auto len = buildOtaReuploadMessage(frame, message);
    sign(ctx, message, len, frame + 101);
    return send(ctx, route, target, frame, kOtaReuploadFrameBytes, meshcore::ota::protocol::OtaAirtimeCategory::Control);
  }
  static bool sendBlock(OtaLeanReceiver& lean, const OtaLeanReceiver::Status& st, uint16_t index, void* ctx,
                          OtaBlockSignFn sign, SendFn send, OtaRfRoute route, const uint8_t* target,
                          meshcore::ota::protocol::OtaAirtimeCategory category) {
    uint8_t data[84], frame[kOtaOwnerSignedBlockMaxBytes]; size_t data_len = 0;
    if (lean.readBlock(index, data, sizeof(data), data_len) != usb::UsbOtaResult::Ok) return false;
    const auto len = signAndEncodeOtaBlock(st.manifestHash, index, data, data_len, ctx, sign, frame, sizeof(frame), st.ownerPublicKey);
    return len && send(ctx, route, target, frame, len, category);
  }
  void nextTarget(uint16_t total) {
    if (++target_ == count_) {
      target_ = 0; first_ = static_cast<uint16_t>(first_ + kOtaCensusWindowBlocks);
      if (first_ >= total) first_ = 0;
    }
    stage_ = Stage::Census; waiting_poll_ = false; repair_unknown_ = false;
  }
  const uint8_t* targets_ = nullptr;
  uint8_t mode_ = 0, count_ = 0, target_ = 0;
  uint16_t index_ = 0, first_ = 0, lease_ = 0;
  uint32_t frequency_ = 0, token_ = 0, last_poll_ = 0, last_direct_request_ = 0;
  uint32_t reupload_spent_ = 0;
  uint32_t reupload_pending_ = 0, reupload_generation_[usb::kMaxSelectedTargets] = {};
  uint32_t normal_poll_ms_ = 0;
  uint8_t normal_stage_ = 0;
  Stage stage_ = Stage::Admission;
  bool active_ = false, waiting_poll_ = false, repair_unknown_ = false, reupload_ = false;
};

}  // namespace ota
}  // namespace mesh
