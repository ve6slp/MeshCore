#pragma once

// Direct high-speed lease engine: remotely authenticated normal-channel
// request/grant/activate/ack/hello rendezvous on a DIFFERENT allowed
// frequency at SF5/BW250kHz/CR5, bounded by a per-epoch watchdog that is
// independent of (and cannot be bypassed by) the transfer session/attempt
// tuple. This is a REAL bilateral wire protocol: both the requester and
// grantor roles are driven entirely through onFrame() decoding actual
// CampaignWire LeaseNegotiation/Hello frames sent via
// IAuthenticatedTransportPort -- neither side ever locally fabricates the
// other side's state transition.
//
// Every legal Timeout/Failure/Abort/Release path calls
// IRadioProfilePort::restoreNormalProfile(); if that call itself FAILS,
// this engine enters an explicit fault state that keeps ordinary transmit
// BLOCKED (never silently claims Normal) until a subsequent restore
// attempt actually succeeds.
//
// Profile validity is a BOARD/REGION POLICY QUERY (IRadioProfilePort),
// never a hardcoded numeric range: a request is valid only if it is
// SF5/BW250kHz/CR5 (CR4 is not a valid SX1262 coding-rate denominator),
// differs from whichever frequency is the board's CURRENTLY ACTIVE normal
// profile (908.525 MHz is a perfectly valid request when the active
// normal profile happens to be 907.525, and vice versa), and falls within
// the board's actual approved-band bounds.
//
// Deliberately NOT persisted across reboot: a lease is a purely transient,
// single-boot-lifetime grant. A fresh instance (post-reboot) always
// starts assuming the Normal profile and the caller MUST additionally
// call forceNormalOnBoot() once at startup as an explicit safety net
// against any hardware state left over from an ungraceful reset.

#include <cstdint>
#include <cstddef>

#include "CampaignCommon.h"
#include "CampaignPorts.h"
#include "CampaignWire.h"
#include "../runtime/OtaLeaseStateMachine.h"

namespace meshcore {
namespace ota {
namespace campaign {

inline uint32_t campaignFreqToMilliMhz(float f) { return static_cast<uint32_t>(f * 1000.0f + 0.5f); }
inline float campaignFreqFromMilliMhz(uint32_t v) { return static_cast<float>(v) / 1000.0f; }
inline uint16_t campaignBwToKhzX10(float f) { return static_cast<uint16_t>(f * 10.0f + 0.5f); }
inline float campaignBwFromKhzX10(uint16_t v) { return static_cast<float>(v) / 10.0f; }

// Board/region policy query, never a hardcoded numeric range: only
// excludes whichever frequency is the board's CURRENTLY ACTIVE normal
// profile, and defers band approval entirely to the radio port.
inline bool isValidDirectHighSpeedProfile(const IRadioProfilePort& radio, const CampaignRadioProfileParams& p) {
  if (p.profile != CampaignRadioProfile::DirectHighSpeed) return false;
  if (p.spreadingFactor != 5) return false;
  if (p.bandwidthKhz != 250.0f) return false;
  if (p.codingRate != 5) return false; // reject CR4 and anything else
  CampaignRadioProfileParams activeNormal = radio.normalProfileParams();
  if (p.freqMhz == activeNormal.freqMhz) return false; // must differ from the board's ACTIVE normal freq only
  return radio.isFrequencyBandApproved(p.freqMhz);
}

// Bounded watchdog epoch: zero is nonsensical (would never time out /
// means "no deadline"), and an unbounded/huge value defeats the
// independent-per-peer watchdog guarantee. Both requester and grantor
// validate the SAME bound on the epoch they are told to honor.
inline constexpr uint32_t kCampaignLeaseMinEpochMs = 250;
inline constexpr uint32_t kCampaignLeaseMaxEpochMs = 60000;
inline constexpr bool isValidLeaseEpoch(uint32_t epochMs) {
  return epochMs >= kCampaignLeaseMinEpochMs && epochMs <= kCampaignLeaseMaxEpochMs;
}

// Bounded guard delay after enqueueing the LAST frame that must be
// physically transmitted on the CURRENT profile before switching away
// from it. Combined with IAuthenticatedTransportPort::txQueueEmpty(),
// this is the actual TX-completion evidence gate: the profile switch is
// deferred (via tick()) until both the guard delay has elapsed AND the
// transport confirms nothing queued from this engine is still in flight.
inline constexpr uint32_t kCampaignLeaseSwitchGuardMs = 20;

enum class DirectLeaseRole : uint8_t { None = 0, Requester = 1, Grantor = 2 };

enum class DirectLeasePhase : uint8_t {
  Normal = 0,
  Requesting,       // requester: sent Request, awaiting Grant/Deny
  AwaitingActivate, // grantor: sent Grant, awaiting Activate
  AwaitingAck,      // requester: sent Activate, awaiting Ack
  AwaitingHello,    // both: profile switch pending/applied, awaiting peer's Hello rendezvous
  Active,           // both: Hello exchanged, direct high-speed TX allowed
  Releasing,        // both: sent/awaiting Release/ReleaseAck, restore pending
};

// A deferred, tick()-driven action gated on actual TX-completion evidence
// (IAuthenticatedTransportPort::txQueueEmpty()) plus a bounded guard
// delay -- NEVER applied synchronously inside a frame handler, because
// the frame that must precede the profile change (Ack before switching
// to high-speed; the final Release/ReleaseAck before restoring Normal)
// must actually have left the radio on the CURRENT profile first, or the
// still-listening peer (on the OLD profile) can never receive it.
enum class PendingLeaseAction : uint8_t {
  None = 0,
  SwitchToHighThenHello,  // apply the requested high-speed profile, then send Hello
  SwitchToNormal,         // drive the underlying FSM's Release/ReleaseAcked restore path
};

class DirectLeaseEngine {
public:
  DirectLeaseEngine(IRadioProfilePort& radio, IClockPort& clock, IAuthenticatedTransportPort& transport,
                     ILeaseGrantPolicyPort& grantPolicy)
      : radio_(radio), clock_(clock), transport_(transport), grantPolicy_(grantPolicy) {
    lease_.setRestoreCallback(&restoreTrampoline, this);
  }

  void forceNormalOnBoot() {
    restoreFaulted_ = !radio_.restoreNormalProfile();
    lease_.handle(runtime::OtaLeaseEvent::Reset);
    phase_ = DirectLeasePhase::Normal;
    role_ = DirectLeaseRole::None;
    pendingAction_ = PendingLeaseAction::None;
    pendingSend_.active = false;
  }

  // Begins a bounded request epoch for `peerId`'s requested profile: an
  // OUTBOUND, locally-initiated decision (not gated by an inbound frame).
  // Rejects (no state change) an invalid profile, a fault-blocked radio,
  // or a request while another peer's lease is already in flight (one
  // radio, one lease at a time). Actually sends the Request wire frame.
  bool requestLease(const CampaignPeerId& peerId, const CampaignRadioProfileParams& requested, uint32_t watchdogMs) {
    if (restoreFaulted_) { lastRefusal_ = CampaignRefusalReason::InvalidRadioProfile; return false; }
    if (phase_ != DirectLeasePhase::Normal) { lastRefusal_ = CampaignRefusalReason::TransportBackpressure; return false; }
    if (!isValidLeaseEpoch(watchdogMs)) { lastRefusal_ = CampaignRefusalReason::InvalidLeaseEpoch; return false; }
    if (!isValidDirectHighSpeedProfile(radio_, requested)) {
      lastRefusal_ = CampaignRefusalReason::InvalidRadioProfile;
      return false;
    }
    if (!lease_.handle(runtime::OtaLeaseEvent::RequestLease)) return false;

    role_ = DirectLeaseRole::Requester;
    peer_ = peerId;
    requested_ = requested;
    leaseId_ = ++leaseIdCounter_;
    nonce_ = nextNonce();
    epochStartMs_ = clock_.nowMs();
    epochDurationMs_ = watchdogMs;
    phase_ = DirectLeasePhase::Requesting;
    lastRefusal_ = CampaignRefusalReason::None;

    CampaignLeasePayload p;
    p.subtype = CampaignLeaseSubtype::Request;
    p.leaseId = leaseId_;
    p.nonce = nonce_;
    p.epochMs = watchdogMs;
    fillProfile(p, requested);
    sendLease(peerId, p); // enqueue failures retried by tick(), never rolled back silently
    return true;
  }

  // Real wire dispatch: decodes the campaign envelope and, for
  // LeaseNegotiation/Hello, the inner payload, validates authenticated
  // Pairwise context + verified peer binding + leaseId/nonce match for
  // the CURRENT phase/role before any mutation, and drives the actual
  // bilateral handshake (including sending the next frame in the
  // sequence). Foreign peer/leaseId/nonce/session frames are rejected
  // before any side effect.
  bool onFrame(const AuthenticatedInboundFrame& frame) {
    if (!frame.hasAuthenticatedPeer()) {
      lastRefusal_ = CampaignRefusalReason::UntrustedContext;
      return false;
    }
    CampaignEnvelopeHeader hdr;
    const uint8_t* payload = nullptr;
    size_t payloadLen = 0;
    if (decodeCampaignEnvelope(frame.payload, frame.payloadLen, hdr, payload, payloadLen) != CampaignCodecResult::Ok) {
      return false;
    }

    if (hdr.type == CampaignMessageType::LeaseNegotiation) {
      CampaignLeasePayload lp;
      if (!decodeCampaignLease(payload, payloadLen, lp)) return false;
      switch (lp.subtype) {
        case CampaignLeaseSubtype::Request: return handleRequest(frame, lp);
        case CampaignLeaseSubtype::Grant: return handleGrant(frame, lp);
        case CampaignLeaseSubtype::Deny: return handleDeny(frame, lp);
        case CampaignLeaseSubtype::Activate: return handleActivate(frame, lp);
        case CampaignLeaseSubtype::Ack: return handleAck(frame, lp);
        case CampaignLeaseSubtype::Release: return handleRelease(frame, lp);
        case CampaignLeaseSubtype::ReleaseAck: return handleReleaseAck(frame, lp);
      }
      return false;
    }
    if (hdr.type == CampaignMessageType::Hello) {
      CampaignHelloPayload hp;
      if (!decodeCampaignHello(payload, payloadLen, hp)) return false;
      return handleHello(frame, hp);
    }
    return false;
  }

  // Locally-initiated release (either role), while Active/AwaitingHello.
  bool release() {
    if (phase_ != DirectLeasePhase::Active && phase_ != DirectLeasePhase::AwaitingHello) return false;
    lease_.handle(runtime::OtaLeaseEvent::Release);
    phase_ = DirectLeasePhase::Releasing;
    CampaignLeasePayload p;
    p.subtype = CampaignLeaseSubtype::Release;
    p.leaseId = leaseId_;
    p.nonce = nonce_;
    sendLease(peer_, p); // enqueue failures retried by tick()
    return true;
  }

  // Must be polled periodically (bounded, no busy loop): drains any
  // outbound-send retry, applies a deferred profile-switch action once
  // TX-completion evidence + guard delay confirm it is safe, and fires
  // the per-peer watchdog on epoch expiry. Returns true iff this call
  // newly forced an epoch timeout restore back to Normal.
  bool tickWatchdog() {
    retryPendingSend();
    applyPendingAction();
    if (phase_ == DirectLeasePhase::Normal) return false;
    if (!campaignElapsedAtLeast(clock_.nowMs(), epochStartMs_, epochDurationMs_)) return false;
    lease_.handle(runtime::OtaLeaseEvent::Timeout);
    phase_ = DirectLeasePhase::Normal;
    role_ = DirectLeaseRole::None;
    pendingAction_ = PendingLeaseAction::None;
    pendingSend_.active = false;
    lastRefusal_ = CampaignRefusalReason::Timeout;
    return true;
  }

  bool forcedAbort() {
    if (phase_ == DirectLeasePhase::Normal) return false;
    lease_.handle(runtime::OtaLeaseEvent::Failure);
    phase_ = DirectLeasePhase::Normal;
    role_ = DirectLeaseRole::None;
    pendingAction_ = PendingLeaseAction::None;
    pendingSend_.active = false;
    lastRefusal_ = CampaignRefusalReason::Aborted;
    return true;
  }

  // Explicit retry after a restore fault (e.g. after a subsequent
  // successful radio re-init). Never called implicitly.
  bool retryRestoreNormal() {
    if (!restoreFaulted_) return true;
    restoreFaulted_ = !radio_.restoreNormalProfile();
    return !restoreFaulted_;
  }

  DirectLeasePhase phase() const { return phase_; }
  DirectLeaseRole role() const { return role_; }
  // Ordinary transmit on the normal profile is blocked whenever a lease
  // is in any non-Normal phase, AND whenever a prior restore attempt
  // itself failed -- a failed restoreNormalProfile() NEVER falls through
  // to claiming Normal is actually active.
  bool isNormalTxBlocked() const { return phase_ != DirectLeasePhase::Normal || restoreFaulted_; }
  bool isRestoreFaulted() const { return restoreFaulted_; }
  uint32_t restoreCount() const { return lease_.restoreCount(); }
  CampaignRefusalReason lastRefusal() const { return lastRefusal_; }

private:
  static void fillProfile(CampaignLeasePayload& p, const CampaignRadioProfileParams& profile) {
    p.freqMhzMilli = campaignFreqToMilliMhz(profile.freqMhz);
    p.bandwidthKhzX10 = campaignBwToKhzX10(profile.bandwidthKhz);
    p.spreadingFactor = profile.spreadingFactor;
    p.codingRate = profile.codingRate;
  }
  static CampaignRadioProfileParams profileFrom(const CampaignLeasePayload& p) {
    CampaignRadioProfileParams out;
    out.profile = CampaignRadioProfile::DirectHighSpeed;
    out.freqMhz = campaignFreqFromMilliMhz(p.freqMhzMilli);
    out.bandwidthKhz = campaignBwFromKhzX10(p.bandwidthKhzX10);
    out.spreadingFactor = p.spreadingFactor;
    out.codingRate = p.codingRate;
    return out;
  }

  uint32_t nextNonce() { return clock_.nowMs() * 2654435761u + (++nonceCounter_); }

  CampaignSendResult sendLease(const CampaignPeerId& peerId, const CampaignLeasePayload& p) {
    uint8_t payload[kCampaignLeasePayloadSize];
    size_t payloadLen = 0;
    if (!encodeCampaignLease(p, payload, sizeof(payload), payloadLen)) return CampaignSendResult::Rejected;
    return sendEnvelope(peerId, CampaignMessageType::LeaseNegotiation, payload, payloadLen);
  }

  CampaignSendResult sendHello(const CampaignPeerId& peerId) {
    CampaignHelloPayload hp{leaseId_, nonce_};
    uint8_t payload[kCampaignHelloPayloadSize];
    size_t payloadLen = 0;
    if (!encodeCampaignHello(hp, payload, sizeof(payload), payloadLen)) return CampaignSendResult::Rejected;
    return sendEnvelope(peerId, CampaignMessageType::Hello, payload, payloadLen);
  }

  // Encodes the full wire frame and attempts delivery; a Backpressure/
  // Rejected/BudgetDenied result is NEVER treated as silent success (no
  // false handshake progress) -- the exact encoded frame is retained in
  // the bounded single-slot retry queue and retried every tick() until
  // the transport accepts it or the per-peer watchdog epoch expires.
  CampaignSendResult sendEnvelope(const CampaignPeerId& peerId, CampaignMessageType type,
                                   const uint8_t* payload, size_t payloadLen) {
    CampaignEnvelopeHeader hdr;
    hdr.type = type;
    hdr.frameSeq = ++frameSeqCounter_;
    uint8_t frame[protocol::kOtaMaxFrameSize];
    size_t frameLen = 0;
    if (encodeCampaignEnvelope(hdr, payload, payloadLen, frame, sizeof(frame), frameLen) != CampaignCodecResult::Ok) {
      return CampaignSendResult::Rejected;
    }
    CampaignDestination dest;
    dest.scope = CampaignAuthScope::Pairwise;
    dest.peerId = peerId;
    CampaignSendResult r = transport_.trySend(dest, protocol::OtaAirtimeCategory::Control, frame, frameLen);
    if (r != CampaignSendResult::Enqueued && frameLen <= sizeof(pendingSend_.frame)) {
      pendingSend_.active = true;
      pendingSend_.dest = dest;
      pendingSend_.frameLen = frameLen;
      for (size_t i = 0; i < frameLen; ++i) pendingSend_.frame[i] = frame[i];
    }
    return r;
  }

  void retryPendingSend() {
    if (!pendingSend_.active) return;
    CampaignSendResult r = transport_.trySend(pendingSend_.dest, protocol::OtaAirtimeCategory::Control,
                                               pendingSend_.frame, pendingSend_.frameLen);
    if (r == CampaignSendResult::Enqueued) pendingSend_.active = false;
  }

  // Deferred, tick()-driven profile switch: only applied once BOTH the
  // bounded guard delay has elapsed AND the transport confirms nothing
  // (including any still-retrying frame above) remains queued from this
  // engine -- real TX-completion evidence, not an assumption that
  // enqueued == transmitted.
  void applyPendingAction() {
    if (pendingAction_ == PendingLeaseAction::None) return;
    if (pendingSend_.active || !transport_.txQueueEmpty()) return;
    if (!campaignElapsedAtLeast(clock_.nowMs(), pendingActionScheduledAtMs_, kCampaignLeaseSwitchGuardMs)) return;

    PendingLeaseAction action = pendingAction_;
    pendingAction_ = PendingLeaseAction::None;
    switch (action) {
      case PendingLeaseAction::SwitchToHighThenHello: {
        if (!radio_.applyProfile(requested_)) {
          forcedLocalAbort();
          lastRefusal_ = CampaignRefusalReason::InvalidRadioProfile;
          return;
        }
        epochStartMs_ = clock_.nowMs();
        sendHello(peer_);
        break;
      }
      case PendingLeaseAction::SwitchToNormal: {
        // The Release event (Active->Releasing) was already fired at the
        // point the Release/ReleaseAck frame was enqueued; only the
        // restore-triggering ReleaseAcked transition is deferred to here.
        lease_.handle(runtime::OtaLeaseEvent::ReleaseAcked);
        phase_ = DirectLeasePhase::Normal;
        role_ = DirectLeaseRole::None;
        break;
      }
      default:
        break;
    }
  }

  void schedulePendingAction(PendingLeaseAction action) {
    pendingAction_ = action;
    pendingActionScheduledAtMs_ = clock_.nowMs();
  }

  // Grantor side: mechanical accept/deny based purely on profile validity,
  // single-lease-at-a-time availability, and EXPLICIT local board/site
  // policy approval (ILeaseGrantPolicyPort) -- authenticated Pairwise
  // identity alone can never force this node off its normal frequency.
  bool handleRequest(const AuthenticatedInboundFrame& frame, const CampaignLeasePayload& lp) {
    if (phase_ != DirectLeasePhase::Normal) {
      CampaignLeasePayload deny;
      deny.subtype = CampaignLeaseSubtype::Deny;
      deny.leaseId = lp.leaseId;
      deny.nonce = lp.nonce;
      deny.reason = static_cast<uint8_t>(CampaignRefusalReason::TransportBackpressure);
      sendLease(frame.pairwise()->peerId, deny);
      return false;
    }
    CampaignRadioProfileParams requested = profileFrom(lp);
    if (!isValidLeaseEpoch(lp.epochMs)) {
      CampaignLeasePayload deny;
      deny.subtype = CampaignLeaseSubtype::Deny;
      deny.leaseId = lp.leaseId;
      deny.nonce = lp.nonce;
      deny.reason = static_cast<uint8_t>(CampaignRefusalReason::InvalidLeaseEpoch);
      sendLease(frame.pairwise()->peerId, deny);
      lastRefusal_ = CampaignRefusalReason::InvalidLeaseEpoch;
      return false;
    }
    if (!isValidDirectHighSpeedProfile(radio_, requested)) {
      CampaignLeasePayload deny;
      deny.subtype = CampaignLeaseSubtype::Deny;
      deny.leaseId = lp.leaseId;
      deny.nonce = lp.nonce;
      deny.reason = static_cast<uint8_t>(CampaignRefusalReason::InvalidRadioProfile);
      sendLease(frame.pairwise()->peerId, deny);
      lastRefusal_ = CampaignRefusalReason::InvalidRadioProfile;
      return false;
    }
    // Pairwise authentication of the SENDER is necessary but NOT
    // sufficient to force this node off its normal operating frequency --
    // local board/site policy must independently approve the grant.
    if (!grantPolicy_.approveLeaseGrant(frame.pairwise()->peerId, requested)) {
      CampaignLeasePayload deny;
      deny.subtype = CampaignLeaseSubtype::Deny;
      deny.leaseId = lp.leaseId;
      deny.nonce = lp.nonce;
      deny.reason = static_cast<uint8_t>(CampaignRefusalReason::LeaseGrantPolicyDenied);
      sendLease(frame.pairwise()->peerId, deny);
      lastRefusal_ = CampaignRefusalReason::LeaseGrantPolicyDenied;
      return false;
    }
    if (!lease_.handle(runtime::OtaLeaseEvent::RequestLease)) return false;
    role_ = DirectLeaseRole::Grantor;
    peer_ = frame.pairwise()->peerId;
    leaseId_ = lp.leaseId;
    nonce_ = lp.nonce;
    requested_ = requested;
    epochStartMs_ = clock_.nowMs();
    epochDurationMs_ = lp.epochMs;
    phase_ = DirectLeasePhase::AwaitingActivate;
    lease_.handle(runtime::OtaLeaseEvent::Granted);

    CampaignLeasePayload grant;
    grant.subtype = CampaignLeaseSubtype::Grant;
    grant.leaseId = leaseId_;
    grant.nonce = nonce_;
    grant.epochMs = lp.epochMs;
    fillProfile(grant, requested_);
    sendLease(peer_, grant);
    lastRefusal_ = CampaignRefusalReason::None;
    return true;
  }

  bool matchesActive(const AuthenticatedInboundFrame& frame, const CampaignLeasePayload& lp) const {
    return frame.pairwise()->peerId == peer_ && lp.leaseId == leaseId_ && lp.nonce == nonce_;
  }

  // Requester side: received Grant.
  bool handleGrant(const AuthenticatedInboundFrame& frame, const CampaignLeasePayload& lp) {
    if (role_ != DirectLeaseRole::Requester || phase_ != DirectLeasePhase::Requesting) return false;
    if (!matchesActive(frame, lp)) { lastRefusal_ = CampaignRefusalReason::ForeignController; return false; }
    CampaignRadioProfileParams granted = profileFrom(lp);
    if (!isValidDirectHighSpeedProfile(radio_, granted) ||
        granted.freqMhz != requested_.freqMhz || granted.spreadingFactor != requested_.spreadingFactor) {
      forcedLocalAbort();
      lastRefusal_ = CampaignRefusalReason::InvalidRadioProfile;
      return false;
    }
    if (!lease_.handle(runtime::OtaLeaseEvent::Granted)) return false;
    epochStartMs_ = clock_.nowMs();
    epochDurationMs_ = lp.epochMs;
    phase_ = DirectLeasePhase::AwaitingAck;

    CampaignLeasePayload activate;
    activate.subtype = CampaignLeaseSubtype::Activate;
    activate.leaseId = leaseId_;
    activate.nonce = nonce_;
    sendLease(peer_, activate);
    return true;
  }

  bool handleDeny(const AuthenticatedInboundFrame& frame, const CampaignLeasePayload& lp) {
    if (role_ != DirectLeaseRole::Requester || phase_ != DirectLeasePhase::Requesting) return false;
    if (!matchesActive(frame, lp)) return false;
    lease_.handle(runtime::OtaLeaseEvent::Denied);
    phase_ = DirectLeasePhase::Normal;
    role_ = DirectLeaseRole::None;
    lastRefusal_ = static_cast<CampaignRefusalReason>(lp.reason);
    return true;
  }

  // Grantor side: received Activate -- send Ack NOW (still on the current
  // profile, so the still-Normal requester can actually receive it), then
  // DEFER the actual high-speed profile switch + Hello to tick() once TX
  // completion evidence confirms the Ack really left the radio. Applying
  // the profile synchronously here (as before) would switch the grantor
  // to the temporary profile BEFORE the Ack physically transmits on the
  // normal channel -- a real deadlock, since the requester is still
  // listening on Normal.
  bool handleActivate(const AuthenticatedInboundFrame& frame, const CampaignLeasePayload& lp) {
    if (role_ != DirectLeaseRole::Grantor || phase_ != DirectLeasePhase::AwaitingActivate) return false;
    if (!matchesActive(frame, lp)) return false;
    phase_ = DirectLeasePhase::AwaitingHello;
    CampaignLeasePayload ack;
    ack.subtype = CampaignLeaseSubtype::Ack;
    ack.leaseId = leaseId_;
    ack.nonce = nonce_;
    sendLease(peer_, ack);
    schedulePendingAction(PendingLeaseAction::SwitchToHighThenHello);
    return true;
  }

  // Requester side: received Ack -- the Ack already confirms the grantor
  // physically transmitted it on Normal; still defer OUR OWN switch
  // behind the same TX-completion + guard gate for symmetry (no frame of
  // ours needs to precede this switch, but this keeps one single code
  // path and one single invariant: never switch profile synchronously
  // inside a frame handler).
  bool handleAck(const AuthenticatedInboundFrame& frame, const CampaignLeasePayload& lp) {
    if (role_ != DirectLeaseRole::Requester || phase_ != DirectLeasePhase::AwaitingAck) return false;
    if (!matchesActive(frame, lp)) return false;
    phase_ = DirectLeasePhase::AwaitingHello;
    schedulePendingAction(PendingLeaseAction::SwitchToHighThenHello);
    return true;
  }

  bool handleHello(const AuthenticatedInboundFrame& frame, const CampaignHelloPayload& hp) {
    if (phase_ != DirectLeasePhase::AwaitingHello) return false;
    if (frame.pairwise()->peerId != peer_ || hp.leaseId != leaseId_ || hp.nonce != nonce_) return false;
    epochStartMs_ = clock_.nowMs();
    phase_ = DirectLeasePhase::Active;
    lastRefusal_ = CampaignRefusalReason::None;
    return true;
  }

  // Peer-initiated release: send ReleaseAck NOW while still on the
  // CURRENT (high-speed) profile -- the peer is still listening there --
  // then DEFER the actual restore-to-Normal (and the FSM's restore-
  // triggering ReleaseAcked transition) to tick() once TX-completion
  // evidence confirms the ReleaseAck really left the radio. Restoring
  // synchronously here (as before) would switch this node back to Normal
  // BEFORE the ReleaseAck physically transmits on the high-speed channel
  // -- the same class of deadlock as handleActivate, mirrored.
  bool handleRelease(const AuthenticatedInboundFrame& frame, const CampaignLeasePayload& lp) {
    if ((phase_ != DirectLeasePhase::Active && phase_ != DirectLeasePhase::AwaitingHello) || !matchesActive(frame, lp)) {
      return false;
    }
    lease_.handle(runtime::OtaLeaseEvent::Release); // Active -> Releasing; does not itself restore
    phase_ = DirectLeasePhase::Releasing;
    CampaignLeasePayload ack;
    ack.subtype = CampaignLeaseSubtype::ReleaseAck;
    ack.leaseId = lp.leaseId;
    ack.nonce = lp.nonce;
    sendLease(frame.pairwise()->peerId, ack);
    schedulePendingAction(PendingLeaseAction::SwitchToNormal);
    return true;
  }

  // Requester (or whichever side called release() locally) received the
  // ReleaseAck confirming the peer got our Release. No further frame of
  // ours needs to precede the restore, but the same deferred gate is used
  // for one single invariant/no synchronous-switch code path.
  bool handleReleaseAck(const AuthenticatedInboundFrame& frame, const CampaignLeasePayload& lp) {
    if (phase_ != DirectLeasePhase::Releasing || !matchesActive(frame, lp)) return false;
    schedulePendingAction(PendingLeaseAction::SwitchToNormal);
    return true;
  }

  void forcedLocalAbort() {
    lease_.handle(runtime::OtaLeaseEvent::Failure);
    phase_ = DirectLeasePhase::Normal;
    role_ = DirectLeaseRole::None;
    pendingAction_ = PendingLeaseAction::None;
    pendingSend_.active = false;
  }

  static void restoreTrampoline(void* ctx) {
    DirectLeaseEngine* self = static_cast<DirectLeaseEngine*>(ctx);
    self->restoreFaulted_ = !self->radio_.restoreNormalProfile();
  }

  struct PendingSend {
    bool active = false;
    CampaignDestination dest{};
    uint8_t frame[protocol::kOtaMaxFrameSize] = {0};
    size_t frameLen = 0;
  };

  IRadioProfilePort& radio_;
  IClockPort& clock_;
  IAuthenticatedTransportPort& transport_;
  ILeaseGrantPolicyPort& grantPolicy_;
  runtime::OtaLeaseStateMachine lease_;
  DirectLeasePhase phase_ = DirectLeasePhase::Normal;
  DirectLeaseRole role_ = DirectLeaseRole::None;
  CampaignPeerId peer_{};
  CampaignRadioProfileParams requested_{};
  uint32_t leaseId_ = 0;
  uint32_t leaseIdCounter_ = 0;
  uint32_t nonce_ = 0;
  uint32_t nonceCounter_ = 0;
  uint32_t frameSeqCounter_ = 0;
  uint32_t epochStartMs_ = 0;
  uint32_t epochDurationMs_ = 0;
  PendingLeaseAction pendingAction_ = PendingLeaseAction::None;
  uint32_t pendingActionScheduledAtMs_ = 0;
  PendingSend pendingSend_{};
  bool restoreFaulted_ = false;
  CampaignRefusalReason lastRefusal_ = CampaignRefusalReason::None;
};

} // namespace campaign
} // namespace ota
} // namespace meshcore
