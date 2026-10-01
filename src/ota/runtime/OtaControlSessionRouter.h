#pragma once

// Device-side USB commissioning session router (commissioning contract
// section D/E/F/G): owns session/job-ticket bookkeeping, the bounded
// upload scratch area, and the typed WouldBlock/RejectedChangedRequest/
// Denied/Busy/... outcome mapping ON TOP OF the wire-format-only
// OtaCommissioningAbi.h. It never performs cryptographic signing/
// verification or touches Store/Boot flash itself -- those are reached
// only through the injected IOtaControlJobBackend, which Authority
// (src/ota/authority/**) and Store (src/ota/security/**) are expected to
// implement once their own coordinator/physical-writer APIs stabilize.
// Until a real backend is bound, every job-bearing request fails closed
// via OtaControlNullJobBackend (NoCapacity) rather than fabricating
// progress.
//
// Scope notes (see also this module's status reports to MAIN/Astra):
//  - True per-physical-USB-endpoint ownership ("replies only to same USB
//    endpoint, not MultiSerialInterface broadcast") cannot be implemented
//    here: BaseSerialInterface/MultiSerialInterface/ArduinoSerialInterface
//    (src/helpers/*.h, *.cpp) expose no per-connection identity at all to
//    callers. This router approximates endpoint ownership with session-id
//    occupancy (one open session at a time, matching the existing
//    single-connection reality of MyMesh's serial command dispatch) and
//    flags the serial-interface gap for an explicit scope grant rather
//    than inventing a fake endpoint identity.
//  - Device-minted entropy (session id, CHALLENGE bytes) is sourced via
//    the small IOtaControlEntropySource interface below, not any
//    particular platform RNG, matching this module's existing convention
//    of not depending on Arduino/mesh::RNG from header-only ota/runtime
//    code (see OtaDirectLeaseHandler for the same pattern). The
//    Arduino-side integration binds this to the real mesh::RNG.

#include "../protocol/OtaCommissioningAbi.h"
#include <cstring>

namespace meshcore {
namespace ota {
namespace runtime {

using ota::protocol::OtaControlObjectKind;
using ota::protocol::OtaControlReplyHeader;
using ota::protocol::OtaControlRequestHeader;
using ota::protocol::OtaControlStatus;
using ota::protocol::OtaControlSubcommand;
using ota::protocol::kOtaControlMaxDataLen;
using ota::protocol::kOtaControlRequestHeaderSize;
using ota::protocol::kOtaControlSessionIdBytes;

// Device-side entropy source for session ids and fresh per-ticket
// CHALLENGE bytes (contract: "single-use", "minted by device", "never
// host-chosen"). Deliberately NOT mesh::RNG so this header stays
// Arduino-independent; the platform integration layer bridges this to the
// real qualified board entropy source (e.g. radio-noise sampling), never
// a deterministic boot-seeded PRNG (StdRNG/millis).
//
// Returns false (and must leave `dest` UNTOUCHED) when fresh entropy is
// genuinely unavailable right now (e.g. the underlying radio is not
// initialized) -- callers must then refuse the OPEN/CHALLENGE outright
// rather than publishing degraded/stale bytes.
class IOtaControlEntropySource {
public:
  virtual ~IOtaControlEntropySource() = default;
  virtual bool fillRandom(uint8_t* dest, size_t len) = 0;
};

// Typed, bounded backend for the long-running (Measure/Certify/Prepare/
// Activate) operations. The router owns framing/session/ticket/ownership
// bookkeeping; this is where Authority's AuthorityCoordinator and Store's
// physical-writer adapter are ultimately expected to be bound. Every
// method must be synchronous and bounded -- "MCU never loops to
// completion inside one USB callback" -- a long-running operation reports
// Pending and lets POLL observe progress across later calls.
class IOtaControlJobBackend {
public:
  virtual ~IOtaControlJobBackend() = default;

  // Begin (first call for a given jobTicket) or continue (subsequent call
  // with an IDENTICAL request fingerprint) one job. `input`/`inputLen`/
  // `inputKind` is the fully-assembled object already accumulated in the
  // router's PUT_FRAGMENT scratch (or None/empty for subs that need no
  // upload, e.g. Measure). Must not be called by the router for a mere
  // status re-check (see pollJob) or for a changed-argument resubmission
  // (rejected by the router before reaching here).
  virtual OtaControlStatus beginJob(OtaControlSubcommand sub, uint32_t jobTicket,
                                     OtaControlObjectKind inputKind, const uint8_t* input,
                                     size_t inputLen, uint16_t& reason) = 0;

  // Status-only re-check of an already-started job; must not advance work
  // (contract: "POLL is status only ... neither advances physical work
  // inline").
  virtual OtaControlStatus pollJob(uint32_t jobTicket, uint16_t& reason) = 0;

  // Copies up to `maxLen` bytes of `kind` at `offset` from the job's
  // result (P683 readback, PrepareAck112, ...) into `dest`, reporting the
  // actual slice length in `outLen`. Must leave `dest`/`outLen` untouched
  // on any non-Ok status.
  virtual OtaControlStatus readObject(uint32_t jobTicket, OtaControlObjectKind kind, uint32_t offset,
                                       uint8_t* dest, uint8_t maxLen, uint8_t& outLen,
                                       uint16_t& reason) = 0;

  // Releases only the job's RAM lease/continuation -- never an
  // Issued/Prepared/Spent/floor/counter fact (contract section G).
  virtual void cancelJob(uint32_t jobTicket) = 0;
};

// Fail-closed default: every job-bearing operation reports NoCapacity
// until a real Authority/Store-backed implementation is constructed and
// bound by the platform integration layer. Intentionally NOT a stub that
// fabricates Ok/Pending -- a build with no backend bound must refuse
// every commissioning step, never stage fake progress.
class OtaControlNullJobBackend : public IOtaControlJobBackend {
public:
  static constexpr uint16_t kReasonNoBackendBound = 1;

  OtaControlStatus beginJob(OtaControlSubcommand, uint32_t, OtaControlObjectKind, const uint8_t*,
                             size_t, uint16_t& reason) override {
    reason = kReasonNoBackendBound;
    return OtaControlStatus::NoCapacity;
  }
  OtaControlStatus pollJob(uint32_t, uint16_t& reason) override {
    reason = kReasonNoBackendBound;
    return OtaControlStatus::NoCapacity;
  }
  OtaControlStatus readObject(uint32_t, OtaControlObjectKind, uint32_t, uint8_t*, uint8_t,
                               uint8_t& outLen, uint16_t& reason) override {
    outLen = 0;
    reason = kReasonNoBackendBound;
    return OtaControlStatus::NoCapacity;
  }
  void cancelJob(uint32_t) override {}
};

// Forwards every call to whichever backend is currently bound (defaulting
// to the fail-closed null backend), so the router itself never needs
// reconstructing when a real Authority/Store-backed implementation
// becomes available later -- mirrors this codebase's existing weak-
// default-then-real-attach pattern (see
// configureCompanionFirmwareOtaBackend()).
class OtaControlJobBackendSlot : public IOtaControlJobBackend {
public:
  OtaControlJobBackendSlot() : current_(&null_backend_) {}

  // Binds the real backend to use from now on, or pass nullptr to revert
  // to the fail-closed default.
  void bind(IOtaControlJobBackend* backend) { current_ = backend ? backend : &null_backend_; }

  OtaControlStatus beginJob(OtaControlSubcommand sub, uint32_t jobTicket, OtaControlObjectKind inputKind,
                             const uint8_t* input, size_t inputLen, uint16_t& reason) override {
    return current_->beginJob(sub, jobTicket, inputKind, input, inputLen, reason);
  }
  OtaControlStatus pollJob(uint32_t jobTicket, uint16_t& reason) override {
    return current_->pollJob(jobTicket, reason);
  }
  OtaControlStatus readObject(uint32_t jobTicket, OtaControlObjectKind kind, uint32_t offset,
                               uint8_t* dest, uint8_t maxLen, uint8_t& outLen, uint16_t& reason) override {
    return current_->readObject(jobTicket, kind, offset, dest, maxLen, outLen, reason);
  }
  void cancelJob(uint32_t jobTicket) override { current_->cancelJob(jobTicket); }

private:
  OtaControlNullJobBackend null_backend_;
  IOtaControlJobBackend* current_;
};

namespace internal {

// Small non-cryptographic fingerprint used ONLY to distinguish "same
// ticket, same request" (Pending passthrough) from "same ticket, changed
// arguments" (RejectedChangedRequest) per contract section G. This is not
// an integrity/authenticity check -- that remains Authority's domain.
inline uint32_t otaControlFnv1a(const uint8_t* data, size_t len, uint32_t seed) {
  uint32_t h = seed ^ 0x811C9DC5u;
  for (size_t i = 0; i < len; i++) {
    h ^= data[i];
    h *= 16777619u;
  }
  return h;
}

} // namespace internal

// Largest object kind any PUT_FRAGMENT upload currently assembles
// (OtaControlObjectKind::PreparedRootP683). Bounded, resident, no dynamic
// allocation.
inline constexpr size_t kOtaControlScratchCapacity = 683;

class OtaControlSessionRouter {
public:
  OtaControlSessionRouter(IOtaControlEntropySource& entropy, IOtaControlJobBackend& backend)
      : entropy_(entropy), backend_(backend) {}

  // Decodes one 37B+payload request from `req`/`reqLen`, dispatches it,
  // and encodes a 40B+payload reply into `reply`/`replyCap`. Returns the
  // number of bytes written to `reply`, or 0 if `req` could not even be
  // decoded as a well-formed request header (caller should fall back to
  // its own generic malformed-frame handling in that case).
  size_t dispatch(const uint8_t* req, size_t reqLen, uint8_t* reply, size_t replyCap) {
    OtaControlRequestHeader hdr;
    if (!ota::protocol::decodeOtaControlRequestHeader(req, reqLen, hdr)) return 0;
    if (hdr.dataLen > kOtaControlMaxDataLen) return 0;
    // ReadObject is the one subcommand where hdr.dataLen is NOT a count of
    // bytes actually present after the header -- it's the requested READ
    // COUNT (1..128) the device should return in the reply, while the
    // request frame itself always carries zero payload bytes. Every other
    // subcommand's dataLen genuinely counts transferred payload bytes.
    if (hdr.sub != ota::protocol::OtaControlSubcommand::ReadObject &&
        reqLen < kOtaControlRequestHeaderSize + hdr.dataLen) {
      return 0;
    }
    const uint8_t* data = req + kOtaControlRequestHeaderSize;

    OtaControlReplyHeader out;
    out.sub = hdr.sub;
    out.requestId = hdr.requestId;
    out.jobTicket = hdr.jobTicket;
    out.objectKind = hdr.objectKind;
    uint16_t reason = 0;

    // Raw header decoding above is purely structural (field widths/
    // ranges); it is NOT semantic admission. Every operation-specific
    // shape/range rule (OPEN/CHALLENGE carry no transferred object,
    // PUT_FRAGMENT/READ_OBJECT ranges stay inside the object kind's fixed
    // size, unrecognised kinds are rejected rather than treated as None,
    // etc.) must be enforced here, before any handler touches session/job
    // state. `payloadLen` is the ACTUAL bytes present after the header
    // (which may exceed hdr.dataLen for a malformed/padded frame), not
    // hdr.dataLen itself, so a declared/actual mismatch is still caught.
    // Admission must happen BEFORE any handler mutates session/job/
    // scratch state -- including making sure the caller's reply buffer
    // could even hold THIS operation's worst-case reply. Checking this
    // only after a handler has already run (as the final encode step
    // below does for the ACTUAL reply size) is too late: a handler could
    // have begun a job, written scratch bytes, or opened a session that
    // can then never be reported back to the caller. Only CHALLENGE
    // (fixed 16 reply bytes) and READ_OBJECT (hdr.dataLen requested
    // bytes, already range-checked to 1..128 above) ever carry reply
    // payload; every other subcommand's reply is header-only.
    size_t maxReplyPayload = 0;
    if (hdr.sub == ota::protocol::OtaControlSubcommand::Challenge) {
      maxReplyPayload = kOtaControlSessionIdBytes;
    } else if (hdr.sub == ota::protocol::OtaControlSubcommand::ReadObject) {
      maxReplyPayload = hdr.dataLen;
    }
    if (replyCap < ota::protocol::kOtaControlReplyHeaderSize + maxReplyPayload) return 0;

    const size_t actualPayloadLen = reqLen - kOtaControlRequestHeaderSize;
    const auto shape = ota::protocol::validateOtaControlRequestShape(hdr, actualPayloadLen);
    if (shape != ota::protocol::OtaControlCodecResult::Ok) {
      out.status = OtaControlStatus::Denied;
      reason = ota::protocol::kOtaControlShapeReasonBase + static_cast<uint16_t>(shape);
      out.reason = reason;
      size_t replyLen = 0;
      if (!ota::protocol::encodeOtaControlReplyHeader(out, reply, replyCap)) return 0;
      return ota::protocol::kOtaControlReplyHeaderSize;
    }

    switch (hdr.sub) {
      case OtaControlSubcommand::Open:
        handleOpen(hdr, data, out, reason);
        break;
      case OtaControlSubcommand::Close:
        handleClose(hdr, out, reason);
        break;
      case OtaControlSubcommand::Cancel:
        handleCancel(hdr, out, reason);
        break;
      case OtaControlSubcommand::PutFragment:
        handlePutFragment(hdr, data, out, reason);
        break;
      case OtaControlSubcommand::Poll:
        handlePoll(hdr, out, reason);
        break;
      case OtaControlSubcommand::ReadObject:
        handleReadObject(hdr, reply, replyCap, out, reason);
        break;
      case OtaControlSubcommand::Challenge:
        handleChallenge(hdr, data, out, reason);
        break;
      case OtaControlSubcommand::Measure:
      case OtaControlSubcommand::Certify:
      case OtaControlSubcommand::Prepare:
      case OtaControlSubcommand::Activate:
        handleJobRequest(hdr, data, out, reason);
        break;
      default:
        out.status = OtaControlStatus::Denied;
        reason = kReasonUnknownSubcommand;
        break;
    }

    // Echo the real, currently-open session id on every reply the
    // request's own session id genuinely matched -- the handlers above
    // that mint/close a session (OPEN/CLOSE/CANCEL/CHALLENGE) already set
    // this themselves; this covers every other op (PUT_FRAGMENT/POLL/
    // READ_OBJECT/job requests) that previously left out.session all-zero
    // even on a successfully-matched session. A request whose session did
    // NOT match is deliberately left with an all-zero reply session.
    if (session_open_ && sessionMatches(hdr)) {
      std::memcpy(out.session, session_id_, kOtaControlSessionIdBytes);
    }

    out.reason = reason;
    size_t replyLen = 0;
    if (!ota::protocol::encodeOtaControlReplyHeader(out, reply, replyCap)) return 0;
    replyLen = ota::protocol::kOtaControlReplyHeaderSize;
    if (out.dataLen > 0) {
      if (replyLen + out.dataLen > replyCap) return 0;
      std::memcpy(reply + replyLen, pending_reply_data_, out.dataLen);
      replyLen += out.dataLen;
    }
    return replyLen;
  }

  bool isSessionOpen() const { return session_open_; }
  uint32_t activeJobTicket() const { return active_job_ticket_; }

  // Unconditionally tears down any open session/job/challenge state
  // without requiring a matching CLOSE request. This is for a genuine
  // transport-level event (USB connection epoch change / disconnect),
  // NOT a substitute for the CLOSE subcommand's session-matched
  // request/reply handshake -- callers on an actually-still-connected
  // transport must keep using CLOSE. Safe to call even if no session is
  // open (no-op in that case beyond the idempotent resets).
  void forceCloseSession() {
    if (active_job_ticket_ != 0) backend_.cancelJob(active_job_ticket_);
    session_open_ = false;
    active_job_ticket_ = 0;
    resetScratch();
    challenge_valid_ = false;
  }

  static constexpr uint16_t kReasonUnknownSubcommand = 100;
  static constexpr uint16_t kReasonNoSession = 101;
  static constexpr uint16_t kReasonSessionMismatch = 102;
  static constexpr uint16_t kReasonOccupied = 103;
  static constexpr uint16_t kReasonZeroTicket = 104;
  static constexpr uint16_t kReasonForeignTicket = 105;
  static constexpr uint16_t kReasonBadObjectKind = 106;
  static constexpr uint16_t kReasonOverflow = 107;
  static constexpr uint16_t kReasonBadChallengePurpose = 108;
  static constexpr uint16_t kReasonEntropyUnavailable = 109;
  static constexpr uint16_t kReasonNoActiveJob = 110;
  static constexpr uint16_t kReasonScratchFrozen = 111;

private:
  IOtaControlEntropySource& entropy_;
  IOtaControlJobBackend& backend_;

  bool session_open_ = false;
  uint8_t session_id_[kOtaControlSessionIdBytes] = {0};

  uint32_t active_job_ticket_ = 0;
  OtaControlSubcommand active_sub_ = OtaControlSubcommand::Open;
  uint32_t active_fingerprint_ = 0;

  // PUT_FRAGMENT scratch: one bounded typed object at a time, keyed by the
  // currently active job ticket. `scratch_received_` is a per-byte
  // coverage bitmap (NOT a high-water mark): a high-water mark alone
  // treats a single fragment landing at the HIGHEST offset as "complete"
  // even though every byte before it is still zero/stale/never written.
  // `scratch_frozen_` becomes true the instant an uploaded object is
  // handed to beginJob(); no further PUT_FRAGMENT may touch it afterward,
  // whether the job is still running or already finished.
  uint8_t scratch_[kOtaControlScratchCapacity] = {0};
  OtaControlObjectKind scratch_kind_ = OtaControlObjectKind::None;
  size_t scratch_fixed_size_ = 0;
  uint8_t scratch_received_[(kOtaControlScratchCapacity + 7) / 8] = {0};
  bool scratch_frozen_ = false;

  // Fresh single-use CHALLENGE bytes, invalidated by a new CHALLENGE call,
  // CANCEL, CLOSE, or a fresh OPEN (contract: "invalidated on reset/
  // reconnect/timeout").
  uint8_t challenge_[kOtaControlSessionIdBytes] = {0};
  bool challenge_valid_ = false;
  // Which operation (Prepare/Activate) the last-issued challenge was
  // minted for; recorded only via otaControlIsValidChallengePurposeByte()-
  // checked inline payload, never caller-asserted trust -- future
  // Authority binding reads this, the router itself does not yet enforce
  // a match (no Authority adapter wired through this router yet).
  OtaControlSubcommand challenge_purpose_ = OtaControlSubcommand::Open;

  uint8_t pending_reply_data_[kOtaControlMaxDataLen] = {0};

  bool sessionMatches(const OtaControlRequestHeader& hdr) const {
    return session_open_ && std::memcmp(hdr.session, session_id_, kOtaControlSessionIdBytes) == 0;
  }

  // Busy and RejectedChangedRequest are explicitly NONTERMINAL per
  // contract section G: only the changed/conflicting attempt itself is
  // rejected, the original in-flight job (and its ticket/scratch/fp
  // state) must remain exactly as it was, fully resumable by its real
  // owner's next matching request.
  static bool isTerminalStatus(OtaControlStatus st) {
    return st != OtaControlStatus::Ok && st != OtaControlStatus::Pending &&
           st != OtaControlStatus::Busy && st != OtaControlStatus::RejectedChangedRequest;
  }

  void resetScratch() {
    scratch_kind_ = OtaControlObjectKind::None;
    scratch_fixed_size_ = 0;
    std::memset(scratch_received_, 0, sizeof(scratch_received_));
    scratch_frozen_ = false;
  }

  bool scratchByteReceived(size_t byteIndex) const {
    return (scratch_received_[byteIndex / 8] & (1u << (byteIndex % 8))) != 0;
  }
  void scratchMarkByteReceived(size_t byteIndex) {
    scratch_received_[byteIndex / 8] |= static_cast<uint8_t>(1u << (byteIndex % 8));
  }

  bool scratchFullyReceived() const {
    for (size_t i = 0; i < scratch_fixed_size_; ++i) {
      if (!scratchByteReceived(i)) return false;
    }
    return true;
  }

  // Writes `len` bytes at `offset` into the scratch buffer, honoring the
  // "identical retries only" contract: any byte in [offset,offset+len)
  // that was ALREADY received must match the incoming byte exactly, or
  // the whole fragment is rejected WITHOUT mutating a single stored byte
  // (a changed overlap could otherwise quietly corrupt an
  // already-accepted region of the object). Only once every byte in the
  // range is confirmed either unreceived-or-identical does it copy/mark
  // anything.
  bool scratchAcceptFragment(size_t offset, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
      if (scratchByteReceived(offset + i) && scratch_[offset + i] != data[i]) return false;
    }
    for (size_t i = 0; i < len; ++i) {
      scratch_[offset + i] = data[i];
      scratchMarkByteReceived(offset + i);
    }
    return true;
  }

  // Returns true if the caller may proceed to touch active-job state;
  // sets out.status/reason and returns false otherwise. `requireTicket`
  // selects whether a zero ticket is itself rejected (job-bearing subs)
  // or tolerated (Poll/ReadObject reuse the same guard).
  bool admitToActiveJob(const OtaControlRequestHeader& hdr, OtaControlReplyHeader& out,
                         uint16_t& reason) {
    if (!sessionMatches(hdr)) {
      out.status = OtaControlStatus::Denied;
      reason = session_open_ ? kReasonSessionMismatch : kReasonNoSession;
      return false;
    }
    if (hdr.jobTicket == 0) {
      out.status = active_job_ticket_ != 0 ? OtaControlStatus::Busy : OtaControlStatus::Denied;
      reason = kReasonZeroTicket;
      return false;
    }
    if (active_job_ticket_ == 0) {
      // No job has even been started yet -- POLL/READ_OBJECT must never
      // reach the backend for an absent/unstarted job, which the
      // `active_job_ticket_ != 0 && ...` foreign-ticket check below would
      // otherwise silently skip (its guard condition is false when no
      // job exists at all, not just when the ticket matches).
      out.status = OtaControlStatus::Missing;
      reason = kReasonNoActiveJob;
      return false;
    }
    if (hdr.jobTicket != active_job_ticket_) {
      out.status = OtaControlStatus::Denied;
      reason = kReasonForeignTicket;
      return false;
    }
    return true;
  }

  void handleOpen(const OtaControlRequestHeader& hdr, const uint8_t* data, OtaControlReplyHeader& out,
                   uint16_t& reason) {
    if (session_open_) {
      out.status = OtaControlStatus::Busy;
      reason = kReasonOccupied;
      return;
    }
    // Shape (dataLen==0, objectKind==None, etc.) is already enforced by
    // validateOtaControlRequestShape() before dispatch() ever calls this
    // handler -- OPEN carries no payload at all (no host challenge).
    (void)data;
    (void)hdr;
    // Stage into a local buffer first: a failed/unavailable entropy
    // source must never publish a session id at all, partial or
    // otherwise -- no session opens, no state is mutated.
    uint8_t fresh_session[kOtaControlSessionIdBytes];
    if (!entropy_.fillRandom(fresh_session, kOtaControlSessionIdBytes)) {
      out.status = OtaControlStatus::NoCapacity;
      reason = kReasonEntropyUnavailable;
      return;
    }
    std::memcpy(session_id_, fresh_session, kOtaControlSessionIdBytes);
    session_open_ = true;
    active_job_ticket_ = 0;
    resetScratch();
    challenge_valid_ = false;
    std::memcpy(out.session, session_id_, kOtaControlSessionIdBytes);
    out.status = OtaControlStatus::Ok;
  }

  void handleClose(const OtaControlRequestHeader& hdr, OtaControlReplyHeader& out, uint16_t& reason) {
    if (!sessionMatches(hdr)) {
      out.status = OtaControlStatus::Denied;
      reason = session_open_ ? kReasonSessionMismatch : kReasonNoSession;
      return;
    }
    if (active_job_ticket_ != 0) backend_.cancelJob(active_job_ticket_);
    session_open_ = false;
    active_job_ticket_ = 0;
    resetScratch();
    challenge_valid_ = false;
    std::memcpy(out.session, session_id_, kOtaControlSessionIdBytes);
    out.status = OtaControlStatus::Ok;
  }

  void handleCancel(const OtaControlRequestHeader& hdr, OtaControlReplyHeader& out, uint16_t& reason) {
    if (!sessionMatches(hdr)) {
      out.status = OtaControlStatus::Denied;
      reason = session_open_ ? kReasonSessionMismatch : kReasonNoSession;
      return;
    }
    // A nonzero ticket that names a DIFFERENT job than whatever is
    // currently active (including "nothing at all is active") is a
    // foreign/absent cancel request -- it must be refused outright, never
    // silently accepted as a no-op Ok.
    if (hdr.jobTicket != 0 && hdr.jobTicket != active_job_ticket_) {
      out.status = OtaControlStatus::Denied;
      reason = kReasonForeignTicket;
      return;
    }
    if (hdr.jobTicket != 0 && hdr.jobTicket == active_job_ticket_) {
      backend_.cancelJob(active_job_ticket_);
      active_job_ticket_ = 0;
      resetScratch();
    }
    // Per the documented challenge_/challenge_valid_ contract ("invalidated
    // by a new CHALLENGE call, CANCEL, CLOSE, or a fresh OPEN"), a single-
    // use challenge must not survive a cancelled job request.
    challenge_valid_ = false;
    std::memcpy(out.session, session_id_, kOtaControlSessionIdBytes);
    out.status = OtaControlStatus::Ok;
  }

  void handleChallenge(const OtaControlRequestHeader& hdr, const uint8_t* data, OtaControlReplyHeader& out,
                        uint16_t& reason) {
    if (!sessionMatches(hdr)) {
      out.status = OtaControlStatus::Denied;
      reason = session_open_ ? kReasonSessionMismatch : kReasonNoSession;
      return;
    }
    // Shape (objectKind=None, total=dataLen=1, offset=0) is already
    // enforced by validateOtaControlRequestShape() before this handler
    // runs. The single inline payload byte is the target operation's
    // purpose (Prepare=0x24 or Activate=0x25); the BYTE VALUE is semantic
    // admission the router checks here, not raw header shape.
    if (data == nullptr || !ota::protocol::otaControlIsValidChallengePurposeByte(data[0])) {
      out.status = OtaControlStatus::Denied;
      reason = kReasonBadChallengePurpose;
      return;
    }
    // Stage first: a failed/unavailable entropy source must never
    // publish a challenge, partial or otherwise, nor mark one valid.
    uint8_t fresh_challenge[kOtaControlSessionIdBytes];
    if (!entropy_.fillRandom(fresh_challenge, kOtaControlSessionIdBytes)) {
      out.status = OtaControlStatus::NoCapacity;
      reason = kReasonEntropyUnavailable;
      return;
    }
    challenge_purpose_ = static_cast<OtaControlSubcommand>(data[0]);
    std::memcpy(challenge_, fresh_challenge, kOtaControlSessionIdBytes);
    challenge_valid_ = true;
    std::memcpy(out.session, session_id_, kOtaControlSessionIdBytes);
    std::memcpy(pending_reply_data_, challenge_, kOtaControlSessionIdBytes);
    out.dataLen = static_cast<uint8_t>(kOtaControlSessionIdBytes);
    out.total = static_cast<uint32_t>(kOtaControlSessionIdBytes);
    out.status = OtaControlStatus::Ok;
  }

  void handlePutFragment(const OtaControlRequestHeader& hdr, const uint8_t* data,
                          OtaControlReplyHeader& out, uint16_t& reason) {
    if (!sessionMatches(hdr)) {
      out.status = OtaControlStatus::Denied;
      reason = session_open_ ? kReasonSessionMismatch : kReasonNoSession;
      return;
    }
    if (hdr.jobTicket == 0) {
      out.status = OtaControlStatus::Denied;
      reason = kReasonZeroTicket;
      return;
    }
    if (active_job_ticket_ != 0 && hdr.jobTicket != active_job_ticket_) {
      out.status = OtaControlStatus::Denied;
      reason = kReasonForeignTicket;
      return;
    }
    // Once the uploaded object has actually been handed to beginJob(),
    // its input is frozen: a running (or already-finished) job's input
    // bytes must never change out from under it, no matter what ticket
    // the PUT names.
    if (scratch_frozen_) {
      out.status = OtaControlStatus::Denied;
      reason = kReasonScratchFrozen;
      return;
    }
    size_t fixedSize = ota::protocol::otaControlObjectKindFixedSize(hdr.objectKind);
    if (fixedSize == 0 || fixedSize > kOtaControlScratchCapacity || hdr.total != fixedSize) {
      out.status = OtaControlStatus::Denied;
      reason = kReasonBadObjectKind;
      return;
    }
    if (active_job_ticket_ == hdr.jobTicket && scratch_kind_ != OtaControlObjectKind::None &&
        scratch_kind_ != hdr.objectKind) {
      // Changed object kind for an in-flight ticket: leave the scratch
      // untouched, report RejectedChangedRequest rather than silently
      // switching objects mid-upload.
      out.status = OtaControlStatus::RejectedChangedRequest;
      return;
    }
    size_t end;
    if (__builtin_add_overflow(static_cast<size_t>(hdr.offset), static_cast<size_t>(hdr.dataLen), &end) ||
        end > fixedSize) {
      out.status = OtaControlStatus::Denied;
      reason = kReasonOverflow;
      return;
    }
    if (active_job_ticket_ == 0) {
      active_job_ticket_ = hdr.jobTicket;
      resetScratch();
      scratch_kind_ = hdr.objectKind;
      scratch_fixed_size_ = fixedSize;
    }
    // Overlapping-but-IDENTICAL bytes are accepted (harmless retries of
    // an already-received fragment); overlapping-but-DIFFERENT bytes are
    // rejected outright and leave every previously-stored byte untouched
    // -- a changed overlap must never silently corrupt an
    // already-accepted region of the object.
    if (!scratchAcceptFragment(hdr.offset, data, hdr.dataLen)) {
      out.status = OtaControlStatus::RejectedChangedRequest;
      return;
    }
    out.status = OtaControlStatus::Ok;
  }

  void handleJobRequest(const OtaControlRequestHeader& hdr, const uint8_t* data,
                        OtaControlReplyHeader& out, uint16_t& reason) {
    if (!admitToActiveJob(hdr, out, reason)) return;

    // Same active ticket, a DIFFERENT job opcode: this is a changed
    // request on the already-occupied ticket, never a fresh job start --
    // restarting here would silently discard the original job's progress
    // (and its backend-side work) out from under its real owner.
    if (active_job_ticket_ == hdr.jobTicket && active_sub_ != hdr.sub) {
      out.status = OtaControlStatus::RejectedChangedRequest;
      return;
    }

    uint32_t fp = internal::otaControlFnv1a(reinterpret_cast<const uint8_t*>(&hdr.sub), sizeof(hdr.sub), 0);
    uint32_t kindRaw = static_cast<uint32_t>(hdr.objectKind);
    fp = internal::otaControlFnv1a(reinterpret_cast<const uint8_t*>(&kindRaw), sizeof(kindRaw), fp);
    fp = internal::otaControlFnv1a(reinterpret_cast<const uint8_t*>(&hdr.total), sizeof(hdr.total), fp);
    fp = internal::otaControlFnv1a(reinterpret_cast<const uint8_t*>(&hdr.offset), sizeof(hdr.offset), fp);
    if (hdr.dataLen > 0) fp = internal::otaControlFnv1a(data, hdr.dataLen, fp);

    // active_sub_ == hdr.sub is now guaranteed whenever active_job_ticket_
    // == hdr.jobTicket (the mismatched-opcode case returned above), so
    // this reduces to "is this ticket already active at all".
    bool sameTicketAlreadyActive = (active_job_ticket_ == hdr.jobTicket && active_job_ticket_ != 0);

    if (sameTicketAlreadyActive) {
      if (fp != active_fingerprint_) {
        out.status = OtaControlStatus::RejectedChangedRequest;
        return;
      }
      // Same ticket, same request: re-check progress without re-invoking
      // beginJob's side effects.
      OtaControlStatus st = backend_.pollJob(hdr.jobTicket, reason);
      out.status = st;
      if (isTerminalStatus(st)) {
        active_job_ticket_ = 0;
        resetScratch();
      }
      return;
    }

    // New job on this ticket (genuinely idle -- the same-ticket-different-
    // opcode case above already returned without reaching here).
    const uint8_t* input = nullptr;
    size_t inputLen = 0;
    OtaControlObjectKind inputKind = hdr.objectKind;
    if (hdr.objectKind != OtaControlObjectKind::None) {
      if (scratch_kind_ != hdr.objectKind || !scratchFullyReceived()) {
        out.status = OtaControlStatus::Missing; // referenced object never fully uploaded
        return;
      }
      input = scratch_;
      inputLen = scratch_fixed_size_;
    } else if (hdr.dataLen > 0) {
      input = data;
      inputLen = hdr.dataLen;
    }

    active_job_ticket_ = hdr.jobTicket;
    active_sub_ = hdr.sub;
    active_fingerprint_ = fp;
    // Freeze the uploaded object's retained bytes the instant they are
    // handed to the backend -- no later PUT_FRAGMENT for this ticket may
    // alter a running/completed job's already-begun input (see
    // handlePutFragment()'s scratch_frozen_ check).
    if (hdr.objectKind != OtaControlObjectKind::None) scratch_frozen_ = true;
    OtaControlStatus st = backend_.beginJob(hdr.sub, hdr.jobTicket, inputKind, input, inputLen, reason);
    out.status = st;
    if (isTerminalStatus(st)) {
      active_job_ticket_ = 0;
      resetScratch();
    }
  }

  void handlePoll(const OtaControlRequestHeader& hdr, OtaControlReplyHeader& out, uint16_t& reason) {
    if (!admitToActiveJob(hdr, out, reason)) return;
    OtaControlStatus st = backend_.pollJob(hdr.jobTicket, reason);
    out.status = st;
    if (isTerminalStatus(st)) {
      active_job_ticket_ = 0;
      resetScratch();
    }
  }

  void handleReadObject(const OtaControlRequestHeader& hdr, uint8_t* /*reply*/, size_t /*replyCap*/,
                        OtaControlReplyHeader& out, uint16_t& reason) {
    if (!admitToActiveJob(hdr, out, reason)) return;
    uint8_t outLen = 0;
    OtaControlStatus st = backend_.readObject(hdr.jobTicket, hdr.objectKind, hdr.offset,
                                               pending_reply_data_, kOtaControlMaxDataLen, outLen, reason);
    out.status = st;
    if (st == OtaControlStatus::Ok) {
      out.dataLen = outLen;
      out.offset = hdr.offset;
      // Echo the full fixed object length (already validated to equal
      // hdr.total before this handler ever runs) -- total0 previously
      // left the caller unable to tell a real object's size from "no
      // object"/zero-length.
      out.total = hdr.total;
    }
  }
};

} // namespace runtime
} // namespace ota
} // namespace meshcore
