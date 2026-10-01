#pragma once

// Injectable ports consumed (never implemented) by this campaign layer.
// Every side effect that touches the outside world -- sending/receiving
// authenticated frames, persisting durable state, changing the physical
// radio profile, reading the wall clock, reading source image bytes for
// autonomous retransmission, local operator/site consent policy, and
// confirming a healthy post-install boot -- goes through one of these. If
// a port is null/unset, the corresponding operation fails closed; this
// layer never fabricates a positive outcome.
//
// Authentication model: strong authentication/encryption is performed by
// the real Mesh integration port BEFORE a frame ever reaches this layer.
// `AuthenticatedInboundFrame::context` (a PairwiseAuthContext or a
// GroupAuthContext -- see below) is populated by that trusted layer,
// out-of-band from the plaintext wire envelope (see CampaignWire.h) --
// this layer never re-derives identity from wire bytes it decodes
// itself, and it rejects any frame whose `authenticated` flag is false
// before it causes any side effect.

#include <cstdint>
#include <cstddef>
#include <variant>
#include "CampaignCommon.h"
#include "../protocol/OtaWireTypes.h"
#include "../protocol/OtaDescriptor.h"
#include "../runtime/OtaSessionIdentity.h"

namespace meshcore {
namespace ota {
namespace campaign {

// The two verified-identity contexts a real transport integration can
// hand this layer are DISTINCT TYPES, not a combined mutable struct with
// an optional peer field: a Group-scoped decrypt structurally CANNOT
// carry a peer identity, because any holder of the shared group key can
// encrypt/decrypt group traffic, so it can never be trusted to prove
// which single member actually sent a frame. Making this a type-level
// distinction (rather than a runtime flag on a shared struct) means
// there is no field to accidentally read a peer id out of a group
// context -- the compiler enforces it, not a comment.
struct PairwiseAuthContext {
  CampaignPeerId peerId{};
};

// Deliberately has NO peer/controller identity field of any kind. Group
// membership alone establishes only "this frame was encrypted/decrypted
// under the campaign's shared group key", never "which specific member
// sent it" -- consent/lease/cohort-assignment/census-control/abort/
// commit/Installed-receipt decisions must never be able to compile
// against this type for an identity claim.
struct GroupAuthContext {
  uint32_t groupId = 0;
  bool membershipVerified = false;
};

// A fully authenticated inbound frame handed to this layer by the real
// transport integration. `payload`/`payloadLen` is the still-encoded
// campaign envelope (see CampaignWire.h) for this layer to decode; the
// bytes themselves carry no identity claim -- `context` (exactly one of
// PairwiseAuthContext/GroupAuthContext) is the ONLY identity/
// authorization fact this layer may trust.
struct AuthenticatedInboundFrame {
  bool authenticated = false;
  std::variant<PairwiseAuthContext, GroupAuthContext> context{PairwiseAuthContext{}};
  const uint8_t* payload = nullptr;
  size_t payloadLen = 0;

  bool isPairwise() const { return std::holds_alternative<PairwiseAuthContext>(context); }
  bool isGroup() const { return std::holds_alternative<GroupAuthContext>(context); }

  // True only when this frame carries a genuine, fully authenticated
  // PAIRWISE peer identity. False for any Group-scoped frame -- group
  // membership alone never establishes "which specific peer sent this".
  // Every consent/lease/cohort-assignment/census-control/abort/commit/
  // Installed-receipt decision in this layer MUST gate on this, not on
  // `authenticated` alone.
  bool hasAuthenticatedPeer() const { return authenticated && isPairwise(); }

  // Valid ONLY when isPairwise() is true; nullptr for a Group context --
  // there is no peer id to hand back.
  const PairwiseAuthContext* pairwise() const { return std::get_if<PairwiseAuthContext>(&context); }
  // Valid ONLY when isGroup() is true; nullptr for a Pairwise context.
  const GroupAuthContext* group() const { return std::get_if<GroupAuthContext>(&context); }
};

enum class CampaignSendResult : uint8_t {
  Enqueued = 0,
  Backpressure = 1,   // bounded deferred residency: caller must retry later, no busy loop
  BudgetDenied = 2,   // dispatcher owner's airtime/ordinary-reserve budget refused this send
  Rejected = 3,
};

// Destination selector for an outbound authenticated send.
struct CampaignDestination {
  CampaignAuthScope scope = CampaignAuthScope::Pairwise;
  CampaignPeerId peerId{};   // meaningful only for Pairwise
  uint32_t groupId = 0;      // meaningful only for Group
};

class IAuthenticatedTransportPort {
public:
  virtual ~IAuthenticatedTransportPort() = default;

  // Attempts to enqueue an already-encoded campaign envelope for
  // authenticated delivery. Never blocks; a full send queue or a denied
  // airtime budget grant returns Backpressure/BudgetDenied rather than
  // spinning or fabricating success.
  virtual CampaignSendResult trySend(const CampaignDestination& dest,
                                      protocol::OtaAirtimeCategory category,
                                      const uint8_t* frame, size_t frameLen) = 0;

  // Non-blocking poll for the next authenticated inbound frame, if any.
  // Returns false when nothing is pending.
  virtual bool pollInbound(AuthenticatedInboundFrame& out) = 0;

  // TX-COMPLETION EVIDENCE: true only once every previously-enqueued send
  // has actually left the radio (not merely been accepted into a queue).
  // Callers that need to change the RADIO PROFILE ITSELF after sending a
  // frame (e.g. DirectLeaseEngine switching to/from the temporary
  // high-speed profile) MUST poll this to true before applying the
  // profile change -- enqueued-for-send is NOT the same event as
  // actually-transmitted, and switching the profile out from under a
  // still-queued frame would silently corrupt/lose it (or transmit it on
  // the WRONG channel from the still-listening peer's perspective).
  virtual bool txQueueEmpty() const = 0;
};

// Durable persistence for campaign/session/controller-binding/geometry/
// bitmap/replay/checkpoint state, stored OUTSIDE the boot journal by
// design (this layer is boot-floor agnostic). `role`/`slot` let one
// backing store multiplex updater, target-receiver and fleet state.
enum class CampaignPersistRole : uint8_t {
  UpdaterCache = 0,
  TargetReceiver = 1,
  FleetCoordinator = 2,
  DirectLease = 3,
  // Auxiliary, campaign-owned "a locally-authorized repair intentionally
  // erased the main TargetReceiver record" fact -- see
  // acknowledgeUnsafeReloadAndReset()/reload(). This is NOT an authority
  // on whether the device was ever commissioned/used: that genuine fact
  // can only come from ICampaignCommissioningProvenancePort (a real
  // factory/security-provisioned backing, positively bound to device
  // identity -- see CampaignCommissioningState below), never from this
  // record's presence/absence. This role exists only so that a
  // subsequent reload() observing a Missing main record on an
  // already-Used device can distinguish "I, this campaign layer,
  // deliberately erased my own record via an authorized repair" from
  // unexplained data loss -- it is consulted, never treated alone as
  // proof of anything about commissioning.
  TargetRepairAuthorization = 4,
};

// Tri-state result of reading independent, positively-verified
// commissioning/factory-security provenance for THIS device -- see
// ICampaignCommissioningProvenancePort. `Unknown` is the safe default:
// it is returned whenever no real backing is wired, the backing's own
// read fails/is corrupt, or (for a real backing) the read does not
// positively bind to this device's own identity. It is NEVER inferred
// from the ABSENCE of some other record (that would be exactly the
// "blank heuristic" this port exists to avoid) -- a genuine `Virgin` or
// `Used` result must be a POSITIVE decode of real, identity-bound
// factory/security facts.
enum class CampaignCommissioningState : uint8_t {
  Unknown = 0,  // safe default: no real backing, unreadable, or identity mismatch -- MUST default-deny
  Virgin = 1,   // positively verified: this device has never been commissioned/used
  Used = 2,     // positively verified: this device has been commissioned/used before
};

struct CampaignCommissioningProvenanceResult {
  CampaignCommissioningState state = CampaignCommissioningState::Unknown;
};

// Result of an attempted Virgin->Used commissioning transition. Mirrors
// CampaignSaveResult's tri-state discipline: a transition attempt may
// physically land bytes but fail to confirm them, and that MUST NOT be
// conflated with either a clean success or a clean pre-mutation refusal.
enum class CampaignMarkUsedResult : uint8_t {
  Rejected = 0,   // refused before any mutation (e.g. Unknown provenance): safe to retry later
  Confirmed = 1,  // durably confirmed Used (either just transitioned, or already Used -- idempotent)
  Uncertain = 2,  // may have mutated durable bytes but could not confirm: caller must freeze
};

// Injectable, independent backing for genuinely positive commissioning/
// factory-security provenance. This layer deliberately does NOT invent
// the final shared security schema (a real implementation is expected to
// be backed by actual factory-provisioned, identity-bound security
// material -- e.g. a reserved flash bank tail -- owned by a separate,
// dedicated security/provisioning workstream); it only defines the
// narrow, safely-defaulted abstract contract this layer needs.
//
// The base class below IS the safe, concrete default: it always returns
// Unknown/Rejected. This is intentional and MUST be usable as-is (no
// override required) wherever a real hardware-bound implementation is
// not yet wired -- until a genuine implementation is supplied, this
// layer can never conclude Virgin, and can never transition a device to
// Used, which is the correct, conservative behavior for unprovisioned
// integration.
class ICampaignCommissioningProvenancePort {
public:
  virtual ~ICampaignCommissioningProvenancePort() = default;

  // Reads the current, independently-persisted commissioning state.
  // Default (safe fallback, no real backing): always Unknown.
  virtual CampaignCommissioningProvenanceResult readCommissioningProvenance() {
    return CampaignCommissioningProvenanceResult{};
  }

  // Durably transitions a genuinely-Virgin device to Used, exactly once,
  // as the very FIRST durable step of a new admission (strictly before
  // any staging/main-record mutation) -- idempotent if already Used.
  // Default (safe fallback, no real backing): always Rejected, so no
  // admission can ever proceed until a real backing is wired.
  virtual CampaignMarkUsedResult markUsedIfCurrentlyVirgin() { return CampaignMarkUsedResult::Rejected; }
};

// Result of a persistence load attempt. Distinguishes "nothing was ever
// saved" (safe to start fresh) from "a record existed but could not be
// trusted" (Corrupt: failed the backing store's own integrity check) or
// "the read itself failed" (IoError: e.g. device/bus error) -- callers
// MUST NOT treat Corrupt/IoError the same as Missing. Silently falling
// back to a fresh/blank in-memory state on Corrupt/IoError would let a
// corrupted or faulted storage device silently reset replay/authorization
// state that a real persisted record was protecting.
enum class CampaignLoadResult : uint8_t {
  Missing = 0,
  Ok = 1,
  Corrupt = 2,
  IoError = 3,
};

// Result of a persistence save attempt. A tri-state result is REQUIRED
// because a real backing store's readback/ack step can fail AFTER the
// underlying bytes have already been physically written (e.g. write
// succeeds, verification read or a durability barrier then fails, or
// power is lost between the write and the ack) -- "did the write
// happen" and "could we confirm the write happened" are NOT the same
// question, and conflating them into a single bool is unsafe:
//   - Saved: the write is durably confirmed (write + readback/ack, per
//     the same discipline as StorageManager::writeAndVerifyChunk). The
//     caller MAY advance in-memory ack/progress state to match exactly
//     what was just persisted.
//   - RejectedBeforeMutation: the attempt was refused BEFORE any bytes
//     were written (e.g. capacity/validation failure at the storage
//     layer) -- the durable record is PROVABLY unchanged. The caller
//     MUST NOT advance any in-memory ack/progress state.
//   - Uncertain: a write was attempted and MAY have altered the durable
//     bytes, but the port could not confirm success (e.g. readback/ack
//     failed, or power was lost mid-operation). The caller MUST NOT
//     advance in-memory state to the new (possibly-not-actually-durable)
//     candidate, but likewise MUST NOT keep trusting/operating on the
//     old in-memory state as if the attempt never happened -- the durable
//     truth is now unknown until a fresh load() authoritatively resolves
//     it. Concretely: no ACK/progress, freeze further mutation of this
//     record (refuse a new/competing session or controller) until an
//     explicit reload() reconstructs state from whatever is ACTUALLY
//     durable.
enum class CampaignSaveResult : uint8_t {
  Saved = 0,
  RejectedBeforeMutation = 1,
  Uncertain = 2,
};

class ICampaignPersistencePort {
public:
  virtual ~ICampaignPersistencePort() = default;

  // Durably stores exactly `len` bytes for `role`. See CampaignSaveResult:
  // Saved/RejectedBeforeMutation/Uncertain are NOT interchangeable
  // outcomes for the caller -- in particular, a non-Saved result does NOT
  // guarantee "this mutation did not happen" (see Uncertain above).
  virtual CampaignSaveResult save(CampaignPersistRole role, const uint8_t* data, size_t len) = 0;

  // Loads previously saved bytes for `role` into `out` (capacity `cap`).
  // See CampaignLoadResult: Missing/Ok/Corrupt/IoError are NOT
  // interchangeable outcomes for the caller.
  virtual CampaignLoadResult load(CampaignPersistRole role, uint8_t* out, size_t cap, size_t& outLen) = 0;

  // Erases the record, e.g. after a terminal Complete/Failed/Aborted
  // outcome that should not be resumed, or as part of a deliberate
  // corrupt-record repair. Returns true only once the erase is DURABLY
  // CONFIRMED (the record is now genuinely absent/unreadable-as-valid);
  // false if the erase attempt itself could not be confirmed (e.g. the
  // confirming readback failed). A caller MUST NOT treat a false result
  // as "safe to now trust a blank state" -- an unconfirmed erase leaves
  // the true durable content unknown, so any guard that was blocking
  // admission on the old (possibly still-present) record must stay
  // latched until a subsequent load() authoritatively resolves it.
  virtual bool erase(CampaignPersistRole role) = 0;
};

enum class CampaignRadioProfile : uint8_t {
  Normal = 0,       // lab default: 907.525 MHz, BW 62.5 kHz, SF7, CR5
  NormalAlternate = 1, // 908.525 MHz fallback, same BW/SF/CR
  DirectHighSpeed = 2, // different allowed frequency, SF5, BW250kHz, CR5
};

struct CampaignRadioProfileParams {
  CampaignRadioProfile profile = CampaignRadioProfile::Normal;
  float freqMhz = 0.0f;
  float bandwidthKhz = 0.0f;
  uint8_t spreadingFactor = 0;
  uint8_t codingRate = 0;
};

// Applied/queried by the direct-mode lease engine. The concrete radio
// integration is responsible for physically applying the profile and for
// blocking ordinary transmit while a non-Normal profile is active; this
// port only reports/requests, it never touches hardware directly.
//
// `normalProfileParams()`/`isFrequencyBandApproved()` exist so profile
// validation is a BOARD/REGION policy query, never a value hardcoded into
// this portable core: the currently active normal frequency (whichever of
// 907.525/908.525/other the board is actually configured with right now)
// is the only frequency a direct-mode request must differ from, and the
// approved-band bounds are whatever the concrete SX1262 board integration
// actually supports -- not an arbitrary 150..2500 MHz guess.
class IRadioProfilePort {
public:
  virtual ~IRadioProfilePort() = default;

  virtual bool applyProfile(const CampaignRadioProfileParams& params) = 0;
  virtual bool restoreNormalProfile() = 0;
  virtual CampaignRadioProfile currentProfile() const = 0;
  virtual CampaignRadioProfileParams normalProfileParams() const = 0;
  virtual bool isFrequencyBandApproved(float freqMhz) const = 0;
};

class IClockPort {
public:
  virtual ~IClockPort() = default;
  virtual uint32_t nowMs() const = 0;
};

// Wrap-safe "has at least `deltaMs` elapsed since `startMs`" per 32-bit
// millisecond clock arithmetic (mirrors the wrap-safe discipline used
// elsewhere in this codebase, reimplemented locally so this module stays
// self-contained).
inline bool campaignElapsedAtLeast(uint32_t nowMs, uint32_t startMs, uint32_t deltaMs) {
  return static_cast<uint32_t>(nowMs - startMs) >= deltaMs;
}

// Autonomous paced image reader used by the updater to keep transmitting a
// cached image after the host has disconnected, and by the direct-mode
// high-speed path to source chunk bytes. Deliberately a NARROW read-only
// interface: two DISTINCT instances are used by the updater (see
// UpdaterCampaignEngine) -- one sourcing bytes from the still-connected
// host during cacheNextChunk(), a completely separate one reading back
// the SEALED local cache during tickTransmit() -- so a host source that is
// no longer reachable after disconnect can never be silently substituted
// with stale/wrong bytes for autonomous retransmission.
class IImageReaderPort {
public:
  virtual ~IImageReaderPort() = default;

  // Reads exactly `len` bytes starting at byte `offset` into `out`.
  // Returns false on any short/failed read -- callers must never send a
  // short/garbage chunk on a false return.
  virtual bool readAt(uint64_t offset, uint8_t* out, size_t len) = 0;
};

// Bound healthy-boot evidence: proof that the CURRENTLY RUNNING image is
// the exact one this session/descriptor describes, not merely "some boot
// happened". `bootedImageHash`/`bootedSession`/`bootedSecurityCounter` are
// independently compared by the caller against the descriptor/session
// actually being confirmed -- a bald `true` with no binding can never
// prove "this exact new image" per the required install-claim discipline.
struct CampaignBootEvidence {
  bool healthyBootConfirmed = false;
  uint8_t bootedImageHash[protocol::kOtaSha256Size] = {};
  runtime::OtaSessionId bootedSession{};
  uint32_t bootedSecurityCounter = 0;
};

// Queried by the target receiver before it may ever report status
// `Installed`. A staged-and-committed image is only "InstalledPending"
// until this reports bound evidence matching the exact descriptor/session
// being confirmed; the target never mutates this itself and never writes
// any security-counter floor -- floor advance is the bootloader's job,
// this port is read-only from the core's perspective.
class IBootEvidencePort {
public:
  virtual ~IBootEvidencePort() = default;
  virtual CampaignBootEvidence queryBootEvidence() const = 0;
};

// Local site/operator consent policy -- DISTINCT from pairwise transport
// authentication. An authenticated, correctly-signed, Pairwise-scoped
// ConsentRequest from the bound controller is necessary but NOT
// sufficient: the local integration may still refuse consent for site
// policy reasons (maintenance window, local lockout switch, role/variant
// mismatch policy, etc.). This layer never treats "transport says the
// sender is who they claim" as equivalent to "local policy approves this
// exact update".
class IConsentPolicyPort {
public:
  virtual ~IConsentPolicyPort() = default;
  virtual bool isConsentPolicyApproved(const CampaignPeerId& controller,
                                        const protocol::OtaDescriptor& descriptor) const = 0;
};

// Local site/board policy gate for GRANTING a direct high-speed lease --
// DISTINCT from pairwise transport authentication. A correctly-signed,
// authenticated Pairwise Request from a genuine peer is necessary but NOT
// sufficient to force this node off its normal operating frequency: the
// local integration may still refuse (role/variant policy, a concurrent
// higher-priority radio duty, a local lockout, etc.). Pairwise
// authentication alone can never compel a node to leave its normal
// profile without this local approval.
class ILeaseGrantPolicyPort {
public:
  virtual ~ILeaseGrantPolicyPort() = default;
  virtual bool approveLeaseGrant(const CampaignPeerId& requester,
                                  const CampaignRadioProfileParams& requested) const = 0;
};

// Marker/narrow interface: an implementation that can ONLY cache image
// bytes and can NEVER install or advance any boot/install floor. This is
// intentionally a DIFFERENT type from runtime::IOtaStagingSink (which a
// real install-capable target implementation may also satisfy) so the
// updater/cache-only role can never be accidentally constructed against
// an install-capable sink: its constructor only accepts this type.
class IOtaCacheOnlySink {
public:
  enum class Result : uint8_t { Ok = 0, Rejected = 1, IoError = 2 };

  virtual ~IOtaCacheOnlySink() = default;
  virtual Result beginCache(const protocol::OtaDescriptor& descriptor) = 0;
  virtual Result writeChunk(uint64_t offset, const uint8_t* data, size_t len) = 0;
  // Rehashes/finalizes the cache against the descriptor. This is a CACHE
  // seal, never an install commit -- no boot/install floor is touched.
  virtual Result sealCache() = 0;
  // Reads back previously cached bytes (used by the updater's post-seal
  // autonomous retransmission path via a dedicated sealed-cache reader
  // wrapper, not the host-side image reader).
  virtual bool readCachedAt(uint64_t offset, uint8_t* out, size_t len) = 0;
  virtual void abort() = 0;
};

// Narrow, campaign-owned resume hook for a REAL install-capable staging
// sink (runtime::IOtaStagingSink) after a reboot. This layer never
// assumes a plain beginSession() call is safe to reissue on an
// already-in-flight session: a real production sink may legitimately
// treat beginSession() as "start brand new", erasing whatever was
// previously durably written -- calling it again purely to "resume"
// would silently discard legitimately-received bytes. A production FW
// integration that wants reboot-resume to actually preserve progress
// MUST provide an adapter implementing this narrow port, bridging to
// whatever its concrete sink's real non-destructive reattachment
// mechanism is; this campaign layer only ever calls resumeSession(),
// never beginSession(), when reloading a Receiving/Verifying record.
// Optional: TargetReceiverEngine works without one bound (existing
// callers are unaffected), but then treats a mid-transfer persisted
// record as reloadUnsafe_ rather than silently resuming without any
// guarantee the sink itself agrees a resumable session exists.
class IOtaStagingResumePort {
public:
  virtual ~IOtaStagingResumePort() = default;

  // Reattaches to a previously-begun, not-yet-committed/aborted staging
  // session matching `descriptor`, preserving every previously durably
  // written byte untouched. Returns false if the underlying sink has no
  // such resumable session (never begun, or already committed/aborted,
  // or the descriptor no longer matches what that sink has in progress)
  // -- the caller must NOT then fall back to beginSession(), which could
  // erase real progress.
  virtual bool resumeSession(const protocol::OtaDescriptor& descriptor) = 0;
};

} // namespace campaign
} // namespace ota
} // namespace meshcore
