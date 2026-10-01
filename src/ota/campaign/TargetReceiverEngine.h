#pragma once

// Target receiver engine: durable, resumable single-target OTA transfer
// receiver used by directed and direct-mode transfers, and by each fleet
// member's pairwise leg of a background campaign (with GROUP-scoped bulk
// chunk/repair delivery allowed once a controller/group binding exists --
// lease/abort/install/consent remain Pairwise-only regardless).
//
// Durability: every accepted mutation is committed through a single
// versioned, magic+CRC32-protected persisted record BEFORE the in-memory
// bitmap/status/replay-watermark is advanced. If the underlying save
// fails (power cut, IO error, etc.) this engine returns false with
// CampaignRefusalReason::PersistenceFailed and leaves in-memory state
// UNCHANGED -- it never reports a durable ACK that did not actually
// happen. reload() independently re-validates magic/version/CRC and
// bounds-checks the persisted chunk count against the real bitmap
// capacity BEFORE ever indexing into the bitmap, so a corrupt or hostile
// persisted record can never cause an out-of-bounds access.
//
// Authorization: consent/verify/commit/abort require a Pairwise-scoped,
// controller-bound authenticated context. Once a controller/group binding
// exists, Chunk/MissingRange traffic may ALSO arrive Group-scoped (for
// background multicast/repair) as long as group membership is verified
// and the group id matches the one bound at consent time -- group
// membership never authorizes the pairwise control actions.
//
// Install claim: a fully verified, committed cache is reported
// `InstalledPending`, never `Installed`, until IBootEvidencePort reports
// bound evidence (exact image hash + session + counter) matching this
// descriptor/session. This engine never advances any security-counter
// floor itself -- that is the bootloader's job.

#include <cstdint>
#include <cstddef>
#include <cstring>

#include "CampaignCommon.h"
#include "CampaignPorts.h"
#include "CampaignWire.h"
#include "../protocol/OtaDescriptor.h"
#include "../protocol/OtaMessages.h"
#include "../protocol/OtaByteStream.h"
#include "../runtime/OtaGeometry.h"
#include "../runtime/OtaBitmap.h"
#include "../runtime/OtaReceiverStateMachine.h"
#include "../runtime/OtaTrustInterfaces.h"
#include "../storage/Crc32.h"
#include "../trust/Ed25519SignatureVerifier.h"

namespace meshcore {
namespace ota {
namespace campaign {

enum class TargetStatus : uint8_t {
  Idle = 0,
  AwaitingDescriptor,
  Receiving,
  Verifying,
  InstalledPending, // committed cache, boot evidence not yet confirmed
  Installed,        // committed cache AND healthy-confirmed boot evidence
  Failed,
  Aborted,
};

inline constexpr uint8_t kTargetStatusMax = static_cast<uint8_t>(TargetStatus::Aborted);

inline constexpr size_t kCampaignBitmapByteCapacity = (runtime::kOtaMaxChunkCount + 7) / 8; // 692 bytes

inline constexpr uint32_t kCampaignTargetPersistMagic = 0x54415243u; // "TARC"
inline constexpr uint16_t kCampaignTargetPersistVersion = 5;
inline constexpr uint16_t kCampaignTargetPersistReserved = 0; // MUST decode as exactly 0 (future flag/extension room)

// In-memory representation of the durable target-receiver record. This
// struct is NEVER persisted verbatim (no memcpy(&struct)/sizeof(struct)
// against the backing store) -- native layout is ABI/padding/endian
// dependent (compiler, struct-packing, and host-vs-target endianness can
// all silently vary), so a byte-for-byte reload on a DIFFERENT process/
// build (a genuine "after reboot" scenario, not just the same still-
// running instance) could misparse a record written by another build.
// encodeCampaignTargetPersistedState()/decodeCampaignTargetPersistedState()
// below (see) are the ONLY sanctioned persistence codec: an explicit,
// versioned, fixed-width, field-by-field big-endian encoding (same
// discipline as protocol::encodeOtaDescriptorCanonical), independent of
// any compiler's struct layout. Two freshly-constructed DTO instances on
// two different processes/builds, given only the encoded bytes, decode
// to bit-identical field values -- no offsetof/sizeof/struct-padding
// knowledge of either process's compiler is ever involved.
//
// Version 5: adds an explicit header `reserved` (must decode as exactly
// 0, reserved for a future flags/extension field without breaking older
// parsers) and a self-describing `bodyLength` field (the exact byte
// count of the body between the header and the trailing CRC32) alongside
// the already-versioned magic/version -- the SAME header discipline
// CampaignEnvelopeHeader already uses for wire frames (ns/version/...
// /payloadLength), applied here to the durable persisted record. Decode
// independently validates: header magic/version/reserved/bodyLength all
// exactly as expected; `bound`/`everBound` decode as strictly 0 or 1 (any
// other byte value is a corrupt record, not a "truthy" flag); a bound
// record's `signatureLen` must be the network's own Ed25519 signature
// size (Ed25519SignatureVerifier::kSignatureBytes = 64), never merely
// "not larger than the buffer"; and any bitmap bit at or beyond the
// persisted `chunkCount` is validated to be exactly 0 (a corrupt/hostile
// record cannot smuggle "phantom" received-chunk bits past the declared
// geometry).
//
// Version 4's descriptor-canonical-59+signature-bytes persistence (rather
// than a raw native-struct memcpy) and geometry-recompute-on-reload
// discipline are unchanged; there is still no stored `geometry` field at
// all, since geometry is a pure deterministic function of
// descriptor.exactSizeBytes.
struct CampaignTargetPersistedState {
  uint32_t magic = kCampaignTargetPersistMagic;
  uint16_t version = kCampaignTargetPersistVersion;
  runtime::OtaSessionId session{};
  uint8_t controllerId[32] = {};
  uint32_t groupId = 0;
  uint8_t descriptorCanonical[protocol::kOtaDescriptorCanonicalSize] = {};
  uint8_t signature[64] = {};
  uint8_t signatureLen = 0;
  uint8_t phase = static_cast<uint8_t>(TargetStatus::Idle);
  uint32_t lastFrameSeq = 0;
  // Bounded anti-replay window bitmask: bit i set means
  // (lastFrameSeq - i) has already been seen/consumed, for
  // i in [0, kCampaignReplayWindowSize). Persisted so a reboot mid-
  // transfer cannot be replay-attacked by resending a frame this engine
  // had already accepted just before the reboot.
  uint32_t replayWindowMask = 0;
  uint32_t chunkCount = 0;
  uint8_t bound = 0;    // 1 once a controller binding is currently active
  uint8_t everBound = 0; // 1 once ANY session has ever been durably bound (replay floor)
  uint8_t bitmap[kCampaignBitmapByteCapacity] = {};
  uint32_t crc32 = 0;
};

// Explicit fixed-width size of the record BODY (everything between the
// 10-byte header [magic(4)+version(2)+reserved(2)+bodyLength(2)] and the
// trailing crc32(4)): campaignId(4)+sessionId(4)+attemptId(2)+
// controllerId(32)+groupId(4)+descriptorCanonical(59)+signature(64)+
// signatureLen(1)+phase(1)+lastFrameSeq(4)+replayWindowMask(4)+
// chunkCount(4)+bound(1)+everBound(1)+bitmap(kCampaignBitmapByteCapacity).
// This is the exact value the header's own `bodyLength` field must equal
// -- an explicit, self-describing, redundant-with-CRC structural check.
inline constexpr size_t kCampaignTargetPersistBodySize =
    4 + 4 + 2 + 32 + 4 + protocol::kOtaDescriptorCanonicalSize + 64 + 1 + 1 + 4 + 4 + 4 + 1 + 1 +
    kCampaignBitmapByteCapacity;

// Explicit fixed-width wire size of the FULL encoded record: 10-byte
// header + body + 4-byte trailing crc32.
inline constexpr size_t kCampaignTargetPersistEncodedSize = 4 + 2 + 2 + 2 + kCampaignTargetPersistBodySize + 4;

// Encodes every durable field individually via OtaBoundedWriter (never a
// memcpy of the struct) in a fixed, versioned big-endian byte order, then
// appends a CRC32 covering every byte written so far (header + body).
// Returns false (no partial bytes usable, `dst` never dereferenced) if
// `dst` is null or `dstCapacity` is too small.
inline bool encodeCampaignTargetPersistedState(const CampaignTargetPersistedState& s, uint8_t* dst,
                                                size_t dstCapacity, size_t& outLen) {
  if (dst == nullptr) return false; // never dereference a null destination, regardless of dstCapacity
  if (dstCapacity < kCampaignTargetPersistEncodedSize) return false;
  protocol::OtaBoundedWriter w(dst, dstCapacity);
  bool ok = w.putU32(s.magic) && w.putU16(s.version) && w.putU16(kCampaignTargetPersistReserved) &&
            w.putU16(static_cast<uint16_t>(kCampaignTargetPersistBodySize)) &&
            w.putU32(s.session.campaignId) && w.putU32(s.session.sessionId) && w.putU16(s.session.attemptId) &&
            w.putBytes(s.controllerId, sizeof(s.controllerId)) && w.putU32(s.groupId) &&
            w.putBytes(s.descriptorCanonical, sizeof(s.descriptorCanonical)) &&
            w.putBytes(s.signature, sizeof(s.signature)) && w.putU8(s.signatureLen) && w.putU8(s.phase) &&
            w.putU32(s.lastFrameSeq) && w.putU32(s.replayWindowMask) && w.putU32(s.chunkCount) &&
            w.putU8(s.bound) && w.putU8(s.everBound) && w.putBytes(s.bitmap, sizeof(s.bitmap));
  if (!ok) return false;
  const uint32_t crc = ::ota::storage::Crc32::computeFinalized(dst, w.size());
  if (!w.putU32(crc)) return false;
  outLen = w.size();
  return true;
}

// Decodes/validates a record produced by encodeCampaignTargetPersistedState
// above: exact-length check, CRC32 re-verification over the bytes actually
// read, explicit header (magic/version/reserved/bodyLength) validation,
// then field-by-field decode via OtaBoundedReader (never a
// reinterpret/memcpy onto a native struct) with strict structural
// invariants enforced on the decoded fields themselves: `bound`/
// `everBound` must each be exactly 0 or 1; a record with `bound == 1`
// must carry EXACTLY a 64-byte signature (Ed25519's own fixed size, via
// Ed25519SignatureVerifier::kSignatureBytes -- reusing the existing
// production constant, never a new/second definition of it); and every
// bitmap bit at or beyond the decoded `chunkCount` must be exactly 0 (a
// corrupt/hostile record cannot claim a chunk index the declared geometry
// does not even contain). Returns false on any violation (including a
// null `src`, never dereferenced), leaving `out` in an unspecified state
// the caller must not trust.
inline bool decodeCampaignTargetPersistedState(const uint8_t* src, size_t srcLen, CampaignTargetPersistedState& out) {
  if (src == nullptr) return false; // never dereference a null source, regardless of srcLen
  if (srcLen != kCampaignTargetPersistEncodedSize) return false;
  const size_t crcCoveredLen = srcLen - 4;
  const uint32_t expectedCrc = ::ota::storage::Crc32::computeFinalized(src, crcCoveredLen);
  uint32_t storedCrc = 0;
  storedCrc |= static_cast<uint32_t>(src[crcCoveredLen + 0]) << 24;
  storedCrc |= static_cast<uint32_t>(src[crcCoveredLen + 1]) << 16;
  storedCrc |= static_cast<uint32_t>(src[crcCoveredLen + 2]) << 8;
  storedCrc |= static_cast<uint32_t>(src[crcCoveredLen + 3]);
  if (storedCrc != expectedCrc) return false;

  protocol::OtaBoundedReader r(src, srcLen);
  uint16_t reserved = 0;
  uint16_t bodyLength = 0;
  if (!(r.getU32(out.magic) && r.getU16(out.version) && r.getU16(reserved) && r.getU16(bodyLength))) return false;
  if (out.magic != kCampaignTargetPersistMagic) return false;
  if (out.version != kCampaignTargetPersistVersion) return false;
  if (reserved != kCampaignTargetPersistReserved) return false;
  if (bodyLength != static_cast<uint16_t>(kCampaignTargetPersistBodySize)) return false;

  uint32_t crcIgnored = 0;
  bool ok = r.getU32(out.session.campaignId) && r.getU32(out.session.sessionId) && r.getU16(out.session.attemptId) &&
            r.getBytes(out.controllerId, sizeof(out.controllerId)) && r.getU32(out.groupId) &&
            r.getBytes(out.descriptorCanonical, sizeof(out.descriptorCanonical)) &&
            r.getBytes(out.signature, sizeof(out.signature)) && r.getU8(out.signatureLen) && r.getU8(out.phase) &&
            r.getU32(out.lastFrameSeq) && r.getU32(out.replayWindowMask) && r.getU32(out.chunkCount) &&
            r.getU8(out.bound) && r.getU8(out.everBound) && r.getBytes(out.bitmap, sizeof(out.bitmap)) &&
            r.getU32(crcIgnored);
  if (!ok) return false;

  if (out.bound > 1 || out.everBound > 1) return false; // strict boolean flag, never any other byte value
  if (out.bound == 1 && out.signatureLen != ::ota::trust::Ed25519SignatureVerifier::kSignatureBytes) return false;
  if (out.chunkCount > runtime::kOtaMaxChunkCount) return false; // must bounds-check before the tail scan below
  for (uint32_t bit = out.chunkCount; bit < kCampaignBitmapByteCapacity * 8; ++bit) {
    if ((out.bitmap[bit / 8] & (1u << (bit % 8))) != 0) return false; // phantom bit beyond declared geometry
  }
  return true;
}

// --- Repair-authorization record --------------------------------------
//
// A tiny, independent, explicitly-versioned durable auxiliary record
// (separate from the main 891-byte CampaignTargetPersistedState record)
// whose SOLE job is to let a FUTURE reload() distinguish "the main
// record is Missing because I, this campaign layer, deliberately erased
// it via a locally-authorized acknowledgeUnsafeReloadAndReset() repair"
// from unexplained data loss. It carries NO authority over whether this
// device was ever commissioned/used -- that genuine fact can ONLY come
// from ICampaignCommissioningProvenancePort's positively-verified,
// identity-bound result (see CampaignPorts.h); this record's
// presence/absence alone must NEVER be treated as proof of anything
// about commissioning (that would be exactly the "blank heuristic"
// this two-fact split exists to avoid). It is written ONLY as part of a
// confirmed repair for an already-Used device, immediately after the
// main record's own erase is confirmed.
//
// SINGLE-USE / bounded lifetime: this record authorizes recovering from
// exactly ONE specific repair -- it is NOT a standing "this device may
// always resume fresh" grant. handleConsentRequest() retires (erases)
// it unconditionally, strictly before any other durable step, at the
// start of every subsequent admission. That guarantees an OLD grant can
// never survive to (mis)authorize the loss of a LATER admitted
// campaign's main record: by the time a later campaign's record could
// even exist, the grant that predates it is already gone. A device that
// is repaired again after that later admission gets a freshly-written
// grant of its own at that later repair time.
inline constexpr uint32_t kCampaignRepairAuthMagic = 0x52504152u;  // "RPAR"
inline constexpr uint16_t kCampaignRepairAuthVersion = 1;
inline constexpr uint8_t kCampaignRepairAuthConfirmedMarker = 0xC7;
inline constexpr size_t kCampaignRepairAuthEncodedSize = 4 + 2 + 1 + 1 + 4;  // magic+version+marker+reserved+crc32

inline bool encodeCampaignRepairAuthorization(uint8_t* dst, size_t dstCapacity, size_t& outLen) {
  if (dst == nullptr) return false;
  if (dstCapacity < kCampaignRepairAuthEncodedSize) return false;
  protocol::OtaBoundedWriter w(dst, dstCapacity);
  bool ok = w.putU32(kCampaignRepairAuthMagic) && w.putU16(kCampaignRepairAuthVersion) &&
            w.putU8(kCampaignRepairAuthConfirmedMarker) && w.putU8(0);
  if (!ok) return false;
  const uint32_t crc = ::ota::storage::Crc32::computeFinalized(dst, w.size());
  if (!w.putU32(crc)) return false;
  outLen = w.size();
  return true;
}

// Returns true only for a structurally exact, CRC-valid, correctly
// versioned record carrying the single valid "repair confirmed" marker
// value. Any other outcome (wrong length/magic/version/reserved/CRC/
// marker) is Unknown, and callers must treat a Missing main record as
// UNEXPLAINED (default-deny) rather than an authorized repair.
inline bool decodeCampaignRepairAuthorizationConfirmed(const uint8_t* src, size_t srcLen) {
  if (src == nullptr) return false;
  if (srcLen != kCampaignRepairAuthEncodedSize) return false;
  const size_t crcCoveredLen = srcLen - 4;
  const uint32_t expectedCrc = ::ota::storage::Crc32::computeFinalized(src, crcCoveredLen);
  uint32_t storedCrc = 0;
  storedCrc |= static_cast<uint32_t>(src[crcCoveredLen + 0]) << 24;
  storedCrc |= static_cast<uint32_t>(src[crcCoveredLen + 1]) << 16;
  storedCrc |= static_cast<uint32_t>(src[crcCoveredLen + 2]) << 8;
  storedCrc |= static_cast<uint32_t>(src[crcCoveredLen + 3]);
  if (storedCrc != expectedCrc) return false;

  protocol::OtaBoundedReader r(src, srcLen);
  uint32_t magic = 0;
  uint16_t version = 0;
  uint8_t marker = 0;
  uint8_t reserved = 0;
  if (!(r.getU32(magic) && r.getU16(version) && r.getU8(marker) && r.getU8(reserved))) return false;
  if (magic != kCampaignRepairAuthMagic || version != kCampaignRepairAuthVersion) return false;
  if (reserved != 0) return false;
  return marker == kCampaignRepairAuthConfirmedMarker;
}

// Bounded lifetime for an UNADMITTED (pre-consent, still-reassembling)
// descriptor-fragment attempt: if no fragment/ConsentRequest activity for
// this exact pending ticket has been seen for this long, the single
// pending-reassembly RAM slot is considered abandoned and may be
// reclaimed by a genuinely different/competing ConsentRequest. This
// bound exists ONLY to reclaim a stalled/abandoned attempt's RAM -- any
// ticket that keeps making real progress (a fresh ConsentRequest retry
// for the SAME ticket, or a new fragment) refreshes the activity clock
// and is never erased by this expiry while still actively in flight. It
// has no bearing whatsoever on an already-ADMITTED (bound_) transfer,
// which is durably persisted and governed entirely by
// handleConsentRequest()'s own ForeignController/ForeignSession guards.
inline constexpr uint32_t kCampaignPendingConsentExpiryMs = 30000;

class TargetReceiverEngine {
public:
  TargetReceiverEngine(runtime::IOtaTrustProvider& trust, runtime::IOtaStagingSink& staging,
                        ICampaignPersistencePort& persistence, IBootEvidencePort& bootEvidence,
                        IConsentPolicyPort& consentPolicy,
                        ICampaignCommissioningProvenancePort& commissioningProvenance)
      : trust_(trust), staging_(staging), persistence_(persistence), bootEvidence_(bootEvidence),
        consentPolicy_(consentPolicy), commissioningProvenance_(commissioningProvenance) {}

  // Reloads durable state after a reboot. Safe to call even if nothing was
  // ever persisted (leaves the engine Idle). Never fabricates progress
  // that was not actually durably recorded, and never trusts any field of
  // a corrupt/undersized/bad-magic/bad-CRC record enough to touch the
  // bitmap or resume anything.
  //
  // CampaignLoadResult::Missing is the ONLY outcome safe to treat as "no
  // record, start fresh, admit anything" -- Corrupt/IoError (whether
  // reported by the persistence port itself, or discovered here via a
  // failed magic/version/CRC/bounds check on an actually-present record)
  // instead latch `reloadUnsafe_`, which blocks ALL new admission
  // (handleConsentRequest et al.) until an explicit, deliberate repair via
  // acknowledgeUnsafeReloadAndReset() -- silently falling back to a blank
  // in-memory state here would let a corrupted/faulted storage device
  // reset replay/authorization protections that a real persisted record
  // was enforcing.
  bool reload() {
    // Captured BEFORE any flag is cleared below: if this engine already
    // believed (from an earlier authoritative Ok load, or a still-
    // unresolved corrupt/uncertain state) that durable commissioned
    // facts existed, a Missing result on THIS load can never be treated
    // as "provably never commissioned" -- see the Missing branch below.
    const bool hadCommissionedOrUnresolvedState = everBound_ || reloadUnsafe_ || persistUncertain_;
    // A fresh reload authoritatively determines the durable truth either
    // way (Ok/Missing resolve it outright; Corrupt/IoError instead latch
    // reloadUnsafe_ below, which takes over blocking admission) -- clear
    // any prior save-uncertainty latch before re-deriving state from it.
    persistUncertain_ = false;
    uint8_t buf[kCampaignTargetPersistEncodedSize];
    size_t len = 0;
    CampaignLoadResult loadResult = persistence_.load(CampaignPersistRole::TargetReceiver, buf, sizeof(buf), len);
    if (loadResult == CampaignLoadResult::Missing) {
      // A Missing main record is NEVER, by itself, proof of anything --
      // neither "provably virgin" (that would be exactly the forbidden
      // blank-heuristic: inferring a positive fact from an absence) nor
      // "provably previously commissioned". The ONLY genuinely positive
      // signal this engine will ever accept for "provably virgin" is an
      // independently-verified Virgin result from
      // ICampaignCommissioningProvenancePort -- real, identity-bound
      // factory/security facts, never inferred from any blob's absence.
      if (hadCommissionedOrUnresolvedState) {
        // THIS instance already believed (from an earlier authoritative
        // Ok load, or a still-unresolved corrupt/uncertain state) that
        // durable commissioned facts existed: Missing here can never be
        // conflated with "those facts were just lost". Freeze exactly
        // like Corrupt/IoError.
        reloadUnsafe_ = true;
        return false;
      }
      const CampaignCommissioningProvenanceResult provenance = commissioningProvenance_.readCommissioningProvenance();
      if (provenance.state == CampaignCommissioningState::Virgin) {
        // Positively verified, identity-bound factory fact: this device
        // has genuinely never been commissioned. Safe to start fresh.
        resetToFreshIdle();
        reloadUnsafe_ = false;
        return true;
      }
      if (provenance.state == CampaignCommissioningState::Used) {
        // Positively verified: this device HAS been used/commissioned
        // before. A Missing main record here is safe to treat as fresh
        // ONLY if explained by a separately-confirmed repair-
        // authorization record (see acknowledgeUnsafeReloadAndReset()) --
        // otherwise an already-Used device whose main record vanished
        // for an UNEXPLAINED reason must still freeze; "used" alone
        // never licenses treating it as virgin.
        uint8_t repairBuf[kCampaignRepairAuthEncodedSize];
        size_t repairLen = 0;
        const CampaignLoadResult repairLoadResult = persistence_.load(
            CampaignPersistRole::TargetRepairAuthorization, repairBuf, sizeof(repairBuf), repairLen);
        const bool repairAuthorized = (repairLoadResult == CampaignLoadResult::Ok) &&
                                       decodeCampaignRepairAuthorizationConfirmed(repairBuf, repairLen);
        if (!repairAuthorized) {
          reloadUnsafe_ = true;
          return false;
        }
        resetToFreshIdle();
        reloadUnsafe_ = false;
        return true;
      }
      // CampaignCommissioningState::Unknown -- no real backing wired,
      // the backing's own read failed/is corrupt, or it did not bind to
      // this device's identity. MUST default-deny: never conclude
      // virgin, never conclude authorized-used-reset. Freeze exactly
      // like Corrupt/IoError and leave every in-memory fact untouched.
      reloadUnsafe_ = true;
      return false;
    }
    if (loadResult != CampaignLoadResult::Ok) { reloadUnsafe_ = true; return false; }

    // Explicit, versioned, fixed-width, field-by-field big-endian decode
    // (see encodeCampaignTargetPersistedState/decodeCampaignTargetPersistedState
    // above) -- NEVER a memcpy/reinterpret_cast onto a native struct, so a
    // record written by a different build/process/endianness is decoded
    // identically rather than misparsed. decode already re-verifies the
    // CRC32 over the exact bytes read before trusting any field.
    CampaignTargetPersistedState loaded;
    if (!decodeCampaignTargetPersistedState(buf, len, loaded)) { reloadUnsafe_ = true; return false; }

    if (loaded.magic != kCampaignTargetPersistMagic) { reloadUnsafe_ = true; return false; }
    if (loaded.version != kCampaignTargetPersistVersion) { reloadUnsafe_ = true; return false; }

    // Bounds-check BEFORE trusting chunkCount for anything else -- a
    // corrupt/malicious chunkCount must never be used to index the bitmap.
    if (loaded.chunkCount > runtime::kOtaMaxChunkCount) { reloadUnsafe_ = true; return false; }
    if (loaded.phase > kTargetStatusMax) { reloadUnsafe_ = true; return false; }
    if (loaded.bound != 0 && loaded.everBound == 0) { reloadUnsafe_ = true; return false; } // internally inconsistent record
    if (loaded.signatureLen > sizeof(loaded.signature)) { reloadUnsafe_ = true; return false; }

    if (loaded.everBound == 0) {
      // Nothing meaningful was ever bound; leave the engine at its fresh
      // Idle defaults (this is NOT a failure -- distinct from the false
      // returns above, which mean "record unusable/corrupt").
      resetToFreshIdle();
      reloadUnsafe_ = false;
      return true;
    }

    // Decode the canonical descriptor and RECOMPUTE geometry from it --
    // geometry is never trusted from a stored blob. chunkCount is then
    // cross-checked against the independently-persisted chunkCount for
    // internal consistency before ever touching the bitmap.
    protocol::OtaDescriptor decodedDescriptor{};
    if (protocol::decodeOtaDescriptorCanonical(loaded.descriptorCanonical, sizeof(loaded.descriptorCanonical),
                                                decodedDescriptor) != protocol::OtaDescriptorCodecResult::Ok) {
      reloadUnsafe_ = true;
      return false;
    }
    runtime::OtaGeometry recomputedGeometry;
    if (runtime::OtaGeometry::compute(decodedDescriptor.exactSizeBytes, runtime::kOtaDefaultChunkPayloadSize,
                                       runtime::kOtaMaxImageBytes, recomputedGeometry) != runtime::OtaGeometryResult::Ok) {
      reloadUnsafe_ = true;
      return false;
    }
    if (recomputedGeometry.chunkCount != loaded.chunkCount) { reloadUnsafe_ = true; return false; }
    // Re-verify the descriptor's signature against the CURRENT trust
    // provider on every reload -- a durable record must never be trusted
    // merely because it once passed verification before an earlier boot.
    if (!trust_.verifyDescriptor(decodedDescriptor, loaded.signature, loaded.signatureLen)) {
      reloadUnsafe_ = true;
      return false;
    }

    persisted_ = loaded;
    bound_ = (loaded.bound != 0);
    everBound_ = true;
    std::memcpy(controllerId_.bytes, loaded.controllerId, 32);
    groupId_ = loaded.groupId;
    descriptor_ = decodedDescriptor;
    geometry_ = recomputedGeometry;
    lastFrameSeq_ = loaded.lastFrameSeq;
    replayWindowMask_ = loaded.replayWindowMask;
    bitmap_.reset(geometry_.chunkCount);
    for (uint32_t i = 0; i < geometry_.chunkCount; ++i) {
      if ((loaded.bitmap[i / 8] & (1u << (i % 8))) != 0) bitmap_.set(i);
    }
    status_ = static_cast<TargetStatus>(loaded.phase);
    reloadUnsafe_ = false;
    // This reload() just authoritatively re-derived every fact from the
    // durable winning record -- any pending descriptor-fragment
    // reassembly or queued outbound reply predating it referred to
    // whatever was true before, and must not be allowed to linger/
    // complete against the just-(re)established ground truth.
    clearPendingAdmissionAndReply();

    if (bound_ && (status_ == TargetStatus::Receiving || status_ == TargetStatus::Verifying)) {
      // A mid-transfer record is being resumed: the real production sink
      // must be reattached to its ALREADY-WRITTEN bytes, never restarted
      // via beginSession() (which a real sink may treat as "start brand
      // new", silently discarding everything received before reboot). If
      // no resume port is bound, or it declines, latch reloadUnsafe_
      // rather than silently proceeding against a sink that may not
      // actually hold the prior bytes.
      if (stagingResume_ == nullptr || !stagingResume_->resumeSession(descriptor_)) {
        reloadUnsafe_ = true;
        return false;
      }
      // Restore the EXACT signed canonical descriptor+signature and the
      // authenticated+locally-consented (session, controller) binding
      // onto the RESUMED sink too -- a real production sink's
      // onVerifiedWireDescriptor()/onAuthorizedSession() bookkeeping
      // (see OtaFirmwareStorageSink) is itself only in-RAM and is lost
      // across the same reboot that this reload() is recovering from;
      // without re-delivering these exact persisted bytes here, a commit()
      // reached via the resumed session would fail closed (or worse, a
      // less careful sink might silently rebind the transaction identity
      // from the descriptor alone). These are the SAME bytes/identity
      // already re-verified above (decodedDescriptor's signature just
      // passed trust_.verifyDescriptor()), never re-derived.
      staging_.onVerifiedWireDescriptor(loaded.descriptorCanonical, sizeof(loaded.descriptorCanonical),
                                         loaded.signature, loaded.signatureLen);
      staging_.onAuthorizedSession(loaded.session, loaded.controllerId);
      receiver_.beginCampaign(loaded.session);
      receiver_.handle(runtime::OtaReceiverEvent::DescriptorComplete, loaded.session);
      receiver_.handle(runtime::OtaReceiverEvent::AuthorizationGranted, loaded.session);
      if (status_ == TargetStatus::Verifying) receiver_.handle(runtime::OtaReceiverEvent::AllChunksReceived, loaded.session);
    }
    return true;
  }

  // Binds the optional clock/staging-resume ports. Both are nullable --
  // an engine with no bound clock simply treats a pending reply as always
  // eligible for retry on the next tick() (no deadline gating); an engine
  // with no bound resume port will latch reloadUnsafe_ rather than ever
  // resuming a mid-transfer record via a destructive re-begin.
  void bindClock(IClockPort& clock) { clock_ = &clock; }
  void bindStagingResume(IOtaStagingResumePort& resume) { stagingResume_ = &resume; }

  // Handles an inbound ConsentRequest (descriptor+signature already fully
  // reassembled, e.g. via onDescriptorFragment() below, or delivered
  // in-band by a test/integration that already has the complete bytes).
  // Rejects (no mutation) any frame that is not authenticated, not
  // Pairwise-scoped, foreign to an existing binding, replayed, or that
  // fails signature/policy verification -- verification and local policy
  // are ALWAYS checked before any replay-guard state is consumed, so an
  // invalid/unsigned request can never burn a legitimate future session's
  // replay window. A resend of the EXACT already-bound (session,
  // controller, descriptor) tuple is idempotent; the SAME tuple with a
  // DIFFERENT descriptor is rejected outright (never silently rebinds).
  bool handleConsentRequest(const AuthenticatedInboundFrame& frame, uint32_t envelopeFrameSeq,
                             const runtime::OtaSessionId& id, const CampaignConsentRequestPayload& payload,
                             const protocol::OtaDescriptor& descriptor,
                             const uint8_t* signature, size_t signatureLen) {
    if (blockedByUnresolvedPersistence()) return false;

    if (!frame.authenticated) { lastRefusal_ = CampaignRefusalReason::UntrustedContext; return false; }
    if (!frame.isPairwise() ||
        static_cast<CampaignAuthScope>(payload.scope) != CampaignAuthScope::Pairwise) {
      lastRefusal_ = CampaignRefusalReason::GroupNotAuthorizedForPairwise;
      return false;
    }
    CampaignPeerId requester;
    std::memcpy(requester.bytes, payload.controllerId, 32);
    if (requester != frame.pairwise()->peerId) {
      lastRefusal_ = CampaignRefusalReason::UntrustedContext;
      return false;
    }
    // The ConsentRequest's declared descriptorTotalLength must agree with
    // the ACTUAL combined canonical-descriptor+signature length being
    // admitted here -- checked for every call path (fresh admission,
    // idempotent retry, and any direct caller), before any mutation. A
    // request that declares one length yet supplies a different (still
    // validly-signed) descriptor+signature must never silently stage or
    // rebind against a length the pending ticket never actually froze.
    if (payload.descriptorTotalLength !=
        static_cast<uint16_t>(protocol::kOtaDescriptorCanonicalSize + signatureLen)) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }

    if (bound_ && runtime::otaSessionEquals(id, persisted_.session) && controllerId_ == requester) {
      // Treat as the SAME already-admitted ticket (idempotent resend) only
      // if descriptor bytes, group, AND the exact signature bytes/length
      // all match what was actually persisted at admission -- a changed
      // signature or group on an otherwise-matching descriptor/session/
      // controller must never be silently accepted as a harmless retry,
      // and must never re-run beginSession()/any staging or rebind logic.
      if (!descriptorBytesEqual(descriptor, descriptor_) || payload.groupId != groupId_ ||
          signatureLen != persisted_.signatureLen ||
          std::memcmp(signature, persisted_.signature, signatureLen) != 0) {
        lastRefusal_ = CampaignRefusalReason::DescriptorConflict;
        return false;
      }
      uint32_t newLastFrameSeq = 0, newReplayMask = 0;
      if (!replayWindowCheck(lastFrameSeq_, replayWindowMask_, envelopeFrameSeq, newLastFrameSeq, newReplayMask)) {
        lastRefusal_ = CampaignRefusalReason::StaleReplay;
        return false;
      }
      CampaignTargetPersistedState candidate = persisted_;
      candidate.lastFrameSeq = newLastFrameSeq;
      candidate.replayWindowMask = newReplayMask;
      if (!commitPersist(candidate)) { lastRefusal_ = CampaignRefusalReason::PersistenceFailed; return false; }
      lastRefusal_ = CampaignRefusalReason::None;
      return true;
    }
    if (bound_ && controllerId_ != requester) {
      lastRefusal_ = CampaignRefusalReason::ForeignController;
      return false;
    }
    // Same controller as an existing binding, but a DIFFERENT session id:
    // only a binding that has already reached an explicitly terminal
    // state (Failed/Aborted) may ever be superseded. A still-live
    // (Receiving/Verifying/InstalledPending) transaction must never be
    // silently replaced/erased by a competing non-terminal session --
    // that would erase already-received bytes and reset authorization.
    if (bound_ && status_ != TargetStatus::Failed && status_ != TargetStatus::Aborted) {
      lastRefusal_ = CampaignRefusalReason::ForeignSession;
      return false;
    }
    // By this point any existing binding for this controller (if present
    // at all) is explicitly terminal or absent, so admitting this new
    // session cannot erase live in-flight state.
    if (everBound_ && !runtime::otaSessionIsNewer(id, persisted_.session)) {
      lastRefusal_ = CampaignRefusalReason::StaleReplay;
      return false;
    }
    if (!trust_.verifyDescriptor(descriptor, signature, signatureLen)) {
      lastRefusal_ = CampaignRefusalReason::DescriptorInvalid;
      return false;
    }
    if (signatureLen > sizeof(CampaignTargetPersistedState{}.signature)) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }
    if (!consentPolicy_.isConsentPolicyApproved(requester, descriptor)) {
      lastRefusal_ = CampaignRefusalReason::ConsentPolicyDenied;
      return false;
    }
    runtime::OtaGeometry geometry;
    if (runtime::OtaGeometry::compute(descriptor.exactSizeBytes, runtime::kOtaDefaultChunkPayloadSize,
                                       runtime::kOtaMaxImageBytes, geometry) != runtime::OtaGeometryResult::Ok) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }
    uint8_t canonical[protocol::kOtaDescriptorCanonicalSize];
    size_t canonicalLen = 0;
    if (protocol::encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), canonicalLen) !=
            protocol::OtaDescriptorCodecResult::Ok ||
        canonicalLen != protocol::kOtaDescriptorCanonicalSize) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }
    // Durable Virgin->Used commissioning transition: FIRST durable step
    // of a new admission, strictly BEFORE staging_.beginSession()'s
    // (generally irreversible) sink mutation and before the main
    // record's own commit -- see ICampaignCommissioningProvenancePort.
    // Rejected (e.g. no real backing wired, or provenance is Unknown)
    // refuses cleanly before ANY mutation; Uncertain freezes (the
    // transition may have already durably landed) before ever touching
    // the staging sink; Confirmed (either just transitioned, or already
    // Used -- idempotent) proceeds.
    const CampaignMarkUsedResult markUsedResult = commissioningProvenance_.markUsedIfCurrentlyVirgin();
    if (markUsedResult == CampaignMarkUsedResult::Rejected) {
      lastRefusal_ = CampaignRefusalReason::CommissioningProvenanceUnknown;
      return false;
    }
    if (markUsedResult == CampaignMarkUsedResult::Uncertain) {
      persistUncertain_ = true;
      lastRefusal_ = CampaignRefusalReason::CommissioningProvenanceUnknown;
      return false;
    }
    // Positive commissioning proof must precede even repair-record mutation.
    // Retire the prior repair grant before staging or publishing this attempt;
    // it must never authorize disappearance of a later campaign's record.
    if (!persistence_.erase(CampaignPersistRole::TargetRepairAuthorization)) {
      persistUncertain_ = true;
      lastRefusal_ = CampaignRefusalReason::RepairAuthorizationRetirementUnconfirmed;
      return false;
    }
    if (staging_.beginSession(descriptor) != runtime::IOtaStagingSink::Result::Ok) {
      lastRefusal_ = CampaignRefusalReason::StagingRejected;
      return false;
    }

    CampaignTargetPersistedState candidate{};
    candidate.session = id;
    std::memcpy(candidate.controllerId, requester.bytes, 32);
    candidate.groupId = payload.groupId;
    std::memcpy(candidate.descriptorCanonical, canonical, protocol::kOtaDescriptorCanonicalSize);
    std::memcpy(candidate.signature, signature, signatureLen);
    candidate.signatureLen = static_cast<uint8_t>(signatureLen);
    candidate.phase = static_cast<uint8_t>(TargetStatus::Receiving);
    candidate.lastFrameSeq = envelopeFrameSeq;
    candidate.replayWindowMask = 0x1u; // fresh window: this starting seq is the only one seen
    candidate.chunkCount = geometry.chunkCount;
    candidate.bound = 1;
    candidate.everBound = 1;
    std::memset(candidate.bitmap, 0, sizeof(candidate.bitmap));

    if (!commitPersist(candidate)) {
      // RejectedBeforeMutation vs Uncertain are NOT the same outcome
      // here. RejectedBeforeMutation: the durable METADATA record is
      // PROVABLY still whatever it was before this call -- but
      // staging_.beginSession() above is NOT reversible in general (a
      // real production sink's begin() may already have durably erased
      // NOR flash; abort() cannot un-erase it). That erasure is still
      // SAFE here specifically because the admission-ordering checks
      // above already guarantee beginSession() is only ever reached
      // once every other check (existing live binding, replay, trust,
      // policy, geometry) has already established that any prior staged
      // bytes for this controller either never existed or belonged to
      // an already-terminal (Failed/Aborted) session -- never a still-
      // live one. staging_.abort() here only marks the SINK's own RAM
      // tracking not-active, matching a metadata record we can safely
      // continue reporting as not-bound; an identical retry (same or
      // newer id) is then fully retriable precisely because no LIVE
      // progress was ever at risk, not because the erase itself was
      // undone.
      // Uncertain: the beginSession() we just issued and/or this exact
      // candidate MAY already be the new durable checkpoint even though
      // the port could not confirm it -- calling staging_.abort() here
      // could destroy real backing bytes that an authoritative reload()
      // later finds durably committed. Freeze in place instead
      // (persistUncertain_ is already latched by commitPersist()) and
      // let reload() -- which resumes rather than re-begins a durably
      // Receiving record -- resolve the truth.
      if (!persistUncertain_) {
        staging_.abort();
      }
      lastRefusal_ = CampaignRefusalReason::PersistenceFailed;
      return false;
    }

    // Hand the sink the EXACT verified wire descriptor+signature bytes and
    // the authenticated+locally-consented (session, controller) binding
    // that just admitted this attempt -- some real production sinks (see
    // OtaFirmwareStorageSink::onVerifiedWireDescriptor/onAuthorizedSession
    // in helpers/ota/OtaFirmwareBackend.h) durably bind an install-command
    // transaction identity to exactly this authenticated authorized
    // attempt at commit() time, and must never fabricate that binding
    // from the descriptor alone. Calling these strictly AFTER durable
    // persistence success mirrors the state-machine transition above; a
    // sink with no such requirement simply ignores them (default no-op).
    staging_.onVerifiedWireDescriptor(canonical, canonicalLen, signature, signatureLen);
    staging_.onAuthorizedSession(id, requester.bytes);

    // Guard/state-machine transition committed strictly AFTER durable
    // success.
    if (receiver_.state() != runtime::OtaReceiverState::Idle) receiver_.reset();
    receiver_.beginCampaign(id);
    receiver_.handle(runtime::OtaReceiverEvent::DescriptorComplete, id);
    receiver_.handle(runtime::OtaReceiverEvent::AuthorizationGranted, id);

    lastRefusal_ = CampaignRefusalReason::None;
    return true;
  }

  // Bounded, no-heap reassembly of a fragmented signed descriptor blob
  // (canonical descriptor bytes followed by the opaque signature) prior
  // to admission. `beginPendingConsent` must be called once with the
  // ConsentRequest metadata before feeding fragments for that session.
  bool beginPendingConsent(const AuthenticatedInboundFrame& frame, const runtime::OtaSessionId& id,
                            const CampaignConsentRequestPayload& payload) {
    if (blockedByUnresolvedPersistence()) return false;
    if (!frame.hasAuthenticatedPeer()) return false;
    CampaignPeerId requester;
    std::memcpy(requester.bytes, payload.controllerId, 32);
    if (requester != frame.pairwise()->peerId) return false;

    if (pendingActive_) {
      CampaignPeerId pendingController;
      std::memcpy(pendingController.bytes, pendingPayload_.controllerId, 32);
      // Freeze the FULL pending ticket -- controller identity, session/
      // attempt, auth scope, group, and declared descriptor length --
      // before deciding whether this inbound ConsentRequest is a
      // legitimate retry of the SAME in-flight attempt or a distinct
      // one. Any single field differing makes it a competing/changed
      // request, never an identical retry.
      const bool sameTicket = runtime::otaSessionEquals(id, pendingSession_) &&
                               pendingController == requester &&
                               pendingPayload_.scope == payload.scope &&
                               pendingPayload_.groupId == payload.groupId &&
                               pendingPayload_.descriptorTotalLength == payload.descriptorTotalLength;
      if (sameTicket) {
        // Identical retry of the attempt already in flight: idempotent
        // no-op that preserves every already-received fragment byte --
        // never reset the reassembler just because the peer resent its
        // ConsentRequest (e.g. its own reply was lost/delayed).
        pendingLastActivityMs_ = clock_ != nullptr ? clock_->nowMs() : pendingLastActivityMs_;
        return true;
      }
      // A competing controller, a different session/attempt, a changed
      // scope/group, or a duplicate ticket declaring a DIFFERENT
      // descriptor length must never reset an original reassembly that
      // is still genuinely active -- only a bounded, bookkeeping-only
      // RAM expiry (no durable state involved) may reclaim an
      // abandoned/stalled slot.
      if (!pendingConsentExpired()) {
        return false;
      }
      // Falls through: the prior pending ticket is genuinely stale/
      // abandoned (no activity for kCampaignPendingConsentExpiryMs) --
      // safe to reclaim the unadmitted RAM slot for this new ticket.
    }

    pendingSession_ = id;
    pendingPayload_ = payload;
    pendingReassembler_.reset();
    pendingFragmentReceivedMask_ = 0;
    pendingActive_ = true;
    pendingLastActivityMs_ = clock_ != nullptr ? clock_->nowMs() : 0;
    return true;
  }

  // Feeds one DescriptorFragment. Once complete, decodes the
  // descriptor+signature and finishes admission via handleConsentRequest.
  // Returns false (no mutation) for any geometry/session mismatch,
  // leaving the reassembler untouched so a corrected retry can proceed.
  bool onDescriptorFragment(const AuthenticatedInboundFrame& frame, uint32_t envelopeFrameSeq,
                             const runtime::OtaSessionId& id, uint8_t fragIndex, uint8_t fragCount,
                             uint16_t totalLength, uint16_t fragmentPayloadSize,
                             const uint8_t* data, size_t dataLen) {
    if (blockedByUnresolvedPersistence()) return false;
    if (!pendingActive_ || !runtime::otaSessionEquals(id, pendingSession_)) return false;
    // A fragment frame is authenticated independently of beginPendingConsent
    // (which only validated the FIRST frame of this reassembly): every
    // fragment must itself be Pairwise-authenticated from the SAME
    // controller that opened this pending reassembly, or a foreign sender
    // could mutate/complete another controller's in-flight descriptor.
    if (!frame.hasAuthenticatedPeer()) return false;
    CampaignPeerId pendingController;
    std::memcpy(pendingController.bytes, pendingPayload_.controllerId, 32);
    if (frame.pairwise()->peerId != pendingController) return false;
    // The declared total length is part of the FROZEN pending ticket
    // (see beginPendingConsent()) -- every fragment of THIS reassembly
    // must agree with it. Without this check a request could declare one
    // length in its ConsentRequest, then stream fragments whose own
    // totalLength describes a DIFFERENT (still validly-signed) descriptor
    // blob, silently completing reassembly/admission against a length
    // the pending ticket never actually froze. Rejected here BEFORE any
    // reassembler/state mutation -- original pending ticket untouched.
    if (totalLength != pendingPayload_.descriptorTotalLength) return false;
    // A duplicate resend of an already-accepted fragment index carrying
    // DIFFERENT bytes than what this attempt already holds for that
    // index must be rejected BEFORE ever reaching the lower-level
    // reassembler -- its own duplicate-resend handling silently accepts
    // (and overwrites with) whatever geometry-consistent bytes arrive
    // for an already-received index, which would let a later, different
    // fragment quietly corrupt/replace part of the original reassembly.
    // An EXACT bit-identical resend is still accepted (idempotent retry).
    if (fragIndex < 32 && (pendingFragmentReceivedMask_ & (1u << fragIndex)) != 0) {
      const bool isLast = (fragCount > 0 && fragIndex == static_cast<uint8_t>(fragCount - 1));
      const size_t offset = static_cast<size_t>(fragIndex) * static_cast<size_t>(fragmentPayloadSize);
      const size_t expectedLen = isLast && totalLength >= offset
                                      ? (static_cast<size_t>(totalLength) - offset)
                                      : static_cast<size_t>(fragmentPayloadSize);
      if (dataLen != expectedLen || offset + expectedLen > protocol::OtaDescriptorReassembler::kMaxBlobSize ||
          std::memcmp(pendingReassembler_.blob() + offset, data, dataLen) != 0) {
        return false;  // differing duplicate: reject, original reassembly untouched.
      }
    }
    if (!pendingReassembler_.addFragment(fragIndex, fragCount, totalLength, fragmentPayloadSize, data, dataLen)) {
      return false;
    }
    if (fragIndex < 32) pendingFragmentReceivedMask_ |= (1u << fragIndex);
    // Real progress on the SAME still-in-flight attempt: refresh the
    // bounded unadmitted-RAM activity clock so a competing ConsentRequest
    // can never treat a genuinely active attempt as abandoned/expired.
    pendingLastActivityMs_ = clock_ != nullptr ? clock_->nowMs() : pendingLastActivityMs_;
    if (!pendingReassembler_.isComplete()) return true; // legal partial progress, no-op
    if (pendingReassembler_.blobLength() < protocol::kOtaDescriptorCanonicalSize) return false;

    protocol::OtaDescriptor descriptor;
    if (protocol::decodeOtaDescriptorCanonical(pendingReassembler_.blob(), protocol::kOtaDescriptorCanonicalSize,
                                                descriptor) != protocol::OtaDescriptorCodecResult::Ok) {
      return false;
    }
    const uint8_t* signature = pendingReassembler_.blob() + protocol::kOtaDescriptorCanonicalSize;
    size_t signatureLen = pendingReassembler_.blobLength() - protocol::kOtaDescriptorCanonicalSize;
    bool ok = handleConsentRequest(frame, envelopeFrameSeq, id, pendingPayload_, descriptor, signature, signatureLen);
    pendingActive_ = false;
    return ok;
  }

  // Applies one inbound chunk. Bitmap test-before-write is the app-level
  // dedup (chunk-index based, independent of frameSeq): an already-
  // received chunk index is a legal idempotent no-op. `envelopeFrameSeq`
  // is the fresh, per-frame authenticated retry sequence (independent of
  // the transfer session/attempt) -- it must be strictly greater than the
  // last accepted frame's sequence, defeating literal wire-frame replay
  // even for an idempotent no-op resend. GROUP-scoped delivery is allowed
  // ONLY for an already-bound controller+group (background multicast/
  // repair); Pairwise from the bound controller always works.
  bool applyChunk(const AuthenticatedInboundFrame& frame, uint32_t envelopeFrameSeq,
                   const runtime::OtaSessionId& id, const protocol::OtaChunkHeader& hdr,
                   const uint8_t* data, size_t dataLen) {
    if (blockedByUnresolvedPersistence()) return false;
    if (!frame.authenticated) { lastRefusal_ = CampaignRefusalReason::UntrustedContext; return false; }
    bool pairwiseOk = bound_ && frame.isPairwise() && frame.pairwise()->peerId == controllerId_;
    const GroupAuthContext* g = frame.group();
    bool groupOk = bound_ && g != nullptr && g->membershipVerified && groupId_ != 0 && g->groupId == groupId_;
    if (!pairwiseOk && !groupOk) {
      lastRefusal_ = bound_ ? CampaignRefusalReason::ForeignController : CampaignRefusalReason::UntrustedContext;
      return false;
    }
    // Session must always match the bound transfer. Status: an
    // already-received chunk (dedup fast-path below) may legitimately be
    // retransmitted by the updater and need re-acking even AFTER this
    // target's bitmap already completed and moved on to Verifying/
    // InstalledPending/Installed -- e.g. the very LAST chunk's original
    // ChunkAck was lost on the wire, so the updater's bounded retry
    // re-sends that chunk's bytes once more. Rejecting that retry with
    // ForeignSession here would create a permanent liveness deadlock:
    // the updater keeps retransmitting a chunk that will never again be
    // acknowledged. Only a genuinely NEW (never-before-seen) chunk index
    // is restricted to the Receiving phase; the dedup path below is safe
    // in any post-Receiving phase because it can only ever re-set an
    // already-set bit and re-send an ack, never mutate staged bytes.
    if (!runtime::otaSessionEquals(id, persisted_.session)) {
      lastRefusal_ = CampaignRefusalReason::ForeignSession;
      return false;
    }
    bool statusAllowsChunkTraffic = status_ == TargetStatus::Receiving || status_ == TargetStatus::Verifying ||
                                     status_ == TargetStatus::InstalledPending || status_ == TargetStatus::Installed;
    if (!statusAllowsChunkTraffic) {
      lastRefusal_ = CampaignRefusalReason::ForeignSession;
      return false;
    }
    if (hdr.dataLength != dataLen) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }
    uint32_t newLastFrameSeq = 0, newReplayMask = 0;
    if (!replayWindowCheck(lastFrameSeq_, replayWindowMask_, envelopeFrameSeq, newLastFrameSeq, newReplayMask)) {
      lastRefusal_ = CampaignRefusalReason::StaleReplay;
      return false;
    }
    uint32_t expectedLen = 0;
    if (!geometry_.chunkLength(hdr.chunkIndex, expectedLen) || expectedLen != dataLen) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }

    if (bitmap_.test(hdr.chunkIndex)) {
      // Already-received: legal no-op, but still bump+persist the replay
      // window so a captured duplicate frame can't be replayed forever.
      CampaignTargetPersistedState candidate = persisted_;
      candidate.lastFrameSeq = newLastFrameSeq;
      candidate.replayWindowMask = newReplayMask;
      if (!commitPersist(candidate)) { lastRefusal_ = CampaignRefusalReason::PersistenceFailed; return false; }
      lastRefusal_ = CampaignRefusalReason::None;
      return true;
    }

    // A genuinely NEW chunk index can only be written while actively
    // Receiving -- once bitmap completion has advanced the phase past
    // Receiving, no unset bit should exist; refuse defensively rather
    // than write staged bytes outside the Receiving phase.
    if (status_ != TargetStatus::Receiving) {
      lastRefusal_ = CampaignRefusalReason::ForeignSession;
      return false;
    }

    uint64_t offset = 0;
    if (!geometry_.chunkOffset(hdr.chunkIndex, offset)) { lastRefusal_ = CampaignRefusalReason::GeometryInvalid; return false; }
    if (staging_.writeChunk(offset, data, dataLen) != runtime::IOtaStagingSink::Result::Ok) {
      lastRefusal_ = CampaignRefusalReason::StagingIoError;
      CampaignTargetPersistedState failCandidate = persisted_;
      failCandidate.phase = static_cast<uint8_t>(TargetStatus::Failed);
      failCandidate.lastFrameSeq = newLastFrameSeq;
      failCandidate.replayWindowMask = newReplayMask;
      if (commitPersist(failCandidate)) receiver_.handle(runtime::OtaReceiverEvent::StagingError, id);
      return false;
    }

    CampaignTargetPersistedState candidate = persisted_;
    candidate.bitmap[hdr.chunkIndex / 8] |= static_cast<uint8_t>(1u << (hdr.chunkIndex % 8));
    candidate.lastFrameSeq = newLastFrameSeq;
    candidate.replayWindowMask = newReplayMask;
    bool wouldBeAllSet = bitmapWouldBeComplete(candidate);
    if (wouldBeAllSet) candidate.phase = static_cast<uint8_t>(TargetStatus::Verifying);

    if (!commitPersist(candidate)) {
      // Bytes ARE durably written into staging already (write+readback is
      // that sink's own contract), but OUR checkpoint did not durably
      // record receipt -- no ACK is given; a retry will re-attempt this
      // exact chunk and, on a subsequent successful persist, be recorded.
      lastRefusal_ = CampaignRefusalReason::PersistenceFailed;
      return false;
    }

    receiver_.handle(runtime::OtaReceiverEvent::ChunkAccepted, id);
    if (wouldBeAllSet) receiver_.handle(runtime::OtaReceiverEvent::AllChunksReceived, id);
    lastRefusal_ = CampaignRefusalReason::None;
    return true;
  }

  // Verifies the full staged hash against the descriptor and commits the
  // cache. Requires an authenticated, Pairwise, bound-controller context
  // (never directly driver-callable without one) -- centralizes the
  // protected inbound path rather than trusting a bare method call.
  // Only legal once every chunk is received. Never claims `Installed`.
  bool verifyAndCommit(const AuthenticatedInboundFrame& frame, const runtime::OtaSessionId& id) {
    if (blockedByUnresolvedPersistence()) return false;
    if (!requirePairwiseBoundController(frame, id)) return false;
    if (status_ != TargetStatus::Verifying) { lastRefusal_ = CampaignRefusalReason::ForeignSession; return false; }
    if (!trust_.verifyStagedImageHash(descriptor_)) {
      lastRefusal_ = CampaignRefusalReason::HashMismatch;
      setPhaseBestEffort(TargetStatus::Failed);
      receiver_.handle(runtime::OtaReceiverEvent::VerificationFailed, id);
      return false;
    }
    if (staging_.commit() != runtime::IOtaStagingSink::Result::Ok) {
      lastRefusal_ = CampaignRefusalReason::StagingIoError;
      setPhaseBestEffort(TargetStatus::Failed);
      receiver_.handle(runtime::OtaReceiverEvent::CommitFailed, id);
      return false;
    }
    if (!setPhaseDurable(TargetStatus::InstalledPending)) {
      lastRefusal_ = CampaignRefusalReason::PersistenceFailed;
      return false;
    }
    receiver_.handle(runtime::OtaReceiverEvent::VerificationOk, id);
    receiver_.handle(runtime::OtaReceiverEvent::CommitOk, id);
    lastRefusal_ = CampaignRefusalReason::None;
    return true;
  }

  bool abort(const AuthenticatedInboundFrame& frame, const runtime::OtaSessionId& id) {
    if (blockedByUnresolvedPersistence()) return false;
    if (!requirePairwiseBoundController(frame, id)) return false;
    if (!runtime::otaSessionEquals(id, persisted_.session)) { lastRefusal_ = CampaignRefusalReason::ForeignSession; return false; }
    staging_.abort();
    if (!setPhaseDurable(TargetStatus::Aborted)) {
      lastRefusal_ = CampaignRefusalReason::PersistenceFailed;
      return false;
    }
    receiver_.handle(runtime::OtaReceiverEvent::Abort, id);
    lastRefusal_ = CampaignRefusalReason::None;
    return true;
  }

  // Must be polled (e.g. once per boot, or periodically) after a commit.
  // Only flips to Installed once genuine BOUND healthy-boot evidence
  // (exact image hash + session + counter) matches this descriptor/
  // session; a device that never actually boots the exact new image is
  // never falsely reported Installed. This engine never writes any
  // security-counter floor -- that is the bootloader's own job.
  bool confirmHealthyBoot() {
    if (blockedByUnresolvedPersistence()) return false;
    if (status_ != TargetStatus::InstalledPending) return false;
    CampaignBootEvidence evidence = bootEvidence_.queryBootEvidence();
    if (!evidence.healthyBootConfirmed) return false;
    if (!runtime::otaSessionEquals(evidence.bootedSession, persisted_.session)) {
      lastRefusal_ = CampaignRefusalReason::BootEvidenceMismatch;
      return false;
    }
    if (std::memcmp(evidence.bootedImageHash, descriptor_.sha256, protocol::kOtaSha256Size) != 0) {
      lastRefusal_ = CampaignRefusalReason::BootEvidenceMismatch;
      return false;
    }
    if (evidence.bootedSecurityCounter != descriptor_.securityCounter) {
      lastRefusal_ = CampaignRefusalReason::BootEvidenceMismatch;
      return false;
    }
    if (!setPhaseDurable(TargetStatus::Installed)) {
      lastRefusal_ = CampaignRefusalReason::PersistenceFailed;
      return false;
    }
    lastRefusal_ = CampaignRefusalReason::None;
    sendReceipt(protocol::OtaReceiptStatus::TransferComplete, 0);
    return true;
  }

  TargetStatus status() const { return status_; }
  CampaignRefusalReason lastRefusal() const { return lastRefusal_; }
  uint32_t receivedChunkCount() const { return static_cast<uint32_t>(bitmap_.countSet()); }
  const runtime::OtaGeometry& geometry() const { return geometry_; }
  bool isControllerBound() const { return bound_; }
  const CampaignPeerId& boundController() const { return controllerId_; }
  uint32_t lastFrameSeq() const { return lastFrameSeq_; }

  // Binds an outbound transport port so this engine can autonomously
  // send its own protocol replies (ConsentGrant/Receipt) from onFrame(),
  // instead of a driver synthesizing them. Purely additive: an engine
  // with no bound transport behaves exactly as before (a pure inbound
  // state machine with zero side-effect sends), so existing callers that
  // never call this are entirely unaffected.
  void bindTransport(IAuthenticatedTransportPort& transport) { transport_ = &transport; }

  // Bounded, non-blocking periodic tick: retries any latched pending
  // reply. Safe to call every scheduler pass regardless of whether
  // anything is actually pending (a no-op in that case). A reply queued
  // BEFORE a fault latched reloadUnsafe_/persistUncertain_ must not be
  // allowed to progress/retry while frozen -- the freeze covers every
  // mutating/emitting entry point, not merely new-mutation calls.
  void tick() {
    if (blockedByUnresolvedPersistence()) return;
    retryPendingReply();
  }

  // Single production entry point for ALL inbound campaign wire traffic:
  // decodes the envelope, routes to the correct internal handler by
  // message type, and (when a transport is bound) autonomously sends the
  // resulting protocol reply. Replaces a driver hand-decoding frames and
  // calling handleConsentRequest/onDescriptorFragment/applyChunk/
  // verifyAndCommit directly with pre-decoded arguments.
  bool onFrame(const AuthenticatedInboundFrame& frame) {
    if (!frame.authenticated) { lastRefusal_ = CampaignRefusalReason::UntrustedContext; return false; }
    CampaignEnvelopeHeader hdr;
    const uint8_t* payload = nullptr;
    size_t payloadLen = 0;
    if (decodeCampaignEnvelope(frame.payload, frame.payloadLen, hdr, payload, payloadLen) != CampaignCodecResult::Ok) {
      lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
      return false;
    }
    switch (hdr.type) {
      case CampaignMessageType::ConsentRequest: {
        CampaignConsentRequestPayload creq;
        if (!decodeCampaignConsentRequest(payload, payloadLen, creq)) {
          lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
          return false;
        }
        bool ok = beginPendingConsent(frame, hdr.session, creq);
        if (!ok) lastRefusal_ = CampaignRefusalReason::UntrustedContext;
        return ok;
      }
      case CampaignMessageType::DescriptorFragment: {
        uint8_t fragIndex = 0, fragCount = 0;
        uint16_t totalLength = 0, fragmentPayloadSize = 0;
        const uint8_t* data = nullptr;
        size_t dataLen = 0;
        if (!decodeCampaignDescriptorFragment(payload, payloadLen, fragIndex, fragCount, totalLength,
                                               fragmentPayloadSize, data, dataLen)) {
          lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
          return false;
        }
        bool wasPending = pendingActive_;
        // Capture the ORIGINAL requester/session of the pending ticket
        // that is about to complete -- NOT controllerId_/bound_, which
        // may still reflect some other, previously-bound owner (e.g. a
        // denial because this attempt is a ForeignSession against an
        // existing bound candidate). The reply must always go to the
        // captured authenticated request context that actually drove
        // this reassembly, never to a receiver-persisted other owner.
        CampaignPeerId completingRequester{};
        runtime::OtaSessionId completingSession{};
        if (wasPending) {
          std::memcpy(completingRequester.bytes, pendingPayload_.controllerId, 32);
          completingSession = pendingSession_;
        }
        bool ok = onDescriptorFragment(frame, hdr.frameSeq, hdr.session, fragIndex, fragCount, totalLength,
                                        fragmentPayloadSize, data, dataLen);
        if (wasPending && !pendingActive_) {
          // The reassembly just finished (successfully or not): reply
          // with an explicit ConsentGrant reporting the outcome, to the
          // actual requester regardless of this engine's current
          // bound_/controllerId_ state.
          sendConsentGrant(completingRequester, completingSession, ok,
                            ok ? CampaignRefusalReason::None : lastRefusal_);
        }
        return ok;
      }
      case CampaignMessageType::Chunk: {
        protocol::OtaChunkHeader chdr;
        const uint8_t* data = nullptr;
        size_t dataLen = 0;
        if (!protocol::decodeOtaChunk(payload, payloadLen, chdr, data, dataLen)) {
          lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
          return false;
        }
        bool ok = applyChunk(frame, hdr.frameSeq, hdr.session, chdr, data, dataLen);
        if (ok) sendReceipt(protocol::OtaReceiptStatus::ChunkAck, chdr.chunkIndex);
        return ok;
      }
      case CampaignMessageType::Commit: {
        protocol::OtaCommitPayload commit;
        if (!protocol::decodeOtaCommit(payload, payloadLen, commit)) {
          lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
          return false;
        }
        if (!bound_ || !runtime::otaSessionEquals(hdr.session, persisted_.session)) {
          lastRefusal_ = CampaignRefusalReason::ForeignSession;
          return false;
        }
        if (commit.campaignId != persisted_.session.campaignId || commit.verifiedOk == 0 ||
            commit.finalSecurityCounter != descriptor_.securityCounter) {
          lastRefusal_ = CampaignRefusalReason::DescriptorConflict;
          return false;
        }
        return verifyAndCommit(frame, hdr.session);
      }
      default:
        lastRefusal_ = CampaignRefusalReason::GeometryInvalid;
        return false;
    }
  }

  // True once reload() found a persisted record that could not be
  // validated (storage-layer Corrupt/IoError, or a failed magic/version/
  // CRC/bounds check here). While true, ALL new admission is refused --
  // see acknowledgeUnsafeReloadAndReset() for the only sanctioned repair.
  bool isReloadUnsafe() const { return reloadUnsafe_; }

  // True once a save() reported Uncertain and hasn't yet been resolved by
  // a subsequent reload(). See persistUncertain_/commitPersist().
  bool isPersistUncertain() const { return persistUncertain_; }

  // Explicit, deliberate repair for an unsafe-reload state: erases the
  // CAMPAIGN-SPECIFIC unreadable/untrusted durable record and resets
  // this engine to a fresh Idle instance so admission can resume. This
  // is NOT called automatically by reload() itself -- silently self-
  // healing would defeat the entire point of latching reloadUnsafe_ in
  // the first place. Callers (FW adapter) should only invoke this after
  // a deliberate, locally-authorized decision.
  //
  // This repair ERASES ONLY the campaign's own TargetReceiver record; it
  // NEVER touches ICampaignCommissioningProvenancePort's independent
  // commissioned/factory-security facts, which must survive a campaign-
  // record repair unconditionally (erasing them here would be exactly
  // the unsafe "recast device Virgin" behavior this two-fact split
  // exists to prevent, and would drop real security history forever).
  //
  // Refuses (false, all guards UNCHANGED) if the independent
  // commissioning provenance is Unknown -- without a positively known
  // Virgin/Used fact this engine cannot be sure erasing the main record
  // is safe. If the device is genuinely Used, a repair additionally
  // requires durably confirming a separate repair-authorization record
  // (see kCampaignRepairAuthMagic above) BEFORE clearing reloadUnsafe_ --
  // this is what lets a FUTURE reload() distinguish "main record Missing
  // because of THIS authorized repair" from unexplained data loss; if
  // that confirmation fails, the repair stays incomplete/latched even
  // though the main record was already erased. If the device is
  // genuinely Virgin, no repair-authorization record is needed (a
  // Missing main record already resolves fresh for a Virgin device in
  // reload()).
  bool acknowledgeUnsafeReloadAndReset() {
    const CampaignCommissioningProvenanceResult provenance = commissioningProvenance_.readCommissioningProvenance();
    if (provenance.state == CampaignCommissioningState::Unknown) {
      return false;
    }
    if (!persistence_.erase(CampaignPersistRole::TargetReceiver)) {
      return false;
    }
    if (provenance.state == CampaignCommissioningState::Used) {
      uint8_t repairEncoded[kCampaignRepairAuthEncodedSize];
      size_t repairEncodedLen = 0;
      if (!encodeCampaignRepairAuthorization(repairEncoded, sizeof(repairEncoded), repairEncodedLen)) {
        return false;  // unreachable: fixed-size local buffer
      }
      if (persistence_.save(CampaignPersistRole::TargetRepairAuthorization, repairEncoded, repairEncodedLen) !=
          CampaignSaveResult::Saved) {
        // Main record IS now erased, but without a durably-confirmed
        // repair-authorization record a future reload() cannot safely
        // distinguish this from unexplained loss -- stay latched; the
        // caller may retry (erase() is idempotent on an already-erased
        // record).
        return false;
      }
    }
    reloadUnsafe_ = false;
    resetToFreshIdle();
    lastRefusal_ = CampaignRefusalReason::None;
    return true;
  }


private:
  // True while a prior corrupt/unreadable/uncertain durable record has
  // not yet been resolved -- ALL mutating operations (new admission,
  // descriptor-fragment reassembly, chunk application, verify/commit,
  // abort) must refuse rather than risk mutating stale/unsafe RAM.
  bool blockedByUnresolvedPersistence() {
    if (reloadUnsafe_ || persistUncertain_) {
      lastRefusal_ = CampaignRefusalReason::UnresolvedPersistedState;
      return true;
    }
    return false;
  }

  // True only when the single pending-consent RAM slot has gone
  // completely silent (no ConsentRequest retry / fragment progress) for
  // at least kCampaignPendingConsentExpiryMs. With no clock bound, we
  // cannot safely measure elapsed time, so this always fails toward
  // "not expired" (never erase a possibly-still-active attempt just
  // because the engine happens to run without a clock port).
  bool pendingConsentExpired() const {
    if (clock_ == nullptr) return false;
    return campaignElapsedAtLeast(clock_->nowMs(), pendingLastActivityMs_, kCampaignPendingConsentExpiryMs);
  }

  // Resets all in-memory state to a genuinely fresh Idle instance
  // (used both by a confirmed-Missing reload() and by
  // acknowledgeUnsafeReloadAndReset() after a confirmed erase). Does not
  // touch reloadUnsafe_/lastRefusal_ -- callers set those explicitly per
  // their own semantics.
  void resetToFreshIdle() {
    bound_ = false;
    everBound_ = false;
    status_ = TargetStatus::Idle;
    lastFrameSeq_ = 0;
    replayWindowMask_ = 0;
    persistUncertain_ = false;
    persisted_ = CampaignTargetPersistedState{};
    descriptor_ = protocol::OtaDescriptor{};
    geometry_ = runtime::OtaGeometry{};
    controllerId_ = CampaignPeerId{};
    groupId_ = 0;
    bitmap_.reset(0);
    receiver_.reset();
    clearPendingAdmissionAndReply();
  }

  // A reload() (whether it lands on a genuinely fresh Idle record or a
  // resumed mid-transfer one) authoritatively re-derives ALL runtime
  // state from the durable winning record. Any in-flight
  // descriptor-fragment reassembly or a queued outbound reply that
  // existed BEFORE this reload() necessarily refers to identity/session
  // facts from before the durable truth was (re-)established, and must
  // never be allowed to complete/retry using stale bindings once reload()
  // has run -- clearing it here is not a mutation of durable state, only
  // of transient RAM bookkeeping that a reload() must always own outright.
  void clearPendingAdmissionAndReply() {
    pendingActive_ = false;
    pendingSession_ = runtime::OtaSessionId{};
    pendingPayload_ = CampaignConsentRequestPayload{};
    pendingReassembler_.reset();
    pendingFragmentReceivedMask_ = 0;
    pendingLastActivityMs_ = 0;
    pendingReply_.active = false;
  }



  // Bounded anti-replay window check (see kCampaignReplayWindowSize):
  // accepts `seq` if it is either newer than everything seen so far, or
  // legitimately unseen-but-within-window behind the current highest
  // (real network reordering) -- rejects only an EXACT duplicate of an
  // already-recorded sequence, or one too far behind the window to track.
  // Pure function: never mutates any member, so callers can compute the
  // candidate's next (lastFrameSeq, replayWindowMask) and only durably
  // commit it on a successful persist, mirroring this engine's existing
  // "no ACK without a durable commit" discipline.
  static bool replayWindowCheck(uint32_t currentLastFrameSeq, uint32_t currentMask, uint32_t seq,
                                 uint32_t& outLastFrameSeq, uint32_t& outMask) {
    return campaignReplayWindowCheck(currentLastFrameSeq, currentMask, seq, outLastFrameSeq, outMask);
  }

  static bool descriptorBytesEqual(const protocol::OtaDescriptor& a, const protocol::OtaDescriptor& b) {
    uint8_t ca[protocol::kOtaDescriptorCanonicalSize];
    uint8_t cb[protocol::kOtaDescriptorCanonicalSize];
    size_t la = 0, lb = 0;
    if (protocol::encodeOtaDescriptorCanonical(a, ca, sizeof(ca), la) != protocol::OtaDescriptorCodecResult::Ok) return false;
    if (protocol::encodeOtaDescriptorCanonical(b, cb, sizeof(cb), lb) != protocol::OtaDescriptorCodecResult::Ok) return false;
    return la == lb && std::memcmp(ca, cb, la) == 0;
  }

  bool bitmapWouldBeComplete(const CampaignTargetPersistedState& candidate) const {
    for (uint32_t i = 0; i < geometry_.chunkCount; ++i) {
      if ((candidate.bitmap[i / 8] & (1u << (i % 8))) == 0) return false;
    }
    return geometry_.chunkCount > 0;
  }

  // Sends one autonomous protocol reply to the currently-bound controller
  // (always Pairwise -- Target replies never use Group scope even if the
  // triggering inbound traffic was Group-scoped bulk delivery). A no-op
  // if no transport is bound or no binding exists yet. On Backpressure/
  // BudgetDenied/Rejected, the bit-identical encoded frame is latched
  // into the single-slot pending-reply retry queue (see PendingReply)
  // instead of being silently dropped -- tick() retries it once the
  // clock-driven timeout elapses; queued != delivered, so this reply
  // path never fabricates an ACK the peer did not actually receive.
  void sendReply(CampaignMessageType type, const uint8_t* payload, size_t payloadLen) {
    if (!bound_) return;
    sendReplyTo(controllerId_, persisted_.session, type, payload, payloadLen);
  }

  // Sends to an EXPLICIT destination/session, independent of bound_/
  // controllerId_. Used for any reply that must target the actual
  // captured authenticated request context of the specific attempt being
  // answered (e.g. a pre-admission consent denial, or a denial that
  // happens to occur while this engine is already bound to a DIFFERENT
  // controller) rather than whatever this engine currently considers
  // itself bound to. Shares the exact same backpressure/retry-latching
  // path as the bound-controller sendReply() above.
  void sendReplyTo(const CampaignPeerId& dest, const runtime::OtaSessionId& session, CampaignMessageType type,
                     const uint8_t* payload, size_t payloadLen) {
    if (transport_ == nullptr) return;
    CampaignEnvelopeHeader hdr;
    hdr.type = type;
    hdr.session = session;
    hdr.frameSeq = ++outboundFrameSeq_;
    uint8_t frame[protocol::kOtaMaxFrameSize];
    size_t frameLen = 0;
    if (encodeCampaignEnvelope(hdr, payload, payloadLen, frame, sizeof(frame), frameLen) != CampaignCodecResult::Ok) {
      return;
    }
    CampaignDestination d;
    d.scope = CampaignAuthScope::Pairwise;
    d.peerId = dest;
    CampaignSendResult result = transport_->trySend(d, protocol::OtaAirtimeCategory::Control, frame, frameLen);
    latchPendingReplyOnFailure(result, d, protocol::OtaAirtimeCategory::Control, frame, frameLen);
  }


  void latchPendingReplyOnFailure(CampaignSendResult result, const CampaignDestination& dest,
                                   protocol::OtaAirtimeCategory category, const uint8_t* frame, size_t frameLen) {
    if (result == CampaignSendResult::Enqueued) {
      pendingReply_.active = false; // this attempt is now the transport's problem, not ours to retry
      return;
    }
    pendingReply_.active = true;
    pendingReply_.frameLen = (frameLen <= sizeof(pendingReply_.frame)) ? frameLen : sizeof(pendingReply_.frame);
    std::memcpy(pendingReply_.frame, frame, pendingReply_.frameLen);
    pendingReply_.dest = dest;
    pendingReply_.category = category;
    pendingReply_.lastAttemptMs = clock_ != nullptr ? clock_->nowMs() : 0;
  }

  // Bounded, non-blocking periodic work: retries a latched pending reply
  // once the clock-driven timeout has elapsed since the last attempt (or
  // immediately, every call, if no clock is bound). Does exactly ONE
  // bounded unit of retry work per call -- never busy-loops, never
  // fabricates delivery on a repeated Backpressure/BudgetDenied result.
  void retryPendingReply() {
    if (!pendingReply_.active || transport_ == nullptr) return;
    uint32_t now = clock_ != nullptr ? clock_->nowMs() : pendingReply_.lastAttemptMs;
    if (clock_ != nullptr && !campaignElapsedAtLeast(now, pendingReply_.lastAttemptMs, kCampaignReplyRetryTimeoutMs)) {
      return;
    }
    CampaignSendResult result = transport_->trySend(pendingReply_.dest, pendingReply_.category,
                                                      pendingReply_.frame, pendingReply_.frameLen);
    pendingReply_.lastAttemptMs = now;
    if (result == CampaignSendResult::Enqueued) pendingReply_.active = false;
  }

  void sendConsentGrant(const CampaignPeerId& dest, const runtime::OtaSessionId& session, bool accepted,
                         CampaignRefusalReason reason) {
    CampaignConsentGrantPayload grant;
    grant.granted = accepted ? 1 : 0;
    grant.refusalReason = static_cast<uint8_t>(reason);
    grant.maxInFlightChunks = kCampaignMaxInFlightChunks;
    uint8_t payload[kCampaignConsentGrantSize];
    size_t payloadLen = 0;
    if (!encodeCampaignConsentGrant(grant, payload, sizeof(payload), payloadLen)) return;
    sendReplyTo(dest, session, CampaignMessageType::ConsentGrant, payload, payloadLen);
  }

  void sendReceipt(protocol::OtaReceiptStatus status, uint32_t chunkIndex) {
    protocol::OtaReceiptPayload r{status, chunkIndex, 0, 0};
    uint8_t payload[protocol::kOtaMaxFrameSize];
    size_t payloadLen = 0;
    if (!protocol::encodeOtaReceipt(r, payload, sizeof(payload), payloadLen)) return;
    sendReply(CampaignMessageType::Receipt, payload, payloadLen);
  }

  bool requirePairwiseBoundController(const AuthenticatedInboundFrame& frame, const runtime::OtaSessionId& id) {
    if (!frame.hasAuthenticatedPeer()) {
      lastRefusal_ = CampaignRefusalReason::UntrustedContext;
      return false;
    }
    if (!bound_ || frame.pairwise()->peerId != controllerId_) {
      lastRefusal_ = CampaignRefusalReason::ForeignController;
      return false;
    }
    if (!runtime::otaSessionEquals(id, persisted_.session)) {
      // Same controller, but a DIFFERENT (wrong/stale/foreign) session id
      // must never be allowed to commit/abort the currently-bound
      // transaction.
      lastRefusal_ = CampaignRefusalReason::ForeignSession;
      return false;
    }
    return true;
  }

  // Best-effort phase transition used only on an already-failing path
  // (hash mismatch / staging commit failure) where the transfer is being
  // abandoned regardless; failure to persist here does not change the
  // fact that the operation being reported to the caller already failed.
  void setPhaseBestEffort(TargetStatus s) {
    CampaignTargetPersistedState candidate = persisted_;
    candidate.phase = static_cast<uint8_t>(s);
    commitPersist(candidate);
  }

  // Phase transition that itself constitutes the durable ACK (Installed/
  // InstalledPending/Aborted) -- failure here must be surfaced, not
  // silently swallowed.
  bool setPhaseDurable(TargetStatus s) {
    CampaignTargetPersistedState candidate = persisted_;
    candidate.phase = static_cast<uint8_t>(s);
    return commitPersist(candidate);
  }

  // Single choke point for every durable mutation: computes the CRC,
  // attempts the save, and ONLY on a confirmed Saved result mirrors the
  // candidate into every piece of in-memory state (persisted_, bitmap_,
  // status_, controllerId_, groupId_, descriptor_, geometry_,
  // lastFrameSeq_, bound_, everBound_).
  //
  // RejectedBeforeMutation: storage is provably unchanged -- in-memory
  // state stays exactly as it was, same as before.
  //
  // Uncertain: bytes MAY have landed durably even though the port could
  // not confirm it. This must NOT be treated as an ack (no in-memory
  // progress advances to the candidate), but the old in-memory state must
  // ALSO stop being trusted enough to admit a new/competing
  // controller/session on top of it -- latches persistUncertain_, which
  // freezes all new admission (handleConsentRequest) until an explicit
  // reload() reconstructs state from whatever is ACTUALLY durable.
  bool commitPersist(CampaignTargetPersistedState& candidate) {
    // Recompute geometry from the candidate's OWN canonical descriptor
    // bytes before ever persisting or mirroring it -- catches an
    // internally-inconsistent candidate (e.g. a stray chunkCount out of
    // step with its descriptor) here rather than letting it become a
    // durable or in-memory invariant violation.
    protocol::OtaDescriptor decodedDescriptor{};
    if (protocol::decodeOtaDescriptorCanonical(candidate.descriptorCanonical, sizeof(candidate.descriptorCanonical),
                                                decodedDescriptor) != protocol::OtaDescriptorCodecResult::Ok) {
      return false;
    }
    runtime::OtaGeometry recomputedGeometry;
    if (runtime::OtaGeometry::compute(decodedDescriptor.exactSizeBytes, runtime::kOtaDefaultChunkPayloadSize,
                                       runtime::kOtaMaxImageBytes, recomputedGeometry) != runtime::OtaGeometryResult::Ok) {
      return false;
    }
    if (recomputedGeometry.chunkCount != candidate.chunkCount) { return false; }

    // Explicit fixed-width, field-by-field big-endian encode (see
    // encodeCampaignTargetPersistedState above) -- never a raw
    // memcpy/reinterpret_cast of the native struct, so the durable bytes
    // are portable across any build/process/endianness that later calls
    // reload().
    uint8_t encoded[kCampaignTargetPersistEncodedSize];
    size_t encodedLen = 0;
    if (!encodeCampaignTargetPersistedState(candidate, encoded, sizeof(encoded), encodedLen)) { return false; }
    CampaignSaveResult result = persistence_.save(CampaignPersistRole::TargetReceiver, encoded, encodedLen);
    if (result == CampaignSaveResult::Uncertain) {
      persistUncertain_ = true;
      return false;
    }
    if (result != CampaignSaveResult::Saved) {
      return false;
    }
    persisted_ = candidate;
    bound_ = (candidate.bound != 0);
    everBound_ = everBound_ || (candidate.everBound != 0);
    std::memcpy(controllerId_.bytes, candidate.controllerId, 32);
    groupId_ = candidate.groupId;
    descriptor_ = decodedDescriptor;
    geometry_ = recomputedGeometry;
    lastFrameSeq_ = candidate.lastFrameSeq;
    replayWindowMask_ = candidate.replayWindowMask;
    status_ = static_cast<TargetStatus>(candidate.phase);
    bitmap_.reset(geometry_.chunkCount);
    for (uint32_t i = 0; i < geometry_.chunkCount; ++i) {
      if ((candidate.bitmap[i / 8] & (1u << (i % 8))) != 0) bitmap_.set(i);
    }
    return true;
  }

  runtime::IOtaTrustProvider& trust_;
  runtime::IOtaStagingSink& staging_;
  ICampaignPersistencePort& persistence_;
  IBootEvidencePort& bootEvidence_;
  IConsentPolicyPort& consentPolicy_;
  ICampaignCommissioningProvenancePort& commissioningProvenance_;
  IAuthenticatedTransportPort* transport_ = nullptr; // optional: bindTransport() enables autonomous replies
  IClockPort* clock_ = nullptr;                      // optional: bindClock() enables timed reply retry
  IOtaStagingResumePort* stagingResume_ = nullptr;    // optional: bindStagingResume() enables non-destructive resume
  uint32_t outboundFrameSeq_ = 0;

  runtime::OtaReceiverStateMachine receiver_;
  runtime::OtaMaxImageBitmap bitmap_;
  protocol::OtaDescriptor descriptor_{};
  runtime::OtaGeometry geometry_{};
  CampaignPeerId controllerId_{};
  uint32_t groupId_ = 0;
  bool bound_ = false;
  bool everBound_ = false;
  bool reloadUnsafe_ = false;
  // Latched by commitPersist() on an Uncertain save result: a write MAY
  // have landed durably but could not be confirmed. Freezes all new
  // admission (same semantics as reloadUnsafe_) until an explicit
  // reload() reconstructs authoritative state from whatever is ACTUALLY
  // durable -- see CampaignSaveResult::Uncertain and commitPersist().
  bool persistUncertain_ = false;
  uint32_t lastFrameSeq_ = 0;
  uint32_t replayWindowMask_ = 0;
  TargetStatus status_ = TargetStatus::Idle;
  CampaignRefusalReason lastRefusal_ = CampaignRefusalReason::None;
  CampaignTargetPersistedState persisted_{};

  bool pendingActive_ = false;
  runtime::OtaSessionId pendingSession_{};
  CampaignConsentRequestPayload pendingPayload_{};
  protocol::OtaDescriptorReassembler pendingReassembler_;
  // Engine-side shadow of which fragment indices this pending attempt has
  // already accepted (the reassembler itself exposes no public "already
  // received this index" query) -- used solely to detect a differing-
  // bytes duplicate resend before it ever reaches addFragment(). Bounded
  // to 32 bits: fragCount for the pending descriptor+signature blob never
  // exceeds that (kOtaMaxFrameSize-sized fragments of a small fixed blob).
  uint32_t pendingFragmentReceivedMask_ = 0;
  // Last time (per clock_) this pending ticket saw genuine activity
  // (opened, retried via an identical ConsentRequest, or accepted a new
  // fragment) -- used only to bound how long an abandoned/stale pending
  // attempt may hold its single RAM slot; never consulted while the
  // SAME ticket keeps making progress.
  uint32_t pendingLastActivityMs_ = 0;

  // Single-slot pending-reply retry queue: sendReply() latches the exact
  // already-encoded bytes here on any non-Enqueued send result (instead
  // of silently dropping them), and tick() retries the SAME bytes
  // (same frameSeq, bit-identical) once kCampaignReplyRetryTimeoutMs has
  // elapsed since the last attempt. A newer reply attempt (e.g. triggered
  // by yet another retried inbound request) simply overwrites this single
  // slot -- acceptable because the peer's own request-retry/timeout loop
  // will re-trigger whatever reply is actually still needed.
  struct PendingReply {
    bool active = false;
    uint8_t frame[protocol::kOtaMaxFrameSize] = {};
    size_t frameLen = 0;
    CampaignDestination dest{};
    protocol::OtaAirtimeCategory category = protocol::OtaAirtimeCategory::Control;
    uint32_t lastAttemptMs = 0;
  };
  PendingReply pendingReply_{};
};

} // namespace campaign
} // namespace ota
} // namespace meshcore
