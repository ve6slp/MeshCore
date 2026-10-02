#pragma once

// Single authoritative definition of the lean local-USB OTA uploader/
// status wire contract, carried as new CMD_OTA_CONTROL (CMD66) subops
// 0x10..0x18 (existing subops 0..5 -- GET_STATUS/SET_MODE/SET_DUTY/
// ABORT/ROLLBACK/DIRECT_LEASE -- stay wire-unchanged/legacy-compatible;
// see examples/companion_radio/MyMesh.cpp). Outer framing (the existing
// '<' + LE16 length + payload / '>' reply FramedSerial envelope) is
// completely unchanged; every NEW multi-byte integer INSIDE this
// contract (both request bodies and the fixed 86-byte reply below) is
// BIG-ENDIAN, unlike the rest of the pre-existing companion command set
// (which is little-endian) -- this is a deliberate, explicit exception
// scoped to only these new opcodes, not a repo-wide convention change.
//
// This header defines ONLY the wire shapes/constants/codec helpers --
// DELIBERATE ABI DEVIATION from the earlier draft: CacheBegin now carries
// ownerPublicKey32 between flagsU8 and canonical59 so a receiver can verify
// the manifest signature against the claimed owner key and independently
// check that key against its real admin-authority policy.
// it intentionally does NOT revive any commissioning/OPEN/CHALLENGE
// session concept, and does not itself implement the local flash-backed
// uploader cache (see MyMesh.cpp's CMD_OTA_CONTROL handler for current
// wiring status/limitations per op).

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace mesh {
namespace ota {
namespace usb {

constexpr uint8_t kCommand = 66;

// Fixed reply "response code" (byte [0] of every reply to one of the
// opcodes below) -- RESP_CODE_OTA_USB in the companion response-code
// space (31 was unused across RESP_CODE_OK..RESP_CODE_OTA_LAB_FLOOR_DATA
// at the time this contract was defined; see MyMesh.cpp's RESP_CODE_*
// list). The existing ASCII CMD_OTA_CONTROL op 0 (GET_STATUS) reply
// (RESP_CODE_OTA_STATUS=29) is completely unchanged -- hosts must filter
// by (byte[0]==31 AND byte[2]==requested op AND, where applicable,
// byte[6..38) == requested target), never by byte[0]==31 alone.
constexpr uint8_t kReplyCode = 31;

// Wire ABI version stamped into every reply's byte[1], so a host can
// detect a future incompatible revision of this fixed layout without
// guessing from reply length alone.
constexpr uint8_t kAbiVersion = 1;

constexpr size_t kPubKeyBytes = 32;
constexpr size_t kHashBytes = 32;
constexpr size_t kSignatureBytes = 64;
constexpr size_t kCanonicalManifestBytes = 59; // same 59-byte canonical wire descriptor used elsewhere in this codebase.

// New CMD_OTA_CONTROL subop byte values (cmd_frame[1]). Existing
// subops 0..5 (GET_STATUS/SET_MODE/SET_DUTY/ABORT/ROLLBACK/
// DIRECT_LEASE, see MyMesh.cpp's OTA_CTRL_* defines) are untouched and
// are NOT redefined here.
enum class UsbOtaOp : uint8_t {
  CacheBegin      = 0x10, // flagsU8 + ownerPublicKey32 + canonical59 + signature64 => 158B total (incl. cmd+op)
  CachePut        = 0x11, // blockIndexBE16 + dataLenU8 + data[1..84]      => up to 89B total
  CacheSeal       = 0x12, // no body                                      => 2B total
  AddTarget       = 0x13, // targetPubKey32                                => 34B total
  Start           = 0x14, // modeU8+channelU8+freqKHzBE32+leaseMsBE16+dutyMilliPercentBE32 => 14B total
  Commit          = 0x15, // targetPubKey32 + manifestHash32 + counterBE32 => 70B total
  Abort           = 0x16, // targetPubKey32 + imageHash32                  => 66B total
  Status          = 0x17, // targetPubKey32 (all-zero => local cache)      => 34B total
  SetContactAdmin = 0x18, // contactPubKey32 + enabledU8                   => 35B total
};

// CACHE_BEGIN flags byte (request body byte 0).
constexpr uint8_t kCacheBeginFlagReupload = 0x01; // explicit restart; active owner/content/purpose checks still apply.

// START mode byte (request body byte 0).
constexpr uint8_t kStartModeDirect     = 0; // off-frequency direct high-speed negotiation; exactly 1 selected target.
constexpr uint8_t kStartModeDirected   = 1; // directed routed delivery; exactly 1 selected target.
constexpr uint8_t kStartModeBackground = 2; // background multicast + census + selective repair; 1..32 selected targets.
constexpr uint8_t kStartChannelDirectedOrDirect = 0xFF; // placeholder channel byte required for modes 0/1.

// START direct-mode bounds (mode 0 ONLY; modes 1/2 require frequency=0,
// lease=0 -- see Start handling). The on-mesh airtime/duty SHARE is a
// caller-configured value for ALL modes (not a fixed constant): it
// reuses the existing supported duty-cycle control semantics/bounds
// already enforced by setFirmwareOtaDutyCycle()/getFirmwareOtaDutyCycle()
// elsewhere in this codebase, and the selected share must actually be
// enforced by the sender (airtime-fairness budget), not merely echoed.
// 2.000% is only the DEFAULT/test value a caller may choose to pass for
// background/directed modes -- it is never the only permitted value.
constexpr uint32_t kDirectLeaseMsMin = 250;
constexpr uint32_t kDirectLeaseMsMax = 60000;
constexpr uint32_t kDutyMilliPercentMin = 0;      // 0.000% (paused) remains valid where the existing control path supports it.
constexpr uint32_t kDutyMilliPercentMax = 100000; // 100.000%
constexpr uint32_t kDefaultDutyMilliPercent = 2000; // default/test convenience value ONLY, not enforced-exclusive.

constexpr size_t kMaxSelectedTargets = 32;

// Fixed per-operation total wire sizes (including the leading
// cmd_frame[0]==CMD_OTA_CONTROL and cmd_frame[1]==op bytes), for callers
// validating `len` before touching a request body.
constexpr size_t kCacheBeginTotalBytes      = 2 + 1 + kPubKeyBytes + kCanonicalManifestBytes + kSignatureBytes; // 158
constexpr size_t kCachePutMinTotalBytes     = 2 + 2 + 1 + 1;                                      // 6  (1-byte data minimum)
constexpr size_t kCachePutMaxTotalBytes     = 2 + 2 + 1 + 84;                                     // 89
constexpr size_t kCacheSealTotalBytes       = 2;                                                  // 2
constexpr size_t kAddTargetTotalBytes       = 2 + kPubKeyBytes;                                   // 34
constexpr size_t kStartTotalBytes           = 2 + 1 + 1 + 4 + 2 + 4;                              // 14
constexpr size_t kCommitTotalBytes          = 2 + kPubKeyBytes + kHashBytes + 4;                  // 70
constexpr size_t kAbortTotalBytes           = 2 + kPubKeyBytes + kHashBytes;                      // 66
constexpr size_t kStatusTotalBytes          = 2 + kPubKeyBytes;                                   // 34
constexpr size_t kSetContactAdminTotalBytes = 2 + kPubKeyBytes + 1;                                // 35

enum class UsbOtaResult : uint8_t {
  Ok           = 0,
  Pending      = 1,
  Busy         = 2,
  BadRequest   = 3,
  Denied       = 4,
  Unavailable  = 5,
  IoError      = 6,
  Mismatch     = 7,
  Incomplete   = 8,
  NotFound     = 9,
  TooLate      = 10,
  BudgetDenied = 11,
  Unsupported  = 12,
};

enum class UsbOtaPhase : uint8_t {
  Unknown       = 0,
  Idle          = 1,
  Erasing       = 2,
  Receiving     = 3,
  Verifying     = 4,
  Ready         = 5,
  CommitPending = 6,
  Trial         = 7,
  Installed     = 8,
  Aborted       = 9,
  Failed        = 10,
  CacheSealed   = 11,
};

// Reply flags byte (reply byte [5]).
constexpr uint8_t kReplyFlagSnapshotValid = 0x01;
constexpr uint8_t kReplyFlagRemote        = 0x02;

// Sentinel "no snapshot age known" value for reply bytes [78..82).
constexpr uint32_t kStatusAgeUnknown = 0xFFFFFFFFu;

constexpr size_t kReplyBytes = 86;

inline void putBE16(uint8_t* out, uint16_t v) {
  out[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
  out[1] = static_cast<uint8_t>(v & 0xFF);
}

inline void putBE32(uint8_t* out, uint32_t v) {
  out[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
  out[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
  out[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
  out[3] = static_cast<uint8_t>(v & 0xFF);
}

inline uint16_t getBE16(const uint8_t* in) {
  return static_cast<uint16_t>((static_cast<uint16_t>(in[0]) << 8) | in[1]);
}

inline uint32_t getBE32(const uint8_t* in) {
  return (static_cast<uint32_t>(in[0]) << 24) | (static_cast<uint32_t>(in[1]) << 16) |
         (static_cast<uint32_t>(in[2]) << 8) | static_cast<uint32_t>(in[3]);
}

// Plain working struct for the fixed 86-byte reply; see field offsets
// documented above each member. `target`/`manifestHash` are the raw 32-
// byte values (all-zero target legitimately means "local cache", never
// encoded/decoded specially).
struct UsbOtaReply {
  uint8_t requestOp = 0;
  UsbOtaResult result = UsbOtaResult::Unavailable;
  UsbOtaPhase phase = UsbOtaPhase::Unknown;
  uint8_t flags = 0; // kReplyFlagSnapshotValid / kReplyFlagRemote
  uint8_t target[kPubKeyBytes] = {0};
  // Generic 32-byte hash slot, reused per request-op context: COMMIT/
  // STATUS/CacheBegin echo manifestHash32 (SHA256 of canonical59);
  // ABORT echoes imageHash32 (descriptor.sha256, content hash) -- see
  // the HASH SEMANTICS note above buildCommitSignedMessage(). Never
  // both at once; callers must interpret per their own request op.
  // NoSnapshot always clears this slot; request echoes are not snapshots.
  uint8_t manifestHash[kHashBytes] = {0};
  uint16_t durableReceivedBlocks = 0;
  uint16_t totalBlocks = 0;
  uint32_t counter = 0;
  uint32_t statusAgeMs = kStatusAgeUnknown;
  uint32_t retryAfterMs = 0;

  // Sets this reply to the canonical "no snapshot" shape required by the
  // contract: flags bit0 clear, phase Unknown, hash/counts/counter zero,
  // age kStatusAgeUnknown -- callers must not hand-roll this elsewhere.
  void setNoSnapshot() {
    phase = UsbOtaPhase::Unknown;
    flags &= static_cast<uint8_t>(~kReplyFlagSnapshotValid);
    std::memset(manifestHash, 0, sizeof(manifestHash));
    durableReceivedBlocks = 0;
    totalBlocks = 0;
    counter = 0;
    statusAgeMs = kStatusAgeUnknown;
  }
};

// Encodes `reply` into the fixed kReplyBytes-byte wire layout at `out`
// (caller-owned buffer, must be >= kReplyBytes). Returns kReplyBytes.
// NoSnapshot canonicalization preserves the operation, scope, target, result and retry.
inline size_t encodeUsbOtaReply(const UsbOtaReply& input, uint8_t* out) {
  UsbOtaReply reply = input;
  if ((reply.flags & kReplyFlagSnapshotValid) == 0) reply.setNoSnapshot();
  out[0] = kReplyCode;
  out[1] = kAbiVersion;
  out[2] = reply.requestOp;
  out[3] = static_cast<uint8_t>(reply.result);
  out[4] = static_cast<uint8_t>(reply.phase);
  out[5] = reply.flags;
  std::memcpy(&out[6], reply.target, kPubKeyBytes);
  std::memcpy(&out[38], reply.manifestHash, kHashBytes);
  putBE16(&out[70], reply.durableReceivedBlocks);
  putBE16(&out[72], reply.totalBlocks);
  putBE32(&out[74], reply.counter);
  putBE32(&out[78], reply.statusAgeMs);
  putBE32(&out[82], reply.retryAfterMs);
  return kReplyBytes;
}

// Ed25519 commit-signature domain, exactly ASCII, deliberately WITHOUT a
// trailing NUL (the signed byte range is domain || targetPubKey32 ||
// manifestHash32 || counterBE32 -- nothing else). Binding the full
// 32-byte target identity AND the full manifest hash AND the counter
// means a commit signature captured for one physical unit's attempt can
// never be replayed to commit a different unit, even sharing the same
// image/fleet (short RF destination-address prefixes used for routing
// are NEVER part of what is signed or verified here).
//
// HASH SEMANTICS (deliberately two distinct hashes, never interchanged):
//   manifestHash32 (COMMIT) = SHA256(exact canonical59 manifest bytes) --
//     identifies the SIGNED DESCRIPTOR a candidate was admitted under.
//   imageHash32   (ABORT)  = descriptor.sha256 (the firmware's own
//     content hash carried inside the manifest) -- identifies the
//     FIRMWARE CONTENT itself, independent of which manifest wrapped it.
// ABORT intentionally signs/stores/suppresses by imageHash32 (content),
// not manifestHash32 (descriptor encoding), because the "ignored image"
// suppression (a single stored ignored-hash until explicit admin Begin/
// reupload/local clear) must survive the SAME firmware being re-offered
// under a different but equivalent manifest encoding -- it is a content-
// level block, not a descriptor-encoding-level block. This distinction
// must stay consistent end-to-end: whatever hash is signed here is the
// SAME hash persisted and later checked against inbound background
// frames before suppression is lifted.
constexpr char kCommitDomain[] = "MeshCore/OTA/commit/v1";
constexpr size_t kCommitDomainLen = sizeof(kCommitDomain) - 1; // drop implicit NUL from the string literal.
constexpr size_t kCommitSignedBytes = kCommitDomainLen + kPubKeyBytes + kHashBytes + 4;

// Fills `out` (>= kCommitSignedBytes) with the exact byte sequence that
// must be Ed25519-signed/verified for a COMMIT -- domain || target32 ||
// manifestHash32 || counterBE32.
inline size_t buildCommitSignedMessage(const uint8_t target[kPubKeyBytes], const uint8_t manifestHash[kHashBytes],
                                       uint32_t counter, uint8_t* out) {
  size_t i = 0;
  std::memcpy(&out[i], kCommitDomain, kCommitDomainLen); i += kCommitDomainLen;
  std::memcpy(&out[i], target, kPubKeyBytes); i += kPubKeyBytes;
  std::memcpy(&out[i], manifestHash, kHashBytes); i += kHashBytes;
  putBE32(&out[i], counter); i += 4;
  return i;
}

// ABORT's own domain (distinct from COMMIT's, deliberately: an admin's
// ABORT authority check is "currently trusted admin", NOT "the original
// owner" required for COMMIT -- reusing COMMIT's domain string would
// blur that different authorization rule even though the byte SHAPE
// happens to be similar). Signed bytes = domain || target32 ||
// imageHash32 (the content hash, see note above -- NOT manifestHash32).
constexpr char kAbortDomain[] = "MeshCore/OTA/abort/v1";
constexpr size_t kAbortDomainLen = sizeof(kAbortDomain) - 1;
constexpr size_t kAbortSignedBytes = kAbortDomainLen + kPubKeyBytes + kHashBytes;

// Fills `out` (>= kAbortSignedBytes) with the exact byte sequence that
// must be Ed25519-signed/verified for a per-target ABORT -- domain ||
// target32 || imageHash32.
inline size_t buildAbortSignedMessage(const uint8_t target[kPubKeyBytes], const uint8_t imageHash[kHashBytes],
                                      uint8_t* out) {
  size_t i = 0;
  std::memcpy(&out[i], kAbortDomain, kAbortDomainLen); i += kAbortDomainLen;
  std::memcpy(&out[i], target, kPubKeyBytes); i += kPubKeyBytes;
  std::memcpy(&out[i], imageHash, kHashBytes); i += kHashBytes;
  return i;
}

}  // namespace usb
}  // namespace ota
}  // namespace mesh
