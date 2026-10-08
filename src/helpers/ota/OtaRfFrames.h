#pragma once

// Real-mesh (not USB-local) signed OTA control frames: Authorization,
// Commit, Abort, and an unsigned informational StatusReport, carried as
// PAYLOAD_TYPE_LORA_OTA packets exactly like the existing SignedBlock
// frame (see OtaBlockSigning.h's kOtaSignedBlockKind=0x01). Every
// authority-bearing frame here reuses the SAME Ed25519 signed-message
// constructions already defined for the USB ABI (mesh::ota::usb::
// buildCommitSignedMessage/buildAbortSignedMessage) -- no new signing
// domain or encoding is invented; relaying one of these frames
// unmodified across hops is exactly "the original signer's authority",
// never re-derived by an intermediate relay.
//
// Frame kinds (byte 0), chosen to never collide with the legacy
// envelope codec's required namespace magic 'O'=0x4F at byte 0 (see
// OtaWireTypes.h kOtaNamespaceId) or with kOtaSignedBlockKind=0x01:
//   0x02 Authorization -- establishes/resumes the single admitted
//        candidate+owner on a RF-only receiver (no USB present). Carries
//        the FULL 32-byte owner public key on the wire: PAYLOAD_TYPE_
//        LORA_OTA packets carry no implicit sender identity (unlike
//        PAYLOAD_TYPE_REQ/GRP_DATA's pairwise/group decrypt), so the
//        signer can only be established from an explicit key field, per
//        the "or a full PK32 field for multicast" requirement -- applied
//        uniformly to direct/routed/multicast since none of these modes
//        give the OTA layer an authenticated sender identity for this
//        payload type.
//   0x03 Commit -- target-bound, signed by the ORIGINAL manifest owner
//        (OtaLeanReceiver::commit() already enforces this by verifying
//        against the already-admitted candidate_.ownerPublicKey).
//   0x04 Abort -- target/generation-bound, signed by ANY current admin (carries its
//        own signer key on the wire, since the aborting admin need not
//        be the original owner).
//   0x06 StatusReport -- unsigned, informational only (receiver's own
//        progress telemetry back onto the mesh); carries no authority
//        and can never admit/mutate/commit/abort anything by itself --
//        a forged one is harmless (worst case: a sender wastes airtime
//        resending already-received blocks, which the receiver's
//        existing idempotent per-index bitmap already absorbs for free).

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <helpers/ota/OtaBlockSigning.h>
#include <helpers/ota/OtaDirectRadioProfile.h>
#include <helpers/ota/OtaUsbProtocol.h>

namespace mesh {
namespace ota {

static constexpr uint8_t kOtaAuthorizationKind = 0x02u;
static constexpr uint8_t kOtaCommitKind = 0x03u;
static constexpr uint8_t kOtaAbortKind = 0x04u;
static constexpr uint8_t kOtaStatusReportKind = 0x06u;
static constexpr uint8_t kOtaStatusPollKind = 0x07u;
static constexpr uint8_t kOtaTargetAuthorizationKind = 0x08u;
static constexpr uint8_t kOtaCensusPollKind = 0x0Au;
static constexpr uint8_t kOtaCensusReportKind = 0x0Bu;
static constexpr uint8_t kOtaDirectRequestKind = 0x0Cu;
static constexpr uint8_t kOtaDirectAckKind = 0x0Du;
static constexpr uint8_t kOtaReuploadKind = 0x0Eu;
static constexpr uint8_t kOtaDirectProfileRequestKind = 0x0Fu;
static constexpr uint8_t kOtaDirectProfileAckKind = 0x10u;
static constexpr size_t kOtaCensusWindowBlocks = 128;
static constexpr size_t kOtaCensusBitmapBytes = kOtaCensusWindowBlocks / 8;
static constexpr size_t kOtaCensusPollBytes = 67;
// Only the nonce-bound v3 report is accepted; 92B/102B reports come from
// receivers that cannot authorize COMMIT/lease under the current domains.
static constexpr size_t kOtaCensusReportBytes = 123;
static constexpr size_t kOtaDirectFrameBytes = 171;
static constexpr size_t kOtaReuploadFrameBytes = 165;

inline void otaTargetTag(const uint8_t target[32], uint8_t out[8]) {
  uint8_t hash[32];
  ::ota::trust::Sha256::hash(target, 32, hash);
  std::memcpy(out, hash, 8);
}

inline size_t encodeOtaTargetAuthorization(const uint8_t target[32], const uint8_t owner[32],
                                           const uint8_t canonical[59], const uint8_t signature[64],
                                           uint8_t* out, size_t capacity) {
  if (!out || capacity < 164) return 0;
  out[0] = kOtaTargetAuthorizationKind;
  otaTargetTag(target, out + 1);
  std::memcpy(out + 9, owner, 32);
  std::memcpy(out + 41, canonical, 59);
  std::memcpy(out + 100, signature, 64);
  return 164;
}

struct OtaCensusReport {
  uint8_t reporter[32] = {};
  uint8_t manifestHash[32] = {};
  uint16_t first = 0;
  uint8_t bitmap[kOtaCensusBitmapBytes] = {};
  uint16_t received = 0;
  uint16_t total = 0;
  uint8_t phase = 0;
  uint32_t generation = 0;
  usb::UsbOtaPhase lifecyclePhase = usb::UsbOtaPhase::Unknown;
  bool floorKnown = false;
  uint32_t confirmedFloor = 0;
  uint32_t counter = 0;
  bool haveLifecycle = false;
  uint8_t wireVersion = 0;
  uint8_t beginNonce[usb::kBeginNonceBytes] = {};
  uint32_t leaseChallenge = 0;
};

struct OtaBootLifecycleEvidence {
  usb::UsbOtaPhase phase = usb::UsbOtaPhase::Unknown;
  bool imageVerified = false;
  bool floorKnown = false;
  uint32_t confirmedFloor = 0;
  uint32_t counter = 0;
  uint64_t transactionNonce = 0;
  uint8_t imageHash[32] = {};
};

inline const char* otaLifecyclePhaseName(usb::UsbOtaPhase phase) {
  using Phase = usb::UsbOtaPhase;
  switch (phase) {
    case Phase::Idle: return "idle";
    case Phase::Erasing: return "erasing";
    case Phase::Receiving: return "receiving";
    case Phase::Verifying: return "verifying";
    case Phase::Ready: return "ready";
    case Phase::CommitPending: return "commit-pending";
    case Phase::Trial: return "trial";
    case Phase::Installed: return "installed";
    case Phase::Aborted: return "aborted";
    case Phase::Failed: return "failed";
    case Phase::CacheSealed: return "cache-sealed";
    default: return "unknown";
  }
}
inline size_t encodeOtaCensusPoll(const uint8_t target[32], const uint8_t hash[32], uint16_t first,
                                  uint8_t* out, size_t capacity) {
  if (!out || capacity < kOtaCensusPollBytes) return 0;
  out[0] = kOtaCensusPollKind;
  std::memcpy(out + 1, target, 32);
  std::memcpy(out + 33, hash, 32);
  usb::putBE16(out + 65, first);
  return kOtaCensusPollBytes;
}

inline size_t encodeOtaCensusReport(const OtaCensusReport& r, uint8_t* out, size_t capacity) {
  if (!out || capacity < kOtaCensusReportBytes) return 0;
  out[0] = kOtaCensusReportKind;
  std::memcpy(out + 1, r.reporter, 32);
  std::memcpy(out + 33, r.manifestHash, 32);
  usb::putBE16(out + 65, r.first);
  std::memcpy(out + 67, r.bitmap, kOtaCensusBitmapBytes);
  usb::putBE16(out + 83, r.received);
  usb::putBE16(out + 85, r.total);
  out[87] = r.phase;
  usb::putBE32(out + 88, r.generation);
  out[92] = static_cast<uint8_t>(r.lifecyclePhase);
  out[93] = r.floorKnown ? 1 : 0;
  usb::putBE32(out + 94, r.confirmedFloor);
  usb::putBE32(out + 98, r.counter);
  out[102] = usb::kOtaWireVersion;
  std::memcpy(out + 103, r.beginNonce, usb::kBeginNonceBytes);
  usb::putBE32(out + 119, r.leaseChallenge);
  return kOtaCensusReportBytes;
}

inline bool parseOtaCensusReport(const uint8_t* frame, size_t len, OtaCensusReport& r) {
  if (!frame || len != kOtaCensusReportBytes || frame[0] != kOtaCensusReportKind ||
      frame[102] != usb::kOtaWireVersion) return false;
  r = OtaCensusReport();
  std::memcpy(r.reporter, frame + 1, 32);
  std::memcpy(r.manifestHash, frame + 33, 32);
  r.first = usb::getBE16(frame + 65);
  std::memcpy(r.bitmap, frame + 67, kOtaCensusBitmapBytes);
  r.received = usb::getBE16(frame + 83);
  r.total = usb::getBE16(frame + 85);
  r.phase = frame[87];
  r.generation = usb::getBE32(frame + 88);
  if (frame[92] > static_cast<uint8_t>(usb::UsbOtaPhase::CacheSealed) || frame[93] > 1) return false;
  r.haveLifecycle = true;
  r.lifecyclePhase = static_cast<usb::UsbOtaPhase>(frame[92]);
  r.floorKnown = frame[93] != 0;
  r.confirmedFloor = usb::getBE32(frame + 94);
  r.counter = usb::getBE32(frame + 98);
  if (r.lifecyclePhase == usb::UsbOtaPhase::Installed &&
      (!r.floorKnown || r.confirmedFloor != r.counter)) return false;
  r.wireVersion = frame[102];
  std::memcpy(r.beginNonce, frame + 103, usb::kBeginNonceBytes);
  r.leaseChallenge = usb::getBE32(frame + 119);
  return true;
}

// Request and ACK sign different kinds under v3 domains. Both bind full target, manifest,
// off-frequency profile and the receiver's current single-use lease
// challenge (token field). The receiver rotates the challenge on boot,
// BEGIN and every acceptance, so captured requests can never retune it.
inline size_t buildOtaDirectMessage(const uint8_t* frame, uint8_t* out) {
  static constexpr char domain[] = "MeshCore/OTA/direct/v3";
  static constexpr char profile_domain[] = "MeshCore/OTA/direct-profile/v3";
  if (frame[0] == kOtaDirectProfileRequestKind || frame[0] == kOtaDirectProfileAckKind) {
    std::memcpy(out, profile_domain, sizeof(profile_domain) - 1);
    std::memcpy(out + sizeof(profile_domain) - 1, frame, 107);
    return sizeof(profile_domain) - 1 + 107;
  }
  std::memcpy(out, domain, sizeof(domain) - 1);
  std::memcpy(out + sizeof(domain) - 1, frame, 107);
  return sizeof(domain) - 1 + 107;
}

inline size_t encodeOtaDirectFrame(uint8_t kind, const uint8_t owner[32], const uint8_t target[32],
                                    const uint8_t hash[32], uint32_t freq_khz, uint16_t lease_ms,
                                    uint32_t token, uint8_t* out, size_t capacity) {
  if (!out || capacity < kOtaDirectFrameBytes) return 0;
  out[0] = kind;
  std::memcpy(out + 1, owner, 32);
  std::memcpy(out + 33, target, 32);
  std::memcpy(out + 65, hash, 32);
  usb::putBE32(out + 97, freq_khz);
  usb::putBE16(out + 101, lease_ms);
  usb::putBE32(out + 103, token);
  return kOtaDirectFrameBytes;
}

// V2 has the same 171-byte ceiling as V1. Only V2 interprets byte97 as
// a selector and bytes98..100 as frequencyBE24; no legacy bits change.
inline size_t encodeOtaDirectProfileFrame(uint8_t kind, OtaDirectProfile profile,
                                         const uint8_t owner[32], const uint8_t target[32],
                                         const uint8_t hash[32], uint32_t freq_khz, uint16_t lease_ms,
                                         uint32_t token, uint8_t* out, size_t capacity) {
  if ((kind != kOtaDirectProfileRequestKind && kind != kOtaDirectProfileAckKind) ||
      (profile != OtaDirectProfile::Bw250 && profile != OtaDirectProfile::Bw500) ||
      freq_khz < 150000 || freq_khz > 2500000 ||
      lease_ms < usb::kDirectLeaseMsMin || lease_ms > usb::kDirectLeaseMsMax) return 0;
  const auto len = encodeOtaDirectFrame(kind, owner, target, hash, freq_khz, lease_ms, token, out, capacity);
  if (len) out[97] = static_cast<uint8_t>(profile);
  return len;
}

inline bool parseOtaDirectProfile(const uint8_t* frame, size_t len,
                                  OtaDirectProfile& profile, uint32_t& freq_khz) {
  if (!frame || len != kOtaDirectFrameBytes) return false;
  if (frame[0] == kOtaDirectRequestKind || frame[0] == kOtaDirectAckKind) {
    profile = OtaDirectProfile::Legacy250;
    freq_khz = usb::getBE32(frame + 97);
  } else if (frame[0] == kOtaDirectProfileRequestKind || frame[0] == kOtaDirectProfileAckKind) {
    profile = static_cast<OtaDirectProfile>(frame[97]);
    if (profile != OtaDirectProfile::Bw250 && profile != OtaDirectProfile::Bw500) return false;
    freq_khz = usb::getBE32(frame + 97) & 0xFFFFFFu;
  } else {
    return false;
  }
  const auto lease = usb::getBE16(frame + 101);
  return freq_khz >= 150000 && freq_khz <= 2500000 &&
         lease >= usb::kDirectLeaseMsMin && lease <= usb::kDirectLeaseMsMax;
}

inline size_t buildOtaReuploadMessage(const uint8_t* frame, uint8_t* out) {
  static constexpr char domain[] = "MeshCore/OTA/reupload/v1";
  std::memcpy(out, domain, sizeof(domain) - 1);
  std::memcpy(out + sizeof(domain) - 1, frame, 101);
  return sizeof(domain) - 1 + 101;
}

static constexpr size_t kOtaAuthorizationFrameBytes =
    1u + 32u + kOtaCanonicalManifestBytes + 64u;  // 1+32+59+64 = 156
static constexpr size_t kOtaCommitFrameBytes = 1u + 32u + 32u + 4u + 4u + 16u + 64u;  // 153
static constexpr size_t kOtaAbortFrameBytes = 1u + 32u + 32u + 32u + 4u + 64u;   // 165
// StatusReport carries the reporting device's own public key: unlike a
// signed frame, PAYLOAD_TYPE_LORA_OTA packets carry no implicit sender
// identity at all, and without this field an uploader tracking several
// AddTarget-ed devices could never attribute an incoming report to the
// correct target entry. This is intentionally UNSIGNED: the field only
// ever drives which target's observed-progress bookkeeping gets updated
// (never an admission/commit/abort decision), so a forged key here can,
// at worst, make the uploader believe a harmless, already fail-closed-
// verified target is further along than it really is -- never mutate
// that target's own real state, which is independently re-verified
// end-to-end (COMMIT/ABORT signatures, seal image-hash check) regardless
// of any StatusReport this device has seen.
static constexpr size_t kOtaStatusReportFrameBytes = 1u + 32u + 4u + 2u + 2u + 1u;  // 42
static constexpr size_t kOtaStatusPollFrameBytes = 1u + kOtaManifestTagBytes;       // 5

// Authority-free attempt identity, outside the unchanged signed inner frame.
// Relays hash the entire payload: one attempt deduplicates, a new one does not.
// Lease negotiation is zero-hop-only and already fills the 171-byte ceiling.
static constexpr uint8_t kOtaRetryAttemptKind = 0x11u;
static constexpr uint8_t kOtaRetryRepairAttemptKind = 0x12u;
static constexpr size_t kOtaRetryAttemptHeaderBytes = 5;
static constexpr size_t kOtaRetryAttemptMaxBytes = 171;

inline bool isOtaRetryAttempt(uint8_t kind) {
  return kind == kOtaRetryAttemptKind || kind == kOtaRetryRepairAttemptKind;
}

inline bool validOtaRetryInner(const uint8_t* frame, size_t len) {
  if (!frame || !len) return false;
  switch (frame[0]) {
    case kOtaSignedBlockKind:
      return len >= kOtaSignedBlockMinBytes && len <= kOtaSignedBlockMaxBytes;
    case kOtaAuthorizationKind: return len == kOtaAuthorizationFrameBytes;
    case kOtaTargetAuthorizationKind: return len == 164;
    case kOtaCommitKind: return len == kOtaCommitFrameBytes;
    case kOtaAbortKind: return len == kOtaAbortFrameBytes;
    case kOtaReuploadKind: return len == kOtaReuploadFrameBytes;
    case kOtaStatusPollKind: return len == kOtaStatusPollFrameBytes;
    case kOtaStatusReportKind: return len == kOtaStatusReportFrameBytes;
    case kOtaCensusPollKind: return len == kOtaCensusPollBytes;
    case kOtaCensusReportKind:
      return len == kOtaCensusReportBytes;
    default: return false;
  }
}

inline bool parseOtaRetryAttempt(const uint8_t* frame, size_t len, uint32_t& attempt,
                                 const uint8_t*& inner, size_t& inner_len) {
  if (!frame || len <= kOtaRetryAttemptHeaderBytes || len > kOtaRetryAttemptMaxBytes ||
      !isOtaRetryAttempt(frame[0])) return false;
  attempt = usb::getBE32(frame + 1);
  inner = frame + kOtaRetryAttemptHeaderBytes;
  inner_len = len - kOtaRetryAttemptHeaderBytes;
  return attempt != 0 && validOtaRetryInner(inner, inner_len) &&
         (frame[0] != kOtaRetryRepairAttemptKind || inner[0] == kOtaSignedBlockKind);
}

inline size_t encodeOtaRetryAttempt(uint32_t attempt, const uint8_t* inner, size_t len,
                                    uint8_t* out, size_t capacity, bool repair = false) {
  if (!attempt || !out || !validOtaRetryInner(inner, len) ||
      len > kOtaRetryAttemptMaxBytes - kOtaRetryAttemptHeaderBytes ||
      capacity < len + kOtaRetryAttemptHeaderBytes ||
      (repair && inner[0] != kOtaSignedBlockKind)) return 0;
  std::memmove(out + kOtaRetryAttemptHeaderBytes, inner, len);
  out[0] = repair ? kOtaRetryRepairAttemptKind : kOtaRetryAttemptKind;
  usb::putBE32(out + 1, attempt);
  return len + kOtaRetryAttemptHeaderBytes;
}

// Shared transport check, including encoded hash width and transport codes.
inline bool otaRfPathFits(size_t payload_len, uint8_t path_len, bool transport_codes = false,
                           size_t raw_ceiling = 255) {
  const size_t width = (path_len >> 6) + 1u;
  const size_t bytes = width * (path_len & 63u);
  const size_t overhead = 2u + (transport_codes ? 4u : 0u) + bytes;
  return width <= 3 && bytes <= 64 && payload_len > 0 && payload_len <= 184 &&
         overhead < raw_ceiling && payload_len <= raw_ceiling - overhead;
}

struct OtaAuthorizationFrame {
  uint8_t ownerPublicKey[32] = {0};
  uint8_t canonical[kOtaCanonicalManifestBytes] = {0};
  uint8_t signature[64] = {0};
};

struct OtaCommitFrame {
  uint8_t target[32] = {0};
  uint8_t manifestHash[32] = {0};
  uint32_t counter = 0;
  uint32_t generation = 0;
  uint8_t beginNonce[usb::kBeginNonceBytes] = {0};
  uint8_t signature[64] = {0};
};

struct OtaAbortFrame {
  uint8_t signerPublicKey[32] = {0};
  uint8_t target[32] = {0};
  uint8_t imageHash[32] = {0};
  uint32_t generation = 0;
  uint8_t signature[64] = {0};
};

struct OtaStatusReportFrame {
  uint8_t reporterPublicKey[32] = {0};
  uint8_t manifestTag[kOtaManifestTagBytes] = {0};
  uint16_t receivedBlocks = 0;
  uint16_t totalBlocks = 0;
  uint8_t phase = 0;
};

inline size_t encodeOtaAuthorizationFrame(const uint8_t owner_public_key[32],
                                          const uint8_t canonical[kOtaCanonicalManifestBytes],
                                          const uint8_t signature[64],
                                          uint8_t* out, size_t out_capacity) {
  if (out == nullptr || out_capacity < kOtaAuthorizationFrameBytes) return 0;
  size_t i = 0;
  out[i++] = kOtaAuthorizationKind;
  std::memcpy(&out[i], owner_public_key, 32); i += 32;
  std::memcpy(&out[i], canonical, kOtaCanonicalManifestBytes); i += kOtaCanonicalManifestBytes;
  std::memcpy(&out[i], signature, 64); i += 64;
  return i;
}

inline bool parseOtaAuthorizationFrame(const uint8_t* frame, size_t frame_len, OtaAuthorizationFrame& out) {
  if (frame == nullptr || frame_len != kOtaAuthorizationFrameBytes || frame[0] != kOtaAuthorizationKind) {
    return false;
  }
  size_t i = 1;
  std::memcpy(out.ownerPublicKey, &frame[i], 32); i += 32;
  std::memcpy(out.canonical, &frame[i], kOtaCanonicalManifestBytes); i += kOtaCanonicalManifestBytes;
  std::memcpy(out.signature, &frame[i], 64); i += 64;
  return true;
}

// [0]=0x03 [1]target32 [33]manifestHash32 [65]counterBE32 [69]generationBE32
// [73]beginNonce16 [89]signature64 over usb::buildCommitSignedMessage().
inline size_t encodeOtaCommitFrame(const uint8_t target[32], const uint8_t manifest_hash[32],
                                   uint32_t counter, uint32_t generation,
                                   const uint8_t begin_nonce[usb::kBeginNonceBytes], const uint8_t signature[64],
                                   uint8_t* out, size_t out_capacity) {
  if (out == nullptr || out_capacity < kOtaCommitFrameBytes || begin_nonce == nullptr) return 0;
  size_t i = 0;
  out[i++] = kOtaCommitKind;
  std::memcpy(&out[i], target, 32); i += 32;
  std::memcpy(&out[i], manifest_hash, 32); i += 32;
  usb::putBE32(&out[i], counter); i += 4;
  usb::putBE32(&out[i], generation); i += 4;
  std::memcpy(&out[i], begin_nonce, usb::kBeginNonceBytes); i += usb::kBeginNonceBytes;
  std::memcpy(&out[i], signature, 64); i += 64;
  return i;
}

inline bool parseOtaCommitFrame(const uint8_t* frame, size_t frame_len, OtaCommitFrame& out) {
  if (frame == nullptr || frame_len != kOtaCommitFrameBytes || frame[0] != kOtaCommitKind) return false;
  size_t i = 1;
  std::memcpy(out.target, &frame[i], 32); i += 32;
  std::memcpy(out.manifestHash, &frame[i], 32); i += 32;
  out.counter = usb::getBE32(&frame[i]); i += 4;
  out.generation = usb::getBE32(&frame[i]); i += 4;
  std::memcpy(out.beginNonce, &frame[i], usb::kBeginNonceBytes); i += usb::kBeginNonceBytes;
  std::memcpy(out.signature, &frame[i], 64); i += 64;
  return true;
}

inline size_t encodeOtaAbortFrame(const uint8_t signer_public_key[32], const uint8_t target[32],
                                  const uint8_t image_hash[32], uint32_t generation, const uint8_t signature[64],
                                  uint8_t* out, size_t out_capacity) {
  if (out == nullptr || out_capacity < kOtaAbortFrameBytes) return 0;
  size_t i = 0;
  out[i++] = kOtaAbortKind;
  std::memcpy(&out[i], signer_public_key, 32); i += 32;
  std::memcpy(&out[i], target, 32); i += 32;
  std::memcpy(&out[i], image_hash, 32); i += 32;
  usb::putBE32(&out[i], generation); i += 4;
  std::memcpy(&out[i], signature, 64); i += 64;
  return i;
}

inline bool parseOtaAbortFrame(const uint8_t* frame, size_t frame_len, OtaAbortFrame& out) {
  if (frame == nullptr || frame_len != kOtaAbortFrameBytes || frame[0] != kOtaAbortKind) return false;
  size_t i = 1;
  std::memcpy(out.signerPublicKey, &frame[i], 32); i += 32;
  std::memcpy(out.target, &frame[i], 32); i += 32;
  std::memcpy(out.imageHash, &frame[i], 32); i += 32;
  out.generation = usb::getBE32(&frame[i]); i += 4;
  std::memcpy(out.signature, &frame[i], 64); i += 64;
  return true;
}

inline size_t encodeOtaStatusReportFrame(const uint8_t reporter_public_key[32],
                                         const uint8_t manifest_tag[kOtaManifestTagBytes],
                                         uint16_t received_blocks, uint16_t total_blocks, uint8_t phase,
                                         uint8_t* out, size_t out_capacity) {
  if (out == nullptr || out_capacity < kOtaStatusReportFrameBytes) return 0;
  size_t i = 0;
  out[i++] = kOtaStatusReportKind;
  std::memcpy(&out[i], reporter_public_key, 32); i += 32;
  std::memcpy(&out[i], manifest_tag, kOtaManifestTagBytes); i += kOtaManifestTagBytes;
  out[i++] = static_cast<uint8_t>((received_blocks >> 8) & 0xFFu);
  out[i++] = static_cast<uint8_t>(received_blocks & 0xFFu);
  out[i++] = static_cast<uint8_t>((total_blocks >> 8) & 0xFFu);
  out[i++] = static_cast<uint8_t>(total_blocks & 0xFFu);
  out[i++] = phase;
  return i;
}

inline bool parseOtaStatusReportFrame(const uint8_t* frame, size_t frame_len, OtaStatusReportFrame& out) {
  if (frame == nullptr || frame_len != kOtaStatusReportFrameBytes || frame[0] != kOtaStatusReportKind) {
    return false;
  }
  size_t i = 1;
  std::memcpy(out.reporterPublicKey, &frame[i], 32); i += 32;
  std::memcpy(out.manifestTag, &frame[i], kOtaManifestTagBytes); i += kOtaManifestTagBytes;
  out.receivedBlocks = static_cast<uint16_t>((static_cast<uint16_t>(frame[i]) << 8) | frame[i + 1]); i += 2;
  out.totalBlocks = static_cast<uint16_t>((static_cast<uint16_t>(frame[i]) << 8) | frame[i + 1]); i += 2;
  out.phase = frame[i];
  return true;
}

struct OtaStatusPollFrame {
  uint8_t manifestTag[kOtaManifestTagBytes] = {0};
};

inline size_t encodeOtaStatusPollFrame(const uint8_t manifest_tag[kOtaManifestTagBytes],
                                       uint8_t* out, size_t out_capacity) {
  if (out == nullptr || out_capacity < kOtaStatusPollFrameBytes) return 0;
  out[0] = kOtaStatusPollKind;
  std::memcpy(&out[1], manifest_tag, kOtaManifestTagBytes);
  return kOtaStatusPollFrameBytes;
}

inline bool parseOtaStatusPollFrame(const uint8_t* frame, size_t frame_len, OtaStatusPollFrame& out) {
  if (frame == nullptr || frame_len != kOtaStatusPollFrameBytes || frame[0] != kOtaStatusPollKind) return false;
  std::memcpy(out.manifestTag, &frame[1], kOtaManifestTagBytes);
  return true;
}

}  // namespace ota
}  // namespace mesh
