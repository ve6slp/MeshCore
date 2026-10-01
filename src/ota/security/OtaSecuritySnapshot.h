#pragma once

// Exact, typed, fixed-layout codec for the 64 KiB per-generation snapshot
// region (see OtaSecurityGeometry.h -- offset 0 of a tail, size 0x10000).
// A snapshot is the CHECKPOINT of all durable facts as of the start of a
// generation; the 32 KiB data/control log (see OtaSecurityAppendEngine.h)
// then accumulates incremental facts on top of it for the rest of that
// generation, until the next compaction folds everything into a fresh
// snapshot for the other bank (see OtaSecurityCompactor.h).
//
// Every byte count below is deliberately spelled out and cross-checked
// with static_asserts against the Astra-approved capacity budget:
//
//   header+authority+PK+global counters   4096
//   350 peer/tombstone      * 48B       = 16800
//     (fullPK32, RXhead4, publisherGroupEpochFloor8, stableIndex2, flags2)
//   4 active cohort         * 160B      =   640
//     (context92, RXhead4, secret32, authorizationBindingDigest32)
//   384 immutable terminal  * 96B       = 36864
//     (controller32, nonce8, campaign4, session4, attempt2,
//      canonicalDescriptorDigest32, profile4, role4, outcome1, flags1, reserved4)
//   live-binding blob area               4096
//   -----------------------------------------
//   TOTAL                               62496   (remaining 3040 of 65536)
//
// This header only defines the byte layout and bounds-checked accessors --
// it does not decide admission policy (capacity refusal, one-use
// enrollment, eviction-never) which lives in OtaSecurityStore.h.

#include <stdint.h>
#include <cstring>

#include "ota/security/OtaSecurityByteCodec.h"
#include "ota/security/OtaSecurityGeometry.h"

namespace ota {
namespace security {

// --- Capacity constants ------------------------------------------------------

constexpr uint32_t kPeerTableCapacity = 350u;
constexpr uint32_t kPeerEntryBytes = 48u;
constexpr uint32_t kCohortTableCapacity = 4u;
constexpr uint32_t kCohortEntryBytes = 160u;
constexpr uint32_t kTerminalTableCapacity = 384u;
constexpr uint32_t kTerminalEntryBytes = 96u;
constexpr uint32_t kHeaderAreaBytes = 4096u;
constexpr uint32_t kLiveBindingAreaBytes = 4096u;

constexpr uint32_t kPeerTableBytes = kPeerTableCapacity * kPeerEntryBytes;         // 16800
constexpr uint32_t kCohortTableBytes = kCohortTableCapacity * kCohortEntryBytes;   // 640
constexpr uint32_t kTerminalTableBytes = kTerminalTableCapacity * kTerminalEntryBytes;  // 36864

static_assert(kPeerTableBytes == 16800u, "peer table must serialize to exactly 16800 bytes");
static_assert(kCohortTableBytes == 640u, "cohort table must serialize to exactly 640 bytes");
static_assert(kTerminalTableBytes == 36864u, "terminal table must serialize to exactly 36864 bytes");

// Real nRF52 QSPI NOR flash program geometry (matches
// Nrf52FlashAdapter::kDefaultPageBytes): a single FlashDevice::program()
// API call that spans more than one of these physical pages is NOT one
// physical program operation on real hardware -- the adapter's own
// program() loop issues a SEPARATE nrfx_qspi_write (and wait-for-complete)
// cycle per page it touches. The live-binding area's start offset below
// is therefore explicitly padded up to a page boundary so that every
// kLiveBindingAreaWriteChunkBytes-sized chunk write lands within exactly
// ONE physical page, keeping the bounded-step "<=1 physical program-or-
// erase call" guarantee honest on real hardware, not just against the
// native test harness's FlashDevice::program()-call counter.
constexpr uint32_t kPhysicalProgramPageBytes = 256u;

constexpr uint32_t kSnapshotUsedBytesUnpadded =
    kHeaderAreaBytes + kPeerTableBytes + kCohortTableBytes + kTerminalTableBytes + kLiveBindingAreaBytes;
static_assert(kSnapshotUsedBytesUnpadded == 62496u, "total unpadded serialized snapshot budget must be exactly 62496 bytes");

// --- Region offsets within the 64 KiB snapshot -------------------------------

constexpr uint32_t kHeaderAreaOffset = 0u;
constexpr uint32_t kPeerTableOffset = kHeaderAreaOffset + kHeaderAreaBytes;               // 4096
constexpr uint32_t kCohortTableOffset = kPeerTableOffset + kPeerTableBytes;               // 20896
constexpr uint32_t kTerminalTableOffset = kCohortTableOffset + kCohortTableBytes;         // 21536
constexpr uint32_t kLiveBindingOffsetUnaligned = kTerminalTableOffset + kTerminalTableBytes;  // 58400
// Rounded UP to the next physical-page boundary (58400 -> 58624): the
// snapshot region's own base (tail A/B's snapshot sub-region) is always
// sector- (hence page-) aligned, so this relative offset being page-
// aligned guarantees the ABSOLUTE flash address is too.
constexpr uint32_t kLiveBindingOffset =
    (kLiveBindingOffsetUnaligned + kPhysicalProgramPageBytes - 1u) / kPhysicalProgramPageBytes * kPhysicalProgramPageBytes;
static_assert(kLiveBindingOffset == 58624u, "live-binding area must start at the first page boundary at/after 58400");
static_assert(kLiveBindingOffset % kPhysicalProgramPageBytes == 0u,
              "live-binding area must start on a physical program-page boundary");

constexpr uint32_t kSnapshotUsedBytes = kLiveBindingOffset + kLiveBindingAreaBytes;
static_assert(kSnapshotUsedBytes == 62720u, "total serialized snapshot budget (with page-alignment padding) must be exactly 62720 bytes");
static_assert(kSnapshotSizeBytes - kSnapshotUsedBytes == 2816u, "unused snapshot remainder must be exactly 2816 bytes");
static_assert(kSnapshotUsedBytes <= kSnapshotSizeBytes, "snapshot budget must fit the 64 KiB snapshot region");
static_assert(kLiveBindingOffset + kLiveBindingAreaBytes == kSnapshotUsedBytes, "live-binding area must end at the used budget boundary");

// --- Header+authority area (4096 bytes; only a small explicit prefix is
//     actually used -- the remainder is reserved/zero padding, never
//     silently repurposed). ---------------------------------------------------
//   [0,4)    magic "OSEC"
//   [4,5)    version
//   [5,8)    reserved
//   [8,16)   storeIdentity (binds this snapshot to one physical store instance)
//   [16,17)  factoryGrantConsumed (0/1 -- one-use commissioning grant already spent)
//   [17,20)  reserved
//   [20,28)  factoryUid (independent one-use factory/full-identity grant binding)
//   [28,60)  fullLocalPublicKey (32 bytes)
//   [60,64)  generation (u32 -- the generation THIS bank's snapshot was built for)
//   [64,68)  txGlobalUpperBoundCheckpoint (u32 -- TX reserve64 upper bound AS OF this snapshot)
//   [68,76)  publisherGroupEpochFloorCheckpoint (u64)
//   [76,78)  liveBindingLength (u16 -- bytes ACTUALLY used within the 4096-byte live-binding area)
//   [82,84)  reserved (was liveBindingLength duplicate slot; kept as padding)
//   [84,88)  grantProfile (u32 -- FactoryGrant format/profile)
//   [88,92)  grantLayout (u32 -- FactoryGrant physical/geometry layout id)
//   [92,96)  grantRole (u32 -- FactoryGrant role)
//   [96,100) grantInitialRole (u32 -- FactoryGrant initial role, pre-any-transition)
//   [100,132) grantConsentOwner (32 bytes -- local consent owner identity)
//   [132,140) grantTransaction (u64 -- the commissioning transaction this one-use grant is bound to)
//   [140,4096) reserved
constexpr uint32_t kHeaderMagic = 0x4F534543u;  // "OSEC" (little-endian bytes C,E,S,O -- arbitrary, just a fixed constant)
constexpr uint32_t kHeaderStoreIdentityOffset = 8u;
constexpr uint32_t kHeaderFactoryGrantConsumedOffset = 16u;
constexpr uint32_t kHeaderFactoryUidOffset = 20u;
constexpr uint32_t kHeaderLocalPublicKeyOffset = 28u;
constexpr uint32_t kHeaderGenerationOffset = 60u;
constexpr uint32_t kHeaderTxUpperBoundOffset = 64u;
constexpr uint32_t kHeaderPublisherFloorOffset = 68u;
constexpr uint32_t kHeaderPeerCountOffset = 76u;
constexpr uint32_t kHeaderCohortCountOffset = 78u;
constexpr uint32_t kHeaderTerminalCountOffset = 80u;
constexpr uint32_t kHeaderLiveBindingLengthOffset = 82u;
constexpr uint32_t kHeaderGrantProfileOffset = 84u;
constexpr uint32_t kHeaderGrantLayoutOffset = 88u;
constexpr uint32_t kHeaderGrantRoleOffset = 92u;
constexpr uint32_t kHeaderGrantInitialRoleOffset = 96u;
constexpr uint32_t kHeaderGrantConsentOwnerOffset = 100u;
constexpr uint32_t kHeaderGrantTransactionOffset = 132u;
static_assert(kHeaderGrantTransactionOffset + 8u <= kHeaderAreaBytes, "header fields must fit within the 4096-byte header area");

// The header AREA reserved in the physical layout is 4096 bytes (see
// above), but the actual ENCODED field content only ever occupies the
// first 140 bytes of it -- the remainder is reserved padding that is
// simply left blank (post-erase 0xFF) rather than ever being explicitly
// materialized. Codec buffers therefore only need to be
// kHeaderEncodedBytes wide, not the full 4096-byte reserved area; this
// keeps on-stack encode/decode scratch small (256B instead of 4096B) on
// resource-constrained targets. Rounded up to a 4-byte-aligned round
// number with modest headroom over the 140 bytes actually used today.
constexpr uint32_t kHeaderEncodedBytes = 256u;
static_assert(kHeaderGrantTransactionOffset + 8u <= kHeaderEncodedBytes, "header fields must fit within the reduced encode/decode buffer");
static_assert(kHeaderEncodedBytes <= kHeaderAreaBytes, "encoded header content must fit within the reserved header area");
static_assert(kHeaderEncodedBytes % 4u == 0u, "encoded header buffer must stay 4-byte aligned for program-unit alignment");

// Independent, durable, ONE-USE, default-deny factory/full-identity
// commissioning grant: device UID + full local PK + format/profile/
// layout/role/initial-role + local consent owner + transaction. Carried
// forward, verbatim, across compaction as part of the snapshot header;
// also durable immediately (before any compaction) via a single ordinary
// append record -- see OtaSecurityStore::commissionFactoryGrant().
struct OtaSecurityFactoryGrant {
  uint64_t deviceUid = 0;
  uint8_t fullLocalPublicKey[32] = {0};
  uint32_t profile = 0;
  uint32_t layout = 0;
  uint32_t role = 0;
  uint32_t initialRole = 0;
  uint8_t consentOwner[32] = {0};
  uint64_t transaction = 0;
};

struct OtaSecuritySnapshotHeader {
  uint64_t storeIdentity = 0;
  bool factoryGrantConsumed = false;
  OtaSecurityFactoryGrant factoryGrant;
  uint32_t generation = 0;
  uint32_t txGlobalUpperBoundCheckpoint = 0;
  uint64_t publisherGroupEpochFloorCheckpoint = 0;
  uint16_t peerCount = 0;
  uint16_t cohortCount = 0;
  uint16_t terminalCount = 0;
  uint16_t liveBindingLength = 0;
};

class OtaSecuritySnapshotHeaderCodec {
public:
  // NOTE: out/outLen refer to a kHeaderEncodedBytes-sized buffer (NOT the
  // full kHeaderAreaBytes reserved area); callers program only these
  // bytes at the start of the header area and leave the rest of the
  // reserved area blank (post-erase 0xFF), never materializing the full
  // 4096-byte area on the stack/heap.
  static bool encode(const OtaSecuritySnapshotHeader& h, uint8_t* out, size_t outLen) {
    if (outLen < kHeaderEncodedBytes) return false;
    std::memset(out, 0, kHeaderEncodedBytes);
    if (!putU32(out, outLen, 0, kHeaderMagic)) return false;
    if (!putU8(out, outLen, 4, 1)) return false;  // version
    if (!putU64(out, outLen, kHeaderStoreIdentityOffset, h.storeIdentity)) return false;
    if (!putU8(out, outLen, kHeaderFactoryGrantConsumedOffset, h.factoryGrantConsumed ? 1u : 0u)) return false;
    if (!putU64(out, outLen, kHeaderFactoryUidOffset, h.factoryGrant.deviceUid)) return false;
    if (!putBytes(out, outLen, kHeaderLocalPublicKeyOffset, h.factoryGrant.fullLocalPublicKey, 32)) return false;
    if (!putU32(out, outLen, kHeaderGenerationOffset, h.generation)) return false;
    if (!putU32(out, outLen, kHeaderTxUpperBoundOffset, h.txGlobalUpperBoundCheckpoint)) return false;
    if (!putU64(out, outLen, kHeaderPublisherFloorOffset, h.publisherGroupEpochFloorCheckpoint)) return false;
    if (!putU16(out, outLen, kHeaderPeerCountOffset, h.peerCount)) return false;
    if (!putU16(out, outLen, kHeaderCohortCountOffset, h.cohortCount)) return false;
    if (!putU16(out, outLen, kHeaderTerminalCountOffset, h.terminalCount)) return false;
    if (!putU16(out, outLen, kHeaderLiveBindingLengthOffset, h.liveBindingLength)) return false;
    if (!putU32(out, outLen, kHeaderGrantProfileOffset, h.factoryGrant.profile)) return false;
    if (!putU32(out, outLen, kHeaderGrantLayoutOffset, h.factoryGrant.layout)) return false;
    if (!putU32(out, outLen, kHeaderGrantRoleOffset, h.factoryGrant.role)) return false;
    if (!putU32(out, outLen, kHeaderGrantInitialRoleOffset, h.factoryGrant.initialRole)) return false;
    if (!putBytes(out, outLen, kHeaderGrantConsentOwnerOffset, h.factoryGrant.consentOwner, 32)) return false;
    if (!putU64(out, outLen, kHeaderGrantTransactionOffset, h.factoryGrant.transaction)) return false;
    return true;
  }

  // Returns false if the magic doesn't match (caller must treat that as
  // Corrupt/blank, never silently substitute defaults).
  static bool decode(const uint8_t* raw, size_t rawLen, OtaSecuritySnapshotHeader& out) {
    if (rawLen < kHeaderEncodedBytes) return false;
    uint32_t magic = 0;
    getU32(raw, rawLen, 0, magic);
    if (magic != kHeaderMagic) return false;
    getU64(raw, rawLen, kHeaderStoreIdentityOffset, out.storeIdentity);
    uint8_t consumed = 0;
    getU8(raw, rawLen, kHeaderFactoryGrantConsumedOffset, consumed);
    out.factoryGrantConsumed = consumed != 0;
    getU64(raw, rawLen, kHeaderFactoryUidOffset, out.factoryGrant.deviceUid);
    getBytes(raw, rawLen, kHeaderLocalPublicKeyOffset, out.factoryGrant.fullLocalPublicKey, 32);
    getU32(raw, rawLen, kHeaderGenerationOffset, out.generation);
    getU32(raw, rawLen, kHeaderTxUpperBoundOffset, out.txGlobalUpperBoundCheckpoint);
    getU64(raw, rawLen, kHeaderPublisherFloorOffset, out.publisherGroupEpochFloorCheckpoint);
    getU16(raw, rawLen, kHeaderPeerCountOffset, out.peerCount);
    getU16(raw, rawLen, kHeaderCohortCountOffset, out.cohortCount);
    getU16(raw, rawLen, kHeaderTerminalCountOffset, out.terminalCount);
    getU16(raw, rawLen, kHeaderLiveBindingLengthOffset, out.liveBindingLength);
    getU32(raw, rawLen, kHeaderGrantProfileOffset, out.factoryGrant.profile);
    getU32(raw, rawLen, kHeaderGrantLayoutOffset, out.factoryGrant.layout);
    getU32(raw, rawLen, kHeaderGrantRoleOffset, out.factoryGrant.role);
    getU32(raw, rawLen, kHeaderGrantInitialRoleOffset, out.factoryGrant.initialRole);
    getBytes(raw, rawLen, kHeaderGrantConsentOwnerOffset, out.factoryGrant.consentOwner, 32);
    getU64(raw, rawLen, kHeaderGrantTransactionOffset, out.factoryGrant.transaction);
    return true;
  }
};

// --- Peer/tombstone table entry (48 bytes) -----------------------------------
struct OtaSecurityPeerEntry {
  uint8_t fullPeerPublicKey[32] = {0};
  uint32_t rxHead = 0;
  uint64_t publisherGroupEpochFloor = 0;
  uint16_t stableIndex = 0;
  uint16_t flags = 0;  // bit0: occupied: stableIndex may not be reused even if the peer later tombstones.
};

class OtaSecurityPeerEntryCodec {
public:
  static bool encode(const OtaSecurityPeerEntry& e, uint8_t* out, size_t outLen) {
    if (outLen < kPeerEntryBytes) return false;
    if (!putBytes(out, outLen, 0, e.fullPeerPublicKey, 32)) return false;
    if (!putU32(out, outLen, 32, e.rxHead)) return false;
    if (!putU64(out, outLen, 36, e.publisherGroupEpochFloor)) return false;
    if (!putU16(out, outLen, 44, e.stableIndex)) return false;
    if (!putU16(out, outLen, 46, e.flags)) return false;
    return true;
  }
  static bool decode(const uint8_t* raw, size_t rawLen, OtaSecurityPeerEntry& out) {
    if (rawLen < kPeerEntryBytes) return false;
    getBytes(raw, rawLen, 0, out.fullPeerPublicKey, 32);
    getU32(raw, rawLen, 32, out.rxHead);
    getU64(raw, rawLen, 36, out.publisherGroupEpochFloor);
    getU16(raw, rawLen, 44, out.stableIndex);
    getU16(raw, rawLen, 46, out.flags);
    return true;
  }
};
static_assert(sizeof(((OtaSecurityPeerEntry*)nullptr)->fullPeerPublicKey) == 32, "peer entry public key must be 32 bytes");

// --- Active cohort table entry (160 bytes) -----------------------------------
struct OtaSecurityCohortEntry {
  uint8_t groupContext[92] = {0};
  uint32_t rxHead = 0;
  uint8_t secret[32] = {0};
  uint8_t authorizationBindingDigest[32] = {0};
};

class OtaSecurityCohortEntryCodec {
public:
  static bool encode(const OtaSecurityCohortEntry& e, uint8_t* out, size_t outLen) {
    if (outLen < kCohortEntryBytes) return false;
    if (!putBytes(out, outLen, 0, e.groupContext, 92)) return false;
    if (!putU32(out, outLen, 92, e.rxHead)) return false;
    if (!putBytes(out, outLen, 96, e.secret, 32)) return false;
    if (!putBytes(out, outLen, 128, e.authorizationBindingDigest, 32)) return false;
    return true;
  }
  static bool decode(const uint8_t* raw, size_t rawLen, OtaSecurityCohortEntry& out) {
    if (rawLen < kCohortEntryBytes) return false;
    getBytes(raw, rawLen, 0, out.groupContext, 92);
    getU32(raw, rawLen, 92, out.rxHead);
    getBytes(raw, rawLen, 96, out.secret, 32);
    getBytes(raw, rawLen, 128, out.authorizationBindingDigest, 32);
    return true;
  }
};

// --- Immutable terminal attempt table entry (96 bytes) -----------------------
struct OtaSecurityTerminalEntry {
  uint8_t controller[32] = {0};
  uint64_t nonce = 0;
  uint32_t campaign = 0;
  uint32_t session = 0;
  uint16_t attempt = 0;
  uint8_t canonicalDescriptorDigest[32] = {0};
  uint32_t profile = 0;
  uint32_t role = 0;
  uint8_t outcome = 0;
  uint8_t flags = 0;
};

class OtaSecurityTerminalEntryCodec {
public:
  static bool encode(const OtaSecurityTerminalEntry& e, uint8_t* out, size_t outLen) {
    if (outLen < kTerminalEntryBytes) return false;
    std::memset(out, 0, kTerminalEntryBytes);
    if (!putBytes(out, outLen, 0, e.controller, 32)) return false;
    if (!putU64(out, outLen, 32, e.nonce)) return false;
    if (!putU32(out, outLen, 40, e.campaign)) return false;
    if (!putU32(out, outLen, 44, e.session)) return false;
    if (!putU16(out, outLen, 48, e.attempt)) return false;
    if (!putBytes(out, outLen, 50, e.canonicalDescriptorDigest, 32)) return false;
    if (!putU32(out, outLen, 82, e.profile)) return false;
    if (!putU32(out, outLen, 86, e.role)) return false;
    if (!putU8(out, outLen, 90, e.outcome)) return false;
    if (!putU8(out, outLen, 91, e.flags)) return false;
    // [92,96) reserved, stays zero.
    return true;
  }
  static bool decode(const uint8_t* raw, size_t rawLen, OtaSecurityTerminalEntry& out) {
    if (rawLen < kTerminalEntryBytes) return false;
    getBytes(raw, rawLen, 0, out.controller, 32);
    getU64(raw, rawLen, 32, out.nonce);
    getU32(raw, rawLen, 40, out.campaign);
    getU32(raw, rawLen, 44, out.session);
    getU16(raw, rawLen, 48, out.attempt);
    getBytes(raw, rawLen, 50, out.canonicalDescriptorDigest, 32);
    getU32(raw, rawLen, 82, out.profile);
    getU32(raw, rawLen, 86, out.role);
    getU8(raw, rawLen, 90, out.outcome);
    getU8(raw, rawLen, 91, out.flags);
    return true;
  }
};

// --- Live-binding blob (within the 4096-byte kLiveBindingAreaBytes area) ----
// Real typed layout -- NOT an opaque reserved blob -- for full signed
// material / consent / a frozen 28-byte SDK identifier / the original
// image SHA-256 / an install extent / a per-roster-peer missing bitmap /
// a BOUNDED roster. The roster is referenced by STABLE PEER-TABLE INDEX
// (u16 into the 350-entry peer table), never a full 32-byte public key:
// 350 full keys would need 350*32 = 11200 bytes, which does NOT fit the
// 4096-byte budget (see the static_assert below); 350 u16 indices need
// only 700 bytes and do fit, with 3180 bytes still spare.
constexpr uint32_t kLiveBindingRosterCapacity = kPeerTableCapacity;  // 350
constexpr uint32_t kLiveBindingSignatureBytes = 64u;
constexpr uint32_t kLiveBindingConsentDigestBytes = 32u;
constexpr uint32_t kLiveBindingFrozenSdkBytes = 28u;
constexpr uint32_t kLiveBindingOriginalShaBytes = 32u;
constexpr uint32_t kLiveBindingBitmapBytes = (kLiveBindingRosterCapacity + 7u) / 8u;  // 44

constexpr uint32_t kLiveBindingFixedBytes =
    4u /*magic*/ + 1u /*version*/ + 1u /*present*/ + 2u /*rosterCount*/ + kLiveBindingSignatureBytes +
    kLiveBindingConsentDigestBytes + kLiveBindingFrozenSdkBytes + kLiveBindingOriginalShaBytes +
    4u /*extentOffset*/ + 4u /*extentLength*/ + kLiveBindingBitmapBytes +
    kLiveBindingRosterCapacity * 2u /*roster peer-table indices*/;
static_assert(kLiveBindingFixedBytes == 916u,
              "live-binding layout (sig64+consent32+sdk28+sha32+extent8+bitmap44+350*idx2+hdr8) must total 916 bytes");
static_assert(kLiveBindingFixedBytes <= kLiveBindingAreaBytes,
              "the real typed live-binding layout must fit the 4096-byte budget");
static_assert(kLiveBindingRosterCapacity * 32u > kLiveBindingAreaBytes,
              "a full 32-byte-key roster (11200 bytes) provably does NOT fit 4096 bytes -- stable peer-table "
              "indices are required, not full keys");

struct OtaSecurityLiveBinding {
  bool present = false;  // false: no live binding has ever been committed (default-deny; never inferred).
  uint16_t rosterCount = 0;
  uint8_t fullSignedMaterial[kLiveBindingSignatureBytes] = {0};
  uint8_t consentDigest[kLiveBindingConsentDigestBytes] = {0};
  uint8_t frozenSdk[kLiveBindingFrozenSdkBytes] = {0};
  uint8_t originalSha[kLiveBindingOriginalShaBytes] = {0};
  uint32_t extentOffset = 0;
  uint32_t extentLength = 0;
  uint8_t missingBitmap[kLiveBindingBitmapBytes] = {0};
  uint16_t rosterPeerIndex[kLiveBindingRosterCapacity] = {0};
};

constexpr uint32_t kLiveBindingMagic = 0x444E424Cu;  // "LBND"

class OtaSecurityLiveBindingCodec {
public:
  static bool encode(const OtaSecurityLiveBinding& b, uint8_t* out, size_t outLen) {
    if (outLen < kLiveBindingAreaBytes) return false;
    if (b.rosterCount > kLiveBindingRosterCapacity) return false;
    std::memset(out, 0, kLiveBindingAreaBytes);
    size_t pos = 0;
    if (!putU32(out, outLen, pos, kLiveBindingMagic)) return false;
    pos += 4;
    if (!putU8(out, outLen, pos, 1)) return false;  // version
    pos += 1;
    if (!putU8(out, outLen, pos, b.present ? 1u : 0u)) return false;
    pos += 1;
    if (!putU16(out, outLen, pos, b.rosterCount)) return false;
    pos += 2;
    if (!putBytes(out, outLen, pos, b.fullSignedMaterial, kLiveBindingSignatureBytes)) return false;
    pos += kLiveBindingSignatureBytes;
    if (!putBytes(out, outLen, pos, b.consentDigest, kLiveBindingConsentDigestBytes)) return false;
    pos += kLiveBindingConsentDigestBytes;
    if (!putBytes(out, outLen, pos, b.frozenSdk, kLiveBindingFrozenSdkBytes)) return false;
    pos += kLiveBindingFrozenSdkBytes;
    if (!putBytes(out, outLen, pos, b.originalSha, kLiveBindingOriginalShaBytes)) return false;
    pos += kLiveBindingOriginalShaBytes;
    if (!putU32(out, outLen, pos, b.extentOffset)) return false;
    pos += 4;
    if (!putU32(out, outLen, pos, b.extentLength)) return false;
    pos += 4;
    if (!putBytes(out, outLen, pos, b.missingBitmap, kLiveBindingBitmapBytes)) return false;
    pos += kLiveBindingBitmapBytes;
    for (uint32_t i = 0; i < kLiveBindingRosterCapacity; ++i) {
      if (!putU16(out, outLen, pos, b.rosterPeerIndex[i])) return false;
      pos += 2;
    }
    return pos == kLiveBindingFixedBytes;
  }

  // Returns false if the magic doesn't match (blank/corrupt area -- caller
  // must treat that as "no live binding", never a silently-defaulted one).
  static bool decode(const uint8_t* raw, size_t rawLen, OtaSecurityLiveBinding& out) {
    if (rawLen < kLiveBindingAreaBytes) return false;
    size_t pos = 0;
    uint32_t magic = 0;
    getU32(raw, rawLen, pos, magic);
    pos += 4;
    if (magic != kLiveBindingMagic) return false;
    uint8_t version = 0, present = 0;
    getU8(raw, rawLen, pos, version);
    pos += 1;
    getU8(raw, rawLen, pos, present);
    pos += 1;
    out.present = present != 0;
    getU16(raw, rawLen, pos, out.rosterCount);
    pos += 2;
    if (out.rosterCount > kLiveBindingRosterCapacity) return false;
    getBytes(raw, rawLen, pos, out.fullSignedMaterial, kLiveBindingSignatureBytes);
    pos += kLiveBindingSignatureBytes;
    getBytes(raw, rawLen, pos, out.consentDigest, kLiveBindingConsentDigestBytes);
    pos += kLiveBindingConsentDigestBytes;
    getBytes(raw, rawLen, pos, out.frozenSdk, kLiveBindingFrozenSdkBytes);
    pos += kLiveBindingFrozenSdkBytes;
    getBytes(raw, rawLen, pos, out.originalSha, kLiveBindingOriginalShaBytes);
    pos += kLiveBindingOriginalShaBytes;
    getU32(raw, rawLen, pos, out.extentOffset);
    pos += 4;
    getU32(raw, rawLen, pos, out.extentLength);
    pos += 4;
    getBytes(raw, rawLen, pos, out.missingBitmap, kLiveBindingBitmapBytes);
    pos += kLiveBindingBitmapBytes;
    for (uint32_t i = 0; i < kLiveBindingRosterCapacity; ++i) {
      getU16(raw, rawLen, pos, out.rosterPeerIndex[i]);
      pos += 2;
    }
    return true;
  }
};

// Bounded, fixed-count multi-cell transaction framing for durably
// committing a live binding to the ordinary append log BEFORE the next
// compaction folds it into the snapshot's contiguous live-binding area.
// Each 100-byte cell payload carries a 12-byte prefix (shared
// transaction LSN + partIndex + partCount + totalLength) plus up to 88
// bytes of the encoded blob; ALL kLiveBindingChunkCount chunks must be
// individually Committed with matching transaction LSN/partCount/
// totalLength before the whole binding is treated as committed (see
// OtaSecurityStore::writeLiveBinding() / reconstruct()) -- a partial set
// is never silently treated as committed.
constexpr uint32_t kLiveBindingChunkPrefixBytes = 12u;
constexpr uint32_t kLiveBindingChunkDataBytes = 88u;
static_assert(kLiveBindingChunkPrefixBytes + kLiveBindingChunkDataBytes == 100u,
              "one live-binding chunk must fit exactly within the 100-byte cell payload");
constexpr uint32_t kLiveBindingChunkCount =
    (kLiveBindingFixedBytes + kLiveBindingChunkDataBytes - 1u) / kLiveBindingChunkDataBytes;
static_assert(kLiveBindingChunkCount == 11u, "916 bytes at 88 bytes/chunk must take exactly 11 chunks");
static_assert(kLiveBindingChunkCount <= 0xFFu, "chunk count must fit the 1-byte partCount field");

// --- Bounded per-service-step snapshot-area write/readback chunking --------
// Distinct from kLiveBindingChunkCount above (which governs the LOG-side
// multi-cell commit transaction): this governs how the already-committed
// LiveBinding blob's SNAPSHOT-AREA copy (kLiveBindingAreaBytes, written
// once per compaction) is programmed/read-back verified during
// compaction, so that EVERY bounded compactStep() call transfers at most
// kSnapshotWriteStepByteBudget bytes -- never the whole 4096-byte area in
// one call.
//
// kSnapshotWriteStepByteBudget (1024B) remains the AGGREGATE per-step
// transfer cap used for READ-only operations (e.g. the witness-prepare
// digest stream), where a single QSPI read burst is genuinely one
// physical operation regardless of length. The live-binding area's
// PROGRAM chunk size is intentionally smaller and DISTINCT:
// kPhysicalProgramPageBytes (256B, the real nRF52 QSPI page-program
// geometry) -- a write any larger risks spanning more than one physical
// page per call, which the "<=1 physical program-or-erase call per
// bounded step" guarantee must never do. The live-binding area's start
// offset (kLiveBindingOffset) is page-aligned above specifically so
// every one of these chunk writes lands within exactly one page.
constexpr uint32_t kSnapshotWriteStepByteBudget = 1024u;
constexpr uint32_t kLiveBindingAreaWriteChunkBytes = kPhysicalProgramPageBytes;
constexpr uint32_t kLiveBindingAreaWriteChunkCount =
    (kLiveBindingAreaBytes + kLiveBindingAreaWriteChunkBytes - 1u) / kLiveBindingAreaWriteChunkBytes;
static_assert(kLiveBindingAreaWriteChunkCount == 16u, "4096 bytes at 256 bytes/chunk must take exactly 16 chunks");

}  // namespace security
}  // namespace ota
