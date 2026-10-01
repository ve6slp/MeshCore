#pragma once

// ****************************************************************************
// AUTHORITATIVE V1 WIRE FORMAT -- decided by ROOT/MAIN in coordination with
// the Boot owner (owner65278) for cross-language (C bootloader / Python /
// C++) interop. This REPLACES this module's own earlier 345-byte-body
// proposal outright: the field set, order, offsets, and endianness below
// are final for V1 and must not be changed here without a fresh ROOT/Boot
// agreement (any future change is a V2, never a silent V1 reinterpretation).
//
// STATUS, precisely:
//   - WIRE ABI: FINAL. The exact 4-byte record `magic` (0x58464152) is
//     copied verbatim from the Boot owner's own published C shared-wire-
//     header, XIAO_OTA_FLOOR_ACTIVATION_MAGIC in
//     bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h (never
//     touched by this file) -- every offset/width/endianness below is
//     settled, not provisional.
//   - C-SIDE INTEROP: PENDING, not claimed complete. This module's own
//     Python/C++ codecs independently verify one shared, byte-identical
//     TEST-key fixture against each other with real crypto (see
//     BootFloorActivationReceiptCodecTest.
//     RealEd25519CrossLanguageInteropVectorVerifiesWithActualCrypto and
//     the matching Python test). Boot's own independent C-side verifier
//     (bootloader/xiao_nrf52840_ota/**, exclusively Boot-owned, never
//     edited here) has NOT itself been run against this fixture by this
//     module -- that cross-check is offered to, and remains the Boot
//     owner's own step to exercise and confirm.
//
// PHYSICAL I/O ALIGNMENT IS NOT PART OF THIS CANONICAL FORMAT: the 386-byte
// canonical record (322-byte body + 64-byte signature) is intentionally
// NOT a multiple of 4 bytes. Boot's own flash-I/O layer may need to round
// its physical read/write buffer up to a 4-byte-aligned 388-byte buffer
// with 2 trailing 0xFF pad bytes -- that padding is a Boot-owned PHYSICAL
// storage-layer concern only, byte count 388 never appears anywhere in
// this codec, is NEVER treated as a valid `recordbytes`/length value by
// parseRecord, and is NEVER produced by serializeRecord. Every file this
// module's own exporter/CLI writes, and every canonical interop test
// vector below, is EXACTLY 386 bytes -- if a future physical-layer
// variant is ever needed it must be a clearly separate, explicitly named
// artifact, never silently substituted for the canonical record.
// ****************************************************************************
//
// A NEW, narrow, genesis-only grant: certifies that this device's boot-
// owned publisher floor counter may be bootstrapped to EXACTLY 0, once,
// backed by positive first-use (Commission) evidence -- entirely separate
// from (a) TX/RX sequence floors (AuthorityTransaction::
// initialTxSequenceFloor/initialRxReplayFloor, ActivationPermit/
// TxRxActivationGrant) and (b) CertifyExistingBaseline (an existing-image
// "Normal" certification that never seeds any counter). Neither of those
// two authorities counts as proof for this one: only a genuine, still-
// undominated Commission ActivationSpent transaction for this exact owner
// qualifies.
//
// `bootDomain` (wire offset 8, a fixed uint32_t) is a FIXED, PROTOCOL-LEVEL
// constant literal (0x424F4F54, ASCII "BOOT") -- identical for every device,
// NEVER derived from hardwareUid/meshFullPublicKey/cryptoDomain/role/
// layout/grant. This is a deliberate correction from this module's earlier
// proposal, which derived a per-device SHA-256 hash from (hardwareUid ||
// literal): that derivation was unnecessary hashing work for the
// bounded boot-side C verifier, and (per the corrected understanding) the
// per-device identity for the lifetime fence is carried ENTIRELY by the
// separate, explicit `hardwareUid` field (wire offset 12) -- the verifier's
// fence is simply "bootDomain == the fixed constant AND hardwareUid ==
// this device's own FICR UID", a trivial two-field compare, never a hash.
// Because the domain is now a single global constant, it is structurally
// incapable of ever minting a second floor-genesis namespace for the same
// physical device no matter what PK/role/layout/cryptoDomain/grant label
// changes around it -- there is nothing device-specific left to hash.
//
// Every multi-byte integer on the wire is EXPLICIT LITTLE-ENDIAN. This is a
// deliberate, SEPARATE convention from AuthorityCodec's big-endian wire
// family elsewhere in this same directory -- this receipt is a distinct,
// Boot-owned-interop wire format, not a reuse of AuthorityCodec's codec.
//
// Signed under SHA-256(`kSignedDomain` || canonical 322-byte body) -- the
// SIGNATURE covers a 32-byte DIGEST of (domain || body), not the raw
// (domain || body) bytes themselves, and this is deliberately plain
// (non-prehash) Ed25519 signing/verifying THAT 32-byte digest as its
// message -- NOT the RFC 8032 Ed25519ph prehash variant (which uses its
// own distinct domain-separator/context construction). Pre-hashing here
// ourselves keeps the boot-side C verifier's buffer bounded to exactly the
// digest + signature (well within an 8 KiB task stack) instead of needing
// to stream/buffer the full 322-byte body through the crypto primitive.
// Reuses the SAME "MeshCore/OTA/<purpose>/v1" domain-string convention
// already used elsewhere in this codebase.
//
// The signing key is the EXISTING firmware publisher key -- this header
// does not create, hold, or simulate any production key. `PublisherKeyTrust`
// below is an explicit, separately-wired abstract seam (default-deny: a
// BootFloorActivationReceiptExporter constructed without one denies every
// export) that a real integrator (MAIN/Store) wires to whatever already
// holds that real key. Ordinary OTA image-signing code paths have no
// access to this seam at all, so they cannot implicitly gain the ability
// to export this receipt.
//
// This header/exporter NEVER touches a filesystem, NEVER parses
// LittleFS, and NEVER writes to boot-owned flash sectors -- it only
// produces (or verifies) the off-device signed receipt bytes. The
// on-device write-durability sequence (floor BODY written first without
// a commit marker; the commit MARKER written last, only after the host
// is durably ActivationSpent in both copies and this receipt has been
// produced/read back) is Boot/Firmware's implementation responsibility,
// not this module's.
//
// Export is retryable ONLY for the exact existing prepared/activated
// binding already on record (same transactionId, same owner, still the
// undominated latest history for that owner) -- never triggers a new
// preparation, never advances any counter, and never "reseeds" a floor
// that isn't already present per this same transaction. Role transition
// is explicitly OUT OF SCOPE for this receipt and is not implemented
// here.

#include <stdint.h>
#include <stddef.h>
#include <cstring>
#include "ota/authority/AuthorityTypes.h"
#include "ota/authority/AuthorityCodec.h"
#include "ota/authority/AuthorityRegistryPort.h"
#include "ota/authority/AuthorityHostInterfaces.h"
#include "ota/authority/AuthorityCrossProcessLock.h"
#include "ota/storage/Crc32.h"
#include "ota/trust/Sha256.h"
#include "ota/trust/SignatureVerifier.h"

namespace ota {
namespace authority {

constexpr size_t kBootFloorPublisherFingerprintBytes = 32;  // FULL SHA-256 of the RAW 32-byte publisher public key
                                                             // itself (never a derivation/selection keyed off
                                                             // publisherKeyId alone) -- no truncation.
constexpr size_t kBootFloorBaselineImageDigestBytes = 32;
// The exact, frozen 28-byte SDK identifier blob is hashed by the caller;
// this header only ever carries/signs the resulting 32-byte SHA-256
// digest (never a version integer, never the raw 28 bytes themselves).
constexpr size_t kBootFloorOriginalSdk28DigestBytes = 32;

// What this specific receipt purpose identifies. Not carried as a
// separate wire byte (the canonical V1 layout has no room for one, and a
// single receipt family exists today) -- purpose is instead entirely
// asserted by the fixed signing-domain literal (signedDomain() below); a
// verifier that checks the domain string already checks purpose.
enum class BootFloorReceiptPurpose : uint8_t {
  PublisherFloorActivation = 1,
};

// HOST/caller-supplied evidence about the CURRENT baseline image this
// floor-genesis event is happening against. This module never measures
// these values itself (it does not parse LittleFS or inspect flash) --
// a real integrator supplies them, typically from the same measurement
// pipeline that backs BaselineCertificationManifest/
// OtaBaselineCertificationEvidence. All-zero evidence is accepted at the
// type level (this header cannot verify image contents) but a real
// integrator must never call exportReceipt with fabricated/placeholder
// values -- that obligation lives outside this module, exactly as for
// DeviceBaselineLocalEvidence.
struct BootFloorBaselineEvidence {
  // Single canonical extent LENGTH -- matches the ROOT-decided wire
  // layout's one "exact extent" field exactly (no separate offset field
  // on the wire; a baseline extent offset, if the caller's pipeline
  // tracks one separately, is not part of this signed receipt and must
  // be conveyed/verified through the CertifyExistingBaseline/
  // BaselineCertificationManifest path instead).
  uint32_t extentLength = 0;
  uint8_t imageSha256[kBootFloorBaselineImageDigestBytes] = {0};
  uint8_t original28Sha256Digest[kBootFloorOriginalSdk28DigestBytes] = {0};
  // Compiled target identifier -- a SEPARATE field from profileId, never
  // assumed equal.
  uint32_t targetId = 0;
};

// Canonical, fixed-width, bounds-checked BootFloorActivationReceiptV1.
// Every field is fixed-width; there are no variable-length/unbounded
// arrays and no dynamic allocation anywhere in the codec below --
// comfortably inside an 8 KiB task stack. Field ORDER here matches the
// in-memory convenience layout, NOT necessarily the wire order (the wire
// order/offsets are exactly and only what serializeBody/parseRecord
// implement below, per ROOT's canonical byte table).
struct BootFloorActivationReceiptV1 {
  uint16_t recordVersion = 1;
  // Full nRF FICR DEVICEID, stored here in the SAME big-endian
  // representation AuthorityBinding::hardwareUid uses everywhere else in
  // this codebase (see AuthorityTypes.h) -- the codec below is
  // responsible for the BE->numeric->LE wire conversion at offset 12,
  // never a caller-visible concern.
  uint8_t hardwareUid[kHardwareUidBytes] = {0};
  uint8_t localMeshFullPublicKey[kPublicKeyBytes] = {0};
  uint8_t consentOwnerPublicKey[kPublicKeyBytes] = {0};
  uint32_t targetId = 0;
  uint32_t profileId = 0;
  uint32_t layoutId = 0;
  uint32_t currentRole = 0;  // At genesis MUST equal the VERIFIED commissioning binding's historicalInitialRoleId
                             // (0 or 1 only); exporter enforces this explicitly and copies it from the
                             // verified binding, never from caller input (see exportReceipt).
  uint16_t publisherKeyId = 0;
  uint8_t publisherKeyFingerprintSha256[kBootFloorPublisherFingerprintBytes] = {0};
  uint8_t hostTransactionId[kTransactionIdBytes] = {0};
  uint8_t authorityTransactionDigestSha256[kDigestBytes] = {0};  // Astra29: A == SHA256(the EXACT
                                                                  // AuthorityCodec::kRecordBytes signed commission
                                                                  // RECORD, INCLUDING the issuer signature) -- see
                                                                  // AuthorityCodec::computeRecordDigestSha256. NOT
                                                                  // just the pre-signature signed message, and NOT
                                                                  // a later wrapper signature (e.g. an
                                                                  // ActivationAuthorizationV1 wrapper, which is a
                                                                  // separate purpose/domain entirely).
  uint8_t commissionManifestDigestSha256[kDigestBytes] = {0};    // Copied from txn.manifestDigestSha256 (M).
  uint8_t preparedRootDigestSha256[kDigestBytes] = {0};          // The fixed, immutable pre-activation
                                                                  // "SnapshotRoot" digest (R): copied verbatim
                                                                  // from the registry's StoredTransactionRecord::
                                                                  // preparedRootDigestSha256, which
                                                                  // AuthorityCoordinator::runPrepareHandshake sets
                                                                  // from the device's own genuinely-staged,
                                                                  // signature-verified response.rootDigestSha256
                                                                  // (see PreparedRootCommitment.h -- there is no
                                                                  // issuer-precommitted value to compare this
                                                                  // against anymore) -- NEVER
                                                                  // txn.manifestDigestSha256 (M, the distinct
                                                                  // policy-document digest, not the root). This
                                                                  // snapshot digest excludes this receipt itself
                                                                  // and excludes mutable post-activation bytes
                                                                  // (TX/RX counters), so there is no
                                                                  // hash-of-itself dependency cycle.
  uint32_t floor = 0;  // MUST be 0 (genesis only); exporter enforces this explicitly, never derived from a caller value.
  uint8_t baselineImageSha256[kBootFloorBaselineImageDigestBytes] = {0};
  uint32_t baselineExtentLength = 0;
  uint8_t originalSdk28Sha256Digest[kBootFloorOriginalSdk28DigestBytes] = {0};
  uint8_t signatureEd25519[kSignatureBytes] = {0};

  // Not part of the wire record at all (no wire byte carries it) -- kept
  // purely as an in-memory convenience so callers/tests can still name
  // the purpose; always PublisherFloorActivation for anything this
  // codec ever produces or accepts.
  BootFloorReceiptPurpose purpose = BootFloorReceiptPurpose::PublisherFloorActivation;
};

// Minimal, local, explicit little-endian byte cursor pair -- deliberately
// NOT added to the shared ota/protocol/OtaByteStream.h (that header's
// OtaBoundedWriter/Reader are big-endian-only and shared by other, out-
// of-scope consumers this module must not perturb). This wire format is
// its own separate little-endian family, so it gets its own tiny,
// bounds-checked, non-throwing cursor, following the exact same
// discipline (never overruns the caller-owned buffer; every put/get
// returns false on failure, leaving no partial state observable).
class BootFloorLeWriter {
public:
  BootFloorLeWriter(uint8_t* buf, size_t capacity) : buf_(buf), capacity_(capacity), pos_(0) {}
  size_t size() const { return pos_; }
  size_t remaining() const { return capacity_ - pos_; }

  bool putU16(uint16_t v) {
    if (remaining() < 2) return false;
    buf_[pos_ + 0] = static_cast<uint8_t>(v & 0xFF);
    buf_[pos_ + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    pos_ += 2;
    return true;
  }
  bool putU32(uint32_t v) {
    if (remaining() < 4) return false;
    for (int i = 0; i < 4; ++i) buf_[pos_ + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
    pos_ += 4;
    return true;
  }
  bool putU64(uint64_t v) {
    if (remaining() < 8) return false;
    for (int i = 0; i < 8; ++i) buf_[pos_ + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
    pos_ += 8;
    return true;
  }
  bool putBytes(const uint8_t* src, size_t len) {
    if (len == 0) return true;
    if (remaining() < len) return false;
    for (size_t i = 0; i < len; ++i) buf_[pos_ + i] = src[i];
    pos_ += len;
    return true;
  }

private:
  uint8_t* buf_;
  size_t capacity_;
  size_t pos_;
};

class BootFloorLeReader {
public:
  BootFloorLeReader(const uint8_t* buf, size_t capacity) : buf_(buf), capacity_(capacity), pos_(0) {}
  size_t remaining() const { return capacity_ - pos_; }
  size_t position() const { return pos_; }

  bool getU16(uint16_t& out) {
    if (remaining() < 2) return false;
    out = static_cast<uint16_t>(buf_[pos_ + 0]) | (static_cast<uint16_t>(buf_[pos_ + 1]) << 8);
    pos_ += 2;
    return true;
  }
  bool getU32(uint32_t& out) {
    if (remaining() < 4) return false;
    out = 0;
    for (int i = 3; i >= 0; --i) out = (out << 8) | buf_[pos_ + i];
    pos_ += 4;
    return true;
  }
  bool getU64(uint64_t& out) {
    if (remaining() < 8) return false;
    out = 0;
    for (int i = 7; i >= 0; --i) out = (out << 8) | buf_[pos_ + i];
    pos_ += 8;
    return true;
  }
  bool getBytes(uint8_t* dst, size_t len) {
    if (len == 0) return true;
    if (remaining() < len) return false;
    for (size_t i = 0; i < len; ++i) dst[i] = buf_[pos_ + i];
    pos_ += len;
    return true;
  }

private:
  const uint8_t* buf_;
  size_t capacity_;
  size_t pos_;
};

class BootFloorActivationReceiptCodec {
public:
  // ROOT-decided canonical V1 body layout (every offset below is an
  // EXPLICIT, load-bearing contract with the Boot owner's independent C
  // codec -- do not reorder/resize without a fresh ROOT/Boot agreement):
  //
  //   offset  size  field
  //   0       4     magic               (FIXED =kRecordMagic, from Boot's header)
  //   4       2     recordVersion       (=1)
  //   6       2     recordBytesTotal    (=kRecordBytes, self-describing)
  //   8       4     bootDomain          (FIXED =kFixedBootDomainLiteral, "BOOT")
  //   12      8     hardwareUid         (full FICR UID, BE-decoded then LE-written)
  //   20      32    localMeshFullPublicKey
  //   52      32    consentOwnerPublicKey
  //   84      4     targetId
  //   88      4     profileId
  //   92      4     layoutId
  //   96      4     currentRole
  //   100     2     publisherKeyId
  //   102     32    publisherKeyFingerprintSha256
  //   134     16    hostTransactionId
  //   150     32    authorityTransactionDigestSha256
  //   182     32    commissionManifestDigestSha256
  //   214     32    preparedRootDigestSha256
  //   246     4     floor               (=0)
  //   250     32    baselineImageSha256
  //   282     4     baselineExtentLength
  //   286     32    originalSdk28Sha256Digest
  //   318     4     crc32               (IEEE 802.3/zlib, over bytes [0,318))
  //   -------
  //   322 total body bytes, then:
  //   322     64    signatureEd25519
  //   386 total record bytes.
  static constexpr size_t kBodyBytes = 322;
  static constexpr size_t kRecordBytes = kBodyBytes + kSignatureBytes;  // 386.

  static constexpr uint16_t kCurrentRecordVersion = 1;

  // CONFIRMED FINAL by ROOT, read directly from the Boot owner's own
  // authoritative shared C header (bootloader/xiao_nrf52840_ota/include/
  // xiao_ota_record.h, XIAO_OTA_FLOOR_ACTIVATION_MAGIC, not touched by
  // this file -- this constant is COPIED, never re-derived from an ASCII
  // comment/mnemonic). Wire bytes (little-endian) are 52 41 46 58.
  static constexpr uint32_t kRecordMagic = 0x58464152u;

  // CONFIRMED FINAL by ROOT: fixed protocol-level literal, ASCII "BOOT"
  // (0x42='B', 0x4F='O', 0x4F='O', 0x54='T'), read as a little-endian
  // uint32_t. Identical for every device -- see the top-of-file
  // commentary for why this replaces the prior per-device derived hash.
  static constexpr uint32_t kFixedBootDomainLiteral = 0x424F4F54u;

  static const char* signedDomain() { return "MeshCore/OTA/publisher-floor-activation/v1"; }
  // Exactly strlen(signedDomain()) -- the domain literal's terminating
  // NUL byte is DELIBERATELY EXCLUDED from the hashed/signed bytes (only
  // the 42 printable ASCII bytes are hashed; computeSignedDigest below
  // never copies/hashes a 43rd NUL byte).
  static constexpr size_t kSignedDomainBytes = 42;

  static size_t serializeBody(const BootFloorActivationReceiptV1& r, uint8_t* out, size_t out_len) {
    BootFloorLeWriter w(out, out_len);
    if (!w.putU32(kRecordMagic)) return 0;                    // @0
    if (!w.putU16(r.recordVersion)) return 0;                            // @4
    if (!w.putU16(static_cast<uint16_t>(kRecordBytes))) return 0;        // @6
    if (!w.putU32(kFixedBootDomainLiteral)) return 0;                    // @8
    if (!w.putU64(decodeUidBigEndian(r.hardwareUid))) return 0;          // @12
    if (!w.putBytes(r.localMeshFullPublicKey, kPublicKeyBytes)) return 0;    // @20
    if (!w.putBytes(r.consentOwnerPublicKey, kPublicKeyBytes)) return 0;     // @52
    if (!w.putU32(r.targetId)) return 0;                                 // @84
    if (!w.putU32(r.profileId)) return 0;                                // @88
    if (!w.putU32(r.layoutId)) return 0;                                 // @92
    if (!w.putU32(r.currentRole)) return 0;                              // @96
    if (!w.putU16(r.publisherKeyId)) return 0;                           // @100
    if (!w.putBytes(r.publisherKeyFingerprintSha256, kBootFloorPublisherFingerprintBytes)) return 0;  // @102
    if (!w.putBytes(r.hostTransactionId, kTransactionIdBytes)) return 0;     // @134
    if (!w.putBytes(r.authorityTransactionDigestSha256, kDigestBytes)) return 0;   // @150
    if (!w.putBytes(r.commissionManifestDigestSha256, kDigestBytes)) return 0;     // @182
    if (!w.putBytes(r.preparedRootDigestSha256, kDigestBytes)) return 0;           // @214
    if (!w.putU32(r.floor)) return 0;                                    // @246
    if (!w.putBytes(r.baselineImageSha256, kBootFloorBaselineImageDigestBytes)) return 0;  // @250
    if (!w.putU32(r.baselineExtentLength)) return 0;                     // @282
    if (!w.putBytes(r.originalSdk28Sha256Digest, kBootFloorOriginalSdk28DigestBytes)) return 0;  // @286
    if (w.size() != kBodyBytes - 4) return 0;  // Everything up to (but excluding) the CRC32 field.
    const uint32_t crc = ota::storage::Crc32::computeFinalized(out, w.size());
    if (!w.putU32(crc)) return 0;              // @318
    return w.size() == kBodyBytes ? w.size() : 0;
  }

  static size_t serializeRecord(const BootFloorActivationReceiptV1& r, uint8_t* out, size_t out_len) {
    BootFloorLeWriter w(out, out_len);
    uint8_t body[kBodyBytes];
    if (serializeBody(r, body, sizeof(body)) != kBodyBytes) return 0;
    if (!w.putBytes(body, kBodyBytes)) return 0;
    if (!w.putBytes(r.signatureEd25519, kSignatureBytes)) return 0;
    return w.size();
  }

  // Computes the 32-byte digest that is actually Ed25519-signed/verified:
  // SHA-256(signedDomain() || canonical 322-byte body). Plain (non-
  // prehash) Ed25519 then signs/verifies THIS digest as its message --
  // never the raw (domain || body) bytes, and never RFC 8032 Ed25519ph.
  static bool computeSignedDigest(const BootFloorActivationReceiptV1& r, uint8_t out_digest[kDigestBytes]) {
    uint8_t body[kBodyBytes];
    if (serializeBody(r, body, sizeof(body)) != kBodyBytes) return false;
    uint8_t domain_and_body[kSignedDomainBytes + kBodyBytes];
    std::memcpy(domain_and_body, signedDomain(), kSignedDomainBytes);
    std::memcpy(domain_and_body + kSignedDomainBytes, body, kBodyBytes);
    ota::trust::Sha256::hash(domain_and_body, sizeof(domain_and_body), out_digest);
    return true;
  }

  // Fails closed on any malformed/truncated/wrong-length/wrong-magic/
  // wrong-domain/wrong-CRC input, same discipline as
  // AuthorityCodec::parseRecord/BaselineCertificationManifestCodec::parse.
  static bool parseRecord(const uint8_t* in, size_t in_len, BootFloorActivationReceiptV1& out) {
    if (in_len != kRecordBytes) return false;

    // CRC32 over the body bytes preceding the CRC field itself must
    // match BEFORE any field is trusted/decoded.
    const uint32_t stored_crc = static_cast<uint32_t>(in[318]) | (static_cast<uint32_t>(in[319]) << 8) |
                                 (static_cast<uint32_t>(in[320]) << 16) | (static_cast<uint32_t>(in[321]) << 24);
    const uint32_t computed_crc = ota::storage::Crc32::computeFinalized(in, 318);
    if (stored_crc != computed_crc) return false;

    BootFloorActivationReceiptV1 parsed;
    BootFloorLeReader reader(in, kRecordBytes);
    uint32_t magic = 0;
    if (!reader.getU32(magic)) return false;
    if (magic != kRecordMagic) return false;
    if (!reader.getU16(parsed.recordVersion)) return false;
    if (parsed.recordVersion != kCurrentRecordVersion) return false;
    uint16_t record_bytes_field = 0;
    if (!reader.getU16(record_bytes_field)) return false;
    if (record_bytes_field != kRecordBytes) return false;
    uint32_t boot_domain = 0;
    if (!reader.getU32(boot_domain)) return false;
    if (boot_domain != kFixedBootDomainLiteral) return false;
    uint64_t uid_numeric = 0;
    if (!reader.getU64(uid_numeric)) return false;
    encodeUidBigEndian(uid_numeric, parsed.hardwareUid);
    if (!reader.getBytes(parsed.localMeshFullPublicKey, kPublicKeyBytes)) return false;
    if (!reader.getBytes(parsed.consentOwnerPublicKey, kPublicKeyBytes)) return false;
    if (!reader.getU32(parsed.targetId)) return false;
    if (!reader.getU32(parsed.profileId)) return false;
    if (!reader.getU32(parsed.layoutId)) return false;
    if (!reader.getU32(parsed.currentRole)) return false;
    if (!reader.getU16(parsed.publisherKeyId)) return false;
    if (!reader.getBytes(parsed.publisherKeyFingerprintSha256, kBootFloorPublisherFingerprintBytes)) return false;
    if (!reader.getBytes(parsed.hostTransactionId, kTransactionIdBytes)) return false;
    if (!reader.getBytes(parsed.authorityTransactionDigestSha256, kDigestBytes)) return false;
    if (!reader.getBytes(parsed.commissionManifestDigestSha256, kDigestBytes)) return false;
    if (!reader.getBytes(parsed.preparedRootDigestSha256, kDigestBytes)) return false;
    if (!reader.getU32(parsed.floor)) return false;
    if (!reader.getBytes(parsed.baselineImageSha256, kBootFloorBaselineImageDigestBytes)) return false;
    if (!reader.getU32(parsed.baselineExtentLength)) return false;
    if (!reader.getBytes(parsed.originalSdk28Sha256Digest, kBootFloorOriginalSdk28DigestBytes)) return false;
    uint32_t crc_field_reread = 0;
    if (!reader.getU32(crc_field_reread)) return false;  // Already validated above; consumed here to advance the cursor.
    if (!reader.getBytes(parsed.signatureEd25519, kSignatureBytes)) return false;
    parsed.purpose = BootFloorReceiptPurpose::PublisherFloorActivation;
    out = parsed;
    return true;
  }

private:
  // Decodes AuthorityBinding::hardwareUid's canonical big-endian 8-byte
  // representation (see AuthorityTypes.h / FW's OtaBaselineCertificationEvidence
  // BE8 UID=(DEVICEID[1]<<32)|DEVICEID[0] convention) into a plain numeric
  // value. Deliberately NOT a raw memcpy -- this module's wire format is
  // little-endian, so the byte order must actually be reinterpreted via
  // genuine numeric decode/encode, never assumed identical.
  static uint64_t decodeUidBigEndian(const uint8_t uid[kHardwareUidBytes]) {
    uint64_t v = 0;
    for (size_t i = 0; i < kHardwareUidBytes; ++i) v = (v << 8) | uid[i];
    return v;
  }

  static void encodeUidBigEndian(uint64_t v, uint8_t out_uid[kHardwareUidBytes]) {
    for (int i = static_cast<int>(kHardwareUidBytes) - 1; i >= 0; --i) {
      out_uid[i] = static_cast<uint8_t>(v & 0xFF);
      v >>= 8;
    }
  }
};

// Astra role-1 residual ("SDK-only match insufficient"): the full set of
// AUTHORITATIVE baseline facts genuinely frozen once, at commissioning/
// prepared-P time, for this exact owner/transaction -- never a live
// re-measurement, and never just the SDK28 digest alone. A caller
// supplying a `BootFloorBaselineEvidence` that matches SDK28 alone but
// disagrees on the actual image contents/extent/compiled target must
// still be rejected.
struct AuthorityBootFloorBaselineProvenanceRecord {
  uint8_t imageSha256[kBootFloorBaselineImageDigestBytes] = {0};
  uint32_t extentLength = 0;
  uint32_t targetId = 0;
  uint8_t original28Sha256Digest[kBootFloorOriginalSdk28DigestBytes] = {0};
};

// Abstract, explicit seam for the AUTHORITATIVE original baseline
// provenance record captured ONCE at commissioning time (Root's own
// separate "original-sidecar/pre-admission provenance" design, not
// implemented by this module) -- deliberately NOT a live re-measurement
// of the device's CURRENT SDK/image: a legitimate later install
// genuinely changes the device's current SDK/image, so re-hashing
// "what's on the device right now" every boot would wrongly punish
// normal operation. Instead, this seam answers "what was ORIGINALLY
// genuinely recorded/certified for this exact owner/transaction at
// commissioning time", a fixed historical fact that never changes for a
// given transaction. Default-deny: a BootFloorActivationReceiptExporter
// constructed without one denies every export (same discipline as
// PublisherKeyTrust/AuthorityIssuerTrust below) -- this module holds NO
// such storage itself and fabricates nothing if the seam is missing.
class OriginalBaselineSdk28Provenance {
public:
  virtual ~OriginalBaselineSdk28Provenance() = default;
  virtual bool lookupOriginalBaselineProvenance(const AuthorityBinding& owner,
                                                 const uint8_t transactionId[kTransactionIdBytes],
                                                 AuthorityBootFloorBaselineProvenanceRecord& out_record) const = 0;
};

// Abstract, explicit seam for the EXISTING firmware publisher signing
// capability. This header does NOT create, hold, or simulate any
// production key -- a real integrator (MAIN/Store) wires this to
// whatever already holds the real existing publisher private key.
// Default-deny: a BootFloorActivationReceiptExporter constructed without
// one denies every export. Deliberately NOT the same interface as
// AuthorityIssuerTrust/any image-signing code path -- ordinary OTA image
// signing has no access to this seam at all and so cannot implicitly gain
// the ability to export this receipt. `signWithPublisherKey`/the
// verification call site below both operate on the 32-byte pre-hashed
// digest (see BootFloorActivationReceiptCodec::computeSignedDigest), not
// the raw domain||body bytes -- the interface itself is unchanged (still
// generic message+len), only what bytes this module passes in differ.
class PublisherKeyTrust {
public:
  virtual ~PublisherKeyTrust() = default;
  virtual bool publisherKeyId(uint16_t& out_key_id) const = 0;
  virtual bool publisherPublicKey(uint8_t out_public_key[kPublicKeyBytes]) const = 0;
  virtual bool signWithPublisherKey(const uint8_t* message, size_t message_len,
                                     uint8_t out_signature[kSignatureBytes]) const = 0;
};

enum class BootFloorExportOutcome : uint8_t {
  Ok = 0,
  Denied = 1,               // A required dependency was never wired.
  TransactionNotFound = 2,
  RegistryDisagreement = 3,  // Anything short of a clean, both-copies-agreed resolution -- never a partial/single-copy export.
  NotActivationSpent = 4,    // The transaction has not (yet, or ever) reached ActivationSpent in both copies.
  OperationMismatch = 5,     // Not a genesis Commission transaction, or its VERIFIED historical role is
                             // neither 0 nor 1 -- Repair/Rekey/CertifyExistingBaseline never qualify for
                             // this grant, and no other role value is a supported genesis.
  SignatureInvalid = 6,      // Independent issuer-signature re-verification failed.
  Superseded = 7,            // A later history already exists for this owner -- never export genesis over it.
  PublisherSigningFailed = 8,
  OriginalBaselineSdk28Mismatch = 9,  // Caller-supplied baseline evidence does not match the authoritative
                                      // original-SDK28 provenance record for this exact owner/transaction.
  BaselineImageProvenanceMismatch = 10,  // Astra role-1 residual: caller-supplied image SHA-256, extent
                                          // length, or compiled target does not match the authoritative
                                          // provenance record -- SDK28 alone matching is not sufficient.
};

// Verifies (1) the issuer-authorized AuthorityTransaction independently,
// (2) that BOTH reconciled host registry copies agree the exact
// transaction is ActivationSpent, and (3) that the caller-supplied
// baseline evidence's original-SDK28 digest actually matches the
// AUTHORITATIVE provenance record captured once at commissioning time
// (never a live re-measurement) -- THEN, and only then, signs/exports a
// BootFloorActivationReceiptV1 under the existing firmware publisher
// key. Performs NO filesystem/LittleFS access; never mutates the
// registry; every export is idempotently retryable for the exact same
// still-undominated transaction (calling twice for the same still-
// current transaction produces the same receipt fields, modulo a fresh
// signature).
class BootFloorActivationReceiptExporter {
public:
  // `crossProcessLock` is a REQUIRED dependency exactly like verifier_/
  // issuerTrust_/publisherKey_/originalBaselineProvenance_ (Sol39 H4):
  // this entrypoint independently reads and signs against the SAME
  // two-copy registry the Coordinator mutates, so it needs the SAME
  // cross-process serialization the Coordinator's own mutating
  // entrypoints already hold -- the Coordinator's own internal storage
  // barriers never covered this entirely separate code path. A caller
  // that genuinely only runs single-process must pass an EXPLICIT
  // InProcessOnlyAuthorityCrossProcessLock, never rely on an implicit
  // nullptr fallback.
  BootFloorActivationReceiptExporter(AuthorityRegistryPair& registry, ota::trust::SignatureVerifier* verifier,
                                      AuthorityIssuerTrust* issuerTrust, PublisherKeyTrust* publisherKey,
                                      OriginalBaselineSdk28Provenance* originalBaselineProvenance,
                                      AuthorityCrossProcessLock* crossProcessLock)
      : registry_(registry),
        verifier_(verifier),
        issuerTrust_(issuerTrust),
        publisherKey_(publisherKey),
        originalBaselineProvenance_(originalBaselineProvenance),
        crossProcessLock_(crossProcessLock) {}
  // Zero I/O here: no file/socket touched until exportReceipt is actually invoked.

  bool dependenciesWired() const {
    return verifier_ != nullptr && issuerTrust_ != nullptr && publisherKey_ != nullptr &&
           originalBaselineProvenance_ != nullptr && crossProcessLock_ != nullptr;
  }

  BootFloorExportOutcome exportReceipt(const uint8_t transactionId[kTransactionIdBytes],
                                        const BootFloorBaselineEvidence& baseline,
                                        BootFloorActivationReceiptV1& out_receipt) {
    if (!dependenciesWired()) return BootFloorExportOutcome::Denied;

    // Sol39 H4: the ENTIRE lookup->provenance->durability-barrier->
    // fresh-readback->signing sequence below is now one atomic
    // critical section under the SAME cross-process lease the
    // Coordinator's mutating entrypoints hold -- never acquired just
    // around a sub-step, which would reopen the exact "readable cached
    // Spent still releases a permit" gap this review found.
    AuthorityCrossProcessLockGuard lock_guard(crossProcessLock_);
    if (!lock_guard.acquired()) return BootFloorExportOutcome::Denied;

    ReconciliationResult rec = registry_.reconcile(transactionId);
    if (rec.outcome == ReconciliationOutcome::NotFound) return BootFloorExportOutcome::TransactionNotFound;
    // Strict: "both reconciled host registry copies ActivationSpent"
    // means a clean Agreed resolution -- RecoveredFromSingleCopy (one
    // copy missing/lagging) is explicitly NOT sufficient for durably
    // exporting an external receipt, even though the ordinary
    // Commission/Repair/Rekey lifecycle itself tolerates it for
    // progressing state. A missing/corrupt copy never becomes unused
    // permission to export, either.
    if (rec.outcome != ReconciliationOutcome::Agreed) return BootFloorExportOutcome::RegistryDisagreement;
    if (rec.resolved.state != TransactionState::ActivationSpent) return BootFloorExportOutcome::NotActivationSpent;
    // Genesis-only: neither an ordinary TX/RX ActivationPermit grant on a
    // Repair/Rekey transaction, nor a CertifyExistingBaseline
    // certification, ever counts as proof for this floor. Only a still-
    // undominated Commission transaction does, and only at a SUPPORTED
    // historical role (Astra role-1 genesis: 0 == companion, 1 ==
    // repeater; no other role is a supported genesis path). The role
    // carried into the receipt below is always this VERIFIED binding's
    // own value -- never caller input, and never silently widened past
    // the two explicitly supported values.
    if (rec.resolved.txn.operation != AuthorityOperation::Commission) return BootFloorExportOutcome::OperationMismatch;
    if (rec.resolved.txn.binding.historicalInitialRoleId != 0 && rec.resolved.txn.binding.historicalInitialRoleId != 1) {
      return BootFloorExportOutcome::OperationMismatch;
    }

    // Independently re-verify the issuer signature -- never trust the
    // registry copy's recorded state alone, even though it was already
    // verified once at submission time (AuthorityCoordinator::
    // submitCommission).
    uint8_t issuer_public_key[kPublicKeyBytes];
    if (!issuerTrust_->lookupIssuerPublicKey(rec.resolved.txn.issuerKeyId, issuer_public_key)) {
      return BootFloorExportOutcome::SignatureInvalid;
    }
    uint8_t signed_msg[AuthorityCodec::kSignedMessageBytes];
    if (AuthorityCodec::serializeSignedMessage(rec.resolved.txn, signed_msg, sizeof(signed_msg)) !=
        AuthorityCodec::kSignedMessageBytes) {
      return BootFloorExportOutcome::SignatureInvalid;
    }
    if (!verifier_->verify(rec.resolved.txn.issuerSignatureEd25519, kSignatureBytes, signed_msg, sizeof(signed_msg),
                            issuer_public_key, kPublicKeyBytes)) {
      return BootFloorExportOutcome::SignatureInvalid;
    }

    // Sol39 H5: the OLD check here scanned reconcileLatestActivationForOwner
    // -- scoped to this EXACT fullPK -- which is structurally BLIND to a
    // cross-key Rekey: after Rekey A->B reaches ActivationSpent, old
    // Commission A's OWN owner-scoped "latest activation" still reports
    // itself as latest (the scope never crosses to B's fullPK), letting
    // a stale genesis receipt be exported for a superseded physical
        // device. reconcilePhysicalLineage instead scans by PHYSICAL
    // device identity (UID+cryptoDomain+layout, deliberately ignoring
    // fullPK) across ANY state (purpose-filtered to exclude
    // CertifyExistingBaseline) -- requiring the Commission being
    // exported to still be the CURRENT tip, across every key this
    // physical device has ever held, fences BOTH same-key supersession
    // (Repair/Rekey past this txn) AND cross-key supersession, and ALSO
    // denies export while any pending (not-yet-activated) higher fact
    // for this physical device exists at all -- "pending higher facts
    // also fence a fresh genesis export".
    ReconciliationResult physical_tip = registry_.reconcilePhysicalLineage(rec.resolved.txn.binding);
    if (physical_tip.outcome != ReconciliationOutcome::Agreed) return BootFloorExportOutcome::RegistryDisagreement;
    if (std::memcmp(physical_tip.resolved.txn.transactionId, transactionId, kTransactionIdBytes) != 0) {
      return BootFloorExportOutcome::Superseded;
    }

    // The caller-supplied baseline evidence must match the AUTHORITATIVE
    // provenance record captured once at commissioning/prepared-P time
    // for this exact owner/transaction -- never trusted from the caller
    // alone, and never a live re-measurement of whatever image/SDK the
    // device currently happens to be running (a legitimate later install
    // genuinely changes that). Astra role-1 residual ("SDK-only match
    // insufficient"): image SHA-256, extent length, and compiled target
    // are ALL independently re-checked here too, not only the SDK28
    // digest -- a caller cannot pass a genuine original SDK28 digest
    // alongside a fabricated/mismatched image or extent/target and have
    // this exporter bless it.
    AuthorityBootFloorBaselineProvenanceRecord authoritative;
    if (!originalBaselineProvenance_->lookupOriginalBaselineProvenance(rec.resolved.txn.binding, transactionId,
                                                                        authoritative)) {
      return BootFloorExportOutcome::Denied;
    }
    if (std::memcmp(authoritative.original28Sha256Digest, baseline.original28Sha256Digest,
                     kBootFloorOriginalSdk28DigestBytes) != 0) {
      return BootFloorExportOutcome::OriginalBaselineSdk28Mismatch;
    }
    if (std::memcmp(authoritative.imageSha256, baseline.imageSha256, kBootFloorBaselineImageDigestBytes) != 0 ||
        authoritative.extentLength != baseline.extentLength || authoritative.targetId != baseline.targetId) {
      return BootFloorExportOutcome::BaselineImageProvenanceMismatch;
    }

    // Sol39 H4: a positive both-copies durability barrier, IMMEDIATELY
    // followed by a FRESH readback of the exact transaction, both still
    // under the SAME held lease, right before producing the signed
    // digest below. A prior fault (e.g. a Spent marker fsync failure)
    // that left a copy's durable-on-disk state unconfirmed must DENY
    // here even though the earlier `rec` above read back a cached-
    // readable Agreed/ActivationSpent view -- "readable CRC/marker
    // agreement != positive durability after a known failure". No
    // poison/undo/history-rollback: a genuine failure here denies
    // THIS export attempt only, it never mutates registry state.
    if (!registry_.confirmBothCopiesDurable()) return BootFloorExportOutcome::RegistryDisagreement;

    ReconciliationResult fresh = registry_.reconcile(transactionId);
    if (fresh.outcome != ReconciliationOutcome::Agreed) return BootFloorExportOutcome::RegistryDisagreement;
    if (fresh.resolved.state != TransactionState::ActivationSpent) return BootFloorExportOutcome::NotActivationSpent;
    if (!fresh.resolved.sameTransactionIdentity(rec.resolved) || !fresh.resolved.sameSignedContent(rec.resolved)) {
      // Something about the durably-committed record disagrees with
      // what was read moments ago under the SAME lease -- never
      // possible in a correctly-behaving store, but if it ever were,
      // this must deny rather than silently sign whichever view "won".
      return BootFloorExportOutcome::RegistryDisagreement;
    }
    rec = fresh;  // Sign from the FRESH, durability-confirmed readback.

    uint16_t publisher_key_id = 0;
    uint8_t publisher_public_key[kPublicKeyBytes];
    if (!publisherKey_->publisherKeyId(publisher_key_id) || !publisherKey_->publisherPublicKey(publisher_public_key)) {
      return BootFloorExportOutcome::Denied;
    }

    BootFloorActivationReceiptV1 receipt;
    receipt.recordVersion = BootFloorActivationReceiptCodec::kCurrentRecordVersion;
    receipt.purpose = BootFloorReceiptPurpose::PublisherFloorActivation;
    std::memcpy(receipt.hardwareUid, rec.resolved.txn.binding.hardwareUid, kHardwareUidBytes);
    std::memcpy(receipt.localMeshFullPublicKey, rec.resolved.txn.binding.meshFullPublicKey, kPublicKeyBytes);
    std::memcpy(receipt.consentOwnerPublicKey, rec.resolved.txn.binding.consentOwnerPublicKey, kPublicKeyBytes);
    receipt.targetId = baseline.targetId;  // Separate compiled identifier -- NOT assumed equal to profileId.
    receipt.profileId = rec.resolved.txn.binding.profileId;
    receipt.layoutId = rec.resolved.txn.binding.layoutId;
    // Genesis: copies the VERIFIED Commission binding's OWN historical
    // role (already independently confirmed to be 0 or 1 above) --
    // never caller input, and never a value this function invents.
    receipt.currentRole = rec.resolved.txn.binding.historicalInitialRoleId;
    receipt.publisherKeyId = publisher_key_id;
    ota::trust::Sha256::hash(publisher_public_key, kPublicKeyBytes, receipt.publisherKeyFingerprintSha256);
    std::memcpy(receipt.hostTransactionId, transactionId, kTransactionIdBytes);
    // Astra29: A must be the digest of the EXACT signed RECORD, including
    // the issuer signature -- not just the pre-signature signed message
    // hashed above purely for signature verification purposes.
    if (!AuthorityCodec::computeRecordDigestSha256(rec.resolved.txn, receipt.authorityTransactionDigestSha256)) {
      return BootFloorExportOutcome::SignatureInvalid;
    }
    std::memcpy(receipt.commissionManifestDigestSha256, rec.resolved.txn.manifestDigestSha256, kDigestBytes);
    std::memcpy(receipt.preparedRootDigestSha256, rec.resolved.preparedRootDigestSha256, kDigestBytes);
    receipt.floor = 0;  // Genesis only: explicitly fixed, never derived from any caller/txn value.
    std::memcpy(receipt.baselineImageSha256, baseline.imageSha256, kBootFloorBaselineImageDigestBytes);
    receipt.baselineExtentLength = baseline.extentLength;
    std::memcpy(receipt.originalSdk28Sha256Digest, baseline.original28Sha256Digest, kBootFloorOriginalSdk28DigestBytes);

    uint8_t digest[kDigestBytes];
    if (!BootFloorActivationReceiptCodec::computeSignedDigest(receipt, digest)) {
      return BootFloorExportOutcome::Denied;
    }
    if (!publisherKey_->signWithPublisherKey(digest, sizeof(digest), receipt.signatureEd25519)) {
      return BootFloorExportOutcome::PublisherSigningFailed;
    }

    out_receipt = receipt;
    return BootFloorExportOutcome::Ok;
  }

private:
  AuthorityRegistryPair& registry_;
  ota::trust::SignatureVerifier* verifier_;
  AuthorityIssuerTrust* issuerTrust_;
  PublisherKeyTrust* publisherKey_;
  OriginalBaselineSdk28Provenance* originalBaselineProvenance_;
  AuthorityCrossProcessLock* crossProcessLock_;
};

}  // namespace authority
}  // namespace ota
