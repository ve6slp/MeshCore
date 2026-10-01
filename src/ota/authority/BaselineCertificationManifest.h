#pragma once

// Canonical, fixed-width, bounds-checked evidence manifest for the
// CertifyExistingBaseline authority operation (AuthorityTypes.h). This is
// NOT a new signed-transaction wire format: an AuthorityTransaction's
// existing `manifestDigestSha256` field (already used generically as
// "digest of the thing this transaction grants" for Repair/Rekey) is
// reused here as the digest of THIS manifest's canonical serialization --
// the wire format everyone else depends on (238-byte AuthorityCodec
// record) never changes.
//
// This manifest binds exactly what the approved Astra contract requires
// for turning an existing stock OTA=1 USB image into a positively
// certified Normal baseline: the approved CURRENT image's SHA-256 +
// exact extent, the exact SDK identifier this baseline was built/verified
// against (a full SHA-256 digest of frozen identifier bytes -- the SAME
// tightened convention as BootFloorActivationReceipt.h's
// originalSdk28Sha256Digest, not a bare version integer that a caller
// could "guess accepted"), a positively identified stock-loader
// artifact's own hash/executable range, the relevant boot config, and
// whether ordinary (read-only, existing) userdata behavior is allowed
// under this baseline. It intentionally carries NO counters/floors/identity
// material of its own -- those stay exclusively in AuthorityBinding /
// AuthorityTransaction, and CertifyExistingBaseline transactions are
// required (see AuthorityCoordinator::submitCertifyExistingBaseline) to
// carry all-zero revision/predecessor/floors, so this manifest can never
// be mistaken for a counter-seeding grant.
//
// Computing/verifying this digest against REAL on-device image/loader
// bytes is explicitly Firmware's integration step (see
// src/helpers/ota/OtaBaselineCertificationEvidence.h, already landed by
// the Firmware owner with the same default-deny Unknown/Certified
// contract this file's digest is meant to bind against) -- this header
// only defines the canonical encoding both sides must agree on.

#include <stdint.h>
#include <stddef.h>
#include "ota/protocol/OtaByteStream.h"
#include "ota/trust/Sha256.h"

namespace ota {
namespace authority {

constexpr size_t kBaselineImageDigestBytes = 32;
constexpr size_t kBaselineStockLoaderDigestBytes = 32;
// Tightened to match BootFloorActivationReceipt.h's
// originalSdk28Sha256Digest convention: a full SHA-256 digest of exact,
// frozen SDK identifier bytes, never a bare version integer.
constexpr size_t kBaselineSdkDigestBytes = 32;

// Every field the approved contract lists for CertifyExistingBaseline,
// beyond what AuthorityBinding/AuthorityTransaction already bind.
// Fixed-width, no variable-length/unbounded fields -- 117 bytes total,
// comfortably inside an 8 KiB task stack.
struct BaselineCertificationManifest {
  uint8_t approvedImageSha256[kBaselineImageDigestBytes] = {0};
  uint32_t approvedImageExtentOffset = 0;
  uint32_t approvedImageExtentLength = 0;
  // Full SHA-256 digest of the exact frozen SDK identifier bytes this
  // baseline was certified against -- NOT a version integer (corrected
  // for the same reason BootFloorActivationReceiptV1's SDK field was
  // corrected: a caller could otherwise "guess" a version int accepted).
  uint8_t expectedSdk28Sha256Digest[kBaselineSdkDigestBytes] = {0};
  uint8_t stockLoaderArtifactSha256[kBaselineStockLoaderDigestBytes] = {0};
  uint32_t stockLoaderArtifactRangeStart = 0;
  uint32_t stockLoaderArtifactRangeLength = 0;
  uint32_t bootConfigId = 0;
  bool allowOrdinaryUserdata = false;  // Ordinary (read-only, existing) userdata use -- never install/format authority.
};

class BaselineCertificationManifestCodec {
public:
  // sha(32) + extentOffset(4) + extentLength(4) + sdk28Digest(32) +
  // loaderSha(32) + loaderRangeStart(4) + loaderRangeLength(4) +
  // bootConfigId(4) + allowUserdata(1) = 117 bytes. (CORRECTED from 89:
  // +28 net for expectedSdk28Sha256Digest[32] replacing the previous
  // guessed sdkVersion[4].)
  static constexpr size_t kManifestBytes = 117;

  static size_t serialize(const BaselineCertificationManifest& manifest, uint8_t* out, size_t out_len) {
    meshcore::ota::protocol::OtaBoundedWriter writer(out, out_len);
    if (!writer.putBytes(manifest.approvedImageSha256, kBaselineImageDigestBytes)) return 0;
    if (!writer.putU32(manifest.approvedImageExtentOffset)) return 0;
    if (!writer.putU32(manifest.approvedImageExtentLength)) return 0;
    if (!writer.putBytes(manifest.expectedSdk28Sha256Digest, kBaselineSdkDigestBytes)) return 0;
    if (!writer.putBytes(manifest.stockLoaderArtifactSha256, kBaselineStockLoaderDigestBytes)) return 0;
    if (!writer.putU32(manifest.stockLoaderArtifactRangeStart)) return 0;
    if (!writer.putU32(manifest.stockLoaderArtifactRangeLength)) return 0;
    if (!writer.putU32(manifest.bootConfigId)) return 0;
    if (!writer.putU8(manifest.allowOrdinaryUserdata ? 1 : 0)) return 0;
    return writer.size();
  }

  // Fails closed (returns false, leaves `out` default-constructed) on any
  // malformed/truncated/wrong-length input -- same discipline as
  // AuthorityCodec::parseRecord.
  static bool parse(const uint8_t* in, size_t in_len, BaselineCertificationManifest& out) {
    if (in_len != kManifestBytes) return false;
    BaselineCertificationManifest parsed;
    meshcore::ota::protocol::OtaBoundedReader reader(in, kManifestBytes);
    if (!reader.getBytes(parsed.approvedImageSha256, kBaselineImageDigestBytes)) return false;
    if (!reader.getU32(parsed.approvedImageExtentOffset)) return false;
    if (!reader.getU32(parsed.approvedImageExtentLength)) return false;
    if (!reader.getBytes(parsed.expectedSdk28Sha256Digest, kBaselineSdkDigestBytes)) return false;
    if (!reader.getBytes(parsed.stockLoaderArtifactSha256, kBaselineStockLoaderDigestBytes)) return false;
    if (!reader.getU32(parsed.stockLoaderArtifactRangeStart)) return false;
    if (!reader.getU32(parsed.stockLoaderArtifactRangeLength)) return false;
    if (!reader.getU32(parsed.bootConfigId)) return false;
    uint8_t allow_raw = 0;
    if (!reader.getU8(allow_raw)) return false;
    if (allow_raw > 1) return false;  // Not a valid bool encoding -- fail closed, never coerce.
    parsed.allowOrdinaryUserdata = (allow_raw == 1);
    out = parsed;
    return true;
  }

  // Digest that goes into AuthorityTransaction::manifestDigestSha256 for
  // a CertifyExistingBaseline transaction. Real SHA-256 (ota::trust::
  // Sha256), not a placeholder -- both the issuer/CLI (computing this
  // once at signing time) and the device (recomputing it from its own
  // freshly-measured evidence every boot, never a cached value) must
  // reach byte-identical results.
  static bool computeDigestSha256(const BaselineCertificationManifest& manifest, uint8_t out_digest[32]) {
    uint8_t encoded[kManifestBytes];
    if (serialize(manifest, encoded, sizeof(encoded)) != kManifestBytes) return false;
    ota::trust::Sha256 hasher;
    hasher.reset();
    hasher.update(encoded, sizeof(encoded));
    hasher.finish(out_digest);
    return true;
  }
};

}  // namespace authority
}  // namespace ota
