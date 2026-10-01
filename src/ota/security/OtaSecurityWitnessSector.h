#pragma once

// Explicit, typed, fixed-layout codec for one 4096-byte head-witness
// sector: a 32-byte sector header binding (store identity, destination
// snapshot digest, protected generation, owner bank) followed by 254
// 16-byte witness records, one per ordinary data-cell index in the
// OPPOSITE bank (see OtaSecurityGeometry.h). No packed struct /
// reinterpret_cast anywhere.

#include <stdint.h>
#include <cstring>

#include "ota/security/OtaSecurityByteCodec.h"
#include "ota/security/OtaSecurityEvidence.h"
#include "ota/security/OtaSecurityGeometry.h"
#include "ota/storage/Crc32.h"

namespace ota {
namespace security {

struct OtaSecurityWitnessSectorHeader {
  uint64_t storeIdentity = 0;        // truncated to 8 bytes; binds this sector to one physical store instance.
  uint64_t destSnapshotDigest = 0;   // truncated to 8 bytes; the generation-defining snapshot this sector protects.
  uint32_t protectedGeneration = 0;  // the generation of cells in the OPPOSITE bank this sector attests to.
  uint16_t ownerBankSlot = 0;        // 0 = bank A, 1 = bank B -- the bank THIS witness sector physically lives in.
};

class OtaSecurityWitnessHeaderCodec {
public:
  static bool encodeBodyAndCrc(const OtaSecurityWitnessSectorHeader& header, uint8_t* out, size_t outLen) {
    if (outLen < kWitnessHeaderBytes) return false;
    std::memset(out, 0, kWitnessHeaderCrcOffset);
    size_t pos = 0;
    if (!putU64(out, outLen, pos, header.storeIdentity)) return false;
    pos += 8;
    if (!putU64(out, outLen, pos, header.destSnapshotDigest)) return false;
    pos += 8;
    if (!putU32(out, outLen, pos, header.protectedGeneration)) return false;
    pos += 4;
    if (!putU16(out, outLen, pos, header.ownerBankSlot)) return false;
    pos += 2;
    pos += 2;  // reserved, stays zero.
    if (pos != kWitnessHeaderFixedBytes) return false;
    const uint32_t crc = ::ota::storage::Crc32::computeFinalized(out, kWitnessHeaderCrcOffset);
    return putU32(out, outLen, kWitnessHeaderCrcOffset, crc);
  }

  // Writes the prepared marker at its absolute kWitnessHeaderMarkerOffset
  // within a FULL kWitnessHeaderBytes-sized sector-header buffer (same
  // convention as OtaSecurityDataCellCodec::encodeCommitMarker() --
  // callers wanting only the isolated 4 marker bytes must encode into a
  // full-size scratch buffer and slice them out themselves).
  static bool encodeMarker(uint8_t* out, size_t outLen) {
    return putU32(out, outLen, kWitnessHeaderMarkerOffset, kWitnessHeaderPreparedMarker);
  }

  static OtaSecurityEvidence classify(const uint8_t* raw, size_t rawLen, OtaSecurityWitnessSectorHeader& outHeader) {
    if (rawLen < kWitnessHeaderBytes) return OtaSecurityEvidence::Unprovable;
    if (isAllFF(raw, rawLen, 0, kWitnessHeaderBytes)) return OtaSecurityEvidence::AbsentBytes;

    const uint32_t bodyCrc = ::ota::storage::Crc32::computeFinalized(raw, kWitnessHeaderCrcOffset);
    uint32_t storedCrc = 0;
    getU32(raw, rawLen, kWitnessHeaderCrcOffset, storedCrc);
    if (bodyCrc != storedCrc) return OtaSecurityEvidence::Unprovable;

    getU64(raw, rawLen, 0, outHeader.storeIdentity);
    getU64(raw, rawLen, 8, outHeader.destSnapshotDigest);
    getU32(raw, rawLen, 16, outHeader.protectedGeneration);
    getU16(raw, rawLen, 20, outHeader.ownerBankSlot);
    if (outHeader.ownerBankSlot > 1) return OtaSecurityEvidence::Unprovable;

    uint32_t marker = 0;
    getU32(raw, rawLen, kWitnessHeaderMarkerOffset, marker);
    if (marker == kWitnessHeaderPreparedMarker) return OtaSecurityEvidence::Committed;
    return OtaSecurityEvidence::BodyOnly;
  }
};

class OtaSecurityWitnessRecordCodec {
public:
  // `contextualCrc` MUST already bind (store identity, snapshot digest,
  // generation, owner bank, slot index, lsn) -- see
  // OtaSecurityAppendEngine.h::computeWitnessContextualCrc().
  static bool encodeBodyAndCrc(uint64_t lsn, uint32_t contextualCrc, uint8_t* out, size_t outLen) {
    if (outLen < kWitnessRecordBytes) return false;
    if (!putU64(out, outLen, 0, lsn)) return false;
    return putU32(out, outLen, kWitnessRecordCrcOffset, contextualCrc);
  }

  // Writes the commit marker at its absolute kWitnessRecordMarkerOffset
  // within a FULL kWitnessRecordBytes-sized record buffer (same convention
  // as the witness header/cell marker encoders above).
  static bool encodeMarker(uint8_t* out, size_t outLen) {
    return putU32(out, outLen, kWitnessRecordMarkerOffset, kCellCommitMarker);
  }

  // `expectedContextualCrc` is computed by the caller from the SAME
  // binding context used at write time; a stored CRC that doesn't match
  // it is treated identically to a raw CRC mismatch (Unprovable) --
  // the witness record is bound to its exact slot/generation/identity,
  // not a standalone arbitrary LSN.
  static OtaSecurityEvidence classify(const uint8_t* raw, size_t rawLen, uint32_t expectedContextualCrc,
                                      uint64_t& outLsn) {
    if (rawLen < kWitnessRecordBytes) return OtaSecurityEvidence::Unprovable;
    if (isAllFF(raw, rawLen, 0, kWitnessRecordBytes)) return OtaSecurityEvidence::AbsentBytes;

    uint64_t lsn = 0;
    uint32_t storedCrc = 0;
    getU64(raw, rawLen, 0, lsn);
    getU32(raw, rawLen, kWitnessRecordCrcOffset, storedCrc);
    if (storedCrc != expectedContextualCrc) {
      return OtaSecurityEvidence::Unprovable;
    }
    outLsn = lsn;

    uint32_t marker = 0;
    getU32(raw, rawLen, kWitnessRecordMarkerOffset, marker);
    if (marker == kCellCommitMarker) return OtaSecurityEvidence::Committed;
    return OtaSecurityEvidence::BodyOnly;
  }
};

}  // namespace security
}  // namespace ota
