#pragma once

// Explicit, typed, fixed-layout codec for one 128-byte data cell (see
// OtaSecurityGeometry.h for the exact byte offsets). No packed struct /
// reinterpret_cast is used anywhere: every field is serialized/deserialized
// through OtaSecurityByteCodec.h's bounds-checked helpers.

#include <stdint.h>
#include <cstring>

#include "ota/security/OtaSecurityByteCodec.h"
#include "ota/security/OtaSecurityEvidence.h"
#include "ota/security/OtaSecurityGeometry.h"
#include "ota/storage/Crc32.h"

namespace ota {
namespace security {

// Record types a data cell can hold. Deliberately a closed, explicit set --
// unknown values found on cold scan are treated as Unprovable, never
// silently interpreted.
enum class OtaSecurityRecordType : uint8_t {
  TxReservation = 1,    // global TX reserve64 upper bound for the local identity.
  RxPeerAdvance = 2,    // full 32-byte peer identity + watermark: FIRST occurrence for a given
                        // peer is that peer's one-use table enrollment; later occurrences for
                        // the SAME full 32 bytes advance its existing table entry.
  RxGroupAdvance = 3,   // full 92-byte group/cohort context + watermark; same first-occurrence-
                        // enrolls / later-occurrence-advances rule as RxPeerAdvance, keyed by the
                        // full 92-byte context (never a hash/selector).
  TerminalAttempt = 4,  // one-use, non-evicted install-attempt terminal record, reserved AT admission.
  SealRecord = 5,       // compaction: source generation seal (reserved cell 254).
  SwitchRecord = 6,     // compaction: destination activation binding (reserved cell 255).
  FactoryGrantRecord = 7,  // independent one-use factory/full-identity commissioning grant.
  LiveBindingChunk = 8,    // one part of the bounded, fixed-count multi-cell live-binding transaction.
};

struct OtaSecurityCellHeader {
  uint8_t version = 1;
  OtaSecurityRecordType recordType = OtaSecurityRecordType::TxReservation;
  uint16_t slotIndex = 0;      // logical slot within its table, or a fixed sentinel for singleton records.
  uint32_t generation = 0;     // generation of the bank this cell was written under.
  uint64_t lsn = 0;            // monotonic log sequence number, unique within (bank, generation).
  uint16_t payloadLength = 0;  // <= kCellPayloadBytes; unused payload bytes must be zero.
};

// One TX/RX has no natural "slot" -- reserved sentinel slot indices used for
// singleton record kinds so the same cold-scan machinery (keyed by
// recordType+slotIndex) works uniformly for every kind of record.
constexpr uint16_t kTxGlobalSlot = 0xFFFFu;
constexpr uint16_t kFactoryGrantSlot = 0xFFFEu;

class OtaSecurityDataCellCodec {
public:
  // Serializes `header` + `payload[0,payloadLen)` (zero-padded to
  // kCellPayloadBytes) plus the computed CRC into `out[0,124)`, leaving
  // `out[124,128)` untouched (the marker is programmed separately -- see
  // OtaSecurityAppendEngine.h). Returns false if payloadLen exceeds the
  // cell's payload capacity or `outLen` is too small.
  static bool encodeBodyAndCrc(const OtaSecurityCellHeader& header, const uint8_t* payload, uint16_t payloadLen,
                                uint8_t* out, size_t outLen) {
    if (payloadLen > kCellPayloadBytes) return false;
    if (outLen < kCellSizeBytes) return false;
    std::memset(out, 0, kCellCrcOffset);  // deterministic zero-padding for CRC stability.
    size_t pos = 0;
    if (!putU8(out, outLen, pos, header.version)) return false;
    pos += 1;
    if (!putU8(out, outLen, pos, (uint8_t)header.recordType)) return false;
    pos += 1;
    if (!putU16(out, outLen, pos, header.slotIndex)) return false;
    pos += 2;
    if (!putU32(out, outLen, pos, header.generation)) return false;
    pos += 4;
    if (!putU64(out, outLen, pos, header.lsn)) return false;
    pos += 8;
    if (!putU16(out, outLen, pos, payloadLen)) return false;
    pos += 2;
    // reserved u16 stays zero.
    pos += 2;
    if (pos != kCellFixedHeaderBytes) return false;
    if (payload != nullptr && payloadLen > 0) {
      if (!putBytes(out, outLen, pos, payload, payloadLen)) return false;
    }
    const uint32_t crc = ::ota::storage::Crc32::computeFinalized(out, kCellCrcOffset);
    return putU32(out, outLen, kCellCrcOffset, crc);
  }

  // Writes the commit marker at its absolute kCellMarkerOffset within a
  // FULL kCellSizeBytes-sized record buffer (the same buffer already
  // populated by encodeBodyAndCrc()). Callers that only want the 4 marker
  // bytes (to program them as an isolated, independently-verified final
  // step -- see OtaSecurityAppendEngine::writeCellMarker()) must encode
  // into a full-size scratch buffer and slice out [kCellMarkerOffset,
  // kCellMarkerOffset+4) themselves; this function does not accept a
  // standalone 4-byte buffer.
  static bool encodeCommitMarker(uint8_t* out, size_t outLen) {
    return putU32(out, outLen, kCellMarkerOffset, kCellCommitMarker);
  }

  // Classifies raw cell bytes (as read back from flash) into an evidence
  // state and, when Committed or BodyOnly, decodes the header/payload.
  static OtaSecurityEvidence classify(const uint8_t* raw, size_t rawLen, OtaSecurityCellHeader& outHeader,
                                      uint8_t* outPayload /* kCellPayloadBytes */) {
    if (rawLen < kCellSizeBytes) return OtaSecurityEvidence::Unprovable;

    if (isAllFF(raw, rawLen, 0, kCellSizeBytes)) {
      return OtaSecurityEvidence::AbsentBytes;
    }

    const uint32_t bodyCrc = ::ota::storage::Crc32::computeFinalized(raw, kCellCrcOffset);
    uint32_t storedCrc = 0;
    getU32(raw, rawLen, kCellCrcOffset, storedCrc);
    if (bodyCrc != storedCrc) {
      // Non-blank but the body itself doesn't check out: real damage to
      // this record, never treated as if it matched.
      return OtaSecurityEvidence::Unprovable;
    }

    uint8_t version = 0, typeRaw = 0;
    uint16_t slotIndex = 0, payloadLength = 0;
    uint32_t generation = 0;
    uint64_t lsn = 0;
    getU8(raw, rawLen, 0, version);
    getU8(raw, rawLen, 1, typeRaw);
    getU16(raw, rawLen, 2, slotIndex);
    getU32(raw, rawLen, 4, generation);
    getU64(raw, rawLen, 8, lsn);
    getU16(raw, rawLen, 16, payloadLength);
    if (payloadLength > kCellPayloadBytes) {
      return OtaSecurityEvidence::Unprovable;  // impossible length: treat as damage, not a crash.
    }
    switch ((OtaSecurityRecordType)typeRaw) {
      case OtaSecurityRecordType::TxReservation:
      case OtaSecurityRecordType::RxPeerAdvance:
      case OtaSecurityRecordType::RxGroupAdvance:
      case OtaSecurityRecordType::TerminalAttempt:
      case OtaSecurityRecordType::SealRecord:
      case OtaSecurityRecordType::SwitchRecord:
      case OtaSecurityRecordType::FactoryGrantRecord:
      case OtaSecurityRecordType::LiveBindingChunk:
        break;
      default:
        return OtaSecurityEvidence::Unprovable;  // unknown record type: never silently accepted.
    }

    outHeader.version = version;
    outHeader.recordType = (OtaSecurityRecordType)typeRaw;
    outHeader.slotIndex = slotIndex;
    outHeader.generation = generation;
    outHeader.lsn = lsn;
    outHeader.payloadLength = payloadLength;
    if (outPayload != nullptr) {
      std::memset(outPayload, 0, kCellPayloadBytes);
      getBytes(raw, rawLen, kCellFixedHeaderBytes, outPayload, payloadLength);
    }

    uint32_t marker = 0;
    getU32(raw, rawLen, kCellMarkerOffset, marker);
    if (marker == kCellCommitMarker) {
      return OtaSecurityEvidence::Committed;
    }
    return OtaSecurityEvidence::BodyOnly;  // valid body, any non-exact marker (including all-FF).
  }
};

}  // namespace security
}  // namespace ota
