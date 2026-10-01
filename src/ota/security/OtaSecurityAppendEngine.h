#pragma once

// Low-level, per-bank append/readback engine over real byte-array NOR
// FlashRegions. Binds:
//   - this bank's OWN data-log FlashRegion (where its 128-byte data cells
//     live), and
//   - the OPPOSITE bank's witness FlashRegion (active-A data is witnessed
//     in B's witness sector, and vice versa -- see OtaSecurityGeometry.h).
//
// The constructor retains only FlashRegion references -- NO flash I/O
// happens until an explicit method call (matches the
// "no I/O in constructors" contract already established by
// OtaSequenceBackingPort.h's adapters).
//
// This header knows nothing about TX/RX/peer/cohort/terminal semantics --
// it only knows how to durably commit ONE typed 100-byte payload into a
// numbered cell slot and its opposite-bank witness, and how to read back
// and classify cold evidence for any slot. OtaSecurityStore.h is the layer
// that assigns meaning (slot allocation policy, generation tracking,
// capacity tables) on top of this.

#include <stdint.h>
#include <cstring>

#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashRegion.h"
#include "ota/platform/FlashTypes.h"
#include "ota/security/OtaSecurityByteCodec.h"
#include "ota/security/OtaSecurityDataCell.h"
#include "ota/security/OtaSecurityEvidence.h"
#include "ota/security/OtaSecurityGeometry.h"
#include "ota/security/OtaSecurityWitnessSector.h"
#include "ota/storage/Crc32.h"

namespace ota {
namespace security {

// Carves the three sub-regions of ONE 100 KiB tail out of the raw
// FlashDevice, given the tail's absolute base offset (kSecurityAOffset /
// kSecurityBOffset from ota::platform::SenseCapQspiLayout). Pure
// arithmetic/object construction -- no I/O.
class OtaSecurityTailCarve {
public:
  OtaSecurityTailCarve(::ota::platform::FlashDevice& device, uint32_t tailBaseOffset)
      : snapshot_(device, tailBaseOffset + kSnapshotOffset, kSnapshotSizeBytes),
        dataLog_(device, tailBaseOffset + kDataLogOffset, kDataLogSizeBytes),
        witness_(device, tailBaseOffset + kWitnessOffset, kWitnessSizeBytes) {}

  ::ota::platform::FlashRegion& snapshot() { return snapshot_; }
  ::ota::platform::FlashRegion& dataLog() { return dataLog_; }
  ::ota::platform::FlashRegion& witness() { return witness_; }

  bool isValid() const { return snapshot_.isValid() && dataLog_.isValid() && witness_.isValid(); }

private:
  ::ota::platform::FlashRegion snapshot_;
  ::ota::platform::FlashRegion dataLog_;
  ::ota::platform::FlashRegion witness_;
};

// Result of a single readback-checked program step against one FlashRegion.
enum class OtaSecurityIoOutcome : uint8_t {
  Ok,        // program() returned Ok AND readback exactly matches the intended bytes.
  IoError,   // read() itself failed -- we cannot even inspect the medium's actual state.
  Mismatch,  // program()/readback succeeded as flash operations, but the bytes landed
             // differently than intended (partial/torn write, or a fault-injected
             // "After"-timing report) -- durability of THIS write is unproven.
};

class OtaSecurityAppendEngine {
public:
  // `ownIdentity`/`destSnapshotDigest` bind every witness this engine
  // writes to (store identity, destination snapshot, protected generation,
  // owner bank) -- see OtaSecurityWitnessSector.h.
  OtaSecurityAppendEngine(::ota::platform::FlashRegion& ownDataLog, ::ota::platform::FlashRegion& oppositeWitness,
                          OtaSecurityBankId ownBank)
      : dataLog_(ownDataLog), oppositeWitness_(oppositeWitness), ownBank_(ownBank) {}

  // --- Data cell I/O -----------------------------------------------------

  // Reads and classifies the cell at `slotIndex` (0..kOrdinaryCellCount-1,
  // or the reserved seal/switch indices). Never throws; a flash read
  // failure is surfaced as IoError, distinct from any content-based
  // evidence state.
  OtaSecurityEvidence readCell(uint32_t slotIndex, OtaSecurityCellHeader& outHeader, uint8_t* outPayload,
                               bool& outIoError) {
    outIoError = false;
    uint8_t raw[kCellSizeBytes];
    ::ota::platform::FlashStatus st = dataLog_.read(slotIndex * kCellSizeBytes, raw, kCellSizeBytes);
    if (!::ota::platform::isOk(st)) {
      outIoError = true;
      return OtaSecurityEvidence::IoError;
    }
    return OtaSecurityDataCellCodec::classify(raw, kCellSizeBytes, outHeader, outPayload);
  }

  // Two-phase commit of one data cell: program body+crc, readback-verify,
  // THEN program marker, readback-verify. Returns an outcome per phase so
  // the caller (OtaSecurityStore) can distinguish "nothing landed" from
  // "body landed, marker didn't" from "fully committed" without ever
  // trusting a bare FlashStatus::Ok alone.
  OtaSecurityIoOutcome writeCellBody(uint32_t slotIndex, const OtaSecurityCellHeader& header, const uint8_t* payload,
                                     uint16_t payloadLen) {
    uint8_t buf[kCellSizeBytes];
    std::memset(buf, 0xFF, sizeof(buf));
    if (!OtaSecurityDataCellCodec::encodeBodyAndCrc(header, payload, payloadLen, buf, sizeof(buf))) {
      return OtaSecurityIoOutcome::Mismatch;
    }
    const uint32_t base = slotIndex * kCellSizeBytes;
    ::ota::platform::FlashStatus programStatus = dataLog_.program(base, buf, kCellCrcOffset + 4u);

    uint8_t readback[kCellCrcOffset + 4u];
    ::ota::platform::FlashStatus readStatus = dataLog_.read(base, readback, sizeof(readback));
    if (!::ota::platform::isOk(readStatus)) {
      return OtaSecurityIoOutcome::IoError;
    }
    const bool bodyMatches = std::memcmp(readback, buf, sizeof(readback)) == 0;
    if (::ota::platform::isOk(programStatus) && bodyMatches) {
      return OtaSecurityIoOutcome::Ok;
    }
    return OtaSecurityIoOutcome::Mismatch;
  }

  OtaSecurityIoOutcome writeCellMarker(uint32_t slotIndex) {
    // encodeCommitMarker() writes at the record's absolute kCellMarkerOffset
    // within a full-size record buffer, so we encode into a full-size
    // scratch buffer here and program only the resulting 4 marker bytes --
    // matching the [scratch, 0xFF-filled -> slice] convention used by the
    // classify()-side reader of this same layout.
    uint8_t scratch[kCellSizeBytes];
    std::memset(scratch, 0, sizeof(scratch));
    if (!OtaSecurityDataCellCodec::encodeCommitMarker(scratch, sizeof(scratch))) return OtaSecurityIoOutcome::Mismatch;
    uint8_t* markerBuf = scratch + kCellMarkerOffset;
    const uint32_t base = slotIndex * kCellSizeBytes + kCellMarkerOffset;
    ::ota::platform::FlashStatus programStatus = dataLog_.program(base, markerBuf, 4);

    uint8_t readback[4];
    ::ota::platform::FlashStatus readStatus = dataLog_.read(base, readback, sizeof(readback));
    if (!::ota::platform::isOk(readStatus)) {
      return OtaSecurityIoOutcome::IoError;
    }
    if (::ota::platform::isOk(programStatus) && std::memcmp(readback, markerBuf, sizeof(readback)) == 0) {
      return OtaSecurityIoOutcome::Ok;
    }
    return OtaSecurityIoOutcome::Mismatch;
  }

  // --- Opposite-bank witness I/O ------------------------------------------

  // Binds (store identity, destination snapshot digest, protected
  // generation, owner bank, slot index, lsn) into one CRC -- see the class
  // doc comment on why this is never a standalone/arbitrary LSN.
  static uint32_t computeWitnessContextualCrc(uint64_t storeIdentity, uint64_t destSnapshotDigest, uint32_t generation,
                                               uint16_t ownerBankSlot, uint32_t slotIndex, uint64_t lsn) {
    uint8_t buf[8 + 8 + 4 + 2 + 4 + 8];
    size_t pos = 0;
    putU64(buf, sizeof(buf), pos, storeIdentity); pos += 8;
    putU64(buf, sizeof(buf), pos, destSnapshotDigest); pos += 8;
    putU32(buf, sizeof(buf), pos, generation); pos += 4;
    putU16(buf, sizeof(buf), pos, ownerBankSlot); pos += 2;
    putU32(buf, sizeof(buf), pos, slotIndex); pos += 4;
    putU64(buf, sizeof(buf), pos, lsn); pos += 8;
    return ::ota::storage::Crc32::computeFinalized(buf, pos);
  }

  OtaSecurityEvidence readWitnessHeader(OtaSecurityWitnessSectorHeader& outHeader, bool& outIoError) {
    outIoError = false;
    uint8_t raw[kWitnessHeaderBytes];
    ::ota::platform::FlashStatus st = oppositeWitness_.read(0, raw, sizeof(raw));
    if (!::ota::platform::isOk(st)) {
      outIoError = true;
      return OtaSecurityEvidence::IoError;
    }
    return OtaSecurityWitnessHeaderCodec::classify(raw, sizeof(raw), outHeader);
  }

  OtaSecurityIoOutcome writeWitnessHeaderBody(const OtaSecurityWitnessSectorHeader& header) {
    // encodeBodyAndCrc() requires a full kWitnessHeaderBytes-sized buffer
    // (same pattern as writeCellBody()'s full-cell-sized scratch buffer)
    // even though only the first kWitnessHeaderMarkerOffset bytes
    // (everything up to and including the CRC) are actually programmed
    // here -- the marker itself is programmed separately, last.
    uint8_t buf[kWitnessHeaderBytes];
    std::memset(buf, 0xFF, sizeof(buf));
    if (!OtaSecurityWitnessHeaderCodec::encodeBodyAndCrc(header, buf, sizeof(buf))) return OtaSecurityIoOutcome::Mismatch;
    ::ota::platform::FlashStatus programStatus = oppositeWitness_.program(0, buf, kWitnessHeaderMarkerOffset);
    uint8_t readback[kWitnessHeaderMarkerOffset];
    ::ota::platform::FlashStatus readStatus = oppositeWitness_.read(0, readback, sizeof(readback));
    if (!::ota::platform::isOk(readStatus)) return OtaSecurityIoOutcome::IoError;
    if (::ota::platform::isOk(programStatus) && std::memcmp(readback, buf, sizeof(readback)) == 0) {
      return OtaSecurityIoOutcome::Ok;
    }
    return OtaSecurityIoOutcome::Mismatch;
  }

  OtaSecurityIoOutcome writeWitnessHeaderMarker() {
    // See writeCellMarker()'s comment: encodeMarker() writes at the sector's
    // absolute kWitnessHeaderMarkerOffset within a full-size header buffer.
    uint8_t scratch[kWitnessHeaderBytes];
    std::memset(scratch, 0, sizeof(scratch));
    if (!OtaSecurityWitnessHeaderCodec::encodeMarker(scratch, sizeof(scratch))) return OtaSecurityIoOutcome::Mismatch;
    uint8_t* markerBuf = scratch + kWitnessHeaderMarkerOffset;
    ::ota::platform::FlashStatus programStatus = oppositeWitness_.program(kWitnessHeaderMarkerOffset, markerBuf, 4);
    uint8_t readback[4];
    ::ota::platform::FlashStatus readStatus = oppositeWitness_.read(kWitnessHeaderMarkerOffset, readback, sizeof(readback));
    if (!::ota::platform::isOk(readStatus)) return OtaSecurityIoOutcome::IoError;
    if (::ota::platform::isOk(programStatus) && std::memcmp(readback, markerBuf, sizeof(readback)) == 0) {
      return OtaSecurityIoOutcome::Ok;
    }
    return OtaSecurityIoOutcome::Mismatch;
  }

  static uint32_t witnessRecordOffset(uint32_t slotIndex) {
    return kWitnessHeaderBytes + slotIndex * kWitnessRecordBytes;
  }

  OtaSecurityEvidence readWitnessRecord(uint32_t slotIndex, uint32_t expectedContextualCrc, uint64_t& outLsn,
                                       bool& outIoError) {
    outIoError = false;
    uint8_t raw[kWitnessRecordBytes];
    ::ota::platform::FlashStatus st = oppositeWitness_.read(witnessRecordOffset(slotIndex), raw, sizeof(raw));
    if (!::ota::platform::isOk(st)) {
      outIoError = true;
      return OtaSecurityEvidence::IoError;
    }
    return OtaSecurityWitnessRecordCodec::classify(raw, sizeof(raw), expectedContextualCrc, outLsn);
  }

  OtaSecurityIoOutcome writeWitnessRecordBody(uint32_t slotIndex, uint64_t lsn, uint32_t contextualCrc) {
    // encodeBodyAndCrc() requires a full kWitnessRecordBytes-sized buffer
    // (mirrors writeWitnessHeaderBody()/writeCellBody()) even though only
    // the first kWitnessRecordMarkerOffset bytes are programmed here; the
    // marker is programmed separately, last.
    uint8_t buf[kWitnessRecordBytes];
    if (!OtaSecurityWitnessRecordCodec::encodeBodyAndCrc(lsn, contextualCrc, buf, sizeof(buf))) {
      return OtaSecurityIoOutcome::Mismatch;
    }
    const uint32_t base = witnessRecordOffset(slotIndex);
    ::ota::platform::FlashStatus programStatus = oppositeWitness_.program(base, buf, kWitnessRecordMarkerOffset);
    uint8_t readback[kWitnessRecordMarkerOffset];
    ::ota::platform::FlashStatus readStatus = oppositeWitness_.read(base, readback, sizeof(readback));
    if (!::ota::platform::isOk(readStatus)) return OtaSecurityIoOutcome::IoError;
    if (::ota::platform::isOk(programStatus) && std::memcmp(readback, buf, sizeof(readback)) == 0) {
      return OtaSecurityIoOutcome::Ok;
    }
    return OtaSecurityIoOutcome::Mismatch;
  }

  OtaSecurityIoOutcome writeWitnessRecordMarker(uint32_t slotIndex) {
    // See writeCellMarker()'s comment: encodeMarker() writes at the record's
    // absolute kWitnessRecordMarkerOffset within a full-size record buffer.
    uint8_t scratch[kWitnessRecordBytes];
    std::memset(scratch, 0, sizeof(scratch));
    if (!OtaSecurityWitnessRecordCodec::encodeMarker(scratch, sizeof(scratch))) return OtaSecurityIoOutcome::Mismatch;
    uint8_t* markerBuf = scratch + kWitnessRecordMarkerOffset;
    const uint32_t base = witnessRecordOffset(slotIndex) + kWitnessRecordMarkerOffset;
    ::ota::platform::FlashStatus programStatus = oppositeWitness_.program(base, markerBuf, 4);
    uint8_t readback[4];
    ::ota::platform::FlashStatus readStatus = oppositeWitness_.read(base, readback, sizeof(readback));
    if (!::ota::platform::isOk(readStatus)) return OtaSecurityIoOutcome::IoError;
    if (::ota::platform::isOk(programStatus) && std::memcmp(readback, markerBuf, sizeof(readback)) == 0) {
      return OtaSecurityIoOutcome::Ok;
    }
    return OtaSecurityIoOutcome::Mismatch;
  }

  OtaSecurityBankId ownBank() const { return ownBank_; }

private:
  ::ota::platform::FlashRegion& dataLog_;
  ::ota::platform::FlashRegion& oppositeWitness_;
  OtaSecurityBankId ownBank_;
};

}  // namespace security
}  // namespace ota
