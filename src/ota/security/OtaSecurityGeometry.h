#pragma once

// Physical sub-region geometry for ONE 100 KiB security tail (securityA or
// securityB -- see ota/platform/SenseCapQspiLayout.h's securityARegion()/
// securityBRegion()). Astra-approved map, cross-checked with static_asserts
// below against the existing shared C layout contract so this NEW module
// can never silently drift from the already-qualified physical partition
// boundaries:
//
//   snapshot         [0x00000, 0x10000)   64 KiB
//   data/control log [0x10000, 0x18000)   32 KiB
//   head-witness     [0x18000, 0x19000)    4 KiB
//
// This header defines ONLY sizes/counts/offsets -- no I/O, no FlashRegion
// construction (see OtaSecurityAppendEngine.h for that).

#include <stdint.h>

#include "ota/platform/Nrf52FlashLayoutContract.h"
#include "ota/platform/SenseCapQspiLayout.h"

namespace ota {
namespace security {

// --- Tail sub-region layout -------------------------------------------------

constexpr uint32_t kTailSizeBytes = OTA_NRF52_SECURITY_TAIL_BYTES;  // 0x19000 (100 KiB)

constexpr uint32_t kSnapshotOffset = 0x00000u;
constexpr uint32_t kSnapshotSizeBytes = 0x10000u;  // 64 KiB

constexpr uint32_t kDataLogOffset = 0x10000u;
constexpr uint32_t kDataLogSizeBytes = 0x08000u;  // 32 KiB

constexpr uint32_t kWitnessOffset = 0x18000u;
constexpr uint32_t kWitnessSizeBytes = 0x01000u;  // 4 KiB

// Physical erase unit -- cross-checked against the shared C layout
// contract so bounded/resumable compaction stepping (OtaSecurityStore::
// compactStep()) can erase exactly ONE sector per call instead of one
// FlashRegion::eraseRange() call covering many sectors in a single
// synchronous burst.
constexpr uint32_t kSecurityEraseUnitBytes = OTA_NRF52_QSPI_ERASE_UNIT_BYTES;  // 4096
static_assert(kSecurityEraseUnitBytes == 4096u, "security store assumes a 4 KiB physical erase unit");
constexpr uint32_t kSnapshotEraseSectorCount = kSnapshotSizeBytes / kSecurityEraseUnitBytes;  // 16
constexpr uint32_t kDataLogEraseSectorCount = kDataLogSizeBytes / kSecurityEraseUnitBytes;    // 8
static_assert(kSnapshotEraseSectorCount * kSecurityEraseUnitBytes == kSnapshotSizeBytes,
              "snapshot region must be an exact multiple of the erase unit");
static_assert(kDataLogEraseSectorCount * kSecurityEraseUnitBytes == kDataLogSizeBytes,
              "data log region must be an exact multiple of the erase unit");

static_assert(kSnapshotSizeBytes + kDataLogSizeBytes + kWitnessSizeBytes == kTailSizeBytes,
              "the three sub-regions must exactly tile one 100 KiB security tail");
static_assert(kSnapshotOffset + kSnapshotSizeBytes == kDataLogOffset, "snapshot must immediately precede data log");
static_assert(kDataLogOffset + kDataLogSizeBytes == kWitnessOffset, "data log must immediately precede witness sector");
static_assert(kWitnessOffset + kWitnessSizeBytes == kTailSizeBytes, "witness sector must end exactly at tail end");

// --- Data cell geometry ------------------------------------------------------

constexpr uint32_t kCellSizeBytes = 128u;
constexpr uint32_t kCellCount = kDataLogSizeBytes / kCellSizeBytes;  // 256
static_assert(kCellCount == 256u, "expected exactly 256 data cells per tail");

// 254 ordinary cells usable for TX/RX/peer/cohort/terminal records, plus two
// reserved cells used by the compaction protocol (a seal record binding the
// frozen source generation, and a switch record binding the destination
// generation/snapshot/head at activation time -- see OtaSecurityStore.h).
constexpr uint32_t kOrdinaryCellCount = 254u;
constexpr uint32_t kSealCellIndex = 254u;
constexpr uint32_t kSwitchCellIndex = 255u;
static_assert(kOrdinaryCellCount + 2u == kCellCount, "254 ordinary + seal + switch must equal total cell count");

// Data cell byte layout (see OtaSecurityDataCell.h for the codec):
//   [0,20)    fixed header fields (version,type,slotIndex,generation,lsn,payloadLength,reserved)
//   [20,120)  payload (100 bytes)
//   [120,124) payloadCrc32 (covers [0,120))
//   [124,128) commitMarker (programmed LAST, separately from the rest)
constexpr uint32_t kCellFixedHeaderBytes = 20u;
constexpr uint32_t kCellPayloadBytes = 100u;
constexpr uint32_t kCellCrcOffset = 120u;
constexpr uint32_t kCellMarkerOffset = 124u;
static_assert(kCellFixedHeaderBytes + kCellPayloadBytes + 4u /*crc*/ + 4u /*marker*/ == kCellSizeBytes,
              "cell fixed fields + payload + crc + marker must exactly fill one 128-byte cell");

// --- Witness sector geometry --------------------------------------------------

constexpr uint32_t kWitnessHeaderBytes = 32u;
constexpr uint32_t kWitnessRecordBytes = 16u;
constexpr uint32_t kWitnessCount = kOrdinaryCellCount;  // one witness slot per ordinary data cell, same index
static_assert(kWitnessHeaderBytes + kWitnessCount * kWitnessRecordBytes == kWitnessSizeBytes,
              "32-byte header + 254*16-byte witnesses must exactly fill the 4096-byte witness sector");

// Witness sector header byte layout (see OtaSecurityWitnessSector.h):
//   [0,8)   storeIdentity (truncated, sector-wide binding)
//   [8,16)  destSnapshotDigest (truncated digest of the generation this sector protects)
//   [16,20) protectedGeneration (u32)
//   [20,22) ownerBankSlot (u16: 0 = bank A, 1 = bank B -- the bank whose witness sector THIS is)
//   [22,24) reserved (must be 0)
//   [24,28) headerCrc32 (covers [0,24))
//   [28,32) headerMarker (programmed LAST)
constexpr uint32_t kWitnessHeaderFixedBytes = 24u;
constexpr uint32_t kWitnessHeaderCrcOffset = 24u;
constexpr uint32_t kWitnessHeaderMarkerOffset = 28u;

// Witness record byte layout: [0,8) lsn, [8,12) contextualCrc32, [12,16) marker (programmed LAST).
constexpr uint32_t kWitnessRecordCrcOffset = 8u;
constexpr uint32_t kWitnessRecordMarkerOffset = 12u;

// --- Commit marker constants --------------------------------------------------
// A committed marker is an EXACT constant value; anything else (including
// an untouched/erased 0xFFFFFFFF) is evidence of, at most, a "BodyOnly"
// possible commitment -- never treated as durable Committed truth. These
// intentionally differ from each other and from 0xFFFFFFFF/0x00000000 so an
// erased sector or an all-zero torn write can never be mistaken for either.
constexpr uint32_t kCellCommitMarker = 0x53454331u;      // "1ES" (ascii-ish "SEC1")
constexpr uint32_t kWitnessHeaderPreparedMarker = 0x57484431u;  // "1DHW" ("WHD1")

// --- Banks -------------------------------------------------------------------
enum class OtaSecurityBankId : uint8_t { A = 0, B = 1 };

inline OtaSecurityBankId otherBank(OtaSecurityBankId b) {
  return b == OtaSecurityBankId::A ? OtaSecurityBankId::B : OtaSecurityBankId::A;
}

}  // namespace security
}  // namespace ota
