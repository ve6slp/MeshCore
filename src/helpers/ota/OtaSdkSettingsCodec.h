#pragma once

// Shared helper for the device's CURRENT SDK/build-settings measurement
// used by OtaBaselineMeasurementCollector.
//
// Root correction (after an earlier, WRONG draft fabricated a distinct
// seven-u32 "softdevice/MDK/toolchain" schema from FICR part/variant/
// package registers plus protocol constants): there is NO separate
// "current silicon SDK28" namespace. The ONLY genuine 28-byte "SDK
// settings" concept in this tree is the real, physical Nordic
// bootloader-settings page at [0xFF000, 0xFF01C) -- the SAME exact bytes
// already structurally decoded by
// ota::storage::XiaoOtaActiveExtentBridge::decodeBank0FromRaw28Bytes()
// for bank-0/CRC/bank-1/padding/size/reserved-words. Real backend
// adapters (otaBoardBaselineReadRawCurrentSdkSettings) must copy those
// EXACT 28 live bytes verbatim -- never synthesize a different 28-byte
// object that merely happens to also be 28 bytes long. A genuine change
// to ANY of the real 28 bytes (bank state, CRC, size, or any reserved/
// padding word) must be observable by re-reading and re-hashing, which a
// fabricated/static-constant record could never detect.
//
// This header only hashes the exact raw bytes handed to it -- it does
// NOT define or interpret any record layout; interpreting bank-0/CRC/
// size fields is the storage layer's (XiaoOtaActiveExtentBridge's)
// job, not this collector-facing helper's. This is also NOT the
// Authority owner's separate frozen "original-SDK28-at-commissioning"
// provenance (see src/ota/authority/BootFloorActivationReceipt.h's
// OriginalBaselineSdk28Provenance, which is explicitly a commissioning-
// time historical fact, not a live re-measurement, and stays out of this
// module's scope).

#include <stdint.h>
#include <string.h>

#include "ota/trust/Sha256.h"

namespace mesh {
namespace ota {

inline constexpr uint32_t kOtaCurrentSdkSettingsRecordBytes = 28;

// Local measurement only -- hashes the exact 28 raw bytes the device
// read (the real [0xFF000, 0xFF01C) bootloader-settings page), via the
// shared Sha256 implementation (never a second hash impl).
inline void hashOtaCurrentSdkSettingsRecordRaw(const uint8_t raw[kOtaCurrentSdkSettingsRecordBytes],
                                                uint8_t out_sha256[32]) {
  ::ota::trust::Sha256::hash(raw, kOtaCurrentSdkSettingsRecordBytes, out_sha256);
}

}  // namespace ota
}  // namespace mesh
