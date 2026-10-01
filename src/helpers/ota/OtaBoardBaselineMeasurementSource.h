#pragma once

// Shared glue between OtaBaselineMeasurementCollector's injectable
// IOtaBaselineMeasurementSource seam and each board backend's REAL local
// hardware reads -- following the exact same weak-linked-free-function
// pattern already established for otaBoardTryConfirmHealthyTrialBoot()
// etc. (see examples/companion_radio/MyMesh.cpp): MyMesh.cpp defines a
// safe fail-closed __attribute__((weak)) default for every function
// below, and each real backend .cpp
// (variants/xiao_nrf52/OtaLabBackend.cpp,
// variants/sensecap_solar/OtaProductionBackend.cpp) provides the STRONG
// override with genuine reads (FICR UID, bank-0 extent via the existing
// incremental resolver, current SDK/build-settings raw bytes,
// stock-loader/QSPI inspection, platform entropy, media arbiter). A
// backend with no OTA support at all simply never overrides them, so the
// weak defaults keep the collector permanently Idle/denied on that
// target -- never a fabricated positive.
//
// This header owns ONLY the thin adapter class that forwards
// IOtaBaselineMeasurementSource calls to these free functions, plus the
// already-loaded public key pointer (supplied by MyMesh from self_id,
// which this module has no access to itself). It contains no hardware
// access of its own.

#include <stdint.h>
#include <string.h>

#include "helpers/ota/OtaBaselineMeasurementCollector.h"
#include "helpers/ota/OtaFirmwareService.h"
#include "helpers/ota/OtaSdkSettingsCodec.h"

namespace mesh {
namespace ota {

bool otaBoardBaselineReadUid8(uint8_t out_uid8[8]);
bool otaBoardBaselineReadCompiledProfile(uint32_t& out_profile_id, uint32_t& out_target_id, uint32_t& out_role_id,
                                        uint32_t& out_layout_id);
bool otaBoardBaselineReadRawCurrentSdkSettings(uint8_t out_raw28[kOtaCurrentSdkSettingsRecordBytes]);
bool otaBoardBaselineReadValidatedBank0Extent(uint32_t& out_extent, uint32_t& out_internal_addr,
                                              uint16_t& out_stored_crc16);
OtaBaselineMeasurementSubStep otaBoardBaselineStepAppImageAccess(uint32_t max_bytes, uint32_t* out_bytes_consumed,
                                                                 const uint8_t** out_image, uint32_t* out_extent);
OtaBaselineMeasurementSubStep otaBoardBaselineStepStockLoaderRangeHash(uint32_t max_bytes,
                                                                       uint32_t* out_bytes_consumed,
                                                                       uint32_t& out_start, uint32_t& out_length,
                                                                       uint8_t out_hash32[32]);
OtaBaselineMeasurementSubStep otaBoardBaselineStepBootConfigSelection(uint32_t max_bytes, uint32_t* out_bytes_consumed,
                                                                      uint32_t& out_boot_config_id,
                                                                      bool& out_catalogue_unavailable,
                                                                      bool& out_mismatch);
OtaBaselineMeasurementSubStep otaBoardBaselineStepQspiStateInspection(uint32_t max_bytes,
                                                                      uint32_t* out_bytes_consumed);
bool otaBoardBaselineGetPlatformEntropy16(uint8_t out[16]);
OtaBaselineMeasurementArbiterResult otaBoardBaselineAcquireMediaArbiter();
void otaBoardBaselineReleaseMediaArbiter();

// Thin forwarding adapter: every method forwards to the function above,
// which is either the safe fail-closed weak default (no OTA-capable
// backend linked, or that specific facility not yet wired) or a real
// backend override. pubkey32 is supplied by the caller (e.g. MyMesh,
// from self_id.pub_key) -- this module never reads or generates identity
// key material itself.
class OtaBoardBaselineMeasurementSource : public IOtaBaselineMeasurementSource {
 public:
  // `service` is the caller's own single authoritative source of truth
  // for "a REAL, durable identity is bound right now" (see
  // OtaFirmwareService.h) -- its identityConfirmedLoaded() is read fresh
  // on every call, never copied/snapshotted at construction time (the
  // caller may not have loaded identity yet when this object is
  // constructed, and a LATER storage fault can invalidate a previously
  // "confirmed" answer). A non-null pubkey32 pointer alone is NOT
  // identity evidence: it is merely the stable address of the eventual
  // storage slot and stays non-null even before/if loading ever
  // succeeds, so it must never substitute for the service's explicit,
  // caller-owned fact.
  explicit OtaBoardBaselineMeasurementSource(const uint8_t* pubkey32, const OtaFirmwareService& service)
      : pubkey32_(pubkey32), service_(&service) {}

  OtaBaselineMeasurementArbiterResult acquireMediaArbiter() override {
    return otaBoardBaselineAcquireMediaArbiter();
  }

  void releaseMediaArbiter() override { otaBoardBaselineReleaseMediaArbiter(); }

  bool readDeviceIdentity(uint8_t out_uid8[8], uint8_t out_pubkey32[32]) override {
    if (pubkey32_ == nullptr) return false;
    if (service_ == nullptr || !service_->identityConfirmedLoaded()) return false;
    if (!otaBoardBaselineReadUid8(out_uid8)) return false;
    memcpy(out_pubkey32, pubkey32_, 32);
    return true;
  }


  bool readCompiledProfile(uint32_t& out_profile_id, uint32_t& out_target_id, uint32_t& out_role_id,
                           uint32_t& out_layout_id) override {
    return otaBoardBaselineReadCompiledProfile(out_profile_id, out_target_id, out_role_id, out_layout_id);
  }

  bool readRawCurrentSdkSettings(uint8_t out_raw28[kOtaCurrentSdkSettingsRecordBytes]) override {
    return otaBoardBaselineReadRawCurrentSdkSettings(out_raw28);
  }

  bool readValidatedBank0Extent(uint32_t& out_extent, uint32_t& out_internal_addr,
                                uint16_t& out_stored_crc16) override {
    return otaBoardBaselineReadValidatedBank0Extent(out_extent, out_internal_addr, out_stored_crc16);
  }

  OtaBaselineMeasurementSubStep stepAppImageAccess(uint32_t max_bytes, uint32_t* out_bytes_consumed,
                                                   const uint8_t** out_image, uint32_t* out_extent) override {
    return otaBoardBaselineStepAppImageAccess(max_bytes, out_bytes_consumed, out_image, out_extent);
  }

  OtaBaselineMeasurementSubStep stepStockLoaderRangeHash(uint32_t max_bytes, uint32_t* out_bytes_consumed,
                                                         uint32_t& out_start, uint32_t& out_length,
                                                         uint8_t out_hash32[32]) override {
    return otaBoardBaselineStepStockLoaderRangeHash(max_bytes, out_bytes_consumed, out_start, out_length, out_hash32);
  }

  OtaBaselineMeasurementSubStep stepBootConfigSelection(uint32_t max_bytes, uint32_t* out_bytes_consumed,
                                                        uint32_t& out_boot_config_id,
                                                        bool& out_catalogue_unavailable,
                                                        bool& out_mismatch) override {
    return otaBoardBaselineStepBootConfigSelection(max_bytes, out_bytes_consumed, out_boot_config_id,
                                                   out_catalogue_unavailable, out_mismatch);
  }

  OtaBaselineMeasurementSubStep stepQspiStateInspection(uint32_t max_bytes, uint32_t* out_bytes_consumed) override {
    return otaBoardBaselineStepQspiStateInspection(max_bytes, out_bytes_consumed);
  }

  bool getPlatformEntropy16(uint8_t out[16]) override { return otaBoardBaselineGetPlatformEntropy16(out); }

 private:
  const uint8_t* pubkey32_;
  const OtaFirmwareService* service_;
};

}  // namespace ota
}  // namespace mesh
