#include <Arduino.h>
#if defined(NRF52840_XXAA)
#include <nrf_soc.h>  // sd_softdevice_is_enabled / sd_rand_application_vector_get
#endif

#if defined(MESHCORE_LORA_OTA) && MESHCORE_LORA_OTA

#include <cstring>
#include <Ed25519.h>

#include <helpers/ota/OtaBoardBackendCommon.h>
#include <helpers/ota/OtaFirmwareBackend.h>
#include <helpers/ota/OtaFirmwareIntegration.h>
#include <ota/platform/Nrf52FlashAdapter.h>
#include <ota/platform/SenseCapQspiLayout.h>
#include <ota/storage/XiaoOtaActiveExtentBridge.h>
#include <ota/storage/XiaoOtaBootInfoReader.h>
#include <ota/storage/XiaoOtaCommandRecord.h>
#include <ota/storage/OtaCandidateStore.h>
#include <ota/trust/DescriptorVerifier.h>
#include <ota/trust/MonotonicCounter.h>
#include <ota/trust/Sha256.h>
#include <target.h>

extern RADIO_CLASS radio;
bool otaBoardApplyRfProfile(float frequency, float bandwidth, uint8_t sf, uint8_t cr) {
  return mesh::ota::applyCheckedOtaRadioProfile(radio, radio_driver, frequency, bandwidth, sf, cr);
}

// Production OTA backend for the SenseCAP Solar board (same nRF52840 +
// P25Q16H QSPI NOR flash family as variants/xiao_nrf52/OtaProductionBackend.cpp,
// sharing the command-v3/counter/qualification logic. Unqualified devices
// expose a non-installable owner-signed uploader cache, not receiver
// admission under an assumed key.
//
// Fail-closed capability note: this board's custom bootloader
// (bootloader/xiao_nrf52840_ota, built/signed with `--board
// sensecap_solar_p1` per boot-Hydra) is NOT physically qualified on any
// real SenseCAP hardware yet -- treat it as build-only capability until a
// real device reports a genuine boot-info marker. This backend declares
// the real, distinct target id (0x53435031 / "SCP1", confirmed via boot-
// Hydra's cross-board rejection test -- never a 0xFFFFFFFF sentinel), but
// the durable v3 install-command handoff remains gated behind live, fail-closed
// detection (magic+format+CRC+board_target_id/role/capability/algorithm
// match) -- never board/JEDEC identity or a compiled flag alone. Until a
// real device reports that marker, its uploader cache reports CACHE_ONLY.
namespace {

class ProductionSignatureVerifier : public ota::trust::SignatureVerifier {
public:
  bool verify(const uint8_t* signature, size_t signature_len,
              const uint8_t* message, size_t message_len,
              const uint8_t* public_key, size_t public_key_len) const override {
    if (signature == nullptr || public_key == nullptr ||
        (message == nullptr && message_len != 0) ||
        signature_len != 64 || public_key_len != 32) {
      return false;
    }
    return Ed25519::verify(signature, public_key, message, message_len);
  }
};

// Must match the boot-side canonical constants exactly (not invented
// here): boot-Hydra's board-target profile flags (`tools/prepare_upstream.py
// --board sensecap_solar_p1` / `tools/sign_image.py --board
// sensecap_solar_p1`) define sensecap_solar_p1 = 0x53435031 ("SCP1"), a
// real, distinct, non-wildcard target -- proven via an actual compiled
// cross-board rejection test on the bootloader side. XIAO_OTA_ROLE_ANY = 0,
// XIAO_OTA_CAP_QSPI_INSTALL = 1 are shared across both board profiles.
constexpr uint32_t kExpectedBoardTargetId = 0x53435031u;
// The ACTUAL compiled application role (0 == companion, 1 == repeater),
// sourced from a per-env build flag exactly like XIAO's
// XIAO_OTA_COMPILED_ROLE_ID -- NEVER hardcoded to 0 for every env. A
// prior revision hardcoded this to 0u, which meant a genuine role-1
// (repeater) SenseCAP OTA build could never be validated against its
// own catalogue row/boot-info marker; it would instead silently inherit
// role 0's identity. Defaults to 0 (companion) when the build flag is
// absent, preserving existing companion-only env behavior.
#if defined(SENSECAP_OTA_COMPILED_ROLE_ID)
constexpr uint32_t kExpectedRoleId = static_cast<uint32_t>(SENSECAP_OTA_COMPILED_ROLE_ID);
#else
#error "LoRa OTA requires an explicitly bound companion/repeater role"
#endif
static_assert(kExpectedRoleId == 0u || kExpectedRoleId == 1u,
              "LoRa OTA role must be companion (0) or repeater (1)");
constexpr uint32_t kExpectedCapabilityFlags = 1u;
// The ONE real, physical Nordic bootloader-settings page address -- see
// OtaSdkSettingsCodec.h's header comment: these are the SAME exact 28
// live bytes read by the bank-0 extent probe, never two separate
// schemas.
constexpr uint32_t kBootloaderSettingsAddress = 0x000FF000u;
// Must match bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h's
// XIAO_OTA_DESCRIPTOR_FORMAT (= 1), shared across both board profiles: the
// canonical descriptor wire-format version this whole boot contract is
// built for. This is a fixed protocol-version identifier, not a
// per-device/per-key value, so unlike expected_key_id/expected_algorithm_id
// it is never sourced from the boot marker itself (XiaoOtaBootInfoReader::
// Info has no format_id field at all).
constexpr uint16_t kExpectedDescriptorFormatId = 1u;
// SenseCAP production profile identifier, kept as one named constant so
// the role-authority anchor cannot silently drift.
constexpr uint32_t kExpectedProfileId = 2u;

ota::platform::Nrf52FlashAdapter flash;
// The physical image bank is 708608 bytes; staging excludes its final
// 8 KiB of durable candidate metadata, including in cache-only mode.
// OtaNrf52FirmwareTrustProvider limits installable images to 643072 bytes
// (0x9D000), protecting the fixed installer at 0xC4000..0xD4000 and
// unchanged InternalExtraFS at 0xD4000..0xED000. A non-installable uploader
// cache retains external/generic bounds.
ota::platform::FlashRegion candidate =
    ota::platform::SenseCapQspiLayout::candidatePayloadRegion(flash);
ota::platform::FlashRegion xiao_floor_region =
    ota::platform::SenseCapQspiLayout::xiaoFloorRegion(flash);
ota::platform::FlashRegion xiao_command_region =
    ota::platform::SenseCapQspiLayout::xiaoCommandRegion(flash);
ota::platform::FlashRegion xiao_state_region = ota::platform::SenseCapQspiLayout::xiaoStateRegion(flash);
ota::platform::FlashRegion xiao_confirm_region = ota::platform::SenseCapQspiLayout::xiaoConfirmRegion(flash);
ota::platform::FlashRegion xiao_journal_full_region = ota::platform::SenseCapQspiLayout::xiaoJournalFullRegion(flash);
ota::platform::FlashRegion candidate_record_region =
    ota::platform::SenseCapQspiLayout::candidateRecordRegion(flash);
mesh::ota::OtaBoardFailClosedMonotonicCounter counter(xiao_floor_region);
// Constructed LAZILY, post-flash.begin() and post-qualification (see
// configureCompanionFirmwareOtaBackend() below) -- NEVER as a file-scope
// global object; see the identical comment in
// variants/xiao_nrf52/OtaProductionBackend.cpp for why a global here would read
// QSPI flash before flash.begin() ever ran.
mesh::ota::OtaBoardTrialBootHealthConfirmer* trial_boot_confirmer_ptr = nullptr;

ota::trust::Sha256 hasher;
ProductionSignatureVerifier signature_verifier;
ota::trust::DeviceTrustAnchor anchor;
uint8_t active_wire_public_key[32] = {0};
ota::trust::DescriptorVerifier* verifier = nullptr;
mesh::ota::OtaFirmwareTrustProvider* trust = nullptr;
meshcore::ota::runtime::IOtaStagingSink* staging = nullptr;
mesh::ota::OtaBoardInstallCommandProviderV3* install_provider_v3 = nullptr;

// Set once by configureCompanionFirmwareOtaBackend() so any caller (e.g. a
// future CLI/status command) can report the real reason install
// capability is or is not available, instead of a success-shaped
// assumption based on board/JEDEC identity or compiled feature flags
// alone -- identical contract to
// variants/xiao_nrf52/OtaProductionBackend.cpp's capability status.
const char* g_install_capability_reason = "not yet configured";
char g_install_capability_status[64] = {0};

// True ONLY once configureCompanionFirmwareOtaBackend() has observed a
// genuinely qualified boot marker AND a fresh valid bank0 record --
// exactly the INSTALL_CAPABLE case. Gates
// otaBoardTryConfirmHealthyTrialBoot() below so an unqualified or
// bank0-invalid device NEVER attempts a trial-boot health confirmation
// merely because a (possibly stale/foreign) TRIAL-phase state record is
// present -- state phase alone is never sufficient.
bool g_backend_qualified_and_bank0_valid = false;

// True whenever a genuinely qualified custom-bootloader marker is
// present, REGARDLESS of bank0/floor validity -- see the identical
// comment in variants/xiao_nrf52/OtaProductionBackend.cpp. Health-tick
// eligibility depends on this flag; stock cache writes require a separate boot proof.
bool g_qualified = false;
mesh::ota::OtaBoardStockBootPreflight::Result g_stock_boot_result =
    mesh::ota::OtaBoardStockBootPreflight::Result::NotStock;
char g_early_write_diagnostic[128] = "proof=not-run";
bool stockBootOrdinaryWritesAllowed(const mesh::ota::OtaBoardBootQualification& qualification, bool early = false) {
  mesh::ota::OtaBoardNrf52RunningContext running;
  mesh::ota::OtaBoardStockBootPreflight::Diagnostic diagnostic;
  g_stock_boot_result = mesh::ota::OtaBoardStockBootPreflight::check(
      qualification, running, xiao_journal_full_region, early ? &diagnostic : nullptr);
  if (early) mesh::ota::OtaBoardStockBootPreflight::formatDiagnostic(
      g_early_write_diagnostic, sizeof(g_early_write_diagnostic), diagnostic);
  return g_stock_boot_result == mesh::ota::OtaBoardStockBootPreflight::Result::Healthy;
}
mesh::ota::OtaBoardBootLifecycleObserver& bootLifecycleObserver() {
  static mesh::ota::OtaBoardNrf52RunningContext running;
  static mesh::ota::OtaBoardOriginalSnapshotProvider original(xiao_state_region, xiao_floor_region, running,
      g_qualified);
  static mesh::ota::OtaBoardBootLifecycleObserver observer(xiao_state_region, xiao_floor_region, original);
  return observer;
}

// Points at the sole OtaBoardTrialGuardedStagingSink instance (see
// production_guarded_staging below) once attached, so the real, grounded
// per-tick storage-fault getter below can report on it. No staging sink
// attached at all (trial-active/no-marker/invalid-bank0/bad-floor early
// returns leave this null) simply reports false.
mesh::ota::OtaBoardTrialGuardedStagingSink* g_active_guarded_staging = nullptr;

}  // namespace

const char* otaProductionInstallCapabilityReason() { return g_install_capability_reason; }

const char* otaBoardInstallCapabilityStatus() {
  if (!g_qualified) return g_install_capability_status;
  static char diagnostic[mesh::ota::kOtaBoardFloorCapabilityStatusBytes];
  mesh::ota::formatOtaBoardFloorCapabilityStatus(diagnostic, sizeof(diagnostic),
                                                g_install_capability_status, xiao_floor_region);
  return diagnostic;
}
const char* otaBoardEarlyWriteDiagnostic() { return g_early_write_diagnostic; }
bool otaBoardGetBootLifecycle(mesh::ota::OtaBootLifecycleEvidence& out) {
  return bootLifecycleObserver().read(g_qualified, out);
}
bool otaBoardBootLifecycleVerificationPending() {
  return g_qualified && bootLifecycleObserver().pending();
}

// See g_active_guarded_staging above.
bool otaBoardStorageIoFaultObserved() {
  return g_active_guarded_staging != nullptr && g_active_guarded_staging->storageIoFaultObserved();
}

// Real trial-boot health confirmation entry point: inert (returns false,
// writes nothing) unless configureCompanionFirmwareOtaBackend() already
// observed a genuinely qualified boot marker AND a fresh valid bank0
// record -- never on TRIAL-phase state alone, which can be foreign/stale
// on an unqualified or bank0-invalid device.
mesh::ota::OtaBoardTrialHealthOutcome otaBoardTryConfirmHealthyTrialBoot(uint32_t now_ms, bool radio_ready,
                                                                        bool filesystem_ready, bool loop_healthy) {
  if (!g_qualified) return mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  bootLifecycleObserver().tick(g_qualified);
  if (trial_boot_confirmer_ptr == nullptr) return mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  return trial_boot_confirmer_ptr->tick(now_ms, radio_ready, filesystem_ready, loop_healthy);
}

// True whenever this device is qualified AND (the confirmer is not yet
// constructed -- fail closed: "unknown" blocks -- OR a genuine trial-boot
// health window is in progress/unresolved). See the identical comment in
// variants/xiao_nrf52/OtaProductionBackend.cpp.
bool otaBoardTrialHealthWindowActive() {
  if (!g_qualified) return g_stock_boot_result != mesh::ota::OtaBoardStockBootPreflight::Result::Healthy;
  if (trial_boot_confirmer_ptr == nullptr) return true;
  return trial_boot_confirmer_ptr->isTrialActive();
}

// Genuine earliest-boot-phase preflight -- see the identical comment in
// variants/xiao_nrf52/OtaProductionBackend.cpp and MyMesh.cpp's weak default.
bool otaBoardEarlyBootTrialOrUnknown() {
  g_stock_boot_result = mesh::ota::OtaBoardStockBootPreflight::Result::IoError;
  snprintf(g_early_write_diagnostic, sizeof(g_early_write_diagnostic), "proof=qspi-layout");
  if (!ota::platform::SenseCapQspiLayout::isValid()) return true;
  snprintf(g_early_write_diagnostic, sizeof(g_early_write_diagnostic), "proof=qspi-read");
  if (!ota::platform::isOk(flash.begin())) {
    // Cannot even read the OTA state region -- genuinely UNKNOWN (a real
    // flash/IO failure, not a positive "no trial concept" observation).
    // Fail closed: block destructive writes rather than allow them.
    return true;
  }
  const uint8_t* jedec = flash.jedecId();
  if (jedec[0] != 0x85 || jedec[1] != 0x60 || jedec[2] != 0x15) {
    snprintf(g_early_write_diagnostic, sizeof(g_early_write_diagnostic), "proof=jedec observed=%02X%02X%02X",
             unsigned(jedec[0]), unsigned(jedec[1]), unsigned(jedec[2]));
    return true;
  }
  const mesh::ota::OtaBoardBootQualification qualification = mesh::ota::resolveOtaBoardBootQualification(
      kExpectedBoardTargetId, kExpectedRoleId, kExpectedCapabilityFlags);
  if (!qualification.qualified) return !stockBootOrdinaryWritesAllowed(qualification, true);
  snprintf(g_early_write_diagnostic, sizeof(g_early_write_diagnostic), "marker=qualified proof=qualified-state");
  g_qualified = true;
  if (trial_boot_confirmer_ptr == nullptr) {
    static mesh::ota::OtaBoardTrialBootHealthConfirmer real_confirmer(xiao_state_region, xiao_confirm_region,
                                                                      0u);
    trial_boot_confirmer_ptr = &real_confirmer;
  }
  // A qualified marker alone is NOT sufficient: `isTrialActive()` only
  // answers "is a TRIAL_BOOT phase (or ambiguous state) currently
  // unresolved" -- it is false both for a genuinely NEVER-installed
  // (blank state region) board AND for a board whose last install
  // outcome is FAILED/mid-transaction, neither of which is positive
  // proof of a safe baseline. resolveOtaBoardStartupDecision() draws
  // that distinction explicitly. Normal additionally requires fresh original
  // SDK/hash/floor evidence and absence of active or unexplained commands.
  mesh::ota::OtaBoardNrf52RunningContext running;
  mesh::ota::OtaBoardOriginalSnapshotProvider original(xiao_state_region, xiao_floor_region, running, g_qualified);
  const bool original_safe = original.ordinaryWritesAllowed(
      xiao_command_region, xiao_confirm_region, signature_verifier, kExpectedBoardTargetId, kExpectedRoleId);
  const mesh::ota::OtaBoardStartupDecision decision = mesh::ota::resolveOtaBoardOriginalStartupDecision(
      true, trial_boot_confirmer_ptr->stateReadStatus(), trial_boot_confirmer_ptr->statePhase(), original_safe);
  snprintf(g_early_write_diagnostic, sizeof(g_early_write_diagnostic),
           "marker=qualified proof=qualified-state state=%u phase=%u decision=%u",
           unsigned(trial_boot_confirmer_ptr->stateReadStatus()), unsigned(trial_boot_confirmer_ptr->statePhase()),
           unsigned(decision.status));
  return decision.status != mesh::ota::OtaBoardStartupDecisionStatus::Normal;
}

bool configureCompanionFirmwareOtaBackend(mesh::ota::OtaFirmwareIntegration& integration) {
  // Reset on every (re)configure attempt: see the xiao_nrf52 lab backend's
  // identical comment -- the only place this is ever set true again is
  // the single fully-qualified INSTALL_CAPABLE path below.
  g_backend_qualified_and_bank0_valid = false;
  g_qualified = false;
  g_stock_boot_result = mesh::ota::OtaBoardStockBootPreflight::Result::IoError;
  install_provider_v3 = nullptr;
  g_active_guarded_staging = nullptr;
  if (!ota::platform::SenseCapQspiLayout::isValid() ||
      !ota::platform::isOk(flash.begin())) {
    g_install_capability_reason = "OTA_DISABLED: QSPI flash unavailable";
    mesh::ota::formatOtaBoardCapabilityStatus(g_install_capability_status, sizeof(g_install_capability_status),
                                              g_install_capability_reason);
    return false;
  }
  const uint8_t* jedec_id = flash.jedecId();
  // P25Q16H (PUYA, 16 Mbit / 2 MiB): manufacturer 0x85, memory type 0x60,
  // capacity 0x15 -- identical part/pinout family to variants/xiao_nrf52.
  if (jedec_id[0] != 0x85 || jedec_id[1] != 0x60 || jedec_id[2] != 0x15) {
    g_install_capability_reason = "OTA_DISABLED: unrecognized QSPI flash JEDEC id";
    mesh::ota::formatOtaBoardCapabilityStatus(g_install_capability_status, sizeof(g_install_capability_status),
                                              g_install_capability_reason);
    return false;
  }

  // Fail-closed capability detection: only a struct that passes
  // XiaoOtaBootInfoReader's magic/format/CRC validation is trusted at
  // all, and even then, only when its board_target_id/role/capability/
  // algorithm genuinely match this build's expectations -- never board/
  // JEDEC identity or a compiled flag alone. All-0xFF (stock/unmodified
  // Adafruit bootloader, i.e. every real SenseCAP board today per boot-
  // Hydra) is the expected, common, non-error case here, not corruption.
  //
  // Unqualified devices can only cache owner-signed bytes for other targets.
  // They gain neither receiver admission nor an install-command provider.
  static mesh::ota::OtaBoardCacheOnlyBackend cache_backend(
      candidate, candidate_record_region, &otaBoardTrialHealthWindowActive);
  auto attach_cache_only = [&](const char* reason) {
    g_install_capability_reason = reason;
    mesh::ota::formatOtaBoardCapabilityStatus(g_install_capability_status, sizeof(g_install_capability_status),
                                              g_install_capability_reason);
    return cache_backend.attach(integration, signature_verifier);
  };
  const mesh::ota::OtaBoardBootQualification qualification = mesh::ota::resolveOtaBoardBootQualification(
      kExpectedBoardTargetId, kExpectedRoleId, kExpectedCapabilityFlags);
  static mesh::ota::OtaBoardNrf52RunningContext running_context;
  static mesh::ota::OtaBoardUnadmittedCommandRecovery recovery(
      xiao_command_region, xiao_state_region, xiao_floor_region, candidate, signature_verifier,
      running_context, g_qualified, kExpectedBoardTargetId, kExpectedRoleId);
  integration.attachUnadmittedAbort(&recovery, &mesh::ota::OtaBoardUnadmittedCommandRecovery::invoke);
  if (!qualification.qualified) {
    const bool stock_healthy = stockBootOrdinaryWritesAllowed(qualification);
    const auto cache_result = stock_healthy ?
        mesh::ota::OtaBoardStockBootPreflight::checkCache(candidate_record_region, signature_verifier) :
        g_stock_boot_result;
    const bool cache_allowed = stock_healthy && mesh::ota::OtaBoardStockBootPreflight::cacheAttachAllowed(cache_result);
    snprintf(g_install_capability_status, sizeof(g_install_capability_status), "%s: %s",
             cache_allowed ? "CACHE_ONLY" : "CACHE_UNAVAILABLE",
             mesh::ota::OtaBoardStockBootPreflight::reason(cache_result));
    g_install_capability_reason = g_install_capability_status;
    return cache_allowed && cache_backend.attach(integration, signature_verifier);
  }
  g_qualified = true;
  // Construct the confirmer NOW -- lazily, exactly once (static local),
  // right after qualification is known and BEFORE any bank0/floor check
  // that could otherwise return early -- so health-tick eligibility
  // (otaBoardTryConfirmHealthyTrialBoot()) depends only on `g_qualified`,
  // decoupled from full INSTALL_CAPABLE status: a device with a qualified
  // marker but an invalid bank0/floor must still be able to run its
  // trial-boot deadline/reboot logic to completion. See the identical
  // comment in variants/xiao_nrf52/OtaProductionBackend.cpp for why this must
  // never be a file-scope global object.
  if (trial_boot_confirmer_ptr == nullptr) {
    // boot_epoch_ms=0, NOT millis() read here: see the identical comment
    // in variants/xiao_nrf52/OtaProductionBackend.cpp -- Arduino's millis() is
    // already relative to genuine power-on/reset, not to whatever moment
    // this configure function happens to run at (which is only reached
    // after Serial.begin()/board.begin()/radio_init()/filesystem begin()
    // calls in main.cpp's setup()); a fresh millis() read here would
    // silently grant extra deadline budget on a slow boot.
    static mesh::ota::OtaBoardTrialBootHealthConfirmer real_confirmer(xiao_state_region, xiao_confirm_region,
                                                                      0u);
    trial_boot_confirmer_ptr = &real_confirmer;
  }
  if (trial_boot_confirmer_ptr->isTrialActive()) {
    // A genuine trial-boot health window is still in progress (or its
    // outcome hasn't yet survived a reboot): do NOT perform the blocking,
    // whole-image bank0 CRC+SHA resolution this boot -- defer it (and
    // therefore INSTALL_CAPABLE status) to a later boot once no longer in
    // a live trial, exactly like the xiao_nrf52 lab backend.
    return attach_cache_only("CACHE_ONLY: trial-boot health window, new staging refused");
  }

  std::memcpy(active_wire_public_key, qualification.info.trustedPublicKey, sizeof(active_wire_public_key));
  std::memcpy(anchor.trusted_signer_public_key_ed25519, active_wire_public_key,
              sizeof(anchor.trusted_signer_public_key_ed25519));
  // A qualified marker alone is not sufficient: this build must also be
  // running from a verified original SDK/hash/floor/state snapshot. An invalid snapshot disables
  // receiver/install admission while leaving a non-installable cache.
  static mesh::ota::OtaBoardOriginalSnapshotProvider original_snapshot(
      xiao_state_region, xiao_floor_region, running_context, g_qualified);
  const mesh::ota::OtaBoardInstallGateResult gate =
      mesh::ota::resolveOtaBoardOriginalInstallGate(qualification.qualified, original_snapshot, counter);
  if (!gate.install_capable) {
    return attach_cache_only(gate.reason);
  }
  // This reflects the protocol-level capability this firmware image is
  // built for, independent of whether THIS PARTICULAR flashed device
  // currently has a qualified custom bootloader installed.
  //
  // Bind the ACTUAL qualified marker's signer key/algorithm identity as
  // trusted policy -- never a hardcoded production key/algorithm -- so a
  // descriptor tagged with any other keyId/algorithmId is rejected before
  // any flash write, even if it happened to verify against this device's
  // one compiled-in signature verifier. Uses the shared helper (not
  // inline field assignment) so all six DeviceTrustAnchor identity
  // fields -- including expected_format_id -- are always populated
  // together; see OtaBoardBackendCommon.h's comment for why that field
  // specifically must never be left at its zero default.
  mesh::ota::configureOtaTrustAnchorIdentity(anchor, kExpectedBoardTargetId, kExpectedRoleId,
                                             kExpectedCapabilityFlags, kExpectedDescriptorFormatId,
                                             qualification.info.keyId, qualification.info.algorithmId);

  // NOTE: this used to also anchor `counter` (OtaBoardFailClosedMonotonicCounter)
  // against a publisher-signed BootFloorActivationReceiptV1 lifetime-role
  // record via counter.setRoleAuthority(). That record format belonged to
  // the deleted parallel Authority/Store system and has been removed as
  // part of the lean identity-simplification migration; `counter` now
  // always runs its documented numeric-floor-only fail-closed behavior
  // (see OtaBoardBackendCommon.h). A durable minimal signer-snapshot +
  // manifest-hash install-command contract, if the Boot owner's migration
  // produces one, is a separate, future, explicitly coordinated addition.

  static ota::trust::DescriptorVerifier production_verifier(
      hasher, signature_verifier, counter, anchor);
  static mesh::ota::OtaNrf52FirmwareTrustProvider production_trust(
      production_verifier, candidate, signature_verifier, active_wire_public_key,
      qualification.info.keyId, qualification.info.algorithmId);
  verifier = &production_verifier;
  trust = &production_trust;

  static mesh::ota::OtaBoardInstallCommandProviderV3 production_install_provider_v3(original_snapshot);
  production_install_provider_v3.setTrialActivePredicate(&otaBoardTrialHealthWindowActive);
  static mesh::ota::OtaFirmwareStorageSink production_staging(candidate, &xiao_command_region,
                                                              &production_install_provider_v3);
  // Even the durable INSTALL_CAPABLE sink must refuse a NEW
  // beginSession() while a PRIOR install's trial-boot confirmation is
  // still active/unresolved -- setTrialActivePredicate() above only ever
  // gated BUILDING a new install command, never the storage sink's own
  // erase-on-beginSession() admission.
  static mesh::ota::OtaBoardTrialGuardedStagingSink production_guarded_staging(
      production_staging, &otaBoardTrialHealthWindowActive);
  staging = &production_guarded_staging;
  g_active_guarded_staging = &production_guarded_staging;
  install_provider_v3 = &production_install_provider_v3;
  g_install_capability_reason = gate.reason;
  g_backend_qualified_and_bank0_valid = true;
  mesh::ota::formatOtaBoardCapabilityStatus(g_install_capability_status, sizeof(g_install_capability_status),
                                            g_install_capability_reason);

  static ::ota::storage::OtaCandidateStore candidate_store(candidate_record_region);
  integration.attachCandidateStore(&candidate_store);
  integration.attachLeanSignatureVerifier(&signature_verifier);
  integration.attachTrustProvider(trust);
  integration.attachStagingSink(staging);
  return integration.backendAvailable();
}

#endif
