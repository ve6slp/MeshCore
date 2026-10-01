#include <Arduino.h>
#if defined(NRF52840_XXAA)
#include <nrf_soc.h>  // sd_softdevice_is_enabled / sd_rand_application_vector_get
#endif

#if defined(MESHCORE_LORA_OTA) && MESHCORE_LORA_OTA

#include <cstring>
#include <Ed25519.h>

#include <helpers/ota/OtaBoardBackendCommon.h>
#include <helpers/ota/OtaBoardBaselineMeasurementSource.h>
#include <helpers/ota/OtaFirmwareBackend.h>
#include <helpers/ota/OtaFirmwareIntegration.h>
#include <ota/platform/Nrf52FlashAdapter.h>
#include <ota/platform/Nrf52BootCatalogue.h>
#include <ota/platform/SenseCapQspiLayout.h>
#include <ota/storage/XiaoOtaActiveExtentBridge.h>
#include <ota/storage/XiaoOtaBootInfoReader.h>
#include <ota/storage/XiaoOtaCommandRecord.h>
#include <ota/trust/DescriptorVerifier.h>
#include <ota/trust/MonotonicCounter.h>
#include <ota/trust/Sha256.h>

// Same zero-link-dependency pattern as OtaLabBackend.cpp: on a
// worktree/board where no approved row has been generated for this
// target/profile (SenseCAP's rows are not yet authorized -- see
// Nrf52BootCatalogue.h), row_count is simply 0 and match_boot_catalogue()
// correctly reports MissingCatalogue, never a fabricated row.
#if __has_include(<ota/platform/Nrf52ApprovedBootCatalogue.h>)
#include <ota/platform/Nrf52ApprovedBootCatalogue.h>
#define OTA_HAVE_APPROVED_BOOT_CATALOGUE 1
#else
#define OTA_HAVE_APPROVED_BOOT_CATALOGUE 0
#endif

// Production OTA backend for the SenseCAP Solar board (same nRF52840 +
// P25Q16H QSPI NOR flash family as variants/xiao_nrf52/OtaLabBackend.cpp,
// sharing OtaBoardBackendCommon.h's command-v2/counter/qualification
// logic; the two backends differ only in board_target_id and in that
// this one has no destructive lab qualification region, AND -- stricter
// than the lab backend -- attaches NO staging sink at all (not even
// STAGING_ONLY) when the boot-info marker is not qualified: production
// hardware must never accept/stage OTA transfers under an assumed key
// that has no real cryptographic backing on this specific device.
//
// Fail-closed capability note: this board's custom bootloader
// (bootloader/xiao_nrf52840_ota, built/signed with `--board
// sensecap_solar_p1` per boot-Hydra) is NOT physically qualified on any
// real SenseCAP hardware yet -- treat it as build-only capability until a
// real device reports a genuine boot-info marker. This backend declares
// the real, distinct target id (0x53435031 / "SCP1", confirmed via boot-
// Hydra's cross-board rejection test -- never a 0xFFFFFFFF sentinel), but
// the durable v2 install-command handoff itself, and any staging sink at
// all, remains gated behind XiaoOtaBootInfoReader's live, fail-closed
// detection (magic+format+CRC+board_target_id/role/capability/algorithm
// match) -- never board/JEDEC identity or a compiled flag alone. Until a
// real device reports that marker, every board of this type reports
// OTA_DISABLED, matching reality rather than claiming readiness.
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
constexpr uint32_t kExpectedRoleId = 0u;
#endif
constexpr uint32_t kExpectedCapabilityFlags = 1u;
// The ONE real, physical Nordic bootloader-settings page address -- see
// OtaSdkSettingsCodec.h's header comment: the baseline collector's
// "current SDK settings" measurement and this file's bank-0 extent read
// (otaBoardBaselineReadValidatedBank0Extent, below) are the SAME exact
// 28 live bytes, never two separate schemas.
constexpr uint32_t kBootloaderSettingsAddress = 0x000FF000u;
// Must match bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h's
// XIAO_OTA_DESCRIPTOR_FORMAT (= 1), shared across both board profiles: the
// canonical descriptor wire-format version this whole boot contract is
// built for. This is a fixed protocol-version identifier, not a
// per-device/per-key value, so unlike expected_key_id/expected_algorithm_id
// it is never sourced from the boot marker itself (XiaoOtaBootInfoReader::
// Info has no format_id field at all).
constexpr uint16_t kExpectedDescriptorFormatId = 1u;
// Matches otaBoardBaselineReadCompiledProfile()'s own `out_profile_id = 2u`
// literal below (SenseCAP production profile) -- kept as one named
// constant here so the role-authority anchor and that collector-seam
// function can never silently drift apart.
constexpr uint32_t kExpectedProfileId = 2u;

ota::platform::Nrf52FlashAdapter flash;
// Full production candidate BANK/staging capacity is 792 KiB (matches the
// external QSPI candidateRegion() partition), but the protocol-wide
// kOtaMaxImageBytes accepted-descriptor ceiling is capped lower (708608
// bytes / 0xAD000) until MeshCore v1.17+'s InternalExtraFS (internal flash
// 0xD4000..0xED000) is migrated into the external QSPI FS -- see the
// kOtaMaxImageBytes comment in OtaGeometry.h. This staging region can
// physically hold a larger candidate than any descriptor is currently
// allowed to declare; that is intentional headroom for the future
// migration, not the other way around. Also note this is not the 16 KiB
// candidateTestRegion() the lab-only XIAO backend uses for repeated
// destructive hardware qualification writes.
ota::platform::FlashRegion candidate =
    ota::platform::SenseCapQspiLayout::candidateRegion(flash);
ota::platform::FlashRegion xiao_floor_region =
    ota::platform::SenseCapQspiLayout::xiaoFloorRegion(flash);
ota::platform::FlashRegion xiao_command_region =
    ota::platform::SenseCapQspiLayout::xiaoCommandRegion(flash);
ota::platform::FlashRegion xiao_state_region = ota::platform::SenseCapQspiLayout::xiaoStateRegion(flash);
ota::platform::FlashRegion xiao_confirm_region = ota::platform::SenseCapQspiLayout::xiaoConfirmRegion(flash);
mesh::ota::OtaBoardFailClosedMonotonicCounter counter(xiao_floor_region);
// Constructed LAZILY, post-flash.begin() and post-qualification (see
// configureCompanionFirmwareOtaBackend() below) -- NEVER as a file-scope
// global object; see the identical comment in
// variants/xiao_nrf52/OtaLabBackend.cpp for why a global here would read
// QSPI flash before flash.begin() ever ran.
mesh::ota::OtaBoardTrialBootHealthConfirmer* trial_boot_confirmer_ptr = nullptr;

ota::trust::Sha256 hasher;
ProductionSignatureVerifier signature_verifier;
ota::trust::DeviceTrustAnchor anchor;
uint8_t active_wire_public_key[32] = {0};
ota::trust::DescriptorVerifier* verifier = nullptr;
mesh::ota::OtaFirmwareTrustProvider* trust = nullptr;
meshcore::ota::runtime::IOtaStagingSink* staging = nullptr;
mesh::ota::OtaBoardInstallCommandProviderV2* install_provider_v2 = nullptr;

// Set once by configureCompanionFirmwareOtaBackend() so any caller (e.g. a
// future CLI/status command) can report the real reason install
// capability is or is not available, instead of a success-shaped
// assumption based on board/JEDEC identity or compiled feature flags
// alone -- identical contract to
// variants/xiao_nrf52/OtaLabBackend.cpp's otaLabInstallCapabilityReason().
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
// comment in variants/xiao_nrf52/OtaLabBackend.cpp. Health-tick
// eligibility and erase-admission blocking depend only on this flag.
bool g_qualified = false;

// Points at the sole OtaBoardTrialGuardedStagingSink instance (see
// production_guarded_staging below) once attached, so the real, grounded
// per-tick storage-fault getter below can report on it. No staging sink
// attached at all (trial-active/no-marker/invalid-bank0/bad-floor early
// returns leave this null) simply reports false.
mesh::ota::OtaBoardTrialGuardedStagingSink* g_active_guarded_staging = nullptr;

}  // namespace

const char* otaProductionInstallCapabilityReason() { return g_install_capability_reason; }

// Compact (<=63 byte) install-capability status line, suitable for
// embedding directly in the existing OTA status serial frame (<=176 byte
// budget) alongside other fields -- not just an unwired getter.
const char* otaBoardInstallCapabilityStatus() { return g_install_capability_status; }

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
  if (trial_boot_confirmer_ptr == nullptr) return mesh::ota::OtaBoardTrialHealthOutcome::Pending;
  return trial_boot_confirmer_ptr->tick(now_ms, radio_ready, filesystem_ready, loop_healthy);
}

// True whenever this device is qualified AND (the confirmer is not yet
// constructed -- fail closed: "unknown" blocks -- OR a genuine trial-boot
// health window is in progress/unresolved). See the identical comment in
// variants/xiao_nrf52/OtaLabBackend.cpp.
bool otaBoardTrialHealthWindowActive() {
  if (!g_qualified) return false;
  if (trial_boot_confirmer_ptr == nullptr) return true;
  return trial_boot_confirmer_ptr->isTrialActive();
}

// Genuine earliest-boot-phase preflight -- see the identical comment in
// variants/xiao_nrf52/OtaLabBackend.cpp and MyMesh.cpp's weak default.
bool otaBoardEarlyBootTrialOrUnknown() {
  if (!ota::platform::SenseCapQspiLayout::isValid() || !ota::platform::isOk(flash.begin())) {
    // Cannot even read the OTA state region -- genuinely UNKNOWN (a real
    // flash/IO failure, not a positive "no trial concept" observation).
    // Fail closed: block destructive writes rather than allow them.
    return true;
  }
  const mesh::ota::OtaBoardBootQualification qualification = mesh::ota::resolveOtaBoardBootQualification(
      kExpectedBoardTargetId, kExpectedRoleId, kExpectedCapabilityFlags);
  if (qualification.status == mesh::ota::OtaBoardQualificationStatus::Normal) {
    // Reserved for a FUTURE, separately signed CertifyExistingBaseline
    // authority (see OtaBaselineCertificationEvidence.h) -- NOT reachable
    // today: resolveOtaBoardBootQualification() never produces Normal
    // from a blank/missing marker alone anymore. Left in place so a
    // future owner wiring that authority in doesn't also have to touch
    // this call site.
    return false;
  }
  if (qualification.status == mesh::ota::OtaBoardQualificationStatus::Unknown) {
    // Corrupt marker, or a validly-formed marker that doesn't match this
    // build's expected board/role/capability/algorithm -- ambiguous, must
    // never be treated the same as genuine stock/factory. Fail closed.
    return true;
  }
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
  // that distinction explicitly; its Normal outcome additionally requires
  // a positive `has_verified_fresh_baseline_proof` (not supplied here --
  // no real fresh SDK/CRC/SHA/signature/role provider is wired yet), so
  // this call is HONESTLY Unknown-or-Trial today even on a CONFIRMED
  // record, never a fabricated Normal.
  const mesh::ota::OtaBoardStartupDecision decision = mesh::ota::resolveOtaBoardStartupDecision(
      /*qualified=*/true, trial_boot_confirmer_ptr->stateReadStatus(), trial_boot_confirmer_ptr->statePhase());
  return decision.status != mesh::ota::OtaBoardStartupDecisionStatus::Normal;
}

// Forward declaration: real body defined below alongside the other
// OtaBaselineMeasurementCollector source-adapter hooks -- needed here to
// seed the BootFloorRoleAuthorityAnchor's device_uid8 with the SAME
// physical-UID read every other consumer of this value already uses
// (never a second, independently-written FICR read). Mirrors the
// xiao_nrf52 lab backend's identical forward declaration.
namespace mesh {
namespace ota {
bool otaBoardBaselineReadUid8(uint8_t out_uid8[8]);
}  // namespace ota
}  // namespace mesh

bool configureCompanionFirmwareOtaBackend(mesh::ota::OtaFirmwareIntegration& integration) {
  // Reset on every (re)configure attempt: see the xiao_nrf52 lab backend's
  // identical comment -- the only place this is ever set true again is
  // the single fully-qualified INSTALL_CAPABLE path below.
  g_backend_qualified_and_bank0_valid = false;
  g_qualified = false;
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
  // Unlike the XIAO lab backend, production has NO hardcoded-key
  // STAGING_ONLY fallback: on any unqualified marker, no trust provider
  // and no staging sink are attached at all -- this device cannot stage
  // or install ANY OTA image, not even into a bench-fixture-only path,
  // until it carries a real, cryptographically qualified custom
  // bootloader.
  const mesh::ota::OtaBoardBootQualification qualification = mesh::ota::resolveOtaBoardBootQualification(
      kExpectedBoardTargetId, kExpectedRoleId, kExpectedCapabilityFlags);
  if (!qualification.qualified) {
    g_install_capability_reason = "OTA_DISABLED: no qualified custom boot detected (production)";
    mesh::ota::formatOtaBoardCapabilityStatus(g_install_capability_status, sizeof(g_install_capability_status),
                                              g_install_capability_reason);
    return false;
  }
  g_qualified = true;
  // Construct the confirmer NOW -- lazily, exactly once (static local),
  // right after qualification is known and BEFORE any bank0/floor check
  // that could otherwise return early -- so health-tick eligibility
  // (otaBoardTryConfirmHealthyTrialBoot()) depends only on `g_qualified`,
  // decoupled from full INSTALL_CAPABLE status: a device with a qualified
  // marker but an invalid bank0/floor must still be able to run its
  // trial-boot deadline/reboot logic to completion. See the identical
  // comment in variants/xiao_nrf52/OtaLabBackend.cpp for why this must
  // never be a file-scope global object.
  if (trial_boot_confirmer_ptr == nullptr) {
    // boot_epoch_ms=0, NOT millis() read here: see the identical comment
    // in variants/xiao_nrf52/OtaLabBackend.cpp -- Arduino's millis() is
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
    g_install_capability_reason =
        "OTA_DISABLED: trial-boot health confirmation in progress, bank0 resolution deferred";
    mesh::ota::formatOtaBoardCapabilityStatus(g_install_capability_status, sizeof(g_install_capability_status),
                                              g_install_capability_reason);
    return false;
  }

  std::memcpy(active_wire_public_key, qualification.info.trustedPublicKey, sizeof(active_wire_public_key));
  std::memcpy(anchor.trusted_signer_public_key_ed25519, active_wire_public_key,
              sizeof(anchor.trusted_signer_public_key_ed25519));
  // A qualified marker alone is not sufficient: this build must also be
  // running from a genuinely valid, freshly resolved bank-0 record
  // (BANK_VALID_APP + matching CRC/size). Production has no staging-only
  // fallback -- an invalid bank0 disables OTA entirely here, same as an
  // unqualified marker, and reports the actual diagnosed reason.
  const ::ota::storage::XiaoOtaActiveExtentInfo bank0 = ::ota::storage::XiaoOtaActiveExtentBridge::resolveCurrent();
  if (bank0.active_image_extent == 0) {
    g_install_capability_reason = "OTA_DISABLED: qualified boot marker but bank0 invalid or unresolved";
    mesh::ota::formatOtaBoardCapabilityStatus(g_install_capability_status, sizeof(g_install_capability_status),
                                              g_install_capability_reason);
    return false;
  }
  // A qualified marker and valid bank0 are still not sufficient: the
  // bootloader-owned confirmed-counter floor must also be genuinely
  // readable (a valid record, or both slots legitimately blank -- a real
  // first-ever-device baseline of 0) before this build ever attaches a
  // trust provider, staging sink, or install-command provider. Production
  // has no staging-only fallback: a corrupt/unreadable floor disables OTA
  // entirely here, exactly like an unqualified marker or invalid bank0,
  // with an explicit diagnosed reason rather than a silent floor==0
  // default. Shared, natively-testable predicate (see
  // OtaBoardBackendCommon.h) rather than duplicated inline logic.
  const mesh::ota::OtaBoardInstallGateResult gate =
      mesh::ota::resolveOtaBoardInstallGate(qualification.qualified, bank0.active_image_extent, counter);
  if (!gate.install_capable) {
    g_install_capability_reason =
        "OTA_DISABLED: qualified boot marker and valid bank0 but floor counter unreadable or corrupt";
    mesh::ota::formatOtaBoardCapabilityStatus(g_install_capability_status, sizeof(g_install_capability_status),
                                              g_install_capability_reason);
    return false;
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

  // Root's "FINAL IMPLEMENTABLE HIGH-FIX CONTRACT" section D: the SAME
  // trusted publisher key just bound above also anchors the durable
  // lifetime-role receipt gate -- there is only one firmware publisher
  // identity in this system, never a second key for this purpose.
  ::ota::storage::BootFloorRoleAuthorityAnchor role_anchor;
  std::memcpy(role_anchor.trusted_publisher_public_key_ed25519, active_wire_public_key,
              sizeof(role_anchor.trusted_publisher_public_key_ed25519));
  role_anchor.expected_target_id = kExpectedBoardTargetId;
  role_anchor.expected_profile_id = kExpectedProfileId;
  role_anchor.expected_layout_id = kExpectedDescriptorFormatId;
  role_anchor.expected_role_id = kExpectedRoleId;
  mesh::ota::otaBoardBaselineReadUid8(role_anchor.device_uid8);
  counter.setRoleAuthority(role_anchor, signature_verifier);

  static ota::trust::DescriptorVerifier production_verifier(
      hasher, signature_verifier, counter, anchor);
  static mesh::ota::OtaFirmwareTrustProvider production_trust(
      production_verifier, candidate, signature_verifier, active_wire_public_key,
      qualification.info.keyId, qualification.info.algorithmId);
  verifier = &production_verifier;
  trust = &production_trust;

  static mesh::ota::OtaBoardInstallCommandProviderV2 production_install_provider_v2;
  production_install_provider_v2.setTrialActivePredicate(&otaBoardTrialHealthWindowActive);
  static mesh::ota::OtaFirmwareStorageSink production_staging(candidate, &xiao_command_region,
                                                              &production_install_provider_v2);
  // Even the durable INSTALL_CAPABLE sink must refuse a NEW
  // beginSession() while a PRIOR install's trial-boot confirmation is
  // still active/unresolved -- setTrialActivePredicate() above only ever
  // gated BUILDING a new install command, never the storage sink's own
  // erase-on-beginSession() admission.
  static mesh::ota::OtaBoardTrialGuardedStagingSink production_guarded_staging(
      production_staging, &otaBoardTrialHealthWindowActive);
  staging = &production_guarded_staging;
  g_active_guarded_staging = &production_guarded_staging;
  install_provider_v2 = &production_install_provider_v2;
  g_install_capability_reason = "INSTALL_CAPABLE: qualified custom bootloader detected (command v2)";
  g_backend_qualified_and_bank0_valid = true;
  mesh::ota::formatOtaBoardCapabilityStatus(g_install_capability_status, sizeof(g_install_capability_status),
                                            g_install_capability_reason);

  integration.attachTrustProvider(trust);
  integration.attachStagingSink(staging);
  return integration.backendAvailable();
}

// -----------------------------------------------------------------------
// Real production source-adapter hooks for OtaBaselineMeasurementCollector
// (see helpers/ota/OtaBoardBaselineMeasurementSource.h): genuine local
// reads only. Normal/write/cert stay entirely out of scope here -- this
// only ever reports FACTS, never grants any permission.
// -----------------------------------------------------------------------
namespace mesh {
namespace ota {

bool otaBoardBaselineReadUid8(uint8_t out_uid8[8]) {
#if defined(NRF52840_XXAA)
  const uint32_t hi = NRF_FICR->DEVICEID[1];
  const uint32_t lo = NRF_FICR->DEVICEID[0];
  out_uid8[0] = static_cast<uint8_t>(hi >> 24);
  out_uid8[1] = static_cast<uint8_t>(hi >> 16);
  out_uid8[2] = static_cast<uint8_t>(hi >> 8);
  out_uid8[3] = static_cast<uint8_t>(hi);
  out_uid8[4] = static_cast<uint8_t>(lo >> 24);
  out_uid8[5] = static_cast<uint8_t>(lo >> 16);
  out_uid8[6] = static_cast<uint8_t>(lo >> 8);
  out_uid8[7] = static_cast<uint8_t>(lo);
  return true;
#else
  (void)out_uid8;
  return false;
#endif
}

bool otaBoardBaselineReadCompiledProfile(uint32_t& out_profile_id, uint32_t& out_target_id, uint32_t& out_role_id,
                                        uint32_t& out_layout_id) {
  out_profile_id = 2u;  // 2 == SenseCAP production profile (see collector seam doc).
  out_target_id = kExpectedBoardTargetId;
  out_role_id = kExpectedRoleId;
  out_layout_id = kExpectedDescriptorFormatId;
  return true;
}

bool otaBoardBaselineReadRawCurrentSdkSettings(uint8_t out_raw28[mesh::ota::kOtaCurrentSdkSettingsRecordBytes]) {
#if defined(NRF52840_XXAA)
  // Exact live copy of the real, physical Nordic bootloader-settings
  // page -- the SAME [0xFF000, 0xFF01C) bytes
  // otaBoardBaselineReadValidatedBank0Extent() (below) structurally
  // decodes via XiaoOtaActiveExtentBridge::decodeBank0FromRaw28Bytes().
  // Never a fabricated/synthesized record.
  const uint8_t* raw = reinterpret_cast<const uint8_t*>(kBootloaderSettingsAddress);
  memcpy(out_raw28, raw, mesh::ota::kOtaCurrentSdkSettingsRecordBytes);
  return true;
#else
  (void)out_raw28;
  return false;
#endif
}

namespace {
::ota::storage::XiaoOtaIncrementalExtentResolver* g_baseline_extent_resolver = nullptr;
uint32_t g_baseline_extent_resolver_prev_progress = 0;

// Real, Boot-confirmed, linker-script-fixed bootloader CODE region --
// identical address/size whether the currently-flashed loader is stock
// or this project's signed OTA-capable replacement (see Boot's
// write_agent coordination). This is a structural fact, not a guess;
// the loader's actual byte CONTENTS are still hashed live below, never
// assumed/cached.
constexpr uint32_t kStockLoaderRangeStart = 0x000F4000u;
constexpr uint32_t kStockLoaderRangeLength = 0x9800u;  // 38,912 bytes.

// Resumable, budget-bounded SHA-256 state for the StockLoader baseline
// phase -- reset exactly once per job below (same reset point as the
// extent resolver above, since Phase::Extent always runs before
// Phase::StockLoader within one job -- see
// OtaBaselineMeasurementCollector.h). stepStockLoaderRangeHash() below
// consumes AT MOST the caller-supplied budget per call and reports the
// exact bytes it actually read, never a whole-region blocking hash.
::ota::trust::Sha256 g_stock_loader_hasher;
uint32_t g_stock_loader_progress = 0;
bool g_stock_loader_active = false;
// Cached result of the StockLoader phase, consumed by the Classified
// phase below -- same rationale as OtaLabBackend.cpp's identical cache:
// the Classified phase must never recompute this hash, and must fail
// closed (not silently proceed with a zeroed hash) if StockLoader never
// resolved earlier this same job.
uint8_t g_stock_loader_hash_cache[32] = {0};
bool g_stock_loader_hash_cache_valid = false;

// Real, Boot/Astra-confirmed (write_agent coordination) fixed addresses
// for the boot-config selector/MBR-params-blank evidence phase. The MBR
// forward-pointer words at 0xFF8/0xFFC and the UICR NRFFW[0]/[1] mirror
// words at 0x10001014/0x10001018 are genuine nRF52 addresses; the MBR
// parameter PAGE itself is the structurally-confirmed [0xFE000,0xFF000)
// region immediately preceding the SDK/bootloader-settings page this
// backend already reads elsewhere (kBootloaderSettingsAddress).
constexpr uint32_t kMbrBootForwardAddr = 0x00000FF8u;
constexpr uint32_t kMbrParamsPageAddrWord = 0x00000FFCu;
constexpr uint32_t kUicrNrffw0Addr = 0x10001014u;
constexpr uint32_t kUicrNrffw1Addr = 0x10001018u;
constexpr uint32_t kMbrParamsPageStart = 0x000FE000u;
constexpr uint32_t kMbrParamsPageLength = 0x00001000u;  // 4096 bytes.

// Root/Astra-pinned selector-tuple POLICY shapes (write_agent
// coordination, Turn "ROOT requested...boot-config/catalogue contract"):
// classify the SELECTOR tuple only. NEVER treated as sufficient
// authorization alone -- see the doc comment on
// otaBoardBaselineStepBootConfigSelection() below for why this always
// stays Failed today regardless of which policy (if any) matches.
// Public pinned reference ranges -- IDENTICAL addresses to
// OtaLabBackend.cpp's: same nRF52840 + S140 7.3.0 SoftDevice family, same
// MBR/CF2/SoftDevice/loader layout (see this file's own top-of-file doc
// comment: "the two backends differ only in board_target_id").
constexpr uint32_t kMbrBodyRangeStart = 0u;
constexpr uint32_t kMbrBodyRangeLength = ::ota::platform::kNrf52MbrBodyRangeEnd;  // 0xFF8
constexpr uint32_t kCf2RangeStart = ::ota::platform::kNrf52BootCf2Offset;         // 0xFD800
constexpr uint32_t kCf2RangeLength = ::ota::platform::kNrf52BootCf2Size;          // 0x800
constexpr uint32_t kSdRangeStart = ::ota::platform::kNrf52SoftDeviceRangeStart;   // 0x1000
constexpr uint32_t kSdRangeLength =
    ::ota::platform::kNrf52SoftDeviceRangeEnd - ::ota::platform::kNrf52SoftDeviceRangeStart;  // 0x26000

constexpr uint32_t kMbrVectorBase = kMbrBodyRangeStart;        // 0x0
constexpr uint32_t kSdVectorBase = kSdRangeStart;              // 0x1000
constexpr uint32_t kLoaderVectorBase = kStockLoaderRangeStart;  // 0xF4000

constexpr uint32_t kFicrCodePageSizeAddr = 0x10000010u;
constexpr uint32_t kFicrCodeSizeAddr = 0x10000014u;

constexpr uint32_t kSdInfoMagicAddr = 0x00003004u;
constexpr uint32_t kSdInfoSizeAddr = 0x00003008u;
constexpr uint32_t kSdInfoFwidAddr = 0x0000300Cu;
constexpr uint32_t kSdInfoVariantAddr = 0x00003010u;
constexpr uint32_t kSdInfoVersionAddr = 0x00003014u;
constexpr uint32_t kSdInfoUniqueIdAddr = 0x00003018u;

enum class BootConfigPhase : uint8_t {
  Idle,
  ReadFieldsAndVectors,
  MbrHash,
  Cf2Hash,
  SdHash,
  BlankScan,
  Classified
};
BootConfigPhase g_boot_config_phase = BootConfigPhase::Idle;
uint32_t g_boot_config_blank_scan_progress = 0;
bool g_boot_config_blank_scan_ok = true;
uint32_t g_boot_config_mbr_boot = 0;
uint32_t g_boot_config_mbr_params = 0;
uint32_t g_boot_config_uicr0 = 0;
uint32_t g_boot_config_uicr1 = 0;
::ota::platform::Nrf52BootVectorPair g_boot_config_mbr_vectors;
::ota::platform::Nrf52BootVectorPair g_boot_config_sd_vectors;
::ota::platform::Nrf52BootVectorPair g_boot_config_loader_vectors;
::ota::platform::Nrf52FicrGeometry g_boot_config_ficr_geometry;
uint32_t g_boot_config_sd_info_magic = 0;
uint32_t g_boot_config_sd_info_size = 0;
uint16_t g_boot_config_sd_info_fwid = 0;
uint16_t g_boot_config_sd_info_variant = 0;
uint32_t g_boot_config_sd_info_version = 0;
uint8_t g_boot_config_sd_info_unique_id[20] = {0};
::ota::trust::Sha256 g_mbr_hasher;
uint32_t g_mbr_hash_progress = 0;
uint8_t g_mbr_hash_cache[32] = {0};
::ota::trust::Sha256 g_cf2_hasher;
uint32_t g_cf2_hash_progress = 0;
uint8_t g_cf2_hash_cache[32] = {0};
// Boot_info[60] lives inside this same CF2 range -- see
// OtaLabBackend.cpp's identical capture rationale; captured
// opportunistically as the Cf2Hash phase streams through, never a
// second read pass.
constexpr uint32_t kBootInfoCaptureStart = ::ota::platform::kNrf52BootInfoOffset - kCf2RangeStart;  // 0x400
::ota::platform::Nrf52BootInfoCaptureStatus g_boot_info_capture_status =
    ::ota::platform::Nrf52BootInfoCaptureStatus::NotCaptured;
uint8_t g_boot_info_capture[::ota::platform::kNrf52BootInfoSize] = {0};
uint32_t g_boot_info_capture_bytes_copied = 0;
::ota::trust::Sha256 g_sd_hasher;
uint32_t g_sd_hash_progress = 0;
uint8_t g_sd_hash_cache[32] = {0};
}  // namespace

bool otaBoardBaselineReadValidatedBank0Extent(uint32_t& out_extent, uint32_t& out_internal_addr,
                                              uint16_t& out_stored_crc16) {
#if defined(NRF52840_XXAA)
  const uint8_t* raw = reinterpret_cast<const uint8_t*>(kBootloaderSettingsAddress);
  const ::ota::storage::XiaoOtaBank0Settings bank0 = ::ota::storage::XiaoOtaActiveExtentBridge::decodeBank0FromRaw28Bytes(raw);
  if (bank0.bank_0 != ::ota::storage::kBankValidApp || bank0.bank_0_size == 0 ||
      bank0.bank_0_size > ::ota::storage::kXiaoOtaAppInstallMaxSize) {
    return false;
  }
  out_extent = bank0.bank_0_size;
  out_internal_addr = ::ota::storage::kXiaoOtaAppStart;
  out_stored_crc16 = bank0.bank_0_crc;
  static ::ota::storage::XiaoOtaIncrementalExtentResolver resolver;
  resolver = ::ota::storage::XiaoOtaIncrementalExtentResolver();
  g_baseline_extent_resolver = &resolver;
  g_baseline_extent_resolver_prev_progress = 0;
  // Arm the StockLoader phase's resumable hasher for this SAME job --
  // Phase::Extent (this call) always runs immediately before
  // Phase::StockLoader within one collector job, so this is the correct
  // single reset point (see g_stock_loader_* doc comment above).
  g_stock_loader_hasher.reset();
  g_stock_loader_progress = 0;
  g_stock_loader_active = true;
  g_stock_loader_hash_cache_valid = false;
  // Arm the BootConfig phase's resumable selector-read/blank-scan for
  // this SAME job -- Phase::StockLoader always runs immediately before
  // Phase::BootConfig within one collector job (see same reset-point
  // rationale as g_stock_loader_* above).
  g_boot_config_phase = BootConfigPhase::ReadFieldsAndVectors;
  g_boot_config_blank_scan_progress = 0;
  g_boot_config_blank_scan_ok = true;
  g_mbr_hasher.reset();
  g_mbr_hash_progress = 0;
  g_cf2_hasher.reset();
  g_cf2_hash_progress = 0;
  g_boot_info_capture_status = ::ota::platform::Nrf52BootInfoCaptureStatus::NotCaptured;
  g_boot_info_capture_bytes_copied = 0;
  g_sd_hasher.reset();
  g_sd_hash_progress = 0;
  return true;
#else
  (void)out_extent;
  (void)out_internal_addr;
  (void)out_stored_crc16;
  return false;
#endif
}

mesh::ota::OtaBaselineMeasurementSubStep otaBoardBaselineStepAppImageAccess(uint32_t max_bytes,
                                                                            uint32_t* out_bytes_consumed,
                                                                            const uint8_t** out_image,
                                                                            uint32_t* out_extent) {
#if defined(NRF52840_XXAA)
  if (g_baseline_extent_resolver == nullptr) {
    *out_bytes_consumed = 0;
    return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
  }
  const auto step = g_baseline_extent_resolver->step(max_bytes, out_image, out_extent);
  const uint32_t now_progress = g_baseline_extent_resolver->bytesProcessedSoFar();
  *out_bytes_consumed = now_progress - g_baseline_extent_resolver_prev_progress;
  g_baseline_extent_resolver_prev_progress = now_progress;
  switch (step) {
    case ::ota::storage::XiaoOtaExtentResolutionStep::Resolved:
      return mesh::ota::OtaBaselineMeasurementSubStep::Resolved;
    case ::ota::storage::XiaoOtaExtentResolutionStep::Failed:
      return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
    default:
      return mesh::ota::OtaBaselineMeasurementSubStep::InProgress;
  }
#else
  (void)max_bytes;
  *out_bytes_consumed = 0;
  (void)out_image;
  (void)out_extent;
  return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
#endif
}

// Stock-loader executable-range hashing is now real and bounded (see
// OtaLabBackend.cpp's matching implementation/doc comment for the full
// rationale, including Root's explicit rejection of treating an
// operator-copied live hash as automatically "approved," and of
// treating Boot's journal-record survivor pick as boot-config-id): the
// (start,length) is Boot's structurally-confirmed, linker-fixed
// bootloader CODE region (kStockLoaderRangeStart/Length above), read
// live from internal flash and SHA-256'd incrementally, at most
// `max_bytes` per call, across as many resumed calls as needed. This
// step only CAPTURES the live hash into evidence -- it does NOT compare
// against any "approved" value itself; real approval requires a Root
// -defined artifact-provenance catalogue, not yet built. Boot-config
// selection (see otaBoardBaselineStepBootConfigSelection() below) now
// does real bounded MBR/UICR selector reads + an MBR-parameter-page
// blank-scan and classifies the tuple against Root/Astra-pinned POLICY
// shapes, but still always resolves Failed until that catalogue lands.
// QSPI-state inspection remains unavailable (fail closed).
mesh::ota::OtaBaselineMeasurementSubStep otaBoardBaselineStepStockLoaderRangeHash(
    uint32_t max_bytes, uint32_t* out_bytes_consumed, uint32_t& out_range_start, uint32_t& out_range_length,
    uint8_t* out_hash32) {
#if defined(NRF52840_XXAA)
  if (!g_stock_loader_active) {
    *out_bytes_consumed = 0;
    return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
  }
  out_range_start = kStockLoaderRangeStart;
  out_range_length = kStockLoaderRangeLength;
  if (g_stock_loader_progress > kStockLoaderRangeLength) {
    // Underflow guard: this should never legitimately happen.
    *out_bytes_consumed = 0;
    g_stock_loader_active = false;
    return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
  }
  const uint32_t remaining = kStockLoaderRangeLength - g_stock_loader_progress;
  const uint32_t take = remaining < max_bytes ? remaining : max_bytes;
  if (take > 0) {
    const uint8_t* raw = reinterpret_cast<const uint8_t*>(kStockLoaderRangeStart + g_stock_loader_progress);
    g_stock_loader_hasher.update(raw, take);
    g_stock_loader_progress += take;
  }
  *out_bytes_consumed = take;
  if (g_stock_loader_progress >= kStockLoaderRangeLength) {
    g_stock_loader_hasher.finish(out_hash32);
    memcpy(g_stock_loader_hash_cache, out_hash32, 32);
    g_stock_loader_hash_cache_valid = true;
    g_stock_loader_active = false;
    return mesh::ota::OtaBaselineMeasurementSubStep::Resolved;
  }
  return mesh::ota::OtaBaselineMeasurementSubStep::InProgress;
#else
  (void)max_bytes;
  *out_bytes_consumed = 0;
  (void)out_range_start;
  (void)out_range_length;
  (void)out_hash32;
  return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
#endif
}

// Boot-config selection is now the REAL, bounded/resumable catalogue
// measurement + matching pipeline -- the SAME concrete DTO
// (src/ota/platform/Nrf52BootCatalogue.h) and the SAME address layout
// as OtaLabBackend.cpp's XIAO implementation (shared nRF52840 + S140
// 7.3.0 family; this backend differs only in target_id/profile_id/role
// source). MBR/UICR selector words, 3 vector-table pairs, FICR geometry,
// the SoftDevice info struct, a full incremental blank-scan of the
// MBR-parameter page, 3 resumable SHA-256 hashes (MBR/CF2/SoftDevice),
// and a bounded boot_info[60] capture opportunistically taken from the
// SAME CF2 scan bytes. The stock-loader hash is reused from the
// StockLoader phase that already ran earlier this SAME job
// (g_stock_loader_hash_cache), never recomputed.
//
// Until Root/the catalogue-producer agent authorizes a SenseCAP row
// (see Nrf52BootCatalogue.h / the "No SenseCAP stock row is authorized"
// constraint), this will correctly resolve MissingCatalogue/Unsupported
// -- never a fabricated Approved -- but it is no longer a selector-only
// stub: a genuine custom SenseCAP row, once authorized, is fully
// verifiable by this SAME pipeline without further backend changes.
mesh::ota::OtaBaselineMeasurementSubStep otaBoardBaselineStepBootConfigSelection(uint32_t max_bytes,
                                                                                 uint32_t* out_bytes_consumed,
                                                                                 uint32_t& out_boot_config_id,
                                                                                 bool& out_catalogue_unavailable,
                                                                                 bool& out_mismatch) {
#if defined(NRF52840_XXAA)
  *out_bytes_consumed = 0;
  out_boot_config_id = 0;
  out_catalogue_unavailable = false;
  out_mismatch = false;
  if (g_boot_config_phase == BootConfigPhase::Idle) {
    return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
  }
  if (g_boot_config_phase == BootConfigPhase::ReadFieldsAndVectors) {
    g_boot_config_mbr_boot = *reinterpret_cast<const volatile uint32_t*>(kMbrBootForwardAddr);
    g_boot_config_mbr_params = *reinterpret_cast<const volatile uint32_t*>(kMbrParamsPageAddrWord);
    g_boot_config_uicr0 = *reinterpret_cast<const volatile uint32_t*>(kUicrNrffw0Addr);
    g_boot_config_uicr1 = *reinterpret_cast<const volatile uint32_t*>(kUicrNrffw1Addr);
    g_boot_config_mbr_vectors.msp = *reinterpret_cast<const volatile uint32_t*>(kMbrVectorBase);
    g_boot_config_mbr_vectors.reset = *reinterpret_cast<const volatile uint32_t*>(kMbrVectorBase + 4u);
    g_boot_config_sd_vectors.msp = *reinterpret_cast<const volatile uint32_t*>(kSdVectorBase);
    g_boot_config_sd_vectors.reset = *reinterpret_cast<const volatile uint32_t*>(kSdVectorBase + 4u);
    g_boot_config_loader_vectors.msp = *reinterpret_cast<const volatile uint32_t*>(kLoaderVectorBase);
    g_boot_config_loader_vectors.reset = *reinterpret_cast<const volatile uint32_t*>(kLoaderVectorBase + 4u);
    g_boot_config_ficr_geometry.code_page_size = *reinterpret_cast<const volatile uint32_t*>(kFicrCodePageSizeAddr);
    g_boot_config_ficr_geometry.code_size = *reinterpret_cast<const volatile uint32_t*>(kFicrCodeSizeAddr);
    g_boot_config_sd_info_magic = *reinterpret_cast<const volatile uint32_t*>(kSdInfoMagicAddr);
    g_boot_config_sd_info_size = *reinterpret_cast<const volatile uint32_t*>(kSdInfoSizeAddr);
    g_boot_config_sd_info_fwid = *reinterpret_cast<const volatile uint16_t*>(kSdInfoFwidAddr);
    g_boot_config_sd_info_variant = *reinterpret_cast<const volatile uint16_t*>(kSdInfoVariantAddr);
    g_boot_config_sd_info_version = *reinterpret_cast<const volatile uint32_t*>(kSdInfoVersionAddr);
    memcpy(g_boot_config_sd_info_unique_id, reinterpret_cast<const void*>(kSdInfoUniqueIdAddr), 20);
    *out_bytes_consumed = 16u + 24u + 8u + 4u + 4u + 2u + 2u + 4u + 20u;  // 84 bytes.
    g_boot_config_phase = BootConfigPhase::MbrHash;
    return mesh::ota::OtaBaselineMeasurementSubStep::InProgress;
  }
  if (g_boot_config_phase == BootConfigPhase::MbrHash) {
    const uint32_t remaining = kMbrBodyRangeLength - g_mbr_hash_progress;
    const uint32_t take = remaining < max_bytes ? remaining : max_bytes;
    if (take > 0) {
      const uint8_t* raw = reinterpret_cast<const uint8_t*>(kMbrBodyRangeStart + g_mbr_hash_progress);
      g_mbr_hasher.update(raw, take);
      g_mbr_hash_progress += take;
    }
    *out_bytes_consumed = take;
    if (g_mbr_hash_progress >= kMbrBodyRangeLength) {
      g_mbr_hasher.finish(g_mbr_hash_cache);
      g_boot_config_phase = BootConfigPhase::Cf2Hash;
    }
    return mesh::ota::OtaBaselineMeasurementSubStep::InProgress;
  }
  if (g_boot_config_phase == BootConfigPhase::Cf2Hash) {
    const uint32_t remaining = kCf2RangeLength - g_cf2_hash_progress;
    const uint32_t take = remaining < max_bytes ? remaining : max_bytes;
    if (take > 0) {
      const uint8_t* raw = reinterpret_cast<const uint8_t*>(kCf2RangeStart + g_cf2_hash_progress);
      g_cf2_hasher.update(raw, take);
      const uint32_t window_start = g_cf2_hash_progress;
      const uint32_t window_end = g_cf2_hash_progress + take;
      const uint32_t marker_start = kBootInfoCaptureStart;
      const uint32_t marker_end = kBootInfoCaptureStart + ::ota::platform::kNrf52BootInfoSize;
      const uint32_t overlap_start = window_start > marker_start ? window_start : marker_start;
      const uint32_t overlap_end = window_end < marker_end ? window_end : marker_end;
      if (overlap_start < overlap_end) {
        memcpy(g_boot_info_capture + (overlap_start - marker_start), raw + (overlap_start - window_start),
               overlap_end - overlap_start);
        g_boot_info_capture_bytes_copied += (overlap_end - overlap_start);
      }
      g_cf2_hash_progress += take;
    }
    *out_bytes_consumed = take;
    if (g_cf2_hash_progress >= kCf2RangeLength) {
      g_cf2_hasher.finish(g_cf2_hash_cache);
      g_boot_info_capture_status = (g_boot_info_capture_bytes_copied >= ::ota::platform::kNrf52BootInfoSize)
                                        ? ::ota::platform::Nrf52BootInfoCaptureStatus::Captured
                                        : ::ota::platform::Nrf52BootInfoCaptureStatus::Unreadable;
      g_boot_config_phase = BootConfigPhase::SdHash;
    }
    return mesh::ota::OtaBaselineMeasurementSubStep::InProgress;
  }
  if (g_boot_config_phase == BootConfigPhase::SdHash) {
    const uint32_t remaining = kSdRangeLength - g_sd_hash_progress;
    const uint32_t take = remaining < max_bytes ? remaining : max_bytes;
    if (take > 0) {
      const uint8_t* raw = reinterpret_cast<const uint8_t*>(kSdRangeStart + g_sd_hash_progress);
      g_sd_hasher.update(raw, take);
      g_sd_hash_progress += take;
    }
    *out_bytes_consumed = take;
    if (g_sd_hash_progress >= kSdRangeLength) {
      g_sd_hasher.finish(g_sd_hash_cache);
      g_boot_config_phase = BootConfigPhase::BlankScan;
    }
    return mesh::ota::OtaBaselineMeasurementSubStep::InProgress;
  }
  if (g_boot_config_phase == BootConfigPhase::BlankScan) {
    if (g_boot_config_blank_scan_progress > kMbrParamsPageLength) {
      g_boot_config_phase = BootConfigPhase::Idle;
      return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
    }
    const uint32_t remaining = kMbrParamsPageLength - g_boot_config_blank_scan_progress;
    const uint32_t take = remaining < max_bytes ? remaining : max_bytes;
    if (take > 0) {
      const uint8_t* raw = reinterpret_cast<const uint8_t*>(kMbrParamsPageStart + g_boot_config_blank_scan_progress);
      for (uint32_t i = 0; i < take; ++i) {
        if (raw[i] != 0xFFu) {
          g_boot_config_blank_scan_ok = false;
          break;
        }
      }
      g_boot_config_blank_scan_progress += take;
    }
    *out_bytes_consumed = take;
    if (g_boot_config_blank_scan_progress >= kMbrParamsPageLength) {
      g_boot_config_phase = BootConfigPhase::Classified;
    }
    return mesh::ota::OtaBaselineMeasurementSubStep::InProgress;
  }
  // BootConfigPhase::Classified: build the real DTO and match it.
  g_boot_config_phase = BootConfigPhase::Idle;
  if (!g_stock_loader_hash_cache_valid) {
    // StockLoader phase did not resolve earlier this job -- a genuine
    // sequencing anomaly, not an absent catalogue.
    return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
  }
  // A non-blank MBR-parameter page is NOT special-cased here: it flows
  // into raw.params_page_blank below and match_boot_catalogue() itself
  // classifies that as Unsupported -- never silently treated as an IO
  // fault or skipped.
  ::ota::platform::Nrf52RawBootMeasurement raw;
  raw.have_measurement = true;
  raw.target_id = kExpectedBoardTargetId;
  raw.profile_id = ::ota::platform::kNrf52BootProfileSenseCap;
  // Real compiled role, never inferred from the live marker or the
  // candidate row -- see this file's SENSECAP_OTA_COMPILED_ROLE_ID fix
  // above and Nrf52RawBootMeasurement::current_role_id's own doc comment.
  raw.current_role_id = kExpectedRoleId;
  memcpy(raw.stock_code_sha256, g_stock_loader_hash_cache, 32);
  memcpy(raw.cf2_sha256, g_cf2_hash_cache, 32);
  memcpy(raw.mbr_sha256, g_mbr_hash_cache, 32);
  memcpy(raw.softdevice_sha256, g_sd_hash_cache, 32);
  raw.mbr_vectors = g_boot_config_mbr_vectors;
  raw.softdevice_vectors = g_boot_config_sd_vectors;
  raw.loader_vectors = g_boot_config_loader_vectors;
  raw.ficr_geometry = g_boot_config_ficr_geometry;
  raw.softdevice_info_magic = g_boot_config_sd_info_magic;
  raw.softdevice_info_size = g_boot_config_sd_info_size;
  raw.softdevice_fwid = g_boot_config_sd_info_fwid;
  raw.softdevice_variant = g_boot_config_sd_info_variant;
  raw.softdevice_version = g_boot_config_sd_info_version;
  memcpy(raw.softdevice_unique_id, g_boot_config_sd_info_unique_id, 20);
  raw.mbr_selectors.bootloader_addr = g_boot_config_mbr_boot;
  raw.mbr_selectors.params_page_addr = g_boot_config_mbr_params;
  raw.params_page_blank = g_boot_config_blank_scan_ok;
  raw.uicr.nrffw0 = g_boot_config_uicr0;
  raw.uicr.nrffw1 = g_boot_config_uicr1;
  raw.boot_info_capture_status = g_boot_info_capture_status;
  memcpy(raw.boot_info, g_boot_info_capture, ::ota::platform::kNrf52BootInfoSize);

#if OTA_HAVE_APPROVED_BOOT_CATALOGUE
  const auto match = ::ota::platform::match_boot_catalogue(
      raw, ::ota::platform::kApprovedBootCatalogueRows, ::ota::platform::kApprovedBootCatalogueRowCount);
#else
  const auto match = ::ota::platform::match_boot_catalogue(raw, nullptr, 0u);
#endif
  switch (match.outcome) {
    case ::ota::platform::BootCatalogueOutcome::Approved:
      out_boot_config_id = match.matched_config_id;
      return mesh::ota::OtaBaselineMeasurementSubStep::Resolved;
    case ::ota::platform::BootCatalogueOutcome::Mismatch:
      out_mismatch = true;
      return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
    case ::ota::platform::BootCatalogueOutcome::IoError:
      return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
    case ::ota::platform::BootCatalogueOutcome::MissingCatalogue:
    case ::ota::platform::BootCatalogueOutcome::Unsupported:
    case ::ota::platform::BootCatalogueOutcome::InvalidCatalogue:
    default:
      out_catalogue_unavailable = true;
      return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
  }
#else
  (void)max_bytes;
  *out_bytes_consumed = 0;
  out_boot_config_id = 0;
  out_catalogue_unavailable = false;  // platform-unsupported, not a catalogue gap.
  out_mismatch = false;
  return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
#endif
}

mesh::ota::OtaBaselineMeasurementSubStep otaBoardBaselineStepQspiStateInspection(uint32_t, uint32_t* out_bytes_consumed) {
  *out_bytes_consumed = 0;
  return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
}

bool otaBoardBaselineGetPlatformEntropy16(uint8_t out[16]) {
#if defined(NRF52840_XXAA)
  // This board's companion firmware links the S140 SoftDevice
  // (nrf52840_s140_v7*.ld) and SerialBLEInterface::begin() (see
  // src/helpers/nrf52/SerialBLEInterface.cpp) genuinely calls
  // Bluefruit.begin(), which enables it at runtime -- at which point the
  // SoftDevice owns the NRF_RNG peripheral (it uses the HW TRNG for its
  // own BLE crypto and forbids concurrent application register access;
  // see NRF52Board.cpp's existing sd_softdevice_is_enabled()-gated
  // pattern, which this follows). Directly commandeering NRF_RNG while
  // the SoftDevice is enabled is unsafe and is NOT this function's
  // fallback path.
  uint8_t sd_enabled = 0;
  sd_softdevice_is_enabled(&sd_enabled);
  if (sd_enabled) {
    // SoftDevice-safe path: pulls from the SD's own maintained entropy
    // pool via the public SVC API, no peripheral register access, no
    // busy-wait -- a single bounded call that either returns the full
    // 16 bytes now or fails immediately (NRF_ERROR_SOC_RAND_NOT_ENOUGH)
    // rather than spinning for the pool to refill.
    return sd_rand_application_vector_get(out, 16) == NRF_SUCCESS;
  }

  // SoftDevice confirmed disabled: the real hardware TRNG, independent
  // of the radio (see NRF52840 Product Spec s.25 RNG), is genuinely
  // ours alone to use. Bias-corrected output, one byte per START/VALRDY
  // cycle. Bounded spin per byte -- a genuinely stuck RNG peripheral
  // fails closed rather than hanging this tick forever.
  NRF_RNG->TASKS_STOP = 1;
  NRF_RNG->CONFIG = (NRF_RNG->CONFIG & ~RNG_CONFIG_DERCEN_Msk) | (RNG_CONFIG_DERCEN_Enabled << RNG_CONFIG_DERCEN_Pos);
  for (int i = 0; i < 16; ++i) {
    NRF_RNG->EVENTS_VALRDY = 0;
    NRF_RNG->TASKS_START = 1;
    uint32_t spins = 0;
    while (NRF_RNG->EVENTS_VALRDY == 0) {
      if (++spins > 1000000u) {
        NRF_RNG->TASKS_STOP = 1;
        return false;
      }
    }
    out[i] = static_cast<uint8_t>(NRF_RNG->VALUE);
  }
  NRF_RNG->TASKS_STOP = 1;
  return true;
#else
  (void)out;
  return false;
#endif
}

// Real arbitration over this board's single QSPI candidate partition,
// shared (via the registry) with any other present-or-future code that
// acquires the same physical identity -- see OtaBoardMediaArbiterGuard's
// doc comment in OtaBoardBackendCommon.h. The physical token is
// `flash.physicalResourceToken()` (see Nrf52QspiPhysicalIdentity.h) --
// the actual QSPI-peripheral + chip-select-GPIO pairing this specific
// `flash` adapter genuinely drives, NOT a board-model literal; a real
// OtaSecurityStore construction for this same adapter MUST derive its
// token from the SAME accessor to ever genuinely arbitrate against this
// guard.
mesh::ota::OtaBoardMediaArbiterGuard g_baseline_media_arbiter_guard(
    flash.physicalResourceToken(), ::ota::platform::SenseCapQspiLayout::kSecurityAOffset,
    ::ota::platform::SenseCapQspiLayout::kSecurityBOffset);

mesh::ota::OtaBaselineMeasurementArbiterResult otaBoardBaselineAcquireMediaArbiter() {
  return g_baseline_media_arbiter_guard.acquire();
}
void otaBoardBaselineReleaseMediaArbiter() { g_baseline_media_arbiter_guard.release(); }

}  // namespace ota
}  // namespace mesh

#endif
