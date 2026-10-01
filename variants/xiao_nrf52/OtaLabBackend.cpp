#include <Arduino.h>
#if defined(NRF52840_XXAA)
#include <nrf_soc.h>  // sd_softdevice_is_enabled / sd_rand_application_vector_get
#endif

#if defined(MESHCORE_OTA_LAB_BACKEND) && MESHCORE_OTA_LAB_BACKEND

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
#include <ota/storage/XiaoOtaLegacyResidue.h>
#include <ota/trust/DescriptorVerifier.h>
#include <ota/trust/MonotonicCounter.h>
#include <ota/trust/Sha256.h>

// The generated approved-row table (produced by Root/Boot from the real
// compiled stock bootloader HEX+ELF via scripts/ota_boot_catalogue.py)
// is now present for the XIAO nRF52840 BLE profile. This header has zero
// link dependency on it either way: on a worktree/board where the file
// is absent (e.g. no row for this target/profile has been generated
// yet), row_count is simply 0 and match_boot_catalogue() correctly
// reports MissingCatalogue -- never a fabricated/placeholder row.
#if __has_include(<ota/platform/Nrf52ApprovedBootCatalogue.h>)
#include <ota/platform/Nrf52ApprovedBootCatalogue.h>
#define OTA_HAVE_APPROVED_BOOT_CATALOGUE 1
#else
#define OTA_HAVE_APPROVED_BOOT_CATALOGUE 0
#endif

namespace {

class LabSignatureVerifier : public ota::trust::SignatureVerifier {
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

// STAGING_ONLY bench-fixture fallback key only: used ONLY when no
// qualified custom bootloader marker is present, so lab hardware without
// the custom bootloader can still exercise the transfer/verification
// pipeline. Once a qualified marker is present, the ACTUAL signer
// pubkey/key_id/algorithm are read from that marker instead (see
// configureCompanionFirmwareOtaBackend() below) -- this constant is never
// used for an INSTALL_CAPABLE decision.
constexpr uint8_t kLabStagingOnlyFallbackPublicKey[32] = {
    0x79, 0xB5, 0x56, 0x2E, 0x8F, 0xE6, 0x54, 0xF9,
    0x40, 0x78, 0xB1, 0x12, 0xE8, 0xA9, 0x8B, 0xA7,
    0x90, 0x1F, 0x85, 0x3A, 0xE6, 0x95, 0xBE, 0xD7,
    0xE0, 0xE3, 0x91, 0x0B, 0xAD, 0x04, 0x96, 0x64,
};
// Fallback (keyId, algorithmId) paired with the fallback public key above:
// algorithmId=1 matches Ed25519 (also pinned by
// resolveOtaBoardBootQualification()'s kExpectedAlgorithmIdEd25519 in
// OtaBoardBackendCommon.h); keyId=1 is this lab fixture's single explicit
// bench key slot. Never used for an INSTALL_CAPABLE decision.
constexpr uint16_t kLabStagingOnlyFallbackKeyId = 1u;
constexpr uint16_t kLabStagingOnlyFallbackAlgorithmId = 1u;

// Must match the boot-side canonical constants exactly (not invented
// here): bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h defines
// XIAO_OTA_TARGET_XIAO_NRF52840 = 0x584E3430 ('XN40'),
// XIAO_OTA_ROLE_ANY = 0, XIAO_OTA_CAP_QSPI_INSTALL = 1.
constexpr uint32_t kExpectedBoardTargetId = 0x584E3430u;
// Single build-time literal, shared in NAME (not in a shared header --
// Boot owns bootloader/** and compiles it independently) with Boot's
// XIAO_OTA_COMPILED_ROLE_ID, restricted to exactly 0 (companion_radio)
// or 1 (simple_repeater): role is a COMPILE-TIME identity, never
// inferred at runtime from a counter, profile, or receipt. platformio.ini
// defines this per build environment (see
// [env:Xiao_nrf52_companion_radio_usb] / [env:Xiao_nrf52_repeater_ota_usb]);
// it is intentionally undefined-by-default here so every OTHER existing
// Xiao_nrf52_* environment (repeater/room_server/kiss_modem builds that
// do not even compile this file's real body) is completely unaffected.
#ifndef XIAO_OTA_COMPILED_ROLE_ID
#define XIAO_OTA_COMPILED_ROLE_ID 0
#endif
static_assert(XIAO_OTA_COMPILED_ROLE_ID == 0 || XIAO_OTA_COMPILED_ROLE_ID == 1,
             "XIAO_OTA_COMPILED_ROLE_ID must be exactly 0 (companion) or 1 (repeater) -- "
             "no other role is defined, and no runtime fallback/inference exists.");
constexpr uint32_t kExpectedRoleId = static_cast<uint32_t>(XIAO_OTA_COMPILED_ROLE_ID);
// The ONE real, physical Nordic bootloader-settings page address -- see
// OtaSdkSettingsCodec.h's header comment: the baseline collector's
// "current SDK settings" measurement and this file's bank-0 extent read
// (otaBoardBaselineReadValidatedBank0Extent, below) are the SAME exact
// 28 live bytes, never two separate schemas.
constexpr uint32_t kBootloaderSettingsAddress = 0x000FF000u;
// Must match bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h's
// XIAO_OTA_DESCRIPTOR_FORMAT (= 1): the canonical descriptor wire-format
// version this whole boot contract is built for. This is a fixed
// protocol-version identifier, not a per-device/per-key value, so it is
// the same in both the qualified and STAGING_ONLY fallback branches
// below -- unlike expected_key_id/expected_algorithm_id, it is never
// sourced from the boot marker itself (XiaoOtaBootInfoReader::Info has
// no format_id field at all).
constexpr uint16_t kExpectedDescriptorFormatId = 1u;
constexpr uint32_t kExpectedCapabilityFlags = 1u;
// Matches otaBoardBaselineReadCompiledProfile()'s own `out_profile_id = 1u`
// literal below (Xiao lab profile) -- kept as one named constant here so
// the role-authority anchor and that collector-seam function can never
// silently drift apart.
constexpr uint32_t kExpectedProfileId = 1u;

ota::platform::Nrf52FlashAdapter flash;
// Real field-use campaigns stage into the full external QSPI candidate
// BANK/staging region (792 KiB physical placement stride/span -- NOT a
// writable capacity figure) -- NOT the 16 KiB candidateTestRegion(),
// which is reserved solely for examples/ota_qspi_hardware_test/main.cpp's
// destructive qualification harness and cannot hold a real application
// image. The actual accepted-descriptor writable ceiling is the
// protocol-wide 708608 bytes (0xAD000 / 692 KiB) from kOtaMaxImageBytes
// (see OtaGeometry.h), not the full 792 KiB bank span: this candidate
// region can physically hold more than any descriptor is currently
// allowed to declare, until MeshCore v1.17+'s InternalExtraFS migration
// (see OtaGeometry.h's kOtaMaxImageBytes comment for the exact rationale).
ota::platform::FlashRegion candidate =
    ota::platform::SenseCapQspiLayout::candidateRegion(flash);
ota::platform::FlashRegion xiao_floor_region =
    ota::platform::SenseCapQspiLayout::xiaoFloorRegion(flash);
ota::platform::FlashRegion xiao_command_region =
    ota::platform::SenseCapQspiLayout::xiaoCommandRegion(flash);
// Full 8-sub-slot journal span (command A/B, state A/B, confirm A/B,
// floor A/B), used ONLY by the lab-only read-only diagnostic and its
// separately-gated floor-A-only erase below -- see
// kJournalLogicalToPhysicalUnit for the wire-facing logical index map.
ota::platform::FlashRegion xiao_journal_full_region =
    ota::platform::SenseCapQspiLayout::xiaoJournalFullRegion(flash);
ota::platform::FlashRegion xiao_state_region = ota::platform::SenseCapQspiLayout::xiaoStateRegion(flash);
ota::platform::FlashRegion xiao_confirm_region = ota::platform::SenseCapQspiLayout::xiaoConfirmRegion(flash);
mesh::ota::OtaBoardFailClosedMonotonicCounter counter(xiao_floor_region);
// Constructed LAZILY, post-flash.begin() and post-qualification (see
// configureCompanionFirmwareOtaBackend() below) -- NEVER as a file-scope
// global object. A global here would be constructed by the C++ runtime
// at static-init time, BEFORE flash.begin() (which only runs inside
// configureCompanionFirmwareOtaBackend(), itself only called from
// setup()) ever executes -- the monitor's eager constructor-time state
// read would then read QSPI flash before the flash driver is ready,
// permanently latching a false/failed read for the rest of this boot.
// While null (not yet constructed), every consumer below fails closed:
// otaBoardTryConfirmHealthyTrialBoot() reports Pending (no health work
// attempted), and otaBoardTrialHealthWindowActive() reports true/active/
// blocking whenever this device is qualified at all -- "unknown" must
// never be silently treated as "not active."
mesh::ota::OtaBoardTrialBootHealthConfirmer* trial_boot_confirmer_ptr = nullptr;


ota::trust::Sha256 hasher;
LabSignatureVerifier signature_verifier;
ota::trust::DeviceTrustAnchor anchor;
uint8_t active_wire_public_key[32] = {0};
uint16_t active_wire_key_id = 0;
uint16_t active_wire_algorithm_id = 0;
ota::trust::DescriptorVerifier* verifier = nullptr;
mesh::ota::OtaFirmwareTrustProvider* trust = nullptr;
meshcore::ota::runtime::IOtaStagingSink* staging = nullptr;
mesh::ota::OtaBoardInstallCommandProviderV2* install_provider_v2 = nullptr;

// Set once by configureCompanionFirmwareOtaBackend() so any caller (e.g.
// a future CLI/status command) can report the real reason install
// capability is or is not available, instead of a success-shaped
// assumption based on board/JEDEC identity or compiled feature flags
// alone.
const char* g_install_capability_reason = "not yet configured";
char g_install_capability_status[64] = {0};

// True ONLY once configureCompanionFirmwareOtaBackend() has observed a
// genuinely qualified boot marker AND a fresh valid bank0 record (see
// bank0.active_image_extent check below) -- i.e. exactly the
// INSTALL_CAPABLE case. Gates otaBoardTryConfirmHealthyTrialBoot() below
// so a stock/unqualified/bank0-invalid device NEVER attempts a trial-
// boot health confirmation (and therefore never touches the confirmation
// flash region) merely because some stale/foreign TRIAL state happens to
// be present -- state phase alone is never sufficient.
bool g_backend_qualified_and_bank0_valid = false;

// True whenever a genuinely qualified custom-bootloader marker is
// present, REGARDLESS of bank0 validity -- distinct from (and strictly
// weaker than) g_backend_qualified_and_bank0_valid above. Health-tick
// eligibility (does otaBoardTryConfirmHealthyTrialBoot() do any work at
// all) and erase-admission blocking (otaBoardTrialHealthWindowActive())
// both depend only on THIS flag: a device with a qualified marker but an
// invalid/unresolved bank0 must still be able to run its trial-boot
// deadline/reboot logic to completion, rather than being stuck in
// permanent inert Pending merely because it also lacks full durable
// install capability.
bool g_qualified = false;

// Points at whichever OtaBoardTrialGuardedStagingSink instance (one of
// the function-local statics below) is currently attached, so the real,
// grounded (not invented) per-tick storage-fault getter below can report
// on it. No staging sink attached at all (e.g. stock/unqualified device
// that never reaches a qualified branch) simply reports false -- there
// is no storage transaction to have faulted.
mesh::ota::OtaBoardTrialGuardedStagingSink* g_active_guarded_staging = nullptr;

}  // namespace

// Exposed so callers (status/CLI reporting) can surface the *actual*
// install-capability determination -- "STAGING_ONLY" is an explicit,
// expected outcome on a stock/unflashed bootloader, never silently
// upgraded to "ready".
const char* otaLabInstallCapabilityReason() { return g_install_capability_reason; }

// Compact (<=63 byte) install-capability status line, suitable for
// embedding directly in the existing OTA status serial frame (<=176 byte
// budget) alongside other fields -- not just an unwired getter.
const char* otaBoardInstallCapabilityStatus() { return g_install_capability_status; }

// See g_active_guarded_staging above.
bool otaBoardStorageIoFaultObserved() {
  return g_active_guarded_staging != nullptr && g_active_guarded_staging->storageIoFaultObserved();
}

// Fixed logical-index-to-physical-sub-slot map for the 8-sector journal
// read API (see MyMesh.cpp's CMD_OTA_LAB subtype-1 wire contract): the
// wire/host-script-facing index numbering is NOT the same as physical
// on-flash sub-slot order within xiao_journal_full_region (which is
// command A/B, state A/B, confirm A/B, floor A/B in that physical order).
//   0=floorA(0x192000)   1=floorB(0x193000)
//   2=commandA(0x18C000) 3=commandB(0x18D000)
//   4=stateA(0x18E000)   5=stateB(0x18F000)
//   6=confirmA(0x190000) 7=confirmB(0x191000)
constexpr uint32_t kJournalLogicalToPhysicalUnit[8] = {6, 7, 0, 1, 2, 3, 4, 5};

// LAB-ONLY, READ-ONLY diagnostic: dumps up to 128 raw bytes from any of
// the 8 fixed logical sub-slots of the bootloader-owned journal partition
// (xiao_journal_full_region, 8 x 4096-byte erase units at
// 0x18C000..0x194000) so a trusted lab host script can inspect exact
// on-flash contents -- e.g. to recognize a known historical contamination
// pattern, confirm both read passes are byte-identical, or refuse to
// proceed with custom-bootloader commissioning if an unrecognized/valid-
// looking floor record or pending transaction is present -- BEFORE any
// destructive step. This never writes anything; it is a plain bounds-
// checked FlashRegion::read().
bool otaLabReadFloorRaw(uint8_t logical_index, uint32_t offset, uint8_t* out, uint32_t len) {
  if (out == nullptr || len == 0 || len > 128) return false;
  if (logical_index > 7) return false;
  const uint32_t erase_unit = xiao_journal_full_region.eraseUnitBytes();
  if (offset > erase_unit || len > (erase_unit - offset)) return false;  // overflow-safe bounds check

  const uint32_t slot_offset = kJournalLogicalToPhysicalUnit[logical_index] * erase_unit;
  return ota::platform::isOk(xiao_journal_full_region.read(slot_offset + offset, out, len));
}

// LAB-ONLY, gated destructive diagnostic: erases EXACTLY the floor A
// erase-unit (4096 bytes, logical index 0, absolute 0x192000) and nothing
// else -- never floor B, never any other sub-slot, never the
// candidate/backup/filesystem regions (FlashRegion::eraseSector() is
// bounds-checked to a single sector of THIS region). Requires the caller
// to present the exact confirm token below (never guessable/triggered by
// routine probing), AND, independent of the token, this function
// re-reads and re-verifies server-side that floor A matches the EXACT
// known 37-byte contamination residue pattern with all other bytes
// blank, AND that floor B plus all six transaction sectors (install
// command A/B, install state A/B, confirmation A/B) are entirely blank
// -- see ota::storage::XiaoOtaLegacyResidue::isSafeToEraseFloorA(). Any
// valid floor record, unknown content, or pending transaction anywhere in
// the journal refuses the erase; nothing is mutated. Returns false (and
// erases nothing) if the token doesn't match, the safety gate refuses, or
// the erase itself fails.
bool otaLabEraseFloorASector(uint32_t confirm_token) {
  constexpr uint32_t kFloorAEraseConfirmToken = 0x464C4145u;  // "FLAE", not a wire-format value
  if (confirm_token != kFloorAEraseConfirmToken) return false;

  const uint32_t erase_unit = xiao_journal_full_region.eraseUnitBytes();
  if (erase_unit != 4096) return false;  // defensive: unexpected geometry, refuse.

  // Stream the whole-journal purity check through a small fixed 128-byte
  // window instead of materializing all 8 sectors (32KiB) on the stack at
  // once -- logical index 0 (floor A) is checked against the exact known
  // residue pattern window-by-window; every other logical index (floor B
  // plus all six transaction sectors) must be entirely blank, also
  // checked window-by-window. Any read failure or mismatch aborts
  // immediately without erasing anything.
  constexpr uint32_t kWindowBytes = 128;
  uint8_t window[kWindowBytes];
  for (uint32_t logical_index = 0; logical_index <= 7; ++logical_index) {
    const uint32_t slot_offset = kJournalLogicalToPhysicalUnit[logical_index] * erase_unit;
    for (uint32_t offset = 0; offset < erase_unit; offset += kWindowBytes) {
      if (!ota::platform::isOk(xiao_journal_full_region.read(slot_offset + offset, window, kWindowBytes))) {
        return false;
      }
      const bool ok = (logical_index == 0)
                          ? ota::storage::XiaoOtaLegacyResidue::isKnownContaminationResidueWindow(
                                offset, window, kWindowBytes)
                          : ota::storage::XiaoOtaLegacyResidue::isEntirelyBlank(window, kWindowBytes);
      if (!ok) return false;
    }
  }

  return ota::platform::isOk(
      xiao_journal_full_region.eraseSector(kJournalLogicalToPhysicalUnit[0] * erase_unit));
}


// Real trial-boot health confirmation entry point (see file header for
// XiaoOtaTrialBootConfirmation's gate) -- called every loop() tick by
// MyMesh with genuine radio/filesystem/loop-liveness signals gathered
// from the actual app (never placeholder `true` constants); see
// OtaBoardTrialBootHealthConfirmer for the one-shot-success latch that
// prevents repeated flash writes once confirmed.
// LAB-ONLY health-confirmation entrypoint: inert (returns false, writes
// nothing) unless configureCompanionFirmwareOtaBackend() already
// observed a genuinely qualified boot marker AND a fresh valid bank0
// record -- a stock/unflashed/mismatched bootloader, or one whose bank0
// is invalid/unresolved, must never durably confirm a trial boot, no
// matter what a (possibly stale/foreign) TRIAL-phase state record says.
mesh::ota::OtaBoardTrialHealthOutcome otaBoardTryConfirmHealthyTrialBoot(uint32_t now_ms, bool radio_ready,
                                                                        bool filesystem_ready, bool loop_healthy) {
  if (!g_qualified) return mesh::ota::OtaBoardTrialHealthOutcome::Pending;  // no bootloader trial concept on this device.
  if (trial_boot_confirmer_ptr == nullptr) return mesh::ota::OtaBoardTrialHealthOutcome::Pending;  // not yet constructed.
  return trial_boot_confirmer_ptr->tick(now_ms, radio_ready, filesystem_ready, loop_healthy);
}

// True whenever this device is qualified AND (the confirmer is not yet
// constructed -- fail closed: "unknown" blocks -- OR a genuine trial-boot
// health window is in progress/unresolved). Callers (see
// resolveOtaBoardInstallGate() call sites below, the erase-admission
// decorator, and MyMesh::hasPendingWork()) use this to refuse a
// competing install/erase and suppress deep sleep. Deliberately gated on
// `g_qualified` alone (NOT g_backend_qualified_and_bank0_valid): a stock/
// unqualified device has no bootloader-tracked trial concept at all and
// must never have its ordinary staging blocked by this predicate.
bool otaBoardTrialHealthWindowActive() {
  if (!g_qualified) return false;
  if (trial_boot_confirmer_ptr == nullptr) return true;  // qualified but unknown -> fail closed (block).
  return trial_boot_confirmer_ptr->isTrialActive();
}

// Genuine earliest-boot-phase preflight -- see MyMesh.cpp's weak-default
// doc comment. Deliberately does ONLY qualification + (if qualified)
// construct-if-null-then-read the state/confirm regions -- the SAME
// cheap, side-effect-bounded work configureCompanionFirmwareOtaBackend()
// performs before EVER reaching bank0 resolution below -- and stops
// there, never proceeding into XiaoOtaActiveExtentBridge::resolveCurrent()
// (a full whole-image SHA-256). `g_qualified`/`trial_boot_confirmer_ptr`
// are shared statics: configureCompanionFirmwareOtaBackend() (called
// later, from MyMesh::begin()) reuses whatever this already established
// rather than redoing it, so calling both this boot costs nothing extra
// beyond this function's own (idempotent, already-cheap) work.
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
    // boot_epoch_ms=0 -- see the identical rationale in
    // configureCompanionFirmwareOtaBackend() below (genuine
    // application-boot origin, not whichever moment this runs at).
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
// (never a second, independently-written FICR read).
namespace mesh {
namespace ota {
bool otaBoardBaselineReadUid8(uint8_t out_uid8[8]);
}  // namespace ota
}  // namespace mesh

bool configureCompanionFirmwareOtaBackend(mesh::ota::OtaFirmwareIntegration& integration) {
  // Reset on every (re)configure attempt: the only place this is ever set
  // true again is the single fully-qualified INSTALL_CAPABLE branch below,
  // so a re-run that no longer reaches it (e.g. floor became unreadable)
  // must not leave a stale `true` from a prior call.
  g_backend_qualified_and_bank0_valid = false;
  g_qualified = false;
  if (!ota::platform::SenseCapQspiLayout::isValid() ||
      !ota::platform::isOk(flash.begin())) {
    g_install_capability_reason = "STAGING_ONLY: QSPI flash unavailable";
    mesh::ota::formatOtaBoardCapabilityStatus(g_install_capability_status, sizeof(g_install_capability_status),
                                              g_install_capability_reason);
    return false;
  }
  const uint8_t* jedec_id = flash.jedecId();
  if (jedec_id[0] != 0x85 || jedec_id[1] != 0x60 || jedec_id[2] != 0x15) {
    g_install_capability_reason = "STAGING_ONLY: unrecognized QSPI flash JEDEC id";
    mesh::ota::formatOtaBoardCapabilityStatus(g_install_capability_status, sizeof(g_install_capability_status),
                                              g_install_capability_reason);
    return false;
  }
  // Fail-closed capability detection happens first: only a struct that
  // passes XiaoOtaBootInfoReader's magic/format/CRC validation is trusted
  // at all, and even then, only when its board_target_id/role/capability/
  // algorithm genuinely match this build's expectations -- never board/
  // JEDEC identity or a compiled flag alone. All-0xFF (stock/unmodified
  // Adafruit bootloader) is the expected, common, non-error case here,
  // not corruption. The qualification result determines WHICH key is
  // trusted below: a qualified marker's own trusted_public_key is the
  // real signer identity; only in the unqualified case does this lab
  // backend fall back to a hardcoded STAGING_ONLY bench-fixture key.
  const mesh::ota::OtaBoardBootQualification qualification = mesh::ota::resolveOtaBoardBootQualification(
      kExpectedBoardTargetId, kExpectedRoleId, kExpectedCapabilityFlags);

  if (qualification.qualified) {
    std::memcpy(active_wire_public_key, qualification.info.trustedPublicKey, sizeof(active_wire_public_key));
    active_wire_key_id = qualification.info.keyId;
    active_wire_algorithm_id = qualification.info.algorithmId;
  } else {
    std::memcpy(active_wire_public_key, kLabStagingOnlyFallbackPublicKey, sizeof(active_wire_public_key));
    active_wire_key_id = kLabStagingOnlyFallbackKeyId;
    active_wire_algorithm_id = kLabStagingOnlyFallbackAlgorithmId;
  }
  std::memcpy(anchor.trusted_signer_public_key_ed25519, active_wire_public_key,
              sizeof(anchor.trusted_signer_public_key_ed25519));
  // xiao_ota_boot.c rejects any descriptor whose target/role don't match
  // exactly or whose required_boot_capability_flags aren't a subset of
  // supported_boot_capability_flags. This lab target's custom bootloader
  // does support QSPI install, so capability flags declare that bit here
  // -- this reflects the protocol-level capability this firmware image is
  // built for, independent of whether THIS PARTICULAR flashed device
  // currently has a qualified custom bootloader installed.
  //
  // Bind the ACTUAL signer key/algorithm identity (from the qualified
  // marker, or the explicit lab fallback) as trusted policy: a descriptor
  // tagged with any other keyId/algorithmId must be rejected before any
  // flash write, even if some other compiled-in key would still verify
  // its signature bytes. Uses the shared helper (not inline field
  // assignment) so all six DeviceTrustAnchor identity fields -- including
  // expected_format_id -- are always populated together; see
  // OtaBoardBackendCommon.h's comment for why that field specifically
  // must never be left at its zero default.
  mesh::ota::configureOtaTrustAnchorIdentity(anchor, kExpectedBoardTargetId, kExpectedRoleId,
                                             kExpectedCapabilityFlags, kExpectedDescriptorFormatId,
                                             active_wire_key_id, active_wire_algorithm_id);

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

  static ota::trust::DescriptorVerifier lab_verifier(
      hasher, signature_verifier, counter, anchor);
  static mesh::ota::OtaFirmwareTrustProvider lab_trust(
      lab_verifier, candidate, signature_verifier, active_wire_public_key,
      active_wire_key_id, active_wire_algorithm_id);
  verifier = &lab_verifier;
  trust = &lab_trust;

  if (qualification.qualified) {
    g_qualified = true;
    // Construct the confirmer NOW -- lazily, exactly once (static local),
    // right after qualification is known and flash.begin() has already
    // succeeded above -- passing the genuine current boot-time clock as
    // this monitor's deadline-arming epoch. This is the earliest point at
    // which reading QSPI state is actually safe, closing the previous
    // global-static-before-flash.begin() hazard; `static` guarantees this
    // runs only once even if configureCompanionFirmwareOtaBackend() were
    // ever invoked again, preserving this boot's already-armed deadline/
    // tick progress rather than resetting it.
    if (trial_boot_confirmer_ptr == nullptr) {
      // boot_epoch_ms=0, NOT millis() read here: Arduino's millis() is
      // already relative to actual power-on/reset (the genuine
      // application boot origin), not to whatever moment this
      // configure function happens to run at. Passing a fresh millis()
      // reading taken here -- AFTER Serial.begin()/board.begin()/
      // radio_init()/InternalFS+QSPIFlash.begin()/etc. have already run
      // in main.cpp's setup() -- would silently grant the 45s deadline
      // extra budget equal to however long that earlier setup() work
      // took (worse on a slow boot), which is exactly the "deadline
      // starts too late" hazard this must close. 0 is both the correct
      // genuine epoch AND still safe against a hypothetical re-entrant
      // call (the `static` local below only ever constructs once).
      static mesh::ota::OtaBoardTrialBootHealthConfirmer real_confirmer(xiao_state_region, xiao_confirm_region,
                                                                        0u);
      trial_boot_confirmer_ptr = &real_confirmer;
    }

    if (trial_boot_confirmer_ptr->isTrialActive()) {
      // A genuine trial-boot health window is still in progress (or its
      // outcome hasn't yet survived a reboot): do NOT perform the
      // blocking, whole-image bank0 CRC+SHA resolution during THIS boot
      // at all -- that would block setup() for as long as it takes to
      // CRC+SHA the whole running image, defeating the entire purpose of
      // the bounded per-tick health monitor ticked from loop() below.
      // Bank0 resolution (and therefore full INSTALL_CAPABLE status) is
      // deferred to a later boot once no longer in a live trial; a new
      // install command cannot be built either way while trial-active
      // (see setTrialActivePredicate() below), so this costs nothing
      // functionally this boot beyond staying STAGING_ONLY.
      static mesh::ota::OtaFirmwareStorageSink lab_staging(candidate);
      static mesh::ota::OtaBoardTrialGuardedStagingSink guarded_staging(lab_staging,
                                                                        &otaBoardTrialHealthWindowActive);
      staging = &guarded_staging;
      g_active_guarded_staging = &guarded_staging;
      g_install_capability_reason =
          "STAGING_ONLY: trial-boot health confirmation in progress, bank0 resolution deferred";
    } else {
    // A qualified custom bootloader marker alone is not sufficient: this
    // build must also be running from a genuinely valid, freshly
    // resolved bank-0 record (BANK_VALID_APP + matching CRC/size) --
    // otherwise a durable install command would bind a bogus/zero
    // extent. Diagnose and report the actual reason rather than silently
    // downgrading without explanation.
    const ::ota::storage::XiaoOtaActiveExtentInfo bank0 = ::ota::storage::XiaoOtaActiveExtentBridge::resolveCurrent();
    if (bank0.active_image_extent == 0) {
      static mesh::ota::OtaFirmwareStorageSink lab_staging(candidate);
      static mesh::ota::OtaBoardTrialGuardedStagingSink guarded_staging(lab_staging,
                                                                        &otaBoardTrialHealthWindowActive);
      staging = &guarded_staging;
      g_active_guarded_staging = &guarded_staging;
      g_install_capability_reason = "STAGING_ONLY: qualified boot marker but bank0 invalid or unresolved";
    } else {
      // A qualified marker and a valid bank0 are still not sufficient: the
      // bootloader-owned confirmed-counter floor (xiao_floor_region) must
      // also be genuinely readable -- either a valid record, or both
      // slots legitimately blank (0xFF, a real first-ever-device
      // baseline of 0) -- before this build ever attaches a durable
      // install-command provider or lets otaBoardTryConfirmHealthyTrialBoot()
      // act. A corrupt/tampered/unreadable floor must disable install
      // capability with an explicit diagnosed reason, never silently
      // default to floor==0 or proceed regardless. The stock/no-marker
      // staging-only path above (and the raw diagnostic reader) remain
      // available either way -- this only gates the durable command/
      // confirmation path. Shared, natively-testable predicate (see
      // OtaBoardBackendCommon.h) rather than duplicated inline logic.
      const mesh::ota::OtaBoardInstallGateResult gate =
          mesh::ota::resolveOtaBoardInstallGate(qualification.qualified, bank0.active_image_extent, counter);
      if (!gate.install_capable) {
        static mesh::ota::OtaFirmwareStorageSink lab_staging(candidate);
        static mesh::ota::OtaBoardTrialGuardedStagingSink guarded_staging(lab_staging,
                                                                          &otaBoardTrialHealthWindowActive);
        staging = &guarded_staging;
        g_active_guarded_staging = &guarded_staging;
        g_install_capability_reason =
            "STAGING_ONLY: qualified boot marker and valid bank0 but floor counter unreadable or corrupt";
      } else {
        static mesh::ota::OtaBoardInstallCommandProviderV2 lab_install_provider_v2;
        lab_install_provider_v2.setTrialActivePredicate(&otaBoardTrialHealthWindowActive);
        static mesh::ota::OtaFirmwareStorageSink lab_staging(candidate, &xiao_command_region,
                                                             &lab_install_provider_v2);
        // Even the durable INSTALL_CAPABLE sink must refuse a NEW
        // beginSession() (erase/stage a fresh incoming campaign) while a
        // PRIOR install's trial-boot confirmation is still active/
        // unresolved -- setTrialActivePredicate() above only ever gated
        // BUILDING a new install command, never the storage sink's own
        // erase-on-beginSession() admission.
        static mesh::ota::OtaBoardTrialGuardedStagingSink guarded_staging(lab_staging,
                                                                          &otaBoardTrialHealthWindowActive);
        staging = &guarded_staging;
        g_active_guarded_staging = &guarded_staging;
        install_provider_v2 = &lab_install_provider_v2;
        g_install_capability_reason = "INSTALL_CAPABLE: qualified custom bootloader detected (command v2)";
        g_backend_qualified_and_bank0_valid = true;
      }
    }
    }
  } else {
    // Stock/unflashed/mismatched bootloader: stage and fully exercise the
    // transfer/verification pipeline (chunk write, SHA-256, receipts) so
    // lab hardware without the custom bootloader can still be tested
    // safely, but never durably hand off an install command -- there is
    // no qualified bootloader to act on it. Only the lab backend keeps
    // this bench-fixture fallback attached; SenseCAP production has none.
    static mesh::ota::OtaFirmwareStorageSink lab_staging(candidate);
    staging = &lab_staging;
    g_install_capability_reason = "STAGING_ONLY: no qualified custom boot detected";
  }
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
  // Canonical BE8: UID = (DEVICEID[1] << 32) | DEVICEID[0] (cross-owner
  // agreed convention -- see OtaBaselineCertificationEvidence.h).
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
  out_profile_id = 1u;  // 1 == Xiao lab profile (see collector seam doc).
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
  // Never a fabricated/synthesized record: a genuine change to ANY of
  // these 28 bytes (bank state, CRC, size, or any reserved/padding word)
  // must be observable by re-reading, which copying the real bytes
  // (rather than reconstructing them from unrelated constants) actually
  // guarantees.
  const uint8_t* raw = reinterpret_cast<const uint8_t*>(kBootloaderSettingsAddress);
  memcpy(out_raw28, raw, mesh::ota::kOtaCurrentSdkSettingsRecordBytes);
  return true;
#else
  (void)out_raw28;
  return false;
#endif
}

namespace {
// Reset on every readValidatedBank0Extent() call (i.e. at the start of
// each job's Extent phase, and harmlessly again at Recheck -- see
// OtaBaselineMeasurementCollector.h's Phase::Extent/Phase::Recheck),
// giving each job's ImageHash phase a fresh, correctly-scoped resolver
// instance rather than one latched across the whole boot.
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
// Cached result of the SAME hash above, captured once Resolved, purely so
// the BootConfig catalogue-matching phase (which runs AFTER StockLoader
// in the same job) can reuse it without a second live hash pass over the
// identical bytes.
uint8_t g_stock_loader_hash_cache[32] = {0};
bool g_stock_loader_hash_cache_valid = false;

// Real, concrete nRF52BootCatalogue DTO (src/ota/platform/
// Nrf52BootCatalogue.h) fixed-geometry addresses, used directly rather
// than re-declared here. The MBR's own two upgrade-forward-pointer
// words live at the ABSOLUTE addresses 0xFF8/0xFFC -- the LAST two
// words of the real system MBR's own first page [0, 0x1000) (see
// kMbrBodyRangeLength below: MBR body ends exactly at 0xFF8) -- and are
// a SEPARATE structure entirely from the independent bootloader MBR-
// PARAMETER PAGE at 0xFE000 (whose own all-0xFF blank-scan is read via
// kMbrParamsPageStart/Length further below, unrelated to these two
// words). Confirmed against the real pinned nrf_mbr.h
// (MBR_BOOTLOADER_ADDR=0xFF8, MBR_PARAM_PAGE_ADDR=0xFFC, both literal
// absolute addresses, not page-relative offsets) -- an earlier revision
// of this code incorrectly treated them as relative to 0xFE000
// (0xFEFF8/0xFEFFC), which was a genuine bug corrected here per MAIN's
// direct header-evidence review.
constexpr uint32_t kMbrParamsPageStart = ::ota::platform::kNrf52BootMbrParamPageOffset;   // 0xFE000
constexpr uint32_t kMbrParamsPageLength = ::ota::platform::kNrf52BootMbrParamPageSize;    // 0x1000
constexpr uint32_t kMbrBootForwardAddr = 0x00000FF8u;
constexpr uint32_t kMbrParamsPageAddrWord = 0x00000FFCu;
constexpr uint32_t kUicrNrffw0Addr = 0x10001014u;
constexpr uint32_t kUicrNrffw1Addr = 0x10001018u;

// Public pinned reference ranges (within the INTERNAL flash addresses
// they are actually loaded at, matching the MBR/S140 HEX load addresses
// exactly): MBR body [0, 0xFF8), SoftDevice [0x1000, 0x27000), CF2 board
// config [0xFD800, 0xFE000), stock loader code (kStockLoaderRangeStart
// above, reused -- same region, same hash).
constexpr uint32_t kMbrBodyRangeStart = 0u;
constexpr uint32_t kMbrBodyRangeLength = ::ota::platform::kNrf52MbrBodyRangeEnd;  // 0xFF8
constexpr uint32_t kCf2RangeStart = ::ota::platform::kNrf52BootCf2Offset;         // 0xFD800
constexpr uint32_t kCf2RangeLength = ::ota::platform::kNrf52BootCf2Size;          // 0x800
constexpr uint32_t kSdRangeStart = ::ota::platform::kNrf52SoftDeviceRangeStart;   // 0x1000
constexpr uint32_t kSdRangeLength =
    ::ota::platform::kNrf52SoftDeviceRangeEnd - ::ota::platform::kNrf52SoftDeviceRangeStart;  // 0x26000

// Cortex-M4 vector-table bases (first two words = MSP, Reset) for each
// of the three images this catalogue cares about.
constexpr uint32_t kMbrVectorBase = kMbrBodyRangeStart;      // 0x0
constexpr uint32_t kSdVectorBase = kSdRangeStart;            // 0x1000
constexpr uint32_t kLoaderVectorBase = kStockLoaderRangeStart;  // 0xF4000

// FICR geometry registers (CODEPAGESIZE/CODESIZE), real fixed nRF52840
// peripheral addresses -- always readable, no SoftDevice contention.
constexpr uint32_t kFicrCodePageSizeAddr = 0x10000010u;
constexpr uint32_t kFicrCodeSizeAddr = 0x10000014u;

// SoftDevice info-struct fixed absolute addresses (public S140 7.3.0
// layout, pinned by the catalogue-producer agent's live HEX decode).
constexpr uint32_t kSdInfoMagicAddr = 0x00003004u;
constexpr uint32_t kSdInfoSizeAddr = 0x00003008u;
constexpr uint32_t kSdInfoFwidAddr = 0x0000300Cu;
constexpr uint32_t kSdInfoVariantAddr = 0x00003010u;
constexpr uint32_t kSdInfoVersionAddr = 0x00003014u;
constexpr uint32_t kSdInfoUniqueIdAddr = 0x00003018u;

enum class BootConfigPhase : uint8_t {
  Idle,
  ReadFieldsAndVectors,  // MBR/UICR selector words + 3 vector pairs + FICR + SD info struct (all cheap, one call).
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
// The 60-byte boot_info marker lives inside the SAME CF2 range being
// hashed above (kNrf52BootInfoOffset - kCf2RangeStart == 0x400, well
// within [0, kCf2RangeLength)). Rather than a second separate read pass,
// these bytes are captured opportunistically as the existing Cf2Hash
// phase streams through -- each call's [progress, progress+take) window
// is intersected with the marker's fixed byte range and any overlap is
// copied into g_boot_info_capture. Status starts Unreadable (fail
// closed) and only becomes Captured once the FULL 60-byte window has
// actually been copied; a job that never reaches/completes the Cf2Hash
// phase (e.g. StockLoader never resolved) must never leave a stale
// Captured status from an earlier job.
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
  // Arm the BootConfig phase's resumable selector-read/catalogue-hash/
  // blank-scan for this SAME job -- Phase::StockLoader always runs
  // immediately before Phase::BootConfig within one collector job (see
  // same reset-point rationale as g_stock_loader_* above).
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

// Stock-loader executable-range hashing is now real and bounded: the
// (start,length) is Boot's structurally-confirmed, linker-fixed
// bootloader CODE region (kStockLoaderRangeStart/Length above), and the
// bytes are read live from internal flash and SHA-256'd incrementally,
// at most `max_bytes` per call, across as many resumed calls as needed
// -- never a whole-region blocking hash. This step only CAPTURES the
// live hash into evidence; it does NOT compare against any "approved"
// value itself (matching the SDK28/image-hash phases' same capture-only
// contract). That comparison is NOT simply "Authority's manifest has a
// stockLoaderArtifactSha256 field, therefore any live-copied hash is
// approved" -- Root has explicitly rejected that shortcut: an unknown,
// arbitrary hash cannot become "approved" merely because an operator
// copied it from a live device. Authority's manifest is a carrier field,
// not a catalogue PRODUCER; the real approval requires known artifact
// provenance bytes matching an approved range/config from a genuine
// catalogue, whose source/producer is still Root's design to pin (next
// step, out of this backend's scope). Boot-config selection is a
// SEPARATE evidence phase, NOT the same thing as this stock-loader
// hash: Root has explicitly rejected treating Boot's internal
// `read_pair()` QSPI-journal-record survivor pick (COMMAND/STATE/
// CONFIRM/FLOOR A/B pairs) as "boot config ID" -- those four pairs
// describe journal RECORD selection, not the live MBR/UICR boot-
// selection/config policy this field actually needs. That phase (see
// otaBoardBaselineStepBootConfigSelection() below) now does real
// bounded MBR/UICR selector reads + an MBR-parameter-page blank-scan
// and classifies the tuple against Root/Astra-pinned POLICY shapes, but
// still always resolves Failed: a real authorized boot_config_id
// requires the full catalogue row match (including the stock-loader
// hash above matched against an approved value), which Root has not
// supplied/frozen yet. QSPI-state inspection likewise has no real
// budget-bounded implementation wired yet, and must stay a separate,
// distinctly-typed inspection (not conflated with boot-config-id or
// SDK-bank-number).
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
// measurement + matching pipeline from the catalogue-producer agent's
// concrete DTO (src/ota/platform/Nrf52BootCatalogue.h): MBR/UICR
// selector words, 3 vector-table pairs (MBR/SoftDevice/loader), FICR
// geometry, the SoftDevice info struct, a full incremental blank-scan
// of the MBR-parameter page, and 3 resumable SHA-256 hashes (MBR body,
// CF2 block, SoftDevice range) -- the stock-loader-code hash is reused
// from the StockLoader phase that already ran earlier THIS SAME job
// (g_stock_loader_hash_cache), never recomputed. All of this is real
// evidence, gathered at most `max_bytes` per call, never a whole-region
// blocking operation.
//
// The resulting `Nrf52RawBootMeasurement` is handed to
// `ota::platform::match_boot_catalogue()` against whichever approved
// rows are compiled in (zero rows -- MissingCatalogue -- on any
// worktree/board lacking a generated Nrf52ApprovedBootCatalogue.h row
// for this target/profile; see the OTA_HAVE_APPROVED_BOOT_CATALOGUE
// guard above). Only a complete,
// EXACT row match (Approved) ever yields a real out_boot_config_id;
// Mismatch/Unsupported/MissingCatalogue all resolve Failed with the
// precise typed signal the collector needs (out_catalogue_unavailable /
// out_mismatch) so none of these three is ever confused with another.
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
    // All cheap, fixed-size reads -- always fits within one call's
    // budget (kMaxBytesPerPublicStep is 1024).
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
      // Opportunistic boot_info capture: intersect this call's
      // [g_cf2_hash_progress, g_cf2_hash_progress+take) window against
      // the fixed [kBootInfoCaptureStart, +kNrf52BootInfoSize) marker
      // range within the SAME bytes already being hashed above -- no
      // second read, no extra budget consumed.
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
    // sequencing anomaly (should never happen given the fixed job
    // ordering), not an absent catalogue.
    return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
  }
  ::ota::platform::Nrf52RawBootMeasurement raw;
  raw.have_measurement = true;
  raw.target_id = kExpectedBoardTargetId;
  // MAIN's correction: a row existing for this target_id alone is not
  // proof of the CURRENT compiled profile -- match_boot_catalogue()
  // requires BOTH target_id AND profile_id to match (see
  // Nrf52BootCatalogue.h's own doc comment on this). raw.profile_id was
  // previously left at its default-initialized 0, meaning this real
  // XIAO device could never reach Approved against the genuine row
  // (profile_id=1) -- a real functional bug, fixed here using the
  // producer's own named profile constant rather than a duplicated
  // local literal.
  raw.profile_id = ::ota::platform::kNrf52BootProfileXiao;
  // Real compiled role, never inferred from the live marker or the
  // candidate row -- see Nrf52RawBootMeasurement::current_role_id's own
  // doc comment on why this must be the build's own hook value.
  raw.current_role_id = kExpectedRoleId;
  raw.boot_info_capture_status = g_boot_info_capture_status;
  memcpy(raw.boot_info, g_boot_info_capture, ::ota::platform::kNrf52BootInfoSize);
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
      // A row for this target exists but genuinely differs -- a real,
      // security-relevant divergence from the approved baseline, never
      // conflated with a merely-absent catalogue.
      out_mismatch = true;
      return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
    case ::ota::platform::BootCatalogueOutcome::IoError:
      // Defensive only: `raw.have_measurement` is always true by this
      // point in this backend's flow.
      return mesh::ota::OtaBaselineMeasurementSubStep::Failed;
    case ::ota::platform::BootCatalogueOutcome::MissingCatalogue:
    case ::ota::platform::BootCatalogueOutcome::Unsupported:
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

// Real media arbiter is Store's RAM physical-token lease (not yet
// coordinated/available here -- see write_agent coordination with Store
// 3a17179e-ecab-4804-90ca-5ad922ed6b3b): fails closed as Unavailable
// (genuine configuration gap, not transient contention) rather than
// access QSPI uncoordinated.
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
