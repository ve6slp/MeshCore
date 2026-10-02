#include <Arduino.h>
#if defined(NRF52840_XXAA)
#include <nrf_soc.h>  // sd_softdevice_is_enabled / sd_rand_application_vector_get
#endif

#if defined(MESHCORE_OTA_LAB_BACKEND) && MESHCORE_OTA_LAB_BACKEND

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
#include <ota/storage/XiaoOtaLegacyResidue.h>
#include <ota/trust/DescriptorVerifier.h>
#include <ota/trust/MonotonicCounter.h>
#include <ota/trust/Sha256.h>
#include <target.h>

extern RADIO_CLASS radio;
bool otaBoardApplyRfProfile(float frequency, float bandwidth, uint8_t sf, uint8_t cr) {
  return mesh::ota::applyCheckedOtaRadioProfile(radio, radio_driver, frequency, bandwidth, sf, cr);
}

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
// OtaSdkSettingsCodec.h's header comment: these are the SAME exact 28
// live bytes read by the bank-0 extent probe below, never two separate
// schemas.
constexpr uint32_t kBootloaderSettingsAddress = 0x000FF000u;
// Must match bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h's
// XIAO_OTA_DESCRIPTOR_FORMAT (= 1): the canonical descriptor wire-format
// version this whole boot contract is built for. This is a fixed
// protocol-version identifier, not a per-device/per-key value, so it is
// the same for every manifest, including cache-only uploads --
// unlike expected_key_id/expected_algorithm_id, it is never
// sourced from the boot marker itself (XiaoOtaBootInfoReader::Info has
// no format_id field at all).
constexpr uint16_t kExpectedDescriptorFormatId = 1u;
constexpr uint32_t kExpectedCapabilityFlags = 1u;
// Xiao lab profile identifier, kept as one named constant so the
// role-authority anchor cannot silently drift.
constexpr uint32_t kExpectedProfileId = 1u;

ota::platform::Nrf52FlashAdapter flash;
// Real field-use campaigns stage into the full external QSPI candidate
// BANK/staging region (792 KiB physical placement stride/span -- NOT a
// writable capacity figure) -- NOT the 16 KiB candidateTestRegion(),
// which is reserved solely for examples/ota_qspi_hardware_test/main.cpp's
// destructive qualification harness and cannot hold a real application
// image. Receiver admission has a fixed 708608-byte application ceiling
// (0xAD000 / 692 KiB), enforced by OtaNrf52FirmwareTrustProvider to protect
// InternalExtraFS. A non-installable local uploader cache instead uses the
// physical candidate region and generic bitmap capacity bounds.
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
ota::platform::FlashRegion candidate_record_scratch_region =
    ota::platform::SenseCapQspiLayout::candidateRecordScratchRegion(flash);
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
mesh::ota::OtaBoardInstallCommandProviderV3* install_provider_v3 = nullptr;

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
// eligibility depends on THIS flag: a device with a qualified marker but an
// invalid/unresolved bank0 must still be able to run its trial-boot
// deadline/reboot logic to completion, rather than being stuck in
// permanent inert Pending merely because it also lacks full durable
// install capability.
bool g_qualified = false;
mesh::ota::OtaBoardStockBootPreflight::Result g_stock_boot_result =
    mesh::ota::OtaBoardStockBootPreflight::Result::NotStock;
bool stockBootOrdinaryWritesAllowed(const mesh::ota::OtaBoardBootQualification& qualification) {
  mesh::ota::OtaBoardNrf52RunningContext running;
  g_stock_boot_result = mesh::ota::OtaBoardStockBootPreflight::check(
      qualification, running, xiao_journal_full_region, candidate_record_scratch_region, signature_verifier);
  return g_stock_boot_result == mesh::ota::OtaBoardStockBootPreflight::Result::Healthy;
}
mesh::ota::OtaBoardBootLifecycleObserver& bootLifecycleObserver() {
  static mesh::ota::OtaBoardBootLifecycleObserver observer(xiao_state_region, xiao_floor_region);
  return observer;
}

// Points at whichever OtaBoardTrialGuardedStagingSink instance (one of
// the function-local statics below) is currently attached, so the real,
// grounded (not invented) per-tick storage-fault getter below can report
// on it. A cache-only backend has no trial-confirmation transaction.
mesh::ota::OtaBoardTrialGuardedStagingSink* g_active_guarded_staging = nullptr;

}  // namespace

// Exposed so callers (status/CLI reporting) can surface the *actual*
// install-capability determination -- "CACHE_ONLY" is an explicit,
// expected outcome on a stock/unflashed bootloader, never install authority.
const char* otaLabInstallCapabilityReason() { return g_install_capability_reason; }

// Compact (<=63 byte) install-capability status line, suitable for
// embedding directly in the existing OTA status serial frame (<=176 byte
// budget) alongside other fields -- not just an unwired getter.
const char* otaBoardInstallCapabilityStatus() { return g_install_capability_status; }
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
  bootLifecycleObserver().tick(g_qualified);
  if (trial_boot_confirmer_ptr == nullptr) return mesh::ota::OtaBoardTrialHealthOutcome::Pending;  // not yet constructed.
  return trial_boot_confirmer_ptr->tick(now_ms, radio_ready, filesystem_ready, loop_healthy);
}

// True whenever this device is qualified AND (the confirmer is not yet
// constructed -- fail closed: "unknown" blocks -- OR a genuine trial-boot
// health window is in progress/unresolved). Callers (see
// resolveOtaBoardInstallGate() call sites below, the erase-admission
// decorator, and MyMesh::hasPendingWork()) use this to refuse a
// competing install/erase and suppress deep sleep. Qualified devices use
// g_qualified, not the full install gate; stock caches require their own boot proof.
bool otaBoardTrialHealthWindowActive() {
  if (!g_qualified) return g_stock_boot_result != mesh::ota::OtaBoardStockBootPreflight::Result::Healthy;
  if (trial_boot_confirmer_ptr == nullptr) return true;  // qualified but unknown -> fail closed (block).
  return trial_boot_confirmer_ptr->isTrialActive();
}

// Genuine earliest-boot-phase preflight -- see MyMesh.cpp's weak-default
// doc comment. Qualified devices only construct/read the state/confirm regions -- the SAME
// cheap, side-effect-bounded work configureCompanionFirmwareOtaBackend()
// performs before EVER reaching bank0 resolution below -- and stops
// there, without a blocking image hash during a trial. The stock path
// independently verifies the SDK/image and erased install journal before FS writes.
// `g_qualified`/`trial_boot_confirmer_ptr`
// are shared statics: later backend configuration reuses the qualified
// confirmer and independently rechecks the stock proof before cache attachment.
bool otaBoardEarlyBootTrialOrUnknown() {
  g_stock_boot_result = mesh::ota::OtaBoardStockBootPreflight::Result::IoError;
  if (!ota::platform::SenseCapQspiLayout::isValid() || !ota::platform::isOk(flash.begin())) {
    // Cannot even read the OTA state region -- genuinely UNKNOWN (a real
    // flash/IO failure, not a positive "no trial concept" observation).
    // Fail closed: block destructive writes rather than allow them.
    return true;
  }
  const uint8_t* jedec = flash.jedecId();
  if (jedec[0] != 0x85 || jedec[1] != 0x60 || jedec[2] != 0x15) return true;
  const mesh::ota::OtaBoardBootQualification qualification = mesh::ota::resolveOtaBoardBootQualification(
      kExpectedBoardTargetId, kExpectedRoleId, kExpectedCapabilityFlags);
  if (!qualification.qualified) return !stockBootOrdinaryWritesAllowed(qualification);
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

bool configureCompanionFirmwareOtaBackend(mesh::ota::OtaFirmwareIntegration& integration) {
  // Reset on every (re)configure attempt: the only place this is ever set
  // true again is the single fully-qualified INSTALL_CAPABLE branch below,
  // so a re-run that no longer reaches it (e.g. floor became unreadable)
  // must not leave a stale `true` from a prior call.
  g_backend_qualified_and_bank0_valid = false;
  g_qualified = false;
  g_stock_boot_result = mesh::ota::OtaBoardStockBootPreflight::Result::IoError;
  install_provider_v3 = nullptr;
  g_active_guarded_staging = nullptr;
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
  // Install admission requires a qualified marker. A stock-loader uploader
  // can still cache owner-signed bytes, without receiver or install authority.
  const mesh::ota::OtaBoardBootQualification qualification = mesh::ota::resolveOtaBoardBootQualification(
      kExpectedBoardTargetId, kExpectedRoleId, kExpectedCapabilityFlags);

  if (!qualification.qualified) {
    const bool stock_healthy = stockBootOrdinaryWritesAllowed(qualification);
    static mesh::ota::OtaBoardCacheOnlyBackend cache_backend(
        candidate, candidate_record_scratch_region, &otaBoardTrialHealthWindowActive);
    snprintf(g_install_capability_status, sizeof(g_install_capability_status), "%s: %s",
             stock_healthy ? "CACHE_ONLY" : "CACHE_UNAVAILABLE",
             mesh::ota::OtaBoardStockBootPreflight::reason(g_stock_boot_result));
    g_install_capability_reason = g_install_capability_status;
    return stock_healthy && cache_backend.attach(integration, signature_verifier);
  }
  std::memcpy(active_wire_public_key, qualification.info.trustedPublicKey, sizeof(active_wire_public_key));
  active_wire_key_id = qualification.info.keyId;
  active_wire_algorithm_id = qualification.info.algorithmId;
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
  // Bind the ACTUAL signer key/algorithm identity from the qualified
  // marker as trusted policy: a descriptor
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

  // NOTE: this used to also anchor `counter` (OtaBoardFailClosedMonotonicCounter)
  // against a publisher-signed BootFloorActivationReceiptV1 lifetime-role
  // record via counter.setRoleAuthority(). That record format belonged to
  // the deleted parallel Authority/Store system and has been removed as
  // part of the lean identity-simplification migration; `counter` now
  // always runs its documented numeric-floor-only fail-closed behavior
  // (see OtaBoardBackendCommon.h). A durable minimal signer-snapshot +
  // manifest-hash install-command contract, if the Boot owner's migration
  // produces one, is a separate, future, explicitly coordinated addition.

  static ota::trust::DescriptorVerifier lab_verifier(
      hasher, signature_verifier, counter, anchor);
  static mesh::ota::OtaNrf52FirmwareTrustProvider lab_trust(
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
        // Command v3: the real, current bootloader's SOLE accepted
        // install-command record_version (see xiao_ota_record.h --
        // record_version 2/no-admitted-key AND the legacy v1 format are
        // both retired). The admitted-signer key supplied to
        // buildInstallCommandV3() flows from onAuthorizedSession()'s
        // `controller`, already threaded through by OtaFirmwareIntegration.h.
        static mesh::ota::OtaBoardInstallCommandProviderV3 lab_install_provider_v3;
        lab_install_provider_v3.setTrialActivePredicate(&otaBoardTrialHealthWindowActive);
        static mesh::ota::OtaFirmwareStorageSink lab_staging(candidate, &xiao_command_region,
                                                             &lab_install_provider_v3);
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
        install_provider_v3 = &lab_install_provider_v3;
        g_install_capability_reason = "INSTALL_CAPABLE: qualified custom bootloader detected (command v3)";
        g_backend_qualified_and_bank0_valid = true;
      }
    }
    }
  }
  mesh::ota::formatOtaBoardCapabilityStatus(g_install_capability_status, sizeof(g_install_capability_status),
                                            g_install_capability_reason);

  static mesh::ota::OtaBoardNrf52RunningContext running_context;
  static mesh::ota::OtaBoardUnadmittedCommandRecovery recovery(
      xiao_command_region, xiao_state_region, xiao_floor_region, candidate, signature_verifier,
      running_context, g_qualified, kExpectedBoardTargetId, kExpectedRoleId);
  integration.attachUnadmittedAbort(&recovery, &mesh::ota::OtaBoardUnadmittedCommandRecovery::invoke);
  static ::ota::storage::OtaCandidateStore candidate_store(candidate_record_scratch_region);
  integration.attachCandidateStore(&candidate_store);
  integration.attachLeanSignatureVerifier(&signature_verifier);
  integration.attachTrustProvider(trust);
  integration.attachStagingSink(staging);
  return integration.backendAvailable();
}


#endif
