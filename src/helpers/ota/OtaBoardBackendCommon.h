#pragma once

// Shared logic for the two nRF52840+P25Q16H QSPI backend wiring files
// (variants/xiao_nrf52/OtaLabBackend.cpp and
// variants/sensecap_solar/OtaProductionBackend.cpp), extracted to avoid
// duplicating ~200 lines of near-identical MonotonicCounter/
// SignatureVerifier/InstallCommandProviderV2/boot-marker-qualification
// logic between the two boards. Board-specific differences (target id,
// whether a hardcoded-key STAGING_ONLY fallback is permitted at all) stay
// in each backend .cpp file and are passed in as parameters here.
//
// Header-only, dependency-free of Arduino/Ed25519 (the caller supplies its
// own ota::trust::SignatureVerifier implementation), so this can be
// exercised directly by PlatformIO's native unit tests.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <ota/runtime/OtaInstallAttemptIdentity.h>
#include <ota/security/OtaSecurityPhysicalPartitionArbiter.h>
#include <ota/storage/XiaoOtaActiveExtentBridge.h>
#include <ota/storage/XiaoOtaBootFloorReceiptGate.h>
#include <ota/storage/XiaoOtaBootInfoReader.h>
#include <ota/storage/XiaoOtaCommandRecord.h>
#include <ota/storage/XiaoOtaTrialBootConfirmation.h>
#include <ota/storage/XiaoOtaTrialHealthMonitor.h>
#include <ota/trust/MonotonicCounter.h>
#include <ota/trust/Sha256.h>
#include <ota/trust/SignatureVerifier.h>
#include <ota/trust/TrustTypes.h>
#include <helpers/ota/OtaFirmwareBackend.h>  // IOtaInstallCommandProviderV2
#include <helpers/ota/OtaBaselineMeasurementCollector.h>  // OtaBaselineMeasurementArbiterResult

namespace mesh {
namespace ota {

// Durable-across-reset anti-rollback counter, shared by both backends.
// Fails closed (currentValue()/commitNewValue() both return false) unless
// the confirmed-counter floor is either (a) a valid record, or (b) both
// slots are genuinely blank/erased (legitimate first-ever-device
// baseline, counter=0) -- see
// XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed()'s doc
// comment for the corrupt-vs-blank distinction this depends on. A slot
// that is non-blank but fails validation (torn write, tampering) must
// NEVER be silently treated as "counter is 0"; that was the previous
// (fail-open) behavior this replaces.
class OtaBoardFailClosedMonotonicCounter : public ::ota::trust::MonotonicCounter {
public:
  explicit OtaBoardFailClosedMonotonicCounter(::ota::platform::FlashRegion& floor_region)
      : floor_region_(floor_region) {}

  // Root's "FINAL IMPLEMENTABLE HIGH-FIX CONTRACT" section D: wires the
  // durable, publisher-signed BootFloorActivationReceiptV1 lifetime-role
  // fact into this already-fail-closed gate, so EVERY existing consumer
  // of currentValue()/commitNewValue() (DescriptorVerifier's anti-
  // rollback check before any admission, and its commitCounter() after
  // confirmation) automatically also requires proven role continuity --
  // no separate call site to keep in sync. Optional: a caller that never
  // calls this gets exactly the prior (numeric-floor-only) behavior,
  // e.g. existing native tests exercising this class directly without a
  // receipt fixture.
  void setRoleAuthority(const ::ota::storage::BootFloorRoleAuthorityAnchor& anchor,
                         ::ota::trust::SignatureVerifier& verifier) {
    role_anchor_ = anchor;
    role_verifier_ = &verifier;
    role_authority_configured_ = true;
    seeded_ = false;  // Force re-evaluation even if an earlier seed attempt already ran.
  }

  // Diagnostic accessor only -- never itself a permission check. Lets a
  // backend report WHY install-path trust decisions are currently denied
  // (pending/IoError/Missing/Corrupt/RoleMismatch/Conflict) distinctly
  // from a bare false return, per the contract's "expose ... separately"
  // requirement. Valid only after ensureSeeded() has actually run (i.e.
  // after any currentValue()/commitNewValue() call); defaults to Ok
  // (meaning "not yet evaluated / no role authority configured") before
  // that, which callers must not mistake for a positive guarantee.
  ::ota::storage::BootFloorRoleAuthorityOutcome lastRoleAuthorityOutcome() const {
    return last_role_outcome_;
  }

  bool currentValue(uint32_t& out) const override {
    ensureSeeded();
    if (!seed_ok_) return false;
    out = value_;
    return true;
  }

  bool commitNewValue(uint32_t value) override {
    ensureSeeded();
    if (!seed_ok_ || value <= value_) return false;
    value_ = value;
    return true;
  }

private:
  void ensureSeeded() const {
    if (seeded_) return;
    seeded_ = true;
    uint32_t floor_value = 0;
    bool floor_ok = ::ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed(floor_region_,
                                                                                       floor_value);
    if (role_authority_configured_) {
      last_role_outcome_ = ::ota::storage::XiaoOtaBootFloorReceiptGate::resolve(
          floor_region_, role_anchor_, *role_verifier_, /*out_receipt=*/nullptr);
      // The role gate must precede every mutation/trust decision this
      // counter gates: a missing/corrupt/wrong-role/conflicting receipt
      // fails the WHOLE seed closed, even if the plain numeric floor
      // read above happened to succeed.
      if (last_role_outcome_ != ::ota::storage::BootFloorRoleAuthorityOutcome::Ok) {
        floor_ok = false;
      }
    }
    seed_ok_ = floor_ok;
    if (seed_ok_) value_ = floor_value;
  }

  ::ota::platform::FlashRegion& floor_region_;
  bool role_authority_configured_ = false;
  ::ota::storage::BootFloorRoleAuthorityAnchor role_anchor_;
  ::ota::trust::SignatureVerifier* role_verifier_ = nullptr;
  mutable ::ota::storage::BootFloorRoleAuthorityOutcome last_role_outcome_ =
      ::ota::storage::BootFloorRoleAuthorityOutcome::Ok;
  mutable bool seeded_ = false;
  mutable bool seed_ok_ = false;
  mutable uint32_t value_ = 0;
};

// Reads a big-endian u32 out of the transport's own 59-byte canonical wire
// descriptor at the securityCounter field's fixed offset (boardFamily(2) +
// boardVariant(2) + role(1) + appAddress(4) + exactSizeBytes(4) +
// sha256(32) = 45), per encodeOtaDescriptorCanonical()'s field order --
// shared by both backends (was duplicated identically before).
inline uint32_t otaBoardWireDescriptorSecurityCounterBE(const uint8_t wire_descriptor[59]) {
  constexpr size_t kOffset = 2 + 2 + 1 + 4 + 4 + 32;  // = 45
  const uint8_t* p = wire_descriptor + kOffset;
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

// First eight SHA256 bytes, interpreted BE64, over the no-NUL domain
// "MeshCore/OTA/install-attempt/v1", controller32, campaignBE32,
// sessionBE32, attemptBE16 and SHA256(canonical59).
// This pure derivation does not authenticate the supplied controller or
// authorize an attempt. The durable attempt owner must preserve the full
// binding and reject zero/colliding nonces before publishing a command.
inline uint64_t computeOtaTransactionNonce(const uint8_t controller[32],
                                           const meshcore::ota::runtime::OtaSessionId& session,
                                           const uint8_t wire_descriptor[59]) {
  return meshcore::ota::runtime::otaInstallAttemptNonce(controller, session, wire_descriptor);
}

// Supplies command v2's fields by copying the transport's own already-
// verified 59-byte wire descriptor + 64-byte Ed25519 signature verbatim
// (no re-signing), and resolving active_image_extent/hash via
// XiaoOtaActiveExtentBridge -- a fresh bank-0 read only, never a
// (possibly stale, wrong-sized after a USB reflash) floor record. Board-
// agnostic: both backends' prior copies were byte-for-byte identical.
class OtaBoardInstallCommandProviderV2 : public IOtaInstallCommandProviderV2 {
public:
  // Optional injected predicate: when set, buildInstallCommandV2() must
  // refuse (return false, write nothing) while a trial-boot health
  // window is genuinely active for this device -- a NEW install command
  // must never race a prior install whose trial-boot confirmation is
  // still pending (competing install during an active trial). Backends
  // wire their own OtaBoardTrialBootHealthConfirmer::isTrialActive() in
  // here via setTrialActivePredicate() once configured; left null (the
  // default) this predicate is simply not consulted.
  using TrialActivePredicate = bool (*)();
  void setTrialActivePredicate(TrialActivePredicate predicate) { trial_active_predicate_ = predicate; }

  bool buildInstallCommandV2(const uint8_t wire_descriptor[59], const uint8_t signature[64],
                             const meshcore::ota::runtime::OtaSessionId& session,
                             const uint8_t controller[32],
                             ::ota::storage::XiaoOtaCommandV2Fields& out) override {
    if (wire_descriptor == nullptr || signature == nullptr || controller == nullptr) return false;
    if (trial_active_predicate_ != nullptr && trial_active_predicate_()) {
      return false;  // refuse: a prior install's trial-boot confirmation is still pending.
    }
    const uint64_t nonce = computeOtaTransactionNonce(controller, session, wire_descriptor);
    if (nonce == 0) return false;
    const ::ota::storage::XiaoOtaActiveExtentInfo extent_info =
        ::ota::storage::XiaoOtaActiveExtentBridge::resolveCurrent();
    if (extent_info.active_image_extent == 0) {
      // resolveCurrent() returns 0 off-target OR whenever bank0 is not a
      // fresh, valid, CRC-verified record -- fail closed rather than
      // write a command with a bogus/guessed extent or hash.
      return false;
    }
    memcpy(out.wire_descriptor, wire_descriptor, sizeof(out.wire_descriptor));
    memcpy(out.signature_ed25519, signature, sizeof(out.signature_ed25519));
    out.active_image_extent = extent_info.active_image_extent;
    memcpy(out.active_image_hash_sha256, extent_info.active_image_hash_sha256,
           sizeof(out.active_image_hash_sha256));
    out.transaction_nonce = nonce;
    return true;
  }

private:
  TrialActivePredicate trial_active_predicate_ = nullptr;
};

// Three-way classification of the boot-info marker check: `Normal` is
// reserved for a FUTURE, separately signed "CertifyExistingBaseline"
// evidence chain (see OtaBaselineCertificationEvidence.h) -- NOT merely
// a blank/erased marker, and NOT merely `!isTrialActive()`. Until that
// authority is wired in (a separate owner's responsibility), this
// function NEVER produces Normal: a genuinely blank/erased marker
// (`BlankUncertifiedStock`) is an uncertified stock board and stays
// Unknown -- read-only local maintenance for this whole boot, honestly
// reported, never a fabricated permissive default. `Qualified` means a
// valid, fully-matching marker is present (trial-boot concept applies;
// consult the confirmer). `Unknown` also covers every other case -- a
// non-blank record that fails validation (corruption/torn write), OR a
// validly-formed record whose board/role/capability/algorithm does NOT
// match this build's expectations (a real bootloader marker is present,
// just not the one we expect) -- and MUST be treated the same as a
// genuine read failure: never silently assumed to be "no trial concept,
// safe to run destructive legacy behaviour".
enum class OtaBoardQualificationStatus { Normal, Qualified, Unknown };

// Why a given Unknown (or Qualified) classification was produced --
// purely diagnostic (e.g. for the OTA status serial frame), never itself
// a basis for any permissive decision.
enum class OtaBoardQualificationReason {
  QualifiedMatch,          // status == Qualified: real, matching marker.
  BlankUncertifiedStock,   // status == Unknown: genuinely blank/erased marker.
  CorruptMarker,           // status == Unknown: non-blank but invalid (torn/corrupt).
  RoleOrCapabilityMismatch // status == Unknown: valid marker, wrong board/role/capability/algorithm.
};


// Result of checking the boot-info/capability marker (bootloader/xiao_
// nrf52840_ota/include/xiao_ota_boot_info.h) against a specific board's
// expected identity. This is the ONLY authoritative source of "is a
// qualified MeshCore custom bootloader actually present" -- board/JEDEC
// identity, compiled feature flags, or backendAvailable() must never be
// used as a substitute (per boot-Hydra's explicit fail-closed contract).
struct OtaBoardBootQualification {
  OtaBoardQualificationStatus status = OtaBoardQualificationStatus::Unknown;
  OtaBoardQualificationReason reason = OtaBoardQualificationReason::BlankUncertifiedStock;
  ::ota::storage::XiaoOtaBootInfoReader::Info info;
  // Back-compat convenience: true iff status == Qualified. Existing call
  // sites that only ever cared about "is the durable install-capable
  // path allowed" (never "is legacy destructive behaviour safe") keep
  // working unchanged against this field.
  bool qualified = false;
};

// Pure, hardware-independent mapping from an already-obtained
// RecordStatus/Info to the OtaBoardQualificationStatus/Reason contract
// above -- extracted so native host tests can drive every branch
// (Blank/Corrupt/mismatched/matching) directly with synthetic values,
// since XiaoOtaBootInfoReader::classifyCurrent() itself is hardware-
// bound (reads a fixed memory-mapped address, only ever Corrupt
// off-target). resolveOtaBoardBootQualification() below is simply this
// function applied to the real classifyCurrent() result.
inline OtaBoardBootQualification resolveOtaBoardBootQualificationFromRecordStatus(
    ::ota::storage::XiaoOtaBootInfoReader::RecordStatus record_status,
    const ::ota::storage::XiaoOtaBootInfoReader::Info& info, uint32_t expected_target_id,
    uint32_t expected_role_id, uint32_t expected_capability_flags) {
  constexpr uint16_t kExpectedAlgorithmIdEd25519 = 1u;
  OtaBoardBootQualification result;
  if (record_status == ::ota::storage::XiaoOtaBootInfoReader::RecordStatus::Blank) {
    // Genuinely blank/erased marker: an uncertified stock/never-flashed
    // board. NOT, by itself, sufficient for a positive Normal
    // classification -- see OtaBoardQualificationStatus's doc comment
    // and OtaBaselineCertificationEvidence.h: Normal requires a
    // separately signed CertifyExistingBaseline record, which no call
    // site constructs/verifies yet. Stays Unknown: read-only local
    // maintenance for this whole boot (never the bounded trial/reboot
    // machinery -- that only ever activates via the Qualified branch
    // below).
    result.status = OtaBoardQualificationStatus::Unknown;
    result.reason = OtaBoardQualificationReason::BlankUncertifiedStock;
    return result;
  }
  if (record_status == ::ota::storage::XiaoOtaBootInfoReader::RecordStatus::Corrupt) {
    result.status = OtaBoardQualificationStatus::Unknown;
    result.reason = OtaBoardQualificationReason::CorruptMarker;
    return result;
  }
  // Found: a genuinely valid (magic/format/CRC) marker is present.
  if (info.boardTargetId == expected_target_id && info.roleId == expected_role_id &&
      (info.capabilityFlags & expected_capability_flags) == expected_capability_flags &&
      info.algorithmId == kExpectedAlgorithmIdEd25519) {
    result.status = OtaBoardQualificationStatus::Qualified;
    result.reason = OtaBoardQualificationReason::QualifiedMatch;
    result.qualified = true;
    result.info = info;
    return result;
  }
  // A real, validly-formed bootloader marker is present, but it doesn't
  // match what THIS build expects (wrong board/role/capability, or an
  // algorithm we can't verify) -- ambiguous, must fail closed rather than
  // fall back to "no trial concept".
  result.status = OtaBoardQualificationStatus::Unknown;
  result.reason = OtaBoardQualificationReason::RoleOrCapabilityMismatch;
  result.info = info;
  return result;
}

// Fail-closed boot-marker qualification check, shared by both backends.
// Only a struct that passes XiaoOtaBootInfoReader's magic/format/CRC
// validation is trusted at all, and even then, only when its
// board_target_id/role/capability genuinely match this build's
// expectations AND algorithm_id is the one value this firmware's
// SignatureVerifier actually implements (Ed25519, id 1) -- never board/
// JEDEC identity or a compiled flag alone. All-0xFF (stock/unmodified
// Adafruit bootloader) is the expected, common, non-error case here, not
// corruption -- see XiaoOtaBootInfoReader::RecordStatus's Blank-vs-Corrupt
// distinction, which this function surfaces via OtaBoardQualificationStatus
// rather than collapsing it into a single boolean.
inline OtaBoardBootQualification resolveOtaBoardBootQualification(uint32_t expected_target_id,
                                                                  uint32_t expected_role_id,
                                                                  uint32_t expected_capability_flags) {
  ::ota::storage::XiaoOtaBootInfoReader::Info info;
  const auto record_status = ::ota::storage::XiaoOtaBootInfoReader::classifyCurrent(info);
  return resolveOtaBoardBootQualificationFromRecordStatus(record_status, info, expected_target_id,
                                                          expected_role_id, expected_capability_flags);
}

// Typed, positively-evidenced startup classification -- DISTINCT from
// (and strictly narrower than) both OtaBoardQualificationStatus (is a
// qualified custom-bootloader marker present at all) and
// OtaBoardTrialBootHealthConfirmer::isTrialActive() (is a TRIAL_BOOT
// phase, or ambiguous state, currently unresolved). Neither of those
// alone is sufficient evidence to permit ordinary destructive userdata
// behaviour (identity generation, format, migrations): a qualified
// marker with a genuinely BLANK state region (no install ever attempted)
// or a Found record whose phase is anything other than kPhaseConfirmed
// (EMPTY/REQUESTED/BACKUP_*/INSTALL_COPYING/ROLLBACK_COPYING/FAILED) is
// ambiguous -- "not currently an active trial" is NOT the same as
// "positively proven safe" -- and must stay Unknown (read-only local
// maintenance for the whole boot), never silently promoted to Normal.
// IMPORTANT: a Found record whose phase is kPhaseConfirmed is NECESSARY
// but NOT SUFFICIENT for Normal. The bootloader phase byte alone only
// proves that the bootloader validated this app's durable confirmation
// record against ITS OWN state record on a prior boot -- it does NOT
// bind that evidence to the CURRENTLY RUNNING image: a USB reflash (or
// any other out-of-band image replacement) after CONFIRMED was written
// leaves the phase byte untouched while the running image/SDK/CRC/
// SHA-256/source-signature/role/floor/sidecar metadata may now disagree
// entirely with what was actually confirmed. Therefore Normal additionally
// requires `has_verified_fresh_baseline_proof` -- a positive result from
// a REAL, currently-unimplemented proof provider that freshly re-binds
// the running image to the confirmed record this boot (see
// OtaBaselineCertificationEvidence.h; separate future owner). No caller
// in this tree currently supplies true for that parameter, so Normal is
// HONESTLY UNREACHABLE today -- Confirmed-phase-without-fresh-proof
// stays Unknown (ConfirmedPendingFreshVerification), never fabricated.
// FAILED (phase 8) alone is explicitly NOT treated as a verified
// rollback: it only records that the bootloader gave up on the trial,
// not that a rollback to a known-good baseline was itself verified
// complete -- absent that additional (not yet implemented -- separate
// future owner) evidence, it stays Unknown and fails closed, exactly
// like every other non-CONFIRMED found phase.
enum class OtaBoardStartupDecisionStatus { Normal, Trial, Unknown };

enum class OtaBoardStartupDecisionReason {
  ConfirmedInstallEvidence,  // Normal: Found + phase == kPhaseConfirmed AND fresh baseline proof supplied.
  ConfirmedPendingFreshVerification, // Unknown: Found + phase == kPhaseConfirmed, but NO fresh
                             // SDK/CRC/SHA/signature/role binding proof was supplied for the
                             // CURRENTLY RUNNING image -- phase alone never promotes to Normal.
  ActiveTrialBoot,           // Trial: Found + phase == kPhaseTrialBoot.
  StateUnreadable,           // Trial (fails closed): state read Unknown or Corrupt.
  NotQualified,              // Unknown: board itself is not Qualified (see OtaBoardQualificationStatus).
  NoInstallHistory,          // Unknown: Qualified, but state region is genuinely Blank (never installed).
  IncompleteOrAmbiguousPhase,// Unknown: Qualified, Found, but phase is neither TrialBoot nor Confirmed
                             // (includes FAILED -- "FAILED alone is not rollback").
};

struct OtaBoardStartupDecision {
  OtaBoardStartupDecisionStatus status = OtaBoardStartupDecisionStatus::Unknown;
  OtaBoardStartupDecisionReason reason = OtaBoardStartupDecisionReason::NotQualified;
};

// Pure, hardware-independent mapping -- native-testable directly with
// synthetic (qualified, ReadStatus, phase, has_verified_fresh_baseline_proof)
// inputs, mirroring resolveOtaBoardBootQualificationFromRecordStatus()'s
// pattern. `has_verified_fresh_baseline_proof` defaults to false and is
// NOT currently wired to any positive evidence source anywhere in this
// tree -- it exists solely so a future real proof provider can supply
// it without another call-site signature change; passing true from
// anywhere without a genuine binding to the running image would itself
// be a fabricated-Normal bug in the CALLER, not in this function.
inline OtaBoardStartupDecision resolveOtaBoardStartupDecision(
    bool qualified, ::ota::storage::XiaoOtaStateReader::ReadStatus state_status, uint32_t state_phase,
    bool has_verified_fresh_baseline_proof = false) {
  OtaBoardStartupDecision result;
  if (!qualified) {
    result.status = OtaBoardStartupDecisionStatus::Unknown;
    result.reason = OtaBoardStartupDecisionReason::NotQualified;
    return result;
  }
  if (state_status == ::ota::storage::XiaoOtaStateReader::ReadStatus::Unknown ||
      state_status == ::ota::storage::XiaoOtaStateReader::ReadStatus::Corrupt) {
    result.status = OtaBoardStartupDecisionStatus::Trial;
    result.reason = OtaBoardStartupDecisionReason::StateUnreadable;
    return result;
  }
  if (state_status == ::ota::storage::XiaoOtaStateReader::ReadStatus::Blank) {
    result.status = OtaBoardStartupDecisionStatus::Unknown;
    result.reason = OtaBoardStartupDecisionReason::NoInstallHistory;
    return result;
  }
  // Found.
  if (state_phase == ::ota::storage::XiaoOtaStateReader::kPhaseTrialBoot) {
    result.status = OtaBoardStartupDecisionStatus::Trial;
    result.reason = OtaBoardStartupDecisionReason::ActiveTrialBoot;
    return result;
  }
  if (state_phase == ::ota::storage::XiaoOtaStateReader::kPhaseConfirmed) {
    if (has_verified_fresh_baseline_proof) {
      result.status = OtaBoardStartupDecisionStatus::Normal;
      result.reason = OtaBoardStartupDecisionReason::ConfirmedInstallEvidence;
    } else {
      result.status = OtaBoardStartupDecisionStatus::Unknown;
      result.reason = OtaBoardStartupDecisionReason::ConfirmedPendingFreshVerification;
    }
    return result;
  }
  result.status = OtaBoardStartupDecisionStatus::Unknown;
  result.reason = OtaBoardStartupDecisionReason::IncompleteOrAmbiguousPhase;
  return result;
}

// Populates ALL SIX identity fields of a DeviceTrustAnchor from an
// explicit, already-resolved (target/role/capability, format/key/
// algorithm) identity -- shared by both backends specifically so that
// `expected_format_id` (a fixed protocol wire-format version, e.g.
// XIAO_OTA_DESCRIPTOR_FORMAT) can never be silently left at its zero
// default the way expected_key_id/expected_algorithm_id are ordinarily
// sourced per-call-site from a qualified marker or lab fallback. See
// DeviceTrustAnchor's own comment (ota/trust/TrustTypes.h): 0 in any of
// format/key/algorithm is a valid, explicit value, never "unset", so a
// caller that forgets one produces a fail-closed rejection of every
// legitimately signed descriptor tagged with a real (nonzero) value --
// not a security hole, but a genuine functional regression that must be
// fixed at the source, never worked around by relaxing the check itself.
inline void configureOtaTrustAnchorIdentity(::ota::trust::DeviceTrustAnchor& anchor,
                                            uint32_t expected_target_id, uint32_t expected_role_id,
                                            uint32_t supported_boot_capability_flags,
                                            uint16_t expected_format_id, uint16_t expected_key_id,
                                            uint16_t expected_algorithm_id) {
  anchor.expected_target_id = expected_target_id;
  anchor.expected_role_id = expected_role_id;
  anchor.supported_boot_capability_flags = supported_boot_capability_flags;
  anchor.expected_format_id = expected_format_id;
  anchor.expected_key_id = expected_key_id;
  anchor.expected_algorithm_id = expected_algorithm_id;
}

// Combined install-capability predicate shared by both backends: a
// durable v2 install-command provider/confirmation path may ONLY be
// attached when ALL THREE hold: (a) a genuinely qualified custom-
// bootloader marker (`qualified`, from resolveOtaBoardBootQualification()
// -- never board/JEDEC identity alone), (b) a fresh, valid, non-zero bank
// -0 active image extent (`bank0_active_image_extent`, from
// XiaoOtaActiveExtentBridge::resolveCurrent() -- a bogus/zero extent
// would bind a durable command to nothing), and (c) the bootloader-owned
// confirmed-counter floor is genuinely readable -- either a valid record,
// or both A/B slots legitimately blank (0xFF, a real first-ever-device
// baseline of 0) -- via `counter.currentValue()`. A corrupt/tampered/
// unreadable floor must disable install capability even when (a) and (b)
// both hold; it must NEVER be silently treated as floor==0 and allowed
// to proceed. This function performs the actual `counter.currentValue()`
// call itself -- callers must not skip straight to "qualified && bank0
// valid" and treat that alone as sufficient. The stock/no-marker
// diagnostic-read path is unaffected either way; this only gates the
// durable command/confirmation path.
struct OtaBoardInstallGateResult {
  bool install_capable = false;
  uint32_t floor_value = 0;
};

inline OtaBoardInstallGateResult resolveOtaBoardInstallGate(bool qualified,
                                                            uint32_t bank0_active_image_extent,
                                                            OtaBoardFailClosedMonotonicCounter& counter) {
  OtaBoardInstallGateResult result;
  if (!qualified || bank0_active_image_extent == 0) return result;
  uint32_t floor_value = 0;
  if (!counter.currentValue(floor_value)) return result;
  result.install_capable = true;
  result.floor_value = floor_value;
  return result;
}

// Formats a compact ("REASON: detail", <=63 bytes incl. NUL) install-
// capability status line into `out` (caller-owned buffer of at least
// `out_len` bytes) so it fits comfortably inside the existing OTA status
// serial frame's <=176-byte budget alongside other fields. Truncates
// (never overflows) if `reason` is longer than `out_len - 1`.
inline void formatOtaBoardCapabilityStatus(char* out, size_t out_len, const char* reason) {
  if (out == nullptr || out_len == 0) return;
  if (reason == nullptr) reason = "";
  size_t n = strlen(reason);
  if (n > out_len - 1) n = out_len - 1;
  memcpy(out, reason, n);
  out[n] = '\0';
}

// Convenience alias so callers outside ::ota::storage (backend .cpp
// files, MyMesh.cpp) can spell the outcome type without the fully
// qualified ::ota::storage:: prefix.
using OtaBoardTrialHealthOutcome = ::ota::storage::XiaoOtaTrialHealthOutcome;

// Real-hardware adapter feeding
// ::ota::storage::XiaoOtaIncrementalExtentResolver (bounded, per-tick
// extent-CRC steps -- never a single blocking whole-image CRC) into
// ::ota::storage::XiaoOtaTrialHealthMonitor's injectable
// IXiaoOtaActiveImageAccessor seam, decoupled so native tests can supply
// a synthetic in-memory image fixture instead (the real resolver reads
// fixed NRF52840_XXAA hardware addresses and fails closed off-target,
// making the real confirm path otherwise untestable off-target).
class OtaBoardRealActiveImageAccessor : public ::ota::storage::IXiaoOtaActiveImageAccessor {
public:
  ::ota::storage::XiaoOtaExtentResolutionStep stepExtentResolution(uint32_t max_bytes, const uint8_t** out_image,
                                                                   uint32_t* out_extent) override {
    return resolver_.step(max_bytes, out_image, out_extent);
  }

private:
  ::ota::storage::XiaoOtaIncrementalExtentResolver resolver_;
};

// Thin board-facing wrapper around ::ota::storage::XiaoOtaTrialHealthMonitor
// (see that header for the full continuous-window/deadline/incremental-
// hash contract), shared by both backends' loop()-tick entry points. Owns
// the real hardware image accessor by default so backend .cpp files never
// need to reference ::ota::storage directly; native tests can instead
// inject a synthetic IXiaoOtaActiveImageAccessor via the 3-arg
// constructor to exercise the genuine positive-confirmation path off
// real hardware.
class OtaBoardTrialBootHealthConfirmer {
public:
  // `boot_epoch_ms` MUST be the genuine application boot origin, NOT a
  // fresh clock reading taken here at (lazy) construction time, and NOT
  // this object's first tick() timestamp. In production, Arduino's
  // millis() already counts from actual power-on/reset, so the correct
  // value is the constant 0 (see the backend .cpp files) -- reading
  // millis() again right before constructing this object (itself only
  // done once the flash driver is ready and the boot marker is
  // qualified, which happens well into setup(), after Serial/board/
  // radio/filesystem begin() calls) would silently discount however
  // long that earlier setup() work took from the 45s deadline budget,
  // extending it on a slow boot -- exactly the hazard this must avoid.
  // See XiaoOtaTrialHealthMonitor's own constructor doc comment for why
  // arming lazily on first tick() is likewise unsafe.
  OtaBoardTrialBootHealthConfirmer(::ota::platform::FlashRegion& state_region,
                                   ::ota::platform::FlashRegion& confirm_region, uint32_t boot_epoch_ms)
      : monitor_(state_region, confirm_region, real_accessor_, boot_epoch_ms) {}

  // Test/alternate-source constructor: `image_accessor` is consulted
  // instead of the real hardware bridge, so callers (native tests) can
  // prove the genuine positive-confirmation path, not just the fail-
  // closed off-target one.
  OtaBoardTrialBootHealthConfirmer(::ota::platform::FlashRegion& state_region,
                                   ::ota::platform::FlashRegion& confirm_region,
                                   ::ota::storage::IXiaoOtaActiveImageAccessor& image_accessor,
                                   uint32_t boot_epoch_ms)
      : monitor_(state_region, confirm_region, image_accessor, boot_epoch_ms) {}

  // Call exactly once per main-loop tick with the genuine current
  // wall-clock time (caller's own monotonic millis clock) and readiness
  // signals; returns the latched outcome (see
  // ::ota::storage::XiaoOtaTrialHealthOutcome). Callers must react to
  // ANY of the three (Pending -> Confirmed), (Pending -> DeadlineExpired)
  // or (Pending -> ConfirmationUncertain) transitions with exactly one
  // deliberate reboot of their own -- this class never reboots and never
  // touches any hardware watchdog register.
  ::ota::storage::XiaoOtaTrialHealthOutcome tick(uint32_t now_ms, bool radio_ready, bool filesystem_ready,
                                                 bool loop_healthy) {
    return monitor_.tick(now_ms, radio_ready, filesystem_ready, loop_healthy);
  }

  // True while a genuine TRIAL_BOOT state record is in progress --
  // INCLUDING after a same-boot terminal outcome has latched; only a
  // genuine subsequent boot with a fresh (non-trial) state record clears
  // this. Callers use this to suppress deep sleep and competing
  // installs/erases while a trial is live or its outcome is unresolved-
  // -pending-reboot.
  bool isTrialActive() const { return monitor_.isTrialActive(); }

  ::ota::storage::XiaoOtaTrialHealthOutcome outcome() const { return monitor_.outcome(); }
  uint32_t lastConfirmedCounter() const { return monitor_.confirmedCounter(); }

  // Raw eager-read state-record outcome/phase (see
  // XiaoOtaTrialHealthMonitor::stateReadStatus()/statePhase()) -- used
  // by resolveOtaBoardStartupDecision() below to build a typed startup
  // decision that distinguishes "no install history" (Blank), "genuine
  // completed-install evidence" (Found + phase == kPhaseConfirmed), and
  // every other ambiguous/incomplete phase, none of which isTrialActive()
  // alone can tell apart.
  ::ota::storage::XiaoOtaStateReader::ReadStatus stateReadStatus() const { return monitor_.stateReadStatus(); }
  uint32_t statePhase() const { return monitor_.statePhase(); }

private:
  OtaBoardRealActiveImageAccessor real_accessor_;
  ::ota::storage::XiaoOtaTrialHealthMonitor monitor_;
};

// Decorator around a real IOtaStagingSink that refuses to BEGIN a new
// staging session (returns Rejected, touches nothing else) while a
// caller-supplied predicate reports that a trial-boot health window is
// genuinely active or its state is unknown (predicate not yet wired /
// confirmer not yet constructed -- see the backends' fail-closed
// null-pointer handling). A NEW incoming OTA campaign must never be
// allowed to erase/stage over the candidate region while a prior
// install's trial-boot confirmation is still pending: that is a genuine
// production hazard this decorator closes, distinct from (and in
// addition to) OtaBoardInstallCommandProviderV2's existing
// trial-active guard, which only ever gated BUILDING a durable install
// command, never the storage sink's own beginSession()/erase itself.
// Once a session has legitimately begun, all other calls (writeChunk/
// commit/abort/the two optional verified-descriptor/authorized-session
// hooks) delegate unconditionally to the wrapped sink -- this decorator
// only ever gates the initial admission decision, never mid-transfer
// behaviour. Also latches a "storage IO fault observed" flag whenever the
// wrapped sink's writeChunk()/commit() reports IoError -- a real,
// grounded filesystem-failure signal reused by the board wiring as part
// of its genuine (not hardcoded-true) per-tick filesystem-readiness
// check for the trial-boot health monitor.
class OtaBoardTrialGuardedStagingSink : public meshcore::ota::runtime::IOtaStagingSink {
public:
  using TrialActiveOrUnknownPredicate = bool (*)();

  OtaBoardTrialGuardedStagingSink(meshcore::ota::runtime::IOtaStagingSink& wrapped,
                                  TrialActiveOrUnknownPredicate predicate)
      : wrapped_(wrapped), predicate_(predicate) {}

  Result beginSession(const meshcore::ota::protocol::OtaDescriptor& descriptor) override {
    // Fail closed on an unknown predicate too: a null predicate must
    // never be silently treated as "not active" and permit an erase --
    // exactly like predicate()==true.
    if (predicate_ == nullptr || predicate_()) {
      return Result::Rejected;  // trial-active/unknown: refuse, no erase/state mutation of any kind.
    }
    return wrapped_.beginSession(descriptor);
  }

  Result writeChunk(uint64_t offset, const uint8_t* data, size_t len) override {
    const Result result = wrapped_.writeChunk(offset, data, len);
    if (result == Result::IoError) io_fault_observed_ = true;
    return result;
  }

  Result commit() override {
    const Result result = wrapped_.commit();
    if (result == Result::IoError) io_fault_observed_ = true;
    return result;
  }

  void abort() override { wrapped_.abort(); }

  void onVerifiedWireDescriptor(const uint8_t* wireDescriptor59, size_t wireDescriptorLen,
                                const uint8_t* signature64, size_t signatureLen) override {
    wrapped_.onVerifiedWireDescriptor(wireDescriptor59, wireDescriptorLen, signature64, signatureLen);
  }

  void onAuthorizedSession(const meshcore::ota::runtime::OtaSessionId& session,
                           const uint8_t controller[32]) override {
    wrapped_.onAuthorizedSession(session, controller);
  }

  // Real, grounded (not invented) filesystem-fault signal: true once any
  // writeChunk()/commit() call on the wrapped sink has ever reported
  // IoError this boot. Latched, never auto-clears -- a device that has
  // observed a genuine storage fault must not silently claim
  // filesystem-ready again without a fresh boot.
  bool storageIoFaultObserved() const { return io_fault_observed_; }

private:
  meshcore::ota::runtime::IOtaStagingSink& wrapped_;
  TrialActiveOrUnknownPredicate predicate_;
  bool io_fault_observed_ = false;
};

// Shared, board-agnostic real arbitration for the baseline-measurement
// job's media-arbiter seam (IOtaBaselineMeasurementSource::
// acquireMediaArbiter/releaseMediaArbiter in
// OtaBaselineMeasurementCollector.h). Backed by the genuine RAM-only
// ota::security::OtaSecurityPartitionArbiterRegistry (the SAME shared
// mechanism OtaSecurityStore itself uses) -- NOT a private/unshared
// token of this collector's own.
//
// Root correction: an EARLIER draft keyed this guard on
// (boardTargetId, candidateRegion.baseOffset(), candidateRegion.baseOffset())
// -- a private tuple Store's OWN OtaSecurityStore construction (real key:
// (physicalToken, SenseCapQspiLayout::kSecurityAOffset,
// SenseCapQspiLayout::kSecurityBOffset)) would NEVER share, so the two
// never actually arbitrated against each other. The collector's own
// QSPI-state-inspection phase inspects the security tails and journal
// too, not just the candidate image, so a candidate-only tuple was also
// unsafe on its own terms. This guard now uses the SAME canonical
// security-partition tuple
// (SenseCapQspiLayout::kSecurityAOffset, SenseCapQspiLayout::kSecurityBOffset)
// as OtaSecurityStore's real construction, so a real OtaSecurityStore
// instance constructed over the SAME physical chip genuinely serializes
// against this guard (and vice versa) via the shared registry -- see
// test_ota_board_media_arbiter_guard.cpp's cross-class tests.
//
// `physical_token` is a full, genuine `ota::security::PhysicalPartitionToken`
// (64-bit) -- never a 32-bit value silently widened -- identifying the
// ONE real physical QSPI chip. Every backend's real per-board chip
// token (see kQspiChipPhysicalToken in each backend .cpp) AND any future
// OtaSecurityStore construction wired into that SAME board MUST supply
// this EXACT value, or the two mechanisms silently stop sharing a lease.
// A zero token ("unknown/unbound", matching OtaSecurityStore's own
// convention) is refused immediately -- Unavailable, never silently
// treated as a valid identity.
//
// Registry acquire/release is called AT MOST once per held lifetime
// (cached in arbiter_): a Contended result must be retried by calling
// acquire() again without spuriously incrementing the registry's
// refcount on every retry.
class OtaBoardMediaArbiterGuard {
 public:
  OtaBoardMediaArbiterGuard(::ota::security::PhysicalPartitionToken physical_token, uint32_t bank_a_offset,
                            uint32_t bank_b_offset)
      : key_{physical_token, bank_a_offset, bank_b_offset}, valid_token_(physical_token != 0) {}

  ~OtaBoardMediaArbiterGuard() { release(); }

  OtaBoardMediaArbiterGuard(const OtaBoardMediaArbiterGuard&) = delete;
  OtaBoardMediaArbiterGuard& operator=(const OtaBoardMediaArbiterGuard&) = delete;

  mesh::ota::OtaBaselineMeasurementArbiterResult acquire() {
    if (!valid_token_) return mesh::ota::OtaBaselineMeasurementArbiterResult::Unavailable;
    if (arbiter_ == nullptr) {
      arbiter_ = ::ota::security::OtaSecurityPartitionArbiterRegistry::acquire(key_, nullptr);
      if (arbiter_ == nullptr) {
        return mesh::ota::OtaBaselineMeasurementArbiterResult::Unavailable;
      }
    }
    if (!arbiter_->acquire(ownerTag())) {
      return mesh::ota::OtaBaselineMeasurementArbiterResult::Contended;
    }
    held_ = true;
    return mesh::ota::OtaBaselineMeasurementArbiterResult::Acquired;
  }

  void release() {
    if (arbiter_ == nullptr) return;
    if (held_) {
      arbiter_->release(ownerTag());
      held_ = false;
    }
    ::ota::security::OtaSecurityPartitionArbiterRegistry::release(key_, arbiter_);
    arbiter_ = nullptr;
  }

 private:
  // Stable per-instance owner identity for
  // OtaSecurityPhysicalPartitionArbiter::OwnerToken (== const void*).
  const void* ownerTag() const { return this; }

  ::ota::security::PhysicalPartitionKey key_;
  ::ota::security::OtaSecurityPhysicalPartitionArbiter* arbiter_ = nullptr;
  bool held_ = false;
  bool valid_token_ = false;
};

}  // namespace ota
}  // namespace mesh
