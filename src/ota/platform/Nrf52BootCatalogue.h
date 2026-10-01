#pragma once

// Pure, header-only DTO + policy-matching contract for the nRF52840 boot
// catalogue (MBR / SoftDevice / stock bootloader "code" region identity).
//
// This header performs NO I/O and NO hardware access. It only:
//   1. Declares the raw, typed fields a caller (firmware) is expected to
//      measure from a live device (`Nrf52RawBootMeasurement`), and
//   2. Declares the shape of one approved catalogue row
//      (`Nrf52ApprovedBootRow`) as produced offline by
//      scripts/ota_boot_catalogue.py from pinned PUBLIC artifacts, and
//   3. Provides a pure matcher (`match_boot_catalogue`) that compares the
//      two and the MBR-parameter-page / UICR upgrade-field policy table,
//      returning one of a small set of TYPED outcomes.
//
// Fixed internal nRF52840 flash geometry this catalogue addresses (bytes):
//   stock bootloader "code" region : [0xF4000, 0xFD800)  length 0x9800
//     (code + ALL initialized-data flash LMA + every padding byte)
//   CF2 board-info / config block  : [0xFD800, 0xFE000)  length 0x0800
//   MBR parameter page              : [0xFE000, 0xFF000)  length 0x1000
//   Bootloader settings page        : [0xFF000, 0x100000) length 0x1000
//
// This header does NOT relabel application "role" (companion vs repeater),
// does NOT authorize installation, does NOT define any new signed wire
// format, and must never be used to approve an unknown/live hash -- only
// an EXACT, COMPLETE row match (see match_boot_catalogue) may report
// Approved. A blank/erased MBR parameter page is a REQUIRED precondition,
// not something this code ever erases, writes, or infers from absence.

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ota {
namespace platform {

// ---------------------------------------------------------------------
// Fixed flash geometry (bytes), internal nRF52840 1 MiB flash.
// ---------------------------------------------------------------------
inline constexpr uint32_t kNrf52BootStockCodeOffset = 0x000F4000u;
inline constexpr uint32_t kNrf52BootStockCodeSize   = 0x00009800u;  // ends 0xFD800
inline constexpr uint32_t kNrf52BootCf2Offset        = 0x000FD800u;
inline constexpr uint32_t kNrf52BootCf2Size          = 0x00000800u;  // ends 0xFE000
inline constexpr uint32_t kNrf52BootMbrParamPageOffset = 0x000FE000u;
inline constexpr uint32_t kNrf52BootMbrParamPageSize   = 0x00001000u;  // ends 0xFF000
inline constexpr uint32_t kNrf52BootSettingsPageOffset = 0x000FF000u;
inline constexpr uint32_t kNrf52BootSettingsPageSize   = 0x00001000u;  // ends 0x100000

// Public (not stock-specific) MBR/SoftDevice pinned reference extents, as
// measured directly inside the MBR / S140 7.3.0 public HEX files
// themselves (NOT the internal flash offsets above -- these describe
// byte ranges *within those public artifact files*).
inline constexpr uint32_t kNrf52MbrBodyRangeEnd          = 0x00000FF8u;  // [0, 0xFF8)
inline constexpr uint32_t kNrf52SoftDeviceRangeStart     = 0x00001000u;
inline constexpr uint32_t kNrf52SoftDeviceRangeEnd       = 0x00027000u;  // [0x1000, 0x27000)

// Sentinel meaning "unset" for an MBR-parameter-page / UICR 32-bit field.
// 0x00000000 is a VALID explicit value and must never be treated as unset.
inline constexpr uint32_t kNrf52BootFieldUnset = 0xFFFFFFFFu;

// Initial catalogue applicability: XIAO nRF52840 BLE only. No SenseCAP /
// profile 2 row exists until explicit, real vendor provenance is supplied.
inline constexpr uint32_t kNrf52BootTargetXiaoNrf52840 = 0x584E3430u;
inline constexpr uint32_t kNrf52BootProfileXiao        = 1u;
// Identifiers only (NOT an approved row): a genuine SenseCAP stock row
// still requires explicit, separate real vendor provenance. These exist
// so a custom-loader row's target/profile cannot be confused with XIAO's.
inline constexpr uint32_t kNrf52BootTargetSenseCapSolarP1 = 0x53435031u;
inline constexpr uint32_t kNrf52BootProfileSenseCap       = 2u;

// Schema version of this DTO header. The generated
// Nrf52ApprovedBootCatalogue.h statically asserts against this value so an
// old generated header (pre-loader_kind/role_binding fields) can never be
// silently aggregate-initialized against a newer DTO shape (which would
// leave loader_kind at its Unknown default -- caught explicitly by
// boot_row_schema_valid regardless, but the static_assert fails fast at
// compile time instead).
inline constexpr uint32_t kNrf52BootCatalogueSchemaVersion = 2u;

// The 60-byte MeshCore Boot "boot_info" marker (as defined/verified by
// bootloader/xiao_nrf52840_ota/tools/verify_boot_info_artifact.py's
// check_artifact -- Boot-owned, not duplicated here) lives inside the CF2
// config block at this fixed offset. This header never reads or decodes
// the marker itself -- firmware captures the raw bytes during its
// existing CF2 scan and this DTO only ever compares captured bytes
// byte-for-byte against an approved row's expected_boot_info.
inline constexpr uint32_t kNrf52BootInfoOffset = 0x000FDC00u;  // within [0xFD800,0xFE000)
inline constexpr size_t kNrf52BootInfoSize = 60;

// FICR geometry this catalogue requires: CODEPAGESIZE * CODESIZE == 1 MiB.
struct Nrf52FicrGeometry {
  uint32_t code_page_size = 0;
  uint32_t code_size = 0;

  bool operator==(const Nrf52FicrGeometry &other) const {
    return code_page_size == other.code_page_size && code_size == other.code_size;
  }
};
inline constexpr uint32_t kNrf52ExpectedCodePageSize = 0x1000u;
inline constexpr uint32_t kNrf52ExpectedCodeSize = 0x100u;  // 0x1000 * 0x100 == 0x100000

// A Cortex-M4 vector-table (MSP, reset) pair.
struct Nrf52BootVectorPair {
  uint32_t msp = 0;
  uint32_t reset = 0;

  bool operator==(const Nrf52BootVectorPair &other) const {
    return msp == other.msp && reset == other.reset;
  }
};

// MBR selector fields: the two 32-bit pointer words the MBR itself reads
// from ABSOLUTE flash addresses 0x00000FF8 (MBR_BOOTLOADER_ADDR) and
// 0x00000FFC (MBR_PARAM_PAGE_ADDR) -- confirmed verbatim from the pinned
// public Nordic headers (nrf_mbr.h, both the standalone MBR headers and
// the s140_nrf52_7.3.0 API copy):
//   #define MBR_BOOTLOADER_ADDR  (0xFF8)
//   #define MBR_PARAM_PAGE_ADDR  (0xFFC)
// These are near the START of flash (inside the MBR's own reserved first
// page) and are UNRELATED, by address arithmetic, to the separate,
// retained "MBR parameter page" region at [0xFE000, 0xFF000) -- that
// region is merely one of the VALUES these selector fields may point to
// (e.g. 0xFE000), never the address these fields are themselves read
// from. Do not blend the two: reading these selectors at
// page-relative/0xFE000-based offsets (e.g. 0xFEFF8/0xFEFFC) is WRONG.
// Either field may independently be kNrf52BootFieldUnset.
inline constexpr uint32_t kNrf52MbrBootloaderAddrFieldOffset = 0x00000FF8u;  // MBR_BOOTLOADER_ADDR
inline constexpr uint32_t kNrf52MbrParamPageAddrFieldOffset = 0x00000FFCu;   // MBR_PARAM_PAGE_ADDR

struct Nrf52MbrSelectorFields {
  uint32_t bootloader_addr = kNrf52BootFieldUnset;   // value read @ kNrf52MbrBootloaderAddrFieldOffset
  uint32_t params_page_addr = kNrf52BootFieldUnset;  // value read @ kNrf52MbrParamPageAddrFieldOffset

  bool operator==(const Nrf52MbrSelectorFields &other) const {
    return bootloader_addr == other.bootloader_addr && params_page_addr == other.params_page_addr;
  }
};

// UICR upgrade fallback fields: NRFFW[0] @ 0x10001014, NRFFW[1] @ 0x10001018.
struct Nrf52UicrUpgradeFields {
  uint32_t nrffw0 = kNrf52BootFieldUnset;
  uint32_t nrffw1 = kNrf52BootFieldUnset;
};

// Each non-kNrf52BootFieldUnset MBR-selector field wins independently over
// the corresponding UICR field; a field value of 0 is explicit and valid,
// never treated as unset. This effective resolution models what the MBR
// itself will actually use -- it is NOT used to pick the policy/config_id
// (see resolve_boot_config_policy, which compares RAW fields), only to
// separately sanity-check the resulting effective addresses.
inline Nrf52MbrSelectorFields effective_mbr_fields(const Nrf52MbrSelectorFields &mbr_selectors,
                                                    const Nrf52UicrUpgradeFields &uicr) {
  Nrf52MbrSelectorFields effective;
  effective.bootloader_addr =
      (mbr_selectors.bootloader_addr != kNrf52BootFieldUnset) ? mbr_selectors.bootloader_addr : uicr.nrffw0;
  effective.params_page_addr =
      (mbr_selectors.params_page_addr != kNrf52BootFieldUnset) ? mbr_selectors.params_page_addr : uicr.nrffw1;
  return effective;
}

// One allowed (configId, RAW MBR-selector-fields, RAW UICR-fields) tuple.
// Config IDs are the exact 32-bit values pinned by the approved Astra
// contract: 0x00010001 and 0x00010002 (NOT the decimal digits "10001"/
// "10002" -- those are a different, incorrect numeric value). Any raw
// tuple not present in kApprovedConfigPolicies -- including any field-
// level mix not explicitly listed, even one whose EFFECTIVE resolution
// would look correct -- is never approved (Unsupported).
struct Nrf52BootConfigPolicy {
  uint32_t config_id;
  Nrf52MbrSelectorFields mbr;
  Nrf52UicrUpgradeFields uicr;
};

inline constexpr uint32_t kBootConfigPolicyMbrBlankUicrSet = 0x00010001u;
inline constexpr uint32_t kBootConfigPolicyMbrSetUicrMirror = 0x00010002u;

inline constexpr Nrf52BootConfigPolicy kApprovedConfigPolicies[] = {
    {kBootConfigPolicyMbrBlankUicrSet, {kNrf52BootFieldUnset, kNrf52BootFieldUnset}, {0x000F4000u, 0x000FE000u}},
    {kBootConfigPolicyMbrSetUicrMirror, {0x000F4000u, 0x000FE000u}, {0x000F4000u, 0x000FE000u}},
};
inline constexpr size_t kApprovedConfigPolicyCount =
    sizeof(kApprovedConfigPolicies) / sizeof(kApprovedConfigPolicies[0]);

// Resolve the config_id by comparing the RAW (mbr, uicr) tuple EXACTLY
// against the fixed policy table -- NOT the effective/merged resolution.
// Comparing effective fields here would make the "MBR blank, fall back to
// UICR" policy (0x00010001) indistinguishable from "MBR explicitly set to
// the same values as UICR" (0x00010002), since both resolve to the same
// effective tuple; raw comparison is required to tell them apart. Returns
// true and sets *out_config_id only on an EXACT raw tuple match; any
// mixed/conflicting/partial tuple is never approved, even if its
// effective resolution happens to look correct.
inline bool resolve_boot_config_policy(const Nrf52MbrSelectorFields &raw_mbr,
                                        const Nrf52UicrUpgradeFields &raw_uicr, uint32_t *out_config_id) {
  for (size_t i = 0; i < kApprovedConfigPolicyCount; ++i) {
    const Nrf52BootConfigPolicy &policy = kApprovedConfigPolicies[i];
    if (policy.mbr == raw_mbr && policy.uicr.nrffw0 == raw_uicr.nrffw0 &&
        policy.uicr.nrffw1 == raw_uicr.nrffw1) {
      *out_config_id = policy.config_id;
      return true;
    }
  }
  return false;
}

// What KIND of loader this row describes. An Unknown/default-constructed
// row is always invalid (see boot_row_schema_valid) -- there is no
// implicit "neutral" meaning for an uninitialized/omitted field.
enum class Nrf52LoaderKind : uint8_t {
  Unknown = 0,
  VendorStock = 1,   // unmodified pinned public vendor bootloader build
  MeshCoreOta = 2,   // qualified MeshCore Boot overlay custom build
};

// Whether a row's expected_role_id binds to one EXACT application role, or
// is not applicable (role-neutral, e.g. vendor stock).
enum class Nrf52RoleBinding : uint8_t {
  NotApplicable = 0,
  Exact = 1,
};

// ---------------------------------------------------------------------
// One approved catalogue row, as emitted by scripts/ota_boot_catalogue.py
// into the generated Nrf52ApprovedBootCatalogue.h. Every field here must
// be a value genuinely measured from pinned PUBLIC (VendorStock) or
// qualified-overlay (MeshCoreOta) artifacts -- never a placeholder.
//
// Schema v2 (kNrf52BootCatalogueSchemaVersion): VendorStock rows MUST have
// role_binding==NotApplicable and expected_role_id==kNrf52BootFieldUnset
// (the canonical "role-neutral" sentinel -- NOT role 0 used as a
// wildcard). MeshCoreOta rows MUST have role_binding==Exact and
// expected_role_id of exactly 0 or 1. See boot_row_schema_valid.
// ---------------------------------------------------------------------
struct Nrf52ApprovedBootRow {
  uint32_t target_id = 0;
  uint32_t profile_id = 0;

  Nrf52LoaderKind loader_kind = Nrf52LoaderKind::Unknown;
  Nrf52RoleBinding role_binding = Nrf52RoleBinding::NotApplicable;
  // kNrf52BootFieldUnset (role-neutral) for VendorStock; exactly 0 or 1
  // for MeshCoreOta. Never role 0 used as an implicit "any role" value.
  uint32_t expected_role_id = kNrf52BootFieldUnset;
  // The exact 60-byte MeshCore Boot marker this row expects at
  // kNrf52BootInfoOffset. For VendorStock this is the GENUINE bytes
  // measured from the real stock artifact at that offset (typically
  // erased/0xFF, since the stock image never writes a marker there) --
  // never a hand-written placeholder. For MeshCoreOta this is the exact
  // artifact-verified marker (see verify_boot_info_artifact.py::check_artifact).
  uint8_t expected_boot_info[kNrf52BootInfoSize] = {0};

  uint8_t stock_code_sha256[32] = {0};   // sha256([0xF4000, 0xFD800))
  uint8_t cf2_sha256[32] = {0};          // sha256([0xFD800, 0xFE000))
  uint8_t mbr_sha256[32] = {0};          // sha256 of public MBR body [0, 0xFF8)
  uint8_t softdevice_sha256[32] = {0};   // sha256 of public S140 7.3.0 [0x1000, 0x27000)

  Nrf52BootVectorPair mbr_vectors;          // {0x20000400, 0x00000A81}
  Nrf52BootVectorPair softdevice_vectors;    // {0x200013C8, 0x00025E39}
  Nrf52BootVectorPair loader_vectors;        // measured from the actual stock bootloader build

  Nrf52FicrGeometry ficr_geometry;  // {0x1000, 0x100}

  uint32_t softdevice_info_magic = 0;    // @0x3004, expect 0x51B1E5DB
  uint32_t softdevice_info_size = 0;     // @0x3008, expect 0x00027000 (absolute, do not add 0x1000)
  uint16_t softdevice_fwid = 0;          // @0x300C, expect 0x0123
  uint16_t softdevice_variant = 0;       // @0x3010, expect 140
  uint32_t softdevice_version = 0;       // @0x3014, expect 7003000
  uint8_t softdevice_unique_id[20] = {0};  // @0x3018
};

// A row's loader_kind/role_binding/expected_role_id tuple must be exactly
// one of the two well-formed shapes below. An Unknown loader_kind (the
// default, e.g. from an under-initialized aggregate) is ALWAYS invalid --
// there is no implicit "neutral" fallback. See match_boot_catalogue /
// InvalidCatalogue: a single malformed row invalidates the whole compiled
// catalogue (fail-closed), since this table is compiled directly into the
// certified app binary and cannot be independently rejected per-row.
inline bool boot_row_schema_valid(const Nrf52ApprovedBootRow &row) {
  if (row.loader_kind == Nrf52LoaderKind::VendorStock) {
    return row.role_binding == Nrf52RoleBinding::NotApplicable &&
           row.expected_role_id == kNrf52BootFieldUnset;
  }
  if (row.loader_kind == Nrf52LoaderKind::MeshCoreOta) {
    return row.role_binding == Nrf52RoleBinding::Exact &&
           (row.expected_role_id == 0u || row.expected_role_id == 1u);
  }
  return false;
}

// ---------------------------------------------------------------------
// Raw, live-measured fields. Firmware populates this; this header never
// reads hardware itself. `have_measurement` must be false whenever any
// underlying read failed -- do not substitute zeros/guesses.
// ---------------------------------------------------------------------
enum class Nrf52BootInfoCaptureStatus : uint8_t {
  NotCaptured = 0,  // firmware has not attempted/completed a capture this pass
  Captured = 1,     // `boot_info` holds genuine bytes read from kNrf52BootInfoOffset
  Unreadable = 2,   // a capture was attempted but the underlying read failed
};

struct Nrf52RawBootMeasurement {
  bool have_measurement = false;

  uint32_t target_id = 0;
  // The ACTUAL profile this measurement was compiled/collected for (e.g.
  // kNrf52BootProfileXiao). Must be populated explicitly by the firmware
  // source (its compiled profile), never defaulted/assumed -- a row can
  // only ever be approved for the exact profile_id it was generated for,
  // so a future/foreign profile can never inherit a row by target_id alone.
  uint32_t profile_id = 0;
  // The ACTUAL application role this build was compiled for (0 or 1),
  // sourced from the real compiled board hook -- NEVER from an incoming
  // catalogue row, and NEVER decoded/inferred from the live boot_info
  // marker itself (that would make the marker self-certifying).
  uint32_t current_role_id = kNrf52BootFieldUnset;

  uint8_t stock_code_sha256[32] = {0};
  uint8_t cf2_sha256[32] = {0};
  uint8_t mbr_sha256[32] = {0};
  uint8_t softdevice_sha256[32] = {0};

  Nrf52BootVectorPair mbr_vectors;
  Nrf52BootVectorPair softdevice_vectors;
  Nrf52BootVectorPair loader_vectors;

  Nrf52FicrGeometry ficr_geometry;

  uint32_t softdevice_info_magic = 0;
  uint32_t softdevice_info_size = 0;
  uint16_t softdevice_fwid = 0;
  uint16_t softdevice_variant = 0;
  uint32_t softdevice_version = 0;
  uint8_t softdevice_unique_id[20] = {0};

  // The two RAW MBR selector words -- read from ABSOLUTE flash addresses
  // kNrf52MbrBootloaderAddrFieldOffset (0xFF8) and
  // kNrf52MbrParamPageAddrFieldOffset (0xFFC); see Nrf52MbrSelectorFields
  // above for why these must NEVER be read at a 0xFE000-page-relative
  // offset. `params_page_blank` separately records whether the WHOLE
  // retained MBR parameter page ([0xFE000,0xFF000), all 0x1000 bytes)
  // reads back as erased (0xFF) -- a distinct condition from the selector
  // words themselves. Only a wholly-erased params page may ever be
  // matched; this code never erases a page or infers blankness from
  // absence.
  Nrf52MbrSelectorFields mbr_selectors;
  bool params_page_blank = false;

  Nrf52UicrUpgradeFields uicr;

  // Bytes captured (bounded, during firmware's existing CF2 scan) from
  // kNrf52BootInfoOffset. `boot_info_capture_status` MUST be Captured for
  // `boot_info` to be meaningful -- a missing/unreadable capture is a
  // distinct typed state and is NEVER silently treated as an all-0xFF
  // marker (an erased/all-FF marker is itself a legitimate real value for
  // an unprovisioned VendorStock device, and must not be confused with
  // "we don't actually know").
  Nrf52BootInfoCaptureStatus boot_info_capture_status = Nrf52BootInfoCaptureStatus::NotCaptured;
  uint8_t boot_info[kNrf52BootInfoSize] = {0};
};

// Typed match outcomes. `None`-style implicit success states do not exist
// here on purpose: every non-Approved outcome must be handled explicitly
// by the caller, and no outcome here ever implies "proceed as normal".
enum class BootCatalogueOutcome : uint8_t {
  MissingCatalogue = 0,  // no approved rows compiled in at all
  IoError = 1,           // measurement could not be taken
  Unsupported = 2,       // policy tuple not recognized, or non-blank params page,
                         // or no row applicable to this target/profile/role
  Mismatch = 3,          // a row applicable to this target+profile(+role) exists but fields differ
  Approved = 4,          // a complete, exact row match
  InvalidCatalogue = 5,  // the compiled catalogue itself is malformed/ambiguous --
                         // never a source-success fallback; no config ID is ever returned
};

struct BootCatalogueMatchResult {
  BootCatalogueOutcome outcome = BootCatalogueOutcome::MissingCatalogue;
  uint32_t matched_config_id = 0;
};

inline bool bytes32_equal(const uint8_t (&a)[32], const uint8_t (&b)[32]) {
  return std::memcmp(a, b, 32) == 0;
}
inline bool bytes20_equal(const uint8_t (&a)[20], const uint8_t (&b)[20]) {
  return std::memcmp(a, b, 20) == 0;
}
inline bool bytes60_equal(const uint8_t (&a)[kNrf52BootInfoSize], const uint8_t (&b)[kNrf52BootInfoSize]) {
  return std::memcmp(a, b, kNrf52BootInfoSize) == 0;
}

// The fields common to EITHER loader kind (code/config/MBR/SD identity).
inline bool boot_row_common_fields_match(const Nrf52ApprovedBootRow &row, const Nrf52RawBootMeasurement &raw) {
  return bytes32_equal(row.stock_code_sha256, raw.stock_code_sha256) &&
         bytes32_equal(row.cf2_sha256, raw.cf2_sha256) && bytes32_equal(row.mbr_sha256, raw.mbr_sha256) &&
         bytes32_equal(row.softdevice_sha256, raw.softdevice_sha256) && row.mbr_vectors == raw.mbr_vectors &&
         row.softdevice_vectors == raw.softdevice_vectors && row.loader_vectors == raw.loader_vectors &&
         row.ficr_geometry == raw.ficr_geometry && row.softdevice_info_magic == raw.softdevice_info_magic &&
         row.softdevice_info_size == raw.softdevice_info_size && row.softdevice_fwid == raw.softdevice_fwid &&
         row.softdevice_variant == raw.softdevice_variant && row.softdevice_version == raw.softdevice_version &&
         bytes20_equal(row.softdevice_unique_id, raw.softdevice_unique_id);
}

// Loader-kind-specific approval requirement. Never performs I/O or
// decodes the marker -- it only byte-compares an ALREADY-captured raw
// marker against the row's approved expected bytes. A capture that is not
// Captured (NotCaptured/Unreadable) can never satisfy either kind: it is
// never silently treated as an all-0xFF erased marker.
inline bool boot_row_kind_specific_match(const Nrf52ApprovedBootRow &row, const Nrf52RawBootMeasurement &raw) {
  if (raw.boot_info_capture_status != Nrf52BootInfoCaptureStatus::Captured) {
    return false;
  }
  if (row.loader_kind == Nrf52LoaderKind::VendorStock) {
    // Role-neutral: a stock loader does not itself constrain which
    // supported application role is compiled in -- but current_role_id
    // must still be one of the genuinely supported roles, never an
    // unpopulated sentinel.
    return (raw.current_role_id == 0u || raw.current_role_id == 1u) &&
           bytes60_equal(row.expected_boot_info, raw.boot_info);
  }
  if (row.loader_kind == Nrf52LoaderKind::MeshCoreOta) {
    return raw.current_role_id == row.expected_role_id && bytes60_equal(row.expected_boot_info, raw.boot_info);
  }
  return false;  // Unknown: unreachable once boot_catalogue_is_valid has gated the table
}

inline bool boot_row_matches(const Nrf52ApprovedBootRow &row, const Nrf52RawBootMeasurement &raw) {
  return row.target_id == raw.target_id && row.profile_id == raw.profile_id &&
         boot_row_common_fields_match(row, raw) && boot_row_kind_specific_match(row, raw);
}

// A row is "applicable" to this raw measurement's (target, profile[, role])
// -- i.e. eligible to produce Mismatch rather than being silently skipped
// as Unsupported -- when target_id+profile_id match AND, for a
// role-bound (MeshCoreOta) row, the row's expected_role_id also matches
// the ACTUAL compiled role. A role-neutral (VendorStock) row is
// applicable regardless of role. This ensures a build compiled for role 1
// can never be judged against (or silently inherit) a role-0-only
// custom-loader row.
inline bool boot_row_is_applicable(const Nrf52ApprovedBootRow &row, const Nrf52RawBootMeasurement &raw) {
  if (row.target_id != raw.target_id || row.profile_id != raw.profile_id) {
    return false;
  }
  if (row.loader_kind == Nrf52LoaderKind::MeshCoreOta && row.expected_role_id != raw.current_role_id) {
    return false;
  }
  return true;
}

// Two rows share a "baseline-signed projection" (target, profile, role
// binding, loader code identity) when target/profile/role-binding and the
// stock-loader-code hash all agree. The signed manifest117/238 projection
// has no independent CF2/marker field, so the SAME projection must never
// map to two different CF2/marker/MBR/SD bindings within one compiled
// catalogue -- that would be an irreducibly ambiguous approval.
inline bool boot_rows_same_projection(const Nrf52ApprovedBootRow &a, const Nrf52ApprovedBootRow &b) {
  return a.target_id == b.target_id && a.profile_id == b.profile_id && a.role_binding == b.role_binding &&
         a.expected_role_id == b.expected_role_id && bytes32_equal(a.stock_code_sha256, b.stock_code_sha256);
}
inline bool boot_rows_identical_binding(const Nrf52ApprovedBootRow &a, const Nrf52ApprovedBootRow &b) {
  return bytes32_equal(a.cf2_sha256, b.cf2_sha256) && bytes32_equal(a.mbr_sha256, b.mbr_sha256) &&
         bytes32_equal(a.softdevice_sha256, b.softdevice_sha256) && a.mbr_vectors == b.mbr_vectors &&
         a.softdevice_vectors == b.softdevice_vectors && a.loader_vectors == b.loader_vectors &&
         a.ficr_geometry == b.ficr_geometry && a.softdevice_info_magic == b.softdevice_info_magic &&
         a.softdevice_info_size == b.softdevice_info_size && a.softdevice_fwid == b.softdevice_fwid &&
         a.softdevice_variant == b.softdevice_variant && a.softdevice_version == b.softdevice_version &&
         bytes20_equal(a.softdevice_unique_id, b.softdevice_unique_id) &&
         bytes60_equal(a.expected_boot_info, b.expected_boot_info);
}

// Catalogue-level validity: EVERY row must be individually well-formed
// (boot_row_schema_valid), and no two rows may share a baseline-signed
// projection while disagreeing on its binding. A single malformed/
// ambiguous row invalidates the WHOLE compiled table (fail-closed) --
// this table is compiled directly into the certified app binary and
// cannot be rejected on a lazy per-row basis once that app is running.
inline bool boot_catalogue_is_valid(const Nrf52ApprovedBootRow *rows, size_t row_count) {
  for (size_t i = 0; i < row_count; ++i) {
    if (!boot_row_schema_valid(rows[i])) {
      return false;
    }
    for (size_t j = i + 1; j < row_count; ++j) {
      if (boot_rows_same_projection(rows[i], rows[j]) && !boot_rows_identical_binding(rows[i], rows[j])) {
        return false;
      }
    }
  }
  return true;
}

// Pure matcher: never performs I/O. `rows`/`row_count` is normally
// `ota::platform::kApprovedBootCatalogueRows` /
// `ota::platform::kApprovedBootCatalogueRowCount` from the generated
// Nrf52ApprovedBootCatalogue.h, passed explicitly so this header has zero
// link-time dependency on whether that generated file exists yet.
inline BootCatalogueMatchResult match_boot_catalogue(const Nrf52RawBootMeasurement &raw,
                                                      const Nrf52ApprovedBootRow *rows, size_t row_count) {
  if (row_count == 0 || rows == nullptr) {
    return {BootCatalogueOutcome::MissingCatalogue, 0};
  }
  if (!raw.have_measurement) {
    return {BootCatalogueOutcome::IoError, 0};
  }
  if (!boot_catalogue_is_valid(rows, row_count)) {
    return {BootCatalogueOutcome::InvalidCatalogue, 0};
  }
  if (raw.ficr_geometry.code_page_size != kNrf52ExpectedCodePageSize ||
      raw.ficr_geometry.code_size != kNrf52ExpectedCodeSize) {
    return {BootCatalogueOutcome::Unsupported, 0};
  }

  // Resolve the policy/config_id from the RAW (mbr, uicr) tuple -- NOT the
  // effective/merged resolution (see resolve_boot_config_policy's doc
  // comment for why). Any mixed/conflicting/partial raw tuple is
  // Unsupported here, even if it happens to resolve to an
  // effective-looking match. `boot_config_id` names ONLY this raw
  // selector policy -- it is never a row/role/loader-kind identifier or a
  // journal-survivor state.
  uint32_t resolved_config_id = 0;
  if (!resolve_boot_config_policy(raw.mbr_selectors, raw.uicr, &resolved_config_id)) {
    return {BootCatalogueOutcome::Unsupported, 0};
  }
  // Separately, independently sanity-check that the EFFECTIVE resolution
  // (MBR-selector-wins-over-UICR) actually lands on the one required
  // absolute pair -- stock bootloader at 0xF4000, params page at 0xFE000.
  // This is redundant for the two currently-listed raw policies (both
  // resolve here by construction) but guards against any future policy
  // table entry whose raw tuple is listed yet whose effective resolution
  // would not actually point at the expected addresses.
  const Nrf52MbrSelectorFields effective = effective_mbr_fields(raw.mbr_selectors, raw.uicr);
  if (effective.bootloader_addr != kNrf52BootStockCodeOffset ||
      effective.params_page_addr != kNrf52BootMbrParamPageOffset) {
    return {BootCatalogueOutcome::Unsupported, 0};
  }
  // A non-blank params page is never approved/guessed/erased here -- it is
  // simply Unsupported. No VTOR/GPREGRET/TIMER2/journal "survivor"
  // heuristics are ever consulted.
  if (!raw.params_page_blank) {
    return {BootCatalogueOutcome::Unsupported, 0};
  }

  // Rows are ALTERNATIVES to compare fully -- never "take the first
  // applicable row and accept its marker". Every applicable row is tried;
  // Approved only on a genuine complete match; otherwise, if at least one
  // row was applicable, the result is Mismatch (never Unsupported, since
  // that would wrongly suggest "not applicable to you").
  bool found_applicable_row = false;
  for (size_t i = 0; i < row_count; ++i) {
    if (!boot_row_is_applicable(rows[i], raw)) {
      continue;
    }
    found_applicable_row = true;
    if (boot_row_matches(rows[i], raw)) {
      return {BootCatalogueOutcome::Approved, resolved_config_id};
    }
  }
  return {found_applicable_row ? BootCatalogueOutcome::Mismatch : BootCatalogueOutcome::Unsupported, 0};
}


}  // namespace platform
}  // namespace ota
