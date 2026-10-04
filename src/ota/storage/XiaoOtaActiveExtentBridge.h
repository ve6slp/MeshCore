#pragma once

// Bridges the app-side "what is the currently-running image, and how big
// is it?" question to the exact `active_image_extent` /
// `active_image_hash_sha256` fields the bootloader's install command
// (v1 and v2 alike) requires -- see the "Power-loss-safe install
// transaction" section referenced by boot-Hydra: on boot, the bootloader
// independently recomputes SHA-256 over internal flash
// [XIAO_OTA_APP_START, XIAO_OTA_APP_START + active_image_extent) and
// aborts the install unless it matches the value the app supplied here.
// Supplying a wrong/stale value therefore fails the install closed; it can
// never make an unsafe install succeed.
//
// CRITICAL, per explicit correction from both main and boot-Hydra:
// `XiaoOtaFloorReader` only ever answers "what did a *previous confirmed
// OTA install* write," never "what is running right now." A device's
// first-ever install (flashed only via USB/SWD) has no confirmed floor at
// all, and even once a floor exists, a user may have USB-reflashed a
// *different* image since it was written -- an old floor's hash would no
// longer match the actually-running app, AND the floor's recorded
// *extent* can also be stale/wrong-sized for the image now actually
// running. This bridge therefore no longer consults the floor at all for
// either the extent or the hash: BOTH are always derived fresh, at call
// time, from whatever is presently mapped at XIAO_OTA_APP_START.
//
// Exactly one source is trusted for the extent: the pinned Adafruit
// bootloader's own upstream "bank 0" settings (bank_0 == valid app,
// non-zero bank_0_size bounded by the app's max size, and a FRESH CRC-16
// over internal flash that must exactly equal the recorded bank_0_crc --
// including the literal value 0, which is a genuine CRC-16 output, NOT a
// flash-erased/"unset" sentinel (that is 0xFFFF), so it is never given a
// special-cased pass or categorical rejection; see
// test_active_extent_crc_zero.cpp for the accepted contract) -- the same
// "legacy extent" trust check xiao_ota_boot.c performs. If bank0 is
// missing/invalid/truncated, or this is built off-target (no safe
// memory-mapped read available), the extent is 0 -- there is NO guessed/
// full-range fallback and NO silent clamp: callers (see
// IOtaInstallCommandProviderV2 implementations) must treat extent==0 as
// "cannot safely determine what is running," and refuse to write an
// install command at all, rather than substitute a value that might not
// match the exact bytes the bootloader will independently re-hash on
// install.
//
// NOTE: the `bootloader_settings_t` field layout consulted by
// resolveCurrent()/decodeBank0FromRaw28Bytes() below is now CONFIRMED
// against boot-Hydra's pinned Adafruit nRF52 bootloader source (SDK11
// components/libraries/bootloader_dfu/bootloader_types.h + dfu_types.h):
// a packed 28-byte little-endian struct with bank_0 (u16) at offset 0,
// bank_0_crc (u16) at offset 2, bank_1 (u16) at offset 4, 2 bytes padding,
// then bank_0_size (u32) at offset 8. BANK_VALID_APP == 1. This replaces
// the earlier unconfirmed `settings[3]/[4]/[5]` u32-array-indexed guess.
//
// This header intentionally reads real memory-mapped hardware addresses
// only under NRF52840_XXAA (matching Nrf52FlashAdapter/XiaoOtaBootInfoReader's
// existing guard pattern) and fails closed (extent=0) off-target, so
// native/host tests can exercise the pure decode logic without needing
// real flash content.

#include <stdint.h>
#include <string.h>

#include "ota/platform/FlashRegion.h"
#include "ota/platform/Nrf52FlashLayoutContract.h"
#include "ota/storage/Crc32.h"
#include "ota/trust/Sha256.h"

namespace ota {
namespace storage {

// The mapped read range is wider than the installable application slot.
// Neither a readable address nor external staging capacity grants writes.
inline constexpr uint32_t kXiaoOtaAppStart = OTA_NRF52_INTERNAL_IMAGE_OFFSET;
inline constexpr uint32_t kXiaoOtaAppEnd = 0x000ED000u;
inline constexpr uint32_t kXiaoOtaAppMaxSize = kXiaoOtaAppEnd - kXiaoOtaAppStart;  // 811008 (raw mapped region).

// A trusted active/backup extent must end before the fixed installer at
// 0xC4000, even though reads beyond it would still be memory-safe.
inline constexpr uint32_t kXiaoOtaAppInstallMaxSize = OTA_NRF52_INTERNAL_IMAGE_SIZE;  // 643072

// Standard Nordic nRF5 SDK `bootloader_settings_t` bank-0 fields (bank_0,
// bank_0_crc, bank_0_size) as consumed by xiao_ota_boot.c's own
// `legacy_extent_from_bank0()`-equivalent check. `BANK_VALID_APP` is
// Nordic SDK's fixed sentinel value for "bank 0 holds a valid application."
inline constexpr uint32_t kBankValidApp = 0x01u;

struct XiaoOtaBank0Settings {
  uint32_t bank_0 = 0;
  uint16_t bank_0_crc = 0;
  uint32_t bank_0_size = 0;
};

struct XiaoOtaActiveExtentInfo {
  uint32_t active_image_extent = 0;
  uint8_t active_image_hash_sha256[32] = {};
};

// Result of one bounded step of incremental extent resolution (see
// XiaoOtaIncrementalExtentResolver below): resolving the extent itself
// (a fresh CRC-16 over up to the whole 628 KiB installable image) is exactly the
// same kind of potentially-large synchronous cost as an image SHA-256
// hash, so per-tick callers (XiaoOtaTrialHealthMonitor) must drive it in
// bounded steps rather than one blocking whole-image call.
enum class XiaoOtaExtentResolutionStep : uint8_t {
  InProgress = 0,  // more bounded work remains; call again next tick.
  Resolved = 1,    // *out_image/*out_extent are now valid.
  Failed = 2,      // bank0 invalid/missing/off-target/CRC mismatch; fail closed, never retried.
};

class XiaoOtaActiveExtentBridge {
public:
  // Pure logic, host-testable: given already-read bank-0 settings and a
  // pointer to the (fake or real) app image bytes, decides the extent to
  // trust, matching xiao_ota_boot.c's legacy-extent check exactly:
  // bank_0 must equal kBankValidApp, bank_0_size must be non-zero and not
  // exceed the app's max size, and a fresh CRC-16 (Nordic crc16_compute,
  // poly 0x1021, seed 0xFFFF) over the first bank_0_size bytes must
  // EXACTLY equal the recorded bank_0_crc -- including when that equality
  // holds at the literal value 0 (see test_active_extent_crc_zero.cpp);
  // bank_0_crc is never treated as a "set/unset" sentinel. Returns 0 on
  // ANY mismatch (invalid marker, zero/oversized/truncated size, CRC
  // mismatch, or a null image) -- there is no guessed/full-range
  // fallback here; 0 means "do not trust this bank0," and callers must
  // fail closed rather than substitute a value.
  static uint32_t resolveExtentFromBank0(const XiaoOtaBank0Settings& bank0, const uint8_t* app_image,
                                        uint32_t app_image_len) {
    // NOTE (Astra CRC contract, accepted): bank_0_crc is a genuine stored
    // CRC-16 value, not a "set/unset" sentinel -- 0x0000 is NOT the
    // flash-erased pattern (that is 0xFFFF) and is a value the real
    // Nordic crc16_compute() can and does legitimately produce for some
    // byte sequences (see test_active_extent_crc_zero.cpp). The bank0
    // record is therefore trusted or rejected SOLELY by an exact
    // computed == stored comparison below, including the (rare but
    // valid) case where the freshly computed CRC is itself 0 and the
    // stored bank_0_crc is also 0 -- never by a categorical "crc == 0
    // means invalid/skip" pre-check.
    if (bank0.bank_0 != kBankValidApp || bank0.bank_0_size == 0 ||
        bank0.bank_0_size > kXiaoOtaAppInstallMaxSize || app_image == nullptr ||
        bank0.bank_0_size > app_image_len) {
      return 0;
    }
    const uint16_t computed = crc16Compute(app_image, bank0.bank_0_size);
    if (computed != bank0.bank_0_crc) {
      return 0;
    }
    return bank0.bank_0_size;
  }

  // Pure logic, host-testable: computes the fresh SHA-256 that must be
  // reported alongside `extent`, over the first `extent` bytes of
  // `app_image` (never cached/persisted -- always recomputed here).
  static void computeFreshHash(const uint8_t* app_image, uint32_t extent, uint8_t out_sha256[32]) {
    trust::Sha256::hash(app_image, extent, out_sha256);
  }

  // End-to-end resolution used by real callers: trusts ONLY a fresh,
  // valid bank-0 record (see resolveExtentFromBank0() above) -- no floor
  // priority, no guessed/full-range fallback, no silent clamp. On any
  // invalid/unavailable bank0, returns extent=0 and an all-zero hash;
  // callers must treat that as "cannot safely determine the running
  // image" and refuse to proceed (see IOtaInstallCommandProviderV2
  // implementations, which fail closed on active_image_extent == 0).
  static XiaoOtaActiveExtentInfo resolve(const XiaoOtaBank0Settings& bank0, const uint8_t* app_image,
                                        uint32_t app_image_len) {
    XiaoOtaActiveExtentInfo info;  // active_image_extent=0, hash=all-zero by default (fail closed).
    const uint32_t extent = resolveExtentFromBank0(bank0, app_image, app_image_len);
    if (extent == 0) {
      return info;
    }
    info.active_image_extent = extent;
    computeFreshHash(app_image, extent, info.active_image_hash_sha256);
    return info;
  }

  // Nordic SDK11 `bootloader_settings_t` (see
  // components/libraries/bootloader_dfu/bootloader_types.h /
  // dfu_types.h, confirmed against the pinned Adafruit bootloader source
  // by boot-Hydra): a packed 28-byte little-endian struct --
  //   offset 0  u16 bank_0        (BANK_VALID_APP == 1)
  //   offset 2  u16 bank_0_crc
  //   offset 4  u16 bank_1
  //   offset 6  u16 <padding, unused>
  //   offset 8  u32 bank_0_size
  //   (remaining bytes unused by this bridge)
  // Pure, host-testable decode of one raw 28-byte settings-page image --
  // no pointer/address logic here, so this can be exhaustively fixture-
  // tested independent of real hardware.
  static constexpr uint32_t kBootloaderSettingsRawBytes = 28;

  static XiaoOtaBank0Settings decodeBank0FromRaw28Bytes(const uint8_t raw[kBootloaderSettingsRawBytes]) {
    XiaoOtaBank0Settings bank0;
    bank0.bank_0 = static_cast<uint32_t>(raw[0]) | (static_cast<uint32_t>(raw[1]) << 8);
    bank0.bank_0_crc = static_cast<uint16_t>(static_cast<uint32_t>(raw[2]) | (static_cast<uint32_t>(raw[3]) << 8));
    bank0.bank_0_size = static_cast<uint32_t>(raw[8]) | (static_cast<uint32_t>(raw[9]) << 8) |
                       (static_cast<uint32_t>(raw[10]) << 16) | (static_cast<uint32_t>(raw[11]) << 24);
    return bank0;
  }

  // Real hardware entry point: reads the pinned Adafruit bootloader
  // settings page and the currently-running app image directly via
  // memory-mapped pointers (nRF52840 internal flash is memory-mapped), and
  // resolves the extent/hash exactly as `resolve()` does above. Fails
  // closed (extent=0) on any build target other than real nRF52840
  // hardware, since these fixed addresses are meaningless off-target.
  static XiaoOtaActiveExtentInfo resolveCurrent() {
#if defined(NRF52840_XXAA)
    constexpr uint32_t kBootloaderSettingsAddress = 0x000FF000u;  // SETTINGS_ADDR under NRF52840_XXAA.
    const uint8_t* raw = reinterpret_cast<const uint8_t*>(kBootloaderSettingsAddress);
    const XiaoOtaBank0Settings bank0 = decodeBank0FromRaw28Bytes(raw);
    const uint8_t* app_image = reinterpret_cast<const uint8_t*>(kXiaoOtaAppStart);
    return resolve(bank0, app_image, kXiaoOtaAppMaxSize);
#else
    XiaoOtaActiveExtentInfo info;
    info.active_image_extent = 0;  // no safe memory-mapped read off-target.
    return info;
#endif
  }

  // NOTE: an all-at-once "resolveExtentAndImageCurrent()" companion to
  // resolveCurrent() (returning the raw pointer+extent without the
  // SHA-256) previously lived here, but its own extent resolution was
  // ITSELF a single blocking whole-image CRC-16 call -- exactly the
  // per-tick anti-pattern this bridge exists to avoid. Removed (unused,
  // no callers) in favour of XiaoOtaIncrementalExtentResolver below,
  // which drives the identical bank0 CRC-16 check in bounded steps for
  // genuine per-tick callers such as XiaoOtaTrialHealthMonitor.

  // Nordic nRF5 SDK's crc16_compute() (poly 0x1021, seed 0xFFFF, no final
  // XOR) -- reimplemented here byte-for-byte so this app-side check stays
  // independently verifiable without a build dependency on the vendored
  // SoftDevice/bootloader SDK tree, matching the exact function
  // xiao_ota_boot.c calls for its own bank-0 legacy-extent trust check.
  static uint16_t crc16Compute(const uint8_t* data, uint32_t len) {
    uint16_t crc = 0xFFFFu;
    for (uint32_t i = 0; i < len; ++i) {
      crc = crc16Step(crc, data[i]);
    }
    return crc;
  }

  // One-byte step of the same CRC-16 algorithm crc16Compute() runs in a
  // single blocking loop -- factored out so an incremental caller (see
  // XiaoOtaIncrementalExtentResolver below) can resume the identical
  // running CRC across many bounded calls and reach the exact same final
  // value crc16Compute() would over the whole buffer in one call.
  static uint16_t crc16Step(uint16_t crc, uint8_t byte) {
    crc = static_cast<uint16_t>((crc >> 8) | (crc << 8));
    crc = static_cast<uint16_t>(crc ^ byte);
    crc = static_cast<uint16_t>(crc ^ ((crc & 0xFFu) >> 4));
    crc = static_cast<uint16_t>(crc ^ ((crc << 8) << 4));
    crc = static_cast<uint16_t>(crc ^ (((crc & 0xFFu) << 4) << 1));
    return crc;
  }
};

// Drives XiaoOtaActiveExtentBridge's bank0-CRC extent resolution in
// bounded per-call steps instead of one blocking whole-image CRC-16 --
// resolveExtentFromBank0()/resolveCurrent() remain correct for genuinely
// one-time-per-install-command callers (e.g. building an install command
// itself), but a PER-TICK caller such as XiaoOtaTrialHealthMonitor must
// never pay a single synchronous 628 KiB CRC in one call during a live
// trial-boot window. Stateful and single-use: construct one instance per
// boot's resolution attempt (matching the monitor's own "resolved/failed
// exactly once" contract).
class XiaoOtaIncrementalExtentResolver {
public:
  // A bank0 settings record plus a bounded pointer to the image bytes it
  // describes, read at one moment in time. `image_len` is the number of
  // bytes ACTUALLY available at `image` -- real hardware callers always
  // report the full mapped region (kXiaoOtaAppMaxSize), but an injected
  // test snapshot may deliberately report a SHORTER length than
  // bank0.bank_0_size to exercise the "recorded size exceeds what is
  // really there to read" fail-closed path below without ever reading
  // out of bounds of the fixture buffer.
  struct Snapshot {
    XiaoOtaBank0Settings bank0;
    const uint8_t* image = nullptr;
    uint32_t image_len = 0;
  };
  // Injectable seam so native/host tests can drive the REAL production
  // incremental-CRC stepping logic in step() below against fixture bank0
  // records/image bytes -- instead of a second, potentially-drifting
  // reimplementation of the algorithm -- while every real on-device
  // caller (the default no-arg constructor) is completely unaffected and
  // keeps reading genuine nRF52840 memory-mapped hardware exactly as
  // before, failing closed off-target exactly as before.
  using SnapshotReader = Snapshot (*)();

  XiaoOtaIncrementalExtentResolver() = default;
  explicit XiaoOtaIncrementalExtentResolver(SnapshotReader injected_reader) : injected_reader_(injected_reader) {}

  // Drives at most `max_bytes` of work per call. Must be called
  // repeatedly until it returns something other than InProgress; once it
  // returns Resolved or Failed, every subsequent call returns that same
  // latched result immediately without doing any further work.
  XiaoOtaExtentResolutionStep step(uint32_t max_bytes, const uint8_t** out_image, uint32_t* out_extent) {
    if (done_) {
      *out_image = resolved_ ? image_ : nullptr;
      *out_extent = resolved_ ? extent_ : 0;
      return resolved_ ? XiaoOtaExtentResolutionStep::Resolved : XiaoOtaExtentResolutionStep::Failed;
    }

    if (!bank0_read_) {
      bank0_read_ = true;
      uint32_t image_len = 0;
      if (injected_reader_ != nullptr) {
        const Snapshot snap = injected_reader_();
        bank0_ = snap.bank0;
        image_ = snap.image;
        image_len = snap.image_len;
      } else {
#if defined(NRF52840_XXAA)
        constexpr uint32_t kBootloaderSettingsAddress = 0x000FF000u;  // SETTINGS_ADDR under NRF52840_XXAA.
        const uint8_t* raw = reinterpret_cast<const uint8_t*>(kBootloaderSettingsAddress);
        bank0_ = XiaoOtaActiveExtentBridge::decodeBank0FromRaw28Bytes(raw);
        image_ = reinterpret_cast<const uint8_t*>(kXiaoOtaAppStart);
        image_len = kXiaoOtaAppMaxSize;
#else
        image_ = nullptr;  // no safe memory-mapped read off-target.
#endif
      }
      // NOTE (Astra CRC contract, accepted): bank_0_crc is a genuine
      // stored CRC-16 value, not a "set/unset" sentinel -- see the
      // matching note on resolveExtentFromBank0() above. It is
      // deliberately NOT checked here; the running CRC computed below is
      // compared against it by exact equality once fully accumulated,
      // including the case where both are 0.
      if (image_ == nullptr || bank0_.bank_0 != kBankValidApp || bank0_.bank_0_size == 0 ||
          bank0_.bank_0_size > kXiaoOtaAppInstallMaxSize || bank0_.bank_0_size > image_len) {
        done_ = true;
        resolved_ = false;
        *out_image = nullptr;
        *out_extent = 0;
        return XiaoOtaExtentResolutionStep::Failed;
      }
      running_crc_ = 0xFFFFu;
      progress_ = 0;
    }

    const uint32_t remaining = bank0_.bank_0_size - progress_;
    const uint32_t take = remaining < max_bytes ? remaining : max_bytes;
    for (uint32_t i = 0; i < take; ++i) {
      running_crc_ = XiaoOtaActiveExtentBridge::crc16Step(running_crc_, image_[progress_ + i]);
    }
    progress_ += take;

    if (progress_ < bank0_.bank_0_size) {
      *out_image = nullptr;
      *out_extent = 0;
      return XiaoOtaExtentResolutionStep::InProgress;
    }

    done_ = true;
    resolved_ = (running_crc_ == bank0_.bank_0_crc);
    extent_ = resolved_ ? bank0_.bank_0_size : 0;
    *out_image = resolved_ ? image_ : nullptr;
    *out_extent = extent_;
    return resolved_ ? XiaoOtaExtentResolutionStep::Resolved : XiaoOtaExtentResolutionStep::Failed;
  }

  // Bytes CRC-accumulated so far (0 until the bank0 record has been read
  // and validated, then monotonically increasing by at most `max_bytes`
  // per step() call until it reaches the recorded extent size at
  // Resolved/Failed). A legitimate, side-effect-free, read-only
  // diagnostic accessor -- exposes no internal mutable state, only a
  // count -- used by tests (and, if ever wanted, real diagnostics/UI) to
  // prove measurable, bounded-per-pass progress across a genuinely
  // large image instead of only observing the final Resolved/Failed
  // result.
  uint32_t bytesProcessedSoFar() const { return progress_; }

private:
  SnapshotReader injected_reader_ = nullptr;
  bool bank0_read_ = false;
  bool done_ = false;
  bool resolved_ = false;
  XiaoOtaBank0Settings bank0_;
  const uint8_t* image_ = nullptr;
  uint32_t extent_ = 0;
  uint32_t progress_ = 0;
  uint16_t running_crc_ = 0xFFFFu;
};

}  // namespace storage
}  // namespace ota
