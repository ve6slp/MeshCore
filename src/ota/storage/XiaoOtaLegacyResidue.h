#pragma once

// Pure, dependency-free predicates recognizing a SPECIFIC, already-
// identified historical contamination pattern at floor A of the XIAO
// nRF52840 journal partition (see SenseCapQspiLayout.h), so a LAB-only
// gated erase command can refuse to touch anything except exactly that
// known-bad residue -- never a valid floor record, an unknown pattern, or
// any other non-blank content (floor B, or any of the six transaction
// sectors: install command A/B, install state A/B, confirmation A/B).
//
// Header-only so the gating logic itself (not just the wire command) is
// directly host-testable, including a "no mutation on anything but the
// exact expected input" regression using a fake erase-counter harness.

#include <stdint.h>

namespace ota {
namespace storage {

class XiaoOtaLegacyResidue {
public:
  // The known contamination pattern occupies exactly 37 bytes starting at
  // sector offset 3: byte[3 + i] == 0xE7 ^ (i * 11) for i in [0, 37).
  static constexpr uint32_t kResidueStartOffset = 3;
  static constexpr uint32_t kResidueByteCount = 37;

  // True iff `sector` (>= kResidueStartOffset + kResidueByteCount bytes)
  // matches the known pattern EXACTLY at the expected offsets, AND every
  // other byte in `sector` is 0xFF (erased/blank). Any unknown byte
  // anywhere -- including a byte that merely LOOKS erased-adjacent but
  // isn't -- fails this check; it is intentionally not a fuzzy match.
  static bool isKnownContaminationResidue(const uint8_t* sector, uint32_t len) {
    if (sector == nullptr || len < kResidueStartOffset + kResidueByteCount) return false;
    for (uint32_t i = 0; i < len; ++i) {
      if (i >= kResidueStartOffset && i < kResidueStartOffset + kResidueByteCount) {
        const uint32_t k = i - kResidueStartOffset;
        const uint8_t expected = static_cast<uint8_t>(0xE7u ^ static_cast<uint8_t>((k * 11u) & 0xFFu));
        if (sector[i] != expected) return false;
      } else if (sector[i] != 0xFFu) {
        return false;
      }
    }
    return true;
  }

  // Windowed equivalent of isKnownContaminationResidue(): checks ONLY the
  // bytes in `window` (a `window_len`-byte slice starting at absolute
  // sector offset `base_offset`) against the same exact expected pattern.
  // Calling this once per contiguous, non-overlapping window covering an
  // entire sector (e.g. 32 x 128-byte windows for a 4096-byte sector) and
  // requiring EVERY call to return true is byte-for-byte equivalent to a
  // single isKnownContaminationResidue() call over the whole sector --
  // this lets a caller stream the check through a small fixed-size stack
  // buffer instead of materializing the whole sector at once.
  static bool isKnownContaminationResidueWindow(uint32_t base_offset, const uint8_t* window,
                                                uint32_t window_len) {
    if (window == nullptr) return window_len == 0;
    for (uint32_t i = 0; i < window_len; ++i) {
      const uint32_t abs = base_offset + i;
      if (abs >= kResidueStartOffset && abs < kResidueStartOffset + kResidueByteCount) {
        const uint32_t k = abs - kResidueStartOffset;
        const uint8_t expected = static_cast<uint8_t>(0xE7u ^ static_cast<uint8_t>((k * 11u) & 0xFFu));
        if (window[i] != expected) return false;
      } else if (window[i] != 0xFFu) {
        return false;
      }
    }
    return true;
  }

  // True iff every byte of `sector` is 0xFF (erased/never-written).
  static bool isEntirelyBlank(const uint8_t* sector, uint32_t len) {
    if (sector == nullptr) return len == 0;
    for (uint32_t i = 0; i < len; ++i) {
      if (sector[i] != 0xFFu) return false;
    }
    return true;
  }

  // The full erase-safety gate: floor A must match the EXACT known
  // contamination residue (never a valid/unrecognized floor record), AND
  // floor B, AND all six transaction sectors (install command A/B, state
  // A/B, confirmation A/B) must be entirely blank -- i.e. no pending
  // transaction, no confirmed record anywhere else in the journal. Any
  // deviation refuses the erase; this function performs NO flash I/O
  // itself, only the decision, so it can be exhaustively tested without
  // real hardware.
  static bool isSafeToEraseFloorA(const uint8_t* floor_a, uint32_t floor_a_len, const uint8_t* floor_b,
                                 uint32_t floor_b_len, const uint8_t* const tx_sectors[6],
                                 uint32_t tx_sector_len) {
    if (!isKnownContaminationResidue(floor_a, floor_a_len)) return false;
    if (!isEntirelyBlank(floor_b, floor_b_len)) return false;
    if (tx_sectors == nullptr) return false;
    for (uint32_t i = 0; i < 6u; ++i) {
      if (!isEntirelyBlank(tx_sectors[i], tx_sector_len)) return false;
    }
    return true;
  }
};

}  // namespace storage
}  // namespace ota
