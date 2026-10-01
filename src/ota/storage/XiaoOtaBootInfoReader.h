#pragma once

// Read-only reader/validator for the XIAO nRF52840 custom bootloader's
// immutable boot-info/capability marker (see
// bootloader/xiao_nrf52840_ota/include/xiao_ota_boot_info.h, which this
// file must remain byte-for-byte compatible with).
//
// This marker is baked into the flashed BOOTLOADER binary itself (not the
// OTA journal, not application flash) at a fixed, memory-mapped internal
// flash address. It is the ONLY authoritative source of "is a qualified
// MeshCore custom bootloader actually present" -- board/JEDEC identity,
// compiled feature flags, or backendAvailable() must never be used as a
// substitute. A stock/unmodified Adafruit bootloader (or any other
// unqualified image) leaves this address erased (all 0xFF), which never
// matches the magic and never produces a valid CRC: this is the expected,
// common, non-error case for a device that has not had this bootloader
// installed, not corruption, and callers MUST fail closed exactly the
// same way as for any other invalid result -- "no qualified custom boot
// detected", refuse to claim install capability.
//
// Header-only so it can be exercised directly by PlatformIO's native unit
// tests (against a synthetic in-memory buffer) without any build-config
// change; only readCurrent() touches the real fixed hardware address, and
// only on an actual nRF52840 build.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ota/storage/Crc32.h"

#if defined(NRF52840_XXAA)
#include <Arduino.h>
#endif

namespace ota {
namespace storage {

class XiaoOtaBootInfoReader {
public:
  static constexpr uint32_t kMagic = 0x584F4249u;  // "XOBI"
  static constexpr uint16_t kFormatVersion = 1u;
  // magic(4)+format_version(2)+struct_bytes(2)+board_target_id(4)+
  // role_id(4)+capability_flags(4)+key_id(2)+algorithm_id(2)+
  // trusted_public_key(32)+crc32(4) = 60.
  static constexpr uint32_t kStructBytes = 60;
  static constexpr uint32_t kCrcOffset = kStructBytes - 4;  // 56
  // Fixed address inside the bootloader's BOOTLOADER_CONFIG flash region
  // (0xFD800..0xFE000); nRF52840 internal flash is memory-mapped, so this
  // is read directly as a pointer on real hardware.
  static constexpr uint32_t kAddress = 0xFDC00u;

  struct Info {
    uint32_t boardTargetId = 0;
    uint32_t roleId = 0;
    uint32_t capabilityFlags = 0;
    uint16_t keyId = 0;
    uint16_t algorithmId = 0;
    uint8_t trustedPublicKey[32] = {};
  };

  // Typed classification of a raw record, distinguishing the two failure
  // shapes that isValidRecord()/decode() otherwise collapse into a single
  // `false`: a genuinely blank/erased marker (every byte 0xFF -- the
  // expected, common, non-error "no custom bootloader has ever been
  // installed" case) versus a non-blank record that still fails magic/
  // format/CRC validation (torn write, tampering, or any other genuine
  // corruption). Callers that need to know "is it actually safe to assume
  // ordinary factory/legacy behaviour" MUST treat Corrupt the same as an
  // outright read failure (fail closed), never the same as Blank.
  enum class RecordStatus { Blank, Found, Corrupt };

  static bool isValidRecord(const uint8_t* record, size_t len) {
    if (record == nullptr || len != kStructBytes) return false;
    if (getU32(record) != kMagic) return false;
    if (getU16(record + 4) != kFormatVersion) return false;
    if (getU16(record + 6) != static_cast<uint16_t>(kStructBytes)) return false;
    return getU32(record + kCrcOffset) == Crc32::computeFinalized(record, kCrcOffset);
  }

  // Decodes a raw 60-byte record already read from flash (or a synthetic
  // buffer, for host tests). Returns false -- leaving `out` untouched --
  // on any validation failure, including all-0xFF.
  static bool decode(const uint8_t* record, size_t len, Info& out) {
    if (!isValidRecord(record, len)) return false;
    out.boardTargetId = getU32(record + 8);
    out.roleId = getU32(record + 12);
    out.capabilityFlags = getU32(record + 16);
    out.keyId = getU16(record + 20);
    out.algorithmId = getU16(record + 22);
    memcpy(out.trustedPublicKey, record + 24, sizeof(out.trustedPublicKey));
    return true;
  }

  // Real hardware entry point: reads the fixed, memory-mapped bootloader
  // address directly and validates it. Fails closed (false) on a build
  // that isn't an actual nRF52840 target too, rather than dereferencing an
  // address that has no meaning there.
  static bool readCurrent(Info& out) {
#if defined(NRF52840_XXAA)
    const uint8_t* p = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(kAddress));
    return decode(p, kStructBytes, out);
#else
    (void)out;
    return false;
#endif
  }

  // Classifies a raw record buffer into Blank/Found/Corrupt (see
  // RecordStatus's doc comment). `out` is populated only on Found.
  static RecordStatus classify(const uint8_t* record, size_t len, Info& out) {
    if (record == nullptr || len != kStructBytes) {
      // Can't even inspect the bytes -- never assume this means blank.
      return RecordStatus::Corrupt;
    }
    if (isValidRecord(record, len)) {
      decode(record, len, out);
      return RecordStatus::Found;
    }
    for (size_t i = 0; i < len; ++i) {
      if (record[i] != 0xFFu) return RecordStatus::Corrupt;
    }
    return RecordStatus::Blank;
  }

  // Real hardware entry point for classify(): reads the fixed, memory-
  // mapped bootloader address directly. On a build that isn't an actual
  // nRF52840 target, there is no meaningful address to dereference at all
  // -- this is genuinely unknown, not a positive "blank" observation, so
  // it fails closed as Corrupt rather than Blank.
  static RecordStatus classifyCurrent(Info& out) {
#if defined(NRF52840_XXAA)
    const uint8_t* p = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(kAddress));
    return classify(p, kStructBytes, out);
#else
    (void)out;
    return RecordStatus::Corrupt;
#endif
  }

private:
  static uint16_t getU16(const uint8_t* in) {
    return static_cast<uint16_t>(in[0]) | (static_cast<uint16_t>(in[1]) << 8);
  }
  static uint32_t getU32(const uint8_t* in) {
    return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
  }
};

}  // namespace storage
}  // namespace ota
