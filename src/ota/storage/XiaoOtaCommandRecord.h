#pragma once

// Byte-exact codec and power-loss-safe A/B writer for the XIAO nRF52840
// bootloader's `xiao_ota_command_t` install-command record (see
// bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h, which this file
// must remain byte-for-byte compatible with -- field order, width, and
// endianness are fixed by that contract and are NOT renegotiable here).
//
// This is a completely separate record/signature from the transport wire
// descriptor in src/ota/protocol/OtaDescriptor.h: the 71-byte descriptor
// prefix embedded below reuses ota::trust::CanonicalDescriptor's layout
// (already byte-compatible), but the *signature* over those 71 bytes must
// be obtained offline (bootloader/xiao_nrf52840_ota/tools/sign_image.py --
// the only holder of the private key) and delivered to this firmware; it
// is never derived from, or interchangeable with, the transport
// descriptor's own Ed25519 signature.
//
// Header-only so it can be exercised directly by PlatformIO's native unit
// tests without any build-config change.

#include <stdint.h>
#include <string.h>

#include "ota/platform/FlashRegion.h"
#include "ota/storage/Crc32.h"
#include "ota/storage/XiaoOtaTransactionalWriter.h"
#include "ota/trust/CanonicalDescriptor.h"
#include "ota/trust/TrustTypes.h"

namespace ota {
namespace storage {

// Fields needed to build one xiao_ota_command_t record. `descriptor` and
// `descriptor_signature` MUST be the bootloader-form 71-byte canonical
// descriptor and its independently-obtained (offline-signed) Ed25519
// signature -- see file header.
struct XiaoOtaCommandFields {
  uint32_t sequence = 0;
  uint64_t transaction_nonce = 0;
  trust::ImageDescriptor descriptor;
  uint8_t descriptor_signature[64] = {};
  uint32_t active_image_extent = 0;
  uint8_t active_image_hash_sha256[32] = {};
};

class XiaoOtaCommandRecord {
public:
  static constexpr uint32_t kMagic = 0x584F5441u;
  static constexpr uint32_t kCommitMarker = 0x434F4D54u;
  static constexpr uint16_t kRecordVersion = 1u;  // XIAO_OTA_COMMAND_VERSION_LEGACY_V1;
                                                   // the only value the bootloader's
                                                   // record_valid() currently accepts.
  static constexpr uint32_t kDescriptorBytes = 71u;  // trust::CanonicalDescriptor::kMessageBytes
  static constexpr uint32_t kSignatureBytes = 64u;
  static constexpr uint32_t kHashBytes = 32u;

  // magic(4) + record_version(2) + record_bytes(2) + sequence(4) +
  // nonce(8) + descriptor(71) + signature(64) + active_image_extent(4) +
  // active_image_hash(32) + reserved(1) + crc32(4) + commit_marker(4).
  static constexpr uint32_t kRecordBytes = 4 + 2 + 2 + 4 + 8 + kDescriptorBytes + kSignatureBytes + 4 +
                                            kHashBytes + 1 + 4 + 4;  // = 200
  static constexpr uint32_t kCrcOffset = kRecordBytes - 8;      // 192: everything before crc32
  static constexpr uint32_t kCommitMarkerOffset = kRecordBytes - 4;  // 196

  // Sector geometry: exactly two erase-unit-sized slots (A, B), alternated
  // by `sequence`. `region` must therefore be exactly 2 erase units.
  static bool regionIsValid(const platform::FlashRegion& region) {
    return region.isValid() && region.sizeBytes() == (2u * region.eraseUnitBytes()) &&
           region.eraseUnitBytes() >= kRecordBytes;
  }

  // Serializes `fields` into `out` (must be >= kRecordBytes). Returns
  // kRecordBytes on success, 0 on failure (e.g. buffer too small).
  static uint32_t serialize(const XiaoOtaCommandFields& fields, uint8_t* out, uint32_t out_len) {
    if (out == nullptr || out_len < kRecordBytes) {
      return 0;
    }
    uint32_t pos = 0;
    putU32(out + pos, kMagic);
    pos += 4;
    putU16(out + pos, kRecordVersion);
    pos += 2;
    putU16(out + pos, static_cast<uint16_t>(kRecordBytes));
    pos += 2;
    putU32(out + pos, fields.sequence);
    pos += 4;
    putU64(out + pos, fields.transaction_nonce);
    pos += 8;

    uint8_t descriptor_bytes[kDescriptorBytes] = {};
    if (trust::CanonicalDescriptor::serialize(fields.descriptor, descriptor_bytes, sizeof(descriptor_bytes)) !=
        kDescriptorBytes) {
      return 0;
    }
    memcpy(out + pos, descriptor_bytes, kDescriptorBytes);
    pos += kDescriptorBytes;

    memcpy(out + pos, fields.descriptor_signature, kSignatureBytes);
    pos += kSignatureBytes;

    putU32(out + pos, fields.active_image_extent);
    pos += 4;
    memcpy(out + pos, fields.active_image_hash_sha256, kHashBytes);
    pos += kHashBytes;

    out[pos] = 0;  // reserved
    pos += 1;

    const uint32_t crc = Crc32::computeFinalized(out, kCrcOffset);
    putU32(out + pos, crc);
    pos += 4;

    putU32(out + pos, kCommitMarker);
    pos += 4;

    return pos;  // == kRecordBytes
  }

  // Validates a raw record buffer using the exact same rules as the
  // bootloader's `xiao_ota_command_valid()` (magic, version, declared
  // size, CRC over [0, kCrcOffset), and commit marker as the final word).
  static bool isValidRecord(const uint8_t* record, uint32_t len) {
    if (record == nullptr || len != kRecordBytes) {
      return false;
    }
    if (getU32(record) != kMagic) return false;
    if (record[4] != static_cast<uint8_t>(kRecordVersion) || record[5] != 0) return false;
    if (getU16(record + 6) != static_cast<uint16_t>(kRecordBytes)) return false;
    if (getU32(record + kCommitMarkerOffset) != kCommitMarker) return false;
    const uint32_t stored_crc = getU32(record + kCrcOffset);
    return stored_crc == Crc32::computeFinalized(record, kCrcOffset);
  }

  // Durably writes `fields` into whichever of the two slots in `region`
  // is NOT the currently-newest valid one (A/B alternation), following
  // write -> readback-verify -> commit-marker-already-included ordering:
  // the whole record (including its trailing commit marker) is built in
  // RAM first, then the destination slot is erased and programmed in one
  // pass, then read back byte-for-byte before being trusted. This mirrors
  // storage::Journal's discipline while remaining a distinct, smaller,
  // boot-defined record shape. Never leaves both slots invalid: the slot
  // not being written is left completely untouched.
  //
  // Defined out-of-line below (after XiaoOtaCommandSlotClassifier, which
  // both this and XiaoOtaCommandRecordV2::writeNext() depend on to
  // correctly recognize a live record of the OTHER command version
  // sharing these same two physical slots -- see that classifier's
  // header comment for why a version-specific scan alone is unsafe).
  static bool writeNext(platform::FlashRegion& region, const XiaoOtaCommandFields& fields,
                        uint32_t* out_sequence_written = nullptr);

  // Returns the newest valid record currently in `region`, if any. An
  // unreadable slot aborts the whole read (returns false) rather than
  // being treated as "no valid record here": the true newest record
  // could be sitting in that currently-unreadable slot, with only an
  // older one in the other, readable slot -- callers must never act on a
  // partial/possibly-stale answer. Also returns false (not the older
  // record) when the true newest-by-sequence slot actually holds a valid
  // XiaoOtaCommandRecordV2 record instead -- see writeNext()'s comment
  // above; defined out-of-line for the same reason.
  static bool readNewest(const platform::FlashRegion& region, uint8_t out_record[kRecordBytes]);

  // Public sequence-field accessor over an already-validated record
  // buffer (offset 8, identical position/width to
  // XiaoOtaCommandRecordV2::sequenceOf()) -- exposed so the shared
  // union-aware slot classifier can compare generations across both
  // command record versions without duplicating the offset.
  static uint32_t sequenceOf(const uint8_t* record) { return getU32(record + 8); }

  // Extracts just the embedded descriptor's monotonic_counter_le field
  // from an already-validated record buffer (offset 20 for the
  // descriptor prefix + 32+4+4+8+1+4 = 53 bytes into it, per
  // CanonicalDescriptor's field order). Callers must call isValidRecord()
  // first; this does not re-check the CRC/marker.
  static uint32_t descriptorMonotonicCounter(const uint8_t* record) {
    constexpr uint32_t kDescriptorStart = 20u;
    constexpr uint32_t kCounterOffsetInDescriptor = 32 + 4 + 4 + 8 + 1 + 4;  // = 53
    return getU32(record + kDescriptorStart + kCounterOffsetInDescriptor);
  }

private:
  static bool readSlot(const platform::FlashRegion& region, uint32_t slot, uint8_t out[kRecordBytes]) {
    const uint32_t slot_offset = slot * region.eraseUnitBytes();
    return platform::isOk(region.read(slot_offset, out, kRecordBytes));
  }

  static void putU16(uint8_t* out, uint16_t v) {
    out[0] = static_cast<uint8_t>(v & 0xFFu);
    out[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
  }
  static void putU32(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>(v & 0xFFu);
    out[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    out[2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
    out[3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
  }
  static void putU64(uint8_t* out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
      out[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    }
  }
  static uint16_t getU16(const uint8_t* in) {
    return static_cast<uint16_t>(in[0]) | (static_cast<uint16_t>(in[1]) << 8);
  }
  static uint32_t getU32(const uint8_t* in) {
    return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
  }
};

// Fields needed to build one xiao_ota_command_v2_t record. Unlike v1,
// `wire_descriptor` and `signature` here are NOT re-derived/re-signed --
// they must be copied verbatim from the transport's own already-verified
// 59-byte canonical wire descriptor (encodeOtaDescriptorCanonical()
// output, see src/ota/protocol/OtaDescriptor.h) and its 64-byte Ed25519
// signature (the exact bytes DescriptorVerifier::verifyPolicy() already
// authenticated). No offline signing tool/private key is involved for v2.
struct XiaoOtaCommandV2Fields {
  uint32_t sequence = 0;
  uint64_t transaction_nonce = 0;
  uint8_t wire_descriptor[59] = {};
  uint8_t signature_ed25519[64] = {};
  uint32_t active_image_extent = 0;
  uint8_t active_image_hash_sha256[32] = {};
};

// Byte-exact codec and power-loss-safe A/B writer for the bootloader's
// `xiao_ota_command_v2_t` record (bootloader/xiao_nrf52840_ota/include/
// xiao_ota_record.h). Structurally a sibling of XiaoOtaCommandRecord (v1):
// same magic/CRC/commit-marker discipline, same A/B alternation, same
// FlashRegion sector geometry -- the only difference is the embedded
// signed payload (59-byte transport wire descriptor instead of the
// 71-byte legacy little-endian one) and the resulting overall size (188
// vs 200 bytes). v1 remains fully supported/unchanged for legacy,
// per-device-targeted installs; this is purely additive.
class XiaoOtaCommandRecordV2 {
public:
  static constexpr uint32_t kMagic = XiaoOtaCommandRecord::kMagic;
  static constexpr uint32_t kCommitMarker = XiaoOtaCommandRecord::kCommitMarker;
  static constexpr uint16_t kRecordVersion = 2u;  // XIAO_OTA_COMMAND_VERSION_WIRE_V2
  static constexpr uint32_t kWireDescriptorBytes = 59u;  // XIAO_OTA_WIRE_DESCRIPTOR_SIZE
  static constexpr uint32_t kSignatureBytes = 64u;
  static constexpr uint32_t kHashBytes = 32u;

  // magic(4) + record_version(2) + record_bytes(2) + sequence(4) +
  // nonce(8) + wire_descriptor(59) + signature(64) + active_image_extent(4) +
  // active_image_hash(32) + reserved(1) + crc32(4) + commit_marker(4) = 188.
  static constexpr uint32_t kRecordBytes = 4 + 2 + 2 + 4 + 8 + kWireDescriptorBytes + kSignatureBytes +
                                            4 + kHashBytes + 1 + 4 + 4;  // = 188
  static constexpr uint32_t kCrcOffset = kRecordBytes - 8;          // 180
  static constexpr uint32_t kCommitMarkerOffset = kRecordBytes - 4;  // 184

  static bool regionIsValid(const platform::FlashRegion& region) {
    return region.isValid() && region.sizeBytes() == (2u * region.eraseUnitBytes()) &&
           region.eraseUnitBytes() >= kRecordBytes;
  }

  static uint32_t serialize(const XiaoOtaCommandV2Fields& fields, uint8_t* out, uint32_t out_len) {
    if (out == nullptr || out_len < kRecordBytes) {
      return 0;
    }
    uint32_t pos = 0;
    putU32(out + pos, kMagic);
    pos += 4;
    putU16(out + pos, kRecordVersion);
    pos += 2;
    putU16(out + pos, static_cast<uint16_t>(kRecordBytes));
    pos += 2;
    putU32(out + pos, fields.sequence);
    pos += 4;
    putU64(out + pos, fields.transaction_nonce);
    pos += 8;

    memcpy(out + pos, fields.wire_descriptor, kWireDescriptorBytes);
    pos += kWireDescriptorBytes;

    memcpy(out + pos, fields.signature_ed25519, kSignatureBytes);
    pos += kSignatureBytes;

    putU32(out + pos, fields.active_image_extent);
    pos += 4;
    memcpy(out + pos, fields.active_image_hash_sha256, kHashBytes);
    pos += kHashBytes;

    out[pos] = 0;  // reserved
    pos += 1;

    const uint32_t crc = Crc32::computeFinalized(out, kCrcOffset);
    putU32(out + pos, crc);
    pos += 4;

    putU32(out + pos, kCommitMarker);
    pos += 4;

    return pos;  // == kRecordBytes
  }

  static bool isValidRecord(const uint8_t* record, uint32_t len) {
    if (record == nullptr || len != kRecordBytes) {
      return false;
    }
    if (getU32(record) != kMagic) return false;
    if (record[4] != static_cast<uint8_t>(kRecordVersion) || record[5] != 0) return false;
    if (getU16(record + 6) != static_cast<uint16_t>(kRecordBytes)) return false;
    if (getU32(record + kCommitMarkerOffset) != kCommitMarker) return false;
    const uint32_t stored_crc = getU32(record + kCrcOffset);
    return stored_crc == Crc32::computeFinalized(record, kCrcOffset);
  }

  static bool writeNext(platform::FlashRegion& region, const XiaoOtaCommandV2Fields& fields,
                        uint32_t* out_sequence_written = nullptr);

  // Same fail-closed rationale as XiaoOtaCommandRecord::readNewest():
  // an unreadable slot aborts the whole read rather than being skipped,
  // and this returns false (not the older V2 record) when the true
  // newest-by-sequence slot actually holds a valid legacy V1 record
  // instead. Defined out-of-line, after XiaoOtaCommandSlotClassifier.
  static bool readNewest(const platform::FlashRegion& region, uint8_t out_record[kRecordBytes]);

  // Extracts the wire descriptor's big-endian securityCounter field
  // (offset 20 for the wire descriptor prefix + 2+2+1+4+4+32 = 45 bytes
  // into it, per encodeOtaDescriptorCanonical()'s field order) from an
  // already-validated record buffer. Callers must call isValidRecord()
  // first.
  static uint32_t descriptorMonotonicCounter(const uint8_t* record) {
    constexpr uint32_t kDescriptorStart = 20u;
    constexpr uint32_t kCounterOffsetInDescriptor = 2 + 2 + 1 + 4 + 4 + 32;  // = 45
    return getBE32(record + kDescriptorStart + kCounterOffsetInDescriptor);
  }

  // Offset of the embedded 59-byte wire descriptor within an already-
  // validated record buffer -- magic(4)+version(2)+bytes(2)+sequence(4)+
  // nonce(8) = 20. Exposed so callers can durably bind a
  // transaction_nonce to "this exact authorized transfer" by comparing
  // wire descriptors byte-for-byte, without duplicating the offset.
  static constexpr uint32_t kWireDescriptorOffset = 20u;

  static uint32_t sequenceOf(const uint8_t* record) { return getU32(record + 8); }
  static uint64_t transactionNonceOf(const uint8_t* record) { return getU64(record + 12); }
  static const uint8_t* wireDescriptorOf(const uint8_t* record) { return record + kWireDescriptorOffset; }

private:
  static bool readSlot(const platform::FlashRegion& region, uint32_t slot, uint8_t out[kRecordBytes]) {
    const uint32_t slot_offset = slot * region.eraseUnitBytes();
    return platform::isOk(region.read(slot_offset, out, kRecordBytes));
  }

  static void putU16(uint8_t* out, uint16_t v) {
    out[0] = static_cast<uint8_t>(v & 0xFFu);
    out[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
  }
  static void putU32(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>(v & 0xFFu);
    out[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    out[2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
    out[3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
  }
  static void putU64(uint8_t* out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
      out[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    }
  }
  static uint16_t getU16(const uint8_t* in) {
    return static_cast<uint16_t>(in[0]) | (static_cast<uint16_t>(in[1]) << 8);
  }
  static uint32_t getU32(const uint8_t* in) {
    return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
  }
  static uint64_t getU64(const uint8_t* in) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
      v = (v << 8) | static_cast<uint64_t>(in[i]);
    }
    return v;
  }
  // Wire descriptor fields are big-endian (transport convention), unlike
  // this record's own little-endian header fields.
  static uint32_t getBE32(const uint8_t* in) {
    return (static_cast<uint32_t>(in[0]) << 24) | (static_cast<uint32_t>(in[1]) << 16) |
           (static_cast<uint32_t>(in[2]) << 8) | static_cast<uint32_t>(in[3]);
  }
};

// Fields for the bootloader's CURRENT (and, per the bootloader owner, now
// SOLE) accepted install-command format: xiao_ota_command_v2_t at
// record_version 3 (bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h
// -- "v2"/"_v2" naming on that struct is kept only to avoid a mechanical
// rename, not because a newer struct name exists). Identical to
// XiaoOtaCommandV2Fields except for one inserted field:
// `admitted_signer_public_key_ed25519` -- the Ed25519 public key the
// CURRENTLY RUNNING app already verified the manifest signer against via
// its own existing MeshCore admin-identity trust mechanism (see
// OtaFirmwareStorageSink::onAuthorizedSession()'s `controller` parameter,
// which is this exact key, captured once per authenticated/authorized
// attempt and threaded through unchanged to commit()). There is no
// compile-time-fixed trust anchor anymore (the bootloader owner's record_
// version 2 shape, which had one, has itself been retired) -- the
// bootloader re-verifies signature_ed25519 over wire_descriptor under
// EXACTLY this embedded key at install time.
struct XiaoOtaCommandV3Fields {
  uint32_t sequence = 0;
  uint64_t transaction_nonce = 0;
  uint8_t wire_descriptor[59] = {};
  uint8_t admitted_signer_public_key_ed25519[32] = {};
  uint8_t signature_ed25519[64] = {};
  uint32_t active_image_extent = 0;
  uint8_t active_image_hash_sha256[32] = {};
};

// Byte-exact codec and power-loss-safe A/B writer for
// xiao_ota_command_v2_t at record_version
// XIAO_OTA_COMMAND_VERSION_CURRENT (3). Structurally a sibling of
// XiaoOtaCommandRecordV2: same magic/CRC/commit-marker discipline, same
// A/B alternation, same FlashRegion sector geometry -- the only
// difference is the inserted 32-byte admitted-signer-key field and the
// resulting overall size (220 vs 188 bytes). V1/V2 remain defined above
// for any still-referencing test/legacy code, but per the bootloader
// owner's current source (not merely a chat claim -- see
// XIAO_OTA_COMMAND_VERSION_CURRENT's doc-comment, which states BOTH the
// legacy 71-byte v1 format AND the no-admitted-key record_version-2 shape
// have been retired) V3 is the only format an actual bootloader build
// will currently accept.
class XiaoOtaCommandRecordV3 {
public:
  static constexpr uint32_t kMagic = XiaoOtaCommandRecord::kMagic;
  static constexpr uint32_t kCommitMarker = XiaoOtaCommandRecord::kCommitMarker;
  static constexpr uint16_t kRecordVersion = 3u;  // XIAO_OTA_COMMAND_VERSION_CURRENT
  static constexpr uint32_t kWireDescriptorBytes = 59u;  // XIAO_OTA_WIRE_DESCRIPTOR_SIZE
  static constexpr uint32_t kSignerKeyBytes = 32u;
  static constexpr uint32_t kSignatureBytes = 64u;
  static constexpr uint32_t kHashBytes = 32u;

  // magic(4) + record_version(2) + record_bytes(2) + sequence(4) +
  // nonce(8) + wire_descriptor(59) + admitted_signer_public_key(32) +
  // signature(64) + active_image_extent(4) + active_image_hash(32) +
  // reserved(1) + crc32(4) + commit_marker(4) = 220.
  static constexpr uint32_t kRecordBytes = 4 + 2 + 2 + 4 + 8 + kWireDescriptorBytes + kSignerKeyBytes +
                                            kSignatureBytes + 4 + kHashBytes + 1 + 4 + 4;  // = 220
  static constexpr uint32_t kCrcOffset = kRecordBytes - 8;           // 212
  static constexpr uint32_t kCommitMarkerOffset = kRecordBytes - 4;  // 216

  static bool regionIsValid(const platform::FlashRegion& region) {
    return region.isValid() && region.sizeBytes() == (2u * region.eraseUnitBytes()) &&
           region.eraseUnitBytes() >= kRecordBytes;
  }

  static uint32_t serialize(const XiaoOtaCommandV3Fields& fields, uint8_t* out, uint32_t out_len) {
    if (out == nullptr || out_len < kRecordBytes) {
      return 0;
    }
    uint32_t pos = 0;
    putU32(out + pos, kMagic);
    pos += 4;
    putU16(out + pos, kRecordVersion);
    pos += 2;
    putU16(out + pos, static_cast<uint16_t>(kRecordBytes));
    pos += 2;
    putU32(out + pos, fields.sequence);
    pos += 4;
    putU64(out + pos, fields.transaction_nonce);
    pos += 8;

    memcpy(out + pos, fields.wire_descriptor, kWireDescriptorBytes);
    pos += kWireDescriptorBytes;

    memcpy(out + pos, fields.admitted_signer_public_key_ed25519, kSignerKeyBytes);
    pos += kSignerKeyBytes;

    memcpy(out + pos, fields.signature_ed25519, kSignatureBytes);
    pos += kSignatureBytes;

    putU32(out + pos, fields.active_image_extent);
    pos += 4;
    memcpy(out + pos, fields.active_image_hash_sha256, kHashBytes);
    pos += kHashBytes;

    out[pos] = 0;  // reserved
    pos += 1;

    const uint32_t crc = Crc32::computeFinalized(out, kCrcOffset);
    putU32(out + pos, crc);
    pos += 4;

    putU32(out + pos, kCommitMarker);
    pos += 4;

    return pos;  // == kRecordBytes
  }

  static bool isValidRecord(const uint8_t* record, uint32_t len) {
    if (record == nullptr || len != kRecordBytes) {
      return false;
    }
    if (getU32(record) != kMagic) return false;
    if (record[4] != static_cast<uint8_t>(kRecordVersion) || record[5] != 0) return false;
    if (getU16(record + 6) != static_cast<uint16_t>(kRecordBytes)) return false;
    if (getU32(record + kCommitMarkerOffset) != kCommitMarker) return false;
    const uint32_t stored_crc = getU32(record + kCrcOffset);
    return stored_crc == Crc32::computeFinalized(record, kCrcOffset);
  }

  static bool writeNext(platform::FlashRegion& region, const XiaoOtaCommandV3Fields& fields,
                        uint32_t* out_sequence_written = nullptr);

  // Same fail-closed rationale as XiaoOtaCommandRecordV2::readNewest().
  static bool readNewest(const platform::FlashRegion& region, uint8_t out_record[kRecordBytes]);

  static uint32_t descriptorMonotonicCounter(const uint8_t* record) {
    constexpr uint32_t kDescriptorStart = 20u;
    constexpr uint32_t kCounterOffsetInDescriptor = 2 + 2 + 1 + 4 + 4 + 32;  // = 45
    return getBE32(record + kDescriptorStart + kCounterOffsetInDescriptor);
  }

  static constexpr uint32_t kWireDescriptorOffset = 20u;
  // Admitted-signer key immediately follows the 59-byte wire descriptor.
  static constexpr uint32_t kAdmittedSignerKeyOffset = kWireDescriptorOffset + kWireDescriptorBytes;  // = 79

  static uint32_t sequenceOf(const uint8_t* record) { return getU32(record + 8); }
  static uint64_t transactionNonceOf(const uint8_t* record) { return getU64(record + 12); }
  static const uint8_t* wireDescriptorOf(const uint8_t* record) { return record + kWireDescriptorOffset; }
  static const uint8_t* admittedSignerKeyOf(const uint8_t* record) { return record + kAdmittedSignerKeyOffset; }

private:
  static bool readSlot(const platform::FlashRegion& region, uint32_t slot, uint8_t out[kRecordBytes]) {
    const uint32_t slot_offset = slot * region.eraseUnitBytes();
    return platform::isOk(region.read(slot_offset, out, kRecordBytes));
  }

  static void putU16(uint8_t* out, uint16_t v) {
    out[0] = static_cast<uint8_t>(v & 0xFFu);
    out[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
  }
  static void putU32(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>(v & 0xFFu);
    out[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    out[2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
    out[3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
  }
  static void putU64(uint8_t* out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
      out[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    }
  }
  static uint16_t getU16(const uint8_t* in) {
    return static_cast<uint16_t>(in[0]) | (static_cast<uint16_t>(in[1]) << 8);
  }
  static uint32_t getU32(const uint8_t* in) {
    return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
  }
  static uint64_t getU64(const uint8_t* in) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
      v = (v << 8) | static_cast<uint64_t>(in[i]);
    }
    return v;
  }
  static uint32_t getBE32(const uint8_t* in) {
    return (static_cast<uint32_t>(in[0]) << 24) | (static_cast<uint32_t>(in[1]) << 16) |
           (static_cast<uint32_t>(in[2]) << 8) | static_cast<uint32_t>(in[3]);
  }
};

// Result of classifying one physical command A/B slot, agnostic of which
// record version (if any) actually occupies it.
struct XiaoOtaCommandSlotView {
  enum class Kind { None, V1, V2, V3 };
  bool read_ok = false;  // false: I/O failure -- caller MUST fail closed.
  bool valid = false;    // true iff a valid V1, V2, OR V3 record was found.
  Kind kind = Kind::None;
  uint32_t sequence = 0;  // meaningful only when `valid` is true.
};

// Shared, union-aware slot classifier for the command A/B region: the
// SAME two physical erase-unit slots may transiently hold a legacy
// 200-byte XiaoOtaCommandRecord (v1), a 188-byte XiaoOtaCommandRecordV2
// record (also now retired per the bootloader's own current source, but
// still classified so an old slot is never misread as empty), or the
// current 220-byte XiaoOtaCommandRecordV3 record -- the bootloader
// dispatches by the record_version byte at a fixed offset regardless of
// which type physically occupies a slot (see OtaFirmwareStorageSink's
// v1/v2/v3 constructor comment in src/helpers/ota/OtaFirmwareBackend.h). A
// version-specific writer/reader that only ever recognizes its OWN
// record type would otherwise treat a live record of ANOTHER type as
// "empty" -- risking erasing/overwriting it, resetting the generation
// sequence, or selecting the wrong (older) slot as "current". This
// helper reads the largest of the three record sizes once per slot and
// classifies it as whichever type (if any) actually validates there,
// exposing a common `sequence` field (byte offset 8, identical
// position/width in all three record layouts) so all three
// XiaoOtaCommandRecord* types can compare and preserve the true max
// generation across every type, never just their own.
class XiaoOtaCommandSlotClassifier {
public:
  // The largest of the three record sizes (200 for v1, 188 for v2, 220
  // for v3): reading this many bytes per slot is always sufficient to
  // validate any of them, since each format's CRC/marker/size fields are
  // fully contained within its own (smaller-or-equal) declared size.
  static constexpr uint32_t kMaxRecordBytes = XiaoOtaCommandRecordV3::kRecordBytes;
  static_assert(XiaoOtaCommandRecordV3::kRecordBytes >= XiaoOtaCommandRecord::kRecordBytes &&
                XiaoOtaCommandRecordV3::kRecordBytes >= XiaoOtaCommandRecordV2::kRecordBytes,
                "kMaxRecordBytes must cover the largest of the three command record sizes");

  static XiaoOtaCommandSlotView classify(const platform::FlashRegion& region, uint32_t slot) {
    XiaoOtaCommandSlotView view;
    // The real xiao_command_region is always erase-unit-sized (4096B) --
    // far larger than kMaxRecordBytes -- but defensively refuse to read
    // past a too-small region rather than assume that layout.
    if (region.eraseUnitBytes() < kMaxRecordBytes) return view;
    uint8_t buf[kMaxRecordBytes];
    const uint32_t slot_offset = slot * region.eraseUnitBytes();
    if (!platform::isOk(region.read(slot_offset, buf, kMaxRecordBytes))) {
      return view;  // read_ok stays false: caller must fail closed.
    }
    view.read_ok = true;
    if (XiaoOtaCommandRecordV3::isValidRecord(buf, XiaoOtaCommandRecordV3::kRecordBytes)) {
      view.valid = true;
      view.kind = XiaoOtaCommandSlotView::Kind::V3;
      view.sequence = XiaoOtaCommandRecordV3::sequenceOf(buf);
    } else if (XiaoOtaCommandRecord::isValidRecord(buf, XiaoOtaCommandRecord::kRecordBytes)) {
      view.valid = true;
      view.kind = XiaoOtaCommandSlotView::Kind::V1;
      view.sequence = XiaoOtaCommandRecord::sequenceOf(buf);
    } else if (XiaoOtaCommandRecordV2::isValidRecord(buf, XiaoOtaCommandRecordV2::kRecordBytes)) {
      view.valid = true;
      view.kind = XiaoOtaCommandSlotView::Kind::V2;
      view.sequence = XiaoOtaCommandRecordV2::sequenceOf(buf);
    }
    return view;
  }
};

inline bool XiaoOtaCommandRecord::writeNext(platform::FlashRegion& region, const XiaoOtaCommandFields& fields,
                                            uint32_t* out_sequence_written) {
  if (!regionIsValid(region)) {
    return false;
  }

  uint32_t current_slot = 0;
  bool have_current = false;
  uint32_t current_sequence = 0;
  for (uint32_t slot = 0; slot < 2u; ++slot) {
    // Classify BOTH command record versions in this slot (not just our
    // own v1 shape): an I/O read failure is not "no valid record here",
    // and a valid live V2 record here must still be recognized as the
    // slot's true occupant/generation -- see XiaoOtaCommandSlotClassifier.
    const XiaoOtaCommandSlotView view = XiaoOtaCommandSlotClassifier::classify(region, slot);
    if (!view.read_ok) return false;
    if (!view.valid) continue;
    if (!have_current || view.sequence >= current_sequence) {
      have_current = true;
      current_sequence = view.sequence;
      current_slot = slot;
    }
  }

  if (have_current && current_sequence == 0xFFFFFFFFu) {
    // Sequence exhaustion: never silently wrap back to 0, which would
    // make the brand-new record indistinguishable from (or falsely
    // older than) the true oldest record ever written. Refuse instead.
    return false;
  }

  const uint32_t target_slot = have_current ? (1u - current_slot) : 0u;
  const uint32_t new_sequence = have_current ? (current_sequence + 1u) : 1u;

  XiaoOtaCommandFields to_write = fields;
  to_write.sequence = new_sequence;

  uint8_t record[kRecordBytes];
  if (serialize(to_write, record, sizeof(record)) != kRecordBytes) {
    return false;
  }

  const uint32_t slot_offset = target_slot * region.eraseUnitBytes();
  if (!writeOtaJournalRecordTransactional(region, slot_offset, record, kRecordBytes, kCommitMarkerOffset,
                                          kRecordBytes - kCommitMarkerOffset)) {
    return false;
  }

  uint8_t readback[kRecordBytes];
  if (!platform::isOk(region.read(slot_offset, readback, kRecordBytes))) {
    return false;
  }
  if (memcmp(record, readback, kRecordBytes) != 0 || !isValidRecord(readback, kRecordBytes)) {
    return false;
  }

  if (out_sequence_written != nullptr) {
    *out_sequence_written = new_sequence;
  }
  return true;
}

inline bool XiaoOtaCommandRecord::readNewest(const platform::FlashRegion& region,
                                             uint8_t out_record[kRecordBytes]) {
  if (!regionIsValid(region)) return false;
  bool found = false;
  uint32_t best_sequence = 0;
  XiaoOtaCommandSlotView::Kind best_kind = XiaoOtaCommandSlotView::Kind::None;
  uint32_t best_slot = 0;
  for (uint32_t slot = 0; slot < 2u; ++slot) {
    const XiaoOtaCommandSlotView view = XiaoOtaCommandSlotClassifier::classify(region, slot);
    if (!view.read_ok) return false;
    if (!view.valid) continue;
    if (!found || view.sequence >= best_sequence) {
      found = true;
      best_sequence = view.sequence;
      best_kind = view.kind;
      best_slot = slot;
    }
  }
  if (!found) return false;
  // The true newest-by-sequence slot actually holds the OTHER command
  // version: this typed reader must not return an older own-version
  // record and pretend it is "the newest" -- report no result instead.
  if (best_kind != XiaoOtaCommandSlotView::Kind::V1) return false;
  uint8_t buf[kRecordBytes];
  if (!readSlot(region, best_slot, buf)) return false;
  if (!isValidRecord(buf, kRecordBytes)) return false;
  memcpy(out_record, buf, kRecordBytes);
  return true;
}

inline bool XiaoOtaCommandRecordV2::writeNext(platform::FlashRegion& region, const XiaoOtaCommandV2Fields& fields,
                                              uint32_t* out_sequence_written) {
  if (!regionIsValid(region)) {
    return false;
  }

  uint32_t current_slot = 0;
  bool have_current = false;
  uint32_t current_sequence = 0;
  for (uint32_t slot = 0; slot < 2u; ++slot) {
    // Same union-aware rationale as XiaoOtaCommandRecord::writeNext():
    // a live legacy V1 record in either slot must be recognized (never
    // treated as "empty") and its generation preserved/extended.
    const XiaoOtaCommandSlotView view = XiaoOtaCommandSlotClassifier::classify(region, slot);
    if (!view.read_ok) return false;
    if (!view.valid) continue;
    if (!have_current || view.sequence >= current_sequence) {
      have_current = true;
      current_sequence = view.sequence;
      current_slot = slot;
    }
  }

  if (have_current && current_sequence == 0xFFFFFFFFu) {
    return false;  // sequence exhaustion: refuse rather than wrap to 0.
  }

  const uint32_t target_slot = have_current ? (1u - current_slot) : 0u;
  const uint32_t new_sequence = have_current ? (current_sequence + 1u) : 1u;

  XiaoOtaCommandV2Fields to_write = fields;
  to_write.sequence = new_sequence;

  uint8_t record[kRecordBytes];
  if (serialize(to_write, record, sizeof(record)) != kRecordBytes) {
    return false;
  }

  const uint32_t slot_offset = target_slot * region.eraseUnitBytes();
  if (!writeOtaJournalRecordTransactional(region, slot_offset, record, kRecordBytes, kCommitMarkerOffset,
                                          kRecordBytes - kCommitMarkerOffset)) {
    return false;
  }

  uint8_t readback[kRecordBytes];
  if (!platform::isOk(region.read(slot_offset, readback, kRecordBytes))) {
    return false;
  }
  if (memcmp(record, readback, kRecordBytes) != 0 || !isValidRecord(readback, kRecordBytes)) {
    return false;
  }

  if (out_sequence_written != nullptr) {
    *out_sequence_written = new_sequence;
  }
  return true;
}

inline bool XiaoOtaCommandRecordV2::readNewest(const platform::FlashRegion& region,
                                               uint8_t out_record[kRecordBytes]) {
  if (!regionIsValid(region)) return false;
  bool found = false;
  uint32_t best_sequence = 0;
  XiaoOtaCommandSlotView::Kind best_kind = XiaoOtaCommandSlotView::Kind::None;
  uint32_t best_slot = 0;
  for (uint32_t slot = 0; slot < 2u; ++slot) {
    const XiaoOtaCommandSlotView view = XiaoOtaCommandSlotClassifier::classify(region, slot);
    if (!view.read_ok) return false;
    if (!view.valid) continue;
    if (!found || view.sequence >= best_sequence) {
      found = true;
      best_sequence = view.sequence;
      best_kind = view.kind;
      best_slot = slot;
    }
  }
  if (!found) return false;
  // Same rationale as XiaoOtaCommandRecord::readNewest(): refuse rather
  // than returning an older V2 record when the true newest is a V1 one.
  if (best_kind != XiaoOtaCommandSlotView::Kind::V2) return false;
  uint8_t buf[kRecordBytes];
  if (!readSlot(region, best_slot, buf)) return false;
  if (!isValidRecord(buf, kRecordBytes)) return false;
  memcpy(out_record, buf, kRecordBytes);
  return true;
}

inline bool XiaoOtaCommandRecordV3::writeNext(platform::FlashRegion& region, const XiaoOtaCommandV3Fields& fields,
                                              uint32_t* out_sequence_written) {
  if (!regionIsValid(region)) {
    return false;
  }

  uint32_t current_slot = 0;
  bool have_current = false;
  uint32_t current_sequence = 0;
  for (uint32_t slot = 0; slot < 2u; ++slot) {
    // Same union-aware rationale as XiaoOtaCommandRecordV2::writeNext():
    // a live V1/V2 record in either slot must be recognized (never
    // treated as "empty") and its generation preserved/extended.
    const XiaoOtaCommandSlotView view = XiaoOtaCommandSlotClassifier::classify(region, slot);
    if (!view.read_ok) return false;
    if (!view.valid) continue;
    if (!have_current || view.sequence >= current_sequence) {
      have_current = true;
      current_sequence = view.sequence;
      current_slot = slot;
    }
  }

  if (have_current && current_sequence == 0xFFFFFFFFu) {
    return false;  // sequence exhaustion: refuse rather than wrap to 0.
  }

  const uint32_t target_slot = have_current ? (1u - current_slot) : 0u;
  const uint32_t new_sequence = have_current ? (current_sequence + 1u) : 1u;

  XiaoOtaCommandV3Fields to_write = fields;
  to_write.sequence = new_sequence;

  uint8_t record[kRecordBytes];
  if (serialize(to_write, record, sizeof(record)) != kRecordBytes) {
    return false;
  }

  const uint32_t slot_offset = target_slot * region.eraseUnitBytes();
  if (!writeOtaJournalRecordTransactional(region, slot_offset, record, kRecordBytes, kCommitMarkerOffset,
                                          kRecordBytes - kCommitMarkerOffset)) {
    return false;
  }

  uint8_t readback[kRecordBytes];
  if (!platform::isOk(region.read(slot_offset, readback, kRecordBytes))) {
    return false;
  }
  if (memcmp(record, readback, kRecordBytes) != 0 || !isValidRecord(readback, kRecordBytes)) {
    return false;
  }

  if (out_sequence_written != nullptr) {
    *out_sequence_written = new_sequence;
  }
  return true;
}

inline bool XiaoOtaCommandRecordV3::readNewest(const platform::FlashRegion& region,
                                               uint8_t out_record[kRecordBytes]) {
  if (!regionIsValid(region)) return false;
  bool found = false;
  uint32_t best_sequence = 0;
  XiaoOtaCommandSlotView::Kind best_kind = XiaoOtaCommandSlotView::Kind::None;
  uint32_t best_slot = 0;
  for (uint32_t slot = 0; slot < 2u; ++slot) {
    const XiaoOtaCommandSlotView view = XiaoOtaCommandSlotClassifier::classify(region, slot);
    if (!view.read_ok) return false;
    if (!view.valid) continue;
    if (!found || view.sequence >= best_sequence) {
      found = true;
      best_sequence = view.sequence;
      best_kind = view.kind;
      best_slot = slot;
    }
  }
  if (!found) return false;
  // Same rationale as XiaoOtaCommandRecordV2::readNewest(): refuse rather
  // than returning an older V1/V2 record when the true newest is a
  // different version.
  if (best_kind != XiaoOtaCommandSlotView::Kind::V3) return false;
  uint8_t buf[kRecordBytes];
  if (!readSlot(region, best_slot, buf)) return false;
  if (!isValidRecord(buf, kRecordBytes)) return false;
  memcpy(out_record, buf, kRecordBytes);
  return true;
}

// READ-ONLY reader for the bootloader-owned `xiao_ota_floor_t` confirmed-
// counter record (0x192000/0x193000 on XIAO's layout). This firmware never
// writes this record -- only the bootloader does, after a trial-boot
// confirms -- but reading it back lets the app durably re-seed its own
// RAM-only anti-rollback counter across a reset, instead of forgetting the
// confirmed floor on every reboot (see LabMonotonicCounter in
// variants/xiao_nrf52/OtaLabBackend.cpp for the consumer of this).
class XiaoOtaFloorReader {
public:
  static constexpr uint32_t kMagic = 0x58464C52u;  // XIAO_OTA_FLOOR_MAGIC
  static constexpr uint32_t kCommitMarker = 0x434F4D54u;
  static constexpr uint16_t kRecordVersion = 1u;
  // magic(4)+version(2)+bytes(2)+sequence(4)+confirmed_counter_floor(4)+
  // active_image_extent(4)+confirmed_hash_sha256(32)+crc32(4)+marker(4) = 60.
  static constexpr uint32_t kRecordBytes = 4 + 2 + 2 + 4 + 4 + 4 + 32 + 4 + 4;
  static constexpr uint32_t kCrcOffset = kRecordBytes - 8;          // 52
  static constexpr uint32_t kCommitMarkerOffset = kRecordBytes - 4;  // 56

  static bool isValidRecord(const uint8_t* record, uint32_t len) {
    if (record == nullptr || len != kRecordBytes) return false;
    if (getU32(record) != kMagic) return false;
    if (record[4] != static_cast<uint8_t>(kRecordVersion) || record[5] != 0) return false;
    if (getU16(record + 6) != static_cast<uint16_t>(kRecordBytes)) return false;
    if (getU32(record + kCommitMarkerOffset) != kCommitMarker) return false;
    return getU32(record + kCrcOffset) == Crc32::computeFinalized(record, kCrcOffset);
  }

  // `region` must be exactly 2 erase units (the floor A/B pair). Returns
  // true and fills `out_confirmed_counter_floor` from the newest valid of
  // the two slots, false if neither slot holds a valid record yet (e.g. a
  // never-updated device) -- callers must treat that as "no known floor",
  // not "floor is 0".
  static bool readNewestConfirmedCounter(const platform::FlashRegion& region,
                                        uint32_t& out_confirmed_counter_floor) {
    if (!region.isValid() || region.sizeBytes() != (2u * region.eraseUnitBytes()) ||
        region.eraseUnitBytes() < kRecordBytes) {
      return false;
    }
    bool found = false;
    uint32_t best_sequence = 0;
    uint32_t best_floor = 0;
    for (uint32_t slot = 0; slot < 2u; ++slot) {
      uint8_t buf[kRecordBytes];
      // An unreadable slot must never be silently skipped: it could have
      // held the true newest record, so this whole lookup must fail
      // closed rather than return a stale/wrong value from the other slot.
      if (!platform::isOk(region.read(slot * region.eraseUnitBytes(), buf, kRecordBytes))) return false;
      if (!isValidRecord(buf, kRecordBytes)) continue;
      const uint32_t seq = getU32(buf + 8);
      if (!found || seq >= best_sequence) {
        found = true;
        best_sequence = seq;
        best_floor = getU32(buf + 12);
      }
    }
    if (!found) return false;
    out_confirmed_counter_floor = best_floor;
    return true;
  }

  // Same slots as readNewestConfirmedCounter(), but distinguishes "no
  // confirmed floor yet" (both slots genuinely blank/erased, i.e. an
  // untouched flash region -- a legitimate first-ever-device baseline of
  // 0) from "a slot holds non-blank data that fails validation" (corrupt
  // -- must fail closed, never silently default to 0). This matters
  // because readNewestConfirmedCounter() above conflates those two cases
  // (both return false), which would let a corrupt/tampered floor slot be
  // silently treated as counter==0 by a naive caller.
  //
  // Returns true (trust `out_confirmed_counter_floor`) when either a
  // valid record was found, OR both slots are entirely 0xFF (blank).
  // Returns false (fail closed -- caller MUST refuse to proceed, never
  // substitute 0) when at least one slot is non-blank but invalid, or a
  // slot could not be read, and no valid record was found.
  static bool readNewestConfirmedCounterFailClosed(const platform::FlashRegion& region,
                                                    uint32_t& out_confirmed_counter_floor) {
    return readNewestConfirmedEvidenceFailClosed(region, out_confirmed_counter_floor, nullptr, nullptr);
  }

  static bool readNewestConfirmedEvidenceFailClosed(const platform::FlashRegion& region,
                                                    uint32_t& out_confirmed_counter_floor,
                                                    uint8_t* out_confirmed_hash,
                                                    uint32_t* out_active_extent) {
    if (out_confirmed_hash) memset(out_confirmed_hash, 0, 32);
    if (out_active_extent) *out_active_extent = 0;
    if (!region.isValid() || region.sizeBytes() != (2u * region.eraseUnitBytes()) ||
        region.eraseUnitBytes() < kRecordBytes) {
      return false;
    }
    bool found_valid = false;
    uint32_t best_sequence = 0;
    uint32_t best_floor = 0;
    uint32_t best_extent = 0;
    uint8_t best_hash[32] = {};
    // A genuinely UNREADABLE slot (I/O error) is categorically worse than
    // a readable-but-corrupt one: it might have held the true newest
    // record, so it ALWAYS fails the whole lookup closed, regardless of
    // whatever the other slot contains. A readable slot whose content is
    // simply invalid/non-blank (corruption of what is very likely an
    // older, already-superseded record) does NOT override a genuinely
    // valid record found in the other slot -- that is the normal,
    // expected steady state of an A/B pair mid-lifecycle.
    bool any_unreadable = false;
    bool any_corrupt_readable = false;
    for (uint32_t slot = 0; slot < 2u; ++slot) {
      const uint32_t slot_offset = slot * region.eraseUnitBytes();
      uint8_t buf[kRecordBytes];
      if (!platform::isOk(region.read(slot_offset, buf, kRecordBytes))) {
        any_unreadable = true;
        continue;
      }
      if (isValidRecord(buf, kRecordBytes)) {
        const uint32_t seq = getU32(buf + 8);
        if (!found_valid || seq >= best_sequence) {
          found_valid = true;
          best_sequence = seq;
          best_floor = getU32(buf + 12);
          best_extent = getU32(buf + 16);
          memcpy(best_hash, buf + 20, 32);
        }
        continue;
      }
      if (!isBlank(buf, kRecordBytes)) {
        any_corrupt_readable = true;
        continue;
      }
      // The record-sized prefix reads as blank, but that alone does not
      // prove this slot is a genuine untouched baseline: a nonblank byte
      // anywhere else in the erase unit (e.g. leftover data near its
      // tail) means this erase unit was previously written to and must
      // not be silently treated as "no record here" -- scan the WHOLE
      // erase unit before trusting the blank-baseline case.
      bool read_ok = true;
      const bool fully_blank = isEraseUnitFullyBlank(region, slot_offset, region.eraseUnitBytes(), read_ok);
      if (!read_ok) {
        any_unreadable = true;
      } else if (!fully_blank) {
        // A nonblank tail with a blank record-prefix header: not a
        // genuine baseline, but also not an I/O failure -- treat the
        // same as any other readable-but-invalid content.
        any_corrupt_readable = true;
      }
    }
    if (any_unreadable) {
      return false;  // fail closed unconditionally: an unreadable slot can never be
                      // outweighed by anything found in the other slot -- it might
                      // have held the true newest floor.
    }
    if (found_valid) {
      out_confirmed_counter_floor = best_floor;
      if (out_confirmed_hash) memcpy(out_confirmed_hash, best_hash, 32);
      if (out_active_extent) *out_active_extent = best_extent;
      return true;
    }
    if (any_corrupt_readable) {
      return false;  // fail closed: readable corruption present, no valid record found.
    }
    out_confirmed_counter_floor = 0;  // both slots genuinely, fully blank: legitimate baseline.
    return true;
  }

  // Same newest-slot search as readNewestConfirmedCounter(), but returns
  // the confirmed `active_image_extent` field (offset 16) instead of the
  // counter floor. NOTE: XiaoOtaActiveExtentBridge::resolve() no longer
  // consults this at all (removed: a confirmed floor can be stale/wrong-
  // sized after a USB reflash) -- it is retained here only as a general-
  // purpose accessor and for its own direct test coverage, not as part of
  // the active-extent-for-install-command resolution path.
  static bool readNewestActiveExtent(const platform::FlashRegion& region, uint32_t& out_active_image_extent) {
    if (!region.isValid() || region.sizeBytes() != (2u * region.eraseUnitBytes()) ||
        region.eraseUnitBytes() < kRecordBytes) {
      return false;
    }
    bool found = false;
    uint32_t best_sequence = 0;
    uint32_t best_extent = 0;
    for (uint32_t slot = 0; slot < 2u; ++slot) {
      uint8_t buf[kRecordBytes];
      // An unreadable slot must never be silently skipped: it could have
      // held the true newest record, so this whole lookup must fail
      // closed rather than return a stale/wrong value from the other slot.
      if (!platform::isOk(region.read(slot * region.eraseUnitBytes(), buf, kRecordBytes))) return false;
      if (!isValidRecord(buf, kRecordBytes)) continue;
      const uint32_t seq = getU32(buf + 8);
      if (!found || seq >= best_sequence) {
        found = true;
        best_sequence = seq;
        best_extent = getU32(buf + 16);
      }
    }
    if (!found) return false;
    out_active_image_extent = best_extent;
    return true;
  }

private:
  static bool isBlank(const uint8_t* buf, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
      if (buf[i] != 0xFFu) return false;
    }
    return true;
  }

  // Scans the ENTIRE erase unit at `slot_offset` (not merely the
  // record-sized prefix) in bounded scratch-sized chunks, so a genuine
  // "blank baseline" determination can never be fooled by nonblank bytes
  // lurking beyond the record itself (e.g. leftover data near the erase
  // unit's tail from a prior, differently-sized record layout). Sets
  // `out_read_ok` to false (return value undefined/false) on any read
  // failure; otherwise sets it true and returns whether every byte in
  // the whole erase unit is 0xFF.
  static bool isEraseUnitFullyBlank(const platform::FlashRegion& region, uint32_t slot_offset,
                                    uint32_t erase_unit_bytes, bool& out_read_ok) {
    constexpr uint32_t kScratchBytes = 256;
    uint8_t scratch[kScratchBytes];
    uint32_t offset = 0;
    while (offset < erase_unit_bytes) {
      const uint32_t chunk = (erase_unit_bytes - offset) < kScratchBytes ? (erase_unit_bytes - offset)
                                                                         : kScratchBytes;
      if (!platform::isOk(region.read(slot_offset + offset, scratch, chunk))) {
        out_read_ok = false;
        return false;
      }
      if (!isBlank(scratch, chunk)) {
        out_read_ok = true;
        return false;
      }
      offset += chunk;
    }
    out_read_ok = true;
    return true;
  }

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
