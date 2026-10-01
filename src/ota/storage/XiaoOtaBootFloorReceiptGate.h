#pragma once

// Device-side (FW-owned) gate establishing DURABLE LIFETIME-ROLE authority
// from the Boot-owned, publisher-signed
// ota::authority::BootFloorActivationReceiptV1 record, before any OTA
// install-path trust decision is allowed to proceed.
//
// This module owns NO wire format of its own: it reuses the existing,
// Boot/Root-agreed BootFloorActivationReceiptCodec (struct + parseRecord/
// computeSignedDigest ONLY -- never the host-only exporter/registry/
// cross-process-lock machinery that lives in the rest of
// src/ota/authority/BootFloorActivationReceipt.h, which this header never
// instantiates) to parse and verify the two fixed 388-byte physical
// receipt windows Root's contract places at each floor erase unit's
// +0x100 byte offset -- the SAME floor FlashRegion XiaoOtaFloorReader
// already consumes (see that class's own 0x192000/0x193000 doc comment).
// This gate reads that region but never writes it.
//
// Root's "FINAL IMPLEMENTABLE HIGH-FIX CONTRACT" section D: a missing/
// corrupt/wrong-role/conflicting receipt (or an unreadable required
// window) must fail EVERY install-path trust decision closed. This class
// is wired into OtaBoardFailClosedMonotonicCounter so that every one of
// DescriptorVerifier's existing counter reads (the anti-rollback check
// before admission, and commitCounter() after confirmation) automatically
// becomes a role-authority check too, with no second call site to keep in
// sync -- see OtaBoardBackendCommon.h.

#include <stdint.h>
#include <string.h>

#include "ota/authority/BootFloorActivationReceipt.h"
#include "ota/platform/FlashRegion.h"
#include "ota/trust/Sha256.h"
#include "ota/trust/SignatureVerifier.h"

namespace ota {
namespace storage {

enum class BootFloorRoleAuthorityOutcome : uint8_t {
  Ok = 0,
  IoError = 1,       // A required receipt window (or the floor region itself) could not be read at all.
  Missing = 2,       // Both windows genuinely blank -- this device has never been granted a floor receipt.
  Corrupt = 3,       // Readable but structurally invalid, wrong signature, or wrong device/target/profile/layout.
  RoleMismatch = 4,  // A single, otherwise-valid, otherwise-matching receipt names a different compiled role.
  Conflict = 5,      // Two independently valid receipts disagree -- never pick either.
};

// What THIS device is willing to accept as lifetime-role proof. Populated
// once per (re)configure from already-provisioned/compiled identity --
// never from the receipt being checked, and never from any caller-
// controlled wire value (mirrors ota::trust::DeviceTrustAnchor's own
// "populated once, never derived from the thing being checked"
// discipline).
struct BootFloorRoleAuthorityAnchor {
  uint8_t trusted_publisher_public_key_ed25519[32] = {0};
  uint32_t expected_target_id = 0;
  uint32_t expected_profile_id = 0;
  uint32_t expected_layout_id = 0;
  uint32_t expected_role_id = 0;
  uint8_t device_uid8[8] = {0};
};

class XiaoOtaBootFloorReceiptGate {
public:
  // Fixed physical layout, shared with Boot (`xiao_ota_record.h`'s own
  // receipt-window placement): one window per floor erase unit, at a
  // +0x100 byte offset, 388 physically-aligned bytes each (386 logical
  // record bytes + 2 bytes 0xFF pad -- see BootFloorActivationReceipt.h's
  // own "PHYSICAL I/O ALIGNMENT IS NOT PART OF THIS CANONICAL FORMAT"
  // comment: the 388-byte physical buffer is this firmware's own storage-
  // layer concern, never a value the shared codec itself accepts).
  static constexpr uint32_t kWindowOffset = 0x100u;
  static constexpr uint32_t kWindowPhysicalBytes = 388u;
  static constexpr uint32_t kRecordBytes =
      static_cast<uint32_t>(::ota::authority::BootFloorActivationReceiptCodec::kRecordBytes);  // 386.

  // `floor_region` must be the SAME 2-erase-unit region XiaoOtaFloorReader
  // consumes (this gate never allocates/owns its own region, and never
  // writes it -- read-only). Returns the combined outcome; `out_receipt`
  // (optional, nullable) is filled with the single verified receipt ONLY
  // on Ok.
  static BootFloorRoleAuthorityOutcome resolve(const ::ota::platform::FlashRegion& floor_region,
                                                const BootFloorRoleAuthorityAnchor& anchor,
                                                ::ota::trust::SignatureVerifier& verifier,
                                                ::ota::authority::BootFloorActivationReceiptV1* out_receipt) {
    if (!floor_region.isValid() || floor_region.sizeBytes() != (2u * floor_region.eraseUnitBytes()) ||
        floor_region.eraseUnitBytes() < (kWindowOffset + kWindowPhysicalBytes)) {
      return BootFloorRoleAuthorityOutcome::IoError;
    }

    SlotResult slots[2];
    for (uint32_t slot = 0; slot < 2u; ++slot) {
      slots[slot] = readSlot(floor_region, slot * floor_region.eraseUnitBytes() + kWindowOffset);
      // An unreadable window fails the WHOLE lookup closed, unconditionally
      // -- it might have held the true surviving receipt (same discipline
      // as XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed()).
      if (slots[slot].status == SlotStatus::IoError) return BootFloorRoleAuthorityOutcome::IoError;
    }

    const bool slot0_valid = slots[0].status == SlotStatus::Valid;
    const bool slot1_valid = slots[1].status == SlotStatus::Valid;

    if (!slot0_valid && !slot1_valid) {
      const bool any_corrupt = slots[0].status == SlotStatus::Corrupt || slots[1].status == SlotStatus::Corrupt;
      return any_corrupt ? BootFloorRoleAuthorityOutcome::Corrupt : BootFloorRoleAuthorityOutcome::Missing;
    }

    if (slot0_valid && slot1_valid && !receiptsAgree(slots[0].receipt, slots[1].receipt)) {
      return BootFloorRoleAuthorityOutcome::Conflict;
    }

    const ::ota::authority::BootFloorActivationReceiptV1& receipt = slot0_valid ? slots[0].receipt : slots[1].receipt;
    return verifyAgainstAnchor(receipt, anchor, verifier, out_receipt);
  }

private:
  enum class SlotStatus : uint8_t { Blank, Valid, Corrupt, IoError };
  struct SlotResult {
    SlotStatus status = SlotStatus::Blank;
    ::ota::authority::BootFloorActivationReceiptV1 receipt;
  };

  static bool isBlank(const uint8_t* buf, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
      if (buf[i] != 0xFFu) return false;
    }
    return true;
  }

  static SlotResult readSlot(const ::ota::platform::FlashRegion& region, uint32_t offset) {
    SlotResult result;
    uint8_t buf[kWindowPhysicalBytes];
    if (!::ota::platform::isOk(region.read(offset, buf, kWindowPhysicalBytes))) {
      result.status = SlotStatus::IoError;
      return result;
    }
    if (isBlank(buf, kRecordBytes)) {
      result.status = SlotStatus::Blank;
      return result;
    }
    if (!::ota::authority::BootFloorActivationReceiptCodec::parseRecord(buf, kRecordBytes, result.receipt)) {
      result.status = SlotStatus::Corrupt;
      return result;
    }
    result.status = SlotStatus::Valid;
    return result;
  }

  static bool receiptsAgree(const ::ota::authority::BootFloorActivationReceiptV1& a,
                             const ::ota::authority::BootFloorActivationReceiptV1& b) {
    return memcmp(a.hardwareUid, b.hardwareUid, sizeof(a.hardwareUid)) == 0 &&
           memcmp(a.localMeshFullPublicKey, b.localMeshFullPublicKey, sizeof(a.localMeshFullPublicKey)) == 0 &&
           a.targetId == b.targetId && a.profileId == b.profileId && a.layoutId == b.layoutId &&
           a.currentRole == b.currentRole && a.publisherKeyId == b.publisherKeyId &&
           memcmp(a.publisherKeyFingerprintSha256, b.publisherKeyFingerprintSha256,
                  sizeof(a.publisherKeyFingerprintSha256)) == 0 &&
           memcmp(a.signatureEd25519, b.signatureEd25519, sizeof(a.signatureEd25519)) == 0;
  }

  static BootFloorRoleAuthorityOutcome verifyAgainstAnchor(
      const ::ota::authority::BootFloorActivationReceiptV1& receipt, const BootFloorRoleAuthorityAnchor& anchor,
      ::ota::trust::SignatureVerifier& verifier, ::ota::authority::BootFloorActivationReceiptV1* out_receipt) {
    // Genuine genesis structural fact: every valid receipt's wire `floor`
    // field MUST be 0 (see BootFloorActivationReceiptV1::floor's own doc
    // comment) -- a nonzero value here means the bytes parsed/CRC'd
    // cleanly but do not describe a genesis grant at all.
    if (receipt.floor != 0) return BootFloorRoleAuthorityOutcome::Corrupt;

    uint8_t anchor_key_fingerprint[32];
    ::ota::trust::Sha256::hash(anchor.trusted_publisher_public_key_ed25519,
                                sizeof(anchor.trusted_publisher_public_key_ed25519), anchor_key_fingerprint);
    if (memcmp(anchor_key_fingerprint, receipt.publisherKeyFingerprintSha256, sizeof(anchor_key_fingerprint)) != 0) {
      return BootFloorRoleAuthorityOutcome::Corrupt;  // Not signed under this device's own trusted publisher key.
    }

    uint8_t digest[32];
    if (!::ota::authority::BootFloorActivationReceiptCodec::computeSignedDigest(receipt, digest)) {
      return BootFloorRoleAuthorityOutcome::Corrupt;
    }
    if (!verifier.verify(receipt.signatureEd25519, sizeof(receipt.signatureEd25519), digest, sizeof(digest),
                          anchor.trusted_publisher_public_key_ed25519,
                          sizeof(anchor.trusted_publisher_public_key_ed25519))) {
      return BootFloorRoleAuthorityOutcome::Corrupt;
    }

    if (memcmp(receipt.hardwareUid, anchor.device_uid8, sizeof(receipt.hardwareUid)) != 0) {
      return BootFloorRoleAuthorityOutcome::Corrupt;  // Not this physical device's receipt.
    }
    if (receipt.targetId != anchor.expected_target_id || receipt.profileId != anchor.expected_profile_id ||
        receipt.layoutId != anchor.expected_layout_id) {
      return BootFloorRoleAuthorityOutcome::Corrupt;
    }

    if (receipt.currentRole != anchor.expected_role_id) {
      return BootFloorRoleAuthorityOutcome::RoleMismatch;
    }

    if (out_receipt != nullptr) *out_receipt = receipt;
    return BootFloorRoleAuthorityOutcome::Ok;
  }
};

}  // namespace storage
}  // namespace ota
