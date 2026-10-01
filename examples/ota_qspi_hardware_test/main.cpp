#include <Arduino.h>
#include <Adafruit_TinyUSB.h>
#include <Ed25519.h>

#include <cstring>

#include <ota/platform/Nrf52FlashAdapter.h>
#include <ota/platform/SenseCapQspiLayout.h>
#include <ota/storage/StorageManager.h>
#include <ota/storage/Journal.h>
#include <ota/storage/XiaoOtaCommissioningGuard.h>
#include <ota/storage/XiaoOtaBootInfoReader.h>
#include <ota/trust/CanonicalDescriptor.h>
#include <ota/trust/DescriptorVerifier.h>
#include <ota/trust/Sha256.h>
#include <helpers/ota/OtaBoardBackendCommon.h>

namespace {

constexpr uint32_t kImageBytes = 8192u;
constexpr uint32_t kChunkBytes = 160u;
// Canonical boot-side identity for the XIAO lab target (must match
// bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h's
// XIAO_OTA_TARGET_XIAO_NRF52840 / XIAO_OTA_ROLE_ANY, and
// variants/xiao_nrf52/OtaLabBackend.cpp's trust anchor) so this
// factory/lab qualification harness rehearses a genuinely representative
// signed descriptor rather than a self-invented value that happens to
// only ever get compared against itself.
constexpr uint32_t kTargetId = 0x584E3430u;
constexpr uint32_t kRoleId = 0u;
constexpr uint32_t kSecurityCounter = 1u;
constexpr uint8_t kLabPublicKey[32] = {
    0x79, 0xB5, 0x56, 0x2E, 0x8F, 0xE6, 0x54, 0xF9,
    0x40, 0x78, 0xB1, 0x12, 0xE8, 0xA9, 0x8B, 0xA7,
    0x90, 0x1F, 0x85, 0x3A, 0xE6, 0x95, 0xBE, 0xD7,
    0xE0, 0xE3, 0x91, 0x0B, 0xAD, 0x04, 0x96, 0x64,
};
constexpr uint8_t kLabSignature[64] = {
    0x26, 0x6E, 0x89, 0x52, 0x55, 0x43, 0xD2, 0x5B,
    0xF0, 0xAC, 0x7F, 0x7D, 0xED, 0xF5, 0x1B, 0x5D,
    0x1A, 0x2A, 0x86, 0x0F, 0x60, 0x30, 0xFA, 0xF5,
    0x92, 0x9A, 0xC7, 0xED, 0xC5, 0xC8, 0x95, 0xF3,
    0x64, 0x9A, 0x51, 0x3D, 0x02, 0xED, 0x2C, 0x09,
    0xC8, 0x6E, 0xED, 0xFC, 0x5A, 0xC0, 0x48, 0xAA,
    0xBF, 0x8C, 0xFA, 0x4B, 0x2C, 0x2F, 0xE9, 0x79,
    0x48, 0x1B, 0x87, 0xD2, 0x75, 0x9B, 0xA6, 0x0B,
};

class LabCounter : public ota::trust::MonotonicCounter {
public:
  bool currentValue(uint32_t& out) const override {
    out = value_;
    return true;
  }

  bool commitNewValue(uint32_t value) override {
    if (value <= value_) return false;
    value_ = value;
    return true;
  }

private:
  uint32_t value_ = 0;
};

class LabSignatureVerifier : public ota::trust::SignatureVerifier {
public:
  bool verify(const uint8_t* signature, size_t signature_len,
              const uint8_t* message, size_t message_len,
              const uint8_t* public_key, size_t public_key_len) const override {
    return signature != nullptr && public_key != nullptr &&
           (message != nullptr || message_len == 0) &&
           signature_len == 64 && public_key_len == 32 &&
           Ed25519::verify(signature, public_key, message, message_len);
  }
};

ota::platform::Nrf52FlashAdapter flash;
// Maintenance/lab-only destructive scratch, gated below on
// deviceAlreadyCommissioned() -- see SenseCapQspiLayout.h's extended
// comment on kCandidateTestOffset for why this range is safe to reuse
// (candidate-owned space, entirely inside the candidate bank's own
// writable image capacity, never inside its securityA tail).
ota::platform::FlashRegion candidate =
    ota::platform::SenseCapQspiLayout::candidateMaintenanceScratchRegion(flash);
// The real (non-test) journal region is opened read-only-in-practice here:
// it is only ever scanned via Journal::recoverLatest() and per-sub-slot
// raw reads for the commissioning guard below, never written by this
// harness. The destructive raw-semantics probe deliberately reuses
// `candidate` (the same reserved sacrificial carve-out as the
// signed-image rehearsal) instead of a separate journal-partition
// carve-out: the journal holds the durable, redundant antirollback
// "floor"/state/command/confirmation records and must never be a target
// of routine hardware-qualification erasing (see SenseCapQspiLayout.h).
//
// Deliberately NOT aliased to journalTestRegion()/candidateRecordScratchRegion():
// that legacy/relocated name is now candidate-owned scratch space and
// contains none of the real journal's checkpoint data, so redirecting
// this read-only commissioning-evidence scan there would silently defeat
// the guard's fail-closed "generic checkpoint present" signal.
ota::platform::FlashRegion real_journal =
    ota::platform::SenseCapQspiLayout::journalRegion(flash);
ota::platform::FlashRegion xiao_journal_full_region =
    ota::platform::SenseCapQspiLayout::xiaoJournalFullRegion(flash);
// Canonical target identity for the commissioning-guard boot-marker
// qualification check below -- deliberately the SAME kTargetId/kRoleId
// this harness rehearses as a signed descriptor, and the SAME
// kExpectedCapabilityFlags variants/xiao_nrf52/OtaLabBackend.cpp expects,
// so "is this device already commissioned" reflects the exact same
// custom-bootloader identity the real companion firmware would trust.
constexpr uint32_t kExpectedCapabilityFlags = 1u;

void fillImageChunk(uint32_t image_offset, uint8_t* out, uint32_t len) {
  for (uint32_t i = 0; i < len; ++i) {
    const uint32_t position = image_offset + i;
    out[i] = static_cast<uint8_t>((position * 37u + (position >> 3) + 0x5Au) & 0xFFu);
  }
}

const char* statusName(ota::platform::FlashStatus status) {
  using ota::platform::FlashStatus;
  switch (status) {
    case FlashStatus::Ok: return "Ok";
    case FlashStatus::InvalidArgument: return "InvalidArgument";
    case FlashStatus::OutOfRange: return "OutOfRange";
    case FlashStatus::Unaligned: return "Unaligned";
    case FlashStatus::IoError: return "IoError";
    case FlashStatus::Unsupported: return "Unsupported";
    case FlashStatus::PartialProgramViolation: return "PartialProgramViolation";
  }
  return "Unknown";
}

bool expectStatus(const char* name, ota::platform::FlashStatus actual,
                  ota::platform::FlashStatus expected) {
  Serial.printf("CHECK %s actual=%s expected=%s %s\n", name, statusName(actual),
                statusName(expected), actual == expected ? "PASS" : "FAIL");
  return actual == expected;
}

// Refuses to proceed with any destructive operation if there is ANY
// evidence this device has already been commissioned via a real custom
// bootloader / OTA campaign -- checked three independent ways (see
// ota::storage::XiaoOtaCommissioningInputs for the full rationale):
//   (a) a genuinely qualified custom bootloader marker is present
//       (XiaoOtaBootInfoReader magic/format/CRC + identity match);
//   (b) ANY of the 8 xiao_ota_* journal sub-slots (install command/
//       state/confirmation/floor A+B) is non-blank -- this is the
//       format the custom bootloader actually writes on real hardware,
//       and a prior version of this guard never checked it at all;
//   (c) the separate generic ota::storage::Journal/JournalCheckpoint
//       format (used by the portable ota::boot::BootTransaction
//       self-install path) has a valid checkpoint.
// Any ONE of these being true refuses the whole harness; this is a
// factory/lab qualification tool only, and running it destructively
// against an already-commissioned device could otherwise silently roll
// back the device's antirollback floor or destroy live staged/installed
// campaign data.
bool deviceAlreadyCommissioned() {
  const mesh::ota::OtaBoardBootQualification qualification =
      mesh::ota::resolveOtaBoardBootQualification(kTargetId, kRoleId, kExpectedCapabilityFlags);

  ota::storage::Journal journal(real_journal);
  bool generic_checkpoint_present = false;
  if (!journal.isValid()) {
    // Journal geometry mismatch (e.g. running against a device whose
    // journal partition isn't erase-unit aligned the way this layout
    // expects) is treated as "cannot prove it's safe" -- fail closed.
    generic_checkpoint_present = true;
  } else {
    ota::storage::JournalCheckpoint existing;
    generic_checkpoint_present = journal.recoverLatest(existing);
  }

  const uint32_t erase_unit = xiao_journal_full_region.eraseUnitBytes();
  uint8_t sub_slot_buf[8][4096];
  const uint8_t* sub_slots[8];
  bool any_subslot_read_ok = erase_unit == sizeof(sub_slot_buf[0]);
  if (any_subslot_read_ok) {
    for (int i = 0; i < 8; ++i) {
      if (!ota::platform::isOk(
              xiao_journal_full_region.read(static_cast<uint32_t>(i) * erase_unit, sub_slot_buf[i], erase_unit))) {
        any_subslot_read_ok = false;
        break;
      }
      sub_slots[i] = sub_slot_buf[i];
    }
  }
  // An unreadable/unexpected-geometry journal partition fails closed
  // (treated as non-blank / "cannot prove it's safe"), matching
  // anyXiaoJournalSubSlotNonBlank()'s own null-pointer fail-closed rule.
  const bool any_subslot_nonblank =
      !any_subslot_read_ok || ota::storage::anyXiaoJournalSubSlotNonBlank(sub_slots, erase_unit);

  ota::storage::XiaoOtaCommissioningInputs inputs;
  inputs.boot_marker_qualified = qualification.qualified;
  inputs.generic_journal_checkpoint_present = generic_checkpoint_present;
  inputs.any_xiao_subslot_nonblank = any_subslot_nonblank;
  return ota::storage::isDeviceAlreadyCommissioned(inputs);
}


bool testRawSemantics() {
  using ota::platform::FlashStatus;
  bool ok = ota::storage::StorageManager::erasePartition(candidate);
  Serial.printf("CHECK candidate_test_erase %s\n", ok ? "PASS" : "FAIL");
  if (!ok) return false;

  uint8_t erased_probe[16] = {0};
  const ota::platform::FlashStatus erased_probe_status =
      candidate.read(0, erased_probe, sizeof(erased_probe));
  Serial.printf("ERASE_PROBE status=%s bytes=", statusName(erased_probe_status));
  for (uint8_t value : erased_probe) Serial.printf("%02X", value);
  Serial.println();

  uint8_t pattern[37];
  for (uint32_t i = 0; i < sizeof(pattern); ++i) {
    pattern[i] = static_cast<uint8_t>(0xE7u ^ (i * 11u));
  }
  uint8_t pre_program[sizeof(pattern)] = {0};
  candidate.read(3, pre_program, sizeof(pre_program));
  Serial.printf("PROGRAM_PROBE old=");
  for (uint8_t value : pre_program) Serial.printf("%02X", value);
  Serial.printf(" new=");
  for (uint8_t value : pattern) Serial.printf("%02X", value);
  Serial.println();
  ok &= expectStatus("unaligned_program_supported",
                     candidate.program(3, pattern, sizeof(pattern)), FlashStatus::Ok);

  uint8_t readback[sizeof(pattern)] = {0};
  ok &= expectStatus("raw_read", candidate.read(3, readback, sizeof(readback)),
                     FlashStatus::Ok);
  const bool bytes_match = std::memcmp(pattern, readback, sizeof(pattern)) == 0;
  Serial.printf("CHECK raw_readback %s\n", bytes_match ? "PASS" : "FAIL");
  ok &= bytes_match;

  uint8_t erased_value[sizeof(pattern)];
  std::memset(erased_value, 0xFF, sizeof(erased_value));
  ok &= expectStatus("zero_to_one_rejected",
                     candidate.program(3, erased_value, sizeof(erased_value)),
                     FlashStatus::PartialProgramViolation);
  ok &= expectStatus("unaligned_erase_rejected", candidate.eraseSector(1),
                     FlashStatus::Unaligned);
  ok &= expectStatus("bounds_rejected",
                     candidate.read(candidate.sizeBytes() - 8u, readback, 16u),
                     FlashStatus::OutOfRange);
  return ok;
}

bool stageAndVerifySignedImage() {
  ota::trust::ImageDescriptor descriptor;
  descriptor.target_id = kTargetId;
  descriptor.role_id = kRoleId;
  descriptor.device_address = 0;
  descriptor.allow_broadcast_address = true;
  descriptor.required_boot_capability_flags = 0;
  descriptor.monotonic_counter = kSecurityCounter;
  descriptor.image_size_bytes = kImageBytes;
  descriptor.app_address = 0x27000u;
  descriptor.format_id = 1u;
  descriptor.key_id = 1u;
  descriptor.algorithm_id = 1u;

  ota::trust::Sha256 image_hash;
  uint8_t chunk[kChunkBytes];
  for (uint32_t offset = 0; offset < kImageBytes; offset += kChunkBytes) {
    const uint32_t len =
        (kImageBytes - offset) > kChunkBytes ? kChunkBytes : (kImageBytes - offset);
    fillImageChunk(offset, chunk, len);
    image_hash.update(chunk, len);
  }
  image_hash.finish(descriptor.image_hash_sha256);
  std::memcpy(descriptor.signature_ed25519, kLabSignature, sizeof(kLabSignature));

  ota::trust::DeviceTrustAnchor anchor;
  std::memcpy(anchor.trusted_signer_public_key_ed25519, kLabPublicKey, sizeof(kLabPublicKey));
  // Must match the descriptor's own format_id/key_id/algorithm_id above
  // (all explicitly 1): DescriptorVerifier::verifyPolicy() checks these
  // against the anchor, not the descriptor's own claim, so leaving these
  // at their zero default would fail-closed reject this genuinely signed
  // fixture with FormatIdMismatch before ever reaching the signature it
  // was built to exercise. Uses the shared helper so all six identity
  // fields are always populated together (see OtaBoardBackendCommon.h).
  mesh::ota::configureOtaTrustAnchorIdentity(anchor, kTargetId, kRoleId, /*supported_boot_capability_flags=*/0,
                                             descriptor.format_id, descriptor.key_id,
                                             descriptor.algorithm_id);

  LabCounter counter;
  ota::trust::Sha256 verifier_hash;
  LabSignatureVerifier signature_verifier;
  ota::trust::DescriptorVerifier verifier(verifier_hash, signature_verifier, counter, anchor);

  const ota::trust::VerificationResult descriptor_result =
      verifier.verifyDescriptor(descriptor);
  Serial.printf("CHECK signed_descriptor %s reason=%u\n",
                descriptor_result.ok ? "PASS" : "FAIL",
                static_cast<unsigned>(descriptor_result.reason));
  if (!descriptor_result.ok) return false;

  if (!ota::storage::StorageManager::erasePartition(candidate)) {
    Serial.println("CHECK candidate_erase FAIL");
    return false;
  }

  const uint32_t chunk_count = (kImageBytes + kChunkBytes - 1u) / kChunkBytes;
  for (uint32_t chunk_index = 0; chunk_index < chunk_count; ++chunk_index) {
    const uint32_t offset = chunk_index * kChunkBytes;
    const uint32_t len =
        (kImageBytes - offset) > kChunkBytes ? kChunkBytes : (kImageBytes - offset);
    fillImageChunk(offset, chunk, len);
    if (!ota::storage::StorageManager::writeAndVerifyChunk(
            candidate, chunk_index, kChunkBytes, chunk, len)) {
      Serial.printf("CHECK storage_stage FAIL chunk=%lu\n",
                    static_cast<unsigned long>(chunk_index));
      return false;
    }
  }
  Serial.printf("CHECK storage_stage PASS bytes=%lu chunks=%lu\n",
                static_cast<unsigned long>(kImageBytes),
                static_cast<unsigned long>(chunk_count));

  uint8_t readback[kChunkBytes];
  for (uint32_t chunk_index = 0; chunk_index < chunk_count; ++chunk_index) {
    const uint32_t offset = chunk_index * kChunkBytes;
    const uint32_t len =
        (kImageBytes - offset) > kChunkBytes ? kChunkBytes : (kImageBytes - offset);
    fillImageChunk(offset, chunk, len);
    if (!ota::storage::StorageManager::readChunk(
            candidate, chunk_index, kChunkBytes, readback, len) ||
        std::memcmp(chunk, readback, len) != 0) {
      Serial.printf("CHECK storage_readback FAIL chunk=%lu\n",
                    static_cast<unsigned long>(chunk_index));
      return false;
    }
  }
  Serial.printf("CHECK storage_readback PASS bytes=%lu\n",
                static_cast<unsigned long>(kImageBytes));

  const ota::trust::VerificationResult image_result =
      verifier.verifyImageBytes(descriptor, candidate);
  Serial.printf("CHECK signed_image_hash %s reason=%u sha256=",
                image_result.ok ? "PASS" : "FAIL",
                static_cast<unsigned>(image_result.reason));
  for (uint8_t value : descriptor.image_hash_sha256) {
    Serial.printf("%02x", value);
  }
  Serial.println();
  return image_result.ok;
}

void runTest() {
  Serial.println("OTA_QSPI_TEST BEGIN");
  Serial.printf("LAYOUT candidate_test=0x%06lx+0x%lx journal_test=0x%06lx+0x%lx "
                "littlefs=0x%06lx+0x%lx\n",
                static_cast<unsigned long>(ota::platform::SenseCapQspiLayout::kCandidateTestOffset),
                static_cast<unsigned long>(ota::platform::SenseCapQspiLayout::kCandidateTestSize),
                static_cast<unsigned long>(ota::platform::SenseCapQspiLayout::kJournalTestOffset),
                static_cast<unsigned long>(ota::platform::SenseCapQspiLayout::kJournalTestSize),
                static_cast<unsigned long>(ota::platform::SenseCapQspiLayout::kFilesystemOffset),
                static_cast<unsigned long>(ota::platform::SenseCapQspiLayout::kFilesystemSize));

  const ota::platform::FlashStatus begin_status = flash.begin();
  Serial.printf("CHECK qspi_begin %s\n", statusName(begin_status));
  if (!ota::platform::isOk(begin_status)) {
    Serial.println("OTA_QSPI_TEST RESULT FAIL");
    return;
  }

  // Commissioning guard: refuse all destructive operations below if the
  // real (non-test) journal partition already holds a valid antirollback
  // checkpoint. See deviceAlreadyCommissioned()'s comment for why.
  if (deviceAlreadyCommissioned()) {
    Serial.println("CHECK commissioning_guard FAIL device_already_commissioned");
    Serial.println("OTA_QSPI_TEST RESULT FAIL");
    return;
  }
  Serial.println("CHECK commissioning_guard PASS device_not_commissioned");


  uint8_t jedec[3] = {0, 0, 0};
  const ota::platform::FlashStatus jedec_status = flash.readJedecId(jedec);
  const bool jedec_ok = ota::platform::isOk(jedec_status) &&
                        jedec[0] == 0x85 && jedec[1] == 0x60 && jedec[2] == 0x15;
  Serial.printf("CHECK jedec %s id=%02X:%02X:%02X expected=85:60:15\n",
                jedec_ok ? "PASS" : "FAIL", jedec[0], jedec[1], jedec[2]);
  Serial.printf("GEOMETRY bytes=%lu erase=%lu program=%lu\n",
                static_cast<unsigned long>(flash.totalSizeBytes()),
                static_cast<unsigned long>(flash.eraseUnitBytes()),
                static_cast<unsigned long>(flash.programUnitBytes()));
  uint8_t status1 = 0;
  uint8_t status2 = 0;
  uint8_t status3 = 0;
  flash.readStatusRegister(0x05, status1);
  flash.readStatusRegister(0x35, status2);
  flash.readStatusRegister(0x15, status3);
  Serial.printf("STATUS sr1=%02X sr2=%02X sr3=%02X\n", status1, status2, status3);

  const bool raw_ok = jedec_ok && testRawSemantics();
  const bool signed_image_ok = raw_ok && stageAndVerifySignedImage();
  Serial.printf("OTA_QSPI_TEST RESULT %s\n",
                (raw_ok && signed_image_ok) ? "PASS" : "FAIL");
  Serial.flush();
}

}  // namespace

void setup() {
  Serial.begin(115200);
  const uint32_t started = millis();
  while (!Serial && millis() - started < 5000u) {
    delay(10);
  }
  Serial.println("OTA_QSPI_TEST READY command=run");
}

void loop() {
  static String command;
  while (Serial.available()) {
    const char value = static_cast<char>(Serial.read());
    if (value == '\r' || value == '\n') {
      command.trim();
      if (command == "run") {
        runTest();
      } else if (command.length() > 0) {
        Serial.println("OTA_QSPI_TEST ERROR expected=run");
      }
      command = "";
    } else if (command.length() < 16) {
      command += value;
    }
  }
  delay(10);
}
