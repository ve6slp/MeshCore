#include "NativeEspSdk.h"
#include <cstdio>
#include <ota/trust/Ed25519SignatureVerifier.h>
#include "../test_lora_ota_trust/Ed25519TestSigner.h"
#include OTA_ESP_BACKEND_SOURCE

NativeRadio radio;
NativeRadioDriver radio_driver;
extern "C" esp_err_t __real_nvs_flash_init() { return ESP_OK; }
bool Ed25519::verify(const uint8_t* signature, const uint8_t* key, const uint8_t* message, size_t size) {
  return ::ota::trust::Ed25519SignatureVerifier().verify(signature, 64, message, size, key, 32);
}

using namespace mesh::ota::v4;
using namespace ::ota::storage;
using ::ota::platform::Esp32OtaMetadataAdapter;
using ::ota::platform::FlashStatus;

class ExclusiveImageOwner final : public Esp32UpdateOwner {
public:
  Esp32UpdateOwnership ownership(const Esp32PartitionIdentity&) const override {
    return Esp32UpdateOwnership::ExclusiveStorage;
  }
};

static void unchangedOutsideMetadata(const std::vector<uint8_t>& before) {
  for (size_t i = 0; i < before.size(); ++i)
    if (i < 0x33c000 || i >= 0x340000) assert(before[i] == nativeEsp.flash[i]);
}

static void actualMetadataCapability() {
  for (unsigned topology = 0; topology < 3; ++topology) {
    nativeEsp.reset(topology == 1 ? 1 : 0);
    if (topology == 1) { nativeEsp.boot = 0; nativeEsp.states[0] = ESP_OTA_IMG_NEW; }
    if (topology == 2) nativeEsp.states[0] = ESP_OTA_IMG_PENDING_VERIFY;
    const auto before = nativeEsp.flash;
    const auto personality = nativeEsp.nvs;
    Esp32IdfPartitionApi sdk;
    Esp32OtaMetadataAdapter device(sdk);
    ::ota::platform::FlashRegion region(device, 0, device.kBytes);
    OtaV4Journal store(region);
    std::vector<uint8_t> manifest(4707, 0x73), recovered(8192);
    Journal out; size_t size = 0;
    assert(store.recover(out, recovered.data(), recovered.size(), size) == Result::State);
    Journal trialJournal; trialJournal.phase = Phase::Trial; trialJournal.generation = 3;
    trialJournal.transaction[0] = 0x41;
    ::ota::trust::Sha256::hash(manifest.data(), manifest.size(), trialJournal.packageHash);
    assert(store.save(trialJournal, manifest.data(), manifest.size()) == Result::Ok);
    OtaV4Journal cold(region);
    assert(cold.recover(out, recovered.data(), recovered.size(), size) == Result::Ok);
    assert(out.phase == Phase::Trial && size == manifest.size() &&
        !std::memcmp(recovered.data(), manifest.data(), size));
    Journal idle; idle.generation = 4;
    assert(cold.repair(idle) == Result::Ok);
    OtaV4Journal repaired(region);
    assert(repaired.recover(out, recovered.data(), recovered.size(), size) == Result::Ok &&
        out.phase == Phase::Idle && out.generation == 4);

    uint8_t last = 0x13, loaded = 0;
    assert(device.program(device.kBytes - 1, &last, 1) == FlashStatus::Ok);
    assert(device.read(device.kBytes - 1, &loaded, 1) == FlashStatus::Ok && loaded == last);
    last = 0xff;
    assert(device.program(device.kBytes - 1, &last, 1) == FlashStatus::PartialProgramViolation);
    ExclusiveImageOwner imageOwner;
    ::ota::platform::Esp32FlashAdapter image(sdk, imageOwner);
    if (!topology) {
      assert(image.bind(4096) == FlashStatus::Ok);
      nativeEsp.boot = 1; nativeEsp.states[1] = ESP_OTA_IMG_NEW;
      assert(image.read(0, &loaded, 1) != FlashStatus::Ok);
      assert(image.program(0, &last, 1) != FlashStatus::Ok);
      assert(image.eraseSector(0) != FlashStatus::Ok);
      nativeEsp.boot = 0; nativeEsp.states[1] = ESP_OTA_IMG_VALID;
    } else {
      assert(image.bind(4096) != FlashStatus::Ok);
    }

    const size_t writes = nativeEsp.writes, erases = nativeEsp.erases;
    uint8_t byte = 0;
    assert(device.read(UINT32_MAX, &byte, 1) == FlashStatus::OutOfRange);
    assert(device.program(device.kBytes - 1, &byte, 2) == FlashStatus::OutOfRange);
    assert(device.eraseSector(device.kBytes) == FlashStatus::OutOfRange);
    assert(sdk.readOtaMetadata(UINT32_MAX, &byte, 1) != ESP_OK);
    assert(sdk.writeOtaMetadata(device.kBytes - 1, &byte, 2) != ESP_OK);
    assert(sdk.writeOtaMetadata(0, nullptr, 1) != ESP_OK);
    assert(sdk.eraseOtaMetadata(1, 4096) != ESP_OK);
    assert(sdk.eraseOtaMetadata(device.kBytes, 4096) != ESP_OK);
    assert(sdk.eraseOtaMetadata(0, UINT32_MAX) != ESP_OK);

    // The very same SDK object must still refuse active/selected image I/O.
    const auto active = Esp32S3PartitionLayout::entry(2 + nativeEsp.running);
    const auto selected = Esp32S3PartitionLayout::entry(2 + nativeEsp.boot);
    for (const auto& p : {active, selected}) {
      assert(sdk.read(p, 0, &byte, 1) != ESP_OK);
      assert(sdk.write(p, 0, &byte, 1) != ESP_OK);
      assert(sdk.erase(p, 0, 4096) != ESP_OK);
    }
    assert(sdk.write(Esp32S3PartitionLayout::entry(0), 0, &byte, 1) != ESP_OK);
    nativeEsp.partitions[2].encrypted = true;
    assert(sdk.writeOtaMetadata(0, &byte, 1) != ESP_OK);
    nativeEsp.partitions[2].encrypted = false;
    nativeEsp.partitions[4].address += 4096;
    assert(sdk.eraseOtaMetadata(0, 4096) != ESP_OK);
    nativeEsp.partitions[4].address -= 4096;
    nativeEsp.physicalSize /= 2;
    assert(sdk.readOtaMetadata(0, &byte, 1) != ESP_OK);
    assert(nativeEsp.writes == writes && nativeEsp.erases == erases);
    unchangedOutsideMetadata(before);
    assert(nativeEsp.nvs == personality);
  }
}

static void oldApplicationTailLayoutIsRejectedBeforeMutation() {
  nativeEsp.reset(0);
  nativeEsp.partitionCount = 6;
  nativeEsp.partitions[2].size = 0x330000;
  Esp32IdfPartitionApi sdk;
  Esp32OtaMetadataAdapter metadata(sdk);
  assert(metadata.eraseSector(0) == FlashStatus::InvalidArgument);
  assert(nativeEsp.writes == 0 && nativeEsp.erases == 0);
}

static void writeLe32(uint8_t* p, uint32_t value) {
  for (unsigned i = 0; i < 4; ++i) p[i] = value >> (8 * i);
}

static std::vector<uint8_t> imageBytes() {
  const uint32_t payloadSize = 257;
  std::vector<uint8_t> image((32 + payloadSize + 16) & ~uint32_t(15), 0);
  image[0] = 0xe9; image[1] = 1;
  writeLe32(image.data() + 4, 0x40370000);
  writeLe32(image.data() + 24, 0x3fc90000);
  writeLe32(image.data() + 28, payloadSize);
  uint8_t checksum = 0xef;
  for (unsigned i = 0; i < payloadSize; ++i) {
    image[32 + i] = uint8_t(i * 73 + 11);
    checksum ^= image[32 + i];
  }
  image.back() = checksum;
  return image;
}

static std::vector<uint8_t> signedPackage(const std::vector<uint8_t>& image,
                                         const ::ota::test::Ed25519TestSigner& signer) {
  std::vector<uint8_t> package(kManifestPrefixBytes + kManifestEntryBytes + 64);
  std::memcpy(package.data(), "MCO4", 4); package[4] = 4; package[5] = 13;
  write16(package.data() + 6, 1); std::memcpy(package.data() + 8, signer.publicKey(), 32);
  Descriptor descriptor;
  const auto policy = espPolicy();
  descriptor.boardFamily = policy.boardFamily; descriptor.boardVariant = policy.boardVariant;
  descriptor.role = policy.role; descriptor.appAddress = policy.appAddress;
  descriptor.exactSizeBytes = image.size(); descriptor.securityCounter = 5;
  descriptor.minBootloaderCapabilities = 1;
  descriptor.formatId = descriptor.keyId = descriptor.algorithmId = 1;
  ::ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
  size_t written = 0;
  assert(meshcore::ota::protocol::encodeOtaDescriptorCanonical(descriptor, package.data() + 40, 59, written) ==
      meshcore::ota::protocol::OtaDescriptorCodecResult::Ok);
  signer.sign(package.data() + 40, 59, package.data() + 99);
  auto* entry = package.data() + kManifestPrefixBytes;
  entry[0] = uint8_t(Codec::Raw); write16(entry + 1, image.size());
  std::memcpy(entry + 3, descriptor.sha256, 32);
  std::vector<uint8_t> transcript(kManifestDomain, kManifestDomain + sizeof(kManifestDomain));
  transcript.insert(transcript.end(), package.begin(), package.end() - 64);
  signer.sign(transcript.data(), transcript.size(), package.data() + package.size() - 64);
  return package;
}

static RuntimeHooks hooksFor(const ::ota::test::Ed25519TestSigner& signer) {
  RuntimeHooks hooks;
  hooks.context = const_cast<::ota::test::Ed25519TestSigner*>(&signer);
  hooks.identity = [](void* context, uint8_t out[32]) {
    std::memcpy(out, static_cast<::ota::test::Ed25519TestSigner*>(context)->publicKey(), 32);
    return Result::Ok;
  };
  hooks.isCurrentAdmin = [](void* context, const uint8_t key[32]) {
    return !std::memcmp(key, static_cast<::ota::test::Ed25519TestSigner*>(context)->publicKey(), 32);
  };
  hooks.sign = [](void* context, const char* domain, size_t domainSize, const uint8_t* message,
                   size_t messageSize, uint8_t signature[64]) {
    std::vector<uint8_t> transcript(domain, domain + domainSize);
    transcript.insert(transcript.end(), message, message + messageSize);
    static_cast<::ota::test::Ed25519TestSigner*>(context)->sign(
        transcript.data(), transcript.size(), signature);
    return Result::Ok;
  };
  return hooks;
}

static void signedRepair(Receiver& receiver, const ::ota::test::Ed25519TestSigner& signer) {
  uint8_t command[kCommandBytes] = {};
  std::memcpy(command, signer.publicKey(), 32);
  std::memcpy(command + 32, signer.publicKey(), 32);
  std::memcpy(command + 96, receiver.challenge(), 16);
  write32(command + 112, receiver.journal().generation);
  std::vector<uint8_t> transcript(kRepairDomain, kRepairDomain + sizeof(kRepairDomain));
  transcript.insert(transcript.end(), command, command + kSignedCommandBytes);
  signer.sign(transcript.data(), transcript.size(), command + kSignedCommandBytes);
  uint8_t frame[kMaxFrameBytes], tag[8] = {};
  for (unsigned slice = 0; slice < 2; ++slice) {
    const size_t bytes = encodeFrame(Kind::Repair, 1, tag, 0, sizeof(command), slice,
        command + slice * kSliceBytes, sliceSize(sizeof(command), slice), frame, sizeof(frame));
    assert(bytes && receiver.onFrame(frame, bytes) == Result::Ok);
  }
  assert(receiver.journal().phase == Phase::Idle);
}

static void sameImageTransaction(unsigned originalSlot, esp_ota_img_states_t outcome) {
  nativeEsp.reset(originalSlot);
  storageFault = resetPending = resetWaiting = false;
  owner.held = true; owner.ordinary = false;
  const uint8_t seed[32] = {0x41};
  ::ota::test::Ed25519TestSigner signer(seed);
  const auto hooks = hooksFor(signer);
  const auto image = imageBytes();
  const auto package = signedPackage(image, signer);
  Manifest manifest;
  assert(manifest.parse(package.data(), package.size()) == Result::Ok);
  const uint32_t originalAddress = nativeEsp.partitions[2 + originalSlot].address;
  std::copy(image.begin(), image.end(), nativeEsp.flash.begin() + originalAddress);
  uint8_t hash[32]; ::ota::trust::Sha256::hash(image.data(), image.size(), hash);
  assert(saveFloor(4, image.size(), hash));
  const auto floorBefore = nativeEsp.nvs.at("meshota").at("floor4");
  const auto personality = nativeEsp.nvs.at("personality");
  earlyTrial();

  EspFirmwarePlatform writer; writer.attach(hooks);
  uint8_t recovered[kMaxManifestBytes]; Journal journal; size_t size = 0;
  assert(writer.recover(journal, recovered, sizeof(recovered), size) == Result::State);
  journal.phase = Phase::Ready; journal.generation = 1; journal.nextChunk = 1;
  journal.transaction[0] = 0x64;
  std::memcpy(journal.packageHash, manifest.hash(), 32);
  assert(writer.save(journal, package.data(), package.size()) == Result::Ok);
  assert(writer.beginStaging(image.size()) == Result::Ok);
  for (size_t offset = 0; offset < image.size(); offset += kSliceBytes) {
    const size_t count = std::min(kSliceBytes, image.size() - offset);
    assert(writer.writeStaging(offset, image.data() + offset, count) == Result::Ok);
  }
  assert(writer.validateInstall(manifest.canonical(), manifest.bootSignature(), signer.publicKey()) ==
      Result::Ok);
  journal.phase = Phase::ActivationPending;
  assert(writer.save(journal, package.data(), package.size()) == Result::Ok);
  assert(writer.activate(manifest.canonical(), manifest.bootSignature(), signer.publicKey(),
                         journal.transaction, journal.generation) == Result::Ok);
  const unsigned targetSlot = 1 - originalSlot;
  assert(nativeEsp.boot == targetSlot && nativeEsp.states[targetSlot] == ESP_OTA_IMG_NEW);
  assert(receiptMatches("select4", journal, nativeEsp.partitions[2 + targetSlot].address) == Result::Ok);
  const auto installedBytes = nativeEsp.flash;
  nativeEsp.bootSelected(); resetPending = false;
  EspFirmwarePlatform trialBoot; trialBoot.attach(hooks);
  Receiver trialReceiver(trialBoot);
  assert(trialReceiver.begin() == Result::Ok && trialReceiver.journal().phase == Phase::Trial);
  assert(nativeEsp.nvs.at("meshota").at("floor4") == floorBefore);
  assert(nativeEsp.markValidCalls == 0);

  if (outcome == ESP_OTA_IMG_VALID) {
    assert(trialPlatform.confirmHealthy() == mesh::ota::Esp32TrialConfirmation::Confirmed);
    assert(nativeEsp.markValidCalls == 1);
    EspFirmwarePlatform confirmed; confirmed.attach(hooks);
    Receiver receiver(confirmed);
    assert(receiver.begin() == Result::Ok && receiver.journal().phase == Phase::Confirmed);
    RunningEvidence evidence;
    assert(confirmed.evidence(evidence) == Result::Ok && evidence.floor == 5 &&
        evidence.flags == (FloorKnown | RunningHashKnown | RunningConfirmed));
    assert(nativeEsp.nvs.at("personality") == personality);
    unchangedOutsideMetadata(installedBytes);
    return;
  }

  if (outcome == ESP_OTA_IMG_INVALID) trialPlatform.rollbackAndRestart();
  else nativeEsp.rollback(outcome);
  assert(nativeEsp.running == originalSlot && nativeEsp.boot == originalSlot);
  EspFirmwarePlatform rolledBack; rolledBack.attach(hooks);
  assert(rolledBack.recover(journal, recovered, sizeof(recovered), size) == Result::Ok);
  uint32_t runningSize = 0; uint8_t runningHash[32];
  assert(runningImage(runningSize, runningHash) && runningSize == image.size() &&
      !std::memcmp(runningHash, manifest.canonical() + 13, 32));
  assert(!runningReceiptMatches(journal));
  Phase phase = Phase::Trial;
  assert(rolledBack.lifecycle(phase) == Result::Ok && phase == Phase::Failed);
  RunningEvidence evidence;
  assert(rolledBack.evidence(evidence) == Result::Ok && evidence.floor == 4 &&
      !(evidence.flags & RunningConfirmed));
  assert(nativeEsp.nvs.at("meshota").at("floor4") == floorBefore);

  // Identical image hashes are not lifecycle proof. Every receipt component
  // and the failed SDK state must bind this exact transaction and partition.
  const auto selection = nativeEsp.nvs.at("meshota").at("select4");
  for (unsigned field : {0u, 32u, 48u, 52u}) {
    auto& receipt = nativeEsp.nvs["meshota"]["select4"];
    receipt = selection; receipt[field] ^= 0x40;
    write32(receipt.data() + 56, crc32(receipt.data(), 56));
    assert(rolledBack.lifecycle(phase) == Result::State);
  }
  nativeEsp.nvs["meshota"].erase("select4");
  assert(rolledBack.lifecycle(phase) == Result::State);
  nativeEsp.nvs["meshota"]["select4"] = selection;
  nativeEsp.states[targetSlot] = ESP_OTA_IMG_VALID;
  assert(rolledBack.lifecycle(phase) == Result::State);
  nativeEsp.states[targetSlot] = outcome;

  EspFirmwarePlatform recoveredBoot; recoveredBoot.attach(hooks);
  Receiver receiver(recoveredBoot);
  assert(receiver.begin() == Result::Ok && receiver.journal().phase == Phase::Failed);
  EspFirmwarePlatform cold; cold.attach(hooks);
  assert(cold.recover(journal, recovered, sizeof(recovered), size) == Result::Ok &&
      journal.phase == Phase::Failed);
  signedRepair(receiver, signer);
  EspFirmwarePlatform repaired; repaired.attach(hooks);
  assert(repaired.recover(journal, recovered, sizeof(recovered), size) == Result::Ok &&
      journal.phase == Phase::Idle);
  assert(nativeEsp.nvs.at("meshota").size() == 1 &&
      nativeEsp.nvs.at("meshota").at("floor4") == floorBefore);
  assert(nativeEsp.markValidCalls == 0 && nativeEsp.nvs.at("personality") == personality);
  unchangedOutsideMetadata(installedBytes);
}

static void damagedMetadataStillBlocksOrdinaryUpdate() {
  nativeEsp.reset(0);
  storageFault = resetPending = resetWaiting = false;
  owner.held = true; owner.ordinary = false;
  nativeEsp.flash[0x33c000] = 0x33;
  const uint8_t seed[32] = {0x41};
  ::ota::test::Ed25519TestSigner signer(seed);
  EspFirmwarePlatform damaged; damaged.attach(hooksFor(signer));
  Receiver receiver(damaged);
  assert(receiver.begin() == Result::Integrity);
  assert(receiver.journal().phase == Phase::MetadataFault);
  assert(!damaged.storageFaultObserved());
  assert(!damaged.ordinaryAllowed());
  signedRepair(receiver, signer);
  assert(damaged.ordinaryAllowed());
}

int main() {
  actualMetadataCapability();
  oldApplicationTailLayoutIsRejectedBeforeMutation();
  for (unsigned slot = 0; slot < 2; ++slot) {
    sameImageTransaction(slot, ESP_OTA_IMG_INVALID);
    sameImageTransaction(slot, ESP_OTA_IMG_ABORTED);
    sameImageTransaction(slot, ESP_OTA_IMG_VALID);
  }
  damagedMetadataStillBlocksOrdinaryUpdate();
  std::puts("ESP production metadata capability and same-image higher-counter rollback/confirmation passed");
}
