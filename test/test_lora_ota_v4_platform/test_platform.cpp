#include <cassert>
#include <algorithm>
#include <cstdio>
#include <vector>
#include <helpers/ota/OtaBoardBackendCommon.h>
#include <helpers/ota/OtaBoardEsp32Trial.h>
#include <ota/platform/Esp32OtaMetadataAdapter.h>
#include <ota/trust/Ed25519SignatureVerifier.h>
#include "../test_lora_ota_storage/FakeNorFlash.h"
#include "../test_lora_ota_trust/Ed25519TestSigner.h"

using namespace mesh::ota::v4;
using Flash = ::ota::test::FakeNorFlash;
using Region = ::ota::platform::FlashRegion;
using Store = ::ota::storage::OtaV4Journal;
using Staging = ::ota::storage::OtaV4Staging;

static Journal candidate(const std::vector<uint8_t>& manifest, Phase phase, uint32_t generation) {
  Journal journal;
  journal.phase = phase; journal.generation = generation; journal.transaction[0] = 17;
  journal.nextChunk = phase == Phase::Ready ? 2 : 0;
  ::ota::trust::Sha256::hash(manifest.data(), manifest.size(), journal.packageHash);
  return journal;
}
static Result load(Store& store, Journal& out, std::vector<uint8_t>& manifest) {
  size_t bytes = 0;
  const Result result = store.recover(out, manifest.data(), manifest.size(), bytes);
  return result;
}
static void journalRoundTrip() {
  Flash flash(32768, 4096);
  Region region(flash, 8192, 8192);
  Store store(region);
  std::vector<uint8_t> manifest(2992, 0x35), recovered(8192);
  Journal out;
  assert(load(store, out, recovered) == Result::State);
  auto journal = candidate(manifest, Phase::Receiving, 1);
  assert(store.save(journal, manifest.data(), manifest.size()) == Result::Ok);
  journal.nextChunk = 2; journal.phase = Phase::Ready;
  assert(store.save(journal, manifest.data(), manifest.size()) == Result::Ok);
  Store cold(region);
  assert(load(cold, out, recovered) == Result::Ok && out.phase == Phase::Ready && out.nextChunk == 2);
  assert(!std::memcmp(manifest.data(), recovered.data(), manifest.size()));
  for (uint32_t i = 0; i < flash.rawSize(); ++i)
    if (i < 8192 || i >= 16384) assert(flash.rawBuffer()[i] == 0xFF);
  manifest.resize(4707);
  assert(store.save(journal, manifest.data(), manifest.size()) == Result::Invalid);
  Flash larger(16384, 4096); Region esp(larger, 0, 16384); Store large(esp);
  assert(load(large, out, recovered) == Result::State);
  journal = candidate(manifest, Phase::Ready, 1);
  assert(large.save(journal, manifest.data(), manifest.size()) == Result::Ok);
}
static void revokedReadyCannotResurrect() {
  Flash baseline(8192, 4096); Region base(baseline, 0, 8192); Store initial(base);
  std::vector<uint8_t> manifest(512, 0x51), buffer(8192); Journal out;
  assert(load(initial, out, buffer) == Result::State);
  auto ready = candidate(manifest, Phase::Ready, 1);
  auto aborted = ready; aborted.phase = Phase::Aborted; aborted.generation = 2;
  assert(initial.save(ready, manifest.data(), manifest.size()) == Result::Ok);
  assert(initial.save(aborted, manifest.data(), manifest.size()) == Result::Ok);
  for (auto kind : {Flash::OpKind::Program, Flash::OpKind::Erase}) {
    for (uint32_t operation = 1; operation <= (kind == Flash::OpKind::Program ? 6u : 1u); ++operation) {
      for (auto timing : {Flash::InjectionTiming::Before, Flash::InjectionTiming::Mid, Flash::InjectionTiming::After}) {
        Flash copy = baseline; Region region(copy, 0, 8192); Store writer(region);
        assert(load(writer, out, buffer) == Result::Ok && out.phase == Phase::Aborted);
        const uint32_t count = kind == Flash::OpKind::Program ? copy.programOpCount() : copy.eraseOpCount();
        copy.armFault({kind, timing, count + operation, 63});
        auto next = candidate(manifest, Phase::Receiving, 3);
        writer.save(next, manifest.data(), manifest.size());
        copy.clearFault();
        Store cold(region);
        const auto result = load(cold, out, buffer);
        assert(result != Result::Ok || out.phase != Phase::Ready);
      }
    }
  }
}
static void committedAbortWithFailedReadbackRemainsRevoked() {
  Flash flash(8192, 4096); Region region(flash, 0, 8192); Store store(region);
  std::vector<uint8_t> manifest(128, 0x41), buffer(8192); Journal out;
  assert(load(store, out, buffer) == Result::State);
  auto journal = candidate(manifest, Phase::Ready, 1);
  assert(store.save(journal, manifest.data(), manifest.size()) == Result::Ok);
  journal.phase = Phase::Aborted; journal.generation = 2;
  flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::After, flash.programOpCount() + 4, 0});
  assert(store.save(journal, manifest.data(), manifest.size()) == Result::Io);
  flash.clearFault();
  Store cold(region);
  assert(load(cold, out, buffer) == Result::Ok && out.phase == Phase::Aborted);
}
static void corruptNewestNeverFallsBackAndRepairIsExplicit() {
  Flash flash(12288, 4096); Region region(flash, 0, 8192); Store store(region);
  std::vector<uint8_t> manifest(256, 0x32), buffer(8192); Journal out;
  assert(load(store, out, buffer) == Result::State);
  auto journal = candidate(manifest, Phase::Ready, 1);
  assert(store.save(journal, manifest.data(), manifest.size()) == Result::Ok);
  journal.phase = Phase::Aborted; journal.generation = 2;
  assert(store.save(journal, manifest.data(), manifest.size()) == Result::Ok);
  const uint8_t zero = 0;
  assert(::ota::platform::isOk(region.program(4096 + 24, &zero, 1)));
  Store cold(region);
  assert(load(cold, out, buffer) == Result::Integrity && out.phase == Phase::MetadataFault);
  assert(cold.save(journal, manifest.data(), manifest.size()) == Result::State);
  Journal idle; idle.generation = 3;
  assert(cold.repair(idle) == Result::Ok);
  Store repaired(region);
  assert(load(repaired, out, buffer) == Result::Ok && out.phase == Phase::Idle && out.generation == 3);
  for (uint32_t i = 8192; i < flash.rawSize(); ++i) assert(flash.rawBuffer()[i] == 0xFF);
}
static void chunkRestartKeepsVerifiedPrefix() {
  Flash flash(24576, 4096); Region payload(flash, 0, 16384); Staging staging(payload);
  std::vector<uint8_t> image(8192 + 129);
  for (size_t i = 0; i < image.size(); ++i) image[i] = uint8_t(i * 73 + 11);
  assert(staging.begin(image.size()) == Result::Ok);
  for (uint32_t i = 0; i < 8192; i += 128)
    assert(staging.write(i, image.data() + i, 128) == Result::Ok);
  assert(staging.write(8192, image.data() + 8192, 128) == Result::Ok);
  Staging cold(payload);
  assert(cold.begin(image.size()) == Result::Ok);
  assert(cold.write(8192 + 128, image.data() + 8192 + 128, 1) == Result::State);
  assert(cold.write(8192, image.data() + 8192, 128) == Result::Ok);
  assert(cold.write(8320, image.data() + 8320, 1) == Result::Ok);
  uint8_t digest[32]; ::ota::trust::Sha256::hash(image.data(), image.size(), digest);
  assert(cold.verifyImage(image.size(), digest) == Result::Ok);
  assert(!std::memcmp(flash.rawBuffer(), image.data(), image.size()));
  for (uint32_t i = 16384; i < flash.rawSize(); ++i) assert(flash.rawBuffer()[i] == 0xFF);
}
static void repairCannotResurrectReadyAtAnyCut() {
  Flash baseline(8192, 4096); Region base(baseline, 0, 8192); Store initial(base);
  std::vector<uint8_t> manifest(128, 0x72), buffer(8192); Journal out;
  assert(load(initial, out, buffer) == Result::State);
  auto journal = candidate(manifest, Phase::Ready, 1);
  assert(initial.save(journal, manifest.data(), manifest.size()) == Result::Ok);
  journal.phase = Phase::Aborted; journal.generation = 2;
  assert(initial.save(journal, manifest.data(), manifest.size()) == Result::Ok);
  const uint8_t zero = 0;
  assert(::ota::platform::isOk(base.program(4096 + 23, &zero, 1)));
  for (auto kind : {Flash::OpKind::Program, Flash::OpKind::Erase})
    for (uint32_t operation = 1; operation <= 8; ++operation)
      for (auto timing : {Flash::InjectionTiming::Before, Flash::InjectionTiming::Mid, Flash::InjectionTiming::After}) {
        Flash copy = baseline; Region region(copy, 0, 8192); Store writer(region);
        assert(load(writer, out, buffer) == Result::Integrity);
        const uint32_t count = kind == Flash::OpKind::Program ? copy.programOpCount() : copy.eraseOpCount();
        copy.armFault({kind, timing, count + operation, 1});
        Journal idle; idle.generation = 3;
        writer.repair(idle);
        copy.clearFault();
        Store cold(region);
        const Result result = load(cold, out, buffer);
        assert(result != Result::Ok || out.phase != Phase::Ready);
      }
}
static Policy testPolicy() {
  Policy policy;
  policy.boardFamily = 0x584e; policy.boardVariant = 0x3430; policy.role = 1;
  policy.appAddress = 0x27000; policy.maxImageBytes = 16384; policy.bootloaderCapabilities = 1;
  return policy;
}
class FirmwareFixture final : public FirmwarePlatform {
public:
  FirmwareFixture(Region& payload, Region& metadata, const ::ota::trust::SignatureVerifier& crypto,
                  const uint8_t* admin)
      : FirmwarePlatform(testPolicy(), payload, metadata, crypto), admin_(admin) {
    RuntimeHooks hooks; hooks.context = this;
    hooks.isCurrentAdmin = [](void* context, const uint8_t key[32]) {
      const auto& self = *static_cast<FirmwareFixture*>(context);
      return !self.revoked && !std::memcmp(key, self.admin_, 32);
    };
    attach(hooks);
  }
  Result random(uint8_t*, size_t) override { return Result::Unsupported; }
  Result evidence(RunningEvidence& out) override {
    out = RunningEvidence(); out.flags = FloorKnown; out.floor = floor; return Result::Ok;
  }
  Result validateInstall(const uint8_t canonical[59], const uint8_t signature[64],
                          const uint8_t signer[32]) override { return verifyRawImage(canonical, signature, signer); }
  Result activate(const uint8_t[59], const uint8_t[64], const uint8_t[32], const uint8_t[16],
                  uint32_t) override { return Result::Unsupported; }
  Result lifecycle(Phase&) override { return Result::State; }
  bool revoked = false;
  uint32_t floor = 0;
protected:
  Result mutationAllowed() override { return Result::Ok; }
private:
  const uint8_t* admin_;
};
static std::vector<uint8_t> signedPackage(const std::vector<uint8_t>& image,
                                         const ::ota::test::Ed25519TestSigner& signer,
                                         uint32_t counter = 9) {
  assert(image.size() <= kChunkBytes);
  std::vector<uint8_t> package(kManifestPrefixBytes + kManifestEntryBytes + 64);
  std::memcpy(package.data(), "MCO4", 4); package[4] = 4; package[5] = 13;
  write16(package.data() + 6, 1); std::memcpy(package.data() + 8, signer.publicKey(), 32);
  Descriptor descriptor;
  const auto policy = testPolicy();
  descriptor.boardFamily = policy.boardFamily; descriptor.boardVariant = policy.boardVariant;
  descriptor.role = policy.role; descriptor.appAddress = policy.appAddress;
  descriptor.exactSizeBytes = image.size(); descriptor.securityCounter = counter;
  descriptor.minBootloaderCapabilities = 1;
  descriptor.formatId = descriptor.keyId = descriptor.algorithmId = 1;
  ::ota::trust::Sha256::hash(image.data(), image.size(), descriptor.sha256);
  size_t written;
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
static void genuineCanonicalInstallBoundary() {
  const uint8_t seed[32] = {17};
  ::ota::test::Ed25519TestSigner signer(seed);
  ::ota::trust::Ed25519SignatureVerifier verifier;
  Flash flash(40960, 4096); Region payload(flash, 0, 16384), metadata(flash, 16384, 16384);
  FirmwareFixture platform(payload, metadata, verifier, signer.publicKey());
  std::vector<uint8_t> image(257, 0x37), recovered(8192);
  auto package = signedPackage(image, signer);
  Manifest manifest; assert(manifest.parse(package.data(), package.size()) == Result::Ok);
  assert(manifest.authorize(platform) == Result::Ok);
  Journal out; size_t bytes;
  assert(platform.recover(out, recovered.data(), recovered.size(), bytes) == Result::State);
  auto journal = candidate(package, Phase::Ready, 1); journal.nextChunk = 1;
  assert(platform.save(journal, package.data(), package.size()) == Result::Ok);
  assert(platform.beginStaging(image.size()) == Result::Ok);
  for (size_t offset = 0; offset < image.size(); offset += 128)
    assert(platform.writeStaging(offset, image.data() + offset,
        image.size() - offset < 128 ? image.size() - offset : 128) == Result::Ok);
  assert(platform.validateInstall(manifest.canonical(), manifest.bootSignature(), signer.publicKey()) == Result::Ok);
  platform.revoked = true;
  assert(platform.validateInstall(manifest.canonical(), manifest.bootSignature(), signer.publicKey()) == Result::Denied);
  platform.revoked = false; platform.floor = 9;
  assert(platform.validateInstall(manifest.canonical(), manifest.bootSignature(), signer.publicKey()) == Result::Replay);
  platform.floor = 0;
  uint8_t signature[64]; std::memcpy(signature, manifest.bootSignature(), 64); signature[5] ^= 1;
  assert(platform.validateInstall(manifest.canonical(), signature, signer.publicKey()) == Result::Denied);
  const uint8_t zero = 0;
  assert(::ota::platform::isOk(payload.program(0, &zero, 1)));
  assert(platform.validateInstall(manifest.canonical(), manifest.bootSignature(), signer.publicKey()) == Result::Integrity);
  FirmwareFixture cold(payload, metadata, verifier, signer.publicKey());
  assert(cold.recover(out, recovered.data(), recovered.size(), bytes) == Result::Ok);
  assert(cold.validateInstall(manifest.canonical(), manifest.bootSignature(), signer.publicKey()) == Result::Integrity);
  for (uint32_t i = 32768; i < flash.rawSize(); ++i) assert(flash.rawBuffer()[i] == 0xFF);
}
class EspMetadataModel final : public ::ota::storage::Esp32PartitionApi {
public:
  EspMetadataModel() : bytes(0x800000, 0x5a) {
    using namespace ::ota::storage;
    snapshot.count = 6; snapshot.flashSize = snapshot.physicalFlashSize = bytes.size();
    for (size_t i = 0; i < 6; ++i) snapshot.table[i] = Esp32S3PartitionLayout::entry(i);
    snapshot.running = snapshot.boot = snapshot.table[2]; snapshot.next = snapshot.table[3];
    const auto begin = snapshot.table[2].address + ::ota::platform::Esp32OtaMetadataAdapter::kOffset;
    std::fill(bytes.begin() + begin, bytes.begin() + begin + 16384, 0xff);
  }
  ::ota::storage::Esp32SdkError inspect(::ota::storage::Esp32PartitionSnapshot& out) const override {
    out = snapshot; return 0;
  }
  ::ota::storage::Esp32SdkError read(const ::ota::storage::Esp32PartitionIdentity& p, uint32_t offset,
                                    uint8_t* out, uint32_t size) const override {
    bounds(p, offset, size); std::memcpy(out, bytes.data() + p.address + offset, size); return 0;
  }
  ::ota::storage::Esp32SdkError write(const ::ota::storage::Esp32PartitionIdentity& p, uint32_t offset,
                                     const uint8_t* in, uint32_t size) override {
    bounds(p, offset, size); std::memcpy(bytes.data() + p.address + offset, in, size); return 0;
  }
  ::ota::storage::Esp32SdkError erase(const ::ota::storage::Esp32PartitionIdentity& p, uint32_t offset,
                                     uint32_t size) override {
    bounds(p, offset, size); std::memset(bytes.data() + p.address + offset, 0xff, size); return 0;
  }
  std::vector<uint8_t> bytes;
  ::ota::storage::Esp32PartitionSnapshot snapshot;
private:
  static void bounds(const ::ota::storage::Esp32PartitionIdentity& p, uint32_t offset, uint32_t size) {
    assert(::ota::storage::esp32PartitionEquals(p, ::ota::storage::Esp32S3PartitionLayout::entry(2)));
    assert(offset >= ::ota::platform::Esp32OtaMetadataAdapter::kOffset &&
        offset <= p.size && size <= p.size - offset);
  }
};
static void espMetadataHasNoPersonaOrPayloadCapability() {
  EspMetadataModel sdk;
  ::ota::platform::Esp32OtaMetadataAdapter device(sdk);
  Region region(device, 0, device.kBytes); Store store(region);
  std::vector<uint8_t> manifest(4707, 0x73), recovered(8192); Journal out;
  assert(load(store, out, recovered) == Result::State);
  auto journal = candidate(manifest, Phase::Ready, 4);
  assert(store.save(journal, manifest.data(), manifest.size()) == Result::Ok);
  sdk.snapshot.running = sdk.snapshot.boot = sdk.snapshot.table[3]; sdk.snapshot.next = sdk.snapshot.table[2];
  sdk.snapshot.appStates[1] = ::ota::storage::Esp32ImageState::PendingVerify;
  Store cold(region);
  assert(load(cold, out, recovered) == Result::Ok && out.phase == Phase::Ready);
  journal.phase = Phase::Trial;
  assert(cold.save(journal, manifest.data(), manifest.size()) == Result::Ok);
  const uint8_t zero = 0;
  assert(device.program(UINT32_MAX, &zero, 1) == ::ota::platform::FlashStatus::OutOfRange);
  assert(device.eraseSector(device.kBytes) == ::ota::platform::FlashStatus::OutOfRange);
  const auto begin = 0x10000 + device.kOffset;
  for (size_t i = 0; i < sdk.bytes.size(); ++i)
    if (i < begin || i >= begin + device.kBytes) assert(sdk.bytes[i] == 0x5a);
  sdk.snapshot.table[0].address += 4096;
  assert(device.program(0, &zero, 1) == ::ota::platform::FlashStatus::InvalidArgument);
}
static void le16(uint8_t* p, uint16_t value) { p[0] = value; p[1] = value >> 8; }
static void le32(uint8_t* p, uint32_t value) {
  for (size_t i = 0; i < 4; ++i) p[i] = value >> (i * 8);
}
class RunningModel final : public NrfRunningReader {
public:
  RunningModel() : image(132, 0x37) {
    context.image = image.data(); context.capacity = image.size(); context.settingsTailErased = true;
    le16(context.settings, 1); le16(context.settings + 4, 0xff); le32(context.settings + 8, 129);
    le16(context.settings + 2, NrfBootSafety::Bridge::crc16Compute(image.data(), 129));
    le32(marker, BootInfo::kMagic); le16(marker + 4, 1); le16(marker + 6, sizeof(marker));
    le32(marker + 8, 0x584e3430); le32(marker + 12, 1); le32(marker + 16, 1);
    le16(marker + 20, 1); le16(marker + 22, 1);
    le32(marker + 56, ::ota::storage::Crc32::computeFinalized(marker, 56));
  }
  BootInfo::RecordStatus readBootInfo(BootInfo::Info& out) const override {
    return BootInfo::classify(marker, sizeof(marker), out);
  }
  bool read(NrfRunningContext& out) const override {
    out = context;
    if (changeOnSecondRead && ++reads == 2) image[11] ^= 1;
    return true;
  }
  mutable std::vector<uint8_t> image;
  NrfRunningContext context;
  mutable unsigned reads = 0;
  bool changeOnSecondRead = false;
  uint8_t marker[BootInfo::kStructBytes] = {};
};
static std::vector<uint8_t> floorRecord(uint32_t sequence, uint32_t counter, uint32_t size,
                                       const uint8_t hash[32]) {
  using Floor = NrfBootSafety::Floor;
  std::vector<uint8_t> record(Floor::kRecordBytes);
  le32(record.data(), Floor::kMagic); le16(record.data() + 4, 1);
  le16(record.data() + 6, record.size()); le32(record.data() + 8, sequence);
  le32(record.data() + 12, counter); le32(record.data() + 16, size);
  std::memcpy(record.data() + 20, hash, 32);
  le32(record.data() + 52, ::ota::storage::Crc32::computeFinalized(record.data(), 52));
  le32(record.data() + 56, Floor::kCommitMarker);
  return record;
}
static void nrfActualBootRecordsGateMutationAndRestoration() {
  Flash flash(32768, 4096);
  Region commands(flash, 0, 8192), state(flash, 8192, 8192), floor(flash, 16384, 8192), confirm(flash, 24576, 8192);
  RunningModel running;
  ::ota::trust::Ed25519SignatureVerifier verifier;
  const auto policy = testPolicy();
  NrfBootSafety safety(commands, state, floor, confirm, running, verifier, policy);
  NrfBootSafety::Snapshot snapshot;
  assert(!safety.normal(snapshot));
  uint8_t zeroHash[32] = {};
  auto genesis = floorRecord(1, 0, 0, zeroHash);
  assert(::ota::platform::isOk(floor.program(0, genesis.data(), genesis.size())));
  assert(safety.normal(snapshot) && !snapshot.confirmed && snapshot.floor == 0);
  auto counterfeitGenesis = floorRecord(2, 0, 0, zeroHash);
  assert(::ota::platform::isOk(floor.program(4096, counterfeitGenesis.data(), counterfeitGenesis.size())));
  assert(!safety.normal(snapshot));
  assert(::ota::platform::isOk(floor.eraseSector(4096)));
  running.changeOnSecondRead = true; running.reads = 0;
  le16(running.context.settings + 2, 0);
  assert(!safety.normal(snapshot));
  running.changeOnSecondRead = false; running.image[11] ^= 1;
  le16(running.context.settings + 2, NrfBootSafety::Bridge::crc16Compute(running.image.data(), 129));
  uint8_t rawHash[32], backupHash[32];
  ::ota::trust::Sha256::hash(running.image.data(), 129, rawHash);
  ::ota::trust::Sha256::hash(running.image.data(), 132, backupHash);
  assert(::ota::platform::isOk(floor.eraseSector(0)));
  auto confirmedFloor = floorRecord(3, 7, 129, rawHash);
  assert(::ota::platform::isOk(floor.program(0, confirmedFloor.data(), confirmedFloor.size())));
  using State = NrfBootSafety::State;
  std::vector<uint8_t> record(State::kRecordBytes);
  le32(record.data(), State::kMagic); le16(record.data() + 4, 1); le16(record.data() + 6, record.size());
  le32(record.data() + 8, 8); le32(record.data() + 12, 111);
  le32(record.data() + 20, State::kPhaseConfirmed); le32(record.data() + 28, 132);
  le32(record.data() + 32, 7);
  std::memcpy(record.data() + 44, rawHash, 32); std::memcpy(record.data() + 108, rawHash, 32);
  auto commitState = [&] {
    le32(record.data() + 144, ::ota::storage::Crc32::computeFinalized(record.data(), 144));
    le32(record.data() + 148, State::kCommitMarker);
    assert(::ota::platform::isOk(state.eraseSector(0)));
    assert(::ota::platform::isOk(state.program(0, record.data(), record.size())));
  };
  commitState();
  assert(safety.normal(snapshot) && snapshot.confirmed);
  const uint8_t seed[32] = {17}; ::ota::test::Ed25519TestSigner signer(seed);
  {
    Flash stagingFlash(32768, 4096); Region payload(stagingFlash, 0, 16384), metadata(stagingFlash, 16384, 16384);
    NrfFirmwarePlatform platform(policy, payload, metadata, commands, state, floor, confirm, verifier,
                                 running, nullptr);
    RuntimeHooks hooks; hooks.context = &signer;
    hooks.isCurrentAdmin = [](void* context, const uint8_t key[32]) {
      return !std::memcmp(key, static_cast<::ota::test::Ed25519TestSigner*>(context)->publicKey(), 32);
    };
    platform.attach(hooks);
    std::vector<uint8_t> actual(running.image.begin(), running.image.begin() + 129), recovered(8192);
    auto confirmedPackage = signedPackage(actual, signer, 7);
    Journal out; size_t size;
    assert(platform.recover(out, recovered.data(), recovered.size(), size) == Result::State);
    auto journal = candidate(confirmedPackage, Phase::Confirmed, 1); journal.nextChunk = 1;
    assert(platform.save(journal, confirmedPackage.data(), confirmedPackage.size()) == Result::Ok);
    RunningEvidence evidence; Phase boot;
    assert(platform.evidence(evidence) == Result::Ok && evidence.flags == 3);
    assert(platform.lifecycle(boot) == Result::State);
    const auto nonce = NrfFirmwarePlatform::transactionNonce(journal.transaction, journal.generation,
        confirmedPackage.data() + 40, signer.publicKey());
    for (size_t i = 0; i < 8; ++i) record[12 + i] = nonce >> (i * 8);
    commitState();
    assert(platform.evidence(evidence) == Result::Ok && evidence.flags == 7);
    assert(platform.lifecycle(boot) == Result::Ok && boot == Phase::Confirmed);
    journal.transaction[1] ^= 1;
    assert(platform.save(journal, confirmedPackage.data(), confirmedPackage.size()) == Result::Ok);
    assert(platform.evidence(evidence) == Result::Ok && evidence.flags == 3);
    assert(platform.lifecycle(boot) == Result::State);
    std::memset(record.data() + 12, 0, 8); le32(record.data() + 12, 111);
    commitState();
  }
  std::vector<uint8_t> image(257, 0x37);
  auto package = signedPackage(image, signer);
  ::ota::storage::XiaoOtaCommandV3Fields command;
  command.transaction_nonce = 111; command.active_image_extent = 132;
  std::memcpy(command.wire_descriptor, package.data() + 40, 59);
  std::memcpy(command.signature_ed25519, package.data() + 99, 64);
  std::memcpy(command.admitted_signer_public_key_ed25519, signer.publicKey(), 32);
  std::memcpy(command.active_image_hash_sha256, backupHash, 32);
  assert(NrfBootSafety::Command::writeNext(commands, command));
  assert(!safety.normal(snapshot));
  le32(record.data() + 20, State::kPhaseFailedMax); le32(record.data() + 32, 9);
  std::memcpy(record.data() + 36, running.context.settings, 4);
  std::memcpy(record.data() + 40, running.context.settings + 8, 4);
  std::memcpy(record.data() + 44, package.data() + 53, 32);
  std::memcpy(record.data() + 76, backupHash, 32);
  commitState();
  assert(!safety.normal(snapshot));
  uint8_t sidecar[88] = {};
  le32(sidecar, 0x58534944); le16(sidecar + 4, 1); le16(sidecar + 6, sizeof(sidecar));
  std::memcpy(sidecar + 8, record.data() + 8, 12);
  std::memcpy(sidecar + 52, running.context.settings, 28);
  le32(sidecar + 80, ::ota::storage::Crc32::computeFinalized(sidecar, 80));
  le32(sidecar + 84, State::kCommitMarker);
  assert(::ota::platform::isOk(state.program(0x100, sidecar, sizeof(sidecar))));
  assert(safety.normal(snapshot) && !snapshot.confirmed && snapshot.phase == State::kPhaseFailedMax);
  const uint8_t zero = 0;
  assert(::ota::platform::isOk(state.program(0x200, &zero, 1)));
  assert(!safety.normal(snapshot));
}
class EspTrialModel final : public mesh::ota::Esp32TrialPlatform {
public:
  bool runningState(::ota::storage::Esp32ImageState& out) override { out = state; return readable; }
  bool unknownTopologyHoldAllowed() override { return holdAllowed; }
  bool armWatchdog(uint32_t remaining) override { armedFor = remaining; return true; }
  void disarmWatchdog() override { ++disarmed; }
  mesh::ota::Esp32TrialConfirmation confirmHealthy() override {
    ++confirmations;
    if (confirmation != mesh::ota::Esp32TrialConfirmation::Unconfirmed)
      state = ::ota::storage::Esp32ImageState::Valid;
    return confirmation;
  }
  void reportUnknownService() override { ++reports; }
  void restartWithoutRollback() override { ++restarts; }
  void rollbackAndRestart() override { ++rollbacks; }
  ::ota::storage::Esp32ImageState state = ::ota::storage::Esp32ImageState::PendingVerify;
  mesh::ota::Esp32TrialConfirmation confirmation = mesh::ota::Esp32TrialConfirmation::Confirmed;
  bool readable = true, holdAllowed = false;
  uint32_t armedFor = 0, disarmed = 0, confirmations = 0, reports = 0, restarts = 0, rollbacks = 0;
};
static void espTrialKeepsRealHealthAndBootDeadlines() {
  using namespace mesh::ota;
  EspTrialModel healthy;
  Esp32TrialController controller(healthy);
  assert(controller.begin(0));
  assert(healthy.armedFor == 45000);
  for (uint32_t now = 0; now < 10000; now += 1000)
    assert(controller.tick(now, true, true, true) == Esp32TrialHealthOutcome::Pending);
  assert(controller.tick(10000, true, true, true) == Esp32TrialHealthOutcome::Confirmed);
  assert(healthy.confirmations == 1 && healthy.disarmed == 1 && !controller.activeOrUnknown());
  controller.tick(11000, true, true, true);
  assert(healthy.confirmations == 1);
  EspTrialModel late;
  Esp32TrialController delayed(late);
  assert(delayed.begin(40000) && late.armedFor == 5000);
  for (uint32_t now = 40000; now < 45000; now += 1000)
    assert(delayed.tick(now, true, true, true) == Esp32TrialHealthOutcome::Pending);
  assert(delayed.tick(45000, true, true, true) == Esp32TrialHealthOutcome::DeadlineExpired);
  assert(late.confirmations == 0 && late.rollbacks == 1);
  EspTrialModel interrupted;
  Esp32TrialController gap(interrupted);
  assert(gap.begin(0));
  for (uint32_t now = 0; now <= 9000; now += 1000) gap.tick(now, true, true, true);
  assert(gap.tick(11001, true, true, true) == Esp32TrialHealthOutcome::Pending);
  for (uint32_t now = 12001; now < 21001; now += 1000)
    assert(gap.tick(now, true, true, true) == Esp32TrialHealthOutcome::Pending);
  assert(gap.tick(21001, true, true, true) == Esp32TrialHealthOutcome::Confirmed);
  EspTrialModel uncertain;
  uncertain.confirmation = Esp32TrialConfirmation::ValidNeedsFloorReconciliation;
  Esp32TrialController forward(uncertain);
  assert(forward.begin(0));
  for (uint32_t now = 0; now <= 10000; now += 1000) forward.tick(now, true, true, true);
  assert(uncertain.confirmations == 1 && uncertain.restarts == 1 && !uncertain.rollbacks);
}
static void espUnknownStartupNeverConfirmsOrLoopsUnbounded() {
  using namespace mesh::ota;
  Esp32StartupRestartState retained = {};
  for (unsigned attempt = 0; attempt < 3; ++attempt) {
    EspTrialModel unknown; unknown.readable = false; unknown.holdAllowed = true;
    Esp32TrialController controller(unknown, &retained);
    assert(!controller.begin(1000) && controller.activeOrUnknown());
    if (attempt < 2) assert(unknown.restarts == 1 && !controller.unknownServiceHeld());
    else assert(!unknown.restarts && controller.unknownServiceHeld() && unknown.disarmed == 1);
    controller.tick(11000, true, true, true);
    assert(!unknown.confirmations && !unknown.rollbacks);
  }
}
int main() {
  journalRoundTrip();
  revokedReadyCannotResurrect();
  committedAbortWithFailedReadbackRemainsRevoked();
  corruptNewestNeverFallsBackAndRepairIsExplicit();
  chunkRestartKeepsVerifiedPrefix();
  repairCannotResurrectReadyAtAnyCut();
  genuineCanonicalInstallBoundary();
  espMetadataHasNoPersonaOrPayloadCapability();
  nrfActualBootRecordsGateMutationAndRestoration();
  espTrialKeepsRealHealthAndBootDeadlines();
  espUnknownStartupNeverConfirmsOrLoopsUnbounded();
  std::puts("OTA v4 journal power cuts, revocation/repair, raw staging, real signatures and ESP persona bounds passed");
}
