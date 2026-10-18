#include <cassert>
#include <cstdio>
#include <vector>
#include <helpers/ota/OtaBoardBackendCommon.h>
#include <helpers/ota/OtaBoardEsp32Trial.h>
#include <ota/platform/Esp32OtaMetadataAdapter.h>
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
int main() {
  journalRoundTrip();
  revokedReadyCannotResurrect();
  committedAbortWithFailedReadbackRemainsRevoked();
  corruptNewestNeverFallsBackAndRepairIsExplicit();
  chunkRestartKeepsVerifiedPrefix();
  std::puts("OTA v4 platform journal, power-cut revocation, repair and raw staging passed");
}
