#include <gtest/gtest.h>
#include <helpers/ota/OtaV4Receiver.h>
#include "../test_lora_ota_trust/Ed25519TestSigner.h"
#include <algorithm>
#include <memory>
#include <vector>

using namespace mesh::ota::v4;
namespace {
const uint8_t adminSeed[32] = {17};
const uint8_t deviceSeed[32] = {29};
using Signer = ::ota::test::Ed25519TestSigner;

std::vector<uint8_t> transcript(const char* domain, size_t domainSize,
                                const uint8_t* bytes, size_t size) {
  std::vector<uint8_t> result;
  if (domainSize) result.insert(result.end(), domain, domain + domainSize);
  result.insert(result.end(), bytes, bytes + size);
  return result;
}

class MemoryPlatform : public Platform {
public:
  Signer admin{adminSeed}, device{deviceSeed};
  Policy configuration;
  RunningEvidence running;
  Journal durable;
  std::vector<uint8_t> manifest, staging;
  bool initialized = false, revoked = false, corrupt = false, failSave = false;
  bool failRead = false, failWrite = false, failInstall = false, active = false;
  bool weakEntropy = false;
  size_t writes = 0, installs = 0, leases = 0;
  uint32_t entropy = 0;
  Phase bootPhase = Phase::ActivationPending;

  MemoryPlatform() {
    configuration.boardFamily = 1; configuration.boardVariant = 2;
    configuration.role = 1; configuration.appAddress = 0x27000;
    configuration.maxImageBytes = kChunkBytes * kMaxChunks;
    configuration.bootloaderCapabilities = 7;
    running.flags = FloorKnown;
  }
  Policy policy() const override { return configuration; }
  Result identity(uint8_t out[32]) override {
    std::memcpy(out, device.publicKey(), 32); return Result::Ok;
  }
  Result evidence(RunningEvidence& out) override { out = running; return Result::Ok; }
  Result random(uint8_t* out, size_t size) override {
    if (weakEntropy) { std::memset(out, 0, size); return Result::Ok; }
    const uint32_t counter = ++entropy;
    uint8_t digest[32];
    ::ota::trust::Sha256::hash(reinterpret_cast<const uint8_t*>(&counter), 4, digest);
    std::memcpy(out, digest, size); return Result::Ok;
  }
  bool isCurrentAdmin(const uint8_t key[32]) override {
    return !revoked && !std::memcmp(key, admin.publicKey(), 32);
  }
  bool verify(const uint8_t key[32], const char* domain, size_t domainSize,
              const uint8_t* bytes, size_t size, const uint8_t sig[64]) override {
    const auto message = transcript(domain, domainSize, bytes, size);
    return ::ota::trust::ed25519_impl::ed25519_verify(sig, message.data(), message.size(), key);
  }
  Result sign(const char* domain, size_t domainSize, const uint8_t* bytes,
              size_t size, uint8_t sig[64]) override {
    const auto message = transcript(domain, domainSize, bytes, size);
    device.sign(message.data(), message.size(), sig); return Result::Ok;
  }
  Result recover(Journal& out, uint8_t* bytes, size_t capacity, size_t& size) override {
    if (corrupt) return Result::Integrity;
    if (!initialized) return Result::State;
    if (manifest.size() > capacity) return Result::Integrity;
    out = durable; size = manifest.size();
    std::copy(manifest.begin(), manifest.end(), bytes); return Result::Ok;
  }
  Result save(const Journal& j, const uint8_t* bytes, size_t size) override {
    if (failSave) return Result::Io;
    durable = j; initialized = true;
    manifest.assign(bytes, bytes + size); return Result::Ok;
  }
  Result beginStaging(uint32_t size) override { staging.resize(size); return Result::Ok; }
  Result writeStaging(uint32_t offset, const uint8_t* bytes, size_t size) override {
    if (failWrite || offset + size > staging.size()) return Result::Io;
    EXPECT_LE(size, kSliceBytes);
    std::copy(bytes, bytes + size, staging.begin() + offset); ++writes; return Result::Ok;
  }
  Result readStaging(uint32_t offset, uint8_t* bytes, size_t size) override {
    if (failRead || offset + size > staging.size()) return Result::Io;
    EXPECT_LE(size, kSliceBytes);
    std::copy(staging.begin() + offset, staging.begin() + offset + size, bytes);
    return Result::Ok;
  }
  Result clearStaging() override { staging.clear(); return Result::Ok; }
  Result repair(const Journal& j) override {
    if (active) return Result::State;
    corrupt = false; staging.clear(); manifest.clear();
    durable = j; initialized = true; return Result::Ok;
  }
  Result validateInstall(const uint8_t canonical[59], const uint8_t sig[64],
                         const uint8_t signer[32]) override {
    if (failInstall) return Result::Io;
    uint8_t digest[32];
    ::ota::trust::Sha256::hash(staging.data(), staging.size(), digest);
    return staging.size() == read32(canonical + 9) && !std::memcmp(digest, canonical + 13, 32) &&
        isCurrentAdmin(signer) && verify(signer, nullptr, 0, canonical, 59, sig) ?
        Result::Ok : Result::Integrity;
  }
  Result activate(const uint8_t[59], const uint8_t[64], const uint8_t[32],
                  const uint8_t[16], uint32_t) override {
    active = true; ++installs; return Result::Ok;
  }
  Result lifecycle(Phase& phase) override {
    if (!active || bootPhase == Phase::ActivationPending) return Result::State;
    phase = bootPhase; return Result::Ok;
  }
  Result lease(uint32_t, uint32_t, uint8_t, uint8_t, uint32_t) override {
    ++leases; return Result::Ok;
  }
};

class CoreTest : public ::testing::Test {
protected:
  MemoryPlatform p;
  std::unique_ptr<Receiver> receiver;
  std::vector<uint8_t> image, package;
  uint32_t attempt = 0;
  void SetUp() override {
    receiver.reset(new Receiver(p));
    ASSERT_EQ(Result::Ok, receiver->begin());
    image.resize(8192 + 137);
    for (size_t i = 0; i < image.size(); ++i) image[i] = static_cast<uint8_t>(i * 73);
    build();
  }
  void build(Codec codec = Codec::Raw, const std::vector<uint8_t>& stored = {}) {
    const size_t count = (image.size() + kChunkBytes - 1) / kChunkBytes;
    package.assign(kManifestPrefixBytes + count * kManifestEntryBytes + 64, 0);
    std::memcpy(package.data(), "MCO4", 4); package[4] = 4; package[5] = 13;
    write16(package.data() + 6, count);
    std::memcpy(package.data() + 8, p.admin.publicKey(), 32);
    Descriptor d;
    d.boardFamily = p.configuration.boardFamily; d.boardVariant = p.configuration.boardVariant;
    d.role = p.configuration.role; d.appAddress = p.configuration.appAddress;
    d.exactSizeBytes = image.size(); d.securityCounter = 9;
    d.minBootloaderCapabilities = 3;
    d.formatId = d.keyId = d.algorithmId = 1;
    ::ota::trust::Sha256::hash(image.data(), image.size(), d.sha256);
    size_t written;
    meshcore::ota::protocol::encodeOtaDescriptorCanonical(d, package.data() + 40, 59, written);
    p.admin.sign(package.data() + 40, 59, package.data() + 99);
    for (size_t i = 0; i < count; ++i) {
      uint8_t* entry = package.data() + kManifestPrefixBytes + i * kManifestEntryBytes;
      entry[0] = static_cast<uint8_t>(codec);
      const size_t raw = std::min(kChunkBytes, image.size() - i * kChunkBytes);
      write16(entry + 1, codec == Codec::Raw ? raw : stored.size());
      ::ota::trust::Sha256::hash(image.data() + i * kChunkBytes, raw, entry + 3);
    }
    resign();
  }
  void resign(bool boot = false) {
    if (boot) p.admin.sign(package.data() + 40, 59, package.data() + 99);
    auto message = transcript(kManifestDomain, sizeof(kManifestDomain),
                              package.data(), package.size() - 64);
    p.admin.sign(message.data(), message.size(), package.data() + package.size() - 64);
  }
  std::vector<uint8_t> packageHash() {
    std::vector<uint8_t> digest(32);
    ::ota::trust::Sha256::hash(package.data(), package.size(), digest.data()); return digest;
  }
  Result send(Kind kind, const std::vector<uint8_t>& bytes, const uint8_t tag[8],
              uint16_t object = 0, int onlySlice = -1) {
    Result result = Result::Ok;
    for (size_t i = 0; i < (bytes.size() + 127) / 128; ++i) {
      if (onlySlice >= 0 && i != static_cast<size_t>(onlySlice)) continue;
      uint8_t frame[kMaxFrameBytes];
      const size_t n = sliceSize(bytes.size(), i);
      const size_t size = encodeFrame(kind, ++attempt, tag, object, bytes.size(), i,
          bytes.data() + i * 128, n, frame, sizeof(frame));
      EXPECT_NE(0u, size);
      result = receiver->onFrame(frame, size);
      if (result != Result::Ok) break;
    }
    return result;
  }
  Result upload() { const auto tag = packageHash(); return send(Kind::Manifest, package, tag.data()); }
  std::vector<uint8_t> command(Kind kind) {
    std::vector<uint8_t> b(kind == Kind::Lease ? kLeaseCommandBytes : kCommandBytes);
    std::memcpy(b.data(), p.admin.publicKey(), 32);
    std::memcpy(b.data() + 32, p.device.publicKey(), 32);
    const auto hash = packageHash();
    if (kind != Kind::Repair) std::memcpy(b.data() + 64, hash.data(), 32);
    std::memcpy(b.data() + 96,
        kind == Kind::Admit || kind == Kind::Repair || kind == Kind::Lease ?
            receiver->challenge() : receiver->journal().transaction, 16);
    write32(b.data() + 112, receiver->journal().generation);
    if (kind == Kind::Lease) {
      write32(b.data() + 116, 915000); write32(b.data() + 120, 125000);
      b[124] = 7; b[125] = 5; write32(b.data() + 126, 60000);
    }
    signCommand(kind, b);
    return b;
  }
  void signCommand(Kind kind, std::vector<uint8_t>& b) {
    const char* domain = kind == Kind::Admit ? kAdmitDomain :
        kind == Kind::Activate ? kActivateDomain : kind == Kind::Abort ? kAbortDomain :
        kind == Kind::Repair ? kRepairDomain : kLeaseDomain;
    const auto message = transcript(domain, std::strlen(domain) + 1, b.data(), b.size() - 64);
    p.admin.sign(message.data(), message.size(), b.data() + b.size() - 64);
  }
  Result control(Kind kind) {
    auto bytes = command(kind);
    uint8_t zeroTag[8] = {};
    return send(kind, bytes, kind == Kind::Repair ? zeroTag : bytes.data() + 64);
  }
  void admit() {
    ASSERT_EQ(Result::Ok, upload());
    ASSERT_EQ(Result::Ok, control(Kind::Admit));
  }
  void pump(size_t ticks = 1024) {
    for (size_t i = 0; i < ticks; ++i) ASSERT_EQ(Result::Ok, receiver->tick());
  }
  void data(uint16_t index) {
    const size_t offset = index * kChunkBytes;
    std::vector<uint8_t> raw(image.begin() + offset,
                            image.begin() + std::min(image.size(), offset + kChunkBytes));
    ASSERT_EQ(Result::Ok, send(Kind::Data, raw, receiver->journal().packageHash, index));
  }
  void ready() {
    admit();
    const size_t count = (image.size() + kChunkBytes - 1) / kChunkBytes;
    for (size_t i = 0; i < count; ++i) { data(i); pump(); }
    ASSERT_EQ(Phase::Ready, receiver->journal().phase);
  }
  void restart() {
    receiver.reset(new Receiver(p));
    ASSERT_EQ(Result::Ok, receiver->begin());
  }
};

TEST_F(CoreTest, SignedAdmissionRawIntegrityAndFreshStatus) {
  ASSERT_EQ(Result::Ok, upload());
  EXPECT_EQ(Phase::Idle, receiver->journal().phase);
  EXPECT_FALSE(p.initialized);
  auto admitBytes = command(Kind::Admit);
  auto stale = admitBytes;
  ASSERT_EQ(Result::Ok, send(Kind::Admit, admitBytes, admitBytes.data() + 64));
  EXPECT_EQ(1u, receiver->journal().generation);
  EXPECT_NE(0, std::memcmp(stale.data() + 96, receiver->challenge(), 16));
  EXPECT_EQ(Result::Replay, send(Kind::Admit, stale, stale.data() + 64));
  data(0); pump();
  EXPECT_EQ(1u, receiver->journal().nextChunk);
  EXPECT_EQ(64u, p.writes);
  data(1); pump();
  ASSERT_EQ(Phase::Ready, receiver->journal().phase);
  EXPECT_EQ(image, p.staging);

  std::vector<uint8_t> query(kQueryBytes);
  std::memcpy(query.data(), p.device.publicKey(), 32); query[32] = 123;
  uint8_t zeroTag[8] = {};
  ASSERT_EQ(Result::Ok, send(Kind::Query, query, zeroTag, 479));
  std::vector<uint8_t> status;
  size_t size;
  while (const uint8_t* bytes = receiver->peek(size)) {
    Frame f;
    ASSERT_TRUE(decodeFrame(bytes, size, f)); EXPECT_EQ(479u, f.object);
    status.insert(status.end(), f.data, f.data + f.size); receiver->release();
  }
  ASSERT_EQ(kStatusBytes, status.size());
  EXPECT_EQ(123, status[32]);
  EXPECT_EQ(Phase::Ready, static_cast<Phase>(status[124]));
  EXPECT_EQ(FloorKnown, status[168]);
  EXPECT_TRUE(p.verify(p.device.publicKey(), kStatusDomain, sizeof(kStatusDomain),
                       status.data(), kSignedStatusBytes, status.data() + kSignedStatusBytes));
  status[32] ^= 1;
  EXPECT_FALSE(p.verify(p.device.publicKey(), kStatusDomain, sizeof(kStatusDomain),
                        status.data(), kSignedStatusBytes, status.data() + kSignedStatusBytes));
}

TEST_F(CoreTest, RejectsRealSignatureTamperingAndNonCurrentAuthority) {
  package.back() ^= 1;
  EXPECT_EQ(Result::Denied, upload());
  package.back() ^= 1;
  ASSERT_EQ(Result::Ok, upload());
  auto bytes = command(Kind::Admit);
  bytes[179] ^= 1;
  EXPECT_EQ(Result::Denied, send(Kind::Admit, bytes, bytes.data() + 64));
  EXPECT_FALSE(p.initialized);
  p.revoked = true;
  EXPECT_EQ(Result::Denied, control(Kind::Admit));
  EXPECT_FALSE(p.initialized);
}

TEST_F(CoreTest, AllMetadataBoundsPrecedeStaging) {
  const auto original = package;
  for (size_t offset : {size_t(40), size_t(42), size_t(44), size_t(45), size_t(93),
                         size_t(95), size_t(97)}) {
    package = original; package[offset] ^= 1; resign(true);
    EXPECT_NE(Result::Ok, upload()) << offset;
    EXPECT_FALSE(p.initialized);
    EXPECT_TRUE(p.staging.empty());
  }
  package = original;
  write32(package.data() + 85, 0); resign(true);
  EXPECT_EQ(Result::Replay, upload());
  package = original;
  write32(package.data() + 89, 0x80000000); resign(true);
  EXPECT_EQ(Result::Unsupported, upload());
  package = original; package[kManifestPrefixBytes] = 3; resign();
  EXPECT_EQ(Result::Unsupported, upload());
}

TEST_F(CoreTest, MissingBitmapAndConflictingDuplicateDoNotWriteOrDropSlices) {
  admit();
  std::vector<uint8_t> raw(image.begin(), image.begin() + kChunkBytes);
  ASSERT_EQ(Result::Ok, send(Kind::Data, raw, receiver->journal().packageHash, 0, 3));
  raw[3 * 128] ^= 1;
  EXPECT_EQ(Result::Integrity, send(Kind::Data, raw, receiver->journal().packageHash, 0, 3));
  std::vector<uint8_t> query(p.device.publicKey(), p.device.publicKey() + 32);
  ASSERT_EQ(Result::Ok, send(Kind::ProgressQuery, query, receiver->journal().packageHash, 9));
  size_t size; Frame f;
  const uint8_t* frame = receiver->peek(size);
  ASSERT_TRUE(decodeFrame(frame, size, f));
  EXPECT_EQ(UINT64_MAX & ~(UINT64_C(1) << 3), read64(f.data + 38));
  receiver->release();
  EXPECT_EQ(0u, p.writes);
  raw[3 * 128] ^= 1;
  ASSERT_EQ(Result::Ok, send(Kind::Data, raw, receiver->journal().packageHash));
  pump();
  EXPECT_EQ(1u, receiver->journal().nextChunk);
}

TEST_F(CoreTest, CorruptDecodedChunkNeverReachesFlashAndCanBeRetried) {
  admit();
  std::vector<uint8_t> raw(image.begin(), image.begin() + kChunkBytes);
  raw[0] ^= 1;
  ASSERT_EQ(Result::Ok, send(Kind::Data, raw, receiver->journal().packageHash));
  for (size_t i = 0; i < 63; ++i) EXPECT_EQ(Result::Ok, receiver->tick());
  EXPECT_EQ(Result::Integrity, receiver->tick());
  EXPECT_EQ(0u, p.writes);
  EXPECT_EQ(0u, p.durable.nextChunk);
  data(0); pump();
  EXPECT_EQ(1u, p.durable.nextChunk);
}

TEST_F(CoreTest, FullImageHashIsCheckedEvenWhenEveryChunkHashIsValid) {
  package[40 + 13] ^= 1; resign(true);
  admit(); data(0); pump();
  data(1);
  Result r = Result::Ok;
  for (size_t i = 0; i < 1024 && r == Result::Ok; ++i) r = receiver->tick();
  EXPECT_EQ(Result::Integrity, r);
  EXPECT_EQ(Phase::Failed, receiver->journal().phase);
  EXPECT_EQ(Phase::Failed, p.durable.phase);
  EXPECT_EQ(0u, p.installs);
}

TEST_F(CoreTest, CommandsBindFullTargetPackageChallengeAndGeneration) {
  ASSERT_EQ(Result::Ok, upload());
  for (size_t offset : {size_t(32), size_t(64), size_t(96), size_t(112)}) {
    auto bytes = command(Kind::Admit);
    bytes[offset] ^= 1; signCommand(Kind::Admit, bytes);
    const auto tag = packageHash();
    EXPECT_NE(Result::Ok, send(Kind::Admit, bytes, tag.data()));
    EXPECT_FALSE(p.initialized);
  }
}

TEST_F(CoreTest, RebootResumesVerifiedChunksAndLosesOnlyActiveRamChunk) {
  admit(); data(0); pump();
  ASSERT_EQ(Result::Ok, upload());
  EXPECT_EQ(1u, receiver->journal().nextChunk);
  std::vector<uint8_t> last(image.begin() + kChunkBytes, image.end());
  ASSERT_EQ(Result::Ok, send(Kind::Data, last, receiver->journal().packageHash, 1, 0));
  const auto nonce = std::vector<uint8_t>(receiver->journal().transaction,
                                         receiver->journal().transaction + 16);
  restart();
  EXPECT_EQ(Phase::Verifying, receiver->journal().phase);
  pump();
  EXPECT_EQ(Phase::Receiving, receiver->journal().phase);
  EXPECT_EQ(1u, receiver->journal().nextChunk);
  EXPECT_EQ(0, std::memcmp(nonce.data(), receiver->journal().transaction, 16));
  data(1); pump();
  EXPECT_EQ(Phase::Ready, receiver->journal().phase);
  restart(); pump();
  EXPECT_EQ(Phase::Ready, receiver->journal().phase);
}

TEST_F(CoreTest, CorruptDurableChunkAndTornJournalFailClosedUntilSignedRepair) {
  admit(); data(0); pump();
  p.staging[57] ^= 1;
  restart();
  for (size_t i = 0; i < 63; ++i) EXPECT_EQ(Result::Ok, receiver->tick());
  EXPECT_EQ(Result::Integrity, receiver->tick());
  EXPECT_EQ(Phase::MetadataFault, receiver->journal().phase);
  const auto floor = p.running.floor;
  ASSERT_EQ(Result::Ok, control(Kind::Repair));
  EXPECT_EQ(Phase::Idle, receiver->journal().phase);
  EXPECT_EQ(floor, p.running.floor);
  EXPECT_TRUE(p.staging.empty());
  p.corrupt = true;
  receiver.reset(new Receiver(p));
  EXPECT_EQ(Result::Integrity, receiver->begin());
  EXPECT_EQ(Phase::MetadataFault, receiver->journal().phase);
  ASSERT_EQ(Result::Ok, control(Kind::Repair));
  EXPECT_EQ(Phase::Idle, receiver->journal().phase);
}

TEST_F(CoreTest, AbortDurablyRevokesReadyAndReplayCannotReviveIt) {
  ready();
  auto activateBytes = command(Kind::Activate);
  auto abortBytes = command(Kind::Abort);
  ASSERT_EQ(Result::Ok, send(Kind::Abort, abortBytes, abortBytes.data() + 64));
  EXPECT_EQ(Phase::Aborted, p.durable.phase);
  EXPECT_TRUE(p.staging.empty());
  restart();
  EXPECT_EQ(Phase::Aborted, receiver->journal().phase);
  EXPECT_EQ(Result::Replay, send(Kind::Activate, activateBytes, activateBytes.data() + 64));
  EXPECT_EQ(Result::Replay, send(Kind::Abort, abortBytes, abortBytes.data() + 64));
  EXPECT_EQ(0u, p.installs);
}

TEST_F(CoreTest, ActivationRechecksAuthorityFloorAndInstallationHash) {
  ready();
  p.revoked = true;
  EXPECT_EQ(Result::Denied, control(Kind::Activate));
  p.revoked = false; p.running.floor = 9;
  EXPECT_EQ(Result::Replay, control(Kind::Activate));
  p.running.floor = 0; p.staging[0] ^= 1;
  EXPECT_EQ(Result::Integrity, control(Kind::Activate));
  EXPECT_EQ(0u, p.installs);
  EXPECT_EQ(Phase::Ready, receiver->journal().phase);
}

TEST_F(CoreTest, ConfirmedRequiresActualMatchingBootEvidenceAndRetainsTransaction) {
  ready();
  ASSERT_EQ(Result::Ok, control(Kind::Activate));
  EXPECT_EQ(Phase::ActivationPending, p.durable.phase);
  EXPECT_EQ(Result::State, control(Kind::Abort));
  EXPECT_EQ(Result::State, control(Kind::Repair));
  restart();
  p.bootPhase = Phase::Trial; pump(1);
  EXPECT_EQ(Phase::Trial, receiver->journal().phase);
  p.bootPhase = Phase::Confirmed;
  EXPECT_EQ(Result::Integrity, receiver->tick());
  p.running.flags = 7; p.running.floor = 9;
  ::ota::trust::Sha256::hash(image.data(), image.size(), p.running.hash);
  pump(1);
  EXPECT_EQ(Phase::Confirmed, receiver->journal().phase);
  EXPECT_EQ(package, p.manifest);
  EXPECT_EQ(1u, p.installs);
  p.running.hash[0] ^= 1;
  std::vector<uint8_t> query(kQueryBytes);
  std::memcpy(query.data(), p.device.publicKey(), 32);
  uint8_t zeroTag[8] = {};
  ASSERT_EQ(Result::Ok, send(Kind::Query, query, zeroTag));
  size_t size; Frame frame;
  const uint8_t* bytes = receiver->peek(size);
  ASSERT_TRUE(decodeFrame(bytes, size, frame));
  EXPECT_EQ(static_cast<uint8_t>(Phase::MetadataFault), frame.data[124]);
}

TEST_F(CoreTest, ExplicitIoFailuresNeverAdvanceDurableProgressOrReady) {
  admit(); data(0);
  pump(64);
  p.failWrite = true;
  EXPECT_EQ(Result::Io, receiver->tick());
  EXPECT_EQ(Phase::MetadataFault, receiver->journal().phase);
  EXPECT_EQ(0u, p.durable.nextChunk);
  p.failWrite = false;
  restart(); data(0); pump(127);
  p.failSave = true;
  EXPECT_EQ(Result::Io, receiver->tick());
  EXPECT_EQ(0u, p.durable.nextChunk);
  EXPECT_EQ(Phase::MetadataFault, receiver->journal().phase);
}

TEST_F(CoreTest, LeaseConsumesChallengeAndCannotExtendOnReplay) {
  admit();
  const auto bytes = command(Kind::Lease);
  ASSERT_EQ(Result::Ok, send(Kind::Lease, bytes, bytes.data() + 64));
  EXPECT_EQ(1u, p.leases);
  EXPECT_EQ(Result::Replay, send(Kind::Lease, bytes, bytes.data() + 64));
  EXPECT_EQ(1u, p.leases);
  auto tooLong = command(Kind::Lease);
  write32(tooLong.data() + 126, 60001); signCommand(Kind::Lease, tooLong);
  EXPECT_EQ(Result::Invalid, send(Kind::Lease, tooLong, tooLong.data() + 64));
}

TEST_F(CoreTest, Fixed8192LzmaAndThumbDecodeWithBoundedTicksAndNoTrailingBytes) {
  const uint8_t compressed[] = {
    0x00,0x00,0x6f,0xfd,0xff,0xff,0xa3,0xb7,0xff,0x44,0x1f,0x9a,0xf8,0xf3,
    0x8b,0x46,0x5f,0xcd,0x86,0x2b,0x4e,0xcd,0xd2,0xd4,0xf1,0x20,0xb4,0x30,
    0x28,0xd9,0xb4,0xfd,0x10,0x27,0x23,0xeb,0x7e,0xcf,0x7f,0xff,0xff,0xd8,
    0x38,0x00,0x00
  };
  std::vector<uint8_t> stored(compressed, compressed + sizeof(compressed));
  for (Codec codec : {Codec::Lzma, Codec::LzmaThumb}) {
    image.assign(8192, 0); build(codec, stored);
    admit();
    ASSERT_EQ(Result::Ok, send(Kind::Data, stored, receiver->journal().packageHash));
    pump(1024);
    EXPECT_EQ(Phase::Ready, receiver->journal().phase);
    EXPECT_EQ(image, p.staging);
    ASSERT_EQ(Result::Ok, control(Kind::Repair));
  }
  stored.push_back(0);
  build(Codec::Lzma, stored); admit();
  ASSERT_EQ(Result::Ok, send(Kind::Data, stored, receiver->journal().packageHash));
  Result last = Result::Ok;
  for (size_t i = 0; i < 256 && last == Result::Ok; ++i) last = receiver->tick();
  EXPECT_EQ(Result::Integrity, last);
  EXPECT_EQ(0u, receiver->journal().nextChunk);
  EXPECT_EQ(Phase::Receiving, receiver->journal().phase);
}

TEST_F(CoreTest, RejectsZeroEntropyInsteadOfInventingChallenge) {
  p.weakEntropy = true;
  receiver.reset(new Receiver(p));
  EXPECT_EQ(Result::Integrity, receiver->begin());
  EXPECT_EQ(Phase::MetadataFault, receiver->journal().phase);
}
}
