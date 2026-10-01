// Native coverage for OtaBoardBaselineMeasurementSource::readDeviceIdentity()
// (see helpers/ota/OtaBoardBaselineMeasurementSource.h) -- the adapter's
// own identity-readiness guard, independent of any real board backend.
// This provides a test-local strong override of the weak-linked
// otaBoardBaselineReadUid8() free function (the same pattern used by
// variants/xiao_nrf52/OtaLabBackend.cpp and
// variants/sensecap_solar/OtaProductionBackend.cpp for the real boards),
// toggled per-case, to exercise the guard without any hardware.
#include <gtest/gtest.h>
#include <cstring>

#include "helpers/ota/OtaBoardBaselineMeasurementSource.h"
#include "helpers/ota/OtaFirmwareService.h"

namespace {

// Test-local controllable fake for the real board UID read -- flips
// between success/failure per test case; reset in SetUp() so cases never
// leak state into each other.
bool g_fake_uid_read_should_succeed = true;
uint8_t g_fake_uid8[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

} // namespace

namespace mesh {
namespace ota {

// Strong override of the weak default declared in
// OtaBoardBaselineMeasurementSource.h (defined as a safe fail-closed
// __attribute__((weak)) stub in examples/companion_radio/MyMesh.cpp,
// which is not part of this native test binary's build_src_filter -- see
// platformio.ini's [env:native] -- so this is the sole definition linked
// here, exactly mirroring how a real backend's strong override works).
bool otaBoardBaselineReadUid8(uint8_t out_uid8[8]) {
  if (!g_fake_uid_read_should_succeed) return false;
  memcpy(out_uid8, g_fake_uid8, 8);
  return true;
}

// The adapter's vtable requires a real definition for every declared
// free function (constructing ANY instance emits every virtual override,
// which references these) -- minimal safe fail-closed stubs for the
// facilities this test suite does not exercise.
bool otaBoardBaselineReadCompiledProfile(uint32_t&, uint32_t&, uint32_t&, uint32_t&) { return false; }
bool otaBoardBaselineReadRawCurrentSdkSettings(uint8_t[kOtaCurrentSdkSettingsRecordBytes]) { return false; }
bool otaBoardBaselineReadValidatedBank0Extent(uint32_t&, uint32_t&, uint16_t&) { return false; }
OtaBaselineMeasurementSubStep otaBoardBaselineStepAppImageAccess(uint32_t, uint32_t*, const uint8_t**, uint32_t*) {
  return OtaBaselineMeasurementSubStep::Failed;
}
OtaBaselineMeasurementSubStep otaBoardBaselineStepStockLoaderRangeHash(uint32_t, uint32_t*, uint32_t&, uint32_t&,
                                                                       uint8_t[32]) {
  return OtaBaselineMeasurementSubStep::Failed;
}
OtaBaselineMeasurementSubStep otaBoardBaselineStepBootConfigSelection(uint32_t, uint32_t*, uint32_t&, bool&, bool&) {
  return OtaBaselineMeasurementSubStep::Failed;
}
OtaBaselineMeasurementSubStep otaBoardBaselineStepQspiStateInspection(uint32_t, uint32_t*) {
  return OtaBaselineMeasurementSubStep::Failed;
}
bool otaBoardBaselineGetPlatformEntropy16(uint8_t[16]) { return false; }
OtaBaselineMeasurementArbiterResult otaBoardBaselineAcquireMediaArbiter() {
  return OtaBaselineMeasurementArbiterResult::Unavailable;
}
void otaBoardBaselineReleaseMediaArbiter() {}

} // namespace ota
} // namespace mesh

using mesh::ota::OtaBoardBaselineMeasurementSource;
using mesh::ota::OtaFirmwareService;

namespace {

const uint8_t kRealPubkey32[32] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

// Sentinel pattern used to fill output buffers before each call, so a
// refusal path can be proven to leave them byte-for-byte untouched
// (never partially written, never zeroed) rather than merely checking
// the bool return value.
void fillSentinel(uint8_t* buf, size_t len) { memset(buf, 0xEE, len); }

bool bufferIsAllSentinel(const uint8_t* buf, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (buf[i] != 0xEE) return false;
  }
  return true;
}

class OtaBoardBaselineMeasurementSourceReadDeviceIdentityTest : public ::testing::Test {
 protected:
  void SetUp() override {
    g_fake_uid_read_should_succeed = true;
    memcpy(g_fake_uid8, "\x11\x22\x33\x44\x55\x66\x77\x88", 8);
  }
};

TEST_F(OtaBoardBaselineMeasurementSourceReadDeviceIdentityTest, UnboundPubkeyPointerIsRefusedEvenWithLoadedFlagTrue) {
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(true);
  OtaBoardBaselineMeasurementSource source(/*pubkey32=*/nullptr, service);

  uint8_t out_uid8[8];
  uint8_t out_pubkey32[32];
  fillSentinel(out_uid8, sizeof(out_uid8));
  fillSentinel(out_pubkey32, sizeof(out_pubkey32));

  EXPECT_FALSE(source.readDeviceIdentity(out_uid8, out_pubkey32));
  EXPECT_TRUE(bufferIsAllSentinel(out_uid8, sizeof(out_uid8)));
  EXPECT_TRUE(bufferIsAllSentinel(out_pubkey32, sizeof(out_pubkey32)));
}

TEST_F(OtaBoardBaselineMeasurementSourceReadDeviceIdentityTest, UnloadedIdentityFlagIsRefusedEvenWithRealPubkey) {
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(false);
  OtaBoardBaselineMeasurementSource source(kRealPubkey32, service);

  uint8_t out_uid8[8];
  uint8_t out_pubkey32[32];
  fillSentinel(out_uid8, sizeof(out_uid8));
  fillSentinel(out_pubkey32, sizeof(out_pubkey32));

  EXPECT_FALSE(source.readDeviceIdentity(out_uid8, out_pubkey32));
  EXPECT_TRUE(bufferIsAllSentinel(out_uid8, sizeof(out_uid8)));
  EXPECT_TRUE(bufferIsAllSentinel(out_pubkey32, sizeof(out_pubkey32)));
}

TEST_F(OtaBoardBaselineMeasurementSourceReadDeviceIdentityTest,
       FreshlyInvalidatedIdentityIsRefusedDespiteAnEarlierConfirmedLoad) {
  // A LATER genuine storage fault must invalidate previously-confirmed
  // identity evidence -- stale "was durable" evidence is not proof the
  // identity is still durable right now (see OtaFirmwareService::
  // noteStorageIoResult()'s doc comment).
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(true);
  ASSERT_TRUE(service.identityConfirmedLoaded());
  service.noteStorageIoResult(/*ok=*/false);
  ASSERT_FALSE(service.identityConfirmedLoaded());
  OtaBoardBaselineMeasurementSource source(kRealPubkey32, service);

  uint8_t out_uid8[8];
  uint8_t out_pubkey32[32];
  fillSentinel(out_uid8, sizeof(out_uid8));
  fillSentinel(out_pubkey32, sizeof(out_pubkey32));

  EXPECT_FALSE(source.readDeviceIdentity(out_uid8, out_pubkey32));
  EXPECT_TRUE(bufferIsAllSentinel(out_uid8, sizeof(out_uid8)));
  EXPECT_TRUE(bufferIsAllSentinel(out_pubkey32, sizeof(out_pubkey32)));
}

TEST_F(OtaBoardBaselineMeasurementSourceReadDeviceIdentityTest, GenuineUidReadFailureIsRefusedDespiteLoadedFlagTrue) {
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(true);
  OtaBoardBaselineMeasurementSource source(kRealPubkey32, service);
  g_fake_uid_read_should_succeed = false;

  uint8_t out_uid8[8];
  uint8_t out_pubkey32[32];
  fillSentinel(out_uid8, sizeof(out_uid8));
  fillSentinel(out_pubkey32, sizeof(out_pubkey32));

  EXPECT_FALSE(source.readDeviceIdentity(out_uid8, out_pubkey32));
  // pubkey32_ is only memcpy'd AFTER a successful UID read -- a genuine
  // UID-read failure must leave BOTH output buffers untouched, not just
  // the uid8 one.
  EXPECT_TRUE(bufferIsAllSentinel(out_uid8, sizeof(out_uid8)));
  EXPECT_TRUE(bufferIsAllSentinel(out_pubkey32, sizeof(out_pubkey32)));
}

TEST_F(OtaBoardBaselineMeasurementSourceReadDeviceIdentityTest, GenuinelyLoadedTrueCaseSucceedsAndCopiesBothFields) {
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(true);
  OtaBoardBaselineMeasurementSource source(kRealPubkey32, service);

  uint8_t out_uid8[8];
  uint8_t out_pubkey32[32];
  fillSentinel(out_uid8, sizeof(out_uid8));
  fillSentinel(out_pubkey32, sizeof(out_pubkey32));

  EXPECT_TRUE(source.readDeviceIdentity(out_uid8, out_pubkey32));
  EXPECT_EQ(0, memcmp(out_uid8, g_fake_uid8, sizeof(out_uid8)));
  EXPECT_EQ(0, memcmp(out_pubkey32, kRealPubkey32, sizeof(out_pubkey32)));
}

TEST_F(OtaBoardBaselineMeasurementSourceReadDeviceIdentityTest, TrueThenFalseIsReadFreshEveryCallNeverSnapshotted) {
  // The service is read fresh via reference on every call, not copied/
  // cached at construction time -- the SAME service's later mutation
  // must immediately change the outcome of the NEXT call, with no
  // special re-construction needed.
  OtaFirmwareService service;
  service.noteIdentityLoadAttempted(true);
  OtaBoardBaselineMeasurementSource source(kRealPubkey32, service);

  uint8_t out_uid8[8];
  uint8_t out_pubkey32[32];
  fillSentinel(out_uid8, sizeof(out_uid8));
  fillSentinel(out_pubkey32, sizeof(out_pubkey32));
  EXPECT_TRUE(source.readDeviceIdentity(out_uid8, out_pubkey32));

  service.noteStorageIoResult(/*ok=*/false);
  fillSentinel(out_uid8, sizeof(out_uid8));
  fillSentinel(out_pubkey32, sizeof(out_pubkey32));
  EXPECT_FALSE(source.readDeviceIdentity(out_uid8, out_pubkey32));
  EXPECT_TRUE(bufferIsAllSentinel(out_uid8, sizeof(out_uid8)));
  EXPECT_TRUE(bufferIsAllSentinel(out_pubkey32, sizeof(out_pubkey32)));
}

} // namespace
