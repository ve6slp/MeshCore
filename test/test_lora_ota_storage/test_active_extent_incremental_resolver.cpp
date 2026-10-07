// Native, production-code coverage for XiaoOtaIncrementalExtentResolver
// (see ota/storage/XiaoOtaActiveExtentBridge.h). These tests drive the
// REAL step()/crc16Step() production stepping logic via the injectable
// SnapshotReader seam -- never a second reimplementation of the
// algorithm -- so a genuine regression in the incremental CRC path would
// be caught here, not just in a hand-rolled fixture copy.
#include <gtest/gtest.h>
#include <vector>

#include "ota/storage/XiaoOtaActiveExtentBridge.h"

using ota::storage::kBankValidApp;
using ota::storage::kXiaoOtaAppInstallMaxSize;
using ota::storage::XiaoOtaBank0Settings;
using ota::storage::XiaoOtaExtentResolutionStep;
using ota::storage::XiaoOtaIncrementalExtentResolver;
using Snapshot = XiaoOtaIncrementalExtentResolver::Snapshot;

namespace {

// One process-wide fixture slot per test, read back by a plain C
// function pointer (SnapshotReader has no capture-state, matching the
// real hardware read's own signature). Each TEST body sets this up
// immediately before constructing its resolver.
Snapshot g_fixture_snapshot;

Snapshot readFixtureSnapshot() { return g_fixture_snapshot; }

// Genuine CRC-16 (Nordic crc16_compute, poly 0x1021, seed 0xFFFF) over a
// small fixture image, computed via the exact same production
// crc16Compute() the resolver itself uses -- so these fixtures encode a
// TRUE match/mismatch, not an assumed one.
uint16_t realCrc(const uint8_t* data, uint32_t len) {
  return ota::storage::XiaoOtaActiveExtentBridge::crc16Compute(data, len);
}

}  // namespace

TEST(XiaoOtaIncrementalExtentResolverTest, GenuineComputedZeroCrcResolvesInOneStep) {
  // {0xFF, 0xFF, 0x00, 0x00} is the exact fixture from
  // test_active_extent_crc_zero.cpp, where the real CRC-16 is genuinely
  // 0 -- the incremental resolver must resolve it exactly like
  // resolveExtentFromBank0() does, never treating a stored/computed
  // bank_0_crc of 0 as an automatic failure.
  static const uint8_t image[] = {0xFF, 0xFF, 0x00, 0x00};
  ASSERT_EQ(0u, realCrc(image, sizeof(image)));

  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = sizeof(image);
  bank0.bank_0_crc = 0;
  g_fixture_snapshot = Snapshot{bank0, image, sizeof(image)};

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  const auto step = resolver.step(/*max_bytes=*/1024, &out_image, &out_extent);

  EXPECT_EQ(XiaoOtaExtentResolutionStep::Resolved, step);
  EXPECT_EQ(sizeof(image), out_extent);
  EXPECT_EQ(image, out_image);
}

TEST(XiaoOtaIncrementalExtentResolverTest, NonzeroComputedCrcMismatchWithZeroStoredCrcFails) {
  // {0x00, 0x00, 0x00, 0x00} genuinely CRCs to a nonzero value (0x84C0
  // per test_active_extent_crc_zero.cpp) -- a stored bank_0_crc of 0
  // here is a genuine MISMATCH, and must still fail even though the
  // stored value happens to be 0.
  static const uint8_t image[] = {0x00, 0x00, 0x00, 0x00};
  ASSERT_EQ(0x84C0u, realCrc(image, sizeof(image)));

  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = sizeof(image);
  bank0.bank_0_crc = 0;
  g_fixture_snapshot = Snapshot{bank0, image, sizeof(image)};

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  const auto step = resolver.step(1024, &out_image, &out_extent);

  EXPECT_EQ(XiaoOtaExtentResolutionStep::Failed, step);
  EXPECT_EQ(0u, out_extent);
  EXPECT_EQ(nullptr, out_image);
}

TEST(XiaoOtaIncrementalExtentResolverTest, NonzeroStoredCrcMismatchFails) {
  // An ordinary nonzero/nonzero mismatch -- the everyday fail-closed
  // case, unrelated to the zero-CRC contract, but still exercised
  // through the real incremental stepping code.
  static const uint8_t image[] = {0x11, 0x22, 0x33, 0x44, 0x55};
  const uint16_t genuine = realCrc(image, sizeof(image));
  ASSERT_NE(0u, genuine);

  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = sizeof(image);
  bank0.bank_0_crc = static_cast<uint16_t>(genuine ^ 0xFFFFu);  // deliberately wrong.
  g_fixture_snapshot = Snapshot{bank0, image, sizeof(image)};

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  EXPECT_EQ(XiaoOtaExtentResolutionStep::Failed, resolver.step(1024, &out_image, &out_extent));
  EXPECT_EQ(0u, out_extent);
}

TEST(XiaoOtaIncrementalExtentResolverTest, FullSizeInOneStepResolvesImmediatelyWithCorrectCrc) {
  static const uint8_t image[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
  const uint16_t genuine = realCrc(image, sizeof(image));

  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = sizeof(image);
  bank0.bank_0_crc = genuine;
  g_fixture_snapshot = Snapshot{bank0, image, sizeof(image)};

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  // max_bytes comfortably exceeds bank_0_size -- must resolve in one call.
  EXPECT_EQ(XiaoOtaExtentResolutionStep::Resolved, resolver.step(4096, &out_image, &out_extent));
  EXPECT_EQ(sizeof(image), out_extent);
}

TEST(XiaoOtaIncrementalExtentResolverTest, PartialStepsAccumulateToTheSameFinalCrcAsOneShot) {
  // A larger fixture, driven 3 bytes at a time, must reach EXACTLY the
  // same final verdict crc16Compute() would produce in a single call --
  // proving the resumed running-CRC state genuinely matches the
  // non-incremental algorithm, not merely "eventually resolves."
  static const uint8_t image[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
  const uint16_t genuine = realCrc(image, sizeof(image));

  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = sizeof(image);
  bank0.bank_0_crc = genuine;
  g_fixture_snapshot = Snapshot{bank0, image, sizeof(image)};

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  XiaoOtaExtentResolutionStep step;
  int in_progress_calls = 0;
  do {
    step = resolver.step(/*max_bytes=*/3, &out_image, &out_extent);
    if (step == XiaoOtaExtentResolutionStep::InProgress) ++in_progress_calls;
  } while (step == XiaoOtaExtentResolutionStep::InProgress);

  EXPECT_GT(in_progress_calls, 0);  // genuinely spanned multiple bounded calls.
  EXPECT_EQ(XiaoOtaExtentResolutionStep::Resolved, step);
  EXPECT_EQ(sizeof(image), out_extent);
}

TEST(XiaoOtaIncrementalExtentResolverTest, RecordedSizeExceedingAvailableImageLengthFailsClosed) {
  // "End read error": the bank0 record claims a size larger than what
  // the (bounded) snapshot actually has available to read. Must fail
  // BEFORE any byte is ever touched, never reading past the fixture's
  // real end.
  static const uint8_t image[] = {0xAA, 0xBB, 0xCC, 0xDD};
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = sizeof(image) + 1;  // one byte more than actually available.
  bank0.bank_0_crc = 0x1234;
  g_fixture_snapshot = Snapshot{bank0, image, sizeof(image)};  // image_len deliberately short.

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  EXPECT_EQ(XiaoOtaExtentResolutionStep::Failed, resolver.step(4096, &out_image, &out_extent));
  EXPECT_EQ(0u, out_extent);
  EXPECT_EQ(nullptr, out_image);
}

TEST(XiaoOtaIncrementalExtentResolverTest, InvalidBankMarkerFailsClosedRegardlessOfCrc) {
  static const uint8_t image[] = {0x01, 0x02, 0x03, 0x04};
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp + 1;  // not BANK_VALID_APP.
  bank0.bank_0_size = sizeof(image);
  bank0.bank_0_crc = realCrc(image, sizeof(image));  // even a genuinely-correct CRC must not save it.
  g_fixture_snapshot = Snapshot{bank0, image, sizeof(image)};

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  EXPECT_EQ(XiaoOtaExtentResolutionStep::Failed, resolver.step(4096, &out_image, &out_extent));
}

TEST(XiaoOtaIncrementalExtentResolverTest, ZeroRecordedSizeFailsClosed) {
  static const uint8_t image[] = {0x01};
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = 0;
  bank0.bank_0_crc = 0;
  g_fixture_snapshot = Snapshot{bank0, image, sizeof(image)};

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  EXPECT_EQ(XiaoOtaExtentResolutionStep::Failed, resolver.step(4096, &out_image, &out_extent));
}

TEST(XiaoOtaIncrementalExtentResolverTest, OversizedRecordedSizeAboveInstallCeilingFailsClosed) {
  static const uint8_t image[] = {0x01};
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = kXiaoOtaAppInstallMaxSize + 1;
  bank0.bank_0_crc = 0;
  // image_len deliberately reported as "big enough" to isolate this from
  // the separate end-of-image-length check above.
  g_fixture_snapshot = Snapshot{bank0, image, kXiaoOtaAppInstallMaxSize + 1};

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  EXPECT_EQ(XiaoOtaExtentResolutionStep::Failed, resolver.step(4096, &out_image, &out_extent));
}

TEST(XiaoOtaIncrementalExtentResolverTest, NullImagePointerFailsClosed) {
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = 4;
  bank0.bank_0_crc = 0;
  g_fixture_snapshot = Snapshot{bank0, /*image=*/nullptr, /*image_len=*/0};

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  EXPECT_EQ(XiaoOtaExtentResolutionStep::Failed, resolver.step(4096, &out_image, &out_extent));
}

TEST(XiaoOtaIncrementalExtentResolverTest, TerminalResultIsLatchedAndNeverRecomputed) {
  static const uint8_t image[] = {0xFF, 0xFF, 0x00, 0x00};
  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = sizeof(image);
  bank0.bank_0_crc = 0;
  g_fixture_snapshot = Snapshot{bank0, image, sizeof(image)};

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  ASSERT_EQ(XiaoOtaExtentResolutionStep::Resolved, resolver.step(1024, &out_image, &out_extent));

  // Mutate the fixture the reader WOULD return next -- if the resolver
  // re-read it, this would flip the verdict. It must not: the resolver
  // is single-use/latched after its first terminal step.
  g_fixture_snapshot.bank0.bank_0 = kBankValidApp + 1;
  const uint8_t* out_image2 = nullptr;
  uint32_t out_extent2 = 0;
  EXPECT_EQ(XiaoOtaExtentResolutionStep::Resolved, resolver.step(1024, &out_image2, &out_extent2));
  EXPECT_EQ(sizeof(image), out_extent2);
}

TEST(XiaoOtaIncrementalExtentResolverTest, DefaultConstructedResolverFailsClosedOffTarget) {
  // No injected reader supplied -- exercises the exact same production
  // path a real on-device call would use, which (off-target, no
  // NRF52840_XXAA) must fail closed rather than resolve anything.
  XiaoOtaIncrementalExtentResolver resolver;
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  EXPECT_EQ(XiaoOtaExtentResolutionStep::Failed, resolver.step(1024, &out_image, &out_extent));
  EXPECT_EQ(0u, out_extent);
  EXPECT_EQ(nullptr, out_image);
}

namespace {
// A genuinely full-size (exactly kXiaoOtaAppInstallMaxSize, i.e. the
// real 0x9D000/643072-byte install ceiling used on real hardware) fixture
// image, built once and reused by the tests below so they cover the
// production 1024-byte-per-pass CRC budget across its ENTIRE real range
// -- not just a handful of bytes -- with measurable, monotonically
// increasing progress each pass, matching the real per-tick budget the
// backend/monitor actually uses.
std::vector<uint8_t>& fullSizeFixtureImage() {
  static std::vector<uint8_t> image = [] {
    std::vector<uint8_t> img(kXiaoOtaAppInstallMaxSize);
    for (uint32_t i = 0; i < img.size(); ++i) {
      img[i] = static_cast<uint8_t>((i * 2654435761u) >> 24);  // deterministic, non-trivial pattern.
    }
    return img;
  }();
  return image;
}
}  // namespace

TEST(XiaoOtaIncrementalExtentResolverTest, FullInstallCeilingSizeResolvesWithMeasurableBoundedProgress) {
  std::vector<uint8_t>& image = fullSizeFixtureImage();
  const uint16_t genuine = realCrc(image.data(), static_cast<uint32_t>(image.size()));

  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = kXiaoOtaAppInstallMaxSize;
  bank0.bank_0_crc = genuine;
  g_fixture_snapshot = Snapshot{bank0, image.data(), static_cast<uint32_t>(image.size())};

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  // Exactly the production per-tick budget (see MyMesh/monitor's
  // "<=1024 bytes/pass" combined CRC+SHA requirement) -- proves the real
  // full install-ceiling size genuinely requires many bounded passes,
  // not a single one, and that word-aligned per-pass sizing is
  // consistent with the boot contract's own 643072-byte ceiling.
  constexpr uint32_t kBudgetPerPass = 1024;
  XiaoOtaExtentResolutionStep step;
  int pass_count = 0;
  uint32_t last_progress = 0;
  do {
    step = resolver.step(kBudgetPerPass, &out_image, &out_extent);
    ++pass_count;
    const uint32_t progress = resolver.bytesProcessedSoFar();
    if (step == XiaoOtaExtentResolutionStep::InProgress) {
      // Every intermediate pass makes real, measurable, monotonic
      // progress -- never stalls, never exceeds the per-pass budget
      // from where it started.
      EXPECT_GT(progress, last_progress);
      EXPECT_LE(progress - last_progress, kBudgetPerPass);
      last_progress = progress;
    }
  } while (step == XiaoOtaExtentResolutionStep::InProgress);

  EXPECT_EQ(XiaoOtaExtentResolutionStep::Resolved, step);
  EXPECT_EQ(kXiaoOtaAppInstallMaxSize, out_extent);
  EXPECT_EQ(kXiaoOtaAppInstallMaxSize, resolver.bytesProcessedSoFar());
  // Real 643072-byte ceiling / 1024-byte budget genuinely spans many
  // passes (not one, not a trivially small handful) -- proves this test
  // exercises the ENTIRE real range, matching the boot-side ceiling.
  EXPECT_GT(pass_count, 600);
}

TEST(XiaoOtaIncrementalExtentResolverTest, FullSizeImageWithGenuineTailMismatchFailsClosedNotJustOverLength) {
  // A genuine read-failure/mismatch semantics case AT the real
  // install-ceiling boundary: the recorded size and available image
  // length both legitimately equal the full ceiling (so this is NOT the
  // "recorded size exceeds available length" over-length path already
  // covered above) -- but the LAST byte was corrupted after the CRC was
  // recorded, so the fully-accumulated running CRC genuinely mismatches
  // only once the tail is actually reached, exercising real end-of-image
  // read/verify semantics across the full budgeted pass count rather
  // than an early, trivial size-label rejection.
  std::vector<uint8_t> image = fullSizeFixtureImage();  // copy: about to corrupt it.
  const uint16_t genuine = realCrc(image.data(), static_cast<uint32_t>(image.size()));
  image.back() ^= 0xFF;  // corrupt exactly the final byte, at the true tail.
  ASSERT_NE(genuine, realCrc(image.data(), static_cast<uint32_t>(image.size())));

  XiaoOtaBank0Settings bank0;
  bank0.bank_0 = kBankValidApp;
  bank0.bank_0_size = kXiaoOtaAppInstallMaxSize;
  bank0.bank_0_crc = genuine;  // the ORIGINAL (pre-corruption) recorded CRC.
  g_fixture_snapshot = Snapshot{bank0, image.data(), static_cast<uint32_t>(image.size())};

  XiaoOtaIncrementalExtentResolver resolver(&readFixtureSnapshot);
  const uint8_t* out_image = nullptr;
  uint32_t out_extent = 0;
  XiaoOtaExtentResolutionStep step;
  do {
    step = resolver.step(1024, &out_image, &out_extent);
  } while (step == XiaoOtaExtentResolutionStep::InProgress);

  EXPECT_EQ(XiaoOtaExtentResolutionStep::Failed, step);
  EXPECT_EQ(0u, out_extent);
  EXPECT_EQ(nullptr, out_image);
  // The full recorded size WAS genuinely, completely processed (this is
  // a real tail-mismatch, not an early bounds rejection).
  EXPECT_EQ(kXiaoOtaAppInstallMaxSize, resolver.bytesProcessedSoFar());
}
