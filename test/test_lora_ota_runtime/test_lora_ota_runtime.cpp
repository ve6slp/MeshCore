#include <gtest/gtest.h>

#include <cstring>
#include <cstdint>
#include <vector>

#include "ota/runtime/OtaGeometry.h"
#include "ota/runtime/OtaBitmap.h"
#include "ota/runtime/OtaSessionIdentity.h"
#include "ota/runtime/OtaTrustInterfaces.h"
#include "ota/runtime/OtaReceiverStateMachine.h"
#include "ota/runtime/OtaCoordinatorStateMachine.h"
#include "ota/runtime/OtaLeaseStateMachine.h"
#include "ota/runtime/OtaAirtimeLimiter.h"
#include "ota/runtime/OtaFleetStateMachine.h"
#include "ota/runtime/OtaTxSequenceLedger.h"
#include "ota/runtime/OtaRxReplayLedger.h"
#include "ota/runtime/OtaSequenceBackingPort.h"
#include "ota/runtime/OtaFlashSequenceBackingAdapters.h"
#include "ota/runtime/OtaSequenceBackedLedgers.h"
#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashRegion.h"

#include "../test_lora_ota_storage/FakeNorFlash.h"

using namespace meshcore::ota::runtime;
using meshcore::ota::protocol::OtaAirtimeCategory;

// ---------------------------------------------------------------------
// Geometry: checked arithmetic, exact final chunk length, overflow cases
// ---------------------------------------------------------------------

TEST(OtaGeometry, MaxImageAtDefaultChunkSizeMatchesExpectedGeometry) {
  OtaGeometry g;
  ASSERT_EQ(OtaGeometryResult::Ok, OtaGeometry::compute(kOtaMaxImageBytes, kOtaDefaultChunkPayloadSize, kOtaMaxImageBytes, g));
  // kOtaMaxImageBytes is an exact multiple of kOtaDefaultChunkPayloadSize
  // (708608 / 128 = 5536 exactly), so the final chunk is full-size too.
  EXPECT_EQ(5536u, g.chunkCount);
  EXPECT_EQ(128u, g.finalChunkLength);
  EXPECT_EQ(kOtaMaxChunkCount, static_cast<size_t>(g.chunkCount));

  uint32_t len = 0;
  ASSERT_TRUE(g.chunkLength(0, len));
  EXPECT_EQ(128u, len);
  ASSERT_TRUE(g.chunkLength(5534, len));
  EXPECT_EQ(128u, len);
  ASSERT_TRUE(g.chunkLength(5535, len)); // last index (0-based), chunkCount-1
  EXPECT_EQ(128u, len);
}

TEST(OtaGeometry, ExactMultipleHasFullFinalChunk) {
  OtaGeometry g;
  ASSERT_EQ(OtaGeometryResult::Ok, OtaGeometry::compute(320, 160, kOtaMaxImageBytes, g));
  EXPECT_EQ(2u, g.chunkCount);
  EXPECT_EQ(160u, g.finalChunkLength);
}

TEST(OtaGeometry, SingleByteImage) {
  OtaGeometry g;
  ASSERT_EQ(OtaGeometryResult::Ok, OtaGeometry::compute(1, 160, kOtaMaxImageBytes, g));
  EXPECT_EQ(1u, g.chunkCount);
  EXPECT_EQ(1u, g.finalChunkLength);
}

TEST(OtaGeometry, RejectsZeroImageSize) {
  OtaGeometry g;
  EXPECT_EQ(OtaGeometryResult::ZeroImageSize, OtaGeometry::compute(0, 160, kOtaMaxImageBytes, g));
}

TEST(OtaGeometry, RejectsZeroChunkSize) {
  OtaGeometry g;
  EXPECT_EQ(OtaGeometryResult::ZeroChunkSize, OtaGeometry::compute(1000, 0, kOtaMaxImageBytes, g));
}

TEST(OtaGeometry, RejectsImageLargerThanCallerBound) {
  OtaGeometry g;
  EXPECT_EQ(OtaGeometryResult::ImageTooLarge, OtaGeometry::compute(1000, 160, 999, g));
}

TEST(OtaGeometry, RejectsImageLargerThanMaxSupportedChunkCount) {
  OtaGeometry g;
  // kOtaMaxChunkCount full 160-byte chunks plus one extra byte requires one
  // more chunk than the fixed-capacity bitmap can represent, even though the
  // caller-supplied maxImageSizeBytes bound is generous.
  const uint32_t imageJustOverMaxChunks = static_cast<uint32_t>(kOtaMaxChunkCount) * kOtaDefaultChunkPayloadSize + 1;
  EXPECT_EQ(OtaGeometryResult::ImageTooLarge,
            OtaGeometry::compute(imageJustOverMaxChunks, kOtaDefaultChunkPayloadSize, 0xFFFFFFFFu, g));
}

TEST(OtaGeometry, RejectsChunkCountOverflowAtUint32Boundary) {
  OtaGeometry g;
  // imageSize just below UINT32_MAX with chunkPayloadSize=1 would require a
  // chunk count that itself is still representable, but the caller-supplied
  // maxImageSizeBytes bound is what actually gates this in practice; here
  // we exercise the raw arithmetic path directly against a huge bound to
  // confirm it never overflows/wraps silently.
  const uint32_t hugeImage = 0xFFFFFFFFu;
  EXPECT_EQ(OtaGeometryResult::ImageTooLarge, OtaGeometry::compute(hugeImage, 1, hugeImage, g));
}

TEST(OtaGeometry, ChunkLengthFailsClosedForOutOfRangeIndex) {
  OtaGeometry g;
  ASSERT_EQ(OtaGeometryResult::Ok, OtaGeometry::compute(320, 160, kOtaMaxImageBytes, g));
  uint32_t len = 0;
  EXPECT_FALSE(g.chunkLength(2, len));
  EXPECT_FALSE(g.chunkLength(0xFFFFFFFFu, len));
}

TEST(OtaGeometry, ChunkLengthFailsClosedOnDefaultConstructedGeometry) {
  OtaGeometry g;
  uint32_t len = 0;
  EXPECT_FALSE(g.chunkLength(0, len));
}

TEST(OtaGeometry, ChunkOffsetIsExact) {
  OtaGeometry g;
  ASSERT_EQ(OtaGeometryResult::Ok, OtaGeometry::compute(kOtaMaxImageBytes, kOtaDefaultChunkPayloadSize, kOtaMaxImageBytes, g));
  uint64_t offset = 0;
  ASSERT_TRUE(g.chunkOffset(5535, offset));
  EXPECT_EQ(5535ull * 128ull, offset);
  EXPECT_EQ(708480ull, offset);
  EXPECT_EQ(kOtaMaxImageBytes, static_cast<uint32_t>(offset + 128));
}

// ---------------------------------------------------------------------
// Bitmap: max-image capacity, no heap, exhaustive edge cases
// ---------------------------------------------------------------------

TEST(OtaBitmap, RepresentsMaxImageChunkCountWithoutHeap) {
  OtaMaxImageBitmap bitmap;
  bitmap.reset(kOtaMaxChunkCount);
  EXPECT_EQ(kOtaMaxChunkCount, bitmap.activeBits());
  EXPECT_FALSE(bitmap.allSet());

  for (size_t i = 0; i < kOtaMaxChunkCount; ++i) {
    EXPECT_TRUE(bitmap.set(i));
  }
  EXPECT_TRUE(bitmap.allSet());
  EXPECT_EQ(kOtaMaxChunkCount, bitmap.countSet());
}

TEST(OtaBitmap, SetAndTestOutOfRangeFailsClosed) {
  OtaMaxImageBitmap bitmap;
  bitmap.reset(10);
  EXPECT_FALSE(bitmap.set(10));
  EXPECT_FALSE(bitmap.set(kOtaMaxChunkCount));
  EXPECT_FALSE(bitmap.test(10));
}

TEST(OtaBitmap, FirstMissingFindsLowestUnsetBit) {
  OtaMaxImageBitmap bitmap;
  bitmap.reset(5);
  bitmap.set(0);
  bitmap.set(1);
  bitmap.set(3);
  size_t idx = 0;
  ASSERT_TRUE(bitmap.firstMissing(idx));
  EXPECT_EQ(2u, idx);
}

TEST(OtaBitmap, FirstMissingReturnsFalseWhenAllSet) {
  OtaMaxImageBitmap bitmap;
  bitmap.reset(3);
  bitmap.set(0);
  bitmap.set(1);
  bitmap.set(2);
  size_t idx = 0;
  EXPECT_FALSE(bitmap.firstMissing(idx));
}

TEST(OtaBitmap, MissingRangesAreBoundedAndContiguous) {
  OtaMaxImageBitmap bitmap;
  bitmap.reset(10);
  bitmap.set(0);
  bitmap.set(1);
  // missing: [2,5), set 5, missing [6,10)
  bitmap.set(5);
  uint32_t starts[4] = {0};
  uint32_t counts[4] = {0};
  size_t n = bitmap.missingRanges(starts, counts, 4);
  ASSERT_EQ(2u, n);
  EXPECT_EQ(2u, starts[0]);
  EXPECT_EQ(3u, counts[0]);
  EXPECT_EQ(6u, starts[1]);
  EXPECT_EQ(4u, counts[1]);
}

TEST(OtaBitmap, MissingRangesRespectsMaxRangesBound) {
  OtaMaxImageBitmap bitmap;
  bitmap.reset(6);
  // alternate set/unset -> 3 separate single-bit missing ranges: 1,3,5
  bitmap.set(0);
  bitmap.set(2);
  bitmap.set(4);
  uint32_t starts[2] = {0};
  uint32_t counts[2] = {0};
  size_t n = bitmap.missingRanges(starts, counts, 2);
  EXPECT_EQ(2u, n); // bounded output, third range not written
}

TEST(OtaBitmap, ResetClearsPreviousCampaignState) {
  OtaMaxImageBitmap bitmap;
  bitmap.reset(5);
  bitmap.set(0);
  bitmap.set(1);
  bitmap.reset(5);
  EXPECT_EQ(0u, bitmap.countSet());
  EXPECT_FALSE(bitmap.test(0));
}

// ---------------------------------------------------------------------
// Session identity / replay isolation
// ---------------------------------------------------------------------

TEST(OtaReplayGuard, AcceptsStrictlyNewerAndRejectsReplay) {
  OtaReplayGuard guard;
  OtaSessionId a{1, 1, 1};
  OtaSessionId b{1, 1, 1};
  OtaSessionId older{1, 0, 5};
  OtaSessionId newerAttempt{1, 1, 2};
  OtaSessionId newerSession{1, 2, 0};
  OtaSessionId newerCampaign{2, 0, 0};

  EXPECT_TRUE(guard.acceptIfNewer(a));
  EXPECT_FALSE(guard.acceptIfNewer(b));       // exact replay
  EXPECT_FALSE(guard.acceptIfNewer(older));    // stale
  EXPECT_TRUE(guard.acceptIfNewer(newerAttempt));
  EXPECT_TRUE(guard.acceptIfNewer(newerSession));
  EXPECT_TRUE(guard.acceptIfNewer(newerCampaign));
  EXPECT_FALSE(guard.acceptIfNewer(a)); // now stale relative to newerCampaign
}

// ---------------------------------------------------------------------
// Trust/staging interfaces: fail-closed when unattached
// ---------------------------------------------------------------------

TEST(OtaTrustInterfaces, FailsClosedWithoutProviderOrSink) {
  uint8_t descriptor[4] = {0};
  uint8_t sig[4] = {0};
  EXPECT_FALSE(verifyDescriptorSignatureFailClosed(nullptr, descriptor, sizeof(descriptor), sig, sizeof(sig), 1, 1));

  meshcore::ota::protocol::OtaDescriptor d;
  EXPECT_EQ(IOtaStagingSink::Result::Rejected, stagingBeginFailClosed(nullptr, d));
  EXPECT_EQ(IOtaStagingSink::Result::Rejected, stagingWriteFailClosed(nullptr, 0, descriptor, sizeof(descriptor)));
  EXPECT_EQ(IOtaStagingSink::Result::Rejected, stagingCommitFailClosed(nullptr));
  stagingAbortFailClosed(nullptr); // must not crash
}

namespace {
class FakeTrustProvider : public IOtaTrustProvider {
public:
  bool allow = true;
  bool verifyDescriptorSignature(const uint8_t*, size_t, const uint8_t*, size_t, uint16_t, uint16_t) override {
    return allow;
  }
};
} // namespace

TEST(OtaTrustInterfaces, DelegatesToAttachedProvider) {
  FakeTrustProvider provider;
  uint8_t descriptor[4] = {0};
  uint8_t sig[4] = {0};
  provider.allow = true;
  EXPECT_TRUE(verifyDescriptorSignatureFailClosed(&provider, descriptor, sizeof(descriptor), sig, sizeof(sig), 1, 1));
  provider.allow = false;
  EXPECT_FALSE(verifyDescriptorSignatureFailClosed(&provider, descriptor, sizeof(descriptor), sig, sizeof(sig), 1, 1));
}

// ---------------------------------------------------------------------
// Receiver state machine: exhaustive legal transitions + every illegal one
// ---------------------------------------------------------------------

namespace {
constexpr OtaSessionId kSession{10, 20, 1};
constexpr OtaSessionId kOtherSession{10, 20, 2};

// All receiver events, for exhaustive illegal-transition enumeration.
constexpr OtaReceiverEvent kAllReceiverEvents[] = {
    OtaReceiverEvent::DescriptorFragmentReceived,
    OtaReceiverEvent::DescriptorComplete,
    OtaReceiverEvent::DescriptorRejected,
    OtaReceiverEvent::AuthorizationGranted,
    OtaReceiverEvent::AuthorizationDenied,
    OtaReceiverEvent::ChunkAccepted,
    OtaReceiverEvent::AllChunksReceived,
    OtaReceiverEvent::StagingError,
    OtaReceiverEvent::VerificationOk,
    OtaReceiverEvent::VerificationFailed,
    OtaReceiverEvent::CommitOk,
    OtaReceiverEvent::CommitFailed,
    OtaReceiverEvent::Abort,
};

bool isLegalReceiverTransition(OtaReceiverState s, OtaReceiverEvent ev) {
  using S = OtaReceiverState;
  using E = OtaReceiverEvent;
  switch (s) {
    case S::AwaitingDescriptor:
      return ev == E::DescriptorFragmentReceived || ev == E::DescriptorComplete || ev == E::DescriptorRejected || ev == E::Abort;
    case S::AwaitingAuthorization:
      return ev == E::AuthorizationGranted || ev == E::AuthorizationDenied || ev == E::Abort;
    case S::Receiving:
      return ev == E::ChunkAccepted || ev == E::AllChunksReceived || ev == E::StagingError || ev == E::Abort;
    case S::Verifying:
      return ev == E::VerificationOk || ev == E::VerificationFailed || ev == E::Abort;
    case S::Committing:
      return ev == E::CommitOk || ev == E::CommitFailed || ev == E::Abort;
    default:
      return false;
  }
}

// Drives the machine to `target` from a fresh beginCampaign(), returning
// true on success. Used so illegal-transition tests can be generated
// mechanically for every reachable state.
bool driveReceiverTo(OtaReceiverStateMachine& m, OtaReceiverState target, const OtaSessionId& id) {
  if (!m.beginCampaign(id)) return false;
  if (target == OtaReceiverState::AwaitingDescriptor) return true;
  if (!m.handle(OtaReceiverEvent::DescriptorComplete, id)) return false;
  if (target == OtaReceiverState::AwaitingAuthorization) return true;
  if (!m.handle(OtaReceiverEvent::AuthorizationGranted, id)) return false;
  if (target == OtaReceiverState::Receiving) return true;
  if (!m.handle(OtaReceiverEvent::AllChunksReceived, id)) return false;
  if (target == OtaReceiverState::Verifying) return true;
  if (!m.handle(OtaReceiverEvent::VerificationOk, id)) return false;
  if (target == OtaReceiverState::Committing) return true;
  return false;
}

constexpr OtaReceiverState kReachableReceiverStates[] = {
    OtaReceiverState::AwaitingDescriptor,
    OtaReceiverState::AwaitingAuthorization,
    OtaReceiverState::Receiving,
    OtaReceiverState::Verifying,
    OtaReceiverState::Committing,
};
} // namespace

TEST(OtaReceiverStateMachine, HappyPathReachesComplete) {
  OtaReceiverStateMachine m;
  ASSERT_TRUE(m.beginCampaign(kSession));
  EXPECT_EQ(OtaReceiverState::AwaitingDescriptor, m.state());
  ASSERT_TRUE(m.handle(OtaReceiverEvent::DescriptorFragmentReceived, kSession));
  EXPECT_EQ(OtaReceiverState::AwaitingDescriptor, m.state());
  ASSERT_TRUE(m.handle(OtaReceiverEvent::DescriptorComplete, kSession));
  EXPECT_EQ(OtaReceiverState::AwaitingAuthorization, m.state());
  ASSERT_TRUE(m.handle(OtaReceiverEvent::AuthorizationGranted, kSession));
  EXPECT_EQ(OtaReceiverState::Receiving, m.state());
  ASSERT_TRUE(m.handle(OtaReceiverEvent::ChunkAccepted, kSession));
  ASSERT_TRUE(m.handle(OtaReceiverEvent::AllChunksReceived, kSession));
  EXPECT_EQ(OtaReceiverState::Verifying, m.state());
  ASSERT_TRUE(m.handle(OtaReceiverEvent::VerificationOk, kSession));
  EXPECT_EQ(OtaReceiverState::Committing, m.state());
  ASSERT_TRUE(m.handle(OtaReceiverEvent::CommitOk, kSession));
  EXPECT_EQ(OtaReceiverState::Complete, m.state());
}

TEST(OtaReceiverStateMachine, EveryIllegalTransitionIsRejectedFromEveryReachableState) {
  for (auto target : kReachableReceiverStates) {
    for (auto ev : kAllReceiverEvents) {
      OtaReceiverStateMachine m;
      ASSERT_TRUE(driveReceiverTo(m, target, kSession)) << "setup failed for state";
      bool legal = isLegalReceiverTransition(target, ev);
      bool result = m.handle(ev, kSession);
      EXPECT_EQ(legal, result) << "state=" << static_cast<int>(target) << " event=" << static_cast<int>(ev);
      if (!legal) {
        EXPECT_EQ(target, m.state()) << "illegal transition must not mutate state";
      }
    }
  }
}

TEST(OtaReceiverStateMachine, EveryFailurePathReachesFailedTerminal) {
  {
    OtaReceiverStateMachine m;
    ASSERT_TRUE(m.beginCampaign(kSession));
    ASSERT_TRUE(m.handle(OtaReceiverEvent::DescriptorRejected, kSession));
    EXPECT_EQ(OtaReceiverState::Failed, m.state());
  }
  {
    OtaReceiverStateMachine m;
    ASSERT_TRUE(driveReceiverTo(m, OtaReceiverState::AwaitingAuthorization, kSession));
    ASSERT_TRUE(m.handle(OtaReceiverEvent::AuthorizationDenied, kSession));
    EXPECT_EQ(OtaReceiverState::Failed, m.state());
  }
  {
    OtaReceiverStateMachine m;
    ASSERT_TRUE(driveReceiverTo(m, OtaReceiverState::Receiving, kSession));
    ASSERT_TRUE(m.handle(OtaReceiverEvent::StagingError, kSession));
    EXPECT_EQ(OtaReceiverState::Failed, m.state());
  }
  {
    OtaReceiverStateMachine m;
    ASSERT_TRUE(driveReceiverTo(m, OtaReceiverState::Verifying, kSession));
    ASSERT_TRUE(m.handle(OtaReceiverEvent::VerificationFailed, kSession));
    EXPECT_EQ(OtaReceiverState::Failed, m.state());
  }
  {
    OtaReceiverStateMachine m;
    ASSERT_TRUE(driveReceiverTo(m, OtaReceiverState::Committing, kSession));
    ASSERT_TRUE(m.handle(OtaReceiverEvent::CommitFailed, kSession));
    EXPECT_EQ(OtaReceiverState::Failed, m.state());
  }
}

TEST(OtaReceiverStateMachine, AbortIsLegalFromEveryReachableState) {
  for (auto target : kReachableReceiverStates) {
    OtaReceiverStateMachine m;
    ASSERT_TRUE(driveReceiverTo(m, target, kSession));
    ASSERT_TRUE(m.handle(OtaReceiverEvent::Abort, kSession));
    EXPECT_EQ(OtaReceiverState::Aborted, m.state());
  }
}

TEST(OtaReceiverStateMachine, RejectsEventsForForeignOrStaleSession) {
  OtaReceiverStateMachine m;
  ASSERT_TRUE(m.beginCampaign(kSession));
  EXPECT_FALSE(m.handle(OtaReceiverEvent::DescriptorComplete, kOtherSession));
  EXPECT_EQ(OtaReceiverState::AwaitingDescriptor, m.state());
}

TEST(OtaReceiverStateMachine, RejectsReplayedOrStaleBeginCampaign) {
  OtaReceiverStateMachine m;
  ASSERT_TRUE(m.beginCampaign(kSession));
  ASSERT_TRUE(m.handle(OtaReceiverEvent::Abort, kSession));
  m.reset();
  EXPECT_FALSE(m.beginCampaign(kSession)); // replay of the same tuple
  OtaSessionId older{10, 20, 0};
  EXPECT_FALSE(m.beginCampaign(older)); // stale
  OtaSessionId newer{10, 21, 0};
  EXPECT_TRUE(m.beginCampaign(newer)); // strictly newer is accepted
}

TEST(OtaReceiverStateMachine, RejectsBeginCampaignWhileActive) {
  OtaReceiverStateMachine m;
  ASSERT_TRUE(m.beginCampaign(kSession));
  OtaSessionId newer{10, 21, 0};
  EXPECT_FALSE(m.beginCampaign(newer)); // still active, must reset() first
}

TEST(OtaReceiverStateMachine, NoEventIsLegalWhileIdle) {
  OtaReceiverStateMachine m;
  for (auto ev : kAllReceiverEvents) {
    EXPECT_FALSE(m.handle(ev, kSession));
  }
  EXPECT_EQ(OtaReceiverState::Idle, m.state());
}

// ---------------------------------------------------------------------
// Coordinator state machine
// ---------------------------------------------------------------------

TEST(OtaCoordinatorStateMachine, HappyPathReachesComplete) {
  OtaCoordinatorStateMachine m;
  ASSERT_TRUE(m.beginCampaign(kSession));
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::DescriptorDeliveryConfirmed, kSession));
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::AuthorizationGranted, kSession));
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::ChunkSent, kSession));
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::ReceiptAllGood, kSession));
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::CommitVerified, kSession));
  EXPECT_EQ(OtaCoordinatorState::Complete, m.state());
}

TEST(OtaCoordinatorStateMachine, RepairLoopEventuallyConverges) {
  OtaCoordinatorStateMachine m;
  ASSERT_TRUE(m.beginCampaign(kSession));
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::DescriptorDeliveryConfirmed, kSession));
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::AuthorizationGranted, kSession));
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::ChunkSent, kSession));
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::ReceiptMissingDetected, kSession));
  EXPECT_EQ(OtaCoordinatorState::Repairing, m.state());
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::RepairChunkSent, kSession));
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::ReceiptMissingDetected, kSession)); // still missing
  EXPECT_EQ(OtaCoordinatorState::Repairing, m.state());
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::ReceiptAllGood, kSession));
  EXPECT_EQ(OtaCoordinatorState::Committing, m.state());
}

TEST(OtaCoordinatorStateMachine, EveryIllegalTransitionRejected) {
  using S = OtaCoordinatorState;
  using E = OtaCoordinatorEvent;
  constexpr E allEvents[] = {
      E::DescriptorDeliveryConfirmed, E::DescriptorRejected, E::AuthorizationGranted, E::AuthorizationDenied,
      E::ChunkSent, E::ReceiptAllGood, E::ReceiptMissingDetected, E::RepairChunkSent,
      E::CommitVerified, E::CommitFailed, E::Abort,
  };
  auto isLegal = [](S s, E ev) {
    switch (s) {
      case S::DescriptorSending:
        return ev == E::DescriptorDeliveryConfirmed || ev == E::DescriptorRejected || ev == E::Abort;
      case S::AwaitingAuthorization:
        return ev == E::AuthorizationGranted || ev == E::AuthorizationDenied || ev == E::Abort;
      case S::Sending:
        return ev == E::ChunkSent || ev == E::ReceiptAllGood || ev == E::ReceiptMissingDetected || ev == E::Abort;
      case S::Repairing:
        return ev == E::RepairChunkSent || ev == E::ReceiptMissingDetected || ev == E::ReceiptAllGood || ev == E::Abort;
      case S::Committing:
        return ev == E::CommitVerified || ev == E::CommitFailed || ev == E::Abort;
      default:
        return false;
    }
  };
  constexpr S reachable[] = {S::DescriptorSending, S::AwaitingAuthorization, S::Sending, S::Repairing, S::Committing};
  for (auto target : reachable) {
    for (auto ev : allEvents) {
      OtaCoordinatorStateMachine m;
      ASSERT_TRUE(m.beginCampaign(kSession));
      if (target != S::DescriptorSending) ASSERT_TRUE(m.handle(E::DescriptorDeliveryConfirmed, kSession));
      if (target == S::Sending || target == S::Repairing || target == S::Committing) {
        ASSERT_TRUE(m.handle(E::AuthorizationGranted, kSession));
      }
      if (target == S::Repairing || target == S::Committing) {
        ASSERT_TRUE(m.handle(E::ReceiptMissingDetected, kSession));
      }
      if (target == S::Committing) {
        ASSERT_TRUE(m.handle(E::ReceiptAllGood, kSession));
      }
      ASSERT_EQ(target, m.state());

      bool legal = isLegal(target, ev);
      bool result = m.handle(ev, kSession);
      EXPECT_EQ(legal, result) << "state=" << static_cast<int>(target) << " event=" << static_cast<int>(ev);
    }
  }
}

TEST(OtaCoordinatorStateMachine, ReplayIsolationMatchesReceiver) {
  OtaCoordinatorStateMachine m;
  ASSERT_TRUE(m.beginCampaign(kSession));
  EXPECT_FALSE(m.handle(OtaCoordinatorEvent::DescriptorDeliveryConfirmed, kOtherSession));
  ASSERT_TRUE(m.handle(OtaCoordinatorEvent::Abort, kSession));
  m.reset();
  EXPECT_FALSE(m.beginCampaign(kSession));
}

// ---------------------------------------------------------------------
// Radio lease state machine: restoration guarantee on every path
// ---------------------------------------------------------------------

namespace {
void countingRestore(void* ctx) {
  auto* counter = static_cast<int*>(ctx);
  if (counter) ++(*counter);
}
} // namespace

TEST(OtaLeaseStateMachine, RestoresOnTimeoutFromEveryActivePhase) {
  int localCount = 0;
  OtaLeaseStateMachine m;
  m.setRestoreCallback(countingRestore, &localCount);

  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  EXPECT_EQ(OtaLeaseState::Requesting, m.state());
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Timeout));
  EXPECT_EQ(OtaLeaseState::Normal, m.state());
  EXPECT_EQ(1, localCount);

  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Granted));
  EXPECT_EQ(OtaLeaseState::Active, m.state());
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Timeout));
  EXPECT_EQ(OtaLeaseState::Normal, m.state());
  EXPECT_EQ(2, localCount);

  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Granted));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Release));
  EXPECT_EQ(OtaLeaseState::Releasing, m.state());
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Timeout));
  EXPECT_EQ(OtaLeaseState::Normal, m.state());
  EXPECT_EQ(3, localCount);
}

TEST(OtaLeaseStateMachine, RestoresOnFailureFromEveryActivePhase) {
  int localCount = 0;
  OtaLeaseStateMachine m;
  m.setRestoreCallback(countingRestore, &localCount);

  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Failure));
  EXPECT_EQ(OtaLeaseState::Normal, m.state());

  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Granted));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Failure));
  EXPECT_EQ(OtaLeaseState::Normal, m.state());

  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Granted));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Release));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Failure));
  EXPECT_EQ(OtaLeaseState::Normal, m.state());

  EXPECT_EQ(3, localCount);
}

TEST(OtaLeaseStateMachine, RestoresOnResetFromEveryPhaseIncludingNormal) {
  int localCount = 0;
  OtaLeaseStateMachine m;
  m.setRestoreCallback(countingRestore, &localCount);

  ASSERT_TRUE(m.handle(OtaLeaseEvent::Reset)); // Normal -> Normal, still restores
  EXPECT_EQ(1, localCount);

  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Reset));
  EXPECT_EQ(OtaLeaseState::Normal, m.state());
  EXPECT_EQ(2, localCount);

  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Granted));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Reset));
  EXPECT_EQ(OtaLeaseState::Normal, m.state());
  EXPECT_EQ(3, localCount);

  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Granted));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Release));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Reset));
  EXPECT_EQ(OtaLeaseState::Normal, m.state());
  EXPECT_EQ(4, localCount);
}

TEST(OtaLeaseStateMachine, DeniedDuringRequestingRestores) {
  int localCount = 0;
  OtaLeaseStateMachine m;
  m.setRestoreCallback(countingRestore, &localCount);
  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Denied));
  EXPECT_EQ(OtaLeaseState::Normal, m.state());
  EXPECT_EQ(1, localCount);
}

TEST(OtaLeaseStateMachine, NormalCompletionViaReleaseAckRestores) {
  int localCount = 0;
  OtaLeaseStateMachine m;
  m.setRestoreCallback(countingRestore, &localCount);
  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Granted));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Release));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::ReleaseAcked));
  EXPECT_EQ(OtaLeaseState::Normal, m.state());
  EXPECT_EQ(1, localCount);
}

TEST(OtaLeaseStateMachine, IllegalEventsRejectedWithoutRestoring) {
  int localCount = 0;
  OtaLeaseStateMachine m;
  m.setRestoreCallback(countingRestore, &localCount);
  EXPECT_FALSE(m.handle(OtaLeaseEvent::Granted)); // not requesting yet
  EXPECT_EQ(OtaLeaseState::Normal, m.state());
  EXPECT_EQ(0, localCount);

  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  EXPECT_FALSE(m.handle(OtaLeaseEvent::Release)); // not active yet
  EXPECT_EQ(OtaLeaseState::Requesting, m.state());
  EXPECT_EQ(0, localCount);
}

TEST(OtaLeaseStateMachine, WorksWithoutRestoreCallbackAttached) {
  OtaLeaseStateMachine m; // no setRestoreCallback() call
  ASSERT_TRUE(m.handle(OtaLeaseEvent::RequestLease));
  ASSERT_TRUE(m.handle(OtaLeaseEvent::Timeout));
  EXPECT_EQ(OtaLeaseState::Normal, m.state());
  EXPECT_EQ(1u, m.restoreCount());
}

// ---------------------------------------------------------------------
// Airtime limiter: 2% window, wrap-safe clock, categories, regulatory and
// normal-traffic precedence inputs
// ---------------------------------------------------------------------

TEST(OtaAirtimeLimiter, DefaultBudgetIsTwoPercentOfOneHour) {
  OtaAirtimeLimiter limiter;
  EXPECT_EQ(3600000u, limiter.windowMs());
  EXPECT_EQ(72000u, limiter.budgetMs());
}

TEST(OtaAirtimeLimiter, AdmitsUpToExactBudgetAndDeniesOneMsOver) {
  OtaAirtimeLimiter limiter;
  OtaAirtimeDecisionInput decision;
  const uint32_t now = 1000;
  EXPECT_TRUE(limiter.canAdmit(now, OtaAirtimeCategory::Relay, 72000, decision));
  ASSERT_TRUE(limiter.recordUsage(now, OtaAirtimeCategory::Relay, 72000));
  EXPECT_EQ(72000u, limiter.storedUsageMs(now));
  EXPECT_FALSE(limiter.canAdmit(now, OtaAirtimeCategory::Relay, 1, decision));
}

TEST(OtaAirtimeLimiter, StoredUsagePlusProspectiveIsCheckedBeforeAdmission) {
  OtaAirtimeLimiter limiter;
  OtaAirtimeDecisionInput decision;
  const uint32_t now = 0;
  ASSERT_TRUE(limiter.recordUsage(now, OtaAirtimeCategory::Repair, 50000));
  EXPECT_TRUE(limiter.canAdmit(now, OtaAirtimeCategory::Repair, 22000, decision));  // 50000+22000=72000 <= budget
  EXPECT_FALSE(limiter.canAdmit(now, OtaAirtimeCategory::Repair, 22001, decision)); // exceeds
}

TEST(OtaAirtimeLimiter, UsageExpiresRatherThanAccumulatingForever) {
  OtaAirtimeLimiter limiter;
  const uint32_t t0 = 1000;
  ASSERT_TRUE(limiter.recordUsage(t0, OtaAirtimeCategory::Relay, 72000));
  EXPECT_EQ(72000u, limiter.storedUsageMs(t0));
  // Just before the window elapses, usage is still counted.
  EXPECT_EQ(72000u, limiter.storedUsageMs(t0 + limiter.windowMs()));
  // Just after the window elapses, the entry has fully expired.
  EXPECT_EQ(0u, limiter.storedUsageMs(t0 + limiter.windowMs() + 1));
}

TEST(OtaAirtimeLimiter, TracksUsageSeparatelyPerCategory) {
  OtaAirtimeLimiter limiter;
  const uint32_t now = 0;
  ASSERT_TRUE(limiter.recordUsage(now, OtaAirtimeCategory::Control, 1000));
  ASSERT_TRUE(limiter.recordUsage(now, OtaAirtimeCategory::Repair, 2000));
  ASSERT_TRUE(limiter.recordUsage(now, OtaAirtimeCategory::Relay, 3000));
  EXPECT_EQ(1000u, limiter.storedUsageMs(now, OtaAirtimeCategory::Control));
  EXPECT_EQ(2000u, limiter.storedUsageMs(now, OtaAirtimeCategory::Repair));
  EXPECT_EQ(3000u, limiter.storedUsageMs(now, OtaAirtimeCategory::Relay));
  EXPECT_EQ(6000u, limiter.storedUsageMs(now));
}

TEST(OtaAirtimeLimiter, RegulatoryDenialOverridesAvailableBudget) {
  OtaAirtimeLimiter limiter;
  OtaAirtimeDecisionInput decision;
  decision.regulatoryAllowed = false;
  EXPECT_FALSE(limiter.canAdmit(0, OtaAirtimeCategory::Control, 1, decision));
}

TEST(OtaAirtimeLimiter, NormalTrafficPrecedenceBlocksAllOtaCategoriesIncludingControl) {
  // Ready normal (non-OTA) mesh traffic takes absolute precedence over
  // every OTA airtime category -- Control (session negotiation, auth,
  // receipts, lease, census, etc.) included. An earlier version exempted
  // Control from this check, letting OTA session-control frames preempt
  // ready normal traffic; that violated the "normal traffic is never
  // starved by OTA" guarantee this limiter exists to enforce.
  OtaAirtimeLimiter limiter;
  OtaAirtimeDecisionInput decision;
  decision.normalTrafficActive = true;
  EXPECT_FALSE(limiter.canAdmit(0, OtaAirtimeCategory::Repair, 100, decision));
  EXPECT_FALSE(limiter.canAdmit(0, OtaAirtimeCategory::Relay, 100, decision));
  EXPECT_FALSE(limiter.canAdmit(0, OtaAirtimeCategory::Control, 100, decision));
}

TEST(OtaAirtimeLimiter, ClockWrapIsHandledCorrectly) {
  OtaAirtimeLimiter limiter;
  const uint32_t t0 = 0xFFFFFFFFu - 100; // near the uint32_t wraparound boundary
  ASSERT_TRUE(limiter.recordUsage(t0, OtaAirtimeCategory::Relay, 5000));
  // now wraps past 0
  const uint32_t nowAfterWrap = 50; // elapsed = 100 + 50 = 150ms since t0
  EXPECT_EQ(5000u, limiter.storedUsageMs(nowAfterWrap));

  // Advance further, past the window relative to t0 (still wrap-safe).
  const uint32_t nowFarAfterWrap = static_cast<uint32_t>(100 + limiter.windowMs() + 1);
  EXPECT_EQ(0u, limiter.storedUsageMs(nowFarAfterWrap));
}

TEST(OtaAirtimeLimiter, RecordUsageFailsClosedWhenRingFullOfValidEntries) {
  OtaAirtimeLimiter limiter;
  const uint32_t now = 0;
  for (size_t i = 0; i < OtaAirtimeLimiter::kMaxEntries; ++i) {
    ASSERT_TRUE(limiter.recordUsage(now, OtaAirtimeCategory::Control, 1));
  }
  // Ring is full and every entry is still within the window: fails closed.
  EXPECT_FALSE(limiter.recordUsage(now, OtaAirtimeCategory::Control, 1));

  // Once entries expire, room is reclaimed.
  const uint32_t later = now + limiter.windowMs() + 1;
  EXPECT_TRUE(limiter.recordUsage(later, OtaAirtimeCategory::Control, 1));
}

TEST(OtaAirtimeLimiter, CanAdmitFailsClosedWhenAccountingRingIsSaturated) {
  OtaAirtimeLimiter limiter;
  OtaAirtimeDecisionInput decision;
  const uint32_t now = 0;
  for (size_t i = 0; i < OtaAirtimeLimiter::kMaxEntries; ++i) {
    ASSERT_TRUE(limiter.recordUsage(now, OtaAirtimeCategory::Control, 1));
  }

  EXPECT_FALSE(limiter.canAdmit(now, OtaAirtimeCategory::Control, 1, decision))
      << "admission must be denied before a transmission that cannot be accounted";

  const uint32_t later = now + limiter.windowMs() + 1;
  EXPECT_TRUE(limiter.canAdmit(later, OtaAirtimeCategory::Control, 1, decision));
}

TEST(OtaAirtimeLimiter, TwoPercentOfOneHourWindowEqualsSeventyTwoThousandMs) {
  const uint32_t oneHourMs = 60u * 60u * 1000u;
  const uint32_t twoPercent = static_cast<uint32_t>((static_cast<uint64_t>(oneHourMs) * 2u) / 100u);
  EXPECT_EQ(72000u, twoPercent);
  EXPECT_LE(twoPercent, 72000u);
  EXPECT_EQ(OtaAirtimeLimiter::kDefaultBudgetMs, twoPercent);
}

// ---------------------------------------------------------------------
// Fleet state machine + bounded census/repair
// ---------------------------------------------------------------------

TEST(OtaFleetStateMachine, HappyPathAnnounceThroughCommit) {
  OtaFleetStateMachine m;
  ASSERT_TRUE(m.beginCampaign(kSession));
  EXPECT_EQ(OtaFleetState::Announcing, m.state());
  ASSERT_TRUE(m.handle(OtaFleetEvent::AnnounceComplete, kSession));
  EXPECT_EQ(OtaFleetState::Census, m.state());
  ASSERT_TRUE(m.handle(OtaFleetEvent::CensusComplete, kSession));
  EXPECT_EQ(OtaFleetState::CohortResolving, m.state());
  ASSERT_TRUE(m.handle(OtaFleetEvent::CohortResolved, kSession));
  EXPECT_EQ(OtaFleetState::Multicasting, m.state());
  ASSERT_TRUE(m.handle(OtaFleetEvent::MulticastComplete, kSession));
  EXPECT_EQ(OtaFleetState::MissingCensus, m.state());
  ASSERT_TRUE(m.handle(OtaFleetEvent::NoneMissing, kSession));
  EXPECT_EQ(OtaFleetState::Committing, m.state());
  ASSERT_TRUE(m.handle(OtaFleetEvent::CommitVerified, kSession));
  EXPECT_EQ(OtaFleetState::Complete, m.state());
}

TEST(OtaFleetStateMachine, RepairLoopReturnsToMissingCensus) {
  OtaFleetStateMachine m;
  ASSERT_TRUE(m.beginCampaign(kSession));
  ASSERT_TRUE(m.handle(OtaFleetEvent::AnnounceComplete, kSession));
  ASSERT_TRUE(m.handle(OtaFleetEvent::CensusComplete, kSession));
  ASSERT_TRUE(m.handle(OtaFleetEvent::CohortResolved, kSession));
  ASSERT_TRUE(m.handle(OtaFleetEvent::MulticastComplete, kSession));
  ASSERT_TRUE(m.handle(OtaFleetEvent::SomeMissing, kSession));
  EXPECT_EQ(OtaFleetState::Repairing, m.state());
  ASSERT_TRUE(m.handle(OtaFleetEvent::RepairRoundComplete, kSession));
  EXPECT_EQ(OtaFleetState::MissingCensus, m.state());
  ASSERT_TRUE(m.handle(OtaFleetEvent::NoneMissing, kSession));
  EXPECT_EQ(OtaFleetState::Committing, m.state());
}

TEST(OtaFleetStateMachine, CensusTimeoutFails) {
  OtaFleetStateMachine m;
  ASSERT_TRUE(m.beginCampaign(kSession));
  ASSERT_TRUE(m.handle(OtaFleetEvent::AnnounceComplete, kSession));
  ASSERT_TRUE(m.handle(OtaFleetEvent::CensusTimeout, kSession));
  EXPECT_EQ(OtaFleetState::Failed, m.state());
}

TEST(OtaFleetStateMachine, AbortLegalFromEveryReachableState) {
  using E = OtaFleetEvent;
  auto driveTo = [](OtaFleetStateMachine& m, int steps) {
    m.beginCampaign(kSession);
    constexpr E path[] = {E::AnnounceComplete, E::CensusComplete, E::CohortResolved, E::MulticastComplete, E::SomeMissing};
    for (int i = 0; i < steps; ++i) m.handle(path[i], kSession);
  };
  for (int steps = 0; steps <= 5; ++steps) {
    OtaFleetStateMachine m;
    driveTo(m, steps);
    ASSERT_TRUE(m.handle(E::Abort, kSession)) << "steps=" << steps;
    EXPECT_EQ(OtaFleetState::Aborted, m.state());
  }
}

TEST(OtaFleetCensus, ReportsBoundedFleetAndIdentifiesMissingMembers) {
  OtaFleetCensus<3> census;
  EXPECT_TRUE(census.reportMember(1, true, 811008));
  EXPECT_TRUE(census.reportMember(2, false, 400000));
  EXPECT_TRUE(census.reportMember(3, false, 0));
  EXPECT_EQ(3u, census.memberCount());
  EXPECT_FALSE(census.allComplete());

  uint32_t missing[3] = {0};
  size_t n = census.missingMembers(missing, 3);
  ASSERT_EQ(2u, n);
  EXPECT_EQ(2u, missing[0]);
  EXPECT_EQ(3u, missing[1]);
}

TEST(OtaFleetCensus, FailsClosedOncePastBoundedCapacity) {
  OtaFleetCensus<2> census;
  EXPECT_TRUE(census.reportMember(1, true, 1));
  EXPECT_TRUE(census.reportMember(2, true, 1));
  EXPECT_FALSE(census.reportMember(3, true, 1)); // bounded: capacity is 2
  EXPECT_EQ(2u, census.memberCount());
}

TEST(OtaFleetCensus, UpdatingExistingMemberDoesNotConsumeCapacity) {
  OtaFleetCensus<1> census;
  EXPECT_TRUE(census.reportMember(1, false, 10));
  EXPECT_TRUE(census.reportMember(1, true, 811008)); // update, same node id
  EXPECT_EQ(1u, census.memberCount());
  EXPECT_TRUE(census.allComplete());
}

TEST(OtaFleetCensus, ResetClearsMembership) {
  OtaFleetCensus<2> census;
  census.reportMember(1, true, 1);
  census.reset();
  EXPECT_EQ(0u, census.memberCount());
  EXPECT_FALSE(census.allComplete());
}

// -----------------------------------------------------------------------
// OtaTxSequenceLedger: durable, block-reserved, never-repeats, reboot
// skips whole prior reserved block, never wraps past UINT32_MAX.
// -----------------------------------------------------------------------

namespace {
constexpr uint32_t kLedgerEraseUnit = 64;
constexpr uint32_t kLedgerRegionBytes = kLedgerEraseUnit * 2;
}  // namespace

TEST(OtaTxSequenceLedger, FirstAllocationOnBlankLedgerStartsAtOneAndReservesBlock) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  OtaTxSequenceAllocator allocator(region, OtaSequenceInitialization::CommissionVirgin);
  uint32_t seq = 0;
  ASSERT_TRUE(allocator.allocate(&seq));
  EXPECT_EQ(seq, 1u);
  ASSERT_TRUE(allocator.allocate(&seq));
  EXPECT_EQ(seq, 2u);
}

TEST(OtaTxSequenceLedger, SequenceNeverRepeatsAcrossManyAllocations) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  OtaTxSequenceAllocator allocator(region, OtaSequenceInitialization::CommissionVirgin);
  uint32_t last = 0;
  for (int i = 0; i < 200; ++i) {
    uint32_t seq = 0;
    ASSERT_TRUE(allocator.allocate(&seq));
    EXPECT_GT(seq, last);
    last = seq;
  }
}

TEST(OtaTxSequenceLedger, RebootSkipsWholeRemainderOfPriorReservedBlock) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  uint32_t seq = 0;
  {
    OtaTxSequenceAllocator allocator(region, OtaSequenceInitialization::CommissionVirgin);
    ASSERT_TRUE(allocator.allocate(&seq));  // reserves block [1,64], issues 1.
    EXPECT_EQ(seq, 1u);
  }  // "reboot": allocator destroyed, only durable ledger state survives.
  {
    OtaTxSequenceAllocator allocator(region);
    ASSERT_TRUE(allocator.allocate(&seq));
    // Must skip the whole rest of [2..64] from the abandoned block and
    // reserve a brand new one starting at 65.
    EXPECT_EQ(seq, 65u);
  }
}

TEST(OtaTxSequenceLedger, CorruptLedgerFailsClosedPermanently) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  // Program garbage (non-blank, invalid record) into slot 0 directly.
  uint8_t garbage[kLedgerEraseUnit];
  memset(garbage, 0x42, sizeof(garbage));
  ASSERT_TRUE(ota::platform::isOk(flash.program(0, garbage, sizeof(garbage))));
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  OtaTxSequenceAllocator allocator(region);
  uint32_t seq = 0;
  EXPECT_FALSE(allocator.allocate(&seq));
  EXPECT_FALSE(allocator.allocate(&seq));  // stays disabled, does not "recover".
}

TEST(OtaTxSequenceLedger, ExhaustionNearUint32MaxFailsClosedNeverWraps) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  // Directly seed the ledger record at the very top of the sequence space.
  uint8_t record[OtaTxSequenceLedgerRecord::kRecordBytes];
  ASSERT_EQ(OtaTxSequenceLedgerRecord::serialize(0xFFFFFFFFu - 1u, record, sizeof(record)),
            OtaTxSequenceLedgerRecord::kRecordBytes);
  ASSERT_TRUE(ota::platform::isOk(region.program(0, record, sizeof(record))));
  OtaTxSequenceAllocator allocator(region);
  uint32_t seq = 0;
  EXPECT_FALSE(allocator.allocate(&seq));  // reserving another block would overflow: refuse.
}

// -----------------------------------------------------------------------
// OtaRxReplayLedger: durable watermark + bounded reorder window,
// replay/duplicate rejection, fail-closed on corrupt state.
// -----------------------------------------------------------------------

TEST(OtaRxReplayLedger, FirstEverSequenceIsAdmittedAndDuplicateIsRejected) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  OtaRxReplayLedger ledger(region, OtaSequenceInitialization::CommissionVirgin);
  EXPECT_TRUE(ledger.admit(5));
  EXPECT_FALSE(ledger.admit(5));  // exact duplicate: replay.
}

TEST(OtaRxReplayLedger, RejectsZeroSequence) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  OtaRxReplayLedger ledger(region);
  EXPECT_FALSE(ledger.admit(0));
}

TEST(OtaRxReplayLedger, AllowsBoundedReorderingWithinWindowButRejectsBeyondIt) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  OtaRxReplayLedger ledger(region, OtaSequenceInitialization::CommissionVirgin);
  ASSERT_TRUE(ledger.admit(100));
  EXPECT_TRUE(ledger.admit(99));    // within the 64-wide reorder window: ok.
  EXPECT_FALSE(ledger.admit(99));   // now a duplicate: reject.
  EXPECT_FALSE(ledger.admit(30));   // 70 below watermark: outside window, reject.
}

TEST(OtaRxReplayLedger, WatermarkSurvivesRebootAndRejectsAtOrBelowIt) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  {
    OtaRxReplayLedger ledger(region, OtaSequenceInitialization::CommissionVirgin);
    ASSERT_TRUE(ledger.admit(50));
  }  // "reboot": in-RAM reorder bitmap is lost, durable watermark is not.
  {
    OtaRxReplayLedger ledger(region);
    EXPECT_FALSE(ledger.admit(50));  // at watermark: rejected even though bitmap reset.
    EXPECT_FALSE(ledger.admit(10));  // below watermark: rejected.
    EXPECT_TRUE(ledger.admit(51));   // strictly above watermark: newly admitted.
  }
}

TEST(OtaRxReplayLedger, CorruptLedgerFailsClosedPermanently) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  uint8_t garbage[kLedgerEraseUnit];
  memset(garbage, 0x5A, sizeof(garbage));
  ASSERT_TRUE(ota::platform::isOk(flash.program(0, garbage, sizeof(garbage))));
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  OtaRxReplayLedger ledger(region);
  EXPECT_FALSE(ledger.admit(1));
  EXPECT_FALSE(ledger.admit(2));
}

TEST(OtaRxReplayLedger, AdvancingAfterRebootNeverReopensOlderAdmissions) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  {
    OtaRxReplayLedger ledger(region, OtaSequenceInitialization::CommissionVirgin);
    ASSERT_TRUE(ledger.admit(50));
    ASSERT_TRUE(ledger.admit(49));
  }
  OtaRxReplayLedger reconstructed(region);
  ASSERT_TRUE(reconstructed.admit(51));
  EXPECT_FALSE(reconstructed.admit(49));
  EXPECT_FALSE(reconstructed.admit(50));
  ASSERT_TRUE(reconstructed.admit(53));
  EXPECT_TRUE(reconstructed.admit(52));
  EXPECT_FALSE(reconstructed.admit(52));
}

TEST(OtaTxSequenceLedger, CorruptNewerSlotNeverFallsBackToPreviouslyIssuedBlock) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  uint32_t seq = 0;
  {
    OtaTxSequenceAllocator allocator(region, OtaSequenceInitialization::CommissionVirgin);
    for (unsigned i = 0; i < 65; ++i) ASSERT_TRUE(allocator.allocate(&seq));
    ASSERT_EQ(seq, 65u);
  }
  const uint8_t corrupt = 0;
  ASSERT_TRUE(ota::platform::isOk(region.program(kLedgerEraseUnit, &corrupt, 1)));
  OtaTxSequenceAllocator reconstructed(region);
  seq = 0xA5A5A5A5;
  EXPECT_FALSE(reconstructed.allocate(&seq));
  EXPECT_EQ(seq, 0xA5A5A5A5u);
}

TEST(OtaTxSequenceLedger, UnreadableNewerSlotNeverFallsBackToPreviouslyIssuedBlock) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  uint32_t seq = 0;
  {
    OtaTxSequenceAllocator allocator(region, OtaSequenceInitialization::CommissionVirgin);
    for (unsigned i = 0; i < 65; ++i) ASSERT_TRUE(allocator.allocate(&seq));
  }
  flash.armFault({ota::test::FakeNorFlash::OpKind::Read,
                  ota::test::FakeNorFlash::InjectionTiming::Before, flash.readOpCount() + 2, 0});
  OtaTxSequenceAllocator reconstructed(region);
  seq = 0xA5A5A5A5;
  EXPECT_FALSE(reconstructed.allocate(&seq));
  EXPECT_EQ(seq, 0xA5A5A5A5u);
}

TEST(OtaRxReplayLedger, CorruptNewerSlotNeverReopensPreviouslyAdmittedSequence) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  {
    OtaRxReplayLedger ledger(region, OtaSequenceInitialization::CommissionVirgin);
    ASSERT_TRUE(ledger.admit(50));
    ASSERT_TRUE(ledger.admit(51));
  }
  const uint8_t corrupt = 0;
  ASSERT_TRUE(ota::platform::isOk(region.program(kLedgerEraseUnit, &corrupt, 1)));
  OtaRxReplayLedger reconstructed(region);
  EXPECT_FALSE(reconstructed.admit(51));
}

TEST(OtaTxSequenceLedger, Uint32MaxCannotWrapReconstructedAllocatorToZero) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  uint8_t record[OtaTxSequenceLedgerRecord::kRecordBytes];
  ASSERT_EQ(OtaTxSequenceLedgerRecord::serialize(UINT32_MAX, record, sizeof(record)),
            sizeof(record));
  ASSERT_TRUE(ota::platform::isOk(region.program(0, record, sizeof(record))));
  OtaTxSequenceAllocator allocator(region);
  uint32_t seq = 0xA5A5A5A5;
  EXPECT_FALSE(allocator.allocate(&seq));
  EXPECT_EQ(seq, 0xA5A5A5A5u);
}

TEST(OtaSequenceLedger, BlankDefaultsNeverAuthorizeIdentityReuse) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  OtaTxSequenceAllocator tx(region);
  OtaRxReplayLedger rx(region);
  uint32_t seq = 0xA5A5A5A5;
  EXPECT_FALSE(tx.allocate(&seq));
  EXPECT_FALSE(rx.admit(1));
  EXPECT_EQ(seq, 0xA5A5A5A5u);
  EXPECT_EQ(flash.eraseOpCount(), 0u);
  EXPECT_EQ(flash.programOpCount(), 0u);
}

TEST(OtaSequenceLedger, LostCommissionedRecordsNeverBecomeVirginAfterReconstruction) {
  ota::test::FakeNorFlash flash(2 * kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion txRegion(flash, 0, kLedgerRegionBytes);
  ota::platform::FlashRegion rxRegion(flash, kLedgerRegionBytes, kLedgerRegionBytes);
  {
    OtaTxSequenceAllocator tx(txRegion, OtaSequenceInitialization::CommissionVirgin);
    OtaRxReplayLedger rx(rxRegion, OtaSequenceInitialization::CommissionVirgin);
    uint32_t seq = 0;
    ASSERT_TRUE(tx.allocate(&seq));
    ASSERT_TRUE(rx.admit(50));
  }
  ASSERT_TRUE(ota::platform::isOk(txRegion.eraseRange(0, kLedgerRegionBytes)));
  ASSERT_TRUE(ota::platform::isOk(rxRegion.eraseRange(0, kLedgerRegionBytes)));
  const auto erases = flash.eraseOpCount();
  const auto programs = flash.programOpCount();
  OtaTxSequenceAllocator tx(txRegion);
  OtaRxReplayLedger rx(rxRegion);
  uint32_t seq = 0xA5A5A5A5;
  EXPECT_FALSE(tx.allocate(&seq));
  EXPECT_FALSE(rx.admit(50));
  EXPECT_EQ(seq, 0xA5A5A5A5u);
  EXPECT_EQ(flash.eraseOpCount(), erases);
  EXPECT_EQ(flash.programOpCount(), programs);
}

TEST(OtaTxSequenceLedger, NullAllocationNeverReadsOrReserves) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  OtaTxSequenceAllocator tx(region, OtaSequenceInitialization::CommissionVirgin);
  EXPECT_FALSE(tx.allocate(nullptr));
  EXPECT_EQ(flash.readOpCount(), 0u);
  EXPECT_EQ(flash.eraseOpCount(), 0u);
  EXPECT_EQ(flash.programOpCount(), 0u);
  uint32_t seq = 0;
  ASSERT_TRUE(tx.allocate(&seq));
  EXPECT_EQ(seq, 1u);
}

TEST(OtaTxSequenceLedger, LastBlockCanIssueUint32MaxOnlyOnceWithoutWrapping) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  uint8_t record[OtaTxSequenceLedgerRecord::kRecordBytes];
  ASSERT_EQ(OtaTxSequenceLedgerRecord::serialize(UINT32_MAX - 64, record, sizeof(record)), sizeof(record));
  ASSERT_TRUE(ota::platform::isOk(region.program(0, record, sizeof(record))));
  OtaTxSequenceAllocator tx(region);
  uint32_t seq = 0;
  for (uint32_t i = 0; i < 64; ++i) {
    ASSERT_TRUE(tx.allocate(&seq));
    EXPECT_EQ(seq, UINT32_MAX - 63 + i);
  }
  seq = 0xA5A5A5A5;
  EXPECT_FALSE(tx.allocate(&seq));
  EXPECT_EQ(seq, 0xA5A5A5A5u);
  OtaTxSequenceAllocator reconstructed(region);
  EXPECT_FALSE(reconstructed.allocate(&seq));
  EXPECT_EQ(seq, 0xA5A5A5A5u);
}

TEST(OtaSequenceLedger, PublicRecordAdvancesRejectZeroEqualAndLowerWithoutMutation) {
  ota::test::FakeNorFlash flash(2 * kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion txRegion(flash, 0, kLedgerRegionBytes);
  ota::platform::FlashRegion rxRegion(flash, kLedgerRegionBytes, kLedgerRegionBytes);
  ASSERT_TRUE(OtaTxSequenceLedgerRecord::reserve(txRegion, 64));
  ASSERT_TRUE(OtaRxReplayLedgerRecord::advance(rxRegion, 100));
  const auto erases = flash.eraseOpCount();
  const auto programs = flash.programOpCount();
  for (uint32_t value : {0u, 63u, 64u}) EXPECT_FALSE(OtaTxSequenceLedgerRecord::reserve(txRegion, value));
  for (uint32_t value : {0u, 99u, 100u}) EXPECT_FALSE(OtaRxReplayLedgerRecord::advance(rxRegion, value));
  EXPECT_EQ(flash.eraseOpCount(), erases);
  EXPECT_EQ(flash.programOpCount(), programs);
}

TEST(OtaSequenceLedger, ChecksummedZeroRecordIsNotVirginEvenWithCommissioningPermission) {
  ota::test::FakeNorFlash flash(2 * kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion txRegion(flash, 0, kLedgerRegionBytes);
  ota::platform::FlashRegion rxRegion(flash, kLedgerRegionBytes, kLedgerRegionBytes);
  uint8_t record[OtaTxSequenceLedgerRecord::kRecordBytes];
  ASSERT_EQ(OtaTxSequenceLedgerRecord::serialize(0, record, sizeof(record)), sizeof(record));
  ASSERT_TRUE(ota::platform::isOk(txRegion.program(0, record, sizeof(record))));
  ASSERT_EQ(OtaRxReplayLedgerRecord::serialize(0, record, sizeof(record)), sizeof(record));
  ASSERT_TRUE(ota::platform::isOk(rxRegion.program(0, record, sizeof(record))));
  OtaTxSequenceAllocator tx(txRegion, OtaSequenceInitialization::CommissionVirgin);
  OtaRxReplayLedger rx(rxRegion, OtaSequenceInitialization::CommissionVirgin);
  uint32_t seq = 0xA5A5A5A5;
  EXPECT_FALSE(tx.allocate(&seq));
  EXPECT_FALSE(rx.admit(1));
  EXPECT_EQ(seq, 0xA5A5A5A5u);
}

TEST(OtaSequenceLedger, TransactionalWriterRejectsOverflowZeroMarkerAndSectorSpillBeforeMutation) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  ASSERT_TRUE(OtaTxSequenceLedgerRecord::reserve(region, 64));
  const std::vector<uint8_t> before(flash.rawBuffer(), flash.rawBuffer() + flash.rawSize());
  const auto erases = flash.eraseOpCount();
  const auto programs = flash.programOpCount();
  const uint8_t record[68] = {};
  EXPECT_FALSE(ota::storage::writeOtaJournalRecordTransactional(region, 0, record, 20, UINT32_MAX, 21));
  EXPECT_FALSE(ota::storage::writeOtaJournalRecordTransactional(region, 0, record, 20, 20, 0));
  EXPECT_FALSE(ota::storage::writeOtaJournalRecordTransactional(region, 0, record, 68, 64, 4));
  EXPECT_EQ(flash.eraseOpCount(), erases);
  EXPECT_EQ(flash.programOpCount(), programs);
  EXPECT_EQ(std::memcmp(flash.rawBuffer(), before.data(), before.size()), 0);
}

namespace {
using LedgerOp = ota::test::FakeNorFlash::OpKind;
using LedgerTiming = ota::test::FakeNorFlash::InjectionTiming;
enum class LedgerRecovery { Existing, New, Unsafe };

struct LedgerFaultCase {
  LedgerOp op;
  LedgerTiming timing;
  uint32_t relative_count;
  uint32_t partial_bytes;
  LedgerRecovery recovery;
};

std::vector<LedgerFaultCase> ledgerFaultCases() {
  std::vector<LedgerFaultCase> cases{
      {LedgerOp::Erase, LedgerTiming::Before, 1, 0, LedgerRecovery::Existing},
      {LedgerOp::Erase, LedgerTiming::After, 1, 0, LedgerRecovery::Existing},
      {LedgerOp::Program, LedgerTiming::Before, 1, 0, LedgerRecovery::Existing},
      {LedgerOp::Program, LedgerTiming::After, 1, 0, LedgerRecovery::Unsafe},
      {LedgerOp::Program, LedgerTiming::Before, 2, 0, LedgerRecovery::Unsafe},
      {LedgerOp::Program, LedgerTiming::After, 2, 0, LedgerRecovery::New},
  };
  for (uint32_t cut = 0; cut <= kLedgerEraseUnit; ++cut) {
    cases.push_back({LedgerOp::Erase, LedgerTiming::Mid, 1, cut,
                     cut == 0 || cut >= 20 ? LedgerRecovery::Existing : LedgerRecovery::Unsafe});
  }
  for (uint32_t cut = 0; cut <= 16; ++cut) {
    cases.push_back({LedgerOp::Program, LedgerTiming::Mid, 1, cut,
                     cut == 0 ? LedgerRecovery::Existing : LedgerRecovery::Unsafe});
  }
  for (uint32_t cut = 0; cut <= 4; ++cut) {
    cases.push_back({LedgerOp::Program, LedgerTiming::Mid, 2, cut,
                     cut == 4 ? LedgerRecovery::New : LedgerRecovery::Unsafe});
  }
  for (uint32_t read = 1; read <= 5; ++read) {
    const auto recovery = read <= 2 ? LedgerRecovery::Existing :
                          read == 3 ? LedgerRecovery::Unsafe : LedgerRecovery::New;
    cases.push_back({LedgerOp::Read, LedgerTiming::Before, read, 0, recovery});
    cases.push_back({LedgerOp::Read, LedgerTiming::After, read, 0, recovery});
  }
  return cases;
}

void armLedgerFault(ota::test::FakeNorFlash& flash, const LedgerFaultCase& fault) {
  const uint32_t count = fault.op == LedgerOp::Erase ? flash.eraseOpCount() :
                         fault.op == LedgerOp::Program ? flash.programOpCount() : flash.readOpCount();
  flash.armFault({fault.op, fault.timing, count + fault.relative_count, fault.partial_bytes});
}
} // namespace

TEST(OtaTxSequenceLedger, EveryEraseBodyMarkerAndReadbackCutFreezesUntilFreshReconstruction) {
  const auto cases = ledgerFaultCases();
  ASSERT_EQ(cases.size(), 103u);
  for (const auto& fault : cases) {
    SCOPED_TRACE(::testing::Message() << int(fault.op) << "/" << int(fault.timing)
                                     << "/" << fault.relative_count << "/" << fault.partial_bytes);
    ota::test::FakeNorFlash flash(4 * kLedgerEraseUnit, kLedgerEraseUnit, 4);
    const std::vector<uint8_t> guard(kLedgerEraseUnit, 0x3C);
    ASSERT_TRUE(ota::platform::isOk(flash.program(0, guard.data(), guard.size())));
    ASSERT_TRUE(ota::platform::isOk(flash.program(3 * kLedgerEraseUnit, guard.data(), guard.size())));
    ota::platform::FlashRegion region(flash, kLedgerEraseUnit, kLedgerRegionBytes);
    OtaTxSequenceAllocator tx(region, OtaSequenceInitialization::CommissionVirgin);
    uint32_t seq = 0;
    for (uint32_t i = 0; i < 128; ++i) ASSERT_TRUE(tx.allocate(&seq));
    ASSERT_EQ(seq, 128u);
    const std::vector<uint8_t> latest(flash.rawBuffer() + 2 * kLedgerEraseUnit,
                                     flash.rawBuffer() + 3 * kLedgerEraseUnit);
    armLedgerFault(flash, fault);
    seq = 0xA5A5A5A5;
    ASSERT_FALSE(tx.allocate(&seq));
    EXPECT_EQ(seq, 0xA5A5A5A5u);
    const auto erases = flash.eraseOpCount();
    const auto programs = flash.programOpCount();
    const auto reads = flash.readOpCount();
    flash.clearFault();
    EXPECT_FALSE(tx.allocate(&seq));
    EXPECT_EQ(seq, 0xA5A5A5A5u);
    EXPECT_EQ(flash.eraseOpCount(), erases);
    EXPECT_EQ(flash.programOpCount(), programs);
    EXPECT_EQ(flash.readOpCount(), reads);
    EXPECT_EQ(std::memcmp(flash.rawBuffer() + 2 * kLedgerEraseUnit, latest.data(), latest.size()), 0);
    OtaTxSequenceAllocator reconstructed(region);
    if (fault.recovery == LedgerRecovery::Unsafe) {
      EXPECT_FALSE(reconstructed.allocate(&seq));
      EXPECT_EQ(seq, 0xA5A5A5A5u);
    } else {
      ASSERT_TRUE(reconstructed.allocate(&seq));
      EXPECT_EQ(seq, fault.recovery == LedgerRecovery::New ? 193u : 129u);
    }
    EXPECT_EQ(std::memcmp(flash.rawBuffer(), guard.data(), guard.size()), 0);
    EXPECT_EQ(std::memcmp(flash.rawBuffer() + 3 * kLedgerEraseUnit, guard.data(), guard.size()), 0);
  }
}

TEST(OtaRxReplayLedger, EveryEraseBodyMarkerAndReadbackCutFreezesEvenReorderedFrames) {
  const auto cases = ledgerFaultCases();
  ASSERT_EQ(cases.size(), 103u);
  for (const auto& fault : cases) {
    SCOPED_TRACE(::testing::Message() << int(fault.op) << "/" << int(fault.timing)
                                     << "/" << fault.relative_count << "/" << fault.partial_bytes);
    ota::test::FakeNorFlash flash(4 * kLedgerEraseUnit, kLedgerEraseUnit, 4);
    const std::vector<uint8_t> guard(kLedgerEraseUnit, 0x3C);
    ASSERT_TRUE(ota::platform::isOk(flash.program(0, guard.data(), guard.size())));
    ASSERT_TRUE(ota::platform::isOk(flash.program(3 * kLedgerEraseUnit, guard.data(), guard.size())));
    ota::platform::FlashRegion region(flash, kLedgerEraseUnit, kLedgerRegionBytes);
    OtaRxReplayLedger rx(region, OtaSequenceInitialization::CommissionVirgin);
    ASSERT_TRUE(rx.admit(50));
    ASSERT_TRUE(rx.admit(100));
    const std::vector<uint8_t> latest(flash.rawBuffer() + 2 * kLedgerEraseUnit,
                                     flash.rawBuffer() + 3 * kLedgerEraseUnit);
    armLedgerFault(flash, fault);
    ASSERT_FALSE(rx.admit(150));
    const auto erases = flash.eraseOpCount();
    const auto programs = flash.programOpCount();
    const auto reads = flash.readOpCount();
    flash.clearFault();
    EXPECT_FALSE(rx.admit(99));
    EXPECT_FALSE(rx.admit(151));
    EXPECT_EQ(flash.eraseOpCount(), erases);
    EXPECT_EQ(flash.programOpCount(), programs);
    EXPECT_EQ(flash.readOpCount(), reads);
    EXPECT_EQ(std::memcmp(flash.rawBuffer() + 2 * kLedgerEraseUnit, latest.data(), latest.size()), 0);
    OtaRxReplayLedger reconstructed(region);
    if (fault.recovery == LedgerRecovery::Unsafe) {
      EXPECT_FALSE(reconstructed.admit(151));
    } else {
      ASSERT_TRUE(reconstructed.load());
      EXPECT_FALSE(reconstructed.admit(100));
      EXPECT_FALSE(reconstructed.admit(50));
      EXPECT_EQ(reconstructed.admit(150), fault.recovery == LedgerRecovery::Existing);
      EXPECT_TRUE(reconstructed.admit(151));
      EXPECT_FALSE(reconstructed.admit(50));
    }
    EXPECT_EQ(std::memcmp(flash.rawBuffer(), guard.data(), guard.size()), 0);
    EXPECT_EQ(std::memcmp(flash.rawBuffer() + 3 * kLedgerEraseUnit, guard.data(), guard.size()), 0);
  }
}

// -----------------------------------------------------------------------
// Store-agnostic backing port (OtaSequenceBackingPort.h /
// OtaSequenceBackedLedgers.h / OtaFlashSequenceBackingAdapters.h):
// proves the SAME block-reservation / watermark-bitmap semantics work
// against (a) the existing FlashRegion-backed 2-sector journal via the
// new adapter, and (b) a bounded, multi-context, deliberately-hash-
// colliding in-memory backing modeling a future shared append store --
// full-byte identity, never a hash/selector, capacity denial, cold
// reconstruction, and durable-but-lost-ack (Uncertain) recovery.
// -----------------------------------------------------------------------
namespace {

// Directly-controllable fakes: every call's result is settable ahead of
// time, so each OtaSequenceBackingResult value can be exercised in
// isolation against OtaBackedTxSequenceAllocator/OtaBackedRxReplayLedger.
class FakeControllableTxBackingStore : public ITxSequenceBackingStore {
public:
  OtaSequenceBackingResult openExisting() override {
    ++openCalls;
    return nextOpenResult;
  }
  OtaSequenceBackingResult readCounter(uint32_t& outReservedUpperBound) override {
    ++readCalls;
    outReservedUpperBound = counter;
    return nextReadResult;
  }
  OtaSequenceBackingResult reserveTx(uint32_t expectedCurrentUpperBound, uint32_t blockSize,
                                      uint32_t& outNewUpperBound) override {
    ++reserveCalls;
    (void)expectedCurrentUpperBound;
    if (nextReserveResult == OtaSequenceBackingResult::Committed) {
      counter += blockSize;
      outNewUpperBound = counter;
    }
    return nextReserveResult;
  }

  OtaSequenceBackingResult nextOpenResult = OtaSequenceBackingResult::Committed;
  OtaSequenceBackingResult nextReadResult = OtaSequenceBackingResult::Committed;
  OtaSequenceBackingResult nextReserveResult = OtaSequenceBackingResult::Committed;
  uint32_t counter = 0;
  int openCalls = 0;
  int readCalls = 0;
  int reserveCalls = 0;
};

class FakeControllableRxBackingStore : public IRxSequenceBackingStore {
public:
  OtaSequenceBackingResult openExisting(const OtaRxLedgerContext&) override {
    ++openCalls;
    return nextOpenResult;
  }
  OtaSequenceBackingResult readCounter(const OtaRxLedgerContext&, uint32_t& outWatermark) override {
    ++readCalls;
    outWatermark = watermark;
    return nextReadResult;
  }
  OtaSequenceBackingResult advanceRx(const OtaRxLedgerContext&, uint32_t expectedHead, uint32_t newHead) override {
    ++advanceCalls;
    if (nextAdvanceResult == OtaSequenceBackingResult::Conflict) {
      // Simulates the durable head having genuinely already moved past
      // what the caller expected (e.g. a previous Uncertain call had
      // actually landed).
      return OtaSequenceBackingResult::Conflict;
    }
    (void)expectedHead;
    if (nextAdvanceResult == OtaSequenceBackingResult::Committed) {
      watermark = newHead;
    } else if (advanceAppliesEvenWhenUncertain && nextAdvanceResult == OtaSequenceBackingResult::Uncertain) {
      watermark = newHead;  // durable write actually landed, ack simply "lost".
    }
    return nextAdvanceResult;
  }

  OtaSequenceBackingResult nextOpenResult = OtaSequenceBackingResult::Committed;
  OtaSequenceBackingResult nextReadResult = OtaSequenceBackingResult::Committed;
  OtaSequenceBackingResult nextAdvanceResult = OtaSequenceBackingResult::Committed;
  bool advanceAppliesEvenWhenUncertain = false;
  uint32_t watermark = 0;
  int openCalls = 0;
  int readCalls = 0;
  int advanceCalls = 0;
};

uint8_t peerByte(uint8_t seed) { return static_cast<uint8_t>(seed * 7u + 3u); }

OtaRxLedgerContext makeFullPeerContext(uint16_t index) {
  uint8_t bytes[32] = {};
  bytes[0] = static_cast<uint8_t>(index & 0xFFu);
  bytes[1] = static_cast<uint8_t>((index >> 8) & 0xFFu);
  for (int i = 2; i < 32; ++i) bytes[i] = peerByte(static_cast<uint8_t>(index + i));
  return OtaRxLedgerContext::forPeer(bytes);
}

OtaRxLedgerContext makeFullGroupContext(uint16_t index) {
  uint8_t bytes[92] = {};
  bytes[0] = static_cast<uint8_t>(index & 0xFFu);
  bytes[1] = static_cast<uint8_t>((index >> 8) & 0xFFu) | 0x80u;  // distinguish from any peer pattern.
  for (int i = 2; i < 92; ++i) bytes[i] = peerByte(static_cast<uint8_t>(index + i + 1));
  return OtaRxLedgerContext::forGroup(bytes);
}

// A bounded, multi-context RX backing modeling the essential shape of a
// future shared append store: durable state OUTLIVES any individual
// OtaBackedRxReplayLedger wrapper (so destroying/recreating the wrapper
// over the SAME store instance genuinely models cold reconstruction),
// capacity is hard-bounded per Astra's "350 full-peer / 4 active group"
// contract, and lookups deliberately hash into only a HANDFUL of
// buckets (so many distinct real contexts collide) yet always resolve
// correctly because every comparison is full-byte, never truncated.
class BoundedMultiContextRxBackingStore : public IRxSequenceBackingStore, public IRxSequenceCommissioningAuthority {
public:
  static constexpr size_t kMaxPeerContexts = 350;
  static constexpr size_t kMaxGroupContexts = 4;
  static constexpr size_t kBucketCount = 8;  // deliberately small: guarantees real collisions at scale 350/4.

  OtaSequenceBackingResult openExisting(const OtaRxLedgerContext& context) override {
    if (forceOpenWouldBlockOnce) {
      forceOpenWouldBlockOnce = false;
      return OtaSequenceBackingResult::WouldBlock;
    }
    Entry* e = find(context);
    if (e == nullptr) return OtaSequenceBackingResult::Missing;
    return OtaSequenceBackingResult::Committed;
  }

  OtaSequenceBackingResult readCounter(const OtaRxLedgerContext& context, uint32_t& outWatermark) override {
    Entry* e = find(context);
    if (e == nullptr) return OtaSequenceBackingResult::Missing;
    outWatermark = e->watermark;
    return OtaSequenceBackingResult::Committed;
  }

  OtaSequenceBackingResult advanceRx(const OtaRxLedgerContext& context, uint32_t expectedHead,
                                     uint32_t newHead) override {
    Entry* e = find(context);
    if (e == nullptr) return OtaSequenceBackingResult::Missing;
    if (e->watermark != expectedHead) return OtaSequenceBackingResult::Conflict;
    if (forceUncertainOnceForNextAdvance) {
      forceUncertainOnceForNextAdvance = false;
      e->watermark = newHead;  // durably applied; only the ACK is "lost".
      return OtaSequenceBackingResult::Uncertain;
    }
    e->watermark = newHead;
    return OtaSequenceBackingResult::Committed;
  }

  bool commissionVirginRx(const OtaRxLedgerContext& context, uint32_t initialWatermark) override {
    if (initialWatermark == 0) return false;
    if (find(context) != nullptr) return false;  // already commissioned: never relax/overwrite.
    auto& bucket = bucketFor(context);
    auto& vec = context.kind() == OtaRxLedgerContext::Kind::Peer ? peerCount_ : groupCount_;
    const size_t cap = context.kind() == OtaRxLedgerContext::Kind::Peer ? kMaxPeerContexts : kMaxGroupContexts;
    if (vec >= cap) return false;  // bounded capacity exhausted.
    bucket.push_back({context, initialWatermark});
    ++vec;
    return true;
  }

  bool forceOpenWouldBlockOnce = false;
  bool forceUncertainOnceForNextAdvance = false;

private:
  struct Entry {
    OtaRxLedgerContext context;
    uint32_t watermark;
  };

  // Deliberately weak/colliding index: only the first byte, folded into
  // a handful of buckets -- real distinguishing power comes ONLY from
  // the full-byte equals() scan below, never from this index alone.
  size_t hashIndex(const OtaRxLedgerContext& context) const {
    const uint8_t firstByte = context.kind() == OtaRxLedgerContext::Kind::Peer ? context.peerId()[0]
                                                                               : context.groupContext()[0];
    return static_cast<size_t>(firstByte) % kBucketCount;
  }

  std::vector<Entry>& bucketFor(const OtaRxLedgerContext& context) { return buckets_[hashIndex(context)]; }

  Entry* find(const OtaRxLedgerContext& context) {
    auto& bucket = bucketFor(context);
    for (auto& e : bucket) {
      if (e.context.equals(context)) return &e;
    }
    return nullptr;
  }

  std::vector<Entry> buckets_[kBucketCount];
  size_t peerCount_ = 0;
  size_t groupCount_ = 0;
};

}  // namespace

TEST(OtaSequenceBackingPort, ContextEqualityIsFullByteNeverKindCrossed) {
  const auto peerA = makeFullPeerContext(1);
  const auto peerB = makeFullPeerContext(1);
  const auto peerC = makeFullPeerContext(2);
  EXPECT_TRUE(peerA.equals(peerB));
  EXPECT_FALSE(peerA.equals(peerC));
  const auto groupA = makeFullGroupContext(1);
  EXPECT_FALSE(peerA.equals(groupA));  // different Kind must never compare equal.
}

TEST(OtaSequenceBackingPort, UnwiredDefaultCommissioningAuthoritiesAlwaysDenyNeverInferPermissionFromAbsence) {
  // The concrete safe-default bases must NEVER treat "no real authority
  // wired" as implicit permission to commission -- blank/Missing alone
  // is never proof of virginity; an unwired default must deny.
  ITxSequenceCommissioningAuthority defaultTxAuthority;
  EXPECT_FALSE(defaultTxAuthority.commissionVirginTx(1));
  EXPECT_FALSE(defaultTxAuthority.commissionVirginTx(64));

  IRxSequenceCommissioningAuthority defaultRxAuthority;
  EXPECT_FALSE(defaultRxAuthority.commissionVirginRx(makeFullPeerContext(1), 1));
  EXPECT_FALSE(defaultRxAuthority.commissionVirginRx(makeFullGroupContext(1), 1));
}

TEST(OtaBackedTxSequenceAllocator, MissingBackingFailsClosedPermanently) {
  FakeControllableTxBackingStore backing;
  backing.nextOpenResult = OtaSequenceBackingResult::Missing;  // never silently commissions.
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t seq = 0;
  EXPECT_FALSE(allocator.allocate(&seq));
  EXPECT_TRUE(allocator.isDisabled());
  EXPECT_FALSE(allocator.allocate(&seq));  // stays disabled, no "recovery".
  EXPECT_EQ(1, backing.openCalls);         // never retried once disabled.
}

TEST(OtaBackedTxSequenceAllocator, WouldBlockOnOpenIsTransientNotPermanentlyDisabling) {
  FakeControllableTxBackingStore backing;
  backing.nextOpenResult = OtaSequenceBackingResult::WouldBlock;
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t seq = 0;
  EXPECT_FALSE(allocator.allocate(&seq));
  EXPECT_FALSE(allocator.isDisabled());
  backing.nextOpenResult = OtaSequenceBackingResult::Committed;
  backing.counter = 1;  // 0 is never a valid durable value -- preseed a positive already-commissioned counter.
  ASSERT_TRUE(allocator.allocate(&seq));  // now succeeds: proves WouldBlock never permanently disabled it.
  EXPECT_EQ(2u, seq);  // sequence 1 is already claimed by the preseeded commissioning value.
}

TEST(OtaBackedTxSequenceAllocator, ConflictOnOpenIsTransientNotPermanentlyDisabling) {
  // The abstract port permits Conflict from openExisting()/readCounter()
  // too (e.g. a future immutable-snapshot read racing a compaction) --
  // every non-Committed, non-permanent-fault result must be treated
  // identically to WouldBlock at every site, not just a hardcoded
  // WouldBlock check.
  FakeControllableTxBackingStore backing;
  backing.nextOpenResult = OtaSequenceBackingResult::Conflict;
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t seq = 0;
  EXPECT_FALSE(allocator.allocate(&seq));
  EXPECT_FALSE(allocator.isDisabled());
  backing.nextOpenResult = OtaSequenceBackingResult::Committed;
  backing.counter = 1;  // 0 is never a valid durable value -- preseed a positive already-commissioned counter.
  ASSERT_TRUE(allocator.allocate(&seq));  // proves Conflict-on-open never permanently disabled it.
  EXPECT_EQ(2u, seq);  // sequence 1 is already claimed by the preseeded commissioning value.
}

TEST(OtaBackedTxSequenceAllocator, ConflictOnInitialReadIsTransientNotPermanentlyDisabling) {
  FakeControllableTxBackingStore backing;
  backing.nextReadResult = OtaSequenceBackingResult::Conflict;
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t seq = 0;
  EXPECT_FALSE(allocator.allocate(&seq));
  EXPECT_FALSE(allocator.isDisabled());
  backing.nextReadResult = OtaSequenceBackingResult::Committed;
  backing.counter = 1;  // 0 is never a valid durable value -- preseed a positive already-commissioned counter.
  ASSERT_TRUE(allocator.allocate(&seq));
  EXPECT_EQ(2u, seq);  // sequence 1 is already claimed by the preseeded commissioning value.
}

TEST(OtaBackedTxSequenceAllocator, WouldBlockOnReserveIsTransientAndSequenceStillNeverRepeats) {
  FakeControllableTxBackingStore backing;
  backing.counter = 1;  // 0 is never a valid durable value -- preseed a positive already-commissioned counter.
  OtaBackedTxSequenceAllocator allocator(backing, /*blockSize=*/4);
  uint32_t seq = 0;
  for (int i = 0; i < 4; ++i) ASSERT_TRUE(allocator.allocate(&seq));
  EXPECT_EQ(5u, seq);  // sequence 1 already claimed by the preseeded commissioning value.
  backing.nextReserveResult = OtaSequenceBackingResult::WouldBlock;
  EXPECT_FALSE(allocator.allocate(&seq));
  EXPECT_FALSE(allocator.isDisabled());
  backing.nextReserveResult = OtaSequenceBackingResult::Committed;
  ASSERT_TRUE(allocator.allocate(&seq));
  EXPECT_EQ(6u, seq);  // never repeats/skips due to the transient WouldBlock.
}

TEST(OtaBackedTxSequenceAllocator, UncertainReserveDisablesPermanentlyUntilFreshReconstruction) {
  FakeControllableTxBackingStore backing;
  backing.counter = 1;  // 0 is never a valid durable value -- preseed a positive already-commissioned counter.
  {
    OtaBackedTxSequenceAllocator allocator(backing, /*blockSize=*/4);
    uint32_t seq = 0;
    ASSERT_TRUE(allocator.allocate(&seq));
    backing.nextReserveResult = OtaSequenceBackingResult::Uncertain;
    for (int i = 0; i < 3; ++i) ASSERT_TRUE(allocator.allocate(&seq));  // exhausts the first block of 4.
    EXPECT_FALSE(allocator.allocate(&seq));                             // 5th needs a new block: Uncertain.
    EXPECT_TRUE(allocator.isDisabled());
    EXPECT_FALSE(allocator.allocate(&seq));  // stays disabled: same instance never self-heals.
  }
  // Fresh reconstruction against the SAME backing re-derives the actual
  // durable truth rather than trusting the disabled instance's RAM.
  backing.nextReserveResult = OtaSequenceBackingResult::Committed;
  OtaBackedTxSequenceAllocator reconstructed(backing);
  uint32_t seq = 0;
  ASSERT_TRUE(reconstructed.allocate(&seq));
  EXPECT_GT(seq, 5u);  // never repeats anything from [1,5] (1 was the preseeded commissioning claim).
}

TEST(OtaBackedRxReplayLedger, MissingBackingFailsClosedPermanently) {
  FakeControllableRxBackingStore backing;
  backing.nextOpenResult = OtaSequenceBackingResult::Missing;
  OtaBackedRxReplayLedger ledger(backing, makeFullPeerContext(1));
  EXPECT_FALSE(ledger.admit(1));
  EXPECT_TRUE(ledger.isDisabled());
  EXPECT_FALSE(ledger.admit(2));
}

TEST(OtaBackedRxReplayLedger, WouldBlockOnLoadIsTransientNotPermanentlyDisabling) {
  FakeControllableRxBackingStore backing;
  backing.nextOpenResult = OtaSequenceBackingResult::WouldBlock;
  OtaBackedRxReplayLedger ledger(backing, makeFullPeerContext(1));
  EXPECT_FALSE(ledger.admit(5));
  EXPECT_FALSE(ledger.isDisabled());
  backing.nextOpenResult = OtaSequenceBackingResult::Committed;
  backing.watermark = 1;  // 0 is never a valid durable value -- preseed a positive already-commissioned counter.
  ASSERT_TRUE(ledger.admit(5));
}

TEST(OtaBackedRxReplayLedger, ConflictOnLoadOpenIsTransientNotPermanentlyDisabling) {
  // Same broadening as the TX-side ConflictOnOpen test: the abstract
  // port permits Conflict here too, and it must be treated identically
  // to WouldBlock, never a hardcoded WouldBlock-only special case.
  FakeControllableRxBackingStore backing;
  backing.nextOpenResult = OtaSequenceBackingResult::Conflict;
  OtaBackedRxReplayLedger ledger(backing, makeFullPeerContext(1));
  EXPECT_FALSE(ledger.admit(5));
  EXPECT_FALSE(ledger.isDisabled());
  backing.nextOpenResult = OtaSequenceBackingResult::Committed;
  backing.watermark = 1;  // 0 is never a valid durable value -- preseed a positive already-commissioned counter.
  ASSERT_TRUE(ledger.admit(5));
}

TEST(OtaBackedRxReplayLedger, ConflictOnInitialReadIsTransientNotPermanentlyDisabling) {
  FakeControllableRxBackingStore backing;
  backing.nextReadResult = OtaSequenceBackingResult::Conflict;
  OtaBackedRxReplayLedger ledger(backing, makeFullPeerContext(1));
  EXPECT_FALSE(ledger.admit(5));
  EXPECT_FALSE(ledger.isDisabled());
  backing.nextReadResult = OtaSequenceBackingResult::Committed;
  backing.watermark = 1;  // 0 is never a valid durable value -- preseed a positive already-commissioned counter.
  ASSERT_TRUE(ledger.admit(5));
}

TEST(OtaBackedRxReplayLedger, ConflictRefreshesAndRetriesWithoutPermanentlyDisabling) {
  // Force exactly one Conflict on the FIRST underlying advance() call,
  // modeling the durable head having already moved (e.g. a previous
  // Uncertain call had actually landed, or -- for a real shared store --
  // another writer advanced it) by the time this attempt is issued.
  class OneShotConflictThenCommit : public FakeControllableRxBackingStore {
   public:
    OtaSequenceBackingResult advanceRx(const OtaRxLedgerContext& c, uint32_t expectedHead,
                                        uint32_t newHead) override {
      if (!firstAttempted) {
        firstAttempted = true;
        return OtaSequenceBackingResult::Conflict;
      }
      return FakeControllableRxBackingStore::advanceRx(c, expectedHead, newHead);
    }
    bool firstAttempted = false;
  };
  OneShotConflictThenCommit conflictBacking;
  conflictBacking.watermark = 10;  // load() sees this as the reboot floor.
  OtaBackedRxReplayLedger conflictLedger(conflictBacking, makeFullPeerContext(1));
  // Bump the backing's real watermark to 12 to model the concurrent
  // advance, so the refresh (readCounter) the ledger performs after the
  // Conflict observes it before the bounded single retry.
  conflictBacking.watermark = 12;
  EXPECT_TRUE(conflictLedger.admit(15));
  EXPECT_FALSE(conflictLedger.isDisabled());
}

TEST(OtaBackedRxReplayLedger, UncertainAdvanceDisablesPermanentlyEvenThoughBytesActuallyLanded) {
  BoundedMultiContextRxBackingStore backing;
  const auto ctx = makeFullPeerContext(7);
  ASSERT_TRUE(backing.commissionVirginRx(ctx, 1));  // sequence 1 marked already-seen at commissioning.
  {
    OtaBackedRxReplayLedger ledger(backing, ctx);
    ASSERT_TRUE(ledger.admit(2));
    backing.forceUncertainOnceForNextAdvance = true;
    EXPECT_FALSE(ledger.admit(3));  // durable write actually applies, but the caller sees Uncertain.
    EXPECT_TRUE(ledger.isDisabled());
    EXPECT_FALSE(ledger.admit(4));  // stays disabled: no self-healing within this instance.
  }
  // Fresh reconstruction against the SAME real backing sees the ACTUAL
  // durable truth (watermark really did advance to 3), not a fake
  // sentinel -- 3 must be rejected as already-admitted, and only 4+ is
  // genuinely new.
  OtaBackedRxReplayLedger reconstructed(backing, ctx);
  EXPECT_FALSE(reconstructed.admit(1));
  EXPECT_FALSE(reconstructed.admit(3));
  EXPECT_TRUE(reconstructed.admit(4));
}

TEST(BoundedMultiContextRxBackingStore, ThreeHundredFiftyFullPeerContextsWithDeliberatelyCollidingHashRemainDistinct) {
  BoundedMultiContextRxBackingStore backing;
  std::vector<OtaRxLedgerContext> contexts;
  contexts.reserve(BoundedMultiContextRxBackingStore::kMaxPeerContexts);
  for (uint16_t i = 0; i < BoundedMultiContextRxBackingStore::kMaxPeerContexts; ++i) {
    contexts.push_back(makeFullPeerContext(i));
    ASSERT_TRUE(backing.commissionVirginRx(contexts.back(), 1)) << "context " << i;
  }
  // Every one of the 350 contexts admits its OWN independent sequence
  // stream without any cross-contamination, despite the backing's
  // deliberately tiny (8-bucket) hash index guaranteeing many real
  // collisions among 350 distinct full identities.
  std::vector<OtaBackedRxReplayLedger> ledgers;
  ledgers.reserve(contexts.size());
  for (auto& c : contexts) ledgers.emplace_back(backing, c);
  for (size_t i = 0; i < ledgers.size(); ++i) {
    EXPECT_TRUE(ledgers[i].admit(static_cast<uint32_t>(100 + i))) << i;
  }
  // Each context's OWN durable watermark must be EXACTLY its own
  // admitted value, never a colliding-bucket neighbor's -- proves the
  // deliberately-weak 8-bucket hash index never leaks/aliases state
  // across the 350 distinct full identities that hash into it.
  for (size_t i = 0; i < contexts.size(); ++i) {
    uint32_t watermark = 0;
    ASSERT_EQ(OtaSequenceBackingResult::Committed, backing.readCounter(contexts[i], watermark)) << i;
    EXPECT_EQ(static_cast<uint32_t>(100 + i), watermark) << i;
  }
  // Exact replay of a context's own just-admitted sequence is rejected.
  for (size_t i = 0; i < ledgers.size(); ++i) {
    EXPECT_FALSE(ledgers[i].admit(static_cast<uint32_t>(100 + i))) << i;
  }
}


TEST(BoundedMultiContextRxBackingStore, FourActiveGroupContextsBoundedSeparatelyFromPeerCapacity) {
  BoundedMultiContextRxBackingStore backing;
  for (uint16_t i = 0; i < BoundedMultiContextRxBackingStore::kMaxGroupContexts; ++i) {
    ASSERT_TRUE(backing.commissionVirginRx(makeFullGroupContext(i), 1)) << i;
  }
  EXPECT_FALSE(backing.commissionVirginRx(makeFullGroupContext(999), 1));  // 5th group: capacity denied.
  // Peer capacity is untouched by group capacity being exhausted.
  EXPECT_TRUE(backing.commissionVirginRx(makeFullPeerContext(1), 1));
}

TEST(BoundedMultiContextRxBackingStore, CapacityDenialAtThreeHundredFiftyFirstPeerContext) {
  BoundedMultiContextRxBackingStore backing;
  for (uint16_t i = 0; i < BoundedMultiContextRxBackingStore::kMaxPeerContexts; ++i) {
    ASSERT_TRUE(backing.commissionVirginRx(makeFullPeerContext(i), 1)) << i;
  }
  EXPECT_FALSE(backing.commissionVirginRx(makeFullPeerContext(9999), 1));  // 351st: denied, never silently evicts.
  // Every previously-commissioned context is still fully intact/usable.
  OtaBackedRxReplayLedger ledger(backing, makeFullPeerContext(0));
  EXPECT_TRUE(ledger.admit(2));
}

TEST(BoundedMultiContextRxBackingStore, DelayedConstructionAndColdReconstructionAcrossManyContexts) {
  BoundedMultiContextRxBackingStore backing;
  const auto ctxA = makeFullPeerContext(11);
  const auto ctxB = makeFullGroupContext(2);
  ASSERT_TRUE(backing.commissionVirginRx(ctxA, 1));
  ASSERT_TRUE(backing.commissionVirginRx(ctxB, 1));
  {
    OtaBackedRxReplayLedger ledgerA(backing, ctxA);
    ASSERT_TRUE(ledgerA.admit(2));
    ASSERT_TRUE(ledgerA.admit(3));
  }  // ledgerA destroyed: only the shared backing's durable state survives.
  // Delayed construction: ctxB's very first ledger wrapper is only
  // constructed now, long after ctxA already transacted.
  OtaBackedRxReplayLedger ledgerB(backing, ctxB);
  ASSERT_TRUE(ledgerB.admit(2));
  // Cold reconstruction of ctxA: a brand new wrapper independently
  // re-derives the exact same durable truth (rejects 2 and 3, accepts
  // 4), proving no per-instance RAM was ever the source of truth.
  OtaBackedRxReplayLedger reconstructedA(backing, ctxA);
  EXPECT_FALSE(reconstructedA.admit(2));
  EXPECT_FALSE(reconstructedA.admit(3));
  EXPECT_TRUE(reconstructedA.admit(4));
  // ctxB's independent state was never perturbed by ctxA's activity.
  OtaBackedRxReplayLedger reconstructedB(backing, ctxB);
  EXPECT_FALSE(reconstructedB.admit(2));
  EXPECT_TRUE(reconstructedB.admit(3));
}

// ---------------------------------------------------------------------
// Flash-backed reference adapters (OtaFlashSequenceBackingAdapters.h):
// proves the store-agnostic port/ledgers reproduce the SAME durable
// behavior as the existing, already fully-tested OtaTxSequenceAllocator
// / OtaRxReplayLedger classes when bridged over the identical physical
// 2-sector journal -- and that commissioning is reachable ONLY through
// the separate one-use authority, never an implicit ctor flag.
// ---------------------------------------------------------------------
TEST(FlashTxSequenceBackingStore, RegularApiRefusesUntilIndependentlyCommissionedRecordExists) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  FlashTxSequenceBackingStore store(region);
  OtaBackedTxSequenceAllocator allocator(store);
  uint32_t seq = 0;
  EXPECT_FALSE(allocator.allocate(&seq));  // blank/never-commissioned: regular API never silently bootstraps.
  EXPECT_TRUE(allocator.isDisabled());

  // Explicitly-authorized test setup: preseed a genuinely-commissioned
  // starting record directly via the existing, already-proven
  // OtaTxSequenceLedgerRecord::reserve() primitive -- NOT via any
  // "authority" method on the reference adapter itself (this adapter
  // deliberately implements no such role; see its header comment).
  // Minimal-waste commissioning (mirrors the RX side's "sequence 1
  // already seen" convention): marks upper bound 1 as already reserved,
  // so the reconstructed allocator's very first real allocate() call
  // reserves a brand new block starting at 2 -- exactly the SAME
  // "skip whatever the ledger cannot prove is unused" discipline
  // OtaTxSequenceAllocator already applies on every ordinary reboot.
  ASSERT_TRUE(OtaTxSequenceLedgerRecord::reserve(region, 1));
  FlashTxSequenceBackingStore freshStore(region);  // separate instance: the disabled one never "recovers".
  OtaBackedTxSequenceAllocator reconstructed(freshStore);
  ASSERT_TRUE(reconstructed.allocate(&seq));
  EXPECT_EQ(2u, seq);
  ASSERT_TRUE(reconstructed.allocate(&seq));
  EXPECT_EQ(3u, seq);
}

TEST(FlashTxSequenceBackingStore, CorruptRecordFailsClosedEvenAfterExternalPreseeding) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  ASSERT_TRUE(OtaTxSequenceLedgerRecord::reserve(region, 1));
  FlashTxSequenceBackingStore store(region);
  ASSERT_EQ(OtaSequenceBackingResult::Committed, store.openExisting());  // genuinely commissioned: opens fine.

  ota::test::FakeNorFlash corruptFlash(kLedgerRegionBytes, kLedgerEraseUnit);
  uint8_t garbage[kLedgerEraseUnit];
  memset(garbage, 0x42, sizeof(garbage));
  ASSERT_TRUE(ota::platform::isOk(corruptFlash.program(0, garbage, sizeof(garbage))));
  ota::platform::FlashRegion corruptRegion(corruptFlash, 0, kLedgerRegionBytes);
  FlashTxSequenceBackingStore corruptStore(corruptRegion);
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, corruptStore.openExisting());  // corrupt: never treated as blank.
}

TEST(FlashRxSequenceBackingStore, OwnershipDeniedForMismatchedContextEvenIfBoundIdentityIsCommissioned) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  const auto boundCtx = makeFullPeerContext(1);
  const auto otherCtx = makeFullPeerContext(2);
  // Explicitly-authorized test setup via the existing reference
  // primitive (see FlashRxSequenceBackingStore header comment) --
  // never a fake "authority" method on the reference adapter itself.
  ASSERT_TRUE(OtaRxReplayLedgerRecord::advance(region, 1));
  FlashRxSequenceBackingStore store(region, boundCtx);
  ASSERT_EQ(OtaSequenceBackingResult::Committed, store.openExisting(boundCtx));
  uint32_t watermark = 0;
  EXPECT_EQ(OtaSequenceBackingResult::OwnershipDenied, store.readCounter(otherCtx, watermark));
  EXPECT_EQ(OtaSequenceBackingResult::Committed, store.readCounter(boundCtx, watermark));
}

TEST(FlashRxSequenceBackingStore, RegularApiRefusesUntilIndependentlyCommissionedRecordExistsThenBehavesLikeReference) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  const auto ctx = makeFullPeerContext(3);
  FlashRxSequenceBackingStore store(region, ctx);
  OtaBackedRxReplayLedger ledger(store, ctx);
  EXPECT_FALSE(ledger.admit(5));
  EXPECT_TRUE(ledger.isDisabled());

  // Explicitly-authorized test setup: sequence 1 marked already-seen,
  // via the existing reference primitive directly.
  ASSERT_TRUE(OtaRxReplayLedgerRecord::advance(region, 1));
  FlashRxSequenceBackingStore freshStore(region, ctx);
  OtaBackedRxReplayLedger reconstructed(freshStore, ctx);
  EXPECT_FALSE(reconstructed.admit(1));
  ASSERT_TRUE(reconstructed.admit(2));
  EXPECT_FALSE(reconstructed.admit(2));

  // Reboot: brand new store+ledger over the SAME region reproduces the
  // exact same durable watermark, exactly like OtaRxReplayLedger's own
  // reboot behavior.
  FlashRxSequenceBackingStore rebooted(region, ctx);
  OtaBackedRxReplayLedger rebootedLedger(rebooted, ctx);
  EXPECT_FALSE(rebootedLedger.admit(2));
  ASSERT_TRUE(rebootedLedger.admit(3));
}

TEST(FlashTxSequenceBackingStore, SecondAdapterInstanceOverSameRegionIsSeenAsGenuineConflictNotSpuriousUncertain) {
  // Root port-correctness fix: readCounter()/reserveTx() must compare
  // against the ACTUAL current durable journal, not one adapter
  // instance's private cache. Two independent FlashTxSequenceBackingStore
  // instances taking turns over the SAME FlashRegion (e.g. two
  // allocators, or the same allocator reconstructed mid-sequence) must
  // never spuriously disable each other with Uncertain -- a stale
  // cache must surface as a transient Conflict that a fresh refresh
  // resolves, exactly like the in-memory GenuineSharedTxBackingStore
  // test double already proves for the abstract port.
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  ASSERT_TRUE(OtaTxSequenceLedgerRecord::reserve(region, 64));  // explicitly-authorized test commissioning.

  FlashTxSequenceBackingStore storeA(region);
  OtaBackedTxSequenceAllocator allocatorA(storeA);
  uint32_t seq = 0;
  ASSERT_TRUE(allocatorA.allocate(&seq));  // opens at actual 64, reserves [65..128].
  EXPECT_EQ(65u, seq);
  for (uint32_t i = 66; i <= 128; ++i) {
    ASSERT_TRUE(allocatorA.allocate(&seq)) << i;
    EXPECT_EQ(i, seq);
  }  // A has now fully drained its own [65..128] block.

  FlashTxSequenceBackingStore storeB(region);
  OtaBackedTxSequenceAllocator allocatorB(storeB);
  ASSERT_TRUE(allocatorB.allocate(&seq));  // opens fresh, sees ACTUAL 128, reserves [129..192].
  EXPECT_EQ(129u, seq);
  for (uint32_t i = 130; i <= 192; ++i) {
    ASSERT_TRUE(allocatorB.allocate(&seq)) << i;
    EXPECT_EQ(i, seq);
  }  // B has now fully drained its own [129..192] block.

  // A's cached upper bound is still the stale 128 -- its next allocate()
  // must refresh against the ACTUAL durable 192 (never Uncertain/
  // permanently disable) and own a brand-new [193..256] block.
  ASSERT_TRUE(allocatorA.allocate(&seq));
  EXPECT_FALSE(allocatorA.isDisabled());
  EXPECT_EQ(193u, seq);
  for (uint32_t i = 194; i <= 256; ++i) {
    ASSERT_TRUE(allocatorA.allocate(&seq)) << i;
    EXPECT_EQ(i, seq);
  }
  EXPECT_FALSE(allocatorB.isDisabled());
}

TEST(FlashRxSequenceBackingStore, SecondAdapterInstanceOverSameRegionActuallyAdvancingIsObservedNotStaleCache) {
  // RX mirror of the TX case above: a second FlashRxSequenceBackingStore
  // bound to the SAME context/region durably advancing the watermark
  // must be genuinely observed on refresh (closing the now-external
  // window) rather than trusted from a stale cache -- and a rejection
  // due to that external advance must never permanently disable the
  // ledger.
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  const auto ctx = makeFullPeerContext(7);
  ASSERT_TRUE(OtaRxReplayLedgerRecord::advance(region, 5));  // explicitly-authorized test commissioning.

  FlashRxSequenceBackingStore storeA(region, ctx);
  OtaBackedRxReplayLedger ledgerA(storeA, ctx);
  ASSERT_TRUE(ledgerA.load());  // A's cached/known watermark is 5.

  FlashRxSequenceBackingStore storeB(region, ctx);
  OtaBackedRxReplayLedger ledgerB(storeB, ctx);
  ASSERT_TRUE(ledgerB.admit(10));  // B independently, durably advances the ACTUAL watermark to 10.

  // A's stale cache still says 5: sequence 7 falls inside the window B
  // already closed -- must be rejected, but NEVER by disabling A.
  EXPECT_FALSE(ledgerA.admit(7));
  EXPECT_FALSE(ledgerA.isDisabled());

  // Past the now-actual watermark, A resumes normal admission correctly.
  EXPECT_TRUE(ledgerA.admit(11));
}

TEST(FlashTxSequenceBackingStore, PostOpenReadFailureIsCorruptAndLeavesOutParamUntouchedNeverCachedCommitted) {
  // One case covering BOTH the read-only path (readCounter()) and the
  // mutation path (reserveTx()): a genuine read failure on the journal
  // AFTER a successful open+warm-read must surface as Corrupt with the
  // out-param left exactly as the caller passed it in -- never a
  // stale/cached success.
  for (int variant = 0; variant < 2; ++variant) {
    ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
    ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
    ASSERT_TRUE(OtaTxSequenceLedgerRecord::reserve(region, 64));  // explicitly-authorized test commissioning.

    FlashTxSequenceBackingStore store(region);
    ASSERT_EQ(OtaSequenceBackingResult::Committed, store.openExisting()) << variant;
    uint32_t warm = 0;
    ASSERT_EQ(OtaSequenceBackingResult::Committed, store.readCounter(warm)) << variant;
    ASSERT_EQ(64u, warm) << variant;

    // Inject a genuine failure on the NEXT journal read -- models either
    // a damaged newest-record CRC or a transient IoError.
    flash.armFault({ota::test::FakeNorFlash::OpKind::Read,
                    ota::test::FakeNorFlash::InjectionTiming::Before, flash.readOpCount() + 1, 0});

    uint32_t out = 0xDEADBEEFu;
    if (variant == 0) {
      EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.readCounter(out)) << variant;
    } else {
      EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.reserveTx(64, 64, out)) << variant;
    }
    EXPECT_EQ(0xDEADBEEFu, out) << variant;  // out-param left untouched, never a stale success value.
  }
}

TEST(FlashRxSequenceBackingStore, PostOpenReadFailureIsCorruptAndLeavesOutParamUntouchedNeverCachedCommitted) {
  for (int variant = 0; variant < 2; ++variant) {
    ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
    ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
    const auto ctx = makeFullPeerContext(7);
    ASSERT_TRUE(OtaRxReplayLedgerRecord::advance(region, 5));  // explicitly-authorized test commissioning.

    FlashRxSequenceBackingStore store(region, ctx);
    ASSERT_EQ(OtaSequenceBackingResult::Committed, store.openExisting(ctx)) << variant;
    uint32_t warm = 0;
    ASSERT_EQ(OtaSequenceBackingResult::Committed, store.readCounter(ctx, warm)) << variant;
    ASSERT_EQ(5u, warm) << variant;

    flash.armFault({ota::test::FakeNorFlash::OpKind::Read,
                    ota::test::FakeNorFlash::InjectionTiming::Before, flash.readOpCount() + 1, 0});

    if (variant == 0) {
      uint32_t out = 0xDEADBEEFu;
      EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.readCounter(ctx, out)) << variant;
      EXPECT_EQ(0xDEADBEEFu, out) << variant;
    } else {
      EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.advanceRx(ctx, 5, 7)) << variant;
    }
  }
}

TEST(FlashTxSequenceBackingStore, RecordGoingBlankAfterSuccessfulOpenIsCorruptNeverSilentRebootstrap) {
  // A record that reads back blank AFTER this instance already
  // successfully opened it (e.g. both sectors erased by some other
  // path) must be reported Corrupt, never treated as a fresh/virgin
  // Missing that would let a lost identity silently rebootstrap.
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  ASSERT_TRUE(OtaTxSequenceLedgerRecord::reserve(region, 64));

  FlashTxSequenceBackingStore store(region);
  ASSERT_EQ(OtaSequenceBackingResult::Committed, store.openExisting());

  // Erase both journal sectors directly -- simulates the durable record
  // going blank out from under this already-opened instance.
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(0)));
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(kLedgerEraseUnit)));

  uint32_t out = 0xDEADBEEFu;
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.readCounter(out));
  EXPECT_EQ(0xDEADBEEFu, out);
}

TEST(FlashRxSequenceBackingStore, RecordGoingBlankAfterSuccessfulOpenIsCorruptNeverSilentRebootstrap) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  const auto ctx = makeFullPeerContext(7);
  ASSERT_TRUE(OtaRxReplayLedgerRecord::advance(region, 5));

  FlashRxSequenceBackingStore store(region, ctx);
  ASSERT_EQ(OtaSequenceBackingResult::Committed, store.openExisting(ctx));

  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(0)));
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(kLedgerEraseUnit)));

  uint32_t out = 0xDEADBEEFu;
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.readCounter(ctx, out));
  EXPECT_EQ(0xDEADBEEFu, out);
}

TEST(FlashTxSequenceBackingStore, DurableHeadRegressingBelowPreviouslyObservedValueIsCorruptNeverTrustedFresh) {
  // The private cache is not dead weight kept only for its own sake: it
  // is the known-durable-floor guard that catches a lower-but-
  // otherwise-valid-looking record (rollback/corruption) that this
  // instance must never trust as a legitimate fresh state.
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  ASSERT_TRUE(OtaTxSequenceLedgerRecord::reserve(region, 64));

  FlashTxSequenceBackingStore store(region);
  ASSERT_EQ(OtaSequenceBackingResult::Committed, store.openExisting());
  uint32_t warm = 0;
  ASSERT_EQ(OtaSequenceBackingResult::Committed, store.readCounter(warm));
  ASSERT_EQ(64u, warm);

  // Directly overwrite the holding slot with a structurally-valid but
  // LOWER record -- models raw corruption/rollback bypassing the
  // journal's own strictly-increasing reserve() invariant.
  uint8_t record[OtaTxSequenceLedgerRecord::kRecordBytes];
  ASSERT_EQ(OtaTxSequenceLedgerRecord::serialize(30, record, sizeof(record)), sizeof(record));
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(0)));
  ASSERT_TRUE(ota::platform::isOk(region.program(0, record, sizeof(record))));

  // Read path (this SAME instance is still `opened_` from its earlier
  // legitimate open): must refuse, out-param untouched.
  uint32_t out = 0xDEADBEEFu;
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.readCounter(out));
  EXPECT_EQ(0xDEADBEEFu, out);

  // Mutation path against the same regressed physical state: must also
  // refuse, never silently reserve a block rooted below the known floor.
  uint32_t reserved = 0xDEADBEEFu;
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.reserveTx(30, 64, reserved));
  EXPECT_EQ(0xDEADBEEFu, reserved);

  // openExisting() itself -- an explicit reopen of the SAME instance --
  // must ALSO catch the regression (not just readCounter/reserveTx).
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.openExisting());

  // A record gone fully blank after a known-positive floor is the SAME
  // kind of regression (0 is always < any known-positive floor) --
  // never re-Missing/rebootstrap it via openExisting() either.
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(0)));
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(kLedgerEraseUnit)));
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.openExisting());

  // The known floor (64) must have been PRESERVED across all of the
  // above failed reopen/read/mutation attempts -- never lowered to 30,
  // 0, or anything else observed only transiently during the fault.
  // Prove it precisely: a value between the corrupted low (30) and the
  // true floor (64) must STILL be rejected...
  ASSERT_EQ(OtaTxSequenceLedgerRecord::serialize(50, record, sizeof(record)), sizeof(record));
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(0)));
  ASSERT_TRUE(ota::platform::isOk(region.program(0, record, sizeof(record))));
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.openExisting());

  // ...while a value genuinely AT/ABOVE the retained floor is correctly
  // accepted and resumes normal operation.
  ASSERT_EQ(OtaTxSequenceLedgerRecord::serialize(100, record, sizeof(record)), sizeof(record));
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(0)));
  ASSERT_TRUE(ota::platform::isOk(region.program(0, record, sizeof(record))));
  EXPECT_EQ(OtaSequenceBackingResult::Committed, store.openExisting());
  uint32_t resumed = 0;
  EXPECT_EQ(OtaSequenceBackingResult::Committed, store.readCounter(resumed));
  EXPECT_EQ(100u, resumed);
}

TEST(FlashRxSequenceBackingStore, DurableHeadRegressingBelowPreviouslyObservedValueIsCorruptNeverTrustedFresh) {
  ota::test::FakeNorFlash flash(kLedgerRegionBytes, kLedgerEraseUnit);
  ota::platform::FlashRegion region(flash, 0, kLedgerRegionBytes);
  const auto ctx = makeFullPeerContext(7);
  ASSERT_TRUE(OtaRxReplayLedgerRecord::advance(region, 64));

  FlashRxSequenceBackingStore store(region, ctx);
  ASSERT_EQ(OtaSequenceBackingResult::Committed, store.openExisting(ctx));
  uint32_t warm = 0;
  ASSERT_EQ(OtaSequenceBackingResult::Committed, store.readCounter(ctx, warm));
  ASSERT_EQ(64u, warm);

  uint8_t record[OtaRxReplayLedgerRecord::kRecordBytes];
  ASSERT_EQ(OtaRxReplayLedgerRecord::serialize(30, record, sizeof(record)), sizeof(record));
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(0)));
  ASSERT_TRUE(ota::platform::isOk(region.program(0, record, sizeof(record))));

  uint32_t out = 0xDEADBEEFu;
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.readCounter(ctx, out));
  EXPECT_EQ(0xDEADBEEFu, out);

  // Mutation path against the same regressed physical state.
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.advanceRx(ctx, 30, 31));

  // openExisting() itself must ALSO catch the regression.
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.openExisting(ctx));

  // Fully blank after a known-positive floor: same regression class.
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(0)));
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(kLedgerEraseUnit)));
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.openExisting(ctx));

  // The known floor (64) must have been PRESERVED across all of the
  // above -- a value between the corrupted low (30) and the true floor
  // must STILL be rejected...
  ASSERT_EQ(OtaRxReplayLedgerRecord::serialize(50, record, sizeof(record)), sizeof(record));
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(0)));
  ASSERT_TRUE(ota::platform::isOk(region.program(0, record, sizeof(record))));
  EXPECT_EQ(OtaSequenceBackingResult::Corrupt, store.openExisting(ctx));

  // ...while a value genuinely AT/ABOVE the retained floor resumes
  // normal operation correctly.
  ASSERT_EQ(OtaRxReplayLedgerRecord::serialize(100, record, sizeof(record)), sizeof(record));
  ASSERT_TRUE(ota::platform::isOk(region.eraseSector(0)));
  ASSERT_TRUE(ota::platform::isOk(region.program(0, record, sizeof(record))));
  EXPECT_EQ(OtaSequenceBackingResult::Committed, store.openExisting(ctx));
  uint32_t resumed = 0;
  EXPECT_EQ(OtaSequenceBackingResult::Committed, store.readCounter(ctx, resumed));
  EXPECT_EQ(100u, resumed);
}

TEST(OtaBackedTxSequenceAllocator, ExhaustedColdCounterNeverEmitsZero) {
  FakeControllableTxBackingStore backing;
  backing.counter = UINT32_MAX;
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t sequence = 0x12345678;
  EXPECT_FALSE(allocator.allocate(&sequence));
  EXPECT_EQ(0x12345678u, sequence);
}

TEST(OtaBackedTxSequenceAllocator, ReadBackpressureNeverPermanentlyDisables) {
  FakeControllableTxBackingStore backing;
  backing.counter = 64;
  backing.nextReadResult = OtaSequenceBackingResult::WouldBlock;
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t sequence = 0x12345678;
  EXPECT_FALSE(allocator.allocate(&sequence));
  EXPECT_FALSE(allocator.isDisabled());
  EXPECT_EQ(0x12345678u, sequence);
  backing.nextReadResult = OtaSequenceBackingResult::Committed;
  ASSERT_TRUE(allocator.allocate(&sequence));
  EXPECT_EQ(65u, sequence);
}

TEST(OtaBackedTxSequenceAllocator, ReservationConflictNeverPermanentlyDisables) {
  FakeControllableTxBackingStore backing;
  backing.counter = 64;
  backing.nextReserveResult = OtaSequenceBackingResult::Conflict;
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t sequence = 0x12345678;
  EXPECT_FALSE(allocator.allocate(&sequence));
  EXPECT_FALSE(allocator.isDisabled());
  EXPECT_EQ(0x12345678u, sequence);
  backing.nextReserveResult = OtaSequenceBackingResult::Committed;
  ASSERT_TRUE(allocator.allocate(&sequence));
  EXPECT_EQ(65u, sequence);
}

// A genuine (not canned-answer) CAS-enforcing shared backing: reserveTx()
// actually compares `expectedCurrentUpperBound` against its own live
// counter and returns real Conflict on mismatch, exactly as a future
// real shared store must. Used to prove the allocator's refresh+retry
// against an ACTUAL race, not a scripted fake result.
class GenuineSharedTxBackingStore : public ITxSequenceBackingStore {
 public:
  OtaSequenceBackingResult openExisting() override {
    opened_ = true;
    return counter == 0 ? OtaSequenceBackingResult::Missing : OtaSequenceBackingResult::Committed;
  }
  OtaSequenceBackingResult readCounter(uint32_t& outReservedUpperBound) override {
    if (!opened_) return OtaSequenceBackingResult::OwnershipDenied;
    outReservedUpperBound = counter;
    return OtaSequenceBackingResult::Committed;
  }
  OtaSequenceBackingResult reserveTx(uint32_t expectedCurrentUpperBound, uint32_t blockSize,
                                     uint32_t& outNewUpperBound) override {
    if (!opened_) return OtaSequenceBackingResult::OwnershipDenied;
    if (expectedCurrentUpperBound != counter) return OtaSequenceBackingResult::Conflict;
    if (blockSize == 0 || counter > (0xFFFFFFFFu - blockSize)) return OtaSequenceBackingResult::NoCapacity;
    counter += blockSize;
    outNewUpperBound = counter;
    return OtaSequenceBackingResult::Committed;
  }
  bool opened_ = false;
  uint32_t counter = 64;  // preseeded as already genuinely commissioned.
};

TEST(OtaBackedTxSequenceAllocator, TwoAllocatorsOverGenuineSharedCounterNeverOverlapAndSurviveExternalConflict) {
  GenuineSharedTxBackingStore shared;
  OtaBackedTxSequenceAllocator allocatorA(shared, 64);
  OtaBackedTxSequenceAllocator allocatorB(shared, 64);

  uint32_t seq = 0;
  ASSERT_TRUE(allocatorA.allocate(&seq));  // opens at counter=64, reserves [65..128].
  EXPECT_EQ(65u, seq);
  ASSERT_TRUE(allocatorB.allocate(&seq));  // opens fresh, sees counter=128, reserves [129..192].
  EXPECT_EQ(129u, seq);

  // Drain B's whole reserved block so its NEXT allocate() must reserve a
  // new one -- its cached upper bound is 192.
  for (uint32_t i = 130; i <= 192; ++i) {
    ASSERT_TRUE(allocatorB.allocate(&seq));
    EXPECT_EQ(i, seq);
  }

  OtaBackedTxSequenceAllocator allocatorC(shared, 64);
  uint32_t externallyIssued = 0;
  ASSERT_TRUE(allocatorC.allocate(&externallyIssued));
  EXPECT_EQ(193u, externallyIssued);
  EXPECT_EQ(256u, shared.counter);

  ASSERT_TRUE(allocatorB.allocate(&seq));
  EXPECT_FALSE(allocatorB.isDisabled());
  EXPECT_NE(externallyIssued, seq);
  EXPECT_EQ(257u, seq);

  for (uint32_t i = 66; i <= 128; ++i) {
    ASSERT_TRUE(allocatorA.allocate(&seq));
    EXPECT_EQ(i, seq);
  }
  ASSERT_TRUE(allocatorA.allocate(&seq));
  EXPECT_EQ(321u, seq);
}

TEST(OtaBackedTxSequenceAllocator, ReservationNearUint32MaxBoundaryFailsClosedWithoutWrapping) {
  GenuineSharedTxBackingStore shared;
  shared.counter = 0xFFFFFFFFu - 10u;  // only 10 values of room left; default block size is 64.
  OtaBackedTxSequenceAllocator allocator(shared);
  uint32_t seq = 0;
  EXPECT_FALSE(allocator.allocate(&seq));  // a full 64-block would overflow: fail closed, never wrap.
  EXPECT_TRUE(allocator.isDisabled());
  EXPECT_EQ(shared.counter, 0xFFFFFFFFu - 10u);  // the live counter was never mutated.
}

TEST(OtaBackedTxSequenceAllocator, ConflictRefreshThenTransientWouldBlockNeitherDisablesNorSkipsSequence) {
  // Force exactly one Conflict, then exactly one WouldBlock, on
  // successive reserveTx() calls before finally landing -- proving the
  // bounded single-refresh discipline composes correctly with ordinary
  // transient backpressure on the retried reservation itself.
  class ConflictThenWouldBlockThenCommit : public FakeControllableTxBackingStore {
   public:
    OtaSequenceBackingResult reserveTx(uint32_t expectedCurrentUpperBound, uint32_t blockSize,
                                       uint32_t& outNewUpperBound) override {
      ++attempts;
      if (attempts == 1) return OtaSequenceBackingResult::Conflict;
      if (attempts == 2) return OtaSequenceBackingResult::WouldBlock;
      return FakeControllableTxBackingStore::reserveTx(expectedCurrentUpperBound, blockSize, outNewUpperBound);
    }
    int attempts = 0;
  };
  ConflictThenWouldBlockThenCommit backing;
  backing.counter = 64;
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t sequence = 0;

  // First call: reserveTx() Conflicts; the bounded refresh (readCounter)
  // sees the SAME counter (64, nothing external actually moved), so the
  // retried reserveTx() is attempted immediately and hits WouldBlock.
  EXPECT_FALSE(allocator.allocate(&sequence));
  EXPECT_FALSE(allocator.isDisabled());

  // Second call: opened_/reservedUpperBound_ state is unchanged (65 is
  // still pending); reserveTx() is attempted a third time and lands.
  ASSERT_TRUE(allocator.allocate(&sequence));
  EXPECT_EQ(65u, sequence);
}

TEST(OtaBackedRxReplayLedger, ReadBackpressureNeverPermanentlyDisables) {
  FakeControllableRxBackingStore backing;
  backing.watermark = 10;
  backing.nextReadResult = OtaSequenceBackingResult::WouldBlock;
  OtaBackedRxReplayLedger ledger(backing, makeFullPeerContext(1));
  EXPECT_FALSE(ledger.load());
  EXPECT_FALSE(ledger.isDisabled());
  backing.nextReadResult = OtaSequenceBackingResult::Committed;
  ASSERT_TRUE(ledger.load());
  EXPECT_TRUE(ledger.admit(11));
}

TEST(OtaBackedRxReplayLedger, ExternalWatermarkAdvanceNeverReopensKnownOrUnknownAdmissions) {
  FakeControllableRxBackingStore backing;
  backing.watermark = 10;
  OtaBackedRxReplayLedger ledger(backing, makeFullPeerContext(1));
  ASSERT_TRUE(ledger.load());
  ASSERT_TRUE(ledger.admit(11));
  backing.watermark = 13;
  backing.nextAdvanceResult = OtaSequenceBackingResult::Conflict;
  EXPECT_FALSE(ledger.admit(12));
  EXPECT_FALSE(ledger.admit(11));
  EXPECT_FALSE(ledger.admit(13));
  EXPECT_FALSE(ledger.isDisabled());
  backing.nextAdvanceResult = OtaSequenceBackingResult::Committed;
  EXPECT_TRUE(ledger.admit(14));
}

TEST(OtaBackedTxSequenceAllocator, ConflictRefreshReadBackpressureNeverPermanentlyDisables) {
  class BackpressuredRefresh : public FakeControllableTxBackingStore {
   public:
    OtaSequenceBackingResult readCounter(uint32_t& outCounter) override {
      if (++attempts == 2) return OtaSequenceBackingResult::WouldBlock;
      return FakeControllableTxBackingStore::readCounter(outCounter);
    }
    uint32_t attempts = 0;
  };
  BackpressuredRefresh backing;
  backing.counter = 64;
  backing.nextReserveResult = OtaSequenceBackingResult::Conflict;
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t sequence = 0x12345678;
  EXPECT_FALSE(allocator.allocate(&sequence));
  EXPECT_FALSE(allocator.isDisabled());
  EXPECT_EQ(0x12345678u, sequence);
  backing.nextReserveResult = OtaSequenceBackingResult::Committed;
  ASSERT_TRUE(allocator.allocate(&sequence));
  EXPECT_EQ(65u, sequence);
}

TEST(OtaBackedRxReplayLedger, ConflictRefreshReadBackpressureNeverPermanentlyDisables) {
  class BackpressuredRefresh : public FakeControllableRxBackingStore {
   public:
    OtaSequenceBackingResult readCounter(const OtaRxLedgerContext& context,
                                        uint32_t& outCounter) override {
      if (++attempts == 2) return OtaSequenceBackingResult::WouldBlock;
      return FakeControllableRxBackingStore::readCounter(context, outCounter);
    }
    uint32_t attempts = 0;
  };
  BackpressuredRefresh backing;
  backing.watermark = 10;
  backing.nextAdvanceResult = OtaSequenceBackingResult::Conflict;
  OtaBackedRxReplayLedger ledger(backing, makeFullPeerContext(1));
  ASSERT_TRUE(ledger.load());
  EXPECT_FALSE(ledger.admit(11));
  EXPECT_FALSE(ledger.isDisabled());
  backing.nextAdvanceResult = OtaSequenceBackingResult::Committed;
  EXPECT_TRUE(ledger.admit(11));
}

TEST(OtaBackedTxSequenceAllocator, ConflictOnRefreshReadIsTransientNotPermanentlyDisabling) {
  // The refresh read triggered mid-Conflict-handling can itself return
  // Conflict from an abstract port (e.g. a snapshot read racing a
  // future compaction) -- must be treated exactly like WouldBlock here
  // too, not only the WouldBlock literal.
  class ConflictedRefresh : public FakeControllableTxBackingStore {
   public:
    OtaSequenceBackingResult readCounter(uint32_t& outCounter) override {
      if (++attempts == 2) return OtaSequenceBackingResult::Conflict;
      return FakeControllableTxBackingStore::readCounter(outCounter);
    }
    uint32_t attempts = 0;
  };
  ConflictedRefresh backing;
  backing.counter = 64;
  backing.nextReserveResult = OtaSequenceBackingResult::Conflict;
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t sequence = 0x12345678;
  EXPECT_FALSE(allocator.allocate(&sequence));
  EXPECT_FALSE(allocator.isDisabled());
  EXPECT_EQ(0x12345678u, sequence);
  backing.nextReserveResult = OtaSequenceBackingResult::Committed;
  ASSERT_TRUE(allocator.allocate(&sequence));
  EXPECT_EQ(65u, sequence);
}

TEST(OtaBackedRxReplayLedger, ConflictOnRefreshReadIsTransientNotPermanentlyDisabling) {
  class ConflictedRefresh : public FakeControllableRxBackingStore {
   public:
    OtaSequenceBackingResult readCounter(const OtaRxLedgerContext& context,
                                        uint32_t& outCounter) override {
      if (++attempts == 2) return OtaSequenceBackingResult::Conflict;
      return FakeControllableRxBackingStore::readCounter(context, outCounter);
    }
    uint32_t attempts = 0;
  };
  ConflictedRefresh backing;
  backing.watermark = 10;
  backing.nextAdvanceResult = OtaSequenceBackingResult::Conflict;
  OtaBackedRxReplayLedger ledger(backing, makeFullPeerContext(1));
  ASSERT_TRUE(ledger.load());
  EXPECT_FALSE(ledger.admit(11));
  EXPECT_FALSE(ledger.isDisabled());
  backing.nextAdvanceResult = OtaSequenceBackingResult::Committed;
  EXPECT_TRUE(ledger.admit(11));
}

TEST(OtaBackedTxSequenceAllocator, ConflictRefreshReportingLowerBoundThanAlreadyKnownDisablesRatherThanReopeningClaimedRange) {
  // A refresh reporting an upper bound LOWER than what this instance
  // already durably knows can only mean corruption/downgrade/a
  // malicious or buggy backing -- trusting it would imply a previously
  // reserved (exclusively-owned) range shrank, which is impossible for
  // an honest monotonic store. Must fail closed, never "reopen" it.
  class LyingLowerRefresh : public FakeControllableTxBackingStore {
   public:
    OtaSequenceBackingResult readCounter(uint32_t& outCounter) override {
      if (++attempts == 2) {
        // Reports a bound lower than the 64 already reserved below.
        outCounter = 32;
        return OtaSequenceBackingResult::Committed;
      }
      return FakeControllableTxBackingStore::readCounter(outCounter);
    }
    uint32_t attempts = 0;
  };
  LyingLowerRefresh backing;
  backing.counter = 1;  // 0 is never a valid durable value -- preseed a positive already-commissioned counter.
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t sequence = 0;
  ASSERT_TRUE(allocator.allocate(&sequence));  // reserves [2..65] (1 already claimed by commissioning).
  EXPECT_EQ(2u, sequence);
  for (uint32_t i = 3; i <= 65; ++i) {
    ASSERT_TRUE(allocator.allocate(&sequence));
    EXPECT_EQ(i, sequence);
  }
  backing.nextReserveResult = OtaSequenceBackingResult::Conflict;
  sequence = 0xAAAAAAAA;
  EXPECT_FALSE(allocator.allocate(&sequence));  // refresh reports 32 < known 65.
  EXPECT_TRUE(allocator.isDisabled());
  EXPECT_EQ(0xAAAAAAAAu, sequence);
  EXPECT_FALSE(allocator.allocate(&sequence));  // stays disabled, no "recovery".
}

TEST(OtaBackedRxReplayLedger, ConflictRefreshReportingLowerWatermarkThanAlreadyKnownDisablesRatherThanReopeningClosedHistory) {
  // Same rationale as the TX case, mirrored for RX: a refresh reporting
  // a watermark LOWER than already-known would silently reopen history
  // already treated as closed/consumed. Must fail closed, never trust it.
  class LyingLowerRefresh : public FakeControllableRxBackingStore {
   public:
    OtaSequenceBackingResult readCounter(const OtaRxLedgerContext& context,
                                        uint32_t& outCounter) override {
      if (++attempts == 2) {
        outCounter = 5;  // lower than the watermark(10) already known below.
        return OtaSequenceBackingResult::Committed;
      }
      return FakeControllableRxBackingStore::readCounter(context, outCounter);
    }
    uint32_t attempts = 0;
  };
  LyingLowerRefresh backing;
  backing.watermark = 10;
  OtaBackedRxReplayLedger ledger(backing, makeFullPeerContext(1));
  ASSERT_TRUE(ledger.load());
  backing.nextAdvanceResult = OtaSequenceBackingResult::Conflict;
  EXPECT_FALSE(ledger.admit(11));  // refresh reports 5 < known watermark 10.
  EXPECT_TRUE(ledger.isDisabled());
  EXPECT_FALSE(ledger.admit(11));  // stays disabled, no "recovery".
}

TEST(OtaBackedTxSequenceAllocator, CommittedZeroCounterNeverAuthorizesFirstUse) {
  FakeControllableTxBackingStore backing;
  backing.counter = 0;
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t sequence = 0x12345678;
  EXPECT_FALSE(allocator.allocate(&sequence));
  EXPECT_TRUE(allocator.isDisabled());
  EXPECT_EQ(0x12345678u, sequence);
  EXPECT_EQ(0, backing.reserveCalls);
}

TEST(OtaBackedRxReplayLedger, CommittedZeroCounterNeverAuthorizesFirstUse) {
  FakeControllableRxBackingStore backing;
  backing.watermark = 0;
  OtaBackedRxReplayLedger ledger(backing, makeFullPeerContext(1));
  EXPECT_FALSE(ledger.admit(1));
  EXPECT_TRUE(ledger.isDisabled());
  EXPECT_EQ(0, backing.advanceCalls);
}

TEST(OtaBackedTxSequenceAllocator, CommittedReservationMustMatchTheClaimedRangeExactly) {
  class InvalidReservation : public FakeControllableTxBackingStore {
   public:
    OtaSequenceBackingResult reserveTx(uint32_t, uint32_t, uint32_t& outUpper) override {
      outUpper = 192;
      return OtaSequenceBackingResult::Committed;
    }
  };
  InvalidReservation backing;
  backing.counter = 64;
  OtaBackedTxSequenceAllocator allocator(backing);
  uint32_t sequence = 0x12345678;
  EXPECT_FALSE(allocator.allocate(&sequence));
  EXPECT_TRUE(allocator.isDisabled());
  EXPECT_EQ(0x12345678u, sequence);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
