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
#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashRegion.h"

#include "../test_lora_ota_storage/FakeNorFlash.h"

using namespace meshcore::ota::runtime;
using meshcore::ota::protocol::OtaAirtimeCategory;

// ---------------------------------------------------------------------
// Geometry: checked arithmetic, exact final chunk length, overflow cases
// ---------------------------------------------------------------------

TEST(OtaGeometry, MaxImageAt160ByteChunksMatchesExpectedGeometry) {
  OtaGeometry g;
  ASSERT_EQ(OtaGeometryResult::Ok, OtaGeometry::compute(kOtaMaxImageBytes, kOtaDefaultChunkPayloadSize, kOtaMaxImageBytes, g));
  EXPECT_EQ(5069u, g.chunkCount);
  EXPECT_EQ(128u, g.finalChunkLength);
  EXPECT_EQ(kOtaMaxChunkCount, static_cast<size_t>(g.chunkCount));

  uint32_t len = 0;
  ASSERT_TRUE(g.chunkLength(0, len));
  EXPECT_EQ(160u, len);
  ASSERT_TRUE(g.chunkLength(5067, len));
  EXPECT_EQ(160u, len);
  ASSERT_TRUE(g.chunkLength(5068, len)); // last index (0-based), chunkCount-1
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
  ASSERT_TRUE(g.chunkOffset(5068, offset));
  EXPECT_EQ(5068ull * 160ull, offset);
  EXPECT_EQ(810880ull, offset);
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

TEST(OtaAirtimeLimiter, NormalTrafficPrecedenceBlocksRepairAndRelayButNotControl) {
  OtaAirtimeLimiter limiter;
  OtaAirtimeDecisionInput decision;
  decision.normalTrafficActive = true;
  EXPECT_FALSE(limiter.canAdmit(0, OtaAirtimeCategory::Repair, 100, decision));
  EXPECT_FALSE(limiter.canAdmit(0, OtaAirtimeCategory::Relay, 100, decision));
  EXPECT_TRUE(limiter.canAdmit(0, OtaAirtimeCategory::Control, 100, decision));
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

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
