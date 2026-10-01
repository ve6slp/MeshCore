#include <gtest/gtest.h>

#include <cstring>
#include <cstdint>
#include <vector>

#include "ota/campaign/CampaignCommon.h"
#include "ota/campaign/CampaignPorts.h"
#include "ota/campaign/CampaignWire.h"
#include "ota/campaign/TargetReceiverEngine.h"
#include "ota/campaign/UpdaterCampaignEngine.h"
#include "ota/campaign/FleetCampaignEngine.h"
#include "ota/campaign/DirectLeaseEngine.h"
#include "ota/campaign/CampaignFirmwareStaging.h"
#include "FakeCampaignPorts.h"

// Gap-B real trust/staging reboot proof: genuine production flash
// primitives + genuine Ed25519 signing/verification (NOT fakes) so a
// reboot-resume test exercises the actual crypto/flash pipeline, not a
// simulated shortcut. FakeNorFlash is read-only-reused from
// test_lora_ota_storage (out of this component's write scope, but a
// faithful, already-reviewed in-memory NOR flash model implementing the
// exact same real ::ota::platform::FlashDevice interface production
// code uses) rather than duplicated: the whole point of Gap B is testing
// against the SAME FlashRegion/StorageManager production code path, and
// re-deriving an equivalent fake here would just be a worse, unreviewed
// copy of that exact file.
#include "../test_lora_ota_storage/FakeNorFlash.h"
#include "ota/trust/DescriptorVerifier.h"
#include "ota/trust/Sha256.h"
#include "ota/trust/Ed25519SignatureVerifier.h"
#include "ota/trust/third_party/ed25519/Ed25519Impl.h"
#include "helpers/ota/OtaFirmwareBackend.h"
#include "helpers/ota/OtaBoardBackendCommon.h"
#include "ota/storage/XiaoOtaCommandRecord.h"

using namespace meshcore::ota::campaign;
using namespace meshcore::ota::campaign::test;
namespace protocol = meshcore::ota::protocol;
namespace runtime = meshcore::ota::runtime;

namespace {

protocol::OtaDescriptor makeDescriptor(uint32_t sizeBytes, uint32_t securityCounter = 1) {
  protocol::OtaDescriptor d;
  d.boardFamily = 1;
  d.boardVariant = 1;
  d.role = 1;
  d.appAddress = 0x1000;
  d.exactSizeBytes = sizeBytes;
  for (size_t i = 0; i < sizeof(d.sha256); ++i) d.sha256[i] = static_cast<uint8_t>(i + 1);
  d.securityCounter = securityCounter;
  d.minBootloaderCapabilities = 0;
  d.formatId = 1;
  d.keyId = 1;
  d.algorithmId = 1;
  return d;
}

std::vector<uint8_t> fakeSignature() { return std::vector<uint8_t>(64, 0xAB); }

CampaignConsentRequestPayload makeConsentPayload(const CampaignPeerId& controller, uint32_t groupId = 0) {
  CampaignConsentRequestPayload p;
  std::memcpy(p.controllerId, controller.bytes, 32);
  p.scope = static_cast<uint8_t>(CampaignAuthScope::Pairwise);
  p.groupId = groupId;
  // Default matches the fixed-size descriptor+signature blob every fixture
  // in this file actually presents (canonical descriptor + 64-byte
  // Ed25519-shaped signature); tests exercising a genuinely differing
  // declared-vs-actual length override this explicitly.
  p.descriptorTotalLength = static_cast<uint16_t>(protocol::kOtaDescriptorCanonicalSize + 64);
  return p;
}

// Encodes a full campaign envelope (any message type) into a byte vector
// so tests can relay REAL wire bytes into a peer engine's onFrame(),
// mirroring how integration would move authenticated frames between
// nodes.
template <typename PayloadEncodeFn>
std::vector<uint8_t> encodeEnvelope(CampaignMessageType type, const runtime::OtaSessionId& session,
                                     uint32_t frameSeq, PayloadEncodeFn encodePayload) {
  uint8_t payload[protocol::kOtaMaxFrameSize];
  size_t payloadLen = 0;
  bool ok = encodePayload(payload, sizeof(payload), payloadLen);
  EXPECT_TRUE(ok);
  CampaignEnvelopeHeader hdr;
  hdr.type = type;
  hdr.session = session;
  hdr.frameSeq = frameSeq;
  uint8_t frame[protocol::kOtaMaxFrameSize];
  size_t frameLen = 0;
  EXPECT_EQ(CampaignCodecResult::Ok, encodeCampaignEnvelope(hdr, payload, payloadLen, frame, sizeof(frame), frameLen));
  return std::vector<uint8_t>(frame, frame + frameLen);
}

std::vector<uint8_t> encodeChunkFrame(const runtime::OtaSessionId& session, uint32_t frameSeq, uint32_t chunkIndex,
                                       const uint8_t* data, size_t len) {
  return encodeEnvelope(CampaignMessageType::Chunk, session, frameSeq,
                         [&](uint8_t* dst, size_t cap, size_t& outLen) {
                           protocol::OtaChunkHeader hdr{chunkIndex, static_cast<uint16_t>(len)};
                           return protocol::encodeOtaChunk(hdr, data, len, dst, cap, outLen);
                         });
}

std::vector<uint8_t> encodeReceiptFrame(const runtime::OtaSessionId& session, uint32_t frameSeq,
                                         protocol::OtaReceiptStatus status, uint32_t chunkIndex) {
  return encodeEnvelope(CampaignMessageType::Receipt, session, frameSeq,
                         [&](uint8_t* dst, size_t cap, size_t& outLen) {
                           protocol::OtaReceiptPayload r{status, chunkIndex, 0, 0};
                           return protocol::encodeOtaReceipt(r, dst, cap, outLen);
                         });
}

std::vector<uint8_t> encodeCommitFrame(const runtime::OtaSessionId& session, uint32_t frameSeq,
                                        uint32_t campaignId, uint8_t verifiedOk, uint32_t finalSecurityCounter) {
  return encodeEnvelope(CampaignMessageType::Commit, session, frameSeq,
                         [&](uint8_t* dst, size_t cap, size_t& outLen) {
                           protocol::OtaCommitPayload c{campaignId, verifiedOk, finalSecurityCounter};
                           return protocol::encodeOtaCommit(c, dst, cap, outLen);
                         });
}

std::vector<uint8_t> encodeConsentRequestFrame(const runtime::OtaSessionId& session, uint32_t frameSeq,
                                                 const CampaignConsentRequestPayload& p) {
  return encodeEnvelope(CampaignMessageType::ConsentRequest, session, frameSeq,
                         [&](uint8_t* dst, size_t cap, size_t& outLen) {
                           return encodeCampaignConsentRequest(p, dst, cap, outLen);
                         });
}

std::vector<uint8_t> encodeDescriptorFragmentFrame(const runtime::OtaSessionId& session, uint32_t frameSeq,
                                                     uint8_t fragIndex, uint8_t fragCount, uint16_t totalLength,
                                                     uint16_t fragmentPayloadSize, const uint8_t* data,
                                                     size_t dataLen) {
  return encodeEnvelope(CampaignMessageType::DescriptorFragment, session, frameSeq,
                         [&](uint8_t* dst, size_t cap, size_t& outLen) {
                           return encodeCampaignDescriptorFragment(fragIndex, fragCount, totalLength,
                                                                    fragmentPayloadSize, data, dataLen, dst, cap,
                                                                    outLen);
                         });
}

std::vector<uint8_t> encodeCensusFrame(const runtime::OtaSessionId& session, uint32_t frameSeq,
                                        const CampaignCensusPagePayload& page) {
  return encodeEnvelope(CampaignMessageType::Census, session, frameSeq,
                         [&](uint8_t* dst, size_t cap, size_t& outLen) {
                           return encodeCampaignCensusPage(page, dst, cap, outLen);
                         });
}

// Extracts an OtaChunkHeader + data pointer from a raw envelope frame
// (as produced by UpdaterCampaignEngine::tickTransmit()), simulating the
// receiver-side decode a real transport integration performs before
// calling TargetReceiverEngine::applyChunk().
bool decodeChunkFromFrame(const std::vector<uint8_t>& frame, runtime::OtaSessionId& outSession, uint32_t& outFrameSeq,
                           protocol::OtaChunkHeader& outHdr, std::vector<uint8_t>& outData) {
  CampaignEnvelopeHeader hdr;
  const uint8_t* payload = nullptr;
  size_t payloadLen = 0;
  if (decodeCampaignEnvelope(frame.data(), frame.size(), hdr, payload, payloadLen) != CampaignCodecResult::Ok) return false;
  if (hdr.type != CampaignMessageType::Chunk) return false;
  const uint8_t* data = nullptr;
  size_t dataLen = 0;
  if (!protocol::decodeOtaChunk(payload, payloadLen, outHdr, data, dataLen)) return false;
  outSession = hdr.session;
  outFrameSeq = hdr.frameSeq;
  outData.assign(data, data + dataLen);
  return true;
}

} // namespace

// =======================================================================
// Directed single-target E2E: real image bytes, unequal final chunk,
// dropped chunk/receipt, reboot-resume, signature/hash/foreign/counter
// refusals, no false Installed.
// =======================================================================

class DirectedE2ETest : public ::testing::Test {
protected:
  void SetUp() override {
    controller_ = makePeerId(0x11);
    imageSize_ = 128 * 5 + 37; // unequal final chunk (37 bytes, not 128)
    descriptor_ = makeDescriptor(imageSize_);
    sig_ = fakeSignature();
    hostImage_.data.resize(imageSize_);
    for (size_t i = 0; i < imageSize_; ++i) hostImage_.data[i] = static_cast<uint8_t>(i);
  }

  CampaignPeerId controller_;
  uint32_t imageSize_ = 0;
  protocol::OtaDescriptor descriptor_;
  std::vector<uint8_t> sig_;
  FakeHostImageReader hostImage_;

  // Drives a FULL directed transfer purely via tick()/onFrame(), but
  // deliberately drops the FIRST occurrence of `dropType` from EITHER
  // direction's sentLog exactly once (simulating a genuine wire loss --
  // the transport reported Enqueued, but the frame never reaches the
  // peer) and, independently, forces the target's very first outbound
  // reply attempt to report Backpressure. Asserts the transfer still
  // autonomously converges to Installed/Complete, and that the dropped
  // type was actually resent (proving a real retry happened, not mere
  // luck). Used to verify EVERY control/reply frame type independently,
  // not just a hand-picked couple.
  void runDirectedTransferDroppingFrameTypeOnce(CampaignMessageType dropType) {
    FakeTrust updaterTrust, targetTrust;
    FakeCacheSink cache;
    FakeTransport updaterTransport;
    FakeTransport targetTransport;
    FakeClock clock;
    UpdaterCampaignEngine updater(updaterTrust, cache, updaterTransport, hostImage_, clock);

    FakeStagingSink staging;
    FakePersistence persistence;
    FakeBootEvidence boot;
    FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
    TargetReceiverEngine target(targetTrust, staging, persistence, boot, consent, commissioning);
    target.bindTransport(targetTransport);
    target.bindClock(clock);
    targetTransport.forcedResults.push_back(CampaignSendResult::Backpressure);

    const CampaignPeerId targetId = makePeerId(0x33);
    runtime::OtaSessionId session{123, 1, 1};
    CampaignDestination dest;
    dest.scope = CampaignAuthScope::Pairwise;
    dest.peerId = targetId;
    ASSERT_TRUE(updater.begin(session, descriptor_, sig_.data(), sig_.size(), dest, controller_));

    size_t updaterCursor = 0;
    size_t targetCursor = 0;
    bool bootFired = false;
    bool droppedOnce = false;
    int typeSeenCount = 0;
    int iterations = 0;
    const int kMaxIterations = 60000; // safety bound: proves no infinite loop despite bounded retries
    while (updater.outcome() == UpdaterOutcome::InProgress && ++iterations < kMaxIterations) {
      updater.tick();
      target.tick();

      while (updaterCursor < updaterTransport.sentLog.size()) {
        const auto& sent = updaterTransport.sentLog[updaterCursor++];
        CampaignEnvelopeHeader hdr;
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        ASSERT_EQ(CampaignCodecResult::Ok,
                  decodeCampaignEnvelope(sent.bytes.data(), sent.bytes.size(), hdr, payload, payloadLen));
        if (hdr.type == dropType) {
          ++typeSeenCount;
          if (!droppedOnce) {
            droppedOnce = true;
            continue; // this exact wire attempt is lost, never relayed
          }
        }
        AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, controller_);
        target.onFrame(f);
      }
      while (targetCursor < targetTransport.sentLog.size()) {
        const auto& sent = targetTransport.sentLog[targetCursor++];
        CampaignEnvelopeHeader hdr;
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        ASSERT_EQ(CampaignCodecResult::Ok,
                  decodeCampaignEnvelope(sent.bytes.data(), sent.bytes.size(), hdr, payload, payloadLen));
        if (hdr.type == dropType) {
          ++typeSeenCount;
          if (!droppedOnce) {
            droppedOnce = true;
            continue;
          }
        }
        AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, targetId);
        updater.onFrame(f);
      }

      if (target.status() == TargetStatus::InstalledPending) {
        if (!bootFired) {
          boot.evidence.healthyBootConfirmed = true;
          boot.evidence.bootedSession = session;
          std::memcpy(boot.evidence.bootedImageHash, descriptor_.sha256, protocol::kOtaSha256Size);
          boot.evidence.bootedSecurityCounter = descriptor_.securityCounter;
          bootFired = true;
        }
        target.confirmHealthyBoot();
      }

      clock.advance(50);
    }

    ASSERT_LT(iterations, kMaxIterations) << "transfer did not converge autonomously despite bounded retry";
    EXPECT_TRUE(droppedOnce) << "the frame type under test was never actually observed on the wire";
    EXPECT_GT(typeSeenCount, 1) << "no retry of the dropped type was ever observed -- test would pass vacuously";
    EXPECT_EQ(TargetStatus::Installed, target.status());
    EXPECT_EQ(UpdaterOutcome::Complete, updater.outcome());
  }
};

TEST_F(DirectedE2ETest, FullTransferInstallsAndConfirmsBoot) {
  FakeTrust updaterTrust, targetTrust;
  FakeCacheSink cache;
  FakeTransport updaterTransport;
  FakeClock clock;
  UpdaterCampaignEngine updater(updaterTrust, cache, updaterTransport, hostImage_, clock);

  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(targetTrust, staging, persistence, boot, consent, commissioning);

  runtime::OtaSessionId session{42, 1, 1};
  CampaignDestination dest;
  dest.scope = CampaignAuthScope::Pairwise;
  dest.peerId = makePeerId(0x22); // target's id, from the updater's point of view
  ASSERT_TRUE(updater.begin(session, descriptor_, sig_.data(), sig_.size(), dest));

  while (updater.cacheNextChunk()) {
  }
  ASSERT_TRUE(updater.sealCache());

  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  ASSERT_EQ(TargetStatus::Receiving, target.status());

  uint32_t targetFrameSeq = 2;
  uint32_t updaterFrameSeq = 1;
  uint32_t chunksSent = 0;
  const uint32_t totalChunks = updater.geometry().chunkCount;
  while (chunksSent < totalChunks) {
    CampaignSendResult r = updater.tickTransmit();
    if (r != CampaignSendResult::Enqueued) continue;
    auto& sent = updaterTransport.sentLog.back();
    runtime::OtaSessionId decodedSession;
    uint32_t envelopeSeq = 0;
    protocol::OtaChunkHeader chdr;
    std::vector<uint8_t> data;
    ASSERT_TRUE(decodeChunkFromFrame(sent.bytes, decodedSession, envelopeSeq, chdr, data));

    AuthenticatedInboundFrame chunkFrame = makeInboundFrame({}, controller_);
    ASSERT_TRUE(target.applyChunk(chunkFrame, targetFrameSeq++, decodedSession, chdr, data.data(), data.size()));

    auto receiptBytes = encodeReceiptFrame(session, updaterFrameSeq++, protocol::OtaReceiptStatus::ChunkAck, chdr.chunkIndex);
    AuthenticatedInboundFrame receiptFrame = makeInboundFrame(receiptBytes, dest.peerId);
    ASSERT_TRUE(updater.applyReceipt(receiptFrame, targetFrameSeq++, session, protocol::OtaReceiptPayload{
                                          protocol::OtaReceiptStatus::ChunkAck, chdr.chunkIndex, 0, 0}));
    ++chunksSent;
  }

  ASSERT_EQ(TargetStatus::Verifying, target.status());
  AuthenticatedInboundFrame controllerFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.verifyAndCommit(controllerFrame, session));
  ASSERT_EQ(TargetStatus::InstalledPending, target.status());

  // Not yet Installed: no false claim before boot evidence exists.
  EXPECT_FALSE(target.confirmHealthyBoot());
  EXPECT_EQ(TargetStatus::InstalledPending, target.status());

  boot.evidence.healthyBootConfirmed = true;
  boot.evidence.bootedSession = session;
  std::memcpy(boot.evidence.bootedImageHash, descriptor_.sha256, protocol::kOtaSha256Size);
  boot.evidence.bootedSecurityCounter = descriptor_.securityCounter;
  ASSERT_TRUE(target.confirmHealthyBoot());
  ASSERT_EQ(TargetStatus::Installed, target.status());

  // Driver observes Installed and reports remote completion to the updater.
  auto completeBytes = encodeReceiptFrame(session, updaterFrameSeq, protocol::OtaReceiptStatus::TransferComplete, 0);
  AuthenticatedInboundFrame completeFrame = makeInboundFrame(completeBytes, dest.peerId);
  ASSERT_TRUE(updater.applyReceipt(completeFrame, targetFrameSeq++, session,
                                    protocol::OtaReceiptPayload{protocol::OtaReceiptStatus::TransferComplete, 0, 0, 0}));
  EXPECT_EQ(UpdaterOutcome::Complete, updater.outcome());
}

// A Group-DESTINATION bulk campaign has NO single expected peer at the
// Updater layer -- cohort-membership-scoped consent/receipt attribution
// is FLEET's job. This proves the Updater no longer accepts "any
// authenticated peer" (regardless of whether that peer is even a
// legitimate cohort member) as if it were the one expected controller:
// neither a ConsentGrant nor a TransferComplete Receipt from a random
// authenticated-but-unrelated peer may ever move state for a Group dest.
TEST_F(DirectedE2ETest, GroupDestinationConsentGrantAndReceiptRejectAnyAuthenticatedPeer) {
  FakeTrust updaterTrust;
  FakeCacheSink cache;
  FakeTransport updaterTransport;
  FakeClock clock;
  UpdaterCampaignEngine updater(updaterTrust, cache, updaterTransport, hostImage_, clock);

  runtime::OtaSessionId session{43, 1, 1};
  CampaignDestination dest;
  dest.scope = CampaignAuthScope::Group;
  dest.groupId = 999;
  ASSERT_TRUE(updater.begin(session, descriptor_, sig_.data(), sig_.size(), dest));

  CampaignPeerId randomAuthenticatedPeer = makePeerId(0x77); // a genuine peer, just not "the" expected one
  CampaignConsentGrantPayload grant;
  grant.granted = 1;
  grant.refusalReason = 0;
  grant.maxInFlightChunks = 4;
  auto grantFrameBytes = encodeEnvelope(CampaignMessageType::ConsentGrant, session, 1,
                                        [&](uint8_t* dst, size_t cap, size_t& outLen) {
                                          return encodeCampaignConsentGrant(grant, dst, cap, outLen);
                                        });
  AuthenticatedInboundFrame grantFrame =
      makeInboundFrame(grantFrameBytes, randomAuthenticatedPeer);
  EXPECT_FALSE(updater.onFrame(grantFrame));
  EXPECT_EQ(CampaignRefusalReason::ForeignController, updater.lastRefusal());
  EXPECT_FALSE(updater.isConsentGranted());

  auto completeBytes = encodeReceiptFrame(session, 1, protocol::OtaReceiptStatus::TransferComplete, 0);
  AuthenticatedInboundFrame completeFrame =
      makeInboundFrame(completeBytes, randomAuthenticatedPeer);
  EXPECT_FALSE(updater.applyReceipt(completeFrame, 2, session,
                                     protocol::OtaReceiptPayload{protocol::OtaReceiptStatus::TransferComplete, 0, 0, 0}));
  EXPECT_EQ(CampaignRefusalReason::ForeignController, updater.lastRefusal());
  EXPECT_NE(UpdaterOutcome::Complete, updater.outcome());
}

// Proves the production facade itself drives the entire directed transfer
// autonomously: the test never calls beginPendingConsent/onDescriptorFragment/
// applyChunk/verifyAndCommit/applyReceipt directly. It only drives
// updater.tick(), relays raw bytes from each side's transport sentLog into
// the other side's onFrame(), and (as the explicitly external physical
// health signal the architecture assigns to FW/boot evidence, never to the
// wire protocol) fires boot evidence + confirmHealthyBoot() once the
// target reaches InstalledPending.
TEST_F(DirectedE2ETest, FullyAutonomousTickAndOnFrameDrivenTransferInstallsAndConfirmsBoot) {
  FakeTrust updaterTrust, targetTrust;
  FakeCacheSink cache;
  FakeTransport updaterTransport;
  FakeTransport targetTransport;
  FakeClock clock;
  UpdaterCampaignEngine updater(updaterTrust, cache, updaterTransport, hostImage_, clock);

  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(targetTrust, staging, persistence, boot, consent, commissioning);
  target.bindTransport(targetTransport);

  const CampaignPeerId targetId = makePeerId(0x22);
  runtime::OtaSessionId session{77, 1, 1};
  CampaignDestination dest;
  dest.scope = CampaignAuthScope::Pairwise;
  dest.peerId = targetId;
  ASSERT_TRUE(updater.begin(session, descriptor_, sig_.data(), sig_.size(), dest, controller_));

  size_t updaterCursor = 0;
  size_t targetCursor = 0;
  bool bootFired = false;
  int iterations = 0;
  const int kMaxIterations = 20000; // safety bound: proves no infinite loop, real progress each pass
  while (updater.outcome() == UpdaterOutcome::InProgress && ++iterations < kMaxIterations) {
    updater.tick();

    while (updaterCursor < updaterTransport.sentLog.size()) {
      const auto& sent = updaterTransport.sentLog[updaterCursor++];
      AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, controller_);
      target.onFrame(f);
    }
    while (targetCursor < targetTransport.sentLog.size()) {
      const auto& sent = targetTransport.sentLog[targetCursor++];
      AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, targetId);
      updater.onFrame(f);
    }

    if (target.status() == TargetStatus::InstalledPending) {
      if (!bootFired) {
        boot.evidence.healthyBootConfirmed = true;
        boot.evidence.bootedSession = session;
        std::memcpy(boot.evidence.bootedImageHash, descriptor_.sha256, protocol::kOtaSha256Size);
        boot.evidence.bootedSecurityCounter = descriptor_.securityCounter;
        bootFired = true;
      }
      target.confirmHealthyBoot();
    }
  }

  ASSERT_LT(iterations, kMaxIterations) << "transfer did not converge autonomously";
  EXPECT_EQ(TargetStatus::Installed, target.status());
  EXPECT_EQ(UpdaterOutcome::Complete, updater.outcome());
}

TEST_F(DirectedE2ETest, DroppedChunkIsRetransmittedByTimeout) {
  FakeTrust trust;
  FakeCacheSink cache;
  FakeTransport transport;
  FakeClock clock;
  UpdaterCampaignEngine updater(trust, cache, transport, hostImage_, clock);
  CampaignDestination dest;
  dest.scope = CampaignAuthScope::Pairwise;
  dest.peerId = makePeerId(0x22);
  runtime::OtaSessionId session{1, 1, 1};
  ASSERT_TRUE(updater.begin(session, descriptor_, sig_.data(), sig_.size(), dest));
  while (updater.cacheNextChunk()) {
  }
  ASSERT_TRUE(updater.sealCache());

  ASSERT_EQ(CampaignSendResult::Enqueued, updater.tickTransmit(2000));
  size_t firstSendCount = transport.sentLog.size();
  // No receipt arrives (simulated drop); before timeout, window is full at
  // 1 of 4 slots so more NEW chunks can still be assigned, but the SAME
  // chunk must not be resent until the timeout elapses.
  clock.advance(500);
  updater.tickTransmit(2000); // assigns a different chunk (window not full)
  EXPECT_GT(transport.sentLog.size(), firstSendCount);

  clock.advance(3000); // now past the 2000ms retry timeout
  size_t beforeRetry = transport.sentLog.size();
  CampaignSendResult r = updater.tickTransmit(2000);
  ASSERT_EQ(CampaignSendResult::Enqueued, r);
  ASSERT_GT(transport.sentLog.size(), beforeRetry);
  runtime::OtaSessionId decodedSession;
  uint32_t seq = 0;
  protocol::OtaChunkHeader chdr;
  std::vector<uint8_t> data;
  ASSERT_TRUE(decodeChunkFromFrame(transport.sentLog.back().bytes, decodedSession, seq, chdr, data));
  EXPECT_EQ(0u, chdr.chunkIndex); // the originally-dropped chunk 0 was retried
}

TEST_F(DirectedE2ETest, RebootMidTransferResumesFromPersistedBitmap) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  runtime::OtaSessionId session{7, 1, 1};

  uint32_t targetFrameSeq = 1;
  {
    TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
    AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
    ASSERT_TRUE(target.handleConsentRequest(consentFrame, targetFrameSeq++, session, makeConsentPayload(controller_),
                                             descriptor_, sig_.data(), sig_.size()));
    for (uint32_t i = 0; i < 3; ++i) {
      uint32_t len = 0;
      ASSERT_TRUE(target.geometry().chunkLength(i, len));
      std::vector<uint8_t> data(len, static_cast<uint8_t>(i));
      protocol::OtaChunkHeader hdr{i, static_cast<uint16_t>(len)};
      AuthenticatedInboundFrame chunkFrame = makeInboundFrame({}, controller_);
      ASSERT_TRUE(target.applyChunk(chunkFrame, targetFrameSeq++, session, hdr, data.data(), data.size()));
    }
    EXPECT_EQ(3u, target.receivedChunkCount());
    // Engine instance is destroyed here, simulating an ungraceful reboot;
    // no explicit shutdown/save call is made beyond what applyChunk()
    // already durably committed per-chunk.
  }

  TargetReceiverEngine reloaded(trust, staging, persistence, boot, consent, commissioning);
  FakeStagingResume resume(staging);
  reloaded.bindStagingResume(resume);
  ASSERT_TRUE(reloaded.reload());
  EXPECT_EQ(1u, resume.resumeCallCount); // proves non-destructive resume was actually used, not beginSession()
  EXPECT_EQ(TargetStatus::Receiving, reloaded.status());
  EXPECT_EQ(3u, reloaded.receivedChunkCount());
  EXPECT_TRUE(reloaded.isControllerBound());
  EXPECT_EQ(controller_, reloaded.boundController());

  // Resuming must not erase previously received bytes or reset
  // authorization: remaining chunks can still be applied post-reload.
  uint32_t len = 0;
  ASSERT_TRUE(reloaded.geometry().chunkLength(3, len));
  std::vector<uint8_t> data(len, 3);
  protocol::OtaChunkHeader hdr{3, static_cast<uint16_t>(len)};
  AuthenticatedInboundFrame chunkFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(reloaded.applyChunk(chunkFrame, targetFrameSeq++, session, hdr, data.data(), data.size()));
  EXPECT_EQ(4u, reloaded.receivedChunkCount());
}

TEST_F(DirectedE2ETest, PowerCutBeforeAckNeverFalselyAcksAndBitmapUnchanged) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{9, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));

  uint32_t len = 0;
  ASSERT_TRUE(target.geometry().chunkLength(0, len));
  std::vector<uint8_t> data(len, 0xAA);
  protocol::OtaChunkHeader hdr{0, static_cast<uint16_t>(len)};

  persistence.saveShouldFail = true;
  AuthenticatedInboundFrame chunkFrame = makeInboundFrame({}, controller_);
  ASSERT_FALSE(target.applyChunk(chunkFrame, 2, session, hdr, data.data(), data.size()));
  EXPECT_EQ(CampaignRefusalReason::PersistenceFailed, target.lastRefusal());
  EXPECT_EQ(0u, target.receivedChunkCount()); // no false ACK: bitmap unchanged

  persistence.saveShouldFail = false;
  ASSERT_TRUE(target.applyChunk(chunkFrame, 2, session, hdr, data.data(), data.size())); // retry, same frameSeq
  EXPECT_EQ(1u, target.receivedChunkCount());
}

// Product crash/replay behavior: a save() can physically write the new
// durable bytes and STILL fail to confirm it (readback/ack step lost,
// power cut immediately after the write lands). This must not be treated
// as a false ACK, but it also must not be treated as "nothing happened" --
// the old in-memory RAM state can no longer be trusted enough to admit a
// new/competing controller or session on top of it. Only an explicit
// reload() (re-deriving state from whatever is ACTUALLY durable) may
// resolve the uncertainty.
TEST_F(DirectedE2ETest, UncertainSaveFreezesAdmissionUntilReloadReconstructsRealDurableState) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{11, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));

  uint32_t len0 = 0;
  ASSERT_TRUE(target.geometry().chunkLength(0, len0));
  std::vector<uint8_t> data0(len0, 0xAA);
  protocol::OtaChunkHeader hdr0{0, static_cast<uint16_t>(len0)};
  AuthenticatedInboundFrame chunkFrame0 = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.applyChunk(chunkFrame0, 2, session, hdr0, data0.data(), data0.size()));
  EXPECT_EQ(1u, target.receivedChunkCount());
  ASSERT_FALSE(target.isPersistUncertain());

  // Chunk 1's save() physically writes the new bitmap/checkpoint bytes
  // into the fake's backing store, but reports Uncertain (simulating a
  // readback/ack failure right after the write landed).
  uint32_t len1 = 0;
  ASSERT_TRUE(target.geometry().chunkLength(1, len1));
  std::vector<uint8_t> data1(len1, 0xBB);
  protocol::OtaChunkHeader hdr1{1, static_cast<uint16_t>(len1)};
  AuthenticatedInboundFrame chunkFrame1 = makeInboundFrame({}, controller_);
  persistence.forceUncertainNextSave = true;
  ASSERT_FALSE(target.applyChunk(chunkFrame1, 3, session, hdr1, data1.data(), data1.size()));
  EXPECT_EQ(CampaignRefusalReason::PersistenceFailed, target.lastRefusal());
  // No false ACK: in-memory bookkeeping did not advance to "2 chunks".
  EXPECT_EQ(1u, target.receivedChunkCount());
  ASSERT_TRUE(target.isPersistUncertain());

  // A DIFFERENT controller trying to open a competing session must be
  // rejected outright while the durable truth is unresolved -- old RAM
  // state cannot be trusted enough to let a new binding overwrite
  // whatever is actually on disk right now.
  CampaignPeerId otherController = makePeerId(0x77);
  runtime::OtaSessionId otherSession{99, 1, 1};
  AuthenticatedInboundFrame otherConsentFrame = makeInboundFrame({}, otherController);
  EXPECT_FALSE(target.handleConsentRequest(otherConsentFrame, 1, otherSession, makeConsentPayload(otherController),
                                            descriptor_, sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::UnresolvedPersistedState, target.lastRefusal());

  // Even the SAME controller attempting a brand-new session must be
  // refused for the same reason -- the freeze is unconditional until
  // reload() resolves it, not merely "different controller" scoped.
  runtime::OtaSessionId newSameControllerSession{12, 1, 1};
  AuthenticatedInboundFrame sameControllerNewSessionFrame =
      makeInboundFrame({}, controller_);
  EXPECT_FALSE(target.handleConsentRequest(sameControllerNewSessionFrame, 1, newSameControllerSession,
                                            makeConsentPayload(controller_), descriptor_, sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::UnresolvedPersistedState, target.lastRefusal());

  // Reconstruct the receiver from the durable store (simulates a reboot):
  // a fresh instance's reload() must see the bytes chunk 1's write
  // actually left behind, prove they were real, and clear the
  // uncertainty -- NOT silently roll back to the pre-chunk-1 state.
  TargetReceiverEngine reconstructed(trust, staging, persistence, boot, consent, commissioning);
  FakeStagingResume reconstructedResume(staging);
  reconstructed.bindStagingResume(reconstructedResume);
  ASSERT_TRUE(reconstructed.reload());
  EXPECT_FALSE(reconstructed.isPersistUncertain());
  EXPECT_FALSE(reconstructed.isReloadUnsafe());
  EXPECT_EQ(2u, reconstructed.receivedChunkCount()); // chunk 0 AND chunk 1 both really landed durably

  // Same-context idempotence: retrying chunk 1 (same session/chunk index)
  // against the reconstructed instance -- using a FRESH per-frame retry
  // sequence, since the durably-recorded watermark now reflects the
  // uncertain write's frameSeq=3 already having truly landed -- must
  // succeed as a legal no-op without duplicating/corrupting state.
  AuthenticatedInboundFrame chunkFrame1Retry = makeInboundFrame({}, controller_);
  ASSERT_TRUE(reconstructed.applyChunk(chunkFrame1Retry, 4, session, hdr1, data1.data(), data1.size()));
  EXPECT_EQ(2u, reconstructed.receivedChunkCount());

  // Also resolve the original in-memory instance the same way (its own
  // reload() picks up the truth too), and confirm the also-attempted
  // resumption on that same object behaves identically post-resolution.
  FakeStagingResume targetResume(staging);
  target.bindStagingResume(targetResume);
  ASSERT_TRUE(target.reload());
  EXPECT_FALSE(target.isPersistUncertain());
  EXPECT_EQ(2u, target.receivedChunkCount());

  // Now that the uncertainty is resolved, a genuinely competing
  // controller session is still correctly rejected -- but for the
  // ordinary "already bound to a different controller" reason, not the
  // uncertainty freeze (proving the freeze itself was lifted, and normal
  // competing-session policy resumed).
  AuthenticatedInboundFrame otherConsentFrameAgain = makeInboundFrame({}, otherController);
  EXPECT_FALSE(target.handleConsentRequest(otherConsentFrameAgain, 1, otherSession, makeConsentPayload(otherController),
                                            descriptor_, sig_.data(), sig_.size()));
  EXPECT_NE(CampaignRefusalReason::UnresolvedPersistedState, target.lastRefusal());
}

TEST_F(DirectedE2ETest, CorruptReloadRecordIsRejectedNotTrusted) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  runtime::OtaSessionId session{11, 1, 1};
  {
    TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
    AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
    ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                            sig_.data(), sig_.size()));
  }

  // Flip a byte inside the magic field (offset 0..3): must be rejected.
  FakePersistence badMagic = persistence;
  badMagic.corruptByte(CampaignPersistRole::TargetReceiver, 0);
  {
    TargetReceiverEngine reloaded(trust, staging, badMagic, boot, consent, commissioning);
    EXPECT_FALSE(reloaded.reload());
  }

  // Flip a byte inside the CRC-covered body without fixing the CRC: must
  // be rejected (CRC mismatch).
  FakePersistence badBody = persistence;
  badBody.corruptByte(CampaignPersistRole::TargetReceiver, 40);
  {
    TargetReceiverEngine reloaded(trust, staging, badBody, boot, consent, commissioning);
    EXPECT_FALSE(reloaded.reload());
  }

  // Untouched record still loads fine (sanity check the corruption helper
  // actually targets meaningful bytes rather than trivially passing).
  {
    TargetReceiverEngine reloaded(trust, staging, persistence, boot, consent, commissioning);
    FakeStagingResume resume(staging);
    reloaded.bindStagingResume(resume);
    EXPECT_TRUE(reloaded.reload());
  }
}

TEST_F(DirectedE2ETest, UnreadablePersistedRecordBlocksNewAdmissionUntilExplicitRepair) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  runtime::OtaSessionId session{12, 1, 1};
  {
    TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
    AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
    ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                            sig_.data(), sig_.size()));
  }

  // The storage layer itself reports IoError on the next boot's reload
  // (distinct from "nothing was ever saved") -- this must NOT be treated
  // as a fresh/blank Idle engine that would happily admit any new session.
  FakePersistence ioFailing = persistence;
  ioFailing.forceIoError = true;
  TargetReceiverEngine reloaded(trust, staging, ioFailing, boot, consent, commissioning);
  EXPECT_FALSE(reloaded.reload());
  EXPECT_TRUE(reloaded.isReloadUnsafe());

  AuthenticatedInboundFrame newAttempt = makeInboundFrame({}, controller_);
  runtime::OtaSessionId newSession{13, 1, 1};
  EXPECT_FALSE(reloaded.handleConsentRequest(newAttempt, 1, newSession, makeConsentPayload(controller_), descriptor_,
                                             sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::UnresolvedPersistedState, reloaded.lastRefusal());

  // Explicit, deliberate repair clears the unsafe latch and admission can
  // proceed normally again.
  reloaded.acknowledgeUnsafeReloadAndReset();
  EXPECT_FALSE(reloaded.isReloadUnsafe());
  EXPECT_TRUE(reloaded.handleConsentRequest(newAttempt, 1, newSession, makeConsentPayload(controller_), descriptor_,
                                            sig_.data(), sig_.size()));
}

TEST_F(DirectedE2ETest, MissingRecordIsNotConflatedWithCorruptOrIoError) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence; // never saved anything
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  // Missing is safe: reload() succeeds and admission is NOT blocked.
  EXPECT_TRUE(target.reload());
  EXPECT_FALSE(target.isReloadUnsafe());
  runtime::OtaSessionId session{14, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  EXPECT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
}

// A durable record that was PREVIOUSLY known-commissioned (this engine's
// own RAM already reflects everBound_==true from an earlier successful
// admission) and then vanishes on a LATER reload() can never be
// conflated with "provably never commissioned" -- Missing there means
// facts were lost, not that nothing ever happened. Proves reload() does
// NOT silently resetToFreshIdle() (which would erase the replay/
// authorization floor an attacker could then exploit); it freezes
// exactly like Corrupt/IoError and leaves every prior in-memory fact
// completely untouched.
TEST_F(DirectedE2ETest, MissingAfterPreviouslyCommissionedStateIsUnsafeNeverFreshIdle) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{71, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  ASSERT_TRUE(target.isControllerBound());
  ASSERT_EQ(TargetStatus::Receiving, target.status());

  // Simulate the durable record vanishing out-of-band (NOT via the
  // sanctioned erase() port method -- e.g. a faulted device that lost
  // the record without ever confirming an erase): the very next reload()
  // now observes Missing.
  persistence.store.erase(CampaignPersistRole::TargetReceiver);
  EXPECT_FALSE(target.reload());
  EXPECT_TRUE(target.isReloadUnsafe());

  // Every prior in-memory fact must remain EXACTLY as it was -- never
  // reset to fresh Idle defaults.
  EXPECT_TRUE(target.isControllerBound());
  EXPECT_EQ(controller_, target.boundController());
  EXPECT_EQ(TargetStatus::Receiving, target.status());

  // And, same as any other reloadUnsafe_ latch, ALL new admission is
  // refused until an explicit, deliberate repair.
  runtime::OtaSessionId otherSession{72, 1, 1};
  CampaignPeerId otherController = makePeerId(0x99);
  AuthenticatedInboundFrame otherFrame = makeInboundFrame({}, otherController);
  EXPECT_FALSE(target.handleConsentRequest(otherFrame, 1, otherSession, makeConsentPayload(otherController),
                                            descriptor_, sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::UnresolvedPersistedState, target.lastRefusal());
}

// The RAM-based guard in the previous test (everBound_/reloadUnsafe_/
// persistUncertain_) cannot, by construction, catch a COLD engine
// reconstruction: a brand-new TargetReceiverEngine object has NO memory
// of anything. This proves a Missing main record on an already-Used
// device (positively verified by the independent commissioning-
// provenance port -- never inferred from any blob's absence) still
// freezes if there is no separately-confirmed repair-authorization
// record to explain WHY the main record vanished: "Used" alone is never
// enough to license treating a Missing main record as an authorized
// reset.
TEST_F(DirectedE2ETest, ColdReconstructionOfUsedDeviceWithoutRepairRecordFreezesEvenWithNoRamMemory) {
  FakeTrust trust;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  FakePersistence persistence;
  {
    FakeStagingSink staging;
    TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
    runtime::OtaSessionId session{81, 1, 1};
    AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
    ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                            sig_.data(), sig_.size()));
    // `target`/`staging` go out of scope here: ALL RAM memory of this
    // commissioning is gone. Only `persistence`'s durable main record
    // survives, plus `commissioning`'s independently-persisted (and now
    // positively Used, via the real markUsedIfCurrentlyVirgin()
    // transition that admission performed) factory-security fact.
  }
  ASSERT_EQ(CampaignCommissioningState::Used, commissioning.readCommissioningProvenance().state);

  // Simulate the main record being lost/corrupted away out-of-band (NOT
  // via the sanctioned erase()+repair-authorization-record path) -- no
  // repair-authorization record exists to explain this loss.
  persistence.store.erase(CampaignPersistRole::TargetReceiver);
  ASSERT_EQ(0u, persistence.store.count(CampaignPersistRole::TargetRepairAuthorization));

  // A completely COLD engine reconstruction: fresh trust/staging/engine,
  // zero RAM memory of the above admission.
  FakeStagingSink staging2;
  TargetReceiverEngine target2(trust, staging2, persistence, boot, consent, commissioning);
  EXPECT_FALSE(target2.reload());
  EXPECT_TRUE(target2.isReloadUnsafe());
  EXPECT_FALSE(target2.isControllerBound());  // no RAM memory of the specific binding...

  // ...but new admission is STILL correctly refused, proving the freeze
  // is real and not merely a cosmetic isControllerBound()==false.
  runtime::OtaSessionId newSession{82, 1, 1};
  AuthenticatedInboundFrame newFrame = makeInboundFrame({}, controller_);
  EXPECT_FALSE(target2.handleConsentRequest(newFrame, 1, newSession, makeConsentPayload(controller_), descriptor_,
                                             sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::UnresolvedPersistedState, target2.lastRefusal());
}

// THE core corrected-blank-heuristic outcome: losing BOTH the main
// campaign record AND the independent commissioning-provenance backing
// (Unknown -- e.g. never provisioned, or the backing itself is lost)
// must ALWAYS freeze, even with a totally fresh engine object and zero
// RAM memory. A Missing main record must NEVER be conflated with
// "provably virgin" merely because nothing else is known either --
// only a POSITIVE, independently-verified Virgin result licenses fresh
// Idle (see GenuinelyVirginDeviceReloadsFreshFromPositiveFactoryProof
// below for the genuinely-safe contrasting case).
TEST_F(DirectedE2ETest, ColdReconstructionWithUnknownCommissioningProvenanceFreezesEvenWithNoRamMemory) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;                // main record never saved
  FakeCommissioningProvenancePort commissioning; // never provisioned: Unknown by construction
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  ASSERT_EQ(CampaignCommissioningState::Unknown, commissioning.readCommissioningProvenance().state);

  EXPECT_FALSE(target.reload());
  EXPECT_TRUE(target.isReloadUnsafe());

  runtime::OtaSessionId session{85, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  EXPECT_FALSE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                            sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::UnresolvedPersistedState, target.lastRefusal());
}

// The abstract port's own base class (no override at all -- exactly
// what a real integration gets before any real factory/security backing
// is wired) IS the safe default, and must refuse on both entry points
// directly, not merely via the engine's own interpretation of Unknown.
TEST(CampaignCommissioningProvenanceDefaultTest, BaseClassRefusesByDefaultWithoutAnyOverride) {
  ICampaignCommissioningProvenancePort defaultPort;
  EXPECT_EQ(CampaignCommissioningState::Unknown, defaultPort.readCommissioningProvenance().state);
  EXPECT_EQ(CampaignMarkUsedResult::Rejected, defaultPort.markUsedIfCurrentlyVirgin());
}

// A genuinely virgin device -- POSITIVELY verified via a real,
// identity-bound factory record (never inferred from any blob's
// absence) -- reloads fresh from a Missing main record, and a
// subsequent admission durably transitions it to Used.
TEST_F(DirectedE2ETest, GenuinelyVirginDeviceReloadsFreshFromPositiveFactoryProof) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;  // main record never saved
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  EXPECT_TRUE(target.reload());
  EXPECT_FALSE(target.isReloadUnsafe());
  EXPECT_FALSE(target.isControllerBound());

  // A record bound to a DIFFERENT device's identity must never be
  // mistaken for genuine local proof, even if otherwise well-formed.
  FakeCommissioningProvenancePort foreignBacked;
  foreignBacked.simulateForeignIdentityRecord(FakeCommissioningProvenancePort::kMarkerVirgin);
  EXPECT_EQ(CampaignCommissioningState::Unknown, foreignBacked.readCommissioningProvenance().state);

  runtime::OtaSessionId session{86, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignCommissioningState::Used, commissioning.readCommissioningProvenance().state);
}

// Repair (acknowledgeUnsafeReloadAndReset()) must: (a) refuse outright
// while commissioning provenance is Unknown (never erase the main
// record without a known commissioning fact to reason about), (b) for
// an already-Used device, additionally require a durably-CONFIRMED
// repair-authorization record before clearing the freeze -- an erased
// main record with an unconfirmed repair-authorization write must stay
// latched, and (c) NEVER touch/erase the commissioning-provenance port's
// own independent security/factory facts -- those must survive a
// campaign-record repair completely unchanged.
TEST_F(DirectedE2ETest, UnknownCommissioningCannotRetireExistingRepairGrant) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  ICampaignCommissioningProvenancePort unknown;
  uint8_t repair[kCampaignRepairAuthEncodedSize];
  size_t repair_len = 0;
  ASSERT_TRUE(encodeCampaignRepairAuthorization(repair, sizeof(repair), repair_len));
  ASSERT_EQ(CampaignSaveResult::Saved,
            persistence.save(CampaignPersistRole::TargetRepairAuthorization, repair, repair_len));
  const auto before = persistence.store;
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, unknown);
  runtime::OtaSessionId session{83, 1, 1};
  AuthenticatedInboundFrame frame = makeInboundFrame({}, controller_);
  EXPECT_FALSE(target.handleConsentRequest(frame, 1, session, makeConsentPayload(controller_), descriptor_,
                                           sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::CommissioningProvenanceUnknown, target.lastRefusal());
  EXPECT_EQ(before, persistence.store);
  EXPECT_EQ(0u, staging.beginSessionCallCount);
}

TEST_F(DirectedE2ETest, RepairRetirementCutsFreezeAndColdReloadUsesActualDurableTruth) {
  for (bool applied : {false, true}) {
    SCOPED_TRACE(applied);
    FakeTrust trust;
    FakeStagingSink staging;
    FakePersistence persistence;
    FakeBootEvidence boot;
    FakeConsentPolicy consent;
    FakeCommissioningProvenancePort commissioning;
    commissioning.initializeGenuineFactoryVirgin();
    persistence.store[CampaignPersistRole::UpdaterCache] = {0x51, 0x52, 0x53};
    TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
    runtime::OtaSessionId session{83, 1, 1};
    AuthenticatedInboundFrame frame = makeInboundFrame({}, controller_);
    ASSERT_TRUE(target.handleConsentRequest(frame, 1, session, makeConsentPayload(controller_), descriptor_,
                                            sig_.data(), sig_.size()));
    persistence.forceCorrupt = true;
    ASSERT_FALSE(target.reload());
    persistence.forceCorrupt = false;
    ASSERT_TRUE(target.acknowledgeUnsafeReloadAndReset());
    const auto image_before = staging.image;
    const auto begins_before = staging.beginSessionCallCount;
    auto expected = persistence.store;
    if (applied) expected.erase(CampaignPersistRole::TargetRepairAuthorization);
    persistence.forceEraseFailForRoleActive = true;
    persistence.forceEraseFailForRole = CampaignPersistRole::TargetRepairAuthorization;
    persistence.forceEraseAppliedBeforeFailure = applied;
    ++session.sessionId;
    EXPECT_FALSE(target.handleConsentRequest(frame, 2, session, makeConsentPayload(controller_), descriptor_,
                                             sig_.data(), sig_.size()));
    EXPECT_TRUE(target.isPersistUncertain());
    EXPECT_EQ(CampaignRefusalReason::RepairAuthorizationRetirementUnconfirmed, target.lastRefusal());
    EXPECT_EQ(expected, persistence.store);
    EXPECT_EQ(image_before, staging.image);
    EXPECT_EQ(begins_before, staging.beginSessionCallCount);
    EXPECT_EQ(CampaignCommissioningState::Used, commissioning.readCommissioningProvenance().state);
    EXPECT_FALSE(target.handleConsentRequest(frame, 3, session, makeConsentPayload(controller_), descriptor_,
                                             sig_.data(), sig_.size()));
    EXPECT_EQ(expected, persistence.store);
    FakeStagingSink fresh;
    TargetReceiverEngine cold(trust, fresh, persistence, boot, consent, commissioning);
    EXPECT_EQ(!applied, cold.reload());
    EXPECT_EQ(applied, cold.isReloadUnsafe());
    EXPECT_EQ(0u, fresh.beginSessionCallCount);
  }
}

TEST_F(DirectedE2ETest, OldRepairCannotAuthorizeLossOfLaterAdmittedCampaign) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{83, 1, 1};
  AuthenticatedInboundFrame frame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(frame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  persistence.forceCorrupt = true;
  ASSERT_FALSE(target.reload());
  persistence.forceCorrupt = false;
  ASSERT_TRUE(target.acknowledgeUnsafeReloadAndReset());
  ASSERT_TRUE(target.reload());

  ++session.sessionId;
  ASSERT_TRUE(target.handleConsentRequest(frame, 2, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  persistence.store.erase(CampaignPersistRole::TargetReceiver);
  FakeStagingSink fresh_staging;
  TargetReceiverEngine cold(trust, fresh_staging, persistence, boot, consent, commissioning);
  EXPECT_FALSE(cold.reload());
  EXPECT_TRUE(cold.isReloadUnsafe());
  ++session.sessionId;
  EXPECT_FALSE(cold.handleConsentRequest(frame, 3, session, makeConsentPayload(controller_), descriptor_,
                                         sig_.data(), sig_.size()));
  EXPECT_EQ(0u, fresh_staging.beginSessionCallCount);
}

TEST_F(DirectedE2ETest, RepairPreservesCommissioningProvenanceAndRequiresConfirmedRepairRecord) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{83, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  ASSERT_EQ(CampaignCommissioningState::Used, commissioning.readCommissioningProvenance().state);
  persistence.forceCorrupt = true;  // main record now reports unreadable
  ASSERT_FALSE(target.reload());
  ASSERT_TRUE(target.isReloadUnsafe());
  persistence.forceCorrupt = false;

  // With commissioning provenance Unknown, repair must refuse WITHOUT
  // even attempting the main record's erase.
  commissioning.forceUnknown = true;
  EXPECT_FALSE(target.acknowledgeUnsafeReloadAndReset());
  EXPECT_TRUE(target.isReloadUnsafe());
  EXPECT_EQ(1u, persistence.store.count(CampaignPersistRole::TargetReceiver));
  commissioning.forceUnknown = false;

  // Commissioning is (genuinely, positively) Used again: repair attempt
  // whose repair-authorization record write cannot be confirmed leaves
  // the whole repair incomplete -- stays latched, even though the main
  // record itself WAS erased.
  persistence.forceRejectNextSaveForRoleActive = true;
  persistence.forceRejectNextSaveForRole = CampaignPersistRole::TargetRepairAuthorization;
  EXPECT_FALSE(target.acknowledgeUnsafeReloadAndReset());
  EXPECT_TRUE(target.isReloadUnsafe());
  EXPECT_EQ(0u, persistence.store.count(CampaignPersistRole::TargetReceiver));
  EXPECT_EQ(0u, persistence.store.count(CampaignPersistRole::TargetRepairAuthorization));
  // The commissioning-provenance port itself was NEVER touched by the
  // repair attempt -- security/factory history survives unconditionally.
  EXPECT_EQ(CampaignCommissioningState::Used, commissioning.readCommissioningProvenance().state);

  // Now the repair-authorization record write succeeds: repair
  // completes, guard clears, and a subsequent reload() resolves this as
  // an authorized-Idle-with-known-history device (not virgin -- the
  // commissioning-provenance fact is still, correctly, Used).
  EXPECT_TRUE(target.acknowledgeUnsafeReloadAndReset());
  EXPECT_FALSE(target.isReloadUnsafe());
  EXPECT_EQ(1u, persistence.store.count(CampaignPersistRole::TargetRepairAuthorization));
  EXPECT_EQ(CampaignCommissioningState::Used, commissioning.readCommissioningProvenance().state);
  EXPECT_TRUE(target.reload());
  EXPECT_FALSE(target.isReloadUnsafe());
  EXPECT_FALSE(target.isControllerBound());

  // A brand-new, cold engine reconstruction over this exact durable
  // state independently confirms the same authorized-fresh outcome --
  // proving it is not merely an artifact of this instance's RAM.
  FakeStagingSink staging2;
  TargetReceiverEngine reconstructed(trust, staging2, persistence, boot, consent, commissioning);
  EXPECT_TRUE(reconstructed.reload());
  EXPECT_FALSE(reconstructed.isReloadUnsafe());
  EXPECT_FALSE(reconstructed.isControllerBound());
}

// The freeze latched by an unresolved persisted state must ALSO block
// tick()'s queued-reply retry path, not just new-mutation entry points:
// a reply queued BEFORE the fault must not be allowed to progress while
// frozen.
TEST_F(DirectedE2ETest, TickDoesNotRetryQueuedReplyWhileUnresolvedPersistenceIsLatched) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  FakeTransport transport;
  FakeClock clock;
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  target.bindTransport(transport);
  target.bindClock(clock);
  runtime::OtaSessionId session{84, 1, 1};

  // Admit normally first (no fault yet).
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));

  // Force chunk 0's Receipt reply to hit Backpressure so it becomes a
  // genuinely queued pending reply (not yet actually sent).
  uint32_t len0 = 0;
  ASSERT_TRUE(target.geometry().chunkLength(0, len0));
  std::vector<uint8_t> data0(len0, 0xCC);
  auto chunkFrame0 = encodeChunkFrame(session, 2, 0, data0.data(), data0.size());
  AuthenticatedInboundFrame inbound0 = makeInboundFrame(chunkFrame0, controller_);
  transport.forcedResults.push_back(CampaignSendResult::Backpressure);
  ASSERT_TRUE(target.onFrame(inbound0));
  ASSERT_TRUE(transport.sentLog.empty());  // genuinely queued, not yet actually sent

  // Now latch an unresolved-persistence freeze via an unrelated
  // Uncertain chunk-apply save.
  uint32_t len1 = 0;
  ASSERT_TRUE(target.geometry().chunkLength(1, len1));
  std::vector<uint8_t> data1(len1, 0xDD);
  protocol::OtaChunkHeader hdr1{1, static_cast<uint16_t>(len1)};
  persistence.forceUncertainNextSave = true;
  AuthenticatedInboundFrame chunkFrame1 = makeInboundFrame({}, controller_);
  ASSERT_FALSE(target.applyChunk(chunkFrame1, 3, session, hdr1, data1.data(), data1.size()));
  ASSERT_TRUE(target.isPersistUncertain());

  // tick() must NOT emit the still-queued (pre-fault) reply while frozen,
  // even well past the ordinary retry deadline.
  clock.advance(100000);
  target.tick();
  target.tick();
  EXPECT_TRUE(transport.sentLog.empty());
}

// An Uncertain result during the VERY FIRST admission (a beginSession()
// that a real production sink may have durably, destructively started)
// must never be papered over by calling staging_.abort() -- that would
// destroy real backing bytes an authoritative reload() might later find
// genuinely durable. Proves the sink is left untouched (never aborted)
// on this specific path, distinct from a RejectedBeforeMutation refusal
// (which correctly DOES roll back the reversible staging side effect).
TEST_F(DirectedE2ETest, UncertainDuringInitialAdmissionNeverAbortsPossiblyDurableStagingSession) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{73, 1, 1};

  persistence.forceUncertainNextSaveForRoleActive = true;
  persistence.forceUncertainNextSaveForRole = CampaignPersistRole::TargetReceiver;
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  EXPECT_FALSE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                            sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::PersistenceFailed, target.lastRefusal());
  EXPECT_TRUE(target.isPersistUncertain());
  EXPECT_TRUE(staging.began);     // beginSession() really happened
  EXPECT_FALSE(staging.aborted);  // and was NEVER rolled back -- may be the real durable checkpoint

  // Contrast: a RejectedBeforeMutation refusal on the SAME kind of first
  // admission attempt (fresh engine/session) DOES roll the reversible
  // staging side effect back, since the durable record is PROVABLY
  // unchanged there.
  FakeStagingSink staging2;
  FakePersistence persistence2;
  TargetReceiverEngine target2(trust, staging2, persistence2, boot, consent, commissioning);
  persistence2.forceRejectNextSaveForRoleActive = true;
  persistence2.forceRejectNextSaveForRole = CampaignPersistRole::TargetReceiver;
  runtime::OtaSessionId session2{74, 1, 1};
  AuthenticatedInboundFrame consentFrame2 = makeInboundFrame({}, controller_);
  EXPECT_FALSE(target2.handleConsentRequest(consentFrame2, 1, session2, makeConsentPayload(controller_), descriptor_,
                                             sig_.data(), sig_.size()));
  EXPECT_FALSE(target2.isPersistUncertain());
  EXPECT_TRUE(staging2.began);
  EXPECT_TRUE(staging2.aborted);
}

// Proves the freeze latched by an Uncertain/Corrupt/IoError persisted
// state genuinely blocks EVERY mutating entry point -- not merely
// handleConsentRequest (already covered by
// UncertainSaveFreezesAdmissionUntilReloadReconstructsRealDurableState)
// -- including descriptor-fragment reassembly, chunk application,
// verify/commit and abort.
TEST_F(DirectedE2ETest, UnresolvedPersistenceFreezeBlocksEveryMutatingEntryPointNotJustConsent) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{75, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));

  // Latch the freeze via an Uncertain chunk-apply save.
  uint32_t len0 = 0;
  ASSERT_TRUE(target.geometry().chunkLength(0, len0));
  std::vector<uint8_t> data0(len0, 0xAA);
  protocol::OtaChunkHeader hdr0{0, static_cast<uint16_t>(len0)};
  persistence.forceUncertainNextSave = true;
  AuthenticatedInboundFrame chunkFrame0 = makeInboundFrame({}, controller_);
  ASSERT_FALSE(target.applyChunk(chunkFrame0, 2, session, hdr0, data0.data(), data0.size()));
  ASSERT_TRUE(target.isPersistUncertain());

  // beginPendingConsent / onDescriptorFragment.
  AuthenticatedInboundFrame anotherConsentFrame = makeInboundFrame({}, controller_);
  EXPECT_FALSE(target.beginPendingConsent(anotherConsentFrame, session, makeConsentPayload(controller_)));
  AuthenticatedInboundFrame fragFrame = makeInboundFrame({}, controller_);
  EXPECT_FALSE(target.onDescriptorFragment(fragFrame, 3, session, 0, 1, 1, 1,
                                            reinterpret_cast<const uint8_t*>("x"), 1));

  // applyChunk (a genuinely new chunk index, distinct from the one above).
  uint32_t len1 = 0;
  ASSERT_TRUE(target.geometry().chunkLength(1, len1));
  std::vector<uint8_t> data1(len1, 0xBB);
  protocol::OtaChunkHeader hdr1{1, static_cast<uint16_t>(len1)};
  AuthenticatedInboundFrame chunkFrame1 = makeInboundFrame({}, controller_);
  EXPECT_FALSE(target.applyChunk(chunkFrame1, 4, session, hdr1, data1.data(), data1.size()));

  // verifyAndCommit / abort.
  AuthenticatedInboundFrame commitFrame = makeInboundFrame({}, controller_);
  EXPECT_FALSE(target.verifyAndCommit(commitFrame, session));
  AuthenticatedInboundFrame abortFrame = makeInboundFrame({}, controller_);
  EXPECT_FALSE(target.abort(abortFrame, session));

  // confirmHealthyBoot (already gated pre-existing, re-checked alongside
  // the rest here for one consolidated proof).
  EXPECT_FALSE(target.confirmHealthyBoot());

  for (auto reason : {target.lastRefusal()}) {
    (void)reason; // lastRefusal_ is overwritten by each call above; the
                  // important invariant already asserted per-call is
                  // that every one of them returned false while frozen.
  }
}

// A reload() authoritatively re-derives ALL runtime state from the
// durable winning record -- any pending descriptor-fragment reassembly
// or queued outbound reply that predates it must not survive to
// complete/retry against stale bindings afterwards.
TEST_F(DirectedE2ETest, PendingReassemblyAndQueuedReplyDoNotSurviveReload) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{76, 1, 1};

  // Open a pending descriptor-fragment reassembly, but never complete
  // it before reload() runs.
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.beginPendingConsent(consentFrame, session, makeConsentPayload(controller_)));

  ASSERT_TRUE(target.reload()); // nothing durable yet -> Missing -> fresh idle, but must ALSO clear pending state

  // Feeding the (now stale) reassembly's fragment must no longer
  // silently resume where it left off -- the pending session was
  // cleared by reload().
  AuthenticatedInboundFrame fragFrame = makeInboundFrame({}, controller_);
  EXPECT_FALSE(target.onDescriptorFragment(fragFrame, 1, session, 0, 1, 1, 1,
                                            reinterpret_cast<const uint8_t*>("x"), 1));
}

// =======================================================================
// Pure explicit-byte-codec tests for CampaignTargetPersistedState's
// encode/decode pair (encodeCampaignTargetPersistedState()/
// decodeCampaignTargetPersistedState() in TargetReceiverEngine.h),
// exercised directly with NO TargetReceiverEngine instance involved.
// These prove the persisted format is an explicit, portable, versioned,
// fixed-endian byte encoding independent of any compiler's native struct
// layout (no sizeof(struct)/offsetof/memcpy-of-struct anywhere): a
// "fresh decode" here constructs a BRAND NEW, default-initialized DTO on
// the SAME process, but the codec itself is agnostic to that -- it goes
// through the exact same OtaBoundedReader field-by-field big-endian
// decode this component's `reload()` uses for a genuine cross-process/
// cross-build reboot.
class TargetPersistCodecTest : public ::testing::Test {
protected:
  // Builds a fully-populated, internally-consistent, VALID fixture
  // record with every field set to a distinguishable, non-default,
  // non-zero-ambiguous value (so a decode bug that swaps/mis-sizes two
  // adjacent fields would visibly fail the round-trip comparison, not
  // coincidentally still match).
  CampaignTargetPersistedState makeFixture() {
    CampaignTargetPersistedState s{};
    s.session = runtime::OtaSessionId{0x11223344u, 0x55667788u, 0x99AAu};
    for (size_t i = 0; i < sizeof(s.controllerId); ++i) s.controllerId[i] = static_cast<uint8_t>(0xC0 + i);
    s.groupId = 0xDEADBEEFu;
    protocol::OtaDescriptor d = makeDescriptor(128 * 5 + 37, 7);
    size_t canonicalLen = 0;
    EXPECT_EQ(protocol::OtaDescriptorCodecResult::Ok,
              protocol::encodeOtaDescriptorCanonical(d, s.descriptorCanonical, sizeof(s.descriptorCanonical),
                                                       canonicalLen));
    EXPECT_EQ(protocol::kOtaDescriptorCanonicalSize, canonicalLen);
    for (size_t i = 0; i < sizeof(s.signature); ++i) s.signature[i] = static_cast<uint8_t>(0x30 + i);
    s.signatureLen = ::ota::trust::Ed25519SignatureVerifier::kSignatureBytes; // exactly 64
    s.phase = static_cast<uint8_t>(TargetStatus::Receiving);
    s.lastFrameSeq = 0x1357u;
    s.replayWindowMask = 0x0Fu;
    runtime::OtaGeometry geometry;
    EXPECT_EQ(runtime::OtaGeometryResult::Ok,
              runtime::OtaGeometry::compute(d.exactSizeBytes, runtime::kOtaDefaultChunkPayloadSize,
                                            runtime::kOtaMaxImageBytes, geometry));
    s.chunkCount = geometry.chunkCount; // 6 chunks for this size
    s.bound = 1;
    s.everBound = 1;
    // Set exactly the first chunkCount bits, leaving every tail bit 0 --
    // a genuinely valid record, not merely "happens to pass".
    for (uint32_t i = 0; i < s.chunkCount; ++i) s.bitmap[i / 8] |= static_cast<uint8_t>(1u << (i % 8));
    return s;
  }

  std::vector<uint8_t> encodeFixture(const CampaignTargetPersistedState& s) {
    std::vector<uint8_t> buf(kCampaignTargetPersistEncodedSize);
    size_t len = 0;
    EXPECT_TRUE(encodeCampaignTargetPersistedState(s, buf.data(), buf.size(), len));
    EXPECT_EQ(kCampaignTargetPersistEncodedSize, len);
    return buf;
  }

  // Recomputes and overwrites the trailing CRC32 over a mutated buffer,
  // so a test can isolate exactly ONE structural validation rule (e.g.
  // "bound must be 0 or 1") without the CRC check firing first and
  // masking which specific rule actually caught the corruption.
  void recomputeCrc(std::vector<uint8_t>& buf) {
    ASSERT_EQ(kCampaignTargetPersistEncodedSize, buf.size());
    const size_t crcCoveredLen = buf.size() - 4;
    const uint32_t crc = ::ota::storage::Crc32::computeFinalized(buf.data(), crcCoveredLen);
    buf[crcCoveredLen + 0] = static_cast<uint8_t>(crc >> 24);
    buf[crcCoveredLen + 1] = static_cast<uint8_t>(crc >> 16);
    buf[crcCoveredLen + 2] = static_cast<uint8_t>(crc >> 8);
    buf[crcCoveredLen + 3] = static_cast<uint8_t>(crc);
  }
};

TEST_F(TargetPersistCodecTest, RoundTripPreservesEveryFieldOnAFreshDecodeTarget) {
  CampaignTargetPersistedState original = makeFixture();
  std::vector<uint8_t> encoded = encodeFixture(original);

  // A BRAND NEW, default-constructed DTO -- decode must derive every
  // field purely from the bytes, with zero reliance on any prior value
  // (proves this is a genuine fresh decode, not an in-place patch of an
  // already-populated struct).
  CampaignTargetPersistedState decoded{};
  ASSERT_TRUE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));

  EXPECT_EQ(original.magic, decoded.magic);
  EXPECT_EQ(original.version, decoded.version);
  EXPECT_EQ(original.session.campaignId, decoded.session.campaignId);
  EXPECT_EQ(original.session.sessionId, decoded.session.sessionId);
  EXPECT_EQ(original.session.attemptId, decoded.session.attemptId);
  EXPECT_EQ(0, std::memcmp(original.controllerId, decoded.controllerId, sizeof(original.controllerId)));
  EXPECT_EQ(original.groupId, decoded.groupId);
  EXPECT_EQ(0, std::memcmp(original.descriptorCanonical, decoded.descriptorCanonical,
                           sizeof(original.descriptorCanonical)));
  EXPECT_EQ(0, std::memcmp(original.signature, decoded.signature, sizeof(original.signature)));
  EXPECT_EQ(original.signatureLen, decoded.signatureLen);
  EXPECT_EQ(original.phase, decoded.phase);
  EXPECT_EQ(original.lastFrameSeq, decoded.lastFrameSeq);
  EXPECT_EQ(original.replayWindowMask, decoded.replayWindowMask);
  EXPECT_EQ(original.chunkCount, decoded.chunkCount);
  EXPECT_EQ(original.bound, decoded.bound);
  EXPECT_EQ(original.everBound, decoded.everBound);
  EXPECT_EQ(0, std::memcmp(original.bitmap, decoded.bitmap, sizeof(original.bitmap)));
}

TEST_F(TargetPersistCodecTest, TruncatedRecordOneByteShortIsRejected) {
  std::vector<uint8_t> encoded = encodeFixture(makeFixture());
  encoded.pop_back();
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
}

TEST_F(TargetPersistCodecTest, ExtraTrailingByteRecordIsRejected) {
  std::vector<uint8_t> encoded = encodeFixture(makeFixture());
  encoded.push_back(0x00);
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
}

TEST_F(TargetPersistCodecTest, CrcMismatchWithoutRecomputeIsRejected) {
  std::vector<uint8_t> encoded = encodeFixture(makeFixture());
  encoded[20] ^= 0xFFu; // flips a byte inside controllerId, CRC deliberately left stale
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
}

TEST_F(TargetPersistCodecTest, WrongVersionIsRejectedEvenWithValidCrc) {
  std::vector<uint8_t> encoded = encodeFixture(makeFixture());
  // version is the u16 at header offset 4..5 (after magic's 4 bytes).
  encoded[4] = 0x00;
  encoded[5] = 0x63; // some other plausible-looking version number
  recomputeCrc(encoded);
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
}

TEST_F(TargetPersistCodecTest, NonZeroReservedHeaderFieldIsRejectedEvenWithValidCrc) {
  std::vector<uint8_t> encoded = encodeFixture(makeFixture());
  // reserved is the u16 at header offset 6..7.
  encoded[6] = 0x00;
  encoded[7] = 0x01;
  recomputeCrc(encoded);
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
}

TEST_F(TargetPersistCodecTest, BodyLengthMismatchHeaderFieldIsRejectedEvenWithValidCrc) {
  std::vector<uint8_t> encoded = encodeFixture(makeFixture());
  // bodyLength is the u16 at header offset 8..9.
  encoded[8] = 0xFFu;
  encoded[9] = 0xFFu;
  recomputeCrc(encoded);
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
}

TEST_F(TargetPersistCodecTest, BadBoundFlagValueIsRejectedEvenWithValidCrc) {
  CampaignTargetPersistedState s = makeFixture();
  s.bound = 2; // neither 0 nor 1
  std::vector<uint8_t> encoded(kCampaignTargetPersistEncodedSize);
  size_t len = 0;
  // encodeCampaignTargetPersistedState() itself has no opinion on `bound`
  // being a strict boolean (it faithfully encodes whatever byte value is
  // given) -- the strictness is entirely decode()'s job, exercised here.
  ASSERT_TRUE(encodeCampaignTargetPersistedState(s, encoded.data(), encoded.size(), len));
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
}

TEST_F(TargetPersistCodecTest, BadEverBoundFlagValueIsRejectedEvenWithValidCrc) {
  CampaignTargetPersistedState s = makeFixture();
  s.everBound = 0xFFu;
  std::vector<uint8_t> encoded(kCampaignTargetPersistEncodedSize);
  size_t len = 0;
  ASSERT_TRUE(encodeCampaignTargetPersistedState(s, encoded.data(), encoded.size(), len));
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
}

TEST_F(TargetPersistCodecTest, ShortSignatureLengthOnABoundRecordIsRejectedEvenWithValidCrc) {
  CampaignTargetPersistedState s = makeFixture();
  ASSERT_EQ(1u, s.bound);
  s.signatureLen = 63; // one byte short of Ed25519's fixed 64
  std::vector<uint8_t> encoded(kCampaignTargetPersistEncodedSize);
  size_t len = 0;
  ASSERT_TRUE(encodeCampaignTargetPersistedState(s, encoded.data(), encoded.size(), len));
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
}

TEST_F(TargetPersistCodecTest, OversizedSignatureLengthOnABoundRecordIsRejectedEvenWithValidCrc) {
  CampaignTargetPersistedState s = makeFixture();
  s.signatureLen = 64 + 1; // still within the fixed 64-byte buffer, but not a valid Ed25519 length
  std::vector<uint8_t> encoded(kCampaignTargetPersistEncodedSize);
  size_t len = 0;
  ASSERT_TRUE(encodeCampaignTargetPersistedState(s, encoded.data(), encoded.size(), len));
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
}

TEST_F(TargetPersistCodecTest, CorruptGeometryChunkCountBeyondBitmapCapacityIsRejectedEvenWithValidCrc) {
  CampaignTargetPersistedState s = makeFixture();
  s.chunkCount = runtime::kOtaMaxChunkCount + 1; // beyond the real bitmap's addressable capacity
  std::vector<uint8_t> encoded(kCampaignTargetPersistEncodedSize);
  size_t len = 0;
  ASSERT_TRUE(encodeCampaignTargetPersistedState(s, encoded.data(), encoded.size(), len));
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
}

TEST_F(TargetPersistCodecTest, PhantomBitmapBitBeyondDeclaredChunkCountIsRejectedEvenWithValidCrc) {
  CampaignTargetPersistedState s = makeFixture();
  ASSERT_LT(s.chunkCount, static_cast<uint32_t>(kCampaignBitmapByteCapacity * 8));
  // Set a bit strictly beyond the declared chunkCount -- a corrupt/
  // hostile record claiming a received chunk the geometry doesn't have.
  const uint32_t phantomBit = s.chunkCount;
  s.bitmap[phantomBit / 8] |= static_cast<uint8_t>(1u << (phantomBit % 8));
  std::vector<uint8_t> encoded(kCampaignTargetPersistEncodedSize);
  size_t len = 0;
  ASSERT_TRUE(encodeCampaignTargetPersistedState(s, encoded.data(), encoded.size(), len));
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
}

TEST_F(TargetPersistCodecTest, ValidZeroFlagsUnboundRecordRoundTrips) {
  // The other polarity of the strict-boolean check: 0/0 (never bound) is
  // exactly as valid as 1/1, and must decode cleanly.
  CampaignTargetPersistedState s{};
  s.bound = 0;
  s.everBound = 0;
  s.signatureLen = 0; // no signature is expected/validated for a never-bound record
  std::vector<uint8_t> encoded = encodeFixture(s);
  CampaignTargetPersistedState decoded{};
  EXPECT_TRUE(decodeCampaignTargetPersistedState(encoded.data(), encoded.size(), decoded));
  EXPECT_EQ(0u, decoded.bound);
  EXPECT_EQ(0u, decoded.everBound);
}

// Asserts LITERAL expected bytes at known fixed offsets for a fully
// known fixture. The round-trip test above only proves encode+decode
// AGREE with each other -- it would still pass if both shared the same
// wrong offset/width assumption for a field. This test independently
// pins the actual on-wire byte layout against values computed by hand
// from the documented header/body layout, so a mutation that shifts a
// field (while keeping encode/decode internally consistent) fails here.
TEST_F(TargetPersistCodecTest, GoldenHeaderAndFieldByteLayoutMatchesDocumentedOffsets) {
  CampaignTargetPersistedState s{};
  s.session = runtime::OtaSessionId{0xAABBCCDDu, 0x11223344u, 0x5566u};
  s.controllerId[0] = 0xEEu;
  s.controllerId[31] = 0x11u;
  s.groupId = 0x01020304u;
  s.phase = 3;
  s.lastFrameSeq = 0x01020304u;
  s.bound = 0;
  s.everBound = 0;
  s.signatureLen = 0;
  std::vector<uint8_t> encoded = encodeFixture(s);

  // Header: magic(4) + version(2) + reserved(2) + bodyLength(2).
  const uint8_t expectedHeader[10] = {0x54, 0x41, 0x52, 0x43,  // "TARC" magic
                                      0x00, 0x05,              // version 5
                                      0x00, 0x00,              // reserved, must be 0
                                      0x03, 0x6D};             // bodyLength 877 (0x036D)
  EXPECT_EQ(0, std::memcmp(expectedHeader, encoded.data(), sizeof(expectedHeader)));

  // Body offsets, per the documented layout comment above
  // kCampaignTargetPersistBodySize: campaignId(4)@10, sessionId(4)@14,
  // attemptId(2)@18, controllerId(32)@20, groupId(4)@52,
  // descriptorCanonical(59)@56, signature(64)@115, signatureLen(1)@179,
  // phase(1)@180, lastFrameSeq(4)@181.
  const uint8_t expectedCampaignId[4] = {0xAA, 0xBB, 0xCC, 0xDD};
  EXPECT_EQ(0, std::memcmp(expectedCampaignId, &encoded[10], sizeof(expectedCampaignId)));
  const uint8_t expectedSessionId[4] = {0x11, 0x22, 0x33, 0x44};
  EXPECT_EQ(0, std::memcmp(expectedSessionId, &encoded[14], sizeof(expectedSessionId)));
  const uint8_t expectedAttemptId[2] = {0x55, 0x66};
  EXPECT_EQ(0, std::memcmp(expectedAttemptId, &encoded[18], sizeof(expectedAttemptId)));
  EXPECT_EQ(0xEEu, encoded[20]);  // controllerId[0]
  EXPECT_EQ(0x11u, encoded[51]); // controllerId[31]
  const uint8_t expectedGroupId[4] = {0x01, 0x02, 0x03, 0x04};
  EXPECT_EQ(0, std::memcmp(expectedGroupId, &encoded[52], sizeof(expectedGroupId)));
  EXPECT_EQ(0u, encoded[179]);   // signatureLen
  EXPECT_EQ(3u, encoded[180]);   // phase
  const uint8_t expectedLastFrameSeq[4] = {0x01, 0x02, 0x03, 0x04};
  EXPECT_EQ(0, std::memcmp(expectedLastFrameSeq, &encoded[181], sizeof(expectedLastFrameSeq)));
}

TEST_F(TargetPersistCodecTest, EncodeRejectsNullDestinationWithoutDereferencing) {
  CampaignTargetPersistedState s = makeFixture();
  size_t len = 12345; // sentinel, must not be touched on a rejected call... verified below is false-return only
  EXPECT_FALSE(encodeCampaignTargetPersistedState(s, nullptr, kCampaignTargetPersistEncodedSize, len));
}

TEST_F(TargetPersistCodecTest, DecodeRejectsNullSourceWithoutDereferencing) {
  CampaignTargetPersistedState decoded{};
  EXPECT_FALSE(decodeCampaignTargetPersistedState(nullptr, kCampaignTargetPersistEncodedSize, decoded));
}

TEST_F(DirectedE2ETest, InvalidSignatureRejectedBeforeReplayGuardConsumed) {
  FakeTrust trust;
  trust.descriptorValid = false;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{13, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_FALSE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                           sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::DescriptorInvalid, target.lastRefusal());
  EXPECT_FALSE(target.isControllerBound());

  // Replay guard must NOT have been burned: a subsequent VALID request for
  // the exact same session id must still be admitted.
  trust.descriptorValid = true;
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 2, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  EXPECT_TRUE(target.isControllerBound());
}

TEST_F(DirectedE2ETest, DuplicateExactTupleIsIdempotentDifferentDescriptorRejected) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{15, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));

  // Exact resend of the same (session, controller, descriptor) tuple:
  // idempotent success, preserving already-received bytes.
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 2, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));

  // Same tuple, DIFFERENT descriptor content: rejected outright.
  protocol::OtaDescriptor different = descriptor_;
  different.exactSizeBytes += 128;
  ASSERT_FALSE(target.handleConsentRequest(consentFrame, 3, session, makeConsentPayload(controller_), different,
                                           sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::DescriptorConflict, target.lastRefusal());
}

TEST_F(DirectedE2ETest, CompetingNonTerminalSessionSameControllerCannotEraseBoundCandidate) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{20, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));

  // Receive one real chunk so there is genuine in-flight progress that
  // must not be erased.
  uint32_t len = 0;
  ASSERT_TRUE(target.geometry().chunkLength(0, len));
  std::vector<uint8_t> data(len, 7);
  protocol::OtaChunkHeader hdr{0, static_cast<uint16_t>(len)};
  ASSERT_TRUE(target.applyChunk(consentFrame, 2, session, hdr, data.data(), data.size()));
  ASSERT_EQ(1u, target.receivedChunkCount());

  // SAME controller, a brand-new (newer) session id, while the existing
  // binding is still Receiving (non-terminal): must be rejected outright,
  // not silently rebind and erase the already-received chunk/authorization.
  runtime::OtaSessionId newerSession{21, 1, 1};
  ASSERT_FALSE(target.handleConsentRequest(consentFrame, 3, newerSession, makeConsentPayload(controller_),
                                           descriptor_, sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::ForeignSession, target.lastRefusal());
  // Original binding/progress must be completely intact.
  EXPECT_EQ(controller_, target.boundController());
  EXPECT_EQ(1u, target.receivedChunkCount());
  EXPECT_EQ(TargetStatus::Receiving, target.status());

  // Once the bound transaction reaches an explicitly terminal state
  // (Aborted), a new session from the SAME controller may legitimately
  // supersede it.
  ASSERT_TRUE(target.abort(consentFrame, session));
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 4, newerSession, makeConsentPayload(controller_),
                                          descriptor_, sig_.data(), sig_.size()));
  EXPECT_EQ(0u, target.receivedChunkCount()); // fresh transaction, no stale bytes carried over
}

TEST_F(DirectedE2ETest, ForeignFragmentSenderCannotMutatePendingReassembly) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{22, 1, 1};
  CampaignConsentRequestPayload payload = makeConsentPayload(controller_);
  AuthenticatedInboundFrame beginFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.beginPendingConsent(beginFrame, session, payload));

  uint8_t canonical[protocol::kOtaDescriptorCanonicalSize];
  size_t canonicalLen = 0;
  ASSERT_EQ(protocol::OtaDescriptorCodecResult::Ok,
            protocol::encodeOtaDescriptorCanonical(descriptor_, canonical, sizeof(canonical), canonicalLen));
  std::vector<uint8_t> blob(canonical, canonical + canonicalLen);
  blob.insert(blob.end(), sig_.begin(), sig_.end());

  CampaignPeerId foreign = makePeerId(0x77);
  AuthenticatedInboundFrame foreignFragFrame = makeInboundFrame({}, foreign);
  EXPECT_FALSE(target.onDescriptorFragment(foreignFragFrame, 1, session, 0, 1,
                                            static_cast<uint16_t>(blob.size()), static_cast<uint16_t>(blob.size()),
                                            blob.data(), blob.size()));

  // Legitimate controller can still complete the reassembly afterwards --
  // the foreign attempt must not have consumed/corrupted the pending
  // reassembler state.
  AuthenticatedInboundFrame realFragFrame = makeInboundFrame({}, controller_);
  EXPECT_TRUE(target.onDescriptorFragment(realFragFrame, 2, session, 0, 1,
                                           static_cast<uint16_t>(blob.size()), static_cast<uint16_t>(blob.size()),
                                           blob.data(), blob.size()));
  EXPECT_EQ(TargetStatus::Receiving, target.status());
}

// =======================================================================
// Pending (pre-admission) ConsentRequest/DescriptorFragment freeze:
// identical retries preserve fragments, competing/changed requests
// cannot reset an active reassembly, differing-bytes duplicate fragments
// are rejected without mutation, and a bounded RAM expiry reclaims only
// genuinely abandoned attempts -- never an actively-progressing one.
// =======================================================================

namespace {
std::vector<uint8_t> makeDescriptorSignatureBlob(const protocol::OtaDescriptor& d, const std::vector<uint8_t>& sig) {
  uint8_t canonical[protocol::kOtaDescriptorCanonicalSize];
  size_t canonicalLen = 0;
  EXPECT_EQ(protocol::OtaDescriptorCodecResult::Ok,
            protocol::encodeOtaDescriptorCanonical(d, canonical, sizeof(canonical), canonicalLen));
  std::vector<uint8_t> blob(canonical, canonical + canonicalLen);
  blob.insert(blob.end(), sig.begin(), sig.end());
  return blob;
}
} // namespace

TEST_F(DirectedE2ETest, PendingConsentIdenticalRetryPreservesAlreadyReceivedFragments) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{30, 1, 1};
  CampaignConsentRequestPayload payload = makeConsentPayload(controller_);
  std::vector<uint8_t> blob = makeDescriptorSignatureBlob(descriptor_, sig_);
  // Split into two fragments so the first fragment's accepted bytes are
  // observable progress that an identical ConsentRequest retry must not
  // erase.
  const uint16_t fragPayloadSize = static_cast<uint16_t>((blob.size() + 1) / 2);
  const uint16_t totalLength = static_cast<uint16_t>(blob.size());
  payload.descriptorTotalLength = totalLength;

  AuthenticatedInboundFrame beginFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.beginPendingConsent(beginFrame, session, payload));
  ASSERT_TRUE(target.onDescriptorFragment(beginFrame, 1, session, 0, 2, totalLength, fragPayloadSize, blob.data(),
                                           fragPayloadSize));

  // Identical retry of the SAME (session, controller, scope, group,
  // declared length) ticket: idempotent no-op, NOT a reset.
  AuthenticatedInboundFrame retryFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.beginPendingConsent(retryFrame, session, payload));

  // The second (final) fragment now completes the reassembly using the
  // bytes already accepted from BEFORE the retry -- if the retry had
  // reset the reassembler, this single remaining fragment could not by
  // itself complete a geometry-correct descriptor+signature.
  const uint16_t secondLen = static_cast<uint16_t>(blob.size() - fragPayloadSize);
  ASSERT_TRUE(target.onDescriptorFragment(retryFrame, 2, session, 1, 2, totalLength, fragPayloadSize,
                                           blob.data() + fragPayloadSize, secondLen));
  EXPECT_EQ(TargetStatus::Receiving, target.status());
  EXPECT_EQ(controller_, target.boundController());
}

TEST_F(DirectedE2ETest, CompetingOrChangedConsentRequestCannotResetActivePendingReassembly) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{31, 1, 1};
  CampaignConsentRequestPayload payload = makeConsentPayload(controller_);
  std::vector<uint8_t> blob = makeDescriptorSignatureBlob(descriptor_, sig_);
  const uint16_t fragPayloadSize = static_cast<uint16_t>((blob.size() + 1) / 2);
  const uint16_t totalLength = static_cast<uint16_t>(blob.size());
  payload.descriptorTotalLength = totalLength;

  AuthenticatedInboundFrame beginFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.beginPendingConsent(beginFrame, session, payload));
  ASSERT_TRUE(target.onDescriptorFragment(beginFrame, 1, session, 0, 2, totalLength, fragPayloadSize, blob.data(),
                                           fragPayloadSize));

  CampaignPeerId otherController = makePeerId(0x44);
  runtime::OtaSessionId otherSession{31, 1, 2};

  // Different controller entirely: rejected, original untouched.
  CampaignConsentRequestPayload competingByController = payload;
  std::memcpy(competingByController.controllerId, otherController.bytes, 32);
  AuthenticatedInboundFrame competingFrame = makeInboundFrame({}, otherController);
  EXPECT_FALSE(target.beginPendingConsent(competingFrame, session, competingByController));

  // Same controller, different (newer) session/attempt: rejected.
  EXPECT_FALSE(target.beginPendingConsent(beginFrame, otherSession, payload));

  // Same controller/session, different scope: rejected.
  CampaignConsentRequestPayload differentScope = payload;
  differentScope.scope = static_cast<uint8_t>(CampaignAuthScope::Group);
  EXPECT_FALSE(target.beginPendingConsent(beginFrame, session, differentScope));

  // Same controller/session/scope, different group: rejected.
  CampaignConsentRequestPayload differentGroup = payload;
  differentGroup.groupId = payload.groupId + 1;
  EXPECT_FALSE(target.beginPendingConsent(beginFrame, session, differentGroup));

  // Same tuple except a different DECLARED descriptor length: rejected.
  CampaignConsentRequestPayload differentLength = payload;
  differentLength.descriptorTotalLength = static_cast<uint16_t>(totalLength + 1);
  EXPECT_FALSE(target.beginPendingConsent(beginFrame, session, differentLength));

  // None of the above competing attempts erased the original: the real
  // controller can still complete the original reassembly with its
  // remaining fragment.
  const uint16_t secondLen = static_cast<uint16_t>(blob.size() - fragPayloadSize);
  ASSERT_TRUE(target.onDescriptorFragment(beginFrame, 2, session, 1, 2, totalLength, fragPayloadSize,
                                           blob.data() + fragPayloadSize, secondLen));
  EXPECT_EQ(TargetStatus::Receiving, target.status());
  EXPECT_EQ(controller_, target.boundController());
}

TEST_F(DirectedE2ETest, DuplicateDescriptorFragmentWithDifferentBytesRejectedOriginalPreserved) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{32, 1, 1};
  CampaignConsentRequestPayload payload = makeConsentPayload(controller_);
  std::vector<uint8_t> blob = makeDescriptorSignatureBlob(descriptor_, sig_);
  const uint16_t fragPayloadSize = static_cast<uint16_t>((blob.size() + 1) / 2);
  const uint16_t totalLength = static_cast<uint16_t>(blob.size());
  payload.descriptorTotalLength = totalLength;

  AuthenticatedInboundFrame frame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.beginPendingConsent(frame, session, payload));
  ASSERT_TRUE(target.onDescriptorFragment(frame, 1, session, 0, 2, totalLength, fragPayloadSize, blob.data(),
                                           fragPayloadSize));

  // Resend of fragment index 0 with DIFFERENT bytes than already
  // accepted: must be rejected outright, never silently overwrite.
  std::vector<uint8_t> tampered(blob.begin(), blob.begin() + fragPayloadSize);
  tampered[0] ^= 0xFF;
  EXPECT_FALSE(
      target.onDescriptorFragment(frame, 2, session, 0, 2, totalLength, fragPayloadSize, tampered.data(), tampered.size()));

  // An EXACT bit-identical resend of fragment 0 is still a legal
  // idempotent retry.
  EXPECT_TRUE(
      target.onDescriptorFragment(frame, 3, session, 0, 2, totalLength, fragPayloadSize, blob.data(), fragPayloadSize));

  // Completing with the real second fragment yields the ORIGINAL,
  // untampered descriptor/signature -- proving the differing-bytes
  // resend never mutated the stored blob.
  const uint16_t secondLen = static_cast<uint16_t>(blob.size() - fragPayloadSize);
  ASSERT_TRUE(target.onDescriptorFragment(frame, 4, session, 1, 2, totalLength, fragPayloadSize,
                                           blob.data() + fragPayloadSize, secondLen));
  EXPECT_EQ(TargetStatus::Receiving, target.status());
}

TEST_F(DirectedE2ETest, DescriptorFragmentDeclaredLengthMustMatchFrozenPendingTotalEvenWithValidSignature) {
  // The ConsentRequest's descriptorTotalLength is frozen as part of the
  // pending ticket at beginPendingConsent() time. A fragment whose OWN
  // declared totalLength disagrees with that frozen value must be
  // rejected BEFORE touching the reassembler, even when the fragment
  // carries a genuinely, independently validly-signed descriptor+
  // signature blob (not an invalid-signature shortcut) -- otherwise a
  // requester could freeze one length via its ConsentRequest, then
  // stream fragments describing an entirely different (still valid)
  // descriptor and silently complete admission against a length the
  // pending ticket never actually froze.
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{33, 1, 1};
  CampaignConsentRequestPayload payload = makeConsentPayload(controller_);
  std::vector<uint8_t> blob = makeDescriptorSignatureBlob(descriptor_, sig_);
  const uint16_t totalLength = static_cast<uint16_t>(blob.size());
  payload.descriptorTotalLength = totalLength;

  AuthenticatedInboundFrame frame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.beginPendingConsent(frame, session, payload));

  // A genuinely, validly-signed descriptor+signature blob (same trust
  // port that every other "valid signature" case in this file relies
  // on), but sent as a SINGLE fragment whose own declared totalLength is
  // ONE BYTE DIFFERENT from what the pending ticket actually froze.
  const uint16_t mismatchedTotalLength = static_cast<uint16_t>(totalLength + 1);
  EXPECT_FALSE(target.onDescriptorFragment(frame, 1, session, 0, 1, mismatchedTotalLength,
                                            static_cast<uint16_t>(blob.size()), blob.data(), blob.size()));
  // Rejected before any reassembler mutation: status is still the
  // pre-reassembly state, and the original pending ticket/owner is
  // completely untouched.
  EXPECT_NE(TargetStatus::Receiving, target.status());
  EXPECT_EQ(0u, staging.beginSessionCallCount);

  // The SAME pending ticket, presented with the CORRECT declared length
  // (matching what beginPendingConsent() actually froze), still succeeds
  // -- proving the guard above is a precise reject, not collateral
  // damage to the legitimate flow.
  EXPECT_TRUE(target.onDescriptorFragment(frame, 2, session, 0, 1, totalLength, static_cast<uint16_t>(blob.size()),
                                           blob.data(), blob.size()));
  EXPECT_EQ(TargetStatus::Receiving, target.status());
  EXPECT_EQ(controller_, target.boundController());
}

TEST_F(DirectedE2ETest, AbandonedPendingConsentExpiresButActivelyProgressingAttemptNeverErased) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);

  FakeClock clock;
  target.bindClock(clock);
  runtime::OtaSessionId session{33, 1, 1};
  CampaignConsentRequestPayload payload = makeConsentPayload(controller_);
  std::vector<uint8_t> blob = makeDescriptorSignatureBlob(descriptor_, sig_);
  const uint16_t fragPayloadSize = static_cast<uint16_t>((blob.size() + 1) / 2);
  const uint16_t totalLength = static_cast<uint16_t>(blob.size());
  payload.descriptorTotalLength = totalLength;

  AuthenticatedInboundFrame frame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.beginPendingConsent(frame, session, payload));
  ASSERT_TRUE(target.onDescriptorFragment(frame, 1, session, 0, 2, totalLength, fragPayloadSize, blob.data(),
                                           fragPayloadSize));

  CampaignPeerId otherController = makePeerId(0x55);
  CampaignConsentRequestPayload competing = payload;
  std::memcpy(competing.controllerId, otherController.bytes, 32);
  AuthenticatedInboundFrame competingFrame = makeInboundFrame({}, otherController);

  // Just under the expiry bound, with continued genuine activity on the
  // original ticket (a fresh ConsentRequest retry) each step: a
  // competitor must still be refused, no matter how much total wall time
  // has passed, because the original attempt keeps proving it is alive.
  for (int i = 0; i < 5; ++i) {
    clock.advance(20000); // well under kCampaignPendingConsentExpiryMs (30000) each hop
    EXPECT_FALSE(target.beginPendingConsent(competingFrame, session, competing));
    ASSERT_TRUE(target.beginPendingConsent(frame, session, payload)); // keeps the ticket's activity clock fresh
  }
  // The original attempt is still completable with its remaining
  // fragment: it was never erased by the repeated (refused) competitor
  // attempts above.
  const uint16_t secondLen = static_cast<uint16_t>(blob.size() - fragPayloadSize);
  ASSERT_TRUE(target.onDescriptorFragment(frame, 2, session, 1, 2, totalLength, fragPayloadSize,
                                           blob.data() + fragPayloadSize, secondLen));
  EXPECT_EQ(controller_, target.boundController());

  // Now start a SECOND pending ticket (new session) and genuinely abandon
  // it (no further activity at all): once kCampaignPendingConsentExpiryMs
  // has elapsed with zero activity, a competing/different ticket may
  // reclaim the slot.
  runtime::OtaSessionId secondSession{34, 1, 1};
  CampaignConsentRequestPayload secondPayload = makeConsentPayload(controller_);
  secondPayload.descriptorTotalLength = totalLength;
  AuthenticatedInboundFrame secondFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.beginPendingConsent(secondFrame, secondSession, secondPayload));
  clock.advance(31000); // past the expiry bound with no further activity at all
  CampaignConsentRequestPayload reclaim = secondPayload;
  std::memcpy(reclaim.controllerId, otherController.bytes, 32);
  AuthenticatedInboundFrame reclaimFrame = makeInboundFrame({}, otherController);
  EXPECT_TRUE(target.beginPendingConsent(reclaimFrame, secondSession, reclaim));
}

TEST_F(DirectedE2ETest, AdmittedIdempotentRetryRequiresExactSignatureBytesAndGroupMatch) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{35, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  EXPECT_EQ(1u, staging.beginSessionCallCount);

  // Same descriptor/session/controller, but a DIFFERENT groupId: rejected,
  // never treated as the idempotent same-ticket retry, and never
  // re-invokes staging_.beginSession().
  EXPECT_FALSE(target.handleConsentRequest(consentFrame, 2, session, makeConsentPayload(controller_, 1), descriptor_,
                                           sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::DescriptorConflict, target.lastRefusal());
  EXPECT_EQ(1u, staging.beginSessionCallCount);

  // Same descriptor/session/controller/group, but DIFFERENT signature
  // bytes (same length): rejected, no restaging.
  std::vector<uint8_t> alteredSig = sig_;
  alteredSig[0] ^= 0xFF;
  EXPECT_FALSE(target.handleConsentRequest(consentFrame, 3, session, makeConsentPayload(controller_), descriptor_,
                                           alteredSig.data(), alteredSig.size()));
  EXPECT_EQ(CampaignRefusalReason::DescriptorConflict, target.lastRefusal());
  EXPECT_EQ(1u, staging.beginSessionCallCount);

  // Same everything but a DIFFERENT signature LENGTH: rejected. With the
  // payload's descriptorTotalLength left at its (now 1-byte-too-long)
  // default, this is caught by the declared-vs-actual length guard
  // itself before ever reaching the already-admitted/persisted
  // signature-bytes comparison -- still zero restaging either way.
  std::vector<uint8_t> shortSig(sig_.begin(), sig_.end() - 1);
  EXPECT_FALSE(target.handleConsentRequest(consentFrame, 4, session, makeConsentPayload(controller_), descriptor_,
                                           shortSig.data(), shortSig.size()));
  EXPECT_EQ(CampaignRefusalReason::GeometryInvalid, target.lastRefusal());
  EXPECT_EQ(1u, staging.beginSessionCallCount);

  // The genuinely EXACT same tuple (descriptor, signature bytes/length,
  // group, session, controller) is still accepted as idempotent, with no
  // additional restaging.
  EXPECT_TRUE(target.handleConsentRequest(consentFrame, 5, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  EXPECT_EQ(1u, staging.beginSessionCallCount);
}

TEST_F(DirectedE2ETest, AdmittedSameTicketWithChangedDeclaredLengthIsRejectedNotRestaged) {
  // Closes the companion gap to the idempotent-retry test above: even
  // with an EXACT descriptor/signature/group/session/controller match
  // against what was actually admitted, a resend that merely changes the
  // DECLARED descriptorTotalLength (while still presenting the real,
  // unchanged descriptor+signature bytes) must be rejected before any
  // restaging -- it is never treated as "the same ticket, just a
  // different length", since the declared length is part of what was
  // frozen/admitted in the first place.
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{36, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  EXPECT_EQ(1u, staging.beginSessionCallCount);

  // Exact same descriptor/signature/group/session/controller, but a
  // DIFFERENT declared descriptorTotalLength than what was actually
  // admitted: rejected before the already-admitted-bytes comparison ever
  // runs, and before any restaging.
  CampaignConsentRequestPayload changedLength = makeConsentPayload(controller_);
  changedLength.descriptorTotalLength =
      static_cast<uint16_t>(protocol::kOtaDescriptorCanonicalSize + sig_.size() + 1);
  EXPECT_FALSE(
      target.handleConsentRequest(consentFrame, 2, session, changedLength, descriptor_, sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::GeometryInvalid, target.lastRefusal());
  EXPECT_EQ(1u, staging.beginSessionCallCount);
  // The already-admitted controller binding is completely untouched by
  // the rejected resend.
  EXPECT_EQ(controller_, target.boundController());

  // The genuinely exact original tuple (correct declared length
  // included) is still accepted as idempotent afterwards, proving the
  // guard above did not collaterally wedge the legitimate retry path.
  EXPECT_TRUE(target.handleConsentRequest(consentFrame, 3, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  EXPECT_EQ(1u, staging.beginSessionCallCount);
}

TEST_F(DirectedE2ETest, InitialConsentDenialRepliesToCapturedRequestContextNotAnyOtherBoundOwner) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  FakeTransport transport;
  target.bindTransport(transport);

  // First, a real controller admits and binds (becomes the "other bound
  // owner").
  runtime::OtaSessionId firstSession{40, 1, 1};
  AuthenticatedInboundFrame firstConsent = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(firstConsent, 1, firstSession, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  ASSERT_EQ(controller_, target.boundController());
  transport.sentLog.clear();

  // A SECOND, different controller now drives a competing (non-terminal,
  // thus refused) descriptor-fragment admission attempt THROUGH THE REAL
  // onFrame()/wire-decode path, while the first controller's binding is
  // still live. The denial reply must go to THIS requester (the captured
  // authenticated request context of the attempt that just completed),
  // not to controller_ (the currently-bound OTHER owner).
  CampaignPeerId secondController = makePeerId(0x66);
  runtime::OtaSessionId secondSession{41, 1, 1};
  CampaignConsentRequestPayload secondPayload = makeConsentPayload(secondController);
  std::vector<uint8_t> blob = makeDescriptorSignatureBlob(descriptor_, sig_);
  secondPayload.descriptorTotalLength = static_cast<uint16_t>(blob.size());

  std::vector<uint8_t> consentBytes = encodeConsentRequestFrame(secondSession, 1, secondPayload);
  AuthenticatedInboundFrame secondConsentFrame = makeInboundFrame(consentBytes, secondController);
  ASSERT_TRUE(target.onFrame(secondConsentFrame));

  std::vector<uint8_t> fragBytes = encodeDescriptorFragmentFrame(
      secondSession, 2, 0, 1, static_cast<uint16_t>(blob.size()), static_cast<uint16_t>(blob.size()), blob.data(),
      blob.size());
  AuthenticatedInboundFrame secondFragFrame = makeInboundFrame(fragBytes, secondController);
  EXPECT_FALSE(target.onFrame(secondFragFrame));
  EXPECT_EQ(CampaignRefusalReason::ForeignController, target.lastRefusal());

  // The reassembly-complete path (inside onFrame()) autonomously replies
  // with a ConsentGrant reporting the denial -- confirm it targeted the
  // actual requester, never the pre-existing other bound owner.
  ASSERT_EQ(1u, transport.sentLog.size());
  EXPECT_EQ(secondController, transport.sentLog[0].dest.peerId);
  EXPECT_NE(controller_, transport.sentLog[0].dest.peerId);
}

TEST_F(DirectedE2ETest, ForeignControllerChunkAndHashMismatchRefused) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{17, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));

  CampaignPeerId foreign = makePeerId(0x99);
  uint32_t len = 0;
  ASSERT_TRUE(target.geometry().chunkLength(0, len));
  std::vector<uint8_t> data(len, 1);
  protocol::OtaChunkHeader hdr{0, static_cast<uint16_t>(len)};
  AuthenticatedInboundFrame foreignFrame = makeInboundFrame({}, foreign);
  ASSERT_FALSE(target.applyChunk(foreignFrame, 2, session, hdr, data.data(), data.size()));
  EXPECT_EQ(CampaignRefusalReason::ForeignController, target.lastRefusal());

  // Now complete the (tiny, single-chunk-relevant) transfer path with the
  // real controller and force a hash mismatch at verify time.
  AuthenticatedInboundFrame okFrame = makeInboundFrame({}, controller_);
  for (uint32_t i = 0; i < target.geometry().chunkCount; ++i) {
    uint32_t l = 0;
    ASSERT_TRUE(target.geometry().chunkLength(i, l));
    std::vector<uint8_t> d(l, static_cast<uint8_t>(i));
    protocol::OtaChunkHeader h{i, static_cast<uint16_t>(l)};
    ASSERT_TRUE(target.applyChunk(okFrame, 100 + i, session, h, d.data(), d.size()));
  }
  ASSERT_EQ(TargetStatus::Verifying, target.status());
  trust.stagedHashValid = false;
  ASSERT_FALSE(target.verifyAndCommit(okFrame, session));
  EXPECT_EQ(CampaignRefusalReason::HashMismatch, target.lastRefusal());
  EXPECT_EQ(TargetStatus::Failed, target.status());
  EXPECT_NE(TargetStatus::Installed, target.status());
}

TEST_F(DirectedE2ETest, BootEvidenceCounterMismatchNeverClaimsInstalled) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{19, 1, 1};
  AuthenticatedInboundFrame frame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(frame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  for (uint32_t i = 0; i < target.geometry().chunkCount; ++i) {
    uint32_t l = 0;
    ASSERT_TRUE(target.geometry().chunkLength(i, l));
    std::vector<uint8_t> d(l, static_cast<uint8_t>(i));
    protocol::OtaChunkHeader h{i, static_cast<uint16_t>(l)};
    ASSERT_TRUE(target.applyChunk(frame, 10 + i, session, h, d.data(), d.size()));
  }
  ASSERT_TRUE(target.verifyAndCommit(frame, session));
  ASSERT_EQ(TargetStatus::InstalledPending, target.status());

  boot.evidence.healthyBootConfirmed = true;
  boot.evidence.bootedSession = session;
  std::memcpy(boot.evidence.bootedImageHash, descriptor_.sha256, protocol::kOtaSha256Size);
  boot.evidence.bootedSecurityCounter = descriptor_.securityCounter + 1; // wrong counter
  EXPECT_FALSE(target.confirmHealthyBoot());
  EXPECT_EQ(CampaignRefusalReason::BootEvidenceMismatch, target.lastRefusal());
  EXPECT_EQ(TargetStatus::InstalledPending, target.status()); // never Installed
}

TEST_F(DirectedE2ETest, GroupScopedChunkAcceptedButGroupScopedConsentRejected) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{21, 1, 1};
  uint32_t groupId = 555;

  // A Group-scoped ConsentRequest must be rejected: consent/install
  // control is Pairwise-only regardless of group membership. Built via
  // makeGroupInboundFrame(), which has NO sender/peer parameter at all --
  // a real Group-scoped decrypt structurally carries no peer identity.
  CampaignConsentRequestPayload groupPayload = makeConsentPayload(controller_, groupId);
  groupPayload.scope = static_cast<uint8_t>(CampaignAuthScope::Group);
  AuthenticatedInboundFrame groupFrame = makeGroupInboundFrame({}, groupId);
  ASSERT_FALSE(target.handleConsentRequest(groupFrame, 1, session, groupPayload, descriptor_, sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::GroupNotAuthorizedForPairwise, target.lastRefusal());

  // Bind pairwise first (with a groupId bound alongside the controller).
  CampaignConsentRequestPayload pairwisePayload = makeConsentPayload(controller_, groupId);
  AuthenticatedInboundFrame pairwiseFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(pairwiseFrame, 2, session, pairwisePayload, descriptor_, sig_.data(),
                                          sig_.size()));

  // Now GROUP-scoped CHUNK delivery (bulk/repair) is allowed once bound --
  // group MEMBERSHIP authorizes chunk mutation, no peer identity needed.
  uint32_t l = 0;
  ASSERT_TRUE(target.geometry().chunkLength(0, l));
  std::vector<uint8_t> d(l, 7);
  protocol::OtaChunkHeader h{0, static_cast<uint16_t>(l)};
  AuthenticatedInboundFrame groupChunkFrame = makeGroupInboundFrame({}, groupId);
  ASSERT_TRUE(target.applyChunk(groupChunkFrame, 3, session, h, d.data(), d.size()));
  EXPECT_EQ(1u, target.receivedChunkCount());

  // But verifyAndCommit/abort still require Pairwise even once bound.
  AuthenticatedInboundFrame groupControlFrame = makeGroupInboundFrame({}, groupId);
  ASSERT_FALSE(target.abort(groupControlFrame, session));
  EXPECT_EQ(CampaignRefusalReason::UntrustedContext, target.lastRefusal());
}

TEST_F(DirectedE2ETest, GroupScopedCensusOrReceiptCannotIdentifyOrImpersonateAnyPeer) {
  // Group frames literally have no peer field to read: this test proves
  // it structurally (a compile-time/type-level guarantee), not merely
  // "the value happens to be zero/default". If AuthenticatedInboundFrame
  // ever regressed to a combined mutable struct with an unused peer
  // field on Group, this static_assert would keep passing wrongly, so
  // the real assertion is on std::variant's alternative INDEX: a
  // GroupAuthContext-holding frame's context can never yield a
  // PairwiseAuthContext*.
  AuthenticatedInboundFrame f = makeGroupInboundFrame({}, /*groupId=*/42);
  ASSERT_TRUE(f.isGroup());
  ASSERT_FALSE(f.isPairwise());
  EXPECT_EQ(nullptr, f.pairwise());
  ASSERT_NE(nullptr, f.group());
  EXPECT_EQ(42u, f.group()->groupId);
  EXPECT_FALSE(f.hasAuthenticatedPeer());
}

// Bounded outcome: a real DIRECTED transfer must survive losing EACH
// control/reply frame type INDEPENDENTLY (not just a hand-picked couple),
// driven ONLY by tick()/onFrame() -- no test-fabricated receipts, no
// manual phase-skipping. "Lost" here means the transport genuinely
// reported Enqueued but the frame is deliberately never relayed to the
// peer (queued != delivered); the bounded clock-driven retry in both
// engines must recover and still reach a genuine Installed/Complete
// outcome for every one of these frame types.
TEST_F(DirectedE2ETest, LosingConsentRequestOnceRecoversViaBoundedRetry) {
  runDirectedTransferDroppingFrameTypeOnce(CampaignMessageType::ConsentRequest);
}

TEST_F(DirectedE2ETest, LosingDescriptorFragmentOnceRecoversViaBoundedRetry) {
  runDirectedTransferDroppingFrameTypeOnce(CampaignMessageType::DescriptorFragment);
}

TEST_F(DirectedE2ETest, LosingCommitOnceRecoversViaBoundedRetry) {
  runDirectedTransferDroppingFrameTypeOnce(CampaignMessageType::Commit);
}

TEST_F(DirectedE2ETest, LosingConsentGrantOnceRecoversViaBoundedRetry) {
  runDirectedTransferDroppingFrameTypeOnce(CampaignMessageType::ConsentGrant);
}

TEST_F(DirectedE2ETest, LosingReceiptOnceRecoversViaBoundedRetry) {
  runDirectedTransferDroppingFrameTypeOnce(CampaignMessageType::Receipt);
}

// A wrong (foreign) session id from the SAME bound controller must never
// be allowed to commit or abort the currently-bound transaction --
// requirePairwiseBoundController() must actually validate the session,
// not `(void)id` it away.
TEST_F(DirectedE2ETest, WrongSessionCommitAndAbortAreRejectedNotAppliedToBoundCandidate) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{31, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  for (uint32_t i = 0; i < target.geometry().chunkCount; ++i) {
    uint32_t len = 0;
    ASSERT_TRUE(target.geometry().chunkLength(i, len));
    std::vector<uint8_t> data(len, static_cast<uint8_t>(i));
    protocol::OtaChunkHeader hdr{i, static_cast<uint16_t>(len)};
    AuthenticatedInboundFrame chunkFrame = makeInboundFrame({}, controller_);
    ASSERT_TRUE(target.applyChunk(chunkFrame, i + 2, session, hdr, data.data(), data.size()));
  }
  ASSERT_EQ(TargetStatus::Verifying, target.status());

  runtime::OtaSessionId wrongSession{31, 1, 2}; // same campaign, DIFFERENT attempt -- not the bound session
  AuthenticatedInboundFrame commitFrame = makeInboundFrame({}, controller_);
  ASSERT_FALSE(target.verifyAndCommit(commitFrame, wrongSession));
  EXPECT_EQ(CampaignRefusalReason::ForeignSession, target.lastRefusal());
  EXPECT_EQ(TargetStatus::Verifying, target.status()); // unchanged: no mutation

  AuthenticatedInboundFrame abortFrame = makeInboundFrame({}, controller_);
  ASSERT_FALSE(target.abort(abortFrame, wrongSession));
  EXPECT_EQ(CampaignRefusalReason::ForeignSession, target.lastRefusal());
  EXPECT_EQ(TargetStatus::Verifying, target.status()); // still unchanged

  // The genuinely-bound session still works correctly afterward.
  AuthenticatedInboundFrame realCommitFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.verifyAndCommit(realCommitFrame, session));
  EXPECT_EQ(TargetStatus::InstalledPending, target.status());
}

// The Commit onFrame case must actually decode and validate the payload
// (campaignId/verifiedOk/finalSecurityCounter) BEFORE ever calling
// verifyAndCommit() -- a malformed, unverified, or counter-mismatched
// commit must cause zero sink mutation.
TEST_F(DirectedE2ETest, MalformedOrMismatchedCommitPayloadRejectedBeforeAnyCommitMutation) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  FakeTransport unusedTransport; // only the inbound decode/validate path is under test here
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  target.bindTransport(unusedTransport);
  runtime::OtaSessionId session{41, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));
  for (uint32_t i = 0; i < target.geometry().chunkCount; ++i) {
    uint32_t len = 0;
    ASSERT_TRUE(target.geometry().chunkLength(i, len));
    std::vector<uint8_t> data(len, static_cast<uint8_t>(i));
    protocol::OtaChunkHeader hdr{i, static_cast<uint16_t>(len)};
    AuthenticatedInboundFrame chunkFrame = makeInboundFrame({}, controller_);
    ASSERT_TRUE(target.applyChunk(chunkFrame, i + 2, session, hdr, data.data(), data.size()));
  }
  ASSERT_EQ(TargetStatus::Verifying, target.status());

  // Truncated/malformed payload bytes: decode itself must fail.
  {
    uint8_t garbage[2] = {0xAA, 0xBB};
    std::vector<uint8_t> frameBytes =
        encodeEnvelope(CampaignMessageType::Commit, session, 100,
                       [&](uint8_t* dst, size_t cap, size_t& outLen) {
                         if (cap < sizeof(garbage)) return false;
                         std::memcpy(dst, garbage, sizeof(garbage));
                         outLen = sizeof(garbage);
                         return true;
                       });
    AuthenticatedInboundFrame f = makeInboundFrame(frameBytes, controller_);
    ASSERT_FALSE(target.onFrame(f));
    EXPECT_EQ(TargetStatus::Verifying, target.status());
  }

  // Wrong campaignId (foreign campaign claiming this session's wire slot).
  {
    std::vector<uint8_t> frameBytes = encodeCommitFrame(session, 101, session.campaignId + 999, 1, descriptor_.securityCounter);
    AuthenticatedInboundFrame f = makeInboundFrame(frameBytes, controller_);
    ASSERT_FALSE(target.onFrame(f));
    EXPECT_EQ(TargetStatus::Verifying, target.status());
  }

  // verifiedOk = 0: the sender itself reports it did NOT verify.
  {
    std::vector<uint8_t> frameBytes = encodeCommitFrame(session, 102, session.campaignId, 0, descriptor_.securityCounter);
    AuthenticatedInboundFrame f = makeInboundFrame(frameBytes, controller_);
    ASSERT_FALSE(target.onFrame(f));
    EXPECT_EQ(TargetStatus::Verifying, target.status());
  }

  // Wrong finalSecurityCounter (does not match this descriptor's).
  {
    std::vector<uint8_t> frameBytes =
        encodeCommitFrame(session, 103, session.campaignId, 1, descriptor_.securityCounter + 1);
    AuthenticatedInboundFrame f = makeInboundFrame(frameBytes, controller_);
    ASSERT_FALSE(target.onFrame(f));
    EXPECT_EQ(TargetStatus::Verifying, target.status());
  }

  // A genuinely valid commit still succeeds afterward.
  {
    std::vector<uint8_t> frameBytes = encodeCommitFrame(session, 104, session.campaignId, 1, descriptor_.securityCounter);
    AuthenticatedInboundFrame f = makeInboundFrame(frameBytes, controller_);
    ASSERT_TRUE(target.onFrame(f));
    EXPECT_EQ(TargetStatus::InstalledPending, target.status());
  }
}

// Legitimate network reordering (a frame carrying a LOWER original
// per-frame sequence arriving after one carrying a HIGHER sequence) must
// be accepted via the bounded anti-replay window, not rejected as stale
// merely because it is not strictly increasing on the wire.
TEST_F(DirectedE2ETest, OutOfOrderOriginalSequenceAcceptedNotRejectedAsStaleReplay) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
  runtime::OtaSessionId session{51, 1, 1};
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                          sig_.data(), sig_.size()));

  // Chunk 0 was originally generated with frameSeq 42 (e.g. queued behind
  // other traffic and delayed), chunk 1 with frameSeq 41 (sent/arrives
  // first). Deliver in ARRIVAL order (41's chunk first, then 42's) --
  // this must NOT be misread as chunk-index arrival order; the two are
  // independent chunk indices sent with genuinely non-monotonic original
  // sequence numbers.
  uint32_t len0 = 0, len1 = 0;
  ASSERT_TRUE(target.geometry().chunkLength(0, len0));
  ASSERT_TRUE(target.geometry().chunkLength(1, len1));
  std::vector<uint8_t> data0(len0, 0xAA), data1(len1, 0xBB);
  protocol::OtaChunkHeader hdr0{0, static_cast<uint16_t>(len0)};
  protocol::OtaChunkHeader hdr1{1, static_cast<uint16_t>(len1)};

  AuthenticatedInboundFrame chunkFrame0 = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.applyChunk(chunkFrame0, 42, session, hdr0, data0.data(), data0.size()));
  EXPECT_EQ(1u, target.receivedChunkCount());

  AuthenticatedInboundFrame chunkFrame1 = makeInboundFrame({}, controller_);
  ASSERT_TRUE(target.applyChunk(chunkFrame1, 41, session, hdr1, data1.data(), data1.size()))
      << "a legitimately-reordered lower original sequence must still be accepted within the replay window";
  EXPECT_EQ(2u, target.receivedChunkCount());

  // An EXACT duplicate of an already-consumed sequence (41 again) must
  // still be rejected as stale, proving the window doesn't just accept
  // everything.
  AuthenticatedInboundFrame chunkFrame1Dup = makeInboundFrame({}, controller_);
  ASSERT_FALSE(target.applyChunk(chunkFrame1Dup, 41, session, hdr1, data1.data(), data1.size()));
  EXPECT_EQ(CampaignRefusalReason::StaleReplay, target.lastRefusal());
}

// erase() now returns bool: an UNCONFIRMED erase must leave every guard
// (reloadUnsafe_) exactly as it was -- a corrupt/unreadable record may
// still be physically present, so admission must stay refused until a
// erase is actually durably confirmed.
TEST_F(DirectedE2ETest, UnconfirmedEraseDoesNotClearReloadUnsafeGuard) {
  FakeTrust trust;
  FakeStagingSink staging;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();
  runtime::OtaSessionId session{61, 1, 1};
  {
    TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
    AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
    ASSERT_TRUE(target.handleConsentRequest(consentFrame, 1, session, makeConsentPayload(controller_), descriptor_,
                                            sig_.data(), sig_.size()));
  }
  persistence.corruptByte(CampaignPersistRole::TargetReceiver, 0); // flips magic -> unreadable record

  TargetReceiverEngine reloaded(trust, staging, persistence, boot, consent, commissioning);
  ASSERT_FALSE(reloaded.reload());
  ASSERT_TRUE(reloaded.isReloadUnsafe());

  persistence.forceEraseFail = true;
  EXPECT_FALSE(reloaded.acknowledgeUnsafeReloadAndReset());
  EXPECT_TRUE(reloaded.isReloadUnsafe()); // guard untouched by the unconfirmed erase attempt

  CampaignPeerId otherController = makePeerId(0x88);
  runtime::OtaSessionId newSession{62, 1, 1};
  AuthenticatedInboundFrame newFrame = makeInboundFrame({}, otherController);
  EXPECT_FALSE(reloaded.handleConsentRequest(newFrame, 1, newSession, makeConsentPayload(otherController),
                                             descriptor_, sig_.data(), sig_.size()));
  EXPECT_EQ(CampaignRefusalReason::UnresolvedPersistedState, reloaded.lastRefusal());

  persistence.forceEraseFail = false;
  EXPECT_TRUE(reloaded.acknowledgeUnsafeReloadAndReset());
  EXPECT_FALSE(reloaded.isReloadUnsafe());
  EXPECT_TRUE(reloaded.handleConsentRequest(newFrame, 1, newSession, makeConsentPayload(otherController), descriptor_,
                                            sig_.data(), sig_.size()));
}

// =======================================================================
// RF budget: worst-case framing must fit under the exact strong-auth
// budget derivation, never silently truncated/oversized.
// =======================================================================

TEST(RfBudgetTest, FullChunkFrameFitsAuthenticatedBudget) {
  EXPECT_EQ(156u, kCampaignAuthenticatedFrameBudget);
  EXPECT_EQ(135u, kCampaignMaxPayloadSize);

  std::vector<uint8_t> data(runtime::kOtaDefaultChunkPayloadSize, 0x42);
  runtime::OtaSessionId session{1, 1, 1};
  auto frame = encodeChunkFrame(session, 1, 0, data.data(), data.size());
  EXPECT_LE(frame.size(), kCampaignAuthenticatedFrameBudget);
}

TEST(RfBudgetTest, DescriptorPlusSignatureFitsSingleFragment) {
  uint8_t canonical[protocol::kOtaDescriptorCanonicalSize];
  size_t canonicalLen = 0;
  auto descriptor = makeDescriptor(1024);
  ASSERT_EQ(protocol::OtaDescriptorCodecResult::Ok,
            protocol::encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), canonicalLen));
  std::vector<uint8_t> blob(canonical, canonical + canonicalLen);
  auto sig = fakeSignature();
  blob.insert(blob.end(), sig.begin(), sig.end());
  ASSERT_EQ(123u, blob.size()); // 59 + 64

  uint8_t payload[kCampaignMaxPayloadSize];
  size_t payloadLen = 0;
  ASSERT_TRUE(encodeCampaignDescriptorFragment(0, 1, static_cast<uint16_t>(blob.size()),
                                                static_cast<uint16_t>(blob.size()), blob.data(), blob.size(), payload,
                                                sizeof(payload), payloadLen));
  EXPECT_LE(payloadLen, kCampaignMaxPayloadSize);
}

TEST(RfBudgetTest, ExactBudgetAcceptedOneByteOverRejected) {
  // A full chunk frame (envelope header 21 + chunk header 6 + 128B data =
  // 155 bytes) fits at exactly one byte of margin under the 156-byte
  // authenticated-frame budget -- confirm the codec accepts a payload
  // sized to land exactly AT the 156-byte ceiling, and explicitly REJECTS
  // one byte over it (no silent truncation/shrinking of chunk size to
  // make an oversized frame "fit").
  runtime::OtaSessionId session{1, 1, 1};
  uint8_t frameBuf[kCampaignAuthenticatedFrameBudget];
  size_t frameLen = 0;

  // Payload sized so header(21) + payload == exactly the budget (156).
  std::vector<uint8_t> exactPayload(kCampaignMaxPayloadSize, 0xAA);
  CampaignEnvelopeHeader hdr;
  hdr.type = CampaignMessageType::Chunk;
  hdr.session = session;
  hdr.frameSeq = 1;
  ASSERT_EQ(CampaignCodecResult::Ok,
            encodeCampaignEnvelope(hdr, exactPayload.data(), exactPayload.size(), frameBuf, sizeof(frameBuf), frameLen));
  EXPECT_EQ(kCampaignAuthenticatedFrameBudget, frameLen);

  // One byte of payload over the max must be rejected, not truncated.
  std::vector<uint8_t> overPayload(kCampaignMaxPayloadSize + 1, 0xAA);
  size_t overLen = 0;
  uint8_t overBuf[kCampaignAuthenticatedFrameBudget + 1];
  EXPECT_EQ(CampaignCodecResult::PayloadTooLarge,
            encodeCampaignEnvelope(hdr, overPayload.data(), overPayload.size(), overBuf, sizeof(overBuf), overLen));
}

// =======================================================================
// Background fleet E2E: paginated census (out-of-order/duplicated pages,
// >8 total missing ranges via multiple pages), repair rounds capped at 3,
// unresolved members explicit, resolved members commit independently.
// =======================================================================

TEST(FleetE2ETest, PaginatedCensusAcrossMultiplePagesAccumulatesAllRanges) {
  FakeTransport transport;
  FleetCampaignEngine fleet(transport);
  runtime::OtaSessionId session{100, 1, 1};
  CampaignPeerId members[3] = {makePeerId(1), makePeerId(2), makePeerId(3)};
  uint32_t groupId = 77;
  ASSERT_TRUE(fleet.beginCampaign(session, groupId, members, 3));
  ASSERT_TRUE(fleet.announceComplete());

  // Member 0 reports 12 missing ranges across 2 pages (>8 total, exercising
  // the page-slot accumulation rather than an 8-total flat cap).
  CampaignCensusPagePayload page0;
  page0.bytesReceived = 1000;
  page0.pageIndex = 0;
  page0.pageCount = 2;
  page0.entryCount = 8;
  for (int i = 0; i < 8; ++i) page0.entries[i] = {static_cast<uint32_t>(i * 10), 1};
  auto page0Bytes = encodeCensusFrame(session, 1, page0);
  AuthenticatedInboundFrame page0Frame = makeInboundFrame(page0Bytes, members[0]);
  ASSERT_TRUE(fleet.onFrame(page0Frame));

  CampaignCensusPagePayload page1;
  page1.bytesReceived = 1000;
  page1.pageIndex = 1;
  page1.pageCount = 2;
  page1.entryCount = 4;
  for (int i = 0; i < 4; ++i) page1.entries[i] = {static_cast<uint32_t>(80 + i * 10), 1};
  auto page1Bytes = encodeCensusFrame(session, 2, page1);
  AuthenticatedInboundFrame page1Frame = makeInboundFrame(page1Bytes, members[0]);
  ASSERT_TRUE(fleet.onFrame(page1Frame));

  CampaignMissingRangeEntry ranges[16];
  size_t written = fleet.memberMissingRanges(members[0], ranges, 16);
  EXPECT_EQ(12u, written); // all 12 entries across both pages preserved

  // Duplicate resend of page 0 (out-of-order/duplicated delivery): must be
  // idempotent, not double-counted or truncate page 1's contribution.
  auto page0DupBytes = encodeCensusFrame(session, 3, page0);
  AuthenticatedInboundFrame page0DupFrame = makeInboundFrame(page0DupBytes, members[0]);
  ASSERT_TRUE(fleet.onFrame(page0DupFrame));
  written = fleet.memberMissingRanges(members[0], ranges, 16);
  EXPECT_EQ(12u, written); // idempotent resend: same declared pageCount does not
                           // truncate page 1's already-accumulated contribution

  // Member 1: complete (0 missing across 1 page) -- empty final page must
  // NOT be treated as complete for member 0's earlier holes, and must
  // correctly mark member 1 itself complete.
  CampaignCensusPagePayload completePage;
  completePage.bytesReceived = 5000;
  completePage.pageIndex = 0;
  completePage.pageCount = 1;
  completePage.entryCount = 0;
  auto completeBytes = encodeCensusFrame(session, 1, completePage);
  AuthenticatedInboundFrame completeFrame = makeInboundFrame(completeBytes, members[1]);
  ASSERT_TRUE(fleet.onFrame(completeFrame));

  // Member 2 never reports at all -- must remain conservatively "missing".
  ASSERT_TRUE(fleet.censusComplete());
  ASSERT_TRUE(fleet.multicastComplete());
  ASSERT_FALSE(fleet.allMembersComplete());
  CampaignPeerId missing[3];
  size_t missingCount = fleet.missingMembers(missing, 3);
  EXPECT_EQ(2u, missingCount); // members 0 (still holes) and 2 (never reported)
}

// Group membership authorizes multicast/repair CHUNK delivery only --
// NEVER a Census report's member identity (a Group-scoped frame carries
// no authenticated peer at all, so it can never be attributed to a real
// member's slot). This proves the coordinator no longer turns a Group
// context into "an identified member reported", and that a genuine
// Pairwise report for the SAME member still legitimately updates state.
TEST(FleetE2ETest, GroupScopedCensusReportIsRejectedNeverIdentifiesMember) {
  FakeTransport transport;
  FleetCampaignEngine fleet(transport);
  runtime::OtaSessionId session{101, 1, 1};
  CampaignPeerId members[2] = {makePeerId(11), makePeerId(12)};
  uint32_t groupId = 88;
  ASSERT_TRUE(fleet.beginCampaign(session, groupId, members, 2));
  ASSERT_TRUE(fleet.announceComplete());

  CampaignCensusPagePayload page;
  page.bytesReceived = 500;
  page.pageIndex = 0;
  page.pageCount = 1;
  page.entryCount = 1;
  page.entries[0] = {0, 1};
  auto pageBytes = encodeCensusFrame(session, 1, page);

  // A Group-scoped "report" (admitted group/campaign membership only,
  // NO authenticated peer) must be rejected outright, and must NOT be
  // silently attributed to any member's slot.
  AuthenticatedInboundFrame groupFrame = makeGroupInboundFrame(pageBytes, groupId);
  EXPECT_FALSE(fleet.onFrame(groupFrame));
  EXPECT_EQ(CampaignRefusalReason::UntrustedContext, fleet.lastRefusal());
  CampaignMissingRangeEntry ranges[16];
  size_t written = fleet.memberMissingRanges(members[0], ranges, 16);
  EXPECT_EQ(0u, written); // nothing accumulated from the rejected group frame

  // The SAME bytes, genuinely Pairwise-authenticated from the actual
  // member, is accepted and correctly bound to that member.
  AuthenticatedInboundFrame pairwiseFrame = makeInboundFrame(pageBytes, members[0]);
  EXPECT_TRUE(fleet.onFrame(pairwiseFrame));
  written = fleet.memberMissingRanges(members[0], ranges, 16);
  EXPECT_EQ(1u, written);
}

TEST(FleetE2ETest, DirectCensusPageEntryPointRejectsUnauthenticatedPairwiseContext) {
  FakeTransport transport;
  FleetCampaignEngine fleet(transport);
  const runtime::OtaSessionId session{101, 1, 1};
  const CampaignPeerId member = makePeerId(11);
  ASSERT_TRUE(fleet.beginCampaign(session, 88, &member, 1));
  ASSERT_TRUE(fleet.announceComplete());
  CampaignCensusPagePayload page;
  page.pageCount = 1;
  page.entryCount = 1;
  page.entries[0] = {0, 1};
  const auto bytes = encodeCensusFrame(session, 1, page);
  auto frame = makeInboundFrame(bytes, member, false);
  EXPECT_FALSE(fleet.reportCensusPage(frame, 1, member, page));
  EXPECT_EQ(CampaignRefusalReason::UntrustedContext, fleet.lastRefusal());
  CampaignMissingRangeEntry ranges[1];
  EXPECT_EQ(0u, fleet.memberMissingRanges(member, ranges, 1));
  frame.authenticated = true;
  EXPECT_TRUE(fleet.reportCensusPage(frame, 1, member, page));
  EXPECT_EQ(1u, fleet.memberMissingRanges(member, ranges, 1));
}

TEST(FleetE2ETest, RepairRoundsCapAtThreeUnresolvedExplicitOthersCommit) {
  FakeTransport transport;
  FleetCampaignEngine fleet(transport);
  runtime::OtaSessionId session{101, 1, 1};
  CampaignPeerId members[2] = {makePeerId(10), makePeerId(11)};
  uint32_t groupId = 88;
  ASSERT_TRUE(fleet.beginCampaign(session, groupId, members, 2));
  ASSERT_TRUE(fleet.announceComplete());

  CampaignCensusPagePayload memberOkPage{5000, 0, 1, 0, 0, {}};
  auto okBytes = encodeCensusFrame(session, 1, memberOkPage);
  AuthenticatedInboundFrame okFrame = makeInboundFrame(okBytes, members[0]);
  ASSERT_TRUE(fleet.onFrame(okFrame));

  uint32_t seq = 2;
  for (int round = 0; round < 3; ++round) {
    CampaignCensusPagePayload stillMissing{1000, 0, 1, 1, static_cast<uint8_t>(round), {{0, 1}}};
    auto missingBytes = encodeCensusFrame(session, seq++, stillMissing);
    AuthenticatedInboundFrame missingFrame = makeInboundFrame(missingBytes, members[1]);
    ASSERT_TRUE(fleet.onFrame(missingFrame));

    if (round == 0) {
      ASSERT_TRUE(fleet.censusComplete());
      ASSERT_TRUE(fleet.multicastComplete());
    }
    ASSERT_TRUE(fleet.resolveMissingCensus()); // SomeMissing -> Repairing
    ASSERT_TRUE(fleet.beginRepairRound());
    ASSERT_TRUE(fleet.repairRoundComplete()); // -> MissingCensus for re-census
  }

  // Round cap reached: a 4th round must be refused explicitly.
  EXPECT_TRUE(fleet.roundCapExceeded());
  EXPECT_FALSE(fleet.beginRepairRound());
  EXPECT_EQ(CampaignRefusalReason::RoundCapExceeded, fleet.lastRefusal());

  CampaignPeerId unresolved[2];
  size_t unresolvedCount = fleet.unresolvedMembers(unresolved, 2);
  ASSERT_EQ(1u, unresolvedCount);
  EXPECT_EQ(members[1], unresolved[0]);

  // Member 0 (resolved) still commits independently, always Pairwise.
  protocol::OtaCommitPayload commit{session.campaignId, 1, 1};
  EXPECT_EQ(CampaignSendResult::Enqueued, fleet.commitMember(members[0], commit));
  // Member 1 (unresolved) is never committed.
  EXPECT_EQ(CampaignSendResult::Rejected, fleet.commitMember(members[1], commit));
}

// Proves the OLD 8-page/8-bit "pagesReceivedMask" cap (64 total holes max)
// is genuinely gone: a single member reports MANY more than 64 disjoint
// missing ranges spread across MANY more than 8 pages, all folded into
// the bitmap correctly (no truncation, no OOB, no silent drop).
TEST(FleetE2ETest, MemberWithMoreThanSixtyFourHolesAcrossManyPagesIsFullyAccumulated) {
  FakeTransport transport;
  FleetCampaignEngine fleet(transport);
  runtime::OtaSessionId session{104, 1, 1};
  CampaignPeerId members[1] = {makePeerId(20)};
  ASSERT_TRUE(fleet.beginCampaign(session, 1, members, 1, /*chunkCount=*/5536));
  ASSERT_TRUE(fleet.announceComplete());

  // 100 pages x 8 entries/page = 800 disjoint single-chunk ranges, spaced
  // far enough apart (every 4 chunks) to stay disjoint and in-bounds of
  // the 5536-chunk geometry: far beyond the old 64-total-hole cap.
  constexpr int kPages = 100;
  constexpr int kEntriesPerPage = 8;
  uint32_t seq = 1;
  for (int p = 0; p < kPages; ++p) {
    CampaignCensusPagePayload page;
    page.bytesReceived = 0;
    page.pageIndex = static_cast<uint16_t>(p);
    page.pageCount = kPages;
    page.entryCount = kEntriesPerPage;
    page.roundIndex = 0;
    for (int e = 0; e < kEntriesPerPage; ++e) {
      page.entries[e] = {static_cast<uint32_t>((p * kEntriesPerPage + e) * 4), 1};
    }
    auto bytes = encodeCensusFrame(session, seq++, page);
    AuthenticatedInboundFrame frame = makeInboundFrame(bytes, members[0]);
    ASSERT_TRUE(fleet.onFrame(frame)) << "page " << p << " refusal=" << static_cast<int>(fleet.lastRefusal());
  }

  CampaignMissingRangeEntry ranges[kPages * kEntriesPerPage];
  size_t written = fleet.memberMissingRanges(members[0], ranges, kPages * kEntriesPerPage);
  EXPECT_EQ(static_cast<size_t>(kPages * kEntriesPerPage), written); // all 800 ranges preserved, none dropped
  ASSERT_FALSE(fleet.allMembersComplete()); // still has (reported) holes
}

// Proves out-of-order page delivery (a non-zero page index arriving
// BEFORE page 0) is no longer rejected: the first page ever seen for a
// member opportunistically establishes the round's pageCount, and a
// subsequently-arriving page 0 with the SAME pageCount completes the
// round without losing the out-of-order page's contribution.
TEST(FleetE2ETest, OutOfOrderPageOneBeforePageZeroIsAcceptedNotRejected) {
  FakeTransport transport;
  FleetCampaignEngine fleet(transport);
  runtime::OtaSessionId session{105, 1, 1};
  CampaignPeerId members[1] = {makePeerId(21)};
  ASSERT_TRUE(fleet.beginCampaign(session, 1, members, 1));
  ASSERT_TRUE(fleet.announceComplete());

  CampaignCensusPagePayload page1{2000, 1, 2, 2, 0, {{200, 5}, {300, 5}}};
  auto page1Bytes = encodeCensusFrame(session, 1, page1);
  AuthenticatedInboundFrame page1Frame = makeInboundFrame(page1Bytes, members[0]);
  ASSERT_TRUE(fleet.onFrame(page1Frame)) << "refusal=" << static_cast<int>(fleet.lastRefusal());

  CampaignCensusPagePayload page0{2000, 0, 2, 2, 0, {{0, 5}, {100, 5}}};
  auto page0Bytes = encodeCensusFrame(session, 2, page0);
  AuthenticatedInboundFrame page0Frame = makeInboundFrame(page0Bytes, members[0]);
  ASSERT_TRUE(fleet.onFrame(page0Frame)) << "refusal=" << static_cast<int>(fleet.lastRefusal());

  CampaignMissingRangeEntry ranges[8];
  size_t written = fleet.memberMissingRanges(members[0], ranges, 8);
  EXPECT_EQ(4u, written); // both pages' ranges preserved despite arriving out of order
}

// Proves census pages are bound to a specific repair round/generation: a
// page tagged with a STALE round index (from before the coordinator
// advanced to a new repair round) is rejected rather than silently
// folded into the new round's accumulation, and the SAME member's
// carried-over holes from the completed round are not resurrected by it.
TEST(FleetE2ETest, StaleRoundCensusPageIsRejectedNotFoldedIntoNewRound) {
  FakeTransport transport;
  FleetCampaignEngine fleet(transport);
  runtime::OtaSessionId session{106, 1, 1};
  CampaignPeerId members[1] = {makePeerId(22)};
  ASSERT_TRUE(fleet.beginCampaign(session, 1, members, 1));
  ASSERT_TRUE(fleet.announceComplete());

  // Round 0 census: member reports one hole.
  CampaignCensusPagePayload round0Page{1000, 0, 1, 1, 0, {{0, 1}}};
  auto round0Bytes = encodeCensusFrame(session, 1, round0Page);
  AuthenticatedInboundFrame round0Frame = makeInboundFrame(round0Bytes, members[0]);
  ASSERT_TRUE(fleet.onFrame(round0Frame));
  ASSERT_TRUE(fleet.censusComplete());
  ASSERT_TRUE(fleet.multicastComplete());
  ASSERT_TRUE(fleet.resolveMissingCensus()); // SomeMissing -> Repairing
  ASSERT_TRUE(fleet.beginRepairRound());      // round_ -> 1
  ASSERT_TRUE(fleet.repairRoundComplete());   // -> MissingCensus (re-census)

  // A page still tagged with round 0 (stale/delayed in flight) must be
  // rejected now that the coordinator is on round 1.
  CampaignCensusPagePayload staleRound0Page{1000, 0, 1, 1, 0, {{5, 1}}};
  auto staleBytes = encodeCensusFrame(session, 2, staleRound0Page);
  AuthenticatedInboundFrame staleFrame = makeInboundFrame(staleBytes, members[0]);
  EXPECT_FALSE(fleet.onFrame(staleFrame));
  EXPECT_EQ(CampaignRefusalReason::StaleCensusRound, fleet.lastRefusal());

  // A correctly-tagged round-1 page reporting the image now complete IS
  // accepted, and is not corrupted by the rejected stale round-0 page.
  CampaignCensusPagePayload round1Page{1000, 0, 1, 0, 1, {}};
  auto round1Bytes = encodeCensusFrame(session, 3, round1Page);
  AuthenticatedInboundFrame round1Frame = makeInboundFrame(round1Bytes, members[0]);
  ASSERT_TRUE(fleet.onFrame(round1Frame));
  ASSERT_TRUE(fleet.resolveMissingCensus()); // NoneMissing -> Committing
  EXPECT_TRUE(fleet.allMembersComplete());
}

TEST(FleetE2ETest, ThirtyTwoMemberCohortBoundedNoSilentDrop) {
  FakeTransport transport;
  FleetCampaignEngine fleet(transport);
  runtime::OtaSessionId session{102, 1, 1};
  CampaignPeerId members[kCampaignMaxFleetMembers];
  for (size_t i = 0; i < kCampaignMaxFleetMembers; ++i) members[i] = makePeerId(static_cast<uint8_t>(i + 1));
  ASSERT_TRUE(fleet.beginCampaign(session, 1, members, kCampaignMaxFleetMembers));
  EXPECT_EQ(kCampaignMaxFleetMembers, fleet.memberCount());

  CampaignPeerId oneTooMany[kCampaignMaxFleetMembers + 1];
  for (size_t i = 0; i < kCampaignMaxFleetMembers + 1; ++i) oneTooMany[i] = makePeerId(static_cast<uint8_t>(i + 1));
  runtime::OtaSessionId session2{103, 1, 1};
  EXPECT_FALSE(fleet.beginCampaign(session2, 1, oneTooMany, kCampaignMaxFleetMembers + 1));
}

// Proves the production coordinator/facade itself drives the ENTIRE
// background fleet flow autonomously: the test never calls
// announceComplete()/censusComplete()/multicastComplete()/
// beginRepairRound()/repairRoundComplete()/resolveMissingCensus()/
// commitMember() directly. It only drives fleet.tick() and relays raw
// wire bytes from fleet's own outbound sentLog into synthesized member
// responses fed back through fleet.onFrame() -- exercising real
// Announcement -> multicast(external signal) -> paginated census ->
// targeted repair -> re-census -> pairwise commit, with one member that
// needs two repair rounds to fully converge and one member that never
// responds at all (offline), ending up explicitly unresolved while the
// other three commit independently.
TEST(FleetE2ETest, FullyAutonomousTickAndOnFrameDrivenFleetCampaignWithOfflineMember) {
  FakeTransport transport;
  FleetCampaignEngine fleet(transport);
  runtime::OtaSessionId session{200, 1, 1};
  CampaignPeerId complete = makePeerId(1);   // already fully has the image
  CampaignPeerId oneRoundFix = makePeerId(2);  // converges after 1 repair round
  CampaignPeerId twoRoundFix = makePeerId(3);  // converges after 2 repair rounds
  CampaignPeerId offline = makePeerId(4);      // never responds at all
  CampaignPeerId members[4] = {complete, oneRoundFix, twoRoundFix, offline};
  const uint32_t groupId = 55;
  const uint32_t chunkCount = 200;
  ASSERT_TRUE(fleet.beginCampaign(session, groupId, members, 4, chunkCount));
  fleet.setCommitTemplate(protocol::OtaCommitPayload{session.campaignId, 1, 1});

  size_t sentCursor = 0;
  uint32_t memberFrameSeq[4] = {1, 1, 1, 1};
  int twoRoundFixRepairsSeen = 0;

  auto memberIndex = [&](const CampaignPeerId& p) -> int {
    for (int i = 0; i < 4; ++i) if (members[i] == p) return i;
    return -1;
  };

  auto injectReport = [&](const CampaignPeerId& who, uint8_t roundIndex,
                           std::vector<CampaignMissingRangeEntry> missing) {
    CampaignCensusPagePayload page{};
    page.bytesReceived = missing.empty() ? chunkCount * 128u : 0;
    page.pageIndex = 0;
    page.pageCount = 1;
    page.roundIndex = roundIndex;
    page.entryCount = static_cast<uint8_t>(missing.size());
    for (size_t i = 0; i < missing.size(); ++i) page.entries[i] = missing[i];
    int idx = memberIndex(who);
    auto bytes = encodeCensusFrame(session, memberFrameSeq[idx]++, page);
    AuthenticatedInboundFrame f = makeInboundFrame(bytes, who);
    ASSERT_TRUE(fleet.onFrame(f));
  };

  int iterations = 0;
  const int kMaxIterations = 20000; // safety bound: proves genuine bounded convergence, no infinite loop
  while (fleet.state() != runtime::OtaFleetState::Complete && ++iterations < kMaxIterations) {
    fleet.tick();

    // Real bulk-transport completion is an external cross-engine signal
    // (owned by a Group-scoped UpdaterCampaignEngine instance elsewhere);
    // fire it as soon as it's actually waited-on, exactly once.
    if (fleet.state() == runtime::OtaFleetState::Multicasting) {
      fleet.multicastComplete();
    }

    while (sentCursor < transport.sentLog.size()) {
      const auto& sent = transport.sentLog[sentCursor++];
      CampaignEnvelopeHeader hdr;
      const uint8_t* payload = nullptr;
      size_t payloadLen = 0;
      ASSERT_EQ(CampaignCodecResult::Ok,
                decodeCampaignEnvelope(sent.bytes.data(), sent.bytes.size(), hdr, payload, payloadLen));
      if (hdr.type != CampaignMessageType::Announcement && hdr.type != CampaignMessageType::MissingRange) {
        continue; // e.g. Commit -- not a census/repair page, nothing to synthesize
      }
      CampaignCensusPagePayload req;
      ASSERT_TRUE(decodeCampaignCensusPage(payload, payloadLen, req));

      if (hdr.type == CampaignMessageType::Announcement) {
        // Group broadcast solicits every cohort member's first report.
        injectReport(complete, req.roundIndex, {});
        injectReport(oneRoundFix, req.roundIndex, {{10, 5}});
        injectReport(twoRoundFix, req.roundIndex, {{20, 3}, {80, 4}});
        // `offline` never responds.
      } else if (hdr.type == CampaignMessageType::MissingRange) {
        if (sent.dest.peerId == oneRoundFix) {
          injectReport(oneRoundFix, req.roundIndex, {}); // fully fixed after 1 round
        } else if (sent.dest.peerId == twoRoundFix) {
          if (twoRoundFixRepairsSeen == 0) {
            injectReport(twoRoundFix, req.roundIndex, {{80, 4}}); // partially fixed
            ++twoRoundFixRepairsSeen;
          } else {
            injectReport(twoRoundFix, req.roundIndex, {}); // fully fixed on 2nd round
          }
        }
        // `offline` gets repair requests too but never replies.
      }
    }
  }

  ASSERT_LT(iterations, kMaxIterations) << "fleet campaign did not converge autonomously";
  EXPECT_EQ(runtime::OtaFleetState::Complete, fleet.state());

  CampaignPeerId unresolved[4];
  size_t unresolvedCount = fleet.unresolvedMembers(unresolved, 4);
  ASSERT_EQ(1u, unresolvedCount);
  EXPECT_EQ(offline, unresolved[0]);
}

// =======================================================================
// Direct high-speed lease: real bilateral wire handshake, lost frames,
// watchdog/expiry, forced abort, restore failure, invalid profile
// rejection, and actual profile-application state transitions.
// =======================================================================

class DirectLeaseE2ETest : public ::testing::Test {
protected:
  void SetUp() override {
    requesterPeer_ = makePeerId(0x30);
    grantorPeer_ = makePeerId(0x31);
  }

  CampaignRadioProfileParams validRequested() const {
    CampaignRadioProfileParams p;
    p.profile = CampaignRadioProfile::DirectHighSpeed;
    p.freqMhz = 908.525f;
    p.bandwidthKhz = 250.0f;
    p.spreadingFactor = 5;
    p.codingRate = 5;
    return p;
  }

  CampaignPeerId requesterPeer_, grantorPeer_;
};

TEST_F(DirectLeaseE2ETest, FullHandshakeReachesActiveOnBothSidesThenReleases) {
  FakeRadioProfilePort requesterRadio, grantorRadio;
  FakeClock requesterClock, grantorClock;
  FakeTransport requesterTransport, grantorTransport;
  FakeLeaseGrantPolicy requesterPolicy, grantorPolicy;
  DirectLeaseEngine requester(requesterRadio, requesterClock, requesterTransport, requesterPolicy);
  DirectLeaseEngine grantor(grantorRadio, grantorClock, grantorTransport, grantorPolicy);

  ASSERT_TRUE(requester.requestLease(grantorPeer_, validRequested(), 5000));
  ASSERT_EQ(DirectLeasePhase::Requesting, requester.phase());

  // Requester -> Grantor: Request
  ASSERT_EQ(1u, requesterTransport.sentLog.size());
  AuthenticatedInboundFrame reqFrame =
      makeInboundFrame(requesterTransport.sentLog[0].bytes, requesterPeer_);
  ASSERT_TRUE(grantor.onFrame(reqFrame));
  ASSERT_EQ(DirectLeasePhase::AwaitingActivate, grantor.phase());

  // Grantor -> Requester: Grant
  ASSERT_EQ(1u, grantorTransport.sentLog.size());
  AuthenticatedInboundFrame grantFrame =
      makeInboundFrame(grantorTransport.sentLog[0].bytes, grantorPeer_);
  ASSERT_TRUE(requester.onFrame(grantFrame));
  ASSERT_EQ(DirectLeasePhase::AwaitingAck, requester.phase());

  // Requester -> Grantor: Activate
  ASSERT_EQ(2u, requesterTransport.sentLog.size());
  AuthenticatedInboundFrame activateFrame =
      makeInboundFrame(requesterTransport.sentLog[1].bytes, requesterPeer_);
  ASSERT_TRUE(grantor.onFrame(activateFrame));
  ASSERT_EQ(DirectLeasePhase::AwaitingHello, grantor.phase());
  // The Ack is sent immediately, but the ACTUAL high-speed profile switch
  // is deferred to tick() -- the grantor must still be Normal here (the
  // Ack has to physically leave the radio on Normal first, or the
  // still-Normal requester could never receive it: this is the exact
  // deadlock fix).
  EXPECT_EQ(CampaignRadioProfile::Normal, grantorRadio.currentProfile());
  ASSERT_EQ(2u, grantorTransport.sentLog.size()); // Grant + Ack only so far, no Hello yet

  // tick() past the bounded switch-guard delay applies the deferred
  // switch (gated on TX-completion evidence) and sends Hello.
  grantorClock.advance(kCampaignLeaseSwitchGuardMs + 1);
  grantor.tickWatchdog();
  EXPECT_EQ(CampaignRadioProfile::DirectHighSpeed, grantorRadio.currentProfile());
  ASSERT_EQ(3u, grantorTransport.sentLog.size());

  // Grantor -> Requester: Ack (already sent above, on Normal).
  AuthenticatedInboundFrame ackFrame =
      makeInboundFrame(grantorTransport.sentLog[1].bytes, grantorPeer_);
  ASSERT_TRUE(requester.onFrame(ackFrame));
  ASSERT_EQ(DirectLeasePhase::AwaitingHello, requester.phase());
  EXPECT_EQ(CampaignRadioProfile::Normal, requesterRadio.currentProfile()); // deferred, not yet switched
  ASSERT_EQ(2u, requesterTransport.sentLog.size()); // Request + Activate only, no Hello yet

  requesterClock.advance(kCampaignLeaseSwitchGuardMs + 1);
  requester.tickWatchdog();
  EXPECT_EQ(CampaignRadioProfile::DirectHighSpeed, requesterRadio.currentProfile());
  ASSERT_EQ(3u, requesterTransport.sentLog.size());

  // Requester -> Grantor: Hello (sent after the deferred switch applied)
  AuthenticatedInboundFrame helloFromRequester =
      makeInboundFrame(requesterTransport.sentLog[2].bytes, requesterPeer_);
  ASSERT_TRUE(grantor.onFrame(helloFromRequester));
  ASSERT_EQ(DirectLeasePhase::Active, grantor.phase());

  // Grantor's own Hello (sent alongside its deferred switch, sentLog[2]).
  AuthenticatedInboundFrame helloFromGrantor =
      makeInboundFrame(grantorTransport.sentLog[2].bytes, grantorPeer_);
  ASSERT_TRUE(requester.onFrame(helloFromGrantor));
  ASSERT_EQ(DirectLeasePhase::Active, requester.phase());

  // Release from the requester: Release is sent NOW while still HIGH (both
  // sides are HIGH, so this is fine); the actual restore-to-Normal on each
  // side is deferred to tick() until AFTER the corresponding
  // Release/ReleaseAck frame has actually left the radio -- restoring
  // synchronously (the original bug) would leave the still-HIGH peer
  // unable to ever receive that frame.
  ASSERT_TRUE(requester.release());
  AuthenticatedInboundFrame releaseFrame =
      makeInboundFrame(requesterTransport.sentLog.back().bytes, requesterPeer_);
  ASSERT_TRUE(grantor.onFrame(releaseFrame));
  EXPECT_EQ(DirectLeasePhase::Releasing, grantor.phase());
  EXPECT_EQ(CampaignRadioProfile::DirectHighSpeed, grantorRadio.currentProfile()); // not yet restored

  grantorClock.advance(kCampaignLeaseSwitchGuardMs + 1);
  grantor.tickWatchdog();
  EXPECT_EQ(DirectLeasePhase::Normal, grantor.phase());
  EXPECT_EQ(CampaignRadioProfile::Normal, grantorRadio.currentProfile());

  AuthenticatedInboundFrame releaseAckFrame =
      makeInboundFrame(grantorTransport.sentLog.back().bytes, grantorPeer_);
  ASSERT_TRUE(requester.onFrame(releaseAckFrame));
  EXPECT_EQ(DirectLeasePhase::Releasing, requester.phase());
  EXPECT_EQ(CampaignRadioProfile::DirectHighSpeed, requesterRadio.currentProfile()); // not yet restored

  requesterClock.advance(kCampaignLeaseSwitchGuardMs + 1);
  requester.tickWatchdog();
  EXPECT_EQ(DirectLeasePhase::Normal, requester.phase());
  EXPECT_EQ(CampaignRadioProfile::Normal, requesterRadio.currentProfile());
}

TEST_F(DirectLeaseE2ETest, LostGrantTimesOutViaWatchdogAndRestoresNormal) {
  FakeRadioProfilePort requesterRadio, grantorRadio;
  FakeClock requesterClock, grantorClock;
  FakeTransport requesterTransport, grantorTransport;
  FakeLeaseGrantPolicy requesterPolicy, grantorPolicy;
  DirectLeaseEngine requester(requesterRadio, requesterClock, requesterTransport, requesterPolicy);
  DirectLeaseEngine grantor(grantorRadio, grantorClock, grantorTransport, grantorPolicy);

  ASSERT_TRUE(requester.requestLease(grantorPeer_, validRequested(), 5000));
  // Grant is lost -- never relayed to the requester.
  requesterClock.advance(5001);
  EXPECT_TRUE(requester.tickWatchdog());
  EXPECT_EQ(DirectLeasePhase::Normal, requester.phase());
  EXPECT_EQ(CampaignRefusalReason::Timeout, requester.lastRefusal());
  EXPECT_FALSE(requester.isNormalTxBlocked());
}

TEST_F(DirectLeaseE2ETest, LostHelloLeavesGrantorInAwaitingHelloUntilTimeout) {
  FakeRadioProfilePort requesterRadio, grantorRadio;
  FakeClock requesterClock, grantorClock;
  FakeTransport requesterTransport, grantorTransport;
  FakeLeaseGrantPolicy requesterPolicy, grantorPolicy;
  DirectLeaseEngine requester(requesterRadio, requesterClock, requesterTransport, requesterPolicy);
  DirectLeaseEngine grantor(grantorRadio, grantorClock, grantorTransport, grantorPolicy);

  ASSERT_TRUE(requester.requestLease(grantorPeer_, validRequested(), 4000));
  AuthenticatedInboundFrame reqFrame =
      makeInboundFrame(requesterTransport.sentLog[0].bytes, requesterPeer_);
  ASSERT_TRUE(grantor.onFrame(reqFrame));
  AuthenticatedInboundFrame grantFrame =
      makeInboundFrame(grantorTransport.sentLog[0].bytes, grantorPeer_);
  ASSERT_TRUE(requester.onFrame(grantFrame));
  AuthenticatedInboundFrame activateFrame =
      makeInboundFrame(requesterTransport.sentLog[1].bytes, requesterPeer_);
  ASSERT_TRUE(grantor.onFrame(activateFrame));
  grantorClock.advance(kCampaignLeaseSwitchGuardMs + 1);
  grantor.tickWatchdog(); // applies deferred switch + sends its own Hello
  // Requester never receives Ack (lost), so it never applies the profile
  // or sends its own Hello.
  ASSERT_EQ(DirectLeasePhase::AwaitingHello, grantor.phase());
  EXPECT_EQ(DirectLeasePhase::AwaitingAck, requester.phase());

  grantorClock.advance(4001);
  EXPECT_TRUE(grantor.tickWatchdog());
  EXPECT_EQ(DirectLeasePhase::Normal, grantor.phase());
  EXPECT_EQ(CampaignRadioProfile::Normal, grantorRadio.currentProfile());
}

TEST_F(DirectLeaseE2ETest, RestoreFailureBlocksNormalTxExplicitly) {
  FakeRadioProfilePort requesterRadio, grantorRadio;
  requesterRadio.restoreShouldFail = true;
  FakeClock requesterClock, grantorClock;
  FakeTransport requesterTransport, grantorTransport;
  FakeLeaseGrantPolicy requesterPolicy;
  DirectLeaseEngine requester(requesterRadio, requesterClock, requesterTransport, requesterPolicy);

  ASSERT_TRUE(requester.requestLease(grantorPeer_, validRequested(), 1000));
  requesterClock.advance(1001);
  requester.tickWatchdog();
  EXPECT_TRUE(requester.isRestoreFaulted());
  EXPECT_TRUE(requester.isNormalTxBlocked()); // never falsely claims Normal

  requesterRadio.restoreShouldFail = false;
  EXPECT_TRUE(requester.retryRestoreNormal());
  EXPECT_FALSE(requester.isNormalTxBlocked());
}

TEST_F(DirectLeaseE2ETest, ForcedAbortAndRebootRestoreNormal) {
  FakeRadioProfilePort radio;
  FakeClock clock;
  FakeTransport transport;
  FakeLeaseGrantPolicy policy;
  DirectLeaseEngine requester(radio, clock, transport, policy);
  DirectLeaseEngine grantorPeerUnused(radio, clock, transport, policy); // unused, just for symmetry

  ASSERT_TRUE(requester.requestLease(grantorPeer_, validRequested(), 5000));
  EXPECT_TRUE(requester.forcedAbort());
  EXPECT_EQ(DirectLeasePhase::Normal, requester.phase());

  // Simulate a reboot: a fresh engine instance defensively forces Normal.
  DirectLeaseEngine postReboot(radio, clock, transport, policy);
  postReboot.forceNormalOnBoot();
  EXPECT_EQ(DirectLeasePhase::Normal, postReboot.phase());
  EXPECT_FALSE(postReboot.isRestoreFaulted());
}

TEST_F(DirectLeaseE2ETest, InvalidProfilesRejectedByPortPolicyNotHardcodedRange) {
  FakeRadioProfilePort radio;
  FakeClock clock;
  FakeTransport transport;
  FakeLeaseGrantPolicy policy;
  DirectLeaseEngine requester(radio, clock, transport, policy);

  // CR4 is not a valid SX1262 coding-rate denominator.
  CampaignRadioProfileParams badCr = validRequested();
  badCr.codingRate = 4;
  EXPECT_FALSE(requester.requestLease(grantorPeer_, badCr, 1000));
  EXPECT_EQ(CampaignRefusalReason::InvalidRadioProfile, requester.lastRefusal());

  // Requesting the board's currently-ACTIVE normal frequency is invalid
  // (radio.normal is 907.525 by default in the fake).
  CampaignRadioProfileParams sameAsNormal = validRequested();
  sameAsNormal.freqMhz = radio.normalProfileParams().freqMhz;
  EXPECT_FALSE(requester.requestLease(grantorPeer_, sameAsNormal, 1000));

  // 908.525 MHz IS valid when the active normal profile is 907.525 (the
  // two frequencies are NOT both hardcoded-excluded).
  EXPECT_TRUE(requester.requestLease(grantorPeer_, validRequested(), 1000));
  requester.forcedAbort();

  // An unapproved band (outside the fake's 902-928 MHz approved range) is
  // rejected via the port policy query, never a hardcoded 150..2500 range.
  CampaignRadioProfileParams outOfBand = validRequested();
  outOfBand.freqMhz = 2400.0f;
  EXPECT_FALSE(requester.requestLease(grantorPeer_, outOfBand, 1000));
}

TEST_F(DirectLeaseE2ETest, BoundedEpochRejectsZeroAndHugeValues) {
  FakeRadioProfilePort radio;
  FakeClock clock;
  FakeTransport transport;
  FakeLeaseGrantPolicy policy;
  DirectLeaseEngine requester(radio, clock, transport, policy);

  EXPECT_FALSE(requester.requestLease(grantorPeer_, validRequested(), 0));
  EXPECT_EQ(CampaignRefusalReason::InvalidLeaseEpoch, requester.lastRefusal());
  EXPECT_FALSE(requester.requestLease(grantorPeer_, validRequested(), 3600000));
  EXPECT_EQ(CampaignRefusalReason::InvalidLeaseEpoch, requester.lastRefusal());
  EXPECT_TRUE(requester.requestLease(grantorPeer_, validRequested(), 5000));
}

TEST_F(DirectLeaseE2ETest, LocalGrantPolicyDenialBlocksGrantEvenWithValidAuthenticatedRequest) {
  FakeRadioProfilePort requesterRadio, grantorRadio;
  FakeClock requesterClock, grantorClock;
  FakeTransport requesterTransport, grantorTransport;
  FakeLeaseGrantPolicy requesterPolicy, grantorPolicy;
  grantorPolicy.approve = false; // local board/site policy refuses, independent of pairwise auth
  DirectLeaseEngine requester(requesterRadio, requesterClock, requesterTransport, requesterPolicy);
  DirectLeaseEngine grantor(grantorRadio, grantorClock, grantorTransport, grantorPolicy);

  ASSERT_TRUE(requester.requestLease(grantorPeer_, validRequested(), 5000));
  AuthenticatedInboundFrame reqFrame =
      makeInboundFrame(requesterTransport.sentLog[0].bytes, requesterPeer_);
  EXPECT_FALSE(grantor.onFrame(reqFrame)); // authenticated, but locally denied by site/board policy
  EXPECT_EQ(DirectLeasePhase::Normal, grantor.phase());
  EXPECT_EQ(CampaignRefusalReason::LeaseGrantPolicyDenied, grantor.lastRefusal());
  EXPECT_EQ(CampaignRadioProfile::Normal, grantorRadio.currentProfile());
}

TEST_F(DirectLeaseE2ETest, ProfileSwitchWithheldUntilTxQueueDrainsProvingNoPrematureDeadlock) {
  FakeRadioProfilePort requesterRadio, grantorRadio;
  FakeClock requesterClock, grantorClock;
  FakeTransport requesterTransport, grantorTransport;
  // Model a real radio where an enqueued Ack is not yet physically
  // transmitted: the deferred switch must NOT apply while this holds.
  grantorTransport.autoCompleteSends = false;
  FakeLeaseGrantPolicy requesterPolicy, grantorPolicy;
  DirectLeaseEngine requester(requesterRadio, requesterClock, requesterTransport, requesterPolicy);
  DirectLeaseEngine grantor(grantorRadio, grantorClock, grantorTransport, grantorPolicy);

  ASSERT_TRUE(requester.requestLease(grantorPeer_, validRequested(), 5000));
  AuthenticatedInboundFrame reqFrame =
      makeInboundFrame(requesterTransport.sentLog[0].bytes, requesterPeer_);
  ASSERT_TRUE(grantor.onFrame(reqFrame));
  AuthenticatedInboundFrame grantFrame =
      makeInboundFrame(grantorTransport.sentLog[0].bytes, grantorPeer_);
  ASSERT_TRUE(requester.onFrame(grantFrame));
  AuthenticatedInboundFrame activateFrame =
      makeInboundFrame(requesterTransport.sentLog[1].bytes, requesterPeer_);
  ASSERT_TRUE(grantor.onFrame(activateFrame)); // enqueues Ack, but it is still "in flight"

  // Even well past the guard delay, the switch must stay withheld because
  // txQueueEmpty() is still false (the Ack has not actually left the radio
  // yet) -- this is the exact evidence the original bug lacked.
  grantorClock.advance(kCampaignLeaseSwitchGuardMs + 500);
  grantor.tickWatchdog();
  EXPECT_EQ(CampaignRadioProfile::Normal, grantorRadio.currentProfile());
  ASSERT_EQ(2u, grantorTransport.sentLog.size()); // Grant + Ack, no Hello yet

  // Once the transport reports the Ack has actually completed, the next
  // tick is free to apply the deferred switch.
  grantorTransport.completeAllSends();
  grantor.tickWatchdog();
  EXPECT_EQ(CampaignRadioProfile::DirectHighSpeed, grantorRadio.currentProfile());
  ASSERT_EQ(3u, grantorTransport.sentLog.size());
}

TEST_F(DirectLeaseE2ETest, BoundedOutboundRetryDeliversAfterTransientBackpressure) {
  FakeRadioProfilePort requesterRadio, grantorRadio;
  FakeClock requesterClock, grantorClock;
  FakeTransport requesterTransport, grantorTransport;
  FakeLeaseGrantPolicy requesterPolicy, grantorPolicy;
  DirectLeaseEngine requester(requesterRadio, requesterClock, requesterTransport, requesterPolicy);
  DirectLeaseEngine grantor(grantorRadio, grantorClock, grantorTransport, grantorPolicy);

  ASSERT_TRUE(requester.requestLease(grantorPeer_, validRequested(), 5000));
  AuthenticatedInboundFrame reqFrame =
      makeInboundFrame(requesterTransport.sentLog[0].bytes, requesterPeer_);
  // The Grant send hits transient backpressure once; the engine must not
  // silently fake an ACK/progress and must not busy-loop -- it retries the
  // identical already-encoded frame on a later tick until accepted.
  grantorTransport.forcedResults.push_back(CampaignSendResult::Backpressure);
  ASSERT_TRUE(grantor.onFrame(reqFrame));
  EXPECT_TRUE(grantorTransport.sentLog.empty());
  EXPECT_EQ(DirectLeasePhase::AwaitingActivate, grantor.phase());

  grantor.tickWatchdog(); // retries the pending Grant send
  ASSERT_EQ(1u, grantorTransport.sentLog.size());

  AuthenticatedInboundFrame grantFrame =
      makeInboundFrame(grantorTransport.sentLog[0].bytes, grantorPeer_);
  ASSERT_TRUE(requester.onFrame(grantFrame));
  EXPECT_EQ(DirectLeasePhase::AwaitingAck, requester.phase());
}

// =======================================================================
// Gap B: genuine real production trust/staging/storage reboot proof.
//
// Everything a false "reboot resume" test could otherwise fake is real
// here: a real ::ota::platform::FlashRegion-backed staging sink (this
// component's own CampaignFirmwareStagingSink, see
// CampaignFirmwareStaging.h) writing/reading actual bytes through
// ::ota::storage::StorageManager against an in-memory NOR flash model
// that enforces real erase/program-once semantics; a real
// ::mesh::ota::OtaFirmwareTrustProvider backed by a real
// ::ota::trust::DescriptorVerifier (real SHA-256 over the flash-resident
// image, real Ed25519 signature verification, a real anti-rollback
// monotonic counter, real target/role/format/key/algorithm policy
// checks). "Host inaccessible after reboot" is modeled by destructing
// EVERY RAM-side object (both engines, both trust providers, both
// staging sinks) and reconstructing brand new ones from nothing but (a)
// the durable persisted-metadata bytes and (b) the SAME underlying
// FakeNorFlash device object (standing in for physical flash, which by
// definition survives a real reboot when RAM does not).
namespace {

// Thin, test-only genuine Ed25519 keypair+signing wrapper -- duplicated
// locally (rather than included across test directories) from the
// identical, already-reviewed pattern in
// test/test_lora_ota_trust/Ed25519TestSigner.h. Calls the same vendored
// ed25519_create_keypair/ed25519_sign routines production code never
// calls (production only ever calls ed25519_verify).
class CampaignEd25519TestSigner {
public:
  explicit CampaignEd25519TestSigner(const uint8_t seed[32]) {
    ::ota::trust::ed25519_impl::ed25519_create_keypair(publicKey_, privateKey_, seed);
  }
  const uint8_t* publicKey() const { return publicKey_; }
  void sign(const uint8_t* message, size_t messageLen, uint8_t outSignature[64]) const {
    ::ota::trust::ed25519_impl::ed25519_sign(outSignature, message, messageLen, publicKey_, privateKey_);
  }

private:
  uint8_t publicKey_[32] = {0};
  uint8_t privateKey_[64] = {0};
};

// A real, correct (not a behavioral shortcut) in-memory implementation of
// the trivial ::ota::trust::MonotonicCounter contract: no production
// flash-backed implementation of this 2-method interface exists inside
// this component's readable scope, and the interface itself has no
// physical-medium subtlety to fake (unlike flash program/erase
// semantics) -- an in-memory value that genuinely refuses any
// non-strictly-increasing commit satisfies the real contract exactly.
class SimpleMonotonicCounter : public ::ota::trust::MonotonicCounter {
public:
  bool currentValue(uint32_t& out) const override {
    out = value_;
    return true;
  }
  bool commitNewValue(uint32_t newValue) override {
    if (newValue <= value_) return false;
    value_ = newValue;
    return true;
  }

private:
  uint32_t value_ = 0;
};

// Test-only IOtaInstallCommandProviderV2 double: the REAL production
// implementation (OtaBoardInstallCommandProviderV2 in
// helpers/ota/OtaBoardBackendCommon.h) depends on
// XiaoOtaActiveExtentBridge::resolveCurrent(), which is hardware/QSPI-
// bound and always fails closed (returns extent 0) off-target, so it
// cannot be exercised in a native host test. This double stands in ONLY
// for "where does the currently-running image's extent/hash come from"
// -- it reuses the REAL, unmodified computeOtaTransactionNonce() helper
// (never reimplements nonce derivation) and copies wireDescriptor/
// signature verbatim (never re-signs), exactly like the real provider,
// so the test still proves genuine commit()/writeNext() plumbing rather
// than fabricating a command record directly.
class TestActiveExtentCommandProviderV2 : public ::mesh::ota::IOtaInstallCommandProviderV2 {
public:
  TestActiveExtentCommandProviderV2(uint32_t activeImageExtent, const uint8_t activeImageHash[32])
      : activeImageExtent_(activeImageExtent) {
    std::memcpy(activeImageHash_, activeImageHash, sizeof(activeImageHash_));
  }

  bool buildInstallCommandV2(const uint8_t wireDescriptor59[::ota::storage::XiaoOtaCommandRecordV2::kWireDescriptorBytes],
                             const uint8_t signature64[::ota::storage::XiaoOtaCommandRecordV2::kSignatureBytes],
                             const runtime::OtaSessionId& session, const uint8_t controller[32],
                             ::ota::storage::XiaoOtaCommandV2Fields& out) override {
    std::memcpy(out.wire_descriptor, wireDescriptor59, sizeof(out.wire_descriptor));
    std::memcpy(out.signature_ed25519, signature64, sizeof(out.signature_ed25519));
    out.active_image_extent = activeImageExtent_;
    std::memcpy(out.active_image_hash_sha256, activeImageHash_, sizeof(out.active_image_hash_sha256));
    out.transaction_nonce = ::mesh::ota::computeOtaTransactionNonce(controller, session, wireDescriptor59);
    return true;
  }

private:
  uint32_t activeImageExtent_;
  uint8_t activeImageHash_[32] = {};
};

} // namespace

class DirectedRealTrustStagingRebootTest : public ::testing::Test {
protected:
  static constexpr uint32_t kFlashTotalBytes = 8192;
  static constexpr uint32_t kEraseUnitBytes = 4096;

  void SetUp() override {
    controller_ = makePeerId(0x77);
    imageSize_ = 128 * 5 + 37; // unequal final chunk, same geometry as the other Directed tests
    hostImage_.data.resize(imageSize_);
    for (size_t i = 0; i < imageSize_; ++i) hostImage_.data[i] = static_cast<uint8_t>((i * 7 + 3) & 0xFF);

    // Real SHA-256 over the actual host image bytes -- this is the exact
    // hash the trust provider will independently recompute from FLASH
    // (not from these RAM bytes) once every chunk has been written, so a
    // mismatch here would be a genuine trust failure, not a fixture bug.
    ::ota::trust::Sha256 hasher;
    uint8_t realHash[32];
    hasher.reset();
    hasher.update(hostImage_.data.data(), hostImage_.data.size());
    hasher.finish(realHash);

    descriptor_ = protocol::OtaDescriptor{};
    descriptor_.boardFamily = 1;
    descriptor_.boardVariant = 1;
    descriptor_.role = 1;
    descriptor_.appAddress = 0x1000;
    descriptor_.exactSizeBytes = imageSize_;
    std::memcpy(descriptor_.sha256, realHash, sizeof(descriptor_.sha256));
    descriptor_.securityCounter = 1;
    descriptor_.minBootloaderCapabilities = 0;
    descriptor_.formatId = 1;
    descriptor_.keyId = 1;
    descriptor_.algorithmId = 1;

    uint8_t canonical[protocol::kOtaDescriptorCanonicalSize];
    size_t canonicalLen = 0;
    ASSERT_EQ(protocol::OtaDescriptorCodecResult::Ok,
              protocol::encodeOtaDescriptorCanonical(descriptor_, canonical, sizeof(canonical), canonicalLen));

    uint8_t seed[32];
    std::memset(seed, 0x42, sizeof(seed));
    CampaignEd25519TestSigner signer(seed);
    std::memcpy(publisherPublicKey_, signer.publicKey(), 32);
    uint8_t sig[64];
    signer.sign(canonical, canonicalLen, sig);
    sig_.assign(sig, sig + 64);
  }

  ::ota::platform::FlashDevice* makeFlashDevice() { return new ota::test::FakeNorFlash(kFlashTotalBytes, kEraseUnitBytes, 1); }

  CampaignPeerId controller_;
  uint32_t imageSize_ = 0;
  protocol::OtaDescriptor descriptor_{};
  std::vector<uint8_t> sig_;
  FakeHostImageReader hostImage_;
  uint8_t publisherPublicKey_[32] = {};
};

TEST_F(DirectedRealTrustStagingRebootTest, RealFlashBackedTransferSurvivesFullProcessRebootWithFreshTrustAndStaging) {
  // NOTE ON SCOPE: this models a REBOOT OF THE TARGET DEVICE mid-transfer
  // (the scenario this whole gap is about: durable target trust/staging
  // reconstruction from real flash after the process that was flashing
  // itself restarts). The updater/host side is intentionally kept alive
  // across the simulated reboot -- exactly like the existing
  // RebootMidTransferResumesFromPersistedBitmap fixture keeps its own
  // frame-sequence counter running rather than resetting it to zero.
  // The updater's own host-disconnect/cache-resume story is a SEPARATE,
  // already-covered concern (IOtaCacheOnlySink-only, no trust/flash
  // involved) and is not what Gap B asked to prove.
  ota::test::FakeNorFlash flash(kFlashTotalBytes, kEraseUnitBytes, 1);
  ::ota::platform::FlashRegion region(flash, 0, kEraseUnitBytes);
  ASSERT_TRUE(region.isValid());

  FakeCacheSink cache;
  FakeTrust updaterTrust; // updater side never needs real trust: it only ever verifies its OWN authored descriptor
  FakeTransport updaterTransport;
  FakeTransport targetTransport;
  FakeClock clock;
  FakePersistence persistence; // durable metadata byte store; survives the simulated target reboot below
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();

  ::ota::trust::DeviceTrustAnchor anchor;
  std::memcpy(anchor.trusted_signer_public_key_ed25519, publisherPublicKey_, 32);
  anchor.expected_target_id = (static_cast<uint32_t>(descriptor_.boardFamily) << 16) | descriptor_.boardVariant;
  anchor.expected_role_id = descriptor_.role;
  anchor.device_address = 0;
  anchor.supported_boot_capability_flags = 0;
  anchor.expected_format_id = descriptor_.formatId;
  anchor.expected_key_id = descriptor_.keyId;
  anchor.expected_algorithm_id = descriptor_.algorithmId;

  const runtime::OtaSessionId session{555, 1, 1};
  CampaignDestination dest;
  dest.scope = CampaignAuthScope::Pairwise;
  dest.peerId = makePeerId(0x88);

  // The updater and its transport/frame cursors survive the "reboot"
  // below untouched -- only the target side (trust provider, staging
  // sink, receiver engine) is destroyed and reconstructed from durable
  // bytes, proving REAL flash-backed resume without discarding the
  // updater's own live retry/ack bookkeeping.
  UpdaterCampaignEngine updater(updaterTrust, cache, updaterTransport, hostImage_, clock);
  ASSERT_TRUE(updater.begin(session, descriptor_, sig_.data(), sig_.size(), dest, controller_));

  size_t updaterCursor = 0;
  size_t targetCursor = 0;

  // --- Phase 1: run everything up to (but not including) the FINAL
  // chunk's receipt reaching the updater, using REAL trust+staging on
  // the target side, then simulate the TARGET rebooting mid-transfer.
  {
    ::ota::trust::Sha256 hasher;
    ::ota::trust::Ed25519SignatureVerifier wireVerifier;
    SimpleMonotonicCounter counter;
    ::ota::trust::DescriptorVerifier targetVerifier(hasher, wireVerifier, counter, anchor);
    ::mesh::ota::OtaFirmwareTrustProvider targetTrust(targetVerifier, region, wireVerifier, publisherPublicKey_);
    CampaignFirmwareStagingSink staging(region);
    TargetReceiverEngine target(targetTrust, staging, persistence, boot, consent, commissioning);
    target.bindTransport(targetTransport);
    target.bindClock(clock);
    target.bindStagingResume(staging);

    bool sawAllButLastReceipt = false;
    int iterations = 0;
    const int kMaxIterations = 2000;
    while (!sawAllButLastReceipt && ++iterations < kMaxIterations) {
      updater.tick();
      target.tick();

      while (updaterCursor < updaterTransport.sentLog.size()) {
        const auto& sent = updaterTransport.sentLog[updaterCursor++];
        AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, controller_);
        target.onFrame(f);
      }
      while (targetCursor < targetTransport.sentLog.size()) {
        const auto& sent = targetTransport.sentLog[targetCursor++];
        CampaignEnvelopeHeader hdr;
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        ASSERT_EQ(CampaignCodecResult::Ok,
                  decodeCampaignEnvelope(sent.bytes.data(), sent.bytes.size(), hdr, payload, payloadLen));
        if (hdr.type == CampaignMessageType::Receipt) {
          protocol::OtaReceiptPayload r;
          ASSERT_TRUE(protocol::decodeOtaReceipt(payload, payloadLen, r));
          if (r.status == protocol::OtaReceiptStatus::ChunkAck && r.chunkIndex == 5) {
            // The reboot below discards this final ack (and every later
            // frame) unread -- the updater must recover it after resume.
            sawAllButLastReceipt = true;
            break;
          }
        }
        AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, makePeerId(0x88));
        updater.onFrame(f);
      }
      clock.advance(50);
    }
    ASSERT_TRUE(sawAllButLastReceipt);
    // Sanity: real flash actually has real data on it now, independent of
    // any RAM object we are about to destroy.
    uint8_t rawCheck[128];
    ASSERT_TRUE(::ota::platform::isOk(region.read(0, rawCheck, 128)));
    EXPECT_EQ(0, std::memcmp(rawCheck, hostImage_.data.data(), 128));
    // The real sink actually received the verified wire descriptor+
    // signature and the authenticated authorized-session binding during
    // admission -- a real bootloader-handoff-capable production sink
    // needs exactly these to durably bind its install-command transaction
    // identity at commit() time; this is the pre-reboot baseline the next
    // check proves reload() genuinely restores.
    EXPECT_TRUE(staging.haveVerifiedWireDescriptor());
    EXPECT_TRUE(staging.haveAuthorizedSession());
    EXPECT_EQ(0, std::memcmp(staging.authorizedController(), controller_.bytes, 32));
    // target/trust/staging (all RAM-side) fall out of scope here --
    // simulating the TARGET device rebooting. Only `flash` (the physical
    // medium) and `persistence` (the durable metadata store) survive.
  }

  // --- Phase 2: full target reboot. Brand new trust/staging/engine
  // objects, reconstructed from nothing but the retained flash bytes and
  // the durable persisted metadata -- the target-side process that ran
  // phase 1 is genuinely gone.
  ::ota::trust::Sha256 hasher2;
  ::ota::trust::Ed25519SignatureVerifier wireVerifier2;
  SimpleMonotonicCounter counter2; // NOTE: counter is separately-provisioned device state that also
                                    // survives reboot in reality; modeled fresh-but-equivalent here.
  ::ota::trust::DescriptorVerifier targetVerifier2(hasher2, wireVerifier2, counter2, anchor);
  ::mesh::ota::OtaFirmwareTrustProvider targetTrust2(targetVerifier2, region, wireVerifier2, publisherPublicKey_);
  CampaignFirmwareStagingSink staging2(region);
  TargetReceiverEngine target2(targetTrust2, staging2, persistence, boot, consent, commissioning);
  target2.bindTransport(targetTransport);
  target2.bindClock(clock);
  target2.bindStagingResume(staging2);

  ASSERT_TRUE(target2.reload());
  EXPECT_TRUE(staging2.isActive());
  // The BRAND NEW sink, freshly constructed with zero RAM carried over,
  // must have had the SAME exact verified-wire-descriptor+signature and
  // authorized-session binding re-delivered by reload() -- proving the
  // "resume" path restores this binding from durable bytes rather than
  // only reattaching the flash region.
  EXPECT_TRUE(staging2.haveVerifiedWireDescriptor());
  EXPECT_TRUE(staging2.haveAuthorizedSession());
  {
    uint8_t expectedCanonical[protocol::kOtaDescriptorCanonicalSize];
    size_t expectedCanonicalLen = 0;
    ASSERT_EQ(protocol::OtaDescriptorCodecResult::Ok,
              protocol::encodeOtaDescriptorCanonical(descriptor_, expectedCanonical, sizeof(expectedCanonical),
                                                       expectedCanonicalLen));
    EXPECT_EQ(0, std::memcmp(staging2.verifiedWireDescriptor(), expectedCanonical,
                             protocol::kOtaDescriptorCanonicalSize));
  }
  EXPECT_EQ(0, std::memcmp(staging2.authorizedController(), controller_.bytes, 32));

  bool bootFired = false;
  int iterations2 = 0;
  const int kMaxIterations2 = 4000;
  while (updater.outcome() == UpdaterOutcome::InProgress && ++iterations2 < kMaxIterations2) {
    updater.tick();
    target2.tick();
    while (updaterCursor < updaterTransport.sentLog.size()) {
      const auto& sent = updaterTransport.sentLog[updaterCursor++];
      AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, controller_);
      target2.onFrame(f);
    }
    while (targetCursor < targetTransport.sentLog.size()) {
      const auto& sent = targetTransport.sentLog[targetCursor++];
      AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, makePeerId(0x88));
      updater.onFrame(f);
    }
    if (target2.status() == TargetStatus::InstalledPending) {
      if (!bootFired) {
        boot.evidence.healthyBootConfirmed = true;
        boot.evidence.bootedSession = session;
        std::memcpy(boot.evidence.bootedImageHash, descriptor_.sha256, protocol::kOtaSha256Size);
        boot.evidence.bootedSecurityCounter = descriptor_.securityCounter;
        bootFired = true;
      }
      target2.confirmHealthyBoot();
    }
    clock.advance(50);
  }

  ASSERT_LT(iterations2, kMaxIterations2) << "post-reboot transfer did not converge";
  EXPECT_EQ(TargetStatus::Installed, target2.status());
  EXPECT_EQ(UpdaterOutcome::Complete, updater.outcome());
  EXPECT_TRUE(staging2.isCommitted());

  // Full-image bytes on the real flash region genuinely match the host
  // image, independently readable after everything above completed --
  // this is the actual SHA-256/Ed25519-enforced outcome, not a
  // RAM-object assertion.
  std::vector<uint8_t> flashImage(imageSize_);
  ASSERT_TRUE(::ota::platform::isOk(region.read(0, flashImage.data(), static_cast<uint32_t>(imageSize_))));
  EXPECT_EQ(0, std::memcmp(flashImage.data(), hostImage_.data.data(), imageSize_));
}

// Full fault-matrix outcome against the REAL production trust+staging
// sink (not fakes): a save-before-mutation refusal (RejectedBeforeMutation)
// during admission is reversibly rolled back and leaves the durable
// store genuinely empty, while an Uncertain outcome AFTER chunk bytes
// are already durably on real flash freezes the target WITHOUT losing
// those bytes -- a completely fresh production trust/staging/engine
// reconstruction (a second, independent "reboot") recovers them and the
// transfer still reaches a genuine, hash-verified Installed outcome.
TEST_F(DirectedRealTrustStagingRebootTest, FullFaultMatrixSaveBeforeMutationAndUncertainAfterDurableBytesRecoverViaFreshReconstruction) {
  ota::test::FakeNorFlash flash(kFlashTotalBytes, kEraseUnitBytes, 1);
  ::ota::platform::FlashRegion region(flash, 0, kEraseUnitBytes);
  ASSERT_TRUE(region.isValid());

  FakeCacheSink cache;
  FakeTrust updaterTrust;
  FakeTransport updaterTransport;
  FakeTransport targetTransport;
  FakeClock clock;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();

  ::ota::trust::DeviceTrustAnchor anchor;
  std::memcpy(anchor.trusted_signer_public_key_ed25519, publisherPublicKey_, 32);
  anchor.expected_target_id = (static_cast<uint32_t>(descriptor_.boardFamily) << 16) | descriptor_.boardVariant;
  anchor.expected_role_id = descriptor_.role;
  anchor.device_address = 0;
  anchor.supported_boot_capability_flags = 0;
  anchor.expected_format_id = descriptor_.formatId;
  anchor.expected_key_id = descriptor_.keyId;
  anchor.expected_algorithm_id = descriptor_.algorithmId;

  const runtime::OtaSessionId session{556, 1, 1};
  CampaignDestination dest;
  dest.scope = CampaignAuthScope::Pairwise;
  dest.peerId = makePeerId(0x88);
  AuthenticatedInboundFrame consentFrame = makeInboundFrame({}, controller_);
  CampaignConsentRequestPayload consentPayload = makeConsentPayload(controller_);

  // --- Sub-scenario 1: RejectedBeforeMutation on the VERY FIRST
  // admission attempt (real sink) is genuinely reversible for the MAIN
  // record and the sink itself: beginSession()'s side effect is rolled
  // back, and the durable store is left provably empty. Uses its OWN
  // isolated commissioning-provenance fixture (deliberately NOT the
  // shared `commissioning` used by the rest of this test): the
  // Virgin->Used transition is durable and irreversible BY DESIGN (see
  // ICampaignCommissioningProvenancePort) even though every OTHER effect
  // of this specific probe attempt is fully undone -- that irreversible
  // transition is exercised/asserted on its own isolated port below, so
  // it does not consume the shared fixture's virginity that sub-scenario
  // 2 depends on for its "genuinely never-commissioned Missing" premise.
  {
    ::ota::trust::Sha256 hasher;
    ::ota::trust::Ed25519SignatureVerifier wireVerifier;
    SimpleMonotonicCounter counter;
    ::ota::trust::DescriptorVerifier verifier(hasher, wireVerifier, counter, anchor);
    ::mesh::ota::OtaFirmwareTrustProvider trust(verifier, region, wireVerifier, publisherPublicKey_);
    CampaignFirmwareStagingSink staging(region);
    FakeCommissioningProvenancePort isolatedCommissioning;
    isolatedCommissioning.initializeGenuineFactoryVirgin();
    TargetReceiverEngine target(trust, staging, persistence, boot, consent, isolatedCommissioning);

    persistence.saveShouldFail = true;
    EXPECT_FALSE(target.handleConsentRequest(consentFrame, 1, session, consentPayload, descriptor_, sig_.data(),
                                              sig_.size()));
    EXPECT_FALSE(target.isPersistUncertain());
    EXPECT_FALSE(target.isReloadUnsafe());
    // Real sink genuinely reversed the begin() it just performed.
    EXPECT_FALSE(staging.isActive());
    // ...but the isolated commissioning-provenance transition is durable
    // and NOT reversed: proves the intended asymmetry (irreversible
    // Virgin->Used vs. reversible sink/main-record mutation).
    EXPECT_EQ(CampaignCommissioningState::Used, isolatedCommissioning.readCommissioningProvenance().state);
    persistence.saveShouldFail = false;
  }
  ASSERT_TRUE(persistence.store.find(CampaignPersistRole::TargetReceiver) == persistence.store.end())
      << "RejectedBeforeMutation must leave the durable store genuinely untouched";

  // A brand-new engine reloading now sees an honest, unambiguous
  // Missing -- and can freely admit a genuinely fresh session.
  UpdaterCampaignEngine updater(updaterTrust, cache, updaterTransport, hostImage_, clock);
  ASSERT_TRUE(updater.begin(session, descriptor_, sig_.data(), sig_.size(), dest, controller_));
  size_t updaterCursor = 0;
  size_t targetCursor = 0;

  bool sawFirstDataChunkDurable = false;
  {
    ::ota::trust::Sha256 hasher;
    ::ota::trust::Ed25519SignatureVerifier wireVerifier;
    SimpleMonotonicCounter counter;
    ::ota::trust::DescriptorVerifier verifier(hasher, wireVerifier, counter, anchor);
    ::mesh::ota::OtaFirmwareTrustProvider trust(verifier, region, wireVerifier, publisherPublicKey_);
    CampaignFirmwareStagingSink staging(region);
    TargetReceiverEngine target(trust, staging, persistence, boot, consent, commissioning);
    target.bindTransport(targetTransport);
    target.bindClock(clock);
    target.bindStagingResume(staging);
    ASSERT_TRUE(target.reload());
    EXPECT_FALSE(target.isControllerBound()); // genuinely never-commissioned Missing -> fresh Idle

    // --- Sub-scenario 2: run the transfer for real until the target has
    // received its first data chunk, then force the NEXT chunk-apply's
    // persistence checkpoint to report Uncertain. The sink write itself
    // (write+readback, the sink's own separate contract) already lands
    // on real flash BEFORE the checkpoint attempt -- so the bytes must
    // remain durably correct even though this target instance freezes
    // and withholds the ack.
    int iterations = 0;
    const int kMaxIterations = 2000;
    while (!sawFirstDataChunkDurable && ++iterations < kMaxIterations) {
      updater.tick();
      if (target.isControllerBound() && !target.isPersistUncertain() && !persistence.forceUncertainNextSave) {
        persistence.forceUncertainNextSave = true; // arms exactly once, consumed by the next chunk save
      }
      target.tick();
      while (updaterCursor < updaterTransport.sentLog.size()) {
        const auto& sent = updaterTransport.sentLog[updaterCursor++];
        AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, controller_);
        target.onFrame(f);
      }
      while (targetCursor < targetTransport.sentLog.size()) {
        const auto& sent = targetTransport.sentLog[targetCursor++];
        AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, makePeerId(0x88));
        updater.onFrame(f);
      }
      if (target.isPersistUncertain()) { sawFirstDataChunkDurable = true; break; }
      clock.advance(50);
    }
    ASSERT_TRUE(sawFirstDataChunkDurable);

    // The first chunk's bytes are genuinely durable on real flash RIGHT
    // NOW, despite this target instance being frozen and never having
    // ack'd them.
    uint32_t chunk0Len = 0;
    ASSERT_TRUE(target.geometry().chunkLength(0, chunk0Len));
    std::vector<uint8_t> rawCheck(chunk0Len);
    ASSERT_TRUE(::ota::platform::isOk(region.read(0, rawCheck.data(), chunk0Len)));
    EXPECT_EQ(0, std::memcmp(rawCheck.data(), hostImage_.data.data(), chunk0Len));
    // No further admission/mutation is possible on this frozen instance.
    EXPECT_FALSE(target.applyChunk(makeInboundFrame({}, controller_), 9999, session,
                                    protocol::OtaChunkHeader{0, static_cast<uint16_t>(chunk0Len)}, rawCheck.data(),
                                    rawCheck.size()));
    EXPECT_EQ(CampaignRefusalReason::UnresolvedPersistedState, target.lastRefusal());
    // target/trust/staging fall out of scope: a completely fresh
    // reconstruction (independent of this frozen instance) is next.
  }

  // --- Sub-scenario 2, continued: fresh production trust/staging/
  // engine, reconstructed from nothing but the retained flash bytes and
  // durable persisted metadata, recovers the ALREADY-DURABLE chunk and
  // drives the transfer to a genuine, hash-verified Installed outcome --
  // proving the Uncertain freeze never sacrificed real progress.
  ::ota::trust::Sha256 hasher3;
  ::ota::trust::Ed25519SignatureVerifier wireVerifier3;
  SimpleMonotonicCounter counter3;
  ::ota::trust::DescriptorVerifier verifier3(hasher3, wireVerifier3, counter3, anchor);
  ::mesh::ota::OtaFirmwareTrustProvider trust3(verifier3, region, wireVerifier3, publisherPublicKey_);
  CampaignFirmwareStagingSink staging3(region);
  TargetReceiverEngine target3(trust3, staging3, persistence, boot, consent, commissioning);
  target3.bindTransport(targetTransport);
  target3.bindClock(clock);
  target3.bindStagingResume(staging3);

  ASSERT_TRUE(target3.reload());
  EXPECT_TRUE(target3.isControllerBound());
  EXPECT_FALSE(target3.isPersistUncertain());
  EXPECT_FALSE(target3.isReloadUnsafe());

  // A foreign controller cannot hijack this recovered, still-live
  // session.
  {
    CampaignPeerId foreign = makePeerId(0xAA);
    runtime::OtaSessionId foreignSession{9999, 1, 1};
    AuthenticatedInboundFrame foreignFrame = makeInboundFrame({}, foreign);
    EXPECT_FALSE(target3.handleConsentRequest(foreignFrame, 1, foreignSession, makeConsentPayload(foreign),
                                               descriptor_, sig_.data(), sig_.size()));
  }
  // The SAME exact already-durable chunk is idempotently re-appliable
  // (same-context idempotence) without erasing/duplicating anything.
  {
    uint32_t chunk0Len = 0;
    ASSERT_TRUE(target3.geometry().chunkLength(0, chunk0Len));
    std::vector<uint8_t> chunk0(hostImage_.data.begin(), hostImage_.data.begin() + chunk0Len);
    EXPECT_TRUE(target3.applyChunk(makeInboundFrame({}, controller_), 1, session,
                                    protocol::OtaChunkHeader{0, static_cast<uint16_t>(chunk0Len)}, chunk0.data(),
                                    chunk0.size()));
  }

  bool bootFired = false;
  int iterations3 = 0;
  const int kMaxIterations3 = 4000;
  while (updater.outcome() == UpdaterOutcome::InProgress && ++iterations3 < kMaxIterations3) {
    updater.tick();
    target3.tick();
    while (updaterCursor < updaterTransport.sentLog.size()) {
      const auto& sent = updaterTransport.sentLog[updaterCursor++];
      AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, controller_);
      target3.onFrame(f);
    }
    while (targetCursor < targetTransport.sentLog.size()) {
      const auto& sent = targetTransport.sentLog[targetCursor++];
      AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, makePeerId(0x88));
      updater.onFrame(f);
    }
    if (target3.status() == TargetStatus::InstalledPending) {
      if (!bootFired) {
        boot.evidence.healthyBootConfirmed = true;
        boot.evidence.bootedSession = session;
        std::memcpy(boot.evidence.bootedImageHash, descriptor_.sha256, protocol::kOtaSha256Size);
        boot.evidence.bootedSecurityCounter = descriptor_.securityCounter;
        bootFired = true;
      }
      target3.confirmHealthyBoot();
    }
    clock.advance(50);
  }

  ASSERT_LT(iterations3, kMaxIterations3) << "post-fault-recovery transfer did not converge";
  EXPECT_EQ(TargetStatus::Installed, target3.status());
  EXPECT_EQ(UpdaterOutcome::Complete, updater.outcome());
  EXPECT_TRUE(staging3.isCommitted());

  std::vector<uint8_t> flashImage3(imageSize_);
  ASSERT_TRUE(::ota::platform::isOk(region.read(0, flashImage3.data(), static_cast<uint32_t>(imageSize_))));
  EXPECT_EQ(0, std::memcmp(flashImage3.data(), hostImage_.data.data(), imageSize_));
}

// Gap 2: proves genuine V2 command-record durability, not merely
// metadata-getter observables. Drives a REAL end-to-end transfer through
// CampaignFirmwareStagingSink's V2 ctor (real production
// OtaFirmwareStorageSink, real StorageManager, real
// XiaoOtaCommandRecordV2::writeNext()) to a genuine commit(), then reads
// back the actual 188-byte record through a FRESHLY reconstructed
// FlashRegion object (proving the bytes survive independent of any RAM
// object from the transfer) and asserts byte-for-byte: the embedded wire
// descriptor/signature are the REAL verified bytes (not re-derived), the
// transaction nonce matches an independently-recomputed call to the
// SAME real computeOtaTransactionNonce() helper the provider used, and
// the active-image extent/hash are exactly what the (test-only,
// hardware-independent) provider supplied.
TEST_F(DirectedRealTrustStagingRebootTest, V2CommandRecordDurablyWrittenWithRealPlumbingAssertedAfterFreshReconstruction) {
  ota::test::FakeNorFlash flash(kFlashTotalBytes, kEraseUnitBytes, 1);
  ::ota::platform::FlashRegion region(flash, 0, kEraseUnitBytes);
  ASSERT_TRUE(region.isValid());

  // XiaoOtaCommandRecordV2 requires an A/B region of EXACTLY 2 erase
  // units, on its OWN flash device here (a real board typically shares
  // physical sectors with candidate storage, but a distinct device is
  // just as valid and keeps this test's fixture simple).
  ota::test::FakeNorFlash commandFlash(2 * kEraseUnitBytes, kEraseUnitBytes, 1);
  ::ota::platform::FlashRegion commandRegion(commandFlash, 0, 2 * kEraseUnitBytes);
  ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV2::regionIsValid(commandRegion));

  // A genuinely-computed (never a hardcoded placeholder) "currently
  // running image" fixture: real SHA-256 over real bytes, standing in
  // for the hardware-bound XiaoOtaActiveExtentBridge::resolveCurrent().
  std::vector<uint8_t> activeImageBytes(256);
  for (size_t i = 0; i < activeImageBytes.size(); ++i) {
    activeImageBytes[i] = static_cast<uint8_t>((i * 13 + 5) & 0xFF);
  }
  ::ota::trust::Sha256 activeHasher;
  uint8_t activeImageHash[32];
  activeHasher.reset();
  activeHasher.update(activeImageBytes.data(), activeImageBytes.size());
  activeHasher.finish(activeImageHash);
  const uint32_t activeImageExtent = static_cast<uint32_t>(activeImageBytes.size());
  TestActiveExtentCommandProviderV2 provider(activeImageExtent, activeImageHash);

  FakeCacheSink cache;
  FakeTrust updaterTrust;
  FakeTransport updaterTransport;
  FakeTransport targetTransport;
  FakeClock clock;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();

  ::ota::trust::DeviceTrustAnchor anchor;
  std::memcpy(anchor.trusted_signer_public_key_ed25519, publisherPublicKey_, 32);
  anchor.expected_target_id = (static_cast<uint32_t>(descriptor_.boardFamily) << 16) | descriptor_.boardVariant;
  anchor.expected_role_id = descriptor_.role;
  anchor.device_address = 0;
  anchor.supported_boot_capability_flags = 0;
  anchor.expected_format_id = descriptor_.formatId;
  anchor.expected_key_id = descriptor_.keyId;
  anchor.expected_algorithm_id = descriptor_.algorithmId;

  const runtime::OtaSessionId session{777, 3, 1};
  CampaignDestination dest;
  dest.scope = CampaignAuthScope::Pairwise;
  dest.peerId = makePeerId(0x88);

  UpdaterCampaignEngine updater(updaterTrust, cache, updaterTransport, hostImage_, clock);
  ASSERT_TRUE(updater.begin(session, descriptor_, sig_.data(), sig_.size(), dest, controller_));

  size_t updaterCursor = 0;
  size_t targetCursor = 0;

  ::ota::trust::Sha256 hasher;
  ::ota::trust::Ed25519SignatureVerifier wireVerifier;
  SimpleMonotonicCounter counter;
  ::ota::trust::DescriptorVerifier targetVerifier(hasher, wireVerifier, counter, anchor);
  ::mesh::ota::OtaFirmwareTrustProvider targetTrust(targetVerifier, region, wireVerifier, publisherPublicKey_);
  CampaignFirmwareStagingSink staging(region, &commandRegion, &provider);
  TargetReceiverEngine target(targetTrust, staging, persistence, boot, consent, commissioning);
  target.bindTransport(targetTransport);
  target.bindClock(clock);
  target.bindStagingResume(staging);

  bool bootFired = false;
  int iterations = 0;
  const int kMaxIterations = 4000;
  while (updater.outcome() == UpdaterOutcome::InProgress && ++iterations < kMaxIterations) {
    updater.tick();
    target.tick();
    while (updaterCursor < updaterTransport.sentLog.size()) {
      const auto& sent = updaterTransport.sentLog[updaterCursor++];
      AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, controller_);
      target.onFrame(f);
    }
    while (targetCursor < targetTransport.sentLog.size()) {
      const auto& sent = targetTransport.sentLog[targetCursor++];
      AuthenticatedInboundFrame f = makeInboundFrame(sent.bytes, makePeerId(0x88));
      updater.onFrame(f);
    }
    if (target.status() == TargetStatus::InstalledPending) {
      if (!bootFired) {
        boot.evidence.healthyBootConfirmed = true;
        boot.evidence.bootedSession = session;
        std::memcpy(boot.evidence.bootedImageHash, descriptor_.sha256, protocol::kOtaSha256Size);
        boot.evidence.bootedSecurityCounter = descriptor_.securityCounter;
        bootFired = true;
      }
      target.confirmHealthyBoot();
    }
    clock.advance(50);
  }
  ASSERT_LT(iterations, kMaxIterations) << "V2 command-record transfer did not converge";
  EXPECT_EQ(TargetStatus::Installed, target.status());
  EXPECT_TRUE(staging.isCommitted());

  // --- Reconstruct from nothing but the retained flash bytes: a
  // brand-new FlashRegion object over the SAME command flash device,
  // proving the durable 188-byte record survives independent of any RAM
  // object above (staging/target/trust all still technically in scope
  // here, but this NEW region object shares none of their state).
  ::ota::platform::FlashRegion freshCommandRegion(commandFlash, 0, 2 * kEraseUnitBytes);
  ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV2::regionIsValid(freshCommandRegion));
  uint8_t rawRecord[::ota::storage::XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV2::readNewest(freshCommandRegion, rawRecord));
  ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV2::isValidRecord(rawRecord, sizeof(rawRecord)));

  uint8_t expectedCanonical[protocol::kOtaDescriptorCanonicalSize];
  size_t expectedCanonicalLen = 0;
  ASSERT_EQ(protocol::OtaDescriptorCodecResult::Ok,
            protocol::encodeOtaDescriptorCanonical(descriptor_, expectedCanonical, sizeof(expectedCanonical),
                                                     expectedCanonicalLen));
  // wire_descriptor at real offset 20 (verified in
  // XiaoOtaCommandRecordV2::kWireDescriptorOffset), signature
  // immediately following at 79 -- both copied VERBATIM by the sink/
  // provider from the transport's own verified bytes, never re-derived.
  EXPECT_EQ(0, std::memcmp(::ota::storage::XiaoOtaCommandRecordV2::wireDescriptorOf(rawRecord), expectedCanonical,
                           protocol::kOtaDescriptorCanonicalSize));
  EXPECT_EQ(0, std::memcmp(rawRecord + 79, sig_.data(), sig_.size()));

  // Transaction nonce is derived from the REAL controller+session+wire-
  // descriptor bytes via the SAME shared production helper -- never
  // fabricated by the test, and stable/reproducible from those inputs.
  const uint64_t storedNonce = ::ota::storage::XiaoOtaCommandRecordV2::transactionNonceOf(rawRecord);
  const uint64_t expectedNonce =
      ::mesh::ota::computeOtaTransactionNonce(controller_.bytes, session, expectedCanonical);
  EXPECT_NE(0u, expectedNonce);
  EXPECT_EQ(expectedNonce, storedNonce);

  // active_image_extent/hash are exactly what the (hardware-independent)
  // test provider supplied -- proving the sink/writeNext() plumbing
  // faithfully persists whatever the provider returns, byte-for-byte.
  constexpr uint32_t kActiveImageExtentOffset = 143;
  constexpr uint32_t kActiveImageHashOffset = 147;
  uint32_t storedExtent = 0;
  for (int i = 0; i < 4; ++i) {
    storedExtent |= static_cast<uint32_t>(rawRecord[kActiveImageExtentOffset + i]) << (8 * i);  // little-endian
  }
  EXPECT_EQ(activeImageExtent, storedExtent);
  EXPECT_EQ(0, std::memcmp(rawRecord + kActiveImageHashOffset, activeImageHash, 32));

  std::vector<uint8_t> flashImage(imageSize_);
  ASSERT_TRUE(::ota::platform::isOk(region.read(0, flashImage.data(), static_cast<uint32_t>(imageSize_))));
  EXPECT_EQ(0, std::memcmp(flashImage.data(), hostImage_.data.data(), imageSize_));
}

// =======================================================================
// REQUIRED comprehensive encoded-frame E2E: two authenticated controllers
// interleaved through the REAL onFrame()/tick() wire path, a local-
// policy-denied admission attempt, a competing/changed-metadata attempt
// against an in-progress pending reassembly, a lost reply recovered by
// bounded retry, a cold target reboot mid-InstalledPending, and genuine
// real Ed25519+flash trust/staging throughout -- never a false Installed
// claim, and the durable authorized-controller/nonce binding stays the
// ORIGINAL admitted attempt's controller, never the descriptor's
// publisher identity.
// =======================================================================
TEST_F(DirectedRealTrustStagingRebootTest, TwoInterleavedControllersLocalPolicyDenialAndLostReplyStillReachHonestOutcome) {
  ota::test::FakeNorFlash flash(kFlashTotalBytes, kEraseUnitBytes, 1);
  ::ota::platform::FlashRegion region(flash, 0, kEraseUnitBytes);
  ASSERT_TRUE(region.isValid());

  FakeCacheSink cache;
  FakeTrust updaterTrust;
  FakeTransport updaterTransport;
  FakeTransport targetTransport;
  FakeClock clock;
  FakePersistence persistence;
  FakeBootEvidence boot;
  FakeConsentPolicy consent;
  FakeCommissioningProvenancePort commissioning;
  commissioning.initializeGenuineFactoryVirgin();

  ::ota::trust::DeviceTrustAnchor anchor;
  std::memcpy(anchor.trusted_signer_public_key_ed25519, publisherPublicKey_, 32);
  anchor.expected_target_id = (static_cast<uint32_t>(descriptor_.boardFamily) << 16) | descriptor_.boardVariant;
  anchor.expected_role_id = descriptor_.role;
  anchor.device_address = 0;
  anchor.supported_boot_capability_flags = 0;
  anchor.expected_format_id = descriptor_.formatId;
  anchor.expected_key_id = descriptor_.keyId;
  anchor.expected_algorithm_id = descriptor_.algorithmId;

  ::ota::trust::Sha256 hasher;
  ::ota::trust::Ed25519SignatureVerifier wireVerifier;
  SimpleMonotonicCounter counter;
  ::ota::trust::DescriptorVerifier targetVerifier(hasher, wireVerifier, counter, anchor);
  ::mesh::ota::OtaFirmwareTrustProvider targetTrust(targetVerifier, region, wireVerifier, publisherPublicKey_);
  CampaignFirmwareStagingSink staging(region);
  TargetReceiverEngine target(targetTrust, staging, persistence, boot, consent, commissioning);
  target.bindTransport(targetTransport);
  target.bindClock(clock);
  target.bindStagingResume(staging);

  const CampaignPeerId attacker = makePeerId(0x99);
  const runtime::OtaSessionId legitSession{777, 1, 1};
  std::vector<uint8_t> blob = makeDescriptorSignatureBlob(descriptor_, sig_);

  // --- Step 1: a DIFFERENT, otherwise-unauthorized identity submits the
  // SAME validly-signed descriptor (so trust/signature verification
  // passes) but local consent policy denies it -- proving denial is a
  // genuine local policy decision, independent of (and after) signature
  // verification, and that it replies to the actual requester.
  consent.approve = false;
  {
    const runtime::OtaSessionId attackerSession{778, 1, 1};
    CampaignConsentRequestPayload attackerPayload = makeConsentPayload(attacker);
    attackerPayload.descriptorTotalLength = static_cast<uint16_t>(blob.size());
    std::vector<uint8_t> consentBytes = encodeConsentRequestFrame(attackerSession, 1, attackerPayload);
    ASSERT_TRUE(target.onFrame(makeInboundFrame(consentBytes, attacker)));
    std::vector<uint8_t> fragBytes = encodeDescriptorFragmentFrame(
        attackerSession, 2, 0, 1, static_cast<uint16_t>(blob.size()), static_cast<uint16_t>(blob.size()), blob.data(),
        blob.size());
    EXPECT_FALSE(target.onFrame(makeInboundFrame(fragBytes, attacker)));
    EXPECT_EQ(CampaignRefusalReason::ConsentPolicyDenied, target.lastRefusal());
    ASSERT_FALSE(target.boundController() == attacker);
  }
  consent.approve = true;

  // --- Step 2: the legitimate controller begins its own admission via a
  // REAL UpdaterCampaignEngine (the SAME engine instance later drives the
  // full directed chunk transfer in Step 3, proving frameSeq/session
  // continuity end-to-end rather than splicing in hand-crafted frames
  // under a session the real engine will reuse). Between its
  // ConsentRequest and its single combined DescriptorFragment (descriptor
  // (59) + signature (64) = 123 bytes always fits one fragment, see
  // RfBudgetTest.DescriptorPlusSignatureFitsSingleFragment), the SAME
  // attacker tries to interleave a competing ConsentRequest with CHANGED
  // metadata (different session, different declared descriptor length)
  // for the single pending slot -- it must be refused without disturbing
  // the legitimate reassembly already opened by the real ConsentRequest.
  UpdaterCampaignEngine updater(updaterTrust, cache, updaterTransport, hostImage_, clock);
  CampaignDestination dest;
  dest.scope = CampaignAuthScope::Pairwise;
  dest.peerId = makePeerId(0x88); // target's id, from the updater's point of view
  ASSERT_TRUE(updater.begin(legitSession, descriptor_, sig_.data(), sig_.size(), dest, controller_));

  size_t updaterCursor = 0;
  ASSERT_TRUE(updater.tick()); // sends the real ConsentRequest
  ASSERT_EQ(1u, updaterTransport.sentLog.size() - updaterCursor);
  while (updaterCursor < updaterTransport.sentLog.size()) {
    const auto& sent = updaterTransport.sentLog[updaterCursor++];
    ASSERT_TRUE(target.onFrame(makeInboundFrame(sent.bytes, controller_)));
  }

  {
    // Changed metadata: different session, different controller AND a
    // different declared descriptor length -- genuinely competing, not a
    // retry of the real admission already opened above.
    const runtime::OtaSessionId competingSession{779, 1, 1};
    CampaignConsentRequestPayload competingPayload = makeConsentPayload(attacker);
    competingPayload.descriptorTotalLength = static_cast<uint16_t>(blob.size() + 5);
    std::vector<uint8_t> competingBytes = encodeConsentRequestFrame(competingSession, 3, competingPayload);
    EXPECT_FALSE(target.onFrame(makeInboundFrame(competingBytes, attacker)));
  }

  // Force the target's NEXT outbound reply attempt (the ConsentGrant the
  // completing DescriptorFragment triggers) to report a transient send
  // failure, modeling a genuinely lost reply -- the admission itself
  // must still succeed, and the reply must be recoverable via bounded
  // retry rather than silently dropped.
  targetTransport.forcedResults.push_back(CampaignSendResult::Backpressure);
  ASSERT_TRUE(updater.tick()); // sends the real (single) DescriptorFragment
  while (updaterCursor < updaterTransport.sentLog.size()) {
    const auto& sent = updaterTransport.sentLog[updaterCursor++];
    ASSERT_TRUE(target.onFrame(makeInboundFrame(sent.bytes, controller_)));
  }
  ASSERT_EQ(controller_, target.boundController());
  ASSERT_EQ(TargetStatus::Receiving, target.status());

  // The ConsentGrant reply attempt above failed transiently and must be
  // latched for retry, not dropped.
  bool sawConsentGrant = false;
  size_t legitGrantIndex = targetTransport.sentLog.size();
  for (int i = 0; i < 10 && !sawConsentGrant; ++i) {
    clock.advance(10000);
    target.tick();
    if (!targetTransport.sentLog.empty()) {
      CampaignEnvelopeHeader hdr;
      const uint8_t* payload = nullptr;
      size_t payloadLen = 0;
      const auto& sent = targetTransport.sentLog.back();
      if (decodeCampaignEnvelope(sent.bytes.data(), sent.bytes.size(), hdr, payload, payloadLen) ==
              CampaignCodecResult::Ok &&
          hdr.type == CampaignMessageType::ConsentGrant && runtime::otaSessionEquals(hdr.session, legitSession)) {
        sawConsentGrant = true;
        legitGrantIndex = targetTransport.sentLog.size() - 1;
      }
    }
  }
  EXPECT_TRUE(sawConsentGrant) << "lost ConsentGrant reply was never recovered via bounded retry";

  // --- Step 3: full directed chunk transfer via tick()/onFrame() between
  // the SAME real UpdaterCampaignEngine (same session/descriptor/
  // signature, already consented above) and the real-trust/flash-backed
  // target, dropping one Receipt once.
  // Earlier ConsentGrant(denied) replies were addressed to the attacker's
  // own session/identity (Steps 1 and 2's competing request), never to
  // this updater's legitimate session -- a real transport only delivers
  // each frame to its actual destination address, so the updater must
  // not observe those unrelated denial replies. Start exactly at the
  // already-sent legitimate grant (recovered via retry above) onward.
  size_t targetCursor = legitGrantIndex;
  bool droppedReceiptOnce = false;
  bool bootFired = false;
  int iterations = 0;
  const int kMaxIterations = 20000;
  while (updater.outcome() == UpdaterOutcome::InProgress && ++iterations < kMaxIterations) {
    updater.tick();
    target.tick();
    while (updaterCursor < updaterTransport.sentLog.size()) {
      const auto& sent = updaterTransport.sentLog[updaterCursor++];
      ASSERT_TRUE(target.onFrame(makeInboundFrame(sent.bytes, controller_)));
    }
    while (targetCursor < targetTransport.sentLog.size()) {
      const auto& sent = targetTransport.sentLog[targetCursor++];
      CampaignEnvelopeHeader hdr;
      const uint8_t* payload = nullptr;
      size_t payloadLen = 0;
      ASSERT_EQ(CampaignCodecResult::Ok,
                decodeCampaignEnvelope(sent.bytes.data(), sent.bytes.size(), hdr, payload, payloadLen));
      if (hdr.type == CampaignMessageType::Receipt && !droppedReceiptOnce) {
        droppedReceiptOnce = true;
        continue; // genuine one-time wire loss
      }
      updater.onFrame(makeInboundFrame(sent.bytes, makePeerId(0x88)));
    }
    if (target.status() == TargetStatus::InstalledPending && !bootFired) {
      // Boot evidence not yet supplied: must stay InstalledPending, NEVER
      // claim Installed, across further ticks until evidence arrives.
      target.tick();
      EXPECT_EQ(TargetStatus::InstalledPending, target.status());
      EXPECT_NE(TargetStatus::Installed, target.status());
      break;
    }
    clock.advance(20);
  }
  ASSERT_LT(iterations, kMaxIterations) << "transfer did not converge";
  ASSERT_EQ(TargetStatus::InstalledPending, target.status());
  EXPECT_TRUE(droppedReceiptOnce);
  // Sanity: the real sink already committed for real before the reboot
  // below destroys every RAM object; the physical flash bytes are
  // independent of any in-process object about to be discarded.
  EXPECT_TRUE(staging.isCommitted());

  // --- Step 4: cold target reboot WHILE still only InstalledPending (no
  // boot evidence yet) -- a brand-new engine/trust/staging reconstructed
  // purely from durable persistence+flash must likewise refuse to claim
  // Installed until real boot evidence is supplied.
  ::ota::trust::Sha256 hasher2;
  ::ota::trust::Ed25519SignatureVerifier wireVerifier2;
  SimpleMonotonicCounter counter2;
  ::ota::trust::DescriptorVerifier targetVerifier2(hasher2, wireVerifier2, counter2, anchor);
  ::mesh::ota::OtaFirmwareTrustProvider targetTrust2(targetVerifier2, region, wireVerifier2, publisherPublicKey_);
  CampaignFirmwareStagingSink staging2(region);
  TargetReceiverEngine target2(targetTrust2, staging2, persistence, boot, consent, commissioning);
  target2.bindTransport(targetTransport);
  target2.bindClock(clock);
  target2.bindStagingResume(staging2);
  ASSERT_TRUE(target2.reload());
  EXPECT_EQ(TargetStatus::InstalledPending, target2.status());
  EXPECT_NE(TargetStatus::Installed, target2.status());

  // The durable authorized-controller binding re-derived purely from the
  // persistence-port record is the ORIGINAL admitted attempt's controller
  // (controller_), never the descriptor's publisher key -- survives the
  // cold reconstruction unchanged. (A freshly-reconstructed sink's own
  // RAM-only authorizedController()/verifiedWireDescriptor() bookkeeping
  // is only re-delivered by reload() for a mid-transfer Receiving/
  // Verifying resume -- a committed InstalledPending record's durable
  // truth surface is target2.status()/boundController() plus the
  // physical flash bytes checked below, not that transient RAM cache.)
  EXPECT_EQ(0, std::memcmp(target2.boundController().bytes, controller_.bytes, 32));
  EXPECT_NE(0, std::memcmp(target2.boundController().bytes, publisherPublicKey_, 32));

  // Now supply REAL matching boot evidence: only then may Installed be
  // claimed.
  boot.evidence.healthyBootConfirmed = true;
  boot.evidence.bootedSession = legitSession;
  std::memcpy(boot.evidence.bootedImageHash, descriptor_.sha256, protocol::kOtaSha256Size);
  boot.evidence.bootedSecurityCounter = descriptor_.securityCounter;
  ASSERT_TRUE(target2.confirmHealthyBoot());
  EXPECT_EQ(TargetStatus::Installed, target2.status());

  // The physically-committed staged image bytes (written+durably
  // confirmed by the ORIGINAL staging sink before the reboot) are
  // readable directly off the real flash region, independent of any
  // RAM object -- this is the actual durable evidence a bootloader
  // handoff would rely on, never a native-test-only boolean sentinel.
  std::vector<uint8_t> flashImage(imageSize_);
  ASSERT_TRUE(::ota::platform::isOk(region.read(0, flashImage.data(), static_cast<uint32_t>(imageSize_))));
  EXPECT_EQ(0, std::memcmp(flashImage.data(), hostImage_.data.data(), imageSize_));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
