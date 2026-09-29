#include <gtest/gtest.h>

#include <cstring>

#include <Dispatcher.h>
#include <helpers/StaticPoolPacketManager.h>
#include <helpers/StaticPoolPacketManager.cpp>
#include <helpers/ota/OtaDirectLease.h>
#include <helpers/ota/OtaFirmwareBackend.h>
#include <helpers/ota/OtaFirmwareIntegration.h>
#include <helpers/ota/OtaMeshHooks.h>
#include <ota/protocol/OtaDescriptor.h>
#include <ota/protocol/OtaEnvelope.h>
#include <ota/protocol/OtaMessages.h>
#include <ota/boot/BootTransaction.h>
#include <ota/storage/Journal.h>
#include <ota/trust/CanonicalDescriptor.h>
#include <ota/trust/DescriptorVerifier.h>
#include <ota/trust/Ed25519SignatureVerifier.h>
#include <ota/trust/Sha256.h>

#include "../test_lora_ota_storage/FakeNorFlash.h"
#include "../test_lora_ota_trust/Ed25519TestSigner.h"
#include "../test_lora_ota_trust/FakeMonotonicCounter.h"

using namespace mesh;
using namespace meshcore::ota::protocol;
using namespace meshcore::ota::runtime;

class FakeClock : public MillisecondClock {
public:
  unsigned long now = 1;
  unsigned long getMillis() override { return now; }
  void advance(unsigned long delta) { now += delta; }
};

class FakeRadio : public Radio {
public:
  uint32_t airtime = 2000;
  int sends = 0;
  bool send_pending = false;

  int recvRaw(uint8_t*, int) override { return 0; }
  uint32_t getEstAirtimeFor(int) override { return airtime; }
  float packetScore(float, int) override { return 1.0f; }
  bool startSendRaw(const uint8_t*, int) override {
    ++sends;
    send_pending = true;
    return true;
  }
  bool isSendComplete() override { return send_pending; }
  void onSendFinished() override { send_pending = false; }
  bool isInRecvMode() const override { return true; }
};

class QueuePacketManager : public PacketManager {
public:
  struct Entry {
    Packet* packet;
    uint8_t priority;
    uint32_t scheduled_for;
  };

  Packet pool[8];
  bool used[8]{};
  Entry outbound[8]{};
  int outbound_count = 0;

  Packet* allocNew() override {
    for (int i = 0; i < 8; ++i) {
      if (!used[i]) {
        used[i] = true;
        return &pool[i];
      }
    }
    return nullptr;
  }

  void free(Packet* packet) override {
    for (int i = 0; i < 8; ++i) {
      if (&pool[i] == packet) {
        used[i] = false;
        return;
      }
    }
  }

  void queueOutbound(Packet* packet, uint8_t priority, uint32_t scheduled_for) override {
    outbound[outbound_count++] = Entry{packet, priority, scheduled_for};
  }

  Packet* getNextOutbound(uint32_t now) override {
    int best = -1;
    uint8_t best_pri = 0xFF;
    for (int i = 0; i < outbound_count; ++i) {
      if ((int32_t)(outbound[i].scheduled_for - now) > 0) continue;
      if (outbound[i].priority < best_pri) {
        best = i;
        best_pri = outbound[i].priority;
      }
    }
    if (best < 0) return nullptr;
    Packet* packet = outbound[best].packet;
    --outbound_count;
    for (int i = best; i < outbound_count; ++i) outbound[i] = outbound[i + 1];
    return packet;
  }

  int getOutboundCount(uint32_t now) const override {
    int count = 0;
    for (int i = 0; i < outbound_count; ++i) {
      if ((int32_t)(outbound[i].scheduled_for - now) <= 0) ++count;
    }
    return count;
  }

  int getOutboundTotal() const override { return outbound_count; }
  int getFreeCount() const override {
    int count = 0;
    for (int i = 0; i < 8; ++i) if (!used[i]) ++count;
    return count;
  }
  Packet* getOutboundByIdx(int i) override { return i >= 0 && i < outbound_count ? outbound[i].packet : nullptr; }
  Packet* removeOutboundByIdx(int i) override {
    if (i < 0 || i >= outbound_count) return nullptr;
    Packet* packet = outbound[i].packet;
    --outbound_count;
    for (; i < outbound_count; ++i) outbound[i] = outbound[i + 1];
    return packet;
  }
  void queueInbound(Packet*, uint32_t) override {}
  Packet* getNextInbound(uint32_t) override { return nullptr; }
};

class TestDispatcher : public Dispatcher {
public:
  TestDispatcher(Radio& radio, MillisecondClock& clock, PacketManager& manager)
      : Dispatcher(radio, clock, manager) {}

protected:
  DispatcherAction onRecvPacket(Packet*) override { return ACTION_RELEASE; }
};

static void fillOtaChunkPayload(Packet* packet) {
  uint8_t payload[32] = {0};
  meshcore::ota::protocol::OtaEnvelopeHeader hdr;
  hdr.type = meshcore::ota::protocol::OtaMessageType::Chunk;
  hdr.campaignId = 1;
  hdr.sessionId = 1;
  hdr.attemptId = 1;
  size_t out_len = 0;
  ASSERT_EQ(meshcore::ota::protocol::OtaCodecResult::Ok,
            meshcore::ota::protocol::encodeOtaEnvelope(hdr, nullptr, 0, payload, sizeof(payload), out_len));
  packet->header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_LORA_OTA << PH_TYPE_SHIFT);
  packet->path_len = 0;
  packet->payload_len = out_len;
  memcpy(packet->payload, payload, out_len);
}

static bool encodeFrame(OtaMessageType type, const uint8_t* payload, size_t payload_len,
                        uint8_t* frame, size_t frame_cap, size_t& frame_len) {
  OtaEnvelopeHeader hdr;
  hdr.type = type;
  hdr.campaignId = 42;
  hdr.sessionId = 7;
  hdr.attemptId = 1;
  return encodeOtaEnvelope(hdr, payload, payload_len, frame, frame_cap, frame_len) == OtaCodecResult::Ok;
}

static void putU16Le(uint8_t* dst, uint16_t value) {
  dst[0] = static_cast<uint8_t>(value & 0xFFu);
  dst[1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
}

static size_t buildDescriptorFragment(uint8_t* payload, size_t cap, const OtaDescriptor& descriptor,
                                      const uint8_t signature[64] = nullptr) {
  uint8_t blob[OtaDescriptorReassembler::kMaxBlobSize] = {};
  size_t canonical_len = 0;
  EXPECT_EQ(OtaDescriptorCodecResult::Ok,
            encodeOtaDescriptorCanonical(descriptor, blob, sizeof(blob), canonical_len));
  if (signature != nullptr) {
    std::memcpy(blob + canonical_len, signature, 64);
  } else {
    for (size_t i = 0; i < 64; ++i) blob[canonical_len + i] = static_cast<uint8_t>(0xA0u + i);
  }
  const size_t blob_len = canonical_len + 64;
  EXPECT_LE(blob_len + 6, cap);
  payload[0] = 0;  // fragment index
  payload[1] = 1;  // fragment count
  putU16Le(&payload[2], static_cast<uint16_t>(blob_len));
  putU16Le(&payload[4], static_cast<uint16_t>(blob_len));
  std::memcpy(&payload[6], blob, blob_len);
  return blob_len + 6;
}

static OtaDescriptor buildProtocolDescriptor(const uint8_t* image, size_t image_len, uint32_t security_counter) {
  OtaDescriptor descriptor;
  descriptor.boardFamily = 0x1001;
  descriptor.boardVariant = 0x0002;
  descriptor.role = 7;
  descriptor.appAddress = 0x27000;
  descriptor.exactSizeBytes = static_cast<uint32_t>(image_len);
  ::ota::trust::Sha256::hash(image, image_len, descriptor.sha256);
  descriptor.securityCounter = security_counter;
  descriptor.minBootloaderCapabilities = 0x00000003u;
  descriptor.formatId = 1;
  descriptor.keyId = 1;
  descriptor.algorithmId = 1;
  return descriptor;
}

static ::ota::trust::ImageDescriptor buildSignedTrustDescriptor(const OtaDescriptor& descriptor,
                                                              const ::ota::test::Ed25519TestSigner& signer) {
  ::ota::trust::ImageDescriptor trust_descriptor =
      mesh::ota::otaTrustImageDescriptorFromWire(descriptor, nullptr, 0);
  uint8_t message[::ota::trust::CanonicalDescriptor::kMessageBytes] = {};
  size_t written = ::ota::trust::CanonicalDescriptor::serialize(trust_descriptor, message, sizeof(message));
  EXPECT_EQ(::ota::trust::CanonicalDescriptor::kMessageBytes, written);
  signer.sign(message, written, trust_descriptor.signature_ed25519);
  return trust_descriptor;
}

static void sendValidDescriptorAndAuthorization(mesh::ota::OtaFirmwareIntegration& integration,
                                                const OtaDescriptor& descriptor,
                                                const uint8_t signature[64]) {
  uint8_t frame[192] = {};
  size_t frame_len = 0;
  uint8_t descriptor_payload[160] = {};
  size_t descriptor_len = buildDescriptorFragment(descriptor_payload, sizeof(descriptor_payload), descriptor, signature);
  ASSERT_TRUE(encodeFrame(OtaMessageType::DescriptorFragment, descriptor_payload, descriptor_len, frame, sizeof(frame), frame_len));
  ASSERT_TRUE(integration.handleReceivedFrame(frame, frame_len));

  OtaAuthorizationPayload authorization;
  authorization.granted = 1;
  authorization.leaseId = 1;
  authorization.expiresAtMs = 60000;
  authorization.maxInFlightChunks = 2;
  uint8_t authorization_payload[kOtaAuthorizationPayloadSize] = {};
  size_t authorization_len = 0;
  ASSERT_TRUE(encodeOtaAuthorization(authorization, authorization_payload, sizeof(authorization_payload), authorization_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Authorization, authorization_payload, authorization_len, frame, sizeof(frame), frame_len));
  ASSERT_TRUE(integration.handleReceivedFrame(frame, frame_len));
}

static void sendImageChunksAndCommit(mesh::ota::OtaFirmwareIntegration& integration,
                                     const uint8_t* image,
                                     const OtaDescriptor& descriptor) {
  uint8_t frame[192] = {};
  size_t frame_len = 0;
  uint8_t chunk_payload[kOtaChunkHeaderSize + kOtaDefaultChunkPayloadSize] = {};
  size_t chunk_len = 0;

  OtaChunkHeader chunk;
  chunk.dataLength = kOtaDefaultChunkPayloadSize;
  for (uint32_t i = 0; i < descriptor.exactSizeBytes / kOtaDefaultChunkPayloadSize; ++i) {
    chunk.chunkIndex = i;
    ASSERT_TRUE(encodeOtaChunk(chunk, image + (i * kOtaDefaultChunkPayloadSize), kOtaDefaultChunkPayloadSize,
                               chunk_payload, sizeof(chunk_payload), chunk_len));
    ASSERT_TRUE(encodeFrame(OtaMessageType::Chunk, chunk_payload, chunk_len, frame, sizeof(frame), frame_len));
    ASSERT_TRUE(integration.handleReceivedFrame(frame, frame_len));
  }

  OtaCommitPayload commit;
  commit.campaignId = 42;
  commit.verifiedOk = 1;
  commit.finalSecurityCounter = descriptor.securityCounter;
  uint8_t commit_payload[kOtaCommitPayloadSize] = {};
  size_t commit_len = 0;
  ASSERT_TRUE(encodeOtaCommit(commit, commit_payload, sizeof(commit_payload), commit_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Commit, commit_payload, commit_len, frame, sizeof(frame), frame_len));
  ASSERT_TRUE(integration.handleReceivedFrame(frame, frame_len));
}

TEST(LoraOtaIntegration, HostileThreeMessageSequenceCannotManufactureVerifiedCommit) {
  mesh::ota::OtaFirmwareIntegration integration;
  uint8_t frame[192] = {};
  size_t frame_len = 0;

  ASSERT_TRUE(encodeFrame(OtaMessageType::DescriptorFragment, nullptr, 0, frame, sizeof(frame), frame_len));
  EXPECT_FALSE(integration.handleReceivedFrame(frame, frame_len));

  OtaAuthorizationPayload authorization;
  authorization.granted = 1;
  authorization.leaseId = 1;
  authorization.expiresAtMs = 60000;
  authorization.maxInFlightChunks = 1;
  uint8_t authorization_payload[kOtaAuthorizationPayloadSize] = {};
  size_t authorization_len = 0;
  ASSERT_TRUE(encodeOtaAuthorization(authorization, authorization_payload, sizeof(authorization_payload), authorization_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Authorization, authorization_payload, authorization_len, frame, sizeof(frame), frame_len));
  EXPECT_FALSE(integration.handleReceivedFrame(frame, frame_len));

  OtaCommitPayload commit;
  commit.campaignId = 42;
  commit.verifiedOk = 1;
  commit.finalSecurityCounter = 1;
  uint8_t commit_payload[kOtaCommitPayloadSize] = {};
  size_t commit_len = 0;
  ASSERT_TRUE(encodeOtaCommit(commit, commit_payload, sizeof(commit_payload), commit_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Commit, commit_payload, commit_len, frame, sizeof(frame), frame_len));
  EXPECT_FALSE(integration.handleReceivedFrame(frame, frame_len));

  mesh::ota::FirmwareOtaStatus status = integration.status(0);
  EXPECT_NE(OtaReceiverState::Complete, status.receiverState);
  EXPECT_NE(OtaReceiverState::Committing, status.receiverState);
  EXPECT_EQ(3u, status.rxFrames);
}

TEST(LoraOtaIntegration, OtaStatusReportsBackendUnavailableUntilCompleteBackendAttached) {
  mesh::ota::OtaFirmwareIntegration integration;
  EXPECT_FALSE(integration.status(0).backendAvailable);

  uint8_t seed[32] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0x40u + i);
  ::ota::test::Ed25519TestSigner signer(seed);
  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  ::ota::test::FakeMonotonicCounter counter(0);
  ::ota::trust::Sha256 hasher;
  ::ota::trust::Ed25519SignatureVerifier sig_verifier;
  ::ota::trust::DeviceTrustAnchor anchor;
  std::memcpy(anchor.trusted_signer_public_key_ed25519, signer.publicKey(), 32);
  anchor.expected_target_id = (0x1001u << 16) | 0x0002u;
  anchor.expected_role_id = 7;
  anchor.supported_boot_capability_flags = 0x0000000Fu;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);
  mesh::ota::OtaFirmwareTrustProvider trust(verifier, candidate);
  mesh::ota::OtaFirmwareStorageSink staging(candidate);

  integration.attachTrustProvider(&trust);
  EXPECT_FALSE(integration.status(0).backendAvailable);
  integration.attachStagingSink(&staging);
  EXPECT_TRUE(integration.status(0).backendAvailable);
}

namespace {
class RecordingDirectLeaseHandler : public mesh::ota::OtaDirectLeaseHandler {
public:
  explicit RecordingDirectLeaseHandler(bool mode_result) : mode_result_(mode_result) {}
  bool setOtaDirectMode() override {
    ++mode_calls;
    return mode_result_;
  }
  void applyOtaDirectLease(const mesh::ota::OtaDirectLeaseParams& params) override {
    ++apply_calls;
    last_params = params;
  }

  int mode_calls = 0;
  int apply_calls = 0;
  mesh::ota::OtaDirectLeaseParams last_params;

private:
  bool mode_result_;
};
}  // namespace

TEST(LoraOtaIntegration, DirectLeaseCommandsRefuseWhenBackendUnavailableWithoutApplyingRadioParams) {
  mesh::ota::OtaDirectLeaseParams text_style{915.0f, 250.0f, 10, 5, 30};
  RecordingDirectLeaseHandler text_handler(false);
  EXPECT_FALSE(mesh::ota::requestOtaDirectLease(text_handler, text_style));
  EXPECT_EQ(1, text_handler.mode_calls);
  EXPECT_EQ(0, text_handler.apply_calls);

  mesh::ota::OtaDirectLeaseParams binary_style{915000.0f / 1000.0f, 250000.0f / 1000.0f, 10, 5, 30};
  RecordingDirectLeaseHandler binary_handler(false);
  EXPECT_FALSE(mesh::ota::requestOtaDirectLease(binary_handler, binary_style));
  EXPECT_EQ(1, binary_handler.mode_calls);
  EXPECT_EQ(0, binary_handler.apply_calls);

  RecordingDirectLeaseHandler allowed_handler(true);
  EXPECT_TRUE(mesh::ota::requestOtaDirectLease(allowed_handler, binary_style));
  EXPECT_EQ(1, allowed_handler.mode_calls);
  EXPECT_EQ(1, allowed_handler.apply_calls);
  EXPECT_FLOAT_EQ(915.0f, allowed_handler.last_params.freqMhz);
}

TEST(LoraOtaIntegration, SignedImageWritesToFlashAndCompletesThroughRealTrustPipeline) {
  mesh::ota::OtaFirmwareIntegration integration;
  uint8_t seed[32] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0x50u + i);
  ::ota::test::Ed25519TestSigner signer(seed);

  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::test::FakeNorFlash backup_flash(4096, 4096);
  ::ota::test::FakeNorFlash target_flash(4096, 4096);
  ::ota::test::FakeNorFlash journal_flash(::ota::storage::Journal::kSlotBytes * 2, ::ota::storage::Journal::kSlotBytes);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  ::ota::platform::FlashRegion backup(backup_flash, 0, 4096);
  ::ota::platform::FlashRegion target(target_flash, 0, 4096);
  ::ota::platform::FlashRegion journal_region(journal_flash, 0, ::ota::storage::Journal::kSlotBytes * 2);
  ::ota::storage::Journal journal(journal_region);
  ASSERT_TRUE(journal.isValid());
  ::ota::test::FakeMonotonicCounter counter(8);
  ::ota::trust::Sha256 hasher;
  ::ota::trust::Ed25519SignatureVerifier sig_verifier;
  ::ota::trust::DeviceTrustAnchor anchor;
  std::memcpy(anchor.trusted_signer_public_key_ed25519, signer.publicKey(), 32);
  anchor.expected_target_id = (0x1001u << 16) | 0x0002u;
  anchor.expected_role_id = 7;
  anchor.supported_boot_capability_flags = 0x0000000Fu;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);

  mesh::ota::OtaFirmwareTrustProvider trust(verifier, candidate);
  mesh::ota::OtaFirmwareStorageSink staging(candidate);
  integration.attachTrustProvider(&trust);
  integration.attachStagingSink(&staging);

  uint8_t image[2 * kOtaDefaultChunkPayloadSize] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(0xC0u + i);
  uint8_t running_image[4096] = {};
  for (size_t i = 0; i < sizeof(running_image); ++i) running_image[i] = static_cast<uint8_t>(0x33u + i);
  ASSERT_TRUE(::ota::platform::isOk(target.program(0, running_image, sizeof(running_image))));

  OtaDescriptor descriptor = buildProtocolDescriptor(image, sizeof(image), 9);
  ::ota::trust::ImageDescriptor trust_descriptor = buildSignedTrustDescriptor(descriptor, signer);

  sendValidDescriptorAndAuthorization(integration, descriptor, trust_descriptor.signature_ed25519);
  EXPECT_EQ(OtaReceiverState::Receiving, integration.status(0).receiverState);

  sendImageChunksAndCommit(integration, image, descriptor);
  EXPECT_EQ(OtaReceiverState::Complete, integration.status(0).receiverState);
  EXPECT_EQ(0, std::memcmp(flash.rawBuffer(), image, sizeof(image)));
  uint32_t committed_counter = 0;
  ASSERT_TRUE(counter.currentValue(committed_counter));
  EXPECT_EQ(8u, committed_counter) << "receive-side commit only completes staging; it must not advance anti-rollback";

  ::ota::boot::BootTransaction boot(journal, 42, candidate, backup, target);
  ASSERT_TRUE(boot.authenticateCandidate(verifier, trust_descriptor));
  ASSERT_TRUE(counter.currentValue(committed_counter));
  EXPECT_EQ(8u, committed_counter);
  ASSERT_TRUE(boot.backupTarget());
  ASSERT_TRUE(boot.installCandidateToTarget(verifier));
  ASSERT_TRUE(counter.currentValue(committed_counter));
  EXPECT_EQ(8u, committed_counter);
  ASSERT_TRUE(boot.enterTrial());
  ASSERT_TRUE(counter.currentValue(committed_counter));
  EXPECT_EQ(8u, committed_counter);
  ASSERT_TRUE(boot.confirmTrial(verifier));
  ASSERT_TRUE(counter.currentValue(committed_counter));
  EXPECT_EQ(9u, committed_counter);
}

TEST(LoraOtaIntegration, FailedInstallLeavesSecurityCounterUnadvanced) {
  uint8_t seed[32] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0x90u + i);
  ::ota::test::Ed25519TestSigner signer(seed);

  ::ota::test::FakeNorFlash candidate_flash(4096, 4096);
  ::ota::test::FakeNorFlash backup_flash(4096, 4096);
  ::ota::test::FakeNorFlash target_flash(4096, 4096);
  ::ota::test::FakeNorFlash journal_flash(::ota::storage::Journal::kSlotBytes * 2, ::ota::storage::Journal::kSlotBytes);
  ::ota::platform::FlashRegion candidate(candidate_flash, 0, 4096);
  ::ota::platform::FlashRegion backup(backup_flash, 0, 4096);
  ::ota::platform::FlashRegion target(target_flash, 0, 4096);
  ::ota::platform::FlashRegion journal_region(journal_flash, 0, ::ota::storage::Journal::kSlotBytes * 2);
  ::ota::storage::Journal journal(journal_region);
  ASSERT_TRUE(journal.isValid());
  ::ota::test::FakeMonotonicCounter counter(8);
  ::ota::trust::Sha256 hasher;
  ::ota::trust::Ed25519SignatureVerifier sig_verifier;
  ::ota::trust::DeviceTrustAnchor anchor;
  std::memcpy(anchor.trusted_signer_public_key_ed25519, signer.publicKey(), 32);
  anchor.expected_target_id = (0x1001u << 16) | 0x0002u;
  anchor.expected_role_id = 7;
  anchor.supported_boot_capability_flags = 0x0000000Fu;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);

  uint8_t image[2 * kOtaDefaultChunkPayloadSize] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(0x44u + i);
  ASSERT_TRUE(::ota::storage::StorageManager::erasePartition(candidate));
  ASSERT_TRUE(::ota::platform::isOk(candidate.program(0, image, sizeof(image))));
  uint8_t running_image[4096] = {};
  for (size_t i = 0; i < sizeof(running_image); ++i) running_image[i] = static_cast<uint8_t>(0x11u + i);
  ASSERT_TRUE(::ota::platform::isOk(target.program(0, running_image, sizeof(running_image))));

  OtaDescriptor descriptor = buildProtocolDescriptor(image, sizeof(image), 9);
  ::ota::trust::ImageDescriptor trust_descriptor = buildSignedTrustDescriptor(descriptor, signer);
  ::ota::boot::BootTransaction boot(journal, 43, candidate, backup, target);
  ASSERT_TRUE(boot.authenticateCandidate(verifier, trust_descriptor));
  ASSERT_TRUE(boot.backupTarget());

  ::ota::test::FakeNorFlash::FaultSpec fault;
  fault.kind = ::ota::test::FakeNorFlash::OpKind::Program;
  fault.timing = ::ota::test::FakeNorFlash::InjectionTiming::Before;
  fault.trigger_op_count = target_flash.programOpCount() + 1;
  target_flash.armFault(fault);

  EXPECT_FALSE(boot.installCandidateToTarget(verifier));
  uint32_t committed_counter = 0;
  ASSERT_TRUE(counter.currentValue(committed_counter));
  EXPECT_EQ(8u, committed_counter);
  target_flash.clearFault();
  EXPECT_TRUE(boot.rollbackToBackup(&verifier));
  ASSERT_TRUE(counter.currentValue(committed_counter));
  EXPECT_EQ(8u, committed_counter);
}

TEST(LoraOtaIntegration, DescriptorSignatureBindsEveryInstallRelevantWireField) {
  uint8_t seed[32] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0xA0u + i);
  ::ota::test::Ed25519TestSigner signer(seed);
  uint8_t image[2 * kOtaDefaultChunkPayloadSize] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(0x22u + i);

  OtaDescriptor signed_descriptor = buildProtocolDescriptor(image, sizeof(image), 9);
  ::ota::trust::ImageDescriptor trust_descriptor = buildSignedTrustDescriptor(signed_descriptor, signer);

  enum class Mutation : uint8_t {
    AppAddress,
    FormatId,
    KeyId,
    AlgorithmId,
    ImageSize,
    ImageHash,
    BoardFamily,
    BoardVariant,
    Role,
    SecurityCounter,
    MinBootloaderCapabilities,
  };
  const Mutation mutations[] = {
      Mutation::AppAddress,
      Mutation::FormatId,
      Mutation::KeyId,
      Mutation::AlgorithmId,
      Mutation::ImageSize,
      Mutation::ImageHash,
      Mutation::BoardFamily,
      Mutation::BoardVariant,
      Mutation::Role,
      Mutation::SecurityCounter,
      Mutation::MinBootloaderCapabilities,
  };

  for (Mutation mutation : mutations) {
    OtaDescriptor mutated = signed_descriptor;
    switch (mutation) {
      case Mutation::AppAddress: mutated.appAddress ^= 0x1000u; break;
      case Mutation::FormatId: mutated.formatId ^= 0x0001u; break;
      case Mutation::KeyId: mutated.keyId ^= 0x0001u; break;
      case Mutation::AlgorithmId: mutated.algorithmId ^= 0x0001u; break;
      case Mutation::ImageSize: mutated.exactSizeBytes += 1; break;
      case Mutation::ImageHash: mutated.sha256[0] ^= 0x01u; break;
      case Mutation::BoardFamily: mutated.boardFamily ^= 0x0001u; break;
      case Mutation::BoardVariant: mutated.boardVariant ^= 0x0001u; break;
      case Mutation::Role: mutated.role ^= 0x01u; break;
      case Mutation::SecurityCounter: mutated.securityCounter += 1; break;
      case Mutation::MinBootloaderCapabilities: mutated.minBootloaderCapabilities ^= 0x00000004u; break;
    }

    mesh::ota::OtaFirmwareIntegration integration;
    ::ota::test::FakeNorFlash flash(4096, 4096);
    ::ota::platform::FlashRegion candidate(flash, 0, 4096);
    ::ota::test::FakeMonotonicCounter counter(8);
    ::ota::trust::Sha256 hasher;
    ::ota::trust::Ed25519SignatureVerifier sig_verifier;
    ::ota::trust::DeviceTrustAnchor anchor;
    std::memcpy(anchor.trusted_signer_public_key_ed25519, signer.publicKey(), 32);
    anchor.expected_target_id = (0x1001u << 16) | 0x0002u;
    anchor.expected_role_id = 7;
    anchor.supported_boot_capability_flags = 0x0000000Fu;
    ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);
    mesh::ota::OtaFirmwareTrustProvider trust(verifier, candidate);
    mesh::ota::OtaFirmwareStorageSink staging(candidate);
    integration.attachTrustProvider(&trust);
    integration.attachStagingSink(&staging);

    uint8_t frame[192] = {};
    size_t frame_len = 0;
    uint8_t descriptor_payload[160] = {};
    size_t descriptor_len = buildDescriptorFragment(descriptor_payload, sizeof(descriptor_payload), mutated,
                                                    trust_descriptor.signature_ed25519);
    ASSERT_TRUE(encodeFrame(OtaMessageType::DescriptorFragment, descriptor_payload, descriptor_len,
                            frame, sizeof(frame), frame_len));
    EXPECT_FALSE(integration.handleReceivedFrame(frame, frame_len));
    EXPECT_EQ(OtaReceiverState::Failed, integration.status(0).receiverState);
  }
}

TEST(LoraOtaIntegration, ForeignAbortDoesNotClearActiveTransferState) {
  mesh::ota::OtaFirmwareIntegration integration;
  uint8_t seed[32] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0x70u + i);
  ::ota::test::Ed25519TestSigner signer(seed);
  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  ::ota::test::FakeMonotonicCounter counter(0);
  ::ota::trust::Sha256 hasher;
  ::ota::trust::Ed25519SignatureVerifier sig_verifier;
  ::ota::trust::DeviceTrustAnchor anchor;
  std::memcpy(anchor.trusted_signer_public_key_ed25519, signer.publicKey(), 32);
  anchor.expected_target_id = (0x1001u << 16) | 0x0002u;
  anchor.expected_role_id = 7;
  anchor.supported_boot_capability_flags = 0x0000000Fu;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);
  mesh::ota::OtaFirmwareTrustProvider trust(verifier, candidate);
  mesh::ota::OtaFirmwareStorageSink staging(candidate);
  integration.attachTrustProvider(&trust);
  integration.attachStagingSink(&staging);

  uint8_t image[2 * kOtaDefaultChunkPayloadSize] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(i);
  OtaDescriptor descriptor = buildProtocolDescriptor(image, sizeof(image), 1);
  ::ota::trust::ImageDescriptor trust_descriptor = buildSignedTrustDescriptor(descriptor, signer);

  uint8_t frame[192] = {};
  size_t frame_len = 0;
  uint8_t descriptor_payload[160] = {};
  size_t descriptor_len = buildDescriptorFragment(descriptor_payload, sizeof(descriptor_payload), descriptor,
                                                  trust_descriptor.signature_ed25519);
  ASSERT_TRUE(encodeFrame(OtaMessageType::DescriptorFragment, descriptor_payload, descriptor_len, frame, sizeof(frame), frame_len));
  ASSERT_TRUE(integration.handleReceivedFrame(frame, frame_len));

  OtaAuthorizationPayload authorization;
  authorization.granted = 1;
  authorization.leaseId = 1;
  authorization.expiresAtMs = 60000;
  authorization.maxInFlightChunks = 2;
  uint8_t authorization_payload[kOtaAuthorizationPayloadSize] = {};
  size_t authorization_len = 0;
  ASSERT_TRUE(encodeOtaAuthorization(authorization, authorization_payload, sizeof(authorization_payload), authorization_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Authorization, authorization_payload, authorization_len, frame, sizeof(frame), frame_len));
  ASSERT_TRUE(integration.handleReceivedFrame(frame, frame_len));

  OtaChunkHeader chunk;
  chunk.chunkIndex = 0;
  chunk.dataLength = kOtaDefaultChunkPayloadSize;
  uint8_t chunk_payload[kOtaChunkHeaderSize + kOtaDefaultChunkPayloadSize] = {};
  size_t chunk_len = 0;
  ASSERT_TRUE(encodeOtaChunk(chunk, image, kOtaDefaultChunkPayloadSize, chunk_payload, sizeof(chunk_payload), chunk_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Chunk, chunk_payload, chunk_len, frame, sizeof(frame), frame_len));
  ASSERT_TRUE(integration.handleReceivedFrame(frame, frame_len));

  OtaEnvelopeHeader foreign_abort;
  foreign_abort.type = OtaMessageType::Abort;
  foreign_abort.campaignId = 42;
  foreign_abort.sessionId = 999;
  foreign_abort.attemptId = 1;
  ASSERT_EQ(OtaCodecResult::Ok, encodeOtaEnvelope(foreign_abort, nullptr, 0, frame, sizeof(frame), frame_len));
  EXPECT_FALSE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_EQ(OtaReceiverState::Receiving, integration.status(0).receiverState);

  chunk.chunkIndex = 1;
  ASSERT_TRUE(encodeOtaChunk(chunk, image + kOtaDefaultChunkPayloadSize, kOtaDefaultChunkPayloadSize,
                             chunk_payload, sizeof(chunk_payload), chunk_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Chunk, chunk_payload, chunk_len, frame, sizeof(frame), frame_len));
  ASSERT_TRUE(integration.handleReceivedFrame(frame, frame_len));

  OtaCommitPayload commit;
  commit.campaignId = 42;
  commit.verifiedOk = 1;
  commit.finalSecurityCounter = descriptor.securityCounter;
  uint8_t commit_payload[kOtaCommitPayloadSize] = {};
  size_t commit_len = 0;
  ASSERT_TRUE(encodeOtaCommit(commit, commit_payload, sizeof(commit_payload), commit_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Commit, commit_payload, commit_len, frame, sizeof(frame), frame_len));
  EXPECT_TRUE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_EQ(OtaReceiverState::Complete, integration.status(0).receiverState);
}

TEST(LoraOtaIntegration, DutyCycleSettingChangePreservesSpentWindow) {
  mesh::ota::OtaFirmwareIntegration integration;
  ASSERT_TRUE(integration.recordTransmit(0, OtaAirtimeCategory::Relay, 72000));
  ASSERT_TRUE(integration.setDutyCyclePercent(2.0f));
  EXPECT_EQ(72000u, integration.status(0).dutyUsedMs);
  EXPECT_FALSE(integration.canTransmit(0, OtaAirtimeCategory::Relay, 1, true, false));

  ASSERT_TRUE(integration.setDutyCyclePercent(4.0f));
  EXPECT_TRUE(integration.canTransmit(0, OtaAirtimeCategory::Relay, 72000, true, false));
  EXPECT_FALSE(integration.canTransmit(0, OtaAirtimeCategory::Relay, 72001, true, false));
}

TEST(LoraOtaIntegration, ForwardingPriorityIsBelowOrdinaryUserTraffic) {
  for (uint8_t ordinary_pri = 0; ordinary_pri <= MAX_PATH_SIZE; ++ordinary_pri) {
    EXPECT_GT(mesh::ota::floodPriorityForPayload(PAYLOAD_TYPE_LORA_OTA, ordinary_pri),
              ordinary_pri);
  }
  EXPECT_GT(mesh::ota::directPriorityForPayload(PAYLOAD_TYPE_LORA_OTA),
            mesh::ota::directPriorityForPayload(PAYLOAD_TYPE_TXT_MSG));
  EXPECT_NE(PAYLOAD_TYPE_LORA_OTA, PAYLOAD_TYPE_RAW_CUSTOM);
  EXPECT_NE(PAYLOAD_TYPE_LORA_OTA, PAYLOAD_TYPE_MULTIPART);
  EXPECT_NE(PAYLOAD_TYPE_LORA_OTA, PAYLOAD_TYPE_CONTROL);
}

TEST(LoraOtaIntegration, PacketQueueGetSendsOrdinaryTrafficBeforeOtaTraffic) {
  for (uint8_t ordinary_pri = 0; ordinary_pri <= MAX_PATH_SIZE; ++ordinary_pri) {
    PacketQueue queue(2);
    Packet normal;
    Packet ota;
    normal.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
    ota.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_LORA_OTA << PH_TYPE_SHIFT);
    ASSERT_TRUE(queue.add(&ota, mesh::ota::floodPriorityForPayload(PAYLOAD_TYPE_LORA_OTA, ordinary_pri), 0));
    ASSERT_TRUE(queue.add(&normal, ordinary_pri, 0));
    EXPECT_EQ(&normal, queue.get(0));
    EXPECT_EQ(&ota, queue.get(0));
  }
}

TEST(LoraOtaIntegration, DispatcherCheckSendEnforcesSeparateOtaRollingBudget) {
  FakeClock clock;
  FakeRadio radio;
  QueuePacketManager manager;
  TestDispatcher dispatcher(radio, clock, manager);
  dispatcher.begin();
  ASSERT_TRUE(dispatcher.setOtaAirtimeDutyCyclePercent(0.1f)); // 3,600 ms per rolling hour

  Packet* first = manager.allocNew();
  ASSERT_NE(nullptr, first);
  fillOtaChunkPayload(first);
  dispatcher.sendPacket(first, mesh::ota::kOtaForwardPriority);

  clock.advance(1);
  dispatcher.loop();
  EXPECT_EQ(1, radio.sends);
  clock.advance(2000);
  dispatcher.loop();
  EXPECT_EQ(1600u, dispatcher.getRemainingOtaAirtimeBudget(clock.getMillis()));

  Packet* second = manager.allocNew();
  ASSERT_NE(nullptr, second);
  fillOtaChunkPayload(second);
  dispatcher.sendPacket(second, mesh::ota::kOtaForwardPriority);

  dispatcher.loop();
  EXPECT_EQ(1, radio.sends) << "second OTA frame must wait because 2000+2000 exceeds the 3600 ms OTA window";
  EXPECT_EQ(1, manager.getOutboundTotal());
}

TEST(LoraOtaIntegration, FutureNormalTrafficDoesNotStarveReadyOtaFrame) {
  FakeClock clock;
  FakeRadio radio;
  QueuePacketManager manager;
  TestDispatcher dispatcher(radio, clock, manager);
  dispatcher.begin();

  Packet* ota = manager.allocNew();
  ASSERT_NE(nullptr, ota);
  fillOtaChunkPayload(ota);
  dispatcher.sendPacket(ota, mesh::ota::kOtaForwardPriority);

  Packet* normal = manager.allocNew();
  ASSERT_NE(nullptr, normal);
  normal->header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
  normal->path_len = 0;
  normal->payload_len = 1;
  normal->payload[0] = 0x42;
  dispatcher.sendPacket(normal, 1, 3600000);

  clock.advance(1);
  dispatcher.loop();
  EXPECT_EQ(1, radio.sends) << "future normal traffic is not active normal traffic for OTA fairness";
}

TEST(LoraOtaIntegration, ReadyNormalTrafficBlocksOtaRelayEvenIfOtaWasSelectedFirst) {
  FakeClock clock;
  FakeRadio radio;
  QueuePacketManager manager;
  TestDispatcher dispatcher(radio, clock, manager);
  dispatcher.begin();

  Packet* ota = manager.allocNew();
  ASSERT_NE(nullptr, ota);
  fillOtaChunkPayload(ota);
  dispatcher.sendPacket(ota, 0);

  Packet* normal = manager.allocNew();
  ASSERT_NE(nullptr, normal);
  normal->header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
  normal->path_len = 0;
  normal->payload_len = 1;
  normal->payload[0] = 0x42;
  dispatcher.sendPacket(normal, 1);

  clock.advance(1);
  dispatcher.loop();
  EXPECT_EQ(0, radio.sends);
  EXPECT_EQ(2, manager.getOutboundTotal());
  EXPECT_EQ(normal, manager.getNextOutbound(clock.getMillis()));
}

TEST(LoraOtaIntegration, OtaStatusReportsDispatcherAirtimeAccounting) {
  FakeClock clock;
  FakeRadio radio;
  QueuePacketManager manager;
  TestDispatcher dispatcher(radio, clock, manager);
  dispatcher.begin();
  ASSERT_TRUE(dispatcher.setOtaAirtimeDutyCyclePercent(0.1f));

  Packet* first = manager.allocNew();
  ASSERT_NE(nullptr, first);
  fillOtaChunkPayload(first);
  dispatcher.sendPacket(first, mesh::ota::kOtaForwardPriority);

  clock.advance(1);
  dispatcher.loop();
  ASSERT_EQ(1, radio.sends);
  clock.advance(2000);
  dispatcher.loop();

  auto status = dispatcher.getOtaStatus(clock.getMillis());
  EXPECT_EQ(2000u, status.dutyUsedMs);
  EXPECT_EQ(3600u, status.dutyBudgetMs);
  EXPECT_EQ(1600u, dispatcher.getRemainingOtaAirtimeBudget(clock.getMillis()));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
