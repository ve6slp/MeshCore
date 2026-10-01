#include <gtest/gtest.h>

#include <cstring>
#include <memory>
#include <vector>

#include <Dispatcher.h>
#include <helpers/StaticPoolPacketManager.h>
#include <helpers/StaticPoolPacketManager.cpp>
#include <helpers/ota/OtaDirectLease.h>
#include <helpers/ota/OtaFirmwareBackend.h>
#include <helpers/ota/OtaBoardBackendCommon.h>
#include <helpers/ota/OtaFirmwareIntegration.h>
#include <helpers/ota/OtaMeshHooks.h>
#include <helpers/ota/OtaRfUploader.h>
#include <ota/protocol/OtaDescriptor.h>
#include <ota/protocol/OtaEnvelope.h>
#include <ota/protocol/OtaMessages.h>
#include <ota/boot/BootTransaction.h>
#include <ota/storage/Journal.h>
#include <ota/storage/XiaoOtaCommandRecord.h>
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

// Returns a single scripted raw frame from recvRaw() (one-shot, then 0
// forever after), so tests can drive Dispatcher::checkRecv()'s real
// ingress/parse/classify path instead of only exercising allocNew() or
// processRecvPacket() directly.
class ScriptedRawRadio : public Radio {
public:
  const uint8_t* next_raw = nullptr;
  int next_len = 0;

  int recvRaw(uint8_t* dest, int max_len) override {
    if (next_raw == nullptr) return 0;
    int len = next_len < max_len ? next_len : max_len;
    memcpy(dest, next_raw, len);
    next_raw = nullptr;
    return len;
  }
  uint32_t getEstAirtimeFor(int) override { return 100; }
  float packetScore(float, int) override { return 1.0f; }
  bool startSendRaw(const uint8_t*, int) override { return false; }
  bool isSendComplete() override { return false; }
  void onSendFinished() override { }
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

  Packet* allocNew(bool is_ota_bulk = false) override {
    (void)is_ota_bulk;
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

  bool queueOutbound(Packet* packet, uint8_t priority, uint32_t scheduled_for) override {
    if (outbound_count >= 8) {
      free(packet);
      return false;
    }
    outbound[outbound_count++] = Entry{packet, priority, scheduled_for};
    return true;
  }

  Packet* getNextOutbound(uint32_t now, uint8_t* out_priority = nullptr) override {
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
    if (out_priority != nullptr) *out_priority = outbound[best].priority;
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
  uint32_t getOutboundScheduledForByIdx(int i) const override {
    return i >= 0 && i < outbound_count ? outbound[i].scheduled_for : 0;
  }
  Packet* removeOutboundByIdx(int i) override {
    if (i < 0 || i >= outbound_count) return nullptr;
    Packet* packet = outbound[i].packet;
    --outbound_count;
    for (; i < outbound_count; ++i) outbound[i] = outbound[i + 1];
    return packet;
  }
  void queueInbound(Packet* packet, uint32_t scheduled_for) override {
    inbound[inbound_count++] = Entry{packet, 0, scheduled_for};
  }
  Packet* getNextInbound(uint32_t now) override {
    for (int i = 0; i < inbound_count; ++i) {
      if ((int32_t)(inbound[i].scheduled_for - now) <= 0) {
        Packet* packet = inbound[i].packet;
        --inbound_count;
        for (; i < inbound_count; ++i) inbound[i] = inbound[i + 1];
        return packet;
      }
    }
    return nullptr;
  }

  Entry inbound[8]{};
  int inbound_count = 0;
};

class TestDispatcher : public Dispatcher {
public:
  TestDispatcher(Radio& radio, MillisecondClock& clock, PacketManager& manager)
      : Dispatcher(radio, clock, manager) {}

protected:
  DispatcherAction onRecvPacket(Packet*) override { return ACTION_RELEASE; }
};

// Counts onRecvPacket() calls, so tests can prove a packet was (or wasn't)
// handed to Mesh-level processing at all -- e.g. dropped earlier for pool
// pressure vs. actually reaching the receive handler.
class CountingRecvDispatcher : public Dispatcher {
public:
  int recv_calls = 0;

  CountingRecvDispatcher(Radio& radio, MillisecondClock& clock, PacketManager& manager)
      : Dispatcher(radio, clock, manager) {}

protected:
  DispatcherAction onRecvPacket(Packet*) override { ++recv_calls; return ACTION_RELEASE; }
};

// Always wants to relay/forward (ACTION_RETRANSMIT), regardless of payload
// type -- used to isolate the pool-pressure relay-drop check in
// Dispatcher::processRecvPacket() from the classification check in
// checkRecv(), and to prove ordinary (non-OTA) relays are never dropped.
class AlwaysRetransmitDispatcher : public Dispatcher {
public:
  AlwaysRetransmitDispatcher(Radio& radio, MillisecondClock& clock, PacketManager& manager)
      : Dispatcher(radio, clock, manager) {}

protected:
  DispatcherAction onRecvPacket(Packet*) override { return ACTION_RETRANSMIT(5); }
};

// A tiny general (non-OTA) duty-cycle window so a single normal packet
// exhausts the budget immediately after begin(), forcing the budget-gated
// requeue branch in Dispatcher::checkSend() on the very first send attempt.
class TinyGeneralBudgetTestDispatcher : public Dispatcher {
public:
  TinyGeneralBudgetTestDispatcher(Radio& radio, MillisecondClock& clock, PacketManager& manager)
      : Dispatcher(radio, clock, manager) {}

protected:
  DispatcherAction onRecvPacket(Packet*) override { return ACTION_RELEASE; }
  // 3000 * 0.5 duty_cycle = 1500 ms starting budget: enough to clear
  // checkSend()'s coarse MAX_TRANS_UNIT-based pre-check (which only
  // requires half of a full-size-packet's estimated airtime), but still
  // short of a real packet's prospective airtime below, so the
  // budget-gated requeue branch itself is what's exercised (not the
  // earlier, priority-blind global backoff).
  unsigned long getDutyCycleWindowMs() const override { return 3000; }
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

static void putU16Be(uint8_t* dst, uint16_t value) {
  dst[0] = static_cast<uint8_t>((value >> 8) & 0xFFu);
  dst[1] = static_cast<uint8_t>(value & 0xFFu);
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
  // Big-endian, matching every other OTA wire codec (OtaWireTypes.h's
  // getOtaBE16/putOtaBE16) and the RF lab reference sender
  // (scripts/ota_rf_lab.py uses struct.pack(">HH", ...) for this header).
  putU16Be(&payload[2], static_cast<uint16_t>(blob_len));
  putU16Be(&payload[4], static_cast<uint16_t>(blob_len));
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
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
  anchor.supported_boot_capability_flags = 0x0000000Fu;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);
  mesh::ota::OtaFirmwareTrustProvider trust(verifier, candidate);
  mesh::ota::OtaFirmwareStorageSink staging(candidate);

  integration.attachTrustProvider(&trust);
  EXPECT_FALSE(integration.status(0).backendAvailable);
  integration.attachStagingSink(&staging);
  EXPECT_TRUE(integration.status(0).backendAvailable);
}

TEST(LoraOtaIntegration, ProductionProviderVerifiesCanonicalWireDescriptorSignature) {
  uint8_t seed[32] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0x30u + i);
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
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
  anchor.supported_boot_capability_flags = 0x0000000Fu;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);
  mesh::ota::OtaFirmwareTrustProvider trust(
      verifier, candidate, sig_verifier, signer.publicKey());

  uint8_t image[kOtaDefaultChunkPayloadSize] = {};
  OtaDescriptor descriptor = buildProtocolDescriptor(image, sizeof(image), 1);
  uint8_t canonical[kOtaDescriptorCanonicalSize] = {};
  size_t canonical_len = 0;
  ASSERT_EQ(OtaDescriptorCodecResult::Ok,
            encodeOtaDescriptorCanonical(
                descriptor, canonical, sizeof(canonical), canonical_len));
  uint8_t signature[64] = {};
  signer.sign(canonical, canonical_len, signature);

  EXPECT_TRUE(trust.verifyDescriptor(descriptor, signature, sizeof(signature)));
  signature[0] ^= 0x80u;
  EXPECT_FALSE(trust.verifyDescriptor(descriptor, signature, sizeof(signature)));
}

// The 6-arg constructor binds a trusted (keyId, algorithmId) so
// `verifyDescriptorSignature()` itself -- not merely the downstream
// DescriptorVerifier::verifyPolicy() check -- refuses a descriptor tagged
// with the wrong key/algorithm identity, even though the Ed25519
// signature bytes are genuinely valid for the (tampered) message that was
// actually signed.
TEST(LoraOtaIntegration, TrustProviderDirectlyRejectsMismatchedKeyOrAlgorithmIdBeforeSignatureCheck) {
  uint8_t seed[32] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0x31u + i);
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
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
  anchor.supported_boot_capability_flags = 0x0000000Fu;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);
  mesh::ota::OtaFirmwareTrustProvider trust(
      verifier, candidate, sig_verifier, signer.publicKey(), /*trusted_key_id=*/1, /*trusted_algorithm_id=*/1);

  uint8_t canonical[16] = {0xAB};
  uint8_t signature[64] = {};
  signer.sign(canonical, sizeof(canonical), signature);

  // Correct key/algorithm ids: signature check runs and passes.
  EXPECT_TRUE(trust.verifyDescriptorSignature(canonical, sizeof(canonical), signature, sizeof(signature),
                                              /*key_id=*/1, /*algorithm_id=*/1));
  // Wrong key id: rejected even though the signature itself is genuinely valid.
  EXPECT_FALSE(trust.verifyDescriptorSignature(canonical, sizeof(canonical), signature, sizeof(signature),
                                               /*key_id=*/2, /*algorithm_id=*/1));
  // Wrong algorithm id: rejected the same way.
  EXPECT_FALSE(trust.verifyDescriptorSignature(canonical, sizeof(canonical), signature, sizeof(signature),
                                               /*key_id=*/1, /*algorithm_id=*/2));
}


// every other OTA wire codec (OtaWireTypes.h) and the RF lab reference
// sender (scripts/ota_rf_lab.py: struct.pack(">HH", len, len)). A firmware
// that decoded these two fields little-endian would silently misparse a
// real signed-wire descriptor from any conformant sender and reject it --
// exactly the failure observed on physical hardware.
TEST(LoraOtaIntegration, DescriptorFragmentHeaderIsBigEndianWireFormat) {
  uint8_t seed[32] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0xB0u + i);
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
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
  anchor.supported_boot_capability_flags = 0x0000000Fu;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);
  mesh::ota::OtaFirmwareTrustProvider trust(verifier, candidate);
  mesh::ota::OtaFirmwareStorageSink staging(candidate);

  uint8_t image[2 * kOtaDefaultChunkPayloadSize] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(0xB5u + i);
  OtaDescriptor descriptor = buildProtocolDescriptor(image, sizeof(image), 3);
  ::ota::trust::ImageDescriptor trust_descriptor = buildSignedTrustDescriptor(descriptor, signer);

  uint8_t canonical[kOtaDescriptorCanonicalSize] = {};
  size_t canonical_len = 0;
  ASSERT_EQ(OtaDescriptorCodecResult::Ok,
            encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), canonical_len));
  ASSERT_EQ(kOtaDescriptorCanonicalSize, canonical_len);
  const size_t blob_len = kOtaDescriptorCanonicalSize + 64;
  ASSERT_LT(blob_len, 256u) << "test relies on the length fitting one byte so a byte-order bug flips it";

  auto sendDescriptor = [&](bool big_endian) -> bool {
    mesh::ota::OtaFirmwareIntegration integration;
    integration.attachTrustProvider(&trust);
    integration.attachStagingSink(&staging);

    uint8_t descriptor_payload[160] = {};
    descriptor_payload[0] = 0;  // fragment index
    descriptor_payload[1] = 1;  // fragment count
    if (big_endian) {
      descriptor_payload[2] = static_cast<uint8_t>((blob_len >> 8) & 0xFFu);
      descriptor_payload[3] = static_cast<uint8_t>(blob_len & 0xFFu);
      descriptor_payload[4] = static_cast<uint8_t>((blob_len >> 8) & 0xFFu);
      descriptor_payload[5] = static_cast<uint8_t>(blob_len & 0xFFu);
    } else {
      // Deliberately wrong (little-endian) byte order, as the firmware bug
      // used to decode it: must be rejected, not silently misinterpreted.
      descriptor_payload[2] = static_cast<uint8_t>(blob_len & 0xFFu);
      descriptor_payload[3] = static_cast<uint8_t>((blob_len >> 8) & 0xFFu);
      descriptor_payload[4] = static_cast<uint8_t>(blob_len & 0xFFu);
      descriptor_payload[5] = static_cast<uint8_t>((blob_len >> 8) & 0xFFu);
    }
    std::memcpy(&descriptor_payload[6], canonical, canonical_len);
    std::memcpy(&descriptor_payload[6 + canonical_len], trust_descriptor.signature_ed25519, 64);

    uint8_t frame[192] = {};
    size_t frame_len = 0;
    if (!encodeFrame(OtaMessageType::DescriptorFragment, descriptor_payload, 6 + blob_len, frame, sizeof(frame), frame_len)) {
      return false;
    }
    bool accepted = integration.handleReceivedFrame(frame, frame_len);
    return accepted && integration.status(0).receiverState == OtaReceiverState::AwaitingAuthorization;
  };

  EXPECT_TRUE(sendDescriptor(/*big_endian=*/true))
      << "a real, correctly big-endian signed-wire descriptor must be accepted";
  EXPECT_FALSE(sendDescriptor(/*big_endian=*/false))
      << "a little-endian-framed header must never be silently accepted";
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

TEST(LoraOtaIntegration, DirectLeaseRejectsTimeoutThatWouldOverflowScheduledRevertDeadline) {
  // 35791 minutes is the largest timeout that keeps
  // 2000 + timeoutMinutes*60*1000 within INT32_MAX ms (the wrap-safe bound
  // Dispatcher::futureMillis()/millisHasNowPassed() require); 35792
  // previously overflowed 32-bit int arithmetic downstream and must be
  // rejected here rather than silently accepted and later corrupted.
  mesh::ota::OtaDirectLeaseParams at_bound{915.0f, 250.0f, 10, 5, 35791};
  EXPECT_TRUE(mesh::ota::isValidOtaDirectLease(at_bound));

  mesh::ota::OtaDirectLeaseParams over_bound{915.0f, 250.0f, 10, 5, 35792};
  EXPECT_FALSE(mesh::ota::isValidOtaDirectLease(over_bound));

  mesh::ota::OtaDirectLeaseParams max_uint16{915.0f, 250.0f, 10, 5, 65535};
  EXPECT_FALSE(mesh::ota::isValidOtaDirectLease(max_uint16));

  RecordingDirectLeaseHandler handler(true);
  EXPECT_FALSE(mesh::ota::requestOtaDirectLease(handler, over_bound));
  EXPECT_EQ(0, handler.mode_calls);
  EXPECT_EQ(0, handler.apply_calls);
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
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
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

namespace {
// Minimal fake V2 install-command provider: proves commit() forwards the
// SAME verbatim wire descriptor/signature bytes the transport verified
// (never re-derived/re-signed) into whatever fields the provider supplies
// for the currently-running image's extent/hash.
class FakeInstallCommandProviderV2 : public mesh::ota::IOtaInstallCommandProviderV2 {
public:
  bool buildInstallCommandV2(const uint8_t wire_descriptor[::ota::storage::XiaoOtaCommandRecordV2::kWireDescriptorBytes],
                             const uint8_t signature[::ota::storage::XiaoOtaCommandRecordV2::kSignatureBytes],
                             const meshcore::ota::runtime::OtaSessionId& session,
                             const uint8_t controller[32],
                             ::ota::storage::XiaoOtaCommandV2Fields& out) override {
    std::memcpy(out.wire_descriptor, wire_descriptor, sizeof(out.wire_descriptor));
    std::memcpy(out.signature_ed25519, signature, sizeof(out.signature_ed25519));
    out.transaction_nonce = 0xAABBCCDDEEFF0011ull;
    out.active_image_extent = 4096;
    for (size_t i = 0; i < sizeof(out.active_image_hash_sha256); ++i) {
      out.active_image_hash_sha256[i] = static_cast<uint8_t>(i);
    }
    last_session = session;
    std::memcpy(last_controller, controller, sizeof(last_controller));
    build_calls++;
    return should_succeed;
  }

  bool should_succeed = true;
  int build_calls = 0;
  meshcore::ota::runtime::OtaSessionId last_session{};
  uint8_t last_controller[32] = {};
};

class FakeInstallCommandProviderV3 : public mesh::ota::IOtaInstallCommandProviderV3 {
public:
  bool buildInstallCommandV3(const uint8_t wire_descriptor[::ota::storage::XiaoOtaCommandRecordV3::kWireDescriptorBytes],
                             const uint8_t signature[::ota::storage::XiaoOtaCommandRecordV3::kSignatureBytes],
                             const uint8_t admitted_signer_public_key[::ota::storage::XiaoOtaCommandRecordV3::kSignerKeyBytes],
                             const meshcore::ota::runtime::OtaSessionId& session,
                             const uint8_t controller[32],
                             ::ota::storage::XiaoOtaCommandV3Fields& out) override {
    std::memcpy(out.wire_descriptor, wire_descriptor, sizeof(out.wire_descriptor));
    std::memcpy(out.admitted_signer_public_key_ed25519, admitted_signer_public_key,
                sizeof(out.admitted_signer_public_key_ed25519));
    std::memcpy(out.signature_ed25519, signature, sizeof(out.signature_ed25519));
    out.transaction_nonce = 0x1122334455667788ull;
    out.active_image_extent = 4096;
    for (size_t i = 0; i < sizeof(out.active_image_hash_sha256); ++i) {
      out.active_image_hash_sha256[i] = static_cast<uint8_t>(i);
    }
    last_session = session;
    std::memcpy(last_controller, controller, sizeof(last_controller));
    std::memcpy(last_admitted_signer_public_key, admitted_signer_public_key,
                sizeof(last_admitted_signer_public_key));
    build_calls++;
    return should_succeed;
  }

  bool should_succeed = true;
  int build_calls = 0;
  meshcore::ota::runtime::OtaSessionId last_session{};
  uint8_t last_controller[32] = {};
  uint8_t last_admitted_signer_public_key[32] = {};
};
}  // namespace

TEST(LoraOtaIntegration, FreshProductionSinkResumesWithoutReadingErasingOrProgramming) {
  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  uint8_t image[kOtaDefaultChunkPayloadSize + 37];
  std::memset(image, 0x51, sizeof(image));
  const OtaDescriptor descriptor = buildProtocolDescriptor(image, sizeof(image), 1);
  using Result = IOtaStagingSink::Result;
  {
    mesh::ota::OtaFirmwareStorageSink original(candidate);
    ASSERT_EQ(Result::Ok, original.beginSession(descriptor));
    ASSERT_EQ(Result::Ok, original.writeChunk(0, image, kOtaDefaultChunkPayloadSize));
  }
  const uint32_t erases = flash.eraseOpCount();
  const uint32_t programs = flash.programOpCount();
  const uint32_t reads = flash.readOpCount();
  mesh::ota::OtaFirmwareStorageSink reloaded(candidate);
  ASSERT_EQ(Result::Ok, reloaded.resumeSession(descriptor));
  EXPECT_EQ(erases, flash.eraseOpCount());
  EXPECT_EQ(programs, flash.programOpCount());
  EXPECT_EQ(reads, flash.readOpCount());
  EXPECT_EQ(0, std::memcmp(flash.rawBuffer(), image, kOtaDefaultChunkPayloadSize));
  EXPECT_FALSE(reloaded.haveVerifiedWireDescriptor());
  EXPECT_FALSE(reloaded.haveAuthorizedSession());
  ASSERT_EQ(Result::Ok, reloaded.writeChunk(kOtaDefaultChunkPayloadSize,
                                          image + kOtaDefaultChunkPayloadSize, 37));
  EXPECT_EQ(0, std::memcmp(flash.rawBuffer(), image, sizeof(image)));
  EXPECT_EQ(Result::Ok, reloaded.commit());
  EXPECT_FALSE(reloaded.isActive());
  EXPECT_TRUE(reloaded.isCommitted());
}

TEST(LoraOtaIntegration, ResumeRejectsInvalidRegionAndExtentWithoutFlashMutation) {
  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  ::ota::platform::FlashRegion invalid(flash, 1, 4096);
  OtaDescriptor descriptor;
  descriptor.exactSizeBytes = 128;
  mesh::ota::OtaFirmwareStorageSink sink(candidate);
  using Result = IOtaStagingSink::Result;
  ASSERT_EQ(Result::Ok, sink.resumeSession(descriptor));
  descriptor.exactSizeBytes = 0;
  EXPECT_EQ(Result::Rejected, sink.resumeSession(descriptor));
  EXPECT_FALSE(sink.isActive());
  descriptor.exactSizeBytes = 4097;
  EXPECT_EQ(Result::Rejected, sink.resumeSession(descriptor));
  descriptor.exactSizeBytes = 128;
  mesh::ota::OtaFirmwareStorageSink invalidSink(invalid);
  EXPECT_EQ(Result::Rejected, invalidSink.resumeSession(descriptor));
  EXPECT_EQ(Result::Rejected, invalidSink.beginSession(descriptor));
  EXPECT_EQ(0u, flash.eraseOpCount());
  EXPECT_EQ(0u, flash.programOpCount());
  EXPECT_EQ(0u, flash.readOpCount());
}

TEST(LoraOtaIntegration, ResumedProductionHandoffRequiresRestoredVerifiedWireAndConsent) {
  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  ::ota::test::FakeNorFlash commands(8192, 4096);
  ::ota::platform::FlashRegion commandRegion(commands, 0, 8192);
  FakeInstallCommandProviderV2 provider;
  mesh::ota::OtaFirmwareStorageSink sink(candidate, &commandRegion, &provider);
  uint8_t image[128] = {};
  const OtaDescriptor descriptor = buildProtocolDescriptor(image, sizeof(image), 1);
  uint8_t canonical[kOtaDescriptorCanonicalSize], signature[64], controller[32];
  size_t canonicalLen = 0;
  ASSERT_EQ(OtaDescriptorCodecResult::Ok,
            encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), canonicalLen));
  std::memset(signature, 0x62, sizeof(signature));
  std::memset(controller, 0x73, sizeof(controller));
  const OtaSessionId session{42, 7, 1};
  using Result = IOtaStagingSink::Result;
  ASSERT_EQ(Result::Ok, sink.resumeSession(descriptor));
  EXPECT_EQ(Result::Rejected, sink.commit());
  sink.onVerifiedWireDescriptor(canonical, canonicalLen, signature, sizeof(signature));
  EXPECT_EQ(Result::Rejected, sink.commit());
  EXPECT_EQ(0, provider.build_calls);
  EXPECT_EQ(0u, commands.eraseOpCount());
  sink.onAuthorizedSession(session, controller);
  ASSERT_EQ(Result::Ok, sink.commit());
  EXPECT_EQ(1, provider.build_calls);
  EXPECT_TRUE(otaSessionEquals(session, provider.last_session));
  EXPECT_EQ(0, std::memcmp(controller, provider.last_controller, sizeof(controller)));
  uint8_t record[::ota::storage::XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV2::readNewest(commandRegion, record));
  EXPECT_EQ(0, std::memcmp(record + 20, canonical, sizeof(canonical)));
  EXPECT_EQ(0, std::memcmp(record + 20 + sizeof(canonical), signature, sizeof(signature)));
}

TEST(LoraOtaIntegration, ReattachingSinkNeverReusesPriorConsentOrVerifiedDescriptor) {
  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  ::ota::test::FakeNorFlash commands(8192, 4096);
  ::ota::platform::FlashRegion commandRegion(commands, 0, 8192);
  FakeInstallCommandProviderV2 provider;
  mesh::ota::OtaFirmwareStorageSink sink(candidate, &commandRegion, &provider);
  OtaDescriptor descriptor;
  descriptor.exactSizeBytes = 128;
  uint8_t canonical[kOtaDescriptorCanonicalSize] = {}, signature[64] = {}, controller[32] = {};
  using Result = IOtaStagingSink::Result;
  for (bool resume : {false, true}) {
    ASSERT_EQ(Result::Ok, sink.resumeSession(descriptor));
    sink.onVerifiedWireDescriptor(canonical, sizeof(canonical), signature, sizeof(signature));
    sink.onAuthorizedSession({42, 7, 1}, controller);
    ASSERT_TRUE(sink.haveVerifiedWireDescriptor());
    ASSERT_TRUE(sink.haveAuthorizedSession());
    ASSERT_EQ(Result::Ok, resume ? sink.resumeSession(descriptor) : sink.beginSession(descriptor));
    EXPECT_FALSE(sink.haveVerifiedWireDescriptor());
    EXPECT_FALSE(sink.haveAuthorizedSession());
    sink.onVerifiedWireDescriptor(canonical, sizeof(canonical), signature, sizeof(signature));
    EXPECT_EQ(Result::Rejected, sink.commit());
  }
  EXPECT_EQ(0, provider.build_calls);
  EXPECT_EQ(0u, commands.eraseOpCount());
}

TEST(LoraOtaIntegration, ResumedSinkRejectsWritesOutsideDeclaredImageBeforeProgramming) {
  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  mesh::ota::OtaFirmwareStorageSink sink(candidate);
  OtaDescriptor descriptor;
  descriptor.exactSizeBytes = kOtaDefaultChunkPayloadSize + 37;
  uint8_t bytes[kOtaDefaultChunkPayloadSize + 1] = {};
  using Result = IOtaStagingSink::Result;
  ASSERT_EQ(Result::Ok, sink.resumeSession(descriptor));
  EXPECT_EQ(Result::Rejected, sink.writeChunk(kOtaDefaultChunkPayloadSize, bytes, 38));
  EXPECT_EQ(Result::Rejected, sink.writeChunk(2 * kOtaDefaultChunkPayloadSize, bytes, 1));
  EXPECT_EQ(Result::Rejected, sink.writeChunk(UINT64_MAX, bytes, 1));
  EXPECT_EQ(Result::Rejected, sink.writeChunk(0, bytes, sizeof(bytes)));
  // The last byte of the declared image is in bounds, but asking for one
  // more byte than remains must still be rejected -- a raw byte offset
  // that isn't a multiple of kOtaDefaultChunkPayloadSize (e.g. the lean
  // path's 84-byte block pitch) is otherwise a perfectly legitimate write
  // and must NOT be rejected purely for being "unaligned" (see
  // StorageManager::writeAndVerifyAtOffset()).
  EXPECT_EQ(Result::Rejected, sink.writeChunk(descriptor.exactSizeBytes - 1, bytes, 2));
  EXPECT_EQ(0u, flash.programOpCount());
}

TEST(LoraOtaIntegration, ResumedSinkAcceptsNonChunkAlignedOffsetWithinDeclaredImageBounds) {
  // Regression test for a genuine defect: writeChunk()/readChunk() used
  // to require `offset % kOtaDefaultChunkPayloadSize == 0` (128-byte
  // pitch), but the lean path addresses blocks at `index *
  // kOtaBlockMaxDataBytes` (84-byte pitch) -- any lean block beyond index
  // 0 landed on an offset that is NOT a multiple of 128 and was
  // previously, silently, always rejected. A raw byte offset is only ever
  // invalid for being outside the declared image, never for its
  // alignment.
  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  mesh::ota::OtaFirmwareStorageSink sink(candidate);
  OtaDescriptor descriptor;
  descriptor.exactSizeBytes = 200;
  using Result = IOtaStagingSink::Result;
  ASSERT_EQ(Result::Ok, sink.resumeSession(descriptor));

  uint8_t block0[84] = {};
  for (size_t i = 0; i < sizeof(block0); ++i) block0[i] = static_cast<uint8_t>(i);
  uint8_t block1[84] = {};
  for (size_t i = 0; i < sizeof(block1); ++i) block1[i] = static_cast<uint8_t>(0x80u + i);

  EXPECT_EQ(Result::Ok, sink.writeChunk(0, block0, sizeof(block0)));
  // offset=84 is NOT a multiple of 128 -- this is the exact case the old
  // modulus check always rejected.
  EXPECT_EQ(Result::Ok, sink.writeChunk(84, block1, sizeof(block1)));

  uint8_t readback0[84] = {};
  uint8_t readback1[84] = {};
  EXPECT_EQ(Result::Ok, sink.readChunk(0, readback0, sizeof(readback0)));
  EXPECT_EQ(Result::Ok, sink.readChunk(84, readback1, sizeof(readback1)));
  EXPECT_EQ(0, std::memcmp(block0, readback0, sizeof(block0)));
  EXPECT_EQ(0, std::memcmp(block1, readback1, sizeof(block1)));
}

TEST(LoraOtaIntegration, ResumedSinkSurfacesProgramAndReadbackFailures) {
  using Flash = ::ota::test::FakeNorFlash;
  using Result = IOtaStagingSink::Result;
  for (Flash::OpKind op : {Flash::OpKind::Program, Flash::OpKind::Read}) {
    Flash flash(4096, 4096);
    ::ota::platform::FlashRegion candidate(flash, 0, 4096);
    mesh::ota::OtaFirmwareStorageSink sink(candidate);
    OtaDescriptor descriptor;
    descriptor.exactSizeBytes = 128;
    ASSERT_EQ(Result::Ok, sink.resumeSession(descriptor));
    Flash::FaultSpec fault;
    fault.kind = op;
    fault.timing = Flash::InjectionTiming::Before;
    flash.armFault(fault);
    uint8_t bytes[128] = {};
    EXPECT_EQ(Result::IoError, sink.writeChunk(0, bytes, sizeof(bytes)));
    EXPECT_EQ(0u, flash.eraseOpCount());
    EXPECT_FALSE(sink.isCommitted());
  }
}

TEST(LoraOtaIntegration, PartialHandoffConfigurationCannotBecomeStagingOnlySuccessOnResume) {
  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  ::ota::test::FakeNorFlash commands(8192, 4096);
  ::ota::platform::FlashRegion commandRegion(commands, 0, 8192);
  FakeInstallCommandProviderV2 provider;
  mesh::ota::OtaFirmwareStorageSink noProvider(
      candidate, &commandRegion, static_cast<mesh::ota::IOtaInstallCommandProviderV2*>(nullptr));
  mesh::ota::OtaFirmwareStorageSink noRegion(candidate, nullptr, &provider);
  OtaDescriptor descriptor;
  descriptor.exactSizeBytes = 128;
  using Result = IOtaStagingSink::Result;
  for (auto* sink : {&noProvider, &noRegion}) {
    ASSERT_EQ(Result::Ok, sink->resumeSession(descriptor));
    EXPECT_EQ(Result::Rejected, sink->commit());
    EXPECT_FALSE(sink->isCommitted());
  }
  EXPECT_EQ(0, provider.build_calls);
  EXPECT_EQ(0u, commands.eraseOpCount());
}

TEST(LoraOtaIntegration, CommandV2ProviderReceivesVerbatimVerifiedWireDescriptorAndWritesDurableRecord) {
  mesh::ota::OtaFirmwareIntegration integration;
  uint8_t seed[32] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0x60u + i);
  ::ota::test::Ed25519TestSigner signer(seed);

  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  ::ota::test::FakeNorFlash command_flash(8192, 4096);
  ::ota::platform::FlashRegion command_region_v2(command_flash, 0, 8192);
  ::ota::test::FakeMonotonicCounter counter(8);
  ::ota::trust::Sha256 hasher;
  ::ota::trust::Ed25519SignatureVerifier sig_verifier;
  ::ota::trust::DeviceTrustAnchor anchor;
  std::memcpy(anchor.trusted_signer_public_key_ed25519, signer.publicKey(), 32);
  anchor.expected_target_id = (0x1001u << 16) | 0x0002u;
  anchor.expected_role_id = 7;
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
  anchor.supported_boot_capability_flags = 0x0000000Fu;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);
  mesh::ota::OtaFirmwareTrustProvider trust(verifier, candidate, sig_verifier, signer.publicKey());
  FakeInstallCommandProviderV2 provider_v2;
  mesh::ota::OtaFirmwareStorageSink staging(candidate, &command_region_v2, &provider_v2);
  integration.attachTrustProvider(&trust);
  integration.attachStagingSink(&staging);

  uint8_t image[2 * kOtaDefaultChunkPayloadSize] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(0xD0u + i);
  OtaDescriptor descriptor = buildProtocolDescriptor(image, sizeof(image), 9);
  uint8_t canonical_wire[kOtaDescriptorCanonicalSize] = {};
  size_t canonical_wire_len = 0;
  ASSERT_EQ(OtaDescriptorCodecResult::Ok,
            encodeOtaDescriptorCanonical(descriptor, canonical_wire, sizeof(canonical_wire), canonical_wire_len));
  uint8_t signature[64] = {};
  signer.sign(canonical_wire, canonical_wire_len, signature);

  sendValidDescriptorAndAuthorization(integration, descriptor, signature);
  sendImageChunksAndCommit(integration, image, descriptor);
  EXPECT_EQ(OtaReceiverState::Complete, integration.status(0).receiverState);
  EXPECT_EQ(1, provider_v2.build_calls);

  // The authorized-session hook must have delivered THIS attempt's
  // session id (from encodeFrame()'s fixed {42,7,1} header) and the
  // controller identity that verified the descriptor's signature (the
  // signer's own pubkey here) -- never a zeroed/placeholder identity.
  EXPECT_EQ(provider_v2.last_session.campaignId, 42u);
  EXPECT_EQ(provider_v2.last_session.sessionId, 7u);
  EXPECT_EQ(provider_v2.last_session.attemptId, 1u);
  EXPECT_EQ(0, std::memcmp(provider_v2.last_controller, signer.publicKey(), 32));

  uint8_t record[::ota::storage::XiaoOtaCommandRecordV2::kRecordBytes];
  ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV2::readNewest(command_region_v2, record));
  EXPECT_TRUE(::ota::storage::XiaoOtaCommandRecordV2::isValidRecord(record, sizeof(record)));

  // The embedded 59-byte wire descriptor must byte-for-byte match the
  // transport's own canonical (big-endian) encoding of `descriptor` --
  // proving no re-derivation happened anywhere in the commit path.
  constexpr uint32_t kWireDescriptorOffset = 4 + 2 + 2 + 4 + 8;  // magic+version+bytes+sequence+nonce
  EXPECT_EQ(0, std::memcmp(record + kWireDescriptorOffset, canonical_wire, sizeof(canonical_wire)));

  constexpr uint32_t kSignatureOffset = kWireDescriptorOffset + kOtaDescriptorCanonicalSize;
  EXPECT_EQ(0, std::memcmp(record + kSignatureOffset, signature, 64));
}

TEST(LoraOtaIntegration, CommandV2ProviderRejectionFailsCommitWithoutFabricatingRecord) {
  mesh::ota::OtaFirmwareIntegration integration;
  uint8_t seed[32] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0x61u + i);
  ::ota::test::Ed25519TestSigner signer(seed);

  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  ::ota::test::FakeNorFlash command_flash(8192, 4096);
  ::ota::platform::FlashRegion command_region_v2(command_flash, 0, 8192);
  ::ota::test::FakeMonotonicCounter counter(8);
  ::ota::trust::Sha256 hasher;
  ::ota::trust::Ed25519SignatureVerifier sig_verifier;
  ::ota::trust::DeviceTrustAnchor anchor;
  std::memcpy(anchor.trusted_signer_public_key_ed25519, signer.publicKey(), 32);
  anchor.expected_target_id = (0x1001u << 16) | 0x0002u;
  anchor.expected_role_id = 7;
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
  anchor.supported_boot_capability_flags = 0x0000000Fu;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);
  mesh::ota::OtaFirmwareTrustProvider trust(verifier, candidate, sig_verifier, signer.publicKey());
  FakeInstallCommandProviderV2 provider_v2;
  provider_v2.should_succeed = false;  // simulates "no genuine extent/hash available yet"
  mesh::ota::OtaFirmwareStorageSink staging(candidate, &command_region_v2, &provider_v2);
  integration.attachTrustProvider(&trust);
  integration.attachStagingSink(&staging);

  uint8_t image[2 * kOtaDefaultChunkPayloadSize] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(0xE0u + i);
  OtaDescriptor descriptor = buildProtocolDescriptor(image, sizeof(image), 11);
  uint8_t canonical_wire[kOtaDescriptorCanonicalSize] = {};
  size_t canonical_wire_len = 0;
  ASSERT_EQ(OtaDescriptorCodecResult::Ok,
            encodeOtaDescriptorCanonical(descriptor, canonical_wire, sizeof(canonical_wire), canonical_wire_len));
  uint8_t signature[64] = {};
  signer.sign(canonical_wire, canonical_wire_len, signature);

  sendValidDescriptorAndAuthorization(integration, descriptor, signature);

  // Inline chunk+commit send (not the shared sendImageChunksAndCommit
  // helper): that helper ASSERT_TRUE's the Commit frame's own handling
  // succeeds, which is correct for the happy path but not here, since a
  // rejecting v2 provider is expected to make handleReceivedFrame(Commit)
  // return false (commit() must fail, not silently "succeed" while
  // skipping the durable bootloader handoff).
  {
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
    EXPECT_FALSE(integration.handleReceivedFrame(frame, frame_len));
  }

  // Fail-closed: a rejecting provider must never leave commit() reporting
  // success, and must never leave a fabricated record in flash.
  EXPECT_NE(OtaReceiverState::Complete, integration.status(0).receiverState);
  uint8_t record[::ota::storage::XiaoOtaCommandRecordV2::kRecordBytes];
  EXPECT_FALSE(::ota::storage::XiaoOtaCommandRecordV2::readNewest(command_region_v2, record));
}

// MAIN's explicit correction: the durable v3 record's admitted signer key
// must be the real cryptographic owner identity, resolved via the
// device's own existing admin-authorization mechanism -- never the
// compiled/qualification-time trust anchor (authorized_controller_, as
// returned by OtaFirmwareTrustProvider::controllerIdentity()) and never
// an image/descriptor tag. Exercised directly against the sink (not the
// full RF round-trip) since onAdmittedOwnerIdentity() is a narrow,
// deliberately NOT-yet-wired-anywhere setter pending that real lookup.
TEST(LoraOtaIntegration, CommandV3CommitFailsClosedWithoutAdmittedOwnerIdentity) {
  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  ::ota::test::FakeNorFlash command_flash(8192, 4096);
  ::ota::platform::FlashRegion command_region_v3(command_flash, 0, 8192);
  FakeInstallCommandProviderV3 provider_v3;
  mesh::ota::OtaFirmwareStorageSink sink(candidate, &command_region_v3, &provider_v3);

  OtaDescriptor descriptor;
  descriptor.exactSizeBytes = 128;
  using Result = IOtaStagingSink::Result;
  ASSERT_EQ(Result::Ok, sink.resumeSession(descriptor));

  uint8_t wire_descriptor[kOtaDescriptorCanonicalSize] = {};
  uint8_t signature[64] = {};
  sink.onVerifiedWireDescriptor(wire_descriptor, sizeof(wire_descriptor), signature, sizeof(signature));
  uint8_t controller[32] = {1, 2, 3};
  sink.onAuthorizedSession(OtaSessionId{42, 7, 1}, controller);

  // onAdmittedOwnerIdentity() deliberately never called: the real owner
  // lookup this represents is not yet wired to any caller.
  EXPECT_EQ(Result::Rejected, sink.commit());
  EXPECT_FALSE(sink.isCommitted());
  EXPECT_EQ(0, provider_v3.build_calls);
  uint8_t record[::ota::storage::XiaoOtaCommandRecordV3::kRecordBytes];
  EXPECT_FALSE(::ota::storage::XiaoOtaCommandRecordV3::readNewest(command_region_v3, record));
}

TEST(LoraOtaIntegration, CommandV3ProviderReceivesGenuineAdmittedOwnerKeyNotAuthorizedController) {
  ::ota::test::FakeNorFlash flash(4096, 4096);
  ::ota::platform::FlashRegion candidate(flash, 0, 4096);
  ::ota::test::FakeNorFlash command_flash(8192, 4096);
  ::ota::platform::FlashRegion command_region_v3(command_flash, 0, 8192);
  FakeInstallCommandProviderV3 provider_v3;
  mesh::ota::OtaFirmwareStorageSink sink(candidate, &command_region_v3, &provider_v3);

  OtaDescriptor descriptor;
  descriptor.exactSizeBytes = 128;
  using Result = IOtaStagingSink::Result;
  ASSERT_EQ(Result::Ok, sink.resumeSession(descriptor));

  uint8_t wire_descriptor[kOtaDescriptorCanonicalSize] = {};
  for (size_t i = 0; i < sizeof(wire_descriptor); ++i) wire_descriptor[i] = static_cast<uint8_t>(0x70u + i);
  uint8_t signature[64] = {};
  for (size_t i = 0; i < sizeof(signature); ++i) signature[i] = static_cast<uint8_t>(0x90u + i);
  sink.onVerifiedWireDescriptor(wire_descriptor, sizeof(wire_descriptor), signature, sizeof(signature));

  // `authorized_controller_` here stands in for the compiled/qualification
  // trust anchor (OtaFirmwareTrustProvider::controllerIdentity()'s current
  // return value) -- deliberately DIFFERENT from the genuinely admitted
  // owner key below, to prove the two are never conflated.
  uint8_t authorized_controller[32] = {};
  for (size_t i = 0; i < sizeof(authorized_controller); ++i) authorized_controller[i] = static_cast<uint8_t>(0x10u + i);
  sink.onAuthorizedSession(OtaSessionId{42, 7, 1}, authorized_controller);

  uint8_t admitted_owner[32] = {};
  for (size_t i = 0; i < sizeof(admitted_owner); ++i) admitted_owner[i] = static_cast<uint8_t>(0xA0u + i);
  sink.onAdmittedOwnerIdentity(admitted_owner);

  ASSERT_EQ(Result::Ok, sink.commit());
  EXPECT_TRUE(sink.isCommitted());
  ASSERT_EQ(1, provider_v3.build_calls);
  // The provider must have received the genuinely admitted owner key --
  // never the authorized_controller_/compiled-anchor stand-in.
  EXPECT_EQ(0, std::memcmp(provider_v3.last_admitted_signer_public_key, admitted_owner, 32));
  EXPECT_NE(0, std::memcmp(provider_v3.last_admitted_signer_public_key, authorized_controller, 32));

  uint8_t record[::ota::storage::XiaoOtaCommandRecordV3::kRecordBytes];
  ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV3::readNewest(command_region_v3, record));
  EXPECT_EQ(0, std::memcmp(::ota::storage::XiaoOtaCommandRecordV3::admittedSignerKeyOf(record), admitted_owner, 32));
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
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
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
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
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
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
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

// A foreign-session Authorization frame must never be able to abort a
// legitimately in-progress session's staging or grant access on its
// behalf, even when its own decoded content would otherwise fail (e.g.
// granted=0): the session-id check must run *before* any staging mutation
// or `authorized_` state change, not only inside receiver_.handle()
// afterward.
TEST(LoraOtaIntegration, ForeignAuthorizationDuringActiveSessionDoesNotAbortStagingOrGrantAccess) {
  mesh::ota::OtaFirmwareIntegration integration;
  uint8_t seed[32] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0xC0u + i);
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
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
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
  ASSERT_EQ(OtaReceiverState::AwaitingAuthorization, integration.status(0).receiverState);

  // Foreign session, deliberately shaped to fail validation (granted=0) so
  // the pre-fix code would reach its failure branch and unconditionally
  // abort the (unrelated, active) staging sink.
  OtaAuthorizationPayload foreign_auth;
  foreign_auth.granted = 0;
  foreign_auth.leaseId = 1;
  foreign_auth.expiresAtMs = 60000;
  foreign_auth.maxInFlightChunks = 2;
  uint8_t foreign_payload[kOtaAuthorizationPayloadSize] = {};
  size_t foreign_len = 0;
  ASSERT_TRUE(encodeOtaAuthorization(foreign_auth, foreign_payload, sizeof(foreign_payload), foreign_len));
  OtaEnvelopeHeader foreign_hdr;
  foreign_hdr.type = OtaMessageType::Authorization;
  foreign_hdr.campaignId = 42;
  foreign_hdr.sessionId = 999;
  foreign_hdr.attemptId = 1;
  ASSERT_EQ(OtaCodecResult::Ok, encodeOtaEnvelope(foreign_hdr, foreign_payload, foreign_len, frame, sizeof(frame), frame_len));
  EXPECT_FALSE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_EQ(OtaReceiverState::AwaitingAuthorization, integration.status(0).receiverState)
      << "a foreign authorization frame must not disturb the active session's state";

  // The real, correctly-addressed authorization must still work: staging
  // was never aborted by the foreign frame above.
  OtaAuthorizationPayload authorization;
  authorization.granted = 1;
  authorization.leaseId = 1;
  authorization.expiresAtMs = 60000;
  authorization.maxInFlightChunks = 2;
  uint8_t authorization_payload[kOtaAuthorizationPayloadSize] = {};
  size_t authorization_len = 0;
  ASSERT_TRUE(encodeOtaAuthorization(authorization, authorization_payload, sizeof(authorization_payload), authorization_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Authorization, authorization_payload, authorization_len, frame, sizeof(frame), frame_len));
  EXPECT_TRUE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_EQ(OtaReceiverState::Receiving, integration.status(0).receiverState);
}

// A foreign-session Chunk frame must be rejected before it is written into
// the active session's staged image or marked in its receipt bitmap, even
// when its chunk index and length are otherwise valid for the active
// campaign's geometry: otherwise an interleaved/foreign packet can silently
// corrupt bytes of a legitimate in-flight transfer.
TEST(LoraOtaIntegration, ForeignChunkDuringActiveSessionDoesNotWriteOrMarkReceipt) {
  mesh::ota::OtaFirmwareIntegration integration;
  uint8_t seed[32] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0xD0u + i);
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
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
  anchor.supported_boot_capability_flags = 0x0000000Fu;
  ::ota::trust::DescriptorVerifier verifier(hasher, sig_verifier, counter, anchor);
  mesh::ota::OtaFirmwareTrustProvider trust(verifier, candidate);
  mesh::ota::OtaFirmwareStorageSink staging(candidate);
  integration.attachTrustProvider(&trust);
  integration.attachStagingSink(&staging);

  uint8_t image[2 * kOtaDefaultChunkPayloadSize] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(0xE0u + i);
  OtaDescriptor descriptor = buildProtocolDescriptor(image, sizeof(image), 1);
  ::ota::trust::ImageDescriptor trust_descriptor = buildSignedTrustDescriptor(descriptor, signer);
  sendValidDescriptorAndAuthorization(integration, descriptor, trust_descriptor.signature_ed25519);
  ASSERT_EQ(OtaReceiverState::Receiving, integration.status(0).receiverState);

  // Foreign session sends malicious data for chunk index 0.
  uint8_t malicious[kOtaDefaultChunkPayloadSize];
  std::memset(malicious, 0x66, sizeof(malicious));
  OtaChunkHeader foreign_chunk;
  foreign_chunk.chunkIndex = 0;
  foreign_chunk.dataLength = kOtaDefaultChunkPayloadSize;
  uint8_t chunk_payload[kOtaChunkHeaderSize + kOtaDefaultChunkPayloadSize] = {};
  size_t chunk_len = 0;
  ASSERT_TRUE(encodeOtaChunk(foreign_chunk, malicious, kOtaDefaultChunkPayloadSize, chunk_payload, sizeof(chunk_payload), chunk_len));
  OtaEnvelopeHeader foreign_hdr;
  foreign_hdr.type = OtaMessageType::Chunk;
  foreign_hdr.campaignId = 42;
  foreign_hdr.sessionId = 999;
  foreign_hdr.attemptId = 1;
  uint8_t frame[192] = {};
  size_t frame_len = 0;
  ASSERT_EQ(OtaCodecResult::Ok, encodeOtaEnvelope(foreign_hdr, chunk_payload, chunk_len, frame, sizeof(frame), frame_len));
  EXPECT_FALSE(integration.handleReceivedFrame(frame, frame_len));

  uint8_t still_erased[kOtaDefaultChunkPayloadSize];
  std::memset(still_erased, 0xFF, sizeof(still_erased));
  EXPECT_EQ(0, std::memcmp(flash.rawBuffer(), still_erased, sizeof(still_erased)))
      << "a foreign-session chunk must not be written into the active session's staged image";

  // The legitimate transfer must still complete normally afterward.
  sendImageChunksAndCommit(integration, image, descriptor);
  EXPECT_EQ(OtaReceiverState::Complete, integration.status(0).receiverState);
  EXPECT_EQ(0, std::memcmp(flash.rawBuffer(), image, sizeof(image)));
}

TEST(LoraOtaIntegration, FleetAnnouncementCensusCohortAndRepairRequireValidCampaignBoundPayloads) {
  mesh::ota::OtaFirmwareIntegration integration;
  uint8_t frame[192] = {};
  size_t frame_len = 0;

  // A malformed/wrong-length Announcement must not begin a fleet campaign.
  const uint8_t garbage[] = {0x01, 0x02, 0x03};
  ASSERT_TRUE(encodeFrame(OtaMessageType::Announcement, garbage, sizeof(garbage), frame, sizeof(frame), frame_len));
  EXPECT_FALSE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_EQ(OtaFleetState::Idle, integration.status(0).fleetState);

  // An Announcement naming a different campaign than the envelope must be
  // rejected too, not merely a length check.
  OtaAnnouncementPayload wrong_campaign;
  wrong_campaign.campaignId = 999;  // encodeFrame() uses campaignId 42
  wrong_campaign.descriptorTotalLength = 200;
  wrong_campaign.priority = 1;
  wrong_campaign.expiresAtMs = 60000;
  uint8_t announce_payload[kOtaAnnouncementPayloadSize] = {};
  size_t announce_len = 0;
  ASSERT_TRUE(encodeOtaAnnouncement(wrong_campaign, announce_payload, sizeof(announce_payload), announce_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Announcement, announce_payload, announce_len, frame, sizeof(frame), frame_len));
  EXPECT_FALSE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_EQ(OtaFleetState::Idle, integration.status(0).fleetState);

  // A real, campaign-bound Announcement begins the campaign.
  OtaAnnouncementPayload announcement;
  announcement.campaignId = 42;
  announcement.descriptorTotalLength = 200;
  announcement.priority = 1;
  announcement.expiresAtMs = 60000;
  ASSERT_TRUE(encodeOtaAnnouncement(announcement, announce_payload, sizeof(announce_payload), announce_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Announcement, announce_payload, announce_len, frame, sizeof(frame), frame_len));
  EXPECT_TRUE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_EQ(OtaFleetState::Announcing, integration.status(0).fleetState);

  // Census reporting that the reporter still lacks the descriptor is a
  // legal no-op that must not falsely advance the phase.
  OtaCensusPayload waiting_census;
  waiting_census.campaignId = 42;
  waiting_census.haveDescriptor = 0;
  waiting_census.bytesReceived = 0;
  waiting_census.missingRangeCount = 0;
  uint8_t census_payload[kOtaCensusPayloadSize] = {};
  size_t census_len = 0;
  ASSERT_TRUE(encodeOtaCensus(waiting_census, census_payload, sizeof(census_payload), census_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Census, census_payload, census_len, frame, sizeof(frame), frame_len));
  EXPECT_TRUE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_EQ(OtaFleetState::Census, integration.status(0).fleetState);
  EXPECT_EQ(1u, integration.status(0).fleetCensusReports);

  // Census reporting the descriptor is present resolves the census phase.
  OtaCensusPayload complete_census;
  complete_census.campaignId = 42;
  complete_census.haveDescriptor = 1;
  complete_census.bytesReceived = 200;
  complete_census.missingRangeCount = 0;
  ASSERT_TRUE(encodeOtaCensus(complete_census, census_payload, sizeof(census_payload), census_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Census, census_payload, census_len, frame, sizeof(frame), frame_len));
  EXPECT_TRUE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_EQ(OtaFleetState::CohortResolving, integration.status(0).fleetState);

  // An invalid cohort assignment (index >= size) must be rejected.
  OtaCohortResolutionPayload bad_cohort;
  bad_cohort.campaignId = 42;
  bad_cohort.cohortId = 3;
  bad_cohort.cohortSize = 4;
  bad_cohort.cohortIndex = 4;  // out of range
  uint8_t cohort_payload[kOtaCohortResolutionPayloadSize] = {};
  size_t cohort_len = 0;
  ASSERT_TRUE(encodeOtaCohortResolution(bad_cohort, cohort_payload, sizeof(cohort_payload), cohort_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::CohortResolution, cohort_payload, cohort_len, frame, sizeof(frame), frame_len));
  EXPECT_FALSE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_FALSE(integration.status(0).fleetHasCohort);
  EXPECT_EQ(OtaFleetState::CohortResolving, integration.status(0).fleetState);

  OtaCohortResolutionPayload cohort;
  cohort.campaignId = 42;
  cohort.cohortId = 3;
  cohort.cohortSize = 4;
  cohort.cohortIndex = 1;
  ASSERT_TRUE(encodeOtaCohortResolution(cohort, cohort_payload, sizeof(cohort_payload), cohort_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::CohortResolution, cohort_payload, cohort_len, frame, sizeof(frame), frame_len));
  EXPECT_TRUE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_EQ(OtaFleetState::Multicasting, integration.status(0).fleetState);
  EXPECT_TRUE(integration.status(0).fleetHasCohort);
  EXPECT_EQ(3u, integration.status(0).fleetCohortId);
  EXPECT_EQ(4u, integration.status(0).fleetCohortSize);
  EXPECT_EQ(1u, integration.status(0).fleetCohortIndex);

  // A directed selective-repair request with a zero chunk count is
  // malformed and must not select the repair phase.
  OtaMissingRangePayload zero_range;
  zero_range.campaignId = 42;
  zero_range.startChunkIndex = 0;
  zero_range.chunkCount = 0;
  uint8_t missing_payload[kOtaMissingRangePayloadSize] = {};
  size_t missing_len = 0;
  ASSERT_TRUE(encodeOtaMissingRange(zero_range, missing_payload, sizeof(missing_payload), missing_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::MissingRange, missing_payload, missing_len, frame, sizeof(frame), frame_len));
  EXPECT_FALSE(integration.handleReceivedFrame(frame, frame_len));

  // A re-census while Multicasting is the round-end signal: it must fold
  // MulticastComplete plus the missing/no-missing decision into one frame,
  // reaching Repairing when the reporter still has gaps. Before this fix
  // the fleet state machine had no path out of Multicasting at all (no
  // wire message ever fired MulticastComplete), so census/repair could
  // never actually run.
  OtaCensusPayload post_multicast_census;
  post_multicast_census.campaignId = 42;
  post_multicast_census.haveDescriptor = 1;
  post_multicast_census.bytesReceived = 150;
  post_multicast_census.missingRangeCount = 2;
  ASSERT_TRUE(encodeOtaCensus(post_multicast_census, census_payload, sizeof(census_payload), census_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Census, census_payload, census_len, frame, sizeof(frame), frame_len));
  EXPECT_TRUE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_EQ(OtaFleetState::Repairing, integration.status(0).fleetState);

  // A valid directed repair request is now accepted while Repairing.
  OtaMissingRangePayload real_range;
  real_range.campaignId = 42;
  real_range.startChunkIndex = 5;
  real_range.chunkCount = 2;
  ASSERT_TRUE(encodeOtaMissingRange(real_range, missing_payload, sizeof(missing_payload), missing_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::MissingRange, missing_payload, missing_len, frame, sizeof(frame), frame_len));
  EXPECT_TRUE(integration.handleReceivedFrame(frame, frame_len));

  // A re-census while Repairing that now reports no more gaps is the
  // repair-round-end signal: it must fold RepairRoundComplete plus the
  // no-missing decision into one frame, converging to Committing.
  OtaCensusPayload converged_census;
  converged_census.campaignId = 42;
  converged_census.haveDescriptor = 1;
  converged_census.bytesReceived = 200;
  converged_census.missingRangeCount = 0;
  ASSERT_TRUE(encodeOtaCensus(converged_census, census_payload, sizeof(census_payload), census_len));
  ASSERT_TRUE(encodeFrame(OtaMessageType::Census, census_payload, census_len, frame, sizeof(frame), frame_len));
  EXPECT_TRUE(integration.handleReceivedFrame(frame, frame_len));
  EXPECT_EQ(OtaFleetState::Committing, integration.status(0).fleetState);
}

// LeaseNegotiation must obey OtaLeaseStateMachine's own transition table
// rather than unconditionally granting/advancing on receipt of any
// LeaseNegotiation-typed frame: a Deny (or any subtype illegal for the
// current phase) must never move the lease into Active.
TEST(LoraOtaIntegration, LeaseNegotiationRequiresValidStateTransitions) {
  mesh::ota::OtaFirmwareIntegration integration;
  uint8_t frame[192] = {};
  size_t frame_len = 0;

  auto sendLease = [&](OtaLeaseSubtype subtype) -> bool {
    OtaLeaseNegotiationPayload negotiation;
    negotiation.subtype = subtype;
    negotiation.leaseId = 1;
    negotiation.durationMs = 60000;
    negotiation.radioProfileId = 0;
    uint8_t payload[kOtaLeaseNegotiationPayloadSize] = {};
    size_t len = 0;
    if (!encodeOtaLeaseNegotiation(negotiation, payload, sizeof(payload), len)) return false;
    if (!encodeFrame(OtaMessageType::LeaseNegotiation, payload, len, frame, sizeof(frame), frame_len)) return false;
    return integration.handleReceivedFrame(frame, frame_len);
  };

  // Grant is illegal before any Request: must not move to Active.
  EXPECT_FALSE(sendLease(OtaLeaseSubtype::Grant));
  EXPECT_EQ(OtaLeaseState::Normal, integration.status(0).leaseState);

  EXPECT_TRUE(sendLease(OtaLeaseSubtype::Request));
  EXPECT_EQ(OtaLeaseState::Requesting, integration.status(0).leaseState);

  // Deny while Requesting is legal and must restore Normal, not Active.
  EXPECT_TRUE(sendLease(OtaLeaseSubtype::Deny));
  EXPECT_EQ(OtaLeaseState::Normal, integration.status(0).leaseState);

  // A fresh Request followed by a valid Grant reaches Active.
  EXPECT_TRUE(sendLease(OtaLeaseSubtype::Request));
  EXPECT_TRUE(sendLease(OtaLeaseSubtype::Grant));
  EXPECT_EQ(OtaLeaseState::Active, integration.status(0).leaseState);

  // Release while Active is legal and restores Normal.
  EXPECT_TRUE(sendLease(OtaLeaseSubtype::Release));
  EXPECT_EQ(OtaLeaseState::Normal, integration.status(0).leaseState);
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

TEST(LoraOtaIntegration, BudgetGatedRequeuePreservesOriginalNonOtaPriority) {
  FakeClock clock;
  FakeRadio radio;
  radio.airtime = 2000;  // exceeds the 10 ms budget below on every attempt
  QueuePacketManager manager;
  TinyGeneralBudgetTestDispatcher dispatcher(radio, clock, manager);
  dispatcher.begin();  // tx_budget_ms starts at 3000ms * 0.5 duty_cycle = 1500ms

  Packet* normal = manager.allocNew();
  ASSERT_NE(nullptr, normal);
  normal->header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
  normal->path_len = 0;
  normal->payload_len = 1;
  normal->payload[0] = 0x42;
  const uint8_t kOriginalPriority = 0;  // e.g. a direct/high-priority send
  dispatcher.sendPacket(normal, kOriginalPriority);

  clock.advance(1);
  dispatcher.loop();
  EXPECT_EQ(0, radio.sends) << "packet must be budget-gated, not sent";
  ASSERT_EQ(1, manager.getOutboundTotal());
  EXPECT_EQ(kOriginalPriority, manager.outbound[0].priority)
      << "budget-gated requeue must preserve the packet's original queue "
         "priority instead of collapsing every non-OTA packet to priority 1";
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

TEST(LoraOtaIntegration, PacketPoolReservesBuffersForNonOtaPathsOverOtaBulkAlloc) {
  // Pool of 6 with a reserve of 4 (StaticPoolPacketManager::kOtaAllocReserve):
  // once only the reserve remains free, OTA bulk allocation (is_ota_bulk=true,
  // used by Mesh::createOtaData()) must fail closed so the ordinary sender /
  // raw radio ingress / delayed-RX / relay paths (is_ota_bulk=false, the
  // default) always have those last buffers available to them.
  StaticPoolPacketManager manager(6);
  ASSERT_EQ(6, manager.getFreeCount());

  Packet* held_a = manager.allocNew(false);
  Packet* held_b = manager.allocNew(false);
  ASSERT_NE(nullptr, held_a);
  ASSERT_NE(nullptr, held_b);
  ASSERT_EQ(4, manager.getFreeCount());

  EXPECT_EQ(nullptr, manager.allocNew(true))
      << "OTA bulk allocation must fail closed at/below the reserve";
  EXPECT_EQ(4, manager.getFreeCount()) << "a failed OTA alloc must not consume a buffer";

  Packet* non_ota = manager.allocNew(false);
  EXPECT_NE(nullptr, non_ota)
      << "non-OTA paths (sender/raw-ingress/delayed-RX/relay) must still be able to allocate";

  manager.free(held_a);
  manager.free(held_b);
  if (non_ota) manager.free(non_ota);
}

TEST(LoraOtaIntegration, PacketPoolAllowsOtaBulkAllocAboveReserve) {
  StaticPoolPacketManager manager(6);
  Packet* ota = manager.allocNew(true);
  EXPECT_NE(nullptr, ota) << "OTA alloc must still succeed while comfortably above the reserve";
  if (ota) manager.free(ota);
}

TEST(LoraOtaIntegration, RawPacketInjectionReleasesOtaPacketAtReserveInsteadOfQueueing) {
  // Reproduces the physical finding: CMD_SEND_RAW_PACKET allocates via
  // allocNew(false) (default) because the payload type isn't known until
  // after parsing, so allocNew()'s own is_ota_bulk reserve check never
  // fires for this path -- OTA traffic injected this way could otherwise
  // consume the whole pool, including the reserve, starving even
  // CMD_SEND_SELF_ADVERT's own allocation. The fix re-checks post-parse
  // using mesh::ota::exceedsOtaAllocReserveAfterParse() and releases
  // (rather than queues) the packet under the same condition already
  // enforced at OTA's own bulk allocation / raw radio ingress / relay.
  StaticPoolPacketManager manager(6);
  Packet* held_a = manager.allocNew(false);
  Packet* held_b = manager.allocNew(false);
  ASSERT_NE(nullptr, held_a);
  ASSERT_NE(nullptr, held_b);
  ASSERT_EQ(4, manager.getFreeCount());

  // Simulate CMD_SEND_RAW_PACKET: allocate (default, non-OTA-aware), then
  // parse -- this parse reveals the packet is actually OTA traffic.
  Packet* pkt = manager.allocNew();
  ASSERT_NE(nullptr, pkt) << "allocNew(false) must still succeed at the reserve boundary";
  ASSERT_EQ(3, manager.getFreeCount());
  fillOtaChunkPayload(pkt);

  EXPECT_TRUE(mesh::ota::exceedsOtaAllocReserveAfterParse(pkt, manager.getFreeCount(),
                                                           PacketManager::kOtaAllocReserve))
      << "an OTA-typed packet must be flagged for release once free count is at/below the reserve";

  manager.free(pkt);  // caller must release (not queue) once flagged
  EXPECT_EQ(4, manager.getFreeCount()) << "the released packet's buffer must return to the pool";

  manager.free(held_a);
  manager.free(held_b);
}

TEST(LoraOtaIntegration, RawPacketInjectionAllowsOtaPacketAboveReserveAndNonOtaAtReserve) {
  StaticPoolPacketManager manager(8);
  Packet* held_a = manager.allocNew(false);
  Packet* held_b = manager.allocNew(false);
  ASSERT_NE(nullptr, held_a);
  ASSERT_NE(nullptr, held_b);
  ASSERT_EQ(6, manager.getFreeCount());

  // An OTA-typed packet comfortably above the reserve must not be flagged.
  Packet* ota_above_reserve = manager.allocNew();
  ASSERT_NE(nullptr, ota_above_reserve);
  ASSERT_EQ(5, manager.getFreeCount());
  fillOtaChunkPayload(ota_above_reserve);
  EXPECT_FALSE(mesh::ota::exceedsOtaAllocReserveAfterParse(
      ota_above_reserve, manager.getFreeCount(), PacketManager::kOtaAllocReserve))
      << "an OTA-typed packet must be allowed to queue while comfortably above the reserve";
  manager.free(ota_above_reserve);

  // A non-OTA packet at/below the reserve must never be flagged: the
  // reserve only ever applies to OTA traffic.
  Packet* extra_a = manager.allocNew();
  Packet* extra_b = manager.allocNew();
  Packet* extra_c = manager.allocNew();
  Packet* extra_d = manager.allocNew();
  ASSERT_NE(nullptr, extra_a);
  ASSERT_NE(nullptr, extra_b);
  ASSERT_NE(nullptr, extra_c);
  ASSERT_NE(nullptr, extra_d);
  ASSERT_EQ(2, manager.getFreeCount());
  extra_a->header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
  EXPECT_FALSE(mesh::ota::exceedsOtaAllocReserveAfterParse(extra_a, manager.getFreeCount(),
                                                            PacketManager::kOtaAllocReserve))
      << "a non-OTA packet must never be released under the OTA-only reserve check";

  manager.free(held_a);
  manager.free(held_b);
  manager.free(extra_a);
  manager.free(extra_b);
  manager.free(extra_c);
  manager.free(extra_d);
}

TEST(LoraOtaIntegration, DispatcherDropsInboundOtaPacketAtIngressWhenPoolAtReserve) {
  // Reproduces the physical finding: sustained incoming OTA traffic must
  // never be allowed to consume buffers down past the shared reserve, or
  // ordinary allocations (e.g. CMD_SEND_SELF_ADVERT) starve. Raw ingress
  // can't know payload type before allocating, so the check happens right
  // after parse, in Dispatcher::checkRecv(), before any further routing.
  FakeClock clock;
  ScriptedRawRadio radio;
  QueuePacketManager manager;  // pool of 8, shared reserve is 4
  CountingRecvDispatcher dispatcher(radio, clock, manager);
  dispatcher.begin();

  Packet* held[4];
  for (int i = 0; i < 4; ++i) {
    held[i] = manager.allocNew(false);
    ASSERT_NE(nullptr, held[i]);
  }
  ASSERT_EQ(4, manager.getFreeCount());

  uint8_t header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_LORA_OTA << PH_TYPE_SHIFT);
  uint8_t raw[3] = { header, 0 /*path_len*/, 0xAA /*payload*/ };
  radio.next_raw = raw;
  radio.next_len = sizeof(raw);

  clock.advance(1);
  dispatcher.loop();

  EXPECT_EQ(0, dispatcher.recv_calls)
      << "an incoming OTA packet must be dropped before reaching onRecvPacket "
         "once the pool is at/below the ordinary-traffic reserve";
  EXPECT_EQ(4, manager.getFreeCount())
      << "the dropped OTA packet's buffer must be returned to the pool immediately";

  for (int i = 0; i < 4; ++i) manager.free(held[i]);
}

TEST(LoraOtaIntegration, DispatcherStillAcceptsInboundNonOtaPacketWhenPoolAtReserve) {
  // The reserve must only ever gate OTA traffic; ordinary ingress (e.g. a
  // text message or advert relay) must still be accepted even while the
  // pool sits exactly at the reserve threshold.
  FakeClock clock;
  ScriptedRawRadio radio;
  QueuePacketManager manager;
  CountingRecvDispatcher dispatcher(radio, clock, manager);
  dispatcher.begin();

  Packet* held[4];
  for (int i = 0; i < 4; ++i) {
    held[i] = manager.allocNew(false);
    ASSERT_NE(nullptr, held[i]);
  }
  ASSERT_EQ(4, manager.getFreeCount());

  uint8_t header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
  uint8_t raw[3] = { header, 0, 0x42 };
  radio.next_raw = raw;
  radio.next_len = sizeof(raw);

  clock.advance(1);
  dispatcher.loop();

  EXPECT_EQ(1, dispatcher.recv_calls)
      << "ordinary (non-OTA) inbound traffic must never be dropped by the OTA reserve";
  EXPECT_EQ(4, manager.getFreeCount())
      << "the ordinary packet was consumed then released (ACTION_RELEASE), back to the reserve level";

  for (int i = 0; i < 4; ++i) manager.free(held[i]);
}

TEST(LoraOtaIntegration, DispatcherDropsRelayedOtaPacketWhenPoolAtReserve) {
  // Reproduces the "queued OTA stayed blocked 15+15s" finding: an OTA
  // packet that already made it past ingress (e.g. delivered via the
  // delayed-RX queue while the pool was still healthy) must not be queued
  // for relay/retransmit if doing so would hold its buffer, for a
  // duty-budget-gated duration, below the ordinary-traffic reserve.
  FakeClock clock;
  FakeRadio radio;
  QueuePacketManager manager;
  AlwaysRetransmitDispatcher dispatcher(radio, clock, manager);
  dispatcher.begin();

  Packet* held[4];
  for (int i = 0; i < 4; ++i) {
    held[i] = manager.allocNew(false);
    ASSERT_NE(nullptr, held[i]);
  }
  ASSERT_EQ(4, manager.getFreeCount());

  Packet* ota = manager.allocNew(false);
  ASSERT_NE(nullptr, ota);
  fillOtaChunkPayload(ota);
  ASSERT_EQ(3, manager.getFreeCount());

  // Simulate the packet having already been accepted into the delayed-RX
  // queue while the pool was healthy, then dequeued for processing now that
  // the pool is under pressure (processRecvPacket() is private, so drive it
  // via the same public loop() -> getNextInbound() -> processRecvPacket()
  // path Dispatcher itself uses).
  manager.queueInbound(ota, clock.getMillis());
  dispatcher.loop();

  EXPECT_EQ(0, manager.getOutboundTotal())
      << "an OTA relay must not be queued when the pool is at/below the reserve";
  EXPECT_EQ(4, manager.getFreeCount())
      << "the dropped relay packet's buffer must be freed back to the pool, not held";

  for (int i = 0; i < 4; ++i) manager.free(held[i]);
}

TEST(LoraOtaIntegration, DispatcherStillRelaysNonOtaPacketWhenPoolAtReserve) {
  // The relay-side reserve check must only ever gate OTA traffic; an
  // ordinary relay (e.g. forwarding a flood advert) must still be queued
  // for retransmit even while the pool sits exactly at the reserve.
  FakeClock clock;
  FakeRadio radio;
  radio.airtime = 5000000;  // huge, so checkSend()'s duty-budget precheck blocks any
                            // immediate send, keeping the packet queued for the assertion below
  QueuePacketManager manager;
  AlwaysRetransmitDispatcher dispatcher(radio, clock, manager);
  dispatcher.begin();

  Packet* held[4];
  for (int i = 0; i < 4; ++i) {
    held[i] = manager.allocNew(false);
    ASSERT_NE(nullptr, held[i]);
  }
  ASSERT_EQ(4, manager.getFreeCount());

  Packet* normal = manager.allocNew(false);
  ASSERT_NE(nullptr, normal);
  normal->header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
  normal->path_len = 0;
  normal->payload_len = 1;
  normal->payload[0] = 0x42;

  manager.queueInbound(normal, clock.getMillis());
  dispatcher.loop();

  EXPECT_EQ(1, manager.getOutboundTotal())
      << "ordinary (non-OTA) relays must never be dropped by the OTA reserve";

  for (int i = 0; i < 4; ++i) manager.free(held[i]);
}

// Filling the outbound send queue must not let sendPacket()/sendFlood()
// silently report success: queueOutbound() drops (and frees) a packet
// that can't fit, and that failure must now be visible to the caller --
// see Dispatcher::sendPacket()/Mesh::sendFlood() return values, added to
// address a physically-reported "no UART error, but the packet never
// actually reached the queue" gap (CMD_OTA_LAB normal-first probe).
TEST(LoraOtaIntegration, SendPacketReturnsFalseAndFreesPacketWhenQueueFull) {
  FakeClock clock;
  FakeRadio radio;
  QueuePacketManager manager;
  TestDispatcher dispatcher(radio, clock, manager);
  dispatcher.begin();

  // Fill the outbound queue to capacity using packets that are NOT drawn
  // from the manager's own pool (so the pool itself stays available and
  // this test isolates queue-capacity exhaustion from pool exhaustion).
  Packet filler[8];
  for (int i = 0; i < 8; ++i) {
    filler[i].header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
    filler[i].path_len = 0;
    filler[i].payload_len = 1;
    filler[i].payload[0] = 0x11;
    ASSERT_TRUE(manager.queueOutbound(&filler[i], 1, 0));
  }
  ASSERT_EQ(8, manager.getOutboundTotal());

  Packet* extra = manager.allocNew();
  ASSERT_NE(nullptr, extra);
  extra->header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
  extra->path_len = 0;
  extra->payload_len = 1;
  extra->payload[0] = 0x22;

  EXPECT_FALSE(dispatcher.sendPacket(extra, 1))
      << "sendPacket() must report failure when the send queue has no room, "
         "not silently swallow the drop";
  EXPECT_EQ(8, manager.getOutboundTotal())
      << "the dropped packet must not have been added to the queue";

  // The dropped packet must have been freed back to the pool, not leaked.
  Packet* reused = manager.allocNew();
  EXPECT_EQ(extra, reused)
      << "the packet dropped by the full queue must be returned to the free pool";
}

// ---------------------------------------------------------------------
// OtaLeanReceiver: the real signed-block RF/USB receiver, exercised
// end-to-end through OtaFirmwareIntegration + the real production
// OtaFirmwareTrustProvider/OtaFirmwareStorageSink/OtaCandidateStore (not
// a hand-rolled test double), matching the KISS lean trust design:
// owner-signed manifest admission, per-block signed-frame verification,
// durable Ready/Commit/Abort with exact target binding.
// ---------------------------------------------------------------------
namespace {

struct LeanAdminRegistry {
  uint8_t keys[4][32] = {};
  int count = 0;
  void add(const uint8_t key[32]) { std::memcpy(keys[count++], key, 32); }
  bool isAdmin(const uint8_t key[32]) const {
    for (int i = 0; i < count; ++i) {
      if (std::memcmp(keys[i], key, 32) == 0) return true;
    }
    return false;
  }
};

bool leanAdminCheckThunk(void* ctx, const uint8_t key[32]) {
  return static_cast<const LeanAdminRegistry*>(ctx)->isAdmin(key);
}

// buildProtocolDescriptor() always emits boardFamily=0x1001/boardVariant=
// 0x0002, so the resulting target_id is fixed and known in advance; this
// MUST be baked into the anchor before DescriptorVerifier is constructed
// below -- DescriptorVerifier copies DeviceTrustAnchor BY VALUE at
// construction (see DescriptorVerifier.h `DeviceTrustAnchor anchor_;`),
// so any field set only in a constructor BODY (which runs after all
// member initializers) is invisible to it.
::ota::trust::DeviceTrustAnchor makeLeanTrustAnchor() {
  ::ota::trust::DeviceTrustAnchor anchor;
  anchor.expected_target_id = (0x1001u << 16) | 0x0002u;
  anchor.expected_role_id = 7;
  anchor.expected_format_id = 1;
  anchor.expected_key_id = 1;
  anchor.expected_algorithm_id = 1;
  anchor.supported_boot_capability_flags = 0x0000000Fu;
  return anchor;
}

bool leanNoTrial() { return false; }

// Bundles every real collaborator OtaLeanReceiver needs so each test can
// drive begin()/putBlock()/requestSeal()/loop()/commit()/abort() against
// genuine flash-backed storage and genuine Ed25519 verification.
struct LeanFixture {
  ::ota::test::FakeNorFlash image_flash{786432, 4096};
  ::ota::platform::FlashRegion image_region{image_flash, 0, 786432};
  ::ota::test::FakeNorFlash candidate_flash{::ota::storage::OtaCandidateStore::kExpectedRegionBytes,
                                            ::ota::storage::OtaCandidateStore::kSectorBytes};
  ::ota::platform::FlashRegion candidate_store_region{candidate_flash, 0,
                                                      ::ota::storage::OtaCandidateStore::kExpectedRegionBytes};
  ::ota::storage::OtaCandidateStore candidate_store{candidate_store_region};
  ::ota::test::FakeMonotonicCounter counter{0};
  ::ota::trust::Sha256 hasher;
  ::ota::trust::Ed25519SignatureVerifier sig_verifier;
  ::ota::trust::DeviceTrustAnchor anchor = makeLeanTrustAnchor();
  ::ota::trust::DescriptorVerifier verifier{hasher, sig_verifier, counter, anchor};
  mesh::ota::OtaFirmwareTrustProvider trust{verifier, image_region};
  mesh::ota::OtaFirmwareStorageSink staging{image_region};
  mesh::ota::OtaBoardTrialGuardedStagingSink guarded{staging, &leanNoTrial};
  LeanAdminRegistry admins;
  mesh::ota::OtaFirmwareIntegration integration;
  uint8_t target_public_key[32] = {};

  LeanFixture() {
    for (size_t i = 0; i < sizeof(target_public_key); ++i) target_public_key[i] = static_cast<uint8_t>(0xD0u + i);
    integration.attachTrustProvider(&trust);
    integration.attachStagingSink(&guarded);
    integration.attachCandidateStore(&candidate_store);
    integration.attachLeanSignatureVerifier(&sig_verifier);
    integration.setLeanAdminCheck(&admins, &leanAdminCheckThunk);
    integration.setLeanTargetPublicKey(target_public_key);
  }

  // Builds a small (<=84 byte, single-block) image descriptor + its
  // canonical59 bytes, matching the anchor's policy fields so
  // verifyDescriptorPolicyOnly() passes.
  void buildSmallManifest(const uint8_t* image, size_t image_len,
                          uint8_t out_canonical[mesh::ota::kOtaCanonicalManifestBytes],
                          uint32_t security_counter = 5) {
    OtaDescriptor descriptor = buildProtocolDescriptor(image, image_len, security_counter);
    size_t canonical_len = 0;
    ASSERT_EQ(OtaDescriptorCodecResult::Ok,
              encodeOtaDescriptorCanonical(descriptor, out_canonical, mesh::ota::kOtaCanonicalManifestBytes, canonical_len));
    ASSERT_EQ(static_cast<size_t>(mesh::ota::kOtaCanonicalManifestBytes), canonical_len);
  }
};

}  // namespace

TEST(LoraOtaLeanReceiver, NrfApplicationCeilingRejectsOneByteOverBeforeEraseButDoesNotLimitLocalCache) {
  using Result = mesh::ota::OtaLeanReceiver::Result;
  LeanFixture fx;
  mesh::ota::OtaNrf52FirmwareTrustProvider trust(fx.verifier, fx.image_region);
  fx.integration.attachTrustProvider(&trust);
  uint8_t seed[32] = {0x75};
  ::ota::test::Ed25519TestSigner owner(seed);
  fx.admins.add(owner.publicKey());
  const uint8_t image[1] = {0x48};
  auto descriptor = buildProtocolDescriptor(image, sizeof(image), 5);
  const auto maximum = mesh::ota::OtaNrf52FirmwareTrustProvider::kMaximumImageBytes;
  descriptor.exactSizeBytes = maximum;
  EXPECT_TRUE(trust.verifyDescriptorPolicyOnly(descriptor));
  descriptor.exactSizeBytes = maximum + 1u;
  EXPECT_FALSE(trust.verifyDescriptorPolicyOnly(descriptor));
  uint8_t canonical[59], signature[64];
  size_t canonical_len = 0;
  ASSERT_EQ(OtaDescriptorCodecResult::Ok,
            encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), canonical_len));
  owner.sign(canonical, sizeof(canonical), signature);
  auto& receiver = fx.integration.leanReceiver();
  const auto image_erases = fx.image_flash.eraseOpCount();
  EXPECT_EQ(Result::Denied, receiver.begin(owner.publicKey(), canonical, signature, false, false));
  EXPECT_EQ(image_erases, fx.image_flash.eraseOpCount());
  EXPECT_FALSE(receiver.status().valid);
  ASSERT_EQ(Result::Ok, receiver.begin(owner.publicKey(), canonical, signature, false, false, true));
  EXPECT_TRUE(receiver.status().localCache);
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Receiving, receiver.status().phase);
}

TEST(LoraOtaLeanReceiver, BeginAcceptsOwnerSignedManifestFromRegisteredAdminAndRejectsUnknownSigner) {
  LeanFixture fx;
  uint8_t owner_seed[32] = {};
  for (size_t i = 0; i < sizeof(owner_seed); ++i) owner_seed[i] = static_cast<uint8_t>(0x10u + i);
  ::ota::test::Ed25519TestSigner owner(owner_seed);
  fx.admins.add(owner.publicKey());

  uint8_t image[40] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(i);
  uint8_t canonical[mesh::ota::kOtaCanonicalManifestBytes] = {};
  fx.buildSmallManifest(image, sizeof(image), canonical);
  uint8_t signature[64] = {};
  owner.sign(canonical, sizeof(canonical), signature);

  auto& lean = fx.integration.leanReceiver();
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok,
            lean.begin(owner.publicKey(), canonical, signature, /*reupload=*/false, /*local_owner_trusted=*/false));
  EXPECT_TRUE(lean.status().valid);

  // An unknown (non-admin) signer producing a perfectly valid signature
  // over a DIFFERENT manifest must still be rejected -- being able to
  // sign is not the same as being a currently-trusted admin.
  uint8_t stranger_seed[32] = {};
  for (size_t i = 0; i < sizeof(stranger_seed); ++i) stranger_seed[i] = static_cast<uint8_t>(0x90u + i);
  ::ota::test::Ed25519TestSigner stranger(stranger_seed);
  uint8_t image2[40] = {};
  for (size_t i = 0; i < sizeof(image2); ++i) image2[i] = static_cast<uint8_t>(0x55u + i);
  uint8_t canonical2[mesh::ota::kOtaCanonicalManifestBytes] = {};
  fx.buildSmallManifest(image2, sizeof(image2), canonical2, /*security_counter=*/6);
  uint8_t signature2[64] = {};
  stranger.sign(canonical2, sizeof(canonical2), signature2);
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Denied,
            lean.begin(stranger.publicKey(), canonical2, signature2, false, false));
}

TEST(LoraOtaLeanReceiver, DuplicateBeginSameOwnerSameManifestIsIdempotentAndNeverErasesProgress) {
  LeanFixture fx;
  uint8_t owner_seed[32] = {};
  for (size_t i = 0; i < sizeof(owner_seed); ++i) owner_seed[i] = static_cast<uint8_t>(0x20u + i);
  ::ota::test::Ed25519TestSigner owner(owner_seed);
  fx.admins.add(owner.publicKey());

  uint8_t image[40] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(i + 1);
  uint8_t canonical[mesh::ota::kOtaCanonicalManifestBytes] = {};
  fx.buildSmallManifest(image, sizeof(image), canonical);
  uint8_t signature[64] = {};
  owner.sign(canonical, sizeof(canonical), signature);

  auto& lean = fx.integration.leanReceiver();
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.begin(owner.publicKey(), canonical, signature, false, false));
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.putBlock(0, image, sizeof(image)));
  EXPECT_EQ(1, lean.status().receivedBlocks);

  // Re-issuing the IDENTICAL CacheBegin (same owner, same manifest, no
  // reupload flag) must be a no-op that preserves the already-received
  // block, not a fresh admission that erases progress.
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.begin(owner.publicKey(), canonical, signature, false, false));
  EXPECT_EQ(1, lean.status().receivedBlocks);
}

TEST(LoraOtaLeanReceiver, CompetingManifestFromDifferentAdminIsBusyUnlessReuploadRequested) {
  LeanFixture fx;
  uint8_t owner_seed[32] = {};
  for (size_t i = 0; i < sizeof(owner_seed); ++i) owner_seed[i] = static_cast<uint8_t>(0x30u + i);
  ::ota::test::Ed25519TestSigner owner(owner_seed);
  uint8_t other_admin_seed[32] = {};
  for (size_t i = 0; i < sizeof(other_admin_seed); ++i) other_admin_seed[i] = static_cast<uint8_t>(0x40u + i);
  ::ota::test::Ed25519TestSigner other_admin(other_admin_seed);
  fx.admins.add(owner.publicKey());
  fx.admins.add(other_admin.publicKey());

  uint8_t image[40] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(i + 2);
  uint8_t canonical[mesh::ota::kOtaCanonicalManifestBytes] = {};
  fx.buildSmallManifest(image, sizeof(image), canonical, 5);
  uint8_t signature[64] = {};
  owner.sign(canonical, sizeof(canonical), signature);
  auto& lean = fx.integration.leanReceiver();
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.begin(owner.publicKey(), canonical, signature, false, false));

  uint8_t image2[40] = {};
  for (size_t i = 0; i < sizeof(image2); ++i) image2[i] = static_cast<uint8_t>(0x70u + i);
  uint8_t canonical2[mesh::ota::kOtaCanonicalManifestBytes] = {};
  fx.buildSmallManifest(image2, sizeof(image2), canonical2, 6);
  uint8_t signature2[64] = {};
  other_admin.sign(canonical2, sizeof(canonical2), signature2);

  // A different admin's different manifest while the first is still
  // active must be refused as Busy -- no silent takeover.
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Busy,
            lean.begin(other_admin.publicKey(), canonical2, signature2, false, false));

  // The explicit REUPLOAD flag is required to discard the active
  // candidate and admit the new one.
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok,
            lean.begin(other_admin.publicKey(), canonical2, signature2, /*reupload=*/true, false));
}

TEST(LoraOtaLeanReceiver, SignedBlockFrameRejectsForeignSignatureAndWrongManifestTagHarmlessly) {
  LeanFixture fx;
  uint8_t owner_seed[32] = {};
  for (size_t i = 0; i < sizeof(owner_seed); ++i) owner_seed[i] = static_cast<uint8_t>(0x50u + i);
  ::ota::test::Ed25519TestSigner owner(owner_seed);
  fx.admins.add(owner.publicKey());

  uint8_t image[40] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(i + 3);
  uint8_t canonical[mesh::ota::kOtaCanonicalManifestBytes] = {};
  fx.buildSmallManifest(image, sizeof(image), canonical);
  uint8_t signature[64] = {};
  owner.sign(canonical, sizeof(canonical), signature);
  auto& lean = fx.integration.leanReceiver();
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.begin(owner.publicKey(), canonical, signature, false, false));

  uint8_t manifest_hash[32] = {};
  mesh::ota::computeOtaManifestHash(canonical, manifest_hash);

  // A block correctly signed by a STRANGER (not the candidate's owner)
  // must be rejected, even with a correct manifest tag/index/data.
  uint8_t stranger_seed[32] = {};
  for (size_t i = 0; i < sizeof(stranger_seed); ++i) stranger_seed[i] = static_cast<uint8_t>(0xA0u + i);
  ::ota::test::Ed25519TestSigner stranger(stranger_seed);
  uint8_t message[mesh::ota::kOtaBlockSignedMessageMaxBytes] = {};
  const size_t message_len = mesh::ota::buildOtaBlockSignedMessage(manifest_hash, mesh::ota::kOtaSignedBlockKind, 0,
                                                                   image, sizeof(image), message);
  uint8_t forged_signature[64] = {};
  stranger.sign(message, message_len, forged_signature);
  uint8_t frame[256] = {};
  size_t frame_len = 0;
  ASSERT_TRUE(mesh::ota::encodeOtaSignedBlockFrame(mesh::ota::kOtaSignedBlockKind, manifest_hash, 0, image,
                                                   sizeof(image), forged_signature, frame, sizeof(frame), frame_len));
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Denied, lean.handleSignedBlockFrame(frame, frame_len));
  EXPECT_EQ(0, lean.status().receivedBlocks) << "a rejected foreign-signed block must not advance progress";

  // A block with the WRONG manifest tag (e.g. stale/foreign campaign)
  // must be rejected as Mismatch without touching state, even if its
  // signature is otherwise validly produced by the real owner over a
  // self-consistent (but irrelevant) message.
  uint8_t wrong_tag_hash[32] = {};
  for (size_t i = 0; i < sizeof(wrong_tag_hash); ++i) wrong_tag_hash[i] = static_cast<uint8_t>(0xEE);
  uint8_t message3[mesh::ota::kOtaBlockSignedMessageMaxBytes] = {};
  const size_t message3_len = mesh::ota::buildOtaBlockSignedMessage(wrong_tag_hash, mesh::ota::kOtaSignedBlockKind, 0,
                                                                    image, sizeof(image), message3);
  uint8_t signature3[64] = {};
  owner.sign(message3, message3_len, signature3);
  uint8_t frame3[256] = {};
  size_t frame3_len = 0;
  ASSERT_TRUE(mesh::ota::encodeOtaSignedBlockFrame(mesh::ota::kOtaSignedBlockKind, wrong_tag_hash, 0, image,
                                                   sizeof(image), signature3, frame3, sizeof(frame3), frame3_len));
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Mismatch, lean.handleSignedBlockFrame(frame3, frame3_len));
  EXPECT_EQ(0, lean.status().receivedBlocks);

  // A genuinely owner-signed, correctly-tagged block is accepted, and a
  // byte-identical duplicate resend is a harmless no-op (not a rewrite,
  // not a progress regression, not an error).
  uint8_t good_signature[64] = {};
  owner.sign(message, message_len, good_signature);
  uint8_t good_frame[256] = {};
  size_t good_frame_len = 0;
  ASSERT_TRUE(mesh::ota::encodeOtaSignedBlockFrame(mesh::ota::kOtaSignedBlockKind, manifest_hash, 0, image,
                                                   sizeof(image), good_signature, good_frame, sizeof(good_frame), good_frame_len));
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.handleSignedBlockFrame(good_frame, good_frame_len));
  EXPECT_EQ(1, lean.status().receivedBlocks);
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.handleSignedBlockFrame(good_frame, good_frame_len));
  EXPECT_EQ(1, lean.status().receivedBlocks) << "a duplicate already-received block must be idempotent, not rewritten";
}

TEST(LoraOtaLeanReceiver, SealReachesReadyThenCommitRequiresExactOwnerAndExactTargetBindingAndAbortRequiresOnlyCurrentAdmin) {
  LeanFixture fx;
  uint8_t owner_seed[32] = {};
  for (size_t i = 0; i < sizeof(owner_seed); ++i) owner_seed[i] = static_cast<uint8_t>(0x60u + i);
  ::ota::test::Ed25519TestSigner owner(owner_seed);
  uint8_t admin2_seed[32] = {};
  for (size_t i = 0; i < sizeof(admin2_seed); ++i) admin2_seed[i] = static_cast<uint8_t>(0x65u + i);
  ::ota::test::Ed25519TestSigner admin2(admin2_seed);  // a different, currently-trusted admin (not the owner)
  fx.admins.add(owner.publicKey());
  fx.admins.add(admin2.publicKey());

  uint8_t image[40] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(i + 4);
  uint8_t canonical[mesh::ota::kOtaCanonicalManifestBytes] = {};
  fx.buildSmallManifest(image, sizeof(image), canonical);
  uint8_t signature[64] = {};
  owner.sign(canonical, sizeof(canonical), signature);
  auto& lean = fx.integration.leanReceiver();
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.begin(owner.publicKey(), canonical, signature, false, false));
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.putBlock(0, image, sizeof(image)));
  // Seal must also actually write the real bytes into the staging flash
  // region for verifyStagedImageHashPolicyOnly()'s image-hash recompute
  // to succeed -- use the real staging sink the fixture wired in.
  ASSERT_EQ(meshcore::ota::runtime::IOtaStagingSink::Result::Ok, fx.staging.writeChunk(0, image, sizeof(image)));

  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Pending, lean.requestSeal());
  fx.integration.loop();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, lean.status().phase)
      << "a genuinely complete, hash-matching, owner-signed candidate must reach durable Ready "
         "(this is the lean-path verifyStagedImageHashPolicyOnly() wiring, not the legacy "
         "compiled-anchor descriptor_verified_ gate)";

  uint8_t manifest_hash[32] = {};
  mesh::ota::computeOtaManifestHash(canonical, manifest_hash);

  // COMMIT captured for a DIFFERENT target device must not commit THIS
  // device, even with the correct owner key/manifest/counter -- the
  // signed message binds the full target identity.
  uint8_t other_target[32] = {};
  for (size_t i = 0; i < sizeof(other_target); ++i) other_target[i] = static_cast<uint8_t>(0xFFu - i);
  uint8_t wrong_target_message[mesh::ota::usb::kCommitSignedBytes] = {};
  const size_t wrong_target_message_len =
      mesh::ota::usb::buildCommitSignedMessage(other_target, manifest_hash, 1u, wrong_target_message);
  uint8_t wrong_target_signature[64] = {};
  owner.sign(wrong_target_message, wrong_target_message_len, wrong_target_signature);
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Denied, lean.commit(1u, wrong_target_signature))
      << "a commit signature captured for a different target must be cryptographically incapable "
         "of committing this device";
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, lean.status().phase) << "a rejected commit must not advance phase";

  // ABORT authorized by admin2 (a CURRENT admin who is NOT the candidate's
  // owner) must still succeed -- ABORT only requires "any current admin",
  // unlike COMMIT's "exact owner" requirement.
  OtaDescriptor descriptor = buildProtocolDescriptor(image, sizeof(image), 5);
  uint8_t abort_message[mesh::ota::usb::kAbortSignedBytes] = {};
  const size_t abort_message_len =
      mesh::ota::usb::buildAbortSignedMessage(fx.target_public_key, descriptor.sha256, abort_message);
  uint8_t abort_signature[64] = {};
  admin2.sign(abort_message, abort_message_len, abort_signature);
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.abort(admin2.publicKey(), abort_signature, descriptor.sha256));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, lean.status().phase);

  // The CORRECT target-bound COMMIT, signed by the genuine owner, must
  // succeed when the candidate is Ready -- verified on a fresh candidate
  // since the previous one was just aborted.
  uint8_t image2[40] = {};
  for (size_t i = 0; i < sizeof(image2); ++i) image2[i] = static_cast<uint8_t>(i + 9);
  uint8_t canonical2[mesh::ota::kOtaCanonicalManifestBytes] = {};
  fx.buildSmallManifest(image2, sizeof(image2), canonical2, 6);
  uint8_t signature2[64] = {};
  owner.sign(canonical2, sizeof(canonical2), signature2);
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok,
            lean.begin(owner.publicKey(), canonical2, signature2, /*reupload=*/true, false));
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.putBlock(0, image2, sizeof(image2)));
  ASSERT_EQ(meshcore::ota::runtime::IOtaStagingSink::Result::Ok, fx.staging.writeChunk(0, image2, sizeof(image2)));
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Pending, lean.requestSeal());
  fx.integration.loop();
  ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, lean.status().phase);

  uint8_t manifest_hash2[32] = {};
  mesh::ota::computeOtaManifestHash(canonical2, manifest_hash2);
  uint8_t commit_message[mesh::ota::usb::kCommitSignedBytes] = {};
  const size_t commit_message_len =
      mesh::ota::usb::buildCommitSignedMessage(fx.target_public_key, manifest_hash2, 6u, commit_message);
  uint8_t commit_signature[64] = {};
  owner.sign(commit_message, commit_message_len, commit_signature);
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.commit(6u, commit_signature))
      << "an exact-target, exact-owner-signed commit over a genuinely Ready candidate must succeed";
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, lean.status().phase);
}

TEST(LoraOtaLeanReceiver, ReadyAppendFailureRetainsDurableVerifyingAndRetriesWithoutRewritingImage) {
  using Result = mesh::ota::OtaLeanReceiver::Result;
  for (const bool local_cache : {false, true}) {
    for (const uint32_t failed_write : {1u, 2u}) {
      SCOPED_TRACE(local_cache);
      SCOPED_TRACE(failed_write);
      LeanFixture fx;
      uint8_t seed[32] = {0x71};
      ::ota::test::Ed25519TestSigner owner(seed);
      fx.admins.add(owner.publicKey());
      uint8_t image[40] = {0x42}, canonical[59], signature[64];
      fx.buildSmallManifest(image, sizeof(image), canonical);
      owner.sign(canonical, sizeof(canonical), signature);
      auto& receiver = fx.integration.leanReceiver();
      ASSERT_EQ(Result::Ok,
                receiver.begin(owner.publicKey(), canonical, signature, false, false, local_cache));
      ASSERT_EQ(Result::Ok, receiver.putBlock(0, image, sizeof(image)));
      ASSERT_EQ(Result::Pending, receiver.requestSeal());
      const auto image_writes = fx.image_flash.programOpCount();
      const auto image_erases = fx.image_flash.eraseOpCount();
      using Flash = ::ota::test::FakeNorFlash;
      Flash::FaultSpec fault;
      fault.kind = Flash::OpKind::Program;
      fault.timing = Flash::InjectionTiming::Before;
      fault.trigger_op_count = fx.candidate_flash.programOpCount() + failed_write;
      fx.candidate_flash.armFault(fault);
      receiver.loop();
      EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Verifying, receiver.status().phase);
      ::ota::storage::OtaCandidateStore::Snapshot durable;
      ASSERT_TRUE(fx.candidate_store.load(durable));
      EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Verifying, durable.phase);
      EXPECT_EQ(1u, durable.receivedBlocks);
      fx.candidate_flash.clearFault();
      receiver.loop();
      ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, receiver.status().phase);
      ASSERT_TRUE(fx.candidate_store.load(durable));
      EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, durable.phase);
      EXPECT_EQ(local_cache, durable.localCache);
      EXPECT_EQ(0, std::memcmp(owner.publicKey(), durable.ownerPublicKey, 32));
      EXPECT_EQ(0, std::memcmp(canonical, durable.canonical, sizeof(canonical)));
      EXPECT_EQ(image_writes, fx.image_flash.programOpCount());
      EXPECT_EQ(image_erases, fx.image_flash.eraseOpCount());
    }
  }
}

TEST(LoraOtaLeanReceiver, VerifyingRebootResumesWithoutUnjournaledPhaseChangeOrMetadataWrite) {
  using Result = mesh::ota::OtaLeanReceiver::Result;
  LeanFixture fx;
  uint8_t seed[32] = {0x72};
  ::ota::test::Ed25519TestSigner owner(seed);
  fx.admins.add(owner.publicKey());
  uint8_t image[40] = {0x43}, canonical[59], signature[64];
  fx.buildSmallManifest(image, sizeof(image), canonical);
  owner.sign(canonical, sizeof(canonical), signature);
  auto& receiver = fx.integration.leanReceiver();
  ASSERT_EQ(Result::Ok, receiver.begin(owner.publicKey(), canonical, signature, false, false));
  ASSERT_EQ(Result::Ok, receiver.putBlock(0, image, sizeof(image)));
  ASSERT_EQ(Result::Pending, receiver.requestSeal());
  const auto metadata_writes = fx.candidate_flash.programOpCount();
  const auto image_writes = fx.image_flash.programOpCount();
  using Flash = ::ota::test::FakeNorFlash;
  Flash::FaultSpec fault;
  fault.kind = Flash::OpKind::Program;
  fault.timing = Flash::InjectionTiming::Before;
  fault.trigger_op_count = metadata_writes + 1;
  fx.candidate_flash.armFault(fault);
  mesh::ota::OtaLeanReceiver restarted;
  restarted.attachTrustProvider(&fx.trust);
  restarted.attachOwnerSignatureVerifier(&fx.sig_verifier);
  restarted.attachStagingSink(&fx.guarded);
  restarted.attachCandidateStore(&fx.candidate_store);
  restarted.setAdminCheck(&fx.admins, &leanAdminCheckThunk);
  restarted.setTargetPublicKey(fx.target_public_key);
  ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Verifying, restarted.status().phase);
  EXPECT_EQ(metadata_writes, fx.candidate_flash.programOpCount());
  restarted.loop();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Verifying, restarted.status().phase);
  fx.candidate_flash.clearFault();
  restarted.loop();
  ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, restarted.status().phase);
  ::ota::storage::OtaCandidateStore::Snapshot durable;
  ASSERT_TRUE(fx.candidate_store.load(durable));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, durable.phase);
  EXPECT_EQ(1u, durable.receivedBlocks);
  EXPECT_EQ(image_writes, fx.image_flash.programOpCount());
}

TEST(LoraOtaLeanReceiver, FailedSealAppendRetriesWithoutReportingAnUnjournaledFailure) {
  using Result = mesh::ota::OtaLeanReceiver::Result;
  LeanFixture fx;
  uint8_t seed[32] = {0x73};
  ::ota::test::Ed25519TestSigner owner(seed);
  fx.admins.add(owner.publicKey());
  uint8_t expected_image[40] = {0x44}, wrong_image[40] = {0x45}, canonical[59], signature[64];
  fx.buildSmallManifest(expected_image, sizeof(expected_image), canonical);
  owner.sign(canonical, sizeof(canonical), signature);
  auto& receiver = fx.integration.leanReceiver();
  ASSERT_EQ(Result::Ok, receiver.begin(owner.publicKey(), canonical, signature, false, false));
  ASSERT_EQ(Result::Ok, receiver.putBlock(0, wrong_image, sizeof(wrong_image)));
  ASSERT_EQ(Result::Pending, receiver.requestSeal());
  using Flash = ::ota::test::FakeNorFlash;
  Flash::FaultSpec fault;
  fault.kind = Flash::OpKind::Program;
  fault.timing = Flash::InjectionTiming::Before;
  fault.trigger_op_count = fx.candidate_flash.programOpCount() + 1;
  fx.candidate_flash.armFault(fault);
  receiver.loop();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Verifying, receiver.status().phase);
  ::ota::storage::OtaCandidateStore::Snapshot durable;
  ASSERT_TRUE(fx.candidate_store.load(durable));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Verifying, durable.phase);
  fx.candidate_flash.clearFault();
  receiver.loop();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Failed, receiver.status().phase);
  ASSERT_TRUE(fx.candidate_store.load(durable));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Failed, durable.phase);
}

TEST(LoraOtaLeanReceiver, ExplicitReuploadDoesNotVerifyAnIncompleteNewCandidateUsingOldSealWork) {
  using Result = mesh::ota::OtaLeanReceiver::Result;
  LeanFixture fx;
  uint8_t seed[32] = {0x74};
  ::ota::test::Ed25519TestSigner owner(seed);
  fx.admins.add(owner.publicKey());
  uint8_t image[40] = {0x46}, canonical[59], signature[64];
  fx.buildSmallManifest(image, sizeof(image), canonical);
  owner.sign(canonical, sizeof(canonical), signature);
  auto& receiver = fx.integration.leanReceiver();
  ASSERT_EQ(Result::Ok, receiver.begin(owner.publicKey(), canonical, signature, false, false));
  ASSERT_EQ(Result::Ok, receiver.putBlock(0, image, sizeof(image)));
  ASSERT_EQ(Result::Pending, receiver.requestSeal());
  image[0] = 0x47;
  fx.buildSmallManifest(image, sizeof(image), canonical, 6);
  owner.sign(canonical, sizeof(canonical), signature);
  ASSERT_EQ(Result::Ok, receiver.begin(owner.publicKey(), canonical, signature, true, false));
  receiver.loop();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Receiving, receiver.status().phase);
  EXPECT_EQ(0u, receiver.status().receivedBlocks);
  ::ota::storage::OtaCandidateStore::Snapshot durable;
  ASSERT_TRUE(fx.candidate_store.load(durable));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Receiving, durable.phase);
  ASSERT_EQ(Result::Ok, receiver.putBlock(0, image, sizeof(image)));
  ASSERT_EQ(Result::Pending, receiver.requestSeal());
  receiver.loop();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, receiver.status().phase);
}

TEST(LoraOtaRfFrames, AuthorizationFrameOverRfAdmitsOwnerSignedCandidateFromRegisteredAdmin) {
  LeanFixture fx;
  uint8_t owner_seed[32] = {};
  for (size_t i = 0; i < sizeof(owner_seed); ++i) owner_seed[i] = static_cast<uint8_t>(0x71u + i);
  ::ota::test::Ed25519TestSigner owner(owner_seed);
  fx.admins.add(owner.publicKey());

  uint8_t image[40] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(i + 11);
  uint8_t canonical[mesh::ota::kOtaCanonicalManifestBytes] = {};
  fx.buildSmallManifest(image, sizeof(image), canonical);
  uint8_t signature[64] = {};
  owner.sign(canonical, sizeof(canonical), signature);

  uint8_t frame[mesh::ota::kOtaAuthorizationFrameBytes] = {};
  const size_t frame_len =
      mesh::ota::encodeOtaAuthorizationFrame(owner.publicKey(), canonical, signature, frame, sizeof(frame));
  ASSERT_EQ(static_cast<size_t>(mesh::ota::kOtaAuthorizationFrameBytes), frame_len);

  // Fed purely through the real-mesh ingress point (no legacy envelope,
  // no USB) -- this is exactly what a pure RF-only receiver with no USB
  // uploader attached sees.
  EXPECT_TRUE(fx.integration.handleReceivedFrame(frame, frame_len, /*now_ms=*/1000));
  EXPECT_TRUE(fx.integration.leanReceiver().status().valid);
  EXPECT_EQ(0, std::memcmp(fx.integration.leanReceiver().status().ownerPublicKey, owner.publicKey(), 32));

  // A well-formed Authorization frame from an UNREGISTERED signer must be
  // rejected (Denied inside begin()) and therefore counted as a bad
  // frame, not silently admitted.
  uint8_t stranger_seed[32] = {};
  for (size_t i = 0; i < sizeof(stranger_seed); ++i) stranger_seed[i] = static_cast<uint8_t>(0xA1u + i);
  ::ota::test::Ed25519TestSigner stranger(stranger_seed);
  uint8_t image2[40] = {};
  for (size_t i = 0; i < sizeof(image2); ++i) image2[i] = static_cast<uint8_t>(0x33u + i);
  uint8_t canonical2[mesh::ota::kOtaCanonicalManifestBytes] = {};
  fx.buildSmallManifest(image2, sizeof(image2), canonical2, 6);
  uint8_t signature2[64] = {};
  stranger.sign(canonical2, sizeof(canonical2), signature2);
  uint8_t frame2[mesh::ota::kOtaAuthorizationFrameBytes] = {};
  const size_t frame2_len =
      mesh::ota::encodeOtaAuthorizationFrame(stranger.publicKey(), canonical2, signature2, frame2, sizeof(frame2));
  const auto status_before = fx.integration.status(1001);
  EXPECT_FALSE(fx.integration.handleReceivedFrame(frame2, frame2_len, 1001));
  EXPECT_EQ(status_before.badFrames + 1, fx.integration.status(1001).badFrames);
  // The already-admitted (first, legitimate) candidate must be untouched.
  EXPECT_EQ(0, std::memcmp(fx.integration.leanReceiver().status().ownerPublicKey, owner.publicKey(), 32));
}

TEST(LoraOtaRfFrames, CommitAndAbortFramesOverRfReuseSameTargetBindingAndAdminRulesAsUsb) {
  LeanFixture fx;
  uint8_t owner_seed[32] = {};
  for (size_t i = 0; i < sizeof(owner_seed); ++i) owner_seed[i] = static_cast<uint8_t>(0x72u + i);
  ::ota::test::Ed25519TestSigner owner(owner_seed);
  fx.admins.add(owner.publicKey());

  uint8_t image[40] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(i + 13);
  uint8_t canonical[mesh::ota::kOtaCanonicalManifestBytes] = {};
  fx.buildSmallManifest(image, sizeof(image), canonical);
  uint8_t signature[64] = {};
  owner.sign(canonical, sizeof(canonical), signature);
  auto& lean = fx.integration.leanReceiver();
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.begin(owner.publicKey(), canonical, signature, false, false));
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.putBlock(0, image, sizeof(image)));
  ASSERT_EQ(meshcore::ota::runtime::IOtaStagingSink::Result::Ok, fx.staging.writeChunk(0, image, sizeof(image)));
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Pending, lean.requestSeal());
  fx.integration.loop();
  ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, lean.status().phase);

  uint8_t manifest_hash[32] = {};
  mesh::ota::computeOtaManifestHash(canonical, manifest_hash);

  // A Commit frame addressed to a DIFFERENT target (wire `target` field)
  // must fail: handleLeanControlFrame routes straight into lean_.commit(),
  // which rebuilds the signed message from ITS OWN target_public_key_, so
  // a signature captured for a different device's target cannot verify
  // here -- the wire target field is informational/routing-only, the
  // actual binding is cryptographic.
  uint8_t other_target[32] = {};
  for (size_t i = 0; i < sizeof(other_target); ++i) other_target[i] = static_cast<uint8_t>(0xE0u + i);
  uint8_t wrong_message[mesh::ota::usb::kCommitSignedBytes] = {};
  const size_t wrong_message_len =
      mesh::ota::usb::buildCommitSignedMessage(other_target, manifest_hash, 1u, wrong_message);
  uint8_t wrong_signature[64] = {};
  owner.sign(wrong_message, wrong_message_len, wrong_signature);
  uint8_t wrong_commit_frame[mesh::ota::kOtaCommitFrameBytes] = {};
  const size_t wrong_commit_len = mesh::ota::encodeOtaCommitFrame(
      other_target, manifest_hash, 1u, wrong_signature, wrong_commit_frame, sizeof(wrong_commit_frame));
  EXPECT_FALSE(fx.integration.handleReceivedFrame(wrong_commit_frame, wrong_commit_len, 2000));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, lean.status().phase)
      << "an RF commit frame bound to a different target must not commit this device";

  // The CORRECT target-bound Commit, signed by the genuine owner, sent as
  // a real RF frame, must commit.
  uint8_t commit_message[mesh::ota::usb::kCommitSignedBytes] = {};
  const size_t commit_message_len =
      mesh::ota::usb::buildCommitSignedMessage(fx.target_public_key, manifest_hash, 5u, commit_message);
  uint8_t commit_signature[64] = {};
  owner.sign(commit_message, commit_message_len, commit_signature);
  uint8_t commit_frame[mesh::ota::kOtaCommitFrameBytes] = {};
  const size_t commit_frame_len = mesh::ota::encodeOtaCommitFrame(
      fx.target_public_key, manifest_hash, 5u, commit_signature, commit_frame, sizeof(commit_frame));
  EXPECT_TRUE(fx.integration.handleReceivedFrame(commit_frame, commit_frame_len, 2001));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, lean.status().phase);

  // Explicit COMMIT has crossed the cancellation boundary.
  uint8_t admin2_seed[32] = {};
  for (size_t i = 0; i < sizeof(admin2_seed); ++i) admin2_seed[i] = static_cast<uint8_t>(0xB2u + i);
  ::ota::test::Ed25519TestSigner admin2(admin2_seed);
  fx.admins.add(admin2.publicKey());
  OtaDescriptor descriptor = buildProtocolDescriptor(image, sizeof(image), 5);
  uint8_t abort_message[mesh::ota::usb::kAbortSignedBytes] = {};
  const size_t abort_message_len =
      mesh::ota::usb::buildAbortSignedMessage(fx.target_public_key, descriptor.sha256, abort_message);
  uint8_t abort_signature[64] = {};
  admin2.sign(abort_message, abort_message_len, abort_signature);
  uint8_t abort_frame[mesh::ota::kOtaAbortFrameBytes] = {};
  const size_t abort_frame_len = mesh::ota::encodeOtaAbortFrame(
      admin2.publicKey(), fx.target_public_key, descriptor.sha256, abort_signature, abort_frame, sizeof(abort_frame));
  EXPECT_FALSE(fx.integration.handleReceivedFrame(abort_frame, abort_frame_len, 2002));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, lean.status().phase);
}

TEST(LoraOtaRfFrames, StatusPollAndStatusReportRoundTripFeedsTrackedTargetObservationWithFreshAge) {
  LeanFixture fx;
  uint8_t owner_seed[32] = {};
  for (size_t i = 0; i < sizeof(owner_seed); ++i) owner_seed[i] = static_cast<uint8_t>(0x73u + i);
  ::ota::test::Ed25519TestSigner owner(owner_seed);
  fx.admins.add(owner.publicKey());

  uint8_t image[40] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(i + 17);
  uint8_t canonical[mesh::ota::kOtaCanonicalManifestBytes] = {};
  fx.buildSmallManifest(image, sizeof(image), canonical);
  uint8_t signature[64] = {};
  owner.sign(canonical, sizeof(canonical), signature);
  auto& lean = fx.integration.leanReceiver();
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.begin(owner.publicKey(), canonical, signature, false, false));
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, lean.putBlock(0, image, sizeof(image)));

  uint8_t manifest_hash[32] = {};
  mesh::ota::computeOtaManifestHash(canonical, manifest_hash);
  uint8_t manifest_tag[mesh::ota::kOtaManifestTagBytes] = {};
  mesh::ota::manifestTagFromHash(manifest_hash, manifest_tag);

  // 1) An uploader-side node polls this manifest tag -- the receiving
  //    node has no uploader state at all for this test, it's just the
  //    device holding the candidate replying to a poll it received.
  uint8_t poll_frame[mesh::ota::kOtaStatusPollFrameBytes] = {};
  const size_t poll_frame_len = mesh::ota::encodeOtaStatusPollFrame(manifest_tag, poll_frame, sizeof(poll_frame));
  EXPECT_TRUE(fx.integration.handleReceivedFrame(poll_frame, poll_frame_len, 3000));

  uint8_t reply[mesh::ota::kOtaStatusReportFrameBytes] = {};
  size_t reply_len = 0;
  ASSERT_TRUE(fx.integration.pollOutboundControlFrame(reply, sizeof(reply), reply_len));
  EXPECT_EQ(static_cast<size_t>(mesh::ota::kOtaStatusReportFrameBytes), reply_len);
  // Draining again with nothing newly queued must report nothing.
  EXPECT_FALSE(fx.integration.pollOutboundControlFrame(reply, sizeof(reply), reply_len));

  // 2) A SEPARATE node (acting as the uploader) tracks fx's target key and
  //    feeds the reply it "received" into its own integration instance;
  //    before any report, the observation must read back as tracked but
  //    with no fresh age.
  LeanFixture uploader_fx;
  uploader_fx.integration.trackOtaTarget(fx.target_public_key);
  mesh::ota::OtaFirmwareIntegration::TargetObservation obs;
  EXPECT_TRUE(uploader_fx.integration.targetObservation(fx.target_public_key, 3500, obs));
  EXPECT_TRUE(obs.tracked);
  EXPECT_FALSE(obs.haveReport);
  EXPECT_EQ(mesh::ota::OtaFirmwareIntegration::kNoObservationAgeMs, obs.ageMs);

  ASSERT_TRUE(uploader_fx.integration.handleReceivedFrame(reply, reply_len, /*now_ms=*/3500));
  ASSERT_TRUE(uploader_fx.integration.targetObservation(fx.target_public_key, 3700, obs));
  EXPECT_TRUE(obs.haveReport);
  EXPECT_EQ(1u, obs.receivedBlocks);
  EXPECT_EQ(200u, (unsigned)obs.ageMs) << "age must reflect now_ms(3700) - observed-at(3500), a genuinely fresh "
                                          "delta, not a stale/zero/constant placeholder";

  // A StatusReport from a reporter key the uploader never tracked must be
  // silently ignored (no observation created, no crash/misattribution).
  uint8_t untracked_target[32] = {};
  for (size_t i = 0; i < sizeof(untracked_target); ++i) untracked_target[i] = static_cast<uint8_t>(0xCCu);
  uint8_t stray_frame[mesh::ota::kOtaStatusReportFrameBytes] = {};
  const size_t stray_len = mesh::ota::encodeOtaStatusReportFrame(untracked_target, manifest_tag, 1, 1, 0,
                                                                 stray_frame, sizeof(stray_frame));
  EXPECT_TRUE(uploader_fx.integration.handleReceivedFrame(stray_frame, stray_len, 4000));
  mesh::ota::OtaFirmwareIntegration::TargetObservation untracked_obs;
  EXPECT_FALSE(uploader_fx.integration.targetObservation(untracked_target, 4000, untracked_obs))
      << "a reporter key this node never called trackOtaTarget() for must not spuriously appear tracked";
}

namespace {
void ed25519TestSignerThunk(void* ctx, const uint8_t* message, size_t message_len, uint8_t signature_out[64]) {
  static_cast<const ::ota::test::Ed25519TestSigner*>(ctx)->sign(message, message_len, signature_out);
}
}  // namespace

// Exercises the real end-to-end uploader path: a LOCAL node's own cached
// candidate (filled exactly as a USB CacheBegin/CachePut/CacheSeal
// sequence would) is read back block-by-block via OtaLeanReceiver::
// readBlock(), freshly re-signed via signAndEncodeOtaBlock() (never a
// stored per-block signature), and the resulting wire frames are fed into
// a SEPARATE remote receiver via the ordinary RF ingress
// (handleReceivedFrame) -- proving the uploader's own small helpers
// produce frames the real receiver genuinely accepts, byte for byte, not
// just a round-trip through the encode/parse functions in isolation.
TEST(LoraOtaRfUploader, ReadsLocalCacheSignsFreshAndRemoteReceiverAdmitsEveryBlock) {
  LeanFixture sender_fx;
  uint8_t owner_seed[32] = {};
  for (size_t i = 0; i < sizeof(owner_seed); ++i) owner_seed[i] = static_cast<uint8_t>(0x74u + i);
  ::ota::test::Ed25519TestSigner owner(owner_seed);
  sender_fx.admins.add(owner.publicKey());

  // A 2-block image (84 + 10 bytes) so the round-robin cursor has
  // something real to wrap over.
  uint8_t image[94] = {};
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(i + 3);
  uint8_t canonical[mesh::ota::kOtaCanonicalManifestBytes] = {};
  sender_fx.buildSmallManifest(image, sizeof(image), canonical);
  uint8_t signature[64] = {};
  owner.sign(canonical, sizeof(canonical), signature);

  auto& sender_lean = sender_fx.integration.leanReceiver();
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok,
            sender_lean.begin(owner.publicKey(), canonical, signature, false, /*local_owner_trusted=*/true));
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, sender_lean.putBlock(0, image, 84));
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok, sender_lean.putBlock(1, image + 84, sizeof(image) - 84));
  ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Pending, sender_lean.requestSeal());
  sender_fx.integration.loop();
  ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, sender_lean.status().phase);

  uint8_t exported_canonical[mesh::ota::kOtaCanonicalManifestBytes] = {};
  uint8_t exported_signature[64] = {};
  ASSERT_TRUE(sender_lean.exportCandidateForUpload(exported_canonical, exported_signature));
  EXPECT_EQ(0, std::memcmp(exported_canonical, canonical, sizeof(canonical)));
  EXPECT_EQ(0, std::memcmp(exported_signature, signature, sizeof(signature)));

  uint8_t manifest_hash[32] = {};
  mesh::ota::computeOtaManifestHash(canonical, manifest_hash);

  // Remote receiver: a different node, same admin set, genuinely
  // authorized purely via an Authorization RF frame built from the
  // exported canonical+signature (no USB on this side at all).
  LeanFixture remote_fx;
  remote_fx.admins.add(owner.publicKey());
  uint8_t auth_frame[mesh::ota::kOtaAuthorizationFrameBytes] = {};
  const size_t auth_len = mesh::ota::encodeOtaAuthorizationFrame(owner.publicKey(), exported_canonical,
                                                                 exported_signature, auth_frame, sizeof(auth_frame));
  ASSERT_TRUE(remote_fx.integration.handleReceivedFrame(auth_frame, auth_len, 5000));
  ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Receiving, remote_fx.integration.leanReceiver().status().phase);

  mesh::ota::OtaRfUploadCursor cursor;
  EXPECT_EQ(0u, cursor.peek());
  const uint16_t total_blocks = sender_lean.status().totalBlocks;
  ASSERT_EQ(2u, total_blocks);

  for (uint16_t sent = 0; sent < total_blocks; ++sent) {
    const uint16_t index = cursor.peek();
    EXPECT_TRUE(sender_lean.isBlockReceived(index));
    uint8_t block_data[mesh::ota::kOtaBlockMaxDataBytes] = {};
    size_t block_len = 0;
    ASSERT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok,
              sender_lean.readBlock(index, block_data, sizeof(block_data), block_len));

    uint8_t wire[mesh::ota::kOtaSignedBlockMaxBytes] = {};
    const size_t wire_len = mesh::ota::signAndEncodeOtaBlock(manifest_hash, index, block_data, block_len,
                                                             (void*)&owner, &ed25519TestSignerThunk, wire,
                                                             sizeof(wire));
    ASSERT_NE(0u, wire_len);

    EXPECT_TRUE(remote_fx.integration.handleReceivedFrame(wire, wire_len, 5000 + index));
    cursor.advance(total_blocks);
  }
  EXPECT_EQ(0u, cursor.peek()) << "cursor must wrap back to 0 after offering every block once";

  // Remote receiver genuinely has every byte, not just a count: seal and
  // compare its received image bytes against the original.
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Pending, remote_fx.integration.leanReceiver().requestSeal());
  remote_fx.integration.loop();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, remote_fx.integration.leanReceiver().status().phase);
  uint8_t remote_image[sizeof(image)] = {};
  ASSERT_EQ(meshcore::ota::runtime::IOtaStagingSink::Result::Ok,
            remote_fx.staging.readChunk(0, remote_image, sizeof(remote_image)));
  EXPECT_EQ(0, std::memcmp(remote_image, image, sizeof(image)));

  // A frame signed by the uploader's identity but for a FOREIGN manifest
  // hash (i.e. corrupted/mismatched tag) must be rejected by the remote
  // receiver, never silently miscounted as another copy of a real block.
  uint8_t wrong_hash[32] = {};
  std::memset(wrong_hash, 0x55, sizeof(wrong_hash));
  uint8_t bad_wire[mesh::ota::kOtaSignedBlockMaxBytes] = {};
  const size_t bad_len = mesh::ota::signAndEncodeOtaBlock(wrong_hash, 0, image, 84, (void*)&owner,
                                                          &ed25519TestSignerThunk, bad_wire, sizeof(bad_wire));
  ASSERT_NE(0u, bad_len);
  const auto before = remote_fx.integration.status(6000);
  EXPECT_FALSE(remote_fx.integration.handleReceivedFrame(bad_wire, bad_len, 6000));
  EXPECT_EQ(before.badFrames + 1, remote_fx.integration.status(6000).badFrames);
}

namespace {
using namespace mesh::ota;

struct RfNode {
  LeanFixture fx;
  ::ota::test::Ed25519TestSigner signer;
  uint32_t frequency = 907525;
  int restores = 0, retunes = 0;
  bool failRestore = false;
  explicit RfNode(const uint8_t seed[32]) : signer(seed) {
    fx.integration.setLeanTargetPublicKey(signer.publicKey());
    fx.integration.attachRfIdentity(this, &RfNode::sign, &RfNode::radio, 907525);
  }
  static void sign(void* ctx, const uint8_t* message, size_t len, uint8_t signature[64]) {
    static_cast<RfNode*>(ctx)->signer.sign(message, len, signature);
  }
  static bool radio(void* ctx, uint32_t frequency, bool restore) {
    auto& node = *static_cast<RfNode*>(ctx);
    if (restore && node.failRestore) return false;
    node.frequency = frequency;
    if (restore) ++node.restores; else ++node.retunes;
    return true;
  }
};

struct RfProductHarness {
  uint8_t ownerSeed[32] = {1}, seedA[32] = {2}, seedB[32] = {3};
  RfNode sender{ownerSeed}, a{seedA}, b{seedB};
  OtaRfUploader uploader;
  uint8_t targets[2][32] = {};
  std::vector<uint8_t> image;
  uint32_t now = 1;
  bool loseAck = false, lostAck = false, loseSparseBlocks = false;
  bool loseAuthorization = false, lostAuthorization = false;
  bool loseReupload = false, lostReupload = false;
  int multicastBlocks = 0, directedBlocks = 0, zeroHopBlocks = 0, census = 0;
  std::vector<uint16_t> repairs;

  void prepare(size_t size, uint8_t mode, bool reupload = false) {
    image.resize(size);
    for (size_t i = 0; i < size; ++i) image[i] = static_cast<uint8_t>(i * 17u);
    uint8_t canonical[59], signature[64];
    sender.fx.buildSmallManifest(image.data(), image.size(), canonical);
    sender.signer.sign(canonical, sizeof(canonical), signature);
    auto& lean = sender.fx.integration.leanReceiver();
    ASSERT_EQ(usb::UsbOtaResult::Ok, lean.begin(sender.signer.publicKey(), canonical, signature, false, true, true));
    for (uint16_t i = 0; i < lean.status().totalBlocks; ++i) {
      const size_t offset = i * 84u;
      ASSERT_EQ(usb::UsbOtaResult::Ok, lean.putBlock(i, image.data() + offset, std::min<size_t>(84, size - offset)));
    }
    ASSERT_EQ(usb::UsbOtaResult::Pending, lean.requestSeal());
    sender.fx.integration.loop();
    ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, lean.status().phase);
    a.fx.admins.add(sender.signer.publicKey()); b.fx.admins.add(sender.signer.publicKey());
    std::memcpy(targets[0], a.signer.publicKey(), 32); std::memcpy(targets[1], b.signer.publicKey(), 32);
    ASSERT_TRUE(uploader.start(sender.fx.integration, mode, &targets[0][0], mode == 2 ? 2 : 1,
                               mode == 0 ? 908525 : 0, mode == 0 ? 60000 : 0, 100, reupload));
  }
  static void sign(void* ctx, const uint8_t* message, size_t len, uint8_t signature[64]) {
    auto& harness = *static_cast<RfProductHarness*>(ctx);
    harness.sender.signer.sign(message, len, signature);
  }
  static bool send(void* ctx, OtaRfRoute route, const uint8_t target[32], const uint8_t* frame, size_t len,
                    meshcore::ota::protocol::OtaAirtimeCategory category) {
    auto& h = *static_cast<RfProductHarness*>(ctx);
    if (!h.sender.fx.integration.canTransmit(h.now, category, 20, true, false)) return false;
    h.sender.fx.integration.recordTransmit(h.now, category, 20);
    if (h.loseReupload && !h.lostReupload && frame[0] == kOtaReuploadKind) {
      h.lostReupload = true; return true;
    }
    if (h.loseAuthorization && !h.lostAuthorization && frame[0] == kOtaTargetAuthorizationKind) {
      h.lostAuthorization = true; return true;
    }
    if (frame[0] == kOtaCensusPollKind) ++h.census;
    if (frame[0] == kOtaOwnerSignedBlockKind) {
      if (route == OtaRfRoute::Multicast) ++h.multicastBlocks;
      else if (route == OtaRfRoute::Directed) ++h.directedBlocks;
      else ++h.zeroHopBlocks;
      if (category == meshcore::ota::protocol::OtaAirtimeCategory::Repair) h.repairs.push_back(usb::getBE16(frame + 33));
    }
    for (auto* node : {&h.a, &h.b}) {
      if (route != OtaRfRoute::Multicast && std::memcmp(target, node->signer.publicKey(), 32)) continue;
      if (h.sender.frequency != node->frequency) continue;
      if (h.loseSparseBlocks && frame[0] == kOtaOwnerSignedBlockKind &&
          category == meshcore::ota::protocol::OtaAirtimeCategory::Relay) {
        const auto index = usb::getBE16(frame + 33);
        if (index == 0 || index == 129) continue;
      }
      node->fx.integration.handleReceivedFrame(frame, len, h.now);
    }
    return true;
  }
  void step(uint32_t elapsed = 1000) {
    now += elapsed;
    sender.fx.integration.tickDirect(now);
    a.fx.integration.tickDirect(now); b.fx.integration.tickDirect(now);
    uploader.pump(sender.fx.integration, now, this, &sign, &send);
    a.fx.integration.loop(); b.fx.integration.loop();
    for (auto* node : {&a, &b}) {
      uint8_t frame[kOtaDirectFrameBytes]; size_t len = 0;
      if (!node->fx.integration.peekOutboundControlFrame(frame, sizeof(frame), len, now)) continue;
      node->fx.integration.releaseOutboundControlFrame();
      if (loseAck && !lostAck && frame[0] == kOtaDirectAckKind) { lostAck = true; continue; }
      if (node->frequency == sender.frequency) sender.fx.integration.handleReceivedFrame(frame, len, now);
    }
  }
  bool ready(RfNode& node) const {
    return node.fx.integration.leanReceiver().status().phase == ::ota::storage::OtaCandidateStore::Phase::Ready;
  }
};
}  // namespace

TEST(LoraOtaRfProduct, DirectedDeliveryUsesRoutingAndSelectivelyRepairsSparseHoleNotReceivedCount) {
  RfProductHarness h;
  h.loseSparseBlocks = true;
  h.prepare(84 * 18 + 7, usb::kStartModeDirected);
  for (int i = 0; i < 300 && !h.ready(h.a); ++i) h.step();
  ASSERT_TRUE(h.ready(h.a));
  EXPECT_FALSE(h.b.fx.integration.leanReceiver().status().valid);
  EXPECT_GT(h.directedBlocks, 0);
  EXPECT_EQ(0, h.multicastBlocks);
  ASSERT_EQ(1u, h.repairs.size());
  EXPECT_EQ(0, h.repairs[0]);
  std::vector<uint8_t> received(h.image.size());
  for (size_t offset = 0; offset < received.size(); offset += 84) {
    ASSERT_EQ(IOtaStagingSink::Result::Ok, h.a.fx.staging.readChunk(offset, received.data() + offset,
                                                                std::min<size_t>(84, received.size() - offset)));
  }
  EXPECT_EQ(h.image, received);
}

TEST(LoraOtaRfProduct, BackgroundMulticastsThenCensusesAllTargetsAndRepairsAcrossBitmapWindows) {
  RfProductHarness h;
  h.loseSparseBlocks = true;
  h.prepare(84 * 130 + 7, usb::kStartModeBackground);
  for (int i = 0; i < 1500 && !(h.ready(h.a) && h.ready(h.b)); ++i) h.step();
  ASSERT_TRUE(h.ready(h.a)); ASSERT_TRUE(h.ready(h.b));
  EXPECT_EQ(131, h.multicastBlocks);
  EXPECT_EQ(4, h.directedBlocks);
  EXPECT_GE(h.census, 4);
  EXPECT_EQ((std::vector<uint16_t>{0, 0, 129, 129}), h.repairs);
}

TEST(LoraOtaRfProduct, DirectNegotiatesOffFrequencySurvivesLostAckAndMoreThanSixtySecondsThenRestores) {
  RfProductHarness h;
  h.loseAck = true;
  h.prepare(84 * 130 + 7, usb::kStartModeDirect);
  for (int i = 0; i < 1500 && !h.ready(h.a); ++i) h.step();
  ASSERT_TRUE(h.lostAck);
  ASSERT_TRUE(h.ready(h.a));
  EXPECT_GT(h.now, 60000u);
  EXPECT_GE(h.a.retunes, 3);
  EXPECT_GE(h.sender.retunes, 2);
  EXPECT_GT(h.zeroHopBlocks, 0);
  EXPECT_EQ(0, h.multicastBlocks);
  EXPECT_EQ(0, h.directedBlocks);
  h.uploader.stop(h.sender.fx.integration);
  EXPECT_EQ(907525u, h.sender.frequency);
  for (int i = 0; i < 80; ++i) h.step();
  EXPECT_EQ(907525u, h.a.frequency);
  EXPECT_GT(h.a.restores, 0);
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, h.a.fx.integration.leanReceiver().status().phase);
}

TEST(LoraOtaRfProduct, RebootResumesDurableBitmapWithoutErasingAndBadFramesPreserveReady) {
  RfProductHarness h;
  h.prepare(84 * 30 + 7, usb::kStartModeDirected);
  for (int i = 0; i < 10; ++i) h.step();
  const auto before = h.a.fx.integration.leanReceiver().status();
  ASSERT_GT(before.receivedBlocks, 0);
  const auto erases = h.a.fx.image_flash.eraseOpCount();
  h.a.fx.integration = OtaFirmwareIntegration();
  h.a.fx.integration.attachTrustProvider(&h.a.fx.trust);
  h.a.fx.integration.attachStagingSink(&h.a.fx.guarded);
  h.a.fx.integration.attachCandidateStore(&h.a.fx.candidate_store);
  h.a.fx.integration.attachLeanSignatureVerifier(&h.a.fx.sig_verifier);
  h.a.fx.integration.setLeanAdminCheck(&h.a.fx.admins, leanAdminCheckThunk);
  h.a.fx.integration.setLeanTargetPublicKey(h.a.signer.publicKey());
  ASSERT_EQ(before.receivedBlocks, h.a.fx.integration.leanReceiver().status().receivedBlocks);
  for (int i = 0; i < 300 && !h.ready(h.a); ++i) h.step();
  ASSERT_TRUE(h.ready(h.a));
  EXPECT_EQ(erases, h.a.fx.image_flash.eraseOpCount());
  const uint8_t garbage[] = {kOtaOwnerSignedBlockKind, 0, 1};
  EXPECT_FALSE(h.a.fx.integration.handleReceivedFrame(garbage, sizeof(garbage), h.now));
  h.a.fx.integration.loop();
  EXPECT_TRUE(h.ready(h.a));
}

TEST(LoraOtaRfProduct, UploaderCacheIsDurablyNonInstallableAndOwnerRevocationDeniesReadyCommit) {
  RfProductHarness h;
  h.prepare(47, usb::kStartModeDirected);
  auto st = h.sender.fx.integration.leanReceiver().status();
  ASSERT_TRUE(st.localCache);
  uint8_t message[usb::kCommitSignedBytes], signature[64];
  usb::buildCommitSignedMessage(h.sender.signer.publicKey(), st.manifestHash, 5, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  EXPECT_EQ(usb::UsbOtaResult::Denied, h.sender.fx.integration.leanReceiver().commit(5, signature));
  ::ota::storage::OtaCandidateStore::Snapshot persisted;
  ASSERT_TRUE(h.sender.fx.candidate_store.load(persisted));
  EXPECT_TRUE(persisted.localCache);
  for (int i = 0; i < 20 && !h.ready(h.a); ++i) h.step();
  ASSERT_TRUE(h.ready(h.a));
  st = h.a.fx.integration.leanReceiver().status();
  usb::buildCommitSignedMessage(h.a.signer.publicKey(), st.manifestHash, 5, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  h.a.fx.admins.count = 0;
  EXPECT_EQ(usb::UsbOtaResult::Denied, h.a.fx.integration.leanReceiver().commit(5, signature));
  EXPECT_TRUE(h.ready(h.a));
}

TEST(LoraOtaRfProduct, AbortSuppressionSurvivesMulticastsAndExplicitBoundReuploadCannotReplayAfterAnotherAbort) {
  RfProductHarness h;
  h.prepare(84 * 5 + 7, usb::kStartModeBackground);
  for (int i = 0; i < 4; ++i) h.step();
  auto& receiver = h.a.fx.integration.leanReceiver();
  auto st = receiver.status();
  uint8_t message[usb::kAbortSignedBytes], signature[64];
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), st.imageHash, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, st.imageHash));
  for (int i = 0; i < 200; ++i) h.step();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, receiver.status().phase);
  EXPECT_TRUE(h.ready(h.b));
  uint8_t frame[kOtaReuploadFrameBytes];
  st = receiver.status();
  frame[0] = kOtaReuploadKind;
  std::memcpy(frame + 1, h.sender.signer.publicKey(), 32);
  std::memcpy(frame + 33, h.a.signer.publicKey(), 32);
  std::memcpy(frame + 65, st.manifestHash, 32);
  usb::putBE32(frame + 97, st.generation);
  uint8_t reuploadMessage[160];
  auto len = buildOtaReuploadMessage(frame, reuploadMessage);
  h.sender.signer.sign(reuploadMessage, len, frame + 101);
  ASSERT_TRUE(h.a.fx.integration.handleReceivedFrame(frame, sizeof(frame), h.now));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Receiving, receiver.status().phase);
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, st.imageHash));
  EXPECT_FALSE(h.a.fx.integration.handleReceivedFrame(frame, sizeof(frame), h.now));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, receiver.status().phase);
}

TEST(LoraOtaRfProduct, ControlWireTargetHashAndCounterCannotBeChangedAfterSigning) {
  RfProductHarness h;
  h.prepare(43, usb::kStartModeDirected);
  for (int i = 0; i < 20 && !h.ready(h.a); ++i) h.step();
  ASSERT_TRUE(h.ready(h.a));
  auto st = h.a.fx.integration.leanReceiver().status();
  uint8_t message[usb::kCommitSignedBytes], signature[64], frame[kOtaCommitFrameBytes];
  usb::buildCommitSignedMessage(h.a.signer.publicKey(), st.manifestHash, 5, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  const auto len = encodeOtaCommitFrame(h.a.signer.publicKey(), st.manifestHash, 5, signature, frame, sizeof(frame));
  for (size_t offset : {size_t(1), size_t(33), size_t(68)}) {
    frame[offset] ^= 1;
    EXPECT_FALSE(h.a.fx.integration.handleReceivedFrame(frame, len, h.now));
    EXPECT_TRUE(h.ready(h.a));
    frame[offset] ^= 1;
  }
  EXPECT_TRUE(h.a.fx.integration.handleReceivedFrame(frame, len, h.now));
}

TEST(LoraOtaRfProduct, DirectRecoversLostAdmissionAndReceiverRebootByNormalProfileCensus) {
  RfProductHarness h;
  h.loseAuthorization = true;
  h.prepare(84 * 70 + 7, usb::kStartModeDirect);
  for (int i = 0; i < 100 && h.a.fx.integration.leanReceiver().status().receivedBlocks < 7; ++i) h.step();
  ASSERT_TRUE(h.lostAuthorization);
  ASSERT_GE(h.a.fx.integration.leanReceiver().status().receivedBlocks, 7);
  const auto erases = h.a.fx.image_flash.eraseOpCount();
  const auto received = h.a.fx.integration.leanReceiver().status().receivedBlocks;
  h.a.frequency = 907525;
  h.a.fx.integration = OtaFirmwareIntegration();
  h.a.fx.integration.attachTrustProvider(&h.a.fx.trust);
  h.a.fx.integration.attachStagingSink(&h.a.fx.guarded);
  h.a.fx.integration.attachCandidateStore(&h.a.fx.candidate_store);
  h.a.fx.integration.attachLeanSignatureVerifier(&h.a.fx.sig_verifier);
  h.a.fx.integration.setLeanAdminCheck(&h.a.fx.admins, leanAdminCheckThunk);
  h.a.fx.integration.setLeanTargetPublicKey(h.a.signer.publicKey());
  h.a.fx.integration.attachRfIdentity(&h.a, RfNode::sign, RfNode::radio, 907525);
  ASSERT_EQ(received, h.a.fx.integration.leanReceiver().status().receivedBlocks);
  for (int i = 0; i < 1500 && !h.ready(h.a); ++i) h.step();
  ASSERT_TRUE(h.ready(h.a));
  EXPECT_EQ(erases, h.a.fx.image_flash.eraseOpCount());
  EXPECT_FALSE(h.repairs.empty());
}

TEST(LoraOtaRfProduct, OneExplicitReuploadApprovalCannotAutomaticallyOverrideALaterAdminAbort) {
  RfProductHarness h;
  h.prepare(84 * 10 + 7, usb::kStartModeBackground, true);
  for (int i = 0; i < 5; ++i) h.step();
  auto& receiver = h.a.fx.integration.leanReceiver();
  const auto st = receiver.status();
  uint8_t message[usb::kAbortSignedBytes], signature[64];
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), st.imageHash, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, st.imageHash));
  const auto erases = h.a.fx.image_flash.eraseOpCount();
  for (int i = 0; i < 500; ++i) {
    h.step();
    if (h.a.fx.image_flash.eraseOpCount() > erases && receiver.status().receivedBlocks > 0) break;
  }
  ASSERT_GT(h.a.fx.image_flash.eraseOpCount(), erases);
  ASSERT_GT(receiver.status().receivedBlocks, 0);
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, st.imageHash));
  const auto erases_after_second_abort = h.a.fx.image_flash.eraseOpCount();
  for (int i = 0; i < 500; ++i) h.step();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, receiver.status().phase);
  EXPECT_EQ(erases_after_second_abort, h.a.fx.image_flash.eraseOpCount());
}

TEST(LoraOtaRfProduct, LostExplicitReuploadRetriesOnlyTheApprovedGeneration) {
  RfProductHarness h;
  h.prepare(84 * 10 + 7, usb::kStartModeBackground, true);
  for (int i = 0; i < 5; ++i) h.step();
  auto& receiver = h.a.fx.integration.leanReceiver();
  const auto st = receiver.status();
  uint8_t message[usb::kAbortSignedBytes], signature[64];
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), st.imageHash, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, st.imageHash));
  h.loseReupload = true;
  for (int i = 0; i < 500 && !h.ready(h.a); ++i) h.step();
  ASSERT_TRUE(h.lostReupload);
  ASSERT_TRUE(h.ready(h.a));
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, st.imageHash));
  const auto erases = h.a.fx.image_flash.eraseOpCount();
  for (int i = 0; i < 200; ++i) h.step();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, receiver.status().phase);
  EXPECT_EQ(erases, h.a.fx.image_flash.eraseOpCount());
}

TEST(LoraOtaRfProduct, ExplicitReuploadCanReplaceAnAbortedDifferentImageAndOwnerWithoutMulticastRevival) {
  RfProductHarness h;
  h.prepare(91, usb::kStartModeDirected);
  for (int i = 0; i < 20 && !h.ready(h.a); ++i) h.step();
  ASSERT_TRUE(h.ready(h.a));
  auto& receiver = h.a.fx.integration.leanReceiver();
  const auto original = receiver.status();
  uint8_t message[usb::kAbortSignedBytes], signature[64];
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), original.imageHash, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, original.imageHash));
  h.uploader.stop(h.sender.fx.integration);
  const uint8_t new_owner_seed[32] = {7};
  h.sender.signer = ::ota::test::Ed25519TestSigner(new_owner_seed);
  h.sender.fx.integration.setLeanTargetPublicKey(h.sender.signer.publicKey());
  h.a.fx.admins.count = 0;
  h.a.fx.admins.add(h.sender.signer.publicKey());
  h.image.assign(257, 0x57);
  uint8_t canonical[59];
  h.sender.fx.buildSmallManifest(h.image.data(), h.image.size(), canonical);
  h.sender.signer.sign(canonical, sizeof(canonical), signature);
  auto& cache = h.sender.fx.integration.leanReceiver();
  ASSERT_EQ(usb::UsbOtaResult::Ok, cache.begin(h.sender.signer.publicKey(), canonical, signature, true, true, true));
  for (uint16_t i = 0; i < cache.status().totalBlocks; ++i) {
    ASSERT_EQ(usb::UsbOtaResult::Ok, cache.putBlock(i, h.image.data() + 84u * i, std::min<size_t>(84, h.image.size() - 84u * i)));
  }
  ASSERT_EQ(usb::UsbOtaResult::Pending, cache.requestSeal());
  h.sender.fx.integration.loop();
  ASSERT_TRUE(h.uploader.start(h.sender.fx.integration, usb::kStartModeDirected, &h.targets[0][0], 1, 0, 0, 0, false));
  for (int i = 0; i < 30; ++i) h.step();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, receiver.status().phase);
  EXPECT_EQ(0, std::memcmp(original.manifestHash, receiver.status().manifestHash, 32));
  ASSERT_TRUE(h.uploader.start(h.sender.fx.integration, usb::kStartModeDirected, &h.targets[0][0], 1, 0, 0, 0, true));
  h.loseReupload = true;
  for (int i = 0; i < 100 && !h.ready(h.a); ++i) h.step();
  ASSERT_TRUE(h.lostReupload);
  ASSERT_TRUE(h.ready(h.a));
  EXPECT_EQ(0, std::memcmp(cache.status().manifestHash, receiver.status().manifestHash, 32));
  EXPECT_EQ(0, std::memcmp(h.sender.signer.publicKey(), receiver.status().ownerPublicKey, 32));
  uint8_t received[257];
  for (size_t offset = 0; offset < sizeof(received); offset += 84) {
    ASSERT_EQ(IOtaStagingSink::Result::Ok, h.a.fx.staging.readChunk(offset, received + offset, std::min<size_t>(84, sizeof(received) - offset)));
  }
  EXPECT_EQ(0, std::memcmp(received, h.image.data(), sizeof(received)));
}

TEST(LoraOtaRfProduct, LegacyTransportAbortPreservesDurableLocalCacheReadback) {
  RfProductHarness h;
  h.prepare(91, usb::kStartModeDirected);
  h.uploader.stop(h.sender.fx.integration);
  h.sender.fx.integration.abortSession();
  uint8_t bytes[84]; size_t length = 0;
  auto& cache = h.sender.fx.integration.leanReceiver();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, cache.status().phase);
  ASSERT_EQ(usb::UsbOtaResult::Ok, cache.readBlock(0, bytes, sizeof(bytes), length));
  EXPECT_EQ(84u, length);
  EXPECT_EQ(0, std::memcmp(bytes, h.image.data(), length));
}

TEST(LoraOtaRfProduct, SignedCommitRetryAfterMetadataFailurePreservesReadyAndNeverReplacesQueuedIntent) {
  RfProductHarness h;
  h.prepare(91, usb::kStartModeDirected);
  for (int i = 0; i < 20 && !h.ready(h.a); ++i) h.step();
  ASSERT_TRUE(h.ready(h.a));
  auto& receiver = h.a.fx.integration.leanReceiver();
  const auto st = receiver.status();
  uint8_t message[usb::kCommitSignedBytes], signature[64];
  usb::buildCommitSignedMessage(h.a.signer.publicKey(), st.manifestHash, st.counter, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  using Flash = ::ota::test::FakeNorFlash;
  Flash::FaultSpec fault;
  fault.kind = Flash::OpKind::Program;
  fault.timing = Flash::InjectionTiming::Before;
  fault.trigger_op_count = h.a.fx.candidate_flash.programOpCount() + 1;
  h.a.fx.candidate_flash.armFault(fault);
  ASSERT_EQ(usb::UsbOtaResult::IoError, receiver.commit(st.counter, signature));
  EXPECT_TRUE(h.ready(h.a));
  ::ota::storage::OtaCandidateStore::Snapshot durable;
  ASSERT_TRUE(h.a.fx.candidate_store.load(durable));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, durable.phase);
  uint8_t abort_message[usb::kAbortSignedBytes], abort_signature[64];
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), st.imageHash, abort_message);
  h.sender.signer.sign(abort_message, sizeof(abort_message), abort_signature);
  EXPECT_EQ(usb::UsbOtaResult::TooLate, receiver.abort(h.sender.signer.publicKey(), abort_signature, st.imageHash));
  h.a.fx.candidate_flash.clearFault();
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.commit(st.counter, signature));
  ASSERT_TRUE(h.a.fx.candidate_store.load(durable));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, durable.phase);
}

TEST(LoraOtaRfProduct, FailedRadioRestoreRetainsObligationAndOffFrequencyDoesNotSpendOnMeshBudget) {
  RfProductHarness h;
  h.prepare(84 * 20 + 7, usb::kStartModeDirect);
  for (int i = 0; i < 100 && !h.sender.fx.integration.directActive(); ++i) h.step();
  ASSERT_TRUE(h.sender.fx.integration.directActive());
  const auto on_mesh_used = h.sender.fx.integration.airtimeLimiter().storedUsageMs(h.now);
  for (int i = 0; i < 512; ++i) {
    ASSERT_TRUE(h.sender.fx.integration.canTransmit(h.now, OtaAirtimeCategory::Relay, 25, true, false));
    ASSERT_TRUE(h.sender.fx.integration.recordTransmit(h.now, OtaAirtimeCategory::Relay, 25));
  }
  EXPECT_EQ(on_mesh_used, h.sender.fx.integration.airtimeLimiter().storedUsageMs(h.now));
  ASSERT_TRUE(h.sender.fx.integration.setDutyCyclePercent(0));
  EXPECT_FALSE(h.sender.fx.integration.canTransmit(h.now, OtaAirtimeCategory::Relay, 25, true, false));
  h.sender.failRestore = true;
  h.now += 61000;
  h.sender.fx.integration.tickDirect(h.now);
  EXPECT_TRUE(h.sender.fx.integration.directActive());
  EXPECT_TRUE(h.sender.fx.integration.hasPendingRfWork());
  EXPECT_FALSE(h.sender.fx.integration.canTransmit(h.now, OtaAirtimeCategory::Relay, 25, true, false));
  h.sender.failRestore = false;
  h.sender.fx.integration.tickDirect(h.now + 1);
  EXPECT_FALSE(h.sender.fx.integration.directActive());
  EXPECT_EQ(907525u, h.sender.frequency);
  EXPECT_FALSE(h.sender.fx.integration.canTransmit(h.now + 1, OtaAirtimeCategory::Relay, 25, true, false));
}

TEST(LoraOtaRfProduct, ForeignBoardRoleImageCanBeCachedButCannotBecomeLocalInstallCandidate) {
  RfProductHarness h;
  const uint8_t image[24] = {};
  auto descriptor = buildProtocolDescriptor(image, sizeof(image), 5);
  descriptor.boardVariant = 3; descriptor.role = 8;
  uint8_t canonical[59], signature[64]; size_t len = 0;
  ASSERT_EQ(OtaDescriptorCodecResult::Ok, encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), len));
  h.sender.signer.sign(canonical, sizeof(canonical), signature);
  auto& cache = h.sender.fx.integration.leanReceiver();
  ASSERT_EQ(usb::UsbOtaResult::Ok, cache.begin(h.sender.signer.publicKey(), canonical, signature, false, true, true));
  ASSERT_EQ(usb::UsbOtaResult::Ok, cache.putBlock(0, image, sizeof(image)));
  ASSERT_EQ(usb::UsbOtaResult::Pending, cache.requestSeal());
  h.sender.fx.integration.loop();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, cache.status().phase);
  h.a.fx.admins.add(h.sender.signer.publicKey());
  EXPECT_EQ(usb::UsbOtaResult::Denied,
            h.a.fx.integration.leanReceiver().begin(h.sender.signer.publicKey(), canonical, signature, false, false));
}

TEST(LoraOtaRfProduct, SignedUsbCompanionCachesRepeaterForAllRfModesWithoutLocalRoleFloorOrBootCapabilityAdmission) {
  const uint32_t board_pairs[][2] = {
    {0x584E3430u, 0x584E3430u}, {0x584E3430u, 0x53435031u},
    {0x53435031u, 0x584E3430u}, {0x53435031u, 0x53435031u},
  };
  for (const auto& pair : board_pairs) {
    const uint32_t source_id = pair[0], target_id = pair[1];
    for (const bool stock_loader : {false, true}) {
      for (const uint8_t mode : {usb::kStartModeDirect, usb::kStartModeDirected, usb::kStartModeBackground}) {
        SCOPED_TRACE(source_id);
        SCOPED_TRACE(target_id);
        SCOPED_TRACE(stock_loader);
        SCOPED_TRACE(mode);
        RfProductHarness h;
        auto source_anchor = makeLeanTrustAnchor();
        source_anchor.expected_target_id = source_id;
        source_anchor.expected_role_id = 0;
        source_anchor.supported_boot_capability_flags = 0;
        auto target_anchor = source_anchor;
        target_anchor.expected_target_id = target_id;
        target_anchor.expected_role_id = 1;
        target_anchor.supported_boot_capability_flags = 1;
        ::ota::test::FakeMonotonicCounter source_floor(100), target_floor(4);
        ::ota::trust::DescriptorVerifier source_verifier(
            h.sender.fx.hasher, h.sender.fx.sig_verifier, source_floor, source_anchor);
        ::ota::trust::DescriptorVerifier target_verifier(
            h.a.fx.hasher, h.a.fx.sig_verifier, target_floor, target_anchor);
        OtaNrf52FirmwareTrustProvider source_trust(source_verifier, h.sender.fx.image_region);
        OtaNrf52FirmwareTrustProvider target_trust(target_verifier, h.a.fx.image_region);
        OtaNrf52FirmwareTrustProvider second_target_trust(target_verifier, h.b.fx.image_region);
        h.sender.fx.integration.attachTrustProvider(&source_trust);
        h.a.fx.integration.attachTrustProvider(&target_trust);
        h.b.fx.integration.attachTrustProvider(&second_target_trust);
        OtaBoardCacheOnlyBackend stock_cache(
            h.sender.fx.image_region, h.sender.fx.candidate_store_region, &leanNoTrial);
        if (stock_loader) ASSERT_TRUE(stock_cache.attach(h.sender.fx.integration, h.sender.fx.sig_verifier));
        h.image.resize(257);
        for (size_t i = 0; i < h.image.size(); ++i) h.image[i] = static_cast<uint8_t>(i * 17u);
        auto descriptor = buildProtocolDescriptor(h.image.data(), h.image.size(), 5);
        descriptor.boardFamily = static_cast<uint16_t>(target_id >> 16);
        descriptor.boardVariant = static_cast<uint16_t>(target_id);
        descriptor.role = 1;
        descriptor.appAddress = 0x27000;
        descriptor.minBootloaderCapabilities = 1;
        EXPECT_FALSE(source_trust.verifyDescriptorPolicyOnly(descriptor));
        auto own_descriptor = descriptor;
        own_descriptor.boardFamily = static_cast<uint16_t>(source_id >> 16);
        own_descriptor.boardVariant = static_cast<uint16_t>(source_id);
        own_descriptor.role = 0;
        own_descriptor.securityCounter = 101;
        own_descriptor.minBootloaderCapabilities = 0;
        ASSERT_TRUE(source_trust.verifyDescriptorPolicyOnly(own_descriptor));
        own_descriptor.role = 1;
        EXPECT_FALSE(source_trust.verifyDescriptorPolicyOnly(own_descriptor));
        own_descriptor.role = 0;
        own_descriptor.securityCounter = 5;
        EXPECT_FALSE(source_trust.verifyDescriptorPolicyOnly(own_descriptor));
        own_descriptor.securityCounter = 101;
        own_descriptor.minBootloaderCapabilities = 1;
        EXPECT_FALSE(source_trust.verifyDescriptorPolicyOnly(own_descriptor));
        ASSERT_TRUE(target_trust.verifyDescriptorPolicyOnly(descriptor));
        uint8_t begin[usb::kCacheBeginTotalBytes] = {usb::kCommand, static_cast<uint8_t>(usb::UsbOtaOp::CacheBegin)};
        std::memcpy(begin + 3, h.sender.signer.publicKey(), 32);
        size_t canonical_len = 0;
        ASSERT_EQ(OtaDescriptorCodecResult::Ok,
                  encodeOtaDescriptorCanonical(descriptor, begin + 35, 59, canonical_len));
        h.sender.signer.sign(begin + 35, canonical_len, begin + 94);
        auto& cache = h.sender.fx.integration.leanReceiver();
        const auto before_erase = h.sender.fx.image_flash.eraseOpCount();
        begin[94] ^= 1;
        EXPECT_EQ(usb::UsbOtaResult::Denied,
                  cache.handleUsbCacheFrame(begin, sizeof(begin), h.sender.signer.publicKey()));
        EXPECT_EQ(before_erase, h.sender.fx.image_flash.eraseOpCount());
        begin[94] ^= 1;
        ASSERT_EQ(usb::UsbOtaResult::Ok,
                  cache.handleUsbCacheFrame(begin, sizeof(begin), h.sender.signer.publicKey()));
        for (uint16_t index = 0; index < cache.status().totalBlocks; ++index) {
          const size_t offset = index * 84u;
          const size_t take = std::min<size_t>(84, h.image.size() - offset);
          uint8_t put[usb::kCachePutMaxTotalBytes] = {usb::kCommand, static_cast<uint8_t>(usb::UsbOtaOp::CachePut)};
          usb::putBE16(put + 2, index);
          put[4] = static_cast<uint8_t>(take);
          std::memcpy(put + 5, h.image.data() + offset, take);
          ASSERT_EQ(usb::UsbOtaResult::Ok,
                    cache.handleUsbCacheFrame(put, 5 + take, h.sender.signer.publicKey()));
        }
        const auto image_writes = h.sender.fx.image_flash.programOpCount();
        const uint8_t seal[] = {usb::kCommand, static_cast<uint8_t>(usb::UsbOtaOp::CacheSeal)};
        ASSERT_EQ(usb::UsbOtaResult::Pending,
                  cache.handleUsbCacheFrame(seal, sizeof(seal), h.sender.signer.publicKey()));
        h.sender.fx.integration.loop();
        ASSERT_EQ(usb::UsbOtaPhase::CacheSealed, h.sender.fx.integration.reportedPhase());
        EXPECT_EQ(image_writes, h.sender.fx.image_flash.programOpCount());
        uint8_t commit_message[usb::kCommitSignedBytes], commit_signature[64];
        usb::buildCommitSignedMessage(h.sender.signer.publicKey(), cache.status().manifestHash, 5, commit_message);
        h.sender.signer.sign(commit_message, sizeof(commit_message), commit_signature);
        EXPECT_EQ(usb::UsbOtaResult::Denied, cache.commit(5, commit_signature));
        EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, cache.status().phase);
        if (stock_loader) {
          ASSERT_TRUE(stock_cache.attach(h.sender.fx.integration, h.sender.fx.sig_verifier));
          EXPECT_EQ(usb::UsbOtaPhase::CacheSealed, h.sender.fx.integration.reportedPhase());
          EXPECT_EQ(image_writes, h.sender.fx.image_flash.programOpCount());
          EXPECT_EQ(usb::UsbOtaResult::Denied, h.sender.fx.integration.leanReceiver().begin(
              h.sender.signer.publicKey(), begin + 35, begin + 94, false, true, false));
        }
        h.a.fx.admins.add(h.sender.signer.publicKey());
        h.b.fx.admins.add(h.sender.signer.publicKey());
        std::memcpy(h.targets[0], h.a.signer.publicKey(), 32);
        std::memcpy(h.targets[1], h.b.signer.publicKey(), 32);
        ASSERT_TRUE(h.uploader.start(h.sender.fx.integration, mode, &h.targets[0][0],
                                     mode == usb::kStartModeBackground ? 2 : 1,
                                     mode == usb::kStartModeDirect ? 908525 : 0,
                                     mode == usb::kStartModeDirect ? 60000 : 0, 100, false));
        for (int i = 0; i < 100 && (!h.ready(h.a) ||
             (mode == usb::kStartModeBackground && !h.ready(h.b))); ++i) h.step();
        ASSERT_TRUE(h.ready(h.a));
        if (mode == usb::kStartModeBackground) ASSERT_TRUE(h.ready(h.b));
        uint8_t actual[257];
        for (size_t offset = 0; offset < sizeof(actual); offset += 84) {
          ASSERT_EQ(IOtaStagingSink::Result::Ok,
                    h.a.fx.staging.readChunk(offset, actual + offset, std::min<size_t>(84, sizeof(actual) - offset)));
        }
        EXPECT_EQ(0, std::memcmp(actual, h.image.data(), sizeof(actual)));
        EXPECT_FALSE(h.a.fx.integration.leanReceiver().status().localCache);
        EXPECT_EQ(5u, h.a.fx.integration.leanReceiver().status().counter);
        EXPECT_EQ(0, std::memcmp(h.sender.signer.publicKey(),
                                 h.a.fx.integration.leanReceiver().status().ownerPublicKey, 32));
        EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, cache.status().phase);
    }
   }
  }
}

TEST(LoraOtaRfProduct, RepeaterRfAdmissionIndependentlyChecksItsOwnRoleFloorAndBootCapabilityBeforeErase) {
  for (int violation = 0; violation < 3; ++violation) {
    SCOPED_TRACE(violation);
    RfProductHarness h;
    auto anchor = makeLeanTrustAnchor();
    anchor.expected_target_id = 0x584E3430;
    anchor.expected_role_id = violation == 0 ? 0 : 1;
    anchor.supported_boot_capability_flags = violation == 2 ? 0 : 1;
    ::ota::test::FakeMonotonicCounter floor(violation == 1 ? 5 : 4);
    ::ota::trust::DescriptorVerifier verifier(h.a.fx.hasher, h.a.fx.sig_verifier, floor, anchor);
    OtaNrf52FirmwareTrustProvider trust(verifier, h.a.fx.image_region);
    h.a.fx.integration.attachTrustProvider(&trust);
    h.a.fx.admins.add(h.sender.signer.publicKey());
    const uint8_t image[40] = {0x51};
    auto descriptor = buildProtocolDescriptor(image, sizeof(image), 5);
    descriptor.boardFamily = 0x584E;
    descriptor.boardVariant = 0x3430;
    descriptor.role = 1;
    descriptor.appAddress = 0x27000;
    descriptor.minBootloaderCapabilities = 1;
    uint8_t canonical[59], signature[64], frame[164];
    size_t canonical_len = 0;
    ASSERT_EQ(OtaDescriptorCodecResult::Ok,
              encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), canonical_len));
    h.sender.signer.sign(canonical, canonical_len, signature);
    ASSERT_EQ(sizeof(frame), encodeOtaTargetAuthorization(h.a.signer.publicKey(),
              h.sender.signer.publicKey(), canonical, signature, frame, sizeof(frame)));
    EXPECT_FALSE(h.a.fx.integration.handleReceivedFrame(frame, sizeof(frame), 1));
    EXPECT_EQ(0u, h.a.fx.image_flash.eraseOpCount());
    EXPECT_EQ(0u, h.a.fx.candidate_flash.eraseOpCount());
    EXPECT_FALSE(h.a.fx.integration.leanReceiver().status().valid);
  }
}

TEST(LoraOtaRfProduct, StockLoaderUsbCacheRequiresSelfOrLiveAdminCanonicalFieldsCapacityAndExactImageHash) {
  RfProductHarness h;
  OtaBoardCacheOnlyBackend backend(h.sender.fx.image_region, h.sender.fx.candidate_store_region, &leanNoTrial);
  ASSERT_TRUE(backend.attach(h.sender.fx.integration, h.sender.fx.sig_verifier));
  const uint8_t image[40] = {0x52};
  auto descriptor = buildProtocolDescriptor(image, sizeof(image), 5);
  descriptor.boardFamily = 0x584E;
  descriptor.boardVariant = 0x3430;
  descriptor.role = 1;
  descriptor.appAddress = 0x27000;
  descriptor.minBootloaderCapabilities = 1;
  descriptor.keyId = 42;
  uint8_t begin[usb::kCacheBeginTotalBytes] = {usb::kCommand, static_cast<uint8_t>(usb::UsbOtaOp::CacheBegin)};
  std::memcpy(begin + 3, h.sender.signer.publicKey(), 32);
  auto sign_descriptor = [&]() {
    size_t len = 0;
    ASSERT_EQ(OtaDescriptorCodecResult::Ok,
              encodeOtaDescriptorCanonical(descriptor, begin + 35, 59, len));
    h.sender.signer.sign(begin + 35, len, begin + 94);
  };
  auto& cache = h.sender.fx.integration.leanReceiver();
  EXPECT_EQ(usb::UsbOtaResult::BadRequest,
            cache.handleUsbCacheFrame(begin, sizeof(begin) - 1, h.sender.signer.publicKey()));
  for (int field = 0; field < 4; ++field) {
    auto invalid = descriptor;
    if (field == 0) descriptor.formatId = 2;
    if (field == 1) descriptor.algorithmId = 2;
    if (field == 2) descriptor.keyId = 0;
    if (field == 3) descriptor.appAddress = 0;
    sign_descriptor();
    EXPECT_EQ(usb::UsbOtaResult::BadRequest,
              cache.handleUsbCacheFrame(begin, sizeof(begin), h.sender.signer.publicKey()));
    EXPECT_FALSE(cache.status().valid);
    descriptor = invalid;
  }
  const auto exact_size = descriptor.exactSizeBytes;
  descriptor.exactSizeBytes = h.sender.fx.image_region.sizeBytes() + 1u;
  sign_descriptor();
  EXPECT_EQ(usb::UsbOtaResult::Busy,
            cache.handleUsbCacheFrame(begin, sizeof(begin), h.sender.signer.publicKey()));
  EXPECT_EQ(0u, h.sender.fx.image_flash.eraseOpCount());
  descriptor.exactSizeBytes = exact_size;
  sign_descriptor();
  EXPECT_EQ(usb::UsbOtaResult::Denied, cache.handleUsbCacheFrame(begin, sizeof(begin), nullptr));
  h.sender.fx.admins.add(h.sender.signer.publicKey());
  ASSERT_EQ(usb::UsbOtaResult::Ok, cache.handleUsbCacheFrame(begin, sizeof(begin), nullptr));
  uint8_t put[45] = {usb::kCommand, static_cast<uint8_t>(usb::UsbOtaOp::CachePut), 0, 0, 40};
  std::memcpy(put + 5, image, sizeof(image));
  put[5] ^= 1;
  ASSERT_EQ(usb::UsbOtaResult::Ok, cache.handleUsbCacheFrame(put, sizeof(put), nullptr));
  const uint8_t seal[] = {usb::kCommand, static_cast<uint8_t>(usb::UsbOtaOp::CacheSeal)};
  ASSERT_EQ(usb::UsbOtaResult::Pending, cache.handleUsbCacheFrame(seal, sizeof(seal), nullptr));
  h.sender.fx.integration.loop();
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Failed, cache.status().phase);
  EXPECT_TRUE(cache.status().localCache);
  EXPECT_FALSE(h.sender.fx.integration.reportedPhase() == usb::UsbOtaPhase::CacheSealed);
}

TEST(LoraOtaRfProduct, UsbCacheCannotWriteOrSealAReceiverInstallCandidate) {
  RfProductHarness h;
  const uint8_t image[40] = {0x53};
  uint8_t canonical[59], signature[64];
  h.a.fx.buildSmallManifest(image, sizeof(image), canonical);
  h.sender.signer.sign(canonical, sizeof(canonical), signature);
  h.a.fx.admins.add(h.sender.signer.publicKey());
  auto& receiver = h.a.fx.integration.leanReceiver();
  ASSERT_EQ(usb::UsbOtaResult::Ok,
            receiver.begin(h.sender.signer.publicKey(), canonical, signature, false, false));
  const auto writes = h.a.fx.image_flash.programOpCount();
  uint8_t put[45] = {usb::kCommand, static_cast<uint8_t>(usb::UsbOtaOp::CachePut), 0, 0, 40};
  std::memcpy(put + 5, image, sizeof(image));
  EXPECT_EQ(usb::UsbOtaResult::Denied, receiver.handleUsbCacheFrame(put, sizeof(put), h.a.signer.publicKey()));
  const uint8_t seal[] = {usb::kCommand, static_cast<uint8_t>(usb::UsbOtaOp::CacheSeal)};
  EXPECT_EQ(usb::UsbOtaResult::Denied, receiver.handleUsbCacheFrame(seal, sizeof(seal), h.a.signer.publicKey()));
  EXPECT_EQ(writes, h.a.fx.image_flash.programOpCount());
  EXPECT_EQ(0u, receiver.status().receivedBlocks);
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Receiving, receiver.status().phase);
}

TEST(LoraOtaRfProduct, StockLoaderCacheStillRefusesDestructiveStagingDuringTrialOrUnknownGuard) {
  for (const bool unknown : {false, true}) {
    SCOPED_TRACE(unknown);
    RfProductHarness h;
    OtaBoardCacheOnlyBackend backend(h.sender.fx.image_region, h.sender.fx.candidate_store_region,
                                     unknown ? nullptr : +[]() { return true; });
    ASSERT_TRUE(backend.attach(h.sender.fx.integration, h.sender.fx.sig_verifier));
    const uint8_t image[40] = {0x54};
    uint8_t canonical[59], signature[64];
    h.sender.fx.buildSmallManifest(image, sizeof(image), canonical);
    h.sender.signer.sign(canonical, sizeof(canonical), signature);
    EXPECT_EQ(usb::UsbOtaResult::Busy, h.sender.fx.integration.leanReceiver().begin(
        h.sender.signer.publicKey(), canonical, signature, false, true, true));
    EXPECT_EQ(0u, h.sender.fx.image_flash.eraseOpCount());
    EXPECT_EQ(0u, h.sender.fx.candidate_flash.eraseOpCount());
  }
}

TEST(LoraOtaRfProduct, CompleteFirmwareLargerThan512KiBSurvivesLeaseCyclesAndIsByteExact) {
  RfProductHarness h;
  h.prepare(540672, usb::kStartModeDirect);
  for (int i = 0; i < 30000 && !h.ready(h.a); ++i) h.step(20);
  ASSERT_TRUE(h.ready(h.a));
  EXPECT_GT(h.sender.retunes, 1);
  EXPECT_GT(h.now, 60000u);
  std::vector<uint8_t> received(h.image.size());
  for (size_t offset = 0; offset < received.size(); offset += 84) {
    ASSERT_EQ(IOtaStagingSink::Result::Ok, h.a.fx.staging.readChunk(offset, received.data() + offset,
                                                                std::min<size_t>(84, received.size() - offset)));
  }
  EXPECT_EQ(h.image, received);
  EXPECT_EQ(6437, h.a.fx.integration.leanReceiver().status().receivedBlocks);
  EXPECT_LT(h.a.fx.candidate_flash.readOpCount(), 16u * 6437u);
}

namespace {
struct LifecycleImageAccessor : ::ota::storage::IXiaoOtaActiveImageAccessor {
  std::vector<uint8_t> image = std::vector<uint8_t>(9000, 0x37);
  int pending = 1;
  bool fail = false;
  ::ota::storage::XiaoOtaExtentResolutionStep stepExtentResolution(uint32_t, const uint8_t** out, uint32_t* extent) override {
    if (fail) return ::ota::storage::XiaoOtaExtentResolutionStep::Failed;
    *out = image.data(); *extent = image.size();
    if (pending-- > 0) return ::ota::storage::XiaoOtaExtentResolutionStep::InProgress;
    return ::ota::storage::XiaoOtaExtentResolutionStep::Resolved;
  }
};
struct LifecycleFixture {
  ::ota::test::FakeNorFlash state_flash{8192, 4096}, floor_flash{8192, 4096};
  ::ota::platform::FlashRegion state{state_flash, 0, 8192}, floor{floor_flash, 0, 8192};
  LifecycleImageAccessor accessor;
  OtaBoardBootLifecycleObserver observer{state, floor, accessor};
  uint8_t hash[32] = {};
  static void le32(uint8_t* out, uint32_t value) {
    for (int i = 0; i < 4; ++i) out[i] = static_cast<uint8_t>(value >> (i * 8));
  }
  void setState(uint32_t phase, uint32_t counter = 5, uint64_t nonce = 17) {
    using Reader = ::ota::storage::XiaoOtaStateReader;
    ::ota::trust::Sha256::hash(accessor.image.data(), accessor.image.size(), hash);
    uint8_t bytes[Reader::kRecordBytes] = {};
    le32(bytes, Reader::kMagic); bytes[4] = 1; bytes[6] = Reader::kRecordBytes; le32(bytes + 8, 1);
    le32(bytes + 12, nonce); le32(bytes + 16, nonce >> 32); le32(bytes + 20, phase);
    le32(bytes + 28, 4096); // Previous image extent, not the new running image length.
    le32(bytes + 32, counter);
    std::memcpy(bytes + 44, hash, 32); std::memcpy(bytes + 108, hash, 32);
    le32(bytes + Reader::kCrcOffset, ::ota::storage::Crc32::computeFinalized(bytes, Reader::kCrcOffset));
    le32(bytes + Reader::kCommitMarkerOffset, Reader::kCommitMarker);
    ASSERT_TRUE(::ota::platform::isOk(state.program(0, bytes, sizeof(bytes))));
  }
  void setFloor(uint32_t value, bool wrong_hash = false, bool wrong_extent = false) {
    using Reader = ::ota::storage::XiaoOtaFloorReader;
    uint8_t bytes[Reader::kRecordBytes] = {};
    le32(bytes, Reader::kMagic); bytes[4] = 1; bytes[6] = Reader::kRecordBytes; le32(bytes + 8, 1);
    le32(bytes + 12, value); le32(bytes + 16, accessor.image.size() + (wrong_extent ? 1 : 0));
    std::memcpy(bytes + 20, hash, 32);
    if (wrong_hash) bytes[20] ^= 1;
    le32(bytes + Reader::kCrcOffset, ::ota::storage::Crc32::computeFinalized(bytes, Reader::kCrcOffset));
    le32(bytes + Reader::kCommitMarkerOffset, Reader::kCommitMarker);
    ASSERT_TRUE(::ota::platform::isOk(floor.program(0, bytes, sizeof(bytes))));
  }
};
}

TEST(LoraOtaLifecycle, ConfirmedRecordNeedsFreshRunningHashAndExactDurableFloorWithoutWritingAnything) {
  LifecycleFixture f;
  f.setState(::ota::storage::XiaoOtaStateReader::kPhaseConfirmed);
  OtaBootLifecycleEvidence boot;
  EXPECT_TRUE(f.observer.pending());
  ASSERT_TRUE(f.observer.read(true, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  for (int i = 0; i < 10; ++i) f.observer.tick(true);
  EXPECT_FALSE(f.observer.pending());
  ASSERT_TRUE(f.observer.read(true, boot));
  EXPECT_TRUE(boot.imageVerified);
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  EXPECT_EQ(0u, boot.confirmedFloor);
  f.setFloor(5);
  const auto programs = f.state_flash.programOpCount() + f.floor_flash.programOpCount();
  ASSERT_TRUE(f.observer.read(true, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Installed, boot.phase);
  EXPECT_EQ(0, std::memcmp(f.hash, boot.imageHash, 32));
  EXPECT_EQ(programs, f.state_flash.programOpCount() + f.floor_flash.programOpCount());
  EXPECT_FALSE(f.observer.read(false, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  EXPECT_FALSE(boot.floorKnown);
}

TEST(LoraOtaLifecycle, ReflashDifferentRunningBytesAndUnresolvableExtentNeverClaimInstalled) {
  for (bool failed_extent : {false, true}) {
    LifecycleFixture f;
    f.setState(::ota::storage::XiaoOtaStateReader::kPhaseConfirmed);
    f.setFloor(5);
    if (failed_extent) f.accessor.fail = true; else f.accessor.image[0] ^= 1;
    for (int i = 0; i < 10; ++i) f.observer.tick(true);
    OtaBootLifecycleEvidence boot;
    ASSERT_TRUE(f.observer.read(true, boot));
    EXPECT_FALSE(boot.imageVerified);
    EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  }
}

TEST(LoraOtaLifecycle, ValidFloorCrcWithDifferentHashExtentOrCounterCannotProveConfirmation) {
  for (int mismatch = 0; mismatch < 3; ++mismatch) {
    LifecycleFixture f;
    f.setState(::ota::storage::XiaoOtaStateReader::kPhaseConfirmed);
    f.setFloor(mismatch == 2 ? 6 : 5, mismatch == 0, mismatch == 1);
    for (int i = 0; i < 10; ++i) f.observer.tick(true);
    OtaBootLifecycleEvidence boot;
    ASSERT_TRUE(f.observer.read(true, boot));
    EXPECT_TRUE(boot.imageVerified);
    EXPECT_TRUE(boot.floorKnown);
    EXPECT_EQ(usb::UsbOtaPhase::Unknown, boot.phase);
  }
}

TEST(LoraOtaLifecycle, TrialDoesNotBecomeInstalledWhenConfirmationRequestOrOldFloorExists) {
  LifecycleFixture f;
  f.setState(::ota::storage::XiaoOtaStateReader::kPhaseTrialBoot);
  f.setFloor(5);
  for (int i = 0; i < 10; ++i) f.observer.tick(true);
  OtaBootLifecycleEvidence boot;
  ASSERT_TRUE(f.observer.read(true, boot));
  EXPECT_EQ(usb::UsbOtaPhase::Trial, boot.phase);
  EXPECT_FALSE(boot.imageVerified);
  EXPECT_EQ(0, std::memcmp(f.hash, boot.imageHash, 32));
}

TEST(LoraOtaLifecycle, RemoteCensusCarriesRealPhaseAndCommitAckCannotFabricateInstalled) {
  RfProductHarness h;
  h.prepare(91, usb::kStartModeDirected);
  for (int i = 0; i < 20 && !h.ready(h.a); ++i) h.step();
  auto& integration = h.a.fx.integration;
  const auto st = integration.leanReceiver().status();
  uint8_t message[usb::kCommitSignedBytes], signature[64];
  usb::buildCommitSignedMessage(h.a.signer.publicKey(), st.manifestHash, st.counter, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, integration.leanReceiver().commit(st.counter, signature));
  EXPECT_EQ(usb::UsbOtaPhase::CommitPending, integration.reportedPhase());
  OtaBootLifecycleEvidence boot;
  boot.phase = usb::UsbOtaPhase::Trial; boot.counter = st.counter; boot.transactionNonce = st.transactionNonce;
  std::memcpy(boot.imageHash, st.imageHash, 32);
  integration.attachBootLifecycle(&boot, [](void* ctx, OtaBootLifecycleEvidence& out) {
    out = *static_cast<OtaBootLifecycleEvidence*>(ctx); return true;
  });
  EXPECT_EQ(usb::UsbOtaPhase::Trial, integration.reportedPhase());
  boot.phase = usb::UsbOtaPhase::Installed;
  EXPECT_EQ(usb::UsbOtaPhase::CommitPending, integration.reportedPhase());
  boot.imageVerified = true; boot.floorKnown = true; boot.confirmedFloor = st.counter;
  ++boot.transactionNonce;
  EXPECT_EQ(usb::UsbOtaPhase::CommitPending, integration.reportedPhase());
  --boot.transactionNonce;
  EXPECT_EQ(usb::UsbOtaPhase::Installed, integration.reportedPhase());
  uint8_t poll[kOtaCensusPollBytes], report[kOtaCensusReportBytes]; size_t len = 0;
  encodeOtaCensusPoll(h.a.signer.publicKey(), st.manifestHash, 0, poll, sizeof(poll));
  ASSERT_TRUE(integration.handleReceivedFrame(poll, sizeof(poll), h.now));
  ASSERT_TRUE(integration.peekOutboundControlFrame(report, sizeof(report), len, h.now + 250));
  integration.releaseOutboundControlFrame();
  ASSERT_TRUE(h.sender.fx.integration.handleReceivedFrame(report, len, h.now));
  OtaFirmwareIntegration::TargetObservation observed;
  ASSERT_TRUE(h.sender.fx.integration.targetObservation(h.a.signer.publicKey(), h.now, observed));
  EXPECT_EQ(usb::UsbOtaPhase::Installed, observed.lifecyclePhase);
  EXPECT_EQ(st.counter, observed.confirmedFloor);
  EXPECT_EQ(st.counter, observed.counter);
}

TEST(LoraOtaLifecycle, TextReadbackFitsNormalRepeaterReplyAndShowsActualHashFloorNotCommitAcknowledgement) {
  OtaBootLifecycleEvidence boot;
  boot.phase = usb::UsbOtaPhase::Installed; boot.imageVerified = true; boot.floorKnown = true;
  boot.confirmedFloor = UINT32_MAX;
  std::memset(boot.imageHash, 0xAB, 32);
  char reply[160];
  formatOtaBootLifecycleStatus(reply, sizeof(reply), boot, usb::UsbOtaPhase::CommitPending, UINT32_MAX);
  EXPECT_NE(nullptr, std::strstr(reply, "boot=confirmed phase=commit-pending floor=4294967295"));
  EXPECT_NE(nullptr, std::strstr(reply, "verified=1 image=abababab"));
  EXPECT_EQ(153u, std::strlen(reply));
}

namespace {
struct ProfileChip {
  float frequency = 907.525f, bandwidth = 250;
  uint8_t sf = 10, cr = 5;
  uint16_t preamble = 16;
  bool fail = false;
  int standby() { return 0; }
  int setFrequency(float value) { frequency = value; return fail ? -1 : 0; }
  int setBandwidth(float value) { bandwidth = value; return 0; }
  int setSpreadingFactor(uint8_t value) { sf = value; return 0; }
  int setCodingRate(uint8_t value) { cr = value; return 0; }
  int setPreambleLength(uint16_t value) { preamble = value; return 0; }
  void setPreambleMillis(uint32_t) {}
  void setMaxPayloadMillis(uint32_t) {}
};
struct ProfileWrapper {
  bool receiving = true, healthy = true;
  int resets = 0, rxStarts = 0;
  struct Timing { uint32_t preambleMillis = 20, payloadMillis = 100; };
  void begin() { receiving = false; ++resets; }
  static uint16_t preambleLengthForSF(uint8_t sf) { return sf <= 8 ? 32 : 16; }
  Timing calcMaxPacketMillis(uint8_t, float, uint8_t, uint16_t) { return {}; }
  int recvRaw(uint8_t*, int) { receiving = healthy; ++rxStarts; return 0; }
  bool isInRecvMode() const { return receiving; }
  bool probeDriverStatus() { return healthy; }
};
}

TEST(LoraOtaRfProduct, CheckedProfileChangesPhysicalParamsAndRestartsRxRatherThanKeepingStaleWrapperState) {
  ProfileChip chip;
  ProfileWrapper wrapper;
  ASSERT_TRUE(mesh::ota::applyCheckedOtaRadioProfile(chip, wrapper, 908.525f, 250, 5, 5));
  EXPECT_FLOAT_EQ(908.525f, chip.frequency);
  EXPECT_EQ(5, chip.sf); EXPECT_EQ(5, chip.cr); EXPECT_EQ(32, chip.preamble);
  EXPECT_TRUE(wrapper.receiving); EXPECT_EQ(1, wrapper.resets); EXPECT_EQ(1, wrapper.rxStarts);
  ASSERT_TRUE(mesh::ota::applyCheckedOtaRadioProfile(chip, wrapper, 907.525f, 125, 10, 6));
  EXPECT_FLOAT_EQ(907.525f, chip.frequency); EXPECT_FLOAT_EQ(125, chip.bandwidth);
  EXPECT_EQ(10, chip.sf); EXPECT_EQ(6, chip.cr); EXPECT_EQ(16, chip.preamble);
  chip.fail = true;
  EXPECT_FALSE(mesh::ota::applyCheckedOtaRadioProfile(chip, wrapper, 908.525f, 250, 5, 5));
  EXPECT_EQ(2, wrapper.resets);
  chip.fail = false; wrapper.healthy = false;
  EXPECT_FALSE(mesh::ota::applyCheckedOtaRadioProfile(chip, wrapper, 908.525f, 250, 5, 5));
  EXPECT_FALSE(wrapper.receiving);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
