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
  EXPECT_EQ(Result::Rejected, sink.writeChunk(1, bytes, 1));
  EXPECT_EQ(0u, flash.programOpCount());
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

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
